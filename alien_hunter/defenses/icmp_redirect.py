"""
Real-Time ICMP Redirect Route Hijacking Guard.
Passively sniffs incoming ICMP Type 5 packets (AF_INET, SOCK_RAW, IPPROTO_ICMP)
to detect Adversary-in-the-Middle (MitM) route manipulation.
MITRE ATT&CK T1557 (Adversary-in-the-Middle: Route Hijacking).
Zero external dependencies.
"""

from collections import deque
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple


class IcmpRedirectEvent:
    """Represents a detected ICMP Redirect route manipulation incident."""

    def __init__(
        self,
        sender_ip: str,
        new_gateway: str,
        orig_dest_ip: Optional[str] = None,
        icmp_code: int = 1,
        timestamp: float = 0.0,
        burst_count: int = 1,
    ):
        self.sender_ip = sender_ip
        self.new_gateway = new_gateway
        self.orig_dest_ip = orig_dest_ip or "0.0.0.0"
        self.icmp_code = icmp_code
        self.timestamp = timestamp or time.time()
        self.burst_count = burst_count

    @property
    def code_description(self) -> str:
        descriptions = {
            0: "Redirect for Network",
            1: "Redirect for Host",
            2: "Redirect for ToS and Network",
            3: "Redirect for ToS and Host",
        }
        return descriptions.get(self.icmp_code, f"Redirect Code {self.icmp_code}")

    def to_threat_string(self) -> str:
        burst_str = f" ({self.burst_count} packet burst)" if self.burst_count > 1 else ""
        dest_str = f" to target destination {self.orig_dest_ip}" if self.orig_dest_ip != "0.0.0.0" else ""
        return (
            f"CRITICAL: Active ICMP Route Hijacking detected! "
            f"Host at {self.sender_ip} emitted forged ICMP Redirect (Type 5: {self.code_description}){burst_str} "
            f"rerouting traffic{dest_str} via gateway {self.new_gateway}! "
            f"Adversary-in-the-Middle route manipulation (MITRE ATT&CK T1557)."
        )


class IcmpRedirectGuard:
    """
    Passively monitors incoming IPv4 ICMP packets for rogue Type 5 redirects.
    On standard flat local subnets with a single gateway router, ICMP Redirects
    are virtually never legitimate and indicate active route manipulation.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        local_ip: Optional[str] = None,
        history_maxlen: int = 250,
    ):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.local_ip = local_ip
        self.history_maxlen = history_maxlen

        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None
        self._lock = threading.Lock()

        self._threat_queue: deque = deque(maxlen=history_maxlen)
        self._event_history: List[IcmpRedirectEvent] = []
        # Key: (sender_ip, new_gateway, orig_dest_ip) -> (last_time, count)
        self._rate_limits: Dict[Tuple[str, str, str], Tuple[float, int]] = {}

    def update_topology(self, gateway_ip: Optional[str] = None, local_ip: Optional[str] = None):
        """Updates local network topology attributes dynamically."""
        with self._lock:
            if gateway_ip:
                self.gateway_ip = gateway_ip
            if local_ip:
                self.local_ip = local_ip

    def start(self) -> bool:
        """Initializes raw socket and begins listening in a background thread."""
        with self._lock:
            if self.running:
                return True

            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                self._socket.settimeout(1.0)

                # Bind socket to specific interface if specified (Linux SO_BINDTODEVICE)
                if self.interface:
                    try:
                        self._socket.setsockopt(socket.SOL_SOCKET, 25, self.interface.encode("utf-8"))
                    except (AttributeError, OSError):
                        pass

                self.running = True
                self._thread = threading.Thread(target=self._sniff_loop, name="IcmpRedirectGuard", daemon=True)
                self._thread.start()
                return True
            except (PermissionError, OSError):
                self._cleanup_socket()
                self.running = False
                return False

    def stop(self):
        """Stops the sniffing thread and cleanly closes the raw socket."""
        with self._lock:
            self.running = False
            self._cleanup_socket()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)

    def _cleanup_socket(self):
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def _sniff_loop(self):
        """Background thread loop receiving and evaluating ICMP packets."""
        while self.running:
            sock = self._socket
            if not sock:
                break

            try:
                data, addr = sock.recvfrom(65535)
                sender_ip = addr[0] if addr else ""
                event = self.parse_icmp_packet(data, sender_ip)
                if event:
                    self._record_event(event)
            except socket.timeout:
                continue
            except OSError:
                if not self.running:
                    break
                time.sleep(0.1)

    def parse_icmp_packet(self, data: bytes, sender_ip: str = "") -> Optional[IcmpRedirectEvent]:
        """
        Parses raw IPv4 ICMP packet bytes and returns an IcmpRedirectEvent if Type 5.
        Designed as a pure, modular parser suitable for unit testing without live sockets.
        """
        if len(data) < 28:
            return None

        # Parse IPv4 Header
        version = data[0] >> 4
        if version != 4:
            return None

        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 8:
            return None

        src_ip = socket.inet_ntoa(data[12:16])
        if not sender_ip:
            sender_ip = src_ip

        # Ignore self-emitted ICMP packets
        if self.local_ip and sender_ip == self.local_ip:
            return None

        icmp_slice = data[ihl:]
        icmp_type = icmp_slice[0]
        icmp_code = icmp_slice[1]

        # ICMP Type 5 = Redirect Message
        if icmp_type != 5:
            return None

        # Bytes 4-7 in ICMP Type 5 header contain the new gateway IP address
        new_gateway = socket.inet_ntoa(icmp_slice[4:8])

        # Bytes 8+ contain the IP header and leading 8 bytes of the original datagram
        orig_dest_ip = "0.0.0.0"
        if len(icmp_slice) >= 8 + 20:
            orig_ip_hdr = icmp_slice[8:28]
            orig_version = orig_ip_hdr[0] >> 4
            if orig_version == 4:
                orig_dest_ip = socket.inet_ntoa(orig_ip_hdr[16:20])

        return IcmpRedirectEvent(
            sender_ip=sender_ip,
            new_gateway=new_gateway,
            orig_dest_ip=orig_dest_ip,
            icmp_code=icmp_code,
            timestamp=time.time(),
        )

    def _record_event(self, event: IcmpRedirectEvent):
        """Thread-safely stores and deduplicates redirect alerts within a 15-second window."""
        with self._lock:
            key = (event.sender_ip, event.new_gateway, event.orig_dest_ip)
            now = event.timestamp
            last_time, count = self._rate_limits.get(key, (0.0, 0))

            if now - last_time < 15.0:
                self._rate_limits[key] = (now, count + 1)
                return

            self._rate_limits[key] = (now, 1)
            self._event_history.append(event)
            self._threat_queue.append(event.to_threat_string())

    def get_threat_strings(self) -> List[str]:
        """Returns and clears all pending threat strings."""
        with self._lock:
            threats = list(self._threat_queue)
            self._threat_queue.clear()
            return threats
