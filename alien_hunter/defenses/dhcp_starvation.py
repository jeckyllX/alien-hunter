"""
DHCP Starvation & IP Pool Exhaustion Detector.
Passively monitors UDP 67/68 traffic to detect rapid bursts of DHCP Discover and
Request packets with spoofed or mutating hardware MAC addresses (Yersinia, dhcpstarv).
MITRE ATT&CK T1499 (Endpoint Denial of Service).
"""

import collections
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class DhcpStarvationEvent:
    """Represents a detected DHCP starvation or pool exhaustion attack."""

    def __init__(
        self,
        distinct_macs: List[str],
        request_count: int,
        burst_rate: float,
        window_seconds: float,
        timestamp: float,
        primary_src_mac: Optional[str] = None,
        is_spoofed_chaddr: bool = False,
    ):
        self.distinct_macs = distinct_macs
        self.request_count = request_count
        self.burst_rate = burst_rate
        self.window_seconds = window_seconds
        self.timestamp = timestamp
        self.primary_src_mac = primary_src_mac
        self.is_spoofed_chaddr = is_spoofed_chaddr

    @property
    def distinct_mac_count(self) -> int:
        return len(self.distinct_macs)

    def to_threat_string(self) -> str:
        sample_macs = ", ".join(self.distinct_macs[:5])
        if len(self.distinct_macs) > 5:
            sample_macs += f", ... (+{len(self.distinct_macs) - 5} more)"

        src_info = f" from L2 host {self.primary_src_mac}" if self.primary_src_mac else ""
        spoof_flag = " [Spoofed DHCP chaddr detected]" if self.is_spoofed_chaddr else ""

        return (
            f"CRITICAL: DHCP Starvation / Pool Exhaustion attack detected! "
            f"Observed burst of {self.request_count} DHCP requests across "
            f"{self.distinct_mac_count} unique MAC(s){src_info}{spoof_flag} "
            f"({self.burst_rate:.1f} req/s over {self.window_seconds:.1f}s) "
            f"[Sample MACs: {sample_macs}]! "
            f"Potential DHCP pool exhaustion and rogue server takeover (MITRE ATT&CK T1499)."
        )


class DhcpStarvationGuard:
    """
    Passively monitors Layer-2 DHCP transactions for rapid Discover/Request floods
    and randomized hardware address exhaustion attacks.
    """

    SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_DROP_MEMBERSHIP = 2
    PACKET_MR_PROMISC = 1

    MAGIC_COOKIE = b"\x63\x82\x53\x63"

    def __init__(
        self,
        interface: Optional[str] = None,
        window_seconds: float = 5.0,
        burst_threshold: int = 5,
        rate_threshold: float = 3.0,
        alert_cooldown: float = 30.0,
    ):
        self.interface = interface
        self.window_seconds = window_seconds
        self.burst_threshold = burst_threshold
        self.rate_threshold = rate_threshold
        self.alert_cooldown = alert_cooldown

        # Sliding window history: list of dict records
        # record: {"time": float, "src_mac": str, "chaddr": str, "msg_type": int, "xid": bytes}
        self._history: collections.deque = collections.deque()
        self._last_alert_time: float = 0.0
        self._detected_events: List[DhcpStarvationEvent] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def parse_dhcp_packet(pkt: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses raw Ethernet frame into DHCP fields if it represents an IPv4 UDP DHCP request.
        Returns parsed dict or None if invalid or non-DHCP request.
        """
        if len(pkt) < 282:  # 14 (Eth) + 20 (IP) + 8 (UDP) + 240 (BOOTP)
            return None

        # Ethernet header (14 bytes)
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        if ethertype != 0x0800:  # IPv4
            return None

        src_mac = ":".join(f"{b:02X}" for b in pkt[6:12])

        # IPv4 header
        v_ihl = pkt[14]
        version = v_ihl >> 4
        if version != 4:
            return None

        ihl = (v_ihl & 0x0F) * 4
        if ihl < 20 or len(pkt) < 14 + ihl + 8 + 240:
            return None

        proto = pkt[23]
        if proto != 17:  # IPPROTO_UDP
            return None

        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])

        # UDP header
        udp_off = 14 + ihl
        src_port, dst_port = struct.unpack("!HH", pkt[udp_off : udp_off + 4])
        # DHCP client traffic targets UDP port 67 (server) or originates from UDP port 68
        if dst_port != 67 and src_port != 68:
            return None

        # BOOTP / DHCP payload
        bootp = pkt[udp_off + 8 :]
        if len(bootp) < 240:
            return None

        op = bootp[0]
        if op != 1:  # BOOTREQUEST only
            return None

        htype = bootp[1]
        hlen = bootp[2]
        xid = bootp[4:8]

        # Extract client hardware address
        chaddr_bytes = bootp[28 : 28 + hlen] if hlen == 6 else bootp[28:34]
        chaddr_mac = ":".join(f"{b:02X}" for b in chaddr_bytes)

        # Magic cookie check
        if bootp[236:240] != DhcpStarvationGuard.MAGIC_COOKIE:
            return None

        # Parse DHCP options to determine message type
        options = bootp[240:]
        msg_type = 0
        idx = 0
        while idx < len(options):
            opt = options[idx]
            if opt == 255:  # End of options
                break
            if opt == 0:  # Pad
                idx += 1
                continue
            if idx + 1 >= len(options):
                break
            opt_len = options[idx + 1]
            if idx + 2 + opt_len > len(options):
                break
            opt_val = options[idx + 2 : idx + 2 + opt_len]
            if opt == 53 and opt_len >= 1:
                msg_type = opt_val[0]
            idx += 2 + opt_len

        # Focus on DHCPDISCOVER (1) and DHCPREQUEST (3)
        if msg_type not in (1, 3):
            return None

        return {
            "src_mac": src_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "xid": xid,
            "chaddr": chaddr_mac,
            "msg_type": msg_type,
            "is_spoofed": (src_mac.upper() != chaddr_mac.upper()),
        }

    def process_packet(self, pkt: bytes, now: Optional[float] = None) -> Optional[DhcpStarvationEvent]:
        """
        Processes a raw Ethernet frame. Updates sliding window state and returns
        a DhcpStarvationEvent if starvation/exhaustion thresholds are exceeded.
        """
        parsed = self.parse_dhcp_packet(pkt)
        if not parsed:
            return None

        if now is None:
            now = time.time()

        with self._lock:
            self._history.append(
                {
                    "time": now,
                    "src_mac": parsed["src_mac"],
                    "chaddr": parsed["chaddr"],
                    "msg_type": parsed["msg_type"],
                    "xid": parsed["xid"],
                    "is_spoofed": parsed["is_spoofed"],
                }
            )

            # Evict entries older than window_seconds
            cutoff = now - self.window_seconds
            while self._history and self._history[0]["time"] < cutoff:
                self._history.popleft()

            total_requests = len(self._history)
            distinct_chaddrs = list(dict.fromkeys(r["chaddr"] for r in self._history))
            distinct_src_macs = set(r["src_mac"] for r in self._history)
            spoofed_entries = [r for r in self._history if r["is_spoofed"]]

            if total_requests < 2:
                return None

            oldest_time = self._history[0]["time"]
            duration = max(0.1, now - oldest_time)
            burst_rate = total_requests / duration

            # Attack criteria:
            # 1. Distinct mutating client hardware MACs >= burst_threshold
            # 2. Total request flood rate >= rate_threshold with >= 3 distinct MACs
            # 3. Explicit MAC spoofing (chaddr != src_mac) with multiple mutating addresses
            is_starvation = False
            if len(distinct_chaddrs) >= self.burst_threshold:
                is_starvation = True
            elif len(distinct_chaddrs) >= 3 and burst_rate >= self.rate_threshold:
                is_starvation = True
            elif len(spoofed_entries) >= 3 and len(distinct_chaddrs) >= 3:
                is_starvation = True

            if is_starvation:
                if now - self._last_alert_time >= self.alert_cooldown:
                    self._last_alert_time = now
                    # Identify primary physical L2 source if common
                    src_counter = collections.Counter(r["src_mac"] for r in self._history)
                    primary_src, _ = src_counter.most_common(1)[0]

                    event = DhcpStarvationEvent(
                        distinct_macs=distinct_chaddrs,
                        request_count=total_requests,
                        burst_rate=burst_rate,
                        window_seconds=round(duration, 2),
                        timestamp=now,
                        primary_src_mac=primary_src,
                        is_spoofed_chaddr=len(spoofed_entries) > 0,
                    )
                    self._detected_events.append(event)
                    return event

        return None

    def sniff(self, duration: float = 2.0) -> List[DhcpStarvationEvent]:
        """
        Passively sniffs raw Layer-2 DHCP traffic for duration seconds.
        """
        events: List[DhcpStarvationEvent] = []
        raw_sock = None
        mreq = None

        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                raw_sock.bind((self.interface, 0))
                try:
                    ifindex = socket.if_nametoindex(self.interface)
                    mreq = struct.pack("IHH8s", ifindex, self.PACKET_MR_PROMISC, 0, b"")
                    raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
                except Exception:
                    mreq = None

            raw_sock.settimeout(0.5)
            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    pkt, _ = raw_sock.recvfrom(2048)
                    ev = self.process_packet(pkt)
                    if ev:
                        events.append(ev)
                except socket.timeout:
                    continue
        except Exception:
            pass
        finally:
            if raw_sock:
                if mreq:
                    try:
                        raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_DROP_MEMBERSHIP, mreq)
                    except Exception:
                        pass
                try:
                    raw_sock.close()
                except Exception:
                    pass

        return events

    def start(self) -> bool:
        """Starts background listener thread for continuous sentinel monitoring."""
        with self._lock:
            if self._running:
                return True
            try:
                test_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                test_sock.close()
            except Exception:
                return False

            self._running = True
            self._thread = threading.Thread(
                target=self._sniff_loop, daemon=True, name="DhcpStarvationGuard"
            )
            self._thread.start()
            return True

    def stop(self):
        """Stops the background listener thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    @property
    def is_running(self) -> bool:
        return self._running

    def _sniff_loop(self):
        """Continuous sniffing loop executed in background daemon thread."""
        raw_sock = None
        mreq = None
        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                raw_sock.bind((self.interface, 0))
                try:
                    ifindex = socket.if_nametoindex(self.interface)
                    mreq = struct.pack("IHH8s", ifindex, self.PACKET_MR_PROMISC, 0, b"")
                    raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
                except Exception:
                    mreq = None

            raw_sock.settimeout(1.0)
            while self._running:
                try:
                    pkt, _ = raw_sock.recvfrom(2048)
                    self.process_packet(pkt)
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            if raw_sock:
                if mreq:
                    try:
                        raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_DROP_MEMBERSHIP, mreq)
                    except Exception:
                        pass
                try:
                    raw_sock.close()
                except Exception:
                    pass

    def get_threat_strings(self) -> List[str]:
        """Drains and returns all detected threat alert strings."""
        with self._lock:
            threats = [e.to_threat_string() for e in self._detected_events]
            self._detected_events.clear()
            return threats
