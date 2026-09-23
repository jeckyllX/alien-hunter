"""
Stealth TCP Half-Open / SYN Port Scan Detector.
Inspects raw Layer-2 Ethernet and IPv4 frames to detect rapid SYN probing,
horizontal subnet sweeps, and abnormal TCP flag manipulation (NULL, FIN, XMAS scans).
MITRE ATT&CK T1046 (Network Service Discovery).
"""

import collections
import ipaddress
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class SynScanEvent:
    """Represents a detected stealth TCP port scan or probe activity."""

    def __init__(
        self,
        src_ip: str,
        src_mac: str,
        scan_type: str,
        scan_profile: str,
        target_count: int,
        probed_ports: List[int],
        probed_hosts: List[str],
        duration: float,
        timestamp: float,
    ):
        self.src_ip = src_ip
        self.src_mac = src_mac
        self.scan_type = scan_type
        self.scan_profile = scan_profile
        self.target_count = target_count
        self.probed_ports = probed_ports
        self.probed_hosts = probed_hosts
        self.duration = duration
        self.timestamp = timestamp

    def to_threat_string(self) -> str:
        ports_summary = ", ".join(map(str, sorted(self.probed_ports)[:8]))
        if len(self.probed_ports) > 8:
            ports_summary += f", ... (+{len(self.probed_ports) - 8} more)"

        hosts_summary = ", ".join(sorted(self.probed_hosts)[:4])
        if len(self.probed_hosts) > 4:
            hosts_summary += f", ... (+{len(self.probed_hosts) - 4} more)"

        if self.duration > 0:
            time_str = f" within {self.duration:.1f}s"
        else:
            time_str = ""

        return (
            f"CRITICAL: Stealth TCP Port Scan detected! Host at {self.src_ip} "
            f"({self.src_mac}) launched a {self.scan_profile} ({self.scan_type}){time_str} "
            f"probing {self.target_count} target endpoint(s) "
            f"[Ports: {ports_summary}] [Targets: {hosts_summary}]! "
            f"Active internal reconnaissance (MITRE ATT&CK T1046)."
        )


class SynScanDetector:
    """
    Passively monitors Layer-2 network frames for stealth TCP SYN scans and
    abnormal TCP control flag patterns.
    """

    SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_DROP_MEMBERSHIP = 2
    PACKET_MR_PROMISC = 1

    def __init__(
        self,
        interface: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_mac: Optional[str] = None,
        window_seconds: float = 5.0,
        port_threshold: int = 8,
        host_threshold: int = 5,
        endpoint_threshold: int = 10,
        alert_cooldown: float = 30.0,
    ):
        self.interface = interface
        self.subnet_cidr = subnet_cidr
        self.local_ip = local_ip
        self.local_mac = local_mac.upper() if local_mac else None
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        self.endpoint_threshold = endpoint_threshold
        self.alert_cooldown = alert_cooldown

        self._local_network = None
        if subnet_cidr:
            try:
                self._local_network = ipaddress.ip_network(subnet_cidr, strict=False)
            except Exception:
                self._local_network = None

        # State tracking: src_ip -> list of probe dicts
        self._probes: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
        self._last_alert_time: Dict[str, float] = {}
        self._detected_events: List[SynScanEvent] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def parse_tcp_packet(pkt: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses raw Ethernet frame into protocol fields if it contains an IPv4 TCP segment.
        Returns parsed dict or None if invalid or non-TCP.
        """
        if len(pkt) < 54:
            return None

        # Ethernet header (14 bytes)
        src_mac = ":".join(f"{b:02X}" for b in pkt[6:12])
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        if ethertype != 0x0800:
            return None

        # IPv4 header (starts at byte 14)
        v_ihl = pkt[14]
        version = v_ihl >> 4
        if version != 4:
            return None

        ihl = (v_ihl & 0x0F) * 4
        if ihl < 20 or len(pkt) < 14 + ihl + 20:
            return None

        proto = pkt[23]
        if proto != 6:  # IPPROTO_TCP
            return None

        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])

        # TCP header (starts at 14 + ihl)
        tcp_off = 14 + ihl
        src_port, dst_port = struct.unpack("!HH", pkt[tcp_off : tcp_off + 4])
        flags = pkt[tcp_off + 13]

        return {
            "src_mac": src_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": flags,
        }

    def process_packet(
        self, pkt: bytes, now: Optional[float] = None
    ) -> Optional[SynScanEvent]:
        """
        Processes a raw Ethernet frame. Detects SYN sweeps and abnormal TCP scan flags.
        Returns SynScanEvent if an alert threshold is met.
        """
        parsed = self.parse_tcp_packet(pkt)
        if not parsed:
            return None

        src_ip = parsed["src_ip"]
        dst_ip = parsed["dst_ip"]
        src_mac = parsed["src_mac"]
        dst_port = parsed["dst_port"]
        flags = parsed["flags"]

        # Filter out self-originated traffic
        if self.local_ip and src_ip == self.local_ip:
            return None
        if self.local_mac and src_mac == self.local_mac:
            return None

        # Only evaluate probes targeting the local subnet or private LAN space
        try:
            dst_obj = ipaddress.ip_address(dst_ip)
            if dst_obj.is_multicast or dst_obj.is_loopback or dst_obj.is_unspecified:
                return None
            if self._local_network:
                if dst_obj not in self._local_network and not dst_obj.is_private:
                    return None
            elif not dst_obj.is_private and not dst_obj.is_link_local:
                return None
        except Exception:
            return None

        # Classify TCP scan pattern based on control flags
        scan_type = None
        if flags == 0x00:
            scan_type = "NULL Scan"
        elif flags == 0x01:
            scan_type = "FIN Scan"
        elif (flags & 0x29) == 0x29:  # FIN + PSH + URG
            scan_type = "XMAS Scan"
        elif (flags & 0x02) != 0 and (flags & 0x10) == 0 and (flags & 0x04) == 0:
            # SYN flag set, ACK flag cleared, RST cleared
            scan_type = "SYN Scan"

        if not scan_type:
            return None

        if now is None:
            now = time.time()

        with self._lock:
            # Prune probes outside the sliding window
            cutoff = now - self.window_seconds
            probes = [p for p in self._probes[src_ip] if p["timestamp"] >= cutoff]
            probes.append(
                {
                    "timestamp": now,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "src_mac": src_mac,
                    "scan_type": scan_type,
                }
            )
            self._probes[src_ip] = probes

            # Immediate alert for abnormal non-SYN scans (NULL, FIN, XMAS have 0 legitimate use)
            if scan_type in ("NULL Scan", "FIN Scan", "XMAS Scan"):
                last_alert = self._last_alert_time.get(src_ip, 0.0)
                if now - last_alert >= self.alert_cooldown:
                    self._last_alert_time[src_ip] = now
                    event = SynScanEvent(
                        src_ip=src_ip,
                        src_mac=src_mac,
                        scan_type=scan_type,
                        scan_profile="Abnormal Flag Stealth Probe",
                        target_count=1,
                        probed_ports=[dst_port],
                        probed_hosts=[dst_ip],
                        duration=0.0,
                        timestamp=now,
                    )
                    self._detected_events.append(event)
                    return event
                return None

            # For SYN scans: evaluate target distributions in the active window
            ports_per_host: Dict[str, Set[int]] = collections.defaultdict(set)
            hosts_per_port: Dict[int, Set[str]] = collections.defaultdict(set)
            endpoints: Set[Tuple[str, int]] = set()

            for p in probes:
                if p["scan_type"] == "SYN Scan":
                    ports_per_host[p["dst_ip"]].add(p["dst_port"])
                    hosts_per_port[p["dst_port"]].add(p["dst_ip"])
                    endpoints.add((p["dst_ip"], p["dst_port"]))

            max_ports_on_host = max((len(pts) for pts in ports_per_host.values()), default=0)
            max_hosts_on_port = max((len(hs) for hs in hosts_per_port.values()), default=0)
            total_endpoints = len(endpoints)

            is_alert = False
            scan_profile = "Multi-Target SYN Scan"

            if max_ports_on_host >= self.port_threshold:
                is_alert = True
                scan_profile = "Vertical Port Scan"
            elif max_hosts_on_port >= self.host_threshold:
                is_alert = True
                scan_profile = "Horizontal Subnet Sweep"
            elif total_endpoints >= self.endpoint_threshold:
                is_alert = True
                scan_profile = "Stealth Port Sweep"

            if is_alert:
                last_alert = self._last_alert_time.get(src_ip, 0.0)
                if now - last_alert >= self.alert_cooldown:
                    self._last_alert_time[src_ip] = now
                    earliest = min(p["timestamp"] for p in probes if p["scan_type"] == "SYN Scan")
                    duration = max(0.1, now - earliest)
                    all_ports = sorted(list(set(p["dst_port"] for p in probes if p["scan_type"] == "SYN Scan")))
                    all_hosts = sorted(list(set(p["dst_ip"] for p in probes if p["scan_type"] == "SYN Scan")))

                    event = SynScanEvent(
                        src_ip=src_ip,
                        src_mac=src_mac,
                        scan_type="SYN Scan",
                        scan_profile=scan_profile,
                        target_count=total_endpoints,
                        probed_ports=all_ports,
                        probed_hosts=all_hosts,
                        duration=duration,
                        timestamp=now,
                    )
                    self._detected_events.append(event)
                    return event

        return None

    def sniff(self, duration: float = 2.0) -> List[SynScanEvent]:
        """
        Sniffs raw Layer-2 packets for duration seconds, returning triggered SynScanEvents.
        """
        events: List[SynScanEvent] = []
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
                target=self._sniff_loop, daemon=True, name="SynScanDetector"
            )
            self._thread.start()
            return True

    def stop(self):
        """Stops the background listener thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

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
