"""
Real-Time ARP Cache Poisoning & Gateway Masquerade Guard.
Passively sniffs Layer-2 ARP frames (EtherType 0x0806) to detect active
Adversary-in-the-Middle (MitM) attacks, gratuitous ARP floods, and gateway hijacking
(arpspoof, ettercap, bettercap).
MITRE ATT&CK T1557.002 (Adversary-in-the-Middle: ARP Poisoning).
"""

import collections
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class ArpPoisonEvent:
    """Represents a detected ARP cache poisoning or spoofing event."""

    def __init__(
        self,
        threat_type: str,
        spoofed_ip: str,
        attacker_mac: str,
        expected_mac: Optional[str] = None,
        eth_src_mac: Optional[str] = None,
        timestamp: float = 0.0,
        burst_count: int = 1,
    ):
        self.threat_type = threat_type
        self.spoofed_ip = spoofed_ip
        self.attacker_mac = attacker_mac.upper()
        self.expected_mac = expected_mac.upper() if expected_mac else None
        self.eth_src_mac = eth_src_mac.upper() if eth_src_mac else None
        self.timestamp = timestamp or time.time()
        self.burst_count = burst_count

    def to_threat_string(self) -> str:
        count_suffix = f" ({self.burst_count} packet burst)" if self.burst_count > 1 else ""

        if self.threat_type == "GATEWAY_POISONING":
            return (
                f"CRITICAL: Active ARP Cache Poisoning detected! "
                f"Host at {self.attacker_mac} is masquerading as default gateway {self.spoofed_ip}{count_suffix} "
                f"(Expected legitimate Gateway MAC: {self.expected_mac or 'Unknown'})! "
                f"Active Adversary-in-the-Middle attack (MITRE ATT&CK T1557.002)."
            )
        elif self.threat_type == "L2_MAC_MISMATCH":
            return (
                f"CRITICAL: Forged ARP Frame detected! "
                f"Ethernet frame from {self.eth_src_mac} contains conflicting ARP sender {self.attacker_mac} "
                f"claiming IP {self.spoofed_ip}{count_suffix}! "
                f"Hardware address spoofing in progress (MITRE ATT&CK T1557.002)."
            )
        elif self.threat_type == "IP_MAC_FLIP":
            return (
                f"CRITICAL: ARP Spoofing / IP Conflict detected! "
                f"Host at {self.attacker_mac} is claiming ownership of {self.spoofed_ip}{count_suffix} "
                f"(Previously bound to trusted host {self.expected_mac})! "
                f"Potential ARP cache poisoning or duplicate IP address."
            )
        elif self.threat_type == "GARP_FLOOD":
            return (
                f"WARNING: Gratuitous ARP Reply Flood detected! "
                f"Host at {self.attacker_mac} sent {self.burst_count} gratuitous ARP replies for "
                f"IP {self.spoofed_ip} in rapid succession! "
                f"Potential ARP cache poisoning attempt."
            )
        else:
            return (
                f"CRITICAL: ARP Anomaly detected on {self.spoofed_ip} from {self.attacker_mac}! "
                f"Potential ARP poisoning (MITRE ATT&CK T1557.002)."
            )


class ArpPoisonGuard:
    """
    Passively monitors Layer-2 ARP traffic for active cache poisoning,
    gateway impersonation, and gratuitous ARP floods.
    """

    SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_DROP_MEMBERSHIP = 2
    PACKET_MR_PROMISC = 1

    ETH_P_ARP = 0x0806

    def __init__(
        self,
        interface: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        trusted_ip_mac_map: Optional[Dict[str, str]] = None,
        garp_burst_threshold: int = 5,
        garp_window_seconds: float = 2.0,
        alert_cooldown: float = 30.0,
    ):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.upper() if gateway_mac else None
        self.trusted_ip_mac_map: Dict[str, str] = {}
        if trusted_ip_mac_map:
            self.trusted_ip_mac_map = {k: v.upper() for k, v in trusted_ip_mac_map.items() if v}

        self.garp_burst_threshold = garp_burst_threshold
        self.garp_window_seconds = garp_window_seconds
        self.alert_cooldown = alert_cooldown

        # Gratuitous ARP tracking: sender_mac -> list of timestamps
        self._garp_history: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        # Alert cooldown tracking: (threat_type, spoofed_ip, attacker_mac) -> timestamp
        self._last_alert_times: Dict[Tuple[str, str, str], float] = {}

        self._detected_events: List[ArpPoisonEvent] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def update_topology(
        self,
        gateway_ip: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        trusted_ip_mac_map: Optional[Dict[str, str]] = None,
    ):
        """Dynamically updates the known gateway and trusted device baseline."""
        with self._lock:
            if gateway_ip:
                self.gateway_ip = gateway_ip
            if gateway_mac:
                self.gateway_mac = gateway_mac.upper()
            if trusted_ip_mac_map:
                for ip, mac in trusted_ip_mac_map.items():
                    if mac and mac != "N/A" and "Asleep" not in mac:
                        self.trusted_ip_mac_map[ip] = mac.upper()

    @staticmethod
    def parse_arp_packet(pkt: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses raw Ethernet frame into ARP fields if EtherType == 0x0806.
        Returns parsed dict or None if invalid or non-ARP.
        """
        if len(pkt) < 42:  # 14 (Ethernet) + 28 (ARP)
            return None

        # Ethernet header (14 bytes)
        eth_dst_mac = ":".join(f"{b:02X}" for b in pkt[0:6])
        eth_src_mac = ":".join(f"{b:02X}" for b in pkt[6:12])
        ethertype = struct.unpack("!H", pkt[12:14])[0]

        if ethertype != ArpPoisonGuard.ETH_P_ARP:
            return None

        # ARP payload (28 bytes)
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", pkt[14:22])
        if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
            return None

        sender_mac = ":".join(f"{b:02X}" for b in pkt[22:28])
        sender_ip = socket.inet_ntoa(pkt[28:32])
        target_mac = ":".join(f"{b:02X}" for b in pkt[32:38])
        target_ip = socket.inet_ntoa(pkt[38:42])

        is_garp = (sender_ip == target_ip) or (op == 2 and eth_dst_mac == "FF:FF:FF:FF:FF:FF")

        return {
            "eth_src_mac": eth_src_mac,
            "eth_dst_mac": eth_dst_mac,
            "op": op,  # 1 = Request, 2 = Reply
            "sender_mac": sender_mac,
            "sender_ip": sender_ip,
            "target_mac": target_mac,
            "target_ip": target_ip,
            "is_garp": is_garp,
        }

    def process_packet(self, pkt: bytes, now: Optional[float] = None) -> Optional[ArpPoisonEvent]:
        """
        Processes a raw Ethernet frame. Returns an ArpPoisonEvent if active
        spoofing, gateway masquerade, or suspicious ARP manipulation is detected.
        """
        parsed = self.parse_arp_packet(pkt)
        if not parsed:
            return None

        if now is None:
            now = time.time()

        eth_src = parsed["eth_src_mac"].upper()
        sender_mac = parsed["sender_mac"].upper()
        sender_ip = parsed["sender_ip"]
        target_ip = parsed["target_ip"]
        op = parsed["op"]
        is_garp = parsed["is_garp"]

        with self._lock:
            # 1. Gateway Poisoning: sender_ip is gateway_ip but sender_mac != gateway_mac
            if self.gateway_ip and self.gateway_mac:
                if sender_ip == self.gateway_ip and sender_mac != self.gateway_mac:
                    key = ("GATEWAY_POISONING", sender_ip, sender_mac)
                    if now - self._last_alert_times.get(key, 0.0) >= self.alert_cooldown:
                        self._last_alert_times[key] = now
                        event = ArpPoisonEvent(
                            threat_type="GATEWAY_POISONING",
                            spoofed_ip=sender_ip,
                            attacker_mac=sender_mac,
                            expected_mac=self.gateway_mac,
                            eth_src_mac=eth_src,
                            timestamp=now,
                        )
                        self._detected_events.append(event)
                        return event

            # 2. Layer-2 Forgery: Ethernet source MAC differs from ARP payload sender MAC
            # (Excludes broadcast or zeroed source MACs)
            if eth_src != sender_mac and eth_src != "00:00:00:00:00:00":
                key = ("L2_MAC_MISMATCH", sender_ip, sender_mac)
                if now - self._last_alert_times.get(key, 0.0) >= self.alert_cooldown:
                    self._last_alert_times[key] = now
                    event = ArpPoisonEvent(
                        threat_type="L2_MAC_MISMATCH",
                        spoofed_ip=sender_ip,
                        attacker_mac=sender_mac,
                        expected_mac=None,
                        eth_src_mac=eth_src,
                        timestamp=now,
                    )
                    self._detected_events.append(event)
                    return event

            # 3. Known Whitelist Device Hijack: an ARP reply changes an existing trusted IP's MAC
            if op == 2 and sender_ip in self.trusted_ip_mac_map:
                expected = self.trusted_ip_mac_map[sender_ip]
                if expected and sender_mac != expected:
                    key = ("IP_MAC_FLIP", sender_ip, sender_mac)
                    if now - self._last_alert_times.get(key, 0.0) >= self.alert_cooldown:
                        self._last_alert_times[key] = now
                        event = ArpPoisonEvent(
                            threat_type="IP_MAC_FLIP",
                            spoofed_ip=sender_ip,
                            attacker_mac=sender_mac,
                            expected_mac=expected,
                            eth_src_mac=eth_src,
                            timestamp=now,
                        )
                        self._detected_events.append(event)
                        return event

            # 4. Gratuitous ARP Reply Flood
            if is_garp and op == 2:
                q = self._garp_history[sender_mac]
                q.append(now)
                cutoff = now - self.garp_window_seconds
                while q and q[0] < cutoff:
                    q.popleft()

                if len(q) >= self.garp_burst_threshold:
                    key = ("GARP_FLOOD", sender_ip, sender_mac)
                    if now - self._last_alert_times.get(key, 0.0) >= self.alert_cooldown:
                        self._last_alert_times[key] = now
                        event = ArpPoisonEvent(
                            threat_type="GARP_FLOOD",
                            spoofed_ip=sender_ip,
                            attacker_mac=sender_mac,
                            expected_mac=None,
                            eth_src_mac=eth_src,
                            timestamp=now,
                            burst_count=len(q),
                        )
                        self._detected_events.append(event)
                        return event

        return None

    def sniff(self, duration: float = 1.0) -> List[ArpPoisonEvent]:
        """
        Passively sniffs raw Layer-2 ARP traffic for duration seconds.
        """
        events: List[ArpPoisonEvent] = []
        raw_sock = None
        mreq = None

        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ARP))
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
                test_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ARP))
                test_sock.close()
            except Exception:
                return False

            self._running = True
            self._thread = threading.Thread(
                target=self._sniff_loop, daemon=True, name="ArpPoisonGuard"
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
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ARP))
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
