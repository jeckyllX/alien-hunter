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

from .arp_healing import ArpSelfHealing
from ..scanners.net_utils import disable_promiscuous_mode, enable_promiscuous_mode


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
    MAX_GARP_TRACKED_MACS = 1024
    MAX_GARP_TIMESTAMPS_PER_MAC = 128
    MAX_ALERT_COOLDOWN_KEYS = 2048

    def __init__(
        self,
        interface: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        trusted_ip_mac_map: Optional[Dict[str, str]] = None,
        garp_burst_threshold: int = 5,
        garp_window_seconds: float = 2.0,
        alert_cooldown: float = 30.0,
        self_healing_enabled: bool = True,
        healer: Optional[ArpSelfHealing] = None,
        history_maxlen: int = 250,
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
        self.self_healing_enabled = self_healing_enabled
        self.history_maxlen = history_maxlen
        self.healer: Optional[ArpSelfHealing] = healer or (
            ArpSelfHealing(interface=self.interface) if self_healing_enabled else None
        )

        # Gratuitous ARP tracking: sender_mac -> bounded deque of timestamps
        self._garp_history: "collections.OrderedDict[str, collections.deque]" = collections.OrderedDict()
        # Alert cooldown tracking: (threat_type, spoofed_ip, attacker_mac) -> timestamp
        self._last_alert_times: Dict[Tuple[str, str, str], float] = {}

        self._detected_events: collections.deque = collections.deque(maxlen=history_maxlen)
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
            if trusted_ip_mac_map is not None:
                new_map = {}
                for ip, mac in trusted_ip_mac_map.items():
                    if mac and mac != "N/A" and "Asleep" not in mac:
                        new_map[ip] = mac.upper()
                self.trusted_ip_mac_map = new_map

            if self.healer and self.interface:
                self.healer.interface = self.interface

    @property
    def is_self_healing_enabled(self) -> bool:
        return self.self_healing_enabled and self.healer is not None

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

    def _check_and_update_cooldown(self, key: Tuple[str, str, str], now: float) -> bool:
        """Checks alert cooldown and bounds stored cooldown keys."""
        last_ts = self._last_alert_times.get(key, 0.0)
        if last_ts > 0.0 and now - last_ts < self.alert_cooldown:
            return False
        if key not in self._last_alert_times and len(self._last_alert_times) >= self.MAX_ALERT_COOLDOWN_KEYS:
            expired = [k for k, ts in self._last_alert_times.items() if now - ts >= self.alert_cooldown]
            for ek in expired:
                del self._last_alert_times[ek]
            if len(self._last_alert_times) >= self.MAX_ALERT_COOLDOWN_KEYS:
                oldest = min(self._last_alert_times, key=self._last_alert_times.__getitem__)
                self._last_alert_times.pop(oldest, None)
        self._last_alert_times[key] = now
        return True

    def process_packet(self, pkt: bytes, now: Optional[float] = None) -> Optional[ArpPoisonEvent]:
        """
        Processes a raw Ethernet frame. Returns an ArpPoisonEvent if active
        spoofing, gateway masquerade, or suspicious ARP manipulation is detected.
        Triggers active self-healing if enabled.
        """
        parsed = self.parse_arp_packet(pkt)
        if not parsed:
            return None

        if now is None:
            now = time.time()

        eth_src = parsed["eth_src_mac"].upper()
        sender_mac = parsed["sender_mac"].upper()
        sender_ip = parsed["sender_ip"]
        op = parsed["op"]
        is_garp = parsed["is_garp"]

        heal_args: Optional[Tuple[str, str, str, str]] = None
        healer: Optional[ArpSelfHealing] = None
        event: Optional[ArpPoisonEvent] = None

        with self._lock:
            healer = self.healer
            # 1. Gateway Poisoning: sender_ip is gateway_ip but sender_mac != gateway_mac
            if self.gateway_ip and self.gateway_mac and sender_ip == self.gateway_ip and sender_mac != self.gateway_mac:
                if healer:
                    heal_args = (sender_ip, self.gateway_mac, sender_mac, "GATEWAY_POISONING")
                key = ("GATEWAY_POISONING", sender_ip, sender_mac)
                if self._check_and_update_cooldown(key, now):
                    event = ArpPoisonEvent(
                        threat_type="GATEWAY_POISONING",
                        spoofed_ip=sender_ip,
                        attacker_mac=sender_mac,
                        expected_mac=self.gateway_mac,
                        eth_src_mac=eth_src,
                        timestamp=now,
                    )
                    self._detected_events.append(event)

            # 2. Layer-2 Forgery: Ethernet source MAC differs from ARP payload sender MAC
            elif eth_src != sender_mac and eth_src != "00:00:00:00:00:00":
                key = ("L2_MAC_MISMATCH", sender_ip, sender_mac)
                if self._check_and_update_cooldown(key, now):
                    event = ArpPoisonEvent(
                        threat_type="L2_MAC_MISMATCH",
                        spoofed_ip=sender_ip,
                        attacker_mac=sender_mac,
                        expected_mac=None,
                        eth_src_mac=eth_src,
                        timestamp=now,
                    )
                    self._detected_events.append(event)

            # 3. Known Whitelist Device Hijack: an ARP reply changes an existing trusted IP's MAC
            elif op == 2 and sender_ip in self.trusted_ip_mac_map and self.trusted_ip_mac_map[sender_ip] and sender_mac != self.trusted_ip_mac_map[sender_ip]:
                expected = self.trusted_ip_mac_map[sender_ip]
                if healer:
                    heal_args = (sender_ip, expected, sender_mac, "IP_MAC_FLIP")
                key = ("IP_MAC_FLIP", sender_ip, sender_mac)
                if self._check_and_update_cooldown(key, now):
                    event = ArpPoisonEvent(
                        threat_type="IP_MAC_FLIP",
                        spoofed_ip=sender_ip,
                        attacker_mac=sender_mac,
                        expected_mac=expected,
                        eth_src_mac=eth_src,
                        timestamp=now,
                    )
                    self._detected_events.append(event)

            # 4. Gratuitous ARP Reply Flood
            elif is_garp and op == 2:
                if sender_mac in self._garp_history:
                    q = self._garp_history[sender_mac]
                    self._garp_history.move_to_end(sender_mac)
                else:
                    if len(self._garp_history) >= self.MAX_GARP_TRACKED_MACS:
                        cutoff_prune = now - self.garp_window_seconds
                        stale_macs = [
                            m for m, dq in self._garp_history.items()
                            if not dq or dq[-1] < cutoff_prune
                        ]
                        for sm in stale_macs:
                            del self._garp_history[sm]
                        if len(self._garp_history) >= self.MAX_GARP_TRACKED_MACS:
                            self._garp_history.popitem(last=False)
                    q = collections.deque(maxlen=self.MAX_GARP_TIMESTAMPS_PER_MAC)
                    self._garp_history[sender_mac] = q

                q.append(now)
                cutoff = now - self.garp_window_seconds
                while q and q[0] < cutoff:
                    q.popleft()

                if len(q) >= self.garp_burst_threshold:
                    key = ("GARP_FLOOD", sender_ip, sender_mac)
                    if self._check_and_update_cooldown(key, now):
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

        if heal_args and healer:
            spoofed_ip, legitimate_mac, atk_mac, ttype = heal_args
            healer.heal(
                spoofed_ip=spoofed_ip,
                legitimate_mac=legitimate_mac,
                attacker_mac=atk_mac,
                threat_type=ttype,
                now=now,
            )

        return event

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
                mreq = enable_promiscuous_mode(
                    raw_sock,
                    self.interface,
                    sol_packet=self.SOL_PACKET,
                    packet_add_membership=self.PACKET_ADD_MEMBERSHIP,
                    packet_mr_promisc=self.PACKET_MR_PROMISC,
                )

            raw_sock.settimeout(0.25)
            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    pkt, addr = raw_sock.recvfrom(2048)
                    if isinstance(addr, tuple) and len(addr) >= 3 and addr[2] in (4, 5):
                        continue
                    ev = self.process_packet(pkt)
                    if ev:
                        events.append(ev)
                except socket.timeout:
                    continue
        except Exception:
            pass
        finally:
            if raw_sock:
                disable_promiscuous_mode(
                    raw_sock,
                    mreq,
                    sol_packet=self.SOL_PACKET,
                    packet_drop_membership=self.PACKET_DROP_MEMBERSHIP,
                )
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
            self._thread.join(timeout=1.5)

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
                mreq = enable_promiscuous_mode(
                    raw_sock,
                    self.interface,
                    sol_packet=self.SOL_PACKET,
                    packet_add_membership=self.PACKET_ADD_MEMBERSHIP,
                    packet_mr_promisc=self.PACKET_MR_PROMISC,
                )

            raw_sock.settimeout(0.25)
            while self._running:
                try:
                    pkt, addr = raw_sock.recvfrom(2048)
                    if isinstance(addr, tuple) and len(addr) >= 3 and addr[2] in (4, 5):
                        continue
                    self.process_packet(pkt)
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            self._running = False
            if raw_sock:
                disable_promiscuous_mode(
                    raw_sock,
                    mreq,
                    sol_packet=self.SOL_PACKET,
                    packet_drop_membership=self.PACKET_DROP_MEMBERSHIP,
                )
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
