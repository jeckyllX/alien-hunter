"""
Active ARP Self-Healing & IPS Counter-Poisoning Subsystem.
Constructs and transmits authoritative Gratuitous ARP (GARP) frames onto Layer-2
subnets to actively neutralize Adversary-in-the-Middle (MitM) ARP poisoning
attacks in real time (arpspoof, ettercap, bettercap).
MITRE ATT&CK T1557.002 (Adversary-in-the-Middle: ARP Poisoning).
"""

import collections
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


class ArpHealAction:
    """Represents a recorded ARP self-healing intervention."""

    def __init__(
        self,
        spoofed_ip: str,
        legitimate_mac: str,
        attacker_mac: Optional[str],
        threat_type: str,
        frames_sent: int,
        timestamp: float = 0.0,
    ):
        self.spoofed_ip = spoofed_ip
        self.legitimate_mac = legitimate_mac.upper()
        self.attacker_mac = attacker_mac.upper() if attacker_mac else None
        self.threat_type = threat_type
        self.frames_sent = frames_sent
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spoofed_ip": self.spoofed_ip,
            "legitimate_mac": self.legitimate_mac,
            "attacker_mac": self.attacker_mac,
            "threat_type": self.threat_type,
            "frames_sent": self.frames_sent,
            "timestamp": self.timestamp,
        }

    def to_log_string(self) -> str:
        attacker_info = f" (disrupting attacker {self.attacker_mac})" if self.attacker_mac else ""
        return (
            f"IPS REMEDIATION: Broadcast {self.frames_sent} authoritative Gratuitous ARP reply frame(s) "
            f"for {self.spoofed_ip} -> {self.legitimate_mac}{attacker_info}. "
            f"Subnet neighbor caches restored."
        )


class ArpSelfHealing:
    """
    Active Layer-2 IPS module that crafts and transmits authoritative Gratuitous ARP
    announcements to overwrite poisoned host caches and neutralize MitM attacks.
    """

    ETH_P_ARP = 0x0806

    def __init__(
        self,
        interface: Optional[str] = None,
        burst_count: int = 3,
        burst_interval: float = 0.04,
        cooldown_seconds: float = 2.0,
    ):
        self.interface = interface
        self.burst_count = burst_count
        self.burst_interval = burst_interval
        self.cooldown_seconds = cooldown_seconds

        # Rate limiting: (spoofed_ip, legitimate_mac) -> last_heal_time
        self._last_heal_times: Dict[Tuple[str, str], float] = collections.defaultdict(float)
        self._heal_history: collections.deque = collections.deque(maxlen=100)
        self._lock = threading.Lock()

    @classmethod
    def build_gratuitous_arp(
        cls,
        ip: str,
        mac: str,
        opcode: int = 2,
        target_mac: Optional[str] = None,
    ) -> bytes:
        """
        Builds a standard RFC 826 Gratuitous ARP frame (14 bytes Eth + 28 bytes ARP = 42 bytes).
        Opcode: 1 = Request, 2 = Reply (Reply is default for authoritative cache overwrites).
        """
        clean_mac = mac.replace(":", "").replace("-", "")
        mac_bytes = bytes.fromhex(clean_mac)

        if target_mac:
            clean_target = target_mac.replace(":", "").replace("-", "")
            target_mac_bytes = bytes.fromhex(clean_target)
            eth_dst = target_mac_bytes
        else:
            target_mac_bytes = b"\xff\xff\xff\xff\xff\xff"
            eth_dst = b"\xff\xff\xff\xff\xff\xff"

        ip_bytes = socket.inet_aton(ip)

        # 14-byte Ethernet Header
        eth_hdr = eth_dst + mac_bytes + struct.pack("!H", cls.ETH_P_ARP)

        # 28-byte ARP Payload
        arp_payload = struct.pack(
            "!HHBBH6s4s6s4s",
            1,  # Hardware Type: Ethernet
            0x0800,  # Protocol Type: IPv4
            6,  # Hardware Length
            4,  # Protocol Length
            opcode,  # 2 = Reply, 1 = Request
            mac_bytes,  # Sender MAC: Legitimate MAC
            ip_bytes,  # Sender IP: Legitimate IP
            target_mac_bytes,  # Target MAC
            ip_bytes,  # Target IP: Same as Sender IP for GARP
        )

        return eth_hdr + arp_payload

    def heal(
        self,
        spoofed_ip: str,
        legitimate_mac: str,
        attacker_mac: Optional[str] = None,
        threat_type: str = "GATEWAY_POISONING",
        now: Optional[float] = None,
        raw_socket: Optional[socket.socket] = None,
    ) -> Optional[ArpHealAction]:
        """
        Injects an authoritative burst of Gratuitous ARP frames to overwrite poisoned caches.
        Enforces a cooldown to prevent excessive packet injection during sustained floods.
        """
        if now is None:
            now = time.time()

        key = (spoofed_ip, legitimate_mac.upper())
        with self._lock:
            last_time = self._last_heal_times.get(key, 0.0)
            if now - last_time < self.cooldown_seconds:
                return None
            self._last_heal_times[key] = now

        # Construct authoritative Gratuitous ARP reply frame
        frame = self.build_gratuitous_arp(ip=spoofed_ip, mac=legitimate_mac, opcode=2)

        sent_count = 0
        sock = raw_socket
        opened_internal_sock = False

        try:
            if not sock:
                try:
                    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                    opened_internal_sock = True
                    if self.interface:
                        sock.bind((self.interface, 0))
                except Exception:
                    sock = None

            if sock:
                for i in range(self.burst_count):
                    try:
                        if self.interface:
                            sock.sendto(frame, (self.interface, 0))
                        else:
                            sock.send(frame)
                        sent_count += 1
                    except Exception:
                        break

                    if i < self.burst_count - 1 and self.burst_interval > 0:
                        time.sleep(self.burst_interval)
        finally:
            if opened_internal_sock and sock:
                try:
                    sock.close()
                except Exception:
                    pass

        action = ArpHealAction(
            spoofed_ip=spoofed_ip,
            legitimate_mac=legitimate_mac,
            attacker_mac=attacker_mac,
            threat_type=threat_type,
            frames_sent=sent_count,
            timestamp=now,
        )

        with self._lock:
            self._heal_history.append(action)

        return action

    def heal_event(
        self,
        event: Any,
        now: Optional[float] = None,
        raw_socket: Optional[socket.socket] = None,
    ) -> Optional[ArpHealAction]:
        """
        Evaluates an ArpPoisonEvent and triggers immediate self-healing if expected MAC is available.
        """
        expected_mac = getattr(event, "expected_mac", None)
        spoofed_ip = getattr(event, "spoofed_ip", None)
        threat_type = getattr(event, "threat_type", "UNKNOWN")
        attacker_mac = getattr(event, "attacker_mac", None)

        if not spoofed_ip or not expected_mac:
            return None

        # Only heal if we have an authoritative expected MAC mapping (GATEWAY_POISONING or IP_MAC_FLIP)
        if threat_type not in ("GATEWAY_POISONING", "IP_MAC_FLIP"):
            return None

        return self.heal(
            spoofed_ip=spoofed_ip,
            legitimate_mac=expected_mac,
            attacker_mac=attacker_mac,
            threat_type=threat_type,
            now=now,
            raw_socket=raw_socket,
        )

    def get_healing_history(self) -> List[Dict[str, Any]]:
        """Returns snapshot of recent self-healing actions."""
        with self._lock:
            return [a.to_dict() for a in self._heal_history]
