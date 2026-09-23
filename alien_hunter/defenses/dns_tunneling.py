"""
High-Entropy DNS Tunneling & Covert Exfiltration Detector.
Passively inspects UDP port 53 DNS queries to identify abnormal subdomain label lengths,
high Shannon entropy payloads, and covert C2 data channels (iodine, dnscat2, Cobalt Strike).
MITRE ATT&CK T1071.004 (DNS C2) and T1048.003 (Exfiltration Over DNS).
"""

import collections
import ipaddress
import math
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class DnsTunnelingEvent:
    """Represents a detected high-entropy DNS tunneling or exfiltration query."""

    def __init__(
        self,
        src_ip: str,
        src_mac: str,
        query_domain: str,
        longest_label: str,
        label_length: int,
        entropy: float,
        qtype: int,
        timestamp: float,
        query_count: int = 1,
    ):
        self.src_ip = src_ip
        self.src_mac = src_mac
        self.query_domain = query_domain
        self.longest_label = longest_label
        self.label_length = label_length
        self.entropy = entropy
        self.qtype = qtype
        self.timestamp = timestamp
        self.query_count = query_count

    @property
    def qtype_name(self) -> str:
        qtypes = {1: "A", 28: "AAAA", 16: "TXT", 10: "NULL", 5: "CNAME", 15: "MX", 12: "PTR"}
        return qtypes.get(self.qtype, f"TYPE_{self.qtype}")

    def to_threat_string(self) -> str:
        count_str = f" ({self.query_count} queries observed)" if self.query_count > 1 else ""
        return (
            f"CRITICAL: High-Entropy DNS Tunneling / Exfiltration detected! "
            f"Host at {self.src_ip} ({self.src_mac}) queried '{self.query_domain}'{count_str} "
            f"[Entropy: {self.entropy:.2f}, Subdomain Length: {self.label_length}, QType: {self.qtype_name}]! "
            f"Potential C2 beaconing or covert data exfiltration (MITRE ATT&CK T1071.004, T1048.003)."
        )


class DnsTunnelingDetector:
    """
    Passively monitors Layer-2 DNS traffic for covert protocol tunneling,
    data exfiltration, and DGA malware using Shannon entropy heuristics.
    """

    SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_DROP_MEMBERSHIP = 2
    PACKET_MR_PROMISC = 1

    DEFAULT_WHITELIST_SUFFIXES = {
        "in-addr.arpa",
        "ip6.arpa",
        "akamaiedge.net",
        "cloudfront.net",
        "trafficmanager.net",
        "1e100.net",
        "azureedge.net",
        "googleusercontent.com",
        "amazonaws.com",
    }

    def __init__(
        self,
        interface: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_mac: Optional[str] = None,
        entropy_threshold: float = 3.8,
        length_threshold: int = 30,
        burst_threshold: int = 3,
        window_seconds: float = 30.0,
        alert_cooldown: float = 30.0,
        custom_whitelist: Optional[List[str]] = None,
    ):
        self.interface = interface
        self.subnet_cidr = subnet_cidr
        self.local_ip = local_ip
        self.local_mac = local_mac.upper() if local_mac else None
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.burst_threshold = burst_threshold
        self.window_seconds = window_seconds
        self.alert_cooldown = alert_cooldown

        self.whitelist_suffixes = set(self.DEFAULT_WHITELIST_SUFFIXES)
        if custom_whitelist:
            self.whitelist_suffixes.update(s.lower().strip() for s in custom_whitelist)

        self._local_network = None
        if subnet_cidr:
            try:
                self._local_network = ipaddress.ip_network(subnet_cidr, strict=False)
            except Exception:
                self._local_network = None

        # State tracking: src_ip -> list of query records
        self._queries: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
        self._last_alert_time: Dict[str, float] = {}
        self._detected_events: List[DnsTunnelingEvent] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        Calculates Shannon entropy: H = - sum(p * log2(p)).
        Higher values indicate high randomness typical of base64/hex encoded data.
        """
        if not text:
            return 0.0
        length = len(text)
        counts = collections.Counter(text.lower())
        entropy = 0.0
        for cnt in counts.values():
            p = cnt / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    @staticmethod
    def parse_dns_packet(pkt: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses raw Ethernet frame into protocol fields if it contains an IPv4 UDP DNS query.
        Returns parsed dict or None if invalid or non-DNS.
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
        if ihl < 20 or len(pkt) < 14 + ihl + 8 + 12:
            return None

        proto = pkt[23]
        if proto != 17:  # IPPROTO_UDP
            return None

        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])

        # UDP header (starts at 14 + ihl, 8 bytes)
        udp_off = 14 + ihl
        src_port, dst_port = struct.unpack("!HH", pkt[udp_off : udp_off + 4])
        if dst_port != 53 and src_port != 53:
            return None

        # DNS message body (starts at udp_off + 8)
        dns_data = pkt[udp_off + 8 :]
        if len(dns_data) < 12:
            return None

        trans_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", dns_data[:12])
        # Only inspect standard queries (QR bit = 0) with at least 1 question
        if (flags & 0x8000) != 0 or qdcount < 1:
            return None

        # Parse question section labels
        idx = 12
        labels = []
        while idx < len(dns_data):
            length = dns_data[idx]
            if length == 0:
                idx += 1
                break
            if (length & 0xC0) == 0xC0:
                idx += 2
                break
            idx += 1
            if idx + length > len(dns_data):
                return None
            labels.append(dns_data[idx : idx + length].decode("utf-8", errors="replace"))
            idx += length

        if idx + 4 > len(dns_data):
            return None

        qtype, qclass = struct.unpack("!HH", dns_data[idx : idx + 4])
        query_domain = ".".join(labels)
        longest_label = max(labels, key=len) if labels else ""

        return {
            "src_mac": src_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "query_domain": query_domain,
            "labels": labels,
            "longest_label": longest_label,
            "qtype": qtype,
            "qclass": qclass,
        }

    def process_packet(
        self, pkt: bytes, now: Optional[float] = None
    ) -> Optional[DnsTunnelingEvent]:
        """
        Inspects an observed frame for high-entropy DNS tunneling queries.
        Returns DnsTunnelingEvent if an exfiltration threshold is exceeded.
        """
        parsed = self.parse_dns_packet(pkt)
        if not parsed:
            return None

        src_ip = parsed["src_ip"]
        src_mac = parsed["src_mac"]
        query_domain = parsed["query_domain"]
        longest_label = parsed["longest_label"]
        qtype = parsed["qtype"]

        # Filter out self-originated queries
        if self.local_ip and src_ip == self.local_ip:
            return None
        if self.local_mac and src_mac == self.local_mac:
            return None

        domain_lower = query_domain.lower()

        # Whitelist filtering for legitimate reverse DNS and infrastructure CDNs
        for suffix in self.whitelist_suffixes:
            if domain_lower == suffix or domain_lower.endswith(f".{suffix}"):
                return None

        label_len = len(longest_label)
        if label_len < 18:
            return None

        entropy = self.calculate_shannon_entropy(longest_label)

        # Tunnel evaluation:
        # 1. High-confidence large payload: label >= 35 and entropy >= 3.9
        # 2. Covert TXT (16) or NULL (10) record tunneling: label >= 24 and entropy >= 3.6
        # 3. Burst rate threshold: label >= length_threshold and entropy >= entropy_threshold
        is_immediate = False
        if label_len >= 35 and entropy >= 3.9:
            is_immediate = True
        elif qtype in (10, 16) and label_len >= 24 and entropy >= 3.6:
            is_immediate = True
        elif label_len >= self.length_threshold and entropy >= self.entropy_threshold:
            pass
        else:
            return None

        if now is None:
            now = time.time()

        with self._lock:
            cutoff = now - self.window_seconds
            queries = [q for q in self._queries[src_ip] if q["timestamp"] >= cutoff]
            queries.append(
                {
                    "timestamp": now,
                    "domain": query_domain,
                    "label_len": label_len,
                    "entropy": entropy,
                    "qtype": qtype,
                }
            )
            self._queries[src_ip] = queries

            # Trigger condition: immediate high-confidence or burst threshold reached
            if is_immediate or len(queries) >= self.burst_threshold:
                last_alert = self._last_alert_time.get(src_ip, 0.0)
                if now - last_alert >= self.alert_cooldown:
                    self._last_alert_time[src_ip] = now
                    event = DnsTunnelingEvent(
                        src_ip=src_ip,
                        src_mac=src_mac,
                        query_domain=query_domain,
                        longest_label=longest_label,
                        label_length=label_len,
                        entropy=entropy,
                        qtype=qtype,
                        timestamp=now,
                        query_count=len(queries),
                    )
                    self._detected_events.append(event)
                    return event

        return None

    def sniff(self, duration: float = 2.0) -> List[DnsTunnelingEvent]:
        """
        Passively sniffs raw Layer-2 DNS packets for duration seconds.
        """
        events: List[DnsTunnelingEvent] = []
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
                target=self._sniff_loop, daemon=True, name="DnsTunnelingDetector"
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
