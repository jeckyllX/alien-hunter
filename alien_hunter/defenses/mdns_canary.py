"""
Multicast DNS (mDNS / Bonjour) Poisoning Canary Trap ("Anti-Responder").
Detects active local name resolution poisoners (e.g. Responder, Inveigh)
by broadcasting mDNS queries for fictitious canary hostnames on UDP 5353.
"""

import os
import socket
import struct
import time
from typing import List, Optional, Tuple

from ..scanners.net_utils import create_udp_socket


class MdnsCanaryTrap:
    """
    Emits canary mDNS queries for non-existent .local hostnames.
    Any affirmative response indicates an active adversary poisoning
    multicast DNS queries to harvest credentials or conduct MitM attacks (MITRE ATT&CK T1557.001).
    """

    MDNS_GROUP = "224.0.0.251"
    MDNS_PORT = 5353

    @staticmethod
    def _encode_dns_label(name: str) -> bytes:
        """Encodes dot-separated domain name into DNS length-prefixed format."""
        parts = name.strip(".").split(".")
        out = bytearray()
        for p in parts:
            b = p.encode("utf-8")
            out.append(len(b))
            out.extend(b)
        out.append(0)
        return bytes(out)

    @classmethod
    def build_mdns_query(cls, hostname: str, trans_id: int = 0) -> bytes:
        """
        Constructs an RFC 6762 Multicast DNS query packet.
        Uses unicast-response requested bit (QU=1, QCLASS 0x8001) so the attacker
        responds directly back to our ephemeral listening socket.
        """
        # Header: ID, Flags (0x0000 = Standard Query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        header = struct.pack("!HHHHHH", trans_id, 0x0000, 1, 0, 0, 0)
        domain = f"{hostname}.local" if not hostname.endswith(".local") else hostname
        qname = cls._encode_dns_label(domain)
        # QTYPE=1 (A), QCLASS=0x8001 (IN with unicast-response requested)
        question = qname + struct.pack("!HH", 1, 0x8001)
        return header + question

    @staticmethod
    def _parse_dns_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
        """Safely extracts a DNS label sequence, following RFC 1035 compression pointers."""
        if depth > 10:
            return "", offset

        labels: List[str] = []
        jumped = False
        next_offset = offset

        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                if not jumped:
                    next_offset = offset
                break

            # Compression pointer: top 2 bits set (0xC0)
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
                if not jumped:
                    next_offset = offset + 2
                    jumped = True
                pointed_name, _ = MdnsCanaryTrap._parse_dns_name(data, pointer, depth + 1)
                labels.append(pointed_name)
                break
            else:
                offset += 1
                if offset + length > len(data):
                    break
                labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
                offset += length

        res_name = ".".join([lbl for lbl in labels if lbl])
        return res_name, next_offset if jumped else offset

    @classmethod
    def check_poisoning(
        cls,
        interface: Optional[str] = None,
        timeout: float = 1.0,
    ) -> List[str]:
        """
        Transmits an mDNS query for a fictitious canary hostname to 224.0.0.251:5353.
        Listens for affirmative responses. Returns threat descriptions if an attacker responds.
        """
        threats: List[str] = []
        canary_token = os.urandom(4).hex()
        canary_hostname = f"canary-srv-{canary_token}"
        canary_domain = f"{canary_hostname}.local"

        trans_id = struct.unpack("!H", os.urandom(2))[0]
        query_pkt = cls.build_mdns_query(canary_hostname, trans_id=trans_id)

        sock = None
        try:
            sock = create_udp_socket(interface=interface, broadcast=True, timeout=0.3)
            # RFC 6762 requirement: IP_MULTICAST_TTL MUST be 255
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

            # Send canary query to multicast group
            sock.sendto(query_pkt, (cls.MDNS_GROUP, cls.MDNS_PORT))

            start_time = time.time()
            detected_attackers: List[Tuple[str, str]] = []  # (attacker_ip, spoofed_ip)

            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    attacker_ip = addr[0]

                    if len(data) < 12:
                        continue

                    _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
                    # Must be a DNS response (QR bit set) with at least 1 answer
                    if not (flags & 0x8000) or ancount == 0:
                        continue

                    offset = 12
                    # Skip Question section
                    for _ in range(qdcount):
                        if offset >= len(data):
                            break
                        _, offset = cls._parse_dns_name(data, offset)
                        offset += 4  # QTYPE (2) + QCLASS (2)

                    # Inspect Answer records
                    matched_canary = False
                    spoofed_ip = ""

                    for _ in range(ancount):
                        if offset >= len(data):
                            break
                        record_name, offset = cls._parse_dns_name(data, offset)
                        if offset + 10 > len(data):
                            break
                        rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
                        offset += 10
                        rdata = data[offset : offset + rdlen]
                        offset += rdlen

                        # Check if answered domain matches our unique canary token
                        if canary_token.lower() in record_name.lower():
                            matched_canary = True
                            if rtype == 1 and len(rdata) == 4:  # Type A (IPv4)
                                spoofed_ip = socket.inet_ntoa(rdata)

                    # Fallback check: look for canary token string in payload if parser encountered unusual compression
                    if not matched_canary and canary_token.encode("utf-8") in data[12:]:
                        matched_canary = True

                    if matched_canary:
                        detected_attackers.append((attacker_ip, spoofed_ip))

                except (socket.timeout, BlockingIOError):
                    continue
                except Exception:
                    break

            for attacker_ip, spoofed_ip in detected_attackers:
                spoof_info = f" (Spoofed Address: {spoofed_ip})" if spoofed_ip else ""
                threats.append(
                    f"CRITICAL: Active mDNS / Bonjour Poisoning Detected! "
                    f"Host at {attacker_ip} fraudulently claimed ownership of fictitious canary host '{canary_domain}'{spoof_info}. "
                    f"Active internal attacker or automated credential harvesting tool (e.g. Responder / Inveigh) confirmed on LAN!"
                )

        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return threats
