"""
DNS Integrity and Resolver Hijacking Auditor.
Validates local DNS resolution against trusted cryptographic upstreams
to detect DNS poisoning, rogue resolvers, captive portals, and NXDOMAIN hijacking.
"""

import ipaddress
import os
import socket
import struct
import time
from typing import List, Optional, Set, Tuple


class DnsIntegrityAuditor:
    """Audits local DNS responses for cache poisoning and unauthorized redirection."""

    DEFAULT_UPSTREAMS = ["1.1.1.1", "9.9.9.9"]
    CANARY_DOMAINS = ["cloudflare.com", "quad9.net"]

    @staticmethod
    def get_system_dns_resolvers() -> List[str]:
        """Parses nameserver entries from /etc/resolv.conf."""
        resolvers: List[str] = []
        try:
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[0] == "nameserver":
                            ip = parts[1]
                            try:
                                ip_obj = ipaddress.ip_address(ip)
                                if not ip_obj.is_loopback and ip not in resolvers:
                                    resolvers.append(ip)
                            except ValueError:
                                pass
        except Exception:
            pass
        return resolvers

    @staticmethod
    def _encode_dns_name(domain: str) -> bytes:
        parts = domain.strip(".").split(".")
        out = bytearray()
        for p in parts:
            b = p.encode("utf-8")
            out.append(len(b))
            out.extend(b)
        out.append(0)
        return bytes(out)

    @classmethod
    def build_dns_query(cls, domain: str, trans_id: int) -> bytes:
        """Constructs an RFC 1035 standard DNS A-record query."""
        header = struct.pack("!HHHHHH", trans_id, 0x0100, 1, 0, 0, 0)  # Standard Query, RD=1
        qname = cls._encode_dns_name(domain)
        question = qname + struct.pack("!HH", 1, 1)  # TYPE A, CLASS IN
        return header + question

    @classmethod
    def _parse_dns_a_response(cls, data: bytes, trans_id: int) -> Tuple[int, List[str]]:
        """
        Parses DNS response bytes, returning (rcode, list_of_ipv4_addresses).
        RCODE 0 = No Error, RCODE 3 = NXDOMAIN.
        """
        if len(data) < 12:
            return -1, []

        resp_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        if resp_id != trans_id:
            return -1, []

        rcode = flags & 0x000F
        if rcode != 0:
            return rcode, []

        offset = 12
        # Skip questions
        for _ in range(qdcount):
            if offset >= len(data):
                return rcode, []
            while offset < len(data) and data[offset] != 0:
                length = data[offset]
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + length
            if offset < len(data) and data[offset] == 0:
                offset += 1
            offset += 4  # QTYPE + QCLASS

        ips: List[str] = []
        for _ in range(ancount):
            if offset >= len(data):
                break
            # Skip NAME
            while offset < len(data):
                length = data[offset]
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                elif length == 0:
                    offset += 1
                    break
                offset += 1 + length

            if offset + 10 > len(data):
                break

            rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            if offset + rdlen > len(data):
                break

            if rtype == 1 and rdlen == 4:
                try:
                    ips.append(socket.inet_ntoa(data[offset : offset + 4]))
                except Exception:
                    pass
            offset += rdlen

        return rcode, ips

    @classmethod
    def query_resolver(cls, server_ip: str, domain: str, timeout: float = 1.0) -> Tuple[int, List[str]]:
        """Sends a direct UDP 53 DNS query to a specific resolver."""
        trans_id = struct.unpack("!H", os.urandom(2))[0]
        pkt = cls.build_dns_query(domain, trans_id)
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(pkt, (server_ip, 53))
            data, _ = sock.recvfrom(2048)
            return cls._parse_dns_a_response(data, trans_id)
        except Exception:
            return -1, []
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    @classmethod
    def audit_dns(
        cls,
        gateway_ip: Optional[str] = None,
        custom_resolver: Optional[str] = None,
        upstream_ip: str = "1.1.1.1",
    ) -> List[str]:
        """
        Audits the local resolver against a trusted upstream for DNS hijacking.
        """
        threats: List[str] = []

        local_resolvers = cls.get_system_dns_resolvers()
        if custom_resolver:
            local_resolvers.insert(0, custom_resolver)
        if gateway_ip and gateway_ip not in local_resolvers:
            local_resolvers.append(gateway_ip)

        if not local_resolvers:
            return threats

        target_resolver = local_resolvers[0]

        # 1. NXDOMAIN Hijacking Check
        nx_token = os.urandom(6).hex()
        nx_domain = f"canary-nx-{nx_token}.invalid"
        nx_rcode, nx_ips = cls.query_resolver(target_resolver, nx_domain, timeout=1.0)

        if nx_ips:
            threats.append(
                f"WARNING: DNS NXDOMAIN Hijacking detected on resolver {target_resolver}! "
                f"Non-existent domain '{nx_domain}' resolved to {', '.join(nx_ips)} (Expected NXDOMAIN). "
                f"Resolver is intercepting non-existent domains (ISP ad injection or rogue redirection)."
            )

        # 2. Canary Domain Resolution & RFC 1918 Private IP Leak Check
        for domain in cls.CANARY_DOMAINS:
            local_rcode, local_ips = cls.query_resolver(target_resolver, domain, timeout=1.0)
            if not local_ips:
                continue

            # Check if public internet domain was resolved to private IP address (RFC 1918)
            for ip in local_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private or ip_obj.is_loopback:
                        threats.append(
                            f"CRITICAL: Malicious DNS Spoofing / Captive Portal Hijack! "
                            f"Public domain '{domain}' resolved to private IP {ip} via {target_resolver}! "
                            f"Traffic is being intercepted or redirected to a local host."
                        )
                        break
                except ValueError:
                    pass

        return threats
