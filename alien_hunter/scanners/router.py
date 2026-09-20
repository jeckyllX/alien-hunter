"""
Gateway DHCP and DNS Lease Auditor.
Directly interrogates the local router's DNS server to uncover registered hostnames
and DHCP leases for sleeping, firewalled, or power-saving mobile devices.
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional, Tuple


class RouterDnsAuditor:
    """Interrogates gateway DNS (reverse PTR) to identify all assigned DHCP client leases."""

    def __init__(self, gateway_ip: Optional[str] = None):
        self.gateway_ip = gateway_ip

    @staticmethod
    def parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
        """Parses a DNS name from raw wire bytes, following compression pointers (0xC0)."""
        labels = []
        visited = set()
        p = offset

        while p < len(data):
            if p in visited:
                break
            visited.add(p)
            length = data[p]

            if length == 0:
                p += 1
                break
            elif (length & 0xC0) == 0xC0:
                # Compression pointer: 14-bit offset
                ptr = int.from_bytes(data[p:p + 2], "big") & 0x3FFF
                sub_name, _ = RouterDnsAuditor.parse_dns_name(data, ptr)
                labels.append(sub_name)
                p += 2
                break
            else:
                p += 1
                labels.append(data[p:p + length].decode("latin1", errors="ignore"))
                p += length

        return ".".join([l for l in labels if l]), p

    @staticmethod
    def clean_hostname(raw_name: str) -> str:
        """Strips local router domains (e.g. host.lan, host.home, host.domain) to get human name."""
        if not raw_name:
            return ""
        base = raw_name.split(".")[0]
        return base.replace("-", " ").strip()

    def audit_subnet(self, subnet_base: str, max_workers: int = 30) -> Dict[str, str]:
        """
        Queries the gateway DNS for reverse PTR records across the full /24 subnet.
        Returns a mapping of {IP_ADDRESS: RAW_HOSTNAME}.
        """
        dns_records: Dict[str, str] = {}
        if not self.gateway_ip or not subnet_base:
            return dns_records

        parts = subnet_base.split(".")
        if len(parts) != 3:
            return dns_records

        rev_suffix = f"{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"

        def query_ptr(host_id: int) -> Tuple[str, Optional[str]]:
            ip = f"{subnet_base}.{host_id}"
            rev_name = f"{host_id}.{rev_suffix}"

            # Standard DNS PTR query packet
            q = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            for label in rev_name.split("."):
                q += bytes([len(label)]) + label.encode()
            q += b"\x00\x00\x0c\x00\x01"  # Type=PTR(12), Class=IN(1)

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.4)
            try:
                s.sendto(q, (self.gateway_ip, 53))
                data, _ = s.recvfrom(512)
                rcode = data[3] & 0x0F
                ancount = int.from_bytes(data[6:8], "big")

                if rcode == 0 and ancount > 0:
                    # Skip header (12 bytes) + question
                    p = 12
                    _, p = self.parse_dns_name(data, p)
                    p += 4  # qtype, qclass
                    # Parse Answer section
                    _, p = self.parse_dns_name(data, p)
                    p += 8  # type, class, ttl
                    p += 2  # rdlength
                    rname, _ = self.parse_dns_name(data, p)
                    return ip, rname
            except Exception:
                pass
            finally:
                s.close()
            return ip, None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for ip, name in executor.map(query_ptr, range(1, 255)):
                if name:
                    dns_records[ip] = name

        return dns_records
