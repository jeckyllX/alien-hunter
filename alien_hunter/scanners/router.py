"""
Gateway DHCP and DNS Lease Auditor.
Directly interrogates the local router's DNS server to uncover registered hostnames
and DHCP leases for sleeping, firewalled, or power-saving mobile devices.
"""

import os
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional, Set, Tuple


class RouterDnsAuditor:
    """Interrogates gateway DNS (reverse PTR) to identify all assigned DHCP client leases."""

    def __init__(self, gateway_ip: Optional[str] = None):
        self.gateway_ip = gateway_ip

    @staticmethod
    def parse_dns_name(
        data: bytes,
        offset: int,
        _visited: Optional[Set[int]] = None,
        _depth: int = 0,
    ) -> Tuple[str, int]:
        """Parses a DNS name from raw wire bytes, following compression pointers (0xC0)."""
        if _depth > 16:
            return "", offset
        labels = []
        visited = _visited if _visited is not None else set()
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
                if p + 1 >= len(data):
                    break
                # Compression pointer: 14-bit offset
                ptr = int.from_bytes(data[p:p + 2], "big") & 0x3FFF
                sub_name, _ = RouterDnsAuditor.parse_dns_name(
                    data, ptr, _visited=visited, _depth=_depth + 1
                )
                labels.append(sub_name)
                p += 2
                break
            else:
                p += 1
                if p + length > len(data):
                    break
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

            txid = os.urandom(2)
            # Standard DNS PTR query packet
            q = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            for label in rev_name.split("."):
                q += bytes([len(label)]) + label.encode()
            q += b"\x00\x00\x0c\x00\x01"  # Type=PTR(12), Class=IN(1)

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.4)
            try:
                s.sendto(q, (self.gateway_ip, 53))
                data, _ = s.recvfrom(512)
                if len(data) < 12 or data[:2] != txid:
                    return ip, None
                flags = int.from_bytes(data[2:4], "big")
                if not (flags & 0x8000):  # Must be DNS response
                    return ip, None
                rcode = flags & 0x0F
                qdcount = int.from_bytes(data[4:6], "big")
                ancount = int.from_bytes(data[6:8], "big")

                if rcode == 0 and ancount > 0:
                    p = 12
                    for _ in range(qdcount):
                        _, p = self.parse_dns_name(data, p)
                        p += 4  # qtype, qclass
                    for _ in range(ancount):
                        if p >= len(data):
                            break
                        _, p = self.parse_dns_name(data, p)
                        if p + 10 > len(data):
                            break
                        rr_type = int.from_bytes(data[p:p + 2], "big")
                        rdlength = int.from_bytes(data[p + 8:p + 10], "big")
                        p += 10
                        if p + rdlength > len(data):
                            break
                        if rr_type == 12:  # PTR
                            rname, _ = self.parse_dns_name(data, p)
                            if rname:
                                return ip, rname
                        p += rdlength
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
