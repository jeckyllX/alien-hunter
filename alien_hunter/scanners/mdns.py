"""
Multicast DNS (mDNS / DNS-SD / Bonjour / Avahi) Discovery Scanner.
Discovers Apple devices, Google Cast/Nest, smart home (Matter/Thread),
printers, and IoT endpoints broadcasting on UDP 5353 (224.0.0.251).
"""

import ipaddress
import os
import select
import socket
import struct
import time
from typing import Dict, List, Optional, Set, Tuple, Any

from .net_utils import create_udp_socket


class MdnsScanner:
    """Discovers network devices and services using Multicast DNS (RFC 6762 / RFC 6763)."""

    MDNS_GROUP = "224.0.0.251"
    MDNS_PORT = 5353

    # Common service types to query for rich device fingerprinting
    DEFAULT_SERVICE_QUERIES = [
        "_services._dns-sd._udp.local",
        "_airplay._tcp.local",
        "_googlecast._tcp.local",
        "_http._tcp.local",
        "_matter._tcp.local",
        "_device-info._tcp.local",
        "_smb._tcp.local",
        "_ssh._tcp.local",
        "_workstation._tcp.local",
        "_sonos._tcp.local",
        "_companion-link._tcp.local",
    ]

    def __init__(
        self,
        interface: Optional[str] = None,
        subnet_base: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
    ):
        self.interface = interface
        self.subnet_base = subnet_base
        self.subnet_cidr = subnet_cidr

    @staticmethod
    def _encode_domain_name(domain: str) -> bytes:
        """Encodes a dot-separated domain name into DNS length-prefixed labels."""
        parts = domain.strip(".").split(".")
        encoded = bytearray()
        for p in parts:
            b = p.encode("utf-8")
            encoded.append(len(b))
            encoded.extend(b)
        encoded.append(0)  # Terminating null byte
        return bytes(encoded)

    @classmethod
    def build_query(cls, service_names: List[str]) -> bytes:
        """Constructs an RFC 1035 / RFC 6762 DNS query packet."""
        # Transaction ID: 0 (mDNS standard), Flags: 0x0000 (Standard Query)
        header = struct.pack("!HHHHHH", 0, 0x0000, len(service_names), 0, 0, 0)
        questions = bytearray()
        for name in service_names:
            qname = cls._encode_domain_name(name)
            # QTYPE=12 (PTR), QCLASS=0x8001 (IN with unicast-response requested)
            questions.extend(qname)
            questions.extend(struct.pack("!HH", 12, 0x8001))
        return header + bytes(questions)

    @staticmethod
    def _parse_dns_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
        """Safely parses a DNS name from packet data, following compression pointers."""
        if depth > 10:  # Prevent circular pointer loops
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

            # Check for compression pointer (top 2 bits set: 0xC0)
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
                if not jumped:
                    next_offset = offset + 2
                    jumped = True
                pointed_name, _ = MdnsScanner._parse_dns_name(data, pointer, depth + 1)
                if pointed_name:
                    labels.append(pointed_name)
                break
            else:
                offset += 1
                if offset + length > len(data):
                    break
                try:
                    label = data[offset : offset + length].decode("utf-8", errors="replace")
                    labels.append(label)
                except Exception:
                    pass
                offset += length
                if not jumped:
                    next_offset = offset

        return ".".join(labels), next_offset

    @classmethod
    def parse_mdns_response(
        cls,
        data: bytes,
        src_ip: str,
        subnet_base: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Parses an mDNS response packet into structured device and service metadata."""
        if len(data) < 12:
            return None

        trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        # Only process responses (QR bit set)
        if not (flags & 0x8000):
            return None

        total_rrs = ancount + nscount + arcount
        offset = 12

        # Skip questions if present
        for _ in range(qdcount):
            if offset >= len(data):
                break
            _, offset = cls._parse_dns_name(data, offset)
            offset += 4  # QTYPE (2) + QCLASS (2)

        discovered_services: List[str] = []
        hostnames: List[str] = []
        txt_records: Dict[str, str] = {}
        ip_addresses: List[str] = []

        for _ in range(total_rrs):
            if offset >= len(data):
                break

            name, offset = cls._parse_dns_name(data, offset)
            if offset + 10 > len(data):
                break

            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata_end = offset + rdlen
            if rdata_end > len(data):
                break

            rdata = data[offset:rdata_end]

            # TYPE 1: A Record (IPv4)
            if rtype == 1 and rdlen == 4:
                try:
                    ip_str = socket.inet_ntoa(rdata)
                    ip_addresses.append(ip_str)
                except Exception:
                    pass

            # TYPE 12: PTR Record (Domain Name)
            elif rtype == 12:
                target_name, _ = cls._parse_dns_name(data, offset)
                if target_name:
                    clean_name = target_name.split(".")[0]
                    if clean_name and clean_name not in discovered_services:
                        discovered_services.append(clean_name)

            # TYPE 16: TXT Record (Key=Value attributes)
            elif rtype == 16:
                txt_offset = 0
                while txt_offset < len(rdata):
                    chunk_len = rdata[txt_offset]
                    txt_offset += 1
                    if txt_offset + chunk_len > len(rdata):
                        break
                    chunk = rdata[txt_offset : txt_offset + chunk_len]
                    txt_offset += chunk_len
                    try:
                        entry = chunk.decode("utf-8", errors="replace")
                        if "=" in entry:
                            k, v = entry.split("=", 1)
                            txt_records[k.lower()] = v
                    except Exception:
                        pass

            # TYPE 33: SRV Record (Target Hostname)
            elif rtype == 33 and rdlen > 6:
                srv_target, _ = cls._parse_dns_name(data, offset + 6)
                if srv_target:
                    host_part = srv_target.split(".")[0]
                    if host_part and host_part not in hostnames:
                        hostnames.append(host_part)

            offset = rdata_end

        # Build local network if specified
        local_net = None
        if subnet_cidr:
            try:
                local_net = ipaddress.ip_network(subnet_cidr, strict=False)
            except (ValueError, TypeError):
                local_net = None
        elif subnet_base:
            try:
                local_net = ipaddress.ip_network(f"{subnet_base}.0/24", strict=False)
            except (ValueError, TypeError):
                local_net = None

        # Filter valid unicast IPs (exclude loopback, multicast, unspecified)
        valid_ips: List[str] = []
        for ip_cand in ip_addresses:
            try:
                ip_obj = ipaddress.ip_address(ip_cand)
                if not ip_obj.is_loopback and not ip_obj.is_unspecified and not ip_obj.is_multicast:
                    valid_ips.append(ip_cand)
            except ValueError:
                pass

        # Resolve primary IP:
        # Prioritize IP on local subnet if multiple A-records returned (e.g. gateway 192.168.1.1 over alias 198.18.100.100)
        primary_ip = None
        if local_net:
            for ip_cand in valid_ips:
                try:
                    if ipaddress.ip_address(ip_cand) in local_net:
                        primary_ip = ip_cand
                        break
                except ValueError:
                    pass

        if not primary_ip and local_net:
            try:
                if ipaddress.ip_address(src_ip) in local_net:
                    primary_ip = src_ip
            except ValueError:
                pass

        if not primary_ip:
            if valid_ips:
                primary_ip = valid_ips[0]
            else:
                primary_ip = src_ip

        aliases = [ip for ip in valid_ips if ip != primary_ip]

        # Infer model and friendly name from TXT records or hostnames
        model = txt_records.get("model") or txt_records.get("md") or txt_records.get("ty")
        device_name = txt_records.get("fn") or txt_records.get("name")
        if not device_name and hostnames:
            device_name = hostnames[0]

        return {
            "ip": primary_ip,
            "aliases": aliases,
            "hostnames": hostnames,
            "device_name": device_name,
            "model": model,
            "services": discovered_services,
            "txt": txt_records,
        }

    def scan(self, timeout: float = 1.5, service_queries: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """
        Sends mDNS queries and returns discovered devices indexed by IP address.
        """
        queries = service_queries or self.DEFAULT_SERVICE_QUERIES
        pkt = self.build_query(queries)
        results: Dict[str, Dict[str, Any]] = {}

        sock = None
        try:
            sock = create_udp_socket(interface=self.interface, broadcast=True, timeout=0.3)
            # Enable multicast TTL for local subnet
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.sendto(pkt, (self.MDNS_GROUP, self.MDNS_PORT))

            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    parsed = self.parse_mdns_response(
                        data, addr[0], subnet_base=self.subnet_base, subnet_cidr=self.subnet_cidr
                    )
                    if parsed and parsed.get("ip"):
                        dev_ip = parsed["ip"]
                        if dev_ip not in results:
                            results[dev_ip] = parsed
                        else:
                            # Merge discovered hostnames and services
                            existing = results[dev_ip]
                            for h in parsed.get("hostnames", []):
                                if h not in existing["hostnames"]:
                                    existing["hostnames"].append(h)
                            for s in parsed.get("services", []):
                                if s not in existing["services"]:
                                    existing["services"].append(s)
                            if not existing.get("model") and parsed.get("model"):
                                existing["model"] = parsed["model"]
                            if not existing.get("device_name") and parsed.get("device_name"):
                                existing["device_name"] = parsed["device_name"]
                            existing["txt"].update(parsed.get("txt", {}))
                except socket.timeout:
                    continue
                except Exception:
                    break

        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return results
