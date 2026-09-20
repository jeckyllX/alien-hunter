"""
Active NetBIOS Node Status Query Scanner.
Discovers Windows hosts, Samba file shares, and domain members by querying
NetBIOS Name Service (NBNS) on UDP port 137. Unmasks real computer names,
workgroups, and hardware MAC addresses even through hostile firewalls or across subnets.
"""

import socket
import struct
import time
from typing import Any, Dict, List, Optional
from .net_utils import create_udp_socket



class NetbiosScanner:
    """Sends RFC 1002 NBSTAT wildcard queries to unmask Windows and Samba systems."""

    NETBIOS_PORT = 137

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface

    @staticmethod
    def build_node_status_request(trans_id: int = 0x1337) -> bytes:
        """Constructs an RFC 1002 NetBIOS Node Status (NBSTAT) wildcard query packet."""
        # Header: ID, Flags=0x0000, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        header = struct.pack("!HHHHHH", trans_id, 0x0000, 1, 0, 0, 0)
        # Encoded wildcard '*' followed by 15 null bytes
        qname = b"\x20CK" + (b"AA" * 15) + b"\x00"
        # QTYPE = 0x0021 (NBSTAT), QCLASS = 0x0001 (IN)
        qtype_class = struct.pack("!HH", 0x0021, 0x0001)
        return header + qname + qtype_class

    def scan(
        self,
        target_ips: Optional[List[str]] = None,
        subnet_broadcast: Optional[str] = None,
        timeout: float = 1.5,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Queries target IPs via unicast and broadcast for NetBIOS Node Status.
        Returns a dictionary of discovered hosts indexed by IP address:
        {
            ip: {
                "computer_name": Optional[str],
                "workgroup": Optional[str],
                "mac": Optional[str],
                "services": List[Dict[str, Any]],
            }
        }
        """
        results: Dict[str, Dict[str, Any]] = {}
        sock = None
        trans_id = 0x1337
        req_pkt = self.build_node_status_request(trans_id)

        try:
            sock = create_udp_socket(interface=self.interface, timeout=0.3)


            # Destination targets: broadcasts + specific unicast IPs
            destinations = set()
            destinations.add("255.255.255.255")
            if subnet_broadcast:
                destinations.add(subnet_broadcast)
            if target_ips:
                for ip in target_ips:
                    destinations.add(ip)

            for dst_ip in destinations:
                try:
                    sock.sendto(req_pkt, (dst_ip, self.NETBIOS_PORT))
                except Exception:
                    pass

            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(2048)
                    sender_ip = addr[0]
                    parsed = self._parse_node_status_response(data)
                    if parsed:
                        results[sender_ip] = parsed
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

    @classmethod
    def _parse_node_status_response(cls, pkt: bytes) -> Optional[Dict[str, Any]]:
        """Parses an RFC 1002 NBSTAT answer packet and extracts computer name, workgroup, and MAC."""
        if len(pkt) < 56:
            return None

        try:
            trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
                "!HHHHHH", pkt[:12]
            )
            # Must be a response (high bit of flags is set) and have at least 1 answer
            if not (flags & 0x8000) or ancount < 1:
                return None

            offset = 12

            # Skip Question Section if present
            for _ in range(qdcount):
                if offset >= len(pkt):
                    return None
                while offset < len(pkt):
                    lbl_len = pkt[offset]
                    if lbl_len == 0:
                        offset += 1
                        break
                    if (lbl_len & 0xC0) == 0xC0:
                        offset += 2
                        break
                    offset += 1 + lbl_len
                offset += 4  # QTYPE + QCLASS

            # Process Answer RRs to find NBSTAT (0x0021)
            for _ in range(ancount):
                if offset >= len(pkt):
                    return None
                # Skip RR Name (label or compression pointer)
                while offset < len(pkt):
                    lbl_len = pkt[offset]
                    if lbl_len == 0:
                        offset += 1
                        break
                    if (lbl_len & 0xC0) == 0xC0:
                        offset += 2
                        break
                    offset += 1 + lbl_len

                if offset + 10 > len(pkt):
                    return None

                rr_type, rr_class, ttl, rdlen = struct.unpack(
                    "!HHIH", pkt[offset : offset + 10]
                )
                offset += 10

                if rr_type == 0x0021:
                    # NBSTAT RR found
                    if offset >= len(pkt):
                        return None
                    num_names = pkt[offset]
                    offset += 1

                    computer_name = None
                    workgroup = None
                    services: List[Dict[str, Any]] = []

                    for _ in range(num_names):
                        if offset + 18 > len(pkt):
                            break
                        raw_name = pkt[offset : offset + 15].decode("latin1", errors="ignore").strip()
                        nb_type = pkt[offset + 15]
                        nb_flags = struct.unpack("!H", pkt[offset + 16 : offset + 18])[0]
                        is_group = bool(nb_flags & 0x8000)
                        offset += 18

                        services.append({
                            "name": raw_name,
                            "type": hex(nb_type),
                            "is_group": is_group,
                        })

                        if is_group and not workgroup:
                            workgroup = raw_name
                        elif not is_group and not computer_name and nb_type in (0x00, 0x20):
                            computer_name = raw_name

                    mac_str = None
                    if offset + 6 <= len(pkt):
                        mac_bytes = pkt[offset : offset + 6]
                        # Discard all 00:00:00:00:00:00 or FF:FF:FF:FF:FF:FF
                        if mac_bytes not in (b"\x00" * 6, b"\xff" * 6):
                            mac_str = ":".join(f"{b:02X}" for b in mac_bytes)

                    return {
                        "computer_name": computer_name,
                        "workgroup": workgroup,
                        "mac": mac_str,
                        "services": services,
                    }

                offset += rdlen

        except Exception:
            pass

        return None
