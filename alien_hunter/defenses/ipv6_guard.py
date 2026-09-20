"""
IPv6 Router Advertisement (RA) Guard and mitm6 Attack Detector.
Audits IPv6 local link traffic for rogue Router Advertisements (ICMPv6 Type 134)
and unauthorized RDNSS recursive DNS servers attempting to hijack LAN traffic.
"""

import os
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class Ipv6Guard:
    """
    Guards local link against rogue IPv6 router advertisements and mitm6 attacks.
    """

    ICMPV6_ROUTER_SOLICIT = 133
    ICMPV6_ROUTER_ADVERT = 134
    ALL_ROUTERS_MULTICAST = "ff02::2"

    @staticmethod
    def is_ipv6_supported() -> bool:
        """Checks if IPv6 is available on the host system."""
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.close()
            return True
        except Exception:
            return False

    @classmethod
    def build_router_solicitation(cls) -> bytes:
        """Constructs an ICMPv6 Router Solicitation message (RFC 4861)."""
        # Type=133, Code=0, Checksum=0 (kernel computes for ICMPv6 raw socket), Reserved=4 bytes 0
        return struct.pack("!BBHI", cls.ICMPV6_ROUTER_SOLICIT, 0, 0, 0)

    @classmethod
    def parse_router_advertisement(cls, data: bytes, src_ip: str) -> Optional[Dict[str, Any]]:
        """
        Parses an ICMPv6 Router Advertisement (Type 134) packet.
        Extracts router lifetime and RDNSS (Recursive DNS Server) options.
        """
        if len(data) < 16:
            return None

        msg_type, code, _, cur_hop, flags, router_lifetime = struct.unpack("!BBHBBH", data[:8])
        if msg_type != cls.ICMPV6_ROUTER_ADVERT:
            return None

        rdnss_servers: List[str] = []
        offset = 16  # Skip 4 bytes reachable time + 4 bytes retransmit timer

        while offset + 2 <= len(data):
            opt_type = data[offset]
            opt_len = data[offset + 1] * 8  # Length in units of 8 octets
            if opt_len == 0 or offset + opt_len > len(data):
                break

            opt_body = data[offset + 2 : offset + opt_len]

            # Option 25: RDNSS (Recursive DNS Server, RFC 8106)
            if opt_type == 25 and len(opt_body) >= 6:
                # Reserved 2B + Lifetime 4B + Addresses (16B each)
                addr_offset = 6
                while addr_offset + 16 <= len(opt_body):
                    raw_addr = opt_body[addr_offset : addr_offset + 16]
                    try:
                        dns_ip = socket.inet_ntop(socket.AF_INET6, raw_addr)
                        rdnss_servers.append(dns_ip)
                    except Exception:
                        pass
                    addr_offset += 16

            offset += opt_len

        return {
            "router_ip": src_ip,
            "router_lifetime": router_lifetime,
            "is_default_gateway": router_lifetime > 0,
            "rdnss": rdnss_servers,
        }

    @classmethod
    def check_rogue_ra(
        cls,
        interface: Optional[str] = None,
        expected_gateway_ipv6: Optional[str] = None,
        timeout: float = 1.0,
    ) -> List[str]:
        """
        Sends an ICMPv6 Router Solicitation and monitors for conflicting
        or rogue Router Advertisements on the local link.
        """
        threats: List[str] = []
        if not cls.is_ipv6_supported():
            return threats

        sock = None
        try:
            # Requires root / CAP_NET_RAW for SOCK_RAW ICMPv6
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            sock.settimeout(0.3)

            if interface:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, 25, interface.encode("utf-8"))  # SO_BINDTODEVICE
                except Exception:
                    pass

            rs_pkt = cls.build_router_solicitation()
            try:
                # Target all-routers multicast
                sock.sendto(rs_pkt, (cls.ALL_ROUTERS_MULTICAST, 0, 0, 0))
            except Exception:
                pass

            discovered_routers: Dict[str, Dict[str, Any]] = {}
            start_time = time.time()

            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(2048)
                    src_ip = addr[0]
                    parsed = cls.parse_router_advertisement(data, src_ip)
                    if parsed:
                        discovered_routers[src_ip] = parsed
                except socket.timeout:
                    continue
                except Exception:
                    break

            # Evaluate discovered IPv6 routers
            for r_ip, r_data in discovered_routers.items():
                if r_data["is_default_gateway"]:
                    if expected_gateway_ipv6 and r_ip != expected_gateway_ipv6:
                        rdnss_str = f" with DNS {', '.join(r_data['rdnss'])}" if r_data["rdnss"] else ""
                        threats.append(
                            f"CRITICAL: Rogue IPv6 Gateway / mitm6 Attack Detected! "
                            f"Host {r_ip} is broadcasting ICMPv6 Router Advertisements claiming default route{rdnss_str} "
                            f"(Expected: {expected_gateway_ipv6})! Potential MitM hijack of Windows IPv6 traffic."
                        )

            if len(discovered_routers) > 1:
                routers_str = ", ".join(discovered_routers.keys())
                threats.append(
                    f"WARNING: Multiple IPv6 Routers detected on local link: {routers_str}. "
                    f"Conflicting Router Advertisements can cause IPv6 traffic interception or blackholing."
                )

        except (PermissionError, OSError):
            # Gracefully handle unprivileged execution or restricted kernel network namespace
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return threats
