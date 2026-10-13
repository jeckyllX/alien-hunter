"""
Phantom Cross-Subnet Device Scanner.
Detects stealth drop boxes, rogue hardware implants, and misconfigured hosts
operating on the physical Layer-2 broadcast domain with out-of-subnet static IPs.
"""

import ipaddress
import json
import socket
import struct
import time
from typing import Dict, List, Optional, Set


class PhantomSweeper:
    """
    Passively monitors Layer-2 traffic to uncover devices communicating
    from IP subnets different from the primary local subnet.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
        gateway_mac: Optional[str] = None,
    ):
        self.interface = interface
        self.subnet_cidr = subnet_cidr
        self.gateway_mac = gateway_mac.upper() if gateway_mac else None
        self._local_network = None
        if subnet_cidr:
            try:
                self._local_network = ipaddress.ip_network(subnet_cidr, strict=False)
            except Exception:
                self._local_network = None

    @staticmethod
    def is_out_of_subnet(ip: str, subnet_cidr: Optional[str]) -> bool:
        """
        Determines if an IPv4 address is outside the specified subnet CIDR.
        Returns False for invalid IPs, multicast, loopback, or broadcast.
        """
        if not ip or not subnet_cidr:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Only consider IPv4 unicast addresses
            if ip_obj.version != 4 or ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_unspecified:
                return False
            net_obj = ipaddress.ip_network(subnet_cidr, strict=False)
            return ip_obj not in net_obj
        except Exception:
            return False

    def scan(self, duration: float = 2.0) -> Dict[str, str]:
        """
        Passively sniffs raw Layer-2 frames for a given duration.
        Returns a mapping {IP: MAC} of observed out-of-subnet phantom transmitters.
        """
        phantom_devices: Dict[str, str] = {}
        if not self.interface or not self._local_network:
            return phantom_devices

        raw_sock = None
        mreq = None
        sol_packet = getattr(socket, "SOL_PACKET", 263)
        packet_mr_promisc = 1
        packet_add_membership = 1
        packet_drop_membership = 2

        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            raw_sock.bind((self.interface, 0))

            try:
                ifindex = socket.if_nametoindex(self.interface)
                mreq = struct.pack("IHH8s", ifindex, packet_mr_promisc, 0, b"")
                raw_sock.setsockopt(sol_packet, packet_add_membership, mreq)
            except Exception:
                mreq = None

            raw_sock.settimeout(0.5)
            start = time.time()

            while time.time() - start < duration:
                try:
                    pkt, _ = raw_sock.recvfrom(2048)
                    if len(pkt) < 14:
                        continue

                    src_mac = ":".join(f"{b:02X}" for b in pkt[6:12])
                    if src_mac == "00:00:00:00:00:00":
                        continue

                    # Filter out frames originating from the default gateway router
                    if self.gateway_mac and src_mac.upper() == self.gateway_mac:
                        continue

                    proto = struct.unpack("!H", pkt[12:14])[0]

                    # 1. ARP frames (strictly local broadcast domain)
                    if proto == 0x0806 and len(pkt) >= 42:
                        sender_ip = socket.inet_ntoa(pkt[28:32])
                        if self.is_out_of_subnet(sender_ip, self.subnet_cidr):
                            phantom_devices[sender_ip] = src_mac.upper()

                    # 2. IPv4 frames
                    elif proto == 0x0800 and len(pkt) >= 34:
                        src_ip = socket.inet_ntoa(pkt[26:30])
                        try:
                            ip_obj = ipaddress.ip_address(src_ip)
                            # Must be private/link-local to avoid logging routed internet traffic
                            if (ip_obj.is_private or ip_obj.is_link_local) and ip_obj not in self._local_network:
                                phantom_devices[src_ip] = src_mac.upper()
                        except Exception:
                            pass

                except socket.timeout:
                    continue
                except Exception:
                    break

        except (PermissionError, OSError):
            pass
        finally:
            if raw_sock:
                if mreq:
                    try:
                        raw_sock.setsockopt(sol_packet, packet_drop_membership, mreq)
                    except Exception:
                        pass
                try:
                    raw_sock.close()
                except Exception:
                    pass

        return phantom_devices
