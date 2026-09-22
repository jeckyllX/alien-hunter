"""
Passive Layer-2 Frame Sniffer.
Listens for raw Ethernet frames crossing the local link to detect unprompted transmissions,
misconfigured hosts, or static out-of-subnet IPs.
"""

import ipaddress
import socket
import struct
import time
from typing import Dict, Optional


class PassiveFrameSniffer:
    """Captures and inspects raw Layer-2 Ethernet traffic to detect silent transmitters."""

    SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_DROP_MEMBERSHIP = 2
    PACKET_MR_PROMISC = 1

    def __init__(self, interface: Optional[str] = None, subnet_cidr: Optional[str] = None):
        self.interface = interface
        self.subnet_cidr = subnet_cidr
        self._local_network = None
        if subnet_cidr:
            try:
                self._local_network = ipaddress.ip_network(subnet_cidr, strict=False)
            except Exception:
                self._local_network = None

    def sniff(self, duration: int = 3) -> Dict[str, str]:
        """
        Passively listens for Ethernet frames over a short duration using promiscuous mode.
        Returns a mapping of {IP_ADDRESS: MAC_ADDRESS} for observed transmitters on the local link.
        Filters out transit WAN internet traffic forwarded through the gateway.
        """
        unadvertised: Dict[str, str] = {}
        raw_sock = None
        mreq = None

        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                raw_sock.bind((self.interface, 0))

                # Enable hardware promiscuous mode on the network interface
                try:
                    ifindex = socket.if_nametoindex(self.interface)
                    mreq = struct.pack("IHH8s", ifindex, self.PACKET_MR_PROMISC, 0, b"")
                    raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
                except Exception:
                    # Fail-safe: continue in standard capture mode if non-root or unsupported
                    mreq = None

            raw_sock.settimeout(1.0)

            start = time.time()
            while time.time() - start < duration:
                try:
                    pkt, _ = raw_sock.recvfrom(2048)
                    if len(pkt) < 14:
                        continue

                    src_mac = ":".join(f"{b:02X}" for b in pkt[6:12])
                    proto = struct.unpack("!H", pkt[12:14])[0]

                    if src_mac != "00:00:00:00:00:00":
                        # ARP Packet (strictly local Layer-2 broadcast domain)
                        if proto == 0x0806 and len(pkt) >= 42:
                            sender_ip = socket.inet_ntoa(pkt[28:32])
                            try:
                                ip_obj = ipaddress.ip_address(sender_ip)
                                if not ip_obj.is_multicast and not ip_obj.is_unspecified:
                                    unadvertised[sender_ip] = src_mac
                            except Exception:
                                pass

                        # IPv4 Packet
                        elif proto == 0x0800 and len(pkt) >= 34:
                            src_ip = socket.inet_ntoa(pkt[26:30])
                            try:
                                ip_obj = ipaddress.ip_address(src_ip)
                                if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback:
                                    continue

                                # Discard transit WAN packets from external internet servers
                                # forwarded through the gateway. Only catalog hosts on the local link:
                                if self._local_network:
                                    if ip_obj in self._local_network or ip_obj.is_link_local:
                                        unadvertised[src_ip] = src_mac
                                elif ip_obj.is_private or ip_obj.is_link_local:
                                    unadvertised[src_ip] = src_mac
                            except Exception:
                                pass
                except socket.timeout:
                    pass
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

        return unadvertised

