"""
IPv6 Shadow Network Discovery module.
Actively probes the local link using IPv6 Multicast (ff02::1) to discover 
stealth devices, IoT hardware, and endpoints that ignore IPv4 ARP sweeps.
"""

import json
import os
import socket
import struct
import subprocess
import time
from typing import Dict, Optional


class Ipv6DiscoveryScanner:
    """Discovers hidden devices by probing IPv6 local-link multicast groups."""

    ALL_NODES_MULTICAST = "ff02::1"
    ICMPV6_ECHO_REQUEST = 128

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface

    @classmethod
    def build_echo_request(cls, ident: int = 0x1337, seq: int = 1) -> bytes:
        """Builds an ICMPv6 Echo Request payload."""
        # Type=128, Code=0, Checksum=0 (kernel computes), Identifier, Sequence
        return struct.pack("!BBHHH", cls.ICMPV6_ECHO_REQUEST, 0, 0, ident, seq)

    def _multicast_ping(self, timeout: float = 1.0) -> None:
        """
        Transmits ICMPv6 Echo Requests to the all-nodes multicast address.
        This forces IPv6-capable devices to respond, populating the kernel neighbor cache.
        """
        sock = None
        try:
            # Requires root / CAP_NET_RAW
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            sock.settimeout(0.2)

            if self.interface:
                try:
                    # Bind to specific interface
                    sock.setsockopt(socket.SOL_SOCKET, 25, self.interface.encode("utf-8"))
                except Exception:
                    pass

                try:
                    ifindex = socket.if_nametoindex(self.interface)
                    # IPV6_MULTICAST_IF (17)
                    sock.setsockopt(socket.IPPROTO_IPV6, 17, struct.pack("i", ifindex))
                except Exception:
                    pass

            pkt = self.build_echo_request()
            
            # Send 2 rapid probes
            for _ in range(2):
                try:
                    sock.sendto(pkt, (self.ALL_NODES_MULTICAST, 0, 0, 0))
                except Exception:
                    pass
                time.sleep(0.1)

            # Briefly read to let the kernel process the incoming replies
            start = time.time()
            while time.time() - start < timeout:
                try:
                    sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except Exception:
                    break

        except (PermissionError, OSError):
            # Fallback to system ping6 if raw sockets fail
            try:
                cmd = ["ping6", "-c", "2", "-I", self.interface] if self.interface else ["ping6", "-c", "2"]
                cmd.append(self.ALL_NODES_MULTICAST)
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1)
            except Exception:
                pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def scan(self, timeout: float = 1.0) -> Dict[str, str]:
        """
        Executes the IPv6 discovery probe and returns discovered IPv6 link-local addresses.
        Returns mapping: {IPv6_ADDRESS: MAC_ADDRESS}
        """
        devices: Dict[str, str] = {}

        # 1. Trigger network activity to populate neighbor cache
        self._multicast_ping(timeout=timeout)

        # 2. Extract results from kernel neighbor cache (NDP table)
        try:
            cmd = ["ip", "-6", "-json", "neigh", "show"]
            if self.interface:
                cmd.extend(["dev", self.interface])

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.stdout:
                entries = json.loads(res.stdout)
                for entry in entries:
                    ip = entry.get("dst")
                    mac = entry.get("lladdr")
                    state = entry.get("state", [])
                    
                    if not ip or not mac:
                        continue
                    if mac.lower() == "00:00:00:00:00:00":
                        continue
                    if "FAILED" in state or "INCOMPLETE" in state:
                        continue
                    
                    devices[ip] = mac.upper()
        except Exception:
            pass

        return devices
