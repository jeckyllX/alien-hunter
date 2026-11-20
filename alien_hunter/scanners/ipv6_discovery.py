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
from typing import Dict, Optional, Set


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

    def _multicast_ping(self, timeout: float = 1.0) -> Set[str]:
        """
        Transmits ICMPv6 Echo Requests to the all-nodes multicast address.
        Returns confirmed responder IPv6 addresses from Echo Replies.
        """
        responders: Set[str] = set()
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

            # Collect ICMPv6 Echo Reply (type 129) peer addresses
            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(2048)
                    if data and data[0] == 129 and isinstance(addr, tuple) and addr:
                        responders.add(str(addr[0]).split("%", 1)[0])
                except socket.timeout:
                    continue
                except Exception:
                    break

        except (PermissionError, OSError):
            # Fallback to system ping -6 / ping6 when interface is set
            if self.interface:
                for cmd in (
                    ["ping", "-6", "-c", "2", "-I", self.interface, self.ALL_NODES_MULTICAST],
                    ["ping6", "-c", "2", "-I", self.interface, self.ALL_NODES_MULTICAST],
                ):
                    try:
                        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1)
                        if res.returncode == 0:
                            break
                    except FileNotFoundError:
                        continue
                    except Exception:
                        break
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return responders

    ACTIVE_NDP_STATES = frozenset({"REACHABLE", "DELAY", "PROBE"})

    def scan(self, timeout: float = 1.0) -> Dict[str, str]:
        """
        Executes the IPv6 discovery probe and returns active IPv6 link-local addresses.
        Returns mapping: {IPv6_ADDRESS: MAC_ADDRESS}
        """
        devices: Dict[str, str] = {}

        # 1. Trigger network activity to populate neighbor cache and collect live replies
        live_responders = self._multicast_ping(timeout=timeout) or set()

        # 2. Extract active results from kernel neighbor cache (NDP table)
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
                    if isinstance(state, str):
                        state = [state]
                    upper_states = {s.upper() for s in state if isinstance(s, str)}
                    ip_clean = str(ip).split("%", 1)[0]
                    is_active = bool(upper_states & self.ACTIVE_NDP_STATES)
                    is_confirmed_stale = ("STALE" in upper_states) and (ip_clean in live_responders)
                    if not (is_active or is_confirmed_stale):
                        continue
                    
                    devices[ip] = mac.upper()
        except Exception:
            pass

        return devices
