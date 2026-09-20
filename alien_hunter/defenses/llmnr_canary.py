"""
LLMNR and NetBIOS-NS Poisoning Canary Trap ("Anti-Responder").
Detects active credential-harvesting tools (e.g. Responder, Inveigh)
by broadcasting queries for non-existent canary hostnames.
"""

import os
import socket
import struct
import time
from typing import List, Optional, Tuple

from ..scanners.net_utils import create_udp_socket


class LlmnrCanaryTrap:
    """
    Sends canary LLMNR and NBT-NS queries for fictitious hostnames.
    Any affirmative response indicates an active attacker conducting
    LLMNR/NBT-NS poisoning and credential harvesting on the LAN.
    """

    LLMNR_GROUP = "224.0.0.252"
    LLMNR_PORT = 5355
    NBT_PORT = 137

    @staticmethod
    def _encode_dns_label(name: str) -> bytes:
        """Encodes domain name into DNS length-prefixed format."""
        parts = name.strip(".").split(".")
        out = bytearray()
        for p in parts:
            b = p.encode("utf-8")
            out.append(len(b))
            out.extend(b)
        out.append(0)
        return bytes(out)

    @classmethod
    def build_llmnr_query(cls, hostname: str, trans_id: int) -> bytes:
        """Constructs an RFC 4795 LLMNR query packet."""
        header = struct.pack("!HHHHHH", trans_id, 0x0000, 1, 0, 0, 0)
        qname = cls._encode_dns_label(f"{hostname}.local")
        question = qname + struct.pack("!HH", 1, 1)  # TYPE A, CLASS IN
        return header + question

    @classmethod
    def _encode_netbios_name(cls, name: str) -> bytes:
        """Encodes a 16-character NetBIOS name into 32-byte half-byte hex representation."""
        padded = name.upper().ljust(15, " ")[:15] + "\x00"  # Workstation service suffix
        encoded = bytearray()
        for char in padded.encode("ascii"):
            encoded.append(((char >> 4) & 0x0F) + 0x41)
            encoded.append((char & 0x0F) + 0x41)
        return bytes(encoded)

    @classmethod
    def build_nbt_query(cls, hostname: str, trans_id: int) -> bytes:
        """Constructs an RFC 1002 NetBIOS Name Service query packet."""
        header = struct.pack("!HHHHHH", trans_id, 0x0110, 1, 0, 0, 0)  # Query, Recursion Desired
        encoded_name = cls._encode_netbios_name(hostname)
        question = b"\x20" + encoded_name + b"\x00" + struct.pack("!HH", 0x0020, 0x0001)  # NB, IN
        return header + question

    @classmethod
    def check_poisoning(
        cls,
        interface: Optional[str] = None,
        subnet_broadcast: Optional[str] = None,
        timeout: float = 1.2,
    ) -> List[str]:
        """
        Broadcasts LLMNR and NetBIOS queries for a fictitious canary hostname.
        Returns a list of detected threat descriptions if an attacker responds.
        """
        threats: List[str] = []
        canary_token = os.urandom(4).hex()
        canary_name = f"canary-trap-{canary_token}"
        trans_id_llmnr = struct.unpack("!H", os.urandom(2))[0]
        trans_id_nbt = struct.unpack("!H", os.urandom(2))[0]

        llmnr_pkt = cls.build_llmnr_query(canary_name, trans_id_llmnr)
        nbt_pkt = cls.build_nbt_query(f"CANARY{canary_token.upper()[:8]}", trans_id_nbt)

        sock_llmnr = None
        sock_nbt = None

        try:
            sock_llmnr = create_udp_socket(interface=interface, broadcast=True, timeout=0.3)
            sock_llmnr.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

            sock_nbt = create_udp_socket(interface=interface, broadcast=True, timeout=0.3)

            # Send LLMNR Canary to multicast group
            try:
                sock_llmnr.sendto(llmnr_pkt, (cls.LLMNR_GROUP, cls.LLMNR_PORT))
            except Exception:
                pass

            # Send NetBIOS Canary to broadcast
            target_bcast = subnet_broadcast or "255.255.255.255"
            try:
                sock_nbt.sendto(nbt_pkt, (target_bcast, cls.NBT_PORT))
            except Exception:
                pass

            start_time = time.time()
            responders = set()

            while time.time() - start_time < timeout:
                # Poll LLMNR socket
                try:
                    data, addr = sock_llmnr.recvfrom(2048)
                    if len(data) >= 12:
                        resp_id, flags = struct.unpack("!HH", data[:4])
                        # If response flag is set and matches our query ID
                        if (flags & 0x8000) and resp_id == trans_id_llmnr:
                            responders.add((addr[0], "LLMNR"))
                except (socket.timeout, BlockingIOError):
                    pass
                except Exception:
                    pass

                # Poll NBT socket
                try:
                    data, addr = sock_nbt.recvfrom(2048)
                    if len(data) >= 12:
                        resp_id, flags = struct.unpack("!HH", data[:4])
                        if (flags & 0x8000) and resp_id == trans_id_nbt:
                            responders.add((addr[0], "NetBIOS-NS"))
                except (socket.timeout, BlockingIOError):
                    pass
                except Exception:
                    pass

            for attacker_ip, proto in responders:
                threats.append(
                    f"CRITICAL: Active {proto} Poisoning / Credential Harvesting Detected! "
                    f"Host at {attacker_ip} fraudulently claimed ownership of fictitious canary host '{canary_name}'. "
                    f"Active internal attacker or automated tool (e.g. Responder / Inveigh) confirmed on LAN!"
                )

        except Exception:
            pass
        finally:
            if sock_llmnr:
                try:
                    sock_llmnr.close()
                except Exception:
                    pass
            if sock_nbt:
                try:
                    sock_nbt.close()
                except Exception:
                    pass

        return threats
