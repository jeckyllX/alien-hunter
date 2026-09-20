"""
Anti-Sniff / Remote Promiscuous Node Detector.
Identifies unauthorized packet sniffers and eavesdroppers on the local network
by exploiting NIC hardware address filtering bypass in promiscuous mode.
"""

import os
import socket
import struct
import time
from typing import Dict, List, Optional, Set


class AntiSniffDetector:
    """
    Tests whether remote network nodes are operating in promiscuous mode (packet sniffing).
    """

    ETH_P_ARP = 0x0806
    # Non-broadcast multicast MAC used to trigger kernel ARP response only on promiscuous NICs
    PROMISCUOUS_PROBE_MAC = bytes.fromhex("01005E000001")

    @classmethod
    def check_promiscuous_hosts(
        cls,
        interface: str,
        local_ip: str,
        local_mac: str,
        target_hosts: Dict[str, str],  # ip -> mac
        timeout_per_host: float = 0.4,
    ) -> List[str]:
        """
        Sends anti-sniff ARP probes to target hosts.
        Returns a list of warnings for any hosts replying while in promiscuous mode.
        """
        threats: List[str] = []
        if not target_hosts or not interface or not local_ip or not local_mac:
            return threats

        sock = None
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(cls.ETH_P_ARP))
            sock.settimeout(timeout_per_host)
            sock.bind((interface, 0))

            src_mac_bytes = bytes.fromhex(local_mac.replace(":", "").replace("-", ""))
            src_ip_bytes = socket.inet_aton(local_ip)

            for target_ip, target_mac in target_hosts.items():
                if target_ip == local_ip:
                    continue  # Skip our own host

                try:
                    target_ip_bytes = socket.inet_aton(target_ip)
                except Exception:
                    continue

                # Construct Ethernet Frame + ARP Request with non-standard destination MAC
                # Ethernet Header (14 bytes): Dest MAC (6B), Src MAC (6B), EtherType 0x0806 (2B)
                eth_header = cls.PROMISCUOUS_PROBE_MAC + src_mac_bytes + struct.pack("!H", cls.ETH_P_ARP)

                # ARP Payload (28 bytes)
                arp_payload = struct.pack(
                    "!HHBBH6s4s6s4s",
                    1,                 # Hardware type: Ethernet (1)
                    0x0800,            # Protocol: IPv4 (0x0800)
                    6,                 # HLEN: 6
                    4,                 # PLEN: 4
                    1,                 # Opcode: Request (1)
                    src_mac_bytes,     # Sender MAC
                    src_ip_bytes,      # Sender IP
                    b"\x00" * 6,       # Target MAC (blank)
                    target_ip_bytes,   # Target IP
                )

                probe_frame = eth_header + arp_payload
                sock.send(probe_frame)

                # Listen for reply
                start_wait = time.time()
                while time.time() - start_wait < timeout_per_host:
                    try:
                        raw_data = sock.recv(2048)
                        if len(raw_data) < 42:
                            continue

                        # Check EtherType
                        eth_type = struct.unpack("!H", raw_data[12:14])[0]
                        if eth_type != cls.ETH_P_ARP:
                            continue

                        arp_data = raw_data[14:42]
                        hw_type, proto_type, hlen, plen, opcode = struct.unpack("!HHBBH", arp_data[:8])
                        if opcode != 2:  # Must be ARP Reply
                            continue

                        rep_sender_mac = ":".join(f"{b:02X}" for b in arp_data[8:14])
                        rep_sender_ip = socket.inet_ntoa(arp_data[14:18])

                        if rep_sender_ip == target_ip:
                            threats.append(
                                f"WARNING: Remote host {target_ip} ({rep_sender_mac}) detected in PROMISCUOUS MODE! "
                                f"The network card is capturing promiscuous network traffic "
                                f"(possible unauthorized packet sniffer, tap, or IDS)."
                            )
                            break
                    except socket.timeout:
                        break
                    except Exception:
                        break

        except (PermissionError, OSError):
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return threats
