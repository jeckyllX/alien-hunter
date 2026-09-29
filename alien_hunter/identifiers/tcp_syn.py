"""
Passive TCP SYN Stack Fingerprinter.
Inspects raw TCP SYN handshakes (IP TTL, TCP Window Size, and TCP Option ordering)
to fingerprint host operating systems (Linux, Windows, macOS/iOS, BSD, Embedded)
even when devices use static IPs or never transmit DHCP requests.
Based on canonical p0f v3 OS fingerprinting techniques.
"""

import socket
import struct
from typing import Any, Dict, List, Optional, Tuple

from .signatures import SignatureManager, TcpSynFingerprintStore, DeviceFingerprintMatch


class TcpSynParser:
    """Parses raw IPv4 TCP SYN frames and extracts OS stack fingerprints."""

    @staticmethod
    def estimate_initial_ttl(observed_ttl: int) -> int:
        """
        Estimates the originating host's initial TTL from observed TTL.
        Standard IP stacks use 64 (Linux/macOS/iOS), 128 (Windows), or 255 (Cisco/Solaris).
        """
        if observed_ttl <= 64:
            return 64
        elif observed_ttl <= 128:
            return 128
        return 255

    @staticmethod
    def parse_tcp_options(opt_bytes: bytes) -> List[int]:
        """
        Extracts the ordered sequence of TCP option kinds from raw option bytes.
        Kind 0 = End of List, 1 = NOP, 2 = MSS, 3 = WScale, 4 = SACK-Permitted, 8 = Timestamp.
        """
        options: List[int] = []
        idx = 0
        total_len = len(opt_bytes)

        while idx < total_len:
            kind = opt_bytes[idx]
            if kind == 0:  # End of Option List
                options.append(0)
                break
            elif kind == 1:  # No-Operation (NOP)
                options.append(1)
                idx += 1
            else:
                if idx + 1 >= total_len:
                    break
                opt_len = opt_bytes[idx + 1]
                if opt_len < 2 or idx + opt_len > total_len:
                    break
                options.append(kind)
                idx += opt_len

        return options

    @classmethod
    def parse_frame(
        cls,
        pkt: bytes,
        sig_manager: Optional[SignatureManager] = None,
        now: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Parses a raw Ethernet frame or raw IPv4 packet.
        If the packet is a TCP SYN request (SYN=1, ACK=0, RST=0), extracts
        the stack fingerprint and records it in TcpSynFingerprintStore.
        """
        if len(pkt) < 34:
            return None

        ip_offset = 0
        # Check if Ethernet header is prepended (14 bytes)
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        if ethertype == 0x0800:
            ip_offset = 14
        elif (pkt[0] >> 4) == 4:
            ip_offset = 0
        else:
            return None

        if len(pkt) < ip_offset + 20:
            return None

        # IPv4 header parsing
        v_ihl = pkt[ip_offset]
        version = v_ihl >> 4
        if version != 4:
            return None

        ihl = (v_ihl & 0x0F) * 4
        if ihl < 20 or len(pkt) < ip_offset + ihl + 20:
            return None

        observed_ttl = pkt[ip_offset + 8]
        proto = pkt[ip_offset + 9]
        if proto != 6:  # IPPROTO_TCP
            return None

        src_ip = socket.inet_ntoa(pkt[ip_offset + 12 : ip_offset + 16])
        dst_ip = socket.inet_ntoa(pkt[ip_offset + 16 : ip_offset + 20])

        # TCP header parsing
        tcp_off = ip_offset + ihl
        src_port, dst_port = struct.unpack("!HH", pkt[tcp_off : tcp_off + 4])
        data_offset = (pkt[tcp_off + 12] >> 4) * 4
        flags = pkt[tcp_off + 13]
        window_size = struct.unpack("!H", pkt[tcp_off + 14 : tcp_off + 16])[0]

        # Only inspect SYN packets (SYN=1, ACK=0, RST=0)
        is_syn = (flags & 0x02) != 0 and (flags & 0x10) == 0 and (flags & 0x04) == 0
        if not is_syn:
            return None

        # Extract TCP options
        options: List[int] = []
        if data_offset > 20 and len(pkt) >= tcp_off + data_offset:
            opt_bytes = pkt[tcp_off + 20 : tcp_off + data_offset]
            options = cls.parse_tcp_options(opt_bytes)

        initial_ttl = cls.estimate_initial_ttl(observed_ttl)
        mgr = sig_manager or SignatureManager()
        match: Optional[DeviceFingerprintMatch] = mgr.match_tcp_syn(
            ttl=initial_ttl, options=options, window_size=window_size
        )

        TcpSynFingerprintStore.get_instance().record(
            ip=src_ip,
            ttl=observed_ttl,
            options=options,
            window_size=window_size,
            match=match,
            now=now,
        )

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "ttl": observed_ttl,
            "initial_ttl": initial_ttl,
            "window_size": window_size,
            "options": options,
            "match": match,
        }
