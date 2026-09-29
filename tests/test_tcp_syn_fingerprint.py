"""
Unit tests for passive TCP SYN stack fingerprinting and OS detection.
"""

import socket
import struct
import unittest
from alien_hunter.identifiers.signatures import (
    SignatureManager,
    TcpSynSignature,
    TcpSynFingerprintStore,
)
from alien_hunter.identifiers.tcp_syn import TcpSynParser


class TestTcpSynFingerprinting(unittest.TestCase):

    def setUp(self):
        self.mgr = SignatureManager()
        self.store = TcpSynFingerprintStore.get_instance()
        self.store.clear()

    def tearDown(self):
        self.store.clear()

    def _build_tcp_syn_packet(
        self,
        src_ip: str = "192.168.1.50",
        dst_ip: str = "192.168.1.1",
        ttl: int = 64,
        window_size: int = 64240,
        options_bytes: bytes = b"",
    ) -> bytes:
        """Constructs a synthetic Ethernet + IPv4 + TCP SYN frame."""
        # Ethernet Header (14 bytes)
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

        # TCP Header
        tcp_hdr_len = 20 + len(options_bytes)
        # Pad to multiple of 4 bytes
        pad_len = (4 - (tcp_hdr_len % 4)) % 4
        options_padded = options_bytes + (b"\x01" * pad_len)
        data_offset = (20 + len(options_padded)) // 4

        tcp = struct.pack(
            "!HHIIBBHHH",
            45678,         # src port
            80,            # dst port
            100000,        # seq
            0,             # ack
            (data_offset << 4),  # data offset
            0x02,          # flags: SYN
            window_size,   # window
            0,             # checksum
            0,             # urgent pointer
        ) + options_padded

        # IPv4 Header (20 bytes)
        ip_total_len = 20 + len(tcp)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,          # version 4, ihl 5
            0,             # dscp/ecn
            ip_total_len,  # total len
            54321,         # id
            0x4000,        # flags: Don't Fragment
            ttl,           # TTL
            6,             # proto TCP
            0,             # checksum
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )

        return eth + ip + tcp

    def test_estimate_initial_ttl(self):
        self.assertEqual(TcpSynParser.estimate_initial_ttl(64), 64)
        self.assertEqual(TcpSynParser.estimate_initial_ttl(62), 64)
        self.assertEqual(TcpSynParser.estimate_initial_ttl(128), 128)
        self.assertEqual(TcpSynParser.estimate_initial_ttl(120), 128)
        self.assertEqual(TcpSynParser.estimate_initial_ttl(255), 255)
        self.assertEqual(TcpSynParser.estimate_initial_ttl(245), 255)

    def test_parse_tcp_options(self):
        # Linux standard options: MSS(2), SACK_PERM(4), TS(8), NOP(1), WSCALE(3)
        raw_opts = (
            bytes([2, 4, 0x05, 0xB4])  # MSS = 1460
            + bytes([4, 2])             # SACK-Permitted
            + bytes([8, 10, 0, 0, 0, 1, 0, 0, 0, 0])  # TS
            + bytes([1])                # NOP
            + bytes([3, 3, 7])          # WScale = 7
        )
        kinds = TcpSynParser.parse_tcp_options(raw_opts)
        self.assertEqual(kinds, [2, 4, 8, 1, 3])

    def test_tcp_syn_signature_matches(self):
        sig_linux = TcpSynSignature(
            vendor="Linux Kernel 5.x",
            category="Laptop / Workstation",
            os_family="Linux",
            initial_ttl=64,
            options=(2, 4, 8, 1, 3),
        )
        self.assertTrue(sig_linux.matches(64, (2, 4, 8, 1, 3)))
        # Routed hop decrement (63)
        self.assertTrue(sig_linux.matches(63, (2, 4, 8, 1, 3)))
        # Wrong TTL
        self.assertFalse(sig_linux.matches(128, (2, 4, 8, 1, 3)))

    def test_signature_manager_match_linux(self):
        match = self.mgr.match_tcp_syn(ttl=64, options=[2, 4, 8, 1, 3])
        self.assertIsNotNone(match)
        self.assertEqual(match.os_family, "Linux")
        self.assertIn("Linux", match.vendor)

    def test_signature_manager_match_windows(self):
        match = self.mgr.match_tcp_syn(ttl=128, options=[2, 1, 3, 1, 1, 4])
        self.assertIsNotNone(match)
        self.assertEqual(match.os_family, "Windows")
        self.assertIn("Windows", match.vendor)

    def test_signature_manager_match_apple(self):
        match = self.mgr.match_tcp_syn(ttl=64, options=[2, 1, 3, 1, 1, 8, 4, 0])
        self.assertIsNotNone(match)
        self.assertEqual(match.os_family, "macOS / iOS")
        self.assertIn("Apple", match.vendor)

    def test_parse_frame_and_store(self):
        # Build synthetic Linux SYN packet
        opts = (
            bytes([2, 4, 0x05, 0xB4])  # MSS
            + bytes([4, 2])             # SACK
            + bytes([8, 10, 0, 0, 0, 1, 0, 0, 0, 0])  # TS
            + bytes([1])                # NOP
            + bytes([3, 3, 7])          # WScale
        )
        pkt = self._build_tcp_syn_packet(
            src_ip="192.168.1.120",
            dst_ip="192.168.1.1",
            ttl=64,
            options_bytes=opts,
        )

        res = TcpSynParser.parse_frame(pkt, sig_manager=self.mgr)
        self.assertIsNotNone(res)
        self.assertEqual(res["src_ip"], "192.168.1.120")
        self.assertEqual(res["ttl"], 64)
        self.assertEqual(res["options"], [2, 4, 8, 1, 3])
        self.assertIsNotNone(res["match"])
        self.assertEqual(res["match"].os_family, "Linux")

        stored = self.store.get("192.168.1.120")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["ttl"], 64)
        self.assertEqual(stored["options"], [2, 4, 8, 1, 3])

    def test_device_display_name_with_tcp_syn(self):
        from alien_hunter.models import Device
        dev = Device(
            ip="192.168.1.99",
            mac="DA:A1:19:55:66:77",
            hostname="Unknown",
            vendor="Randomized Private MAC",
            is_randomized=True,
            tcp_syn_fingerprint="Linux Kernel 4.x - 6.x / Android",
        )
        self.assertEqual(dev.display_name, "Linux Kernel 4.x - 6.x / Android (Randomized Private MAC)")


if __name__ == "__main__":
    unittest.main()
