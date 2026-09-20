"""
Unit tests for Multicast DNS (mDNS / DNS-SD / Bonjour) discovery scanner.
"""

import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.scanners.mdns import MdnsScanner


class TestMdnsScanner(unittest.TestCase):
    """Tests mDNS query encoding and response decoding."""

    def test_encode_domain_name(self):
        encoded = MdnsScanner._encode_domain_name("_airplay._tcp.local")
        expected = b"\x08_airplay\x04_tcp\x05local\x00"
        self.assertEqual(encoded, expected)

    def test_build_query(self):
        query = MdnsScanner.build_query(["_airplay._tcp.local"])
        self.assertGreater(len(query), 12)
        trans_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", query[:12])
        self.assertEqual(trans_id, 0)
        self.assertEqual(flags, 0)
        self.assertEqual(qdcount, 1)
        self.assertEqual(ancount, 0)

    def test_parse_mdns_response_a_and_txt(self):
        # Build synthetic DNS response
        # Header: ID=0, Flags=0x8400 (Response, Authoritative), QD=0, AN=3
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 3, 0, 0)

        # Record 1: PTR record (LivingRoomAppleTV._airplay._tcp.local)
        r1_name = MdnsScanner._encode_domain_name("_airplay._tcp.local")
        r1_target = MdnsScanner._encode_domain_name("LivingRoomAppleTV._airplay._tcp.local")
        r1 = r1_name + struct.pack("!HHIH", 12, 1, 120, len(r1_target)) + r1_target

        # Record 2: A record for LivingRoomAppleTV.local -> 192.168.1.105
        r2_name = MdnsScanner._encode_domain_name("LivingRoomAppleTV.local")
        r2_ip = socket.inet_aton("192.168.1.105")
        r2 = r2_name + struct.pack("!HHIH", 1, 1, 120, len(r2_ip)) + r2_ip

        # Record 3: TXT record with model=AppleTV6,2 and fn=Living Room
        r3_name = MdnsScanner._encode_domain_name("LivingRoomAppleTV.local")
        fn_b = b"fn=Living Room"
        md_b = b"model=AppleTV6,2"
        txt_chunks = bytes([len(fn_b)]) + fn_b + bytes([len(md_b)]) + md_b
        r3 = r3_name + struct.pack("!HHIH", 16, 1, 120, len(txt_chunks)) + txt_chunks

        full_pkt = header + r1 + r2 + r3
        parsed = MdnsScanner.parse_mdns_response(full_pkt, "192.168.1.105")

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["ip"], "192.168.1.105")
        self.assertEqual(parsed["device_name"], "Living Room")
        self.assertEqual(parsed["model"], "AppleTV6,2")
        self.assertIn("LivingRoomAppleTV", parsed["services"])
        self.assertEqual(parsed["txt"].get("model"), "AppleTV6,2")

    def test_parse_mdns_response_multi_ip_subnet_prioritization(self):
        # Header: 2 A-records: 198.18.100.100 first, then 192.168.1.1
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 2, 0, 0)

        # Record 1: A record -> 198.18.100.100
        r1_name = MdnsScanner._encode_domain_name("router.local")
        r1_ip = socket.inet_aton("198.18.100.100")
        r1 = r1_name + struct.pack("!HHIH", 1, 1, 120, len(r1_ip)) + r1_ip

        # Record 2: A record -> 192.168.1.1
        r2_name = MdnsScanner._encode_domain_name("router.local")
        r2_ip = socket.inet_aton("192.168.1.1")
        r2 = r2_name + struct.pack("!HHIH", 1, 1, 120, len(r2_ip)) + r2_ip

        full_pkt = header + r1 + r2
        parsed = MdnsScanner.parse_mdns_response(
            full_pkt, src_ip="192.168.1.1", subnet_cidr="192.168.1.0/24"
        )

        self.assertIsNotNone(parsed)
        # Authoritative primary IP should be on local subnet, with 198.18.100.100 as alias
        self.assertEqual(parsed["ip"], "192.168.1.1")
        self.assertIn("198.18.100.100", parsed["aliases"])


if __name__ == "__main__":
    unittest.main()
