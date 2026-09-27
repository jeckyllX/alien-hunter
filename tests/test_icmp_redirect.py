"""
Unit tests for ICMP Redirect Route Hijacking defense module.
"""

import socket
import struct
import unittest

from alien_hunter.defenses.icmp_redirect import IcmpRedirectGuard, IcmpRedirectEvent


def build_icmp_redirect_packet(
    src_ip: str,
    dst_ip: str,
    new_gateway: str,
    orig_dest: str,
    icmp_code: int = 1,
) -> bytes:
    """Constructs a synthetic IPv4 packet containing an ICMP Type 5 Redirect message."""
    # IPv4 Header: 20 bytes
    ip_total_len = 20 + 8 + 20 + 8
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_len,
        54321,
        0,
        64,
        socket.IPPROTO_ICMP,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    # ICMP Type 5 Header: 8 bytes
    icmp_hdr = struct.pack(
        "!BBH4s",
        5,  # Type 5: Redirect
        icmp_code,
        0,  # Checksum
        socket.inet_aton(new_gateway),
    )
    # Original IP header: 20 bytes
    orig_ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        60,
        1234,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(dst_ip),
        socket.inet_aton(orig_dest),
    )
    # Original datagram 8-byte payload snippet
    orig_payload = b"\x00\x50\x04\xd2\x00\x00\x00\x00"
    return ip_hdr + icmp_hdr + orig_ip_hdr + orig_payload


class TestIcmpRedirectGuard(unittest.TestCase):
    """Tests ICMP packet parsing, route hijacking detection, and rate limiting."""

    def setUp(self):
        self.guard = IcmpRedirectGuard(
            gateway_ip="192.168.1.1",
            local_ip="192.168.1.73",
        )

    def test_parse_valid_host_redirect(self):
        packet = build_icmp_redirect_packet(
            src_ip="192.168.1.55",
            dst_ip="192.168.1.73",
            new_gateway="192.168.1.200",
            orig_dest="104.244.42.1",
            icmp_code=1,
        )
        event = self.guard.parse_icmp_packet(packet, sender_ip="192.168.1.55")
        self.assertIsNotNone(event)
        self.assertEqual(event.sender_ip, "192.168.1.55")
        self.assertEqual(event.new_gateway, "192.168.1.200")
        self.assertEqual(event.orig_dest_ip, "104.244.42.1")
        self.assertEqual(event.icmp_code, 1)
        self.assertEqual(event.code_description, "Redirect for Host")
        threat_str = event.to_threat_string()
        self.assertIn("CRITICAL: Active ICMP Route Hijacking detected!", threat_str)
        self.assertIn("192.168.1.55", threat_str)
        self.assertIn("192.168.1.200", threat_str)
        self.assertIn("104.244.42.1", threat_str)

    def test_parse_network_redirect(self):
        packet = build_icmp_redirect_packet(
            src_ip="192.168.1.99",
            dst_ip="192.168.1.73",
            new_gateway="192.168.1.250",
            orig_dest="8.8.8.8",
            icmp_code=0,
        )
        event = self.guard.parse_icmp_packet(packet)
        self.assertIsNotNone(event)
        self.assertEqual(event.icmp_code, 0)
        self.assertEqual(event.code_description, "Redirect for Network")

    def test_ignore_self_packets(self):
        # Packets emitted by the local host itself should be ignored
        packet = build_icmp_redirect_packet(
            src_ip="192.168.1.73",
            dst_ip="192.168.1.1",
            new_gateway="192.168.1.200",
            orig_dest="8.8.8.8",
        )
        event = self.guard.parse_icmp_packet(packet, sender_ip="192.168.1.73")
        self.assertIsNone(event)

    def test_ignore_non_redirect_icmp(self):
        # ICMP Type 8 (Echo Request)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 28, 1, 0, 64, socket.IPPROTO_ICMP, 0,
            socket.inet_aton("192.168.1.10"), socket.inet_aton("192.168.1.73")
        )
        echo_hdr = struct.pack("!BBHHH", 8, 0, 0, 123, 1)
        packet = ip_hdr + echo_hdr
        event = self.guard.parse_icmp_packet(packet)
        self.assertIsNone(event)

    def test_ignore_truncated_packets(self):
        self.assertIsNone(self.guard.parse_icmp_packet(b"too_short"))

    def test_record_and_rate_limiting(self):
        event1 = IcmpRedirectEvent(
            sender_ip="192.168.1.55",
            new_gateway="192.168.1.200",
            orig_dest_ip="8.8.8.8",
            timestamp=100.0,
        )
        self.guard._record_event(event1)
        threats = self.guard.get_threat_strings()
        self.assertEqual(len(threats), 1)

        # Immediate repeat within rate limit window (15s)
        event2 = IcmpRedirectEvent(
            sender_ip="192.168.1.55",
            new_gateway="192.168.1.200",
            orig_dest_ip="8.8.8.8",
            timestamp=105.0,
        )
        self.guard._record_event(event2)
        # Should not append new threat string
        self.assertEqual(len(self.guard.get_threat_strings()), 0)

        # New destination after rate limit window expires
        event3 = IcmpRedirectEvent(
            sender_ip="192.168.1.55",
            new_gateway="192.168.1.200",
            orig_dest_ip="8.8.8.8",
            timestamp=125.0,
        )
        self.guard._record_event(event3)
        threats3 = self.guard.get_threat_strings()
        self.assertEqual(len(threats3), 1)

    def test_update_topology(self):
        self.guard.update_topology(gateway_ip="192.168.1.254", local_ip="192.168.1.120")
        self.assertEqual(self.guard.gateway_ip, "192.168.1.254")
        self.assertEqual(self.guard.local_ip, "192.168.1.120")


if __name__ == "__main__":
    unittest.main()
