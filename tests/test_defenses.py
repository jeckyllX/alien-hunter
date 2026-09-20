"""
Unit and functional tests for Alien Hunter active defenses and intrusion detection modules.
"""

import os
import socket
import struct
import time
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.defenses.llmnr_canary import LlmnrCanaryTrap
from alien_hunter.defenses.dns_integrity import DnsIntegrityAuditor
from alien_hunter.defenses.ipv6_guard import Ipv6Guard
from alien_hunter.defenses.anti_sniff import AntiSniffDetector
from alien_hunter.defenses.port_drift import PortDriftTracker
from alien_hunter.defenses.honey_port import HoneyPortListener, HoneyPortEvent


class TestLlmnrCanaryTrap(unittest.TestCase):
    """Tests LLMNR and NetBIOS canary query construction and responder detection."""

    def test_build_llmnr_query(self):
        pkt = LlmnrCanaryTrap.build_llmnr_query("canary-test", 0x1234)
        self.assertGreater(len(pkt), 12)
        trans_id, flags = struct.unpack("!HH", pkt[:4])
        self.assertEqual(trans_id, 0x1234)
        self.assertEqual(flags, 0)
        self.assertIn(b"canary-test", pkt)

    def test_build_nbt_query(self):
        pkt = LlmnrCanaryTrap.build_nbt_query("CANARY1234", 0x5678)
        self.assertGreater(len(pkt), 12)
        trans_id, flags = struct.unpack("!HH", pkt[:4])
        self.assertEqual(trans_id, 0x5678)
        self.assertEqual(flags, 0x0110)

    @patch("socket.socket")
    def test_detects_active_poisoner(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Mock incoming LLMNR response from attacker 192.168.1.199
        resp_data = struct.pack("!HHHHHH", 0x1234, 0x8000, 1, 1, 0, 0) + b"\x00" * 30
        mock_sock.recvfrom.side_effect = [
            (resp_data, ("192.168.1.199", 5355)),
            TimeoutError(),
        ]

        with patch("os.urandom", side_effect=[b"\x12\x34\x56\x78", b"\x12\x34", b"\x56\x78"]):
            threats = LlmnrCanaryTrap.check_poisoning(timeout=0.1)

        self.assertTrue(len(threats) > 0)
        self.assertTrue(any("192.168.1.199" in t for t in threats))
        self.assertTrue(any("Poisoning" in t for t in threats))


class TestDnsIntegrityAuditor(unittest.TestCase):
    """Tests DNS query generation, RFC 1918 spoofing detection, and NXDOMAIN hijacking."""

    def test_build_dns_query(self):
        pkt = DnsIntegrityAuditor.build_dns_query("cloudflare.com", 0x9999)
        trans_id, flags, qdcount = struct.unpack("!HHH", pkt[:6])
        self.assertEqual(trans_id, 0x9999)
        self.assertEqual(flags, 0x0100)
        self.assertEqual(qdcount, 1)

    def test_detects_rfc1918_private_ip_spoofing(self):
        # When querying public domain cloudflare.com, if resolver returns private IP 192.168.1.50
        with patch.object(DnsIntegrityAuditor, "get_system_dns_resolvers", return_value=["192.168.1.1"]), \
             patch.object(DnsIntegrityAuditor, "query_resolver", side_effect=[
                 (3, []),  # NXDOMAIN query
                 (0, ["192.168.1.50"]),  # Canary cloudflare.com spoofed to private IP!
                 (0, ["192.168.1.50"]),
             ]):
            threats = DnsIntegrityAuditor.audit_dns(gateway_ip="192.168.1.1")

        self.assertTrue(len(threats) > 0)
        self.assertTrue(any("192.168.1.50" in t for t in threats))
        self.assertTrue(any("Malicious DNS Spoofing" in t for t in threats))

    def test_detects_nxdomain_hijacking(self):
        # When querying nonexistent domain, resolver returns an IP instead of NXDOMAIN
        with patch.object(DnsIntegrityAuditor, "get_system_dns_resolvers", return_value=["192.168.1.1"]), \
             patch.object(DnsIntegrityAuditor, "query_resolver", side_effect=[
                 (0, ["104.244.42.1"]),  # NXDOMAIN hijacked!
                 (0, ["1.1.1.1"]),
                 (0, ["9.9.9.9"]),
             ]):
            threats = DnsIntegrityAuditor.audit_dns(gateway_ip="192.168.1.1")

        self.assertTrue(len(threats) > 0)
        self.assertTrue(any("NXDOMAIN Hijacking" in t for t in threats))


class TestIpv6Guard(unittest.TestCase):
    """Tests IPv6 Router Advertisement decoding and rogue gateway detection."""

    def test_parse_router_advertisement_with_rdnss(self):
        # Type 134 (RA), Code 0, Checksum 0, Hop 64, Flags 0x80, Lifetime 1800s
        ra_header = struct.pack("!BBHBBH", 134, 0, 0, 64, 0x80, 1800)
        reach_retrans = struct.pack("!II", 30000, 1000)

        # Option 25: RDNSS (Type 25, Length 3 = 24 bytes)
        # Reserved 2B, Lifetime 4B (1800s), IPv6 DNS Addr 16B (2001:db8::1)
        dns_raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        rdnss_opt = struct.pack("!BBHI", 25, 3, 0, 1800) + dns_raw

        full_pkt = ra_header + reach_retrans + rdnss_opt
        parsed = Ipv6Guard.parse_router_advertisement(full_pkt, "fe80::1")

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["router_ip"], "fe80::1")
        self.assertEqual(parsed["router_lifetime"], 1800)
        self.assertTrue(parsed["is_default_gateway"])
        self.assertIn("2001:db8::1", parsed["rdnss"])


class TestPortDriftTracker(unittest.TestCase):
    """Tests baseline port drift and compromised device detection."""

    def test_detects_high_risk_port_drift(self):
        threats = PortDriftTracker.check_device_drift(
            ip="192.168.1.100",
            mac="AA:BB:CC:11:22:33",
            display_name="Living Room Smart Plug",
            current_open_ports=["80/HTTP", "23/Telnet"],
            whitelist_entry={"name": "Smart Plug", "ports": ["80/HTTP"]},
        )
        self.assertTrue(len(threats) > 0)
        self.assertTrue(any("High-Risk Port Drift" in t for t in threats))
        self.assertTrue(any("23/Telnet" in t for t in threats))

    def test_no_drift_when_ports_match(self):
        threats = PortDriftTracker.check_device_drift(
            ip="192.168.1.100",
            mac="AA:BB:CC:11:22:33",
            display_name="Living Room Smart Plug",
            current_open_ports=["80/HTTP"],
            whitelist_entry={"name": "Smart Plug", "ports": ["80/HTTP"]},
        )
        self.assertEqual(threats, [])


class TestHoneyPortListener(unittest.TestCase):
    """Tests Decoy Honey-Port listener lifecycle and intrusion event capture."""

    def test_start_stop_listener(self):
        # Choose high unprivileged ports for testing
        test_port = 19555
        listener = HoneyPortListener(ports=[test_port], bind_host="127.0.0.1")
        bound = listener.start()
        self.assertIn(test_port, bound)

        # Trigger simulated connection to honey-port
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", test_port))
        client.close()

        # Wait briefly for select loop to capture event
        time.sleep(0.2)
        threats = listener.get_threat_strings()
        listener.stop()

        self.assertTrue(len(threats) > 0)
        self.assertTrue(any(str(test_port) in t for t in threats))
        self.assertTrue(any("Honey-Port Canary Triggered" in t for t in threats))


if __name__ == "__main__":
    unittest.main()
