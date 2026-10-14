"""
Unit tests for Phantom Cross-Subnet Sweeper and Dynamic Multi-Tier Port Scanner.
"""

import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.scanners.phantom import PhantomSweeper
from alien_hunter.scanners.ports import (
    PortScanner,
    parse_port_specs,
    FAST_PORTS,
    DEEP_PORTS,
    SECURITY_PORT_SIGNATURES,
)
from alien_hunter.threats import ThreatDetector
from alien_hunter.models import Device


class TestPortScannerFlexibility(unittest.TestCase):
    """Tests flexible port parsing, tiered scanning, concurrency, and TLS inspection."""

    def test_parse_port_specs_single_and_comma(self):
        self.assertEqual(parse_port_specs("80"), [80])
        self.assertEqual(parse_port_specs("443, 80, 22"), [22, 80, 443])

    def test_parse_port_specs_ranges(self):
        self.assertEqual(parse_port_specs("8000-8003"), [8000, 8001, 8002, 8003])
        self.assertEqual(parse_port_specs("8003-8000"), [8000, 8001, 8002, 8003])

    def test_parse_port_specs_mixed_and_deduplication(self):
        result = parse_port_specs("22, 80, 8000-8002, 80, 22")
        self.assertEqual(result, [22, 80, 8000, 8001, 8002])

    def test_parse_port_specs_invalid_and_out_of_bounds(self):
        result = parse_port_specs("-1, 0, 70000, abc, 80, 65535, 65536")
        self.assertEqual(result, [80, 65535])

    def test_parse_port_specs_iterables(self):
        self.assertEqual(parse_port_specs([80, 443]), [80, 443])
        self.assertEqual(parse_port_specs(["22", "80-82"]), [22, 80, 81, 82])

    @patch.object(PortScanner, "check_port")
    def test_scan_host_with_custom_ports(self, mock_check_port):
        # Open port 8080 and 9999
        mock_check_port.side_effect = lambda ip, p: p in (8080, 9999)

        scanner = PortScanner()
        open_ports, threats, notes = scanner.scan_host("192.168.1.10", ports=[22, 8080, 9999])

        self.assertEqual(len(open_ports), 2)
        self.assertTrue(any("8080/HTTP-Alt" in p for p in open_ports))
        self.assertTrue(any("9999" in p for p in open_ports))

    @patch.object(PortScanner, "check_port")
    def test_scan_host_fast_vs_deep_tier(self, mock_check_port):
        mock_check_port.return_value = False

        scanner = PortScanner()
        # Fast scan
        scanner.scan_host("192.168.1.10", deep_scan=False)
        fast_calls = [c[0][1] for c in mock_check_port.call_args_list]
        self.assertEqual(sorted(fast_calls), sorted(FAST_PORTS))

        mock_check_port.reset_mock()
        # Deep scan
        scanner.scan_host("192.168.1.10", deep_scan=True)
        deep_calls = [c[0][1] for c in mock_check_port.call_args_list]
        self.assertEqual(sorted(deep_calls), sorted(DEEP_PORTS))

    @patch.object(PortScanner, "check_port")
    @patch("socket.getservbyport", return_value="customsvc")
    def test_scan_host_dynamic_iana_resolution(self, mock_getserv, mock_check_port):
        mock_check_port.side_effect = lambda ip, p: p == 45000

        scanner = PortScanner()
        open_ports, threats, notes = scanner.scan_host("192.168.1.10", ports=[45000])

        self.assertEqual(open_ports, ["45000/CUSTOMSVC"])
        mock_getserv.assert_called_with(45000, "tcp")

    @patch("ssl.get_server_certificate", return_value="-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n")
    def test_probe_tls_certificate_success(self, mock_get_cert):
        scanner = PortScanner()

        mock_decoded = {
            "subject": ((("commonName", "router.internal"),),),
            "subjectAltName": (("DNS", "router.internal"), ("DNS", "gateway.local")),
        }

        with patch("ssl._ssl._test_decode_cert", return_value=mock_decoded):
            cert_note = scanner.probe_tls_certificate("192.168.1.1", 443)
            self.assertIsNotNone(cert_note)
            self.assertIn("CN: router.internal", cert_note)
            self.assertIn("SANs: router.internal, gateway.local", cert_note)

    @patch("ssl.get_server_certificate", side_effect=Exception("Connection refused"))
    def test_probe_tls_certificate_failure_handles_cleanly(self, mock_get_cert):
        scanner = PortScanner()
        cert_note = scanner.probe_tls_certificate("192.168.1.1", 443)
        self.assertIsNone(cert_note)


class TestPhantomCrossSubnetSweeper(unittest.TestCase):
    """Tests out-of-subnet IP validation, Layer-2 frame parsing, and threat detection."""

    def test_is_out_of_subnet(self):
        # Different private subnet
        self.assertTrue(PhantomSweeper.is_out_of_subnet("10.0.0.5", "192.168.1.0/24"))
        self.assertTrue(PhantomSweeper.is_out_of_subnet("172.16.1.10", "192.168.1.0/24"))
        self.assertTrue(PhantomSweeper.is_out_of_subnet("192.168.2.1", "192.168.1.0/24"))

        # Inside local subnet
        self.assertFalse(PhantomSweeper.is_out_of_subnet("192.168.1.50", "192.168.1.0/24"))
        self.assertFalse(PhantomSweeper.is_out_of_subnet("192.168.1.1", "192.168.1.0/24"))

        # Multicast, broadcast, loopback, invalid
        self.assertFalse(PhantomSweeper.is_out_of_subnet("224.0.0.251", "192.168.1.0/24"))
        self.assertFalse(PhantomSweeper.is_out_of_subnet("127.0.0.1", "192.168.1.0/24"))
        self.assertFalse(PhantomSweeper.is_out_of_subnet("0.0.0.0", "192.168.1.0/24"))
        self.assertFalse(PhantomSweeper.is_out_of_subnet("not-valid-ip", "192.168.1.0/24"))
        self.assertFalse(PhantomSweeper.is_out_of_subnet("", "192.168.1.0/24"))
        self.assertFalse(PhantomSweeper.is_out_of_subnet("10.0.0.5", ""))

    def _build_arp_packet(self, sender_ip: str, sender_mac: str) -> bytes:
        eth_dst = b"\xff\xff\xff\xff\xff\xff"
        mac_bytes = bytes.fromhex(sender_mac.replace(":", ""))
        eth_hdr = eth_dst + mac_bytes + struct.pack("!H", 0x0806)
        arp_body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac_bytes + socket.inet_aton(sender_ip) + b"\x00" * 6 + socket.inet_aton("10.0.0.1")
        return eth_hdr + arp_body

    def _build_ipv4_packet(self, src_ip: str, src_mac: str) -> bytes:
        eth_dst = b"\x00\x11\x22\x33\x44\x55"
        mac_bytes = bytes.fromhex(sender_mac := src_mac.replace(":", ""))
        eth_hdr = eth_dst + mac_bytes + struct.pack("!H", 0x0800)
        # Minimal IPv4 header (20 bytes)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton("8.8.8.8"))
        return eth_hdr + ip_hdr + (b"\x00" * 20)

    @patch("socket.socket")
    @patch("socket.if_nametoindex", return_value=2)
    def test_phantom_sweeper_captures_out_of_subnet_arp_and_ipv4(self, mock_ifindex, mock_sock_cls):
        mock_sock = MagicMock()
        
        # 1. ARP from out-of-subnet 10.99.1.5
        arp_pkt = self._build_arp_packet("10.99.1.5", "00:AA:BB:CC:DD:01")
        # 2. Local ARP from 192.168.1.45 (should be ignored)
        local_arp = self._build_arp_packet("192.168.1.45", "00:AA:BB:CC:DD:02")
        # 3. IPv4 from out-of-subnet 172.16.50.2
        ipv4_pkt = self._build_ipv4_packet("172.16.50.2", "00:AA:BB:CC:DD:03")
        # 4. IPv4 from Gateway MAC claiming 172.16.50.99 (should be ignored as routed transit)
        gw_pkt = self._build_ipv4_packet("172.16.50.99", "11:22:33:44:55:66")

        mock_sock.recvfrom.side_effect = [
            (arp_pkt, None),
            (local_arp, None),
            (ipv4_pkt, None),
            (gw_pkt, None),
            TimeoutError(),
        ]
        mock_sock_cls.return_value = mock_sock

        sweeper = PhantomSweeper(
            interface="eth0",
            subnet_cidr="192.168.1.0/24",
            gateway_mac="11:22:33:44:55:66",
        )
        found = sweeper.scan(duration=0.1)

        self.assertIn("10.99.1.5", found)
        self.assertEqual(found["10.99.1.5"], "00:AA:BB:CC:DD:01")

        self.assertIn("172.16.50.2", found)
        self.assertEqual(found["172.16.50.2"], "00:AA:BB:CC:DD:03")

        # Local IP and Gateway transit traffic must not be flagged
        self.assertNotIn("192.168.1.45", found)
        self.assertNotIn("172.16.50.99", found)

    def test_threat_detector_check_phantom_devices(self):
        devices = [
            Device(ip="192.168.1.20", mac="00:11:22:33:44:55", hostname="normal-pc"),
            Device(ip="10.50.1.99", mac="AA:BB:CC:DD:EE:FF", hostname="rogue-implant"),
            Device(ip="192.168.1.1", mac="11:22:33:44:55:66", hostname="gateway"),
        ]

        threats = ThreatDetector.check_phantom_devices(
            devices=devices,
            subnet_cidr="192.168.1.0/24",
            gateway_mac="11:22:33:44:55:66",
        )

        self.assertEqual(len(threats), 1)
        self.assertIn("Out-of-Subnet Static Device / Phantom Implant detected", threats[0])
        self.assertIn("10.50.1.99", threats[0])
        self.assertIn("AA:BB:CC:DD:EE:FF", threats[0])


if __name__ == "__main__":
    unittest.main()
