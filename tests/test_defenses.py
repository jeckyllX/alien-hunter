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
from alien_hunter.defenses.mdns_canary import MdnsCanaryTrap
from alien_hunter.defenses.dns_integrity import DnsIntegrityAuditor
from alien_hunter.defenses.ipv6_guard import Ipv6Guard
from alien_hunter.defenses.anti_sniff import AntiSniffDetector
from alien_hunter.defenses.port_drift import PortDriftTracker
from alien_hunter.defenses.honey_port import HoneyPortListener, HoneyPortEvent
from alien_hunter.defenses.honey_auth import HoneyAuthTrap
from alien_hunter.defenses.syn_scan import SynScanDetector, SynScanEvent
from alien_hunter.defenses.dns_tunneling import DnsTunnelingDetector, DnsTunnelingEvent
from alien_hunter.defenses.dhcp_starvation import DhcpStarvationGuard, DhcpStarvationEvent


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


class TestMdnsCanaryTrap(unittest.TestCase):
    """Tests mDNS / Bonjour canary query construction and poisoner detection."""

    def test_build_mdns_query(self):
        pkt = MdnsCanaryTrap.build_mdns_query("canary-test", trans_id=0x4321)
        self.assertGreater(len(pkt), 12)
        trans_id, flags, qdcount, ancount = struct.unpack("!HHHH", pkt[:8])
        self.assertEqual(trans_id, 0x4321)
        self.assertEqual(flags, 0)
        self.assertEqual(qdcount, 1)
        self.assertEqual(ancount, 0)
        self.assertIn(b"canary-test", pkt)
        self.assertIn(b"local", pkt)

    def test_parse_dns_name(self):
        encoded = b"\x03foo\x03bar\x05local\x00"
        name, offset = MdnsCanaryTrap._parse_dns_name(encoded, 0)
        self.assertEqual(name, "foo.bar.local")
        self.assertEqual(offset, len(encoded))

    @patch("alien_hunter.defenses.mdns_canary.create_udp_socket")
    def test_detects_active_mdns_poisoner(self, mock_create_sock):
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock

        canary_token = "abcd1234"
        canary_domain = f"canary-srv-{canary_token}.local"
        qname = MdnsCanaryTrap._encode_dns_label(canary_domain)

        # Build simulated affirmative mDNS response from attacker (192.168.1.88)
        # Header: ID 0x4321, Flags 0x8400 (Response, Authoritative), QDCOUNT 1, ANCOUNT 1, NS 0, AR 0
        header = struct.pack("!HHHHHH", 0x4321, 0x8400, 1, 1, 0, 0)
        question = qname + struct.pack("!HH", 1, 1)  # Type A, Class IN
        answer = qname + struct.pack("!HHIH", 1, 1, 120, 4) + socket.inet_aton("192.168.1.88")
        resp_data = header + question + answer

        mock_sock.recvfrom.side_effect = [
            (resp_data, ("192.168.1.88", 5353)),
            TimeoutError(),
        ]

        with patch("os.urandom", side_effect=[bytes.fromhex(canary_token), b"\x43\x21"]):
            threats = MdnsCanaryTrap.check_poisoning(timeout=0.1)

        self.assertTrue(len(threats) > 0)
        self.assertTrue(any("192.168.1.88" in t for t in threats))
        self.assertTrue(any("mDNS / Bonjour Poisoning" in t for t in threats))
        self.assertTrue(any(canary_domain in t for t in threats))

    @patch("alien_hunter.defenses.mdns_canary.create_udp_socket")
    def test_ignores_unrelated_mdns_response(self, mock_create_sock):
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock

        # Unrelated Apple TV AirPlay response
        airplay_domain = "_airplay._tcp.local"
        qname = MdnsCanaryTrap._encode_dns_label(airplay_domain)
        header = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0)
        question = qname + struct.pack("!HH", 12, 1)
        answer = qname + struct.pack("!HHIH", 12, 1, 120, 4) + b"\x01a\x00\x00"
        resp_data = header + question + answer

        mock_sock.recvfrom.side_effect = [
            (resp_data, ("192.168.1.20", 5353)),
            TimeoutError(),
        ]

        with patch("os.urandom", side_effect=[b"\x11\x22\x33\x44", b"\x00\x00"]):
            threats = MdnsCanaryTrap.check_poisoning(timeout=0.1)

        self.assertEqual(threats, [])


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


class TestHoneyAuthTrap(unittest.TestCase):
    """Tests decoy honeypot payload and authentication handshake inspection."""

    def test_inspect_http_payload_extracts_user_agent_and_basic_auth(self):
        mock_conn = MagicMock()
        # Simulated basic auth: admin:password123 -> base64 YWRtaW46cGFzc3dvcmQxMjM=
        payload = (
            b"GET /admin/config HTTP/1.1\r\n"
            b"Host: 192.168.1.10\r\n"
            b"User-Agent: Nikto/2.1.6\r\n"
            b"Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=\r\n\r\n"
        )
        mock_conn.recv.return_value = payload

        meta = HoneyAuthTrap.inspect_connection(mock_conn, dest_port=8080)
        self.assertEqual(meta["payload_snippet"], "GET /admin/config HTTP/1.1")
        self.assertEqual(meta["tooling"], "Nikto/2.1.6")
        self.assertEqual(meta["credentials"], "admin:password123")

    def test_inspect_smb_dialect_probe(self):
        mock_conn = MagicMock()
        payload = b"\x00\x00\x00\x45\xffSMBs\x00\x00\x00\x00"
        mock_conn.recv.return_value = payload

        meta = HoneyAuthTrap.inspect_connection(mock_conn, dest_port=445)
        self.assertEqual(meta["tooling"], "SMB Dialect Probe")
        self.assertEqual(meta["payload_snippet"], "SMB Negotiation Request")


class TestSynScanDetector(unittest.TestCase):
    """Tests stealth TCP SYN, NULL, FIN, and XMAS port scan detection."""

    @staticmethod
    def _make_tcp_pkt(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flags: int,
        src_mac: str = "AA:BB:CC:DD:EE:FF",
    ) -> bytes:
        dst_mac_bytes = b"\x00\x11\x22\x33\x44\x55"
        src_mac_bytes = bytes.fromhex(src_mac.replace(":", ""))
        eth_hdr = dst_mac_bytes + src_mac_bytes + struct.pack("!H", 0x0800)
        s_ip = socket.inet_aton(src_ip)
        d_ip = socket.inet_aton(dst_ip)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 12345, 0, 64, 6, 0, s_ip, d_ip)
        tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, 1000, 0, 0x50, flags, 65535, 0, 0)
        return eth_hdr + ip_hdr + tcp_hdr

    def test_parse_tcp_packet(self):
        pkt = self._make_tcp_pkt("192.168.1.100", "192.168.1.1", 54321, 80, 0x02)
        parsed = SynScanDetector.parse_tcp_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_ip"], "192.168.1.100")
        self.assertEqual(parsed["dst_ip"], "192.168.1.1")
        self.assertEqual(parsed["dst_port"], 80)
        self.assertEqual(parsed["flags"], 0x02)

        # Truncated packet
        self.assertIsNone(SynScanDetector.parse_tcp_packet(pkt[:40]))

        # Non-IPv4 ethertype (e.g. ARP 0x0806)
        arp_pkt = pkt[:12] + struct.pack("!H", 0x0806) + pkt[14:]
        self.assertIsNone(SynScanDetector.parse_tcp_packet(arp_pkt))

    def test_vertical_port_scan_detection(self):
        detector = SynScanDetector(subnet_cidr="192.168.1.0/24", port_threshold=8)
        event = None
        ports = [21, 22, 23, 25, 80, 110, 143, 443]

        for i, port in enumerate(ports):
            pkt = self._make_tcp_pkt("192.168.1.150", "192.168.1.1", 40000 + i, port, 0x02)
            ev = detector.process_packet(pkt)
            if ev:
                event = ev

        self.assertIsNotNone(event)
        self.assertEqual(event.scan_profile, "Vertical Port Scan")
        self.assertEqual(event.scan_type, "SYN Scan")
        self.assertEqual(event.target_count, 8)
        self.assertIn("CRITICAL: Stealth TCP Port Scan detected!", event.to_threat_string())
        self.assertIn("Vertical Port Scan", event.to_threat_string())

    def test_horizontal_subnet_sweep_detection(self):
        detector = SynScanDetector(subnet_cidr="192.168.1.0/24", host_threshold=5)
        event = None

        for i in range(1, 6):
            pkt = self._make_tcp_pkt("192.168.1.150", f"192.168.1.{i}", 40000 + i, 445, 0x02)
            ev = detector.process_packet(pkt)
            if ev:
                event = ev

        self.assertIsNotNone(event)
        self.assertEqual(event.scan_profile, "Horizontal Subnet Sweep")
        self.assertEqual(event.scan_type, "SYN Scan")
        self.assertIn("Horizontal Subnet Sweep", event.to_threat_string())

    def test_abnormal_scan_flags(self):
        detector = SynScanDetector(subnet_cidr="192.168.1.0/24")

        # XMAS Scan (FIN + PSH + URG = 0x29)
        xmas_pkt = self._make_tcp_pkt("192.168.1.200", "192.168.1.1", 41001, 80, 0x29)
        ev_xmas = detector.process_packet(xmas_pkt)
        self.assertIsNotNone(ev_xmas)
        self.assertEqual(ev_xmas.scan_type, "XMAS Scan")

        # NULL Scan (Flags = 0x00)
        null_pkt = self._make_tcp_pkt("192.168.1.201", "192.168.1.1", 41002, 80, 0x00)
        ev_null = detector.process_packet(null_pkt)
        self.assertIsNotNone(ev_null)
        self.assertEqual(ev_null.scan_type, "NULL Scan")

        # FIN Scan (Flags = 0x01)
        fin_pkt = self._make_tcp_pkt("192.168.1.202", "192.168.1.1", 41003, 80, 0x01)
        ev_fin = detector.process_packet(fin_pkt)
        self.assertIsNotNone(ev_fin)
        self.assertEqual(ev_fin.scan_type, "FIN Scan")

    def test_filters_benign_traffic_and_self(self):
        detector = SynScanDetector(
            subnet_cidr="192.168.1.0/24",
            local_ip="192.168.1.50",
            local_mac="AA:BB:CC:00:11:22",
        )

        # Self-originated traffic
        self_pkt = self._make_tcp_pkt("192.168.1.50", "192.168.1.1", 50000, 80, 0x02)
        self.assertIsNone(detector.process_packet(self_pkt))

        # Single benign SYN connection from another host (does not exceed threshold)
        benign_pkt = self._make_tcp_pkt("192.168.1.70", "192.168.1.1", 50001, 443, 0x02)
        self.assertIsNone(detector.process_packet(benign_pkt))

        # Normal established ACK data packet (flags 0x10)
        ack_pkt = self._make_tcp_pkt("192.168.1.70", "192.168.1.1", 50001, 443, 0x10)
        self.assertIsNone(detector.process_packet(ack_pkt))

    @patch("socket.socket")
    def test_sniff_handles_permission_error_gracefully(self, mock_socket_cls):
        mock_socket_cls.side_effect = PermissionError("Operation not permitted")
        detector = SynScanDetector(interface="eth0")
        events = detector.sniff(duration=0.1)
        self.assertEqual(events, [])


class TestDnsTunnelingDetector(unittest.TestCase):
    """Tests high-entropy DNS tunneling and covert exfiltration detection."""

    @staticmethod
    def _make_dns_pkt(
        src_ip: str,
        dst_ip: str,
        domain: str,
        qtype: int = 1,
        src_mac: str = "AA:BB:CC:DD:EE:FF",
    ) -> bytes:
        dst_mac_bytes = b"\x00\x11\x22\x33\x44\x55"
        src_mac_bytes = bytes.fromhex(src_mac.replace(":", ""))
        eth_hdr = dst_mac_bytes + src_mac_bytes + struct.pack("!H", 0x0800)

        hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = bytearray()
        for part in domain.split("."):
            b = part.encode("utf-8")
            qname.append(len(b))
            qname.extend(b)
        qname.append(0)
        qtail = struct.pack("!HH", qtype, 1)
        dns_body = hdr + bytes(qname) + qtail

        udp_len = 8 + len(dns_body)
        udp_hdr = struct.pack("!HHHH", 54321, 53, udp_len, 0)

        ip_len = 20 + udp_len
        s_ip = socket.inet_aton(src_ip)
        d_ip = socket.inet_aton(dst_ip)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 1234, 0, 64, 17, 0, s_ip, d_ip)
        return eth_hdr + ip_hdr + udp_hdr + dns_body

    def test_calculate_shannon_entropy(self):
        self.assertEqual(DnsTunnelingDetector.calculate_shannon_entropy(""), 0.0)
        self.assertEqual(DnsTunnelingDetector.calculate_shannon_entropy("aaaaaaa"), 0.0)
        # Normal dictionary words have low entropy
        self.assertLess(DnsTunnelingDetector.calculate_shannon_entropy("google"), 2.5)
        # Random hex / base32 strings have high entropy
        self.assertGreater(
            DnsTunnelingDetector.calculate_shannon_entropy("a8f9c2d1e0b54321fedcba098765432101234567"),
            3.8,
        )

    def test_parse_dns_packet(self):
        pkt = self._make_dns_pkt("192.168.1.50", "8.8.8.8", "api.example.com", qtype=1)
        parsed = DnsTunnelingDetector.parse_dns_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_ip"], "192.168.1.50")
        self.assertEqual(parsed["query_domain"], "api.example.com")
        self.assertEqual(parsed["longest_label"], "example")
        self.assertEqual(parsed["qtype"], 1)

        # Truncated packet
        self.assertIsNone(DnsTunnelingDetector.parse_dns_packet(pkt[:40]))

        # Non-DNS packet (e.g. TCP port 80)
        tcp_pkt = pkt[:23] + b"\x06" + pkt[24:]
        self.assertIsNone(DnsTunnelingDetector.parse_dns_packet(tcp_pkt))

    def test_detect_high_entropy_dns_tunnel(self):
        detector = DnsTunnelingDetector()
        tunnel_domain = "a8f9c2d1e0b54321fedcba098765432101234567.c2.attacker.com"
        pkt = self._make_dns_pkt("192.168.1.100", "8.8.8.8", tunnel_domain, qtype=1)

        event = detector.process_packet(pkt)
        self.assertIsNotNone(event)
        self.assertEqual(event.src_ip, "192.168.1.100")
        self.assertEqual(event.longest_label, "a8f9c2d1e0b54321fedcba098765432101234567")
        self.assertGreaterEqual(event.entropy, 3.8)
        self.assertEqual(event.qtype_name, "A")
        self.assertIn("High-Entropy DNS Tunneling / Exfiltration detected!", event.to_threat_string())
        self.assertIn("MITRE ATT&CK T1071.004", event.to_threat_string())

    def test_detect_txt_or_null_record_tunnel(self):
        detector = DnsTunnelingDetector()
        # TXT record (QTYPE 16) with length 26 and entropy > 3.6
        tunnel_domain = "k54f2g8b19x83m01zpq928cb4a.c2.net"
        pkt = self._make_dns_pkt("192.168.1.105", "1.1.1.1", tunnel_domain, qtype=16)

        event = detector.process_packet(pkt)
        self.assertIsNotNone(event)
        self.assertEqual(event.qtype_name, "TXT")
        self.assertIn("QType: TXT", event.to_threat_string())

    def test_whitelist_filtering(self):
        detector = DnsTunnelingDetector()

        # Reverse DNS pointer query
        ptr_pkt = self._make_dns_pkt("192.168.1.100", "8.8.8.8", "1.1.168.192.in-addr.arpa", qtype=12)
        self.assertIsNone(detector.process_packet(ptr_pkt))

        # Legitimate cloud CDN suffix
        cdn_domain = "d3g9o9273j5189a8f9c2d1e0b54321fedcba.cloudfront.net"
        cdn_pkt = self._make_dns_pkt("192.168.1.100", "8.8.8.8", cdn_domain, qtype=1)
        self.assertIsNone(detector.process_packet(cdn_pkt))

    def test_burst_detection(self):
        detector = DnsTunnelingDetector(
            burst_threshold=3,
            length_threshold=28,
            entropy_threshold=3.7,
        )

        # Send 3 distinct queries with length >= 28 and entropy >= 3.7
        domains = [
            "c2-data-chunk-01-a8f9c2d1e0b54.attacker.com",
            "c2-data-chunk-02-a8f9c2d1e0b55.attacker.com",
            "c2-data-chunk-03-a8f9c2d1e0b56.attacker.com",
        ]

        event = None
        for d in domains:
            pkt = self._make_dns_pkt("192.168.1.110", "8.8.8.8", d, qtype=1)
            ev = detector.process_packet(pkt)
            if ev:
                event = ev

        self.assertIsNotNone(event)
        self.assertEqual(event.query_count, 3)

    @patch("socket.socket")
    def test_sniff_handles_permission_error_gracefully(self, mock_socket_cls):
        mock_socket_cls.side_effect = PermissionError("Operation not permitted")
        detector = DnsTunnelingDetector(interface="eth0")
        events = detector.sniff(duration=0.1)
        self.assertEqual(events, [])


class TestDhcpStarvationGuard(unittest.TestCase):
    """Tests DHCP starvation, pool exhaustion, and MAC spoofing detection."""

    @staticmethod
    def _make_dhcp_frame(
        src_mac_str: str,
        chaddr_str: str,
        msg_type: int = 1,
        src_ip: str = "0.0.0.0",
        dst_ip: str = "255.255.255.255",
        xid: bytes = b"\x12\x34\x56\x78",
    ) -> bytes:
        dst_mac = b"\xff\xff\xff\xff\xff\xff"
        src_mac = bytes.fromhex(src_mac_str.replace(":", ""))
        ethertype = struct.pack("!H", 0x0800)

        options = b"\x35\x01" + bytes([msg_type]) + b"\xff"

        bootp = bytearray(240)
        bootp[0] = 1  # BOOTREQUEST
        bootp[1] = 1  # 10Mb Ethernet
        bootp[2] = 6  # 6-byte MAC
        bootp[3] = 0  # hops
        bootp[4:8] = xid
        bootp[8:10] = b"\x00\x00"
        bootp[10:12] = b"\x80\x00"
        bootp[12:16] = socket.inet_aton(src_ip)
        bootp[28:34] = bytes.fromhex(chaddr_str.replace(":", ""))
        bootp[236:240] = b"\x63\x82\x53\x63"
        bootp.extend(options)

        udp_len = 8 + len(bootp)
        udp_hdr = struct.pack("!HHHH", 68, 67, udp_len, 0)

        ip_total_len = 20 + udp_len
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_len,
            0x1234,
            0,
            64,
            17,  # UDP
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )

        return dst_mac + src_mac + ethertype + ip_hdr + udp_hdr + bytes(bootp)

    def test_parse_dhcp_packet_valid_discover(self):
        pkt = self._make_dhcp_frame("00:11:22:33:44:55", "00:11:22:33:44:55", msg_type=1)
        parsed = DhcpStarvationGuard.parse_dhcp_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_mac"], "00:11:22:33:44:55")
        self.assertEqual(parsed["chaddr"], "00:11:22:33:44:55")
        self.assertEqual(parsed["msg_type"], 1)
        self.assertFalse(parsed["is_spoofed"])

    def test_parse_dhcp_packet_spoofed_chaddr(self):
        pkt = self._make_dhcp_frame("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55", msg_type=1)
        parsed = DhcpStarvationGuard.parse_dhcp_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(parsed["chaddr"], "00:11:22:33:44:55")
        self.assertTrue(parsed["is_spoofed"])

    def test_parse_dhcp_packet_non_dhcp_short(self):
        self.assertIsNone(DhcpStarvationGuard.parse_dhcp_packet(b"\x00" * 100))

    def test_detects_dhcp_starvation_burst(self):
        guard = DhcpStarvationGuard(burst_threshold=5, rate_threshold=10.0, window_seconds=5.0, alert_cooldown=30.0)
        macs = [
            "02:00:00:00:00:01",
            "02:00:00:00:00:02",
            "02:00:00:00:00:03",
            "02:00:00:00:00:04",
            "02:00:00:00:00:05",
        ]

        event = None
        base_time = 1000.0
        for i, mac in enumerate(macs):
            pkt = self._make_dhcp_frame(mac, mac, msg_type=1)
            ev = guard.process_packet(pkt, now=base_time + (i * 0.5))
            if ev:
                event = ev

        self.assertIsNotNone(event)
        self.assertEqual(event.distinct_mac_count, 5)
        self.assertEqual(event.request_count, 5)
        self.assertIn("DHCP Starvation", event.to_threat_string())

    def test_detects_dhcp_rate_flood(self):
        guard = DhcpStarvationGuard(burst_threshold=10, rate_threshold=3.0, window_seconds=5.0)
        macs = [
            "02:00:00:00:00:01",
            "02:00:00:00:00:02",
            "02:00:00:00:00:03",
        ]

        event = None
        base_time = 1000.0
        # 3 distinct MACs within 0.4s -> 7.5 req/s, exceeding rate_threshold=3.0
        for i, mac in enumerate(macs):
            pkt = self._make_dhcp_frame(mac, mac, msg_type=1)
            ev = guard.process_packet(pkt, now=base_time + (i * 0.2))
            if ev:
                event = ev

        self.assertIsNotNone(event)
        self.assertEqual(event.distinct_mac_count, 3)
        self.assertGreaterEqual(event.burst_rate, 3.0)

    def test_detects_mac_spoofing_flood(self):
        guard = DhcpStarvationGuard(burst_threshold=5, window_seconds=5.0, alert_cooldown=30.0)
        attacker_nic = "AA:BB:CC:11:22:33"
        spoofed_chaddrs = [
            "DE:AD:BE:EF:00:01",
            "DE:AD:BE:EF:00:02",
            "DE:AD:BE:EF:00:03",
        ]

        event = None
        base_time = 1000.0
        for i, chaddr in enumerate(spoofed_chaddrs):
            pkt = self._make_dhcp_frame(attacker_nic, chaddr, msg_type=1)
            ev = guard.process_packet(pkt, now=base_time + (i * 0.1))
            if ev:
                event = ev

        self.assertIsNotNone(event)
        self.assertTrue(event.is_spoofed_chaddr)
        self.assertEqual(event.primary_src_mac, attacker_nic)
        self.assertIn("Spoofed DHCP chaddr", event.to_threat_string())

    def test_alert_cooldown_suppression(self):
        guard = DhcpStarvationGuard(burst_threshold=3, alert_cooldown=10.0)
        macs = ["02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"]
        base_time = 1000.0

        event1 = None
        for i, mac in enumerate(macs):
            pkt = self._make_dhcp_frame(mac, mac, msg_type=1)
            ev = guard.process_packet(pkt, now=base_time + (i * 0.1))
            if ev:
                event1 = ev

        self.assertIsNotNone(event1)

        pkt4 = self._make_dhcp_frame("02:00:00:00:00:04", "02:00:00:00:00:04", msg_type=1)
        event2 = guard.process_packet(pkt4, now=base_time + 1.0)
        self.assertIsNone(event2)

    @patch("socket.socket")
    def test_sniff_handles_permission_error_gracefully(self, mock_socket_cls):
        mock_socket_cls.side_effect = PermissionError("Operation not permitted")
        guard = DhcpStarvationGuard(interface="eth0")
        events = guard.sniff(duration=0.1)
        self.assertEqual(events, [])

    @patch("alien_hunter.threats.DhcpStarvationGuard.sniff")
    def test_threat_detector_facade_check(self, mock_sniff):
        from alien_hunter.threats import ThreatDetector

        mock_event = MagicMock()
        mock_event.to_threat_string.return_value = "CRITICAL: DHCP Starvation detected!"
        mock_sniff.return_value = [mock_event]

        threats = ThreatDetector.check_dhcp_starvation(interface="eth0", duration=0.1)
        self.assertEqual(len(threats), 1)
        self.assertIn("DHCP Starvation", threats[0])


if __name__ == "__main__":
    unittest.main()

