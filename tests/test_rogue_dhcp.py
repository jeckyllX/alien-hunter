"""
Unit and functional tests for the Rogue DHCP Server & Gateway Hijack Canary Guard (RogueDhcpGuard).
"""

import os
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.defenses.rogue_dhcp import RogueDhcpGuard, RogueDhcpEvent
from alien_hunter.threats import ThreatDetector


class TestRogueDhcpGuard(unittest.TestCase):
    """Tests for packet generation, parsing, and detection of rogue DHCP servers and gateway hijacking."""

    @staticmethod
    def _build_dhcp_reply_payload(
        xid: bytes,
        yiaddr: str = "192.168.1.120",
        server_ip: str = "192.168.1.1",
        router_ip: str = "192.168.1.1",
        dns_ips: list = None,
        domain: str = "lan",
        lease: int = 86400,
        msg_type: int = 2,  # 2 = DHCPOFFER, 5 = DHCPACK
        chaddr: str = "02:11:22:33:44:55",
    ) -> bytes:
        pkt = bytearray(240)
        pkt[0] = 2  # BOOTREPLY
        pkt[1] = 1  # HTYPE: Ethernet
        pkt[2] = 6  # HLEN
        pkt[3] = 0  # HOPS
        pkt[4:8] = xid
        pkt[8:10] = b"\x00\x00"
        pkt[10:12] = b"\x80\x00"  # Broadcast flag
        pkt[12:16] = b"\x00\x00\x00\x00"  # ciaddr
        pkt[16:20] = socket.inet_aton(yiaddr)  # yiaddr
        pkt[20:24] = socket.inet_aton(server_ip)  # siaddr
        pkt[24:28] = b"\x00\x00\x00\x00"  # giaddr

        clean_mac = chaddr.replace(":", "")
        pkt[28 : 28 + len(bytes.fromhex(clean_mac))] = bytes.fromhex(clean_mac)
        pkt[236:240] = RogueDhcpGuard.MAGIC_COOKIE

        # Option 53: Message Type
        pkt.extend(struct.pack("!BBB", 53, 1, msg_type))
        # Option 54: Server Identifier
        pkt.extend(struct.pack("!BB4s", 54, 4, socket.inet_aton(server_ip)))
        # Option 1: Subnet Mask
        pkt.extend(struct.pack("!BB4s", 1, 4, socket.inet_aton("255.255.255.0")))
        # Option 3: Router
        if router_ip:
            pkt.extend(struct.pack("!BB4s", 3, 4, socket.inet_aton(router_ip)))
        # Option 6: DNS Servers
        if dns_ips:
            dns_bytes = b"".join(socket.inet_aton(ip) for ip in dns_ips)
            pkt.extend(struct.pack("!BB", 6, len(dns_bytes)) + dns_bytes)
        # Option 15: Domain Name
        if domain:
            dom_bytes = domain.encode("utf-8")
            pkt.extend(struct.pack("!BB", 15, len(dom_bytes)) + dom_bytes)
        # Option 51: Lease Time
        if lease:
            pkt.extend(struct.pack("!BBI", 51, 4, lease))
        # Option 255: End
        pkt.extend(b"\xff")
        return bytes(pkt)

    @classmethod
    def _build_l2_frame(
        cls,
        eth_src: str,
        eth_dst: str,
        src_ip: str,
        dst_ip: str,
        dhcp_payload: bytes,
    ) -> bytes:
        udp_len = 8 + len(dhcp_payload)
        udp_hdr = struct.pack("!HHHH", 67, 68, udp_len, 0)
        ip_total_len = 20 + udp_len
        ip_hdr_no_ck = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_len,
            0x1234,
            0,
            64,
            17,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        cksum = RogueDhcpGuard._calc_ip_checksum(ip_hdr_no_ck)
        ip_hdr = ip_hdr_no_ck[:10] + struct.pack("!H", cksum) + ip_hdr_no_ck[12:]
        eth_hdr = (
            bytes.fromhex(eth_dst.replace(":", ""))
            + bytes.fromhex(eth_src.replace(":", ""))
            + struct.pack("!H", 0x0800)
        )
        return eth_hdr + ip_hdr + udp_hdr + dhcp_payload

    def test_build_dhcp_discover(self):
        xid = b"\x11\x22\x33\x44"
        chaddr = bytes.fromhex("021122334455")
        pkt = RogueDhcpGuard.build_dhcp_discover(xid=xid, chaddr_bytes=chaddr)
        self.assertGreaterEqual(len(pkt), 240)
        self.assertEqual(pkt[0], 1)  # BOOTREQUEST
        self.assertEqual(pkt[4:8], xid)
        self.assertEqual(pkt[236:240], RogueDhcpGuard.MAGIC_COOKIE)
        self.assertIn(b"\x35\x01\x01", pkt)  # Option 53: Discover

    def test_build_raw_dhcp_discover_frame(self):
        xid = b"\xaa\xbb\xcc\xdd"
        chaddr = "02:11:22:33:44:55"
        frame = RogueDhcpGuard.build_raw_dhcp_discover_frame(xid, chaddr)
        self.assertGreater(len(frame), 282)
        # Check EtherType IPv4
        ethertype = struct.unpack("!H", frame[12:14])[0]
        self.assertEqual(ethertype, 0x0800)
        # Check UDP protocol
        self.assertEqual(frame[23], 17)

    def test_parse_dhcp_packet_bare_bootp(self):
        xid = b"\x99\x88\x77\x66"
        payload = self._build_dhcp_reply_payload(
            xid=xid,
            yiaddr="192.168.1.155",
            server_ip="192.168.1.1",
            router_ip="192.168.1.1",
            dns_ips=["192.168.1.1", "8.8.8.8"],
            domain="corp.local",
            lease=3600,
        )
        parsed = RogueDhcpGuard.parse_dhcp_packet(payload)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["op"], 2)
        self.assertEqual(parsed["xid"], xid)
        self.assertEqual(parsed["yiaddr"], "192.168.1.155")
        self.assertEqual(parsed["server_id"], "192.168.1.1")
        self.assertEqual(parsed["routers"], ["192.168.1.1"])
        self.assertEqual(parsed["dns_servers"], ["192.168.1.1", "8.8.8.8"])
        self.assertEqual(parsed["domain_name"], "corp.local")
        self.assertEqual(parsed["lease_time"], 3600)

    def test_detects_rogue_dhcp_server_passive(self):
        guard = RogueDhcpGuard(
            gateway_ip="192.168.1.1",
            gateway_mac="00:11:22:33:44:55",
            alert_cooldown=30.0,
        )
        xid = b"\x01\x02\x03\x04"
        payload = self._build_dhcp_reply_payload(
            xid=xid,
            server_ip="192.168.1.99",  # Rogue server
            router_ip="192.168.1.99",  # Rogue router
        )
        l2_frame = self._build_l2_frame(
            eth_src="AA:BB:CC:DD:EE:99",
            eth_dst="FF:FF:FF:FF:FF:FF",
            src_ip="192.168.1.99",
            dst_ip="255.255.255.255",
            dhcp_payload=payload,
        )

        events = guard.process_packet(l2_frame)
        self.assertGreaterEqual(len(events), 1)

        types = [e.threat_type for e in events]
        self.assertIn("ROGUE_SERVER", types)
        rogue_ev = next(e for e in events if e.threat_type == "ROGUE_SERVER")
        self.assertEqual(rogue_ev.server_ip, "192.168.1.99")
        self.assertEqual(rogue_ev.server_mac, "AA:BB:CC:DD:EE:99")
        self.assertIn("Rogue DHCP Server detected", rogue_ev.to_threat_string())
        self.assertIn("MITRE ATT&CK T1557", rogue_ev.to_threat_string())

    def test_detects_gateway_hijack_passive(self):
        # Server is authorized IP 192.168.1.1 but advertises router 192.168.1.200 (MitM hijack)
        guard = RogueDhcpGuard(
            gateway_ip="192.168.1.1",
            gateway_mac="00:11:22:33:44:55",
            alert_cooldown=30.0,
        )
        xid = b"\x05\x06\x07\x08"
        payload = self._build_dhcp_reply_payload(
            xid=xid,
            server_ip="192.168.1.1",
            router_ip="192.168.1.200",  # Hijacked gateway!
        )
        l2_frame = self._build_l2_frame(
            eth_src="00:11:22:33:44:55",
            eth_dst="FF:FF:FF:FF:FF:FF",
            src_ip="192.168.1.1",
            dst_ip="255.255.255.255",
            dhcp_payload=payload,
        )

        events = guard.process_packet(l2_frame)
        self.assertGreaterEqual(len(events), 1)

        hijack_ev = next(e for e in events if e.threat_type == "GATEWAY_HIJACK")
        self.assertEqual(hijack_ev.offered_router, "192.168.1.200")
        self.assertEqual(hijack_ev.expected_gateway_ip, "192.168.1.1")
        self.assertIn("DHCP Gateway Hijacking detected", hijack_ev.to_threat_string())

    def test_alert_cooldown_suppresses_duplicate_alerts(self):
        guard = RogueDhcpGuard(
            gateway_ip="192.168.1.1",
            alert_cooldown=10.0,
        )
        xid = b"\x11\x11\x11\x11"
        payload = self._build_dhcp_reply_payload(
            xid=xid, server_ip="192.168.1.99", router_ip="192.168.1.99"
        )
        l2_frame = self._build_l2_frame(
            eth_src="AA:BB:CC:DD:EE:99",
            eth_dst="FF:FF:FF:FF:FF:FF",
            src_ip="192.168.1.99",
            dst_ip="255.255.255.255",
            dhcp_payload=payload,
        )

        ev1 = guard.process_packet(l2_frame, now=1000.0)
        self.assertEqual(len(ev1), 2)  # ROGUE_SERVER and GATEWAY_HIJACK

        # Immediate repeat within cooldown
        ev2 = guard.process_packet(l2_frame, now=1005.0)
        self.assertEqual(len(ev2), 0)

        # After cooldown expiry
        ev3 = guard.process_packet(l2_frame, now=1015.0)
        self.assertEqual(len(ev3), 2)

    def test_update_topology(self):
        guard = RogueDhcpGuard()
        self.assertIsNone(guard.gateway_ip)
        self.assertEqual(guard.authorized_dhcp_ips, set())

        guard.update_topology(
            gateway_ip="192.168.1.254",
            gateway_mac="00:22:33:44:55:66",
            authorized_dhcp_ips={"192.168.1.253"},
        )
        self.assertEqual(guard.gateway_ip, "192.168.1.254")
        self.assertEqual(guard.gateway_mac, "00:22:33:44:55:66")
        self.assertIn("192.168.1.254", guard.authorized_dhcp_ips)
        self.assertIn("192.168.1.253", guard.authorized_dhcp_ips)

    @patch("socket.socket")
    def test_probe_canary_detects_multiple_servers(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        canary_xid = b"\xaa\xbb\xcc\xdd"

        # Server 1: legitimate gateway
        s1_payload = self._build_dhcp_reply_payload(
            xid=canary_xid,
            server_ip="192.168.1.1",
            router_ip="192.168.1.1",
        )
        # Server 2: rogue attacker
        s2_payload = self._build_dhcp_reply_payload(
            xid=canary_xid,
            server_ip="192.168.1.88",
            router_ip="192.168.1.88",
        )

        mock_sock.recvfrom.side_effect = [
            (s1_payload, ("192.168.1.1", 67)),
            (s2_payload, ("192.168.1.88", 67)),
            socket.timeout(),
        ]

        guard = RogueDhcpGuard(
            gateway_ip="192.168.1.1",
            gateway_mac="00:11:22:33:44:55",
        )

        with patch("os.urandom", side_effect=[b"\x12\x34\x56\x78\x90", canary_xid]):
            events = guard.probe_canary(timeout=0.1)

        types = [e.threat_type for e in events]
        self.assertIn("MULTIPLE_SERVERS", types)
        self.assertIn("ROGUE_SERVER", types)

        multi_ev = next(e for e in events if e.threat_type == "MULTIPLE_SERVERS")
        self.assertTrue(multi_ev.is_canary)
        self.assertIn("[Canary Trap]", multi_ev.to_threat_string())
        self.assertIn("Multiple DHCP Servers active", multi_ev.to_threat_string())

    @patch("alien_hunter.threats.RogueDhcpGuard.probe_canary")
    def test_threat_detector_facade_check(self, mock_probe):
        mock_event = RogueDhcpEvent(
            threat_type="ROGUE_SERVER",
            server_ip="192.168.1.99",
            offered_router="192.168.1.99",
            is_canary=True,
        )
        mock_probe.return_value = [mock_event]

        threats = ThreatDetector.check_rogue_dhcp(
            interface="wlan0",
            gateway_ip="192.168.1.1",
            timeout=0.1,
        )
        self.assertEqual(len(threats), 1)
        self.assertIn("Rogue DHCP Server detected", threats[0])
        self.assertIn("[Canary Trap]", threats[0])


if __name__ == "__main__":
    unittest.main()
