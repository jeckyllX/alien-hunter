"""
Unit and functional tests for Alien Hunter scanners and defensive threat detection.
"""

import struct
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.scanners.sniffer import PassiveFrameSniffer
from alien_hunter.scanners.ssdp import SsdpScanner
from alien_hunter.scanners.netbios import NetbiosScanner
from alien_hunter.threats import ThreatDetector


class TestPassiveFrameSniffer(unittest.TestCase):
    """Tests hardware promiscuous mode socket setup and packet handling."""

    def test_promiscuous_constants(self):
        self.assertEqual(PassiveFrameSniffer.PACKET_ADD_MEMBERSHIP, 1)
        self.assertEqual(PassiveFrameSniffer.PACKET_DROP_MEMBERSHIP, 2)
        self.assertEqual(PassiveFrameSniffer.PACKET_MR_PROMISC, 1)

    @patch("socket.socket")
    @patch("socket.if_nametoindex", return_value=3)
    def test_promiscuous_mode_enabled_and_cleaned_up(self, mock_ifindex, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = TimeoutError()
        mock_socket_cls.return_value = mock_sock

        sniffer = PassiveFrameSniffer(interface="wlan0")
        result = sniffer.sniff(duration=0.1)

        self.assertIsInstance(result, dict)
        mock_ifindex.assert_called_once_with("wlan0")
        # Check that setsockopt was called with PACKET_ADD_MEMBERSHIP and then PACKET_DROP_MEMBERSHIP
        calls = [c[0] for c in mock_sock.setsockopt.call_args_list]
        self.assertTrue(any(PassiveFrameSniffer.PACKET_ADD_MEMBERSHIP in c for c in calls))
        self.assertTrue(any(PassiveFrameSniffer.PACKET_DROP_MEMBERSHIP in c for c in calls))
        mock_sock.close.assert_called_once()


class TestSsdpScanner(unittest.TestCase):
    """Tests SSDP / UPnP response parsing and descriptor extraction."""

    def test_parse_headers(self):
        raw_resp = (
            "HTTP/1.1 200 OK\r\n"
            "CACHE-CONTROL: max-age=1800\r\n"
            "LOCATION: http://192.168.1.100:8080/description.xml\r\n"
            "SERVER: Linux/3.14.0 UPnP/1.0 Sonos/66.2-22120\r\n"
            "ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n"
            "USN: uuid:RINCON_123456789::urn:schemas-upnp-org:device:ZonePlayer:1\r\n"
            "\r\n"
        )
        headers = SsdpScanner._parse_headers(raw_resp)
        self.assertEqual(headers["location"], "http://192.168.1.100:8080/description.xml")
        self.assertEqual(headers["server"], "Linux/3.14.0 UPnP/1.0 Sonos/66.2-22120")
        self.assertEqual(headers["st"], "urn:schemas-upnp-org:device:ZonePlayer:1")

    @patch("urllib.request.urlopen")
    def test_fetch_device_descriptor(self, mock_urlopen):
        xml_data = (
            b'<?xml version="1.0"?>\n'
            b'<root xmlns="urn:schemas-upnp-org:device-1-0">\n'
            b'  <device>\n'
            b'    <friendlyName>Living Room Speaker</friendlyName>\n'
            b'    <manufacturer>Sonos, Inc.</manufacturer>\n'
            b'    <modelName>Sonos One</modelName>\n'
            b'  </device>\n'
            b'</root>'
        )
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = xml_data
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = SsdpScanner._fetch_device_descriptor("http://192.168.1.100:8080/desc.xml")
        self.assertIsNotNone(res)
        self.assertEqual(res["device_name"], "Living Room Speaker")
        self.assertEqual(res["manufacturer"], "Sonos, Inc.")
        self.assertEqual(res["model"], "Sonos One")


class TestNetbiosScanner(unittest.TestCase):
    """Tests NetBIOS Node Status query building and response decoding."""

    def test_build_node_status_request(self):
        pkt = NetbiosScanner.build_node_status_request(0x1337)
        self.assertEqual(len(pkt), 50)
        trans_id = struct.unpack("!H", pkt[:2])[0]
        self.assertEqual(trans_id, 0x1337)

    def test_parse_node_status_response(self):
        header = struct.pack("!HHHHHH", 0x1337, 0x8400, 1, 1, 0, 0)
        q = b"\x20CK" + (b"AA" * 15) + b"\x00\x00\x21\x00\x01"

        # Answer Section
        comp_record = b"WIN-SERVER-01  \x00" + struct.pack("!H", 0x0400)  # Unique host
        workgroup_record = b"CORP-DOMAIN    \x00" + struct.pack("!H", 0x8400)  # Group
        unit_mac = bytes.fromhex("001122334455")
        rdata = (
            struct.pack("!B", 2)
            + comp_record
            + workgroup_record
            + unit_mac
            + bytes(40)
        )
        ans_rr = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 0x0021, 0x0001, 300, len(rdata))
            + rdata
        )

        full_pkt = header + q + ans_rr
        parsed = NetbiosScanner._parse_node_status_response(full_pkt)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["computer_name"], "WIN-SERVER-01")
        self.assertEqual(parsed["workgroup"], "CORP-DOMAIN")
        self.assertEqual(parsed["mac"], "00:11:22:33:44:55")


class TestThreatDetectorRogueDhcp(unittest.TestCase):
    """Tests Rogue DHCP and DHCP Gateway Hijacking detection."""

    @patch("socket.socket")
    def test_detects_rogue_dhcp_server(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Mock incoming DHCPOFFER from unauthorized server 192.168.1.200
        xid = b"\xaa\xbb\xcc\xdd"
        pkt = bytearray(240)
        pkt[0] = 2  # BOOTREPLY
        pkt[4:8] = xid
        pkt[16:20] = bytes([192, 168, 1, 150])  # Offered IP
        pkt[236:240] = b"\x63\x82\x53\x63"
        # Option 53: Offer (2)
        pkt.extend(b"\x35\x01\x02")
        # Option 54: Server ID (192.168.1.200)
        pkt.extend(b"\x36\x04" + bytes([192, 168, 1, 200]))
        # Option 3: Router (192.168.1.200)
        pkt.extend(b"\x03\x04" + bytes([192, 168, 1, 200]))
        pkt.extend(b"\xff")

        with patch("os.urandom", return_value=xid):
            mock_sock.recvfrom.side_effect = [
                (bytes(pkt), ("192.168.1.200", 67)),
                TimeoutError(),
            ]

            threats = ThreatDetector.check_rogue_dhcp(
                interface="eth0",
                local_mac="AA:BB:CC:DD:EE:FF",
                gateway_ip="192.168.1.1",  # Legitimate gateway is 192.168.1.1
                timeout=0.1,
            )

        self.assertTrue(len(threats) > 0)
        self.assertTrue(any("Rogue DHCP Server detected" in t for t in threats))
        self.assertTrue(any("192.168.1.200" in t for t in threats))

    @patch("socket.socket")
    def test_legitimate_gateway_dhcp_no_threat(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        xid = b"\x11\x22\x33\x44"
        pkt = bytearray(240)
        pkt[0] = 2
        pkt[4:8] = xid
        pkt[16:20] = bytes([192, 168, 1, 75])
        pkt[236:240] = b"\x63\x82\x53\x63"
        pkt.extend(b"\x35\x01\x02")
        # Option 54: Server ID (192.168.1.1)
        pkt.extend(b"\x36\x04" + bytes([192, 168, 1, 1]))
        # Option 3: Router (192.168.1.1)
        pkt.extend(b"\x03\x04" + bytes([192, 168, 1, 1]))
        pkt.extend(b"\xff")

        with patch("os.urandom", return_value=xid):
            mock_sock.recvfrom.side_effect = [
                (bytes(pkt), ("192.168.1.1", 67)),
                TimeoutError(),
            ]

            threats = ThreatDetector.check_rogue_dhcp(
                interface="eth0",
                local_mac="AA:BB:CC:DD:EE:FF",
                gateway_ip="192.168.1.1",
                timeout=0.1,
            )

        self.assertEqual(threats, [])


if __name__ == "__main__":
    unittest.main()
