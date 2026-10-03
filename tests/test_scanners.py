"""
Unit and functional tests for Alien Hunter scanners and defensive threat detection.
"""

import struct
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.scanners.sniffer import PassiveFrameSniffer
from alien_hunter.scanners.ssdp import SsdpScanner
from alien_hunter.scanners.netbios import NetbiosScanner
from alien_hunter.scanners.arp import ArpScanner, NativeArpSweeper
from alien_hunter.scanners.ports import PortScanner
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


class TestNativeArpSweeper(unittest.TestCase):
    """Tests pure Python raw AF_PACKET ARP broadcast scanning."""

    @patch("socket.socket")
    @patch("select.select")
    def test_native_arp_sweep_receives_replies(self, mock_select, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        def fake_select(r, w, x, timeout=0):
            import time
            time.sleep(0.06)
            return ([mock_sock], [], [])

        mock_select.side_effect = fake_select

        # Simulated incoming ARP reply from 192.168.1.50 (AA:BB:CC:DD:EE:11)
        target_mac = bytes.fromhex("AABBCCDDEE11")
        target_ip = bytes([192, 168, 1, 50])
        local_mac = bytes.fromhex("001122334455")
        local_ip = bytes([192, 168, 1, 73])

        eth_hdr = local_mac + target_mac + struct.pack("!H", 0x0806)
        arp_reply = struct.pack(
            "!HHBBH6s4s6s4s",
            1, 0x0800, 6, 4, 2,  # Opcode 2 = Reply
            target_mac, target_ip,
            local_mac, local_ip,
        )
        resp_pkt = eth_hdr + arp_reply

        mock_sock.recvfrom.side_effect = [(resp_pkt, ("wlan0", 0))] + [BlockingIOError()] * 10

        devices = NativeArpSweeper.sweep(
            interface="wlan0",
            local_mac="00:11:22:33:44:55",
            local_ip="192.168.1.73",
            subnet_cidr="192.168.1.0/24",
            timeout=0.05,
        )

        self.assertIn("192.168.1.50", devices)
        self.assertEqual(devices["192.168.1.50"], "AA:BB:CC:DD:EE:11")
        mock_sock.close.assert_called()


class TestArpScanner(unittest.TestCase):
    """Tests Layer-2 ARP scanner logic, candidate unicast probing, and neighbor filtering."""

    @patch("subprocess.run")
    @patch.object(NativeArpSweeper, "sweep", return_value={})
    def test_scan_filters_failed_and_stale_neighbors(self, mock_sweep, mock_subproc):
        # Simulated ip neigh with 1 REACHABLE host, 1 FAILED host, and 1 STALE host
        import json
        neigh_json = json.dumps([
            {"dst": "192.168.1.1", "lladdr": "18:EF:C0:10:FF:B0", "state": ["REACHABLE"]},
            {"dst": "192.168.1.112", "lladdr": "08:ED:B9:1A:37:BD", "state": ["FAILED"]},
            {"dst": "192.168.1.132", "lladdr": "64:4A:7D:D0:0E:1C", "state": ["INCOMPLETE"]},
        ])
        mock_res = MagicMock()
        mock_res.stdout = neigh_json
        mock_res.returncode = 0
        mock_subproc.return_value = mock_res

        scanner = ArpScanner(
            interface="eth0",
            local_mac="00:11:22:33:44:55",
            local_ip="192.168.1.73",
            subnet_cidr="192.168.1.0/24",
        )
        devs = scanner.scan()

        self.assertIn("192.168.1.1", devs)
        self.assertNotIn("192.168.1.112", devs)
        self.assertNotIn("192.168.1.132", devs)

    @patch("subprocess.run")
    @patch.object(NativeArpSweeper, "sweep", return_value={})
    def test_proc_net_arp_requires_atf_com_flag(self, mock_sweep, mock_subproc):
        mock_subproc.side_effect = Exception("ip command unavailable")

        # 192.168.1.10 has 0x2 (ATF_COM - completed), 192.168.1.112 has 0x0 (failed)
        arp_data = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.10     0x1         0x2         AA:BB:CC:DD:EE:10     *        eth0\n"
            "192.168.1.112    0x1         0x0         08:ED:B9:1A:37:BD     *        eth0\n"
        )
        with patch("builtins.open", unittest.mock.mock_open(read_data=arp_data)):
            scanner = ArpScanner(
                interface="eth0",
                local_mac="00:11:22:33:44:55",
                local_ip="192.168.1.73",
                subnet_cidr="192.168.1.0/24",
            )
            devs = scanner.scan()

        self.assertIn("192.168.1.10", devs)
        self.assertNotIn("192.168.1.112", devs)


class TestPortScannerBanner(unittest.TestCase):
    """Tests protocol-agnostic service banner probing and integration."""

    @patch("socket.socket")
    def test_probe_service_banner_spontaneous_greeting(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        mock_sock.__enter__.return_value = mock_sock
        mock_socket_cls.return_value = mock_sock

        scanner = PortScanner()
        banner = scanner.probe_service_banner("192.168.1.50", 22)

        self.assertEqual(banner, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

    @patch("urllib.request.urlopen")
    @patch("socket.socket")
    def test_probe_service_banner_http_fallback(self, mock_socket_cls, mock_urlopen):
        # Socket greeting returns empty
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        mock_sock.__enter__.return_value = mock_sock
        mock_socket_cls.return_value = mock_sock

        # HTTP returns server header and HTML title
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
        mock_resp.read.return_value = b"<html><head><title>Test Gateway</title></head><body>OK</body></html>"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        scanner = PortScanner()
        banner = scanner.probe_service_banner("192.168.1.50", 80)

        self.assertEqual(banner, "Server: Apache/2.4.41 (Ubuntu); Title: 'Test Gateway'")

    @patch("socket.socket")
    def test_probe_service_banner_connection_failure(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        mock_sock.__enter__.return_value = mock_sock
        mock_socket_cls.return_value = mock_sock

        scanner = PortScanner()
        banner = scanner.probe_service_banner("192.168.1.50", 9999)

        self.assertIsNone(banner)

    @patch.object(PortScanner, "check_port", side_effect=lambda ip, port: port == 22)
    @patch.object(PortScanner, "probe_service_banner", return_value="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
    def test_scan_host_records_banner_in_notes(self, mock_banner, mock_probe):
        scanner = PortScanner()
        open_ports, threats, notes = scanner.scan_host("192.168.1.50", deep_scan=False)

        self.assertIn("22/SSH", open_ports)
        self.assertTrue(any("Banner (22/SSH): SSH-2.0-OpenSSH_8.9p1" in n for n in notes))


if __name__ == "__main__":
    unittest.main()

