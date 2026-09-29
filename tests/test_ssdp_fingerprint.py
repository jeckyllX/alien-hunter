"""
Unit tests for SSDP / UPnP device fingerprinting and parsing.
"""

import unittest
from alien_hunter.identifiers.signatures import (
    SignatureManager,
    SsdpSignature,
    SsdpFingerprintStore,
)
from alien_hunter.identifiers.ssdp import SsdpParser


class TestSsdpFingerprinting(unittest.TestCase):

    def setUp(self):
        self.mgr = SignatureManager()
        self.store = SsdpFingerprintStore.get_instance()
        self.store.clear()

    def tearDown(self):
        self.store.clear()

    def test_ssdp_signature_matching(self):
        sig = SsdpSignature(
            vendor="Samsung Smart TV",
            category="Smart TV / Entertainment",
            os_family="Tizen OS",
            server_pattern=r"(?i)(samsung|sec_tizen|tizen)",
        )
        self.assertTrue(sig.matches(server="SHP/2.0 SEC_TIZEN-5.5 UPnP/1.0"))
        self.assertTrue(sig.matches(server="Linux/3.14.0 UPnP/1.0 Samsung-Wlan-AP"))
        self.assertFalse(sig.matches(server="Roku/9.4.0 UPnP/1.0"))

    def test_signature_manager_match_ssdp(self):
        # Samsung
        match_samsung = self.mgr.match_ssdp(server="SEC_TIZEN-6.0 UPnP/1.0")
        self.assertIsNotNone(match_samsung)
        self.assertIn("Samsung", match_samsung.vendor)
        self.assertEqual(match_samsung.os_family, "Tizen OS")

        # Roku
        match_roku = self.mgr.match_ssdp(server="Roku/11.5.0 UPnP/1.0")
        self.assertIsNotNone(match_roku)
        self.assertIn("Roku", match_roku.vendor)

        # Sonos
        match_sonos = self.mgr.match_ssdp(server="Linux 3.14 UPnP/1.0 Sonos/70.1-36070")
        self.assertIsNotNone(match_sonos)
        self.assertIn("Sonos", match_sonos.vendor)

        # Philips Hue
        match_hue = self.mgr.match_ssdp(server="Linux/3.14.0 UPnP/1.0 IpBridge/1.54.0")
        self.assertIsNotNone(match_hue)
        self.assertIn("Philips Hue", match_hue.vendor)

        # Windows UPnP
        match_win = self.mgr.match_ssdp(server="Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0")
        self.assertIsNotNone(match_win)
        self.assertIn("Windows", match_win.vendor)

    def test_ssdp_header_parsing(self):
        raw_payload = (
            b"NOTIFY * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"CACHE-CONTROL: max-age=1800\r\n"
            b"LOCATION: http://192.168.1.55:8080/description.xml\r\n"
            b"NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            b"SERVER: Linux/3.14.0 UPnP/1.0 SEC_TIZEN-5.5\r\n"
            b"USN: uuid:12345678-abcd::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            b"\r\n"
        )
        headers = SsdpParser.parse_headers(raw_payload)
        self.assertEqual(headers.get("server"), "Linux/3.14.0 UPnP/1.0 SEC_TIZEN-5.5")
        self.assertEqual(headers.get("location"), "http://192.168.1.55:8080/description.xml")
        self.assertEqual(headers.get("nt"), "urn:schemas-upnp-org:device:MediaRenderer:1")

    def test_ssdp_process_payload_records_store(self):
        raw_payload = (
            b"NOTIFY * HTTP/1.1\r\n"
            b"SERVER: Roku/10.0.0 UPnP/1.0\r\n"
            b"LOCATION: http://192.168.1.80:8060/dial/dd.xml\r\n"
            b"ST: urn:roku-com:service:ecp:1\r\n"
            b"\r\n"
        )
        parsed = SsdpParser.process_payload(
            data=raw_payload,
            src_ip="192.168.1.80",
            sig_manager=self.mgr,
        )
        self.assertIsNotNone(parsed)
        self.assertIsNotNone(parsed["match"])
        self.assertIn("Roku", parsed["match"].vendor)

        record = self.store.get("192.168.1.80")
        self.assertIsNotNone(record)
        self.assertEqual(record["server"], "Roku/10.0.0 UPnP/1.0")
        self.assertEqual(record["location"], "http://192.168.1.80:8060/dial/dd.xml")
        self.assertIn("urn:roku-com:service:ecp:1", record["services"])

    def test_device_display_name_with_ssdp(self):
        from alien_hunter.models import Device
        dev = Device(
            ip="192.168.1.75",
            mac="DA:A1:19:22:33:44",
            hostname="Unknown",
            vendor="Randomized Private MAC",
            is_randomized=True,
            ssdp_fingerprint="Samsung Smart TV",
        )
        self.assertEqual(dev.display_name, "Samsung Smart TV (Randomized Private MAC)")


if __name__ == "__main__":
    unittest.main()
