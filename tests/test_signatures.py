"""
Unit tests for SignatureManager and DhcpFingerprintStore.
Tests DHCP Option 55 sequence matching, vendor class matching, and mDNS service detection.
"""

import unittest
from alien_hunter.identifiers.signatures import (
    SignatureManager,
    DhcpSignature,
    MdnsSignature,
    DhcpFingerprintStore,
)


class TestSignatureManager(unittest.TestCase):
    def setUp(self):
        self.mgr = SignatureManager()

    def test_bundled_signatures_loaded(self):
        """Verifies bundled signatures.json is discovered and parsed."""
        self.assertGreater(len(self.mgr.dhcp_signatures), 10)
        self.assertGreater(len(self.mgr.mdns_signatures), 10)
        self.assertGreater(len(self.mgr.ssdp_signatures), 10)
        self.assertGreater(len(self.mgr.tcp_syn_signatures), 5)

    def test_match_apple_ios(self):
        """Tests exact and prefix matching for Apple iOS DHCP Option 55."""
        # iOS 14-18 standard sequence
        ios_params = [1, 121, 3, 6, 15, 114, 119, 252]
        match = self.mgr.match_dhcp(ios_params)
        self.assertIsNotNone(match)
        self.assertIn("Apple iOS", match.vendor)
        self.assertEqual(match.category, "Smartphone")
        self.assertEqual(match.confidence, "HIGH")

    def test_match_android(self):
        """Tests matching for Google Android devices with vendor class."""
        android_params = [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]
        match = self.mgr.match_dhcp(android_params, vendor_class="android-dhcp-14")
        self.assertIsNotNone(match)
        self.assertIn("Android", match.vendor)
        self.assertEqual(match.category, "Smartphone")

    def test_match_windows(self):
        """Tests matching for Windows 10/11 devices."""
        win_params = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
        match = self.mgr.match_dhcp(win_params, vendor_class="MSFT 5.0")
        self.assertIsNotNone(match)
        self.assertIn("Windows", match.vendor)
        self.assertEqual(match.category, "Laptop / Workstation")

    def test_match_linux(self):
        """Tests matching for dhcpcd / Linux hosts."""
        linux_params = [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42]
        match = self.mgr.match_dhcp(linux_params)
        self.assertIsNotNone(match)
        self.assertIn("Linux", match.vendor)
        self.assertEqual(match.category, "Laptop / Workstation")

    def test_match_iot(self):
        """Tests matching for Espressif ESP8266/ESP32 IoT devices."""
        esp_params = [1, 3, 6, 15, 28, 42]
        match = self.mgr.match_dhcp(esp_params)
        self.assertIsNotNone(match)
        self.assertIn("Espressif", match.vendor)
        self.assertEqual(match.category, "Smart Home / IoT")

    def test_match_mdns_services(self):
        """Tests mDNS DNS-SD service matching."""
        # Chromecast / Google Cast
        cast_match = self.mgr.match_mdns(["_googlecast._tcp.local"])
        self.assertIsNotNone(cast_match)
        self.assertIn("Google Chromecast", cast_match.vendor)
        self.assertEqual(cast_match.category, "Smart TV / Streaming")

        # Apple AirPlay
        airplay_match = self.mgr.match_mdns(["_airplay._tcp.local"])
        self.assertIsNotNone(airplay_match)
        self.assertIn("AirPlay", airplay_match.vendor)

        # Network Printer
        printer_match = self.mgr.match_mdns(["_ipp._tcp.local"])
        self.assertIsNotNone(printer_match)
        self.assertEqual(printer_match.category, "Network Printer")


class TestDhcpFingerprintStore(unittest.TestCase):
    def setUp(self):
        self.store = DhcpFingerprintStore(max_entries=5)
        self.store.clear()

    def test_record_and_retrieve(self):
        mac = "02:00:00:00:00:28"
        params = [1, 121, 3, 6, 15, 114, 119, 252]
        self.store.record(mac, params, vendor_class="dhcp-client", hostname="My-iPhone")

        retrieved = self.store.get(mac)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["mac"], mac.upper())
        self.assertEqual(retrieved["param_list"], params)
        self.assertEqual(retrieved["hostname"], "My-iPhone")

    def test_eviction(self):
        for i in range(6):
            self.store.record(f"00:11:22:33:44:0{i}", [1, 3, 6], now=100.0 + i)

        # Oldest entry 00:11:22:33:44:00 should be evicted
        self.assertIsNone(self.store.get("00:11:22:33:44:00"))
        # Newest entry should remain
        self.assertIsNotNone(self.store.get("00:11:22:33:44:05"))


class TestIdentifierAndConsoleRegressions(unittest.TestCase):
    """Regression tests for signature matching, fingerprint stores, vendor resolver, and console output."""

    def test_dhcp_vendor_class_required_and_longest_prefix_5(self):
        sig = DhcpSignature(
            vendor="Android",
            category="Smartphone",
            os_family="Android",
            param_list=(1, 3, 6, 15, 26),
            vendor_class_pattern=r"^android-dhcp-",
        )
        # Missing vendor class must not match when vendor_class_pattern is required
        self.assertFalse(sig.matches((1, 3, 6, 15, 26), vendor_class=None))
        # Overlap < 5 must not prefix-match
        generic = DhcpSignature(
            vendor="Generic", category="Other", os_family="Unknown", param_list=(1, 3, 6, 15)
        )
        self.assertFalse(generic.matches((1, 3, 6, 15, 28, 42)))

        # SignatureManager picks longest prefix (>=5) match
        mgr = SignatureManager()
        mgr.dhcp_signatures = [
            DhcpSignature(vendor="Short", category="Other", os_family="OS1", param_list=(1, 3, 6, 15, 28)),
            DhcpSignature(vendor="Long", category="IoT", os_family="OS2", param_list=(1, 3, 6, 15, 28, 42)),
        ]
        # Short matches 5-element prefix, Long matches 6-element prefix -> Long wins
        match = mgr.match_dhcp([1, 3, 6, 15, 28, 42, 88])
        self.assertIsNotNone(match)
        self.assertEqual(match.vendor, "Long")

    def test_tcp_syn_wildcard_ttl_and_store_clears_stale_match(self):
        from alien_hunter.identifiers.signatures import TcpSynSignature, TcpSynFingerprintStore

        mgr = SignatureManager()
        wildcard_match = mgr.match_tcp_syn(ttl=255, options=[])
        self.assertIsNotNone(wildcard_match)
        self.assertIn("Router", wildcard_match.vendor + wildcard_match.category)

        store = TcpSynFingerprintStore(max_entries=10)
        sig_win = TcpSynSignature("Windows", "PC", "Windows", 128, (2, 1, 3, 1, 1, 4))
        store.record("198.51.100.30", ttl=128, options=[2, 1, 3, 1, 1, 4], match=sig_win)
        # Stack changes to Linux TTL 64 with match=None -> stale Windows match must be cleared
        store.record("198.51.100.30", ttl=64, options=[2, 4, 8, 1, 3], match=None)
        self.assertIsNone(store.get("198.51.100.30")["match"])

    def test_vendor_resolver_skips_http_for_randomized_mac(self):
        from unittest.mock import patch
        from alien_hunter.identifiers.vendor import MacVendorResolver

        resolver = MacVendorResolver()
        with patch("urllib.request.urlopen") as mock_urlopen:
            vendor, is_rand = resolver.resolve("02-00-00-11-22-33")
            self.assertTrue(is_rand)
            self.assertEqual(vendor, "Randomized Private MAC")
            mock_urlopen.assert_not_called()

    def test_console_reporter_strips_ansi_escape_sequences(self):
        import io
        from contextlib import redirect_stdout
        from alien_hunter.models import Device
        from alien_hunter.reporting.console import ConsoleReporter

        malicious = Device(
            ip="198.51.100.55",
            mac="02:00:00:00:00:55",
            hostname="\x1b[31mFAKE\x1b]0;TITLE\x07\r\nHOST",
            vendor="\x1b[2JEvil",
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            ConsoleReporter.render_table([malicious])
        out = buf.getvalue()
        self.assertNotIn("\x1b]0;TITLE", out)
        self.assertNotIn("\x1b[2J", out)


if __name__ == "__main__":
    unittest.main()
