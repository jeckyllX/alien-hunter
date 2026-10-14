"""
Unit tests for Hardware Doppelgänger and Identity Spoofing Detector.
"""

import unittest
from alien_hunter.defenses.doppelganger import DoppelgangerDetector
from alien_hunter.threats import ThreatDetector
from alien_hunter.models import Device


class TestHardwareDoppelganger(unittest.TestCase):
    """Tests stack fingerprint validation, baseline inference, and spoofing detection."""

    def setUp(self):
        DoppelgangerDetector.reset_runtime_baselines()

    def tearDown(self):
        DoppelgangerDetector.reset_runtime_baselines()

    def test_estimate_initial_ttl(self):
        self.assertEqual(DoppelgangerDetector.estimate_initial_ttl(64), 64)
        self.assertEqual(DoppelgangerDetector.estimate_initial_ttl(56), 64)
        self.assertEqual(DoppelgangerDetector.estimate_initial_ttl(128), 128)
        self.assertEqual(DoppelgangerDetector.estimate_initial_ttl(115), 128)
        self.assertEqual(DoppelgangerDetector.estimate_initial_ttl(255), 255)
        self.assertEqual(DoppelgangerDetector.estimate_initial_ttl(240), 255)

    def test_infer_expected_ttl_configured_and_inferred(self):
        # 1. Explicit baseline_ttl
        self.assertEqual(DoppelgangerDetector.infer_expected_ttl({"baseline_ttl": 64}), 64)
        self.assertEqual(DoppelgangerDetector.infer_expected_ttl({"expected_ttl": 128}), 128)

        # 2. Configured baseline_os
        self.assertEqual(DoppelgangerDetector.infer_expected_ttl({"baseline_os": "Microsoft Windows 11"}), 128)
        self.assertEqual(DoppelgangerDetector.infer_expected_ttl({"baseline_os": "Ubuntu Linux 22.04"}), 64)
        self.assertEqual(DoppelgangerDetector.infer_expected_ttl({"device_type": "Apple iPhone"}), 64)

        # 3. Inferred from hardware vendor
        self.assertEqual(DoppelgangerDetector.infer_expected_ttl(vendor="Apple Inc."), 64)
        self.assertEqual(DoppelgangerDetector.infer_expected_ttl(vendor="Raspberry Pi Foundation"), 64)
        self.assertEqual(DoppelgangerDetector.infer_expected_ttl(vendor="Microsoft Corporation"), 128)
        self.assertEqual(DoppelgangerDetector.infer_expected_ttl(vendor="Unknown Vendor"), None)

    def test_check_device_legitimate_baseline_no_threats(self):
        wl_entry = {
            "name": "Living Room Apple TV",
            "baseline_ttl": 64,
            "baseline_os": "Apple tvOS",
        }
        threats = DoppelgangerDetector.check_device(
            ip="192.168.1.50",
            mac="00:11:22:33:44:55",
            display_name="Living Room Apple TV",
            observed_ttl=64,
            current_os="Apple iOS/macOS",
            dhcp_os="Apple iOS",
            whitelist_entry=wl_entry,
            vendor="Apple Inc.",
        )
        self.assertEqual(threats, [])

    def test_check_device_ttl_conflict_detection(self):
        # Trusted device is an Apple device (expected TTL=64), but attacker uses Windows (TTL=128)
        wl_entry = {
            "name": "CEO MacBook Pro",
            "baseline_ttl": 64,
            "baseline_os": "Apple macOS",
        }
        threats = DoppelgangerDetector.check_device(
            ip="192.168.1.75",
            mac="00:AA:BB:CC:DD:EE",
            display_name="CEO MacBook Pro",
            observed_ttl=128,  # Attacker machine emits Windows TTL=128
            current_os=None,
            whitelist_entry=wl_entry,
            vendor="Apple Inc.",
        )
        self.assertTrue(len(threats) >= 1)
        self.assertIn("Hardware Doppelgänger / MAC Spoofing", threats[0])
        self.assertIn("Observed stack TTL=128", threats[0])
        self.assertIn("Expected TTL=64", threats[0])

    def test_check_device_os_stack_masquerade_conflict(self):
        # Whitelisted as Windows PC, but observed fingerprint is Linux
        wl_entry = {
            "name": "Finance Workstation",
            "baseline_os": "Microsoft Windows",
            "baseline_ttl": 128,
        }
        threats = DoppelgangerDetector.check_device(
            ip="192.168.1.80",
            mac="11:22:33:44:55:66",
            display_name="Finance Workstation",
            observed_ttl=64,  # Linux stack
            current_os="Linux (generic)",
            dhcp_os="Linux",
            whitelist_entry=wl_entry,
            vendor="Dell Inc.",
        )
        self.assertTrue(len(threats) >= 1)
        self.assertTrue(any("Hardware Doppelgänger" in t for t in threats))
        self.assertTrue(any("Linux (generic)" in t for t in threats))

    def test_runtime_baseline_drift_detection(self):
        mac = "22:33:44:55:66:77"
        # First scan: observes host at TTL=64
        threats_first = DoppelgangerDetector.check_device(
            ip="192.168.1.90",
            mac=mac,
            display_name="Custom IoT Node",
            observed_ttl=64,
            vendor="Unknown Vendor",
        )
        self.assertEqual(threats_first, [])

        # Subsequent scan: same MAC suddenly transmits with TTL=128 (Windows attack machine took over MAC)
        threats_second = DoppelgangerDetector.check_device(
            ip="192.168.1.90",
            mac=mac,
            display_name="Custom IoT Node",
            observed_ttl=128,
            vendor="Unknown Vendor",
        )
        self.assertTrue(len(threats_second) >= 1)
        self.assertIn("Runtime Stack Drift", threats_second[0])
        self.assertIn("TTL=64 to TTL=128", threats_second[0])

    def test_threat_detector_check_hardware_doppelgangers(self):
        devices = [
            Device(
                ip="192.168.1.10",
                mac="00:11:22:33:44:55",
                hostname="my-iphone",
                vendor="Apple Inc.",
                observed_ttl=128,  # Cloned!
                tcp_syn_fingerprint="Microsoft Windows",
            ),
            Device(
                ip="192.168.1.11",
                mac="AA:BB:CC:DD:EE:01",
                hostname="desktop-pc",
                vendor="Microsoft Corporation",
                observed_ttl=128,
                tcp_syn_fingerprint="Microsoft Windows",
            ),
        ]
        whitelist = {
            "00:11:22:33:44:55": {"name": "Company iPhone", "baseline_ttl": 64, "baseline_os": "Apple iOS"},
            "AA:BB:CC:DD:EE:01": {"name": "Office PC", "baseline_ttl": 128, "baseline_os": "Microsoft Windows"},
        }

        threats = ThreatDetector.check_hardware_doppelgangers(devices, whitelist)
        self.assertTrue(len(threats) >= 1)
        self.assertIn("00:11:22:33:44:55", threats[0])
        self.assertNotIn("AA:BB:CC:DD:EE:01", "\n".join(threats))

    def test_threat_detector_check_device_doppelganger(self):
        wl = {"name": "Test Server", "baseline_ttl": 64, "baseline_os": "Linux"}
        threats = ThreatDetector.check_device_doppelganger(
            ip="192.168.1.55",
            mac="AA:BB:CC:DD:EE:FF",
            display_name="Test Server",
            observed_ttl=128,
            current_os="Microsoft Windows",
            whitelist_entry=wl,
            update_baseline=False,
        )
        self.assertTrue(len(threats) >= 1)
        self.assertIn("Hardware Doppelgänger", threats[0])


if __name__ == "__main__":
    unittest.main()
