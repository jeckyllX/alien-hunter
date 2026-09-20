"""
Unit tests for ConfigManager and device inventory synchronization.
"""

import os
import tempfile
import unittest
from types import SimpleNamespace

from alien_hunter.config import ConfigManager


class TestConfigManager(unittest.TestCase):
    """Tests configuration loading, resolution, and inventory synchronization."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.whitelist_file = os.path.join(self.temp_dir.name, "known_devices.json")
        self.config_mgr = ConfigManager()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sync_device_inventory_subnet_prioritization(self):
        # Seed whitelist with trusted gateway entry
        initial_whitelist = {
            "AA:BB:CC:DD:EE:FF": {
                "name": "Main Gateway Router",
                "device_type": "Gateway Router",
                "owner": "Network Admin",
                "primary_ip": "192.168.1.1",
            }
        }
        self.config_mgr.save_whitelist(initial_whitelist, self.whitelist_file)

        # Device observed with multiple IPs: alias 192.168.1.254 and LAN IP 192.168.1.1
        dev = SimpleNamespace(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.1",
            aliases=["192.168.1.254"],
            vendor="Example Gateway Corp",
            discovery_method="Layer-2 ARP Scan, mDNS (Multicast DNS)",
            mdns_services=["_http._tcp.local"],
            open_ports=["80/HTTP", "443/HTTPS"],
        )

        success = self.config_mgr.sync_device_inventory(
            devices=[dev],
            custom_path=self.whitelist_file,
            subnet_cidr="192.168.1.0/24",
        )
        self.assertTrue(success)

        updated = self.config_mgr.load_whitelist(self.whitelist_file)
        entry = updated.get("AA:BB:CC:DD:EE:FF")

        self.assertIsNotNone(entry)
        self.assertEqual(entry["name"], "Main Gateway Router")
        self.assertEqual(entry["owner"], "Network Admin")
        self.assertEqual(entry["primary_ip"], "192.168.1.1")
        self.assertIn("192.168.1.254", entry["aliases"])
        self.assertIn("Layer-2 ARP Scan", entry["discovery_methods"])
        self.assertIn("mDNS (Multicast DNS)", entry["discovery_methods"])
        self.assertIn("_http._tcp.local", entry["services"])
        self.assertEqual(entry["ports"], ["80/HTTP", "443/HTTPS"])
        self.assertIn("T", entry["last_seen"])  # ISO-8601 UTC timestamp format


if __name__ == "__main__":
    unittest.main()
