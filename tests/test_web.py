"""
Unit tests for Alien Hunter Web Dashboard and REST API.
"""

import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from alien_hunter.config import ConfigManager
from alien_hunter.models import Device, NetworkInfo
from alien_hunter.web.server import LightweightWebServer
from alien_hunter.web.state import SentinelState
from alien_hunter.web.ui import DASHBOARD_HTML


class TestSentinelState(unittest.TestCase):
    """Tests in-memory thread-safe state store functionality."""

    def setUp(self):
        self.state = SentinelState(interval=300)

    def test_initial_state(self):
        summary = self.state.get_status_summary()
        self.assertTrue(summary["is_running"])
        self.assertGreaterEqual(summary["uptime_seconds"], 0)
        self.assertEqual(summary["interval_seconds"], 300)
        self.assertIsNone(summary["seconds_since_last_scan"])
        self.assertEqual(summary["counts"]["total_devices"], 0)
        self.assertEqual(summary["counts"]["trusted_devices"], 0)
        self.assertEqual(summary["counts"]["alien_devices"], 0)
        self.assertEqual(summary["counts"]["active_threats"], 0)

    def test_initialize_from_whitelist(self):
        sample_whitelist = {
            "11:22:33:44:55:66": {
                "name": "Trusted Router",
                "owner": "Network Admin",
                "device_type": "Gateway Router",
                "primary_ip": "192.168.1.1",
                "vendor": "Netgear",
            }
        }
        self.state.initialize_from_whitelist(sample_whitelist)
        devices = self.state.get_devices_payload()
        self.assertEqual(len(devices["trusted"]), 1)
        self.assertEqual(devices["trusted"][0]["mac"], "11:22:33:44:55:66")
        self.assertEqual(devices["trusted"][0]["name"], "Trusted Router")
        self.assertEqual(len(devices["alien"]), 0)

    def test_update_audit(self):
        dev_trusted = Device(
            ip="192.168.1.1",
            mac="11:22:33:44:55:66",
            hostname="router.lan",
            trusted=True,
            is_alien=False,
        )
        dev_alien = Device(
            ip="192.168.1.99",
            mac="AA:BB:CC:DD:EE:FF",
            hostname="unrecognized.lan",
            trusted=False,
            is_alien=True,
        )
        net_info = NetworkInfo(
            interface="eth0",
            local_ip="192.168.1.50",
            local_mac="00:11:22:33:44:55",
            gateway_ip="192.168.1.1",
            gateway_mac="11:22:33:44:55:66",
            subnet_base="192.168.1",
        )
        defenses = {"syn_scan": True, "arp_poison": True}
        threats = ["Test threat warning"]

        self.state.update_audit(
            devices=[dev_trusted, dev_alien],
            threats=threats,
            network_info=net_info,
            active_defenses=defenses,
        )

        summary = self.state.get_status_summary()
        self.assertEqual(summary["counts"]["trusted_devices"], 1)
        self.assertEqual(summary["counts"]["alien_devices"], 1)
        self.assertEqual(summary["counts"]["total_devices"], 2)
        self.assertEqual(summary["counts"]["active_threats"], 1)
        self.assertEqual(summary["network"]["interface"], "eth0")
        self.assertEqual(summary["active_defenses"], defenses)
        self.assertIsNotNone(summary["seconds_since_last_scan"])

    def test_update_whitelist_entry(self):
        dev_alien = Device(
            ip="192.168.1.99",
            mac="AA:BB:CC:DD:EE:FF",
            hostname="unrecognized.lan",
            vendor="Espressif",
            trusted=False,
            is_alien=True,
        )
        self.state.update_audit(devices=[dev_alien], threats=[])
        self.assertEqual(len(self.state.alien_devices), 1)
        self.assertEqual(len(self.state.trusted_devices), 0)

        # Transition to trusted
        entry = {
            "name": "Living Room ESP32",
            "owner": "Smart Home",
            "device_type": "IoT Sensor",
            "primary_ip": "192.168.1.99",
            "vendor": "Espressif",
        }
        self.state.update_whitelist_entry("AA:BB:CC:DD:EE:FF", entry)

        self.assertEqual(len(self.state.alien_devices), 0)
        self.assertEqual(len(self.state.trusted_devices), 1)
        trusted_dev = self.state.trusted_devices[0]
        self.assertEqual(trusted_dev["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(trusted_dev["name"], "Living Room ESP32")
        self.assertTrue(trusted_dev["trusted"])
        self.assertFalse(trusted_dev["is_alien"])

    def test_format_uptime(self):
        self.assertEqual(SentinelState._format_uptime(45), "45s")
        self.assertEqual(SentinelState._format_uptime(125), "2m 5s")
        self.assertEqual(SentinelState._format_uptime(3665), "1h 1m 5s")
        self.assertEqual(SentinelState._format_uptime(90060), "1d 1h 1m")


class TestLightweightWebServer(unittest.TestCase):
    """Tests HTTP endpoints, JSON API, and whitelisting workflow."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.whitelist_file = os.path.join(self.temp_dir.name, "known_devices.json")
        self.config_mgr = ConfigManager()

        # Seed whitelist
        initial_whitelist = {
            "11:22:33:44:55:66": {
                "name": "Gateway Router",
                "owner": "Admin",
                "device_type": "Gateway",
                "primary_ip": "192.168.1.1",
            }
        }
        self.config_mgr.save_whitelist(initial_whitelist, self.whitelist_file)

        self.state = SentinelState(interval=300)
        self.state.initialize_from_whitelist(initial_whitelist)

        # Seed an alien device in memory
        alien_dev = Device(
            ip="192.168.1.120",
            mac="AA:BB:CC:11:22:33",
            hostname="suspicious-host",
            vendor="Raspberry Pi Foundation",
            trusted=False,
            is_alien=True,
            open_ports=["22/SSH", "80/HTTP"],
        )
        self.state.update_audit(devices=[alien_dev], threats=["Sample alert"])

        # Start server on dynamic loopback port
        self.web_server = LightweightWebServer(
            state=self.state,
            config_mgr=self.config_mgr,
            whitelist_path=self.whitelist_file,
            host="127.0.0.1",
            port=0,
        )
        started = self.web_server.start()
        self.assertTrue(started)
        self.assertGreater(self.web_server.port, 0)
        self.base_url = f"http://127.0.0.1:{self.web_server.port}"

    def tearDown(self):
        self.web_server.stop()
        self.temp_dir.cleanup()

    def test_get_root_and_index(self):
        # GET /
        req = Request(f"{self.base_url}/")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("text/html", res.headers.get("Content-Type", ""))
            body = res.read().decode("utf-8")
            self.assertIn("Alien Hunter", body)
            self.assertIn("alienPanel", body)

        # GET /index.html
        req = Request(f"{self.base_url}/index.html")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)

    def test_get_api_status(self):
        req = Request(f"{self.base_url}/api/status")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("application/json", res.headers.get("Content-Type", ""))
            data = json.loads(res.read().decode("utf-8"))
            self.assertTrue(data["is_running"])
            self.assertEqual(data["counts"]["trusted_devices"], 0)
            self.assertEqual(data["counts"]["alien_devices"], 1)
            self.assertEqual(data["counts"]["active_threats"], 1)

    def test_get_api_devices(self):
        req = Request(f"{self.base_url}/api/devices")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertIn("trusted", data)
            self.assertIn("alien", data)
            self.assertEqual(len(data["alien"]), 1)
            self.assertEqual(data["alien"][0]["mac"], "AA:BB:CC:11:22:33")

    def test_post_whitelist_success(self):
        payload = {
            "mac": "AA:BB:CC:11:22:33",
            "name": "Development Pi",
            "owner": "Engineer",
            "device_type": "Single Board Computer",
            "primary_ip": "192.168.1.120",
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        req = Request(
            f"{self.base_url}/api/whitelist",
            data=body_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertTrue(data["success"])
            self.assertIn("whitelisted successfully", data["message"])

        # Check in-memory state transitioned
        devices = self.state.get_devices_payload()
        self.assertEqual(len(devices["alien"]), 0)
        trusted_macs = [d["mac"] for d in devices["trusted"]]
        self.assertIn("AA:BB:CC:11:22:33", trusted_macs)

        # Check persisted to disk
        persisted = self.config_mgr.load_whitelist(self.whitelist_file)
        self.assertIn("AA:BB:CC:11:22:33", persisted)
        self.assertEqual(persisted["AA:BB:CC:11:22:33"]["name"], "Development Pi")
        self.assertEqual(persisted["AA:BB:CC:11:22:33"]["owner"], "Engineer")

    def test_post_whitelist_invalid_mac(self):
        payload = {
            "mac": "INVALID_MAC_ADDR",
            "name": "Bad Device",
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        req = Request(
            f"{self.base_url}/api/whitelist",
            data=body_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 400)
        err_data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertFalse(err_data["success"])
        self.assertIn("Invalid MAC", err_data["message"])

    def test_post_whitelist_invalid_json(self):
        req = Request(
            f"{self.base_url}/api/whitelist",
            data=b"not valid json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 400)

    def test_404_not_found(self):
        req = Request(f"{self.base_url}/api/non_existent_endpoint")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
