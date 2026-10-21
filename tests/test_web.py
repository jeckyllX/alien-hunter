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

    def test_update_audit_preserves_offline_trusted_devices_and_timestamps(self):
        sample_whitelist = {
            "08:ED:B9:1A:37:BD": {
                "name": "Acer Laptop",
                "owner": "User",
                "primary_ip": "192.168.1.112",
                "last_seen": "2026-09-20T10:00:00Z",
            }
        }
        self.state.initialize_from_whitelist(sample_whitelist)

        # Audit runs but Acer Laptop did NOT respond (it is offline)
        dev_active = Device(
            ip="192.168.1.1",
            mac="18:EF:C0:10:FF:B0",
            hostname="gateway.lan",
            trusted=True,
            status="Online / Active",
        )
        self.state.update_audit(devices=[dev_active], threats=[])

        devices = self.state.get_devices_payload()
        trusted_map = {d["mac"]: d for d in devices["trusted"]}

        self.assertIn("08:ED:B9:1A:37:BD", trusted_map)
        acer = trusted_map["08:ED:B9:1A:37:BD"]
        self.assertEqual(acer["status"], "Offline / Asleep")
        self.assertEqual(acer["last_seen"], "2026-09-20T10:00:00Z")

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

    def test_events_transitions_and_aliens(self):
        # Initial scan: dev_trusted online, dev_sleeping offline
        dev_trusted = Device(
            ip="192.168.1.1",
            mac="11:22:33:44:55:66",
            hostname="router.lan",
            trusted=True,
            is_alien=False,
        )
        dev_sleeping = Device(
            ip="192.168.1.50",
            mac="22:33:44:55:66:77",
            hostname="laptop.lan",
            trusted=True,
            is_alien=False,
            status="Offline / Asleep",
        )
        self.state.update_audit(devices=[dev_trusted, dev_sleeping], threats=[])
        # Initial scan should seed state without transition spam
        initial_events = self.state.get_events_payload()["events"]
        self.assertEqual(len(initial_events), 0)

        # Subsequent scan: laptop comes online, router goes offline, new alien detected
        dev_laptop_online = Device(
            ip="192.168.1.50",
            mac="22:33:44:55:66:77",
            hostname="laptop.lan",
            trusted=True,
            is_alien=False,
            status="Online / Active",
        )
        dev_alien = Device(
            ip="192.168.1.99",
            mac="AA:BB:CC:DD:EE:FF",
            hostname="intruder.lan",
            trusted=False,
            is_alien=True,
            open_ports=["22/SSH", "80/HTTP"],
        )
        # router is missing from scan, so it transitions to Offline / Asleep
        self.state.update_audit(
            devices=[dev_laptop_online, dev_alien],
            threats=[
                "Stealth TCP SYN scan detected from 192.168.1.99",
                "CRITICAL: Active ICMP Route Hijacking detected! Host at 192.168.1.55 sent ICMP Redirect",
            ],
        )

        events_payload = self.state.get_events_payload()
        self.assertGreaterEqual(events_payload["count"], 4)
        event_types = [e["event_type"] for e in events_payload["events"]]
        self.assertIn("DEVICE_ONLINE", event_types)
        self.assertIn("DEVICE_OFFLINE", event_types)
        self.assertIn("ALIEN_DETECTED", event_types)
        self.assertIn("SYN_SCAN_DETECTED", event_types)
        self.assertIn("ICMP_REDIRECT_DETECTED", event_types)

        # Whitelisting the alien device generates DEVICE_WHITELISTED
        self.state.update_whitelist_entry("AA:BB:CC:DD:EE:FF", {"name": "Approved Intruder", "owner": "Admin"})
        updated_payload = self.state.get_events_payload()
        updated_types = [e["event_type"] for e in updated_payload["events"]]
        self.assertIn("DEVICE_WHITELISTED", updated_types)

    def test_format_uptime(self):
        self.assertEqual(SentinelState._format_uptime(45), "45s")
        self.assertEqual(SentinelState._format_uptime(125), "2m 5s")
        self.assertEqual(SentinelState._format_uptime(3665), "1h 1m 5s")
        self.assertEqual(SentinelState._format_uptime(90060), "1d 1h 1m")

    def test_update_audit_deduplicates_same_mac_across_ipv4_and_ipv6(self):
        # A trusted device discovered on both IPv4 and IPv6 with the same hardware MAC
        dev_v4 = Device(
            ip="192.168.1.150",
            mac="02:00:00:00:00:01",
            hostname="device-host",
            friendly_name="Test Device",
            vendor="Generic Vendor Inc.",
            trusted=True,
            is_alien=False,
            open_ports=["443/HTTPS"],
            discovery_method="Layer-2 ARP Scan",
        )
        dev_v6 = Device(
            ip="fe80::1",
            mac="02:00:00:00:00:01",
            hostname="Unknown",
            friendly_name="Test Device",
            vendor="Generic Vendor Inc.",
            trusted=True,
            is_alien=False,
            open_ports=["80/HTTP"],
            discovery_method="IPv6 Neighbor Discovery",
        )
        net_info = NetworkInfo(
            interface="eth0",
            local_ip="192.168.1.50",
            local_mac="00:11:22:33:44:55",
            subnet_base="192.168.1",
            prefix_len=24,
        )

        self.state.update_audit(devices=[dev_v4, dev_v6], threats=[], network_info=net_info)
        devices_payload = self.state.get_devices_payload()

        # Must be exactly one trusted entry, not two
        self.assertEqual(len(devices_payload["trusted"]), 1)
        entry = devices_payload["trusted"][0]
        self.assertEqual(entry["mac"], "02:00:00:00:00:01")
        self.assertEqual(entry["ip"], "192.168.1.150")
        self.assertIn("fe80::1", entry["aliases"])
        self.assertIn("443/HTTPS", entry["ports"])
        self.assertIn("80/HTTP", entry["ports"])
        self.assertIn("Layer-2 ARP Scan", entry["discovery_method"])
        self.assertIn("IPv6 Neighbor Discovery", entry["discovery_method"])

    def test_update_audit_deduplicates_alien_devices_same_mac(self):
        alien_v4 = Device(
            ip="192.168.1.222",
            mac="DE:AD:BE:EF:CA:FE",
            hostname="intruder",
            vendor="Unknown Vendor",
            trusted=False,
            is_alien=True,
            discovery_method="Layer-2 ARP Scan",
        )
        alien_v6 = Device(
            ip="fe80::dead:beef:cafe:1",
            mac="DE:AD:BE:EF:CA:FE",
            hostname="Unknown",
            vendor="Unknown Vendor",
            trusted=False,
            is_alien=True,
            discovery_method="Passive Frame Sniffer",
        )

        self.state.update_audit(devices=[alien_v4, alien_v6], threats=[])
        devices_payload = self.state.get_devices_payload()

        self.assertEqual(len(devices_payload["alien"]), 1)
        entry = devices_payload["alien"][0]
        self.assertEqual(entry["mac"], "DE:AD:BE:EF:CA:FE")
        self.assertEqual(entry["ip"], "192.168.1.222")
        self.assertIn("fe80::dead:beef:cafe:1", entry["aliases"])


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
                "last_seen": "2026-09-24T12:00:00Z",
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

        # HEAD /
        req = Request(f"{self.base_url}/", method="HEAD")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("text/html", res.headers.get("Content-Type", ""))
            self.assertGreater(int(res.headers.get("Content-Length", 0)), 0)

    def test_get_api_status(self):
        req = Request(f"{self.base_url}/api/status")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("application/json", res.headers.get("Content-Type", ""))
            data = json.loads(res.read().decode("utf-8"))
            self.assertTrue(data["is_running"])
            self.assertEqual(data["counts"]["trusted_devices"], 1)
            self.assertEqual(data["counts"]["alien_devices"], 1)
            self.assertEqual(data["counts"]["active_threats"], 1)

    def test_get_api_devices(self):
        req = Request(f"{self.base_url}/api/devices")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertIn("trusted", data)
            self.assertIn("alien", data)
            self.assertEqual(len(data["trusted"]), 1)
            self.assertEqual(data["trusted"][0]["mac"], "11:22:33:44:55:66")
            self.assertTrue(bool(data["trusted"][0].get("last_seen", "")))
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

    def test_get_api_events(self):
        self.state.event_mgr.record(
            event_type="DEVICE_ONLINE",
            severity="INFO",
            title="Device Active",
            description="Testing API",
            ip="192.168.1.10",
        )
        req = Request(f"{self.base_url}/api/events")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            self.assertEqual(res.headers.get("Content-Type"), "application/json")
            data = json.loads(res.read().decode("utf-8"))
            self.assertIn("count", data)
            self.assertIn("events", data)
            self.assertGreaterEqual(data["count"], 1)
            self.assertEqual(data["events"][0]["title"], "Device Active")

        # Test limit query param
        req_limit = Request(f"{self.base_url}/api/events?limit=1")
        with urlopen(req_limit, timeout=3) as res:
            data = json.loads(res.read().decode("utf-8"))
            self.assertLessEqual(len(data["events"]), 1)

        # Test ip query param
        req_ip = Request(f"{self.base_url}/api/events?ip=192.168.1.10")
        with urlopen(req_ip, timeout=3) as res:
            data = json.loads(res.read().decode("utf-8"))
            self.assertEqual(len(data["events"]), 1)
            self.assertEqual(data["events"][0]["ip"], "192.168.1.10")

        # Test HEAD request
        head_req = Request(f"{self.base_url}/api/events", method="HEAD")
        with urlopen(head_req, timeout=3) as res:
            self.assertEqual(res.status, 200)

    def test_post_api_scan_trigger(self):
        triggered_args = {}

        def mock_scan_trigger(deep=True, ai=True, analyze_all=False):
            triggered_args["deep"] = deep
            triggered_args["ai"] = ai
            triggered_args["analyze_all"] = analyze_all
            self.state.set_scanning(True)

        setattr(self.web_server.server, "scan_trigger", mock_scan_trigger)

        # Trigger via query params
        req = Request(
            f"{self.base_url}/api/scan?deep=true&ai=false",
            data=b"",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertTrue(data["success"])
            self.assertTrue(data["deep"])
            self.assertFalse(data["ai"])

        self.assertEqual(triggered_args["deep"], True)
        self.assertEqual(triggered_args["ai"], False)
        self.assertTrue(self.state.is_scanning)

        # Trigger via JSON body
        req_json = Request(
            f"{self.base_url}/api/scan",
            data=json.dumps({"deep": False, "ai": True}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req_json, timeout=3) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertTrue(data["success"])
            self.assertFalse(data["deep"])
            self.assertTrue(data["ai"])

        self.assertEqual(triggered_args["deep"], False)
        self.assertEqual(triggered_args["ai"], True)

    def test_dashboard_html_has_deep_scan_button(self):
        req = Request(f"{self.base_url}/")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            html = res.read().decode("utf-8")
            self.assertIn('id="btnDeepScan"', html)
            self.assertIn('triggerManualScan', html)
            self.assertIn('pollScanProgress', html)

    def test_404_not_found(self):
        req = Request(f"{self.base_url}/api/non_existent_endpoint")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
