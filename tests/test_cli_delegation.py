"""
Unit tests for Alien Hunter CLI client-daemon delegation.
"""

import json
import unittest
from unittest.mock import patch, MagicMock

from alien_hunter.cli import (
    build_parser,
    check_daemon_status,
    trigger_daemon_scan,
    device_from_dict,
)
from alien_hunter.models import Device


class TestCliDelegation(unittest.TestCase):
    """Tests CLI delegation handshake and device conversion."""

    def test_build_parser_has_no_delegate_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--no-delegate"])
        self.assertTrue(args.no_delegate)

    @patch("urllib.request.urlopen")
    def test_check_daemon_status_running(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "is_running": True,
            "uptime_seconds": 120,
            "is_scanning": False,
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        status = check_daemon_status("127.0.0.1", 8080)
        self.assertIsNotNone(status)
        self.assertTrue(status["is_running"])
        self.assertFalse(status["is_scanning"])

    @patch("urllib.request.urlopen")
    def test_check_daemon_status_offline(self, mock_urlopen):
        mock_urlopen.side_effect = ConnectionRefusedError("Connection refused")
        status = check_daemon_status("127.0.0.1", 8080)
        self.assertIsNone(status)

    @patch("urllib.request.urlopen")
    def test_trigger_daemon_scan_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "success": True,
            "message": "Manual network audit triggered successfully",
            "deep": True,
            "ai": True,
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        success = trigger_daemon_scan("127.0.0.1", 8080, deep=True, ai=True)
        self.assertTrue(success)

    def test_device_from_dict_trusted(self):
        raw = {
            "mac": "11:22:33:44:55:66",
            "ip": "192.168.1.1",
            "name": "Router",
            "friendly_name": "Gateway Router",
            "hostname": "vodafone.station",
            "vendor": "Vodafone",
            "trusted": True,
            "is_alien": False,
            "ports": [80, 443],
            "threats": [],
            "notes": ["Gateway device"],
        }
        dev = device_from_dict(raw)
        self.assertIsInstance(dev, Device)
        self.assertEqual(dev.mac, "11:22:33:44:55:66")
        self.assertEqual(dev.ip, "192.168.1.1")
        self.assertEqual(dev.display_name, "Gateway Router")
        self.assertTrue(dev.trusted)
        self.assertFalse(dev.is_alien)
        self.assertEqual(dev.open_ports, ["80/TCP", "443/TCP"])

    def test_device_from_dict_with_ai_assessment(self):
        raw = {
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.168.1.200",
            "name": "Unknown Host",
            "hostname": "Unknown",
            "vendor": "Espressif Inc.",
            "trusted": False,
            "is_alien": True,
            "open_ports": ["80/HTTP", "23/Telnet"],
            "threats": ["Telnet open"],
            "ai_assessment": {
                "device_type": "Smart Plug / IoT",
                "risk_level": "CRITICAL",
                "summary": "Exposed legacy Telnet service on IoT endpoint",
                "whitelist_recommendation": "BLOCK",
                "action_advice": "Isolate on IoT VLAN immediately",
                "vulnerabilities": ["Unencrypted Telnet (port 23)"],
            },
        }
        dev = device_from_dict(raw)
        self.assertTrue(dev.is_alien)
        self.assertIsNotNone(dev.ai_assessment)
        self.assertEqual(dev.ai_assessment.risk_level, "CRITICAL")
        self.assertEqual(dev.ai_assessment.device_type, "Smart Plug / IoT")
        self.assertEqual(dev.ai_assessment.whitelist_recommendation, "BLOCK")


if __name__ == "__main__":
    unittest.main()
