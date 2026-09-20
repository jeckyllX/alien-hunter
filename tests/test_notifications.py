"""
Tests for Alien Hunter notification templates, report formats, and hook dispatching.
"""

import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.notifications.template import AlertMessage
from alien_hunter.notifications.hooks.telegram import TelegramHook
from alien_hunter.models import Device, NetworkInfo, AuditResult
from alien_hunter.ai.models import NetworkPostureAssessment


class TestNotificationTemplates(unittest.TestCase):
    """Tests AlertMessage formatting for intrusion alerts and audit reports."""

    def test_audit_report_markdown_generation(self):
        net = NetworkInfo(
            interface="wlan0",
            local_ip="192.168.1.10",
            local_mac="AA:BB:CC:DD:EE:11",
            gateway_ip="192.168.1.1",
            subnet_base="192.168.1",
        )
        posture = NetworkPostureAssessment(
            posture="SECURE",
            summary="All active nodes are verified trusted hosts.",
            threats_found=[],
            hardening_advice=["Continue regular monitoring"],
        )
        dev = Device(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:01", friendly_name="Gateway Router")
        audit = AuditResult(
            timestamp=1000.0,
            network=net,
            devices=[dev],
            alien_devices=[],
            threats=[],
            ai_posture=posture,
        )

        alert = AlertMessage(alien_devices=[], threats=[], audit_result=audit)
        self.assertTrue(alert.is_report)
        md = alert.to_markdown()
        self.assertIn("Network Security Audit Report", md)
        self.assertIn("AI Network Posture:* `SECURE`", md)
        self.assertIn("All active nodes are verified trusted hosts.", md)
        self.assertIn("Gateway Router", md)

    @patch("alien_hunter.notifications.base.BaseNotificationHook._post_json")
    def test_telegram_hook_dispatches_report_successfully(self, mock_post):
        mock_post.return_value = True

        hook = TelegramHook({"bot_token": "123456:FAKE_TOKEN", "chat_id": "999999"})
        net = NetworkInfo(interface="eth0", local_ip="10.0.0.5", local_mac="00:11:22:33:44:55")
        audit = AuditResult(timestamp=1000.0, network=net, devices=[], alien_devices=[], threats=[])

        alert = AlertMessage(alien_devices=[], threats=[], audit_result=audit)
        success = hook.send(alert)

        self.assertTrue(success)
        mock_post.assert_called_once()
        call_args = mock_post.call_args[0]
        self.assertIn("https://api.telegram.org/bot123456:FAKE_TOKEN/sendMessage", call_args[0])
        self.assertIn("chat_id", call_args[1])


if __name__ == "__main__":
    unittest.main()
