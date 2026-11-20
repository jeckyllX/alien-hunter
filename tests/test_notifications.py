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

    def test_threat_only_alert_with_audit_is_not_clean_report_and_slack_escapes(self):
        from alien_hunter.notifications.engine import NotificationEngine

        net = NetworkInfo(interface="eth0", local_ip="198.51.100.1", local_mac="02:00:00:00:00:01")
        audit = AuditResult(
            timestamp=1000.0, network=net, devices=[], alien_devices=[], threats=["<Evil> & Spoof"]
        )
        alert = AlertMessage(alien_devices=[], threats=["<Evil> & Spoof"], audit_result=audit)
        self.assertFalse(alert.is_report)
        md = alert.to_markdown()
        self.assertNotIn("0 unrecognized device(s)", md)
        self.assertIn("security threat(s) detected", md)

        blocks = alert.to_slack_blocks()
        blocks_text = str(blocks)
        self.assertIn("&lt;Evil&gt; &amp; Spoof", blocks_text)

        # NotificationEngine handles non-dict notifications and skips unconfigured hooks
        engine_bad = NotificationEngine.from_config({"notifications": None})
        self.assertEqual(engine_bad.hooks, [])
        engine_empty = NotificationEngine.from_config(
            {"notifications": {"telegram": {"enabled": True, "bot_token": "", "chat_id": ""}}}
        )
        self.assertEqual(engine_empty.hooks, [])

    def test_telegram_retries_plain_text_only_on_http_400(self):
        import urllib.error

        hook = TelegramHook({"bot_token": "123:TEST", "chat_id": "999"})
        net = NetworkInfo(interface="eth0", local_ip="198.51.100.1", local_mac="02:00:00:00:00:01")
        audit = AuditResult(timestamp=1000.0, network=net, devices=[], alien_devices=[], threats=["Threat"])
        alert = AlertMessage(alien_devices=[], threats=["Threat"], audit_result=audit)

        # HTTP 401 -> no plain-text retry
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                "https://api.telegram.org/bot123:TEST/sendMessage", 401, "Unauthorized", {}, None
            )
            self.assertFalse(hook.send(alert))
            self.assertEqual(mock_urlopen.call_count, 1)

        # HTTP 400 -> retry plain text once
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_ok = MagicMock()
            mock_ok.status = 200
            mock_ok.read.return_value = b'{"ok": true}'
            mock_ok.__enter__.return_value = mock_ok
            mock_urlopen.side_effect = [
                urllib.error.HTTPError(
                    "https://api.telegram.org/bot123:TEST/sendMessage", 400, "Bad Request", {}, None
                ),
                mock_ok,
            ]
            self.assertTrue(hook.send(alert))
            self.assertEqual(mock_urlopen.call_count, 2)


if __name__ == "__main__":
    unittest.main()
