"""
Unit tests for Alien Hunter AI risk assessment and engine logic.
"""

import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.ai.models import (
    DeviceRiskAssessment,
    NetworkPostureAssessment,
    NetworkPosture,
    RiskLevel,
    WhitelistRecommendation,
)
from alien_hunter.ai.engine import AIEngine
from alien_hunter.ai.providers.ollama import OllamaProvider
from alien_hunter.models import Device, NetworkInfo, AuditResult


class TestAIEngine(unittest.TestCase):
    """Tests AI Engine caching, batching, and provider invocation."""

    def setUp(self):
        self.config = {
            "enabled": True,
            "provider": "ollama",
            "model": "qwen2.5:0.5b",
            "cache_results": True,
            "analyze_on": "all_devices",
        }
        self.provider = OllamaProvider(self.config)
        self.ai_engine = AIEngine(provider=self.provider, config=self.config)

    def test_provider_initialization(self):
        self.assertEqual(self.provider.model, "qwen2.5:0.5b")
        self.assertTrue(self.ai_engine.cache_enabled)
        self.assertEqual(self.ai_engine.analyze_on, "all_devices")

    def test_cache_key_generation(self):
        dev = Device(
            ip="192.168.1.50",
            mac="AA:BB:CC:DD:EE:FF",
            open_ports=["80/HTTP", "22/SSH"],
        )
        key = self.ai_engine._cache_key(dev)
        self.assertEqual(key, "AA:BB:CC:DD:EE:FF::22/SSH,80/HTTP")

    def test_analyze_devices_caching(self):
        mock_assessment = DeviceRiskAssessment(
            risk_level="LOW",
            device_type="Workstation",
            summary="Benign developer machine",
            whitelist_recommendation="ALLOW",
            action_advice="Monitor occasionally",
            provider="ollama:qwen2.5:0.5b",
        )

        with patch.object(self.provider, "analyze", return_value=mock_assessment) as mock_assess:
            dev1 = Device(ip="192.168.1.10", mac="00:11:22:33:44:55")
            dev2 = Device(ip="192.168.1.11", mac="00:11:22:33:44:55")  # Same MAC and empty ports -> cache hit!

            self.ai_engine.analyze_devices([dev1, dev2])

            self.assertIsNotNone(dev1.ai_assessment)
            self.assertIsNotNone(dev2.ai_assessment)
            self.assertEqual(dev1.ai_assessment.risk_level, "LOW")
            # Provider.analyze should only have been called ONCE due to cache!
            self.assertEqual(mock_assess.call_count, 1)

    @patch("urllib.request.urlopen")
    def test_ollama_provider_payload(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = (
            b'{"response": "{\\"risk_level\\": \\"MEDIUM\\", \\"confidence\\": \\"HIGH\\", '
            b'\\"device_type\\": \\"Smart Bulb\\", \\"summary\\": \\"IoT light\\", '
            b'\\"whitelist_recommendation\\": \\"INVESTIGATE\\", '
            b'\\"action_advice\\": \\"Isolate on IoT VLAN\\"}"}'
        )
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        dev = Device(ip="192.168.1.80", mac="11:22:33:44:55:66")
        assessment = self.provider.analyze(dev)

        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.risk_level, "MEDIUM")
        self.assertEqual(assessment.device_type, "Smart Bulb")
        self.assertEqual(assessment.whitelist_recommendation, "INVESTIGATE")

    def test_infer_device_hint(self):
        # Nothing Phone
        phone = Device(
            ip="192.0.2.40",
            mac="02:00:00:00:00:40",
            hostname="Mobile-01",
            vendor="Nothing Technology Limited",
        )
        self.assertEqual(self.provider.infer_device_hint(phone), "Smartphone")

        # Windows Laptop
        laptop = Device(
            ip="192.0.2.41",
            mac="02:00:00:00:00:41",
            hostname="LAPTOP-TEST01",
            vendor="Generic PC Vendor",
        )
        self.assertEqual(self.provider.infer_device_hint(laptop), "Laptop / Workstation")

    def test_unknown_device_type_fallback(self):
        laptop = Device(
            ip="192.0.2.41",
            mac="02:00:00:00:00:41",
            hostname="LAPTOP-TEST01",
            vendor="Generic PC Vendor",
        )
        raw_json = (
            '{"device_type": "Unknown Device", "risk_level": "LOW", '
            '"summary": "LAN host connected without identified service.", '
            '"whitelist_recommendation": "INVESTIGATE", "action_advice": "Check device ownership."}'
        )
        assessment = self.provider._parse_response_json(raw_json, device=laptop)
        self.assertIsNotNone(assessment)
        # Should gracefully fall back to deterministic hint
        self.assertEqual(assessment.device_type, "Laptop / Workstation")

    def test_deterministic_compute_posture(self):
        # 1. Threat flags present -> CRITICAL
        self.assertEqual(self.provider.compute_posture(["ARP Spoofing detected"], alien_count=0), NetworkPosture.CRITICAL)
        self.assertEqual(self.provider.compute_posture(["Telnet exposed"], alien_count=2), NetworkPosture.CRITICAL)

        # 2. Zero threats, alien devices present -> WARNING
        self.assertEqual(self.provider.compute_posture([], alien_count=2), NetworkPosture.WARNING)

        # 3. Zero threats, zero alien devices -> SECURE
        self.assertEqual(self.provider.compute_posture([], alien_count=0), NetworkPosture.SECURE)

    def test_parse_posture_json(self):
        raw_json = (
            '{"summary": "Network inventory shows 2 unwhitelisted endpoints. No active exploits observed.", '
            '"threats_found": [], "hardening_advice": ["Review new devices"]}'
        )
        posture = self.provider._parse_posture_json(raw_json, posture=NetworkPosture.WARNING)
        self.assertIsNotNone(posture)
        self.assertEqual(posture.posture, NetworkPosture.WARNING)
        self.assertIsInstance(posture.posture, NetworkPosture)
        self.assertIn("unwhitelisted", posture.summary)
        self.assertEqual(posture.hardening_advice, ["Review new devices"])


if __name__ == "__main__":
    unittest.main()
