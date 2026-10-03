"""
Unit tests for Alien Hunter AI risk assessment and engine logic.
"""

import json
import os
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
            ip="192.168.1.178",
            mac="2C:BE:EE:98:09:A6",
            hostname="Cobalt",
            vendor="Nothing Technology Limited (GB)",
        )
        self.assertEqual(self.provider.infer_device_hint(phone), "Smartphone")

        # Windows Laptop
        laptop = Device(
            ip="192.168.1.203",
            mac="70:08:94:55:3F:69",
            hostname="LAPTOP 4F3BFHRJ",
            vendor="Liteon Technology Corporation (TW)",
        )
        self.assertEqual(self.provider.infer_device_hint(laptop), "Laptop / Workstation")

        # Stealth Randomized MAC Mobile Device (e.g. iPhone Private Wi-Fi Address)
        iphone = Device(
            ip="192.168.1.114",
            mac="2A:A9:34:C4:17:28",
            vendor="Randomized Private MAC",
            is_randomized=True,
        )
        self.assertEqual(self.provider.infer_device_hint(iphone), "Smartphone")

        # Randomized MAC with PC Hostname
        laptop_rand = Device(
            ip="192.168.1.115",
            mac="2A:A9:34:C4:17:29",
            hostname="LAPTOP-CORP",
            vendor="Randomized Private MAC",
            is_randomized=True,
        )
        self.assertEqual(self.provider.infer_device_hint(laptop_rand), "Laptop / Workstation")

        # Randomized MAC with Workstation SMB Port
        pc_smb = Device(
            ip="192.168.1.116",
            mac="2A:A9:34:C4:17:30",
            vendor="Randomized Private MAC",
            is_randomized=True,
            open_ports=["445/tcp microsoft-ds"],
        )
        self.assertEqual(self.provider.infer_device_hint(pc_smb), "Laptop / Workstation")

        # IP Surveillance Camera with RTSP Port
        cam = Device(
            ip="192.168.1.150",
            mac="B0:C5:54:12:34:56",
            open_ports=["554/tcp rtsp"],
        )
        self.assertEqual(self.provider.infer_device_hint(cam), "Smart IP Camera")

    def test_parse_response_with_analysis(self):
        iphone = Device(
            ip="192.168.1.114",
            mac="2A:A9:34:C4:17:28",
            is_randomized=True,
        )
        raw_json = (
            '{"analysis": "Ephemeral MAC with stealth port profile matches mobile OS privacy.", '
            '"device_type": "Smartphone", "risk_level": "LOW", '
            '"summary": "Mobile device with randomized MAC.", '
            '"whitelist_recommendation": "INVESTIGATE", "action_advice": "Check ownership."}'
        )
        assessment = self.provider._parse_response_json(raw_json, device=iphone)
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.device_type, "Smartphone")
        self.assertEqual(assessment.analysis, "Ephemeral MAC with stealth port profile matches mobile OS privacy.")

    def test_parse_response_with_vulnerabilities(self):
        srv = Device(
            ip="192.168.1.50",
            mac="00:11:22:33:44:55",
            notes=["Banner (21/FTP): ProFTPD 1.3.5 Server"],
        )
        raw_json = (
            '{"analysis": "Legacy FTP daemon exposed with known remote command execution.", '
            '"device_type": "Network Server", "risk_level": "CRITICAL", '
            '"summary": "Exposed vulnerable ProFTPD daemon.", '
            '"whitelist_recommendation": "BLOCK", "action_advice": "Disable FTP or upgrade immediately.", '
            '"vulnerabilities": ["CVE-2015-3306: ProFTPD mod_copy Remote Command Execution"]}'
        )
        assessment = self.provider._parse_response_json(raw_json, device=srv)
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.risk_level, "CRITICAL")
        self.assertEqual(len(assessment.vulnerabilities), 1)
        self.assertIn("CVE-2015-3306", assessment.vulnerabilities[0])

    def test_device_risk_assessment_to_dict_includes_vulnerabilities(self):
        assessment = DeviceRiskAssessment(
            risk_level="HIGH",
            device_type="NAS / File Server",
            summary="Vulnerable service detected",
            whitelist_recommendation="INVESTIGATE",
            action_advice="Patch firmware",
            vulnerabilities=["CVE-2023-48795 Terrapin Attack"],
        )
        d = assessment.to_dict()
        self.assertIn("vulnerabilities", d)
        self.assertEqual(d["vulnerabilities"], ["CVE-2023-48795 Terrapin Attack"])

    def test_prompts_structure(self):
        sys_prompt = self.provider.build_system_prompt()
        self.assertIn("Reference Audit Exemplars", sys_prompt)
        self.assertIn("Hardware Taxonomy", sys_prompt)
        self.assertIn('"analysis":', sys_prompt)
        self.assertIn('"vulnerabilities":', sys_prompt)
        self.assertIn("Vulnerability Evaluation", sys_prompt)

        dev = Device(
            ip="192.168.1.114",
            mac="2A:A9:34:C4:17:28",
            is_randomized=True,
        )
        user_prompt = self.provider.build_user_prompt(dev)
        self.assertIn("Addressing Mode: Locally Administered / Randomized", user_prompt)
        self.assertIn("Stealth / Closed Profile", user_prompt)
        self.assertIn("Deterministic Hint: Smartphone", user_prompt)

    def test_unknown_device_type_fallback(self):
        laptop = Device(
            ip="192.168.1.203",
            mac="70:08:94:55:3F:69",
            hostname="LAPTOP 4F3BFHRJ",
            vendor="Liteon Technology Corporation (TW)",
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

    def test_openrouter_provider_initialization(self):
        from alien_hunter.ai.providers.openai_compatible import OpenAICompatibleProvider
        cfg = {
            "enabled": True,
            "provider": "openrouter",
            "api_key": "sk-or-v1-test",
        }
        provider = OpenAICompatibleProvider(cfg)
        self.assertEqual(provider.name, "openrouter")
        self.assertEqual(provider.endpoint, "https://openrouter.ai/api/v1/chat/completions")
        self.assertEqual(provider.model, "google/gemini-2.0-flash-001")
        self.assertEqual(provider.api_key, "sk-or-v1-test")
        self.assertEqual(provider.provider_label, "openrouter:google/gemini-2.0-flash-001")

    @patch("urllib.request.urlopen")
    def test_openrouter_headers(self, mock_urlopen):
        from alien_hunter.ai.providers.openai_compatible import OpenAICompatibleProvider
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = (
            b'{"choices": [{"message": {"content": "{\\"device_type\\": \\"Smart Bulb\\", '
            b'\\"risk_level\\": \\"LOW\\", \\"summary\\": \\"IoT Bulb\\"}"}}]}'
        )
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        cfg = {
            "enabled": True,
            "provider": "openrouter",
            "api_key": "sk-or-v1-test-key",
            "model": "anthropic/claude-3.5-haiku",
        }
        provider = OpenAICompatibleProvider(cfg)
        dev = Device(ip="192.168.1.55", mac="00:11:22:33:44:55")
        provider.analyze(dev)

        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header("Authorization"), "Bearer sk-or-v1-test-key")
        self.assertEqual(req.get_header("Http-referer"), "https://github.com/jekyll86/alien-hunter")
        self.assertEqual(req.get_header("X-title"), "Alien Hunter")

    @patch("urllib.request.urlopen")
    def test_max_tokens_configuration(self, mock_urlopen):
        from alien_hunter.ai.providers.openai_compatible import OpenAICompatibleProvider
        import json

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = (
            b'{"choices": [{"message": {"content": "{\\"device_type\\": \\"Smart Bulb\\", '
            b'\\"risk_level\\": \\"LOW\\", \\"summary\\": \\"IoT Bulb\\"}"}}]}'
        )
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        # Default max_tokens
        p1 = OpenAICompatibleProvider({"provider": "openrouter", "api_key": "test"})
        self.assertEqual(p1.max_tokens, 1500)
        p1.analyze(Device(ip="10.0.0.1", mac="00:11:22:33:44:55"))
        sent_body = json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))
        self.assertEqual(sent_body.get("max_tokens"), 1500)

        # Custom max_tokens
        p2 = OpenAICompatibleProvider({"provider": "openrouter", "api_key": "test", "max_tokens": 2048})
        self.assertEqual(p2.max_tokens, 2048)
        p2.analyze(Device(ip="10.0.0.2", mac="00:11:22:33:44:56"))
        sent_body2 = json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))
        self.assertEqual(sent_body2.get("max_tokens"), 2048)

    def test_ai_engine_provider_profiles(self):
        cfg = {
            "ai_analysis": {
                "enabled": True,
                "provider": "ollama",
                "providers": {
                    "ollama": {
                        "endpoint": "http://localhost:11434",
                        "model": "qwen2.5:0.5b",
                    },
                    "openrouter": {
                        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
                        "model": "openrouter/free",
                        "api_key": "sk-or-v1-profile-key",
                    },
                },
            }
        }
        engine_ollama = AIEngine.from_config(cfg)
        self.assertIsNotNone(engine_ollama)
        self.assertEqual(engine_ollama.provider.name, "ollama")
        self.assertEqual(engine_ollama.provider.model, "qwen2.5:0.5b")
        self.assertEqual(engine_ollama.provider.endpoint, "http://localhost:11434")

        # Switch active provider to openrouter
        cfg["ai_analysis"]["provider"] = "openrouter"
        engine_or = AIEngine.from_config(cfg)
        self.assertIsNotNone(engine_or)
        self.assertEqual(engine_or.provider.name, "openrouter")
        self.assertEqual(engine_or.provider.model, "openrouter/free")
        self.assertEqual(engine_or.provider.api_key, "sk-or-v1-profile-key")
        self.assertEqual(engine_or.provider.endpoint, "https://openrouter.ai/api/v1/chat/completions")

    def test_cli_set_ai_provider(self):
        import tempfile
        from alien_hunter.cli import build_parser, main
        from alien_hunter.config import ConfigManager

        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp:
            tmp.write(json.dumps({"ai_analysis": {"enabled": True, "provider": "ollama"}}))
            tmp_path = tmp.name

        try:
            with patch("sys.argv", ["alien-hunter", "--config-file", tmp_path, "--set-ai-provider", "openrouter"]):
                with patch("subprocess.run") as mock_subproc:
                    mock_subproc.return_value = MagicMock(returncode=1)
                    with self.assertRaises(SystemExit) as cm:
                        main()
                    self.assertEqual(cm.exception.code, 0)

            cfg_mgr = ConfigManager()
            saved = cfg_mgr.load_config(tmp_path)
            self.assertEqual(saved["ai_analysis"]["provider"], "openrouter")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()

