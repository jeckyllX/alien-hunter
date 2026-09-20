"""
Abstract Base Provider for AI Device Security Analyzers.
Provides standard prompt generation, defensive system framing,
safe HTTP execution, and robust JSON parsing across all providers.
"""

import json
import re
import urllib.request
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union

from .models import (
    DeviceRiskAssessment,
    NetworkPostureAssessment,
    NetworkPosture,
    RiskLevel,
    WhitelistRecommendation,
)
from ..models import Device


class BaseAIProvider(ABC):
    """Abstract interface for AI security analysis providers."""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.model = str(config.get("model", "")).strip()
        self.endpoint = str(config.get("endpoint", "")).strip()
        self.api_key = str(config.get("api_key", "")).strip()
        self.timeout = float(config.get("timeout_seconds", 120.0))

    @property
    def provider_label(self) -> str:
        return f"{self.name}:{self.model}" if self.model else self.name

    @staticmethod
    def infer_device_hint(device: Device) -> Optional[str]:
        """
        Infers an authoritative hardware classification hint using deterministic
        vendor OUIs, hostname conventions, mDNS services, and port fingerprints.
        Acts as ground-truth anchoring for smaller local LLMs.
        """
        text = f"{device.display_name} {device.hostname} {device.vendor} {' '.join(device.notes)} {' '.join(device.mdns_services)}".lower()

        # 1. Smart IP Cameras / Surveillance (check first if explicitly indicated)
        if any(k in text for k in ("camera", "webcam", "ipcam", "hikvision", "dahua", "reolink", "ring", "nest", "wyze", "amcrest", "onvif", "ezviz", "arlo", "axis communications")):
            return "Smart IP Camera"

        # 2. Laptops / Workstations / PCs
        if any(k in text for k in ("laptop", "desktop", "thinkpad", "workstation", "surface", "macbook", "imac", "windows", "win10", "win11", "pc-", "liteon")):
            return "Laptop / Workstation"

        # 3. Smartphones / Mobile Devices
        if any(k in text for k in ("phone", "pixel", "iphone", "galaxy", "nothing", "xiaomi", "oneplus", "huawei", "redmi", "oppo", "vivo", "realme", "motorola", "xperia", "ipad", "android", "mobile")):
            return "Smartphone"

        # 4. Smart TV / Streaming
        if any(k in text for k in ("appletv", "roku", "chromecast", "firetv", "smarttv", "bravia", "lgtv", "samsung-tv", "tcl", "shield", "kodi")):
            return "Smart TV / Streaming"

        # 5. Network Printers
        if any(k in text for k in ("printer", "epson", "canon", "brother", "hp-print", "laserjet", "deskjet", "xerox", "kyocera")):
            return "Network Printer"

        # 6. Network Infrastructure (Routers / APs / Gateways / Switches)
        if any(k in text for k in ("router", "gateway", "access-point", "fritz", "vodafone", "sercomm", "unifi", "ubiquiti", "netgear", "tp-link", "switch", "cisco", "mikrotik")):
            return "Network Appliance / Router"

        # 7. Smart Speaker / Audio
        if any(k in text for k in ("sonos", "echo", "alexa", "homepod", "google-home", "nest-mini", "bose")):
            return "Smart Speaker / Audio"

        # 8. NAS / Network Storage
        if any(k in text for k in ("nas", "synology", "qnap", "truenas", "unraid")):
            return "NAS / Storage"

        return None

    def build_system_prompt(self) -> str:
        return (
            "You are an expert defensive network security auditor analyzing devices discovered on a private LAN. "
            "Your role is to help the administrator classify hardware, evaluate exposure, and decide whether to whitelist or isolate it.\n"
            "Hardware Taxonomy:\n"
            "- 'Smartphone': Mobile phones and handheld tablets (e.g. Android, iPhone, Pixel, Nothing Phone, Galaxy).\n"
            "- 'Laptop / Workstation': Portable laptops, PCs, desktops, development workstations.\n"
            "- 'Smart TV / Streaming': Streaming dongles, set-top boxes, smart televisions.\n"
            "- 'Smart IP Camera': Surveillance cameras, NVRs (ONLY when video or camera indicators are present).\n"
            "- 'Network Appliance / Router': Gateways, access points, managed switches, firewalls.\n"
            "- 'Network Printer': Printers, multi-function copiers.\n"
            "- 'Smart Home / IoT': Smart plugs, light bulbs, thermostats, smart speakers.\n"
            "- 'Unknown Device': Unidentifiable hardware.\n\n"
            "Return strictly valid JSON matching this schema:\n"
            "{\n"
            '  "device_type": "string (selected from taxonomy above)",\n'
            '  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",\n'
            '  "summary": "string (1-2 sentences summarizing what this hardware is and why it has this risk profile)",\n'
            '  "whitelist_recommendation": "ALLOW" | "BLOCK" | "INVESTIGATE",\n'
            '  "action_advice": "string (1 sentence concrete advice for the network admin)"\n'
            "}\n\n"
            "CRITICAL: Do NOT classify devices as 'Smart IP Camera' unless camera/video/surveillance keywords are explicitly present. "
            "Examine Hostname, Vendor, and the Hardware Category Hint carefully."
        )

    def build_user_prompt(self, device: Device, threats: List[str] = None) -> str:
        threat_list = (threats or []) + device.threats
        threats_text = ", ".join(threat_list) if threat_list else "None detected"
        ports_text = ", ".join(device.open_ports) if device.open_ports else "None open / unresponsive"
        notes_text = "; ".join(device.notes) if device.notes else "None"
        hint = self.infer_device_hint(device)
        hint_line = f"- Hardware Category Hint: {hint}\n" if hint else ""

        return (
            f"Analyze the following newly discovered LAN host:\n"
            f"- IP Address: {device.ip}\n"
            f"- MAC Address: {device.mac} ({'Randomized/Private MAC' if device.is_randomized else 'Physical OUI'})\n"
            f"- Hostname / mDNS: {device.display_name}\n"
            f"- Hardware Vendor: {device.vendor}\n"
            f"{hint_line}"
            f"- Open Ports & Services: {ports_text}\n"
            f"- Scanner Threat Flags: {threats_text}\n"
            f"- Notes / HTTP Banners: {notes_text}\n\n"
            f"Provide the assessment JSON."
        )

    def _clean_json_text(self, text: str) -> str:
        """Strips markdown code blocks or surrounding text to isolate raw JSON."""
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text)
        # Try to locate opening and closing braces
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start : end + 1]
        return text

    def _parse_response_json(
        self, raw_text: str, device: Optional[Device] = None
    ) -> Optional[DeviceRiskAssessment]:
        """Safely parses LLM text into a strongly-typed DeviceRiskAssessment with grounding validation."""
        try:
            clean = self._clean_json_text(raw_text)
            data = json.loads(clean)

            risk_raw = str(data.get("risk_level", RiskLevel.MEDIUM.value)).upper().strip()
            try:
                risk = RiskLevel(risk_raw)
            except ValueError:
                risk = RiskLevel.MEDIUM

            rec_raw = str(data.get("whitelist_recommendation", WhitelistRecommendation.INVESTIGATE.value)).upper().strip()
            try:
                rec = WhitelistRecommendation(rec_raw)
            except ValueError:
                rec = WhitelistRecommendation.INVESTIGATE

            device_type = str(data.get("device_type", "Unknown Device")).strip()
            summary = str(data.get("summary", "No summary provided.")).strip()
            action = str(data.get("action_advice", "Monitor device traffic.")).strip()

            # If device type is unclassified or unknown, fall back to deterministic hint:
            if device and (not device_type or device_type.lower() in ("unknown", "unknown device")):
                hint = self.infer_device_hint(device)
                if hint:
                    device_type = hint

            return DeviceRiskAssessment(
                device_type=device_type,
                risk_level=risk,
                summary=summary,
                whitelist_recommendation=rec,
                action_advice=action,
                provider=self.provider_label,
            )
        except Exception:
            return None

    @staticmethod
    def compute_posture(threats: List[str], alien_count: int) -> NetworkPosture:
        """
        Deterministically computes the network security posture:
        - CRITICAL: Active security threats or high-risk vulnerabilities detected.
        - WARNING: Unrecognized alien devices present, requiring admin review.
        - SECURE: All active devices verified against whitelist with zero threats.
        """
        if threats:
            return NetworkPosture.CRITICAL
        if alien_count > 0:
            return NetworkPosture.WARNING
        return NetworkPosture.SECURE

    def build_network_posture_system_prompt(self) -> str:
        return (
            "You are a defensive network security auditor providing executive analysis of a private LAN audit.\n"
            "Given the network facts and security posture, return valid JSON matching this schema:\n"
            "{\n"
            '  "summary": "1-2 sentence executive assessment of the network posture",\n'
            '  "hardening_advice": ["actionable recommendation 1", "actionable recommendation 2"]\n'
            "}"
        )

    def build_network_posture_user_prompt(self, audit: Any, posture: str) -> str:
        threats_str = "\n".join(f"- {t}" for t in audit.threats) if audit.threats else "None detected"
        dev_sample = []
        for d in audit.devices[:12]:
            status = "Alien" if d.is_alien else ("Trusted" if d.trusted else "Unverified")
            ports = f"Ports: {', '.join(d.open_ports)}" if d.open_ports else "No open ports"
            dev_sample.append(f"- {d.display_name} ({d.ip}, {status}, {ports})")
        dev_text = "\n".join(dev_sample) if dev_sample else "No devices cataloged"

        return (
            f"Audit Summary for local subnet {audit.network.subnet_cidr}:\n"
            f"- Computed Posture: [{posture}]\n"
            f"- Total Hosts: {audit.total_count}, Trusted: {audit.trusted_count}, Unrecognized Aliens: {audit.alien_count}\n"
            f"- Security Threat Flags: {threats_str}\n\n"
            f"Device Inventory Sample:\n{dev_text}\n\n"
            f"Provide the executive assessment JSON with summary and hardening recommendations."
        )

    def _parse_posture_json(
        self,
        raw_text: str,
        posture: Union[NetworkPosture, str] = NetworkPosture.SECURE,
        audit: Optional[Any] = None,
    ) -> Optional[NetworkPostureAssessment]:
        try:
            if not isinstance(posture, NetworkPosture):
                try:
                    posture = NetworkPosture(str(posture).upper())
                except ValueError:
                    posture = NetworkPosture.SECURE

            clean = self._clean_json_text(raw_text)
            data = json.loads(clean)

            threats = data.get("threats_found", [])
            if not isinstance(threats, list):
                threats = [str(threats)] if threats else []
            threats = [str(t) for t in threats if t]

            advice = data.get("hardening_advice", [])
            if not isinstance(advice, list):
                advice = [str(advice)] if advice else []
            advice = [str(a) for a in advice if a]

            summary = str(data.get("summary", "")).strip()
            if not summary:
                if posture == NetworkPosture.SECURE:
                    summary = "All active devices verified against trusted whitelist. Zero threats detected."
                elif posture == NetworkPosture.WARNING:
                    alien_cnt = getattr(audit, "alien_count", 0)
                    summary = f"Network is operating normally, but {alien_cnt} unrecognized device(s) require review."
                else:
                    summary = "Active security threats detected requiring immediate administrator attention."

            return NetworkPostureAssessment(
                posture=posture,
                summary=summary,
                threats_found=threats or getattr(audit, "threats", []),
                hardening_advice=advice,
                provider=self.provider_label,
            )
        except Exception:
            return None

    def _post_json(self, url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        """Executes an HTTP POST using only Python standard library."""
        try:
            data = json.dumps(payload).encode("utf-8")
            req_headers = {"Content-Type": "application/json", "User-Agent": "AlienHunter/1.0"}
            if headers:
                req_headers.update(headers)

            req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if 200 <= resp.status < 300:
                    body = resp.read().decode("utf-8", errors="ignore")
                    return json.loads(body)
        except Exception:
            return None
        return None

    @abstractmethod
    def _generate_content(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 300
    ) -> Optional[str]:
        """Subclasses implement provider-specific REST API call and return raw response text."""
        pass

    def analyze(self, device: Device, threats: List[str] = None) -> Optional[DeviceRiskAssessment]:
        """Analyzes a device by invoking _generate_content and parsing the returned JSON."""
        sys_prompt = self.build_system_prompt()
        usr_prompt = self.build_user_prompt(device, threats)
        raw_text = self._generate_content(sys_prompt, usr_prompt, max_tokens=250)
        return self._parse_response_json(raw_text, device=device) if raw_text else None

    def analyze_network_posture(self, audit: Any) -> Optional[NetworkPostureAssessment]:
        """Analyzes the holistic security posture of the network."""
        posture = self.compute_posture(getattr(audit, "threats", []), getattr(audit, "alien_count", 0))
        sys_prompt = self.build_network_posture_system_prompt()
        usr_prompt = self.build_network_posture_user_prompt(audit, posture)
        raw_text = self._generate_content(sys_prompt, usr_prompt, max_tokens=350)
        if raw_text:
            return self._parse_posture_json(raw_text, posture=posture, audit=audit)
        return self._parse_posture_json("{}", posture=posture, audit=audit)

