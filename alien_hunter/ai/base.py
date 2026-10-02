"""
Abstract Base Provider for AI Device Security Analyzers.
Provides standard prompt generation, defensive system framing,
safe HTTP execution, and robust JSON parsing across all providers.
"""

import json
import re
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional, List, Union, Tuple, Set

from .models import (
    DeviceRiskAssessment,
    NetworkPostureAssessment,
    NetworkPosture,
    RiskLevel,
    WhitelistRecommendation,
)
from ..models import Device


@dataclass(frozen=True)
class DeviceSignature:
    """Declarative signature mapping network fingerprints to hardware categories."""
    category: str
    tokens: Tuple[str, ...] = ()
    ports: Tuple[int, ...] = ()
    is_randomized: Optional[bool] = None
    stealth_only: bool = False

    def matches(self, device: Device, text: str, open_ports: Set[int]) -> bool:
        if self.is_randomized is not None and device.is_randomized != self.is_randomized:
            return False
        if self.stealth_only and open_ports:
            return False
        if self.ports and not any(p in open_ports for p in self.ports):
            return False
        if self.tokens and not any(t in text for t in self.tokens):
            return False
        return True


DEVICE_SIGNATURES: Tuple[DeviceSignature, ...] = (
    # Surveillance / Cameras
    DeviceSignature(
        category="Smart IP Camera",
        tokens=("camera", "webcam", "ipcam", "hikvision", "dahua", "reolink", "ring", "nest", "wyze", "amcrest", "onvif", "ezviz", "arlo", "axis communications"),
    ),
    DeviceSignature(
        category="Smart IP Camera",
        ports=(554,),
    ),
    # Workstations / PCs
    DeviceSignature(
        category="Laptop / Workstation",
        tokens=("laptop", "desktop", "thinkpad", "workstation", "surface", "macbook", "imac", "windows", "win10", "win11", "pc-", "liteon"),
    ),
    DeviceSignature(
        category="Laptop / Workstation",
        ports=(135, 139, 445, 3389),
    ),
    # Smartphones / Tablets
    DeviceSignature(
        category="Smartphone",
        tokens=("phone", "pixel", "iphone", "galaxy", "nothing", "cobalt", "xiaomi", "oneplus", "huawei", "redmi", "oppo", "vivo", "realme", "motorola", "xperia", "ipad", "android", "mobile"),
    ),
    # Streaming / Smart TVs
    DeviceSignature(
        category="Smart TV / Streaming",
        tokens=("appletv", "roku", "chromecast", "firetv", "smarttv", "bravia", "lgtv", "samsung-tv", "tcl", "shield", "kodi"),
    ),
    # Network Printers
    DeviceSignature(
        category="Network Printer",
        tokens=("printer", "epson", "canon", "brother", "hp-print", "laserjet", "deskjet", "xerox", "kyocera"),
    ),
    DeviceSignature(
        category="Network Printer",
        ports=(515, 631, 9100),
    ),
    # Network Infrastructure / Gateways
    DeviceSignature(
        category="Network Appliance / Router",
        tokens=("router", "gateway", "access-point", "fritz", "vodafone", "sercomm", "unifi", "ubiquiti", "netgear", "tp-link", "switch", "cisco", "mikrotik"),
    ),
    # Smart Audio
    DeviceSignature(
        category="Smart Speaker / Audio",
        tokens=("sonos", "echo", "alexa", "homepod", "google-home", "nest-mini", "bose"),
    ),
    # Network Attached Storage
    DeviceSignature(
        category="NAS / Storage",
        tokens=("nas", "synology", "qnap", "truenas", "unraid"),
    ),
    # Mobile Devices using IEEE 802 Locally Administered / Private MAC Address
    DeviceSignature(
        category="Smartphone",
        is_randomized=True,
        stealth_only=True,
    ),
)


class BaseAIProvider(ABC):
    """Abstract interface for AI security analysis providers."""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.model = str(config.get("model", "")).strip()
        self.endpoint = str(config.get("endpoint", "")).strip()
        self.api_key = str(config.get("api_key", "")).strip()
        self.timeout = float(config.get("timeout_seconds", 120.0))
        self.max_tokens = int(config.get("max_tokens", 1500))

    @property
    def provider_label(self) -> str:
        return f"{self.name}:{self.model}" if self.model else self.name

    @staticmethod
    def infer_device_hint(device: Device) -> Optional[str]:
        """
        Infers an authoritative hardware classification hint using declarative
        vendor OUIs, hostname conventions, mDNS services, and port fingerprints.
        """
        # 1. Authoritative DHCP Option 55/60 fingerprint from passive listener
        if device.dhcp_params:
            from ..identifiers.signatures import SignatureManager
            match = SignatureManager().match_dhcp(device.dhcp_params)
            if match:
                return match.category

        text = f"{device.display_name} {device.hostname} {device.vendor} {' '.join(device.notes)} {' '.join(device.mdns_services)}".lower()
        open_ports: Set[int] = set()
        for p_str in (device.open_ports or []):
            try:
                open_ports.add(int(p_str.split()[0].split("/")[0]))
            except (ValueError, IndexError):
                pass

        for sig in DEVICE_SIGNATURES:
            if sig.matches(device, text, open_ports):
                return sig.category

        return None

    def build_system_prompt(self) -> str:
        return (
            "You are an expert defensive network security auditor analyzing hosts discovered on a private local area network (LAN).\n"
            "Your task is to analyze host telemetry, evaluate exposure risk, and output structured JSON.\n\n"
            "### Hardware Taxonomy\n"
            "- 'Smartphone': Mobile phones and handheld tablets (iOS, Android).\n"
            "- 'Laptop / Workstation': Laptops, personal computers, developer workstations.\n"
            "- 'Smart TV / Streaming': Smart TVs, streaming dongles, set-top boxes.\n"
            "- 'Smart IP Camera': Surveillance cameras, NVRs, webcams.\n"
            "- 'Network Appliance / Router': Gateways, access points, managed switches, firewalls.\n"
            "- 'Network Printer': Printers, multi-function copiers.\n"
            "- 'Smart Home / IoT': Smart plugs, lights, environmental sensors, smart speakers.\n"
            "- 'NAS / Storage': Network-attached storage devices and file servers.\n"
            "- 'Unknown Device': Insufficient telemetry to categorize.\n\n"
            "### Reference Audit Exemplars\n\n"
            "Example 1: Guest Mobile Client\n"
            "Telemetry: MAC=Locally Administered (Randomized), Exposure=None (Stealth / Closed Profile), Banners=None\n"
            "Analysis: Ephemeral MAC with stealth port profile and no OS service exposure is characteristic of a modern mobile operating system (iOS/Android MAC privacy).\n"
            "Result: {\"analysis\": \"Ephemeral MAC with closed port profile indicates mobile OS privacy.\", \"device_type\": \"Smartphone\", \"risk_level\": \"LOW\", \"whitelist_recommendation\": \"INVESTIGATE\", \"summary\": \"Mobile device operating with randomized MAC privacy and stealth network profile.\", \"action_advice\": \"Verify guest smartphone identity and assign an alias if authorized.\"}\n\n"
            "Example 2: Enterprise Workstation\n"
            "Telemetry: MAC=Physical Registered OUI, Exposure=445 (microsoft-ds), Hostname=DESKTOP-8K2N, Banners=NetBIOS\n"
            "Analysis: Advertised PC desktop naming convention and active SMB file-sharing service indicate a workstation.\n"
            "Result: {\"analysis\": \"Active SMB service and workstation hostname pattern indicate a PC.\", \"device_type\": \"Laptop / Workstation\", \"risk_level\": \"LOW\", \"whitelist_recommendation\": \"ALLOW\", \"summary\": \"Internal workstation with active directory / file sharing services.\", \"action_advice\": \"Ensure host is enrolled in device management.\"}\n\n"
            "Example 3: IP Surveillance Camera\n"
            "Telemetry: MAC=Physical Registered OUI, Exposure=554 (rtsp), Hostname=CAM-DRIVEWAY, Banners=ONVIF\n"
            "Analysis: Active RTSP streaming port and ONVIF discovery banner identify a surveillance camera.\n"
            "Result: {\"analysis\": \"RTSP streaming service and ONVIF banner identify an IP camera.\", \"device_type\": \"Smart IP Camera\", \"risk_level\": \"MEDIUM\", \"whitelist_recommendation\": \"ALLOW\", \"summary\": \"Network IP surveillance camera streaming RTSP video.\", \"action_advice\": \"Isolate camera on a dedicated surveillance VLAN.\"}\n\n"
            "### Output Schema\n"
            "Return strictly valid JSON with this exact structure:\n"
            "{\n"
            '  "analysis": "1-2 sentences reasoning over telemetry (addressing type, ports, banners)",\n'
            '  "device_type": "<Type from Hardware Taxonomy>",\n'
            '  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",\n'
            '  "summary": "1-2 sentence executive summary of device function and risk",\n'
            '  "whitelist_recommendation": "ALLOW" | "INVESTIGATE" | "BLOCK",\n'
            '  "action_advice": "1 concise, actionable recommendation for the administrator"\n'
            "}"
        )

    def build_user_prompt(self, device: Device, threats: List[str] = None) -> str:
        threat_list = (threats or []) + device.threats
        threats_text = ", ".join(threat_list) if threat_list else "None detected"
        ports_text = ", ".join(device.open_ports) if device.open_ports else "None (Stealth / Closed Profile)"
        notes_text = "; ".join(device.notes) if device.notes else "None"
        hint = self.infer_device_hint(device)
        hint_line = f"- Deterministic Hint: {hint}\n" if hint else ""
        dhcp_line = f"- DHCP OS Fingerprint: {device.dhcp_fingerprint}\n" if device.dhcp_fingerprint else ""
        mac_type = "Locally Administered / Randomized (OS Privacy Feature)" if device.is_randomized else "Physical Registered OUI"

        return (
            f"Analyze the following discovered LAN host:\n\n"
            f"### Target Host Telemetry\n"
            f"- IP Address: {device.ip}\n"
            f"- MAC Address: {device.mac} (Addressing Mode: {mac_type})\n"
            f"- Hostname / Identifier: {device.display_name}\n"
            f"- Hardware Vendor: {device.vendor}\n"
            f"{dhcp_line}"
            f"{hint_line}"
            f"- Network Exposure: {ports_text}\n"
            f"- Active Threat Flags: {threats_text}\n"
            f"- Protocol Banners & Notes: {notes_text}\n\n"
            f"Provide the device assessment JSON matching the output schema."
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
            analysis = str(data.get("analysis", "")).strip()

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
                analysis=analysis,
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
            "You are an expert defensive network security auditor delivering an executive posture assessment for a private LAN audit.\n"
            "Evaluate aggregate network audit findings objectively and provide concise executive analysis and hardening recommendations.\n\n"
            "### Posture Tiers\n"
            "- 'SECURE': All active devices are verified against authorization baseline with zero threats detected.\n"
            "- 'WARNING': Unrecognized or unverified alien devices are present, requiring review.\n"
            "- 'CRITICAL': Active security exploits, spoofing, or severe protocol anomalies detected.\n\n"
            "### Output Schema\n"
            "Return strictly valid JSON with this structure:\n"
            "{\n"
            '  "summary": "<1-2 sentence executive assessment of the network security posture>",\n'
            '  "hardening_advice": [\n'
            '    "<actionable recommendation 1>",\n'
            '    "<actionable recommendation 2>"\n'
            "  ]\n"
            "}"
        )

    def build_network_posture_user_prompt(self, audit: Any, posture: str) -> str:
        threats_str = "\n".join(f"- {t}" for t in audit.threats) if audit.threats else "None detected"
        dev_sample = []
        for d in audit.devices[:12]:
            status = "Alien" if d.is_alien else ("Trusted" if d.trusted else "Unverified")
            ports = f"Ports: {', '.join(d.open_ports)}" if d.open_ports else "Stealth / Closed Profile"
            dev_sample.append(f"- {d.display_name} ({d.ip}, {status}, {ports})")
        dev_text = "\n".join(dev_sample) if dev_sample else "No devices cataloged"

        return (
            f"### Network Audit Context\n"
            f"- Subnet: {audit.network.subnet_cidr}\n"
            f"- Computed Posture: [{posture}]\n"
            f"- Inventory: {audit.total_count} total hosts ({audit.trusted_count} trusted, {audit.alien_count} unrecognized aliens)\n"
            f"- Active Threats: {threats_str}\n\n"
            f"### Sample Device Inventory\n"
            f"{dev_text}\n\n"
            f"Provide the executive assessment JSON matching the output schema."
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
        self, system_prompt: str, user_prompt: str, max_tokens: int = 1500
    ) -> Optional[str]:
        """Subclasses implement provider-specific REST API call and return raw response text."""
        pass

    def analyze(self, device: Device, threats: List[str] = None) -> Optional[DeviceRiskAssessment]:
        """Analyzes a device by invoking _generate_content and parsing the returned JSON."""
        sys_prompt = self.build_system_prompt()
        usr_prompt = self.build_user_prompt(device, threats)
        raw_text = self._generate_content(sys_prompt, usr_prompt, max_tokens=self.max_tokens)
        return self._parse_response_json(raw_text, device=device) if raw_text else None

    def analyze_network_posture(self, audit: Any) -> Optional[NetworkPostureAssessment]:
        """Analyzes the holistic security posture of the network."""
        posture = self.compute_posture(getattr(audit, "threats", []), getattr(audit, "alien_count", 0))
        sys_prompt = self.build_network_posture_system_prompt()
        usr_prompt = self.build_network_posture_user_prompt(audit, posture)
        raw_text = self._generate_content(sys_prompt, usr_prompt, max_tokens=self.max_tokens)
        if raw_text:
            return self._parse_posture_json(raw_text, posture=posture, audit=audit)
        return self._parse_posture_json("{}", posture=posture, audit=audit)

