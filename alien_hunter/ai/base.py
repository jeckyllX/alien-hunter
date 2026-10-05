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
    AttackPath,
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
            '  "action_advice": "1 concise, actionable recommendation for the administrator",\n'
            '  "vulnerabilities": ["Specific identified CVEs, daemon vulnerabilities, or security exposures from banners (or empty array if none)"]\n'
            "}\n\n"
            "### Vulnerability Evaluation\n"
            "Evaluate observed protocol banners and service versions for known security weaknesses (e.g., outdated daemons, known unauthenticated exposure, unencrypted legacy protocols). Return identified vulnerabilities in the 'vulnerabilities' array (or empty array if none).\n"
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
            vulns_raw = data.get("vulnerabilities", [])
            vulnerabilities = [str(v).strip() for v in vulns_raw if str(v).strip()] if isinstance(vulns_raw, list) else []

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
                vulnerabilities=vulnerabilities,
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
            "You are an expert defensive network security auditor and threat modeling specialist analyzing a private LAN audit.\n"
            "Evaluate aggregate network audit findings, topology segmentation, blast radius, and potential lateral movement vectors.\n\n"
            "### Posture Tiers\n"
            "- 'SECURE': All active devices are verified against authorization baseline with zero active threats.\n"
            "- 'WARNING': Unrecognized alien devices or notable segmentation risks present, requiring review.\n"
            "- 'CRITICAL': Active security exploits, spoofing, or severe service exposures detected.\n\n"
            "### Scope of Analysis\n"
            "1. Segmentation & Blast Radius:\n"
            "   - Identify weaknesses where low-trust or unmanaged devices (Smart TVs, IoT devices, guest phones, alien hosts) share the same unsegmented Layer-2 broadcast domain with sensitive workstations or infrastructure.\n"
            "   - Evaluate the blast radius if an untrusted or IoT node is compromised.\n"
            "2. Lateral Movement & Attack Paths:\n"
            "   - Identify realistic lateral movement attack paths that an adversary with access to a low-trust device could execute against critical assets (e.g., pivot to workstation SMB/RDP, router web administration, DNS hijacking, or unauthenticated UPnP/mDNS).\n"
            "3. Defensive Mitigation:\n"
            "   - Provide concrete, prioritized network hardening actions (e.g. guest Wi-Fi isolation, VLAN segmentation, firewall rules).\n\n"
            "### Output Schema\n"
            "Return strictly valid JSON with this exact structure:\n"
            "{\n"
            '  "summary": "1-2 sentence executive assessment of overall network security posture",\n'
            '  "blast_radius_summary": "1-2 sentence assessment of blast radius if a low-trust or IoT node is compromised",\n'
            '  "segmentation_risks": [\n'
            '    "Specific segmentation risk (e.g. Flat /24 subnet permits IoT devices to probe workstation file shares)"\n'
            '  ],\n'
            '  "attack_paths": [\n'
            '    {\n'
            '      "entry_point": "<Identified entry or pivot node, e.g. TLC Smart TV (192.168.1.26)>",\n'
            '      "target": "<Target high-value node, e.g. Acer Biagio (192.168.1.112) or Gateway (192.168.1.1)>",\n'
            '      "vector": "<Specific lateral movement mechanism, e.g. Layer-2 unsegmented SMB/RPC probe>",\n'
            '      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n'
            '      "mitigation": "<Concrete defensive countermeasure, e.g. Isolate Smart TV on Guest Wi-Fi / IoT VLAN>"\n'
            '    }\n'
            '  ],\n'
            '  "hardening_advice": [\n'
            '    "Actionable network hardening recommendation 1",\n'
            '    "Actionable network hardening recommendation 2"\n'
            '  ]\n'
            "}"
        )

    def build_network_posture_user_prompt(self, audit: Any, posture: str) -> str:
        threats_str = "\n".join(f"- {t}" for t in audit.threats) if audit.threats else "None detected"

        # Categorize devices into security zones
        infra_devices = []
        workstations = []
        iot_devices = []
        mobile_devices = []
        alien_devices = []
        other_devices = []

        gateway_ip = getattr(getattr(audit, "network", None), "gateway_ip", "")

        for d in getattr(audit, "devices", []):
            hint = self.infer_device_hint(d) or ""
            status = "Alien" if d.is_alien else ("Trusted" if d.trusted else "Unverified")
            ports = f"Ports: {', '.join(d.open_ports)}" if d.open_ports else "Stealth / Closed"
            notes = f" [{'; '.join(d.notes[:2])}]" if d.notes else ""
            line = f"- {d.display_name} ({d.ip}, {status}, {ports}{notes})"

            if d.is_alien:
                alien_devices.append(line)
            elif d.ip == gateway_ip or "router" in hint.lower() or "appliance" in hint.lower():
                infra_devices.append(line)
            elif "workstation" in hint.lower() or "laptop" in hint.lower() or "storage" in hint.lower():
                workstations.append(line)
            elif any(k in hint.lower() for k in ("camera", "tv", "iot", "printer", "speaker")):
                iot_devices.append(line)
            elif "smartphone" in hint.lower():
                mobile_devices.append(line)
            else:
                other_devices.append(line)

        sections = []
        if infra_devices:
            sections.append("#### Infrastructure & Gateway Assets:\n" + "\n".join(infra_devices))
        if workstations:
            sections.append("#### Sensitive Workstations & High-Value Assets:\n" + "\n".join(workstations))
        if iot_devices:
            sections.append("#### IoT, Media & Peripheral Devices (Potential Pivot Points):\n" + "\n".join(iot_devices))
        if mobile_devices:
            sections.append("#### Mobile & Roaming Endpoints:\n" + "\n".join(mobile_devices))
        if alien_devices:
            sections.append("#### Unrecognized / Alien Nodes:\n" + "\n".join(alien_devices))
        if other_devices:
            sections.append("#### Other Discovered Hosts:\n" + "\n".join(other_devices))

        inventory_text = "\n\n".join(sections) if sections else "No devices cataloged"

        net = getattr(audit, "network", None)
        subnet_cidr = getattr(net, "subnet_cidr", "192.168.1.0/24")
        gw_ip = getattr(net, "gateway_ip", "Unknown")
        gw_mac = getattr(net, "gateway_mac", "Unknown")
        iface = getattr(net, "interface", "Unknown")
        loc_ip = getattr(net, "local_ip", "Unknown")

        return (
            f"### Network Audit Context\n"
            f"- Subnet: {subnet_cidr} (Broadcast Domain: Layer-2 Flat Subnet)\n"
            f"- Gateway: {gw_ip} ({gw_mac})\n"
            f"- Auditor Interface: {iface} (Local Host: {loc_ip})\n"
            f"- Deterministic Posture: [{posture}]\n"
            f"- Total Cataloged Inventory: {audit.total_count} hosts ({audit.trusted_count} trusted, {audit.alien_count} alien)\n"
            f"- Active Threats & Anomalies: {threats_str}\n\n"
            f"### Categorized Network Topology & Inventory\n"
            f"{inventory_text}\n\n"
            f"Perform an exhaustive lateral movement and segmentation analysis. Return the structured JSON assessment."
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

            attack_paths_raw = data.get("attack_paths", [])
            attack_paths: List[AttackPath] = []
            if isinstance(attack_paths_raw, list):
                for p in attack_paths_raw:
                    if isinstance(p, dict):
                        ep = str(p.get("entry_point", "")).strip()
                        tgt = str(p.get("target", "")).strip()
                        vec = str(p.get("vector", "")).strip()
                        sev = str(p.get("severity", "MEDIUM")).upper().strip()
                        mit = str(p.get("mitigation", "")).strip()
                        if ep or tgt or vec:
                            attack_paths.append(
                                AttackPath(
                                    entry_point=ep or "Unknown Node",
                                    target=tgt or "Network Asset",
                                    vector=vec or "Layer-2 Lateral Access",
                                    severity=sev if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM",
                                    mitigation=mit or "Implement network isolation",
                                )
                            )

            seg_risks_raw = data.get("segmentation_risks", [])
            if not isinstance(seg_risks_raw, list):
                seg_risks_raw = [str(seg_risks_raw)] if seg_risks_raw else []
            segmentation_risks = [str(r).strip() for r in seg_risks_raw if str(r).strip()]

            blast_radius = str(data.get("blast_radius_summary", "")).strip()

            return NetworkPostureAssessment(
                posture=posture,
                summary=summary,
                threats_found=threats or getattr(audit, "threats", []),
                hardening_advice=advice,
                provider=self.provider_label,
                attack_paths=attack_paths,
                segmentation_risks=segmentation_risks,
                blast_radius_summary=blast_radius,
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
        """
        LLM posture analysis. Returns None on transport failure or unparseable
        output so callers can distinguish a real assessment from a fallback.
        """
        posture = self.compute_posture(getattr(audit, "threats", []), getattr(audit, "alien_count", 0))
        sys_prompt = self.build_network_posture_system_prompt()
        usr_prompt = self.build_network_posture_user_prompt(audit, posture)
        raw_text = self._generate_content(sys_prompt, usr_prompt, max_tokens=self.max_tokens)
        if not raw_text:
            return None
        return self._parse_posture_json(raw_text, posture=posture, audit=audit)

    def fallback_posture(self, audit: Any) -> Optional[NetworkPostureAssessment]:
        """Deterministic posture without an LLM call (used when the provider fails)."""
        posture = self.compute_posture(getattr(audit, "threats", []), getattr(audit, "alien_count", 0))
        return self._parse_posture_json("{}", posture=posture, audit=audit)

