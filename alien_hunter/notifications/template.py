"""
Reusable Alert Message Formatter for Alien Hunter.
Generates standardized text, markdown, embed fields, and JSON representations
of intrusion alerts for consumption by diverse notification hooks.
"""

import time
from typing import List, Dict, Any, Optional
from ..models import Device



class AlertMessage:
    """Encapsulates and formats an intrusion alert across various presentation standards."""

    def __init__(
        self,
        alien_devices: List[Device],
        threats: List[str] = None,
        audit_result: Optional[Any] = None,
    ):
        self.alien_devices = alien_devices
        self.threats = threats or []
        self.audit_result = audit_result
        self.created_at = time.time()

    @property
    def count(self) -> int:
        return len(self.alien_devices)

    @property
    def is_empty(self) -> bool:
        return not self.alien_devices and not self.threats and not self.audit_result

    @property
    def is_report(self) -> bool:

        return bool(self.audit_result and not self.alien_devices)

    @property
    def title(self) -> str:
        if self.is_report:
            return "Alien Hunter: Network Security Audit Report"
        if not self.alien_devices and self.threats:
            return "Alien Hunter: Threat Alert"
        return "Alien Hunter: Unrecognized Device Alert"

    @property
    def headline(self) -> str:
        if self.is_report and self.audit_result:
            return f"**Alien Hunter Audit**: {self.audit_result.total_count} device(s) on LAN"
        if not self.alien_devices and self.threats:
            return f"**Alien Hunter Threat**: {len(self.threats)} threat(s) detected on LAN"
        return f"**Alien Hunter Alert**: {self.count} unrecognized device(s) detected on LAN"

    @property
    def formatted_time(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.created_at))

    @property
    def iso_timestamp(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.created_at))

    @staticmethod
    def categorize_threat(threat_str: str) -> str:
        """Identifies the specific defensive subsystem that detected the threat."""
        if threat_str.startswith("["):
            return threat_str
        t_lower = threat_str.lower()
        if "arp spoofing" in t_lower or "rogue gateway" in t_lower:
            detector = "ARP Spoofing Monitor"
        elif "dhcp" in t_lower:
            detector = "Rogue DHCP Guard"
        elif "llmnr" in t_lower or "netbios-ns" in t_lower or "responder" in t_lower or "inveigh" in t_lower:
            detector = "LLMNR Canary Trap (Anti-Responder)"
        elif "dns" in t_lower or "nxdomain" in t_lower:
            detector = "DNS Integrity Auditor"
        elif "ipv6" in t_lower or "mitm6" in t_lower:
            detector = "IPv6 RA Guard"
        elif "promiscuous mode" in t_lower:
            detector = "Anti-Sniff Promiscuous Detector"
        elif "port drift" in t_lower or "newly opened" in t_lower:
            detector = "Port Drift Tracker"
        elif "honey-port" in t_lower or "honeypot" in t_lower:
            detector = "Honey-Port Canary"
        elif "evil twin" in t_lower or "rogue ap" in t_lower or "airspace" in t_lower:
            detector = "Wireless Airspace Auditor"
        elif "unencrypted" in t_lower or "telnet" in t_lower or "smb" in t_lower or "ftp" in t_lower:
            detector = "Service Vulnerability Scanner"
        else:
            detector = "Threat Detection Engine"
        return f"[{detector}] {threat_str}"

    def to_markdown(self) -> str:
        """Standard Markdown representation for Telegram, Matrix, NTFY, or chat bodies."""
        if self.is_report and self.audit_result:
            audit = self.audit_result
            lines = [
                f"*{self.title}*",
                f"📋 *Audit Complete:* `{audit.total_count}` cataloged hosts ({audit.trusted_count} trusted, {audit.alien_count} alien)\n",
            ]
            if audit.ai_posture:
                ap = audit.ai_posture
                lines.append(f"🤖 *AI Network Posture:* `{ap.posture}`")
                lines.append(f"*Assessment:* _{ap.summary}_")
                if ap.threats_found:
                    lines.append(f"*Threats:* {', '.join(ap.threats_found)}")
                if ap.hardening_advice:
                    lines.append(f"*Hardening Advice:* {', '.join(ap.hardening_advice)}")
                lines.append("")

            if self.threats:
                lines.append("*⚠️ Security Threats Detected:*")
                for t in self.threats[:5]:
                    lines.append(f"  • {self.categorize_threat(t)}")
                lines.append("")
            else:
                lines.append("✅ *No active ARP spoofing, Evil Twin, or rogue DHCP servers detected.*\n")

            if audit.devices:
                lines.append("*Cataloged Devices:*")
                for d in audit.devices[:8]:
                    lines.append(f"• `{d.ip}`: {d.display_name} ({d.status})")
                lines.append("")

            lines.append(f"🕒 _{self.formatted_time}_")
            return "\n".join(lines)

        lines = [
            f"*{self.title}*",
            f"*{self.count} unrecognized device(s) joined your local network:*\n",
        ]

        for d in self.alien_devices[:10]:
            lines.append(f"• *Device:* `{d.display_name}`")
            lines.append(f"  *IP:* `{d.ip}`")
            lines.append(f"  *MAC:* `{d.mac}`")
            lines.append(f"  *Vendor:* {d.vendor}")
            lines.append(f"  🔍 *Discovery Method:* {d.discovery_method}")
            if d.open_ports:
                lines.append(f"  *Ports:* {', '.join(d.open_ports[:5])}")
            if d.threats:
                lines.append(f"  ⚠️ *Host Threats:* {', '.join(d.threats)}")
            if d.ai_assessment:
                ai = d.ai_assessment
                lines.append(f"  🤖 *AI Risk:* `{ai.risk_level}` ({ai.device_type})")
                lines.append(f"  *Summary:* _{ai.summary}_")
                lines.append(f"  *Advice:* {ai.action_advice}")
            lines.append(f"  *Status:* {d.status}\n")

        if self.threats:
            lines.append("*⚠️ Security Threats Detected:*")
            for t in self.threats[:5]:
                lines.append(f"  • {self.categorize_threat(t)}")
            lines.append("")

        lines.append(f"🕒 _{self.formatted_time}_")
        return "\n".join(lines)

    def to_plain_text(self) -> str:
        """Plain ASCII text representation for logs, SMS, or basic notification daemons."""
        if self.is_report and self.audit_result:
            audit = self.audit_result
            lines = [
                self.title,
                f"Audit Complete: {audit.total_count} cataloged hosts ({audit.trusted_count} trusted, {audit.alien_count} alien)\n",
            ]
            if audit.ai_posture:
                ap = audit.ai_posture
                lines.append(f"AI Network Posture: {ap.posture}")
                lines.append(f"Assessment: {ap.summary}")
                if ap.threats_found:
                    lines.append(f"Threats: {', '.join(ap.threats_found)}")
                if ap.hardening_advice:
                    lines.append(f"Hardening Advice: {', '.join(ap.hardening_advice)}")
                lines.append("")

            if self.threats:
                lines.append("Security Threats Detected:")
                for t in self.threats[:5]:
                    lines.append(f"  - {self.categorize_threat(t)}")
                lines.append("")
            else:
                lines.append("No active ARP spoofing, Evil Twin, or rogue DHCP servers detected.\n")

            if audit.devices:
                lines.append("Cataloged Devices:")
                for d in audit.devices[:8]:
                    lines.append(f"- {d.ip}: {d.display_name} ({d.status})")
                lines.append("")

            lines.append(f"Timestamp: {self.formatted_time}")
            return "\n".join(lines)

        lines = [
            "ALERT: Alien Hunter Intrusion Detected!",
            f"{self.count} unrecognized device(s) found on network:\n",
        ]

        for d in self.alien_devices[:10]:
            lines.append(f"- Device:           {d.display_name}")
            lines.append(f"  IP:               {d.ip}")
            lines.append(f"  MAC:              {d.mac}")
            lines.append(f"  Vendor:           {d.vendor}")
            lines.append(f"  Discovery Method: {d.discovery_method}")
            if d.threats:
                lines.append(f"  Host Threats:     {', '.join(d.threats)}")
            if d.ai_assessment:
                ai = d.ai_assessment
                lines.append(f"  AI Risk:          [{ai.risk_level}] {ai.device_type} - {ai.summary}")
                lines.append(f"  Advice:           {ai.action_advice}")
            lines.append(f"  Status:           {d.status}\n")

        if self.threats:
            lines.append("Threats:")
            for t in self.threats[:5]:
                lines.append(f"  - {self.categorize_threat(t)}")
            lines.append("")

        lines.append(f"Timestamp: {self.formatted_time}")
        return "\n".join(lines)

    def to_fields(self) -> List[Dict[str, Any]]:
        """Field objects formatted for Discord rich embeds and Slack attachments."""
        fields = []
        for d in self.alien_devices[:10]:
            desc_parts = [
                f"**IP:** `{d.ip}`",
                f"**MAC:** `{d.mac}`",
                f"**Vendor:** {d.vendor}",
                f"**Discovery:** {d.discovery_method}",
            ]
            if d.open_ports:
                desc_parts.append(f"**Ports:** {', '.join(d.open_ports[:5])}")
            if d.threats:
                desc_parts.append(f"**Threats:** {', '.join(d.threats)}")
            if d.ai_assessment:
                ai = d.ai_assessment
                desc_parts.append(f"**AI Risk:** `{ai.risk_level}` ({ai.device_type})")
                desc_parts.append(f"**AI Summary:** {ai.summary}")
                desc_parts.append(f"**Advice:** {ai.action_advice}")
            desc_parts.append(f"**Status:** {d.status}")

            fields.append({
                "name": f"Device: {d.display_name}",
                "value": "\n".join(desc_parts),
                "inline": False,
            })

        if self.threats:
            fields.append({
                "name": "⚠️ Threats Detected",
                "value": "\n".join(f"• {t}" for t in self.threats[:5]),
                "inline": False,
            })

        return fields

    def to_slack_blocks(self) -> List[Dict[str, Any]]:
        """BlockKit blocks formatted for Slack incoming webhooks."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🛸 Alien Hunter: Intrusion Alert!", "emoji": True},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Alert:* {self.count} unrecognized device(s) detected on your local network.",
                },
            },
            {"type": "divider"},
        ]

        for d in self.alien_devices[:10]:
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Device:*\n{d.display_name}"},
                    {"type": "mrkdwn", "text": f"*IP:*\n`{d.ip}`"},
                    {"type": "mrkdwn", "text": f"*MAC:*\n`{d.mac}`"},
                    {"type": "mrkdwn", "text": f"*Vendor:*\n{d.vendor}"},
                ],
            })

        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Detected at: {self.formatted_time}"}],
        })
        return blocks

    def to_dict(self) -> Dict[str, Any]:
        """Structured dictionary representation for generic JSON webhooks and SIEM ingestion."""
        return {
            "title": self.title,
            "count": self.count,
            "timestamp": self.created_at,
            "formatted_time": self.formatted_time,
            "devices": [d.to_dict() for d in self.alien_devices],
            "threats": self.threats,
        }
