"""
Reusable Alert Message Formatter for Alien Hunter.
Generates standardized text, markdown, embed fields, and JSON representations
of intrusion alerts for consumption by diverse notification hooks.
"""

import re
import time
from typing import List, Dict, Any, Optional
from ..models import Device


def _truncate(text: Any, limit: int) -> str:
    s = str(text or "")
    if len(s) <= limit:
        return s
    return s[: max(1, limit - 3)] + "..."


def _escape_markdown(text: Any) -> str:
    """Escapes Markdown metacharacters in untrusted fields for Telegram/chat delivery."""
    cleaned = re.sub(r"[\r\n]+", " ", str(text or ""))
    return re.sub(r"([\\_*`\[\]])", r"\\\1", cleaned)


def _escape_code(text: Any) -> str:
    """Sanitizes untrusted text embedded inside inline Markdown backticks."""
    cleaned = re.sub(r"[\r\n]+", " ", str(text or ""))
    return cleaned.replace("`", "'")


def _escape_slack(text: Any) -> str:
    """Escapes Slack mrkdwn special characters (&, <, >)."""
    cleaned = re.sub(r"[\r\n]+", " ", str(text or ""))
    return cleaned.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


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
        return bool(self.audit_result and not self.alien_devices and not self.threats)

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

    def _append_markdown_posture(self, lines: List[str], ap: Any) -> None:
        lines.append(f"🤖 *AI Network Posture:* `{_escape_code(ap.posture)}`")
        lines.append(f"*Assessment:* _{_escape_markdown(ap.summary)}_")
        blast = getattr(ap, "blast_radius_summary", "")
        if blast:
            lines.append(f"💥 *Blast Radius:* _{_escape_markdown(blast)}_")
        paths = getattr(ap, "attack_paths", [])
        if paths:
            lines.append("*🎯 Lateral Movement & Attack Paths:*")
            for p in paths[:3]:
                sev = getattr(p, "severity", "MEDIUM") if hasattr(p, "severity") else p.get("severity", "MEDIUM")
                ep = getattr(p, "entry_point", "") if hasattr(p, "entry_point") else p.get("entry_point", "")
                tgt = getattr(p, "target", "") if hasattr(p, "target") else p.get("target", "")
                vec = getattr(p, "vector", "") if hasattr(p, "vector") else p.get("vector", "")
                lines.append(
                    f"  • `[{_escape_code(sev)}]` *{_escape_markdown(ep)}* ➔ *{_escape_markdown(tgt)}*: {_escape_markdown(vec)}"
                )
        if ap.threats_found:
            lines.append(f"*Threats:* {', '.join(_escape_markdown(t) for t in ap.threats_found)}")
        if ap.hardening_advice:
            lines.append(f"*Hardening Advice:* {', '.join(_escape_markdown(a) for a in ap.hardening_advice)}")
        lines.append("")

    def to_markdown(self) -> str:
        """Standard Markdown representation for Telegram, Matrix, NTFY, or chat bodies."""
        if self.is_report and self.audit_result:
            audit = self.audit_result
            lines = [
                f"*{_escape_markdown(self.title)}*",
                f"📋 *Audit Complete:* `{audit.total_count}` cataloged hosts ({audit.trusted_count} trusted, {audit.alien_count} alien)\n",
            ]
            if audit.ai_posture:
                self._append_markdown_posture(lines, audit.ai_posture)

            if self.threats:
                lines.append("*⚠️ Security Threats Detected:*")
                for t in self.threats[:5]:
                    lines.append(f"  • {_escape_markdown(self.categorize_threat(t))}")
                lines.append("")
            else:
                lines.append("✅ *No active ARP spoofing, Evil Twin, or rogue DHCP servers detected.*\n")

            if audit.devices:
                lines.append("*Cataloged Devices:*")
                for d in audit.devices[:8]:
                    lines.append(
                        f"• `{_escape_code(d.ip)}`: {_escape_markdown(d.display_name)} ({_escape_markdown(d.status)})"
                    )
                lines.append("")

            lines.append(f"🕒 _{self.formatted_time}_")
            return "\n".join(lines)

        lines = [f"*{_escape_markdown(self.title)}*"]
        if self.alien_devices:
            lines.append(f"*{self.count} unrecognized device(s) joined your local network:*\n")
            for d in self.alien_devices[:10]:
                lines.append(f"• *Device:* `{_escape_code(d.display_name)}`")
                lines.append(f"  *IP:* `{_escape_code(d.ip)}`")
                lines.append(f"  *MAC:* `{_escape_code(d.mac)}`")
                lines.append(f"  *Vendor:* {_escape_markdown(d.vendor)}")
                lines.append(f"  🔍 *Discovery Method:* {_escape_markdown(d.discovery_method)}")
                if d.open_ports:
                    lines.append(f"  *Ports:* {', '.join(_escape_markdown(p) for p in d.open_ports[:5])}")
                if d.threats:
                    lines.append(f"  ⚠️ *Host Threats:* {', '.join(_escape_markdown(t) for t in d.threats)}")
                if d.ai_assessment:
                    ai = d.ai_assessment
                    lines.append(
                        f"  🤖 *AI Risk:* `{_escape_code(ai.risk_level)}` ({_escape_markdown(ai.device_type)})"
                    )
                    lines.append(f"  *Summary:* _{_escape_markdown(ai.summary)}_")
                    if getattr(ai, "vulnerabilities", None):
                        lines.append(
                            f"  🛡️ *Vulnerabilities:* {'; '.join(_escape_markdown(v) for v in ai.vulnerabilities[:3])}"
                        )
                    lines.append(f"  *Advice:* {_escape_markdown(ai.action_advice)}")
                lines.append(f"  *Status:* {_escape_markdown(d.status)}\n")
        elif self.threats:
            lines.append(f"*{len(self.threats)} security threat(s) detected on your local network:*\n")

        if self.threats:
            lines.append("*⚠️ Security Threats Detected:*")
            for t in self.threats[:5]:
                lines.append(f"  • {_escape_markdown(self.categorize_threat(t))}")
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
                blast = getattr(ap, "blast_radius_summary", "")
                if blast:
                    lines.append(f"Blast Radius: {blast}")
                paths = getattr(ap, "attack_paths", [])
                if paths:
                    lines.append("Lateral Movement & Attack Paths:")
                    for p in paths[:3]:
                        sev = getattr(p, "severity", "MEDIUM") if hasattr(p, "severity") else p.get("severity", "MEDIUM")
                        ep = getattr(p, "entry_point", "") if hasattr(p, "entry_point") else p.get("entry_point", "")
                        tgt = getattr(p, "target", "") if hasattr(p, "target") else p.get("target", "")
                        vec = getattr(p, "vector", "") if hasattr(p, "vector") else p.get("vector", "")
                        lines.append(f"  - [{sev}] {ep} -> {tgt}: {vec}")
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

        lines = []
        if self.alien_devices:
            lines.append("ALERT: Alien Hunter Intrusion Detected!")
            lines.append(f"{self.count} unrecognized device(s) found on network:\n")
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
                    if getattr(ai, "vulnerabilities", None):
                        lines.append(f"  Vulnerabilities:  {'; '.join(ai.vulnerabilities[:3])}")
                    lines.append(f"  Advice:           {ai.action_advice}")
                lines.append(f"  Status:           {d.status}\n")
        else:
            lines.append("ALERT: Alien Hunter Security Threat Detected!")
            if self.threats:
                lines.append(f"{len(self.threats)} security threat(s) detected on network:\n")

        if self.threats:
            lines.append("Threats:")
            for t in self.threats[:5]:
                lines.append(f"  - {self.categorize_threat(t)}")
            lines.append("")

        lines.append(f"Timestamp: {self.formatted_time}")
        return "\n".join(lines)

    def to_fields(self) -> List[Dict[str, Any]]:
        """Field objects formatted for Discord rich embeds and Slack attachments."""
        fields: List[Dict[str, Any]] = []

        if self.is_report and self.audit_result:
            audit = self.audit_result
            summary_lines = [
                f"**Cataloged Hosts:** {audit.total_count} ({audit.trusted_count} trusted, {audit.alien_count} alien)"
            ]
            if audit.ai_posture:
                ap = audit.ai_posture
                summary_lines.append(f"**AI Posture:** `{_escape_code(ap.posture)}`")
                summary_lines.append(f"**Assessment:** {_escape_markdown(ap.summary)}")
                if getattr(ap, "hardening_advice", None):
                    summary_lines.append(
                        f"**Hardening:** {'; '.join(_escape_markdown(a) for a in ap.hardening_advice[:3])}"
                    )
            fields.append({
                "name": "Audit Summary",
                "value": _truncate("\n".join(summary_lines), 1024),
                "inline": False,
            })

        for d in self.alien_devices[:10]:
            desc_parts = [
                f"**IP:** `{_escape_code(d.ip)}`",
                f"**MAC:** `{_escape_code(d.mac)}`",
                f"**Vendor:** {_escape_markdown(d.vendor)}",
                f"**Discovery:** {_escape_markdown(d.discovery_method)}",
            ]
            if d.open_ports:
                desc_parts.append(f"**Ports:** {', '.join(_escape_markdown(p) for p in d.open_ports[:5])}")
            if d.threats:
                desc_parts.append(f"**Threats:** {', '.join(_escape_markdown(t) for t in d.threats)}")
            if d.ai_assessment:
                ai = d.ai_assessment
                desc_parts.append(
                    f"**AI Risk:** `{_escape_code(ai.risk_level)}` ({_escape_markdown(ai.device_type)})"
                )
                desc_parts.append(f"**AI Summary:** {_escape_markdown(ai.summary)}")
                if getattr(ai, "vulnerabilities", None):
                    desc_parts.append(
                        f"**Vulnerabilities:** {'; '.join(_escape_markdown(v) for v in ai.vulnerabilities[:3])}"
                    )
                desc_parts.append(f"**Advice:** {_escape_markdown(ai.action_advice)}")
            desc_parts.append(f"**Status:** {_escape_markdown(d.status)}")

            fields.append({
                "name": _truncate(f"Device: {_escape_markdown(d.display_name)}", 256),
                "value": _truncate("\n".join(desc_parts), 1024),
                "inline": False,
            })

        if self.threats:
            threats_val = "\n".join(
                f"• {_escape_markdown(self.categorize_threat(t))}" for t in self.threats[:5]
            )
            fields.append({
                "name": "⚠️ Threats Detected",
                "value": _truncate(threats_val, 1024),
                "inline": False,
            })

        return fields

    def to_slack_blocks(self) -> List[Dict[str, Any]]:
        """BlockKit blocks formatted for Slack incoming webhooks."""
        if self.is_report and self.audit_result:
            audit = self.audit_result
            header_text = "📋 Alien Hunter: Audit Report"
            intro_text = (
                f"*Audit Complete:* {audit.total_count} cataloged hosts "
                f"({audit.trusted_count} trusted, {audit.alien_count} alien)."
            )
        elif not self.alien_devices and self.threats:
            header_text = "🚨 Alien Hunter: Threat Alert!"
            intro_text = (
                f"*Threat Alert:* {len(self.threats)} security threat(s) detected on your local network."
            )
        else:
            header_text = "🛸 Alien Hunter: Intrusion Alert!"
            intro_text = (
                f"*Alert:* {self.count} unrecognized device(s) detected on your local network."
            )

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": _truncate(header_text, 150), "emoji": True},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": _truncate(intro_text, 3000)},
            },
            {"type": "divider"},
        ]

        if self.is_report and self.audit_result and self.audit_result.ai_posture:
            ap = self.audit_result.ai_posture
            posture_lines = [
                f"*AI Network Posture:* `{_escape_code(ap.posture)}`",
                f"*Assessment:* {_escape_slack(ap.summary)}",
            ]
            if getattr(ap, "hardening_advice", None):
                advice_str = ", ".join(_escape_slack(a) for a in ap.hardening_advice[:3])
                posture_lines.append(f"*Hardening Advice:* {advice_str}")
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": _truncate("\n".join(posture_lines), 3000)},
            })

        for d in self.alien_devices[:10]:
            dev_fields = [
                {"type": "mrkdwn", "text": _truncate(f"*Device:*\n{_escape_slack(d.display_name)}", 2000)},
                {"type": "mrkdwn", "text": _truncate(f"*IP:*\n`{_escape_code(d.ip)}`", 2000)},
                {"type": "mrkdwn", "text": _truncate(f"*MAC:*\n`{_escape_code(d.mac)}`", 2000)},
                {"type": "mrkdwn", "text": _truncate(f"*Vendor:*\n{_escape_slack(d.vendor)}", 2000)},
            ]
            if d.ai_assessment:
                ai = d.ai_assessment
                dev_fields.append({
                    "type": "mrkdwn",
                    "text": _truncate(
                        f"*AI Risk:*\n`{_escape_code(ai.risk_level)}` ({_escape_slack(ai.device_type)})",
                        2000,
                    ),
                })
                dev_fields.append({
                    "type": "mrkdwn",
                    "text": _truncate(f"*Advice:*\n{_escape_slack(ai.action_advice)}", 2000),
                })
            blocks.append({"type": "section", "fields": dev_fields[:10]})

        if self.threats:
            threats_lines = [
                f"• {_escape_slack(self.categorize_threat(t))}" for t in self.threats[:5]
            ]
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": _truncate("*Security Threats Detected:*\n" + "\n".join(threats_lines), 3000),
                },
            })

        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Detected at: {self.formatted_time}"}],
        })
        return blocks

    def to_dict(self) -> Dict[str, Any]:
        """Structured dictionary representation for generic JSON webhooks and SIEM ingestion."""
        payload: Dict[str, Any] = {
            "title": self.title,
            "is_report": self.is_report,
            "count": self.count,
            "timestamp": self.created_at,
            "formatted_time": self.formatted_time,
            "devices": [d.to_dict() for d in self.alien_devices],
            "threats": self.threats,
        }
        if self.audit_result is not None:
            audit = self.audit_result
            net = getattr(audit, "network", None)
            audit_summary: Dict[str, Any] = {
                "total_count": getattr(audit, "total_count", len(getattr(audit, "devices", []))),
                "trusted_count": getattr(audit, "trusted_count", 0),
                "alien_count": getattr(audit, "alien_count", 0),
                "network": {
                    "interface": getattr(net, "interface", "") if net else "",
                    "subnet_cidr": getattr(net, "subnet_cidr", "") if net else "",
                    "gateway_ip": getattr(net, "gateway_ip", None) if net else None,
                },
            }
            if getattr(audit, "ai_posture", None) and hasattr(audit.ai_posture, "to_dict"):
                audit_summary["ai_posture"] = audit.ai_posture.to_dict()
            payload["audit_summary"] = audit_summary
        return payload
