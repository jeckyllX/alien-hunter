"""
Console and Terminal Reporting for Alien Hunter.
Renders ANSI-colorized status tables, threat alerts, and interactive whitelisting prompts.
"""

import re
from typing import Any, List
from ..models import AuditResult, Device, NetworkInfo
from ..config import ConfigManager

_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_ESC_RE = re.compile(r"\x1b[@-Z\\-_]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]+")
_VALID_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _sanitize_terminal_text(value: Any) -> str:
    """Strips ANSI escape sequences and C0/C1 control characters from untrusted strings."""
    if value is None:
        return ""
    s = str(value)
    s = _ANSI_OSC_RE.sub("", s)
    s = _ANSI_CSI_RE.sub("", s)
    s = _ANSI_ESC_RE.sub("", s)
    s = _CONTROL_CHARS_RE.sub(" ", s)
    return s.strip()


class Colors:
    """ANSI color escape sequences."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


class ConsoleReporter:
    """Renders formatted visual scan outputs to the terminal."""

    @staticmethod
    def render_banner(version: str):
        print(f"\n{Colors.BOLD}{Colors.CYAN}========================================================================{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}            ALIEN HUNTER v{version}: LAN SECURITY AUDITOR                {Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}========================================================================{Colors.RESET}\n")

    @staticmethod
    def render_network_info(net: NetworkInfo, whitelist_count: int, whitelist_path: str):
        print(f"[*] Interface:       {Colors.BOLD}{_sanitize_terminal_text(net.interface)}{Colors.RESET}")
        print(
            f"[*] Local Host:      {Colors.BOLD}{_sanitize_terminal_text(net.local_ip)}{Colors.RESET} "
            f"({_sanitize_terminal_text(net.local_mac)})"
        )
        print(
            f"[*] Gateway:         {Colors.BOLD}{_sanitize_terminal_text(net.gateway_ip or 'Unknown')}{Colors.RESET} "
            f"({_sanitize_terminal_text(net.gateway_mac or 'Unknown')})"
        )
        print(f"[*] Subnet:          {Colors.BOLD}{_sanitize_terminal_text(net.subnet_cidr)}{Colors.RESET}")
        print(f"[*] Whitelist:       {whitelist_count} trusted device(s) loaded from {whitelist_path}\n")

    @staticmethod
    def render_table(devices: List[Device]):
        print(f"{Colors.BOLD}{'IP ADDRESS':<16} {'MAC ADDRESS':<18} {'STATUS':<18} {'DEVICE / NAME / VENDOR':<34} {'SECURITY':<10}{Colors.RESET}")
        print("-" * 102)

        for dev in devices:
            ip_str = _sanitize_terminal_text(dev.ip)
            mac_str = _sanitize_terminal_text(dev.mac)
            status_str = _sanitize_terminal_text(dev.status)
            name_str = _sanitize_terminal_text(dev.display_name)
            if len(name_str) > 33:
                name_str = name_str[:31] + ".."

            if dev.is_alien:
                badge = f"{Colors.BOLD}{Colors.RED}ALIEN{Colors.RESET}"
                color = Colors.RED
            elif not dev.trusted:
                badge = f"{Colors.YELLOW}UNVERIFIED{Colors.RESET}"
                color = Colors.YELLOW
            else:
                badge = f"{Colors.GREEN}TRUSTED{Colors.RESET}"
                color = Colors.RESET

            print(f"{color}{ip_str:<16} {mac_str:<18} {status_str:<18} {name_str:<34}{Colors.RESET} {badge}")

            if getattr(dev, "aliases", None):
                aliases = ", ".join(_sanitize_terminal_text(a) for a in dev.aliases)
                print(f"   {Colors.BLUE}└─ 🌐 Aliases: {aliases}{Colors.RESET}")
            if dev.open_ports:
                ports = ", ".join(_sanitize_terminal_text(p) for p in dev.open_ports)
                print(f"   {Colors.CYAN}└─ Open Ports: {ports}{Colors.RESET}")
            for n in dev.notes:
                print(f"   {Colors.BLUE}└─ ℹ️  {_sanitize_terminal_text(n)}{Colors.RESET}")
            for t in dev.threats:
                print(f"   {Colors.YELLOW}└─ ⚠️  {_sanitize_terminal_text(t)}{Colors.RESET}")
            if dev.ai_assessment:
                ai = dev.ai_assessment
                print(
                    f"   {Colors.MAGENTA}└─ 🤖 AI Profile: [{_sanitize_terminal_text(ai.risk_level)}] "
                    f"{_sanitize_terminal_text(ai.device_type)} - {_sanitize_terminal_text(ai.summary)}{Colors.RESET}"
                )
                if getattr(ai, "vulnerabilities", None):
                    vulns = "; ".join(_sanitize_terminal_text(v) for v in ai.vulnerabilities)
                    print(f"      {Colors.RED}└─ 🛡️ Vulnerabilities: {vulns}{Colors.RESET}")
                print(
                    f"      {Colors.MAGENTA}Recommendation: {_sanitize_terminal_text(ai.whitelist_recommendation)} -> "
                    f"{_sanitize_terminal_text(ai.action_advice)}{Colors.RESET}"
                )

    @staticmethod
    def render_summary(result: AuditResult):
        print(f"\n{Colors.BOLD}{Colors.CYAN}============================= AUDIT SUMMARY ============================={Colors.RESET}")
        print(f"Total Network Devices Cataloged: {result.total_count}")
        print(f"Verified Trusted Devices:        {result.trusted_count}")

        if result.alien_devices:
            print(f"\n{Colors.BOLD}{Colors.RED}[!] Unrecognized device(s) detected ({result.alien_count}):{Colors.RESET}")
            for a in result.alien_devices:
                print(
                    f"   {Colors.RED}• IP: {_sanitize_terminal_text(a.ip):<15} "
                    f"MAC: {_sanitize_terminal_text(a.mac)} ({_sanitize_terminal_text(a.vendor)}) "
                    f"Name: {_sanitize_terminal_text(a.display_name)}{Colors.RESET}"
                )
                if a.ai_assessment:
                    ai = a.ai_assessment
                    print(
                        f"     {Colors.MAGENTA}AI Risk: [{_sanitize_terminal_text(ai.risk_level)}] "
                        f"{_sanitize_terminal_text(ai.summary)}{Colors.RESET}"
                    )
                    if getattr(ai, "vulnerabilities", None):
                        vulns = "; ".join(_sanitize_terminal_text(v) for v in ai.vulnerabilities)
                        print(f"     {Colors.RED}Vulnerabilities: {vulns}{Colors.RESET}")
                    print(
                        f"     {Colors.MAGENTA}Action: {_sanitize_terminal_text(ai.whitelist_recommendation)} "
                        f"({_sanitize_terminal_text(ai.action_advice)}){Colors.RESET}"
                    )
        else:
            print(f"\n{Colors.BOLD}{Colors.GREEN}[✓] All active devices match whitelist.{Colors.RESET}")

        if result.threats:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}[!] Potential security threats detected ({len(result.threats)}):{Colors.RESET}")
            for th in result.threats:
                print(f"   {Colors.YELLOW}• {_sanitize_terminal_text(th)}{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}[✓] No critical service vulnerabilities or spoofing detected.{Colors.RESET}")

        if result.ai_posture:
            ap = result.ai_posture
            color = Colors.GREEN if ap.posture == "SECURE" else (Colors.RED if ap.posture == "CRITICAL" else Colors.YELLOW)
            print(f"\n{Colors.BOLD}{color}AI Network Posture: [{_sanitize_terminal_text(ap.posture)}]{Colors.RESET}")
            print(f"   {color}{_sanitize_terminal_text(ap.summary)}{Colors.RESET}")

            blast = getattr(ap, "blast_radius_summary", "")
            if blast:
                print(f"\n   {Colors.BOLD}{Colors.YELLOW}💥 Blast Radius Assessment:{Colors.RESET}")
                print(f"   {Colors.YELLOW}{_sanitize_terminal_text(blast)}{Colors.RESET}")

            seg_risks = getattr(ap, "segmentation_risks", [])
            if seg_risks:
                print(f"\n   {Colors.BOLD}{Colors.YELLOW}⚡ Topology & Segmentation Risks:{Colors.RESET}")
                for sr in seg_risks:
                    print(f"     • {_sanitize_terminal_text(sr)}")

            paths = getattr(ap, "attack_paths", [])
            if paths:
                print(f"\n   {Colors.BOLD}{Colors.MAGENTA}🎯 Lateral Movement & Attack Paths:{Colors.RESET}")
                for p in paths:
                    sev = _sanitize_terminal_text(
                        getattr(p, "severity", "MEDIUM") if hasattr(p, "severity") else p.get("severity", "MEDIUM")
                    )
                    ep = _sanitize_terminal_text(
                        getattr(p, "entry_point", "") if hasattr(p, "entry_point") else p.get("entry_point", "")
                    )
                    tgt = _sanitize_terminal_text(
                        getattr(p, "target", "") if hasattr(p, "target") else p.get("target", "")
                    )
                    vec = _sanitize_terminal_text(
                        getattr(p, "vector", "") if hasattr(p, "vector") else p.get("vector", "")
                    )
                    mit = _sanitize_terminal_text(
                        getattr(p, "mitigation", "") if hasattr(p, "mitigation") else p.get("mitigation", "")
                    )
                    sev_color = Colors.RED if sev in ("HIGH", "CRITICAL") else Colors.YELLOW
                    print(f"     {sev_color}[{sev}]{Colors.RESET} {Colors.BOLD}{ep} ➔ {tgt}{Colors.RESET}")
                    if vec:
                        print(f"        Vector:     {vec}")
                    if mit:
                        print(f"        Mitigation: {mit}")

            if ap.threats_found:
                print(f"\n   {Colors.YELLOW}Threats Highlighted:{Colors.RESET}")
                for tf in ap.threats_found:
                    print(f"     • {_sanitize_terminal_text(tf)}")
            if ap.hardening_advice:
                print(f"\n   {Colors.CYAN}Hardening Recommendations:{Colors.RESET}")
                for ha in ap.hardening_advice:
                    print(f"     ✔ {_sanitize_terminal_text(ha)}")

        print(f"{Colors.BOLD}{Colors.CYAN}========================================================================{Colors.RESET}\n")

    @staticmethod
    def prompt_whitelist(
        alien_devices: List[Device],
        config_mgr: ConfigManager,
        whitelist_path: str,
        current_whitelist: dict,
    ):
        """Interactively prompts the user to trust newly detected alien devices."""
        if not alien_devices:
            return

        print(f"{Colors.CYAN}[?] Interactive Whitelisting Mode:{Colors.RESET}")
        updated_count = 0

        for a in alien_devices:
            mac_clean = _sanitize_terminal_text(a.mac).upper()
            if not _VALID_MAC_RE.match(mac_clean):
                continue

            ip_safe = _sanitize_terminal_text(a.ip)
            vendor_safe = _sanitize_terminal_text(a.vendor)
            host_safe = _sanitize_terminal_text(a.hostname)
            try:
                resp = input(
                    f"Trust {ip_safe} - {mac_clean} ({vendor_safe} / {host_safe})? [y/N]: "
                ).strip().lower()
                if resp == "y":
                    dev_name = _sanitize_terminal_text(input("Enter friendly name: ")) or host_safe
                    if hasattr(config_mgr, "update_whitelist_entry"):
                        updated_entry = config_mgr.update_whitelist_entry(
                            mac_clean,
                            lambda existing: {
                                **(existing or {}),
                                "name": dev_name,
                                "owner": (existing or {}).get("owner", "User"),
                                "trusted": True,
                            },
                            custom_path=whitelist_path,
                        )
                        current_whitelist[mac_clean] = updated_entry
                    else:
                        current_whitelist[mac_clean] = {
                            "name": dev_name,
                            "owner": "User",
                            "trusted": True,
                        }
                        if not config_mgr.save_whitelist(current_whitelist, whitelist_path):
                            raise OSError("Failed to persist whitelist")
                    updated_count += 1
            except (EOFError, KeyboardInterrupt):
                print()
                break
            except Exception as e:
                print(f"{Colors.RED}[-] Failed to save whitelist entry for {mac_clean}: {e}{Colors.RESET}")

        if updated_count > 0:
            print(f"{Colors.GREEN}[+] Whitelist updated ({updated_count} device(s)) at {whitelist_path}{Colors.RESET}")
