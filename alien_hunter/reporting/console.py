"""
Console and Terminal Reporting for Alien Hunter.
Renders ANSI-colorized status tables, threat alerts, and interactive whitelisting prompts.
"""

from typing import List
from ..models import AuditResult, Device, NetworkInfo
from ..config import ConfigManager


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
        print(f"[*] Interface:       {Colors.BOLD}{net.interface}{Colors.RESET}")
        print(f"[*] Local Host:      {Colors.BOLD}{net.local_ip}{Colors.RESET} ({net.local_mac})")
        print(f"[*] Gateway:         {Colors.BOLD}{net.gateway_ip or 'Unknown'}{Colors.RESET} ({net.gateway_mac or 'Unknown'})")
        print(f"[*] Subnet:          {Colors.BOLD}{net.subnet_cidr}{Colors.RESET}")
        print(f"[*] Whitelist:       {whitelist_count} trusted device(s) loaded from {whitelist_path}\n")

    @staticmethod
    def render_table(devices: List[Device]):
        print(f"{Colors.BOLD}{'IP ADDRESS':<16} {'MAC ADDRESS':<18} {'STATUS':<18} {'DEVICE / NAME / VENDOR':<34} {'SECURITY':<10}{Colors.RESET}")
        print("-" * 102)

        for dev in devices:
            ip_str = dev.ip
            mac_str = dev.mac
            status_str = dev.status
            name_str = dev.display_name
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
                print(f"   {Colors.BLUE}└─ 🌐 Aliases: {', '.join(dev.aliases)}{Colors.RESET}")
            if dev.open_ports:
                print(f"   {Colors.CYAN}└─ Open Ports: {', '.join(dev.open_ports)}{Colors.RESET}")
            for n in dev.notes:
                print(f"   {Colors.BLUE}└─ ℹ️  {n}{Colors.RESET}")
            for t in dev.threats:
                print(f"   {Colors.YELLOW}└─ ⚠️  {t}{Colors.RESET}")
            if dev.ai_assessment:

                ai = dev.ai_assessment
                print(f"   {Colors.MAGENTA}└─ 🤖 AI Profile: [{ai.risk_level}] {ai.device_type} - {ai.summary}{Colors.RESET}")
                print(f"      {Colors.MAGENTA}Recommendation: {ai.whitelist_recommendation} -> {ai.action_advice}{Colors.RESET}")

    @staticmethod
    def render_summary(result: AuditResult):
        print(f"\n{Colors.BOLD}{Colors.CYAN}============================= AUDIT SUMMARY ============================={Colors.RESET}")
        print(f"Total Network Devices Cataloged: {result.total_count}")
        print(f"Verified Trusted Devices:        {result.trusted_count}")

        if result.alien_devices:
            print(f"\n{Colors.BOLD}{Colors.RED}[!] Unrecognized device(s) detected ({result.alien_count}):{Colors.RESET}")
            for a in result.alien_devices:
                print(f"   {Colors.RED}• IP: {a.ip:<15} MAC: {a.mac} ({a.vendor}) Name: {a.display_name}{Colors.RESET}")
                if a.ai_assessment:
                    ai = a.ai_assessment
                    print(f"     {Colors.MAGENTA}AI Risk: [{ai.risk_level}] {ai.summary}{Colors.RESET}")
                    print(f"     {Colors.MAGENTA}Action: {ai.whitelist_recommendation} ({ai.action_advice}){Colors.RESET}")
        else:
            print(f"\n{Colors.BOLD}{Colors.GREEN}[✓] All active devices match whitelist.{Colors.RESET}")

        if result.threats:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}[!] Potential security threats detected ({len(result.threats)}):{Colors.RESET}")
            for th in result.threats:
                print(f"   {Colors.YELLOW}• {th}{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}[✓] No critical service vulnerabilities or spoofing detected.{Colors.RESET}")

        if result.ai_posture:
            ap = result.ai_posture
            color = Colors.GREEN if ap.posture == "SECURE" else (Colors.RED if ap.posture == "CRITICAL" else Colors.YELLOW)
            print(f"\n{Colors.BOLD}{color}AI Network Posture: [{ap.posture}]{Colors.RESET}")
            print(f"   {color}{ap.summary}{Colors.RESET}")
            if ap.threats_found:
                print(f"   {Colors.YELLOW}Threats Highlighted:{Colors.RESET}")
                for tf in ap.threats_found:
                    print(f"     • {tf}")
            if ap.hardening_advice:
                print(f"   {Colors.CYAN}Hardening Recommendations:{Colors.RESET}")
                for ha in ap.hardening_advice:
                    print(f"     ✔ {ha}")

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
        modified = False

        for a in alien_devices:
            resp = input(f"Trust {a.ip} - {a.mac} ({a.vendor} / {a.hostname})? [y/N]: ").strip().lower()
            if resp == "y":
                dev_name = input("Enter friendly name: ").strip() or a.hostname
                current_whitelist[a.mac.upper()] = {
                    "name": dev_name,
                    "owner": "User",
                    "trusted": True,
                }
                modified = True

        if modified:
            if config_mgr.save_whitelist(current_whitelist, whitelist_path):
                print(f"{Colors.GREEN}[+] Whitelist updated successfully at {whitelist_path}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[-] Failed to save whitelist.{Colors.RESET}")
