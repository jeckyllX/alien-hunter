"""
Command-Line Interface for Alien Hunter.
Parses CLI arguments, elevates permissions if necessary, and drives execution.
"""

import argparse
import json
import os
import sys

from . import __version__
from .config import ConfigManager
from .core.engine import DiscoveryEngine
from .core.sentinel import SentinelWatchdog
from .reporting.console import ConsoleReporter, Colors
from .notifications.engine import NotificationEngine
from .ai.engine import AIEngine


def ensure_root():
    """Ensures root privileges for Layer-2 raw packet and ARP scanning."""
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[!] Alien Hunter requires root privileges for Layer-2 ARP and raw packet inspection.{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Elevating with sudo...{Colors.RESET}")
        try:
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            print(f"{Colors.RED}[-] Failed to elevate with sudo: {e}{Colors.RESET}")
            sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alien-hunter",
        description="Alien Hunter - LAN Security Auditor & Rogue Device Hunter",
    )
    parser.add_argument("-v", "--version", action="version", version=f"Alien Hunter v{__version__}")
    parser.add_argument("--whitelist-file", type=str, default="", help="Custom path to known_devices.json whitelist")
    parser.add_argument("--config-file", type=str, default="", help="Custom path to config.json")
    parser.add_argument("--events-file", type=str, default="", help="Custom path to events.jsonl audit log")
    parser.add_argument("-i", "--interface", type=str, default="", help="Network interface to scan (default: auto-detected)")
    parser.add_argument("--deep", action="store_true", help="Perform deep port and vulnerability scanning on all hosts")
    parser.add_argument("--whitelist", action="store_true", help="Interactively add newly detected alien devices to whitelist")
    parser.add_argument("--json", action="store_true", help="Output results in machine-readable JSON format")
    parser.add_argument("-w", "--watch", action="store_true", help="Run in continuous sentinel / daemon mode")
    parser.add_argument("--interval", type=int, default=300, help="Interval in seconds for watch mode (default: 300)")
    parser.add_argument("--web", action="store_true", help="Launch web dashboard and REST API")
    parser.add_argument("--web-port", type=int, default=None, help="Port for the web dashboard (default: 8080)")
    parser.add_argument("--web-host", type=str, default=None, help="Host/IP to bind the web dashboard (default: 0.0.0.0)")
    parser.add_argument("--test-notify", action="store_true", help="Send a simulated test alert through configured notification hooks")
    parser.add_argument("--notify", action="store_true", help="Dispatch scan findings & AI posture notification even if no alien devices are found")
    parser.add_argument("--sync-db", action="store_true", help="Sync observed device telemetry (aliases, discovery methods, ports, services) into known_devices.json")
    parser.add_argument("--no-sync-db", action="store_true", help="Disable automated database updates")
    parser.add_argument("--ai", action="store_true", help="Enable AI device profiling and risk assessment")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI device profiling")
    parser.add_argument("--test-ai", action="store_true", help="Test the configured AI provider with a simulated alien device")
    parser.add_argument("--update-signatures", action="store_true", help="Download and synchronize the latest device signatures feed")
    parser.add_argument("--force-sync", action="store_true", help="Force signature synchronization bypassing 24h interval check")
    parser.add_argument("--set-ai-provider", type=str, metavar="NAME", help="Switch active AI provider in config.json (e.g. ollama, openrouter, groq)")
    parser.add_argument("--ai-provider", type=str, metavar="NAME", help="Temporarily override AI provider for this run")
    return parser



def main():
    parser = build_parser()
    args = parser.parse_args()

    if (
        not args.test_notify
        and not args.test_ai
        and not args.update_signatures
        and not args.set_ai_provider
    ):
        ensure_root()

    if args.set_ai_provider:
        target_provider = args.set_ai_provider.strip().lower()
        valid_providers = sorted(set(AIEngine.PROVIDER_REGISTRY.keys()))
        if target_provider not in valid_providers:
            print(f"{Colors.RED}[-] Unknown AI provider '{target_provider}'. Valid choices: {', '.join(valid_providers)}{Colors.RESET}")
            sys.exit(1)

        config_mgr = ConfigManager()
        config_path = config_mgr.resolve_path("config.json", args.config_file)
        config = config_mgr.load_config(config_path)
        if "ai_analysis" not in config or not isinstance(config["ai_analysis"], dict):
            config["ai_analysis"] = {"enabled": True}
        config["ai_analysis"]["provider"] = target_provider
        if not config_mgr.save_config(config, config_path):
            print(f"{Colors.RED}[-] Failed to write updated configuration to {config_path}. Check file permissions.{Colors.RESET}")
            sys.exit(1)

        print(f"{Colors.GREEN}[+] Active AI provider set to '{target_provider}' in {config_path}{Colors.RESET}")

        import subprocess
        try:
            res = subprocess.run(["systemctl", "is-active", "--quiet", "alien-hunter.service"])
            if res.returncode == 0:
                print(f"{Colors.CYAN}[*] Restarting alien-hunter.service...{Colors.RESET}")
                subprocess.run(["sudo", "systemctl", "restart", "alien-hunter.service"], check=False)
                print(f"{Colors.GREEN}[+] Service restarted successfully.{Colors.RESET}")
        except Exception:
            pass
        sys.exit(0)

    if args.update_signatures:
        from .identifiers.sync import SignatureSyncEngine
        print(f"{Colors.CYAN}[*] Synchronizing device fingerprint signatures...{Colors.RESET}")
        sync_engine = SignatureSyncEngine()
        success, msg = sync_engine.sync(force=args.force_sync)
        if success:
            print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
            sys.exit(0)
        else:
            print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
            sys.exit(1)

    selected_interface = args.interface.strip() if args.interface else None

    config_mgr = ConfigManager()
    whitelist_path = config_mgr.resolve_path("known_devices.json", args.whitelist_file)
    config_path = config_mgr.resolve_path("config.json", args.config_file)
    events_path = config_mgr.resolve_path("events.jsonl", args.events_file)

    whitelist = config_mgr.load_whitelist(whitelist_path)
    config = config_mgr.load_config(config_path)

    engine = DiscoveryEngine(
        mac_api_url=config.get("mac_lookup_api_url"),
        mac_api_timeout=config.get("mac_lookup_timeout"),
    )
    notifier = NotificationEngine.from_config(config)

    ai_engine = None
    ai_cfg = config.get("ai_analysis", {})
    ai_enabled = ai_cfg.get("enabled", False)
    if args.ai:
        ai_enabled = True
    elif args.no_ai:
        ai_enabled = False

    if args.ai_provider:
        target_provider = args.ai_provider.strip().lower()
        valid_providers = sorted(set(AIEngine.PROVIDER_REGISTRY.keys()))
        if target_provider not in valid_providers:
            print(f"{Colors.RED}[-] Unknown AI provider '{target_provider}'. Valid choices: {', '.join(valid_providers)}{Colors.RESET}")
            sys.exit(1)
        ai_cfg["provider"] = target_provider

    if ai_enabled or args.test_ai:
        ai_cfg["enabled"] = True
        config["ai_analysis"] = ai_cfg
        ai_engine = AIEngine.from_config(config)

    if args.test_ai:
        if not ai_engine:
            print(f"{Colors.YELLOW}[!] AI analysis is not configured in {config_path}{Colors.RESET}")
            print(f"    Please check the 'ai_analysis' block in your config.json.")
            return

        from .models import Device
        test_device = Device(
            ip="192.168.1.150",
            mac="50:02:91:AA:BB:CC",
            hostname="LivingRoomCam",
            vendor="Tuya Inc.",
            open_ports=["80/HTTP", "554/RTSP", "23/Telnet"],
            threats=["Unencrypted legacy remote shell (Telnet)"],
            is_alien=True,
        )
        print(f"{Colors.CYAN}[*] Testing AI Provider: {ai_engine.provider.provider_label} ({ai_engine.provider.endpoint})...{Colors.RESET}")
        assessment = ai_engine.analyze_device(test_device)
        if assessment:
            print(f"{Colors.GREEN}[✔] Device Assessment successful!{Colors.RESET}")
            print(f"    • Device Type:    {assessment.device_type}")
            print(f"    • Risk Level:     {assessment.risk_level}")
            print(f"    • Summary:        {assessment.summary}")
            print(f"    • Recommendation: {assessment.whitelist_recommendation}")
            print(f"    • Action Advice:  {assessment.action_advice}")
        else:
            print(f"{Colors.RED}[✘] Device assessment failed. Please check provider endpoint, model, or credentials.{Colors.RESET}")

        from .models import NetworkInfo, AuditResult
        mock_net = NetworkInfo(interface="test0", local_ip="192.168.1.50", local_mac="00:11:22:33:44:55", subnet_base="192.168.1", gateway_ip="192.168.1.1")
        mock_audit = AuditResult(timestamp=0, network=mock_net, devices=[test_device], alien_devices=[test_device], threats=["Unencrypted legacy remote shell (Telnet) on 192.168.1.150"])
        print(f"\n{Colors.CYAN}[*] Testing Network Posture Assessment...{Colors.RESET}")
        posture = ai_engine.analyze_network(mock_audit)
        if posture:
            print(f"{Colors.GREEN}[✔] Network Posture Assessment successful!{Colors.RESET}")
            print(f"    • Network Posture: {posture.posture}")
            print(f"    • Summary:         {posture.summary}")
            if posture.threats_found:
                print(f"    • Threats:         {', '.join(posture.threats_found)}")
            if posture.hardening_advice:
                print(f"    • Hardening:       {', '.join(posture.hardening_advice)}")
        else:
            print(f"{Colors.RED}[✘] Network posture assessment failed.{Colors.RESET}")
        return

    if args.test_notify:
        if notifier.active_hook_count == 0:
            print(f"{Colors.YELLOW}[!] No notification hooks are enabled in {config_path}{Colors.RESET}")
            print(f"    Please enable 'telegram' in config.json and provide bot_token and chat_id.")
            return

        from .models import Device
        test_device = Device(
            ip="192.168.1.250",
            mac="00:1A:2B:3C:4D:5E",
            hostname="SmartCam-77",
            vendor="Tuya / ShenZhen Bilian",
            friendly_name="Test Simulation Alien Device",
            status="Online / Active",
            open_ports=["80/HTTP", "554/RTSP", "23/Telnet"],
            threats=["Legacy unencrypted remote management (Telnet)"],
            notes=["Web Title: 'IP Camera Login'"],
            is_alien=True,
        )

        simulation_threats = ["Simulation: Test intrusion notification"]
        if ai_engine:
            print(f"{Colors.CYAN}[*] Profiling simulated alien device with AI ({ai_engine.provider.provider_label})...{Colors.RESET}")
            assessment = ai_engine.analyze_device(test_device, threats=simulation_threats)
            if assessment:
                print(f"{Colors.GREEN}[✔] AI Assessment generated: [{assessment.risk_level}] {assessment.device_type}{Colors.RESET}")
                print(f"    • Summary: {assessment.summary}")
                print(f"    • Advice:  {assessment.action_advice}")

        print(f"{Colors.CYAN}[*] Sending test alert to {notifier.active_hook_count} active hook(s)...{Colors.RESET}")
        dispatched = notifier.dispatch([test_device], threats=simulation_threats)
        for hook_name, success in dispatched.items():
            if success:
                print(f"{Colors.GREEN}[✔] {hook_name.capitalize()}: Alert delivered successfully!{Colors.RESET}")
            else:
                print(f"{Colors.RED}[✘] {hook_name.capitalize()}: Delivery failed. Please check credentials or network connectivity.{Colors.RESET}")
        return


    should_sync = (args.sync_db or config.get("auto_sync_database", True)) and not args.no_sync_db

    web_cfg = config.get("web_ui", {})
    web_enabled = bool(args.web or web_cfg.get("enabled", False))
    web_port = args.web_port if args.web_port is not None else int(web_cfg.get("port", 8080))
    web_host = args.web_host if args.web_host is not None else str(web_cfg.get("host", "0.0.0.0"))

    if args.watch or args.web:
        defenses_cfg = config.get("defenses", {})
        honey_ports = defenses_cfg.get("honey_ports", [5555, 2323, 8888]) if defenses_cfg.get("honey_port_enabled", True) else None
        syn_scan_enabled = defenses_cfg.get("syn_scan_enabled", True)
        dns_tunneling_enabled = defenses_cfg.get("dns_tunneling_enabled", True)
        dhcp_starvation_enabled = defenses_cfg.get("dhcp_starvation_enabled", True)
        arp_poison_enabled = defenses_cfg.get("arp_poison_enabled", True)
        icmp_redirect_enabled = defenses_cfg.get("icmp_redirect_enabled", True)
        sentinel = SentinelWatchdog(
            engine=engine,
            notifier=notifier,
            config_mgr=config_mgr,
            whitelist_path=whitelist_path,
            events_path=events_path,
            interval=args.interval,
            deep_scan=args.deep,
            interface=selected_interface,
            ai_engine=ai_engine,
            honey_ports=honey_ports,
            syn_scan_enabled=syn_scan_enabled,
            dns_tunneling_enabled=dns_tunneling_enabled,
            dhcp_starvation_enabled=dhcp_starvation_enabled,
            arp_poison_enabled=arp_poison_enabled,
            icmp_redirect_enabled=icmp_redirect_enabled,
            sync_db=should_sync,
            web_enabled=web_enabled,
            web_host=web_host,
            web_port=web_port,
        )
        sentinel.start()
        return

    # Standard Audit Mode
    if not args.json:
        ConsoleReporter.render_banner(__version__)
        net_info = engine.get_network_info(interface=selected_interface)
        ConsoleReporter.render_network_info(net_info, len(whitelist), whitelist_path)

    result = engine.run_audit(
        whitelist=whitelist,
        deep_scan=args.deep,
        passive_duration=3,
        interface=selected_interface,
        ai_engine=ai_engine,
    )

    # Automatically persist observed metadata (aliases, discovery methods, services, ports) into known_devices.json
    if should_sync:
        config_mgr.sync_device_inventory(
            result.devices,
            whitelist_path,
            subnet_cidr=result.network.subnet_cidr if result.network else None,
        )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    ConsoleReporter.render_table(result.devices)
    ConsoleReporter.render_summary(result)

    # Dispatch alerts to active notification hooks if alien devices or threats exist, or if --notify was requested
    should_notify = bool(result.alien_devices) or bool(result.threats) or args.notify
    if should_notify and notifier.active_hook_count > 0:
        print(f"\n{Colors.CYAN}[*] Dispatching notification to {notifier.active_hook_count} active hook(s)...{Colors.RESET}")
        dispatched = notifier.dispatch(
            result.alien_devices,
            threats=result.threats,
            audit_result=result,
        )
        success_hooks = [k for k, v in dispatched.items() if v]
        if success_hooks:
            print(f"{Colors.GREEN}[✔] Notification dispatched via: {', '.join(success_hooks)}{Colors.RESET}")
        else:
            print(f"{Colors.RED}[✘] Failed to dispatch notifications via active hooks.{Colors.RESET}")

    if args.whitelist and result.alien_devices:

        ConsoleReporter.prompt_whitelist(
            result.alien_devices, config_mgr, whitelist_path, whitelist
        )


if __name__ == "__main__":
    main()
