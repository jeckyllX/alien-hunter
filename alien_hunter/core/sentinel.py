"""
24/7 Sentinel Watchdog Daemon.
Runs continuous periodic audits and dispatches alerts across all configured notification hooks.
"""

import time
from typing import List, Set, Optional, Any
from ..reporting.console import Colors
from ..notifications.engine import NotificationEngine
from ..config import ConfigManager
from ..defenses.honey_port import HoneyPortListener
from ..defenses.syn_scan import SynScanDetector
from ..defenses.dns_tunneling import DnsTunnelingDetector
from .engine import DiscoveryEngine


class SentinelWatchdog:
    """Continuously monitors network state and dispatches alerts on new device intrusions."""

    def __init__(
        self,
        engine: DiscoveryEngine,
        notifier: NotificationEngine,
        config_mgr: ConfigManager,
        whitelist_path: Optional[str] = None,
        interval: int = 300,
        deep_scan: bool = False,
        interface: Optional[str] = None,
        ai_engine: Optional[Any] = None,
        honey_ports: Optional[List[int]] = None,
        syn_scan_enabled: bool = True,
        dns_tunneling_enabled: bool = True,
    ):
        self.engine = engine
        self.notifier = notifier
        self.config_mgr = config_mgr
        self.whitelist_path = whitelist_path
        self.interval = interval
        self.deep_scan = deep_scan
        self.interface = interface
        self.ai_engine = ai_engine
        self.known_alien_macs: Set[str] = set()
        self.honey_ports = honey_ports
        self.honey_listener: Optional[HoneyPortListener] = None
        self.syn_scan_enabled = syn_scan_enabled
        self.syn_detector: Optional[SynScanDetector] = None
        self.dns_tunneling_enabled = dns_tunneling_enabled
        self.dns_tunnel_detector: Optional[DnsTunnelingDetector] = None

    def start(self):
        """Starts the sentinel polling loop."""
        active_hooks = self.notifier.active_hook_count
        iface_str = f" on {self.interface}" if self.interface else ""
        ai_str = f" | AI: {self.ai_engine.provider.provider_label}" if self.ai_engine else ""
        print(
            f"{Colors.GREEN}[*] Alien Hunter Sentinel active{iface_str}{ai_str}.{Colors.RESET} "
            f"Polling every {self.interval}s. Active notification hooks: {active_hooks}. Press Ctrl+C to stop."
        )

        if self.honey_ports:
            self.honey_listener = HoneyPortListener(ports=self.honey_ports)
            bound = self.honey_listener.start()
            if bound:
                print(f"{Colors.GREEN}[+] Decoy Honey-Port Canary active on TCP ports: {', '.join(map(str, bound))}{Colors.RESET}")

        if self.syn_scan_enabled:
            self.syn_detector = SynScanDetector(interface=self.interface)
            if self.syn_detector.start():
                print(f"{Colors.GREEN}[+] Stealth TCP SYN Scan Detector active.{Colors.RESET}")

        if self.dns_tunneling_enabled:
            self.dns_tunnel_detector = DnsTunnelingDetector(interface=self.interface)
            if self.dns_tunnel_detector.start():
                print(f"{Colors.GREEN}[+] High-Entropy DNS Tunneling Detector active.{Colors.RESET}")

        try:
            while True:
                try:
                    # Reload whitelist dynamically in case user updated it
                    whitelist = self.config_mgr.load_whitelist(self.whitelist_path)
                    result = self.engine.run_audit(
                        whitelist=whitelist,
                        deep_scan=self.deep_scan,
                        passive_duration=2,
                        interface=self.interface,
                        ai_engine=self.ai_engine,
                    )
                    self.config_mgr.sync_device_inventory(
                        result.devices,
                        self.whitelist_path,
                        subnet_cidr=result.network.subnet_cidr if result.network else None,
                    )

                    # Check for honeypot intrusions
                    honey_threats = self.honey_listener.get_threat_strings() if self.honey_listener else []
                    if honey_threats:
                        for ht in honey_threats:
                            print(f"{Colors.BOLD}{Colors.RED}[!] {ht}{Colors.RESET}")

                    # Check for stealth SYN port scans
                    syn_threats = self.syn_detector.get_threat_strings() if self.syn_detector else []
                    if syn_threats:
                        for st in syn_threats:
                            print(f"{Colors.BOLD}{Colors.RED}[!] {st}{Colors.RESET}")

                    # Check for high-entropy DNS tunneling & exfiltration
                    dns_threats = self.dns_tunnel_detector.get_threat_strings() if self.dns_tunnel_detector else []
                    if dns_threats:
                        for dt in dns_threats:
                            print(f"{Colors.BOLD}{Colors.RED}[!] {dt}{Colors.RESET}")

                    combined_threats = result.threats + honey_threats + syn_threats + dns_threats
                    new_aliens = [
                        a for a in result.alien_devices if a.mac not in self.known_alien_macs
                    ]

                    if new_aliens or honey_threats or syn_threats or dns_threats:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        if new_aliens:
                            print(
                                f"\n{Colors.BOLD}{Colors.RED}[{timestamp}] [!] Unrecognized device(s) detected:{Colors.RESET}"
                            )
                            for a in new_aliens:
                                print(
                                    f"   {Colors.RED}• {a.ip:<15} {a.mac:<18} {a.vendor} ({a.display_name}){Colors.RESET}"
                                )
                                self.known_alien_macs.add(a.mac)

                        # Dispatch to all active notification hooks
                        dispatched = self.notifier.dispatch(new_aliens, combined_threats)
                        if dispatched:
                            success_hooks = [k for k, v in dispatched.items() if v]
                            if success_hooks:
                                print(f"{Colors.GREEN}[+] Alerts dispatched via: {', '.join(success_hooks)}{Colors.RESET}")
                            failed_hooks = [k for k, v in dispatched.items() if not v]
                            if failed_hooks:
                                print(f"{Colors.YELLOW}[!] Alerts failed on: {', '.join(failed_hooks)}{Colors.RESET}")

                    time.sleep(self.interval)

                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Sentinel audit iteration error: {e}{Colors.RESET}")
                    time.sleep(self.interval)

        except KeyboardInterrupt:
            print(f"\n{Colors.CYAN}[*] Alien Hunter Sentinel terminated by user.{Colors.RESET}")
        finally:
            if self.honey_listener:
                self.honey_listener.stop()
            if self.syn_detector:
                self.syn_detector.stop()
            if self.dns_tunnel_detector:
                self.dns_tunnel_detector.stop()
