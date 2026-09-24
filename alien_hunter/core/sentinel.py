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
from ..defenses.dhcp_starvation import DhcpStarvationGuard
from ..defenses.arp_poison import ArpPoisonGuard
from ..web.state import SentinelState
from ..web.server import LightweightWebServer
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
        dhcp_starvation_enabled: bool = True,
        arp_poison_enabled: bool = True,
        sync_db: bool = True,
        web_enabled: bool = False,
        web_host: str = "0.0.0.0",
        web_port: int = 8080,
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
        self.dhcp_starvation_enabled = dhcp_starvation_enabled
        self.dhcp_guard: Optional[DhcpStarvationGuard] = None
        self.arp_poison_enabled = arp_poison_enabled
        self.arp_guard: Optional[ArpPoisonGuard] = None
        self.sync_db = sync_db
        self.web_enabled = web_enabled
        self.web_host = web_host
        self.web_port = web_port
        self.web_state = SentinelState(interval=interval)
        self.web_server: Optional[LightweightWebServer] = None

        if self.whitelist_path:
            try:
                initial_wl = self.config_mgr.load_whitelist(self.whitelist_path)
                self.web_state.initialize_from_whitelist(initial_wl)
            except Exception:
                pass

    def start(self):
        """Starts the sentinel polling loop."""
        active_hooks = self.notifier.active_hook_count
        iface_str = f" on {self.interface}" if self.interface else ""
        ai_str = f" | AI: {self.ai_engine.provider.provider_label}" if self.ai_engine else ""
        print(
            f"{Colors.GREEN}[*] Alien Hunter Sentinel active{iface_str}{ai_str}.{Colors.RESET} "
            f"Polling every {self.interval}s. Active notification hooks: {active_hooks}. Press Ctrl+C to stop."
        )

        net_info = None
        if self.engine:
            try:
                net_info = self.engine.get_network_info(interface=self.interface)
            except Exception:
                pass

        local_ip = net_info.local_ip if net_info else None
        local_mac = net_info.local_mac if net_info else None
        subnet_cidr = net_info.subnet_cidr if net_info else None
        gateway_ip = net_info.gateway_ip if net_info else None
        gateway_mac = net_info.gateway_mac if net_info else None

        if self.honey_ports:
            self.honey_listener = HoneyPortListener(ports=self.honey_ports)
            bound = self.honey_listener.start()
            if bound:
                print(f"{Colors.GREEN}[+] Decoy Honey-Port Canary active on TCP ports: {', '.join(map(str, bound))}{Colors.RESET}")

        if self.syn_scan_enabled:
            self.syn_detector = SynScanDetector(
                interface=self.interface,
                subnet_cidr=subnet_cidr,
                local_ip=local_ip,
                local_mac=local_mac,
            )
            if self.syn_detector.start():
                print(f"{Colors.GREEN}[+] Stealth TCP SYN Scan Detector active.{Colors.RESET}")

        if self.dns_tunneling_enabled:
            self.dns_tunnel_detector = DnsTunnelingDetector(
                interface=self.interface,
                subnet_cidr=subnet_cidr,
                local_ip=local_ip,
                local_mac=local_mac,
            )
            if self.dns_tunnel_detector.start():
                print(f"{Colors.GREEN}[+] High-Entropy DNS Tunneling Detector active.{Colors.RESET}")

        if self.dhcp_starvation_enabled:
            self.dhcp_guard = DhcpStarvationGuard(interface=self.interface)
            if self.dhcp_guard.start():
                print(f"{Colors.GREEN}[+] DHCP Starvation & Pool Exhaustion Guard active.{Colors.RESET}")

        if self.arp_poison_enabled:
            self.arp_guard = ArpPoisonGuard(
                interface=self.interface,
                gateway_ip=gateway_ip,
                gateway_mac=gateway_mac,
            )
            if self.arp_guard.start():
                print(f"{Colors.GREEN}[+] Real-Time ARP Poisoning & Gateway Masquerade Guard active.{Colors.RESET}")

        if self.web_enabled:
            self.web_server = LightweightWebServer(
                state=self.web_state,
                config_mgr=self.config_mgr,
                whitelist_path=self.whitelist_path,
                host=self.web_host,
                port=self.web_port,
            )
            if self.web_server.start():
                print(f"{Colors.GREEN}[+] Web Dashboard active at http://{self.web_host}:{self.web_port}{Colors.RESET}")

        if self.web_state:
            if net_info:
                self.web_state.network_info = {
                    "interface": getattr(net_info, "interface", ""),
                    "local_ip": getattr(net_info, "local_ip", ""),
                    "local_mac": getattr(net_info, "local_mac", ""),
                    "gateway_ip": getattr(net_info, "gateway_ip", ""),
                    "gateway_mac": getattr(net_info, "gateway_mac", ""),
                    "subnet_cidr": getattr(net_info, "subnet_cidr", ""),
                }
            self.web_state.active_defenses = {
                "honey_ports": bool(self.honey_listener),
                "syn_scan": bool(self.syn_detector),
                "dns_tunneling": bool(self.dns_tunnel_detector),
                "dhcp_starvation": bool(self.dhcp_guard),
                "arp_poison": bool(self.arp_guard),
            }

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
                    if self.sync_db:
                        self.config_mgr.sync_device_inventory(
                            result.devices,
                            self.whitelist_path,
                            subnet_cidr=result.network.subnet_cidr if result.network else None,
                        )

                    # Update defense modules with current local identity and network baseline
                    if result.network:
                        if self.syn_detector:
                            if result.network.local_ip:
                                self.syn_detector.local_ip = result.network.local_ip
                            if result.network.local_mac:
                                self.syn_detector.local_mac = result.network.local_mac.upper()
                        if self.dns_tunnel_detector:
                            if result.network.local_ip:
                                self.dns_tunnel_detector.local_ip = result.network.local_ip
                            if result.network.local_mac:
                                self.dns_tunnel_detector.local_mac = result.network.local_mac.upper()

                        if self.arp_guard:
                            trusted_map = {
                                d.ip: d.mac for d in result.devices if d.mac and d.trusted
                            }
                            self.arp_guard.update_topology(
                                gateway_ip=result.network.gateway_ip,
                                gateway_mac=result.network.gateway_mac,
                                trusted_ip_mac_map=trusted_map,
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

                    # Check for DHCP starvation floods
                    dhcp_threats = self.dhcp_guard.get_threat_strings() if self.dhcp_guard else []
                    if dhcp_threats:
                        for dht in dhcp_threats:
                            print(f"{Colors.BOLD}{Colors.RED}[!] {dht}{Colors.RESET}")

                    # Check for real-time ARP cache poisoning
                    arp_threats = self.arp_guard.get_threat_strings() if self.arp_guard else []
                    if arp_threats:
                        for at in arp_threats:
                            print(f"{Colors.BOLD}{Colors.RED}[!] {at}{Colors.RESET}")

                    combined_threats = (
                        result.threats
                        + honey_threats
                        + syn_threats
                        + dns_threats
                        + dhcp_threats
                        + arp_threats
                    )

                    if self.web_state:
                        self.web_state.update_audit(
                            devices=result.devices,
                            threats=combined_threats,
                            network_info=result.network,
                            active_defenses={
                                "honey_ports": bool(self.honey_listener),
                                "syn_scan": bool(self.syn_detector),
                                "dns_tunneling": bool(self.dns_tunnel_detector),
                                "dhcp_starvation": bool(self.dhcp_guard),
                                "arp_poison": bool(self.arp_guard),
                            },
                        )

                    new_aliens = [
                        a for a in result.alien_devices if a.mac not in self.known_alien_macs
                    ]

                    if new_aliens or honey_threats or syn_threats or dns_threats or dhcp_threats or arp_threats:
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
            if self.web_state:
                self.web_state.is_running = False
            if self.web_server:
                self.web_server.stop()
            if self.honey_listener:
                self.honey_listener.stop()
            if self.syn_detector:
                self.syn_detector.stop()
            if self.dns_tunnel_detector:
                self.dns_tunnel_detector.stop()
            if self.dhcp_guard:
                self.dhcp_guard.stop()
            if self.arp_guard:
                self.arp_guard.stop()
