"""
24/7 Sentinel Watchdog Daemon.
Runs continuous periodic audits and dispatches alerts across all configured notification hooks.
"""

import threading
import time
from typing import List, Set, Optional, Any, Dict, Tuple
from ..logging_setup import get_logger
from ..models import SentinelConfig
from ..reporting.console import Colors
from ..notifications.engine import NotificationEngine
from ..config import ConfigManager
from ..defenses.honey_port import HoneyPortListener
from ..defenses.syn_scan import SynScanDetector
from ..defenses.dns_tunneling import DnsTunnelingDetector
from ..defenses.dhcp_starvation import DhcpStarvationGuard
from ..defenses.arp_poison import ArpPoisonGuard
from ..defenses.icmp_redirect import IcmpRedirectGuard
from ..defenses.rogue_dhcp import RogueDhcpGuard
from ..defenses.storm_guard import StormGuard
from ..identifiers.ssdp import SsdpListener
from ..web.state import SentinelState
from ..web.server import LightweightWebServer
from ..events import EventManager
from .engine import DiscoveryEngine

log = get_logger()


class SentinelWatchdog:
    """Continuously monitors network state and dispatches alerts on new device intrusions."""

    def __init__(
        self,
        engine: DiscoveryEngine,
        notifier: NotificationEngine,
        config_mgr: ConfigManager,
        cfg: Optional[SentinelConfig] = None,
        ai_engine: Optional[Any] = None,
    ):
        self.cfg = cfg or SentinelConfig()
        self.engine = engine
        self.notifier = notifier
        self.config_mgr = config_mgr
        self.ai_engine = ai_engine

        self.config_path = self.cfg.config_path
        self.whitelist_path = self.cfg.whitelist_path
        self.events_path = self.cfg.events_path
        self.custom_ports = self.cfg.custom_ports
        self.interval = self.cfg.interval
        self.deep_scan = self.cfg.deep_scan
        self.interface = self.cfg.interface
        self.honey_ports = self.cfg.honey_ports
        self.syn_scan_enabled = self.cfg.syn_scan_enabled
        self.dns_tunneling_enabled = self.cfg.dns_tunneling_enabled
        self.dhcp_starvation_enabled = self.cfg.dhcp_starvation_enabled
        self.arp_poison_enabled = self.cfg.arp_poison_enabled
        self.icmp_redirect_enabled = self.cfg.icmp_redirect_enabled
        self.rogue_dhcp_enabled = self.cfg.rogue_dhcp_enabled
        self.storm_guard_enabled = self.cfg.storm_guard_enabled
        self.cam_flood_threshold = self.cfg.cam_flood_threshold
        self.broadcast_storm_threshold = self.cfg.broadcast_storm_threshold
        self.sync_db = self.cfg.sync_db
        self.web_enabled = self.cfg.web_enabled
        self.web_host = self.cfg.web_host
        self.web_port = self.cfg.web_port
        self.web_auth = self.cfg.web_auth

        self.known_alien_macs: Set[str] = set()
        self.known_audit_threats: Set[str] = set()
        self._pinned_gateway_ip: Optional[str] = None
        self._pinned_gateway_mac: Optional[str] = None
        self.honey_listener: Optional[HoneyPortListener] = None
        self.syn_detector: Optional[SynScanDetector] = None
        self.dns_tunnel_detector: Optional[DnsTunnelingDetector] = None
        self.dhcp_guard: Optional[DhcpStarvationGuard] = None
        self.arp_guard: Optional[ArpPoisonGuard] = None
        self.icmp_guard: Optional[IcmpRedirectGuard] = None
        self.rogue_dhcp_guard: Optional[RogueDhcpGuard] = None
        self.storm_guard: Optional[StormGuard] = None
        self.ssdp_listener: Optional[SsdpListener] = None

        event_mgr = EventManager(log_path=self.events_path) if self.events_path else EventManager()
        self.web_state = SentinelState(interval=self.interval, event_manager=event_mgr)
        self.web_server: Optional[LightweightWebServer] = None
        self._scan_trigger = threading.Event()
        self._force_deep = False
        self._force_ai = False
        self._force_analyze_all = False
        self._audit_lock = threading.Lock()

        if self.whitelist_path:
            try:
                initial_wl = self.config_mgr.load_whitelist(self.whitelist_path)
                self.web_state.initialize_from_whitelist(initial_wl)
            except Exception as e:
                log.debug("Failed to initialize web state from whitelist: %s", e)

    @staticmethod
    def _is_guard_active(guard: Optional[Any]) -> bool:
        if not guard:
            return False
        attr = getattr(guard, "is_running", None)
        if callable(attr):
            return bool(attr())
        if attr is not None:
            return bool(attr)
        return bool(getattr(guard, "running", getattr(guard, "_running", True)))

    def _resolve_authoritative_gateway_mac(
        self,
        gateway_ip: Optional[str],
        fallback_mac: Optional[str],
        whitelist: Optional[Dict[str, dict]] = None,
    ) -> Optional[str]:
        """Pins the gateway MAC from the whitelist or initial verified baseline."""
        if not gateway_ip:
            return None

        if isinstance(whitelist, dict):
            for w_mac, w_info in whitelist.items():
                if not isinstance(w_info, dict) or not w_info.get("trusted", True):
                    continue
                if w_info.get("primary_ip") == gateway_ip and DiscoveryEngine._is_valid_hardware_mac(w_mac):
                    self._pinned_gateway_ip = gateway_ip
                    self._pinned_gateway_mac = w_mac.upper()
                    return self._pinned_gateway_mac

        if self._pinned_gateway_ip == gateway_ip and self._pinned_gateway_mac:
            return self._pinned_gateway_mac

        if fallback_mac and DiscoveryEngine._is_valid_hardware_mac(fallback_mac):
            self._pinned_gateway_ip = gateway_ip
            self._pinned_gateway_mac = fallback_mac.upper()
            return self._pinned_gateway_mac

        return None

    @staticmethod
    def _alien_identity_key(dev: Any) -> Optional[str]:
        mac = getattr(dev, "mac", None)
        if mac and DiscoveryEngine._is_valid_hardware_mac(mac):
            return mac.upper()
        ip = getattr(dev, "ip", None)
        if ip:
            return f"IP:{ip}"
        return None

    def _active_defenses_dict(self) -> Dict[str, Any]:
        """Snapshot of currently active defense subsystems for the web dashboard."""
        return {
            "honey_ports": list(self.honey_listener.active_sockets.keys()) if self.honey_listener else [],
            "syn_scan": self._is_guard_active(self.syn_detector),
            "dns_tunneling": self._is_guard_active(self.dns_tunnel_detector),
            "dhcp_starvation": self._is_guard_active(self.dhcp_guard),
            "arp_poison": self._is_guard_active(self.arp_guard),
            "arp_self_healing": bool(self._is_guard_active(self.arp_guard) and self.arp_guard.is_self_healing_enabled),
            "icmp_redirect": self._is_guard_active(self.icmp_guard),
            "rogue_dhcp": self._is_guard_active(self.rogue_dhcp_guard),
            "storm_guard": self._is_guard_active(self.storm_guard),
            "ssdp_harvester": self._is_guard_active(self.ssdp_listener),
        }

    def _drain_threats(self) -> Dict[str, List[str]]:
        """
        Drains and clears the threat queues of every active defense module.

        Returns a mapping of defense name -> freshly observed threat strings.
        """
        drainable: List[Tuple[str, Optional[Any]]] = [
            ("honey", self.honey_listener),
            ("syn_scan", self.syn_detector),
            ("dns_tunneling", self.dns_tunnel_detector),
            ("dhcp_starvation", self.dhcp_guard),
            ("arp_poison", self.arp_guard),
            ("icmp_redirect", self.icmp_guard),
            ("rogue_dhcp", self.rogue_dhcp_guard),
            ("storm_guard", self.storm_guard),
        ]
        return {
            name: (module.get_threat_strings() if module else [])
            for name, module in drainable
        }

    def trigger_scan(self, deep: bool = True, ai: bool = True, analyze_all: bool = False) -> int:
        """Signals the sentinel loop to immediately execute an on-demand audit."""
        with self._audit_lock:
            self._force_deep = deep
            self._force_ai = ai
            self._force_analyze_all = analyze_all
            scan_id = self.web_state.begin_triggered_scan() if self.web_state else 1
            self._scan_trigger.set()
            return scan_id

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
            except Exception as e:
                log.debug("Failed to resolve network info at startup: %s", e)

        if net_info and not self.interface and net_info.local_ip:
            self.interface = net_info.interface

        local_ip = net_info.local_ip if net_info else None
        local_mac = net_info.local_mac if net_info else None
        subnet_cidr = net_info.subnet_cidr if net_info else None
        gateway_ip = net_info.gateway_ip if net_info else None
        startup_wl = {}
        if self.whitelist_path:
            try:
                startup_wl = self.config_mgr.load_whitelist(self.whitelist_path)
            except Exception:
                startup_wl = {}
        gateway_mac = self._resolve_authoritative_gateway_mac(
            gateway_ip,
            net_info.gateway_mac if net_info else None,
            whitelist=startup_wl,
        )

        if self.honey_ports:
            ignored_ips = {"127.0.0.1", "::1"}
            if local_ip:
                ignored_ips.add(local_ip)
            self.honey_listener = HoneyPortListener(ports=self.honey_ports, ignored_ips=ignored_ips)
            bound = self.honey_listener.start()
            if bound:
                print(f"{Colors.GREEN}[+] Decoy Honey-Port Canary active on TCP ports: {', '.join(map(str, bound))}{Colors.RESET}")
            else:
                self.honey_listener = None

        if self.syn_scan_enabled:
            self.syn_detector = SynScanDetector(
                interface=self.interface,
                subnet_cidr=subnet_cidr,
                local_ip=local_ip,
                local_mac=local_mac,
            )
            if self.syn_detector.start():
                print(f"{Colors.GREEN}[+] Stealth TCP SYN Scan Detector active.{Colors.RESET}")
            else:
                self.syn_detector = None

        if self.dns_tunneling_enabled:
            self.dns_tunnel_detector = DnsTunnelingDetector(
                interface=self.interface,
                subnet_cidr=subnet_cidr,
                local_ip=local_ip,
                local_mac=local_mac,
            )
            if self.dns_tunnel_detector.start():
                print(f"{Colors.GREEN}[+] High-Entropy DNS Tunneling Detector active.{Colors.RESET}")
            else:
                self.dns_tunnel_detector = None

        if self.dhcp_starvation_enabled:
            self.dhcp_guard = DhcpStarvationGuard(interface=self.interface)
            if self.dhcp_guard.start():
                print(f"{Colors.GREEN}[+] DHCP Starvation & Pool Exhaustion Guard active.{Colors.RESET}")
            else:
                self.dhcp_guard = None

        if self.arp_poison_enabled:
            self.arp_guard = ArpPoisonGuard(
                interface=self.interface,
                gateway_ip=gateway_ip,
                gateway_mac=gateway_mac,
                self_healing_enabled=True,
            )
            if self.arp_guard.start():
                print(f"{Colors.GREEN}[+] Real-Time ARP Poisoning Guard & Self-Healing IPS active.{Colors.RESET}")
            else:
                self.arp_guard = None

        if self.icmp_redirect_enabled:
            self.icmp_guard = IcmpRedirectGuard(
                interface=self.interface,
                gateway_ip=gateway_ip,
                local_ip=local_ip,
            )
            if self.icmp_guard.start():
                print(f"{Colors.GREEN}[+] Real-Time ICMP Redirect Route Hijacking Guard active.{Colors.RESET}")
            else:
                self.icmp_guard = None

        if self.rogue_dhcp_enabled:
            self.rogue_dhcp_guard = RogueDhcpGuard(
                interface=self.interface,
                gateway_ip=gateway_ip,
                gateway_mac=gateway_mac,
            )
            if self.rogue_dhcp_guard.start():
                print(f"{Colors.GREEN}[+] Rogue DHCP Server & Gateway Hijack Guard active.{Colors.RESET}")
            else:
                self.rogue_dhcp_guard = None

        if self.storm_guard_enabled:
            self.storm_guard = StormGuard(
                interface=self.interface,
                local_mac=local_mac,
                cam_flood_threshold=self.cam_flood_threshold,
                broadcast_storm_threshold=self.broadcast_storm_threshold,
            )
            if self.storm_guard.start():
                print(f"{Colors.GREEN}[+] Switch CAM Flooding & Broadcast Storm Guard active.{Colors.RESET}")
            else:
                self.storm_guard = None

        self.ssdp_listener = SsdpListener(interface_ip=local_ip)
        if self.ssdp_listener.start():
            print(f"{Colors.GREEN}[+] SSDP / UPnP Device Harvester active.{Colors.RESET}")
        else:
            self.ssdp_listener = None

        if self.web_enabled:
            self.web_server = LightweightWebServer(
                state=self.web_state,
                config_mgr=self.config_mgr,
                whitelist_path=self.whitelist_path,
                host=self.web_host,
                port=self.web_port,
                scan_trigger=self.trigger_scan,
                auth_config=self.web_auth,
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
                    "prefix_len": getattr(net_info, "prefix_len", None),
                }
            self.web_state.active_defenses = self._active_defenses_dict()

        try:
            while True:
                try:
                    # Atomically consume any triggered scan flags and snapshot scan generation ID
                    with self._audit_lock:
                        force_deep = self._force_deep
                        force_ai = self._force_ai
                        force_analyze_all = self._force_analyze_all
                        self._force_deep = False
                        self._force_ai = False
                        self._force_analyze_all = False
                        self._scan_trigger.clear()
                        active_scan_id = self.web_state.scan_id if self.web_state else 0
                        if self.web_state:
                            self.web_state.set_scanning(True)

                    deep_scan = self.deep_scan or force_deep
                    ai_engine = self.ai_engine
                    if (force_ai or force_analyze_all) and not ai_engine:
                        try:
                            from ..ai.engine import AIEngine
                            config = self.config_mgr.load_config(self.config_path)
                            config_copy = dict(config) if isinstance(config, dict) else {}
                            ai_cfg = dict(config_copy.get("ai_analysis") or {}) if isinstance(config_copy.get("ai_analysis"), dict) else {}
                            ai_cfg["enabled"] = True
                            config_copy["ai_analysis"] = ai_cfg
                            ai_engine = AIEngine.from_config(config_copy)
                        except Exception as e:
                            log.debug("On-demand AI engine initialization failed: %s", e)

                    original_analyze_on = ai_engine.analyze_on if ai_engine else None
                    if ai_engine and force_analyze_all:
                        ai_engine.analyze_on = "all_devices"

                    try:
                        # Reload whitelist dynamically in case user updated it
                        whitelist = self.config_mgr.load_whitelist(self.whitelist_path)
                        result = self.engine.run_audit(
                            whitelist=whitelist,
                            deep_scan=deep_scan,
                            passive_duration=2,
                            interface=self.interface,
                            ai_engine=ai_engine,
                            custom_ports=self.custom_ports,
                            active_background_defenses=self._active_defenses_dict(),
                        )
                    finally:
                        if ai_engine and original_analyze_on is not None:
                            ai_engine.analyze_on = original_analyze_on

                    if self.sync_db:
                        self.config_mgr.sync_device_inventory(
                            result.devices,
                            self.whitelist_path,
                            subnet_cidr=result.network.subnet_cidr if result.network else None,
                        )

                    # Update defense modules with current local identity and network baseline
                    if result.network:
                        if self.honey_listener and result.network.local_ip:
                            self.honey_listener.update_local_ip(result.network.local_ip)
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

                        auth_gw_mac = self._resolve_authoritative_gateway_mac(
                            result.network.gateway_ip,
                            result.network.gateway_mac,
                            whitelist=whitelist,
                        )
                        if self.arp_guard:
                            trusted_map = {
                                d.ip: d.mac
                                for d in result.devices
                                if d.mac
                                and DiscoveryEngine._is_valid_hardware_mac(d.mac)
                                and d.trusted
                                and d.status in ("Online / Active", "Local Machine")
                            }
                            if result.network.gateway_ip and auth_gw_mac:
                                trusted_map[result.network.gateway_ip] = auth_gw_mac
                            self.arp_guard.update_topology(
                                gateway_ip=result.network.gateway_ip,
                                gateway_mac=auth_gw_mac,
                                trusted_ip_mac_map=trusted_map,
                            )
                        if self.icmp_guard:
                            self.icmp_guard.update_topology(
                                gateway_ip=result.network.gateway_ip,
                                local_ip=result.network.local_ip,
                            )
                        if self.rogue_dhcp_guard:
                            self.rogue_dhcp_guard.update_topology(
                                gateway_ip=result.network.gateway_ip,
                                gateway_mac=auth_gw_mac,
                            )
                        if self.storm_guard and result.network and result.network.local_mac:
                            self.storm_guard.update_local_mac(result.network.local_mac)

                    # Drain threat queues from every active defense module
                    threat_groups = self._drain_threats()
                    for msgs in threat_groups.values():
                        for msg in msgs:
                            print(f"{Colors.BOLD}{Colors.RED}[!] {msg}{Colors.RESET}")

                    new_audit_threats = [
                        t for t in result.threats if t not in self.known_audit_threats
                    ]
                    for msg in new_audit_threats:
                        print(f"{Colors.BOLD}{Colors.RED}[!] {msg}{Colors.RESET}")
                        self.known_audit_threats.add(msg)

                    combined_threats = result.threats + [
                        msg for msgs in threat_groups.values() for msg in msgs
                    ]

                    if self.web_state:
                        self.web_state.update_audit(
                            devices=result.devices,
                            threats=combined_threats,
                            network_info=result.network,
                            active_defenses=self._active_defenses_dict(),
                            ai_posture=result.ai_posture,
                            completed_scan_id=active_scan_id,
                        )

                    new_aliens = []
                    for a in result.alien_devices:
                        akey = self._alien_identity_key(a)
                        if akey and akey not in self.known_alien_macs:
                            new_aliens.append(a)

                    has_live_threats = any(threat_groups.values()) or bool(new_audit_threats)
                    if new_aliens or has_live_threats:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        if new_aliens:
                            print(
                                f"\n{Colors.BOLD}{Colors.RED}[{timestamp}] [!] Unrecognized device(s) detected:{Colors.RESET}"
                            )
                            for a in new_aliens:
                                print(
                                    f"   {Colors.RED}• {a.ip:<15} {a.mac:<18} {a.vendor} ({a.display_name}){Colors.RESET}"
                                )
                                akey = self._alien_identity_key(a)
                                if akey:
                                    self.known_alien_macs.add(akey)

                        # Dispatch only new audit threats + live defense events to prevent repeated notifications
                        notify_threats = new_audit_threats + [
                            msg for msgs in threat_groups.values() for msg in msgs
                        ]
                        dispatched = self.notifier.dispatch(
                            new_aliens, notify_threats, audit_result=result
                        )
                        if dispatched:
                            success_hooks = [k for k, v in dispatched.items() if v]
                            if success_hooks:
                                print(f"{Colors.GREEN}[+] Alerts dispatched via: {', '.join(success_hooks)}{Colors.RESET}")
                            failed_hooks = [k for k, v in dispatched.items() if not v]
                            if failed_hooks:
                                print(f"{Colors.YELLOW}[!] Alerts failed on: {', '.join(failed_hooks)}{Colors.RESET}")

                    # Sync known threats and alien keys so resolved issues can alert if they recur
                    self.known_audit_threats = set(result.threats)
                    current_alien_keys = {
                        k for k in (self._alien_identity_key(a) for a in result.alien_devices) if k
                    }
                    self.known_alien_macs = {m for m in self.known_alien_macs if m in current_alien_keys}

                    self._scan_trigger.wait(self.interval)
                    self._scan_trigger.clear()

                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    if self.web_state:
                        self.web_state.set_scanning(False)
                    log.debug("Sentinel audit iteration error", exc_info=True)
                    print(f"{Colors.YELLOW}[!] Sentinel audit iteration error: {e}{Colors.RESET}")
                    self._scan_trigger.wait(self.interval)
                    self._scan_trigger.clear()

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
            if self.icmp_guard:
                self.icmp_guard.stop()
            if self.rogue_dhcp_guard:
                self.rogue_dhcp_guard.stop()
            if self.storm_guard:
                self.storm_guard.stop()
            if self.ssdp_listener:
                self.ssdp_listener.stop()
