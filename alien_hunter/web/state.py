"""
In-Memory Sentinel State Store for Web Interface.
Maintains live daemon state, defense statuses, and discovered device inventories
with thread-safe access and zero disk I/O.
"""

import ipaddress
import re
import threading
import time
from typing import Any, Dict, List, Optional, Set

from ..events import EventManager


class SentinelState:
    """
    Thread-safe in-memory store capturing live Sentinel daemon state, inventory, and events.
    """

    def __init__(self, interval: int = 300, event_manager: Optional[EventManager] = None):
        self._lock = threading.Lock()
        self.start_time: float = time.time()
        self.last_scan_time: float = 0.0
        self.interval: int = interval
        self.is_running: bool = True
        self.is_scanning: bool = False
        self.active_defenses: Dict[str, Any] = {}
        self.network_info: Dict[str, Any] = {}
        self.trusted_devices: List[Dict[str, Any]] = []
        self.alien_devices: List[Dict[str, Any]] = []
        self.recent_threats: List[str] = []
        self.ai_posture: Optional[Dict[str, Any]] = None
        self.event_mgr = event_manager or EventManager()
        self._logged_threats: Dict[str, float] = {}
        self._known_alien_macs: Set[str] = set()

    def set_scanning(self, scanning: bool = True):
        with self._lock:
            self.is_scanning = scanning

    @staticmethod
    def _ip_rank(ip_str: str, subnet_cidr: Optional[str] = None) -> int:
        if not ip_str or not isinstance(ip_str, str):
            return -1
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.version == 4:
                if subnet_cidr:
                    try:
                        if addr in ipaddress.ip_network(subnet_cidr, strict=False):
                            return 5
                    except ValueError:
                        pass
                if addr.is_private:
                    return 4
                return 3
            elif addr.version == 6:
                if not addr.is_link_local:
                    return 2
                return 1
        except ValueError:
            pass
        return 0

    @classmethod
    def _merge_state_device_dict(cls, existing: Dict[str, Any], incoming: Dict[str, Any], subnet_cidr: Optional[str] = None) -> None:
        """Merges telemetry from multiple entries sharing the same hardware MAC."""
        inc_ip = incoming.get("ip") or incoming.get("primary_ip") or ""
        cur_ip = existing.get("ip") or existing.get("primary_ip") or ""

        aliases: List[str] = list(existing.get("aliases", []))
        if cls._ip_rank(inc_ip, subnet_cidr) > cls._ip_rank(cur_ip, subnet_cidr):
            if cur_ip and cur_ip != inc_ip and cur_ip not in aliases:
                aliases.append(cur_ip)
            existing["ip"] = inc_ip
            existing["primary_ip"] = inc_ip
        else:
            if inc_ip and inc_ip != cur_ip and inc_ip not in aliases:
                aliases.append(inc_ip)

        for a in incoming.get("aliases", []):
            if a and a != existing.get("ip") and a not in aliases:
                aliases.append(a)
        existing["aliases"] = aliases

        # Status
        status_ranks = {"Local Machine": 3, "Online / Active": 2, "Offline / Asleep": 1, "Sleeping / Inactive Lease": 1}
        if status_ranks.get(incoming.get("status", ""), 0) > status_ranks.get(existing.get("status", ""), 0):
            existing["status"] = incoming.get("status")

        # Ports
        e_ports = list(existing.get("ports", [])) or list(existing.get("open_ports", []))
        i_ports = list(incoming.get("ports", [])) or list(incoming.get("open_ports", []))
        merged_ports = list(dict.fromkeys(e_ports + i_ports))
        def _port_key(p: Any) -> int:
            try:
                return int(str(p).split("/")[0])
            except (ValueError, IndexError):
                return 99999
        merged_ports.sort(key=_port_key)
        existing["ports"] = merged_ports
        existing["open_ports"] = merged_ports

        # Services
        e_serv = list(existing.get("services", [])) or list(existing.get("mdns_services", []))
        i_serv = list(incoming.get("services", [])) or list(incoming.get("mdns_services", []))
        existing["services"] = list(dict.fromkeys(e_serv + i_serv))
        existing["mdns_services"] = existing["services"]

        # Discovery methods
        e_m = [m.strip() for m in str(existing.get("discovery_method", "")).split(",") if m.strip()]
        i_m = [m.strip() for m in str(incoming.get("discovery_method", "")).split(",") if m.strip()]
        existing["discovery_method"] = ", ".join(list(dict.fromkeys(e_m + i_m)))

        # Notes & Threats
        existing["notes"] = list(dict.fromkeys(list(existing.get("notes", [])) + list(incoming.get("notes", []))))
        existing["threats"] = list(dict.fromkeys(list(existing.get("threats", [])) + list(incoming.get("threats", []))))

        # Last seen
        if incoming.get("last_seen") and (not existing.get("last_seen") or incoming["last_seen"] > existing["last_seen"]):
            existing["last_seen"] = incoming["last_seen"]

    def update_audit(
        self,
        devices: List[Any],
        threats: List[str],
        network_info: Optional[Any] = None,
        active_defenses: Optional[Dict[str, Any]] = None,
        ai_posture: Optional[Any] = None,
    ):
        """Updates live inventory, telemetry, and records security timeline events."""
        with self._lock:
            self.is_scanning = False
            is_subsequent_scan = (self.last_scan_time > 0)
            self.last_scan_time = time.time()

            if ai_posture is not None:
                self.ai_posture = (
                    ai_posture.to_dict()
                    if hasattr(ai_posture, "to_dict")
                    else (dict(ai_posture) if isinstance(ai_posture, dict) else None)
                )

            if network_info:
                if hasattr(network_info, "__dict__"):
                    self.network_info = {
                        "interface": getattr(network_info, "interface", ""),
                        "local_ip": getattr(network_info, "local_ip", ""),
                        "local_mac": getattr(network_info, "local_mac", ""),
                        "gateway_ip": getattr(network_info, "gateway_ip", ""),
                        "gateway_mac": getattr(network_info, "gateway_mac", ""),
                        "subnet_cidr": getattr(network_info, "subnet_cidr", ""),
                        "prefix_len": getattr(network_info, "prefix_len", None),
                    }
                elif isinstance(network_info, dict):
                    self.network_info = dict(network_info)

            if active_defenses is not None:
                self.active_defenses = dict(active_defenses)

            self.recent_threats = list(threats)

            # Record threat alerts
            current_threat_keys = set()
            for threat_msg in threats:
                t_clean = threat_msg.strip()
                if not t_clean:
                    continue
                current_threat_keys.add(t_clean)
                if t_clean not in self._logged_threats:
                    self._logged_threats[t_clean] = time.time()
                    self._record_threat_event(t_clean)

            # Prune cleared threats so recurring events can alert again
            for old_threat in list(self._logged_threats.keys()):
                if old_threat not in current_threat_keys:
                    del self._logged_threats[old_threat]

            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            existing_trusted = {
                d.get("mac", "").upper(): dict(d)
                for d in self.trusted_devices
                if d.get("mac") and not d.get("mac", "").startswith("N/A")
            }
            existing_alien = {
                d.get("mac", "").upper(): dict(d)
                for d in self.alien_devices
                if d.get("mac") and not d.get("mac", "").startswith("N/A")
            }

            trusted_map: Dict[str, Dict[str, Any]] = {}
            alien_map: Dict[str, Dict[str, Any]] = {}
            unkeyed_trusted: List[Dict[str, Any]] = []
            unkeyed_alien: List[Dict[str, Any]] = []
            seen_trusted_macs = set()

            for dev in devices:
                dev_dict = self._device_to_dict(dev)
                mac_upper = dev_dict.get("mac", "").strip().upper()
                is_hw_mac = bool(
                    mac_upper
                    and not mac_upper.startswith("N/A")
                    and re.match(r"^([0-9A-FA-F]{2}[:-]){5}([0-9A-FA-F]{2})$", mac_upper)
                )

                if dev_dict.get("trusted"):
                    dev_status = getattr(dev, "status", "Online / Active")
                    if dev_status not in ("Online / Active", "Local Machine"):
                        dev_status = "Offline / Asleep"
                    dev_dict["status"] = dev_status

                    if dev_status in ("Online / Active", "Local Machine"):
                        dev_dict["last_seen"] = now_iso
                    else:
                        prev_last = existing_trusted.get(mac_upper, {}).get("last_seen")
                        dev_dict["last_seen"] = prev_last

                    if is_hw_mac and mac_upper in trusted_map:
                        self._merge_state_device_dict(trusted_map[mac_upper], dev_dict, self.network_info.get("subnet_cidr"))
                        continue

                    if mac_upper in existing_trusted:
                        prev = existing_trusted[mac_upper]
                        prev_status = prev.get("status")

                        if not dev_dict.get("owner") or dev_dict.get("owner") == "User":
                            dev_dict["owner"] = prev.get("owner", "User")
                        if not dev_dict.get("device_type") or dev_dict.get("device_type") == "Generic":
                            dev_dict["device_type"] = prev.get("device_type", "Generic")
                        if prev.get("friendly_name") and (not dev_dict.get("friendly_name") or dev_dict.get("friendly_name") == "Unknown"):
                            dev_dict["friendly_name"] = prev["friendly_name"]
                            dev_dict["name"] = prev["friendly_name"]
                        if not dev_dict.get("last_seen") and prev.get("last_seen"):
                            dev_dict["last_seen"] = prev["last_seen"]
                        if not dev_dict.get("ai_assessment") and prev.get("ai_assessment"):
                            dev_dict["ai_assessment"] = prev["ai_assessment"]

                        prev_ip = prev.get("ip") or prev.get("primary_ip")
                        if prev_ip and prev_ip != dev_dict.get("ip"):
                            cur_rank = self._ip_rank(dev_dict.get("ip", ""), self.network_info.get("subnet_cidr"))
                            prev_rank = self._ip_rank(prev_ip, self.network_info.get("subnet_cidr"))
                            if prev_rank > cur_rank:
                                demoted = dev_dict.get("ip")
                                dev_dict["ip"] = prev_ip
                                dev_dict["primary_ip"] = prev_ip
                                if demoted:
                                    aliases = dev_dict.setdefault("aliases", [])
                                    if demoted not in aliases:
                                        aliases.append(demoted)

                        # Check for offline -> online transition
                        if is_subsequent_scan and prev_status == "Offline / Asleep" and dev_status in ("Online / Active", "Local Machine"):
                            name = dev_dict.get("friendly_name") or dev_dict.get("name") or "Trusted Device"
                            ip_addr = dev_dict.get("ip") or dev_dict.get("primary_ip") or "LAN"
                            self.event_mgr.record(
                                event_type="DEVICE_ONLINE",
                                severity="INFO",
                                title=f"Device Online: {name}",
                                description=f"Trusted device '{name}' ({ip_addr}) is now active on the network.",
                                device_name=name,
                                ip=dev_dict.get("ip"),
                                mac=mac_upper,
                            )

                    if is_hw_mac:
                        trusted_map[mac_upper] = dev_dict
                        seen_trusted_macs.add(mac_upper)
                        self._known_alien_macs.discard(mac_upper)
                    else:
                        unkeyed_trusted.append(dev_dict)
                else:
                    dev_dict["status"] = "Online / Active"
                    dev_dict["last_seen"] = now_iso
                    if not dev_dict.get("ai_assessment") and mac_upper in existing_alien and existing_alien[mac_upper].get("ai_assessment"):
                        dev_dict["ai_assessment"] = existing_alien[mac_upper]["ai_assessment"]

                    if is_hw_mac and mac_upper in alien_map:
                        self._merge_state_device_dict(alien_map[mac_upper], dev_dict, self.network_info.get("subnet_cidr"))
                        continue

                    if is_hw_mac:
                        alien_map[mac_upper] = dev_dict
                    else:
                        unkeyed_alien.append(dev_dict)

                    # Log newly detected alien host
                    if mac_upper and mac_upper not in self._known_alien_macs:
                        self._known_alien_macs.add(mac_upper)
                        name_label = dev_dict.get("hostname") or dev_dict.get("vendor") or "Alien Host"
                        if name_label == "Unknown":
                            name_label = f"Device [{mac_upper}]"
                        ip_addr = dev_dict.get("ip") or "LAN"
                        port_list = dev_dict.get("open_ports") or dev_dict.get("ports") or []
                        port_str = ", ".join(map(str, port_list)) if port_list else "None open"
                        self.event_mgr.record(
                            event_type="ALIEN_DETECTED",
                            severity="CRITICAL",
                            title=f"Alien Device Detected: {name_label}",
                            description=f"Unrecognized device with MAC {mac_upper} ({ip_addr}) observed on LAN. Open ports: {port_str}.",
                            device_name=name_label,
                            ip=dev_dict.get("ip"),
                            mac=mac_upper,
                            details={"vendor": dev_dict.get("vendor"), "open_ports": port_list},
                        )

            # Preserve trusted devices that are currently inactive/sleeping
            for mac_upper, prev in existing_trusted.items():
                if mac_upper not in seen_trusted_macs:
                    prev_status = prev.get("status")
                    unseen_dev = dict(prev)
                    unseen_dev["status"] = "Offline / Asleep"
                    trusted_map[mac_upper] = unseen_dev

                    # Check for online -> offline transition
                    if is_subsequent_scan and prev_status in ("Online / Active", "Local Machine"):
                        name = prev.get("friendly_name") or prev.get("name") or "Trusted Device"
                        ip_addr = prev.get("ip") or prev.get("primary_ip") or "LAN"
                        self.event_mgr.record(
                            event_type="DEVICE_OFFLINE",
                            severity="INFO",
                            title=f"Device Offline: {name}",
                            description=f"Trusted device '{name}' ({ip_addr}) is no longer responding on the network.",
                            device_name=name,
                            ip=prev.get("ip"),
                            mac=mac_upper,
                        )

            self.trusted_devices = list(trusted_map.values()) + unkeyed_trusted
            self.alien_devices = list(alien_map.values()) + unkeyed_alien

    def _record_threat_event(self, threat_msg: str):
        """Maps threat message to appropriate security event type and severity."""
        low = threat_msg.lower()
        is_critical = low.startswith("critical:")
        if "honey-port" in low:
            ev_type = "CANARY_TRIGGERED"
            sev = "CRITICAL"
            title = "Honey-Port Canary Tripped"
        elif "doppelgänger" in low or "doppelganger" in low or "mac spoofing" in low or "stack masquerade" in low or "stack drift" in low:
            ev_type = "DOPPELGANGER_DETECTED"
            sev = "CRITICAL"
            title = "Hardware Doppelgänger / MAC Spoofing Detected"
        elif "out-of-subnet" in low or "phantom implant" in low:
            ev_type = "PHANTOM_DEVICE_DETECTED"
            sev = "CRITICAL" if is_critical else "WARN"
            title = "Out-of-Subnet Phantom Device Detected"
        elif "rogue dhcp" in low or "unauthorized dhcp" in low:
            ev_type = "ROGUE_DHCP_DETECTED"
            sev = "CRITICAL"
            title = "Rogue DHCP Server Detected"
        elif "cam table" in low or "broadcast storm" in low:
            ev_type = "L2_STORM_DETECTED"
            sev = "CRITICAL" if is_critical else "WARN"
            title = "Layer-2 Flood / Storm Detected"
        elif "llmnr" in low or "mdns poisoning" in low or "nbt-ns" in low:
            ev_type = "NAME_POISONING_DETECTED"
            sev = "CRITICAL"
            title = "Name Resolution Poisoning Detected"
        elif "canary" in low:
            ev_type = "CANARY_TRIGGERED"
            sev = "CRITICAL"
            title = "Honey-Port Canary Tripped"
        elif "syn scan" in low:
            ev_type = "SYN_SCAN_DETECTED"
            sev = "CRITICAL"
            title = "Stealth TCP SYN Scan Detected"
        elif "dns tunnel" in low:
            ev_type = "DNS_TUNNEL_DETECTED"
            sev = "CRITICAL"
            title = "High-Entropy DNS Tunneling Detected"
        elif "dhcp starvation" in low:
            ev_type = "DHCP_STARVATION_DETECTED"
            sev = "CRITICAL"
            title = "DHCP Starvation Flood Detected"
        elif "arp cache poisoning" in low or "arp poison" in low or "gateway masquerade" in low or "arp spoofing" in low:
            ev_type = "ARP_POISON_DETECTED"
            sev = "CRITICAL"
            title = "ARP Cache Poisoning Detected"
        elif "icmp route hijacking" in low or "icmp redirect" in low:
            ev_type = "ICMP_REDIRECT_DETECTED"
            sev = "CRITICAL"
            title = "ICMP Route Hijacking Detected"
        elif "port drift" in low:
            ev_type = "PORT_DRIFT"
            sev = "CRITICAL" if is_critical else "WARN"
            title = "Unexpected Port Drift Detected"
        else:
            ev_type = "SECURITY_THREAT"
            sev = "CRITICAL" if is_critical else "WARN"
            title = "Security Threat Alert"

        self.event_mgr.record(
            event_type=ev_type,
            severity=sev,
            title=title,
            description=threat_msg,
        )

    def initialize_from_whitelist(self, whitelist: Dict[str, Any]):
        """Seeds trusted devices in memory from known_devices whitelist on startup."""
        with self._lock:
            trusted: List[Dict[str, Any]] = []
            for mac, entry in whitelist.items():
                if not isinstance(entry, dict):
                    continue
                mac_upper = mac.upper()
                name = entry.get("name", "Trusted Device")
                trusted.append(
                    {
                        "mac": mac_upper,
                        "ip": entry.get("primary_ip", ""),
                        "name": name,
                        "friendly_name": name,
                        "display_name": name,
                        "hostname": entry.get("hostname", "Unknown"),
                        "owner": entry.get("owner", "User"),
                        "device_type": entry.get("device_type", "Generic"),
                        "status": "Offline / Asleep",
                        "trusted": True,
                        "is_alien": False,
                        "ports": entry.get("ports", []),
                        "open_ports": entry.get("ports", []),
                        "services": entry.get("services", []),
                        "vendor": entry.get("vendor", "N/A"),
                        "last_seen": entry.get("last_seen") or None,
                        "aliases": entry.get("aliases", []),
                    }
                )
            self.trusted_devices = trusted

    def update_whitelist_entry(self, mac: str, entry: Dict[str, Any]):
        """Transfers a device from alien to trusted (or updates existing trusted entry) in real time."""
        mac_upper = mac.upper()
        name = entry.get("name", "Trusted Device")
        owner = entry.get("owner", "User")
        device_type = entry.get("device_type", "Generic")
        primary_ip = entry.get("primary_ip", "")

        with self._lock:
            self._known_alien_macs.discard(mac_upper)
            new_alien: List[Dict[str, Any]] = []
            target_dev = None

            for dev in self.alien_devices:
                if dev.get("mac", "").upper() == mac_upper:
                    target_dev = dict(dev)
                else:
                    new_alien.append(dev)

            self.alien_devices = new_alien

            existing_idx = None
            for idx, tdev in enumerate(self.trusted_devices):
                if tdev.get("mac", "").upper() == mac_upper:
                    existing_idx = idx
                    if not target_dev:
                        target_dev = dict(tdev)
                    break

            if target_dev:
                target_dev["trusted"] = True
                target_dev["is_alien"] = False
                target_dev["name"] = name
                target_dev["friendly_name"] = name
                target_dev["display_name"] = name
                target_dev["owner"] = owner
                target_dev["device_type"] = device_type
                if not primary_ip:
                    primary_ip = target_dev.get("ip", "")
                elif not target_dev.get("ip"):
                    target_dev["ip"] = primary_ip
                if existing_idx is not None:
                    self.trusted_devices[existing_idx] = target_dev
                else:
                    self.trusted_devices.append(target_dev)
            else:
                self.trusted_devices.append(
                    {
                        "mac": mac_upper,
                        "ip": primary_ip,
                        "name": name,
                        "friendly_name": name,
                        "display_name": name,
                        "hostname": entry.get("hostname", "Unknown"),
                        "owner": owner,
                        "device_type": device_type,
                        "trusted": True,
                        "is_alien": False,
                        "ports": entry.get("ports", []),
                        "open_ports": entry.get("ports", []),
                        "services": entry.get("services", []),
                        "vendor": entry.get("vendor", "N/A"),
                        "last_seen": entry.get("last_seen", ""),
                        "aliases": entry.get("aliases", []),
                    }
                )

            # Record DEVICE_WHITELISTED event
            self.event_mgr.record(
                event_type="DEVICE_WHITELISTED",
                severity="INFO",
                title=f"Device Whitelisted: {name}",
                description=f"Device {mac_upper} ('{name}', {owner}) was added to trusted whitelist.",
                device_name=name,
                ip=primary_ip or (target_dev.get("ip") if target_dev else None),
                mac=mac_upper,
            )

    def get_status_summary(self) -> Dict[str, Any]:
        """Returns JSON-serializable status dictionary."""
        with self._lock:
            now = time.time()
            uptime_seconds = int(now - self.start_time)
            since_last_scan = int(now - self.last_scan_time) if self.last_scan_time > 0 else None

            return {
                "is_running": self.is_running,
                "is_scanning": self.is_scanning,
                "uptime_seconds": uptime_seconds,
                "uptime_human": self._format_uptime(uptime_seconds),
                "last_scan_time": self.last_scan_time,
                "seconds_since_last_scan": since_last_scan,
                "since_last_scan_human": f"{self._format_uptime(since_last_scan)} ago" if since_last_scan is not None else "In progress...",
                "interval_seconds": self.interval,
                "network": dict(self.network_info),
                "active_defenses": dict(self.active_defenses),
                "counts": {
                    "total_devices": len(self.trusted_devices) + len(self.alien_devices),
                    "trusted_devices": len(self.trusted_devices),
                    "alien_devices": len(self.alien_devices),
                    "active_threats": len(self.recent_threats),
                    "total_events": len(self.event_mgr),
                },
                "recent_threats": list(self.recent_threats),
                "ai_posture": dict(self.ai_posture) if isinstance(self.ai_posture, dict) else None,
            }

    def get_devices_payload(self) -> Dict[str, Any]:
        """Returns JSON-serializable lists of trusted and alien devices."""
        with self._lock:
            return {
                "trusted": list(self.trusted_devices),
                "alien": list(self.alien_devices),
                "ai_posture": dict(self.ai_posture) if isinstance(self.ai_posture, dict) else None,
            }

    def get_events_payload(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        mac: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Returns JSON-serializable list of recent security events."""
        events = self.event_mgr.get_events(limit=limit, event_type=event_type, mac=mac, ip=ip)
        return {
            "count": len(events),
            "events": events,
        }

    @staticmethod
    def _device_to_dict(dev: Any) -> Dict[str, Any]:
        """Converts Device model or dictionary into uniform JSON-serializable dict."""
        if isinstance(dev, dict):
            return dict(dev)
        friendly = getattr(dev, "friendly_name", None) or getattr(dev, "display_name", None)
        hostname = getattr(dev, "hostname", "Unknown")
        name = friendly or (hostname if hostname != "Unknown" else "Device")
        return {
            "ip": getattr(dev, "ip", ""),
            "mac": getattr(dev, "mac", ""),
            "name": name,
            "friendly_name": friendly or name,
            "display_name": getattr(dev, "display_name", name),
            "hostname": hostname,
            "owner": getattr(dev, "owner", "User"),
            "device_type": getattr(dev, "device_type", "Generic"),
            "vendor": getattr(dev, "vendor", "N/A"),
            "status": getattr(dev, "status", "Online / Active"),
            "trusted": getattr(dev, "trusted", False),
            "is_alien": getattr(dev, "is_alien", False),
            "is_randomized": getattr(dev, "is_randomized", False),
            "is_apple": getattr(dev, "is_apple", False),
            "open_ports": getattr(dev, "open_ports", []),
            "ports": getattr(dev, "open_ports", []),
            "threats": getattr(dev, "threats", []),
            "notes": getattr(dev, "notes", []),
            "mdns_services": getattr(dev, "mdns_services", []),
            "ws_types": getattr(dev, "ws_types", []),
            "aliases": getattr(dev, "aliases", []),
            "discovery_method": getattr(dev, "discovery_method", "Layer-2 ARP Scan"),
            "last_seen": getattr(dev, "last_seen", None) or None,
            "dhcp_fingerprint": getattr(dev, "dhcp_fingerprint", None),
            "dhcp_params": getattr(dev, "dhcp_params", None),
            "ssdp_fingerprint": getattr(dev, "ssdp_fingerprint", None),
            "tcp_syn_fingerprint": getattr(dev, "tcp_syn_fingerprint", None),
            "observed_ttl": getattr(dev, "observed_ttl", None),
            "ai_assessment": (
                getattr(dev, "ai_assessment").to_dict()
                if getattr(dev, "ai_assessment", None) and hasattr(getattr(dev, "ai_assessment"), "to_dict")
                else None
            ),
        }

    @staticmethod
    def _format_uptime(seconds: int) -> str:
        """Formats seconds into human-readable uptime."""
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        days, hours = divmod(hours, 24)
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        return f"{secs}s"
