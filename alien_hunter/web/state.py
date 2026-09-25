"""
In-Memory Sentinel State Store for Web Interface.
Maintains live daemon state, defense statuses, and discovered device inventories
with thread-safe access and zero disk I/O.
"""

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
        self.active_defenses: Dict[str, Any] = {}
        self.network_info: Dict[str, Any] = {}
        self.trusted_devices: List[Dict[str, Any]] = []
        self.alien_devices: List[Dict[str, Any]] = []
        self.recent_threats: List[str] = []
        self.event_mgr = event_manager or EventManager()
        self._logged_threats: Set[str] = set()
        self._known_alien_macs: Set[str] = set()

    def update_audit(
        self,
        devices: List[Any],
        threats: List[str],
        network_info: Optional[Any] = None,
        active_defenses: Optional[Dict[str, Any]] = None,
    ):
        """Updates live inventory, telemetry, and records security timeline events."""
        with self._lock:
            is_subsequent_scan = (self.last_scan_time > 0)
            self.last_scan_time = time.time()

            if network_info:
                if hasattr(network_info, "__dict__"):
                    self.network_info = {
                        "interface": getattr(network_info, "interface", ""),
                        "local_ip": getattr(network_info, "local_ip", ""),
                        "local_mac": getattr(network_info, "local_mac", ""),
                        "gateway_ip": getattr(network_info, "gateway_ip", ""),
                        "gateway_mac": getattr(network_info, "gateway_mac", ""),
                        "subnet_cidr": getattr(network_info, "subnet_cidr", ""),
                    }
                elif isinstance(network_info, dict):
                    self.network_info = dict(network_info)

            if active_defenses is not None:
                self.active_defenses = dict(active_defenses)

            self.recent_threats = list(threats)

            # Record threat alerts
            for threat_msg in threats:
                t_clean = threat_msg.strip()
                if t_clean and t_clean not in self._logged_threats:
                    self._logged_threats.add(t_clean)
                    self._record_threat_event(t_clean)

            if len(self._logged_threats) > 1000:
                self._logged_threats = set(list(self._logged_threats)[-500:])

            trusted: List[Dict[str, Any]] = []
            alien: List[Dict[str, Any]] = []

            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            existing_trusted = {d.get("mac", "").upper(): dict(d) for d in self.trusted_devices if d.get("mac")}
            seen_trusted_macs = set()

            for dev in devices:
                dev_dict = self._device_to_dict(dev)
                mac_upper = dev_dict.get("mac", "").upper()
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

                    trusted.append(dev_dict)
                    seen_trusted_macs.add(mac_upper)
                else:
                    dev_dict["status"] = "Online / Active"
                    dev_dict["last_seen"] = now_iso
                    alien.append(dev_dict)

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
                    trusted.append(unseen_dev)

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

            self.trusted_devices = trusted
            self.alien_devices = alien

    def _record_threat_event(self, threat_msg: str):
        """Maps threat message to appropriate security event type and severity."""
        low = threat_msg.lower()
        if "honey-port" in low or "canary" in low:
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
        elif "arp cache poisoning" in low or "arp poison" in low or "gateway masquerade" in low:
            ev_type = "ARP_POISON_DETECTED"
            sev = "CRITICAL"
            title = "ARP Cache Poisoning Detected"
        elif "port drift" in low:
            ev_type = "PORT_DRIFT"
            sev = "WARN"
            title = "Unexpected Port Drift Detected"
        else:
            ev_type = "SECURITY_THREAT"
            sev = "WARN"
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
        """Transfers a device from alien to trusted in real time after whitelisting."""
        mac_upper = mac.upper()
        name = entry.get("name", "Trusted Device")
        owner = entry.get("owner", "User")
        device_type = entry.get("device_type", "Generic")
        primary_ip = entry.get("primary_ip", "")

        with self._lock:
            new_alien: List[Dict[str, Any]] = []
            target_dev = None

            for dev in self.alien_devices:
                if dev.get("mac", "").upper() == mac_upper:
                    target_dev = dict(dev)
                else:
                    new_alien.append(dev)

            self.alien_devices = new_alien

            if target_dev:
                target_dev["trusted"] = True
                target_dev["is_alien"] = False
                target_dev["name"] = name
                target_dev["friendly_name"] = name
                target_dev["owner"] = owner
                target_dev["device_type"] = device_type
                if not primary_ip:
                    primary_ip = target_dev.get("ip", "")
                self.trusted_devices.append(target_dev)
            else:
                self.trusted_devices.append(
                    {
                        "mac": mac_upper,
                        "ip": primary_ip,
                        "name": name,
                        "friendly_name": name,
                        "display_name": name,
                        "hostname": "Unknown",
                        "owner": owner,
                        "device_type": device_type,
                        "trusted": True,
                        "is_alien": False,
                        "ports": entry.get("ports", []),
                        "open_ports": entry.get("ports", []),
                        "services": entry.get("services", []),
                        "vendor": entry.get("vendor", "N/A"),
                        "last_seen": entry.get("last_seen", ""),
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
                "uptime_seconds": uptime_seconds,
                "uptime_human": self._format_uptime(uptime_seconds),
                "last_scan_time": self.last_scan_time,
                "seconds_since_last_scan": since_last_scan,
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
            }

    def get_devices_payload(self) -> Dict[str, Any]:
        """Returns JSON-serializable lists of trusted and alien devices."""
        with self._lock:
            return {
                "trusted": list(self.trusted_devices),
                "alien": list(self.alien_devices),
            }

    def get_events_payload(self, limit: int = 100, event_type: Optional[str] = None) -> Dict[str, Any]:
        """Returns JSON-serializable list of recent security events."""
        events = self.event_mgr.get_events(limit=limit, event_type=event_type)
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
            "vendor": getattr(dev, "vendor", "N/A"),
            "status": getattr(dev, "status", "Online / Active"),
            "trusted": getattr(dev, "trusted", False),
            "is_alien": getattr(dev, "is_alien", False),
            "open_ports": getattr(dev, "open_ports", []),
            "ports": getattr(dev, "open_ports", []),
            "threats": getattr(dev, "threats", []),
            "notes": getattr(dev, "notes", []),
            "mdns_services": getattr(dev, "mdns_services", []),
            "aliases": getattr(dev, "aliases", []),
            "discovery_method": getattr(dev, "discovery_method", "Layer-2 ARP Scan"),
            "last_seen": getattr(dev, "last_seen", None) or None,
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
