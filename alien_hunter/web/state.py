"""
In-Memory Sentinel State Store for Web Interface.
Maintains live daemon state, defense statuses, and discovered device inventories
with thread-safe access and zero disk I/O.
"""

import threading
import time
from typing import Any, Dict, List, Optional


class SentinelState:
    """
    Thread-safe in-memory store capturing live Sentinel daemon state and inventory.
    """

    def __init__(self, interval: int = 300):
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

    def update_audit(
        self,
        devices: List[Any],
        threats: List[str],
        network_info: Optional[Any] = None,
        active_defenses: Optional[Dict[str, Any]] = None,
    ):
        """Updates live inventory and telemetry from an audit iteration."""
        with self._lock:
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

            trusted: List[Dict[str, Any]] = []
            alien: List[Dict[str, Any]] = []

            for dev in devices:
                dev_dict = self._device_to_dict(dev)
                if dev_dict.get("trusted"):
                    trusted.append(dev_dict)
                else:
                    alien.append(dev_dict)

            self.trusted_devices = trusted
            self.alien_devices = alien

    def initialize_from_whitelist(self, whitelist: Dict[str, Any]):
        """Seeds trusted devices in memory from known_devices whitelist on startup."""
        with self._lock:
            trusted: List[Dict[str, Any]] = []
            for mac, entry in whitelist.items():
                if not isinstance(entry, dict):
                    continue
                mac_upper = mac.upper()
                trusted.append(
                    {
                        "mac": mac_upper,
                        "ip": entry.get("primary_ip", ""),
                        "name": entry.get("name", "Trusted Device"),
                        "owner": entry.get("owner", "User"),
                        "device_type": entry.get("device_type", "Generic"),
                        "trusted": True,
                        "is_alien": False,
                        "ports": entry.get("ports", []),
                        "services": entry.get("services", []),
                        "vendor": entry.get("vendor", "N/A"),
                        "last_seen": entry.get("last_seen", ""),
                        "aliases": entry.get("aliases", []),
                    }
                )
            self.trusted_devices = trusted

    def update_whitelist_entry(self, mac: str, entry: Dict[str, Any]):
        """Transfers a device from alien to trusted in real time after whitelisting."""
        mac_upper = mac.upper()
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
                target_dev["name"] = entry.get("name", target_dev.get("hostname", ""))
                target_dev["owner"] = entry.get("owner", "User")
                target_dev["device_type"] = entry.get("device_type", "Generic")
                self.trusted_devices.append(target_dev)
            else:
                self.trusted_devices.append(
                    {
                        "mac": mac_upper,
                        "ip": entry.get("primary_ip", ""),
                        "name": entry.get("name", "Trusted Device"),
                        "owner": entry.get("owner", "User"),
                        "device_type": entry.get("device_type", "Generic"),
                        "trusted": True,
                        "is_alien": False,
                        "ports": entry.get("ports", []),
                        "services": entry.get("services", []),
                        "vendor": entry.get("vendor", "N/A"),
                        "last_seen": entry.get("last_seen", ""),
                    }
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

    @staticmethod
    def _device_to_dict(dev: Any) -> Dict[str, Any]:
        """Converts Device model or dictionary into uniform JSON-serializable dict."""
        if isinstance(dev, dict):
            return dict(dev)
        return {
            "ip": getattr(dev, "ip", ""),
            "mac": getattr(dev, "mac", ""),
            "hostname": getattr(dev, "hostname", "Unknown"),
            "display_name": getattr(dev, "display_name", getattr(dev, "hostname", "Unknown")),
            "friendly_name": getattr(dev, "friendly_name", None),
            "vendor": getattr(dev, "vendor", "N/A"),
            "status": getattr(dev, "status", "Online / Active"),
            "trusted": getattr(dev, "trusted", False),
            "is_alien": getattr(dev, "is_alien", False),
            "open_ports": getattr(dev, "open_ports", []),
            "threats": getattr(dev, "threats", []),
            "notes": getattr(dev, "notes", []),
            "mdns_services": getattr(dev, "mdns_services", []),
            "aliases": getattr(dev, "aliases", []),
            "discovery_method": getattr(dev, "discovery_method", "Layer-2 ARP Scan"),
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
