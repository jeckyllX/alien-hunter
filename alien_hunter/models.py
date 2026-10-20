"""
Data models for Alien Hunter.
Defines structured objects representing network interfaces, discovered devices, and audit results.
"""

import ipaddress
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any


class StackTtl(int, Enum):
    """Canonical initial TTL boundaries across operating system kernels."""
    UNIX = 64        # Linux, Android, macOS, iOS, BSD
    WINDOWS = 128    # Microsoft Windows Desktop and Server
    NETWORK = 255    # Cisco IOS, Solaris, specialized network hardware


class OsFamily(str, Enum):
    """Normalized operating system families for stack fingerprint correlation."""
    WINDOWS = "Windows"
    APPLE = "Apple"
    LINUX_IOT = "Linux/IoT"
    BSD = "BSD"
    NETWORK = "Network"


def estimate_initial_ttl(observed_ttl: int) -> int:
    """Estimates the initial TTL set by the originating operating system kernel."""
    if observed_ttl <= StackTtl.UNIX:
        return StackTtl.UNIX.value
    elif observed_ttl <= StackTtl.WINDOWS:
        return StackTtl.WINDOWS.value
    return StackTtl.NETWORK.value


@dataclass
class NetworkInfo:
    """Represents the local network interface and routing context."""
    interface: str
    local_ip: str
    local_mac: str
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    subnet_base: str = ""
    prefix_len: Optional[int] = None

    @property
    def subnet_cidr(self) -> str:
        """
        Returns the local subnet in CIDR form.

        Prefers the kernel-reported prefix length (correct for /8, /16, and
        non-/24 masks); falls back to a /24 assumption for callers that only
        populate ``subnet_base``.
        """
        if self.local_ip and self.prefix_len is not None:
            try:
                net = ipaddress.ip_interface(f"{self.local_ip}/{self.prefix_len}").network
                return str(net)
            except (ValueError, TypeError):
                pass
        return f"{self.subnet_base}.0/24" if self.subnet_base else ""

    @property
    def broadcast_ip(self) -> Optional[str]:
        """Calculates the authoritative broadcast address for any subnet size."""
        cidr = self.subnet_cidr
        if cidr:
            try:
                return str(ipaddress.ip_network(cidr, strict=False).broadcast_address)
            except ValueError:
                pass
        return None


@dataclass
class Device:
    """Represents a discovered hardware host on the network."""
    ip: str
    mac: str
    hostname: str = "Unknown"
    vendor: str = "N/A"
    friendly_name: Optional[str] = None
    status: str = "Online / Active"
    trusted: bool = False
    is_alien: bool = False
    is_randomized: bool = False
    is_apple: bool = False
    open_ports: List[str] = field(default_factory=list)
    threats: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    mdns_services: List[str] = field(default_factory=list)
    ws_types: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    discovery_method: str = "Layer-2 ARP Scan"
    ai_assessment: Optional[Any] = None
    dhcp_fingerprint: Optional[str] = None
    dhcp_params: Optional[List[int]] = None
    ssdp_fingerprint: Optional[str] = None
    tcp_syn_fingerprint: Optional[str] = None
    observed_ttl: Optional[int] = None

    @property
    def display_name(self) -> str:
        """Returns the best human-readable identifier for the device."""
        if self.friendly_name:
            return self.friendly_name
        if self.hostname and self.hostname != "Unknown":
            return f"{self.hostname} ({self.vendor})"
        if self.ssdp_fingerprint:
            return f"{self.ssdp_fingerprint} ({self.vendor})"
        if self.dhcp_fingerprint and self.is_randomized:
            return f"{self.dhcp_fingerprint} ({self.vendor})"
        if self.tcp_syn_fingerprint and self.is_randomized:
            return f"{self.tcp_syn_fingerprint} ({self.vendor})"
        return self.vendor or "Unknown Device"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    """Encapsulates the complete findings of a network scan."""
    timestamp: float
    network: NetworkInfo
    devices: List[Device] = field(default_factory=list)
    alien_devices: List[Device] = field(default_factory=list)
    threats: List[str] = field(default_factory=list)
    ai_posture: Optional[Any] = None

    @property
    def total_count(self) -> int:
        return len(self.devices)

    @property
    def trusted_count(self) -> int:
        return len([d for d in self.devices if d.trusted])

    @property
    def alien_count(self) -> int:
        return len(self.alien_devices)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "network": asdict(self.network),
            "inventory": [d.to_dict() for d in self.devices],
            "alien_devices": [d.to_dict() for d in self.alien_devices],
            "threats": self.threats,
            "ai_posture": self.ai_posture.to_dict() if self.ai_posture and hasattr(self.ai_posture, "to_dict") else self.ai_posture,
        }


@dataclass
class SentinelConfig:
    """
    Bundled runtime configuration for the SentinelWatchdog daemon.

    Groups the polling interval, interface/filesystem paths, web dashboard
    settings, and every defense toggle and threshold into a single object,
    replacing the previous 20+ parameter constructor.
    """
    interval: int = 300
    deep_scan: bool = False
    interface: Optional[str] = None
    whitelist_path: Optional[str] = None
    events_path: Optional[str] = None
    custom_ports: Optional[List[int]] = None
    sync_db: bool = True
    web_enabled: bool = False
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    web_auth: Optional[Dict[str, Any]] = None
    honey_ports: Optional[List[int]] = None
    syn_scan_enabled: bool = True
    dns_tunneling_enabled: bool = True
    dhcp_starvation_enabled: bool = True
    arp_poison_enabled: bool = True
    icmp_redirect_enabled: bool = True
    rogue_dhcp_enabled: bool = True
    storm_guard_enabled: bool = True
    cam_flood_threshold: int = 30
    broadcast_storm_threshold: int = 150

    @classmethod
    def from_defense_config(
        cls,
        config: Optional[Dict[str, Any]] = None,
        **overrides: Any,
    ) -> "SentinelConfig":
        """
        Builds a SentinelConfig from a parsed ``config.json`` mapping, applying
        the ``defenses``/``web_ui`` sections, then any explicit keyword overrides.
        """
        config = config or {}
        defenses = config.get("defenses", {}) or {}
        web = config.get("web_ui", {}) or {}

        honey_enabled = defenses.get("honey_port_enabled", True)
        values: Dict[str, Any] = {
            "web_enabled": bool(web.get("enabled", False)),
            "web_host": str(web.get("host", "0.0.0.0")),
            "web_port": int(web.get("port", 8080)),
            "web_auth": web.get("auth"),
            "honey_ports": defenses.get("honey_ports", [5555, 2323, 8888]) if honey_enabled else None,
            "syn_scan_enabled": bool(defenses.get("syn_scan_enabled", True)),
            "dns_tunneling_enabled": bool(defenses.get("dns_tunneling_enabled", True)),
            "dhcp_starvation_enabled": bool(defenses.get("dhcp_starvation_enabled", True)),
            "arp_poison_enabled": bool(defenses.get("arp_poison_enabled", True)),
            "icmp_redirect_enabled": bool(defenses.get("icmp_redirect_enabled", True)),
            "rogue_dhcp_enabled": bool(defenses.get("rogue_dhcp_enabled", True)),
            "storm_guard_enabled": bool(defenses.get("storm_guard_enabled", True)),
            "cam_flood_threshold": int(defenses.get("cam_flood_threshold", 30)),
            "broadcast_storm_threshold": int(defenses.get("broadcast_storm_threshold", 150)),
            "sync_db": bool(config.get("auto_sync_database", True)),
        }
        # Only apply overrides that correspond to real dataclass fields; silently
        # ignore unknown keys so a stale config/CLI flag cannot crash startup.
        known_fields = set(cls.__dataclass_fields__.keys())
        values.update(
            {k: v for k, v in overrides.items() if v is not None and k in known_fields}
        )
        return cls(**values)
