"""
Data models for Alien Hunter.
Defines structured objects representing network interfaces, discovered devices, and audit results.
"""

import ipaddress
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class NetworkInfo:
    """Represents the local network interface and routing context."""
    interface: str
    local_ip: str
    local_mac: str
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    subnet_base: str = ""

    @property
    def subnet_cidr(self) -> str:
        return f"{self.subnet_base}.0/24" if self.subnet_base else ""

    @property
    def broadcast_ip(self) -> Optional[str]:
        """Calculates the authoritative broadcast address for any subnet size."""
        if self.subnet_cidr:
            try:
                return str(ipaddress.ip_network(self.subnet_cidr, strict=False).broadcast_address)
            except Exception:
                pass
        return f"{self.subnet_base}.255" if self.subnet_base else None


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

    @property
    def display_name(self) -> str:
        """Returns the best human-readable identifier for the device."""
        if self.friendly_name:
            return self.friendly_name
        if self.hostname and self.hostname != "Unknown":
            return f"{self.hostname} ({self.vendor})"
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
