"""
Alien Hunter
LAN security auditor and network discovery tool
"""

__version__ = "1.0.0"

from .models import Device, NetworkInfo, AuditResult
from .core.engine import DiscoveryEngine
from .core.sentinel import SentinelWatchdog
from .config import ConfigManager
from .events import EventManager, SecurityEvent

__all__ = [
    "__version__",
    "Device",
    "NetworkInfo",
    "AuditResult",
    "DiscoveryEngine",
    "SentinelWatchdog",
    "ConfigManager",
    "EventManager",
    "SecurityEvent",
]
