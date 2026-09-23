"""Defenses and Intrusion Detection Systems subpackage for Alien Hunter."""

from .llmnr_canary import LlmnrCanaryTrap
from .mdns_canary import MdnsCanaryTrap
from .dns_integrity import DnsIntegrityAuditor
from .ipv6_guard import Ipv6Guard
from .anti_sniff import AntiSniffDetector
from .port_drift import PortDriftTracker
from .honey_port import HoneyPortListener, HoneyPortEvent
from .honey_auth import HoneyAuthTrap
from .syn_scan import SynScanDetector, SynScanEvent

__all__ = [
    "LlmnrCanaryTrap",
    "MdnsCanaryTrap",
    "DnsIntegrityAuditor",
    "Ipv6Guard",
    "AntiSniffDetector",
    "PortDriftTracker",
    "HoneyPortListener",
    "HoneyPortEvent",
    "HoneyAuthTrap",
    "SynScanDetector",
    "SynScanEvent",
]
