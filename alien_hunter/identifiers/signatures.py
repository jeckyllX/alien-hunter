"""
Device Signature Registry and Fingerprint Matcher.
Loads versioned device signatures (DHCP Option 55/60 and mDNS services)
to unmask operating system identities and hardware classes across the LAN.
"""

import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

from ..config import ConfigManager


@dataclass(frozen=True)
class DhcpSignature:
    """Canonical DHCP Parameter Request List (Option 55) signature."""
    vendor: str
    category: str
    os_family: str
    param_list: Tuple[int, ...]
    vendor_class_pattern: Optional[str] = None
    confidence: str = "HIGH"

    def matches(self, incoming_params: Tuple[int, ...], vendor_class: Optional[str] = None) -> bool:
        """Evaluates whether incoming DHCP parameters match this signature."""
        if vendor_class and self.vendor_class_pattern:
            if not re.search(self.vendor_class_pattern, vendor_class, re.IGNORECASE):
                return False

        # Exact sequence match
        if self.param_list == incoming_params:
            return True

        # Prefix / subset match if length >= 4
        if len(self.param_list) >= 4 and len(incoming_params) >= 4:
            min_len = min(len(self.param_list), len(incoming_params))
            if self.param_list[:min_len] == incoming_params[:min_len]:
                return True

        return False


@dataclass(frozen=True)
class MdnsSignature:
    """Canonical mDNS (DNS-SD) service signature."""
    vendor: str
    category: str
    os_family: str
    service_type: str


@dataclass(frozen=True)
class DeviceFingerprintMatch:
    """Represents an authoritative fingerprint resolution result."""
    vendor: str
    category: str
    os_family: str
    source: str
    confidence: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor,
            "category": self.category,
            "os_family": self.os_family,
            "source": self.source,
            "confidence": self.confidence,
        }


class SignatureManager:
    """
    Manages loading, caching, and matching of device signatures.
    Supports resolution hierarchy: user override -> system config -> bundled package data.
    """

    BUNDLED_FILENAME = "signatures.json"

    def __init__(self, custom_path: Optional[str] = None):
        self.custom_path = custom_path
        self._lock = threading.Lock()
        self.version: str = "1.0.0"
        self.updated_at: str = ""
        self.dhcp_signatures: List[DhcpSignature] = []
        self.mdns_signatures: Dict[str, MdnsSignature] = {}
        self.active_path: Optional[str] = None
        self.reload()

    def resolve_signature_path(self) -> str:
        """Resolves the active signature file path using fallback hierarchy."""
        if self.custom_path and os.path.exists(self.custom_path):
            return os.path.abspath(self.custom_path)

        # 1. User config directory (~/.config/alien-hunter/signatures.json)
        user_path = ConfigManager.resolve_path(self.BUNDLED_FILENAME)
        if os.path.exists(user_path):
            return user_path

        # 2. Package bundled directory (alien_hunter/data/signatures.json)
        pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bundled = os.path.join(pkg_dir, "data", self.BUNDLED_FILENAME)
        if os.path.exists(bundled):
            return bundled

        return user_path

    def reload(self) -> bool:
        """Reloads signatures into memory thread-safely."""
        path = self.resolve_signature_path()
        with self._lock:
            self.active_path = path
            if not os.path.exists(path):
                # Fall back to package bundled path
                pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                fallback_path = os.path.join(pkg_dir, "data", self.BUNDLED_FILENAME)
                if os.path.exists(fallback_path):
                    path = fallback_path
                    self.active_path = path

            data = ConfigManager.load_json(path, default={})
            self.version = str(data.get("version", "1.0.0"))
            self.updated_at = str(data.get("updated_at", ""))

            # Parse DHCP signatures
            dhcp_list: List[DhcpSignature] = []
            for item in data.get("dhcp_signatures", []):
                try:
                    params = tuple(int(x) for x in item.get("param_list", []))
                    if not params:
                        continue
                    dhcp_list.append(
                        DhcpSignature(
                            vendor=str(item.get("vendor", "Unknown")),
                            category=str(item.get("category", "Unknown Device")),
                            os_family=str(item.get("os_family", "Unknown")),
                            param_list=params,
                            vendor_class_pattern=item.get("vendor_class_pattern"),
                            confidence=str(item.get("confidence", "HIGH")),
                        )
                    )
                except Exception:
                    continue
            self.dhcp_signatures = dhcp_list

            # Parse mDNS signatures
            mdns_map: Dict[str, MdnsSignature] = {}
            for svc_type, item in data.get("mdns_signatures", {}).items():
                try:
                    clean_type = str(svc_type).strip().lower()
                    mdns_map[clean_type] = MdnsSignature(
                        vendor=str(item.get("vendor", "Unknown")),
                        category=str(item.get("category", "Unknown Device")),
                        os_family=str(item.get("os_family", "Unknown")),
                        service_type=clean_type,
                    )
                except Exception:
                    continue
            self.mdns_signatures = mdns_map

            return bool(self.dhcp_signatures or self.mdns_signatures)

    def match_dhcp(
        self, param_list: List[int], vendor_class: Optional[str] = None
    ) -> Optional[DeviceFingerprintMatch]:
        """
        Matches a client's DHCP Option 55 parameter sequence against the signature database.
        Checks exact matches first, then prefix/vendor class matches.
        """
        if not param_list:
            return None

        incoming_tuple = tuple(int(p) for p in param_list)
        with self._lock:
            # Pass 1: Exact matches
            for sig in self.dhcp_signatures:
                if sig.param_list == incoming_tuple:
                    if not sig.vendor_class_pattern or (
                        vendor_class and re.search(sig.vendor_class_pattern, vendor_class, re.IGNORECASE)
                    ):
                        return DeviceFingerprintMatch(
                            vendor=sig.vendor,
                            category=sig.category,
                            os_family=sig.os_family,
                            source="DHCP Option 55 (Exact Match)",
                            confidence=sig.confidence,
                        )

            # Pass 2: Fuzzy/prefix matches
            for sig in self.dhcp_signatures:
                if sig.matches(incoming_tuple, vendor_class):
                    return DeviceFingerprintMatch(
                        vendor=sig.vendor,
                        category=sig.category,
                        os_family=sig.os_family,
                        source="DHCP Option 55 (Prefix Match)",
                        confidence="MEDIUM" if sig.confidence == "HIGH" else sig.confidence,
                    )

        return None

    def match_mdns(self, service_types: List[str]) -> Optional[DeviceFingerprintMatch]:
        """Matches advertised mDNS service types against the service dictionary."""
        if not service_types:
            return None

        with self._lock:
            for raw_svc in service_types:
                svc = raw_svc.strip().lower()
                # Exact or substring match (e.g. "_googlecast._tcp.local" matches "_googlecast._tcp")
                for registered_type, sig in self.mdns_signatures.items():
                    if registered_type in svc:
                        return DeviceFingerprintMatch(
                            vendor=sig.vendor,
                            category=sig.category,
                            os_family=sig.os_family,
                            source=f"mDNS Service ({registered_type})",
                            confidence="HIGH",
                        )

        return None


class DhcpFingerprintStore:
    """Thread-safe store mapping client MAC addresses to captured DHCP Option 55/60 fingerprints."""
    _instance: Optional["DhcpFingerprintStore"] = None
    _singleton_lock = threading.Lock()

    def __init__(self, max_entries: int = 500):
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._access_lock = threading.Lock()
        self.max_entries = max_entries

    @classmethod
    def get_instance(cls) -> "DhcpFingerprintStore":
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def record(
        self,
        mac: str,
        param_list: List[int],
        vendor_class: Optional[str] = None,
        hostname: Optional[str] = None,
        now: Optional[float] = None,
    ):
        if not mac or not param_list:
            return
        mac_key = mac.upper()
        if now is None:
            now = time.time()
        with self._access_lock:
            if len(self._entries) >= self.max_entries and mac_key not in self._entries:
                oldest_mac = min(self._entries.keys(), key=lambda k: self._entries[k].get("timestamp", 0))
                self._entries.pop(oldest_mac, None)

            self._entries[mac_key] = {
                "mac": mac_key,
                "param_list": param_list,
                "vendor_class": vendor_class,
                "hostname": hostname,
                "timestamp": now,
            }

    def get(self, mac: str) -> Optional[Dict[str, Any]]:
        if not mac:
            return None
        with self._access_lock:
            return self._entries.get(mac.upper())

    def clear(self):
        with self._access_lock:
            self._entries.clear()
