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
class SsdpSignature:
    """Canonical SSDP / UPnP device signature."""
    vendor: str
    category: str
    os_family: str
    server_pattern: Optional[str] = None
    target_pattern: Optional[str] = None
    confidence: str = "HIGH"

    def matches(self, server: Optional[str] = None, target: Optional[str] = None) -> bool:
        if self.server_pattern and server:
            if re.search(self.server_pattern, server, re.IGNORECASE):
                return True
        if self.target_pattern and target:
            if re.search(self.target_pattern, target, re.IGNORECASE):
                return True
        return False


@dataclass(frozen=True)
class TcpSynSignature:
    """Canonical passive TCP SYN stack signature."""
    vendor: str
    category: str
    os_family: str
    initial_ttl: int
    options: Tuple[int, ...]
    confidence: str = "HIGH"

    def matches(self, ttl: int, incoming_options: Tuple[int, ...]) -> bool:
        # Match TTL bucket (64, 128, 255) allowing minor decrements across routed hops
        ttl_match = False
        if self.initial_ttl == 64 and (56 <= ttl <= 64):
            ttl_match = True
        elif self.initial_ttl == 128 and (116 <= ttl <= 128):
            ttl_match = True
        elif self.initial_ttl == 255 and (240 <= ttl <= 255):
            ttl_match = True

        if not ttl_match:
            return False

        # Exact sequence match on options
        if self.options == incoming_options:
            return True

        # Subset match if options length >= 4
        if len(self.options) >= 4 and len(incoming_options) >= 4:
            min_len = min(len(self.options), len(incoming_options))
            if self.options[:min_len] == incoming_options[:min_len]:
                return True

        return False


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
        self.ssdp_signatures: List[SsdpSignature] = []
        self.tcp_syn_signatures: List[TcpSynSignature] = []
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

            # Parse SSDP signatures
            ssdp_list: List[SsdpSignature] = []
            for item in data.get("ssdp_signatures", []):
                try:
                    ssdp_list.append(
                        SsdpSignature(
                            vendor=str(item.get("vendor", "Unknown")),
                            category=str(item.get("category", "Unknown Device")),
                            os_family=str(item.get("os_family", "Unknown")),
                            server_pattern=item.get("server_pattern"),
                            target_pattern=item.get("target_pattern"),
                            confidence=str(item.get("confidence", "HIGH")),
                        )
                    )
                except Exception:
                    continue
            self.ssdp_signatures = ssdp_list

            # Parse TCP SYN signatures
            tcp_syn_list: List[TcpSynSignature] = []
            for item in data.get("tcp_syn_signatures", []):
                try:
                    opts = tuple(int(x) for x in item.get("options", []))
                    ttl = int(item.get("initial_ttl", 64))
                    tcp_syn_list.append(
                        TcpSynSignature(
                            vendor=str(item.get("vendor", "Unknown")),
                            category=str(item.get("category", "Unknown Device")),
                            os_family=str(item.get("os_family", "Unknown")),
                            initial_ttl=ttl,
                            options=opts,
                            confidence=str(item.get("confidence", "HIGH")),
                        )
                    )
                except Exception:
                    continue
            self.tcp_syn_signatures = tcp_syn_list

            return bool(
                self.dhcp_signatures
                or self.mdns_signatures
                or self.ssdp_signatures
                or self.tcp_syn_signatures
            )

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

    def match_ssdp(
        self, server: Optional[str] = None, target: Optional[str] = None
    ) -> Optional[DeviceFingerprintMatch]:
        """Matches SSDP/UPnP SERVER or ST/NT headers against registered SSDP signatures."""
        if not server and not target:
            return None

        with self._lock:
            for sig in self.ssdp_signatures:
                if sig.matches(server=server, target=target):
                    return DeviceFingerprintMatch(
                        vendor=sig.vendor,
                        category=sig.category,
                        os_family=sig.os_family,
                        source="SSDP / UPnP",
                        confidence=sig.confidence,
                    )

        return None

    def match_tcp_syn(
        self, ttl: int, options: List[int], window_size: Optional[int] = None
    ) -> Optional[DeviceFingerprintMatch]:
        """
        Matches passive TCP SYN stack parameters (IP TTL and TCP options ordering)
        against canonical operating system TCP stack fingerprints.
        """
        if not ttl or not options:
            return None

        opts_tuple = tuple(int(x) for x in options)
        with self._lock:
            # Pass 1: Exact matches
            for sig in self.tcp_syn_signatures:
                if sig.initial_ttl == ttl and sig.options == opts_tuple:
                    return DeviceFingerprintMatch(
                        vendor=sig.vendor,
                        category=sig.category,
                        os_family=sig.os_family,
                        source="Passive TCP SYN (Exact Match)",
                        confidence=sig.confidence,
                    )

            # Pass 2: Fuzzy/tolerant matches (hop decrements and prefix option match)
            for sig in self.tcp_syn_signatures:
                if sig.matches(ttl, opts_tuple):
                    return DeviceFingerprintMatch(
                        vendor=sig.vendor,
                        category=sig.category,
                        os_family=sig.os_family,
                        source="Passive TCP SYN",
                        confidence="MEDIUM" if sig.confidence == "HIGH" else sig.confidence,
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


class SsdpFingerprintStore:
    """Thread-safe store mapping client IP addresses to SSDP/UPnP discovered metadata."""
    _instance: Optional["SsdpFingerprintStore"] = None
    _singleton_lock = threading.Lock()

    def __init__(self, max_entries: int = 500):
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._access_lock = threading.Lock()
        self.max_entries = max_entries

    @classmethod
    def get_instance(cls) -> "SsdpFingerprintStore":
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def record(
        self,
        ip: str,
        server: Optional[str] = None,
        location: Optional[str] = None,
        device_name: Optional[str] = None,
        manufacturer: Optional[str] = None,
        model: Optional[str] = None,
        services: Optional[List[str]] = None,
        match: Optional[DeviceFingerprintMatch] = None,
        now: Optional[float] = None,
    ):
        if not ip:
            return
        if now is None:
            now = time.time()
        with self._access_lock:
            if len(self._entries) >= self.max_entries and ip not in self._entries:
                oldest_ip = min(self._entries.keys(), key=lambda k: self._entries[k].get("timestamp", 0))
                self._entries.pop(oldest_ip, None)

            existing = self._entries.get(ip, {})
            merged_services = list(set((existing.get("services") or []) + (services or [])))
            self._entries[ip] = {
                "ip": ip,
                "server": server or existing.get("server"),
                "location": location or existing.get("location"),
                "device_name": device_name or existing.get("device_name"),
                "manufacturer": manufacturer or existing.get("manufacturer"),
                "model": model or existing.get("model"),
                "services": merged_services,
                "match": match or existing.get("match"),
                "timestamp": now,
            }

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        if not ip:
            return None
        with self._access_lock:
            return self._entries.get(ip)

    def all(self) -> Dict[str, Dict[str, Any]]:
        with self._access_lock:
            return dict(self._entries)

    def clear(self):
        with self._access_lock:
            self._entries.clear()


class TcpSynFingerprintStore:
    """Thread-safe store mapping client IP addresses to observed TCP SYN stack parameters."""
    _instance: Optional["TcpSynFingerprintStore"] = None
    _singleton_lock = threading.Lock()

    def __init__(self, max_entries: int = 500):
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._access_lock = threading.Lock()
        self.max_entries = max_entries

    @classmethod
    def get_instance(cls) -> "TcpSynFingerprintStore":
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def record(
        self,
        ip: str,
        ttl: int,
        options: List[int],
        window_size: Optional[int] = None,
        match: Optional[DeviceFingerprintMatch] = None,
        now: Optional[float] = None,
    ):
        if not ip or not ttl:
            return
        if now is None:
            now = time.time()
        with self._access_lock:
            if len(self._entries) >= self.max_entries and ip not in self._entries:
                oldest_ip = min(self._entries.keys(), key=lambda k: self._entries[k].get("timestamp", 0))
                self._entries.pop(oldest_ip, None)

            existing = self._entries.get(ip, {})
            self._entries[ip] = {
                "ip": ip,
                "ttl": ttl,
                "options": options,
                "window_size": window_size or existing.get("window_size"),
                "match": match or existing.get("match"),
                "timestamp": now,
            }

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        if not ip:
            return None
        with self._access_lock:
            return self._entries.get(ip)

    def all(self) -> Dict[str, Dict[str, Any]]:
        with self._access_lock:
            return dict(self._entries)

    def clear(self):
        with self._access_lock:
            self._entries.clear()
