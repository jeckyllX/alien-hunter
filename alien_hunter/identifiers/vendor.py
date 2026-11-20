"""
MAC Address Vendor and OUI Resolver.
Determines manufacturer identity, country of registration, IEEE block types,
and detects locally administered (randomized) private MAC addresses.
"""

import collections
import json
import threading
import urllib.parse
import urllib.request
from typing import Tuple, Optional
from dataclasses import dataclass

from ..http_utils import safe_urlopen, read_bounded

# ============================================================================
# Configuration Constants
# ============================================================================
# Public OUI vendor lookup API endpoint. {mac} placeholder is replaced with target MAC.
DEFAULT_MAC_API_URL = "https://api.maclookup.app/v2/macs/{mac}"

# Network timeout (seconds) for vendor lookup requests.
DEFAULT_HTTP_TIMEOUT = 1.8

# User-Agent header sent with HTTP requests.
DEFAULT_USER_AGENT = "AlienHunter/1.0"


@dataclass
class MacVendorInfo:
    """
    Detailed metadata returned by IEEE OUI registration registries:
    - company: Registered corporate name of the manufacturer.
    - country: Two-letter ISO country code of headquarters (e.g. US, TW, GB, CN).
    - block_type: IEEE assignment tier:
        * MA-L (Large: 24-bit OUI, ~16.7M addresses) - Global consumer electronics brands.
        * MA-M (Medium: 28-bit OUI, ~1.0M addresses).
        * MA-S (Small: 36-bit OUI, ~4K addresses) - Niche or specialized IoT equipment.
    - is_randomized: Whether the address is an OS-level private/ephemeral MAC.
    - prefix: The 6-character hex OUI prefix (e.g. 001A2B).
    """
    company: str = "Unknown Vendor"
    country: Optional[str] = None
    block_type: Optional[str] = None
    is_randomized: bool = False
    prefix: Optional[str] = None

    @property
    def display_str(self) -> str:
        """Formats company name with country code for security visibility."""
        if self.is_randomized:
            return "Randomized Private MAC"
        if self.company and self.company != "Unknown Vendor":
            if self.country:
                return f"{self.company} ({self.country})"
            return self.company
        return "Unknown Vendor"


class MacVendorResolver:
    """Resolves MAC hardware vendors and identifies privacy-randomized MAC addresses."""

    def __init__(
        self,
        api_url: str = DEFAULT_MAC_API_URL,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        max_cache_size: int = 4096,
    ):
        self.api_url = api_url
        self.timeout = timeout
        self.user_agent = user_agent
        self._max_cache_size = max(1, max_cache_size)
        self._lock = threading.Lock()
        # Bounded cache to prevent redundant HTTP queries for the same MAC
        self._cache: "collections.OrderedDict[str, Tuple[str, bool]]" = collections.OrderedDict()
        self._info_cache: "collections.OrderedDict[str, MacVendorInfo]" = collections.OrderedDict()

    @staticmethod
    def is_randomized_mac(mac: str) -> bool:
        """
        Checks if the locally administered bit (bit 1 of first byte) is set.
        Modern iOS, Android, and Windows devices set this bit when randomizing their MAC.
        Example: b6:be:e4:... -> b6 in binary is 10110110 (bit 1 is 1 -> True).
        """
        if not mac:
            return False
        norm = mac.strip().replace("-", ":")
        if ":" not in norm:
            return False
        try:
            first_byte = int(norm.split(":", 1)[0], 16)
            return bool(first_byte & 0x02)
        except Exception:
            return False

    def _store_cache(self, mac_upper: str, info: MacVendorInfo) -> None:
        """Stores a resolved MAC vendor entry with bounded LRU eviction."""
        with self._lock:
            if mac_upper in self._info_cache:
                self._info_cache.move_to_end(mac_upper)
            elif len(self._info_cache) >= self._max_cache_size:
                self._info_cache.popitem(last=False)
            self._info_cache[mac_upper] = info

            if mac_upper in self._cache:
                self._cache.move_to_end(mac_upper)
            elif len(self._cache) >= self._max_cache_size:
                self._cache.popitem(last=False)
            self._cache[mac_upper] = (info.display_str, info.is_randomized)

    def resolve_details(self, mac: str) -> MacVendorInfo:
        """
        Performs an OUI lookup extracting company, country of registration,
        IEEE block size type, and randomization status.
        """
        if not mac or mac in ("LOCAL", "N/A"):
            return MacVendorInfo(company="N/A", is_randomized=False)

        mac_upper = mac.strip().upper().replace("-", ":")
        with self._lock:
            cached = self._info_cache.get(mac_upper)
            if cached is not None:
                self._info_cache.move_to_end(mac_upper)
                return cached

        is_rand = self.is_randomized_mac(mac_upper)
        info = MacVendorInfo(
            company="Randomized Private MAC" if is_rand else "Unknown Vendor",
            is_randomized=is_rand,
        )

        # Skip external HTTP calls for randomized MACs to avoid leaking local client identifiers
        if is_rand:
            self._store_cache(mac_upper, info)
            return info

        lookup_success = False
        try:
            encoded_mac = urllib.parse.quote(mac_upper, safe="")
            url = self.api_url.format(mac=encoded_mac)
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            with safe_urlopen(
                req, timeout=self.timeout, allowed_schemes=("https", "http"), allow_redirects=False
            ) as resp:
                status = getattr(resp, "status", 200)
                if status == 200:
                    data = json.loads(read_bounded(resp, 65536).decode("utf-8"))
                    if isinstance(data, dict):
                        company = data.get("company")
                        country = data.get("country")
                        block_type = data.get("blockType")
                        prefix = data.get("macPrefix")
                        api_rand = data.get("isRand", False) or data.get("isPrivate", False)

                        if company:
                            info.company = company
                        if country:
                            info.country = country
                        if block_type:
                            info.block_type = block_type
                        if prefix:
                            info.prefix = prefix
                        if api_rand:
                            info.is_randomized = True
                        lookup_success = True
        except Exception:
            pass

        # Only cache authoritative HTTP 200 responses so transient failures can retry later
        if lookup_success:
            self._store_cache(mac_upper, info)
        return info

    def resolve(self, mac: str) -> Tuple[str, bool]:
        """
        Resolves the hardware vendor display name (with country code) and randomization status.
        Returns (vendor_name, is_randomized).
        """
        if not mac or mac in ("LOCAL", "N/A"):
            return "N/A", False

        mac_upper = mac.strip().upper().replace("-", ":")
        with self._lock:
            cached = self._cache.get(mac_upper)
            if cached is not None:
                self._cache.move_to_end(mac_upper)
                return cached

        info = self.resolve_details(mac_upper)
        return info.display_str, info.is_randomized
