"""
MAC Address Vendor and OUI Resolver.
Determines manufacturer identity, country of registration, IEEE block types,
and detects locally administered (randomized) private MAC addresses.
"""

import json
import urllib.request
from typing import Tuple, Dict, Optional
from dataclasses import dataclass

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
    ):
        self.api_url = api_url
        self.timeout = timeout
        self.user_agent = user_agent
        # Cache to prevent redundant HTTP queries for the same MAC
        self._cache: Dict[str, Tuple[str, bool]] = {}
        self._info_cache: Dict[str, MacVendorInfo] = {}

    @staticmethod
    def is_randomized_mac(mac: str) -> bool:
        """
        Checks if the locally administered bit (bit 1 of first byte) is set.
        Modern iOS, Android, and Windows devices set this bit when randomizing their MAC.
        Example: b6:be:e4:... -> b6 in binary is 10110110 (bit 1 is 1 -> True).
        """
        if not mac or ":" not in mac:
            return False
        try:
            first_byte = int(mac.split(":")[0], 16)
            return bool(first_byte & 0x02)
        except Exception:
            return False

    def resolve_details(self, mac: str) -> MacVendorInfo:
        """
        Performs an OUI lookup extracting company, country of registration,
        IEEE block size type, and randomization status.
        """
        if not mac or mac in ("LOCAL", "N/A"):
            return MacVendorInfo(company="N/A", is_randomized=False)

        mac_upper = mac.upper()
        if mac_upper in self._info_cache:
            return self._info_cache[mac_upper]

        is_rand = self.is_randomized_mac(mac_upper)
        info = MacVendorInfo(
            company="Randomized Private MAC" if is_rand else "Unknown Vendor",
            is_randomized=is_rand,
        )

        try:
            url = self.api_url.format(mac=mac_upper)
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
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
        except Exception:
            pass

        self._info_cache[mac_upper] = info
        self._cache[mac_upper] = (info.display_str, info.is_randomized)
        return info

    def resolve(self, mac: str) -> Tuple[str, bool]:
        """
        Resolves the hardware vendor display name (with country code) and randomization status.
        Returns (vendor_name, is_randomized).
        """
        if not mac or mac in ("LOCAL", "N/A"):
            return "N/A", False

        mac_upper = mac.upper()
        if mac_upper in self._cache:
            return self._cache[mac_upper]

        info = self.resolve_details(mac_upper)
        return info.display_str, info.is_randomized
