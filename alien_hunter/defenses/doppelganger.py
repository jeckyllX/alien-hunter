"""
Hardware Doppelgänger & Identity Spoofing Detector.
Detects MAC spoofing and device masquerading attacks (MITRE ATT&CK T1036)
by comparing live TCP/IP stack fingerprints (TTL, TCP window sizes, TCP options,
and DHCP Option 55 parameter lists) against established device baselines.
"""

import collections
from dataclasses import dataclass
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from ..models import StackTtl, OsFamily, estimate_initial_ttl


@dataclass(frozen=True)
class OsProfileDefinition:
    """Encapsulates canonical OS signature patterns and expected stack baselines."""
    family: OsFamily
    expected_ttl: StackTtl
    keywords: Tuple[str, ...]


# Canonical, declarative OS profile registry (single source of truth).
# NETWORK precedes APPLE so "Cisco IOS" matches NETWORK rather than Apple "ios".
OS_PROFILES: Tuple[OsProfileDefinition, ...] = (
    OsProfileDefinition(
        family=OsFamily.NETWORK,
        expected_ttl=StackTtl.NETWORK,
        keywords=("cisco", "juniper", "arista", "solaris", "fortinet", "mikrotik"),
    ),
    OsProfileDefinition(
        family=OsFamily.WINDOWS,
        expected_ttl=StackTtl.WINDOWS,
        keywords=("windows", "microsoft", "msft", "win10", "win11", "winserver", "xbox"),
    ),
    OsProfileDefinition(
        family=OsFamily.APPLE,
        expected_ttl=StackTtl.UNIX,
        keywords=("apple", "ios", "macos", "os x", "darwin", "iphone", "ipad", "macbook", "imac", "tvos"),
    ),
    OsProfileDefinition(
        family=OsFamily.LINUX_IOT,
        expected_ttl=StackTtl.UNIX,
        keywords=(
            "linux", "android", "ubuntu", "debian", "raspbian", "raspberry",
            "synology", "qnap", "sonos", "google", "nest", "chromecast",
            "espressif", "tasmota", "openwrt", "busybox", "alpine", "fedora", "centos"
        ),
    ),
    OsProfileDefinition(
        family=OsFamily.BSD,
        expected_ttl=StackTtl.UNIX,
        keywords=("freebsd", "openbsd", "netbsd", "pfsense", "opnsense", "truenas"),
    ),
)


class DoppelgangerDetector:
    """
    Evaluates observed hardware stack telemetry against declared or learned
    device baselines to detect identity hijacking and MAC address cloning.
    """

    MAX_RUNTIME_BASELINES = 4096
    _lock = threading.Lock()
    _runtime_baselines: "collections.OrderedDict[str, Dict[str, Any]]" = collections.OrderedDict()

    @classmethod
    def match_profile(cls, text: Optional[str]) -> Optional[OsProfileDefinition]:
        """Matches arbitrary text against the canonical OS profile registry."""
        if not text:
            return None
        text_lower = text.strip().lower()
        for profile in OS_PROFILES:
            if text_lower == profile.family.value.lower():
                return profile
            for k in profile.keywords:
                if len(k) <= 4:
                    if re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", text_lower):
                        return profile
                elif k in text_lower:
                    return profile
        return None

    @classmethod
    def estimate_initial_ttl(cls, observed_ttl: int) -> int:
        """Estimates the initial TTL set by the originating operating system kernel."""
        return estimate_initial_ttl(observed_ttl)

    @classmethod
    def infer_expected_ttl(
        cls,
        whitelist_entry: Optional[Dict[str, Any]] = None,
        vendor: str = "",
        name: str = "",
    ) -> Optional[int]:
        """
        Determines the expected initial TTL for a device based on
        whitelist configuration, declared OS, or vendor signatures.
        """
        if whitelist_entry:
            # 1. Explicitly configured TTL
            configured_ttl = whitelist_entry.get("baseline_ttl") or whitelist_entry.get("expected_ttl")
            if isinstance(configured_ttl, int) and configured_ttl in (64, 128, 255):
                return configured_ttl

            # 2. Configured or previously learned OS
            known_os = str(
                whitelist_entry.get("baseline_os")
                or whitelist_entry.get("expected_os")
                or whitelist_entry.get("device_type")
                or ""
            )
            profile = cls.match_profile(known_os)
            if profile:
                return profile.expected_ttl.value

        # 3. Inferred from hardware vendor and device name
        profile = cls.match_profile(f"{vendor} {name}")
        return profile.expected_ttl.value if profile else None

    @classmethod
    def infer_expected_os_family(
        cls,
        whitelist_entry: Optional[Dict[str, Any]] = None,
        vendor: str = "",
        name: str = "",
    ) -> Optional[OsFamily]:
        """Categorizes expected operating system into a normalized OsFamily."""
        if whitelist_entry:
            declared = str(
                whitelist_entry.get("baseline_os")
                or whitelist_entry.get("expected_os")
                or whitelist_entry.get("device_type")
                or ""
            )
            profile = cls.match_profile(declared)
            if profile:
                return profile.family

        profile = cls.match_profile(f"{vendor} {name}")
        return profile.family if profile else None

    @classmethod
    def infer_allowed_os_profiles(
        cls,
        whitelist_entry: Optional[Dict[str, Any]] = None,
    ) -> List[OsProfileDefinition]:
        """Resolves optional per-device ``allowed_os_families`` (e.g. for WSL2 or VMs)."""
        if not whitelist_entry:
            return []
        raw = whitelist_entry.get("allowed_os_families")
        if not raw:
            return []
        items = [raw] if isinstance(raw, str) else list(raw) if isinstance(raw, (list, tuple, set)) else []
        profiles: List[OsProfileDefinition] = []
        seen_families = set()
        for item in items:
            profile = cls.match_profile(str(item))
            if profile and profile.family not in seen_families:
                seen_families.add(profile.family)
                profiles.append(profile)
        return profiles

    @classmethod
    def normalize_observed_os(cls, os_str: Optional[str]) -> Optional[OsFamily]:
        """Normalizes an observed fingerprint string into an OsFamily."""
        profile = cls.match_profile(os_str)
        return profile.family if profile else None

    @classmethod
    def is_os_family_conflict(
        cls,
        expected: OsFamily,
        observed: OsFamily,
        vendor: str = "",
    ) -> bool:
        """
        Evaluates whether an observed OS family conflicts with the expected family.
        Cross-tolerance between Apple and Linux/IoT is permitted unless the vendor is explicitly Apple.
        Windows vs Unix-like OS and Network appliance vs host OS are hard conflicts.
        """
        if expected == observed:
            return False

        # Network OS conflicts with any non-network concrete OS family
        concrete_host_families = (OsFamily.WINDOWS, OsFamily.APPLE, OsFamily.LINUX_IOT, OsFamily.BSD)
        if (expected == OsFamily.NETWORK and observed in concrete_host_families) or \
           (observed == OsFamily.NETWORK and expected in concrete_host_families):
            return True

        # Windows vs Unix-like is always a hard conflict
        if (expected == OsFamily.WINDOWS and observed in (OsFamily.APPLE, OsFamily.LINUX_IOT, OsFamily.BSD)) or \
           (expected in (OsFamily.APPLE, OsFamily.LINUX_IOT, OsFamily.BSD) and observed == OsFamily.WINDOWS):
            return True

        # Apple hardware transmitting generic Linux/IoT fingerprints indicates a non-Apple impersonator
        if expected == OsFamily.APPLE and observed == OsFamily.LINUX_IOT and "apple" in vendor.lower():
            return True

        return False

    @classmethod
    def check_device(
        cls,
        ip: str,
        mac: str,
        display_name: str,
        observed_ttl: Optional[int] = None,
        current_os: Optional[str] = None,
        dhcp_os: Optional[str] = None,
        whitelist_entry: Optional[Dict[str, Any]] = None,
        vendor: str = "",
        update_baseline: bool = True,
    ) -> List[str]:
        """
        Validates live stack observations against expected baselines.
        Returns a list of critical threat warnings if stack parameters conflict.
        """
        threats: List[str] = []
        mac_upper = mac.upper() if mac else ""
        if not mac_upper or mac_upper.startswith("N/A"):
            return threats

        expected_ttl = cls.infer_expected_ttl(whitelist_entry, vendor=vendor, name=display_name)
        expected_family = cls.infer_expected_os_family(whitelist_entry, vendor=vendor, name=display_name)
        allowed_profiles = cls.infer_allowed_os_profiles(whitelist_entry)
        allowed_families = {p.family for p in allowed_profiles}
        allowed_ttls = {p.expected_ttl.value for p in allowed_profiles}

        # 1. TTL Conflict Check
        if observed_ttl is not None and expected_ttl is not None:
            estimated_initial = cls.estimate_initial_ttl(observed_ttl)
            valid_ttls = {expected_ttl} | allowed_ttls
            if estimated_initial not in valid_ttls:
                threats.append(
                    f"CRITICAL: Hardware Doppelgänger / MAC Spoofing on {display_name} ({ip}, MAC: {mac_upper})! "
                    f"Observed stack TTL={observed_ttl} (estimated initial {estimated_initial}) conflicts with "
                    f"trusted baseline (Expected TTL={expected_ttl}). Potential identity cloning or rogue host impersonation!"
                )

        # 2. OS Family Signature Conflict Check (TCP SYN or DHCP Option 55)
        active_os = current_os or dhcp_os
        observed_family = cls.normalize_observed_os(active_os)

        if expected_family and observed_family and observed_family not in allowed_families:
            if cls.is_os_family_conflict(expected_family, observed_family, vendor=vendor):
                threats.append(
                    f"CRITICAL: Hardware Doppelgänger / OS Stack Masquerade on {display_name} ({ip}, MAC: {mac_upper})! "
                    f"Observed network stack signature '{active_os}' ({observed_family.value}) conflicts with "
                    f"trusted identity profile '{expected_family.value}'. Possible rogue device using cloned MAC address!"
                )

        # 3. Dynamic Runtime Baseline Drift
        # If no explicit static baseline was declared, track runtime consistency across scans
        if update_baseline and observed_ttl is not None:
            est_ttl = cls.estimate_initial_ttl(observed_ttl)
            with cls._lock:
                existing = cls._runtime_baselines.get(mac_upper)
                if existing:
                    cls._runtime_baselines.move_to_end(mac_upper)
                    prev_ttl = existing.get("estimated_ttl")
                    allowed_runtime_ttls = ({expected_ttl} if expected_ttl is not None else set()) | allowed_ttls
                    if prev_ttl and prev_ttl != est_ttl and est_ttl not in allowed_runtime_ttls and not threats:
                        threats.append(
                            f"CRITICAL: Hardware Doppelgänger / Runtime Stack Drift on {display_name} ({ip}, MAC: {mac_upper})! "
                            f"Host operating system stack abruptly shifted from initial TTL={prev_ttl} to TTL={est_ttl}. "
                            f"Indicates rogue device took over trusted MAC address!"
                        )
                else:
                    if len(cls._runtime_baselines) >= cls.MAX_RUNTIME_BASELINES:
                        cls._runtime_baselines.popitem(last=False)
                    cls._runtime_baselines[mac_upper] = {
                        "estimated_ttl": est_ttl,
                        "os_family": observed_family,
                        "first_seen": time.time(),
                    }

        return threats

    @classmethod
    def check_inventory(
        cls,
        devices: List[Any],
        whitelist: Dict[str, dict],
    ) -> List[str]:
        """Audits an entire device inventory for Hardware Doppelgänger anomalies."""
        threats: List[str] = []
        for dev in devices:
            mac = getattr(dev, "mac", "")
            if not mac or mac.startswith("N/A"):
                continue

            mac_upper = mac.upper()
            dev_threats = cls.check_device(
                ip=getattr(dev, "ip", "Unknown"),
                mac=mac_upper,
                display_name=getattr(dev, "display_name", dev.ip),
                observed_ttl=getattr(dev, "observed_ttl", None),
                current_os=getattr(dev, "tcp_syn_fingerprint", None),
                dhcp_os=getattr(dev, "dhcp_fingerprint", None),
                whitelist_entry=whitelist.get(mac_upper),
                vendor=getattr(dev, "vendor", ""),
            )
            threats.extend(dev_threats)

        return threats

    @classmethod
    def reset_runtime_baselines(cls) -> None:
        """Clears the runtime baseline store (useful for test isolation)."""
        with cls._lock:
            cls._runtime_baselines.clear()
