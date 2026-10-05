"""
Change-detection gate for network posture LLM calls.

The daemon audits every poll interval, but the posture narrative only changes
when security-relevant inputs change. The gate fingerprints those inputs and
reuses the last successful assessment otherwise.

Refresh triggers (in priority order):
  1. forced           - explicit on-demand request (CLI / web trigger)
  2. initial          - no successful assessment yet
  3. tier_escalated   - deterministic tier became more severe (immediate)
  4. tier_deescalated - tier became less severe (subject to ``min_interval``)
  5. inputs_changed   - fingerprint differs (subject to ``min_interval``)
  6. stale            - cached assessment older than ``max_age``

Failed calls are never cached; after a failure, non-forced retries wait
``min_interval``. While a refresh is deferred, callers fall back to the
deterministic posture, so the reported tier is always current.
"""

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, List, Optional, Tuple

from .models import NetworkPosture, NetworkPostureAssessment

_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_SAMPLES_RE = re.compile(r"\(Samples:[^)]*\)", re.IGNORECASE)
# IPv4 alternative first so addresses are matched whole and preserved.
_IP_OR_NUM_RE = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)|\d+(?:\.\d+)?")

_TIER_RANK = {NetworkPosture.SECURE: 0, NetworkPosture.WARNING: 1, NetworkPosture.CRITICAL: 2}


@dataclass(frozen=True)
class PostureDecision:
    refresh: bool
    reason: str


@dataclass
class _CacheEntry:
    fingerprint: str
    tier: NetworkPosture
    assessment: NetworkPostureAssessment
    created_at: float


def normalize_threat(threat: str) -> str:
    """
    Reduces a threat string to its stable identity.

    Volatile counters (e.g. "Observed 53 MACs in 2.0s") and MAC sample lists
    change every scan without changing meaning. IPv4 addresses are kept since
    they identify the affected host. Port-level changes are tracked separately
    through device open ports.
    """
    text = _SAMPLES_RE.sub("", threat)
    text = _MAC_RE.sub("<mac>", text)
    text = _IP_OR_NUM_RE.sub(lambda m: m.group("ip") or "#", text)
    return " ".join(text.split()).lower()


def _port_numbers(open_ports: List[str]) -> Tuple[int, ...]:
    nums = set()
    for p in open_ports or []:
        try:
            nums.add(int(str(p).split()[0].split("/")[0]))
        except (ValueError, IndexError):
            continue
    return tuple(sorted(nums))


def compute_fingerprint(
    audit: Any,
    tier: NetworkPosture,
    categorize: Optional[Callable[[Any], Optional[str]]] = None,
) -> str:
    """
    Stable hash over the inputs that materially change the posture assessment.

    Deliberately excluded (churn without security meaning): IPs (DHCP renewals),
    online/offline transitions of trusted devices (phones sleeping), banners and
    passive-sniff notes (intermittent), timestamps.
    Alien presence is included: ``is_alien`` is only set for online untrusted hosts.
    """
    devices = []
    for d in getattr(audit, "devices", []) or []:
        category = categorize(d) if categorize else None
        devices.append(
            (
                str(getattr(d, "mac", "")).upper(),
                bool(getattr(d, "trusted", False)),
                bool(getattr(d, "is_alien", False)),
                _port_numbers(getattr(d, "open_ports", [])),
                category or "",
            )
        )
    devices.sort()
    threats = sorted({normalize_threat(t) for t in getattr(audit, "threats", []) or []})
    payload = {"tier": str(tier), "devices": devices, "threats": threats}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class PostureGate:
    """Thread-safe cache + refresh policy for network posture assessments."""

    def __init__(
        self,
        min_interval: float = 900.0,
        max_age: float = 86400.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        if min_interval < 0 or max_age <= 0:
            raise ValueError("min_interval must be >= 0 and max_age > 0")
        self.min_interval = float(min_interval)
        self.max_age = float(max_age)
        self._clock = clock
        self._lock = threading.Lock()
        self._entry: Optional[_CacheEntry] = None
        self._last_attempt: Optional[float] = None
        self._last_failed = False

    def decide(self, fingerprint: str, tier: NetworkPosture, force: bool = False) -> PostureDecision:
        with self._lock:
            if force:
                return PostureDecision(True, "forced")
            now = self._clock()
            in_cooldown = self._last_attempt is not None and (now - self._last_attempt) < self.min_interval
            # After a provider failure every non-forced path waits, so an outage
            # costs at most one call per min_interval.
            if self._last_failed and in_cooldown:
                return PostureDecision(False, "retry_cooldown")

            entry = self._entry
            if entry is None:
                return PostureDecision(True, "initial")
            if tier != entry.tier:
                if _TIER_RANK[tier] > _TIER_RANK[entry.tier]:
                    return PostureDecision(True, "tier_escalated")
                # De-escalation can flap (intermittent threats); caller shows the
                # deterministic tier until the cooldown elapses.
                if in_cooldown:
                    return PostureDecision(False, "tier_deescalated_cooldown")
                return PostureDecision(True, "tier_deescalated")
            if fingerprint != entry.fingerprint:
                if in_cooldown:
                    return PostureDecision(False, "inputs_changed_cooldown")
                return PostureDecision(True, "inputs_changed")
            if (now - entry.created_at) >= self.max_age:
                return PostureDecision(True, "stale")
            return PostureDecision(False, "unchanged")

    def record_failure(self) -> None:
        with self._lock:
            self._last_attempt = self._clock()
            self._last_failed = True

    def store(self, fingerprint: str, tier: NetworkPosture, assessment: NetworkPostureAssessment) -> None:
        with self._lock:
            now = self._clock()
            self._entry = _CacheEntry(fingerprint, tier, assessment, now)
            self._last_attempt = now
            self._last_failed = False

    def cached(self, tier: NetworkPosture, current_threats: List[str]) -> Optional[NetworkPostureAssessment]:
        """Copy of the cached assessment with current threat strings, if it matches ``tier``."""
        with self._lock:
            if self._entry is None or self._entry.tier != tier:
                return None
            return replace(self._entry.assessment, threats_found=list(current_threats))

    def cache_age(self) -> Optional[float]:
        with self._lock:
            return None if self._entry is None else self._clock() - self._entry.created_at
