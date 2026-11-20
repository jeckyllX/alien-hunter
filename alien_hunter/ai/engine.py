"""
AI Security Analysis Engine for Alien Hunter.
Coordinates provider selection, MAC/port caching, and concurrent assessment execution.
"""

import collections
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import threading
import time
from typing import Dict, List, Any, Optional, Tuple, Type

from .base import BaseAIProvider
from .models import DeviceRiskAssessment, NetworkPostureAssessment
from .posture_gate import PostureDecision, PostureGate, compute_fingerprint
from .providers.ollama import OllamaProvider
from .providers.openai_compatible import OpenAICompatibleProvider
from .providers.anthropic import AnthropicProvider
from .providers.gemini import GeminiProvider
from ..models import Device


class AIEngine:
    """Manages AI providers and coordinates risk assessment caching and execution."""

    PROVIDER_REGISTRY: Dict[str, Type[BaseAIProvider]] = {
        "ollama": OllamaProvider,
        "openai": OpenAICompatibleProvider,
        "openai_compatible": OpenAICompatibleProvider,
        "groq": OpenAICompatibleProvider,
        "deepseek": OpenAICompatibleProvider,
        "openrouter": OpenAICompatibleProvider,
        "anthropic": AnthropicProvider,
        "claude": AnthropicProvider,
        "gemini": GeminiProvider,
    }

    def __init__(self, provider: BaseAIProvider, config: Optional[Dict[str, Any]] = None):
        self.provider = provider
        self.config = config or {}
        self.cache_enabled = bool(self.config.get("cache_results", True))
        self.analyze_on = str(self.config.get("analyze_on", "alien_only")).lower().strip()
        self._cache: "collections.OrderedDict[str, Tuple[float, DeviceRiskAssessment]]" = collections.OrderedDict()
        self._cache_lock = threading.Lock()
        self._max_cache_entries = 512
        self._cache_ttl_seconds = float(self.config.get("cache_ttl_seconds", 3600.0))
        self.posture_gate = PostureGate(
            min_interval=float(self.config.get("posture_min_interval_seconds", 900)),
            max_age=float(self.config.get("posture_max_age_seconds", 86400)),
        )
        self.last_posture_decision: Optional[PostureDecision] = None

    @classmethod
    def register_provider(cls, name: str, provider_cls: Type[BaseAIProvider]):
        """Registers a custom AI provider."""
        cls.PROVIDER_REGISTRY[name.lower()] = provider_cls

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> Optional["AIEngine"]:
        """Factory method to construct AIEngine from config.json."""
        ai_cfg = config.get("ai_analysis", {})
        if not isinstance(ai_cfg, dict) or not ai_cfg.get("enabled", False):
            return None

        provider_name = str(ai_cfg.get("provider", "ollama")).lower().strip()
        provider_cls = cls.PROVIDER_REGISTRY.get(provider_name)
        if not provider_cls:
            return None

        providers_dict = ai_cfg.get("providers", {})
        if (
            isinstance(providers_dict, dict)
            and provider_name in providers_dict
            and isinstance(providers_dict[provider_name], dict)
        ):
            # Exclude top-level connection credentials so named profiles never inherit stale endpoint/key values
            merged_cfg = {
                k: v for k, v in ai_cfg.items() if k not in ("providers", "endpoint", "model", "api_key")
            }
            merged_cfg.update(providers_dict[provider_name])
        else:
            merged_cfg = {k: v for k, v in ai_cfg.items() if k != "providers"}

        merged_cfg["provider"] = provider_name
        provider = provider_cls(merged_cfg)
        return cls(provider=provider, config=merged_cfg)

    def _cache_key(self, device: Device, threats: Optional[List[str]] = None) -> str:
        ports_str = ",".join(sorted(device.open_ports))
        base_key = f"{device.mac.upper()}::{ports_str}"
        vendor_val = device.vendor if device.vendor not in ("", "N/A") else ""
        dev_threats = getattr(device, "threats", None) or []
        dev_notes = getattr(device, "notes", None) or []
        extra_threats = threats or []
        if not (extra_threats or dev_threats or dev_notes or getattr(device, "is_alien", False) or vendor_val):
            return base_key

        ctx_payload = json.dumps(
            {
                "threats": sorted(str(t) for t in extra_threats + list(dev_threats)),
                "notes": sorted(str(n) for n in dev_notes),
                "is_alien": bool(getattr(device, "is_alien", False)),
                "vendor": vendor_val,
            },
            sort_keys=True,
        )
        ctx_hash = hashlib.sha256(ctx_payload.encode("utf-8")).hexdigest()[:12]
        return f"{base_key}::ctx={ctx_hash}"

    def analyze_device(self, device: Device, threats: List[str] = None) -> Optional[DeviceRiskAssessment]:
        """Analyzes a single device, utilizing thread-safe bounded TTL cache when available."""
        if not device:
            return None

        cache_key = self._cache_key(device, threats)
        now = time.time()
        if self.cache_enabled:
            with self._cache_lock:
                entry = self._cache.get(cache_key)
                if entry is not None:
                    cached_at, assessment = entry
                    if now - cached_at < self._cache_ttl_seconds:
                        self._cache.move_to_end(cache_key)
                        device.ai_assessment = assessment
                        return assessment
                    self._cache.pop(cache_key, None)

        assessment = self.provider.analyze(device, threats)
        if assessment:
            if self.cache_enabled:
                with self._cache_lock:
                    if cache_key in self._cache:
                        self._cache.move_to_end(cache_key)
                    elif len(self._cache) >= self._max_cache_entries:
                        expired_keys = [
                            k
                            for k, (ts, _) in self._cache.items()
                            if now - ts >= self._cache_ttl_seconds
                        ]
                        for ek in expired_keys:
                            del self._cache[ek]
                        while len(self._cache) >= self._max_cache_entries:
                            self._cache.popitem(last=False)
                    self._cache[cache_key] = (now, assessment)
            device.ai_assessment = assessment

        return assessment

    def analyze_devices(
        self, devices: List[Device], threats: List[str] = None, max_workers: int = 2
    ) -> Dict[str, DeviceRiskAssessment]:
        """Concurrently analyzes multiple devices."""
        if not devices:
            return {}

        results: Dict[str, DeviceRiskAssessment] = {}

        def _worker(d: Device):
            try:
                res = self.analyze_device(d, threats)
                return d.mac, res
            except Exception:
                return d.mac, None

        with ThreadPoolExecutor(max_workers=min(max_workers, len(devices))) as executor:
            for mac, assessment in executor.map(_worker, devices):
                if assessment:
                    results[mac] = assessment

        return results

    def analyze_network(self, audit: Any, force: bool = False) -> Optional[NetworkPostureAssessment]:
        """
        Posture assessment gated by PostureGate: the LLM is only called when
        security-relevant inputs change (or on ``force``). Otherwise the last
        successful assessment is reused. Provider failures fall back to a
        deterministic posture that is never cached.
        """
        if not audit:
            return None
        try:
            tier = BaseAIProvider.compute_posture(
                getattr(audit, "threats", []), getattr(audit, "alien_count", 0)
            )
            fingerprint = compute_fingerprint(audit, tier, BaseAIProvider.infer_device_hint)
            decision = self.posture_gate.decide(fingerprint, tier, force=force)
            self.last_posture_decision = decision

            posture: Optional[NetworkPostureAssessment] = None
            if decision.refresh:
                posture = self.provider.analyze_network_posture(audit)
                if posture:
                    self.posture_gate.store(fingerprint, tier, posture)
                else:
                    self.posture_gate.record_failure()
                    self.last_posture_decision = PostureDecision(False, f"{decision.reason}_failed")
            else:
                posture = self.posture_gate.cached(tier, getattr(audit, "threats", []))

            if posture is None:
                posture = self.provider.fallback_posture(audit)
            if posture:
                audit.ai_posture = posture
            return posture
        except Exception:
            return None
