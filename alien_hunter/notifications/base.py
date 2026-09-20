"""
Base Notification Hook Interface.
Defines the abstract contract and common HTTP dispatch helpers for all notification providers.
"""

from abc import ABC, abstractmethod
import json
import urllib.request
from typing import Dict, Any
from .template import AlertMessage


class BaseNotificationHook(ABC):
    """Abstract Base Class for alert notification hooks."""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.enabled = bool(config.get("enabled", True))
        self.timeout = float(config.get("timeout", 6.0))
        self.user_agent = config.get("user_agent", "AlienHunter/1.0")

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the hook has all required credentials/endpoints."""
        pass

    @abstractmethod
    def _dispatch(self, alert: AlertMessage) -> bool:
        """Service-specific dispatch logic."""
        pass

    def send(self, alert: AlertMessage) -> bool:
        """
        Template method validating configuration and alert content before dispatching.
        Dispatches an intrusion alert to the destination service.
        Returns True on success, False on failure.
        """
        if not self.enabled or alert.is_empty or not self.is_configured:
            return False
        return self._dispatch(alert)


    def _post_json(self, url: str, payload: Dict[str, Any], headers: Dict[str, str] = None) -> bool:
        """Utility method to safely send an HTTP POST request with JSON data."""
        if not url:
            return False

        req_headers = {
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
        }
        if headers:
            req_headers.update(headers)

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=req_headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False
