"""
Base Notification Hook Interface.
Defines the abstract contract and common HTTP dispatch helpers for all notification providers.
"""

from abc import ABC, abstractmethod
import json
import threading
import urllib.error
import urllib.request
from typing import Dict, Any
from .template import AlertMessage
from ..http_utils import safe_urlopen, read_bounded, redact_url_secrets
from ..logging_setup import get_logger

log = get_logger()


class BaseNotificationHook(ABC):
    """Abstract Base Class for alert notification hooks."""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.enabled = bool(config.get("enabled", True))
        self.timeout = float(config.get("timeout", 6.0))
        self.user_agent = config.get("user_agent", "AlienHunter/1.0")
        self._thread_state = threading.local()

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
        """Utility method to safely send a validated HTTP POST request with JSON data."""
        self._thread_state.last_status = None
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
            with safe_urlopen(
                req,
                timeout=self.timeout,
                allowed_schemes=("http", "https"),
                allow_redirects=False,
            ) as resp:
                status = getattr(resp, "status", 200)
                self._thread_state.last_status = status
                read_bounded(resp, 65536)
                return 200 <= status < 300
        except urllib.error.HTTPError as e:
            self._thread_state.last_status = e.code
            log.debug("Notification HTTP %s for %s", e.code, redact_url_secrets(url))
            return False
        except Exception as e:
            log.debug("Notification request failed for %s: %s", redact_url_secrets(url), e)
            return False
