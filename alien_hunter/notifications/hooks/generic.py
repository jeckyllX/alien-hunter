"""
Generic JSON Webhook Notification Hook.
Dispatches intrusion alert payloads in structured JSON format to any arbitrary HTTP/HTTPS endpoint.
"""

from typing import Dict, Any
from ..base import BaseNotificationHook
from ..template import AlertMessage


class GenericWebhookHook(BaseNotificationHook):
    """Notification hook for arbitrary HTTP POST endpoints."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("generic_webhook", config)
        self.url = str(config.get("url", config.get("webhook_url", ""))).strip()
        self.custom_headers = config.get("headers", {})

    @property
    def is_configured(self) -> bool:
        return bool(self.url)

    def _dispatch(self, alert: AlertMessage) -> bool:
        payload = alert.to_dict()
        return self._post_json(self.url, payload, headers=self.custom_headers)

