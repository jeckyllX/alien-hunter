"""
Discord Webhook Notification Hook.
Dispatches intrusion alerts with rich embed cards to Discord channels.
"""

from typing import Dict, Any
from ..base import BaseNotificationHook
from ..template import AlertMessage


class DiscordHook(BaseNotificationHook):
    """Notification hook for Discord Webhooks."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("discord", config)
        self.webhook_url = str(config.get("webhook_url", "")).strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.webhook_url)

    def _dispatch(self, alert: AlertMessage) -> bool:
        payload = {
            "content": alert.headline,
            "embeds": [
                {
                    "title": alert.title,
                    "color": 15158332,  # Red hex
                    "fields": alert.to_fields(),
                    "footer": {"text": "Alien Hunter Network Sentinel"},
                    "timestamp": alert.iso_timestamp,
                }
            ],
        }

        return self._post_json(self.webhook_url, payload)

