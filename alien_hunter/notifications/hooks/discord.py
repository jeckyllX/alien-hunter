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

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: max(1, limit - 3)] + "..."

    def _dispatch(self, alert: AlertMessage) -> bool:
        title = self._truncate(alert.title, 256)
        footer_text = "Alien Hunter Network Sentinel"
        raw_fields = alert.to_fields()[:25]

        # Enforce per-field limits and total 6000-char embed budget
        budget = 6000 - len(title) - len(footer_text)
        fields = []
        for field in raw_fields:
            name = self._truncate(str(field.get("name", "")), 256)
            value = self._truncate(str(field.get("value", "")), 1024)
            cost = len(name) + len(value)
            if budget - cost < 0:
                break
            budget -= cost
            fields.append({
                "name": name,
                "value": value,
                "inline": bool(field.get("inline", False)),
            })

        payload = {
            "content": self._truncate(alert.headline, 2000),
            "embeds": [
                {
                    "title": title,
                    "color": 15158332,  # Red hex
                    "fields": fields,
                    "footer": {"text": footer_text},
                    "timestamp": alert.iso_timestamp,
                }
            ],
        }

        return self._post_json(self.webhook_url, payload)

