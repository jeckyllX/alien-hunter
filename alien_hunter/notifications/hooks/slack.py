"""
Slack Incoming Webhook Notification Hook.
Dispatches intrusion alerts using Slack BlockKit formatting.
"""

from typing import Dict, Any
from ..base import BaseNotificationHook
from ..template import AlertMessage


class SlackHook(BaseNotificationHook):
    """Notification hook for Slack Incoming Webhooks."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("slack", config)
        self.webhook_url = str(config.get("webhook_url", "")).strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.webhook_url)

    def _dispatch(self, alert: AlertMessage) -> bool:
        payload = {
            "text": alert.headline,
            "blocks": alert.to_slack_blocks(),
        }

        return self._post_json(self.webhook_url, payload)

