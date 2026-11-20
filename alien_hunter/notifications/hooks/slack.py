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

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: max(1, limit - 3)] + "..."

    def _dispatch(self, alert: AlertMessage) -> bool:
        blocks = alert.to_slack_blocks()
        bounded_blocks = []
        for block in blocks[:50]:
            b = dict(block)
            btype = b.get("type")
            if btype == "header" and isinstance(b.get("text"), dict):
                txt = dict(b["text"])
                txt["text"] = self._truncate(str(txt.get("text", "")), 150)
                b["text"] = txt
            elif btype == "section":
                if isinstance(b.get("text"), dict):
                    txt = dict(b["text"])
                    txt["text"] = self._truncate(str(txt.get("text", "")), 3000)
                    b["text"] = txt
                if isinstance(b.get("fields"), list):
                    bounded_fields = []
                    for f in b["fields"][:10]:
                        if isinstance(f, dict):
                            nf = dict(f)
                            nf["text"] = self._truncate(str(nf.get("text", "")), 2000)
                            bounded_fields.append(nf)
                    b["fields"] = bounded_fields
            bounded_blocks.append(b)

        payload = {
            "text": self._truncate(alert.headline, 3000),
            "blocks": bounded_blocks,
        }

        return self._post_json(self.webhook_url, payload)

