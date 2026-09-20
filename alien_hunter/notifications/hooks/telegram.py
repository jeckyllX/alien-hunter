"""
Telegram Bot Notification Hook.
Dispatches intrusion alerts directly to Telegram chats using the Telegram Bot API.
"""

from typing import Dict, Any
from ..base import BaseNotificationHook
from ..template import AlertMessage


class TelegramHook(BaseNotificationHook):
    """Notification hook for Telegram Bot API."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("telegram", config)
        self.bot_token = str(config.get("bot_token", "")).strip()
        self.chat_id = str(config.get("chat_id", "")).strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def _dispatch(self, alert: AlertMessage) -> bool:
        payload = {
            "chat_id": self.chat_id,
            "text": alert.to_markdown(),
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        success = self._post_json(url, payload)
        if not success:
            # Fallback to plain text if Telegram rejects unescaped Markdown entities
            payload["text"] = alert.to_plain_text()
            payload.pop("parse_mode", None)
            return self._post_json(url, payload)

        return True


