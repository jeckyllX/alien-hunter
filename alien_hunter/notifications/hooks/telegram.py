"""
Telegram Bot Notification Hook.
Dispatches intrusion alerts directly to Telegram chats using the Telegram Bot API.
"""

from typing import Dict, Any
from ..base import BaseNotificationHook
from ..template import AlertMessage


class TelegramHook(BaseNotificationHook):
    """Notification hook for Telegram Bot API."""

    MAX_MESSAGE_LEN = 4096

    def __init__(self, config: Dict[str, Any]):
        super().__init__("telegram", config)
        self.bot_token = str(config.get("bot_token", "")).strip()
        self.chat_id = str(config.get("chat_id", "")).strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    @classmethod
    def _truncate_text(cls, text: str) -> str:
        if len(text) <= cls.MAX_MESSAGE_LEN:
            return text
        return text[: cls.MAX_MESSAGE_LEN - 3] + "..."

    def _dispatch(self, alert: AlertMessage) -> bool:
        payload = {
            "chat_id": self.chat_id,
            "text": self._truncate_text(alert.to_markdown()),
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        success = self._post_json(url, payload)
        if success:
            return True

        # Fallback to plain text only when Telegram rejects Markdown entities with HTTP 400
        if getattr(self._thread_state, "last_status", None) == 400:
            payload["text"] = self._truncate_text(alert.to_plain_text())
            payload.pop("parse_mode", None)
            return self._post_json(url, payload)

        return False


