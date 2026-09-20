"""
Notification Engine for Alien Hunter.
Coordinates and dispatches alert messages across all configured notification hooks
using an extensible registry and factory pattern.
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Optional, Type

from .base import BaseNotificationHook
from .template import AlertMessage
from .hooks.telegram import TelegramHook
from .hooks.discord import DiscordHook
from .hooks.slack import SlackHook
from .hooks.generic import GenericWebhookHook
from ..models import Device


class NotificationEngine:
    """Manages active notification hooks and orchestrates concurrent alert delivery."""

    HOOK_REGISTRY: Dict[str, Type[BaseNotificationHook]] = {
        "telegram": TelegramHook,
        "discord": DiscordHook,
        "slack": SlackHook,
        "generic_webhook": GenericWebhookHook,
    }

    def __init__(self, hooks: Optional[List[BaseNotificationHook]] = None):
        self.hooks: List[BaseNotificationHook] = hooks or []

    @classmethod
    def register_hook_type(cls, name: str, hook_cls: Type[BaseNotificationHook]):
        """Allows registering new or custom notification hooks dynamically."""
        cls.HOOK_REGISTRY[name.lower()] = hook_cls

    def register_hook(self, hook: BaseNotificationHook):
        """Registers an active notification hook instance."""
        self.hooks.append(hook)

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "NotificationEngine":
        """
        Cycles over the configured hooks in config.json and instantiates
        all enabled hooks found in the registry.
        """
        engine = cls()
        notifications_cfg = config.get("notifications", {})

        for hook_name, hook_cfg in notifications_cfg.items():
            if not isinstance(hook_cfg, dict) or not hook_cfg.get("enabled", True):
                continue

            hook_cls = cls.HOOK_REGISTRY.get(hook_name.lower())
            if hook_cls:
                engine.register_hook(hook_cls(hook_cfg))

        return engine

    @property
    def active_hook_count(self) -> int:
        return sum(1 for h in self.hooks if h.enabled and h.is_configured)


    def dispatch(
        self,
        alien_devices: List[Device],
        threats: List[str] = None,
        audit_result: Optional[Any] = None,
    ) -> Dict[str, bool]:
        """
        Builds the unified AlertMessage and dispatches it concurrently to all active hooks.
        Returns a mapping of {hook_name: success_boolean}.
        """
        if not alien_devices and not threats and not audit_result:
            return {}
        if not self.hooks:
            return {}

        alert = AlertMessage(alien_devices, threats or [], audit_result=audit_result)
        results: Dict[str, bool] = {}


        def send_hook(hook: BaseNotificationHook):
            try:
                success = hook.send(alert)
                return hook.name, success
            except Exception:
                return hook.name, False

        with ThreadPoolExecutor(max_workers=len(self.hooks)) as executor:
            for name, success in executor.map(send_hook, self.hooks):
                results[name] = success

        return results
