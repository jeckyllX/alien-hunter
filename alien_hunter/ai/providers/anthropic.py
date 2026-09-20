"""
Anthropic Claude AI Provider.
Communicates with the Anthropic Messages API (v1/messages).
"""

from typing import Dict, Any, Optional, List
from ..base import BaseAIProvider
from ..models import DeviceRiskAssessment, NetworkPostureAssessment
from ...models import Device


class AnthropicProvider(BaseAIProvider):
    """Provider for Anthropic Claude models (e.g. Claude 3.5 Haiku, Sonnet)."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("anthropic", config)
        if not self.endpoint:
            self.endpoint = "https://api.anthropic.com/v1/messages"
        if not self.model:
            self.model = "claude-3-5-haiku-20241022"

    def _generate_content(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 300
    ) -> Optional[str]:
        if not self.api_key:
            return None

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "max_tokens": max_tokens,
            "temperature": 0.1,
        }

        resp_data = self._post_json(self.endpoint, payload, headers=headers)
        if not resp_data:
            return None

        try:
            content_blocks = resp_data.get("content", [])
            if content_blocks and "text" in content_blocks[0]:
                return content_blocks[0]["text"]
        except Exception:
            pass

        return None

