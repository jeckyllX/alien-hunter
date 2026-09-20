"""
Universal OpenAI-Compatible Provider.
Supports OpenAI, Groq, OpenRouter, DeepSeek, Mistral, LM Studio, LocalAI, vLLM,
and any engine implementing the standard POST /v1/chat/completions specification.
"""

from typing import Dict, Any, Optional, List
from ..base import BaseAIProvider
from ..models import DeviceRiskAssessment, NetworkPostureAssessment
from ...models import Device


class OpenAICompatibleProvider(BaseAIProvider):
    """Universal provider connecting to any OpenAI-compatible completions endpoint."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("openai_compatible", config)
        if not self.endpoint:
            self.endpoint = "https://api.openai.com/v1/chat/completions"
        elif not self.endpoint.endswith("/chat/completions"):
            self.endpoint = f"{self.endpoint.rstrip('/')}/chat/completions"

        if not self.model:
            self.model = "gpt-4o-mini"

    def _generate_content(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 300
    ) -> Optional[str]:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
            "max_tokens": max_tokens,
        }

        resp_data = self._post_json(self.endpoint, payload, headers=headers)
        if not resp_data:
            # Fallback retry without response_format in case local server doesn't support json_object mode
            payload.pop("response_format", None)
            resp_data = self._post_json(self.endpoint, payload, headers=headers)

        if not resp_data:
            return None

        try:
            choices = resp_data.get("choices", [])
            if choices and "message" in choices[0]:
                return choices[0]["message"].get("content", "")
        except Exception:
            pass

        return None

