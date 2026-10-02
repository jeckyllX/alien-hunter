"""
Universal OpenAI-Compatible Provider.
Supports OpenAI, Groq, OpenRouter, DeepSeek, Mistral, LM Studio, LocalAI, vLLM,
and any engine implementing the standard POST /v1/chat/completions specification.
"""

import os
from typing import Dict, Any, Optional, List
from ..base import BaseAIProvider
from ..models import DeviceRiskAssessment, NetworkPostureAssessment
from ...models import Device


class OpenAICompatibleProvider(BaseAIProvider):
    """Universal provider connecting to any OpenAI-compatible completions endpoint."""

    DEFAULT_ENDPOINTS = {
        "openrouter": "https://openrouter.ai/api/v1/chat/completions",
        "groq": "https://api.groq.com/openai/v1/chat/completions",
        "deepseek": "https://api.deepseek.com/v1/chat/completions",
        "openai": "https://api.openai.com/v1/chat/completions",
    }

    DEFAULT_MODELS = {
        "openrouter": "google/gemini-2.0-flash-001",
        "groq": "llama-3.3-70b-versatile",
        "deepseek": "deepseek-chat",
        "openai": "gpt-4o-mini",
    }

    def __init__(self, config: Dict[str, Any]):
        provider_name = str(config.get("provider", "openai_compatible")).lower().strip()
        super().__init__(provider_name, config)

        if not self.api_key:
            env_var = f"{provider_name.upper()}_API_KEY"
            self.api_key = os.environ.get(env_var, os.environ.get("OPENAI_API_KEY", "")).strip()

        if not self.endpoint:
            self.endpoint = self.DEFAULT_ENDPOINTS.get(
                provider_name, "https://api.openai.com/v1/chat/completions"
            )
        elif not self.endpoint.endswith("/chat/completions"):
            self.endpoint = f"{self.endpoint.rstrip('/')}/chat/completions"

        if not self.model:
            self.model = self.DEFAULT_MODELS.get(provider_name, "gpt-4o-mini")

    def _generate_content(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 300
    ) -> Optional[str]:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if "openrouter" in self.name or "openrouter.ai" in self.endpoint:
            headers["HTTP-Referer"] = "https://github.com/jekyll86/alien-hunter"
            headers["X-Title"] = "Alien Hunter"

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

