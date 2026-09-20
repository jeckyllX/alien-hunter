"""
Ollama Local AI Provider.
Communicates directly with the local Ollama daemon (REST API) using native JSON schema formatting.
"""

from typing import Dict, Any, Optional, List
from ..base import BaseAIProvider
from ..models import DeviceRiskAssessment, NetworkPostureAssessment
from ...models import Device


class OllamaProvider(BaseAIProvider):
    """Local provider connecting to Ollama instances (e.g. Raspberry Pi, local workstation)."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("ollama", config)
        if not self.endpoint:
            self.endpoint = "http://localhost:11434"
        if not self.model:
            self.model = "qwen2.5:0.5b"

        # Ensure endpoint doesn't have trailing slash
        self.endpoint = self.endpoint.rstrip("/")
        self.api_url = f"{self.endpoint}/api/generate"

    def _generate_content(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 300
    ) -> Optional[str]:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": max_tokens,
            },
        }
        resp = self._post_json(self.api_url, payload)
        return resp.get("response", "") if resp else None

