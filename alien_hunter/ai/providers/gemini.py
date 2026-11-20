"""
Google Gemini AI Provider.
Communicates with the Google Gemini REST API (v1beta/models/...:generateContent).
"""

import re
from typing import Dict, Any, Optional, List
import urllib.parse

from ..base import BaseAIProvider
from ..models import DeviceRiskAssessment, NetworkPostureAssessment
from ...models import Device


class GeminiProvider(BaseAIProvider):
    """Provider for Google Gemini models (e.g. gemini-1.5-flash)."""

    _MODEL_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]+$")

    def __init__(self, config: Dict[str, Any]):
        super().__init__("gemini", config)
        if not self.model:
            self.model = "gemini-flash-lite-latest"

    def _generate_content(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 1500
    ) -> Optional[str]:
        if not self.api_key or not self._MODEL_PATTERN.match(self.model):
            return None

        encoded_model = urllib.parse.quote(self.model, safe="")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{encoded_model}:generateContent"
        headers = {"x-goog-api-key": self.api_key}

        payload = {
            "systemInstruction": {
                "parts": [{"text": system_prompt}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": max_tokens,
                "responseMimeType": "application/json",
            },
        }

        resp_data = self._post_json(url, payload, headers=headers)
        if not resp_data:
            return None

        try:
            candidates = resp_data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts and "text" in parts[0]:
                    return parts[0]["text"]
        except Exception:
            pass

        return None

