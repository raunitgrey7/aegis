"""Local LLM client (Ollama). No API keys, ever.

The client is defensive: short timeouts, JSON-mode when asked, and a hard availability check so the
investigation engine can fall back to its deterministic synthesizer when no model is running. The LLM
is *only* used for language tasks (planning, summarising, explaining) — never for detection.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import httpx

log = logging.getLogger(__name__)


class LLMUnavailable(RuntimeError):
    pass


@dataclass
class LLMResponse:
    text: str
    model: str
    tokens: int = 0
    duration_ms: float = 0.0


class LLMClient:
    def __init__(self, base_url: str, model: str, timeout: float = 90.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._available: bool | None = None

    def available(self, refresh: bool = False) -> bool:
        if self._available is not None and not refresh:
            return self._available
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=3.0)
            self._available = r.status_code == 200
        except Exception:
            self._available = False
        return self._available

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        json_mode: bool = False,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if system:
            payload["system"] = system
        if json_mode:
            payload["format"] = "json"
        try:
            r = httpx.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as exc:
            self._available = False
            raise LLMUnavailable(str(exc)) from exc
        return LLMResponse(
            text=data.get("response", ""),
            model=self.model,
            tokens=int(data.get("eval_count", 0)),
            duration_ms=round(data.get("total_duration", 0) / 1e6, 1),
        )

    def generate_json(self, prompt: str, system: str | None = None, **kw) -> dict:
        resp = self.generate(prompt, system=system, json_mode=True, **kw)
        try:
            return json.loads(resp.text)
        except json.JSONDecodeError:
            start, end = resp.text.find("{"), resp.text.rfind("}")
            if 0 <= start < end:
                try:
                    return json.loads(resp.text[start : end + 1])
                except json.JSONDecodeError:
                    pass
            raise LLMUnavailable("model did not return valid JSON") from None


_singleton: LLMClient | None = None


def get_llm() -> LLMClient:
    global _singleton
    if _singleton is None:
        from aegis.config import get_settings

        s = get_settings()
        _singleton = LLMClient(s.ollama_url, s.ollama_model, s.llm_timeout_seconds)
    return _singleton
