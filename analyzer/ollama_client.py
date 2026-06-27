import time
from typing import Any

import requests


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout_seconds: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    def tags(self) -> dict[str, Any]:
        url = f"{self.base_url}/api/tags"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            raise OllamaError(f"Ollama /api/tags request failed: {exc}") from exc
        except ValueError as exc:
            raise OllamaError("Ollama /api/tags returned non-JSON data") from exc

    def generate(self, prompt: str) -> dict[str, Any]:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_ctx": 8192,
            },
        }

        started = time.monotonic()
        try:
            response = requests.post(url, json=payload, timeout=self.timeout_seconds)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise OllamaError(f"Ollama /api/generate request failed: {exc}") from exc
        except ValueError as exc:
            raise OllamaError("Ollama /api/generate returned non-JSON data") from exc

        if "error" in data:
            raise OllamaError(f"Ollama generation error: {data['error']}")

        return {
            "status": "OK",
            "model": self.model,
            "duration_seconds": round(time.monotonic() - started, 6),
            "response": data.get("response", ""),
            "raw_payload": data,
        }
