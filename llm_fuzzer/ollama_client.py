from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class OllamaError(RuntimeError):
    """Raised when the Ollama API cannot return a usable response."""


def generate(
    prompt: str,
    *,
    base_url: str = "http://127.0.0.1:11434",
    model: str = "gemma4",
    timeout: int = 180,
) -> str:
    endpoint = base_url.rstrip("/") + "/api/generate"
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload: dict[str, Any] = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise OllamaError(f"failed to reach Ollama at {endpoint}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise OllamaError("Ollama returned invalid JSON") from exc

    text = payload.get("response")
    if not isinstance(text, str) or not text.strip():
        raise OllamaError("Ollama response did not include generated text")
    return text

