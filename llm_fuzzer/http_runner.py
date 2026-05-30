from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def run_http_case(base_url: str, case: dict[str, Any], timeout: float) -> dict[str, Any]:
    method = str(case.get("method", "GET")).upper()
    path = str(case.get("path") or "/")
    payload = str(case.get("payload") or "")
    body = case.get("body")
    headers = case.get("headers") if isinstance(case.get("headers"), dict) else {}

    if method not in {"GET", "POST"}:
        return {
            "id": case.get("id"),
            "executed": False,
            "error": f"unsupported HTTP method: {method}",
        }

    url = _join_url(base_url, path)
    data = None
    if method == "GET" and payload:
        separator = "&" if urllib.parse.urlparse(url).query else "?"
        url = url + separator + urllib.parse.urlencode({"llm_fuzz": payload})
    elif method == "POST":
        data = str(body if body is not None else payload).encode("utf-8")
        headers.setdefault("Content-Type", "text/plain")

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content = response.read(4096)
            status = response.status
            response_headers = dict(response.headers.items())
            error = None
    except urllib.error.HTTPError as exc:
        content = exc.read(4096)
        status = exc.code
        response_headers = dict(exc.headers.items())
        error = None
    except urllib.error.URLError as exc:
        return {
            "id": case.get("id"),
            "executed": True,
            "method": method,
            "url": url,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": str(exc),
        }

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "id": case.get("id"),
        "executed": True,
        "method": method,
        "url": url,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "response_sha256": hashlib.sha256(content).hexdigest(),
        "response_preview": content.decode("utf-8", errors="replace")[:300],
        "content_type": response_headers.get("Content-Type", ""),
        "error": error,
    }


def _join_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base_url.rstrip("/") + "/" + path.lstrip("/")

