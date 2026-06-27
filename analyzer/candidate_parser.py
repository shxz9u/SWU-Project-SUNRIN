import json
import re
from pathlib import Path
from typing import Any


def _extract_json_object(text: str) -> str | None:
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if match:
        return match.group(0)
    return None


def _repair_common_json_issues(text: str) -> str:
    def replace_repeat(match: re.Match[str]) -> str:
        prefix = match.group(1)
        repeated = match.group(2)
        count = int(match.group(3))
        return json.dumps(prefix + (repeated * count))

    repaired = text
    pattern = re.compile(r'"([^"]*)"\s*\+\s*"([^"]*)"\.repeat\((\d+)\)')
    previous = None
    while previous != repaired:
        previous = repaired
        repaired = pattern.sub(replace_repeat, repaired)
    return repaired


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _normalize_candidate(index: int, item: dict[str, Any]) -> dict[str, Any]:
    candidate_id = str(item.get("candidate_id") or f"LLM-{index:03d}")
    if not candidate_id.startswith("LLM-"):
        candidate_id = f"LLM-{index:03d}"

    return {
        "candidate_id": candidate_id,
        "vulnerability_type": str(item.get("vulnerability_type") or "unknown"),
        "file": str(item.get("file") or "input.c"),
        "function": str(item.get("function") or "unknown"),
        "reason": str(item.get("reason") or ""),
        "evidence": str(item.get("evidence") or ""),
        "suggested_seeds": _as_string_list(item.get("suggested_seeds")),
        "confidence": str(item.get("confidence") or "unknown"),
        "status": "LLM_CANDIDATE",
    }


def parse_llm_candidates(raw_output: str, logs_dir: Path) -> dict[str, Any]:
    json_text = _extract_json_object(raw_output)
    if json_text is None:
        raw_path = logs_dir / "llm_raw_output.txt"
        raw_path.write_text(raw_output, encoding="utf-8")
        return {
            "status": "PARSE_FAILED",
            "error": "No JSON object found in LLM output",
            "raw_output_path": str(raw_path),
            "candidates": [],
        }

    try:
        parsed = json.loads(_repair_common_json_issues(json_text))
    except json.JSONDecodeError as exc:
        raw_path = logs_dir / "llm_raw_output.txt"
        raw_path.write_text(raw_output, encoding="utf-8")
        return {
            "status": "PARSE_FAILED",
            "error": f"Invalid JSON from LLM: {exc}",
            "raw_output_path": str(raw_path),
            "candidates": [],
        }

    raw_candidates: Any
    if isinstance(parsed, dict) and isinstance(parsed.get("candidates"), list):
        raw_candidates = parsed["candidates"]
    elif isinstance(parsed, list):
        raw_candidates = parsed
    elif isinstance(parsed, dict) and "candidate_id" in parsed:
        raw_candidates = [parsed]
    else:
        raw_candidates = []

    candidates = [
        _normalize_candidate(index, item)
        for index, item in enumerate(raw_candidates, start=1)
        if isinstance(item, dict)
    ]

    return {
        "status": "OK",
        "candidates": candidates,
    }
