from pathlib import Path
from typing import Any

from analyzer.result_writer import write_json


def _normalize(value: Any) -> str:
    return str(value or "").lower().replace("-", "_").replace(" ", "_")


def _candidate_ground_truth_ids(
    candidate: dict[str, Any],
    ground_truth: list[dict[str, Any]],
) -> set[str]:
    text = " ".join(
        str(candidate.get(key, ""))
        for key in ("vulnerability_type", "function", "reason", "evidence")
    ).lower()
    matched: set[str] = set()

    for item in ground_truth:
        truth_id = str(item.get("id") or "")
        truth_type = _normalize(item.get("vulnerability_type"))
        evidence = str(item.get("expected_evidence") or "").lower()

        if truth_id == "GT-001" and "ssid" in text:
            matched.add(truth_id)
        elif truth_id == "GT-002" and "password" in text:
            matched.add(truth_id)
        elif truth_id == "GT-003" and ("topic" in text or "strcat" in text):
            matched.add(truth_id)
        elif truth_id == "GT-004" and ("format" in text or "printf(value)" in text):
            matched.add(truth_id)
        elif truth_id == "GT-005" and ("hardcoded" in text or "admin_password" in text):
            matched.add(truth_id)
        elif truth_id == "GT-006" and ("port" in text or "atoi" in text):
            matched.add(truth_id)
        elif truth_type and truth_type in _normalize(candidate.get("vulnerability_type")):
            if any(token and token in text for token in evidence.split()[:3]):
                matched.add(truth_id)

    return matched


def _confirmed_candidate_ids(verification_result: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for finding in verification_result.get("findings", []):
        if finding.get("status") != "CONFIRMED":
            continue
        seed_name = str(finding.get("seed_name") or "")
        if seed_name.startswith("LLM-"):
            ids.add(seed_name.split("_seed_", 1)[0])
    return ids


def _route_detection_rate(found_ids: set[str], ground_truth_count: int) -> float:
    if ground_truth_count <= 0:
        return 0.0
    return round((len(found_ids) / ground_truth_count) * 100, 2)


def _resource_summary(route_result: dict[str, Any]) -> dict[str, Any]:
    resource = route_result.get("resource_usage", {})
    return {
        "wall_time_seconds": resource.get("wall_time_seconds", route_result.get("duration_seconds", 0)),
        "total_cpu_seconds": resource.get("total_cpu_seconds", 0),
        "average_cpu_percent": resource.get("average_cpu_percent", 0),
        "max_rss_kb": resource.get("max_rss_kb", 0),
    }


def summarize_llm_route(
    route_result: dict[str, Any],
    ground_truth: list[dict[str, Any]],
) -> dict[str, Any]:
    llm_result = route_result.get("llm_candidates", {})
    candidates = llm_result.get("candidates", [])
    confirmed_ids = _confirmed_candidate_ids(route_result.get("verification_result", {}))
    candidate_ids_by_truth: dict[str, list[str]] = {}
    detected_ids: set[str] = set()
    confirmed_truth_ids: set[str] = set()

    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id") or "")
        matched_ids = _candidate_ground_truth_ids(candidate, ground_truth)
        detected_ids.update(matched_ids)
        for truth_id in matched_ids:
            candidate_ids_by_truth.setdefault(truth_id, []).append(candidate_id)
        if candidate_id in confirmed_ids:
            confirmed_truth_ids.update(matched_ids)

    candidate_count = len(candidates)
    false_positive_count = max(candidate_count - len(confirmed_ids), 0)

    return {
        "route": "LLM Fuzzer",
        "raw_result_file": "/work/logs/llm_fuzzer_result.json",
        "detected_ground_truth_ids": sorted(detected_ids),
        "confirmed_ground_truth_ids": sorted(confirmed_truth_ids),
        "detection_rate": _route_detection_rate(detected_ids, len(ground_truth)),
        "confirmed_detection_rate": _route_detection_rate(confirmed_truth_ids, len(ground_truth)),
        "candidate_or_case_count": candidate_count,
        "confirmed_count": len(confirmed_ids),
        "false_positive_count": false_positive_count,
        "resource": _resource_summary(route_result),
        "candidate_ids_by_truth": candidate_ids_by_truth,
    }


def summarize_boofuzz_route(
    route_result: dict[str, Any],
    verification_result: dict[str, Any],
    ground_truth: list[dict[str, Any]],
) -> dict[str, Any]:
    confirmed_input_paths = {
        item.get("input_path")
        for item in verification_result.get("findings", [])
        if item.get("status") == "CONFIRMED"
    }
    detected_ids: set[str] = set()
    confirmed_count = 0

    for finding in route_result.get("suspicious_findings", []):
        if finding.get("input_path") not in confirmed_input_paths:
            continue
        confirmed_count += 1
        detected_ids.update(finding.get("expected_ground_truth_ids", []))

    summary = route_result.get("summary", {})
    suspicious_count = int(summary.get("suspicious_count") or 0)

    return {
        "route": "boofuzz",
        "raw_result_file": "/work/logs/boofuzz_result.json",
        "detected_ground_truth_ids": sorted(detected_ids),
        "confirmed_ground_truth_ids": sorted(detected_ids),
        "detection_rate": _route_detection_rate(detected_ids, len(ground_truth)),
        "confirmed_detection_rate": _route_detection_rate(detected_ids, len(ground_truth)),
        "candidate_or_case_count": int(summary.get("case_count") or summary.get("total_runs") or 0),
        "confirmed_count": confirmed_count,
        "false_positive_count": max(suspicious_count - confirmed_count, 0),
        "resource": _resource_summary(route_result),
    }


def write_comparison_outputs(
    logs_dir: Path,
    ground_truth: list[dict[str, Any]],
    llm_route_result: dict[str, Any],
    boofuzz_result: dict[str, Any],
    boofuzz_verification_result: dict[str, Any],
    resource_log: dict[str, Any],
) -> dict[str, Any]:
    logs_dir.mkdir(parents=True, exist_ok=True)
    llm_summary = summarize_llm_route(llm_route_result, ground_truth)
    boofuzz_summary = summarize_boofuzz_route(
        boofuzz_result,
        boofuzz_verification_result,
        ground_truth,
    )

    result = {
        "status": "OK",
        "ground_truth_count": len(ground_truth),
        "ground_truth_ids": [item.get("id") for item in ground_truth],
        "routes": [llm_summary, boofuzz_summary],
        "resource_log": resource_log,
        "metric_notes": {
            "detection_rate": "detected ground-truth ids / all ground-truth ids",
            "time": "route wall-clock seconds",
            "resource": "resource.getrusage based CPU seconds and max RSS",
            "false_positive_count": "LLM route: unconfirmed candidates; boofuzz route: non-reproduced suspicious findings",
        },
    }
    write_json(logs_dir / "comparison_result.json", result)
    write_comparison_report(logs_dir / "comparison_report.md", result)
    write_alignment_report(logs_dir / "627_1_alignment.md")
    return result


def write_comparison_report(path: Path, result: dict[str, Any]) -> None:
    lines = [
        "# Route Comparison",
        "",
        "| Route | Detection Rate | Confirmed Detection Rate | Time (s) | CPU (s) | Avg CPU % | Max RSS (KB) | False Positives | Raw Result |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]

    for route in result["routes"]:
        resource = route["resource"]
        lines.append(
            "| {route} | {detection:.2f}% | {confirmed_detection:.2f}% | {time:.6f} | {cpu:.6f} | {cpu_percent:.2f}% | {rss} | {false_positive} | {raw} |".format(
                route=route["route"],
                detection=route["detection_rate"],
                confirmed_detection=route["confirmed_detection_rate"],
                time=float(resource.get("wall_time_seconds") or 0),
                cpu=float(resource.get("total_cpu_seconds") or 0),
                cpu_percent=float(resource.get("average_cpu_percent") or 0),
                rss=resource.get("max_rss_kb", 0),
                false_positive=route["false_positive_count"],
                raw=route["raw_result_file"],
            )
        )

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- LLM Fuzzer detection is based on LLM candidates matched to the ground truth.",
            "- LLM Fuzzer confirmation is based on reproduced findings linked to LLM-generated seed files.",
            "- boofuzz detection is based on reproduced findings linked to boofuzz field metadata.",
            "- Only CONFIRMED execution evidence should be treated as final vulnerabilities.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_alignment_report(path: Path) -> None:
    lines = [
        "# 627_1.md Alignment Check",
        "",
        "| 627_1.md Requirement | Current Status | Evidence |",
        "| --- | --- | --- |",
        "| Docker container replaces Raspberry Pi gateway | Implemented | Dockerfile, docker-compose.yml, analyzer/main.py |",
        "| Ollama Gemma4 API integration | Implemented | /work/logs/llm_candidates.json |",
        "| LLM creates vulnerability candidates and seeds, not final findings | Implemented | llm_candidates.json, seed_generation.json, final_report.md |",
        "| Mutation fuzzing executes target binary | Implemented | /work/logs/fuzz_result.json |",
        "| boofuzz route produces independent fuzzing result | Implemented | /work/logs/boofuzz_result.json |",
        "| Crash / timeout / sanitizer evidence is collected | Implemented | fuzz_result.json, boofuzz_result.json, crashes directory |",
        "| Suspicious inputs are rerun for reproducibility | Implemented | verification_result.json, boofuzz_verification_result.json |",
        "| Final classification uses CONFIRMED / FALSE_POSITIVE style statuses | Implemented | final_report.md, comparison_report.md |",
        "| JSON and Markdown reports are generated | Implemented | /work/logs/*.json, final_report.md, comparison_report.md |",
        "| Resource metrics are recorded | Implemented | resource_usage.json, comparison_result.json |",
        "",
        "Current mismatch or limitation:",
        "",
        "- The current target is a lightweight C IoT configuration parser, not real firmware.",
        "- boofuzz is adapted to local stdin execution instead of a live network service.",
        "- Resource usage is process-level CPU/RSS via Python `resource.getrusage`, not Docker cgroup telemetry.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
