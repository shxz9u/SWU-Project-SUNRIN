import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_NAME = "라즈베리파이-클라우드 연계형 IoT 취약점 분석 시스템"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def ensure_llm_candidates(logs_dir: Path) -> dict[str, Any]:
    path = logs_dir / "llm_candidates.json"
    default = {
        "status": "NOT_RUN",
        "candidates": [],
        "note": "LLM candidate generation has not been executed yet.",
    }
    if not path.exists():
        write_json(path, default)
        return default
    return read_json(path, default)


def percentage(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "N/A"
    return f"{(numerator / denominator) * 100:.2f}%"


def _normalized_type(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _candidate_matches_ground_truth(
    candidate: dict[str, Any], ground_truth: dict[str, Any]
) -> bool:
    candidate_type = _normalized_type(candidate.get("vulnerability_type"))
    truth_type = _normalized_type(ground_truth.get("vulnerability_type"))
    if not candidate_type or not truth_type:
        return False
    return candidate_type in truth_type or truth_type in candidate_type


def _detected_ground_truth_count(
    candidates: list[dict[str, Any]], ground_truth: list[dict[str, Any]]
) -> int:
    detected = 0
    for truth in ground_truth:
        if any(_candidate_matches_ground_truth(candidate, truth) for candidate in candidates):
            detected += 1
    return detected


def _confirmed_candidate_ids(
    verification_findings: list[dict[str, Any]],
) -> set[str]:
    confirmed_ids: set[str] = set()
    for item in verification_findings:
        if item.get("status") != "CONFIRMED":
            continue
        seed_name = str(item.get("seed_name") or "")
        if seed_name.startswith("LLM-"):
            confirmed_ids.add(seed_name.split("_seed_", 1)[0])
    return confirmed_ids


def _candidate_final_status(
    candidate: dict[str, Any], confirmed_candidate_ids: set[str]
) -> str:
    candidate_id = str(candidate.get("candidate_id") or "")
    if candidate_id in confirmed_candidate_ids:
        return "CONFIRMED"
    return "FALSE_POSITIVE"


def _duration_value(*values: Any) -> float:
    for value in values:
        if isinstance(value, (int, float)):
            return float(value)
    return 0.0


def _markdown_cell(value: Any, limit: int | None = None) -> str:
    text = str(value or "N/A").replace("\n", " ").replace("\r", " ")
    text = text.replace("|", "\\|")
    if limit is not None:
        text = text[:limit]
    return text


def write_final_report(
    logs_dir: Path,
    target_info: dict[str, Any],
    fuzz_result: dict[str, Any],
    verification_result: dict[str, Any],
) -> None:
    logs_dir.mkdir(parents=True, exist_ok=True)
    llm_result = ensure_llm_candidates(logs_dir)

    candidates = llm_result.get("candidates", [])
    if not isinstance(candidates, list):
        candidates = []

    verification_findings = verification_result.get("findings", [])
    if not isinstance(verification_findings, list):
        verification_findings = []

    confirmed = [
        item for item in verification_findings if item.get("status") == "CONFIRMED"
    ]
    not_reproduced = [
        item
        for item in verification_findings
        if item.get("status") == "NOT_REPRODUCED"
    ]

    summary = fuzz_result.get("summary", {})
    candidate_count = len(candidates)
    confirmed_count = len(confirmed)

    ground_truth = target_info.get("ground_truth", [])
    if not isinstance(ground_truth, list):
        ground_truth = []
    ground_truth_count = int(target_info.get("ground_truth_count") or len(ground_truth))
    detected_ground_truth_count = _detected_ground_truth_count(candidates, ground_truth)
    if not ground_truth and ground_truth_count:
        detected_ground_truth_count = min(candidate_count, ground_truth_count)

    confirmed_candidate_ids = _confirmed_candidate_ids(verification_findings)
    confirmed_candidate_count = len(confirmed_candidate_ids)
    false_positive_count = max(candidate_count - confirmed_candidate_count, 0)

    llm_duration = _duration_value(llm_result.get("duration_seconds"))
    fuzz_duration = _duration_value(summary.get("duration_seconds"))
    verification_duration = _duration_value(verification_result.get("duration_seconds"))
    total_duration = _duration_value(
        target_info.get("total_duration_seconds"),
        llm_duration + fuzz_duration + verification_duration,
    )

    lines = [
        f"# {PROJECT_NAME}",
        "",
        "## Environment Summary",
        "",
        f"- Generated At: {datetime.now(timezone.utc).isoformat()}",
        f"- Platform: {platform.platform()}",
        f"- Python: {platform.python_version()}",
        f"- Target Source: {target_info.get('source_path') or 'N/A'}",
        f"- Target Binary: {target_info.get('binary_path') or 'N/A'}",
        f"- Input Mode: {target_info.get('input_mode') or 'stdin'}",
        f"- Ollama Base URL: {target_info.get('ollama_base_url') or 'N/A'}",
        f"- Ollama Model: {target_info.get('ollama_model') or 'N/A'}",
        "",
        "## LLM Candidate Summary",
        "",
        f"- Status: {llm_result.get('status', 'UNKNOWN')}",
        f"- Candidate Count: {candidate_count}",
        f"- Duration Seconds: {llm_duration}",
        "",
        "| Candidate ID | Status | Type | Function | Confidence | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    if candidates:
        for candidate in candidates:
            status = _candidate_final_status(candidate, confirmed_candidate_ids)
            evidence = _markdown_cell(
                candidate.get("evidence") or candidate.get("reason"), 120
            )
            lines.append(
                "| {candidate_id} | {status} | {vuln_type} | {function} | {confidence} | {evidence} |".format(
                    candidate_id=_markdown_cell(candidate.get("candidate_id")),
                    status=status,
                    vuln_type=_markdown_cell(candidate.get("vulnerability_type")),
                    function=_markdown_cell(candidate.get("function")),
                    confidence=_markdown_cell(candidate.get("confidence")),
                    evidence=evidence,
                )
            )
    else:
        lines.append("| N/A | N/A | N/A | N/A | N/A | N/A |")

    lines.extend(
        [
            "",
            "## Fuzzing Summary",
            "",
            f"- Status: {fuzz_result.get('status', 'UNKNOWN')}",
            f"- Total Runs: {summary.get('total_runs', 0)}",
            f"- Suspicious Findings: {summary.get('suspicious_count', 0)}",
            f"- Crash Count: {summary.get('crash_count', 0)}",
            f"- Timeout Count: {summary.get('timeout_count', 0)}",
            f"- Sanitizer Error Count: {summary.get('sanitizer_error_count', 0)}",
            f"- Abnormal Exit Count: {summary.get('abnormal_exit_count', 0)}",
            f"- Duration Seconds: {fuzz_duration}",
            "",
            "## Verification Summary",
            "",
            f"- Status: {verification_result.get('status', 'UNKNOWN')}",
            f"- Verification Runs Per Finding: {verification_result.get('runs_per_finding', 0)}",
            f"- Confirmation Threshold: {verification_result.get('confirmation_threshold', 0)}",
            f"- Confirmed Finding Count: {confirmed_count}",
            f"- Confirmed LLM Candidate Count: {confirmed_candidate_count}",
            f"- Not Reproduced Count: {len(not_reproduced)}",
            f"- Duration Seconds: {verification_duration}",
            "",
            "## Metrics",
            "",
            "| Metric | Value |",
            "| --- | --- |",
            f"| Detection Rate | {percentage(detected_ground_truth_count, ground_truth_count)} |",
            f"| Verification Success Rate | {percentage(confirmed_candidate_count, candidate_count)} |",
            f"| False Positive Rate | {percentage(false_positive_count, candidate_count)} |",
            f"| Total Time | {total_duration:.6f} seconds |",
            "",
            "## Final Classification Table",
            "",
            "| Finding ID | Source | Status | Issue Type | Reproduced | Input |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )

    if candidates:
        for candidate in candidates:
            status = _candidate_final_status(candidate, confirmed_candidate_ids)
            lines.append(
                "| {candidate_id} | LLM | {status} | {issue_type} | N/A | N/A |".format(
                    candidate_id=_markdown_cell(candidate.get("candidate_id")),
                    status=status,
                    issue_type=_markdown_cell(candidate.get("vulnerability_type")),
                )
            )

    if verification_findings:
        for item in verification_findings:
            lines.append(
                "| {finding_id} | Fuzzing | {status} | {issue_type} | {matches}/{runs} | {input_path} |".format(
                    finding_id=item.get("finding_id", "N/A"),
                    status=item.get("status", "UNKNOWN"),
                    issue_type=item.get("expected_issue_type", "N/A"),
                    matches=item.get("matching_runs", 0),
                    runs=item.get("verification_runs", 0),
                    input_path=item.get("input_path", "N/A"),
                )
            )
    elif not candidates:
        lines.append("| N/A | N/A | N/A | N/A | 0/0 | N/A |")

    lines.extend(
        [
            "",
            "## Ground Truth",
            "",
            "| ID | Type | Function | Expected Evidence |",
            "| --- | --- | --- | --- |",
        ]
    )

    if ground_truth:
        for item in ground_truth:
            lines.append(
                "| {truth_id} | {truth_type} | {function} | {evidence} |".format(
                    truth_id=_markdown_cell(item.get("id")),
                    truth_type=_markdown_cell(item.get("vulnerability_type")),
                    function=_markdown_cell(item.get("function")),
                    evidence=_markdown_cell(item.get("expected_evidence")),
                )
            )
    else:
        lines.append("| N/A | N/A | N/A | N/A |")

    lines.extend(
        [
            "",
            "## Observations",
            "",
            "- LLM output is not treated as a final vulnerability.",
            "- Only reproducible execution evidence is eligible for CONFIRMED status.",
            "- LLM candidates are confirmed only when a reproduced finding is linked to an LLM-generated seed.",
            "",
            "## Limitations",
            "",
            "- This MVP uses mutation fuzzing only; it does not collect coverage.",
            "- Candidate-to-finding linkage is seed-based, not code-location based.",
            "- Resource usage metrics are not implemented yet.",
            "",
            "## Next Steps",
            "",
            "- Add resource usage logging for CPU and memory metrics.",
            "- Add target-specific execution mode configuration for firmware-style programs.",
            "- Replace the sample target with an authorized firmware component when selected.",
        ]
    )

    (logs_dir / "final_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
