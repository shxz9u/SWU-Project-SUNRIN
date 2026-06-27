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


def write_final_report(
    logs_dir: Path,
    target_info: dict[str, Any],
    fuzz_result: dict[str, Any],
    verification_result: dict[str, Any],
) -> None:
    logs_dir.mkdir(parents=True, exist_ok=True)
    llm_result = ensure_llm_candidates(logs_dir)

    candidates = llm_result.get("candidates", [])
    verification_findings = verification_result.get("findings", [])
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
        "",
        "## LLM Candidate Summary",
        "",
        f"- Status: {llm_result.get('status', 'UNKNOWN')}",
        f"- Candidate Count: {candidate_count}",
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
        f"- Duration Seconds: {summary.get('duration_seconds', 0)}",
        "",
        "## Verification Summary",
        "",
        f"- Status: {verification_result.get('status', 'UNKNOWN')}",
        f"- Verification Runs Per Finding: {verification_result.get('runs_per_finding', 0)}",
        f"- Confirmation Threshold: {verification_result.get('confirmation_threshold', 0)}",
        f"- Confirmed Count: {confirmed_count}",
        f"- Not Reproduced Count: {len(not_reproduced)}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Detection Rate | {percentage(candidate_count, target_info.get('ground_truth_count', 0))} |",
        f"| Verification Success Rate | {percentage(confirmed_count, candidate_count)} |",
        f"| False Positive Rate | {percentage(max(candidate_count - confirmed_count, 0), candidate_count)} |",
        f"| Total Time | {summary.get('duration_seconds', 0)} seconds |",
        "",
        "## Final Classification Table",
        "",
        "| Finding ID | Status | Issue Type | Reproduced | Input |",
        "| --- | --- | --- | --- | --- |",
    ]

    if verification_findings:
        for item in verification_findings:
            lines.append(
                "| {finding_id} | {status} | {issue_type} | {matches}/{runs} | {input_path} |".format(
                    finding_id=item.get("finding_id", "N/A"),
                    status=item.get("status", "UNKNOWN"),
                    issue_type=item.get("expected_issue_type", "N/A"),
                    matches=item.get("matching_runs", 0),
                    runs=item.get("verification_runs", 0),
                    input_path=item.get("input_path", "N/A"),
                )
            )
    else:
        lines.append("| N/A | N/A | N/A | 0/0 | N/A |")

    lines.extend(
        [
            "",
            "## Observations",
            "",
            "- LLM output is not treated as a final vulnerability.",
            "- Only reproducible execution evidence is eligible for CONFIRMED status.",
            "",
            "## Limitations",
            "",
            "- This MVP uses mutation fuzzing only; it does not collect coverage.",
            "- Non-zero exit codes are treated as suspicious and may need target-specific tuning.",
            "- Resource usage metrics are not implemented yet.",
            "",
            "## Next Steps",
            "",
            "- Add LLM candidate generation and seed generation once the Ollama model is ready.",
            "- Add target-specific execution mode configuration for firmware-style programs.",
            "- Add resource usage logging for CPU and memory metrics.",
        ]
    )

    (logs_dir / "final_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
