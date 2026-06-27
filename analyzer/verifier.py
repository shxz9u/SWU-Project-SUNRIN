import time
from pathlib import Path
from typing import Any

from analyzer.execution import run_target


def verify_findings(
    binary_path: Path,
    findings: list[dict[str, Any]],
    input_mode: str,
    timeout_seconds: float,
    runs_per_finding: int = 3,
    confirmation_threshold: int = 2,
) -> dict[str, Any]:
    started = time.monotonic()
    verified: list[dict[str, Any]] = []

    for finding in findings:
        input_path = Path(finding["input_path"])
        input_data = input_path.read_bytes()
        expected_issue_type = finding.get("issue_type")
        expected_signature = finding.get("issue_signature")
        runs = []
        matching_runs = 0

        for run_index in range(runs_per_finding):
            result = run_target(binary_path, input_data, input_mode, timeout_seconds)
            same_type = result.get("issue_type") == expected_issue_type
            same_signature = result.get("issue_signature") == expected_signature
            matched = same_type and (
                same_signature or expected_issue_type in {"timeout", "sanitizer_error"}
            )
            if matched:
                matching_runs += 1

            runs.append(
                {
                    "run_index": run_index,
                    "issue_type": result.get("issue_type"),
                    "issue_signature": result.get("issue_signature"),
                    "exit_code": result.get("exit_code"),
                    "timed_out": result.get("timed_out"),
                    "duration_seconds": result.get("duration_seconds"),
                    "matched": matched,
                }
            )

        status = (
            "CONFIRMED"
            if matching_runs >= confirmation_threshold
            else "NOT_REPRODUCED"
        )
        verified.append(
            {
                "finding_id": finding.get("finding_id"),
                "status": status,
                "input_path": str(input_path),
                "input_sha256": finding.get("input_sha256"),
                "expected_issue_type": expected_issue_type,
                "expected_issue_signature": expected_signature,
                "verification_runs": runs_per_finding,
                "matching_runs": matching_runs,
                "runs": runs,
            }
        )

    duration = time.monotonic() - started
    return {
        "status": "OK",
        "runs_per_finding": runs_per_finding,
        "confirmation_threshold": confirmation_threshold,
        "duration_seconds": round(duration, 6),
        "findings": verified,
        "summary": {
            "total_findings": len(verified),
            "confirmed_count": sum(
                1 for item in verified if item.get("status") == "CONFIRMED"
            ),
            "not_reproduced_count": sum(
                1 for item in verified if item.get("status") == "NOT_REPRODUCED"
            ),
        },
    }
