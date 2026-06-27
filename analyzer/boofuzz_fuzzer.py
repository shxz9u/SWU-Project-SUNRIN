import logging
import time
from pathlib import Path
from typing import Any

from analyzer.execution import run_target
from analyzer.result_writer import write_json
from analyzer.verifier import verify_findings


BLOCKED_PATTERNS = (
    "rm -rf",
    "mkfs",
    "shutdown",
    "poweroff",
    "reboot",
    "halt",
    "touch /tmp",
    ":(){",
)


FIELD_SPECS = (
    {
        "field": "ssid",
        "default": "iot-lab",
        "ground_truth_ids": ["GT-001"],
        "values": ["iot-lab", "A" * 40, "A" * 96, "A" * 256],
    },
    {
        "field": "password",
        "default": "guest",
        "ground_truth_ids": ["GT-002"],
        "values": ["guest", "B" * 40, "B" * 96, "B" * 256],
    },
    {
        "field": "topic",
        "default": "telemetry/data",
        "ground_truth_ids": ["GT-003"],
        "values": ["telemetry/data", "C" * 80, "C" * 160, "C" * 512],
    },
    {
        "field": "log",
        "default": "boot ok",
        "ground_truth_ids": ["GT-004"],
        "values": ["boot ok", "%x%x%x%x", "%p.%p.%p", "%n%n%n%n"],
    },
    {
        "field": "auth",
        "default": "admin:sunrin_admin123",
        "ground_truth_ids": ["GT-005"],
        "values": ["admin:sunrin_admin123", "admin:admin", "root:root"],
    },
    {
        "field": "port",
        "default": "1883",
        "ground_truth_ids": ["GT-006"],
        "values": ["1883", "-1", "0", "65536", "2147483647"],
    },
    {
        "field": "cmd",
        "default": "status",
        "ground_truth_ids": [],
        "values": ["status", "status;id", "status&&id", "status|id"],
    },
)


def _safe_text(value: str) -> bool:
    lowered = value.lower()
    return not any(pattern in lowered for pattern in BLOCKED_PATTERNS)


def _boofuzz_library_values(limit: int = 8) -> list[str]:
    try:
        from boofuzz import String
    except ImportError:
        return []

    values: list[str] = []
    for value in getattr(String, "_fuzz_library", []):
        text = str(value)
        if not _safe_text(text):
            continue
        if len(text.encode("utf-8", errors="ignore")) > 512:
            continue
        values.append(text)
        if len(values) >= limit:
            break
    return values


def _render_boofuzz_case(field: str, value: str, index: int) -> bytes:
    from boofuzz import Request, Static, String
    from boofuzz.mutation import Mutation
    from boofuzz.mutation_context import MutationContext

    request = Request(
        name=f"{field}_config_line",
        children=[
            Static(name=f"{field}_prefix", default_value=f"{field}="),
            String(name=f"{field}_value", default_value="normal"),
            Static(name=f"{field}_newline", default_value="\n"),
        ],
    )
    value_node = request.names[f"{request.name}.{field}_value"]
    mutation = Mutation(
        value=value,
        qualified_name=value_node.qualified_name,
        index=index,
    )
    return request.render(MutationContext([mutation]))


def generate_boofuzz_cases(max_cases: int) -> list[dict[str, Any]]:
    library_values = _boofuzz_library_values()
    cases: list[dict[str, Any]] = []
    seen_payloads: set[bytes] = set()

    for spec in FIELD_SPECS:
        values = [*spec["values"], *library_values]
        for value in values:
            if len(cases) >= max_cases:
                return cases
            if not _safe_text(str(value)):
                continue

            payload = _render_boofuzz_case(
                spec["field"],
                str(value),
                len(cases),
            )
            if payload in seen_payloads:
                continue
            seen_payloads.add(payload)
            cases.append(
                {
                    "case_id": f"BOOFUZZ-CASE-{len(cases) + 1:03d}",
                    "field": spec["field"],
                    "request_name": f"{spec['field']}_config_line",
                    "expected_ground_truth_ids": spec["ground_truth_ids"],
                    "payload": payload,
                }
            )

    return cases


def _save_suspicious_input(
    crashes_dir: Path,
    finding_id: str,
    issue_type: str,
    input_data: bytes,
) -> Path:
    path = crashes_dir / f"{finding_id}_{issue_type.replace('/', '_')}.input"
    path.write_bytes(input_data)
    return path


def _clear_generated_crashes(crashes_dir: Path) -> None:
    crashes_dir.mkdir(parents=True, exist_ok=True)
    for path in crashes_dir.iterdir():
        if path.is_file() and path.name.startswith("BOOFUZZ-") and path.suffix == ".input":
            path.unlink()


def run_boofuzz_route(
    binary_path: Path,
    logs_dir: Path,
    crashes_dir: Path,
    input_mode: str,
    timeout_seconds: float,
    max_cases: int,
    verify_runs: int,
    verify_threshold: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    started = time.monotonic()
    _clear_generated_crashes(crashes_dir)
    cases = generate_boofuzz_cases(max_cases)
    runs: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()

    logging.info("starting boofuzz route: cases=%d", len(cases))

    for index, case in enumerate(cases):
        input_data = case["payload"]
        result = run_target(binary_path, input_data, input_mode, timeout_seconds)
        result.update(
            {
                "run_index": index,
                "case_id": case["case_id"],
                "field": case["field"],
                "request_name": case["request_name"],
                "expected_ground_truth_ids": case["expected_ground_truth_ids"],
            }
        )
        runs.append(result)

        issue_type = result.get("issue_type")
        input_hash = result["input_sha256"]
        if issue_type and input_hash not in seen_hashes:
            finding_id = f"BOOFUZZ-{len(suspicious) + 1:03d}"
            input_path = _save_suspicious_input(
                crashes_dir,
                finding_id,
                issue_type,
                input_data,
            )
            suspicious.append(
                {
                    "finding_id": finding_id,
                    "status": "FUZZ_TRIGGERED",
                    "input_path": str(input_path),
                    **result,
                }
            )
            seen_hashes.add(input_hash)
            logging.info("boofuzz suspicious input saved: %s", input_path)

    duration = time.monotonic() - started
    result = {
        "status": "OK",
        "route": "boofuzz",
        "binary_path": str(binary_path),
        "input_mode": input_mode,
        "timeout_seconds": timeout_seconds,
        "max_cases": max_cases,
        "summary": {
            "total_runs": len(runs),
            "case_count": len(cases),
            "suspicious_count": len(suspicious),
            "crash_count": sum(1 for item in runs if item.get("issue_type") == "crash"),
            "timeout_count": sum(1 for item in runs if item.get("issue_type") == "timeout"),
            "sanitizer_error_count": sum(
                1 for item in runs if item.get("issue_type") == "sanitizer_error"
            ),
            "abnormal_exit_count": sum(
                1 for item in runs if item.get("issue_type") == "abnormal_exit"
            ),
            "duration_seconds": round(duration, 6),
        },
        "suspicious_findings": suspicious,
        "runs": runs,
    }

    verification = verify_findings(
        binary_path=binary_path,
        findings=suspicious,
        input_mode=input_mode,
        timeout_seconds=timeout_seconds,
        runs_per_finding=verify_runs,
        confirmation_threshold=verify_threshold,
    )
    write_json(logs_dir / "boofuzz_result.json", result)
    write_json(logs_dir / "boofuzz_verification_result.json", verification)
    return result, verification
