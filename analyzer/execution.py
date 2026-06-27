import hashlib
import os
import subprocess
import time
from pathlib import Path
from typing import Any


SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "LeakSanitizer",
    "MemorySanitizer",
    "runtime error:",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "use-after-free",
    "double-free",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def preview_bytes(data: bytes, limit: int = 4096) -> str:
    return data[:limit].decode("utf-8", errors="replace")


def sanitizer_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0:symbolize=0")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
    return env


def issue_signature(issue_type: str | None, exit_code: int | None, stderr: bytes) -> str:
    if not issue_type:
        return "none"
    if issue_type == "sanitizer_error":
        stderr_text = stderr.decode("utf-8", errors="replace")
        for marker in SANITIZER_MARKERS:
            if marker in stderr_text:
                return f"sanitizer:{marker}"
        return "sanitizer:unknown"
    if issue_type in {"crash", "abnormal_exit"}:
        return f"{issue_type}:exit_code={exit_code}"
    return issue_type


def classify_issue(
    timed_out: bool, exit_code: int | None, stdout: bytes, stderr: bytes
) -> str | None:
    if timed_out:
        return "timeout"

    combined = preview_bytes(stdout + b"\n" + stderr, limit=16384)
    if any(marker in combined for marker in SANITIZER_MARKERS):
        return "sanitizer_error"

    if exit_code is None:
        return "timeout"
    if exit_code < 0 or exit_code >= 128:
        return "crash"
    if exit_code != 0:
        return "abnormal_exit"
    return None


def run_target(
    binary_path: Path,
    input_data: bytes,
    input_mode: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    started = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    stdout = b""
    stderr = b""

    command = [str(binary_path)]
    run_input = input_data

    if input_mode == "argv":
        argv_value = input_data.replace(b"\x00", b"\\0").decode(
            "utf-8", errors="replace"
        )
        command.append(argv_value)
        run_input = None

    try:
        completed = subprocess.run(
            command,
            input=run_input,
            capture_output=True,
            timeout=timeout_seconds,
            env=sanitizer_env(),
            check=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""

    duration = time.monotonic() - started
    issue_type = classify_issue(timed_out, exit_code, stdout, stderr)

    return {
        "input_sha256": sha256_bytes(input_data),
        "input_size": len(input_data),
        "input_mode": input_mode,
        "timeout_seconds": timeout_seconds,
        "duration_seconds": round(duration, 6),
        "timed_out": timed_out,
        "exit_code": exit_code,
        "issue_type": issue_type,
        "issue_signature": issue_signature(issue_type, exit_code, stderr),
        "stdout_preview": preview_bytes(stdout),
        "stderr_preview": preview_bytes(stderr),
    }
