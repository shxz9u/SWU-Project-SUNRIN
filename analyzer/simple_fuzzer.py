import argparse
import logging
import os
import random
import subprocess
import time
from pathlib import Path
from typing import Any

from analyzer.execution import run_target, sha256_bytes
from analyzer.result_writer import write_final_report, write_json
from analyzer.verifier import verify_findings


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
DEFAULT_SEEDS = (
    b"",
    b"normal",
    b"test",
    b"A" * 32,
    b"A" * 128,
    b"%x%x%x%x",
    b"../../../../etc/passwd",
    b"\x00",
    b"1",
    b"-1",
    b"2147483647",
)
INTERESTING_TOKENS = (
    b"A",
    b"B" * 16,
    b"%s%s%s%s",
    b"%n",
    b"../",
    b";id",
    b"&&id",
    b"\x00",
    b"\xff",
    b"\r\n",
)


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


def ensure_work_dirs(work_dir: Path) -> dict[str, Path]:
    dirs = {
        "target": work_dir / "target",
        "seeds": work_dir / "seeds",
        "crashes": work_dir / "crashes",
        "logs": work_dir / "logs",
        "build": work_dir / "build",
    }
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def compile_target(source_path: Path, binary_path: Path, logs_dir: Path) -> dict[str, Any]:
    compile_log = logs_dir / "compile.log"
    commands = [
        [
            "clang",
            "-fsanitize=address,undefined",
            "-g",
            "-O1",
            "-o",
            str(binary_path),
            str(source_path),
        ],
        ["gcc", "-g", "-O0", "-o", str(binary_path), str(source_path)],
    ]

    log_lines = []
    for index, command in enumerate(commands):
        label = "sanitizer" if index == 0 else "fallback"
        logging.info("compiling target with %s command: %s", label, " ".join(command))
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        log_lines.extend(
            [
                f"$ {' '.join(command)}",
                f"exit_code={completed.returncode}",
                completed.stdout,
                completed.stderr,
                "",
            ]
        )
        compile_log.write_text("\n".join(log_lines), encoding="utf-8")

        if completed.returncode == 0 and binary_path.exists():
            binary_path.chmod(0o755)
            return {
                "compiled": True,
                "compiler": command[0],
                "sanitizer_enabled": index == 0,
                "compile_log": str(compile_log),
            }

    return {
        "compiled": False,
        "compiler": None,
        "sanitizer_enabled": False,
        "compile_log": str(compile_log),
    }


def prepare_target(
    target_dir: Path, logs_dir: Path, recompile: bool
) -> tuple[Path, dict[str, Any]]:
    source_path = target_dir / "input.c"
    binary_path = target_dir / "target_binary"
    target_info: dict[str, Any] = {
        "source_path": str(source_path) if source_path.exists() else None,
        "binary_path": str(binary_path),
        "ground_truth_count": 0,
    }

    if binary_path.exists() and not recompile:
        binary_path.chmod(0o755)
        target_info.update({"compiled": False, "compile_skipped": True})
        return binary_path, target_info

    if source_path.exists():
        compile_result = compile_target(source_path, binary_path, logs_dir)
        target_info.update(compile_result)
        if compile_result["compiled"]:
            return binary_path, target_info
        raise RuntimeError(f"target compilation failed; see {compile_result['compile_log']}")

    if binary_path.exists():
        binary_path.chmod(0o755)
        target_info.update({"compiled": False, "compile_skipped": True})
        return binary_path, target_info

    raise FileNotFoundError(
        "no fuzz target found: provide /work/target/input.c or /work/target/target_binary"
    )


def load_seed_inputs(seeds_dir: Path) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    for path in sorted(seeds_dir.rglob("*")):
        if not path.is_file() or path.name == ".gitkeep":
            continue
        data = path.read_bytes()
        seeds.append({"name": path.name, "path": str(path), "data": data})

    if seeds:
        return seeds

    return [
        {"name": f"builtin_{index:03d}", "path": None, "data": data}
        for index, data in enumerate(DEFAULT_SEEDS)
    ]


def clamp_input(data: bytes, max_bytes: int) -> bytes:
    if len(data) <= max_bytes:
        return data
    return data[:max_bytes]


def mutate(seed: bytes, rng: random.Random, max_bytes: int) -> bytes:
    choice = rng.randrange(10)
    token = rng.choice(INTERESTING_TOKENS)

    if choice == 0:
        data = seed
    elif choice == 1:
        data = seed * rng.randint(2, 64)
    elif choice == 2:
        data = token + seed + token
    elif choice == 3:
        data = seed + token * rng.randint(1, 32)
    elif choice == 4:
        size = rng.choice([64, 128, 255, 256, 512, 1024, 2048, max_bytes])
        data = rng.choice([b"A", b"\xff", b"%"]) * size
    elif choice == 5:
        data = bytes(rng.randrange(0, 256) for _ in range(rng.randint(1, max_bytes)))
    elif choice == 6:
        mutable = bytearray(seed or b"A")
        for _ in range(rng.randint(1, max(1, min(16, len(mutable))))):
            mutable[rng.randrange(len(mutable))] = rng.randrange(0, 256)
        data = bytes(mutable)
    elif choice == 7:
        data = seed + b"\x00" + token + b"\x00"
    elif choice == 8:
        data = b"/" * rng.randint(16, 512) + seed
    else:
        data = str(rng.choice([-1, 0, 1, 255, 256, 1024, 2147483647])).encode()

    return clamp_input(data, max_bytes)


def save_suspicious_input(
    crashes_dir: Path,
    finding_id: str,
    issue_type: str,
    input_data: bytes,
) -> Path:
    safe_issue = issue_type.replace("/", "_")
    path = crashes_dir / f"{finding_id}_{safe_issue}.input"
    path.write_bytes(input_data)
    return path


def clear_generated_crashes(crashes_dir: Path) -> None:
    crashes_dir.mkdir(parents=True, exist_ok=True)
    for path in crashes_dir.iterdir():
        if path.is_file() and path.name.startswith("FUZZ-") and path.suffix == ".input":
            path.unlink()


def fuzz(
    binary_path: Path,
    dirs: dict[str, Path],
    iterations: int,
    timeout_seconds: float,
    input_mode: str,
    rng_seed: int,
    max_input_bytes: int,
) -> dict[str, Any]:
    started = time.monotonic()
    rng = random.Random(rng_seed)
    seeds = load_seed_inputs(dirs["seeds"])
    runs: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []
    seen_suspicious_hashes: set[str] = set()

    clear_generated_crashes(dirs["crashes"])
    logging.info("loaded %d seed inputs", len(seeds))
    logging.info("starting mutation fuzzing: iterations=%d", iterations)

    for index in range(iterations):
        seed = seeds[index % len(seeds)]
        input_data = mutate(seed["data"], rng, max_input_bytes)
        result = run_target(binary_path, input_data, input_mode, timeout_seconds)
        result.update(
            {
                "run_index": index,
                "seed_name": seed["name"],
                "seed_path": seed["path"],
            }
        )
        runs.append(result)

        issue_type = result.get("issue_type")
        input_hash = result["input_sha256"]
        if issue_type and input_hash not in seen_suspicious_hashes:
            finding_id = f"FUZZ-{len(suspicious) + 1:03d}"
            input_path = save_suspicious_input(
                dirs["crashes"], finding_id, issue_type, input_data
            )
            finding = {
                "finding_id": finding_id,
                "status": "FUZZ_TRIGGERED",
                "input_path": str(input_path),
                **result,
            }
            suspicious.append(finding)
            seen_suspicious_hashes.add(input_hash)
            logging.info(
                "suspicious input saved: %s issue=%s", input_path, issue_type
            )

    duration = time.monotonic() - started
    summary = {
        "total_runs": len(runs),
        "seed_count": len(seeds),
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
    }

    return {
        "status": "OK",
        "binary_path": str(binary_path),
        "input_mode": input_mode,
        "timeout_seconds": timeout_seconds,
        "rng_seed": rng_seed,
        "max_input_bytes": max_input_bytes,
        "summary": summary,
        "suspicious_findings": suspicious,
        "runs": runs,
    }


def build_error_outputs(
    logs_dir: Path,
    target_info: dict[str, Any],
    message: str,
) -> None:
    fuzz_result = {
        "status": "ERROR",
        "error": message,
        "target_info": target_info,
        "summary": {
            "total_runs": 0,
            "suspicious_count": 0,
            "crash_count": 0,
            "timeout_count": 0,
            "sanitizer_error_count": 0,
            "abnormal_exit_count": 0,
            "duration_seconds": 0,
        },
        "suspicious_findings": [],
        "runs": [],
    }
    verification_result = {
        "status": "SKIPPED",
        "reason": message,
        "runs_per_finding": 0,
        "confirmation_threshold": 0,
        "findings": [],
        "summary": {"total_findings": 0, "confirmed_count": 0},
    }
    write_json(logs_dir / "fuzz_result.json", fuzz_result)
    write_json(logs_dir / "verification_result.json", verification_result)
    write_final_report(logs_dir, target_info, fuzz_result, verification_result)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple mutation fuzzer")
    parser.add_argument("--iterations", type=int, default=int(os.getenv("FUZZ_ITERATIONS", "200")))
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.getenv("FUZZ_TIMEOUT_SECONDS", "2")),
        help="Per-input timeout in seconds",
    )
    parser.add_argument(
        "--input-mode",
        choices=("stdin", "argv"),
        default=os.getenv("FUZZ_INPUT_MODE", "stdin"),
    )
    parser.add_argument("--seed", type=int, default=int(os.getenv("FUZZ_RANDOM_SEED", "1337")))
    parser.add_argument(
        "--max-input-bytes",
        type=int,
        default=int(os.getenv("FUZZ_MAX_INPUT_BYTES", "4096")),
    )
    parser.add_argument(
        "--verify-runs",
        type=int,
        default=int(os.getenv("FUZZ_VERIFY_RUNS", "3")),
    )
    parser.add_argument(
        "--verify-threshold",
        type=int,
        default=int(os.getenv("FUZZ_VERIFY_THRESHOLD", "2")),
    )
    parser.add_argument(
        "--recompile",
        action="store_true",
        default=os.getenv("FUZZ_RECOMPILE", "0") == "1",
    )
    return parser.parse_args()


def main() -> int:
    configure_logging()
    args = parse_args()
    work_dir = Path(os.getenv("WORK_DIR", "/work"))
    dirs = ensure_work_dirs(work_dir)
    target_info: dict[str, Any] = {"input_mode": args.input_mode}

    try:
        binary_path, prepared_target = prepare_target(
            dirs["target"], dirs["logs"], args.recompile
        )
        target_info.update(prepared_target)
        target_info["input_mode"] = args.input_mode
    except Exception as exc:
        logging.error("target preparation failed: %s", exc)
        build_error_outputs(dirs["logs"], target_info, str(exc))
        return 2

    fuzz_result = fuzz(
        binary_path=binary_path,
        dirs=dirs,
        iterations=args.iterations,
        timeout_seconds=args.timeout,
        input_mode=args.input_mode,
        rng_seed=args.seed,
        max_input_bytes=args.max_input_bytes,
    )
    fuzz_result["target_info"] = target_info
    verification_result = verify_findings(
        binary_path=binary_path,
        findings=fuzz_result["suspicious_findings"],
        input_mode=args.input_mode,
        timeout_seconds=args.timeout,
        runs_per_finding=args.verify_runs,
        confirmation_threshold=args.verify_threshold,
    )

    write_json(dirs["logs"] / "fuzz_result.json", fuzz_result)
    write_json(dirs["logs"] / "verification_result.json", verification_result)
    write_final_report(dirs["logs"], target_info, fuzz_result, verification_result)

    logging.info("fuzzing complete: %s", dirs["logs"] / "fuzz_result.json")
    logging.info("verification complete: %s", dirs["logs"] / "verification_result.json")
    logging.info("report written: %s", dirs["logs"] / "final_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
