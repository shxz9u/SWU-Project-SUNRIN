import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from analyzer.boofuzz_fuzzer import run_boofuzz_route
from analyzer.candidate_parser import parse_llm_candidates
from analyzer.comparison_writer import write_comparison_outputs
from analyzer.ollama_client import OllamaClient, OllamaError
from analyzer.prompt_builder import build_vulnerability_prompt
from analyzer.result_writer import write_final_report, write_json
from analyzer.resource_monitor import measure_resource_usage
from analyzer.seed_generator import generate_seed_files
from analyzer.simple_fuzzer import build_error_outputs, fuzz, prepare_target
from analyzer.verifier import verify_findings


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
REQUIRED_WORK_DIRS = ("target", "seeds", "crashes", "logs", "build")


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


def ensure_work_dirs(work_dir: Path) -> dict[str, Path]:
    dirs = {name: work_dir / name for name in REQUIRED_WORK_DIRS}
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
        logging.info("work directory ready: %s", path)
    return dirs


def model_matches(configured_model: str, available_model: str) -> bool:
    return available_model == configured_model or available_model.startswith(
        f"{configured_model}:"
    )


def check_ollama(client: OllamaClient) -> bool:
    logging.info("checking Ollama API: %s/api/tags", client.base_url)
    try:
        payload = client.tags()
    except OllamaError as exc:
        logging.error("Ollama connection failed: %s", exc)
        return False

    models = [item.get("name", "") for item in payload.get("models", [])]
    models = [name for name in models if name]

    logging.info("Ollama connection succeeded")
    if models:
        logging.info("available Ollama models: %s", ", ".join(models))
    else:
        logging.warning("Ollama responded successfully, but no models were listed")

    if client.model:
        if any(model_matches(client.model, available) for available in models):
            logging.info("configured Ollama model found: %s", client.model)
        else:
            logging.warning(
                "configured Ollama model not listed by /api/tags: %s", client.model
            )

    return True


def wait_for_ollama(
    client: OllamaClient, retries: int, delay_seconds: float
) -> bool:
    for attempt in range(1, retries + 1):
        if check_ollama(client):
            return True

        if attempt < retries:
            logging.info(
                "retrying Ollama connection in %.1f seconds (%d/%d)",
                delay_seconds,
                attempt,
                retries,
            )
            time.sleep(delay_seconds)

    return False


def load_ground_truth(target_dir: Path) -> list[dict[str, Any]]:
    path = target_dir / "ground_truth.json"
    if not path.exists():
        return []

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logging.warning("ground truth JSON could not be parsed: %s", exc)
        return []

    if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
        return [
            item for item in payload["vulnerabilities"] if isinstance(item, dict)
        ]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def run_llm_analysis(
    client: OllamaClient,
    source_path: Path,
    logs_dir: Path,
) -> dict[str, Any]:
    if not source_path.exists():
        result = {
            "status": "SKIPPED",
            "reason": f"source file not found: {source_path}",
            "candidates": [],
        }
        write_json(logs_dir / "llm_candidates.json", result)
        return result

    source_text = source_path.read_text(encoding="utf-8", errors="replace")
    prompt = build_vulnerability_prompt(source_path, source_text)

    try:
        generation = client.generate(prompt)
    except OllamaError as exc:
        result = {
            "status": "ERROR",
            "error": str(exc),
            "model": client.model,
            "candidates": [],
        }
        write_json(logs_dir / "llm_candidates.json", result)
        return result

    parsed = parse_llm_candidates(generation["response"], logs_dir)
    if parsed.get("status") == "OK":
        raw_path = logs_dir / "llm_raw_output.txt"
        if raw_path.exists():
            raw_path.unlink()
    parsed.update(
        {
            "model": client.model,
            "duration_seconds": generation["duration_seconds"],
            "source_path": str(source_path),
            "raw_response_size": len(generation["response"].encode("utf-8")),
        }
    )
    write_json(logs_dir / "llm_candidates.json", parsed)
    return parsed


def run_pipeline(
    work_dir: Path,
    client: OllamaClient,
) -> int:
    started = time.monotonic()
    dirs = ensure_work_dirs(work_dir)

    input_mode = os.getenv("FUZZ_INPUT_MODE", "stdin")
    iterations = int(os.getenv("FUZZ_ITERATIONS", "200"))
    timeout_seconds = float(os.getenv("FUZZ_TIMEOUT_SECONDS", "2"))
    rng_seed = int(os.getenv("FUZZ_RANDOM_SEED", "1337"))
    max_input_bytes = int(os.getenv("FUZZ_MAX_INPUT_BYTES", "4096"))
    verify_runs = int(os.getenv("FUZZ_VERIFY_RUNS", "3"))
    verify_threshold = int(os.getenv("FUZZ_VERIFY_THRESHOLD", "2"))
    recompile = os.getenv("FUZZ_RECOMPILE", "1") == "1"
    boofuzz_max_cases = int(os.getenv("BOOFUZZ_MAX_CASES", "200"))

    ground_truth = load_ground_truth(dirs["target"])
    target_info: dict[str, Any] = {
        "input_mode": input_mode,
        "ollama_base_url": client.base_url,
        "ollama_model": client.model,
        "ground_truth": ground_truth,
        "ground_truth_count": len(ground_truth),
    }

    try:
        binary_path, prepared_target = prepare_target(
            dirs["target"], dirs["logs"], recompile
        )
        target_info.update(prepared_target)
        target_info["input_mode"] = input_mode
    except Exception as exc:
        logging.error("target preparation failed: %s", exc)
        build_error_outputs(dirs["logs"], target_info, str(exc))
        return 2

    resource_log: dict[str, Any] = {"routes": {}}
    source_path = dirs["target"] / "input.c"
    llm_crashes_dir = dirs["crashes"] / "llm_fuzzer"
    boofuzz_crashes_dir = dirs["crashes"] / "boofuzz"
    llm_dirs = {**dirs, "crashes": llm_crashes_dir}

    logging.info("running LLM fuzzer route")
    with measure_resource_usage("llm_fuzzer") as llm_resource:
        llm_result = run_llm_analysis(client, source_path, dirs["logs"])
        logging.info("LLM candidate status: %s", llm_result.get("status"))
        logging.info(
            "LLM candidate count: %d", len(llm_result.get("candidates", []))
        )

        seed_result = generate_seed_files(
            llm_result.get("candidates", []),
            dirs["seeds"],
            dirs["logs"],
        )
        logging.info("seed generation complete: %d seeds", seed_result["seed_count"])

        fuzz_result = fuzz(
            binary_path=binary_path,
            dirs=llm_dirs,
            iterations=iterations,
            timeout_seconds=timeout_seconds,
            input_mode=input_mode,
            rng_seed=rng_seed,
            max_input_bytes=max_input_bytes,
        )
        fuzz_result["target_info"] = target_info
        fuzz_result["seed_generation"] = seed_result

        verification_result = verify_findings(
            binary_path=binary_path,
            findings=fuzz_result["suspicious_findings"],
            input_mode=input_mode,
            timeout_seconds=timeout_seconds,
            runs_per_finding=verify_runs,
            confirmation_threshold=verify_threshold,
        )

    resource_log["routes"]["llm_fuzzer"] = llm_resource
    llm_route_result = {
        "status": "OK",
        "route": "llm_fuzzer",
        "duration_seconds": llm_resource.get("wall_time_seconds", 0),
        "resource_usage": llm_resource,
        "llm_candidates": llm_result,
        "seed_generation": seed_result,
        "fuzz_result": fuzz_result,
        "verification_result": verification_result,
    }

    target_info["total_duration_seconds"] = round(time.monotonic() - started, 6)
    fuzz_result["target_info"] = target_info

    write_json(dirs["logs"] / "fuzz_result.json", fuzz_result)
    write_json(dirs["logs"] / "verification_result.json", verification_result)
    write_json(dirs["logs"] / "llm_fuzzer_result.json", llm_route_result)
    write_json(
        dirs["logs"] / "llm_fuzzer_verification_result.json",
        verification_result,
    )
    write_final_report(dirs["logs"], target_info, fuzz_result, verification_result)

    logging.info("running boofuzz route")
    with measure_resource_usage("boofuzz") as boofuzz_resource:
        boofuzz_result, boofuzz_verification_result = run_boofuzz_route(
            binary_path=binary_path,
            logs_dir=dirs["logs"],
            crashes_dir=boofuzz_crashes_dir,
            input_mode=input_mode,
            timeout_seconds=timeout_seconds,
            max_cases=boofuzz_max_cases,
            verify_runs=verify_runs,
            verify_threshold=verify_threshold,
        )

    resource_log["routes"]["boofuzz"] = boofuzz_resource
    boofuzz_result["resource_usage"] = boofuzz_resource
    write_json(dirs["logs"] / "boofuzz_result.json", boofuzz_result)
    write_json(
        dirs["logs"] / "boofuzz_verification_result.json",
        boofuzz_verification_result,
    )

    llm_route_result["duration_seconds"] = llm_resource.get("wall_time_seconds", 0)
    llm_route_result["resource_usage"] = llm_resource
    write_json(dirs["logs"] / "llm_fuzzer_result.json", llm_route_result)

    write_json(dirs["logs"] / "resource_usage.json", resource_log)
    write_comparison_outputs(
        logs_dir=dirs["logs"],
        ground_truth=ground_truth,
        llm_route_result=llm_route_result,
        boofuzz_result=boofuzz_result,
        boofuzz_verification_result=boofuzz_verification_result,
        resource_log=resource_log,
    )

    target_info["total_duration_seconds"] = round(time.monotonic() - started, 6)
    logging.info("fuzzing complete: %s", dirs["logs"] / "fuzz_result.json")
    logging.info("verification complete: %s", dirs["logs"] / "verification_result.json")
    logging.info("report written: %s", dirs["logs"] / "final_report.md")
    logging.info("comparison written: %s", dirs["logs"] / "comparison_report.md")
    logging.info("pipeline completed in %.6f seconds", target_info["total_duration_seconds"])
    return 0


def main() -> int:
    configure_logging()

    work_dir = Path(os.getenv("WORK_DIR", "/work"))
    ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "gemma4")
    ollama_retries = int(os.getenv("OLLAMA_CONNECT_RETRIES", "30"))
    ollama_delay = float(os.getenv("OLLAMA_CONNECT_DELAY_SECONDS", "2"))
    ollama_timeout = float(os.getenv("OLLAMA_REQUEST_TIMEOUT_SECONDS", "120"))

    client = OllamaClient(ollama_base_url, ollama_model, ollama_timeout)

    logging.info("Raspberry Pi analysis gateway container starting")
    logging.info("WORK_DIR=%s", work_dir)
    logging.info("OLLAMA_BASE_URL=%s", ollama_base_url)
    logging.info("OLLAMA_MODEL=%s", ollama_model)

    if not wait_for_ollama(client, ollama_retries, ollama_delay):
        return 1

    return run_pipeline(work_dir, client)


if __name__ == "__main__":
    sys.exit(main())
