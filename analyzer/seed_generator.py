from pathlib import Path
from typing import Any

from analyzer.result_writer import write_json


BASELINE_SEEDS = (
    "ssid=lab-gateway\npassword=guest1234\nlog=boot ok\n",
    "ssid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
    "password=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n",
    "log=%x%x%x%x%x%x%x%x\n",
    "log=%n%n%n%n\n",
    "cmd=status\n",
    "cmd=restart;id\n",
    "port=-1\n",
    "port=65536\n",
    "auth=admin:sunrin_admin123\n",
)
BLOCKED_SEED_PATTERNS = (
    "rm -rf",
    "mkfs",
    "shutdown",
    "poweroff",
    "reboot",
    "halt",
)


def _safe_candidate_id(value: str, fallback: str) -> str:
    candidate_id = value if value.startswith("LLM-") else fallback
    return "".join(ch for ch in candidate_id if ch.isalnum() or ch in "-_")


def _clear_generated_seeds(seeds_dir: Path) -> None:
    for path in seeds_dir.iterdir():
        if not path.is_file():
            continue
        if path.name.startswith(("LLM-", "baseline_seed_")):
            path.unlink()


def generate_seed_files(
    candidates: list[dict[str, Any]],
    seeds_dir: Path,
    logs_dir: Path,
) -> dict[str, Any]:
    seeds_dir.mkdir(parents=True, exist_ok=True)
    _clear_generated_seeds(seeds_dir)

    written: list[dict[str, Any]] = []
    seen_values: set[str] = set()

    def write_seed(name: str, value: str, source: str, candidate_id: str | None) -> None:
        lowered = value.lower()
        if any(pattern in lowered for pattern in BLOCKED_SEED_PATTERNS):
            return
        normalized = value if value.endswith("\n") else f"{value}\n"
        if normalized in seen_values:
            return
        seen_values.add(normalized)
        path = seeds_dir / name
        path.write_text(normalized, encoding="utf-8")
        written.append(
            {
                "name": name,
                "path": str(path),
                "source": source,
                "candidate_id": candidate_id,
                "size": len(normalized.encode("utf-8")),
            }
        )

    for candidate_index, candidate in enumerate(candidates, start=1):
        candidate_id = _safe_candidate_id(
            str(candidate.get("candidate_id") or ""),
            f"LLM-{candidate_index:03d}",
        )
        for seed_index, seed in enumerate(candidate.get("suggested_seeds", []), start=1):
            if not str(seed):
                continue
            write_seed(
                f"{candidate_id}_seed_{seed_index:03d}.txt",
                str(seed),
                "llm",
                candidate_id,
            )

    for index, seed in enumerate(BASELINE_SEEDS, start=1):
        write_seed(f"baseline_seed_{index:03d}.txt", seed, "baseline", None)

    result = {
        "status": "OK",
        "seed_count": len(written),
        "seeds": written,
    }
    write_json(logs_dir / "seed_generation.json", result)
    return result
