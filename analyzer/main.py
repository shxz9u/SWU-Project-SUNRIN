import logging
import os
import sys
import time
from pathlib import Path

import requests


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
REQUIRED_WORK_DIRS = ("target", "seeds", "crashes", "logs")


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


def ensure_work_dirs(work_dir: Path) -> None:
    for dirname in REQUIRED_WORK_DIRS:
        path = work_dir / dirname
        path.mkdir(parents=True, exist_ok=True)
        logging.info("work directory ready: %s", path)


def model_matches(configured_model: str, available_model: str) -> bool:
    return available_model == configured_model or available_model.startswith(
        f"{configured_model}:"
    )


def check_ollama(base_url: str, model: str) -> bool:
    tags_url = f"{base_url.rstrip('/')}/api/tags"
    logging.info("checking Ollama API: %s", tags_url)

    try:
        response = requests.get(tags_url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as exc:
        logging.error("Ollama connection failed: %s", exc)
        return False

    try:
        payload = response.json()
    except ValueError:
        logging.error("Ollama connection failed: /api/tags returned non-JSON data")
        return False

    models = [item.get("name", "") for item in payload.get("models", [])]
    models = [name for name in models if name]

    logging.info("Ollama connection succeeded")
    if models:
        logging.info("available Ollama models: %s", ", ".join(models))
    else:
        logging.warning("Ollama responded successfully, but no models were listed")

    if model:
        if any(model_matches(model, available) for available in models):
            logging.info("configured Ollama model found: %s", model)
        else:
            logging.warning("configured Ollama model not listed by /api/tags: %s", model)

    return True


def wait_for_ollama(
    base_url: str, model: str, retries: int, delay_seconds: float
) -> bool:
    for attempt in range(1, retries + 1):
        if check_ollama(base_url, model):
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


def main() -> int:
    configure_logging()

    work_dir = Path(os.getenv("WORK_DIR", "/work"))
    ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "gemma4")
    ollama_retries = int(os.getenv("OLLAMA_CONNECT_RETRIES", "30"))
    ollama_delay = float(os.getenv("OLLAMA_CONNECT_DELAY_SECONDS", "2"))

    logging.info("Raspberry Pi analysis gateway container starting")
    logging.info("WORK_DIR=%s", work_dir)
    logging.info("OLLAMA_BASE_URL=%s", ollama_base_url)
    logging.info("OLLAMA_MODEL=%s", ollama_model)

    ensure_work_dirs(work_dir)

    if not wait_for_ollama(
        ollama_base_url, ollama_model, ollama_retries, ollama_delay
    ):
        return 1

    logging.info("startup checks completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
