#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-gemma4}"

cd "$ROOT_DIR"

mkdir -p work/target work/seeds work/crashes work/logs

echo "[ollama] starting Docker service"
docker compose up -d ollama

echo "[ollama] waiting for API at ${OLLAMA_BASE_URL}/api/tags"
for attempt in $(seq 1 60); do
  if curl -fsS --max-time 3 "${OLLAMA_BASE_URL%/}/api/tags" >/dev/null; then
    break
  fi

  if [ "$attempt" -eq 60 ]; then
    echo "[ollama] API did not become ready in time" >&2
    exit 1
  fi

  sleep 2
done

echo "[ollama] pulling model: ${OLLAMA_MODEL}"
docker exec ollama ollama pull "$OLLAMA_MODEL"

echo "[ollama] installed models"
curl -fsS "${OLLAMA_BASE_URL%/}/api/tags" | jq .

echo "[ollama] setup complete"
