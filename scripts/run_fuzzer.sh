#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DOCKER_CONFIG="${DOCKER_CONFIG:-/tmp/docker-config}"

mkdir -p "$DOCKER_CONFIG"
cd "$ROOT_DIR"

docker compose build pi-gateway
docker compose run --rm --no-deps pi-gateway python -m analyzer.simple_fuzzer "$@"
