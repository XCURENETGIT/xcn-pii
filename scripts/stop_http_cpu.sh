#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

echo "Stopping HTTP CPU mode"
docker compose -f docker-compose.http-cpu.yml --profile http stop api >/dev/null 2>&1 || true
docker compose -f docker-compose.http-cpu.yml --profile http rm -f api >/dev/null 2>&1 || true
