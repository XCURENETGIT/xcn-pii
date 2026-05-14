#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

echo "Stopping HTTP HTTPS-only mode"
docker compose -f docker-compose.yml -f docker-compose.https-only.yml -f docker-compose.https.yml --profile http --profile https stop https-proxy api >/dev/null 2>&1 || true
docker compose -f docker-compose.yml -f docker-compose.https-only.yml -f docker-compose.https.yml --profile http --profile https rm -f https-proxy api >/dev/null 2>&1 || true
