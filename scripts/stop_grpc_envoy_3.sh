#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"
docker compose --profile grpc stop api-grpc-envoy api-grpc || true
docker compose --profile grpc rm -f api-grpc-envoy api-grpc || true
