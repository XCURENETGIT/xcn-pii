#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/lib/version_common.sh"
GRPC_WORKERS="${1:-${PII_GRPC_MAX_WORKERS:-6}}"

if ! [[ "${GRPC_WORKERS}" =~ ^[0-9]+$ ]] || [[ "${GRPC_WORKERS}" -lt 1 ]]; then
  echo "grpc_workers must be a positive integer" >&2
  exit 1
fi

cd "${PROJECT_ROOT}"
pii_export_image_version "${PROJECT_ROOT}"
export PII_GRPC_MAX_WORKERS="${GRPC_WORKERS}"
export PII_HS_COMBINED_ENABLED="${PII_HS_COMBINED_ENABLED:-true}"
export PII_CONTEXT_EMBED_MAX_CHARS="${PII_CONTEXT_EMBED_MAX_CHARS:-256}"
export PII_EMBED_DEVICE=cpu
export PII_GUARDRAIL_DEVICE=cpu
export NVIDIA_VISIBLE_DEVICES=void
export NVIDIA_DRIVER_CAPABILITIES=
export TORCH_INSTALL_PACKAGE="${TORCH_INSTALL_PACKAGE:-torch==2.11.0+cpu}"
export TORCH_INDEX_URL="${TORCH_INDEX_URL:-https://download.pytorch.org/whl/cpu}"
export TORCH_EXTRA_INDEX_URL="${TORCH_EXTRA_INDEX_URL:-https://pypi.org/simple}"

echo "Starting gRPC CPU direct mode with 1 replica, ${GRPC_WORKERS} worker(s)"
docker compose --profile grpc stop api-grpc-lb api-grpc >/dev/null 2>&1 || true
docker compose --profile grpc rm -f api-grpc-lb api-grpc >/dev/null 2>&1 || true
docker compose -f docker-compose.grpc-cpu.yml --profile grpc stop api-grpc-lb api-grpc >/dev/null 2>&1 || true
docker compose -f docker-compose.grpc-cpu.yml --profile grpc rm -f api-grpc-lb api-grpc >/dev/null 2>&1 || true
docker compose -f docker-compose.grpc-cpu.yml -f docker-compose.direct.yml --profile grpc up -d --build api-grpc
