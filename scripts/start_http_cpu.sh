#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/lib/version_common.sh"

cd "${PROJECT_ROOT}"
pii_export_image_version "${PROJECT_ROOT}"
export PII_EMBED_DEVICE=cpu
export PII_GUARDRAIL_ENABLED=false
export PII_GUARDRAIL_DEVICE=cpu
export NVIDIA_VISIBLE_DEVICES=void
export NVIDIA_DRIVER_CAPABILITIES=

echo "Starting HTTP CPU mode on port 8005"
docker compose -f docker-compose.http-cpu.yml --profile http up -d --build api
