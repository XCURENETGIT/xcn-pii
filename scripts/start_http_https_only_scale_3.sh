#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/lib/version_common.sh"

cd "${PROJECT_ROOT}"
if [[ ! -f certs/tls.crt || ! -f certs/tls.key ]]; then
  echo "Missing certs/tls.crt or certs/tls.key. Run ./scripts/make_self_signed_cert.sh <hostname> first, or place production cert files there." >&2
  exit 1
fi

HTTP_SCALE="${PII_HTTP_SCALE:-3}"
if ! [[ "${HTTP_SCALE}" =~ ^[0-9]+$ ]] || [[ "${HTTP_SCALE}" -lt 1 ]]; then
  echo "PII_HTTP_SCALE must be a positive integer" >&2
  exit 1
fi

pii_export_image_version "${PROJECT_ROOT}"
echo "Starting HTTP API HTTPS-only scale mode with api=${HTTP_SCALE} on port ${PII_HTTPS_PORT:-28443}"
docker compose -f docker-compose.yml -f docker-compose.https-only.yml -f docker-compose.http-scale.yml -f docker-compose.https.yml --profile http --profile https up -d --build --scale "api=${HTTP_SCALE}" api https-proxy
