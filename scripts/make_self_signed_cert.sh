#!/usr/bin/env bash
set -euo pipefail

HOSTNAME="${1:-localhost}"
DAYS="${2:-3650}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${PROJECT_ROOT}/certs"

mkdir -p "${CERT_DIR}"

if [[ "${HOSTNAME}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  SAN="IP:${HOSTNAME},IP:127.0.0.1,DNS:localhost"
else
  SAN="DNS:${HOSTNAME},DNS:localhost,IP:127.0.0.1"
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${CERT_DIR}/tls.key" \
  -out "${CERT_DIR}/tls.crt" \
  -days "${DAYS}" \
  -subj "/CN=${HOSTNAME}" \
  -addext "subjectAltName=${SAN}"

chmod 600 "${CERT_DIR}/tls.key"
chmod 644 "${CERT_DIR}/tls.crt"

echo "Created ${CERT_DIR}/tls.crt and ${CERT_DIR}/tls.key"
echo "SubjectAltName: ${SAN}"
