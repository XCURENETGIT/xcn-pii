#!/usr/bin/env sh
set -eu

BUNDLE_PATH="${1:-.}"
BASE_IMAGE="${2:-}"
TARGET_IMAGE="${3:-}"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/build_patched_image.sh <patch-bundle-dir|patch-bundle.tar.gz> <base-image> [target-image]

Examples:
  ./scripts/build_patched_image.sh ./patch-http-cpu-1.0.1 xcn-pii/api-http-cpu:1.0.0 xcn-pii/api-http-cpu:1.0.1-patch1
  ./scripts/build_patched_image.sh ./patch-grpc-cpu-1.0.1.tar.gz xcn-pii/api-grpc-cpu:1.0.0 xcn-pii/api-grpc-cpu:1.0.1-patch1

Behavior:
  - Verifies payload file hashes with apply_runtime_patch.sh.
  - Builds a new Docker image layer from the existing base image.
  - Copies payload files into /app inside the new image.
EOF
}

if [ "${BUNDLE_PATH}" = "--help" ] || [ "${BUNDLE_PATH}" = "-h" ] || [ -z "${BASE_IMAGE}" ]; then
  usage
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "required command not found: docker" >&2
  exit 1
fi

if ! docker image inspect "${BASE_IMAGE}" >/dev/null 2>&1; then
  echo "base image not found locally: ${BASE_IMAGE}" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

if [ -d "${BUNDLE_PATH}" ]; then
  BUNDLE_DIR="${BUNDLE_PATH}"
else
  tar -xzf "${BUNDLE_PATH}" -C "${WORK_DIR}"
  BUNDLE_DIR="$(find "${WORK_DIR}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
fi

MANIFEST_PATH="${BUNDLE_DIR}/manifest.json"
PAYLOAD_DIR="${BUNDLE_DIR}/payload"
if [ ! -f "${MANIFEST_PATH}" ] || [ ! -d "${PAYLOAD_DIR}" ]; then
  echo "invalid patch bundle: ${BUNDLE_PATH}" >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -x "${BUNDLE_DIR}/apply_runtime_patch.sh" ]; then
  APPLY_SCRIPT="${BUNDLE_DIR}/apply_runtime_patch.sh"
else
  APPLY_SCRIPT="${SCRIPT_DIR}/apply_runtime_patch.sh"
fi

VERIFY_ROOT="${WORK_DIR}/verify-root"
mkdir -p "${VERIFY_ROOT}"
XCN_PATCH_SKIP_PREFLIGHT=1 sh "${APPLY_SCRIPT}" "${BUNDLE_DIR}" "${VERIFY_ROOT}" >/dev/null

if [ -z "${TARGET_IMAGE}" ]; then
  TARGET_IMAGE="$(python - "${MANIFEST_PATH}" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(manifest.get("target_image") or "")
PY
)"
fi

if [ -z "${TARGET_IMAGE}" ]; then
  echo "target image is required when manifest.target_image is empty" >&2
  exit 1
fi

BUILD_DIR="${WORK_DIR}/build"
mkdir -p "${BUILD_DIR}"
cp -R "${PAYLOAD_DIR}" "${BUILD_DIR}/payload"
cp "${MANIFEST_PATH}" "${BUILD_DIR}/manifest.json"

cat > "${BUILD_DIR}/Dockerfile.patch" <<EOF
FROM ${BASE_IMAGE}
WORKDIR /app
COPY payload/ /app/
COPY manifest.json /app/PATCH_MANIFEST.json
LABEL xcn.patch.base_image="${BASE_IMAGE}"
LABEL xcn.patch.target_image="${TARGET_IMAGE}"
EOF

docker build -t "${TARGET_IMAGE}" -f "${BUILD_DIR}/Dockerfile.patch" "${BUILD_DIR}"
echo "Created patched image: ${TARGET_IMAGE}"
