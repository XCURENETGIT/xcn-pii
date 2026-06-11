#!/usr/bin/env bash
set -euo pipefail

NO_START="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-start)
      NO_START="true"
      shift
      ;;
    --help|-h)
      echo "Usage: ./install.sh [--no-start]"
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 1
      ;;
  esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROJECT_ROOT}"

if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose plugin is required" >&2
  exit 1
fi

if compgen -G "images/*.tar" >/dev/null; then
  for image_archive in images/*.tar; do
    echo "Loading Docker image archive: ${image_archive}"
    docker load -i "${image_archive}"
  done
else
  echo "no image archive found under ${PROJECT_ROOT}/images" >&2
  exit 1
fi

if [[ -f ".env.package" && ! -f ".env" ]]; then
  cp ".env.package" ".env"
fi

mkdir -p logs

if [[ -f "model-cache/hf-cache.tar.gz" ]]; then
  echo "Restoring HuggingFace model cache into Docker volume xcn-pii_hf_cache"
  docker volume create xcn-pii_hf_cache >/dev/null

  CACHE_RESTORE_REPO="$(grep -E '^PII_IMAGE_REPO=' .env 2>/dev/null | tail -n 1 | cut -d '=' -f 2- || true)"
  CACHE_RESTORE_TAG="$(grep -E '^PII_IMAGE_TAG=' .env 2>/dev/null | tail -n 1 | cut -d '=' -f 2- || true)"
  CACHE_RESTORE_REPO="${CACHE_RESTORE_REPO:-xcn-pii}"
  CACHE_RESTORE_TAG="${CACHE_RESTORE_TAG:-$(tr -d '\r' < VERSION | head -n 1)}"

  CACHE_RESTORE_IMAGE="${CACHE_RESTORE_REPO}/api-http-cpu:${CACHE_RESTORE_TAG}"
  if ! docker image inspect "${CACHE_RESTORE_IMAGE}" >/dev/null 2>&1; then
    CACHE_RESTORE_IMAGE="${CACHE_RESTORE_REPO}/api-grpc-cpu:${CACHE_RESTORE_TAG}"
  fi
  if ! docker image inspect "${CACHE_RESTORE_IMAGE}" >/dev/null 2>&1; then
    echo "cache restore image not found for tag ${CACHE_RESTORE_TAG}: ${CACHE_RESTORE_REPO}/api-http-cpu or ${CACHE_RESTORE_REPO}/api-grpc-cpu" >&2
    exit 1
  fi

  docker run --rm \
    -v "xcn-pii_hf_cache:/hf" \
    -v "${PROJECT_ROOT}/model-cache:/cache:ro" \
    "${CACHE_RESTORE_IMAGE}" \
    sh -c 'tar -C /hf -xzf /cache/hf-cache.tar.gz'
fi

if [[ "${NO_START}" == "true" ]]; then
  echo "Install completed. Start manually with ./start.sh"
  exit 0
fi

./start.sh
