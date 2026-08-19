#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROFILE="all"
BASE_VERSION=""
CPU_BASE_VERSION=""
GPU_BASE_VERSION=""
IMAGE_REPO="xcn-pii"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/prepare_source_build_env.sh [options]

Options:
  --profile cpu|gpu|all          Profile to prepare. Default: all
  --base-version <version>       Base version for every selected profile.
  --cpu-base-version <version>   CPU base version (overrides --base-version).
  --gpu-base-version <version>   GPU base version (overrides --base-version).
  --image-repo <repo>            Docker repository. Default: xcn-pii

The matching HTTP and gRPC runtime images must already exist on this host.
Only compiler tools and Cython are added; application dependencies are reused.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    --base-version) BASE_VERSION="$2"; shift 2 ;;
    --base-version=*) BASE_VERSION="${1#*=}"; shift ;;
    --cpu-base-version) CPU_BASE_VERSION="$2"; shift 2 ;;
    --cpu-base-version=*) CPU_BASE_VERSION="${1#*=}"; shift ;;
    --gpu-base-version) GPU_BASE_VERSION="$2"; shift 2 ;;
    --gpu-base-version=*) GPU_BASE_VERSION="${1#*=}"; shift ;;
    --image-repo) IMAGE_REPO="$2"; shift 2 ;;
    --image-repo=*) IMAGE_REPO="${1#*=}"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

case "${PROFILE}" in cpu|gpu|all) ;; *) echo "unsupported profile: ${PROFILE}" >&2; exit 1 ;; esac

for command_name in docker sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "required command not found: ${command_name}" >&2
    exit 1
  }
done

profile_base_version() {
  local profile="$1"
  local version="${BASE_VERSION}"
  if [[ "${profile}" == "cpu" && -n "${CPU_BASE_VERSION}" ]]; then version="${CPU_BASE_VERSION}"; fi
  if [[ "${profile}" == "gpu" && -n "${GPU_BASE_VERSION}" ]]; then version="${GPU_BASE_VERSION}"; fi
  if [[ -z "${version}" ]]; then
    echo "base version is required for profile ${profile}" >&2
    exit 1
  fi
  printf '%s\n' "${version}"
}

dependency_sha() {
  local profile="$1"
  local semantic_file="${PROJECT_ROOT}/requirements-semantic.txt"
  if [[ "${profile}" == "gpu" ]]; then semantic_file="${PROJECT_ROOT}/requirements-semantic-gpu.txt"; fi
  sha256sum \
    "${PROJECT_ROOT}/Dockerfile.${profile}" \
    "${PROJECT_ROOT}/Dockerfile.source-builder.${profile}" \
    "${PROJECT_ROOT}/Dockerfile.source-release" \
    "${PROJECT_ROOT}/requirements-base.txt" \
    "${PROJECT_ROOT}/requirements-http.txt" \
    "${PROJECT_ROOT}/requirements-grpc.txt" \
    "${semantic_file}" \
    | sha256sum | awk '{print $1}'
}

prepare_profile() {
  local profile="$1"
  local base_version
  base_version="$(profile_base_version "${profile}")"
  local http_image="${IMAGE_REPO}/api-http-${profile}:${base_version}"
  local grpc_image="${IMAGE_REPO}/api-grpc-${profile}:${base_version}"
  local dependency_fingerprint short_fingerprint builder_image
  dependency_fingerprint="$(dependency_sha "${profile}")"
  short_fingerprint="${dependency_fingerprint:0:12}"
  builder_image="${IMAGE_REPO}/source-builder-${profile}:${base_version}-${short_fingerprint}"

  for base_image in "${http_image}" "${grpc_image}"; do
    docker image inspect "${base_image}" >/dev/null 2>&1 || {
      echo "base runtime image not found: ${base_image}" >&2
      exit 1
    }
  done

  local http_image_id grpc_image_id
  http_image_id="$(docker image inspect -f '{{.Id}}' "${http_image}")"
  grpc_image_id="$(docker image inspect -f '{{.Id}}' "${grpc_image}")"

  if docker image inspect "${builder_image}" >/dev/null 2>&1; then
    if [[ "$(docker image inspect -f '{{ index .Config.Labels "xcn.source-build.http-base-image-id" }}' "${builder_image}")" == "${http_image_id}" \
       && "$(docker image inspect -f '{{ index .Config.Labels "xcn.source-build.grpc-base-image-id" }}' "${builder_image}")" == "${grpc_image_id}" \
       && "$(docker image inspect -f '{{ index .Config.Labels "xcn.source-build.dependencies-sha256" }}' "${builder_image}")" == "${dependency_fingerprint}" ]]; then
      echo "Reusing prepared source builder: ${builder_image}"
      return
    fi
  fi

  echo "Preparing ${profile} source builder"
  echo "  http_base=${http_image}"
  echo "  grpc_base=${grpc_image}"
  echo "  dependency_sha256=${dependency_fingerprint}"
  echo "  builder_image=${builder_image}"

  docker build --pull=false \
    --build-arg "BASE_RUNTIME_IMAGE=${grpc_image}" \
    --build-arg "HTTP_BASE_IMAGE_ID=${http_image_id}" \
    --build-arg "GRPC_BASE_IMAGE_ID=${grpc_image_id}" \
    --build-arg "DEPENDENCY_SHA256=${dependency_fingerprint}" \
    -f "${PROJECT_ROOT}/Dockerfile.source-builder.${profile}" \
    -t "${builder_image}" \
    "${PROJECT_ROOT}"

  echo "Prepared source builder: ${builder_image}"
}

cd "${PROJECT_ROOT}"
if [[ "${PROFILE}" == "cpu" || "${PROFILE}" == "all" ]]; then prepare_profile cpu; fi
if [[ "${PROFILE}" == "gpu" || "${PROFILE}" == "all" ]]; then prepare_profile gpu; fi
