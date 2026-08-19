#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROFILE="all"
BASE_VERSION=""
CPU_BASE_VERSION=""
GPU_BASE_VERSION=""
TARGET_VERSION=""
TARGET_TAG=""
IMAGE_REPO="xcn-pii"
PACKAGE="false"
FORCE="false"
OUTPUT_DIR="${PROJECT_ROOT}/dist"
NAME_SUFFIX="$(date +%Y%m%d-%H%M%S)"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/build_source_release.sh [options]

Options:
  --profile cpu|gpu|all          Profile to build. Default: all
  --base-version <version>       Base version for every selected profile.
  --cpu-base-version <version>   CPU base version (overrides --base-version).
  --gpu-base-version <version>   GPU base version (overrides --base-version).
  --target-version <version>     Version expected in VERSION. Default: VERSION.
  --target-tag <tag>             Docker tag. Default: target version.
  --image-repo <repo>            Docker repository. Default: xcn-pii
  --package                      Create the selected offline package(s).
  --force                        Allow replacing target images/bundles.
  --output-dir <dir>             Package output directory. Default: dist
  --name-suffix <suffix>         Package name suffix. Default: timestamp
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
    --target-version) TARGET_VERSION="$2"; shift 2 ;;
    --target-version=*) TARGET_VERSION="${1#*=}"; shift ;;
    --target-tag) TARGET_TAG="$2"; shift 2 ;;
    --target-tag=*) TARGET_TAG="${1#*=}"; shift ;;
    --image-repo) IMAGE_REPO="$2"; shift 2 ;;
    --image-repo=*) IMAGE_REPO="${1#*=}"; shift ;;
    --package) PACKAGE="true"; shift ;;
    --force) FORCE="true"; shift ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --output-dir=*) OUTPUT_DIR="${1#*=}"; shift ;;
    --name-suffix) NAME_SUFFIX="$2"; shift 2 ;;
    --name-suffix=*) NAME_SUFFIX="${1#*=}"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

case "${PROFILE}" in cpu|gpu|all) ;; *) echo "unsupported profile: ${PROFILE}" >&2; exit 1 ;; esac
for command_name in docker sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 || { echo "required command not found: ${command_name}" >&2; exit 1; }
done

read_version() { tr -d '\r' < "${PROJECT_ROOT}/VERSION" | head -n 1; }
TARGET_VERSION="${TARGET_VERSION:-$(read_version)}"
TARGET_TAG="${TARGET_TAG:-${TARGET_VERSION}}"
if [[ "$(read_version)" != "${TARGET_VERSION}" ]]; then
  echo "VERSION mismatch: expected ${TARGET_VERSION}, found $(read_version)" >&2
  exit 1
fi
if [[ "${PACKAGE}" == "true" && "${TARGET_TAG}" != "${TARGET_VERSION}" ]]; then
  echo "--package requires --target-tag to match --target-version" >&2
  exit 1
fi

profile_base_version() {
  local profile="$1" version="${BASE_VERSION}"
  if [[ "${profile}" == "cpu" && -n "${CPU_BASE_VERSION}" ]]; then version="${CPU_BASE_VERSION}"; fi
  if [[ "${profile}" == "gpu" && -n "${GPU_BASE_VERSION}" ]]; then version="${GPU_BASE_VERSION}"; fi
  if [[ -z "${version}" ]]; then echo "base version is required for profile ${profile}" >&2; exit 1; fi
  printf '%s\n' "${version}"
}

dependency_sha() {
  local profile="$1" semantic_file="${PROJECT_ROOT}/requirements-semantic.txt"
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

build_profile() {
  local profile="$1" base_version
  base_version="$(profile_base_version "${profile}")"
  local dependency_fingerprint short_fingerprint builder_image
  dependency_fingerprint="$(dependency_sha "${profile}")"
  short_fingerprint="${dependency_fingerprint:0:12}"
  builder_image="${IMAGE_REPO}/source-builder-${profile}:${base_version}-${short_fingerprint}"

  docker image inspect "${builder_image}" >/dev/null 2>&1 || {
    echo "source builder not found: ${builder_image}" >&2
    echo "run prepare_source_build_env.sh for ${profile} base ${base_version}" >&2
    exit 1
  }

  local kind base_image target_image base_image_id expected_label
  for kind in http grpc; do
    base_image="${IMAGE_REPO}/api-${kind}-${profile}:${base_version}"
    target_image="${IMAGE_REPO}/api-${kind}-${profile}:${TARGET_TAG}"
    docker image inspect "${base_image}" >/dev/null 2>&1 || { echo "base runtime image not found: ${base_image}" >&2; exit 1; }
    if [[ "${FORCE}" != "true" ]] && docker image inspect "${target_image}" >/dev/null 2>&1; then
      echo "target image already exists: ${target_image}" >&2
      echo "use --force only when replacing it is intentional" >&2
      exit 1
    fi
  done

  if [[ "$(docker image inspect -f '{{ index .Config.Labels "xcn.source-build.dependencies-sha256" }}' "${builder_image}")" != "${dependency_fingerprint}" ]]; then
    echo "dependency inputs changed; full build and source-builder refresh are required" >&2
    exit 1
  fi

  for kind in http grpc; do
    base_image="${IMAGE_REPO}/api-${kind}-${profile}:${base_version}"
    target_image="${IMAGE_REPO}/api-${kind}-${profile}:${TARGET_TAG}"
    base_image_id="$(docker image inspect -f '{{.Id}}' "${base_image}")"
    expected_label="xcn.source-build.${kind}-base-image-id"
    if [[ "$(docker image inspect -f "{{ index .Config.Labels \"${expected_label}\" }}" "${builder_image}")" != "${base_image_id}" ]]; then
      echo "${kind} base image changed; prepare the source builder again" >&2
      exit 1
    fi

    echo "Building source-only ${profile}/${kind} image: ${target_image}"
    docker build --pull=false \
      --build-arg "SOURCE_BUILDER_IMAGE=${builder_image}" \
      --build-arg "BASE_RUNTIME_IMAGE=${base_image}" \
      --build-arg "BASE_IMAGE_ID=${base_image_id}" \
      --build-arg "DEPENDENCY_SHA256=${dependency_fingerprint}" \
      --build-arg "RELEASE_VERSION=${TARGET_VERSION}" \
      --build-arg "RUNTIME_KIND=${kind}" \
      --build-arg "RUNTIME_PROFILE=${profile}" \
      -f "${PROJECT_ROOT}/Dockerfile.source-release" \
      -t "${target_image}" \
      "${PROJECT_ROOT}"

    local image_version
    image_version="$(docker run --rm --entrypoint cat "${target_image}" /app/VERSION | tr -d '\r')"
    [[ "${image_version}" == "${TARGET_VERSION}" ]] || { echo "built image version mismatch: ${image_version}" >&2; exit 1; }
    docker run --rm --entrypoint python3 "${target_image}" -c 'import app.store; print("source_modules=ok")'
    echo "Created source-only image: ${target_image}"
  done

  if [[ "${PACKAGE}" == "true" ]]; then
    bash "${PROJECT_ROOT}/scripts/package_deploy_bundle.sh" \
      --mode "all-${profile}" \
      --output-dir "${OUTPUT_DIR}" \
      --name "xcn-pii-package-${TARGET_VERSION}-${profile}-${NAME_SUFFIX}"
  fi
}

cd "${PROJECT_ROOT}"
if [[ "${PROFILE}" == "cpu" || "${PROFILE}" == "all" ]]; then build_profile cpu; fi
if [[ "${PROFILE}" == "gpu" || "${PROFILE}" == "all" ]]; then build_profile gpu; fi
