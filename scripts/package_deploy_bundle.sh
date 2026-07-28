#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_DIR="${PROJECT_ROOT}/dist"
BUNDLE_NAME=""
MODE="all-cpu"
INCLUDE_ENV="false"
INCLUDE_HTTPS="false"
HTTPS_ONLY="false"
INCLUDE_HF_CACHE="true"
HF_CACHE_VOLUME="${PII_HF_CACHE_VOLUME:-xcn-pii_hf_cache}"
GRPC_SCALE="${PII_GRPC_SCALE:-3}"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/package_deploy_bundle.sh [--output-dir <dir>] [--name <bundle-name>] [--include-env] [--no-hf-cache] [--hf-volume <name>] [--grpc-scale <n>]

Examples:
  docker compose -f docker-compose.http-cpu.yml --profile http up -d --build api
  docker compose -f docker-compose.grpc-cpu.yml --profile grpc up -d --build api-grpc api-grpc-lb
  ./scripts/package_deploy_bundle.sh --output-dir ./dist

Behavior:
  - Uses VERSION as the Docker image tag.
  - Packages Docker images already present on this build host.
  - Creates a single runtime package for HTTP + HTTPS + gRPC CPU services.
  - The target host starts services with: docker compose up -d
  - Includes the HuggingFace model cache Docker volume by default for offline semantic context.
  - Does not build images. Build first with docker compose build/up when VERSION changes.
  - Writes .env.package so the target host runs the VERSION-tagged images.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --mode=*)
      MODE="${1#*=}"
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --output-dir=*)
      OUTPUT_DIR="${1#*=}"
      shift
      ;;
    --name)
      BUNDLE_NAME="$2"
      shift 2
      ;;
    --name=*)
      BUNDLE_NAME="${1#*=}"
      shift
      ;;
    --include-env)
      INCLUDE_ENV="true"
      shift
      ;;
    --include-https)
      INCLUDE_HTTPS="true"
      shift
      ;;
    --https-only)
      INCLUDE_HTTPS="true"
      HTTPS_ONLY="true"
      shift
      ;;
    --no-hf-cache)
      INCLUDE_HF_CACHE="false"
      shift
      ;;
    --hf-volume)
      HF_CACHE_VOLUME="$2"
      shift 2
      ;;
    --hf-volume=*)
      HF_CACHE_VOLUME="${1#*=}"
      shift
      ;;
    --grpc-scale)
      GRPC_SCALE="$2"
      shift 2
      ;;
    --grpc-scale=*)
      GRPC_SCALE="${1#*=}"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "required command not found: ${command_name}" >&2
    exit 1
  fi
}

read_app_version() {
  local version_file="${PROJECT_ROOT}/VERSION"
  if [[ ! -f "${version_file}" ]]; then
    echo "VERSION file is missing: ${version_file}" >&2
    exit 1
  fi
  local version_line
  version_line="$(tr -d '\r' < "${version_file}" | head -n 1)"
  if [[ -z "${version_line}" ]]; then
    echo "VERSION file is empty" >&2
    exit 1
  fi
  printf '%s\n' "${version_line}"
}

load_env_file() {
  local file_path="$1"
  if [[ -f "${file_path}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${file_path}"
    set +a
  fi
}

image_exists() {
  docker image inspect "$1" >/dev/null 2>&1
}

volume_exists() {
  docker volume inspect "$1" >/dev/null 2>&1
}

tag_first_existing_image() {
  local target_image="$1"
  shift
  local candidates=("$@")

  for candidate in "${target_image}" "${candidates[@]}"; do
    if image_exists "${candidate}"; then
      if [[ "${candidate}" != "${target_image}" ]]; then
        docker tag "${candidate}" "${target_image}"
      fi
      return 0
    fi
  done
  return 1
}

copy_file() {
  local source_path="$1"
  local target_path="$2"
  mkdir -p "$(dirname "${target_path}")"
  cp "${source_path}" "${target_path}"
}

write_sanitized_env() {
  local target_path="$1"
  {
    echo "PII_IMAGE_REPO=${PII_IMAGE_REPO}"
    echo "PII_IMAGE_TAG=${PII_IMAGE_TAG}"
    echo "PII_GRPC_SCALE=${GRPC_SCALE}"
    echo "PII_GRPC_MAX_WORKERS=${PII_GRPC_MAX_WORKERS:-7}"
    echo "PII_DETECT_PROCESS_WORKERS=${PII_DETECT_PROCESS_WORKERS:-4}"
    echo "PII_DETECT_QUEUE_LIMIT=${PII_DETECT_QUEUE_LIMIT:-1}"
    echo "PII_SPLIT_MAX_WORKERS=${PII_SPLIT_MAX_WORKERS:-1}"
    echo "PII_CONTEXT_RULE_FIRST_ENABLED=${PII_CONTEXT_RULE_FIRST_ENABLED:-true}"
    echo "PII_CONTEXT_EMBED_NORMALIZE_DIGITS=${PII_CONTEXT_EMBED_NORMALIZE_DIGITS:-true}"
    echo "PII_MODEL_PRELOAD_ENABLED=true"
    if [[ -f "${PROJECT_ROOT}/.env" ]]; then
      while IFS= read -r line || [[ -n "${line}" ]]; do
        case "${line}" in
          ""|\#*) continue ;;
          PII_IMAGE_REPO=*|PII_IMAGE_TAG=*|PII_GRPC_SCALE=*|PII_GRPC_MAX_WORKERS=*|PII_DETECT_PROCESS_WORKERS=*|PII_DETECT_QUEUE_LIMIT=*|PII_SPLIT_MAX_WORKERS=*|PII_CONTEXT_RULE_FIRST_ENABLED=*|PII_CONTEXT_EMBED_NORMALIZE_DIGITS=*|PII_MODEL_PRELOAD_ENABLED=*) continue ;;
          *) echo "${line}" ;;
        esac
      done < "${PROJECT_ROOT}/.env"
    fi
  } > "${target_path}"
}

write_install_script() {
  local target_path="$1"
  cat > "${target_path}" <<'INSTALL_EOF'
#!/usr/bin/env bash
set -euo pipefail

NO_START="false"
INSTALL_MODE="grpc"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      INSTALL_MODE="$2"
      shift 2
      ;;
    --mode=*)
      INSTALL_MODE="${1#*=}"
      shift
      ;;
    --no-start)
      NO_START="true"
      shift
      ;;
    --help|-h)
      echo "Usage: ./install.sh [--mode all|http|https|grpc] [--no-start]"
      echo "Default mode: grpc"
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

case "${INSTALL_MODE}" in
  all)
    INSTALL_PROFILES="http,https,grpc"
    ;;
  http)
    INSTALL_PROFILES="http"
    ;;
  https)
    INSTALL_PROFILES="https"
    ;;
  grpc)
    INSTALL_PROFILES="grpc"
    ;;
  *)
    echo "unsupported mode: ${INSTALL_MODE}" >&2
    echo "valid modes: all, http, https, grpc" >&2
    exit 1
    ;;
esac

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
touch ".env"

set_env_value() {
  local key="$1"
  local value="$2"
  local tmp_file
  tmp_file="$(mktemp)"
  if grep -qE "^${key}=" ".env"; then
    sed -E "s|^${key}=.*|${key}=${value}|" ".env" > "${tmp_file}"
  else
    cat ".env" > "${tmp_file}"
    printf '%s=%s\n' "${key}" "${value}" >> "${tmp_file}"
  fi
  mv "${tmp_file}" ".env"
}

set_env_value "COMPOSE_PROFILES" "${INSTALL_PROFILES}"
set_env_value "PII_PACKAGE_MODE" "${INSTALL_MODE}"

mkdir -p logs
mkdir -p data certs

if [[ "${INSTALL_MODE}" == "all" || "${INSTALL_MODE}" == "https" ]] && [[ ! -f "certs/tls.crt" || ! -f "certs/tls.key" ]]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "certs/tls.crt and certs/tls.key are missing, and openssl is not available to create a self-signed certificate" >&2
    echo "place TLS files under ${PROJECT_ROOT}/certs before running docker compose up -d" >&2
    exit 1
  fi
  HTTPS_NAME="$(grep -E '^PII_HTTPS_SERVER_NAME=' .env 2>/dev/null | tail -n 1 | cut -d '=' -f 2- || true)"
  HTTPS_NAME="${HTTPS_NAME:-localhost}"
  if [[ "${HTTPS_NAME}" == "_" ]]; then
    HTTPS_NAME="localhost"
  fi
  if [[ "${HTTPS_NAME}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    HTTPS_SAN="IP:${HTTPS_NAME},IP:127.0.0.1,DNS:localhost"
  else
    HTTPS_SAN="DNS:${HTTPS_NAME},DNS:localhost,IP:127.0.0.1"
  fi
  echo "Creating self-signed HTTPS certificate for ${HTTPS_NAME}"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "certs/tls.key" \
    -out "certs/tls.crt" \
    -days 3650 \
    -subj "/CN=${HTTPS_NAME}" \
    -addext "subjectAltName=${HTTPS_SAN}"
  chmod 600 "certs/tls.key"
  chmod 644 "certs/tls.crt"
fi

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
  if ! docker run --rm \
    -v "xcn-pii_hf_cache:/hf" \
    -v "${PROJECT_ROOT}/model-cache:/cache:ro" \
    "${CACHE_RESTORE_IMAGE}" \
    sh -c 'find /hf -mindepth 1 -exec rm -rf {} + && tar -C /hf -xzf /cache/hf-cache.tar.gz'; then
    echo "Docker-based cache restore failed; falling back to host tar" >&2
    CACHE_VOLUME_DIR="$(docker volume inspect xcn-pii_hf_cache --format '{{ .Mountpoint }}')"
    if [[ -z "${CACHE_VOLUME_DIR}" || ! -d "${CACHE_VOLUME_DIR}" ]]; then
      echo "cannot resolve Docker volume mountpoint for xcn-pii_hf_cache" >&2
      exit 1
    fi
    find "${CACHE_VOLUME_DIR}" -mindepth 1 -exec rm -rf {} +
    tar -C "${CACHE_VOLUME_DIR}" -xzf "model-cache/hf-cache.tar.gz"
  fi
fi

if [[ "${NO_START}" == "true" ]]; then
  echo "Install completed for mode=${INSTALL_MODE}. Start manually with: docker compose up -d"
  exit 0
fi

echo "Starting package mode=${INSTALL_MODE} profiles=${INSTALL_PROFILES}"
docker compose up -d --force-recreate --remove-orphans
INSTALL_EOF
}

validate_generated_install_script() {
  local target_path="$1"
  if ! bash -n "${target_path}"; then
    echo "generated install.sh has a shell syntax error: ${target_path}" >&2
    exit 1
  fi
  if ! grep -q 'api-http-cpu' "${target_path}" || ! grep -q 'api-grpc-cpu' "${target_path}"; then
    echo "generated install.sh must support both HTTP and gRPC cache restore images" >&2
    exit 1
  fi
  if ! grep -q 'docker image inspect "${CACHE_RESTORE_IMAGE}"' "${target_path}"; then
    echo "generated install.sh is missing local image inspection before cache restore" >&2
    exit 1
  fi
}

write_package_readme() {
  local target_path="$1"
  cat > "${target_path}" <<'README_EOF'
# xcn-pii offline package

This directory is a fixed-layout offline runtime package.

Common commands:

```bash
./install.sh
./install.sh --mode all --no-start
./install.sh --mode http --no-start
./install.sh --mode https --no-start
./install.sh --mode grpc --no-start
docker compose up -d
docker compose down
docker compose ps
docker compose logs -f
```

Notes:

- `install.sh` loads Docker images and prepares runtime files. It also runs `docker compose up -d` unless `--no-start` is specified.
- `install.sh` defaults to gRPC mode. Use `--mode all|http|https|grpc` to select another runtime mode.
- `install.sh --mode all|http|https|grpc` selects which services are active by writing `COMPOSE_PROFILES` to `.env`.
- gRPC modes start `api-grpc` with 3 replicas by default through `PII_GRPC_SCALE=3` and HAProxy LB.
- Each gRPC replica runs 4 detector processes and accepts 1 waiting request by default.
- This CPU/PyTorch package supports at most 3 gRPC replicas.
- Runtime images exclude compiler/CMake packages and Python test/development files.
- `docker-compose.yml` is the single runtime compose file for HTTP, HTTPS, gRPC, and HAProxy.
- `install.sh` creates a self-signed HTTPS certificate if `certs/tls.crt` and `certs/tls.key` are missing.
- Use `docker compose up -d` for start/restart and `docker compose down` for stop.
- Source build/start scripts are not required on the offline target host.
README_EOF
}

case "${MODE}" in
  http-cpu|grpc-cpu|all-cpu)
    ;;
  *)
    echo "unsupported mode: ${MODE}" >&2
    usage >&2
    exit 1
    ;;
esac

if [[ "${MODE}" != "all-cpu" ]]; then
  echo "single package mode only supports --mode all-cpu" >&2
  exit 1
fi

if [[ "${INCLUDE_HTTPS}" == "true" || "${HTTPS_ONLY}" == "true" ]]; then
  echo "compose-only single package does not support --include-https/--https-only yet" >&2
  exit 1
fi

if ! [[ "${GRPC_SCALE}" =~ ^[0-9]+$ ]] || [[ "${GRPC_SCALE}" -lt 1 ]] || [[ "${GRPC_SCALE}" -gt 3 ]]; then
  echo "grpc scale must be an integer between 1 and 3" >&2
  exit 1
fi

require_command docker
require_command tar
if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose plugin is required" >&2
  exit 1
fi

cd "${PROJECT_ROOT}"
load_env_file "${PROJECT_ROOT}/.env"

APP_VERSION="$(read_app_version)"
PII_IMAGE_REPO="${PII_IMAGE_REPO:-xcn-pii}"
PII_IMAGE_TAG="${APP_VERSION}"

HTTP_IMAGE="${PII_IMAGE_REPO}/api-http-cpu:${PII_IMAGE_TAG}"
GRPC_IMAGE="${PII_IMAGE_REPO}/api-grpc-cpu:${PII_IMAGE_TAG}"

IMAGES=()
if ! tag_first_existing_image \
  "${HTTP_IMAGE}" \
  "xcn-pii/api-http-cpu:${APP_VERSION}" \
  "xcn-pii/api-http-cpu:latest" \
  "xcn-pii/api:${APP_VERSION}" \
  "xcn-pii/api:latest" \
  "xcn-pii-api:latest" \
  "xcn-pii-api"; then
  echo "failed to find HTTP CPU image: ${HTTP_IMAGE}" >&2
  echo "build first with: docker compose -f docker-compose.http-cpu.yml --profile http build api" >&2
  exit 1
fi
IMAGES+=("${HTTP_IMAGE}")

if ! tag_first_existing_image \
  "${GRPC_IMAGE}" \
  "xcn-pii/api-grpc-cpu:${APP_VERSION}" \
  "xcn-pii/api-grpc-cpu:latest" \
  "xcn-pii/api-grpc:${APP_VERSION}-cpu" \
  "xcn-pii/api-grpc:${APP_VERSION}" \
  "xcn-pii/api-grpc:latest-cpu" \
  "xcn-pii/api-grpc:latest" \
  "xcn-pii-api-grpc:latest" \
  "xcn-pii-api-grpc"; then
  echo "failed to find gRPC CPU image: ${GRPC_IMAGE}" >&2
  echo "build first with: docker compose -f docker-compose.grpc-cpu.yml --profile grpc build api-grpc" >&2
  exit 1
fi
IMAGES+=("${GRPC_IMAGE}" "haproxy:3.1-alpine" "nginx:1.27-alpine")

for image_name in "${IMAGES[@]}"; do
  if ! image_exists "${image_name}"; then
    echo "required image not found: ${image_name}" >&2
    exit 1
  fi
done

if [[ -z "${BUNDLE_NAME}" ]]; then
  BUNDLE_NAME="xcn-pii-all-cpu-package-${APP_VERSION}-$(date +%Y%m%d-%H%M%S)"
fi

mkdir -p "${OUTPUT_DIR}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
BUNDLE_ROOT_NAME="xcn-pii"
BUNDLE_DIR="${WORK_DIR}/${BUNDLE_ROOT_NAME}"
mkdir -p "${BUNDLE_DIR}/images"

copy_file "${PROJECT_ROOT}/VERSION" "${BUNDLE_DIR}/VERSION"
copy_file "${PROJECT_ROOT}/.env.example" "${BUNDLE_DIR}/.env.example"
copy_file "${PROJECT_ROOT}/docker-compose.package.yml" "${BUNDLE_DIR}/docker-compose.yml"
copy_file "${PROJECT_ROOT}/infra/haproxy/grpc-lb.cfg" "${BUNDLE_DIR}/infra/haproxy/grpc-lb.cfg"
copy_file "${PROJECT_ROOT}/infra/nginx/https.conf.template" "${BUNDLE_DIR}/infra/nginx/https.conf.template"

write_sanitized_env "${BUNDLE_DIR}/.env.package"
if [[ "${INCLUDE_ENV}" == "true" && -f "${PROJECT_ROOT}/.env" ]]; then
  copy_file "${PROJECT_ROOT}/.env" "${BUNDLE_DIR}/.env.source"
fi
write_install_script "${BUNDLE_DIR}/install.sh"
validate_generated_install_script "${BUNDLE_DIR}/install.sh"
write_package_readme "${BUNDLE_DIR}/README.md"

if [[ "${INCLUDE_HF_CACHE}" == "true" ]]; then
  if ! volume_exists "${HF_CACHE_VOLUME}"; then
    echo "HuggingFace cache volume not found: ${HF_CACHE_VOLUME}" >&2
    echo "start the service and run a context-enabled request first, or use --no-hf-cache" >&2
    exit 1
  fi
  mkdir -p "${BUNDLE_DIR}/model-cache"
  CACHE_EXPORT_IMAGE="${HTTP_IMAGE}"
  if [[ "${MODE}" == "grpc-cpu" ]]; then
    CACHE_EXPORT_IMAGE="${GRPC_IMAGE}"
  fi
  echo "Saving HuggingFace model cache from Docker volume ${HF_CACHE_VOLUME}"
  docker run --rm \
    -v "${HF_CACHE_VOLUME}:/hf:ro" \
    -v "${BUNDLE_DIR}/model-cache:/out" \
    "${CACHE_EXPORT_IMAGE}" \
    sh -c 'if [ -z "$(find /hf -mindepth 1 -print -quit)" ]; then exit 42; fi; tar -C /hf -czf /out/hf-cache.tar.gz .'
fi

chmod +x "${BUNDLE_DIR}/install.sh"

IMAGE_ARCHIVE="${BUNDLE_DIR}/images/xcn-pii-images.tar"
echo "Saving Docker images to ${IMAGE_ARCHIVE}"
docker save -o "${IMAGE_ARCHIVE}" "${IMAGES[@]}"

{
  echo "package=${BUNDLE_NAME}"
  echo "created_at=$(date -Iseconds)"
  echo "app_version=${APP_VERSION}"
  echo "mode=${MODE}"
  echo "runtime_modes=all,http,https,grpc"
  echo "runtime_backend=cpu-pytorch"
  echo "runtime_pruning=build-toolchain,python-tests,torch-development-files"
  echo "grpc_scale=${GRPC_SCALE}"
  echo "include_http=true"
  echo "include_https=true"
  echo "include_grpc=true"
  echo "include_hf_cache=${INCLUDE_HF_CACHE}"
  if [[ "${INCLUDE_HF_CACHE}" == "true" ]]; then
    echo "hf_cache_volume=${HF_CACHE_VOLUME}"
  fi
  echo "images:"
  printf '  - %s\n' "${IMAGES[@]}"
} > "${BUNDLE_DIR}/MANIFEST.txt"

ARCHIVE_PATH="${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz"
tar -C "${WORK_DIR}" -czf "${ARCHIVE_PATH}" "${BUNDLE_ROOT_NAME}"

echo "Created package: ${ARCHIVE_PATH}"
echo "Install on target:"
echo "  tar -xzf $(basename "${ARCHIVE_PATH}")"
echo "  cd ${BUNDLE_ROOT_NAME}"
echo "  ./install.sh --no-start"
echo "  docker compose up -d"
