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
  ./scripts/package_deploy_bundle.sh [--mode http-cpu|grpc-cpu|all-cpu] [--output-dir <dir>] [--name <bundle-name>] [--include-env] [--include-https] [--https-only] [--no-hf-cache] [--hf-volume <name>] [--grpc-scale <n>]

Examples:
  ./scripts/start_http_cpu.sh
  ./scripts/start_grpc_cpu_lb_3.sh
  ./scripts/package_deploy_bundle.sh --mode all-cpu --output-dir ./dist

Behavior:
  - Uses VERSION as the Docker image tag.
  - Packages Docker images already present on this build host.
  - Includes the HuggingFace model cache Docker volume by default for offline semantic context.
  - Does not build images. Build first with the start scripts when VERSION changes.
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
    echo "PII_MODEL_PRELOAD_ENABLED=true"
    if [[ -f "${PROJECT_ROOT}/.env" ]]; then
      while IFS= read -r line || [[ -n "${line}" ]]; do
        case "${line}" in
          ""|\#*) continue ;;
          PII_IMAGE_REPO=*|PII_IMAGE_TAG=*|PII_GRPC_SCALE=*) continue ;;
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

write_start_script() {
  local target_path="$1"
  local mode="$2"
  local include_https="$3"
  local https_only="$4"
  cat > "${target_path}" <<START_EOF
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
if [[ "\$(basename "\${SCRIPT_DIR}")" == "scripts" ]]; then
  PROJECT_ROOT="\$(cd "\${SCRIPT_DIR}/.." && pwd)"
else
  PROJECT_ROOT="\${SCRIPT_DIR}"
fi
cd "\${PROJECT_ROOT}"

if [[ -f ".env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source ".env"
  set +a
elif [[ -f ".env.package" ]]; then
  set -a
  # shellcheck disable=SC1091
  source ".env.package"
  set +a
fi

MODE="${mode}"
INCLUDE_HTTPS="${include_https}"
HTTPS_ONLY="${https_only}"
GRPC_SCALE="\${PII_GRPC_SCALE:-${GRPC_SCALE}}"

case "\${MODE}" in
  http-cpu)
    if [[ "\${INCLUDE_HTTPS}" == "true" && "\${HTTPS_ONLY}" == "true" ]]; then
      mkdir -p certs
      if [[ ! -f certs/tls.crt || ! -f certs/tls.key ]]; then
        echo "HTTPS files certs/tls.crt and certs/tls.key are missing. Place certificates before starting https-proxy." >&2
        exit 1
      fi
      docker compose -f docker-compose.http-cpu.yml -f docker-compose.https-only.yml -f docker-compose.https.yml --profile http --profile https up -d --no-build api https-proxy
    else
      docker compose -f docker-compose.http-cpu.yml --profile http up -d --no-build api
    fi
    ;;
  grpc-cpu)
    docker compose -f docker-compose.grpc-cpu.yml --profile grpc up -d --no-build api-grpc api-grpc-lb
    docker compose -f docker-compose.grpc-cpu.yml --profile grpc up -d --no-build --scale "api-grpc=\${GRPC_SCALE}" api-grpc
    ;;
  all-cpu)
    if [[ "\${INCLUDE_HTTPS}" == "true" && "\${HTTPS_ONLY}" == "true" ]]; then
      mkdir -p certs
      if [[ ! -f certs/tls.crt || ! -f certs/tls.key ]]; then
        echo "HTTPS files certs/tls.crt and certs/tls.key are missing. Place certificates before starting https-proxy." >&2
        exit 1
      fi
      docker compose -f docker-compose.http-cpu.yml -f docker-compose.https-only.yml -f docker-compose.https.yml --profile http --profile https up -d --no-build api https-proxy
    else
      docker compose -f docker-compose.http-cpu.yml --profile http up -d --no-build api
    fi
    docker compose -f docker-compose.grpc-cpu.yml --profile grpc up -d --no-build api-grpc api-grpc-lb
    docker compose -f docker-compose.grpc-cpu.yml --profile grpc up -d --no-build --scale "api-grpc=\${GRPC_SCALE}" api-grpc
    ;;
  *)
    echo "unsupported mode: \${MODE}" >&2
    exit 1
    ;;
esac

if [[ "\${INCLUDE_HTTPS}" == "true" && "\${HTTPS_ONLY}" != "true" ]]; then
  mkdir -p certs
  if [[ ! -f certs/tls.crt || ! -f certs/tls.key ]]; then
    echo "HTTPS files certs/tls.crt and certs/tls.key are missing. Place certificates before starting https-proxy." >&2
  else
    docker compose -f docker-compose.http-cpu.yml -f docker-compose.https.yml --profile http --profile https up -d --no-build https-proxy
  fi
fi
START_EOF
}

write_stop_script() {
  local target_path="$1"
  local mode="$2"
  local include_https="$3"
  local https_only="$4"
  cat > "${target_path}" <<STOP_EOF
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
if [[ "\$(basename "\${SCRIPT_DIR}")" == "scripts" ]]; then
  PROJECT_ROOT="\$(cd "\${SCRIPT_DIR}/.." && pwd)"
else
  PROJECT_ROOT="\${SCRIPT_DIR}"
fi
cd "\${PROJECT_ROOT}"

MODE="${mode}"
INCLUDE_HTTPS="${include_https}"
HTTPS_ONLY="${https_only}"

if [[ "\${INCLUDE_HTTPS}" == "true" && -f "docker-compose.https.yml" ]]; then
  if [[ "\${HTTPS_ONLY}" == "true" && -f "docker-compose.https-only.yml" ]]; then
    docker compose -f docker-compose.http-cpu.yml -f docker-compose.https-only.yml -f docker-compose.https.yml --profile http --profile https stop https-proxy >/dev/null 2>&1 || true
    docker compose -f docker-compose.http-cpu.yml -f docker-compose.https-only.yml -f docker-compose.https.yml --profile http --profile https rm -f https-proxy >/dev/null 2>&1 || true
  else
    docker compose -f docker-compose.http-cpu.yml -f docker-compose.https.yml --profile http --profile https stop https-proxy >/dev/null 2>&1 || true
    docker compose -f docker-compose.http-cpu.yml -f docker-compose.https.yml --profile http --profile https rm -f https-proxy >/dev/null 2>&1 || true
  fi
fi

case "\${MODE}" in
  http-cpu)
    docker compose -f docker-compose.http-cpu.yml --profile http stop api >/dev/null 2>&1 || true
    docker compose -f docker-compose.http-cpu.yml --profile http rm -f api >/dev/null 2>&1 || true
    ;;
  grpc-cpu)
    docker compose -f docker-compose.grpc-cpu.yml --profile grpc stop api-grpc api-grpc-lb >/dev/null 2>&1 || true
    docker compose -f docker-compose.grpc-cpu.yml --profile grpc rm -f api-grpc api-grpc-lb >/dev/null 2>&1 || true
    ;;
  all-cpu)
    docker compose -f docker-compose.http-cpu.yml --profile http stop api >/dev/null 2>&1 || true
    docker compose -f docker-compose.http-cpu.yml --profile http rm -f api >/dev/null 2>&1 || true
    docker compose -f docker-compose.grpc-cpu.yml --profile grpc stop api-grpc api-grpc-lb >/dev/null 2>&1 || true
    docker compose -f docker-compose.grpc-cpu.yml --profile grpc rm -f api-grpc api-grpc-lb >/dev/null 2>&1 || true
    ;;
  *)
    echo "unsupported mode: \${MODE}" >&2
    exit 1
    ;;
esac
STOP_EOF
}

write_package_readme() {
  local target_path="$1"
  cat > "${target_path}" <<'README_EOF'
# xcn-pii offline package

This directory is a fixed-layout offline runtime package.

Common commands:

```bash
./install.sh
./install.sh --no-start
./start.sh
./stop.sh
./scripts/start-http-cpu.sh
./scripts/stop-http-cpu.sh
./scripts/start-grpc-cpu.sh
./scripts/stop-grpc-cpu.sh
./scripts/start-all-cpu.sh
./scripts/stop-all-cpu.sh
```

Notes:

- `install.sh` loads Docker images and prepares runtime files.
- `start.sh` starts the default mode selected when this package was created.
- `stop.sh` stops the default mode selected when this package was created.
- `scripts/start-http-cpu.sh` and `scripts/stop-http-cpu.sh` operate only the HTTP service.
- `scripts/start-grpc-cpu.sh` and `scripts/stop-grpc-cpu.sh` operate only the gRPC service.
- `scripts/start-all-cpu.sh` and `scripts/stop-all-cpu.sh` operate both HTTP and gRPC services.
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

if [[ "${HTTPS_ONLY}" == "true" && "${MODE}" == "grpc-cpu" ]]; then
  echo "--https-only requires an HTTP mode: use --mode http-cpu or --mode all-cpu" >&2
  exit 1
fi

if ! [[ "${GRPC_SCALE}" =~ ^[0-9]+$ ]] || [[ "${GRPC_SCALE}" -lt 1 ]]; then
  echo "grpc scale must be a positive integer" >&2
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
if [[ "${MODE}" == "http-cpu" || "${MODE}" == "all-cpu" ]]; then
  if ! tag_first_existing_image \
    "${HTTP_IMAGE}" \
    "xcn-pii/api-http-cpu:${APP_VERSION}" \
    "xcn-pii/api-http-cpu:latest" \
    "xcn-pii/api:${APP_VERSION}" \
    "xcn-pii/api:latest" \
    "xcn-pii-api:latest" \
    "xcn-pii-api"; then
    echo "failed to find HTTP CPU image: ${HTTP_IMAGE}" >&2
    echo "build first with: ./scripts/start_http_cpu.sh" >&2
    exit 1
  fi
  IMAGES+=("${HTTP_IMAGE}")
fi

if [[ "${MODE}" == "grpc-cpu" || "${MODE}" == "all-cpu" ]]; then
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
    echo "build first with: ./scripts/start_grpc_cpu_lb_3.sh" >&2
    exit 1
  fi
  IMAGES+=("${GRPC_IMAGE}" "haproxy:3.1-alpine")
fi

if [[ "${INCLUDE_HTTPS}" == "true" ]]; then
  IMAGES+=("nginx:1.27-alpine")
fi

for image_name in "${IMAGES[@]}"; do
  if ! image_exists "${image_name}"; then
    echo "required image not found: ${image_name}" >&2
    exit 1
  fi
done

if [[ -z "${BUNDLE_NAME}" ]]; then
  BUNDLE_MODE="${MODE}"
  if [[ "${HTTPS_ONLY}" == "true" ]]; then
    BUNDLE_MODE="${MODE}-https-only"
  elif [[ "${INCLUDE_HTTPS}" == "true" ]]; then
    BUNDLE_MODE="${MODE}-https"
  fi
  BUNDLE_NAME="xcn-pii-${BUNDLE_MODE}-package-${APP_VERSION}-$(date +%Y%m%d-%H%M%S)"
fi

mkdir -p "${OUTPUT_DIR}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
BUNDLE_ROOT_NAME="xcn-pii"
BUNDLE_DIR="${WORK_DIR}/${BUNDLE_ROOT_NAME}"
mkdir -p "${BUNDLE_DIR}/images" "${BUNDLE_DIR}/scripts"

copy_file "${PROJECT_ROOT}/VERSION" "${BUNDLE_DIR}/VERSION"
copy_file "${PROJECT_ROOT}/.env.example" "${BUNDLE_DIR}/.env.example"
if [[ "${MODE}" == "http-cpu" || "${MODE}" == "all-cpu" || "${INCLUDE_HTTPS}" == "true" ]]; then
  copy_file "${PROJECT_ROOT}/docker-compose.http-cpu.yml" "${BUNDLE_DIR}/docker-compose.http-cpu.yml"
fi
if [[ "${MODE}" == "grpc-cpu" || "${MODE}" == "all-cpu" ]]; then
  copy_file "${PROJECT_ROOT}/docker-compose.grpc-cpu.yml" "${BUNDLE_DIR}/docker-compose.grpc-cpu.yml"
  copy_file "${PROJECT_ROOT}/infra/haproxy/grpc-lb.cfg" "${BUNDLE_DIR}/infra/haproxy/grpc-lb.cfg"
fi
if [[ "${INCLUDE_HTTPS}" == "true" ]]; then
  copy_file "${PROJECT_ROOT}/docker-compose.https.yml" "${BUNDLE_DIR}/docker-compose.https.yml"
  copy_file "${PROJECT_ROOT}/infra/nginx/https.conf.template" "${BUNDLE_DIR}/infra/nginx/https.conf.template"
  copy_file "${PROJECT_ROOT}/scripts/make_self_signed_cert.sh" "${BUNDLE_DIR}/scripts/make_self_signed_cert.sh"
fi
if [[ "${HTTPS_ONLY}" == "true" ]]; then
  copy_file "${PROJECT_ROOT}/docker-compose.https-only.yml" "${BUNDLE_DIR}/docker-compose.https-only.yml"
fi

write_sanitized_env "${BUNDLE_DIR}/.env.package"
if [[ "${INCLUDE_ENV}" == "true" && -f "${PROJECT_ROOT}/.env" ]]; then
  copy_file "${PROJECT_ROOT}/.env" "${BUNDLE_DIR}/.env.source"
fi
write_install_script "${BUNDLE_DIR}/install.sh"
validate_generated_install_script "${BUNDLE_DIR}/install.sh"
write_start_script "${BUNDLE_DIR}/start.sh" "${MODE}" "${INCLUDE_HTTPS}" "${HTTPS_ONLY}"
write_stop_script "${BUNDLE_DIR}/stop.sh" "${MODE}" "${INCLUDE_HTTPS}" "${HTTPS_ONLY}"
if [[ "${MODE}" == "http-cpu" || "${MODE}" == "all-cpu" ]]; then
  write_start_script "${BUNDLE_DIR}/scripts/start-http-cpu.sh" "http-cpu" "${INCLUDE_HTTPS}" "${HTTPS_ONLY}"
  write_stop_script "${BUNDLE_DIR}/scripts/stop-http-cpu.sh" "http-cpu" "${INCLUDE_HTTPS}" "${HTTPS_ONLY}"
fi
if [[ "${MODE}" == "grpc-cpu" || "${MODE}" == "all-cpu" ]]; then
  write_start_script "${BUNDLE_DIR}/scripts/start-grpc-cpu.sh" "grpc-cpu" "false" "false"
  write_stop_script "${BUNDLE_DIR}/scripts/stop-grpc-cpu.sh" "grpc-cpu" "false" "false"
fi
if [[ "${MODE}" == "all-cpu" ]]; then
  write_start_script "${BUNDLE_DIR}/scripts/start-all-cpu.sh" "all-cpu" "${INCLUDE_HTTPS}" "${HTTPS_ONLY}"
  write_stop_script "${BUNDLE_DIR}/scripts/stop-all-cpu.sh" "all-cpu" "${INCLUDE_HTTPS}" "${HTTPS_ONLY}"
fi
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

chmod +x \
  "${BUNDLE_DIR}/install.sh" \
  "${BUNDLE_DIR}/start.sh" \
  "${BUNDLE_DIR}/stop.sh"
if [[ -d "${BUNDLE_DIR}/scripts" ]]; then
  find "${BUNDLE_DIR}/scripts" -maxdepth 1 -type f -name '*.sh' -exec chmod +x {} +
fi
if [[ -f "${BUNDLE_DIR}/scripts/make_self_signed_cert.sh" ]]; then
  chmod +x "${BUNDLE_DIR}/scripts/make_self_signed_cert.sh"
fi

IMAGE_ARCHIVE="${BUNDLE_DIR}/images/xcn-pii-${MODE}-images.tar"
echo "Saving Docker images to ${IMAGE_ARCHIVE}"
docker save -o "${IMAGE_ARCHIVE}" "${IMAGES[@]}"

{
  echo "package=${BUNDLE_NAME}"
  echo "created_at=$(date -Iseconds)"
  echo "app_version=${APP_VERSION}"
  echo "mode=${MODE}"
  echo "grpc_scale=${GRPC_SCALE}"
  echo "include_https=${INCLUDE_HTTPS}"
  echo "https_only=${HTTPS_ONLY}"
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
echo "  ./install.sh"
