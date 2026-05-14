#!/usr/bin/env bash

pii_read_app_version() {
  local project_root="$1"
  local version_file="${project_root}/VERSION"
  if [[ ! -f "${version_file}" ]]; then
    echo "failed to resolve app version: VERSION file is missing" >&2
    exit 1
  fi
  local version_line
  version_line="$(tr -d '\r' < "${version_file}" | head -n 1)"
  if [[ -z "${version_line}" ]]; then
    echo "resolved app version is empty" >&2
    exit 1
  fi
  printf '%s\n' "${version_line}"
}

pii_export_image_version() {
  local project_root="$1"
  export PII_IMAGE_REPO="${PII_IMAGE_REPO:-xcn-pii}"
  export PII_IMAGE_TAG="${PII_IMAGE_TAG:-$(pii_read_app_version "${project_root}")}"
}
