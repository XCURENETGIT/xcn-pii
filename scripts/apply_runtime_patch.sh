#!/usr/bin/env sh
set -eu

BUNDLE_DIR="${1:-.}"
TARGET_ROOT="${2:-/app}"
FORCE="${XCN_PATCH_FORCE:-0}"
SKIP_PREFLIGHT="${XCN_PATCH_SKIP_PREFLIGHT:-0}"

if [ "${3:-}" = "--force" ]; then
  FORCE=1
fi

MANIFEST_PATH="${BUNDLE_DIR}/manifest.json"
PAYLOAD_DIR="${BUNDLE_DIR}/payload"

if [ ! -f "${MANIFEST_PATH}" ]; then
  echo "manifest not found: ${MANIFEST_PATH}" >&2
  exit 1
fi

if [ ! -d "${PAYLOAD_DIR}" ]; then
  echo "payload directory not found: ${PAYLOAD_DIR}" >&2
  exit 1
fi

python - "${MANIFEST_PATH}" "${PAYLOAD_DIR}" "${TARGET_ROOT}" "${FORCE}" "${SKIP_PREFLIGHT}" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def entry_after_sha(entry: dict) -> str:
    return str(entry.get("after_sha256") or entry.get("sha256") or "")


def entry_before_sha(entry: dict) -> str:
    return str(entry.get("before_sha256") or "")


def fail(message: str) -> None:
    raise SystemExit(message)


manifest_path = Path(sys.argv[1])
payload_dir = Path(sys.argv[2])
target_root = Path(sys.argv[3])
force = sys.argv[4] == "1"
skip_preflight = sys.argv[5] == "1"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
schema_version = int(manifest.get("schema_version") or 1)
preflight_required = bool(manifest.get("preflight_required"))
bundle_name = str(manifest.get("bundle_name") or "patch")
backup_root = Path(
    os.environ.get("XCN_PATCH_BACKUP_DIR")
    or target_root / ".patch-backups" / f"{bundle_name}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
)

for entry in manifest["files"]:
    relative_path = Path(entry["path"])
    source_path = payload_dir / relative_path
    if not source_path.is_file():
        fail(f"missing payload file: {source_path}")
    actual_hash = sha256_file(source_path)
    expected_hash = entry_after_sha(entry)
    if actual_hash != expected_hash:
        fail(f"payload sha256 mismatch for {relative_path}: {actual_hash} != {expected_hash}")

if schema_version >= 2 and preflight_required and not skip_preflight:
    for entry in manifest["files"]:
        relative_path = Path(entry["path"])
        target_path = target_root / relative_path
        before_sha256 = entry_before_sha(entry)
        action = str(entry.get("action") or ("modify" if before_sha256 else "add"))

        if before_sha256:
            if not target_path.is_file():
                if force:
                    print(f"preflight force: target missing for {relative_path}")
                    continue
                fail(f"preflight failed: target missing for {relative_path}")
            actual_hash = sha256_file(target_path)
            if actual_hash != before_sha256:
                if force:
                    print(f"preflight force: target sha256 mismatch for {relative_path}: {actual_hash} != {before_sha256}")
                    continue
                fail(f"preflight failed: target sha256 mismatch for {relative_path}: {actual_hash} != {before_sha256}")
        elif action == "add" and target_path.exists():
            if force:
                print(f"preflight force: add target already exists for {relative_path}")
            else:
                fail(f"preflight failed: add target already exists for {relative_path}")

for entry in manifest["files"]:
    relative_path = Path(entry["path"])
    source_path = payload_dir / relative_path
    target_path = target_root / relative_path
    if target_path.exists():
        backup_path = backup_root / relative_path
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target_path, backup_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, target_path)
    if entry.get("mode"):
        os.chmod(target_path, int(str(entry["mode"]), 8))
    print(f"patched {target_path}")

for entry in manifest["files"]:
    relative_path = Path(entry["path"])
    target_path = target_root / relative_path
    actual_hash = sha256_file(target_path)
    expected_hash = entry_after_sha(entry)
    if actual_hash != expected_hash:
        fail(f"post-verify failed: target sha256 mismatch for {relative_path}: {actual_hash} != {expected_hash}")

if backup_root.exists():
    print(f"backup_dir={backup_root}")
PY
