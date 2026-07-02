from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import platform
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent

MANAGED_INCLUDE_FILES = [
    ".env",
    ".env.example",
    "VERSION",
    "docker-compose.yml",
    "docker-compose.direct.yml",
    "docker-compose.grpc-cpu.yml",
    "docker-compose.http-cpu.yml",
    "docker-compose.https.yml",
    "app/__init__.py",
    "app/main.py",
    "app/grpc_server.py",
    "app/context_debug_api.py",
    "app/schemas.py",
]

MANAGED_INCLUDE_DIRS = [
    "app/proto",
    "app/rules",
    "app/static",
    "bin",
    "infra",
    "scripts",
    "tools",
]

MANAGED_INCLUDE_GLOBS = [
    "app/**/*.so",
]

MANAGED_EXCLUDE_GLOBS = [
    "certs/**",
    "data/**",
    "dist/**",
    "logs/**",
    "models/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/.ruff_cache/**",
    "**/.git/**",
    ".secrets/**",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_mode(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


def get_git_sha(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return result.stdout.strip()


def normalize_relative_path(path: Path) -> str:
    return path.as_posix().lstrip("./")


def is_excluded(relative_path: str, exclude_globs: list[str] | None = None) -> bool:
    patterns = exclude_globs or MANAGED_EXCLUDE_GLOBS
    return any(fnmatch.fnmatch(relative_path, pattern) for pattern in patterns)


def collect_managed_files(
    root: Path,
    include_files: list[str] | None = None,
    include_dirs: list[str] | None = None,
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    require_so: bool = False,
) -> list[Path]:
    root = root.resolve()
    files: list[Path] = []

    for relative in include_files or MANAGED_INCLUDE_FILES:
        path = root / relative
        if path.is_file():
            files.append(path)

    for relative in include_dirs or MANAGED_INCLUDE_DIRS:
        path = root / relative
        if path.is_dir():
            files.extend(sorted(candidate for candidate in path.rglob("*") if candidate.is_file()))

    so_files: list[Path] = []
    for pattern in include_globs or MANAGED_INCLUDE_GLOBS:
        matched = sorted(candidate for candidate in root.glob(pattern) if candidate.is_file())
        if pattern.endswith("*.so"):
            so_files.extend(matched)
        files.extend(matched)

    if require_so and not so_files:
        raise FileNotFoundError(f"No compiled .so files found under {root}")

    unique_files: list[Path] = []
    seen: set[Path] = set()
    for path in files:
        resolved = path.resolve()
        try:
            relative_path = normalize_relative_path(resolved.relative_to(root))
        except ValueError:
            continue
        if is_excluded(relative_path, exclude_globs):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_files.append(resolved)
    return sorted(unique_files)


def make_file_entry(path: Path, root: Path) -> dict[str, Any]:
    relative_path = normalize_relative_path(path.resolve().relative_to(root.resolve()))
    return {
        "path": relative_path,
        "size": path.stat().st_size,
        "mode": file_mode(path),
        "sha256": sha256_file(path),
    }


def build_file_manifest(
    root: Path,
    files: list[Path],
    *,
    manifest_type: str,
    profile: str = "",
    version: str = "",
    source_label: str = "",
    base_image: str = "",
    target_image: str = "",
    bundle_name: str = "",
) -> dict[str, Any]:
    root = root.resolve()
    return {
        "schema_version": 2,
        "manifest_type": manifest_type,
        "bundle_name": bundle_name,
        "profile": profile,
        "version": version,
        "source_label": source_label,
        "created_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "git_sha": get_git_sha(PROJECT_ROOT),
        "python_version": os.sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "base_image": base_image,
        "target_image": target_image,
        "files": [make_file_entry(path, root) for path in sorted(files)],
    }


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_files_by_path(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {normalize_relative_path(Path(str(entry["path"]))): entry for entry in manifest.get("files", [])}
