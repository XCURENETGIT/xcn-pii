from __future__ import annotations

from pathlib import Path


def read_app_version() -> str:
    version_file = Path(__file__).resolve().parents[1] / "VERSION"
    try:
        version = version_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"failed to read app version file: {exc}") from exc
    if not version:
        raise RuntimeError("app version file is empty")
    return version


APP_VERSION = read_app_version()
