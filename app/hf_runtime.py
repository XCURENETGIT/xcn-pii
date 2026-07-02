from __future__ import annotations

import os


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def hf_offline_enabled() -> bool:
    return _env_bool("PII_HF_OFFLINE", True)


def configure_hf_runtime() -> bool:
    offline = hf_offline_enabled()
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    if offline:
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        os.environ["HF_DATASETS_OFFLINE"] = "1"
    return offline
