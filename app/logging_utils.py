from __future__ import annotations

import logging
import os
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from logging.handlers import WatchedFileHandler

from app.hf_runtime import configure_hf_runtime


KST = timezone(timedelta(hours=9), "KST")


class KSTFormatter(logging.Formatter):
    def converter(self, timestamp: float) -> time.struct_time:
        return datetime.fromtimestamp(timestamp, tz=KST).timetuple()


def _configure_process_timezone() -> None:
    tz_name = str(os.getenv("PII_LOG_TIMEZONE", "Asia/Seoul")).strip() or "Asia/Seoul"
    # POSIX TZ avoids depending on OS tzdata inside slim containers.
    os.environ["TZ"] = "KST-9" if tz_name in ("Asia/Seoul", "KST") else tz_name
    if hasattr(time, "tzset"):
        time.tzset()


def _configure_console_logging(level: int) -> None:
    formatter = KSTFormatter("%(asctime)s KST %(levelname)s [%(name)s] %(message)s")
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "pii.api", "pii.detect", "pii.engine", "pii.grpc"):
        lg = logging.getLogger(name)
        lg.setLevel(level)
        for handler in lg.handlers:
            if isinstance(handler, WatchedFileHandler):
                continue
            handler.setLevel(level)
            handler.setFormatter(formatter)


def _safe_log_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "-" for ch in value.strip())
    return cleaned.strip(".-") or "default"


def _log_file_path(log_dir: Path) -> Path:
    configured = str(os.getenv("PII_LOG_FILE_NAME", "")).strip()
    if configured:
        return log_dir / configured

    compose_service = str(os.getenv("COMPOSE_SERVICE") or os.getenv("PII_LOG_SERVICE_NAME") or "").strip()
    compose_replica = str(os.getenv("COMPOSE_CONTAINER_NUMBER") or os.getenv("PII_LOG_REPLICA") or "").strip()
    hostname = str(os.getenv("HOSTNAME") or socket.gethostname() or "").strip()
    if compose_service and compose_replica:
        return log_dir / f"pii-api-{_safe_log_name(compose_service)}-{_safe_log_name(compose_replica)}.log"
    if compose_service and hostname:
        return log_dir / f"pii-api-{_safe_log_name(compose_service)}-{_safe_log_name(hostname)}.log"
    if hostname:
        return log_dir / f"pii-api-{_safe_log_name(hostname)}.log"
    return log_dir / "pii-api.log"


def setup_file_logging() -> None:
    _configure_process_timezone()
    configure_hf_runtime()

    level_name = str(os.getenv("PII_LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    third_party_level_name = str(os.getenv("PII_THIRD_PARTY_LOG_LEVEL", "WARNING")).upper()
    third_party_level = getattr(logging, third_party_level_name, logging.WARNING)
    _configure_console_logging(level)
    for noisy_name in ("httpx", "httpcore", "urllib3", "sentence_transformers", "transformers"):
        logging.getLogger(noisy_name).setLevel(third_party_level)

    if str(os.getenv("PII_FILE_LOG_ENABLED", "true")).strip().lower() not in ("1", "true", "yes", "on"):
        return

    log_dir = Path(os.getenv("PII_LOG_DIR", "/logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = _log_file_path(log_dir)

    # Rotation and compression are handled by the single app.logrotate service.
    # WatchedFileHandler reopens the path after that service atomically renames it.
    handler = WatchedFileHandler(
        filename=str(log_file),
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(KSTFormatter("%(asctime)s KST %(levelname)s [%(name)s] %(message)s"))

    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "pii.api", "pii.detect", "pii.engine", "pii.grpc"):
        lg = logging.getLogger(name)
        lg.setLevel(level)
        if not any(isinstance(h, WatchedFileHandler) and getattr(h, "baseFilename", "") == str(log_file) for h in lg.handlers):
            lg.addHandler(handler)
        if name:
            lg.propagate = False
