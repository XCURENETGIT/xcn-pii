from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

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
            if isinstance(handler, TimedRotatingFileHandler):
                continue
            handler.setLevel(level)
            handler.setFormatter(formatter)


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
    log_file = log_dir / "pii-api.log"

    handler = TimedRotatingFileHandler(
        filename=str(log_file),
        when="midnight",
        interval=1,
        backupCount=int(os.getenv("PII_LOG_BACKUP_DAYS", "30")),
        encoding="utf-8",
        utc=False,
    )
    handler.suffix = "%Y-%m-%d"
    handler.setLevel(level)
    handler.setFormatter(KSTFormatter("%(asctime)s KST %(levelname)s [%(name)s] %(message)s"))

    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "pii.api", "pii.detect", "pii.engine", "pii.grpc"):
        lg = logging.getLogger(name)
        lg.setLevel(level)
        if not any(isinstance(h, TimedRotatingFileHandler) and getattr(h, "baseFilename", "") == str(log_file) for h in lg.handlers):
            lg.addHandler(handler)
        if name:
            lg.propagate = False
