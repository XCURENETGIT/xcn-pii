from __future__ import annotations

import logging
import os
import socket
import tarfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

from app.hf_runtime import configure_hf_runtime


KST = timezone(timedelta(hours=9), "KST")


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return int(default)
    try:
        return int(str(value).strip())
    except Exception:
        return int(default)


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


def _archive_name_for_date(log_dir: Path, date_suffix: str) -> Path:
    prefix = _safe_log_name(str(os.getenv("PII_LOG_ARCHIVE_PREFIX", "pii-api-logs")))
    return log_dir / f"{prefix}-{date_suffix}.tar.gz"


def _acquire_archive_lock(log_dir: Path, date_suffix: str, timeout_sec: float = 10.0) -> Path | None:
    lock_path = log_dir / f".pii-log-archive-{date_suffix}.lock"
    deadline = time.monotonic() + max(0.1, timeout_sec)
    while time.monotonic() < deadline:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(f"{os.getpid()}\n")
            return lock_path
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > 60:
                    lock_path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            time.sleep(0.2)
    return None


def _archive_rotated_logs(log_dir: Path, date_suffix: str, backup_days: int) -> None:
    if not _env_bool("PII_LOG_ARCHIVE_ENABLED", True):
        return

    lock_path = _acquire_archive_lock(log_dir, date_suffix)
    if lock_path is None:
        return

    try:
        archive_path = _archive_name_for_date(log_dir, date_suffix)
        tmp_path = archive_path.with_name(f".{archive_path.name}.{os.getpid()}.tmp")
        rotated_files = sorted(
            p
            for p in log_dir.glob(f"*.log.{date_suffix}")
            if p.is_file() and p.name != archive_path.name
        )
        if not rotated_files and not archive_path.exists():
            return

        added_names = {p.name for p in rotated_files}
        with tarfile.open(tmp_path, "w:gz") as out_tar:
            if archive_path.exists():
                try:
                    with tarfile.open(archive_path, "r:gz") as in_tar:
                        for member in in_tar.getmembers():
                            if member.name in added_names:
                                continue
                            src = in_tar.extractfile(member) if member.isfile() else None
                            out_tar.addfile(member, src)
                            if src is not None:
                                src.close()
                except (tarfile.TarError, OSError):
                    pass
            for path in rotated_files:
                out_tar.add(path, arcname=path.name)

        os.replace(tmp_path, archive_path)
        for path in rotated_files:
            try:
                path.unlink()
            except OSError:
                pass
        _cleanup_old_log_archives(log_dir, backup_days)
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass


def _cleanup_old_log_archives(log_dir: Path, backup_days: int) -> None:
    if backup_days <= 0:
        return
    prefix = _safe_log_name(str(os.getenv("PII_LOG_ARCHIVE_PREFIX", "pii-api-logs")))
    cutoff = datetime.now(tz=KST).date() - timedelta(days=backup_days)
    for path in log_dir.glob(f"{prefix}-*.tar.gz"):
        suffix = path.name.removeprefix(f"{prefix}-").removesuffix(".tar.gz")
        try:
            archive_date = datetime.strptime(suffix, "%Y-%m-%d").date()
        except ValueError:
            continue
        if archive_date < cutoff:
            try:
                path.unlink()
            except OSError:
                pass


class DailyArchiveTimedRotatingFileHandler(TimedRotatingFileHandler):
    def __init__(self, *args, backup_days: int, **kwargs):
        super().__init__(*args, **kwargs)
        self.backup_days = int(backup_days)

    def doRollover(self) -> None:
        super().doRollover()
        date_suffix = (datetime.now(tz=KST) - timedelta(days=1)).strftime("%Y-%m-%d")
        _archive_rotated_logs(Path(self.baseFilename).parent, date_suffix, self.backup_days)


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

    backup_days = _env_int("PII_LOG_BACKUP_DAYS", 30)
    handler = DailyArchiveTimedRotatingFileHandler(
        filename=str(log_file),
        when="midnight",
        interval=1,
        backupCount=backup_days,
        encoding="utf-8",
        utc=False,
        backup_days=backup_days,
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
