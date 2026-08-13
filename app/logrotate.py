from __future__ import annotations

import gzip
import logging
import os
import shutil
import signal
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


KST = timezone(timedelta(hours=9), "KST")
logger = logging.getLogger("pii.logrotate")
_STOP = False

DEFAULT_ACTIVE_GLOBS = (
    "pii-api-grpc-1.log",
    "pii-api-grpc-2.log",
    "pii-api-grpc-3.log",
    "pii-api-api-http-*.log",
    "pii-api-api-grpc-*.log",
)


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.getenv(name, default)).strip())
    except Exception:
        return int(default)


def _active_globs() -> tuple[str, ...]:
    raw = str(os.getenv("PII_LOG_ACTIVE_GLOBS", "")).strip()
    values = tuple(item.strip() for item in raw.split(",") if item.strip()) if raw else DEFAULT_ACTIVE_GLOBS
    for value in values:
        if "/" in value or "\\" in value or value in {"*", "*.log"}:
            raise ValueError(f"unsafe active log glob: {value}")
    return values


def _validate_log_dir(value: str | Path) -> Path:
    path = Path(value).resolve()
    if path == Path(path.anchor) or len(path.parts) < 2:
        raise ValueError(f"unsafe log directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _managed_archives(log_dir: Path) -> list[Path]:
    return sorted(
        (path for path in log_dir.glob("*.log.rotation-*.gz") if path.is_file()),
        key=lambda path: (path.stat().st_mtime, path.name),
    )


def _active_files(log_dir: Path, patterns: tuple[str, ...]) -> list[Path]:
    found: dict[str, Path] = {}
    for pattern in patterns:
        for path in log_dir.glob(pattern):
            if path.is_file() and ".rotation-" not in path.name:
                found[str(path)] = path
    return sorted(found.values(), key=lambda path: path.name)


def _compress_file(path: Path) -> Path:
    output = path.with_name(f"{path.name}.gz")
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with path.open("rb") as source, gzip.open(temporary, "wb", compresslevel=6) as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        os.replace(temporary, output)
        path.unlink()
        return output
    finally:
        temporary.unlink(missing_ok=True)


def rotate_file(path: Path, *, now: datetime | None = None) -> Path | None:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    if stat.st_size <= 0:
        return None
    stamp = (now or datetime.now(tz=KST)).strftime("%Y%m%d-%H%M%S")
    rotated = path.with_name(f"{path.name}.rotation-{stamp}-{uuid.uuid4().hex[:8]}")
    os.replace(path, rotated)
    path.touch(mode=stat.st_mode & 0o777)
    os.chmod(path, stat.st_mode & 0o777)
    if hasattr(os, "chown"):
        try:
            os.chown(path, stat.st_uid, stat.st_gid)
        except PermissionError:
            pass
    return _compress_file(rotated)


def enforce_retention(
    log_dir: Path,
    *,
    active_files: list[Path],
    total_max_bytes: int,
    backup_days: int,
    now: datetime | None = None,
) -> list[Path]:
    removed: list[Path] = []
    current_time = now or datetime.now(tz=KST)
    cutoff = current_time.timestamp() - max(0, backup_days) * 86400
    archives = _managed_archives(log_dir)
    if backup_days > 0:
        for path in list(archives):
            if path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)
                removed.append(path)
                archives.remove(path)

    active_bytes = sum(path.stat().st_size for path in active_files if path.exists())
    archive_bytes = sum(path.stat().st_size for path in archives)
    while archives and active_bytes + archive_bytes > total_max_bytes:
        path = archives.pop(0)
        size = path.stat().st_size
        path.unlink(missing_ok=True)
        archive_bytes -= size
        removed.append(path)
    return removed


def run_once(
    log_dir: Path,
    *,
    patterns: tuple[str, ...],
    max_file_bytes: int,
    total_max_bytes: int,
    backup_days: int,
) -> dict[str, object]:
    active = _active_files(log_dir, patterns)
    rotated: list[Path] = []
    for path in active:
        if path.stat().st_size >= max_file_bytes:
            archive = rotate_file(path)
            if archive is not None:
                rotated.append(archive)
    active = _active_files(log_dir, patterns)
    removed = enforce_retention(
        log_dir,
        active_files=active,
        total_max_bytes=total_max_bytes,
        backup_days=backup_days,
    )
    return {
        "active_files": len(active),
        "rotated": [path.name for path in rotated],
        "removed": [path.name for path in removed],
    }


def _handle_stop(_signum, _frame) -> None:
    global _STOP
    _STOP = True


def main() -> None:
    import fcntl

    logging.basicConfig(
        level=os.getenv("PII_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    log_dir = _validate_log_dir(os.getenv("PII_LOG_DIR", "/logs"))
    patterns = _active_globs()
    max_file_bytes = max(1, _env_int("PII_LOG_MAX_FILE_MB", 100)) * 1024 * 1024
    total_max_bytes = max(1, _env_int("PII_LOG_TOTAL_MAX_MB", 10240)) * 1024 * 1024
    backup_days = max(0, _env_int("PII_LOG_BACKUP_DAYS", 30))
    interval_sec = max(5, _env_int("PII_LOG_ROTATE_INTERVAL_SEC", 30))
    lock_path = log_dir / ".pii-logrotate.lock"
    lock_file = lock_path.open("a+")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.error("another logrotate process owns %s", lock_path)
        return

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    logger.info(
        "logrotate started dir=%s max_file_mb=%d total_max_mb=%d backup_days=%d interval_sec=%d patterns=%s",
        log_dir,
        max_file_bytes // 1024 // 1024,
        total_max_bytes // 1024 // 1024,
        backup_days,
        interval_sec,
        ",".join(patterns),
    )
    while not _STOP:
        try:
            result = run_once(
                log_dir,
                patterns=patterns,
                max_file_bytes=max_file_bytes,
                total_max_bytes=total_max_bytes,
                backup_days=backup_days,
            )
            if result["rotated"] or result["removed"]:
                logger.info("logrotate completed %s", result)
        except Exception:
            logger.exception("logrotate cycle failed")
        for _ in range(interval_sec):
            if _STOP:
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
