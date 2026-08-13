from __future__ import annotations

import gzip
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from app.logrotate import _active_globs, enforce_retention, run_once


class LogRotateTest(unittest.TestCase):
    def test_run_once_rotates_only_configured_active_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            active = log_dir / "pii-api-grpc-1.log"
            legacy = log_dir / "pii-api-grpc-1-worker-123.log"
            payload = b"stage timing disabled\n" * 20
            active.write_bytes(payload)
            legacy.write_bytes(b"preserve legacy")

            result = run_once(
                log_dir,
                patterns=("pii-api-grpc-1.log",),
                max_file_bytes=100,
                total_max_bytes=10_000,
                backup_days=30,
            )

            self.assertEqual(active.read_bytes(), b"")
            self.assertEqual(legacy.read_bytes(), b"preserve legacy")
            self.assertEqual(len(result["rotated"]), 1)
            archive = log_dir / result["rotated"][0]
            with gzip.open(archive, "rb") as source:
                self.assertEqual(source.read(), payload)

    def test_retention_removes_oldest_managed_archive_until_under_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            active = log_dir / "pii-api-grpc-1.log"
            active.write_bytes(b"active")
            old = log_dir / "pii-api-grpc-1.log.rotation-20260801-000000-old.gz"
            new = log_dir / "pii-api-grpc-1.log.rotation-20260802-000000-new.gz"
            old.write_bytes(b"o" * 80)
            new.write_bytes(b"n" * 80)
            os.utime(old, (1, 1))
            os.utime(new, (2, 2))

            removed = enforce_retention(
                log_dir,
                active_files=[active],
                total_max_bytes=100,
                backup_days=0,
                now=datetime.now(tz=timezone.utc),
            )

            self.assertEqual(removed, [old])
            self.assertFalse(old.exists())
            self.assertTrue(new.exists())

    def test_active_globs_rejects_broad_or_path_patterns(self) -> None:
        for value in ("*", "*.log", "../logs/*.log", "/logs/*.log"):
            with self.subTest(value=value), patch.dict(os.environ, {"PII_LOG_ACTIVE_GLOBS": value}):
                with self.assertRaises(ValueError):
                    _active_globs()


if __name__ == "__main__":
    unittest.main()
