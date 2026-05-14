from __future__ import annotations

import os
import shlex
import stat
import subprocess
from pathlib import Path


XUTF8_BINARY = Path(os.getenv("XUTF8_BINARY_PATH", "/app/bin/xutf_8"))
XUTF8_TIMEOUT_SEC = int(os.getenv("XUTF8_TIMEOUT_SEC", "60"))


class TextExtractError(RuntimeError):
    pass


def _ensure_executable(path: Path) -> None:
    if not path.exists():
        raise TextExtractError(f"xutf_8 binary is missing: {path}")
    mode = path.stat().st_mode
    if mode & stat.S_IXUSR:
        return
    path.chmod(mode | stat.S_IXUSR)


def _decode_output(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        raise TextExtractError("xutf_8 returned empty output")
    return text


def extract_text_from_file(file_path: Path) -> str:
    _ensure_executable(XUTF8_BINARY)

    direct_commands = (
        ([str(XUTF8_BINARY), str(file_path)], None),
        ([str(XUTF8_BINARY)], file_path),
    )

    for command, stdin_path in direct_commands:
        try:
            if stdin_path is None:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    timeout=XUTF8_TIMEOUT_SEC,
                    check=False,
                )
            else:
                with stdin_path.open("rb") as source:
                    completed = subprocess.run(
                        command,
                        stdin=source,
                        capture_output=True,
                        timeout=XUTF8_TIMEOUT_SEC,
                        check=False,
                    )
        except subprocess.TimeoutExpired as exc:
            raise TextExtractError(f"xutf_8 timed out after {XUTF8_TIMEOUT_SEC}s") from exc
        except PermissionError:
            continue
        except OSError as exc:
            raise TextExtractError(f"failed to execute xutf_8: {exc}") from exc

        if completed.returncode == 0 and completed.stdout.strip():
            return _decode_output(completed.stdout)

    shell_commands = (
        f'{shlex.quote(str(XUTF8_BINARY))} {shlex.quote(str(file_path))}',
        f'{shlex.quote(str(XUTF8_BINARY))} < {shlex.quote(str(file_path))}',
    )

    for command in shell_commands:
        try:
            completed = subprocess.run(
                ["/bin/sh", "-lc", command],
                capture_output=True,
                timeout=XUTF8_TIMEOUT_SEC,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TextExtractError(f"xutf_8 timed out after {XUTF8_TIMEOUT_SEC}s") from exc
        except OSError as exc:
            raise TextExtractError(f"failed to execute xutf_8 via shell: {exc}") from exc

        if completed.returncode == 0 and completed.stdout.strip():
            return _decode_output(completed.stdout)

    stderr = completed.stderr.decode("utf-8", errors="replace").strip()
    stdout = completed.stdout.decode("utf-8", errors="replace").strip()
    details = stderr or stdout or f"exit_code={completed.returncode}"
    raise TextExtractError(f"xutf_8 failed: {details}")
