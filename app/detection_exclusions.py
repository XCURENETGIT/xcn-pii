from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


PII_TYPES = ("SN", "SSN", "DN", "PN", "MN", "BN", "BRN", "AN", "CN", "EML")
_TYPE_SET = set(PII_TYPES)
_SEPARATOR_RE = re.compile(r"[\s\-._@:/\\]+")


@dataclass(frozen=True)
class DetectionExclusionConfig:
    raw: Any
    all_values: set[str] = field(default_factory=set)
    all_compact_values: set[str] = field(default_factory=set)
    all_patterns: tuple[re.Pattern[str], ...] = ()
    all_compact_patterns: tuple[re.Pattern[str], ...] = ()
    type_values: dict[str, set[str]] = field(default_factory=dict)
    type_compact_values: dict[str, set[str]] = field(default_factory=dict)
    type_patterns: dict[str, tuple[re.Pattern[str], ...]] = field(default_factory=dict)
    type_compact_patterns: dict[str, tuple[re.Pattern[str], ...]] = field(default_factory=dict)

    @property
    def total_values(self) -> int:
        total = len(self.all_values) + len(self.all_patterns)
        for values in self.type_values.values():
            total += len(values)
        for patterns in self.type_patterns.values():
            total += len(patterns)
        return total

    @property
    def type_counts(self) -> dict[str, int]:
        keys = set(self.type_values) | set(self.type_patterns)
        return {
            k: len(self.type_values.get(k, set())) + len(self.type_patterns.get(k, ()))
            for k in sorted(keys)
            if self.type_values.get(k) or self.type_patterns.get(k)
        }


_LOCK = threading.Lock()
_CACHE_PATH: Path | None = None
_CACHE_MTIME_NS: int | None = None
_CACHE_CONFIG = DetectionExclusionConfig(raw={})


def exclusion_file_path() -> Path:
    return Path(os.getenv("PII_DETECTION_EXCLUSION_FILE", "data/pii_detection_exclusions.json"))


def exclusions_enabled() -> bool:
    raw = os.getenv("PII_DETECTION_EXCLUSION_ENABLED")
    if raw is None:
        return True
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _normalize(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    return " ".join(text.strip().lower().split())


def _compact(value: Any) -> str:
    return _SEPARATOR_RE.sub("", _normalize(value))


def _has_wildcard(value: str) -> bool:
    return "*" in value


def _compile_wildcard(value: str) -> re.Pattern[str] | None:
    if not value:
        return None
    pattern = re.escape(value).replace(r"\*", ".*")
    return re.compile(rf"^{pattern}$")


def _add_pattern(patterns: dict[str, list[re.Pattern[str]]], key: str, value: str) -> None:
    compiled = _compile_wildcard(value)
    if compiled is not None:
        patterns.setdefault(key, []).append(compiled)


def _add_value(config: dict[str, Any], pii_type: str | None, value: Any) -> None:
    normalized = _normalize(value)
    compacted = _compact(value)
    if not normalized:
        return
    if pii_type:
        key = str(pii_type).strip().upper()
        if key not in _TYPE_SET:
            raise ValueError(f"unsupported PII type in exclusion file: {pii_type}")
        if _has_wildcard(normalized):
            _add_pattern(config["type_patterns"], key, normalized)
            if compacted:
                _add_pattern(config["type_compact_patterns"], key, compacted)
            return
        config["type_values"].setdefault(key, set()).add(normalized)
        if compacted:
            config["type_compact_values"].setdefault(key, set()).add(compacted)
        return
    if _has_wildcard(normalized):
        _add_pattern(config["all_patterns"], "__all__", normalized)
        if compacted:
            _add_pattern(config["all_compact_patterns"], "__all__", compacted)
        return
    config["all_values"].add(normalized)
    if compacted:
        config["all_compact_values"].add(compacted)


def _iter_values(values: Any) -> list[Any]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError("exclusion values must be arrays")
    return values


def parse_detection_exclusions(payload: Any) -> DetectionExclusionConfig:
    parsed: dict[str, Any] = {
        "all_values": set(),
        "all_compact_values": set(),
        "all_patterns": {},
        "all_compact_patterns": {},
        "type_values": {},
        "type_compact_values": {},
        "type_patterns": {},
        "type_compact_patterns": {},
    }

    if isinstance(payload, list):
        for value in payload:
            if isinstance(value, dict):
                _add_value(parsed, value.get("type"), value.get("value", value.get("matchString")))
            else:
                _add_value(parsed, None, value)
    elif isinstance(payload, dict):
        for value in _iter_values(payload.get("values")):
            _add_value(parsed, None, value)

        types = payload.get("types") or {}
        if not isinstance(types, dict):
            raise ValueError("exclusion types must be an object")
        for pii_type, values in types.items():
            for value in _iter_values(values):
                _add_value(parsed, str(pii_type), value)

        for entry in _iter_values(payload.get("entries")):
            if not isinstance(entry, dict):
                raise ValueError("exclusion entries must be objects")
            _add_value(parsed, entry.get("type"), entry.get("value", entry.get("matchString")))

        for pii_type in PII_TYPES:
            if pii_type in payload:
                for value in _iter_values(payload.get(pii_type)):
                    _add_value(parsed, pii_type, value)
    else:
        raise ValueError("exclusion file root must be a JSON object or array")

    return DetectionExclusionConfig(
        raw=payload,
        all_values=parsed["all_values"],
        all_compact_values=parsed["all_compact_values"],
        all_patterns=tuple(parsed["all_patterns"].get("__all__", [])),
        all_compact_patterns=tuple(parsed["all_compact_patterns"].get("__all__", [])),
        type_values=parsed["type_values"],
        type_compact_values=parsed["type_compact_values"],
        type_patterns={k: tuple(v) for k, v in parsed["type_patterns"].items()},
        type_compact_patterns={k: tuple(v) for k, v in parsed["type_compact_patterns"].items()},
    )


def write_detection_exclusion_file(payload: Any, path: Path | None = None) -> DetectionExclusionConfig:
    config = parse_detection_exclusions(payload)
    target = path or exclusion_file_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        tmp_path = Path(tmp.name)
        json.dump(payload, tmp, ensure_ascii=False, indent=2)
        tmp.write("\n")
    os.replace(tmp_path, target)
    os.chmod(target, 0o644)

    with _LOCK:
        global _CACHE_PATH, _CACHE_MTIME_NS, _CACHE_CONFIG
        stat = target.stat()
        _CACHE_PATH = target
        _CACHE_MTIME_NS = stat.st_mtime_ns
        _CACHE_CONFIG = config
    return config


def load_detection_exclusions(path: Path | None = None) -> DetectionExclusionConfig:
    target = path or exclusion_file_path()
    if not target.exists():
        return DetectionExclusionConfig(raw={})
    with target.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    return parse_detection_exclusions(payload)


def get_detection_exclusions() -> DetectionExclusionConfig:
    if not exclusions_enabled():
        return DetectionExclusionConfig(raw={})

    target = exclusion_file_path()
    try:
        stat = target.stat()
    except FileNotFoundError:
        return DetectionExclusionConfig(raw={})

    with _LOCK:
        global _CACHE_PATH, _CACHE_MTIME_NS, _CACHE_CONFIG
        if _CACHE_PATH == target and _CACHE_MTIME_NS == stat.st_mtime_ns:
            return _CACHE_CONFIG
        config = load_detection_exclusions(target)
        _CACHE_PATH = target
        _CACHE_MTIME_NS = stat.st_mtime_ns
        _CACHE_CONFIG = config
        return config


def is_excluded_match(pii_type: str, match_string: Any, config: DetectionExclusionConfig | None = None) -> bool:
    cfg = config or get_detection_exclusions()
    normalized = _normalize(match_string)
    compacted = _compact(match_string)
    pii_key = str(pii_type or "").strip().upper()
    if not normalized:
        return False
    if normalized in cfg.all_values or compacted in cfg.all_compact_values:
        return True
    if normalized in cfg.type_values.get(pii_key, set()):
        return True
    if compacted and compacted in cfg.type_compact_values.get(pii_key, set()):
        return True
    if any(pattern.match(normalized) for pattern in cfg.all_patterns):
        return True
    if compacted and any(pattern.match(compacted) for pattern in cfg.all_compact_patterns):
        return True
    if any(pattern.match(normalized) for pattern in cfg.type_patterns.get(pii_key, ())):
        return True
    return bool(compacted and any(pattern.match(compacted) for pattern in cfg.type_compact_patterns.get(pii_key, ())))


def apply_detection_exclusions(found: dict[str, list[dict]]) -> tuple[dict[str, list[dict]], dict[str, int]]:
    cfg = get_detection_exclusions()
    if cfg.total_values <= 0:
        return found, {}

    removed: dict[str, int] = {}
    filtered: dict[str, list[dict]] = {}
    for key, items in (found or {}).items():
        if not isinstance(items, list):
            filtered[key] = items
            continue
        out = []
        for item in items:
            if isinstance(item, dict) and is_excluded_match(key, item.get("matchString"), cfg):
                removed[key] = removed.get(key, 0) + 1
                continue
            out.append(item)
        filtered[key] = out
    return filtered, removed


def exclusion_status() -> dict[str, Any]:
    target = exclusion_file_path()
    cfg = get_detection_exclusions()
    exists = target.exists()
    updated_at = None
    if exists:
        updated_at = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(target.stat().st_mtime))
    return {
        "enabled": exclusions_enabled(),
        "path": str(target),
        "exists": exists,
        "updated_at": updated_at,
        "total_values": cfg.total_values,
        "type_counts": cfg.type_counts,
    }
