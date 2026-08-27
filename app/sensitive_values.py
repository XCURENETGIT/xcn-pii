from __future__ import annotations

import ipaddress
import math
import os
import re
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Pattern, Tuple
from urllib.parse import urlsplit

import yaml


SENSITIVE_RULE_TYPES: Tuple[Tuple[str, str], ...] = (
    ("OTP", "otp.yaml"),
    ("API_KEY", "api_key.yaml"),
    ("AUTH_TOKEN", "auth_token.yaml"),
    ("PASSWORD", "password.yaml"),
    ("INTERNAL_ACCESS", "internal_access.yaml"),
)


def _compile_flags(flags_cfg: Dict[str, Any] | None) -> int:
    cfg = flags_cfg or {}
    flags = 0
    if cfg.get("ignorecase"):
        flags |= re.IGNORECASE
    if cfg.get("multiline"):
        flags |= re.MULTILINE
    if cfg.get("dotall"):
        flags |= re.DOTALL
    if cfg.get("verbose"):
        flags |= re.VERBOSE
    return flags


def _shannon_entropy(value: str) -> float:
    raw = str(value or "")
    if not raw:
        return 0.0
    size = len(raw)
    return -sum((count / size) * math.log2(count / size) for count in Counter(raw).values())


def _strip_host_port(value: str) -> str:
    raw = str(value or "").strip()
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.index("]")]
    if raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            return host
    return raw


def _ip_is_internal(value: str) -> bool:
    try:
        address = ipaddress.ip_address(str(value or "").strip("[]"))
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local)


def _network_is_internal(value: str) -> bool:
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return False
    return bool(network.is_private or network.is_loopback or network.is_link_local)


def _host_is_internal(value: str) -> bool:
    host = _strip_host_port(value).strip().rstrip(".").lower()
    if not host:
        return False
    if _ip_is_internal(host):
        return True
    if host == "localhost" or "." not in host:
        return True
    suffixes = (
        ".internal",
        ".local",
        ".lan",
        ".corp",
        ".intranet",
        ".svc",
        ".svc.cluster.local",
        ".cluster.local",
        ".home.arpa",
        ".private",
        ".localdomain",
    )
    return host.endswith(suffixes)


def _url_is_internal(value: str) -> bool:
    raw = str(value or "").strip()
    if raw.lower().startswith("jdbc:"):
        raw = raw[5:]
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    return bool(parsed.scheme and parsed.hostname and _host_is_internal(parsed.hostname))


def _character_class_count(value: str) -> int:
    raw = str(value or "")
    return sum(
        (
            any(ch.islower() for ch in raw),
            any(ch.isupper() for ch in raw),
            any(ch.isdigit() for ch in raw),
            any(not ch.isalnum() for ch in raw),
        )
    )


class SensitivePatternSet:
    """Compiled value-capturing patterns for one sensitive-data output type."""

    def __init__(self, out_key: str, rule_doc: Dict[str, Any]):
        self.out_key = str(out_key).upper()
        self.enabled = bool(rule_doc.get("enabled", True))
        self.max_match_len = max(1, int(rule_doc.get("max_match_len") or 4096))
        self.patterns: List[Tuple[Pattern[str], Dict[str, Any], Tuple[str, ...]]] = []

        patterns = rule_doc.get("patterns") or []
        if not isinstance(patterns, list):
            raise ValueError(f"{self.out_key}.patterns must be a list")
        for index, spec in enumerate(patterns):
            if not isinstance(spec, dict):
                continue
            raw = str(spec.get("regex") or "").strip()
            if not raw:
                continue
            try:
                compiled = re.compile(raw, _compile_flags(spec.get("flags")))
            except re.error as exc:
                raise ValueError(f"invalid {self.out_key} regex at index {index}: {exc}") from exc
            raw_prefilter_any = spec.get("prefilter_any") or []
            if isinstance(raw_prefilter_any, str):
                raw_prefilter_any = [raw_prefilter_any]
            if not isinstance(raw_prefilter_any, (list, tuple)):
                raise ValueError(f"{self.out_key}.prefilter_any must be a list at index {index}")
            prefilter_any = tuple(str(item).lower() for item in raw_prefilter_any if str(item))
            self.patterns.append((compiled, dict(spec), prefilter_any))

    @staticmethod
    def _value_span(match: re.Match[str], spec: Dict[str, Any]) -> Tuple[int, int] | None:
        group = spec.get("value_group", "value")
        try:
            start, end = match.span(group)
        except (IndexError, KeyError):
            start, end = match.span(0)
        if start < 0 or end <= start:
            return None
        return start, end

    @staticmethod
    def _is_valid(value: str, spec: Dict[str, Any]) -> bool:
        min_length = max(0, int(spec.get("min_length") or 0))
        max_length = max(min_length, int(spec.get("max_length") or 10000000))
        if not (min_length <= len(value) <= max_length):
            return False

        min_entropy = float(spec.get("min_entropy") or 0.0)
        if min_entropy > 0.0 and _shannon_entropy(value) < min_entropy:
            return False

        min_classes = max(0, int(spec.get("min_character_classes") or 0))
        if min_classes and _character_class_count(value) < min_classes:
            return False

        validator = str(spec.get("validator") or "").strip().lower()
        if validator == "private_ip":
            return _ip_is_internal(value)
        if validator == "private_network":
            return _network_is_internal(value)
        if validator == "internal_host":
            return _host_is_internal(value)
        if validator == "internal_url":
            return _url_is_internal(value)
        return True

    def find(self, text: str, max_results: int = 500) -> List[dict]:
        if not self.enabled or not text or max_results <= 0:
            return []

        found: List[dict] = []
        lowered_text: str | None = None
        for regex, spec, prefilter_any in self.patterns:
            if prefilter_any:
                if lowered_text is None:
                    lowered_text = text.lower()
                if not any(hint in lowered_text for hint in prefilter_any):
                    continue
            for match in regex.finditer(text):
                span = self._value_span(match, spec)
                if span is None:
                    continue
                start, end = span
                trim_trailing = str(spec.get("trim_trailing") or "")
                if trim_trailing:
                    while end > start and text[end - 1] in trim_trailing:
                        end -= 1
                if end <= start or end - start > self.max_match_len:
                    continue
                value = text[start:end]
                if not self._is_valid(value, spec):
                    continue
                found.append(
                    {
                        "start": start,
                        "end": end,
                        "matchString": value,
                        "detected_by": str(spec.get("detected_by") or spec.get("name") or "regex"),
                    }
                )
                if len(found) >= max_results:
                    break
            if len(found) >= max_results:
                break

        # Prefer a wider match when two rules capture overlapping values.
        selected: List[dict] = []
        last_end = -1
        for item in sorted(found, key=lambda x: (x["start"], -x["end"])):
            if item["start"] < last_end:
                continue
            selected.append(item)
            last_end = item["end"]
        return selected[:max_results]


_REDACTOR_CACHE_LOCK = threading.RLock()
_REDACTOR_CACHE: Dict[str, Tuple[Tuple[Tuple[str, float], ...], List[SensitivePatternSet]]] = {}


def _sensitive_rule_paths(rules_dir: Path) -> List[Tuple[str, Path]]:
    return [(out_key, rules_dir / filename) for out_key, filename in SENSITIVE_RULE_TYPES]


def _load_redaction_pattern_sets(rules_dir: Path) -> List[SensitivePatternSet]:
    paths = _sensitive_rule_paths(rules_dir)
    signature = tuple((str(path), path.stat().st_mtime) for _, path in paths)
    cache_key = str(rules_dir.resolve())
    with _REDACTOR_CACHE_LOCK:
        cached = _REDACTOR_CACHE.get(cache_key)
        if cached is not None and cached[0] == signature:
            return cached[1]

        compiled: List[SensitivePatternSet] = []
        for out_key, path in paths:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(raw, dict):
                raise ValueError(f"sensitive rule root must be a mapping: {path}")
            compiled.append(SensitivePatternSet(out_key, raw))
        _REDACTOR_CACHE[cache_key] = (signature, compiled)
        return compiled


def redact_sensitive_text(
    text: str,
    *,
    rules_dir: str | Path | None = None,
    max_results_per_type: int = 5000,
) -> str:
    """Replace detected secret/access values while preserving surrounding context."""

    raw = str(text or "")
    if not raw:
        return raw
    directory = Path(rules_dir or os.getenv("PII_RULES_DIR", "app/rules"))
    spans: List[Tuple[int, int, str]] = []
    for pattern_set in _load_redaction_pattern_sets(directory):
        for item in pattern_set.find(raw, max_results=max_results_per_type):
            spans.append((int(item["start"]), int(item["end"]), pattern_set.out_key))
    if not spans:
        return raw

    selected: List[Tuple[int, int, str]] = []
    last_end = -1
    for start, end, out_key in sorted(spans, key=lambda x: (x[0], -x[1])):
        if start < last_end:
            continue
        selected.append((start, end, out_key))
        last_end = end

    redacted = raw
    for start, end, out_key in reversed(selected):
        redacted = redacted[:start] + f"[REDACTED:{out_key}]" + redacted[end:]
    return redacted
