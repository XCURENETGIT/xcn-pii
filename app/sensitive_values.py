from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import os
import re
import threading
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Pattern, Tuple
from urllib.parse import parse_qs, urlsplit

import yaml


SENSITIVE_RULE_TYPES: Tuple[Tuple[str, str], ...] = (
    ("OTP", "otp.yaml"),
    ("API_KEY", "api_key.yaml"),
    ("AUTH_TOKEN", "auth_token.yaml"),
    ("PASSWORD", "password.yaml"),
    ("INTERNAL_ACCESS", "internal_access.yaml"),
    ("PRIVATE_KEY", "private_key.yaml"),
    ("CLOUD_CREDENTIAL", "cloud_credential.yaml"),
    ("CONNECTION_STRING", "connection_string.yaml"),
    ("SIGNED_URL", "signed_url.yaml"),
    ("MFA_SECRET", "mfa_secret.yaml"),
    ("RECOVERY_CODE", "recovery_code.yaml"),
    ("SESSION_COOKIE", "session_cookie.yaml"),
)

PHASE1_SENSITIVE_TYPES = frozenset(
    {
        "PRIVATE_KEY",
        "CLOUD_CREDENTIAL",
        "CONNECTION_STRING",
        "SIGNED_URL",
        "MFA_SECRET",
        "RECOVERY_CODE",
        "SESSION_COOKIE",
    }
)
_PHASE1_STRONG_LABEL_HINTS = (
    "aws_",
    "azure_storage",
    "accountkey",
    "sharedaccesskey",
    "totp_secret",
    "totp_seed",
    "hotp_secret",
    "hotp_seed",
    "mfa_secret",
    "mfa_seed",
    "2fa_secret",
    "2fa_seed",
    "authenticator_secret",
    "authenticator_seed",
    "otp_secret",
    "otp_seed",
    "recovery_code",
    "recovery code",
    "backup_code",
    "backup code",
    "복구 코드",
    "백업 코드",
    "jsessionid",
    "phpsessid",
    "asp.net_sessionid",
    "connect.sid",
    "laravel_session",
    "ci_session",
    "rack.session",
    "play_session",
)
_PHASE1_STRONG_LABEL_ROOT_HINTS = (
    "_",
    "code",
    "secret",
    "seed",
    "key",
    "sess",
    "복구",
    "백업",
)


_INVISIBLE_FORMAT_CHARS = frozenset(
    {
        "\u00ad",  # soft hyphen
        "\u034f",  # combining grapheme joiner
        "\u061c",  # Arabic letter mark
        "\u180e",  # Mongolian vowel separator
        "\u200b",  # zero-width space
        "\u200c",  # zero-width non-joiner
        "\u200d",  # zero-width joiner
        "\u200e",  # left-to-right mark
        "\u200f",  # right-to-left mark
        "\u2060",  # word joiner
        "\ufeff",  # zero-width no-break space/BOM
    }
)
_PUNCTUATION_FOLD = str.maketrans(
    {
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2015": "-",
        "\u2212": "-",
        "\u2044": "/",
        "\u2215": "/",
        "\u2236": ":",
        "\ua789": ":",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
    }
)
_UNICODE_OBFUSCATION_TRIGGER_RE = re.compile(
    r"[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff"
    r"\uff01-\uff5e\u3000\u2010-\u2015\u2212\u2044\u2215\u2236\ua789\u2018\u2019\u201c\u201d]"
)
_ENCODED_OBFUSCATION_TRIGGER_RE = re.compile(
    r"\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2})"
    r"|&#(?:x[0-9A-Fa-f]{1,8}|[0-9]{1,10});"
    r"|(?:%[0-9A-Fa-f]{2})+"
)


@dataclass(frozen=True)
class SensitiveScanView:
    """Normalized scan text with an exact mapping back to the request text."""

    text: str
    starts: Tuple[int, ...]
    ends: Tuple[int, ...]

    def original_span(self, start: int, end: int) -> Tuple[int, int] | None:
        if start < 0 or end <= start or end > len(self.starts):
            return None
        return self.starts[start], self.ends[end - 1]


def _fold_obfuscated_chunk(value: str) -> str:
    folded: List[str] = []
    for char in str(value or ""):
        if char in _INVISIBLE_FORMAT_CHARS or unicodedata.category(char) == "Cf":
            continue
        normalized = unicodedata.normalize("NFKC", char).translate(_PUNCTUATION_FOLD)
        folded.extend(item for item in normalized if unicodedata.category(item) != "Cf")
    return "".join(folded)


def _decode_obfuscated_sequence(text: str, start: int) -> Tuple[str, int] | None:
    raw = str(text or "")
    if raw.startswith("\\u", start) and start + 6 <= len(raw):
        token = raw[start + 2:start + 6]
        if re.fullmatch(r"[0-9A-Fa-f]{4}", token):
            return chr(int(token, 16)), start + 6
    if raw.startswith("\\U", start) and start + 10 <= len(raw):
        token = raw[start + 2:start + 10]
        if re.fullmatch(r"[0-9A-Fa-f]{8}", token):
            codepoint = int(token, 16)
            if codepoint <= 0x10FFFF:
                return chr(codepoint), start + 10
    if raw.startswith("\\x", start) and start + 4 <= len(raw):
        token = raw[start + 2:start + 4]
        if re.fullmatch(r"[0-9A-Fa-f]{2}", token):
            return chr(int(token, 16)), start + 4
    if raw.startswith("&#", start):
        match = re.match(r"&#(?:x([0-9A-Fa-f]{1,8})|([0-9]{1,10}));", raw[start:])
        if match is not None:
            codepoint = int(match.group(1), 16) if match.group(1) else int(match.group(2), 10)
            if codepoint <= 0x10FFFF:
                return chr(codepoint), start + len(match.group(0))
    if raw.startswith("%", start):
        end = start
        encoded = bytearray()
        while end + 3 <= len(raw) and re.fullmatch(r"%[0-9A-Fa-f]{2}", raw[end:end + 3]):
            encoded.append(int(raw[end + 1:end + 3], 16))
            end += 3
        if encoded:
            try:
                return bytes(encoded).decode("utf-8"), end
            except UnicodeDecodeError:
                if all(item < 128 for item in encoded):
                    return bytes(encoded).decode("ascii"), end
    return None


def build_sensitive_scan_view(text: str) -> SensitiveScanView | None:
    """Build a bounded de-obfuscated view only when a cheap trigger matches.

    The original request is never mutated. Each normalized character retains
    its source span so API results and log redaction still cover the exact raw
    text supplied by the caller.
    """

    raw = str(text or "")
    if not raw:
        return None
    unicode_triggered = _UNICODE_OBFUSCATION_TRIGGER_RE.search(raw) is not None
    encoded_possible = "%" in raw or "\\" in raw or "&#" in raw
    if not unicode_triggered and (
        not encoded_possible or _ENCODED_OBFUSCATION_TRIGGER_RE.search(raw) is None
    ):
        return None

    chars: List[str] = []
    starts: List[int] = []
    ends: List[int] = []
    index = 0
    while index < len(raw):
        decoded = _decode_obfuscated_sequence(raw, index)
        if decoded is None:
            chunk = raw[index]
            source_end = index + 1
        else:
            chunk, source_end = decoded
        folded = _fold_obfuscated_chunk(chunk)
        for char in folded:
            chars.append(char)
            starts.append(index)
            ends.append(source_end)
        index = source_end

    normalized = "".join(chars)
    if normalized == raw:
        return None
    return SensitiveScanView(normalized, tuple(starts), tuple(ends))


def phase1_sensitive_syntax_possible(text: str, lowered_text: str | None = None) -> bool:
    """Cheap common gate for phase-1 secret syntaxes.

    Every phase-1 rule requires an assignment/header delimiter or a PEM armor
    header. Keeping this check outside individual rule sets avoids dozens of
    full-text substring scans for ordinary prose.
    """

    raw = str(text or "")
    if "=" in raw or ":" in raw or "#" in raw or "-----BEGIN" in raw:
        return True
    lowered = lowered_text if lowered_text is not None else raw.lower()
    if not any(hint in lowered for hint in _PHASE1_STRONG_LABEL_ROOT_HINTS):
        return False
    return any(hint in lowered for hint in _PHASE1_STRONG_LABEL_HINTS)


_PLACEHOLDER_VALUES = {
    "changeme",
    "change_me",
    "change-me",
    "example",
    "sample",
    "dummy",
    "placeholder",
    "redacted",
    "secret",
    "password",
    "your-secret-here",
}


def _is_placeholder(value: str) -> bool:
    normalized = str(value or "").strip().strip("<>{}[]()\"'").lower()
    if not normalized:
        return True
    if normalized in _PLACEHOLDER_VALUES:
        return True
    return normalized.startswith("${") or normalized.startswith("{{")


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


_PEM_PRIVATE_RE = re.compile(
    r"\A-----BEGIN (?P<label>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\r?\n"
    r"(?P<body>[A-Za-z0-9+/=\r\n]{40,32768})\r?\n"
    r"-----END (?P=label)-----\Z"
)


def _pem_private_key_valid(value: str) -> bool:
    raw = str(value or "").strip().replace("\\r\\n", "\n").replace("\\n", "\n")
    if raw.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----"):
        return raw.endswith("-----END PGP PRIVATE KEY BLOCK-----") and len(raw) >= 128
    match = _PEM_PRIVATE_RE.fullmatch(raw)
    if match is None:
        return False
    body = "".join(match.group("body").split())
    try:
        decoded = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) >= 32


def _credential_connection_string_valid(value: str) -> bool:
    raw = str(value or "").strip().strip("\"'")
    if not raw or _is_placeholder(raw):
        return False

    parsed_raw = raw[5:] if raw.lower().startswith("jdbc:") else raw
    try:
        parsed = urlsplit(parsed_raw)
    except ValueError:
        parsed = None
    if parsed is not None and parsed.scheme:
        if parsed.password and not _is_placeholder(parsed.password):
            if parsed.username or parsed.scheme.lower() in ("redis", "rediss"):
                return True
        query = {key.lower(): vals for key, vals in parse_qs(parsed.query, keep_blank_values=True).items()}
        users = query.get("user") or query.get("username") or query.get("uid")
        passwords = query.get("password") or query.get("passwd") or query.get("pwd")
        if users and passwords and any(value and not _is_placeholder(value) for value in passwords):
            return True

    parts: Dict[str, str] = {}
    for token in raw.split(";"):
        if "=" not in token:
            continue
        key, item = token.split("=", 1)
        parts[key.strip().lower().replace(" ", "")] = item.strip()
    password = parts.get("password") or parts.get("passwd") or parts.get("pwd")
    username = parts.get("userid") or parts.get("user") or parts.get("username") or parts.get("uid")
    account_key = parts.get("accountkey") or parts.get("sharedaccesssignature")
    if account_key and not _is_placeholder(account_key):
        return True
    return bool(username and password and not _is_placeholder(password))


def _signed_url_valid(value: str) -> bool:
    raw = str(value or "").strip().strip("\"'")
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    path = parsed.path or ""
    query = {key.lower(): vals for key, vals in parse_qs(parsed.query, keep_blank_values=True).items()}
    if "x-amz-signature" in query and "x-amz-credential" in query:
        return True
    if "x-goog-signature" in query and "x-goog-credential" in query:
        return True
    if host.endswith((".blob.core.windows.net", ".file.core.windows.net", ".dfs.core.windows.net")):
        return "sig" in query and "se" in query and ("sp" in query or "sv" in query)
    if host == "hooks.slack.com":
        return bool(re.fullmatch(r"/services/[A-Za-z0-9_-]{6,}/[A-Za-z0-9_-]{6,}/[A-Za-z0-9_-]{16,}", path))
    if host in ("discord.com", "discordapp.com"):
        return bool(re.fullmatch(r"/api(?:/v\d+)?/webhooks/\d{6,}/[A-Za-z0-9._-]{16,}", path))
    return False


def _base32_secret_valid(value: str) -> bool:
    raw = str(value or "").strip().replace(" ", "").replace("-", "").upper().rstrip("=")
    if not (16 <= len(raw) <= 128) or _is_placeholder(raw):
        return False
    return bool(re.fullmatch(r"[A-Z2-7]+", raw)) and len(set(raw)) >= 6


def _recovery_code_valid(value: str) -> bool:
    raw = str(value or "").strip()
    compact = re.sub(r"[-\s]", "", raw)
    if not (8 <= len(compact) <= 32) or _is_placeholder(compact):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9]+", compact)) and len(set(compact.lower())) >= 5


def _secret_value_valid(value: str) -> bool:
    raw = str(value or "").strip()
    return bool(raw) and not _is_placeholder(raw)


def _unquoted_password_valid(value: str) -> bool:
    """Reject policy vocabulary captured after a Korean password label."""

    raw = str(value or "").strip()
    if not _secret_value_valid(raw):
        return False
    folded = raw.casefold()
    if folded in {
        "policy",
        "rule",
        "rules",
        "대문자",
        "소문자",
        "영문",
        "숫자",
        "특수문자",
        "문자",
        "정책",
        "규칙",
        "최소",
        "이상",
    }:
        return False
    if re.fullmatch(r"\d{1,3}자", raw):
        return False
    return True


def _fragmented_otp_valid(value: str) -> bool:
    raw = str(value or "").strip()
    compact = re.sub(r"[\s&/.'`|_-]", "", raw)
    return compact.isdigit() and 4 <= len(compact) <= 8 and compact != raw


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
        raw_prefilter_any = rule_doc.get("prefilter_any") or []
        if isinstance(raw_prefilter_any, str):
            raw_prefilter_any = [raw_prefilter_any]
        if not isinstance(raw_prefilter_any, (list, tuple)):
            raise ValueError(f"{self.out_key}.prefilter_any must be a list")
        self.prefilter_any = tuple(str(item).lower() for item in raw_prefilter_any if str(item))

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
        if validator == "pem_private_key":
            return _pem_private_key_valid(value)
        if validator == "credential_connection_string":
            return _credential_connection_string_valid(value)
        if validator == "signed_url":
            return _signed_url_valid(value)
        if validator == "base32_secret":
            return _base32_secret_valid(value)
        if validator == "recovery_code":
            return _recovery_code_valid(value)
        if validator == "secret_value":
            return _secret_value_valid(value)
        if validator == "unquoted_password":
            return _unquoted_password_valid(value)
        if validator == "fragmented_otp":
            return _fragmented_otp_valid(value)
        return True

    def _find_in_text(self, text: str, max_results: int, lowered_text: str | None = None) -> List[dict]:
        if not self.enabled or not text or max_results <= 0:
            return []

        found: List[dict] = []
        if self.prefilter_any:
            if lowered_text is None:
                lowered_text = text.lower()
            if not any(hint in lowered_text for hint in self.prefilter_any):
                return []
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

        return found

    def find(
        self,
        text: str,
        max_results: int = 500,
        lowered_text: str | None = None,
        scan_view: SensitiveScanView | None = None,
    ) -> List[dict]:
        if not self.enabled or not text or max_results <= 0:
            return []

        found = self._find_in_text(text, max_results=max_results, lowered_text=lowered_text)
        if scan_view is not None and scan_view.text:
            normalized_items = self._find_in_text(
                scan_view.text,
                max_results=max_results,
                lowered_text=scan_view.text.lower(),
            )
            for item in normalized_items:
                span = scan_view.original_span(int(item["start"]), int(item["end"]))
                if span is None:
                    continue
                start, end = span
                found.append(
                    {
                        "start": start,
                        "end": end,
                        "matchString": text[start:end],
                        "detected_by": f'{item["detected_by"]}:normalized',
                    }
                )

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
    lowered = raw.lower()
    scan_view = build_sensitive_scan_view(raw)
    phase1_possible = phase1_sensitive_syntax_possible(raw, lowered) or bool(
        scan_view is not None and phase1_sensitive_syntax_possible(scan_view.text, scan_view.text.lower())
    )
    for pattern_set in _load_redaction_pattern_sets(directory):
        if pattern_set.out_key in PHASE1_SENSITIVE_TYPES and not phase1_possible:
            continue
        for item in pattern_set.find(
            raw,
            max_results=max_results_per_type,
            lowered_text=lowered,
            scan_view=scan_view,
        ):
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
