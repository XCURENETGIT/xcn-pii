from __future__ import annotations

import app.grpc_server as grpc_server
import app.main as main
from app.sensitive_values import redact_sensitive_text


SENSITIVE_TEXT = (
    "인증번호: 482913, "
    "API_KEY=abcDEF1234567890xyz, "
    "Authorization: Bearer abcDEF1234567890.xyz, "
    "비밀번호: S3cure!Pass#2026, "
    "내부 IP: 10.20.30.40"
)


def test_redact_sensitive_text_masks_values_and_keeps_labels() -> None:
    redacted = redact_sensitive_text(SENSITIVE_TEXT)
    for value in (
        "482913",
        "abcDEF1234567890xyz",
        "abcDEF1234567890.xyz",
        "S3cure!Pass#2026",
        "10.20.30.40",
    ):
        assert value not in redacted
    for marker in (
        "[REDACTED:OTP]",
        "[REDACTED:API_KEY]",
        "[REDACTED:AUTH_TOKEN]",
        "[REDACTED:PASSWORD]",
        "[REDACTED:INTERNAL_ACCESS]",
    ):
        assert marker in redacted
    assert "인증번호:" in redacted
    assert "비밀번호:" in redacted


def test_http_and_grpc_request_log_suffix_redacts_by_default(monkeypatch) -> None:
    monkeypatch.setenv("PII_LOG_REQUEST_TEXT_ENABLED", "true")
    monkeypatch.setenv("PII_LOG_REQUEST_TEXT_LIMIT", "10000000")
    monkeypatch.delenv("PII_LOG_REQUEST_TEXT_REDACT_SENSITIVE", raising=False)

    for suffix in (main._request_text_log_suffix(SENSITIVE_TEXT), grpc_server._request_text_log_suffix(SENSITIVE_TEXT)):
        assert "text_logged=true" in suffix
        assert "sensitive_redaction=applied" in suffix
        assert "S3cure!Pass#2026" not in suffix
        assert "[REDACTED:PASSWORD]" in suffix


def test_expanded_contexts_are_redacted() -> None:
    text = (
        'MFA code: 739201 '
        '{"apiKey":"AbCDef1234567890xyz"} '
        '{"X-Auth-Token":"Auth-2026.AbCdEfGhIjKl"} '
        '{"password":"Json!Pass-2026"} '
        'jdbc:postgresql://db01.internal:5432/app'
    )
    redacted = redact_sensitive_text(text)
    for value in (
        "739201",
        "AbCDef1234567890xyz",
        "Auth-2026.AbCdEfGhIjKl",
        "Json!Pass-2026",
        "jdbc:postgresql://db01.internal:5432/app",
    ):
        assert value not in redacted
    for out_type in ("OTP", "API_KEY", "AUTH_TOKEN", "PASSWORD", "INTERNAL_ACCESS"):
        assert f"[REDACTED:{out_type}]" in redacted


def test_request_log_redaction_fails_closed(monkeypatch) -> None:
    monkeypatch.setenv("PII_LOG_REQUEST_TEXT_ENABLED", "true")
    monkeypatch.setenv("PII_LOG_REQUEST_TEXT_REDACT_SENSITIVE", "true")

    def fail(_text: str) -> str:
        raise RuntimeError("redaction unavailable")

    monkeypatch.setattr(main, "redact_sensitive_text", fail)
    suffix = main._request_text_log_suffix("password=must-not-leak")
    assert "sensitive_redaction=failed_closed" in suffix
    assert "must-not-leak" not in suffix
    assert "[REDACTION_FAILED]" in suffix
