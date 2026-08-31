from __future__ import annotations

import base64

import pytest

from app.pii_engine.detectors import SensitiveValueDetector
from app.pii_engine.engine import PiiEngine
from app.pii_engine.pipeline_builder import build_pipeline
from app.rules_loader import load_rules
from app.sensitive_values import build_sensitive_scan_view, redact_sensitive_text


PEM_BODY = base64.b64encode(bytes(range(64))).decode("ascii")
AWS_SECRET = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AB"


@pytest.fixture(scope="module")
def sensitive_engine() -> PiiEngine:
    bundle = load_rules()
    pipeline = [step for step in build_pipeline(bundle) if isinstance(step, SensitiveValueDetector)]
    return PiiEngine(bundle, pipeline)


@pytest.mark.parametrize(
    ("out_key", "text", "expected"),
    [
        ("OTP", "O\u200bTP＝１２３４５６", "１２３４５６"),
        ("API_KEY", "ＡＰＩ＿ＫＥＹ＝abcD\u200bEF1234567890xyz", "abcD\u200bEF1234567890xyz"),
        ("AUTH_TOKEN", "Authorization： Be\u200barer AbCdEf0123456789-token.value", "AbCdEf0123456789-token.value"),
        ("PASSWORD", "pass\u200bword＝S3cure!Pass#2026", "S3cure!Pass#2026"),
        ("INTERNAL_ACCESS", "내부 IP： １０．２０．３０．４０", "１０．２０．３０．４０"),
        (
            "PRIVATE_KEY",
            f"-----BEGIN PRI\u200bVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----",
            f"-----BEGIN PRI\u200bVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----",
        ),
        ("CLOUD_CREDENTIAL", f"AWS_SECRET_ACCESS_KEY＝{AWS_SECRET}", AWS_SECRET),
        (
            "CONNECTION_STRING",
            "postgresql：／／svc:S3cretPassw0rd@db.example.com/app",
            "postgresql：／／svc:S3cretPassw0rd@db.example.com/app",
        ),
        (
            "SIGNED_URL",
            "https://bucket.s3.amazonaws.com/a.txt?X-Amz-Credential=AKIA123%2F20260827&X-Amz-Signature＝abcdef0123456789abcdef0123456789",
            "https://bucket.s3.amazonaws.com/a.txt?X-Amz-Credential=AKIA123%2F20260827&X-Amz-Signature＝abcdef0123456789abcdef0123456789",
        ),
        ("MFA_SECRET", "TOTP_SECRET＝JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"),
        ("RECOVERY_CODE", "recovery_code＝ABCD-EF12-IJKL-3456", "ABCD-EF12-IJKL-3456"),
        ("SESSION_COOKIE", "Cookie： JSESSIONID＝ABCDEF0123456789ABCDEF0123456789", "ABCDEF0123456789ABCDEF0123456789"),
        ("API_KEY", r"API\u005fKEY\u003dabcDEF1234567890xyz", "abcDEF1234567890xyz"),
        ("PASSWORD", "password&#x3d;S3cure!Pass#2026", "S3cure!Pass#2026"),
        ("AUTH_TOKEN", "AUTH_TOKEN%20AbCdEf0123456789-token.value", "AbCdEf0123456789-token.value"),
    ],
)
def test_unicode_and_encoded_obfuscation_maps_to_original_text(
    sensitive_engine: PiiEngine,
    out_key: str,
    text: str,
    expected: str,
) -> None:
    found = sensitive_engine.detect(text, max_results_per_type=20)
    item = next(item for item in found.get(out_key, []) if item["matchString"] == expected)
    assert text[item["start"]:item["end"]] == expected
    assert item["detected_by"]


@pytest.mark.parametrize(
    ("out_key", "text", "expected"),
    [
        ("API_KEY", "API_KEY\nabcDEF1234567890xyz", "abcDEF1234567890xyz"),
        ("API_KEY", "**API_KEY** `abcDEF1234567890xyz`", "abcDEF1234567890xyz"),
        ("API_KEY", "API_KEY | abcDEF1234567890xyz", "abcDEF1234567890xyz"),
        ("API_KEY", "API_KEY -> abcDEF1234567890xyz", "abcDEF1234567890xyz"),
        ("AUTH_TOKEN", "AUTH_TOKEN AbCdEf0123456789-token.value", "AbCdEf0123456789-token.value"),
        ("PASSWORD", "PASSWORD S3cure!Pass#2026", "S3cure!Pass#2026"),
        ("CLOUD_CREDENTIAL", f"AWS_SECRET_ACCESS_KEY {AWS_SECRET}", AWS_SECRET),
        ("MFA_SECRET", "TOTP_SECRET JBSW Y3DP EHPK 3PXP", "JBSW Y3DP EHPK 3PXP"),
        ("RECOVERY_CODE", "RECOVERY_CODE ABCD-EF12-IJKL-3456", "ABCD-EF12-IJKL-3456"),
        ("SESSION_COOKIE", "JSESSIONID ABCDEF0123456789ABCDEF0123456789", "ABCDEF0123456789ABCDEF0123456789"),
        ("OTP", "OTP 1 2 3 4 5 6", "1 2 3 4 5 6"),
        ("OTP", "인증번호 | 1&2&3&4&5&6", "1&2&3&4&5&6"),
    ],
)
def test_strong_labels_accept_bounded_evasion_separators(
    sensitive_engine: PiiEngine,
    out_key: str,
    text: str,
    expected: str,
) -> None:
    found = sensitive_engine.detect(text, max_results_per_type=20)
    item = next(item for item in found.get(out_key, []) if item["matchString"] == expected)
    assert text[item["start"]:item["end"]] == expected


@pytest.mark.parametrize(
    ("out_key", "text"),
    [
        ("API_KEY", "service key abcDEF1234567890xyz"),
        ("API_KEY", "API_KEY AAAAAAAAAAAAAAAAAAAA"),
        ("API_KEY", "ΑPI_KEY abcDEF1234567890xyz"),  # Greek alpha is not folded to Latin A.
        ("AUTH_TOKEN", "AUTH_TOKEN documentationonly"),
        ("PASSWORD", "PASSWORD POLICY"),
        ("RECOVERY_CODE", "recovery code documentation"),
        ("SESSION_COOKIE", "JSESSIONID documentation"),
        ("API_KEY", r"API\uZZZZKEY abcDEF1234567890xyz"),
    ],
)
def test_evasion_hardening_keeps_negative_guards(
    sensitive_engine: PiiEngine,
    out_key: str,
    text: str,
) -> None:
    found = sensitive_engine.detect(text, max_results_per_type=20)
    assert found.get(out_key, []) == []


def test_normalized_detection_redacts_the_exact_obfuscated_source_span() -> None:
    raw_value = "abcD\u200bEF1234567890xyz"
    text = f"ＡＰＩ＿ＫＥＹ＝{raw_value}"
    redacted = redact_sensitive_text(text)
    assert raw_value not in redacted
    assert "[REDACTED:API_KEY]" in redacted
    assert "ＡＰＩ＿ＫＥＹ＝" in redacted


def test_ordinary_text_does_not_build_a_secondary_scan_view() -> None:
    assert build_sensitive_scan_view("일반 공개 문서의 처리 절차와 상태를 설명합니다.") is None


def test_fullwidth_and_escape_views_are_built_only_on_demand() -> None:
    assert build_sensitive_scan_view("ＡＰＩ＿ＫＥＹ＝value").text == "API_KEY=value"
    assert build_sensitive_scan_view(r"API\u005fKEY\u003dvalue").text == "API_KEY=value"
