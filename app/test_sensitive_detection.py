from __future__ import annotations

import pytest

from app.grpc_server import _build_data
from app.pii_engine.detectors import SensitiveValueDetector
from app.pii_engine.engine import PiiEngine
from app.pii_engine.pipeline_builder import build_pipeline
from app.proto import pii_pb2
from app.response_builders import build_detect_response
from app.rules_loader import load_rules


@pytest.fixture(scope="module")
def sensitive_engine() -> PiiEngine:
    bundle = load_rules()
    pipeline = [step for step in build_pipeline(bundle) if isinstance(step, SensitiveValueDetector)]
    assert [step.out_key for step in pipeline] == [
        "OTP",
        "API_KEY",
        "AUTH_TOKEN",
        "PASSWORD",
        "INTERNAL_ACCESS",
        "PRIVATE_KEY",
        "CLOUD_CREDENTIAL",
        "CONNECTION_STRING",
        "SIGNED_URL",
        "MFA_SECRET",
        "RECOVERY_CODE",
        "SESSION_COOKIE",
    ]
    return PiiEngine(bundle, pipeline)


@pytest.mark.parametrize(
    ("out_key", "text", "expected", "detected_by"),
    [
        ("OTP", "인증번호: 482913", "482913", "otp_context_before"),
        ("OTP", "Your verification code is 847201", "847201", "otp_context_before"),
        ("API_KEY", "AWS key AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "aws_access_key_id"),
        ("API_KEY", "API_KEY=abcDEF1234567890xyz", "abcDEF1234567890xyz", "generic_api_key"),
        (
            "API_KEY",
            "API_KEY abcDEF1234567890xyz",
            "abcDEF1234567890xyz",
            "generic_api_key",
        ),
        (
            "API_KEY",
            "API_KEY\nabcDEF1234567890xyz",
            "abcDEF1234567890xyz",
            "generic_api_key",
        ),
        (
            "AUTH_TOKEN",
            "Authorization: Bearer abcDEF1234567890.xyz",
            "abcDEF1234567890.xyz",
            "bearer_token",
        ),
        (
            "AUTH_TOKEN",
            "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
            "jwt",
        ),
        ("AUTH_TOKEN", "Authorization: Basic dXNlcjpTM2NyZXQh", "dXNlcjpTM2NyZXQh", "basic_auth_token"),
        ("PASSWORD", "비밀번호: S3cure!Pass#2026", "S3cure!Pass#2026", "labeled_password"),
        ("PASSWORD", 'password="correct horse battery staple"', "correct horse battery staple", "labeled_password"),
        ("INTERNAL_ACCESS", "내부 IP: 10.20.30.40", "10.20.30.40", "private_ipv4"),
        (
            "INTERNAL_ACCESS",
            "접속: https://admin:pw@10.20.30.40:8443/admin",
            "https://admin:pw@10.20.30.40:8443/admin",
            "internal_url",
        ),
        ("INTERNAL_ACCESS", "호스트: db01.internal:5432", "db01.internal:5432", "internal_host"),
        ("INTERNAL_ACCESS", "내부 IP: ::1", "::1", "private_ipv6"),
    ],
)
def test_sensitive_types_detect_only_value(
    sensitive_engine: PiiEngine,
    out_key: str,
    text: str,
    expected: str,
    detected_by: str,
) -> None:
    found = sensitive_engine.detect(text, max_results_per_type=20)
    assert [item["matchString"] for item in found.get(out_key, [])] == [expected]
    assert found[out_key][0]["detected_by"] == detected_by
    start = text.index(expected)
    assert (found[out_key][0]["start"], found[out_key][0]["end"]) == (start, start + len(expected))


@pytest.mark.parametrize(
    "text",
    [
        "주문번호 482913",
        "order_id=abcDEF1234567890xyz",
        "비밀번호 정책을 변경하세요",
        "공개 DNS는 8.8.8.8 입니다",
        "문서는 https://www.example.com/public 에 있습니다",
        "endpoint: https://example.com/api",
        "공개 DNS는 2001:4860:4860::8888 입니다",
        "API_KEY=AAAAAAAAAAAAAAAAAAAA",
        "API_KEY AAAAAAAAAAAAAAAAAAAA",
        "service key abcDEF1234567890xyz",
    ],
)
def test_sensitive_types_reject_unlabeled_or_public_values(sensitive_engine: PiiEngine, text: str) -> None:
    found = sensitive_engine.detect(text, max_results_per_type=20)
    for key in (
        "OTP", "API_KEY", "AUTH_TOKEN", "PASSWORD", "INTERNAL_ACCESS",
        "PRIVATE_KEY", "CLOUD_CREDENTIAL", "CONNECTION_STRING", "SIGNED_URL",
        "MFA_SECRET", "RECOVERY_CODE", "SESSION_COOKIE",
    ):
        assert found.get(key, []) == []


def test_sensitive_types_are_returned_by_http_and_grpc_builders(sensitive_engine: PiiEngine) -> None:
    text = (
        "인증번호: 482913\n"
        "API_KEY=abcDEF1234567890xyz\n"
        "Authorization: Bearer abcDEF1234567890.xyz\n"
        "비밀번호: S3cure!Pass#2026\n"
        "내부 IP: 10.20.30.40"
    )
    found = sensitive_engine.detect(text, max_results_per_type=20)
    meta = {
        "ruleset_name": "default",
        "ruleset_version": "test",
        "ruleset_updated_at": "2026-08-26T00:00:00+00:00",
    }

    http_data = build_detect_response(found, meta).data
    assert http_data.OTP_CNT == 1
    assert http_data.API_KEY_CNT == 1
    assert http_data.AUTH_TOKEN_CNT == 1
    assert http_data.PASSWORD_CNT == 1
    assert http_data.INTERNAL_ACCESS_CNT == 1

    grpc_data = _build_data(pii_pb2, found)
    assert grpc_data.otp_cnt == 1
    assert grpc_data.api_key_cnt == 1
    assert grpc_data.auth_token_cnt == 1
    assert grpc_data.password_cnt == 1
    assert grpc_data.internal_access_cnt == 1
    assert grpc_data.password[0].match_string == "S3cure!Pass#2026"
