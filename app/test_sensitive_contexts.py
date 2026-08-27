from __future__ import annotations

import pytest

from app.pii_engine.detectors import SensitiveValueDetector
from app.pii_engine.engine import PiiEngine
from app.pii_engine.pipeline_builder import build_pipeline
from app.rules_loader import load_rules


@pytest.fixture(scope="module")
def sensitive_engine() -> PiiEngine:
    bundle = load_rules()
    pipeline = [step for step in build_pipeline(bundle) if isinstance(step, SensitiveValueDetector)]
    return PiiEngine(bundle, pipeline)


@pytest.mark.parametrize(
    ("out_key", "text", "expected"),
    [
        ("OTP", "MFA code: 739201", "739201"),
        ("OTP", "2FA_PIN=884422", "884422"),
        ("OTP", "본인확인 코드 [551122]", "551122"),
        ("OTP", "739201 is your verification code", "739201"),
        ("OTP", "482913은 인증번호입니다", "482913"),
        ("OTP", "로그인 코드는 663311", "663311"),
        ("API_KEY", '{"apiKey":"AbCDef1234567890xyz"}', "AbCDef1234567890xyz"),
        ("API_KEY", "Ocp-Apim-Subscription-Key: Az9xY8wV7uT6sR5qP4nM3kL2", "Az9xY8wV7uT6sR5qP4nM3kL2"),
        ("API_KEY", "client_secret = Cl13nt.S3cret-2026-Prod", "Cl13nt.S3cret-2026-Prod"),
        ("API_KEY", "웹훅 시크릿: whsec_Z9y8X7w6V5u4T3s2R1q0", "whsec_Z9y8X7w6V5u4T3s2R1q0"),
        ("API_KEY", "Hugging Face token hf_abcdefghijklmnopqrstuvwxyzABCDEFGH", "hf_abcdefghijklmnopqrstuvwxyzABCDEFGH"),
        ("API_KEY", "GitLab token glpat-AbCdEfGhIjKlMnOpQrStUvWx", "glpat-AbCdEfGhIjKlMnOpQrStUvWx"),
        ("API_KEY", "SvcK3y-2026-AbCdEfGh is the service key", "SvcK3y-2026-AbCdEfGh"),
        ("AUTH_TOKEN", '{"X-Auth-Token":"Auth-2026.AbCdEfGhIjKl"}', "Auth-2026.AbCdEfGhIjKl"),
        ("AUTH_TOKEN", "session_token=Sess-2026-AbCdEfGhIjKl", "Sess-2026-AbCdEfGhIjKl"),
        ("AUTH_TOKEN", "csrfToken: a1b2c3d4e5f60718293a4b5c6d7e8f90", "a1b2c3d4e5f60718293a4b5c6d7e8f90"),
        ("AUTH_TOKEN", "Tok3n-2026.AbCdEfGhIjKl is the access token", "Tok3n-2026.AbCdEfGhIjKl"),
        ("AUTH_TOKEN", "Authorization: Token Tok3n-Header-2026.AbCd", "Tok3n-Header-2026.AbCd"),
        ("AUTH_TOKEN", "세션 토큰은 Sess-KR-2026.AbCdEfGh", "Sess-KR-2026.AbCdEfGh"),
        ("PASSWORD", '{"password":"Json!Pass-2026"}', "Json!Pass-2026"),
        ("PASSWORD", "DB_PASSWORD=Db!Pass-2026", "Db!Pass-2026"),
        ("PASSWORD", "The admin password is Adm1n!Pass-2026", "Adm1n!Pass-2026"),
        ("PASSWORD", "tool --password Cli!Pass-2026 --verbose", "Cli!Pass-2026"),
        ("PASSWORD", "<password>Xml!Pass-2026</password>", "Xml!Pass-2026"),
        ("PASSWORD", "초기 비밀번호는 Init!Pass-2026", "Init!Pass-2026"),
        ("PASSWORD", "비밀번호를 입력하세요: Input!Pass-2026", "Input!Pass-2026"),
        ("INTERNAL_ACCESS", '{"hostname":"app01.svc.cluster.local"}', "app01.svc.cluster.local"),
        ("INTERNAL_ACCESS", "DB_HOST=db01", "db01"),
        ("INTERNAL_ACCESS", "운영 DB 주소는 10.0.20.15", "10.0.20.15"),
        ("INTERNAL_ACCESS", "bastion_host=jump01.corp:22", "jump01.corp:22"),
        ("INTERNAL_ACCESS", "jdbc:postgresql://db01.internal:5432/app", "jdbc:postgresql://db01.internal:5432/app"),
        ("INTERNAL_ACCESS", "redis://cache01:6379/0", "redis://cache01:6379/0"),
        ("INTERNAL_ACCESS", "internal subnet 10.20.0.0/16", "10.20.0.0/16"),
        ("INTERNAL_ACCESS", "socket_path=/var/run/postgresql/.s.PGSQL.5432", "/var/run/postgresql/.s.PGSQL.5432"),
        ("INTERNAL_ACCESS", "KAFKA_BROKER=kafka01.svc:9092", "kafka01.svc:9092"),
        ("INTERNAL_ACCESS", 'endpoint="http://api01.internal/v1"', "http://api01.internal/v1"),
        ("INTERNAL_ACCESS", "VPN 서버 주소: vpn-gw", "vpn-gw"),
    ],
)
def test_expanded_sensitive_contexts(
    sensitive_engine: PiiEngine,
    out_key: str,
    text: str,
    expected: str,
) -> None:
    found = sensitive_engine.detect(text, max_results_per_type=20)
    values = [item["matchString"] for item in found.get(out_key, [])]
    assert expected in values
    item = next(item for item in found[out_key] if item["matchString"] == expected)
    assert text[item["start"]:item["end"]] == expected


@pytest.mark.parametrize(
    ("out_key", "text"),
    [
        ("OTP", "MFA rollout requires a six digit code"),
        ("OTP", "verification code length is 6"),
        ("API_KEY", '{"apiKey":"short"}'),
        ("API_KEY", "public_key=AbCDef1234567890xyz"),
        ("API_KEY", "client secret rotation policy"),
        ("AUTH_TOKEN", '{"token":"short"}'),
        ("AUTH_TOKEN", "token validation documentation"),
        ("PASSWORD", "--password-help shows usage"),
        ("PASSWORD", '{"password":""}'),
        ("INTERNAL_ACCESS", '{"host":"api.example.com"}'),
        ("INTERNAL_ACCESS", "DB_HOST=example.com"),
        ("INTERNAL_ACCESS", "public subnet 8.8.8.0/24"),
        ("INTERNAL_ACCESS", "endpoint=https://example.com/api"),
        ("INTERNAL_ACCESS", "socket documentation at /docs/socket"),
    ],
)
def test_expanded_contexts_keep_negative_guards(
    sensitive_engine: PiiEngine,
    out_key: str,
    text: str,
) -> None:
    found = sensitive_engine.detect(text, max_results_per_type=20)
    assert found.get(out_key, []) == []


def test_value_before_otp_context_does_not_capture_nearby_date(sensitive_engine: PiiEngine) -> None:
    text = "CTXLOG_HTTP_20260827 MFA code: 739201"
    found = sensitive_engine.detect(text, max_results_per_type=20)
    assert [item["matchString"] for item in found.get("OTP", [])] == ["739201"]
