from __future__ import annotations

import base64

import pytest

from app.grpc_server import _build_data
from app.pii_engine.detectors import SensitiveValueDetector
from app.pii_engine.engine import PiiEngine
from app.pii_engine.pipeline_builder import build_pipeline
from app.proto import pii_pb2
from app.response_builders import build_detect_response
from app.rules_loader import load_rules
from app.sensitive_values import SENSITIVE_RULE_TYPES, redact_sensitive_text


PEM_BODY = base64.b64encode(bytes(range(64))).decode("ascii")
PEM_PRIVATE_KEY = f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----"
ESCAPED_PEM_PRIVATE_KEY = f"-----BEGIN PRIVATE KEY-----\\n{PEM_BODY}\\n-----END PRIVATE KEY-----"
PGP_PRIVATE_KEY = f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{('AbCdEf0123456789' * 8)}\n-----END PGP PRIVATE KEY BLOCK-----"
AWS_SECRET = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AB"
AWS_SESSION = "IQoJb3JpZ2luX2VjEAbCdEfGhIjKlMnOpQrStUvWxYz012345"
AZURE_KEY = "QWJjZEVmR2hJamtsTW5PcFFyU3RVdld4WXowMTIzNDU2Nzg5QUJDREVGR0hJSktMTU5PUA=="


@pytest.fixture(scope="module")
def sensitive_engine() -> PiiEngine:
    bundle = load_rules()
    pipeline = [step for step in build_pipeline(bundle) if isinstance(step, SensitiveValueDetector)]
    return PiiEngine(bundle, pipeline)


@pytest.mark.parametrize(
    ("out_key", "text", "expected", "detected_by"),
    [
        ("PRIVATE_KEY", PEM_PRIVATE_KEY, PEM_PRIVATE_KEY, "pem_private_key"),
        ("PRIVATE_KEY", f'{{"private_key":"{ESCAPED_PEM_PRIVATE_KEY}\\n"}}', ESCAPED_PEM_PRIVATE_KEY, "escaped_pem_private_key"),
        ("PRIVATE_KEY", PGP_PRIVATE_KEY, PGP_PRIVATE_KEY, "pgp_private_key"),
        ("CLOUD_CREDENTIAL", f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}", AWS_SECRET, "aws_secret_access_key"),
        ("CLOUD_CREDENTIAL", f"aws_session_token = {AWS_SESSION}", AWS_SESSION, "aws_session_token"),
        ("CLOUD_CREDENTIAL", f"AccountKey={AZURE_KEY}", AZURE_KEY, "azure_storage_account_key"),
        (
            "CONNECTION_STRING",
            "postgresql://svc_user:S3cretPassw0rd@db.example.com:5432/app",
            "postgresql://svc_user:S3cretPassw0rd@db.example.com:5432/app",
            "credential_uri",
        ),
        ("CONNECTION_STRING", "redis://:R3disPassw0rd@cache.example.com:6379/0", "redis://:R3disPassw0rd@cache.example.com:6379/0", "credential_uri"),
        (
            "CONNECTION_STRING",
            "jdbc:postgresql://db.example.com/app?user=svc&password=S3cretPassw0rd",
            "jdbc:postgresql://db.example.com/app?user=svc&password=S3cretPassw0rd",
            "jdbc_credential_url",
        ),
        (
            "CONNECTION_STRING",
            f"DefaultEndpointsProtocol=https;AccountName=storeprod;AccountKey={AZURE_KEY};EndpointSuffix=core.windows.net",
            f"DefaultEndpointsProtocol=https;AccountName=storeprod;AccountKey={AZURE_KEY};EndpointSuffix=core.windows.net",
            "key_value_connection_string",
        ),
        (
            "SIGNED_URL",
            "https://bucket.s3.amazonaws.com/a.txt?X-Amz-Credential=AKIA123%2F20260827&X-Amz-Signature=abcdef0123456789abcdef0123456789",
            "https://bucket.s3.amazonaws.com/a.txt?X-Amz-Credential=AKIA123%2F20260827&X-Amz-Signature=abcdef0123456789abcdef0123456789",
            "signed_url",
        ),
        (
            "SIGNED_URL",
            "https://hooks.slack.com/services/T0123456/B0123456/AbCdEfGhIjKlMnOpQrStUvWx",
            "https://hooks.slack.com/services/T0123456/B0123456/AbCdEfGhIjKlMnOpQrStUvWx",
            "signed_url",
        ),
        (
            "SIGNED_URL",
            "https://storage.googleapis.com/bucket/a.txt?X-Goog-Credential=svc%40example.iam.gserviceaccount.com&X-Goog-Signature=abcdef0123456789abcdef0123456789",
            "https://storage.googleapis.com/bucket/a.txt?X-Goog-Credential=svc%40example.iam.gserviceaccount.com&X-Goog-Signature=abcdef0123456789abcdef0123456789",
            "signed_url",
        ),
        (
            "SIGNED_URL",
            "https://store.blob.core.windows.net/c/a.txt?sv=2025-01-01&sp=r&se=2030-01-01&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%3D",
            "https://store.blob.core.windows.net/c/a.txt?sv=2025-01-01&sp=r&se=2030-01-01&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%3D",
            "signed_url",
        ),
        (
            "SIGNED_URL",
            "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz012345",
            "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz012345",
            "signed_url",
        ),
        ("MFA_SECRET", "otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example", "JBSWY3DPEHPK3PXP", "otpauth_secret"),
        ("MFA_SECRET", "TOTP_SECRET=JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP", "labeled_mfa_secret"),
        ("RECOVERY_CODE", "recovery_code=ABCD-EF12-IJKL-3456", "ABCD-EF12-IJKL-3456", "labeled_recovery_code"),
        ("SESSION_COOKIE", "Cookie: JSESSIONID=ABCDEF0123456789ABCDEF0123456789", "ABCDEF0123456789ABCDEF0123456789", "framework_session_cookie"),
        ("SESSION_COOKIE", "Cookie: theme=dark; access_token=AbCdEf0123456789AbCdEf0123456789", "AbCdEf0123456789AbCdEf0123456789", "auth_cookie_header"),
    ],
)
def test_phase1_secret_types(
    sensitive_engine: PiiEngine,
    out_key: str,
    text: str,
    expected: str,
    detected_by: str,
) -> None:
    found = sensitive_engine.detect(text, max_results_per_type=20)
    item = next(item for item in found.get(out_key, []) if item["matchString"] == expected)
    assert item["detected_by"] == detected_by


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN CERTIFICATE-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END CERTIFICATE-----",
        "AWS_SECRET_ACCESS_KEY=changeme",
        "postgresql://db.example.com:5432/app",
        "https://example.com/public?sig=abcdef",
        "TOTP generates a six digit code",
        "JBSWY3DPEHPK3PXP",
        "recovery code documentation",
        "Cookie: theme=dark; locale=ko-KR",
        "JSESSIONID=short",
        "access_token=AbCdEf0123456789AbCdEf0123456789",
    ],
)
def test_phase1_secret_types_reject_non_secrets(sensitive_engine: PiiEngine, text: str) -> None:
    found = sensitive_engine.detect(text, max_results_per_type=20)
    for key in ("PRIVATE_KEY", "CLOUD_CREDENTIAL", "CONNECTION_STRING", "SIGNED_URL", "MFA_SECRET", "RECOVERY_CODE", "SESSION_COOKIE"):
        assert found.get(key, []) == []


def test_phase1_types_are_exposed_over_http_grpc_and_redaction(sensitive_engine: PiiEngine) -> None:
    values = {
        "PRIVATE_KEY": PEM_PRIVATE_KEY,
        "CLOUD_CREDENTIAL": AWS_SECRET,
        "CONNECTION_STRING": "postgresql://svc:S3cretPassw0rd@db.example.com/app",
        "SIGNED_URL": "https://hooks.slack.com/services/T0123456/B0123456/AbCdEfGhIjKlMnOpQrStUvWx",
        "MFA_SECRET": "JBSWY3DPEHPK3PXP",
        "RECOVERY_CODE": "ABCD-EF12-IJKL-3456",
        "SESSION_COOKIE": "ABCDEF0123456789ABCDEF0123456789",
    }
    text = "\n".join(
        (
            PEM_PRIVATE_KEY,
            f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}",
            values["CONNECTION_STRING"],
            values["SIGNED_URL"],
            f"TOTP_SECRET={values['MFA_SECRET']}",
            f"recovery_code={values['RECOVERY_CODE']}",
            f"Cookie: JSESSIONID={values['SESSION_COOKIE']}",
        )
    )
    found = sensitive_engine.detect(text, max_results_per_type=20)
    meta = {"ruleset_name": "default", "ruleset_version": "test", "ruleset_updated_at": "2026-08-27T00:00:00+09:00"}
    http_data = build_detect_response(found, meta).data
    grpc_data = _build_data(pii_pb2, found)
    redacted = redact_sensitive_text(text)

    for out_key, _ in SENSITIVE_RULE_TYPES[5:]:
        assert getattr(http_data, f"{out_key}_CNT") >= 1
        grpc_name = out_key.lower()
        assert getattr(grpc_data, f"{grpc_name}_cnt") >= 1
        assert f"[REDACTED:{out_key}]" in redacted
        assert values[out_key] not in redacted


def test_every_phase1_pattern_has_prefilter_and_bounded_regex() -> None:
    bundle = load_rules()
    for key in ("private_key", "cloud_credential", "connection_string", "signed_url", "mfa_secret", "recovery_code", "session_cookie"):
        doc = bundle.rule_docs[key]
        assert doc.get("prefilter_any"), key
        for pattern in doc.get("patterns") or []:
            assert pattern.get("prefilter_any"), f"{key}.{pattern.get('name')}"
            regex = str(pattern.get("regex") or "")
            assert ".*" not in regex, f"unbounded wildcard in {key}.{pattern.get('name')}"
