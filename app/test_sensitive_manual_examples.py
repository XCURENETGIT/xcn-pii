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


PROVIDER_CASES = (
    ("AK01", "AWS AKIA", "AKIAIOSFODNN7EXAMPLE", "aws_access_key_id"),
    ("AK02", "AWS ASIA", "ASIAIOSFODNN7EXAMPLE", "aws_access_key_id"),
    ("AK03", "GitHub ghp", "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github_token"),
    ("AK04", "GitHub gho", "gho_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github_token"),
    ("AK05", "GitHub ghu", "ghu_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github_token"),
    ("AK06", "GitHub ghs", "ghs_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github_token"),
    ("AK07", "GitHub ghr", "ghr_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github_token"),
    ("AK08", "GitHub fine-grained", "github_pat_11AA22BB33CC44DD55EE66FF", "github_token"),
    ("AK09", "Google", "AIzaAbCdEfGhIjKlMnOpQrStUvWxYz012345678", "google_api_key"),
    ("AK10", "Slack xoxb", "xoxb-1234567890-AbCdEfGhIjKlMnOp", "slack_token"),
    ("AK11", "Slack xoxa", "xoxa-1234567890-AbCdEfGhIjKlMnOp", "slack_token"),
    ("AK12", "Slack xoxp", "xoxp-1234567890-AbCdEfGhIjKlMnOp", "slack_token"),
    ("AK13", "Slack xoxr", "xoxr-1234567890-AbCdEfGhIjKlMnOp", "slack_token"),
    ("AK14", "Slack xoxs", "xoxs-1234567890-AbCdEfGhIjKlMnOp", "slack_token"),
    ("AK15", "OpenAI standard", "sk-AbCdEfGhIjKlMnOpQrStUvWx", "openai_api_key"),
    ("AK16", "OpenAI project", "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx", "openai_api_key"),
    ("AK17", "Stripe sk_live", "sk_live_AbCdEfGhIjKlMnOp", "stripe_secret_key"),
    ("AK18", "Stripe sk_test", "sk_test_AbCdEfGhIjKlMnOp", "stripe_secret_key"),
    ("AK19", "Stripe rk_live", "rk_live_AbCdEfGhIjKlMnOp", "stripe_secret_key"),
    ("AK20", "Stripe rk_test", "rk_test_AbCdEfGhIjKlMnOp", "stripe_secret_key"),
    ("AK21", "GitLab", "glpat-AbCdEfGhIjKlMnOpQrStUvWx", "gitlab_token"),
    ("AK22", "Hugging Face", "hf_abcdefghijklmnopqrstuvwxyzABCDEFGH", "huggingface_token"),
    ("AK23", "npm", "npm_abcdefghijklmnopqrstuvwxyzABCDEFGH", "npm_token"),
    ("AK24", "SendGrid", "SG.AbCdEfGhIjKlMnOp.QrStUvWxYz012345", "sendgrid_api_key"),
    ("AK25", "Twilio", "SK0123456789abcdef0123456789abcdef", "twilio_api_key"),
)


@pytest.mark.parametrize(("case_id", "description", "value", "detected_by"), PROVIDER_CASES)
def test_documented_provider_formats(
    sensitive_engine: PiiEngine,
    case_id: str,
    description: str,
    value: str,
    detected_by: str,
) -> None:
    del case_id, description
    found = sensitive_engine.detect(f"provider credential: {value}", max_results_per_type=20)
    item = next(item for item in found.get("API_KEY", []) if item["matchString"] == value)
    assert item["detected_by"] == detected_by


INTERNAL_URL_SCHEMES = (
    ("IA01", "http", "http://app01.internal:8080/api"),
    ("IA02", "https", "https://app01.internal/api"),
    ("IA03", "ssh", "ssh://admin@jump01.corp:22"),
    ("IA04", "sftp", "sftp://files01.internal:22/in"),
    ("IA05", "ftp", "ftp://files01.internal/in"),
    ("IA06", "postgres", "postgres://svc:FakePass@db01.internal:5432/app"),
    ("IA07", "postgresql", "postgresql://svc:FakePass@db01.internal:5432/app"),
    ("IA08", "jdbc:postgresql", "jdbc:postgresql://db01.internal:5432/app"),
    ("IA09", "mysql", "mysql://svc:FakePass@db01.internal:3306/app"),
    ("IA10", "jdbc:mysql", "jdbc:mysql://db01.internal:3306/app"),
    ("IA11", "mariadb", "mariadb://db01.internal:3306/app"),
    ("IA12", "mssql", "mssql://sql01.internal:1433/app"),
    ("IA13", "sqlserver", "sqlserver://sql01.internal:1433/app"),
    ("IA14", "oracle", "oracle://ora01.internal:1521/XEPDB1"),
    ("IA15", "mongodb", "mongodb://mongo01.internal:27017/app"),
    ("IA16", "mongodb+srv", "mongodb+srv://mongo01.internal/app"),
    ("IA17", "redis", "redis://cache01.internal:6379/0"),
    ("IA18", "rediss", "rediss://cache01.internal:6380/0"),
    ("IA19", "amqp", "amqp://mq01.internal:5672/vhost"),
    ("IA20", "amqps", "amqps://mq01.internal:5671/vhost"),
    ("IA21", "kafka", "kafka://broker01.internal:9092/topic"),
    ("IA22", "nats", "nats://nats01.internal:4222"),
    ("IA23", "ldap", "ldap://ldap01.internal:389"),
    ("IA24", "ldaps", "ldaps://ldap01.internal:636"),
    ("IA25", "rmi", "rmi://java01.internal:1099/service"),
    ("IA26", "tcp", "tcp://collector01.internal:9000"),
    ("IA27", "ws", "ws://socket01.internal:8080/ws"),
    ("IA28", "wss", "wss://socket01.internal/ws"),
)


@pytest.mark.parametrize(("case_id", "scheme", "value"), INTERNAL_URL_SCHEMES)
def test_documented_internal_url_schemes(
    sensitive_engine: PiiEngine,
    case_id: str,
    scheme: str,
    value: str,
) -> None:
    del case_id, scheme
    found = sensitive_engine.detect(value, max_results_per_type=20)
    item = next(item for item in found.get("INTERNAL_ACCESS", []) if item["matchString"] == value)
    assert item["detected_by"] == "internal_url"


MANUAL_FAMILY_CASES = (
    ("OT01", "OTP", "OTP=1234", "1234", "otp_context_before"),
    ("OT02", "OTP", "MFA code: 739201", "739201", "otp_context_before"),
    ("OT03", "OTP", "본인확인 코드 [551122]", "551122", "otp_context_before"),
    ("OT04", "OTP", "482913은 인증번호입니다", "482913", "otp_context_after"),
    ("OT05", "OTP", "12345678 is your one-time password", "12345678", "otp_context_after"),
    ("GK01", "API_KEY", '{"apiKey":"AbCDef1234567890xyz"}', "AbCDef1234567890xyz", "generic_api_key"),
    ("GK02", "API_KEY", "Ocp-Apim-Subscription-Key: Az9xY8wV7uT6sR5qP4nM3kL2", "Az9xY8wV7uT6sR5qP4nM3kL2", "generic_api_key"),
    ("GK03", "API_KEY", "웹훅 시크릿: whsec_Z9y8X7w6V5u4T3s2R1q0", "whsec_Z9y8X7w6V5u4T3s2R1q0", "generic_api_key"),
    ("GK04", "API_KEY", "SvcK3y-2026-AbCdEfGh is the service key", "SvcK3y-2026-AbCdEfGh", "generic_api_key_context_after"),
    ("AT01", "AUTH_TOKEN", "Authorization: Bearer AbCdEf0123456789-token.value", "AbCdEf0123456789-token.value", "bearer_token"),
    ("AT02", "AUTH_TOKEN", "Authorization: Basic dXNlcjpTM2NyZXQh", "dXNlcjpTM2NyZXQh", "basic_auth_token"),
    ("AT03", "AUTH_TOKEN", "Authorization: Token Tok3n-Header-2026.AbCd", "Tok3n-Header-2026.AbCd", "authorization_token_scheme"),
    ("AT04", "AUTH_TOKEN", "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature123", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature123", "jwt"),
    ("AT05", "AUTH_TOKEN", '{"X-Auth-Token":"Auth-2026.AbCdEfGhIjKl"}', "Auth-2026.AbCdEfGhIjKl", "labeled_auth_token"),
    ("AT06", "AUTH_TOKEN", "Tok3n-2026.AbCdEfGhIjKl is the access token", "Tok3n-2026.AbCdEfGhIjKl", "auth_token_context_after"),
    ("PW01", "PASSWORD", '{"password":"Json!Pass-2026"}', "Json!Pass-2026", "labeled_password"),
    ("PW02", "PASSWORD", "DB_PASSWORD='Db Pass! 2026'", "Db Pass! 2026", "labeled_password"),
    ("PW03", "PASSWORD", "tool --password Cli!Pass-2026 --verbose", "Cli!Pass-2026", "password_cli_argument"),
    ("PW04", "PASSWORD", "tool --pwd \"Cli Pass! 2026\"", "Cli Pass! 2026", "password_cli_argument"),
    ("PW05", "PASSWORD", "<password>Xml!Pass-2026</password>", "Xml!Pass-2026", "password_xml_element"),
    ("PW06", "PASSWORD", "비밀번호를 입력하세요: Input!Pass-2026", "Input!Pass-2026", "password_instruction"),
    ("IA29", "INTERNAL_ACCESS", "내부 IP: 10.20.30.40", "10.20.30.40", "private_ipv4"),
    ("IA30", "INTERNAL_ACCESS", "내부 IP: fd00::10", "fd00::10", "private_ipv6"),
    ("IA31", "INTERNAL_ACCESS", "internal subnet 10.20.0.0/16", "10.20.0.0/16", "private_network"),
    ("IA32", "INTERNAL_ACCESS", "internal subnet fd00:1234::/64", "fd00:1234::/64", "private_network"),
    ("IA33", "INTERNAL_ACCESS", "DB_HOST=db01", "db01", "internal_host"),
    ("IA34", "INTERNAL_ACCESS", 'endpoint="app01.svc.cluster.local:8080"', "app01.svc.cluster.local:8080", "internal_host"),
    ("IA35", "INTERNAL_ACCESS", "socket_path=/var/run/postgresql/.s.PGSQL.5432", "/var/run/postgresql/.s.PGSQL.5432", "internal_socket_path"),
    ("IA36", "INTERNAL_ACCESS", "유닉스 소켓은 unix:/run/redis/redis.sock", "unix:/run/redis/redis.sock", "internal_socket_path"),
)


@pytest.mark.parametrize(("case_id", "out_key", "text", "value", "detected_by"), MANUAL_FAMILY_CASES)
def test_documented_pattern_families(
    sensitive_engine: PiiEngine,
    case_id: str,
    out_key: str,
    text: str,
    value: str,
    detected_by: str,
) -> None:
    del case_id
    found = sensitive_engine.detect(text, max_results_per_type=20)
    item = next(item for item in found.get(out_key, []) if item["matchString"] == value)
    assert item["detected_by"] == detected_by


MANUAL_NEGATIVE_CASES = (
    ("NG01", "OTP", "주문번호 482913"),
    ("NG02", "OTP", "OTP=123"),
    ("NG03", "OTP", "OTP=123456789"),
    ("NG04", "API_KEY", "API_KEY=AAAAAAAAAAAAAAAAAAAA"),
    ("NG05", "API_KEY", "public_key=AbCDef1234567890xyz"),
    ("NG06", "AUTH_TOKEN", "Authorization: Bearer short-token"),
    ("NG07", "AUTH_TOKEN", '{"token":"short"}'),
    ("NG08", "PASSWORD", "password policy requires 12 characters"),
    ("NG09", "PASSWORD", "--password-help shows usage"),
    ("NG10", "INTERNAL_ACCESS", "DNS server: 8.8.8.8"),
    ("NG11", "INTERNAL_ACCESS", "endpoint: https://example.com/api"),
    ("NG12", "INTERNAL_ACCESS", "public subnet 8.8.8.0/24"),
    ("NG13", "INTERNAL_ACCESS", "DB_HOST=example.com"),
)


@pytest.mark.parametrize(("case_id", "out_key", "text"), MANUAL_NEGATIVE_CASES)
def test_documented_negative_cases(
    sensitive_engine: PiiEngine,
    case_id: str,
    out_key: str,
    text: str,
) -> None:
    del case_id
    found = sensitive_engine.detect(text, max_results_per_type=20)
    assert found.get(out_key, []) == []
