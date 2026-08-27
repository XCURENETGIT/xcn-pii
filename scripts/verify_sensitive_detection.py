#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


SENSITIVE_TYPES = ("OTP", "API_KEY", "AUTH_TOKEN", "PASSWORD", "INTERNAL_ACCESS")
TYPE_FIELDS = {
    "OTP": ("OTP_CNT", "OTP", "otp_cnt", "otp"),
    "API_KEY": ("API_KEY_CNT", "API_KEY", "api_key_cnt", "api_key"),
    "AUTH_TOKEN": ("AUTH_TOKEN_CNT", "AUTH_TOKEN", "auth_token_cnt", "auth_token"),
    "PASSWORD": ("PASSWORD_CNT", "PASSWORD", "password_cnt", "password"),
    "INTERNAL_ACCESS": (
        "INTERNAL_ACCESS_CNT",
        "INTERNAL_ACCESS",
        "internal_access_cnt",
        "internal_access",
    ),
    "MN": ("MN_CNT", "MN", "mn_cnt", "mn"),
}


@dataclass(frozen=True)
class Case:
    case_id: str
    description: str
    text: str
    expected: dict[str, tuple[str, ...]] = field(default_factory=dict)
    absent: tuple[str, ...] = ()
    exact: tuple[str, ...] = ()


CASES = (
    Case("P01", "한국어 OTP", "인증번호: 482913", {"OTP": ("482913",)}),
    Case("P02", "영문 verification code", "Your verification code is 847201", {"OTP": ("847201",)}),
    Case("P03", "OTP 최소 길이 4", "OTP=1234", {"OTP": ("1234",)}),
    Case("P04", "OTP 최대 길이 8", "OTP=12345678", {"OTP": ("12345678",)}),
    Case("P05", "AWS Access Key 형식", "AWS key AKIAIOSFODNN7EXAMPLE", {"API_KEY": ("AKIAIOSFODNN7EXAMPLE",)}),
    Case("P06", "일반 API Key 라벨과 엔트로피", "API_KEY=abcDEF1234567890xyz", {"API_KEY": ("abcDEF1234567890xyz",)}),
    Case(
        "P07",
        "GitHub token 형식",
        "token ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        {"API_KEY": ("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",)},
    ),
    Case(
        "P08",
        "Bearer token",
        "Authorization: Bearer AbCdEf0123456789-token.value",
        {"AUTH_TOKEN": ("AbCdEf0123456789-token.value",)},
    ),
    Case(
        "P09",
        "JWT 구조",
        "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature123",
        {"AUTH_TOKEN": ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature123",)},
    ),
    Case(
        "P10",
        "명시적 refresh token",
        "refresh_token=ZXhhbXBsZS1yZWZyZXNoLXRva2VuLTIwMjY",
        {"AUTH_TOKEN": ("ZXhhbXBsZS1yZWZyZXNoLXRva2VuLTIwMjY",)},
    ),
    Case(
        "P10B",
        "Basic 인증 값",
        "Authorization: Basic dXNlcjpTM2NyZXQh",
        {"AUTH_TOKEN": ("dXNlcjpTM2NyZXQh",)},
    ),
    Case("P11", "한국어 비밀번호", "비밀번호: S3cure!Pass#2026", {"PASSWORD": ("S3cure!Pass#2026",)}),
    Case(
        "P12",
        "공백 포함 따옴표 비밀번호",
        'password="correct horse battery staple"',
        {"PASSWORD": ("correct horse battery staple",)},
    ),
    Case("P13", "사설 IPv4", "내부 IP: 10.20.30.40", {"INTERNAL_ACCESS": ("10.20.30.40",)}),
    Case(
        "P14",
        "내부 접속 URL",
        "접속주소 postgresql://svc:secret@db01.internal:5432/app",
        {"INTERNAL_ACCESS": ("postgresql://svc:secret@db01.internal:5432/app",)},
    ),
    Case("P15", "내부 호스트와 포트", "호스트: db01.internal:5432", {"INTERNAL_ACCESS": ("db01.internal:5432",)}),
    Case("P15B", "loopback IPv6", "내부 IP: ::1", {"INTERNAL_ACCESS": ("::1",)}),
    Case(
        "P16",
        "신규 타입 혼합 입력",
        "인증번호: 482913\nAPI_KEY=abcDEF1234567890xyz\n"
        "Authorization: Bearer AbCdEf0123456789-token.value\n"
        "비밀번호: S3cure!Pass#2026\n내부 IP: 192.168.10.20",
        {
            "OTP": ("482913",),
            "API_KEY": ("abcDEF1234567890xyz",),
            "AUTH_TOKEN": ("AbCdEf0123456789-token.value",),
            "PASSWORD": ("S3cure!Pass#2026",),
            "INTERNAL_ACCESS": ("192.168.10.20",),
        },
    ),
    Case("C01", "MFA code 문맥", "MFA code: 739201", {"OTP": ("739201",)}),
    Case("C02", "2FA PIN 환경변수", "2FA_PIN=884422", {"OTP": ("884422",)}),
    Case("C03", "본인확인 코드 괄호 표기", "본인확인 코드 [551122]", {"OTP": ("551122",)}),
    Case("C04", "값 앞 영문 OTP 문장", "739201 is your verification code", {"OTP": ("739201",)}),
    Case("C05", "값 앞 한국어 OTP 문장", "482913은 인증번호입니다", {"OTP": ("482913",)}),
    Case("C06", "로그인 코드 조사 문맥", "로그인 코드는 663311", {"OTP": ("663311",)}),
    Case("C07", "JSON camelCase API Key", '{"apiKey":"AbCDef1234567890xyz"}', {"API_KEY": ("AbCDef1234567890xyz",)}),
    Case(
        "C08",
        "Azure APIM subscription key header",
        "Ocp-Apim-Subscription-Key: Az9xY8wV7uT6sR5qP4nM3kL2",
        {"API_KEY": ("Az9xY8wV7uT6sR5qP4nM3kL2",)},
    ),
    Case("C09", "client_secret 설정", "client_secret = Cl13nt.S3cret-2026-Prod", {"API_KEY": ("Cl13nt.S3cret-2026-Prod",)}),
    Case("C10", "한국어 webhook secret", "웹훅 시크릿: whsec_Z9y8X7w6V5u4T3s2R1q0", {"API_KEY": ("whsec_Z9y8X7w6V5u4T3s2R1q0",)}),
    Case("C11", "Hugging Face token 형식", "Hugging Face token hf_abcdefghijklmnopqrstuvwxyzABCDEFGH", {"API_KEY": ("hf_abcdefghijklmnopqrstuvwxyzABCDEFGH",)}),
    Case("C12", "GitLab token 형식", "GitLab token glpat-AbCdEfGhIjKlMnOpQrStUvWx", {"API_KEY": ("glpat-AbCdEfGhIjKlMnOpQrStUvWx",)}),
    Case("C13", "값 앞 service key 문장", "SvcK3y-2026-AbCdEfGh is the service key", {"API_KEY": ("SvcK3y-2026-AbCdEfGh",)}),
    Case("C14", "JSON X-Auth-Token", '{"X-Auth-Token":"Auth-2026.AbCdEfGhIjKl"}', {"AUTH_TOKEN": ("Auth-2026.AbCdEfGhIjKl",)}),
    Case("C15", "session_token 설정", "session_token=Sess-2026-AbCdEfGhIjKl", {"AUTH_TOKEN": ("Sess-2026-AbCdEfGhIjKl",)}),
    Case("C16", "camelCase CSRF token", "csrfToken: a1b2c3d4e5f60718293a4b5c6d7e8f90", {"AUTH_TOKEN": ("a1b2c3d4e5f60718293a4b5c6d7e8f90",)}),
    Case("C17", "값 앞 access token 문장", "Tok3n-2026.AbCdEfGhIjKl is the access token", {"AUTH_TOKEN": ("Tok3n-2026.AbCdEfGhIjKl",)}),
    Case("C18", "Authorization Token scheme", "Authorization: Token Tok3n-Header-2026.AbCd", {"AUTH_TOKEN": ("Tok3n-Header-2026.AbCd",)}),
    Case("C19", "한국어 세션 토큰", "세션 토큰은 Sess-KR-2026.AbCdEfGh", {"AUTH_TOKEN": ("Sess-KR-2026.AbCdEfGh",)}),
    Case("C20", "JSON password", '{"password":"Json!Pass-2026"}', {"PASSWORD": ("Json!Pass-2026",)}),
    Case("C21", "DB_PASSWORD 환경변수", "DB_PASSWORD=Db!Pass-2026", {"PASSWORD": ("Db!Pass-2026",)}),
    Case("C22", "영문 password is 문장", "The admin password is Adm1n!Pass-2026", {"PASSWORD": ("Adm1n!Pass-2026",)}),
    Case("C23", "CLI password 인수", "tool --password Cli!Pass-2026 --verbose", {"PASSWORD": ("Cli!Pass-2026",)}),
    Case("C24", "XML password 요소", "<password>Xml!Pass-2026</password>", {"PASSWORD": ("Xml!Pass-2026",)}),
    Case("C25", "한국어 초기 비밀번호", "초기 비밀번호는 Init!Pass-2026", {"PASSWORD": ("Init!Pass-2026",)}),
    Case("C26", "한국어 비밀번호 입력 지시", "비밀번호를 입력하세요: Input!Pass-2026", {"PASSWORD": ("Input!Pass-2026",)}),
    Case("C27", "JSON Kubernetes hostname", '{"hostname":"app01.svc.cluster.local"}', {"INTERNAL_ACCESS": ("app01.svc.cluster.local",)}),
    Case("C28", "DB_HOST 단일 호스트", "DB_HOST=db01", {"INTERNAL_ACCESS": ("db01",)}),
    Case("C29", "한국어 운영 DB 주소", "운영 DB 주소는 10.0.20.15", {"INTERNAL_ACCESS": ("10.0.20.15",)}),
    Case("C30", "bastion host와 포트", "bastion_host=jump01.corp:22", {"INTERNAL_ACCESS": ("jump01.corp:22",)}),
    Case("C31", "JDBC PostgreSQL URL", "jdbc:postgresql://db01.internal:5432/app", {"INTERNAL_ACCESS": ("jdbc:postgresql://db01.internal:5432/app",)}),
    Case("C32", "Redis 내부 URL", "redis://cache01:6379/0", {"INTERNAL_ACCESS": ("redis://cache01:6379/0",)}),
    Case("C33", "사설 CIDR", "internal subnet 10.20.0.0/16", {"INTERNAL_ACCESS": ("10.20.0.0/16",)}),
    Case("C34", "Unix socket path", "socket_path=/var/run/postgresql/.s.PGSQL.5432", {"INTERNAL_ACCESS": ("/var/run/postgresql/.s.PGSQL.5432",)}),
    Case("C35", "Kafka broker 환경변수", "KAFKA_BROKER=kafka01.svc:9092", {"INTERNAL_ACCESS": ("kafka01.svc:9092",)}),
    Case("C36", "따옴표 내부 endpoint URL", 'endpoint="http://api01.internal/v1"', {"INTERNAL_ACCESS": ("http://api01.internal/v1",)}),
    Case("C37", "한국어 VPN 서버 주소", "VPN 서버 주소: vpn-gw", {"INTERNAL_ACCESS": ("vpn-gw",)}),
    Case("R01", "기존 MN 연락처 회귀", "연락처: 010-1234-5678", {"MN": ("010-1234-5678",)}),
    Case("R02", "허용되는 MN 연락처 대조군", "연락처: 010-2234-5678", {"MN": ("010-2234-5678",)}),
    Case("N01", "라벨 없는 6자리 숫자", "주문번호 482913", absent=("OTP",)),
    Case("N02", "OTP 최소 길이 미만", "OTP=123", absent=("OTP",)),
    Case("N03", "OTP 최대 길이 초과", "OTP=123456789", absent=("OTP",)),
    Case("N04", "저엔트로피 일반 API Key", "API_KEY=AAAAAAAAAAAAAAAAAAAA", absent=("API_KEY",)),
    Case("N05", "비밀번호 정책 설명 문장", "password policy requires 12 characters", absent=("PASSWORD",)),
    Case("N06", "공인 IPv4 제외", "DNS server: 8.8.8.8", absent=("INTERNAL_ACCESS",)),
    Case("N07", "외부 공개 URL 제외", "endpoint: https://example.com/api", absent=("INTERNAL_ACCESS",)),
    Case("N08", "너무 짧은 Bearer 값", "Authorization: Bearer short-token", absent=("AUTH_TOKEN",)),
    Case("N09", "라벨 없는 임의 문자열", "abcDEF1234567890xyz", absent=("API_KEY",)),
    Case("N10", "유효하지 않은 IPv4", "내부 IP: 999.999.999.999", absent=("INTERNAL_ACCESS",)),
    Case("N11", "공인 IPv6 제외", "DNS: 2001:4860:4860::8888", absent=("INTERNAL_ACCESS",)),
    Case("NC01", "MFA 정책 설명", "MFA rollout requires a six digit code", absent=("OTP",)),
    Case("NC02", "verification code 길이 설명", "verification code length is 6", absent=("OTP",)),
    Case("NC03", "짧은 JSON API Key", '{"apiKey":"short"}', absent=("API_KEY",)),
    Case("NC04", "public_key 분류 제외", "public_key=AbCDef1234567890xyz", absent=("API_KEY",)),
    Case("NC05", "client secret 정책 설명", "client secret rotation policy", absent=("API_KEY",)),
    Case("NC06", "짧은 JSON token", '{"token":"short"}', absent=("AUTH_TOKEN",)),
    Case("NC07", "token 문서 설명", "token validation documentation", absent=("AUTH_TOKEN",)),
    Case("NC08", "CLI password help 옵션", "--password-help shows usage", absent=("PASSWORD",)),
    Case("NC09", "빈 JSON password", '{"password":""}', absent=("PASSWORD",)),
    Case("NC10", "공개 JSON host", '{"host":"api.example.com"}', absent=("INTERNAL_ACCESS",)),
    Case("NC11", "공개 DB_HOST", "DB_HOST=example.com", absent=("INTERNAL_ACCESS",)),
    Case("NC12", "공인 CIDR", "public subnet 8.8.8.0/24", absent=("INTERNAL_ACCESS",)),
    Case("NC13", "공개 endpoint URL", "endpoint=https://example.com/api", absent=("INTERNAL_ACCESS",)),
    Case("NC14", "socket 문서 설명", "socket documentation at /docs/socket", absent=("INTERNAL_ACCESS",)),
    Case(
        "NC15",
        "OTP 라벨 앞 날짜 오탐 방지",
        "CTXLOG_HTTP_20260827 MFA code: 739201",
        {"OTP": ("739201",)},
        exact=("OTP",),
    ),
)


def _http_detect(base_url: str, case: Case, ruleset: str, timeout: float) -> dict[str, Any]:
    body = json.dumps({"text": case.text, "max_results_per_type": 100}, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/pii/detect",
        data=body,
        headers={"Content-Type": "application/json", "X-PII-RULESET": ruleset},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    if not payload.get("success"):
        raise RuntimeError(f"unsuccessful HTTP response: {payload}")
    return payload.get("data") or {}


def _grpc_client(target: str) -> tuple[Any, Callable[[Case, str, float], dict[str, Any]]]:
    import grpc
    from app.proto import pii_pb2, pii_pb2_grpc

    channel = grpc.insecure_channel(target)
    stub = pii_pb2_grpc.PiiDetectorStub(channel)

    def detect(case: Case, ruleset: str, timeout: float) -> dict[str, Any]:
        response = stub.Detect(
            pii_pb2.DetectRequest(text=case.text, max_results_per_type=100, ruleset=ruleset),
            timeout=timeout,
        )
        if not response.success:
            raise RuntimeError(f"unsuccessful gRPC response: status={response.status} message={response.message}")
        data: dict[str, Any] = {}
        for out_type, (_, _, count_field, list_field) in TYPE_FIELDS.items():
            items = []
            for item in getattr(response.data, list_field):
                items.append(
                    {
                        "start": item.start,
                        "end": item.end,
                        "matchString": item.match_string,
                        "detected_by": item.detected_by,
                    }
                )
            data[out_type] = items
            data[f"{out_type}_COUNT"] = getattr(response.data, count_field)
        return data

    return channel, detect


def _normalize(data: dict[str, Any], protocol: str) -> dict[str, list[dict[str, Any]]]:
    normalized: dict[str, list[dict[str, Any]]] = {}
    for out_type, (http_count, http_list, _, _) in TYPE_FIELDS.items():
        if protocol == "http":
            items = list(data.get(http_list) or [])
            count = int(data.get(http_count) or 0)
        else:
            items = list(data.get(out_type) or [])
            count = int(data.get(f"{out_type}_COUNT") or 0)
        if count != len(items):
            raise AssertionError(f"{out_type} count={count}, items={len(items)}")
        normalized[out_type] = items
    return normalized


def _evaluate(case: Case, actual: dict[str, list[dict[str, Any]]]) -> list[str]:
    errors: list[str] = []
    for out_type, expected_values in case.expected.items():
        items = actual.get(out_type, [])
        values = [str(item.get("matchString") or "") for item in items]
        for expected in expected_values:
            if expected not in values:
                errors.append(f"{out_type}: expected {expected!r}, actual={values!r}")
                continue
            for item in items:
                if item.get("matchString") != expected:
                    continue
                start, end = int(item.get("start", -1)), int(item.get("end", -1))
                if start < 0 or end <= start or case.text[start:end] != expected:
                    errors.append(f"{out_type}: invalid offsets start={start} end={end} value={expected!r}")
                break
    for out_type in case.exact:
        expected_values = list(case.expected.get(out_type) or ())
        actual_values = [str(item.get("matchString") or "") for item in actual.get(out_type, [])]
        if actual_values != expected_values:
            errors.append(f"{out_type}: expected exact {expected_values!r}, actual={actual_values!r}")
    for out_type in case.absent:
        values = [str(item.get("matchString") or "") for item in actual.get(out_type, [])]
        if values:
            errors.append(f"{out_type}: expected absent, actual={values!r}")
    return errors


def _actual_values(actual: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    return {
        out_type: [str(item.get("matchString") or "") for item in items]
        for out_type, items in actual.items()
        if items
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify xcn-pii sensitive-data detection over HTTP and gRPC")
    parser.add_argument("--http-url", default="http://127.0.0.1:18005")
    parser.add_argument("--grpc-target", default="127.0.0.1:15051")
    parser.add_argument("--protocol", choices=("http", "grpc", "both"), default="both")
    parser.add_argument("--rulesets", default="default,strict")
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    rulesets = tuple(item.strip() for item in args.rulesets.split(",") if item.strip())
    protocols = ("http", "grpc") if args.protocol == "both" else (args.protocol,)
    grpc_channel = None
    grpc_detect = None
    if "grpc" in protocols:
        grpc_channel, grpc_detect = _grpc_client(args.grpc_target)

    report: dict[str, Any] = {
        "started_at_epoch": time.time(),
        "http_url": args.http_url,
        "grpc_target": args.grpc_target,
        "protocols": protocols,
        "rulesets": rulesets,
        "case_count": len(CASES),
        "results": [],
    }
    for protocol in protocols:
        for ruleset in rulesets:
            for case in CASES:
                entry: dict[str, Any] = {
                    "protocol": protocol,
                    "ruleset": ruleset,
                    "case_id": case.case_id,
                    "description": case.description,
                    "status": "FAIL",
                    "errors": [],
                }
                try:
                    raw = (
                        _http_detect(args.http_url, case, ruleset, args.timeout)
                        if protocol == "http"
                        else grpc_detect(case, ruleset, args.timeout)  # type: ignore[misc]
                    )
                    actual = _normalize(raw, protocol)
                    entry["actual"] = _actual_values(actual)
                    entry["errors"] = _evaluate(case, actual)
                    entry["status"] = "PASS" if not entry["errors"] else "FAIL"
                except Exception as exc:
                    entry["errors"] = [f"{type(exc).__name__}: {exc}"]
                report["results"].append(entry)
                print(
                    f"[{entry['status']}] {protocol.upper():4s} {ruleset:7s} "
                    f"{case.case_id} {case.description}"
                )
                for error in entry["errors"]:
                    print(f"       {error}")

    if grpc_channel is not None:
        grpc_channel.close()
    passed = sum(item["status"] == "PASS" for item in report["results"])
    failed = len(report["results"]) - passed
    report["finished_at_epoch"] = time.time()
    report["summary"] = {"total": len(report["results"]), "passed": passed, "failed": failed}
    print(f"SUMMARY total={passed + failed} passed={passed} failed={failed}")

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"REPORT {output}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
