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
    Case("R01", "기존 MN 연락처 회귀", "연락처: 010-1234-5678", {"MN": ("010-1234-5678",)}),
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
    parser.add_argument("--grpc-target", default="127.0.0.1:150051")
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
