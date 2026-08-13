from __future__ import annotations

import argparse
from collections import Counter
import http.client
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import sys
from typing import Any, Callable
from urllib.parse import urlsplit

import grpc

PROJECT_ROOT = str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.proto import pii_pb2, pii_pb2_grpc
from scripts.grpc_benchmark import summarize


def _load_payload(path: str) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8-sig")
    suffix = "business registration number 110-81-40818"
    return "x" * (52_042 - len(suffix) - 1) + "\n" + suffix


def _run_requests(
    call: Callable[[], tuple[bool, str]],
    requests: int,
    warmup_requests: int,
    concurrency: int,
) -> dict[str, Any]:
    for _ in range(max(0, warmup_requests)):
        success, detail = call()
        if not success:
            raise RuntimeError(f"warmup failed: {detail}")

    def measured(request_id: int) -> dict[str, Any]:
        started = time.perf_counter()
        success, detail = call()
        return {
            "request_id": request_id,
            "success": success,
            "details": detail,
            "latency_ms": (time.perf_counter() - started) * 1000.0,
        }

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(measured, index + 1) for index in range(requests)]
        rows = [future.result() for future in as_completed(futures)]
    report = summarize(rows, time.perf_counter() - started)
    report["errors_by_detail"] = dict(
        sorted(Counter(str(row.get("details") or "unknown") for row in rows if not row.get("success")).items())
    )
    return report


def benchmark_http(
    target: str,
    payload: str,
    requests: int,
    warmup_requests: int,
    concurrency: int,
    timeout: float,
) -> dict[str, Any]:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"invalid HTTP target: {target}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/pii/detect"
    body = json.dumps(
        {"text": payload, "max_results_per_type": 500},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    local = threading.local()

    def connection():
        conn = getattr(local, "connection", None)
        if conn is None:
            cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            conn = cls(parsed.hostname, port, timeout=timeout)
            local.connection = conn
        return conn

    def call() -> tuple[bool, str]:
        conn = connection()
        try:
            conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read()
            if response.status != 200:
                return False, f"HTTP {response.status}"
            data = json.loads(raw)
            brn_count = int((data.get("data") or {}).get("BRN_CNT") or 0)
            success = bool(data.get("success")) and brn_count == 1
            return success, str(data.get("status", "")) if success else f"BRN_CNT={brn_count}"
        except Exception:
            try:
                conn.close()
            finally:
                local.connection = None
            raise

    report = _run_requests(call, requests, warmup_requests, concurrency)
    return {"protocol": "http", "target": target, **report}


def benchmark_grpc(
    target: str,
    payload: str,
    requests: int,
    warmup_requests: int,
    concurrency: int,
    timeout: float,
) -> dict[str, Any]:
    local = threading.local()
    request = pii_pb2.DetectRequest(text=payload, max_results_per_type=500, ruleset="default")

    def stub():
        value = getattr(local, "stub", None)
        if value is None:
            channel = grpc.insecure_channel(target)
            local.channel = channel
            value = pii_pb2_grpc.PiiDetectorStub(channel)
            local.stub = value
        return value

    def call() -> tuple[bool, str]:
        try:
            response = stub().Detect(request, timeout=timeout)
            success = bool(response.success) and int(response.status) == 200 and int(response.data.brn_cnt) == 1
            return success, str(response.status) if success else f"BRN_CNT={response.data.brn_cnt}"
        except grpc.RpcError as exc:
            return False, f"{exc.code().name}: {exc.details() or ''}"

    report = _run_requests(call, requests, warmup_requests, concurrency)
    return {"protocol": "grpc", "target": target, **report}


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare HTTP and gRPC using one payload and persistent connections")
    parser.add_argument("--http-target", default="http://xcn-pii-api:8000/pii/detect")
    parser.add_argument("--grpc-direct-target", default="127.0.0.1:50051")
    parser.add_argument("--grpc-lb-target", default="xcn-pii-grpc-lb:50051")
    parser.add_argument("--payload-file", default="")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--warmup-requests", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if args.requests < 1 or args.concurrency < 1:
        parser.error("--requests and --concurrency must be positive")

    payload = _load_payload(args.payload_file)
    common = (payload, args.requests, args.warmup_requests, args.concurrency, args.timeout)
    reports = [benchmark_http(args.http_target, *common)]
    if args.grpc_direct_target:
        reports.append(benchmark_grpc(args.grpc_direct_target, *common))
    if args.grpc_lb_target:
        reports.append(benchmark_grpc(args.grpc_lb_target, *common))
    print(
        json.dumps(
            {
                "payload_chars": len(payload),
                "requests_per_target": args.requests,
                "warmup_requests_per_target": args.warmup_requests,
                "concurrency": args.concurrency,
                "reports": reports,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if any(report["errors"] for report in reports):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
