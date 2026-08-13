from __future__ import annotations

import argparse
import csv
import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import sys
from typing import Any

import grpc


PROJECT_ROOT = str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.proto import pii_pb2, pii_pb2_grpc  # noqa: E402


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    rank = max(0.0, min(1.0, float(q))) * (len(ordered) - 1)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return ordered[lower]
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def summarize(results: list[dict[str, Any]], wall_seconds: float) -> dict[str, Any]:
    successful = [row for row in results if row.get("success")]
    latencies = [float(row["latency_ms"]) for row in successful]
    total = len(results)
    success_count = len(successful)
    return {
        "requests": total,
        "successes": success_count,
        "errors": total - success_count,
        "error_rate": round((total - success_count) / total, 6) if total else 0.0,
        "wall_seconds": round(max(0.0, wall_seconds), 3),
        "rps": round(success_count / wall_seconds, 3) if wall_seconds > 0 else 0.0,
        "latency_ms": {
            "min": round(min(latencies), 3) if latencies else 0.0,
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "grpc_errors": dict(
            sorted(
                {
                    code: sum(1 for row in results if row.get("grpc_code") == code)
                    for code in {str(row.get("grpc_code")) for row in results if row.get("grpc_code")}
                }.items()
            )
        ),
    }


def _detect_once(stub, request, timeout: float, request_id: int) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        response = stub.Detect(request, timeout=timeout)
        return {
            "request_id": request_id,
            "success": bool(response.success) and int(response.status) == 200,
            "status": int(response.status),
            "latency_ms": (time.perf_counter() - started) * 1000.0,
        }
    except grpc.RpcError as exc:
        return {
            "request_id": request_id,
            "success": False,
            "grpc_code": exc.code().name,
            "details": exc.details() or "",
            "latency_ms": (time.perf_counter() - started) * 1000.0,
        }


def _write_csv(path: str, results: list[dict[str, Any]]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    columns = ["request_id", "success", "status", "grpc_code", "details", "latency_ms"]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in sorted(results, key=lambda item: int(item.get("request_id", 0))):
            writer.writerow({key: row.get(key) for key in columns})


def _load_payload(args) -> str:
    if args.payload_file:
        return Path(args.payload_file).read_text(encoding="utf-8-sig")
    if args.payload_text:
        return args.payload_text
    return "주민등록번호 890512-2054508"


def main() -> None:
    parser = argparse.ArgumentParser(description="Concurrent gRPC PII detector benchmark")
    parser.add_argument("--target", default="127.0.0.1:50055")
    parser.add_argument("--requests", type=int, default=500, help="Total requests; use -1 with --duration-sec")
    parser.add_argument("--duration-sec", type=float, default=0.0)
    parser.add_argument("--warmup-requests", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--channels", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--payload-file", default="")
    parser.add_argument("--payload-text", default="")
    parser.add_argument("--ruleset", default="default")
    parser.add_argument("--max-results", type=int, default=500)
    parser.add_argument("--out-csv", default="")
    args = parser.parse_args()

    if args.concurrency < 1 or args.channels < 1:
        parser.error("--concurrency and --channels must be positive")
    if args.requests < 0 and args.duration_sec <= 0:
        parser.error("--requests -1 requires a positive --duration-sec")
    if args.requests == 0:
        parser.error("--requests must be positive or -1")

    payload = _load_payload(args)
    request = pii_pb2.DetectRequest(
        text=payload,
        max_results_per_type=max(1, int(args.max_results)),
        ruleset=args.ruleset,
    )
    channel_count = min(max(1, int(args.channels)), max(1, int(args.concurrency)))
    channels = [grpc.insecure_channel(args.target) for _ in range(channel_count)]
    stubs = [pii_pb2_grpc.PiiDetectorStub(channel) for channel in channels]

    try:
        for index in range(max(0, int(args.warmup_requests))):
            warmup = _detect_once(stubs[index % len(stubs)], request, args.timeout, -(index + 1))
            if not warmup.get("success"):
                raise RuntimeError(f"warmup failed: {warmup}")

        results: list[dict[str, Any]] = []
        started = time.perf_counter()
        if args.requests > 0:
            with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                futures = [
                    executor.submit(
                        _detect_once,
                        stubs[index % len(stubs)],
                        request,
                        args.timeout,
                        index + 1,
                    )
                    for index in range(args.requests)
                ]
                results = [future.result() for future in as_completed(futures)]
        else:
            deadline = started + float(args.duration_sec)
            counter = 0
            counter_lock = threading.Lock()

            def run_until_deadline(worker_index: int) -> list[dict[str, Any]]:
                nonlocal counter
                worker_results: list[dict[str, Any]] = []
                while time.perf_counter() < deadline:
                    with counter_lock:
                        counter += 1
                        request_id = counter
                    worker_results.append(
                        _detect_once(
                            stubs[worker_index % len(stubs)],
                            request,
                            args.timeout,
                            request_id,
                        )
                    )
                return worker_results

            with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                futures = [executor.submit(run_until_deadline, index) for index in range(args.concurrency)]
                for future in as_completed(futures):
                    results.extend(future.result())

        wall_seconds = time.perf_counter() - started
    finally:
        for channel in channels:
            channel.close()

    report = {
        "target": args.target,
        "payload_chars": len(payload),
        "concurrency": args.concurrency,
        "channels": channel_count,
        "warmup_requests": max(0, int(args.warmup_requests)),
        "ruleset": args.ruleset,
        **summarize(results, wall_seconds),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.out_csv:
        _write_csv(args.out_csv, results)

    if report["errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
