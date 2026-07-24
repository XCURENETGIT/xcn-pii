from __future__ import annotations

import argparse
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import grpc

from app.proto import pii_pb2, pii_pb2_grpc


def _alpha_token(index: int) -> str:
    value = max(1, int(index))
    chars = []
    while value:
        value, remainder = divmod(value - 1, 26)
        chars.append(chr(ord("a") + remainder))
    return "".join(reversed(chars))


def _row_marker(index: int, unique_text: bool) -> str:
    return _alpha_token(index) if unique_text else f"{index:06d}"


def build_payload(rows: int, force_pass: bool, unique_text: bool) -> str:
    prefix = "등본 " if force_pass else ""
    return "".join(
        f"고객 {index:06d} {prefix}주민등록번호 890512-2054508 문맥 행 "
        f"{_row_marker(index, unique_text)}\n"
        for index in range(1, rows + 1)
    )


def detect_once(target: str, request: pii_pb2.DetectRequest, timeout: float) -> dict:
    started_at = time.perf_counter()
    try:
        with grpc.insecure_channel(target) as channel:
            response = pii_pb2_grpc.PiiDetectorStub(channel).Detect(request, timeout=timeout)
        return {
            "elapsed_ms": round((time.perf_counter() - started_at) * 1000.0, 1),
            "success": bool(response.success),
            "status": int(response.status),
            "sn_count": int(response.data.sn_cnt),
            "accept_by": sorted({str(item.context_accept_by) for item in response.data.sn}),
        }
    except grpc.RpcError as exc:
        return {
            "elapsed_ms": round((time.perf_counter() - started_at) * 1000.0, 1),
            "success": False,
            "grpc_code": exc.code().name,
            "details": exc.details(),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--rows", type=int, default=300)
    parser.add_argument("--force-pass", action="store_true")
    parser.add_argument("--unique-text", action="store_true")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    text = build_payload(args.rows, args.force_pass, args.unique_text)
    request = pii_pb2.DetectRequest(text=text, max_results_per_type=500, ruleset="default")
    total_calls = args.concurrency * args.repeat
    started_at = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(detect_once, args.target, request, args.timeout)
            for _ in range(total_calls)
        ]
        results = [future.result() for future in as_completed(futures)]
    wall_ms = (time.perf_counter() - started_at) * 1000.0
    elapsed = [float(item["elapsed_ms"]) for item in results]
    print(
        json.dumps(
            {
                "chars": len(text),
                "rows": args.rows,
                "force_pass": args.force_pass,
                "unique_text": args.unique_text,
                "concurrency": args.concurrency,
                "calls": total_calls,
                "wall_ms": round(wall_ms, 1),
                "min_ms": round(min(elapsed), 1),
                "median_ms": round(statistics.median(elapsed), 1),
                "max_ms": round(max(elapsed), 1),
                "successes": sum(1 for item in results if item.get("success")),
                "sample": results[0],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
