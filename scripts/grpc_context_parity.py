from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import grpc

from app.proto import pii_pb2, pii_pb2_grpc


def _cases() -> list[tuple[str, str]]:
    base = [
        ("sn_label", "주민등록번호 890512-2054508"),
        ("sn_document", "문서번호 890512-2054508"),
        ("sn_customer", "고객번호 890512-2054508"),
        ("sn_force", "등본 발급 대상 890512-2054508"),
        ("fn_label", "외국인등록번호 900101-5123456"),
        ("mobile_label", "휴대전화 010-1234-5678"),
        ("business_label", "사업자등록번호 123-45-67890"),
        ("card_label", "카드번호 4111-1111-1111-1111"),
        ("email_label", "이메일 user123@example.com"),
        ("passport_label", "여권번호 M12345678"),
        ("vn_cccd", "số căn cước công dân 001203004567"),
        ("vn_mobile", "số điện thoại 0912345678"),
        ("vn_tax", "mã số thuế 0312345678"),
        ("mixed_numbers", "주문 20260724 고객 123456 주민등록번호 890512-2054508 문서 998877"),
    ]
    repeated = "\n".join(
        f"고객 {index:06d} 주민등록번호 890512-{2000000 + index:07d} 문맥 행 {index:06d}"
        for index in range(1, 101)
    )
    base.append(("repeated_template", repeated))
    return base


def _detect(target: str, text: str, timeout: float):
    with grpc.insecure_channel(target) as channel:
        return pii_pb2_grpc.PiiDetectorStub(channel).Detect(
            pii_pb2.DetectRequest(text=text, max_results_per_type=500, ruleset="default"),
            timeout=timeout,
        )


def _snapshot(response) -> tuple[dict[str, list[tuple[Any, ...]]], dict[tuple[Any, ...], float]]:
    items_by_type: dict[str, list[tuple[Any, ...]]] = {}
    scores: dict[tuple[Any, ...], float] = {}
    for field in response.data.DESCRIPTOR.fields:
        if field.label != field.LABEL_REPEATED or field.message_type is None:
            continue
        values = getattr(response.data, field.name)
        rows = []
        for item in values:
            identity = (
                field.name,
                int(item.start),
                int(item.end),
                str(item.match_string),
                bool(item.is_valid),
                str(item.context_method),
                str(item.context_accept_by),
                bool(item.context_pass),
                str(item.detected_by),
            )
            rows.append(identity[1:])
            scores[identity] = float(item.context_score)
        if rows:
            items_by_type[field.name] = sorted(rows)
    return items_by_type, scores


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--input-file", action="append", default=[])
    args = parser.parse_args()

    cases = _cases()
    for input_file in args.input_file:
        path = Path(input_file)
        cases.append((f"file:{path.name}", path.read_text(encoding="utf-8")))

    mismatches = []
    max_score_delta = 0.0
    for name, text in cases:
        baseline = _detect(args.baseline, text, args.timeout)
        candidate = _detect(args.candidate, text, args.timeout)
        baseline_items, baseline_scores = _snapshot(baseline)
        candidate_items, candidate_scores = _snapshot(candidate)
        if baseline_items != candidate_items:
            mismatches.append(
                {
                    "case": name,
                    "baseline": baseline_items,
                    "candidate": candidate_items,
                }
            )
            continue
        for identity, score in baseline_scores.items():
            max_score_delta = max(max_score_delta, abs(score - candidate_scores.get(identity, score)))

    print(
        json.dumps(
            {
                "cases": len(cases),
                "mismatch_count": len(mismatches),
                "max_context_score_delta": round(max_score_delta, 6),
                "mismatches": mismatches,
            },
            ensure_ascii=False,
        )
    )
    raise SystemExit(1 if mismatches else 0)


if __name__ == "__main__":
    main()
