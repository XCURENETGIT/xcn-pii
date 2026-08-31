from __future__ import annotations

import argparse
import json
import statistics
import time

from app.pii_engine.detectors import SensitiveValueDetector
from app.pii_engine.engine import PiiEngine
from app.pii_engine.pipeline_builder import build_pipeline
from app.rules_loader import load_rules
from app.sensitive_values import (
    PHASE1_SENSITIVE_TYPES,
    SENSITIVE_RULE_TYPES,
    SensitivePatternSet,
    phase1_sensitive_syntax_possible,
    redact_sensitive_text,
)


def _measure(fn, repeats: int) -> dict[str, float]:
    samples: list[float] = []
    fn()
    for _ in range(repeats):
        started = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - started) * 1000.0)
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95) - 1))
    return {
        "median_ms": round(statistics.median(samples), 3),
        "p95_ms": round(ordered[p95_index], 3),
        "min_ms": round(min(samples), 3),
        "max_ms": round(max(samples), 3),
    }


def _measure_pair(baseline_fn, candidate_fn, repeats: int) -> tuple[dict[str, float], dict[str, float]]:
    baseline_fn()
    candidate_fn()
    baseline_samples: list[float] = []
    candidate_samples: list[float] = []
    for index in range(repeats):
        ordered = (
            ((baseline_fn, baseline_samples), (candidate_fn, candidate_samples))
            if index % 2 == 0
            else ((candidate_fn, candidate_samples), (baseline_fn, baseline_samples))
        )
        for fn, samples in ordered:
            started = time.perf_counter()
            fn()
            samples.append((time.perf_counter() - started) * 1000.0)

    def summarize(samples: list[float]) -> dict[str, float]:
        values = sorted(samples)
        p95_index = min(len(values) - 1, max(0, int(len(values) * 0.95) - 1))
        return {
            "median_ms": round(statistics.median(samples), 3),
            "p95_ms": round(values[p95_index], 3),
            "min_ms": round(min(samples), 3),
            "max_ms": round(max(samples), 3),
        }

    return summarize(baseline_samples), summarize(candidate_samples)


def _scan_pattern_sets(text: str, pattern_sets: list[SensitivePatternSet]) -> None:
    lowered = text.lower()
    phase1_possible = phase1_sensitive_syntax_possible(text)
    for pattern_set in pattern_sets:
        if pattern_set.out_key in PHASE1_SENSITIVE_TYPES and not phase1_possible:
            continue
        pattern_set.find(text, max_results=20, lowered_text=lowered)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark sensitive detectors on a clean payload")
    parser.add_argument("--chars", type=int, default=1_000_000)
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--max-detect-median-ms", type=float, default=0.0, help="Optional absolute limit; 0 disables it")
    parser.add_argument("--max-redact-median-ms", type=float, default=0.0, help="Optional absolute limit; 0 disables it")
    parser.add_argument("--max-added-overhead-percent", type=float, default=10.0)
    parser.add_argument("--max-config-added-overhead-percent", type=float, default=25.0)
    args = parser.parse_args()

    unit = "일반 문서의 공개 내용과 처리 절차를 설명하는 중립 문장입니다. "
    text = (unit * ((args.chars // len(unit)) + 1))[: args.chars]
    config_unit = "timestamp=2026-08-27T12:00:00 level=INFO session_mode=public token_count=0 endpoint=https://example.com/public status=200\n"
    config_text = (config_unit * ((args.chars // len(config_unit)) + 1))[: args.chars]
    bundle = load_rules()
    sensitive_pipeline = [step for step in build_pipeline(bundle) if isinstance(step, SensitiveValueDetector)]
    engine = PiiEngine(bundle, sensitive_pipeline)
    baseline_keys = {"OTP", "API_KEY", "AUTH_TOKEN", "PASSWORD", "INTERNAL_ACCESS"}
    baseline_pipeline = [step for step in sensitive_pipeline if step.out_key in baseline_keys]
    baseline_engine = PiiEngine(bundle, baseline_pipeline)
    pattern_sets = [SensitivePatternSet(out_key, bundle.rule_docs[out_key.lower()]) for out_key, _ in SENSITIVE_RULE_TYPES]
    baseline_pattern_sets = [pattern_set for pattern_set in pattern_sets if pattern_set.out_key in baseline_keys]

    baseline_report, detect_report = _measure_pair(
        lambda: baseline_engine.detect(text, max_results_per_type=20),
        lambda: engine.detect(text, max_results_per_type=20),
        args.repeats,
    )
    added_overhead_percent = round(
        max(0.0, detect_report["median_ms"] - baseline_report["median_ms"])
        / max(0.001, baseline_report["median_ms"])
        * 100.0,
        3,
    )
    config_baseline_report, config_detect_report = _measure_pair(
        lambda: baseline_engine.detect(config_text, max_results_per_type=20),
        lambda: engine.detect(config_text, max_results_per_type=20),
        args.repeats,
    )
    config_added_overhead_percent = round(
        max(0.0, config_detect_report["median_ms"] - config_baseline_report["median_ms"])
        / max(0.001, config_baseline_report["median_ms"])
        * 100.0,
        3,
    )
    redact_baseline_report, redact_scan_report = _measure_pair(
        lambda: _scan_pattern_sets(text, baseline_pattern_sets),
        lambda: _scan_pattern_sets(text, pattern_sets),
        args.repeats,
    )
    redact_added_overhead_percent = round(
        max(0.0, redact_scan_report["median_ms"] - redact_baseline_report["median_ms"])
        / max(0.001, redact_baseline_report["median_ms"])
        * 100.0,
        3,
    )
    config_redact_baseline_report, config_redact_scan_report = _measure_pair(
        lambda: _scan_pattern_sets(config_text, baseline_pattern_sets),
        lambda: _scan_pattern_sets(config_text, pattern_sets),
        args.repeats,
    )
    config_redact_added_overhead_percent = round(
        max(0.0, config_redact_scan_report["median_ms"] - config_redact_baseline_report["median_ms"])
        / max(0.001, config_redact_baseline_report["median_ms"])
        * 100.0,
        3,
    )

    report = {
        "chars": len(text),
        "repeats": args.repeats,
        "detector_count": len(sensitive_pipeline),
        "baseline_detector_count": len(baseline_pipeline),
        "baseline_detect": baseline_report,
        "detect": detect_report,
        "added_overhead_percent": added_overhead_percent,
        "redaction_scan_baseline": redact_baseline_report,
        "redaction_scan": redact_scan_report,
        "redaction_added_overhead_percent": redact_added_overhead_percent,
        "redact": _measure(lambda: redact_sensitive_text(text), args.repeats),
        "config_like": {
            "baseline_detect": config_baseline_report,
            "detect": config_detect_report,
            "added_overhead_percent": config_added_overhead_percent,
            "redaction_scan_baseline": config_redact_baseline_report,
            "redaction_scan": config_redact_scan_report,
            "redaction_added_overhead_percent": config_redact_added_overhead_percent,
            "redact": _measure(lambda: redact_sensitive_text(config_text), args.repeats),
        },
        "limits": {
            "detect_median_ms": args.max_detect_median_ms,
            "redact_median_ms": args.max_redact_median_ms,
            "added_overhead_percent": args.max_added_overhead_percent,
            "config_added_overhead_percent": args.max_config_added_overhead_percent,
        },
    }
    report["passed"] = bool(
        report["added_overhead_percent"] <= args.max_added_overhead_percent
        and report["redaction_added_overhead_percent"] <= args.max_added_overhead_percent
        and report["config_like"]["added_overhead_percent"] <= args.max_config_added_overhead_percent
        and report["config_like"]["redaction_added_overhead_percent"] <= args.max_config_added_overhead_percent
        and (args.max_detect_median_ms <= 0 or report["detect"]["median_ms"] <= args.max_detect_median_ms)
        and (args.max_detect_median_ms <= 0 or report["config_like"]["detect"]["median_ms"] <= args.max_detect_median_ms)
        and (args.max_redact_median_ms <= 0 or report["redact"]["median_ms"] <= args.max_redact_median_ms)
        and (args.max_redact_median_ms <= 0 or report["config_like"]["redact"]["median_ms"] <= args.max_redact_median_ms)
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
