from __future__ import annotations

import argparse
import copy
import json
import statistics
import sys
import time
from dataclasses import replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.pii_engine.engine import PiiEngine
from app.pii_engine.detectors import BNPostFilter, MNPostFilter, NumericAlternateSeparatorDetector
from app.pii_engine.pipeline_builder import build_pipeline
from app.rules_loader import RuleBundle, load_rules


def _without_alternate_scanners(bundle: RuleBundle) -> RuleBundle:
    docs = copy.deepcopy(bundle.rule_docs)
    for key in ("mn", "bn"):
        alternate = docs.get(key, {}).get("alternate_separator")
        if isinstance(alternate, dict):
            alternate["enabled"] = False
    return replace(bundle, rule_docs=docs)


def _relevant_pipeline(bundle: RuleBundle) -> list[object]:
    """Keep the changed numeric paths and exclude unrelated context/secret work."""
    return [
        step
        for step in build_pipeline(bundle)
        if isinstance(step, (MNPostFilter, BNPostFilter, NumericAlternateSeparatorDetector))
        or getattr(step, "out_key", None) in {"MN", "BN", "CN"}
    ]


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


def _case_report(
    text: str,
    baseline_engine: PiiEngine,
    candidate_engine: PiiEngine,
    repeats: int,
) -> dict[str, object]:
    baseline, candidate = _measure_pair(
        lambda: baseline_engine.detect(text, max_results_per_type=20),
        lambda: candidate_engine.detect(text, max_results_per_type=20),
        repeats,
    )
    added_ms = round(candidate["median_ms"] - baseline["median_ms"], 3)
    added_percent = round(max(0.0, added_ms) / max(0.001, baseline["median_ms"]) * 100.0, 3)
    return {
        "chars": len(text),
        "baseline": baseline,
        "candidate": candidate,
        "added_median_ms": added_ms,
        "added_overhead_percent": added_percent,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark bounded MN/BN alternate-separator scanning")
    parser.add_argument("--chars", type=int, default=100_000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--max-added-median-ms", type=float, default=50.0)
    args = parser.parse_args()

    clean_unit = "일반 공개 문서의 처리 절차와 상태를 설명하는 중립 문장입니다. "
    noise_unit = "path=/public/v1.2/items&status=ok|count=4 `sample` owner='public'\n"
    clean_text = (clean_unit * ((args.chars // len(clean_unit)) + 1))[: args.chars]
    noise_text = (noise_unit * ((args.chars // len(noise_unit)) + 1))[: args.chars]

    candidate_bundle = load_rules(rules_dir="app/rules", ruleset_name="default")
    baseline_bundle = _without_alternate_scanners(candidate_bundle)
    baseline_pipeline = _relevant_pipeline(baseline_bundle)
    candidate_pipeline = _relevant_pipeline(candidate_bundle)
    baseline_engine = PiiEngine(baseline_bundle, baseline_pipeline)
    candidate_engine = PiiEngine(candidate_bundle, candidate_pipeline)

    cases = {
        "clean_without_labels": _case_report(clean_text, baseline_engine, candidate_engine, args.repeats),
        "separator_noise_without_labels": _case_report(noise_text, baseline_engine, candidate_engine, args.repeats),
    }
    report = {
        "repeats": args.repeats,
        "pipeline_steps": len(candidate_pipeline),
        "cases": cases,
        "limit": {"max_added_median_ms": args.max_added_median_ms},
    }
    report["passed"] = all(
        float(case["added_median_ms"]) <= args.max_added_median_ms
        for case in cases.values()
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
