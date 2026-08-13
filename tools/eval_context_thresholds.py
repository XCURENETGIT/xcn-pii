from __future__ import annotations

import argparse
from collections import Counter
import json
import math
import csv
from numbers import Real
from pathlib import Path
import sys
from typing import Dict, List, Tuple
import urllib.request
import yaml


def _call_api(url: str, text: str, max_results: int = 200) -> Dict:
    req = urllib.request.Request(
        url,
        data=json.dumps({"text": text, "max_results_per_type": max_results}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _call_debug(url: str, text: str, ruleset: str = "default") -> Dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(
            {"text": text, "ruleset": ruleset, "use_pipeline_config": True}
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _find_match(items: List[Dict], match: str) -> Dict | None:
    for it in items or []:
        if str(it.get("matchString", "")) == match:
            return it
    return None


def _find_debug_item(debug_items: List[Dict], ptype: str, match: str) -> Dict | None:
    for it in debug_items or []:
        if it.get("key") == ptype and str(it.get("matchString", "")) == match:
            return it
    return None


def _metrics(tp: int, fp: int, fn: int) -> Dict[str, float]:
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    return {"precision": prec, "recall": rec, "f1": f1}


def _decision_metrics(rows: List[Dict]) -> Dict[str, float | int]:
    tp = fp = fn = tn = 0
    for row in rows:
        expected = int(row.get("label", 0)) == 1
        accepted = bool(row.get("accepted"))
        if expected and accepted:
            tp += 1
        elif accepted:
            fp += 1
        elif expected:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, **_metrics(tp, fp, fn)}


def _row_prediction(row: Dict, key: str, threshold: float) -> int:
    score = row.get(key)
    if isinstance(score, Real) and math.isfinite(float(score)):
        return 1 if float(score) >= threshold else 0
    if row.get("decision_fixed") is True:
        return 1 if row.get("accepted") is True else 0
    return 0


def _eval_thresholds(rows: List[Dict], key: str, thresholds: List[float]) -> Tuple[float, Dict[str, float]]:
    best_t = None
    best = None
    for t in thresholds:
        tp = fp = fn = 0
        for r in rows:
            # Rule-first decisions and hard negatives have no embedding score,
            # but remain fixed while semantic thresholds are swept.
            pred = _row_prediction(r, key, t)
            if pred == 1 and r["label"] == 1:
                tp += 1
            elif pred == 1 and r["label"] == 0:
                fp += 1
            elif pred == 0 and r["label"] == 1:
                fn += 1
        m = _metrics(tp, fp, fn)
        if best is None or m["f1"] > best["f1"]:
            best_t = t
            best = m
    return best_t, best or {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def _eval_thresholds_per_type(rows: List[Dict], key: str, thresholds: List[float]) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    types = sorted({r.get("type") for r in rows if r.get("type")})
    for tname in types:
        subset = [r for r in rows if r.get("type") == tname]
        best_t, best = _eval_thresholds(subset, key, thresholds)
        out[tname] = {"threshold": best_t, **best}
    return out


def _write_rows_csv(path: str, rows: List[Dict]) -> None:
    cols = [
        "id",
        "type",
        "label",
        "match",
        "case_kind",
        "accepted",
        "accept_by",
        "context_method",
        "decision_fixed",
        "context_score_norm",
        "context_hybrid_score",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in cols})


def _write_summary_csv(path: str, overall: Dict, per_type: Dict[str, Dict]) -> None:
    cols = ["scope", "metric", "threshold", "precision", "recall", "f1"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for metric, info in overall.items():
            w.writerow(
                {
                    "scope": "overall",
                    "metric": metric,
                    "threshold": info["threshold"],
                    "precision": info["precision"],
                    "recall": info["recall"],
                    "f1": info["f1"],
                }
            )
        for metric, by_type in per_type.items():
            for tname, info in by_type.items():
                w.writerow(
                    {
                        "scope": tname,
                        "metric": metric,
                        "threshold": info["threshold"],
                        "precision": info["precision"],
                        "recall": info["recall"],
                        "f1": info["f1"],
                    }
                )


def _update_context_yaml(path: str, per_type_norm: Dict[str, Dict], per_type_hybrid: Dict[str, Dict], overall_hybrid: Dict) -> None:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    ctx = data.get("context")
    if not isinstance(ctx, dict):
        ctx = {}
        data["context"] = ctx

    if isinstance(ctx.get("hybrid"), dict):
        ctx["hybrid"]["accept_threshold"] = overall_hybrid.get("threshold")

    if not isinstance(ctx.get("per_type"), dict):
        ctx["per_type"] = {}

    for tname, info in per_type_norm.items():
        entry = ctx["per_type"].get(tname, {})
        entry["sim_threshold"] = info.get("threshold")
        ctx["per_type"][tname] = entry

    for tname, info in per_type_hybrid.items():
        entry = ctx["per_type"].get(tname, {})
        if not isinstance(entry.get("hybrid"), dict):
            entry["hybrid"] = {}
        entry["hybrid"]["accept_threshold"] = info.get("threshold")
        ctx["per_type"][tname] = entry

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="tools/context_eval.json")
    ap.add_argument("--url", default="http://localhost:8005/pii/detect")
    ap.add_argument("--local", action="store_true", help="Run against the local engine without HTTP")
    ap.add_argument("--ruleset", default="default")
    ap.add_argument("--min", type=float, default=0.0)
    ap.add_argument("--max", type=float, default=1.0)
    ap.add_argument("--step", type=float, default=0.05)
    ap.add_argument("--out-rows", default="tools/context_eval_rows.csv")
    ap.add_argument("--out-summary", default="tools/context_eval_summary.csv")
    ap.add_argument(
        "--update-context",
        default="",
        help="Optional context.yaml path to update after review (disabled by default)",
    )
    ap.add_argument(
        "--allow-nonrepresentative-update",
        action="store_true",
        help="Allow updating YAML from a non-representative dataset (not recommended)",
    )
    args = ap.parse_args()

    with open(args.data, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    items = data.get("items", [])
    if not isinstance(items, list) or not items:
        raise ValueError("evaluation data must contain a non-empty 'items' list")
    rows: List[Dict] = []

    local_detect = None
    if args.local:
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from app.pii_engine import detect as local_detect

    debug_url = args.url.replace("/pii/detect", "/debug/context")

    for it in items:
        missing = [key for key in ("type", "text", "match", "label") if key not in it]
        if missing:
            raise ValueError(f"evaluation item {it.get('id')!r} missing fields: {', '.join(missing)}")

        if args.local:
            found_with_debug = local_detect(
                text=it["text"],
                max_results_per_type=200,
                ruleset=args.ruleset,
                include_context_debug=True,
            )
            dbg = {
                "found": found_with_debug,
                "debug": found_with_debug.get("__context_debug", []),
            }
        else:
            dbg = _call_debug(debug_url, it["text"], ruleset=args.ruleset)

        pdata = dbg.get("found", {})
        arr = pdata.get(it["type"], [])
        found = _find_match(arr, it["match"])
        ditem = _find_debug_item(dbg.get("debug", []), it["type"], it["match"])
        row = {
            "id": it.get("id"),
            "label": int(it.get("label", 0)),
            "type": it.get("type"),
            "match": it.get("match"),
            "case_kind": it.get("case_kind"),
            "accepted": bool(found),
            "accept_by": (found or {}).get("context_accept_by") or (ditem or {}).get("method"),
            "context_method": (found or {}).get("context_method") or (ditem or {}).get("method"),
            "decision_fixed": False,
            "context_score_norm": None,
            "context_hybrid_score": None,
        }
        if found and row["context_method"] == "embed":
            row["context_score_norm"] = found.get("context_score_norm")
            row["context_hybrid_score"] = found.get("context_hybrid_score")
        if ditem and row["context_method"] == "embed":
            if row["context_score_norm"] is None:
                row["context_score_norm"] = ditem.get("score_norm")
            if row["context_hybrid_score"] is None:
                row["context_hybrid_score"] = ditem.get("hybrid_score")
        row["decision_fixed"] = (
            row["context_method"] != "embed"
            or not isinstance(row["context_score_norm"], Real)
        )
        rows.append(row)

    thresholds = []
    t = args.min
    while t <= args.max + 1e-9:
        thresholds.append(round(t, 4))
        t += args.step

    best_norm_t, best_norm = _eval_thresholds(rows, "context_score_norm", thresholds)
    best_hybrid_t, best_hybrid = _eval_thresholds(rows, "context_hybrid_score", thresholds)
    per_type_norm = _eval_thresholds_per_type(rows, "context_score_norm", thresholds)
    per_type_hybrid = _eval_thresholds_per_type(rows, "context_hybrid_score", thresholds)

    method_counts = Counter(str(row.get("context_method") or "none") for row in rows)
    embed_score_count = sum(isinstance(row.get("context_score_norm"), Real) for row in rows)
    print(f"== Evaluation coverage ==\nmethods={dict(method_counts)} embed_scores={embed_score_count}/{len(rows)}")
    decision_metrics = _decision_metrics(rows)
    print("== Current end-to-end decisions ==")
    print(json.dumps(decision_metrics, ensure_ascii=False))
    print("== Current decisions by case kind ==")
    for case_kind in sorted({str(row.get("case_kind") or "unknown") for row in rows}):
        subset = [row for row in rows if str(row.get("case_kind") or "unknown") == case_kind]
        print(f"{case_kind}: {json.dumps(_decision_metrics(subset), ensure_ascii=False)}")
    if embed_score_count == 0:
        print(
            "WARNING: no embedding scores were produced; threshold results only reflect "
            "fixed rule/keyword decisions and must not be applied to context.yaml"
        )

    print("== Best threshold (context_score_norm) ==")
    print(f"threshold={best_norm_t} precision={best_norm['precision']:.3f} recall={best_norm['recall']:.3f} f1={best_norm['f1']:.3f}")
    print("== Best threshold (context_hybrid_score) ==")
    print(f"threshold={best_hybrid_t} precision={best_hybrid['precision']:.3f} recall={best_hybrid['recall']:.3f} f1={best_hybrid['f1']:.3f}")
    print("== Per-type thresholds (context_score_norm) ==")
    for tname, info in per_type_norm.items():
        print(f"{tname}: threshold={info['threshold']} precision={info['precision']:.3f} recall={info['recall']:.3f} f1={info['f1']:.3f}")
    print("== Per-type thresholds (context_hybrid_score) ==")
    for tname, info in per_type_hybrid.items():
        print(f"{tname}: threshold={info['threshold']} precision={info['precision']:.3f} recall={info['recall']:.3f} f1={info['f1']:.3f}")
    print("== Rows ==")
    for r in rows:
        print(json.dumps(r, ensure_ascii=False))

    _write_rows_csv(args.out_rows, rows)
    overall = {
        "context_score_norm": {"threshold": best_norm_t, **best_norm},
        "context_hybrid_score": {"threshold": best_hybrid_t, **best_hybrid},
    }
    per_type = {
        "context_score_norm": per_type_norm,
        "context_hybrid_score": per_type_hybrid,
    }
    _write_summary_csv(args.out_summary, overall, per_type)
    if args.update_context:
        dataset_kind = str(data.get("dataset_kind") or "unknown")
        if embed_score_count == 0:
            raise RuntimeError("cannot update context.yaml without embedding scores")
        if dataset_kind != "representative" and not args.allow_nonrepresentative_update:
            raise RuntimeError(
                f"cannot update context.yaml from dataset_kind={dataset_kind!r}; "
                "use a representative dataset or explicitly override"
            )
        _update_context_yaml(
            args.update_context,
            per_type_norm,
            per_type_hybrid,
            overall.get("context_hybrid_score", {}),
        )


if __name__ == "__main__":
    main()
