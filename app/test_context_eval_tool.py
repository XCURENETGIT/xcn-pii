import json
from pathlib import Path

import yaml

from tools.eval_context_thresholds import _decision_metrics, _eval_thresholds


def test_missing_positive_score_counts_as_false_negative() -> None:
    rows = [
        {"label": 1, "context_score_norm": None},
        {"label": 1, "context_score_norm": 0.8},
    ]

    threshold, metrics = _eval_thresholds(rows, "context_score_norm", [0.5])

    assert threshold == 0.5
    assert metrics == {"precision": 1.0, "recall": 0.5, "f1": 2 / 3}


def test_rule_first_decision_stays_fixed_during_threshold_sweep() -> None:
    rows = [
        {"label": 1, "accepted": True, "decision_fixed": True, "context_score_norm": None},
        {"label": 0, "accepted": False, "decision_fixed": True, "context_score_norm": None},
    ]

    _threshold, metrics = _eval_thresholds(rows, "context_score_norm", [0.0, 1.0])

    assert metrics == {"precision": 1.0, "recall": 1.0, "f1": 1.0}


def test_seed_dataset_matches_configured_context_targets() -> None:
    data = json.loads(Path("tools/context_eval.json").read_text(encoding="utf-8-sig"))
    context_doc = yaml.safe_load(Path("app/rules/context.yaml").read_text(encoding="utf-8"))["context"]

    dataset_types = {str(item["type"]) for item in data["items"]}

    assert data["dataset_kind"] == "synthetic_adversarial"
    assert len(data["items"]) == 136
    assert dataset_types == set(context_doc["target_keys"])
    assert not dataset_types.intersection({"MN", "EML", "AN"})


def test_current_decision_metrics_include_confusion_counts() -> None:
    rows = [
        {"label": 1, "accepted": True},
        {"label": 1, "accepted": False},
        {"label": 0, "accepted": True},
        {"label": 0, "accepted": False},
    ]

    assert _decision_metrics(rows) == {
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
    }
