from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import patch

from app.pii import _split_text_ranges_bounded
from app.pii_engine.detectors import RegexDetector
from app.pii_engine.engine import PiiEngine


def test_bounded_split_covers_entire_input_without_tail_drop() -> None:
    text = "x" * 4_000_000
    ranges = _split_text_ranges_bounded(text, chunk_chars=50_000, overlap_chars=2_000, max_chunks=64)

    assert len(ranges) <= 64
    assert ranges[0][0] == 0
    assert ranges[-1][1] == len(text)
    assert all(next_start < end for (_start, end), (next_start, _next_end) in zip(ranges, ranges[1:]))


def test_large_input_does_not_disable_detector_outside_legacy_fast_keys() -> None:
    value = "123456-01-123456"
    text = f"계좌번호 {value}" + (" 가" * 26_000)
    detector = RegexDetector("BN", [re.compile(re.escape(value))], enabled=True, max_match_len=32)
    bundle = SimpleNamespace(
        ruleset={"defaults": {"max_results_per_type": 10}},
        rule_docs={"bn": {}},
        ruleset_name="test",
    )
    engine = PiiEngine(bundle=bundle, pipeline=[detector])

    with patch.dict(
        "os.environ",
        {
            "PII_FASTPATH_ENABLED": "true",
            "PII_FASTPATH_TEXT_LEN": "50000",
            "PII_FASTPATH_TARGET_KEYS": "SN,CN",
        },
        clear=False,
    ):
        found = engine.detect(text, max_results_per_type=10)

    assert [item["matchString"] for item in found.get("BN", [])] == [value]
