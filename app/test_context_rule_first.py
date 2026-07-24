from __future__ import annotations

from unittest.mock import patch

import numpy as np

from app.pii_engine.common import DetectContext
from app.pii_engine.context_filters import ContextualLLMPostFilter


class _RecordingEmbedder:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def encode(self, texts, **kwargs):
        values = [str(text) for text in texts]
        self.calls.append(values)
        out = np.ones((len(values), 3), dtype=np.float32)
        return out / np.linalg.norm(out, axis=1, keepdims=True)


def _build_filter(embedder: _RecordingEmbedder) -> ContextualLLMPostFilter:
    return ContextualLLMPostFilter(
        enabled=True,
        target_keys=["SN"],
        window_sentences=1,
        sim_threshold=0.4,
        embedder=embedder,
        indicator_phrases=["주민등록번호"],
        non_pii_phrases=["문서번호"],
        per_type={
            "SN": {
                "force_pass_phrases": ["등본"],
                "force_pass_scope": "snippet",
                "indicator_phrases": ["주민등록번호"],
                "non_pii_phrases": ["문서번호"],
            }
        },
    )


def test_rule_first_skips_semantic_encode_for_unconditional_accept() -> None:
    text = "등본 주민등록번호 890512-2054508"
    match = "890512-2054508"
    start = text.index(match)
    item = {"start": start, "end": start + len(match), "matchString": match, "isValid": True}
    embedder = _RecordingEmbedder()
    ctx = DetectContext(text=text, max_results=10, out={"SN": [item]})

    with patch.dict(
        "os.environ",
        {
            "PII_CONTEXT_RULE_FIRST_ENABLED": "true",
            "PII_INCLUDE_CONTEXT_SCORES": "false",
            "PII_CONTEXT_EMBED_NORMALIZE_DIGITS": "false",
        },
        clear=False,
    ):
        _build_filter(embedder).run(ctx)

    assert len(ctx.get("SN")) == 1
    assert ctx.get("SN")[0]["context_accept_by"] == "force_phrase"
    assert ctx.get("SN")[0]["context_pass"] is True
    assert not any(text in batch for call in embedder.calls for batch in call)


def test_rule_first_is_disabled_when_context_scores_are_requested() -> None:
    text = "등본 주민등록번호 890512-2054508"
    match = "890512-2054508"
    start = text.index(match)
    item = {"start": start, "end": start + len(match), "matchString": match, "isValid": True}
    embedder = _RecordingEmbedder()
    ctx = DetectContext(text=text, max_results=10, out={"SN": [item]})

    with patch.dict(
        "os.environ",
        {
            "PII_CONTEXT_RULE_FIRST_ENABLED": "true",
            "PII_INCLUDE_CONTEXT_SCORES": "true",
            "PII_CONTEXT_EMBED_NORMALIZE_DIGITS": "false",
        },
        clear=False,
    ):
        _build_filter(embedder).run(ctx)

    assert len(ctx.get("SN")) == 1
    assert ctx.get("SN")[0]["context_accept_by"] == "force_phrase"
    assert "context_score" in ctx.get("SN")[0]
    assert any(text in batch for call in embedder.calls for batch in call)


def test_digit_normalization_reuses_embedding_for_same_context_template() -> None:
    embedder = _RecordingEmbedder()

    with patch.dict(
        "os.environ",
        {
            "PII_CONTEXT_RULE_FIRST_ENABLED": "false",
            "PII_CONTEXT_EMBED_NORMALIZE_DIGITS": "true",
        },
        clear=False,
    ):
        context_filter = _build_filter(embedder)
        scores = []
        snippet_call_counts = []
        for match in ("890512-2054508", "910101-1234567"):
            text = f"고객 123 주민등록번호 {match}"
            start = text.index(match)
            item = {"start": start, "end": start + len(match), "matchString": match, "isValid": True}
            ctx = DetectContext(text=text, max_results=10, out={"SN": [item]})
            context_filter.run(ctx)
            result_items = ctx.get("SN") or ctx.get("SN_CTX_REJECTED")
            scores.append(result_items[0]["context_score"])
            snippet_call_counts.append(sum(len(call) for call in embedder.calls))

    assert scores[0] == scores[1]
    assert snippet_call_counts[1] == snippet_call_counts[0]
    assert any("000000-0000000" in text for call in embedder.calls for text in call)
