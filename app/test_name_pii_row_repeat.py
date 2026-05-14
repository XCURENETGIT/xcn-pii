from app.pii_engine import ContextualPostFilter, DetectContext


def _item(text: str, value: str) -> dict:
    start = text.find(value)
    assert start >= 0
    return {"start": start, "end": start + len(value), "matchString": value}


def test_name_pii_row_repeat_force_pass_without_context_label():
    text = "\n".join(
        [
            "홍길동 010-1234-5678",
            "김철수 010-2222-3333",
        ]
    )
    items = [_item(text, "010-1234-5678"), _item(text, "010-2222-3333")]
    ctx = DetectContext(text=text, max_results=10, out={"MN": items})
    filt = ContextualPostFilter(
        enabled=True,
        target_keys=["MN"],
        threshold=99,
        indicator_phrases=["전화번호"],
        non_pii_phrases=[],
        hybrid_cfg={
            "enabled": True,
            "accept_threshold": 99.0,
            "name_pii_row_repeat_enabled": True,
            "name_pii_row_repeat_min_count": 2,
            "name_pii_row_repeat_require_consecutive": True,
        },
    )

    filt.run(ctx)

    kept = ctx.get("MN")
    assert len(kept) == 2
    assert {x["context_accept_by"] for x in kept} == {"name_pii_row_repeat"}


def test_single_name_pii_row_is_not_force_passed():
    text = "홍길동 010-1234-5678"
    items = [_item(text, "010-1234-5678")]
    ctx = DetectContext(text=text, max_results=10, out={"MN": items})
    filt = ContextualPostFilter(
        enabled=True,
        target_keys=["MN"],
        threshold=99,
        indicator_phrases=["전화번호"],
        non_pii_phrases=[],
        hybrid_cfg={
            "enabled": True,
            "accept_threshold": 99.0,
            "name_pii_row_repeat_enabled": True,
            "name_pii_row_repeat_min_count": 2,
        },
    )

    filt.run(ctx)

    assert ctx.get("MN") == []
    assert len(ctx.get("MN_CTX_REJECTED")) == 1


def test_single_name_rrn_row_can_be_force_passed_by_type_override():
    text = "홍길동 890512-2054508"
    items = [_item(text, "890512-2054508")]
    ctx = DetectContext(text=text, max_results=10, out={"SN": items})
    filt = ContextualPostFilter(
        enabled=True,
        target_keys=["SN"],
        threshold=99,
        indicator_phrases=["주민등록번호"],
        non_pii_phrases=[],
        per_type={
            "SN": {
                "hybrid": {
                    "name_pii_row_repeat_min_count": 1,
                }
            }
        },
        hybrid_cfg={
            "enabled": True,
            "accept_threshold": 99.0,
            "name_pii_row_repeat_enabled": True,
            "name_pii_row_repeat_min_count": 2,
        },
    )

    filt.run(ctx)

    kept = ctx.get("SN")
    assert len(kept) == 1
    assert kept[0]["context_accept_by"] == "name_pii_row_repeat"


def test_long_korean_text_before_rrn_is_not_treated_as_name():
    text = "고길동 전광판다고광이건뭐야전광판다고광이건뭐야전광판다고광이건뭐야 890512-2054508"
    items = [_item(text, "890512-2054508")]
    ctx = DetectContext(text=text, max_results=10, out={"SN": items})
    filt = ContextualPostFilter(
        enabled=True,
        target_keys=["SN"],
        threshold=99,
        indicator_phrases=["주민등록번호"],
        non_pii_phrases=[],
        per_type={
            "SN": {
                "hybrid": {
                    "name_pii_row_repeat_min_count": 1,
                }
            }
        },
        hybrid_cfg={
            "enabled": True,
            "accept_threshold": 99.0,
            "name_pii_row_repeat_enabled": True,
            "name_pii_row_repeat_min_count": 2,
        },
    )

    filt.run(ctx)

    assert ctx.get("SN") == []
    assert len(ctx.get("SN_CTX_REJECTED")) == 1


def test_repeated_row_structure_ignores_trailing_punctuation():
    text = "\n".join(
        [
            "이름이아니야  011228-4295354,",
            "이름이아니야 960805-6437730",
        ]
    )
    items = [_item(text, "011228-4295354"), _item(text, "960805-6437730")]
    ctx = DetectContext(text=text, max_results=10, out={"SN": items})
    filt = ContextualPostFilter(
        enabled=True,
        target_keys=["SN"],
        threshold=99,
        indicator_phrases=["주민등록번호"],
        non_pii_phrases=[],
        hybrid_cfg={
            "enabled": True,
            "accept_threshold": 0.3,
            "repeat_boost_enabled": True,
            "repeat_boost_min_count": 2,
            "repeat_boost_unique_min": 1,
            "repeat_boost_weight": 0.35,
            "repeat_boost_require_structure": True,
            "repeat_boost_structure_min_tokens": 2,
            "repeat_boost_require_consecutive": True,
            "repeat_boost_consecutive_min_count": 2,
            "digit_weight": 0.0,
        },
    )

    filt.run(ctx)

    kept = ctx.get("SN")
    assert len(kept) == 2
    assert {x["context_accept_by"] for x in kept} == {"hybrid_base"}
