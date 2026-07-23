from pathlib import Path

from app.pii_engine import ContextualPostFilter, DetectContext, build_pipeline
from app.rules_loader import load_doc
from app.rules_loader import load_rules


def _item(text: str, value: str) -> dict:
    start = text.find(value)
    assert start >= 0
    return {"start": start, "end": start + len(value), "matchString": value}


def _ssn_filter() -> ContextualPostFilter:
    ctx_doc = load_doc(Path("app/rules/context.yaml"))["context"]
    return ContextualPostFilter(
        enabled=True,
        target_keys=["SSN"],
        threshold=99,
        indicator_phrases=[],
        non_pii_phrases=[],
        per_type={"SSN": ctx_doc["per_type"]["SSN"]},
        hybrid_cfg=ctx_doc["hybrid"],
    )


def _type_filter(key: str) -> ContextualPostFilter:
    ctx_doc = load_doc(Path("app/rules/context.yaml"))["context"]
    return ContextualPostFilter(
        enabled=True,
        target_keys=[key],
        threshold=99,
        indicator_phrases=[],
        non_pii_phrases=[],
        per_type={key: ctx_doc["per_type"][key]},
        hybrid_cfg=ctx_doc["hybrid"],
    )


def test_ssn_context_accepts_common_label_variants():
    cases = [
        "social security no. 123-45-6789",
        "tax id: 123-45-6789",
        "TIN 123-45-6789",
        "사회보장번호: 123-45-6789",
        "소셜 시큐리티 123-45-6789",
    ]

    for text in cases:
        ctx = DetectContext(text=text, max_results=10, out={"SSN": [_item(text, "123-45-6789")]})
        _ssn_filter().run(ctx)

        kept = ctx.get("SSN")
        assert len(kept) == 1, text
        assert kept[0]["context_pass"] is True


def test_ssn_spaced_format_passes_only_with_context_label():
    bundle = load_rules(rules_dir="app/rules", ruleset_name="default")
    pipeline = build_pipeline(bundle)

    labeled = DetectContext(text="ssn 078 05 1120", max_results=20, out={})
    for detector in pipeline:
        detector.run(labeled)

    kept = labeled.get("SSN")
    assert len(kept) == 1
    assert kept[0]["matchString"] == "078 05 1120"
    assert kept[0]["context_pass"] is True

    unlabeled = DetectContext(text="078 05 1120", max_results=20, out={})
    for detector in pipeline:
        detector.run(unlabeled)

    assert unlabeled.get("SSN") == []
    rejected = unlabeled.get("SSN_CTX_REJECTED")
    assert len(rejected) == 1
    assert rejected[0]["matchString"] == "078 05 1120"


def test_ssn_compact_url_page_id_is_rejected():
    text = ".resourceUrl https://xcnsoultion.atlassian.net/wiki/pages/viewpage.action?pageId=115605505"
    bundle = load_rules(rules_dir="app/rules", ruleset_name="default")
    pipeline = build_pipeline(bundle)
    ctx = DetectContext(text=text, max_results=20, out={})

    for detector in pipeline:
        detector.run(ctx)

    assert ctx.get("SSN") == []


def test_ssn_compact_explicit_ssn_url_parameter_is_detected():
    text = "https://example.test/person?ssn=123456789"
    bundle = load_rules(rules_dir="app/rules", ruleset_name="default")
    pipeline = build_pipeline(bundle)
    ctx = DetectContext(text=text, max_results=20, out={})

    for detector in pipeline:
        detector.run(ctx)

    kept = ctx.get("SSN")
    assert len(kept) == 1
    assert kept[0]["matchString"] == "123456789"


def test_context_accepts_added_indicator_variants_by_type():
    cases = [
        ("SN", "resident registration number 890512-2054508", "890512-2054508"),
        ("DN", "driver licence number 11-22-333333-44", "11-22-333333-44"),
        ("PN", "passport no. M12345678", "M12345678"),
        ("MN", "핸드폰번호 010-1234-5678", "010-1234-5678"),
        ("BN", "환불계좌 123456-01-123456", "123456-01-123456"),
        ("CN", "cc number 4111-1111-1111-1111", "4111-1111-1111-1111"),
        ("EML", "전자우편 user.name_01@sub.example.com", "user.name_01@sub.example.com"),
    ]

    for key, text, value in cases:
        ctx = DetectContext(text=text, max_results=10, out={key: [_item(text, value)]})
        _type_filter(key).run(ctx)

        kept = ctx.get(key)
        assert len(kept) == 1, f"{key}: {text}"
        assert kept[0]["context_pass"] is True
