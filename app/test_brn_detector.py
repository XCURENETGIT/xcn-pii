from app.pii_engine.common import DetectContext, brn_checksum_valid, brn_structure_valid
from app.pii_engine.pipeline_builder import build_pipeline
from app.response_builders import build_detect_response
from app.rules_loader import load_rules


def _detect(text: str) -> dict:
    bundle = load_rules(rules_dir="app/rules", ruleset_name="default")
    pipeline = build_pipeline(bundle)
    ctx = DetectContext(text=text, max_results=20, out={})
    for detector in pipeline:
        detector.run(ctx)
    return ctx.out


def test_brn_checksum_validates_hyphen_and_compact_forms():
    assert brn_checksum_valid("220-81-62517") is True
    assert brn_checksum_valid("2208162517") is True
    assert brn_structure_valid("220-81-62517") is True


def test_brn_checksum_rejects_invalid_number():
    assert brn_checksum_valid("123-45-67890") is False
    assert brn_structure_valid("000-00-00000") is False


def test_brn_detector_keeps_valid_brn_and_rejects_overlapping_bn():
    out = _detect("사업자등록번호: 220-81-62517 / 계좌번호: 123456-01-123456")

    assert [x["matchString"] for x in out.get("BRN", [])] == ["220-81-62517"]
    assert "220-81-62517" not in [x["matchString"] for x in out.get("BN", [])]


def test_invalid_brn_shape_is_not_reclassified_as_bank_number():
    out = _detect("사업자등록번호: 123-45-67890")

    assert out.get("BRN", []) == []
    assert "123-45-67890" not in [x["matchString"] for x in out.get("BN", [])]


def test_brn_response_schema_includes_brn_key():
    response = build_detect_response(
        {"BRN": [{"start": 0, "end": 12, "matchString": "220-81-62517", "isValid": True}]},
        {"ruleset_name": "default", "ruleset_version": "test", "ruleset_updated_at": "test"},
    )

    dumped = response.model_dump(exclude_none=True)
    assert dumped["data"]["BRN_CNT"] == 1
    assert dumped["data"]["BRN"][0]["matchString"] == "220-81-62517"
