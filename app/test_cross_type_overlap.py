from app.pii import detect_all
from app.pii_engine.common import _resolve_cross_type_overlaps


def test_same_span_uses_context_score_before_type_priority() -> None:
    out = {
        "VN_MN": [
            {
                "start": 10,
                "end": 20,
                "matchString": "0981234567",
                "context_pass": True,
                "context_hybrid_score": 0.72,
            }
        ],
        "VN_TIN": [
            {
                "start": 10,
                "end": 20,
                "matchString": "0981234567",
                "context_pass": True,
                "context_hybrid_score": 0.65,
            }
        ],
    }

    _resolve_cross_type_overlaps(out)

    assert [x["matchString"] for x in out["VN_MN"]] == ["0981234567"]
    assert out["VN_TIN"] == []


def test_same_span_falls_back_to_specific_phone_before_broad_tax_number() -> None:
    text = "so dien thoai 0981234567"

    found = detect_all(text, max_results_per_type=20)

    assert [x["matchString"] for x in found.get("VN_MN", [])] == ["0981234567"]
    assert found.get("MN", []) == []
    assert found.get("VN_TIN", []) == []
    assert found.get("VN_SI", []) == []
    assert found.get("BRN", []) == []
