from app.pii import detect_all
from app.response_builders import build_detect_response


def test_vietnam_cccd_mobile_and_passport_are_detected():
    text = (
        "CCCD 079213456789 "
        "mobile 0981234567 "
        "passport B12345678 "
        "mã số thuế 0312345678 "
        "mã số BHXH 7938922623"
    )

    found = detect_all(text, max_results_per_type=20)

    assert [x["matchString"] for x in found.get("VN_CCCD", [])] == ["079213456789"]
    assert [x["matchString"] for x in found.get("VN_MN", [])] == ["0981234567"]
    assert [x["matchString"] for x in found.get("VN_PN", [])] == ["B12345678"]
    assert [x["matchString"] for x in found.get("VN_TIN", [])] == ["0312345678"]
    assert [x["matchString"] for x in found.get("VN_SI", [])] == ["7938922623"]


def test_vietnam_cccd_rejects_unknown_region_code():
    found = detect_all("CCCD 999213456789", max_results_per_type=20)

    assert found.get("VN_CCCD", []) == []


def test_vietnam_mobile_requires_known_prefix():
    text = "số điện thoại 0321234567 0551234567 0871234567 invalid 0311234567"

    found = detect_all(text, max_results_per_type=20)

    assert [x["matchString"] for x in found.get("VN_MN", [])] == [
        "0321234567",
        "0551234567",
        "0871234567",
    ]


def test_vietnam_passport_requires_documented_type_code():
    text = "hộ chiếu D12345678 passport C87654321 invalid 12345678"

    found = detect_all(text, max_results_per_type=20)

    assert [x["matchString"] for x in found.get("VN_PN", [])] == ["D12345678", "C87654321"]


def test_vietnam_context_accepts_vietnamese_labels_and_rejects_unlabeled_values():
    labeled = detect_all(
        "số căn cước công dân 079213456789\n"
        "số điện thoại 0981234567\n"
        "số hộ chiếu B12345678\n"
        "mã số thuế 0312345678\n"
        "mã số BHXH 7938922623",
        max_results_per_type=20,
    )
    unlabeled = detect_all("079213456789 0981234567 B12345678 0312345678 7938922623", max_results_per_type=20)

    assert [x["matchString"] for x in labeled.get("VN_CCCD", [])] == ["079213456789"]
    assert [x["matchString"] for x in labeled.get("VN_MN", [])] == ["0981234567"]
    assert [x["matchString"] for x in labeled.get("VN_PN", [])] == ["B12345678"]
    assert [x["matchString"] for x in labeled.get("VN_TIN", [])] == ["0312345678"]
    assert [x["matchString"] for x in labeled.get("VN_SI", [])] == ["7938922623"]
    assert labeled["VN_CCCD"][0].get("context_pass") is True
    assert labeled["VN_MN"][0].get("context_pass") is True
    assert labeled["VN_PN"][0].get("context_pass") is True
    assert labeled["VN_TIN"][0].get("context_pass") is True
    assert labeled["VN_SI"][0].get("context_pass") is True
    assert unlabeled.get("VN_CCCD", []) == []
    assert unlabeled.get("VN_MN", []) == []
    assert unlabeled.get("VN_PN", []) == []
    assert unlabeled.get("VN_TIN", []) == []
    assert unlabeled.get("VN_SI", []) == []


def test_vietnam_fields_are_in_http_response_model():
    response = build_detect_response(
        {
            "VN_CCCD": [{"start": 0, "end": 12, "matchString": "079213456789"}],
            "VN_MN": [{"start": 13, "end": 23, "matchString": "0981234567"}],
            "VN_PN": [{"start": 24, "end": 33, "matchString": "B12345678"}],
            "VN_TIN": [{"start": 34, "end": 44, "matchString": "0312345678"}],
            "VN_SI": [{"start": 45, "end": 55, "matchString": "7938922623"}],
        },
        {"ruleset_name": "default", "ruleset_version": "test", "ruleset_updated_at": "test"},
    )

    dumped = response.model_dump(exclude_none=True)
    assert dumped["data"]["VN_CCCD_CNT"] == 1
    assert dumped["data"]["VN_MN_CNT"] == 1
    assert dumped["data"]["VN_PN_CNT"] == 1
    assert dumped["data"]["VN_TIN_CNT"] == 1
    assert dumped["data"]["VN_SI_CNT"] == 1
