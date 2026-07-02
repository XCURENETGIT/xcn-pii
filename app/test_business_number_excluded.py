from app.pii import detect_all
from app.response_builders import build_detect_response


def test_business_registration_number_is_detected_as_brn_not_bn():
    text = "사업자등록번호: 220-81-62517"

    found = detect_all(text, max_results_per_type=20)

    assert [x["matchString"] for x in found.get("BRN", [])] == ["220-81-62517"]
    assert found.get("BN") in (None, [])


def test_business_registration_number_is_included_in_response_schema():
    response = build_detect_response(
        {"BRN": [{"start": 0, "end": 12, "matchString": "220-81-62517"}]},
        {"ruleset_name": "default", "ruleset_version": "test", "ruleset_updated_at": "test"},
    )

    dumped = response.model_dump(exclude_none=True)
    assert dumped["data"]["BRN_CNT"] == 1
    assert dumped["data"]["BRN"][0]["matchString"] == "220-81-62517"
