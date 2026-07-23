from __future__ import annotations

from app.detection_exclusions import parse_detection_exclusions
from app.pii import detect_with_meta
from app.response_builders import build_detect_response


def test_detects_cpn_crn_imei_mcn_with_labels():
    text = (
        "법인 등록번호 110111-1234569 "
        "자동차 등록번호 123가 4567 "
        "IMEI 490154203237518 "
        "MAC 주소 AA:BB:CC:DD:EE:FF"
    )

    found, _ = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("CPN", [])] == ["110111-1234569"]
    assert [x["matchString"] for x in found.get("CRN", [])] == ["123가 4567"]
    assert [x["matchString"] for x in found.get("IMEI", [])] == ["490154203237518"]
    assert [x["matchString"] for x in found.get("MCN", [])] == ["AA:BB:CC:DD:EE:FF"]


def test_invalid_imei_is_rejected():
    found, _ = detect_with_meta("IMEI 490154203237519", max_results_per_type=20, ruleset="default")

    assert found.get("IMEI", []) == []


def test_invalid_cpn_checksum_is_rejected():
    found, _ = detect_with_meta("법인 등록번호 110111-1234567", max_results_per_type=20, ruleset="default")

    assert found.get("CPN", []) == []


def test_extended_identifier_pattern_variants():
    text = (
        "법인 등기 번호 1101-11-123456-9 "
        "구형 차량번호 서울 1가 2345 "
        "신형 차량번호 123허 4567 "
        "device imei 49015420-323751-8 "
        "장비 MAC aabb.ccdd.eeff"
    )

    found, _ = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("CPN", [])] == ["1101-11-123456-9"]
    assert [x["matchString"] for x in found.get("CRN", [])] == ["서울 1가 2345", "123허 4567"]
    assert [x["matchString"] for x in found.get("IMEI", [])] == ["49015420-323751-8"]
    assert [x["matchString"] for x in found.get("MCN", [])] == ["aabb.ccdd.eeff"]


def test_extended_identifier_context_aliases_pass_filter():
    text = (
        "법인등기번호 110111-1234569 "
        "차번 123가 4567 "
        "단말기 고유번호 490154203237518 "
        "네트워크 인터페이스 AA:BB:CC:DD:EE:FF"
    )

    found, _ = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("CPN", [])] == ["110111-1234569"]
    assert [x["matchString"] for x in found.get("CRN", [])] == ["123가 4567"]
    assert [x["matchString"] for x in found.get("IMEI", [])] == ["490154203237518"]
    assert [x["matchString"] for x in found.get("MCN", [])] == ["AA:BB:CC:DD:EE:FF"]


def test_crn_followed_by_korean_sentence_ending():
    text = (
        "운영 로그 확인용 혼합 문장 계약 법인의 회사 등록 번호는 110111-1234569이고, "
        "현장 차량번호는 123가 4567입니다. "
        "지급 단말기의 mobile equipment identity 값은 490154203237518이며, "
        "무선 장비 MAC address는 AA:BB:CC:DD:EE:FF입니다."
    )

    found, _ = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("CRN", [])] == ["123가 4567"]


def test_imei_and_card_number_overlap_respects_context():
    found, _ = detect_with_meta("IMEI 490154203237518", max_results_per_type=20, ruleset="default")
    assert [x["matchString"] for x in found.get("IMEI", [])] == ["490154203237518"]
    assert found.get("CN", []) == []

    found, _ = detect_with_meta("카드번호 490154203237518", max_results_per_type=20, ruleset="default")
    assert found.get("IMEI", []) == []
    assert [x["matchString"] for x in found.get("CN", [])] == ["490154203237518"]


def test_extended_identifier_types_are_in_api_and_exclusion_schema():
    found = {
        "CPN": [{"start": 0, "end": 14, "matchString": "110111-1234569"}],
        "CRN": [{"start": 15, "end": 23, "matchString": "123가 4567"}],
        "IMEI": [{"start": 24, "end": 39, "matchString": "490154203237518"}],
        "MCN": [{"start": 40, "end": 57, "matchString": "AA:BB:CC:DD:EE:FF"}],
    }

    response = build_detect_response(found, {"ruleset_name": "default", "ruleset_version": "test", "ruleset_updated_at": "test"})
    dumped = response.model_dump(exclude_none=True)

    assert dumped["data"]["CPN_CNT"] == 1
    assert dumped["data"]["CRN_CNT"] == 1
    assert dumped["data"]["IMEI_CNT"] == 1
    assert dumped["data"]["MCN_CNT"] == 1
    cfg = parse_detection_exclusions({"types": {"CPN": ["110111-1234569"], "MCN": ["AA:BB:CC:DD:EE:FF"]}})
    assert cfg.type_counts == {"CPN": 1, "MCN": 1}
