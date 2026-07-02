from app.pii import detect_with_meta
from app.pii_engine.context_helpers import _is_name_like_korean_token


def test_name_like_token_requires_korean_surname_shape():
    assert _is_name_like_korean_token("홍길동") is True
    assert _is_name_like_korean_token("김철수") is True
    assert _is_name_like_korean_token("이영희") is True
    assert _is_name_like_korean_token("팽길동") is False
    assert _is_name_like_korean_token("팽길동", allow_extended_surname=True) is True
    assert _is_name_like_korean_token("김구") is False
    assert _is_name_like_korean_token("김구", allow_short_given=True) is True

    assert _is_name_like_korean_token("마스킹") is False
    assert _is_name_like_korean_token("정책이") is False
    assert _is_name_like_korean_token("형태로") is False
    assert _is_name_like_korean_token("내부") is False


def test_sn_random_text_with_valid_checksum_is_rejected_without_real_context():
    text = "룰라룰루랄라띠로리랄라부부부부띠라라룰루랄라. 900101-1123459 관련 안내문 작성해줘."

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert found.get("SN", []) == []


def test_sn_internal_document_management_number_is_rejected():
    text = "우리 부서 내부 문서관리번호 900101-1123459 로 등록해줘."

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert found.get("SN", []) == []


def test_sn_masking_policy_example_is_rejected():
    text = "정책이 ‘마스킹 전송’일 때 941118-1143557 →9411**-******* 형태로 치환 전송되는가?"

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert found.get("SN", []) == []


def test_sn_name_row_repeat_still_accepts_repeated_name_rows():
    text = "홍길동 890512-2054508\n김철수 900101-1123459"

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("SN", [])] == [
        "890512-2054508",
        "900101-1123459",
    ]
    assert all(x.get("context_accept_by") == "name_pii_row_repeat" for x in found.get("SN", []))


def test_sn_name_row_accepts_single_reversed_number_name_row():
    text = "890512-2054508 홍길동"

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("SN", [])] == ["890512-2054508"]
    assert found["SN"][0].get("context_accept_by") == "name_pii_row_repeat"
    assert found["SN"][0].get("context_name_pii_row_token") == "홍길동"


def test_sn_name_row_accepts_repeated_reversed_number_name_rows():
    text = "890512-2054508 홍길동\n900101-1123459 김철수"

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("SN", [])] == [
        "890512-2054508",
        "900101-1123459",
    ]
    assert all(x.get("context_accept_by") == "name_pii_row_repeat" for x in found.get("SN", []))


def test_sn_reversed_extended_surname_still_requires_explicit_name_label():
    unlabeled = "941118-1143557 팽길동"
    labeled = "941118-1143557 신청자 팽길동"

    found_unlabeled, _meta = detect_with_meta(unlabeled, max_results_per_type=20, ruleset="default")
    found_labeled, _meta = detect_with_meta(labeled, max_results_per_type=20, ruleset="default")

    assert found_unlabeled.get("SN", []) == []
    assert [x["matchString"] for x in found_labeled.get("SN", [])] == ["941118-1143557"]


def test_sn_extended_surname_requires_explicit_name_label():
    unlabeled = "팽길동 941118-1143557"
    labeled = "신청자 팽길동 941118-1143557"

    found_unlabeled, _meta = detect_with_meta(unlabeled, max_results_per_type=20, ruleset="default")
    found_labeled, _meta = detect_with_meta(labeled, max_results_per_type=20, ruleset="default")

    assert found_unlabeled.get("SN", []) == []
    assert [x["matchString"] for x in found_labeled.get("SN", [])] == ["941118-1143557"]


def test_fn_foreigner_registration_context_accepts_valid_foreigner_number():
    cases = [
        "Please draft an official letter for foreigner 900101-5123450",
        "Please draft an official letter for foreigner reg no 900101-5123450",
        "foreigner registration number 900101-5123450",
        "alien reg no 900101-5123450",
        "외국인등록번호 900101-5123450",
    ]

    for text in cases:
        found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

        assert found.get("SN", []) == []
        assert [x["matchString"] for x in found.get("FN", [])] == ["900101-5123450"]


def test_fn_foreigner_context_does_not_accept_domestic_gender_code():
    text = "Please draft an official letter for foreigner 941118-1143557"

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert found.get("SN", []) == []
    assert found.get("FN", []) == []


def test_fn_is_separate_from_sn_in_labeled_mixed_text():
    text = "주민등록번호 890512-2054508 / 외국인등록번호 900101-5123450"

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("SN", [])] == ["890512-2054508"]
    assert [x["matchString"] for x in found.get("FN", [])] == ["900101-5123450"]
