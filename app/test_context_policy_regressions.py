from app.pii import detect_with_meta


def _detect(text: str) -> dict:
    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")
    return found


def test_ssn_logistics_code_context_is_rejected():
    found = _detect("물류 코드 123-45-6789 기준으로 목록 정리해줘")

    assert found.get("SSN", []) == []


def test_ssn_explicit_label_is_detected():
    found = _detect("social security number 123-45-6789")

    assert [item["matchString"] for item in found.get("SSN", [])] == ["123-45-6789"]


def test_internal_management_number_does_not_force_pass_as_name_row():
    found = _detect("내부 관리번호 941118-1143557 정리표 작성해줘")

    assert found.get("SN", []) == []


def test_business_context_accepts_checksum_valid_brn():
    found = _detect("110-81-40818 엑스큐어넷 사업자 GS 인증 접수 진행해줘")

    assert [item["matchString"] for item in found.get("BRN", [])] == ["110-81-40818"]
    assert found["BRN"][0].get("context_accept_by") == "label"


def test_explicit_test_marker_rejects_brn_even_with_positive_label():
    found = _detect("테스트 사업자등록번호 110-81-40818")

    assert found.get("BRN", []) == []


def test_distant_test_marker_does_not_reject_labeled_brn():
    text = "테스트 절차 안내입니다. " + ("일반 안내 내용 " * 12) + "사업자등록번호 110-81-40818"
    found = _detect(text)

    assert [item["matchString"] for item in found.get("BRN", [])] == ["110-81-40818"]


def test_test_marker_on_previous_table_row_does_not_reject_brn():
    found = _detect("테스트 데이터 안내\n사업자등록번호\t110-81-40818")

    assert [item["matchString"] for item in found.get("BRN", [])] == ["110-81-40818"]


def test_account_label_resolves_16_digit_overlap_to_bank_account():
    found = _detect("4716-1292-3626-5625 이것 계좌번호 어디 은행인지 알려줘")

    assert [item["matchString"] for item in found.get("BN", [])] == ["4716-1292-3626-5625"]
    assert found.get("CN", []) == []


def test_card_label_resolves_same_16_digit_value_to_card():
    found = _detect("카드번호 4532-1234-5678-9014 결제 내역 확인")

    assert [item["matchString"] for item in found.get("CN", [])] == ["4532-1234-5678-9014"]
    assert found.get("BN", []) == []
