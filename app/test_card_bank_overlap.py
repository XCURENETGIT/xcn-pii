from app.pii import detect_all


def test_card_number_overlap_keeps_card_and_drops_partial_bank_number() -> None:
    text = "안내문 작성해줘. 결제 카드 4532-1234-5678-9014 입니다."

    found = detect_all(text, max_results_per_type=20)

    assert [x["matchString"] for x in found.get("CN", [])] == ["4532-1234-5678-9014"]
    assert found.get("BN", []) == []
