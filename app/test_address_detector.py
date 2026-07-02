from app.pii import detect_all


def test_address_is_detected_in_default_ruleset():
    text = "주소는 서울특별시 강남구 테헤란로 123-4 5층입니다."

    found = detect_all(text, max_results_per_type=20)

    assert found.get("AN")
    assert "서울특별시 강남구 테헤란로 123-4" in found["AN"][0]["matchString"]


def test_address_is_detected_in_strict_ruleset():
    text = "주소는 경기도 성남시 분당구 정자동 12-3 번지입니다."

    found = detect_all(text, max_results_per_type=20, ruleset="strict")

    assert found.get("AN")
    assert "경기도 성남시 분당구 정자동 12-3" in found["AN"][0]["matchString"]


def test_address_does_not_include_explanatory_sentence():
    text = "서울특별시 은평구 가좌로 276 실제 존재하는 주소로 판단됩니다. 이거 어디까지 잡히는거야"

    found = detect_all(text, max_results_per_type=20)

    assert found.get("AN")
    assert found["AN"][0]["matchString"] == "서울특별시 은평구 가좌로 276"


def test_address_accepts_seoul_city_short_suffix():
    text = "서울시 은평구 가좌로 276"

    found = detect_all(text, max_results_per_type=20)

    assert found.get("AN")
    assert found["AN"][0]["matchString"] == "서울시 은평구 가좌로 276"


def test_address_keeps_common_detail_tokens_only():
    text = "주소: 서울특별시 은평구 가좌로 276 101동 1203호 실제 존재하는 주소입니다."

    found = detect_all(text, max_results_per_type=20)

    assert found.get("AN")
    assert found["AN"][0]["matchString"] == "서울특별시 은평구 가좌로 276 101동 1203호"
