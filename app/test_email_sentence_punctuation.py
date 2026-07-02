from app.pii import detect_with_meta


def test_email_before_sentence_period_is_detected_without_period():
    text = "신청자 회신용 안내메일 작성해줘. 받는사람 hong.gildong@gmail.com."

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("EML", [])] == ["hong.gildong@gmail.com"]


def test_email_before_space_period_is_detected_without_period():
    text = "받는사람 hong.gildong@gmail.com. 본문 작성"

    found, _meta = detect_with_meta(text, max_results_per_type=20, ruleset="default")

    assert [x["matchString"] for x in found.get("EML", [])] == ["hong.gildong@gmail.com"]
