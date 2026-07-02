from app.pii import detect_all


def test_mn_detects_dot_separated_phone_number() -> None:
    found = detect_all("연락처는 010.2234.1258 입니다.", max_results_per_type=20)
    matches = [item.get("matchString") for item in found.get("MN", [])]
    assert "010.2234.1258" in matches


def test_mn_rejects_010_numbers_with_0xxx_or_1xxx_middle_block() -> None:
    text = (
        "공공기관 대표번호 후보 "
        "010-0234-5678 / 010.0999.0000 / 01008889999 / "
        "010-1234-5678 / 010.1999.0000 / 01018889999"
    )

    found = detect_all(text, max_results_per_type=20)

    assert found.get("MN", []) == []


def test_mn_keeps_other_010_mobile_numbers() -> None:
    text = "개인 연락처 010-2234-5678 / 010.9234.5678"

    found = detect_all(text, max_results_per_type=20)
    matches = [item.get("matchString") for item in found.get("MN", [])]

    assert "010-2234-5678" in matches
    assert "010.9234.5678" in matches
