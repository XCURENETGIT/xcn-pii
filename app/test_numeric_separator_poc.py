import pytest

from app.pii import detect_all


NUMERIC_TYPE_CASES = [
    ("SN", "주민등록번호 890512&2054508", "890512&2054508"),
    ("FN", "외국인등록번호 900101&5123450", "900101&5123450"),
    ("SSN", "SSN 123/45/6789", "123/45/6789"),
    ("DN", "운전면허번호 11.22.333333.44", "11.22.333333.44"),
    ("MN", "전화번호 010'5110'7263", "010'5110'7263"),
    ("BRN", "사업자등록번호 220/81/62517", "220/81/62517"),
    ("BN", "계좌번호 4716/1292.3626|7849", "4716/1292.3626|7849"),
    ("CN", "카드번호 4532/1234.5678|9014", "4532/1234.5678|9014"),
    ("CPN", "법인등록번호 110111/1234569", "110111/1234569"),
    ("IMEI", "IMEI 49015420/323751/8", "49015420/323751/8"),
    ("VN_MN", "so dien thoai 098/123/4567", "098/123/4567"),
    ("VN_CCCD", "CCCD 079/213/456/789", "079/213/456/789"),
    ("VN_TIN", "ma so thue 0312/345/678", "0312/345/678"),
    ("VN_SI", "ma so bhxh 7938/922/623", "7938/922/623"),
]


@pytest.mark.parametrize("ruleset", ["default", "strict"])
@pytest.mark.parametrize(("out_key", "text", "expected"), NUMERIC_TYPE_CASES)
def test_all_numeric_pii_types_accept_alternate_separators(
    ruleset: str,
    out_key: str,
    text: str,
    expected: str,
) -> None:
    found = detect_all(text, max_results_per_type=30, ruleset=ruleset)

    assert [item["matchString"] for item in found.get(out_key, [])] == [expected]
    assert found[out_key][0].get("detected_by", "").endswith(f":{out_key.lower()}")


@pytest.mark.parametrize("separator", ["&", "/", ".", "'", "`", "|"])
def test_unlabeled_phone_accepts_every_poc_separator(separator: str) -> None:
    value = separator.join(("010", "5110", "7263"))
    found = detect_all(value, max_results_per_type=20)

    assert [item["matchString"] for item in found.get("MN", [])] == [value]


@pytest.mark.parametrize(
    ("out_key", "text"),
    [
        ("SN", "주민등록번호 890512&2054509"),
        ("BRN", "사업자등록번호 220/81/62518"),
        ("CN", "카드번호 4532/1234/5678/9015"),
        ("CPN", "법인등록번호 110111/1234568"),
        ("IMEI", "IMEI 49015420/323751/9"),
    ],
)
def test_checksum_types_still_reject_invalid_values(out_key: str, text: str) -> None:
    found = detect_all(text, max_results_per_type=30)

    assert found.get(out_key, []) == []
