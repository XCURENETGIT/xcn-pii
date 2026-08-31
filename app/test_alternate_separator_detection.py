import pytest

from app.pii import detect_all


USER_EXAMPLES = [
    ("MN", "전화번호 : 010&5110&7263", "010&5110&7263"),
    ("BN", "계좌번호 4716/1292/3626/7849", "4716/1292/3626/7849"),
    ("BN", "계좌번호 : 4716.1292.3626.7849", "4716.1292.3626.7849"),
    ("BN", "계좌번호4716'1292'3626'7849", "4716'1292'3626'7849"),
    ("BN", "계좌번호 4716|1292|3626|7849", "4716|1292|3626|7849"),
]


@pytest.mark.parametrize("ruleset", ["default", "strict"])
@pytest.mark.parametrize(("out_key", "text", "expected"), USER_EXAMPLES)
def test_user_examples_detect_once_with_expected_type(
    ruleset: str,
    out_key: str,
    text: str,
    expected: str,
) -> None:
    found = detect_all(text, max_results_per_type=20, ruleset=ruleset)

    assert [item["matchString"] for item in found.get(out_key, [])] == [expected]
    assert found[out_key][0].get("detected_by") == f"labeled_alternate_separator:{out_key.lower()}"
    other_key = "BN" if out_key == "MN" else "MN"
    assert found.get(other_key, []) == []
    assert found.get("CN", []) == []


@pytest.mark.parametrize("separator", ["&", "/", "'", "`", "|"])
def test_phone_labeled_alternate_separator_matrix(separator: str) -> None:
    value = separator.join(("010", "5110", "7263"))
    found = detect_all(f"휴대전화 번호: {value}", max_results_per_type=20)

    assert [item["matchString"] for item in found.get("MN", [])] == [value]


@pytest.mark.parametrize("separator", ["&", "/", ".", "'", "`", "|"])
def test_account_labeled_alternate_separator_matrix(separator: str) -> None:
    value = separator.join(("4716", "1292", "3626", "7849"))
    found = detect_all(f"입금 계좌: {value}", max_results_per_type=20)

    assert [item["matchString"] for item in found.get("BN", [])] == [value]
    assert found.get("CN", []) == []


@pytest.mark.parametrize(
    ("out_key", "text", "expected"),
    [
        ("MN", "010&5110&7263", "010&5110&7263"),
        ("MN", "query=010&5110&7263", "010&5110&7263"),
        ("MN", "전화번호: 010&5110|7263", "010&5110|7263"),
        ("BN", "계좌번호 4716/1292.3626|7849", "4716/1292.3626|7849"),
        ("BN", "계좌번호\n4716/1292/3626/7849", "4716/1292/3626/7849"),
        ("BN", "계좌번호          4716/1292/3626/7849", "4716/1292/3626/7849"),
    ],
)
def test_poc_detects_unlabeled_mixed_and_distant_numeric_values(
    out_key: str,
    text: str,
    expected: str,
) -> None:
    found = detect_all(text, max_results_per_type=20)

    assert [item["matchString"] for item in found.get(out_key, [])] == [expected]


def test_horizontal_space_around_same_separator_is_supported() -> None:
    phone = "010 & 5110 & 7263"
    account = "4716 / 1292 / 3626 / 7849"
    found = detect_all(f"연락처: {phone}, 계좌번호: {account}", max_results_per_type=20)

    assert [item["matchString"] for item in found.get("MN", [])] == [phone]
    assert [item["matchString"] for item in found.get("BN", [])] == [account]


def test_existing_dot_phone_path_does_not_duplicate_match() -> None:
    value = "010.5110.7263"
    found = detect_all(f"연락처: {value}", max_results_per_type=20)

    assert [item["matchString"] for item in found.get("MN", [])] == [value]


def test_strict_16_digit_exception_is_limited_to_labeled_alternate_path() -> None:
    alternate = detect_all(
        "계좌번호 4716/1292/3626/7849",
        max_results_per_type=20,
        ruleset="strict",
    )
    ordinary = detect_all(
        "계좌번호 4716-1292-3626-7849",
        max_results_per_type=20,
        ruleset="strict",
    )

    assert [item["matchString"] for item in alternate.get("BN", [])] == ["4716/1292/3626/7849"]
    assert ordinary.get("BN", []) == []


def test_explicit_labels_control_ambiguous_alternate_number_type() -> None:
    phone = detect_all("전화번호: 010&5110&7263", max_results_per_type=20)
    account = detect_all("계좌번호: 010&5110&7263", max_results_per_type=20)

    assert [item["matchString"] for item in phone.get("MN", [])] == ["010&5110&7263"]
    assert phone.get("BN", []) == []
    assert [item["matchString"] for item in account.get("BN", [])] == ["010&5110&7263"]
    assert account.get("MN", []) == []


def test_repeated_single_digit_noise_is_not_promoted() -> None:
    found = detect_all("000&000&0000", max_results_per_type=20)

    assert found.get("MN", []) == []
    assert found.get("BN", []) == []
