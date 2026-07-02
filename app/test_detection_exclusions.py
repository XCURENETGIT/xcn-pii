from app.detection_exclusions import (
    apply_detection_exclusions,
    parse_detection_exclusions,
    write_detection_exclusion_file,
)


def test_detection_exclusion_parser_accepts_supported_shapes():
    cfg = parse_detection_exclusions(
        {
            "values": ["test@example.com"],
            "types": {"SN": ["900101-1234567"]},
            "entries": [{"type": "MN", "value": "010-1234-5678"}],
            "CN": ["4111-1111-1111-1111"],
        }
    )

    assert cfg.total_values == 4
    assert cfg.type_counts == {"CN": 1, "MN": 1, "SN": 1}


def test_apply_detection_exclusions_filters_by_type_and_global_values(monkeypatch, tmp_path):
    path = tmp_path / "exclusions.json"
    monkeypatch.setenv("PII_DETECTION_EXCLUSION_FILE", str(path))
    write_detection_exclusion_file(
        {
            "values": ["test@example.com"],
            "types": {"SN": ["9001011234567"]},
        }
    )

    found = {
        "SN": [
            {"start": 0, "end": 14, "matchString": "900101-1234567"},
            {"start": 20, "end": 34, "matchString": "800101-1234567"},
        ],
        "EML": [{"start": 40, "end": 56, "matchString": "test@example.com"}],
    }

    filtered, removed = apply_detection_exclusions(found)

    assert removed == {"SN": 1, "EML": 1}
    assert [x["matchString"] for x in filtered["SN"]] == ["800101-1234567"]
    assert filtered["EML"] == []


def test_apply_detection_exclusions_supports_wildcard_suffix_prefix_and_contains(monkeypatch, tmp_path):
    path = tmp_path / "wildcard-exclusions.json"
    monkeypatch.setenv("PII_DETECTION_EXCLUSION_FILE", str(path))
    write_detection_exclusion_file(
        {
            "values": ["*shared*"],
            "types": {
                "SN": ["*1234567", "900101*", "*101123*"],
                "EML": ["*@example.com"],
            },
        }
    )

    found = {
        "SN": [
            {"matchString": "800101-1234567"},
            {"matchString": "900101-7654321"},
            {"matchString": "991011-2345678"},
            {"matchString": "700101-7654321"},
        ],
        "EML": [
            {"matchString": "user@example.com"},
            {"matchString": "user@company.co.kr"},
        ],
        "MN": [
            {"matchString": "010-shared-9999"},
            {"matchString": "010-2222-3333"},
        ],
    }

    filtered, removed = apply_detection_exclusions(found)

    assert removed == {"SN": 3, "EML": 1, "MN": 1}
    assert [x["matchString"] for x in filtered["SN"]] == ["700101-7654321"]
    assert [x["matchString"] for x in filtered["EML"]] == ["user@company.co.kr"]
    assert [x["matchString"] for x in filtered["MN"]] == ["010-2222-3333"]


def test_detection_exclusion_wildcard_counts_as_value():
    cfg = parse_detection_exclusions(
        {
            "values": ["*shared*"],
            "types": {"SN": ["*1234567", "900101*", "*101123*"]},
        }
    )

    assert cfg.total_values == 4
    assert cfg.type_counts == {"SN": 3}


def test_mn_exclusion_supports_separator_wildcard_payload(monkeypatch, tmp_path):
    path = tmp_path / "mn-wildcard-exclusions.json"
    monkeypatch.setenv("PII_DETECTION_EXCLUSION_FILE", str(path))
    write_detection_exclusion_file(
        {
            "types": {
                "AN": ["은평구1", "서울시*"],
                "BN": [],
                "BRN": [],
                "CN": [],
                "DN": [],
                "EML": [],
                "MN": ["010-*-9648", "*1234"],
                "PN": [],
                "SN": [],
                "SSN": [],
            }
        }
    )

    found = {
        "MN": [
            {"matchString": "010-2222-9648"},
            {"matchString": "01022229648"},
            {"matchString": "010-2222-1234"},
            {"matchString": "01022221234"},
            {"matchString": "010-2222-5678"},
        ]
    }

    filtered, removed = apply_detection_exclusions(found)

    assert removed == {"MN": 4}
    assert [x["matchString"] for x in filtered["MN"]] == ["010-2222-5678"]
