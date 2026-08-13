from app.pii_engine.common import (
    DetectContext,
    rrn_birth_date_tuple,
    rrn_candidate_shape,
    rrn_checksum_policy_status,
    rrn_checksum_valid,
    rrn_uses_random_serial_candidate,
    rrn_structure_valid,
)
from app.pii_engine.pipeline_builder import build_pipeline
from app.rules_loader import load_rules


def test_rrn_checksum_policy_keeps_legacy_checksum_behavior():
    assert rrn_checksum_valid("890512-2054508") is True
    assert rrn_checksum_policy_status("890512-2054508") == "checksum_pass"

    assert rrn_checksum_valid("900101-1234567") is False
    assert rrn_checksum_policy_status("900101-1234567") == "checksum_fail"


def test_rrn_checksum_policy_skips_checksum_for_new_system_birth_dates():
    assert rrn_birth_date_tuple("201005-3123456") == (2020, 10, 5)
    assert rrn_uses_random_serial_candidate("201005-3123456") is True
    assert rrn_checksum_valid("201005-3123456") is False
    assert rrn_checksum_policy_status("201005-3123456") == "new_system_checksum_skipped"


def test_rrn_checksum_policy_cutoff_is_birth_date_based():
    assert rrn_birth_date_tuple("201004-4123456") == (2020, 10, 4)
    assert rrn_uses_random_serial_candidate("201004-4123456") is False
    assert rrn_checksum_policy_status("201004-4123456") == "checksum_fail"


def test_invalid_birth_date_rrn_shapes_do_not_fall_back_to_bank_number():
    bundle = load_rules(rules_dir="app/rules", ruleset_name="default")
    pipeline = build_pipeline(bundle)
    cases = [
        "잘못된 월 주민등록번호: 201305-3123456 미검출",
        "잘못된 일자 주민등록번호: 201032-3123456 미검출",
        "존재하지 않는 날짜 주민등록번호: 210230-3123456 미검출",
    ]

    for text in cases:
        ctx = DetectContext(text=text, max_results=20, out={})
        for detector in pipeline:
            detector.run(ctx)

        assert ctx.get("SN") == []
        assert ctx.get("BN") == []


def test_invalid_birth_date_rrn_shapes_are_rejected_as_rrn_like_noise():
    for value in ["201305-3123456", "201032-3123456", "210230-3123456"]:
        assert rrn_candidate_shape(value) is True
        assert rrn_structure_valid(value) is False
        assert rrn_checksum_policy_status(value) == "checksum_fail"


def test_rrn_flexible_spacing_and_delimiter_variants_are_detected():
    bundle = load_rules(rules_dir="app/rules", ruleset_name="default")
    pipeline = build_pipeline(bundle)
    cases = [
        "홍길동 890512 2054508",
        "홍길동 890512\t2054508",
        "홍길동 890512 - 2054508",
        "홍길동 8 9 0 5 1 2 - 2 0 5 4 5 0 8",
        "홍길동 8 9 0 5 1 2 2 0 5 4 5 0 8",
        "홍길동 890512*2054508",
        "홍길동 890512/2054508",
    ]

    for text in cases:
        ctx = DetectContext(text=text, max_results=20, out={})
        for detector in pipeline:
            detector.run(ctx)

        assert len(ctx.get("SN") or []) == 1
        assert ctx.get("SN")[0]["matchString"] == text.replace("홍길동 ", "")
        assert ctx.get("SN")[0]["checksum_status"] == "checksum_pass"


def test_rrn_space_separator_does_not_cross_newline():
    bundle = load_rules(rules_dir="app/rules", ruleset_name="default")
    pipeline = build_pipeline(bundle)
    ctx = DetectContext(text="주번 890512\n2054508", max_results=20, out={})

    for detector in pipeline:
        detector.run(ctx)

    assert ctx.get("SN") == []
