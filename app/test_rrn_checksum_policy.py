from app.pii_engine.common import (
    rrn_birth_date_tuple,
    rrn_checksum_policy_status,
    rrn_checksum_valid,
    rrn_uses_random_serial_candidate,
)


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
