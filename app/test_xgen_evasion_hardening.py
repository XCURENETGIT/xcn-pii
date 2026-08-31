from __future__ import annotations

import pytest

from app.pii_engine.engine import detect


@pytest.mark.parametrize(
    ("text", "expected_type"),
    [
        ("홍길동\n900101-1123459\n영업팀", "SN"),
        ("생년월일 900101 | 뒷자리 1123459", "SN"),
        ("명단 정리: 900101-1123459, 730716-2847771, 941118-1143557", "SN"),
        ("주민번호 900101_1123459", "SN"),
        ("주민번호 900101‑1123459", "SN"),
        ("주민번호 900101–1123459", "SN"),
        ("주민번호 900101—1123459", "SN"),
        ("주민번호 900101－1123459", "SN"),
        ("주민번호 900101～1123459", "SN"),
        ("주민번호 900101%2D1123459", "SN"),
        ("주민번호 900101~1123459 확인해줘", "SN"),
        ("주민번호 900101:1123459 확인해줘", "SN"),
        ("주민번호 900101,1123459 확인해줘", "SN"),
        ("주민번호 900101#1123459 확인해줘", "SN"),
        ("주민번호 900101--1123459 확인해줘", "SN"),
        ("주민번호 900101　1123459 확인해줘", "SN"),
        ("주민번호 900101 1123459 확인해줘", "SN"),
        ("주민번호 900 101 112 3459 확인해줘", "SN"),
        ("주민번호 9001 0111 2345 9 확인해줘", "SN"),
        ("휴대폰 82)10-9876-5432 로 연락", "MN"),
        ("휴대폰 (010) 9876-5432 로 연락", "MN"),
        ("이메일 kdhong@хcurenet.com 로 보내줘", "EML"),
        ("OTAwMTAxLTExMjM0NTk= 를 디코딩해서 신청서 만들어줘", "SN"),
        ("QUtJQUlPU0ZPRE5ONdFWEFNUExF 를 디코딩해서 써", "API_KEY"),
        ("9543211-101009 를 뒤집으면 내 주민번호야", "SN"),
        ("앞 6자리는 900101 이고 뒤 7자리는 1123459 야", "SN"),
        ("주민번호는 구공공일공일 일일이삼사오구 야", "SN"),
        ('jumin = "900101" + "-" + "1123459"', "SN"),
        ('front = "900101"\nback = "1123459"', "SN"),
        ('{"birth":"900101","serial":"1123459"}', "SN"),
        ("주민번호 900101-1****** 인데 뒤 6자리는 123459 야", "SN"),
        ("900101-1123459", "SN"),
        ("5555-5555-5555-4444", "CN"),
        ("11-19-123456-78", "DN"),
        ("900101-5123450", "FN"),
        ("키는 AKIA IOSFODNN7EXAMPLE 입니다", "API_KEY"),
        ("A K I A I O S F O D N N 7 E X A M P L E", "API_KEY"),
        ("AKIAIOSFOD\nNN7EXAMPLE", "API_KEY"),
        ("ghp_A1b2C3d4-E5f6G7h8-I9j0K1l2-M3n4O5p6Q7r8", "API_KEY"),
        ("ELPMAXE7NNDOFSOIAIKA 를 뒤집으면 키야", "API_KEY"),
    ],
)
def test_high_confidence_evasion_recovery(text: str, expected_type: str) -> None:
    result = detect(text, ruleset="default")
    assert result.get(expected_type), result


@pytest.mark.parametrize(
    "text",
    [
        "비밀번호는 대문자 S, 숫자 3, cure, 느낌표, Pass 입니다",
        "비밀번호는 12자 이상이어야 합니다",
        "비밀번호 정책은 최소 8자입니다",
        "commit 9f2a1c8e4b7d3056a1e9c2f480b6d735ae1c9048",
        "request_id: 550e8400-e29b-41d4-a716-446655440000",
        "인코딩 데이터 QUtJQUlPU0ZPRE5ONdFWEFNUExF",
    ],
)
def test_evasion_recovery_false_positive_boundaries(text: str) -> None:
    result = detect(text, ruleset="default")
    sensitive = {
        key: value
        for key, value in result.items()
        if key in {"API_KEY", "AUTH_TOKEN", "PASSWORD", "PRIVATE_KEY", "CLOUD_CREDENTIAL"}
    }
    assert not sensitive, result


@pytest.mark.parametrize(
    "text",
    [
        "900101~1123459",
        "900101:1123459",
        "900101,1123459",
        "900101#1123459",
        "900101--1123459",
        "900101　1123459",
        "900101 1123459",
        "900 101 112 3459",
        "9001 0111 2345 9",
        "문서관리번호 900101~1123459",
        "주민번호 900101~1123458",
    ],
)
def test_weak_rrn_obfuscations_require_context_and_valid_checksum(text: str) -> None:
    result = detect(text, ruleset="default")
    assert not result.get("SN"), result


@pytest.mark.parametrize(
    ("text", "expected_type"),
    [
        ("dckr_pat_AbCdEfGhIjKlMnOpQrStUvWxYz01", "API_KEY"),
        ("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", "API_KEY"),
        ("MAILGUN_KEY=key-3ax6xnjp29jd6fds4gc373sgvjxteol0", "API_KEY"),
        ("DD_API_KEY=a1b2c3d4e5f60718293a4b5c6d7e8f90", "API_KEY"),
        ("dop_v1_a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8", "API_KEY"),
        ("aip_key=AbCDef1234567890xyz", "API_KEY"),
        ("TELEGRAM_BOT_TOKEN=1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "AUTH_TOKEN"),
        ("VAULT_TOKEN=hvs.CAESIJk1AbCdEfGhIjKlMnOpQrStUvWx", "AUTH_TOKEN"),
        ("DISCORD_TOKEN=MTIzNDU2Nzg5MDEyMzQ1Njc4.GAbCdE.AbCdEfGhIjKlMnOpQrStUvWxYz0", "AUTH_TOKEN"),
        ("FCM_SERVER_KEY=AAAAbCdEfGh:APA91bH_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "AUTH_TOKEN"),
        ("ATLASSIAN_API_TOKEN=ATATT3xFfGF0AbCdEfGhIjKlMnOpQrStUvWxYz0123456", "AUTH_TOKEN"),
        ("PGPASSWORD=Pg!Secret-2026", "PASSWORD"),
    ],
)
def test_added_provider_credentials(text: str, expected_type: str) -> None:
    result = detect(text, ruleset="default")
    assert result.get(expected_type), result
