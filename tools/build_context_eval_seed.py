from __future__ import annotations

import json
from pathlib import Path


SAMPLES = [
    ("SN", "890512-2054508", "주민등록번호", "resident registration number", "문서 관리 코드"),
    ("FN", "900101-5123450", "외국인등록번호", "alien registration number", "회원 조회 코드"),
    ("SSN", "123-45-6789", "social security number", "미국 사회보장번호", "배송 추적 코드"),
    ("DN", "11-22-333333-44", "운전면허번호", "driver license number", "제품 일련 코드"),
    ("PN", "M12345678", "여권번호", "여권 No", "제품 모델 번호"),
    ("BRN", "110-81-40818", "사업자등록번호", "business registration number", "접수 처리 코드"),
    ("BN", "123456-01-123456", "계좌번호", "bank account number", "거래 참조 번호"),
    ("CN", "4111-1111-1111-1111", "카드번호", "credit card number", "주문 승인 코드"),
    ("CPN", "110111-1234569", "법인등록번호", "corporate registration number", "문서 등록 코드"),
    ("CRN", "123가 4567", "차량등록번호", "vehicle registration number", "주차 위치 코드"),
    ("IMEI", "490154203237518", "IMEI", "mobile equipment identity", "제품 일련번호"),
    ("MCN", "AA:BB:CC:DD:EE:FF", "MAC 주소", "MAC address", "장비 표시 문자열"),
    ("VN_CCCD", "001234567890", "CCCD", "can cuoc cong dan", "ma don hang"),
    ("VN_MN", "098-123-4567", "so dien thoai", "베트남 휴대폰", "ma giao dich"),
    ("VN_PN", "B12345678", "ho chieu", "베트남 여권번호", "ma san pham"),
    ("VN_TIN", "0312345678-001", "ma so thue", "베트남 세금번호", "ma don hang"),
    ("VN_SI", "0123456789", "ma so BHXH", "베트남 사회보험번호", "ma giao dich"),
]


def build_items() -> list[dict]:
    items: list[dict] = []
    for pii_type, match, primary_label, alternate_label, neutral_context in SAMPLES:
        prefix = pii_type.lower()
        items.extend(
            [
                {
                    "id": f"{prefix}_positive_primary",
                    "type": pii_type,
                    "match": match,
                    "label": 1,
                    "text": f"{primary_label}: {match}",
                    "case_kind": "positive_label",
                },
                {
                    "id": f"{prefix}_positive_alternate",
                    "type": pii_type,
                    "match": match,
                    "label": 1,
                    "text": f"{alternate_label}: {match}",
                    "case_kind": "positive_alias",
                },
                {
                    "id": f"{prefix}_negative_hard",
                    "type": pii_type,
                    "match": match,
                    "label": 0,
                    "text": f"테스트용 {primary_label}: {match}",
                    "case_kind": "negative_hard_marker",
                },
                {
                    "id": f"{prefix}_negative_neutral",
                    "type": pii_type,
                    "match": match,
                    "label": 0,
                    "text": f"{neutral_context}: {match}",
                    "case_kind": "negative_neutral_context",
                },
                {
                    "id": f"{prefix}_positive_spacing",
                    "type": pii_type,
                    "match": match,
                    "label": 1,
                    "text": f"고객 자료 | {primary_label}    {match} | 확인",
                    "case_kind": "positive_spacing",
                },
                {
                    "id": f"{prefix}_positive_distant_negative",
                    "type": pii_type,
                    "match": match,
                    "label": 1,
                    "text": f"테스트용 예시 코드는 이전 행에만 있습니다.\n{primary_label}: {match}",
                    "case_kind": "positive_distant_negative",
                },
                {
                    "id": f"{prefix}_negative_postfix_hard",
                    "type": pii_type,
                    "match": match,
                    "label": 0,
                    "text": f"{primary_label}: {match} 샘플",
                    "case_kind": "negative_postfix_hard_marker",
                },
                {
                    "id": f"{prefix}_negative_marker_boundary",
                    "type": pii_type,
                    "match": match,
                    "label": 0,
                    "text": f"latest release {neutral_context}: {match}",
                    "case_kind": "negative_marker_word_boundary",
                },
            ]
        )
    return items


def main() -> None:
    output = Path(__file__).with_name("context_eval.json")
    payload = {
        "schema_version": 3,
        "dataset_kind": "synthetic_adversarial",
        "description": (
            "문맥 평가 파이프라인과 유형별 기본·경계·교란 회귀를 검증하기 위한 합성 평가셋. "
            "운영 precision/recall 확정에는 별도의 비식별 대표 데이터셋을 사용해야 한다."
        ),
        "target_policy": "context.target_keys only; intentionally excluded types are not included",
        "items": build_items(),
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(payload['items'])} items to {output}")


if __name__ == "__main__":
    main()
