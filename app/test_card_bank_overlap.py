from app.pii import detect_all
from app.pii_engine.common import DetectContext
from app.pii_engine.detectors import HSRegexDetector


def test_card_number_overlap_keeps_card_and_drops_partial_bank_number() -> None:
    text = "안내문 작성해줘. 결제 카드 4532-1234-5678-9014 입니다."

    found = detect_all(text, max_results_per_type=20)

    assert [x["matchString"] for x in found.get("CN", [])] == ["4532-1234-5678-9014"]
    assert found.get("BN", []) == []


class _FakeHyperscanDb:
    def __init__(self, value: str) -> None:
        self.value = value

    def detect(self, text: str) -> list[dict]:
        start = text.index(self.value)
        return [{"start": start, "end": start + len(self.value), "matchString": self.value}]


def test_hyperscan_card_path_applies_luhn_validation() -> None:
    invalid = "4111-1111-1111-1112"
    text = f"카드번호 {invalid}"
    detector = HSRegexDetector(
        "CN",
        hs_db=_FakeHyperscanDb(invalid),
        enabled=True,
        max_match_len=32,
    )
    ctx = DetectContext(text=text, max_results=10, out={})

    detector.run(ctx)

    assert ctx.get("CN") == []
