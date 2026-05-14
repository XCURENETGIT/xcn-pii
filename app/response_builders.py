from __future__ import annotations

from app.schemas import DetectPiiResponse, GuardrailResult, MatchItem, PiiData, PiiMeta


def build_detect_response(found: dict, meta: dict | None, guardrail: dict | None = None) -> DetectPiiResponse:
    data_kwargs = {}
    for key in ("SN", "SSN", "DN", "PN", "MN", "BN", "CN", "EML"):
        values = found.get(key, []) or []
        if not values:
            continue
        data_kwargs[f"{key}_CNT"] = len(values)
        data_kwargs[key] = [MatchItem(**x) for x in values]
    data = PiiData(**data_kwargs)
    guardrail_result = GuardrailResult(**guardrail) if guardrail else None
    return DetectPiiResponse(success=True, status=200, data=data, meta=PiiMeta(**(meta or {})), guardrail=guardrail_result)
