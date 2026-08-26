from __future__ import annotations

from app.schemas import DetectPiiResponse, MatchItem, PiiData, PiiMeta


def build_detect_response(found: dict, meta: dict | None) -> DetectPiiResponse:
    data_kwargs = {}
    for key in (
        "SN", "FN", "SSN", "DN", "PN", "MN", "BRN", "BN", "AN", "CN", "CPN", "CRN", "IMEI", "MCN", "EML",
        "VN_CCCD", "VN_MN", "VN_PN", "VN_TIN", "VN_SI",
        "OTP", "API_KEY", "AUTH_TOKEN", "PASSWORD", "INTERNAL_ACCESS",
    ):
        values = found.get(key, []) or []
        if not values:
            continue
        data_kwargs[f"{key}_CNT"] = len(values)
        data_kwargs[key] = [MatchItem(**x) for x in values]
    data = PiiData(**data_kwargs)
    return DetectPiiResponse(success=True, status=200, data=data, meta=PiiMeta(**(meta or {})))
