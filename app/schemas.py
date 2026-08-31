from __future__ import annotations

from pydantic import BaseModel, Field
from typing import List, Literal, Optional


class DetectPiiRequest(BaseModel):
    # Large payloads are handled by split/fast-path logic in app.pii.
    text: str = Field(min_length=1, max_length=10000000)
    max_results_per_type: int = Field(default=500, ge=1, le=5000)


class MatchItem(BaseModel):
    start: int
    end: int
    matchString: str
    isValid: Optional[bool] = None  
    checksum_status: Optional[str] = None
    context_score: Optional[float] = None
    context_score_norm: Optional[float] = None
    context_hybrid_score: Optional[float] = None
    context_method: Optional[str] = None
    context_accept_by: Optional[str] = None
    context_pass: Optional[bool] = None
    detected_by: Optional[str] = None


class PiiData(BaseModel):
    SN_CNT: Optional[int] = None
    SN: Optional[List[MatchItem]] = None
    FN_CNT: Optional[int] = None
    FN: Optional[List[MatchItem]] = None
    SSN_CNT: Optional[int] = None
    SSN: Optional[List[MatchItem]] = None
    DN_CNT: Optional[int] = None
    DN: Optional[List[MatchItem]] = None
    PN_CNT: Optional[int] = None
    PN: Optional[List[MatchItem]] = None
    MN_CNT: Optional[int] = None
    MN: Optional[List[MatchItem]] = None
    BN_CNT: Optional[int] = None
    BN: Optional[List[MatchItem]] = None
    BRN_CNT: Optional[int] = None
    BRN: Optional[List[MatchItem]] = None
    AN_CNT: Optional[int] = None
    AN: Optional[List[MatchItem]] = None
    CN_CNT: Optional[int] = None
    CN: Optional[List[MatchItem]] = None
    CPN_CNT: Optional[int] = None
    CPN: Optional[List[MatchItem]] = None
    CRN_CNT: Optional[int] = None
    CRN: Optional[List[MatchItem]] = None
    IMEI_CNT: Optional[int] = None
    IMEI: Optional[List[MatchItem]] = None
    MCN_CNT: Optional[int] = None
    MCN: Optional[List[MatchItem]] = None
    EML_CNT: Optional[int] = None
    EML: Optional[List[MatchItem]] = None
    VN_CCCD_CNT: Optional[int] = None
    VN_CCCD: Optional[List[MatchItem]] = None
    VN_MN_CNT: Optional[int] = None
    VN_MN: Optional[List[MatchItem]] = None
    VN_PN_CNT: Optional[int] = None
    VN_PN: Optional[List[MatchItem]] = None
    VN_TIN_CNT: Optional[int] = None
    VN_TIN: Optional[List[MatchItem]] = None
    VN_SI_CNT: Optional[int] = None
    VN_SI: Optional[List[MatchItem]] = None
    OTP_CNT: Optional[int] = None
    OTP: Optional[List[MatchItem]] = None
    API_KEY_CNT: Optional[int] = None
    API_KEY: Optional[List[MatchItem]] = None
    AUTH_TOKEN_CNT: Optional[int] = None
    AUTH_TOKEN: Optional[List[MatchItem]] = None
    PASSWORD_CNT: Optional[int] = None
    PASSWORD: Optional[List[MatchItem]] = None
    INTERNAL_ACCESS_CNT: Optional[int] = None
    INTERNAL_ACCESS: Optional[List[MatchItem]] = None
    PRIVATE_KEY_CNT: Optional[int] = None
    PRIVATE_KEY: Optional[List[MatchItem]] = None
    CLOUD_CREDENTIAL_CNT: Optional[int] = None
    CLOUD_CREDENTIAL: Optional[List[MatchItem]] = None
    CONNECTION_STRING_CNT: Optional[int] = None
    CONNECTION_STRING: Optional[List[MatchItem]] = None
    SIGNED_URL_CNT: Optional[int] = None
    SIGNED_URL: Optional[List[MatchItem]] = None
    MFA_SECRET_CNT: Optional[int] = None
    MFA_SECRET: Optional[List[MatchItem]] = None
    RECOVERY_CODE_CNT: Optional[int] = None
    RECOVERY_CODE: Optional[List[MatchItem]] = None
    SESSION_COOKIE_CNT: Optional[int] = None
    SESSION_COOKIE: Optional[List[MatchItem]] = None

class PiiMeta(BaseModel):
    ruleset_name: str
    ruleset_version: str
    ruleset_updated_at: str


class DetectPiiResponse(BaseModel):
    success: bool
    status: int
    data: PiiData
    meta: PiiMeta | None = None


class DetectPiiFileResponse(DetectPiiResponse):
    filename: str
    extracted_text_length: int


class DetectionExclusionUploadResponse(BaseModel):
    success: bool
    status: int
    path: str
    updated_at: str
    total_values: int
    type_counts: dict[str, int]


class GrpcTestRequest(BaseModel):
    target: str = Field(default="api-grpc:50051", min_length=3, max_length=255)
    method: Literal["Health", "Detect"] = "Health"
    use_tls: bool = False
    timeout_sec: float = Field(default=10.0, ge=0.5, le=60.0)
    text: str = Field(default="", max_length=10000000)
    max_results_per_type: int = Field(default=500, ge=1, le=5000)
    ruleset: Optional[str] = Field(default=None, max_length=120)
