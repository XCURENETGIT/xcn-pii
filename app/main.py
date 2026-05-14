from __future__ import annotations

import logging
import os
import time
import hashlib
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.schemas import DetectPiiFileResponse, DetectPiiRequest, DetectPiiResponse, GrpcTestRequest
from app.pii import detect_all, detect_with_meta
from app.pii_engine import preload_models
from app.rules_loader import list_rulesets, load_rules
from app.context_debug_api import router as debug_router
from app.file_text_extract import TextExtractError, extract_text_from_file
from app.guardrail import evaluate_guardrail
from app.logging_utils import setup_file_logging
from app.response_builders import build_detect_response
from app.version import APP_VERSION


setup_file_logging()

app = FastAPI(title="PII Detector (Hyperscan + re)", version=APP_VERSION)
app.include_router(debug_router)
logger = logging.getLogger("pii.api")

app.mount("/static", StaticFiles(directory="app/static"), name="static")


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return int(default)
    try:
        return int(str(v).strip())
    except Exception:
        return int(default)


def _http_max_upload_bytes() -> int:
    mb = _env_int("PII_HTTP_MAX_UPLOAD_MB", 100)
    return max(1, mb) * 1024 * 1024


def _truncate_request_text(text: str, limit: int | None = None) -> str:
    normalized = str(text or "").replace("\r", " ").replace("\n", " ").strip()
    max_chars = max(16, limit or _env_int("PII_LOG_REQUEST_TEXT_LIMIT", 240))
    if len(normalized) <= max_chars:
        return normalized
    return normalized[:max_chars] + "..."


def _grpc_channel(target: str, use_tls: bool):
    import grpc

    if use_tls:
        return grpc.secure_channel(target, grpc.ssl_channel_credentials())
    return grpc.insecure_channel(target)


def _grpc_test_default_target() -> str:
    return os.getenv("PII_GRPC_TEST_TARGET", "api-grpc:50051").strip() or "api-grpc:50051"


@app.on_event("startup")
def preload_pii_models() -> None:
    if not _env_bool("PII_MODEL_PRELOAD_ENABLED", True):
        logger.info("PII model preload disabled")
        return
    try:
        warmed = preload_models()
        logger.info(
            "PII model preload complete. rulesets=%d models=%d type_embeddings=%d",
            int(warmed.get("rulesets", 0)),
            int(warmed.get("models", 0)),
            int(warmed.get("type_embeddings", 0)),
        )
    except Exception:
        logger.exception("PII model preload failed")


@app.get("/")
def root():
    return FileResponse("app/static/index.html")


@app.post("/pii/detect", response_model=DetectPiiResponse, response_model_exclude_none=True)
def pii_detect(
    req: DetectPiiRequest,
    x_pii_ruleset: str | None = Header(default=None, alias="X-PII-RULESET"),
):
    """PII 탐지.

    룰셋 스위칭
    -----------
    - 요청 헤더로 룰셋을 지정할 수 있습니다.
        X-PII-RULESET: strict
    - 헤더가 없으면 환경변수 PII_RULESET (기본: default)를 사용합니다.

    응답 meta
    ---------
    - ruleset_name / ruleset_version / ruleset_updated_at 을 포함해
      "어떤 룰"로 탐지했는지 추적 가능하게 합니다.
    """

    text = req.text or ""
    t0 = time.perf_counter()
    req_id = hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:8] if text else "empty"
    logger.info(
        "[request] /pii/detect\n"
        "  req=%s chars=%d bytes=%d max_results_per_type=%d ruleset=%s\n"
        "  text=%s",
        req_id,
        len(text),
        len(text.encode("utf-8", errors="ignore")),
        int(req.max_results_per_type or 0),
        x_pii_ruleset or os.getenv("PII_RULESET", "default"),
        _truncate_request_text(text),
    )

    t_detect = time.perf_counter()
    found, meta = detect_with_meta(text, max_results_per_type=req.max_results_per_type, ruleset=x_pii_ruleset)
    detect_ms = (time.perf_counter() - t_detect) * 1000.0
    guardrail = evaluate_guardrail(text)

    total_ms = (time.perf_counter() - t0) * 1000.0
    logger.info(
        "[timing] /pii/detect\n"
        "  req=%s detect_ms=%.1f total_ms=%.1f\n"
        "  kept: SN=%d SSN=%d DN=%d PN=%d MN=%d BN=%d CN=%d EML=%d",
        req_id,
        detect_ms,
        total_ms,
        len(found.get("SN", [])),
        len(found.get("SSN", [])),
        len(found.get("DN", [])),
        len(found.get("PN", [])),
        len(found.get("MN", [])),
        len(found.get("BN", [])),
        len(found.get("CN", [])),
        len(found.get("EML", [])),
    )
    return build_detect_response(found, meta, guardrail=guardrail)


@app.post("/pii/detect/file", response_model=DetectPiiFileResponse, response_model_exclude_none=True)
async def pii_detect_file(
    file: UploadFile = File(...),
    max_results_per_type: int = Form(default=500),
    x_pii_ruleset: str | None = Header(default=None, alias="X-PII-RULESET"),
):
    if max_results_per_type < 1 or max_results_per_type > 5000:
        raise HTTPException(status_code=400, detail="max_results_per_type must be between 1 and 5000")
    if not file.filename:
        raise HTTPException(status_code=400, detail="filename is required")

    suffix = Path(file.filename).suffix or ".bin"
    max_upload_bytes = _http_max_upload_bytes()
    payload_size = 0
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="pii-upload-", suffix=suffix, delete=False) as tmp:
            tmp_path = Path(tmp.name)
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                payload_size += len(chunk)
                if payload_size > max_upload_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large (max {max_upload_bytes // 1024 // 1024} MB)",
                    )
                tmp.write(chunk)
    except HTTPException:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("failed to remove temp upload file: %s", tmp_path)
        raise

    try:
        if tmp_path is None:
            raise HTTPException(status_code=500, detail="failed to create temp upload file")
        text = extract_text_from_file(tmp_path)
    except TextExtractError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            logger.warning("failed to remove temp upload file: %s", tmp_path)

    req_id = hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:8] if text else "empty"
    logger.info(
        "[request] /pii/detect/file\n"
        "  req=%s filename=%s extracted_chars=%d bytes=%d max_results_per_type=%d ruleset=%s\n"
        "  text=%s",
        req_id,
        file.filename,
        len(text),
        payload_size,
        max_results_per_type,
        x_pii_ruleset or os.getenv("PII_RULESET", "default"),
        _truncate_request_text(text),
    )
    found, meta = detect_with_meta(text, max_results_per_type=max_results_per_type, ruleset=x_pii_ruleset)
    guardrail = evaluate_guardrail(text)
    result = build_detect_response(found, meta, guardrail=guardrail)
    return DetectPiiFileResponse(
        **result.model_dump(),
        filename=file.filename,
        extracted_text_length=len(text),
    )

@app.get("/pii/rulesets")
def pii_rulesets():
    """서버가 인식하는 룰셋 목록을 반환합니다.

    - rules_dir: PII_RULES_DIR(기본: app/rules)
    - _ruleset.yaml          -> default
    - _ruleset_<name>.yaml   -> <name>

    각 룰셋의 version/updated_at 도 함께 제공합니다.
    """
    rules_dir = os.getenv("PII_RULES_DIR", "app/rules")
    names = list_rulesets(rules_dir)

    out = []
    for name in names:
        try:
            b = load_rules(rules_dir=rules_dir, ruleset_name=name)
            out.append({
                "ruleset_name": b.ruleset_name,
                "ruleset_version": b.version,
                "ruleset_updated_at": b.updated_at,
                "ruleset_path": str(b.ruleset_path),
            })
        except Exception as e:
            out.append({"ruleset_name": name, "error": str(e)})

    return {"rules_dir": rules_dir, "rulesets": out}


@app.get("/pii/selftest")
def pii_selftest():
    sample = (
        "SN=900101-1234567 "
        "DN=11-22-333333-44 "
        "PN=M12345678 "
        "MN=010-1234-5678 "
        "SSN=123-45-6789 "
        "EML=test.user+aa@company.co.kr "
        "CN=4111-1111-1111-1111"
    )
    found = detect_all(sample, max_results_per_type=50)
    return {
        "sample": sample,
        "counts": {k: len(v) for k, v in found.items()},
        "found": found,
    }


@app.get("/grpc/test/defaults")
def grpc_test_defaults():
    return {
        "target": _grpc_test_default_target(),
        "timeout_sec": float(os.getenv("PII_GRPC_TEST_TIMEOUT_SEC", "10") or "10"),
    }


@app.post("/grpc/test")
def grpc_test(req: GrpcTestRequest):
    try:
        import grpc
        from google.protobuf.json_format import MessageToDict
        from app.proto import pii_pb2, pii_pb2_grpc
    except ModuleNotFoundError as exc:
        return {
            "ok": False,
            "method": req.method,
            "target": (req.target or _grpc_test_default_target()).strip(),
            "use_tls": req.use_tls,
            "elapsed_ms": 0.0,
            "error": {
                "type": "dependency",
                "message": f"gRPC test bridge dependency missing: {exc.name}",
            },
        }

    target = (req.target or _grpc_test_default_target()).strip()
    t0 = time.perf_counter()
    try:
        with _grpc_channel(target, req.use_tls) as channel:
            stub = pii_pb2_grpc.PiiDetectorStub(channel)
            if req.method == "Health":
                response = stub.Health(
                    pii_pb2.HealthRequest(),
                    timeout=req.timeout_sec,
                )
            else:
                response = stub.Detect(
                    pii_pb2.DetectRequest(
                        text=req.text or "",
                        max_results_per_type=int(req.max_results_per_type or 500),
                        ruleset=(req.ruleset or "").strip(),
                    ),
                    timeout=req.timeout_sec,
                )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        logger.info(
            "[grpc-test] method=%s target=%s tls=%s elapsed_ms=%.1f ok=true",
            req.method,
            target,
            str(req.use_tls).lower(),
            elapsed_ms,
        )
        return {
            "ok": True,
            "method": req.method,
            "target": target,
            "use_tls": req.use_tls,
            "elapsed_ms": round(elapsed_ms, 1),
            "response": MessageToDict(response, preserving_proto_field_name=True),
        }
    except grpc.RpcError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        logger.warning(
            "[grpc-test] method=%s target=%s tls=%s elapsed_ms=%.1f ok=false code=%s detail=%s",
            req.method,
            target,
            str(req.use_tls).lower(),
            elapsed_ms,
            getattr(exc.code(), "name", str(exc.code())),
            exc.details(),
        )
        return {
            "ok": False,
            "method": req.method,
            "target": target,
            "use_tls": req.use_tls,
            "elapsed_ms": round(elapsed_ms, 1),
            "error": {
                "type": "grpc",
                "code": getattr(exc.code(), "name", str(exc.code())),
                "details": exc.details(),
            },
        }
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        logger.exception("[grpc-test] unexpected failure method=%s target=%s", req.method, target)
        return {
            "ok": False,
            "method": req.method,
            "target": target,
            "use_tls": req.use_tls,
            "elapsed_ms": round(elapsed_ms, 1),
            "error": {
                "type": "unexpected",
                "message": str(exc),
            },
        }
