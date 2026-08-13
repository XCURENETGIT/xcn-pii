from fastapi import FastAPI, HTTPException, APIRouter
from pydantic import BaseModel, ConfigDict
from typing import Optional
from starlette.concurrency import run_in_threadpool

from .pii_engine import (
    detect,
    DetectContext,
    ContextualPostFilter,
    ContextualLLMPostFilter,
)
from .pii_engine.common import _request_id

app = FastAPI(title="PII Context Debug API")
router = APIRouter()


class DebugRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    text: str
    method: Optional[str] = "embed"  # embed or keyword
    window_sentences: Optional[int] = 2
    sim_threshold: Optional[float] = None
    model_name: Optional[str] = None
    target_keys: Optional[list[str]] = None
    ruleset: Optional[str] = None
    use_pipeline_config: bool = True


@router.post("/debug/context")
async def debug_context(req: DebugRequest):
    text = req.text or ""
    if not text.strip():
        raise HTTPException(status_code=400, detail="text is required")

    # Use the configured production pipeline by default. Per-request debug
    # preserves the scores of context-rejected candidates and prevents model,
    # threshold or target-key drift between debugging and normal detection.
    if req.use_pipeline_config:
        found = await run_in_threadpool(
            detect,
            text=text,
            ruleset=req.ruleset,
            include_context_debug=True,
        )
        debug_items = list(found.get("__context_debug", []) or [])
        visible_found = {key: value for key, value in found.items() if key != "__context_debug"}
        return {
            "found": visible_found,
            "debug": debug_items,
            "mode": "pipeline",
            "ruleset": req.ruleset or "default",
        }

    # Retain custom model/threshold comparison as an explicit experimental
    # mode; its output must not be used as production threshold evidence.
    found = await run_in_threadpool(detect, text=text, ruleset=req.ruleset)

    # Create a DetectContext wrapper so we can run post-filter and capture debug
    ctx = DetectContext(text=text, source_text=text, max_results=500, out=found, request_id=_request_id(text))

    target_keys = req.target_keys or [
        "SN", "FN", "SSN", "DN", "PN", "MN", "BN", "CN", "CPN", "CRN", "IMEI", "MCN", "EML",
        "VN_CCCD", "VN_MN", "VN_PN", "VN_TIN", "VN_SI",
    ]

    if (req.method or "embed").lower() in ("embed", "semantic"):
        filt = ContextualLLMPostFilter(
            enabled=True,
            target_keys=target_keys,
            window_sentences=req.window_sentences,
            sim_threshold=req.sim_threshold if req.sim_threshold is not None else 0.55,
            model_name=req.model_name or "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
            debug=True,
        )
    else:
        filt = ContextualPostFilter(enabled=True, target_keys=target_keys, window_sentences=req.window_sentences, threshold=1, debug=True)

    # Run filter which will populate ctx.out and ctx.out['__context_debug'] when debug
    filt.run(ctx)

    # Return results and any debug entries
    result = {
        "found": ctx.out,
        "debug": ctx.out.get("__context_debug", []),
        "mode": "custom",
    }
    return result


app.include_router(router)
