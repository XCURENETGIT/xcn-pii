from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

logger = logging.getLogger("pii.guardrail")

SGUARD_CONTENT_MODEL = "SamsungSDS-Research/SGuard-ContentFilter-2B-v1"
SGUARD_JAILBREAK_MODEL = "SamsungSDS-Research/SGuard-JailbreakFilter-2B-v1"


@dataclass
class GuardrailConfig:
    enabled: bool
    device: str
    max_chars: int
    fail_open: bool
    content_model: str
    jailbreak_model: str
    content_enabled: bool
    jailbreak_enabled: bool
    content_thresholds: tuple[float, float, float, float, float]
    jailbreak_threshold: float


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return int(default)
    try:
        return int(str(value).strip())
    except ValueError:
        return int(default)


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return float(default)
    try:
        return float(str(value).strip())
    except ValueError:
        return float(default)


def _env_float_tuple(name: str, default: tuple[float, ...], count: int) -> tuple[float, ...]:
    value = os.getenv(name)
    if not value:
        return default
    parts = [part.strip() for part in str(value).split(",") if part.strip()]
    out: list[float] = []
    for part in parts[:count]:
        try:
            out.append(float(part))
        except ValueError:
            out.append(default[len(out)])
    while len(out) < count:
        out.append(default[len(out)])
    return tuple(out)


def get_guardrail_config() -> GuardrailConfig:
    provider = os.getenv("PII_GUARDRAIL_PROVIDER", "sguard").strip().lower()
    if provider != "sguard":
        logger.warning("Unsupported guardrail provider=%s; using sguard", provider)

    return GuardrailConfig(
        enabled=_env_bool("PII_GUARDRAIL_ENABLED", False),
        device=os.getenv("PII_GUARDRAIL_DEVICE", "cuda").strip().lower() or "cuda",
        max_chars=max(200, _env_int("PII_GUARDRAIL_MAX_CHARS", 4000)),
        fail_open=_env_bool("PII_GUARDRAIL_FAIL_OPEN", True),
        content_model=os.getenv("PII_SGUARD_CONTENT_MODEL", SGUARD_CONTENT_MODEL).strip() or SGUARD_CONTENT_MODEL,
        jailbreak_model=os.getenv("PII_SGUARD_JAILBREAK_MODEL", SGUARD_JAILBREAK_MODEL).strip() or SGUARD_JAILBREAK_MODEL,
        content_enabled=_env_bool("PII_SGUARD_CONTENT_ENABLED", True),
        jailbreak_enabled=_env_bool("PII_SGUARD_JAILBREAK_ENABLED", True),
        content_thresholds=_env_float_tuple("PII_SGUARD_CONTENT_THRESHOLDS", (0.5, 0.5, 0.5, 0.5, 0.5), 5),
        jailbreak_threshold=_env_float("PII_SGUARD_JAILBREAK_THRESHOLD", 0.6),
    )


def _truncate_text(text: str, max_chars: int) -> str:
    text = (text or "").strip()
    if len(text) <= max_chars:
        return text
    head_chars = max(100, int(max_chars * 0.65))
    tail_chars = max(100, max_chars - head_chars - 40)
    return f"{text[:head_chars]}\n...[중간 생략]...\n{text[-tail_chars:]}"


@lru_cache(maxsize=2)
def _load_sguard_model(model_name: str, device: str):
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except Exception as exc:
        raise RuntimeError("torch/transformers is required for SGuard") from exc

    if device == "cuda":
        if not torch.cuda.is_available():
            raise RuntimeError("PII_GUARDRAIL_DEVICE=cuda requested but CUDA is not available")
        resolved_device = "cuda"
    else:
        resolved_device = "cpu"

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name, torch_dtype="auto").eval()
    model.to(resolved_device)
    logger.info("Loaded SGuard model=%s device=%s", model_name, resolved_device)
    return tokenizer, model, resolved_device


def _token_id(tokenizer, token: str) -> int:
    vocab = tokenizer.get_vocab()
    if token in vocab:
        return int(vocab[token])
    token_ids = tokenizer.encode(token, add_special_tokens=False)
    if len(token_ids) != 1:
        raise ValueError(f"token must map to a single id: {token}")
    return int(token_ids[0])


def _sguard_inputs(tokenizer, prompt: str, device: str, *, prompt_field: str):
    messages = [{"role": "user", prompt_field: prompt}]
    if hasattr(tokenizer, "apply_chat_template"):
        return tokenizer.apply_chat_template(
            messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
        ).to(device)
    return tokenizer(prompt, return_tensors="pt").to(device)


def _classify_sguard_jailbreak(prompt: str, config: GuardrailConfig) -> dict[str, Any]:
    import torch

    tokenizer, model, device = _load_sguard_model(config.jailbreak_model, config.device)
    safe_token_id = _token_id(tokenizer, "safe")
    unsafe_token_id = _token_id(tokenizer, "unsafe")
    inputs = _sguard_inputs(tokenizer, _truncate_text(prompt, config.max_chars), device, prompt_field="content")
    with torch.inference_mode():
        output = model.generate(
            **inputs,
            max_new_tokens=1,
            do_sample=False,
            return_dict_in_generate=True,
            output_logits=True,
            pad_token_id=tokenizer.eos_token_id,
        )
    score = output.logits[0][0]
    probs = torch.softmax(torch.tensor([score[safe_token_id], score[unsafe_token_id]], device=device), dim=0)
    safe_prob = float(probs[0].item())
    unsafe_prob = float(probs[1].item())
    return {
        "unsafe": unsafe_prob >= config.jailbreak_threshold,
        "safe_prob": round(safe_prob, 6),
        "unsafe_prob": round(unsafe_prob, 6),
        "threshold": config.jailbreak_threshold,
    }


def _classify_sguard_content(prompt: str, config: GuardrailConfig) -> dict[str, Any]:
    import torch

    tokenizer, model, device = _load_sguard_model(config.content_model, config.device)
    safe_token_id = _token_id(tokenizer, "safe")
    unsafe_token_id = _token_id(tokenizer, "unsafe")
    category_names = ["crime", "manipulation", "privacy", "sexual", "violence"]
    inputs = _sguard_inputs(tokenizer, _truncate_text(prompt, config.max_chars), device, prompt_field="prompt")
    with torch.inference_mode():
        output = model.generate(
            **inputs,
            max_new_tokens=len(category_names),
            do_sample=False,
            return_dict_in_generate=True,
            output_logits=True,
            pad_token_id=tokenizer.eos_token_id,
        )

    categories: dict[str, dict[str, float | bool]] = {}
    unsafe = False
    max_unsafe_prob = 0.0
    for idx, category in enumerate(category_names):
        score = output.logits[idx][0]
        probs = torch.softmax(torch.stack([score[safe_token_id], score[unsafe_token_id]]), dim=0)
        unsafe_prob = float(probs[1].item())
        threshold = float(config.content_thresholds[idx])
        is_unsafe = unsafe_prob >= threshold
        categories[category] = {
            "unsafe": is_unsafe,
            "unsafe_prob": round(unsafe_prob, 6),
            "threshold": threshold,
        }
        unsafe = unsafe or is_unsafe
        max_unsafe_prob = max(max_unsafe_prob, unsafe_prob)
    return {
        "unsafe": unsafe,
        "score": round(max_unsafe_prob, 6),
        "categories": categories,
    }


def _run_sguard(text: str, config: GuardrailConfig) -> dict[str, Any]:
    content_result = None
    jailbreak_result = None
    unsafe = False
    labels: dict[str, Any] = {}
    score = 0.0

    if config.content_enabled:
        content_result = _classify_sguard_content(text, config)
        unsafe = unsafe or bool(content_result["unsafe"])
        score = max(score, float(content_result.get("score") or 0.0))
        for category, item in content_result.get("categories", {}).items():
            labels[f"content_{category}"] = bool(item.get("unsafe"))

    if config.jailbreak_enabled:
        jailbreak_result = _classify_sguard_jailbreak(text, config)
        unsafe = unsafe or bool(jailbreak_result["unsafe"])
        score = max(score, float(jailbreak_result.get("unsafe_prob") or 0.0))
        labels["jailbreak"] = bool(jailbreak_result["unsafe"])

    return {
        "enabled": True,
        "provider": "sguard",
        "model": f"{config.content_model}+{config.jailbreak_model}",
        "status": "ok",
        "unsafe": unsafe,
        "labels": labels,
        "score": round(score, 6),
        "content": content_result,
        "jailbreak": jailbreak_result,
    }


def evaluate_guardrail(text: str) -> dict[str, Any] | None:
    config = get_guardrail_config()
    if not config.enabled:
        return None

    started = time.perf_counter()
    try:
        result = _run_sguard(text, config)
    except Exception as exc:
        if not config.fail_open:
            raise
        logger.exception("SGuard evaluation failed")
        result = {
            "enabled": True,
            "provider": "sguard",
            "model": f"{config.content_model}+{config.jailbreak_model}",
            "status": "error",
            "unsafe": False,
            "labels": {},
            "error": repr(exc),
        }
    result["latency_ms"] = int((time.perf_counter() - started) * 1000)
    return result
