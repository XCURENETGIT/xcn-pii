from types import SimpleNamespace

from app.pii_engine.context_filters import _resolve_embed_device


def _torch_with_cuda(available: bool):
    return SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: available))


def test_embed_device_stays_on_cpu_when_requested(monkeypatch):
    monkeypatch.setenv("PII_EMBED_DEVICE", "cpu")

    assert _resolve_embed_device() == "cpu"


def test_embed_device_uses_cuda_when_available(monkeypatch):
    monkeypatch.setenv("PII_EMBED_DEVICE", "cuda")
    monkeypatch.setitem(__import__("sys").modules, "torch", _torch_with_cuda(True))

    assert _resolve_embed_device() == "cuda"


def test_embed_device_auto_falls_back_to_cpu(monkeypatch):
    monkeypatch.setenv("PII_EMBED_DEVICE", "auto")
    monkeypatch.setitem(__import__("sys").modules, "torch", _torch_with_cuda(False))

    assert _resolve_embed_device() == "cpu"


def test_embed_device_rejects_unknown_value(monkeypatch):
    monkeypatch.setenv("PII_EMBED_DEVICE", "tpu")

    assert _resolve_embed_device() == "cpu"
