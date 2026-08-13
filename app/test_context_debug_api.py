from fastapi.testclient import TestClient

import app.context_debug_api as context_debug_api


def test_debug_endpoint_uses_pipeline_configuration(monkeypatch) -> None:
    calls = []

    def fake_detect(**kwargs):
        calls.append(kwargs)
        return {
            "SN": [{"start": 0, "end": 14, "matchString": "890512-2054508"}],
            "__context_debug": [
                {
                    "key": "SN",
                    "matchString": "890512-2054508",
                    "method": "embed",
                    "score_norm": 0.7,
                }
            ],
        }

    monkeypatch.setattr(context_debug_api, "detect", fake_detect)
    client = TestClient(context_debug_api.app)

    response = client.post(
        "/debug/context",
        json={"text": "주민등록번호 890512-2054508", "ruleset": "default"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "pipeline"
    assert "__context_debug" not in body["found"]
    assert body["debug"][0]["score_norm"] == 0.7
    assert calls == [
        {
            "text": "주민등록번호 890512-2054508",
            "ruleset": "default",
            "include_context_debug": True,
        }
    ]
