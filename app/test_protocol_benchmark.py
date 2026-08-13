from scripts.protocol_benchmark import _load_payload, _run_requests


def test_default_comparison_payload_has_expected_length_and_tail() -> None:
    payload = _load_payload("")

    assert len(payload) == 52_042
    assert payload.endswith("business registration number 110-81-40818")


def test_common_runner_reports_success_and_latency() -> None:
    report = _run_requests(lambda: (True, "200"), requests=4, warmup_requests=1, concurrency=2)

    assert report["requests"] == 4
    assert report["successes"] == 4
    assert report["errors"] == 0
    assert report["errors_by_detail"] == {}


def test_common_runner_groups_failure_details() -> None:
    report = _run_requests(lambda: (False, "queue-full"), requests=3, warmup_requests=0, concurrency=1)

    assert report["successes"] == 0
    assert report["errors_by_detail"] == {"queue-full": 3}
