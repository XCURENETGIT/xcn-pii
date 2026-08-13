from scripts.grpc_benchmark import percentile, summarize


def test_percentile_interpolates_sorted_values() -> None:
    values = [40.0, 10.0, 30.0, 20.0]

    assert percentile(values, 0.0) == 10.0
    assert percentile(values, 0.5) == 25.0
    assert percentile(values, 1.0) == 40.0


def test_summary_reports_latency_rps_and_errors() -> None:
    rows = [
        {"success": True, "latency_ms": 10.0},
        {"success": True, "latency_ms": 30.0},
        {"success": False, "latency_ms": 5.0, "grpc_code": "UNAVAILABLE"},
    ]

    report = summarize(rows, wall_seconds=2.0)

    assert report["requests"] == 3
    assert report["successes"] == 2
    assert report["errors"] == 1
    assert report["rps"] == 1.0
    assert report["latency_ms"]["p50"] == 20.0
    assert report["grpc_errors"] == {"UNAVAILABLE": 1}
