from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

from app.detection_exclusions import parse_detection_exclusions


def _post_detect(base_url: str, request_payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    payload = dict(request_payload)
    ruleset = str(payload.pop("ruleset", "") or "").strip()
    headers = {"Content-Type": "application/json"}
    if ruleset:
        headers["X-PII-RULESET"] = ruleset
    request = urllib.request.Request(
        base_url.rstrip("/") + "/pii/detect",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _actual_value(data: dict[str, Any], key: str) -> Any:
    value = data.get(key)
    if key.endswith("_CNT"):
        return int(value or 0)
    if isinstance(value, list):
        return [str(item.get("matchString") or "") for item in value if isinstance(item, dict)]
    return [] if value is None else value


def _verify_expected(name: str, response: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if response.get("success") is not True or int(response.get("status") or 0) != 200:
        failures.append(f"{name}: unsuccessful response: {response}")
        return failures
    data = dict(response.get("data") or {})
    for key, expected_value in expected.items():
        actual_value = _actual_value(data, key)
        if actual_value != expected_value:
            failures.append(
                f"{name}: {key} expected={expected_value!r} actual={actual_value!r}"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify every JSON testcase under examples/")
    parser.add_argument("--base-url", default="http://127.0.0.1:8005")
    parser.add_argument("--examples-dir", type=Path, default=Path("examples"))
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()

    failures: list[str] = []
    detection_cases = 0
    exclusion_samples = 0
    json_files = sorted(args.examples_dir.glob("*.json"))
    for path in json_files:
        document = json.loads(path.read_text(encoding="utf-8"))
        if "request" in document and "expected" in document:
            name = path.name
            response = _post_detect(args.base_url, dict(document["request"]), args.timeout)
            case_failures = _verify_expected(name, response, dict(document["expected"]))
            failures.extend(case_failures)
            detection_cases += 1
            print(("FAIL" if case_failures else "PASS"), name)

        for case in document.get("cases") or []:
            name = f"{path.name}:{case.get('id') or detection_cases + 1}"
            response = _post_detect(args.base_url, dict(case["request"]), args.timeout)
            case_failures = _verify_expected(name, response, dict(case["expected"]))
            failures.extend(case_failures)
            detection_cases += 1
            print(("FAIL" if case_failures else "PASS"), name)

        if path.name == "pii_exclusions_all_sample.json":
            config = parse_detection_exclusions(document)
            if not config.all_values or not config.type_values:
                failures.append(f"{path.name}: parsed exclusion configuration is empty")
                print("FAIL", path.name)
            else:
                print("PASS", path.name, "(parser)")
            exclusion_samples += 1

    for failure in failures:
        print(failure, file=sys.stderr)
    print(
        f"summary json_files={len(json_files)} detection_cases={detection_cases} "
        f"exclusion_samples={exclusion_samples} failures={len(failures)}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
