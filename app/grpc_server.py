from __future__ import annotations

import hashlib
import json
import logging
import multiprocessing as mp
import os
import queue
import threading
import time
import traceback
from concurrent import futures
from typing import Any

import grpc

from .logging_utils import setup_file_logging
from .detection_exclusions import exclusion_status, write_detection_exclusion_file
from .pii import detect_with_meta
from .pii_engine import preload_models
from .proto import pii_pb2, pii_pb2_grpc
from .version import APP_VERSION

logger = logging.getLogger("pii.grpc")


class DetectTimeoutError(TimeoutError):
    pass


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v.strip() if v and v.strip() else default


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return int(default)
    try:
        return int(str(v).strip())
    except Exception:
        return int(default)


def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None:
        return float(default)
    try:
        return float(str(v).strip())
    except Exception:
        return float(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _truncate_request_text(text: str, limit: int | None = None) -> str:
    normalized = str(text or "").replace("\r", " ").replace("\n", " ").strip()
    max_chars = max(16, limit or _env_int("PII_LOG_REQUEST_TEXT_LIMIT", 240))
    if len(normalized) <= max_chars:
        return normalized
    return normalized[:max_chars] + "..."


def _build_match_item(pb2: Any, it: dict) -> Any:
    return pb2.MatchItem(
        start=int(it.get("start", 0)),
        end=int(it.get("end", 0)),
        match_string=str(it.get("matchString", "")),
        is_valid=bool(it.get("isValid", False)),
        context_score=float(it.get("context_score", 0.0) or 0.0),
        context_score_norm=float(it.get("context_score_norm", 0.0) or 0.0),
        context_hybrid_score=float(it.get("context_hybrid_score", 0.0) or 0.0),
        context_method=str(it.get("context_method", "")),
        context_accept_by=str(it.get("context_accept_by", "")),
        context_pass=bool(it.get("context_pass", False)),
        detected_by=str(it.get("detected_by", "")),
    )


def _build_data(pb2: Any, found: dict) -> Any:
    def items(key: str) -> list[Any]:
        return [_build_match_item(pb2, x) for x in (found.get(key, []) or [])]

    field_map = {
        "SN": ("sn_cnt", "sn"),
        "FN": ("fn_cnt", "fn"),
        "SSN": ("ssn_cnt", "ssn"),
        "DN": ("dn_cnt", "dn"),
        "PN": ("pn_cnt", "pn"),
        "MN": ("mn_cnt", "mn"),
        "BRN": ("brn_cnt", "brn"),
        "BN": ("bn_cnt", "bn"),
        "AN": ("an_cnt", "an"),
        "CN": ("cn_cnt", "cn"),
        "CPN": ("cpn_cnt", "cpn"),
        "CRN": ("crn_cnt", "crn"),
        "IMEI": ("imei_cnt", "imei"),
        "MCN": ("mcn_cnt", "mcn"),
        "EML": ("eml_cnt", "eml"),
        "VN_CCCD": ("vn_cccd_cnt", "vn_cccd"),
        "VN_MN": ("vn_mn_cnt", "vn_mn"),
        "VN_PN": ("vn_pn_cnt", "vn_pn"),
        "VN_TIN": ("vn_tin_cnt", "vn_tin"),
        "VN_SI": ("vn_si_cnt", "vn_si"),
    }
    kwargs: dict[str, Any] = {}
    for key, (cnt_field, items_field) in field_map.items():
        values = found.get(key, []) or []
        if not values:
            continue
        kwargs[cnt_field] = len(values)
        kwargs[items_field] = [_build_match_item(pb2, x) for x in values]
    return pb2.PiiData(**kwargs)


def _format_count_summary(found: dict) -> str:
    keys = ("SN", "FN", "SSN", "DN", "PN", "MN", "BRN", "BN", "AN", "CN", "CPN", "CRN", "IMEI", "MCN", "EML", "VN_CCCD", "VN_MN", "VN_PN", "VN_TIN", "VN_SI")
    return " ".join(f"{key}={len(found.get(key, []) or [])}" for key in keys)


def _log_detect_request(req_id: str, text: str, max_results_per_type: int, ruleset: str | None) -> None:
    logger.info(
        "[request] api=grpc method=Detect req=%s chars=%d bytes=%d max_results=%d ruleset=%s text=\"%s\"",
        req_id,
        len(text),
        len(text.encode("utf-8", errors="ignore")),
        max_results_per_type,
        ruleset or os.getenv("PII_RULESET", "default"),
        _truncate_request_text(text),
    )


def _log_detect_summary(req_id: str, found: dict, detect_ms: float, total_ms: float) -> None:
    logger.info(
        "[summary] api=grpc method=Detect req=%s status=200 detect_ms=%.1f total_ms=%.1f counts=\"%s\"",
        req_id,
        detect_ms,
        total_ms,
        _format_count_summary(found),
    )


def _detect_worker(text: str, max_results_per_type: int, ruleset: str | None, result_queue) -> None:
    try:
        found, meta = detect_with_meta(
            text,
            max_results_per_type=max_results_per_type,
            ruleset=ruleset,
        )
        result_queue.put(("ok", found, meta))
    except BaseException as exc:
        result_queue.put(("error", f"{type(exc).__name__}: {exc}", traceback.format_exc()))


def _detect_worker_loop(task_queue, result_queue, ready_queue) -> None:
    try:
        if _env_bool("PII_STAGE_TIMING_ENABLED", False):
            configured_name = _env("PII_LOG_FILE_NAME", "pii-api-grpc")
            log_stem = configured_name[:-4] if configured_name.lower().endswith(".log") else configured_name
            worker_host = _env("HOSTNAME", "container")[:12]
            os.environ["PII_LOG_FILE_NAME"] = f"{log_stem}-{worker_host}-worker-{os.getpid()}.log"
            setup_file_logging()
        worker_threads = str(max(1, _env_int("PII_DETECT_WORKER_TORCH_THREADS", 1)))
        for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
            os.environ[name] = worker_threads
        try:
            import torch

            torch.set_num_threads(int(worker_threads))
            torch.set_num_interop_threads(1)
        except Exception:
            pass
        warmed = preload_models()
        ready_queue.put(("ready", warmed, ""))
    except BaseException as exc:
        ready_queue.put(("error", f"{type(exc).__name__}: {exc}", traceback.format_exc()))
        return

    while True:
        task = task_queue.get()
        if task is None:
            return
        task_id, text, max_results_per_type, ruleset = task
        try:
            found, meta = detect_with_meta(
                text,
                max_results_per_type=max_results_per_type,
                ruleset=ruleset,
            )
            result_queue.put((task_id, "ok", found, meta))
        except BaseException as exc:
            result_queue.put((task_id, "error", f"{type(exc).__name__}: {exc}", traceback.format_exc()))


def _detect_process_context() -> mp.context.BaseContext:
    default_method = "spawn"
    method = _env("PII_DETECT_PROCESS_START_METHOD", default_method)
    return mp.get_context(method)


class DetectWorkerPool:
    def __init__(self, size: int) -> None:
        self.size = max(1, int(size))
        self.ctx = _detect_process_context()
        self._lock = threading.Lock()
        self._available: queue.Queue[int] = queue.Queue()
        self._workers: list[dict[str, Any]] = []
        for idx in range(self.size):
            self._workers.append(self._start_worker(idx))
            self._available.put(idx)

    def _start_worker(self, idx: int) -> dict[str, Any]:
        task_queue = self.ctx.Queue(maxsize=1)
        result_queue = self.ctx.Queue(maxsize=1)
        ready_queue = self.ctx.Queue(maxsize=1)
        proc = self.ctx.Process(target=_detect_worker_loop, args=(task_queue, result_queue, ready_queue))
        proc.daemon = True
        proc.start()
        try:
            status, first, second = ready_queue.get(timeout=max(1.0, _env_float("PII_DETECT_WORKER_START_TIMEOUT_SEC", 90.0)))
        except queue.Empty as exc:
            self._terminate_raw(proc, task_queue, result_queue, ready_queue)
            raise RuntimeError(f"PII detect worker {idx} did not become ready") from exc
        finally:
            ready_queue.close()
            ready_queue.join_thread()

        if status != "ready":
            self._terminate_raw(proc, task_queue, result_queue, ready_queue)
            raise RuntimeError(f"PII detect worker {idx} preload failed: {first}\n{second}")
        return {"idx": idx, "task_queue": task_queue, "result_queue": result_queue, "proc": proc}

    @staticmethod
    def _drain(result_queue) -> None:
        while True:
            try:
                result_queue.get_nowait()
            except queue.Empty:
                return

    @staticmethod
    def _terminate_raw(proc, *queues) -> None:
        if proc.is_alive():
            proc.terminate()
            proc.join(2.0)
        if proc.is_alive() and hasattr(proc, "kill"):
            proc.kill()
            proc.join(1.0)
        for q in queues:
            try:
                q.close()
                q.join_thread()
            except Exception:
                pass

    def _terminate_worker(self, worker: dict[str, Any]) -> None:
        self._terminate_raw(worker["proc"], worker["task_queue"], worker["result_queue"])

    @staticmethod
    def _request_worker_termination(worker: dict[str, Any]) -> None:
        proc = worker["proc"]
        if proc.is_alive():
            proc.terminate()

    def _replace_worker_in_background(self, idx: int, worker: dict[str, Any]) -> None:
        started_at = time.monotonic()
        retry_sec = max(0.1, _env_float("PII_DETECT_WORKER_RESTART_RETRY_SEC", 1.0))
        while True:
            try:
                self._terminate_worker(worker)
                break
            except Exception:
                logger.exception(
                    "[worker-recovery] worker index=%d termination cleanup failed retry_sec=%.1f",
                    idx,
                    retry_sec,
                )
                time.sleep(retry_sec)

        attempt = 0
        while True:
            attempt += 1
            try:
                replacement = self._start_worker(idx)
            except Exception:
                logger.exception(
                    "[worker-recovery] worker index=%d restart failed attempt=%d retry_sec=%.1f",
                    idx,
                    attempt,
                    retry_sec,
                )
                time.sleep(retry_sec)
                continue

            with self._lock:
                self._workers[idx] = replacement
            self._available.put(idx)
            logger.info(
                "[worker-recovery] worker index=%d ready attempts=%d recovery_ms=%.1f",
                idx,
                attempt,
                (time.monotonic() - started_at) * 1000.0,
            )
            return

    def _schedule_worker_replacement(self, idx: int, worker: dict[str, Any]) -> None:
        try:
            self._request_worker_termination(worker)
        except Exception:
            logger.exception("[worker-recovery] worker index=%d initial termination request failed", idx)
        replacement_thread = threading.Thread(
            target=self._replace_worker_in_background,
            args=(idx, worker),
            name=f"pii-detect-worker-recovery-{idx}",
            daemon=True,
        )
        replacement_thread.start()

    def run(self, text: str, max_results_per_type: int, ruleset: str | None, timeout_sec: float) -> tuple[dict, dict]:
        idx = self._available.get()
        worker = self._workers[idx]
        task_id = f"{idx}-{time.monotonic_ns()}"
        timed_out = False
        try:
            self._drain(worker["result_queue"])
            worker["task_queue"].put((task_id, text, max_results_per_type, ruleset))
            deadline = time.monotonic() + timeout_sec
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    self._schedule_worker_replacement(idx, worker)
                    raise DetectTimeoutError(
                        f"PII detection exceeded {timeout_sec:.1f}s timeout; worker index={idx} terminated"
                    )
                try:
                    result_task_id, status, first, second = worker["result_queue"].get(timeout=remaining)
                except queue.Empty:
                    timed_out = True
                    self._schedule_worker_replacement(idx, worker)
                    raise DetectTimeoutError(
                        f"PII detection exceeded {timeout_sec:.1f}s timeout; worker index={idx} terminated"
                    )
                if result_task_id != task_id:
                    continue
                if status == "ok":
                    return first, second
                raise RuntimeError(f"PII detection worker failed: {first}\n{second}")
        finally:
            if not timed_out:
                self._available.put(idx)


def _detect_with_process_timeout(pool: DetectWorkerPool, text: str, max_results_per_type: int, ruleset: str | None, timeout_sec: float) -> tuple[dict, dict]:
    return pool.run(text, max_results_per_type, ruleset, timeout_sec)


def _detect_with_single_process_timeout(text: str, max_results_per_type: int, ruleset: str | None, timeout_sec: float) -> tuple[dict, dict]:
    ctx = _detect_process_context()
    result_queue = ctx.Queue(maxsize=1)
    proc = ctx.Process(target=_detect_worker, args=(text, max_results_per_type, ruleset, result_queue))
    proc.start()
    proc.join(timeout_sec)
    if proc.is_alive():
        proc.terminate()
        proc.join(2.0)
        if proc.is_alive() and hasattr(proc, "kill"):
            proc.kill()
            proc.join(1.0)
        result_queue.close()
        result_queue.join_thread()
        raise DetectTimeoutError(f"PII detection exceeded {timeout_sec:.1f}s timeout; worker pid={proc.pid} terminated")

    try:
        status, first, second = result_queue.get_nowait()
    except queue.Empty as exc:
        raise RuntimeError(f"PII detection worker exited without result; exitcode={proc.exitcode}") from exc
    finally:
        result_queue.close()
        result_queue.join_thread()

    if status == "ok":
        return first, second
    raise RuntimeError(f"PII detection worker failed: {first}\n{second}")


def serve() -> None:
    use_process_timeout = _env_bool("PII_DETECT_PROCESS_TIMEOUT_ENABLED", True)
    if _env_bool("PII_MODEL_PRELOAD_ENABLED", True) and not use_process_timeout:
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
    elif use_process_timeout:
        logger.info("PII model preload will run inside detect worker processes")

    max_workers = max(1, _env_int("PII_GRPC_MAX_WORKERS", 6))
    detect_timeout_sec = max(0.1, _env_float("PII_DETECT_TIMEOUT_SEC", 10.0))
    detect_worker_pool = DetectWorkerPool(_env_int("PII_DETECT_PROCESS_WORKERS", 4))
    logger.info(
        "PII detect worker process pool started. workers=%d timeout_sec=%.1f start_method=%s",
        detect_worker_pool.size,
        detect_timeout_sec,
        _detect_process_context().get_start_method(),
    )

    class PiiDetectorServicer(pii_pb2_grpc.PiiDetectorServicer):
        def Detect(self, request, context):  # noqa: N802
            try:
                text = request.text or ""
                max_results_per_type = int(request.max_results_per_type or 500)
                ruleset = request.ruleset.strip() if request.ruleset else None
                req_id = hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:8] if text else "empty"
                t0 = time.perf_counter()
                _log_detect_request(req_id, text, max_results_per_type, ruleset)
                t_detect = time.perf_counter()
                try:
                    found, meta = _detect_with_process_timeout(
                        detect_worker_pool,
                        text,
                        max_results_per_type,
                        ruleset,
                        detect_timeout_sec,
                    )
                except DetectTimeoutError as exc:
                    total_ms = (time.perf_counter() - t0) * 1000.0
                    logger.warning(
                        "[timeout] api=grpc method=Detect req=%s status=504 timeout_sec=%.1f total_ms=%.1f chars=%d bytes=%d max_results=%d ruleset=%s detail=\"%s\"",
                        req_id,
                        detect_timeout_sec,
                        total_ms,
                        len(text),
                        len(text.encode("utf-8", errors="ignore")),
                        max_results_per_type,
                        ruleset or os.getenv("PII_RULESET", "default"),
                        str(exc),
                    )
                    context.set_code(grpc.StatusCode.DEADLINE_EXCEEDED)
                    context.set_details(f"PII detection exceeded {detect_timeout_sec:.1f}s timeout")
                    return pii_pb2.DetectResponse(
                        success=False,
                        status=504,
                        message=f"PII detection exceeded {detect_timeout_sec:.1f}s timeout",
                    )
                detect_ms = (time.perf_counter() - t_detect) * 1000.0
                total_ms = (time.perf_counter() - t0) * 1000.0
                _log_detect_summary(req_id, found, detect_ms, total_ms)
                return pii_pb2.DetectResponse(
                    success=True,
                    status=200,
                    message="OK",
                    data=_build_data(pii_pb2, found),
                    meta=pii_pb2.PiiMeta(
                        ruleset_name=str((meta or {}).get("ruleset_name", "")),
                        ruleset_version=str((meta or {}).get("ruleset_version", "")),
                        ruleset_updated_at=str((meta or {}).get("ruleset_updated_at", "")),
                    ),
                )
            except Exception as e:  # pragma: no cover
                logger.exception("gRPC Detect failed")
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(str(e))
                return pii_pb2.DetectResponse(
                    success=False,
                    status=500,
                    message=str(e),
                )

        def Health(self, request, context):  # noqa: N802
            return pii_pb2.HealthResponse(
                ok=True,
                service="xcn-pii-full-grpc",
                version=APP_VERSION,
            )

        def ReplaceExclusions(self, request, context):  # noqa: N802
            try:
                raw = request.json_payload or ""
                if not raw.strip():
                    context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                    context.set_details("exclusion JSON payload is required")
                    return pii_pb2.ReplaceExclusionsResponse(
                        success=False,
                        status=400,
                        message="exclusion JSON payload is required",
                    )
                payload = json.loads(raw)
                config = write_detection_exclusion_file(payload)
                status = exclusion_status()
                logger.info(
                    "[exclusion] grpc ReplaceExclusions updated path=%s total_values=%d type_counts=%s",
                    status["path"],
                    config.total_values,
                    config.type_counts,
                )
                return pii_pb2.ReplaceExclusionsResponse(
                    success=True,
                    status=200,
                    message="OK",
                    path=str(status["path"]),
                    updated_at=str(status["updated_at"] or ""),
                    total_values=int(config.total_values),
                    type_counts={str(k): int(v) for k, v in config.type_counts.items()},
                )
            except json.JSONDecodeError as exc:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details(f"invalid JSON: {exc.msg}")
                return pii_pb2.ReplaceExclusionsResponse(
                    success=False,
                    status=400,
                    message=f"invalid JSON: {exc.msg}",
                )
            except ValueError as exc:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details(str(exc))
                return pii_pb2.ReplaceExclusionsResponse(
                    success=False,
                    status=400,
                    message=str(exc),
                )
            except Exception as exc:  # pragma: no cover
                logger.exception("gRPC ReplaceExclusions failed")
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(str(exc))
                return pii_pb2.ReplaceExclusionsResponse(
                    success=False,
                    status=500,
                    message=str(exc),
                )

    max_concurrent_streams = max(1, _env_int("PII_GRPC_MAX_CONCURRENT_STREAMS", 1024))
    keepalive_time_ms = max(1000, _env_int("PII_GRPC_KEEPALIVE_TIME_MS", 30000))
    keepalive_timeout_ms = max(1000, _env_int("PII_GRPC_KEEPALIVE_TIMEOUT_MS", 10000))
    max_concurrent_rpcs = _env_int("PII_GRPC_MAX_CONCURRENT_RPCS", 0)
    host = _env("PII_GRPC_HOST", "0.0.0.0")
    port = _env_int("PII_GRPC_PORT", 50051)
    bind = f"{host}:{port}"
    options = [
        ("grpc.so_reuseport", int(_env_bool("PII_GRPC_SO_REUSEPORT", True))),
        ("grpc.max_concurrent_streams", max_concurrent_streams),
        ("grpc.keepalive_time_ms", keepalive_time_ms),
        ("grpc.keepalive_timeout_ms", keepalive_timeout_ms),
        ("grpc.keepalive_permit_without_calls", 1),
        ("grpc.http2.max_pings_without_data", 0),
    ]

    kwargs = {}
    if max_concurrent_rpcs > 0:
        kwargs["maximum_concurrent_rpcs"] = max_concurrent_rpcs
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        options=options,
        **kwargs,
    )
    pii_pb2_grpc.add_PiiDetectorServicer_to_server(PiiDetectorServicer(), server)
    server.add_insecure_port(bind)
    server.start()
    logger.info(
        "gRPC server started on %s workers=%d max_streams=%d max_rpcs=%s reuseport=%s",
        bind,
        max_workers,
        max_concurrent_streams,
        str(max_concurrent_rpcs) if max_concurrent_rpcs > 0 else "unlimited",
        str(_env_bool("PII_GRPC_SO_REUSEPORT", True)).lower(),
    )
    server.wait_for_termination()


if __name__ == "__main__":
    setup_file_logging()
    logging.basicConfig(level=os.getenv("PII_LOG_LEVEL", "INFO"))
    serve()
