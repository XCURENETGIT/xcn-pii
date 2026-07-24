from __future__ import annotations

import queue
import threading
import time
import unittest

from app.grpc_server import DetectTimeoutError, DetectWorkerPool


class _FakeProcess:
    def __init__(self) -> None:
        self.alive = True
        self.terminate_calls = 0

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        self.terminate_calls += 1
        self.alive = False

    def join(self, _timeout: float) -> None:
        return None


class DetectWorkerPoolTimeoutTests(unittest.TestCase):
    def test_timeout_returns_before_replacement_preload_finishes(self) -> None:
        pool = object.__new__(DetectWorkerPool)
        pool.size = 1
        pool._lock = threading.Lock()
        pool._available = queue.Queue()
        pool._available.put(0)

        old_process = _FakeProcess()
        old_worker = {
            "idx": 0,
            "task_queue": queue.Queue(maxsize=1),
            "result_queue": queue.Queue(maxsize=1),
            "proc": old_process,
        }
        pool._workers = [old_worker]

        replacement_started = threading.Event()
        allow_replacement_to_finish = threading.Event()
        replacement_worker = {
            "idx": 0,
            "task_queue": queue.Queue(maxsize=1),
            "result_queue": queue.Queue(maxsize=1),
            "proc": _FakeProcess(),
        }

        def slow_start_worker(_idx: int) -> dict:
            replacement_started.set()
            allow_replacement_to_finish.wait(timeout=2.0)
            return replacement_worker

        pool._start_worker = slow_start_worker

        started_at = time.monotonic()
        with self.assertRaises(DetectTimeoutError):
            pool.run("slow input", 500, None, 0.05)
        timeout_elapsed = time.monotonic() - started_at

        self.assertLess(timeout_elapsed, 0.25)
        self.assertGreaterEqual(old_process.terminate_calls, 1)
        self.assertTrue(replacement_started.wait(timeout=1.0))
        self.assertTrue(pool._available.empty())

        allow_replacement_to_finish.set()
        self.assertEqual(0, pool._available.get(timeout=1.0))
        self.assertIs(pool._workers[0], replacement_worker)


if __name__ == "__main__":
    unittest.main()
