"""One background thread that runs pipeline jobs in order: fetch, ingest and analyse,
pre-patch, dry run, upload. One at a time keeps spend and SQLite writes simple. Decisions
don't queue here: they run at once, under the audit log's lock."""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable

log = logging.getLogger(__name__)


class Lane:
    def __init__(self, size: int = 5) -> None:
        self._jobs: queue.Queue[Callable[[], None]] = queue.Queue(maxsize=size)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="cti-agent-jobs", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def submit(self, job: Callable[[], None]) -> int:
        """Queue a job and return how many are waiting, this one included. Raises
        queue.Full when the queue is full."""
        self._jobs.put_nowait(job)
        return self._jobs.qsize()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                job()
            except Exception:  # jobs report their own failures; the lane keeps going
                log.exception("a job failed outside its own error handling")
            finally:
                self._jobs.task_done()


class InlineLane:
    """Runs each job as it's submitted: for tests."""

    def submit(self, job: Callable[[], None]) -> int:
        job()
        return 0
