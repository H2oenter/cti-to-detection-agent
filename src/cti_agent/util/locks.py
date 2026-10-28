"""A lock for files that several writers share, such as the audit log, which the Slack
bot's threads and a terminal `review` can both append to.

Exclusive across threads and processes, and reentrant within a thread. The lock lives in
a separate file next to the data and is never deleted, because deleting lock files races.
The operating system releases it if the holding process dies, so it can't go stale.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class LockTimeout(Exception):
    pass


@dataclass
class _State:
    guard: threading.Lock = field(default_factory=threading.Lock)
    owner: int | None = None
    depth: int = 0
    fd: int | None = None


_STATES: dict[str, _State] = {}
_STATES_GUARD = threading.Lock()


class InterProcessLock:
    def __init__(self, path: Path, timeout: float = 30.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        key = os.path.normcase(str(self.path.resolve()))
        with _STATES_GUARD:  # every lock on one file shares one state in this process
            self._state = _STATES.setdefault(key, _State())

    def __enter__(self) -> InterProcessLock:
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def acquire(self) -> None:
        state, me = self._state, threading.get_ident()
        if state.owner == me:
            state.depth += 1
            return
        deadline = time.monotonic() + self.timeout
        if not state.guard.acquire(timeout=self.timeout):
            raise LockTimeout(f"another thread is holding {self.path}; try again shortly")
        try:
            state.fd = _lock_file(self.path, deadline)
        except BaseException:
            state.guard.release()
            raise
        state.owner, state.depth = me, 1

    def release(self) -> None:
        state = self._state
        if state.owner != threading.get_ident():
            raise RuntimeError(f"this thread doesn't hold {self.path}")
        state.depth -= 1
        if state.depth:
            return
        fd, state.fd, state.owner = state.fd, None, None
        try:
            _unlock(fd)
        finally:
            os.close(fd)
            state.guard.release()


def _lock_file(path: Path, deadline: float) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    delay = 0.005
    while True:
        try:
            _try_lock(fd)
            return fd
        except OSError:
            if time.monotonic() >= deadline:
                os.close(fd)
                raise LockTimeout(
                    f"another cti-agent process is holding {path}; try again shortly"
                ) from None
            time.sleep(delay)
            delay = min(delay * 2, 0.1)


if os.name == "nt":

    def _try_lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:

    def _try_lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
