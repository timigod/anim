"""Optional operational controls, separate from scientific execution authority."""

from __future__ import annotations

import signal
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from types import FrameType

from ebm_audit.errors import AuditError, ExitCode


class ExecutionPhase(StrEnum):
    READY = "READY"
    RUNNING = "RUNNING"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ADMISSION_REJECTED = "ADMISSION_REJECTED"


@dataclass(frozen=True, slots=True)
class ExecutionProgress:
    """Closed phase and counts only; no input, path, worker text or identifiers."""

    phase: ExecutionPhase
    planned_candidates: int
    submitted_candidates: int
    persisted_candidates: int
    effective_parallel_workers: int

    def counts(self) -> dict[str, int]:
        return {
            "planned_candidates": self.planned_candidates,
            "submitted_candidates": self.submitted_candidates,
            "persisted_candidates": self.persisted_candidates,
            "effective_parallel_workers": self.effective_parallel_workers,
        }


class ExecutionCancelled(AuditError):
    """An incomplete operational attempt, never a scientific worker failure."""

    def __init__(self, progress: ExecutionProgress | None = None) -> None:
        super().__init__(
            code="EXECUTION.CANCELLED",
            safe_message=(
                "Execution was cancelled; persisted results remain in the incomplete attempt."
            ),
            exit_code=ExitCode.PARTIAL,
            details={} if progress is None else progress.counts(),
        )


class MemoryAdmissionError(AuditError):
    def __init__(self) -> None:
        super().__init__(
            code="EXECUTION.MEMORY_ADMISSION_REJECTED",
            safe_message=(
                "Memory admission requires positive integer budget and per-worker reservation "
                "values, with capacity for at least one worker."
            ),
            exit_code=ExitCode.INVALID_INPUT_OR_SPECIFICATION,
        )


class ExecutionControl:
    """A cooperative cancellation flag and an explicit concurrency admission policy.

    The budget reserves worker capacity; it is neither measured RSS nor an OS
    memory limit. The coordinator invokes progress callbacks synchronously.
    Observers must return promptly; their exceptions are ignored so observation
    cannot replace execution outcomes or expose arbitrary callback messages.
    """

    def __init__(
        self,
        *,
        progress_callback: Callable[[ExecutionProgress], None] | None = None,
        memory_budget_bytes: int | None = None,
        per_worker_memory_bytes: int | None = None,
    ) -> None:
        if progress_callback is not None and not callable(progress_callback):
            raise TypeError("The execution progress callback must be callable.")
        if (memory_budget_bytes is None) != (per_worker_memory_bytes is None) or any(
            value is not None and (type(value) is not int or value <= 0)
            for value in (memory_budget_bytes, per_worker_memory_bytes)
        ):
            raise MemoryAdmissionError()
        self._progress_callback = progress_callback
        self._memory_budget_bytes = memory_budget_bytes
        self._per_worker_memory_bytes = per_worker_memory_bytes
        self._cancel_requested = False
        self._progress_callback_failures = 0

    @property
    def memory_budget_bytes(self) -> int | None:
        return self._memory_budget_bytes

    @property
    def per_worker_memory_bytes(self) -> int | None:
        return self._per_worker_memory_bytes

    @property
    def progress_callback_failures(self) -> int:
        return self._progress_callback_failures

    @property
    def cancellation_requested(self) -> bool:
        return self._cancel_requested

    def request_cancel(self) -> None:
        # A plain flag also keeps the Python signal handler free of locks: a
        # repeated signal cannot interrupt an Event.set() while it owns a lock.
        self._cancel_requested = True

    def raise_if_cancelled(self) -> None:
        if self.cancellation_requested:
            raise ExecutionCancelled()

    def effective_parallel_workers(self, planned_ceiling: int) -> int:
        if type(planned_ceiling) is not int or planned_ceiling <= 0:
            raise TypeError("Execution admission requires a positive planned worker ceiling.")
        if self._memory_budget_bytes is None or self._per_worker_memory_bytes is None:
            return planned_ceiling
        capacity = self._memory_budget_bytes // self._per_worker_memory_bytes
        if capacity < 1:
            raise MemoryAdmissionError()
        return min(planned_ceiling, capacity)

    def _emit(self, progress: ExecutionProgress) -> None:
        if self._progress_callback is not None:
            try:
                self._progress_callback(progress)
            except Exception:
                self._progress_callback_failures += 1

    @contextmanager
    def signal_handlers(self) -> Iterator[ExecutionControl]:
        """Temporarily handle SIGINT/SIGTERM on the main thread; restore on exit."""

        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("Execution signal handlers require the main thread.")
        previous = {}

        def cancel(_signum: int, _frame: FrameType | None) -> None:
            self.request_cancel()

        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous[signum] = signal.signal(signum, cancel)
            yield self
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
