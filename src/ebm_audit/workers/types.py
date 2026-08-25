"""Typed worker callback boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ebm_audit.privacy.safe import (
    core_owned_negative_response_message,
    normalize_worker_validation_issue,
)


@dataclass(frozen=True)
class WorkerSuccess:
    """One successful callback result before transport framing."""

    payload: Mapping[str, Any]
    arrays: Mapping[str, Any] = field(default_factory=dict)
    warnings: tuple[Mapping[str, Any], ...] = ()


@dataclass(eq=False)
class WorkerFailure(Exception):
    """A typed, privacy-safe negative worker response."""

    status: str
    code: str
    safe_message: str
    phase: str
    retryable_identical_request: bool = False
    issues: tuple[Mapping[str, Any], ...] = ()
    counts: Mapping[str, int] = field(default_factory=dict)
    internal_indexes: tuple[int, ...] = ()
    approved_event_ids: tuple[str, ...] = ()
    digests: Mapping[str, str] = field(default_factory=dict)
    callback_failure: Mapping[str, Any] | None = None
    payload_finalization_failure: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        has_finalization_code = self.code == "BACKEND.FIT_PAYLOAD_FINALIZATION_FAILED"
        has_finalization_failure = self.payload_finalization_failure is not None
        if has_finalization_code != has_finalization_failure:
            raise ValueError("Fit-payload finalization code and detail must be present together.")
        # Backend prose is never an operator-facing exception message. Keep the
        # callback field for source compatibility, but replace its value (and
        # nested issue prose) before the exception can be logged or rendered.
        owned_message = core_owned_negative_response_message(self.status)
        self.safe_message = owned_message
        self.issues = tuple(normalize_worker_validation_issue(issue) for issue in self.issues)
        Exception.__init__(self, owned_message)

    def as_error(self) -> dict[str, Any]:
        error: dict[str, Any] = {
            "code": self.code,
            "category": self.status,
            "safe_message": core_owned_negative_response_message(self.status),
            "phase": self.phase,
            "retryable_identical_request": self.retryable_identical_request,
            "issues": [normalize_worker_validation_issue(issue) for issue in self.issues],
            "details": {
                "counts": dict(self.counts),
                "internal_indexes": list(self.internal_indexes),
                "approved_event_ids": list(self.approved_event_ids),
                "digests": dict(self.digests),
            },
        }
        if self.code == "BACKEND.CALLBACK_FAILED" and self.callback_failure is not None:
            error["callback_failure"] = dict(self.callback_failure)
        if (
            self.code == "BACKEND.FIT_PAYLOAD_FINALIZATION_FAILED"
            and self.payload_finalization_failure is not None
        ):
            error["payload_finalization_failure"] = dict(self.payload_finalization_failure)
        return error


class WorkerBackend(Protocol):
    """Callbacks execute only inside the external worker process."""

    @property
    def describe_result(self) -> Mapping[str, Any]: ...

    def backend_identity(self, algorithm_id: str | None) -> Mapping[str, Any]: ...

    def capabilities_for(self, algorithm_id: str) -> Mapping[str, Any]: ...

    def capabilities_digest_for(self, algorithm_id: str) -> str: ...

    def describe(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess: ...

    def validate(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess: ...

    def fit(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess: ...

    def self_test(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess: ...
