"""Privacy-safe structured errors for the auditor command line and adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum


class ExitCode(IntEnum):
    """Stable process exits from the normative CLI lifecycle registry."""

    SUCCESS = 0
    INVALID_INPUT_OR_SPECIFICATION = 10
    WORKER_OR_CAPABILITY_UNAVAILABLE = 11
    PARTIAL = 12
    BENCHMARK_FAILED = 13
    PRIVACY_FAILED = 14
    BACKEND_OR_PROTOCOL_FAILURE = 15
    UNEXPECTED_CORE_ERROR = 16


@dataclass(eq=False)
class AuditError(Exception):
    """An operator-facing error whose text is safe to show by construction.

    The class deliberately does not retain an arbitrary underlying exception or
    raw worker output. Those often contain paths, values, or backend internals.
    Diagnostic evidence is represented by bounded counts and digests instead.
    """

    code: str
    safe_message: str
    exit_code: ExitCode
    details: Mapping[str, int | str | bool] = field(default_factory=dict)
    invocation_observation: object | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        Exception.__init__(self, self.safe_message)

    def __str__(self) -> str:
        return self.safe_message


class InvalidInputError(AuditError):
    def __init__(self, code: str, safe_message: str) -> None:
        super().__init__(
            code=code,
            safe_message=safe_message,
            exit_code=ExitCode.INVALID_INPUT_OR_SPECIFICATION,
        )


class WorkerUnavailableError(AuditError):
    def __init__(self, safe_message: str = "The configured worker is unavailable.") -> None:
        super().__init__(
            code="WORKER.UNAVAILABLE",
            safe_message=safe_message,
            exit_code=ExitCode.WORKER_OR_CAPABILITY_UNAVAILABLE,
        )


class WorkerProtocolError(AuditError):
    def __init__(
        self,
        code: str,
        safe_message: str,
        *,
        details: Mapping[str, int | str | bool] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            safe_message=safe_message,
            exit_code=ExitCode.BACKEND_OR_PROTOCOL_FAILURE,
            details=details or {},
        )


class PrivacyViolationError(AuditError):
    def __init__(self, code: str, safe_message: str) -> None:
        super().__init__(
            code=code,
            safe_message=safe_message,
            exit_code=ExitCode.PRIVACY_FAILED,
        )


class UnexpectedCoreError(AuditError):
    def __init__(self, code: str, safe_message: str) -> None:
        super().__init__(
            code=code,
            safe_message=safe_message,
            exit_code=ExitCode.UNEXPECTED_CORE_ERROR,
        )
