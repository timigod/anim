"""Backend-neutral local subprocess adapters."""

from .config import WorkerCommand, WorkerConfig
from .contract import CaseStatus, run_contract_test
from .invocation import (
    AuthenticatedWorkerDescription,
    AuthenticatedWorkerExecutionEvidence,
    AuthenticatedWorkerRequestEvidence,
    InvocationFailureClass,
    WorkerExecution,
    WorkerInvocationObservation,
    WorkerInvoker,
    normalize_worker_timeout_seconds,
)
from .service import describe_worker

__all__ = [
    "AuthenticatedWorkerDescription",
    "AuthenticatedWorkerExecutionEvidence",
    "AuthenticatedWorkerRequestEvidence",
    "CaseStatus",
    "InvocationFailureClass",
    "WorkerCommand",
    "WorkerConfig",
    "WorkerExecution",
    "WorkerInvocationObservation",
    "WorkerInvoker",
    "describe_worker",
    "normalize_worker_timeout_seconds",
    "run_contract_test",
]
