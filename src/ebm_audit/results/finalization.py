"""One core-owned authority for immutable candidate result finalization.

The pure protocol validator remains useful for serialized readback.  It is not
runtime authority.  This module is the only path that turns exact in-process
worker capabilities and other core-owned inputs into a ``FinalizedResult``.
Raw mappings never authorize an identity, persistence, cache admission, or a
candidate terminal.  Every production result retains and revalidates the exact
prepared or unprepared ``CandidateResultAuthorization`` that issued it.
Production prepared finalization additionally derives its owner only from exact
evidence whose non-null planning-summary identity matches that authority.  The
test-only contract-harness branch has a null planning-summary identity and has
no promotion path.  Descriptive ``SUCCESS`` and ``CONVERGENCE_WARN`` results
retain every successful fit-execution owner; only ``SUCCESS`` can issue
baseline authority.
"""

from __future__ import annotations

import copy
import math
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any, Final, NamedTuple, Never, SupportsIndex, cast, final

import numpy as np

from ebm_audit._capability_registry import (
    CallbackFreeWeakIdentityMap,
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.adapters import (
    AuthenticatedWorkerExecutionEvidence,
    InvocationFailureClass,
    WorkerInvocationObservation,
)
from ebm_audit.adapters.invocation import (
    _AuthenticatedExecutionReadback,
    _AuthenticatedRequestReadback,
    _readback_authenticated_execution,
    _readback_worker_invocation_observation,
)
from ebm_audit.data import CanonicalDataset, validate_canonical_dataset
from ebm_audit.metrics import CONVERGENCE_RULE, ConvergenceChainInput, derive_convergence_record
from ebm_audit.privacy.safe import core_owned_negative_response_message
from ebm_audit.protocol import (
    authenticated_execution_evidence_digest,
    backend_identity_digest,
    canonical_json_bytes,
    capabilities_digest,
    core_observed_failure_digest,
    exact_file_sha256,
    execution_input_projection_digest,
    response_metadata_digest,
    retry_equivalence_digest,
    strict_json_loads,
    structured_sha256,
    validate_result_record_finalization,
    worker_command_evidence_digest,
    worker_fit_payload_digest,
)
from ebm_audit.schema import validate_instance
from ebm_audit.workers.arrays import array_catalog_entry

_SHA256_PREFIX: Final = "sha256:"
_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
_RESULT_SCHEMA_VERSION: Final = "ebm-audit-fit-result/2.0"
_CHAIN_PAYLOAD_SCHEMA_VERSION: Final = "ebm-audit-final-chain-payload/1.0"
_EVIDENCE_REFERENCE_SCHEMA_VERSION: Final = "ebm-audit-worker-execution-evidence-reference/2.0"
_RETRY_ELIGIBLE_PROCESS_FAILURE_CODES: Final = frozenset(
    {"BACKEND.WORKER_START_FAILED", "BACKEND.WORKER_PROCESS_FAILED"}
)
_NEGATIVE_STATUS_PRECEDENCE: Final = (
    "PRIVACY_VIOLATION",
    "PROTOCOL_ERROR",
    "TIMEOUT",
    "BACKEND_ERROR",
    "INVALID_INPUT",
    "INVALID_SPECIFICATION",
    "UNSUPPORTED_CAPABILITY",
)
_CORE_FAILURE_STATUS: Final = {
    InvocationFailureClass.TIMEOUT: "TIMEOUT",
    InvocationFailureClass.PRIVACY_VIOLATION: "PRIVACY_VIOLATION",
    InvocationFailureClass.PROCESS_FAILURE: "BACKEND_ERROR",
    InvocationFailureClass.RESPONSE_MISSING: "PROTOCOL_ERROR",
    InvocationFailureClass.RESPONSE_INVALID: "PROTOCOL_ERROR",
    InvocationFailureClass.PROTOCOL_FAILURE: "PROTOCOL_ERROR",
    InvocationFailureClass.UNEXPECTED_CORE_ERROR: "PROTOCOL_ERROR",
}
_CONVERGENCE_STATUS: Final = {
    "NOT_APPLICABLE": "SUCCESS",
    "CONVERGENCE_PASS": "SUCCESS",
    "CONVERGENCE_WARN": "CONVERGENCE_WARN",
    "CONVERGENCE_FAIL": "CONVERGENCE_FAILED",
    "CONVERGENCE_NOT_ASSESSABLE": "CONVERGENCE_NOT_ASSESSABLE",
}
_WorkerEvidenceCapability = AuthenticatedWorkerExecutionEvidence | WorkerInvocationObservation
_INFER_PLANNING_SUMMARY_ID = object()


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith(_SHA256_PREFIX)
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _is_nonnegative_finite_number(value: object) -> bool:
    if type(value) not in {int, float}:
        return False
    try:
        number = float(cast(int | float, value))
    except (OverflowError, ValueError):
        return False
    return math.isfinite(number) and number >= 0.0


def _exact_worker_evidence(value: object) -> _WorkerEvidenceCapability:
    if type(value) is AuthenticatedWorkerExecutionEvidence:
        return value
    if type(value) is WorkerInvocationObservation:
        return value
    raise TypeError("Prepared finalization requires exact sealed worker evidence.")


def _reject_copy() -> Never:
    raise TypeError("Core result capabilities cannot be copied or serialized.")


@dataclass(frozen=True, repr=False)
class _PreparedCandidateState:
    planning_summary_id: str | None
    prepared_execution_authorization: object | None
    plan_digest: str
    candidate_ordinal: int
    candidate_id: str
    analysis_spec_id: str
    universe_id: str
    execution_input_projection_digest: str
    ordered_chain_execution_ids: tuple[str, ...]
    started_at_utc: str
    ended_at_utc: str
    runtime_seconds: float
    validation_evidence: _WorkerEvidenceCapability
    fit_attempt_evidence: tuple[_WorkerEvidenceCapability, ...]
    cache_lineage: VerifiedCacheLineage | None
    canonical_dataset: CanonicalDataset | None
    prepared_candidate_execution_context: object | None = None
    prepared_candidate_execution_context_state: object | None = None
    prepared_execution_state: object | None = None


_PREPARED_CANDIDATE_STATES: OneShotWeakRegistry[
    object, _PreparedCandidateState
]
_PREPARED_CANDIDATE_STATE_ISSUER: OneShotRegistryIssuer[
    object, _PreparedCandidateState
]
(
    _PREPARED_CANDIDATE_STATES,
    _PREPARED_CANDIDATE_STATE_ISSUER,
) = create_one_shot_registry()
_PREPARED_EXECUTION_FINALIZATION_ISSUER = object()


@final
class _PreparedFinalizationOwner:
    """Opaque prepared-candidate owner expected from future orchestration."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("_PreparedFinalizationOwner cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Prepared candidate finalization is issued by core orchestration only.")

    def _state(self) -> _PreparedCandidateState:
        try:
            state = _PREPARED_CANDIDATE_STATES[self]
        except (KeyError, TypeError):
            raise TypeError(
                "A genuine prepared-candidate finalization owner is required."
            ) from None
        if type(state) is not _PreparedCandidateState:
            raise TypeError("A genuine prepared-candidate finalization owner is required.")
        return state

    def __repr__(self) -> str:
        self._state()
        return "_PreparedFinalizationOwner(<opaque temporary core owner>)"

    def __copy__(self) -> _PreparedFinalizationOwner:
        _reject_copy()

    def __deepcopy__(self, _memo: object) -> _PreparedFinalizationOwner:
        _reject_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_copy()

    def __getstate__(self) -> object:
        _reject_copy()


def _request_readback_from_worker_evidence(
    value: object,
) -> _AuthenticatedRequestReadback:
    if type(value) is AuthenticatedWorkerExecutionEvidence:
        return _readback_authenticated_execution(value).request_readback
    if type(value) is WorkerInvocationObservation:
        return _readback_worker_invocation_observation(value).request_readback
    raise TypeError("Prepared finalization requires exact sealed worker evidence.")


def _issue_prepared_execution_finalization(
    issuer: object,
    *,
    authorization: object,
    started_at_utc: str,
    ended_at_utc: str,
    runtime_seconds: float,
    validation_evidence: object,
    fit_attempt_evidence: object,
    cache_lineage: object | None,
    candidate_execution_context: object | None = None,
) -> _PreparedFinalizationOwner:
    """Bind finalization only to exact PreparationTransaction execution owners."""

    from ebm_audit.adapters.invocation import (
        _read_prepared_candidate_execution_context,
    )
    from ebm_audit.universe.identities import validated_planning_summary_id
    from ebm_audit.universe.preparation import _resolve_prepared_execution_authorization

    if issuer is not _PREPARED_EXECUTION_FINALIZATION_ISSUER:
        raise TypeError("Prepared execution finalization has no public issuer.")
    if candidate_execution_context is None:
        prepared = _resolve_prepared_execution_authorization(authorization)
    else:
        context_state = _read_prepared_candidate_execution_context(candidate_execution_context)
        invocation_context = context_state.invocation_context
        if invocation_context.authorization is not authorization:
            raise TypeError("Prepared finalization context is detached from its authorization.")
        prepared = invocation_context.prepared_state
    plan = strict_json_loads(prepared.plan_bytes)
    record = strict_json_loads(prepared.record_bytes)
    universe = strict_json_loads(prepared.universe_bytes)
    planning_summary = strict_json_loads(prepared.planning_summary_binding_bytes)
    selected_binding = strict_json_loads(prepared.selected_algorithm_binding_bytes)
    if (
        type(plan) is not dict
        or type(record) is not dict
        or type(universe) is not dict
        or type(planning_summary) is not dict
        or type(selected_binding) is not dict
        or type(started_at_utc) is not str
        or type(ended_at_utc) is not str
        or not _is_nonnegative_finite_number(runtime_seconds)
        or type(fit_attempt_evidence) is not tuple
    ):
        raise TypeError("Prepared execution finalization inputs are invalid.")
    planning_summary_id = validated_planning_summary_id(planning_summary)
    validation_owner = _exact_worker_evidence(validation_evidence)
    validation_request = _request_readback_from_worker_evidence(validation_owner)
    effective_execution_context = (
        candidate_execution_context
        if candidate_execution_context is not None
        else validation_request.prepared_candidate_execution_context
    )
    try:
        effective_context_state = _read_prepared_candidate_execution_context(
            effective_execution_context
        )
    except TypeError:
        raise TypeError(
            "Validation evidence is detached from the prepared execution authorization."
        ) from None
    effective_invocation_context = effective_context_state.invocation_context
    if (
        effective_invocation_context.authorization is not authorization
        or effective_invocation_context.prepared_state is not prepared
        or validation_request.prepared_candidate_execution_context
        is not effective_execution_context
        or validation_request.prepared_candidate_execution_context_state
        is not effective_context_state
        or validation_request.command != "validate"
        or validation_request.planning_summary_id != planning_summary_id
        or validation_request.authenticated_description is not prepared.authenticated_description
        or validation_request.selected_algorithm_binding is None
        or dict(validation_request.selected_algorithm_binding) != selected_binding
        or validation_request.execution_input_projection_digest is None
    ):
        raise TypeError(
            "Validation evidence is detached from the prepared execution authorization."
        )
    fit_owners = tuple(
        _exact_worker_evidence(value) for value in cast(tuple[object, ...], fit_attempt_evidence)
    )
    for fit_owner in fit_owners:
        request = _request_readback_from_worker_evidence(fit_owner)
        if (
            request.command != "fit"
            or request.prepared_candidate_execution_context is not effective_execution_context
            or request.prepared_candidate_execution_context_state
            is not effective_context_state
            or request.planning_summary_id != planning_summary_id
            or request.authenticated_description is not prepared.authenticated_description
            or request.selected_algorithm_binding is None
            or dict(request.selected_algorithm_binding) != selected_binding
        ):
            raise TypeError("Fit evidence is detached from the prepared execution authorization.")
    if cache_lineage is not None and type(cache_lineage) is not VerifiedCacheLineage:
        raise TypeError("Prepared candidate cache lineage has no exact core owner.")
    chain_plan = universe.get("chain_plan")
    if not isinstance(chain_plan, list) or not chain_plan:
        raise TypeError("Prepared execution finalization has no exact chain plan.")
    ordered_chain_ids = tuple(
        str(cast(Mapping[str, Any], row)["chain_execution_id"]) for row in chain_plan
    )
    owner = object.__new__(_PreparedFinalizationOwner)
    _PREPARED_CANDIDATE_STATE_ISSUER.bind_once(
        owner,
        _PreparedCandidateState(
            planning_summary_id=planning_summary_id,
            prepared_execution_authorization=authorization,
            prepared_candidate_execution_context=effective_execution_context,
            prepared_candidate_execution_context_state=effective_context_state,
            prepared_execution_state=prepared,
            plan_digest=str(plan["plan_digest"]),
            candidate_ordinal=int(record["candidate_ordinal"]),
            candidate_id=str(record["candidate_id"]),
            analysis_spec_id=str(record["analysis_spec_id"]),
            universe_id=str(universe["universe_id"]),
            execution_input_projection_digest=(
                validation_request.execution_input_projection_digest
            ),
            ordered_chain_execution_ids=ordered_chain_ids,
            started_at_utc=started_at_utc,
            ended_at_utc=ended_at_utc,
            runtime_seconds=float(runtime_seconds),
            validation_evidence=validation_owner,
            fit_attempt_evidence=fit_owners,
            cache_lineage=cache_lineage,
            canonical_dataset=prepared.canonical_dataset,
        ),
    )
    owner._state()
    return owner


@dataclass(frozen=True, repr=False)
class _VerifiedCacheLineageState:
    canonical_bytes: bytes
    source_result: FinalizedResult | None


_VERIFIED_CACHE_STATES: OneShotWeakRegistry[object, _VerifiedCacheLineageState]
_VERIFIED_CACHE_STATE_ISSUER: OneShotRegistryIssuer[
    object, _VerifiedCacheLineageState
]
(
    _VERIFIED_CACHE_STATES,
    _VERIFIED_CACHE_STATE_ISSUER,
) = create_one_shot_registry()
_VERIFIED_CACHE_ISSUER = object()


@final
class VerifiedCacheLineage:
    """Opaque cache-subsystem proof; a lineage mapping is never sufficient."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("VerifiedCacheLineage cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Verified cache lineage is issued by the core cache subsystem only.")

    def _state(self) -> _VerifiedCacheLineageState:
        try:
            state = _VERIFIED_CACHE_STATES[self]
        except (KeyError, TypeError):
            raise TypeError("A genuine verified cache-lineage owner is required.") from None
        if type(state) is not _VerifiedCacheLineageState:
            raise TypeError("A genuine verified cache-lineage owner is required.")
        return state

    def __repr__(self) -> str:
        self._state()
        return "VerifiedCacheLineage(<opaque core cache proof>)"

    def __copy__(self) -> VerifiedCacheLineage:
        _reject_copy()

    def __deepcopy__(self, _memo: object) -> VerifiedCacheLineage:
        _reject_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_copy()

    def __getstate__(self) -> object:
        _reject_copy()


def _issue_verified_cache_lineage(
    issuer: object,
    *,
    cache_disposition: str,
    universe_id: str,
    fit_execution_evidence: object,
    source_result: FinalizedResult | None,
) -> VerifiedCacheLineage:
    if issuer is not _VERIFIED_CACHE_ISSUER:
        raise TypeError("Verified cache lineage has no public issuer.")
    cache_identity = _derive_cache_identity(
        universe_id=universe_id,
        fit_execution_evidence=fit_execution_evidence,
    )
    if cache_disposition == "HIT":
        source_bytes = finalized_result_cache_admission_bytes(source_result)
        source_record = strict_json_loads(source_bytes)
        if type(source_record) is not dict:
            raise TypeError("A cache hit source result is invalid.")
        source_lineage = source_record["body"].get("cache_lineage")
        if not isinstance(source_lineage, Mapping) or (
            source_lineage.get("universe_cache_key") != cache_identity["universe_cache_key"]
            or source_lineage.get("chain_cache_keys") != cache_identity["chain_cache_keys"]
        ):
            raise TypeError("A cache hit source is detached from the current cache identity.")
        source_state = _read_finalized_result(source_result)
        source_result_id: str | None = source_state.result_id
    elif cache_disposition == "MISS" and source_result is None:
        source_result_id = None
    else:
        raise TypeError("A cache miss cannot name a source result capability.")
    preimage = {
        "cache_disposition": cache_disposition,
        "universe_cache_key": cache_identity["universe_cache_key"],
        "chain_cache_keys": cache_identity["chain_cache_keys"],
        "source_result_id": source_result_id,
    }
    value = {
        **preimage,
        "cache_verification_digest": structured_sha256(
            "ebm-audit/cache-lineage-verification/1", preimage
        ),
    }
    validate_instance(value, "canonical-records.schema.json", definition="CacheLineage")
    self = object.__new__(VerifiedCacheLineage)
    _VERIFIED_CACHE_STATE_ISSUER.bind_once(
        self,
        _VerifiedCacheLineageState(
            canonical_bytes=canonical_json_bytes(value),
            source_result=source_result,
        ),
    )
    self._state()
    return self


class _FinalizedResultState(NamedTuple):
    canonical_bytes: bytes
    result_id: str
    record_kind: str
    status: str
    candidate_result_authorization: object | None
    prepared_finalization_owner: _PreparedFinalizationOwner | None
    cache_lineage: VerifiedCacheLineage | None
    canonical_dataset: CanonicalDataset | None
    scientific_owner_bytes: bytes | None
    reference_chain_execution: AuthenticatedWorkerExecutionEvidence | None
    descriptive_chain_executions: tuple[AuthenticatedWorkerExecutionEvidence, ...]
    unprepared_execution_state: object | None = None
    execution_origin: str = "ORDINARY"
    profile_fit_session: object | None = None
    profile_fit_slot_group: object | None = None
    profile_candidate_ordinal: int | None = None
    profile_validation_evidence: object | None = None
    profile_fit_terminals: tuple[object, ...] = ()
    profile_storage_observations: tuple[object, ...] = ()


_FINALIZED_RESULT_STATES: OneShotWeakRegistry[object, _FinalizedResultState]
_FINALIZED_RESULT_STATE_ISSUER: OneShotRegistryIssuer[
    object, _FinalizedResultState
]
(
    _FINALIZED_RESULT_STATES,
    _FINALIZED_RESULT_STATE_ISSUER,
) = create_one_shot_registry()

@final
class FinalizedResult:
    """Opaque authority over one exact canonical and semantically read-back result."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("FinalizedResult cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Finalized results are issued by the core result finalizer only.")

    def __repr__(self) -> str:
        state = _read_finalized_result(self)
        return f"FinalizedResult(kind={state.record_kind!r}, status={state.status!r})"

    def __copy__(self) -> FinalizedResult:
        _reject_copy()

    def __deepcopy__(self, _memo: object) -> FinalizedResult:
        _reject_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_copy()

    def __getstate__(self) -> object:
        _reject_copy()

    @property
    def result_id(self) -> str:
        return _read_finalized_result(self).result_id

    @property
    def canonical_bytes(self) -> bytes:
        state = _read_finalized_result(self)
        _require_ordinary_finalized_result(state)
        return bytes(state.canonical_bytes)


_FINALIZATION_LOCK = RLock()
_PROFILE_FINALIZATION_ISSUER = object()
_FINALIZED_BY_PREPARED_OWNER = CallbackFreeWeakIdentityMap[
    _PreparedFinalizationOwner, FinalizedResult
](_FINALIZATION_LOCK)
_FINALIZED_BY_UNPREPARED_AUTHORIZATION = CallbackFreeWeakIdentityMap[
    object, FinalizedResult
](_FINALIZATION_LOCK)


@dataclass(frozen=True, repr=False)
class _UnpreparedFinalizationSnapshot:
    authorization_state: object
    canonical_bytes: bytes
    result_id: str
    status: str


_UNPREPARED_FINALIZATION_SNAPSHOTS: OneShotWeakRegistry[
    object, _UnpreparedFinalizationSnapshot
]
_UNPREPARED_FINALIZATION_SNAPSHOT_ISSUER: OneShotRegistryIssuer[
    object, _UnpreparedFinalizationSnapshot
]
(
    _UNPREPARED_FINALIZATION_SNAPSHOTS,
    _UNPREPARED_FINALIZATION_SNAPSHOT_ISSUER,
) = create_one_shot_registry()


def _unprepared_result_body(
    authorization_state: object,
    *,
    timestamp: str,
) -> dict[str, Any]:
    from ebm_audit.adapters.invocation import _core_code_digest
    from ebm_audit.universe.preparation import (
        _unprepared_terminal_status,
        _UnpreparedResultAuthorizationState,
    )

    if (
        type(authorization_state) is not _UnpreparedResultAuthorizationState
        or type(timestamp) is not str
    ):
        raise TypeError("Unprepared authorization storage is invalid.")
    state = authorization_state
    plan = strict_json_loads(state.plan_bytes)
    record = strict_json_loads(state.record_bytes)
    if type(plan) is not dict or type(record) is not dict:
        raise TypeError("Unprepared authorization storage is invalid.")
    status = _unprepared_terminal_status(record)
    error_code = {
        "INVALID_SPECIFICATION": "PREPARATION.INVALID_SPECIFICATION",
        "UNSUPPORTED_CAPABILITY": "PREPARATION.UNSUPPORTED_CAPABILITY",
    }[status]
    return {
        "record_kind": "UNPREPARED",
        "plan_schema_version": "ebm-audit-analysis-plan/3.0",
        "plan_digest": plan["plan_digest"],
        "candidate_ordinal": record["candidate_ordinal"],
        "candidate_id": record["candidate_id"],
        "analysis_spec_id": record["analysis_spec_id"],
        "universe_id": None,
        "status": status,
        "input_digest": state.input_digest,
        "config_digest": state.config_digest,
        "core_code_digest": _core_code_digest(),
        "started_at_utc": timestamp,
        "ended_at_utc": timestamp,
        "runtime_seconds": 0.0,
        "warnings": [],
        "output_hashes": {},
        "preparation_state": record["state"],
        "operation_seed": record["operation_seed"],
        "preparation_reasons": copy.deepcopy(record["reasons"]),
        "error": {
            "code": error_code,
            "category": status,
            "safe_message": core_owned_negative_response_message(status),
            "phase": "candidate-finalization",
            "retryable_identical_request": False,
            "issues": [],
            "details": {
                "counts": {},
                "internal_indexes": [],
                "approved_event_ids": [],
                "digests": {},
            },
        },
        "diagnostic_references": [],
    }


def _validate_unprepared_finalization_snapshot(
    snapshot: object,
    *,
    authorization_state: object,
) -> _UnpreparedFinalizationSnapshot:
    """Reprove stable reissuance bytes against the still-live authorization."""

    from ebm_audit.universe.preparation import _UnpreparedResultAuthorizationState

    if (
        type(snapshot) is not _UnpreparedFinalizationSnapshot
        or type(authorization_state) is not _UnpreparedResultAuthorizationState
        or snapshot.authorization_state is not authorization_state
    ):
        raise TypeError("Unprepared finalization snapshot is invalid.")
    state = authorization_state
    decoded = strict_json_loads(snapshot.canonical_bytes)
    if (
        type(decoded) is not dict
        or canonical_json_bytes(decoded) != snapshot.canonical_bytes
        or validate_result_record_finalization(decoded) != decoded
        or decoded.get("result_id") != snapshot.result_id
    ):
        raise TypeError("Unprepared finalization snapshot is invalid.")
    body = decoded.get("body")
    if (
        not isinstance(body, Mapping)
        or type(body.get("started_at_utc")) is not str
        or dict(body)
        != _unprepared_result_body(
            state,
            timestamp=cast(str, body["started_at_utc"]),
        )
        or snapshot.status != body["status"]
    ):
        raise TypeError("Unprepared finalization snapshot is invalid.")
    return snapshot


def _require_finalized_result_state_identity(
    value: object,
    state: object,
) -> _FinalizedResultState:
    """Require one exact retained state without replaying its scientific owners."""

    if type(value) is not FinalizedResult or type(state) is not _FinalizedResultState:
        raise TypeError("A genuine finalized-result capability is required.")
    try:
        _FINALIZED_RESULT_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError("A genuine finalized-result capability is required.") from None
    return state


def _capture_finalized_result_state_identity(
    value: object,
) -> _FinalizedResultState:
    """Capture registry identity only after this boundary fully validated the owner."""

    if type(value) is not FinalizedResult:
        raise TypeError("A genuine finalized-result capability is required.")
    try:
        state = _FINALIZED_RESULT_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine finalized-result capability is required.") from None
    return _require_finalized_result_state_identity(value, state)


def _require_ordinary_finalized_result(
    state: _FinalizedResultState,
) -> _FinalizedResultState:
    if type(state) is not _FinalizedResultState or state.execution_origin != "ORDINARY":
        raise TypeError("Profile finalized results have no ordinary result authority.")
    return state


def _read_finalized_result(value: object) -> _FinalizedResultState:
    state = _capture_finalized_result_state_identity(value)
    try:
        record = strict_json_loads(state.canonical_bytes)
        if type(record) is not dict:
            raise TypeError("Finalized-result storage is invalid.")
        if state.execution_origin == "PROFILE":
            body = record.get("body")
            preimage = {
                "result_schema_version": record.get("result_schema_version"),
                "body": body,
            }
            if (
                set(record) != {"result_schema_version", "body", "result_id"}
                or record.get("result_schema_version") != _RESULT_SCHEMA_VERSION
                or type(body) is not dict
                or canonical_json_bytes(record) != state.canonical_bytes
                or record.get("result_id")
                != structured_sha256("ebm-audit/result-record/2", preimage)
                or record.get("result_id") != state.result_id
                or body.get("record_kind") != state.record_kind
                or body.get("status") != state.status
                or body.get("execution_origin") != "PROFILE"
                or body.get("candidate_ordinal")
                != state.profile_candidate_ordinal
                or body.get("cache_lineage") is not None
                or state.candidate_result_authorization is None
                or state.profile_fit_session is None
                or state.profile_fit_slot_group is None
                or type(state.profile_candidate_ordinal) is not int
                or state.profile_candidate_ordinal not in {0, 1, 2}
                or state.profile_validation_evidence is None
                or type(state.profile_fit_terminals) is not tuple
                or len(state.profile_fit_terminals) != 3
                or type(state.profile_storage_observations) is not tuple
                or len(state.profile_storage_observations) != 2
                or state.prepared_finalization_owner is not None
                or state.cache_lineage is not None
                or state.canonical_dataset is not None
                or state.scientific_owner_bytes is not None
                or state.reference_chain_execution is not None
                or state.descriptive_chain_executions
                or state.unprepared_execution_state is not None
            ):
                raise TypeError("Profile finalized-result authority storage is invalid.")
            return state
        validated = validate_result_record_finalization(cast(Mapping[str, Any], record))
        body = validated["body"]
        retained_lineage = _cache_lineage(state.cache_lineage)
        if (
            canonical_json_bytes(validated) != state.canonical_bytes
            or validated["result_id"] != state.result_id
            or body["record_kind"] != state.record_kind
            or body["status"] != state.status
            or body.get("cache_lineage") != retained_lineage
        ):
            raise TypeError("Finalized-result storage is invalid.")
        if state.execution_origin == "ORDINARY":
            if (
                body.get("execution_origin") is not None
                or state.profile_fit_session is not None
                or state.profile_fit_slot_group is not None
                or state.profile_candidate_ordinal is not None
                or state.profile_validation_evidence is not None
                or state.profile_fit_terminals
                or state.profile_storage_observations
            ):
                raise TypeError("Ordinary finalized-result authority storage is invalid.")
            resolved_fit_groups = _revalidate_candidate_result_authorization(
                cast(FinalizedResult, value),
                state,
                cast(Mapping[str, Any], body),
            )
            _revalidate_descriptive_chain_executions(
                state,
                cast(Mapping[str, Any], body),
                resolved_fit_groups=resolved_fit_groups,
            )
        else:
            raise TypeError("Finalized-result execution origin is invalid.")
        return state
    finally:
        _require_finalized_result_state_identity(value, state)


def _capture_finalized_result_state(value: object) -> _FinalizedResultState:
    """Capture one exact finalized-result state after complete semantic readback."""

    return _require_ordinary_finalized_result(_read_finalized_result(value))


def _assert_finalized_result_state_current(
    value: object,
    state: _FinalizedResultState,
) -> None:
    """Use a retained result state for semantics and live lookup only as a guard."""

    if (
        type(value) is not FinalizedResult
        or type(state) is not _FinalizedResultState
        or state.execution_origin != "ORDINARY"
        or _FINALIZED_RESULT_STATES.get(value) is not state
        or _read_finalized_result(value) is not state
    ):
        raise TypeError("Finalized result state changed.")


def _revalidate_prepared_worker_evidence(
    state: _PreparedCandidateState,
) -> tuple[tuple[_ResolvedAttempt, ...], ...]:
    """Reprove every retained validation and fit execution for this result owner."""

    _resolve_attempt(
        state.validation_evidence,
        expected_command="validate",
        chain_plan_position=None,
        expected_planning_summary_id=state.planning_summary_id,
    )
    return _resolve_fit_groups(
        tuple(state.fit_attempt_evidence),
        state=state,
    )


def _revalidate_candidate_result_authorization(
    value: FinalizedResult,
    state: _FinalizedResultState,
    body: Mapping[str, Any],
) -> tuple[tuple[_ResolvedAttempt, ...], ...] | None:
    """Reprove the exact preparation capability that issued this result."""

    from ebm_audit.universe.preparation import (
        PreparedExecutionAuthorization,
        UnpreparedResultAuthorization,
        _resolve_prepared_execution_authorization,
        _resolve_unprepared_result_authorization,
    )

    authorization = state.candidate_result_authorization
    prepared_owner = state.prepared_finalization_owner
    if type(authorization) is PreparedExecutionAuthorization:
        if type(prepared_owner) is not _PreparedFinalizationOwner:
            raise TypeError("Finalized-result preparation authority is invalid.")
        owner_state = prepared_owner._state()
        resolved_fit_groups = _revalidate_prepared_worker_evidence(owner_state)
        live_prepared = _resolve_prepared_execution_authorization(authorization)
        prepared = cast(Any, owner_state.prepared_execution_state)
        if prepared is None:
            prepared = live_prepared
        record = strict_json_loads(prepared.record_bytes)
        universe = strict_json_loads(prepared.universe_bytes)
        plan = strict_json_loads(prepared.plan_bytes)
        if (
            owner_state.prepared_execution_authorization is not authorization
            or live_prepared is not prepared
            or _FINALIZED_BY_PREPARED_OWNER.get(prepared_owner) is not value
            or type(record) is not dict
            or type(universe) is not dict
            or type(plan) is not dict
            or (
                plan["plan_digest"],
                record["candidate_ordinal"],
                record["candidate_id"],
                record["analysis_spec_id"],
                universe["universe_id"],
            )
            != (
                body["plan_digest"],
                body["candidate_ordinal"],
                body["candidate_id"],
                body["analysis_spec_id"],
                body["universe_id"],
            )
        ):
            raise TypeError("Finalized result is detached from its exact preparation authority.")
        return resolved_fit_groups
    if type(authorization) is UnpreparedResultAuthorization:
        unprepared = state.unprepared_execution_state
        live_unprepared = _resolve_unprepared_result_authorization(authorization)
        if (
            unprepared is None
            or live_unprepared is not unprepared
            or prepared_owner is not None
            or _FINALIZED_BY_UNPREPARED_AUTHORIZATION.get(authorization) is not value
        ):
            raise TypeError("Finalized result is detached from its exact preparation authority.")
        _validate_unprepared_finalization_snapshot(
            _UnpreparedFinalizationSnapshot(
                authorization_state=unprepared,
                canonical_bytes=state.canonical_bytes,
                result_id=state.result_id,
                status=state.status,
            ),
            authorization_state=unprepared,
        )
        if dict(body) != strict_json_loads(state.canonical_bytes)["body"]:
            raise TypeError("Finalized result is detached from its exact preparation authority.")
        return None

    # The null branch is an explicitly non-promotable contract-harness seam. It
    # still retains and revalidates the exact temporary prepared owner.
    if authorization is None and type(prepared_owner) is _PreparedFinalizationOwner:
        owner_state = prepared_owner._state()
        if (
            owner_state.prepared_execution_authorization is None
            and _FINALIZED_BY_PREPARED_OWNER.get(prepared_owner) is value
        ):
            resolved_fit_groups = _revalidate_prepared_worker_evidence(owner_state)
            if owner_state.planning_summary_id is None and (
                owner_state.plan_digest,
                owner_state.candidate_ordinal,
                owner_state.candidate_id,
                owner_state.analysis_spec_id,
                owner_state.universe_id,
            ) == (
                body["plan_digest"],
                body["candidate_ordinal"],
                body["candidate_id"],
                body["analysis_spec_id"],
                body["universe_id"],
            ):
                return resolved_fit_groups
    raise TypeError("Finalized-result preparation authority is invalid.")


def _finalized_result_candidate_authorization(value: object) -> object:
    """Return the exact production preparation capability after full revalidation."""

    state = _read_finalized_result(value)
    return _finalized_result_candidate_authorization_from_state(value, state)


def _finalized_result_candidate_authorization_from_state(
    value: object,
    state: _FinalizedResultState,
) -> object:
    """Project authorization from a state validated in this exact call boundary."""

    _require_finalized_result_state_identity(value, state)
    _require_ordinary_finalized_result(state)
    if state.candidate_result_authorization is None:
        raise TypeError("The contract-harness result has no production candidate authorization.")
    return state.candidate_result_authorization


def _revalidate_descriptive_chain_executions(
    state: _FinalizedResultState,
    body: Mapping[str, Any],
    *,
    resolved_fit_groups: tuple[tuple[_ResolvedAttempt, ...], ...] | None,
) -> None:
    """Reprove every retained descriptive chain against the exact result body."""

    retained = state.descriptive_chain_executions
    if type(retained) is not tuple or any(
        type(execution) is not AuthenticatedWorkerExecutionEvidence for execution in retained
    ):
        raise TypeError("Finalized-result descriptive-chain authority is invalid.")
    if state.status not in {"SUCCESS", "CONVERGENCE_WARN"}:
        if retained or state.reference_chain_execution is not None:
            raise TypeError("A non-descriptive result retained descriptive-chain authority.")
        return

    chain_results = body.get("chain_results")
    evidence_rows = body.get("fit_attempt_evidence")
    if (
        state.record_kind != "COMPLETED"
        or not isinstance(chain_results, list)
        or not isinstance(evidence_rows, list)
        or len(retained) != len(chain_results)
        or not retained
        or (
            state.reference_chain_execution
            is not (retained[0] if state.status == "SUCCESS" else None)
        )
    ):
        raise TypeError("Finalized-result descriptive-chain authority is invalid.")
    prepared_owner = state.prepared_finalization_owner
    if type(prepared_owner) is not _PreparedFinalizationOwner or resolved_fit_groups is None:
        raise TypeError("Finalized-result descriptive-chain authority is invalid.")
    owner_terminals = tuple(group[-1] for group in resolved_fit_groups)
    if len(owner_terminals) != len(retained) or any(
        terminal.status != "SUCCESS" or terminal.capability is not execution
        for terminal, execution in zip(owner_terminals, retained, strict=True)
    ):
        raise TypeError("Finalized-result descriptive-chain authority is invalid.")
    for position, (_execution, terminal, expected_payload) in enumerate(
        zip(retained, owner_terminals, chain_results, strict=True)
    ):
        response = terminal.response
        if response is None:
            raise TypeError("Finalized-result descriptive-chain authority is invalid.")
        if response["command"] != "fit" or response["status"] != "SUCCESS":
            raise TypeError("Finalized-result descriptive-chain authority is invalid.")
        payload = _chain_payload_from_result(
            cast(Mapping[str, Any], response["payload"]["result"]),
            chain_plan_position=position,
        )
        matching_rows = [
            row
            for row in evidence_rows
            if isinstance(row, Mapping)
            and row.get("chain_plan_position") == position
            and row.get("status") == "SUCCESS"
            and row.get("authenticated_execution_evidence_digest")
            == terminal.reference["authenticated_execution_evidence_digest"]
        ]
        if payload != expected_payload or len(matching_rows) != 1:
            raise TypeError("Finalized-result descriptive-chain authority is invalid.")


def _finalized_result_descriptive_chain_executions(
    value: object,
) -> tuple[AuthenticatedWorkerExecutionEvidence, ...]:
    """Return exact retained owners only after full result and chain revalidation."""

    state = _read_finalized_result(value)
    return _finalized_result_descriptive_chain_executions_from_state(value, state)


def _finalized_result_descriptive_chain_executions_from_state(
    value: object,
    state: _FinalizedResultState,
) -> tuple[AuthenticatedWorkerExecutionEvidence, ...]:
    """Project retained chain owners from this boundary's validated state."""

    _require_finalized_result_state_identity(value, state)
    _require_ordinary_finalized_result(state)
    return state.descriptive_chain_executions


@dataclass(frozen=True, repr=False)
class _FinalizedBaselineSource:
    """Private exact owners needed to project one successful baseline result."""

    source_result: FinalizedResult
    source_record: Mapping[str, Any]
    canonical_dataset: CanonicalDataset
    scientific_owner: Mapping[str, Any]
    reference_chain_payload: Mapping[str, Any]
    reference_chain_arrays: Mapping[str, Any]


def _assert_canonical_dataset_owner(
    canonical_dataset: CanonicalDataset,
    scientific_owner: Mapping[str, Any],
) -> None:
    """Bind the retained private canonical owner to the worker's exact input."""

    if type(canonical_dataset) is not CanonicalDataset:
        raise TypeError("Finalized baseline data has no exact canonical owner.")
    validate_canonical_dataset(canonical_dataset)
    dataset = scientific_owner.get("dataset")
    if not isinstance(dataset, Mapping):
        raise TypeError("Finalized baseline data has no exact worker-input owner.")
    view = canonical_dataset.view
    private_arrays = canonical_dataset.private.arrays
    catalog = dataset.get("array_catalog")
    if not isinstance(catalog, Mapping):
        raise TypeError("Finalized baseline data has no exact worker-input array owner.")
    expected_array_sources = {
        "train_values": "event_values",
        "training_row_indexes": "participant_internal_indexes",
        "train_group_codes": "group_role_codes",
    }
    for request_name, canonical_name in expected_array_sources.items():
        entry = catalog.get(request_name)
        if not isinstance(entry, Mapping) or canonical_name not in private_arrays:
            raise TypeError("Finalized baseline data has no exact worker-input array owner.")
        observed = array_catalog_entry(
            request_name,
            private_arrays[canonical_name],
            semantic_version=cast(str, entry.get("semantic_version")),
        )
        if observed != entry:
            raise TypeError("Finalized baseline data is detached from its worker input.")
    if (
        dataset.get("variant_id") != view.variant_id
        or dataset.get("participant_count") != view.participant_count
        or dataset.get("event_count") != view.event_count
        or dataset.get("event_ids") != list(view.event_ids)
        or dataset.get("event_directions") != list(view.event_directions)
        or dataset.get("scientific_data_digest") != canonical_dataset.scientific_data_digest
        or scientific_owner.get("data_accounting") != view.data_accounting.to_record()
    ):
        raise TypeError("Finalized baseline data is detached from its worker input.")


def _prepared_result_can_own_canonical_baseline(prepared_state: object) -> bool:
    """Return whether the exact prepared result used unmodified canonical training rows."""

    analysis_spec_bytes = getattr(prepared_state, "analysis_spec_bytes", None)
    if type(analysis_spec_bytes) is not bytes:
        raise TypeError("Prepared baseline eligibility has no exact analysis owner.")
    analysis_spec = strict_json_loads(analysis_spec_bytes)
    operation_intent = (
        analysis_spec.get("operation_intent") if type(analysis_spec) is dict else None
    )
    preprocessing = (
        analysis_spec.get("preprocessing") if type(analysis_spec) is dict else None
    )
    if (
        type(analysis_spec) is not dict
        or canonical_json_bytes(analysis_spec) != analysis_spec_bytes
        or not isinstance(operation_intent, Mapping)
        or type(operation_intent.get("kind")) is not str
        or type(preprocessing) is not list
    ):
        raise TypeError("Prepared baseline eligibility has no exact analysis owner.")
    return cast(str, operation_intent["kind"]) == "ordinary" and preprocessing == []


def _baseline_source_from_finalized_result(value: object) -> _FinalizedBaselineSource:
    """Return private source owners only for one exact eligible successful result."""

    state = _read_finalized_result(value)
    return _baseline_source_from_validated_finalized_result(value, state)


def _baseline_source_from_validated_finalized_result(
    value: object,
    state: _FinalizedResultState,
) -> _FinalizedBaselineSource:
    """Project baseline owners from a result fully validated by this boundary."""

    _require_finalized_result_state_identity(value, state)
    _require_ordinary_finalized_result(state)
    prepared_owner = state.prepared_finalization_owner
    if state.record_kind != "COMPLETED" or state.status != "SUCCESS":
        raise TypeError("Baseline projection requires one exact successful finalized result.")
    if (
        type(state.canonical_dataset) is not CanonicalDataset
        or type(state.scientific_owner_bytes) is not bytes
        or type(state.reference_chain_execution) is not AuthenticatedWorkerExecutionEvidence
        or type(prepared_owner) is not _PreparedFinalizationOwner
        or not _prepared_result_can_own_canonical_baseline(
            prepared_owner._state().prepared_execution_state
        )
    ):
        raise TypeError("The finalized result has no exact private baseline source owner.")
    prepared_state = prepared_owner._state()

    record = strict_json_loads(state.canonical_bytes)
    scientific_owner = strict_json_loads(state.scientific_owner_bytes)
    if type(record) is not dict or type(scientific_owner) is not dict:
        raise TypeError("The finalized result has invalid private baseline source storage.")
    validate_instance(
        scientific_owner,
        "worker-protocol.schema.json",
        definition="ExecutionInputProjection",
    )
    if canonical_json_bytes(scientific_owner) != state.scientific_owner_bytes:
        raise TypeError("The finalized result has invalid private baseline source storage.")
    _assert_canonical_dataset_owner(state.canonical_dataset, scientific_owner)

    (
        _execution,
        request,
        response,
        _command_digest,
        _execution_digest,
        response_arrays,
        _request_evidence_digest,
        _response_warnings_bytes,
        _planning_summary_id,
    ) = _resolved_execution(
        state.reference_chain_execution,
        expected_planning_summary_id=prepared_state.planning_summary_id,
    )
    if response["status"] != "SUCCESS":
        raise TypeError("The finalized result baseline source is not successful.")
    request_payload = cast(Mapping[str, Any], request["payload"])
    if request_payload.get("execution_input_projection") != scientific_owner or request_payload.get(
        "execution_input_projection_digest"
    ) != execution_input_projection_digest(scientific_owner):
        raise TypeError("The finalized result baseline source is detached.")
    body = cast(Mapping[str, Any], record["body"])
    reference = cast(Mapping[str, Any], body["reference_chain"])
    position = cast(int, reference["chain_plan_position"])
    chains = cast(list[Mapping[str, Any]], body["chain_results"])
    if position < 0 or position >= len(chains):
        raise TypeError("The finalized result reference-chain owner is invalid.")
    result = cast(Mapping[str, Any], response["payload"]["result"])
    payload = _chain_payload_from_result(result, chain_plan_position=position)
    if (
        payload != chains[position]
        or reference["chain_execution_id"] != payload["chain_execution_id"]
        or reference["final_attempt_id"] != payload["final_attempt_id"]
        or reference["chain_payload_digest"] != payload["chain_payload_digest"]
    ):
        raise TypeError("The finalized result reference-chain owner is detached.")
    return _FinalizedBaselineSource(
        source_result=cast(FinalizedResult, value),
        source_record=copy.deepcopy(record),
        canonical_dataset=state.canonical_dataset,
        scientific_owner=copy.deepcopy(scientific_owner),
        reference_chain_payload=copy.deepcopy(payload),
        reference_chain_arrays=response_arrays,
    )


@dataclass(frozen=True, repr=False)
class _ResolvedAttempt:
    capability: AuthenticatedWorkerExecutionEvidence | WorkerInvocationObservation
    request: Mapping[str, Any]
    response: Mapping[str, Any] | None
    response_arrays: Mapping[str, Any] | None
    response_warnings_bytes: bytes | None
    reference: Mapping[str, Any]
    command: str
    status: str
    chain_execution_id: str | None
    attempt_id: str | None
    attempt_ordinal: int | None
    retry_equivalence_digest: str | None
    failure_class: str | None
    failure_code: str | None
    planning_summary_id: str | None


def _verify_response_owner(response: Mapping[str, Any]) -> None:
    identity = response.get("backend_identity")
    if not isinstance(identity, Mapping) or response.get(
        "backend_identity_digest"
    ) != backend_identity_digest(identity):
        raise TypeError("Authenticated response backend identity failed finalization readback.")
    capabilities = response.get("capabilities")
    if not isinstance(capabilities, Mapping) or response.get(
        "capabilities_digest"
    ) != capabilities_digest(capabilities):
        raise TypeError("Authenticated response capabilities failed finalization readback.")


def _verify_fit_payload_and_artifacts(
    response_file_bytes: Callable[[str], bytes],
    response: Mapping[str, Any],
) -> None:
    if response["command"] != "fit" or response["status"] != "SUCCESS":
        return
    result = response["payload"]["result"]
    if not isinstance(result, Mapping):
        raise TypeError("Authenticated fit response has no scientific result owner.")
    fit_preimage = copy.deepcopy(dict(result))
    supplied = fit_preimage.pop("worker_fit_payload_digest", None)
    if supplied != worker_fit_payload_digest(fit_preimage):
        raise TypeError("Authenticated fit payload failed finalization digest readback.")

    for artifact in cast(list[Mapping[str, Any]], result["backend_artifacts"]):
        relative_path = str(artifact["relative_path"])
        try:
            material = response_file_bytes(relative_path)
        except Exception:
            raise TypeError("Authenticated fit artifact has no retained byte owner.") from None
        if (
            response["files"].get(relative_path)
            != {
                "byte_length": artifact["byte_length"],
                "sha256": artifact["sha256"],
            }
            or len(material) != artifact["byte_length"]
            or exact_file_sha256(material) != artifact["sha256"]
        ):
            raise TypeError("Authenticated fit artifact failed exact-byte readback.")


def _resolved_execution(
    capability: object,
    *,
    expected_planning_summary_id: str | None | object,
    authenticated_readback: _AuthenticatedExecutionReadback | None = None,
) -> tuple[
    AuthenticatedWorkerExecutionEvidence,
    Mapping[str, Any],
    Mapping[str, Any],
    str,
    str,
    Mapping[str, Any],
    str,
    bytes,
    str | None,
]:
    if type(capability) is not AuthenticatedWorkerExecutionEvidence:
        raise TypeError("Finalization requires exact authenticated execution evidence.")
    readback = (
        _readback_authenticated_execution(capability)
        if authenticated_readback is None
        else authenticated_readback
    )
    if (
        type(readback) is not _AuthenticatedExecutionReadback
        or readback.execution is not capability
    ):
        raise TypeError("Authenticated execution evidence failed finalization readback.")
    execution = readback.execution
    request = readback.request
    response = readback.response
    command_evidence = readback.command_evidence
    if (
        (
            expected_planning_summary_id is not _INFER_PLANNING_SUMMARY_ID
            and readback.request_planning_summary_id != expected_planning_summary_id
        )
        or readback.execution_evidence_digest
        != authenticated_execution_evidence_digest(dict(readback.execution_identity_projection))
        or response["response_metadata_digest"] != response_metadata_digest(response)
        or response.get("request_metadata_digest") != request["request_metadata_digest"]
        or response.get("scientific_request_digest") != request["scientific_request_digest"]
        or response.get("command") != request["command"]
        or command_evidence is None
    ):
        raise TypeError("Authenticated execution evidence failed finalization readback.")
    command_evidence_digest = worker_command_evidence_digest(command_evidence)
    reference = readback.execution_identity_projection.get("command_evidence_reference")
    if not isinstance(reference, Mapping) or reference.get("digest") != command_evidence_digest:
        raise TypeError("Authenticated command evidence failed finalization readback.")
    _verify_response_owner(response)
    _verify_fit_payload_and_artifacts(readback.response_file_bytes, response)
    return (
        execution,
        request,
        response,
        command_evidence_digest,
        readback.execution_evidence_digest,
        readback.response_arrays,
        str(readback.execution_identity_projection["authenticated_request_evidence_digest"]),
        readback.response_file_bytes("warnings.jsonl"),
        readback.request_planning_summary_id,
    )


def _observation_status(
    failure_class: InvocationFailureClass,
    failure_code: str,
) -> str:
    if type(failure_class) is not InvocationFailureClass:
        raise TypeError("Core-observed failure has an invalid closed class.")
    if failure_class is InvocationFailureClass.PROCESS_FAILURE:
        if failure_code not in _RETRY_ELIGIBLE_PROCESS_FAILURE_CODES:
            raise TypeError("Core-observed process failure has an invalid exact code.")
    elif failure_code in _RETRY_ELIGIBLE_PROCESS_FAILURE_CODES:
        raise TypeError("Core-observed failure class cannot borrow a process-failure code.")
    return _CORE_FAILURE_STATUS[failure_class]


def _resolve_attempt(
    capability: object,
    *,
    expected_command: str,
    chain_plan_position: int | None,
    expected_planning_summary_id: str | None | object,
    authenticated_readback: _AuthenticatedExecutionReadback | None = None,
) -> _ResolvedAttempt:
    response: Mapping[str, Any] | None
    command_evidence_digest: str | None
    execution_digest: str | None
    failure: Mapping[str, Any] | None
    failure_digest: str | None
    failure_class: str | None
    failure_code: str | None

    if type(capability) is AuthenticatedWorkerExecutionEvidence:
        (
            execution,
            request,
            response,
            command_evidence_digest,
            execution_digest,
            response_arrays,
            request_evidence_digest,
            response_warnings_bytes,
            planning_summary_id,
        ) = _resolved_execution(
            capability,
            expected_planning_summary_id=expected_planning_summary_id,
            authenticated_readback=authenticated_readback,
        )
        status = str(response["status"])
        failure = None
        failure_digest = None
        failure_class = None
        failure_code = None
        retained_capability: AuthenticatedWorkerExecutionEvidence | WorkerInvocationObservation = (
            execution
        )
    elif type(capability) is WorkerInvocationObservation:
        if authenticated_readback is not None:
            raise TypeError("Observed failures cannot borrow authenticated readback.")
        observation = capability
        observation_readback = _readback_worker_invocation_observation(observation)
        request = observation_readback.request
        planning_summary_id = observation_readback.request_planning_summary_id
        projection = observation_readback.identity_projection
        request_evidence_digest = str(projection["authenticated_request_evidence_digest"])
        if (
            (
                expected_planning_summary_id is not _INFER_PLANNING_SUMMARY_ID
                and planning_summary_id != expected_planning_summary_id
            )
            or observation_readback.observation_digest
            != core_observed_failure_digest(dict(projection))
            or projection.get("failure_class") != observation_readback.failure_class.value
            or projection.get("failure_code") != observation_readback.failure_code
        ):
            raise TypeError("Core-observed failure failed finalization readback.")
        status = _observation_status(
            observation_readback.failure_class,
            observation_readback.failure_code,
        )
        response = None
        response_arrays = None
        response_warnings_bytes = None
        command_evidence_digest = None
        execution_digest = None
        failure = dict(projection)
        failure_digest = observation_readback.observation_digest
        failure_class = observation_readback.failure_class.value
        failure_code = observation_readback.failure_code
        retained_capability = observation
    else:
        raise TypeError("Finalization evidence must be an exact sealed worker capability.")

    command = str(request["command"])
    if command != expected_command:
        raise TypeError("Finalization evidence belongs to another worker command.")
    scientific_digest = request["scientific_request_digest"]
    if scientific_digest is None:
        raise TypeError("Finalization evidence has no scientific request identity.")

    chain_execution_id: str | None = None
    attempt_id: str | None = None
    attempt_ordinal: int | None = None
    retry_digest: str | None = None
    if command == "fit":
        payload = cast(Mapping[str, Any], request["payload"])
        chain_execution_id = cast(str, payload["chain_execution_id"])
        attempt_id = cast(str, payload["attempt_id"])
        attempt_ordinal = cast(int, payload["attempt_ordinal"])
        retry_digest = retry_equivalence_digest(request)
    elif chain_plan_position is not None:
        raise TypeError("Validate evidence cannot own a chain-plan position.")

    reference_value = {
        "evidence_reference_schema_version": _EVIDENCE_REFERENCE_SCHEMA_VERSION,
        "command": command,
        "status": status,
        "chain_plan_position": chain_plan_position,
        "chain_execution_id": chain_execution_id,
        "authenticated_request_evidence_digest": request_evidence_digest,
        "authenticated_execution_evidence_digest": execution_digest,
        "core_observed_failure": failure,
        "core_observed_failure_digest": failure_digest,
        "core_failure_class": failure_class,
        "core_failure_code": failure_code,
        "command_evidence_digest": command_evidence_digest,
        "request_metadata_digest": request["request_metadata_digest"],
        "scientific_request_digest": scientific_digest,
        "response_metadata_digest": (
            None if response is None else response["response_metadata_digest"]
        ),
        "attempt_id": attempt_id,
        "attempt_ordinal": attempt_ordinal,
        "retry_equivalence_digest": retry_digest,
    }
    validate_instance(
        reference_value,
        "canonical-records.schema.json",
        definition="WorkerExecutionEvidenceReference",
    )
    return _ResolvedAttempt(
        capability=retained_capability,
        request=request,
        response=response,
        response_arrays=response_arrays,
        response_warnings_bytes=response_warnings_bytes,
        reference=reference_value,
        command=command,
        status=status,
        chain_execution_id=chain_execution_id,
        attempt_id=attempt_id,
        attempt_ordinal=attempt_ordinal,
        retry_equivalence_digest=retry_digest,
        failure_class=failure_class,
        failure_code=failure_code,
        planning_summary_id=planning_summary_id,
    )


def _resolve_fit_groups(
    values: object,
    *,
    state: _PreparedCandidateState,
) -> tuple[tuple[_ResolvedAttempt, ...], ...]:
    if type(values) is not tuple:
        raise TypeError("Fit finalization evidence must use one exact ordered tuple.")
    supplied = cast(tuple[object, ...], values)
    groups: list[tuple[_ResolvedAttempt, ...]] = []
    cursor = 0
    for position, expected_chain_id in enumerate(state.ordered_chain_execution_ids):
        if cursor == len(supplied):
            break
        first = _resolve_attempt(
            supplied[cursor],
            expected_command="fit",
            chain_plan_position=position,
            expected_planning_summary_id=state.planning_summary_id,
        )
        _assert_fit_attempt_identity(first, universe_id=state.universe_id)
        if (
            first.chain_execution_id != expected_chain_id
            or first.attempt_ordinal != 0
            or first.attempt_id is None
        ):
            raise TypeError("Fit attempt zero is detached from the frozen chain plan.")
        cursor += 1
        group = [first]
        if cursor < len(supplied):
            candidate = _resolve_attempt(
                supplied[cursor],
                expected_command="fit",
                chain_plan_position=position,
                expected_planning_summary_id=state.planning_summary_id,
            )
            _assert_fit_attempt_identity(candidate, universe_id=state.universe_id)
            if candidate.attempt_ordinal == 1:
                if candidate.chain_execution_id != expected_chain_id:
                    raise TypeError("Fit retry is detached from its chain execution.")
                group.append(candidate)
                cursor += 1
        if len(group) == 2:
            initial, retry = group
            if (
                type(initial.capability) is not WorkerInvocationObservation
                or initial.failure_class != InvocationFailureClass.PROCESS_FAILURE.value
                or initial.failure_code not in _RETRY_ELIGIBLE_PROCESS_FAILURE_CODES
                or initial.status != "BACKEND_ERROR"
                or initial.retry_equivalence_digest != retry.retry_equivalence_digest
                or initial.attempt_id == retry.attempt_id
                or initial.reference["authenticated_request_evidence_digest"]
                == retry.reference["authenticated_request_evidence_digest"]
                or initial.reference["scientific_request_digest"]
                == retry.reference["scientific_request_digest"]
            ):
                raise TypeError("Fit retry lacks exact sealed start/crash authority.")
        groups.append(tuple(group))
    if cursor != len(supplied):
        raise TypeError("Fit finalization evidence is not the frozen chain-plan prefix.")
    return tuple(groups)


def _execution_input(attempt: _ResolvedAttempt) -> Mapping[str, Any]:
    payload = cast(Mapping[str, Any], attempt.request["payload"])
    return cast(Mapping[str, Any], payload["execution_input_projection"])


def _assert_fit_attempt_identity(
    attempt: _ResolvedAttempt,
    *,
    universe_id: str,
) -> None:
    if attempt.command != "fit":
        raise TypeError("Only fit evidence may own a chain-attempt identity.")
    payload = cast(Mapping[str, Any], attempt.request["payload"])
    if payload.get("universe_id") != universe_id:
        raise TypeError("Fit attempt is detached from its prepared universe.")
    chain_preimage = {
        "universe_id": universe_id,
        "chain_id": payload.get("chain_id"),
        "seed": payload.get("seed"),
    }
    validate_instance(
        chain_preimage,
        "analysis-universe.schema.json",
        definition="ChainExecutionIdPreimage",
    )
    expected_chain_id = structured_sha256("ebm-audit/chain-execution/3", chain_preimage)
    if attempt.chain_execution_id != expected_chain_id:
        raise TypeError("Fit chain execution identity is detached from its frozen owner.")
    attempt_preimage = {
        "chain_execution_id": expected_chain_id,
        "attempt_ordinal": attempt.attempt_ordinal,
    }
    validate_instance(
        attempt_preimage,
        "analysis-universe.schema.json",
        definition="AttemptIdPreimage",
    )
    if attempt.attempt_id != structured_sha256("ebm-audit/chain-attempt/3", attempt_preimage):
        raise TypeError("Fit attempt identity is detached from its chain and ordinal.")


def _chain_cache_key(attempt: _ResolvedAttempt) -> str:
    if (
        type(attempt.capability) is not AuthenticatedWorkerExecutionEvidence
        or attempt.response is None
        or attempt.status != "SUCCESS"
        or attempt.attempt_id is None
        or attempt.attempt_ordinal is None
        or attempt.chain_execution_id is None
    ):
        raise TypeError("A chain cache key requires one exact successful fit execution.")
    owner = _execution_input(attempt)
    dataset = cast(Mapping[str, Any], owner["dataset"])
    identity = cast(Mapping[str, Any], owner["selected_backend_identity"])
    preimage = {
        "cache_schema_version": "ebm-audit-chain-cache-preimage/4.0",
        "chain_execution_id": attempt.chain_execution_id,
        "attempt_id": attempt.attempt_id,
        "attempt_ordinal": attempt.attempt_ordinal,
        "scientific_data_digest": dataset["scientific_data_digest"],
        "config_digest": owner["config_digest"],
        "core_code_digest": owner["core_code_digest"],
        "backend_identity_digest": owner["selected_backend_identity_digest"],
        "worker_executable_digest": identity["worker_executable_digest"],
        "worker_code_digest": identity["worker_code_digest"],
        "backend_source_digest": identity["backend_source_digest"],
        "environment_digest": identity["environment_digest"],
        "capabilities_digest": owner["capabilities_digest"],
        "settings_digest": owner["settings_digest"],
        "requested_outputs_digest": owner["requested_outputs_digest"],
        "protocol_version": attempt.request["protocol_version"],
        "request_schema_version": attempt.request["request_schema_version"],
        "response_schema_version": attempt.response["response_schema_version"],
        "worker_payload_schema_version": attempt.response["payload_schema_version"],
        "canonical_result_schema_version": _RESULT_SCHEMA_VERSION,
    }
    validate_instance(
        preimage,
        "analysis-universe.schema.json",
        definition="ChainCachePreimage",
    )
    return structured_sha256("ebm-audit/chain-cache/4", preimage)


def _fixed_convergence_rule_digest() -> str:
    rule = asdict(CONVERGENCE_RULE)
    validate_instance(
        rule,
        "evaluator-receipts.schema.json",
        definition="ConvergenceRuleOwner",
    )
    return structured_sha256("ebm-audit/convergence-rule/1", rule)


def _cache_identity_for_attempts(
    *,
    universe_id: str,
    attempts: tuple[_ResolvedAttempt, ...],
) -> dict[str, Any]:
    if not attempts:
        raise TypeError("Cache identity requires at least one successful fit execution.")
    chain_keys = [_chain_cache_key(attempt) for attempt in attempts]
    chain_ids = [attempt.chain_execution_id for attempt in attempts]
    if len(chain_ids) != len(set(chain_ids)):
        raise TypeError("Cache identity repeats a chain execution owner.")
    preimage = {
        "cache_schema_version": "ebm-audit-universe-cache-preimage/3.0",
        "universe_id": universe_id,
        "ordered_chain_cache_keys": chain_keys,
        "convergence_rule_digest": _fixed_convergence_rule_digest(),
        "reference_chain_rule_id": "lowest-chain-plan-position/1",
        "result_schema_version": _RESULT_SCHEMA_VERSION,
    }
    validate_instance(
        preimage,
        "analysis-universe.schema.json",
        definition="UniverseCachePreimage",
    )
    return {
        "universe_cache_key": structured_sha256("ebm-audit/universe-cache/3", preimage),
        "chain_cache_keys": chain_keys,
    }


def _derive_cache_identity(
    *,
    universe_id: str,
    fit_execution_evidence: object,
) -> dict[str, Any]:
    if type(fit_execution_evidence) is not tuple or not fit_execution_evidence:
        raise TypeError("Cache identity requires one exact ordered fit-evidence tuple.")
    supplied = cast(tuple[object, ...], fit_execution_evidence)
    first = _resolve_attempt(
        supplied[0],
        expected_command="fit",
        chain_plan_position=0,
        expected_planning_summary_id=_INFER_PLANNING_SUMMARY_ID,
    )
    planning_summary_id = first.planning_summary_id
    resolved = [first]
    for position, capability in enumerate(supplied[1:], start=1):
        attempt = _resolve_attempt(
            capability,
            expected_command="fit",
            chain_plan_position=position,
            expected_planning_summary_id=planning_summary_id,
        )
        resolved.append(attempt)
    for attempt in resolved:
        _assert_fit_attempt_identity(attempt, universe_id=universe_id)
        if attempt.status != "SUCCESS":
            raise TypeError("Cache identity cannot admit unsuccessful fit evidence.")
    return _cache_identity_for_attempts(
        universe_id=universe_id,
        attempts=tuple(resolved),
    )


def _assert_scientific_owner_binding(
    state: _PreparedCandidateState,
    validation: _ResolvedAttempt,
    groups: tuple[tuple[_ResolvedAttempt, ...], ...],
) -> Mapping[str, Any]:
    owner = _execution_input(validation)
    if execution_input_projection_digest(owner) != state.execution_input_projection_digest:
        raise TypeError("Validation evidence is detached from its prepared execution owner.")
    for group in groups:
        for attempt in group:
            payload = cast(Mapping[str, Any], attempt.request["payload"])
            if (
                payload.get("universe_id") != state.universe_id
                or execution_input_projection_digest(_execution_input(attempt))
                != state.execution_input_projection_digest
                or _execution_input(attempt) != owner
            ):
                raise TypeError("Fit evidence is detached from its prepared scientific owner.")
    return owner


def _warnings(attempts: tuple[_ResolvedAttempt, ...]) -> list[Mapping[str, Any]]:
    warnings: list[Mapping[str, Any]] = []
    for attempt in attempts:
        if attempt.response_warnings_bytes is None:
            continue
        for line in attempt.response_warnings_bytes.splitlines():
            value = strict_json_loads(line)
            if not isinstance(value, Mapping):
                raise TypeError("Authenticated warning evidence failed finalization readback.")
            validate_instance(value, "canonical-records.schema.json", definition="WarningRecord")
            warnings.append(copy.deepcopy(dict(value)))
    return warnings


def _negative_error(attempt: _ResolvedAttempt) -> Mapping[str, Any]:
    if attempt.response is not None:
        error = attempt.response.get("error")
        if not isinstance(error, Mapping) or error.get("category") != attempt.status:
            raise TypeError("Authenticated negative response has no matching error owner.")
        return copy.deepcopy(dict(error))
    failure_code = cast(str, attempt.reference["core_failure_code"])
    return {
        "code": failure_code,
        "category": attempt.status,
        "safe_message": core_owned_negative_response_message(attempt.status),
        "phase": "worker-invocation",
        "retryable_identical_request": False,
        "issues": [],
        "details": {
            "counts": {},
            "internal_indexes": [],
            "approved_event_ids": [],
            "digests": {},
        },
    }


def _selected_negative(terminals: tuple[_ResolvedAttempt, ...]) -> _ResolvedAttempt:
    for status in _NEGATIVE_STATUS_PRECEDENCE:
        for terminal in terminals:
            if terminal.status == status:
                return terminal
    raise TypeError("Fit finalization has no negative terminal evidence.")


def _cache_lineage(value: object | None) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if type(value) is not VerifiedCacheLineage:
        raise TypeError("Cache lineage requires one exact core-verified owner.")
    state = value._state()
    parsed = strict_json_loads(state.canonical_bytes)
    if type(parsed) is not dict or canonical_json_bytes(parsed) != state.canonical_bytes:
        raise TypeError("Verified cache lineage storage is invalid.")
    lineage = cast(Mapping[str, Any], parsed)
    validate_instance(lineage, "canonical-records.schema.json", definition="CacheLineage")
    preimage = copy.deepcopy(dict(lineage))
    supplied = preimage.pop("cache_verification_digest")
    if supplied != structured_sha256("ebm-audit/cache-lineage-verification/1", preimage):
        raise TypeError("Verified cache lineage storage is invalid.")
    if lineage["cache_disposition"] == "HIT":
        source = _read_finalized_result(state.source_result)
        source_lineage_owner = source.cache_lineage
        if type(source_lineage_owner) is not VerifiedCacheLineage:
            raise TypeError("Verified cache hit source result is invalid.")
        source_bytes = _finalized_result_cache_admission_from_state(
            source,
            source_lineage_owner,
        )
        source_record = strict_json_loads(source_bytes)
        if type(source_record) is not dict:
            raise TypeError("Verified cache hit source result is invalid.")
        source_lineage = source_record["body"].get("cache_lineage")
        if (
            lineage["source_result_id"] != source.result_id
            or not isinstance(source_lineage, Mapping)
            or source_lineage.get("universe_cache_key") != lineage["universe_cache_key"]
            or source_lineage.get("chain_cache_keys") != lineage["chain_cache_keys"]
        ):
            raise TypeError("Verified cache hit has no cache-admissible source result.")
    elif state.source_result is not None:
        raise TypeError("Verified cache miss cannot retain a source result.")
    return lineage


def _candidate_core(
    state: _PreparedCandidateState,
    owner: Mapping[str, Any],
    *,
    kind: str,
    status: str,
    attempts: tuple[_ResolvedAttempt, ...],
) -> dict[str, Any]:
    dataset = cast(Mapping[str, Any], owner["dataset"])
    body: dict[str, Any] = {
        "record_kind": kind,
        "plan_schema_version": "ebm-audit-analysis-plan/3.0",
        "plan_digest": state.plan_digest,
        "candidate_ordinal": state.candidate_ordinal,
        "candidate_id": state.candidate_id,
        "analysis_spec_id": state.analysis_spec_id,
        "universe_id": state.universe_id,
        "status": status,
        "input_digest": dataset["scientific_data_digest"],
        "config_digest": owner["config_digest"],
        "core_code_digest": owner["core_code_digest"],
        "started_at_utc": state.started_at_utc,
        "ended_at_utc": state.ended_at_utc,
        "runtime_seconds": state.runtime_seconds,
        "warnings": _warnings(attempts),
        "output_hashes": {},
    }
    synthetic_provenance = dataset.get("synthetic_provenance")
    if synthetic_provenance is not None:
        body["synthetic_provenance"] = dict(cast(Mapping[str, Any], synthetic_provenance))
    return body


def _prepared_core(
    owner: Mapping[str, Any],
    validation: _ResolvedAttempt,
    groups: tuple[tuple[_ResolvedAttempt, ...], ...],
    *,
    cache_lineage: Mapping[str, Any] | None,
) -> dict[str, Any]:
    identity = copy.deepcopy(dict(cast(Mapping[str, Any], owner["selected_backend_identity"])))
    return {
        "preparation_state": "PREPARED",
        "protocol_version": "ebm-audit-worker/v2",
        "backend_identity": identity,
        "backend_identity_digest": backend_identity_digest(identity),
        "backend_acceptance": "NOT_EVALUATED",
        "capabilities_digest": owner["capabilities_digest"],
        "worker_executable_digest": identity["worker_executable_digest"],
        "worker_code_digest": identity["worker_code_digest"],
        "backend_source_digest": identity["backend_source_digest"],
        "environment_digest": identity["environment_digest"],
        "settings_digest": owner["settings_digest"],
        "validation_evidence": copy.deepcopy(dict(validation.reference)),
        "fit_attempt_evidence": [
            copy.deepcopy(dict(attempt.reference)) for group in groups for attempt in group
        ],
        "cache_lineage": (None if cache_lineage is None else copy.deepcopy(dict(cache_lineage))),
    }


def _chain_payload_from_result(
    result: Mapping[str, Any],
    *,
    chain_plan_position: int,
) -> dict[str, Any]:
    event_ids = list(cast(list[str], result["event_ids"]))
    permutation = list(cast(list[int], result["central_order_permutation"]))
    preimage = {
        "chain_payload_schema_version": _CHAIN_PAYLOAD_SCHEMA_VERSION,
        "chain_plan_position": chain_plan_position,
        "chain_execution_id": result["chain_execution_id"],
        "final_attempt_id": result["attempt_id"],
        "seed": result["seed"],
        "chain_id": result["chain_id"],
        "event_ids": event_ids,
        "central_order_event_ids": [event_ids[index] for index in permutation],
        "central_order_permutation": permutation,
        "central_order_method": copy.deepcopy(result["central_order_method"]),
        "raw_iteration_count": result["raw_iteration_count"],
        "burn_in_count": result["burn_in_count"],
        "thinning_interval": result["thinning_interval"],
        "postburn_unthinned_state_count": result["postburn_unthinned_state_count"],
        "retained_state_count": result["retained_state_count"],
        "likelihood_indexing": result["likelihood_indexing"],
        "actual_transition_count": result["actual_transition_count"],
        "actual_transition_fraction": result["actual_transition_fraction"],
        "arrays": copy.deepcopy(result["array_catalog"]),
        "field_origins": copy.deepcopy(result["field_origins"]),
        "participant_event_manifest": copy.deepcopy(result["participant_event_manifest"]),
        "preprocessing_manifest_digest": result["preprocessing_manifest_digest"],
        "stage_semantics_digest": result["stage_semantics_digest"],
        "stage_model_reference": copy.deepcopy(result["stage_model_reference"]),
        "component_applicability": copy.deepcopy(result["component_applicability"]),
        "resource_summary": copy.deepcopy(result["resource_summary"]),
        "backend_artifacts": copy.deepcopy(result["backend_artifacts"]),
    }
    payload = {
        **preimage,
        "chain_payload_digest": structured_sha256("ebm-audit/final-chain-payload/1", preimage),
    }
    validate_instance(
        payload,
        "canonical-records.schema.json",
        definition="FinalChainScientificPayload",
    )
    return payload


def _chain_payload(
    attempt: _ResolvedAttempt,
    *,
    chain_plan_position: int,
) -> dict[str, Any]:
    if (
        type(attempt.capability) is not AuthenticatedWorkerExecutionEvidence
        or attempt.response is None
        or attempt.status != "SUCCESS"
    ):
        raise TypeError("Scientific chain payload requires exact successful fit evidence.")
    result = cast(Mapping[str, Any], attempt.response["payload"]["result"])
    return _chain_payload_from_result(result, chain_plan_position=chain_plan_position)


def _convergence_order_state_snapshot(value: object) -> np.ndarray[Any, np.dtype[np.int64]]:
    """Copy authenticated Worker/2 int32 order states into the core int64 contract."""

    if type(value) is not np.ndarray or value.dtype != np.dtype(np.int32) or value.ndim != 2:
        raise TypeError("Authenticated worker order states cannot enter convergence.")
    snapshot = np.array(
        value,
        dtype=np.int64,
        order="C",
        copy=True,
    )
    snapshot.flags.writeable = False
    return snapshot


def _convergence(
    terminals: tuple[_ResolvedAttempt, ...],
    chain_payloads: tuple[Mapping[str, Any], ...],
) -> Mapping[str, Any]:
    inputs: list[ConvergenceChainInput] = []
    non_sampling_fit = True
    for attempt, payload in zip(terminals, chain_payloads, strict=True):
        if type(attempt.capability) is not AuthenticatedWorkerExecutionEvidence:
            raise TypeError("Convergence requires exact successful fit evidence.")
        arrays = attempt.response_arrays
        if arrays is None:
            raise TypeError("Convergence requires exact successful fit arrays.")
        execution_input = _execution_input(attempt)
        capabilities = execution_input.get("capabilities")
        requested_outputs = execution_input.get("requested_outputs")
        adapter_semantics = execution_input.get("adapter_semantics")
        if (
            not isinstance(capabilities, Mapping)
            or not isinstance(requested_outputs, list)
            or not isinstance(adapter_semantics, Mapping)
        ):
            raise TypeError("Convergence requires an exact adapter execution owner.")
        mcmc_projection = adapter_semantics.get("mcmc_projection")
        if not isinstance(mcmc_projection, Mapping) or mcmc_projection.get("availability") not in {
            "AVAILABLE",
            "UNAVAILABLE",
        }:
            raise TypeError("Convergence requires an exact MCMC semantic owner.")
        requested = frozenset(requested_outputs)
        output_arrays = {
            "order_samples": (
                "postburn_order_state_chain",
                "order_state_chain",
            ),
            "likelihood_trace": (
                "postburn_likelihood_trace",
                "likelihood_trace",
            ),
            "accepted_transition_diagnostics": ("postburn_state_change_mask",),
            "position_probabilities": ("position_probabilities",),
            "pairwise_precedence": ("pairwise_precedence",),
        }
        for output_id, member_names in output_arrays.items():
            capability = capabilities.get(output_id)
            if type(capability) is not bool:
                raise TypeError("Convergence requires exact independent capabilities.")
            output_requested = output_id in requested
            if output_requested and capability is not True:
                raise TypeError("A requested convergence output has no capability.")
            if any((name in arrays) is not output_requested for name in member_names):
                raise TypeError(
                    "Convergence artifacts do not match the authenticated output request."
                )
        sampling_schedule = (
            payload["raw_iteration_count"],
            payload["burn_in_count"],
            payload["thinning_interval"],
            payload["postburn_unthinned_state_count"],
            payload["retained_state_count"],
        )
        if "likelihood_trace" in requested:
            if payload["likelihood_indexing"] != "post-proposal-state/1":
                raise TypeError("Requested likelihood evidence has no exact indexing rule.")
        elif payload["likelihood_indexing"] is not None:
            raise TypeError("Unrequested likelihood indexing was returned.")
        transition_requested = "accepted_transition_diagnostics" in requested
        transition_scalars = (
            payload["actual_transition_count"],
            payload["actual_transition_fraction"],
        )
        if transition_requested:
            if payload["actual_transition_count"] is None:
                raise TypeError("Requested transition evidence has no exact count.")
        elif any(value is not None for value in transition_scalars):
            raise TypeError("Unrequested transition evidence was returned.")
        if all(value is None for value in sampling_schedule):
            if mcmc_projection["availability"] != "UNAVAILABLE":
                raise TypeError("An MCMC worker omitted its exact sampling accounting.")
            if capabilities.get("multiple_chains") is not False:
                raise TypeError(
                    "A multiple-chain algorithm cannot use strict non-sampling finalization."
                )
            if any(
                capabilities.get(output_id) is not False
                for output_id in (
                    "order_samples",
                    "likelihood_trace",
                    "accepted_transition_diagnostics",
                )
            ):
                raise TypeError("A non-chain worker advertised sampler-history capabilities.")
            continue
        non_sampling_fit = False
        if any(value is None for value in sampling_schedule):
            raise TypeError("A worker returned partial sampling accounting.")
        if mcmc_projection["availability"] != "AVAILABLE":
            raise TypeError("A non-chain worker returned MCMC sampling accounting.")
        order_states = arrays.get("postburn_order_state_chain")
        if order_states is not None:
            order_states = _convergence_order_state_snapshot(order_states)
        inputs.append(
            ConvergenceChainInput(
                chain_execution_id=cast(str, payload["chain_execution_id"]),
                event_ids=tuple(cast(list[str], payload["event_ids"])),
                thinning_interval=payload["thinning_interval"],
                postburn_unthinned_state_count=payload["postburn_unthinned_state_count"],
                retained_state_count=payload["retained_state_count"],
                postburn_order_state_chain=order_states,
                position_probabilities=arrays.get("position_probabilities"),
                pairwise_precedence=arrays.get("pairwise_precedence"),
                postburn_likelihood_trace=arrays.get("postburn_likelihood_trace"),
            )
        )
    value = derive_convergence_record(tuple(inputs))
    if non_sampling_fit:
        value["assessment"] = "NOT_APPLICABLE"
        value["reasons"] = ["CONVERGENCE.NOT_APPLICABLE_NON_SAMPLING"]
    validate_instance(value, "canonical-records.schema.json", definition="ConvergenceRecord")
    return value


def _convergence_error(status: str) -> Mapping[str, Any]:
    code = {
        "CONVERGENCE_FAILED": "CONVERGENCE.FAILED",
        "CONVERGENCE_NOT_ASSESSABLE": "CONVERGENCE.NOT_ASSESSABLE",
    }[status]
    return {
        "code": code,
        "category": status,
        "safe_message": core_owned_negative_response_message(status),
        "phase": "candidate-finalization",
        "retryable_identical_request": False,
        "issues": [],
        "details": {
            "counts": {},
            "internal_indexes": [],
            "approved_event_ids": [],
            "digests": {},
        },
    }


def _bound_prepared_call(
    owner: object,
    *,
    validation_evidence: object,
    fit_attempt_evidence: object,
) -> tuple[_PreparedFinalizationOwner, _PreparedCandidateState, tuple[object, ...]]:
    """Temporary seam replaced by preparation's unexported authorization projection."""

    if type(owner) is not _PreparedFinalizationOwner:
        raise TypeError("Finalization requires one exact prepared-candidate owner.")
    state = owner._state()
    if state.prepared_execution_authorization is not None:
        if state.prepared_candidate_execution_context is None:
            from ebm_audit.universe.preparation import (
                _resolve_prepared_execution_authorization,
            )

            prepared = _resolve_prepared_execution_authorization(
                state.prepared_execution_authorization
            )
        else:
            from ebm_audit.adapters.invocation import (
                _read_prepared_candidate_execution_context,
            )

            context_state = _read_prepared_candidate_execution_context(
                state.prepared_candidate_execution_context
            )
            invocation_context = context_state.invocation_context
            if (
                invocation_context.authorization is not state.prepared_execution_authorization
                or invocation_context.prepared_state is not state.prepared_execution_state
                or context_state
                is not state.prepared_candidate_execution_context_state
            ):
                raise TypeError("Prepared finalization is detached from its execution context.")
            prepared = cast(Any, invocation_context.prepared_state)
        record = strict_json_loads(prepared.record_bytes)
        universe = strict_json_loads(prepared.universe_bytes)
        if (
            type(record) is not dict
            or type(universe) is not dict
            or (
                record["candidate_ordinal"],
                record["candidate_id"],
                record["analysis_spec_id"],
                universe["universe_id"],
            )
            != (
                state.candidate_ordinal,
                state.candidate_id,
                state.analysis_spec_id,
                state.universe_id,
            )
        ):
            raise TypeError("Prepared finalization is detached from its exact authorization.")
    if validation_evidence is not state.validation_evidence:
        raise TypeError("Validation evidence is not the exact prepared execution owner.")
    if type(fit_attempt_evidence) is not tuple:
        raise TypeError("Fit evidence is not the exact prepared execution owner.")
    supplied_fit = cast(tuple[object, ...], fit_attempt_evidence)
    if len(supplied_fit) != len(state.fit_attempt_evidence) or any(
        supplied is not expected
        for supplied, expected in zip(
            supplied_fit,
            state.fit_attempt_evidence,
            strict=True,
        )
    ):
        raise TypeError("Fit evidence is not the exact prepared execution owner.")
    return owner, state, supplied_fit


def _finalize_unprepared_candidate_with_state(
    authorization: object,
    authorization_state: object,
) -> FinalizedResult:
    """Finalize from one retained unprepared state, rejecting live registry drift."""

    from ebm_audit.universe.preparation import (
        UnpreparedResultAuthorization,
        _resolve_unprepared_result_authorization,
        _UnpreparedResultAuthorizationState,
    )

    if (
        type(authorization) is not UnpreparedResultAuthorization
        or type(authorization_state) is not _UnpreparedResultAuthorizationState
    ):
        raise TypeError("A genuine unprepared result authorization is required.")
    state = authorization_state
    with _FINALIZATION_LOCK:
        if _resolve_unprepared_result_authorization(authorization) is not state:
            raise TypeError("Unprepared result authorization changed before finalization.")
        existing = _FINALIZED_BY_UNPREPARED_AUTHORIZATION.get(authorization)
        if existing is not None:
            _read_finalized_result(existing)
            return existing
        snapshot = _UNPREPARED_FINALIZATION_SNAPSHOTS.get(authorization)
        if snapshot is not None:
            snapshot = _validate_unprepared_finalization_snapshot(
                snapshot,
                authorization_state=state,
            )
            result = object.__new__(FinalizedResult)
            _FINALIZED_RESULT_STATE_ISSUER.bind_once(
                result,
                _FinalizedResultState(
                    canonical_bytes=snapshot.canonical_bytes,
                    result_id=snapshot.result_id,
                    record_kind="UNPREPARED",
                    status=snapshot.status,
                    candidate_result_authorization=authorization,
                    prepared_finalization_owner=None,
                    cache_lineage=None,
                    canonical_dataset=None,
                    scientific_owner_bytes=None,
                    reference_chain_execution=None,
                    descriptive_chain_executions=(),
                    unprepared_execution_state=state,
                ),
            )
            if _resolve_unprepared_result_authorization(authorization) is not state:
                raise TypeError("Unprepared result authorization changed before finalization.")
            _FINALIZED_BY_UNPREPARED_AUTHORIZATION.bind_once(
                authorization,
                result,
            )
            _read_finalized_result(result)
            return result
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        body = _unprepared_result_body(state, timestamp=timestamp)
        status = cast(str, body["status"])
        preimage = {"result_schema_version": _RESULT_SCHEMA_VERSION, "body": body}
        validate_instance(
            preimage,
            "canonical-records.schema.json",
            definition="ResultRecordDigestPreimage",
        )
        record_value = {
            **preimage,
            "result_id": structured_sha256("ebm-audit/result-record/2", preimage),
        }
        validated = validate_result_record_finalization(record_value)
        canonical = canonical_json_bytes(validated)
        readback = strict_json_loads(canonical)
        if type(readback) is not dict or validate_result_record_finalization(readback) != validated:
            raise TypeError("Unprepared result failed canonical semantic readback.")
        snapshot = _UnpreparedFinalizationSnapshot(
            authorization_state=state,
            canonical_bytes=canonical,
            result_id=cast(str, validated["result_id"]),
            status=status,
        )
        _validate_unprepared_finalization_snapshot(
            snapshot,
            authorization_state=state,
        )
        if _resolve_unprepared_result_authorization(authorization) is not state:
            raise TypeError("Unprepared result authorization changed before finalization.")
        _UNPREPARED_FINALIZATION_SNAPSHOT_ISSUER.bind_once(authorization, snapshot)
        result = object.__new__(FinalizedResult)
        _FINALIZED_RESULT_STATE_ISSUER.bind_once(
            result,
            _FinalizedResultState(
                canonical_bytes=snapshot.canonical_bytes,
                result_id=snapshot.result_id,
                record_kind="UNPREPARED",
                status=snapshot.status,
                candidate_result_authorization=authorization,
                prepared_finalization_owner=None,
                cache_lineage=None,
                canonical_dataset=None,
                scientific_owner_bytes=None,
                reference_chain_execution=None,
                descriptive_chain_executions=(),
                unprepared_execution_state=state,
            ),
        )
        _FINALIZED_BY_UNPREPARED_AUTHORIZATION.bind_once(
            authorization,
            result,
        )
        _read_finalized_result(result)
        return result


def finalize_unprepared_candidate(authorization: object) -> FinalizedResult:
    """Construct the sole result bound to one exact unprepared authorization."""

    from ebm_audit.universe.preparation import (
        _resolve_unprepared_result_authorization,
    )

    state = _resolve_unprepared_result_authorization(authorization)
    return _finalize_unprepared_candidate_with_state(authorization, state)


def _finalize_prepared_candidate_once(
    prepared_owner: _PreparedFinalizationOwner,
    state: _PreparedCandidateState,
    *,
    validation_evidence: object,
    supplied_fit: tuple[object, ...],
    cache_lineage: object | None,
) -> FinalizedResult:
    retained_canonical_dataset: CanonicalDataset | None = None
    retained_scientific_owner_bytes: bytes | None = None
    retained_reference_execution: AuthenticatedWorkerExecutionEvidence | None = None
    retained_descriptive_chain_executions: tuple[AuthenticatedWorkerExecutionEvidence, ...] = ()
    validation = _resolve_attempt(
        validation_evidence,
        expected_command="validate",
        chain_plan_position=None,
        expected_planning_summary_id=state.planning_summary_id,
    )
    groups = _resolve_fit_groups(supplied_fit, state=state)
    scientific_owner = _assert_scientific_owner_binding(state, validation, groups)
    flattened = (validation, *(attempt for group in groups for attempt in group))
    cache_value = _cache_lineage(cache_lineage)

    if validation.status != "SUCCESS":
        if groups or cache_value is not None:
            raise TypeError("Validate-terminal finalization cannot carry fit or cache evidence.")
        body = _candidate_core(
            state,
            scientific_owner,
            kind="EXECUTION_NON_SUCCESS",
            status=validation.status,
            attempts=flattened,
        )
        body.update(
            _prepared_core(
                scientific_owner,
                validation,
                groups,
                cache_lineage=None,
            )
        )
        body.update(
            {
                "failed_command": "validate",
                "error": _negative_error(validation),
                "diagnostic_references": [],
                "side_effects_reference": None,
            }
        )
    else:
        if (
            validation.response is None
            or validation.response["payload"].get("fit_permitted") is not True
        ):
            raise TypeError("Successful validation did not authorize fitting.")
        if len(groups) != len(state.ordered_chain_execution_ids):
            raise TypeError(
                "Prepared fit finalization requires terminal evidence for every planned chain."
            )
        terminals = tuple(group[-1] for group in groups)
        negative = tuple(attempt for attempt in terminals if attempt.status != "SUCCESS")
        if negative:
            if cache_value is not None:
                raise TypeError("Execution non-success cannot admit a cache lineage.")
            selected = _selected_negative(terminals)
            body = _candidate_core(
                state,
                scientific_owner,
                kind="EXECUTION_NON_SUCCESS",
                status=selected.status,
                attempts=flattened,
            )
            body.update(
                _prepared_core(
                    scientific_owner,
                    validation,
                    groups,
                    cache_lineage=None,
                )
            )
            body.update(
                {
                    "failed_command": "fit",
                    "error": _negative_error(selected),
                    "diagnostic_references": [],
                    "side_effects_reference": None,
                }
            )
        else:
            expected_cache_identity = _cache_identity_for_attempts(
                universe_id=state.universe_id,
                attempts=terminals,
            )
            if cache_value is not None and (
                cache_value["universe_cache_key"] != expected_cache_identity["universe_cache_key"]
                or cache_value["chain_cache_keys"] != expected_cache_identity["chain_cache_keys"]
            ):
                raise TypeError("Cache lineage is detached from the finalized universe owner.")
            chain_payloads = tuple(
                _chain_payload(terminal, chain_plan_position=position)
                for position, terminal in enumerate(terminals)
            )
            event_ids = chain_payloads[0]["event_ids"]
            if any(payload["event_ids"] != event_ids for payload in chain_payloads[1:]):
                raise TypeError("Scientific finalization has inconsistent event owners.")
            convergence = _convergence(terminals, chain_payloads)
            status = _CONVERGENCE_STATUS[cast(str, convergence["assessment"])]
            kind = (
                "COMPLETED"
                if status in {"SUCCESS", "CONVERGENCE_WARN"}
                else "CONVERGENCE_NON_SUCCESS"
            )
            body = _candidate_core(
                state,
                scientific_owner,
                kind=kind,
                status=status,
                attempts=flattened,
            )
            body.update(
                _prepared_core(
                    scientific_owner,
                    validation,
                    groups,
                    cache_lineage=cache_value,
                )
            )
            first = chain_payloads[0]
            if status in {"SUCCESS", "CONVERGENCE_WARN"}:
                reference_capability = terminals[0].capability
                if type(reference_capability) is not AuthenticatedWorkerExecutionEvidence or any(
                    type(terminal.capability) is not AuthenticatedWorkerExecutionEvidence
                    for terminal in terminals
                ):
                    raise TypeError(
                        "Scientific finalization lacks exact descriptive-chain execution owners."
                    )
                retained_descriptive_chain_executions = tuple(
                    cast(AuthenticatedWorkerExecutionEvidence, terminal.capability)
                    for terminal in terminals
                )
                if status == "SUCCESS":
                    retained_reference_execution = reference_capability
                    if state.canonical_dataset is not None and (
                        _prepared_result_can_own_canonical_baseline(
                            state.prepared_execution_state
                        )
                    ):
                        _assert_canonical_dataset_owner(
                            state.canonical_dataset,
                            scientific_owner,
                        )
                        retained_canonical_dataset = state.canonical_dataset
                        retained_scientific_owner_bytes = canonical_json_bytes(scientific_owner)
            body.update(
                {
                    "event_ids": copy.deepcopy(event_ids),
                    "chain_results": [copy.deepcopy(payload) for payload in chain_payloads],
                    "reference_chain": {
                        "rule_id": "lowest-chain-plan-position/1",
                        "chain_plan_position": 0,
                        "chain_execution_id": first["chain_execution_id"],
                        "final_attempt_id": first["final_attempt_id"],
                        "chain_payload_digest": first["chain_payload_digest"],
                    },
                    "convergence": copy.deepcopy(dict(convergence)),
                }
            )
            if kind == "CONVERGENCE_NON_SUCCESS":
                body.update(
                    {
                        "error": _convergence_error(status),
                        "diagnostic_references": [],
                    }
                )

    preimage = {"result_schema_version": _RESULT_SCHEMA_VERSION, "body": body}
    validate_instance(
        preimage,
        "canonical-records.schema.json",
        definition="ResultRecordDigestPreimage",
    )
    result_id = structured_sha256("ebm-audit/result-record/2", preimage)
    record = {**preimage, "result_id": result_id}
    validated = validate_result_record_finalization(record)
    canonical = canonical_json_bytes(validated)
    readback = strict_json_loads(canonical)
    if type(readback) is not dict or validate_result_record_finalization(readback) != validated:
        raise TypeError("Finalized result failed canonical semantic readback.")
    validated_body = cast(Mapping[str, Any], validated["body"])
    result = object.__new__(FinalizedResult)
    _FINALIZED_RESULT_STATE_ISSUER.bind_once(
        result,
        _FinalizedResultState(
            canonical_bytes=canonical,
            result_id=cast(str, validated["result_id"]),
            record_kind=cast(str, validated_body["record_kind"]),
            status=cast(str, validated_body["status"]),
            candidate_result_authorization=state.prepared_execution_authorization,
            prepared_finalization_owner=prepared_owner,
            cache_lineage=cast(VerifiedCacheLineage | None, cache_lineage),
            canonical_dataset=retained_canonical_dataset,
            scientific_owner_bytes=retained_scientific_owner_bytes,
            reference_chain_execution=retained_reference_execution,
            descriptive_chain_executions=retained_descriptive_chain_executions,
        ),
    )
    return result


def _issue_profile_finalized_result(
    issuer: object,
    *,
    body: Mapping[str, Any],
    candidate_result_authorization: object,
    profile_fit_session: object,
    profile_fit_slot_group: object,
    profile_candidate_ordinal: int,
    profile_validation_evidence: object,
    profile_fit_terminals: tuple[object, object, object],
    profile_storage_observations: tuple[object, object],
) -> FinalizedResult:
    """Issue one profile-only result without creating ordinary result authority."""

    if (
        issuer is not _PROFILE_FINALIZATION_ISSUER
        or candidate_result_authorization is None
        or profile_fit_session is None
        or profile_fit_slot_group is None
        or type(profile_candidate_ordinal) is not int
        or profile_candidate_ordinal not in {0, 1, 2}
        or type(profile_fit_terminals) is not tuple
        or len(profile_fit_terminals) != 3
        or type(profile_storage_observations) is not tuple
        or len(profile_storage_observations) != 2
        or body.get("execution_origin") != "PROFILE"
        or body.get("candidate_ordinal") != profile_candidate_ordinal
        or body.get("cache_lineage") is not None
    ):
        raise TypeError("Profile finalized-result issuance inputs are invalid.")
    preimage = {
        "result_schema_version": _RESULT_SCHEMA_VERSION,
        "body": copy.deepcopy(dict(body)),
    }
    validate_instance(
        preimage,
        "canonical-records.schema.json",
        definition="ResultRecordDigestPreimage",
    )
    record = {
        **preimage,
        "result_id": structured_sha256("ebm-audit/result-record/2", preimage),
    }
    validated = validate_result_record_finalization(record)
    canonical = canonical_json_bytes(validated)
    readback = strict_json_loads(canonical)
    if type(readback) is not dict or validate_result_record_finalization(readback) != validated:
        raise TypeError("Profile finalized result failed canonical semantic readback.")
    validated_body = cast(Mapping[str, Any], validated["body"])
    result = object.__new__(FinalizedResult)
    state = _FinalizedResultState(
        canonical_bytes=canonical,
        result_id=cast(str, validated["result_id"]),
        record_kind=cast(str, validated_body["record_kind"]),
        status=cast(str, validated_body["status"]),
        candidate_result_authorization=candidate_result_authorization,
        prepared_finalization_owner=None,
        cache_lineage=None,
        canonical_dataset=None,
        scientific_owner_bytes=None,
        reference_chain_execution=None,
        descriptive_chain_executions=(),
        execution_origin="PROFILE",
        profile_fit_session=profile_fit_session,
        profile_fit_slot_group=profile_fit_slot_group,
        profile_candidate_ordinal=profile_candidate_ordinal,
        profile_validation_evidence=profile_validation_evidence,
        profile_fit_terminals=profile_fit_terminals,
        profile_storage_observations=profile_storage_observations,
    )
    _FINALIZED_RESULT_STATE_ISSUER.bind_once(
        result,
        state,
    )
    if _read_finalized_result(result) is not state:
        raise TypeError("Profile finalized-result seal issuance failed.")
    return result


def finalize_prepared_candidate(
    owner: object,
    *,
    validation_evidence: object,
    fit_attempt_evidence: object,
    cache_lineage: object | None = None,
) -> FinalizedResult:
    """Atomically finalize one prepared candidate from exact sealed owners."""

    prepared_owner, state, supplied_fit = _bound_prepared_call(
        owner,
        validation_evidence=validation_evidence,
        fit_attempt_evidence=fit_attempt_evidence,
    )
    if cache_lineage is not state.cache_lineage:
        raise TypeError("Cache lineage is not the exact prepared cache owner.")
    with _FINALIZATION_LOCK:
        existing = _FINALIZED_BY_PREPARED_OWNER.get(prepared_owner)
        if existing is not None:
            _read_finalized_result(existing)
            return existing
        result = _finalize_prepared_candidate_once(
            prepared_owner,
            state,
            validation_evidence=validation_evidence,
            supplied_fit=supplied_fit,
            cache_lineage=cache_lineage,
        )
        _FINALIZED_BY_PREPARED_OWNER.bind_once(prepared_owner, result)
        _read_finalized_result(result)
        return result


def finalized_result_persistence_bytes(value: object) -> bytes:
    """Return exact bytes only after the opaque finalized-result gate."""

    state = _read_finalized_result(value)
    return _finalized_result_persistence_bytes_from_state(value, state)


def _finalized_result_persistence_bytes_from_state(
    value: object,
    state: _FinalizedResultState,
) -> bytes:
    """Project bytes from a state validated in this exact call boundary."""

    _require_finalized_result_state_identity(value, state)
    _require_ordinary_finalized_result(state)
    return bytes(state.canonical_bytes)


def finalized_result_cache_admission_bytes(value: object) -> bytes:
    """Return cache-admissible bytes only for a completed finalized result."""

    state = _read_finalized_result(value)
    _require_ordinary_finalized_result(state)
    if state.record_kind != "COMPLETED":
        raise TypeError("Only a cache-admissible completed result may enter the result cache.")
    lineage = state.cache_lineage
    if type(lineage) is not VerifiedCacheLineage:
        raise TypeError("A cache-admissible result requires exact verified cache lineage.")
    return _finalized_result_cache_admission_from_state(state, lineage)


def _finalized_result_cache_admission_bytes(
    value: object,
    cache_lineage: object,
) -> bytes:
    """Bind cache bytes to the exact lineage capability retained at finalization."""

    state = _read_finalized_result(value)
    return _finalized_result_cache_admission_bytes_from_state(
        value,
        state,
        cache_lineage,
    )


def _finalized_result_cache_admission_bytes_from_state(
    value: object,
    state: _FinalizedResultState,
    cache_lineage: object,
) -> bytes:
    """Project cache bytes from a state validated in this exact call boundary."""

    _require_finalized_result_state_identity(value, state)
    return _finalized_result_cache_admission_from_state(
        state,
        cache_lineage,
    )


def _finalized_result_cache_admission_from_state(
    state: _FinalizedResultState,
    cache_lineage: object,
) -> bytes:
    """Use one already-proved finalized-result snapshot for cache admission."""

    _require_ordinary_finalized_result(state)
    if type(cache_lineage) is not VerifiedCacheLineage or state.cache_lineage is not cache_lineage:
        raise TypeError("A cache-admissible result requires its exact verified cache lineage.")
    if state.record_kind != "COMPLETED":
        raise TypeError("Only a cache-admissible completed result may enter the result cache.")
    record = strict_json_loads(state.canonical_bytes)
    lineage = _cache_lineage(cache_lineage)
    if type(record) is not dict or record["body"].get("cache_lineage") != lineage:
        raise TypeError("A cache-admissible result requires exact verified cache lineage.")
    return bytes(state.canonical_bytes)


def candidate_terminal_from_finalized_result(value: object) -> dict[str, Any]:
    """Derive CandidateTerminal only from an exact finalized-result capability."""

    state = _read_finalized_result(value)
    return _candidate_terminal_from_finalized_result_state(value, state)


def _candidate_terminal_from_finalized_result_state(
    value: object,
    state: _FinalizedResultState,
) -> dict[str, Any]:
    """Derive a terminal from a state validated in this exact call boundary."""

    _require_finalized_result_state_identity(value, state)
    _require_ordinary_finalized_result(state)
    record = strict_json_loads(state.canonical_bytes)
    if type(record) is not dict:
        raise TypeError("Finalized-result storage is invalid.")
    body = cast(Mapping[str, Any], record["body"])
    error = body.get("error")
    terminal = {
        "terminal_schema_version": "ebm-audit-candidate-terminal/1.0",
        "candidate_ordinal": body["candidate_ordinal"],
        "candidate_id": body["candidate_id"],
        "analysis_spec_id": body["analysis_spec_id"],
        "universe_id": body["universe_id"],
        "final_status": body["status"],
        "result_id": state.result_id,
        "result_digest": exact_file_sha256(state.canonical_bytes),
        "error_evidence_digest": (
            None if error is None else structured_sha256("ebm-audit/result-error-evidence/1", error)
        ),
    }
    validate_instance(terminal, "run-artifacts.schema.json", definition="CandidateTerminal")
    return terminal
