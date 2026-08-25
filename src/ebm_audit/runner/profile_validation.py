"""Atomic validation-only execution for one exact profile candidate group."""

from __future__ import annotations

import math
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock, RLock
from types import MappingProxyType
from typing import Any, NamedTuple, SupportsIndex, cast, final
from weakref import ReferenceType, ref

import numpy as np

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.adapters import (
    AuthenticatedWorkerDescription,
    AuthenticatedWorkerExecutionEvidence,
    WorkerConfig,
    WorkerInvocationObservation,
    WorkerInvoker,
)
from ebm_audit.adapters.invocation import (
    _AuthenticatedDescriptionReadback,
    _AuthenticatedExecutionReadback,
    _issue_profile_validation_invocation_authorizations,
    _PreparedCandidateExecutionContext,
    _PreparedCandidateExecutionContextState,
    _PreparedInvocationContext,
    _profile_fit_array_catalog,
    _ProfileValidationInvocationAuthorization,
    _read_prepared_candidate_execution_context,
    _read_profile_validation_invocation_authorization,
    _readback_authenticated_execution,
    _readback_worker_invocation_observation,
    _require_prepared_candidate_execution_context_state_identity,
)
from ebm_audit.errors import AuditError
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    execution_input_projection_digest,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.results.finalization import _resolve_attempt, _ResolvedAttempt
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.universe.identities import attempt_id
from ebm_audit.universe.preparation import (
    ProfilePreparedCandidateGroup,
    _PreparedExecutionAuthorizationState,
    _ProfilePreparedCandidateGroupState,
    _read_profile_prepared_candidate_group,
    _read_profile_prepared_candidate_group_boundary,
)

_CANONICAL_PROFILE_IDS = (
    "characterization_2000",
    "characterization_5000",
    "characterization_10000",
)
_PROFILE_CHAIN_COUNT = 3
_PROFILE_FIT_ATTEMPT_ORDINAL = 0


class _ProfileValidationPublication:
    """Callback-free publication cell for one exact prepared group."""

    __slots__ = ("lock", "session_ref", "status", "token")

    lock: RLock
    session_ref: ReferenceType[ProfileValidationSession] | None
    status: str
    token: object

    def __init__(self) -> None:
        self.lock = RLock()
        self.session_ref = None
        self.status = "FRESH"
        self.token = object()


@dataclass(frozen=True, repr=False)
class _ProfileValidationCoreFailure:
    """A fixed safe terminal when no worker observation could be issued."""

    failure_code: str = "PROFILE_VALIDATION.UNOBSERVED_CORE_FAILURE"


class _ProfileValidationTerminal(NamedTuple):
    ordinal: int
    candidate_authorization: object
    candidate_state: _PreparedExecutionAuthorizationState
    started_at_utc: str
    started_monotonic: float
    evidence: (
        AuthenticatedWorkerExecutionEvidence
        | WorkerInvocationObservation
        | _ProfileValidationCoreFailure
    )


class _ProfileValidationCandidateBasis(NamedTuple):
    ordinal: int
    candidate_authorization: object
    candidate_state: _PreparedExecutionAuthorizationState
    invocation_context: _PreparedInvocationContext
    validation_payload_bytes: bytes
    array_catalog_bytes: bytes
    arrays: Mapping[str, np.ndarray[Any, Any]]
    plan_bytes: bytes
    planning_summary_binding_bytes: bytes
    record_bytes: bytes
    universe_bytes: bytes
    array_identity_seal: tuple[
        tuple[
            str,
            np.ndarray[Any, Any],
            bytes,
            tuple[int, ...],
            tuple[int, ...],
            str,
        ],
        ...,
    ]


class _ProfileValidationScheduleBasisState(NamedTuple):
    group: ProfilePreparedCandidateGroup
    group_state: _ProfilePreparedCandidateGroupState
    invoker: WorkerInvoker
    token: object
    candidates: tuple[
        _ProfileValidationCandidateBasis,
        _ProfileValidationCandidateBasis,
        _ProfileValidationCandidateBasis,
    ]
    fit_payload_bytes: tuple[bytes, ...]
    execution_policy_bytes: bytes
    canonical_bytes: bytes
    digest: str


class _ProfileValidationResolvedSnapshot(NamedTuple):
    capability: AuthenticatedWorkerExecutionEvidence
    request_bytes: bytes
    response_bytes: bytes
    response_warnings_bytes: bytes
    reference_bytes: bytes
    planning_summary_id: str


class _ProfileFitDispatchContextSeal(NamedTuple):
    candidate_execution_context: _PreparedCandidateExecutionContext
    candidate_execution_context_state: _PreparedCandidateExecutionContextState
    invoker: WorkerInvoker
    candidate_authorization: object
    candidate_state: _PreparedExecutionAuthorizationState
    authenticated_description: AuthenticatedWorkerDescription
    authenticated_description_state: object
    selected_algorithm_binding_bytes: bytes
    planning_summary_id: str
    schedule_basis: _ProfileValidationScheduleBasis
    schedule_basis_token: object
    execution_origin_bytes: bytes
    description_projection_bytes: bytes


class _ProfileFitRequestOwner(NamedTuple):
    row: _ProfileFitScheduleReceiptRow
    candidate_execution_context: _PreparedCandidateExecutionContext
    candidate_execution_context_state: _PreparedCandidateExecutionContextState
    invocation_context: _PreparedInvocationContext


def _profile_array_immutable_bytes(
    array: np.ndarray[Any, Any],
) -> bytes | None:
    """Return the exact immutable buffer owner without reading array values."""

    owner: object = array
    while type(owner) is np.ndarray:
        owner = owner.base
    return owner if type(owner) is bytes else None


def _immutable_profile_array_snapshot(
    value: np.ndarray[Any, Any],
) -> tuple[np.ndarray[Any, Any], bytes]:
    """Detach one C-order view whose storage can never become writable."""

    if type(value) is not np.ndarray:
        raise TypeError("Profile validation candidate arrays are invalid.")
    immutable_bytes = value.tobytes(order="C")
    detached = np.frombuffer(
        immutable_bytes,
        dtype=value.dtype,
    ).reshape(value.shape)
    if (
        detached.flags.writeable
        or not detached.flags.c_contiguous
        or detached.flags.owndata
        or _profile_array_immutable_bytes(detached) is not immutable_bytes
    ):
        raise TypeError("Profile validation candidate arrays are not immutable.")
    try:
        detached.flags.writeable = True
    except ValueError:
        pass
    else:
        raise TypeError("Profile validation candidate arrays are not immutable.")
    return detached, immutable_bytes


@final
class _ProfileValidationScheduleBasis:
    """Opaque pre-validation owner of one detached profile schedule."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> _ProfileValidationScheduleBasis:
        raise TypeError("Profile validation schedule bases are privately issued.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile validation schedule bases are immutable.")

    @property
    def token(self) -> object:
        return _bound_profile_validation_schedule_basis(self).token

    @property
    def candidates(
        self,
    ) -> tuple[
        _ProfileValidationCandidateBasis,
        _ProfileValidationCandidateBasis,
        _ProfileValidationCandidateBasis,
    ]:
        return _bound_profile_validation_schedule_basis(self).candidates

    @property
    def fit_payload_bytes(self) -> tuple[bytes, ...]:
        return _bound_profile_validation_schedule_basis(self).fit_payload_bytes

    @property
    def execution_policy_bytes(self) -> bytes:
        return _bound_profile_validation_schedule_basis(self).execution_policy_bytes

    @property
    def canonical_bytes(self) -> bytes:
        return _bound_profile_validation_schedule_basis(self).canonical_bytes

    @property
    def digest(self) -> str:
        return _bound_profile_validation_schedule_basis(self).digest


class _ProfileFitScheduleReceiptRow(NamedTuple):
    runtime_position: int
    runtime_profile_position: int
    profile_id: str
    candidate_ordinal: int
    candidate_authorization: object
    candidate_state: _PreparedExecutionAuthorizationState
    validation_evidence: AuthenticatedWorkerExecutionEvidence
    validation_snapshot: _ProfileValidationResolvedSnapshot
    dispatch_context_seal: _ProfileFitDispatchContextSeal
    candidate_execution_context: _PreparedCandidateExecutionContext
    candidate_execution_context_state: _PreparedCandidateExecutionContextState
    execution_input_projection_digest: str
    chain_plan_position: int
    universe_id: str
    chain_id: str
    chain_execution_id: str
    attempt_id: str
    seed: str
    attempt_ordinal: int


class _ProfileFitScheduleReceiptState(NamedTuple):
    token: object
    basis: _ProfileValidationScheduleBasis
    invoker: WorkerInvoker
    rows: tuple[_ProfileFitScheduleReceiptRow, ...]
    canonical_bytes: bytes
    digest: str


def _profile_utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _valid_profile_utc_timestamp(value: object) -> bool:
    if type(value) is not str or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return (
        parsed.tzinfo is UTC
        and parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") == value
    )


class _ProfileValidationBarrierState(NamedTuple):
    group: ProfilePreparedCandidateGroup
    group_state: _ProfilePreparedCandidateGroupState
    invoker: WorkerInvoker
    terminals: tuple[
        _ProfileValidationTerminal,
        _ProfileValidationTerminal,
        _ProfileValidationTerminal,
    ]
    fit_receipt: _ProfileFitScheduleReceipt


class _ProfileValidationSessionState(NamedTuple):
    publication: _ProfileValidationPublication
    publication_token: object
    group: ProfilePreparedCandidateGroup
    group_state: _ProfilePreparedCandidateGroupState
    invoker: WorkerInvoker
    schedule_basis: _ProfileValidationScheduleBasis
    authorizations: tuple[
        _ProfileValidationInvocationAuthorization,
        _ProfileValidationInvocationAuthorization,
        _ProfileValidationInvocationAuthorization,
    ]
    terminals: tuple[
        _ProfileValidationTerminal,
        _ProfileValidationTerminal,
        _ProfileValidationTerminal,
    ]
    barrier: ProfileValidationBarrier | None


_PROFILE_VALIDATION_PUBLICATIONS: OneShotWeakRegistry[object, _ProfileValidationPublication]
_PROFILE_VALIDATION_PUBLICATION_ISSUER: OneShotRegistryIssuer[object, _ProfileValidationPublication]
(
    _PROFILE_VALIDATION_PUBLICATIONS,
    _PROFILE_VALIDATION_PUBLICATION_ISSUER,
) = create_one_shot_registry()
_PROFILE_VALIDATION_PUBLICATIONS_LOCK = Lock()

_PROFILE_VALIDATION_SCHEDULE_BASIS_STATES: OneShotWeakRegistry[
    object, _ProfileValidationScheduleBasisState
]
_PROFILE_VALIDATION_SCHEDULE_BASIS_STATE_ISSUER: OneShotRegistryIssuer[
    object, _ProfileValidationScheduleBasisState
]
(
    _PROFILE_VALIDATION_SCHEDULE_BASIS_STATES,
    _PROFILE_VALIDATION_SCHEDULE_BASIS_STATE_ISSUER,
) = create_one_shot_registry()

_PROFILE_FIT_SCHEDULE_RECEIPT_STATES: OneShotWeakRegistry[
    object, _ProfileFitScheduleReceiptState
]
_PROFILE_FIT_SCHEDULE_RECEIPT_STATE_ISSUER: OneShotRegistryIssuer[
    object, _ProfileFitScheduleReceiptState
]
(
    _PROFILE_FIT_SCHEDULE_RECEIPT_STATES,
    _PROFILE_FIT_SCHEDULE_RECEIPT_STATE_ISSUER,
) = create_one_shot_registry()

_PROFILE_VALIDATION_BARRIER_STATES: OneShotWeakRegistry[object, _ProfileValidationBarrierState]
_PROFILE_VALIDATION_BARRIER_STATE_ISSUER: OneShotRegistryIssuer[
    object, _ProfileValidationBarrierState
]
(
    _PROFILE_VALIDATION_BARRIER_STATES,
    _PROFILE_VALIDATION_BARRIER_STATE_ISSUER,
) = create_one_shot_registry()

_PROFILE_VALIDATION_SESSION_STATES: OneShotWeakRegistry[object, _ProfileValidationSessionState]
_PROFILE_VALIDATION_SESSION_STATE_ISSUER: OneShotRegistryIssuer[
    object, _ProfileValidationSessionState
]
(
    _PROFILE_VALIDATION_SESSION_STATES,
    _PROFILE_VALIDATION_SESSION_STATE_ISSUER,
) = create_one_shot_registry()


@final
class ProfileValidationBarrier:
    """Opaque proof that all three exact profile validations permitted fitting."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ProfileValidationBarrier:
        raise TypeError("Profile validation barriers are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile validation barriers cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile validation barriers are immutable.")

    def __copy__(self) -> ProfileValidationBarrier:
        raise TypeError("Profile validation barriers cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> ProfileValidationBarrier:
        raise TypeError("Profile validation barriers cannot be copied or serialized.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Profile validation barriers cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Profile validation barriers cannot be copied or serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Profile validation barriers cannot be copied or serialized.")

    def __repr__(self) -> str:
        _read_profile_validation_barrier(self)
        return "ProfileValidationBarrier(<sealed-three-validation-gate>)"


@final
class _ProfileFitScheduleReceipt:
    """Opaque owner of one canonical nine-fit schedule receipt."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _ProfileFitScheduleReceipt:
        raise TypeError("Profile fit schedule receipts are privately issued.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile fit schedule receipts are immutable.")


@final
class ProfileValidationSession:
    """Opaque terminal owner for exactly three ordered profile validations."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ProfileValidationSession:
        raise TypeError("Profile validation sessions are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile validation sessions cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile validation sessions are immutable.")

    @property
    def terminal_count(self) -> int:
        return len(_read_profile_validation_session(self).terminals)

    @property
    def barrier(self) -> ProfileValidationBarrier | None:
        return _read_profile_validation_session(self).barrier

    def __copy__(self) -> ProfileValidationSession:
        raise TypeError("Profile validation sessions cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> ProfileValidationSession:
        raise TypeError("Profile validation sessions cannot be copied or serialized.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Profile validation sessions cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Profile validation sessions cannot be copied or serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Profile validation sessions cannot be copied or serialized.")

    def __repr__(self) -> str:
        _read_profile_validation_session(self)
        return "ProfileValidationSession(<sealed-three-validation-terminals>)"


def _profile_validation_publication(
    group: object,
) -> _ProfileValidationPublication:
    if type(group) is not ProfilePreparedCandidateGroup:
        raise TypeError("A genuine profile prepared-candidate group is required.")
    with _PROFILE_VALIDATION_PUBLICATIONS_LOCK:
        publication = _PROFILE_VALIDATION_PUBLICATIONS.get(group)
        if publication is None:
            publication = _ProfileValidationPublication()
            _PROFILE_VALIDATION_PUBLICATION_ISSUER.bind_once(group, publication)
    if type(publication) is not _ProfileValidationPublication:
        raise TypeError("Profile validation publication state is invalid.")
    return publication


def _profile_validation_invoker(
    group_state: _ProfilePreparedCandidateGroupState,
    plan_projection: Mapping[str, Any],
) -> WorkerInvoker:
    execution_contract = plan_projection.get("execution_contract")
    if type(execution_contract) is not dict:
        raise TypeError("The profile validation group has no sealed execution contract.")
    timeout_seconds = execution_contract.get("timeout_seconds")
    if type(timeout_seconds) not in {int, float}:
        raise TypeError("The profile validation timeout is invalid.")
    worker_config = group_state.input_binding_state.run_config.consume_worker_config(
        lambda handle: WorkerConfig.from_yaml_bytes(handle.read())
    )
    if type(worker_config) is not WorkerConfig or worker_config.expected_identity is None:
        raise TypeError("The profile validation worker identity is invalid.")
    return WorkerInvoker(
        worker_config.worker,
        timeout_seconds=cast(float, timeout_seconds),
        expected_identity=worker_config.expected_identity,
    )


def _request_context_matches_candidate(
    *,
    request_readback: Any,
    invoker: WorkerInvoker,
    candidate_authorization: object,
    candidate_state: _PreparedExecutionAuthorizationState,
) -> bool:
    context = request_readback.prepared_candidate_execution_context
    retained_context_state = request_readback.prepared_candidate_execution_context_state
    try:
        context_state = _read_prepared_candidate_execution_context(context)
    except TypeError:
        return False
    return (
        context_state is retained_context_state
        and context_state.invoker is invoker
        and context_state.invocation_context.authorization is candidate_authorization
        and context_state.invocation_context.prepared_state is candidate_state
        and candidate_state.execution_origin.route == "PROFILE"
    )


def _validate_profile_terminal(
    terminal: _ProfileValidationTerminal,
    *,
    basis: _ProfileValidationScheduleBasis,
    invoker: WorkerInvoker,
) -> tuple[bool, _AuthenticatedExecutionReadback | None]:
    if (
        type(terminal) is not _ProfileValidationTerminal
        or type(terminal.ordinal) is not int
        or terminal.ordinal not in {0, 1, 2}
        or type(terminal.candidate_state) is not _PreparedExecutionAuthorizationState
        or not _valid_profile_utc_timestamp(terminal.started_at_utc)
        or type(terminal.started_monotonic) is not float
        or not math.isfinite(terminal.started_monotonic)
        or terminal.started_monotonic < 0.0
    ):
        raise TypeError("Profile validation terminal storage is invalid.")
    candidate_basis = basis.candidates[terminal.ordinal]
    candidate = candidate_basis.candidate_authorization
    candidate_state = candidate_basis.candidate_state
    if (
        terminal.candidate_authorization is not candidate
        or terminal.candidate_state is not candidate_state
    ):
        raise TypeError("A profile validation terminal changed candidate ownership.")

    evidence = terminal.evidence
    if type(evidence) is AuthenticatedWorkerExecutionEvidence:
        readback = _readback_authenticated_execution(evidence)
        if not _request_context_matches_candidate(
            request_readback=readback.request_readback,
            invoker=invoker,
            candidate_authorization=candidate,
            candidate_state=candidate_state,
        ):
            raise TypeError("Profile validation evidence belongs to another candidate.")
        response = readback.response
        if readback.request.get("command") != "validate" or response.get("command") != "validate":
            raise TypeError("Profile validation evidence is not a validate terminal.")
        success = (
            response.get("status") == "SUCCESS"
            and type(response.get("payload")) is dict
            and response["payload"].get("fit_permitted") is True
        )
        return success, readback if success else None
    if type(evidence) is WorkerInvocationObservation:
        observation_readback = _readback_worker_invocation_observation(evidence)
        if not _request_context_matches_candidate(
            request_readback=observation_readback.request_readback,
            invoker=invoker,
            candidate_authorization=candidate,
            candidate_state=candidate_state,
        ):
            raise TypeError("Profile validation failure belongs to another candidate.")
        if observation_readback.request.get("command") != "validate":
            raise TypeError("Profile validation failure is not a validate terminal.")
        return False, None
    if type(evidence) is _ProfileValidationCoreFailure:
        if evidence.failure_code != "PROFILE_VALIDATION.UNOBSERVED_CORE_FAILURE":
            raise TypeError("Profile validation core-failure storage is invalid.")
        return False, None
    raise TypeError("Profile validation terminal evidence is invalid.")


def _validate_terminal_tuple(
    terminals: object,
    *,
    basis: _ProfileValidationScheduleBasis,
    invoker: WorkerInvoker,
) -> tuple[
    tuple[
        _ProfileValidationTerminal,
        _ProfileValidationTerminal,
        _ProfileValidationTerminal,
    ],
    tuple[bool, bool, bool],
    tuple[
        _AuthenticatedExecutionReadback | None,
        _AuthenticatedExecutionReadback | None,
        _AuthenticatedExecutionReadback | None,
    ],
]:
    if type(terminals) is not tuple or len(terminals) != 3:
        raise TypeError("Profile validation requires exactly three terminal observations.")
    typed = cast(
        tuple[
            _ProfileValidationTerminal,
            _ProfileValidationTerminal,
            _ProfileValidationTerminal,
        ],
        terminals,
    )
    if (
        tuple(item.ordinal for item in typed) != (0, 1, 2)
        or len({id(item.evidence) for item in typed}) != 3
    ):
        raise TypeError("Profile validation terminal order or identity changed.")
    validated = tuple(
        _validate_profile_terminal(item, basis=basis, invoker=invoker)
        for item in typed
    )
    successes = cast(tuple[bool, bool, bool], tuple(row[0] for row in validated))
    readbacks = cast(
        tuple[
            _AuthenticatedExecutionReadback | None,
            _AuthenticatedExecutionReadback | None,
            _AuthenticatedExecutionReadback | None,
        ],
        tuple(row[1] for row in validated),
    )
    return typed, successes, readbacks


def _require_sealed_profile_terminal_tuple(
    terminals: object,
    *,
    basis: _ProfileValidationScheduleBasis,
) -> tuple[
    _ProfileValidationTerminal,
    _ProfileValidationTerminal,
    _ProfileValidationTerminal,
]:
    if type(terminals) is not tuple or len(terminals) != 3:
        raise TypeError("Profile validation requires exactly three terminal observations.")
    typed = cast(
        tuple[
            _ProfileValidationTerminal,
            _ProfileValidationTerminal,
            _ProfileValidationTerminal,
        ],
        terminals,
    )
    if (
        tuple(item.ordinal for item in typed) != (0, 1, 2)
        or len({id(item.evidence) for item in typed}) != 3
        or any(
            type(item) is not _ProfileValidationTerminal
            or item.candidate_authorization
            is not basis.candidates[item.ordinal].candidate_authorization
            or item.candidate_state is not basis.candidates[item.ordinal].candidate_state
            or not _valid_profile_utc_timestamp(item.started_at_utc)
            or type(item.started_monotonic) is not float
            or not math.isfinite(item.started_monotonic)
            or item.started_monotonic < 0.0
            for item in typed
        )
    ):
        raise TypeError("Profile validation sealed terminal ownership changed.")
    return typed


def _profile_fit_receipt_mapping(raw: bytes, *, label: str) -> dict[str, Any]:
    value = strict_json_loads(raw)
    if type(value) is not dict:
        raise TypeError(f"{label} is invalid.")
    return cast(dict[str, Any], value)


def _capture_profile_validation_schedule_basis(
    *,
    group: ProfilePreparedCandidateGroup,
    group_state: _ProfilePreparedCandidateGroupState,
    invoker: WorkerInvoker,
    plan_projection: Mapping[str, Any],
    candidate_pairs: tuple[tuple[object, _PreparedExecutionAuthorizationState], ...],
) -> _ProfileValidationScheduleBasis:
    """Detach every fit/finalization input before validation execution starts."""

    plan_receipt = plan_projection.get("plan_receipt")
    if type(plan_receipt) is not dict:
        raise TypeError("The profile fit plan has no exact receipt.")
    budgets = plan_receipt.get("ordered_budgets")
    execution_policy = plan_receipt.get("execution_policy")
    if (
        type(budgets) is not list
        or len(budgets) != 3
        or type(execution_policy) is not dict
        or set(execution_policy)
        != {
            "policy_schema_version",
            "fit_execution_mode",
            "cache_policy",
            "checkpoint_policy",
            "retry_policy",
            "caller_supplied_seeds_allowed",
            "ordered_budget_rotations",
        }
        or execution_policy.get("policy_schema_version")
        != "ebm-audit-profile-execution-policy/1.0"
        or execution_policy.get("fit_execution_mode")
        != "FRESH_INDEPENDENT_SERIAL_PROCESSES"
        or execution_policy.get("cache_policy") != "NO_READ_NO_WRITE"
        or execution_policy.get("checkpoint_policy") != "NO_READ_NO_WRITE"
        or execution_policy.get("retry_policy") != "DISALLOWED"
        or execution_policy.get("caller_supplied_seeds_allowed") is not False
    ):
        raise TypeError("The profile fit execution policy changed.")
    if any(type(row) is not dict for row in budgets):
        raise TypeError("The profile fit budget vector is invalid.")
    typed_budgets = cast(list[dict[str, Any]], budgets)
    if (
        tuple(row.get("profile_id") for row in typed_budgets)
        != _CANONICAL_PROFILE_IDS
        or tuple(row.get("analysis_spec_id") for row in typed_budgets)
        != group_state.ordered_analysis_spec_ids
        or len(set(group_state.ordered_analysis_spec_ids)) != 3
    ):
        raise TypeError("The profile fit budget identities changed.")

    if (
        len(candidate_pairs) != 3
        or any(
            candidate is not group_state.candidate_authorizations[ordinal]
            or candidate_state is not group_state.candidate_states[ordinal]
            for ordinal, (candidate, candidate_state) in enumerate(candidate_pairs)
        )
    ):
        raise TypeError("The profile validation boundary changed its candidates.")
    candidate_contexts = tuple(
        invoker._prepared_invocation_context_from_state(candidate, candidate_state)
        for candidate, candidate_state in candidate_pairs
    )
    candidate_basis_rows: list[_ProfileValidationCandidateBasis] = []
    for ordinal, ((candidate, candidate_state), context) in enumerate(
        zip(candidate_pairs, candidate_contexts, strict=True)
    ):
        validation_payload, validation_arrays = invoker._prepared_scientific_payload(
            context,
            command="validate",
        )
        if not isinstance(validation_arrays, Mapping):
            raise TypeError("Profile validation candidate arrays are invalid.")
        detached_arrays: dict[str, np.ndarray[Any, Any]] = {}
        array_identity_seal: list[
            tuple[
                str,
                np.ndarray[Any, Any],
                bytes,
                tuple[int, ...],
                tuple[int, ...],
                str,
            ]
        ] = []
        for name, value in validation_arrays.items():
            if type(name) is not str or type(value) is not np.ndarray:
                raise TypeError("Profile validation candidate arrays are invalid.")
            detached, immutable_bytes = _immutable_profile_array_snapshot(value)
            detached_arrays[name] = detached
            array_identity_seal.append(
                (
                    name,
                    detached,
                    immutable_bytes,
                    tuple(detached.shape),
                    tuple(detached.strides),
                    detached.dtype.str,
                )
            )
        frozen_arrays = MappingProxyType(detached_arrays)
        array_catalog = _profile_fit_array_catalog(
            {"dataset": validation_payload["dataset"]},
            frozen_arrays,
        )
        candidate_basis_rows.append(
            _ProfileValidationCandidateBasis(
                ordinal=ordinal,
                candidate_authorization=candidate,
                candidate_state=candidate_state,
                invocation_context=context,
                validation_payload_bytes=canonical_json_bytes(validation_payload),
                array_catalog_bytes=canonical_json_bytes(array_catalog),
                arrays=frozen_arrays,
                plan_bytes=bytes(candidate_state.plan_bytes),
                planning_summary_binding_bytes=bytes(
                    candidate_state.planning_summary_binding_bytes
                ),
                record_bytes=bytes(candidate_state.record_bytes),
                universe_bytes=bytes(candidate_state.universe_bytes),
                array_identity_seal=tuple(array_identity_seal),
            )
        )
    candidates = cast(
        tuple[
            _ProfileValidationCandidateBasis,
            _ProfileValidationCandidateBasis,
            _ProfileValidationCandidateBasis,
        ],
        tuple(candidate_basis_rows),
    )
    coordinate = _profile_fit_receipt_mapping(
        group_state.input_binding_state.coordinate_bytes,
        label="Profile fit coordinate",
    )
    replicate_index = coordinate.get("replicate_index")
    rotations = execution_policy.get("ordered_budget_rotations")
    if (
        type(replicate_index) is not int
        or isinstance(replicate_index, bool)
        or replicate_index not in {0, 1, 2}
        or type(rotations) is not list
    ):
        raise TypeError("The profile fit coordinate rotation is invalid.")
    matching_rotations: list[dict[str, Any]] = []
    for candidate_row in rotations:
        if type(candidate_row) is not dict:
            raise TypeError("The profile fit rotation table is invalid.")
        row = cast(dict[str, Any], candidate_row)
        if set(row) != set(coordinate) | {"ordered_profile_ids"}:
            raise TypeError("A profile fit rotation row changed shape.")
        if all(row.get(field) == value for field, value in coordinate.items()):
            matching_rotations.append(row)
    expected_rotation = tuple(
        _CANONICAL_PROFILE_IDS[(replicate_index + offset) % len(_CANONICAL_PROFILE_IDS)]
        for offset in range(len(_CANONICAL_PROFILE_IDS))
    )
    if (
        len(matching_rotations) != 1
        or type(matching_rotations[0].get("ordered_profile_ids")) is not list
        or tuple(matching_rotations[0]["ordered_profile_ids"]) != expected_rotation
    ):
        raise TypeError("The profile fit runtime rotation changed.")

    schedule_rows: list[dict[str, Any]] = []
    fit_payload_rows: list[bytes] = []
    profile_to_candidate = {
        profile_id: ordinal for ordinal, profile_id in enumerate(_CANONICAL_PROFILE_IDS)
    }
    for runtime_profile_position, profile_id in enumerate(expected_rotation):
        candidate_ordinal = profile_to_candidate[profile_id]
        candidate_basis = candidates[candidate_ordinal]
        context = candidate_contexts[candidate_ordinal]
        universe = _profile_fit_receipt_mapping(
            candidate_basis.universe_bytes,
            label="Profile fit candidate universe",
        )
        chain_plan = universe.get("chain_plan")
        universe_id = universe.get("universe_id")
        if (
            type(chain_plan) is not list
            or len(chain_plan) != _PROFILE_CHAIN_COUNT
            or type(universe_id) is not str
            or not universe_id
        ):
            raise TypeError("The profile fit chain plan changed.")
        for chain_plan_position, candidate_chain in enumerate(chain_plan):
            if type(candidate_chain) is not dict:
                raise TypeError("A profile fit chain row is invalid.")
            chain = cast(dict[str, Any], candidate_chain)
            expected_chain_id = f"chain-{chain_plan_position:04d}"
            if (
                set(chain)
                != {
                    "chain_ordinal",
                    "chain_id",
                    "seed",
                    "chain_execution_id",
                }
                or chain.get("chain_ordinal") != chain_plan_position
                or chain.get("chain_id") != expected_chain_id
                or chain.get("seed")
                != group_state.profile_chain_seeds[chain_plan_position]
                or type(chain.get("chain_execution_id")) is not str
                or not cast(str, chain["chain_execution_id"])
            ):
                raise TypeError("A profile fit chain row changed owner or position.")
            fit_payload, _fit_arrays = invoker._prepared_scientific_payload(
                context,
                command="fit",
                chain_plan_position=chain_plan_position,
                attempt_ordinal=_PROFILE_FIT_ATTEMPT_ORDINAL,
            )
            array_catalog = _profile_fit_receipt_mapping(
                candidate_basis.array_catalog_bytes,
                label="Profile candidate array catalogue",
            )
            fit_dataset = fit_payload.get("dataset")
            if (
                type(fit_dataset) is not dict
                or fit_dataset.get("array_catalog") != array_catalog
            ):
                raise TypeError("Profile fit payload changed its candidate catalogue.")
            chain_execution_id = cast(str, chain["chain_execution_id"])
            fit_payload_bytes = canonical_json_bytes(fit_payload)
            schedule_rows.append(
                {
                    "runtime_position": len(schedule_rows),
                    "runtime_profile_position": runtime_profile_position,
                    "profile_id": profile_id,
                    "candidate_ordinal": candidate_ordinal,
                    "chain_plan_position": chain_plan_position,
                    "universe_id": universe_id,
                    "chain_id": expected_chain_id,
                    "chain_execution_id": chain_execution_id,
                    "attempt_id": attempt_id(
                        chain_execution_id,
                        _PROFILE_FIT_ATTEMPT_ORDINAL,
                    ),
                    "seed": cast(str, chain["seed"]),
                    "attempt_ordinal": _PROFILE_FIT_ATTEMPT_ORDINAL,
                    "fit_payload_sha256": exact_file_sha256(fit_payload_bytes),
                    "array_catalog_sha256": exact_file_sha256(
                        candidate_basis.array_catalog_bytes
                    ),
                }
            )
            fit_payload_rows.append(fit_payload_bytes)
    if (
        len(schedule_rows) != 9
        or tuple(row.get("runtime_position") for row in schedule_rows)
        != tuple(range(9))
    ):
        raise TypeError("The profile validation schedule basis is incomplete.")
    canonical_basis = {
        "basis_schema_version": "ebm-audit-profile-validation-schedule-basis/1.0",
        "profile_execution_identity_sha256": (
            group_state.profile_execution_identity_sha256
        ),
        "coordinate_bytes_sha256": exact_file_sha256(
            group_state.input_binding_state.coordinate_bytes
        ),
        "coordinate_ordinal": group_state.input_binding_state.coordinate_ordinal,
        "ordered_analysis_spec_ids": list(group_state.ordered_analysis_spec_ids),
        "profile_chain_seeds": list(group_state.profile_chain_seeds),
        "plan_receipt_sha256": exact_file_sha256(canonical_json_bytes(plan_receipt)),
        "execution_policy_sha256": exact_file_sha256(
            canonical_json_bytes(execution_policy)
        ),
        "candidates": [
            {
                "ordinal": row.ordinal,
                "validation_payload_sha256": exact_file_sha256(
                    row.validation_payload_bytes
                ),
                "array_catalog_sha256": exact_file_sha256(row.array_catalog_bytes),
                "plan_sha256": exact_file_sha256(row.plan_bytes),
                "planning_summary_sha256": exact_file_sha256(
                    row.planning_summary_binding_bytes
                ),
                "record_sha256": exact_file_sha256(row.record_bytes),
                "universe_sha256": exact_file_sha256(row.universe_bytes),
            }
            for row in candidates
        ],
        "rows": schedule_rows,
    }
    canonical_bytes = canonical_json_bytes(canonical_basis)
    basis = object.__new__(_ProfileValidationScheduleBasis)
    basis_state = _ProfileValidationScheduleBasisState(
        group=group,
        group_state=group_state,
        invoker=invoker,
        token=object(),
        candidates=candidates,
        fit_payload_bytes=tuple(fit_payload_rows),
        execution_policy_bytes=canonical_json_bytes(execution_policy),
        canonical_bytes=canonical_bytes,
        digest=structured_sha256(
            "ebm-audit/profile-validation-schedule-basis/1",
            canonical_basis,
        ),
    )
    _PROFILE_VALIDATION_SCHEDULE_BASIS_STATE_ISSUER.bind_once(
        basis,
        basis_state,
    )
    _require_profile_validation_schedule_basis(
        basis,
        group=group,
        group_state=group_state,
        invoker=invoker,
    )
    return basis


def _bound_profile_validation_schedule_basis(
    value: object,
) -> _ProfileValidationScheduleBasisState:
    state = (
        _PROFILE_VALIDATION_SCHEDULE_BASIS_STATES.get(value)
        if type(value) is _ProfileValidationScheduleBasis
        else None
    )
    if type(state) is not _ProfileValidationScheduleBasisState:
        raise TypeError("A genuine profile validation schedule basis is required.")
    _PROFILE_VALIDATION_SCHEDULE_BASIS_STATES.require(value, state)
    return state


def _require_profile_validation_schedule_basis(
    basis: object,
    *,
    group: object | None = None,
    group_state: object | None = None,
    invoker: object | None = None,
) -> _ProfileValidationScheduleBasis:
    state = _bound_profile_validation_schedule_basis(basis)
    decoded = strict_json_loads(state.canonical_bytes)
    if (
        type(decoded) is not dict
        or canonical_json_bytes(decoded) != state.canonical_bytes
        or structured_sha256(
            "ebm-audit/profile-validation-schedule-basis/1",
            decoded,
        )
        != state.digest
        or type(state.group) is not ProfilePreparedCandidateGroup
        or type(state.group_state) is not _ProfilePreparedCandidateGroupState
        or type(state.invoker) is not WorkerInvoker
        or (group is not None and state.group is not group)
        or (group_state is not None and state.group_state is not group_state)
        or (invoker is not None and state.invoker is not invoker)
        or type(state.token) is not object
        or type(state.candidates) is not tuple
        or len(state.candidates) != 3
        or type(state.fit_payload_bytes) is not tuple
        or len(state.fit_payload_bytes) != 9
        or decoded.get("execution_policy_sha256")
        != exact_file_sha256(state.execution_policy_bytes)
    ):
        raise TypeError("Profile validation schedule basis changed.")
    candidate_projection = [
        {
            "ordinal": row.ordinal,
            "validation_payload_sha256": exact_file_sha256(row.validation_payload_bytes),
            "array_catalog_sha256": exact_file_sha256(row.array_catalog_bytes),
            "plan_sha256": exact_file_sha256(row.plan_bytes),
            "planning_summary_sha256": exact_file_sha256(
                row.planning_summary_binding_bytes
            ),
            "record_sha256": exact_file_sha256(row.record_bytes),
            "universe_sha256": exact_file_sha256(row.universe_bytes),
        }
        for row in state.candidates
        if type(row) is _ProfileValidationCandidateBasis
    ]
    row_projection = decoded.get("rows")
    if (
        len(candidate_projection) != 3
        or any(
            not isinstance(candidate.arrays, MappingProxyType)
            or type(candidate.invocation_context) is not _PreparedInvocationContext
            or candidate.invocation_context.authorization
            is not candidate.candidate_authorization
            or candidate.invocation_context.prepared_state
            is not candidate.candidate_state
            or set(candidate.arrays)
            != set(
                _profile_fit_receipt_mapping(
                    candidate.array_catalog_bytes,
                    label="Profile candidate array catalogue",
                )
            )
            or any(
                type(array) is not np.ndarray
                or array.flags.writeable
                or not array.flags.c_contiguous
                or array.flags.owndata
                for array in candidate.arrays.values()
            )
            or tuple(candidate.arrays) != tuple(
                row[0] for row in candidate.array_identity_seal
            )
            or any(
                candidate.arrays.get(row[0]) is not row[1]
                or _profile_array_immutable_bytes(row[1]) is not row[2]
                or tuple(row[1].shape) != row[3]
                or tuple(row[1].strides) != row[4]
                or row[1].dtype.str != row[5]
                or row[1].flags.writeable
                or not row[1].flags.c_contiguous
                or row[1].flags.owndata
                for row in candidate.array_identity_seal
            )
            for candidate in state.candidates
        )
        or type(row_projection) is not list
        or len(row_projection) != 9
        or any(type(row) is not dict for row in row_projection)
        or tuple(row.get("runtime_position") for row in row_projection)
        != tuple(range(9))
        or any(
            type(row.get("candidate_ordinal")) is not int
            or isinstance(row.get("candidate_ordinal"), bool)
            or cast(int, row.get("candidate_ordinal")) not in {0, 1, 2}
            for row in row_projection
        )
        or any(
            row.get("fit_payload_sha256")
            != exact_file_sha256(state.fit_payload_bytes[position])
            or row.get("array_catalog_sha256")
            != exact_file_sha256(
                state.candidates[cast(int, row.get("candidate_ordinal"))]
                .array_catalog_bytes
            )
            for position, row in enumerate(row_projection)
        )
        or decoded.get("candidates") != candidate_projection
    ):
        raise TypeError("Profile validation schedule basis rows changed.")
    return cast(_ProfileValidationScheduleBasis, basis)


def _validate_profile_validation_schedule_basis(
    basis: object,
) -> _ProfileValidationScheduleBasis:
    return _require_profile_validation_schedule_basis(basis)


def _profile_validation_basis_schedule_rows(
    basis: _ProfileValidationScheduleBasis,
) -> tuple[dict[str, Any], ...]:
    basis = _require_profile_validation_schedule_basis(basis)
    decoded = strict_json_loads(basis.canonical_bytes)
    rows = decoded.get("rows") if type(decoded) is dict else None
    if type(rows) is not list or any(type(row) is not dict for row in rows):
        raise TypeError("Profile validation schedule basis rows changed.")
    return tuple(cast(dict[str, Any], row) for row in rows)


def _profile_fit_plain_json(value: object) -> object:
    """Detach one closed readback projection into encoder-owned JSON containers."""

    if value is None or type(value) in {bool, float, int, str}:
        return value
    if isinstance(value, Mapping):
        detached: dict[str, object] = {}
        for key, child in value.items():
            if type(key) is not str:
                raise TypeError("Profile fit dispatch description changed.")
            detached[key] = _profile_fit_plain_json(child)
        return detached
    if isinstance(value, (list, tuple)):
        return [_profile_fit_plain_json(child) for child in value]
    raise TypeError("Profile fit dispatch description changed.")


def _profile_fit_description_projection_bytes(
    description: object,
) -> bytes:
    if type(description) is not _AuthenticatedDescriptionReadback:
        raise TypeError("Profile fit dispatch description changed.")
    projection = {
        "canonical_response": strict_json_loads(
            description.canonical_response_bytes
        ),
        "backend_identity": description.backend_identity,
        "backend_identity_digest": description.backend_identity_digest,
        "description_result": description.description_result,
        "expected_identity": description.expected_identity,
        "expected_identity_digest": description.expected_identity_digest,
        "requested_output_registry_digest": (
            description.requested_output_registry_digest
        ),
        "response_metadata_digest": description.response_metadata_digest,
        "supported_algorithms": description.supported_algorithms,
        "selected_algorithm_binding": description.selected_algorithm_binding,
        "selected_algorithm_binding_digest": (
            description.selected_algorithm_binding_digest
        ),
    }
    return canonical_json_bytes(_profile_fit_plain_json(projection))


def _profile_fit_execution_origin_bytes(
    candidate_state: _PreparedExecutionAuthorizationState,
) -> bytes:
    origin = candidate_state.execution_origin
    try:
        projection = {
            "route": origin.route,
            "profile_candidate_ordinal": origin.profile_candidate_ordinal,
            "profile_execution_identity_sha256": (
                origin.profile_execution_identity_sha256
            ),
            "profile_chain_seeds": (
                None
                if origin.profile_chain_seeds is None
                else list(origin.profile_chain_seeds)
            ),
        }
        owner = origin.owner
    except AttributeError:
        raise TypeError("Profile fit dispatch execution origin changed.") from None
    if projection["route"] != "PROFILE" or owner is None:
        raise TypeError("Profile fit dispatch execution origin changed.")
    return canonical_json_bytes(projection)


def _capture_profile_fit_dispatch_context_seal(
    *,
    context: _PreparedCandidateExecutionContext,
    context_state: _PreparedCandidateExecutionContextState,
    basis: _ProfileValidationScheduleBasis,
    basis_token: object,
    candidate_authorization: object,
    candidate_state: _PreparedExecutionAuthorizationState,
    invoker: WorkerInvoker,
) -> _ProfileFitDispatchContextSeal:
    invocation_context = context_state.invocation_context
    if (
        type(context_state) is not _PreparedCandidateExecutionContextState
        or type(invocation_context) is not _PreparedInvocationContext
        or context_state.invoker is not invoker
        or context_state.profile_validation_schedule_basis is not basis
        or context_state.profile_validation_schedule_basis_token is not basis_token
        or invocation_context.authorization is not candidate_authorization
        or invocation_context.prepared_state is not candidate_state
        or invocation_context.required_execution_input_projection_digest is not None
    ):
        raise TypeError("Profile fit dispatch context capture changed.")
    return _ProfileFitDispatchContextSeal(
        candidate_execution_context=context,
        candidate_execution_context_state=context_state,
        invoker=invoker,
        candidate_authorization=candidate_authorization,
        candidate_state=candidate_state,
        authenticated_description=invocation_context.authenticated_description,
        authenticated_description_state=(
            invocation_context.authenticated_description_state
        ),
        selected_algorithm_binding_bytes=canonical_json_bytes(
            invocation_context.selected_algorithm_binding
        ),
        planning_summary_id=invocation_context.planning_summary_id,
        schedule_basis=basis,
        schedule_basis_token=basis_token,
        execution_origin_bytes=_profile_fit_execution_origin_bytes(candidate_state),
        description_projection_bytes=_profile_fit_description_projection_bytes(
            invocation_context.description
        ),
    )


def _profile_fit_request_owner_from_row(
    row: object,
) -> _ProfileFitRequestOwner:
    if type(row) is not _ProfileFitScheduleReceiptRow:
        raise TypeError("Profile fit dispatch projection changed.")
    seal = row.dispatch_context_seal
    if type(seal) is not _ProfileFitDispatchContextSeal:
        raise TypeError("Profile fit dispatch projection changed.")
    description_projection = strict_json_loads(
        seal.description_projection_bytes
    )
    selected_binding = strict_json_loads(
        seal.selected_algorithm_binding_bytes
    )
    origin = strict_json_loads(seal.execution_origin_bytes)
    if (
        type(seal.candidate_execution_context)
        is not _PreparedCandidateExecutionContext
        or type(seal.candidate_execution_context_state)
        is not _PreparedCandidateExecutionContextState
        or type(seal.invoker) is not WorkerInvoker
        or type(description_projection) is not dict
        or canonical_json_bytes(description_projection)
        != seal.description_projection_bytes
        or type(selected_binding) is not dict
        or canonical_json_bytes(selected_binding)
        != seal.selected_algorithm_binding_bytes
        or type(origin) is not dict
        or canonical_json_bytes(origin) != seal.execution_origin_bytes
        or origin.get("route") != "PROFILE"
        or type(seal.planning_summary_id) is not str
        or not seal.planning_summary_id
        or row.candidate_authorization is not seal.candidate_authorization
        or row.candidate_state is not seal.candidate_state
        or row.candidate_execution_context
        is not seal.candidate_execution_context
        or row.candidate_execution_context_state
        is not seal.candidate_execution_context_state
    ):
        raise TypeError("Profile fit dispatch projection changed.")
    _require_prepared_candidate_execution_context_state_identity(
        seal.candidate_execution_context,
        seal.candidate_execution_context_state,
    )
    canonical_response = description_projection.get("canonical_response")
    supported_algorithms = description_projection.get("supported_algorithms")
    if (
        type(canonical_response) is not dict
        or type(supported_algorithms) is not list
        or any(type(item) is not dict for item in supported_algorithms)
    ):
        raise TypeError("Profile fit dispatch projection changed.")
    description = _AuthenticatedDescriptionReadback(
        description=seal.authenticated_description,
        canonical_response_bytes=canonical_json_bytes(canonical_response),
        backend_identity=MappingProxyType(
            cast(dict[str, Any], description_projection["backend_identity"])
        ),
        backend_identity_digest=cast(
            str, description_projection["backend_identity_digest"]
        ),
        description_result=MappingProxyType(
            cast(dict[str, Any], description_projection["description_result"])
        ),
        expected_identity=MappingProxyType(
            cast(dict[str, Any], description_projection["expected_identity"])
        ),
        expected_identity_digest=cast(
            str, description_projection["expected_identity_digest"]
        ),
        requested_output_registry_digest=cast(
            str,
            description_projection["requested_output_registry_digest"],
        ),
        response_metadata_digest=cast(
            str, description_projection["response_metadata_digest"]
        ),
        supported_algorithms=tuple(
            cast(list[dict[str, Any]], supported_algorithms)
        ),
        selected_algorithm_binding=MappingProxyType(selected_binding),
        selected_algorithm_binding_digest=cast(
            str,
            description_projection["selected_algorithm_binding_digest"],
        ),
    )
    invocation_context = _PreparedInvocationContext(
        authorization=seal.candidate_authorization,
        prepared_state=seal.candidate_state,
        authenticated_description=seal.authenticated_description,
        authenticated_description_state=seal.authenticated_description_state,
        description=description,
        selected_algorithm_binding=MappingProxyType(selected_binding),
        planning_summary_id=seal.planning_summary_id,
        required_execution_input_projection_digest=(
            row.execution_input_projection_digest
        ),
    )
    return _ProfileFitRequestOwner(
        row=row,
        candidate_execution_context=seal.candidate_execution_context,
        candidate_execution_context_state=(
            seal.candidate_execution_context_state
        ),
        invocation_context=invocation_context,
    )


def _profile_fit_request_owner_from_receipt(
    receipt: object,
    row_index: object,
    *,
    invoker: WorkerInvoker,
) -> _ProfileFitRequestOwner:
    state = _bound_profile_fit_schedule_receipt(receipt)
    if (
        state.invoker is not invoker
        or type(row_index) is not int
        or isinstance(row_index, bool)
        or row_index < 0
        or row_index >= len(state.rows)
    ):
        raise TypeError("Profile fit dispatch projection changed.")
    owner = _profile_fit_request_owner_from_row(state.rows[row_index])
    if owner.row is not state.rows[row_index]:
        raise TypeError("Profile fit dispatch projection changed.")
    return owner


def _validate_profile_validation_resolved_snapshot(
    snapshot: object,
    *,
    evidence: AuthenticatedWorkerExecutionEvidence | None = None,
    planning_summary_id: str | None = None,
) -> _ProfileValidationResolvedSnapshot:
    if (
        type(snapshot) is not _ProfileValidationResolvedSnapshot
        or type(snapshot.capability) is not AuthenticatedWorkerExecutionEvidence
        or (evidence is not None and snapshot.capability is not evidence)
        or type(snapshot.planning_summary_id) is not str
        or not snapshot.planning_summary_id
        or (
            planning_summary_id is not None
            and snapshot.planning_summary_id != planning_summary_id
        )
        or type(snapshot.response_warnings_bytes) is not bytes
    ):
        raise TypeError("Profile validation resolved snapshot changed.")
    request = strict_json_loads(snapshot.request_bytes)
    response = strict_json_loads(snapshot.response_bytes)
    reference = strict_json_loads(snapshot.reference_bytes)
    request_payload = (
        request.get("payload") if type(request) is dict else None
    )
    execution_input_projection = (
        request_payload.get("execution_input_projection")
        if type(request_payload) is dict
        else None
    )
    try:
        validate_instance(
            reference,
            "canonical-records.schema.json",
            definition="WorkerExecutionEvidenceReference",
        )
    except SchemaValidationError:
        raise TypeError("Profile validation resolved snapshot changed.") from None
    if (
        type(request) is not dict
        or type(response) is not dict
        or type(reference) is not dict
        or canonical_json_bytes(request) != snapshot.request_bytes
        or canonical_json_bytes(response) != snapshot.response_bytes
        or canonical_json_bytes(reference) != snapshot.reference_bytes
        or request.get("command") != "validate"
        or type(request_payload) is not dict
        or type(execution_input_projection) is not dict
        or request_payload.get("execution_input_projection_digest")
        != execution_input_projection_digest(execution_input_projection)
        or response.get("command") != "validate"
        or response.get("status") != "SUCCESS"
        or type(response.get("payload")) is not dict
        or response["payload"].get("fit_permitted") is not True
        or reference.get("command") != "validate"
        or reference.get("status") != "SUCCESS"
        or reference.get("chain_plan_position") is not None
        or reference.get("chain_execution_id") is not None
        or reference.get("attempt_id") is not None
        or reference.get("attempt_ordinal") is not None
        or reference.get("scientific_request_digest")
        != request.get("scientific_request_digest")
        or reference.get("request_metadata_digest")
        != request.get("request_metadata_digest")
        or reference.get("response_metadata_digest")
        != response.get("response_metadata_digest")
    ):
        raise TypeError("Profile validation resolved snapshot changed.")
    return snapshot


def _capture_profile_validation_resolved_snapshot(
    *,
    evidence: AuthenticatedWorkerExecutionEvidence,
    readback: _AuthenticatedExecutionReadback,
) -> _ProfileValidationResolvedSnapshot:
    planning_summary_id = readback.request_planning_summary_id
    if (
        type(readback) is not _AuthenticatedExecutionReadback
        or readback.execution is not evidence
        or type(planning_summary_id) is not str
        or not planning_summary_id
    ):
        raise TypeError("Profile validation resolved snapshot has no exact owner.")
    resolved = _resolve_attempt(
        evidence,
        expected_command="validate",
        chain_plan_position=None,
        expected_planning_summary_id=planning_summary_id,
        authenticated_readback=readback,
    )
    if (
        type(resolved) is not _ResolvedAttempt
        or resolved.capability is not evidence
        or resolved.command != "validate"
        or resolved.status != "SUCCESS"
        or resolved.response is None
        or resolved.response["payload"].get("fit_permitted") is not True
        or resolved.chain_execution_id is not None
        or resolved.attempt_id is not None
        or resolved.attempt_ordinal is not None
        or resolved.retry_equivalence_digest is not None
        or resolved.failure_class is not None
        or resolved.failure_code is not None
        or resolved.planning_summary_id != planning_summary_id
        or bool(resolved.response_arrays)
        or type(resolved.response_warnings_bytes) is not bytes
    ):
        raise TypeError("Profile validation resolved snapshot changed.")
    snapshot = _ProfileValidationResolvedSnapshot(
        capability=evidence,
        request_bytes=canonical_json_bytes(resolved.request),
        response_bytes=canonical_json_bytes(resolved.response),
        response_warnings_bytes=resolved.response_warnings_bytes,
        reference_bytes=canonical_json_bytes(resolved.reference),
        planning_summary_id=planning_summary_id,
    )
    return _validate_profile_validation_resolved_snapshot(
        snapshot,
        evidence=evidence,
        planning_summary_id=planning_summary_id,
    )


def _resolved_profile_validation_attempt(
    snapshot: object,
) -> _ResolvedAttempt:
    sealed = _validate_profile_validation_resolved_snapshot(snapshot)
    request = _profile_fit_receipt_mapping(
        sealed.request_bytes,
        label="Profile validation snapshot request",
    )
    response = _profile_fit_receipt_mapping(
        sealed.response_bytes,
        label="Profile validation snapshot response",
    )
    reference = _profile_fit_receipt_mapping(
        sealed.reference_bytes,
        label="Profile validation snapshot reference",
    )
    return _ResolvedAttempt(
        capability=sealed.capability,
        request=MappingProxyType(request),
        response=MappingProxyType(response),
        response_arrays=MappingProxyType({}),
        response_warnings_bytes=sealed.response_warnings_bytes,
        reference=MappingProxyType(reference),
        command="validate",
        status="SUCCESS",
        chain_execution_id=None,
        attempt_id=None,
        attempt_ordinal=None,
        retry_equivalence_digest=None,
        failure_class=None,
        failure_code=None,
        planning_summary_id=sealed.planning_summary_id,
    )


def _require_profile_validation_wire_projection(
    request_payload: object,
    *,
    projection_digest: object,
    basis_validation_payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Join one authenticated validate wire owner back to its captured basis."""

    execution_input_projection = (
        request_payload.get("execution_input_projection")
        if type(request_payload) is dict
        else None
    )
    if (
        type(request_payload) is not dict
        or set(request_payload)
        != {
            "execution_input_projection",
            "execution_input_projection_digest",
        }
        or type(execution_input_projection) is not dict
        or type(projection_digest) is not str
        or not projection_digest.startswith("sha256:")
        or len(projection_digest) != 71
        or request_payload.get("execution_input_projection_digest")
        != projection_digest
        or execution_input_projection_digest(execution_input_projection)
        != projection_digest
        or any(
            execution_input_projection.get(field)
            != basis_validation_payload.get(field)
            for field in (
                "algorithm_id",
                "settings",
                "settings_digest",
                "config_digest",
                "requested_outputs",
                "requested_outputs_digest",
                "dataset",
            )
        )
    ):
        raise TypeError("Profile fit receipt lost its validation wire projection.")
    return execution_input_projection


def _capture_profile_fit_schedule_receipt(
    *,
    basis: _ProfileValidationScheduleBasis,
    invoker: WorkerInvoker,
    terminals: tuple[
        _ProfileValidationTerminal,
        _ProfileValidationTerminal,
        _ProfileValidationTerminal,
    ],
    readbacks: tuple[
        _AuthenticatedExecutionReadback,
        _AuthenticatedExecutionReadback,
        _AuthenticatedExecutionReadback,
    ],
) -> _ProfileFitScheduleReceipt:
    """Seal the post-validation receipt from basis plus authenticated requests only."""

    basis = _require_profile_validation_schedule_basis(
        basis,
        invoker=invoker,
    )
    basis_state = _bound_profile_validation_schedule_basis(basis)
    if (
        _read_profile_prepared_candidate_group(basis_state.group)
        is not basis_state.group_state
    ):
        raise TypeError("Profile source changed before fit receipt issuance.")
    validation_owners: dict[
        int,
        tuple[
            AuthenticatedWorkerExecutionEvidence,
            _PreparedCandidateExecutionContext,
            _PreparedCandidateExecutionContextState,
            str,
            str,
            _ProfileValidationResolvedSnapshot,
            _ProfileFitDispatchContextSeal,
        ],
    ] = {}
    for candidate_basis, terminal, readback in zip(
        basis.candidates,
        terminals,
        readbacks,
        strict=True,
    ):
        evidence = terminal.evidence
        if (
            terminal.ordinal != candidate_basis.ordinal
            or terminal.candidate_authorization is not candidate_basis.candidate_authorization
            or terminal.candidate_state is not candidate_basis.candidate_state
            or type(evidence) is not AuthenticatedWorkerExecutionEvidence
        ):
            raise TypeError("Profile fit receipt changed its basis candidate owner.")
        request_payload = readback.request.get("payload")
        context = readback.request_readback.prepared_candidate_execution_context
        context_state = readback.request_readback.prepared_candidate_execution_context_state
        projection_digest = readback.request_execution_input_projection_digest
        basis_validation_payload = _profile_fit_receipt_mapping(
            candidate_basis.validation_payload_bytes,
            label="Profile validation basis payload",
        )
        if (
            type(readback) is not _AuthenticatedExecutionReadback
            or readback.execution is not evidence
            or type(request_payload) is not dict
            or type(context) is not _PreparedCandidateExecutionContext
            or type(context_state) is not _PreparedCandidateExecutionContextState
            or _read_prepared_candidate_execution_context(context) is not context_state
            or context_state.invoker is not invoker
            or context_state.profile_validation_schedule_basis is not basis
            or context_state.profile_validation_schedule_basis_token
            is not basis_state.token
            or context_state.invocation_context.authorization
            is not candidate_basis.candidate_authorization
            or context_state.invocation_context.prepared_state
            is not candidate_basis.candidate_state
            or readback.request.get("command") != "validate"
            or readback.response.get("command") != "validate"
            or readback.response.get("status") != "SUCCESS"
            or type(readback.response.get("payload")) is not dict
            or readback.response["payload"].get("fit_permitted") is not True
        ):
            raise TypeError("Profile fit receipt lost its validation schedule basis.")
        _require_profile_validation_wire_projection(
            request_payload,
            projection_digest=projection_digest,
            basis_validation_payload=basis_validation_payload,
        )
        projection_digest = cast(str, projection_digest)
        validation_snapshot = _capture_profile_validation_resolved_snapshot(
            evidence=evidence,
            readback=readback,
        )
        dispatch_context_seal = _capture_profile_fit_dispatch_context_seal(
            context=context,
            context_state=context_state,
            basis=basis,
            basis_token=basis_state.token,
            candidate_authorization=candidate_basis.candidate_authorization,
            candidate_state=candidate_basis.candidate_state,
            invoker=invoker,
        )
        validation_owners[candidate_basis.ordinal] = (
            evidence,
            context,
            context_state,
            projection_digest,
            readback.execution_evidence_digest,
            validation_snapshot,
            dispatch_context_seal,
        )

    schedule_rows = _profile_validation_basis_schedule_rows(basis)
    rows: list[_ProfileFitScheduleReceiptRow] = []
    for runtime_position, basis_row in enumerate(schedule_rows):
        candidate_ordinal = basis_row.get("candidate_ordinal")
        if (
            type(candidate_ordinal) is not int
            or isinstance(candidate_ordinal, bool)
            or candidate_ordinal not in {0, 1, 2}
        ):
            raise TypeError("Profile fit receipt changed its candidate owner.")
        candidate_basis = basis.candidates[candidate_ordinal]
        (
            evidence,
            context,
            context_state,
            projection_digest,
            _evidence_digest,
            validation_snapshot,
            dispatch_context_seal,
        ) = validation_owners[candidate_ordinal]
        fit_payload = _profile_fit_receipt_mapping(
            basis.fit_payload_bytes[runtime_position],
            label="Profile fit basis payload",
        )
        array_catalog = _profile_fit_receipt_mapping(
            candidate_basis.array_catalog_bytes,
            label="Profile fit basis array catalogue",
        )
        fit_dataset = fit_payload.get("dataset")
        if (
            type(fit_dataset) is not dict
            or fit_dataset.get("array_catalog") != array_catalog
        ):
            raise TypeError("Profile fit receipt changed its array catalogue.")
        row_fields = {
            field: basis_row.get(field)
            for field in (
                "runtime_position",
                "runtime_profile_position",
                "profile_id",
                "chain_plan_position",
                "universe_id",
                "chain_id",
                "chain_execution_id",
                "attempt_id",
                "seed",
                "attempt_ordinal",
            )
        }
        if (
            any(
                type(row_fields[field]) is not int
                or isinstance(row_fields[field], bool)
                for field in (
                    "runtime_position",
                    "runtime_profile_position",
                    "chain_plan_position",
                    "attempt_ordinal",
                )
            )
            or any(
                type(row_fields[field]) is not str or not row_fields[field]
                for field in (
                    "profile_id",
                    "universe_id",
                    "chain_id",
                    "chain_execution_id",
                    "attempt_id",
                    "seed",
                )
            )
        ):
            raise TypeError("Profile fit receipt schedule row is invalid.")
        rows.append(
            _ProfileFitScheduleReceiptRow(
                runtime_position=cast(int, row_fields["runtime_position"]),
                runtime_profile_position=cast(
                    int, row_fields["runtime_profile_position"]
                ),
                profile_id=cast(str, row_fields["profile_id"]),
                candidate_ordinal=candidate_ordinal,
                candidate_authorization=candidate_basis.candidate_authorization,
                candidate_state=candidate_basis.candidate_state,
                validation_evidence=evidence,
                validation_snapshot=validation_snapshot,
                dispatch_context_seal=dispatch_context_seal,
                candidate_execution_context=context,
                candidate_execution_context_state=context_state,
                execution_input_projection_digest=projection_digest,
                chain_plan_position=cast(
                    int, row_fields["chain_plan_position"]
                ),
                universe_id=cast(str, row_fields["universe_id"]),
                chain_id=cast(str, row_fields["chain_id"]),
                chain_execution_id=cast(
                    str, row_fields["chain_execution_id"]
                ),
                attempt_id=cast(str, row_fields["attempt_id"]),
                seed=cast(str, row_fields["seed"]),
                attempt_ordinal=cast(int, row_fields["attempt_ordinal"]),
            )
        )
    receipt_rows = tuple(rows)
    receipt_value = {
        "receipt_schema_version": "ebm-audit-profile-fit-session-receipt/1.0",
        "basis_digest": basis.digest,
        "validation_evidence_digests": [
            validation_owners[ordinal][4] for ordinal in range(3)
        ],
        "rows": [
            {
                "runtime_position": row.runtime_position,
                "runtime_profile_position": row.runtime_profile_position,
                "profile_id": row.profile_id,
                "candidate_ordinal": row.candidate_ordinal,
                "validation_request_sha256": exact_file_sha256(
                    row.validation_snapshot.request_bytes
                ),
                "validation_response_sha256": exact_file_sha256(
                    row.validation_snapshot.response_bytes
                ),
                "validation_reference_sha256": exact_file_sha256(
                    row.validation_snapshot.reference_bytes
                ),
                "validation_warnings_sha256": exact_file_sha256(
                    row.validation_snapshot.response_warnings_bytes
                ),
                "validation_planning_summary_id": (
                    row.validation_snapshot.planning_summary_id
                ),
                "dispatch_context_sha256": exact_file_sha256(
                    row.dispatch_context_seal.description_projection_bytes
                ),
                "dispatch_origin_sha256": exact_file_sha256(
                    row.dispatch_context_seal.execution_origin_bytes
                ),
                "dispatch_selected_binding_sha256": exact_file_sha256(
                    row.dispatch_context_seal.selected_algorithm_binding_bytes
                ),
                "execution_input_projection_digest": (
                    row.execution_input_projection_digest
                ),
                "chain_plan_position": row.chain_plan_position,
                "universe_id": row.universe_id,
                "chain_id": row.chain_id,
                "chain_execution_id": row.chain_execution_id,
                "attempt_id": row.attempt_id,
                "seed": row.seed,
                "attempt_ordinal": row.attempt_ordinal,
            }
            for row in receipt_rows
        ],
    }
    receipt_bytes = canonical_json_bytes(receipt_value)
    receipt = object.__new__(_ProfileFitScheduleReceipt)
    receipt_state = _ProfileFitScheduleReceiptState(
        token=object(),
        basis=basis,
        invoker=invoker,
        rows=receipt_rows,
        canonical_bytes=receipt_bytes,
        digest=structured_sha256(
            "ebm-audit/profile-fit-session-receipt/1",
            receipt_value,
        ),
    )
    _PROFILE_FIT_SCHEDULE_RECEIPT_STATE_ISSUER.bind_once(
        receipt,
        receipt_state,
    )
    if _require_profile_fit_schedule_receipt(receipt) is not receipt_state:
        raise TypeError("Profile fit schedule receipt issuance failed.")
    return receipt


def _profile_fit_receipt_row_projection(
    row: _ProfileFitScheduleReceiptRow,
) -> dict[str, object]:
    return {
        "runtime_position": row.runtime_position,
        "runtime_profile_position": row.runtime_profile_position,
        "profile_id": row.profile_id,
        "candidate_ordinal": row.candidate_ordinal,
        "validation_request_sha256": exact_file_sha256(
            row.validation_snapshot.request_bytes
        ),
        "validation_response_sha256": exact_file_sha256(
            row.validation_snapshot.response_bytes
        ),
        "validation_reference_sha256": exact_file_sha256(
            row.validation_snapshot.reference_bytes
        ),
        "validation_warnings_sha256": exact_file_sha256(
            row.validation_snapshot.response_warnings_bytes
        ),
        "validation_planning_summary_id": (
            row.validation_snapshot.planning_summary_id
        ),
        "dispatch_context_sha256": exact_file_sha256(
            row.dispatch_context_seal.description_projection_bytes
        ),
        "dispatch_origin_sha256": exact_file_sha256(
            row.dispatch_context_seal.execution_origin_bytes
        ),
        "dispatch_selected_binding_sha256": exact_file_sha256(
            row.dispatch_context_seal.selected_algorithm_binding_bytes
        ),
        "execution_input_projection_digest": row.execution_input_projection_digest,
        "chain_plan_position": row.chain_plan_position,
        "universe_id": row.universe_id,
        "chain_id": row.chain_id,
        "chain_execution_id": row.chain_execution_id,
        "attempt_id": row.attempt_id,
        "seed": row.seed,
        "attempt_ordinal": row.attempt_ordinal,
    }


def _bound_profile_fit_schedule_receipt(
    value: object,
) -> _ProfileFitScheduleReceiptState:
    state = (
        _PROFILE_FIT_SCHEDULE_RECEIPT_STATES.get(value)
        if type(value) is _ProfileFitScheduleReceipt
        else None
    )
    if type(state) is not _ProfileFitScheduleReceiptState:
        raise TypeError("A genuine profile fit schedule receipt is required.")
    _PROFILE_FIT_SCHEDULE_RECEIPT_STATES.require(value, state)
    return state


def _require_profile_fit_schedule_receipt(
    value: object,
) -> _ProfileFitScheduleReceiptState:
    state = _bound_profile_fit_schedule_receipt(value)
    basis_state = _bound_profile_validation_schedule_basis(state.basis)
    if (
        type(state.token) is not object
        or type(state.basis) is not _ProfileValidationScheduleBasis
        or type(state.invoker) is not WorkerInvoker
        or type(state.rows) is not tuple
        or len(state.rows) != 9
        or any(type(row) is not _ProfileFitScheduleReceiptRow for row in state.rows)
        or type(state.canonical_bytes) is not bytes
        or type(state.digest) is not str
    ):
        raise TypeError("A genuine profile fit schedule receipt is required.")
    decoded = strict_json_loads(state.canonical_bytes)
    decoded_rows = decoded.get("rows") if type(decoded) is dict else None
    evidence_digests = (
        decoded.get("validation_evidence_digests")
        if type(decoded) is dict
        else None
    )
    if (
        type(decoded) is not dict
        or canonical_json_bytes(decoded) != state.canonical_bytes
        or structured_sha256(
            "ebm-audit/profile-fit-session-receipt/1",
            decoded,
        )
        != state.digest
        or decoded.get("receipt_schema_version")
        != "ebm-audit-profile-fit-session-receipt/1.0"
        or decoded.get("basis_digest") != state.basis.digest
        or decoded_rows
        != [_profile_fit_receipt_row_projection(row) for row in state.rows]
        or type(evidence_digests) is not list
        or len(evidence_digests) != 3
        or any(
            type(digest) is not str
            or not digest.startswith("sha256:")
            or len(digest) != 71
            for digest in evidence_digests
        )
    ):
        raise TypeError("Profile fit schedule receipt changed.")
    candidate_owner_rows: dict[int, _ProfileFitScheduleReceiptRow] = {}
    for position, row in enumerate(state.rows):
        if row.candidate_ordinal not in {0, 1, 2}:
            raise TypeError("Profile fit schedule receipt changed.")
        candidate = state.basis.candidates[row.candidate_ordinal]
        owner = candidate_owner_rows.setdefault(row.candidate_ordinal, row)
        seal = row.dispatch_context_seal
        validation_snapshot = _validate_profile_validation_resolved_snapshot(
            row.validation_snapshot,
            evidence=row.validation_evidence,
            planning_summary_id=seal.planning_summary_id,
        )
        dispatch_owner = _profile_fit_request_owner_from_row(row)
        if (
            row.runtime_position != position
            or row.attempt_id
            != attempt_id(row.chain_execution_id, row.attempt_ordinal)
            or row.candidate_authorization is not candidate.candidate_authorization
            or row.candidate_state is not candidate.candidate_state
            or seal.invoker is not state.invoker
            or seal.schedule_basis is not state.basis
            or seal.schedule_basis_token is not basis_state.token
            or seal.candidate_authorization is not row.candidate_authorization
            or seal.candidate_state is not row.candidate_state
            or seal.candidate_execution_context
            is not row.candidate_execution_context
            or seal.candidate_execution_context_state
            is not row.candidate_execution_context_state
            or dispatch_owner.row is not row
            or row.candidate_authorization is not owner.candidate_authorization
            or row.candidate_state is not owner.candidate_state
            or row.validation_evidence is not owner.validation_evidence
            or validation_snapshot is not owner.validation_snapshot
            or seal is not owner.dispatch_context_seal
            or row.candidate_execution_context
            is not owner.candidate_execution_context
            or row.candidate_execution_context_state
            is not owner.candidate_execution_context_state
            or row.execution_input_projection_digest
            != owner.execution_input_projection_digest
        ):
            raise TypeError("Profile fit schedule receipt changed.")
    _PROFILE_FIT_SCHEDULE_RECEIPT_STATES.require(value, state)
    return state


def _bound_profile_validation_barrier(
    value: object,
) -> _ProfileValidationBarrierState:
    state: _ProfileValidationBarrierState | None = None
    if type(value) is ProfileValidationBarrier:
        try:
            state = _PROFILE_VALIDATION_BARRIER_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _ProfileValidationBarrierState:
        raise TypeError("A genuine profile validation barrier is required.")
    _PROFILE_VALIDATION_BARRIER_STATES.require(value, state)
    return state


def _validate_profile_validation_barrier_state(
    value: ProfileValidationBarrier,
    state: _ProfileValidationBarrierState,
    receipt_state: _ProfileFitScheduleReceiptState,
) -> _ProfileValidationBarrierState:
    if (
        type(state.group) is not ProfilePreparedCandidateGroup
        or type(state.group_state) is not _ProfilePreparedCandidateGroupState
        or type(state.invoker) is not WorkerInvoker
        or type(state.terminals) is not tuple
        or len(state.terminals) != 3
        or any(
            type(terminal) is not _ProfileValidationTerminal
            for terminal in state.terminals
        )
    ):
        raise TypeError("Profile validation barrier ownership changed.")
    basis_state = _bound_profile_validation_schedule_basis(receipt_state.basis)
    if (
        _bound_profile_fit_schedule_receipt(state.fit_receipt) is not receipt_state
        or receipt_state.invoker is not state.invoker
        or basis_state.group is not state.group
        or basis_state.group_state is not state.group_state
        or basis_state.invoker is not state.invoker
        or tuple(terminal.ordinal for terminal in state.terminals) != (0, 1, 2)
        or any(
            row.validation_evidence
            is not state.terminals[row.candidate_ordinal].evidence
            for row in receipt_state.rows
        )
    ):
        raise TypeError("Profile validation barrier fit receipt ownership changed.")
    _PROFILE_VALIDATION_BARRIER_STATES.require(value, state)
    return state


def _read_profile_validation_barrier(
    value: object,
) -> _ProfileValidationBarrierState:
    state = _bound_profile_validation_barrier(value)
    receipt_state = _require_profile_fit_schedule_receipt(state.fit_receipt)
    return _validate_profile_validation_barrier_state(
        cast(ProfileValidationBarrier, value),
        state,
        receipt_state,
    )


def _validate_profile_validation_session_state(
    value: ProfileValidationSession,
    state: _ProfileValidationSessionState,
    *,
    publication_status: str,
) -> None:
    if (
        type(state) is not _ProfileValidationSessionState
        or type(state.publication) is not _ProfileValidationPublication
        or state.publication_token is not state.publication.token
        or type(state.group) is not ProfilePreparedCandidateGroup
        or type(state.invoker) is not WorkerInvoker
        or type(state.schedule_basis) is not _ProfileValidationScheduleBasis
        or type(state.authorizations) is not tuple
        or len(state.authorizations) != 3
    ):
        raise TypeError("Profile validation session storage is invalid.")
    with state.publication.lock:
        published = (
            None if state.publication.session_ref is None else state.publication.session_ref()
        )
        if state.publication.status != publication_status or published is not value:
            raise TypeError("Profile validation session publication changed.")
    basis = _require_profile_validation_schedule_basis(
        state.schedule_basis,
        group=state.group,
        group_state=state.group_state,
        invoker=state.invoker,
    )
    basis_state = _bound_profile_validation_schedule_basis(basis)
    if state.barrier is None:
        for ordinal, authorization in enumerate(state.authorizations):
            authorization_state = _read_profile_validation_invocation_authorization(
                authorization
            )
            candidate_basis = basis.candidates[ordinal]
            if (
                authorization_state.group is not state.group
                or authorization_state.ordinal != ordinal
                or authorization_state.invoker is not state.invoker
                or authorization_state.candidate_authorization
                is not candidate_basis.candidate_authorization
                or authorization_state.candidate_state is not candidate_basis.candidate_state
                or authorization_state.schedule_basis is not basis
                or authorization_state.schedule_basis_token is not basis_state.token
                or authorization_state.one_use.consumed is not True
            ):
                raise TypeError("Profile validation invocation authority changed.")
        terminals = _require_sealed_profile_terminal_tuple(
            state.terminals,
            basis=basis,
        )
        if terminals is not state.terminals:
            raise TypeError("Profile validation terminal ownership changed.")
    else:
        terminals = _require_sealed_profile_terminal_tuple(
            state.terminals,
            basis=basis,
        )
        if terminals is not state.terminals:
            raise TypeError("Profile validation terminal ownership changed.")
        barrier_state = _read_profile_validation_barrier(state.barrier)
        if (
            barrier_state.group is not state.group
            or barrier_state.group_state is not state.group_state
            or barrier_state.invoker is not state.invoker
            or barrier_state.terminals is not state.terminals
            or _require_profile_fit_schedule_receipt(
                barrier_state.fit_receipt
            ).basis
            is not basis
        ):
            raise TypeError("Profile validation barrier is detached from its session.")
    _PROFILE_VALIDATION_SESSION_STATES.require(value, state)


def _read_profile_validation_session(
    value: object,
) -> _ProfileValidationSessionState:
    state: _ProfileValidationSessionState | None = None
    if type(value) is ProfileValidationSession:
        try:
            state = _PROFILE_VALIDATION_SESSION_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _ProfileValidationSessionState:
        raise TypeError("A genuine profile validation session is required.")
    _validate_profile_validation_session_state(
        cast(ProfileValidationSession, value),
        state,
        publication_status="PUBLISHED",
    )
    return state


def run_profile_validation_session(
    group: ProfilePreparedCandidateGroup,
) -> ProfileValidationSession:
    """Run and atomically publish exactly three serial profile validations."""

    publication = _profile_validation_publication(group)
    with publication.lock:
        existing = None if publication.session_ref is None else publication.session_ref()
        if existing is not None:
            _read_profile_validation_session(existing)
            return existing
        if publication.status != "FRESH":
            raise TypeError("The profile validation publication was already consumed.")
        publication.status = "ACTIVATING"

        try:
            (
                group_state,
                plan_projection,
            ) = _read_profile_prepared_candidate_group_boundary(group)
            invoker = _profile_validation_invoker(group_state, plan_projection)
            candidate_pairs = tuple(
                zip(
                    group_state.candidate_authorizations,
                    group_state.candidate_states,
                    strict=True,
                )
            )
            schedule_basis = _capture_profile_validation_schedule_basis(
                group=group,
                group_state=group_state,
                invoker=invoker,
                plan_projection=plan_projection,
                candidate_pairs=candidate_pairs,
            )
            authorizations = _issue_profile_validation_invocation_authorizations(
                group,
                invoker,
                schedule_basis=schedule_basis,
                schedule_basis_token=schedule_basis.token,
                expected_candidates=tuple(
                    (
                        row.candidate_authorization,
                        row.candidate_state,
                    )
                    for row in schedule_basis.candidates
                ),
            )
            terminal_rows: list[_ProfileValidationTerminal] = []
            for ordinal, authorization in enumerate(authorizations):
                candidate_basis = schedule_basis.candidates[ordinal]
                started_at_utc = _profile_utc_now()
                started_monotonic = time.monotonic()
                evidence: (
                    AuthenticatedWorkerExecutionEvidence
                    | WorkerInvocationObservation
                    | _ProfileValidationCoreFailure
                )
                try:
                    execution = invoker._invoke_profile_prepared_validate(authorization)
                except AuditError as error:
                    observation = error.invocation_observation
                    evidence = (
                        observation
                        if type(observation) is WorkerInvocationObservation
                        else _ProfileValidationCoreFailure()
                    )
                else:
                    authenticated = execution.authenticated_execution
                    evidence = (
                        authenticated
                        if type(authenticated) is AuthenticatedWorkerExecutionEvidence
                        else _ProfileValidationCoreFailure()
                    )
                terminal_rows.append(
                    _ProfileValidationTerminal(
                        ordinal=ordinal,
                        candidate_authorization=(candidate_basis.candidate_authorization),
                        candidate_state=candidate_basis.candidate_state,
                        started_at_utc=started_at_utc,
                        started_monotonic=started_monotonic,
                        evidence=evidence,
                    )
                )

            terminals = cast(
                tuple[
                    _ProfileValidationTerminal,
                    _ProfileValidationTerminal,
                    _ProfileValidationTerminal,
                ],
                tuple(terminal_rows),
            )
            terminals, successes, validation_readbacks = _validate_terminal_tuple(
                terminals,
                basis=schedule_basis,
                invoker=invoker,
            )
            barrier: ProfileValidationBarrier | None = None
            if successes == (True, True, True):
                successful_readbacks = cast(
                    tuple[
                        _AuthenticatedExecutionReadback,
                        _AuthenticatedExecutionReadback,
                        _AuthenticatedExecutionReadback,
                    ],
                    validation_readbacks,
                )
                if any(
                    type(readback) is not _AuthenticatedExecutionReadback
                    for readback in successful_readbacks
                ):
                    raise TypeError("Successful profile validation lost exact readback.")
                fit_receipt = _capture_profile_fit_schedule_receipt(
                    basis=schedule_basis,
                    invoker=invoker,
                    terminals=terminals,
                    readbacks=successful_readbacks,
                )
                barrier = object.__new__(ProfileValidationBarrier)
                barrier_state = _ProfileValidationBarrierState(
                    group=group,
                    group_state=group_state,
                    invoker=invoker,
                    terminals=terminals,
                    fit_receipt=fit_receipt,
                )
                _PROFILE_VALIDATION_BARRIER_STATE_ISSUER.bind_once(
                    barrier,
                    barrier_state,
                )
                if _read_profile_validation_barrier(barrier) is not barrier_state:
                    raise TypeError("Profile validation barrier issuance failed.")

            session = object.__new__(ProfileValidationSession)
            session_state = _ProfileValidationSessionState(
                publication=publication,
                publication_token=publication.token,
                group=group,
                group_state=group_state,
                invoker=invoker,
                schedule_basis=schedule_basis,
                authorizations=authorizations,
                terminals=terminals,
                barrier=barrier,
            )
            session_reference = ref(session)
            publication.session_ref = session_reference
            _PROFILE_VALIDATION_SESSION_STATE_ISSUER.bind_once(session, session_state)
            _validate_profile_validation_session_state(
                session,
                session_state,
                publication_status="ACTIVATING",
            )
            publication.session_ref = session_reference
            publication.status = "PUBLISHED"
            _read_profile_validation_session(session)
        except BaseException:
            publication.session_ref = None
            publication.status = "CONSUMED"
            raise

        return session


__all__ = [
    "ProfileValidationBarrier",
    "ProfileValidationSession",
    "run_profile_validation_session",
]
