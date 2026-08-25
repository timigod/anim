"""Exact candidate-execution disposition from sealed result evidence."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from threading import RLock
from typing import TYPE_CHECKING, Any, Literal, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    CallbackFreeWeakIdentityMap,
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.errors import ExitCode, InvalidInputError
from ebm_audit.protocol import canonical_json_bytes, exact_file_sha256, strict_json_loads
from ebm_audit.schema import SchemaValidationError, resource_bytes, validate_instance

if TYPE_CHECKING:
    from ebm_audit.results.persistence import SealedResultEvidenceSet

LifecycleState = Literal["COMPLETE", "PARTIAL", "FAILED", "PRIVACY_FAILED"]
PrimaryFailureClass = Literal[
    "INVALID_INPUT_OR_SPECIFICATION",
    "WORKER_OR_CAPABILITY_UNAVAILABLE",
    "BACKEND_OR_PROTOCOL_FAILURE",
]

_TERMINAL_STATUS_KEYS = (
    "CONVERGENCE_WARN",
    "INVALID_INPUT",
    "UNSUPPORTED_CAPABILITY",
    "INVALID_SPECIFICATION",
    "BACKEND_ERROR",
    "TIMEOUT",
    "CONVERGENCE_FAILED",
    "CONVERGENCE_NOT_ASSESSABLE",
    "PRIVACY_VIOLATION",
    "PROTOCOL_ERROR",
)
_FAILURE_PRECEDENCE: tuple[PrimaryFailureClass, ...] = (
    "BACKEND_OR_PROTOCOL_FAILURE",
    "WORKER_OR_CAPABILITY_UNAVAILABLE",
    "INVALID_INPUT_OR_SPECIFICATION",
)
_INPUT_FIELDS = (
    "requested_candidate_count",
    "terminal_record_count",
    "success_count",
    "non_success_terminal_count",
    "privacy_failure_count",
    "terminal_status_counts",
)
_FAILURE_STATUS_CLASSES: Mapping[PrimaryFailureClass, tuple[str, ...]] = {
    "BACKEND_OR_PROTOCOL_FAILURE": (
        "BACKEND_ERROR",
        "TIMEOUT",
        "CONVERGENCE_FAILED",
        "CONVERGENCE_NOT_ASSESSABLE",
        "CONVERGENCE_WARN",
        "PROTOCOL_ERROR",
    ),
    "WORKER_OR_CAPABILITY_UNAVAILABLE": ("UNSUPPORTED_CAPABILITY",),
    "INVALID_INPUT_OR_SPECIFICATION": (
        "INVALID_INPUT",
        "INVALID_SPECIFICATION",
    ),
}
_LIFECYCLE_REGISTRY_SHA256 = (
    "sha256:1edd2911f3fcef490eb300b82382ab792388220f915c1f82eb4da4c57af2dccf"
)
_PLAN_CANDIDATE_AUTHORIZATION_ISSUER = object()
_CANDIDATE_TERMINAL_AUTHORIZATION_ISSUER = object()


@dataclass(frozen=True, repr=False)
class _PlanCandidateAuthorizationState:
    plan_digest: str
    baseline_analysis_spec_id: str
    baseline_candidate_ordinal: int
    max_parallel_workers: int
    canonical_candidates_bytes: bytes
    preparation_publication_token: object


def _reject_plan_authorization_copy() -> Never:
    raise TypeError("Plan candidate authorizations cannot be copied or serialized.")


@final
class PlanCandidateAuthorization:
    """Opaque proof of the exact ordered candidate projection of one Plan/3."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("PlanCandidateAuthorization cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Plan candidate authorization comes from PlanningAuthority only.")

    def _state(self) -> _PlanCandidateAuthorizationState:
        try:
            state = _PLAN_CANDIDATE_AUTHORIZATION_STATES[self]
        except (KeyError, TypeError):
            raise TypeError("A genuine Plan/3 candidate authorization is required.") from None
        if type(state) is not _PlanCandidateAuthorizationState:
            raise TypeError("A genuine Plan/3 candidate authorization is required.")
        return state

    @property
    def plan_digest(self) -> str:
        return self._state().plan_digest

    @property
    def requested_candidate_count(self) -> int:
        return len(_plan_candidate_rows(self))

    @property
    def baseline_analysis_spec_id(self) -> str:
        return self._state().baseline_analysis_spec_id

    @property
    def baseline_candidate_ordinal(self) -> int:
        return self._state().baseline_candidate_ordinal

    @property
    def max_parallel_workers(self) -> int:
        return self._state().max_parallel_workers

    def __repr__(self) -> str:
        state = self._state()
        return (
            "PlanCandidateAuthorization("
            f"requested_candidate_count={len(_plan_candidate_rows(self))}, "
            f"plan_digest={state.plan_digest!r})"
        )

    def __copy__(self) -> PlanCandidateAuthorization:
        _reject_plan_authorization_copy()

    def __deepcopy__(self, _memo: object) -> PlanCandidateAuthorization:
        _reject_plan_authorization_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_plan_authorization_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_plan_authorization_copy()

    def __getstate__(self) -> object:
        _reject_plan_authorization_copy()


_PLAN_CANDIDATE_AUTHORIZATION_STATES: OneShotWeakRegistry[
    PlanCandidateAuthorization, _PlanCandidateAuthorizationState
]
_PLAN_CANDIDATE_AUTHORIZATION_STATE_ISSUER: OneShotRegistryIssuer[
    PlanCandidateAuthorization, _PlanCandidateAuthorizationState
]
(
    _PLAN_CANDIDATE_AUTHORIZATION_STATES,
    _PLAN_CANDIDATE_AUTHORIZATION_STATE_ISSUER,
) = create_one_shot_registry()


def _issue_plan_candidate_authorization(
    issuer: object,
    *,
    plan_digest: object,
    baseline_analysis_spec_id: object,
    max_parallel_workers: object,
    candidates: object,
    preparation_publication_token: object,
) -> PlanCandidateAuthorization:
    if issuer is not _PLAN_CANDIDATE_AUTHORIZATION_ISSUER:
        raise TypeError("Plan candidate authorization has no public mapping issuer.")
    if (
        type(plan_digest) is not str
        or type(baseline_analysis_spec_id) is not str
        or type(max_parallel_workers) is not int
        or max_parallel_workers <= 0
        or type(candidates) is not tuple
        or preparation_publication_token is None
    ):
        raise TypeError("Plan candidate authorization requires one closed Plan/3 projection.")
    try:
        validate_instance(plan_digest, "canonical-records.schema.json", definition="Sha256Digest")
        rows = cast(tuple[object, ...], candidates)
        normalized: list[dict[str, Any]] = []
        for ordinal, row in enumerate(rows):
            if type(row) is not dict:
                raise TypeError
            candidate = cast(dict[str, Any], row)
            validate_instance(candidate, "run-artifacts.schema.json", definition="PlannedCandidate")
            if (
                candidate["candidate_ordinal"] != ordinal
                or candidate["candidate_id"] != candidate["analysis_spec_id"]
            ):
                raise TypeError
            normalized.append(dict(candidate))
        candidate_ids = [row["candidate_id"] for row in normalized]
        analysis_spec_ids = [row["analysis_spec_id"] for row in normalized]
        if (
            len(candidate_ids) != len(set(candidate_ids))
            or analysis_spec_ids.count(baseline_analysis_spec_id) != 1
        ):
            raise TypeError
        baseline_candidate_ordinal = analysis_spec_ids.index(baseline_analysis_spec_id)
    except (SchemaValidationError, KeyError, TypeError):
        raise TypeError(
            "Plan candidate authorization requires one closed Plan/3 projection."
        ) from None
    self = object.__new__(PlanCandidateAuthorization)
    _PLAN_CANDIDATE_AUTHORIZATION_STATE_ISSUER.bind_once(
        self,
        _PlanCandidateAuthorizationState(
            plan_digest=plan_digest,
            baseline_analysis_spec_id=baseline_analysis_spec_id,
            baseline_candidate_ordinal=baseline_candidate_ordinal,
            max_parallel_workers=max_parallel_workers,
            canonical_candidates_bytes=canonical_json_bytes(normalized),
            preparation_publication_token=preparation_publication_token,
        ),
    )
    _read_plan_candidate_authorization(self)
    return self


def authorize_plan_candidates(planning_authority: object) -> PlanCandidateAuthorization:
    """Project exact candidate order only from a genuine PlanningAuthority."""

    from ebm_audit.universe.planning import PlanningAuthority, compile_analysis_plan

    if type(planning_authority) is not PlanningAuthority:
        raise TypeError("A genuine PlanningAuthority is required.")
    publication_token = planning_authority._state().preparation_publication_token
    if publication_token is None:
        raise TypeError("PlanningAuthority lacks preparation publication ownership.")
    plan = compile_analysis_plan(planning_authority)
    rows = tuple(
        {
            "candidate_ordinal": row["candidate_ordinal"],
            "candidate_id": row["candidate_id"],
            "analysis_spec_id": row["analysis_spec_id"],
        }
        for row in cast(list[Mapping[str, Any]], plan["candidates"])
    )
    return _issue_plan_candidate_authorization(
        _PLAN_CANDIDATE_AUTHORIZATION_ISSUER,
        plan_digest=plan["plan_digest"],
        baseline_analysis_spec_id=plan["baseline_analysis_spec_id"],
        max_parallel_workers=plan["budget_decision"]["max_parallel_workers"],
        candidates=rows,
        preparation_publication_token=publication_token,
    )


def _read_plan_candidate_authorization(value: object) -> _PlanCandidateAuthorizationState:
    if type(value) is not PlanCandidateAuthorization:
        raise TypeError("A genuine Plan/3 candidate authorization is required.")
    state = value._state()
    return _require_plan_candidate_authorization_state(value, state)


def _require_plan_candidate_authorization_state(
    value: object,
    state: object,
) -> _PlanCandidateAuthorizationState:
    """Require one already-captured Plan/3 state to remain the live exact state."""

    if (
        type(value) is not PlanCandidateAuthorization
        or type(state) is not _PlanCandidateAuthorizationState
    ):
        raise TypeError("A genuine Plan/3 candidate authorization is required.")
    try:
        _PLAN_CANDIDATE_AUTHORIZATION_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError("A genuine Plan/3 candidate authorization is required.") from None
    return state


def _plan_candidate_preparation_publication_token(value: object) -> object:
    """Return the exact preparation-publication owner of a projected Plan/3."""

    state = _read_plan_candidate_authorization(value)
    try:
        return state.preparation_publication_token
    finally:
        _require_plan_candidate_authorization_state(value, state)


def _plan_candidate_rows_from_state(
    state: _PlanCandidateAuthorizationState,
) -> tuple[dict[str, Any], ...]:
    """Decode one retained immutable Plan/3 state without resolving a sibling state."""

    if type(state) is not _PlanCandidateAuthorizationState:
        raise TypeError("Plan candidate authorization storage is invalid.")
    decoded = strict_json_loads(state.canonical_candidates_bytes)
    if (
        type(decoded) is not list
        or canonical_json_bytes(decoded) != state.canonical_candidates_bytes
    ):
        raise TypeError("Plan candidate authorization storage is invalid.")
    rows = tuple(dict(cast(Mapping[str, Any], row)) for row in decoded)
    try:
        baseline = rows[state.baseline_candidate_ordinal]
    except (IndexError, TypeError):
        raise TypeError("Plan candidate authorization storage is invalid.") from None
    if (
        type(state.baseline_analysis_spec_id) is not str
        or type(state.baseline_candidate_ordinal) is not int
        or baseline["candidate_ordinal"] != state.baseline_candidate_ordinal
        or baseline["analysis_spec_id"] != state.baseline_analysis_spec_id
        or sum(row["analysis_spec_id"] == state.baseline_analysis_spec_id for row in rows) != 1
    ):
        raise TypeError("Plan candidate authorization storage is invalid.")
    return rows


def _plan_candidate_rows(value: object) -> tuple[dict[str, Any], ...]:
    state = _read_plan_candidate_authorization(value)
    try:
        return _plan_candidate_rows_from_state(state)
    finally:
        _require_plan_candidate_authorization_state(value, state)


def _plan_baseline_candidate_row_from_state(
    state: _PlanCandidateAuthorizationState,
) -> dict[str, Any]:
    rows = _plan_candidate_rows_from_state(state)
    try:
        baseline = rows[state.baseline_candidate_ordinal]
    except IndexError:
        raise TypeError("Plan candidate authorization baseline storage is invalid.") from None
    if baseline["analysis_spec_id"] != state.baseline_analysis_spec_id:
        raise TypeError("Plan candidate authorization baseline storage is invalid.")
    return dict(baseline)


def _plan_baseline_candidate_row(value: object) -> dict[str, Any]:
    state = _read_plan_candidate_authorization(value)
    try:
        return _plan_baseline_candidate_row_from_state(state)
    finally:
        _require_plan_candidate_authorization_state(value, state)


@dataclass(repr=False)
class _CandidateTerminalAuthorizationState:
    plan_candidate_authorization: PlanCandidateAuthorization
    terminal_entries: list[tuple[bytes, object, Callable[[object], None]]]
    lock: RLock


@final
class CandidateTerminalAuthorization:
    """Opaque append authority over result-persisted candidate terminals."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("CandidateTerminalAuthorization cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Candidate terminal authorization comes from result persistence only.")

    def _state(self) -> _CandidateTerminalAuthorizationState:
        try:
            state = _CANDIDATE_TERMINAL_AUTHORIZATION_STATES[self]
        except (KeyError, TypeError):
            raise TypeError(
                "A genuine persisted candidate-terminal authorization is required."
            ) from None
        if type(state) is not _CandidateTerminalAuthorizationState:
            raise TypeError("A genuine persisted candidate-terminal authorization is required.")
        return state

    @property
    def terminal_count(self) -> int:
        return len(_candidate_terminal_rows(self))

    def __repr__(self) -> str:
        return (
            f"CandidateTerminalAuthorization(terminal_count={len(_candidate_terminal_rows(self))})"
        )

    def __copy__(self) -> CandidateTerminalAuthorization:
        _reject_plan_authorization_copy()

    def __deepcopy__(self, _memo: object) -> CandidateTerminalAuthorization:
        _reject_plan_authorization_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_plan_authorization_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_plan_authorization_copy()

    def __getstate__(self) -> object:
        _reject_plan_authorization_copy()


_CANDIDATE_TERMINAL_AUTHORIZATION_STATES: OneShotWeakRegistry[
    CandidateTerminalAuthorization, _CandidateTerminalAuthorizationState
]
_CANDIDATE_TERMINAL_AUTHORIZATION_STATE_ISSUER: OneShotRegistryIssuer[
    CandidateTerminalAuthorization, _CandidateTerminalAuthorizationState
]
(
    _CANDIDATE_TERMINAL_AUTHORIZATION_STATES,
    _CANDIDATE_TERMINAL_AUTHORIZATION_STATE_ISSUER,
) = create_one_shot_registry()


def _issue_candidate_terminal_authorization(
    issuer: object,
    *,
    plan_candidate_authorization: object,
) -> CandidateTerminalAuthorization:
    if issuer is not _CANDIDATE_TERMINAL_AUTHORIZATION_ISSUER:
        raise TypeError("Candidate terminal authorization has no public mapping issuer.")
    _read_plan_candidate_authorization(plan_candidate_authorization)
    self = object.__new__(CandidateTerminalAuthorization)
    _CANDIDATE_TERMINAL_AUTHORIZATION_STATE_ISSUER.bind_once(
        self,
        _CandidateTerminalAuthorizationState(
            plan_candidate_authorization=cast(
                PlanCandidateAuthorization,
                plan_candidate_authorization,
            ),
            terminal_entries=[],
            lock=RLock(),
        ),
    )
    _read_candidate_terminal_authorization(self)
    return self


def _read_candidate_terminal_authorization(
    value: object,
) -> _CandidateTerminalAuthorizationState:
    if type(value) is not CandidateTerminalAuthorization:
        raise TypeError("A genuine persisted candidate-terminal authorization is required.")
    state = value._state()
    return _require_candidate_terminal_authorization_state(value, state)


def _require_candidate_terminal_authorization_state(
    value: object,
    state: object,
) -> _CandidateTerminalAuthorizationState:
    """Require one captured terminal state to remain the live exact state."""

    if (
        type(value) is not CandidateTerminalAuthorization
        or type(state) is not _CandidateTerminalAuthorizationState
    ):
        raise TypeError("A genuine persisted candidate-terminal authorization is required.")
    try:
        _CANDIDATE_TERMINAL_AUTHORIZATION_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError(
            "A genuine persisted candidate-terminal authorization is required."
        ) from None
    return state


def _candidate_terminal_rows_from_state(
    state: _CandidateTerminalAuthorizationState,
) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for canonical, persisted_owner, persisted_owner_validator in state.terminal_entries:
        persisted_owner_validator(persisted_owner)
        decoded = strict_json_loads(canonical)
        if (
            type(decoded) is not dict
            or canonical_json_bytes(decoded) != canonical
            or persisted_owner is None
        ):
            raise TypeError("Candidate terminal authorization storage is invalid.")
        rows.append(dict(decoded))
    return tuple(rows)


def _candidate_terminal_projection_from_prevalidated_state(
    value: object,
    state: _CandidateTerminalAuthorizationState,
) -> tuple[tuple[dict[str, Any], ...], tuple[object, ...]]:
    """Project exact entries after their outer boundary validated every owner."""

    with state.lock:
        _require_candidate_terminal_authorization_state(value, state)
        try:
            rows: list[dict[str, Any]] = []
            owners: list[object] = []
            for canonical, persisted_owner, _persisted_owner_validator in state.terminal_entries:
                decoded = strict_json_loads(canonical)
                if (
                    type(decoded) is not dict
                    or canonical_json_bytes(decoded) != canonical
                    or persisted_owner is None
                ):
                    raise TypeError("Candidate terminal authorization storage is invalid.")
                rows.append(dict(decoded))
                owners.append(persisted_owner)
            return tuple(rows), tuple(owners)
        finally:
            _require_candidate_terminal_authorization_state(value, state)


def _candidate_terminal_rows(value: object) -> tuple[dict[str, Any], ...]:
    state = _read_candidate_terminal_authorization(value)
    return _candidate_terminal_rows_with_state(value, state)


def _candidate_terminal_rows_with_state(
    value: object,
    state: _CandidateTerminalAuthorizationState,
) -> tuple[dict[str, Any], ...]:
    """Read terminals from one exact captured state under its own lock."""

    with state.lock:
        _require_candidate_terminal_authorization_state(value, state)
        try:
            return _candidate_terminal_rows_from_state(state)
        finally:
            _require_candidate_terminal_authorization_state(value, state)


def _candidate_terminal_persisted_owners(value: object) -> tuple[object, ...]:
    state = _read_candidate_terminal_authorization(value)
    return _candidate_terminal_persisted_owners_with_state(value, state)


def _candidate_terminal_persisted_owners_with_state(
    value: object,
    state: _CandidateTerminalAuthorizationState,
) -> tuple[object, ...]:
    """Read persisted owners from one exact captured state under its own lock."""

    with state.lock:
        _require_candidate_terminal_authorization_state(value, state)
        try:
            _candidate_terminal_rows_from_state(state)
            return tuple(
                persisted_owner
                for _canonical, persisted_owner, _validator in state.terminal_entries
            )
        finally:
            _require_candidate_terminal_authorization_state(value, state)


def _append_candidate_terminal_authorization(
    issuer: object,
    authorization: object,
    *,
    terminal: object,
    persisted_owner: object,
    persisted_owner_validator: object,
    persisted_owner_prevalidated_validator: object | None = None,
) -> None:
    state = _read_candidate_terminal_authorization(authorization)
    plan_state = _read_plan_candidate_authorization(state.plan_candidate_authorization)
    _append_candidate_terminal_authorization_with_state(
        issuer,
        authorization,
        state,
        plan_candidate_authorization_state=plan_state,
        terminal=terminal,
        persisted_owner=persisted_owner,
        persisted_owner_validator=persisted_owner_validator,
        persisted_owner_prevalidated_validator=(persisted_owner_prevalidated_validator),
    )


def _append_candidate_terminal_authorization_with_state(
    issuer: object,
    authorization: object,
    state: _CandidateTerminalAuthorizationState,
    *,
    plan_candidate_authorization_state: _PlanCandidateAuthorizationState,
    terminal: object,
    persisted_owner: object,
    persisted_owner_validator: object,
    persisted_owner_prevalidated_validator: object | None = None,
) -> None:
    """Append through exact retained terminal and Plan/3 states only."""

    if issuer is not _CANDIDATE_TERMINAL_AUTHORIZATION_ISSUER:
        raise TypeError("Candidate terminal authorization has no public mapping issuer.")
    with state.lock:
        _require_candidate_terminal_authorization_state(authorization, state)
        _require_plan_candidate_authorization_state(
            state.plan_candidate_authorization,
            plan_candidate_authorization_state,
        )
        try:
            if (
                type(terminal) is not dict
                or persisted_owner is None
                or not callable(persisted_owner_validator)
                or (
                    persisted_owner_prevalidated_validator is not None
                    and not callable(persisted_owner_prevalidated_validator)
                )
            ):
                raise TypeError(
                    "Candidate terminal append requires exact persisted-result authority."
                )
            candidate_terminal = cast(dict[str, Any], terminal)
            try:
                validate_instance(
                    candidate_terminal,
                    "run-artifacts.schema.json",
                    definition="CandidateTerminal",
                )
            except SchemaValidationError:
                raise TypeError(
                    "Candidate terminal append requires exact persisted-result authority."
                ) from None
            owner_validator = cast(Callable[[object], None], persisted_owner_validator)
            immediate_owner_validator = cast(
                Callable[[object], None],
                (
                    owner_validator
                    if persisted_owner_prevalidated_validator is None
                    else persisted_owner_prevalidated_validator
                ),
            )
            immediate_owner_validator(persisted_owner)
            planned = _plan_candidate_rows_from_state(plan_candidate_authorization_state)
            ordinal = len(state.terminal_entries)
            if ordinal >= len(planned) or (
                candidate_terminal["candidate_ordinal"],
                candidate_terminal["candidate_id"],
                candidate_terminal["analysis_spec_id"],
            ) != (
                planned[ordinal]["candidate_ordinal"],
                planned[ordinal]["candidate_id"],
                planned[ordinal]["analysis_spec_id"],
            ):
                raise TypeError("Candidate terminal append is not the exact Plan/3 prefix.")
            _require_candidate_terminal_authorization_state(authorization, state)
            _require_plan_candidate_authorization_state(
                state.plan_candidate_authorization,
                plan_candidate_authorization_state,
            )
            state.terminal_entries.append(
                (
                    canonical_json_bytes(candidate_terminal),
                    persisted_owner,
                    owner_validator,
                )
            )
        finally:
            _require_candidate_terminal_authorization_state(authorization, state)
            _require_plan_candidate_authorization_state(
                state.plan_candidate_authorization,
                plan_candidate_authorization_state,
            )


class LifecycleInputError(ValueError):
    """Raised when exact candidate-execution evidence violates the closed registry."""


@dataclass(frozen=True, repr=False)
class _CandidateExecutionDispositionState:
    sealed_result_evidence_set: SealedResultEvidenceSet
    requested_candidate_count: int
    terminal_record_count: int
    success_count: int
    non_success_terminal_count: int
    privacy_failure_count: int
    terminal_status_counts: tuple[tuple[str, int], ...]
    state: LifecycleState
    exit_code: ExitCode
    primary_failure_class: PrimaryFailureClass | None


_CANDIDATE_EXECUTION_DISPOSITION_LOCK = RLock()


def _reject_candidate_execution_disposition_copy() -> Never:
    raise TypeError("Sealed candidate-execution dispositions cannot be copied or serialized.")


@final
class SealedCandidateExecutionDisposition:
    """Opaque execution classification owned by one exact sealed result set."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("SealedCandidateExecutionDisposition cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "Candidate-execution dispositions come from exact sealed result evidence only."
        )

    @property
    def state(self) -> LifecycleState:
        return _read_candidate_execution_disposition(self).state

    @property
    def exit_code(self) -> ExitCode:
        return _read_candidate_execution_disposition(self).exit_code

    @property
    def primary_failure_class(self) -> PrimaryFailureClass | None:
        return _read_candidate_execution_disposition(self).primary_failure_class

    @property
    def requested_candidate_count(self) -> int:
        return _read_candidate_execution_disposition(self).requested_candidate_count

    @property
    def terminal_record_count(self) -> int:
        return _read_candidate_execution_disposition(self).terminal_record_count

    @property
    def success_count(self) -> int:
        return _read_candidate_execution_disposition(self).success_count

    @property
    def non_success_terminal_count(self) -> int:
        return _read_candidate_execution_disposition(self).non_success_terminal_count

    @property
    def privacy_failure_count(self) -> int:
        return _read_candidate_execution_disposition(self).privacy_failure_count

    @property
    def terminal_status_counts(self) -> Mapping[str, int]:
        state = _read_candidate_execution_disposition(self)
        return dict(state.terminal_status_counts)

    def __repr__(self) -> str:
        state = _read_candidate_execution_disposition(self)
        return (
            "SealedCandidateExecutionDisposition("
            f"state={state.state!r}, "
            f"requested_candidate_count={state.requested_candidate_count}, "
            f"terminal_record_count={state.terminal_record_count})"
        )

    def __copy__(self) -> SealedCandidateExecutionDisposition:
        _reject_candidate_execution_disposition_copy()

    def __deepcopy__(self, _memo: object) -> SealedCandidateExecutionDisposition:
        _reject_candidate_execution_disposition_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_candidate_execution_disposition_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_candidate_execution_disposition_copy()

    def __getstate__(self) -> object:
        _reject_candidate_execution_disposition_copy()


_CANDIDATE_EXECUTION_DISPOSITION_STATES: OneShotWeakRegistry[
    SealedCandidateExecutionDisposition,
    _CandidateExecutionDispositionState,
]
_CANDIDATE_EXECUTION_DISPOSITION_STATE_ISSUER: OneShotRegistryIssuer[
    SealedCandidateExecutionDisposition,
    _CandidateExecutionDispositionState,
]
(
    _CANDIDATE_EXECUTION_DISPOSITION_STATES,
    _CANDIDATE_EXECUTION_DISPOSITION_STATE_ISSUER,
) = create_one_shot_registry()
_CANDIDATE_EXECUTION_DISPOSITIONS_BY_EVIDENCE: CallbackFreeWeakIdentityMap[
    SealedResultEvidenceSet,
    SealedCandidateExecutionDisposition,
] = CallbackFreeWeakIdentityMap(_CANDIDATE_EXECUTION_DISPOSITION_LOCK)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate object key")
        value[key] = item
    return value


def _reject_non_json_constant(value: str) -> Any:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _decode_registry_bytes(data: bytes) -> Mapping[str, Any]:
    if data.startswith(b"\xef\xbb\xbf"):
        raise LifecycleInputError("The CLI lifecycle registry is invalid.")
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise LifecycleInputError("The CLI lifecycle registry is invalid.") from exc
    if not isinstance(value, Mapping):
        raise LifecycleInputError("The CLI lifecycle registry is invalid.")
    return value


@lru_cache(maxsize=2)
def verify_lifecycle_registry(registry_bytes: bytes | None = None) -> None:
    """Prove the packaged normative vocabulary agrees with this evaluator."""

    exact_bytes = (
        resource_bytes("cli-lifecycle-registry.json") if registry_bytes is None else registry_bytes
    )
    if exact_file_sha256(exact_bytes) != _LIFECYCLE_REGISTRY_SHA256:
        raise LifecycleInputError(
            "The packaged CLI lifecycle registry has unreviewed semantic drift."
        )
    value = _decode_registry_bytes(exact_bytes)
    contract = value.get("input_contract")
    states = value.get("terminal_state_precedence")
    run_artifact_rules = value.get("run_artifact_invariant_registry")
    if (
        not isinstance(contract, Mapping)
        or not isinstance(states, list)
        or len(states) != 4
        or any(not isinstance(row, Mapping) for row in states)
        or not isinstance(run_artifact_rules, list)
        or len(run_artifact_rules) != 8
        or any(not isinstance(row, Mapping) for row in run_artifact_rules)
    ):
        raise LifecycleInputError("The CLI lifecycle registry is invalid.")
    state_maps = tuple(row for row in states if isinstance(row, Mapping))
    failure_exits = state_maps[1].get("exit_code_by_derived_primary_failure_class")
    expected_state_rows: tuple[tuple[str, int | None], ...] = (
        ("PRIVACY_FAILED", 14),
        ("FAILED", None),
        ("PARTIAL", 12),
        ("COMPLETE", 0),
    )
    try:
        state_rows = tuple((row["state"], row.get("exit_code")) for row in state_maps)
        valid = (
            value["registry_schema_version"] == "ebm-audit-cli-lifecycle/4.0"
            and tuple(value["input_fields"]) == _INPUT_FIELDS
            and tuple(contract["terminal_status_count_keys"]) == _TERMINAL_STATUS_KEYS
            and contract["authority"] == "exact_current_sealed_result_evidence_set"
            and contract["complete_terminal_coverage_required"] is True
            and contract["baseline_assessment_is_execution_input"] is False
            and tuple(contract["prohibited_caller_fields"])
            == (
                "unexpected_core_error_count",
                "mandatory_gate_failure_counts",
                "baseline_assessment_id",
                "baseline_assessment_status",
                "status",
            )
            and tuple(value["primary_failure_class_precedence"]) == _FAILURE_PRECEDENCE
            and state_rows == expected_state_rows
            and failure_exits
            == {
                "INVALID_INPUT_OR_SPECIFICATION": 10,
                "WORKER_OR_CAPABILITY_UNAVAILABLE": 11,
                "BACKEND_OR_PROTOCOL_FAILURE": 15,
            }
        )
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise LifecycleInputError(
            "The packaged CLI lifecycle registry does not match the product evaluator."
        )


def _failed_primary_class(statuses: Mapping[str, int]) -> PrimaryFailureClass:
    for failure_class in _FAILURE_PRECEDENCE:
        if any(statuses[status] > 0 for status in _FAILURE_STATUS_CLASSES[failure_class]):
            return failure_class
    raise LifecycleInputError(
        "A failed candidate execution has no registered terminal failure class."
    )


def _derive_candidate_execution_state(
    sealed_result_evidence_set: object,
) -> _CandidateExecutionDispositionState:
    verify_lifecycle_registry()
    try:
        from ebm_audit.results.persistence import (
            SealedResultEvidenceSet,
            _sealed_result_evidence_run,
        )

        if type(sealed_result_evidence_set) is not SealedResultEvidenceSet:
            raise TypeError
        run = _sealed_result_evidence_run(sealed_result_evidence_set)
    except (InvalidInputError, TypeError):
        raise LifecycleInputError(
            "The exact current sealed result-evidence set is required."
        ) from None

    requested = len(run.candidate_result_authorizations)
    terminal = len(run.candidate_terminals)
    if requested <= 0 or terminal != requested:
        raise LifecycleInputError(
            "Candidate-execution disposition requires exact complete terminal coverage."
        )

    statuses = {status: 0 for status in _TERMINAL_STATUS_KEYS}
    success = 0
    try:
        for terminal_row in run.candidate_terminals:
            final_status = terminal_row["final_status"]
            if final_status == "SUCCESS":
                success += 1
            elif type(final_status) is str and final_status in statuses:
                statuses[final_status] += 1
            else:
                raise TypeError
    except (KeyError, TypeError):
        raise LifecycleInputError(
            "The exact current candidate terminals have an invalid status."
        ) from None

    non_success = terminal - success
    if sum(statuses.values()) != non_success:
        raise LifecycleInputError("The exact current candidate terminal counts are inconsistent.")
    privacy = statuses["PRIVACY_VIOLATION"]

    state: LifecycleState
    exit_code: ExitCode
    primary: PrimaryFailureClass | None
    if privacy > 0:
        state = "PRIVACY_FAILED"
        exit_code = ExitCode.PRIVACY_FAILED
        primary = None
    elif success == 0:
        state = "FAILED"
        primary = _failed_primary_class(statuses)
        exit_code = ExitCode[primary]
    elif non_success > 0:
        state = "PARTIAL"
        exit_code = ExitCode.PARTIAL
        primary = None
    else:
        state = "COMPLETE"
        exit_code = ExitCode.SUCCESS
        primary = None

    return _CandidateExecutionDispositionState(
        sealed_result_evidence_set=sealed_result_evidence_set,
        requested_candidate_count=requested,
        terminal_record_count=terminal,
        success_count=success,
        non_success_terminal_count=non_success,
        privacy_failure_count=privacy,
        terminal_status_counts=tuple(
            (status, statuses[status]) for status in _TERMINAL_STATUS_KEYS
        ),
        state=state,
        exit_code=exit_code,
        primary_failure_class=primary,
    )


def _read_candidate_execution_disposition(
    value: object,
) -> _CandidateExecutionDispositionState:
    if type(value) is not SealedCandidateExecutionDisposition:
        raise LifecycleInputError("A genuine sealed candidate-execution disposition is required.")
    try:
        retained = _CANDIDATE_EXECUTION_DISPOSITION_STATES[value]
    except (KeyError, TypeError):
        raise LifecycleInputError(
            "A genuine sealed candidate-execution disposition is required."
        ) from None
    current = _derive_candidate_execution_state(retained.sealed_result_evidence_set)
    if current != retained:
        raise LifecycleInputError(
            "The sealed candidate-execution disposition is detached from current evidence."
        )
    return retained


def _candidate_execution_disposition_evidence(
    value: object,
) -> SealedResultEvidenceSet:
    """Return the exact retained evidence set for trusted run-artifact consumers."""

    return _read_candidate_execution_disposition(value).sealed_result_evidence_set


def _candidate_execution_disposition_record(value: object) -> dict[str, object]:
    """Return deterministic safe counts from the exact execution disposition."""

    state = _read_candidate_execution_disposition(value)
    return {
        "requested_candidate_count": state.requested_candidate_count,
        "terminal_record_count": state.terminal_record_count,
        "success_count": state.success_count,
        "non_success_terminal_count": state.non_success_terminal_count,
        "privacy_failure_count": state.privacy_failure_count,
        "terminal_status_counts": dict(state.terminal_status_counts),
    }


def project_candidate_execution_disposition(
    value: SealedCandidateExecutionDisposition,
    /,
) -> dict[str, object]:
    """Return one atomic privacy-safe projection after exact revalidation."""

    state = _read_candidate_execution_disposition(value)
    return {
        "state": state.state,
        "exit_code": int(state.exit_code),
        "primary_failure_class": state.primary_failure_class,
        "requested_candidate_count": state.requested_candidate_count,
        "terminal_record_count": state.terminal_record_count,
        "success_count": state.success_count,
        "non_success_terminal_count": state.non_success_terminal_count,
        "privacy_failure_count": state.privacy_failure_count,
        "terminal_status_counts": dict(state.terminal_status_counts),
    }


def classify_candidate_execution(
    sealed_result_evidence_set: SealedResultEvidenceSet,
    /,
) -> SealedCandidateExecutionDisposition:
    """Seal one candidate-execution disposition from exact current result evidence."""

    with _CANDIDATE_EXECUTION_DISPOSITION_LOCK:
        state = _derive_candidate_execution_state(sealed_result_evidence_set)
        existing = _CANDIDATE_EXECUTION_DISPOSITIONS_BY_EVIDENCE.get(sealed_result_evidence_set)
        if existing is not None:
            retained = _read_candidate_execution_disposition(existing)
            if retained != state:
                raise LifecycleInputError(
                    "The current result evidence has a conflicting execution disposition."
                )
            return existing
        disposition = object.__new__(SealedCandidateExecutionDisposition)
        _CANDIDATE_EXECUTION_DISPOSITION_STATE_ISSUER.bind_once(disposition, state)
        _read_candidate_execution_disposition(disposition)
        _CANDIDATE_EXECUTION_DISPOSITIONS_BY_EVIDENCE.bind_once(
            sealed_result_evidence_set,
            disposition,
        )
        return disposition


__all__ = [
    "CandidateTerminalAuthorization",
    "LifecycleInputError",
    "LifecycleState",
    "PlanCandidateAuthorization",
    "PrimaryFailureClass",
    "SealedCandidateExecutionDisposition",
    "authorize_plan_candidates",
    "classify_candidate_execution",
    "project_candidate_execution_disposition",
    "verify_lifecycle_registry",
]
