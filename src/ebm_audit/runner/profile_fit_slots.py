"""Opaque, exact-order fit authorities for one validated profile coordinate."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock, RLock
from typing import Any, SupportsIndex, cast, final
from weakref import ReferenceType, ref

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.adapters import (
    AuthenticatedWorkerExecutionEvidence,
    WorkerInvocationObservation,
    WorkerInvoker,
)
from ebm_audit.adapters.invocation import (
    _PreparedCandidateExecutionContext,
    _PreparedCandidateExecutionContextState,
    _readback_authenticated_execution,
    _readback_worker_invocation_observation,
)
from ebm_audit.protocol import (
    canonical_json_bytes,
    strict_json_loads,
)
from ebm_audit.runner.profile_validation import (
    ProfileValidationBarrier,
    _bound_profile_fit_schedule_receipt,
    _bound_profile_validation_barrier,
    _ProfileFitScheduleReceipt,
    _ProfileFitScheduleReceiptRow,
    _ProfileFitScheduleReceiptState,
    _ProfileValidationBarrierState,
    _require_profile_fit_schedule_receipt,
    _validate_profile_validation_barrier_state,
)
from ebm_audit.universe.preparation import (
    _PreparedExecutionAuthorizationState,
    _ProfilePreparedCandidateGroupState,
    _read_profile_prepared_candidate_group,
)

_PROFILE_FIT_SLOT_COUNT = 9
_PROFILE_CHAIN_COUNT = 3
_PROFILE_FIT_ATTEMPT_ORDINAL = 0


def _reattest_profile_source_at_phase_boundary(
    group: object,
    expected_state: object,
) -> None:
    """Run the one full source/tree reattestation allowed at a phase boundary."""

    if (
        type(expected_state) is not _ProfilePreparedCandidateGroupState
        or _read_profile_prepared_candidate_group(group) is not expected_state
    ):
        raise TypeError("Profile source changed before phase activation.")


class _ProfileFitSlotPublication:
    """One callback-free publication cell per exact validation barrier."""

    __slots__ = ("barrier_state", "group_ref", "lock", "status", "token")

    barrier_state: _ProfileValidationBarrierState | None
    group_ref: ReferenceType[ProfileFitSlotGroup] | None
    lock: RLock
    status: str
    token: object

    def __init__(self) -> None:
        self.barrier_state = None
        self.group_ref = None
        self.lock = RLock()
        self.status = "FRESH"
        self.token = object()


class _ProfileFitSlotLedger:
    """Shared serial-dispatch state without retaining any slot capability."""

    __slots__ = ("active_position", "lock", "next_position", "token")

    active_position: int | None
    lock: RLock
    next_position: int
    token: object

    def __init__(self) -> None:
        self.active_position = None
        self.lock = RLock()
        self.next_position = 0
        self.token = object()


class _ProfileFitSlotUse:
    """Mutable terminal cell owned by one exact predeclared slot."""

    __slots__ = ("consumed", "terminal")

    consumed: bool
    terminal: (
        AuthenticatedWorkerExecutionEvidence
        | WorkerInvocationObservation
        | _ProfileFitUnobservedCoreFailure
        | None
    )

    def __init__(self) -> None:
        self.consumed = False
        self.terminal = None


_PROFILE_FIT_UNOBSERVED_CORE_FAILURE_STATE = object()
_PROFILE_FIT_UNOBSERVED_CORE_FAILURE_STATES: OneShotWeakRegistry[object, object]
_PROFILE_FIT_UNOBSERVED_CORE_FAILURE_STATE_ISSUER: OneShotRegistryIssuer[object, object]
(
    _PROFILE_FIT_UNOBSERVED_CORE_FAILURE_STATES,
    _PROFILE_FIT_UNOBSERVED_CORE_FAILURE_STATE_ISSUER,
) = create_one_shot_registry()


@final
class _ProfileFitUnobservedCoreFailure:
    """Fixed safe terminal when dispatch produced no authenticated observation."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _ProfileFitUnobservedCoreFailure:
        raise TypeError("Profile fit core-failure terminals are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile fit core-failure terminals cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile fit core-failure terminals are immutable.")

    @property
    def failure_code(self) -> str:
        _require_profile_fit_unobserved_core_failure(self)
        return "PROFILE_FIT.UNOBSERVED_CORE_FAILURE"

    def __copy__(self) -> _ProfileFitUnobservedCoreFailure:
        raise TypeError("Profile fit core-failure terminals cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> _ProfileFitUnobservedCoreFailure:
        raise TypeError("Profile fit core-failure terminals cannot be copied or serialized.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Profile fit core-failure terminals cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Profile fit core-failure terminals cannot be copied or serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Profile fit core-failure terminals cannot be copied or serialized.")


def _issue_profile_fit_unobserved_core_failure() -> _ProfileFitUnobservedCoreFailure:
    terminal = object.__new__(_ProfileFitUnobservedCoreFailure)
    _PROFILE_FIT_UNOBSERVED_CORE_FAILURE_STATE_ISSUER.bind_once(
        terminal,
        _PROFILE_FIT_UNOBSERVED_CORE_FAILURE_STATE,
    )
    _require_profile_fit_unobserved_core_failure(terminal)
    return terminal


def _require_profile_fit_unobserved_core_failure(
    value: object,
) -> _ProfileFitUnobservedCoreFailure:
    if (
        type(value) is not _ProfileFitUnobservedCoreFailure
        or _PROFILE_FIT_UNOBSERVED_CORE_FAILURE_STATES.get(value)
        is not _PROFILE_FIT_UNOBSERVED_CORE_FAILURE_STATE
    ):
        raise TypeError("A genuine profile fit core-failure terminal is required.")
    return value


@dataclass(frozen=True, repr=False)
class _ProfileFitSlotAuthorizationState:
    group_ref: ReferenceType[ProfileFitSlotGroup]
    receipt: _ProfileFitScheduleReceipt
    row_index: int
    one_use: _ProfileFitSlotUse

    def _row(self) -> _ProfileFitScheduleReceiptRow:
        return _profile_fit_slot_row(self)

    @property
    def invoker(self) -> WorkerInvoker:
        return _bound_profile_fit_schedule_receipt(self.receipt).invoker

    @property
    def runtime_position(self) -> int:
        return self._row().runtime_position

    @property
    def runtime_profile_position(self) -> int:
        return self._row().runtime_profile_position

    @property
    def profile_id(self) -> str:
        return self._row().profile_id

    @property
    def candidate_ordinal(self) -> int:
        return self._row().candidate_ordinal

    @property
    def candidate_authorization(self) -> object:
        return self._row().candidate_authorization

    @property
    def candidate_state(self) -> _PreparedExecutionAuthorizationState:
        return self._row().candidate_state

    @property
    def validation_evidence(self) -> AuthenticatedWorkerExecutionEvidence:
        return self._row().validation_evidence

    @property
    def candidate_execution_context(self) -> _PreparedCandidateExecutionContext:
        return self._row().candidate_execution_context

    @property
    def candidate_execution_context_state(
        self,
    ) -> _PreparedCandidateExecutionContextState:
        return self._row().candidate_execution_context_state

    @property
    def execution_input_projection_digest(self) -> str:
        return self._row().execution_input_projection_digest

    @property
    def chain_plan_position(self) -> int:
        return self._row().chain_plan_position

    @property
    def universe_id(self) -> str:
        return self._row().universe_id

    @property
    def chain_id(self) -> str:
        return self._row().chain_id

    @property
    def chain_execution_id(self) -> str:
        return self._row().chain_execution_id

    @property
    def attempt_id(self) -> str:
        return self._row().attempt_id

    @property
    def seed(self) -> str:
        return self._row().seed

    @property
    def attempt_ordinal(self) -> int:
        return self._row().attempt_ordinal


@dataclass(frozen=True, repr=False)
class _ProfileFitSlotGroupState:
    publication: _ProfileFitSlotPublication
    publication_token: object
    barrier: ProfileValidationBarrier
    barrier_state: _ProfileValidationBarrierState
    ledger: _ProfileFitSlotLedger
    ledger_token: object
    receipt: _ProfileFitScheduleReceipt
    receipt_state: _ProfileFitScheduleReceiptState
    slots: tuple[_ProfileFitSlotAuthorization, ...]


_PROFILE_FIT_SLOT_PUBLICATIONS: OneShotWeakRegistry[object, _ProfileFitSlotPublication]
_PROFILE_FIT_SLOT_PUBLICATION_ISSUER: OneShotRegistryIssuer[object, _ProfileFitSlotPublication]
(
    _PROFILE_FIT_SLOT_PUBLICATIONS,
    _PROFILE_FIT_SLOT_PUBLICATION_ISSUER,
) = create_one_shot_registry()
_PROFILE_FIT_SLOT_PUBLICATIONS_LOCK = Lock()

_PROFILE_FIT_SLOT_AUTHORIZATION_STATES: OneShotWeakRegistry[
    object, _ProfileFitSlotAuthorizationState
]
_PROFILE_FIT_SLOT_AUTHORIZATION_STATE_ISSUER: OneShotRegistryIssuer[
    object, _ProfileFitSlotAuthorizationState
]
(
    _PROFILE_FIT_SLOT_AUTHORIZATION_STATES,
    _PROFILE_FIT_SLOT_AUTHORIZATION_STATE_ISSUER,
) = create_one_shot_registry()

_PROFILE_FIT_SLOT_GROUP_STATES: OneShotWeakRegistry[object, _ProfileFitSlotGroupState]
_PROFILE_FIT_SLOT_GROUP_STATE_ISSUER: OneShotRegistryIssuer[object, _ProfileFitSlotGroupState]
(
    _PROFILE_FIT_SLOT_GROUP_STATES,
    _PROFILE_FIT_SLOT_GROUP_STATE_ISSUER,
) = create_one_shot_registry()


@final
class _ProfileFitSlotAuthorization:
    """Opaque one-use authority for one exact rotated profile-chain fit."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _ProfileFitSlotAuthorization:
        raise TypeError("Profile fit-slot authority is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile fit-slot authority cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile fit-slot authority is immutable.")

    def __copy__(self) -> _ProfileFitSlotAuthorization:
        raise TypeError("Profile fit-slot authority cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> _ProfileFitSlotAuthorization:
        raise TypeError("Profile fit-slot authority cannot be copied or serialized.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Profile fit-slot authority cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Profile fit-slot authority cannot be copied or serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Profile fit-slot authority cannot be copied or serialized.")


@final
class ProfileFitSlotGroup:
    """Opaque owner of exactly nine predeclared serial fit authorities."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ProfileFitSlotGroup:
        raise TypeError("Profile fit-slot groups are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile fit-slot groups cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile fit-slot groups are immutable.")

    def __copy__(self) -> ProfileFitSlotGroup:
        raise TypeError("Profile fit-slot groups cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> ProfileFitSlotGroup:
        raise TypeError("Profile fit-slot groups cannot be copied or serialized.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Profile fit-slot groups cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Profile fit-slot groups cannot be copied or serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Profile fit-slot groups cannot be copied or serialized.")

    def __repr__(self) -> str:
        _read_profile_fit_slot_group(self)
        return "ProfileFitSlotGroup(<sealed-nine-serial-fit-slots>)"


def _closed_mapping(value: bytes, *, label: str) -> dict[str, Any]:
    try:
        decoded = strict_json_loads(value)
    except (TypeError, ValueError):
        raise TypeError(f"{label} is not canonical closed JSON.") from None
    if type(decoded) is not dict or canonical_json_bytes(decoded) != value:
        raise TypeError(f"{label} is not canonical closed JSON.")
    return cast(dict[str, Any], decoded)


def _profile_fit_slot_publication(
    barrier: object,
) -> _ProfileFitSlotPublication:
    if type(barrier) is not ProfileValidationBarrier:
        raise TypeError("A genuine profile validation barrier is required.")
    with _PROFILE_FIT_SLOT_PUBLICATIONS_LOCK:
        publication = _PROFILE_FIT_SLOT_PUBLICATIONS.get(barrier)
        if publication is None:
            publication = _ProfileFitSlotPublication()
            _PROFILE_FIT_SLOT_PUBLICATION_ISSUER.bind_once(barrier, publication)
    if type(publication) is not _ProfileFitSlotPublication:
        raise TypeError("Profile fit-slot publication state is invalid.")
    with publication.lock:
        if publication.barrier_state is None:
            publication.barrier_state = _bound_profile_validation_barrier(barrier)
    return publication


def _profile_fit_slot_row(
    state: _ProfileFitSlotAuthorizationState,
) -> _ProfileFitScheduleReceiptRow:
    receipt_state = _bound_profile_fit_schedule_receipt(state.receipt)
    if (
        type(state.row_index) is not int
        or isinstance(state.row_index, bool)
        or state.row_index < 0
        or state.row_index >= len(receipt_state.rows)
    ):
        raise TypeError("Profile fit-slot receipt row is invalid.")
    return receipt_state.rows[state.row_index]


def _validate_slot_state(
    authority: _ProfileFitSlotAuthorization,
    state: _ProfileFitSlotAuthorizationState,
    group_state: _ProfileFitSlotGroupState,
    *,
    publication_status: str,
) -> None:
    group = state.group_ref() if type(state.group_ref) is ReferenceType else None
    row = _profile_fit_slot_row(state)
    if (
        type(state) is not _ProfileFitSlotAuthorizationState
        or type(state.group_ref) is not ReferenceType
        or type(state.receipt) is not _ProfileFitScheduleReceipt
        or state.receipt is not group_state.receipt
        or _bound_profile_fit_schedule_receipt(state.receipt)
        is not group_state.receipt_state
        or row is not group_state.receipt_state.rows[state.row_index]
        or row.runtime_position != state.row_index
        or type(state.one_use) is not _ProfileFitSlotUse
        or type(state.one_use.consumed) is not bool
    ):
        raise TypeError("Profile fit-slot authority storage is invalid.")
    with group_state.publication.lock:
        if (
            group_state.publication.status != publication_status
            or group_state.publication.group_ref is not state.group_ref
            or type(group) is not ProfileFitSlotGroup
        ):
            raise TypeError("Profile fit-slot authority publication changed.")

    ledger = group_state.ledger
    position = state.row_index
    with ledger.lock:
        if (
            type(ledger.next_position) is not int
            or ledger.next_position < 0
            or ledger.next_position > _PROFILE_FIT_SLOT_COUNT
            or (
                ledger.active_position is not None
                and (
                    type(ledger.active_position) is not int
                    or ledger.active_position != ledger.next_position
                    or ledger.active_position >= _PROFILE_FIT_SLOT_COUNT
                )
            )
        ):
            raise TypeError("Profile fit-slot serial ledger is invalid.")
        if position < ledger.next_position:
            expected_consumed = True
            expected_terminal = True
        elif position == ledger.next_position and ledger.active_position == position:
            expected_consumed = True
            expected_terminal = False
        else:
            expected_consumed = False
            expected_terminal = False
        if (
            state.one_use.consumed is not expected_consumed
            or (state.one_use.terminal is not None) is not expected_terminal
        ):
            raise TypeError("Profile fit-slot consumption or terminal state changed.")
        if state.one_use.terminal is not None and not (
            type(state.one_use.terminal) is AuthenticatedWorkerExecutionEvidence
            or type(state.one_use.terminal) is WorkerInvocationObservation
            or type(state.one_use.terminal) is _ProfileFitUnobservedCoreFailure
        ):
            raise TypeError("Profile fit-slot terminal storage changed.")
    _PROFILE_FIT_SLOT_AUTHORIZATION_STATES.require(authority, state)


def _bound_profile_fit_slot_authorization(
    value: object,
) -> _ProfileFitSlotAuthorizationState:
    state: _ProfileFitSlotAuthorizationState | None = None
    if type(value) is _ProfileFitSlotAuthorization:
        try:
            state = _PROFILE_FIT_SLOT_AUTHORIZATION_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _ProfileFitSlotAuthorizationState:
        raise TypeError("A genuine profile fit-slot authority is required.")
    _PROFILE_FIT_SLOT_AUTHORIZATION_STATES.require(value, state)
    return state


def _read_profile_fit_slot_authorization(
    value: object,
) -> _ProfileFitSlotAuthorizationState:
    state = _bound_profile_fit_slot_authorization(value)
    group = state.group_ref()
    if type(group) is not ProfileFitSlotGroup:
        raise TypeError("Profile fit-slot authority publication changed.")
    group_state = _PROFILE_FIT_SLOT_GROUP_STATES.get(group)
    if type(group_state) is not _ProfileFitSlotGroupState:
        raise TypeError("Profile fit-slot authority publication changed.")
    if (
        type(state.row_index) is not int
        or isinstance(state.row_index, bool)
        or state.row_index < 0
        or state.row_index >= len(group_state.slots)
        or group_state.slots[state.row_index] is not value
    ):
        raise TypeError("Profile fit-slot position is invalid.")
    _validate_slot_state(
        value,
        state,
        group_state,
        publication_status="PUBLISHED",
    )
    return state


def _validate_profile_fit_slot_group_state(
    value: ProfileFitSlotGroup,
    state: _ProfileFitSlotGroupState,
    *,
    publication_status: str,
) -> None:
    if (
        type(state) is not _ProfileFitSlotGroupState
        or type(state.publication) is not _ProfileFitSlotPublication
        or state.publication_token is not state.publication.token
        or type(state.barrier) is not ProfileValidationBarrier
        or type(state.barrier_state) is not _ProfileValidationBarrierState
        or type(state.ledger) is not _ProfileFitSlotLedger
        or state.ledger_token is not state.ledger.token
        or type(state.receipt) is not _ProfileFitScheduleReceipt
        or type(state.receipt_state) is not _ProfileFitScheduleReceiptState
        or _bound_profile_fit_schedule_receipt(state.receipt)
        is not state.receipt_state
        or state.barrier_state.fit_receipt is not state.receipt
        or type(state.slots) is not tuple
        or len(state.slots) != _PROFILE_FIT_SLOT_COUNT
        or len({id(slot) for slot in state.slots}) != _PROFILE_FIT_SLOT_COUNT
    ):
        raise TypeError("Profile fit-slot group storage is invalid.")
    with state.publication.lock:
        published = None if state.publication.group_ref is None else state.publication.group_ref()
        if (
            state.publication.status != publication_status
            or published is not value
            or state.publication.barrier_state is not state.barrier_state
        ):
            raise TypeError("Profile fit-slot group publication changed.")
    for position, slot in enumerate(state.slots):
        slot_state = _PROFILE_FIT_SLOT_AUTHORIZATION_STATES.get(slot)
        if (
            type(slot) is not _ProfileFitSlotAuthorization
            or type(slot_state) is not _ProfileFitSlotAuthorizationState
            or slot_state.group_ref() is not value
            or slot_state.receipt is not state.receipt
            or slot_state.row_index != position
        ):
            raise TypeError("Profile fit-slot group lost an exact slot owner.")
        _validate_slot_state(
            slot,
            slot_state,
            state,
            publication_status=publication_status,
        )
    _PROFILE_FIT_SLOT_GROUP_STATES.require(value, state)


def _read_profile_fit_slot_group(
    value: object,
) -> _ProfileFitSlotGroupState:
    state: _ProfileFitSlotGroupState | None = None
    if type(value) is ProfileFitSlotGroup:
        try:
            state = _PROFILE_FIT_SLOT_GROUP_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _ProfileFitSlotGroupState:
        raise TypeError("A genuine profile fit-slot group is required.")
    _validate_profile_fit_slot_group_state(
        cast(ProfileFitSlotGroup, value),
        state,
        publication_status="PUBLISHED",
    )
    return state


def _activate_profile_fit_slot_group(
    publication: _ProfileFitSlotPublication,
    barrier: ProfileValidationBarrier,
) -> ProfileFitSlotGroup:
    """Build one fresh group while its publication lock remains exclusive."""

    try:
        barrier_state = publication.barrier_state
        if type(barrier_state) is not _ProfileValidationBarrierState:
            raise TypeError("Profile fit-slot publication has no validated barrier state.")
        _reattest_profile_source_at_phase_boundary(
            barrier_state.group,
            barrier_state.group_state,
        )
        receipt = barrier_state.fit_receipt
        receipt_state = _require_profile_fit_schedule_receipt(receipt)
        _validate_profile_validation_barrier_state(
            barrier,
            barrier_state,
            receipt_state,
        )
        rows = receipt_state.rows
        if (
            receipt_state.invoker is not barrier_state.invoker
            or tuple(row.runtime_position for row in rows)
            != tuple(range(_PROFILE_FIT_SLOT_COUNT))
            or any(
                rows[chain_position].seed
                != rows[chain_position + _PROFILE_CHAIN_COUNT].seed
                or rows[chain_position].seed
                != rows[chain_position + (2 * _PROFILE_CHAIN_COUNT)].seed
                for chain_position in range(_PROFILE_CHAIN_COUNT)
            )
        ):
            raise TypeError("The exact nine-slot profile fit schedule is invalid.")
        ledger = _ProfileFitSlotLedger()
        slots = tuple(
            object.__new__(_ProfileFitSlotAuthorization)
            for _position in range(_PROFILE_FIT_SLOT_COUNT)
        )
        group = object.__new__(ProfileFitSlotGroup)
        group_reference = ref(group)
        publication.group_ref = group_reference
        states = tuple(
            _ProfileFitSlotAuthorizationState(
                group_ref=group_reference,
                receipt=receipt,
                row_index=position,
                one_use=_ProfileFitSlotUse(),
            )
            for position in range(_PROFILE_FIT_SLOT_COUNT)
        )
        group_state = _ProfileFitSlotGroupState(
            publication=publication,
            publication_token=publication.token,
            barrier=barrier,
            barrier_state=barrier_state,
            ledger=ledger,
            ledger_token=ledger.token,
            receipt=receipt,
            receipt_state=receipt_state,
            slots=slots,
        )
        for slot, state in zip(slots, states, strict=True):
            _PROFILE_FIT_SLOT_AUTHORIZATION_STATE_ISSUER.bind_once(slot, state)
            _validate_slot_state(
                slot,
                state,
                group_state,
                publication_status="ACTIVATING",
            )
        _PROFILE_FIT_SLOT_GROUP_STATE_ISSUER.bind_once(group, group_state)
        _validate_profile_fit_slot_group_state(
            group,
            group_state,
            publication_status="ACTIVATING",
        )
        publication.group_ref = group_reference
        publication.status = "PUBLISHED"
        _read_profile_fit_slot_group(group)
    except BaseException:
        publication.barrier_state = None
        publication.group_ref = None
        publication.status = "FRESH"
        raise
    return group


def issue_profile_fit_slot_group(
    barrier: ProfileValidationBarrier,
) -> ProfileFitSlotGroup:
    """Atomically predeclare the exact nine serial slots for one barrier."""

    publication = _profile_fit_slot_publication(barrier)
    with publication.lock:
        existing = None if publication.group_ref is None else publication.group_ref()
        if existing is None:
            if publication.status != "FRESH":
                raise TypeError("The profile fit-slot publication was already consumed.")
            publication.status = "ACTIVATING"
            return _activate_profile_fit_slot_group(publication, barrier)

    published_group = existing
    _read_profile_fit_slot_group(published_group)
    return published_group


def _consume_profile_fit_slot_authorization(
    value: object,
    *,
    invoker: WorkerInvoker,
    candidate_execution_context: _PreparedCandidateExecutionContext,
    execution_input_projection_digest: str,
) -> _ProfileFitSlotAuthorizationState:
    """Consume the next exact slot immediately before guarded dispatch."""

    bound_state = _bound_profile_fit_slot_authorization(value)
    group = bound_state.group_ref()
    group_state = (
        None if group is None else _PROFILE_FIT_SLOT_GROUP_STATES.get(group)
    )
    if type(group_state) is not _ProfileFitSlotGroupState:
        raise TypeError("Profile fit-slot group ownership changed.")
    ledger = group_state.ledger
    with ledger.lock:
        state = _read_profile_fit_slot_authorization(value)
        if (
            state is not bound_state
            or state.invoker is not invoker
            or state.candidate_execution_context is not candidate_execution_context
            or state.execution_input_projection_digest != execution_input_projection_digest
            or state.one_use.consumed
            or state.one_use.terminal is not None
            or ledger.active_position is not None
            or ledger.next_position != state.runtime_position
        ):
            raise TypeError("Profile fit slots must dispatch once in exact serial rotation order.")
        state.one_use.consumed = True
        ledger.active_position = state.runtime_position
    return state


def _request_matches_profile_fit_slot(
    *,
    request_readback: Any,
    request: Any,
    state: _ProfileFitSlotAuthorizationState,
) -> bool:
    payload = request.get("payload") if isinstance(request, Mapping) else None
    receipt_row = _profile_fit_slot_row(state)
    return (
        request_readback.profile_fit_receipt_row is receipt_row
        and request.get("command") == "fit"
        and isinstance(payload, Mapping)
        and payload.get("execution_input_projection_digest")
        == receipt_row.execution_input_projection_digest
        and request_readback.prepared_candidate_execution_context
        is receipt_row.candidate_execution_context
        and request_readback.prepared_candidate_execution_context_state
        is receipt_row.candidate_execution_context_state
        and request_readback.authenticated_description
        is receipt_row.dispatch_context_seal.authenticated_description
        and request_readback.planning_summary_id
        == receipt_row.dispatch_context_seal.planning_summary_id
        and payload.get("universe_id") == receipt_row.universe_id
        and payload.get("chain_execution_id") == receipt_row.chain_execution_id
        and payload.get("attempt_id") == receipt_row.attempt_id
        and payload.get("attempt_ordinal") == receipt_row.attempt_ordinal
        and payload.get("seed") == receipt_row.seed
        and payload.get("chain_id") == receipt_row.chain_id
    )


def _validate_profile_fit_terminal(
    state: _ProfileFitSlotAuthorizationState,
    terminal: object,
) -> None:
    if type(terminal) is AuthenticatedWorkerExecutionEvidence:
        execution_readback = _readback_authenticated_execution(terminal)
        if (
            not _request_matches_profile_fit_slot(
                request_readback=execution_readback.request_readback,
                request=execution_readback.request,
                state=state,
            )
            or execution_readback.response.get("command") != "fit"
        ):
            raise TypeError("Profile fit terminal belongs to another exact slot.")
        return
    if type(terminal) is WorkerInvocationObservation:
        observation_readback = _readback_worker_invocation_observation(terminal)
        if not _request_matches_profile_fit_slot(
            request_readback=observation_readback.request_readback,
            request=observation_readback.request,
            state=state,
        ):
            raise TypeError("Profile fit failure belongs to another exact slot.")
        return
    if (
        type(terminal) is _ProfileFitUnobservedCoreFailure
        and terminal.failure_code == "PROFILE_FIT.UNOBSERVED_CORE_FAILURE"
    ):
        return
    raise TypeError("Profile fit terminal evidence is invalid.")


def _complete_profile_fit_slot_authorization(
    value: object,
    terminal: object,
) -> None:
    """Retain one exact terminal and unlock only the immediately next slot."""

    bound_state = _bound_profile_fit_slot_authorization(value)
    group = bound_state.group_ref()
    group_state = (
        None if group is None else _PROFILE_FIT_SLOT_GROUP_STATES.get(group)
    )
    if type(group_state) is not _ProfileFitSlotGroupState:
        raise TypeError("Profile fit-slot group ownership changed.")
    ledger = group_state.ledger
    with ledger.lock:
        state = _read_profile_fit_slot_authorization(value)
        if (
            state is not bound_state
            or not state.one_use.consumed
            or state.one_use.terminal is not None
            or ledger.active_position != state.runtime_position
            or ledger.next_position != state.runtime_position
        ):
            raise TypeError("Profile fit-slot terminal cannot be replaced or reordered.")
        _validate_profile_fit_terminal(state, terminal)
        state.one_use.terminal = cast(
            AuthenticatedWorkerExecutionEvidence
            | WorkerInvocationObservation
            | _ProfileFitUnobservedCoreFailure,
            terminal,
        )
        ledger.active_position = None
        ledger.next_position += 1


def _complete_profile_fit_slot_without_observation(value: object) -> None:
    """Retain the sole fixed terminal without inventing worker evidence."""

    _complete_profile_fit_slot_authorization(
        value,
        _issue_profile_fit_unobserved_core_failure(),
    )


__all__ = [
    "ProfileFitSlotGroup",
    "issue_profile_fit_slot_group",
]
