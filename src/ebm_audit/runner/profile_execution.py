"""Opaque all-terminal execution for one exact profile fit-slot group."""

from __future__ import annotations

import math
import time
from contextlib import suppress
from contextvars import Token
from datetime import UTC, datetime
from threading import Lock, RLock
from typing import NamedTuple, SupportsIndex, cast, final
from weakref import ReferenceType, ref

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit._profile_storage_boundary import (
    _activate_profile_storage_observer,
    _deactivate_profile_storage_observer,
    _ProfileStorageOperationObserver,
)
from ebm_audit.adapters import (
    AuthenticatedWorkerExecutionEvidence,
    WorkerInvocationObservation,
    WorkerInvoker,
)
from ebm_audit.errors import AuditError
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256
from ebm_audit.runner.profile_fit_slots import (
    ProfileFitSlotGroup,
    _bound_profile_fit_slot_authorization,
    _ProfileFitSlotAuthorization,
    _ProfileFitSlotGroupState,
    _ProfileFitUnobservedCoreFailure,
    _read_profile_fit_slot_authorization,
    _read_profile_fit_slot_group,
    _reattest_profile_source_at_phase_boundary,
    _require_profile_fit_unobserved_core_failure,
    _validate_profile_fit_terminal,
)
from ebm_audit.runner.profile_validation import (
    _bound_profile_fit_schedule_receipt,
    _ProfileFitScheduleReceipt,
    _ProfileFitScheduleReceiptRow,
    _ProfileFitScheduleReceiptState,
    _ProfileValidationTerminal,
    _valid_profile_utc_timestamp,
)

_PROFILE_STORAGE_OBSERVATION_ISSUER = object()
_PROFILE_STORAGE_RESOURCES = ("CACHE", "CHECKPOINT")


class _ProfileFitSessionPublication:
    """Callback-free publication cell for one exact fit-slot group."""

    __slots__ = ("lock", "session_ref", "status", "token")

    lock: RLock
    session_ref: ReferenceType[ProfileFitSession] | None
    status: str
    token: object

    def __init__(self) -> None:
        self.lock = RLock()
        self.session_ref = None
        self.status = "FRESH"
        self.token = object()


class _ProfileCandidateLifecycleTiming(NamedTuple):
    candidate_ordinal: int
    validation_terminal: _ProfileValidationTerminal
    final_fit_slot: _ProfileFitSlotAuthorization
    started_at_utc: str
    ended_at_utc: str
    started_monotonic: float
    ended_monotonic: float
    runtime_seconds: float


class _ProfileStorageGuardReceipt(NamedTuple):
    issuer: object
    group: ProfileFitSlotGroup
    group_state: _ProfileFitSlotGroupState
    guard_token: object
    activated_monotonic: float
    closed_monotonic: float
    cache_read_count: int
    cache_write_count: int
    checkpoint_read_count: int
    checkpoint_write_count: int
    runtime_scope_completed: bool


class _ProfileNoReadNoWriteObservation(NamedTuple):
    issuer: object
    resource: str
    candidate_ordinal: int
    candidate_authorization: object
    candidate_state: object
    covered_fit_slots: tuple[
        _ProfileFitSlotAuthorization,
        _ProfileFitSlotAuthorization,
        _ProfileFitSlotAuthorization,
    ]
    execution_policy_bytes: bytes
    guard_receipt: _ProfileStorageGuardReceipt
    read_count: int
    write_count: int


class _ProfileFitCompletionSnapshot(NamedTuple):
    group: ProfileFitSlotGroup
    group_state: _ProfileFitSlotGroupState
    receipt: _ProfileFitScheduleReceipt
    receipt_state: _ProfileFitScheduleReceiptState
    invoker: WorkerInvoker
    profile_execution_identity_sha256: str
    coordinate_ordinal: int
    ordered_analysis_spec_ids: tuple[str, str, str]
    slots: tuple[_ProfileFitSlotAuthorization, ...]
    receipt_rows: tuple[_ProfileFitScheduleReceiptRow, ...]
    terminals: tuple[object, ...]
    lifecycle_timings: tuple[
        _ProfileCandidateLifecycleTiming,
        _ProfileCandidateLifecycleTiming,
        _ProfileCandidateLifecycleTiming,
    ]
    storage_guard_receipt: _ProfileStorageGuardReceipt
    storage_observations: tuple[
        tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation],
        tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation],
        tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation],
    ]


class _ProfileFitSessionState(NamedTuple):
    publication: _ProfileFitSessionPublication
    publication_token: object
    completion_snapshot: _ProfileFitCompletionSnapshot

    @property
    def group(self) -> ProfileFitSlotGroup:
        return self.completion_snapshot.group

    @property
    def group_state(self) -> _ProfileFitSlotGroupState:
        return self.completion_snapshot.group_state

    @property
    def invoker(self) -> WorkerInvoker:
        return self.completion_snapshot.invoker

    @property
    def lifecycle_timings(
        self,
    ) -> tuple[
        _ProfileCandidateLifecycleTiming,
        _ProfileCandidateLifecycleTiming,
        _ProfileCandidateLifecycleTiming,
    ]:
        return self.completion_snapshot.lifecycle_timings

    @property
    def storage_guard_receipt(self) -> _ProfileStorageGuardReceipt:
        return self.completion_snapshot.storage_guard_receipt

    @property
    def storage_observations(
        self,
    ) -> tuple[
        tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation],
        tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation],
        tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation],
    ]:
        return self.completion_snapshot.storage_observations


class _ProfileStorageGuard:
    """Active zero-operation counter for the dedicated profile fit path."""

    __slots__ = (
        "_activated_monotonic",
        "_closed",
        "_counts",
        "_group",
        "_group_state",
        "_runtime_scope_active",
        "_runtime_scope_completed",
        "_token",
    )

    def __init__(
        self,
        group: ProfileFitSlotGroup,
        group_state: _ProfileFitSlotGroupState,
    ) -> None:
        self._group = group
        self._group_state = group_state
        self._token = object()
        self._activated_monotonic = time.monotonic()
        self._closed = False
        self._runtime_scope_active = False
        self._runtime_scope_completed = False
        self._counts = {
            ("CACHE", "READ"): 0,
            ("CACHE", "WRITE"): 0,
            ("CHECKPOINT", "READ"): 0,
            ("CHECKPOINT", "WRITE"): 0,
        }

    def _observe(self, *, resource: str, operation: str) -> None:
        if (
            self._closed
            or not self._runtime_scope_active
            or (resource, operation) not in self._counts
        ):
            raise TypeError("Profile storage observation is outside its active guard.")
        self._counts[(resource, operation)] += 1
        raise TypeError("Profile execution forbids cache and checkpoint operations.")

    def activate(
        self,
    ) -> Token[_ProfileStorageOperationObserver | None]:
        if self._closed or self._runtime_scope_active or self._runtime_scope_completed:
            raise TypeError("Profile storage guard activation is invalid.")
        token = _activate_profile_storage_observer(self)
        self._runtime_scope_active = True
        return token

    def deactivate(
        self,
        token: Token[_ProfileStorageOperationObserver | None],
    ) -> None:
        if self._closed or not self._runtime_scope_active:
            raise TypeError("Profile storage guard deactivation is invalid.")
        _deactivate_profile_storage_observer(token)
        self._runtime_scope_active = False
        self._runtime_scope_completed = True

    def close(self) -> _ProfileStorageGuardReceipt:
        if (
            self._closed
            or self._runtime_scope_active
            or not self._runtime_scope_completed
        ):
            raise TypeError("Profile storage guard was already closed.")
        self._closed = True
        receipt = _ProfileStorageGuardReceipt(
            issuer=_PROFILE_STORAGE_OBSERVATION_ISSUER,
            group=self._group,
            group_state=self._group_state,
            guard_token=self._token,
            activated_monotonic=self._activated_monotonic,
            closed_monotonic=time.monotonic(),
            cache_read_count=self._counts[("CACHE", "READ")],
            cache_write_count=self._counts[("CACHE", "WRITE")],
            checkpoint_read_count=self._counts[("CHECKPOINT", "READ")],
            checkpoint_write_count=self._counts[("CHECKPOINT", "WRITE")],
            runtime_scope_completed=self._runtime_scope_completed,
        )
        _validate_profile_storage_guard_receipt(
            receipt,
            group=self._group,
            group_state=self._group_state,
        )
        return receipt


_PROFILE_FIT_SESSION_PUBLICATIONS: OneShotWeakRegistry[object, _ProfileFitSessionPublication]
_PROFILE_FIT_SESSION_PUBLICATION_ISSUER: OneShotRegistryIssuer[
    object, _ProfileFitSessionPublication
]
(
    _PROFILE_FIT_SESSION_PUBLICATIONS,
    _PROFILE_FIT_SESSION_PUBLICATION_ISSUER,
) = create_one_shot_registry()
_PROFILE_FIT_SESSION_PUBLICATIONS_LOCK = Lock()

_PROFILE_FIT_SESSION_STATES: OneShotWeakRegistry[object, _ProfileFitSessionState]
_PROFILE_FIT_SESSION_STATE_ISSUER: OneShotRegistryIssuer[object, _ProfileFitSessionState]
(
    _PROFILE_FIT_SESSION_STATES,
    _PROFILE_FIT_SESSION_STATE_ISSUER,
) = create_one_shot_registry()


@final
class ProfileFitSession:
    """Opaque terminal owner for exactly nine serial profile fits."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ProfileFitSession:
        raise TypeError("Profile fit sessions are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile fit sessions cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile fit sessions are immutable.")

    @property
    def terminal_count(self) -> int:
        state = _read_profile_fit_session(self)
        return len(state.completion_snapshot.terminals)

    def __copy__(self) -> ProfileFitSession:
        raise TypeError("Profile fit sessions cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> ProfileFitSession:
        raise TypeError("Profile fit sessions cannot be copied or serialized.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Profile fit sessions cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Profile fit sessions cannot be copied or serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Profile fit sessions cannot be copied or serialized.")

    def __repr__(self) -> str:
        _read_profile_fit_session(self)
        return "ProfileFitSession(<sealed-nine-fit-terminals>)"


def _profile_fit_session_publication(
    group: object,
) -> _ProfileFitSessionPublication:
    if type(group) is not ProfileFitSlotGroup:
        raise TypeError("A genuine profile fit-slot group is required.")
    with _PROFILE_FIT_SESSION_PUBLICATIONS_LOCK:
        publication = _PROFILE_FIT_SESSION_PUBLICATIONS.get(group)
        if publication is None:
            publication = _ProfileFitSessionPublication()
            _PROFILE_FIT_SESSION_PUBLICATION_ISSUER.bind_once(group, publication)
    if type(publication) is not _ProfileFitSessionPublication:
        raise TypeError("Profile fit-session publication state is invalid.")
    return publication


def _profile_utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _profile_execution_policy_bytes(
    group_state: _ProfileFitSlotGroupState,
) -> bytes:
    receipt_state = _bound_profile_fit_schedule_receipt(group_state.receipt)
    if receipt_state is not group_state.receipt_state:
        raise TypeError("Profile execution policy lost its fit receipt.")
    policy_bytes = receipt_state.basis.execution_policy_bytes
    policy = strict_json_loads(policy_bytes)
    if (
        type(policy) is not dict
        or policy.get("cache_policy") != "NO_READ_NO_WRITE"
        or policy.get("checkpoint_policy") != "NO_READ_NO_WRITE"
        or policy.get("retry_policy") != "DISALLOWED"
    ):
        raise TypeError("Profile storage observations require the sealed no-storage policy.")
    return policy_bytes


def _profile_completion_identity(
    receipt_state: _ProfileFitScheduleReceiptState,
) -> tuple[str, int, tuple[str, str, str]]:
    """Read immutable persistence identity from the sealed schedule basis only."""

    basis = receipt_state.basis
    basis_bytes = basis.canonical_bytes
    decoded = strict_json_loads(basis_bytes)
    identity = (
        decoded.get("profile_execution_identity_sha256")
        if type(decoded) is dict
        else None
    )
    coordinate_ordinal = (
        decoded.get("coordinate_ordinal") if type(decoded) is dict else None
    )
    analysis_spec_ids = (
        decoded.get("ordered_analysis_spec_ids") if type(decoded) is dict else None
    )
    if (
        type(decoded) is not dict
        or canonical_json_bytes(decoded) != basis_bytes
        or structured_sha256(
            "ebm-audit/profile-validation-schedule-basis/1",
            decoded,
        )
        != basis.digest
        or type(identity) is not str
        or len(identity) != 64
        or any(character not in "0123456789abcdef" for character in identity)
        or type(coordinate_ordinal) is not int
        or isinstance(coordinate_ordinal, bool)
        or coordinate_ordinal < 0
        or type(analysis_spec_ids) is not list
        or len(analysis_spec_ids) != 3
        or any(
            type(analysis_spec_id) is not str or not analysis_spec_id
            for analysis_spec_id in analysis_spec_ids
        )
    ):
        raise TypeError("Profile completion identity changed.")
    return (
        identity,
        coordinate_ordinal,
        cast(tuple[str, str, str], tuple(analysis_spec_ids)),
    )


def _candidate_fit_slots(
    group_state: _ProfileFitSlotGroupState,
    candidate_ordinal: int,
) -> tuple[
    _ProfileFitSlotAuthorization,
    _ProfileFitSlotAuthorization,
    _ProfileFitSlotAuthorization,
]:
    rows = tuple(
        slot
        for slot in group_state.slots
        if _read_profile_fit_slot_authorization(slot).candidate_ordinal == candidate_ordinal
    )
    if len(rows) != 3 or tuple(
        _read_profile_fit_slot_authorization(slot).chain_plan_position for slot in rows
    ) != (0, 1, 2):
        raise TypeError("Profile candidate storage coverage changed its three exact slots.")
    return rows


def _validate_profile_storage_guard_receipt(
    receipt: object,
    *,
    group: ProfileFitSlotGroup,
    group_state: _ProfileFitSlotGroupState,
) -> _ProfileStorageGuardReceipt:
    if (
        type(receipt) is not _ProfileStorageGuardReceipt
        or receipt.issuer is not _PROFILE_STORAGE_OBSERVATION_ISSUER
        or receipt.group is not group
        or receipt.group_state is not group_state
        or type(receipt.guard_token) is not object
        or type(receipt.activated_monotonic) is not float
        or type(receipt.closed_monotonic) is not float
        or not math.isfinite(receipt.activated_monotonic)
        or not math.isfinite(receipt.closed_monotonic)
        or receipt.activated_monotonic < 0.0
        or receipt.closed_monotonic < receipt.activated_monotonic
        or receipt.runtime_scope_completed is not True
        or (
            receipt.cache_read_count,
            receipt.cache_write_count,
            receipt.checkpoint_read_count,
            receipt.checkpoint_write_count,
        )
        != (0, 0, 0, 0)
    ):
        raise TypeError("Profile storage guard did not prove zero operations.")
    return receipt


def _issue_profile_storage_observations(
    group: ProfileFitSlotGroup,
    group_state: _ProfileFitSlotGroupState,
    receipt: _ProfileStorageGuardReceipt,
) -> tuple[
    tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation],
    tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation],
    tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation],
]:
    _validate_profile_storage_guard_receipt(
        receipt,
        group=group,
        group_state=group_state,
    )
    policy_bytes = _profile_execution_policy_bytes(group_state)
    rows: list[tuple[_ProfileNoReadNoWriteObservation, _ProfileNoReadNoWriteObservation]] = []
    for candidate_ordinal in range(3):
        slots = _candidate_fit_slots(group_state, candidate_ordinal)
        first_state = _read_profile_fit_slot_authorization(slots[0])
        candidate_rows = cast(
            tuple[
                _ProfileNoReadNoWriteObservation,
                _ProfileNoReadNoWriteObservation,
            ],
            tuple(
                _ProfileNoReadNoWriteObservation(
                    issuer=_PROFILE_STORAGE_OBSERVATION_ISSUER,
                    resource=resource,
                    candidate_ordinal=candidate_ordinal,
                    candidate_authorization=first_state.candidate_authorization,
                    candidate_state=first_state.candidate_state,
                    covered_fit_slots=slots,
                    execution_policy_bytes=policy_bytes,
                    guard_receipt=receipt,
                    read_count=0,
                    write_count=0,
                )
                for resource in _PROFILE_STORAGE_RESOURCES
            ),
        )
        for observation in candidate_rows:
            _validate_profile_storage_observation(
                observation,
                group=group,
                group_state=group_state,
                receipt=receipt,
            )
        rows.append(candidate_rows)
    return cast(
        tuple[
            tuple[
                _ProfileNoReadNoWriteObservation,
                _ProfileNoReadNoWriteObservation,
            ],
            tuple[
                _ProfileNoReadNoWriteObservation,
                _ProfileNoReadNoWriteObservation,
            ],
            tuple[
                _ProfileNoReadNoWriteObservation,
                _ProfileNoReadNoWriteObservation,
            ],
        ],
        tuple(rows),
    )


def _validate_profile_storage_observation(
    observation: object,
    *,
    group: ProfileFitSlotGroup,
    group_state: _ProfileFitSlotGroupState,
    receipt: _ProfileStorageGuardReceipt,
) -> _ProfileNoReadNoWriteObservation:
    if (
        type(observation) is not _ProfileNoReadNoWriteObservation
        or observation.issuer is not _PROFILE_STORAGE_OBSERVATION_ISSUER
        or observation.resource not in _PROFILE_STORAGE_RESOURCES
        or type(observation.candidate_ordinal) is not int
        or observation.candidate_ordinal not in {0, 1, 2}
        or observation.guard_receipt is not receipt
        or observation.execution_policy_bytes != _profile_execution_policy_bytes(group_state)
        or (observation.read_count, observation.write_count) != (0, 0)
    ):
        raise TypeError("Profile no-read/no-write observation storage is invalid.")
    _validate_profile_storage_guard_receipt(
        receipt,
        group=group,
        group_state=group_state,
    )
    expected_slots = _candidate_fit_slots(
        group_state,
        observation.candidate_ordinal,
    )
    first_state = _read_profile_fit_slot_authorization(expected_slots[0])
    if (
        observation.covered_fit_slots != expected_slots
        or observation.candidate_authorization is not first_state.candidate_authorization
        or observation.candidate_state is not first_state.candidate_state
    ):
        raise TypeError("Profile no-read/no-write observation changed its candidate owner.")
    return observation


def _validate_profile_lifecycle_timing(
    timing: object,
    *,
    group_state: _ProfileFitSlotGroupState,
) -> _ProfileCandidateLifecycleTiming:
    if (
        type(timing) is not _ProfileCandidateLifecycleTiming
        or type(timing.candidate_ordinal) is not int
        or timing.candidate_ordinal not in {0, 1, 2}
        or not _valid_profile_utc_timestamp(timing.started_at_utc)
        or not _valid_profile_utc_timestamp(timing.ended_at_utc)
        or type(timing.started_monotonic) is not float
        or type(timing.ended_monotonic) is not float
        or type(timing.runtime_seconds) is not float
        or not math.isfinite(timing.started_monotonic)
        or not math.isfinite(timing.ended_monotonic)
        or not math.isfinite(timing.runtime_seconds)
        or timing.started_monotonic < 0.0
        or timing.ended_monotonic < timing.started_monotonic
        or timing.runtime_seconds != timing.ended_monotonic - timing.started_monotonic
    ):
        raise TypeError("Profile candidate lifecycle timing is invalid.")
    validation = group_state.barrier_state.terminals[timing.candidate_ordinal]
    slots = _candidate_fit_slots(group_state, timing.candidate_ordinal)
    if (
        type(validation) is not _ProfileValidationTerminal
        or timing.validation_terminal is not validation
        or timing.started_at_utc != validation.started_at_utc
        or timing.started_monotonic != validation.started_monotonic
        or timing.final_fit_slot is not slots[2]
        or _read_profile_fit_slot_authorization(slots[2]).one_use.terminal is None
    ):
        raise TypeError("Profile candidate lifecycle timing changed its exact terminal owners.")
    return timing


def _validate_complete_profile_fit_group(
    group: ProfileFitSlotGroup,
    expected_state: _ProfileFitSlotGroupState,
) -> None:
    state = _read_profile_fit_slot_group(group)
    if (
        state is not expected_state
        or type(state.barrier_state.invoker) is not WorkerInvoker
        or type(state.slots) is not tuple
        or len(state.slots) != 9
    ):
        raise TypeError("Profile fit session changed its exact group owner.")
    with state.ledger.lock:
        if (
            state.ledger.next_position != len(state.slots)
            or state.ledger.active_position is not None
        ):
            raise TypeError("Profile fit session requires all nine exact terminals.")


def _capture_profile_fit_completion_terminals(
    slots: object,
) -> tuple[object, ...]:
    """Authenticate each mutable slot terminal once before immutable capture."""

    if (
        type(slots) is not tuple
        or len(slots) != 9
        or any(type(slot) is not _ProfileFitSlotAuthorization for slot in slots)
    ):
        raise TypeError("Profile fit completion snapshot requires nine exact slots.")
    terminals: list[object] = []
    for slot in slots:
        state = _bound_profile_fit_slot_authorization(slot)
        terminal = state.one_use.terminal
        if terminal is None:
            raise TypeError("Profile fit completion snapshot requires nine terminals.")
        _validate_profile_fit_terminal(state, terminal)
        terminals.append(terminal)
    return tuple(terminals)


def _validate_profile_fit_completion_snapshot(
    snapshot: object,
) -> _ProfileFitCompletionSnapshot:
    if (
        type(snapshot) is not _ProfileFitCompletionSnapshot
        or type(snapshot.group) is not ProfileFitSlotGroup
        or type(snapshot.group_state) is not _ProfileFitSlotGroupState
        or type(snapshot.receipt) is not _ProfileFitScheduleReceipt
        or type(snapshot.receipt_state) is not _ProfileFitScheduleReceiptState
        or type(snapshot.invoker) is not WorkerInvoker
        or snapshot.group_state.receipt is not snapshot.receipt
        or snapshot.group_state.receipt_state is not snapshot.receipt_state
        or snapshot.group_state.barrier_state.invoker is not snapshot.invoker
        or snapshot.receipt_state.invoker is not snapshot.invoker
        or type(snapshot.profile_execution_identity_sha256) is not str
        or type(snapshot.coordinate_ordinal) is not int
        or isinstance(snapshot.coordinate_ordinal, bool)
        or type(snapshot.ordered_analysis_spec_ids) is not tuple
        or len(snapshot.ordered_analysis_spec_ids) != 3
        or _bound_profile_fit_schedule_receipt(snapshot.receipt)
        is not snapshot.receipt_state
        or type(snapshot.slots) is not tuple
        or len(snapshot.slots) != 9
        or snapshot.slots is not snapshot.group_state.slots
        or type(snapshot.receipt_rows) is not tuple
        or len(snapshot.receipt_rows) != 9
        or snapshot.receipt_rows is not snapshot.receipt_state.rows
        or type(snapshot.terminals) is not tuple
        or len(snapshot.terminals) != 9
        or type(snapshot.lifecycle_timings) is not tuple
        or len(snapshot.lifecycle_timings) != 3
        or type(snapshot.storage_guard_receipt) is not _ProfileStorageGuardReceipt
        or type(snapshot.storage_observations) is not tuple
        or len(snapshot.storage_observations) != 3
    ):
        raise TypeError("Profile fit completion snapshot is invalid.")
    if (
        snapshot.profile_execution_identity_sha256,
        snapshot.coordinate_ordinal,
        snapshot.ordered_analysis_spec_ids,
    ) != _profile_completion_identity(snapshot.receipt_state):
        raise TypeError("Profile fit completion snapshot identity changed.")
    for terminal in snapshot.terminals:
        if type(terminal) is _ProfileFitUnobservedCoreFailure:
            _require_profile_fit_unobserved_core_failure(terminal)
        elif type(terminal) not in {
            AuthenticatedWorkerExecutionEvidence,
            WorkerInvocationObservation,
        }:
            raise TypeError("Profile fit completion snapshot terminal changed.")
    if tuple(row.candidate_ordinal for row in snapshot.lifecycle_timings) != (0, 1, 2):
        raise TypeError("Profile fit-session lifecycle timing order changed.")
    for timing in snapshot.lifecycle_timings:
        candidate_positions = tuple(
            position
            for position, row in enumerate(snapshot.receipt_rows)
            if row.candidate_ordinal == timing.candidate_ordinal
        )
        if (
            len(candidate_positions) != 3
            or tuple(
                snapshot.receipt_rows[position].chain_plan_position
                for position in candidate_positions
            )
            != (0, 1, 2)
        ):
            raise TypeError("Profile candidate lifecycle timing changed its owners.")
        validation = snapshot.group_state.barrier_state.terminals[
            timing.candidate_ordinal
        ]
        if (
            type(timing) is not _ProfileCandidateLifecycleTiming
            or timing.validation_terminal is not validation
            or timing.started_at_utc != validation.started_at_utc
            or timing.started_monotonic != validation.started_monotonic
            or timing.final_fit_slot is not snapshot.slots[candidate_positions[2]]
            or not _valid_profile_utc_timestamp(timing.ended_at_utc)
            or type(timing.ended_monotonic) is not float
            or type(timing.runtime_seconds) is not float
            or not math.isfinite(timing.ended_monotonic)
            or not math.isfinite(timing.runtime_seconds)
            or timing.ended_monotonic < timing.started_monotonic
            or timing.runtime_seconds
            != timing.ended_monotonic - timing.started_monotonic
        ):
            raise TypeError("Profile candidate lifecycle timing is invalid.")
    receipt = _validate_profile_storage_guard_receipt(
        snapshot.storage_guard_receipt,
        group=snapshot.group,
        group_state=snapshot.group_state,
    )
    policy_bytes = _profile_execution_policy_bytes(snapshot.group_state)
    for candidate_ordinal, observations in enumerate(snapshot.storage_observations):
        candidate_positions = tuple(
            position
            for position, row in enumerate(snapshot.receipt_rows)
            if row.candidate_ordinal == candidate_ordinal
        )
        covered_slots = cast(
            tuple[
                _ProfileFitSlotAuthorization,
                _ProfileFitSlotAuthorization,
                _ProfileFitSlotAuthorization,
            ],
            tuple(snapshot.slots[position] for position in candidate_positions),
        )
        first_row = snapshot.receipt_rows[candidate_positions[0]]
        if (
            type(observations) is not tuple
            or len(observations) != 2
            or tuple(observation.resource for observation in observations)
            != _PROFILE_STORAGE_RESOURCES
        ):
            raise TypeError("Profile fit-session storage observation order changed.")
        for observation in observations:
            if (
                type(observation) is not _ProfileNoReadNoWriteObservation
                or observation.issuer is not _PROFILE_STORAGE_OBSERVATION_ISSUER
                or observation.candidate_ordinal != candidate_ordinal
                or observation.guard_receipt is not receipt
                or observation.execution_policy_bytes != policy_bytes
                or observation.covered_fit_slots != covered_slots
                or observation.candidate_authorization
                is not first_row.candidate_authorization
                or observation.candidate_state is not first_row.candidate_state
                or (observation.read_count, observation.write_count) != (0, 0)
            ):
                raise TypeError("Profile no-read/no-write observation changed.")
    return snapshot


def _validate_profile_fit_session_state(
    value: ProfileFitSession,
    state: _ProfileFitSessionState,
    *,
    publication_status: str,
) -> None:
    if (
        type(state) is not _ProfileFitSessionState
        or type(state.publication) is not _ProfileFitSessionPublication
        or state.publication_token is not state.publication.token
        or type(state.completion_snapshot) is not _ProfileFitCompletionSnapshot
    ):
        raise TypeError("Profile fit-session storage is invalid.")
    with state.publication.lock:
        published = (
            None if state.publication.session_ref is None else state.publication.session_ref()
        )
        if state.publication.status != publication_status or published is not value:
            raise TypeError("Profile fit-session publication changed.")
    _validate_profile_fit_completion_snapshot(state.completion_snapshot)
    _PROFILE_FIT_SESSION_STATES.require(value, state)


def _read_profile_fit_session(
    value: object,
) -> _ProfileFitSessionState:
    state: _ProfileFitSessionState | None = None
    if type(value) is ProfileFitSession:
        try:
            state = _PROFILE_FIT_SESSION_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _ProfileFitSessionState:
        raise TypeError("A genuine profile fit session is required.")
    _validate_profile_fit_session_state(
        cast(ProfileFitSession, value),
        state,
        publication_status="PUBLISHED",
    )
    return state


def run_profile_fit_session(
    group: ProfileFitSlotGroup,
) -> ProfileFitSession:
    """Run all nine stored slots and publish only their terminal owner."""

    publication = _profile_fit_session_publication(group)
    with publication.lock:
        existing = None if publication.session_ref is None else publication.session_ref()
        if existing is None:
            if publication.status != "FRESH":
                raise TypeError("The profile fit-session publication was already consumed.")
            publication.status = "ACTIVATING"
            try:
                group_state = _read_profile_fit_slot_group(group)
                _reattest_profile_source_at_phase_boundary(
                    group_state.barrier_state.group,
                    group_state.barrier_state.group_state,
                )
                invoker = group_state.barrier_state.invoker
                if type(invoker) is not WorkerInvoker:
                    raise TypeError("Profile fit-session invoker ownership changed.")
                storage_guard = _ProfileStorageGuard(group, group_state)
                timing_rows: dict[int, _ProfileCandidateLifecycleTiming] = {}
                storage_scope_token = storage_guard.activate()
                try:
                    for slot in group_state.slots:
                        slot_state = _read_profile_fit_slot_authorization(slot)
                        with suppress(AuditError):
                            invoker._invoke_profile_prepared_fit(slot)
                        ended_at_utc = _profile_utc_now()
                        ended_monotonic = time.monotonic()
                        terminal_state = _read_profile_fit_slot_authorization(slot)
                        if (
                            terminal_state is not slot_state
                            or terminal_state.one_use.terminal is None
                        ):
                            raise TypeError(
                                "Profile fit session lost an exact terminal after dispatch."
                            )
                        if slot_state.chain_plan_position == 2:
                            candidate_ordinal = slot_state.candidate_ordinal
                            validation_terminal = group_state.barrier_state.terminals[
                                candidate_ordinal
                            ]
                            if candidate_ordinal in timing_rows:
                                raise TypeError(
                                    "Profile fit session repeated a candidate lifecycle end."
                                )
                            timing_rows[candidate_ordinal] = _ProfileCandidateLifecycleTiming(
                                candidate_ordinal=candidate_ordinal,
                                validation_terminal=validation_terminal,
                                final_fit_slot=slot,
                                started_at_utc=validation_terminal.started_at_utc,
                                ended_at_utc=ended_at_utc,
                                started_monotonic=validation_terminal.started_monotonic,
                                ended_monotonic=ended_monotonic,
                                runtime_seconds=(
                                    ended_monotonic - validation_terminal.started_monotonic
                                ),
                            )
                finally:
                    storage_guard.deactivate(storage_scope_token)

                _validate_complete_profile_fit_group(group, group_state)
                lifecycle_timings = cast(
                    tuple[
                        _ProfileCandidateLifecycleTiming,
                        _ProfileCandidateLifecycleTiming,
                        _ProfileCandidateLifecycleTiming,
                    ],
                    tuple(timing_rows[ordinal] for ordinal in range(3)),
                )
                for timing in lifecycle_timings:
                    _validate_profile_lifecycle_timing(
                        timing,
                        group_state=group_state,
                    )
                storage_guard_receipt = storage_guard.close()
                storage_observations = _issue_profile_storage_observations(
                    group,
                    group_state,
                    storage_guard_receipt,
                )
                terminal_rows = _capture_profile_fit_completion_terminals(
                    group_state.slots
                )
                (
                    profile_execution_identity_sha256,
                    coordinate_ordinal,
                    ordered_analysis_spec_ids,
                ) = _profile_completion_identity(group_state.receipt_state)
                completion_snapshot = _ProfileFitCompletionSnapshot(
                    group=group,
                    group_state=group_state,
                    receipt=group_state.receipt,
                    receipt_state=group_state.receipt_state,
                    invoker=invoker,
                    profile_execution_identity_sha256=(
                        profile_execution_identity_sha256
                    ),
                    coordinate_ordinal=coordinate_ordinal,
                    ordered_analysis_spec_ids=ordered_analysis_spec_ids,
                    slots=group_state.slots,
                    receipt_rows=group_state.receipt_state.rows,
                    terminals=terminal_rows,
                    lifecycle_timings=lifecycle_timings,
                    storage_guard_receipt=storage_guard_receipt,
                    storage_observations=storage_observations,
                )
                _validate_profile_fit_completion_snapshot(completion_snapshot)
                session = object.__new__(ProfileFitSession)
                session_state = _ProfileFitSessionState(
                    publication=publication,
                    publication_token=publication.token,
                    completion_snapshot=completion_snapshot,
                )
                session_reference = ref(session)
                publication.session_ref = session_reference
                _PROFILE_FIT_SESSION_STATE_ISSUER.bind_once(session, session_state)
                _validate_profile_fit_session_state(
                    session,
                    session_state,
                    publication_status="ACTIVATING",
                )
                publication.session_ref = session_reference
                publication.status = "PUBLISHED"
                _read_profile_fit_session(session)
            except BaseException:
                publication.session_ref = None
                publication.status = "CONSUMED"
                raise
            return session

    published_session = existing
    _read_profile_fit_session(published_session)
    return published_session


__all__ = [
    "ProfileFitSession",
    "run_profile_fit_session",
]
