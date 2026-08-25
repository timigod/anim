"""Atomic profile-only finalization for one exact nine-fit session."""

from __future__ import annotations

import copy
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
)
from ebm_audit.privacy.safe import core_owned_negative_response_message
from ebm_audit.protocol import (
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256,
    validate_result_record_finalization,
)
from ebm_audit.results.finalization import (
    _CONVERGENCE_STATUS,
    _NEGATIVE_STATUS_PRECEDENCE,
    _PROFILE_FINALIZATION_ISSUER,
    FinalizedResult,
    _assert_fit_attempt_identity,
    _assert_scientific_owner_binding,
    _candidate_core,
    _capture_finalized_result_state_identity,
    _chain_payload,
    _convergence,
    _convergence_error,
    _FinalizedResultState,
    _issue_profile_finalized_result,
    _negative_error,
    _prepared_core,
    _PreparedCandidateState,
    _read_finalized_result,
    _resolve_attempt,
    _ResolvedAttempt,
)
from ebm_audit.runner.profile_execution import (
    ProfileFitSession,
    _ProfileFitSessionState,
    _ProfileNoReadNoWriteObservation,
    _read_profile_fit_session,
)
from ebm_audit.runner.profile_fit_slots import (
    _ProfileFitUnobservedCoreFailure,
    _reattest_profile_source_at_phase_boundary,
    _require_profile_fit_unobserved_core_failure,
)
from ebm_audit.runner.profile_validation import (
    _bound_profile_fit_schedule_receipt,
    _ProfileFitScheduleReceiptRow,
    _ProfileValidationCandidateBasis,
    _ProfileValidationResolvedSnapshot,
    _resolved_profile_validation_attempt,
)
from ebm_audit.schema import validate_instance
from ebm_audit.universe.identities import validated_planning_summary_id
from ebm_audit.universe.preparation import (
    _read_profile_prepared_candidate_group,
)

_PROFILE_RESULT_COUNT = 3
_PROFILE_CHAIN_COUNT = 3


class _ProfileFinalizedResultPublication:
    """Callback-free publication cell for one exact profile fit session."""

    __slots__ = ("group_ref", "lock", "status", "token")

    group_ref: ReferenceType[ProfileFinalizedResultGroup] | None
    lock: RLock
    status: str
    token: object

    def __init__(self) -> None:
        self.group_ref = None
        self.lock = RLock()
        self.status = "FRESH"
        self.token = object()


@dataclass(frozen=True, repr=False)
class _ProfileFinalizedResultGroupState:
    publication: _ProfileFinalizedResultPublication
    publication_token: object
    session: ProfileFitSession
    session_state: _ProfileFitSessionState
    results: tuple[FinalizedResult, FinalizedResult, FinalizedResult]
    result_states: tuple[_FinalizedResultState, _FinalizedResultState, _FinalizedResultState]


@dataclass(frozen=True, repr=False)
class _ProfileFinalizedResultSnapshot:
    candidate_ordinal: int
    result_id: str
    canonical_bytes: bytes


@dataclass(frozen=True, repr=False)
class _ProfileFinalizedResultGroupSnapshot:
    profile_execution_identity_sha256: str
    coordinate_ordinal: int
    ordered_analysis_spec_ids: tuple[str, str, str]
    results: tuple[
        _ProfileFinalizedResultSnapshot,
        _ProfileFinalizedResultSnapshot,
        _ProfileFinalizedResultSnapshot,
    ]


@dataclass(frozen=True, repr=False)
class _ProfileCandidateFinalizationInputs:
    candidate_ordinal: int
    candidate_authorization: object
    validation_evidence: AuthenticatedWorkerExecutionEvidence
    validation_snapshot: _ProfileValidationResolvedSnapshot
    fit_terminals: tuple[object, object, object]
    storage_observations: tuple[
        _ProfileNoReadNoWriteObservation,
        _ProfileNoReadNoWriteObservation,
    ]
    prepared_state: _PreparedCandidateState
    candidate_basis: _ProfileValidationCandidateBasis
    fit_rows: tuple[
        _ProfileFitScheduleReceiptRow,
        _ProfileFitScheduleReceiptRow,
        _ProfileFitScheduleReceiptRow,
    ]


_PROFILE_FINALIZED_RESULT_PUBLICATIONS: OneShotWeakRegistry[
    object, _ProfileFinalizedResultPublication
]
_PROFILE_FINALIZED_RESULT_PUBLICATION_ISSUER: OneShotRegistryIssuer[
    object, _ProfileFinalizedResultPublication
]
(
    _PROFILE_FINALIZED_RESULT_PUBLICATIONS,
    _PROFILE_FINALIZED_RESULT_PUBLICATION_ISSUER,
) = create_one_shot_registry()
_PROFILE_FINALIZED_RESULT_PUBLICATIONS_LOCK = Lock()

_PROFILE_FINALIZED_RESULT_GROUP_STATES: OneShotWeakRegistry[
    object, _ProfileFinalizedResultGroupState
]
_PROFILE_FINALIZED_RESULT_GROUP_STATE_ISSUER: OneShotRegistryIssuer[
    object, _ProfileFinalizedResultGroupState
]
(
    _PROFILE_FINALIZED_RESULT_GROUP_STATES,
    _PROFILE_FINALIZED_RESULT_GROUP_STATE_ISSUER,
) = create_one_shot_registry()


@final
class ProfileFinalizedResultGroup:
    """Opaque owner of exactly three profile-origin finalized results."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ProfileFinalizedResultGroup:
        raise TypeError("Profile finalized-result groups are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile finalized-result groups cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile finalized-result groups are immutable.")

    @property
    def result_count(self) -> int:
        return len(_read_profile_finalized_result_group(self).results)

    def __copy__(self) -> ProfileFinalizedResultGroup:
        raise TypeError("Profile finalized-result groups cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> ProfileFinalizedResultGroup:
        raise TypeError("Profile finalized-result groups cannot be copied or serialized.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Profile finalized-result groups cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Profile finalized-result groups cannot be copied or serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Profile finalized-result groups cannot be copied or serialized.")

    def __repr__(self) -> str:
        count = len(_read_profile_finalized_result_group(self).results)
        return f"ProfileFinalizedResultGroup(result_count={count})"


def _profile_finalized_result_publication(
    session: object,
) -> _ProfileFinalizedResultPublication:
    if type(session) is not ProfileFitSession:
        raise TypeError("A genuine profile fit session is required.")
    with _PROFILE_FINALIZED_RESULT_PUBLICATIONS_LOCK:
        publication = _PROFILE_FINALIZED_RESULT_PUBLICATIONS.get(session)
        if publication is None:
            publication = _ProfileFinalizedResultPublication()
            _PROFILE_FINALIZED_RESULT_PUBLICATION_ISSUER.bind_once(session, publication)
    if type(publication) is not _ProfileFinalizedResultPublication:
        raise TypeError("Profile finalized-result publication state is invalid.")
    return publication


def _closed_mapping(value: bytes, *, label: str) -> dict[str, Any]:
    decoded = strict_json_loads(value)
    if type(decoded) is not dict or canonical_json_bytes(decoded) != value:
        raise TypeError(f"{label} is not canonical closed JSON.")
    return cast(dict[str, Any], decoded)


def _candidate_inputs(
    session_state: _ProfileFitSessionState,
    candidate_ordinal: int,
) -> _ProfileCandidateFinalizationInputs:
    if (
        type(session_state) is not _ProfileFitSessionState
        or type(candidate_ordinal) is not int
        or candidate_ordinal not in {0, 1, 2}
    ):
        raise TypeError("Profile finalization candidate inputs are invalid.")
    snapshot = session_state.completion_snapshot
    group_state = snapshot.group_state
    candidate_positions = tuple(
        position
        for position, row in enumerate(snapshot.receipt_rows)
        if row.candidate_ordinal == candidate_ordinal
    )
    if len(candidate_positions) != 3:
        raise TypeError("Profile finalization lost an exact candidate slot owner.")
    slots = tuple(snapshot.slots[position] for position in candidate_positions)
    fit_rows = cast(
        tuple[
            _ProfileFitScheduleReceiptRow,
            _ProfileFitScheduleReceiptRow,
            _ProfileFitScheduleReceiptRow,
        ],
        tuple(snapshot.receipt_rows[position] for position in candidate_positions),
    )
    if (
        tuple(row.chain_plan_position for row in fit_rows) != (0, 1, 2)
        or any(
            row.candidate_authorization is not fit_rows[0].candidate_authorization
            or row.candidate_state is not fit_rows[0].candidate_state
            or row.validation_evidence is not fit_rows[0].validation_evidence
            or row.candidate_execution_context
            is not fit_rows[0].candidate_execution_context
            or row.candidate_execution_context_state
            is not fit_rows[0].candidate_execution_context_state
            or row.execution_input_projection_digest
            != fit_rows[0].execution_input_projection_digest
            for row in fit_rows[1:]
        )
    ):
        raise TypeError("Profile finalization lost an exact candidate slot owner.")
    candidate_state = fit_rows[0].candidate_state
    receipt_state = _bound_profile_fit_schedule_receipt(snapshot.receipt)
    if receipt_state is not snapshot.receipt_state:
        raise TypeError("Profile finalization lost its fit receipt.")
    candidate_basis = receipt_state.basis.candidates[candidate_ordinal]
    validation_snapshot = fit_rows[0].validation_snapshot
    if (
        candidate_basis.candidate_authorization
        is not fit_rows[0].candidate_authorization
        or candidate_basis.candidate_state is not candidate_state
        or any(
            row.validation_snapshot is not validation_snapshot
            for row in fit_rows[1:]
        )
    ):
        raise TypeError("Profile finalization candidate changed after validation.")
    validation_terminal = group_state.barrier_state.terminals[candidate_ordinal]
    validation_evidence = validation_terminal.evidence
    if (
        type(validation_evidence) is not AuthenticatedWorkerExecutionEvidence
        or validation_evidence is not fit_rows[0].validation_evidence
    ):
        raise TypeError("Profile finalization requires exact successful validation evidence.")

    plan = _closed_mapping(candidate_basis.plan_bytes, label="Profile candidate plan")
    planning_summary = _closed_mapping(
        candidate_basis.planning_summary_binding_bytes,
        label="Profile candidate planning summary",
    )
    record = _closed_mapping(candidate_basis.record_bytes, label="Profile candidate record")
    universe = _closed_mapping(candidate_basis.universe_bytes, label="Profile candidate universe")
    chain_plan = universe.get("chain_plan")
    timing = session_state.lifecycle_timings[candidate_ordinal]
    if (
        type(chain_plan) is not list
        or len(chain_plan) != _PROFILE_CHAIN_COUNT
        or any(type(row) is not dict for row in chain_plan)
        or timing.candidate_ordinal != candidate_ordinal
        or timing.validation_terminal is not validation_terminal
        or timing.final_fit_slot is not slots[2]
        or record.get("candidate_ordinal") != candidate_ordinal
        or tuple(cast(dict[str, Any], row).get("chain_execution_id") for row in chain_plan)
        != tuple(row.chain_execution_id for row in fit_rows)
    ):
        raise TypeError("Profile finalization candidate identity changed.")
    terminals = cast(
        tuple[object, object, object],
        tuple(snapshot.terminals[position] for position in candidate_positions),
    )
    observed = tuple(
        terminal
        for terminal in terminals
        if type(terminal) in {AuthenticatedWorkerExecutionEvidence, WorkerInvocationObservation}
    )
    prepared_state = _PreparedCandidateState(
        planning_summary_id=validated_planning_summary_id(planning_summary),
        prepared_execution_authorization=fit_rows[0].candidate_authorization,
        plan_digest=cast(str, plan["plan_digest"]),
        candidate_ordinal=candidate_ordinal,
        candidate_id=cast(str, record["candidate_id"]),
        analysis_spec_id=cast(str, record["analysis_spec_id"]),
        universe_id=cast(str, universe["universe_id"]),
        execution_input_projection_digest=(fit_rows[0].execution_input_projection_digest),
        ordered_chain_execution_ids=tuple(row.chain_execution_id for row in fit_rows),
        started_at_utc=timing.started_at_utc,
        ended_at_utc=timing.ended_at_utc,
        runtime_seconds=timing.runtime_seconds,
        validation_evidence=validation_evidence,
        fit_attempt_evidence=cast(tuple[Any, ...], observed),
        cache_lineage=None,
        canonical_dataset=None,
        prepared_candidate_execution_context=(fit_rows[0].candidate_execution_context),
        prepared_candidate_execution_context_state=(
            fit_rows[0].candidate_execution_context_state
        ),
        prepared_execution_state=candidate_state,
    )
    observations = session_state.storage_observations[candidate_ordinal]
    if type(observations) is not tuple or len(observations) != 2:
        raise TypeError("Profile finalization storage observations changed.")
    return _ProfileCandidateFinalizationInputs(
        candidate_ordinal=candidate_ordinal,
        candidate_authorization=fit_rows[0].candidate_authorization,
        validation_evidence=validation_evidence,
        validation_snapshot=validation_snapshot,
        fit_terminals=terminals,
        storage_observations=observations,
        prepared_state=prepared_state,
        candidate_basis=candidate_basis,
        fit_rows=fit_rows,
    )


def _profile_execution_policy_digest(
    observation: _ProfileNoReadNoWriteObservation,
) -> str:
    policy = _closed_mapping(
        observation.execution_policy_bytes,
        label="Profile execution policy",
    )
    digest: str = structured_sha256(
        "ebm-audit/profile-execution-policy/1",
        policy,
    )
    return digest


def _profile_storage_guard_receipt_digest(
    session_state: _ProfileFitSessionState,
    *,
    execution_policy_digest: str,
) -> str:
    receipt = session_state.storage_guard_receipt
    ordered_rows = session_state.completion_snapshot.receipt_rows
    preimage = {
        "guard_receipt_schema_version": "ebm-audit-profile-storage-guard-receipt/1.0",
        "ordered_fit_slot_bindings": [
            {
                "runtime_position": state.runtime_position,
                "runtime_profile_position": state.runtime_profile_position,
                "profile_id": state.profile_id,
                "candidate_ordinal": state.candidate_ordinal,
                "chain_plan_position": state.chain_plan_position,
                "universe_id": state.universe_id,
                "chain_execution_id": state.chain_execution_id,
                "attempt_id": state.attempt_id,
                "attempt_ordinal": state.attempt_ordinal,
            }
            for state in ordered_rows
        ],
        "execution_policy_digest": execution_policy_digest,
        "cache_read_count": receipt.cache_read_count,
        "cache_write_count": receipt.cache_write_count,
        "checkpoint_read_count": receipt.checkpoint_read_count,
        "checkpoint_write_count": receipt.checkpoint_write_count,
        "runtime_scope_completed": receipt.runtime_scope_completed,
    }
    digest: str = structured_sha256(
        "ebm-audit/profile-storage-guard-receipt/1",
        preimage,
    )
    return digest


def _profile_storage_observation_record(
    session_state: _ProfileFitSessionState,
    inputs: _ProfileCandidateFinalizationInputs,
    observation: _ProfileNoReadNoWriteObservation,
) -> dict[str, Any]:
    candidate = _closed_mapping(
        inputs.candidate_basis.record_bytes,
        label="Profile storage candidate record",
    )
    universe = _closed_mapping(
        inputs.candidate_basis.universe_bytes,
        label="Profile storage candidate universe",
    )
    covered = inputs.fit_rows
    execution_policy_digest = _profile_execution_policy_digest(observation)
    preimage = {
        "observation_schema_version": "ebm-audit-profile-storage-observation/1.0",
        "resource": observation.resource,
        "policy": "NO_READ_NO_WRITE",
        "candidate_ordinal": inputs.candidate_ordinal,
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "universe_id": universe["universe_id"],
        "covered_chain_execution_ids": [state.chain_execution_id for state in covered],
        "covered_attempt_ids": [state.attempt_id for state in covered],
        "read_count": observation.read_count,
        "write_count": observation.write_count,
        "execution_policy_digest": execution_policy_digest,
        "guard_receipt_digest": _profile_storage_guard_receipt_digest(
            session_state,
            execution_policy_digest=execution_policy_digest,
        ),
    }
    value = {
        **preimage,
        "observation_digest": structured_sha256(
            "ebm-audit/profile-storage-observation/1",
            preimage,
        ),
    }
    validate_instance(
        value,
        "canonical-records.schema.json",
        definition="ProfileNoReadNoWriteObservation",
    )
    return value


def _profile_unobserved_reference(
    terminal: object,
    slot_state: _ProfileFitScheduleReceiptRow,
) -> dict[str, Any]:
    _require_profile_fit_unobserved_core_failure(terminal)
    value = {
        "evidence_reference_schema_version": (
            "ebm-audit-profile-fit-unobserved-core-failure-reference/1.0"
        ),
        "kind": "PROFILE_UNOBSERVED_CORE_FAILURE",
        "command": "fit",
        "status": "PROTOCOL_ERROR",
        "runtime_position": slot_state.runtime_position,
        "runtime_profile_position": slot_state.runtime_profile_position,
        "profile_id": slot_state.profile_id,
        "candidate_ordinal": slot_state.candidate_ordinal,
        "chain_plan_position": slot_state.chain_plan_position,
        "universe_id": slot_state.universe_id,
        "chain_id": slot_state.chain_id,
        "chain_execution_id": slot_state.chain_execution_id,
        "attempt_id": slot_state.attempt_id,
        "attempt_ordinal": slot_state.attempt_ordinal,
        "failure_code": "PROFILE_FIT.UNOBSERVED_CORE_FAILURE",
    }
    validate_instance(
        value,
        "canonical-records.schema.json",
        definition="ProfileFitUnobservedCoreFailureReference",
    )
    return value


def _profile_unobserved_error() -> dict[str, Any]:
    return {
        "code": "PROFILE_FIT.UNOBSERVED_CORE_FAILURE",
        "category": "PROTOCOL_ERROR",
        "safe_message": core_owned_negative_response_message("PROTOCOL_ERROR"),
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


def _resolve_profile_fit_terminals(
    inputs: _ProfileCandidateFinalizationInputs,
) -> tuple[
    tuple[_ResolvedAttempt | None, _ResolvedAttempt | None, _ResolvedAttempt | None],
    tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
]:
    resolved: list[_ResolvedAttempt | None] = []
    references: list[Mapping[str, Any]] = []
    state = inputs.prepared_state
    for terminal, slot_state in zip(
        inputs.fit_terminals,
        inputs.fit_rows,
        strict=True,
    ):
        if type(terminal) is _ProfileFitUnobservedCoreFailure:
            resolved.append(None)
            references.append(_profile_unobserved_reference(terminal, slot_state))
            continue
        attempt = _resolve_attempt(
            terminal,
            expected_command="fit",
            chain_plan_position=slot_state.chain_plan_position,
            expected_planning_summary_id=state.planning_summary_id,
        )
        _assert_fit_attempt_identity(attempt, universe_id=state.universe_id)
        if (
            attempt.chain_execution_id != slot_state.chain_execution_id
            or attempt.attempt_id != slot_state.attempt_id
            or attempt.attempt_ordinal != 0
        ):
            raise TypeError("Profile fit terminal changed its exact slot identity.")
        resolved.append(attempt)
        references.append(attempt.reference)
    return (
        cast(
            tuple[
                _ResolvedAttempt | None,
                _ResolvedAttempt | None,
                _ResolvedAttempt | None,
            ],
            tuple(resolved),
        ),
        cast(
            tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
            tuple(references),
        ),
    )


def _selected_profile_negative_position(
    resolved: tuple[
        _ResolvedAttempt | None,
        _ResolvedAttempt | None,
        _ResolvedAttempt | None,
    ],
) -> int:
    statuses = tuple(
        "PROTOCOL_ERROR" if attempt is None else attempt.status for attempt in resolved
    )
    for status in _NEGATIVE_STATUS_PRECEDENCE:
        for position, observed in enumerate(statuses):
            if observed == status:
                return position
    raise TypeError("Profile fit finalization has no negative terminal evidence.")


def _profile_candidate_body(
    session_state: _ProfileFitSessionState,
    inputs: _ProfileCandidateFinalizationInputs,
) -> dict[str, Any]:
    state = inputs.prepared_state
    validation = _resolved_profile_validation_attempt(
        inputs.validation_snapshot,
    )
    if (
        validation.capability is not inputs.validation_evidence
        or validation.planning_summary_id != state.planning_summary_id
        or validation.status != "SUCCESS"
        or validation.response is None
        or validation.response["payload"].get("fit_permitted") is not True
    ):
        raise TypeError("Profile result finalization requires fit-permitted validation.")
    resolved, references = _resolve_profile_fit_terminals(inputs)
    observed = tuple(attempt for attempt in resolved if attempt is not None)
    owner = _assert_scientific_owner_binding(
        state,
        validation,
        tuple((attempt,) for attempt in observed),
    )
    flattened = (validation, *observed)
    prepared = _prepared_core(
        owner,
        validation,
        tuple((attempt,) for attempt in observed),
        cache_lineage=None,
    )
    prepared["fit_attempt_evidence"] = [copy.deepcopy(dict(reference)) for reference in references]
    prepared["execution_origin"] = "PROFILE"
    prepared["profile_storage_observations"] = [
        _profile_storage_observation_record(session_state, inputs, observation)
        for observation in inputs.storage_observations
    ]

    if any(attempt is None or attempt.status != "SUCCESS" for attempt in resolved):
        selected_position = _selected_profile_negative_position(resolved)
        selected = resolved[selected_position]
        body: dict[str, Any] = _candidate_core(
            state,
            owner,
            kind="EXECUTION_NON_SUCCESS",
            status=("PROTOCOL_ERROR" if selected is None else selected.status),
            attempts=flattened,
        )
        body.update(prepared)
        body.update(
            {
                "failed_command": "fit",
                "error": (
                    _profile_unobserved_error() if selected is None else _negative_error(selected)
                ),
                "diagnostic_references": [],
                "side_effects_reference": None,
            }
        )
        return body

    successful = cast(
        tuple[_ResolvedAttempt, _ResolvedAttempt, _ResolvedAttempt],
        resolved,
    )
    chain_payloads = tuple(
        _chain_payload(attempt, chain_plan_position=position)
        for position, attempt in enumerate(successful)
    )
    event_ids = chain_payloads[0]["event_ids"]
    if any(payload["event_ids"] != event_ids for payload in chain_payloads[1:]):
        raise TypeError("Profile scientific finalization has inconsistent event owners.")
    convergence = _convergence(successful, chain_payloads)
    status = _CONVERGENCE_STATUS[cast(str, convergence["assessment"])]
    kind = "COMPLETED" if status in {"SUCCESS", "CONVERGENCE_WARN"} else "CONVERGENCE_NON_SUCCESS"
    body = _candidate_core(
        state,
        owner,
        kind=kind,
        status=status,
        attempts=flattened,
    )
    body.update(prepared)
    first = chain_payloads[0]
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
    return body


def _profile_result_matches_inputs(
    state: _FinalizedResultState,
    inputs: _ProfileCandidateFinalizationInputs,
) -> bool:
    return (
        state.execution_origin == "PROFILE"
        and state.candidate_result_authorization is inputs.candidate_authorization
        and state.profile_candidate_ordinal == inputs.candidate_ordinal
        and state.profile_validation_evidence is inputs.validation_evidence
        and len(state.profile_fit_terminals) == _PROFILE_CHAIN_COUNT
        and all(
            retained is current
            for retained, current in zip(
                state.profile_fit_terminals,
                inputs.fit_terminals,
                strict=True,
            )
        )
        and len(state.profile_storage_observations) == 2
        and all(
            retained is current
            for retained, current in zip(
                state.profile_storage_observations,
                inputs.storage_observations,
                strict=True,
            )
        )
    )


def _validate_profile_finalized_result_group_state(
    value: ProfileFinalizedResultGroup,
    state: _ProfileFinalizedResultGroupState,
    *,
    publication_status: str,
) -> None:
    if (
        type(state) is not _ProfileFinalizedResultGroupState
        or type(state.publication) is not _ProfileFinalizedResultPublication
        or state.publication_token is not state.publication.token
        or type(state.session) is not ProfileFitSession
        or type(state.session_state) is not _ProfileFitSessionState
        or type(state.results) is not tuple
        or len(state.results) != _PROFILE_RESULT_COUNT
        or type(state.result_states) is not tuple
        or len(state.result_states) != _PROFILE_RESULT_COUNT
    ):
        raise TypeError("Profile finalized-result group storage is invalid.")
    with state.publication.lock:
        published = None if state.publication.group_ref is None else state.publication.group_ref()
        if state.publication.status != publication_status or published is not value:
            raise TypeError("Profile finalized-result group publication changed.")
    current_session_state = _read_profile_fit_session(state.session)
    if current_session_state is not state.session_state:
        raise TypeError("Profile finalized-result group changed its exact session.")
    for ordinal, (result, retained_state) in enumerate(
        zip(state.results, state.result_states, strict=True)
    ):
        current_state = _read_finalized_result(result)
        if (
            current_state is not retained_state
            or current_state.profile_fit_session is not state.session
            or current_state.profile_fit_slot_group is not state.session_state.group
            or current_state.profile_candidate_ordinal != ordinal
        ):
            raise TypeError("Profile finalized-result group changed a result owner.")
    _PROFILE_FINALIZED_RESULT_GROUP_STATES.require(value, state)


def _read_profile_finalized_result_group(
    value: object,
) -> _ProfileFinalizedResultGroupState:
    state: _ProfileFinalizedResultGroupState | None = None
    if type(value) is ProfileFinalizedResultGroup:
        try:
            state = _PROFILE_FINALIZED_RESULT_GROUP_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _ProfileFinalizedResultGroupState:
        raise TypeError("A genuine profile finalized-result group is required.")
    _validate_profile_finalized_result_group_state(
        cast(ProfileFinalizedResultGroup, value),
        state,
        publication_status="PUBLISHED",
    )
    return state


def _snapshot_profile_finalized_result_group(
    value: object,
) -> _ProfileFinalizedResultGroupSnapshot:
    """Copy persistence-safe fields only after one locked whole-group readback."""

    state = _read_profile_finalized_result_group(value)
    group = cast(ProfileFinalizedResultGroup, value)
    with state.publication.lock:
        _validate_profile_finalized_result_group_state(
            group,
            state,
            publication_status="PUBLISHED",
        )
        completion = state.session_state.completion_snapshot
        prepared_group = completion.group_state.barrier_state.group
        prepared_gate = _read_profile_prepared_candidate_group(prepared_group)
        if (
            prepared_gate
            is not completion.group_state.barrier_state.group_state
        ):
            raise TypeError("Profile finalized-result group changed its prepared owner.")

        snapshots: list[_ProfileFinalizedResultSnapshot] = []
        for ordinal, (result, retained_state) in enumerate(
            zip(state.results, state.result_states, strict=True)
        ):
            current_state = _read_finalized_result(result)
            record = strict_json_loads(current_state.canonical_bytes)
            if (
                type(record) is not dict
                or validate_result_record_finalization(record) != record
                or type(record.get("body")) is not dict
            ):
                raise TypeError("Profile finalized-result storage is invalid.")
            body = cast(dict[str, Any], record["body"])
            if (
                current_state is not retained_state
                or current_state.profile_candidate_ordinal != ordinal
                or body.get("candidate_ordinal") != ordinal
                or body.get("analysis_spec_id")
                != completion.ordered_analysis_spec_ids[ordinal]
                or record.get("result_id") != current_state.result_id
            ):
                raise TypeError("Profile finalized-result group changed a result binding.")
            snapshots.append(
                _ProfileFinalizedResultSnapshot(
                    candidate_ordinal=ordinal,
                    result_id=current_state.result_id,
                    canonical_bytes=bytes(current_state.canonical_bytes),
                )
            )

        return _ProfileFinalizedResultGroupSnapshot(
            profile_execution_identity_sha256=(
                completion.profile_execution_identity_sha256
            ),
            coordinate_ordinal=completion.coordinate_ordinal,
            ordered_analysis_spec_ids=completion.ordered_analysis_spec_ids,
            results=cast(
                tuple[
                    _ProfileFinalizedResultSnapshot,
                    _ProfileFinalizedResultSnapshot,
                    _ProfileFinalizedResultSnapshot,
                ],
                tuple(snapshots),
            ),
        )


def finalize_profile_fit_session(
    session: ProfileFitSession,
) -> ProfileFinalizedResultGroup:
    """Atomically publish exactly three profile-only finalized result owners."""

    publication = _profile_finalized_result_publication(session)
    with publication.lock:
        existing = None if publication.group_ref is None else publication.group_ref()
        if existing is None:
            if publication.status != "FRESH":
                raise TypeError("The profile finalization publication was already consumed.")
            publication.status = "ACTIVATING"
            try:
                session_state = _read_profile_fit_session(session)
                _reattest_profile_source_at_phase_boundary(
                    session_state.group_state.barrier_state.group,
                    session_state.group_state.barrier_state.group_state,
                )
                results: list[FinalizedResult] = []
                result_states: list[_FinalizedResultState] = []
                for candidate_ordinal in range(_PROFILE_RESULT_COUNT):
                    inputs = _candidate_inputs(session_state, candidate_ordinal)
                    result = _issue_profile_finalized_result(
                        _PROFILE_FINALIZATION_ISSUER,
                        body=_profile_candidate_body(session_state, inputs),
                        candidate_result_authorization=(inputs.candidate_authorization),
                        profile_fit_session=session,
                        profile_fit_slot_group=session_state.group,
                        profile_candidate_ordinal=candidate_ordinal,
                        profile_validation_evidence=inputs.validation_evidence,
                        profile_fit_terminals=inputs.fit_terminals,
                        profile_storage_observations=inputs.storage_observations,
                    )
                    retained_state = _capture_finalized_result_state_identity(
                        result
                    )
                    if not _profile_result_matches_inputs(retained_state, inputs):
                        raise TypeError(
                            "Profile finalization lost an exact candidate result owner."
                        )
                    results.append(result)
                    result_states.append(retained_state)
                group = object.__new__(ProfileFinalizedResultGroup)
                group_state = _ProfileFinalizedResultGroupState(
                    publication=publication,
                    publication_token=publication.token,
                    session=session,
                    session_state=session_state,
                    results=cast(
                        tuple[FinalizedResult, FinalizedResult, FinalizedResult],
                        tuple(results),
                    ),
                    result_states=cast(
                        tuple[
                            _FinalizedResultState,
                            _FinalizedResultState,
                            _FinalizedResultState,
                        ],
                        tuple(result_states),
                    ),
                )
                group_reference = ref(group)
                publication.group_ref = group_reference
                _PROFILE_FINALIZED_RESULT_GROUP_STATE_ISSUER.bind_once(
                    group,
                    group_state,
                )
                _validate_profile_finalized_result_group_state(
                    group,
                    group_state,
                    publication_status="ACTIVATING",
                )
                publication.group_ref = group_reference
                publication.status = "PUBLISHED"
                _read_profile_finalized_result_group(group)
            except BaseException:
                publication.group_ref = None
                publication.status = "CONSUMED"
                raise
            return group

    published_group = existing
    _read_profile_finalized_result_group(published_group)
    return published_group


__all__ = [
    "ProfileFinalizedResultGroup",
    "finalize_profile_fit_session",
]
