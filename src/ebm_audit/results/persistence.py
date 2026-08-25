"""Capability-gated, create-exclusive persistence for finalized candidate results.

Serialized result mappings, caller-supplied digests, and caller-supplied terminal
rows are never accepted here.  The journal consumes only exact in-process core
capabilities, commits canonical bytes through :class:`PrivateArtifactStore`,
rereads the private file, derives its exact-file digest, and only then appends
the result-derived candidate terminal to the ordered lifecycle authority.

The cache API in this module is deliberately write-side only.  Attaching to an
existing run root does not recreate ``FinalizedResult`` or
``VerifiedCacheLineage`` authority from bytes.  Cross-process cache reuse stays
fail-closed until execution orchestration can issue an authenticated
persisted-execution bundle from retained request/execution evidence and the
current Plan/3 owner.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING, Any, Literal, Never, SupportsIndex, cast, final
from weakref import ReferenceType, ref

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.adapters import AuthenticatedWorkerExecutionEvidence
from ebm_audit.artifacts import PrivateArtifactStore
from ebm_audit.errors import InvalidInputError
from ebm_audit.lifecycle import (
    _CANDIDATE_TERMINAL_AUTHORIZATION_ISSUER,
    CandidateTerminalAuthorization,
    PlanCandidateAuthorization,
    _append_candidate_terminal_authorization,
    _candidate_terminal_projection_from_prevalidated_state,
    _candidate_terminal_rows,
    _CandidateTerminalAuthorizationState,
    _issue_candidate_terminal_authorization,
    _plan_baseline_candidate_row,
    _plan_candidate_preparation_publication_token,
    _plan_candidate_rows,
    _read_candidate_terminal_authorization,
    _read_plan_candidate_authorization,
    _require_candidate_terminal_authorization_state,
)
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
    structured_sha256,
    validate_result_record_finalization,
)
from ebm_audit.schema import validate_instance
from ebm_audit.universe import PreparationTransaction
from ebm_audit.universe._influence_receipt import (
    _InfluencePreparationInputReceipt,
    _InfluencePreparationInputSnapshot,
    _read_influence_preparation_input_receipt,
)
from ebm_audit.universe.identities import (
    _plan_preimage,
    _receipt_preimage,
    analysis_plan_digest,
    preparation_receipt_digest,
)
from ebm_audit.universe.preparation import (
    _capture_preparation_transaction_candidate_state_identities,
    _capture_preparation_transaction_state_identity,
    _preparation_transaction_influence_input_receipt,
    _preparation_transaction_publication_token,
    _require_preparation_transaction_candidate_state_identities_current,
)

from .finalization import (
    FinalizedResult,
    VerifiedCacheLineage,
    _candidate_terminal_from_finalized_result_state,
    _capture_finalized_result_state,
    _capture_finalized_result_state_identity,
    _finalized_result_cache_admission_bytes_from_state,
    _finalized_result_candidate_authorization_from_state,
    _finalized_result_descriptive_chain_executions_from_state,
    _finalized_result_persistence_bytes_from_state,
    _FinalizedResultState,
    _require_finalized_result_state_identity,
)

if TYPE_CHECKING:
    from ebm_audit.science import SealedScientificEvidence

_RESULT_DIRECTORY = "results"
_TERMINAL_DIRECTORY = "state/candidate-terminals"
_TERMINAL_INDEX_PATH = "state/candidate-terminal-index.json"
_CACHE_DIRECTORY = "cache/results"
_JOURNAL_CREATION_LOCK = RLock()
_SEALED_TERMINAL_INDEX_ISSUER = object()
_CORE_WARNING_MESSAGE = "The worker reported a structured warning."
_CONVERGENCE_WARNING_MESSAGE = "The candidate completed with a convergence warning."
_SCIENCE_GATE_WARNING_MESSAGE = "The science completion gate is not satisfied."
_LEDGER_PROJECTION_ERROR = "Terminal ledger projection failed."
_FAILURE_LEDGER_SCHEMA_VERSION = "ebm-audit-failure-ledger/2.0"
_WARNING_LEDGER_SCHEMA_VERSION = "ebm-audit-warning-ledger/2.0"
_SCIENCE_LEDGER_RECEIPT_SCHEMA_VERSION = "ebm-audit-science-ledger-receipt/1.0"
_SCIENCE_LEDGER_RECEIPT_DIGEST_DOMAIN = "ebm-audit/science-ledger-receipt/1"
_SEALED_SCIENTIFIC_EVIDENCE_SCHEMA_VERSION = "ebm-audit-sealed-scientific-evidence/10.0"
_SEALED_SCIENTIFIC_EVIDENCE_RULE_ID = (
    "within-fit-chain-sampling-analyst-decision-participant-influence-null-evidence-rules/10"
)


def _reject_capability_copy() -> Never:
    raise TypeError("Result-persistence capabilities cannot be copied or serialized.")


def _result_path(candidate_ordinal: int) -> str:
    return f"{_RESULT_DIRECTORY}/candidate-{candidate_ordinal:08d}.json"


def _terminal_path(candidate_ordinal: int) -> str:
    return f"{_TERMINAL_DIRECTORY}/{candidate_ordinal:08d}.json"


def _cache_path(candidate_ordinal: int) -> str:
    return f"{_CACHE_DIRECTORY}/candidate-{candidate_ordinal:08d}.json"


def _read_optional(store: PrivateArtifactStore, relative_path: str) -> bytes | None:
    try:
        return store.read_bytes(relative_path)
    except InvalidInputError as exc:
        if exc.code == "SPEC.OUTPUT_MISSING":
            return None
        raise


def _commit_exact_bytes(
    store: PrivateArtifactStore,
    relative_path: str,
    content: bytes,
    *,
    mismatch_code: str,
    mismatch_message: str,
) -> bytes:
    """Create exact bytes or accept only their exact create-once replay."""

    try:
        store.write_bytes(relative_path, content)
    except InvalidInputError as exc:
        if exc.code != "SPEC.OUTPUT_ALREADY_EXISTS":
            raise
    readback = store.read_bytes(relative_path, maximum_bytes=len(content))
    if readback != content:
        raise InvalidInputError(mismatch_code, mismatch_message)
    return readback


def _closed_result_identity(canonical: bytes) -> tuple[str, int, str, str]:
    record = strict_json_loads(canonical)
    if type(record) is not dict or type(record.get("body")) is not dict:
        raise TypeError("Finalized-result storage is invalid.")
    body = cast(dict[str, Any], record["body"])
    try:
        plan_digest = body["plan_digest"]
        ordinal = body["candidate_ordinal"]
        candidate_id = body["candidate_id"]
        analysis_spec_id = body["analysis_spec_id"]
    except KeyError:
        raise TypeError("Finalized-result storage is invalid.") from None
    if (
        type(plan_digest) is not str
        or type(ordinal) is not int
        or type(candidate_id) is not str
        or type(analysis_spec_id) is not str
    ):
        raise TypeError("Finalized-result storage is invalid.")
    return plan_digest, ordinal, candidate_id, analysis_spec_id


@dataclass(frozen=True, repr=False)
class _PersistedFinalizedResultState:
    store: PrivateArtifactStore
    finalized_result: FinalizedResult
    canonical_bytes: bytes
    terminal_bytes: bytes
    result_digest: str
    candidate_ordinal: int
    result_path: str
    terminal_path: str


@final
class PersistedFinalizedResult:
    """Opaque proof that one exact finalized result and terminal are durable."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("PersistedFinalizedResult cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Persisted results are issued by the result journal only.")

    @property
    def result_digest(self) -> str:
        return _read_persisted_result(self).result_digest

    @property
    def candidate_ordinal(self) -> int:
        return _read_persisted_result(self).candidate_ordinal

    def __repr__(self) -> str:
        state = _read_persisted_result(self)
        return f"PersistedFinalizedResult(candidate_ordinal={state.candidate_ordinal})"

    def __copy__(self) -> PersistedFinalizedResult:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> PersistedFinalizedResult:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()


_PERSISTED_RESULT_STATES: OneShotWeakRegistry[
    PersistedFinalizedResult, _PersistedFinalizedResultState
]
_PERSISTED_RESULT_STATE_ISSUER: OneShotRegistryIssuer[
    PersistedFinalizedResult, _PersistedFinalizedResultState
]
_PERSISTED_RESULT_STATES, _PERSISTED_RESULT_STATE_ISSUER = create_one_shot_registry()


def _read_persisted_result(value: object) -> _PersistedFinalizedResultState:
    state, _finalized_state = _read_persisted_result_and_finalized_state(value)
    return state


def _read_persisted_result_and_finalized_state(
    value: object,
) -> tuple[_PersistedFinalizedResultState, _FinalizedResultState]:
    if type(value) is not PersistedFinalizedResult:
        raise TypeError("A genuine persisted finalized-result capability is required.")
    try:
        state = _PERSISTED_RESULT_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine persisted finalized-result capability is required.") from None
    finalized_state = _capture_finalized_result_state(state.finalized_result)
    return (
        _read_persisted_result_with_states(
            value,
            state,
            finalized_state=finalized_state,
        ),
        finalized_state,
    )


def _read_persisted_result_with_states(
    value: object,
    state: _PersistedFinalizedResultState,
    *,
    finalized_state: _FinalizedResultState,
) -> _PersistedFinalizedResultState:
    """Read one persisted owner from this call's validated finalized state."""

    _require_persisted_result_state_identity(value, state)
    finalized_result = state.finalized_result
    _require_finalized_result_state_identity(finalized_result, finalized_state)
    try:
        if type(state.store) is not PrivateArtifactStore:
            raise TypeError("Persisted finalized-result authority is invalid.")
        canonical = _finalized_result_persistence_bytes_from_state(
            finalized_result,
            finalized_state,
        )
        terminal = _candidate_terminal_from_finalized_result_state(
            finalized_result,
            finalized_state,
        )
        result_readback = state.store.read_bytes(
            state.result_path,
            maximum_bytes=len(state.canonical_bytes),
        )
        terminal_readback = state.store.read_bytes(
            state.terminal_path,
            maximum_bytes=len(state.terminal_bytes),
        )
        if (
            canonical != state.canonical_bytes
            or canonical_json_bytes(terminal) != state.terminal_bytes
            or exact_file_sha256(canonical) != state.result_digest
            or terminal["result_digest"] != state.result_digest
            or terminal["candidate_ordinal"] != state.candidate_ordinal
            or result_readback != state.canonical_bytes
            or terminal_readback != state.terminal_bytes
        ):
            raise InvalidInputError(
                "RESULT.PERSISTED_BYTES_MISMATCH",
                "Persisted candidate artifacts no longer match their exact authority.",
            )
        return state
    finally:
        _require_finalized_result_state_identity(finalized_result, finalized_state)
        _require_persisted_result_state_identity(value, state)


def _require_persisted_result_state_identity(
    value: object,
    state: object,
) -> _PersistedFinalizedResultState:
    if (
        type(value) is not PersistedFinalizedResult
        or type(state) is not _PersistedFinalizedResultState
    ):
        raise TypeError("A genuine persisted finalized-result capability is required.")
    try:
        _PERSISTED_RESULT_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError("A genuine persisted finalized-result capability is required.") from None
    return state


def _capture_persisted_result_state_identity(
    value: object,
) -> _PersistedFinalizedResultState:
    """Capture registry identity after this boundary fully validated the owner."""

    if type(value) is not PersistedFinalizedResult:
        raise TypeError("A genuine persisted finalized-result capability is required.")
    try:
        state = _PERSISTED_RESULT_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine persisted finalized-result capability is required.") from None
    return _require_persisted_result_state_identity(value, state)


def _validate_persisted_result_owner(value: object) -> None:
    _read_persisted_result(value)


@dataclass(frozen=True, repr=False)
class _PersistedCacheResultState:
    store: PrivateArtifactStore
    finalized_result: FinalizedResult
    cache_lineage: VerifiedCacheLineage
    canonical_bytes: bytes
    artifact_digest: str
    candidate_ordinal: int
    cache_path: str


@final
class PersistedCacheResult:
    """Opaque proof that one exact cache-admissible result is durable."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("PersistedCacheResult cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Persisted cache results are issued by the result journal only.")

    @property
    def artifact_digest(self) -> str:
        return _read_persisted_cache_result(self).artifact_digest

    def __repr__(self) -> str:
        state = _read_persisted_cache_result(self)
        return f"PersistedCacheResult(candidate_ordinal={state.candidate_ordinal})"

    def __copy__(self) -> PersistedCacheResult:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> PersistedCacheResult:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()


_PERSISTED_CACHE_STATES: OneShotWeakRegistry[PersistedCacheResult, _PersistedCacheResultState]
_PERSISTED_CACHE_STATE_ISSUER: OneShotRegistryIssuer[
    PersistedCacheResult, _PersistedCacheResultState
]
_PERSISTED_CACHE_STATES, _PERSISTED_CACHE_STATE_ISSUER = create_one_shot_registry()


def _read_persisted_cache_result(value: object) -> _PersistedCacheResultState:
    if type(value) is not PersistedCacheResult:
        raise TypeError("A genuine persisted cache-result capability is required.")
    try:
        state = _PERSISTED_CACHE_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine persisted cache-result capability is required.") from None
    finalized_state = _capture_finalized_result_state(state.finalized_result)
    return _read_persisted_cache_result_with_states(
        value,
        state,
        finalized_state=finalized_state,
    )


def _read_persisted_cache_result_with_states(
    value: object,
    state: _PersistedCacheResultState,
    *,
    finalized_state: _FinalizedResultState,
) -> _PersistedCacheResultState:
    """Read one cache owner from this call's validated finalized state."""

    _require_persisted_cache_result_state_identity(value, state)
    finalized_result = state.finalized_result
    _require_finalized_result_state_identity(finalized_result, finalized_state)
    try:
        if type(state.store) is not PrivateArtifactStore:
            raise TypeError("Persisted cache-result authority is invalid.")
        canonical = _finalized_result_cache_admission_bytes_from_state(
            finalized_result,
            finalized_state,
            state.cache_lineage,
        )
        readback = state.store.read_bytes(
            state.cache_path,
            maximum_bytes=len(state.canonical_bytes),
        )
        if (
            canonical != state.canonical_bytes
            or exact_file_sha256(canonical) != state.artifact_digest
            or readback != state.canonical_bytes
        ):
            raise InvalidInputError(
                "RESULT.CACHE_BYTES_MISMATCH",
                "The persisted cache artifact no longer matches its exact authority.",
            )
        return state
    finally:
        _require_finalized_result_state_identity(finalized_result, finalized_state)
        _require_persisted_cache_result_state_identity(value, state)


def _require_persisted_cache_result_state_identity(
    value: object,
    state: object,
) -> _PersistedCacheResultState:
    if type(value) is not PersistedCacheResult or type(state) is not _PersistedCacheResultState:
        raise TypeError("A genuine persisted cache-result capability is required.")
    try:
        _PERSISTED_CACHE_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError("A genuine persisted cache-result capability is required.") from None
    return state


def _capture_persisted_cache_result_state_identity(
    value: object,
) -> _PersistedCacheResultState:
    """Capture registry identity after this boundary fully validated the owner."""

    if type(value) is not PersistedCacheResult:
        raise TypeError("A genuine persisted cache-result capability is required.")
    try:
        state = _PERSISTED_CACHE_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine persisted cache-result capability is required.") from None
    return _require_persisted_cache_result_state_identity(value, state)


@dataclass(frozen=True, repr=False)
class _SealedCandidateTerminalIndexState:
    store: PrivateArtifactStore
    plan_candidate_authorization: PlanCandidateAuthorization
    terminal_authorization: CandidateTerminalAuthorization
    canonical_bytes: bytes
    artifact_digest: str


@final
class SealedCandidateTerminalIndex:
    """Opaque proof of the complete, persisted candidate-terminal index."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("SealedCandidateTerminalIndex cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Candidate-terminal indexes are sealed by the result journal only.")

    @property
    def artifact_digest(self) -> str:
        return _read_sealed_terminal_index(self).artifact_digest

    def __repr__(self) -> str:
        state = _read_sealed_terminal_index(self)
        rows = _candidate_terminal_rows(state.terminal_authorization)
        return f"SealedCandidateTerminalIndex(terminal_count={len(rows)})"

    def __copy__(self) -> SealedCandidateTerminalIndex:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> SealedCandidateTerminalIndex:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()


_SEALED_INDEX_STATES: OneShotWeakRegistry[
    SealedCandidateTerminalIndex, _SealedCandidateTerminalIndexState
]
_SEALED_INDEX_STATE_ISSUER: OneShotRegistryIssuer[
    SealedCandidateTerminalIndex, _SealedCandidateTerminalIndexState
]
_SEALED_INDEX_STATES, _SEALED_INDEX_STATE_ISSUER = create_one_shot_registry()


def _read_sealed_terminal_index(value: object) -> _SealedCandidateTerminalIndexState:
    state = _capture_sealed_terminal_index_state_identity(value)
    rows = _candidate_terminal_rows(state.terminal_authorization)
    return _validate_sealed_terminal_index_state_with_rows(value, state, rows)


def _capture_sealed_terminal_index_state_identity(
    value: object,
) -> _SealedCandidateTerminalIndexState:
    if type(value) is not SealedCandidateTerminalIndex:
        raise TypeError("A genuine sealed candidate-terminal index is required.")
    try:
        state = _SEALED_INDEX_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine sealed candidate-terminal index is required.") from None
    return _require_sealed_terminal_index_state_identity(value, state)


def _validate_sealed_terminal_index_state_with_rows(
    value: object,
    state: _SealedCandidateTerminalIndexState,
    rows: tuple[dict[str, Any], ...],
) -> _SealedCandidateTerminalIndexState:
    """Validate index bytes from terminal rows already validated by this boundary."""

    _require_sealed_terminal_index_state_identity(value, state)
    try:
        if type(state.store) is not PrivateArtifactStore:
            raise TypeError("Sealed candidate-terminal index authority is invalid.")
        plan_state = _read_plan_candidate_authorization(state.plan_candidate_authorization)
        terminal_state = _read_candidate_terminal_authorization(state.terminal_authorization)
        planned = _plan_candidate_rows(state.plan_candidate_authorization)
        expected = canonical_json_bytes(
            {
                "candidate_terminal_index_schema_version": (
                    "ebm-audit-candidate-terminal-index/1.0"
                ),
                "plan_digest": plan_state.plan_digest,
                "candidate_terminals": list(rows),
            }
        )
        readback = state.store.read_bytes(
            _TERMINAL_INDEX_PATH,
            maximum_bytes=len(state.canonical_bytes),
        )
        if (
            terminal_state.plan_candidate_authorization is not state.plan_candidate_authorization
            or len(rows) != len(planned)
            or state.canonical_bytes != expected
            or exact_file_sha256(expected) != state.artifact_digest
            or readback != state.canonical_bytes
        ):
            raise InvalidInputError(
                "RESULT.TERMINAL_INDEX_BYTES_MISMATCH",
                "The candidate-terminal index no longer matches its exact authority.",
            )
        return state
    finally:
        _require_sealed_terminal_index_state_identity(value, state)


def _require_sealed_terminal_index_state_identity(
    value: object,
    state: object,
) -> _SealedCandidateTerminalIndexState:
    if (
        type(value) is not SealedCandidateTerminalIndex
        or type(state) is not _SealedCandidateTerminalIndexState
    ):
        raise TypeError("A genuine sealed candidate-terminal index is required.")
    try:
        _SEALED_INDEX_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError("A genuine sealed candidate-terminal index is required.") from None
    return state


def _issue_sealed_candidate_terminal_index(
    issuer: object,
    *,
    store: object,
    plan_candidate_authorization: object,
    terminal_authorization: object,
    canonical_bytes: object,
    prevalidated_terminal_rows: tuple[dict[str, Any], ...] | None = None,
) -> SealedCandidateTerminalIndex:
    """Private issuer used only after the exact index file already exists."""

    if issuer is not _SEALED_TERMINAL_INDEX_ISSUER:
        raise TypeError("Candidate-terminal index authority has no public issuer.")
    if (
        type(store) is not PrivateArtifactStore
        or type(plan_candidate_authorization) is not PlanCandidateAuthorization
        or type(terminal_authorization) is not CandidateTerminalAuthorization
        or type(canonical_bytes) is not bytes
    ):
        raise TypeError("Candidate-terminal index authority requires exact persisted owners.")
    exact_store = store
    plan_authorization = plan_candidate_authorization
    terminal_owner = terminal_authorization
    plan_state = _read_plan_candidate_authorization(plan_authorization)
    terminal_state = _read_candidate_terminal_authorization(terminal_owner)
    rows = (
        _candidate_terminal_rows(terminal_owner)
        if prevalidated_terminal_rows is None
        else prevalidated_terminal_rows
    )
    planned = _plan_candidate_rows(plan_authorization)
    expected_record = {
        "candidate_terminal_index_schema_version": ("ebm-audit-candidate-terminal-index/1.0"),
        "plan_digest": plan_state.plan_digest,
        "candidate_terminals": list(rows),
    }
    validate_instance(
        expected_record,
        "run-artifacts.schema.json",
        definition="CandidateTerminalIndex",
    )
    expected_bytes = canonical_json_bytes(expected_record)
    if (
        terminal_state.plan_candidate_authorization is not plan_authorization
        or len(rows) != len(planned)
        or canonical_bytes != expected_bytes
        or exact_store.read_bytes(
            _TERMINAL_INDEX_PATH,
            maximum_bytes=len(expected_bytes),
        )
        != expected_bytes
    ):
        raise TypeError("Candidate-terminal index authority requires exact persisted owners.")
    sealed = object.__new__(SealedCandidateTerminalIndex)
    sealed_state = _SealedCandidateTerminalIndexState(
        store=exact_store,
        plan_candidate_authorization=plan_authorization,
        terminal_authorization=terminal_owner,
        canonical_bytes=expected_bytes,
        artifact_digest=exact_file_sha256(expected_bytes),
    )
    _SEALED_INDEX_STATE_ISSUER.bind_once(sealed, sealed_state)
    _validate_sealed_terminal_index_state_with_rows(
        sealed,
        sealed_state,
        rows,
    )
    return sealed


@dataclass(repr=False)
class _ResultPersistenceJournalState:
    store: PrivateArtifactStore
    plan_candidate_authorization: PlanCandidateAuthorization
    preparation_transaction: PreparationTransaction
    influence_input_receipt: _InfluencePreparationInputReceipt
    influence_input_snapshot: _InfluencePreparationInputSnapshot
    candidate_result_authorizations: tuple[object, ...]
    terminal_authorization: CandidateTerminalAuthorization
    persisted_cache_results: list[PersistedCacheResult]
    sealed_terminal_index: SealedCandidateTerminalIndex | None
    sealed_result_evidence_set: SealedResultEvidenceSet | None
    lock: RLock


@dataclass(frozen=True, slots=True)
class _ClosedResultJournalTombstone:
    run_root_id: str
    reason: Literal["ABANDONED", "CLOSED"]


def _require_exact_influence_input_snapshot(
    snapshot: object,
    plan_candidate_authorization: object,
) -> _InfluencePreparationInputSnapshot:
    """Bind one retained preparation snapshot to the exact Plan projection."""

    if (
        type(snapshot) is not _InfluencePreparationInputSnapshot
        or type(plan_candidate_authorization) is not PlanCandidateAuthorization
    ):
        raise TypeError("Influence preparation receipt has no exact Plan/3 source.")
    plan_state = _read_plan_candidate_authorization(plan_candidate_authorization)
    try:
        plan = strict_json_loads(snapshot.plan_bytes)
        receipt = strict_json_loads(snapshot.preparation_receipt_bytes)
        candidates = strict_json_loads(snapshot.plan_candidates_bytes)
        edges = strict_json_loads(snapshot.origin_comparison_edges_bytes)
        baseline = strict_json_loads(snapshot.baseline_candidate_bytes)
        expected_plan_digest = analysis_plan_digest(_plan_preimage(plan))
        expected_preparation_receipt_digest = preparation_receipt_digest(_receipt_preimage(receipt))
        projected = _plan_candidate_rows(plan_candidate_authorization)
        projected_baseline = _plan_baseline_candidate_row(plan_candidate_authorization)
    except (KeyError, TypeError, ValueError):
        raise TypeError("Influence preparation receipt has no exact Plan/3 source.") from None
    if (
        type(plan) is not dict
        or canonical_json_bytes(plan) != snapshot.plan_bytes
        or type(receipt) is not dict
        or canonical_json_bytes(receipt) != snapshot.preparation_receipt_bytes
        or type(candidates) is not list
        or canonical_json_bytes(candidates) != snapshot.plan_candidates_bytes
        or type(edges) is not list
        or canonical_json_bytes(edges) != snapshot.origin_comparison_edges_bytes
        or type(baseline) is not dict
        or canonical_json_bytes(baseline) != snapshot.baseline_candidate_bytes
        or plan.get("plan_digest") != snapshot.plan_digest
        or expected_plan_digest != snapshot.plan_digest
        or receipt.get("receipt_digest") != snapshot.preparation_receipt_digest
        or expected_preparation_receipt_digest != snapshot.preparation_receipt_digest
        or receipt.get("plan_digest") != snapshot.plan_digest
        or plan.get("baseline_analysis_spec_id") != snapshot.baseline_analysis_spec_id
        or plan.get("candidates") != candidates
        or plan.get("origin_comparison_edges") != edges
        or snapshot.plan_digest != plan_state.plan_digest
        or len(candidates) != len(projected)
        or any(
            type(candidate) is not dict
            or (
                candidate.get("candidate_ordinal"),
                candidate.get("candidate_id"),
                candidate.get("analysis_spec_id"),
            )
            != (
                row["candidate_ordinal"],
                row["candidate_id"],
                row["analysis_spec_id"],
            )
            for candidate, row in zip(candidates, projected, strict=True)
        )
        or (
            baseline.get("candidate_ordinal"),
            baseline.get("candidate_id"),
            baseline.get("analysis_spec_id"),
        )
        != (
            projected_baseline["candidate_ordinal"],
            projected_baseline["candidate_id"],
            projected_baseline["analysis_spec_id"],
        )
        or baseline != candidates[cast(int, projected_baseline["candidate_ordinal"])]
    ):
        raise TypeError("Influence preparation receipt has no exact Plan/3 source.")
    return snapshot


_JOURNALS_BY_RUN_ROOT_ID: dict[
    str,
    ReferenceType[ResultPersistenceJournal] | _ClosedResultJournalTombstone,
] = {}


@final
class ResultPersistenceJournal:
    """One ordered result-persistence authority for one authenticated run root."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("ResultPersistenceJournal cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Result journals are opened from exact core authorities only.")

    @property
    def plan_candidate_authorization(self) -> PlanCandidateAuthorization:
        return _read_result_journal(self).plan_candidate_authorization

    @property
    def candidate_terminal_authorization(self) -> CandidateTerminalAuthorization:
        return _read_result_journal(self).terminal_authorization

    @property
    def preparation_transaction(self) -> PreparationTransaction:
        return _read_result_journal(self).preparation_transaction

    def __repr__(self) -> str:
        rows = _candidate_terminal_rows(_read_result_journal(self).terminal_authorization)
        return f"ResultPersistenceJournal(terminal_count={len(rows)})"

    def __copy__(self) -> ResultPersistenceJournal:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> ResultPersistenceJournal:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()


_RESULT_JOURNAL_STATES: OneShotWeakRegistry[
    ResultPersistenceJournal, _ResultPersistenceJournalState
]
_RESULT_JOURNAL_STATE_ISSUER: OneShotRegistryIssuer[
    ResultPersistenceJournal, _ResultPersistenceJournalState
]
_RESULT_JOURNAL_STATES, _RESULT_JOURNAL_STATE_ISSUER = create_one_shot_registry()


def _validate_result_journal_state(
    value: object,
    state: _ResultPersistenceJournalState,
) -> _ResultPersistenceJournalState:
    _require_result_journal_state_identity(value, state)
    try:
        if (
            type(state.store) is not PrivateArtifactStore
            or type(state.plan_candidate_authorization) is not PlanCandidateAuthorization
            or type(state.preparation_transaction) is not PreparationTransaction
            or type(state.influence_input_receipt) is not _InfluencePreparationInputReceipt
            or type(state.influence_input_snapshot) is not _InfluencePreparationInputSnapshot
            or type(state.candidate_result_authorizations) is not tuple
            or type(state.terminal_authorization) is not CandidateTerminalAuthorization
            or type(state.persisted_cache_results) is not list
        ):
            raise TypeError("A genuine result-persistence journal is required.")
        transaction_authorizations = _preparation_transaction_authorizations(
            state.preparation_transaction,
            state.plan_candidate_authorization,
        )
        influence_input = _read_influence_preparation_input_receipt(state.influence_input_receipt)
        _require_exact_influence_input_snapshot(
            state.influence_input_snapshot,
            state.plan_candidate_authorization,
        )
        if influence_input is not state.influence_input_snapshot:
            raise TypeError("Result-persistence journal preparation authority is invalid.")
        if len(transaction_authorizations) != len(state.candidate_result_authorizations) or any(
            current is not retained
            for current, retained in zip(
                transaction_authorizations,
                state.candidate_result_authorizations,
                strict=True,
            )
        ):
            raise TypeError("Result-persistence journal preparation authority is invalid.")
        terminal_state = _read_candidate_terminal_authorization(state.terminal_authorization)
        if terminal_state.plan_candidate_authorization is not state.plan_candidate_authorization:
            raise TypeError("Result-persistence journal authority is invalid.")
        terminal_rows, owners = _candidate_terminal_projection_from_prevalidated_state(
            state.terminal_authorization,
            terminal_state,
        )
        if len(owners) > len(transaction_authorizations):
            raise TypeError("Result-persistence journal authority is invalid.")
        finalized_states: dict[FinalizedResult, _FinalizedResultState] = {}
        for ordinal, owner in enumerate(owners):
            persisted, finalized_state = _read_persisted_result_and_finalized_state(owner)
            if (
                persisted.candidate_ordinal != ordinal
                or _finalized_result_candidate_authorization_from_state(
                    persisted.finalized_result,
                    finalized_state,
                )
                is not transaction_authorizations[ordinal]
                or canonical_json_bytes(terminal_rows[ordinal]) != persisted.terminal_bytes
            ):
                raise TypeError("Result-persistence journal authority is invalid.")
            if persisted.finalized_result in finalized_states:
                raise TypeError("Result-persistence journal authority is invalid.")
            finalized_states[persisted.finalized_result] = finalized_state
        for cached in state.persisted_cache_results:
            cached_state = _capture_persisted_cache_result_state_identity(cached)
            try:
                cached_finalized_state = finalized_states[cached_state.finalized_result]
            except KeyError:
                raise TypeError("Result-persistence journal authority is invalid.") from None
            _read_persisted_cache_result_with_states(
                cached,
                cached_state,
                finalized_state=cached_finalized_state,
            )
            _require_exact_result_authorization(
                state,
                cached_state.finalized_result,
                cached_state.candidate_ordinal,
                finalized_result_state=cached_finalized_state,
            )
        if state.sealed_terminal_index is not None:
            sealed_value = state.sealed_terminal_index
            sealed = _capture_sealed_terminal_index_state_identity(sealed_value)
            _validate_sealed_terminal_index_state_with_rows(
                sealed_value,
                sealed,
                terminal_rows,
            )
            if (
                sealed.plan_candidate_authorization is not state.plan_candidate_authorization
                or sealed.terminal_authorization is not state.terminal_authorization
            ):
                raise TypeError("Result-persistence journal authority is invalid.")
        if state.sealed_result_evidence_set is not None:
            evidence_value = state.sealed_result_evidence_set
            try:
                evidence = _SEALED_RESULT_EVIDENCE_SET_STATES[evidence_value]
            except (KeyError, TypeError):
                raise TypeError("Result-persistence journal authority is invalid.") from None
            _require_sealed_result_evidence_set_state_identity(
                evidence_value,
                evidence,
            )
            validated_finalized_results = tuple(
                _capture_persisted_result_state_identity(owner).finalized_result for owner in owners
            )
            if (
                state.sealed_terminal_index is None
                or evidence.plan_candidate_authorization is not state.plan_candidate_authorization
                or evidence.preparation_transaction is not state.preparation_transaction
                or evidence.influence_input_receipt is not state.influence_input_receipt
                or evidence.influence_input_snapshot is not state.influence_input_snapshot
                or len(evidence.candidate_result_authorizations)
                != len(state.candidate_result_authorizations)
                or any(
                    current is not retained
                    for current, retained in zip(
                        evidence.candidate_result_authorizations,
                        state.candidate_result_authorizations,
                        strict=True,
                    )
                )
                or evidence.terminal_authorization is not state.terminal_authorization
                or evidence.sealed_terminal_index is not state.sealed_terminal_index
                or len(evidence.persisted_cache_results) != len(state.persisted_cache_results)
                or any(
                    current is not retained
                    for current, retained in zip(
                        evidence.persisted_cache_results,
                        state.persisted_cache_results,
                        strict=True,
                    )
                )
                or len(evidence.persisted_results) != len(owners)
                or any(
                    current is not retained
                    for current, retained in zip(
                        evidence.persisted_results,
                        owners,
                        strict=True,
                    )
                )
                or len(evidence.finalized_results) != len(validated_finalized_results)
                or any(
                    current is not retained
                    for current, retained in zip(
                        evidence.finalized_results,
                        validated_finalized_results,
                        strict=True,
                    )
                )
                or len(evidence.descriptive_chain_execution_sets) != len(evidence.finalized_results)
                or any(
                    evidence.descriptive_chain_execution_sets[ordinal]
                    != _finalized_result_descriptive_chain_executions_from_state(
                        finalized,
                        finalized_states[finalized],
                    )
                    for ordinal, finalized in enumerate(evidence.finalized_results)
                )
            ):
                raise TypeError("Result-persistence journal authority is invalid.")
        return state
    finally:
        _require_result_journal_state_identity(value, state)


def _require_result_journal_state_identity(
    value: object,
    state: object,
) -> _ResultPersistenceJournalState:
    """Require a captured journal state without resolving a replacement state."""

    if (
        type(value) is not ResultPersistenceJournal
        or type(state) is not _ResultPersistenceJournalState
    ):
        raise TypeError("A genuine result-persistence journal is required.")
    try:
        _RESULT_JOURNAL_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError("A genuine result-persistence journal is required.") from None
    return state


def _require_result_journal_state_graph_identity(
    value: object,
    state: _ResultPersistenceJournalState,
) -> None:
    """Require the immutable one-shot root binding after child revalidation."""

    _require_result_journal_state_identity(value, state)


@contextmanager
def _locked_result_journal_state(
    journal: object,
    state: _ResultPersistenceJournalState,
) -> Iterator[_ResultPersistenceJournalState]:
    """Bind one operation to exactly one captured journal authority graph."""

    _require_result_journal_state_identity(journal, state)
    with state.lock:
        _require_result_journal_state_identity(journal, state)
        try:
            yield state
        finally:
            _require_result_journal_state_identity(journal, state)


def _read_result_journal(value: object) -> _ResultPersistenceJournalState:
    if type(value) is not ResultPersistenceJournal:
        raise TypeError("A genuine result-persistence journal is required.")
    try:
        state = _RESULT_JOURNAL_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine result-persistence journal is required.") from None
    return _validate_result_journal_state(value, state)


def _prevalidated_terminal_projection(
    state: _ResultPersistenceJournalState,
) -> tuple[tuple[dict[str, Any], ...], tuple[object, ...]]:
    """Project terminal entries already validated by this exact journal boundary."""

    terminal_state = _read_candidate_terminal_authorization(state.terminal_authorization)
    return _candidate_terminal_projection_from_prevalidated_state(
        state.terminal_authorization,
        terminal_state,
    )


def _reread_prevalidated_persisted_artifacts(
    state: _ResultPersistenceJournalState,
    owners: tuple[object, ...],
) -> None:
    """Reread every durable artifact without replaying scientific owner validation."""

    finalized_states: dict[FinalizedResult, _FinalizedResultState] = {}
    for owner in owners:
        persisted_state = _capture_persisted_result_state_identity(owner)
        finalized_result = persisted_state.finalized_result
        finalized_state = _capture_finalized_result_state_identity(finalized_result)
        _read_persisted_result_with_states(
            owner,
            persisted_state,
            finalized_state=finalized_state,
        )
        finalized_states[finalized_result] = finalized_state
    for cached in state.persisted_cache_results:
        cached_state = _capture_persisted_cache_result_state_identity(cached)
        try:
            finalized_state = finalized_states[cached_state.finalized_result]
        except KeyError:
            raise TypeError("Result-persistence journal authority is invalid.") from None
        _read_persisted_cache_result_with_states(
            cached,
            cached_state,
            finalized_state=finalized_state,
        )


def _preparation_transaction_authorizations(
    preparation_transaction: object,
    plan_candidate_authorization: PlanCandidateAuthorization,
) -> tuple[object, ...]:
    """Revalidate one exact transaction against the current Plan/3 authority."""

    if (
        type(preparation_transaction) is not PreparationTransaction
        or type(plan_candidate_authorization) is not PlanCandidateAuthorization
    ):
        raise TypeError("A genuine preparation transaction is required.")
    plan_state = _read_plan_candidate_authorization(plan_candidate_authorization)
    transaction_state = preparation_transaction._state()
    candidate_states = _capture_preparation_transaction_candidate_state_identities(
        transaction_state
    )
    transaction_plan = strict_json_loads(transaction_state.plan_bytes)
    receipt = strict_json_loads(transaction_state.receipt_bytes)
    if type(receipt) is not dict:
        raise TypeError("Preparation transaction is detached from the exact Plan/3 authority.")
    receipt_records = receipt.get("records")
    planned = _plan_candidate_rows(plan_candidate_authorization)
    authorizations = transaction_state.candidate_authorizations
    if (
        type(transaction_plan) is not dict
        or type(receipt_records) is not list
        or _plan_candidate_preparation_publication_token(plan_candidate_authorization)
        is not _preparation_transaction_publication_token(preparation_transaction)
        or transaction_plan.get("plan_digest") != plan_state.plan_digest
        or len(receipt_records) != len(planned)
        or len(authorizations) != len(planned)
    ):
        raise TypeError("Preparation transaction is detached from the exact Plan/3 authority.")
    for ordinal, (record, planned_row, authorization) in enumerate(
        zip(receipt_records, planned, authorizations, strict=True)
    ):
        if (
            type(record) is not dict
            or (
                record.get("candidate_ordinal"),
                record.get("candidate_id"),
                record.get("analysis_spec_id"),
            )
            != (
                ordinal,
                planned_row["candidate_id"],
                planned_row["analysis_spec_id"],
            )
            or transaction_state.candidate_authorizations[ordinal] is not authorization
        ):
            raise TypeError("Preparation transaction is detached from the exact Plan/3 authority.")
    if (
        _capture_preparation_transaction_state_identity(preparation_transaction)
        is not transaction_state
    ):
        raise TypeError("Preparation transaction is detached from the exact Plan/3 authority.")
    _require_preparation_transaction_candidate_state_identities_current(
        transaction_state,
        candidate_states,
    )
    return cast(tuple[object, ...], authorizations)


def _require_exact_result_authorization(
    state: _ResultPersistenceJournalState,
    finalized_result: FinalizedResult,
    ordinal: int,
    *,
    finalized_result_state: _FinalizedResultState,
) -> None:
    """Require authorization from this call's validated journal and result states."""

    result_authorization = _finalized_result_candidate_authorization_from_state(
        finalized_result,
        finalized_result_state,
    )
    if (
        type(ordinal) is not int
        or ordinal < 0
        or ordinal >= len(state.candidate_result_authorizations)
        or result_authorization is not state.candidate_result_authorizations[ordinal]
    ):
        raise TypeError(
            "Finalized result is detached from the journal's exact preparation transaction."
        )


def open_result_persistence_journal(
    store: object,
    plan_candidate_authorization: object,
    preparation_transaction: object,
) -> ResultPersistenceJournal:
    """Open or return the sole in-process journal for one freshly created run root."""

    if type(store) is not PrivateArtifactStore:
        raise TypeError("An exact private artifact store is required.")
    if type(plan_candidate_authorization) is not PlanCandidateAuthorization:
        raise TypeError("A genuine Plan/3 candidate authorization is required.")
    if type(preparation_transaction) is not PreparationTransaction:
        raise TypeError("A genuine preparation transaction is required.")
    _read_plan_candidate_authorization(plan_candidate_authorization)
    candidate_result_authorizations = _preparation_transaction_authorizations(
        preparation_transaction,
        plan_candidate_authorization,
    )
    influence_input_receipt = _preparation_transaction_influence_input_receipt(
        preparation_transaction
    )
    influence_input = _read_influence_preparation_input_receipt(influence_input_receipt)
    _require_exact_influence_input_snapshot(
        influence_input,
        plan_candidate_authorization,
    )
    private_store = store
    plan_authorization = plan_candidate_authorization
    exact_transaction = preparation_transaction
    if private_store.attachment_mode != "CREATED_FRESH":
        raise TypeError(
            "Existing run roots require the pending authenticated persisted-execution authority."
        )
    with _JOURNAL_CREATION_LOCK:
        existing = _JOURNALS_BY_RUN_ROOT_ID.get(private_store.run_root_id)
        if existing is not None:
            if type(existing) is _ClosedResultJournalTombstone:
                if existing.reason == "ABANDONED":
                    raise TypeError("The private run root has an abandoned result journal.")
                raise TypeError("The private run root has a closed result journal.")
            if not isinstance(existing, ReferenceType):
                raise TypeError("The private run root result-journal state is invalid.")
            existing_journal = existing()
            if existing_journal is None:
                _JOURNALS_BY_RUN_ROOT_ID[private_store.run_root_id] = _ClosedResultJournalTombstone(
                    private_store.run_root_id,
                    "ABANDONED",
                )
                raise TypeError("The private run root has an abandoned result journal.")
            state = _read_result_journal(existing_journal)
            if (
                state.store is not private_store
                or state.plan_candidate_authorization is not plan_authorization
                or state.preparation_transaction is not exact_transaction
                or state.influence_input_receipt is not influence_input_receipt
                or state.influence_input_snapshot is not influence_input
                or len(state.candidate_result_authorizations)
                != len(candidate_result_authorizations)
                or any(
                    current is not retained
                    for current, retained in zip(
                        state.candidate_result_authorizations,
                        candidate_result_authorizations,
                        strict=True,
                    )
                )
            ):
                raise TypeError("The private run root already has a different result journal.")
            return existing_journal
        terminal_authorization = _issue_candidate_terminal_authorization(
            _CANDIDATE_TERMINAL_AUTHORIZATION_ISSUER,
            plan_candidate_authorization=plan_authorization,
        )
        journal = object.__new__(ResultPersistenceJournal)
        journal_state = _ResultPersistenceJournalState(
            store=private_store,
            plan_candidate_authorization=plan_authorization,
            preparation_transaction=exact_transaction,
            influence_input_receipt=influence_input_receipt,
            influence_input_snapshot=influence_input,
            candidate_result_authorizations=candidate_result_authorizations,
            terminal_authorization=terminal_authorization,
            persisted_cache_results=[],
            sealed_terminal_index=None,
            sealed_result_evidence_set=None,
            lock=RLock(),
        )
        _RESULT_JOURNAL_STATE_ISSUER.bind_once(journal, journal_state)
        _validate_result_journal_state(journal, journal_state)

        run_root_id = private_store.run_root_id
        journal_reference = ref(journal)
        _JOURNALS_BY_RUN_ROOT_ID[run_root_id] = journal_reference
        return journal


def persist_finalized_candidate(
    journal: object,
    finalized_result: object,
) -> PersistedFinalizedResult:
    """Persist, reread, digest, and terminalize one exact next Plan/3 candidate."""

    state = _read_result_journal(journal)
    return _persist_finalized_candidate_with_state(journal, state, finalized_result)


def _persist_finalized_candidate_with_state(
    journal: object,
    state: _ResultPersistenceJournalState,
    finalized_result: object,
) -> PersistedFinalizedResult:
    """Persist through one executor-captured journal state only."""

    persisted, _finalized_state = _persist_finalized_candidate_with_state_capture(
        journal,
        state,
        finalized_result,
    )
    return persisted


def _persist_finalized_candidate_with_state_capture(
    journal: object,
    state: _ResultPersistenceJournalState,
    finalized_result: object,
    *,
    prevalidated_finalized_state: _FinalizedResultState | None = None,
) -> tuple[PersistedFinalizedResult, _FinalizedResultState]:
    """Persist once and retain the exact finalized state validated by this boundary."""

    with _locked_result_journal_state(journal, state):
        if state.sealed_result_evidence_set is not None:
            raise TypeError("Result persistence is closed after evidence sealing.")
        _require_live_result_journal_registration(journal, state)
        _terminal_rows, owners = _prevalidated_terminal_projection(state)
        matching_persisted_state: _PersistedFinalizedResultState | None = None
        for owner in owners:
            existing_state = _capture_persisted_result_state_identity(owner)
            if existing_state.finalized_result is finalized_result:
                matching_persisted_state = existing_state
                break
        exact_result = cast(FinalizedResult, finalized_result)
        if matching_persisted_state is None:
            finalized_state = (
                _capture_finalized_result_state(exact_result)
                if prevalidated_finalized_state is None
                else _require_finalized_result_state_identity(
                    exact_result,
                    prevalidated_finalized_state,
                )
            )
        else:
            finalized_state = _capture_finalized_result_state_identity(exact_result)
            if (
                prevalidated_finalized_state is not None
                and finalized_state is not prevalidated_finalized_state
            ):
                raise TypeError("Finalized result state changed.")
        canonical = _finalized_result_persistence_bytes_from_state(
            exact_result,
            finalized_state,
        )
        plan_digest, ordinal, candidate_id, analysis_spec_id = _closed_result_identity(canonical)
        _require_exact_result_authorization(
            state,
            exact_result,
            ordinal,
            finalized_result_state=finalized_state,
        )
        if ordinal < len(owners):
            existing = _capture_persisted_result_state_identity(owners[ordinal])
            if existing.finalized_result is not exact_result:
                raise TypeError("A different finalized result already owns this candidate.")
            result_readback = state.store.read_bytes(
                existing.result_path,
                maximum_bytes=len(existing.canonical_bytes),
            )
            terminal_readback = state.store.read_bytes(
                existing.terminal_path,
                maximum_bytes=len(existing.terminal_bytes),
            )
            if (
                result_readback != existing.canonical_bytes
                or terminal_readback != existing.terminal_bytes
            ):
                raise InvalidInputError(
                    "RESULT.PERSISTED_BYTES_MISMATCH",
                    "Persisted candidate artifacts no longer match their exact authority.",
                )
            return cast(PersistedFinalizedResult, owners[ordinal]), finalized_state
        if ordinal != len(owners):
            raise TypeError("Finalized results must persist in the exact Plan/3 prefix order.")
        plan_state = _read_plan_candidate_authorization(state.plan_candidate_authorization)
        planned = _plan_candidate_rows(state.plan_candidate_authorization)
        if ordinal >= len(planned):
            raise TypeError("Finalized result is not an authorized Plan/3 candidate.")
        planned_row = planned[ordinal]
        if plan_digest != plan_state.plan_digest or (
            ordinal,
            candidate_id,
            analysis_spec_id,
        ) != (
            planned_row["candidate_ordinal"],
            planned_row["candidate_id"],
            planned_row["analysis_spec_id"],
        ):
            raise TypeError("Finalized result is not the exact next Plan/3 candidate.")
        result_path = _result_path(ordinal)
        terminal_path = _terminal_path(ordinal)
        existing_result = _read_optional(state.store, result_path)
        existing_terminal = _read_optional(state.store, terminal_path)
        if existing_terminal is not None and existing_result is None:
            raise InvalidInputError(
                "RESULT.TERMINAL_BEFORE_RESULT",
                "A candidate terminal cannot exist before its exact result artifact.",
            )
        _require_live_result_journal_registration(journal, state)
        result_readback = _commit_exact_bytes(
            state.store,
            result_path,
            canonical,
            mismatch_code="RESULT.PERSISTED_BYTES_MISMATCH",
            mismatch_message=(
                "The persisted result artifact does not match its finalized authority."
            ),
        )
        persisted_digest = exact_file_sha256(result_readback)
        terminal = _candidate_terminal_from_finalized_result_state(
            exact_result,
            finalized_state,
        )
        if terminal["result_digest"] != persisted_digest or (
            terminal["candidate_ordinal"],
            terminal["candidate_id"],
            terminal["analysis_spec_id"],
        ) != (ordinal, candidate_id, analysis_spec_id):
            raise TypeError("The result-derived candidate terminal is invalid.")
        terminal_bytes = canonical_json_bytes(terminal)
        _require_live_result_journal_registration(journal, state)
        _commit_exact_bytes(
            state.store,
            terminal_path,
            terminal_bytes,
            mismatch_code="RESULT.TERMINAL_BYTES_MISMATCH",
            mismatch_message=(
                "The persisted candidate terminal does not match its result authority."
            ),
        )
        _require_live_result_journal_registration(journal, state)
        persisted = object.__new__(PersistedFinalizedResult)
        persisted_state = _PersistedFinalizedResultState(
            store=state.store,
            finalized_result=exact_result,
            canonical_bytes=canonical,
            terminal_bytes=terminal_bytes,
            result_digest=persisted_digest,
            candidate_ordinal=ordinal,
            result_path=result_path,
            terminal_path=terminal_path,
        )
        _PERSISTED_RESULT_STATE_ISSUER.bind_once(persisted, persisted_state)
        _require_persisted_result_state_identity(persisted, persisted_state)

        def validate_new_persisted_owner(value: object) -> None:
            if value is not persisted:
                raise TypeError("A genuine persisted finalized-result capability is required.")
            _read_persisted_result_with_states(
                value,
                persisted_state,
                finalized_state=finalized_state,
            )

        _require_live_result_journal_registration(journal, state)
        _append_candidate_terminal_authorization(
            _CANDIDATE_TERMINAL_AUTHORIZATION_ISSUER,
            state.terminal_authorization,
            terminal=terminal,
            persisted_owner=persisted,
            persisted_owner_validator=_validate_persisted_result_owner,
            persisted_owner_prevalidated_validator=validate_new_persisted_owner,
        )
        _require_live_result_journal_registration(journal, state)
        _require_persisted_result_state_identity(persisted, persisted_state)
        _retained_rows, retained = _prevalidated_terminal_projection(state)
        if ordinal >= len(retained) or retained[ordinal] is not persisted:
            raise TypeError("Result persistence lost its exact terminal owner.")
        return persisted, finalized_state


def persisted_candidate_terminals(journal: object) -> tuple[dict[str, Any], ...]:
    """Return a readback copy of the exact persisted terminal prefix."""

    state = _read_result_journal(journal)
    with _locked_result_journal_state(journal, state):
        rows, _owners = _prevalidated_terminal_projection(state)
        return tuple(dict(row) for row in rows)


def all_candidates_terminal(journal: object) -> bool:
    """Report exact full Plan/3 terminal coverage without inferring missing rows."""

    state = _read_result_journal(journal)
    with _locked_result_journal_state(journal, state):
        rows, _owners = _prevalidated_terminal_projection(state)
        return len(rows) == len(_plan_candidate_rows(state.plan_candidate_authorization))


def _journal_root_registration(
    journal: object,
    state: _ResultPersistenceJournalState,
) -> Literal["LIVE", "ABANDONED", "CLOSED"]:
    current = _JOURNALS_BY_RUN_ROOT_ID.get(state.store.run_root_id)
    if (
        type(current) is _ClosedResultJournalTombstone
        and current.run_root_id == state.store.run_root_id
    ):
        return current.reason
    if isinstance(current, ReferenceType):
        owner = current()
        if owner is journal:
            return "LIVE"
        if owner is None:
            _JOURNALS_BY_RUN_ROOT_ID[state.store.run_root_id] = _ClosedResultJournalTombstone(
                state.store.run_root_id,
                "ABANDONED",
            )
            return "ABANDONED"
    raise TypeError("The private run root result-journal state is invalid.")


def _require_live_result_journal_registration(
    journal: object,
    state: _ResultPersistenceJournalState,
) -> None:
    """Require the exact captured journal graph to remain the live run-root owner."""

    _require_result_journal_state_graph_identity(journal, state)
    with _JOURNAL_CREATION_LOCK:
        _require_result_journal_state_graph_identity(journal, state)
        registration = _journal_root_registration(journal, state)
        if registration != "LIVE":
            if registration == "ABANDONED":
                raise TypeError("The private run root has an abandoned result journal.")
            raise TypeError("The private run root has a closed result journal.")


def seal_candidate_terminal_index(journal: object) -> SealedCandidateTerminalIndex:
    """Persist the complete terminal index only after exact all-candidate coverage."""

    state = _read_result_journal(journal)
    return _seal_candidate_terminal_index_with_state(journal, state)


def _seal_candidate_terminal_index_with_state(
    journal: object,
    state: _ResultPersistenceJournalState,
) -> SealedCandidateTerminalIndex:
    """Seal the index through one executor-captured journal state only."""

    with _locked_result_journal_state(journal, state):
        rows, owners = _prevalidated_terminal_projection(state)
        _reread_prevalidated_persisted_artifacts(state, owners)
        if state.sealed_terminal_index is not None:
            with _JOURNAL_CREATION_LOCK:
                registration = _journal_root_registration(journal, state)
                if registration == "ABANDONED" or (
                    state.sealed_result_evidence_set is None and registration != "LIVE"
                ):
                    raise TypeError("The private run root result-journal state is invalid.")
            sealed_state = _capture_sealed_terminal_index_state_identity(
                state.sealed_terminal_index
            )
            _validate_sealed_terminal_index_state_with_rows(
                state.sealed_terminal_index,
                sealed_state,
                rows,
            )
            readback = state.store.read_bytes(
                _TERMINAL_INDEX_PATH,
                maximum_bytes=len(sealed_state.canonical_bytes),
            )
            if readback != sealed_state.canonical_bytes:
                raise InvalidInputError(
                    "RESULT.TERMINAL_INDEX_BYTES_MISMATCH",
                    "The candidate-terminal index no longer matches its exact authority.",
                )
            return state.sealed_terminal_index
        _require_live_result_journal_registration(journal, state)
        plan_state = _read_plan_candidate_authorization(state.plan_candidate_authorization)
        planned = _plan_candidate_rows(state.plan_candidate_authorization)
        if len(rows) != len(planned):
            raise TypeError("The candidate-terminal index requires exact complete coverage.")
        index_record = {
            "candidate_terminal_index_schema_version": ("ebm-audit-candidate-terminal-index/1.0"),
            "plan_digest": plan_state.plan_digest,
            "candidate_terminals": list(rows),
        }
        validate_instance(
            index_record,
            "run-artifacts.schema.json",
            definition="CandidateTerminalIndex",
        )
        content = canonical_json_bytes(index_record)
        _require_live_result_journal_registration(journal, state)
        readback = _commit_exact_bytes(
            state.store,
            _TERMINAL_INDEX_PATH,
            content,
            mismatch_code="RESULT.TERMINAL_INDEX_BYTES_MISMATCH",
            mismatch_message=("The candidate-terminal index does not match its exact authority."),
        )
        _require_live_result_journal_registration(journal, state)
        sealed = _issue_sealed_candidate_terminal_index(
            _SEALED_TERMINAL_INDEX_ISSUER,
            store=state.store,
            plan_candidate_authorization=state.plan_candidate_authorization,
            terminal_authorization=state.terminal_authorization,
            canonical_bytes=readback,
            prevalidated_terminal_rows=rows,
        )
        _require_live_result_journal_registration(journal, state)
        state.sealed_terminal_index = sealed
        return sealed


def candidate_terminal_index_digest(value: object) -> str:
    """Return the exact persisted index-file digest from its sealed capability."""

    return _read_sealed_terminal_index(value).artifact_digest


@dataclass(frozen=True, repr=False)
class _SealedResultEvidenceSetState:
    plan_candidate_authorization: PlanCandidateAuthorization
    preparation_transaction: PreparationTransaction
    influence_input_receipt: _InfluencePreparationInputReceipt
    influence_input_snapshot: _InfluencePreparationInputSnapshot
    candidate_result_authorizations: tuple[object, ...]
    terminal_authorization: CandidateTerminalAuthorization
    sealed_terminal_index: SealedCandidateTerminalIndex
    persisted_results: tuple[PersistedFinalizedResult, ...]
    persisted_cache_results: tuple[PersistedCacheResult, ...]
    finalized_results: tuple[FinalizedResult, ...]
    descriptive_chain_execution_sets: tuple[tuple[AuthenticatedWorkerExecutionEvidence, ...], ...]


@final
class SealedResultEvidenceSet:
    """Opaque complete owner set retained only inside the current process."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("SealedResultEvidenceSet cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Result evidence sets are sealed by the result journal only.")

    @property
    def plan_digest(self) -> str:
        state = _read_sealed_result_evidence_set(self)
        return _read_plan_candidate_authorization(state.plan_candidate_authorization).plan_digest

    @property
    def terminal_index_digest(self) -> str:
        state = _read_sealed_result_evidence_set(self)
        return _read_sealed_terminal_index(state.sealed_terminal_index).artifact_digest

    @property
    def result_count(self) -> int:
        return len(_read_sealed_result_evidence_set(self).finalized_results)

    @property
    def descriptive_chain_count(self) -> int:
        return sum(
            len(chains)
            for chains in _read_sealed_result_evidence_set(self).descriptive_chain_execution_sets
        )

    def __repr__(self) -> str:
        state = _read_sealed_result_evidence_set(self)
        chain_count = sum(len(chains) for chains in state.descriptive_chain_execution_sets)
        return (
            "SealedResultEvidenceSet("
            f"result_count={len(state.finalized_results)}, "
            f"descriptive_chain_count={chain_count})"
        )

    def __copy__(self) -> SealedResultEvidenceSet:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> SealedResultEvidenceSet:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()


_SEALED_RESULT_EVIDENCE_SET_STATES: OneShotWeakRegistry[
    SealedResultEvidenceSet, _SealedResultEvidenceSetState
]
_SEALED_RESULT_EVIDENCE_SET_STATE_ISSUER: OneShotRegistryIssuer[
    SealedResultEvidenceSet, _SealedResultEvidenceSetState
]
(
    _SEALED_RESULT_EVIDENCE_SET_STATES,
    _SEALED_RESULT_EVIDENCE_SET_STATE_ISSUER,
) = create_one_shot_registry()


def _read_sealed_result_evidence_set(value: object) -> _SealedResultEvidenceSetState:
    if type(value) is not SealedResultEvidenceSet:
        raise TypeError("A genuine sealed result-evidence set is required.")
    try:
        state = _SEALED_RESULT_EVIDENCE_SET_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine sealed result-evidence set is required.") from None
    return _read_sealed_result_evidence_set_with_state(value, state)


def _read_sealed_result_evidence_set_with_state(
    value: object,
    state: _SealedResultEvidenceSetState,
) -> _SealedResultEvidenceSetState:
    """Read one exact retained evidence state without adopting a replacement."""

    _require_sealed_result_evidence_set_state_identity(value, state)
    try:
        return _validate_sealed_result_evidence_set_state_contents(state)
    finally:
        _require_sealed_result_evidence_set_state_identity(value, state)


def _require_sealed_result_evidence_set_state_identity(
    value: object,
    state: object,
) -> _SealedResultEvidenceSetState:
    if (
        type(value) is not SealedResultEvidenceSet
        or type(state) is not _SealedResultEvidenceSetState
    ):
        raise TypeError("A genuine sealed result-evidence set is required.")
    try:
        _SEALED_RESULT_EVIDENCE_SET_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError("A genuine sealed result-evidence set is required.") from None
    return state


def _validate_sealed_result_evidence_set_state_contents(
    state: _SealedResultEvidenceSetState,
) -> _SealedResultEvidenceSetState:
    _read_plan_candidate_authorization(state.plan_candidate_authorization)
    transaction_authorizations = _preparation_transaction_authorizations(
        state.preparation_transaction,
        state.plan_candidate_authorization,
    )
    influence_input = _read_influence_preparation_input_receipt(state.influence_input_receipt)
    _require_exact_influence_input_snapshot(
        state.influence_input_snapshot,
        state.plan_candidate_authorization,
    )
    if influence_input is not state.influence_input_snapshot:
        raise TypeError("Sealed result-evidence authority is detached.")
    terminal_state = _read_candidate_terminal_authorization(state.terminal_authorization)
    terminal_rows, persisted = _candidate_terminal_projection_from_prevalidated_state(
        state.terminal_authorization,
        terminal_state,
    )
    sealed = _capture_sealed_terminal_index_state_identity(state.sealed_terminal_index)
    _validate_sealed_terminal_index_state_with_rows(
        state.sealed_terminal_index,
        sealed,
        terminal_rows,
    )
    if (
        len(transaction_authorizations) != len(state.candidate_result_authorizations)
        or any(
            current is not retained
            for current, retained in zip(
                transaction_authorizations,
                state.candidate_result_authorizations,
                strict=True,
            )
        )
        or len(transaction_authorizations) != len(state.finalized_results)
        or terminal_state.plan_candidate_authorization is not state.plan_candidate_authorization
        or sealed.plan_candidate_authorization is not state.plan_candidate_authorization
        or sealed.terminal_authorization is not state.terminal_authorization
    ):
        raise TypeError("Sealed result-evidence authority is detached.")
    if len(persisted) != len(state.persisted_results) or any(
        supplied is not expected
        for supplied, expected in zip(
            persisted,
            state.persisted_results,
            strict=True,
        )
    ):
        raise TypeError("Sealed result-evidence authority is detached.")
    if len(state.finalized_results) != len(state.persisted_results) or len(
        state.descriptive_chain_execution_sets
    ) != len(state.finalized_results):
        raise TypeError("Sealed result-evidence authority is detached.")
    finalized_states: dict[FinalizedResult, _FinalizedResultState] = {}
    for ordinal, (
        persisted_owner,
        finalized,
        retained_chains,
    ) in enumerate(
        zip(
            state.persisted_results,
            state.finalized_results,
            state.descriptive_chain_execution_sets,
            strict=True,
        )
    ):
        finalized_state = _capture_finalized_result_state(finalized)
        finalized_states[finalized] = finalized_state
        persisted_state = _capture_persisted_result_state_identity(persisted_owner)
        _read_persisted_result_with_states(
            persisted_owner,
            persisted_state,
            finalized_state=finalized_state,
        )
        current_chains = _finalized_result_descriptive_chain_executions_from_state(
            finalized,
            finalized_state,
        )
        if (
            persisted_state.finalized_result is not finalized
            or persisted_state.candidate_ordinal != ordinal
            or _finalized_result_candidate_authorization_from_state(
                finalized,
                finalized_state,
            )
            is not transaction_authorizations[ordinal]
            or len(current_chains) != len(retained_chains)
            or any(
                current is not retained
                for current, retained in zip(current_chains, retained_chains, strict=True)
            )
        ):
            raise TypeError("Sealed result-evidence authority is detached.")
    for cached in state.persisted_cache_results:
        cached_state = _capture_persisted_cache_result_state_identity(cached)
        finalized = cached_state.finalized_result
        cache_finalized_state = finalized_states.get(finalized)
        if cache_finalized_state is None:
            cache_finalized_state = _capture_finalized_result_state(finalized)
            finalized_states[finalized] = cache_finalized_state
        _read_persisted_cache_result_with_states(
            cached,
            cached_state,
            finalized_state=cache_finalized_state,
        )
        ordinal = cached_state.candidate_ordinal
        if (
            ordinal < 0
            or ordinal >= len(transaction_authorizations)
            or _finalized_result_candidate_authorization_from_state(
                finalized,
                cache_finalized_state,
            )
            is not transaction_authorizations[ordinal]
        ):
            raise TypeError("Sealed result-evidence authority is detached.")
    _read_plan_candidate_authorization(state.plan_candidate_authorization)
    _read_candidate_terminal_authorization(state.terminal_authorization)
    _validate_sealed_terminal_index_state_with_rows(
        state.sealed_terminal_index,
        sealed,
        terminal_rows,
    )
    return state


@dataclass(frozen=True, repr=False)
class _SealedResultEvidenceRunBinding:
    sealed_result_evidence_set: SealedResultEvidenceSet
    plan_candidate_authorization: PlanCandidateAuthorization
    preparation_transaction: PreparationTransaction
    influence_input_receipt: _InfluencePreparationInputReceipt
    influence_input_snapshot: _InfluencePreparationInputSnapshot
    preparation_receipt_digest: str
    influence_preparation_binding_bytes: tuple[bytes, ...]
    influence_preparation_bindings_digest: str
    stage_preparation_binding_bytes: tuple[bytes, ...]
    stage_preparation_bindings_digest: str
    baseline_analysis_spec_id: str
    plan_candidates: tuple[dict[str, Any], ...]
    origin_comparison_edges: tuple[dict[str, Any], ...]
    candidate_result_authorizations: tuple[object, ...]
    terminal_authorization: CandidateTerminalAuthorization
    sealed_terminal_index: SealedCandidateTerminalIndex
    candidate_terminals: tuple[dict[str, Any], ...]
    persisted_results: tuple[PersistedFinalizedResult, ...]
    persisted_cache_results: tuple[PersistedCacheResult, ...]
    finalized_results: tuple[FinalizedResult, ...]
    terminal_index_digest: str


def _sealed_result_evidence_run(value: object) -> _SealedResultEvidenceRunBinding:
    """Return the complete exact current-run owner graph for trusted core consumers."""

    state = _read_sealed_result_evidence_set(value)
    return _sealed_result_evidence_run_with_state(value, state)


def _sealed_result_evidence_run_with_state(
    value: object,
    state: _SealedResultEvidenceSetState,
) -> _SealedResultEvidenceRunBinding:
    _require_sealed_result_evidence_set_state_identity(value, state)
    try:
        influence_input = _require_exact_influence_input_snapshot(
            state.influence_input_snapshot,
            state.plan_candidate_authorization,
        )
        plan_candidates = strict_json_loads(influence_input.plan_candidates_bytes)
        comparison_edges = strict_json_loads(influence_input.origin_comparison_edges_bytes)
        projected_candidates = _plan_candidate_rows(state.plan_candidate_authorization)
        if (
            influence_input.plan_digest
            != _read_plan_candidate_authorization(state.plan_candidate_authorization).plan_digest
            or type(plan_candidates) is not list
            or type(comparison_edges) is not list
            or len(plan_candidates) != len(projected_candidates)
            or any(type(candidate) is not dict for candidate in plan_candidates)
            or any(type(edge) is not dict for edge in comparison_edges)
            or any(
                (
                    candidate.get("candidate_ordinal"),
                    candidate.get("candidate_id"),
                    candidate.get("analysis_spec_id"),
                )
                != (
                    projected["candidate_ordinal"],
                    projected["candidate_id"],
                    projected["analysis_spec_id"],
                )
                for candidate, projected in zip(
                    plan_candidates,
                    projected_candidates,
                    strict=True,
                )
            )
        ):
            raise TypeError("Sealed result evidence has no exact Plan/3 source.")
        terminal_state = _read_candidate_terminal_authorization(state.terminal_authorization)
        terminal_rows, _persisted_owners = _candidate_terminal_projection_from_prevalidated_state(
            state.terminal_authorization,
            terminal_state,
        )
        sealed_index = _capture_sealed_terminal_index_state_identity(state.sealed_terminal_index)
        _validate_sealed_terminal_index_state_with_rows(
            state.sealed_terminal_index,
            sealed_index,
            terminal_rows,
        )
        return _SealedResultEvidenceRunBinding(
            sealed_result_evidence_set=cast(SealedResultEvidenceSet, value),
            plan_candidate_authorization=state.plan_candidate_authorization,
            preparation_transaction=state.preparation_transaction,
            influence_input_receipt=state.influence_input_receipt,
            influence_input_snapshot=state.influence_input_snapshot,
            preparation_receipt_digest=influence_input.preparation_receipt_digest,
            influence_preparation_binding_bytes=influence_input.binding_bytes,
            influence_preparation_bindings_digest=influence_input.bindings_digest,
            stage_preparation_binding_bytes=influence_input.stage_binding_bytes,
            stage_preparation_bindings_digest=influence_input.stage_bindings_digest,
            baseline_analysis_spec_id=influence_input.baseline_analysis_spec_id,
            plan_candidates=tuple(
                cast(dict[str, Any], strict_json_loads(canonical_json_bytes(candidate)))
                for candidate in plan_candidates
            ),
            origin_comparison_edges=tuple(
                cast(dict[str, Any], strict_json_loads(canonical_json_bytes(edge)))
                for edge in comparison_edges
            ),
            candidate_result_authorizations=state.candidate_result_authorizations,
            terminal_authorization=state.terminal_authorization,
            sealed_terminal_index=state.sealed_terminal_index,
            candidate_terminals=tuple(dict(row) for row in terminal_rows),
            persisted_results=state.persisted_results,
            persisted_cache_results=state.persisted_cache_results,
            finalized_results=state.finalized_results,
            terminal_index_digest=sealed_index.artifact_digest,
        )
    finally:
        _require_sealed_result_evidence_set_state_identity(value, state)


def _same_owner_sequence(
    left: Sequence[object],
    right: Sequence[object],
) -> bool:
    return len(left) == len(right) and all(
        current is retained for current, retained in zip(left, right, strict=True)
    )


def _same_sealed_result_evidence_run(
    current: _SealedResultEvidenceRunBinding,
    retained: _SealedResultEvidenceRunBinding,
) -> bool:
    """Compare every closed owner and projection in two reads of one sealed run."""

    return (
        current.sealed_result_evidence_set is retained.sealed_result_evidence_set
        and current.plan_candidate_authorization is retained.plan_candidate_authorization
        and current.preparation_transaction is retained.preparation_transaction
        and current.influence_input_receipt is retained.influence_input_receipt
        and current.influence_input_snapshot is retained.influence_input_snapshot
        and current.preparation_receipt_digest == retained.preparation_receipt_digest
        and current.influence_preparation_binding_bytes
        == retained.influence_preparation_binding_bytes
        and current.influence_preparation_bindings_digest
        == retained.influence_preparation_bindings_digest
        and current.stage_preparation_binding_bytes == retained.stage_preparation_binding_bytes
        and current.stage_preparation_bindings_digest == retained.stage_preparation_bindings_digest
        and current.baseline_analysis_spec_id == retained.baseline_analysis_spec_id
        and current.plan_candidates == retained.plan_candidates
        and current.origin_comparison_edges == retained.origin_comparison_edges
        and _same_owner_sequence(
            current.candidate_result_authorizations,
            retained.candidate_result_authorizations,
        )
        and current.terminal_authorization is retained.terminal_authorization
        and current.sealed_terminal_index is retained.sealed_terminal_index
        and current.candidate_terminals == retained.candidate_terminals
        and _same_owner_sequence(
            current.persisted_results,
            retained.persisted_results,
        )
        and _same_owner_sequence(
            current.persisted_cache_results,
            retained.persisted_cache_results,
        )
        and _same_owner_sequence(
            current.finalized_results,
            retained.finalized_results,
        )
        and current.terminal_index_digest == retained.terminal_index_digest
    )


@dataclass(frozen=True, repr=False, slots=True)
class _ScientificLedgerReceiptState:
    """Persistence-owned closed science facts needed by terminal ledgers."""

    sealed_result_evidence_set: SealedResultEvidenceSet
    canonical_bytes: bytes
    receipt_digest: str


def _validate_scientific_ledger_receipt_state_contents(
    state: object,
    *,
    run: _SealedResultEvidenceRunBinding,
) -> tuple[str, tuple[str, ...]]:
    if (
        type(state) is not _ScientificLedgerReceiptState
        or state.sealed_result_evidence_set is not run.sealed_result_evidence_set
        or type(state.canonical_bytes) is not bytes
        or type(state.receipt_digest) is not str
    ):
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    try:
        receipt = strict_json_loads(state.canonical_bytes)
    except Exception:
        raise TypeError(_LEDGER_PROJECTION_ERROR) from None
    if type(receipt) is not dict:
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    receipt = cast(dict[str, Any], receipt)
    assert_no_direct_identifier_fields(receipt)
    expected_keys = {
        "science_ledger_receipt_schema_version",
        "scientific_evidence_schema_version",
        "scientific_evidence_rule_id",
        "plan_digest",
        "terminal_index_digest",
        "scientific_evidence_digest",
        "candidate_bindings",
        "science_completion_gate",
        "receipt_digest",
    }
    if set(receipt) != expected_keys:
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    try:
        canonical = canonical_json_bytes(receipt)
    except Exception:
        raise TypeError(_LEDGER_PROJECTION_ERROR) from None
    if canonical != state.canonical_bytes:
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    receipt_preimage = dict(receipt)
    receipt_digest = receipt_preimage.pop("receipt_digest", None)
    try:
        expected_receipt_digest = structured_sha256(
            _SCIENCE_LEDGER_RECEIPT_DIGEST_DOMAIN,
            receipt_preimage,
        )
    except Exception:
        raise TypeError(_LEDGER_PROJECTION_ERROR) from None
    plan_digest = _read_plan_candidate_authorization(run.plan_candidate_authorization).plan_digest
    candidate_bindings = receipt.get("candidate_bindings")
    gate = receipt.get("science_completion_gate")
    evidence_digest = receipt.get("scientific_evidence_digest")
    if (
        receipt.get("science_ledger_receipt_schema_version")
        != _SCIENCE_LEDGER_RECEIPT_SCHEMA_VERSION
        or receipt.get("scientific_evidence_schema_version")
        != _SEALED_SCIENTIFIC_EVIDENCE_SCHEMA_VERSION
        or receipt.get("scientific_evidence_rule_id") != _SEALED_SCIENTIFIC_EVIDENCE_RULE_ID
        or receipt.get("plan_digest") != plan_digest
        or receipt.get("terminal_index_digest") != run.terminal_index_digest
        or type(evidence_digest) is not str
        or type(candidate_bindings) is not list
        or len(candidate_bindings) != len(run.candidate_terminals)
        or type(gate) is not dict
        or set(gate) != {"status", "reason_codes"}
        or receipt_digest != state.receipt_digest
        or receipt_digest != expected_receipt_digest
    ):
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    candidate_keys = {
        "candidate_id",
        "final_status",
    }
    for terminal, candidate in zip(
        run.candidate_terminals,
        candidate_bindings,
        strict=True,
    ):
        if (
            type(candidate) is not dict
            or set(candidate) != candidate_keys
            or (
                candidate.get("candidate_id"),
                candidate.get("final_status"),
            )
            != (
                terminal["candidate_id"],
                terminal["final_status"],
            )
        ):
            raise TypeError(_LEDGER_PROJECTION_ERROR)
    status = gate.get("status")
    reason_codes = gate.get("reason_codes")
    if (
        status not in {"BLOCKED", "COMPLETE"}
        or type(reason_codes) is not list
        or any(type(reason) is not str for reason in reason_codes)
        or len(reason_codes) != len(set(reason_codes))
        or (status == "BLOCKED") != bool(reason_codes)
    ):
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    return evidence_digest, tuple(cast(list[str], reason_codes))


def _build_scientific_ledger_receipt_boundary() -> tuple[
    OneShotWeakRegistry[object, _ScientificLedgerReceiptState],
    object,
]:
    """Build one reader and one handoff consumed by the science seal closure."""

    registry: OneShotWeakRegistry[object, _ScientificLedgerReceiptState]
    issuer: OneShotRegistryIssuer[object, _ScientificLedgerReceiptState]
    registry, issuer = create_one_shot_registry()
    claimed = False
    lock = RLock()
    module_globals = globals()

    def acquire() -> tuple[object, object]:
        nonlocal claimed
        with lock:
            if claimed:
                raise TypeError("Scientific ledger receipt issuer is unavailable.")
            claimed = True
            module_globals.pop(
                "_acquire_scientific_ledger_receipt_issuer",
                None,
            )

        def issue(
            sealed_scientific_evidence: object,
            sealed_result_evidence_set: SealedResultEvidenceSet,
            canonical_bytes: bytes,
            receipt_digest: str,
            /,
        ) -> None:
            run = _sealed_result_evidence_run(sealed_result_evidence_set)
            state = _ScientificLedgerReceiptState(
                sealed_result_evidence_set=sealed_result_evidence_set,
                canonical_bytes=canonical_bytes,
                receipt_digest=receipt_digest,
            )
            _validate_scientific_ledger_receipt_state_contents(state, run=run)
            issuer.bind_once(sealed_scientific_evidence, state)
            _read_scientific_ledger_receipt_with_state(
                sealed_scientific_evidence,
                state,
                run=run,
            )

        def require_exact(
            sealed_scientific_evidence: object,
            sealed_result_evidence_set: SealedResultEvidenceSet,
            canonical_bytes: bytes,
            receipt_digest: str,
            /,
        ) -> None:
            run = _sealed_result_evidence_run(sealed_result_evidence_set)
            state = _read_scientific_ledger_receipt(
                sealed_scientific_evidence,
                run=run,
            )
            if (
                state.sealed_result_evidence_set is not sealed_result_evidence_set
                or state.canonical_bytes != canonical_bytes
                or state.receipt_digest != receipt_digest
            ):
                raise TypeError(_LEDGER_PROJECTION_ERROR)

        return issue, require_exact

    return registry, acquire


(
    _SCIENTIFIC_LEDGER_RECEIPT_STATES,
    _acquire_scientific_ledger_receipt_issuer,
) = _build_scientific_ledger_receipt_boundary()
del _build_scientific_ledger_receipt_boundary


def _require_scientific_ledger_receipt_state_identity(
    sealed_scientific_evidence: object,
    state: object,
) -> _ScientificLedgerReceiptState:
    if type(state) is not _ScientificLedgerReceiptState:
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    try:
        return _SCIENTIFIC_LEDGER_RECEIPT_STATES.require(
            sealed_scientific_evidence,
            state,
        )
    except TypeError:
        raise TypeError(_LEDGER_PROJECTION_ERROR) from None


def _read_scientific_ledger_receipt(
    sealed_scientific_evidence: object,
    *,
    run: _SealedResultEvidenceRunBinding,
) -> _ScientificLedgerReceiptState:
    try:
        state = _SCIENTIFIC_LEDGER_RECEIPT_STATES[sealed_scientific_evidence]
    except TypeError:
        raise TypeError(_LEDGER_PROJECTION_ERROR) from None
    return _read_scientific_ledger_receipt_with_state(
        sealed_scientific_evidence,
        state,
        run=run,
    )


def _read_scientific_ledger_receipt_with_state(
    sealed_scientific_evidence: object,
    state: _ScientificLedgerReceiptState,
    *,
    run: _SealedResultEvidenceRunBinding,
) -> _ScientificLedgerReceiptState:
    _require_scientific_ledger_receipt_state_identity(
        sealed_scientific_evidence,
        state,
    )
    try:
        _validate_scientific_ledger_receipt_state_contents(state, run=run)
        return state
    finally:
        _require_scientific_ledger_receipt_state_identity(
            sealed_scientific_evidence,
            state,
        )


def _projectable_result_record(
    *,
    ordinal: int,
    terminal: object,
    persisted_result: object,
    persisted_state: _PersistedFinalizedResultState,
    finalized_result: object,
    finalized_state: _FinalizedResultState,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(terminal) is not dict:
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    terminal_row = cast(dict[str, Any], terminal)
    validate_instance(
        terminal_row,
        "run-artifacts.schema.json",
        definition="CandidateTerminal",
    )
    _require_persisted_result_state_identity(persisted_result, persisted_state)
    _require_finalized_result_state_identity(finalized_result, finalized_state)
    try:
        canonical = persisted_state.canonical_bytes
        terminal_bytes = canonical_json_bytes(terminal_row)
        result_readback = persisted_state.store.read_bytes(
            persisted_state.result_path,
            maximum_bytes=len(canonical),
        )
        terminal_readback = persisted_state.store.read_bytes(
            persisted_state.terminal_path,
            maximum_bytes=len(persisted_state.terminal_bytes),
        )
        if (
            result_readback != canonical
            or terminal_readback != persisted_state.terminal_bytes
            or exact_file_sha256(canonical) != persisted_state.result_digest
        ):
            raise InvalidInputError(
                "RESULT.PERSISTED_BYTES_MISMATCH",
                "Persisted candidate artifacts no longer match their exact authority.",
            )
        record = strict_json_loads(canonical)
        if type(record) is not dict:
            raise TypeError(_LEDGER_PROJECTION_ERROR)
        validated = validate_result_record_finalization(cast(Mapping[str, Any], record))
        body = validated.get("body")
        if (
            type(body) is not dict
            or canonical_json_bytes(validated) != canonical
            or persisted_state.finalized_result is not finalized_result
            or persisted_state.candidate_ordinal != ordinal
            or persisted_state.terminal_bytes != terminal_bytes
            or terminal_row["candidate_ordinal"] != ordinal
            or (
                body["candidate_ordinal"],
                body["candidate_id"],
                body["analysis_spec_id"],
                body["universe_id"],
                body["status"],
                validated["result_id"],
                persisted_state.result_digest,
            )
            != (
                terminal_row["candidate_ordinal"],
                terminal_row["candidate_id"],
                terminal_row["analysis_spec_id"],
                terminal_row["universe_id"],
                terminal_row["final_status"],
                terminal_row["result_id"],
                terminal_row["result_digest"],
            )
        ):
            raise TypeError(_LEDGER_PROJECTION_ERROR)
        return terminal_row, cast(dict[str, Any], body)
    finally:
        _require_finalized_result_state_identity(finalized_result, finalized_state)
        _require_persisted_result_state_identity(persisted_result, persisted_state)


def _reread_ledger_projection_artifacts(
    evidence: SealedResultEvidenceSet,
    evidence_state: _SealedResultEvidenceSetState,
    *,
    run: _SealedResultEvidenceRunBinding,
    terminal_state: _CandidateTerminalAuthorizationState,
    persisted_states: tuple[_PersistedFinalizedResultState, ...],
    finalized_states: tuple[_FinalizedResultState, ...],
    cache_states: tuple[_PersistedCacheResultState, ...],
    sealed_index_state: _SealedCandidateTerminalIndexState,
) -> None:
    """Re-require one captured graph and cheaply reread every durable result artifact."""

    _require_sealed_result_evidence_set_state_identity(evidence, evidence_state)
    _require_candidate_terminal_authorization_state(
        run.terminal_authorization,
        terminal_state,
    )
    try:
        terminal_rows, persisted_owners = _candidate_terminal_projection_from_prevalidated_state(
            run.terminal_authorization,
            terminal_state,
        )
        if (
            terminal_rows != run.candidate_terminals
            or not _same_owner_sequence(persisted_owners, run.persisted_results)
            or len(persisted_states) != len(run.persisted_results)
            or len(finalized_states) != len(run.finalized_results)
            or len(cache_states) != len(run.persisted_cache_results)
        ):
            raise TypeError(_LEDGER_PROJECTION_ERROR)
        finalized_state_by_owner: dict[FinalizedResult, _FinalizedResultState] = {}
        for ordinal, (
            persisted_result,
            persisted_state,
            finalized_result,
            finalized_state,
            terminal_row,
        ) in enumerate(
            zip(
                run.persisted_results,
                persisted_states,
                run.finalized_results,
                finalized_states,
                terminal_rows,
                strict=True,
            )
        ):
            _require_persisted_result_state_identity(
                persisted_result,
                persisted_state,
            )
            _require_finalized_result_state_identity(
                finalized_result,
                finalized_state,
            )
            result_readback = persisted_state.store.read_bytes(
                persisted_state.result_path,
                maximum_bytes=len(persisted_state.canonical_bytes),
            )
            terminal_readback = persisted_state.store.read_bytes(
                persisted_state.terminal_path,
                maximum_bytes=len(persisted_state.terminal_bytes),
            )
            if (
                persisted_state.finalized_result is not finalized_result
                or persisted_state.candidate_ordinal != ordinal
                or result_readback != persisted_state.canonical_bytes
                or terminal_readback != persisted_state.terminal_bytes
                or exact_file_sha256(persisted_state.canonical_bytes)
                != persisted_state.result_digest
                or canonical_json_bytes(terminal_row) != persisted_state.terminal_bytes
            ):
                raise InvalidInputError(
                    "RESULT.PERSISTED_BYTES_MISMATCH",
                    "Persisted candidate artifacts no longer match their exact authority.",
                )
            finalized_state_by_owner[finalized_result] = finalized_state
        for persisted_cache, cache_state in zip(
            run.persisted_cache_results,
            cache_states,
            strict=True,
        ):
            _require_persisted_cache_result_state_identity(
                persisted_cache,
                cache_state,
            )
            try:
                finalized_state = finalized_state_by_owner[cache_state.finalized_result]
            except KeyError:
                raise TypeError(_LEDGER_PROJECTION_ERROR) from None
            _require_finalized_result_state_identity(
                cache_state.finalized_result,
                finalized_state,
            )
            cache_readback = cache_state.store.read_bytes(
                cache_state.cache_path,
                maximum_bytes=len(cache_state.canonical_bytes),
            )
            if (
                cache_readback != cache_state.canonical_bytes
                or exact_file_sha256(cache_state.canonical_bytes) != cache_state.artifact_digest
            ):
                raise InvalidInputError(
                    "RESULT.CACHE_BYTES_MISMATCH",
                    "The persisted cache artifact no longer matches its exact authority.",
                )
        _require_sealed_terminal_index_state_identity(
            run.sealed_terminal_index,
            sealed_index_state,
        )
        index_readback = sealed_index_state.store.read_bytes(
            _TERMINAL_INDEX_PATH,
            maximum_bytes=len(sealed_index_state.canonical_bytes),
        )
        if (
            sealed_index_state.plan_candidate_authorization is not run.plan_candidate_authorization
            or sealed_index_state.terminal_authorization is not run.terminal_authorization
            or index_readback != sealed_index_state.canonical_bytes
            or exact_file_sha256(sealed_index_state.canonical_bytes)
            != sealed_index_state.artifact_digest
            or sealed_index_state.artifact_digest != run.terminal_index_digest
        ):
            raise InvalidInputError(
                "RESULT.TERMINAL_INDEX_BYTES_MISMATCH",
                "The candidate-terminal index no longer matches its exact authority.",
            )
    finally:
        for persisted_result, persisted_state in zip(
            run.persisted_results,
            persisted_states,
            strict=False,
        ):
            _require_persisted_result_state_identity(
                persisted_result,
                persisted_state,
            )
        for finalized_result, finalized_state in zip(
            run.finalized_results,
            finalized_states,
            strict=False,
        ):
            _require_finalized_result_state_identity(
                finalized_result,
                finalized_state,
            )
        for persisted_cache, cache_state in zip(
            run.persisted_cache_results,
            cache_states,
            strict=False,
        ):
            _require_persisted_cache_result_state_identity(
                persisted_cache,
                cache_state,
            )
        _require_sealed_terminal_index_state_identity(
            run.sealed_terminal_index,
            sealed_index_state,
        )
        _require_candidate_terminal_authorization_state(
            run.terminal_authorization,
            terminal_state,
        )
        _require_sealed_result_evidence_set_state_identity(
            evidence,
            evidence_state,
        )


def _scientific_gate_for_run(
    sealed_scientific_evidence: object,
    *,
    run: _SealedResultEvidenceRunBinding,
) -> tuple[str, tuple[str, ...]]:
    state = _read_scientific_ledger_receipt(
        sealed_scientific_evidence,
        run=run,
    )
    return _validate_scientific_ledger_receipt_state_contents(state, run=run)


def _append_closed_ledger_row(
    rows: list[dict[str, Any]],
    row: dict[str, Any],
    *,
    schema_definition: str,
) -> None:
    validate_instance(
        row,
        "run-artifacts.schema.json",
        definition=schema_definition,
    )
    assert_no_direct_identifier_fields(row)
    rows.append(row)


def _append_failure_ledger_row(
    rows: list[dict[str, Any]],
    *,
    terminal: Mapping[str, Any],
    error: Mapping[str, Any],
) -> None:
    validate_instance(
        error,
        "canonical-records.schema.json",
        definition="NegativeResponseError",
    )
    if (
        error["category"] != terminal["final_status"]
        or type(terminal["error_evidence_digest"]) is not str
    ):
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    row = {
        "failure_ledger_schema_version": _FAILURE_LEDGER_SCHEMA_VERSION,
        "candidate_ordinal": terminal["candidate_ordinal"],
        "candidate_id": terminal["candidate_id"],
        "analysis_spec_id": terminal["analysis_spec_id"],
        "universe_id": terminal["universe_id"],
        "result_id": terminal["result_id"],
        "result_digest": terminal["result_digest"],
        "final_status": terminal["final_status"],
        "code": error["code"],
        "category": error["category"],
        "phase": error["phase"],
        "retryable_identical_request": error["retryable_identical_request"],
        "error_evidence_digest": terminal["error_evidence_digest"],
    }
    _append_closed_ledger_row(
        rows,
        row,
        schema_definition="FailureLedgerRecordV2",
    )


def _append_candidate_warning_ledger_row(
    rows: list[dict[str, Any]],
    *,
    terminal: Mapping[str, Any],
    warning_source_ordinal: int,
    warning: object,
) -> None:
    if type(warning) is not dict:
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    warning_record = cast(dict[str, Any], warning)
    validate_instance(
        warning_record,
        "canonical-records.schema.json",
        definition="WarningRecord",
    )
    if warning_record["safe_message"] != _CORE_WARNING_MESSAGE:
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    row = {
        "warning_ledger_schema_version": _WARNING_LEDGER_SCHEMA_VERSION,
        "scope": "CANDIDATE",
        "warning_source": "RESULT_WARNING",
        "warning_source_ordinal": warning_source_ordinal,
        "candidate_ordinal": terminal["candidate_ordinal"],
        "candidate_id": terminal["candidate_id"],
        "analysis_spec_id": terminal["analysis_spec_id"],
        "universe_id": terminal["universe_id"],
        "result_id": terminal["result_id"],
        "result_digest": terminal["result_digest"],
        "final_status": terminal["final_status"],
        "code": warning_record["code"],
        "severity": warning_record["severity"],
        "safe_message": warning_record["safe_message"],
        "details": strict_json_loads(canonical_json_bytes(warning_record["details"])),
    }
    _append_closed_ledger_row(
        rows,
        row,
        schema_definition="WarningLedgerRecordV2",
    )


def _append_convergence_warning_ledger_row(
    rows: list[dict[str, Any]],
    *,
    terminal: Mapping[str, Any],
    body: Mapping[str, Any],
) -> None:
    convergence = body.get("convergence")
    if type(convergence) is not dict:
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    validate_instance(
        convergence,
        "canonical-records.schema.json",
        definition="ConvergenceRecord",
    )
    if (
        terminal["final_status"] != "CONVERGENCE_WARN"
        or convergence.get("assessment") != "CONVERGENCE_WARN"
        or convergence.get("reasons") != ["CONVERGENCE.PASS_THRESHOLDS_NOT_MET"]
    ):
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    row = {
        "warning_ledger_schema_version": _WARNING_LEDGER_SCHEMA_VERSION,
        "scope": "CANDIDATE",
        "warning_source": "CONVERGENCE",
        "warning_source_ordinal": 0,
        "candidate_ordinal": terminal["candidate_ordinal"],
        "candidate_id": terminal["candidate_id"],
        "analysis_spec_id": terminal["analysis_spec_id"],
        "universe_id": terminal["universe_id"],
        "result_id": terminal["result_id"],
        "result_digest": terminal["result_digest"],
        "final_status": terminal["final_status"],
        "code": "CONVERGENCE.PASS_THRESHOLDS_NOT_MET",
        "severity": "WARNING",
        "safe_message": _CONVERGENCE_WARNING_MESSAGE,
        "details": {
            "counts": {},
            "internal_indexes": [],
            "approved_event_ids": [],
            "digests": {},
        },
    }
    _append_closed_ledger_row(
        rows,
        row,
        schema_definition="WarningLedgerRecordV2",
    )


def _append_science_warning_ledger_row(
    rows: list[dict[str, Any]],
    *,
    plan_digest: str,
    terminal_index_digest: str,
    scientific_evidence_digest: str,
    reason_code: str,
) -> None:
    warning_record = {
        "code": reason_code,
        "severity": "WARNING",
        "safe_message": _SCIENCE_GATE_WARNING_MESSAGE,
        "details": {
            "counts": {},
            "internal_indexes": [],
            "approved_event_ids": [],
            "digests": {},
        },
    }
    validate_instance(
        warning_record,
        "canonical-records.schema.json",
        definition="WarningRecord",
    )
    row = {
        "warning_ledger_schema_version": _WARNING_LEDGER_SCHEMA_VERSION,
        "scope": "SCIENCE_COMPLETION_GATE",
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "scientific_evidence_digest": scientific_evidence_digest,
        **warning_record,
    }
    _append_closed_ledger_row(
        rows,
        row,
        schema_definition="WarningLedgerRecordV2",
    )


def _canonical_jsonl(rows: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(row) + b"\n" for row in rows)


def project_terminal_ledgers(
    evidence: SealedResultEvidenceSet,
    *,
    sealed_scientific_evidence: SealedScientificEvidence,
) -> tuple[bytes, bytes]:
    """Project closed privacy-safe failure and warning JSONL from one live run."""

    evidence_state = _read_sealed_result_evidence_set(evidence)
    run = _sealed_result_evidence_run_with_state(evidence, evidence_state)
    if not (
        len(run.candidate_terminals) == len(run.persisted_results) == len(run.finalized_results)
    ):
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    terminal_state = _read_candidate_terminal_authorization(run.terminal_authorization)
    persisted_states = tuple(
        _capture_persisted_result_state_identity(persisted) for persisted in run.persisted_results
    )
    finalized_states = tuple(
        _capture_finalized_result_state_identity(finalized) for finalized in run.finalized_results
    )
    cache_states = tuple(
        _capture_persisted_cache_result_state_identity(persisted_cache)
        for persisted_cache in run.persisted_cache_results
    )
    sealed_index_state = _capture_sealed_terminal_index_state_identity(run.sealed_terminal_index)
    if any(
        persisted_state.finalized_result is not finalized
        for persisted_state, finalized in zip(
            persisted_states,
            run.finalized_results,
            strict=True,
        )
    ):
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    scientific_evidence_digest, science_reasons = _scientific_gate_for_run(
        sealed_scientific_evidence,
        run=run,
    )
    failure_rows: list[dict[str, Any]] = []
    warning_rows: list[dict[str, Any]] = []
    for ordinal, (
        terminal,
        persisted,
        persisted_state,
        finalized,
        finalized_state,
    ) in enumerate(
        zip(
            run.candidate_terminals,
            run.persisted_results,
            persisted_states,
            run.finalized_results,
            finalized_states,
            strict=True,
        )
    ):
        terminal_row, body = _projectable_result_record(
            ordinal=ordinal,
            terminal=terminal,
            persisted_result=persisted,
            persisted_state=persisted_state,
            finalized_result=finalized,
            finalized_state=finalized_state,
        )
        error = body.get("error")
        if error is None:
            if (
                terminal_row["final_status"] not in {"SUCCESS", "CONVERGENCE_WARN"}
                or terminal_row["error_evidence_digest"] is not None
            ):
                raise TypeError(_LEDGER_PROJECTION_ERROR)
        else:
            if type(error) is not dict or terminal_row["final_status"] in {
                "SUCCESS",
                "CONVERGENCE_WARN",
            }:
                raise TypeError(_LEDGER_PROJECTION_ERROR)
            _append_failure_ledger_row(
                failure_rows,
                terminal=terminal_row,
                error=cast(dict[str, Any], error),
            )
        warnings = body.get("warnings")
        if type(warnings) is not list:
            raise TypeError(_LEDGER_PROJECTION_ERROR)
        for warning_source_ordinal, warning in enumerate(warnings):
            _append_candidate_warning_ledger_row(
                warning_rows,
                terminal=terminal_row,
                warning_source_ordinal=warning_source_ordinal,
                warning=warning,
            )
        if terminal_row["final_status"] == "CONVERGENCE_WARN":
            _append_convergence_warning_ledger_row(
                warning_rows,
                terminal=terminal_row,
                body=body,
            )
    plan_digest = _read_plan_candidate_authorization(run.plan_candidate_authorization).plan_digest
    for reason in science_reasons:
        _append_science_warning_ledger_row(
            warning_rows,
            plan_digest=plan_digest,
            terminal_index_digest=run.terminal_index_digest,
            scientific_evidence_digest=scientific_evidence_digest,
            reason_code=reason,
        )
    failure_ledger = _canonical_jsonl(failure_rows)
    warning_ledger = _canonical_jsonl(warning_rows)
    _reread_ledger_projection_artifacts(
        evidence,
        evidence_state,
        run=run,
        terminal_state=terminal_state,
        persisted_states=persisted_states,
        finalized_states=finalized_states,
        cache_states=cache_states,
        sealed_index_state=sealed_index_state,
    )
    final_run = _sealed_result_evidence_run_with_state(
        evidence,
        evidence_state,
    )
    final_scientific_evidence_digest, final_science_reasons = _scientific_gate_for_run(
        sealed_scientific_evidence,
        run=final_run,
    )
    if (
        not _same_sealed_result_evidence_run(final_run, run)
        or final_scientific_evidence_digest != scientific_evidence_digest
        or final_science_reasons != science_reasons
    ):
        raise TypeError(_LEDGER_PROJECTION_ERROR)
    return failure_ledger, warning_ledger


@dataclass(frozen=True, repr=False)
class _BaselineResultEvidenceBinding:
    plan_candidate_authorization: PlanCandidateAuthorization
    preparation_transaction: PreparationTransaction
    candidate_result_authorizations: tuple[object, ...]
    terminal_authorization: CandidateTerminalAuthorization
    sealed_terminal_index: SealedCandidateTerminalIndex
    baseline_candidate: dict[str, Any]
    baseline_terminal: dict[str, Any]
    baseline_finalized_result: FinalizedResult
    baseline_finalized_state: _FinalizedResultState
    baseline_persisted_result: PersistedFinalizedResult
    terminal_index_digest: str


def _sealed_result_evidence_baseline(value: object) -> _BaselineResultEvidenceBinding:
    """Resolve the exact Plan/3 baseline owner from one complete evidence set."""

    state = _read_sealed_result_evidence_set(value)
    return _sealed_result_evidence_baseline_with_state(value, state)


def _sealed_result_evidence_baseline_with_state(
    value: object,
    state: _SealedResultEvidenceSetState,
) -> _BaselineResultEvidenceBinding:
    """Resolve a baseline from one exact already-captured evidence state."""

    _require_sealed_result_evidence_set_state_identity(value, state)
    baseline = _plan_baseline_candidate_row(state.plan_candidate_authorization)
    ordinal = cast(int, baseline["candidate_ordinal"])
    terminal_state = _read_candidate_terminal_authorization(state.terminal_authorization)
    terminals, _persisted_owners = _candidate_terminal_projection_from_prevalidated_state(
        state.terminal_authorization,
        terminal_state,
    )
    try:
        terminal = terminals[ordinal]
        persisted = state.persisted_results[ordinal]
        finalized = state.finalized_results[ordinal]
    except IndexError:
        raise TypeError("The sealed result-evidence set has no exact baseline owner.") from None
    persisted_state = _capture_persisted_result_state_identity(persisted)
    if (
        (
            terminal["candidate_ordinal"],
            terminal["candidate_id"],
            terminal["analysis_spec_id"],
        )
        != (
            baseline["candidate_ordinal"],
            baseline["candidate_id"],
            baseline["analysis_spec_id"],
        )
        or persisted_state.candidate_ordinal != ordinal
        or persisted_state.finalized_result is not finalized
    ):
        raise TypeError("The sealed result-evidence set has no exact baseline owner.")
    sealed_index = _capture_sealed_terminal_index_state_identity(state.sealed_terminal_index)
    _validate_sealed_terminal_index_state_with_rows(
        state.sealed_terminal_index,
        sealed_index,
        terminals,
    )
    finalized_state = _capture_finalized_result_state_identity(finalized)
    try:
        return _BaselineResultEvidenceBinding(
            plan_candidate_authorization=state.plan_candidate_authorization,
            preparation_transaction=state.preparation_transaction,
            candidate_result_authorizations=state.candidate_result_authorizations,
            terminal_authorization=state.terminal_authorization,
            sealed_terminal_index=state.sealed_terminal_index,
            baseline_candidate=baseline,
            baseline_terminal=dict(terminal),
            baseline_finalized_result=finalized,
            baseline_finalized_state=finalized_state,
            baseline_persisted_result=persisted,
            terminal_index_digest=sealed_index.artifact_digest,
        )
    finally:
        _require_sealed_result_evidence_set_state_identity(value, state)


def seal_result_evidence_set(journal: object) -> SealedResultEvidenceSet:
    """Seal all exact result and descriptive-chain owners after terminal-index seal."""

    state = _read_result_journal(journal)
    return _seal_result_evidence_set_with_state(journal, state)


def _seal_result_evidence_set_with_state(
    journal: object,
    state: _ResultPersistenceJournalState,
) -> SealedResultEvidenceSet:
    """Seal evidence through one executor-captured journal state only."""

    with _locked_result_journal_state(journal, state):
        if state.sealed_result_evidence_set is not None:
            sealed = state.sealed_result_evidence_set
            evidence_state = _SEALED_RESULT_EVIDENCE_SET_STATES.get(sealed)
            _require_sealed_result_evidence_set_state_identity(sealed, evidence_state)
            with _JOURNAL_CREATION_LOCK:
                registration = _journal_root_registration(journal, state)
                if registration == "LIVE":
                    _JOURNALS_BY_RUN_ROOT_ID[state.store.run_root_id] = (
                        _ClosedResultJournalTombstone(
                            state.store.run_root_id,
                            "CLOSED",
                        )
                    )
                elif registration != "CLOSED":
                    raise TypeError("The private run root result-journal state is invalid.")
            return sealed
        if state.sealed_terminal_index is None:
            raise TypeError("Result evidence requires the exact sealed terminal index first.")
        _require_live_result_journal_registration(journal, state)
        terminal_rows, owners = _prevalidated_terminal_projection(state)
        persisted = tuple(cast(PersistedFinalizedResult, owner) for owner in owners)
        _reread_prevalidated_persisted_artifacts(state, owners)
        sealed_index_state = _capture_sealed_terminal_index_state_identity(
            state.sealed_terminal_index
        )
        _validate_sealed_terminal_index_state_with_rows(
            state.sealed_terminal_index,
            sealed_index_state,
            terminal_rows,
        )
        finalized = tuple(
            _capture_persisted_result_state_identity(persisted_owner).finalized_result
            for persisted_owner in persisted
        )
        chain_sets = tuple(
            _finalized_result_descriptive_chain_executions_from_state(
                result,
                _capture_finalized_result_state_identity(result),
            )
            for result in finalized
        )
        with _JOURNAL_CREATION_LOCK:
            _require_result_journal_state_graph_identity(journal, state)
            if _journal_root_registration(journal, state) != "LIVE":
                raise TypeError("The private run root result-journal state is invalid.")
            sealed = object.__new__(SealedResultEvidenceSet)
            evidence_state = _SealedResultEvidenceSetState(
                plan_candidate_authorization=state.plan_candidate_authorization,
                preparation_transaction=state.preparation_transaction,
                influence_input_receipt=state.influence_input_receipt,
                influence_input_snapshot=state.influence_input_snapshot,
                candidate_result_authorizations=state.candidate_result_authorizations,
                terminal_authorization=state.terminal_authorization,
                sealed_terminal_index=state.sealed_terminal_index,
                persisted_results=persisted,
                persisted_cache_results=tuple(state.persisted_cache_results),
                finalized_results=finalized,
                descriptive_chain_execution_sets=chain_sets,
            )
            _SEALED_RESULT_EVIDENCE_SET_STATE_ISSUER.bind_once(
                sealed,
                evidence_state,
            )
            _require_sealed_result_evidence_set_state_identity(sealed, evidence_state)
            _reread_prevalidated_persisted_artifacts(state, owners)
            _validate_sealed_terminal_index_state_with_rows(
                state.sealed_terminal_index,
                sealed_index_state,
                terminal_rows,
            )
            _require_result_journal_state_graph_identity(journal, state)
            if _journal_root_registration(journal, state) != "LIVE":
                raise TypeError("The private run root result-journal state is invalid.")
            state.sealed_result_evidence_set = sealed
            _JOURNALS_BY_RUN_ROOT_ID[state.store.run_root_id] = _ClosedResultJournalTombstone(
                state.store.run_root_id,
                "CLOSED",
            )
            return sealed


def persist_cache_admissible_result(
    journal: object,
    finalized_result: object,
    cache_lineage: object,
) -> PersistedCacheResult:
    """Write exact completed bytes; this does not issue cross-process cache reuse."""

    state = _read_result_journal(journal)
    return _persist_cache_admissible_result_with_state(
        journal,
        state,
        finalized_result,
        cache_lineage,
    )


def _persist_cache_admissible_result_with_state(
    journal: object,
    state: _ResultPersistenceJournalState,
    finalized_result: object,
    cache_lineage: object,
) -> PersistedCacheResult:
    """Persist cache bytes through one executor-captured journal state only."""

    with _locked_result_journal_state(journal, state):
        if state.sealed_result_evidence_set is not None:
            raise TypeError("Cache persistence is closed after evidence sealing.")
        _require_live_result_journal_registration(journal, state)
        exact_result = cast(FinalizedResult, finalized_result)
        exact_lineage = cast(VerifiedCacheLineage, cache_lineage)
        persisted_owner: PersistedFinalizedResult | None = None
        persisted_owner_state: _PersistedFinalizedResultState | None = None
        _terminal_rows, owners = _prevalidated_terminal_projection(state)
        for owner in owners:
            persisted = _capture_persisted_result_state_identity(owner)
            if persisted.finalized_result is exact_result:
                persisted_owner = cast(PersistedFinalizedResult, owner)
                persisted_owner_state = persisted
                break
        if persisted_owner_state is None:
            finalized_state = _capture_finalized_result_state(exact_result)
        else:
            finalized_state = _capture_finalized_result_state_identity(exact_result)
        canonical = _finalized_result_cache_admission_bytes_from_state(
            exact_result,
            finalized_state,
            exact_lineage,
        )
        _plan_digest, ordinal, _candidate_id, _analysis_spec_id = _closed_result_identity(canonical)
        if persisted_owner is None or persisted_owner_state is None:
            raise TypeError("A result must be exactly persisted before cache admission.")
        for existing_capability in state.persisted_cache_results:
            existing = _capture_persisted_cache_result_state_identity(existing_capability)
            if existing.finalized_result is exact_result:
                if existing.cache_lineage is not exact_lineage:
                    raise TypeError("A different cache lineage already owns this result.")
                readback = state.store.read_bytes(
                    existing.cache_path,
                    maximum_bytes=len(existing.canonical_bytes),
                )
                if readback != existing.canonical_bytes:
                    raise InvalidInputError(
                        "RESULT.CACHE_BYTES_MISMATCH",
                        "The persisted cache artifact no longer matches its exact authority.",
                    )
                return existing_capability
        if (
            _require_persisted_result_state_identity(
                persisted_owner,
                persisted_owner_state,
            )
            is not persisted_owner_state
            or persisted_owner_state.canonical_bytes != canonical
        ):
            raise TypeError("Cache admission is detached from the persisted result.")
        _require_exact_result_authorization(
            state,
            exact_result,
            ordinal,
            finalized_result_state=finalized_state,
        )
        cache_path = _cache_path(ordinal)
        _require_live_result_journal_registration(journal, state)
        readback = _commit_exact_bytes(
            state.store,
            cache_path,
            canonical,
            mismatch_code="RESULT.CACHE_BYTES_MISMATCH",
            mismatch_message="The cache artifact does not match its exact authority.",
        )
        _require_live_result_journal_registration(journal, state)
        _finalized_result_candidate_authorization_from_state(
            exact_result,
            finalized_state,
        )
        _finalized_result_cache_admission_bytes_from_state(
            exact_result,
            finalized_state,
            exact_lineage,
        )
        persisted_cache = object.__new__(PersistedCacheResult)
        persisted_cache_state = _PersistedCacheResultState(
            store=state.store,
            finalized_result=exact_result,
            cache_lineage=exact_lineage,
            canonical_bytes=readback,
            artifact_digest=exact_file_sha256(readback),
            candidate_ordinal=ordinal,
            cache_path=cache_path,
        )
        _PERSISTED_CACHE_STATE_ISSUER.bind_once(
            persisted_cache,
            persisted_cache_state,
        )
        _read_persisted_cache_result_with_states(
            persisted_cache,
            persisted_cache_state,
            finalized_state=finalized_state,
        )
        _require_live_result_journal_registration(journal, state)
        _require_persisted_cache_result_state_identity(
            persisted_cache,
            persisted_cache_state,
        )
        state.persisted_cache_results.append(persisted_cache)
        return persisted_cache


__all__ = [
    "PersistedCacheResult",
    "PersistedFinalizedResult",
    "ResultPersistenceJournal",
    "SealedCandidateTerminalIndex",
    "SealedResultEvidenceSet",
    "all_candidates_terminal",
    "candidate_terminal_index_digest",
    "open_result_persistence_journal",
    "persist_cache_admissible_result",
    "persist_finalized_candidate",
    "persisted_candidate_terminals",
    "project_terminal_ledgers",
    "seal_candidate_terminal_index",
    "seal_result_evidence_set",
]
