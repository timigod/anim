"""Exact in-process scientific source capture.

The capture capability in this module is an authority bridge, not a metric or
report model.  It can be issued only from the exact live
``SealedResultEvidenceSet`` owner graph.  The same closure owns the one-shot
``SealedScientificEvidence`` issuer, derives its records from private immutable
snapshots, and exposes only privacy-safe deterministic aggregate projections.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import date
from math import isfinite as _math_isfinite
from threading import RLock
from types import MappingProxyType
from typing import Any, Final, Never, Protocol, SupportsIndex, cast, final
from unicodedata import category as _unicode_category
from unicodedata import is_normalized as _unicode_is_normalized

import numpy as np
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from ebm_audit._capability_registry import (
    CallbackFreeWeakIdentityMap,
    OneShotRegistryError,
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.adapters import AuthenticatedWorkerExecutionEvidence
from ebm_audit.adapters.invocation import _readback_authenticated_execution
from ebm_audit.errors import InvalidInputError
from ebm_audit.metrics import ConvergenceChainInput, derive_convergence_record
from ebm_audit.metrics.convergence import is_canonical_non_sampling_convergence_record
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.protocol.canonical import structured_sha256_hex
from ebm_audit.results.finalization import (
    FinalizedResult,
    _assert_finalized_result_state_current,
    _capture_finalized_result_state,
    _FinalizedResultState,
)
from ebm_audit.results.persistence import (
    SealedResultEvidenceSet,
    _acquire_scientific_ledger_receipt_issuer,
    _sealed_result_evidence_run,
    _SealedResultEvidenceRunBinding,
)
from ebm_audit.schema import validate_instance
from ebm_audit.schema.validation import (
    _RFC3339_DATE_TIME,
    _schema_registry,
    _validation_schema,
)
from ebm_audit.synthetic.authority import ScenarioAuthority
from ebm_audit.synthetic.models import ResolvedSyntheticCase
from ebm_audit.universe.preparation import (
    _capture_preparation_transaction_candidate_states,
    _capture_preparation_transaction_state_identity,
    _capture_public_synthetic_preparation_binding,
    _resolve_prepared_execution_authorization,
)

from ._evidence_records import (
    CHAIN_TOP_K_RULE_ID,
    OVERALL_EVIDENCE_RULE_ID,
    POSITION_SUMMARY_QUANTILE_PROBABILITIES,
    POSITION_SUMMARY_RULE_ID,
    _CanonicalCandidateEvidenceRecord,
    _ChainEvidenceInput,
    _cross_check_tolerance_rule,
    _derive_candidate_evidence_record,
    _uncertainty_layer_coverage,
)
from ._frozen_derivation import build_frozen_dependency_guard
from ._influence_evidence import (
    _INFLUENCE_DERIVATION,
    INFLUENCE_EVIDENCE_RULE_ID,
    _CanonicalInfluenceAttempt,
    _CanonicalInfluenceEvidenceBundle,
    _CanonicalInfluenceLayerEvidence,
    _derive_influence_evidence,
    _InfluenceCandidateInput,
    _InfluenceOriginInput,
    _validate_influence_semantics,
)
from ._null_evidence import (
    _NULL_DERIVATION,
    NULL_EVIDENCE_RULE_ID,
    _CanonicalNullLayerEvidence,
    _derive_null_evidence,
    _NullCandidateInput,
    _validate_null_semantics,
)
from ._origin_comparisons import (
    _ANALYST_DECISION_DERIVATION,
    ANALYST_DECISION_EVIDENCE_RULE_ID,
    SEALED_EVIDENCE_RULE_ID,
    _AnalystDecisionCandidateInput,
    _AnalystDecisionOriginInput,
    _CanonicalAnalystDecisionAggregate,
    _CanonicalAnalystDecisionEvidenceBundle,
    _CanonicalAnalystDecisionLayerEvidence,
    _CanonicalOriginComparisonAttempt,
    _CanonicalOriginNumericComparisonRecord,
    _derive_analyst_decision_evidence,
)
from ._sampling_evidence import (
    _SAMPLING_DERIVATION,
    SAMPLING_EVIDENCE_RULE_ID,
    _CanonicalSamplingEvidenceBundle,
    _CanonicalSamplingFamilyAggregate,
    _CanonicalSamplingLayerEvidence,
    _CanonicalSamplingNumericComparison,
    _CanonicalSamplingOriginAttempt,
    _derive_sampling_evidence,
    _SamplingCandidateInput,
    _SamplingOriginInput,
    _validate_sampling_semantics,
)
from ._stage_comparisons import (
    _STAGE_COMPARISON_DERIVATION,
    PRIVATE_STAGE_COMPARISON_DIGEST_DOMAIN,
    _DerivedStageComparison,
    _StageComparisonSideInput,
    derive_stage_comparison_owner,
)

_CAPTURE_LOCK = RLock()
SCIENTIFIC_EVIDENCE_SCHEMA_VERSION: Final = "ebm-audit-sealed-scientific-evidence/10.0"
_SCIENCE_LEDGER_RECEIPT_SCHEMA_VERSION: Final = "ebm-audit-science-ledger-receipt/1.0"
_SCIENCE_LEDGER_RECEIPT_DIGEST_DOMAIN: Final = "ebm-audit/science-ledger-receipt/1"
(
    _ISSUE_SCIENTIFIC_LEDGER_RECEIPT,
    _REQUIRE_SCIENTIFIC_LEDGER_RECEIPT,
) = cast(Any, _acquire_scientific_ledger_receipt_issuer)()
globals().pop("_acquire_scientific_ledger_receipt_issuer", None)


class ScientificEvidenceError(TypeError):
    """Raised when exact live scientific source authority is absent or detached."""


def _validated_synthetic_case_binding(
    authority: ScenarioAuthority,
    resolved_case: ResolvedSyntheticCase,
    /,
) -> dict[str, str]:
    """Return the exact synthetic identity after full authority verification."""

    if type(authority) is not ScenarioAuthority or type(resolved_case) is not ResolvedSyntheticCase:
        raise ScientificEvidenceError(
            "A genuine scenario authority and resolved synthetic case are required."
        )
    try:
        authority.verify_resolved_case(resolved_case)
    except (TypeError, ValueError):
        raise ScientificEvidenceError("Synthetic case authority validation failed.") from None
    return {
        "case_id": resolved_case.case_id,
        "source_contract_sha256": resolved_case.source_contract_sha256,
        "scenario_definitions_sha256": resolved_case.scenario_definitions_sha256,
    }


def _captured_synthetic_case_binding_bytes(
    finalized_record_bytes: Sequence[bytes],
    /,
    *,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
) -> bytes | None:
    """Project one exact synthetic identity from authenticated finalized records."""

    retained_binding_bytes: bytes | None = None
    saw_unbound_record = False
    for canonical_bytes in finalized_record_bytes:
        record = _strict_json_loads(canonical_bytes)
        body = record.get("body") if type(record) is dict else None
        provenance = body.get("synthetic_provenance") if type(body) is dict else None
        if provenance is None:
            saw_unbound_record = True
            if retained_binding_bytes is not None:
                raise _scientific_evidence_error_type(
                    "Captured synthetic source identity is incomplete."
                )
            continue
        if type(provenance) is not dict:
            raise _scientific_evidence_error_type("Captured synthetic source identity is invalid.")
        project_candidate = provenance.get("project_candidate")
        if project_candidate is None:
            saw_unbound_record = True
            if retained_binding_bytes is not None:
                raise _scientific_evidence_error_type(
                    "Captured synthetic source identity is incomplete."
                )
            continue
        if type(project_candidate) is not dict:
            raise _scientific_evidence_error_type(
                "Captured synthetic source identity is invalid."
            )
        case_id = project_candidate.get("case_id")
        source_contract_sha256 = project_candidate.get("source_contract_sha256")
        scenario_definitions_sha256 = project_candidate.get(
            "scenario_definitions_sha256"
        )
        if (
            saw_unbound_record
            or type(case_id) is not str
            or provenance.get("complete_truth_record_id") != case_id
            or type(source_contract_sha256) is not str
            or not source_contract_sha256.startswith("sha256:")
            or type(scenario_definitions_sha256) is not str
            or not scenario_definitions_sha256.startswith("sha256:")
        ):
            raise _scientific_evidence_error_type(
                "Captured synthetic source identity is incomplete."
            )
        binding = {
            "case_id": case_id,
            "source_contract_sha256": source_contract_sha256.removeprefix("sha256:"),
            "scenario_definitions_sha256": scenario_definitions_sha256.removeprefix(
                "sha256:"
            ),
        }
        binding_bytes = _canonical_json_bytes(binding)
        if retained_binding_bytes is None:
            retained_binding_bytes = binding_bytes
        elif binding_bytes != retained_binding_bytes:
            raise _scientific_evidence_error_type(
                "Captured synthetic source identity is inconsistent."
            )
    return retained_binding_bytes


def _require_captured_synthetic_case_binding(
    finalized_record_bytes: Sequence[bytes],
    expected_binding_bytes: bytes | None,
    /,
    *,
    _captured_binding_bytes: Callable[
        [Sequence[bytes]], bytes | None
    ] = _captured_synthetic_case_binding_bytes,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
) -> None:
    captured_binding_bytes = _captured_binding_bytes(finalized_record_bytes)
    if captured_binding_bytes is not None and captured_binding_bytes != expected_binding_bytes:
        raise _scientific_evidence_error_type(
            "Resolved synthetic case does not match captured scientific source evidence."
        )


class _LockedScientificType(type):
    """Reject ordinary mutation of calculation-bound private classes."""

    def __setattr__(cls, name: str, value: object) -> None:
        namespace = cast(Mapping[str, object], type.__getattribute__(cls, "__dict__"))
        if namespace.get("_scientific_boundary_locked", False):
            raise TypeError("Scientific boundary classes cannot be modified.")
        type.__setattr__(cls, name, value)

    def __delattr__(cls, name: str) -> None:
        namespace = cast(Mapping[str, object], type.__getattribute__(cls, "__dict__"))
        if namespace.get("_scientific_boundary_locked", False):
            raise TypeError("Scientific boundary classes cannot be modified.")
        type.__delattr__(cls, name)


def _lock_scientific_type(class_type: type[object], /) -> None:
    type.__setattr__(class_type, "_scientific_boundary_locked", True)


_METHOD_DISPATCH_ISSUER = object()


@final
class _OneShotMethodDispatch(metaclass=_LockedScientificType):
    """Bind one opaque-class method path exactly once, then expose only calls."""

    __slots__ = ("__target",)

    def __init__(self) -> None:
        object.__setattr__(self, "_OneShotMethodDispatch__target", None)

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise TypeError("Scientific method dispatch is immutable.")

    def bind_once(
        self,
        issuer: object,
        target: Callable[[object], object],
        /,
        *,
        _expected_issuer: object = _METHOD_DISPATCH_ISSUER,
    ) -> None:
        current = object.__getattribute__(self, "_OneShotMethodDispatch__target")
        if issuer is not _expected_issuer or current is not None or not callable(target):
            raise TypeError("Scientific method dispatch cannot be rebound.")
        object.__setattr__(self, "_OneShotMethodDispatch__target", target)

    def __call__(
        self,
        value: object,
        /,
        _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    ) -> object:
        target = object.__getattribute__(self, "_OneShotMethodDispatch__target")
        if not callable(target):
            raise _error_type("Scientific method boundary is unavailable.")
        try:
            return target(value)
        finally:
            del value


_lock_scientific_type(_OneShotMethodDispatch)
_CAPTURE_METHOD_DISPATCH = _OneShotMethodDispatch()
_EVIDENCE_METHOD_DISPATCH = _OneShotMethodDispatch()


@dataclass(frozen=True, repr=False, slots=True)
class _ScientificArraySnapshot(metaclass=_LockedScientificType):
    """One private C-order copy backed by immutable bytes."""

    name: str
    dtype: str
    shape: tuple[int, ...]
    catalog_bytes: bytes
    private_array_bytes: bytes

    def _array(
        self,
        _ScientificEvidenceError: type[ScientificEvidenceError] = ScientificEvidenceError,
        _np_dtype: Callable[[Any], np.dtype[Any]] = np.dtype,
        _np_frombuffer: Callable[..., np.ndarray[Any, Any]] = np.frombuffer,
    ) -> np.ndarray[Any, Any]:
        value = _np_frombuffer(
            self.private_array_bytes,
            dtype=_np_dtype(self.dtype),
        ).reshape(self.shape)
        if value.flags.writeable:
            raise _ScientificEvidenceError("Captured scientific array storage is mutable.")
        return value


_lock_scientific_type(_ScientificArraySnapshot)


@dataclass(frozen=True, repr=False, slots=True)
class _CapturedChainState(metaclass=_LockedScientificType):
    execution: AuthenticatedWorkerExecutionEvidence
    execution_evidence_digest: str
    response_bytes: bytes
    chain_payload_bytes: bytes
    chain_plan_position: int
    chain_execution_id: str
    final_attempt_id: str
    chain_payload_digest: str
    retained_state_count: int | None
    central_order_event_ids: tuple[str, ...]
    central_order_method_bytes: bytes
    arrays: tuple[_ScientificArraySnapshot, ...]


_lock_scientific_type(_CapturedChainState)


@dataclass(frozen=True, repr=False, slots=True)
class _CapturedCandidateState(metaclass=_LockedScientificType):
    candidate_ordinal: int
    candidate_id: str
    analysis_spec_id: str
    candidate_record_bytes: bytes
    comparison_edges_bytes: bytes
    terminal_record_bytes: bytes
    persisted_result: object
    finalized_result: FinalizedResult
    finalized_result_state: _FinalizedResultState
    finalized_record_bytes: bytes
    result_id: str
    universe_id: str | None
    final_status: str
    planned_chain_count: int
    finalized_terminal_chain_count: int
    authenticated_available_chain_count: int
    convergence_record_bytes: bytes | None
    convergence_assessment: str | None
    convergence_rule_set_version: str | None
    reference_chain_bytes: bytes | None
    event_ids: tuple[str, ...]
    event_directions: tuple[tuple[str, str], ...]
    stage_semantics_digest: str
    chains: tuple[_CapturedChainState, ...]


_lock_scientific_type(_CapturedCandidateState)


@dataclass(frozen=True, repr=False)
class _CapturedScientificRunState(metaclass=_LockedScientificType):
    sealed_result_evidence_set: SealedResultEvidenceSet
    plan_candidate_authorization: object
    preparation_transaction: object
    influence_input_receipt: object
    influence_input_snapshot: object
    candidate_result_authorizations: tuple[object, ...]
    terminal_authorization: object
    sealed_terminal_index: object
    persisted_results: tuple[object, ...]
    persisted_cache_results: tuple[object, ...]
    finalized_results: tuple[FinalizedResult, ...]
    terminal_index_digest: str
    plan_digest: str
    preparation_receipt_digest: str
    influence_preparation_binding_bytes: tuple[bytes, ...]
    influence_preparation_bindings_digest: str
    stage_preparation_binding_bytes: tuple[bytes, ...]
    stage_preparation_bindings_digest: str
    baseline_analysis_spec_id: str
    plan_candidates_bytes: bytes
    origin_comparison_edges_bytes: bytes
    candidate_terminals_bytes: bytes
    synthetic_case_binding_bytes: bytes | None
    candidates: tuple[_CapturedCandidateState, ...]


_lock_scientific_type(_CapturedScientificRunState)


@dataclass(frozen=True, repr=False, slots=True)
class _SealedScientificEvidenceState(metaclass=_LockedScientificType):
    capture: CapturedScientificRun
    canonical_projection_bytes: bytes
    ledger_receipt_canonical_bytes: bytes
    ledger_receipt_digest: str
    candidate_preimage_bytes: tuple[bytes, ...]
    candidate_canonical_bytes: tuple[bytes, ...]
    candidate_record_digests: tuple[str, ...]
    attempt_preimage_bytes: tuple[bytes, ...]
    attempt_canonical_bytes: tuple[bytes, ...]
    attempt_digests: tuple[str, ...]
    numeric_preimage_bytes: tuple[bytes, ...]
    numeric_canonical_bytes: tuple[bytes, ...]
    numeric_digests: tuple[str, ...]
    aggregate_preimage_bytes: tuple[bytes, ...]
    aggregate_canonical_bytes: tuple[bytes, ...]
    aggregate_digests: tuple[str, ...]
    stage_comparison_private_canonical_bytes: tuple[bytes, ...]
    stage_comparison_private_digests: tuple[str, ...]
    analyst_layer_preimage_bytes: bytes
    analyst_layer_canonical_bytes: bytes
    analyst_layer_digest: str
    sampling_attempt_preimage_bytes: tuple[bytes, ...]
    sampling_attempt_canonical_bytes: tuple[bytes, ...]
    sampling_attempt_digests: tuple[str, ...]
    sampling_numeric_preimage_bytes: tuple[bytes, ...]
    sampling_numeric_canonical_bytes: tuple[bytes, ...]
    sampling_numeric_digests: tuple[str, ...]
    sampling_aggregate_preimage_bytes: tuple[bytes, ...]
    sampling_aggregate_canonical_bytes: tuple[bytes, ...]
    sampling_aggregate_digests: tuple[str, ...]
    sampling_layer_preimage_bytes: bytes
    sampling_layer_canonical_bytes: bytes
    sampling_layer_digest: str
    influence_attempt_preimage_bytes: tuple[bytes, ...]
    influence_attempt_canonical_bytes: tuple[bytes, ...]
    influence_attempt_digests: tuple[str, ...]
    influence_layer_preimage_bytes: bytes
    influence_layer_canonical_bytes: bytes
    influence_layer_digest: str
    null_layer_preimage_bytes: bytes
    null_layer_canonical_bytes: bytes
    null_layer_digest: str
    evidence_digest: str
    candidate_count: int


_lock_scientific_type(_SealedScientificEvidenceState)


@dataclass(frozen=True, repr=False, slots=True)
class _DerivedScientificProjection(metaclass=_LockedScientificType):
    canonical_projection_bytes: bytes
    evidence_digest: str
    ledger_receipt_canonical_bytes: bytes
    ledger_receipt_digest: str
    candidate_preimage_bytes: tuple[bytes, ...]
    candidate_canonical_bytes: tuple[bytes, ...]
    candidate_record_digests: tuple[str, ...]
    attempt_preimage_bytes: tuple[bytes, ...]
    attempt_canonical_bytes: tuple[bytes, ...]
    attempt_digests: tuple[str, ...]
    numeric_preimage_bytes: tuple[bytes, ...]
    numeric_canonical_bytes: tuple[bytes, ...]
    numeric_digests: tuple[str, ...]
    aggregate_preimage_bytes: tuple[bytes, ...]
    aggregate_canonical_bytes: tuple[bytes, ...]
    aggregate_digests: tuple[str, ...]
    stage_comparison_private_canonical_bytes: tuple[bytes, ...]
    stage_comparison_private_digests: tuple[str, ...]
    analyst_layer_preimage_bytes: bytes
    analyst_layer_canonical_bytes: bytes
    analyst_layer_digest: str
    sampling_attempt_preimage_bytes: tuple[bytes, ...]
    sampling_attempt_canonical_bytes: tuple[bytes, ...]
    sampling_attempt_digests: tuple[str, ...]
    sampling_numeric_preimage_bytes: tuple[bytes, ...]
    sampling_numeric_canonical_bytes: tuple[bytes, ...]
    sampling_numeric_digests: tuple[str, ...]
    sampling_aggregate_preimage_bytes: tuple[bytes, ...]
    sampling_aggregate_canonical_bytes: tuple[bytes, ...]
    sampling_aggregate_digests: tuple[str, ...]
    sampling_layer_preimage_bytes: bytes
    sampling_layer_canonical_bytes: bytes
    sampling_layer_digest: str
    influence_attempt_preimage_bytes: tuple[bytes, ...]
    influence_attempt_canonical_bytes: tuple[bytes, ...]
    influence_attempt_digests: tuple[str, ...]
    influence_layer_preimage_bytes: bytes
    influence_layer_canonical_bytes: bytes
    influence_layer_digest: str
    null_layer_preimage_bytes: bytes
    null_layer_canonical_bytes: bytes
    null_layer_digest: str


_lock_scientific_type(_DerivedScientificProjection)


@dataclass(frozen=True, repr=False, slots=True)
class _SanitizedScientificControlFlow(metaclass=_LockedScientificType):
    kind: str
    exit_code: int | None = None


_lock_scientific_type(_SanitizedScientificControlFlow)


def _reject_capture_copy() -> Never:
    raise TypeError("Captured scientific runs cannot be copied or serialized.")


@final
class CapturedScientificRun(metaclass=_LockedScientificType):
    """Opaque private capture of one exact current sealed result-evidence graph."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("CapturedScientificRun cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "Captured scientific runs are issued from exact sealed result evidence only."
        )

    @property
    def candidate_count(
        self,
        _dispatch: Callable[[object], object] = _CAPTURE_METHOD_DISPATCH,
        _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    ) -> int:
        try:
            summary = _dispatch(self)
        finally:
            del self
        if (
            type(summary) is not tuple
            or len(summary) != 2
            or type(summary[0]) is not int
            or type(summary[1]) is not int
        ):
            raise _error_type("Captured scientific summary is invalid.")
        return summary[0]

    @property
    def descriptive_chain_count(
        self,
        _dispatch: Callable[[object], object] = _CAPTURE_METHOD_DISPATCH,
        _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    ) -> int:
        try:
            summary = _dispatch(self)
        finally:
            del self
        if (
            type(summary) is not tuple
            or len(summary) != 2
            or type(summary[0]) is not int
            or type(summary[1]) is not int
        ):
            raise _error_type("Captured scientific summary is invalid.")
        return summary[1]

    def __repr__(
        self,
        _dispatch: Callable[[object], object] = _CAPTURE_METHOD_DISPATCH,
        _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    ) -> str:
        try:
            summary = _dispatch(self)
        finally:
            del self
        if (
            type(summary) is not tuple
            or len(summary) != 2
            or type(summary[0]) is not int
            or type(summary[1]) is not int
        ):
            raise _error_type("Captured scientific summary is invalid.")
        candidate_count, descriptive_chain_count = summary
        return (
            "CapturedScientificRun("
            f"candidate_count={candidate_count}, "
            f"descriptive_chain_count={descriptive_chain_count})"
        )

    def __copy__(
        self,
        _reject: Callable[[], Never] = _reject_capture_copy,
    ) -> CapturedScientificRun:
        _reject()

    def __deepcopy__(
        self,
        _memo: object,
        _reject: Callable[[], Never] = _reject_capture_copy,
    ) -> CapturedScientificRun:
        _reject()

    def __reduce__(
        self,
        _reject: Callable[[], Never] = _reject_capture_copy,
    ) -> str | tuple[object, ...]:
        _reject()

    def __reduce_ex__(
        self,
        _protocol: SupportsIndex,
        _reject: Callable[[], Never] = _reject_capture_copy,
    ) -> str | tuple[object, ...]:
        _reject()

    def __getstate__(
        self,
        _reject: Callable[[], Never] = _reject_capture_copy,
    ) -> object:
        _reject()


_lock_scientific_type(CapturedScientificRun)


def _reject_evidence_copy() -> Never:
    raise TypeError("Sealed scientific evidence cannot be copied or serialized.")


@final
class SealedScientificEvidence(metaclass=_LockedScientificType):
    """Opaque authority for deterministic privacy-safe scientific records."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("SealedScientificEvidence cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Sealed scientific evidence is issued from one exact captured run only.")

    @property
    def candidate_count(
        self,
        _dispatch: Callable[[object], object] = _EVIDENCE_METHOD_DISPATCH,
        _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    ) -> int:
        try:
            projection = _dispatch(self)
        finally:
            del self
        if type(projection) is not dict:
            raise _error_type("Sealed scientific evidence projection is invalid.")
        records = projection["candidate_records"]
        if type(records) is not list:
            raise _error_type("Sealed scientific evidence projection is invalid.")
        return len(records)

    @property
    def evidence_digest(
        self,
        _dispatch: Callable[[object], object] = _EVIDENCE_METHOD_DISPATCH,
        _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    ) -> str:
        try:
            projection = _dispatch(self)
        finally:
            del self
        if type(projection) is not dict:
            raise _error_type("Sealed scientific evidence projection is invalid.")
        digest = projection["scientific_evidence_digest"]
        if type(digest) is not str:
            raise _error_type("Sealed scientific evidence projection is invalid.")
        return digest

    def __repr__(
        self,
        _dispatch: Callable[[object], object] = _EVIDENCE_METHOD_DISPATCH,
        _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    ) -> str:
        try:
            projection = _dispatch(self)
        finally:
            del self
        if type(projection) is not dict:
            raise _error_type("Sealed scientific evidence projection is invalid.")
        records = projection.get("candidate_records")
        digest = projection.get("scientific_evidence_digest")
        if type(records) is not list or type(digest) is not str:
            raise _error_type("Sealed scientific evidence projection is invalid.")
        return (
            f"SealedScientificEvidence(candidate_count={len(records)}, evidence_digest={digest!r})"
        )

    def __copy__(
        self,
        _reject: Callable[[], Never] = _reject_evidence_copy,
    ) -> SealedScientificEvidence:
        _reject()

    def __deepcopy__(
        self,
        _memo: object,
        _reject: Callable[[], Never] = _reject_evidence_copy,
    ) -> SealedScientificEvidence:
        _reject()

    def __reduce__(
        self,
        _reject: Callable[[], Never] = _reject_evidence_copy,
    ) -> str | tuple[object, ...]:
        _reject()

    def __reduce_ex__(
        self,
        _protocol: SupportsIndex,
        _reject: Callable[[], Never] = _reject_evidence_copy,
    ) -> str | tuple[object, ...]:
        _reject()

    def __getstate__(
        self,
        _reject: Callable[[], Never] = _reject_evidence_copy,
    ) -> object:
        _reject()


_lock_scientific_type(SealedScientificEvidence)


@dataclass(slots=True)
class _ScientificEvidenceReadLease:
    """One fully authenticated science pair retained for one live transaction."""

    active: bool
    capture_owner: object
    capture_state: object
    evidence_owner: object | None
    evidence_state: object | None
    lock: RLock


_ACTIVE_SCIENTIFIC_EVIDENCE_READS: ContextVar[
    tuple[_ScientificEvidenceReadLease, ...]
] = ContextVar("ebm_audit_scientific_evidence_read_leases", default=())


def _leased_captured_scientific_run_state(value: object) -> object | None:
    """Return an exact live captured state only from the current transaction."""

    for lease in reversed(_ACTIVE_SCIENTIFIC_EVIDENCE_READS.get()):
        with lease.lock:
            if lease.active and lease.capture_owner is value:
                return lease.capture_state
    return None


def _leased_sealed_scientific_evidence_state(value: object) -> object | None:
    """Return an exact live sealed state only from the current transaction."""

    for lease in reversed(_ACTIVE_SCIENTIFIC_EVIDENCE_READS.get()):
        with lease.lock:
            if lease.active and lease.evidence_owner is value:
                return lease.evidence_state
    return None


def _closed_mapping_bytes(
    value: object,
    *,
    description: str,
    _mapping_type: Any = Mapping,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
    canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
) -> bytes:
    if not isinstance(value, _mapping_type):
        raise _scientific_evidence_error_type(description)
    try:
        return canonical_json_bytes(dict(value))
    except (TypeError, ValueError):
        raise _scientific_evidence_error_type(description) from None


def _capture_array_snapshots(
    response: Mapping[str, Any],
    response_arrays: Mapping[str, Any],
    *,
    _mapping_type: Any = Mapping,
    _scientific_array_snapshot_type: type[_ScientificArraySnapshot] = (_ScientificArraySnapshot),
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
    _closed_mapping_bytes: Any = _closed_mapping_bytes,
    np_ndarray_type: type[np.ndarray[Any, Any]] = np.ndarray,
) -> tuple[_ScientificArraySnapshot, ...]:
    payload = response.get("payload")
    result = payload.get("result") if isinstance(payload, _mapping_type) else None
    catalog = result.get("array_catalog") if isinstance(result, _mapping_type) else None
    if not isinstance(catalog, _mapping_type) or set(catalog) != set(response_arrays):
        raise _scientific_evidence_error_type(
            "Authenticated scientific arrays have no exact closed catalogue."
        )
    snapshots: list[_ScientificArraySnapshot] = []
    for name in sorted(response_arrays):
        if type(name) is not str:
            raise _scientific_evidence_error_type(
                "Authenticated scientific arrays have invalid names."
            )
        array = response_arrays[name]
        catalog_entry = catalog.get(name)
        if type(array) is not np_ndarray_type or not isinstance(
            catalog_entry,
            _mapping_type,
        ):
            raise _scientific_evidence_error_type(
                "Authenticated scientific arrays have invalid exact storage."
            )
        snapshot = _scientific_array_snapshot_type(
            name=name,
            dtype=array.dtype.str,
            shape=tuple(int(size) for size in array.shape),
            catalog_bytes=_closed_mapping_bytes(
                catalog_entry,
                description="Authenticated scientific array catalogue is invalid.",
            ),
            private_array_bytes=bytes(array.tobytes(order="C")),
        )
        snapshot._array()
        snapshots.append(snapshot)
    return tuple(snapshots)


def _candidate_origins(
    candidate: Mapping[str, Any],
    *,
    _cast: Any = cast,
    _mapping_type: Any = Mapping,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
) -> tuple[Mapping[str, Any], ...]:
    primary = candidate.get("primary_origin")
    duplicates = candidate.get("duplicate_origins")
    if (
        not isinstance(primary, _mapping_type)
        or type(duplicates) is not list
        or any(not isinstance(origin, _mapping_type) for origin in duplicates)
    ):
        raise _scientific_evidence_error_type("Plan/3 candidate origins are invalid.")
    origins = (primary, *(_cast(Mapping[str, Any], origin) for origin in duplicates))
    for origin in origins:
        choices = origin.get("axis_choices")
        if (
            type(origin.get("experiment_mode")) is not str
            or type(choices) is not list
            or any(
                not isinstance(choice, _mapping_type)
                or type(choice.get("axis_id")) is not str
                or type(choice.get("choice_id")) is not str
                for choice in choices
            )
            or (origin["experiment_mode"] == "one-axis" and len(choices) != 1)
            or (
                origin["experiment_mode"] in {"declared-combinations", "full-factorial"}
                and len(choices) < 2
            )
        ):
            raise _scientific_evidence_error_type("Plan/3 candidate origins are invalid.")
    return origins


def _candidate_event_semantics(
    candidate: Mapping[str, Any],
    *,
    _cast: Any = cast,
    _mapping_type: Any = Mapping,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...], str]:
    analysis_spec = candidate.get("analysis_spec")
    if not isinstance(analysis_spec, _mapping_type):
        raise _scientific_evidence_error_type("Plan/3 candidate event semantics are invalid.")
    event_set = analysis_spec.get("event_set")
    directions = analysis_spec.get("event_directions")
    backend = analysis_spec.get("backend")
    if (
        type(event_set) is not list
        or any(not isinstance(event, _mapping_type) for event in event_set)
        or not isinstance(directions, _mapping_type)
        or not isinstance(backend, _mapping_type)
    ):
        raise _scientific_evidence_error_type("Plan/3 candidate event semantics are invalid.")
    event_ids = tuple(event.get("event_id") for event in event_set)
    stage_semantics_digest = backend.get("stage_semantics_digest")
    if (
        any(type(event_id) is not str for event_id in event_ids)
        or len(set(event_ids)) != len(event_ids)
        or type(stage_semantics_digest) is not str
        or set(directions) != set(event_ids)
        or any(type(directions[event_id]) is not str for event_id in event_ids)
    ):
        raise _scientific_evidence_error_type("Plan/3 candidate event semantics are invalid.")
    exact_event_ids = _cast(tuple[str, ...], event_ids)
    return (
        exact_event_ids,
        tuple((event_id, _cast(str, directions[event_id])) for event_id in exact_event_ids),
        stage_semantics_digest,
    )


def _planned_chain_count(
    candidate: Mapping[str, Any],
    *,
    _mapping_type: Any = Mapping,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
) -> int:
    analysis_spec = candidate.get("analysis_spec")
    chain_slots = candidate.get("chain_slots")
    planned_fit_ceiling = candidate.get("planned_fit_ceiling")
    planning_outcome = candidate.get("planning_outcome")
    if (
        not isinstance(analysis_spec, _mapping_type)
        or type(chain_slots) is not list
        or type(planned_fit_ceiling) is not int
        or planned_fit_ceiling < 0
        or len(chain_slots) != planned_fit_ceiling
        or planning_outcome not in {"PLANNED", "PLAN_INELIGIBLE"}
    ):
        raise _scientific_evidence_error_type("Plan/3 AnalysisSpec storage is invalid.")
    for ordinal, slot in enumerate(chain_slots):
        if (
            not isinstance(slot, _mapping_type)
            or slot.get("chain_ordinal") != ordinal
            or slot.get("chain_id") != f"chain-{ordinal:04d}"
        ):
            raise _scientific_evidence_error_type("Plan/3 chain-slot storage is invalid.")
    mcmc = analysis_spec.get("mcmc")
    if planning_outcome == "PLAN_INELIGIBLE":
        if planned_fit_ceiling != 0:
            raise _scientific_evidence_error_type("Plan/3 ineligible chain accounting is invalid.")
        return 0
    if mcmc is None:
        if planned_fit_ceiling != 1:
            raise _scientific_evidence_error_type("Plan/3 non-sampling fit accounting is invalid.")
        return planned_fit_ceiling
    chain_count = mcmc.get("chain_count") if isinstance(mcmc, _mapping_type) else None
    if type(chain_count) is not int or chain_count < 1 or chain_count != planned_fit_ceiling:
        raise _scientific_evidence_error_type("Plan/3 AnalysisSpec chain count is invalid.")
    return planned_fit_ceiling


def _finalized_terminal_chain_count(
    body: Mapping[str, Any],
    *,
    planned_chain_count: int,
    _mapping_type: Any = Mapping,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
) -> int:
    rows = body.get("fit_attempt_evidence")
    if rows is None:
        if body.get("record_kind") != "UNPREPARED":
            raise _scientific_evidence_error_type("Finalized fit-terminal accounting is invalid.")
        return 0
    if type(rows) is not list:
        raise _scientific_evidence_error_type("Finalized fit-terminal accounting is invalid.")

    observed_positions: list[int] = []
    attempt_ordinals_by_position: dict[int, list[int]] = {}
    for row in rows:
        if not isinstance(row, _mapping_type):
            raise _scientific_evidence_error_type("Finalized fit-terminal accounting is invalid.")
        position = row.get("chain_plan_position")
        attempt_ordinal = row.get("attempt_ordinal")
        if (
            row.get("command") != "fit"
            or type(position) is not int
            or position < 0
            or position >= planned_chain_count
            or type(attempt_ordinal) is not int
            or attempt_ordinal not in {0, 1}
        ):
            raise _scientific_evidence_error_type("Finalized fit-terminal accounting is invalid.")
        if position not in attempt_ordinals_by_position:
            observed_positions.append(position)
            attempt_ordinals_by_position[position] = []
        attempt_ordinals_by_position[position].append(attempt_ordinal)

    if observed_positions != list(range(len(observed_positions))) or any(
        ordinals not in ([0], [0, 1]) for ordinals in attempt_ordinals_by_position.values()
    ):
        raise _scientific_evidence_error_type("Finalized fit-terminal accounting is invalid.")
    terminal_count = len(observed_positions)
    record_kind = body.get("record_kind")
    failed_command = body.get("failed_command")
    if record_kind in {"COMPLETED", "CONVERGENCE_NON_SUCCESS"} or (
        record_kind == "EXECUTION_NON_SUCCESS" and failed_command == "fit"
    ):
        if terminal_count != planned_chain_count:
            raise _scientific_evidence_error_type(
                "Finalized fit-terminal accounting is incomplete."
            )
    elif terminal_count != 0:
        raise _scientific_evidence_error_type("Finalized fit-terminal accounting is invalid.")

    chain_results = body.get("chain_results")
    if record_kind in {"COMPLETED", "CONVERGENCE_NON_SUCCESS"}:
        if type(chain_results) is not list or len(chain_results) != terminal_count:
            raise _scientific_evidence_error_type("Finalized chain-result accounting is invalid.")
    elif chain_results is not None:
        raise _scientific_evidence_error_type("Finalized chain-result accounting is invalid.")
    return terminal_count


def _convergence_identity(
    convergence: object,
    *,
    _mapping_type: Any = Mapping,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
) -> tuple[str | None, str | None]:
    if convergence is None:
        return None, None
    if not isinstance(convergence, _mapping_type):
        raise _scientific_evidence_error_type("Finalized convergence storage is invalid.")
    assessment = convergence.get("assessment")
    rule_set_version = convergence.get("rule_set_version")
    if type(assessment) is not str or type(rule_set_version) is not str:
        raise _scientific_evidence_error_type("Finalized convergence identity is invalid.")
    return assessment, rule_set_version


def _capture_candidate(
    *,
    candidate: Mapping[str, Any],
    comparison_edges: tuple[Mapping[str, Any], ...],
    terminal: Mapping[str, Any],
    persisted_result: object,
    finalized_result: FinalizedResult,
    _authenticated_execution_type: type[AuthenticatedWorkerExecutionEvidence] = (
        AuthenticatedWorkerExecutionEvidence
    ),
    _captured_candidate_state_type: type[_CapturedCandidateState] = (_CapturedCandidateState),
    _captured_chain_state_type: type[_CapturedChainState] = _CapturedChainState,
    _cast: Any = cast,
    _mapping_type: Any = Mapping,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
    _capture_finalized_result_state: Any = _capture_finalized_result_state,
    _planned_chain_count: Any = _planned_chain_count,
    _finalized_terminal_chain_count: Any = _finalized_terminal_chain_count,
    _candidate_event_semantics: Any = _candidate_event_semantics,
    _readback_authenticated_execution: Any = _readback_authenticated_execution,
    _closed_mapping_bytes: Any = _closed_mapping_bytes,
    _capture_array_snapshots: Any = _capture_array_snapshots,
    _convergence_identity: Any = _convergence_identity,
    canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
) -> _CapturedCandidateState:
    ordinal = candidate.get("candidate_ordinal")
    candidate_id = candidate.get("candidate_id")
    analysis_spec_id = candidate.get("analysis_spec_id")
    if (
        type(ordinal) is not int
        or type(candidate_id) is not str
        or type(analysis_spec_id) is not str
    ):
        raise _scientific_evidence_error_type("Plan/3 candidate identity is invalid.")
    if (
        terminal.get("candidate_ordinal"),
        terminal.get("candidate_id"),
        terminal.get("analysis_spec_id"),
    ) != (ordinal, candidate_id, analysis_spec_id):
        raise _scientific_evidence_error_type(
            "Candidate terminal is detached from its exact Plan/3 candidate."
        )
    result_state = _capture_finalized_result_state(finalized_result)
    record = strict_json_loads(result_state.canonical_bytes)
    if type(record) is not dict:
        raise _scientific_evidence_error_type("Finalized scientific result storage is invalid.")
    body = record.get("body")
    if not isinstance(body, _mapping_type):
        raise _scientific_evidence_error_type("Finalized scientific result storage is invalid.")
    if (
        body.get("candidate_ordinal"),
        body.get("candidate_id"),
        body.get("analysis_spec_id"),
        record.get("result_id"),
        body.get("status"),
    ) != (
        ordinal,
        candidate_id,
        analysis_spec_id,
        terminal.get("result_id"),
        terminal.get("final_status"),
    ):
        raise _scientific_evidence_error_type(
            "Finalized scientific result identity is detached from its terminal."
        )
    universe_id = body.get("universe_id")
    if (universe_id is not None and type(universe_id) is not str) or terminal.get(
        "universe_id"
    ) != universe_id:
        raise _scientific_evidence_error_type(
            "Finalized scientific universe identity is detached from its terminal."
        )

    planned_chain_count = _planned_chain_count(candidate)
    finalized_terminal_chain_count = _finalized_terminal_chain_count(
        body,
        planned_chain_count=planned_chain_count,
    )
    event_ids, event_directions, stage_semantics_digest = _candidate_event_semantics(candidate)
    body_event_ids = body.get("event_ids")
    if body_event_ids is not None and body_event_ids != list(event_ids):
        raise _scientific_evidence_error_type(
            "Finalized scientific result event identity is detached from Plan/3."
        )

    chains: list[_CapturedChainState] = []
    chain_results = body.get("chain_results")
    retained_chains = result_state.descriptive_chain_executions
    if retained_chains:
        if type(chain_results) is not list or len(chain_results) != len(retained_chains):
            raise _scientific_evidence_error_type(
                "Finalized scientific chain coverage is detached."
            )
        for position, (execution, chain_result) in enumerate(
            zip(retained_chains, chain_results, strict=True)
        ):
            if type(execution) is not _authenticated_execution_type or not isinstance(
                chain_result,
                _mapping_type,
            ):
                raise _scientific_evidence_error_type(
                    "Finalized scientific chain authority is invalid."
                )
            readback = _readback_authenticated_execution(execution)
            response = readback.response
            response_payload = response.get("payload")
            response_result = (
                response_payload.get("result")
                if isinstance(response_payload, _mapping_type)
                else None
            )
            chain_execution_id = chain_result.get("chain_execution_id")
            chain_plan_position = chain_result.get("chain_plan_position")
            final_attempt_id = chain_result.get("final_attempt_id")
            chain_payload_digest = chain_result.get("chain_payload_digest")
            retained_state_count = chain_result.get("retained_state_count")
            central_order = chain_result.get("central_order_event_ids")
            central_order_method = chain_result.get("central_order_method")
            if (
                not isinstance(response_result, _mapping_type)
                or type(chain_plan_position) is not int
                or chain_plan_position != position
                or type(chain_execution_id) is not str
                or type(final_attempt_id) is not str
                or type(chain_payload_digest) is not str
                or (
                    retained_state_count is not None
                    and (type(retained_state_count) is not int or retained_state_count < 1)
                )
                or type(central_order) is not list
                or any(type(event_id) is not str for event_id in central_order)
                or tuple(central_order) == ()
                or set(_cast(list[str], central_order)) != set(event_ids)
                or len(_cast(list[str], central_order)) != len(event_ids)
                or not isinstance(central_order_method, _mapping_type)
                or response_result.get("chain_execution_id") != chain_execution_id
                or response_result.get("attempt_id") != final_attempt_id
                or response_result.get("event_ids") != list(event_ids)
                or response_result.get("stage_semantics_digest") != stage_semantics_digest
            ):
                raise _scientific_evidence_error_type(
                    "Authenticated scientific chain semantics are detached."
                )
            chains.append(
                _captured_chain_state_type(
                    execution=execution,
                    execution_evidence_digest=readback.execution_evidence_digest,
                    response_bytes=canonical_json_bytes(dict(response)),
                    chain_payload_bytes=_closed_mapping_bytes(
                        chain_result,
                        description="Finalized scientific chain payload is invalid.",
                    ),
                    chain_plan_position=chain_plan_position,
                    chain_execution_id=chain_execution_id,
                    final_attempt_id=final_attempt_id,
                    chain_payload_digest=chain_payload_digest,
                    retained_state_count=retained_state_count,
                    central_order_event_ids=tuple(_cast(list[str], central_order)),
                    central_order_method_bytes=_closed_mapping_bytes(
                        central_order_method,
                        description=("Finalized scientific central-order method is invalid."),
                    ),
                    arrays=_capture_array_snapshots(
                        response,
                        readback.response_arrays,
                    ),
                )
            )
    elif body.get("status") in {"SUCCESS", "CONVERGENCE_WARN"}:
        raise _scientific_evidence_error_type(
            "Finalized scientific result lacks its exact descriptive chains."
        )

    convergence = body.get("convergence")
    convergence_assessment, convergence_rule_set_version = _convergence_identity(convergence)
    convergence_bytes = (
        None
        if convergence is None
        else _closed_mapping_bytes(
            convergence,
            description="Finalized convergence storage is invalid.",
        )
    )
    reference = body.get("reference_chain")
    if chains:
        reference_position = (
            reference.get("chain_plan_position") if isinstance(reference, _mapping_type) else None
        )
        reference_matches = tuple(
            chain for chain in chains if chain.chain_plan_position == reference_position
        )
        if (
            not isinstance(reference, _mapping_type)
            or type(reference_position) is not int
            or len(reference_matches) != 1
            or reference.get("chain_execution_id") != reference_matches[0].chain_execution_id
            or reference.get("final_attempt_id") != reference_matches[0].final_attempt_id
            or reference.get("chain_payload_digest") != reference_matches[0].chain_payload_digest
        ):
            raise _scientific_evidence_error_type(
                "Finalized scientific reference chain is detached."
            )
        reference_bytes = _closed_mapping_bytes(
            reference,
            description="Finalized scientific reference chain is invalid.",
        )
    else:
        if reference is None:
            reference_bytes = None
        elif isinstance(reference, _mapping_type):
            reference_bytes = _closed_mapping_bytes(
                reference,
                description="Finalized scientific reference chain is invalid.",
            )
        else:
            raise _scientific_evidence_error_type(
                "Finalized scientific reference chain is invalid."
            )
    authenticated_available_chain_count = len(chains)
    if (
        authenticated_available_chain_count > finalized_terminal_chain_count
        or finalized_terminal_chain_count > planned_chain_count
        or (
            body.get("status") in {"SUCCESS", "CONVERGENCE_WARN"}
            and authenticated_available_chain_count != planned_chain_count
        )
        or (
            body.get("status") not in {"SUCCESS", "CONVERGENCE_WARN"}
            and authenticated_available_chain_count != 0
        )
    ):
        raise _scientific_evidence_error_type("Scientific chain accounting is invalid.")
    return _captured_candidate_state_type(
        candidate_ordinal=ordinal,
        candidate_id=candidate_id,
        analysis_spec_id=analysis_spec_id,
        candidate_record_bytes=_closed_mapping_bytes(
            candidate,
            description="Plan/3 candidate storage is invalid.",
        ),
        comparison_edges_bytes=canonical_json_bytes([dict(edge) for edge in comparison_edges]),
        terminal_record_bytes=_closed_mapping_bytes(
            terminal,
            description="Candidate-terminal storage is invalid.",
        ),
        persisted_result=persisted_result,
        finalized_result=finalized_result,
        finalized_result_state=result_state,
        finalized_record_bytes=bytes(result_state.canonical_bytes),
        result_id=_cast(str, record["result_id"]),
        universe_id=universe_id,
        final_status=_cast(str, body["status"]),
        planned_chain_count=planned_chain_count,
        finalized_terminal_chain_count=finalized_terminal_chain_count,
        authenticated_available_chain_count=authenticated_available_chain_count,
        convergence_record_bytes=convergence_bytes,
        convergence_assessment=convergence_assessment,
        convergence_rule_set_version=convergence_rule_set_version,
        reference_chain_bytes=reference_bytes,
        event_ids=event_ids,
        event_directions=event_directions,
        stage_semantics_digest=stage_semantics_digest,
        chains=tuple(chains),
    )


def _derive_capture_state(
    sealed_result_evidence_set: object,
    run: _SealedResultEvidenceRunBinding,
    *,
    synthetic_case_binding_bytes: bytes | None,
    _cast: Any = cast,
    _captured_scientific_run_state_type: type[_CapturedScientificRunState] = (
        _CapturedScientificRunState
    ),
    _capture_public_synthetic_preparation_binding: Callable[
        [object], dict[str, str] | None
    ] = _capture_public_synthetic_preparation_binding,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
    _sealed_result_evidence_set_type: type[SealedResultEvidenceSet] = (SealedResultEvidenceSet),
    _candidate_origins: Any = _candidate_origins,
    _capture_candidate: Any = _capture_candidate,
    _require_captured_synthetic_case_binding: Callable[
        [Sequence[bytes], bytes | None], None
    ] = _require_captured_synthetic_case_binding,
    canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
    structured_sha256: Callable[[str, object], str] = structured_sha256,
) -> _CapturedScientificRunState:
    if (
        type(sealed_result_evidence_set) is not _sealed_result_evidence_set_type
        or run.sealed_result_evidence_set is not sealed_result_evidence_set
        or len(run.plan_candidates) != len(run.candidate_terminals)
        or len(run.plan_candidates) != len(run.persisted_results)
        or len(run.plan_candidates) != len(run.finalized_results)
    ):
        raise _scientific_evidence_error_type(
            "Scientific capture requires exact complete sealed result evidence."
        )
    edges_by_origin: dict[str, Mapping[str, Any]] = {}
    for edge in run.origin_comparison_edges:
        origin_id = edge.get("origin_id")
        if type(origin_id) is not str or origin_id in edges_by_origin:
            raise _scientific_evidence_error_type("Plan/3 origin-comparison coverage is invalid.")
        edges_by_origin[origin_id] = edge

    candidates: list[_CapturedCandidateState] = []
    observed_origin_ids: list[str] = []
    for ordinal, (candidate, terminal, persisted, finalized) in enumerate(
        zip(
            run.plan_candidates,
            run.candidate_terminals,
            run.persisted_results,
            run.finalized_results,
            strict=True,
        )
    ):
        if candidate.get("candidate_ordinal") != ordinal:
            raise _scientific_evidence_error_type("Plan/3 candidate order is invalid.")
        origins = _candidate_origins(candidate)
        origin_ids = tuple(origin.get("origin_id") for origin in origins)
        if any(type(origin_id) is not str for origin_id in origin_ids):
            raise _scientific_evidence_error_type("Plan/3 candidate origin identity is invalid.")
        exact_origin_ids = _cast(tuple[str, ...], origin_ids)
        if len(set(exact_origin_ids)) != len(exact_origin_ids):
            raise _scientific_evidence_error_type("Plan/3 candidate origins are duplicated.")
        try:
            candidate_edges = tuple(edges_by_origin[origin_id] for origin_id in exact_origin_ids)
        except KeyError:
            raise _scientific_evidence_error_type(
                "Plan/3 candidate origin has no declared comparison edge."
            ) from None
        if any(
            edge.get("subject_analysis_spec_id") != candidate.get("analysis_spec_id")
            for edge in candidate_edges
        ):
            raise _scientific_evidence_error_type("Plan/3 candidate comparison edge is detached.")
        observed_origin_ids.extend(exact_origin_ids)
        candidates.append(
            _capture_candidate(
                candidate=candidate,
                comparison_edges=candidate_edges,
                terminal=terminal,
                persisted_result=persisted,
                finalized_result=finalized,
            )
        )
    if len(set(observed_origin_ids)) != len(observed_origin_ids) or set(observed_origin_ids) != set(
        edges_by_origin
    ):
        raise _scientific_evidence_error_type("Plan/3 origin-comparison coverage is incomplete.")
    if (
        type(run.baseline_analysis_spec_id) is not str
        or sum(
            candidate.analysis_spec_id == run.baseline_analysis_spec_id for candidate in candidates
        )
        != 1
    ):
        raise _scientific_evidence_error_type("Plan/3 baseline analysis identity is invalid.")

    influence_spec_ids = tuple(
        _cast(str, candidate["analysis_spec_id"])
        for candidate in run.plan_candidates
        if _cast(
            Mapping[str, Any],
            _cast(Mapping[str, Any], candidate["analysis_spec"])["operation_intent"],
        ).get("kind")
        == "influence"
    )
    binding_bytes_by_spec_id: dict[str, bytes] = {}
    decoded_bindings: list[dict[str, object]] = []
    try:
        for binding_bytes in run.influence_preparation_binding_bytes:
            binding = strict_json_loads(binding_bytes)
            analysis_spec_id = binding.get("analysis_spec_id") if type(binding) is dict else None
            if (
                type(binding_bytes) is not bytes
                or type(binding) is not dict
                or canonical_json_bytes(binding) != binding_bytes
                or type(analysis_spec_id) is not str
                or analysis_spec_id in binding_bytes_by_spec_id
            ):
                raise _scientific_evidence_error_type(
                    "Captured influence preparation evidence is invalid."
                )
            binding_bytes_by_spec_id[analysis_spec_id] = binding_bytes
        if set(binding_bytes_by_spec_id) != set(influence_spec_ids):
            raise _scientific_evidence_error_type(
                "Captured influence preparation evidence is incomplete."
            )
        ordered_binding_bytes = tuple(
            binding_bytes_by_spec_id[analysis_spec_id] for analysis_spec_id in influence_spec_ids
        )
        decoded_bindings = [
            _cast(dict[str, object], strict_json_loads(binding_bytes))
            for binding_bytes in ordered_binding_bytes
        ]
    except _scientific_evidence_error_type:
        raise
    except (KeyError, TypeError, ValueError):
        raise _scientific_evidence_error_type(
            "Captured influence preparation evidence is invalid."
        ) from None
    influence_preparation_bindings_digest = structured_sha256(
        "ebm-audit/captured-influence-preparation-bindings/1",
        decoded_bindings,
    )
    if influence_preparation_bindings_digest != run.influence_preparation_bindings_digest:
        raise _scientific_evidence_error_type("Captured influence preparation evidence is invalid.")

    stage_spec_ids = tuple(
        _cast(str, candidate["analysis_spec_id"]) for candidate in run.plan_candidates
    )
    stage_binding_bytes_by_spec_id: dict[str, bytes] = {}
    decoded_stage_bindings: list[dict[str, object]] = []
    try:
        for binding_bytes in run.stage_preparation_binding_bytes:
            binding = strict_json_loads(binding_bytes)
            analysis_spec_id = binding.get("analysis_spec_id") if type(binding) is dict else None
            if (
                type(binding_bytes) is not bytes
                or type(binding) is not dict
                or canonical_json_bytes(binding) != binding_bytes
                or type(analysis_spec_id) is not str
                or analysis_spec_id in stage_binding_bytes_by_spec_id
            ):
                raise _scientific_evidence_error_type(
                    "Captured stage preparation evidence is invalid."
                )
            stage_binding_bytes_by_spec_id[analysis_spec_id] = binding_bytes
        if set(stage_binding_bytes_by_spec_id) != set(stage_spec_ids):
            raise _scientific_evidence_error_type(
                "Captured stage preparation evidence is incomplete."
            )
        ordered_stage_binding_bytes = tuple(
            stage_binding_bytes_by_spec_id[analysis_spec_id] for analysis_spec_id in stage_spec_ids
        )
        decoded_stage_bindings = [
            _cast(dict[str, object], strict_json_loads(binding_bytes))
            for binding_bytes in ordered_stage_binding_bytes
        ]
    except _scientific_evidence_error_type:
        raise
    except (KeyError, TypeError, ValueError):
        raise _scientific_evidence_error_type(
            "Captured stage preparation evidence is invalid."
        ) from None
    stage_preparation_bindings_digest = structured_sha256(
        "ebm-audit/captured-stage-preparation-bindings/1",
        decoded_stage_bindings,
    )
    if stage_preparation_bindings_digest != run.stage_preparation_bindings_digest:
        raise _scientific_evidence_error_type("Captured stage preparation evidence is invalid.")

    _require_captured_synthetic_case_binding(
        tuple(candidate.finalized_record_bytes for candidate in candidates),
        synthetic_case_binding_bytes,
    )

    return _captured_scientific_run_state_type(
        sealed_result_evidence_set=sealed_result_evidence_set,
        plan_candidate_authorization=run.plan_candidate_authorization,
        preparation_transaction=run.preparation_transaction,
        influence_input_receipt=run.influence_input_receipt,
        influence_input_snapshot=run.influence_input_snapshot,
        candidate_result_authorizations=run.candidate_result_authorizations,
        terminal_authorization=run.terminal_authorization,
        sealed_terminal_index=run.sealed_terminal_index,
        persisted_results=run.persisted_results,
        persisted_cache_results=run.persisted_cache_results,
        finalized_results=run.finalized_results,
        terminal_index_digest=run.terminal_index_digest,
        plan_digest=run.plan_candidate_authorization.plan_digest,
        preparation_receipt_digest=run.preparation_receipt_digest,
        influence_preparation_binding_bytes=ordered_binding_bytes,
        influence_preparation_bindings_digest=influence_preparation_bindings_digest,
        stage_preparation_binding_bytes=ordered_stage_binding_bytes,
        stage_preparation_bindings_digest=stage_preparation_bindings_digest,
        baseline_analysis_spec_id=run.baseline_analysis_spec_id,
        plan_candidates_bytes=canonical_json_bytes(list(run.plan_candidates)),
        origin_comparison_edges_bytes=canonical_json_bytes(list(run.origin_comparison_edges)),
        candidate_terminals_bytes=canonical_json_bytes(list(run.candidate_terminals)),
        synthetic_case_binding_bytes=synthetic_case_binding_bytes,
        candidates=tuple(candidates),
    )


def _same_owner_sequence(
    left: Sequence[object],
    right: Sequence[object],
) -> bool:
    return len(left) == len(right) and all(
        current is retained for current, retained in zip(left, right, strict=True)
    )


def _assert_array_snapshot_current(
    snapshot: _ScientificArraySnapshot,
    array: object,
    catalog_entry: object,
    *,
    _mapping_type: Any = Mapping,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
    _closed_mapping_bytes: Any = _closed_mapping_bytes,
    np_ndarray_type: type[np.ndarray[Any, Any]] = np.ndarray,
) -> None:
    if (
        type(array) is not np_ndarray_type
        or not isinstance(catalog_entry, _mapping_type)
        or array.dtype.str != snapshot.dtype
        or tuple(int(size) for size in array.shape) != snapshot.shape
        or array.tobytes(order="C") != snapshot.private_array_bytes
        or _closed_mapping_bytes(
            catalog_entry,
            description="Authenticated scientific array catalogue is invalid.",
        )
        != snapshot.catalog_bytes
    ):
        raise _scientific_evidence_error_type("Captured scientific array changed.")
    snapshot._array()


def _assert_candidate_current(
    candidate: _CapturedCandidateState,
    *,
    _cast: Any = cast,
    _mapping_type: Any = Mapping,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
    _assert_finalized_result_state_current: Any = _assert_finalized_result_state_current,
    _closed_mapping_bytes: Any = _closed_mapping_bytes,
    _planned_chain_count: Any = _planned_chain_count,
    _finalized_terminal_chain_count: Any = _finalized_terminal_chain_count,
    _convergence_identity: Any = _convergence_identity,
    _readback_authenticated_execution: Any = _readback_authenticated_execution,
    _assert_array_snapshot_current: Any = _assert_array_snapshot_current,
    canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
) -> None:
    _assert_finalized_result_state_current(
        candidate.finalized_result,
        candidate.finalized_result_state,
    )
    if candidate.finalized_result_state.canonical_bytes != candidate.finalized_record_bytes:
        raise _scientific_evidence_error_type("Captured finalized scientific result changed.")
    record = strict_json_loads(candidate.finalized_record_bytes)
    body = record.get("body") if isinstance(record, _mapping_type) else None
    terminal = strict_json_loads(candidate.terminal_record_bytes)
    if (
        not isinstance(record, _mapping_type)
        or not isinstance(body, _mapping_type)
        or not isinstance(terminal, _mapping_type)
        or record.get("result_id") != candidate.result_id
        or body.get("universe_id") != candidate.universe_id
        or terminal.get("universe_id") != candidate.universe_id
        or body.get("status") != candidate.final_status
    ):
        raise _scientific_evidence_error_type("Captured finalized scientific result changed.")
    current_event_ids = body.get("event_ids")
    if current_event_ids is not None and current_event_ids != list(candidate.event_ids):
        raise _scientific_evidence_error_type("Captured finalized scientific result changed.")
    convergence = body.get("convergence")
    current_convergence_bytes = (
        None
        if convergence is None
        else _closed_mapping_bytes(
            convergence,
            description="Finalized convergence storage is invalid.",
        )
    )
    if current_convergence_bytes != candidate.convergence_record_bytes:
        raise _scientific_evidence_error_type("Captured convergence evidence changed.")
    current_candidate = strict_json_loads(candidate.candidate_record_bytes)
    if (
        not isinstance(current_candidate, _mapping_type)
        or _planned_chain_count(current_candidate) != candidate.planned_chain_count
        or _finalized_terminal_chain_count(
            body,
            planned_chain_count=candidate.planned_chain_count,
        )
        != candidate.finalized_terminal_chain_count
        or _convergence_identity(convergence)
        != (
            candidate.convergence_assessment,
            candidate.convergence_rule_set_version,
        )
        or len(candidate.chains) != candidate.authenticated_available_chain_count
    ):
        raise _scientific_evidence_error_type("Captured scientific chain accounting changed.")
    chain_results = body.get("chain_results")
    if candidate.chains:
        if type(chain_results) is not list or len(chain_results) != len(candidate.chains):
            raise _scientific_evidence_error_type("Captured scientific chain coverage changed.")
        reference = body.get("reference_chain")
        if (
            not isinstance(reference, _mapping_type)
            or candidate.reference_chain_bytes is None
            or _closed_mapping_bytes(
                reference,
                description="Finalized scientific reference chain is invalid.",
            )
            != candidate.reference_chain_bytes
        ):
            raise _scientific_evidence_error_type("Captured scientific reference chain changed.")
    else:
        reference = body.get("reference_chain")
        current_reference_bytes = (
            None
            if reference is None
            else _closed_mapping_bytes(
                reference,
                description="Finalized scientific reference chain is invalid.",
            )
        )
        if current_reference_bytes != candidate.reference_chain_bytes:
            raise _scientific_evidence_error_type("Captured scientific reference chain changed.")
    if len(candidate.chains) != len(candidate.finalized_result_state.descriptive_chain_executions):
        raise _scientific_evidence_error_type("Captured scientific chain coverage changed.")
    current_chain_results = (
        _cast(list[object], chain_results)
        if candidate.chains and type(chain_results) is list
        else []
    )
    for retained, execution, chain_result in zip(
        candidate.chains,
        candidate.finalized_result_state.descriptive_chain_executions,
        current_chain_results,
        strict=True,
    ):
        if (
            retained.execution is not execution
            or not isinstance(chain_result, _mapping_type)
            or _closed_mapping_bytes(
                chain_result,
                description="Finalized scientific chain payload is invalid.",
            )
            != retained.chain_payload_bytes
        ):
            raise _scientific_evidence_error_type("Captured scientific chain owner changed.")
        readback = _readback_authenticated_execution(execution)
        response = readback.response
        if (
            readback.execution_evidence_digest != retained.execution_evidence_digest
            or canonical_json_bytes(dict(response)) != retained.response_bytes
        ):
            raise _scientific_evidence_error_type("Captured scientific chain evidence changed.")
        payload = response.get("payload")
        result = payload.get("result") if isinstance(payload, _mapping_type) else None
        catalog = result.get("array_catalog") if isinstance(result, _mapping_type) else None
        if (
            not isinstance(catalog, _mapping_type)
            or set(catalog) != {snapshot.name for snapshot in retained.arrays}
            or set(readback.response_arrays) != {snapshot.name for snapshot in retained.arrays}
        ):
            raise _scientific_evidence_error_type("Captured scientific array coverage changed.")
        for snapshot in retained.arrays:
            _assert_array_snapshot_current(
                snapshot,
                readback.response_arrays.get(snapshot.name),
                catalog.get(snapshot.name),
            )


class _CaptureSummary(Protocol):
    def __call__(self, value: object, /) -> tuple[int, int]: ...


class _CaptureScientificRun(Protocol):
    def __call__(
        self,
        sealed_result_evidence_set: SealedResultEvidenceSet,
        /,
        *,
        scenario_authority: ScenarioAuthority | None = None,
        resolved_synthetic_case: ResolvedSyntheticCase | None = None,
    ) -> CapturedScientificRun: ...


class _SealScientificEvidence(Protocol):
    def __call__(
        self,
        captured_scientific_run: CapturedScientificRun,
        /,
    ) -> SealedScientificEvidence: ...


class _ProjectScientificEvidence(Protocol):
    def __call__(
        self,
        sealed_scientific_evidence: SealedScientificEvidence,
        /,
    ) -> dict[str, object]: ...


class _ReadPrivateStageComparisonEvidence(Protocol):
    def __call__(
        self,
        sealed_scientific_evidence: SealedScientificEvidence,
        /,
    ) -> tuple[tuple[bytes, str], ...]: ...


class _ReadCapturedScientificRun(Protocol):
    def __call__(self, value: object, /) -> _CapturedScientificRunState: ...


class _ReadSealedScientificEvidence(Protocol):
    def __call__(self, value: object, /) -> _SealedScientificEvidenceState: ...


class _BuildDependencyGuard(Protocol):
    def __call__(
        self,
        roots: tuple[object, ...],
    ) -> Callable[[], None]: ...


def _build_scientific_evidence_boundary(
    *,
    _any_type_marker: Any = Any,
    _CAPTURE_LOCK: Any = _CAPTURE_LOCK,
    _date_fromisoformat: Any = date.fromisoformat,
    _draft_validator_type: Any = Draft202012Validator,
    _format_checker_type: Any = FormatChecker,
    _mapping_proxy_type: Any = MappingProxyType,
    _math_isfinite: Any = _math_isfinite,
    _rfc3339_date_time_pattern: Any = _RFC3339_DATE_TIME,
    _schema_registry_factory: Any = _schema_registry,
    _validation_schema_factory: Any = _validation_schema,
    _unicode_category: Any = _unicode_category,
    _unicode_is_normalized: Any = _unicode_is_normalized,
    _analyst_dependencies_current: Callable[[], None] = (
        _ANALYST_DECISION_DERIVATION.assert_dependencies_current
    ),
    _sampling_dependencies_current: Callable[[], None] = (
        _SAMPLING_DERIVATION.assert_dependencies_current
    ),
    _influence_dependencies_current: Callable[[], None] = (
        _INFLUENCE_DERIVATION.assert_dependencies_current
    ),
    _null_dependencies_current: Callable[[], None] = (_NULL_DERIVATION.assert_dependencies_current),
    _stage_dependencies_current: Callable[[], None] = (
        _STAGE_COMPARISON_DERIVATION.assert_dependencies_current
    ),
    _derive_stage_comparison_owner: Callable[
        [_StageComparisonSideInput, _StageComparisonSideInput],
        _DerivedStageComparison,
    ] = derive_stage_comparison_owner,
    _build_dependency_guard: _BuildDependencyGuard = build_frozen_dependency_guard,
    _captured_scientific_run_state_type: type[_CapturedScientificRunState] = (
        _CapturedScientificRunState
    ),
    _captured_synthetic_case_binding_bytes: Callable[
        [Sequence[bytes]], bytes | None
    ] = _captured_synthetic_case_binding_bytes,
    _require_captured_synthetic_case_binding: Callable[
        [Sequence[bytes], bytes | None], None
    ] = _require_captured_synthetic_case_binding,
    _captured_scientific_run_type: type[CapturedScientificRun] = CapturedScientificRun,
    _cast: Any = cast,
    _counter_type: Any = Counter,
    _derived_scientific_projection_type: type[_DerivedScientificProjection] = (
        _DerivedScientificProjection
    ),
    _derived_stage_comparison_type: type[_DerivedStageComparison] = (_DerivedStageComparison),
    _private_stage_comparison_digest_domain: str = (PRIVATE_STAGE_COMPARISON_DIGEST_DOMAIN),
    _invalid_input_error_type: type[InvalidInputError] = InvalidInputError,
    _issue_scientific_ledger_receipt: Callable[
        [object, SealedResultEvidenceSet, bytes, str],
        None,
    ] = _ISSUE_SCIENTIFIC_LEDGER_RECEIPT,
    _mapping_type: Any = Mapping,
    _require_scientific_ledger_receipt: Callable[
        [object, SealedResultEvidenceSet, bytes, str],
        None,
    ] = _REQUIRE_SCIENTIFIC_LEDGER_RECEIPT,
    _science_ledger_receipt_digest_domain: str = (_SCIENCE_LEDGER_RECEIPT_DIGEST_DOMAIN),
    _science_ledger_receipt_schema_version: str = (_SCIENCE_LEDGER_RECEIPT_SCHEMA_VERSION),
    _SanitizedScientificControlFlow: Any = _SanitizedScientificControlFlow,
    _scientific_evidence_error_type: type[ScientificEvidenceError] = (ScientificEvidenceError),
    _sealed_result_evidence_set_type: type[SealedResultEvidenceSet] = (SealedResultEvidenceSet),
    _sealed_scientific_evidence_state_type: type[_SealedScientificEvidenceState] = (
        _SealedScientificEvidenceState
    ),
    _sealed_scientific_evidence_type: type[SealedScientificEvidence] = (SealedScientificEvidence),
    _stage_comparison_side_input_type: type[_StageComparisonSideInput] = (
        _StageComparisonSideInput
    ),
    _validated_synthetic_case_binding: Callable[
        [ScenarioAuthority, ResolvedSyntheticCase], dict[str, str]
    ] = _validated_synthetic_case_binding,
    canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    np_array: Any = np.array,
    np_dtype: Any = np.dtype,
    np_int32: Any = np.int32,
    np_int64: Any = np.int64,
    np_ndarray_type: type[np.ndarray[Any, Any]] = np.ndarray,
    strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
    structured_sha256: Callable[[str, object], str] = structured_sha256,
) -> tuple[
    _CaptureSummary,
    _CaptureScientificRun,
    _SealScientificEvidence,
    _ProjectScientificEvidence,
    _ReadPrivateStageComparisonEvidence,
    _ReadCapturedScientificRun,
    _ReadSealedScientificEvidence,
]:
    format_checker = _format_checker_type()

    def unicode_nfc(value: object) -> bool:
        return isinstance(value, str) and _unicode_is_normalized("NFC", value)

    def participant_private_id_text(value: object) -> bool:
        if (
            not isinstance(value, str)
            or not value
            or value.isspace()
            or not _unicode_is_normalized("NFC", value)
        ):
            return False
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return False
        return all(_unicode_category(character) not in {"Cc", "Cf", "Cs"} for character in value)

    def rfc3339_date_time(value: object) -> bool:
        if not isinstance(value, str):
            return False
        match = _rfc3339_date_time_pattern.fullmatch(value)
        if match is None:
            return False
        _date_fromisoformat(match.group("date"))
        if match.group("second") == "60":
            return bool(match.group("hour") == "23" and match.group("minute") == "59")
        return True

    def finite_number(value: object) -> bool:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        try:
            return bool(_math_isfinite(float(value)))
        except (OverflowError, TypeError, ValueError):
            return False

    format_checker.checks("unicode-nfc", raises=(TypeError,))(unicode_nfc)
    format_checker.checks("participant-private-id-text")(participant_private_id_text)
    format_checker.checks("date-time", raises=(TypeError, ValueError))(rfc3339_date_time)
    format_checker.checks("finite-number")(finite_number)
    schema_registry = _schema_registry_factory()
    analyst_schema_validators = _mapping_proxy_type(
        {
            definition: _draft_validator_type(
                _validation_schema_factory(
                    "analyst-decision-evidence.schema.json",
                    definition,
                ),
                registry=schema_registry,
                format_checker=format_checker,
            )
            for definition in (
                "OriginComparisonAttempt",
                "OriginNumericComparisonRecord",
                "AnalystDecisionAggregate",
                "AnalystDecisionLayerEvidence",
            )
        }
    )
    sampling_schema_validators = _mapping_proxy_type(
        {
            definition: _draft_validator_type(
                _validation_schema_factory(
                    "sampling-evidence.schema.json",
                    definition,
                ),
                registry=schema_registry,
                format_checker=format_checker,
            )
            for definition in (
                "SamplingOriginAttempt",
                "SamplingNumericComparison",
                "SamplingFamilyAggregate",
                "SamplingLayerEvidence",
            )
        }
    )
    influence_schema_validators = _mapping_proxy_type(
        {
            definition: _draft_validator_type(
                _validation_schema_factory(
                    "influence-evidence.schema.json",
                    definition,
                ),
                registry=schema_registry,
                format_checker=format_checker,
            )
            for definition in (
                "InfluenceAttempt",
                "InfluenceLayerEvidence",
            )
        }
    )

    def validator_dependency_manifest() -> tuple[
        tuple[object, ...],
        Callable[[], None],
    ]:
        validator_mappings = (
            analyst_schema_validators,
            sampling_schema_validators,
            influence_schema_validators,
        )
        validator_items = tuple(
            item for validators in validator_mappings for item in validators.items()
        )
        checker_mapping = format_checker.checkers
        required_checker_items = tuple(
            (name, checker_mapping[name])
            for name in (
                "unicode-nfc",
                "participant-private-id-text",
                "date-time",
                "finite-number",
            )
        )
        roots: list[object] = [
            type(format_checker),
            type(format_checker).check,
            type(format_checker).conforms,
            schema_registry,
            type(schema_registry),
            *(entry for _name, entry in required_checker_items),
        ]
        seen_registries: set[int] = set()
        validator_states: list[tuple[object, tuple[tuple[str, object], ...]]] = []

        def retain_registry(registry: object) -> None:
            registry_identity = id(registry)
            if registry_identity in seen_registries:
                return
            seen_registries.add(registry_identity)
            roots.extend((registry, type(registry)))
            for method_name in (
                "anchor",
                "contents",
                "crawl",
                "get",
                "resolver",
                "resolver_with_root",
            ):
                method = getattr(type(registry), method_name, None)
                if callable(method):
                    roots.append(method)
            for slot_name in (
                "_resources",
                "_anchors",
                "_uncrawled",
                "_retrieve",
            ):
                try:
                    retained = object.__getattribute__(registry, slot_name)
                except AttributeError:
                    continue
                roots.append(retained)
                items = getattr(retained, "items", None)
                if callable(items):
                    retained_items = tuple(items())
                    roots.append(retained_items)
                    for key, item in retained_items:
                        roots.extend((key, item))
                        resource_type = type(item)
                        roots.extend(
                            getattr(resource_type, method_name)
                            for method_name in (
                                "id",
                                "subresources",
                                "anchors",
                                "pointer",
                            )
                            if callable(getattr(resource_type, method_name, None))
                        )
                        try:
                            roots.append(object.__getattribute__(item, "contents"))
                        except AttributeError:
                            continue

        retain_registry(schema_registry)
        for _definition, validator in validator_items:
            validator_type = type(validator)
            validator_state = tuple(
                (
                    name,
                    object.__getattribute__(validator, name),
                )
                for name in (
                    "schema",
                    "_validators",
                    "format_checker",
                    "_registry",
                    "_resolver",
                )
            )
            validator_states.append((validator, validator_state))
            roots.extend(
                (
                    validator_type,
                    validator.schema,
                    validator._validators,
                    validator_type.VALIDATORS,
                    validator_type.iter_errors,
                    validator_type.descend,
                    validator_type._validate_reference,
                    validator_type.evolve,
                )
            )
            checker = validator.format_checker
            if checker is not None:
                roots.extend(
                    (
                        type(checker),
                        type(checker).check,
                        type(checker).conforms,
                    )
                )
            registry = validator._registry
            retain_registry(registry)
            resolver = validator._resolver
            roots.extend(
                (
                    resolver,
                    type(resolver),
                    type(resolver).lookup,
                    type(resolver).in_subresource,
                    type(resolver).dynamic_scope,
                )
            )
            retain_registry(resolver._registry)

        def assert_validator_configuration_current() -> None:
            current_items = tuple(
                item for validators in validator_mappings for item in validators.items()
            )
            if len(current_items) != len(validator_items) or any(
                current_name is not expected_name or current is not expected
                for (current_name, current), (expected_name, expected) in zip(
                    current_items,
                    validator_items,
                    strict=True,
                )
            ):
                raise TypeError("Scientific validator configuration changed.")
            if format_checker.checkers is not checker_mapping or any(
                checker_mapping.get(name) is not expected
                for name, expected in required_checker_items
            ):
                raise TypeError("Scientific validator configuration changed.")
            for validator, expected_state in validator_states:
                if type(validator) is not _draft_validator_type or any(
                    object.__getattribute__(validator, name) is not expected
                    for name, expected in expected_state
                ):
                    raise TypeError("Scientific validator configuration changed.")

        return tuple(roots), assert_validator_configuration_current

    sealed_result_evidence_run = _sealed_result_evidence_run
    derive_capture_state = _derive_capture_state
    candidate_origins = _candidate_origins
    closed_mapping_bytes = _closed_mapping_bytes
    derive_candidate_evidence_record = _derive_candidate_evidence_record
    derive_analyst_decision_evidence = _derive_analyst_decision_evidence
    derive_sampling_evidence = _derive_sampling_evidence
    derive_influence_evidence = _derive_influence_evidence
    derive_null_evidence = _derive_null_evidence
    derive_stage_comparison_owner = _derive_stage_comparison_owner
    validate_sampling_semantics = _validate_sampling_semantics
    validate_influence_semantics = _validate_influence_semantics
    validate_null_semantics = _validate_null_semantics
    canonical_candidate_evidence_record_type = _CanonicalCandidateEvidenceRecord
    canonical_origin_attempt_type = _CanonicalOriginComparisonAttempt
    canonical_numeric_comparison_type = _CanonicalOriginNumericComparisonRecord
    canonical_analyst_aggregate_type = _CanonicalAnalystDecisionAggregate
    canonical_analyst_layer_type = _CanonicalAnalystDecisionLayerEvidence
    canonical_analyst_bundle_type = _CanonicalAnalystDecisionEvidenceBundle
    canonical_sampling_attempt_type = _CanonicalSamplingOriginAttempt
    canonical_sampling_numeric_type = _CanonicalSamplingNumericComparison
    canonical_sampling_aggregate_type = _CanonicalSamplingFamilyAggregate
    canonical_sampling_layer_type = _CanonicalSamplingLayerEvidence
    canonical_sampling_bundle_type = _CanonicalSamplingEvidenceBundle
    canonical_influence_attempt_type = _CanonicalInfluenceAttempt
    canonical_influence_layer_type = _CanonicalInfluenceLayerEvidence
    canonical_influence_bundle_type = _CanonicalInfluenceEvidenceBundle
    canonical_null_layer_type = _CanonicalNullLayerEvidence
    chain_evidence_input_type = _ChainEvidenceInput
    analyst_candidate_input_type = _AnalystDecisionCandidateInput
    analyst_origin_input_type = _AnalystDecisionOriginInput
    stage_comparison_side_input_type = _stage_comparison_side_input_type
    derived_stage_comparison_type = _derived_stage_comparison_type
    sampling_candidate_input_type = _SamplingCandidateInput
    sampling_origin_input_type = _SamplingOriginInput
    influence_candidate_input_type = _InfluenceCandidateInput
    influence_origin_input_type = _InfluenceOriginInput
    null_candidate_input_type = _NullCandidateInput
    convergence_chain_input_type = ConvergenceChainInput
    derive_convergence = derive_convergence_record
    is_canonical_non_sampling_convergence = is_canonical_non_sampling_convergence_record
    cross_check_tolerance_rule = _cross_check_tolerance_rule
    uncertainty_layer_coverage = _uncertainty_layer_coverage
    candidate_evidence_rule_id = OVERALL_EVIDENCE_RULE_ID
    sealed_evidence_rule_id = SEALED_EVIDENCE_RULE_ID
    analyst_decision_evidence_rule_id = ANALYST_DECISION_EVIDENCE_RULE_ID
    sampling_evidence_rule_id = SAMPLING_EVIDENCE_RULE_ID
    influence_evidence_rule_id = INFLUENCE_EVIDENCE_RULE_ID
    null_evidence_rule_id = NULL_EVIDENCE_RULE_ID
    position_summary_rule_id = POSITION_SUMMARY_RULE_ID
    position_summary_quantile_probabilities = tuple(POSITION_SUMMARY_QUANTILE_PROBABILITIES)
    chain_top_k_rule_id = CHAIN_TOP_K_RULE_ID
    scientific_evidence_schema_version = SCIENTIFIC_EVIDENCE_SCHEMA_VERSION
    capture_state_registry: OneShotWeakRegistry[
        CapturedScientificRun,
        _CapturedScientificRunState,
    ]
    capture_state_issuer: OneShotRegistryIssuer[
        CapturedScientificRun,
        _CapturedScientificRunState,
    ]
    capture_state_registry, capture_state_issuer = create_one_shot_registry()
    live_captures: CallbackFreeWeakIdentityMap[
        SealedResultEvidenceSet,
        CapturedScientificRun,
    ] = CallbackFreeWeakIdentityMap(_CAPTURE_LOCK)
    evidence_state_registry: OneShotWeakRegistry[
        SealedScientificEvidence,
        _SealedScientificEvidenceState,
    ]
    evidence_state_issuer: OneShotRegistryIssuer[
        SealedScientificEvidence,
        _SealedScientificEvidenceState,
    ]
    evidence_state_registry, evidence_state_issuer = create_one_shot_registry()
    live_evidence: CallbackFreeWeakIdentityMap[
        CapturedScientificRun,
        SealedScientificEvidence,
    ] = CallbackFreeWeakIdentityMap(_CAPTURE_LOCK)
    capture_success = object()
    summary_success = object()
    seal_success = object()
    projection_success = object()
    scientific_failure = object()

    def read_captured_scientific_run(
        value: object,
        /,
        *,
        _leased_state: Any = _leased_captured_scientific_run_state,
        _same_owner_sequence: Any = _same_owner_sequence,
        _planned_chain_count: Any = _planned_chain_count,
        _closed_mapping_bytes: Any = _closed_mapping_bytes,
        _candidate_event_semantics: Any = _candidate_event_semantics,
        _candidate_origins: Any = _candidate_origins,
        _assert_candidate_current: Any = _assert_candidate_current,
    ) -> _CapturedScientificRunState:
        if type(value) is not _captured_scientific_run_type:
            raise _scientific_evidence_error_type("A genuine captured scientific run is required.")
        leased_state = _leased_state(value)
        if type(leased_state) is _captured_scientific_run_state_type:
            return leased_state
        try:
            state = capture_state_registry[value]
        except (KeyError, TypeError):
            raise _scientific_evidence_error_type(
                "A genuine captured scientific run is required."
            ) from None
        if type(state) is not _captured_scientific_run_state_type:
            raise _scientific_evidence_error_type("A genuine captured scientific run is required.")
        if live_captures.get(state.sealed_result_evidence_set) is not value:
            raise _scientific_evidence_error_type(
                "Captured scientific run is not the canonical live capture."
            )
        try:
            run = sealed_result_evidence_run(state.sealed_result_evidence_set)
        except (_invalid_input_error_type, TypeError, ValueError):
            raise _scientific_evidence_error_type(
                "Captured scientific source evidence is no longer current."
            ) from None
        if (
            run.sealed_result_evidence_set is not state.sealed_result_evidence_set
            or run.plan_candidate_authorization is not state.plan_candidate_authorization
            or run.preparation_transaction is not state.preparation_transaction
            or run.influence_input_receipt is not state.influence_input_receipt
            or run.influence_input_snapshot is not state.influence_input_snapshot
            or not _same_owner_sequence(
                run.candidate_result_authorizations,
                state.candidate_result_authorizations,
            )
            or run.terminal_authorization is not state.terminal_authorization
            or run.sealed_terminal_index is not state.sealed_terminal_index
            or not _same_owner_sequence(
                run.persisted_results,
                state.persisted_results,
            )
            or not _same_owner_sequence(
                run.persisted_cache_results,
                state.persisted_cache_results,
            )
            or not _same_owner_sequence(
                run.finalized_results,
                state.finalized_results,
            )
            or run.terminal_index_digest != state.terminal_index_digest
            or run.plan_candidate_authorization.plan_digest != state.plan_digest
            or run.preparation_receipt_digest != state.preparation_receipt_digest
            or run.influence_preparation_binding_bytes != state.influence_preparation_binding_bytes
            or run.influence_preparation_bindings_digest
            != state.influence_preparation_bindings_digest
            or structured_sha256(
                "ebm-audit/captured-influence-preparation-bindings/1",
                [
                    strict_json_loads(binding_bytes)
                    for binding_bytes in state.influence_preparation_binding_bytes
                ],
            )
            != state.influence_preparation_bindings_digest
            or run.stage_preparation_binding_bytes != state.stage_preparation_binding_bytes
            or run.stage_preparation_bindings_digest != state.stage_preparation_bindings_digest
            or structured_sha256(
                "ebm-audit/captured-stage-preparation-bindings/1",
                [
                    strict_json_loads(binding_bytes)
                    for binding_bytes in state.stage_preparation_binding_bytes
                ],
            )
            != state.stage_preparation_bindings_digest
            or run.baseline_analysis_spec_id != state.baseline_analysis_spec_id
            or canonical_json_bytes(list(run.plan_candidates)) != state.plan_candidates_bytes
            or canonical_json_bytes(list(run.origin_comparison_edges))
            != state.origin_comparison_edges_bytes
            or canonical_json_bytes(list(run.candidate_terminals))
            != state.candidate_terminals_bytes
            or len(run.plan_candidates) != len(state.candidates)
        ):
            raise _scientific_evidence_error_type(
                "Captured scientific source evidence is detached."
            )
        if state.synthetic_case_binding_bytes is not None:
            synthetic_case_binding = strict_json_loads(state.synthetic_case_binding_bytes)
            if (
                type(synthetic_case_binding) is not dict
                or set(synthetic_case_binding)
                != {
                    "case_id",
                    "source_contract_sha256",
                    "scenario_definitions_sha256",
                }
                or any(type(value) is not str for value in synthetic_case_binding.values())
                or canonical_json_bytes(synthetic_case_binding)
                != state.synthetic_case_binding_bytes
            ):
                raise _scientific_evidence_error_type("Captured synthetic case binding is invalid.")
        current_synthetic_binding = _capture_public_synthetic_preparation_binding(
            state.preparation_transaction
        )
        current_synthetic_binding_bytes = (
            None
            if current_synthetic_binding is None
            else canonical_json_bytes(current_synthetic_binding)
        )
        if current_synthetic_binding_bytes != state.synthetic_case_binding_bytes:
            raise _scientific_evidence_error_type("Captured synthetic preparation owner changed.")
        _require_captured_synthetic_case_binding(
            tuple(candidate.finalized_record_bytes for candidate in state.candidates),
            state.synthetic_case_binding_bytes,
        )
        for retained, candidate, terminal, persisted, finalized in zip(
            state.candidates,
            run.plan_candidates,
            run.candidate_terminals,
            run.persisted_results,
            run.finalized_results,
            strict=True,
        ):
            if (
                candidate.get("candidate_ordinal") != retained.candidate_ordinal
                or candidate.get("candidate_id") != retained.candidate_id
                or candidate.get("analysis_spec_id") != retained.analysis_spec_id
                or _planned_chain_count(candidate) != retained.planned_chain_count
                or _closed_mapping_bytes(
                    candidate,
                    description="Plan/3 candidate storage is invalid.",
                )
                != retained.candidate_record_bytes
                or _closed_mapping_bytes(
                    terminal,
                    description="Candidate-terminal storage is invalid.",
                )
                != retained.terminal_record_bytes
                or persisted is not retained.persisted_result
                or finalized is not retained.finalized_result
            ):
                raise _scientific_evidence_error_type(
                    "Captured candidate scientific source is detached."
                )
            current_event_ids, current_event_directions, current_stage_semantics = (
                _candidate_event_semantics(candidate)
            )
            origins = _candidate_origins(candidate)
            origin_ids = tuple(_cast(str, origin["origin_id"]) for origin in origins)
            current_edges = tuple(
                edge
                for origin_id in origin_ids
                for edge in run.origin_comparison_edges
                if edge.get("origin_id") == origin_id
            )
            if (
                current_event_ids != retained.event_ids
                or current_event_directions != retained.event_directions
                or current_stage_semantics != retained.stage_semantics_digest
                or canonical_json_bytes([dict(edge) for edge in current_edges])
                != retained.comparison_edges_bytes
                or len(current_edges) != len(origin_ids)
            ):
                raise _scientific_evidence_error_type(
                    "Captured candidate scientific semantics are detached."
                )
            _assert_candidate_current(retained)
        if live_captures.get(state.sealed_result_evidence_set) is not value:
            raise _scientific_evidence_error_type(
                "Captured scientific run is not the canonical live capture."
            )
        return state

    def try_capture_summary(
        value: object,
        /,
    ) -> tuple[object, tuple[int, int]] | object | _SanitizedScientificControlFlow:
        try:
            assert_science_dependencies_current()
            state = read_captured_scientific_run(value)
            summary = (
                len(state.candidates),
                sum(len(candidate.chains) for candidate in state.candidates),
            )
            assert_science_dependencies_current()
            return summary_success, summary
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                return _SanitizedScientificControlFlow("keyboard_interrupt")
            if type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                return _SanitizedScientificControlFlow("system_exit", safe_exit_code)
            if type(stopped) is GeneratorExit:
                return _SanitizedScientificControlFlow("generator_exit")
            return scientific_failure

    def capture_summary(value: object, /) -> tuple[int, int]:
        try:
            outcome: tuple[object, tuple[int, int]] | object | _SanitizedScientificControlFlow = (
                try_capture_summary(value)
            )
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                outcome = _SanitizedScientificControlFlow("keyboard_interrupt")
            elif type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                outcome = _SanitizedScientificControlFlow("system_exit", safe_exit_code)
                del stopped_code
            elif type(stopped) is GeneratorExit:
                outcome = _SanitizedScientificControlFlow("generator_exit")
            else:
                outcome = scientific_failure
        finally:
            del value
        if type(outcome) is _SanitizedScientificControlFlow:
            sanitized_outcome = _cast(_any_type_marker, outcome)
            if sanitized_outcome.kind == "keyboard_interrupt":
                raise KeyboardInterrupt
            if sanitized_outcome.kind == "system_exit":
                raise SystemExit(sanitized_outcome.exit_code)
            raise GeneratorExit
        if (
            type(outcome) is tuple
            and len(outcome) == 2
            and outcome[0] is summary_success
            and type(outcome[1]) is tuple
            and len(outcome[1]) == 2
            and type(outcome[1][0]) is int
            and type(outcome[1][1]) is int
        ):
            return outcome[1][0], outcome[1][1]
        del outcome
        raise _scientific_evidence_error_type(
            "Captured scientific source validation failed integrity validation."
        )

    def try_capture_scientific_run(
        sealed_result_evidence_set: SealedResultEvidenceSet,
        /,
        *,
        scenario_authority: ScenarioAuthority | None,
        resolved_synthetic_case: ResolvedSyntheticCase | None,
    ) -> tuple[object, CapturedScientificRun] | object | _SanitizedScientificControlFlow:
        try:
            assert_science_dependencies_current()
            if (scenario_authority is None) != (resolved_synthetic_case is None):
                return scientific_failure
            asserted_synthetic_case_binding_bytes = (
                None
                if scenario_authority is None or resolved_synthetic_case is None
                else canonical_json_bytes(
                    _validated_synthetic_case_binding(
                        scenario_authority,
                        resolved_synthetic_case,
                    )
                )
            )
            existing = live_captures.get(sealed_result_evidence_set)
            if existing is None:
                with _CAPTURE_LOCK:
                    existing = live_captures.get(sealed_result_evidence_set)
                    if existing is None:
                        try:
                            run = sealed_result_evidence_run(sealed_result_evidence_set)
                        except (_invalid_input_error_type, TypeError, ValueError):
                            return scientific_failure
                        synthetic_case_binding = _capture_public_synthetic_preparation_binding(
                            run.preparation_transaction
                        )
                        synthetic_case_binding_bytes = (
                            None
                            if synthetic_case_binding is None
                            else canonical_json_bytes(synthetic_case_binding)
                        )
                        if (
                            asserted_synthetic_case_binding_bytes is not None
                            and asserted_synthetic_case_binding_bytes
                            != synthetic_case_binding_bytes
                        ):
                            return scientific_failure
                        state = derive_capture_state(
                            sealed_result_evidence_set,
                            run,
                            synthetic_case_binding_bytes=synthetic_case_binding_bytes,
                        )
                        assert_science_dependencies_current()
                        captured = object.__new__(_captured_scientific_run_type)
                        capture_state_issuer.bind_once(captured, state)
                        live_captures.bind_once(
                            sealed_result_evidence_set,
                            captured,
                        )
                        read_captured_scientific_run(captured)
                        assert_science_dependencies_current()
                        return capture_success, captured
            if existing is None:
                return scientific_failure
            state = read_captured_scientific_run(existing)
            if state.sealed_result_evidence_set is not sealed_result_evidence_set or (
                asserted_synthetic_case_binding_bytes is not None
                and state.synthetic_case_binding_bytes != asserted_synthetic_case_binding_bytes
            ):
                return scientific_failure
            assert_science_dependencies_current()
            return capture_success, existing
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                return _SanitizedScientificControlFlow("keyboard_interrupt")
            if type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                return _SanitizedScientificControlFlow("system_exit", safe_exit_code)
            if type(stopped) is GeneratorExit:
                return _SanitizedScientificControlFlow("generator_exit")
            return scientific_failure

    def capture_scientific_run(
        sealed_result_evidence_set: SealedResultEvidenceSet,
        /,
        *,
        scenario_authority: ScenarioAuthority | None = None,
        resolved_synthetic_case: ResolvedSyntheticCase | None = None,
    ) -> CapturedScientificRun:
        """Capture one live private science source from exact current sealed evidence."""

        try:
            outcome: (
                tuple[object, CapturedScientificRun] | object | _SanitizedScientificControlFlow
            ) = try_capture_scientific_run(
                sealed_result_evidence_set,
                scenario_authority=scenario_authority,
                resolved_synthetic_case=resolved_synthetic_case,
            )
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                outcome = _SanitizedScientificControlFlow("keyboard_interrupt")
            elif type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                outcome = _SanitizedScientificControlFlow("system_exit", safe_exit_code)
                del stopped_code
            elif type(stopped) is GeneratorExit:
                outcome = _SanitizedScientificControlFlow("generator_exit")
            else:
                outcome = scientific_failure
        finally:
            del sealed_result_evidence_set
        if type(outcome) is _SanitizedScientificControlFlow:
            sanitized_outcome = _cast(_any_type_marker, outcome)
            if sanitized_outcome.kind == "keyboard_interrupt":
                raise KeyboardInterrupt
            if sanitized_outcome.kind == "system_exit":
                raise SystemExit(sanitized_outcome.exit_code)
            raise GeneratorExit
        if (
            type(outcome) is tuple
            and len(outcome) == 2
            and outcome[0] is capture_success
            and type(outcome[1]) is _captured_scientific_run_type
        ):
            return outcome[1]
        del outcome
        raise _scientific_evidence_error_type("Scientific capture failed integrity validation.")

    def chain_input(
        candidate: _CapturedCandidateState,
        chain: _CapturedChainState,
        /,
    ) -> _ChainEvidenceInput:
        snapshots = {snapshot.name: snapshot for snapshot in chain.arrays}
        relevant_names = (
            "postburn_order_state_chain",
            "order_state_chain",
            "position_probabilities",
            "pairwise_precedence",
            "postburn_likelihood_trace",
        )
        array_digests: list[tuple[str, str]] = []
        for name in relevant_names:
            snapshot = snapshots.get(name)
            if snapshot is None:
                continue
            catalog = strict_json_loads(snapshot.catalog_bytes)
            digest = catalog.get("array_digest") if isinstance(catalog, _mapping_type) else None
            if type(digest) is not str:
                raise _scientific_evidence_error_type(
                    "Captured scientific array provenance is invalid."
                )
            array_digests.append((name, digest))
        chain_payload = strict_json_loads(chain.chain_payload_bytes)
        if (
            type(chain_payload) is not dict
            or chain_payload.get("chain_plan_position") != chain.chain_plan_position
            or chain_payload.get("chain_execution_id") != chain.chain_execution_id
            or chain_payload.get("event_ids") != list(candidate.event_ids)
            or chain_payload.get("retained_state_count") != chain.retained_state_count
        ):
            raise _scientific_evidence_error_type("Captured scientific chain payload is invalid.")
        return chain_evidence_input_type(
            chain_plan_position=chain.chain_plan_position,
            chain_execution_id=chain.chain_execution_id,
            final_attempt_id=chain.final_attempt_id,
            chain_payload_digest=chain.chain_payload_digest,
            execution_evidence_digest=chain.execution_evidence_digest,
            event_ids=candidate.event_ids,
            retained_state_count=chain.retained_state_count,
            headline_order_event_ids=chain.central_order_event_ids,
            headline_order_method_bytes=chain.central_order_method_bytes,
            order_state_chain=(
                None
                if snapshots.get("order_state_chain") is None
                else snapshots["order_state_chain"]._array()
            ),
            position_probabilities=(
                None
                if snapshots.get("position_probabilities") is None
                else snapshots["position_probabilities"]._array()
            ),
            pairwise_precedence=(
                None
                if snapshots.get("pairwise_precedence") is None
                else snapshots["pairwise_precedence"]._array()
            ),
            array_digests=tuple(array_digests),
            thinning_interval=chain_payload.get("thinning_interval"),
            postburn_unthinned_state_count=chain_payload.get("postburn_unthinned_state_count"),
            postburn_order_state_chain=(
                None
                if snapshots.get("postburn_order_state_chain") is None
                else snapshots["postburn_order_state_chain"]._array()
            ),
            postburn_likelihood_trace=(
                None
                if snapshots.get("postburn_likelihood_trace") is None
                else snapshots["postburn_likelihood_trace"]._array()
            ),
        )

    def stage_comparison_side_input(
        candidate: _CapturedCandidateState,
        reference_chain: _CapturedChainState | None,
        preparation_binding_bytes: bytes,
        /,
    ) -> _StageComparisonSideInput:
        """Join authenticated stage rows to preparation-owned private identities."""

        directions = tuple(direction for event_id, direction in candidate.event_directions)
        if tuple(event_id for event_id, _direction in candidate.event_directions) != (
            candidate.event_ids
        ) or any(direction not in {"higher", "lower"} for direction in directions):
            raise _scientific_evidence_error_type("Captured stage event semantics are invalid.")

        def unavailable(
            availability: str,
            reason_code: str,
        ) -> _StageComparisonSideInput:
            return stage_comparison_side_input_type(
                availability=_cast(_any_type_marker, availability),
                availability_reason_code=reason_code,
                ordered_event_ids=candidate.event_ids,
                ordered_event_directions=_cast(_any_type_marker, directions),
                stage_semantics_digest=candidate.stage_semantics_digest,
                stage_model_reference_digest=None,
                reference_order_event_ids=None,
                headline_central_order_event_ids=None,
                evaluation_cohort_digest=None,
                evaluation_row_indexes_digest=None,
                evaluation_stage_posterior_digest=None,
                evaluation_row_indexes=None,
                evaluation_unit_bindings=None,
                evaluation_stage_posteriors=None,
            )

        try:
            preparation = strict_json_loads(preparation_binding_bytes)
        except (TypeError, ValueError):
            raise _scientific_evidence_error_type(
                "Captured stage preparation evidence is invalid."
            ) from None
        if (
            type(preparation) is not dict
            or canonical_json_bytes(preparation) != preparation_binding_bytes
            or (
                preparation.get("candidate_ordinal"),
                preparation.get("candidate_id"),
                preparation.get("analysis_spec_id"),
            )
            != (
                candidate.candidate_ordinal,
                candidate.candidate_id,
                candidate.analysis_spec_id,
            )
        ):
            raise _scientific_evidence_error_type(
                "Captured stage preparation evidence is detached."
            )
        preparation_preimage = dict(preparation)
        preparation_digest = preparation_preimage.pop("binding_digest", None)
        if preparation_digest != structured_sha256(
            "ebm-audit/stage-preparation-evidence-input/1",
            preparation_preimage,
        ):
            raise _scientific_evidence_error_type("Captured stage preparation evidence is invalid.")
        if preparation.get("preparation_state") != "PREPARED":
            return unavailable(
                "NOT_ASSESSABLE",
                "STAGE.PREPARATION_NOT_ASSESSABLE",
            )
        if reference_chain is None:
            return unavailable(
                "NOT_ASSESSABLE",
                "STAGE.REFERENCE_CHAIN_NOT_ASSESSABLE",
            )

        chain_payload = strict_json_loads(reference_chain.chain_payload_bytes)
        if type(chain_payload) is not dict:
            raise _scientific_evidence_error_type("Captured stage chain payload is invalid.")
        applicability = chain_payload.get("component_applicability")
        if type(applicability) is not list or any(type(row) is not dict for row in applicability):
            raise _scientific_evidence_error_type(
                "Captured stage component applicability is invalid."
            )
        posterior_applicability = [
            row
            for row in applicability
            if _cast(dict[str, object], row).get("output_id") == "evaluation_stage_posterior"
        ]
        if len(posterior_applicability) > 1:
            raise _scientific_evidence_error_type(
                "Captured stage component applicability is invalid."
            )
        snapshots = {snapshot.name: snapshot for snapshot in reference_chain.arrays}
        posterior_snapshot = snapshots.get("evaluation_stage_posterior")
        row_index_snapshot = snapshots.get("evaluation_row_indexes")
        if posterior_snapshot is None:
            if posterior_applicability == [
                {
                    "output_id": "evaluation_stage_posterior",
                    "status": "NOT_APPLICABLE_BY_CAPABILITY",
                    "value": None,
                    "reason_code": "STAGING.FIXED_COHORT_UNAVAILABLE",
                }
            ]:
                return unavailable(
                    "NOT_APPLICABLE_BY_CAPABILITY",
                    "STAGING.FIXED_COHORT_UNAVAILABLE",
                )
            return unavailable(
                "NOT_ASSESSABLE",
                "STAGE.EVALUATION_POSTERIOR_NOT_REQUESTED",
            )
        if posterior_applicability or row_index_snapshot is None:
            raise _scientific_evidence_error_type("Captured stage array coverage is invalid.")

        try:
            response = strict_json_loads(reference_chain.response_bytes)
        except (TypeError, ValueError):
            raise _scientific_evidence_error_type(
                "Captured stage reference evidence is invalid."
            ) from None
        response_payload = response.get("payload") if type(response) is dict else None
        response_result = (
            response_payload.get("result") if isinstance(response_payload, _mapping_type) else None
        )
        chain_reference = chain_payload.get("stage_model_reference")
        response_reference = (
            response_result.get("stage_model_reference")
            if isinstance(response_result, _mapping_type)
            else None
        )
        expected_reference_keys = {
            "stage_model_reference_schema_version",
            "stage_model_reference_digest",
            "event_ids",
            "selection_method_id",
            "reference_order_permutation",
            "reference_order_binding",
            "fitted_distribution_bindings",
            "final_stage_prior_binding",
            "final_stage_prior_fixed_point_l1_residual",
            "stage_semantics_digest",
        }
        if (
            type(response_reference) is not dict
            or type(chain_reference) is not dict
            or response_reference != chain_reference
            or set(response_reference) != expected_reference_keys
        ):
            raise _scientific_evidence_error_type(
                "Captured stage reference evidence is missing or detached."
            )
        reference_preimage = dict(response_reference)
        reference_digest = reference_preimage.pop(
            "stage_model_reference_digest",
            None,
        )
        permutation = response_reference.get("reference_order_permutation")
        event_count = len(candidate.event_ids)
        if (
            reference_digest
            != structured_sha256(
                "ebm-audit/stage-model-reference/1",
                reference_preimage,
            )
            or response_reference.get("stage_model_reference_schema_version")
            != "ebm-audit-stage-model-reference/1.0"
            or response_reference.get("event_ids") != list(candidate.event_ids)
            or response_reference.get("stage_semantics_digest") != candidate.stage_semantics_digest
            or type(response_reference.get("selection_method_id")) is not str
            or type(permutation) is not list
            or len(permutation) != event_count
            or any(type(index) is not int for index in permutation)
            or sorted(_cast(list[int], permutation)) != list(range(event_count))
        ):
            raise _scientific_evidence_error_type("Captured stage reference evidence is invalid.")

        def bound_snapshot(binding: object) -> _ScientificArraySnapshot:
            if (
                type(binding) is not dict
                or set(binding) != {"member_name", "array_digest"}
                or type(binding.get("member_name")) is not str
                or type(binding.get("array_digest")) is not str
            ):
                raise _scientific_evidence_error_type(
                    "Captured stage reference array binding is invalid."
                )
            member_name = _cast(str, binding["member_name"])
            snapshot = snapshots.get(member_name)
            if snapshot is None:
                raise _scientific_evidence_error_type(
                    "Captured stage reference array binding is detached."
                )
            catalog = strict_json_loads(snapshot.catalog_bytes)
            if (
                not isinstance(catalog, _mapping_type)
                or catalog.get("array_digest") != binding["array_digest"]
            ):
                raise _scientific_evidence_error_type(
                    "Captured stage reference array binding is detached."
                )
            return snapshot

        fitted_bindings = response_reference.get("fitted_distribution_bindings")
        if type(fitted_bindings) is not list or not fitted_bindings:
            raise _scientific_evidence_error_type("Captured stage reference evidence is invalid.")
        reference_bindings = [
            response_reference.get("reference_order_binding"),
            *fitted_bindings,
            response_reference.get("final_stage_prior_binding"),
        ]
        bound_snapshots = tuple(bound_snapshot(binding) for binding in reference_bindings)
        bound_names = [
            _cast(dict[str, object], binding)["member_name"] for binding in reference_bindings
        ]
        if len(set(bound_names)) != len(bound_names):
            raise _scientific_evidence_error_type(
                "Captured stage reference array binding is duplicated."
            )
        reference_order_array = bound_snapshots[0]._array()
        if (
            np_dtype(reference_order_array.dtype) != np_dtype("int32")
            or reference_order_array.shape != (event_count,)
            or reference_order_array.tolist() != permutation
        ):
            raise _scientific_evidence_error_type("Captured stage reference order is invalid.")
        if any(
            snapshot._array().ndim < 1 or int(snapshot._array().shape[0]) != event_count
            for snapshot in bound_snapshots[1:-1]
        ):
            raise _scientific_evidence_error_type(
                "Captured stage fitted-distribution binding is invalid."
            )
        final_prior = bound_snapshots[-1]._array()
        if np_dtype(final_prior.dtype) != np_dtype("float64") or final_prior.shape != (
            event_count + 1,
        ):
            raise _scientific_evidence_error_type("Captured stage final-prior binding is invalid.")
        central_permutation = (
            response_result.get("central_order_permutation")
            if isinstance(response_result, _mapping_type)
            else None
        )
        if (
            type(central_permutation) is not list
            or len(central_permutation) != event_count
            or any(type(index) is not int for index in central_permutation)
            or sorted(_cast(list[int], central_permutation)) != list(range(event_count))
        ):
            raise _scientific_evidence_error_type("Captured stage headline order is invalid.")
        headline_order = tuple(
            candidate.event_ids[index] for index in _cast(list[int], central_permutation)
        )
        if headline_order != reference_chain.central_order_event_ids or chain_payload.get(
            "central_order_event_ids"
        ) != list(headline_order):
            raise _scientific_evidence_error_type("Captured stage headline order is detached.")
        reference_order = tuple(
            candidate.event_ids[index] for index in _cast(list[int], permutation)
        )

        def snapshot_digest(snapshot: _ScientificArraySnapshot) -> str:
            catalog = strict_json_loads(snapshot.catalog_bytes)
            digest = catalog.get("array_digest") if isinstance(catalog, _mapping_type) else None
            if type(digest) is not str:
                raise _scientific_evidence_error_type("Captured stage array provenance is invalid.")
            return digest

        units = preparation.get("evaluation_units")
        cohort_digest = preparation.get("evaluation_membership_digest")
        cohort_count = preparation.get("evaluation_participant_count")
        if (
            type(units) is not list
            or type(cohort_digest) is not str
            or type(cohort_count) is not int
            or cohort_count < 1
            or len(units) != cohort_count
            or any(type(unit) is not dict for unit in units)
        ):
            raise _scientific_evidence_error_type("Captured stage preparation evidence is invalid.")
        row_index_array = row_index_snapshot._array()
        posterior_array = posterior_snapshot._array()
        if (
            row_index_array.ndim != 1
            or posterior_array.ndim != 2
            or int(row_index_array.shape[0]) != cohort_count
            or int(posterior_array.shape[0]) != cohort_count
            or int(posterior_array.shape[1]) != len(candidate.event_ids) + 1
        ):
            raise _scientific_evidence_error_type("Captured stage posterior shape is invalid.")
        returned_positions: dict[int, int] = {}
        for position, raw_row_index in enumerate(row_index_array.tolist()):
            if type(raw_row_index) is not int or raw_row_index < 0:
                raise _scientific_evidence_error_type("Captured stage row identity is invalid.")
            if raw_row_index in returned_positions:
                raise _scientific_evidence_error_type("Captured stage row identity is duplicated.")
            returned_positions[raw_row_index] = position
        ordered_row_indexes: list[int] = []
        ordered_bindings: list[str] = []
        ordered_posteriors: list[tuple[float, ...]] = []
        for unit in _cast(list[dict[str, object]], units):
            row_index = unit.get("evaluation_row_index")
            unit_binding = unit.get("evaluation_unit_binding")
            if (
                type(row_index) is not int
                or type(unit_binding) is not str
                or row_index not in returned_positions
            ):
                raise _scientific_evidence_error_type("Captured stage row identity is detached.")
            ordered_row_indexes.append(row_index)
            ordered_bindings.append(unit_binding)
            ordered_posteriors.append(
                tuple(
                    float(value)
                    for value in posterior_array[returned_positions[row_index]].tolist()
                )
            )
        if set(ordered_row_indexes) != set(returned_positions):
            raise _scientific_evidence_error_type("Captured stage row coverage is incomplete.")
        return stage_comparison_side_input_type(
            availability="AVAILABLE",
            availability_reason_code=None,
            ordered_event_ids=candidate.event_ids,
            ordered_event_directions=_cast(_any_type_marker, directions),
            stage_semantics_digest=candidate.stage_semantics_digest,
            stage_model_reference_digest=reference_digest,
            reference_order_event_ids=reference_order,
            headline_central_order_event_ids=headline_order,
            evaluation_cohort_digest=cohort_digest,
            evaluation_row_indexes_digest=snapshot_digest(row_index_snapshot),
            evaluation_stage_posterior_digest=snapshot_digest(posterior_snapshot),
            evaluation_row_indexes=tuple(ordered_row_indexes),
            evaluation_unit_bindings=tuple(ordered_bindings),
            evaluation_stage_posteriors=tuple(ordered_posteriors),
        )

    def selected_reference_chain_state(
        candidate: _CapturedCandidateState,
        /,
    ) -> tuple[int | None, _CapturedChainState | None]:
        if candidate.reference_chain_bytes is None:
            return None, None
        reference = strict_json_loads(candidate.reference_chain_bytes)
        if (
            not isinstance(reference, _mapping_type)
            or type(reference.get("chain_plan_position")) is not int
        ):
            raise _scientific_evidence_error_type("Captured scientific reference chain is invalid.")
        reference_position = _cast(int, reference["chain_plan_position"])
        if not candidate.chains:
            return reference_position, None
        reference_matches = tuple(
            chain for chain in candidate.chains if chain.chain_plan_position == reference_position
        )
        if len(reference_matches) != 1:
            raise _scientific_evidence_error_type("Captured scientific reference chain is invalid.")
        return reference_position, reference_matches[0]

    def validate_convergence_source(
        candidate: _CapturedCandidateState,
        chains: tuple[_ChainEvidenceInput, ...],
        /,
    ) -> None:
        if candidate.final_status not in {"SUCCESS", "CONVERGENCE_WARN"}:
            return
        if candidate.convergence_record_bytes is None:
            raise _scientific_evidence_error_type("Captured convergence evidence is unavailable.")
        convergence = strict_json_loads(candidate.convergence_record_bytes)
        non_sampling_convergence = is_canonical_non_sampling_convergence(convergence)
        convergence_inputs: list[ConvergenceChainInput] = []
        for chain in chains:
            postburn_orders = chain.postburn_order_state_chain
            if non_sampling_convergence:
                if any(
                    value is not None
                    for value in (
                        postburn_orders,
                        chain.thinning_interval,
                        chain.postburn_unthinned_state_count,
                        chain.retained_state_count,
                    )
                ):
                    raise _scientific_evidence_error_type(
                        "Captured non-sampling convergence evidence is invalid."
                    )
                continue
            if (
                type(postburn_orders) is not np_ndarray_type
                or postburn_orders.dtype != np_dtype(np_int32)
                or postburn_orders.ndim != 2
            ):
                raise _scientific_evidence_error_type(
                    "Captured convergence order-state evidence is invalid."
                )
            convergence_orders = np_array(
                postburn_orders,
                dtype=np_int64,
                order="C",
                copy=True,
            )
            convergence_orders.flags.writeable = False
            convergence_inputs.append(
                convergence_chain_input_type(
                    chain_execution_id=chain.chain_execution_id,
                    event_ids=chain.event_ids,
                    thinning_interval=chain.thinning_interval,
                    postburn_unthinned_state_count=(chain.postburn_unthinned_state_count),
                    retained_state_count=chain.retained_state_count,
                    postburn_order_state_chain=convergence_orders,
                    position_probabilities=chain.position_probabilities,
                    pairwise_precedence=chain.pairwise_precedence,
                    postburn_likelihood_trace=chain.postburn_likelihood_trace,
                )
            )
        if non_sampling_convergence:
            return
        recomputed = derive_convergence(tuple(convergence_inputs))
        if canonical_json_bytes(recomputed) != candidate.convergence_record_bytes:
            raise _scientific_evidence_error_type(
                "Captured convergence evidence failed exact rule rederivation."
            )

    def validate_candidate_envelope(
        value: object,
        /,
    ) -> tuple[dict[str, object], bytes, bytes, str]:
        if type(value) is not canonical_candidate_evidence_record_type:
            raise _scientific_evidence_error_type(
                "Derived scientific candidate evidence is invalid."
            )
        envelope = _cast(_any_type_marker, value)
        if (
            type(envelope.preimage_bytes) is not bytes
            or type(envelope.canonical_bytes) is not bytes
            or type(envelope.record_digest) is not str
        ):
            raise _scientific_evidence_error_type(
                "Derived scientific candidate evidence is invalid."
            )
        preimage = strict_json_loads(envelope.preimage_bytes)
        record = strict_json_loads(envelope.canonical_bytes)
        if (
            type(preimage) is not dict
            or type(record) is not dict
            or canonical_json_bytes(preimage) != envelope.preimage_bytes
            or canonical_json_bytes(record) != envelope.canonical_bytes
        ):
            raise _scientific_evidence_error_type(
                "Derived scientific candidate evidence is invalid."
            )
        supplied_digest = record.get("record_digest")
        record_preimage = dict(record)
        if "record_digest" not in record_preimage:
            raise _scientific_evidence_error_type(
                "Derived scientific candidate evidence is invalid."
            )
        del record_preimage["record_digest"]
        expected_digest = structured_sha256(
            "ebm-audit/scientific-candidate-evidence/1",
            preimage,
        )
        if (
            record_preimage != preimage
            or canonical_json_bytes(record_preimage) != envelope.preimage_bytes
            or preimage.get("evidence_rule_id") != candidate_evidence_rule_id
            or supplied_digest != expected_digest
            or envelope.record_digest != expected_digest
            or canonical_json_bytes(
                {
                    **preimage,
                    "record_digest": expected_digest,
                }
            )
            != envelope.canonical_bytes
        ):
            raise _scientific_evidence_error_type(
                "Derived scientific candidate evidence is invalid."
            )
        return (
            _cast(dict[str, object], record),
            envelope.preimage_bytes,
            envelope.canonical_bytes,
            envelope.record_digest,
        )

    def validate_layer_envelope(
        value: object,
        /,
        *,
        expected_type: type[object],
        digest_attribute: str,
        digest_field: str,
        domain: str,
        schema_definition: str,
        validators: Mapping[str, object],
    ) -> tuple[dict[str, object], bytes, bytes, str]:
        if type(value) is not expected_type:
            raise _scientific_evidence_error_type("Derived scientific layer evidence is invalid.")
        envelope = _cast(_any_type_marker, value)
        preimage_bytes = getattr(envelope, "preimage_bytes", None)
        canonical_bytes = getattr(envelope, "canonical_bytes", None)
        retained_digest = getattr(envelope, digest_attribute, None)
        if (
            type(preimage_bytes) is not bytes
            or type(canonical_bytes) is not bytes
            or type(retained_digest) is not str
        ):
            raise _scientific_evidence_error_type("Derived scientific layer evidence is invalid.")
        preimage = strict_json_loads(preimage_bytes)
        record = strict_json_loads(canonical_bytes)
        if (
            type(preimage) is not dict
            or type(record) is not dict
            or canonical_json_bytes(preimage) != preimage_bytes
            or canonical_json_bytes(record) != canonical_bytes
        ):
            raise _scientific_evidence_error_type("Derived scientific layer evidence is invalid.")
        record_preimage = dict(record)
        supplied_digest = record_preimage.pop(digest_field, None)
        expected_digest = structured_sha256(domain, preimage)
        if (
            record_preimage != preimage
            or canonical_json_bytes(record_preimage) != preimage_bytes
            or supplied_digest != expected_digest
            or retained_digest != expected_digest
            or canonical_json_bytes({**preimage, digest_field: expected_digest}) != canonical_bytes
        ):
            raise _scientific_evidence_error_type("Derived scientific layer evidence is invalid.")
        validator = validators.get(schema_definition)
        if validator is None:
            raise _scientific_evidence_error_type("Derived scientific layer evidence is invalid.")
        try:
            first_schema_error = next(_cast(_any_type_marker, validator).iter_errors(record), None)
        except Exception:
            raise _scientific_evidence_error_type(
                "Derived scientific layer evidence is invalid."
            ) from None
        if first_schema_error is not None:
            del first_schema_error
            raise _scientific_evidence_error_type("Derived scientific layer evidence is invalid.")
        return (
            _cast(dict[str, object], record),
            preimage_bytes,
            canonical_bytes,
            retained_digest,
        )

    def validate_analyst_bundle(
        value: object,
        /,
    ) -> tuple[
        dict[str, object],
        tuple[bytes, ...],
        tuple[bytes, ...],
        tuple[str, ...],
        tuple[bytes, ...],
        tuple[bytes, ...],
        tuple[str, ...],
        tuple[bytes, ...],
        tuple[bytes, ...],
        tuple[str, ...],
        bytes,
        bytes,
        str,
    ]:
        if type(value) is not canonical_analyst_bundle_type:
            raise _scientific_evidence_error_type("Derived analyst-decision evidence is invalid.")
        bundle = _cast(_any_type_marker, value)
        attempt_records: list[dict[str, object]] = []
        attempt_preimages: list[bytes] = []
        attempt_canonical: list[bytes] = []
        attempt_digests: list[str] = []
        for envelope in bundle.attempts:
            record, preimage, canonical, digest = validate_layer_envelope(
                envelope,
                expected_type=canonical_origin_attempt_type,
                digest_attribute="attempt_digest",
                digest_field="attempt_digest",
                domain="ebm-audit/scientific-origin-comparison-attempt/2",
                schema_definition="OriginComparisonAttempt",
                validators=analyst_schema_validators,
            )
            attempt_records.append(record)
            attempt_preimages.append(preimage)
            attempt_canonical.append(canonical)
            attempt_digests.append(digest)
        numeric_records: list[dict[str, object]] = []
        numeric_preimages: list[bytes] = []
        numeric_canonical: list[bytes] = []
        numeric_digests: list[str] = []
        for envelope in bundle.numeric_records:
            record, preimage, canonical, digest = validate_layer_envelope(
                envelope,
                expected_type=canonical_numeric_comparison_type,
                digest_attribute="numeric_comparison_digest",
                digest_field="numeric_comparison_digest",
                domain="ebm-audit/scientific-origin-numeric-comparison/4",
                schema_definition="OriginNumericComparisonRecord",
                validators=analyst_schema_validators,
            )
            numeric_records.append(record)
            numeric_preimages.append(preimage)
            numeric_canonical.append(canonical)
            numeric_digests.append(digest)
        aggregate_records: list[dict[str, object]] = []
        aggregate_preimages: list[bytes] = []
        aggregate_canonical: list[bytes] = []
        aggregate_digests: list[str] = []
        for envelope in bundle.aggregates:
            record, preimage, canonical, digest = validate_layer_envelope(
                envelope,
                expected_type=canonical_analyst_aggregate_type,
                digest_attribute="aggregate_digest",
                digest_field="aggregate_digest",
                domain="ebm-audit/scientific-analyst-decision-aggregate/2",
                schema_definition="AnalystDecisionAggregate",
                validators=analyst_schema_validators,
            )
            aggregate_records.append(record)
            aggregate_preimages.append(preimage)
            aggregate_canonical.append(canonical)
            aggregate_digests.append(digest)
        layer, layer_preimage, layer_canonical, layer_digest = validate_layer_envelope(
            bundle.layer,
            expected_type=canonical_analyst_layer_type,
            digest_attribute="layer_digest",
            digest_field="layer_digest",
            domain="ebm-audit/scientific-analyst-decision-evidence/2",
            schema_definition="AnalystDecisionLayerEvidence",
            validators=analyst_schema_validators,
        )
        aggregate_sort_keys = [
            canonical_json_bytes(
                [
                    record.get("aggregate_kind"),
                    record.get("experiment_set_id"),
                    (
                        record.get("axis_id")
                        if record.get("aggregate_kind") == "ONE_AXIS_FAMILY"
                        else record.get("experiment_mode")
                    ),
                    (
                        None
                        if record.get("aggregate_kind") == "ONE_AXIS_FAMILY"
                        else record.get("axis_choices")
                    ),
                ]
            )
            for record in aggregate_records
        ]
        if (
            layer.get("evidence_rule_id") != analyst_decision_evidence_rule_id
            or layer.get("attempts") != attempt_records
            or layer.get("numeric_records") != numeric_records
            or layer.get("aggregates") != aggregate_records
            or len(set(attempt_digests)) != len(attempt_digests)
            or len(set(numeric_digests)) != len(numeric_digests)
            or len(set(aggregate_digests)) != len(aggregate_digests)
            or [record.get("origin_id") for record in attempt_records]
            != sorted(
                (record.get("origin_id") for record in attempt_records),
                key=lambda value: _cast(str, value).encode("utf-8"),
            )
            or [
                (
                    _cast(dict[str, object], record.get("numeric_identity")).get(
                        "subject_analysis_spec_id"
                    ),
                    _cast(dict[str, object], record.get("numeric_identity")).get(
                        "comparator_analysis_spec_id"
                    ),
                )
                for record in numeric_records
            ]
            != sorted(
                (
                    (
                        _cast(dict[str, object], record.get("numeric_identity")).get(
                            "subject_analysis_spec_id"
                        ),
                        _cast(dict[str, object], record.get("numeric_identity")).get(
                            "comparator_analysis_spec_id"
                        ),
                    )
                    for record in numeric_records
                ),
                key=lambda pair: (
                    _cast(str, pair[0]).encode("utf-8"),
                    _cast(str, pair[1]).encode("utf-8"),
                ),
            )
            or aggregate_sort_keys != sorted(aggregate_sort_keys)
        ):
            raise _scientific_evidence_error_type("Derived analyst-decision evidence is invalid.")
        numeric_digest_set = set(numeric_digests)
        attempt_by_digest = {
            _cast(str, record["attempt_digest"]): record for record in attempt_records
        }
        for attempt in attempt_records:
            applicability = attempt.get("applicability_state")
            numeric_digest = attempt.get("numeric_comparison_digest")
            applicable = applicability in {
                "APPLICABLE_ORDINARY_ONE_AXIS",
                "APPLICABLE_DECLARED_COMBINATION",
                "APPLICABLE_FULL_FACTORIAL",
            }
            if (applicable and numeric_digest not in numeric_digest_set) or (
                not applicable and numeric_digest is not None
            ):
                raise _scientific_evidence_error_type(
                    "Derived analyst-decision evidence is invalid."
                )
        for aggregate in aggregate_records:
            rows = (
                aggregate.get("choice_rows")
                if aggregate.get("aggregate_kind") == "ONE_AXIS_FAMILY"
                else aggregate.get("member_rows")
            )
            if type(rows) is not list:
                raise _scientific_evidence_error_type(
                    "Derived analyst-decision evidence is invalid."
                )
            for row in rows:
                if (
                    type(row) is not dict
                    or row.get("attempt_digest") not in attempt_by_digest
                    or row.get("numeric_comparison_digest") not in numeric_digest_set
                ):
                    raise _scientific_evidence_error_type(
                        "Derived analyst-decision evidence is invalid."
                    )
        return (
            layer,
            tuple(attempt_preimages),
            tuple(attempt_canonical),
            tuple(attempt_digests),
            tuple(numeric_preimages),
            tuple(numeric_canonical),
            tuple(numeric_digests),
            tuple(aggregate_preimages),
            tuple(aggregate_canonical),
            tuple(aggregate_digests),
            layer_preimage,
            layer_canonical,
            layer_digest,
        )

    def validate_sampling_bundle(
        value: object,
        /,
    ) -> tuple[
        dict[str, object],
        tuple[bytes, ...],
        tuple[bytes, ...],
        tuple[str, ...],
        tuple[bytes, ...],
        tuple[bytes, ...],
        tuple[str, ...],
        tuple[bytes, ...],
        tuple[bytes, ...],
        tuple[str, ...],
        bytes,
        bytes,
        str,
    ]:
        if type(value) is not canonical_sampling_bundle_type:
            raise _scientific_evidence_error_type("Derived sampling evidence is invalid.")
        bundle = _cast(_any_type_marker, value)
        attempt_records: list[dict[str, object]] = []
        attempt_preimages: list[bytes] = []
        attempt_canonical: list[bytes] = []
        attempt_digests: list[str] = []
        for envelope in bundle.attempts:
            record, preimage, canonical, digest = validate_layer_envelope(
                envelope,
                expected_type=canonical_sampling_attempt_type,
                digest_attribute="attempt_digest",
                digest_field="attempt_digest",
                domain="ebm-audit/scientific-sampling-origin-attempt/3",
                schema_definition="SamplingOriginAttempt",
                validators=sampling_schema_validators,
            )
            attempt_records.append(record)
            attempt_preimages.append(preimage)
            attempt_canonical.append(canonical)
            attempt_digests.append(digest)
        numeric_records: list[dict[str, object]] = []
        numeric_preimages: list[bytes] = []
        numeric_canonical: list[bytes] = []
        numeric_digests: list[str] = []
        for envelope in bundle.numeric_records:
            record, preimage, canonical, digest = validate_layer_envelope(
                envelope,
                expected_type=canonical_sampling_numeric_type,
                digest_attribute="numeric_comparison_digest",
                digest_field="numeric_comparison_digest",
                domain="ebm-audit/scientific-sampling-numeric-comparison/3",
                schema_definition="SamplingNumericComparison",
                validators=sampling_schema_validators,
            )
            numeric_records.append(record)
            numeric_preimages.append(preimage)
            numeric_canonical.append(canonical)
            numeric_digests.append(digest)
        aggregate_records: list[dict[str, object]] = []
        aggregate_preimages: list[bytes] = []
        aggregate_canonical: list[bytes] = []
        aggregate_digests: list[str] = []
        for envelope in bundle.aggregates:
            record, preimage, canonical, digest = validate_layer_envelope(
                envelope,
                expected_type=canonical_sampling_aggregate_type,
                digest_attribute="aggregate_digest",
                digest_field="aggregate_digest",
                domain="ebm-audit/scientific-sampling-family-aggregate/3",
                schema_definition="SamplingFamilyAggregate",
                validators=sampling_schema_validators,
            )
            aggregate_records.append(record)
            aggregate_preimages.append(preimage)
            aggregate_canonical.append(canonical)
            aggregate_digests.append(digest)
        layer, layer_preimage, layer_canonical, layer_digest = validate_layer_envelope(
            bundle.layer,
            expected_type=canonical_sampling_layer_type,
            digest_attribute="layer_digest",
            digest_field="layer_digest",
            domain="ebm-audit/scientific-sampling-layer-evidence/3",
            schema_definition="SamplingLayerEvidence",
            validators=sampling_schema_validators,
        )
        try:
            validate_sampling_semantics(layer)
        except Exception:
            raise _scientific_evidence_error_type("Derived sampling evidence is invalid.") from None
        if (
            layer.get("evidence_rule_id") != sampling_evidence_rule_id
            or layer.get("attempts") != attempt_records
            or layer.get("numeric_records") != numeric_records
            or layer.get("aggregates") != aggregate_records
            or len(set(attempt_digests)) != len(attempt_digests)
            or len(set(numeric_digests)) != len(numeric_digests)
            or len(set(aggregate_digests)) != len(aggregate_digests)
        ):
            raise _scientific_evidence_error_type("Derived sampling evidence is invalid.")
        return (
            layer,
            tuple(attempt_preimages),
            tuple(attempt_canonical),
            tuple(attempt_digests),
            tuple(numeric_preimages),
            tuple(numeric_canonical),
            tuple(numeric_digests),
            tuple(aggregate_preimages),
            tuple(aggregate_canonical),
            tuple(aggregate_digests),
            layer_preimage,
            layer_canonical,
            layer_digest,
        )

    def validate_influence_bundle(
        value: object,
        /,
    ) -> tuple[
        dict[str, object],
        tuple[bytes, ...],
        tuple[bytes, ...],
        tuple[str, ...],
        bytes,
        bytes,
        str,
    ]:
        if type(value) is not canonical_influence_bundle_type:
            raise _scientific_evidence_error_type(
                "Derived participant-influence evidence is invalid."
            )
        bundle = _cast(_any_type_marker, value)
        attempt_records: list[dict[str, object]] = []
        attempt_preimages: list[bytes] = []
        attempt_canonical: list[bytes] = []
        attempt_digests: list[str] = []
        for envelope in bundle.attempts:
            record, preimage, canonical, digest = validate_layer_envelope(
                envelope,
                expected_type=canonical_influence_attempt_type,
                digest_attribute="attempt_digest",
                digest_field="attempt_digest",
                domain="ebm-audit/scientific-influence-attempt/1",
                schema_definition="InfluenceAttempt",
                validators=influence_schema_validators,
            )
            attempt_records.append(record)
            attempt_preimages.append(preimage)
            attempt_canonical.append(canonical)
            attempt_digests.append(digest)
        layer, layer_preimage, layer_canonical, layer_digest = validate_layer_envelope(
            bundle.layer,
            expected_type=canonical_influence_layer_type,
            digest_attribute="layer_digest",
            digest_field="layer_digest",
            domain="ebm-audit/scientific-influence-layer-evidence/1",
            schema_definition="InfluenceLayerEvidence",
            validators=influence_schema_validators,
        )
        try:
            validate_influence_semantics(layer)
        except Exception:
            raise _scientific_evidence_error_type(
                "Derived participant-influence evidence is invalid."
            ) from None
        if (
            layer.get("evidence_rule_id") != influence_evidence_rule_id
            or layer.get("attempts") != attempt_records
            or len(set(attempt_digests)) != len(attempt_digests)
        ):
            raise _scientific_evidence_error_type(
                "Derived participant-influence evidence is invalid."
            )
        return (
            layer,
            tuple(attempt_preimages),
            tuple(attempt_canonical),
            tuple(attempt_digests),
            layer_preimage,
            layer_canonical,
            layer_digest,
        )

    def validate_null_layer(
        value: object,
        /,
    ) -> tuple[dict[str, object], bytes, bytes, str]:
        if type(value) is not canonical_null_layer_type:
            raise _scientific_evidence_error_type("Derived null evidence is invalid.")
        layer_envelope = _cast(_any_type_marker, value)
        preimage_bytes = layer_envelope.preimage_bytes
        canonical_bytes = layer_envelope.canonical_bytes
        layer_digest = layer_envelope.layer_digest
        try:
            preimage = strict_json_loads(preimage_bytes)
            layer = strict_json_loads(canonical_bytes)
            if (
                type(preimage_bytes) is not bytes
                or type(canonical_bytes) is not bytes
                or type(layer_digest) is not str
                or type(preimage) is not dict
                or type(layer) is not dict
                or canonical_json_bytes(preimage) != preimage_bytes
                or canonical_json_bytes(layer) != canonical_bytes
                or layer != {**preimage, "layer_digest": layer_digest}
                or layer.get("evidence_rule_id") != null_evidence_rule_id
            ):
                raise ValueError
            validate_null_semantics(layer)
        except Exception:
            raise _scientific_evidence_error_type("Derived null evidence is invalid.") from None
        return (
            _cast(dict[str, object], layer),
            preimage_bytes,
            canonical_bytes,
            layer_digest,
        )

    def derive_projection(
        state: _CapturedScientificRunState,
        /,
    ) -> _DerivedScientificProjection:
        candidate_records: list[dict[str, object]] = []
        candidate_preimage_bytes: list[bytes] = []
        candidate_canonical_bytes: list[bytes] = []
        candidate_record_digests: list[str] = []
        private_stage_bytes_by_digest: dict[str, bytes] = {}
        analyst_candidates: list[_AnalystDecisionCandidateInput] = []
        sampling_candidates: list[_SamplingCandidateInput] = []
        influence_candidates: list[_InfluenceCandidateInput] = []
        null_candidates: list[_NullCandidateInput] = []
        try:
            retained_influence_preparation_inputs = state.influence_preparation_binding_bytes
            retained_bindings_digest = structured_sha256(
                "ebm-audit/captured-influence-preparation-bindings/1",
                [
                    strict_json_loads(binding_bytes)
                    for binding_bytes in retained_influence_preparation_inputs
                ],
            )
        except (TypeError, ValueError):
            raise _scientific_evidence_error_type(
                "Captured participant-influence preparation evidence is invalid."
            ) from None
        if retained_bindings_digest != state.influence_preparation_bindings_digest:
            raise _scientific_evidence_error_type(
                "Captured participant-influence preparation evidence is invalid."
            )
        influence_preparation_by_candidate: dict[tuple[int, str], bytes] = {}
        for retained in retained_influence_preparation_inputs:
            if type(retained) is not bytes:
                raise _scientific_evidence_error_type(
                    "Captured participant-influence preparation evidence is invalid."
                )
            decoded_binding = strict_json_loads(retained)
            if (
                type(decoded_binding) is not dict
                or canonical_json_bytes(decoded_binding) != retained
                or type(decoded_binding.get("candidate_ordinal")) is not int
                or _cast(int, decoded_binding["candidate_ordinal"]) < 0
                or type(decoded_binding.get("analysis_spec_id")) is not str
            ):
                raise _scientific_evidence_error_type(
                    "Captured participant-influence preparation evidence is invalid."
                )
            binding_key = (
                _cast(int, decoded_binding["candidate_ordinal"]),
                _cast(str, decoded_binding["analysis_spec_id"]),
            )
            if binding_key in influence_preparation_by_candidate:
                raise _scientific_evidence_error_type(
                    "Captured participant-influence preparation evidence is invalid."
                )
            influence_preparation_by_candidate[binding_key] = retained
        consumed_influence_preparation_keys: set[tuple[int, str]] = set()
        try:
            retained_stage_preparation_inputs = state.stage_preparation_binding_bytes
            retained_stage_bindings_digest = structured_sha256(
                "ebm-audit/captured-stage-preparation-bindings/1",
                [
                    strict_json_loads(binding_bytes)
                    for binding_bytes in retained_stage_preparation_inputs
                ],
            )
        except (TypeError, ValueError):
            raise _scientific_evidence_error_type(
                "Captured stage preparation evidence is invalid."
            ) from None
        if retained_stage_bindings_digest != state.stage_preparation_bindings_digest:
            raise _scientific_evidence_error_type("Captured stage preparation evidence is invalid.")
        stage_preparation_by_candidate: dict[tuple[int, str], bytes] = {}
        for retained in retained_stage_preparation_inputs:
            if type(retained) is not bytes:
                raise _scientific_evidence_error_type(
                    "Captured stage preparation evidence is invalid."
                )
            decoded_binding = strict_json_loads(retained)
            if (
                type(decoded_binding) is not dict
                or canonical_json_bytes(decoded_binding) != retained
                or type(decoded_binding.get("candidate_ordinal")) is not int
                or _cast(int, decoded_binding["candidate_ordinal"]) < 0
                or type(decoded_binding.get("analysis_spec_id")) is not str
            ):
                raise _scientific_evidence_error_type(
                    "Captured stage preparation evidence is invalid."
                )
            binding_key = (
                _cast(int, decoded_binding["candidate_ordinal"]),
                _cast(str, decoded_binding["analysis_spec_id"]),
            )
            if binding_key in stage_preparation_by_candidate:
                raise _scientific_evidence_error_type(
                    "Captured stage preparation evidence is invalid."
                )
            stage_preparation_by_candidate[binding_key] = retained
        consumed_stage_preparation_keys: set[tuple[int, str]] = set()
        stage_side_by_analysis_spec_id: dict[str, _StageComparisonSideInput] = {}
        reference_state_by_analysis_spec_id: dict[
            str,
            tuple[int | None, _CapturedChainState | None],
        ] = {}
        for candidate in state.candidates:
            stage_binding_key = (
                candidate.candidate_ordinal,
                candidate.analysis_spec_id,
            )
            stage_preparation_binding = stage_preparation_by_candidate.get(stage_binding_key)
            if (
                stage_preparation_binding is None
                or candidate.analysis_spec_id in stage_side_by_analysis_spec_id
            ):
                raise _scientific_evidence_error_type(
                    "Captured stage preparation evidence is incomplete."
                )
            reference_state = selected_reference_chain_state(candidate)
            reference_state_by_analysis_spec_id[candidate.analysis_spec_id] = reference_state
            stage_side_by_analysis_spec_id[candidate.analysis_spec_id] = (
                stage_comparison_side_input(
                    candidate,
                    reference_state[1],
                    stage_preparation_binding,
                )
            )
            consumed_stage_preparation_keys.add(stage_binding_key)
        for candidate in state.candidates:
            (
                reference_chain_plan_position,
                reference_chain_state,
            ) = reference_state_by_analysis_spec_id[candidate.analysis_spec_id]
            reference_chain_input = (
                None
                if reference_chain_state is None
                else chain_input(candidate, reference_chain_state)
            )
            candidate_chains = tuple(chain_input(candidate, chain) for chain in candidate.chains)
            validate_convergence_source(candidate, candidate_chains)
            derived_record = derive_candidate_evidence_record(
                candidate_ordinal=candidate.candidate_ordinal,
                candidate_id=candidate.candidate_id,
                analysis_spec_id=candidate.analysis_spec_id,
                result_id=candidate.result_id,
                final_status=candidate.final_status,
                event_ids=candidate.event_ids,
                event_directions=candidate.event_directions,
                stage_semantics_digest=candidate.stage_semantics_digest,
                planned_chain_count=candidate.planned_chain_count,
                finalized_terminal_chain_count=(candidate.finalized_terminal_chain_count),
                authenticated_available_chain_count=(candidate.authenticated_available_chain_count),
                reference_chain_plan_position=reference_chain_plan_position,
                convergence_record_bytes=candidate.convergence_record_bytes,
                chains=candidate_chains,
            )
            (
                decoded_record,
                preimage_bytes,
                canonical_bytes,
                record_digest,
            ) = validate_candidate_envelope(derived_record)
            candidate_records.append(decoded_record)
            candidate_preimage_bytes.append(preimage_bytes)
            candidate_canonical_bytes.append(canonical_bytes)
            candidate_record_digests.append(record_digest)
            candidate_source = strict_json_loads(candidate.candidate_record_bytes)
            comparison_edges = strict_json_loads(candidate.comparison_edges_bytes)
            if type(candidate_source) is not dict or type(comparison_edges) is not list:
                raise _scientific_evidence_error_type("Captured Plan/3 analyst source is invalid.")
            analysis_spec = candidate_source.get("analysis_spec")
            operation = (
                analysis_spec.get("operation_intent")
                if isinstance(analysis_spec, _mapping_type)
                else None
            )
            operation_kind = operation.get("kind") if isinstance(operation, _mapping_type) else None
            origins = candidate_origins(candidate_source)
            edge_by_origin = {
                edge.get("origin_id"): edge
                for edge in comparison_edges
                if isinstance(edge, _mapping_type) and type(edge.get("origin_id")) is str
            }
            if (
                type(operation_kind) is not str
                or len(edge_by_origin) != len(comparison_edges)
                or set(edge_by_origin) != {_cast(str, origin["origin_id"]) for origin in origins}
            ):
                raise _scientific_evidence_error_type("Captured Plan/3 analyst source is invalid.")
            operation_bytes = closed_mapping_bytes(
                operation,
                description="Captured Plan/3 operation is invalid.",
            )
            influence_binding_key = (
                candidate.candidate_ordinal,
                candidate.analysis_spec_id,
            )
            influence_preparation_binding = influence_preparation_by_candidate.get(
                influence_binding_key
            )
            if operation_kind == "influence":
                if influence_preparation_binding is None:
                    raise _scientific_evidence_error_type(
                        "Captured participant-influence preparation evidence is incomplete."
                    )
                consumed_influence_preparation_keys.add(influence_binding_key)
            elif influence_preparation_binding is not None:
                raise _scientific_evidence_error_type(
                    "Captured participant-influence preparation evidence is detached."
                )

            stage_comparison_bytes_by_origin_id: dict[str, bytes] = {}

            def stage_comparison_bytes(
                origin: Mapping[str, Any],
                edge_by_origin_map: Mapping[object, object] = edge_by_origin,
                subject_analysis_spec_id: str = candidate.analysis_spec_id,
                subject_operation_kind: str = _cast(str, operation_kind),
                stage_bytes_by_origin_id: dict[str, bytes] = stage_comparison_bytes_by_origin_id,
            ) -> bytes:
                origin_id = origin.get("origin_id")
                edge = edge_by_origin_map.get(origin_id)
                if type(origin_id) is not str or not isinstance(edge, _mapping_type):
                    raise _scientific_evidence_error_type(
                        "Captured stage comparison source is incomplete."
                    )
                existing = stage_bytes_by_origin_id.get(origin_id)
                if existing is not None:
                    return existing
                origin_mode = origin.get("experiment_mode")
                stage_row_is_public = (
                    subject_operation_kind in {"bootstrap", "subsample"}
                    and origin_mode == subject_operation_kind
                ) or (
                    subject_operation_kind == "ordinary"
                    and origin_mode in {"one-axis", "declared-combinations", "full-factorial"}
                )
                if not stage_row_is_public:
                    empty = canonical_json_bytes({})
                    stage_bytes_by_origin_id[origin_id] = empty
                    return empty
                comparator_analysis_spec_id = (
                    edge.get("comparator_analysis_spec_id")
                    if isinstance(edge, _mapping_type)
                    else None
                )
                comparator_stage_side = (
                    stage_side_by_analysis_spec_id.get(comparator_analysis_spec_id)
                    if type(comparator_analysis_spec_id) is str
                    else None
                )
                if comparator_stage_side is None:
                    raise _scientific_evidence_error_type(
                        "Captured stage comparison source is incomplete."
                    )
                derived_stage = derive_stage_comparison_owner(
                    stage_side_by_analysis_spec_id[subject_analysis_spec_id],
                    comparator_stage_side,
                )
                if type(derived_stage) is not derived_stage_comparison_type:
                    raise _scientific_evidence_error_type(
                        "Derived participant-stage comparison is invalid."
                    )
                private_bytes = derived_stage.private_evidence_bytes
                private_digest = derived_stage.private_evidence_digest
                public_bytes = derived_stage.public_projection_bytes
                try:
                    private_record = strict_json_loads(private_bytes)
                    public_record = strict_json_loads(public_bytes)
                except (TypeError, ValueError):
                    raise _scientific_evidence_error_type(
                        "Derived participant-stage comparison is invalid."
                    ) from None
                private_preimage = dict(private_record) if type(private_record) is dict else {}
                supplied_private_digest = private_preimage.pop(
                    "private_evidence_digest",
                    None,
                )
                if (
                    type(private_bytes) is not bytes
                    or type(public_bytes) is not bytes
                    or type(private_digest) is not str
                    or type(private_record) is not dict
                    or type(public_record) is not dict
                    or canonical_json_bytes(private_record) != private_bytes
                    or canonical_json_bytes(public_record) != public_bytes
                    or supplied_private_digest != private_digest
                    or public_record.get("private_evidence_digest") != private_digest
                    or structured_sha256(
                        _private_stage_comparison_digest_domain,
                        private_preimage,
                    )
                    != private_digest
                ):
                    raise _scientific_evidence_error_type(
                        "Derived participant-stage comparison is invalid."
                    )
                previous_private = private_stage_bytes_by_digest.setdefault(
                    private_digest,
                    private_bytes,
                )
                if previous_private != private_bytes:
                    raise _scientific_evidence_error_type(
                        "Derived participant-stage comparison is invalid."
                    )
                retained_public = closed_mapping_bytes(
                    public_record,
                    description="Derived participant-stage comparison is invalid.",
                )
                stage_bytes_by_origin_id[origin_id] = retained_public
                return retained_public

            analyst_origin_inputs = tuple(
                analyst_origin_input_type(
                    origin_bytes=closed_mapping_bytes(
                        origin,
                        description="Captured Plan/3 origin is invalid.",
                    ),
                    comparison_edge_bytes=closed_mapping_bytes(
                        edge,
                        description="Captured Plan/3 comparison edge is invalid.",
                    ),
                    stage_comparison_bytes=stage_comparison_bytes(origin),
                )
                for origin in origins
                for edge in [edge_by_origin[_cast(str, origin["origin_id"])]]
            )

            analyst_candidates.append(
                analyst_candidate_input_type(
                    candidate_ordinal=candidate.candidate_ordinal,
                    candidate_id=candidate.candidate_id,
                    analysis_spec_id=candidate.analysis_spec_id,
                    result_id=candidate.result_id,
                    universe_id=candidate.universe_id,
                    final_status=candidate.final_status,
                    candidate_record_digest=record_digest,
                    operation_kind=operation_kind,
                    event_ids=candidate.event_ids,
                    origins=analyst_origin_inputs,
                    reference_chain=reference_chain_input,
                )
            )
            sampling_candidates.append(
                sampling_candidate_input_type(
                    candidate_record_bytes=canonical_bytes,
                    universe_id=candidate.universe_id,
                    operation_bytes=operation_bytes,
                    origins=tuple(
                        sampling_origin_input_type(
                            origin_bytes=closed_mapping_bytes(
                                origin,
                                description="Captured Plan/3 sampling origin is invalid.",
                            ),
                            comparison_edge_bytes=closed_mapping_bytes(
                                edge_by_origin[_cast(str, origin["origin_id"])],
                                description=(
                                    "Captured Plan/3 sampling comparison edge is invalid."
                                ),
                            ),
                            stage_comparison_bytes=stage_comparison_bytes(origin),
                        )
                        for origin in origins
                    ),
                )
            )
            influence_candidates.append(
                influence_candidate_input_type(
                    candidate_record_bytes=canonical_bytes,
                    universe_id=candidate.universe_id,
                    operation_bytes=operation_bytes,
                    origins=tuple(
                        influence_origin_input_type(
                            origin_bytes=closed_mapping_bytes(
                                origin,
                                description=(
                                    "Captured Plan/3 participant-influence origin is invalid."
                                ),
                            ),
                            comparison_edge_bytes=closed_mapping_bytes(
                                edge_by_origin[_cast(str, origin["origin_id"])],
                                description=(
                                    "Captured Plan/3 participant-influence comparison edge "
                                    "is invalid."
                                ),
                            ),
                        )
                        for origin in origins
                    ),
                    preparation_binding_bytes=influence_preparation_binding,
                )
            )
            null_candidates.append(
                null_candidate_input_type(
                    candidate_record_bytes=canonical_bytes,
                    universe_id=candidate.universe_id,
                    operation_bytes=operation_bytes,
                )
            )
        if consumed_influence_preparation_keys != set(influence_preparation_by_candidate):
            raise _scientific_evidence_error_type(
                "Captured participant-influence preparation evidence is detached."
            )
        if consumed_stage_preparation_keys != set(stage_preparation_by_candidate):
            raise _scientific_evidence_error_type(
                "Captured stage preparation evidence is detached."
            )
        analyst_bundle = derive_analyst_decision_evidence(
            plan_digest=state.plan_digest,
            terminal_index_digest=state.terminal_index_digest,
            baseline_analysis_spec_id=state.baseline_analysis_spec_id,
            candidates=tuple(analyst_candidates),
        )
        (
            analyst_layer,
            attempt_preimage_bytes,
            attempt_canonical_bytes,
            attempt_digests,
            numeric_preimage_bytes,
            numeric_canonical_bytes,
            numeric_digests,
            aggregate_preimage_bytes,
            aggregate_canonical_bytes,
            aggregate_digests,
            analyst_layer_preimage_bytes,
            analyst_layer_canonical_bytes,
            analyst_layer_digest,
        ) = validate_analyst_bundle(analyst_bundle)
        sampling_bundle = derive_sampling_evidence(
            plan_digest=state.plan_digest,
            terminal_index_digest=state.terminal_index_digest,
            candidates=tuple(sampling_candidates),
        )
        (
            sampling_layer,
            sampling_attempt_preimage_bytes,
            sampling_attempt_canonical_bytes,
            sampling_attempt_digests,
            sampling_numeric_preimage_bytes,
            sampling_numeric_canonical_bytes,
            sampling_numeric_digests,
            sampling_aggregate_preimage_bytes,
            sampling_aggregate_canonical_bytes,
            sampling_aggregate_digests,
            sampling_layer_preimage_bytes,
            sampling_layer_canonical_bytes,
            sampling_layer_digest,
        ) = validate_sampling_bundle(sampling_bundle)
        public_stage_digests: list[str] = []
        for stage_layer in (analyst_layer, sampling_layer):
            stage_numeric_records = stage_layer.get("numeric_records")
            if type(stage_numeric_records) is not list:
                raise _scientific_evidence_error_type(
                    "Derived participant-stage evidence is invalid."
                )
            for stage_numeric_record in stage_numeric_records:
                if type(stage_numeric_record) is not dict:
                    raise _scientific_evidence_error_type(
                        "Derived participant-stage evidence is invalid."
                    )
                stage_public_record = stage_numeric_record.get("participant_stage_comparison")
                stage_private_digest = (
                    stage_public_record.get("private_evidence_digest")
                    if type(stage_public_record) is dict
                    else None
                )
                if type(stage_private_digest) is not str:
                    raise _scientific_evidence_error_type(
                        "Derived participant-stage evidence is invalid."
                    )
                public_stage_digests.append(stage_private_digest)
        if set(public_stage_digests) != set(private_stage_bytes_by_digest):
            raise _scientific_evidence_error_type(
                "Derived private participant-stage evidence is detached."
            )
        stage_comparison_private_digests = tuple(public_stage_digests)
        stage_comparison_private_canonical_bytes = tuple(
            private_stage_bytes_by_digest[digest] for digest in stage_comparison_private_digests
        )
        influence_bundle = derive_influence_evidence(
            plan_digest=state.plan_digest,
            terminal_index_digest=state.terminal_index_digest,
            candidates=tuple(influence_candidates),
        )
        (
            influence_layer,
            influence_attempt_preimage_bytes,
            influence_attempt_canonical_bytes,
            influence_attempt_digests,
            influence_layer_preimage_bytes,
            influence_layer_canonical_bytes,
            influence_layer_digest,
        ) = validate_influence_bundle(influence_bundle)
        null_layer_envelope = derive_null_evidence(
            plan_digest=state.plan_digest,
            terminal_index_digest=state.terminal_index_digest,
            candidates=tuple(null_candidates),
        )
        (
            null_layer,
            null_layer_preimage_bytes,
            null_layer_canonical_bytes,
            null_layer_digest,
        ) = validate_null_layer(null_layer_envelope)
        coverage = uncertainty_layer_coverage(
            tuple(candidate_records),
            sampling_layer,
            analyst_layer,
            influence_layer,
            null_layer,
        )
        science_completion_reason_codes = [
            "SCIENCE.UNCERTAINTY_LAYER_IMPLEMENTATION_PENDING",
            "SCIENCE.MATRIX_CROSS_CHECK_TOLERANCE_RULE_NOT_FROZEN",
        ]
        if _cast(int, null_layer["attempt_count"]) > 0:
            science_completion_reason_codes.insert(
                1,
                "NULL_CALIBRATION_NOT_VALIDATED",
            )
        synthetic_case_binding: dict[str, object] | None = None
        if state.synthetic_case_binding_bytes is not None:
            decoded_synthetic_case_binding = strict_json_loads(state.synthetic_case_binding_bytes)
            if (
                type(decoded_synthetic_case_binding) is not dict
                or canonical_json_bytes(decoded_synthetic_case_binding)
                != state.synthetic_case_binding_bytes
            ):
                raise _scientific_evidence_error_type("Captured synthetic case binding is invalid.")
            synthetic_case_binding = _cast(dict[str, object], decoded_synthetic_case_binding)
        preimage: dict[str, object] = {
            "scientific_evidence_schema_version": scientific_evidence_schema_version,
            "evidence_rule_id": sealed_evidence_rule_id,
            "plan_digest": state.plan_digest,
            "terminal_index_digest": state.terminal_index_digest,
            "synthetic_case_binding": synthetic_case_binding,
            "influence_preparation_bindings_digest": (state.influence_preparation_bindings_digest),
            "position_summary_rule": {
                "rule_id": position_summary_rule_id,
                "quantile_probabilities": list(position_summary_quantile_probabilities),
                "median_probability": 0.5,
            },
            "chain_top_k_rule": {
                "rule_id": chain_top_k_rule_id,
                "k_rule": "min(3,event_count)",
            },
            "matrix_cross_check_tolerance_rule": cross_check_tolerance_rule(),
            "uncertainty_layer_coverage": coverage,
            "science_completion_gate": {
                "status": "BLOCKED",
                "reason_codes": science_completion_reason_codes,
            },
            "candidate_records": candidate_records,
            "sampling_evidence": sampling_layer,
            "analyst_decision_evidence": analyst_layer,
            "participant_influence_evidence": influence_layer,
            "null_evidence": null_layer,
        }
        digest = structured_sha256(
            "ebm-audit/sealed-scientific-evidence/10",
            preimage,
        )
        ledger_receipt_preimage: dict[str, object] = {
            "science_ledger_receipt_schema_version": (_science_ledger_receipt_schema_version),
            "scientific_evidence_schema_version": scientific_evidence_schema_version,
            "scientific_evidence_rule_id": sealed_evidence_rule_id,
            "plan_digest": state.plan_digest,
            "terminal_index_digest": state.terminal_index_digest,
            "scientific_evidence_digest": digest,
            "candidate_bindings": [
                {
                    "candidate_id": candidate["candidate_id"],
                    "final_status": candidate["final_status"],
                }
                for candidate in candidate_records
            ],
            "science_completion_gate": preimage["science_completion_gate"],
        }
        ledger_receipt_digest = structured_sha256(
            _science_ledger_receipt_digest_domain,
            ledger_receipt_preimage,
        )
        return _derived_scientific_projection_type(
            canonical_projection_bytes=canonical_json_bytes(
                {
                    **preimage,
                    "scientific_evidence_digest": digest,
                }
            ),
            evidence_digest=digest,
            ledger_receipt_canonical_bytes=canonical_json_bytes(
                {
                    **ledger_receipt_preimage,
                    "receipt_digest": ledger_receipt_digest,
                }
            ),
            ledger_receipt_digest=ledger_receipt_digest,
            candidate_preimage_bytes=tuple(candidate_preimage_bytes),
            candidate_canonical_bytes=tuple(candidate_canonical_bytes),
            candidate_record_digests=tuple(candidate_record_digests),
            attempt_preimage_bytes=attempt_preimage_bytes,
            attempt_canonical_bytes=attempt_canonical_bytes,
            attempt_digests=attempt_digests,
            numeric_preimage_bytes=numeric_preimage_bytes,
            numeric_canonical_bytes=numeric_canonical_bytes,
            numeric_digests=numeric_digests,
            aggregate_preimage_bytes=aggregate_preimage_bytes,
            aggregate_canonical_bytes=aggregate_canonical_bytes,
            aggregate_digests=aggregate_digests,
            stage_comparison_private_canonical_bytes=(stage_comparison_private_canonical_bytes),
            stage_comparison_private_digests=stage_comparison_private_digests,
            analyst_layer_preimage_bytes=analyst_layer_preimage_bytes,
            analyst_layer_canonical_bytes=analyst_layer_canonical_bytes,
            analyst_layer_digest=analyst_layer_digest,
            sampling_attempt_preimage_bytes=sampling_attempt_preimage_bytes,
            sampling_attempt_canonical_bytes=sampling_attempt_canonical_bytes,
            sampling_attempt_digests=sampling_attempt_digests,
            sampling_numeric_preimage_bytes=sampling_numeric_preimage_bytes,
            sampling_numeric_canonical_bytes=sampling_numeric_canonical_bytes,
            sampling_numeric_digests=sampling_numeric_digests,
            sampling_aggregate_preimage_bytes=sampling_aggregate_preimage_bytes,
            sampling_aggregate_canonical_bytes=sampling_aggregate_canonical_bytes,
            sampling_aggregate_digests=sampling_aggregate_digests,
            sampling_layer_preimage_bytes=sampling_layer_preimage_bytes,
            sampling_layer_canonical_bytes=sampling_layer_canonical_bytes,
            sampling_layer_digest=sampling_layer_digest,
            influence_attempt_preimage_bytes=influence_attempt_preimage_bytes,
            influence_attempt_canonical_bytes=influence_attempt_canonical_bytes,
            influence_attempt_digests=influence_attempt_digests,
            influence_layer_preimage_bytes=influence_layer_preimage_bytes,
            influence_layer_canonical_bytes=influence_layer_canonical_bytes,
            influence_layer_digest=influence_layer_digest,
            null_layer_preimage_bytes=null_layer_preimage_bytes,
            null_layer_canonical_bytes=null_layer_canonical_bytes,
            null_layer_digest=null_layer_digest,
        )

    def validate_sealed_projection(
        state: _SealedScientificEvidenceState,
        /,
    ) -> dict[str, object]:
        projection = strict_json_loads(state.canonical_projection_bytes)
        expected_projection_keys = {
            "scientific_evidence_schema_version",
            "evidence_rule_id",
            "plan_digest",
            "terminal_index_digest",
            "synthetic_case_binding",
            "influence_preparation_bindings_digest",
            "position_summary_rule",
            "chain_top_k_rule",
            "matrix_cross_check_tolerance_rule",
            "uncertainty_layer_coverage",
            "science_completion_gate",
            "candidate_records",
            "sampling_evidence",
            "analyst_decision_evidence",
            "participant_influence_evidence",
            "null_evidence",
            "scientific_evidence_digest",
        }
        if (
            type(projection) is not dict
            or set(projection) != expected_projection_keys
            or canonical_json_bytes(projection) != state.canonical_projection_bytes
            or type(state.ledger_receipt_canonical_bytes) is not bytes
            or type(state.ledger_receipt_digest) is not str
            or projection.get("scientific_evidence_digest") != state.evidence_digest
            or projection.get("scientific_evidence_schema_version")
            != scientific_evidence_schema_version
            or projection.get("evidence_rule_id") != sealed_evidence_rule_id
            or type(projection.get("influence_preparation_bindings_digest")) is not str
            or type(projection.get("candidate_records")) is not list
            or type(projection.get("sampling_evidence")) is not dict
            or type(projection.get("analyst_decision_evidence")) is not dict
            or type(projection.get("participant_influence_evidence")) is not dict
            or type(projection.get("null_evidence")) is not dict
        ):
            raise _scientific_evidence_error_type(
                "Sealed scientific evidence projection is invalid."
            )
        synthetic_case_binding = projection["synthetic_case_binding"]
        if synthetic_case_binding is not None and (
            type(synthetic_case_binding) is not dict
            or set(synthetic_case_binding)
            != {
                "case_id",
                "source_contract_sha256",
                "scenario_definitions_sha256",
            }
            or any(type(value) is not str for value in synthetic_case_binding.values())
        ):
            raise _scientific_evidence_error_type("Sealed synthetic case binding is invalid.")
        candidate_records = _cast(list[object], projection["candidate_records"])
        if not (
            len(candidate_records)
            == len(state.candidate_preimage_bytes)
            == len(state.candidate_canonical_bytes)
            == len(state.candidate_record_digests)
            == state.candidate_count
        ):
            raise _scientific_evidence_error_type(
                "Sealed scientific evidence projection is invalid."
            )
        exact_candidate_records: list[dict[str, object]] = []
        for projected, preimage_bytes, canonical_bytes, retained_digest in zip(
            candidate_records,
            state.candidate_preimage_bytes,
            state.candidate_canonical_bytes,
            state.candidate_record_digests,
            strict=True,
        ):
            if (
                type(projected) is not dict
                or type(preimage_bytes) is not bytes
                or type(canonical_bytes) is not bytes
                or type(retained_digest) is not str
                or canonical_json_bytes(projected) != canonical_bytes
            ):
                raise _scientific_evidence_error_type(
                    "Sealed scientific evidence candidate record is invalid."
                )
            retained_preimage = strict_json_loads(preimage_bytes)
            retained_record = strict_json_loads(canonical_bytes)
            if (
                type(retained_preimage) is not dict
                or type(retained_record) is not dict
                or canonical_json_bytes(retained_preimage) != preimage_bytes
                or canonical_json_bytes(retained_record) != canonical_bytes
                or retained_record != projected
            ):
                raise _scientific_evidence_error_type(
                    "Sealed scientific evidence candidate record is invalid."
                )
            supplied_digest = retained_record.get("record_digest")
            record_preimage = dict(retained_record)
            if "record_digest" not in record_preimage:
                raise _scientific_evidence_error_type(
                    "Sealed scientific evidence candidate record is invalid."
                )
            del record_preimage["record_digest"]
            expected_digest = structured_sha256(
                "ebm-audit/scientific-candidate-evidence/1",
                retained_preimage,
            )
            if (
                record_preimage != retained_preimage
                or canonical_json_bytes(record_preimage) != preimage_bytes
                or retained_preimage.get("evidence_rule_id") != candidate_evidence_rule_id
                or supplied_digest != expected_digest
                or retained_digest != expected_digest
            ):
                raise _scientific_evidence_error_type(
                    "Sealed scientific evidence candidate record is invalid."
                )
            exact_candidate_records.append(_cast(dict[str, object], retained_record))
        retained_bundle = canonical_analyst_bundle_type(
            attempts=tuple(
                canonical_origin_attempt_type(
                    preimage_bytes=preimage,
                    canonical_bytes=canonical,
                    attempt_digest=digest,
                )
                for preimage, canonical, digest in zip(
                    state.attempt_preimage_bytes,
                    state.attempt_canonical_bytes,
                    state.attempt_digests,
                    strict=True,
                )
            ),
            numeric_records=tuple(
                canonical_numeric_comparison_type(
                    preimage_bytes=preimage,
                    canonical_bytes=canonical,
                    numeric_comparison_digest=digest,
                )
                for preimage, canonical, digest in zip(
                    state.numeric_preimage_bytes,
                    state.numeric_canonical_bytes,
                    state.numeric_digests,
                    strict=True,
                )
            ),
            aggregates=tuple(
                canonical_analyst_aggregate_type(
                    preimage_bytes=preimage,
                    canonical_bytes=canonical,
                    aggregate_digest=digest,
                )
                for preimage, canonical, digest in zip(
                    state.aggregate_preimage_bytes,
                    state.aggregate_canonical_bytes,
                    state.aggregate_digests,
                    strict=True,
                )
            ),
            layer=canonical_analyst_layer_type(
                preimage_bytes=state.analyst_layer_preimage_bytes,
                canonical_bytes=state.analyst_layer_canonical_bytes,
                layer_digest=state.analyst_layer_digest,
            ),
        )
        (
            exact_analyst_layer,
            attempt_preimages,
            attempt_canonical,
            attempt_digests,
            numeric_preimages,
            numeric_canonical,
            numeric_digests,
            aggregate_preimages,
            aggregate_canonical,
            aggregate_digests,
            layer_preimage,
            layer_canonical,
            layer_digest,
        ) = validate_analyst_bundle(retained_bundle)
        retained_sampling_bundle = canonical_sampling_bundle_type(
            attempts=tuple(
                canonical_sampling_attempt_type(
                    preimage_bytes=preimage,
                    canonical_bytes=canonical,
                    attempt_digest=digest,
                )
                for preimage, canonical, digest in zip(
                    state.sampling_attempt_preimage_bytes,
                    state.sampling_attempt_canonical_bytes,
                    state.sampling_attempt_digests,
                    strict=True,
                )
            ),
            numeric_records=tuple(
                canonical_sampling_numeric_type(
                    preimage_bytes=preimage,
                    canonical_bytes=canonical,
                    numeric_comparison_digest=digest,
                )
                for preimage, canonical, digest in zip(
                    state.sampling_numeric_preimage_bytes,
                    state.sampling_numeric_canonical_bytes,
                    state.sampling_numeric_digests,
                    strict=True,
                )
            ),
            aggregates=tuple(
                canonical_sampling_aggregate_type(
                    preimage_bytes=preimage,
                    canonical_bytes=canonical,
                    aggregate_digest=digest,
                )
                for preimage, canonical, digest in zip(
                    state.sampling_aggregate_preimage_bytes,
                    state.sampling_aggregate_canonical_bytes,
                    state.sampling_aggregate_digests,
                    strict=True,
                )
            ),
            layer=canonical_sampling_layer_type(
                preimage_bytes=state.sampling_layer_preimage_bytes,
                canonical_bytes=state.sampling_layer_canonical_bytes,
                layer_digest=state.sampling_layer_digest,
            ),
        )
        (
            exact_sampling_layer,
            sampling_attempt_preimages,
            sampling_attempt_canonical,
            sampling_attempt_digests,
            sampling_numeric_preimages,
            sampling_numeric_canonical,
            sampling_numeric_digests,
            sampling_aggregate_preimages,
            sampling_aggregate_canonical,
            sampling_aggregate_digests,
            sampling_layer_preimage,
            sampling_layer_canonical,
            sampling_layer_digest,
        ) = validate_sampling_bundle(retained_sampling_bundle)
        retained_influence_bundle = canonical_influence_bundle_type(
            attempts=tuple(
                canonical_influence_attempt_type(
                    preimage_bytes=preimage,
                    canonical_bytes=canonical,
                    attempt_digest=digest,
                )
                for preimage, canonical, digest in zip(
                    state.influence_attempt_preimage_bytes,
                    state.influence_attempt_canonical_bytes,
                    state.influence_attempt_digests,
                    strict=True,
                )
            ),
            layer=canonical_influence_layer_type(
                preimage_bytes=state.influence_layer_preimage_bytes,
                canonical_bytes=state.influence_layer_canonical_bytes,
                layer_digest=state.influence_layer_digest,
            ),
        )
        (
            exact_influence_layer,
            influence_attempt_preimages,
            influence_attempt_canonical,
            influence_attempt_digests,
            influence_layer_preimage,
            influence_layer_canonical,
            influence_layer_digest,
        ) = validate_influence_bundle(retained_influence_bundle)
        (
            exact_null_layer,
            null_layer_preimage,
            null_layer_canonical,
            null_layer_digest,
        ) = validate_null_layer(
            canonical_null_layer_type(
                preimage_bytes=state.null_layer_preimage_bytes,
                canonical_bytes=state.null_layer_canonical_bytes,
                layer_digest=state.null_layer_digest,
            )
        )
        private_stage_bytes = state.stage_comparison_private_canonical_bytes
        private_stage_digests = state.stage_comparison_private_digests
        if len(private_stage_bytes) != len(private_stage_digests):
            raise _scientific_evidence_error_type(
                "Sealed private participant-stage evidence is invalid."
            )
        for private_bytes, retained_digest in zip(
            private_stage_bytes,
            private_stage_digests,
            strict=True,
        ):
            try:
                private_record = strict_json_loads(private_bytes)
            except (TypeError, ValueError):
                raise _scientific_evidence_error_type(
                    "Sealed private participant-stage evidence is invalid."
                ) from None
            private_preimage = dict(private_record) if type(private_record) is dict else {}
            supplied_digest = private_preimage.pop(
                "private_evidence_digest",
                None,
            )
            if (
                type(private_bytes) is not bytes
                or type(retained_digest) is not str
                or type(private_record) is not dict
                or canonical_json_bytes(private_record) != private_bytes
                or supplied_digest != retained_digest
                or structured_sha256(
                    _private_stage_comparison_digest_domain,
                    private_preimage,
                )
                != retained_digest
            ):
                raise _scientific_evidence_error_type(
                    "Sealed private participant-stage evidence is invalid."
                )
        public_stage_digests = [
            stage.get("private_evidence_digest")
            for stage_layer in (exact_analyst_layer, exact_sampling_layer)
            for numeric in _cast(list[dict[str, object]], stage_layer["numeric_records"])
            for stage in [
                _cast(
                    dict[str, object],
                    numeric["participant_stage_comparison"],
                )
            ]
        ]
        retained_stage_counts = _counter_type(private_stage_digests)
        public_stage_counts = _counter_type(public_stage_digests)
        if (
            any(type(digest) is not str for digest in public_stage_digests)
            or retained_stage_counts != public_stage_counts
        ):
            raise _scientific_evidence_error_type(
                "Sealed private participant-stage evidence is detached."
            )
        if (
            attempt_preimages != state.attempt_preimage_bytes
            or attempt_canonical != state.attempt_canonical_bytes
            or attempt_digests != state.attempt_digests
            or numeric_preimages != state.numeric_preimage_bytes
            or numeric_canonical != state.numeric_canonical_bytes
            or numeric_digests != state.numeric_digests
            or aggregate_preimages != state.aggregate_preimage_bytes
            or aggregate_canonical != state.aggregate_canonical_bytes
            or aggregate_digests != state.aggregate_digests
            or layer_preimage != state.analyst_layer_preimage_bytes
            or layer_canonical != state.analyst_layer_canonical_bytes
            or layer_digest != state.analyst_layer_digest
            or projection["analyst_decision_evidence"] != exact_analyst_layer
            or sampling_attempt_preimages != state.sampling_attempt_preimage_bytes
            or sampling_attempt_canonical != state.sampling_attempt_canonical_bytes
            or sampling_attempt_digests != state.sampling_attempt_digests
            or sampling_numeric_preimages != state.sampling_numeric_preimage_bytes
            or sampling_numeric_canonical != state.sampling_numeric_canonical_bytes
            or sampling_numeric_digests != state.sampling_numeric_digests
            or sampling_aggregate_preimages != state.sampling_aggregate_preimage_bytes
            or sampling_aggregate_canonical != state.sampling_aggregate_canonical_bytes
            or sampling_aggregate_digests != state.sampling_aggregate_digests
            or sampling_layer_preimage != state.sampling_layer_preimage_bytes
            or sampling_layer_canonical != state.sampling_layer_canonical_bytes
            or sampling_layer_digest != state.sampling_layer_digest
            or projection["sampling_evidence"] != exact_sampling_layer
            or influence_attempt_preimages != state.influence_attempt_preimage_bytes
            or influence_attempt_canonical != state.influence_attempt_canonical_bytes
            or influence_attempt_digests != state.influence_attempt_digests
            or influence_layer_preimage != state.influence_layer_preimage_bytes
            or influence_layer_canonical != state.influence_layer_canonical_bytes
            or influence_layer_digest != state.influence_layer_digest
            or projection["participant_influence_evidence"] != exact_influence_layer
            or null_layer_preimage != state.null_layer_preimage_bytes
            or null_layer_canonical != state.null_layer_canonical_bytes
            or null_layer_digest != state.null_layer_digest
            or projection["null_evidence"] != exact_null_layer
            or projection.get("uncertainty_layer_coverage")
            != uncertainty_layer_coverage(
                tuple(exact_candidate_records),
                exact_sampling_layer,
                exact_analyst_layer,
                exact_influence_layer,
                exact_null_layer,
            )
        ):
            raise _scientific_evidence_error_type(
                "Sealed scientific evidence layer coverage is invalid."
            )
        if projection.get("matrix_cross_check_tolerance_rule") != (cross_check_tolerance_rule()):
            raise _scientific_evidence_error_type(
                "Sealed scientific evidence tolerance rule is invalid."
            )
        outer_preimage = dict(projection)
        if "scientific_evidence_digest" not in outer_preimage:
            raise _scientific_evidence_error_type(
                "Sealed scientific evidence projection is invalid."
            )
        del outer_preimage["scientific_evidence_digest"]
        expected_outer_digest = structured_sha256(
            "ebm-audit/sealed-scientific-evidence/10",
            outer_preimage,
        )
        if expected_outer_digest != state.evidence_digest:
            raise _scientific_evidence_error_type(
                "Sealed scientific evidence projection is invalid."
            )
        exact_projection: dict[str, object] = {}
        for key, item in projection.items():
            if type(key) is not str:
                raise _scientific_evidence_error_type(
                    "Sealed scientific evidence projection is invalid."
                )
            exact_projection[key] = item
        return exact_projection

    def read_sealed_scientific_evidence(
        value: object,
        /,
        *,
        _leased_state: Any = _leased_sealed_scientific_evidence_state,
    ) -> _SealedScientificEvidenceState:
        if type(value) is not _sealed_scientific_evidence_type:
            raise _scientific_evidence_error_type("Genuine sealed scientific evidence is required.")
        leased_state = _leased_state(value)
        if type(leased_state) is _sealed_scientific_evidence_state_type:
            return leased_state
        try:
            state = evidence_state_registry[value]
        except (KeyError, TypeError):
            raise _scientific_evidence_error_type(
                "Genuine sealed scientific evidence is required."
            ) from None
        if type(state) is not _sealed_scientific_evidence_state_type:
            raise _scientific_evidence_error_type("Genuine sealed scientific evidence is required.")
        if live_evidence.get(state.capture) is not value:
            raise _scientific_evidence_error_type(
                "Sealed scientific evidence is not the canonical live object."
            )
        captured_state = read_captured_scientific_run(state.capture)
        if live_evidence.get(state.capture) is not value:
            raise _scientific_evidence_error_type(
                "Sealed scientific evidence is not the canonical live object."
            )
        rederived = derive_projection(captured_state)
        if (
            rederived.canonical_projection_bytes != state.canonical_projection_bytes
            or rederived.evidence_digest != state.evidence_digest
            or rederived.ledger_receipt_canonical_bytes != state.ledger_receipt_canonical_bytes
            or rederived.ledger_receipt_digest != state.ledger_receipt_digest
            or rederived.candidate_preimage_bytes != state.candidate_preimage_bytes
            or rederived.candidate_canonical_bytes != state.candidate_canonical_bytes
            or rederived.candidate_record_digests != state.candidate_record_digests
            or rederived.attempt_preimage_bytes != state.attempt_preimage_bytes
            or rederived.attempt_canonical_bytes != state.attempt_canonical_bytes
            or rederived.attempt_digests != state.attempt_digests
            or rederived.numeric_preimage_bytes != state.numeric_preimage_bytes
            or rederived.numeric_canonical_bytes != state.numeric_canonical_bytes
            or rederived.numeric_digests != state.numeric_digests
            or rederived.aggregate_preimage_bytes != state.aggregate_preimage_bytes
            or rederived.aggregate_canonical_bytes != state.aggregate_canonical_bytes
            or rederived.aggregate_digests != state.aggregate_digests
            or rederived.stage_comparison_private_canonical_bytes
            != state.stage_comparison_private_canonical_bytes
            or rederived.stage_comparison_private_digests != state.stage_comparison_private_digests
            or rederived.analyst_layer_preimage_bytes != state.analyst_layer_preimage_bytes
            or rederived.analyst_layer_canonical_bytes != state.analyst_layer_canonical_bytes
            or rederived.analyst_layer_digest != state.analyst_layer_digest
            or rederived.sampling_attempt_preimage_bytes != state.sampling_attempt_preimage_bytes
            or rederived.sampling_attempt_canonical_bytes != state.sampling_attempt_canonical_bytes
            or rederived.sampling_attempt_digests != state.sampling_attempt_digests
            or rederived.sampling_numeric_preimage_bytes != state.sampling_numeric_preimage_bytes
            or rederived.sampling_numeric_canonical_bytes != state.sampling_numeric_canonical_bytes
            or rederived.sampling_numeric_digests != state.sampling_numeric_digests
            or rederived.sampling_aggregate_preimage_bytes
            != state.sampling_aggregate_preimage_bytes
            or rederived.sampling_aggregate_canonical_bytes
            != state.sampling_aggregate_canonical_bytes
            or rederived.sampling_aggregate_digests != state.sampling_aggregate_digests
            or rederived.sampling_layer_preimage_bytes != state.sampling_layer_preimage_bytes
            or rederived.sampling_layer_canonical_bytes != state.sampling_layer_canonical_bytes
            or rederived.sampling_layer_digest != state.sampling_layer_digest
            or rederived.influence_attempt_preimage_bytes != state.influence_attempt_preimage_bytes
            or rederived.influence_attempt_canonical_bytes
            != state.influence_attempt_canonical_bytes
            or rederived.influence_attempt_digests != state.influence_attempt_digests
            or rederived.influence_layer_preimage_bytes != state.influence_layer_preimage_bytes
            or rederived.influence_layer_canonical_bytes != state.influence_layer_canonical_bytes
            or rederived.influence_layer_digest != state.influence_layer_digest
            or rederived.null_layer_preimage_bytes != state.null_layer_preimage_bytes
            or rederived.null_layer_canonical_bytes != state.null_layer_canonical_bytes
            or rederived.null_layer_digest != state.null_layer_digest
        ):
            raise _scientific_evidence_error_type(
                "Sealed scientific evidence no longer matches its live source."
            )
        validate_sealed_projection(state)
        _require_scientific_ledger_receipt(
            value,
            captured_state.sealed_result_evidence_set,
            state.ledger_receipt_canonical_bytes,
            state.ledger_receipt_digest,
        )
        return state

    def try_seal_scientific_evidence(
        captured_scientific_run: CapturedScientificRun,
        /,
    ) -> tuple[object, SealedScientificEvidence] | object | _SanitizedScientificControlFlow:
        try:
            assert_science_dependencies_current()
            if type(captured_scientific_run) is not _captured_scientific_run_type:
                return scientific_failure
            existing = live_evidence.get(captured_scientific_run)
            if existing is None:
                with _CAPTURE_LOCK:
                    existing = live_evidence.get(captured_scientific_run)
                    if existing is None:
                        captured_state = read_captured_scientific_run(captured_scientific_run)
                        derived = derive_projection(captured_state)
                        evidence = object.__new__(_sealed_scientific_evidence_type)
                        evidence_state = _sealed_scientific_evidence_state_type(
                            capture=captured_scientific_run,
                            canonical_projection_bytes=derived.canonical_projection_bytes,
                            ledger_receipt_canonical_bytes=(derived.ledger_receipt_canonical_bytes),
                            ledger_receipt_digest=derived.ledger_receipt_digest,
                            candidate_preimage_bytes=derived.candidate_preimage_bytes,
                            candidate_canonical_bytes=derived.candidate_canonical_bytes,
                            candidate_record_digests=derived.candidate_record_digests,
                            attempt_preimage_bytes=derived.attempt_preimage_bytes,
                            attempt_canonical_bytes=derived.attempt_canonical_bytes,
                            attempt_digests=derived.attempt_digests,
                            numeric_preimage_bytes=derived.numeric_preimage_bytes,
                            numeric_canonical_bytes=derived.numeric_canonical_bytes,
                            numeric_digests=derived.numeric_digests,
                            aggregate_preimage_bytes=derived.aggregate_preimage_bytes,
                            aggregate_canonical_bytes=derived.aggregate_canonical_bytes,
                            aggregate_digests=derived.aggregate_digests,
                            stage_comparison_private_canonical_bytes=(
                                derived.stage_comparison_private_canonical_bytes
                            ),
                            stage_comparison_private_digests=(
                                derived.stage_comparison_private_digests
                            ),
                            analyst_layer_preimage_bytes=(derived.analyst_layer_preimage_bytes),
                            analyst_layer_canonical_bytes=(derived.analyst_layer_canonical_bytes),
                            analyst_layer_digest=derived.analyst_layer_digest,
                            sampling_attempt_preimage_bytes=(
                                derived.sampling_attempt_preimage_bytes
                            ),
                            sampling_attempt_canonical_bytes=(
                                derived.sampling_attempt_canonical_bytes
                            ),
                            sampling_attempt_digests=derived.sampling_attempt_digests,
                            sampling_numeric_preimage_bytes=(
                                derived.sampling_numeric_preimage_bytes
                            ),
                            sampling_numeric_canonical_bytes=(
                                derived.sampling_numeric_canonical_bytes
                            ),
                            sampling_numeric_digests=derived.sampling_numeric_digests,
                            sampling_aggregate_preimage_bytes=(
                                derived.sampling_aggregate_preimage_bytes
                            ),
                            sampling_aggregate_canonical_bytes=(
                                derived.sampling_aggregate_canonical_bytes
                            ),
                            sampling_aggregate_digests=derived.sampling_aggregate_digests,
                            sampling_layer_preimage_bytes=(derived.sampling_layer_preimage_bytes),
                            sampling_layer_canonical_bytes=(derived.sampling_layer_canonical_bytes),
                            sampling_layer_digest=derived.sampling_layer_digest,
                            influence_attempt_preimage_bytes=(
                                derived.influence_attempt_preimage_bytes
                            ),
                            influence_attempt_canonical_bytes=(
                                derived.influence_attempt_canonical_bytes
                            ),
                            influence_attempt_digests=(derived.influence_attempt_digests),
                            influence_layer_preimage_bytes=(derived.influence_layer_preimage_bytes),
                            influence_layer_canonical_bytes=(
                                derived.influence_layer_canonical_bytes
                            ),
                            influence_layer_digest=derived.influence_layer_digest,
                            null_layer_preimage_bytes=derived.null_layer_preimage_bytes,
                            null_layer_canonical_bytes=derived.null_layer_canonical_bytes,
                            null_layer_digest=derived.null_layer_digest,
                            evidence_digest=derived.evidence_digest,
                            candidate_count=len(captured_state.candidates),
                        )
                        validate_sealed_projection(evidence_state)
                        assert_science_dependencies_current()
                        evidence_state_issuer.bind_once(evidence, evidence_state)
                        _issue_scientific_ledger_receipt(
                            evidence,
                            captured_state.sealed_result_evidence_set,
                            evidence_state.ledger_receipt_canonical_bytes,
                            evidence_state.ledger_receipt_digest,
                        )
                        live_evidence.bind_once(captured_scientific_run, evidence)
                        assert_science_dependencies_current()
                        return seal_success, evidence
            if existing is None:
                return scientific_failure
            state = read_sealed_scientific_evidence(existing)
            if state.capture is not captured_scientific_run:
                return scientific_failure
            captured_state = read_captured_scientific_run(captured_scientific_run)
            _require_scientific_ledger_receipt(
                existing,
                captured_state.sealed_result_evidence_set,
                state.ledger_receipt_canonical_bytes,
                state.ledger_receipt_digest,
            )
            assert_science_dependencies_current()
            return seal_success, existing
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                return _SanitizedScientificControlFlow("keyboard_interrupt")
            if type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                return _SanitizedScientificControlFlow(
                    "system_exit",
                    safe_exit_code,
                )
            if type(stopped) is GeneratorExit:
                return _SanitizedScientificControlFlow("generator_exit")
            return scientific_failure

    def seal_scientific_evidence(
        captured_scientific_run: CapturedScientificRun,
        /,
    ) -> SealedScientificEvidence:
        """Issue one canonical evidence object from one exact current capture."""

        try:
            outcome: (
                tuple[object, SealedScientificEvidence] | object | _SanitizedScientificControlFlow
            ) = try_seal_scientific_evidence(captured_scientific_run)
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                outcome = _SanitizedScientificControlFlow("keyboard_interrupt")
            elif type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                outcome = _SanitizedScientificControlFlow(
                    "system_exit",
                    safe_exit_code,
                )
                del stopped_code
            elif type(stopped) is GeneratorExit:
                outcome = _SanitizedScientificControlFlow("generator_exit")
            else:
                outcome = scientific_failure
        finally:
            del captured_scientific_run
        if type(outcome) is _SanitizedScientificControlFlow:
            sanitized_outcome = _cast(_any_type_marker, outcome)
            if sanitized_outcome.kind == "keyboard_interrupt":
                raise KeyboardInterrupt
            if sanitized_outcome.kind == "system_exit":
                raise SystemExit(sanitized_outcome.exit_code)
            raise GeneratorExit
        if (
            type(outcome) is tuple
            and len(outcome) == 2
            and outcome[0] is seal_success
            and type(outcome[1]) is _sealed_scientific_evidence_type
        ):
            return outcome[1]
        del outcome
        raise _scientific_evidence_error_type(
            "Scientific evidence derivation failed integrity validation."
        )

    def try_project_scientific_evidence(
        sealed_scientific_evidence: SealedScientificEvidence,
        /,
    ) -> tuple[object, dict[str, object]] | object | _SanitizedScientificControlFlow:
        try:
            assert_science_dependencies_current()
            state = read_sealed_scientific_evidence(sealed_scientific_evidence)
            projection = strict_json_loads(state.canonical_projection_bytes)
            if type(projection) is not dict:
                return scientific_failure
            assert_science_dependencies_current()
            return projection_success, _cast(dict[str, object], projection)
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                return _SanitizedScientificControlFlow("keyboard_interrupt")
            if type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                return _SanitizedScientificControlFlow(
                    "system_exit",
                    safe_exit_code,
                )
            if type(stopped) is GeneratorExit:
                return _SanitizedScientificControlFlow("generator_exit")
            return scientific_failure

    def project_scientific_evidence(
        sealed_scientific_evidence: SealedScientificEvidence,
        /,
    ) -> dict[str, object]:
        """Return a fresh privacy-safe deterministic aggregate projection."""

        try:
            outcome: tuple[object, dict[str, object]] | object | _SanitizedScientificControlFlow = (
                try_project_scientific_evidence(sealed_scientific_evidence)
            )
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                outcome = _SanitizedScientificControlFlow("keyboard_interrupt")
            elif type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                outcome = _SanitizedScientificControlFlow(
                    "system_exit",
                    safe_exit_code,
                )
                del stopped_code
            elif type(stopped) is GeneratorExit:
                outcome = _SanitizedScientificControlFlow("generator_exit")
            else:
                outcome = scientific_failure
        finally:
            del sealed_scientific_evidence
        if type(outcome) is _SanitizedScientificControlFlow:
            sanitized_outcome = _cast(_any_type_marker, outcome)
            if sanitized_outcome.kind == "keyboard_interrupt":
                raise KeyboardInterrupt
            if sanitized_outcome.kind == "system_exit":
                raise SystemExit(sanitized_outcome.exit_code)
            raise GeneratorExit
        if (
            type(outcome) is tuple
            and len(outcome) == 2
            and outcome[0] is projection_success
            and type(outcome[1]) is dict
        ):
            return outcome[1]
        del outcome
        raise _scientific_evidence_error_type(
            "Scientific evidence projection failed integrity validation."
        )

    def read_private_stage_comparison_evidence(
        sealed_scientific_evidence: SealedScientificEvidence,
        /,
    ) -> tuple[tuple[bytes, str], ...]:
        """Internal private-store handoff from one genuine revalidated capability."""

        assert_science_dependencies_current()
        state = read_sealed_scientific_evidence(sealed_scientific_evidence)
        assert_science_dependencies_current()
        return tuple(
            (private_bytes, digest)
            for private_bytes, digest in zip(
                state.stage_comparison_private_canonical_bytes,
                state.stage_comparison_private_digests,
                strict=True,
            )
        )

    capture_helper_dependencies_current = _build_dependency_guard(
        (
            _captured_synthetic_case_binding_bytes,
            _capture_public_synthetic_preparation_binding.__code__,
            candidate_origins,
            closed_mapping_bytes,
            _require_captured_synthetic_case_binding,
            _validated_synthetic_case_binding,
        )
    )
    candidate_rule_dependencies_current = _build_dependency_guard(
        (
            derive_candidate_evidence_record,
            _counter_type.__init__,
            _counter_type.update,
        )
    )
    convergence_dependencies_current = _build_dependency_guard((derive_convergence,))
    evidence_summary_dependencies_current = _build_dependency_guard(
        (cross_check_tolerance_rule, uncertainty_layer_coverage)
    )
    canonical_dependencies_current = _build_dependency_guard(
        (
            canonical_json_bytes,
            strict_json_loads,
            structured_sha256,
        )
    )
    capture_type_dependencies_current = _build_dependency_guard(
        (
            canonical_candidate_evidence_record_type,
            canonical_origin_attempt_type,
            canonical_numeric_comparison_type,
            canonical_analyst_aggregate_type,
            canonical_analyst_layer_type,
            canonical_analyst_bundle_type,
            canonical_sampling_attempt_type,
            canonical_sampling_numeric_type,
            canonical_sampling_aggregate_type,
            canonical_sampling_layer_type,
            canonical_sampling_bundle_type,
            canonical_influence_attempt_type,
            canonical_influence_layer_type,
            canonical_influence_bundle_type,
            canonical_null_layer_type,
            chain_evidence_input_type,
            analyst_candidate_input_type,
            analyst_origin_input_type,
            stage_comparison_side_input_type,
            derived_stage_comparison_type,
            sampling_candidate_input_type,
            sampling_origin_input_type,
            influence_candidate_input_type,
            influence_origin_input_type,
            null_candidate_input_type,
            _captured_scientific_run_state_type,
            _captured_scientific_run_type,
            _derived_scientific_projection_type,
            _sealed_scientific_evidence_state_type,
            _sealed_scientific_evidence_type,
        )
    )
    validator_dependency_roots, assert_validator_configuration_current = (
        validator_dependency_manifest()
    )
    validator_dependencies_current = _build_dependency_guard(validator_dependency_roots)

    def assert_science_dependencies_current() -> None:
        _analyst_dependencies_current()
        _sampling_dependencies_current()
        _influence_dependencies_current()
        _null_dependencies_current()
        _stage_dependencies_current()
        capture_helper_dependencies_current()
        candidate_rule_dependencies_current()
        convergence_dependencies_current()
        evidence_summary_dependencies_current()
        canonical_dependencies_current()
        capture_type_dependencies_current()
        assert_validator_configuration_current()
        validator_dependencies_current()

    assert_science_dependencies_current()

    return (
        capture_summary,
        capture_scientific_run,
        seal_scientific_evidence,
        project_scientific_evidence,
        read_private_stage_comparison_evidence,
        read_captured_scientific_run,
        read_sealed_scientific_evidence,
    )


(
    capture_summary,
    capture_scientific_run,
    seal_scientific_evidence,
    project_scientific_evidence,
    _read_private_stage_comparison_evidence,
    _read_captured_scientific_run,
    _read_sealed_scientific_evidence,
) = _build_scientific_evidence_boundary()


@contextmanager
def _scientific_evidence_read_scope(
    capture: object,
    evidence: object,
    *,
    _read_capture: Callable[[object], object] = _read_captured_scientific_run,
    _read_evidence: Callable[[object], object] = _read_sealed_scientific_evidence,
) -> Iterator[None]:
    """Reuse one authenticated science pair only inside one live transaction."""

    active_leases = _ACTIVE_SCIENTIFIC_EVIDENCE_READS.get()
    for lease in reversed(active_leases):
        with lease.lock:
            reuses_active_lease = (
                lease.active
                and lease.capture_owner is capture
                and lease.evidence_owner is evidence
                and type(lease.capture_state) is _CapturedScientificRunState
                and type(lease.evidence_state) is _SealedScientificEvidenceState
            )
        if reuses_active_lease:
            yield
            return

    captured_state = _read_capture(capture)
    retained_leases: list[_ScientificEvidenceReadLease] = []
    for lease in active_leases:
        with lease.lock:
            if lease.active:
                retained_leases.append(lease)
    lease = _ScientificEvidenceReadLease(
        active=True,
        capture_owner=capture,
        capture_state=captured_state,
        evidence_owner=None,
        evidence_state=None,
        lock=RLock(),
    )
    token = _ACTIVE_SCIENTIFIC_EVIDENCE_READS.set((*retained_leases, lease))
    try:
        evidence_state = _read_evidence(evidence)
        with lease.lock:
            if not lease.active:
                raise ScientificEvidenceError("Scientific evidence read lease expired.")
            lease.evidence_owner = evidence
            lease.evidence_state = evidence_state
        yield
    finally:
        with lease.lock:
            lease.active = False
            lease.capture_owner = None
            lease.capture_state = None
            lease.evidence_owner = None
            lease.evidence_state = None
        _ACTIVE_SCIENTIFIC_EVIDENCE_READS.reset(token)


def _read_finalized_result_record_digests(
    value: object,
    /,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _capture_finalized_result_state: Callable[[object], _FinalizedResultState] = (
        _capture_finalized_result_state
    ),
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
) -> tuple[tuple[str, str], ...]:
    """Recompute complete core finalized-result digests from a live capture only."""

    state = _read_captured_scientific_run(value)
    digests: list[tuple[str, str]] = []
    for candidate in state.candidates:
        try:
            record = _strict_json_loads(candidate.finalized_record_bytes)
            finalized_state = _capture_finalized_result_state(candidate.finalized_result)
            if (
                type(record) is not dict
                or _canonical_json_bytes(record) != candidate.finalized_record_bytes
                or record.get("result_id") != candidate.result_id
                or finalized_state.canonical_bytes != candidate.finalized_record_bytes
                or finalized_state.result_id != candidate.result_id
            ):
                raise ScientificEvidenceError("Finalized result record is detached.")
            validate_instance(
                record,
                "canonical-records.schema.json",
                definition="ResultRecord",
            )
            digests.append(
                (
                    candidate.candidate_id,
                    structured_sha256_hex("ebm-audit/finalized-result-record/1", record),
                )
            )
        except ScientificEvidenceError:
            raise
        except Exception as error:
            raise ScientificEvidenceError("Finalized result record is invalid.") from error
    return tuple(digests)


def _captured_preparation_projection(
    prepared: object,
    spec: dict[str, object],
    universe: dict[str, object],
    source_instances: list[dict[str, int]],
    data_accounting: object,
) -> dict[str, object]:
    """Return privacy-safe identities for the exact prepared worker input."""

    try:
        validate_instance(
            data_accounting,
            "canonical-records.schema.json",
            definition="DataAccounting",
        )
        event_set = spec.get("event_set")
        if type(event_set) is not list:
            raise ScientificEvidenceError("Captured preparation event axes are invalid.")
        event_ids = [
            row["event_id"]
            for row in event_set
            if type(row) is dict and type(row.get("event_id")) is str
        ]
        if len(event_ids) != len(event_set):
            raise ScientificEvidenceError("Captured preparation event axes are invalid.")
        exact_prepared = cast(Any, prepared)
        source_catalog = exact_prepared.canonical_dataset.view.array_catalog
        missingness = source_catalog.get("missingness_mask")
        group_roles = source_catalog.get("group_role_codes")
        if missingness is None or group_roles is None:
            raise ScientificEvidenceError(
                "Captured preparation source arrays are invalid."
            )
        train_values = exact_prepared.arrays["train_values"]
        train_groups = exact_prepared.arrays["train_group_codes"]

        def array_identity(name: str, array: object) -> str:
            typed = cast(Any, array)
            return structured_sha256_hex(
                "ebm-audit/direct-preparation-array-identity/1",
                {
                    "name": name,
                    "dtype": typed.dtype.name,
                    "shape": list(typed.shape),
                    "values": typed.tolist(),
                },
            )

        axes_sha256 = structured_sha256_hex(
            "ebm-audit/transformation-event-axes/1", event_ids
        )
        source_alignment_sha256 = structured_sha256_hex(
            "ebm-audit/participant-event-alignment/1",
            {"rows": source_instances, "event_ids": event_ids},
        )
        covariates_sha256 = structured_sha256_hex(
            "ebm-audit/transformation-covariates/1",
            spec.get("covariate_adjustment"),
        )
        return {
            "source_scientific_data_sha256": (
                exact_prepared.canonical_dataset.scientific_data_digest.removeprefix(
                    "sha256:"
                )
            ),
            "output_scientific_data_sha256": cast(
                str, universe["training_prepared_data_digest"]
            ).removeprefix("sha256:"),
            "source_axes_sha256": axes_sha256,
            "output_axes_sha256": axes_sha256,
            "source_missingness_sha256": missingness.array_digest.removeprefix(
                "sha256:"
            ),
            "output_missingness_sha256": array_identity(
                "output_missingness", np.isnan(train_values)
            ),
            "source_labels_sha256": group_roles.array_digest.removeprefix("sha256:"),
            "output_labels_sha256": array_identity("output_labels", train_groups),
            "source_covariates_sha256": covariates_sha256,
            "output_covariates_sha256": covariates_sha256,
            "source_participant_event_alignment_sha256": source_alignment_sha256,
            "output_participant_event_alignment_sha256": source_alignment_sha256,
            "data_accounting": data_accounting,
        }
    except ScientificEvidenceError:
        raise
    except Exception as error:
        raise ScientificEvidenceError(
            "Captured preparation projection is invalid."
        ) from error


@dataclass(frozen=True, repr=False, slots=True)
class _CapturedPublicOperationFact:
    """One terminal operation fact revalidated from a live captured run."""

    candidate_ordinal: int
    operation_instance_id: str | None
    analysis_spec_sha256: str
    terminal_status: str
    reason_code: str | None
    backend_invoked: bool
    finalized_result_record_sha256: str
    terminal_record_sha256: str
    fit_response_binding_sha256: str | None
    canonical_payload_fact_bytes: bytes | None
    direct_preparation_fact_bytes: bytes | None


@dataclass(frozen=True, repr=False, slots=True)
class _CapturedPublicOperationProjection:
    """Private capture-authority projection used by ordinary public evidence."""

    captured_run_sha256: str
    plan_digest: str
    terminal_index_digest: str
    synthetic_case_binding: Mapping[str, str]
    operations: tuple[_CapturedPublicOperationFact, ...]
    scientific_evidence_digest: str
    influence_removal_fact_bytes: tuple[bytes, ...]


@final
class CapturedPublicOperationEvidence:
    """Opaque capture authority for ordinary per-operation execution facts."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> CapturedPublicOperationEvidence:
        raise TypeError("Captured public operation evidence is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Captured public operation evidence cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Captured public operation evidence is immutable.")


def _build_captured_public_operation_evidence_boundary() -> tuple[
    Callable[
        [CapturedScientificRun, SealedScientificEvidence],
        CapturedPublicOperationEvidence,
    ],
    Callable[
        [CapturedPublicOperationEvidence],
        tuple[CapturedScientificRun, _CapturedPublicOperationProjection],
    ],
]:
    """Keep capture ownership private while exposing deterministic facts."""

    states: OneShotWeakRegistry[
        CapturedPublicOperationEvidence,
        tuple[
            CapturedScientificRun,
            SealedScientificEvidence,
            _CapturedPublicOperationProjection,
        ],
    ]
    states, issuer = create_one_shot_registry()
    by_capture: OneShotWeakRegistry[CapturedScientificRun, CapturedPublicOperationEvidence]
    by_capture, by_capture_issuer = create_one_shot_registry()

    def project(
        capture: CapturedScientificRun,
        sealed: SealedScientificEvidence,
    ) -> _CapturedPublicOperationProjection:
        state = _read_captured_scientific_run(capture)
        sealed_state = _read_sealed_scientific_evidence(sealed)
        scientific = project_scientific_evidence(sealed)
        influence = scientific.get("participant_influence_evidence")
        if (
            sealed_state.capture is not capture
            or type(scientific.get("scientific_evidence_digest")) is not str
            or type(influence) is not dict
            or influence.get("plan_digest") != state.plan_digest
            or influence.get("terminal_index_digest") != state.terminal_index_digest
            or type(influence.get("attempts")) is not list
        ):
            raise ScientificEvidenceError(
                "Captured public operation scientific authority is invalid."
            )
        try:
            binding = strict_json_loads(state.synthetic_case_binding_bytes or b"")
        except CanonicalizationError as error:
            raise ScientificEvidenceError(
                "Captured public operation case binding is invalid."
            ) from error
        if (
            type(binding) is not dict
            or set(binding)
            != {
                "case_id",
                "source_contract_sha256",
                "scenario_definitions_sha256",
            }
            or any(type(value) is not str or not value for value in binding.values())
        ):
            raise ScientificEvidenceError("Captured public operation case binding is invalid.")
        try:
            transaction = _capture_preparation_transaction_state_identity(
                state.preparation_transaction
            )
            prepared_states = _capture_preparation_transaction_candidate_states(transaction)
            authorizations = transaction.candidate_authorizations
        except Exception as error:
            raise ScientificEvidenceError(
                "Captured public operation preparation authority is invalid."
            ) from error
        if len(prepared_states) != len(state.candidates) or len(authorizations) != len(
            state.candidates
        ):
            raise ScientificEvidenceError(
                "Captured public operation preparation coverage is invalid."
            )
        influence_facts: list[bytes] = []
        seen_influence_slots: set[tuple[str, int]] = set()
        for value in cast(list[object], influence["attempts"]):
            if type(value) is not dict:
                raise ScientificEvidenceError(
                    "Captured public operation influence evidence is invalid."
                )
            attempt = cast(dict[str, object], value)
            removal_analysis_spec_id = attempt.get("removal_analysis_spec_id")
            source_analysis_spec_id = attempt.get("source_analysis_spec_id")
            removal_slot_ordinal = attempt.get("removal_slot_ordinal")
            reason_rows = attempt.get("reason_rows")
            influence_record = attempt.get("influence_record")
            if (
                type(removal_analysis_spec_id) is not str
                or not removal_analysis_spec_id.startswith("sha256:")
                or type(source_analysis_spec_id) is not str
                or not source_analysis_spec_id.startswith("sha256:")
                or type(removal_slot_ordinal) is not int
                or removal_slot_ordinal < 0
                or type(reason_rows) is not list
                or any(
                    type(row) is not dict or type(row.get("reason_code")) is not str
                    for row in reason_rows
                )
                or (influence_record is not None and type(influence_record) is not dict)
            ):
                raise ScientificEvidenceError(
                    "Captured public operation influence evidence is invalid."
                )
            influence_key = (removal_analysis_spec_id, removal_slot_ordinal)
            if influence_key in seen_influence_slots:
                raise ScientificEvidenceError(
                    "Captured public operation influence evidence is duplicated."
                )
            seen_influence_slots.add(influence_key)
            public_record: dict[str, object] | None = None
            if type(influence_record) is dict:
                public_record = {
                    field: influence_record.get(field)
                    for field in (
                        "central_order_kendall_distance",
                        "maximum_normalized_event_rank_displacement",
                        "strict_pairwise_majority_flip_fraction",
                        "position_matrix_distance",
                        "convergence_degradation",
                        "fixed_cohort_stage_wasserstein_median",
                        "fixed_cohort_stage_wasserstein_maximum",
                    )
                }
            influence_facts.append(
                canonical_json_bytes(
                    {
                        "removal_analysis_spec_sha256": removal_analysis_spec_id.removeprefix(
                            "sha256:"
                        ),
                        "source_analysis_spec_sha256": source_analysis_spec_id.removeprefix(
                            "sha256:"
                        ),
                        "removal_slot_ordinal": removal_slot_ordinal,
                        "removal_universe_id": attempt.get("removal_universe_id"),
                        "source_universe_id": attempt.get("source_universe_id"),
                        "removal_terminal_status": attempt.get("removal_terminal_status"),
                        "source_terminal_status": attempt.get("source_terminal_status"),
                        "contribution_state": attempt.get("contribution_state"),
                        "reason_codes": sorted(
                            {
                                cast(str, cast(dict[str, object], row)["reason_code"])
                                for row in reason_rows
                            }
                        ),
                        "component_records": public_record,
                    }
                )
            )

        operations: list[_CapturedPublicOperationFact] = []
        for candidate, authorization, prepared in zip(
            state.candidates, authorizations, prepared_states, strict=True
        ):
            _assert_candidate_current(candidate)
            if _resolve_prepared_execution_authorization(authorization) is not prepared:
                raise ScientificEvidenceError(
                    "Captured public operation preparation authority changed."
                )
            try:
                terminal = strict_json_loads(candidate.terminal_record_bytes)
                finalized = strict_json_loads(candidate.finalized_record_bytes)
            except CanonicalizationError as error:
                raise ScientificEvidenceError(
                    "Captured public operation terminal is invalid."
                ) from error
            body = finalized.get("body") if type(finalized) is dict else None
            reason_code = terminal.get("reason_code") if type(terminal) is dict else None
            if reason_code is None and type(body) is dict:
                reason_code = body.get("reason_code")
            if reason_code is not None and type(reason_code) is not str:
                raise ScientificEvidenceError("Captured public operation reason code is invalid.")
            fit_response_binding_sha256: str | None = None
            canonical_payload_fact: dict[str, object] | None = None
            if candidate.final_status in {"SUCCESS", "CONVERGENCE_WARN"}:
                if (
                    type(candidate.universe_id) is not str
                    or not candidate.universe_id
                    or candidate.convergence_record_bytes is None
                    or candidate.planned_chain_count < 1
                    or candidate.planned_chain_count != len(candidate.chains)
                    or candidate.planned_chain_count
                    != candidate.finalized_terminal_chain_count
                    or candidate.planned_chain_count
                    != candidate.authenticated_available_chain_count
                ):
                    raise ScientificEvidenceError(
                        "Captured public operation success evidence is incomplete."
                    )
                canonical_chains: list[dict[str, object]] = []
                binding_digests: list[str] = []
                for chain in sorted(candidate.chains, key=lambda row: row.chain_plan_position):
                    readback = _readback_authenticated_execution(chain.execution)
                    response = readback.response
                    command = readback.command_evidence
                    payload = response.get("payload") if type(response) is dict else None
                    result = payload.get("result") if type(payload) is dict else None
                    files = response.get("files") if type(response) is dict else None
                    if (
                        readback.execution is not chain.execution
                        or readback.execution_evidence_digest
                        != chain.execution_evidence_digest
                        or canonical_json_bytes(response) != chain.response_bytes
                        or type(command) is not dict
                        or command.get("command") != "fit"
                        or command.get("status") != "SUCCESS"
                        or command.get("payload_digest_kind") != "WORKER_FIT_PAYLOAD"
                        or type(result) is not dict
                        or command.get("payload_digest")
                        != result.get("worker_fit_payload_digest")
                        or type(files) is not dict
                    ):
                        raise ScientificEvidenceError(
                            "Captured public operation Fit response is invalid."
                        )
                    binding_fields = (
                        "protocol_version",
                        "response_schema_version",
                        "payload_schema_version",
                        "request_id",
                        "request_metadata_digest",
                        "scientific_request_digest",
                        "response_metadata_digest",
                        "command",
                        "status",
                        "backend_identity",
                        "backend_identity_digest",
                        "capabilities",
                        "capabilities_digest",
                        "settings_digest",
                        "requested_outputs_digest",
                        "execution_input_projection_digest",
                        "core_code_digest",
                        "started_at_utc",
                        "ended_at_utc",
                        "runtime_seconds",
                        "resource_summary",
                        "warnings_record_count",
                        "warnings_file_digest",
                        "side_effects_file_digest",
                        "error",
                    )
                    try:
                        binding = {
                            "binding_schema_version": (
                                "ebm-audit-evaluator-worker-response-binding/2.0"
                            ),
                            **{field: response[field] for field in binding_fields},
                            "payload_digest_kind": "WORKER_FIT_PAYLOAD",
                            "payload_digest": result["worker_fit_payload_digest"],
                            "files": [
                                {
                                    "relative_path": path,
                                    "byte_length": files[path]["byte_length"],
                                    "sha256": files[path]["sha256"],
                                }
                                for path in sorted(files)
                            ],
                        }
                    except (KeyError, TypeError) as error:
                        raise ScientificEvidenceError(
                            "Captured public operation Fit response is incomplete."
                        ) from error
                    validate_instance(
                        binding,
                        "evaluator-receipts.schema.json",
                        definition="FitSuccessEvaluatorWorkerResponseBinding",
                    )
                    binding_digest = structured_sha256_hex(
                        "ebm-audit/fit-evaluator-worker-response-binding/1",
                        binding,
                    )
                    binding_digests.append(binding_digest)
                    chain_payload = strict_json_loads(chain.chain_payload_bytes)
                    validate_instance(
                        chain_payload,
                        "canonical-records.schema.json",
                        definition="FinalChainScientificPayload",
                    )
                    if (
                        type(chain_payload) is not dict
                        or chain_payload.get("chain_payload_digest")
                        != chain.chain_payload_digest
                        or chain_payload.get("chain_plan_position")
                        != chain.chain_plan_position
                        or chain_payload.get("chain_execution_id")
                        != chain.chain_execution_id
                        or chain_payload.get("final_attempt_id") != chain.final_attempt_id
                    ):
                        raise ScientificEvidenceError(
                            "Captured public operation chain payload is invalid."
                        )
                    canonical_chain = dict(chain_payload)
                    canonical_chain["attempt_id"] = canonical_chain.pop("final_attempt_id")
                    canonical_chain[
                        "fit_evaluator_worker_response_binding_sha256"
                    ] = binding_digest
                    for field in (
                        "chain_payload_schema_version",
                        "chain_payload_digest",
                        "chain_plan_position",
                        "resource_summary",
                        "backend_artifacts",
                    ):
                        canonical_chain.pop(field)
                    validate_instance(
                        canonical_chain,
                        "canonical-records.schema.json",
                        definition="CanonicalChainScientificProjection",
                    )
                    canonical_chains.append(canonical_chain)
                if tuple(
                    chain.chain_plan_position
                    for chain in sorted(
                        candidate.chains, key=lambda row: row.chain_plan_position
                    )
                ) != tuple(range(len(candidate.chains))):
                    raise ScientificEvidenceError(
                        "Captured public operation chain order is invalid."
                    )
                convergence = strict_json_loads(candidate.convergence_record_bytes)
                if type(convergence) is not dict:
                    raise ScientificEvidenceError(
                        "Captured public operation convergence evidence is invalid."
                    )
                fit_response_binding_sha256 = binding_digests[0]
                canonical_payload_fact = {
                    "operation_instance_id": candidate.universe_id,
                    "analysis_spec_id": candidate.analysis_spec_id,
                    "universe_id": candidate.universe_id,
                    "core_final_status": candidate.final_status,
                    "event_ids": list(candidate.event_ids),
                    "ordered_chain_payloads": canonical_chains,
                    "convergence": convergence,
                }

            direct_preparation: dict[str, object] | None = None
            try:
                if not all(
                    hasattr(prepared, field)
                    for field in (
                        "universe_bytes",
                        "analysis_spec_bytes",
                        "private_replay",
                        "canonical_dataset",
                        "arrays",
                    )
                ):
                    raise AttributeError
                universe = strict_json_loads(prepared.universe_bytes)
                spec = strict_json_loads(prepared.analysis_spec_bytes)
                transition = strict_json_loads(
                    prepared.private_replay.private_transition_chain_bytes
                )
                if (
                    type(universe) is not dict
                    or type(spec) is not dict
                    or type(transition) is not dict
                    or universe.get("universe_id") != candidate.universe_id
                    or universe.get("analysis_spec_id") != candidate.analysis_spec_id
                ):
                    raise ScientificEvidenceError("Captured direct preparation facts are detached.")
                source_indexes = prepared.canonical_dataset.private.source_row_manifest.get(
                    "source_row_index_by_internal_index"
                )
                if type(source_indexes) is not tuple or any(
                    type(value) is not int for value in source_indexes
                ):
                    raise ScientificEvidenceError("Captured source row identities are invalid.")
                source_instances = [
                    {
                        "source_row_index": source_indexes[row.internal_row_index],
                        "occurrence_ordinal": 0,
                    }
                    for row in prepared.private_replay.source_membership
                ]
                role_instances = {
                    role: [
                        source_instances[index]
                        for index, row in enumerate(prepared.private_replay.source_membership)
                        if row.role == role
                    ]
                    for role in ("REFERENCE", "AT_RISK")
                }
                direct_preparation = {
                    "analysis_spec_sha256": candidate.analysis_spec_id.removeprefix("sha256:"),
                    "executed_request_sha256": structured_sha256_hex(
                        "ebm-audit/executed-operation-request/1",
                        {
                            "analysis_spec": spec,
                            "universe_id": universe.get("universe_id"),
                            "training_prepared_data_digest": universe.get(
                                "training_prepared_data_digest"
                            ),
                        },
                    ),
                    "reference_group_row_manifest_sha256": structured_sha256_hex(
                        "ebm-audit/reference-group-row-manifest/1",
                        role_instances["REFERENCE"],
                    ),
                    "at_risk_group_row_manifest_sha256": structured_sha256_hex(
                        "ebm-audit/at-risk-group-row-manifest/1",
                        role_instances["AT_RISK"],
                    ),
                    "ordered_applied_group_roles": ["REFERENCE", "AT_RISK"],
                    "reference_fit_method_id": (
                        spec.get("covariate_adjustment", {}).get("method")
                        if type(spec.get("covariate_adjustment")) is dict
                        else None
                    ),
                    "preprocessing_parameters_sha256": structured_sha256_hex(
                        "ebm-audit/preprocessing-parameters/1",
                        spec.get("preprocessing"),
                    ),
                    "preparation_projection": None,
                    "transformation": None,
                }
                null_map = transition.get("null_transformation")
                training_accounting = transition.get("training_accounting")
                data_accounting = (
                    training_accounting.get("data_accounting")
                    if type(training_accounting) is dict
                    else None
                )
                preparation_projection = _captured_preparation_projection(
                    prepared,
                    cast(dict[str, object], spec),
                    cast(dict[str, object], universe),
                    source_instances,
                    data_accounting,
                )
                direct_preparation["preparation_projection"] = preparation_projection
                if type(null_map) is dict:
                    source_alignment_sha256 = cast(
                        str,
                        preparation_projection[
                            "source_participant_event_alignment_sha256"
                        ],
                    )
                    alignment_changed = bool(null_map.get("participant_event_alignment_changed"))
                    direct_preparation["transformation"] = {
                        "method_id": null_map.get("method_id"),
                        "executed_parameters_sha256": cast(
                            str,
                            cast(dict[str, object], transition["operation_identity"])[
                                "operation_parameters_digest"
                            ],
                        ).removeprefix("sha256:"),
                        **preparation_projection,
                        "output_participant_event_alignment_sha256": (
                            structured_sha256_hex(
                                "ebm-audit/participant-event-alignment/1",
                                {
                                    "source": source_alignment_sha256,
                                    "changed": alignment_changed,
                                    "mapping": null_map,
                                },
                            )
                            if alignment_changed
                            else source_alignment_sha256
                        ),
                    }
            except AttributeError:
                direct_preparation = None
            except ScientificEvidenceError:
                raise
            except Exception as error:
                raise ScientificEvidenceError(
                    "Captured direct preparation facts are invalid."
                ) from error
            operations.append(
                _CapturedPublicOperationFact(
                    candidate_ordinal=candidate.candidate_ordinal,
                    operation_instance_id=candidate.universe_id,
                    analysis_spec_sha256=candidate.analysis_spec_id.removeprefix("sha256:"),
                    terminal_status=candidate.final_status,
                    reason_code=reason_code,
                    backend_invoked=bool(candidate.chains),
                    finalized_result_record_sha256=structured_sha256_hex(
                        "ebm-audit/finalized-result-record/1", finalized
                    ),
                    terminal_record_sha256=structured_sha256_hex(
                        "ebm-audit/captured-candidate-terminal/1", terminal
                    ),
                    fit_response_binding_sha256=fit_response_binding_sha256,
                    canonical_payload_fact_bytes=(
                        None
                        if canonical_payload_fact is None
                        else canonical_json_bytes(canonical_payload_fact)
                    ),
                    direct_preparation_fact_bytes=(
                        None
                        if direct_preparation is None
                        else canonical_json_bytes(direct_preparation)
                    ),
                )
            )
        run_preimage = {
            "schema_version": "ebm-audit-captured-public-operation-run/1.0",
            "plan_digest": state.plan_digest,
            "terminal_index_digest": state.terminal_index_digest,
            "preparation_receipt_digest": state.preparation_receipt_digest,
            "synthetic_case_binding": binding,
            "ordered_operations": [
                {
                    "candidate_ordinal": row.candidate_ordinal,
                    "operation_instance_id": row.operation_instance_id,
                    "analysis_spec_sha256": row.analysis_spec_sha256,
                    "terminal_status": row.terminal_status,
                    "finalized_result_record_sha256": (row.finalized_result_record_sha256),
                    "terminal_record_sha256": row.terminal_record_sha256,
                    "fit_response_binding_sha256": row.fit_response_binding_sha256,
                    "canonical_payload_fact_sha256": (
                        None
                        if row.canonical_payload_fact_bytes is None
                        else structured_sha256_hex(
                            "ebm-audit/captured-canonical-payload-fact/1",
                            strict_json_loads(row.canonical_payload_fact_bytes),
                        )
                    ),
                    "direct_preparation_fact_sha256": (
                        None
                        if row.direct_preparation_fact_bytes is None
                        else structured_sha256_hex(
                            "ebm-audit/captured-direct-preparation-fact/1",
                            strict_json_loads(row.direct_preparation_fact_bytes),
                        )
                    ),
                }
                for row in operations
            ],
            "scientific_evidence_digest": scientific["scientific_evidence_digest"],
            "ordered_influence_removal_fact_sha256": [
                structured_sha256_hex(
                    "ebm-audit/captured-influence-removal-fact/1",
                    strict_json_loads(row),
                )
                for row in influence_facts
            ],
        }
        return _CapturedPublicOperationProjection(
            captured_run_sha256=structured_sha256_hex(
                "ebm-audit/captured-public-operation-run/1", run_preimage
            ),
            plan_digest=state.plan_digest,
            terminal_index_digest=state.terminal_index_digest,
            synthetic_case_binding=MappingProxyType(cast(dict[str, str], binding)),
            operations=tuple(operations),
            scientific_evidence_digest=cast(str, scientific["scientific_evidence_digest"]),
            influence_removal_fact_bytes=tuple(influence_facts),
        )

    def issue(
        capture: CapturedScientificRun,
        sealed: SealedScientificEvidence,
    ) -> CapturedPublicOperationEvidence:
        if (
            type(capture) is not CapturedScientificRun
            or type(sealed) is not SealedScientificEvidence
        ):
            raise ScientificEvidenceError(
                "Captured public operation evidence requires live science owners."
            )
        try:
            existing = by_capture.read(capture)
            retained_capture, retained_sealed, _projection = states.read(existing)
            if retained_capture is not capture or retained_sealed is not sealed:
                raise ScientificEvidenceError(
                    "Captured public operation scientific authority changed."
                )
            return existing
        except OneShotRegistryError:
            pass
        projection = project(capture, sealed)
        owner = object.__new__(CapturedPublicOperationEvidence)
        issuer.bind_once(owner, (capture, sealed, projection))
        by_capture_issuer.bind_once(capture, owner)
        return owner

    def read(
        owner: CapturedPublicOperationEvidence,
    ) -> tuple[CapturedScientificRun, _CapturedPublicOperationProjection]:
        if type(owner) is not CapturedPublicOperationEvidence:
            raise ScientificEvidenceError("Captured public operation evidence is invalid.")
        try:
            capture, sealed, retained = states.read(owner)
        except OneShotRegistryError as error:
            raise ScientificEvidenceError(
                "Captured public operation evidence is invalid."
            ) from error
        current = project(capture, sealed)
        if current != retained:
            raise ScientificEvidenceError(
                "Captured public operation evidence changed after issuance."
            )
        return capture, retained

    return issue, read


(
    _issue_captured_public_operation_evidence,
    _read_captured_public_operation_evidence,
) = _build_captured_public_operation_evidence_boundary()


@dataclass(frozen=True, repr=False)
class _PreparationAuditEvidenceState:
    capture: CapturedScientificRun
    canonical_record_bytes: tuple[bytes, ...]
    row_manifest_canonical_record_bytes: tuple[bytes, ...]
    row_instance_manifests: PreparationRowInstanceManifests


@final
class PreparationAuditEvidence:
    """Opaque PAE v2 projection issued only from one live captured core run."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PreparationAuditEvidence:
        raise TypeError("Preparation audit evidence is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Preparation audit evidence cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Preparation audit evidence is immutable.")


@final
class PreparationRowInstanceManifests:
    """Opaque four-role row-instance records attached to one PAE and run."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PreparationRowInstanceManifests:
        raise TypeError("Preparation row instance manifests are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Preparation row instance manifests cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Preparation row instance manifests are immutable.")


@dataclass(frozen=True, repr=False)
class _PreparationAuditEvidenceUnavailableState:
    capture: CapturedScientificRun
    canonical_record_bytes: tuple[bytes, ...]


@final
class PreparationAuditEvidenceUnavailable:
    """Opaque proof that complete PAE v2 source coverage is unavailable."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PreparationAuditEvidenceUnavailable:
        raise TypeError("Preparation audit evidence unavailability is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Preparation audit evidence unavailability cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Preparation audit evidence unavailability is immutable.")


_PREPARATION_AUDIT_EVIDENCE_STATES: OneShotWeakRegistry[
    PreparationAuditEvidence, _PreparationAuditEvidenceState
]
_PREPARATION_AUDIT_EVIDENCE_ISSUER: OneShotRegistryIssuer[
    PreparationAuditEvidence, _PreparationAuditEvidenceState
]
(
    _PREPARATION_AUDIT_EVIDENCE_STATES,
    _PREPARATION_AUDIT_EVIDENCE_ISSUER,
) = create_one_shot_registry()
_PREPARATION_AUDIT_EVIDENCE_BY_CAPTURE: OneShotWeakRegistry[
    CapturedScientificRun, PreparationAuditEvidence
]
_PREPARATION_AUDIT_EVIDENCE_BY_CAPTURE_ISSUER: OneShotRegistryIssuer[
    CapturedScientificRun, PreparationAuditEvidence
]
(
    _PREPARATION_AUDIT_EVIDENCE_BY_CAPTURE,
    _PREPARATION_AUDIT_EVIDENCE_BY_CAPTURE_ISSUER,
) = create_one_shot_registry()
_PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS: OneShotWeakRegistry[
    PreparationRowInstanceManifests, PreparationAuditEvidence
]
_PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS_ISSUER: OneShotRegistryIssuer[
    PreparationRowInstanceManifests, PreparationAuditEvidence
]
(
    _PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS,
    _PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS_ISSUER,
) = create_one_shot_registry()
_PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_STATES: OneShotWeakRegistry[
    PreparationAuditEvidenceUnavailable, _PreparationAuditEvidenceUnavailableState
]
_PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_ISSUER: OneShotRegistryIssuer[
    PreparationAuditEvidenceUnavailable, _PreparationAuditEvidenceUnavailableState
]
(
    _PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_STATES,
    _PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_ISSUER,
) = create_one_shot_registry()
_PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_BY_CAPTURE: OneShotWeakRegistry[
    CapturedScientificRun, PreparationAuditEvidenceUnavailable
]
_PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_BY_CAPTURE_ISSUER: OneShotRegistryIssuer[
    CapturedScientificRun, PreparationAuditEvidenceUnavailable
]
(
    _PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_BY_CAPTURE,
_PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_BY_CAPTURE_ISSUER,
) = create_one_shot_registry()


def _preparation_audit_baseline_candidate_index(
    candidates: tuple[_CapturedCandidateState, ...],
    baseline_analysis_spec_id: str,
) -> int:
    """Return the one baseline index that can own case-level PAE."""

    if type(candidates) is not tuple or type(baseline_analysis_spec_id) is not str:
        raise ScientificEvidenceError("Preparation audit baseline identity is invalid.")
    matches = tuple(
        index
        for index, candidate in enumerate(candidates)
        if type(candidate) is _CapturedCandidateState
        and candidate.analysis_spec_id == baseline_analysis_spec_id
    )
    if len(matches) != 1:
        raise ScientificEvidenceError("Preparation audit baseline identity is invalid.")
    return matches[0]


def _derive_preparation_audit_bundle(
    capture: CapturedScientificRun,
    /,
    _capture_transaction: Callable[[object], Any] = (
        _capture_preparation_transaction_state_identity
    ),
    _capture_candidate_states: Callable[..., tuple[Any, ...]] = (
        _capture_preparation_transaction_candidate_states
    ),
    _resolve_prepared: Callable[[object], object] = _resolve_prepared_execution_authorization,
    _read_capture: Callable[[object], _CapturedScientificRunState] = (
        _read_captured_scientific_run
    ),
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _derive_record: Callable[
        [str, _CapturedCandidateState, object],
        tuple[dict[str, object], tuple[dict[str, object], ...]],
    ]
    | None = None,
) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
    """Rebuild the one case-level baseline PAE from preparation authority."""

    if _derive_record is None:
        raise _error_type("Preparation audit derivation is unavailable.")
    state = _read_capture(capture)
    transaction = _capture_transaction(state.preparation_transaction)
    prepared_states = _capture_candidate_states(transaction)
    authorizations = transaction.candidate_authorizations
    if len(prepared_states) != len(state.candidates) or len(authorizations) != len(
        state.candidates
    ):
        raise _error_type("Preparation candidate coverage is invalid.")
    binding = _strict_json_loads(state.synthetic_case_binding_bytes or b"")
    if (
        type(binding) is not dict
        or _canonical_json_bytes(binding) != state.synthetic_case_binding_bytes
        or set(binding)
        != {
            "case_id",
            "source_contract_sha256",
            "scenario_definitions_sha256",
        }
    ):
        raise _error_type("Preparation audit evidence requires a synthetic case.")
    case_id = binding.get("case_id")
    if type(case_id) is not str:
        raise _error_type("Preparation audit case identity is invalid.")
    try:
        baseline_index = _preparation_audit_baseline_candidate_index(
            state.candidates,
            state.baseline_analysis_spec_id,
        )
    except ScientificEvidenceError:
        raise _error_type("Preparation audit baseline identity is invalid.") from None
    records: list[bytes] = []
    row_manifest_records: list[bytes] = []
    for index, (candidate, authorization, prepared_state) in enumerate(
        zip(
            state.candidates,
            authorizations,
            prepared_states,
            strict=True,
        )
    ):
        resolved = _resolve_prepared(authorization)
        if resolved is not prepared_state:
            raise _error_type("Preparation authorization changed.")
        if index != baseline_index:
            continue
        record, manifests = _derive_record(case_id, candidate, resolved)
        records.append(_canonical_json_bytes(record))
        row_manifest_records.extend(_canonical_json_bytes(manifest) for manifest in manifests)
    return tuple(records), tuple(row_manifest_records)


def _authenticated_preparation_reference_chain(
    candidate: _CapturedCandidateState,
    /,
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
) -> _CapturedChainState | None:
    """Return the exact retained authenticated chain selected as the reference."""

    if candidate.reference_chain_bytes is None:
        return None
    reference = _strict_json_loads(candidate.reference_chain_bytes)
    if type(reference) is not dict:
        return None
    chain_execution_id = reference.get("chain_execution_id")
    chain_plan_position = reference.get("chain_plan_position")
    if type(chain_execution_id) is not str or type(chain_plan_position) is not int:
        return None
    matches = tuple(
        chain
        for chain in candidate.chains
        if chain.chain_execution_id == chain_execution_id
        and chain.chain_plan_position == chain_plan_position
    )
    return matches[0] if len(matches) == 1 else None


def _derive_preparation_audit_evidence_unavailable_records(
    capture: CapturedScientificRun,
    /,
    _authenticated_reference_chain: Callable[
        [_CapturedCandidateState], _CapturedChainState | None
    ] = _authenticated_preparation_reference_chain,
    _read_capture: Callable[[object], _CapturedScientificRunState] = (
        _read_captured_scientific_run
    ),
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _structured_sha256_hex: Callable[[str, object], str] = structured_sha256_hex,
    _validate_instance: Callable[..., None] = validate_instance,
) -> tuple[bytes, ...]:
    """Derive typed unavailable records without projecting unowned fit facts."""

    state = _read_capture(capture)
    binding = _strict_json_loads(state.synthetic_case_binding_bytes or b"")
    if (
        type(binding) is not dict
        or _canonical_json_bytes(binding) != state.synthetic_case_binding_bytes
        or set(binding)
        != {
            "case_id",
            "source_contract_sha256",
            "scenario_definitions_sha256",
        }
    ):
        raise _error_type("Preparation audit evidence requires a synthetic case.")
    case_id = binding.get("case_id")
    if type(case_id) is not str:
        raise _error_type("Preparation audit case identity is invalid.")

    records: list[bytes] = []
    for candidate in state.candidates:
        if _authenticated_reference_chain(candidate) is not None:
            continue
        candidate_id = candidate.candidate_id
        operation_instance_id = candidate.universe_id
        analysis_spec_id = candidate.analysis_spec_id
        if (
            type(candidate_id) is not str
            or (operation_instance_id is not None and type(operation_instance_id) is not str)
            or type(analysis_spec_id) is not str
        ):
            raise _error_type("Preparation audit identity is unavailable.")
        preimage: dict[str, object] = {
            "schema_version": "ebm-audit-preparation-audit-evidence-unavailable/1.0",
            "digest_state": "DIGEST_PREIMAGE",
            "status": "UNAVAILABLE",
            "case_id": case_id,
            "candidate_id": candidate_id,
            "operation_instance_id": operation_instance_id,
            "analysis_spec_sha256": analysis_spec_id.removeprefix("sha256:"),
            "reason_code": "PAE.AUTHENTICATED_REFERENCE_EXECUTION_UNAVAILABLE",
            "preparation_audit_evidence_unavailable_sha256": None,
        }
        _validate_instance(
            preimage,
            "scenario-evidence.schema.json",
            definition="PreparationAuditEvidenceUnavailableDigestPreimage",
        )
        digest = _structured_sha256_hex(
            "ebm-audit/preparation-audit-evidence-unavailable/1", preimage
        )
        persisted = dict(preimage)
        persisted["digest_state"] = "PERSISTED"
        persisted["preparation_audit_evidence_unavailable_sha256"] = digest
        _validate_instance(
            persisted,
            "scenario-evidence.schema.json",
            definition="PreparationAuditEvidenceUnavailable",
        )
        records.append(_canonical_json_bytes(persisted))
    return tuple(records)


def _issue_preparation_audit_evidence(
    value: object,
    /,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _evidence_by_capture: OneShotWeakRegistry[CapturedScientificRun, PreparationAuditEvidence] = (
        _PREPARATION_AUDIT_EVIDENCE_BY_CAPTURE
    ),
    _evidence_by_capture_issuer: OneShotRegistryIssuer[
        CapturedScientificRun, PreparationAuditEvidence
    ] = _PREPARATION_AUDIT_EVIDENCE_BY_CAPTURE_ISSUER,
    _evidence_issuer: OneShotRegistryIssuer[
        PreparationAuditEvidence, _PreparationAuditEvidenceState
    ] = _PREPARATION_AUDIT_EVIDENCE_ISSUER,
    _evidence_state_type: type[_PreparationAuditEvidenceState] = (_PreparationAuditEvidenceState),
    _evidence_type: type[PreparationAuditEvidence] = PreparationAuditEvidence,
    _evidence_by_manifest_issuer: OneShotRegistryIssuer[
        PreparationRowInstanceManifests, PreparationAuditEvidence
    ] = _PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS_ISSUER,
    _manifest_type: type[PreparationRowInstanceManifests] = (PreparationRowInstanceManifests),
    _unavailable_by_capture: OneShotWeakRegistry[
        CapturedScientificRun, PreparationAuditEvidenceUnavailable
    ] = _PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_BY_CAPTURE,
    _unavailable_by_capture_issuer: OneShotRegistryIssuer[
        CapturedScientificRun, PreparationAuditEvidenceUnavailable
    ] = _PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_BY_CAPTURE_ISSUER,
    _unavailable_issuer: OneShotRegistryIssuer[
        PreparationAuditEvidenceUnavailable, _PreparationAuditEvidenceUnavailableState
    ] = _PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_ISSUER,
    _unavailable_state_type: type[_PreparationAuditEvidenceUnavailableState] = (
        _PreparationAuditEvidenceUnavailableState
    ),
    _unavailable_type: type[PreparationAuditEvidenceUnavailable] = (
        PreparationAuditEvidenceUnavailable
    ),
    _derive_bundle: Callable[[CapturedScientificRun], tuple[tuple[bytes, ...], tuple[bytes, ...]]]
    | None = None,
    _derive_unavailable_records: Callable[[CapturedScientificRun], tuple[bytes, ...]] = (
        _derive_preparation_audit_evidence_unavailable_records
    ),
    _read_evidence: Callable[[object], tuple[dict[str, object], ...]] | None = None,
    _read_unavailable: Callable[[object], tuple[dict[str, object], ...]] | None = None,
    _cast: Any = cast,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
) -> PreparationAuditEvidence | PreparationAuditEvidenceUnavailable:
    """Issue one complete PAE v2 projection from retained execution owners only."""

    if _derive_bundle is None or _read_evidence is None or _read_unavailable is None:
        raise _error_type("Preparation audit reader is unavailable.")
    capture = _cast(CapturedScientificRun, value)
    existing = _evidence_by_capture.get(capture)
    existing_unavailable = _unavailable_by_capture.get(capture)
    if existing is not None and existing_unavailable is not None:
        raise _error_type("Preparation audit evidence state is ambiguous.")
    if existing is not None:
        _read_evidence(existing)
        return existing
    if existing_unavailable is not None:
        _read_unavailable(existing_unavailable)
        return existing_unavailable
    try:
        unavailable_records = _derive_unavailable_records(capture)
        if unavailable_records:
            unavailable = object.__new__(_unavailable_type)
            unavailable_state = _unavailable_state_type(capture, unavailable_records)
            _unavailable_issuer.bind_once(unavailable, unavailable_state)
            _unavailable_by_capture_issuer.bind_once(capture, unavailable)
            _read_unavailable(unavailable)
            return unavailable
        records, row_manifest_records = _derive_bundle(capture)
        manifests = object.__new__(_manifest_type)
        evidence = object.__new__(_evidence_type)
        evidence_state = _evidence_state_type(
            capture,
            records,
            row_manifest_records,
            manifests,
        )
        _evidence_issuer.bind_once(evidence, evidence_state)
        _evidence_by_manifest_issuer.bind_once(manifests, evidence)
        _evidence_by_capture_issuer.bind_once(capture, evidence)
        return evidence
    except _error_type:
        raise
    except Exception as error:
        raise _error_type("Preparation audit evidence is unavailable.") from error


def _read_preparation_audit_evidence_unavailable(
    value: object,
    /,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _evidence_by_capture: OneShotWeakRegistry[
        CapturedScientificRun, PreparationAuditEvidenceUnavailable
    ] = _PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_BY_CAPTURE,
    _evidence_states: OneShotWeakRegistry[
        PreparationAuditEvidenceUnavailable, _PreparationAuditEvidenceUnavailableState
    ] = _PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_STATES,
    _evidence_state_type: type[_PreparationAuditEvidenceUnavailableState] = (
        _PreparationAuditEvidenceUnavailableState
    ),
    _evidence_type: type[PreparationAuditEvidenceUnavailable] = (
        PreparationAuditEvidenceUnavailable
    ),
    _derive_records: Callable[[CapturedScientificRun], tuple[bytes, ...]] = (
        _derive_preparation_audit_evidence_unavailable_records
    ),
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
    _cast: Any = cast,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _read_capture: Callable[[object], _CapturedScientificRunState] = (
        _read_captured_scientific_run
    ),
    _structured_sha256_hex: Callable[[str, object], str] = structured_sha256_hex,
    _validate_instance: Callable[..., None] = validate_instance,
) -> tuple[dict[str, object], ...]:
    if type(value) is not _evidence_type:
        raise _error_type(
            "A genuine preparation audit evidence unavailable capability is required."
        )
    try:
        state = _evidence_states.read(value)
        if (
            type(state) is not _evidence_state_type
            or _evidence_by_capture.get(state.capture) is not value
        ):
            raise _error_type("Preparation audit unavailability is detached.")
        _read_capture(state.capture)
        if _derive_records(state.capture) != state.canonical_record_bytes:
            raise _error_type("Preparation audit unavailability was replaced.")
        records: list[dict[str, object]] = []
        for encoded in state.canonical_record_bytes:
            record = _strict_json_loads(encoded)
            if type(record) is not dict or _canonical_json_bytes(record) != encoded:
                raise _error_type("Preparation audit unavailability storage is invalid.")
            _validate_instance(
                record,
                "scenario-evidence.schema.json",
                definition="PreparationAuditEvidenceUnavailable",
            )
            preimage = dict(record)
            digest = preimage.pop("preparation_audit_evidence_unavailable_sha256")
            preimage["digest_state"] = "DIGEST_PREIMAGE"
            preimage["preparation_audit_evidence_unavailable_sha256"] = None
            _validate_instance(
                preimage,
                "scenario-evidence.schema.json",
                definition="PreparationAuditEvidenceUnavailableDigestPreimage",
            )
            if (
                record.get("digest_state") != "PERSISTED"
                or type(digest) is not str
                or digest
                != _structured_sha256_hex(
                    "ebm-audit/preparation-audit-evidence-unavailable/1", preimage
                )
            ):
                raise _error_type("Preparation audit unavailability digest is invalid.")
            records.append(_cast(dict[str, object], record))
        if not records:
            raise _error_type("Preparation audit unavailability is empty.")
        _evidence_states.require(value, state)
        return tuple(records)
    except _error_type:
        raise
    except Exception as error:
        raise _error_type("Preparation audit unavailability is invalid.") from error


def _validate_preparation_row_instance_manifest_records(
    canonical_record_bytes: tuple[bytes, ...],
    pae_records: tuple[dict[str, object], ...],
    /,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
    _cast: Any = cast,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _structured_sha256_hex: Callable[[str, object], str] = structured_sha256_hex,
    _validate_instance: Callable[..., None] = validate_instance,
) -> tuple[dict[str, object], ...]:
    if len(canonical_record_bytes) != len(pae_records) * 4:
        raise _error_type("Preparation row instance manifest coverage is invalid.")
    records: list[dict[str, object]] = []
    roles = ("INPUT", "TRAINING", "OUTPUT", "REFERENCE_FIT")
    pae_digest_fields = (
        "input_row_instance_manifest_sha256",
        "training_row_instance_manifest_sha256",
        "output_row_instance_manifest_sha256",
        "reference_fit_row_instance_manifest_sha256",
    )
    for index, encoded in enumerate(canonical_record_bytes):
        record = _strict_json_loads(encoded)
        if type(record) is not dict or _canonical_json_bytes(record) != encoded:
            raise _error_type("Preparation row instance manifest storage is invalid.")
        _validate_instance(
            record,
            "scenario-evidence.schema.json",
            definition="PreparationRowInstanceManifest",
        )
        preimage = dict(record)
        digest = preimage.get("row_instance_manifest_sha256")
        preimage["digest_state"] = "DIGEST_PREIMAGE"
        preimage["row_instance_manifest_sha256"] = None
        _validate_instance(
            preimage,
            "scenario-evidence.schema.json",
            definition="PreparationRowInstanceManifest",
        )
        pae_record = pae_records[index // 4]
        role_index = index % 4
        if (
            record.get("digest_state") != "PERSISTED"
            or record.get("row_role") != roles[role_index]
            or record.get("case_id") != pae_record.get("case_id")
            or record.get("operation_instance_id") != pae_record.get("operation_instance_id")
            or type(digest) is not str
            or digest
            != _structured_sha256_hex("ebm-audit/preparation-row-instance-manifest/1", preimage)
            or pae_record.get(pae_digest_fields[role_index]) != digest
        ):
            raise _error_type("Preparation row instance manifest attachment is invalid.")
        records.append(_cast(dict[str, object], record))
    return tuple(records)


def _read_preparation_audit_evidence(
    value: object,
    /,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _evidence_by_capture: OneShotWeakRegistry[CapturedScientificRun, PreparationAuditEvidence] = (
        _PREPARATION_AUDIT_EVIDENCE_BY_CAPTURE
    ),
    _evidence_states: OneShotWeakRegistry[
        PreparationAuditEvidence, _PreparationAuditEvidenceState
    ] = _PREPARATION_AUDIT_EVIDENCE_STATES,
    _evidence_state_type: type[_PreparationAuditEvidenceState] = (_PreparationAuditEvidenceState),
    _evidence_type: type[PreparationAuditEvidence] = PreparationAuditEvidence,
    _evidence_by_manifest: OneShotWeakRegistry[
        PreparationRowInstanceManifests, PreparationAuditEvidence
    ] = _PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS,
    _manifest_type: type[PreparationRowInstanceManifests] = (PreparationRowInstanceManifests),
    _derive_bundle: Callable[[CapturedScientificRun], tuple[tuple[bytes, ...], tuple[bytes, ...]]]
    | None = None,
    _validate_manifest_records: Callable[
        [tuple[bytes, ...], tuple[dict[str, object], ...]],
        tuple[dict[str, object], ...],
    ]
    | None = None,
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
    _cast: Any = cast,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _read_capture: Callable[[object], _CapturedScientificRunState] = (
        _read_captured_scientific_run
    ),
    _structured_sha256_hex: Callable[[str, object], str] = structured_sha256_hex,
    _validate_instance: Callable[..., None] = validate_instance,
) -> tuple[dict[str, object], ...]:
    if (
        _derive_bundle is None
        or _validate_manifest_records is None
        or type(value) is not _evidence_type
    ):
        raise _error_type("A genuine preparation audit evidence capability is required.")
    try:
        state = _evidence_states.read(value)
        if (
            type(state) is not _evidence_state_type
            or _evidence_by_capture.get(state.capture) is not value
            or type(state.row_instance_manifests) is not _manifest_type
            or _evidence_by_manifest.get(state.row_instance_manifests) is not value
        ):
            raise _error_type("Preparation audit evidence is detached.")
        _read_capture(state.capture)
        if _derive_bundle(state.capture) != (
            state.canonical_record_bytes,
            state.row_manifest_canonical_record_bytes,
        ):
            raise _error_type("Preparation audit evidence was replaced.")
        records: list[dict[str, object]] = []
        for encoded in state.canonical_record_bytes:
            record = _strict_json_loads(encoded)
            if type(record) is not dict or _canonical_json_bytes(record) != encoded:
                raise _error_type("Preparation audit evidence storage is invalid.")
            _validate_instance(
                record,
                "scenario-evidence.schema.json",
                definition="PreparationAuditEvidence",
            )
            preimage = dict(record)
            digest = preimage.pop("preparation_audit_evidence_sha256")
            preimage["digest_state"] = "DIGEST_PREIMAGE"
            preimage["preparation_audit_evidence_sha256"] = None
            _validate_instance(
                preimage,
                "scenario-evidence.schema.json",
                definition="PreparationAuditEvidenceDigestPreimage",
            )
            if (
                record.get("digest_state") != "PERSISTED"
                or type(digest) is not str
                or digest
                != _structured_sha256_hex("ebm-audit/preparation-audit-evidence/2", preimage)
            ):
                raise _error_type("Preparation audit evidence digest is invalid.")
            records.append(_cast(dict[str, object], record))
        _validate_manifest_records(
            state.row_manifest_canonical_record_bytes,
            tuple(records),
        )
        _evidence_states.require(value, state)
        _evidence_by_manifest.require(state.row_instance_manifests, value)
        return tuple(records)
    except _error_type:
        raise
    except Exception as error:
        raise _error_type("Preparation audit evidence is invalid.") from error


def _issue_preparation_row_instance_manifests(
    value: object,
    /,
    _evidence_by_manifest: OneShotWeakRegistry[
        PreparationRowInstanceManifests, PreparationAuditEvidence
    ] = _PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS,
    _evidence_states: OneShotWeakRegistry[
        PreparationAuditEvidence, _PreparationAuditEvidenceState
    ] = _PREPARATION_AUDIT_EVIDENCE_STATES,
    _evidence_type: type[PreparationAuditEvidence] = PreparationAuditEvidence,
    _read_evidence: Callable[[object], tuple[dict[str, object], ...]] | None = None,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
) -> PreparationRowInstanceManifests:
    """Issue the four persisted row roles for one exact PAE and captured run."""

    if _read_evidence is None or type(value) is not _evidence_type:
        raise _error_type("A genuine preparation audit evidence capability is required.")
    evidence = value
    try:
        _read_evidence(evidence)
        evidence_state = _evidence_states.read(evidence)
        _evidence_states.require(evidence, evidence_state)
        _evidence_by_manifest.require(evidence_state.row_instance_manifests, evidence)
        return evidence_state.row_instance_manifests
    except _error_type:
        raise
    except Exception as error:
        raise _error_type("Preparation row instance manifests are unavailable.") from error


def _read_preparation_row_instance_manifests(
    value: object,
    /,
    _evidence_by_manifest: OneShotWeakRegistry[
        PreparationRowInstanceManifests, PreparationAuditEvidence
    ] = _PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS,
    _evidence_states: OneShotWeakRegistry[
        PreparationAuditEvidence, _PreparationAuditEvidenceState
    ] = _PREPARATION_AUDIT_EVIDENCE_STATES,
    _manifest_type: type[PreparationRowInstanceManifests] = (PreparationRowInstanceManifests),
    _read_evidence: Callable[[object], tuple[dict[str, object], ...]] | None = None,
    _validate_manifest_records: Callable[
        [tuple[bytes, ...], tuple[dict[str, object], ...]],
        tuple[dict[str, object], ...],
    ]
    | None = None,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
) -> tuple[dict[str, object], ...]:
    """Read four-role manifests after one combined PAE bundle revalidation."""

    if (
        _read_evidence is None
        or _validate_manifest_records is None
        or type(value) is not _manifest_type
    ):
        raise _error_type("A genuine preparation row instance manifest capability is required.")
    try:
        evidence = _evidence_by_manifest.read(value)
        pae_records = _read_evidence(evidence)
        state = _evidence_states.read(evidence)
        if state.row_instance_manifests is not value:
            raise _error_type("Preparation row instance manifests are detached.")
        records = _validate_manifest_records(
            state.row_manifest_canonical_record_bytes,
            pae_records,
        )
        _evidence_states.require(evidence, state)
        _evidence_by_manifest.require(value, evidence)
        return records
    except _error_type:
        raise
    except Exception as error:
        raise _error_type("Preparation row instance manifests are invalid.") from error


def _persist_preparation_row_instance_manifest(
    *,
    case_id: str,
    operation_instance_id: str,
    role: str,
    rows: object,
    source_indexes: tuple[int, ...],
    _any_type_marker: Any = Any,
    _cast: Any = cast,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _sequence_type: Any = Sequence,
    _structured_sha256_hex: Callable[[str, object], str] = structured_sha256_hex,
    _validate_instance: Callable[..., None] = validate_instance,
) -> dict[str, object]:
    ordered: list[dict[str, int]] = []
    for row in _cast(_sequence_type[object], rows):
        values = _cast(_any_type_marker, row)._asdict()
        internal = values.get("internal_row_index")
        occurrence = values.get("occurrence_ordinal", 0)
        if (
            type(internal) is not int
            or internal < 0
            or internal >= len(source_indexes)
            or type(occurrence) is not int
            or occurrence < 0
        ):
            raise _error_type("Preparation row instance is invalid.")
        ordered.append(
            {
                "source_row_index": source_indexes[internal],
                "occurrence_ordinal": occurrence,
            }
        )
    preimage: dict[str, object] = {
        "schema_version": "ebm-audit-preparation-row-instance-manifest/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "case_id": case_id,
        "operation_instance_id": operation_instance_id,
        "row_role": role,
        "ordered_row_instances": ordered,
        "row_instance_manifest_sha256": None,
    }
    _validate_instance(
        preimage,
        "scenario-evidence.schema.json",
        definition="PreparationRowInstanceManifest",
    )
    persisted = dict(preimage)
    persisted["digest_state"] = "PERSISTED"
    persisted["row_instance_manifest_sha256"] = _structured_sha256_hex(
        "ebm-audit/preparation-row-instance-manifest/1", preimage
    )
    _validate_instance(
        persisted,
        "scenario-evidence.schema.json",
        definition="PreparationRowInstanceManifest",
    )
    return persisted


def _preparation_row_instance_manifest_digests(
    manifests: tuple[dict[str, object], ...],
    /,
    _cast: Any = cast,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _structured_sha256_hex: Callable[[str, object], str] = structured_sha256_hex,
    _validate_instance: Callable[..., None] = validate_instance,
) -> tuple[str, str, str, str]:
    roles = ("INPUT", "TRAINING", "OUTPUT", "REFERENCE_FIT")
    if len(manifests) != len(roles):
        raise _error_type("Preparation row instance manifest coverage is invalid.")
    digests: list[str] = []
    attachment: tuple[object, object] | None = None
    for role, manifest in zip(roles, manifests, strict=True):
        _validate_instance(
            manifest,
            "scenario-evidence.schema.json",
            definition="PreparationRowInstanceManifest",
        )
        digest = manifest.get("row_instance_manifest_sha256")
        current_attachment = (
            manifest.get("case_id"),
            manifest.get("operation_instance_id"),
        )
        if (
            manifest.get("digest_state") != "PERSISTED"
            or manifest.get("row_role") != role
            or type(digest) is not str
            or (attachment is not None and current_attachment != attachment)
        ):
            raise _error_type("Preparation row instance manifest attachment is invalid.")
        preimage = dict(manifest)
        preimage["digest_state"] = "DIGEST_PREIMAGE"
        preimage["row_instance_manifest_sha256"] = None
        if digest != _structured_sha256_hex(
            "ebm-audit/preparation-row-instance-manifest/1", preimage
        ):
            raise _error_type("Preparation row instance manifest digest is invalid.")
        attachment = current_attachment
        digests.append(digest)
    validated_digests: tuple[str, str, str, str] = _cast(tuple[str, str, str, str], tuple(digests))
    return validated_digests


def _derive_preparation_audit_record(
    case_id: str,
    candidate: _CapturedCandidateState,
    prepared: Any,
    /,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _readback: Callable[[object], Any] = _readback_authenticated_execution,
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
    _persist_manifest: Callable[..., dict[str, object]] = (
        _persist_preparation_row_instance_manifest
    ),
    _manifest_digests: Callable[
        [tuple[dict[str, object], ...]], tuple[str, str, str, str]
    ] = _preparation_row_instance_manifest_digests,
    _authenticated_reference_chain: Callable[
        [_CapturedCandidateState], _CapturedChainState | None
    ] = _authenticated_preparation_reference_chain,
    _any_type_marker: Any = Any,
    _cast: Any = cast,
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _mapping_proxy_type: Any = MappingProxyType,
    _np_array_equal: Callable[[Any, Any], Any] = np.array_equal,
    _np_bool_type: Any = np.bool_,
    _np_count_nonzero: Callable[[Any], Any] = np.count_nonzero,
    _np_isfinite: Callable[[Any], Any] = np.isfinite,
    _np_issubdtype: Callable[[Any, Any], bool] = np.issubdtype,
    _np_ndarray_type: type[np.ndarray[Any, Any]] = np.ndarray,
    _np_number_type: Any = np.number,
    _structured_sha256_hex: Callable[[str, object], str] = structured_sha256_hex,
    _validate_instance: Callable[..., None] = validate_instance,
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    """Derive one PAE v2 record from private replay and exact reference execution."""

    plan = _strict_json_loads(prepared.plan_bytes)
    universe = _strict_json_loads(prepared.universe_bytes)
    spec = _strict_json_loads(prepared.analysis_spec_bytes)
    transition = _strict_json_loads(prepared.private_replay.private_transition_chain_bytes)
    if (
        type(plan) is not dict
        or type(universe) is not dict
        or type(spec) is not dict
        or type(transition) is not dict
        or _canonical_json_bytes(plan) != prepared.plan_bytes
        or _canonical_json_bytes(universe) != prepared.universe_bytes
        or _canonical_json_bytes(spec) != prepared.analysis_spec_bytes
        or _canonical_json_bytes(transition)
        != prepared.private_replay.private_transition_chain_bytes
        or universe.get("analysis_spec_id") != candidate.analysis_spec_id
        or universe.get("candidate_id") != candidate.candidate_id
        or universe.get("universe_id") != candidate.universe_id
    ):
        raise _error_type("Preparation audit provenance is detached.")
    policy = spec.get("missingness_policy")
    if type(policy) is not dict or policy.get("policy") not in {"error", "complete_case"}:
        raise _error_type("Preparation missingness policy is invalid.")
    if spec.get("preprocessing") != []:
        raise _error_type("Preparation preprocessing replay is unavailable.")
    if policy["policy"] != "error":
        raise _error_type("Preparation complete-case source missingness is not retained.")
    accounting = transition.get("training_accounting")
    if type(accounting) is not dict or type(accounting.get("data_accounting")) is not dict:
        raise _error_type("Preparation data accounting is unavailable.")
    data_accounting = _cast(dict[str, object], accounting["data_accounting"])
    _validate_instance(
        data_accounting,
        "canonical-records.schema.json",
        definition="DataAccounting",
    )
    canonical = prepared.canonical_dataset
    source_manifest = canonical.private.source_row_manifest
    if type(source_manifest) is not _mapping_proxy_type:
        raise _error_type("Preparation source row manifest is invalid.")
    source_indexes = source_manifest.get("source_row_index_by_internal_index")
    if type(source_indexes) is not tuple or any(type(item) is not int for item in source_indexes):
        raise _error_type("Preparation source row manifest is invalid.")
    missing_mask = canonical.private.arrays["missingness_mask"]
    missing_count = int(_np_count_nonzero(missing_mask))
    mask_entry = canonical.view.array_catalog["missingness_mask"]
    if missing_count:
        raise _error_type("Preparation error-policy source is missing values.")

    def unprefix(value: object) -> str:
        if type(value) is not str:
            raise _error_type("Preparation digest is invalid.")
        return value.removeprefix("sha256:")

    operation_instance_id = universe.get("universe_id")
    if type(operation_instance_id) is not str:
        raise _error_type("Preparation operation identity is invalid.")
    analysis_spec_sha256 = unprefix(candidate.analysis_spec_id)

    replay = prepared.private_replay
    row_manifests = (
        _persist_manifest(
            case_id=case_id,
            operation_instance_id=operation_instance_id,
            role="INPUT",
            rows=replay.source_membership,
            source_indexes=source_indexes,
        ),
        _persist_manifest(
            case_id=case_id,
            operation_instance_id=operation_instance_id,
            role="TRAINING",
            rows=replay.training_instances,
            source_indexes=source_indexes,
        ),
        _persist_manifest(
            case_id=case_id,
            operation_instance_id=operation_instance_id,
            role="OUTPUT",
            rows=replay.operation_instances,
            source_indexes=source_indexes,
        ),
        _persist_manifest(
            case_id=case_id,
            operation_instance_id=operation_instance_id,
            role="REFERENCE_FIT",
            rows=replay.training_instances,
            source_indexes=source_indexes,
        ),
    )
    row_manifest_digests = _manifest_digests(row_manifests)
    reference_chain = _authenticated_reference_chain(candidate)
    if reference_chain is None:
        raise _error_type("Preparation reference execution is unavailable.")
    readback = _readback(reference_chain.execution)
    request_indexes = readback.request_arrays.get("training_row_indexes")
    prepared_indexes = prepared.arrays.get("training_row_indexes")
    if (
        type(request_indexes) is not _np_ndarray_type
        or type(prepared_indexes) is not _np_ndarray_type
        or request_indexes.flags.writeable
        or not _np_array_equal(request_indexes, prepared_indexes)
    ):
        raise _error_type("Preparation reference request is detached.")
    response_payload = _cast(dict[str, object], readback.response["payload"])
    response_result = _cast(dict[str, object], response_payload["result"])
    participant_manifest = response_result.get("participant_event_manifest")
    _validate_instance(
        participant_manifest,
        "canonical-records.schema.json",
        definition="ParticipantEventManifest",
    )

    def all_finite(arrays: Mapping[str, object]) -> bool:
        numeric_seen = False
        for array in arrays.values():
            if type(array) is not _np_ndarray_type:
                raise _error_type("Worker array storage is invalid.")
            typed_array = _cast(_any_type_marker, array)
            if _np_issubdtype(typed_array.dtype, _np_bool_type):
                continue
            if not _np_issubdtype(typed_array.dtype, _np_number_type):
                raise _error_type("Worker array dtype is unsupported.")
            numeric_seen = True
            if not bool(_np_isfinite(typed_array).all()):
                return False
        return numeric_seen

    ordered_preprocessing = {
        "schema_version": "ebm-audit-ordered-preprocessing-refit/1.0",
        "case_id": case_id,
        "operation_instance_id": operation_instance_id,
        "analysis_spec_sha256": analysis_spec_sha256,
        "ordered_preprocessing_execution_record_sha256": [],
    }
    _validate_instance(
        ordered_preprocessing,
        "scenario-evidence.schema.json",
        definition="OrderedPreprocessingRefitDigestPreimage",
    )
    finalized_record = _strict_json_loads(candidate.finalized_record_bytes)
    _validate_instance(
        finalized_record,
        "canonical-records.schema.json",
        definition="ResultRecord",
    )
    if (
        type(finalized_record) is not dict
        or _canonical_json_bytes(finalized_record) != candidate.finalized_record_bytes
        or finalized_record.get("result_id") != candidate.result_id
    ):
        raise _error_type("Preparation finalized result is detached.")
    preimage: dict[str, object] = {
        "schema_version": "ebm-audit-preparation-audit-evidence/2.0",
        "digest_state": "DIGEST_PREIMAGE",
        "case_id": case_id,
        "operation_instance_id": operation_instance_id,
        "analysis_spec_sha256": analysis_spec_sha256,
        "input_scientific_data_sha256": unprefix(canonical.scientific_data_digest),
        "output_scientific_data_sha256": unprefix(universe["training_prepared_data_digest"]),
        "selected_event_ids": list(candidate.event_ids),
        "missingness_policy": policy["policy"],
        "source_missingness_mask_sha256": unprefix(mask_entry.array_digest),
        "source_missing_count": missing_count,
        "predicted_complete_case_removals": 0,
        "input_row_instance_manifest_sha256": row_manifest_digests[0],
        "training_row_instance_manifest_sha256": row_manifest_digests[1],
        "output_row_instance_manifest_sha256": row_manifest_digests[2],
        "reference_fit_row_instance_manifest_sha256": row_manifest_digests[3],
        "data_accounting": data_accounting,
        "ordered_preprocessing_refit_sha256": _structured_sha256_hex(
            "ebm-audit/ordered-preprocessing-refit/1", ordered_preprocessing
        ),
        "backend_invoked": True,
        "request_all_finite": all_finite(readback.request_arrays),
        "response_all_finite": all_finite(readback.response_arrays),
        "participant_event_manifest_sha256": _structured_sha256_hex(
            "ebm-audit/participant-event-manifest/1", participant_manifest
        ),
        "finalized_result_record_sha256": _structured_sha256_hex(
            "ebm-audit/finalized-result-record/1", finalized_record
        ),
        "preparation_audit_evidence_sha256": None,
    }
    _validate_instance(
        preimage,
        "scenario-evidence.schema.json",
        definition="PreparationAuditEvidenceDigestPreimage",
    )
    digest = _structured_sha256_hex("ebm-audit/preparation-audit-evidence/2", preimage)
    persisted = dict(preimage)
    persisted["digest_state"] = "PERSISTED"
    persisted["preparation_audit_evidence_sha256"] = digest
    _validate_instance(
        persisted,
        "scenario-evidence.schema.json",
        definition="PreparationAuditEvidence",
    )
    return persisted, row_manifests


def _build_preparation_audit_evidence_boundary(
    _any_type_marker: Any = Any,
    _capture_candidate_states: Callable[..., tuple[Any, ...]] = (
        _capture_preparation_transaction_candidate_states
    ),
    _capture_transaction: Callable[[object], Any] = (
        _capture_preparation_transaction_state_identity
    ),
    _cast: Any = cast,
    _canonical_json_bytes: Callable[[object], bytes] = canonical_json_bytes,
    _derive_bundle_impl: Callable[..., tuple[tuple[bytes, ...], tuple[bytes, ...]]] = (
        _derive_preparation_audit_bundle
    ),
    _derive_unavailable_records_impl: Callable[..., tuple[bytes, ...]] = (
        _derive_preparation_audit_evidence_unavailable_records
    ),
    _derive_record: Callable[..., tuple[dict[str, object], tuple[dict[str, object], ...]]] = (
        _derive_preparation_audit_record
    ),
    _error_type: type[ScientificEvidenceError] = ScientificEvidenceError,
    _evidence_states: OneShotWeakRegistry[
        PreparationAuditEvidence, _PreparationAuditEvidenceState
    ] = _PREPARATION_AUDIT_EVIDENCE_STATES,
    _evidence_by_manifest: OneShotWeakRegistry[
        PreparationRowInstanceManifests, PreparationAuditEvidence
    ] = _PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS,
    _mapping_proxy_type: Any = MappingProxyType,
    _np_array_equal: Callable[[Any, Any], Any] = np.array_equal,
    _np_bool_type: Any = np.bool_,
    _np_count_nonzero: Callable[[Any], Any] = np.count_nonzero,
    _np_isfinite: Callable[[Any], Any] = np.isfinite,
    _np_issubdtype: Callable[[Any, Any], bool] = np.issubdtype,
    _np_ndarray_type: type[np.ndarray[Any, Any]] = np.ndarray,
    _np_number_type: Any = np.number,
    _persist_manifest: Callable[..., dict[str, object]] = (
        _persist_preparation_row_instance_manifest
    ),
    _read_capture: Callable[[object], _CapturedScientificRunState] = (
        _read_captured_scientific_run
    ),
    _readback: Callable[[object], Any] = _readback_authenticated_execution,
    _resolve_prepared: Callable[[object], object] = _resolve_prepared_execution_authorization,
    _sequence_type: Any = Sequence,
    _strict_json_loads: Callable[[bytes | bytearray | memoryview], Any] = strict_json_loads,
    _structured_sha256_hex: Callable[[str, object], str] = structured_sha256_hex,
    _validate_instance: Callable[..., None] = validate_instance,
    _manifest_digests: Callable[..., tuple[str, str, str, str]] = (
        _preparation_row_instance_manifest_digests
    ),
    _authenticated_reference_chain: Callable[..., _CapturedChainState | None] = (
        _authenticated_preparation_reference_chain
    ),
    _validate_manifest_records: Callable[..., tuple[dict[str, object], ...]] = (
        _validate_preparation_row_instance_manifest_records
    ),
    _issue: Callable[
        ...,
        PreparationAuditEvidence | PreparationAuditEvidenceUnavailable,
    ] = _issue_preparation_audit_evidence,
    _read: Callable[..., tuple[dict[str, object], ...]] = (_read_preparation_audit_evidence),
    _read_unavailable: Callable[..., tuple[dict[str, object], ...]] = (
        _read_preparation_audit_evidence_unavailable
    ),
    _issue_manifests: Callable[..., PreparationRowInstanceManifests] = (
        _issue_preparation_row_instance_manifests
    ),
    _read_manifests: Callable[..., tuple[dict[str, object], ...]] = (
        _read_preparation_row_instance_manifests
    ),
) -> tuple[
    Callable[
        [object],
        PreparationAuditEvidence | PreparationAuditEvidenceUnavailable,
    ],
    Callable[[object], tuple[dict[str, object], ...]],
    Callable[[object], tuple[dict[str, object], ...]],
    Callable[[object], PreparationRowInstanceManifests],
    Callable[[object], tuple[dict[str, object], ...]],
    Callable[
        [object],
        tuple[
            tuple[dict[str, object], ...],
            PreparationRowInstanceManifests,
            tuple[dict[str, object], ...],
        ],
    ],
]:
    """Close PAE issuance over the exact definitions captured at module setup."""

    def authenticated_reference_chain(
        candidate: _CapturedCandidateState,
    ) -> _CapturedChainState | None:
        return _authenticated_reference_chain(
            candidate,
            _strict_json_loads=_strict_json_loads,
        )

    def persist_manifest(**kwargs: object) -> dict[str, object]:
        return _persist_manifest(
            **kwargs,
            _any_type_marker=_any_type_marker,
            _cast=_cast,
            _error_type=_error_type,
            _sequence_type=_sequence_type,
            _structured_sha256_hex=_structured_sha256_hex,
            _validate_instance=_validate_instance,
        )

    def manifest_digests(
        manifests: tuple[dict[str, object], ...],
    ) -> tuple[str, str, str, str]:
        return _manifest_digests(
            manifests,
            _cast=_cast,
            _error_type=_error_type,
            _structured_sha256_hex=_structured_sha256_hex,
            _validate_instance=_validate_instance,
        )

    def derive_record(
        case_id: str,
        candidate: _CapturedCandidateState,
        prepared: object,
    ) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
        return _derive_record(
            case_id,
            candidate,
            prepared,
            _canonical_json_bytes=_canonical_json_bytes,
            _readback=_readback,
            _strict_json_loads=_strict_json_loads,
            _persist_manifest=persist_manifest,
            _manifest_digests=manifest_digests,
            _authenticated_reference_chain=authenticated_reference_chain,
            _any_type_marker=_any_type_marker,
            _cast=_cast,
            _error_type=_error_type,
            _mapping_proxy_type=_mapping_proxy_type,
            _np_array_equal=_np_array_equal,
            _np_bool_type=_np_bool_type,
            _np_count_nonzero=_np_count_nonzero,
            _np_isfinite=_np_isfinite,
            _np_issubdtype=_np_issubdtype,
            _np_ndarray_type=_np_ndarray_type,
            _np_number_type=_np_number_type,
            _structured_sha256_hex=_structured_sha256_hex,
            _validate_instance=_validate_instance,
        )

    def derive_bundle(
        capture: CapturedScientificRun,
    ) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
        return _derive_bundle_impl(
            capture,
            _capture_transaction=_capture_transaction,
            _capture_candidate_states=_capture_candidate_states,
            _resolve_prepared=_resolve_prepared,
            _read_capture=_read_capture,
            _strict_json_loads=_strict_json_loads,
            _canonical_json_bytes=_canonical_json_bytes,
            _error_type=_error_type,
            _derive_record=derive_record,
        )

    def derive_unavailable_records(
        capture: CapturedScientificRun,
    ) -> tuple[bytes, ...]:
        return _derive_unavailable_records_impl(
            capture,
            _authenticated_reference_chain=authenticated_reference_chain,
            _read_capture=_read_capture,
            _strict_json_loads=_strict_json_loads,
            _canonical_json_bytes=_canonical_json_bytes,
            _error_type=_error_type,
            _structured_sha256_hex=_structured_sha256_hex,
            _validate_instance=_validate_instance,
        )

    def validate_manifest_records(
        canonical_record_bytes: tuple[bytes, ...],
        pae_records: tuple[dict[str, object], ...],
    ) -> tuple[dict[str, object], ...]:
        return _validate_manifest_records(
            canonical_record_bytes,
            pae_records,
            _canonical_json_bytes=_canonical_json_bytes,
            _strict_json_loads=_strict_json_loads,
            _cast=_cast,
            _error_type=_error_type,
            _structured_sha256_hex=_structured_sha256_hex,
            _validate_instance=_validate_instance,
        )

    def issue(
        value: object,
    ) -> PreparationAuditEvidence | PreparationAuditEvidenceUnavailable:
        return _issue(
            value,
            _derive_bundle=derive_bundle,
            _derive_unavailable_records=derive_unavailable_records,
            _read_evidence=read,
            _read_unavailable=read_unavailable,
            _cast=_cast,
            _error_type=_error_type,
        )

    def read(value: object) -> tuple[dict[str, object], ...]:
        return _read(
            value,
            _derive_bundle=derive_bundle,
            _validate_manifest_records=validate_manifest_records,
            _strict_json_loads=_strict_json_loads,
            _cast=_cast,
            _error_type=_error_type,
            _read_capture=_read_capture,
            _structured_sha256_hex=_structured_sha256_hex,
            _validate_instance=_validate_instance,
        )

    def read_unavailable(value: object) -> tuple[dict[str, object], ...]:
        return _read_unavailable(
            value,
            _canonical_json_bytes=_canonical_json_bytes,
            _derive_records=derive_unavailable_records,
            _strict_json_loads=_strict_json_loads,
            _cast=_cast,
            _error_type=_error_type,
            _read_capture=_read_capture,
            _structured_sha256_hex=_structured_sha256_hex,
            _validate_instance=_validate_instance,
        )

    def issue_manifests(value: object) -> PreparationRowInstanceManifests:
        return _issue_manifests(
            value,
            _read_evidence=read,
            _error_type=_error_type,
        )

    def read_manifests(value: object) -> tuple[dict[str, object], ...]:
        return _read_manifests(
            value,
            _read_evidence=read,
            _validate_manifest_records=validate_manifest_records,
            _error_type=_error_type,
        )

    def read_bundle(
        value: object,
    ) -> tuple[
        tuple[dict[str, object], ...],
        PreparationRowInstanceManifests,
        tuple[dict[str, object], ...],
    ]:
        """Authenticate one PAE and its exact four-role bundle once."""

        records = read(value)
        evidence = _cast(PreparationAuditEvidence, value)
        try:
            state = _evidence_states.read(evidence)
            manifests = state.row_instance_manifests
            if (
                type(manifests) is not PreparationRowInstanceManifests
                or _evidence_by_manifest.read(manifests) is not evidence
            ):
                raise _error_type("Preparation row instance manifests are detached.")
            manifest_records = validate_manifest_records(
                state.row_manifest_canonical_record_bytes,
                records,
            )
            _evidence_states.require(evidence, state)
            _evidence_by_manifest.require(manifests, evidence)
            return records, manifests, manifest_records
        except _error_type:
            raise
        except Exception as error:
            raise _error_type("Preparation audit evidence bundle is invalid.") from error

    return (
        issue,
        read,
        read_unavailable,
        issue_manifests,
        read_manifests,
        read_bundle,
    )


_preparation_audit_boundary = cast(Any, _build_preparation_audit_evidence_boundary())
(
    _issue_preparation_audit_evidence,
    _read_preparation_audit_evidence,
    _read_preparation_audit_evidence_unavailable,
    _issue_preparation_row_instance_manifests,
    _read_preparation_row_instance_manifests,
    _read_preparation_audit_evidence_bundle,
) = _preparation_audit_boundary
del _preparation_audit_boundary
del _build_preparation_audit_evidence_boundary
globals().pop("_PREPARATION_AUDIT_EVIDENCE_STATES", None)
globals().pop("_PREPARATION_AUDIT_EVIDENCE_ISSUER", None)
globals().pop("_PREPARATION_AUDIT_EVIDENCE_BY_CAPTURE", None)
globals().pop("_PREPARATION_AUDIT_EVIDENCE_BY_CAPTURE_ISSUER", None)
globals().pop("_PreparationAuditEvidenceState", None)
globals().pop("_PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS", None)
globals().pop("_PREPARATION_AUDIT_EVIDENCE_BY_ROW_MANIFESTS_ISSUER", None)
globals().pop("_PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_STATES", None)
globals().pop("_PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_ISSUER", None)
globals().pop("_PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_BY_CAPTURE", None)
globals().pop("_PREPARATION_AUDIT_EVIDENCE_UNAVAILABLE_BY_CAPTURE_ISSUER", None)
globals().pop("_PreparationAuditEvidenceUnavailableState", None)
globals().pop("_derive_preparation_audit_bundle", None)
globals().pop("_derive_preparation_audit_record", None)
globals().pop("_persist_preparation_row_instance_manifest", None)
globals().pop("_preparation_row_instance_manifest_digests", None)
globals().pop("_validate_preparation_row_instance_manifest_records", None)


_CAPTURE_METHOD_DISPATCH.bind_once(
    _METHOD_DISPATCH_ISSUER,
    cast(Callable[[object], object], capture_summary),
)
_EVIDENCE_METHOD_DISPATCH.bind_once(
    _METHOD_DISPATCH_ISSUER,
    cast(Callable[[object], object], project_scientific_evidence),
)
del capture_summary
del _build_scientific_evidence_boundary
globals().pop("_CAPTURE_METHOD_DISPATCH", None)
globals().pop("_EVIDENCE_METHOD_DISPATCH", None)
globals().pop("_METHOD_DISPATCH_ISSUER", None)
globals().pop("_ISSUE_SCIENTIFIC_LEDGER_RECEIPT", None)
globals().pop("_REQUIRE_SCIENTIFIC_LEDGER_RECEIPT", None)
globals().pop("_SCIENCE_LEDGER_RECEIPT_DIGEST_DOMAIN", None)
globals().pop("_SCIENCE_LEDGER_RECEIPT_SCHEMA_VERSION", None)
globals().pop("_OneShotMethodDispatch", None)
globals().pop("_LockedScientificType", None)
globals().pop("_lock_scientific_type", None)
globals().pop("Counter", None)
globals().pop("ConvergenceChainInput", None)
globals().pop("derive_convergence_record", None)
globals().pop("is_canonical_non_sampling_convergence_record", None)
globals().pop("_assert_array_snapshot_current", None)
globals().pop("_assert_candidate_current", None)
globals().pop("_assert_finalized_result_state_current", None)
globals().pop("_CanonicalCandidateEvidenceRecord", None)
globals().pop("_CanonicalOriginComparisonAttempt", None)
globals().pop("_CanonicalOriginNumericComparisonRecord", None)
globals().pop("_CanonicalAnalystDecisionAggregate", None)
globals().pop("_CanonicalAnalystDecisionLayerEvidence", None)
globals().pop("_CanonicalAnalystDecisionEvidenceBundle", None)
globals().pop("_CanonicalSamplingOriginAttempt", None)
globals().pop("_CanonicalSamplingNumericComparison", None)
globals().pop("_CanonicalSamplingFamilyAggregate", None)
globals().pop("_CanonicalSamplingLayerEvidence", None)
globals().pop("_CanonicalSamplingEvidenceBundle", None)
globals().pop("_CanonicalInfluenceAttempt", None)
globals().pop("_CanonicalInfluenceLayerEvidence", None)
globals().pop("_CanonicalInfluenceEvidenceBundle", None)
globals().pop("_CanonicalNullLayerEvidence", None)
globals().pop("_ChainEvidenceInput", None)
globals().pop("_AnalystDecisionCandidateInput", None)
globals().pop("_AnalystDecisionOriginInput", None)
globals().pop("_SamplingCandidateInput", None)
globals().pop("_SamplingOriginInput", None)
globals().pop("_InfluenceCandidateInput", None)
globals().pop("_InfluenceOriginInput", None)
globals().pop("_NullCandidateInput", None)
globals().pop("_derive_analyst_decision_evidence", None)
globals().pop("_derive_sampling_evidence", None)
globals().pop("_derive_influence_evidence", None)
globals().pop("_derive_null_evidence", None)
globals().pop("_validate_sampling_semantics", None)
globals().pop("_validate_influence_semantics", None)
globals().pop("_validate_null_semantics", None)
globals().pop("_candidate_event_semantics", None)
globals().pop("_candidate_origins", None)
globals().pop("_capture_array_snapshots", None)
globals().pop("_capture_candidate", None)
globals().pop("_capture_finalized_result_state", None)
globals().pop("_CAPTURE_LOCK", None)
globals().pop("_SanitizedScientificControlFlow", None)
globals().pop("_closed_mapping_bytes", None)
globals().pop("_convergence_identity", None)
globals().pop("_cross_check_tolerance_rule", None)
globals().pop("_derive_capture_state", None)
globals().pop("_derive_candidate_evidence_record", None)
globals().pop("_finalized_terminal_chain_count", None)
globals().pop("_planned_chain_count", None)
globals().pop("_readback_authenticated_execution", None)
globals().pop("_same_owner_sequence", None)
globals().pop("_sealed_result_evidence_run", None)
globals().pop("_uncertainty_layer_coverage", None)
globals().pop("OVERALL_EVIDENCE_RULE_ID", None)
globals().pop("SEALED_EVIDENCE_RULE_ID", None)
globals().pop("ANALYST_DECISION_EVIDENCE_RULE_ID", None)
globals().pop("SAMPLING_EVIDENCE_RULE_ID", None)
globals().pop("INFLUENCE_EVIDENCE_RULE_ID", None)
globals().pop("NULL_EVIDENCE_RULE_ID", None)
globals().pop("canonical_json_bytes", None)
globals().pop("strict_json_loads", None)
globals().pop("structured_sha256", None)


__all__ = [
    "CHAIN_TOP_K_RULE_ID",
    "POSITION_SUMMARY_QUANTILE_PROBABILITIES",
    "POSITION_SUMMARY_RULE_ID",
    "SCIENTIFIC_EVIDENCE_SCHEMA_VERSION",
    "CapturedScientificRun",
    "ScientificEvidenceError",
    "SealedScientificEvidence",
    "capture_scientific_run",
    "project_scientific_evidence",
    "seal_scientific_evidence",
]
