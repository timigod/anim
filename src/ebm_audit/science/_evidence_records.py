"""Private derivation of privacy-safe science-v2 aggregate records.

This module is deliberately not re-exported.  Its inputs are immutable copies
owned by :mod:`ebm_audit.science.capture`; the only public scientific-evidence
issuer accepts one exact ``CapturedScientificRun`` and no arrays, summaries, or
metric choices.
"""

from __future__ import annotations

import builtins as _builtins
import math as _math
from collections import Counter
from collections.abc import Callable
from dataclasses import FrozenInstanceError, dataclass
from typing import Any, Final, Literal, Protocol, TypeGuard
from typing import cast as _cast

import numpy as np

from ebm_audit.metrics import (
    CONVERGENCE_RULE as _CONVERGENCE_RULE,
)
from ebm_audit.metrics import (
    MatrixMetricResult,
    OrderComparison,
    PairwiseMajorityComparison,
    PairwiseMajorityResult,
    PositionSummaryResult,
    RankShiftComparison,
    ScalarMetricResult,
    TopKStabilityComparison,
)
from ebm_audit.metrics.convergence import is_canonical_non_sampling_convergence_record
from ebm_audit.metrics.core import _METRIC_KERNEL, _build_frozen_dataclass_methods
from ebm_audit.protocol.canonical import _CANONICAL_OPERATIONS

POSITION_SUMMARY_RULE_ID: Final = "inverse-empirical-cdf-fixed-q10-q25-q75-q90/1"
POSITION_SUMMARY_QUANTILE_PROBABILITIES: Final = (0.10, 0.25, 0.75, 0.90)
CHAIN_TOP_K_RULE_ID: Final = "first-min-3-events/1"
OVERALL_EVIDENCE_RULE_ID: Final = "within-fit-chain-evidence-rules/1"
CHAIN_ACCOUNTING_RULE_ID: Final = "frozen-chain-plan-terminal-available-contributing/1"
CHAIN_PAIR_DENOMINATOR_RULE_ID: Final = "unordered-distinct-chain-pairs/1"
CHAIN_PAIR_SUMMARY_RULE_ID: Final = "inverse-empirical-cdf-median-maximum/1"
WITHIN_MEAN_ENTROPY_METRIC_ID: Final = "within-fit-mean-normalized-position-entropy/1"
WITHIN_EVENT_ENTROPY_METRIC_ID: Final = "within-fit-per-event-normalized-position-entropy/1"
WITHIN_INCLUSIVE_MIDDLE_BAND_METRIC_ID: Final = (
    "within-fit-pairwise-precedence-inclusive-0.40-0.60-fraction/1"
)
WITHIN_STRICT_OUTSIDE_BAND_METRIC_ID: Final = (
    "within-fit-pairwise-precedence-strict-outside-0.25-0.75-fraction/1"
)
CENTRAL_ORDER_KENDALL_METRIC_ID: Final = "central-order-kendall/1"
POSITION_MATRIX_METRIC_ID: Final = "position-matrix/1"
PAIRWISE_PRECEDENCE_MATRIX_METRIC_ID: Final = "pairwise-precedence-matrix/1"
POSITION_CONCENTRATION_METRIC_ID: Final = "position_concentration/v1"
PAIRWISE_CONCENTRATION_METRIC_ID: Final = "pairwise_concentration/v1"
MATRIX_CROSS_CHECK_TOLERANCE_RULE_ID: Final = "scientific-matrix-allclose/1"
MATRIX_CROSS_CHECK_ABSOLUTE_TOLERANCE: Final = 1e-12
MATRIX_CROSS_CHECK_RELATIVE_TOLERANCE: Final = 1e-10
MATRIX_CROSS_CHECK_TOLERANCE_STATUS: Final = (
    "FROZEN_WITH_CROSS_PLATFORM_CHARACTERIZATION_UNVERIFIED"
)
SCIENTIFIC_CANDIDATE_RECORD_SCHEMA_VERSION: Final = "ebm-audit-scientific-candidate-evidence/1.0"
_MATRIX_CROSS_CHECK_INEQUALITY: Final = (
    "abs(observed-derived) <= absolute_tolerance + relative_tolerance * abs(derived)"
)
_UNCERTAINTY_LAYER_COVERAGE_RULE_ID: Final = "science-v2-uncertainty-layer-coverage/3"
_EVENT_SEMANTICS_RULE_ID: Final = "event-semantics-aligned-to-canonical-event-order/1"

type _LaneStatus = Literal[
    "ASSESSABLE",
    "NOT_ASSESSABLE",
    "NOT_APPLICABLE_BY_CAPABILITY",
]
type _Eligibility = Literal["INTERPRETIVE", "DESCRIPTIVE_ONLY", "UNAVAILABLE"]


class _IsExactTypeOp(Protocol):
    __module__: str
    __name__: str
    __qualname__: str

    def __call__[T](
        self,
        value: object,
        expected_type: type[T],
        /,
    ) -> TypeGuard[T]: ...


def _make_is_exact_type_op(
    type_builtin: Callable[[object], type[object]],
) -> _IsExactTypeOp:
    """Bind exact-type narrowing to the import-time builtin operation."""

    def is_exact_type[T](
        value: object,
        expected_type: type[T],
        /,
    ) -> TypeGuard[T]:
        return type_builtin(value) is expected_type

    return _cast(_IsExactTypeOp, is_exact_type)


_IS_EXACT_TYPE = _make_is_exact_type_op(type)
_IS_EXACT_TYPE.__name__ = "_IS_EXACT_TYPE"
_IS_EXACT_TYPE.__qualname__ = "_IS_EXACT_TYPE"
_IS_EXACT_TYPE.__module__ = __name__


def _make_scientific_record_integrity_error_init(
    value_error_init: Callable[..., None],
) -> Callable[..., None]:
    """Bind the privacy-safe exception message to the exact builtin base initializer."""

    def __init__(self: _ScientificRecordIntegrityError, code: str) -> None:
        self.code = code
        value_error_init(
            self,
            "Retained scientific evidence failed integrity validation.",
        )

    __init__.__qualname__ = "_ScientificRecordIntegrityError.__init__"
    return __init__


class _ScientificRecordIntegrityError(ValueError):
    """A privacy-safe failure to derive a record from retained source arrays."""

    code: str
    __init__ = _make_scientific_record_integrity_error_init(ValueError.__init__)


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalCandidateEvidenceRecord:
    """Exact canonical candidate bytes returned only by the bound deriver."""

    preimage_bytes: bytes
    canonical_bytes: bytes
    record_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _ChainEvidenceInput:
    """One closure-owned chain snapshot normalized for pure record derivation."""

    chain_plan_position: int
    chain_execution_id: str
    final_attempt_id: str
    chain_payload_digest: str
    execution_evidence_digest: str
    event_ids: tuple[str, ...]
    retained_state_count: int | None
    headline_order_event_ids: tuple[str, ...]
    headline_order_method_bytes: bytes
    order_state_chain: object | None
    position_probabilities: object | None
    pairwise_precedence: object | None
    array_digests: tuple[tuple[str, str], ...]
    thinning_interval: object = None
    postburn_unthinned_state_count: object = None
    postburn_order_state_chain: object | None = None
    postburn_likelihood_trace: object | None = None


@dataclass(frozen=True, repr=False, slots=True)
class _DerivedChain:
    source: dict[str, object]
    retained_state_count: int
    order_state_chain_digest: str
    cross_checks: dict[str, object]
    headline_order_event_ids: tuple[str, ...]
    headline_order_method: dict[str, object]
    headline_order_method_bytes: bytes
    retained_state_modal_order_event_ids: tuple[str, ...]
    order_samples: tuple[tuple[str, ...], ...]
    position_probabilities: np.ndarray[Any, Any]
    pairwise_precedence: np.ndarray[Any, Any]


@dataclass(frozen=True, slots=True)
class _CandidateEvidenceKernel:
    """Exact import-time candidate, coverage, and tolerance operations."""

    _integrity: Callable[[str], _ScientificRecordIntegrityError]
    _scalar: Callable[..., dict[str, object]]
    _unavailable_scalar: Callable[..., dict[str, object]]
    _matrix_value: Callable[..., np.ndarray[Any, Any]]
    _source: Callable[[_ChainEvidenceInput], dict[str, object]]
    _cross_check_tolerance_rule: Callable[[], dict[str, object]]
    _cross_check_tolerance_binding: Callable[[], dict[str, object]]
    _convergence_rule: Callable[[], dict[str, object]]
    _uncertainty_layer_coverage: Callable[..., dict[str, object]]
    _array_digest: Callable[[_ChainEvidenceInput, str], str | None]
    _core_derived_provenance: Callable[..., dict[str, object]]
    _matrix_cross_check: Callable[..., dict[str, object]]
    _orders: Callable[..., tuple[tuple[str, ...], ...] | None]
    _central_order: Callable[[tuple[tuple[str, ...], ...]], tuple[str, ...]]
    _same_matrix: Callable[[object, np.ndarray[Any, Any]], bool]
    _derive_chain: Callable[[_ChainEvidenceInput], _DerivedChain | None]
    _position_summaries: Callable[[PositionSummaryResult], dict[str, object]]
    _majorities: Callable[[PairwiseMajorityResult], dict[str, object]]
    _within_entropy_metrics: Callable[..., tuple[dict[str, object], dict[str, object]]]
    _within_pairwise_band_metrics: Callable[..., tuple[dict[str, object], dict[str, object]]]
    _rank_shifts: Callable[[RankShiftComparison], dict[str, object]]
    _top_k: Callable[[TopKStabilityComparison], dict[str, object]]
    _flips: Callable[[PairwiseMajorityComparison], dict[str, object]]
    _chain_accounting: Callable[..., dict[str, object]]
    _empty_chain_metric_summary: Callable[..., dict[str, object]]
    _absence: Callable[..., dict[str, object]]
    _within_fit: Callable[..., dict[str, object]]
    _order_diagnostics: Callable[..., dict[str, object]]
    _chain_pair: Callable[..., dict[str, object]]
    _convergence_record: Callable[
        [bytes | None],
        tuple[dict[str, object], dict[str, object] | None],
    ]
    _scalar_value: Callable[..., float]
    _within_tolerance: Callable[[float, float], bool]
    _convergence_pair_value: Callable[..., float]
    _convergence_summary_cross_check: Callable[..., dict[str, object]]
    _convergence_binding_reference: Callable[..., dict[str, object]]
    _convergence_relationship: Callable[..., dict[str, object]]
    _chain_metric_summary: Callable[..., dict[str, object]]
    _chain: Callable[..., dict[str, object]]
    _eligibility: Callable[[str], _Eligibility]
    _terminal_absence_status: Callable[[str], _LaneStatus]
    _terminal_reason: Callable[[str], str]
    _event_semantics_record: Callable[..., dict[str, object]]
    _derive_candidate_evidence_record: Callable[..., _CanonicalCandidateEvidenceRecord]


_FROZEN_CANDIDATE_CLASSES = (
    _CanonicalCandidateEvidenceRecord,
    _ChainEvidenceInput,
    _DerivedChain,
    _CandidateEvidenceKernel,
)
for _frozen_class_type in _FROZEN_CANDIDATE_CLASSES:
    _frozen_methods = _build_frozen_dataclass_methods(
        class_type=_frozen_class_type,
        field_names=tuple(_frozen_class_type.__dataclass_fields__),
        frozenset_op=frozenset,
        frozen_instance_error_type=FrozenInstanceError,
        getattr_op=getattr,
        hash_op=hash,
        not_implemented=NotImplemented,
        super_op=super,
        tuple_type=tuple,
        type_op=type,
    )
    for _method_name, _method in (
        ("__eq__", _frozen_methods.eq),
        ("__hash__", _frozen_methods.hash),
        ("__setattr__", _frozen_methods.setattr),
        ("__delattr__", _frozen_methods.delattr),
    ):
        _method.__name__ = _method_name
        _method.__qualname__ = f"{_frozen_class_type.__qualname__}.{_method_name}"
        _method.__module__ = __name__
        setattr(_frozen_class_type, _method_name, _method)


def _build_candidate_evidence_kernel(
    *,
    canonical_json_bytes: Callable[[object], bytes],
    strict_json_loads: Callable[[bytes | bytearray | memoryview], Any],
    structured_sha256: Callable[[str, object], str],
    empirical_quantile: Callable[..., ScalarMetricResult],
    pairwise_concentration: Callable[..., ScalarMetricResult],
    pairwise_matrix_distance: Callable[..., ScalarMetricResult],
    pairwise_precedence_matrix: Callable[..., MatrixMetricResult],
    per_event_rank_shifts: Callable[..., RankShiftComparison],
    position_concentration: Callable[..., ScalarMetricResult],
    position_event_summaries: Callable[..., PositionSummaryResult],
    position_matrix: Callable[..., MatrixMetricResult],
    position_matrix_distance: Callable[..., ScalarMetricResult],
    strict_order_comparison: Callable[..., OrderComparison],
    strict_pairwise_majority_flips: Callable[..., PairwiseMajorityComparison],
    strict_pairwise_majority_relations: Callable[..., PairwiseMajorityResult],
    top_k_stability: Callable[..., TopKStabilityComparison],
    integrity_error_type: _builtins.type[_ScientificRecordIntegrityError],
    candidate_record_type: _builtins.type[_CanonicalCandidateEvidenceRecord],
    derived_chain_type: _builtins.type[_DerivedChain],
    CONVERGENCE_RULE: Any,
    is_canonical_non_sampling_convergence_record: Callable[[object], bool],
    POSITION_SUMMARY_RULE_ID: str,
    POSITION_SUMMARY_QUANTILE_PROBABILITIES: tuple[float, ...],
    CHAIN_TOP_K_RULE_ID: str,
    OVERALL_EVIDENCE_RULE_ID: str,
    CHAIN_ACCOUNTING_RULE_ID: str,
    CHAIN_PAIR_DENOMINATOR_RULE_ID: str,
    CHAIN_PAIR_SUMMARY_RULE_ID: str,
    WITHIN_MEAN_ENTROPY_METRIC_ID: str,
    WITHIN_EVENT_ENTROPY_METRIC_ID: str,
    WITHIN_INCLUSIVE_MIDDLE_BAND_METRIC_ID: str,
    WITHIN_STRICT_OUTSIDE_BAND_METRIC_ID: str,
    CENTRAL_ORDER_KENDALL_METRIC_ID: str,
    POSITION_MATRIX_METRIC_ID: str,
    PAIRWISE_PRECEDENCE_MATRIX_METRIC_ID: str,
    POSITION_CONCENTRATION_METRIC_ID: str,
    PAIRWISE_CONCENTRATION_METRIC_ID: str,
    MATRIX_CROSS_CHECK_TOLERANCE_RULE_ID: str,
    MATRIX_CROSS_CHECK_ABSOLUTE_TOLERANCE: float,
    MATRIX_CROSS_CHECK_RELATIVE_TOLERANCE: float,
    MATRIX_CROSS_CHECK_TOLERANCE_STATUS: str,
    SCIENTIFIC_CANDIDATE_RECORD_SCHEMA_VERSION: str,
    _MATRIX_CROSS_CHECK_INEQUALITY: str,
    _UNCERTAINTY_LAYER_COVERAGE_RULE_ID: str,
    _EVENT_SEMANTICS_RULE_ID: str,
    Counter: _builtins.type[Counter[Any]],
    math_comb: Callable[[int, int], int],
    math_isfinite: Callable[[float], bool],
    np_allclose: Callable[..., Any],
    np_dtype: Callable[[Any], np.dtype[Any]],
    np_float64: type[np.float64],
    np_int32: type[np.int32],
    np_isclose: Callable[..., Any],
    np_ndarray_type: _builtins.type[np.ndarray[Any, Any]],
    is_exact_type: _IsExactTypeOp,
    abs: Callable[[Any], Any],
    all: Callable[[Any], bool],
    any: Callable[[Any], bool],
    bool: _builtins.type[bool],
    dict: _builtins.type[dict[Any, Any]],
    enumerate: Callable[..., Any],
    float: _builtins.type[float],
    int: _builtins.type[int],
    len: Callable[[Any], int],
    list: _builtins.type[list[Any]],
    max: Callable[..., Any],
    min: Callable[..., Any],
    next: Callable[..., Any],
    object: _builtins.type[object],
    range: _builtins.type[range],
    set: _builtins.type[set[Any]],
    sorted: Callable[..., list[Any]],
    str: _builtins.type[str],
    sum: Callable[..., Any],
    tuple: _builtins.type[tuple[Any, ...]],
    zip: Callable[..., Any],
) -> _CandidateEvidenceKernel:
    """Build one explicit closure graph from exact immutable operation leaves."""

    def _integrity(code: _builtins.str) -> _ScientificRecordIntegrityError:
        error: _ScientificRecordIntegrityError = integrity_error_type(code)
        return error

    def _scalar(
        result: ScalarMetricResult,
        *,
        metric_id: _builtins.str,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        return {
            "metric_id": metric_id,
            "status": result.status,
            "value": result.value,
            "reason_code": result.reason_code,
            "metadata_code": result.metadata_code,
        }

    def _unavailable_scalar(
        *,
        metric_id: _builtins.str,
        status: _LaneStatus = "NOT_ASSESSABLE",
        reason_code: _builtins.str,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        return {
            "metric_id": metric_id,
            "status": status,
            "value": None,
            "reason_code": reason_code,
            "metadata_code": None,
        }

    def _matrix_value(result: MatrixMetricResult, *, code: _builtins.str) -> np.ndarray[Any, Any]:
        if result.status != "ASSESSABLE" or result.value is None:
            raise _integrity(code)
        return result.value

    def _source(chain: _ChainEvidenceInput) -> _builtins.dict[_builtins.str, _builtins.object]:
        return {
            "chain_plan_position": chain.chain_plan_position,
            "chain_execution_id": chain.chain_execution_id,
            "final_attempt_id": chain.final_attempt_id,
            "chain_payload_digest": chain.chain_payload_digest,
            "execution_evidence_digest": chain.execution_evidence_digest,
        }

    def _cross_check_tolerance_rule() -> _builtins.dict[_builtins.str, _builtins.object]:
        preimage: _builtins.dict[_builtins.str, _builtins.object] = {
            "rule_id": MATRIX_CROSS_CHECK_TOLERANCE_RULE_ID,
            "status": MATRIX_CROSS_CHECK_TOLERANCE_STATUS,
            "absolute_tolerance": MATRIX_CROSS_CHECK_ABSOLUTE_TOLERANCE,
            "relative_tolerance": MATRIX_CROSS_CHECK_RELATIVE_TOLERANCE,
            "inequality": _MATRIX_CROSS_CHECK_INEQUALITY,
        }
        return {
            **preimage,
            "rule_digest": structured_sha256(
                "ebm-audit/scientific-matrix-cross-check-rule/1",
                preimage,
            ),
        }

    def _cross_check_tolerance_binding() -> _builtins.dict[_builtins.str, _builtins.object]:
        rule = _cross_check_tolerance_rule()
        return {
            "rule_id": rule["rule_id"],
            "rule_digest": rule["rule_digest"],
        }

    def _convergence_rule() -> _builtins.dict[_builtins.str, _builtins.object]:
        preimage: _builtins.dict[_builtins.str, _builtins.object] = {
            "rule_schema_version": CONVERGENCE_RULE.rule_schema_version,
            "rule_id": CONVERGENCE_RULE.rule_id,
            "rule_status": CONVERGENCE_RULE.rule_status,
            "assessable_min_independent_chains": (
                CONVERGENCE_RULE.assessable_min_independent_chains
            ),
            "assessable_min_unthinned_postburn_states_per_chain": (
                CONVERGENCE_RULE.assessable_min_unthinned_postburn_states_per_chain
            ),
            "pass_transition_rate_exclusive_min": (
                CONVERGENCE_RULE.pass_transition_rate_exclusive_min
            ),
            "pass_median_position_distance_max": (
                CONVERGENCE_RULE.pass_median_position_distance_max
            ),
            "pass_max_position_distance_max": (CONVERGENCE_RULE.pass_max_position_distance_max),
            "pass_median_precedence_distance_max": (
                CONVERGENCE_RULE.pass_median_precedence_distance_max
            ),
            "fail_combined_max_position_distance_over": (
                CONVERGENCE_RULE.fail_combined_max_position_distance_over
            ),
            "fail_combined_max_kendall_distance_over": (
                CONVERGENCE_RULE.fail_combined_max_kendall_distance_over
            ),
            "fail_invalid_or_nonfinite_samples": (
                CONVERGENCE_RULE.fail_invalid_or_nonfinite_samples
            ),
            "fail_stuck_chains_in_distinct_states": (
                CONVERGENCE_RULE.fail_stuck_chains_in_distinct_states
            ),
            "likelihood_drift_role": CONVERGENCE_RULE.likelihood_drift_role,
        }
        return {
            **preimage,
            "rule_digest": structured_sha256(
                "ebm-audit/convergence-rule/1",
                preimage,
            ),
        }

    def _uncertainty_layer_coverage(
        candidate_records: _builtins.tuple[_builtins.dict[_builtins.str, _builtins.object], ...],
        sampling_evidence: _builtins.dict[_builtins.str, _builtins.object],
        analyst_decision_evidence: _builtins.dict[_builtins.str, _builtins.object],
        participant_influence_evidence: _builtins.dict[
            _builtins.str,
            _builtins.object,
        ],
        null_evidence: _builtins.dict[_builtins.str, _builtins.object],
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        """Build the sole run-level six-layer implementation/evidence ledger."""

        def component_status(
            coverage: _builtins.list[_builtins.object],
            *,
            pending_reason: _builtins.str,
        ) -> _builtins.tuple[_builtins.str, _builtins.str | None]:
            if not coverage or any(
                not is_exact_type(row, dict)
                or not is_exact_type(row.get("implementation_status"), str)
                or row.get("implementation_status")
                not in {"IMPLEMENTED", "PENDING_IMPLEMENTATION"}
                or (
                    row.get("implementation_status") == "IMPLEMENTED"
                    and row.get("reason_code") is not None
                )
                or (
                    row.get("implementation_status") != "IMPLEMENTED"
                    and not is_exact_type(row.get("reason_code"), str)
                )
                for row in coverage
            ):
                raise _integrity("SCIENCE.UNCERTAINTY_LAYER_COVERAGE")
            if all(
                is_exact_type(row, dict)
                and row.get("implementation_status") == "IMPLEMENTED"
                for row in coverage
            ):
                return "IMPLEMENTED", None
            return "PARTIALLY_IMPLEMENTED", pending_reason

        rows: _builtins.list[_builtins.dict[_builtins.str, _builtins.object]] = []
        for layer, field in (("WITHIN_FIT", "within_fit"), ("CHAIN", "chain")):
            evidence: _builtins.list[_builtins.dict[_builtins.str, _builtins.object]] = []
            for candidate in candidate_records:
                candidate_evidence = candidate.get(field)
                if (
                    not is_exact_type(candidate.get("candidate_ordinal"), int)
                    or not is_exact_type(candidate_evidence, dict)
                    or not is_exact_type(candidate_evidence.get("status"), str)
                ):
                    raise _integrity("SCIENCE.UNCERTAINTY_LAYER_COVERAGE")
                evidence.append(
                    {
                        "candidate_ordinal": candidate["candidate_ordinal"],
                        "status": candidate_evidence["status"],
                        "reason_code": candidate_evidence.get("reason_code"),
                    }
                )
            rows.append(
                {
                    "layer": layer,
                    "implementation_status": "IMPLEMENTED",
                    "evidence": evidence,
                    "reason_code": None,
                }
            )
        sampling_component_coverage = sampling_evidence.get("component_coverage")
        sampling_layer_digest = sampling_evidence.get("layer_digest")
        if not is_exact_type(sampling_component_coverage, list) or not is_exact_type(
            sampling_layer_digest,
            str,
        ):
            raise _integrity("SCIENCE.UNCERTAINTY_LAYER_COVERAGE")
        sampling_status, sampling_reason = component_status(
            sampling_component_coverage,
            pending_reason="SCIENCE.SAMPLING_COMPONENTS_PENDING",
        )
        rows.append(
            {
                "layer": "SAMPLING",
                "implementation_status": sampling_status,
                "evidence": {
                    "layer_digest": sampling_layer_digest,
                    "component_coverage": sampling_component_coverage,
                },
                "reason_code": sampling_reason,
            }
        )
        component_coverage = analyst_decision_evidence.get("component_coverage")
        layer_digest = analyst_decision_evidence.get("layer_digest")
        if not is_exact_type(component_coverage, list) or not is_exact_type(
            layer_digest,
            str,
        ):
            raise _integrity("SCIENCE.UNCERTAINTY_LAYER_COVERAGE")
        analyst_status, analyst_reason = component_status(
            component_coverage,
            pending_reason="SCIENCE.ANALYST_DECISION_COMPONENTS_PENDING",
        )
        if (
            analyst_decision_evidence.get("implementation_status") != analyst_status
            or analyst_decision_evidence.get("reason_code") != analyst_reason
        ):
            raise _integrity("SCIENCE.UNCERTAINTY_LAYER_COVERAGE")
        rows.append(
            {
                "layer": "ANALYST_DECISION",
                "implementation_status": analyst_status,
                "evidence": {
                    "layer_digest": layer_digest,
                    "component_coverage": component_coverage,
                },
                "reason_code": analyst_reason,
            }
        )
        influence_layer_digest = participant_influence_evidence.get("layer_digest")
        influence_planned_origin_count = participant_influence_evidence.get("planned_origin_count")
        influence_attempt_count = participant_influence_evidence.get("attempt_count")
        influence_record_count = participant_influence_evidence.get("influence_record_count")
        influence_contribution_counts = participant_influence_evidence.get("contribution_counts")
        influence_classification_status = participant_influence_evidence.get(
            "classification_status"
        )
        if (
            not is_exact_type(influence_layer_digest, str)
            or not is_exact_type(influence_planned_origin_count, int)
            or influence_planned_origin_count < 0
            or not is_exact_type(influence_attempt_count, int)
            or influence_attempt_count < 0
            or influence_attempt_count != influence_planned_origin_count
            or not is_exact_type(influence_record_count, int)
            or influence_record_count < 0
            or influence_record_count > influence_attempt_count
            or not is_exact_type(influence_contribution_counts, dict)
            or set(influence_contribution_counts)
            != {
                "INTERPRETIVE",
                "DESCRIPTIVE_ONLY",
                "METRIC_NOT_ASSESSABLE",
                "FAILED",
            }
            or any(
                not is_exact_type(count, int) or count < 0
                for count in influence_contribution_counts.values()
            )
            or sum(influence_contribution_counts.values()) != influence_attempt_count
            or influence_classification_status
            != "FROZEN_REVIEWED_WITH_DEVELOPMENT_SENSITIVITY_UNVERIFIED"
        ):
            raise _integrity("SCIENCE.UNCERTAINTY_LAYER_COVERAGE")
        rows.append(
            {
                "layer": "PARTICIPANT_INFLUENCE",
                "implementation_status": "IMPLEMENTED",
                "evidence": {
                    "layer_digest": influence_layer_digest,
                    "planned_origin_count": influence_planned_origin_count,
                    "attempt_count": influence_attempt_count,
                    "influence_record_count": influence_record_count,
                    "contribution_counts": influence_contribution_counts,
                    "classification_status": influence_classification_status,
                },
                "reason_code": None,
            }
        )
        null_layer_digest = null_evidence.get("layer_digest")
        null_component_coverage = null_evidence.get("component_coverage")
        null_attempt_count = null_evidence.get("attempt_count")
        null_family_count = null_evidence.get("family_count")
        null_terminal_status_counts = null_evidence.get("terminal_status_counts")
        if (
            not is_exact_type(null_layer_digest, str)
            or not is_exact_type(null_component_coverage, list)
            or not is_exact_type(null_attempt_count, int)
            or null_attempt_count < 0
            or not is_exact_type(null_family_count, int)
            or null_family_count < 0
            or null_family_count > null_attempt_count
            or not is_exact_type(null_terminal_status_counts, list)
            or null_evidence.get("calibration_state") != "UNCALIBRATED"
            or null_evidence.get("null_relative_label") != "NULL_CALIBRATION_NOT_VALIDATED"
            or null_evidence.get("held_out_false_positive_rate_eligible") is not False
            or null_evidence.get("strong_null_relative_language_eligible") is not False
        ):
            raise _integrity("SCIENCE.UNCERTAINTY_LAYER_COVERAGE")
        rows.append(
            {
                "layer": "NULL",
                "implementation_status": "PARTIALLY_IMPLEMENTED",
                "evidence": {
                    "layer_digest": null_layer_digest,
                    "component_coverage": null_component_coverage,
                    "attempt_count": null_attempt_count,
                    "family_count": null_family_count,
                    "terminal_status_counts": null_terminal_status_counts,
                    "calibration_state": "UNCALIBRATED",
                    "null_relative_label": "NULL_CALIBRATION_NOT_VALIDATED",
                    "held_out_false_positive_rate_eligible": False,
                    "strong_null_relative_language_eligible": False,
                },
                "reason_code": (
                    "NULL_CALIBRATION_NOT_VALIDATED"
                    if null_attempt_count
                    else "SCIENCE.NULL_FAMILIES_NOT_PLANNED"
                ),
            }
        )
        preimage: _builtins.dict[_builtins.str, _builtins.object] = {
            "rule_id": _UNCERTAINTY_LAYER_COVERAGE_RULE_ID,
            "layers": rows,
        }
        return {
            **preimage,
            "coverage_digest": structured_sha256(
                "ebm-audit/uncertainty-layer-coverage/3",
                preimage,
            ),
        }

    def _array_digest(chain: _ChainEvidenceInput, name: _builtins.str) -> _builtins.str | None:
        matches = [digest for current_name, digest in chain.array_digests if current_name == name]
        if len(matches) > 1:
            raise _integrity("SCIENCE.ARRAY_DIGEST_IDENTITY")
        return matches[0] if matches else None

    def _core_derived_provenance(
        *chains: _DerivedChain,
        method_id: _builtins.str,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        return {
            "origin": "CORE_DERIVED",
            "method_id": method_id,
            "source_fields": ["order_state_chain"],
            "source_hashes": [chain.order_state_chain_digest for chain in chains],
        }

    def _matrix_cross_check(
        chain: _ChainEvidenceInput,
        *,
        array_name: Literal["position_probabilities", "pairwise_precedence"],
        observed: _builtins.object | None,
        derived: np.ndarray[Any, Any],
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        observed_digest = _array_digest(chain, array_name)
        if observed is None:
            if observed_digest is not None:
                raise _integrity("SCIENCE.CROSS_CHECK_DIGEST_WITHOUT_ARRAY")
            return {
                "status": "NOT_PROVIDED",
                "observed_array_digest": None,
                "tolerance_rule_binding": _cross_check_tolerance_binding(),
            }
        if observed_digest is None:
            raise _integrity("SCIENCE.CROSS_CHECK_ARRAY_WITHOUT_DIGEST")
        if not _same_matrix(observed, derived):
            raise _integrity(f"SCIENCE.{array_name.upper()}_SOURCE_MISMATCH")
        return {
            "status": "PASS",
            "observed_array_digest": observed_digest,
            "tolerance_rule_binding": _cross_check_tolerance_binding(),
        }

    def _orders(
        value: _builtins.object,
        *,
        event_ids: _builtins.tuple[_builtins.str, ...],
    ) -> _builtins.tuple[_builtins.tuple[_builtins.str, ...], ...] | None:
        if (
            not is_exact_type(value, np_ndarray_type)
            or value.dtype != np_dtype(np_int32)
            or value.ndim != 2
            or value.shape[0] == 0
            or value.shape[1] != len(event_ids)
        ):
            return None
        expected = list(range(len(event_ids)))
        orders: _builtins.list[_builtins.tuple[_builtins.str, ...]] = []
        for row in value:
            indexes = [int(index) for index in row]
            if sorted(indexes) != expected:
                return None
            orders.append(tuple(event_ids[index] for index in indexes))
        return tuple(orders)

    def _central_order(
        orders: _builtins.tuple[_builtins.tuple[_builtins.str, ...], ...],
    ) -> _builtins.tuple[_builtins.str, ...]:
        counts = Counter(orders)
        maximum = max(counts.values())
        central_order: _builtins.tuple[_builtins.str, ...] = min(
            (order for order, count in counts.items() if count == maximum),
            key=lambda order: tuple(event_id.encode("utf-8") for event_id in order),
        )
        return central_order

    def _same_matrix(left: _builtins.object, right: np.ndarray[Any, Any]) -> _builtins.bool:
        return (
            is_exact_type(left, np_ndarray_type)
            and left.dtype == np_dtype(np_float64)
            and left.shape == right.shape
            and bool(
                np_allclose(
                    left,
                    right,
                    atol=MATRIX_CROSS_CHECK_ABSOLUTE_TOLERANCE,
                    rtol=MATRIX_CROSS_CHECK_RELATIVE_TOLERANCE,
                )
            )
        )

    def _derive_chain(chain: _ChainEvidenceInput) -> _DerivedChain | None:
        orders = _orders(chain.order_state_chain, event_ids=chain.event_ids)
        if orders is None:
            return None
        if chain.retained_state_count != len(orders):
            raise _integrity("SCIENCE.RETAINED_STATE_ACCOUNTING")
        if len(chain.headline_order_event_ids) != len(chain.event_ids) or set(
            chain.headline_order_event_ids
        ) != set(chain.event_ids):
            raise _integrity("SCIENCE.HEADLINE_ORDER_IDENTITY")
        headline_method = strict_json_loads(chain.headline_order_method_bytes)
        if (
            not is_exact_type(headline_method, dict)
            or set(headline_method)
            != {
                "method_id",
                "candidate_source",
                "objective_id",
                "tie_break_rule",
            }
            or headline_method.get("method_id")
            not in {"retained-state-mode/1", "backend-objective-maximum/1"}
            or headline_method.get("tie_break_rule")
            != "lexicographically-smallest-event-id-sequence/1"
        ):
            raise _integrity("SCIENCE.HEADLINE_ORDER_METHOD")
        if headline_method["method_id"] == "retained-state-mode/1":
            if (
                headline_method.get("candidate_source") != "retained_order_state_chain"
                or headline_method.get("objective_id") is not None
            ):
                raise _integrity("SCIENCE.HEADLINE_ORDER_METHOD")
        elif headline_method.get(
            "candidate_source"
        ) != "backend_explored_order_set" or not is_exact_type(
            headline_method.get("objective_id"), str
        ):
            raise _integrity("SCIENCE.HEADLINE_ORDER_METHOD")
        modal_order = _central_order(orders)
        if (
            headline_method["method_id"] == "retained-state-mode/1"
            and chain.headline_order_event_ids != modal_order
        ):
            raise _integrity("SCIENCE.RETAINED_MODE_HEADLINE_MISMATCH")
        position = _matrix_value(
            position_matrix(orders, chain.event_ids),
            code="SCIENCE.POSITION_DERIVATION",
        )
        precedence = _matrix_value(
            pairwise_precedence_matrix(orders, chain.event_ids),
            code="SCIENCE.PAIRWISE_DERIVATION",
        )
        order_state_chain_digest = _array_digest(chain, "order_state_chain")
        if order_state_chain_digest is None:
            raise _integrity("SCIENCE.ORDER_STATE_CHAIN_DIGEST")
        cross_checks: _builtins.dict[_builtins.str, _builtins.object] = {
            "position_probabilities": _matrix_cross_check(
                chain,
                array_name="position_probabilities",
                observed=chain.position_probabilities,
                derived=position,
            ),
            "pairwise_precedence": _matrix_cross_check(
                chain,
                array_name="pairwise_precedence",
                observed=chain.pairwise_precedence,
                derived=precedence,
            ),
        }
        return derived_chain_type(
            source=_source(chain),
            retained_state_count=len(orders),
            order_state_chain_digest=order_state_chain_digest,
            cross_checks=cross_checks,
            headline_order_event_ids=chain.headline_order_event_ids,
            headline_order_method=headline_method,
            headline_order_method_bytes=chain.headline_order_method_bytes,
            retained_state_modal_order_event_ids=modal_order,
            order_samples=orders,
            position_probabilities=position,
            pairwise_precedence=precedence,
        )

    def _position_summaries(
        result: PositionSummaryResult,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        if result.status != "ASSESSABLE" or result.value is None:
            return {
                "rule_id": POSITION_SUMMARY_RULE_ID,
                "status": result.status,
                "value": None,
                "reason_code": result.reason_code,
            }
        return {
            "rule_id": POSITION_SUMMARY_RULE_ID,
            "metric_ids": {
                "probability_by_position": "event-position-probability/1",
                "expected_position": "event-expected-position/1",
                "median_position": "event-position-inverse-empirical-cdf/1",
                "quantile_position": "event-position-inverse-empirical-cdf/1",
                "interquartile_range": "event-position-interquartile-range/1",
                "normalized_entropy": WITHIN_EVENT_ENTROPY_METRIC_ID,
            },
            "status": "ASSESSABLE",
            "value": [
                {
                    "event_id": summary.event_id,
                    "probability_by_position": list(summary.probability_by_position),
                    "expected_position": summary.expected_position,
                    "median_position": summary.median_position,
                    "q10_position": next(
                        item.position for item in summary.quantiles if item.probability == 0.10
                    ),
                    "q90_position": next(
                        item.position for item in summary.quantiles if item.probability == 0.90
                    ),
                    "interquartile_range": (
                        next(
                            item.position for item in summary.quantiles if item.probability == 0.75
                        )
                        - next(
                            item.position for item in summary.quantiles if item.probability == 0.25
                        )
                    ),
                    "quantiles": [
                        {
                            "probability": quantile.probability,
                            "position": quantile.position,
                        }
                        for quantile in summary.quantiles
                    ],
                    "normalized_entropy": summary.normalized_entropy,
                    "metadata_code": summary.metadata_code,
                }
                for summary in result.value
            ],
            "reason_code": None,
        }

    def _majorities(
        result: PairwiseMajorityResult,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        if result.status != "ASSESSABLE" or result.value is None:
            return {
                "metric_id": "pairwise-precedence-probability/1",
                "relation_rule_id": "strict-pairwise-majority-relation/1",
                "status": result.status,
                "value": None,
                "reason_code": result.reason_code,
            }
        return {
            "metric_id": "pairwise-precedence-probability/1",
            "relation_rule_id": "strict-pairwise-majority-relation/1",
            "status": "ASSESSABLE",
            "value": [
                {
                    "event_a_id": item.event_a_id,
                    "event_b_id": item.event_b_id,
                    "probability_a_before_b": item.probability_a_before_b,
                    "relation": item.relation,
                }
                for item in result.value
            ],
            "reason_code": None,
        }

    def _within_entropy_metrics(
        result: PositionSummaryResult,
    ) -> _builtins.tuple[
        _builtins.dict[_builtins.str, _builtins.object],
        _builtins.dict[_builtins.str, _builtins.object],
    ]:
        if result.status != "ASSESSABLE" or result.value is None or not result.value:
            reason_code = result.reason_code or "WITHIN_FIT.POSITION_ENTROPY_UNAVAILABLE"
            return (
                _unavailable_scalar(
                    metric_id=WITHIN_MEAN_ENTROPY_METRIC_ID,
                    reason_code=reason_code,
                ),
                {
                    "metric_id": WITHIN_EVENT_ENTROPY_METRIC_ID,
                    "status": "NOT_ASSESSABLE",
                    "event_count": 0,
                    "values": None,
                    "reason_code": reason_code,
                },
            )
        rows = [
            {
                "event_id": summary.event_id,
                "value": summary.normalized_entropy,
                "metadata_code": summary.metadata_code,
            }
            for summary in result.value
        ]
        values = [float(summary.normalized_entropy) for summary in result.value]
        if any(not math_isfinite(value) for value in values):
            raise _integrity("SCIENCE.WITHIN_POSITION_ENTROPY")
        mean_metadata_code = (
            "DEGENERATE_ONE_EVENT"
            if len(result.value) == 1 and result.value[0].metadata_code == "DEGENERATE_ONE_EVENT"
            else None
        )
        return (
            {
                "metric_id": WITHIN_MEAN_ENTROPY_METRIC_ID,
                "status": "ASSESSABLE",
                "value": sum(values) / len(values),
                "reason_code": None,
                "metadata_code": mean_metadata_code,
                "event_denominator": len(values),
                "mean_rule_id": "arithmetic-mean-over-planned-events/1",
            },
            {
                "metric_id": WITHIN_EVENT_ENTROPY_METRIC_ID,
                "status": "ASSESSABLE",
                "event_count": len(rows),
                "values": rows,
                "reason_code": None,
            },
        )

    def _within_pairwise_band_metrics(
        pairwise_precedence: np.ndarray[Any, Any],
    ) -> _builtins.tuple[
        _builtins.dict[_builtins.str, _builtins.object],
        _builtins.dict[_builtins.str, _builtins.object],
    ]:
        if (
            pairwise_precedence.dtype != np_dtype(np_float64)
            or pairwise_precedence.ndim != 2
            or pairwise_precedence.shape[0] != pairwise_precedence.shape[1]
            or pairwise_precedence.shape[0] < 1
        ):
            raise _integrity("SCIENCE.WITHIN_PAIRWISE_BANDS")
        event_count = int(pairwise_precedence.shape[0])
        values = [
            float(pairwise_precedence[left, right])
            for left in range(event_count - 1)
            for right in range(left + 1, event_count)
        ]
        denominator = math_comb(event_count, 2)
        if denominator == 0:
            reason_code = "WITHIN_FIT.FEWER_THAN_TWO_EVENTS"
            return (
                {
                    "metric_id": WITHIN_INCLUSIVE_MIDDLE_BAND_METRIC_ID,
                    "status": "NOT_ASSESSABLE",
                    "value": None,
                    "numerator": None,
                    "unordered_pair_denominator": 0,
                    "denominator_rule_id": "unordered-distinct-event-pairs/1",
                    "lower_bound": 0.40,
                    "upper_bound": 0.60,
                    "lower_bound_inclusive": True,
                    "upper_bound_inclusive": True,
                    "report_exposure": "INTERNAL_CLASSIFIER_INPUT_ONLY",
                    "reason_code": reason_code,
                },
                {
                    "metric_id": WITHIN_STRICT_OUTSIDE_BAND_METRIC_ID,
                    "status": "NOT_ASSESSABLE",
                    "value": None,
                    "numerator": None,
                    "unordered_pair_denominator": 0,
                    "denominator_rule_id": "unordered-distinct-event-pairs/1",
                    "lower_bound": 0.25,
                    "upper_bound": 0.75,
                    "lower_bound_inclusive": False,
                    "upper_bound_inclusive": False,
                    "report_exposure": "INTERNAL_CLASSIFIER_INPUT_ONLY",
                    "reason_code": reason_code,
                },
            )
        if len(values) != denominator or any(
            not math_isfinite(value) or not 0.0 <= value <= 1.0 for value in values
        ):
            raise _integrity("SCIENCE.WITHIN_PAIRWISE_BANDS")
        inclusive_numerator = sum(0.40 <= value <= 0.60 for value in values)
        outside_numerator = sum(value < 0.25 or value > 0.75 for value in values)
        return (
            {
                "metric_id": WITHIN_INCLUSIVE_MIDDLE_BAND_METRIC_ID,
                "status": "ASSESSABLE",
                "value": inclusive_numerator / denominator,
                "numerator": inclusive_numerator,
                "unordered_pair_denominator": denominator,
                "denominator_rule_id": "unordered-distinct-event-pairs/1",
                "lower_bound": 0.40,
                "upper_bound": 0.60,
                "lower_bound_inclusive": True,
                "upper_bound_inclusive": True,
                "report_exposure": "INTERNAL_CLASSIFIER_INPUT_ONLY",
                "reason_code": None,
            },
            {
                "metric_id": WITHIN_STRICT_OUTSIDE_BAND_METRIC_ID,
                "status": "ASSESSABLE",
                "value": outside_numerator / denominator,
                "numerator": outside_numerator,
                "unordered_pair_denominator": denominator,
                "denominator_rule_id": "unordered-distinct-event-pairs/1",
                "lower_bound": 0.25,
                "upper_bound": 0.75,
                "lower_bound_inclusive": False,
                "upper_bound_inclusive": False,
                "report_exposure": "INTERNAL_CLASSIFIER_INPUT_ONLY",
                "reason_code": None,
            },
        )

    def _rank_shifts(
        result: RankShiftComparison,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        return {
            "rule_id": "common-event-rank-shift/1",
            "absolute_rank_shift_metric_id": "absolute-event-rank-shift/1",
            "normalized_rank_shift_metric_id": "normalized-event-rank-shift/1",
            "common_event_ids": list(result.common_event_ids),
            "common_event_count": result.common_event_count,
            "events_only_in_left": list(result.events_only_in_left),
            "events_only_in_right": list(result.events_only_in_right),
            "shifts": [
                {
                    "event_id": shift.event_id,
                    "left_rank": shift.left_rank,
                    "right_rank": shift.right_rank,
                    "absolute_rank_shift": shift.absolute_rank_shift,
                    "normalized_rank_shift": shift.normalized_rank_shift,
                }
                for shift in result.shifts
            ],
            "maximum_normalized_rank_shift": _scalar(
                result.maximum_normalized_rank_shift,
                metric_id="maximum-normalized-event-rank-shift/1",
            ),
        }

    def _top_k(result: TopKStabilityComparison) -> _builtins.dict[_builtins.str, _builtins.object]:
        return {
            "rule_id": CHAIN_TOP_K_RULE_ID,
            "common_event_ids": list(result.common_event_ids),
            "common_event_count": result.common_event_count,
            "events_only_in_left": list(result.events_only_in_left),
            "events_only_in_right": list(result.events_only_in_right),
            "k": result.k,
            "top_k_overlap": _scalar(
                result.top_k_overlap,
                metric_id="top-k-overlap-fraction/1",
            ),
            "top_k_jaccard": _scalar(
                result.top_k_jaccard,
                metric_id="top-k-jaccard/1",
            ),
            "first_event_stable": _scalar(
                result.first_event_stable,
                metric_id="first-endpoint-stability/1",
            ),
            "last_event_stable": _scalar(
                result.last_event_stable,
                metric_id="last-endpoint-stability/1",
            ),
        }

    def _flips(
        result: PairwiseMajorityComparison,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        return {
            "rule_id": "strict-pairwise-majority-flips/1",
            "probability_metric_id": "pairwise-precedence-probability/1",
            "denominator_rule_id": "unordered-common-event-pairs/1",
            "common_event_ids": list(result.common_event_ids),
            "common_event_count": result.common_event_count,
            "events_only_in_left": list(result.events_only_in_left),
            "events_only_in_right": list(result.events_only_in_right),
            "strict_pairwise_majority_flip_denominator": (
                result.strict_pairwise_majority_flip_denominator
            ),
            "flips": [
                {
                    "event_a_id": flip.event_a_id,
                    "event_b_id": flip.event_b_id,
                    "left_probability_a_before_b": (flip.left_probability_a_before_b),
                    "right_probability_a_before_b": (flip.right_probability_a_before_b),
                    "left_relation": flip.left_relation,
                    "right_relation": flip.right_relation,
                }
                for flip in result.flips
            ],
            "flip_count": _scalar(
                result.flip_count,
                metric_id="strict-pairwise-majority-flip-count/1",
            ),
            "flip_fraction": _scalar(
                result.flip_fraction,
                metric_id="strict-pairwise-majority-flip-fraction/1",
            ),
        }

    def _chain_accounting(
        *,
        planning_outcome: Literal["PLAN_ELIGIBLE", "PLAN_INELIGIBLE"],
        planned_chain_count: _builtins.int,
        finalized_terminal_chain_count: _builtins.int,
        authenticated_available_chain_count: _builtins.int,
        contributing_chain_count: _builtins.int,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        counts = (
            planned_chain_count,
            finalized_terminal_chain_count,
            authenticated_available_chain_count,
            contributing_chain_count,
        )
        if (
            any(not is_exact_type(count, int) or count < 0 for count in counts)
            or finalized_terminal_chain_count > planned_chain_count
            or authenticated_available_chain_count > finalized_terminal_chain_count
            or contributing_chain_count > authenticated_available_chain_count
            or (planning_outcome == "PLAN_INELIGIBLE" and any(count != 0 for count in counts))
            or (planning_outcome == "PLAN_ELIGIBLE" and planned_chain_count == 0)
        ):
            raise _integrity("SCIENCE.CHAIN_ACCOUNTING")
        return {
            "chain_accounting_rule_id": CHAIN_ACCOUNTING_RULE_ID,
            "pair_denominator_rule_id": CHAIN_PAIR_DENOMINATOR_RULE_ID,
            "planning_outcome": planning_outcome,
            "planned_chain_count": planned_chain_count,
            "finalized_terminal_chain_count": finalized_terminal_chain_count,
            "authenticated_available_chain_count": authenticated_available_chain_count,
            "contributing_chain_count": contributing_chain_count,
            "planned_pair_count": math_comb(planned_chain_count, 2),
            "finalized_terminal_pair_count": math_comb(
                finalized_terminal_chain_count,
                2,
            ),
            "authenticated_available_pair_count": math_comb(
                authenticated_available_chain_count,
                2,
            ),
            "contributing_pair_count": math_comb(contributing_chain_count, 2),
        }

    def _empty_chain_metric_summary(
        *,
        metric_id: _builtins.str,
        accounting: _builtins.dict[_builtins.str, _builtins.object],
        status: _LaneStatus,
        reason_code: _builtins.str,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        return {
            "metric_id": metric_id,
            "summary_rule_id": CHAIN_PAIR_SUMMARY_RULE_ID,
            "status": status,
            "reason_code": reason_code,
            "planned_pair_count": accounting["planned_pair_count"],
            "finalized_terminal_pair_count": accounting["finalized_terminal_pair_count"],
            "authenticated_available_pair_count": accounting["authenticated_available_pair_count"],
            "contributing_chain_count": 0,
            "contributing_pair_count": 0,
            "metric_available_pair_count": 0,
            "median_distance": None,
            "maximum_distance": None,
        }

    def _absence(
        *,
        layer: Literal["WITHIN_FIT", "CHAIN"],
        planning_outcome: Literal["PLAN_ELIGIBLE", "PLAN_INELIGIBLE"],
        status: _LaneStatus,
        reason_code: _builtins.str,
        planned_chain_count: _builtins.int,
        finalized_terminal_chain_count: _builtins.int,
        available_chain_count: _builtins.int,
        reference_chain_plan_position: _builtins.int | None = None,
        metric_reason_code: _builtins.str | None = None,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        contributing_chain_count = 0 if layer == "WITHIN_FIT" else available_chain_count
        accounting = _chain_accounting(
            planning_outcome=planning_outcome,
            planned_chain_count=planned_chain_count,
            finalized_terminal_chain_count=finalized_terminal_chain_count,
            authenticated_available_chain_count=available_chain_count,
            contributing_chain_count=contributing_chain_count,
        )
        record: _builtins.dict[_builtins.str, _builtins.object] = {
            "layer": layer,
            "evidence_rule_id": OVERALL_EVIDENCE_RULE_ID,
            "status": status,
            "reason_code": reason_code,
            **accounting,
        }
        if layer == "WITHIN_FIT":
            record.update(
                {
                    "available_descriptive_chain_count": available_chain_count,
                    "within_fit_contributing_chain_count": 0,
                    "reference_chain_plan_position": reference_chain_plan_position,
                    "source": None,
                    "retained_state_count": None,
                    "retained_state_count_rule_id": ("authenticated-retained-order-state-count/1"),
                    "headline_order_event_ids": None,
                    "headline_order_method": None,
                    "retained_state_modal_order_event_ids": None,
                    "retained_state_modal_order_method_id": None,
                    "position_probabilities": None,
                    "position_summaries": {
                        "rule_id": POSITION_SUMMARY_RULE_ID,
                        "status": status,
                        "value": None,
                        "reason_code": reason_code,
                    },
                    "mean_normalized_position_entropy": _unavailable_scalar(
                        metric_id=WITHIN_MEAN_ENTROPY_METRIC_ID,
                        status=status,
                        reason_code=reason_code,
                    ),
                    "per_event_normalized_position_entropy": {
                        "metric_id": WITHIN_EVENT_ENTROPY_METRIC_ID,
                        "status": status,
                        "event_count": 0,
                        "values": None,
                        "reason_code": reason_code,
                    },
                    "inclusive_pairwise_middle_band_fraction": {
                        "metric_id": WITHIN_INCLUSIVE_MIDDLE_BAND_METRIC_ID,
                        "status": status,
                        "value": None,
                        "numerator": None,
                        "unordered_pair_denominator": None,
                        "denominator_rule_id": "unordered-distinct-event-pairs/1",
                        "lower_bound": 0.40,
                        "upper_bound": 0.60,
                        "lower_bound_inclusive": True,
                        "upper_bound_inclusive": True,
                        "report_exposure": "INTERNAL_CLASSIFIER_INPUT_ONLY",
                        "reason_code": reason_code,
                    },
                    "strict_pairwise_outside_band_fraction": {
                        "metric_id": WITHIN_STRICT_OUTSIDE_BAND_METRIC_ID,
                        "status": status,
                        "value": None,
                        "numerator": None,
                        "unordered_pair_denominator": None,
                        "denominator_rule_id": "unordered-distinct-event-pairs/1",
                        "lower_bound": 0.25,
                        "upper_bound": 0.75,
                        "lower_bound_inclusive": False,
                        "upper_bound_inclusive": False,
                        "report_exposure": "INTERNAL_CLASSIFIER_INPUT_ONLY",
                        "reason_code": reason_code,
                    },
                    "position_concentration": _unavailable_scalar(
                        metric_id=POSITION_CONCENTRATION_METRIC_ID,
                        status=status,
                        reason_code=reason_code,
                    ),
                    "pairwise_precedence": None,
                    "pairwise_majorities": {
                        "metric_id": "pairwise-precedence-probability/1",
                        "relation_rule_id": "strict-pairwise-majority-relation/1",
                        "status": status,
                        "value": None,
                        "reason_code": reason_code,
                    },
                    "pairwise_concentration": _unavailable_scalar(
                        metric_id=PAIRWISE_CONCENTRATION_METRIC_ID,
                        status=status,
                        reason_code=reason_code,
                    ),
                    "core_derived_provenance_by_field": {},
                    "cross_checks": {},
                    "within_fit_classifier_status": "WITHIN_FIT_NOT_ASSESSABLE",
                }
            )
        else:
            record.update(
                {
                    "planned_independent_chain_count": planned_chain_count,
                    "independent_chain_count": available_chain_count,
                    "available_descriptive_chain_count": available_chain_count,
                    "expected_pair_count": accounting["planned_pair_count"],
                    "observed_pair_count": 0,
                    "source_chains": [],
                    "pairs": [],
                    "metric_summaries": [
                        _empty_chain_metric_summary(
                            metric_id=metric_id,
                            accounting=accounting,
                            status=status,
                            reason_code=metric_reason_code or reason_code,
                        )
                        for metric_id in (
                            CENTRAL_ORDER_KENDALL_METRIC_ID,
                            POSITION_MATRIX_METRIC_ID,
                            PAIRWISE_PRECEDENCE_MATRIX_METRIC_ID,
                        )
                    ],
                }
            )
        return record

    def _within_fit(
        chains: _builtins.tuple[_ChainEvidenceInput, ...],
        *,
        planned_chain_count: _builtins.int,
        finalized_terminal_chain_count: _builtins.int,
        reference_chain_plan_position: _builtins.int | None,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        reference_matches = tuple(
            chain for chain in chains if chain.chain_plan_position == reference_chain_plan_position
        )
        if reference_chain_plan_position is None or len(reference_matches) != 1:
            return _absence(
                layer="WITHIN_FIT",
                planning_outcome="PLAN_ELIGIBLE",
                status="NOT_ASSESSABLE",
                reason_code="WITHIN_FIT.REFERENCE_CHAIN_UNAVAILABLE",
                planned_chain_count=planned_chain_count,
                finalized_terminal_chain_count=finalized_terminal_chain_count,
                available_chain_count=len(chains),
                reference_chain_plan_position=reference_chain_plan_position,
            )
        reference_chain = reference_matches[0]
        derived = _derive_chain(reference_chain)
        if derived is None:
            return _absence(
                layer="WITHIN_FIT",
                planning_outcome="PLAN_ELIGIBLE",
                status="NOT_ASSESSABLE",
                reason_code="WITHIN_FIT.ORDER_STATE_CHAIN_UNAVAILABLE",
                planned_chain_count=planned_chain_count,
                finalized_terminal_chain_count=finalized_terminal_chain_count,
                available_chain_count=len(chains),
                reference_chain_plan_position=reference_chain_plan_position,
            )
        summaries = position_event_summaries(
            derived.position_probabilities,
            event_ids=reference_chain.event_ids,
            quantile_probabilities=POSITION_SUMMARY_QUANTILE_PROBABILITIES,
        )
        mean_entropy, per_event_entropy = _within_entropy_metrics(summaries)
        inclusive_middle_band, strict_outside_band = _within_pairwise_band_metrics(
            derived.pairwise_precedence
        )
        accounting = _chain_accounting(
            planning_outcome="PLAN_ELIGIBLE",
            planned_chain_count=planned_chain_count,
            finalized_terminal_chain_count=finalized_terminal_chain_count,
            authenticated_available_chain_count=len(chains),
            contributing_chain_count=1,
        )
        provenance = {
            "retained_state_modal_order_event_ids": _core_derived_provenance(
                derived,
                method_id="retained-state-mode/1",
            ),
            "position_probabilities": _core_derived_provenance(
                derived,
                method_id="retained-order-state-chain-position-matrix/1",
            ),
            "position_summaries": _core_derived_provenance(
                derived,
                method_id=POSITION_SUMMARY_RULE_ID,
            ),
            "mean_normalized_position_entropy": _core_derived_provenance(
                derived,
                method_id=WITHIN_MEAN_ENTROPY_METRIC_ID,
            ),
            "per_event_normalized_position_entropy": _core_derived_provenance(
                derived,
                method_id=WITHIN_EVENT_ENTROPY_METRIC_ID,
            ),
            "position_concentration": _core_derived_provenance(
                derived,
                method_id=POSITION_CONCENTRATION_METRIC_ID,
            ),
            "pairwise_precedence": _core_derived_provenance(
                derived,
                method_id="retained-order-state-chain-pairwise-precedence/1",
            ),
            "pairwise_majorities": _core_derived_provenance(
                derived,
                method_id="strict-pairwise-majority-relations/1",
            ),
            "pairwise_concentration": _core_derived_provenance(
                derived,
                method_id=PAIRWISE_CONCENTRATION_METRIC_ID,
            ),
            "inclusive_pairwise_middle_band_fraction": _core_derived_provenance(
                derived,
                method_id=WITHIN_INCLUSIVE_MIDDLE_BAND_METRIC_ID,
            ),
            "strict_pairwise_outside_band_fraction": _core_derived_provenance(
                derived,
                method_id=WITHIN_STRICT_OUTSIDE_BAND_METRIC_ID,
            ),
        }
        return {
            "layer": "WITHIN_FIT",
            "evidence_rule_id": OVERALL_EVIDENCE_RULE_ID,
            "status": "ASSESSABLE",
            "reason_code": None,
            **accounting,
            "available_descriptive_chain_count": len(chains),
            "within_fit_contributing_chain_count": 1,
            "reference_chain_plan_position": reference_chain_plan_position,
            "source": derived.source,
            "retained_state_count": derived.retained_state_count,
            "retained_state_count_rule_id": "authenticated-retained-order-state-count/1",
            "headline_order_event_ids": list(derived.headline_order_event_ids),
            "headline_order_method": derived.headline_order_method,
            "retained_state_modal_order_event_ids": list(
                derived.retained_state_modal_order_event_ids
            ),
            "retained_state_modal_order_method_id": "retained-state-mode/1",
            "position_probabilities": derived.position_probabilities.tolist(),
            "position_probabilities_metric_id": "event-position-probability-matrix/1",
            "position_derivation_method_id": "retained-order-state-chain-position-matrix/1",
            "position_summary_rule": {
                "rule_id": POSITION_SUMMARY_RULE_ID,
                "quantile_probabilities": list(POSITION_SUMMARY_QUANTILE_PROBABILITIES),
                "median_probability": 0.5,
            },
            "position_summaries": _position_summaries(summaries),
            "mean_normalized_position_entropy": mean_entropy,
            "per_event_normalized_position_entropy": per_event_entropy,
            "position_concentration": _scalar(
                position_concentration(derived.position_probabilities),
                metric_id=POSITION_CONCENTRATION_METRIC_ID,
            ),
            "pairwise_precedence": derived.pairwise_precedence.tolist(),
            "pairwise_precedence_metric_id": "pairwise-precedence-probability-matrix/1",
            "pairwise_derivation_method_id": ("retained-order-state-chain-pairwise-precedence/1"),
            "pairwise_majorities": _majorities(
                strict_pairwise_majority_relations(
                    derived.pairwise_precedence,
                    event_ids=reference_chain.event_ids,
                )
            ),
            "inclusive_pairwise_middle_band_fraction": inclusive_middle_band,
            "strict_pairwise_outside_band_fraction": strict_outside_band,
            "pairwise_concentration": _scalar(
                pairwise_concentration(derived.pairwise_precedence),
                metric_id=PAIRWISE_CONCENTRATION_METRIC_ID,
            ),
            "core_derived_provenance_by_field": provenance,
            "cross_checks": derived.cross_checks,
            "within_fit_classifier_status": (
                "WITHIN_FIT_NOT_ASSESSABLE"
                if len(reference_chain.event_ids) == 1
                else "WITHIN_FIT_INPUTS_AVAILABLE"
            ),
        }

    def _order_diagnostics(
        left_order: _builtins.tuple[_builtins.str, ...],
        right_order: _builtins.tuple[_builtins.str, ...],
        *,
        rule_id: _builtins.str,
        kendall_metric_id: _builtins.str,
        footrule_metric_id: _builtins.str,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        order = strict_order_comparison(
            left_order,
            right_order,
        )
        top_k = min(3, order.common_event_count)
        top_k_result = top_k_stability(
            left_order,
            right_order,
            k=top_k,
        )
        return {
            "rule_id": rule_id,
            "strict_order_comparison": {
                "rule_id": "strict-common-event-order-comparison/1",
                "common_event_ids": list(order.common_event_ids),
                "common_event_count": order.common_event_count,
                "events_only_in_left": list(order.events_only_in_left),
                "events_only_in_right": list(order.events_only_in_right),
                "kendall_distance": _scalar(
                    order.kendall_distance,
                    metric_id=kendall_metric_id,
                ),
                "footrule_distance": _scalar(
                    order.footrule_distance,
                    metric_id=footrule_metric_id,
                ),
            },
            "per_event_rank_shifts": _rank_shifts(
                per_event_rank_shifts(
                    left_order,
                    right_order,
                )
            ),
            "top_k_and_endpoint_stability": _top_k(top_k_result),
        }

    def _chain_pair(
        left: _ChainEvidenceInput,
        right: _ChainEvidenceInput,
        left_derived: _DerivedChain,
        right_derived: _DerivedChain,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        if left_derived.headline_order_method_bytes == right_derived.headline_order_method_bytes:
            headline: _builtins.dict[_builtins.str, _builtins.object] = {
                "status": "ASSESSABLE",
                "reason_code": None,
                "left_order_method": left_derived.headline_order_method,
                "right_order_method": right_derived.headline_order_method,
                **_order_diagnostics(
                    left_derived.headline_order_event_ids,
                    right_derived.headline_order_event_ids,
                    rule_id="headline-central-order-diagnostics/1",
                    kendall_metric_id="headline-central-order-kendall/1",
                    footrule_metric_id="headline-central-order-footrule/1",
                ),
            }
        else:
            headline = {
                "status": "NOT_ASSESSABLE",
                "reason_code": "CHAIN.HEADLINE_ORDER_METHOD_MISMATCH",
                "left_order_method": left_derived.headline_order_method,
                "right_order_method": right_derived.headline_order_method,
                "strict_order_comparison": None,
                "per_event_rank_shifts": None,
                "top_k_and_endpoint_stability": None,
            }
        retained_state_modal_order_diagnostics = {
            "status": "ASSESSABLE",
            "reason_code": None,
            "method_id": "retained-state-mode/1",
            **_order_diagnostics(
                left_derived.retained_state_modal_order_event_ids,
                right_derived.retained_state_modal_order_event_ids,
                rule_id="retained-state-modal-order-diagnostics/1",
                kendall_metric_id=CENTRAL_ORDER_KENDALL_METRIC_ID,
                footrule_metric_id="retained-state-modal-order-footrule/1",
            ),
        }
        position_distance = _scalar(
            position_matrix_distance(
                left_derived.position_probabilities,
                right_derived.position_probabilities,
                left_event_ids=left.event_ids,
                right_event_ids=right.event_ids,
            ),
            metric_id=POSITION_MATRIX_METRIC_ID,
        )
        pairwise_distance = _scalar(
            pairwise_matrix_distance(
                left_derived.pairwise_precedence,
                right_derived.pairwise_precedence,
                left_event_ids=left.event_ids,
                right_event_ids=right.event_ids,
            ),
            metric_id=PAIRWISE_PRECEDENCE_MATRIX_METRIC_ID,
        )
        majority_flips = _flips(
            strict_pairwise_majority_flips(
                left_derived.pairwise_precedence,
                right_derived.pairwise_precedence,
                left_event_ids=left.event_ids,
                right_event_ids=right.event_ids,
            )
        )
        return {
            "pair_row_rule_id": CHAIN_PAIR_DENOMINATOR_RULE_ID,
            "left_chain_plan_position": left.chain_plan_position,
            "right_chain_plan_position": right.chain_plan_position,
            "left_source": left_derived.source,
            "right_source": right_derived.source,
            "left_retained_state_count": left_derived.retained_state_count,
            "right_retained_state_count": right_derived.retained_state_count,
            "retained_state_count_rule_id": "authenticated-retained-order-state-count/1",
            "headline_order_diagnostics": headline,
            "retained_state_modal_order_diagnostics": (retained_state_modal_order_diagnostics),
            "position_matrix_distance": position_distance,
            "pairwise_matrix_distance": pairwise_distance,
            "strict_pairwise_majority_flips": majority_flips,
            "core_derived_provenance_by_field": {
                "retained_state_modal_order_diagnostics": _core_derived_provenance(
                    left_derived,
                    right_derived,
                    method_id=CENTRAL_ORDER_KENDALL_METRIC_ID,
                ),
                "position_matrix_distance": _core_derived_provenance(
                    left_derived,
                    right_derived,
                    method_id=POSITION_MATRIX_METRIC_ID,
                ),
                "pairwise_matrix_distance": _core_derived_provenance(
                    left_derived,
                    right_derived,
                    method_id=PAIRWISE_PRECEDENCE_MATRIX_METRIC_ID,
                ),
                "strict_pairwise_majority_flips": _core_derived_provenance(
                    left_derived,
                    right_derived,
                    method_id="strict-pairwise-majority-flips/1",
                ),
            },
        }

    def _convergence_record(
        convergence_record_bytes: bytes | None,
    ) -> _builtins.tuple[
        _builtins.dict[_builtins.str, _builtins.object],
        _builtins.dict[_builtins.str, _builtins.object] | None,
    ]:
        convergence_rule = _convergence_rule()
        if convergence_record_bytes is None:
            return (
                {
                    "status": "NOT_AVAILABLE",
                    "convergence_record_digest": None,
                    "assessment": None,
                    "rule_set_version": None,
                    "reasons": [],
                    "convergence_rule": convergence_rule,
                    "relationship": "NO_CONVERGENCE_RECORD",
                },
                None,
            )
        record = strict_json_loads(convergence_record_bytes)
        if (
            not is_exact_type(record, dict)
            or not is_exact_type(record.get("rule_set_version"), str)
            or not is_exact_type(record.get("assessment"), str)
            or not is_exact_type(record.get("reasons"), list)
            or any(not is_exact_type(reason, str) for reason in record["reasons"])
            or record.get("rule_set_version") != CONVERGENCE_RULE.rule_id
            or (
                record.get("assessment")
                not in {
                    "CONVERGENCE_PASS",
                    "CONVERGENCE_WARN",
                    "CONVERGENCE_FAIL",
                    "CONVERGENCE_NOT_ASSESSABLE",
                }
                and not is_canonical_non_sampling_convergence_record(record)
            )
        ):
            raise _integrity("SCIENCE.CONVERGENCE_RECORD")
        return (
            {
                "status": "BOUND",
                "convergence_record_digest": structured_sha256(
                    "ebm-audit/convergence-record-binding/1",
                    record,
                ),
                "assessment": record["assessment"],
                "rule_set_version": record["rule_set_version"],
                "reasons": list(record["reasons"]),
                "convergence_rule": convergence_rule,
                "relationship": "CORE_CHAIN_DIAGNOSTICS_OVERLAP_REQUIRES_EXPLICIT_CROSS_CHECK",
            },
            record,
        )

    def _scalar_value(value: _builtins.object, *, code: _builtins.str) -> _builtins.float:
        numeric_value: _builtins.object
        if not is_exact_type(value, dict) or value.get("status") != "ASSESSABLE":
            raise _integrity(code)
        numeric_value = value.get("value")
        if not (is_exact_type(numeric_value, float) or is_exact_type(numeric_value, int)):
            raise _integrity(code)
        result = float(numeric_value)
        if not math_isfinite(result):
            raise _integrity(code)
        return result

    def _within_tolerance(observed: _builtins.float, derived: _builtins.float) -> _builtins.bool:
        return bool(
            np_isclose(
                observed,
                derived,
                atol=MATRIX_CROSS_CHECK_ABSOLUTE_TOLERANCE,
                rtol=MATRIX_CROSS_CHECK_RELATIVE_TOLERANCE,
            )
        )

    def _convergence_pair_value(
        pair: _builtins.dict[_builtins.str, _builtins.object],
        *,
        field: Literal["central", "position", "precedence"],
    ) -> _builtins.float:
        if field == "central":
            diagnostics = pair.get("retained_state_modal_order_diagnostics")
            comparison = (
                diagnostics.get("strict_order_comparison")
                if is_exact_type(diagnostics, dict)
                else None
            )
            value = comparison.get("kendall_distance") if is_exact_type(comparison, dict) else None
            return _scalar_value(value, code="SCIENCE.CONVERGENCE_CENTRAL_OVERLAP")
        output_field = (
            "position_matrix_distance" if field == "position" else "pairwise_matrix_distance"
        )
        return _scalar_value(
            pair.get(output_field),
            code="SCIENCE.CONVERGENCE_MATRIX_OVERLAP",
        )

    def _convergence_summary_cross_check(
        pairs: _builtins.list[_builtins.dict[_builtins.str, _builtins.object]],
        summary: _builtins.object,
        *,
        field: Literal["central", "position", "precedence"],
        metric_id: _builtins.str,
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        if summary is None:
            raise _integrity("SCIENCE.CONVERGENCE_SUMMARY_MISSING")
        observed_pairs_value: _builtins.object
        if (
            not is_exact_type(summary, dict)
            or set(summary) != {"metric_id", "pairs", "median_distance", "maximum_distance"}
            or summary.get("metric_id") != metric_id
        ):
            raise _integrity("SCIENCE.CONVERGENCE_SUMMARY")
        observed_pairs_value = summary.get("pairs")
        if not is_exact_type(observed_pairs_value, list):
            raise _integrity("SCIENCE.CONVERGENCE_SUMMARY")
        observed_pairs = observed_pairs_value
        if len(observed_pairs) != len(pairs):
            raise _integrity("SCIENCE.CONVERGENCE_PAIR_COVERAGE")
        derived_values: _builtins.list[_builtins.float] = []
        for pair, observed_pair in zip(pairs, observed_pairs, strict=True):
            if not is_exact_type(observed_pair, dict):
                raise _integrity("SCIENCE.CONVERGENCE_PAIR")
            left_source = pair.get("left_source")
            right_source = pair.get("right_source")
            observed_distance = observed_pair.get("distance")
            if (
                not is_exact_type(left_source, dict)
                or not is_exact_type(right_source, dict)
                or observed_pair.get("left_chain_execution_id")
                != left_source.get("chain_execution_id")
                or observed_pair.get("right_chain_execution_id")
                != right_source.get("chain_execution_id")
                or not (
                    is_exact_type(observed_distance, float) or is_exact_type(observed_distance, int)
                )
            ):
                raise _integrity("SCIENCE.CONVERGENCE_PAIR")
            derived = _convergence_pair_value(pair, field=field)
            if not _within_tolerance(float(observed_distance), derived):
                raise _integrity("SCIENCE.CONVERGENCE_PAIR_MISMATCH")
            derived_values.append(derived)
        expected_median: _builtins.float | None = None
        expected_maximum: _builtins.float | None = None
        if derived_values:
            median = empirical_quantile(derived_values, 0.5)
            expected_median = _scalar_value(
                _scalar(median, metric_id=metric_id),
                code="SCIENCE.CONVERGENCE_MEDIAN",
            )
            expected_maximum = max(derived_values)
        observed_median = summary.get("median_distance")
        observed_maximum = summary.get("maximum_distance")
        if expected_median is None:
            if observed_median is not None or observed_maximum is not None:
                raise _integrity("SCIENCE.CONVERGENCE_EMPTY_SUMMARY")
        elif (
            not (is_exact_type(observed_median, float) or is_exact_type(observed_median, int))
            or not (is_exact_type(observed_maximum, float) or is_exact_type(observed_maximum, int))
            or not _within_tolerance(float(observed_median), expected_median)
            or expected_maximum is None
            or not _within_tolerance(float(observed_maximum), expected_maximum)
        ):
            raise _integrity("SCIENCE.CONVERGENCE_SUMMARY_MISMATCH")
        return {
            "status": "PASS",
            "metric_id": metric_id,
            "checked_pair_count": len(pairs),
            "tolerance_rule_binding": _cross_check_tolerance_binding(),
        }

    def _convergence_binding_reference(
        binding: _builtins.dict[_builtins.str, _builtins.object],
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        convergence_rule = binding.get("convergence_rule")
        if not is_exact_type(convergence_rule, dict):
            raise _integrity("SCIENCE.CONVERGENCE_RULE_BINDING")
        return {
            "status": binding["status"],
            "convergence_record_digest": binding["convergence_record_digest"],
            "assessment": binding["assessment"],
            "rule_set_version": binding["rule_set_version"],
            "reasons": binding["reasons"],
            "convergence_rule_binding": {
                "rule_id": convergence_rule.get("rule_id"),
                "rule_digest": convergence_rule.get("rule_digest"),
            },
        }

    def _convergence_relationship(
        pairs: _builtins.list[_builtins.dict[_builtins.str, _builtins.object]],
        convergence: _builtins.dict[_builtins.str, _builtins.object] | None,
        binding: _builtins.dict[_builtins.str, _builtins.object],
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        reference = _convergence_binding_reference(binding)
        if convergence is None:
            return {
                **reference,
                "relationship": "NO_CONVERGENCE_RECORD",
                "reason_code": "SCIENCE.CONVERGENCE_RECORD_NOT_AVAILABLE",
                "cross_checks": {},
            }
        if is_canonical_non_sampling_convergence_record(convergence):
            return {
                **reference,
                "relationship": "NOT_APPLICABLE_NON_SAMPLING",
                "reason_code": "CONVERGENCE.NOT_APPLICABLE_NON_SAMPLING",
                "cross_checks": {},
            }
        return {
            **reference,
            "relationship": "OVERLAPPING_PAIR_SUMMARIES_CROSS_CHECKED",
            "cross_checks": {
                "retained_state_modal_kendall_distance": (
                    _convergence_summary_cross_check(
                        pairs,
                        convergence.get("central_order_chain_distances"),
                        field="central",
                        metric_id="central-order-kendall/1",
                    )
                ),
                "position_matrix_distance": _convergence_summary_cross_check(
                    pairs,
                    convergence.get("position_matrix_chain_distances"),
                    field="position",
                    metric_id="position-matrix/1",
                ),
                "pairwise_matrix_distance": _convergence_summary_cross_check(
                    pairs,
                    convergence.get("precedence_matrix_chain_distances"),
                    field="precedence",
                    metric_id="pairwise-precedence-matrix/1",
                ),
            },
        }

    def _chain_metric_summary(
        pairs: _builtins.list[_builtins.dict[_builtins.str, _builtins.object]],
        *,
        metric_id: _builtins.str,
        field: Literal["central", "position", "precedence"],
        accounting: _builtins.dict[_builtins.str, _builtins.object],
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        values = [_convergence_pair_value(pair, field=field) for pair in pairs]
        if not values:
            return _empty_chain_metric_summary(
                metric_id=metric_id,
                accounting=accounting,
                status="NOT_ASSESSABLE",
                reason_code="CHAIN.NO_CONTRIBUTING_PAIRS",
            )
        median = empirical_quantile(values, 0.5)
        median_distance = _scalar_value(
            _scalar(median, metric_id=metric_id),
            code="SCIENCE.CHAIN_METRIC_MEDIAN",
        )
        contributing_positions: _builtins.set[_builtins.int] = set()
        for pair in pairs:
            for key in ("left_chain_plan_position", "right_chain_plan_position"):
                position = pair[key]
                if not is_exact_type(position, int):
                    raise _integrity("SCIENCE.CHAIN_PAIR_POSITION")
                contributing_positions.add(position)
        return {
            "metric_id": metric_id,
            "summary_rule_id": CHAIN_PAIR_SUMMARY_RULE_ID,
            "status": "ASSESSABLE",
            "reason_code": None,
            "planned_pair_count": accounting["planned_pair_count"],
            "finalized_terminal_pair_count": accounting["finalized_terminal_pair_count"],
            "authenticated_available_pair_count": accounting["authenticated_available_pair_count"],
            "contributing_chain_count": len(contributing_positions),
            "contributing_pair_count": len(values),
            "metric_available_pair_count": len(values),
            "median_distance": median_distance,
            "maximum_distance": max(values),
        }

    def _chain(
        chains: _builtins.tuple[_ChainEvidenceInput, ...],
        *,
        planned_chain_count: _builtins.int,
        finalized_terminal_chain_count: _builtins.int,
        convergence: _builtins.dict[_builtins.str, _builtins.object] | None,
        convergence_binding: _builtins.dict[_builtins.str, _builtins.object],
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        available_chain_count = len(chains)
        if available_chain_count < 2:
            record = _absence(
                layer="CHAIN",
                planning_outcome="PLAN_ELIGIBLE",
                status="NOT_ASSESSABLE",
                reason_code="CHAIN.INSUFFICIENT_INDEPENDENT_CHAINS",
                planned_chain_count=planned_chain_count,
                finalized_terminal_chain_count=finalized_terminal_chain_count,
                available_chain_count=available_chain_count,
                metric_reason_code="CHAIN.NO_CONTRIBUTING_PAIRS",
            )
            record["convergence_relationship"] = _convergence_relationship(
                [],
                convergence,
                convergence_binding,
            )
            return record
        if available_chain_count != planned_chain_count:
            raise _integrity("SCIENCE.PLANNED_CHAIN_COVERAGE")
        chain_count = available_chain_count
        derived = tuple(_derive_chain(chain) for chain in chains)
        if any(item is None for item in derived):
            record = _absence(
                layer="CHAIN",
                planning_outcome="PLAN_ELIGIBLE",
                status="NOT_ASSESSABLE",
                reason_code="CHAIN.ORDER_STATE_CHAIN_UNAVAILABLE",
                planned_chain_count=planned_chain_count,
                finalized_terminal_chain_count=finalized_terminal_chain_count,
                available_chain_count=available_chain_count,
            )
            record["convergence_relationship"] = _convergence_relationship(
                [],
                convergence,
                convergence_binding,
            )
            return record
        exact_derived = tuple(item for item in derived if item is not None)
        pairs: _builtins.list[_builtins.dict[_builtins.str, _builtins.object]] = []
        for left_index, left in enumerate(chains[:-1]):
            for right_index in range(left_index + 1, chain_count):
                pairs.append(
                    _chain_pair(
                        left,
                        chains[right_index],
                        exact_derived[left_index],
                        exact_derived[right_index],
                    )
                )
        expected_pair_count = math_comb(chain_count, 2)
        if len(pairs) != expected_pair_count:
            raise _integrity("SCIENCE.CHAIN_PAIR_COVERAGE")
        accounting = _chain_accounting(
            planning_outcome="PLAN_ELIGIBLE",
            planned_chain_count=planned_chain_count,
            finalized_terminal_chain_count=finalized_terminal_chain_count,
            authenticated_available_chain_count=available_chain_count,
            contributing_chain_count=available_chain_count,
        )
        summary_specs: _builtins.tuple[
            _builtins.tuple[_builtins.str, Literal["central", "position", "precedence"]],
            ...,
        ] = (
            (CENTRAL_ORDER_KENDALL_METRIC_ID, "central"),
            (POSITION_MATRIX_METRIC_ID, "position"),
            (PAIRWISE_PRECEDENCE_MATRIX_METRIC_ID, "precedence"),
        )
        metric_summaries = [
            _chain_metric_summary(
                pairs,
                metric_id=metric_id,
                field=field,
                accounting=accounting,
            )
            for metric_id, field in summary_specs
        ]
        return {
            "layer": "CHAIN",
            "evidence_rule_id": OVERALL_EVIDENCE_RULE_ID,
            "status": "ASSESSABLE",
            "reason_code": None,
            **accounting,
            "planned_independent_chain_count": planned_chain_count,
            "independent_chain_count": available_chain_count,
            "available_descriptive_chain_count": available_chain_count,
            "expected_pair_count": accounting["planned_pair_count"],
            "observed_pair_count": len(pairs),
            "source_chains": [
                {
                    **item.source,
                    "cross_checks": item.cross_checks,
                }
                for item in exact_derived
            ],
            "top_k_rule": {
                "rule_id": CHAIN_TOP_K_RULE_ID,
                "k_rule": "min(3,event_count)",
            },
            "pairs": pairs,
            "metric_summaries": metric_summaries,
            "convergence_relationship": _convergence_relationship(
                pairs,
                convergence,
                convergence_binding,
            ),
        }

    def _eligibility(final_status: _builtins.str) -> _Eligibility:
        if final_status == "SUCCESS":
            return "INTERPRETIVE"
        if final_status == "CONVERGENCE_WARN":
            return "DESCRIPTIVE_ONLY"
        return "UNAVAILABLE"

    def _terminal_absence_status(final_status: _builtins.str) -> _LaneStatus:
        if final_status == "UNSUPPORTED_CAPABILITY":
            return "NOT_APPLICABLE_BY_CAPABILITY"
        return "NOT_ASSESSABLE"

    def _terminal_reason(final_status: _builtins.str) -> _builtins.str:
        if final_status == "UNSUPPORTED_CAPABILITY":
            return "CANDIDATE.UNSUPPORTED_CAPABILITY"
        return f"CANDIDATE.{final_status}"

    def _event_semantics_record(
        *,
        event_ids: _builtins.tuple[_builtins.str, ...],
        event_directions: _builtins.tuple[_builtins.tuple[_builtins.str, _builtins.str], ...],
        stage_semantics_digest: _builtins.str,
        planning_outcome: Literal["PLAN_ELIGIBLE", "PLAN_INELIGIBLE"],
    ) -> _builtins.dict[_builtins.str, _builtins.object]:
        directions = tuple(direction for _event_id, direction in event_directions)
        requires_confirmation = any(
            direction == "REQUIRES_CONFIRMATION" for direction in directions
        )
        if requires_confirmation and planning_outcome != "PLAN_INELIGIBLE":
            raise _integrity("SCIENCE.EVENT_SEMANTICS_UNRESOLVED")
        preimage: _builtins.dict[_builtins.str, _builtins.object] = {
            "rule_id": _EVENT_SEMANTICS_RULE_ID,
            "status": "REQUIRES_CONFIRMATION" if requires_confirmation else "CONFIRMED",
            "ordered_event_ids": list(event_ids),
            "ordered_event_directions": list(directions),
            "stage_semantics_digest": stage_semantics_digest,
        }
        return {
            **preimage,
            "event_semantics_digest": structured_sha256(
                "ebm-audit/event-semantics-record/1",
                preimage,
            ),
        }

    def _derive_candidate_evidence_record(
        *,
        candidate_ordinal: _builtins.int,
        candidate_id: _builtins.str,
        analysis_spec_id: _builtins.str,
        result_id: _builtins.str,
        final_status: _builtins.str,
        event_ids: _builtins.tuple[_builtins.str, ...],
        event_directions: _builtins.tuple[_builtins.tuple[_builtins.str, _builtins.str], ...],
        stage_semantics_digest: _builtins.str,
        planned_chain_count: _builtins.int,
        finalized_terminal_chain_count: _builtins.int,
        authenticated_available_chain_count: _builtins.int,
        reference_chain_plan_position: _builtins.int | None,
        convergence_record_bytes: bytes | None,
        chains: _builtins.tuple[_ChainEvidenceInput, ...],
    ) -> _CanonicalCandidateEvidenceRecord:
        """Derive one complete safe record while preserving terminal coverage."""

        if (
            not is_exact_type(planned_chain_count, int)
            or planned_chain_count < 0
            or not is_exact_type(finalized_terminal_chain_count, int)
            or not is_exact_type(authenticated_available_chain_count, int)
            or authenticated_available_chain_count != len(chains)
            or finalized_terminal_chain_count > planned_chain_count
            or authenticated_available_chain_count > finalized_terminal_chain_count
            or tuple(event_id for event_id, _direction in event_directions) != event_ids
            or any(
                direction not in {"higher", "lower", "REQUIRES_CONFIRMATION"}
                for _event_id, direction in event_directions
            )
            or not is_exact_type(stage_semantics_digest, str)
            or any(
                not is_exact_type(chain.chain_plan_position, int)
                or chain.chain_plan_position < 0
                or chain.chain_plan_position >= planned_chain_count
                for chain in chains
            )
            or len({chain.chain_plan_position for chain in chains}) != len(chains)
            or (
                reference_chain_plan_position is not None
                and (
                    not is_exact_type(reference_chain_plan_position, int)
                    or reference_chain_plan_position != 0
                )
            )
        ):
            raise _integrity("SCIENCE.CANDIDATE_CONTRACT")
        planning_outcome: Literal["PLAN_ELIGIBLE", "PLAN_INELIGIBLE"] = (
            "PLAN_INELIGIBLE" if planned_chain_count == 0 else "PLAN_ELIGIBLE"
        )
        convergence_binding, convergence = _convergence_record(convergence_record_bytes)
        convergence_derived_final_statuses = {
            "SUCCESS",
            "CONVERGENCE_WARN",
            "CONVERGENCE_FAILED",
            "CONVERGENCE_NOT_ASSESSABLE",
        }
        if final_status in convergence_derived_final_statuses and convergence is None:
            raise _integrity("SCIENCE.CONVERGENCE_RECORD_REQUIRED")
        if convergence is not None:
            convergence_assessment = convergence.get("assessment")
            if not is_exact_type(convergence_assessment, str):
                raise _integrity("SCIENCE.CONVERGENCE_TERMINAL_MAPPING")
            if is_canonical_non_sampling_convergence_record(convergence):
                expected_final_status = "SUCCESS"
            else:
                expected_final_status_candidate = {
                    "CONVERGENCE_PASS": "SUCCESS",
                    "CONVERGENCE_WARN": "CONVERGENCE_WARN",
                    "CONVERGENCE_FAIL": "CONVERGENCE_FAILED",
                    "CONVERGENCE_NOT_ASSESSABLE": "CONVERGENCE_NOT_ASSESSABLE",
                }.get(convergence_assessment)
                if expected_final_status_candidate is None:
                    raise _integrity("SCIENCE.CONVERGENCE_TERMINAL_MAPPING")
                expected_final_status = expected_final_status_candidate
            if expected_final_status != final_status:
                raise _integrity("SCIENCE.CONVERGENCE_TERMINAL_MAPPING")
        eligibility = _eligibility(final_status)
        if final_status in {"SUCCESS", "CONVERGENCE_WARN"}:
            if reference_chain_plan_position != 0:
                raise _integrity("SCIENCE.REFERENCE_CHAIN_POSITION")
            if (
                finalized_terminal_chain_count != planned_chain_count
                or authenticated_available_chain_count != planned_chain_count
            ):
                raise _integrity("SCIENCE.PLANNED_CHAIN_COVERAGE")
            within_fit = _within_fit(
                chains,
                planned_chain_count=planned_chain_count,
                finalized_terminal_chain_count=finalized_terminal_chain_count,
                reference_chain_plan_position=reference_chain_plan_position,
            )
            chain = _chain(
                chains,
                planned_chain_count=planned_chain_count,
                finalized_terminal_chain_count=finalized_terminal_chain_count,
                convergence=convergence,
                convergence_binding=convergence_binding,
            )
        else:
            if (
                final_status not in {"CONVERGENCE_FAILED", "CONVERGENCE_NOT_ASSESSABLE"}
                and reference_chain_plan_position is not None
            ):
                raise _integrity("SCIENCE.NON_SUCCESS_REFERENCE_CHAIN")
            absence_status = _terminal_absence_status(final_status)
            reason_code = _terminal_reason(final_status)
            within_fit = _absence(
                layer="WITHIN_FIT",
                planning_outcome=planning_outcome,
                status=absence_status,
                reason_code=reason_code,
                planned_chain_count=planned_chain_count,
                finalized_terminal_chain_count=finalized_terminal_chain_count,
                available_chain_count=len(chains),
                reference_chain_plan_position=reference_chain_plan_position,
            )
            chain = _absence(
                layer="CHAIN",
                planning_outcome=planning_outcome,
                status=absence_status,
                reason_code=reason_code,
                planned_chain_count=planned_chain_count,
                finalized_terminal_chain_count=finalized_terminal_chain_count,
                available_chain_count=len(chains),
            )
            chain["convergence_relationship"] = {
                **_convergence_binding_reference(convergence_binding),
                "relationship": "NOT_CHECKED",
                "reason_code": "SCIENCE.NO_DESCRIPTIVE_CHAIN_AUTHORITY",
                "cross_checks": {},
            }
        preimage: _builtins.dict[_builtins.str, _builtins.object] = {
            "record_schema_version": SCIENTIFIC_CANDIDATE_RECORD_SCHEMA_VERSION,
            "evidence_rule_id": OVERALL_EVIDENCE_RULE_ID,
            "candidate_ordinal": candidate_ordinal,
            "candidate_id": candidate_id,
            "analysis_spec_id": analysis_spec_id,
            "result_id": result_id,
            "final_status": final_status,
            "eligibility": eligibility,
            "event_semantics": _event_semantics_record(
                event_ids=event_ids,
                event_directions=event_directions,
                stage_semantics_digest=stage_semantics_digest,
                planning_outcome=planning_outcome,
            ),
            "planned_chain_count": planned_chain_count,
            "finalized_terminal_chain_count": finalized_terminal_chain_count,
            "authenticated_available_chain_count": authenticated_available_chain_count,
            "available_descriptive_chain_count": len(chains),
            "matrix_cross_check_tolerance_rule_binding": (_cross_check_tolerance_binding()),
            "convergence_record_binding": convergence_binding,
            "within_fit": within_fit,
            "chain": chain,
        }
        record_digest = structured_sha256(
            "ebm-audit/scientific-candidate-evidence/1",
            preimage,
        )
        return candidate_record_type(
            preimage_bytes=canonical_json_bytes(preimage),
            canonical_bytes=canonical_json_bytes(
                {
                    **preimage,
                    "record_digest": record_digest,
                }
            ),
            record_digest=record_digest,
        )

    return _CandidateEvidenceKernel(
        _integrity=_integrity,
        _scalar=_scalar,
        _unavailable_scalar=_unavailable_scalar,
        _matrix_value=_matrix_value,
        _source=_source,
        _cross_check_tolerance_rule=_cross_check_tolerance_rule,
        _cross_check_tolerance_binding=_cross_check_tolerance_binding,
        _convergence_rule=_convergence_rule,
        _uncertainty_layer_coverage=_uncertainty_layer_coverage,
        _array_digest=_array_digest,
        _core_derived_provenance=_core_derived_provenance,
        _matrix_cross_check=_matrix_cross_check,
        _orders=_orders,
        _central_order=_central_order,
        _same_matrix=_same_matrix,
        _derive_chain=_derive_chain,
        _position_summaries=_position_summaries,
        _majorities=_majorities,
        _within_entropy_metrics=_within_entropy_metrics,
        _within_pairwise_band_metrics=_within_pairwise_band_metrics,
        _rank_shifts=_rank_shifts,
        _top_k=_top_k,
        _flips=_flips,
        _chain_accounting=_chain_accounting,
        _empty_chain_metric_summary=_empty_chain_metric_summary,
        _absence=_absence,
        _within_fit=_within_fit,
        _order_diagnostics=_order_diagnostics,
        _chain_pair=_chain_pair,
        _convergence_record=_convergence_record,
        _scalar_value=_scalar_value,
        _within_tolerance=_within_tolerance,
        _convergence_pair_value=_convergence_pair_value,
        _convergence_summary_cross_check=_convergence_summary_cross_check,
        _convergence_binding_reference=_convergence_binding_reference,
        _convergence_relationship=_convergence_relationship,
        _chain_metric_summary=_chain_metric_summary,
        _chain=_chain,
        _eligibility=_eligibility,
        _terminal_absence_status=_terminal_absence_status,
        _terminal_reason=_terminal_reason,
        _event_semantics_record=_event_semantics_record,
        _derive_candidate_evidence_record=_derive_candidate_evidence_record,
    )


_CANDIDATE_EVIDENCE_KERNEL = _build_candidate_evidence_kernel(
    canonical_json_bytes=_CANONICAL_OPERATIONS.canonical_json_bytes,
    strict_json_loads=_CANONICAL_OPERATIONS.strict_json_loads,
    structured_sha256=_CANONICAL_OPERATIONS.structured_sha256,
    empirical_quantile=_METRIC_KERNEL.empirical_quantile,
    pairwise_concentration=_METRIC_KERNEL.pairwise_concentration,
    pairwise_matrix_distance=_METRIC_KERNEL.pairwise_matrix_distance,
    pairwise_precedence_matrix=_METRIC_KERNEL.pairwise_precedence_matrix,
    per_event_rank_shifts=_METRIC_KERNEL.per_event_rank_shifts,
    position_concentration=_METRIC_KERNEL.position_concentration,
    position_event_summaries=_METRIC_KERNEL.position_event_summaries,
    position_matrix=_METRIC_KERNEL.position_matrix,
    position_matrix_distance=_METRIC_KERNEL.position_matrix_distance,
    strict_order_comparison=_METRIC_KERNEL.strict_order_comparison,
    strict_pairwise_majority_flips=_METRIC_KERNEL.strict_pairwise_majority_flips,
    strict_pairwise_majority_relations=_METRIC_KERNEL.strict_pairwise_majority_relations,
    top_k_stability=_METRIC_KERNEL.top_k_stability,
    integrity_error_type=_ScientificRecordIntegrityError,
    candidate_record_type=_CanonicalCandidateEvidenceRecord,
    derived_chain_type=_DerivedChain,
    CONVERGENCE_RULE=type(_CONVERGENCE_RULE)(
        _CONVERGENCE_RULE.rule_schema_version,
        _CONVERGENCE_RULE.rule_id,
        _CONVERGENCE_RULE.rule_status,
        _CONVERGENCE_RULE.assessable_min_independent_chains,
        _CONVERGENCE_RULE.assessable_min_unthinned_postburn_states_per_chain,
        _CONVERGENCE_RULE.pass_transition_rate_exclusive_min,
        _CONVERGENCE_RULE.pass_median_position_distance_max,
        _CONVERGENCE_RULE.pass_max_position_distance_max,
        _CONVERGENCE_RULE.pass_median_precedence_distance_max,
        _CONVERGENCE_RULE.fail_combined_max_position_distance_over,
        _CONVERGENCE_RULE.fail_combined_max_kendall_distance_over,
        _CONVERGENCE_RULE.fail_invalid_or_nonfinite_samples,
        _CONVERGENCE_RULE.fail_stuck_chains_in_distinct_states,
        _CONVERGENCE_RULE.likelihood_drift_role,
    ),
    is_canonical_non_sampling_convergence_record=(
        is_canonical_non_sampling_convergence_record
    ),
    POSITION_SUMMARY_RULE_ID=POSITION_SUMMARY_RULE_ID,
    POSITION_SUMMARY_QUANTILE_PROBABILITIES=POSITION_SUMMARY_QUANTILE_PROBABILITIES,
    CHAIN_TOP_K_RULE_ID=CHAIN_TOP_K_RULE_ID,
    OVERALL_EVIDENCE_RULE_ID=OVERALL_EVIDENCE_RULE_ID,
    CHAIN_ACCOUNTING_RULE_ID=CHAIN_ACCOUNTING_RULE_ID,
    CHAIN_PAIR_DENOMINATOR_RULE_ID=CHAIN_PAIR_DENOMINATOR_RULE_ID,
    CHAIN_PAIR_SUMMARY_RULE_ID=CHAIN_PAIR_SUMMARY_RULE_ID,
    WITHIN_MEAN_ENTROPY_METRIC_ID=WITHIN_MEAN_ENTROPY_METRIC_ID,
    WITHIN_EVENT_ENTROPY_METRIC_ID=WITHIN_EVENT_ENTROPY_METRIC_ID,
    WITHIN_INCLUSIVE_MIDDLE_BAND_METRIC_ID=WITHIN_INCLUSIVE_MIDDLE_BAND_METRIC_ID,
    WITHIN_STRICT_OUTSIDE_BAND_METRIC_ID=WITHIN_STRICT_OUTSIDE_BAND_METRIC_ID,
    CENTRAL_ORDER_KENDALL_METRIC_ID=CENTRAL_ORDER_KENDALL_METRIC_ID,
    POSITION_MATRIX_METRIC_ID=POSITION_MATRIX_METRIC_ID,
    PAIRWISE_PRECEDENCE_MATRIX_METRIC_ID=PAIRWISE_PRECEDENCE_MATRIX_METRIC_ID,
    POSITION_CONCENTRATION_METRIC_ID=POSITION_CONCENTRATION_METRIC_ID,
    PAIRWISE_CONCENTRATION_METRIC_ID=PAIRWISE_CONCENTRATION_METRIC_ID,
    MATRIX_CROSS_CHECK_TOLERANCE_RULE_ID=MATRIX_CROSS_CHECK_TOLERANCE_RULE_ID,
    MATRIX_CROSS_CHECK_ABSOLUTE_TOLERANCE=MATRIX_CROSS_CHECK_ABSOLUTE_TOLERANCE,
    MATRIX_CROSS_CHECK_RELATIVE_TOLERANCE=MATRIX_CROSS_CHECK_RELATIVE_TOLERANCE,
    MATRIX_CROSS_CHECK_TOLERANCE_STATUS=MATRIX_CROSS_CHECK_TOLERANCE_STATUS,
    SCIENTIFIC_CANDIDATE_RECORD_SCHEMA_VERSION=SCIENTIFIC_CANDIDATE_RECORD_SCHEMA_VERSION,
    _MATRIX_CROSS_CHECK_INEQUALITY=_MATRIX_CROSS_CHECK_INEQUALITY,
    _UNCERTAINTY_LAYER_COVERAGE_RULE_ID=_UNCERTAINTY_LAYER_COVERAGE_RULE_ID,
    _EVENT_SEMANTICS_RULE_ID=_EVENT_SEMANTICS_RULE_ID,
    Counter=Counter,
    math_comb=_math.comb,
    math_isfinite=_math.isfinite,
    np_allclose=np.allclose,
    np_dtype=np.dtype,
    np_float64=np.float64,
    np_int32=np.int32,
    np_isclose=np.isclose,
    np_ndarray_type=np.ndarray,
    is_exact_type=_IS_EXACT_TYPE,
    abs=abs,
    all=all,
    any=any,
    bool=bool,
    dict=dict,
    enumerate=enumerate,
    float=float,
    int=int,
    len=len,
    list=list,
    max=max,
    min=min,
    next=next,
    object=object,
    range=range,
    set=set,
    sorted=sorted,
    str=str,
    sum=sum,
    tuple=tuple,
    zip=zip,
)

for _operation_name in _CandidateEvidenceKernel.__dataclass_fields__:
    _operation = getattr(_CANDIDATE_EVIDENCE_KERNEL, _operation_name)
    _operation.__name__ = _operation_name
    _operation.__qualname__ = _operation_name
    _operation.__module__ = __name__

_integrity = _CANDIDATE_EVIDENCE_KERNEL._integrity
_scalar = _CANDIDATE_EVIDENCE_KERNEL._scalar
_unavailable_scalar = _CANDIDATE_EVIDENCE_KERNEL._unavailable_scalar
_matrix_value = _CANDIDATE_EVIDENCE_KERNEL._matrix_value
_source = _CANDIDATE_EVIDENCE_KERNEL._source
_cross_check_tolerance_rule = _CANDIDATE_EVIDENCE_KERNEL._cross_check_tolerance_rule
_cross_check_tolerance_binding = _CANDIDATE_EVIDENCE_KERNEL._cross_check_tolerance_binding
_convergence_rule = _CANDIDATE_EVIDENCE_KERNEL._convergence_rule
_uncertainty_layer_coverage = _CANDIDATE_EVIDENCE_KERNEL._uncertainty_layer_coverage
_array_digest = _CANDIDATE_EVIDENCE_KERNEL._array_digest
_core_derived_provenance = _CANDIDATE_EVIDENCE_KERNEL._core_derived_provenance
_matrix_cross_check = _CANDIDATE_EVIDENCE_KERNEL._matrix_cross_check
_orders = _CANDIDATE_EVIDENCE_KERNEL._orders
_central_order = _CANDIDATE_EVIDENCE_KERNEL._central_order
_same_matrix = _CANDIDATE_EVIDENCE_KERNEL._same_matrix
_derive_chain = _CANDIDATE_EVIDENCE_KERNEL._derive_chain
_position_summaries = _CANDIDATE_EVIDENCE_KERNEL._position_summaries
_majorities = _CANDIDATE_EVIDENCE_KERNEL._majorities
_within_entropy_metrics = _CANDIDATE_EVIDENCE_KERNEL._within_entropy_metrics
_within_pairwise_band_metrics = _CANDIDATE_EVIDENCE_KERNEL._within_pairwise_band_metrics
_rank_shifts = _CANDIDATE_EVIDENCE_KERNEL._rank_shifts
_top_k = _CANDIDATE_EVIDENCE_KERNEL._top_k
_flips = _CANDIDATE_EVIDENCE_KERNEL._flips
_chain_accounting = _CANDIDATE_EVIDENCE_KERNEL._chain_accounting
_empty_chain_metric_summary = _CANDIDATE_EVIDENCE_KERNEL._empty_chain_metric_summary
_absence = _CANDIDATE_EVIDENCE_KERNEL._absence
_within_fit = _CANDIDATE_EVIDENCE_KERNEL._within_fit
_order_diagnostics = _CANDIDATE_EVIDENCE_KERNEL._order_diagnostics
_chain_pair = _CANDIDATE_EVIDENCE_KERNEL._chain_pair
_convergence_record = _CANDIDATE_EVIDENCE_KERNEL._convergence_record
_scalar_value = _CANDIDATE_EVIDENCE_KERNEL._scalar_value
_within_tolerance = _CANDIDATE_EVIDENCE_KERNEL._within_tolerance
_convergence_pair_value = _CANDIDATE_EVIDENCE_KERNEL._convergence_pair_value
_convergence_summary_cross_check = _CANDIDATE_EVIDENCE_KERNEL._convergence_summary_cross_check
_convergence_binding_reference = _CANDIDATE_EVIDENCE_KERNEL._convergence_binding_reference
_convergence_relationship = _CANDIDATE_EVIDENCE_KERNEL._convergence_relationship
_chain_metric_summary = _CANDIDATE_EVIDENCE_KERNEL._chain_metric_summary
_chain = _CANDIDATE_EVIDENCE_KERNEL._chain
_eligibility = _CANDIDATE_EVIDENCE_KERNEL._eligibility
_terminal_absence_status = _CANDIDATE_EVIDENCE_KERNEL._terminal_absence_status
_terminal_reason = _CANDIDATE_EVIDENCE_KERNEL._terminal_reason
_event_semantics_record = _CANDIDATE_EVIDENCE_KERNEL._event_semantics_record
_derive_candidate_evidence_record = _CANDIDATE_EVIDENCE_KERNEL._derive_candidate_evidence_record

__all__: list[str] = []
