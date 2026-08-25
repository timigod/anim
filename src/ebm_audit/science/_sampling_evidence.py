"""Sealed declared-resampling uncertainty evidence.

This module derives only the participant-resampling layer. It compares each
declared bootstrap or participant-subsample refit with its exact ordinary
source fit, preserves failed and warning terminals, and never pools distinct
operation families with each other, chain variation, or analyst-decision
variation.

Participant-stage evidence is calculated by the shared fixed-cohort owner and
carried here without recomputation. It remains an orthogonal report domain
that retains ``SAMPLING`` as its originating uncertainty layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite as _math_isfinite
from typing import Any, Final, Literal, cast

from numpy import asarray as _np_asarray
from numpy import float64 as _np_float64

from ebm_audit.metrics import (
    empirical_quantile,
    pairwise_matrix_distance,
    per_event_rank_shifts,
    position_matrix_distance,
    strict_order_comparison,
    strict_pairwise_majority_flips,
    strict_pairwise_majority_relations,
    top_k_stability,
)
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256

from ._evidence_records import (
    _integrity,
    _scalar,
    _ScientificRecordIntegrityError,
)
from ._frozen_derivation import build_frozen_derivation_graph
from ._participant_stage_validation import (
    validate_participant_stage_comparison_semantics as _validate_shared_participant_stage_semantics,
)

SAMPLING_EVIDENCE_RULE_ID: Final = "sampling-source-fit-comparison/3"
SAMPLING_NUMERIC_SCHEMA_VERSION: Final = "ebm-audit-sampling-numeric-comparison/3.0"
SAMPLING_ATTEMPT_SCHEMA_VERSION: Final = "ebm-audit-sampling-origin-attempt/3.0"
SAMPLING_AGGREGATE_SCHEMA_VERSION: Final = "ebm-audit-sampling-family-aggregate/3.0"
SAMPLING_LAYER_SCHEMA_VERSION: Final = "ebm-audit-sampling-layer-evidence/3.0"

_NUMERIC_DOMAIN: Final = "ebm-audit/scientific-sampling-numeric-comparison/3"
_ATTEMPT_DOMAIN: Final = "ebm-audit/scientific-sampling-origin-attempt/3"
_AGGREGATE_DOMAIN: Final = "ebm-audit/scientific-sampling-family-aggregate/3"
_LAYER_DOMAIN: Final = "ebm-audit/scientific-sampling-layer-evidence/3"
_OPERATION_DESCRIPTOR_DOMAIN: Final = "ebm-audit/sampling-operation-descriptor/1"
_STAGE_COMPARISON_DOMAIN: Final = "ebm-audit/public-participant-stage-comparison/1"

_TERMINAL_STATUSES: Final = (
    "SUCCESS",
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
_CONTRIBUTION_STATES: Final = (
    "INTERPRETIVE",
    "DESCRIPTIVE_ONLY",
    "METRIC_NOT_ASSESSABLE",
    "FAILED",
)
_SUMMARY_METRICS: Final = (
    ("central-order-kendall-distance/1", "kendall_distance"),
    ("central-order-footrule-distance/1", "footrule_distance"),
    ("top-k-overlap-fraction/1", "top_k_overlap"),
    ("top-k-jaccard/1", "top_k_jaccard"),
    (
        "maximum-normalized-event-rank-displacement/1",
        "maximum_normalized_event_rank_displacement",
    ),
    ("position-matrix-distance/1", "position_matrix_distance"),
    ("pairwise-matrix-distance/1", "pairwise_matrix_distance"),
    ("strict-pairwise-majority-flip-fraction/1", "flip_fraction"),
)

type _Eligibility = Literal["INTERPRETIVE", "DESCRIPTIVE_ONLY", "UNAVAILABLE"]
type _ContributionState = Literal[
    "INTERPRETIVE",
    "DESCRIPTIVE_ONLY",
    "METRIC_NOT_ASSESSABLE",
    "FAILED",
]


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalSamplingNumericComparison:
    preimage_bytes: bytes
    canonical_bytes: bytes
    numeric_comparison_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalSamplingOriginAttempt:
    preimage_bytes: bytes
    canonical_bytes: bytes
    attempt_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalSamplingFamilyAggregate:
    preimage_bytes: bytes
    canonical_bytes: bytes
    aggregate_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalSamplingLayerEvidence:
    preimage_bytes: bytes
    canonical_bytes: bytes
    layer_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalSamplingEvidenceBundle:
    attempts: tuple[_CanonicalSamplingOriginAttempt, ...]
    numeric_records: tuple[_CanonicalSamplingNumericComparison, ...]
    aggregates: tuple[_CanonicalSamplingFamilyAggregate, ...]
    layer: _CanonicalSamplingLayerEvidence


@dataclass(frozen=True, repr=False, slots=True)
class _SamplingOriginInput:
    origin_bytes: bytes
    comparison_edge_bytes: bytes
    stage_comparison_bytes: bytes


@dataclass(frozen=True, repr=False, slots=True)
class _SamplingCandidateInput:
    candidate_record_bytes: bytes
    universe_id: str | None
    operation_bytes: bytes
    origins: tuple[_SamplingOriginInput, ...]


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _closed_record(value: bytes, *, code: str) -> dict[str, object]:
    if type(value) is not bytes:
        raise _integrity(code)
    decoded = strict_json_loads(value)
    if type(decoded) is not dict or canonical_json_bytes(decoded) != value:
        raise _integrity(code)
    return cast(dict[str, object], decoded)


def _candidate_identity(record: dict[str, object]) -> tuple[int, str, str, str, str, str]:
    ordinal = record.get("candidate_ordinal")
    candidate_id = record.get("candidate_id")
    analysis_spec_id = record.get("analysis_spec_id")
    result_id = record.get("result_id")
    final_status = record.get("final_status")
    record_digest = record.get("record_digest")
    if (
        type(ordinal) is not int
        or ordinal < 0
        or type(candidate_id) is not str
        or type(analysis_spec_id) is not str
        or candidate_id != analysis_spec_id
        or type(result_id) is not str
        or final_status not in _TERMINAL_STATUSES
        or type(record_digest) is not str
    ):
        raise _integrity("SCIENCE.SAMPLING_CANDIDATE_IDENTITY")
    return ordinal, candidate_id, analysis_spec_id, result_id, final_status, record_digest


def _validate_operation_descriptor(
    descriptor: object,
    *,
    expected_scope: str,
) -> dict[str, object]:
    """Validate one closed privacy-safe sampling-operation descriptor."""

    required = {
        "descriptor_schema_version",
        "operation_scope",
        "experiment_mode",
        "sampling_method_id",
        "sampling_design",
        "strata_group_spec_ids",
        "replicate_ordinal",
        "refit_preprocessing",
        "fixed_evaluation_cohort_policy",
        "retained_fraction",
        "retained_count_rounding_rule",
    }
    if type(descriptor) is not dict or set(descriptor) != required:
        raise _integrity("SCIENCE.SAMPLING_OPERATION_DESCRIPTOR")
    exact = cast(dict[str, object], descriptor)
    mode = exact.get("experiment_mode")
    method = exact.get("sampling_method_id")
    design = exact.get("sampling_design")
    strata = exact.get("strata_group_spec_ids")
    ordinal = exact.get("replicate_ordinal")
    fraction = exact.get("retained_fraction")
    rounding = exact.get("retained_count_rounding_rule")
    fixed_policy = exact.get("fixed_evaluation_cohort_policy")
    if (
        exact.get("descriptor_schema_version") != "ebm-audit-sampling-operation-descriptor/1.0"
        or exact.get("operation_scope") != expected_scope
        or mode not in {"bootstrap", "subsample"}
        or design not in {"ordinary", "stratified"}
        or type(strata) is not list
        or any(type(value) is not str or not value for value in strata)
        or len(set(cast(list[str], strata))) != len(strata)
        or (design == "ordinary" and strata != [])
        or (design == "stratified" and not strata)
        or exact.get("refit_preprocessing") is not True
        or (expected_scope == "replicate" and (type(ordinal) is not int or ordinal < 0))
        or (expected_scope == "family" and ordinal is not None)
    ):
        raise _integrity("SCIENCE.SAMPLING_OPERATION_DESCRIPTOR")
    if mode == "bootstrap":
        if (
            method != "participant-bootstrap-with-replacement/1"
            or fixed_policy != "fixed-baseline-cohort-or-unsupported/1"
            or fraction is not None
            or rounding is not None
        ):
            raise _integrity("SCIENCE.SAMPLING_OPERATION_DESCRIPTOR")
    elif (
        method != "participant-subsample-without-replacement/1"
        or fixed_policy != "fixed-subsample-cohort-or-unsupported/1"
        or type(fraction) not in {int, float}
        or not _math_isfinite(float(cast(int | float, fraction)))
        or not 0 < cast(int | float, fraction) < 1
        or rounding != "floor-pre-operation-count-times-fraction/1"
    ):
        raise _integrity("SCIENCE.SAMPLING_OPERATION_DESCRIPTOR")
    return exact


def _sampling_operation_descriptor(operation: dict[str, object]) -> dict[str, object]:
    """Project one exact AnalysisSpec operation into its public sampling owner."""

    mode = operation.get("kind")
    descriptor: dict[str, object] = {
        "descriptor_schema_version": "ebm-audit-sampling-operation-descriptor/1.0",
        "operation_scope": "replicate",
        "experiment_mode": mode,
        "sampling_method_id": operation.get("sampling_method_id"),
        "sampling_design": operation.get("sampling_design"),
        "strata_group_spec_ids": operation.get("strata_group_spec_ids"),
        "replicate_ordinal": operation.get("replicate_ordinal"),
        "refit_preprocessing": operation.get("refit_preprocessing"),
        "fixed_evaluation_cohort_policy": operation.get("fixed_evaluation_cohort_policy"),
        "retained_fraction": (operation.get("retained_fraction") if mode == "subsample" else None),
        "retained_count_rounding_rule": (
            operation.get("retained_count_rounding_rule") if mode == "subsample" else None
        ),
    }
    return _validate_operation_descriptor(descriptor, expected_scope="replicate")


def _sampling_family_descriptor(
    replicate_descriptor: dict[str, object],
) -> dict[str, object]:
    """Remove only the replicate ordinal for one non-poolable family key."""

    exact = _validate_operation_descriptor(
        replicate_descriptor,
        expected_scope="replicate",
    )
    family = {
        **exact,
        "operation_scope": "family",
        "replicate_ordinal": None,
    }
    return _validate_operation_descriptor(family, expected_scope="family")


def _operation_descriptor_digest(descriptor: dict[str, object]) -> str:
    scope = descriptor.get("operation_scope")
    if scope not in {"replicate", "family"}:
        raise _integrity("SCIENCE.SAMPLING_OPERATION_DESCRIPTOR")
    exact = _validate_operation_descriptor(descriptor, expected_scope=scope)
    return structured_sha256(_OPERATION_DESCRIPTOR_DOMAIN, exact)


def _event_semantics(
    record: dict[str, object],
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    semantics = record.get("event_semantics")
    if type(semantics) is not dict:
        raise _integrity("SCIENCE.SAMPLING_EVENT_SEMANTICS")
    event_ids = semantics.get("ordered_event_ids")
    directions = semantics.get("ordered_event_directions")
    stage_digest = semantics.get("stage_semantics_digest")
    if (
        type(event_ids) is not list
        or not event_ids
        or any(type(value) is not str for value in event_ids)
        or len(set(event_ids)) != len(event_ids)
        or type(directions) is not list
        or len(directions) != len(event_ids)
        or any(value not in {"higher", "lower"} for value in directions)
        or type(stage_digest) is not str
    ):
        raise _integrity("SCIENCE.SAMPLING_EVENT_SEMANTICS")
    return (
        tuple(cast(list[str], event_ids)),
        tuple(cast(list[str], directions)),
        stage_digest,
    )


def _within_fit(record: dict[str, object]) -> dict[str, object]:
    value = record.get("within_fit")
    if type(value) is not dict or type(value.get("status")) is not str:
        raise _integrity("SCIENCE.SAMPLING_WITHIN_FIT")
    return cast(dict[str, object], value)


def _finite_square_matrix(
    value: object,
    *,
    size: int,
    code: str,
) -> Any:
    if (
        type(value) is not list
        or len(value) != size
        or any(type(row) is not list or len(row) != size for row in value)
    ):
        raise _integrity(code)
    rows = cast(list[list[object]], value)
    if any(
        type(cell) not in {int, float} or not _math_isfinite(float(cast(int | float, cell)))
        for row in rows
        for cell in row
    ):
        raise _integrity(code)
    return _np_asarray(rows, dtype=_np_float64)


def _absent_scalar(metric_id: str, reason_code: str) -> dict[str, object]:
    return {
        "metric_id": metric_id,
        "status": "NOT_ASSESSABLE",
        "value": None,
        "reason_code": reason_code,
        "metadata_code": None,
    }


def _absent_boolean(metric_id: str, reason_code: str) -> dict[str, object]:
    return {
        "metric_id": metric_id,
        "status": "NOT_ASSESSABLE",
        "value": None,
        "reason_code": reason_code,
        "metadata_code": None,
    }


def _top_k_bundle(
    subject_order: tuple[str, ...] | None,
    source_order: tuple[str, ...] | None,
    *,
    event_ids: tuple[str, ...],
    absent_reason: str,
) -> dict[str, object]:
    k = min(3, len(event_ids))
    if subject_order is None or source_order is None:
        return {
            "rule_id": "first-min-3-events/1",
            "common_event_ids": list(event_ids),
            "common_event_count": len(event_ids),
            "events_only_in_subject": [],
            "events_only_in_source": [],
            "k": k,
            "top_k_overlap": _absent_scalar(
                "top-k-overlap-fraction/1",
                absent_reason,
            ),
            "top_k_jaccard": _absent_scalar(
                "top-k-jaccard/1",
                absent_reason,
            ),
            "first_event_stable": _absent_boolean(
                "first-endpoint-stability/1",
                absent_reason,
            ),
            "last_event_stable": _absent_boolean(
                "last-endpoint-stability/1",
                absent_reason,
            ),
        }
    result = top_k_stability(subject_order, source_order, k=k)
    return {
        "rule_id": "first-min-3-events/1",
        "common_event_ids": list(result.common_event_ids),
        "common_event_count": result.common_event_count,
        "events_only_in_subject": list(result.events_only_in_left),
        "events_only_in_source": list(result.events_only_in_right),
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


def _combined_eligibility(subject_status: str, source_status: str) -> _Eligibility:
    if subject_status == source_status == "SUCCESS":
        return "INTERPRETIVE"
    if subject_status in {"SUCCESS", "CONVERGENCE_WARN"} and source_status in {
        "SUCCESS",
        "CONVERGENCE_WARN",
    }:
        return "DESCRIPTIVE_ONLY"
    return "UNAVAILABLE"


def _component_coverage() -> list[dict[str, object]]:
    return [
        {
            "component": "BOOTSTRAP_ORDER_POSITION_PAIRWISE",
            "implementation_status": "IMPLEMENTED",
            "reason_code": None,
        },
        {
            "component": "DECLARED_SUBSAMPLING",
            "implementation_status": "IMPLEMENTED",
            "reason_code": None,
        },
        {
            "component": "PARTICIPANT_STAGE",
            "implementation_status": "IMPLEMENTED",
            "reason_code": None,
        },
    ]


def _snapshot(
    record: dict[str, object],
    *,
    event_ids: tuple[str, ...],
) -> dict[str, object] | None:
    within = _within_fit(record)
    if within.get("status") != "ASSESSABLE":
        return None
    modal = within.get("retained_state_modal_order_event_ids")
    position = within.get("position_probabilities")
    pairwise = within.get("pairwise_precedence")
    source = within.get("source")
    retained_state_count = within.get("retained_state_count")
    if (
        type(modal) is not list
        or tuple(modal) == ()
        or any(type(value) is not str for value in modal)
        or len(modal) != len(event_ids)
        or set(modal) != set(event_ids)
        or type(source) is not dict
        or set(source)
        != {
            "chain_plan_position",
            "chain_execution_id",
            "final_attempt_id",
            "chain_payload_digest",
            "execution_evidence_digest",
        }
        or type(source.get("chain_plan_position")) is not int
        or cast(int, source.get("chain_plan_position")) < 0
        or any(
            type(source.get(field)) is not str
            for field in (
                "chain_execution_id",
                "final_attempt_id",
                "chain_payload_digest",
                "execution_evidence_digest",
            )
        )
        or type(retained_state_count) is not int
        or retained_state_count < 1
    ):
        raise _integrity("SCIENCE.SAMPLING_REFERENCE_SNAPSHOT")
    _finite_square_matrix(
        position,
        size=len(event_ids),
        code="SCIENCE.SAMPLING_POSITION_MATRIX",
    )
    _finite_square_matrix(
        pairwise,
        size=len(event_ids),
        code="SCIENCE.SAMPLING_PAIRWISE_MATRIX",
    )
    return {
        "reference_chain_source": source,
        "retained_state_count": retained_state_count,
        "modal_order_event_ids": list(cast(list[str], modal)),
        "position_probabilities": position,
        "pairwise_precedence": pairwise,
    }


def _metric_bundle(
    subject_snapshot: dict[str, object] | None,
    source_snapshot: dict[str, object] | None,
    *,
    event_ids: tuple[str, ...],
    absent_reason: str,
) -> tuple[dict[str, object], str, str | None]:
    if subject_snapshot is None or source_snapshot is None:
        absent = {
            metric_id: _absent_scalar(metric_name, absent_reason)
            for metric_name, metric_id in (
                ("central-order-kendall-distance/1", "kendall_distance"),
                ("central-order-footrule-distance/1", "footrule_distance"),
                (
                    "maximum-normalized-event-rank-displacement/1",
                    "maximum_normalized_event_rank_displacement",
                ),
                ("position-matrix-distance/1", "position_matrix_distance"),
                ("pairwise-matrix-distance/1", "pairwise_matrix_distance"),
            )
        }
        unavailable_flips: dict[str, object] = {
            "rule_id": "strict-pairwise-majority-flips/1",
            "denominator_rule_id": "unordered-identical-event-pairs/1",
            "strict_pairwise_majority_flip_denominator": None,
            "flipped_pairs": [],
            "flip_count": _absent_scalar(
                "strict-pairwise-majority-flip-count/1",
                absent_reason,
            ),
            "flip_fraction": _absent_scalar(
                "strict-pairwise-majority-flip-fraction/1",
                absent_reason,
            ),
        }
        return (
            {
                "comparison_rule_id": "sampling-identical-event-reference-comparison/2",
                **absent,
                "top_k_and_endpoint_stability": _top_k_bundle(
                    None,
                    None,
                    event_ids=event_ids,
                    absent_reason=absent_reason,
                ),
                "event_rank_shifts": {
                    "rule_id": "identical-event-rank-shift/1",
                    "status": "NOT_ASSESSABLE",
                    "reason_code": absent_reason,
                    "event_rows": [],
                },
                "pairwise_majority_flips": unavailable_flips,
            },
            "NOT_ASSESSABLE",
            absent_reason,
        )

    subject_order = tuple(cast(list[str], subject_snapshot["modal_order_event_ids"]))
    source_order = tuple(cast(list[str], source_snapshot["modal_order_event_ids"]))
    order = strict_order_comparison(subject_order, source_order)
    if order.common_event_ids != event_ids:
        raise _integrity("SCIENCE.SAMPLING_EVENT_ALIGNMENT")
    shifts = per_event_rank_shifts(subject_order, source_order)
    subject_position = _finite_square_matrix(
        subject_snapshot["position_probabilities"],
        size=len(event_ids),
        code="SCIENCE.SAMPLING_POSITION_MATRIX",
    )
    source_position = _finite_square_matrix(
        source_snapshot["position_probabilities"],
        size=len(event_ids),
        code="SCIENCE.SAMPLING_POSITION_MATRIX",
    )
    subject_pairwise = _finite_square_matrix(
        subject_snapshot["pairwise_precedence"],
        size=len(event_ids),
        code="SCIENCE.SAMPLING_PAIRWISE_MATRIX",
    )
    source_pairwise = _finite_square_matrix(
        source_snapshot["pairwise_precedence"],
        size=len(event_ids),
        code="SCIENCE.SAMPLING_PAIRWISE_MATRIX",
    )
    position_distance = position_matrix_distance(
        subject_position,
        source_position,
        left_event_ids=event_ids,
        right_event_ids=event_ids,
    )
    pairwise_distance = pairwise_matrix_distance(
        subject_pairwise,
        source_pairwise,
        left_event_ids=event_ids,
        right_event_ids=event_ids,
    )
    flip_comparison = strict_pairwise_majority_flips(
        subject_pairwise,
        source_pairwise,
        left_event_ids=event_ids,
        right_event_ids=event_ids,
    )
    top_k = _top_k_bundle(
        subject_order,
        source_order,
        event_ids=event_ids,
        absent_reason=absent_reason,
    )
    metric_rows = (
        _scalar(
            order.kendall_distance,
            metric_id="central-order-kendall-distance/1",
        ),
        _scalar(
            order.footrule_distance,
            metric_id="central-order-footrule-distance/1",
        ),
        _scalar(
            shifts.maximum_normalized_rank_shift,
            metric_id="maximum-normalized-event-rank-displacement/1",
        ),
        _scalar(position_distance, metric_id="position-matrix-distance/1"),
        _scalar(pairwise_distance, metric_id="pairwise-matrix-distance/1"),
        _scalar(
            flip_comparison.flip_count,
            metric_id="strict-pairwise-majority-flip-count/1",
        ),
        _scalar(
            flip_comparison.flip_fraction,
            metric_id="strict-pairwise-majority-flip-fraction/1",
        ),
    )
    status = (
        "FULLY_ASSESSABLE"
        if all(metric["status"] == "ASSESSABLE" for metric in metric_rows)
        and all(
            cast(dict[str, object], top_k[field])["status"] == "ASSESSABLE"
            for field in (
                "top_k_overlap",
                "top_k_jaccard",
                "first_event_stable",
                "last_event_stable",
            )
        )
        else "PARTIALLY_ASSESSABLE"
    )
    reason = None if status == "FULLY_ASSESSABLE" else "SAMPLING.PARTIAL_METRIC_COVERAGE"
    return (
        {
            "comparison_rule_id": "sampling-identical-event-reference-comparison/2",
            "kendall_distance": metric_rows[0],
            "footrule_distance": metric_rows[1],
            "top_k_and_endpoint_stability": top_k,
            "maximum_normalized_event_rank_displacement": metric_rows[2],
            "event_rank_shifts": {
                "rule_id": "identical-event-rank-shift/1",
                "status": "ASSESSABLE",
                "reason_code": None,
                "event_rows": [
                    {
                        "event_id": shift.event_id,
                        "subject_rank": shift.left_rank,
                        "source_rank": shift.right_rank,
                        "absolute_rank_shift": shift.absolute_rank_shift,
                        "normalized_rank_shift": shift.normalized_rank_shift,
                    }
                    for shift in shifts.shifts
                ],
            },
            "position_matrix_distance": metric_rows[3],
            "pairwise_matrix_distance": metric_rows[4],
            "pairwise_majority_flips": {
                "rule_id": "strict-pairwise-majority-flips/1",
                "denominator_rule_id": "unordered-identical-event-pairs/1",
                "strict_pairwise_majority_flip_denominator": (
                    flip_comparison.strict_pairwise_majority_flip_denominator
                ),
                "flipped_pairs": [
                    {
                        "event_a_id": flip.event_a_id,
                        "event_b_id": flip.event_b_id,
                        "subject_probability_a_before_b": (flip.left_probability_a_before_b),
                        "source_probability_a_before_b": (flip.right_probability_a_before_b),
                        "subject_relation": flip.left_relation,
                        "source_relation": flip.right_relation,
                    }
                    for flip in flip_comparison.flips
                ],
                "flip_count": metric_rows[5],
                "flip_fraction": metric_rows[6],
            },
        },
        status,
        reason,
    )


def _validate_sampling_stage_comparison(
    value: object,
    *,
    event_ids: tuple[str, ...],
) -> dict[str, object]:
    try:
        _validate_shared_participant_stage_semantics(
            value,
            common_event_ids=event_ids,
            left_only_event_ids=(),
            right_only_event_ids=(),
            expected_left_ordered_event_ids=event_ids,
            expected_right_ordered_event_ids=event_ids,
        )
    except (TypeError, ValueError, OverflowError):
        raise _integrity("SCIENCE.SAMPLING_STAGE_SEMANTICS") from None
    return cast(dict[str, object], value)


def _stage_comparison_digest(record: dict[str, object]) -> str:
    return structured_sha256(_STAGE_COMPARISON_DOMAIN, record)


def _numeric_identity(
    subject: dict[str, object],
    source: dict[str, object],
    operation_descriptor: dict[str, object],
    participant_stage_comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "subject_analysis_spec_id": subject["analysis_spec_id"],
        "source_analysis_spec_id": source["analysis_spec_id"],
        "subject_result_id": subject["result_id"],
        "source_result_id": source["result_id"],
        "subject_candidate_record_digest": subject["record_digest"],
        "source_candidate_record_digest": source["record_digest"],
        "operation_descriptor_digest": _operation_descriptor_digest(operation_descriptor),
        "participant_stage_comparison_digest": _stage_comparison_digest(
            participant_stage_comparison
        ),
    }


def _derive_numeric(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    subject: dict[str, object],
    source: dict[str, object],
    subject_universe_id: str | None,
    source_universe_id: str | None,
    operation_descriptor: dict[str, object],
    participant_stage_comparison: dict[str, object],
) -> _CanonicalSamplingNumericComparison:
    exact_operation_descriptor = _validate_operation_descriptor(
        operation_descriptor,
        expected_scope="replicate",
    )
    subject_event_ids, subject_directions, subject_stage = _event_semantics(subject)
    source_event_ids, source_directions, source_stage = _event_semantics(source)
    if (
        subject_event_ids != source_event_ids
        or subject_directions != source_directions
        or subject_stage != source_stage
    ):
        raise _integrity("SCIENCE.SAMPLING_SOURCE_SEMANTICS_CHANGED")
    exact_stage_comparison = _validate_sampling_stage_comparison(
        participant_stage_comparison,
        event_ids=subject_event_ids,
    )
    subject_status = cast(str, subject["final_status"])
    source_status = cast(str, source["final_status"])
    eligibility = _combined_eligibility(subject_status, source_status)
    subject_snapshot = (
        None if eligibility == "UNAVAILABLE" else _snapshot(subject, event_ids=subject_event_ids)
    )
    source_snapshot = (
        None if eligibility == "UNAVAILABLE" else _snapshot(source, event_ids=source_event_ids)
    )
    absent_reason = (
        "SAMPLING.TERMINAL_UNAVAILABLE"
        if eligibility == "UNAVAILABLE"
        else "SAMPLING.REFERENCE_SNAPSHOT_UNAVAILABLE"
    )
    metrics, numeric_status, reason_code = _metric_bundle(
        subject_snapshot,
        source_snapshot,
        event_ids=subject_event_ids,
        absent_reason=absent_reason,
    )
    preimage: dict[str, object] = {
        "record_schema_version": SAMPLING_NUMERIC_SCHEMA_VERSION,
        "evidence_rule_id": SAMPLING_EVIDENCE_RULE_ID,
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "numeric_identity": _numeric_identity(
            subject,
            source,
            exact_operation_descriptor,
            exact_stage_comparison,
        ),
        "operation_descriptor": exact_operation_descriptor,
        "subject_universe_id": subject_universe_id,
        "source_universe_id": source_universe_id,
        "subject_terminal_status": subject_status,
        "source_terminal_status": source_status,
        "eligibility": eligibility,
        "event_ids": list(subject_event_ids),
        "event_directions": list(subject_directions),
        "stage_semantics_digest": subject_stage,
        "subject_snapshot": subject_snapshot,
        "source_snapshot": source_snapshot,
        "metric_bundle": metrics,
        "participant_stage_comparison": exact_stage_comparison,
        "numeric_status": numeric_status,
        "reason_code": reason_code,
    }
    digest = structured_sha256(_NUMERIC_DOMAIN, preimage)
    return _CanonicalSamplingNumericComparison(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes({**preimage, "numeric_comparison_digest": digest}),
        numeric_comparison_digest=digest,
    )


def _contribution(
    numeric: dict[str, object],
) -> tuple[_ContributionState, str | None]:
    eligibility = numeric.get("eligibility")
    status = numeric.get("numeric_status")
    if eligibility == "UNAVAILABLE":
        return "FAILED", "SAMPLING.TERMINAL_UNAVAILABLE"
    if status != "FULLY_ASSESSABLE":
        return "METRIC_NOT_ASSESSABLE", cast(str | None, numeric.get("reason_code"))
    if eligibility == "INTERPRETIVE":
        return "INTERPRETIVE", None
    if eligibility == "DESCRIPTIVE_ONLY":
        return "DESCRIPTIVE_ONLY", "SAMPLING.CONVERGENCE_WARNING"
    raise _integrity("SCIENCE.SAMPLING_CONTRIBUTION")


def _derive_attempt(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    origin: dict[str, object],
    edge: dict[str, object],
    operation_descriptor: dict[str, object],
    subject: dict[str, object],
    source: dict[str, object],
    subject_universe_id: str | None,
    source_universe_id: str | None,
    numeric: dict[str, object],
) -> _CanonicalSamplingOriginAttempt:
    exact_operation_descriptor = _validate_operation_descriptor(
        operation_descriptor,
        expected_scope="replicate",
    )
    contribution_state, reason_code = _contribution(numeric)
    preimage: dict[str, object] = {
        "record_schema_version": SAMPLING_ATTEMPT_SCHEMA_VERSION,
        "evidence_rule_id": SAMPLING_EVIDENCE_RULE_ID,
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "origin_id": origin["origin_id"],
        "analysis_declaration_id": origin["analysis_declaration_id"],
        "source_declaration_digest": origin["source_declaration_digest"],
        "experiment_set_id": origin["experiment_set_id"],
        "operation_descriptor": exact_operation_descriptor,
        "comparison_edge": edge,
        "subject_analysis_spec_id": subject["analysis_spec_id"],
        "source_analysis_spec_id": source["analysis_spec_id"],
        "subject_result_id": subject["result_id"],
        "source_result_id": source["result_id"],
        "subject_universe_id": subject_universe_id,
        "source_universe_id": source_universe_id,
        "subject_terminal_status": subject["final_status"],
        "source_terminal_status": source["final_status"],
        "subject_candidate_record_digest": subject["record_digest"],
        "source_candidate_record_digest": source["record_digest"],
        "numeric_comparison_digest": numeric["numeric_comparison_digest"],
        "contribution_state": contribution_state,
        "reason_code": reason_code,
    }
    digest = structured_sha256(_ATTEMPT_DOMAIN, preimage)
    return _CanonicalSamplingOriginAttempt(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes({**preimage, "attempt_digest": digest}),
        attempt_digest=digest,
    )


def _finite_metric(record: dict[str, object], field: str) -> float | None:
    bundle = record.get("metric_bundle")
    metric: object
    if field == "flip_fraction":
        flips = bundle.get("pairwise_majority_flips") if type(bundle) is dict else None
        metric = flips.get("flip_fraction") if type(flips) is dict else None
    elif field in {"top_k_overlap", "top_k_jaccard"}:
        top_k = bundle.get("top_k_and_endpoint_stability") if type(bundle) is dict else None
        metric = top_k.get(field) if type(top_k) is dict else None
    else:
        metric = bundle.get(field) if type(bundle) is dict else None
    if (
        type(metric) is not dict
        or metric.get("status") != "ASSESSABLE"
        or type(metric.get("value")) not in {int, float}
    ):
        return None
    value = float(cast(int | float, metric["value"]))
    return value if _math_isfinite(value) else None


def _boolean_metric(record: dict[str, object], field: str) -> bool | None:
    bundle = record.get("metric_bundle")
    top_k = bundle.get("top_k_and_endpoint_stability") if type(bundle) is dict else None
    metric = top_k.get(field) if type(top_k) is dict else None
    if (
        type(metric) is not dict
        or metric.get("status") != "ASSESSABLE"
        or type(metric.get("value")) is not bool
    ):
        return None
    return cast(bool, metric["value"])


def _distribution(values: list[float], *, metric_id: str) -> dict[str, object]:
    if not values:
        return {
            "metric_id": metric_id,
            "quantile_rule_id": "inverse-empirical-cdf/1",
            "status": "NOT_ASSESSABLE",
            "valid_count": 0,
            "q10": None,
            "median": None,
            "q90": None,
            "maximum": None,
            "reason_code": "SAMPLING.NO_INTERPRETIVE_CONTRIBUTORS",
        }
    quantiles = tuple(empirical_quantile(values, probability) for probability in (0.1, 0.5, 0.9))
    if any(
        result.status != "ASSESSABLE" or type(result.value) is not float for result in quantiles
    ):
        raise _integrity("SCIENCE.SAMPLING_DISTRIBUTION")
    return {
        "metric_id": metric_id,
        "quantile_rule_id": "inverse-empirical-cdf/1",
        "status": "ASSESSABLE",
        "valid_count": len(values),
        "q10": quantiles[0].value,
        "median": quantiles[1].value,
        "q90": quantiles[2].value,
        "maximum": max(values),
        "reason_code": None,
    }


def _event_position_frequencies(
    records: tuple[dict[str, object], ...],
    event_ids: tuple[str, ...],
) -> list[dict[str, object]]:
    counts = {event_id: [0 for _ in event_ids] for event_id in event_ids}
    for record in records:
        snapshot = record.get("subject_snapshot")
        modal = snapshot.get("modal_order_event_ids") if type(snapshot) is dict else None
        if type(modal) is not list or set(modal) != set(event_ids):
            raise _integrity("SCIENCE.SAMPLING_MODAL_FREQUENCY")
        for position, event_id in enumerate(cast(list[str], modal)):
            counts[event_id][position] += 1
    denominator = len(records)
    return [
        {
            "event_id": event_id,
            "contributing_count": denominator,
            "position_counts": counts[event_id],
            "position_frequencies": (
                [] if denominator == 0 else [count / denominator for count in counts[event_id]]
            ),
        }
        for event_id in event_ids
    ]


def _central_order_relation_frequencies(
    records: tuple[dict[str, object], ...],
    event_ids: tuple[str, ...],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    denominator = len(records)
    for left_index, event_a_id in enumerate(event_ids[:-1]):
        for right_index in range(left_index + 1, len(event_ids)):
            event_b_id = event_ids[right_index]
            relation_counts = {"A_BEFORE_B": 0, "B_BEFORE_A": 0, "TIED": 0}
            for record in records:
                snapshot = record.get("subject_snapshot")
                modal = snapshot.get("modal_order_event_ids") if type(snapshot) is dict else None
                if type(modal) is not list or set(modal) != set(event_ids):
                    raise _integrity("SCIENCE.SAMPLING_CENTRAL_ORDER_FREQUENCY")
                positions = {
                    event_id: position for position, event_id in enumerate(cast(list[str], modal))
                }
                relation = (
                    "A_BEFORE_B" if positions[event_a_id] < positions[event_b_id] else "B_BEFORE_A"
                )
                relation_counts[relation] += 1
            rows.append(
                {
                    "relation_basis": "CENTRAL_ORDER",
                    "event_a_id": event_a_id,
                    "event_b_id": event_b_id,
                    "contributing_count": denominator,
                    "a_before_b_count": relation_counts["A_BEFORE_B"],
                    "b_before_a_count": relation_counts["B_BEFORE_A"],
                    "tied_count": relation_counts["TIED"],
                    "a_before_b_frequency": (
                        None if denominator == 0 else relation_counts["A_BEFORE_B"] / denominator
                    ),
                    "b_before_a_frequency": (
                        None if denominator == 0 else relation_counts["B_BEFORE_A"] / denominator
                    ),
                    "tied_frequency": (
                        None if denominator == 0 else relation_counts["TIED"] / denominator
                    ),
                }
            )
    return rows


def _within_fit_majority_relation_frequencies(
    records: tuple[dict[str, object], ...],
    event_ids: tuple[str, ...],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    denominator = len(records)
    for left_index, event_a_id in enumerate(event_ids[:-1]):
        for right_index in range(left_index + 1, len(event_ids)):
            event_b_id = event_ids[right_index]
            relation_counts = {"A_BEFORE_B": 0, "B_BEFORE_A": 0, "TIED": 0}
            for record in records:
                snapshot = record.get("subject_snapshot")
                matrix = snapshot.get("pairwise_precedence") if type(snapshot) is dict else None
                exact = _finite_square_matrix(
                    matrix,
                    size=len(event_ids),
                    code="SCIENCE.SAMPLING_PAIRWISE_FREQUENCY",
                )
                relations = strict_pairwise_majority_relations(
                    exact,
                    event_ids=event_ids,
                )
                if relations.status != "ASSESSABLE" or relations.value is None:
                    raise _integrity("SCIENCE.SAMPLING_PAIRWISE_FREQUENCY")
                match = tuple(
                    relation
                    for relation in relations.value
                    if relation.event_a_id == event_a_id and relation.event_b_id == event_b_id
                )
                if len(match) != 1:
                    raise _integrity("SCIENCE.SAMPLING_PAIRWISE_FREQUENCY")
                relation_counts[match[0].relation] += 1
            rows.append(
                {
                    "relation_basis": "WITHIN_FIT_PAIRWISE_MAJORITY",
                    "event_a_id": event_a_id,
                    "event_b_id": event_b_id,
                    "contributing_count": denominator,
                    "a_before_b_count": relation_counts["A_BEFORE_B"],
                    "b_before_a_count": relation_counts["B_BEFORE_A"],
                    "tied_count": relation_counts["TIED"],
                    "a_before_b_frequency": (
                        None if denominator == 0 else relation_counts["A_BEFORE_B"] / denominator
                    ),
                    "b_before_a_frequency": (
                        None if denominator == 0 else relation_counts["B_BEFORE_A"] / denominator
                    ),
                    "tied_frequency": (
                        None if denominator == 0 else relation_counts["TIED"] / denominator
                    ),
                }
            )
    return rows


def _within_fit_pairwise_probability_distributions(
    records: tuple[dict[str, object], ...],
    event_ids: tuple[str, ...],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for left_index, event_a_id in enumerate(event_ids[:-1]):
        for right_index in range(left_index + 1, len(event_ids)):
            event_b_id = event_ids[right_index]
            values: list[float] = []
            for record in records:
                snapshot = record.get("subject_snapshot")
                matrix = snapshot.get("pairwise_precedence") if type(snapshot) is dict else None
                exact = _finite_square_matrix(
                    matrix,
                    size=len(event_ids),
                    code="SCIENCE.SAMPLING_PAIRWISE_DISTRIBUTION",
                )
                value = float(exact[left_index, right_index])
                if not 0.0 <= value <= 1.0:
                    raise _integrity("SCIENCE.SAMPLING_PAIRWISE_DISTRIBUTION")
                values.append(value)
            quantiles = tuple(
                empirical_quantile(values, probability) for probability in (0.1, 0.5, 0.9)
            )
            if any(
                result.status != "ASSESSABLE" or type(result.value) is not float
                for result in quantiles
            ):
                raise _integrity("SCIENCE.SAMPLING_PAIRWISE_DISTRIBUTION")
            rows.append(
                {
                    "event_a_id": event_a_id,
                    "event_b_id": event_b_id,
                    "probability_metric_id": "within-fit-pairwise-precedence-probability/1",
                    "quantile_rule_id": "inverse-empirical-cdf/1",
                    "contributing_count": len(values),
                    "q10": quantiles[0].value,
                    "median": quantiles[1].value,
                    "q90": quantiles[2].value,
                    "minimum": min(values),
                    "maximum": max(values),
                    "mean": sum(values) / len(values),
                }
            )
    return rows


def _endpoint_stability_summary(
    records: tuple[dict[str, object], ...],
    event_ids: tuple[str, ...],
) -> dict[str, object]:
    first = [
        value
        for record in records
        if (value := _boolean_metric(record, "first_event_stable")) is not None
    ]
    last = [
        value
        for record in records
        if (value := _boolean_metric(record, "last_event_stable")) is not None
    ]
    if len(first) != len(records) or len(last) != len(records):
        raise _integrity("SCIENCE.SAMPLING_ENDPOINT_STABILITY")
    denominator = len(records)
    return {
        "rule_id": "first-min-3-events/1",
        "k": None if not event_ids else min(3, len(event_ids)),
        "contributing_count": denominator,
        "first_event_stable_count": sum(first),
        "first_event_stable_frequency": (None if denominator == 0 else sum(first) / denominator),
        "last_event_stable_count": sum(last),
        "last_event_stable_frequency": (None if denominator == 0 else sum(last) / denominator),
        "reason_code": ("SAMPLING.NO_INTERPRETIVE_CONTRIBUTORS" if denominator == 0 else None),
    }


def _derive_aggregate(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    experiment_set_id: str,
    source_analysis_spec_id: str,
    operation_descriptor: dict[str, object],
    rows: tuple[tuple[dict[str, object], dict[str, object]], ...],
) -> _CanonicalSamplingFamilyAggregate:
    exact_family_descriptor = _validate_operation_descriptor(
        operation_descriptor,
        expected_scope="family",
    )
    attempts = tuple(row[0] for row in rows)
    numeric_by_digest: dict[str, dict[str, object]] = {}
    for attempt, numeric in rows:
        digest = numeric.get("numeric_comparison_digest")
        replicate_descriptor = _validate_operation_descriptor(
            attempt.get("operation_descriptor"),
            expected_scope="replicate",
        )
        if (
            type(digest) is not str
            or attempt.get("numeric_comparison_digest") != digest
            or numeric.get("operation_descriptor") != replicate_descriptor
            or _sampling_family_descriptor(replicate_descriptor) != exact_family_descriptor
        ):
            raise _integrity("SCIENCE.SAMPLING_AGGREGATE_SOURCE")
        previous = numeric_by_digest.setdefault(digest, numeric)
        if previous != numeric:
            raise _integrity("SCIENCE.SAMPLING_NUMERIC_DEDUPLICATION")
    unique_numeric = tuple(
        numeric_by_digest[digest] for digest in sorted(numeric_by_digest, key=_utf8)
    )
    interpretive = tuple(
        numeric for numeric in unique_numeric if _contribution(numeric)[0] == "INTERPRETIVE"
    )
    if interpretive:
        first_event_ids = interpretive[0].get("event_ids")
        if type(first_event_ids) is not list or any(
            numeric.get("event_ids") != first_event_ids for numeric in interpretive[1:]
        ):
            raise _integrity("SCIENCE.SAMPLING_FAMILY_EVENT_IDENTITY")
        event_ids = tuple(cast(list[str], first_event_ids))
    else:
        event_ids = ()
    candidate_contribution_counts = {
        state: sum(_contribution(numeric)[0] == state for numeric in unique_numeric)
        for state in _CONTRIBUTION_STATES
    }
    origin_contribution_counts = {
        state: sum(attempt.get("contribution_state") == state for attempt in attempts)
        for state in _CONTRIBUTION_STATES
    }
    metric_summaries = [
        _distribution(
            [
                value
                for numeric in interpretive
                if (value := _finite_metric(numeric, field)) is not None
            ],
            metric_id=metric_id,
        )
        for metric_id, field in _SUMMARY_METRICS
    ]
    preimage: dict[str, object] = {
        "record_schema_version": SAMPLING_AGGREGATE_SCHEMA_VERSION,
        "evidence_rule_id": SAMPLING_EVIDENCE_RULE_ID,
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "experiment_set_id": experiment_set_id,
        "source_analysis_spec_id": source_analysis_spec_id,
        "operation_descriptor": exact_family_descriptor,
        "replicate_ordinals": sorted(
            {
                cast(
                    int,
                    cast(
                        dict[str, object],
                        attempt["operation_descriptor"],
                    )["replicate_ordinal"],
                )
                for attempt in attempts
            }
        ),
        "planned_origin_count": len(attempts),
        "planned_unique_candidate_count": len(
            {attempt["subject_analysis_spec_id"] for attempt in attempts}
        ),
        "unique_numeric_record_count": len(unique_numeric),
        "interpretive_numeric_count": len(interpretive),
        "candidate_contribution_counts": candidate_contribution_counts,
        "origin_contribution_counts": origin_contribution_counts,
        "attempt_digests": [attempt["attempt_digest"] for attempt in attempts],
        "numeric_comparison_digests": [
            numeric["numeric_comparison_digest"] for numeric in unique_numeric
        ],
        "metric_summaries": metric_summaries,
        "event_modal_position_frequencies": _event_position_frequencies(
            interpretive,
            event_ids,
        ),
        "endpoint_stability": _endpoint_stability_summary(
            interpretive,
            event_ids,
        ),
        "central_order_relation_frequencies": _central_order_relation_frequencies(
            interpretive,
            event_ids,
        ),
        "within_fit_majority_relation_frequencies": (
            _within_fit_majority_relation_frequencies(
                interpretive,
                event_ids,
            )
        ),
        "within_fit_pairwise_probability_distributions": (
            _within_fit_pairwise_probability_distributions(
                interpretive,
                event_ids,
            )
        ),
        "classification_status": "NO_FROZEN_SAMPLING_CLASSIFICATION",
    }
    digest = structured_sha256(_AGGREGATE_DOMAIN, preimage)
    return _CanonicalSamplingFamilyAggregate(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes({**preimage, "aggregate_digest": digest}),
        aggregate_digest=digest,
    )


def _validate_sampling_semantics(layer: dict[str, object]) -> None:
    try:
        if (
            type(layer) is not dict
            or layer.get("layer_schema_version") != SAMPLING_LAYER_SCHEMA_VERSION
            or layer.get("evidence_rule_id") != SAMPLING_EVIDENCE_RULE_ID
            or layer.get("uncertainty_layer") != "SAMPLING"
        ):
            raise _integrity("SCIENCE.SAMPLING_LAYER_SEMANTICS")
        attempts = layer.get("attempts")
        numeric_records = layer.get("numeric_records")
        aggregates = layer.get("aggregates")
        if (
            type(attempts) is not list
            or type(numeric_records) is not list
            or type(aggregates) is not list
            or any(type(value) is not dict for value in (*attempts, *numeric_records, *aggregates))
        ):
            raise _integrity("SCIENCE.SAMPLING_LAYER_SEMANTICS")
        exact_attempts = cast(list[dict[str, object]], attempts)
        exact_numeric = cast(list[dict[str, object]], numeric_records)
        exact_aggregates = cast(list[dict[str, object]], aggregates)
        plan_digest = layer.get("plan_digest")
        terminal_index_digest = layer.get("terminal_index_digest")
        if (
            type(plan_digest) is not str
            or type(terminal_index_digest) is not str
            or layer.get("pooling_policy") != "NON_POOLABLE_ACROSS_OPERATION_FAMILIES"
            or layer.get("classification_status") != "NO_FROZEN_SAMPLING_CLASSIFICATION"
            or layer.get("component_coverage") != _component_coverage()
            or layer.get("attempt_count") != len(exact_attempts)
            or layer.get("unique_numeric_record_count") != len(exact_numeric)
            or layer.get("family_count") != len(exact_aggregates)
        ):
            raise _integrity("SCIENCE.SAMPLING_LAYER_ACCOUNTING")
        attempt_origin_ids = [attempt.get("origin_id") for attempt in exact_attempts]
        if (
            any(type(origin_id) is not str for origin_id in attempt_origin_ids)
            or len(set(attempt_origin_ids)) != len(attempt_origin_ids)
            or attempt_origin_ids
            != sorted(
                cast(list[str], attempt_origin_ids),
                key=_utf8,
            )
        ):
            raise _integrity("SCIENCE.SAMPLING_ATTEMPT_ORDER")
        numeric_by_digest: dict[str, dict[str, object]] = {}
        numeric_identities: list[tuple[str, str, str, str, str, str, str, str]] = []
        for record in exact_numeric:
            preimage = dict(record)
            supplied = preimage.pop("numeric_comparison_digest", None)
            identity = record.get("numeric_identity")
            if type(identity) is not dict:
                raise _integrity("SCIENCE.SAMPLING_NUMERIC_IDENTITY")
            exact_identity = cast(dict[str, object], identity)
            identity_tuple = (
                exact_identity.get("subject_analysis_spec_id"),
                exact_identity.get("source_analysis_spec_id"),
                exact_identity.get("subject_result_id"),
                exact_identity.get("source_result_id"),
                exact_identity.get("subject_candidate_record_digest"),
                exact_identity.get("source_candidate_record_digest"),
                exact_identity.get("operation_descriptor_digest"),
                exact_identity.get("participant_stage_comparison_digest"),
            )
            operation_descriptor = _validate_operation_descriptor(
                record.get("operation_descriptor"),
                expected_scope="replicate",
            )
            subject_status = record.get("subject_terminal_status")
            source_status = record.get("source_terminal_status")
            event_ids_value = record.get("event_ids")
            event_directions = record.get("event_directions")
            if (
                type(supplied) is not str
                or any(type(value) is not str for value in identity_tuple)
                or supplied in numeric_by_digest
                or record.get("record_schema_version") != SAMPLING_NUMERIC_SCHEMA_VERSION
                or record.get("evidence_rule_id") != SAMPLING_EVIDENCE_RULE_ID
                or record.get("plan_digest") != plan_digest
                or record.get("terminal_index_digest") != terminal_index_digest
                or exact_identity.get("operation_descriptor_digest")
                != _operation_descriptor_digest(operation_descriptor)
                or subject_status not in _TERMINAL_STATUSES
                or source_status not in _TERMINAL_STATUSES
                or record.get("eligibility")
                != _combined_eligibility(
                    subject_status,
                    source_status,
                )
                or type(event_ids_value) is not list
                or not event_ids_value
                or any(type(value) is not str for value in event_ids_value)
                or len(set(event_ids_value)) != len(event_ids_value)
                or type(event_directions) is not list
                or len(event_directions) != len(event_ids_value)
                or any(value not in {"higher", "lower"} for value in event_directions)
                or type(record.get("stage_semantics_digest")) is not str
                or supplied != structured_sha256(_NUMERIC_DOMAIN, preimage)
                or canonical_json_bytes(record)
                != canonical_json_bytes({**preimage, "numeric_comparison_digest": supplied})
            ):
                raise _integrity("SCIENCE.SAMPLING_NUMERIC_IDENTITY")
            event_ids = tuple(cast(list[str], event_ids_value))
            stage_comparison = _validate_sampling_stage_comparison(
                record.get("participant_stage_comparison"),
                event_ids=event_ids,
            )
            if exact_identity.get(
                "participant_stage_comparison_digest"
            ) != _stage_comparison_digest(stage_comparison):
                raise _integrity("SCIENCE.SAMPLING_NUMERIC_IDENTITY")
            numeric_by_digest[supplied] = record
            numeric_identities.append(
                cast(tuple[str, str, str, str, str, str, str, str], identity_tuple)
            )
            expected_bundle, expected_status, expected_reason = _metric_bundle(
                cast(dict[str, object] | None, record.get("subject_snapshot")),
                cast(dict[str, object] | None, record.get("source_snapshot")),
                event_ids=event_ids,
                absent_reason=(
                    "SAMPLING.TERMINAL_UNAVAILABLE"
                    if record.get("eligibility") == "UNAVAILABLE"
                    else "SAMPLING.REFERENCE_SNAPSHOT_UNAVAILABLE"
                ),
            )
            if (
                record.get("metric_bundle") != expected_bundle
                or record.get("numeric_status") != expected_status
                or record.get("reason_code") != expected_reason
            ):
                raise _integrity("SCIENCE.SAMPLING_NUMERIC_METRICS")
        if len(set(numeric_identities)) != len(numeric_identities) or numeric_identities != sorted(
            numeric_identities,
            key=lambda identity: tuple(_utf8(value) for value in identity),
        ):
            raise _integrity("SCIENCE.SAMPLING_NUMERIC_ORDER")
        aggregate_sources: dict[
            tuple[str, str, str],
            list[tuple[dict[str, object], dict[str, object]]],
        ] = {}
        aggregate_descriptors: dict[
            tuple[str, str, str],
            dict[str, object],
        ] = {}
        referenced_numeric_digests: set[str] = set()
        for attempt in exact_attempts:
            preimage = dict(attempt)
            supplied = preimage.pop("attempt_digest", None)
            numeric = numeric_by_digest.get(cast(str, attempt.get("numeric_comparison_digest")))
            numeric_identity = numeric.get("numeric_identity") if type(numeric) is dict else None
            comparison_edge = attempt.get("comparison_edge")
            operation_descriptor = _validate_operation_descriptor(
                attempt.get("operation_descriptor"),
                expected_scope="replicate",
            )
            family_descriptor = _sampling_family_descriptor(operation_descriptor)
            aggregate_key_values = (
                attempt.get("experiment_set_id"),
                attempt.get("source_analysis_spec_id"),
                _operation_descriptor_digest(family_descriptor),
            )
            if (
                numeric is None
                or type(numeric_identity) is not dict
                or type(comparison_edge) is not dict
                or type(supplied) is not str
                or any(type(value) is not str for value in aggregate_key_values)
                or attempt.get("record_schema_version") != SAMPLING_ATTEMPT_SCHEMA_VERSION
                or attempt.get("evidence_rule_id") != SAMPLING_EVIDENCE_RULE_ID
                or attempt.get("plan_digest") != plan_digest
                or attempt.get("terminal_index_digest") != terminal_index_digest
                or supplied != structured_sha256(_ATTEMPT_DOMAIN, preimage)
                or comparison_edge.get("origin_id") != attempt.get("origin_id")
                or comparison_edge.get("subject_analysis_spec_id")
                != attempt.get("subject_analysis_spec_id")
                or comparison_edge.get("comparator_analysis_spec_id")
                != attempt.get("source_analysis_spec_id")
                or comparison_edge.get("derivation_rule_id") != "derived-origin-to-source/1"
                or comparison_edge.get("semantics")
                != {
                    "order_event_alignment": "identical-event-set",
                    "native_stage_comparability": "comparable",
                }
                or attempt.get("subject_analysis_spec_id")
                != numeric_identity.get("subject_analysis_spec_id")
                or attempt.get("source_analysis_spec_id")
                != numeric_identity.get("source_analysis_spec_id")
                or attempt.get("subject_result_id") != numeric_identity.get("subject_result_id")
                or attempt.get("source_result_id") != numeric_identity.get("source_result_id")
                or attempt.get("subject_candidate_record_digest")
                != numeric_identity.get("subject_candidate_record_digest")
                or attempt.get("source_candidate_record_digest")
                != numeric_identity.get("source_candidate_record_digest")
                or attempt.get("operation_descriptor") != numeric.get("operation_descriptor")
                or numeric_identity.get("operation_descriptor_digest")
                != _operation_descriptor_digest(operation_descriptor)
                or attempt.get("subject_universe_id") != numeric.get("subject_universe_id")
                or attempt.get("source_universe_id") != numeric.get("source_universe_id")
                or attempt.get("subject_terminal_status") != numeric.get("subject_terminal_status")
                or attempt.get("source_terminal_status") != numeric.get("source_terminal_status")
                or _contribution(numeric)
                != (attempt.get("contribution_state"), attempt.get("reason_code"))
            ):
                raise _integrity("SCIENCE.SAMPLING_ATTEMPT_SEMANTICS")
            aggregate_key = cast(tuple[str, str, str], aggregate_key_values)
            aggregate_sources.setdefault(aggregate_key, []).append((attempt, numeric))
            previous_descriptor = aggregate_descriptors.setdefault(
                aggregate_key,
                family_descriptor,
            )
            if previous_descriptor != family_descriptor:
                raise _integrity("SCIENCE.SAMPLING_AGGREGATE_SOURCE")
            referenced_numeric_digests.add(cast(str, attempt["numeric_comparison_digest"]))
        if set(numeric_by_digest) != referenced_numeric_digests:
            raise _integrity("SCIENCE.SAMPLING_NUMERIC_COVERAGE")
        expected_aggregates = [
            strict_json_loads(
                _derive_aggregate(
                    plan_digest=plan_digest,
                    terminal_index_digest=terminal_index_digest,
                    experiment_set_id=key[0],
                    source_analysis_spec_id=key[1],
                    operation_descriptor=aggregate_descriptors[key],
                    rows=tuple(aggregate_sources[key]),
                ).canonical_bytes
            )
            for key in sorted(
                aggregate_sources,
                key=lambda item: tuple(_utf8(value) for value in item),
            )
        ]
        if exact_aggregates != expected_aggregates:
            raise _integrity("SCIENCE.SAMPLING_AGGREGATE_SEMANTICS")
        layer_preimage = dict(layer)
        supplied_layer_digest = layer_preimage.pop("layer_digest", None)
        if supplied_layer_digest != structured_sha256(_LAYER_DOMAIN, layer_preimage):
            raise _integrity("SCIENCE.SAMPLING_LAYER_DIGEST")
    except _ScientificRecordIntegrityError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError):
        raise _integrity("SCIENCE.SAMPLING_LAYER_SEMANTICS") from None


def _derive_sampling_evidence(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    candidates: tuple[_SamplingCandidateInput, ...],
) -> _CanonicalSamplingEvidenceBundle:
    """Derive declared sampling evidence from exact sealed candidate records."""

    if type(plan_digest) is not str or type(terminal_index_digest) is not str or not candidates:
        raise _integrity("SCIENCE.SAMPLING_RUN_IDENTITY")
    decoded: list[
        tuple[
            _SamplingCandidateInput,
            dict[str, object],
            dict[str, object],
        ]
    ] = []
    for expected_ordinal, candidate in enumerate(candidates):
        if type(candidate) is not _SamplingCandidateInput:
            raise _integrity("SCIENCE.SAMPLING_CANDIDATE_INPUT")
        record = _closed_record(
            candidate.candidate_record_bytes,
            code="SCIENCE.SAMPLING_CANDIDATE_BYTES",
        )
        operation = _closed_record(
            candidate.operation_bytes,
            code="SCIENCE.SAMPLING_OPERATION_BYTES",
        )
        candidate_identity = _candidate_identity(record)
        if (
            candidate_identity[0] != expected_ordinal
            or (candidate.universe_id is not None and type(candidate.universe_id) is not str)
            or not candidate.origins
        ):
            raise _integrity("SCIENCE.SAMPLING_CANDIDATE_INPUT")
        decoded.append((candidate, record, operation))
    by_analysis = {
        cast(str, record["analysis_spec_id"]): (candidate, record, operation)
        for candidate, record, operation in decoded
    }
    if len(by_analysis) != len(decoded):
        raise _integrity("SCIENCE.SAMPLING_CANDIDATE_IDENTITY")

    contexts: list[
        tuple[
            dict[str, object],
            dict[str, object],
            dict[str, object],
            _SamplingCandidateInput,
            dict[str, object],
            _SamplingCandidateInput,
            dict[str, object],
            dict[str, object],
        ]
    ] = []
    sampling_kinds = {"bootstrap", "subsample"}
    observed_origin_ids: set[str] = set()
    for subject_input, subject, operation in decoded:
        kind = operation.get("kind")
        for retained in subject_input.origins:
            if type(retained) is not _SamplingOriginInput:
                raise _integrity("SCIENCE.SAMPLING_ORIGIN_INPUT")
            origin = _closed_record(
                retained.origin_bytes,
                code="SCIENCE.SAMPLING_ORIGIN_BYTES",
            )
            edge = _closed_record(
                retained.comparison_edge_bytes,
                code="SCIENCE.SAMPLING_EDGE_BYTES",
            )
            origin_id = origin.get("origin_id")
            mode = origin.get("experiment_mode")
            if type(origin_id) is not str or origin_id in observed_origin_ids:
                raise _integrity("SCIENCE.SAMPLING_ORIGIN_IDENTITY")
            observed_origin_ids.add(origin_id)
            if kind not in sampling_kinds:
                if mode in sampling_kinds:
                    raise _integrity("SCIENCE.SAMPLING_OPERATION_ORIGIN_MISMATCH")
                continue
            participant_stage_comparison = _closed_record(
                retained.stage_comparison_bytes,
                code="SCIENCE.SAMPLING_STAGE_BYTES",
            )
            source_id = operation.get("source_analysis_spec_id")
            source_entry = by_analysis.get(cast(str, source_id))
            if (
                mode != kind
                or type(origin.get("experiment_set_id")) is not str
                or type(source_id) is not str
                or source_entry is None
                or edge.get("origin_id") != origin_id
                or edge.get("subject_analysis_spec_id") != subject["analysis_spec_id"]
                or edge.get("comparator_analysis_spec_id") != source_id
                or edge.get("derivation_rule_id") != "derived-origin-to-source/1"
                or edge.get("semantics")
                != {
                    "order_event_alignment": "identical-event-set",
                    "native_stage_comparability": "comparable",
                }
            ):
                raise _integrity("SCIENCE.SAMPLING_OPERATION_ORIGIN_MISMATCH")
            _sampling_operation_descriptor(operation)
            source_input, source, source_operation = source_entry
            if source_operation.get("kind") != "ordinary":
                raise _integrity("SCIENCE.SAMPLING_SOURCE_NOT_ORDINARY")
            contexts.append(
                (
                    origin,
                    edge,
                    operation,
                    subject_input,
                    subject,
                    source_input,
                    source,
                    participant_stage_comparison,
                )
            )
    contexts.sort(key=lambda row: _utf8(cast(str, row[0]["origin_id"])))

    numeric_by_identity: dict[
        tuple[str, str, str, str, str, str, str, str],
        _CanonicalSamplingNumericComparison,
    ] = {}
    decoded_numeric_by_identity: dict[
        tuple[str, str, str, str, str, str, str, str],
        dict[str, object],
    ] = {}
    context_identity: dict[str, tuple[str, str, str, str, str, str, str, str]] = {}
    identity_by_subject_operation: dict[
        tuple[str, str, str],
        tuple[str, str, str, str, str, str, str, str],
    ] = {}
    for (
        origin,
        _edge,
        operation,
        subject_input,
        subject,
        source_input,
        source,
        participant_stage_comparison,
    ) in contexts:
        operation_descriptor = _sampling_operation_descriptor(operation)
        identity_record = _numeric_identity(
            subject,
            source,
            operation_descriptor,
            participant_stage_comparison,
        )
        identity = (
            cast(str, identity_record["subject_analysis_spec_id"]),
            cast(str, identity_record["source_analysis_spec_id"]),
            cast(str, identity_record["subject_result_id"]),
            cast(str, identity_record["source_result_id"]),
            cast(str, identity_record["subject_candidate_record_digest"]),
            cast(str, identity_record["source_candidate_record_digest"]),
            cast(str, identity_record["operation_descriptor_digest"]),
            cast(str, identity_record["participant_stage_comparison_digest"]),
        )
        subject_operation_key = (
            identity[0],
            identity[1],
            identity[6],
        )
        previous_identity = identity_by_subject_operation.setdefault(
            subject_operation_key,
            identity,
        )
        if previous_identity != identity:
            raise _integrity("SCIENCE.SAMPLING_STAGE_IDENTITY_CONFLICT")
        envelope = numeric_by_identity.get(identity)
        if envelope is None:
            envelope = _derive_numeric(
                plan_digest=plan_digest,
                terminal_index_digest=terminal_index_digest,
                subject=subject,
                source=source,
                subject_universe_id=subject_input.universe_id,
                source_universe_id=source_input.universe_id,
                operation_descriptor=operation_descriptor,
                participant_stage_comparison=participant_stage_comparison,
            )
            numeric_by_identity[identity] = envelope
            numeric_decoded = strict_json_loads(envelope.canonical_bytes)
            if type(numeric_decoded) is not dict:
                raise _integrity("SCIENCE.SAMPLING_NUMERIC_RECORD")
            decoded_numeric_by_identity[identity] = cast(
                dict[str, object],
                numeric_decoded,
            )
        context_identity[cast(str, origin["origin_id"])] = identity

    numeric_envelopes = tuple(
        envelope
        for _identity, envelope in sorted(
            numeric_by_identity.items(),
            key=lambda item: tuple(_utf8(value) for value in item[0]),
        )
    )
    attempt_envelopes: list[_CanonicalSamplingOriginAttempt] = []
    aggregate_sources: dict[
        tuple[str, str, str],
        list[tuple[dict[str, object], dict[str, object]]],
    ] = {}
    aggregate_descriptors: dict[
        tuple[str, str, str],
        dict[str, object],
    ] = {}
    for (
        origin,
        edge,
        operation,
        subject_input,
        subject,
        source_input,
        source,
        _participant_stage_comparison,
    ) in contexts:
        operation_descriptor = _sampling_operation_descriptor(operation)
        numeric = decoded_numeric_by_identity[context_identity[cast(str, origin["origin_id"])]]
        attempt = _derive_attempt(
            plan_digest=plan_digest,
            terminal_index_digest=terminal_index_digest,
            origin=origin,
            edge=edge,
            operation_descriptor=operation_descriptor,
            subject=subject,
            source=source,
            subject_universe_id=subject_input.universe_id,
            source_universe_id=source_input.universe_id,
            numeric=numeric,
        )
        decoded_attempt = strict_json_loads(attempt.canonical_bytes)
        if type(decoded_attempt) is not dict:
            raise _integrity("SCIENCE.SAMPLING_ATTEMPT_RECORD")
        exact_attempt = cast(dict[str, object], decoded_attempt)
        attempt_envelopes.append(attempt)
        key = (
            cast(str, origin["experiment_set_id"]),
            cast(str, source["analysis_spec_id"]),
            _operation_descriptor_digest(_sampling_family_descriptor(operation_descriptor)),
        )
        aggregate_sources.setdefault(key, []).append((exact_attempt, numeric))
        family_descriptor = _sampling_family_descriptor(operation_descriptor)
        previous_descriptor = aggregate_descriptors.setdefault(
            key,
            family_descriptor,
        )
        if previous_descriptor != family_descriptor:
            raise _integrity("SCIENCE.SAMPLING_AGGREGATE_SOURCE")
    attempts = tuple(attempt_envelopes)
    aggregates = tuple(
        _derive_aggregate(
            plan_digest=plan_digest,
            terminal_index_digest=terminal_index_digest,
            experiment_set_id=key[0],
            source_analysis_spec_id=key[1],
            operation_descriptor=aggregate_descriptors[key],
            rows=tuple(aggregate_sources[key]),
        )
        for key in sorted(
            aggregate_sources,
            key=lambda item: tuple(_utf8(value) for value in item),
        )
    )
    decoded_attempts = [
        cast(dict[str, object], strict_json_loads(value.canonical_bytes)) for value in attempts
    ]
    decoded_numeric = [
        cast(dict[str, object], strict_json_loads(value.canonical_bytes))
        for value in numeric_envelopes
    ]
    decoded_aggregates = [
        cast(dict[str, object], strict_json_loads(value.canonical_bytes)) for value in aggregates
    ]
    preimage: dict[str, object] = {
        "layer_schema_version": SAMPLING_LAYER_SCHEMA_VERSION,
        "evidence_rule_id": SAMPLING_EVIDENCE_RULE_ID,
        "uncertainty_layer": "SAMPLING",
        "pooling_policy": "NON_POOLABLE_ACROSS_OPERATION_FAMILIES",
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "component_coverage": _component_coverage(),
        "attempt_count": len(decoded_attempts),
        "unique_numeric_record_count": len(decoded_numeric),
        "family_count": len(decoded_aggregates),
        "attempts": decoded_attempts,
        "numeric_records": decoded_numeric,
        "aggregates": decoded_aggregates,
        "classification_status": "NO_FROZEN_SAMPLING_CLASSIFICATION",
    }
    layer_digest = structured_sha256(_LAYER_DOMAIN, preimage)
    layer = _CanonicalSamplingLayerEvidence(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes({**preimage, "layer_digest": layer_digest}),
        layer_digest=layer_digest,
    )
    decoded_layer = strict_json_loads(layer.canonical_bytes)
    if type(decoded_layer) is not dict:
        raise _integrity("SCIENCE.SAMPLING_LAYER_SHAPE")
    _validate_sampling_semantics(cast(dict[str, object], decoded_layer))
    return _CanonicalSamplingEvidenceBundle(
        attempts=attempts,
        numeric_records=numeric_envelopes,
        aggregates=aggregates,
        layer=layer,
    )


_SAMPLING_DERIVATION = build_frozen_derivation_graph(
    globals(),
    module_name=__name__,
    root_names=(
        "_derive_sampling_evidence",
        "_validate_sampling_semantics",
    ),
    record_type_names=(
        "_CanonicalSamplingNumericComparison",
        "_CanonicalSamplingOriginAttempt",
        "_CanonicalSamplingFamilyAggregate",
        "_CanonicalSamplingLayerEvidence",
        "_CanonicalSamplingEvidenceBundle",
        "_SamplingOriginInput",
        "_SamplingCandidateInput",
    ),
)
for _function_name, _frozen_function in _SAMPLING_DERIVATION.functions.items():
    globals()[_function_name] = _frozen_function
for _record_type_name, _frozen_record_type in _SAMPLING_DERIVATION.record_types.items():
    globals()[_record_type_name] = _frozen_record_type
del _function_name
del _frozen_function
del _record_type_name
del _frozen_record_type
del build_frozen_derivation_graph


__all__: list[str] = []
