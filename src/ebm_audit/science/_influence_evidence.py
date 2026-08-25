"""Sealed participant-influence evidence for exact removal refits.

Every declared influence origin becomes one attempt. Exact leave-one-participant
out refits are compared with their ordinary source fit; unavailable and
unsupported removals remain visible as typed non-contributing attempts. The
stage component is never approximated: without authenticated fixed-cohort
posterior output it is explicitly not applicable by capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite as _math_isfinite
from typing import Final, Literal, cast

from numpy import asarray as _np_asarray
from numpy import float64 as _np_float64

from ebm_audit.metrics import (
    pairwise_matrix_distance,
    per_event_rank_shifts,
    position_matrix_distance,
    strict_order_comparison,
    strict_pairwise_majority_flips,
)
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256

from ._evidence_records import _integrity, _ScientificRecordIntegrityError
from ._frozen_derivation import build_frozen_derivation_graph

INFLUENCE_EVIDENCE_RULE_ID: Final = "influence-source-fit-comparison/1"
INFLUENCE_ATTEMPT_SCHEMA_VERSION: Final = "ebm-audit-influence-attempt/2.0"
INFLUENCE_LAYER_SCHEMA_VERSION: Final = "ebm-audit-influence-layer-evidence/2.0"
INFLUENCE_RECORD_SCHEMA_VERSION: Final = "ebm-audit-influence/2.0"
INFLUENCE_RULE_VERSION: Final = "metrics/influence/v0.1.0"

_ATTEMPT_DOMAIN: Final = "ebm-audit/scientific-influence-attempt/1"
_LAYER_DOMAIN: Final = "ebm-audit/scientific-influence-layer-evidence/1"
_PREPARATION_BINDING_DOMAIN: Final = "ebm-audit/influence-preparation-evidence-input/1"
_PREPARATION_BINDING_SCHEMA_VERSION: Final = "ebm-audit-influence-preparation-evidence-input/1.0"

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
_COMPLETED_TERMINALS: Final = ("SUCCESS", "CONVERGENCE_WARN")
_CONTRIBUTION_STATES: Final = (
    "INTERPRETIVE",
    "DESCRIPTIVE_ONLY",
    "METRIC_NOT_ASSESSABLE",
    "FAILED",
)
_COMPONENT_IDS: Final = (
    "central_order_kendall_distance",
    "maximum_normalized_event_rank_displacement",
    "strict_pairwise_majority_flip_fraction",
    "position_matrix_distance",
    "pairwise_matrix_distance",
    "fixed_cohort_stage_movement",
    "convergence_degradation",
)
_KENDALL_THRESHOLD: Final = 0.25
_RANK_DISPLACEMENT_THRESHOLD: Final = 0.30
_FLIP_FRACTION_THRESHOLD: Final = 0.15
_POSITION_MATRIX_THRESHOLD: Final = 0.20
_PAIRWISE_MATRIX_THRESHOLD: Final = 0.15
_REFERENCE_SNAPSHOT_UNAVAILABLE: Final = "INFLUENCE.REFERENCE_SNAPSHOT_UNAVAILABLE"

type _ContributionState = Literal[
    "INTERPRETIVE",
    "DESCRIPTIVE_ONLY",
    "METRIC_NOT_ASSESSABLE",
    "FAILED",
]


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalInfluenceAttempt:
    preimage_bytes: bytes
    canonical_bytes: bytes
    attempt_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalInfluenceLayerEvidence:
    preimage_bytes: bytes
    canonical_bytes: bytes
    layer_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalInfluenceEvidenceBundle:
    attempts: tuple[_CanonicalInfluenceAttempt, ...]
    layer: _CanonicalInfluenceLayerEvidence


@dataclass(frozen=True, repr=False, slots=True)
class _InfluenceOriginInput:
    origin_bytes: bytes
    comparison_edge_bytes: bytes


@dataclass(frozen=True, repr=False, slots=True)
class _InfluenceCandidateInput:
    candidate_record_bytes: bytes
    universe_id: str | None
    operation_bytes: bytes
    origins: tuple[_InfluenceOriginInput, ...]
    preparation_binding_bytes: bytes | None


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _closed_record(value: bytes, *, code: str) -> dict[str, object]:
    if type(value) is not bytes:
        raise _integrity(code)
    decoded = strict_json_loads(value)
    if type(decoded) is not dict or canonical_json_bytes(decoded) != value:
        raise _integrity(code)
    return cast(dict[str, object], decoded)


def _candidate_identity(
    record: dict[str, object],
) -> tuple[int, str, str, str, str, str]:
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
        raise _integrity("SCIENCE.INFLUENCE_CANDIDATE_IDENTITY")
    preimage = dict(record)
    supplied = preimage.pop("record_digest", None)
    if supplied != structured_sha256(
        "ebm-audit/scientific-candidate-evidence/1",
        preimage,
    ):
        raise _integrity("SCIENCE.INFLUENCE_CANDIDATE_IDENTITY")
    return ordinal, candidate_id, analysis_spec_id, result_id, final_status, record_digest


def _event_semantics(
    record: dict[str, object],
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    semantics = record.get("event_semantics")
    if type(semantics) is not dict:
        raise _integrity("SCIENCE.INFLUENCE_EVENT_SEMANTICS")
    event_ids = semantics.get("ordered_event_ids")
    directions = semantics.get("ordered_event_directions")
    stage_digest = semantics.get("stage_semantics_digest")
    if (
        type(event_ids) is not list
        or len(event_ids) < 2
        or any(type(value) is not str for value in event_ids)
        or len(set(event_ids)) != len(event_ids)
        or type(directions) is not list
        or len(directions) != len(event_ids)
        or any(value not in {"higher", "lower"} for value in directions)
        or type(stage_digest) is not str
    ):
        raise _integrity("SCIENCE.INFLUENCE_EVENT_SEMANTICS")
    return (
        tuple(cast(list[str], event_ids)),
        tuple(cast(list[str], directions)),
        stage_digest,
    )


def _finite_square_matrix(value: object, *, size: int, code: str) -> object:
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


def _snapshot(
    record: dict[str, object],
    *,
    event_ids: tuple[str, ...],
) -> dict[str, object]:
    within = record.get("within_fit")
    if type(within) is not dict or within.get("status") != "ASSESSABLE":
        raise _integrity("SCIENCE.INFLUENCE_REFERENCE_SNAPSHOT")
    modal = within.get("retained_state_modal_order_event_ids")
    position = within.get("position_probabilities")
    pairwise = within.get("pairwise_precedence")
    retained_state_count = within.get("retained_state_count")
    source = within.get("source")
    if (
        type(modal) is not list
        or len(modal) != len(event_ids)
        or any(type(value) is not str for value in modal)
        or set(modal) != set(event_ids)
        or type(retained_state_count) is not int
        or retained_state_count < 1
        or type(source) is not dict
    ):
        raise _integrity("SCIENCE.INFLUENCE_REFERENCE_SNAPSHOT")
    _finite_square_matrix(
        position,
        size=len(event_ids),
        code="SCIENCE.INFLUENCE_POSITION_MATRIX",
    )
    _finite_square_matrix(
        pairwise,
        size=len(event_ids),
        code="SCIENCE.INFLUENCE_PAIRWISE_MATRIX",
    )
    return {
        "modal_order_event_ids": list(cast(list[str], modal)),
        "position_probabilities": position,
        "pairwise_precedence": pairwise,
    }


def _metric_unavailability_reason(
    record: dict[str, object],
    *,
    owner: str,
) -> dict[str, str] | None:
    within = record.get("within_fit")
    if type(within) is not dict:
        raise _integrity("SCIENCE.INFLUENCE_REFERENCE_SNAPSHOT")
    status = within.get("status")
    reason_code = within.get("reason_code")
    if status == "ASSESSABLE":
        if reason_code is not None:
            raise _integrity("SCIENCE.INFLUENCE_REFERENCE_SNAPSHOT")
        return None
    if status in {"NOT_ASSESSABLE", "NOT_APPLICABLE_BY_CAPABILITY"} and type(reason_code) is str:
        return {
            "owner": owner,
            "reason_code": reason_code,
        }
    raise _integrity("SCIENCE.INFLUENCE_REFERENCE_SNAPSHOT")


def _metric_result(metric_id: str, result: object) -> dict[str, object]:
    status = getattr(result, "status", None)
    value = getattr(result, "value", None)
    reason_code = getattr(result, "reason_code", None)
    if status == "ASSESSABLE":
        if (
            type(value) not in {int, float}
            or not _math_isfinite(float(cast(int | float, value)))
            or reason_code is not None
        ):
            raise _integrity("SCIENCE.INFLUENCE_METRIC")
        return {
            "metric_id": metric_id,
            "status": "ASSESSABLE",
            "value": float(cast(int | float, value)),
            "reason_code": None,
        }
    if status == "NOT_ASSESSABLE" and type(reason_code) is str and value is None:
        return {
            "metric_id": metric_id,
            "status": "NOT_ASSESSABLE",
            "value": None,
            "reason_code": reason_code,
        }
    raise _integrity("SCIENCE.INFLUENCE_METRIC")


def _count_metric(result: object) -> dict[str, object]:
    status = getattr(result, "status", None)
    value = getattr(result, "value", None)
    reason_code = getattr(result, "reason_code", None)
    if status == "ASSESSABLE":
        if type(value) is not int or value < 0 or reason_code is not None:
            raise _integrity("SCIENCE.INFLUENCE_PAIRWISE_METRIC")
        return {
            "metric_id": "strict-pairwise-majority-flip-count/1",
            "status": "ASSESSABLE",
            "value": value,
            "reason_code": None,
        }
    if status == "NOT_ASSESSABLE" and type(reason_code) is str and value is None:
        return {
            "metric_id": "strict-pairwise-majority-flip-count/1",
            "status": "NOT_ASSESSABLE",
            "value": None,
            "reason_code": "INFLUENCE.INSUFFICIENT_COMMON_EVENTS",
        }
    raise _integrity("SCIENCE.INFLUENCE_PAIRWISE_METRIC")


def _unavailable_metric(metric_id: str) -> dict[str, object]:
    return {
        "metric_id": metric_id,
        "status": "NOT_ASSESSABLE",
        "value": None,
        "reason_code": _REFERENCE_SNAPSHOT_UNAVAILABLE,
    }


def _unavailable_count_metric() -> dict[str, object]:
    return {
        "metric_id": "strict-pairwise-majority-flip-count/1",
        "status": "NOT_ASSESSABLE",
        "value": None,
        "reason_code": _REFERENCE_SNAPSHOT_UNAVAILABLE,
    }


def _stage_metric(metric_id: str) -> dict[str, object]:
    return {
        "metric_id": metric_id,
        "status": "NOT_APPLICABLE_BY_CAPABILITY",
        "value": None,
        "reason_code": "STAGING.FIXED_COHORT_UNAVAILABLE",
    }


def _convergence_state(status: str) -> str:
    return {
        "SUCCESS": "CONVERGENCE_PASS",
        "CONVERGENCE_WARN": "CONVERGENCE_WARN",
        "CONVERGENCE_FAILED": "CONVERGENCE_FAIL",
    }.get(status, "CONVERGENCE_NOT_ASSESSABLE")


def _component_state(
    metric: dict[str, object],
    *,
    threshold: float,
) -> str:
    if metric.get("status") != "ASSESSABLE":
        return "INFLUENCE_COMPONENT_NOT_ASSESSABLE"
    value = metric.get("value")
    if type(value) not in {int, float}:
        raise _integrity("SCIENCE.INFLUENCE_COMPONENT")
    return (
        "INFLUENCE_COMPONENT_HIGH"
        if float(cast(int | float, value)) >= threshold
        else "INFLUENCE_COMPONENT_NOT_HIGH"
    )


def _participant_state(component_states: dict[str, str]) -> str:
    assessable = [
        component_id
        for component_id in _COMPONENT_IDS
        if component_states[component_id] != "INFLUENCE_COMPONENT_NOT_ASSESSABLE"
    ]
    if len(assessable) < 3:
        return "PARTICIPANT_INFLUENCE_NOT_ASSESSABLE"
    high_count = sum(
        component_states[component_id] == "INFLUENCE_COMPONENT_HIGH" for component_id in assessable
    )
    if high_count >= 2:
        return "PARTICIPANT_INFLUENCE_MULTICOMPONENT"
    if high_count == 1:
        return "PARTICIPANT_INFLUENCE_SINGLE_COMPONENT"
    return "PARTICIPANT_INFLUENCE_NO_HIGH_COMPONENT"


def _validate_preparation_binding(
    binding: dict[str, object],
    *,
    candidate_ordinal: int,
    analysis_spec_id: str,
    operation: dict[str, object],
) -> None:
    preimage = dict(binding)
    supplied_digest = preimage.pop("binding_digest", None)
    aliases = binding.get("removed_aliases")
    reasons = binding.get("preparation_reason_rows")
    if (
        binding.get("binding_schema_version") != _PREPARATION_BINDING_SCHEMA_VERSION
        or binding.get("candidate_ordinal") != candidate_ordinal
        or binding.get("analysis_spec_id") != analysis_spec_id
        or binding.get("source_analysis_spec_id") != operation.get("source_analysis_spec_id")
        or binding.get("removal_method_id") != operation.get("removal_method_id")
        or binding.get("removal_kind") != operation.get("removal_kind")
        or binding.get("removal_slot_ordinal") != operation.get("removal_slot_ordinal")
        or binding.get("named_group_spec_id") != operation.get("named_group_spec_id")
        or type(aliases) is not list
        or any(type(alias) is not str for alias in aliases)
        or len(set(cast(list[str], aliases))) != len(aliases)
        or type(reasons) is not list
        or any(type(row) is not dict for row in reasons)
        or type(supplied_digest) is not str
        or supplied_digest != structured_sha256(_PREPARATION_BINDING_DOMAIN, preimage)
    ):
        raise _integrity("SCIENCE.INFLUENCE_PREPARATION_BINDING")
    removal_kind = operation.get("removal_kind")
    if removal_kind == "leave-one-participant-out":
        if len(aliases) != 1:
            raise _integrity("SCIENCE.INFLUENCE_PREPARATION_BINDING")
    elif removal_kind == "named-group-removal":
        if aliases:
            raise _integrity("SCIENCE.INFLUENCE_PREPARATION_BINDING")
    else:
        raise _integrity("SCIENCE.INFLUENCE_PREPARATION_BINDING")


def _derive_influence_record(
    *,
    removal: dict[str, object],
    source: dict[str, object],
    removal_universe_id: str,
    source_universe_id: str,
    operation: dict[str, object],
    preparation: dict[str, object],
) -> dict[str, object]:
    removal_event_ids, removal_directions, removal_stage = _event_semantics(removal)
    source_event_ids, source_directions, source_stage = _event_semantics(source)
    if (
        removal_event_ids != source_event_ids
        or removal_directions != source_directions
        or removal_stage != source_stage
    ):
        raise _integrity("SCIENCE.INFLUENCE_SOURCE_SEMANTICS_CHANGED")
    removal_snapshot = _snapshot(removal, event_ids=removal_event_ids)
    source_snapshot = _snapshot(source, event_ids=source_event_ids)
    source_order = cast(list[str], source_snapshot["modal_order_event_ids"])
    removal_order = cast(list[str], removal_snapshot["modal_order_event_ids"])
    order = strict_order_comparison(source_order, removal_order)
    shifts = per_event_rank_shifts(source_order, removal_order)
    source_position = _finite_square_matrix(
        source_snapshot["position_probabilities"],
        size=len(source_event_ids),
        code="SCIENCE.INFLUENCE_POSITION_MATRIX",
    )
    removal_position = _finite_square_matrix(
        removal_snapshot["position_probabilities"],
        size=len(removal_event_ids),
        code="SCIENCE.INFLUENCE_POSITION_MATRIX",
    )
    source_pairwise = _finite_square_matrix(
        source_snapshot["pairwise_precedence"],
        size=len(source_event_ids),
        code="SCIENCE.INFLUENCE_PAIRWISE_MATRIX",
    )
    removal_pairwise = _finite_square_matrix(
        removal_snapshot["pairwise_precedence"],
        size=len(removal_event_ids),
        code="SCIENCE.INFLUENCE_PAIRWISE_MATRIX",
    )
    position = position_matrix_distance(
        source_position,
        removal_position,
        left_event_ids=source_event_ids,
        right_event_ids=removal_event_ids,
    )
    pairwise = pairwise_matrix_distance(
        source_pairwise,
        removal_pairwise,
        left_event_ids=source_event_ids,
        right_event_ids=removal_event_ids,
    )
    flips = strict_pairwise_majority_flips(
        source_pairwise,
        removal_pairwise,
        left_event_ids=source_event_ids,
        right_event_ids=removal_event_ids,
    )
    kendall_metric = _metric_result(
        "central-order-kendall-distance/1",
        order.kendall_distance,
    )
    displacement_metric = _metric_result(
        "maximum-normalized-event-rank-displacement/1",
        shifts.maximum_normalized_rank_shift,
    )
    flip_count_metric = _count_metric(flips.flip_count)
    flip_fraction_metric = _metric_result(
        "strict-pairwise-majority-flip-fraction/1",
        flips.flip_fraction,
    )
    position_metric = _metric_result("position-matrix-distance/1", position)
    pairwise_metric = _metric_result("pairwise-matrix-distance/1", pairwise)
    baseline_convergence = _convergence_state(cast(str, source["final_status"]))
    removal_convergence = _convergence_state(cast(str, removal["final_status"]))
    convergence_degraded = baseline_convergence == "CONVERGENCE_PASS" and (
        removal_convergence != "CONVERGENCE_PASS"
    )
    convergence_metric: dict[str, object] = {
        "metric_id": "convergence-degradation/1",
        "status": "ASSESSABLE",
        "value": convergence_degraded,
        "reason_code": None,
    }
    stage_median = _stage_metric("fixed-cohort-stage-wasserstein-median/1")
    stage_maximum = _stage_metric("fixed-cohort-stage-wasserstein-maximum/1")
    component_states = {
        "central_order_kendall_distance": _component_state(
            kendall_metric,
            threshold=_KENDALL_THRESHOLD,
        ),
        "maximum_normalized_event_rank_displacement": _component_state(
            displacement_metric,
            threshold=_RANK_DISPLACEMENT_THRESHOLD,
        ),
        "strict_pairwise_majority_flip_fraction": _component_state(
            flip_fraction_metric,
            threshold=_FLIP_FRACTION_THRESHOLD,
        ),
        "position_matrix_distance": _component_state(
            position_metric,
            threshold=_POSITION_MATRIX_THRESHOLD,
        ),
        "pairwise_matrix_distance": _component_state(
            pairwise_metric,
            threshold=_PAIRWISE_MATRIX_THRESHOLD,
        ),
        "fixed_cohort_stage_movement": ("INFLUENCE_COMPONENT_NOT_ASSESSABLE"),
        "convergence_degradation": (
            "INFLUENCE_COMPONENT_HIGH" if convergence_degraded else "INFLUENCE_COMPONENT_NOT_HIGH"
        ),
    }
    fixed_digest = preparation.get("fixed_evaluation_cohort_digest")
    fixed_count = preparation.get("fixed_evaluation_cohort_count")
    aliases = preparation.get("removed_aliases")
    if (
        type(fixed_digest) is not str
        or type(fixed_count) is not int
        or fixed_count < 0
        or type(aliases) is not list
        or len(aliases) != 1
    ):
        raise _integrity("SCIENCE.INFLUENCE_FIXED_COHORT")
    pairwise_assessable = flips.common_event_count >= 2
    if pairwise_assessable:
        if (
            flips.strict_pairwise_majority_flip_denominator is None
            or flip_count_metric["status"] != "ASSESSABLE"
            or flip_fraction_metric["status"] != "ASSESSABLE"
        ):
            raise _integrity("SCIENCE.INFLUENCE_PAIRWISE_METRIC")
    else:
        if (
            flips.strict_pairwise_majority_flip_denominator is not None
            or flips.flips
            or flip_count_metric["status"] != "NOT_ASSESSABLE"
            or flip_fraction_metric["status"] != "NOT_ASSESSABLE"
        ):
            raise _integrity("SCIENCE.INFLUENCE_PAIRWISE_METRIC")
    assessable_components = [
        component_id
        for component_id in _COMPONENT_IDS
        if component_states[component_id] != "INFLUENCE_COMPONENT_NOT_ASSESSABLE"
    ]
    return {
        "influence_schema_version": INFLUENCE_RECORD_SCHEMA_VERSION,
        "influence_rule_version": INFLUENCE_RULE_VERSION,
        "uncertainty_layer": "participant_influence",
        "removal_spec_id": operation["removal_analysis_spec_id"],
        "removed_aliases": list(cast(list[str], aliases)),
        "baseline_universe_id": source_universe_id,
        "removal_universe_id": removal_universe_id,
        "baseline_event_ids": list(source_event_ids),
        "removal_event_ids": list(removal_event_ids),
        "pairwise_assessment": (
            "ASSESSABLE" if pairwise_assessable else "NOT_ASSESSABLE_FEWER_THAN_TWO_COMMON_EVENTS"
        ),
        "pairwise_assessment_reason_code": (
            None if pairwise_assessable else "INFLUENCE.INSUFFICIENT_COMMON_EVENTS"
        ),
        "common_event_count": flips.common_event_count,
        "strict_pairwise_majority_flip_denominator": (
            flips.strict_pairwise_majority_flip_denominator
        ),
        "fixed_evaluation_cohort_digest": fixed_digest,
        "fixed_evaluation_cohort_count": fixed_count,
        "central_order_kendall_distance": kendall_metric,
        "maximum_normalized_event_rank_displacement": displacement_metric,
        "strict_pairwise_majority_flip_count": flip_count_metric,
        "strict_pairwise_majority_flip_fraction": flip_fraction_metric,
        "strict_pairwise_majority_flips": [
            {
                "event_a_id": flip.event_a_id,
                "event_b_id": flip.event_b_id,
                "baseline_probability_a_before_b": (flip.left_probability_a_before_b),
                "removal_probability_a_before_b": (flip.right_probability_a_before_b),
                "baseline_relation": flip.left_relation,
                "removal_relation": flip.right_relation,
            }
            for flip in flips.flips
        ],
        "position_matrix_distance": position_metric,
        "pairwise_matrix_distance": pairwise_metric,
        "baseline_convergence_state": baseline_convergence,
        "removal_convergence_state": removal_convergence,
        "convergence_degradation": convergence_metric,
        "fixed_cohort_stage_wasserstein_median": stage_median,
        "fixed_cohort_stage_wasserstein_maximum": stage_maximum,
        "component_states": component_states,
        "assessable_component_ids": assessable_components,
        "participant_state": _participant_state(component_states),
        "display_component_percentiles": None,
        "influence_display_score": None,
    }


def _derive_convergence_degradation_record(
    *,
    removal: dict[str, object],
    source: dict[str, object],
    removal_universe_id: str,
    source_universe_id: str,
    operation: dict[str, object],
    preparation: dict[str, object],
) -> dict[str, object]:
    """Retain typed convergence degradation without unavailable order evidence."""

    removal_event_ids, removal_directions, removal_stage = _event_semantics(removal)
    source_event_ids, source_directions, source_stage = _event_semantics(source)
    removal_status = cast(str, removal["final_status"])
    source_status = cast(str, source["final_status"])
    if (
        source_status != "SUCCESS"
        or removal_status
        not in {
            "CONVERGENCE_FAILED",
            "CONVERGENCE_NOT_ASSESSABLE",
        }
        or removal_event_ids != source_event_ids
        or removal_directions != source_directions
        or removal_stage != source_stage
    ):
        raise _integrity("SCIENCE.INFLUENCE_CONVERGENCE_DEGRADATION")
    fixed_digest = preparation.get("fixed_evaluation_cohort_digest")
    fixed_count = preparation.get("fixed_evaluation_cohort_count")
    aliases = preparation.get("removed_aliases")
    if (
        type(fixed_digest) is not str
        or type(fixed_count) is not int
        or fixed_count < 0
        or type(aliases) is not list
        or len(aliases) != 1
    ):
        raise _integrity("SCIENCE.INFLUENCE_FIXED_COHORT")
    unavailable_metrics = {
        "central_order_kendall_distance": _unavailable_metric("central-order-kendall-distance/1"),
        "maximum_normalized_event_rank_displacement": _unavailable_metric(
            "maximum-normalized-event-rank-displacement/1"
        ),
        "strict_pairwise_majority_flip_fraction": _unavailable_metric(
            "strict-pairwise-majority-flip-fraction/1"
        ),
        "position_matrix_distance": _unavailable_metric("position-matrix-distance/1"),
        "pairwise_matrix_distance": _unavailable_metric("pairwise-matrix-distance/1"),
    }
    component_states = {
        component_id: (
            "INFLUENCE_COMPONENT_HIGH"
            if component_id == "convergence_degradation"
            else "INFLUENCE_COMPONENT_NOT_ASSESSABLE"
        )
        for component_id in _COMPONENT_IDS
    }
    stage_median = _stage_metric("fixed-cohort-stage-wasserstein-median/1")
    stage_maximum = _stage_metric("fixed-cohort-stage-wasserstein-maximum/1")
    record: dict[str, object] = {
        "influence_schema_version": INFLUENCE_RECORD_SCHEMA_VERSION,
        "influence_rule_version": INFLUENCE_RULE_VERSION,
        "uncertainty_layer": "participant_influence",
        "removal_spec_id": operation["removal_analysis_spec_id"],
        "removed_aliases": list(cast(list[str], aliases)),
        "baseline_universe_id": source_universe_id,
        "removal_universe_id": removal_universe_id,
        "baseline_event_ids": list(source_event_ids),
        "removal_event_ids": list(removal_event_ids),
        "pairwise_assessment": "NOT_ASSESSABLE_REFERENCE_SNAPSHOT_UNAVAILABLE",
        "pairwise_assessment_reason_code": _REFERENCE_SNAPSHOT_UNAVAILABLE,
        "common_event_count": len(source_event_ids),
        "strict_pairwise_majority_flip_denominator": None,
        "fixed_evaluation_cohort_digest": fixed_digest,
        "fixed_evaluation_cohort_count": fixed_count,
        **unavailable_metrics,
        "strict_pairwise_majority_flip_count": _unavailable_count_metric(),
        "strict_pairwise_majority_flips": [],
        "baseline_convergence_state": "CONVERGENCE_PASS",
        "removal_convergence_state": _convergence_state(removal_status),
        "convergence_degradation": {
            "metric_id": "convergence-degradation/1",
            "status": "ASSESSABLE",
            "value": True,
            "reason_code": None,
        },
        "fixed_cohort_stage_wasserstein_median": stage_median,
        "fixed_cohort_stage_wasserstein_maximum": stage_maximum,
        "component_states": component_states,
        "assessable_component_ids": ["convergence_degradation"],
        "participant_state": "PARTICIPANT_INFLUENCE_NOT_ASSESSABLE",
        "display_component_percentiles": None,
        "influence_display_score": None,
    }
    _validate_influence_record(record)
    return record


def _reason_rows(
    *,
    removal: dict[str, object],
    source: dict[str, object],
    preparation: dict[str, object],
    contribution_state: _ContributionState,
    metric_reason_rows: tuple[dict[str, str], ...],
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    preparation_reasons = preparation.get("preparation_reason_rows")
    if type(preparation_reasons) is not list:
        raise _integrity("SCIENCE.INFLUENCE_REASON_ROWS")
    for row in preparation_reasons:
        if (
            type(row) is not dict
            or type(row.get("reason_code")) is not str
            or type(row.get("rule_id")) is not str
        ):
            raise _integrity("SCIENCE.INFLUENCE_REASON_ROWS")
        result.append(
            {
                "owner": "REMOVAL",
                "reason_code": cast(str, row["reason_code"]),
            }
        )
    result.extend(metric_reason_rows)
    removal_status = cast(str, removal["final_status"])
    source_status = cast(str, source["final_status"])
    if (
        removal_status not in _COMPLETED_TERMINALS
        and removal_status
        not in {
            "CONVERGENCE_FAILED",
            "CONVERGENCE_NOT_ASSESSABLE",
        }
        and not result
    ):
        result.append(
            {
                "owner": "REMOVAL",
                "reason_code": f"CANDIDATE.{removal_status}",
            }
        )
    if source_status not in _COMPLETED_TERMINALS:
        result.append(
            {
                "owner": "SOURCE",
                "reason_code": f"CANDIDATE.{source_status}",
            }
        )
    if contribution_state == "DESCRIPTIVE_ONLY":
        influence_reason = {
            "CONVERGENCE_FAILED": "INFLUENCE.CONVERGENCE_FAILED",
            "CONVERGENCE_NOT_ASSESSABLE": ("INFLUENCE.CONVERGENCE_NOT_ASSESSABLE"),
        }.get(removal_status, "INFLUENCE.CONVERGENCE_WARNING")
        result.append(
            {
                "owner": "INFLUENCE_DERIVATION",
                "reason_code": influence_reason,
            }
        )
    unique = {(row["owner"], row["reason_code"]): row for row in result}
    return [
        unique[key]
        for key in sorted(
            unique,
            key=lambda key: (_utf8(key[0]), _utf8(key[1])),
        )
    ]


def _derive_attempt(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    origin: dict[str, object],
    edge: dict[str, object],
    operation: dict[str, object],
    removal: dict[str, object],
    source: dict[str, object],
    removal_universe_id: str | None,
    source_universe_id: str | None,
    preparation: dict[str, object],
) -> _CanonicalInfluenceAttempt:
    removal_status = cast(str, removal["final_status"])
    source_status = cast(str, source["final_status"])
    both_completed = (
        removal_status in _COMPLETED_TERMINALS and source_status in _COMPLETED_TERMINALS
    )
    convergence_degradation_only = source_status == "SUCCESS" and removal_status in {
        "CONVERGENCE_FAILED",
        "CONVERGENCE_NOT_ASSESSABLE",
    }
    metric_reason_rows = (
        tuple(
            row
            for row in (
                _metric_unavailability_reason(removal, owner="REMOVAL"),
                _metric_unavailability_reason(source, owner="SOURCE"),
            )
            if row is not None
        )
        if both_completed
        else ()
    )
    contribution_state: _ContributionState
    if both_completed or convergence_degradation_only:
        if removal_universe_id is None or source_universe_id is None:
            raise _integrity("SCIENCE.INFLUENCE_COMPLETED_UNIVERSE")
        if convergence_degradation_only:
            contribution_state = "DESCRIPTIVE_ONLY"
            influence_record = _derive_convergence_degradation_record(
                removal=removal,
                source=source,
                removal_universe_id=removal_universe_id,
                source_universe_id=source_universe_id,
                operation=operation,
                preparation=preparation,
            )
        elif metric_reason_rows:
            contribution_state = "METRIC_NOT_ASSESSABLE"
            influence_record = None
        else:
            contribution_state = (
                "INTERPRETIVE"
                if removal_status == source_status == "SUCCESS"
                else "DESCRIPTIVE_ONLY"
            )
            influence_record = _derive_influence_record(
                removal=removal,
                source=source,
                removal_universe_id=removal_universe_id,
                source_universe_id=source_universe_id,
                operation=operation,
                preparation=preparation,
            )
    else:
        contribution_state = "FAILED"
        influence_record = None
    reasons = _reason_rows(
        removal=removal,
        source=source,
        preparation=preparation,
        contribution_state=contribution_state,
        metric_reason_rows=metric_reason_rows,
    )
    if contribution_state in {"FAILED", "METRIC_NOT_ASSESSABLE"} and not reasons:
        raise _integrity("SCIENCE.INFLUENCE_REASON_ROWS")
    preimage: dict[str, object] = {
        "record_schema_version": INFLUENCE_ATTEMPT_SCHEMA_VERSION,
        "evidence_rule_id": INFLUENCE_EVIDENCE_RULE_ID,
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "origin_id": origin["origin_id"],
        "analysis_declaration_id": origin["analysis_declaration_id"],
        "source_declaration_digest": origin["source_declaration_digest"],
        "experiment_set_id": origin["experiment_set_id"],
        "experiment_mode": "influence",
        "comparison_edge": edge,
        "candidate_ordinal": removal["candidate_ordinal"],
        "removal_analysis_spec_id": removal["analysis_spec_id"],
        "source_analysis_spec_id": source["analysis_spec_id"],
        "removal_spec_id": removal["analysis_spec_id"],
        "removal_method_id": operation["removal_method_id"],
        "removal_kind": operation["removal_kind"],
        "removal_slot_ordinal": operation["removal_slot_ordinal"],
        "named_group_spec_id": operation.get("named_group_spec_id"),
        "refit_preprocessing": operation["refit_preprocessing"],
        "fixed_non_removed_cohort_policy": operation["fixed_non_removed_cohort_policy"],
        "removed_aliases": preparation["removed_aliases"],
        "preparation_binding_digest": preparation["binding_digest"],
        "removal_result_id": removal["result_id"],
        "source_result_id": source["result_id"],
        "removal_universe_id": removal_universe_id,
        "source_universe_id": source_universe_id,
        "removal_terminal_status": removal_status,
        "source_terminal_status": source_status,
        "removal_candidate_record_digest": removal["record_digest"],
        "source_candidate_record_digest": source["record_digest"],
        "contribution_state": contribution_state,
        "reason_rows": reasons,
        "influence_record": influence_record,
    }
    digest = structured_sha256(_ATTEMPT_DOMAIN, preimage)
    return _CanonicalInfluenceAttempt(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes(
            {
                **preimage,
                "attempt_digest": digest,
            }
        ),
        attempt_digest=digest,
    )


def _validate_influence_record(record: dict[str, object]) -> None:
    baseline_ids = record.get("baseline_event_ids")
    removal_ids = record.get("removal_event_ids")
    flips = record.get("strict_pairwise_majority_flips")
    states = record.get("component_states")
    assessable = record.get("assessable_component_ids")
    if (
        record.get("influence_schema_version") != INFLUENCE_RECORD_SCHEMA_VERSION
        or record.get("influence_rule_version") != INFLUENCE_RULE_VERSION
        or record.get("uncertainty_layer") != "participant_influence"
        or type(baseline_ids) is not list
        or type(removal_ids) is not list
        or type(flips) is not list
        or type(states) is not dict
        or type(assessable) is not list
        or set(states) != set(_COMPONENT_IDS)
    ):
        raise _integrity("SCIENCE.INFLUENCE_RECORD")
    common = sorted(
        set(cast(list[str], baseline_ids)) & set(cast(list[str], removal_ids)),
        key=_utf8,
    )
    common_count = len(common)
    pairwise_assessment = record.get("pairwise_assessment")
    expected_denominator = (
        None
        if common_count < 2
        or pairwise_assessment == "NOT_ASSESSABLE_REFERENCE_SNAPSHOT_UNAVAILABLE"
        else common_count * (common_count - 1) // 2
    )
    flip_count = record.get("strict_pairwise_majority_flip_count")
    flip_fraction = record.get("strict_pairwise_majority_flip_fraction")
    if (
        record.get("common_event_count") != common_count
        or record.get("strict_pairwise_majority_flip_denominator") != expected_denominator
        or type(flip_count) is not dict
        or type(flip_fraction) is not dict
    ):
        raise _integrity("SCIENCE.INFLUENCE_PAIRWISE_ACCOUNTING")
    if pairwise_assessment == "NOT_ASSESSABLE_REFERENCE_SNAPSHOT_UNAVAILABLE":
        if (
            record.get("pairwise_assessment_reason_code") != _REFERENCE_SNAPSHOT_UNAVAILABLE
            or record.get("strict_pairwise_majority_flip_denominator") is not None
            or flips
            or flip_count.get("status") != "NOT_ASSESSABLE"
            or flip_count.get("value") is not None
            or flip_count.get("reason_code") != _REFERENCE_SNAPSHOT_UNAVAILABLE
            or flip_fraction.get("status") != "NOT_ASSESSABLE"
            or flip_fraction.get("value") is not None
            or flip_fraction.get("reason_code") != _REFERENCE_SNAPSHOT_UNAVAILABLE
        ):
            raise _integrity("SCIENCE.INFLUENCE_PAIRWISE_ACCOUNTING")
    elif common_count < 2:
        if (
            pairwise_assessment != "NOT_ASSESSABLE_FEWER_THAN_TWO_COMMON_EVENTS"
            or record.get("pairwise_assessment_reason_code")
            != "INFLUENCE.INSUFFICIENT_COMMON_EVENTS"
            or flips
            or flip_count.get("status") != "NOT_ASSESSABLE"
            or flip_count.get("value") is not None
            or flip_fraction.get("status") != "NOT_ASSESSABLE"
            or flip_fraction.get("value") is not None
        ):
            raise _integrity("SCIENCE.INFLUENCE_PAIRWISE_ACCOUNTING")
    else:
        count = flip_count.get("value")
        fraction = flip_fraction.get("value")
        if (
            pairwise_assessment != "ASSESSABLE"
            or record.get("pairwise_assessment_reason_code") is not None
            or type(count) is not int
            or count != len(flips)
            or type(fraction) not in {int, float}
            or abs(float(cast(int | float, fraction)) - count / cast(int, expected_denominator))
            > 1e-12
        ):
            raise _integrity("SCIENCE.INFLUENCE_PAIRWISE_ACCOUNTING")
    metric_fields = {
        "central_order_kendall_distance": (
            "central_order_kendall_distance",
            _KENDALL_THRESHOLD,
        ),
        "maximum_normalized_event_rank_displacement": (
            "maximum_normalized_event_rank_displacement",
            _RANK_DISPLACEMENT_THRESHOLD,
        ),
        "strict_pairwise_majority_flip_fraction": (
            "strict_pairwise_majority_flip_fraction",
            _FLIP_FRACTION_THRESHOLD,
        ),
        "position_matrix_distance": (
            "position_matrix_distance",
            _POSITION_MATRIX_THRESHOLD,
        ),
        "pairwise_matrix_distance": (
            "pairwise_matrix_distance",
            _PAIRWISE_MATRIX_THRESHOLD,
        ),
    }
    expected_states: dict[str, str] = {}
    for component_id, (field, threshold) in metric_fields.items():
        metric = record.get(field)
        if type(metric) is not dict:
            raise _integrity("SCIENCE.INFLUENCE_COMPONENT_ACCOUNTING")
        expected_states[component_id] = _component_state(
            cast(dict[str, object], metric),
            threshold=threshold,
        )
    convergence = record.get("convergence_degradation")
    baseline_convergence = record.get("baseline_convergence_state")
    removal_convergence = record.get("removal_convergence_state")
    if (
        type(convergence) is not dict
        or convergence.get("status") != "ASSESSABLE"
        or type(convergence.get("value")) is not bool
        or convergence.get("value")
        != (
            baseline_convergence == "CONVERGENCE_PASS" and removal_convergence != "CONVERGENCE_PASS"
        )
    ):
        raise _integrity("SCIENCE.INFLUENCE_COMPONENT_ACCOUNTING")
    expected_states["fixed_cohort_stage_movement"] = "INFLUENCE_COMPONENT_NOT_ASSESSABLE"
    expected_states["convergence_degradation"] = (
        "INFLUENCE_COMPONENT_HIGH"
        if convergence["value"] is True
        else "INFLUENCE_COMPONENT_NOT_HIGH"
    )
    expected_assessable = [
        component_id
        for component_id in _COMPONENT_IDS
        if expected_states[component_id] != "INFLUENCE_COMPONENT_NOT_ASSESSABLE"
    ]
    if (
        states != expected_states
        or assessable != expected_assessable
        or record.get("participant_state") != _participant_state(cast(dict[str, str], states))
        or record.get("display_component_percentiles") is not None
        or record.get("influence_display_score") is not None
        or record.get("fixed_cohort_stage_wasserstein_median")
        != _stage_metric("fixed-cohort-stage-wasserstein-median/1")
        or record.get("fixed_cohort_stage_wasserstein_maximum")
        != _stage_metric("fixed-cohort-stage-wasserstein-maximum/1")
        or states.get("fixed_cohort_stage_movement") != "INFLUENCE_COMPONENT_NOT_ASSESSABLE"
    ):
        raise _integrity("SCIENCE.INFLUENCE_COMPONENT_ACCOUNTING")


def _validate_influence_semantics(layer: dict[str, object]) -> None:
    try:
        attempts = layer.get("attempts")
        planned_origin_ids = layer.get("planned_origin_ids")
        counts = layer.get("contribution_counts")
        if (
            type(layer) is not dict
            or layer.get("layer_schema_version") != INFLUENCE_LAYER_SCHEMA_VERSION
            or layer.get("evidence_rule_id") != INFLUENCE_EVIDENCE_RULE_ID
            or layer.get("uncertainty_layer") != "PARTICIPANT_INFLUENCE"
            or layer.get("pooling_policy") != "NON_POOLABLE"
            or type(layer.get("plan_digest")) is not str
            or type(layer.get("terminal_index_digest")) is not str
            or type(attempts) is not list
            or type(planned_origin_ids) is not list
            or type(counts) is not dict
            or layer.get("classification_status")
            != "FROZEN_REVIEWED_WITH_DEVELOPMENT_SENSITIVITY_UNVERIFIED"
        ):
            raise _integrity("SCIENCE.INFLUENCE_LAYER")
        exact_attempts = cast(list[dict[str, object]], attempts)
        origin_ids = [attempt.get("origin_id") for attempt in exact_attempts]
        if (
            any(type(attempt) is not dict for attempt in exact_attempts)
            or any(type(origin_id) is not str for origin_id in origin_ids)
            or origin_ids != sorted(cast(list[str], origin_ids), key=_utf8)
            or len(set(origin_ids)) != len(origin_ids)
            or planned_origin_ids != origin_ids
            or layer.get("planned_origin_count") != len(origin_ids)
            or layer.get("attempt_count") != len(exact_attempts)
        ):
            raise _integrity("SCIENCE.INFLUENCE_LAYER_ACCOUNTING")
        expected_counts = {
            state: sum(attempt.get("contribution_state") == state for attempt in exact_attempts)
            for state in _CONTRIBUTION_STATES
        }
        if counts != expected_counts or layer.get("influence_record_count") != sum(
            attempt.get("influence_record") is not None for attempt in exact_attempts
        ):
            raise _integrity("SCIENCE.INFLUENCE_LAYER_ACCOUNTING")
        for attempt in exact_attempts:
            preimage = dict(attempt)
            supplied = preimage.pop("attempt_digest", None)
            contribution = attempt.get("contribution_state")
            record = attempt.get("influence_record")
            reasons = attempt.get("reason_rows")
            removal_status = attempt.get("removal_terminal_status")
            source_status = attempt.get("source_terminal_status")
            if (
                type(supplied) is not str
                or supplied != structured_sha256(_ATTEMPT_DOMAIN, preimage)
                or attempt.get("record_schema_version") != INFLUENCE_ATTEMPT_SCHEMA_VERSION
                or attempt.get("evidence_rule_id") != INFLUENCE_EVIDENCE_RULE_ID
                or attempt.get("plan_digest") != layer.get("plan_digest")
                or attempt.get("terminal_index_digest") != layer.get("terminal_index_digest")
                or contribution not in _CONTRIBUTION_STATES
                or type(reasons) is not list
                or any(type(reason) is not dict for reason in cast(list[object], reasons))
            ):
                raise _integrity("SCIENCE.INFLUENCE_ATTEMPT")
            both_completed = (
                removal_status in _COMPLETED_TERMINALS and source_status in _COMPLETED_TERMINALS
            )
            convergence_degradation_only = source_status == "SUCCESS" and removal_status in {
                "CONVERGENCE_FAILED",
                "CONVERGENCE_NOT_ASSESSABLE",
            }
            expected_contribution = (
                (
                    "INTERPRETIVE"
                    if removal_status == source_status == "SUCCESS"
                    else "DESCRIPTIVE_ONLY"
                )
                if type(record) is dict and both_completed
                else (
                    "DESCRIPTIVE_ONLY"
                    if type(record) is dict and convergence_degradation_only
                    else ("METRIC_NOT_ASSESSABLE" if both_completed else "FAILED")
                )
            )
            exact_reasons = cast(list[dict[str, object]], reasons)
            if contribution != expected_contribution or (
                convergence_degradation_only
                and not any(
                    reason.get("owner") == "INFLUENCE_DERIVATION"
                    and reason.get("reason_code")
                    == {
                        "CONVERGENCE_FAILED": "INFLUENCE.CONVERGENCE_FAILED",
                        "CONVERGENCE_NOT_ASSESSABLE": ("INFLUENCE.CONVERGENCE_NOT_ASSESSABLE"),
                    }[cast(str, removal_status)]
                    for reason in exact_reasons
                )
            ):
                raise _integrity("SCIENCE.INFLUENCE_ATTEMPT")
            if contribution in {"INTERPRETIVE", "DESCRIPTIVE_ONLY"}:
                if type(record) is not dict:
                    raise _integrity("SCIENCE.INFLUENCE_ATTEMPT")
                _validate_influence_record(cast(dict[str, object], record))
                if (
                    record.get("removal_spec_id") != attempt.get("removal_spec_id")
                    or record.get("removed_aliases") != attempt.get("removed_aliases")
                    or record.get("baseline_universe_id") != attempt.get("source_universe_id")
                    or record.get("removal_universe_id") != attempt.get("removal_universe_id")
                ):
                    raise _integrity("SCIENCE.INFLUENCE_ATTEMPT")
            elif record is not None or not reasons:
                raise _integrity("SCIENCE.INFLUENCE_ATTEMPT")
        layer_preimage = dict(layer)
        supplied_layer_digest = layer_preimage.pop("layer_digest", None)
        if supplied_layer_digest != structured_sha256(
            _LAYER_DOMAIN,
            layer_preimage,
        ):
            raise _integrity("SCIENCE.INFLUENCE_LAYER_DIGEST")
    except _ScientificRecordIntegrityError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError):
        raise _integrity("SCIENCE.INFLUENCE_LAYER") from None


def _derive_influence_evidence(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    candidates: tuple[_InfluenceCandidateInput, ...],
) -> _CanonicalInfluenceEvidenceBundle:
    """Derive one exact attempt for every declared participant-removal origin."""

    if type(plan_digest) is not str or type(terminal_index_digest) is not str:
        raise _integrity("SCIENCE.INFLUENCE_RUN_IDENTITY")
    decoded: list[
        tuple[
            _InfluenceCandidateInput,
            dict[str, object],
            dict[str, object],
            dict[str, object] | None,
        ]
    ] = []
    observed_candidate_ids: set[str] = set()
    for expected_ordinal, candidate in enumerate(candidates):
        if type(candidate) is not _InfluenceCandidateInput:
            raise _integrity("SCIENCE.INFLUENCE_CANDIDATE_INPUT")
        record = _closed_record(
            candidate.candidate_record_bytes,
            code="SCIENCE.INFLUENCE_CANDIDATE_BYTES",
        )
        operation = _closed_record(
            candidate.operation_bytes,
            code="SCIENCE.INFLUENCE_OPERATION_BYTES",
        )
        identity = _candidate_identity(record)
        if (
            identity[0] != expected_ordinal
            or identity[1] in observed_candidate_ids
            or (candidate.universe_id is not None and type(candidate.universe_id) is not str)
        ):
            raise _integrity("SCIENCE.INFLUENCE_CANDIDATE_INPUT")
        observed_candidate_ids.add(identity[1])
        preparation = (
            None
            if candidate.preparation_binding_bytes is None
            else _closed_record(
                candidate.preparation_binding_bytes,
                code="SCIENCE.INFLUENCE_PREPARATION_BYTES",
            )
        )
        decoded.append((candidate, record, operation, preparation))
    by_analysis = {
        cast(str, record["analysis_spec_id"]): (
            candidate,
            record,
            operation,
            preparation,
        )
        for candidate, record, operation, preparation in decoded
    }
    if len(by_analysis) != len(decoded):
        raise _integrity("SCIENCE.INFLUENCE_CANDIDATE_IDENTITY")
    contexts: list[
        tuple[
            dict[str, object],
            dict[str, object],
            dict[str, object],
            _InfluenceCandidateInput,
            dict[str, object],
            _InfluenceCandidateInput,
            dict[str, object],
            dict[str, object],
        ]
    ] = []
    all_origin_ids: set[str] = set()
    for removal_input, removal, operation, preparation in decoded:
        kind = operation.get("kind")
        for origin_input in removal_input.origins:
            if type(origin_input) is not _InfluenceOriginInput:
                raise _integrity("SCIENCE.INFLUENCE_ORIGIN_INPUT")
            origin = _closed_record(
                origin_input.origin_bytes,
                code="SCIENCE.INFLUENCE_ORIGIN_BYTES",
            )
            edge = _closed_record(
                origin_input.comparison_edge_bytes,
                code="SCIENCE.INFLUENCE_EDGE_BYTES",
            )
            origin_id = origin.get("origin_id")
            if type(origin_id) is not str or origin_id in all_origin_ids:
                raise _integrity("SCIENCE.INFLUENCE_ORIGIN_IDENTITY")
            all_origin_ids.add(origin_id)
            if kind != "influence":
                if origin.get("experiment_mode") == "influence":
                    raise _integrity("SCIENCE.INFLUENCE_OPERATION_ORIGIN_MISMATCH")
                continue
            source_id = operation.get("source_analysis_spec_id")
            source_entry = by_analysis.get(cast(str, source_id))
            if (
                origin.get("experiment_mode") != "influence"
                or type(origin.get("analysis_declaration_id")) is not str
                or type(origin.get("source_declaration_digest")) is not str
                or type(origin.get("experiment_set_id")) is not str
                or type(source_id) is not str
                or source_entry is None
                or preparation is None
                or edge.get("origin_id") != origin_id
                or edge.get("subject_analysis_spec_id") != removal["analysis_spec_id"]
                or edge.get("comparator_analysis_spec_id") != source_id
                or edge.get("derivation_rule_id") != "derived-origin-to-source/1"
                or edge.get("semantics")
                != {
                    "order_event_alignment": "identical-event-set",
                    "native_stage_comparability": "comparable",
                }
                or operation.get("removal_method_id")
                != "exact-participant-or-named-group-removal/1"
                or operation.get("removal_kind")
                not in {
                    "leave-one-participant-out",
                    "named-group-removal",
                }
                or type(operation.get("removal_slot_ordinal")) is not int
                or cast(int, operation["removal_slot_ordinal"]) < 0
                or operation.get("refit_preprocessing") is not True
                or operation.get("fixed_non_removed_cohort_policy")
                != "fixed-non-removed-baseline-cohort-or-unsupported/1"
            ):
                raise _integrity("SCIENCE.INFLUENCE_OPERATION_ORIGIN_MISMATCH")
            source_input, source, source_operation, _source_preparation = source_entry
            if source_operation.get("kind") != "ordinary":
                raise _integrity("SCIENCE.INFLUENCE_SOURCE_NOT_ORDINARY")
            _validate_preparation_binding(
                preparation,
                candidate_ordinal=cast(int, removal["candidate_ordinal"]),
                analysis_spec_id=cast(str, removal["analysis_spec_id"]),
                operation={
                    **operation,
                    "removal_analysis_spec_id": removal["analysis_spec_id"],
                },
            )
            contexts.append(
                (
                    origin,
                    edge,
                    {
                        **operation,
                        "removal_analysis_spec_id": removal["analysis_spec_id"],
                    },
                    removal_input,
                    removal,
                    source_input,
                    source,
                    preparation,
                )
            )
    contexts.sort(key=lambda row: _utf8(cast(str, row[0]["origin_id"])))
    attempts = tuple(
        _derive_attempt(
            plan_digest=plan_digest,
            terminal_index_digest=terminal_index_digest,
            origin=origin,
            edge=edge,
            operation=operation,
            removal=removal,
            source=source,
            removal_universe_id=removal_input.universe_id,
            source_universe_id=source_input.universe_id,
            preparation=preparation,
        )
        for (
            origin,
            edge,
            operation,
            removal_input,
            removal,
            source_input,
            source,
            preparation,
        ) in contexts
    )
    decoded_attempts = [
        cast(dict[str, object], strict_json_loads(attempt.canonical_bytes)) for attempt in attempts
    ]
    origin_ids = [cast(str, attempt["origin_id"]) for attempt in decoded_attempts]
    contribution_counts = {
        state: sum(attempt["contribution_state"] == state for attempt in decoded_attempts)
        for state in _CONTRIBUTION_STATES
    }
    preimage: dict[str, object] = {
        "layer_schema_version": INFLUENCE_LAYER_SCHEMA_VERSION,
        "evidence_rule_id": INFLUENCE_EVIDENCE_RULE_ID,
        "uncertainty_layer": "PARTICIPANT_INFLUENCE",
        "pooling_policy": "NON_POOLABLE",
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "planned_origin_count": len(origin_ids),
        "planned_origin_ids": origin_ids,
        "attempt_count": len(decoded_attempts),
        "influence_record_count": sum(
            attempt["influence_record"] is not None for attempt in decoded_attempts
        ),
        "contribution_counts": contribution_counts,
        "attempts": decoded_attempts,
        "classification_status": ("FROZEN_REVIEWED_WITH_DEVELOPMENT_SENSITIVITY_UNVERIFIED"),
    }
    layer_digest = structured_sha256(_LAYER_DOMAIN, preimage)
    layer = _CanonicalInfluenceLayerEvidence(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes(
            {
                **preimage,
                "layer_digest": layer_digest,
            }
        ),
        layer_digest=layer_digest,
    )
    decoded_layer = strict_json_loads(layer.canonical_bytes)
    if type(decoded_layer) is not dict:
        raise _integrity("SCIENCE.INFLUENCE_LAYER")
    _validate_influence_semantics(cast(dict[str, object], decoded_layer))
    return _CanonicalInfluenceEvidenceBundle(
        attempts=attempts,
        layer=layer,
    )


_INFLUENCE_DERIVATION = build_frozen_derivation_graph(
    globals(),
    module_name=__name__,
    root_names=(
        "_derive_influence_evidence",
        "_validate_influence_semantics",
    ),
    record_type_names=(
        "_CanonicalInfluenceAttempt",
        "_CanonicalInfluenceLayerEvidence",
        "_CanonicalInfluenceEvidenceBundle",
        "_InfluenceOriginInput",
        "_InfluenceCandidateInput",
    ),
)
for _function_name, _frozen_function in _INFLUENCE_DERIVATION.functions.items():
    globals()[_function_name] = _frozen_function
for _record_type_name, _frozen_record_type in _INFLUENCE_DERIVATION.record_types.items():
    globals()[_record_type_name] = _frozen_record_type
del _function_name
del _frozen_function
del _record_type_name
del _frozen_record_type
del build_frozen_derivation_graph


__all__: list[str] = []
