"""Pure sealed ordinary-origin decision evidence.

This private module receives only closure-built immutable candidate and reference-chain
inputs. It never receives a result owner, caller-authored summary, report model, or raw
participant value.

Every applicable ordinary origin is compared with the literal declared baseline.
Combination and factorial rows are descriptive matched associations; this module does
not derive factorial effects, interactions, variance decompositions, or p-values.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from math import comb as _math_comb
from math import isfinite as _math_isfinite
from typing import Final, Literal, cast

from ebm_audit.metrics import (
    METRIC_ABSOLUTE_TOLERANCE,
    empirical_quantile,
    pairwise_matrix_distance,
    pairwise_precedence_matrix,
    per_event_rank_shifts,
    position_matrix,
    position_matrix_distance,
    strict_order_comparison,
    strict_pairwise_majority_flips,
)
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256

from ._evidence_records import (
    _central_order,
    _ChainEvidenceInput,
    _derive_chain,
    _DerivedChain,
    _integrity,
    _matrix_value,
    _scalar,
    _ScientificRecordIntegrityError,
)
from ._frozen_derivation import build_frozen_analyst_derivation
from ._participant_stage_validation import (
    validate_participant_stage_comparison_semantics as _validate_shared_participant_stage_semantics,
)

SEALED_EVIDENCE_RULE_ID: Final = (
    "within-fit-chain-sampling-analyst-decision-participant-influence-null-evidence-rules/10"
)
ANALYST_DECISION_EVIDENCE_RULE_ID: Final = (
    "ordinary-origin-to-literal-baseline-descriptive-association/2"
)
ORIGIN_COMPARISON_ATTEMPT_SCHEMA_VERSION: Final = "ebm-audit-origin-comparison-attempt/2.0"
ORIGIN_NUMERIC_COMPARISON_SCHEMA_VERSION: Final = "ebm-audit-origin-numeric-comparison/4.0"
ANALYST_DECISION_AGGREGATE_SCHEMA_VERSION: Final = "ebm-audit-analyst-decision-aggregate/2.0"
ANALYST_DECISION_LAYER_SCHEMA_VERSION: Final = "ebm-audit-analyst-decision-layer-evidence/2.0"
_ANALYST_DECISION_COMPONENT_COVERAGE: Final = (
    ("ORDINARY_ONE_AXIS_ORIGIN_COMPARISON", "IMPLEMENTED", None),
    (
        "DECLARED_COMBINATION_ATTRIBUTION",
        "IMPLEMENTED",
        None,
    ),
    (
        "FULL_FACTORIAL_ATTRIBUTION",
        "IMPLEMENTED",
        None,
    ),
    (
        "PARTICIPANT_STAGE_COMPARISON",
        "IMPLEMENTED",
        None,
    ),
)
_ANALYST_DECISION_APPLICABILITY_STATES: Final = (
    "REFERENCE_ONLY_BASELINE",
    "APPLICABLE_ORDINARY_ONE_AXIS",
    "APPLICABLE_DECLARED_COMBINATION",
    "APPLICABLE_FULL_FACTORIAL",
    "NOT_APPLICABLE_BOOTSTRAP",
    "NOT_APPLICABLE_SUBSAMPLE",
    "NOT_APPLICABLE_INFLUENCE",
    "NOT_APPLICABLE_NULL",
    "NOT_APPLICABLE_CUSTOM",
)
_ANALYST_DECISION_APPLICABLE_STATES: Final = frozenset(
    {
        "APPLICABLE_ORDINARY_ONE_AXIS",
        "APPLICABLE_DECLARED_COMBINATION",
        "APPLICABLE_FULL_FACTORIAL",
    }
)
_ANALYST_DECISION_METRIC_SPECIFICATIONS: Final = (
    ("central-order-kendall-distance/1", "kendall_distance"),
    ("central-order-footrule-distance/1", "footrule_distance"),
    ("position-matrix-distance/1", "position_matrix_distance"),
    ("pairwise-matrix-distance/1", "pairwise_matrix_distance"),
    ("strict-pairwise-majority-flip-count/1", "flip_count"),
    ("strict-pairwise-majority-flip-fraction/1", "flip_fraction"),
)
_ANALYST_DECISION_RANK_SHIFT_METRIC_IDS: Final = (
    "absolute-event-rank-shift/1",
    "normalized-event-rank-shift/1",
)
_ATTEMPT_DIGEST_DOMAIN: Final = "ebm-audit/scientific-origin-comparison-attempt/2"
_NUMERIC_DIGEST_DOMAIN: Final = "ebm-audit/scientific-origin-numeric-comparison/4"
_AGGREGATE_DIGEST_DOMAIN: Final = "ebm-audit/scientific-analyst-decision-aggregate/2"
_LAYER_DIGEST_DOMAIN: Final = "ebm-audit/scientific-analyst-decision-evidence/2"
_ORIGIN_ID_DOMAIN: Final = "ebm-audit/candidate-origin/1"

type _Eligibility = Literal["INTERPRETIVE", "DESCRIPTIVE_ONLY", "UNAVAILABLE"]
type _ApplicabilityState = Literal[
    "REFERENCE_ONLY_BASELINE",
    "APPLICABLE_ORDINARY_ONE_AXIS",
    "APPLICABLE_DECLARED_COMBINATION",
    "APPLICABLE_FULL_FACTORIAL",
    "NOT_APPLICABLE_BOOTSTRAP",
    "NOT_APPLICABLE_SUBSAMPLE",
    "NOT_APPLICABLE_INFLUENCE",
    "NOT_APPLICABLE_NULL",
    "NOT_APPLICABLE_CUSTOM",
]
type _ContributionState = Literal[
    "INTERPRETIVE",
    "DESCRIPTIVE_ONLY",
    "METRIC_NOT_ASSESSABLE",
    "FAILED",
    "NOT_CONTRIBUTING",
]
type _AggregateSourceRow = tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
]
type _AggregateSourceRows = tuple[_AggregateSourceRow, ...]
type _CandidateIdentityBinding = tuple[str, str | None, str, str]
type _CandidateEvidenceBinding = tuple[
    tuple[str, ...],
    dict[str, object] | None,
]


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalOriginComparisonAttempt:
    preimage_bytes: bytes
    canonical_bytes: bytes
    attempt_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalOriginNumericComparisonRecord:
    preimage_bytes: bytes
    canonical_bytes: bytes
    numeric_comparison_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalAnalystDecisionAggregate:
    preimage_bytes: bytes
    canonical_bytes: bytes
    aggregate_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalAnalystDecisionLayerEvidence:
    preimage_bytes: bytes
    canonical_bytes: bytes
    layer_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalAnalystDecisionEvidenceBundle:
    attempts: tuple[_CanonicalOriginComparisonAttempt, ...]
    numeric_records: tuple[_CanonicalOriginNumericComparisonRecord, ...]
    aggregates: tuple[_CanonicalAnalystDecisionAggregate, ...]
    layer: _CanonicalAnalystDecisionLayerEvidence


@dataclass(frozen=True, repr=False, slots=True)
class _AnalystDecisionOriginInput:
    origin_bytes: bytes
    comparison_edge_bytes: bytes
    stage_comparison_bytes: bytes


@dataclass(frozen=True, repr=False, slots=True)
class _AnalystDecisionCandidateInput:
    candidate_ordinal: int
    candidate_id: str
    analysis_spec_id: str
    result_id: str
    universe_id: str | None
    final_status: str
    candidate_record_digest: str
    operation_kind: str
    event_ids: tuple[str, ...]
    origins: tuple[_AnalystDecisionOriginInput, ...]
    reference_chain: _ChainEvidenceInput | None


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _decoded_closed_record(value: bytes, *, code: str) -> dict[str, object]:
    if type(value) is not bytes:
        raise _integrity(code)
    decoded = strict_json_loads(value)
    if type(decoded) is not dict or canonical_json_bytes(decoded) != value:
        raise _integrity(code)
    return cast(dict[str, object], decoded)


def _analyst_applicability(
    *,
    origin: dict[str, object],
    edge: dict[str, object],
    operation_kind: str,
    baseline_analysis_spec_id: str,
    subject_analysis_spec_id: str,
    subject_event_ids: tuple[str, ...],
    comparator_event_ids: tuple[str, ...],
) -> tuple[_ApplicabilityState, str | None, str | None]:
    expected_origin_keys = {
        "analysis_declaration_id",
        "experiment_set_id",
        "experiment_mode",
        "declaration_ordinal",
        "axis_choices",
        "source_declaration_digest",
        "origin_id",
    }
    expected_edge_keys = {
        "origin_id",
        "subject_analysis_spec_id",
        "comparator_analysis_spec_id",
        "derivation_rule_id",
        "semantics",
    }
    if set(origin) != expected_origin_keys or set(edge) != expected_edge_keys:
        raise _integrity("SCIENCE.ANALYST_DECISION_SOURCE_SHAPE")
    origin_id = origin.get("origin_id")
    experiment_set_id = origin.get("experiment_set_id")
    mode = origin.get("experiment_mode")
    choices = origin.get("axis_choices")
    semantics = edge.get("semantics")
    if (
        type(origin_id) is not str
        or type(experiment_set_id) is not str
        or type(mode) is not str
        or type(choices) is not list
        or any(
            type(choice) is not dict
            or set(choice) != {"axis_id", "choice_id"}
            or type(choice.get("axis_id")) is not str
            or type(choice.get("choice_id")) is not str
            for choice in choices
        )
        or edge.get("origin_id") != origin_id
        or edge.get("subject_analysis_spec_id") != subject_analysis_spec_id
        or type(edge.get("comparator_analysis_spec_id")) is not str
        or type(edge.get("derivation_rule_id")) is not str
        or type(semantics) is not dict
        or set(semantics) != {"order_event_alignment", "native_stage_comparability"}
        or semantics.get("order_event_alignment")
        not in {"identical-event-set", "common-event-only"}
        or semantics.get("native_stage_comparability") not in {"comparable", "non-equivalent"}
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_SOURCE_SHAPE")
    exact_choices = cast(list[dict[str, object]], choices)
    axis_ids = [cast(str, choice["axis_id"]) for choice in exact_choices]
    expected_order_alignment = (
        "identical-event-set"
        if set(subject_event_ids) == set(comparator_event_ids)
        else "common-event-only"
    )
    if semantics.get("order_event_alignment") != expected_order_alignment:
        raise _integrity("SCIENCE.ANALYST_DECISION_EVENT_ALIGNMENT")
    if (
        expected_order_alignment == "common-event-only"
        and semantics.get("native_stage_comparability") != "non-equivalent"
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_STAGE_COMPARABILITY")
    if (
        edge.get("subject_analysis_spec_id") == edge.get("comparator_analysis_spec_id")
        and semantics.get("native_stage_comparability") != "comparable"
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_STAGE_COMPARABILITY")
    if len(set(axis_ids)) != len(axis_ids) or exact_choices != sorted(
        exact_choices,
        key=lambda choice: (
            _utf8(cast(str, choice["axis_id"])),
            _utf8(cast(str, choice["choice_id"])),
        ),
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_AXIS_CHOICES")

    if mode == "baseline":
        if (
            exact_choices
            or operation_kind != "ordinary"
            or subject_analysis_spec_id != baseline_analysis_spec_id
            or edge["comparator_analysis_spec_id"] != subject_analysis_spec_id
            or edge["derivation_rule_id"] != "baseline-origin-self/1"
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_BASELINE_CONTRADICTION")
        return "REFERENCE_ONLY_BASELINE", None, None
    if mode == "one-axis":
        if (
            len(exact_choices) != 1
            or operation_kind != "ordinary"
            or edge["comparator_analysis_spec_id"] != baseline_analysis_spec_id
            or edge["derivation_rule_id"] != "ordinary-origin-to-plan-baseline/1"
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_ONE_AXIS_CONTRADICTION")
        choice = exact_choices[0]
        return (
            "APPLICABLE_ORDINARY_ONE_AXIS",
            cast(str, choice["axis_id"]),
            cast(str, choice["choice_id"]),
        )
    if mode in {"declared-combinations", "full-factorial"}:
        if (
            len(exact_choices) < 2
            or operation_kind != "ordinary"
            or edge["comparator_analysis_spec_id"] != baseline_analysis_spec_id
            or edge["derivation_rule_id"] != "ordinary-origin-to-plan-baseline/1"
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_COMBINATION_CONTRADICTION")
        return (
            (
                "APPLICABLE_DECLARED_COMBINATION"
                if mode == "declared-combinations"
                else "APPLICABLE_FULL_FACTORIAL"
            ),
            None,
            None,
        )

    expected: dict[str, tuple[_ApplicabilityState, str]] = {
        "bootstrap": ("NOT_APPLICABLE_BOOTSTRAP", "bootstrap"),
        "subsample": ("NOT_APPLICABLE_SUBSAMPLE", "subsample"),
        "influence": ("NOT_APPLICABLE_INFLUENCE", "influence"),
        "null": ("NOT_APPLICABLE_NULL", "null"),
        "custom": ("NOT_APPLICABLE_CUSTOM", "ordinary"),
    }
    resolved = expected.get(mode)
    if resolved is None or operation_kind != resolved[1]:
        raise _integrity("SCIENCE.ANALYST_DECISION_MODE_OPERATION_CONTRADICTION")
    expected_rule = (
        "ordinary-origin-to-plan-baseline/1"
        if operation_kind == "ordinary"
        else "derived-origin-to-source/1"
    )
    if edge["derivation_rule_id"] != expected_rule:
        raise _integrity("SCIENCE.ANALYST_DECISION_EDGE_CONTRADICTION")
    return resolved[0], None, None


def _project_order_samples(
    samples: tuple[tuple[str, ...], ...],
    common_event_ids: tuple[str, ...],
) -> tuple[tuple[str, ...], ...]:
    common = set(common_event_ids)
    projected = tuple(
        tuple(event_id for event_id in sample if event_id in common) for sample in samples
    )
    if any(len(sample) != len(common_event_ids) or set(sample) != common for sample in projected):
        raise _integrity("SCIENCE.ANALYST_DECISION_PROJECTED_ORDER")
    return projected


def _numeric_absence_scalar(metric_id: str, reason_code: str) -> dict[str, object]:
    return {
        "metric_id": metric_id,
        "status": "NOT_ASSESSABLE",
        "value": None,
        "reason_code": reason_code,
        "metadata_code": None,
    }


def _numeric_identity(
    subject: _AnalystDecisionCandidateInput,
    comparator: _AnalystDecisionCandidateInput,
) -> dict[str, object]:
    return {
        "subject_analysis_spec_id": subject.analysis_spec_id,
        "comparator_analysis_spec_id": comparator.analysis_spec_id,
        "subject_result_id": subject.result_id,
        "comparator_result_id": comparator.result_id,
        "subject_candidate_record_digest": subject.candidate_record_digest,
        "comparator_candidate_record_digest": comparator.candidate_record_digest,
    }


def _combined_eligibility(
    subject_status: str,
    comparator_status: str,
) -> _Eligibility:
    if subject_status == comparator_status == "SUCCESS":
        return "INTERPRETIVE"
    if (
        subject_status in {"SUCCESS", "CONVERGENCE_WARN"}
        and comparator_status in {"SUCCESS", "CONVERGENCE_WARN"}
        and "CONVERGENCE_WARN" in {subject_status, comparator_status}
    ):
        return "DESCRIPTIVE_ONLY"
    return "UNAVAILABLE"


def _reference_source_record(
    derived: _DerivedChain | None,
) -> dict[str, object] | None:
    if derived is None:
        return None
    return {
        **derived.source,
        "retained_state_count": derived.retained_state_count,
        "order_state_chain_digest": derived.order_state_chain_digest,
    }


def _numeric_metric_status(metrics: tuple[dict[str, object], ...]) -> str:
    assessable = sum(metric.get("status") == "ASSESSABLE" for metric in metrics)
    if assessable == len(metrics):
        return "FULLY_ASSESSABLE"
    if assessable:
        return "PARTIALLY_ASSESSABLE"
    return "NOT_ASSESSABLE"


def _derive_origin_numeric_comparison(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    subject: _AnalystDecisionCandidateInput,
    comparator: _AnalystDecisionCandidateInput,
    participant_stage_comparison: dict[str, object],
) -> _CanonicalOriginNumericComparisonRecord:
    eligibility = _combined_eligibility(subject.final_status, comparator.final_status)
    subject_events = set(subject.event_ids)
    comparator_events = set(comparator.event_ids)
    common_event_ids: tuple[str, ...] = tuple(sorted(subject_events & comparator_events, key=_utf8))
    subject_only_event_ids: tuple[str, ...] = tuple(
        sorted(subject_events - comparator_events, key=_utf8)
    )
    comparator_only_event_ids: tuple[str, ...] = tuple(
        sorted(comparator_events - subject_events, key=_utf8)
    )
    subject_derived = (
        None if subject.reference_chain is None else _derive_chain(subject.reference_chain)
    )
    comparator_derived = (
        None if comparator.reference_chain is None else _derive_chain(comparator.reference_chain)
    )
    reason_code: str | None
    rank_shifts: dict[str, object]
    if eligibility == "UNAVAILABLE":
        numeric_status = "TERMINAL_UNAVAILABLE"
        reason_code = "ANALYST_DECISION.TERMINAL_UNAVAILABLE"
        subject_modal: tuple[str, ...] = ()
        comparator_modal: tuple[str, ...] = ()
        absent_reason = "ANALYST_DECISION.TERMINAL_UNAVAILABLE"
        kendall = _numeric_absence_scalar(
            "central-order-kendall-distance/1",
            absent_reason,
        )
        footrule = _numeric_absence_scalar(
            "central-order-footrule-distance/1",
            absent_reason,
        )
        rank_shifts = {
            "rule_id": "common-event-rank-shift/1",
            "absolute_rank_shift_metric_id": "absolute-event-rank-shift/1",
            "normalized_rank_shift_metric_id": "normalized-event-rank-shift/1",
            "status": "NOT_ASSESSABLE",
            "reason_code": absent_reason,
            "event_rows": [],
        }
        position_distance = _numeric_absence_scalar(
            "position-matrix-distance/1",
            absent_reason,
        )
        pairwise_distance = _numeric_absence_scalar(
            "pairwise-matrix-distance/1",
            absent_reason,
        )
        flip_count = _numeric_absence_scalar(
            "strict-pairwise-majority-flip-count/1",
            absent_reason,
        )
        flip_fraction = _numeric_absence_scalar(
            "strict-pairwise-majority-flip-fraction/1",
            absent_reason,
        )
        pairwise_flips: dict[str, object] = {
            "rule_id": "strict-pairwise-majority-flips/1",
            "denominator_rule_id": "unordered-common-event-pairs/1",
            "strict_pairwise_majority_flip_denominator": None,
            "flipped_pairs": [],
            "flip_count": flip_count,
            "flip_fraction": flip_fraction,
        }
    else:
        subject_reference = subject.reference_chain
        comparator_reference = comparator.reference_chain
        if (
            subject_derived is None
            or comparator_derived is None
            or subject_reference is None
            or comparator_reference is None
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_REFERENCE_CHAIN_REQUIRED")
        if (
            subject_reference.event_ids != subject.event_ids
            or comparator_reference.event_ids != comparator.event_ids
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_EVENT_IDENTITY")
        if len(common_event_ids) < 2:
            subject_modal = ()
            comparator_modal = ()
            absent_reason = "ORDER.FEWER_THAN_TWO_COMMON_EVENTS"
            kendall = _numeric_absence_scalar(
                "central-order-kendall-distance/1",
                absent_reason,
            )
            footrule = _numeric_absence_scalar(
                "central-order-footrule-distance/1",
                absent_reason,
            )
            rank_shifts = {
                "rule_id": "common-event-rank-shift/1",
                "absolute_rank_shift_metric_id": "absolute-event-rank-shift/1",
                "normalized_rank_shift_metric_id": "normalized-event-rank-shift/1",
                "status": "NOT_ASSESSABLE",
                "reason_code": absent_reason,
                "event_rows": [],
            }
            position_distance = _numeric_absence_scalar(
                "position-matrix-distance/1",
                "POSITION.FEWER_THAN_TWO_COMMON_EVENTS",
            )
            pairwise_distance = _numeric_absence_scalar(
                "pairwise-matrix-distance/1",
                "PAIRWISE.FEWER_THAN_TWO_COMMON_EVENTS",
            )
            flip_count = _numeric_absence_scalar(
                "strict-pairwise-majority-flip-count/1",
                "PAIRWISE.FEWER_THAN_TWO_COMMON_EVENTS",
            )
            flip_fraction = _numeric_absence_scalar(
                "strict-pairwise-majority-flip-fraction/1",
                "PAIRWISE.FEWER_THAN_TWO_COMMON_EVENTS",
            )
            pairwise_flips = {
                "rule_id": "strict-pairwise-majority-flips/1",
                "denominator_rule_id": "unordered-common-event-pairs/1",
                "strict_pairwise_majority_flip_denominator": None,
                "flipped_pairs": [],
                "flip_count": flip_count,
                "flip_fraction": flip_fraction,
            }
            numeric_status = "NOT_ASSESSABLE"
            reason_code = "ANALYST_DECISION.FEWER_THAN_TWO_COMMON_EVENTS"
        else:
            subject_samples = _project_order_samples(
                subject_derived.order_samples,
                common_event_ids,
            )
            comparator_samples = _project_order_samples(
                comparator_derived.order_samples,
                common_event_ids,
            )
            subject_modal = _central_order(subject_samples)
            comparator_modal = _central_order(comparator_samples)
            order_comparison = strict_order_comparison(subject_modal, comparator_modal)
            kendall = _scalar(
                order_comparison.kendall_distance,
                metric_id="central-order-kendall-distance/1",
            )
            footrule = _scalar(
                order_comparison.footrule_distance,
                metric_id="central-order-footrule-distance/1",
            )
            shifts = per_event_rank_shifts(subject_modal, comparator_modal)
            rank_shifts = {
                "rule_id": "common-event-rank-shift/1",
                "absolute_rank_shift_metric_id": "absolute-event-rank-shift/1",
                "normalized_rank_shift_metric_id": "normalized-event-rank-shift/1",
                "status": (
                    "ASSESSABLE"
                    if shifts.maximum_normalized_rank_shift.status == "ASSESSABLE"
                    else "NOT_ASSESSABLE"
                ),
                "reason_code": shifts.maximum_normalized_rank_shift.reason_code,
                "event_rows": [
                    {
                        "event_id": shift.event_id,
                        "subject_rank": shift.left_rank,
                        "comparator_rank": shift.right_rank,
                        "absolute_rank_shift": shift.absolute_rank_shift,
                        "normalized_rank_shift": shift.normalized_rank_shift,
                    }
                    for shift in shifts.shifts
                ],
            }
            subject_position = _matrix_value(
                position_matrix(subject_samples, common_event_ids),
                code="SCIENCE.ANALYST_DECISION_POSITION_DERIVATION",
            )
            comparator_position = _matrix_value(
                position_matrix(comparator_samples, common_event_ids),
                code="SCIENCE.ANALYST_DECISION_POSITION_DERIVATION",
            )
            subject_pairwise = _matrix_value(
                pairwise_precedence_matrix(subject_samples, common_event_ids),
                code="SCIENCE.ANALYST_DECISION_PAIRWISE_DERIVATION",
            )
            comparator_pairwise = _matrix_value(
                pairwise_precedence_matrix(comparator_samples, common_event_ids),
                code="SCIENCE.ANALYST_DECISION_PAIRWISE_DERIVATION",
            )
            position_distance = _scalar(
                position_matrix_distance(
                    subject_position,
                    comparator_position,
                    left_event_ids=common_event_ids,
                    right_event_ids=common_event_ids,
                ),
                metric_id="position-matrix-distance/1",
            )
            pairwise_distance = _scalar(
                pairwise_matrix_distance(
                    subject_pairwise,
                    comparator_pairwise,
                    left_event_ids=common_event_ids,
                    right_event_ids=common_event_ids,
                ),
                metric_id="pairwise-matrix-distance/1",
            )
            flips = strict_pairwise_majority_flips(
                subject_pairwise,
                comparator_pairwise,
                left_event_ids=common_event_ids,
                right_event_ids=common_event_ids,
            )
            flip_count = _scalar(
                flips.flip_count,
                metric_id="strict-pairwise-majority-flip-count/1",
            )
            flip_fraction = _scalar(
                flips.flip_fraction,
                metric_id="strict-pairwise-majority-flip-fraction/1",
            )
            pairwise_flips = {
                "rule_id": "strict-pairwise-majority-flips/1",
                "denominator_rule_id": "unordered-common-event-pairs/1",
                "strict_pairwise_majority_flip_denominator": (
                    flips.strict_pairwise_majority_flip_denominator
                ),
                "flipped_pairs": [
                    {
                        "event_a_id": flip.event_a_id,
                        "event_b_id": flip.event_b_id,
                        "subject_probability_a_before_b": (flip.left_probability_a_before_b),
                        "comparator_probability_a_before_b": (flip.right_probability_a_before_b),
                        "subject_relation": flip.left_relation,
                        "comparator_relation": flip.right_relation,
                    }
                    for flip in flips.flips
                ],
                "flip_count": flip_count,
                "flip_fraction": flip_fraction,
            }
            numeric_status = _numeric_metric_status(
                (
                    kendall,
                    footrule,
                    position_distance,
                    pairwise_distance,
                    flip_count,
                    flip_fraction,
                )
            )
            reason_code = (
                None
                if numeric_status == "FULLY_ASSESSABLE"
                else "ANALYST_DECISION.PARTIAL_METRIC_COVERAGE"
            )

    preimage: dict[str, object] = {
        "record_schema_version": ORIGIN_NUMERIC_COMPARISON_SCHEMA_VERSION,
        "evidence_rule_id": ANALYST_DECISION_EVIDENCE_RULE_ID,
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "numeric_identity": _numeric_identity(subject, comparator),
        "subject_universe_id": subject.universe_id,
        "comparator_universe_id": comparator.universe_id,
        "subject_terminal_status": subject.final_status,
        "comparator_terminal_status": comparator.final_status,
        "eligibility": eligibility,
        "subject_reference_chain_source": _reference_source_record(subject_derived),
        "comparator_reference_chain_source": _reference_source_record(comparator_derived),
        "common_event_ids": list(common_event_ids),
        "subject_only_event_ids": list(subject_only_event_ids),
        "comparator_only_event_ids": list(comparator_only_event_ids),
        "subject_projected_modal_order_event_ids": list(subject_modal),
        "comparator_projected_modal_order_event_ids": list(comparator_modal),
        "metric_bundle": {
            "projection_rule_id": "project-every-retained-reference-chain-sample/1",
            "central_order_rule_id": "retained-state-mode-utf8-tie-break/1",
            "kendall_distance": kendall,
            "footrule_distance": footrule,
            "event_rank_shifts": rank_shifts,
            "position_matrix_distance": position_distance,
            "pairwise_matrix_distance": pairwise_distance,
            "pairwise_majority_flips": pairwise_flips,
        },
        "participant_stage_comparison": participant_stage_comparison,
        "numeric_status": numeric_status,
        "reason_code": reason_code,
    }
    digest = structured_sha256(_NUMERIC_DIGEST_DOMAIN, preimage)
    return _CanonicalOriginNumericComparisonRecord(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes({**preimage, "numeric_comparison_digest": digest}),
        numeric_comparison_digest=digest,
    )


def _numeric_contribution_state(
    record: dict[str, object],
) -> tuple[_ContributionState, str | None]:
    eligibility = record.get("eligibility")
    numeric_status = record.get("numeric_status")
    if eligibility == "UNAVAILABLE":
        return "FAILED", "ANALYST_DECISION.TERMINAL_UNAVAILABLE"
    if numeric_status == "NOT_ASSESSABLE":
        return "METRIC_NOT_ASSESSABLE", cast(str | None, record.get("reason_code"))
    if eligibility == "INTERPRETIVE":
        return "INTERPRETIVE", None
    if eligibility == "DESCRIPTIVE_ONLY":
        return "DESCRIPTIVE_ONLY", "ANALYST_DECISION.CONVERGENCE_WARNING"
    raise _integrity("SCIENCE.ANALYST_DECISION_CONTRIBUTION_STATE")


def _origin_attempt(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    origin: dict[str, object],
    edge: dict[str, object],
    subject: _AnalystDecisionCandidateInput,
    comparator: _AnalystDecisionCandidateInput,
    applicability: _ApplicabilityState,
    axis_id: str | None,
    choice_id: str | None,
    numeric_record: dict[str, object] | None,
) -> _CanonicalOriginComparisonAttempt:
    contribution_reason: str | None
    if numeric_record is None:
        numeric_digest = None
        contribution_state: _ContributionState = "NOT_CONTRIBUTING"
        contribution_reason = (
            "ANALYST_DECISION.REFERENCE_BASELINE"
            if applicability == "REFERENCE_ONLY_BASELINE"
            else f"ANALYST_DECISION.{applicability}"
        )
    else:
        numeric_digest = numeric_record.get("numeric_comparison_digest")
        if type(numeric_digest) is not str:
            raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_REFERENCE")
        contribution_state, contribution_reason = _numeric_contribution_state(numeric_record)
    preimage: dict[str, object] = {
        "record_schema_version": ORIGIN_COMPARISON_ATTEMPT_SCHEMA_VERSION,
        "evidence_rule_id": ANALYST_DECISION_EVIDENCE_RULE_ID,
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "origin_id": origin["origin_id"],
        "analysis_declaration_id": origin["analysis_declaration_id"],
        "source_declaration_digest": origin["source_declaration_digest"],
        "declaration_ordinal": origin["declaration_ordinal"],
        "experiment_set_id": origin["experiment_set_id"],
        "experiment_mode": origin["experiment_mode"],
        "axis_choices": origin["axis_choices"],
        "axis_id": axis_id,
        "choice_id": choice_id,
        "attribution_semantics": "DESCRIPTIVE_ASSOCIATION",
        "interpretation_phrase": "associated with movement",
        "applicability_state": applicability,
        "comparison_edge": edge,
        "subject_analysis_spec_id": subject.analysis_spec_id,
        "comparator_analysis_spec_id": comparator.analysis_spec_id,
        "subject_result_id": subject.result_id,
        "comparator_result_id": comparator.result_id,
        "subject_universe_id": subject.universe_id,
        "comparator_universe_id": comparator.universe_id,
        "subject_terminal_status": subject.final_status,
        "comparator_terminal_status": comparator.final_status,
        "subject_candidate_record_digest": subject.candidate_record_digest,
        "comparator_candidate_record_digest": comparator.candidate_record_digest,
        "numeric_comparison_digest": numeric_digest,
        "contribution_state": contribution_state,
        "reason_code": contribution_reason,
    }
    digest = structured_sha256(_ATTEMPT_DIGEST_DOMAIN, preimage)
    return _CanonicalOriginComparisonAttempt(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes({**preimage, "attempt_digest": digest}),
        attempt_digest=digest,
    )


def _finite_metric_value(metric: object) -> float | None:
    if (
        type(metric) is not dict
        or metric.get("status") != "ASSESSABLE"
        or isinstance(metric.get("value"), bool)
        or not isinstance(metric.get("value"), (int, float))
    ):
        return None
    value = float(cast(int | float, metric["value"]))
    return value if _math_isfinite(value) else None


def _numeric_metric(
    record: dict[str, object],
    field: Literal[
        "kendall_distance",
        "footrule_distance",
        "position_matrix_distance",
        "pairwise_matrix_distance",
    ],
) -> dict[str, object]:
    bundle = record.get("metric_bundle")
    metric = bundle.get(field) if type(bundle) is dict else None
    if type(metric) is not dict:
        raise _integrity("SCIENCE.ANALYST_DECISION_METRIC_SHAPE")
    return cast(dict[str, object], metric)


def _numeric_flips(record: dict[str, object]) -> dict[str, object]:
    bundle = record.get("metric_bundle")
    flips = bundle.get("pairwise_majority_flips") if type(bundle) is dict else None
    if type(flips) is not dict:
        raise _integrity("SCIENCE.ANALYST_DECISION_METRIC_SHAPE")
    return cast(dict[str, object], flips)


def _distribution_summary(
    values: list[float],
    *,
    metric_id: str,
) -> dict[str, object]:
    if not values:
        return {
            "metric_id": metric_id,
            "status": "NOT_ASSESSABLE",
            "valid_count": 0,
            "median": None,
            "inverse_ecdf_iqr": None,
            "maximum": None,
            "reason_code": "ANALYST_DECISION.NO_INTERPRETIVE_CONTRIBUTORS",
        }
    median = empirical_quantile(values, 0.5)
    lower = empirical_quantile(values, 0.25)
    upper = empirical_quantile(values, 0.75)
    maximum = max(values)
    if (
        median.status != "ASSESSABLE"
        or lower.status != "ASSESSABLE"
        or upper.status != "ASSESSABLE"
        or not isinstance(median.value, float)
        or not isinstance(lower.value, float)
        or not isinstance(upper.value, float)
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_DISTRIBUTION")
    return {
        "metric_id": metric_id,
        "status": "ASSESSABLE",
        "valid_count": len(values),
        "median": median.value,
        "inverse_ecdf_iqr": upper.value - lower.value,
        "maximum": maximum,
        "reason_code": None,
    }


def _aggregate_event_rows(
    records: tuple[dict[str, object], ...],
) -> list[dict[str, object]]:
    by_event: dict[str, tuple[list[float], list[float]]] = {}
    for record in records:
        bundle = record.get("metric_bundle")
        rank_shifts = bundle.get("event_rank_shifts") if type(bundle) is dict else None
        rows = rank_shifts.get("event_rows") if type(rank_shifts) is dict else None
        if type(rows) is not list:
            raise _integrity("SCIENCE.ANALYST_DECISION_RANK_SHIFT_SHAPE")
        for row in rows:
            if (
                type(row) is not dict
                or type(row.get("event_id")) is not str
                or isinstance(row.get("absolute_rank_shift"), bool)
                or not isinstance(row.get("absolute_rank_shift"), (int, float))
                or isinstance(row.get("normalized_rank_shift"), bool)
                or not isinstance(row.get("normalized_rank_shift"), (int, float))
            ):
                raise _integrity("SCIENCE.ANALYST_DECISION_RANK_SHIFT_SHAPE")
            event_id = cast(str, row["event_id"])
            absolute, normalized = by_event.setdefault(event_id, ([], []))
            absolute.append(float(cast(int | float, row["absolute_rank_shift"])))
            normalized.append(float(cast(int | float, row["normalized_rank_shift"])))
    return [
        {
            "event_id": event_id,
            "contributing_count": len(by_event[event_id][0]),
            "absolute_rank_shift": _distribution_summary(
                by_event[event_id][0],
                metric_id="absolute-event-rank-shift/1",
            ),
            "normalized_rank_shift": _distribution_summary(
                by_event[event_id][1],
                metric_id="normalized-event-rank-shift/1",
            ),
        }
        for event_id in sorted(by_event, key=_utf8)
    ]


def _choice_metric_or_absence(
    numeric: dict[str, object],
    field: Literal[
        "position_matrix_distance",
        "pairwise_matrix_distance",
    ],
) -> dict[str, object]:
    return _numeric_metric(numeric, field)


def _analyst_decision_aggregate_preimage(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    experiment_set_id: str,
    axis_id: str,
    rows: _AggregateSourceRows,
) -> dict[str, object]:
    choice_rows: list[dict[str, object]] = []
    interpretive_by_digest: dict[str, dict[str, object]] = {}
    for origin, attempt, numeric in rows:
        choice_id = origin.get("choice_id")
        origin_id = origin.get("origin_id")
        attempt_digest = attempt.get("attempt_digest")
        numeric_digest = numeric.get("numeric_comparison_digest")
        contribution_state = attempt.get("contribution_state")
        if (
            type(choice_id) is not str
            or type(origin_id) is not str
            or type(attempt_digest) is not str
            or type(numeric_digest) is not str
            or contribution_state
            not in {
                "INTERPRETIVE",
                "DESCRIPTIVE_ONLY",
                "METRIC_NOT_ASSESSABLE",
                "FAILED",
            }
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_SOURCE")
        flips = _numeric_flips(numeric)
        flip_count = flips.get("flip_count")
        flip_fraction = flips.get("flip_fraction")
        if type(flip_count) is not dict or type(flip_fraction) is not dict:
            raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_SOURCE")
        choice_rows.append(
            {
                "choice_id": choice_id,
                "origin_id": origin_id,
                "attempt_digest": attempt_digest,
                "numeric_comparison_digest": numeric_digest,
                "contribution_state": contribution_state,
                "strict_flip_count": flip_count,
                "strict_flip_rate": flip_fraction,
                "position_matrix_distance": _choice_metric_or_absence(
                    numeric,
                    "position_matrix_distance",
                ),
                "pairwise_matrix_distance": _choice_metric_or_absence(
                    numeric,
                    "pairwise_matrix_distance",
                ),
            }
        )
        if contribution_state == "INTERPRETIVE":
            previous = interpretive_by_digest.setdefault(numeric_digest, numeric)
            if previous != numeric:
                raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_DEDUPLICATION")
    choice_rows.sort(
        key=lambda row: (
            _utf8(cast(str, row["choice_id"])),
            _utf8(cast(str, row["origin_id"])),
        )
    )
    interpretive = tuple(
        interpretive_by_digest[digest] for digest in sorted(interpretive_by_digest, key=_utf8)
    )
    kendall_values = [
        value
        for record in interpretive
        if (value := _finite_metric_value(_numeric_metric(record, "kendall_distance"))) is not None
    ]
    footrule_values = [
        value
        for record in interpretive
        if (value := _finite_metric_value(_numeric_metric(record, "footrule_distance"))) is not None
    ]
    flip_numerator = 0
    flip_denominator = 0
    pooled_count = 0
    for record in interpretive:
        flips = _numeric_flips(record)
        count = _finite_metric_value(flips.get("flip_count"))
        denominator = flips.get("strict_pairwise_majority_flip_denominator")
        if (
            count is None
            or type(denominator) is not int
            or denominator < 1
            or not count.is_integer()
        ):
            continue
        flip_numerator += int(count)
        flip_denominator += denominator
        pooled_count += 1
    pooled_flips: dict[str, object]
    if pooled_count == 0:
        pooled_flips = {
            "status": "NOT_ASSESSABLE",
            "contributing_numeric_count": 0,
            "numerator": None,
            "exact_common_pair_denominator": None,
            "rate": None,
            "reason_code": "ANALYST_DECISION.NO_INTERPRETIVE_CONTRIBUTORS",
        }
    else:
        pooled_flips = {
            "status": "ASSESSABLE",
            "contributing_numeric_count": pooled_count,
            "numerator": flip_numerator,
            "exact_common_pair_denominator": flip_denominator,
            "rate": flip_numerator / flip_denominator,
            "reason_code": None,
        }
    return {
        "record_schema_version": ANALYST_DECISION_AGGREGATE_SCHEMA_VERSION,
        "evidence_rule_id": ANALYST_DECISION_EVIDENCE_RULE_ID,
        "aggregate_kind": "ONE_AXIS_FAMILY",
        "attribution_semantics": "DESCRIPTIVE_ASSOCIATION",
        "interpretation_phrase": "associated with movement",
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "experiment_set_id": experiment_set_id,
        "axis_id": axis_id,
        "choice_rows": choice_rows,
        "unique_interpretive_numeric_count": len(interpretive),
        "central_order_kendall_summary": _distribution_summary(
            kendall_values,
            metric_id="central-order-kendall-distance/1",
        ),
        "central_order_footrule_summary": _distribution_summary(
            footrule_values,
            metric_id="central-order-footrule-distance/1",
        ),
        "event_rank_shift_rows": _aggregate_event_rows(interpretive),
        "family_pooled_pairwise_flips": pooled_flips,
    }


def _combination_aggregate_preimage(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    experiment_set_id: str,
    experiment_mode: Literal["declared-combinations", "full-factorial"],
    axis_choices: tuple[tuple[str, str], ...],
    rows: _AggregateSourceRows,
) -> dict[str, object]:
    member_rows: list[dict[str, object]] = []
    interpretive_by_digest: dict[str, dict[str, object]] = {}
    contribution_counts: Counter[str] = Counter()
    unavailable_count = 0
    expected_choices = [
        {"axis_id": axis_id, "choice_id": choice_id}
        for axis_id, choice_id in axis_choices
    ]
    for origin, attempt, numeric in rows:
        origin_id = origin.get("origin_id")
        analysis_declaration_id = origin.get("analysis_declaration_id")
        source_declaration_digest = origin.get("source_declaration_digest")
        declaration_ordinal = origin.get("declaration_ordinal")
        attempt_digest = attempt.get("attempt_digest")
        numeric_digest = numeric.get("numeric_comparison_digest")
        numeric_identity = numeric.get("numeric_identity")
        contribution_state = attempt.get("contribution_state")
        if (
            type(origin_id) is not str
            or type(analysis_declaration_id) is not str
            or type(source_declaration_digest) is not str
            or type(declaration_ordinal) is not int
            or isinstance(declaration_ordinal, bool)
            or origin.get("axis_choices") != expected_choices
            or type(attempt_digest) is not str
            or type(numeric_digest) is not str
            or type(numeric_identity) is not dict
            or contribution_state
            not in {
                "INTERPRETIVE",
                "DESCRIPTIVE_ONLY",
                "METRIC_NOT_ASSESSABLE",
                "FAILED",
            }
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_COMBINATION_AGGREGATE_SOURCE")
        contribution_counts[contribution_state] += 1
        if numeric.get("eligibility") == "UNAVAILABLE":
            unavailable_count += 1
        flips = _numeric_flips(numeric)
        member_rows.append(
            {
                "origin_id": origin_id,
                "member_identity": {
                    "analysis_declaration_id": analysis_declaration_id,
                    "source_declaration_digest": source_declaration_digest,
                    "declaration_ordinal": declaration_ordinal,
                },
                "axis_choices": expected_choices,
                "attempt_digest": attempt_digest,
                "numeric_comparison_digest": numeric_digest,
                "numeric_identity": numeric_identity,
                "contribution_state": contribution_state,
                "reason_code": attempt.get("reason_code"),
                "strict_flip_count": flips["flip_count"],
                "strict_flip_rate": flips["flip_fraction"],
                "position_matrix_distance": _numeric_metric(
                    numeric,
                    "position_matrix_distance",
                ),
                "pairwise_matrix_distance": _numeric_metric(
                    numeric,
                    "pairwise_matrix_distance",
                ),
            }
        )
        if contribution_state == "INTERPRETIVE":
            previous = interpretive_by_digest.setdefault(numeric_digest, numeric)
            if previous != numeric:
                raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_DEDUPLICATION")
    member_rows.sort(
        key=lambda row: (
            _utf8(cast(str, row["origin_id"])),
            _utf8(
                cast(
                    str,
                    cast(dict[str, object], row["member_identity"])[
                        "analysis_declaration_id"
                    ],
                )
            ),
        )
    )
    interpretive = tuple(
        interpretive_by_digest[digest]
        for digest in sorted(interpretive_by_digest, key=_utf8)
    )
    kendall_values = [
        value
        for record in interpretive
        if (value := _finite_metric_value(_numeric_metric(record, "kendall_distance")))
        is not None
    ]
    footrule_values = [
        value
        for record in interpretive
        if (value := _finite_metric_value(_numeric_metric(record, "footrule_distance")))
        is not None
    ]
    flip_numerator = 0
    flip_denominator = 0
    pooled_count = 0
    for record in interpretive:
        flips = _numeric_flips(record)
        count = _finite_metric_value(flips.get("flip_count"))
        denominator = flips.get("strict_pairwise_majority_flip_denominator")
        if (
            count is None
            or type(denominator) is not int
            or denominator < 1
            or not count.is_integer()
        ):
            continue
        flip_numerator += int(count)
        flip_denominator += denominator
        pooled_count += 1
    pooled_flips: dict[str, object]
    if pooled_count:
        pooled_flips = {
            "status": "ASSESSABLE",
            "contributing_numeric_count": pooled_count,
            "numerator": flip_numerator,
            "exact_common_pair_denominator": flip_denominator,
            "rate": flip_numerator / flip_denominator,
            "reason_code": None,
        }
    else:
        pooled_flips = {
            "status": "NOT_ASSESSABLE",
            "contributing_numeric_count": 0,
            "numerator": None,
            "exact_common_pair_denominator": None,
            "rate": None,
            "reason_code": "ANALYST_DECISION.NO_INTERPRETIVE_CONTRIBUTORS",
        }
    return {
        "record_schema_version": ANALYST_DECISION_AGGREGATE_SCHEMA_VERSION,
        "evidence_rule_id": ANALYST_DECISION_EVIDENCE_RULE_ID,
        "aggregate_kind": "COMBINATION_FACTORIAL_VECTOR",
        "attribution_semantics": "DESCRIPTIVE_ASSOCIATION",
        "interpretation_phrase": "associated with movement",
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "experiment_set_id": experiment_set_id,
        "experiment_mode": experiment_mode,
        "axis_choices": expected_choices,
        "member_rows": member_rows,
        "denominators": {
            "planned_origin_count": len(member_rows),
            "interpretive_origin_count": contribution_counts["INTERPRETIVE"],
            "descriptive_only_origin_count": contribution_counts["DESCRIPTIVE_ONLY"],
            "metric_not_assessable_origin_count": contribution_counts[
                "METRIC_NOT_ASSESSABLE"
            ],
            "failed_origin_count": contribution_counts["FAILED"],
            "terminal_unavailable_origin_count": unavailable_count,
            "unique_interpretive_numeric_count": len(interpretive),
        },
        "central_order_kendall_summary": _distribution_summary(
            kendall_values,
            metric_id="central-order-kendall-distance/1",
        ),
        "central_order_footrule_summary": _distribution_summary(
            footrule_values,
            metric_id="central-order-footrule-distance/1",
        ),
        "event_rank_shift_rows": _aggregate_event_rows(interpretive),
        "vector_pooled_pairwise_flips": pooled_flips,
    }


def _derive_analyst_decision_aggregate(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    experiment_set_id: str,
    axis_id: str,
    rows: _AggregateSourceRows,
) -> _CanonicalAnalystDecisionAggregate:
    preimage = _analyst_decision_aggregate_preimage(
        plan_digest=plan_digest,
        terminal_index_digest=terminal_index_digest,
        experiment_set_id=experiment_set_id,
        axis_id=axis_id,
        rows=rows,
    )
    digest = structured_sha256(_AGGREGATE_DIGEST_DOMAIN, preimage)
    return _CanonicalAnalystDecisionAggregate(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes({**preimage, "aggregate_digest": digest}),
        aggregate_digest=digest,
    )


def _derive_combination_aggregate(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    experiment_set_id: str,
    experiment_mode: Literal["declared-combinations", "full-factorial"],
    axis_choices: tuple[tuple[str, str], ...],
    rows: _AggregateSourceRows,
) -> _CanonicalAnalystDecisionAggregate:
    preimage = _combination_aggregate_preimage(
        plan_digest=plan_digest,
        terminal_index_digest=terminal_index_digest,
        experiment_set_id=experiment_set_id,
        experiment_mode=experiment_mode,
        axis_choices=axis_choices,
        rows=rows,
    )
    digest = structured_sha256(_AGGREGATE_DIGEST_DOMAIN, preimage)
    return _CanonicalAnalystDecisionAggregate(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes({**preimage, "aggregate_digest": digest}),
        aggregate_digest=digest,
    )


def _aggregate_order_key(record: dict[str, object]) -> bytes:
    kind = record.get("aggregate_kind")
    if kind == "ONE_AXIS_FAMILY":
        key: list[object] = [
            kind,
            record.get("experiment_set_id"),
            record.get("axis_id"),
        ]
    elif kind == "COMBINATION_FACTORIAL_VECTOR":
        choices = record.get("axis_choices")
        vector = tuple(
            (
                cast(str, cast(dict[str, object], choice).get("axis_id")),
                cast(str, cast(dict[str, object], choice).get("choice_id")),
            )
            for choice in cast(list[object], choices)
        )
        key = [
            kind,
            record.get("experiment_set_id"),
            record.get("experiment_mode"),
            [list(choice) for choice in vector],
        ]
    else:
        raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_IDENTITY")
    return canonical_json_bytes(key)


def _aggregate_identity_order_key(key: tuple[object, ...]) -> bytes:
    values = list(key)
    if len(values) == 4 and type(values[3]) is tuple:
        values[3] = [list(cast(tuple[str, str], choice)) for choice in values[3]]
    return canonical_json_bytes(values)


def _combination_source_order_key(
    key: tuple[str, str, tuple[tuple[str, str], ...]],
) -> bytes:
    return canonical_json_bytes(
        [key[0], key[1], [list(choice) for choice in key[2]]]
    )


def _status_partition(
    attempts: tuple[dict[str, object], ...],
    *,
    field: Literal["subject_terminal_status", "comparator_terminal_status"],
) -> list[dict[str, object]]:
    counts = Counter(
        cast(str, attempt[field])
        for attempt in attempts
        if attempt.get("applicability_state")
        in {
            "APPLICABLE_ORDINARY_ONE_AXIS",
            "APPLICABLE_DECLARED_COMBINATION",
            "APPLICABLE_FULL_FACTORIAL",
        }
    )
    return [{"status": status, "count": counts[status]} for status in sorted(counts, key=_utf8)]


def _metric_valid_counts(
    numeric_records: tuple[dict[str, object], ...],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for metric_id, field in _ANALYST_DECISION_METRIC_SPECIFICATIONS:
        valid_count = 0
        for record in numeric_records:
            metric = (
                _numeric_flips(record).get(field)
                if field in {"flip_count", "flip_fraction"}
                else _numeric_metric(
                    record,
                    cast(
                        Literal[
                            "kendall_distance",
                            "footrule_distance",
                            "position_matrix_distance",
                            "pairwise_matrix_distance",
                        ],
                        field,
                    ),
                )
            )
            if _finite_metric_value(metric) is not None:
                valid_count += 1
        rows.append({"metric_id": metric_id, "valid_count": valid_count})
    for metric_id in _ANALYST_DECISION_RANK_SHIFT_METRIC_IDS:
        valid_count = 0
        for record in numeric_records:
            bundle = record.get("metric_bundle")
            shifts = bundle.get("event_rank_shifts") if type(bundle) is dict else None
            if (
                type(shifts) is dict
                and shifts.get("status") == "ASSESSABLE"
                and shifts.get(
                    "absolute_rank_shift_metric_id"
                    if metric_id == "absolute-event-rank-shift/1"
                    else "normalized_rank_shift_metric_id"
                )
                == metric_id
            ):
                valid_count += 1
        rows.append({"metric_id": metric_id, "valid_count": valid_count})
    return rows


def _analyst_decision_accounting(
    attempts: tuple[dict[str, object], ...],
    numeric_records: tuple[dict[str, object], ...],
) -> dict[str, object]:
    applicability_counts = Counter(
        cast(str, attempt["applicability_state"]) for attempt in attempts
    )
    contribution_counts = Counter(
        cast(str, attempt["contribution_state"])
        for attempt in attempts
        if attempt["applicability_state"]
        in {
            "APPLICABLE_ORDINARY_ONE_AXIS",
            "APPLICABLE_DECLARED_COMBINATION",
            "APPLICABLE_FULL_FACTORIAL",
        }
    )
    reference_count = applicability_counts["REFERENCE_ONLY_BASELINE"]
    applicable_count = sum(
        applicability_counts[state]
        for state in (
            "APPLICABLE_ORDINARY_ONE_AXIS",
            "APPLICABLE_DECLARED_COMBINATION",
            "APPLICABLE_FULL_FACTORIAL",
        )
    )
    not_applicable_count = len(attempts) - reference_count - applicable_count
    interpretive_count = contribution_counts["INTERPRETIVE"]
    descriptive_count = contribution_counts["DESCRIPTIVE_ONLY"]
    metric_not_assessable_count = contribution_counts["METRIC_NOT_ASSESSABLE"]
    failed_count = contribution_counts["FAILED"]
    assessable_count = interpretive_count + descriptive_count
    if (
        len(attempts) != reference_count + applicable_count + not_applicable_count
        or applicable_count != assessable_count + metric_not_assessable_count + failed_count
        or assessable_count != interpretive_count + descriptive_count
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_ACCOUNTING")
    return {
        "planned_origin_count": len(attempts),
        "reference_origin_count": reference_count,
        "applicable_origin_count": applicable_count,
        "not_applicable_origin_count": not_applicable_count,
        "assessable_origin_count": assessable_count,
        "interpretive_origin_count": interpretive_count,
        "descriptive_only_origin_count": descriptive_count,
        "metric_not_assessable_origin_count": metric_not_assessable_count,
        "failed_origin_count": failed_count,
        "unique_applicable_numeric_pair_count": len(numeric_records),
        "subject_terminal_status_partition": _status_partition(
            attempts,
            field="subject_terminal_status",
        ),
        "comparator_terminal_status_partition": _status_partition(
            attempts,
            field="comparator_terminal_status",
        ),
        "applicability_state_counts": [
            {"state": state, "count": applicability_counts[state]}
            for state in _ANALYST_DECISION_APPLICABILITY_STATES
        ],
        "per_metric_unique_numeric_valid_counts": _metric_valid_counts(numeric_records),
    }


def _analyst_decision_component_coverage() -> list[dict[str, object]]:
    return [
        {
            "component": component,
            "implementation_status": status,
            "reason_code": reason,
        }
        for component, status, reason in _ANALYST_DECISION_COMPONENT_COVERAGE
    ]


def _analyst_decision_layer_status(
    component_coverage: list[dict[str, object]],
) -> tuple[str, str | None]:
    if component_coverage and all(
        row.get("implementation_status") == "IMPLEMENTED"
        and row.get("reason_code") is None
        for row in component_coverage
    ):
        return "IMPLEMENTED", None
    return "PARTIALLY_IMPLEMENTED", "SCIENCE.ANALYST_DECISION_COMPONENTS_PENDING"


def _analyst_decision_layer_preimage(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    attempts: tuple[dict[str, object], ...],
    numeric_records: tuple[dict[str, object], ...],
    aggregates: tuple[dict[str, object], ...],
) -> dict[str, object]:
    component_coverage = _analyst_decision_component_coverage()
    implementation_status, reason_code = _analyst_decision_layer_status(
        component_coverage
    )
    return {
        "record_schema_version": ANALYST_DECISION_LAYER_SCHEMA_VERSION,
        "layer": "ANALYST_DECISION",
        "evidence_rule_id": ANALYST_DECISION_EVIDENCE_RULE_ID,
        "implementation_status": implementation_status,
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "component_coverage": component_coverage,
        "attempts": list(attempts),
        "numeric_records": list(numeric_records),
        "aggregates": list(aggregates),
        "accounting": _analyst_decision_accounting(attempts, numeric_records),
        "reason_code": reason_code,
    }


def _record_sequence(value: object, *, code: str) -> tuple[dict[str, object], ...]:
    if type(value) is not list or any(type(item) is not dict for item in value):
        raise _integrity(code)
    return tuple(cast(dict[str, object], item) for item in value)


def _record_preimage(
    record: dict[str, object],
    *,
    digest_field: str,
    domain: str,
    code: str,
) -> tuple[dict[str, object], str]:
    preimage = dict(record)
    digest = preimage.pop(digest_field, None)
    if type(digest) is not str or structured_sha256(domain, preimage) != digest:
        raise _integrity(code)
    return preimage, digest


def _string_sequence(value: object, *, code: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise _integrity(code)
    return tuple(cast(str, item) for item in value)


def _numeric_identity_tuple(record: dict[str, object]) -> tuple[str, str, str, str, str, str]:
    identity = record.get("numeric_identity")
    fields = (
        "subject_analysis_spec_id",
        "comparator_analysis_spec_id",
        "subject_result_id",
        "comparator_result_id",
        "subject_candidate_record_digest",
        "comparator_candidate_record_digest",
    )
    if type(identity) is not dict or set(identity) != set(fields):
        raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_IDENTITY")
    values = tuple(identity.get(field) for field in fields)
    if any(type(value) is not str for value in values):
        raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_IDENTITY")
    return cast(tuple[str, str, str, str, str, str], values)


def _bind_candidate_identity(
    registry: dict[str, _CandidateIdentityBinding],
    *,
    analysis_spec_id: object,
    result_id: object,
    universe_id: object,
    terminal_status: object,
    candidate_record_digest: object,
) -> None:
    if (
        type(analysis_spec_id) is not str
        or type(result_id) is not str
        or (universe_id is not None and type(universe_id) is not str)
        or type(terminal_status) is not str
        or type(candidate_record_digest) is not str
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_CANDIDATE_IDENTITY")
    binding: _CandidateIdentityBinding = (
        result_id,
        universe_id,
        terminal_status,
        candidate_record_digest,
    )
    previous = registry.setdefault(analysis_spec_id, binding)
    if previous != binding:
        raise _integrity("SCIENCE.ANALYST_DECISION_CANDIDATE_IDENTITY_CONFLICT")


def _bind_candidate_evidence(
    registry: dict[str, _CandidateEvidenceBinding],
    *,
    analysis_spec_id: str,
    event_ids: tuple[str, ...],
    reference_source: object,
) -> None:
    if reference_source is not None and type(reference_source) is not dict:
        raise _integrity("SCIENCE.ANALYST_DECISION_CANDIDATE_EVIDENCE")
    binding: _CandidateEvidenceBinding = (
        event_ids,
        cast(dict[str, object] | None, reference_source),
    )
    previous = registry.setdefault(analysis_spec_id, binding)
    if previous != binding:
        raise _integrity("SCIENCE.ANALYST_DECISION_CANDIDATE_EVIDENCE_CONFLICT")


def _metric_with_id(
    value: object,
    *,
    metric_id: str,
) -> dict[str, object]:
    if (
        type(value) is not dict
        or value.get("metric_id") != metric_id
        or value.get("status") not in {"ASSESSABLE", "NOT_ASSESSABLE"}
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_METRIC_IDENTITY")
    return cast(dict[str, object], value)


def _expected_rank_shift_bundle(
    subject_modal: tuple[str, ...],
    comparator_modal: tuple[str, ...],
) -> dict[str, object]:
    shifts = per_event_rank_shifts(subject_modal, comparator_modal)
    if shifts.maximum_normalized_rank_shift.status != "ASSESSABLE":
        raise _integrity("SCIENCE.ANALYST_DECISION_RANK_SHIFT_SEMANTICS")
    return {
        "rule_id": "common-event-rank-shift/1",
        "absolute_rank_shift_metric_id": "absolute-event-rank-shift/1",
        "normalized_rank_shift_metric_id": "normalized-event-rank-shift/1",
        "status": "ASSESSABLE",
        "reason_code": shifts.maximum_normalized_rank_shift.reason_code,
        "event_rows": [
            {
                "event_id": shift.event_id,
                "subject_rank": shift.left_rank,
                "comparator_rank": shift.right_rank,
                "absolute_rank_shift": shift.absolute_rank_shift,
                "normalized_rank_shift": shift.normalized_rank_shift,
            }
            for shift in shifts.shifts
        ],
    }


def _strict_relation(value: float) -> str | None:
    if value > 0.5 + METRIC_ABSOLUTE_TOLERANCE:
        return "A_BEFORE_B"
    if value < 0.5 - METRIC_ABSOLUTE_TOLERANCE:
        return "B_BEFORE_A"
    return None


def _validate_assessable_flip_semantics(
    flips: dict[str, object],
    *,
    common_event_ids: tuple[str, ...],
) -> None:
    denominator = flips.get("strict_pairwise_majority_flip_denominator")
    rows = flips.get("flipped_pairs")
    count_metric = cast(dict[str, object], flips["flip_count"])
    fraction_metric = cast(dict[str, object], flips["flip_fraction"])
    expected_denominator = _math_comb(len(common_event_ids), 2)
    if (
        type(denominator) is not int
        or isinstance(denominator, bool)
        or denominator != expected_denominator
        or type(rows) is not list
        or count_metric.get("status") != "ASSESSABLE"
        or fraction_metric.get("status") != "ASSESSABLE"
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_FLIP_ACCOUNTING")
    exact_rows = cast(list[object], rows)
    pairs: list[tuple[str, str]] = []
    common = set(common_event_ids)
    for row in exact_rows:
        if type(row) is not dict:
            raise _integrity("SCIENCE.ANALYST_DECISION_FLIP_ROW")
        event_a = row.get("event_a_id")
        event_b = row.get("event_b_id")
        subject_probability = row.get("subject_probability_a_before_b")
        comparator_probability = row.get("comparator_probability_a_before_b")
        if (
            type(event_a) is not str
            or type(event_b) is not str
            or event_a not in common
            or event_b not in common
            or _utf8(event_a) >= _utf8(event_b)
            or isinstance(subject_probability, bool)
            or not isinstance(subject_probability, (int, float))
            or isinstance(comparator_probability, bool)
            or not isinstance(comparator_probability, (int, float))
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_FLIP_ROW")
        subject_value = float(subject_probability)
        comparator_value = float(comparator_probability)
        subject_relation = _strict_relation(subject_value)
        comparator_relation = _strict_relation(comparator_value)
        if (
            not _math_isfinite(subject_value)
            or not 0.0 <= subject_value <= 1.0
            or not _math_isfinite(comparator_value)
            or not 0.0 <= comparator_value <= 1.0
            or subject_relation is None
            or comparator_relation is None
            or subject_relation == comparator_relation
            or row.get("subject_relation") != subject_relation
            or row.get("comparator_relation") != comparator_relation
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_FLIP_RELATION")
        pairs.append((event_a, event_b))
    if pairs != sorted(set(pairs), key=lambda pair: (_utf8(pair[0]), _utf8(pair[1]))):
        raise _integrity("SCIENCE.ANALYST_DECISION_FLIP_ORDER")
    count = count_metric.get("value")
    fraction = fraction_metric.get("value")
    expected_count = len(exact_rows)
    expected_fraction = expected_count / expected_denominator
    if (
        type(count) is not int
        or isinstance(count, bool)
        or count != expected_count
        or isinstance(fraction, bool)
        or not isinstance(fraction, (int, float))
        or not _math_isfinite(float(fraction))
        or float(fraction) != expected_fraction
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_FLIP_ACCOUNTING")


def _validate_participant_stage_semantics(
    value: object,
    *,
    common_event_ids: tuple[str, ...],
    subject_only_event_ids: tuple[str, ...],
    comparator_only_event_ids: tuple[str, ...],
) -> None:
    try:
        _validate_shared_participant_stage_semantics(
            value,
            common_event_ids=common_event_ids,
            left_only_event_ids=subject_only_event_ids,
            right_only_event_ids=comparator_only_event_ids,
        )
    except (TypeError, ValueError, OverflowError):
        raise _integrity("SCIENCE.ANALYST_DECISION_STAGE_SEMANTICS") from None


def _validate_numeric_semantics(record: dict[str, object]) -> tuple[str, str, str, str, str, str]:
    identity = _numeric_identity_tuple(record)
    subject_status = record.get("subject_terminal_status")
    comparator_status = record.get("comparator_terminal_status")
    if type(subject_status) is not str or type(comparator_status) is not str:
        raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_STATUS")
    eligibility = _combined_eligibility(subject_status, comparator_status)
    if record.get("eligibility") != eligibility:
        raise _integrity("SCIENCE.ANALYST_DECISION_ELIGIBILITY")
    terminal_with_reference_chain = {"SUCCESS", "CONVERGENCE_WARN"}
    subject_reference_source = record.get("subject_reference_chain_source")
    comparator_reference_source = record.get("comparator_reference_chain_source")
    if (type(subject_reference_source) is dict) != (
        subject_status in terminal_with_reference_chain
    ) or (type(comparator_reference_source) is dict) != (
        comparator_status in terminal_with_reference_chain
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_REFERENCE_CHAIN_STATUS")
    common_event_ids = _string_sequence(
        record.get("common_event_ids"),
        code="SCIENCE.ANALYST_DECISION_EVENT_PARTITION",
    )
    subject_only = _string_sequence(
        record.get("subject_only_event_ids"),
        code="SCIENCE.ANALYST_DECISION_EVENT_PARTITION",
    )
    comparator_only = _string_sequence(
        record.get("comparator_only_event_ids"),
        code="SCIENCE.ANALYST_DECISION_EVENT_PARTITION",
    )
    if (
        common_event_ids != tuple(sorted(set(common_event_ids), key=_utf8))
        or subject_only != tuple(sorted(set(subject_only), key=_utf8))
        or comparator_only != tuple(sorted(set(comparator_only), key=_utf8))
        or not (common_event_ids or subject_only)
        or not (common_event_ids or comparator_only)
        or set(common_event_ids) & set(subject_only)
        or set(common_event_ids) & set(comparator_only)
        or set(subject_only) & set(comparator_only)
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_EVENT_PARTITION")
    _validate_participant_stage_semantics(
        record.get("participant_stage_comparison"),
        common_event_ids=common_event_ids,
        subject_only_event_ids=subject_only,
        comparator_only_event_ids=comparator_only,
    )
    subject_modal = _string_sequence(
        record.get("subject_projected_modal_order_event_ids"),
        code="SCIENCE.ANALYST_DECISION_MODAL_ORDER",
    )
    comparator_modal = _string_sequence(
        record.get("comparator_projected_modal_order_event_ids"),
        code="SCIENCE.ANALYST_DECISION_MODAL_ORDER",
    )
    self_pair = identity[0] == identity[1]
    if self_pair and (
        identity[2] != identity[3]
        or identity[4] != identity[5]
        or record.get("subject_universe_id") != record.get("comparator_universe_id")
        or subject_status != comparator_status
        or subject_reference_source != comparator_reference_source
        or subject_only
        or comparator_only
        or subject_modal != comparator_modal
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_SELF_PAIR_IDENTITY")
    bundle = record.get("metric_bundle")
    if (
        type(bundle) is not dict
        or bundle.get("projection_rule_id") != "project-every-retained-reference-chain-sample/1"
        or bundle.get("central_order_rule_id") != "retained-state-mode-utf8-tie-break/1"
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_METRIC_BUNDLE")
    kendall = _metric_with_id(
        bundle.get("kendall_distance"),
        metric_id="central-order-kendall-distance/1",
    )
    footrule = _metric_with_id(
        bundle.get("footrule_distance"),
        metric_id="central-order-footrule-distance/1",
    )
    position_distance = _metric_with_id(
        bundle.get("position_matrix_distance"),
        metric_id="position-matrix-distance/1",
    )
    pairwise_distance = _metric_with_id(
        bundle.get("pairwise_matrix_distance"),
        metric_id="pairwise-matrix-distance/1",
    )
    rank_shifts = bundle.get("event_rank_shifts")
    flips = bundle.get("pairwise_majority_flips")
    if (
        type(rank_shifts) is not dict
        or rank_shifts.get("rule_id") != "common-event-rank-shift/1"
        or rank_shifts.get("absolute_rank_shift_metric_id") != "absolute-event-rank-shift/1"
        or rank_shifts.get("normalized_rank_shift_metric_id") != "normalized-event-rank-shift/1"
        or type(flips) is not dict
        or flips.get("rule_id") != "strict-pairwise-majority-flips/1"
        or flips.get("denominator_rule_id") != "unordered-common-event-pairs/1"
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_METRIC_BUNDLE")
    flip_count = _metric_with_id(
        flips.get("flip_count"),
        metric_id="strict-pairwise-majority-flip-count/1",
    )
    flip_fraction = _metric_with_id(
        flips.get("flip_fraction"),
        metric_id="strict-pairwise-majority-flip-fraction/1",
    )
    if eligibility == "UNAVAILABLE":
        absent_reason = "ANALYST_DECISION.TERMINAL_UNAVAILABLE"
        expected_rank: dict[str, object] = {
            "rule_id": "common-event-rank-shift/1",
            "absolute_rank_shift_metric_id": "absolute-event-rank-shift/1",
            "normalized_rank_shift_metric_id": "normalized-event-rank-shift/1",
            "status": "NOT_ASSESSABLE",
            "reason_code": absent_reason,
            "event_rows": [],
        }
        expected_flips: dict[str, object] = {
            "rule_id": "strict-pairwise-majority-flips/1",
            "denominator_rule_id": "unordered-common-event-pairs/1",
            "strict_pairwise_majority_flip_denominator": None,
            "flipped_pairs": [],
            "flip_count": _numeric_absence_scalar(
                "strict-pairwise-majority-flip-count/1",
                absent_reason,
            ),
            "flip_fraction": _numeric_absence_scalar(
                "strict-pairwise-majority-flip-fraction/1",
                absent_reason,
            ),
        }
        if (
            subject_modal
            or comparator_modal
            or kendall != _numeric_absence_scalar("central-order-kendall-distance/1", absent_reason)
            or footrule
            != _numeric_absence_scalar("central-order-footrule-distance/1", absent_reason)
            or position_distance
            != _numeric_absence_scalar("position-matrix-distance/1", absent_reason)
            or pairwise_distance
            != _numeric_absence_scalar("pairwise-matrix-distance/1", absent_reason)
            or rank_shifts != expected_rank
            or flips != expected_flips
            or record.get("numeric_status") != "TERMINAL_UNAVAILABLE"
            or record.get("reason_code") != absent_reason
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_TERMINAL_NUMERIC")
        return identity
    if type(subject_reference_source) is not dict or type(comparator_reference_source) is not dict:
        raise _integrity("SCIENCE.ANALYST_DECISION_REFERENCE_CHAIN_REQUIRED")
    if len(common_event_ids) < 2:
        order_reason = "ORDER.FEWER_THAN_TWO_COMMON_EVENTS"
        pair_reason = "PAIRWISE.FEWER_THAN_TWO_COMMON_EVENTS"
        expected_rank = {
            "rule_id": "common-event-rank-shift/1",
            "absolute_rank_shift_metric_id": "absolute-event-rank-shift/1",
            "normalized_rank_shift_metric_id": "normalized-event-rank-shift/1",
            "status": "NOT_ASSESSABLE",
            "reason_code": order_reason,
            "event_rows": [],
        }
        expected_flips = {
            "rule_id": "strict-pairwise-majority-flips/1",
            "denominator_rule_id": "unordered-common-event-pairs/1",
            "strict_pairwise_majority_flip_denominator": None,
            "flipped_pairs": [],
            "flip_count": _numeric_absence_scalar(
                "strict-pairwise-majority-flip-count/1",
                pair_reason,
            ),
            "flip_fraction": _numeric_absence_scalar(
                "strict-pairwise-majority-flip-fraction/1",
                pair_reason,
            ),
        }
        if (
            subject_modal
            or comparator_modal
            or kendall != _numeric_absence_scalar("central-order-kendall-distance/1", order_reason)
            or footrule
            != _numeric_absence_scalar("central-order-footrule-distance/1", order_reason)
            or position_distance
            != _numeric_absence_scalar(
                "position-matrix-distance/1",
                "POSITION.FEWER_THAN_TWO_COMMON_EVENTS",
            )
            or pairwise_distance
            != _numeric_absence_scalar("pairwise-matrix-distance/1", pair_reason)
            or rank_shifts != expected_rank
            or flips != expected_flips
            or record.get("numeric_status") != "NOT_ASSESSABLE"
            or record.get("reason_code") != "ANALYST_DECISION.FEWER_THAN_TWO_COMMON_EVENTS"
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_UNASSESSABLE_NUMERIC")
        return identity
    common = set(common_event_ids)
    if (
        len(subject_modal) != len(common_event_ids)
        or set(subject_modal) != common
        or len(comparator_modal) != len(common_event_ids)
        or set(comparator_modal) != common
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_MODAL_ORDER")
    order_comparison = strict_order_comparison(subject_modal, comparator_modal)
    if (
        kendall
        != _scalar(
            order_comparison.kendall_distance,
            metric_id="central-order-kendall-distance/1",
        )
        or footrule
        != _scalar(
            order_comparison.footrule_distance,
            metric_id="central-order-footrule-distance/1",
        )
        or rank_shifts != _expected_rank_shift_bundle(subject_modal, comparator_modal)
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_ORDER_METRICS")
    for metric in (position_distance, pairwise_distance):
        value = _finite_metric_value(metric)
        if value is None or not 0.0 <= value <= 1.0:
            raise _integrity("SCIENCE.ANALYST_DECISION_MATRIX_METRICS")
    _validate_assessable_flip_semantics(
        flips,
        common_event_ids=common_event_ids,
    )
    if self_pair:
        self_pair_values = (
            _finite_metric_value(kendall),
            _finite_metric_value(footrule),
            _finite_metric_value(position_distance),
            _finite_metric_value(pairwise_distance),
            _finite_metric_value(flip_count),
            _finite_metric_value(flip_fraction),
        )
        if any(value != 0.0 for value in self_pair_values) or flips.get("flipped_pairs") != []:
            raise _integrity("SCIENCE.ANALYST_DECISION_SELF_PAIR_NUMERIC")
    numeric_status = _numeric_metric_status(
        (
            kendall,
            footrule,
            position_distance,
            pairwise_distance,
            flip_count,
            flip_fraction,
        )
    )
    if record.get("numeric_status") != numeric_status or record.get("reason_code") != (
        None if numeric_status == "FULLY_ASSESSABLE" else "ANALYST_DECISION.PARTIAL_METRIC_COVERAGE"
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_STATUS")
    return identity


def _validate_attempt_semantics(
    attempt: dict[str, object],
    *,
    numeric_by_digest: dict[str, dict[str, object]],
) -> str | None:
    applicability = attempt.get("applicability_state")
    mode = attempt.get("experiment_mode")
    edge = attempt.get("comparison_edge")
    origin_id = attempt.get("origin_id")
    subject_id = attempt.get("subject_analysis_spec_id")
    comparator_id = attempt.get("comparator_analysis_spec_id")
    if (
        applicability not in _ANALYST_DECISION_APPLICABILITY_STATES
        or type(mode) is not str
        or type(edge) is not dict
        or type(origin_id) is not str
        or type(subject_id) is not str
        or type(comparator_id) is not str
        or edge.get("origin_id") != origin_id
        or edge.get("subject_analysis_spec_id") != subject_id
        or edge.get("comparator_analysis_spec_id") != comparator_id
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_ATTEMPT_IDENTITY")
    mode_rules = {
        "REFERENCE_ONLY_BASELINE": ("baseline", "baseline-origin-self/1"),
        "APPLICABLE_ORDINARY_ONE_AXIS": (
            "one-axis",
            "ordinary-origin-to-plan-baseline/1",
        ),
        "APPLICABLE_DECLARED_COMBINATION": (
            "declared-combinations",
            "ordinary-origin-to-plan-baseline/1",
        ),
        "APPLICABLE_FULL_FACTORIAL": (
            "full-factorial",
            "ordinary-origin-to-plan-baseline/1",
        ),
        "NOT_APPLICABLE_BOOTSTRAP": ("bootstrap", "derived-origin-to-source/1"),
        "NOT_APPLICABLE_SUBSAMPLE": ("subsample", "derived-origin-to-source/1"),
        "NOT_APPLICABLE_INFLUENCE": ("influence", "derived-origin-to-source/1"),
        "NOT_APPLICABLE_NULL": ("null", "derived-origin-to-source/1"),
        "NOT_APPLICABLE_CUSTOM": (
            "custom",
            "ordinary-origin-to-plan-baseline/1",
        ),
    }
    expected_mode, expected_rule = mode_rules[applicability]
    if mode != expected_mode or edge.get("derivation_rule_id") != expected_rule:
        raise _integrity("SCIENCE.ANALYST_DECISION_ATTEMPT_APPLICABILITY")
    choices = attempt.get("axis_choices")
    if (
        type(choices) is not list
        or any(
            type(choice) is not dict
            or set(choice) != {"axis_id", "choice_id"}
            or type(choice.get("axis_id")) is not str
            or type(choice.get("choice_id")) is not str
            for choice in choices
        )
        or choices
        != sorted(
            choices,
            key=lambda choice: (
                _utf8(cast(str, choice["axis_id"])),
                _utf8(cast(str, choice["choice_id"])),
            ),
        )
        or len({cast(str, choice["axis_id"]) for choice in choices}) != len(choices)
        or attempt.get("attribution_semantics") != "DESCRIPTIVE_ASSOCIATION"
        or attempt.get("interpretation_phrase") != "associated with movement"
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_ATTEMPT_VECTOR")
    analysis_declaration_id = attempt.get("analysis_declaration_id")
    experiment_set_id = attempt.get("experiment_set_id")
    declaration_ordinal = attempt.get("declaration_ordinal")
    source_declaration_digest = attempt.get("source_declaration_digest")
    if (
        type(analysis_declaration_id) is not str
        or type(experiment_set_id) is not str
        or type(declaration_ordinal) is not int
        or isinstance(declaration_ordinal, bool)
        or not 0 <= declaration_ordinal <= 9007199254740991
        or type(source_declaration_digest) is not str
        or origin_id
        != structured_sha256(
            _ORIGIN_ID_DOMAIN,
            {
                "analysis_declaration_id": analysis_declaration_id,
                "experiment_set_id": experiment_set_id,
                "experiment_mode": mode,
                "declaration_ordinal": declaration_ordinal,
                "axis_choices": choices,
                "source_declaration_digest": source_declaration_digest,
            },
        )
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_ATTEMPT_ORIGIN_IDENTITY")
    numeric_digest = attempt.get("numeric_comparison_digest")
    if applicability not in _ANALYST_DECISION_APPLICABLE_STATES:
        expected_reason = (
            "ANALYST_DECISION.REFERENCE_BASELINE"
            if applicability == "REFERENCE_ONLY_BASELINE"
            else f"ANALYST_DECISION.{applicability}"
        )
        baseline_self_pairs = (
            (
                attempt.get("subject_result_id"),
                attempt.get("comparator_result_id"),
            ),
            (
                attempt.get("subject_universe_id"),
                attempt.get("comparator_universe_id"),
            ),
            (
                attempt.get("subject_terminal_status"),
                attempt.get("comparator_terminal_status"),
            ),
            (
                attempt.get("subject_candidate_record_digest"),
                attempt.get("comparator_candidate_record_digest"),
            ),
        )
        baseline_semantics = {
            "order_event_alignment": "identical-event-set",
            "native_stage_comparability": "comparable",
        }
        if (
            numeric_digest is not None
            or choices
            or attempt.get("axis_id") is not None
            or attempt.get("choice_id") is not None
            or attempt.get("contribution_state") != "NOT_CONTRIBUTING"
            or attempt.get("reason_code") != expected_reason
            or (applicability == "REFERENCE_ONLY_BASELINE" and subject_id != comparator_id)
            or (
                applicability == "REFERENCE_ONLY_BASELINE"
                and (
                    any(left != right for left, right in baseline_self_pairs)
                    or edge.get("semantics") != baseline_semantics
                )
            )
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_NONCONTRIBUTING_ATTEMPT")
        return None
    if type(numeric_digest) is not str:
        raise _integrity("SCIENCE.ANALYST_DECISION_APPLICABLE_ATTEMPT")
    if applicability == "APPLICABLE_ORDINARY_ONE_AXIS":
        if (
            len(choices) != 1
            or attempt.get("axis_id") != choices[0]["axis_id"]
            or attempt.get("choice_id") != choices[0]["choice_id"]
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_APPLICABLE_ATTEMPT")
    elif (
        len(choices) < 2
        or attempt.get("axis_id") is not None
        or attempt.get("choice_id") is not None
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_APPLICABLE_ATTEMPT")
    numeric = numeric_by_digest.get(numeric_digest)
    if numeric is None:
        raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_REFERENCE")
    identity = _numeric_identity_tuple(numeric)
    exact_pairs = (
        (attempt.get("subject_analysis_spec_id"), identity[0]),
        (attempt.get("comparator_analysis_spec_id"), identity[1]),
        (attempt.get("subject_result_id"), identity[2]),
        (attempt.get("comparator_result_id"), identity[3]),
        (attempt.get("subject_candidate_record_digest"), identity[4]),
        (attempt.get("comparator_candidate_record_digest"), identity[5]),
        (attempt.get("subject_universe_id"), numeric.get("subject_universe_id")),
        (attempt.get("comparator_universe_id"), numeric.get("comparator_universe_id")),
        (attempt.get("subject_terminal_status"), numeric.get("subject_terminal_status")),
        (
            attempt.get("comparator_terminal_status"),
            numeric.get("comparator_terminal_status"),
        ),
    )
    contribution_state, reason = _numeric_contribution_state(numeric)
    subject_only_event_ids = numeric.get("subject_only_event_ids")
    comparator_only_event_ids = numeric.get("comparator_only_event_ids")
    if type(subject_only_event_ids) is not list or type(comparator_only_event_ids) is not list:
        raise _integrity("SCIENCE.ANALYST_DECISION_EVENT_ALIGNMENT")
    expected_alignment = (
        "identical-event-set"
        if not subject_only_event_ids and not comparator_only_event_ids
        else "common-event-only"
    )
    semantics = edge.get("semantics")
    if (
        any(left != right for left, right in exact_pairs)
        or attempt.get("contribution_state") != contribution_state
        or attempt.get("reason_code") != reason
        or type(semantics) is not dict
        or semantics.get("order_event_alignment") != expected_alignment
        or (
            expected_alignment == "common-event-only"
            and semantics.get("native_stage_comparability") != "non-equivalent"
        )
        or (
            subject_id == comparator_id
            and semantics.get("native_stage_comparability") != "comparable"
        )
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_ATTEMPT_NUMERIC_IDENTITY")
    return numeric_digest


def _validate_analyst_decision_semantics_impl(layer: dict[str, object]) -> None:
    layer_preimage, _ = _record_preimage(
        layer,
        digest_field="layer_digest",
        domain=_LAYER_DIGEST_DOMAIN,
        code="SCIENCE.ANALYST_DECISION_LAYER_DIGEST",
    )
    attempts = _record_sequence(
        layer.get("attempts"),
        code="SCIENCE.ANALYST_DECISION_ATTEMPT_RECORD",
    )
    numeric_records = _record_sequence(
        layer.get("numeric_records"),
        code="SCIENCE.ANALYST_DECISION_NUMERIC_RECORD",
    )
    aggregates = _record_sequence(
        layer.get("aggregates"),
        code="SCIENCE.ANALYST_DECISION_AGGREGATE_RECORD",
    )
    plan_digest = layer.get("plan_digest")
    terminal_index_digest = layer.get("terminal_index_digest")
    if type(plan_digest) is not str or type(terminal_index_digest) is not str:
        raise _integrity("SCIENCE.ANALYST_DECISION_RUN_IDENTITY")
    shared_identity = (
        ANALYST_DECISION_EVIDENCE_RULE_ID,
        plan_digest,
        terminal_index_digest,
    )
    numeric_by_digest: dict[str, dict[str, object]] = {}
    numeric_pairs: list[tuple[str, str]] = []
    numeric_full_identities: set[tuple[str, str, str, str, str, str]] = set()
    candidate_identities: dict[str, _CandidateIdentityBinding] = {}
    candidate_evidence: dict[str, _CandidateEvidenceBinding] = {}
    for record in numeric_records:
        _, digest = _record_preimage(
            record,
            digest_field="numeric_comparison_digest",
            domain=_NUMERIC_DIGEST_DOMAIN,
            code="SCIENCE.ANALYST_DECISION_NUMERIC_DIGEST",
        )
        if (
            record.get("record_schema_version") != ORIGIN_NUMERIC_COMPARISON_SCHEMA_VERSION
            or (
                record.get("evidence_rule_id"),
                record.get("plan_digest"),
                record.get("terminal_index_digest"),
            )
            != shared_identity
            or digest in numeric_by_digest
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_IDENTITY")
        identity = _validate_numeric_semantics(record)
        pair = identity[:2]
        if identity in numeric_full_identities or pair in numeric_pairs:
            raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_IDENTITY")
        numeric_full_identities.add(identity)
        numeric_pairs.append(pair)
        numeric_by_digest[digest] = record
        _bind_candidate_identity(
            candidate_identities,
            analysis_spec_id=identity[0],
            result_id=identity[2],
            universe_id=record.get("subject_universe_id"),
            terminal_status=record.get("subject_terminal_status"),
            candidate_record_digest=identity[4],
        )
        _bind_candidate_identity(
            candidate_identities,
            analysis_spec_id=identity[1],
            result_id=identity[3],
            universe_id=record.get("comparator_universe_id"),
            terminal_status=record.get("comparator_terminal_status"),
            candidate_record_digest=identity[5],
        )
        common_event_ids = _string_sequence(
            record.get("common_event_ids"),
            code="SCIENCE.ANALYST_DECISION_EVENT_PARTITION",
        )
        subject_event_ids = tuple(
            sorted(
                (
                    *common_event_ids,
                    *_string_sequence(
                        record.get("subject_only_event_ids"),
                        code="SCIENCE.ANALYST_DECISION_EVENT_PARTITION",
                    ),
                ),
                key=_utf8,
            )
        )
        comparator_event_ids = tuple(
            sorted(
                (
                    *common_event_ids,
                    *_string_sequence(
                        record.get("comparator_only_event_ids"),
                        code="SCIENCE.ANALYST_DECISION_EVENT_PARTITION",
                    ),
                ),
                key=_utf8,
            )
        )
        _bind_candidate_evidence(
            candidate_evidence,
            analysis_spec_id=identity[0],
            event_ids=subject_event_ids,
            reference_source=record.get("subject_reference_chain_source"),
        )
        _bind_candidate_evidence(
            candidate_evidence,
            analysis_spec_id=identity[1],
            event_ids=comparator_event_ids,
            reference_source=record.get("comparator_reference_chain_source"),
        )
    if numeric_pairs != sorted(numeric_pairs, key=lambda pair: (_utf8(pair[0]), _utf8(pair[1]))):
        raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_ORDER")
    attempt_origins: list[str] = []
    referenced_numeric: set[str] = set()
    aggregate_sources: dict[tuple[str, str], list[_AggregateSourceRow]] = {}
    combination_aggregate_sources: dict[
        tuple[str, str, tuple[tuple[str, str], ...]],
        list[_AggregateSourceRow],
    ] = {}
    combination_axis_sets: dict[tuple[str, str], tuple[str, ...]] = {}
    experiment_modes: dict[str, str] = {}
    combination_vectors: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()
    baseline_analysis_ids: list[str] = []
    ordinary_comparator_ids: list[str] = []
    for attempt in attempts:
        _record_preimage(
            attempt,
            digest_field="attempt_digest",
            domain=_ATTEMPT_DIGEST_DOMAIN,
            code="SCIENCE.ANALYST_DECISION_ATTEMPT_DIGEST",
        )
        origin_id = attempt.get("origin_id")
        if (
            attempt.get("record_schema_version") != ORIGIN_COMPARISON_ATTEMPT_SCHEMA_VERSION
            or (
                attempt.get("evidence_rule_id"),
                attempt.get("plan_digest"),
                attempt.get("terminal_index_digest"),
            )
            != shared_identity
            or type(origin_id) is not str
            or origin_id in attempt_origins
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_ATTEMPT_IDENTITY")
        attempt_origins.append(origin_id)
        numeric_digest = _validate_attempt_semantics(
            attempt,
            numeric_by_digest=numeric_by_digest,
        )
        _bind_candidate_identity(
            candidate_identities,
            analysis_spec_id=attempt.get("subject_analysis_spec_id"),
            result_id=attempt.get("subject_result_id"),
            universe_id=attempt.get("subject_universe_id"),
            terminal_status=attempt.get("subject_terminal_status"),
            candidate_record_digest=attempt.get("subject_candidate_record_digest"),
        )
        _bind_candidate_identity(
            candidate_identities,
            analysis_spec_id=attempt.get("comparator_analysis_spec_id"),
            result_id=attempt.get("comparator_result_id"),
            universe_id=attempt.get("comparator_universe_id"),
            terminal_status=attempt.get("comparator_terminal_status"),
            candidate_record_digest=attempt.get("comparator_candidate_record_digest"),
        )
        edge = cast(dict[str, object], attempt["comparison_edge"])
        if attempt.get("applicability_state") == "REFERENCE_ONLY_BASELINE":
            baseline_analysis_ids.append(cast(str, attempt["subject_analysis_spec_id"]))
        if edge.get("derivation_rule_id") == "ordinary-origin-to-plan-baseline/1":
            ordinary_comparator_ids.append(cast(str, attempt["comparator_analysis_spec_id"]))
        if numeric_digest is None:
            continue
        referenced_numeric.add(numeric_digest)
        experiment_set_id = attempt.get("experiment_set_id")
        mode = attempt.get("experiment_mode")
        choices = attempt.get("axis_choices")
        if type(experiment_set_id) is not str or type(mode) is not str or type(choices) is not list:
            raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_SOURCE")
        previous_mode = experiment_modes.setdefault(experiment_set_id, mode)
        if previous_mode != mode:
            raise _integrity("SCIENCE.ANALYST_DECISION_CROSS_MODE_VECTOR")
        if attempt.get("applicability_state") == "APPLICABLE_ORDINARY_ONE_AXIS":
            axis_id = attempt.get("axis_id")
            choice_id = attempt.get("choice_id")
            if type(axis_id) is not str or type(choice_id) is not str:
                raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_SOURCE")
            source_origin: dict[str, object] = {
                "experiment_set_id": experiment_set_id,
                "axis_id": axis_id,
                "choice_id": choice_id,
                "origin_id": origin_id,
            }
            aggregate_sources.setdefault((experiment_set_id, axis_id), []).append(
                (source_origin, attempt, numeric_by_digest[numeric_digest])
            )
        else:
            vector = tuple(
                (
                    cast(str, cast(dict[str, object], choice)["axis_id"]),
                    cast(str, cast(dict[str, object], choice)["choice_id"]),
                )
                for choice in choices
            )
            vector_key = (experiment_set_id, mode, vector)
            if vector_key in combination_vectors:
                raise _integrity("SCIENCE.ANALYST_DECISION_DUPLICATE_VECTOR")
            combination_vectors.add(vector_key)
            axis_set = tuple(axis_id for axis_id, _choice_id in vector)
            scope = (experiment_set_id, mode)
            previous_axes = combination_axis_sets.setdefault(scope, axis_set)
            if previous_axes != axis_set:
                raise _integrity("SCIENCE.ANALYST_DECISION_PARTIAL_VECTOR")
            source_origin = {
                "origin_id": origin_id,
                "analysis_declaration_id": attempt["analysis_declaration_id"],
                "source_declaration_digest": attempt["source_declaration_digest"],
                "declaration_ordinal": attempt["declaration_ordinal"],
                "axis_choices": choices,
            }
            combination_aggregate_sources.setdefault(vector_key, []).append(
                (source_origin, attempt, numeric_by_digest[numeric_digest])
            )
    if len(baseline_analysis_ids) != 1 or any(
        comparator_id != baseline_analysis_ids[0] for comparator_id in ordinary_comparator_ids
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_BASELINE_REFERENCE")
    if attempt_origins != sorted(attempt_origins, key=_utf8) or referenced_numeric != set(
        numeric_by_digest
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_REFERENCE_CLOSURE")
    aggregate_preimages: list[dict[str, object]] = []
    aggregate_keys: list[tuple[object, ...]] = []
    for aggregate in aggregates:
        preimage, _ = _record_preimage(
            aggregate,
            digest_field="aggregate_digest",
            domain=_AGGREGATE_DIGEST_DOMAIN,
            code="SCIENCE.ANALYST_DECISION_AGGREGATE_DIGEST",
        )
        aggregate_kind = aggregate.get("aggregate_kind")
        experiment_set_id = aggregate.get("experiment_set_id")
        if type(experiment_set_id) is not str:
            raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_IDENTITY")
        if aggregate_kind == "ONE_AXIS_FAMILY":
            axis_id = aggregate.get("axis_id")
            if type(axis_id) is not str:
                raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_IDENTITY")
            key: tuple[object, ...] = ("ONE_AXIS_FAMILY", experiment_set_id, axis_id)
        elif aggregate_kind == "COMBINATION_FACTORIAL_VECTOR":
            mode = aggregate.get("experiment_mode")
            choices = aggregate.get("axis_choices")
            if (
                mode not in {"declared-combinations", "full-factorial"}
                or type(choices) is not list
                or any(
                    type(choice) is not dict
                    or type(choice.get("axis_id")) is not str
                    or type(choice.get("choice_id")) is not str
                    for choice in choices
                )
            ):
                raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_IDENTITY")
            vector = tuple(
                (
                    cast(str, cast(dict[str, object], choice)["axis_id"]),
                    cast(str, cast(dict[str, object], choice)["choice_id"]),
                )
                for choice in choices
            )
            key = ("COMBINATION_FACTORIAL_VECTOR", experiment_set_id, mode, vector)
        else:
            raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_IDENTITY")
        if key in aggregate_keys:
            raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_IDENTITY")
        aggregate_keys.append(key)
        aggregate_preimages.append(preimage)
    expected_keys: list[tuple[object, ...]] = [
        ("ONE_AXIS_FAMILY", experiment_set_id, axis_id)
        for experiment_set_id, axis_id in aggregate_sources
    ]
    expected_keys.extend(
        ("COMBINATION_FACTORIAL_VECTOR", experiment_set_id, mode, vector)
        for experiment_set_id, mode, vector in combination_aggregate_sources
    )
    expected_keys.sort(key=_aggregate_identity_order_key)
    if aggregate_keys != expected_keys:
        raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_ORDER")
    for key, supplied_preimage in zip(
        expected_keys,
        aggregate_preimages,
        strict=True,
    ):
        if key[0] == "ONE_AXIS_FAMILY":
            one_axis_key = (cast(str, key[1]), cast(str, key[2]))
            expected_preimage = _analyst_decision_aggregate_preimage(
                plan_digest=plan_digest,
                terminal_index_digest=terminal_index_digest,
                experiment_set_id=one_axis_key[0],
                axis_id=one_axis_key[1],
                rows=tuple(aggregate_sources[one_axis_key]),
            )
        else:
            combination_key = (
                cast(str, key[1]),
                cast(str, key[2]),
                cast(tuple[tuple[str, str], ...], key[3]),
            )
            expected_preimage = _combination_aggregate_preimage(
                plan_digest=plan_digest,
                terminal_index_digest=terminal_index_digest,
                experiment_set_id=combination_key[0],
                experiment_mode=cast(
                    Literal["declared-combinations", "full-factorial"],
                    combination_key[1],
                ),
                axis_choices=combination_key[2],
                rows=tuple(combination_aggregate_sources[combination_key]),
            )
        if supplied_preimage != expected_preimage:
            raise _integrity("SCIENCE.ANALYST_DECISION_AGGREGATE_SEMANTICS")
    expected_layer = _analyst_decision_layer_preimage(
        plan_digest=plan_digest,
        terminal_index_digest=terminal_index_digest,
        attempts=attempts,
        numeric_records=numeric_records,
        aggregates=aggregates,
    )
    if layer_preimage != expected_layer:
        raise _integrity("SCIENCE.ANALYST_DECISION_LAYER_SEMANTICS")


def _validate_analyst_decision_semantics(layer: dict[str, object]) -> None:
    """Fail closed unless a decoded privacy-safe layer is semantically self-consistent.

    The privacy-safe layer deliberately omits retained order samples and derived
    position/pairwise matrices.  Correspondence of those lower-level values to
    source-chain science is therefore enforced by the frozen derivation graph
    and exact readback rederivation, not reconstructed from this projection.
    """

    if type(layer) is not dict:
        raise _integrity("SCIENCE.ANALYST_DECISION_LAYER_SHAPE")
    try:
        _validate_analyst_decision_semantics_impl(layer)
    except _ScientificRecordIntegrityError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError):
        raise _integrity("SCIENCE.ANALYST_DECISION_LAYER_SEMANTICS") from None


def _validate_analyst_candidate_inputs(
    candidates: tuple[_AnalystDecisionCandidateInput, ...],
    *,
    baseline_analysis_spec_id: str,
) -> None:
    if (
        not candidates
        or type(baseline_analysis_spec_id) is not str
        or [candidate.candidate_ordinal for candidate in candidates] != list(range(len(candidates)))
        or len({candidate.candidate_id for candidate in candidates}) != len(candidates)
        or len({candidate.analysis_spec_id for candidate in candidates}) != len(candidates)
        or sum(candidate.analysis_spec_id == baseline_analysis_spec_id for candidate in candidates)
        != 1
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_CANDIDATE_IDENTITY")
    for candidate in candidates:
        if (
            type(candidate.candidate_id) is not str
            or type(candidate.analysis_spec_id) is not str
            or candidate.candidate_id != candidate.analysis_spec_id
            or type(candidate.result_id) is not str
            or (candidate.universe_id is not None and type(candidate.universe_id) is not str)
            or type(candidate.final_status) is not str
            or type(candidate.candidate_record_digest) is not str
            or type(candidate.operation_kind) is not str
            or not candidate.event_ids
            or any(type(event_id) is not str for event_id in candidate.event_ids)
            or len(set(candidate.event_ids)) != len(candidate.event_ids)
            or not candidate.origins
            or (
                candidate.final_status in {"SUCCESS", "CONVERGENCE_WARN"}
                and candidate.reference_chain is None
            )
            or (
                candidate.final_status not in {"SUCCESS", "CONVERGENCE_WARN"}
                and candidate.reference_chain is not None
            )
        ):
            raise _integrity("SCIENCE.ANALYST_DECISION_CANDIDATE_IDENTITY")


def _derive_analyst_decision_evidence(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    baseline_analysis_spec_id: str,
    candidates: tuple[_AnalystDecisionCandidateInput, ...],
) -> _CanonicalAnalystDecisionEvidenceBundle:
    """Derive the closed ordinary-origin analyst-decision evidence layer."""

    if type(plan_digest) is not str or type(terminal_index_digest) is not str:
        raise _integrity("SCIENCE.ANALYST_DECISION_RUN_IDENTITY")
    _validate_analyst_candidate_inputs(
        candidates,
        baseline_analysis_spec_id=baseline_analysis_spec_id,
    )
    candidate_by_analysis = {candidate.analysis_spec_id: candidate for candidate in candidates}
    contexts: list[
        tuple[
            dict[str, object],
            dict[str, object],
            _AnalystDecisionCandidateInput,
            _AnalystDecisionCandidateInput,
            dict[str, object],
            _ApplicabilityState,
            str | None,
            str | None,
        ]
    ] = []
    observed_origin_ids: set[str] = set()
    for subject in candidates:
        for retained in subject.origins:
            if type(retained) is not _AnalystDecisionOriginInput:
                raise _integrity("SCIENCE.ANALYST_DECISION_SOURCE_SHAPE")
            origin = _decoded_closed_record(
                retained.origin_bytes,
                code="SCIENCE.ANALYST_DECISION_ORIGIN_BYTES",
            )
            edge = _decoded_closed_record(
                retained.comparison_edge_bytes,
                code="SCIENCE.ANALYST_DECISION_EDGE_BYTES",
            )
            participant_stage_comparison = _decoded_closed_record(
                retained.stage_comparison_bytes,
                code="SCIENCE.ANALYST_DECISION_STAGE_BYTES",
            )
            origin_id = origin.get("origin_id")
            comparator_id = edge.get("comparator_analysis_spec_id")
            if (
                type(origin_id) is not str
                or origin_id in observed_origin_ids
                or type(comparator_id) is not str
            ):
                raise _integrity("SCIENCE.ANALYST_DECISION_ORIGIN_IDENTITY")
            observed_origin_ids.add(origin_id)
            comparator = candidate_by_analysis.get(comparator_id)
            if comparator is None:
                raise _integrity("SCIENCE.ANALYST_DECISION_COMPARATOR_MISSING")
            applicability, axis_id, choice_id = _analyst_applicability(
                origin=origin,
                edge=edge,
                operation_kind=subject.operation_kind,
                baseline_analysis_spec_id=baseline_analysis_spec_id,
                subject_analysis_spec_id=subject.analysis_spec_id,
                subject_event_ids=subject.event_ids,
                comparator_event_ids=comparator.event_ids,
            )
            contexts.append(
                (
                    origin,
                    edge,
                    subject,
                    comparator,
                    participant_stage_comparison,
                    applicability,
                    axis_id,
                    choice_id,
                )
            )
    contexts.sort(key=lambda row: _utf8(cast(str, row[0]["origin_id"])))

    numeric_by_identity: dict[
        tuple[str, str, str, str, str, str],
        _CanonicalOriginNumericComparisonRecord,
    ] = {}
    numeric_identity_by_pair: dict[
        tuple[str, str],
        tuple[str, str, str, str, str, str],
    ] = {}
    numeric_decoded_by_identity: dict[
        tuple[str, str, str, str, str, str],
        dict[str, object],
    ] = {}
    stage_comparison_by_identity: dict[
        tuple[str, str, str, str, str, str],
        dict[str, object],
    ] = {}
    context_numeric_identity: dict[str, tuple[str, str, str, str, str, str]] = {}
    for (
        origin,
        _edge,
        subject,
        comparator,
        participant_stage_comparison,
        applicability,
        _axis_id,
        _choice_id,
    ) in contexts:
        if applicability not in _ANALYST_DECISION_APPLICABLE_STATES:
            continue
        identity_record = _numeric_identity(subject, comparator)
        identity = (
            cast(str, identity_record["subject_analysis_spec_id"]),
            cast(str, identity_record["comparator_analysis_spec_id"]),
            cast(str, identity_record["subject_result_id"]),
            cast(str, identity_record["comparator_result_id"]),
            cast(str, identity_record["subject_candidate_record_digest"]),
            cast(str, identity_record["comparator_candidate_record_digest"]),
        )
        pair = identity[:2]
        previous_identity = numeric_identity_by_pair.setdefault(pair, identity)
        if previous_identity != identity:
            raise _integrity("SCIENCE.ANALYST_DECISION_PAIR_IDENTITY_CONFLICT")
        previous_stage_comparison = stage_comparison_by_identity.setdefault(
            identity,
            participant_stage_comparison,
        )
        if previous_stage_comparison != participant_stage_comparison:
            raise _integrity("SCIENCE.ANALYST_DECISION_STAGE_IDENTITY_CONFLICT")
        envelope = numeric_by_identity.get(identity)
        if envelope is None:
            envelope = _derive_origin_numeric_comparison(
                plan_digest=plan_digest,
                terminal_index_digest=terminal_index_digest,
                subject=subject,
                comparator=comparator,
                participant_stage_comparison=participant_stage_comparison,
            )
            numeric_by_identity[identity] = envelope
            decoded = strict_json_loads(envelope.canonical_bytes)
            if type(decoded) is not dict:
                raise _integrity("SCIENCE.ANALYST_DECISION_NUMERIC_RECORD")
            numeric_decoded_by_identity[identity] = cast(dict[str, object], decoded)
        context_numeric_identity[cast(str, origin["origin_id"])] = identity
    numeric_envelopes = tuple(
        sorted(
            numeric_by_identity.values(),
            key=lambda envelope: (
                _utf8(
                    cast(
                        str,
                        strict_json_loads(envelope.canonical_bytes)["numeric_identity"][
                            "subject_analysis_spec_id"
                        ],
                    )
                ),
                _utf8(
                    cast(
                        str,
                        strict_json_loads(envelope.canonical_bytes)["numeric_identity"][
                            "comparator_analysis_spec_id"
                        ],
                    )
                ),
            ),
        )
    )

    attempt_envelopes: list[_CanonicalOriginComparisonAttempt] = []
    attempt_decoded_by_origin: dict[str, dict[str, object]] = {}
    aggregate_source_by_family: dict[
        tuple[str, str],
        list[tuple[dict[str, object], dict[str, object], dict[str, object]]],
    ] = {}
    combination_source_by_vector: dict[
        tuple[str, str, tuple[tuple[str, str], ...]],
        list[tuple[dict[str, object], dict[str, object], dict[str, object]]],
    ] = {}
    combination_axis_sets: dict[tuple[str, str], tuple[str, ...]] = {}
    combination_vectors: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()
    experiment_modes: dict[str, str] = {}
    for (
        origin,
        edge,
        subject,
        comparator,
        _participant_stage_comparison,
        applicability,
        axis_id,
        choice_id,
    ) in contexts:
        origin_id = cast(str, origin["origin_id"])
        numeric_identity = context_numeric_identity.get(origin_id)
        numeric = (
            None if numeric_identity is None else numeric_decoded_by_identity[numeric_identity]
        )
        attempt = _origin_attempt(
            plan_digest=plan_digest,
            terminal_index_digest=terminal_index_digest,
            origin=origin,
            edge=edge,
            subject=subject,
            comparator=comparator,
            applicability=applicability,
            axis_id=axis_id,
            choice_id=choice_id,
            numeric_record=numeric,
        )
        decoded_attempt = strict_json_loads(attempt.canonical_bytes)
        if type(decoded_attempt) is not dict:
            raise _integrity("SCIENCE.ANALYST_DECISION_ATTEMPT_RECORD")
        exact_attempt = cast(dict[str, object], decoded_attempt)
        attempt_envelopes.append(attempt)
        attempt_decoded_by_origin[origin_id] = exact_attempt
        if applicability in _ANALYST_DECISION_APPLICABLE_STATES:
            experiment_set_id = cast(str, origin["experiment_set_id"])
            mode = cast(str, origin["experiment_mode"])
            previous_mode = experiment_modes.setdefault(experiment_set_id, mode)
            if previous_mode != mode:
                raise _integrity("SCIENCE.ANALYST_DECISION_CROSS_MODE_VECTOR")
        if applicability == "APPLICABLE_ORDINARY_ONE_AXIS":
            if axis_id is None or choice_id is None or numeric is None:
                raise _integrity("SCIENCE.ANALYST_DECISION_APPLICABLE_RECORD")
            aggregate_origin = {
                "experiment_set_id": origin["experiment_set_id"],
                "axis_id": axis_id,
                "choice_id": choice_id,
                "origin_id": origin_id,
            }
            key = (cast(str, origin["experiment_set_id"]), axis_id)
            aggregate_source_by_family.setdefault(key, []).append(
                (aggregate_origin, exact_attempt, numeric)
            )
        elif applicability in {
            "APPLICABLE_DECLARED_COMBINATION",
            "APPLICABLE_FULL_FACTORIAL",
        }:
            if numeric is None:
                raise _integrity("SCIENCE.ANALYST_DECISION_APPLICABLE_RECORD")
            choices = cast(list[dict[str, object]], origin["axis_choices"])
            vector = tuple(
                (
                    cast(str, choice["axis_id"]),
                    cast(str, choice["choice_id"]),
                )
                for choice in choices
            )
            mode = cast(str, origin["experiment_mode"])
            experiment_set_id = cast(str, origin["experiment_set_id"])
            combination_key = (experiment_set_id, mode, vector)
            if combination_key in combination_vectors:
                raise _integrity("SCIENCE.ANALYST_DECISION_DUPLICATE_VECTOR")
            combination_vectors.add(combination_key)
            axis_set = tuple(axis_id for axis_id, _choice_id in vector)
            previous_axes = combination_axis_sets.setdefault(
                (experiment_set_id, mode),
                axis_set,
            )
            if previous_axes != axis_set:
                raise _integrity("SCIENCE.ANALYST_DECISION_PARTIAL_VECTOR")
            aggregate_origin = {
                "origin_id": origin_id,
                "analysis_declaration_id": origin["analysis_declaration_id"],
                "source_declaration_digest": origin["source_declaration_digest"],
                "declaration_ordinal": origin["declaration_ordinal"],
                "axis_choices": origin["axis_choices"],
            }
            combination_source_by_vector.setdefault(combination_key, []).append(
                (aggregate_origin, exact_attempt, numeric)
            )
    attempts = tuple(attempt_envelopes)
    if [strict_json_loads(item.canonical_bytes)["origin_id"] for item in attempts] != sorted(
        observed_origin_ids,
        key=_utf8,
    ):
        raise _integrity("SCIENCE.ANALYST_DECISION_ATTEMPT_ORDER")

    one_axis_aggregate_envelopes = tuple(
        _derive_analyst_decision_aggregate(
            plan_digest=plan_digest,
            terminal_index_digest=terminal_index_digest,
            experiment_set_id=experiment_set_id,
            axis_id=axis_id,
            rows=tuple(aggregate_source_by_family[(experiment_set_id, axis_id)]),
        )
        for experiment_set_id, axis_id in sorted(
            aggregate_source_by_family,
            key=lambda key: (_utf8(key[0]), _utf8(key[1])),
        )
    )
    combination_aggregate_envelopes = tuple(
        _derive_combination_aggregate(
            plan_digest=plan_digest,
            terminal_index_digest=terminal_index_digest,
            experiment_set_id=experiment_set_id,
            experiment_mode=cast(
                Literal["declared-combinations", "full-factorial"],
                experiment_mode,
            ),
            axis_choices=axis_choices,
            rows=tuple(
                combination_source_by_vector[
                    (experiment_set_id, experiment_mode, axis_choices)
                ]
            ),
        )
        for experiment_set_id, experiment_mode, axis_choices in sorted(
            combination_source_by_vector,
            key=_combination_source_order_key,
        )
    )
    aggregate_envelopes = tuple(
        sorted(
            (*one_axis_aggregate_envelopes, *combination_aggregate_envelopes),
            key=lambda envelope: _aggregate_order_key(
                cast(
                    dict[str, object],
                    strict_json_loads(envelope.canonical_bytes),
                )
            ),
        )
    )
    decoded_attempts = tuple(
        cast(dict[str, object], strict_json_loads(item.canonical_bytes)) for item in attempts
    )
    decoded_numeric = tuple(
        cast(dict[str, object], strict_json_loads(item.canonical_bytes))
        for item in numeric_envelopes
    )
    decoded_aggregates = tuple(
        cast(dict[str, object], strict_json_loads(item.canonical_bytes))
        for item in aggregate_envelopes
    )
    layer_preimage = _analyst_decision_layer_preimage(
        plan_digest=plan_digest,
        terminal_index_digest=terminal_index_digest,
        attempts=decoded_attempts,
        numeric_records=decoded_numeric,
        aggregates=decoded_aggregates,
    )
    layer_digest = structured_sha256(_LAYER_DIGEST_DOMAIN, layer_preimage)
    layer = _CanonicalAnalystDecisionLayerEvidence(
        preimage_bytes=canonical_json_bytes(layer_preimage),
        canonical_bytes=canonical_json_bytes({**layer_preimage, "layer_digest": layer_digest}),
        layer_digest=layer_digest,
    )
    decoded_layer = strict_json_loads(layer.canonical_bytes)
    if type(decoded_layer) is not dict:
        raise _integrity("SCIENCE.ANALYST_DECISION_LAYER_SHAPE")
    _validate_analyst_decision_semantics(cast(dict[str, object], decoded_layer))
    return _CanonicalAnalystDecisionEvidenceBundle(
        attempts=attempts,
        numeric_records=numeric_envelopes,
        aggregates=aggregate_envelopes,
        layer=layer,
    )


_ANALYST_DECISION_DERIVATION = build_frozen_analyst_derivation(
    globals(),
    module_name=__name__,
    root_names=(
        "_derive_analyst_decision_evidence",
        "_validate_analyst_decision_semantics",
    ),
    record_type_names=(
        "_CanonicalOriginComparisonAttempt",
        "_CanonicalOriginNumericComparisonRecord",
        "_CanonicalAnalystDecisionAggregate",
        "_CanonicalAnalystDecisionLayerEvidence",
        "_CanonicalAnalystDecisionEvidenceBundle",
        "_AnalystDecisionOriginInput",
        "_AnalystDecisionCandidateInput",
    ),
    additional_dependency_roots=(
        Counter.__init__,
        Counter.update,
    ),
)
for _function_name, _frozen_function in _ANALYST_DECISION_DERIVATION.functions.items():
    globals()[_function_name] = _frozen_function
for _record_type_name, _frozen_record_type in _ANALYST_DECISION_DERIVATION.record_types.items():
    globals()[_record_type_name] = _frozen_record_type
del _function_name
del _frozen_function
del _record_type_name
del _frozen_record_type
del build_frozen_analyst_derivation


__all__: list[str] = []
