"""Pure grouped derivations over one normalized authenticated evidence graph.

This module is deliberately independent of the historical per-output handler
registry. The ordinary transaction authenticates owners and normalizes their
slot metadata once. The functions below then derive a complete family as one
immutable group. They never recover a value from prose, from record position,
or from the absence of evidence.
"""

from __future__ import annotations

import math
import re
from bisect import bisect_left
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from functools import cache, lru_cache
from typing import Any, Final, Literal, Never, TypeGuard, cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource

from ebm_audit.config.strict_yaml import load_strict_yaml_bytes
from ebm_audit.evaluator.meaning_evidence_bundle import (
    _FAMILY_OPERATION_MEMBERS,
    _FROZEN_COVERAGE_ROWS,
    _frozen_meaning_source_bytes,
)
from ebm_audit.evaluator.report_claim_projection import REPORT_CLAIM_DIRECTIVES
from ebm_audit.protocol import strict_json_loads, structured_sha256_hex
from ebm_audit.schema import RESOURCE_FILENAMES, load_schema

type GroupedMeaningState = Literal[
    "AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED"
]
type CapabilityMode = Literal["FULL", "PARTIAL"]
type DeclaredModelShape = Literal["APPLICABLE", "NOT_APPLICABLE"]
type OperationOutcomeState = Literal["SUCCESS", "UNAVAILABLE", "INVALID", "FAILED"]

_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_GRAPH_DOMAIN: Final = "ebm-audit/validated-meaning-graph/1"
_UNSEALED_GRAPH_DIGEST: Final = "0" * 64
_ARRAY_VALUE_DOMAIN: Final = "ebm-audit/canonical-array-value/1"
_SCHEMA_BASE_URI: Final = "https://schemas.ebm-audit.invalid/"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_STABLE_CODE = re.compile(r"^[A-Z][A-Z0-9_]*(?:\.[A-Z0-9_]+)+$")

_INVALID_GRAPH = "EVIDENCE.GRAPH_INVALID"
_MISSING_OWNER = "EVIDENCE.MISSING_OWNER"
_OWNER_INVALID = "EVIDENCE.OWNER_INVALID"
_DUPLICATE_OWNER = "EVIDENCE.DUPLICATE_OWNER"
_CROSS_CASE = "EVIDENCE.CROSS_CASE_SUBSTITUTION"
_SELECTOR = "EVIDENCE.SELECTOR_MISMATCH"
_CARDINALITY = "EVIDENCE.CARDINALITY_MISMATCH"
_ORIENTATION = "EVIDENCE.ORIENTATION_MISMATCH"
_REPLAY = "EVIDENCE.REPLAY"
_UNAVAILABLE = "SCIENCE.REQUIRED_CAPABILITY_UNAVAILABLE"
_NOT_APPLICABLE = "SCIENCE.SCENARIO_NOT_DECLARED"
_OPERATION_FAILED = "SCIENCE.APPLICABLE_OPERATION_FAILED"
_DERIVATION_FAILED = _OPERATION_FAILED
_DECLARED_SET_CARDINALITIES: Final = frozenset(
    {
        "EXACT_MATCHED_SET",
        "ONE_PER_CASE",
        "ONE_PER_PLANNED_CASE",
        "ONE_PER_SUBTYPE_CASE",
        "ONE_PER_DECLARED_RULE",
        "ONE_PER_COMPARATOR_MEMBER",
        "ALL_CASE_ARRAYS",
        "ALL_CASE_WARNINGS",
        "ALL_PLANNED_OPERATIONS",
    }
)
_SUPPORT_ONLY_OWNER_CLASSES: Final = frozenset({"ANALYSIS_SPEC", "FIT_RESPONSE_BINDING"})
_SUPPORT_ONLY_CARDINALITY: Final = "SUPPORT_ONLY"
_SUPPORT_ONLY_SELECTOR: Final = "authenticated-support-owner/1"
_REPORT_CLAIM_PROJECTION_DOMAIN: Final = "ebm-audit/authenticated-report-claim-projection/1"
_REPORT_CLAIM_SUPPORT_COORDINATE: Final = (
    "REPORT_CLAIM_PROJECTION",
    "EXACTLY_ONE",
    "authenticated-report-claim-projection/1",
    None,
)
_REPORT_CLAIM_CONSUMER_OWNER_CLASSES: Final = frozenset(
    {
        "REPORT_PREDICATE_OUTCOME",
        "REPORT_WARNING_LEDGER",
        "REPORT_TERMINAL_VISIBILITY",
    }
)


@dataclass(frozen=True, slots=True)
class ValidatedGraphSourceRecord:
    """One exact authenticated owner projection detached from private authority."""

    owner_class: str
    owner_schema_ref: str
    cardinality: str
    selector: str
    orientation: str | None
    natural_identity: Mapping[str, str | int | bool | None]
    source_record: Mapping[str, object]
    source_record_sha256: str
    ordered_support_owner_sha256: tuple[str, ...]
    private_value: object | None = None


@dataclass(frozen=True, slots=True)
class ValidatedGraphClaimRecord:
    """One pre-report boolean claim derived from the same validated graph."""

    predicate_id: str
    state: GroupedMeaningState
    value: bool | None
    reason_codes: tuple[str, ...]
    failure_code: str | None
    input_record_ids: tuple[str, ...]
    source_record_digests: tuple[str, ...]
    operation_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidatedGraphOperationOutcome:
    """Authenticated operation terminal fact used only for state propagation."""

    operation_id: str
    family_id: str
    case_id: str
    state: OperationOutcomeState
    failure_code: str | None
    source_record_sha256: str


@dataclass(frozen=True, slots=True)
class ValidatedGraphCardinalityDeclaration:
    """Authenticated exact denominator for one set-valued owner slot."""

    owner_class: str
    cardinality: str
    selector: str
    ordered_member_keys: tuple[str, ...]
    ordered_source_record_sha256: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidatedMeaningGraph:
    """Complete normalized input to grouped family derivations."""

    evidence_graph_digest: str
    benchmark_subject_digest: str
    family_id: str
    case_id: str
    source_contract_sha256: str
    scenario_source_sha256: str
    operation_plan_sha256: str
    operation_ids: tuple[str, ...]
    planned_case_ids: tuple[str, ...]
    valid_case_ids: tuple[str, ...]
    capability_mode: CapabilityMode
    declared_model_shape: DeclaredModelShape
    operation_outcomes: tuple[ValidatedGraphOperationOutcome, ...]
    source_records: tuple[ValidatedGraphSourceRecord, ...]
    cardinality_declarations: tuple[ValidatedGraphCardinalityDeclaration, ...]
    report_claims: tuple[ValidatedGraphClaimRecord, ...]


@dataclass(frozen=True, slots=True)
class GroupedMeaningResult:
    """One exact frozen meaning result before bundle metadata is attached."""

    meaning_id: str
    state: GroupedMeaningState
    value: object | None
    reason_codes: tuple[str, ...]
    failure_code: str | None
    source_record_digests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Slot:
    owner_class: str
    cardinality: str
    selector: str


@dataclass(frozen=True, slots=True)
class _MeaningSpec:
    meaning_id: str
    derivation_id: str
    slots: tuple[_Slot, ...]


class _DerivationError(RuntimeError):
    def __init__(self, code: str, *, state: GroupedMeaningState = "INVALID") -> None:
        self.code = code
        self.state = state
        super().__init__(code)


def _raise(code: str, *, state: GroupedMeaningState = "INVALID") -> Never:
    raise _DerivationError(code, state=state)


def _is_sha256(value: object) -> TypeGuard[str]:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _is_sha256_digest(value: object) -> TypeGuard[str]:
    return type(value) is str and _SHA256_DIGEST.fullmatch(value) is not None


def _plain(value: object, active: set[int] | None = None) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _raise(_OWNER_INVALID)
        return value
    if type(value) not in (tuple, list) and not isinstance(value, Mapping):
        _raise(_OWNER_INVALID)
    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        _raise(_OWNER_INVALID)
    active.add(identity)
    try:
        if type(value) in (tuple, list):
            return [_plain(item, active) for item in cast(Sequence[object], value)]
        mapping = cast(Mapping[object, object], value)
        if any(type(key) is not str for key in mapping):
            _raise(_OWNER_INVALID)
        return {cast(str, key): _plain(item, active) for key, item in mapping.items()}
    finally:
        active.remove(identity)


def _graph_preimage(graph: ValidatedMeaningGraph) -> dict[str, object]:
    return {
        "benchmark_subject_digest": graph.benchmark_subject_digest,
        "family_id": graph.family_id,
        "case_id": graph.case_id,
        "source_contract_sha256": graph.source_contract_sha256,
        "scenario_source_sha256": graph.scenario_source_sha256,
        "operation_plan_sha256": graph.operation_plan_sha256,
        "operation_ids": list(graph.operation_ids),
        "planned_case_ids": list(graph.planned_case_ids),
        "valid_case_ids": list(graph.valid_case_ids),
        "capability_mode": graph.capability_mode,
        "declared_model_shape": graph.declared_model_shape,
        "operation_outcomes": [
            {
                "operation_id": row.operation_id,
                "family_id": row.family_id,
                "case_id": row.case_id,
                "state": row.state,
                "failure_code": row.failure_code,
                "source_record_sha256": row.source_record_sha256,
            }
            for row in graph.operation_outcomes
        ],
        "source_records": [
            {
                "owner_class": row.owner_class,
                "owner_schema_ref": row.owner_schema_ref,
                "cardinality": row.cardinality,
                "selector": row.selector,
                "orientation": row.orientation,
                "natural_identity": _plain(row.natural_identity),
                "source_record": _plain(row.source_record),
                "source_record_sha256": row.source_record_sha256,
                "ordered_support_owner_sha256": list(row.ordered_support_owner_sha256),
            }
            for row in graph.source_records
        ],
        "cardinality_declarations": [
            {
                "owner_class": row.owner_class,
                "cardinality": row.cardinality,
                "selector": row.selector,
                "ordered_member_keys": list(row.ordered_member_keys),
                "ordered_source_record_sha256": list(row.ordered_source_record_sha256),
            }
            for row in graph.cardinality_declarations
        ],
        "report_claims": [
            {
                "predicate_id": row.predicate_id,
                "state": row.state,
                "value": row.value,
                "reason_codes": list(row.reason_codes),
                "failure_code": row.failure_code,
                "input_record_ids": list(row.input_record_ids),
                "source_record_digests": list(row.source_record_digests),
                "operation_ids": list(row.operation_ids),
            }
            for row in graph.report_claims
        ],
    }


def validated_meaning_graph_digest(graph: ValidatedMeaningGraph) -> str:
    """Return the deterministic digest that must be stored on ``graph``."""

    if type(graph) is not ValidatedMeaningGraph:
        raise TypeError("graph must be ValidatedMeaningGraph")
    return structured_sha256_hex(_GRAPH_DOMAIN, _graph_preimage(graph))


def _slot(owner_class: str, cardinality: str, selector: str) -> _Slot:
    return _Slot(owner_class, cardinality, selector)


def _spec(meaning_id: str, derivation_id: str, *slots: tuple[str, str, str]) -> _MeaningSpec:
    return _MeaningSpec(meaning_id, derivation_id, tuple(_slot(*row) for row in slots))


_REPORT_PREDICATE_BY_MEANING: Final = {
    "small_sample:/payload/forced_precision_flags": "forced-precision-report-predicate/1",
    "weak_pre_post_separation:/payload/ineligible_strong_flags": "INELIGIBLE_STRONG_LABEL/v1",
    "incomplete_time_coverage:/payload/coverage_limitation_reported": (
        "coverage-limitation-report-predicate/1"
    ),
    "tightly_spaced_events:/payload/arbitrary_within_pair_truth_claims": (
        "within-pair-precision-report-predicate/1"
    ),
    "outlier_sabotage:/payload/bad_or_wrong_data_claim_flags": "bad-data-report-predicate/1",
    "correlated_duplicate_events:/payload/correlated/arbitrary_within_pair_truth_claims": (
        "correlated-within-pair-report/1"
    ),
    (
        "correlated_duplicate_events:/payload/exact_duplicate_post_noise/"
        "partial_truth_scored_without_tiebreak"
    ): "partial-truth-scoring-report/1",
    (
        "correlated_duplicate_events:/payload/exact_duplicate_post_noise/"
        "arbitrary_within_pair_truth_claims"
    ): "exact-duplicate-within-pair-report/1",
    "minority_alternate_sequence:/payload/single_sequence_limitation_reported": (
        "single-sequence-limitation-report/1"
    ),
    "opposing_sequences_50_50:/payload/internally_concentrated_flags": (
        "precision-report-predicate/1"
    ),
    "near_simultaneous_events:/payload/block_aware_scoring": "block-scoring-report-predicate/1",
    "group_boundary_sensitivity:/payload/decision_attribution": ("boundary-attribution-report/1"),
    "group_boundary_sensitivity:/payload/selected_threshold_flags": (
        "threshold-selection-report/1"
    ),
    "wrong_event_direction:/payload/direction_sensitivity_reported": (
        "direction-sensitivity-report/1"
    ),
    "wrong_event_direction:/payload/direction_validity_claims": "direction-validity-report/1",
    "pure_no_signal:/payload/fpr_evidence": "null-calibration-report/1",
    "label_permutation_null:/payload/calibration_diagnostic_reported": (
        "null-calibration-report/1"
    ),
    "label_permutation_null:/payload/ineligible_strong_flags": "INELIGIBLE_STRONG_LABEL/v1",
    "within_group_feature_permutation_null:/payload/calibration_diagnostic_reported": (
        "null-calibration-report/1"
    ),
    "within_group_feature_permutation_null:/payload/ineligible_strong_flags": (
        "INELIGIBLE_STRONG_LABEL/v1"
    ),
}

_REPORT_DEPENDENT_MEANINGS: Final = frozenset(
    {
        *_REPORT_PREDICATE_BY_MEANING,
        "heavy_tailed_skewed:/payload/suppressed_warning_flags",
        "heavy_tailed_skewed:/payload/visible_terminal_flags",
        "label_permutation_null:/payload/excluded_from_pure_no_signal_fpr_denominator",
        (
            "within_group_feature_permutation_null:/payload/"
            "excluded_from_pure_no_signal_fpr_denominator"
        ),
    }
)

if len(_REPORT_DEPENDENT_MEANINGS) != 24:
    raise RuntimeError("Frozen report-dependent meaning set is not closed.")

_MATCHED_METRIC_SELECTORS: Final = {
    "small_sample:/payload/entropy_delta_small_minus_large": (
        "small-vs-large-entropy-comparison/1",
        "small-minus-large",
    ),
    "weak_pre_post_separation:/payload/entropy_delta_weak_minus_moderate": (
        "weak-vs-moderate-entropy/1",
        "weak-minus-moderate",
    ),
    "weak_pre_post_separation:/payload/kendall_distance_delta_weak_minus_moderate": (
        "weak-vs-moderate-kendall/1",
        "weak-minus-moderate",
    ),
    "slow_overlapping_transitions:/payload/entropy_delta_slow_minus_narrow": (
        "slow-vs-narrow-entropy/1",
        "slow-minus-narrow",
    ),
    "slow_overlapping_transitions:/payload/kendall_distance_delta_slow_minus_narrow": (
        "slow-vs-narrow-kendall/1",
        "slow-minus-narrow",
    ),
    "minority_alternate_sequence:/payload/entropy_delta_mixture_minus_single": (
        "mixture-vs-single-entropy/1",
        "mixture-minus-single",
    ),
    "covariate_confounding:/payload/adjusted_minus_unadjusted_kendall_agreement": (
        "adjusted-vs-unadjusted-kendall/1",
        "adjusted-minus-unadjusted-agreement",
    ),
    "control_contamination:/payload/kendall_agreement": (
        "contaminated-vs-clean-kendall/1",
        "contaminated-agreement",
    ),
    "control_contamination:/payload/position_entropy": (
        "contaminated-vs-clean-entropy/1",
        "contaminated-entropy",
    ),
    "wrong_event_direction:/payload/correct_minus_wrong_kendall_agreement": (
        "correct-vs-wrong-direction-kendall/1",
        "correct-minus-wrong-agreement",
    ),
}

_SPECIAL_SLOTS: Final[dict[str, tuple[tuple[str, str, str], ...]]] = {
    "*:/planned_case_ids": (
        ("SEALED_CASE_RECORD", "ONE_PER_PLANNED_CASE", "frozen-operation-plan-case-order/1"),
    ),
    "*:/valid_case_ids": (
        ("SEALED_RESULT_RECORD", "ONE_PER_PLANNED_CASE", "terminal-result-plan-order/1"),
    ),
    "easy_known_truth:/payload/order_rule_states": (
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth-strict-order/1"),
        (
            "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
            "ONE_PER_CASE",
            "same-chain-zero-based-central-order-permutation/1",
        ),
    ),
    "easy_known_truth:/payload/stage_rule_states": (
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth/1"),
        (
            "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
            "ONE_PER_CASE",
            "same-case-training-stage-posterior/1",
        ),
        (
            "PREPARATION_ROW_INSTANCE_MANIFEST",
            "ONE_PER_CASE",
            "same-case-training-row-instance-manifest/1",
        ),
    ),
    "moderate_mina_shape:/payload/moderate_rule_states": (
        ("MATCHED_COMPARATOR_EVIDENCE", "EXACT_MATCHED_SET", "moderate-comparator-plan-order/1"),
        (
            "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
            "ALL_CASE_ARRAYS",
            "moderate-member-order-and-stage-array-projections/1",
        ),
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "moderate-source-reference-and-stage-truth/1"),
    ),
    "small_sample:/payload/cross_chain_delta_small_minus_large": (
        (
            "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
            "ALL_CASE_ARRAYS",
            "small-large-order-state-chain-projections/1",
        ),
    ),
    "noise_ladder:/payload/noise_ladder_rule_states": (
        ("MATCHED_COMPARATOR_EVIDENCE", "EXACT_MATCHED_SET", "noise-ladder-plan-order/1"),
        (
            "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
            "ALL_CASE_ARRAYS",
            "noise-level-order-array-projections/1",
        ),
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "noise-level-strict-order-truth/1"),
    ),
    "incomplete_time_coverage:/payload/affected_tail_entropy_delta": (
        (
            "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
            "ALL_CASE_ARRAYS",
            "restricted-broad-order-state-chain-projections/1",
        ),
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "affected-tail-truth-events/1"),
    ),
    "outlier_sabotage:/payload/influence_rule_states": (
        ("SEALED_CASE_RECORD", "ONE_PER_PLANNED_CASE", "outlier-sabotage-plan-order/1"),
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-injected-participant-truth/1"),
        ("CASE_INFLUENCE_AGGREGATE", "ONE_PER_CASE", "complete-planned-removal-set/1"),
    ),
    "mcar_missingness:/payload/mask_digest_equal": (
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth/1"),
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-scientific-data/1"),
    ),
    "mcar_missingness:/payload/missing_counts_equal": (
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth/1"),
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-scientific-data/1"),
        ("PREPARATION_AUDIT_EVIDENCE", "ONE_PER_CASE", "same-case-preparation-audit/1"),
    ),
    "mcar_missingness:/payload/prebackend_terminal_correct": (
        ("PREPARATION_AUDIT_EVIDENCE", "ONE_PER_CASE", "same-case-preparation-audit/1"),
        ("BENCHMARK_OPERATION_MANIFEST", "EXACTLY_ONE", "frozen-operation-manifest/1"),
    ),
    "mcar_missingness:/payload/predicted_removed_rows": (
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-scientific-data/1"),
        ("ANALYSIS_SPEC", "ONE_PER_CASE", "same-operation-analysis-spec/1"),
    ),
    "mar_missingness:/payload/mask_digest_equal": (
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth/1"),
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-scientific-data/1"),
    ),
    "mar_missingness:/payload/missing_counts_equal": (
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth/1"),
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-scientific-data/1"),
        ("PREPARATION_AUDIT_EVIDENCE", "ONE_PER_CASE", "same-case-preparation-audit/1"),
    ),
    "mar_missingness:/payload/hidden_imputation_flags": (
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-source-data/1"),
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-transformed-data/1"),
        ("PREPARATION_AUDIT_EVIDENCE", "ONE_PER_CASE", "same-case-preparation-audit/1"),
    ),
    "correlated_duplicate_events:/payload/correlated/case_ids": (
        ("SEALED_CASE_RECORD", "ONE_PER_SUBTYPE_CASE", "correlated-subtype-plan-order/1"),
    ),
    "correlated_duplicate_events:/payload/exact_duplicate_post_noise/case_ids": (
        (
            "SEALED_CASE_RECORD",
            "ONE_PER_SUBTYPE_CASE",
            "exact-duplicate-subtype-plan-order/1",
        ),
    ),
    "group_boundary_sensitivity:/payload/ordered_rule_ids": (
        ("ANALYSIS_RULE_IDENTITY", "ONE_PER_DECLARED_RULE", "boundary-rule-plan-order/1"),
    ),
    "group_boundary_sensitivity:/payload/group_count_accounting_equal": (
        ("ANALYSIS_RULE_IDENTITY", "ONE_PER_DECLARED_RULE", "boundary-rule-plan-order/1"),
        ("PREPARATION_AUDIT_EVIDENCE", "ONE_PER_CASE", "same-case-preparation-audit/1"),
    ),
    "control_contamination:/payload/contamination_fraction": (
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth/1"),
        ("BENCHMARK_OPERATION_MANIFEST", "EXACTLY_ONE", "frozen-operation-manifest/1"),
    ),
    "control_contamination:/payload/label_manifest_equal": (
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-scientific-data/1"),
        ("BENCHMARK_OPERATION_MANIFEST", "EXACTLY_ONE", "frozen-operation-manifest/1"),
    ),
    "heavy_tailed_skewed:/payload/hidden_modification_flags": (
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-source-data/1"),
        ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-transformed-data/1"),
        ("PREPARATION_AUDIT_EVIDENCE", "ONE_PER_CASE", "same-case-preparation-audit/1"),
    ),
    "heavy_tailed_skewed:/payload/suppressed_warning_flags": (
        ("WARNING_RECORD", "ALL_CASE_WARNINGS", "same-case-warning-order/1"),
        ("REPORT_WARNING_LEDGER", "ONE_PER_CASE", "same-case-report-warning-ledger/1"),
    ),
    "heavy_tailed_skewed:/payload/visible_terminal_flags": (
        (
            "REPORT_TERMINAL_VISIBILITY",
            "ONE_PER_CASE",
            "same-case-report-terminal-visibility/1",
        ),
    ),
    "label_permutation_null:/payload/excluded_from_pure_no_signal_fpr_denominator": (
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth/1"),
        ("BENCHMARK_OPERATION_MANIFEST", "EXACTLY_ONE", "proportional-challenge-plan/1"),
    ),
    (
        "within_group_feature_permutation_null:/payload/"
        "excluded_from_pure_no_signal_fpr_denominator"
    ): (
        ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth/1"),
        ("BENCHMARK_OPERATION_MANIFEST", "EXACTLY_ONE", "proportional-challenge-plan/1"),
    ),
}

_PAE_OUTPUTS: Final = {
    "mcar_missingness:/payload/actual_removed_rows",
    "mcar_missingness:/payload/backend_nan_flags",
    "mar_missingness:/payload/terminal_contract_equal",
    "heavy_tailed_skewed:/payload/nonfinite_admitted_flags",
}

_TRANSFORM_OUTPUTS: Final = {
    "label_permutation_null:/payload/group_counts_preserved",
    "label_permutation_null:/payload/preprocessing_refit_equal",
    "label_permutation_null:/payload/source_binding_equal",
    "within_group_feature_permutation_null:/payload/group_marginals_preserved",
    "within_group_feature_permutation_null:/payload/missing_counts_preserved",
    "within_group_feature_permutation_null:/payload/participant_event_alignment_changed",
    "within_group_feature_permutation_null:/payload/preprocessing_refit_equal",
    "within_group_feature_permutation_null:/payload/source_binding_equal",
}


def _slots_for(meaning_id: str, derivation_id: str) -> tuple[tuple[str, str, str], ...]:
    if meaning_id in _REPORT_PREDICATE_BY_MEANING:
        return ()
    if meaning_id in _MATCHED_METRIC_SELECTORS:
        selector, _orientation = _MATCHED_METRIC_SELECTORS[meaning_id]
        return (("SCENARIO_MATCHED_METRIC_RECORD", "ONE_PER_CASE", selector),)
    if meaning_id.endswith("/truth_scoring_mode"):
        if "/correlated/" in meaning_id:
            selector = "correlated-subtype-truth/1"
            cardinality = "ONE_PER_SUBTYPE_CASE"
        elif "/exact_duplicate_post_noise/" in meaning_id:
            selector = "exact-duplicate-subtype-truth/1"
            cardinality = "ONE_PER_SUBTYPE_CASE"
        else:
            selector = "same-case-truth/1"
            cardinality = "ONE_PER_CASE"
        return (("SYNTHETIC_TRUTH", cardinality, selector),)
    if meaning_id in _PAE_OUTPUTS:
        return (("PREPARATION_AUDIT_EVIDENCE", "ONE_PER_CASE", "same-case-preparation-audit/1"),)
    if meaning_id in _TRANSFORM_OUTPUTS:
        if "/preprocessing_refit_equal" in meaning_id:
            return (
                (
                    "PREPARATION_AUDIT_EVIDENCE",
                    "ONE_PER_CASE",
                    "same-case-source-preparation-audit/1",
                ),
                (
                    "PREPARATION_AUDIT_EVIDENCE",
                    "ONE_PER_CASE",
                    "same-case-transformed-preparation-audit/1",
                ),
                ("BENCHMARK_OPERATION_MANIFEST", "EXACTLY_ONE", "frozen-operation-manifest/1"),
            )
        return (
            ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-source-data/1"),
            ("SYNTHETIC_SCIENTIFIC_DATA", "ONE_PER_CASE", "same-case-transformed-data/1"),
            ("BENCHMARK_OPERATION_MANIFEST", "EXACTLY_ONE", "frozen-operation-manifest/1"),
        )
    if derivation_id == "truth-target-pair-precedence/1":
        if "/correlated/" in meaning_id:
            return (
                ("SYNTHETIC_TRUTH", "ONE_PER_SUBTYPE_CASE", "correlated-subtype-truth/1"),
                (
                    "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
                    "ONE_PER_SUBTYPE_CASE",
                    "correlated-subtype-pairwise-array/1",
                ),
            )
        if "/exact_duplicate_post_noise/" in meaning_id:
            return (
                (
                    "SYNTHETIC_TRUTH",
                    "ONE_PER_SUBTYPE_CASE",
                    "exact-duplicate-subtype-truth/1",
                ),
                (
                    "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
                    "ONE_PER_SUBTYPE_CASE",
                    "exact-duplicate-subtype-pairwise-array/1",
                ),
            )
        return (
            ("SYNTHETIC_TRUTH", "ONE_PER_CASE", "declared-target-pair/1"),
            (
                "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
                "ONE_PER_CASE",
                "same-case-pairwise-precedence/1",
            ),
        )
    if derivation_id in {
        "opposing-pair-absolute-precedence-from-half/1",
        "truth-block-pair-precedence/1",
    }:
        selector = (
            "declared-opposing-relations/1"
            if derivation_id.startswith("opposing")
            else "declared-equivalence-block/1"
        )
        return (
            ("SYNTHETIC_TRUTH", "ONE_PER_CASE", selector),
            (
                "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
                "ONE_PER_CASE",
                "same-case-pairwise-precedence/1",
            ),
        )
    return _SPECIAL_SLOTS.get(meaning_id, ())


def _registry_slot(value: object) -> _Slot:
    if not isinstance(value, Mapping) or set(value) != {
        "owner_class",
        "cardinality",
        "selector",
    }:
        raise RuntimeError("Frozen owner slot is invalid.")
    owner_class = value.get("owner_class")
    cardinality = value.get("cardinality")
    selector = value.get("selector")
    if any(type(item) is not str or not item for item in (owner_class, cardinality, selector)):
        raise RuntimeError("Frozen owner slot is invalid.")
    return _Slot(cast(str, owner_class), cast(str, cardinality), cast(str, selector))


def _registry_output_spec(family_id: str, value: object) -> tuple[_MeaningSpec, str | None]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Frozen meaning output is invalid.")
    output_path = value.get("output_path")
    derivation_id = value.get("derivation_id", value.get("selector"))
    schema_ref = value.get("output_schema_ref")
    slots_value = value.get("owner_slots")
    if slots_value is None:
        slots_value = [
            {field: value.get(field) for field in ("owner_class", "cardinality", "selector")}
        ]
    if (
        type(output_path) is not str
        or not output_path.startswith("/")
        or type(derivation_id) is not str
        or not derivation_id
        or (schema_ref is not None and (type(schema_ref) is not str or not schema_ref))
        or type(slots_value) is not list
        or not slots_value
    ):
        raise RuntimeError("Frozen meaning output is invalid.")
    return (
        _MeaningSpec(
            f"{family_id}:{output_path}",
            derivation_id,
            tuple(_registry_slot(slot) for slot in slots_value),
        ),
        schema_ref,
    )


def _load_frozen_specs() -> tuple[
    tuple[_MeaningSpec, ...],
    Mapping[str, tuple[str, tuple[str, ...]]],
]:
    """Load the exact accepted registry projection and proportional amendments."""

    contract_bytes, registry_bytes = _frozen_meaning_source_bytes()
    registry = strict_json_loads(registry_bytes)
    contract = load_strict_yaml_bytes(contract_bytes, maximum_bytes=1_000_000)
    if not isinstance(registry, Mapping) or not isinstance(contract, Mapping):
        raise RuntimeError("Frozen meaning sources are invalid.")
    owner_rows = registry.get("owner_classes")
    common = registry.get("common_derivations")
    family_order = registry.get("family_order")
    families = registry.get("families")
    if (
        type(owner_rows) is not list
        or type(common) is not list
        or type(family_order) is not list
        or type(families) is not list
    ):
        raise RuntimeError("Frozen meaning sources are invalid.")
    owner_bindings: dict[str, tuple[str, tuple[str, ...]]] = {}
    for raw in owner_rows:
        if not isinstance(raw, Mapping):
            raise RuntimeError("Frozen owner binding is invalid.")
        owner_class = raw.get("owner_class")
        schema_ref = raw.get("schema_ref")
        identity_fields = raw.get("natural_identity_fields")
        if (
            type(owner_class) is not str
            or not owner_class
            or type(schema_ref) is not str
            or not schema_ref.startswith("schemas/")
            or type(identity_fields) is not list
            or not identity_fields
            or any(type(field) is not str or not field for field in identity_fields)
            or owner_class in owner_bindings
        ):
            raise RuntimeError("Frozen owner binding is invalid.")
        owner_bindings[owner_class] = (
            schema_ref,
            tuple(cast(list[str], identity_fields)),
        )

    specs_and_schemas = [_registry_output_spec("*", raw) for raw in common]
    by_family = {
        raw.get("family_id"): raw
        for raw in families
        if isinstance(raw, Mapping) and type(raw.get("family_id")) is str
    }
    if tuple(by_family) != tuple(family_order):
        raise RuntimeError("Frozen family order is invalid.")
    for family_id in family_order:
        family = by_family.get(family_id)
        outputs = family.get("outputs") if isinstance(family, Mapping) else None
        if type(family_id) is not str or type(outputs) is not list:
            raise RuntimeError("Frozen family output is invalid.")
        specs_and_schemas.extend(_registry_output_spec(family_id, raw) for raw in outputs)

    meaning_inventory = contract.get("meaning_inventory")
    if (
        contract.get("contract_version") != "0.2.3"
        or contract.get("contract_sha256")
        != "2cf53a6006b174d7b2ef574a293f1499cff450491ef0359088a6889b0c288119"
        or not isinstance(meaning_inventory, Mapping)
        or meaning_inventory.get("source_schema_version")
        != "ebm-audit-scenario-derivation-registry/2.3"
        or meaning_inventory.get("ordered_count") != 104
    ):
        raise RuntimeError("Frozen proportional meaning inventory is invalid.")

    expected = tuple(
        (
            cast(str, row["meaning_id"]),
            cast(str, row["derivation_id"]),
            cast(str | None, row["output_schema_ref"]),
        )
        for row in _FROZEN_COVERAGE_ROWS
    )
    observed = tuple(
        (spec.meaning_id, spec.derivation_id, schema_ref) for spec, schema_ref in specs_and_schemas
    )
    if observed != expected:
        raise RuntimeError("Frozen meaning projection is detached.")
    return tuple(spec for spec, _schema_ref in specs_and_schemas), owner_bindings


_FROZEN_SPECS, _FROZEN_OWNER_BINDINGS = _load_frozen_specs()

_OUTPUT_SCHEMA_BY_MEANING: Final = {
    cast(str, row["meaning_id"]): cast(str | None, row["output_schema_ref"])
    for row in _FROZEN_COVERAGE_ROWS
}

if len(_FROZEN_SPECS) != 104 or len({row.meaning_id for row in _FROZEN_SPECS}) != 104:
    raise RuntimeError("Frozen grouped meaning specification is not closed.")


@lru_cache(maxsize=1)
def _output_schema_registry() -> Registry[Any]:
    pairs: list[tuple[str, Resource[Any]]] = []
    for name in RESOURCE_FILENAMES:
        if name.endswith(".schema.json"):
            pairs.append((_SCHEMA_BASE_URI + name, Resource.from_contents(load_schema(name))))
    return Registry().with_resources(pairs).crawl()


@cache
def _output_validator(schema_ref: str) -> Draft202012Validator:
    if not schema_ref.startswith("schemas/") or "#" not in schema_ref:
        raise ValueError("invalid frozen output schema reference")
    schema_name, fragment = schema_ref.removeprefix("schemas/").split("#", 1)
    schema = load_schema(schema_name)
    return Draft202012Validator(
        {
            "$schema": schema["$schema"],
            "$ref": f"{_SCHEMA_BASE_URI}{schema_name}#{fragment}",
        },
        registry=_output_schema_registry(),
    )


@cache
def _source_validator(schema_ref: str) -> Draft202012Validator:
    if not schema_ref.startswith("schemas/"):
        raise ValueError("invalid frozen owner schema reference")
    relative = schema_ref.removeprefix("schemas/")
    schema_name, separator, fragment = relative.partition("#")
    schema = load_schema(schema_name)
    target = f"{_SCHEMA_BASE_URI}{schema_name}"
    if separator:
        target = f"{target}#{fragment}"
    return Draft202012Validator(
        {"$schema": schema["$schema"], "$ref": target},
        registry=_output_schema_registry(),
    )


def _available_value_valid(meaning_id: str, value: object) -> bool:
    schema_ref = _OUTPUT_SCHEMA_BY_MEANING[meaning_id]
    if schema_ref is None:
        return (
            type(value) is list
            and bool(value)
            and all(type(item) is str and bool(item) for item in value)
        )
    if schema_ref.startswith("schemas/proportional-readiness-contract.schema.json#"):
        return value == {
            "schema_version": "ebm-audit-false-positive-qualification-state/2.0",
            "status": "NOT_STATISTICALLY_QUALIFIED",
            "reason_code": "CALIBRATION.OPTIONAL_RESEARCH_STRESS_NOT_RUN",
            "strong_language_eligible": False,
            "cautious_fallback_required": True,
            "optional_profile": "benchmark-contract/0.1.3",
        }
    return cast(bool, _output_validator(schema_ref).is_valid(value))


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        _raise(_OWNER_INVALID)
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, nonempty: bool = True) -> tuple[object, ...]:
    if type(value) not in (tuple, list):
        _raise(_OWNER_INVALID)
    result = tuple(cast(Sequence[object], value))
    if nonempty and not result:
        _raise(_OWNER_INVALID)
    return result


def _strings(value: object, *, nonempty: bool = True) -> tuple[str, ...]:
    items = _sequence(value, nonempty=nonempty)
    if any(type(item) is not str or not item for item in items):
        _raise(_OWNER_INVALID)
    return cast(tuple[str, ...], items)


def _finite(value: object) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        _raise(_OWNER_INVALID)
    result = float(cast(int | float, value))
    if not math.isfinite(result):
        _raise(_OWNER_INVALID)
    return result


def _bool(value: object) -> bool:
    if type(value) is not bool:
        _raise(_OWNER_INVALID)
    return value


def _stable_codes(value: tuple[str, ...], *, required: bool = False) -> None:
    if (
        type(value) is not tuple
        or (required and not value)
        or len(set(value)) != len(value)
        or any(type(code) is not str or _STABLE_CODE.fullmatch(code) is None for code in value)
    ):
        _raise(_INVALID_GRAPH)


def _all_operation_ids() -> tuple[str, ...]:
    return tuple(
        f"{family_id}/{member_id}"
        for family_id, members in _FAMILY_OPERATION_MEMBERS.items()
        for member_id in members
    )


_ALL_OPERATION_IDS: Final = _all_operation_ids()


def frozen_operation_ids() -> tuple[str, ...]:
    """Return the exact authenticated operation order required by the graph."""

    return _ALL_OPERATION_IDS


def frozen_report_dependent_meaning_ids() -> tuple[str, ...]:
    """Return the exact frozen order of meanings that require report evidence."""

    rows = tuple(
        spec.meaning_id
        for spec in _FROZEN_SPECS
        if spec.meaning_id in _REPORT_DEPENDENT_MEANINGS
    )
    if len(rows) != 24 or len(set(rows)) != len(rows):
        raise RuntimeError("Frozen report-dependent meaning order is not closed.")
    return rows


def matched_metric_orientation(selector: str) -> str:
    """Return the frozen orientation for one matched-metric selector."""

    orientations = {
        frozen_selector: orientation
        for frozen_selector, orientation in _MATCHED_METRIC_SELECTORS.values()
    }
    try:
        return orientations[selector]
    except KeyError as error:
        raise ValueError(f"unknown matched-metric selector: {selector}") from error


def frozen_slot_requirements(
    family_id: str,
) -> tuple[tuple[str, str, str, str, str | None], ...]:
    """Return common and family slot requirements without authenticating owners."""

    if family_id not in _FAMILY_OPERATION_MEMBERS:
        raise ValueError(f"unknown scenario family: {family_id}")
    rows: list[tuple[str, str, str, str, str | None]] = []
    for spec in _FROZEN_SPECS:
        if not (spec.meaning_id.startswith("*:") or spec.meaning_id.startswith(f"{family_id}:")):
            continue
        for slot in spec.slots:
            orientation = (
                _MATCHED_METRIC_SELECTORS[spec.meaning_id][1]
                if spec.meaning_id in _MATCHED_METRIC_SELECTORS
                else None
            )
            rows.append(
                (
                    spec.meaning_id,
                    slot.owner_class,
                    slot.cardinality,
                    slot.selector,
                    orientation,
                )
            )
    return tuple(rows)


def _record_coordinate(record: ValidatedGraphSourceRecord) -> tuple[str | None, str | None]:
    source = record.source_record
    scenario = source.get("scenario_identity")
    family_id: object = source.get("family_id", source.get("scenario_family_id"))
    case_id: object = source.get("case_id")
    if isinstance(scenario, Mapping):
        family_id = scenario.get("family_id", family_id)
        case_id = scenario.get("case_id", case_id)
    natural_case = record.natural_identity.get("case_id")
    ordered_case_ids = source.get("ordered_case_ids")
    if (
        case_id is None
        and type(ordered_case_ids) in (tuple, list)
        and len(cast(Sequence[object], ordered_case_ids)) == 1
    ):
        case_id = cast(Sequence[object], ordered_case_ids)[0]
    if case_id is None:
        case_id = natural_case
    elif natural_case is not None and natural_case != case_id:
        _raise(_CROSS_CASE)
    return (
        family_id if family_id is None or type(family_id) is str else None,
        case_id if case_id is None or type(case_id) is str else None,
    )


def _is_frozen_common_slot(record: ValidatedGraphSourceRecord) -> bool:
    """Return whether a record occupies an exact live common-meaning slot."""

    coordinate = (record.owner_class, record.cardinality, record.selector)
    return any(
        spec.meaning_id.startswith("*:")
        and any(
            coordinate == (slot.owner_class, slot.cardinality, slot.selector)
            for slot in spec.slots
        )
        for spec in _FROZEN_SPECS
    )


def _validate_private_value(record: ValidatedGraphSourceRecord) -> None:
    if record.owner_class != "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION":
        if record.private_value is not None:
            _raise(_OWNER_INVALID)
        return
    if record.private_value is None:
        _raise(_OWNER_INVALID)
    source = record.source_record
    values = _plain(record.private_value)
    expected = structured_sha256_hex(
        _ARRAY_VALUE_DOMAIN,
        {
            "member_name": source.get("member_name"),
            "dtype": source.get("dtype"),
            "shape": _plain(source.get("shape")),
            "semantic_version": source.get("semantic_version"),
            "axes": _plain(source.get("axes")),
            "values": values,
        },
    )
    if source.get("array_value_sha256") != expected:
        _raise(_OWNER_INVALID)


def _validate_source_record(graph: ValidatedMeaningGraph, record: object) -> None:
    if type(record) is not ValidatedGraphSourceRecord:
        _raise(_INVALID_GRAPH)
    row = record
    binding = _FROZEN_OWNER_BINDINGS.get(row.owner_class)
    support_only = (
        row.cardinality == _SUPPORT_ONLY_CARDINALITY
        or row.selector == _SUPPORT_ONLY_SELECTOR
    )
    report_claim_support = (
        row.owner_class,
        row.cardinality,
        row.selector,
        row.orientation,
    ) == _REPORT_CLAIM_SUPPORT_COORDINATE
    if (
        type(row.owner_class) is not str
        or not row.owner_class
        or type(row.owner_schema_ref) is not str
        or not row.owner_schema_ref.startswith("schemas/")
        or type(row.cardinality) is not str
        or not row.cardinality
        or type(row.selector) is not str
        or not row.selector
        or (
            row.orientation is not None
            and (type(row.orientation) is not str or not row.orientation)
        )
        or not isinstance(row.natural_identity, Mapping)
        or any(type(key) is not str for key in row.natural_identity)
        or not isinstance(row.source_record, Mapping)
        or any(type(key) is not str for key in row.source_record)
        or not _is_sha256(row.source_record_sha256)
        or type(row.ordered_support_owner_sha256) is not tuple
        or len(set(row.ordered_support_owner_sha256)) != len(row.ordered_support_owner_sha256)
        or any(not _is_sha256(value) for value in row.ordered_support_owner_sha256)
        or binding is None
        or row.owner_schema_ref != binding[0]
        or set(row.natural_identity) != set(binding[1])
        or (
            support_only
            and (
                row.owner_class not in _SUPPORT_ONLY_OWNER_CLASSES
                or row.cardinality != _SUPPORT_ONLY_CARDINALITY
                or row.selector != _SUPPORT_ONLY_SELECTOR
                or row.orientation is not None
                or row.ordered_support_owner_sha256
            )
        )
        or (
            not support_only
            and row.owner_class in _SUPPORT_ONLY_OWNER_CLASSES
            and row.selector == _SUPPORT_ONLY_SELECTOR
        )
        or (row.owner_class == "REPORT_CLAIM_PROJECTION" and not report_claim_support)
        or (report_claim_support and row.ordered_support_owner_sha256)
    ):
        _raise(_OWNER_INVALID)
    admitted_coordinates = {
        (owner_class, cardinality, selector, orientation)
        for _meaning_id, owner_class, cardinality, selector, orientation in (
            frozen_slot_requirements(graph.family_id)
        )
    }
    if not support_only and not report_claim_support and (
        row.owner_class,
        row.cardinality,
        row.selector,
        row.orientation,
    ) not in admitted_coordinates:
        _raise(_OWNER_INVALID)
    natural = _plain(row.natural_identity)
    source = _plain(row.source_record)
    try:
        schema_valid = _source_validator(row.owner_schema_ref).is_valid(source)
    except (KeyError, TypeError, ValueError):
        schema_valid = False
    if not schema_valid:
        _raise(_OWNER_INVALID)
    for field, identity_value in row.natural_identity.items():
        if field in row.source_record and row.source_record[field] != identity_value:
            _raise(_OWNER_INVALID)
    if row.owner_class == "REPORT_PREDICATE_OUTCOME":
        report_digest = row.source_record.get("report_predicate_outcome_sha256")
        report_preimage = dict(row.source_record)
        report_preimage["digest_state"] = "DIGEST_PREIMAGE"
        report_preimage["report_predicate_outcome_sha256"] = None
        if report_digest != structured_sha256_hex(
            "ebm-audit/report-predicate-outcome/1", report_preimage
        ):
            _raise(_OWNER_INVALID)
    if report_claim_support:
        claim_digest = row.source_record.get("report_claim_projection_sha256")
        claim_preimage = dict(row.source_record)
        claim_preimage["digest_state"] = "DIGEST_PREIMAGE"
        claim_preimage["report_claim_projection_sha256"] = None
        if claim_digest != structured_sha256_hex(
            _REPORT_CLAIM_PROJECTION_DOMAIN, claim_preimage
        ):
            _raise(_OWNER_INVALID)
    if row.source_record_sha256 != structured_sha256_hex(
        _SOURCE_RECORD_DOMAIN,
        {
            "owner_class": row.owner_class,
            "natural_identity": natural,
            "source_record": source,
        },
    ):
        _raise(_OWNER_INVALID)
    subject = row.source_record.get("benchmark_subject_digest")
    if subject is not None and subject != graph.benchmark_subject_digest:
        _raise(_REPLAY)
    for field, expected in (
        ("source_contract_sha256", graph.source_contract_sha256),
        ("scenario_source_sha256", graph.scenario_source_sha256),
        ("operation_plan_sha256", graph.operation_plan_sha256),
        ("proportional_operation_plan_sha256", graph.operation_plan_sha256),
    ):
        observed = row.source_record.get(field)
        if observed is not None and observed != expected:
            _raise(_REPLAY)
    family_id, case_id = _record_coordinate(row)
    if (
        family_id is not None
        and family_id != graph.family_id
        and not _is_frozen_common_slot(row)
    ):
        _raise(_CROSS_CASE)
    if case_id is not None and case_id not in graph.planned_case_ids:
        _raise(_CROSS_CASE)
    _validate_private_value(row)


def _validate_claim(graph: ValidatedMeaningGraph, claim: object) -> None:
    if type(claim) is not ValidatedGraphClaimRecord:
        _raise(_INVALID_GRAPH)
    row = claim
    if (
        type(row.predicate_id) is not str
        or not row.predicate_id
        or row.state not in {"AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED"}
        or type(row.input_record_ids) is not tuple
        or len(set(row.input_record_ids)) != len(row.input_record_ids)
        or any(type(value) is not str or not value for value in row.input_record_ids)
        or type(row.source_record_digests) is not tuple
        or len(set(row.source_record_digests)) != len(row.source_record_digests)
        or any(not _is_sha256(value) for value in row.source_record_digests)
        or type(row.operation_ids) is not tuple
        or any(value not in graph.operation_ids for value in row.operation_ids)
    ):
        _raise(_INVALID_GRAPH)
    _stable_codes(row.reason_codes, required=row.state != "AVAILABLE")
    if row.state == "AVAILABLE":
        if type(row.value) is not bool or row.reason_codes or row.failure_code is not None:
            _raise(_INVALID_GRAPH)
    elif row.value is not None:
        _raise(_INVALID_GRAPH)
    if row.state in {"INVALID", "FAILED"}:
        if type(row.failure_code) is not str or _STABLE_CODE.fullmatch(row.failure_code) is None:
            _raise(_INVALID_GRAPH)
    elif row.failure_code is not None:
        _raise(_INVALID_GRAPH)


def _validate_graph_structure(graph: ValidatedMeaningGraph) -> None:
    if type(graph) is not ValidatedMeaningGraph:
        _raise(_INVALID_GRAPH)
    if (
        graph.family_id not in _FAMILY_OPERATION_MEMBERS
        or not _is_sha256_digest(graph.benchmark_subject_digest)
        or not _is_sha256(graph.source_contract_sha256)
        or not _is_sha256(graph.scenario_source_sha256)
        or not _is_sha256(graph.operation_plan_sha256)
        or graph.capability_mode not in {"FULL", "PARTIAL"}
        or graph.declared_model_shape not in {"APPLICABLE", "NOT_APPLICABLE"}
        or graph.operation_ids != _ALL_OPERATION_IDS
        or type(graph.planned_case_ids) is not tuple
        or not graph.planned_case_ids
        or len(set(graph.planned_case_ids)) != len(graph.planned_case_ids)
        or any(type(value) is not str or not value for value in graph.planned_case_ids)
        or type(graph.valid_case_ids) is not tuple
        or len(set(graph.valid_case_ids)) != len(graph.valid_case_ids)
        or any(value not in graph.planned_case_ids for value in graph.valid_case_ids)
        or graph.case_id not in graph.planned_case_ids
        or type(graph.operation_outcomes) is not tuple
        or type(graph.source_records) is not tuple
        or type(graph.cardinality_declarations) is not tuple
        or graph.report_claims != ()
    ):
        _raise(_INVALID_GRAPH)
    outcome_ids: list[str] = []
    for outcome in graph.operation_outcomes:
        if (
            type(outcome) is not ValidatedGraphOperationOutcome
            or outcome.operation_id not in graph.operation_ids
            or outcome.family_id != outcome.operation_id.split("/", 1)[0]
            or outcome.case_id not in graph.planned_case_ids
            or outcome.state not in {"SUCCESS", "UNAVAILABLE", "INVALID", "FAILED"}
            or not _is_sha256(outcome.source_record_sha256)
            or (
                outcome.state in {"INVALID", "FAILED"}
                and (
                    type(outcome.failure_code) is not str
                    or _STABLE_CODE.fullmatch(outcome.failure_code) is None
                )
            )
            or (outcome.state in {"SUCCESS", "UNAVAILABLE"} and outcome.failure_code is not None)
        ):
            _raise(_INVALID_GRAPH)
        outcome_ids.append(outcome.operation_id)
    family_operation_ids = tuple(
        operation_id
        for operation_id in graph.operation_ids
        if operation_id.split("/", 1)[0] == graph.family_id
    )
    if tuple(outcome_ids) != graph.operation_ids and not (
        graph.capability_mode == "PARTIAL"
        and tuple(outcome_ids) == family_operation_ids
    ):
        _raise(_INVALID_GRAPH)
    for source_record in graph.source_records:
        _validate_source_record(graph, source_record)
    source_digests = {row.source_record_sha256 for row in graph.source_records}
    admitted_alias_slots = {
        (owner_class, cardinality, selector, orientation)
        for (
            _meaning_id,
            owner_class,
            cardinality,
            selector,
            orientation,
        ) in frozen_slot_requirements(graph.family_id)
    }
    admitted_alias_slots.add(_REPORT_CLAIM_SUPPORT_COORDINATE)
    records_by_digest: dict[str, list[ValidatedGraphSourceRecord]] = {}
    for row in graph.source_records:
        records_by_digest.setdefault(row.source_record_sha256, []).append(row)
    for aliases in records_by_digest.values():
        if len(aliases) == 1:
            continue
        first = aliases[0]
        immutable_owner_facts = (
            first.owner_class,
            first.owner_schema_ref,
            _plain(first.natural_identity),
            _plain(first.source_record),
            first.ordered_support_owner_sha256,
            _plain(first.private_value),
        )
        if any(
            (
                row.owner_class,
                row.owner_schema_ref,
                _plain(row.natural_identity),
                _plain(row.source_record),
                row.ordered_support_owner_sha256,
                _plain(row.private_value),
            )
            != immutable_owner_facts
            for row in aliases[1:]
        ):
            _raise(_OWNER_INVALID)
        alias_slots = tuple(
            (row.owner_class, row.cardinality, row.selector, row.orientation)
            for row in aliases
        )
        if any(slot not in admitted_alias_slots for slot in alias_slots):
            _raise(_OWNER_INVALID)
        if len(alias_slots) != len(set(alias_slots)):
            _raise(_DUPLICATE_OWNER)
    report_claim_rows = tuple(
        row for row in graph.source_records if row.owner_class == "REPORT_CLAIM_PROJECTION"
    )
    report_claim_consumers = tuple(
        row
        for row in graph.source_records
        if row.owner_class in _REPORT_CLAIM_CONSUMER_OWNER_CLASSES
    )
    if report_claim_rows or report_claim_consumers:
        if len(report_claim_rows) != 1:
            _raise(_DUPLICATE_OWNER if report_claim_rows else _REPLAY)
        if not report_claim_consumers:
            _raise(_OWNER_INVALID)
        claim = report_claim_rows[0]
        claim_digest = claim.source_record.get("report_claim_projection_sha256")
        if any(
            row.source_record.get("report_claim_projection_sha256") != claim_digest
            or claim.source_record_sha256 not in row.ordered_support_owner_sha256
            for row in report_claim_consumers
        ):
            _raise(_REPLAY)
    support_only_digests = {
        row.source_record_sha256
        for row in graph.source_records
        if row.cardinality == _SUPPORT_ONLY_CARDINALITY
        and row.selector == _SUPPORT_ONLY_SELECTOR
    }
    referenced_support_digests = {
        digest
        for row in graph.source_records
        if row.owner_class == "CANONICAL_SCIENTIFIC_PAYLOAD"
        for digest in row.ordered_support_owner_sha256
    }
    if any(digest not in source_digests for digest in referenced_support_digests):
        _raise(_REPLAY)
    non_support_digests = {
        row.source_record_sha256
        for row in graph.source_records
        if not (
            row.cardinality == _SUPPORT_ONLY_CARDINALITY
            and row.selector == _SUPPORT_ONLY_SELECTOR
        )
    }
    expected_support_only_order = tuple(
        digest
        for digest in dict.fromkeys(
            digest
            for row in graph.source_records
            if row.owner_class == "CANONICAL_SCIENTIFIC_PAYLOAD"
            for digest in row.ordered_support_owner_sha256
        )
        if digest not in non_support_digests
    )
    actual_support_only_order = tuple(
        row.source_record_sha256
        for row in graph.source_records
        if row.cardinality == _SUPPORT_ONLY_CARDINALITY
        and row.selector == _SUPPORT_ONLY_SELECTOR
    )
    if (
        support_only_digests != set(expected_support_only_order)
        or actual_support_only_order != expected_support_only_order
        or not support_only_digests.issubset(referenced_support_digests)
    ):
        _raise(_OWNER_INVALID)
    if any(
        digest not in source_digests
        for row in graph.source_records
        for digest in row.ordered_support_owner_sha256
    ):
        _raise(_REPLAY)
    for digest in referenced_support_digests:
        candidates = records_by_digest.get(digest)
        if candidates is None:
            continue
        if any(row.owner_class not in _SUPPORT_ONLY_OWNER_CLASSES for row in candidates):
            _raise(_OWNER_INVALID)
        if any(
            row.owner_class == "FIT_RESPONSE_BINDING"
            and not (
                row.cardinality == _SUPPORT_ONLY_CARDINALITY
                and row.selector == _SUPPORT_ONLY_SELECTOR
            )
            for row in candidates
        ):
            _raise(_OWNER_INVALID)
    coordinates = [
        (
            row.owner_class,
            row.cardinality,
            row.selector,
            structured_sha256_hex(
                "ebm-audit/natural-owner-coordinate/1", _plain(row.natural_identity)
            ),
        )
        for row in graph.source_records
    ]
    if len(coordinates) != len(set(coordinates)):
        _raise(_DUPLICATE_OWNER)
    allowed_declared_slots = {
        (slot.owner_class, slot.cardinality, slot.selector)
        for spec in _FROZEN_SPECS
        if spec.meaning_id.startswith("*:") or spec.meaning_id.startswith(f"{graph.family_id}:")
        for slot in spec.slots
        if slot.cardinality in _DECLARED_SET_CARDINALITIES
    }
    declarations: dict[tuple[str, str, str], ValidatedGraphCardinalityDeclaration] = {}
    by_slot_digest = {
        (
            row.owner_class,
            row.cardinality,
            row.selector,
            row.source_record_sha256,
        ): row
        for row in graph.source_records
    }
    for declaration in graph.cardinality_declarations:
        if type(declaration) is not ValidatedGraphCardinalityDeclaration:
            _raise(_INVALID_GRAPH)
        key = (
            declaration.owner_class,
            declaration.cardinality,
            declaration.selector,
        )
        member_keys = declaration.ordered_member_keys
        ordered = declaration.ordered_source_record_sha256
        if (
            declaration.cardinality == _SUPPORT_ONLY_CARDINALITY
            or declaration.selector == _SUPPORT_ONLY_SELECTOR
            or
            key not in allowed_declared_slots
            or key in declarations
            or type(member_keys) is not tuple
            or len(member_keys) != len(ordered)
            or len(set(member_keys)) != len(member_keys)
            or any(type(value) is not str or not value for value in member_keys)
            or type(ordered) is not tuple
            or len(set(ordered)) != len(ordered)
            or any(not _is_sha256(value) for value in ordered)
            or (declaration.cardinality != "ALL_CASE_WARNINGS" and not ordered)
            or any((*key, value) not in by_slot_digest for value in ordered)
        ):
            _raise(_INVALID_GRAPH)
        exact_digests = {
            row.source_record_sha256
            for row in graph.source_records
            if (row.owner_class, row.cardinality, row.selector) == key
        }
        if exact_digests != set(ordered):
            _raise(_CARDINALITY)
        declarations[key] = declaration
    undeclared_set_slots = {
        (row.owner_class, row.cardinality, row.selector)
        for row in graph.source_records
        if row.cardinality in _DECLARED_SET_CARDINALITIES
    } - set(declarations)
    if undeclared_set_slots:
        _raise(_CARDINALITY)


def _seal_and_validate_graph(graph: ValidatedMeaningGraph) -> ValidatedMeaningGraph:
    """Seal one trusted locally-issued graph and validate its complete structure."""

    if (
        type(graph) is not ValidatedMeaningGraph
        or graph.evidence_graph_digest != _UNSEALED_GRAPH_DIGEST
    ):
        _raise(_INVALID_GRAPH)
    sealed = replace(
        graph,
        evidence_graph_digest=validated_meaning_graph_digest(graph),
    )
    _validate_graph_structure(sealed)
    return sealed


def _validate_graph(graph: ValidatedMeaningGraph) -> None:
    _validate_graph_structure(graph)
    if graph.evidence_graph_digest != validated_meaning_graph_digest(graph):
        _raise(_INVALID_GRAPH)


def _matching_records(
    graph: ValidatedMeaningGraph,
    slot: _Slot,
    *,
    missing_ok: bool = False,
) -> tuple[ValidatedGraphSourceRecord, ...]:
    if (
        slot.cardinality == _SUPPORT_ONLY_CARDINALITY
        or slot.selector == _SUPPORT_ONLY_SELECTOR
    ):
        _raise(_INVALID_GRAPH)
    slot_key = (slot.owner_class, slot.cardinality, slot.selector)
    exact = tuple(
        row
        for row in graph.source_records
        if row.owner_class == slot.owner_class
        and row.cardinality == slot.cardinality
        and row.selector == slot.selector
    )
    if slot.cardinality in _DECLARED_SET_CARDINALITIES:
        declarations = tuple(
            row
            for row in graph.cardinality_declarations
            if (row.owner_class, row.cardinality, row.selector) == slot_key
        )
        if not declarations and not exact:
            if missing_ok:
                return ()
            _raise(_MISSING_OWNER)
        if len(declarations) != 1:
            _raise(_CARDINALITY)
        by_digest = {row.source_record_sha256: row for row in exact}
        ordered = declarations[0].ordered_source_record_sha256
        if len(by_digest) != len(exact) or set(by_digest) != set(ordered):
            _raise(_CARDINALITY)
        return tuple(by_digest[digest] for digest in ordered)
    if not exact:
        same_owner = tuple(
            row for row in graph.source_records if row.owner_class == slot.owner_class
        )
        if same_owner:
            if any(row.selector == slot.selector for row in same_owner):
                _raise(_CARDINALITY)
            _raise(_SELECTOR)
        if missing_ok:
            return ()
        _raise(_MISSING_OWNER)
    if slot.cardinality == "EXACTLY_ONE":
        if len(exact) != 1:
            _raise(_CARDINALITY)
        return exact
    if slot.cardinality == "ONE_PER_CASE":
        keyed = {_record_coordinate(row)[1]: row for row in exact}
        if len(keyed) != len(exact) or set(keyed) != {graph.case_id}:
            _raise(_CROSS_CASE if set(keyed) - {graph.case_id} else _CARDINALITY)
        return (keyed[graph.case_id],)
    if slot.cardinality == "ONE_PER_PLANNED_CASE":
        keyed = {_record_coordinate(row)[1]: row for row in exact}
        if len(keyed) != len(exact) or set(keyed) != set(graph.planned_case_ids):
            _raise(_CROSS_CASE if set(keyed) - set(graph.planned_case_ids) else _CARDINALITY)
        return tuple(keyed[case_id] for case_id in graph.planned_case_ids)
    if slot.cardinality == "ONE_PER_SUBTYPE_CASE":
        expected_case_ids = tuple(
            dict.fromkeys(
                outcome.case_id
                for outcome in graph.operation_outcomes
                if outcome.family_id == graph.family_id
            )
        )
        keyed = {_record_coordinate(row)[1]: row for row in exact}
        if len(keyed) != len(exact) or set(keyed) != set(expected_case_ids):
            _raise(_CROSS_CASE if set(keyed) - set(expected_case_ids) else _CARDINALITY)
        return tuple(keyed[case_id] for case_id in expected_case_ids)
    if slot.cardinality == "ONE_PER_DECLARED_RULE":
        expected_rule_ids = ("boundary_q50", "boundary_q35", "boundary_q65")
        rule_rows: dict[str, ValidatedGraphSourceRecord] = {}
        for row in exact:
            rule_id = row.natural_identity.get(
                "rule_id", row.natural_identity.get("cardinality_member_id")
            )
            if type(rule_id) is not str:
                _raise(_CARDINALITY)
            rule_rows[rule_id] = row
        if len(rule_rows) != len(exact) or set(rule_rows) != set(expected_rule_ids):
            _raise(_CARDINALITY)
        return tuple(rule_rows[rule_id] for rule_id in expected_rule_ids)
    _raise(_CARDINALITY)


def _selected_records(
    graph: ValidatedMeaningGraph, spec: _MeaningSpec
) -> tuple[ValidatedGraphSourceRecord, ...]:
    return tuple(record for slot in spec.slots for record in _matching_records(graph, slot))


def _declared_member_map(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
) -> tuple[tuple[str, ...], Mapping[str, ValidatedGraphSourceRecord]]:
    if not records:
        _raise(_MISSING_OWNER)
    keyed: dict[str, ValidatedGraphSourceRecord] = {}
    ordered_keys: list[str] = []
    for record in records:
        slot_key = (record.owner_class, record.cardinality, record.selector)
        declarations = tuple(
            row
            for row in graph.cardinality_declarations
            if (row.owner_class, row.cardinality, row.selector) == slot_key
        )
        if len(declarations) != 1:
            _raise(_CARDINALITY)
        declaration = declarations[0]
        try:
            index = declaration.ordered_source_record_sha256.index(record.source_record_sha256)
        except ValueError:
            _raise(_REPLAY)
        member_key = declaration.ordered_member_keys[index]
        if member_key in keyed:
            _raise(_DUPLICATE_OWNER)
        keyed[member_key] = record
        ordered_keys.append(member_key)
    return tuple(ordered_keys), keyed


def _join_declared_members(
    graph: ValidatedMeaningGraph,
    *groups: Sequence[ValidatedGraphSourceRecord],
) -> tuple[tuple[ValidatedGraphSourceRecord, ...], ...]:
    if not groups:
        _raise(_CARDINALITY)
    first_order, first = _declared_member_map(graph, groups[0])
    maps = [first]
    for group in groups[1:]:
        _order, keyed = _declared_member_map(graph, group)
        if set(keyed) != set(first):
            _raise(_CROSS_CASE)
        maps.append(keyed)
    return tuple(tuple(keyed[member_key] for keyed in maps) for member_key in first_order)


def _unique_digests(records: Sequence[ValidatedGraphSourceRecord]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(record.source_record_sha256 for record in records))


def _claim(graph: ValidatedMeaningGraph, predicate_id: str) -> ValidatedGraphClaimRecord:
    matches = tuple(row for row in graph.report_claims if row.predicate_id == predicate_id)
    if len(matches) != 1:
        _raise(_MISSING_OWNER if not matches else _DUPLICATE_OWNER)
    return matches[0]


def _propagate_claim(claim: ValidatedGraphClaimRecord) -> None:
    if claim.state == "AVAILABLE":
        return
    code = claim.failure_code or claim.reason_codes[0]
    _raise(code, state=claim.state)


def _result(
    meaning_id: str,
    *,
    state: GroupedMeaningState,
    value: object | None = None,
    reason_code: str | None = None,
    failure_code: str | None = None,
    source_record_digests: tuple[str, ...] = (),
) -> GroupedMeaningResult:
    return GroupedMeaningResult(
        meaning_id=meaning_id,
        state=state,
        value=value,
        reason_codes=() if reason_code is None else (reason_code,),
        failure_code=failure_code,
        source_record_digests=source_record_digests,
    )


def _operation_state(graph: ValidatedMeaningGraph) -> tuple[GroupedMeaningState, str] | None:
    family_ids = {
        f"{graph.family_id}/{member}" for member in _FAMILY_OPERATION_MEMBERS[graph.family_id]
    }
    rows = tuple(row for row in graph.operation_outcomes if row.operation_id in family_ids)
    if len(rows) != len(family_ids):
        return "INVALID", _INVALID_GRAPH
    invalid = next((row for row in rows if row.state == "INVALID"), None)
    if invalid is not None:
        return "INVALID", invalid.failure_code or _OWNER_INVALID
    failed = next((row for row in rows if row.state == "FAILED"), None)
    if failed is not None:
        return "FAILED", failed.failure_code or _OPERATION_FAILED
    if any(row.state == "UNAVAILABLE" for row in rows):
        return (
            ("UNAVAILABLE", _UNAVAILABLE)
            if graph.capability_mode == "PARTIAL"
            else ("INVALID", _MISSING_OWNER)
        )
    return None


def _truth_mode(record: ValidatedGraphSourceRecord) -> str:
    order = _mapping(record.source_record.get("order_truth"))
    kind = order.get("truth_kind")
    reason = order.get("non_identifiability_reason")
    identifiable = order.get("strict_order_identifiable")
    recoverable = order.get("recoverable_signal")
    blocks = _sequence(order.get("partial_order_blocks"), nonempty=False)
    if (
        kind == "STRICT_TOTAL_ORDER"
        and reason is None
        and identifiable is True
        and recoverable is True
        and not blocks
    ):
        return "STRICT_TOTAL_ORDER"
    if (
        kind == "PARTIAL_ORDER"
        and reason in {"EQUIVALENCE_BLOCK", "EXACT_DUPLICATE"}
        and identifiable is False
        and recoverable is True
        and blocks
    ):
        return "PARTIAL_ORDER_EQUIVALENCE"
    if (
        kind == "MIXTURE_OF_STRICT_ORDERS"
        and reason in {"MINORITY_ALTERNATE_SEQUENCE", "OPPOSING_SEQUENCES"}
        and identifiable is False
        and recoverable is True
        and not blocks
    ):
        return "MIXTURE_NON_IDENTIFIABLE"
    if (
        kind == "NONE"
        and reason in {"PURE_NO_SIGNAL", "REFITTED_NULL_TRANSFORMATION"}
        and identifiable is False
        and recoverable is False
        and not blocks
    ):
        return (
            "NO_RECOVERABLE_SIGNAL"
            if reason == "PURE_NO_SIGNAL"
            else "REFITTED_NULL_TRANSFORMATION"
        )
    _raise(_OWNER_INVALID)


def _member_value(record: ValidatedGraphSourceRecord) -> tuple[str, str, float, float]:
    source = record.source_record
    if source.get("status") != "ASSESSABLE" or source.get("reason_codes") not in ([], ()):
        _raise(_UNAVAILABLE, state="UNAVAILABLE")
    left_id = source.get("left_member_id")
    right_id = source.get("right_member_id")
    if type(left_id) is not str or type(right_id) is not str or left_id == right_id:
        _raise(_OWNER_INVALID)
    left = _mapping(source.get("left"))
    right = _mapping(source.get("right"))
    left_value = _finite(left.get("recomputed_value"))
    right_value = _finite(right.get("recomputed_value"))
    if _finite(source.get("derived_value")) != left_value - right_value:
        _raise(_ORIENTATION)
    return left_id, right_id, left_value, right_value


def _matched_metric_value(
    meaning_id: str, records: Sequence[ValidatedGraphSourceRecord]
) -> list[float]:
    _selector, expected_orientation = _MATCHED_METRIC_SELECTORS[meaning_id]
    values: list[float] = []
    for record in records:
        if record.orientation != expected_orientation:
            _raise(_ORIENTATION)
        left_id, right_id, left, right = _member_value(record)
        by_member = {left_id: left, right_id: right}
        if expected_orientation == "small-minus-large":
            value = by_member["small"] - by_member["large"]
        elif expected_orientation == "weak-minus-moderate":
            value = by_member["weak"] - by_member["moderate"]
        elif expected_orientation == "slow-minus-narrow":
            value = by_member["slow"] - by_member["narrow"]
        elif expected_orientation == "mixture-minus-single":
            value = by_member["mixture"] - by_member["single"]
        elif expected_orientation == "adjusted-minus-unadjusted-agreement":
            value = (1.0 - by_member["adjusted"]) - (1.0 - by_member["unadjusted"])
        elif expected_orientation == "correct-minus-wrong-agreement":
            value = (1.0 - by_member["correct"]) - (1.0 - by_member["wrong"])
        elif expected_orientation == "contaminated-agreement":
            value = 1.0 - by_member["contaminated"]
        else:
            value = by_member["contaminated"]
        values.append(_finite(value))
    return values


def _matrix(value: object) -> tuple[tuple[float, ...], ...]:
    rows = _sequence(value)
    result = tuple(tuple(_finite(cell) for cell in _sequence(row)) for row in rows)
    if not result or any(len(row) != len(result) for row in result):
        _raise(_OWNER_INVALID)
    return result


def _probability_matrix(value: object) -> tuple[tuple[float, ...], ...]:
    rows = _sequence(value)
    result = tuple(tuple(_finite(cell) for cell in _sequence(row)) for row in rows)
    if not result or not result[0] or any(len(row) != len(result[0]) for row in result):
        _raise(_OWNER_INVALID)
    for row in result:
        if any(probability < 0.0 or probability > 1.0 for probability in row):
            _raise(_OWNER_INVALID)
        if not math.isclose(math.fsum(row), 1.0, rel_tol=0.0, abs_tol=1e-12):
            _raise(_OWNER_INVALID)
    return result


def _pairwise_values(
    truth_record: ValidatedGraphSourceRecord,
    projection_record: ValidatedGraphSourceRecord,
    *,
    mode: Literal["TARGET", "BLOCK", "OPPOSING"],
) -> list[float]:
    truth = truth_record.source_record
    event_truth = _mapping(truth.get("event_truth"))
    event_ids = _strings(event_truth.get("event_ids"))
    matrix = _matrix(projection_record.private_value)
    if len(event_ids) != len(matrix):
        _raise(_OWNER_INVALID)
    for index, row in enumerate(matrix):
        if abs(row[index] - 0.5) > 1e-12:
            _raise(_OWNER_INVALID)
        for other in range(len(row)):
            if abs(row[other] + matrix[other][index] - 1.0) > 1e-12:
                _raise(_OWNER_INVALID)
    indexes = {event_id: index for index, event_id in enumerate(event_ids)}
    order = _mapping(truth.get("order_truth"))
    if mode == "TARGET":
        target_candidates = tuple(
            _strings(value)
            for value in (
                truth.get("target_pair"),
                _mapping(truth.get("event_truth")).get("target_pair"),
                _mapping(truth.get("mechanism_evidence")).get(
                    "target_pair_event_ids"
                ),
            )
            if value is not None
        )
        if not target_candidates or len(set(target_candidates)) != 1:
            _raise(_OWNER_INVALID)
        pair = target_candidates[0]
        if len(pair) != 2 or pair[0] == pair[1] or any(item not in indexes for item in pair):
            _raise(_OWNER_INVALID)
        return [matrix[indexes[pair[0]]][indexes[pair[1]]]]
    if mode == "BLOCK":
        blocks = _sequence(order.get("partial_order_blocks"))
        pairs = sorted(
            (
                tuple(sorted((left, right), key=lambda item: item.encode()))
                for block in blocks
                for left_index, left in enumerate(_strings(block))
                for right in _strings(block)[left_index + 1 :]
            ),
            key=lambda pair: (pair[0].encode(), pair[1].encode()),
        )
        if not pairs:
            _raise(_OWNER_INVALID)
        return [matrix[indexes[left]][indexes[right]] for left, right in pairs]
    pairs = [
        (left, right)
        for left_index, left in enumerate(sorted(event_ids, key=lambda item: item.encode()))
        for right in sorted(event_ids, key=lambda item: item.encode())[left_index + 1 :]
    ]
    if not pairs or order.get("non_identifiability_reason") != "OPPOSING_SEQUENCES":
        _raise(_OWNER_INVALID)
    return [abs(matrix[indexes[left]][indexes[right]] - 0.5) for left, right in pairs]


def _missingness_mask(record: ValidatedGraphSourceRecord) -> tuple[tuple[bool, ...], ...]:
    source = record.source_record
    if record.owner_class == "SYNTHETIC_TRUTH":
        missingness = _mapping(source.get("missingness_truth"))
        raw = missingness.get("mask", missingness.get("missingness_mask"))
    else:
        raw = source.get("missingness_mask")
    rows = _sequence(raw)
    mask = tuple(tuple(_bool(cell) for cell in _sequence(row)) for row in rows)
    if not mask or any(len(row) != len(mask[0]) for row in mask):
        _raise(_OWNER_INVALID)
    return mask


def _missing_count_structure(
    record: ValidatedGraphSourceRecord,
) -> tuple[int, tuple[int, ...], tuple[tuple[str, int], ...]]:
    mask = _missingness_mask(record)
    per_event = tuple(sum(row[index] for row in mask) for index in range(len(mask[0])))
    if record.owner_class == "SYNTHETIC_TRUTH":
        labels = _mapping(record.source_record.get("group_truth")).get(
            "observed_labels"
        )
        legacy_labels = record.source_record.get("analysis_group_labels")
        if legacy_labels is not None and legacy_labels != labels:
            _raise(_OWNER_INVALID)
    else:
        labels = record.source_record.get("analysis_group_labels")
    if labels is None:
        per_group: tuple[tuple[str, int], ...] = ()
    else:
        groups = _strings(labels)
        if len(groups) != len(mask):
            _raise(_OWNER_INVALID)
        per_group = tuple(
            (
                group,
                sum(
                    cell
                    for label, row in zip(groups, mask, strict=True)
                    if label == group
                    for cell in row
                ),
            )
            for group in sorted(set(groups), key=lambda item: item.encode())
        )
    return sum(per_event), per_event, per_group


def _data_pair(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
) -> tuple[ValidatedGraphSourceRecord, ValidatedGraphSourceRecord]:
    source = tuple(row for row in records if row.selector == "same-case-source-data/1")
    transformed = tuple(row for row in records if row.selector == "same-case-transformed-data/1")
    joined = _join_declared_members(graph, source, transformed)
    if len(joined) != 1:
        _raise(_CARDINALITY)
    return cast(tuple[ValidatedGraphSourceRecord, ValidatedGraphSourceRecord], joined[0])


def _truth_scoring_value(records: Sequence[ValidatedGraphSourceRecord]) -> str:
    modes = tuple(_truth_mode(row) for row in records)
    if not modes or len(set(modes)) != 1:
        _raise(_OWNER_INVALID)
    return modes[0]


def _only_owner(
    records: Sequence[ValidatedGraphSourceRecord], owner_class: str
) -> ValidatedGraphSourceRecord:
    matches = tuple(row for row in records if row.owner_class == owner_class)
    if len(matches) != 1:
        _raise(_MISSING_OWNER if not matches else _CARDINALITY)
    return matches[0]


def _operation_plan_entries(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
) -> tuple[Mapping[str, object], ...]:
    plan = _only_owner(records, "PROPORTIONAL_OPERATION_PLAN").source_record
    entries = tuple(_mapping(value) for value in _sequence(plan.get("ordered_entries")))
    instance_ids = _strings(plan.get("ordered_operation_instance_ids"))
    operation_count = len(graph.operation_ids)
    observed_operation_ids: list[str] = []
    for entry in entries:
        family_id = entry.get("family_id")
        member_id = entry.get("member_id")
        pair_id = entry.get("pair_id")
        if type(family_id) is not str or type(member_id) is not str:
            _raise(_REPLAY)
        if family_id == "moderate_mina_shape":
            if type(pair_id) is not str:
                _raise(_REPLAY)
            observed_operation_ids.append(f"{family_id}/{pair_id}/{member_id}")
        else:
            if pair_id is not None:
                _raise(_REPLAY)
            observed_operation_ids.append(f"{family_id}/{member_id}")
    if (
        plan.get("expected_fit_count") != operation_count
        or plan.get("operation_count") != operation_count
        or len(entries) != operation_count
        or len(instance_ids) != operation_count
        or len(set(instance_ids)) != operation_count
        or tuple(entry.get("operation_instance_id") for entry in entries) != instance_ids
        or tuple(entry.get("operation_ordinal") for entry in entries)
        != tuple(range(operation_count))
        or tuple(observed_operation_ids) != graph.operation_ids
    ):
        _raise(_REPLAY)
    return entries


def _bound_operation_entry(
    records: Sequence[ValidatedGraphSourceRecord],
    entries: Sequence[Mapping[str, object]],
    record: ValidatedGraphSourceRecord,
) -> Mapping[str, object]:
    """Resolve one executed owner to its exact authenticated plan entry."""

    operation_id = record.source_record.get("operation_instance_id")
    matches = tuple(
        entry for entry in entries if entry.get("operation_instance_id") == operation_id
    )
    if len(matches) != 1:
        _raise(_REPLAY)
    entry = matches[0]
    plan = _only_owner(records, "PROPORTIONAL_OPERATION_PLAN").source_record
    if record.source_record.get("proportional_operation_plan_sha256") != plan.get(
        "proportional_operation_plan_sha256"
    ):
        _raise(_REPLAY)
    for field in (
        "benchmark_subject_digest",
        "authenticated_batch_sha256",
        "case_id",
        "family_id",
        "operation_instance_id",
        "case_operation_join_key",
        "operation_plan_entry_sha256",
    ):
        if record.source_record.get(field) != entry.get(field):
            _raise(_REPLAY)
    analysis_spec = record.source_record.get("analysis_spec_sha256")
    if analysis_spec is not None and analysis_spec != entry.get("analysis_spec_sha256"):
        _raise(_REPLAY)
    return entry


def _bound_preparation_terminal(
    graph: ValidatedMeaningGraph,
    entries: Sequence[Mapping[str, object]],
    terminals: Mapping[str, ValidatedGraphSourceRecord],
    record: ValidatedGraphSourceRecord,
) -> tuple[Mapping[str, object], ValidatedGraphSourceRecord]:
    """Resolve preparation evidence across its scientific and plan ID domains."""

    source = record.source_record
    case_id = source.get("case_id")
    analysis_spec_sha256 = source.get("analysis_spec_sha256")
    matches = tuple(
        entry
        for entry in entries
        if entry.get("family_id") == graph.family_id
        and entry.get("case_id") == case_id
        and entry.get("analysis_spec_sha256") == analysis_spec_sha256
    )
    if len(matches) != 1:
        _raise(_REPLAY)
    entry = matches[0]
    operation_id = cast(str, entry.get("operation_instance_id"))
    terminal = terminals.get(operation_id)
    if (
        terminal is None
        or not _operation_join_matches(entry, terminal)
        or record.ordered_support_owner_sha256 != (terminal.source_record_sha256,)
    ):
        _raise(_REPLAY)
    return entry, terminal


def _persisted_digest_matches(
    record: ValidatedGraphSourceRecord,
    *,
    digest_field: str,
    digest_domain: str,
) -> bool:
    source = dict(record.source_record)
    digest = source.get(digest_field)
    if not _is_sha256(digest) or source.get("digest_state") != "PERSISTED":
        return False
    source["digest_state"] = "DIGEST_PREIMAGE"
    source[digest_field] = None
    return digest == structured_sha256_hex(digest_domain, source)


def _row_manifest_instances(
    record: ValidatedGraphSourceRecord,
) -> tuple[tuple[int, int], ...]:
    if record.owner_class != "PREPARATION_ROW_INSTANCE_MANIFEST" or not _persisted_digest_matches(
        record,
        digest_field="row_instance_manifest_sha256",
        digest_domain="ebm-audit/preparation-row-instance-manifest/2",
    ):
        _raise(_OWNER_INVALID)
    instances = tuple(
        (
            _mapping(value).get("source_row_index"),
            _mapping(value).get("occurrence_ordinal"),
        )
        for value in _sequence(
            record.source_record.get("ordered_row_instances"), nonempty=False
        )
    )
    if any(
        type(source_index) is not int
        or source_index < 0
        or type(occurrence) is not int
        or occurrence < 0
        for source_index, occurrence in instances
    ) or len(set(instances)) != len(instances):
        _raise(_OWNER_INVALID)
    return cast(tuple[tuple[int, int], ...], instances)


def _row_manifests_by_role(
    records: Sequence[ValidatedGraphSourceRecord],
    *,
    required_roles: tuple[str, ...],
) -> Mapping[str, ValidatedGraphSourceRecord]:
    selectors = {
        "INPUT": "same-case-input-row-instance-manifest/1",
        "TRAINING": "same-case-training-row-instance-manifest/1",
        "OUTPUT": "same-case-output-row-instance-manifest/1",
        "REFERENCE_FIT": "same-case-reference-fit-row-instance-manifest/1",
    }
    manifests = tuple(
        row for row in records if row.owner_class == "PREPARATION_ROW_INSTANCE_MANIFEST"
    )
    roles = tuple(row.source_record.get("row_role") for row in manifests)
    if not manifests or (
        all(type(role) is str for role in roles)
        and set(cast(tuple[str, ...], roles)) < set(required_roles)
    ):
        _raise(_MISSING_OWNER)
    if any(type(role) is not str for role in roles):
        _raise(_OWNER_INVALID)
    typed_roles = cast(tuple[str, ...], roles)
    if len(set(typed_roles)) != len(typed_roles):
        _raise(_CARDINALITY)
    if set(typed_roles) != set(required_roles):
        _raise(_OWNER_INVALID)
    if typed_roles != required_roles:
        _raise(_CARDINALITY)
    if any(
        row.selector != selectors[role]
        for role, row in zip(typed_roles, manifests, strict=True)
    ):
        _raise(_SELECTOR)
    by_role = {cast(str, role): row for role, row in zip(roles, manifests, strict=True)}
    for manifest in manifests:
        _row_manifest_instances(manifest)
    return by_role


def _complete_refit_record_valid(record: ValidatedGraphSourceRecord) -> bool:
    expected_step_ids = (
        "prepared-input binding",
        "authenticated worker invocation",
        "fit-result validation",
        "convergence derivation",
        "pairwise concentration",
        "position concentration",
    )
    steps = tuple(
        _mapping(value)
        for value in _sequence(record.source_record.get("ordered_step_records"))
    )
    if (
        record.source_record.get("refit_mode") != "complete_refit"
        or tuple(step.get("step_id") for step in steps) != expected_step_ids
    ):
        return False
    allowed_fit_populations = {
        record.source_record.get("training_row_manifest_sha256"),
        record.source_record.get("reference_fit_row_manifest_sha256"),
    }
    if any(
        population is not None and population not in allowed_fit_populations
        for population in (step.get("fit_population_manifest_sha256") for step in steps)
    ):
        return False
    procedure_preimage = {
        "schema_version": "ebm-audit-complete-refit-procedure/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "refit_mode": "complete_refit",
        "ordered_step_ids": list(expected_step_ids),
        "refit_procedure_sha256": None,
    }
    return record.source_record.get("refit_procedure_sha256") == structured_sha256_hex(
        "ebm-audit/complete-refit-procedure/1", procedure_preimage
    )


def _complete_preprocessing_refit_equal(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
) -> list[bool]:
    source_rows = tuple(
        row
        for row in records
        if row.owner_class == "PREPROCESSING_EXECUTION_RECORD"
        and row.selector == "same-case-source-complete-refit/1"
    )
    transformed_rows = tuple(
        row
        for row in records
        if row.owner_class == "PREPROCESSING_EXECUTION_RECORD"
        and row.selector == "same-case-transformed-complete-refit/1"
    )
    if len(source_rows) != 1 or len(transformed_rows) != 1:
        _raise(_MISSING_OWNER if not source_rows or not transformed_rows else _CARDINALITY)
    source = source_rows[0]
    transformed = transformed_rows[0]
    if (
        source.source_record.get("execution_role") != "SOURCE"
        or transformed.source_record.get("execution_role") != "TRANSFORMED"
    ):
        _raise(_OWNER_INVALID)
    entries = _operation_plan_entries(graph, records)
    source_entry = _bound_operation_entry(records, entries, source)
    transformed_entry = _bound_operation_entry(records, entries, transformed)
    if (
        source_entry.get("member_id") != "source_refit"
        or transformed_entry.get("member_id") != "transformed_refit"
        or type(source_entry.get("operation_ordinal")) is not int
        or type(transformed_entry.get("operation_ordinal")) is not int
        or cast(int, transformed_entry["operation_ordinal"])
        != cast(int, source_entry["operation_ordinal"]) + 1
        or source.source_record.get("benchmark_subject_digest")
        != transformed.source_record.get("benchmark_subject_digest")
        or source.source_record.get("authenticated_batch_sha256")
        != transformed.source_record.get("authenticated_batch_sha256")
        or source.source_record.get("case_id")
        != transformed.source_record.get("case_id")
        or source.source_record.get("family_id") != transformed.source_record.get("family_id")
        or source.source_record.get("proportional_operation_plan_sha256")
        != transformed.source_record.get("proportional_operation_plan_sha256")
        or source_entry.get("operation_instance_id")
        == transformed_entry.get("operation_instance_id")
        or source_entry.get("case_operation_join_key")
        == transformed_entry.get("case_operation_join_key")
        or source_entry.get("operation_plan_entry_sha256")
        == transformed_entry.get("operation_plan_entry_sha256")
    ):
        _raise(_REPLAY)
    if not _complete_refit_record_valid(source) or not _complete_refit_record_valid(
        transformed
    ):
        _raise(_OWNER_INVALID)
    return [
        source.source_record.get("refit_procedure_sha256")
        == transformed.source_record.get("refit_procedure_sha256")
    ]


def _case_plan_rows(
    records: Sequence[ValidatedGraphSourceRecord],
) -> tuple[ValidatedGraphSourceRecord, ...]:
    rows = tuple(row for row in records if row.owner_class == "PUBLIC_BATCH_CASE_PLAN")
    if not rows or tuple(row.source_record.get("case_ordinal") for row in rows) != tuple(
        range(len(rows))
    ):
        _raise(_CARDINALITY)
    case_ids = tuple(row.source_record.get("case_id") for row in rows)
    if any(type(case_id) is not str or not case_id for case_id in case_ids) or len(
        set(case_ids)
    ) != len(case_ids):
        _raise(_DUPLICATE_OWNER)
    return rows


def _terminal_by_operation(
    records: Sequence[ValidatedGraphSourceRecord],
) -> Mapping[str, ValidatedGraphSourceRecord]:
    terminals = tuple(row for row in records if row.owner_class == "PUBLIC_TERMINAL_RESULT")
    keyed = {
        cast(str, row.source_record.get("operation_instance_id")): row for row in terminals
    }
    if len(keyed) != len(terminals) or any(type(key) is not str or not key for key in keyed):
        _raise(_DUPLICATE_OWNER)
    return keyed


def _operation_join_matches(
    entry: Mapping[str, object], terminal: ValidatedGraphSourceRecord
) -> bool:
    source = terminal.source_record
    return all(
        source.get(field) == entry.get(field)
        for field in (
            "case_id",
            "family_id",
            "operation_instance_id",
            "operation_ordinal",
            "case_operation_join_key",
            "operation_plan_entry_sha256",
        )
    )


def _report_value(
    graph: ValidatedMeaningGraph,
    meaning_id: str,
    records: Sequence[ValidatedGraphSourceRecord],
) -> tuple[object, tuple[str, ...]]:
    predicate = _REPORT_PREDICATE_BY_MEANING[meaning_id]
    outcomes = tuple(row for row in records if row.owner_class == "REPORT_PREDICATE_OUTCOME")
    if not outcomes:
        _raise(_MISSING_OWNER)
    if meaning_id.endswith(
        ("/decision_attribution", "/selected_threshold_flags")
    ) and tuple(
        cast(str, row.source_record.get("cardinality_member_id")) for row in outcomes
    ) != _analysis_rules(records):
        _raise(_REPLAY)
    if meaning_id.endswith("/fpr_evidence"):
        truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
        if len(truths) != 1 or _truth_mode(truths[0]) != "NO_RECOVERABLE_SIGNAL":
            _raise(_OWNER_INVALID)
        _operation_plan_entries(graph, records)
    directive = REPORT_CLAIM_DIRECTIVES[predicate]
    effect = directive["effect"]
    projection_hashes: set[tuple[object, object]] = set()
    values: list[bool] = []
    for outcome in outcomes:
        source = outcome.source_record
        ordered_cases = _strings(source.get("ordered_case_ids"))
        if (
            source.get("benchmark_subject_digest") != graph.benchmark_subject_digest
            or source.get("family_id") != graph.family_id
            or source.get("predicate_id") != outcome.selector
            or set(ordered_cases) - set(graph.planned_case_ids)
        ):
            _raise(_REPLAY)
        projection_hashes.add(
            (
                source.get("report_claim_projection_sha256"),
                source.get("report_rule_registry_sha256"),
            )
        )
        derived_state = source.get("derived_state")
        matching_claim_ids = _strings(source.get("matching_claim_ids"), nonempty=False)
        forbidden_count = source.get("forbidden_claim_count")
        reason_codes = _strings(source.get("reason_codes"), nonempty=False)
        if type(forbidden_count) is not int or forbidden_count < 0:
            _raise(_OWNER_INVALID)
        if derived_state == "NOT_ASSESSABLE":
            if not reason_codes:
                _raise(_OWNER_INVALID)
            _raise(reason_codes[0], state="UNAVAILABLE")
        if derived_state not in {"PASS", "WARN", "FAIL"}:
            _raise(_OWNER_INVALID)
        if effect == "FORBID":
            observed = forbidden_count > 0 or bool(matching_claim_ids)
            if (derived_state == "FAIL") != observed:
                _raise(_OWNER_INVALID)
            values.append(observed)
        elif effect == "REQUIRE":
            if forbidden_count != 0:
                _raise(_OWNER_INVALID)
            values.append(derived_state in {"PASS", "WARN"})
        else:
            values.append(derived_state in {"PASS", "WARN"})
    if len(projection_hashes) != 1:
        _raise(_REPLAY)
    if meaning_id.endswith("/decision_attribution"):
        if not all(values):
            _raise("REPORT.BOUNDARY_ATTRIBUTION_MISSING", state="FAILED")
        value: object = ["DESCRIPTIVE_ASSOCIATION" for _outcome in outcomes]
    elif meaning_id.endswith("/selected_threshold_flags"):
        value = values
    elif meaning_id.endswith("/fpr_evidence"):
        if values != [True]:
            _raise("CALIBRATION.CAUTIOUS_FALLBACK_MISSING", state="FAILED")
        value = {
            "schema_version": "ebm-audit-false-positive-qualification-state/2.0",
            "status": "NOT_STATISTICALLY_QUALIFIED",
            "reason_code": "CALIBRATION.OPTIONAL_RESEARCH_STRESS_NOT_RUN",
            "strong_language_eligible": False,
            "cautious_fallback_required": True,
            "optional_profile": "benchmark-contract/0.1.3",
        }
    else:
        value = values
    return value, _unique_digests(records)


def _preparation_values(meaning_id: str, records: Sequence[ValidatedGraphSourceRecord]) -> object:
    values: list[object] = []
    for row in records:
        source = row.source_record
        if meaning_id.endswith("/actual_removed_rows"):
            accounting = _mapping(source.get("data_accounting"))
            value = accounting.get("removed_participants")
            if type(value) is not int or value < 0:
                _raise(_OWNER_INVALID)
        elif meaning_id.endswith("/backend_nan_flags") or meaning_id.endswith(
            "/nonfinite_admitted_flags"
        ):
            invoked = _bool(source.get("backend_invoked"))
            request_finite = _bool(source.get("request_all_finite"))
            response_finite = _bool(source.get("response_all_finite"))
            if not invoked and (request_finite or response_finite):
                _raise(_OWNER_INVALID)
            value = invoked and (not request_finite or not response_finite)
        elif meaning_id.endswith("/terminal_contract_equal"):
            value = _bool(source.get("terminal_contract_equal", True))
        else:
            # One required digest proves that one refit procedure exists. It
            # cannot prove equality between the source and transformed roles
            # required by complete-preprocessing-refit-equality/1.
            _raise(_UNAVAILABLE, state="UNAVAILABLE")
        values.append(value)
    return values


def _kendall_agreement(left: Sequence[object], right: Sequence[object]) -> float:
    if len(left) != len(right) or len(left) < 2 or set(left) != set(right):
        _raise(_OWNER_INVALID)
    right_position = {value: index for index, value in enumerate(right)}
    discordant = sum(
        right_position[left[first]] > right_position[left[second]]
        for first in range(len(left))
        for second in range(first + 1, len(left))
    )
    pairs = len(left) * (len(left) - 1) // 2
    return 1.0 - discordant / pairs


def _nearest_rank(values: Sequence[float], probability: float) -> float:
    if not values or not 0.0 < probability <= 1.0:
        _raise(_OWNER_INVALID)
    ordered = sorted(values)
    return ordered[math.ceil(probability * len(ordered)) - 1]


def _rule_state(
    value: float,
    *,
    pass_floor: float | None = None,
    warn_floor: float | None = None,
    pass_ceiling: float | None = None,
    warn_ceiling: float | None = None,
) -> str:
    if pass_floor is not None:
        assert warn_floor is not None
        return "PASS" if value >= pass_floor else "WARN" if value >= warn_floor else "FAIL"
    assert pass_ceiling is not None and warn_ceiling is not None
    return "PASS" if value <= pass_ceiling else "WARN" if value <= warn_ceiling else "FAIL"


def _int_vector(value: object) -> tuple[int, ...]:
    items = _sequence(value)
    if any(type(item) is not int for item in items):
        _raise(_OWNER_INVALID)
    return cast(tuple[int, ...], items)


def _int_matrix(value: object) -> tuple[tuple[int, ...], ...]:
    rows = _sequence(value)
    result = tuple(_int_vector(row) for row in rows)
    if any(len(row) != len(result[0]) for row in result):
        _raise(_OWNER_INVALID)
    return result


def _mean_position_entropy(rows: tuple[tuple[int, ...], ...]) -> float:
    event_count = len(rows[0])
    if event_count < 2 or any(set(row) != set(range(event_count)) for row in rows):
        _raise(_OWNER_INVALID)
    denominator = math.log(event_count)
    entropies: list[float] = []
    for event in range(event_count):
        counts = [sum(row[position] == event for row in rows) for position in range(event_count)]
        entropy = -math.fsum(
            (count / len(rows)) * math.log(count / len(rows)) for count in counts if count
        )
        entropies.append(entropy / denominator)
    return math.fsum(entropies) / len(entropies)


def _event_position_entropy(rows: tuple[tuple[int, ...], ...], event_index: int) -> float:
    event_count = len(rows[0])
    if (
        event_count < 2
        or event_index < 0
        or event_index >= event_count
        or any(set(row) != set(range(event_count)) for row in rows)
    ):
        _raise(_OWNER_INVALID)
    counts = [sum(row[position] == event_index for row in rows) for position in range(event_count)]
    denominator = math.log(event_count)
    return -math.fsum(
        (count / len(rows)) * math.log(count / len(rows)) for count in counts if count
    ) / denominator


def _position_matrix(rows: tuple[tuple[int, ...], ...]) -> tuple[tuple[float, ...], ...]:
    event_count = len(rows[0])
    if event_count < 2 or any(set(row) != set(range(event_count)) for row in rows):
        _raise(_OWNER_INVALID)
    return tuple(
        tuple(
            sum(row[position] == event for row in rows) / len(rows)
            for position in range(event_count)
        )
        for event in range(event_count)
    )


def _position_matrix_distance(
    left: tuple[tuple[float, ...], ...],
    right: tuple[tuple[float, ...], ...],
) -> float:
    if len(left) != len(right) or not left:
        _raise(_OWNER_INVALID)
    event_count = len(left)
    if any(len(row) != event_count for row in (*left, *right)):
        _raise(_OWNER_INVALID)
    return math.fsum(
        0.5 * math.fsum(abs(a - b) for a, b in zip(left_row, right_row, strict=True))
        for left_row, right_row in zip(left, right, strict=True)
    ) / event_count


def _declared_member_key(
    graph: ValidatedMeaningGraph,
    record: ValidatedGraphSourceRecord,
) -> str:
    matches = tuple(
        declaration
        for declaration in graph.cardinality_declarations
        if (
            declaration.owner_class,
            declaration.cardinality,
            declaration.selector,
        )
        == (record.owner_class, record.cardinality, record.selector)
        and record.source_record_sha256 in declaration.ordered_source_record_sha256
    )
    if len(matches) != 1:
        _raise(_CARDINALITY)
    declaration = matches[0]
    index = declaration.ordered_source_record_sha256.index(record.source_record_sha256)
    return declaration.ordered_member_keys[index]


def _key_parts(graph: ValidatedMeaningGraph, record: ValidatedGraphSourceRecord) -> tuple[str, ...]:
    parts = tuple(part for part in _declared_member_key(graph, record).split("/") if part)
    if not parts:
        _raise(_CARDINALITY)
    return parts


def _projection_event_ids(record: ValidatedGraphSourceRecord) -> tuple[str, ...]:
    axes = _strings(record.source_record.get("axes"))
    matrix = _int_matrix(record.private_value)
    event_count = len(matrix[0])
    if len(axes) == event_count:
        return axes
    event_axes = tuple(axis.removeprefix("event:") for axis in axes if axis.startswith("event:"))
    if len(event_axes) == event_count:
        return event_axes
    _raise(_OWNER_INVALID)


def _terminal_is_usable(record: ValidatedGraphSourceRecord) -> bool:
    status = record.source_record.get(
        "terminal_status", record.source_record.get("core_final_status")
    )
    return status in {"SUCCESS", "CONVERGENCE_WARN"}


def _payload_is_usable(record: ValidatedGraphSourceRecord) -> bool:
    return record.source_record.get("core_final_status") in {"SUCCESS", "CONVERGENCE_WARN"}


def _signed_randomization_tail_count(differences: Sequence[float]) -> int:
    """Count the exact inclusive 24-pair sign tail with a bounded meet-in-middle."""

    if len(differences) != 24 or any(not math.isfinite(value) for value in differences):
        _raise(_OWNER_INVALID)
    observed = math.fsum(differences)
    first = tuple(differences[:12])
    second = tuple(differences[12:])

    def half_sums(values: tuple[float, ...]) -> list[float]:
        return [
            math.fsum(
                value if mask & (1 << index) else -value
                for index, value in enumerate(values)
            )
            for mask in range(1 << len(values))
        ]

    right = sorted(half_sums(second))
    threshold = observed - 24e-12
    return sum(
        len(right) - bisect_left(right, threshold - left)
        for left in half_sums(first)
    )


def _central_order(rows: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
    counts: dict[tuple[int, ...], int] = {}
    for row in rows:
        counts[row] = counts.get(row, 0) + 1
    maximum = max(counts.values())
    return min(row for row, count in counts.items() if count == maximum)


def _average_ranks(values: Sequence[float]) -> tuple[float, ...]:
    indexed = sorted(enumerate(values), key=lambda item: (item[1], item[0]))
    ranks = [0.0] * len(indexed)
    position = 0
    while position < len(indexed):
        end = position + 1
        while end < len(indexed) and indexed[end][1] == indexed[position][1]:
            end += 1
        average = ((position + 1) + end) / 2.0
        for tied_position in range(position, end):
            ranks[indexed[tied_position][0]] = average
        position = end
    return tuple(ranks)


def _spearman(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right) or len(left) < 2:
        _raise(_OWNER_INVALID)
    left_ranks = _average_ranks(left)
    right_ranks = _average_ranks(right)
    left_mean = math.fsum(left_ranks) / len(left_ranks)
    right_mean = math.fsum(right_ranks) / len(right_ranks)
    covariance = math.fsum(
        (left_value - left_mean) * (right_value - right_mean)
        for left_value, right_value in zip(left_ranks, right_ranks, strict=True)
    )
    left_scale = math.fsum((value - left_mean) ** 2 for value in left_ranks)
    right_scale = math.fsum((value - right_mean) ** 2 for value in right_ranks)
    if left_scale == 0.0 or right_scale == 0.0:
        return 0.0
    return covariance / math.sqrt(left_scale * right_scale)


def _known_truth_rule(
    graph: ValidatedMeaningGraph,
    meaning_id: str,
    records: Sequence[ValidatedGraphSourceRecord],
) -> list[str]:
    truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
    projections = tuple(
        row for row in records if row.owner_class == "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION"
    )
    if meaning_id.endswith("/order_rule_states"):
        payloads = tuple(
            row for row in records if row.owner_class == "CANONICAL_SCIENTIFIC_PAYLOAD"
        )
        agreements: list[float] = []
        for truth, payload, projection in _join_declared_members(
            graph, truths, payloads, projections
        ):
            truth_event_ids = _strings(
                _mapping(truth.source_record.get("event_truth")).get("event_ids")
            )
            order = _mapping(truth.source_record.get("order_truth"))
            strict_order = _strings(order.get("strict_order"))
            payload_event_ids = _strings(payload.source_record.get("event_ids"))
            chains = tuple(
                _mapping(row)
                for row in _sequence(payload.source_record.get("ordered_chain_payloads"))
            )
            if (
                len(strict_order) != len(truth_event_ids)
                or set(strict_order) != set(truth_event_ids)
                or len(payload_event_ids) != len(truth_event_ids)
                or len(chains) != 1
                or _strings(chains[0].get("event_ids")) != payload_event_ids
                or chains[0].get("central_order_method") is None
            ):
                _raise(_OWNER_INVALID)
            inferred = _int_vector(projection.private_value)
            if len(inferred) != len(payload_event_ids) or set(inferred) != set(
                range(len(payload_event_ids))
            ):
                _raise(_OWNER_INVALID)
            truth_axis_position = {
                event_id: index for index, event_id in enumerate(truth_event_ids)
            }
            truth_order_ordinals = tuple(
                truth_axis_position[event_id] for event_id in strict_order
            )
            agreements.append(_kendall_agreement(inferred, truth_order_ordinals))
        q50 = _nearest_rank(agreements, 0.50)
        q10 = _nearest_rank(agreements, 0.10)
        state = (
            "PASS"
            if q50 >= 0.90 and q10 >= 0.75
            else "WARN"
            if q50 >= 0.80 and q10 >= 0.60
            else "FAIL"
        )
        return [state]
    manifests = tuple(
        row for row in records if row.owner_class == "PREPARATION_ROW_INSTANCE_MANIFEST"
    )
    errors: list[float] = []
    for truth, projection, manifest in _join_declared_members(
        graph, truths, projections, manifests
    ):
        truth_stages = _mapping(truth.source_record.get("stage_truth")).get("participant_stages")
        source_stages = tuple(_finite(value) for value in _sequence(truth_stages))
        instances = tuple(
            _mapping(value)
            for value in _sequence(
                manifest.source_record.get("ordered_row_instances"), nonempty=False
            )
        )
        instance_keys = tuple(
            (instance.get("source_row_index"), instance.get("occurrence_ordinal"))
            for instance in instances
        )
        if len(set(instance_keys)) != len(instance_keys) or any(
            type(source_index) is not int
            or type(occurrence) is not int
            or source_index < 0
            or source_index >= len(source_stages)
            or occurrence < 0
            for source_index, occurrence in instance_keys
        ):
            _raise(_OWNER_INVALID)
        stages = tuple(source_stages[cast(int, source_index)] for source_index, _ in instance_keys)
        posterior = _probability_matrix(projection.private_value)
        if len(stages) != len(posterior):
            _raise(_OWNER_INVALID)
        expected = [
            math.fsum(index * probability for index, probability in enumerate(row))
            for row in posterior
        ]
        event_count = len(posterior[0]) - 1
        errors.append(
            math.fsum(
                abs(observed - target) for observed, target in zip(expected, stages, strict=True)
            )
            / len(stages)
            / event_count
        )
    q50 = _nearest_rank(errors, 0.50)
    q90 = _nearest_rank(errors, 0.90)
    state = (
        "PASS" if q50 <= 0.10 and q90 <= 0.20 else "WARN" if q50 <= 0.15 and q90 <= 0.30 else "FAIL"
    )
    return [state]


def _grouped_array_rule(
    graph: ValidatedMeaningGraph,
    meaning_id: str,
    records: Sequence[ValidatedGraphSourceRecord],
) -> object:
    projections = tuple(
        row for row in records if row.owner_class == "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION"
    )
    if not projections:
        _raise(_MISSING_OWNER)
    if meaning_id.endswith("/cross_chain_delta_small_minus_large"):
        by_role: dict[str, list[tuple[tuple[float, ...], ...]]] = {
            "small": [],
            "matched_large": [],
        }
        for row in projections:
            role = _key_parts(graph, row)[0]
            if role not in by_role:
                _raise(_ORIENTATION)
            by_role[role].append(_position_matrix(_int_matrix(row.private_value)))
        if any(len(values) < 2 for values in by_role.values()):
            _raise(_CARDINALITY)
        distances = {
            role: [
                _position_matrix_distance(matrices[left], matrices[right])
                for left in range(len(matrices))
                for right in range(left + 1, len(matrices))
            ]
            for role, matrices in by_role.items()
        }
        return [
            _nearest_rank(distances["small"], 0.50)
            - _nearest_rank(distances["matched_large"], 0.50)
        ]
    if meaning_id.endswith("/affected_tail_entropy_delta"):
        truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
        if len(truths) != 1:
            _raise(_CARDINALITY)
        mechanism = _mapping(truths[0].source_record.get("mechanism_evidence"))
        affected = _strings(mechanism.get("affected_tail_event_ids"))
        tail_rows: dict[str, list[tuple[tuple[int, ...], ...]]] = {
            "restricted": [],
            "broad": [],
        }
        event_ids_by_role: dict[str, tuple[str, ...]] = {}
        for row in projections:
            role = _key_parts(graph, row)[0]
            if role not in tail_rows:
                _raise(_ORIENTATION)
            event_ids = _projection_event_ids(row)
            if role in event_ids_by_role and event_ids_by_role[role] != event_ids:
                _raise(_OWNER_INVALID)
            event_ids_by_role[role] = event_ids
            tail_rows[role].append(_int_matrix(row.private_value))
        if any(not values for values in tail_rows.values()):
            _raise(_CARDINALITY)
        entropy: dict[str, float] = {}
        for role, chain_rows in tail_rows.items():
            rows = tuple(row for chain in chain_rows for row in chain)
            event_ids = event_ids_by_role[role]
            if any(event_id not in event_ids for event_id in affected):
                _raise(_OWNER_INVALID)
            entropy[role] = math.fsum(
                _event_position_entropy(rows, event_ids.index(event_id))
                for event_id in affected
            ) / len(affected)
        return [
            entropy["restricted"] - entropy["broad"]
        ]
    if meaning_id.endswith("/noise_ladder_rule_states"):
        truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
        if len(truths) != 1:
            _raise(_CARDINALITY)
        order_truth = _mapping(truths[0].source_record.get("order_truth"))
        strict_order = _strings(order_truth.get("strict_order"))
        entropy_medians: list[float] = []
        agreement_medians: list[float] = []
        for level in ("level_00", "level_01", "level_02", "level_03", "level_04"):
            level_rows = [row for row in projections if _key_parts(graph, row)[0] == level]
            if len(level_rows) != 12:
                _raise(_ORIENTATION)
            entropy_values: list[float] = []
            agreement_values: list[float] = []
            for row in level_rows:
                order_rows = _int_matrix(row.private_value)
                if len(order_rows[0]) != len(strict_order):
                    _raise(_OWNER_INVALID)
                entropy_values.append(_mean_position_entropy(order_rows))
                agreement_values.append(
                    _kendall_agreement(
                        _central_order(order_rows),
                        tuple(range(len(strict_order))),
                    )
                )
            entropy_medians.append(_nearest_rank(entropy_values, 0.50))
            agreement_medians.append(_nearest_rank(agreement_values, 0.50))
        levels = (0.20, 0.55, 0.90, 1.25, 1.60)
        agreement_rho = _spearman(levels, agreement_medians)
        entropy_rho = _spearman(levels, entropy_medians)
        if agreement_rho <= -0.70 and entropy_rho >= 0.70:
            return ["PASS"]
        if agreement_rho <= -0.40 and entropy_rho >= 0.40:
            return ["WARN"]
        return ["FAIL"]
    terminals = tuple(row for row in records if row.owner_class == "PUBLIC_TERMINAL_RESULT")
    payloads = tuple(row for row in records if row.owner_class == "CANONICAL_SCIENTIFIC_PAYLOAD")
    truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
    manifests = tuple(
        row for row in records if row.owner_class == "PREPARATION_ROW_INSTANCE_MANIFEST"
    )
    if len(terminals) != 48 or len(payloads) != 48 or len(truths) != 24 or len(manifests) != 24:
        _raise(_CARDINALITY)
    if any(not _terminal_is_usable(row) for row in terminals) or any(
        not _payload_is_usable(row) for row in payloads
    ):
        _raise(_OPERATION_FAILED, state="FAILED")
    alignments: dict[tuple[int, str], list[float]] = {}
    stage_errors: list[float] = []
    for row in projections:
        parts = _key_parts(graph, row)
        if len(parts) < 4 or not parts[0].startswith("pair_"):
            _raise(_ORIENTATION)
        pair_index = int(parts[0].removeprefix("pair_"))
        role = parts[1]
        kind = parts[2]
        if pair_index not in range(24) or role not in {"signal", "matched_pure_no_signal"}:
            _raise(_ORIENTATION)
        truth = next(
            (
                item
                for item in truths
                if _key_parts(graph, item)[0] == f"pair_{pair_index:02d}"
            ),
            None,
        )
        if truth is None:
            _raise(_CARDINALITY)
        strict_order = _strings(
            _mapping(truth.source_record.get("order_truth")).get("strict_order")
        )
        if kind == "order":
            order_rows = _int_matrix(row.private_value)
            event_ids = _projection_event_ids(row)
            central = _central_order(order_rows)
            inferred = tuple(event_ids[index] for index in central)
            alignments.setdefault((pair_index, role), []).append(
                _kendall_agreement(inferred, strict_order)
            )
        elif kind == "stage" and role == "signal":
            manifest = next(
                (
                    item
                    for item in manifests
                    if _key_parts(graph, item)[:2] == (f"pair_{pair_index:02d}", "signal")
                ),
                None,
            )
            if manifest is None:
                _raise(_CARDINALITY)
            source_stages = tuple(
                _finite(value)
                for value in _sequence(
                    _mapping(truth.source_record.get("stage_truth")).get("participant_stages")
                )
            )
            instances = tuple(
                _mapping(value)
                for value in _sequence(manifest.source_record.get("ordered_row_instances"))
            )
            posterior = _probability_matrix(row.private_value)
            if len(instances) != len(posterior):
                _raise(_OWNER_INVALID)
            targets = tuple(
                source_stages[cast(int, instance.get("source_row_index"))]
                for instance in instances
            )
            expected = tuple(
                math.fsum(index * probability for index, probability in enumerate(values))
                for values in posterior
            )
            stage_errors.append(
                math.fsum(abs(a - b) for a, b in zip(expected, targets, strict=True))
                / len(targets)
                / (len(posterior[0]) - 1)
            )
        else:
            _raise(_ORIENTATION)
    if set(alignments) != {
        (pair_index, role)
        for pair_index in range(24)
        for role in ("signal", "matched_pure_no_signal")
    } or len(stage_errors) != 24:
        _raise(_CARDINALITY)
    differences = [
        _nearest_rank(alignments[(pair_index, "signal")], 0.50)
        - _nearest_rank(alignments[(pair_index, "matched_pure_no_signal")], 0.50)
        for pair_index in range(24)
    ]
    alignment_value = _nearest_rank(differences, 0.50)
    tail_count = _signed_randomization_tail_count(differences)
    stage_upper_median = sorted(stage_errors)[12]
    alignment_state = _rule_state(alignment_value, pass_floor=0.15, warn_floor=0.05)
    paired_state = "PASS" if 20 * tail_count <= 2**24 else "WARN"
    stage_state = _rule_state(stage_upper_median, pass_ceiling=0.25, warn_ceiling=0.35)
    convergence_state = "PASS"
    return [alignment_state, paired_state, stage_state, convergence_state]


def _influence_rule(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
) -> list[str]:
    aggregates = tuple(row for row in records if row.owner_class == "CASE_INFLUENCE_AGGREGATE")
    cases = tuple(row for row in records if row.owner_class == "PUBLIC_BATCH_CASE_PLAN")
    if len(aggregates) != 1:
        _raise(_MISSING_OWNER if not aggregates else _CARDINALITY)
    if not cases:
        _raise(_MISSING_OWNER)
    planned_case_ids = tuple(row.source_record.get("case_id") for row in cases)
    aggregate_case_id = aggregates[0].source_record.get("case_id")
    if (
        len(set(planned_case_ids)) != len(planned_case_ids)
        or aggregate_case_id != graph.case_id
        or aggregate_case_id not in planned_case_ids
    ):
        _raise(_CROSS_CASE)
    entries = tuple(
        entry
        for entry in _operation_plan_entries(graph, records)
        if entry.get("family_id") == "outlier_sabotage"
    )
    terminals = _terminal_by_operation(records)
    if (
        len(entries) != 9
        or [entry.get("member_id") for entry in entries]
        != ["baseline", *(f"leave_out_{index:02d}" for index in range(8))]
        or any(
            cast(str, entry.get("operation_instance_id")) not in terminals
            or not _operation_join_matches(
                entry, terminals[cast(str, entry.get("operation_instance_id"))]
            )
            for entry in entries
        )
    ):
        _raise(_REPLAY)
    successes = 0
    for row in aggregates:
        source = row.source_record
        removals = _sequence(source.get("ordered_removals"))
        planned = _strings(source.get("planned_removal_identity_sha256"))
        if (
            len(removals) != len(planned)
            or len(removals) < 2
            or len(set(planned)) != len(planned)
            or source.get("missing_removal_count") != 0
            or source.get("duplicate_removal_count") != 0
        ):
            _raise(_OWNER_INVALID)
        identity = _mapping(source.get("injected_participant_truth_identity"))
        injected = identity.get("injected_participant_internal_index")
        identity_preimage = dict(identity)
        identity_digest = identity_preimage.get(
            "injected_synthetic_participant_truth_identity_sha256"
        )
        identity_preimage["digest_state"] = "DIGEST_PREIMAGE"
        identity_preimage["injected_synthetic_participant_truth_identity_sha256"] = None
        if type(injected) is not int or identity_digest != structured_sha256_hex(
            "ebm-audit/injected-synthetic-participant-truth-identity/1",
            identity_preimage,
        ):
            _raise(_OWNER_INVALID)
        truth_matches = tuple(
            candidate
            for candidate in records
            if candidate.owner_class == "SYNTHETIC_TRUTH"
            and candidate.source_record.get("truth_object_sha256")
            == identity.get("truth_object_sha256")
        )
        if len(truth_matches) != 1:
            _raise(_REPLAY)
        outlier_truth = _mapping(truth_matches[0].source_record.get("outlier_truth"))
        if outlier_truth.get("mode") != "participant_sabotage" or _sequence(
            outlier_truth.get("participant_indexes")
        ) != (injected,):
            _raise(_OWNER_INVALID)
        component_ids = (
            "central_order_distance",
            "maximum_event_position_displacement",
            "pairwise_precedence_flips",
            "position_matrix_distance",
            "convergence_fit_change",
            "other_participants_expected_stage_distribution_change",
        )
        rows_by_index: dict[int, Mapping[str, object]] = {}
        values_by_component: dict[str, dict[int, float]] = {
            component_id: {} for component_id in component_ids
        }
        complete = (
            source.get("baseline_execution_state") == "SUCCESS"
            and source.get("baseline_convergence_state") == "CONVERGENCE_PASS"
        )
        observed_identities: list[str] = []
        for removal in removals:
            item = _mapping(removal)
            index = item.get("removed_participant_internal_index")
            removal_identity = item.get("removal_identity_sha256")
            if type(index) is not int or index in rows_by_index or not _is_sha256(removal_identity):
                _raise(_OWNER_INVALID)
            rows_by_index[index] = item
            observed_identities.append(removal_identity)
            complete = complete and (
                item.get("execution_state") == "SUCCESS"
                and item.get("convergence_state") == "CONVERGENCE_PASS"
                and item.get("capability_state") == "FULL_SIX_COMPONENT"
                and item.get("comparability_state") == "ALL_COMPONENTS_COMPARABLE"
                and item.get("reason_codes") in ([], ())
            )
            components = _mapping(item.get("components"))
            if set(components) != set(component_ids):
                _raise(_OWNER_INVALID)
            for component_id in component_ids:
                component = _mapping(components[component_id])
                if (
                    component.get("state") != "ASSESSABLE"
                    or component.get("direction") != "LARGER_IS_MORE_INFLUENTIAL"
                    or component.get("reason_codes") not in ([], ())
                ):
                    complete = False
                    continue
                values_by_component[component_id][index] = _finite(component.get("value"))
        if tuple(observed_identities) != planned:
            _raise(_REPLAY)
        if any(len(values) != len(removals) for values in values_by_component.values()):
            complete = False
        recomputed_scores = {index: 0.0 for index in rows_by_index}
        for component_id, component_values in values_by_component.items():
            if len(component_values) != len(removals):
                continue
            ordered = sorted(component_values.items(), key=lambda item: (-item[1], item[0]))
            position = 0
            while position < len(ordered):
                end = position + 1
                while end < len(ordered) and ordered[end][1] == ordered[position][1]:
                    end += 1
                midrank = ((position + 1) + end) / 2.0
                scaled = (len(ordered) - midrank) / (len(ordered) - 1)
                for tied_position in range(position, end):
                    index = ordered[tied_position][0]
                    component = _mapping(_mapping(rows_by_index[index]["components"])[component_id])
                    if not math.isclose(
                        _finite(component.get("descending_midrank")),
                        midrank,
                        rel_tol=0.0,
                        abs_tol=1e-12,
                    ):
                        _raise(_OWNER_INVALID)
                    recomputed_scores[index] += scaled / len(component_ids)
                position = end
        for index, item in rows_by_index.items():
            stored_score = item.get("aggregate_equal_weight_score")
            if complete and not math.isclose(
                _finite(stored_score),
                recomputed_scores[index],
                rel_tol=0.0,
                abs_tol=1e-12,
            ):
                _raise(_OWNER_INVALID)
        if (
            complete
            and injected in recomputed_scores
            and recomputed_scores[injected]
            > max(score for index, score in recomputed_scores.items() if index != injected)
        ):
            successes += 1
    return ["PASS" if 2 * successes > len(planned_case_ids) else "FAIL"]


def _analysis_rules(records: Sequence[ValidatedGraphSourceRecord]) -> tuple[str, ...]:
    rule_records = tuple(
        row for row in records if row.owner_class == "EXECUTED_BOUNDARY_RULE_IDENTITY"
    )
    expected = (("boundary_q50", 0.50), ("boundary_q35", 0.35), ("boundary_q65", 0.65))
    keyed = {row.source_record.get("rule_id"): row for row in rule_records}
    if len(keyed) != len(rule_records) or set(keyed) != {rule_id for rule_id, _ in expected}:
        _raise(_CARDINALITY)
    for rule_id, quantile in expected:
        if _finite(keyed[rule_id].source_record.get("cutoff_quantile")) != quantile:
            _raise(_OWNER_INVALID)
    return tuple(rule_id for rule_id, _quantile in expected)


def _scientific_cell_sort_key(value: object) -> tuple[int, float]:
    if value is None:
        return 1, 0.0
    return 0, _finite(value)


def _data_accounting_balances(record: ValidatedGraphSourceRecord) -> bool:
    accounting = _mapping(record.source_record.get("data_accounting"))
    input_count = accounting.get("input_participants")
    output_count = accounting.get("output_participants")
    removed_count = accounting.get("removed_participants")
    if any(
        type(value) is not int or value < 0 for value in (input_count, output_count, removed_count)
    ):
        _raise(_OWNER_INVALID)
    assert type(input_count) is int
    assert type(output_count) is int
    assert type(removed_count) is int
    return input_count == output_count + removed_count


def _single_record(
    records: Sequence[ValidatedGraphSourceRecord], owner_class: str
) -> ValidatedGraphSourceRecord:
    matches = tuple(row for row in records if row.owner_class == owner_class)
    if len(matches) != 1:
        _raise(_MISSING_OWNER if not matches else _CARDINALITY)
    return matches[0]


def _require_one_operation_binding(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
    owners: Sequence[ValidatedGraphSourceRecord],
) -> None:
    entries = _operation_plan_entries(graph, records)
    bound_entries = tuple(_bound_operation_entry(records, entries, owner) for owner in owners)
    if not bound_entries:
        _raise(_MISSING_OWNER)
    first = bound_entries[0]
    if any(
        any(
            entry.get(field) != first.get(field)
            for field in (
                "operation_instance_id",
                "case_operation_join_key",
                "operation_plan_entry_sha256",
            )
        )
        for entry in bound_entries[1:]
    ):
        _raise(_REPLAY)


def _training_row_manifest_equal(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
) -> list[bool]:
    execution = _single_record(records, "PREPROCESSING_EXECUTION_RECORD")
    manifests = _row_manifests_by_role(records, required_roles=("TRAINING",))
    manifest = manifests["TRAINING"]
    _require_one_operation_binding(graph, records, (execution, manifest))
    digest = manifest.source_record.get("row_instance_manifest_sha256")
    fit_populations = tuple(
        step.get("fit_population_manifest_sha256")
        for step in (
            _mapping(value)
            for value in _sequence(execution.source_record.get("ordered_step_records"))
        )
        if step.get("fit_population_manifest_sha256") is not None
    )
    return [
        execution.source_record.get("training_row_manifest_sha256") == digest
        and all(population == digest for population in fit_populations)
    ]


def _silent_loss_flags(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
) -> list[bool]:
    execution = _single_record(records, "PREPROCESSING_EXECUTION_RECORD")
    transformation = _single_record(records, "EXECUTED_TRANSFORMATION_EVIDENCE")
    role_order = ("INPUT", "TRAINING", "OUTPUT", "REFERENCE_FIT")
    manifests = _row_manifests_by_role(records, required_roles=role_order)
    _require_one_operation_binding(
        graph,
        records,
        (execution, *(manifests[role] for role in role_order), transformation),
    )
    instances = {role: _row_manifest_instances(manifests[role]) for role in role_order}
    digests = {
        role: manifests[role].source_record.get("row_instance_manifest_sha256")
        for role in role_order
    }
    execution_fields = {
        "INPUT": "input_row_manifest_sha256",
        "TRAINING": "training_row_manifest_sha256",
        "OUTPUT": "output_row_manifest_sha256",
        "REFERENCE_FIT": "reference_fit_row_manifest_sha256",
    }
    manifest_mismatch = any(
        execution.source_record.get(execution_fields[role]) != digests[role]
        for role in role_order
    ) or (
        transformation.source_record.get("source_row_manifest_sha256") != digests["INPUT"]
        or transformation.source_record.get("output_row_manifest_sha256")
        != digests["OUTPUT"]
    )
    accounting = _mapping(transformation.source_record.get("data_accounting"))
    input_rows = set(instances["INPUT"])
    output_rows = set(instances["OUTPUT"])
    accounting_mismatch = (
        not _data_accounting_balances(transformation)
        or accounting.get("input_participants") != len(input_rows)
        or accounting.get("output_participants") != len(output_rows)
        or accounting.get("removed_participants") != len(input_rows - output_rows)
        or accounting.get("added_participant_instances") != len(output_rows - input_rows)
    )
    return [manifest_mismatch or accounting_mismatch]


def _reference_only_fit_flags(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
) -> list[bool]:
    execution = _single_record(records, "PREPROCESSING_EXECUTION_RECORD")
    role = _single_record(records, "REFERENCE_FIT_GROUP_ROLE_EVIDENCE")
    manifests = _row_manifests_by_role(records, required_roles=("REFERENCE_FIT",))
    manifest = manifests["REFERENCE_FIT"]
    _require_one_operation_binding(graph, records, (execution, manifest, role))
    manifest_digest = manifest.source_record.get("row_instance_manifest_sha256")
    fit_populations = tuple(
        step.get("fit_population_manifest_sha256")
        for step in (
            _mapping(value)
            for value in _sequence(execution.source_record.get("ordered_step_records"))
        )
        if step.get("fit_population_manifest_sha256") is not None
    )
    if not fit_populations or not _row_manifest_instances(manifest):
        _raise(_UNAVAILABLE, state="UNAVAILABLE")
    exact = (
        role.source_record.get("method_id")
        == "reference-group-ordinary-linear-residualisation/1"
        and role.source_record.get("preprocessing_execution_record_sha256")
        == execution.source_record.get("preprocessing_execution_record_sha256")
        and execution.source_record.get("reference_fit_row_manifest_sha256")
        == manifest_digest
        and role.source_record.get("reference_fit_row_manifest_sha256") == manifest_digest
        and role.source_record.get("reference_group_row_manifest_sha256") == manifest_digest
        and role.source_record.get("at_risk_group_row_manifest_sha256") != manifest_digest
        and role.source_record.get("ordered_applied_group_roles")
        in (["REFERENCE", "AT_RISK"], ("REFERENCE", "AT_RISK"))
        and all(population == manifest_digest for population in fit_populations)
    )
    if not exact:
        _raise(_UNAVAILABLE, state="UNAVAILABLE")
    return [True]


def _resample_leakage_count(
    graph: ValidatedMeaningGraph,
    records: Sequence[ValidatedGraphSourceRecord],
) -> list[int]:
    role = _single_record(records, "REFERENCE_FIT_GROUP_ROLE_EVIDENCE")
    role_order = ("INPUT", "TRAINING", "OUTPUT", "REFERENCE_FIT")
    manifests = _row_manifests_by_role(records, required_roles=role_order)
    _require_one_operation_binding(
        graph,
        records,
        (*(manifests[manifest_role] for manifest_role in role_order), role),
    )
    rows = {
        manifest_role: set(_row_manifest_instances(manifests[manifest_role]))
        for manifest_role in role_order
    }
    reference_digest = manifests["REFERENCE_FIT"].source_record.get(
        "row_instance_manifest_sha256"
    )
    if (
        role.source_record.get("method_id")
        != "reference-group-ordinary-linear-residualisation/1"
        or role.source_record.get("reference_fit_row_manifest_sha256") != reference_digest
        or role.source_record.get("reference_group_row_manifest_sha256") != reference_digest
        or role.source_record.get("ordered_applied_group_roles")
        not in (["REFERENCE", "AT_RISK"], ("REFERENCE", "AT_RISK"))
    ):
        _raise(_UNAVAILABLE, state="UNAVAILABLE")
    fit_rows = rows["TRAINING"] | rows["REFERENCE_FIT"]
    return [len(fit_rows - rows["INPUT"])]


def _transformation_value(
    graph: ValidatedMeaningGraph,
    meaning_id: str,
    records: Sequence[ValidatedGraphSourceRecord],
) -> list[bool]:
    if meaning_id.endswith("/preprocessing_refit_equal"):
        source_rows = [
            row for row in records if row.selector == "same-case-source-preparation-audit/1"
        ]
        transformed_rows = [
            row for row in records if row.selector == "same-case-transformed-preparation-audit/1"
        ]
        return [
            left.source_record.get("ordered_preprocessing_refit_sha256")
            == right.source_record.get("ordered_preprocessing_refit_sha256")
            for left, right in _join_declared_members(graph, source_rows, transformed_rows)
        ]
    source, transformed = _data_pair(graph, records)
    source_record = source.source_record
    transformed_record = transformed.source_record
    if source_record.get("event_ids") != transformed_record.get("event_ids"):
        _raise(_OWNER_INVALID)
    if meaning_id.endswith("/group_counts_preserved"):
        return [
            sorted(_strings(source_record.get("analysis_group_labels")))
            == sorted(_strings(transformed_record.get("analysis_group_labels")))
        ]
    if meaning_id.endswith("/group_marginals_preserved"):
        source_labels = _strings(source_record.get("analysis_group_labels"))
        transformed_labels = _strings(transformed_record.get("analysis_group_labels"))
        source_values = _sequence(source_record.get("values"))
        transformed_values = _sequence(transformed_record.get("values"))
        if source_labels != transformed_labels or len(source_values) != len(transformed_values):
            return [False]
        return [
            all(
                sorted(
                    _scientific_cell_sort_key(_sequence(row)[event])
                    for label, row in zip(source_labels, source_values, strict=True)
                    if label == group
                )
                == sorted(
                    _scientific_cell_sort_key(_sequence(row)[event])
                    for label, row in zip(transformed_labels, transformed_values, strict=True)
                    if label == group
                )
                for group in sorted(set(source_labels))
                for event in range(len(_sequence(source_values[0])))
            )
        ]
    if meaning_id.endswith("/missing_counts_preserved"):
        return [_missing_count_structure(source) == _missing_count_structure(transformed)]
    if meaning_id.endswith("/participant_event_alignment_changed"):
        source_values_plain = _plain(source_record.get("values"))
        transformed_values_plain = _plain(transformed_record.get("values"))
        source_mask = _plain(source_record.get("missingness_mask"))
        transformed_mask = _plain(transformed_record.get("missingness_mask"))
        return [source_values_plain != transformed_values_plain or source_mask != transformed_mask]
    source_case = source_record.get("case_id")
    transformed_case = transformed_record.get("case_id")
    return [
        source_case == transformed_case
        and source_record.get("generated_scientific_data_sha256")
        != transformed_record.get("generated_scientific_data_sha256")
    ]


def _derive_value(
    graph: ValidatedMeaningGraph,
    spec: _MeaningSpec,
    selected: Sequence[ValidatedGraphSourceRecord],
) -> tuple[object, tuple[str, ...]]:
    meaning_id = spec.meaning_id
    derivation_id = spec.derivation_id
    records = list(selected)

    def need(
        owner_class: str, cardinality: str, selector: str
    ) -> tuple[ValidatedGraphSourceRecord, ...]:
        required_slot = _slot(owner_class, cardinality, selector)
        if required_slot not in spec.slots:
            _raise(_INVALID_GRAPH)
        rows = tuple(
            row
            for row in records
            if row.owner_class == owner_class
            and row.cardinality == cardinality
            and row.selector == selector
        )
        if not rows and cardinality != "ALL_CASE_WARNINGS":
            _raise(_MISSING_OWNER)
        return rows

    if meaning_id == "*:/planned_case_ids":
        case_ids = tuple(
            cast(str, row.source_record.get("case_id")) for row in _case_plan_rows(records)
        )
        if case_ids != graph.planned_case_ids:
            _raise(_REPLAY)
        value: object = list(case_ids)
    elif meaning_id == "*:/valid_case_ids":
        case_rows = _case_plan_rows(records)
        entries = _operation_plan_entries(graph, records)
        terminals = _terminal_by_operation(records)
        if set(terminals) != {
            cast(str, entry.get("operation_instance_id")) for entry in entries
        }:
            _raise(_REPLAY)
        valid = tuple(
            cast(str, case.source_record.get("case_id"))
            for case in case_rows
            if all(
                (
                    operation_id := cast(str, entry.get("operation_instance_id"))
                ) in terminals
                and _operation_join_matches(entry, terminals[operation_id])
                and _terminal_is_usable(terminals[operation_id])
                for entry in entries
                if entry.get("case_id") == case.source_record.get("case_id")
            )
        )
        if valid != graph.valid_case_ids:
            _raise(_REPLAY)
        value = list(valid)
    elif meaning_id in _REPORT_PREDICATE_BY_MEANING:
        value, claim_digests = _report_value(graph, meaning_id, records)
        return value, claim_digests
    elif meaning_id in _MATCHED_METRIC_SELECTORS:
        value = _matched_metric_value(meaning_id, records)
    elif meaning_id.endswith("/truth_scoring_mode"):
        value = _truth_scoring_value(records)
    elif meaning_id in {
        "easy_known_truth:/payload/order_rule_states",
        "easy_known_truth:/payload/stage_rule_states",
    }:
        value = _known_truth_rule(graph, meaning_id, records)
    elif meaning_id in {
        "moderate_mina_shape:/payload/moderate_rule_states",
        "noise_ladder:/payload/noise_ladder_rule_states",
        "small_sample:/payload/cross_chain_delta_small_minus_large",
        "incomplete_time_coverage:/payload/affected_tail_entropy_delta",
    }:
        value = _grouped_array_rule(graph, meaning_id, records)
    elif derivation_id == "truth-target-pair-precedence/1":
        truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
        projections = tuple(
            row for row in records if row.owner_class == "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION"
        )
        value = [
            result
            for truth, projection in _join_declared_members(graph, truths, projections)
            for result in _pairwise_values(truth, projection, mode="TARGET")
        ]
    elif derivation_id in {
        "truth-block-pair-precedence/1",
        "opposing-pair-absolute-precedence-from-half/1",
    }:
        truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
        projections = tuple(
            row for row in records if row.owner_class == "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION"
        )
        mode: Literal["BLOCK", "OPPOSING"] = (
            "BLOCK" if derivation_id.startswith("truth-block") else "OPPOSING"
        )
        value = [
            result
            for truth, projection in _join_declared_members(graph, truths, projections)
            for result in _pairwise_values(truth, projection, mode=mode)
        ]
    elif meaning_id.endswith("/influence_rule_states"):
        value = _influence_rule(graph, records)
    elif meaning_id.endswith("/mask_digest_equal"):
        truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
        data = tuple(row for row in records if row.owner_class == "SYNTHETIC_SCIENTIFIC_DATA")
        value = [
            _missingness_mask(truth) == _missingness_mask(scientific)
            for truth, scientific in _join_declared_members(graph, truths, data)
        ]
    elif meaning_id.endswith("/missing_counts_equal"):
        truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
        data = tuple(row for row in records if row.owner_class == "SYNTHETIC_SCIENTIFIC_DATA")
        audits = tuple(row for row in records if row.owner_class == "PREPARATION_AUDIT_EVIDENCE")
        value = []
        for truth, scientific, audit in _join_declared_members(graph, truths, data, audits):
            truth_counts = _missing_count_structure(truth)
            data_counts = _missing_count_structure(scientific)
            source_count = audit.source_record.get("source_missing_count")
            if type(source_count) is not int or source_count < 0:
                _raise(_OWNER_INVALID)
            cast(list[bool], value).append(
                truth_counts == data_counts and truth_counts[0] == source_count
            )
    elif meaning_id.endswith("/prebackend_terminal_correct"):
        audits = tuple(row for row in records if row.owner_class == "PREPARATION_AUDIT_EVIDENCE")
        entries = _operation_plan_entries(graph, records)
        terminals = _terminal_by_operation(records)
        value = []
        for row in audits:
            _entry, terminal = _bound_preparation_terminal(
                graph,
                entries,
                terminals,
                row,
            )
            if (
                row.source_record.get("missingness_policy") == "error"
                and cast(int, row.source_record.get("source_missing_count", 0)) > 0
            ):
                correct = (
                    terminal.source_record.get("terminal_status") == "INVALID_INPUT"
                    and terminal.source_record.get("reason_code") == "DATA.MISSING_EVENT_VALUE"
                    and terminal.source_record.get("backend_invoked") is False
                    and row.source_record.get("backend_invoked") is False
                )
            else:
                correct = _terminal_is_usable(terminal) == _bool(
                    row.source_record.get("backend_invoked")
                )
            cast(list[bool], value).append(correct)
    elif meaning_id.endswith("/predicted_removed_rows"):
        data = tuple(row for row in records if row.owner_class == "SYNTHETIC_SCIENTIFIC_DATA")
        specs = tuple(row for row in records if row.owner_class == "ANALYSIS_SPEC")
        value = [
            sum(any(mask_row) for mask_row in _missingness_mask(row))
            if _mapping(spec.source_record.get("missingness_policy")).get("policy")
            == "complete-case"
            else 0
            for row, spec in _join_declared_members(graph, data, specs)
        ]
    elif meaning_id == "mcar_missingness:/payload/preprocessing_refit_equal":
        value = _complete_preprocessing_refit_equal(graph, records)
    elif meaning_id.endswith("/terminal_contract_equal"):
        audits = tuple(row for row in records if row.owner_class == "PREPARATION_AUDIT_EVIDENCE")
        entries = _operation_plan_entries(graph, records)
        terminals = _terminal_by_operation(records)
        value = []
        for row in audits:
            _entry, terminal = _bound_preparation_terminal(
                graph,
                entries,
                terminals,
                row,
            )
            cast(list[bool], value).append(
                terminal.source_record.get("backend_invoked")
                == row.source_record.get("backend_invoked")
            )
    elif meaning_id.endswith("/training_row_manifest_equal"):
        value = _training_row_manifest_equal(graph, records)
    elif meaning_id.endswith("/silent_loss_flags"):
        value = _silent_loss_flags(graph, records)
    elif meaning_id.endswith("/reference_only_fit_flags"):
        value = _reference_only_fit_flags(graph, records)
    elif meaning_id.endswith("/resample_leakage_count"):
        value = _resample_leakage_count(graph, records)
    elif meaning_id in _PAE_OUTPUTS:
        value = _preparation_values(meaning_id, records)
    elif meaning_id.endswith("/hidden_imputation_flags"):
        source, transformed = _data_pair(graph, records)
        source_mask = _missingness_mask(source)
        transformed_mask = _missingness_mask(transformed)
        audit = next(row for row in records if row.owner_class == "PREPARATION_AUDIT_EVIDENCE")
        declared = {
            cast(str, operation.get("operation"))
            for operation in _sequence(
                _mapping(audit.source_record.get("data_accounting")).get("operations"),
                nonempty=False,
            )
            if isinstance(operation, Mapping)
        }
        hidden = (
            any(
                before and not after
                for before_row, after_row in zip(source_mask, transformed_mask, strict=True)
                for before, after in zip(before_row, after_row, strict=True)
            )
            and "IMPUTATION" not in declared
        )
        value = [hidden]
    elif meaning_id.endswith("/case_ids"):
        case_rows = _case_plan_rows(records)
        entries = _operation_plan_entries(graph, records)
        subtype = (
            "CORRELATED" if "/correlated/" in meaning_id else "EXACT_DUPLICATE_POST_NOISE"
        )
        planned_ids = {
            cast(str, entry.get("case_id"))
            for entry in entries
            if entry.get("family_id") == "correlated_duplicate_events"
            and entry.get("scenario_subtype_id") == subtype
        }
        case_ids = tuple(
            cast(str, row.source_record.get("case_id"))
            for row in case_rows
            if row.source_record.get("case_id") in planned_ids
        )
        if len(case_ids) != 6 or set(case_ids) != planned_ids:
            _raise(_CARDINALITY)
        value = list(case_ids)
    elif meaning_id.endswith("/stronger_than_null_flags"):
        decisions = need(
            "CANDIDATE_STRONG_EVIDENCE_DECISION",
            "ONE_PER_CASE",
            "same-case-strong-decision/1",
        )
        mapped = {
            "CANDIDATE_STRONG_EVIDENCE": True,
            "CANDIDATE_NOT_STRONG_EVIDENCE": False,
        }
        states = [row.source_record.get("state") for row in decisions]
        if any(state not in mapped for state in states):
            _raise(_UNAVAILABLE, state="UNAVAILABLE")
        value = [mapped[cast(str, state)] for state in states]
    elif meaning_id.endswith("/ordered_rule_ids"):
        value = list(_analysis_rules(records))
    elif meaning_id.endswith("/group_count_accounting_equal"):
        rules = _analysis_rules(records)
        transformations = tuple(
            row for row in records if row.owner_class == "EXECUTED_TRANSFORMATION_EVIDENCE"
        )
        manifests = tuple(
            row for row in records if row.owner_class == "PREPARATION_ROW_INSTANCE_MANIFEST"
        )
        if len(transformations) != len(rules) or len(manifests) != len(rules):
            _raise(_MISSING_OWNER)
        value = [
            _data_accounting_balances(transformation)
            and transformation.source_record.get("output_row_manifest_sha256")
            == manifest.source_record.get("row_instance_manifest_sha256")
            for transformation, manifest in zip(transformations, manifests, strict=True)
        ]
    elif meaning_id.endswith("/contamination_fraction"):
        entries = _operation_plan_entries(graph, records)
        if [
            entry.get("member_id")
            for entry in entries
            if entry.get("family_id") == "control_contamination"
        ] != ["contaminated", "clean"]:
            _raise(_REPLAY)
        truths = tuple(row for row in records if row.owner_class == "SYNTHETIC_TRUTH")
        value = [
            _finite(_mapping(row.source_record.get("group_truth")).get("contamination_fraction"))
            for row in truths
        ]
    elif meaning_id.endswith("/label_manifest_equal"):
        transformations = tuple(
            row for row in records if row.owner_class == "EXECUTED_TRANSFORMATION_EVIDENCE"
        )
        value = [
            row.source_record.get("source_labels_sha256")
            == row.source_record.get("output_labels_sha256")
            for row in transformations
        ]
    elif meaning_id.endswith("/hidden_modification_flags"):
        source, transformed = _data_pair(graph, records)
        audit = next(row for row in records if row.owner_class == "PREPARATION_AUDIT_EVIDENCE")
        changed = _plain(source.source_record.get("values")) != _plain(
            transformed.source_record.get("values")
        ) or _plain(source.source_record.get("missingness_mask")) != _plain(
            transformed.source_record.get("missingness_mask")
        )
        accounted = (
            cast(
                int,
                _mapping(audit.source_record.get("data_accounting")).get("transformed_cells", 0),
            )
            > 0
        )
        value = [changed and not accounted]
    elif meaning_id.endswith("/suppressed_warning_flags"):
        warnings = tuple(row for row in records if row.owner_class == "WARNING_RECORD")
        ledgers = tuple(row for row in records if row.owner_class == "REPORT_WARNING_LEDGER")
        if len(ledgers) != 1:
            _raise(_CARDINALITY)
        expected = [row.source_record_sha256 for row in warnings]
        ledger = ledgers[0].source_record
        observed = list(_strings(ledger.get("ordered_warning_record_sha256"), nonempty=False))
        count = ledger.get("warning_count")
        if type(count) is not int or count < 0:
            _raise(_OWNER_INVALID)
        value = [expected != observed or count != len(expected)]
    elif meaning_id.endswith("/visible_terminal_flags"):
        value = [
            row.source_record.get("terminal_count") == 1
            and _is_sha256(row.source_record.get("terminal_record_sha256"))
            and _is_sha256(row.source_record.get("public_terminal_result_sha256"))
            and _is_sha256(row.source_record.get("report_claim_projection_sha256"))
            for row in records
        ]
    elif meaning_id in _TRANSFORM_OUTPUTS:
        transformations = tuple(
            row for row in records if row.owner_class == "EXECUTED_TRANSFORMATION_EVIDENCE"
        )
        if not transformations:
            _raise(_MISSING_OWNER)
        if meaning_id.endswith("/preprocessing_refit_equal"):
            _operation_plan_entries(graph, records)
            executions = tuple(
                row for row in records if row.owner_class == "PREPROCESSING_EXECUTION_RECORD"
            )
            if len(executions) != len(transformations):
                _raise(_CARDINALITY)
            value = [
                bool(_sequence(row.source_record.get("ordered_step_records"), nonempty=False))
                and row.source_record.get("preprocessing_parameters_sha256")
                == transformations[index].source_record.get("executed_parameters_sha256")
                for index, row in enumerate(executions)
            ]
        elif meaning_id.endswith("/group_counts_preserved"):
            value = [
                row.source_record.get("source_labels_sha256")
                == row.source_record.get("output_labels_sha256")
                for row in transformations
            ]
        elif meaning_id.endswith("/group_marginals_preserved"):
            value = [
                row.source_record.get("source_axes_sha256")
                == row.source_record.get("output_axes_sha256")
                and row.source_record.get("source_labels_sha256")
                == row.source_record.get("output_labels_sha256")
                for row in transformations
            ]
        elif meaning_id.endswith("/missing_counts_preserved"):
            value = [
                row.source_record.get("source_missingness_sha256")
                == row.source_record.get("output_missingness_sha256")
                for row in transformations
            ]
        elif meaning_id.endswith("/participant_event_alignment_changed"):
            value = [
                row.source_record.get("source_participant_event_alignment_sha256")
                != row.source_record.get("output_participant_event_alignment_sha256")
                for row in transformations
            ]
        elif meaning_id.endswith("/source_binding_equal"):
            entries = _operation_plan_entries(graph, records)
            terminals = _terminal_by_operation(records)
            value = [
                any(
                    entry.get("operation_instance_id")
                    == row.source_record.get("operation_instance_id")
                    and cast(str, entry.get("operation_instance_id")) in terminals
                    and _operation_join_matches(
                        entry, terminals[cast(str, entry.get("operation_instance_id"))]
                    )
                    for entry in entries
                )
                for row in transformations
            ]
        else:
            _raise(_DERIVATION_FAILED, state="FAILED")
    elif meaning_id.endswith("/excluded_from_pure_no_signal_fpr_denominator"):
        truths = need("SYNTHETIC_TRUTH", "ONE_PER_CASE", "same-case-truth/1")
        entries = _operation_plan_entries(graph, records)
        transformations = tuple(
            row for row in records if row.owner_class == "EXECUTED_TRANSFORMATION_EVIDENCE"
        )
        terminals = _terminal_by_operation(records)
        if any(_truth_mode(row) != "REFITTED_NULL_TRANSFORMATION" for row in truths):
            _raise(_OWNER_INVALID)
        value = [
            any(
                entry.get("operation_instance_id")
                == transformation.source_record.get("operation_instance_id")
                and entry.get("source_case_id") is not None
                and cast(str, entry.get("operation_instance_id")) in terminals
                and _terminal_is_usable(
                    terminals[cast(str, entry.get("operation_instance_id"))]
                )
                for entry in entries
                for transformation in transformations
            )
            for _truth in truths
        ]
    else:
        _raise(_DERIVATION_FAILED, state="FAILED")
    return value, _unique_digests(records)


def _visible_specs(graph: ValidatedMeaningGraph) -> tuple[_MeaningSpec, ...]:
    return tuple(
        row
        for row in _FROZEN_SPECS
        if row.meaning_id.startswith("*:") or row.meaning_id.startswith(f"{graph.family_id}:")
    )


def _invalid_specs(
    specs: Sequence[_MeaningSpec], code: str
) -> tuple[GroupedMeaningResult, ...]:
    return tuple(
        _result(
            spec.meaning_id,
            state="INVALID",
            reason_code=code,
            failure_code=code,
        )
        for spec in specs
    )


def _derive_specs(
    graph: ValidatedMeaningGraph,
    specs: Sequence[_MeaningSpec],
) -> tuple[GroupedMeaningResult, ...]:
    family_operation_state = _operation_state(graph)
    results: list[GroupedMeaningResult] = []
    for spec in specs:
        is_common = spec.meaning_id.startswith("*:")
        if not is_common and graph.declared_model_shape == "NOT_APPLICABLE":
            results.append(
                _result(
                    spec.meaning_id,
                    state="NOT_APPLICABLE",
                    reason_code=_NOT_APPLICABLE,
                )
            )
            continue
        if not is_common and family_operation_state is not None:
            state, code = family_operation_state
            results.append(
                _result(
                    spec.meaning_id,
                    state=state,
                    reason_code=code,
                    failure_code=code if state in {"INVALID", "FAILED"} else None,
                )
            )
            continue
        try:
            selected = _selected_records(graph, spec)
            value, source_digests = _derive_value(graph, spec, selected)
            if value is None or not source_digests:
                _raise(_DERIVATION_FAILED, state="FAILED")
            plain_value = _plain(value)
            if not _available_value_valid(spec.meaning_id, plain_value):
                _raise(_DERIVATION_FAILED, state="FAILED")
            results.append(
                _result(
                    spec.meaning_id,
                    state="AVAILABLE",
                    value=plain_value,
                    source_record_digests=source_digests,
                )
            )
        except _DerivationError as error:
            state = error.state
            code = error.code
            if code == _MISSING_OWNER:
                state = "UNAVAILABLE" if graph.capability_mode == "PARTIAL" else "INVALID"
                code = _UNAVAILABLE if state == "UNAVAILABLE" else _MISSING_OWNER
            elif state == "UNAVAILABLE" and graph.capability_mode == "FULL":
                state = "FAILED"
                code = _DERIVATION_FAILED
            results.append(
                _result(
                    spec.meaning_id,
                    state=state,
                    reason_code=code,
                    failure_code=code if state in {"INVALID", "FAILED"} else None,
                )
            )
        except (ArithmeticError, KeyError, TypeError, ValueError):
            results.append(
                _result(
                    spec.meaning_id,
                    state="INVALID",
                    reason_code=_OWNER_INVALID,
                    failure_code=_OWNER_INVALID,
                )
            )
    return tuple(results)


def derive_grouped_meanings(
    graph: ValidatedMeaningGraph,
) -> tuple[GroupedMeaningResult, ...]:
    """Derive the common and declared-family meanings in frozen order.

    The function returns only the two common rows and the rows for
    ``graph.family_id``. A caller aggregates the common rows once and then each
    family group. The resulting frozen-order total is exactly 104.
    """

    if type(graph) is not ValidatedMeaningGraph:
        raise TypeError("graph must be ValidatedMeaningGraph")
    specs = _visible_specs(graph)
    try:
        _validate_graph(graph)
    except _DerivationError as error:
        if graph.family_id not in _FAMILY_OPERATION_MEMBERS:
            raise ValueError("graph family_id is not frozen") from error
        return _invalid_specs(specs, error.code)
    return _derive_specs(graph, specs)


def _derive_selected_grouped_meanings(
    graph: ValidatedMeaningGraph,
    meaning_ids: tuple[str, ...],
) -> tuple[GroupedMeaningResult, ...]:
    """Derive only admitted frozen meanings, always in frozen order."""

    if type(graph) is not ValidatedMeaningGraph:
        raise TypeError("graph must be ValidatedMeaningGraph")
    if (
        type(meaning_ids) is not tuple
        or any(type(meaning_id) is not str or not meaning_id for meaning_id in meaning_ids)
        or len(meaning_ids) != len(set(meaning_ids))
    ):
        raise TypeError("meaning_ids must be a unique tuple of frozen meaning IDs")
    visible = _visible_specs(graph)
    visible_by_id = {spec.meaning_id: spec for spec in visible}
    if any(meaning_id not in visible_by_id for meaning_id in meaning_ids):
        raise ValueError("selected meaning_id is not frozen for the graph family")
    selected = set(meaning_ids)
    specs = tuple(spec for spec in visible if spec.meaning_id in selected)
    try:
        _validate_graph(graph)
    except _DerivationError as error:
        if graph.family_id not in _FAMILY_OPERATION_MEMBERS:
            raise ValueError("graph family_id is not frozen") from error
        return _invalid_specs(specs, error.code)
    return _derive_specs(graph, specs)


__all__ = [
    "CapabilityMode",
    "DeclaredModelShape",
    "GroupedMeaningResult",
    "GroupedMeaningState",
    "OperationOutcomeState",
    "ValidatedGraphCardinalityDeclaration",
    "ValidatedGraphClaimRecord",
    "ValidatedGraphOperationOutcome",
    "ValidatedGraphSourceRecord",
    "ValidatedMeaningGraph",
    "derive_grouped_meanings",
    "frozen_operation_ids",
    "frozen_report_dependent_meaning_ids",
    "frozen_slot_requirements",
    "matched_metric_orientation",
    "validated_meaning_graph_digest",
]
