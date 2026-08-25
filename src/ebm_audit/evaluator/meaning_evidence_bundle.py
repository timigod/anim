"""Ordered immutable evidence for all frozen proportional-contract meanings."""

from __future__ import annotations

import copy
import hashlib
import math
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from threading import RLock
from typing import Final, Literal, Never, SupportsIndex, cast, final, overload

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.config.strict_yaml import StrictYamlError, load_strict_yaml_bytes
from ebm_audit.evaluator.report_claim_projection import (
    AuthenticatedReportClaimProjection,
    _read_cohort_report_evidence_graph_digest,
    read_authenticated_report_claim_projection,
)
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256_hex
from ebm_audit.schema.validation import _format_checker, _schema_registry

type MeaningState = Literal["AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED"]

_PROPORTIONAL_CONTRACT_DOMAIN: Final = "ebm-audit/proportional-benchmark-contract/1"
_CONTRACT_SHA256: Final = "2cf53a6006b174d7b2ef574a293f1499cff450491ef0359088a6889b0c288119"
_CONTRACT_RAW_SHA256: Final = "dda790e2e1fb322a0acd362c4504fc5bcb8bbedad816004bdf7efa05bdf610af"
_REGISTRY_SHA256: Final = "dca5d1a00362ac35f36127066ecf7028ad2c4b57345a21e9cf1a192f5646bb6c"
_REGISTRY_RAW_SHA256: Final = "e2f1c504b7e1118173858f494818499afc59dc277d1fdeaaded3e62de4e71e1f"
_PREDICATE_REGISTRY_RAW_SHA256: Final = (
    "2e6efdca9835f39da2e7068fb92c2cb83bc76a08d58904aca203f589d45b69dc"
)
_INVENTORY_SHA256: Final = "66adadf73f8ef6b86c9806d4fe281caad8e705bdbd30cdbda0a5f1c64dabc677"
_COVERAGE_SHA256: Final = "693266d3e89f1474d6472ddcc2032b52ead1f8cb1a7a579845070422c9764b66"
_BUNDLE_DOMAIN: Final = "ebm-audit/meaning-evidence-bundle/1"
_EXTENSION_DOMAIN: Final = "ebm-audit/authenticated-meaning-evidence-extension/1"
_MEANING_STATES: Final = frozenset(
    {"AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED"}
)
_SCHEMA_BASE_URI: Final = "https://schemas.ebm-audit.invalid/"
_ROOT: Final = Path(__file__).resolve().parents[3]
_PREDICATE_REGISTRY_PATH: Final = _ROOT / "evaluator/scenario_predicate_registry.yaml"
_PROPORTIONAL_CONTRACT_PATH: Final = _ROOT / "evaluator/proportional_benchmark_contract.yaml"
_DERIVATION_REGISTRY_PATH: Final = _ROOT / "evaluator/scenario_derivation_registry.json"
_PACKAGED_EVALUATOR_SOURCE_DIRECTORY: Final = "evaluator_contracts"
_FROZEN_SOURCE_LOCK: Final = RLock()
_FROZEN_SOURCE_PHASE: Literal[
    "EXTERNAL_CHECKOUT",
    "PACKAGED_INSTALL",
    "AUTHENTICATED_REHYDRATED",
] | None = None
_FROZEN_PREDICATE_REGISTRY_BYTES: bytes | None = None
_FROZEN_PROPORTIONAL_CONTRACT_BYTES: bytes | None = None
_FROZEN_REGISTRY_BYTES: bytes | None = None
_FAMILY_OPERATION_MEMBERS_CACHE: Mapping[str, tuple[str, ...]] | None = None
_FROZEN_COVERAGE_ROWS_CACHE: tuple[dict[str, object], ...] | None = None
_FROZEN_COVERAGE_BY_ID_CACHE: Mapping[str, dict[str, object]] | None = None


class MeaningEvidenceBundleError(TypeError):
    """Raised when meaning evidence is incomplete, reordered, or detached."""


def _reject() -> Never:
    raise MeaningEvidenceBundleError("Authenticated meaning evidence failed closed validation.")


def _parse_frozen_family_operation_members(
    contract_bytes: bytes,
) -> Mapping[str, tuple[str, ...]]:
    contract = load_strict_yaml_bytes(contract_bytes, maximum_bytes=1_000_000)
    if not isinstance(contract, Mapping):
        _reject()
    contract_mapping = cast(Mapping[str, object], contract)
    contract_preimage = copy.deepcopy(dict(contract_mapping))
    contract_preimage["contract_sha256"] = None
    meaning_inventory = contract_mapping.get("meaning_inventory")
    challenge = contract_mapping.get("challenge")
    ledger = challenge.get("fit_ledger") if isinstance(challenge, Mapping) else None
    if (
        hashlib.sha256(contract_bytes).hexdigest() != _CONTRACT_RAW_SHA256
        or contract_mapping.get("contract_sha256") != _CONTRACT_SHA256
        or structured_sha256_hex(_PROPORTIONAL_CONTRACT_DOMAIN, contract_preimage)
        != _CONTRACT_SHA256
        or not isinstance(meaning_inventory, Mapping)
        or meaning_inventory.get("source_sha256") != _REGISTRY_RAW_SHA256
        or not isinstance(challenge, Mapping)
        or challenge.get("fit_ceiling") != 104
        or type(ledger) is not list
        or len(ledger) != 23
    ):
        _reject()
    result: dict[str, tuple[str, ...]] = {}
    for row in ledger:
        if not isinstance(row, Mapping):
            _reject()
        family_id = row.get("family_id")
        member_ids = row.get("member_ids")
        if (
            type(family_id) is not str
            or not family_id
            or family_id in result
            or type(member_ids) is not list
            or not member_ids
            or any(type(member_id) is not str or not member_id for member_id in member_ids)
            or len(set(member_ids)) != len(member_ids)
            or row.get("fit_count") != len(member_ids)
        ):
            _reject()
        result[family_id] = tuple(cast(list[str], member_ids))
    if sum(len(member_ids) for member_ids in result.values()) != 104:
        _reject()
    return result


def _validate_frozen_registry_bytes(registry_bytes: bytes) -> None:
    registry = strict_json_loads(registry_bytes)
    if not isinstance(registry, Mapping):
        _reject()
    claimed = registry.get("scenario_derivation_registry_sha256")
    preimage = copy.deepcopy(dict(registry))
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage["scenario_derivation_registry_sha256"] = None
    if (
        hashlib.sha256(registry_bytes).hexdigest() != _REGISTRY_RAW_SHA256
        or claimed != _REGISTRY_SHA256
        or claimed
        != structured_sha256_hex(
            "ebm-audit/scenario-derivation-registry/1",
            preimage,
        )
    ):
        _reject()


def _validate_frozen_predicate_registry_bytes(registry_bytes: bytes) -> None:
    try:
        registry = load_strict_yaml_bytes(registry_bytes, maximum_bytes=1_000_000)
    except StrictYamlError:
        _reject()
    if (
        hashlib.sha256(registry_bytes).hexdigest() != _PREDICATE_REGISTRY_RAW_SHA256
        or not isinstance(registry, Mapping)
        or set(registry) != {"scenario_predicate_registry"}
    ):
        _reject()


def _frozen_evaluator_source_bytes() -> tuple[bytes, bytes, bytes]:
    """Return the three product sources required for frozen meaning derivation."""

    global _FROZEN_PREDICATE_REGISTRY_BYTES, _FROZEN_PROPORTIONAL_CONTRACT_BYTES
    global _FROZEN_REGISTRY_BYTES, _FROZEN_SOURCE_PHASE
    with _FROZEN_SOURCE_LOCK:
        sources = (
            _FROZEN_PREDICATE_REGISTRY_BYTES,
            _FROZEN_PROPORTIONAL_CONTRACT_BYTES,
            _FROZEN_REGISTRY_BYTES,
        )
        if any(source is None for source in sources):
            if any(source is not None for source in sources):
                _reject()
            source_phase: Literal["EXTERNAL_CHECKOUT", "PACKAGED_INSTALL"] = (
                "EXTERNAL_CHECKOUT"
            )
            try:
                predicate_registry_bytes = _PREDICATE_REGISTRY_PATH.read_bytes()
                proportional_contract_bytes = _PROPORTIONAL_CONTRACT_PATH.read_bytes()
                registry_bytes = _DERIVATION_REGISTRY_PATH.read_bytes()
            except OSError:
                try:
                    packaged = resources.files("ebm_audit").joinpath(
                        _PACKAGED_EVALUATOR_SOURCE_DIRECTORY
                    )
                    predicate_registry_bytes = packaged.joinpath(
                        "scenario_predicate_registry.yaml"
                    ).read_bytes()
                    proportional_contract_bytes = packaged.joinpath(
                        "proportional_benchmark_contract.yaml"
                    ).read_bytes()
                    registry_bytes = packaged.joinpath(
                        "scenario_derivation_registry.json"
                    ).read_bytes()
                except (FileNotFoundError, ModuleNotFoundError, OSError, TypeError):
                    _reject()
                source_phase = "PACKAGED_INSTALL"
            _validate_frozen_predicate_registry_bytes(predicate_registry_bytes)
            _parse_frozen_family_operation_members(proportional_contract_bytes)
            _validate_frozen_registry_bytes(registry_bytes)
            _FROZEN_PREDICATE_REGISTRY_BYTES = bytes(predicate_registry_bytes)
            _FROZEN_PROPORTIONAL_CONTRACT_BYTES = bytes(proportional_contract_bytes)
            _FROZEN_REGISTRY_BYTES = bytes(registry_bytes)
            _FROZEN_SOURCE_PHASE = source_phase
        if (
            _FROZEN_PREDICATE_REGISTRY_BYTES is None
            or _FROZEN_PROPORTIONAL_CONTRACT_BYTES is None
            or _FROZEN_REGISTRY_BYTES is None
        ):
            _reject()
        return (
            bytes(_FROZEN_PREDICATE_REGISTRY_BYTES),
            bytes(_FROZEN_PROPORTIONAL_CONTRACT_BYTES),
            bytes(_FROZEN_REGISTRY_BYTES),
        )


def _frozen_meaning_source_bytes() -> tuple[bytes, bytes]:
    """Return the proportional contract and registry from the shared source phase."""

    _predicate_registry_bytes, proportional_contract_bytes, registry_bytes = (
        _frozen_evaluator_source_bytes()
    )
    return proportional_contract_bytes, registry_bytes


def _bind_authenticated_frozen_meaning_sources(
    *,
    predicate_registry_bytes: bytes,
    proportional_contract_bytes: bytes,
    derivation_registry_bytes: bytes,
) -> None:
    """Bind authenticated outer-preflight bytes before installed evaluator imports."""

    global _FAMILY_OPERATION_MEMBERS_CACHE
    global _FROZEN_PREDICATE_REGISTRY_BYTES, _FROZEN_PROPORTIONAL_CONTRACT_BYTES
    global _FROZEN_REGISTRY_BYTES, _FROZEN_SOURCE_PHASE
    if (
        type(predicate_registry_bytes) is not bytes
        or not predicate_registry_bytes
        or type(proportional_contract_bytes) is not bytes
        or not proportional_contract_bytes
        or type(derivation_registry_bytes) is not bytes
        or not derivation_registry_bytes
    ):
        _reject()
    _validate_frozen_predicate_registry_bytes(predicate_registry_bytes)
    members = _parse_frozen_family_operation_members(proportional_contract_bytes)
    _validate_frozen_registry_bytes(derivation_registry_bytes)
    with _FROZEN_SOURCE_LOCK:
        if (
            _FROZEN_PREDICATE_REGISTRY_BYTES is not None
            and predicate_registry_bytes != _FROZEN_PREDICATE_REGISTRY_BYTES
        ) or (
            _FROZEN_PROPORTIONAL_CONTRACT_BYTES is not None
            and proportional_contract_bytes != _FROZEN_PROPORTIONAL_CONTRACT_BYTES
        ) or (
            _FROZEN_REGISTRY_BYTES is not None
            and derivation_registry_bytes != _FROZEN_REGISTRY_BYTES
        ):
            _reject()
        _FROZEN_PREDICATE_REGISTRY_BYTES = bytes(predicate_registry_bytes)
        _FROZEN_PROPORTIONAL_CONTRACT_BYTES = bytes(proportional_contract_bytes)
        _FROZEN_REGISTRY_BYTES = bytes(derivation_registry_bytes)
        _FAMILY_OPERATION_MEMBERS_CACHE = dict(members)
        _FROZEN_SOURCE_PHASE = "AUTHENTICATED_REHYDRATED"


def _frozen_family_operation_members() -> Mapping[str, tuple[str, ...]]:
    global _FAMILY_OPERATION_MEMBERS_CACHE
    with _FROZEN_SOURCE_LOCK:
        if _FAMILY_OPERATION_MEMBERS_CACHE is None:
            contract_bytes, _registry_bytes = _frozen_meaning_source_bytes()
            _FAMILY_OPERATION_MEMBERS_CACHE = dict(
                _parse_frozen_family_operation_members(contract_bytes)
            )
        return _FAMILY_OPERATION_MEMBERS_CACHE


@final
class _FrozenFamilyOperationMembers(Mapping[str, tuple[str, ...]]):
    def __getitem__(self, key: str) -> tuple[str, ...]:
        return _frozen_family_operation_members()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(_frozen_family_operation_members())

    def __len__(self) -> int:
        return len(_frozen_family_operation_members())


_FAMILY_OPERATION_MEMBERS: Final = _FrozenFamilyOperationMembers()
_FAMILY_PAYLOAD_DEFINITION: Final = {
    "easy_known_truth": "EasyKnownTruthEvidence",
    "moderate_mina_shape": "ModerateEvidence",
    "small_sample": "SmallSampleEvidence",
    "noise_ladder": "NoiseEvidence",
    "weak_pre_post_separation": "WeakSeparationEvidence",
    "incomplete_time_coverage": "IncompleteCoverageEvidence",
    "tightly_spaced_events": "TightlySpacedEvidence",
    "slow_overlapping_transitions": "SlowTransitionEvidence",
    "outlier_sabotage": "OutlierEvidence",
    "mcar_missingness": "McarEvidence",
    "mar_missingness": "MarEvidence",
    "correlated_duplicate_events": "CorrelatedDuplicateEvidence",
    "minority_alternate_sequence": "MinorityAlternateEvidence",
    "opposing_sequences_50_50": "OpposingEvidence",
    "near_simultaneous_events": "NearSimultaneousEvidence",
    "covariate_confounding": "CovariateEvidence",
    "group_boundary_sensitivity": "GroupBoundaryEvidence",
    "control_contamination": "ControlContaminationEvidence",
    "heavy_tailed_skewed": "HeavyTailEvidence",
    "wrong_event_direction": "WrongDirectionEvidence",
    "pure_no_signal": "PureNoSignalEvidence",
    "label_permutation_null": "LabelPermutationEvidence",
    "within_group_feature_permutation_null": "FeaturePermutationEvidence",
}
_FROZEN_MEANING_DERIVATIONS: Final = (
    ("*:/planned_case_ids", "frozen-operation-plan-case-order/1"),
    ("*:/valid_case_ids", "terminal-result-plan-order/1"),
    ("easy_known_truth:/payload/order_rule_states", "known-truth-order-rule-state/1"),
    ("easy_known_truth:/payload/stage_rule_states", "known-truth-stage-rule-state/1"),
    ("easy_known_truth:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("moderate_mina_shape:/payload/moderate_rule_states", "moderate-matched-null-rule-state/1"),
    ("moderate_mina_shape:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("small_sample:/payload/entropy_delta_small_minus_large", "matched-entropy-delta/1"),
    ("small_sample:/payload/cross_chain_delta_small_minus_large", "matched-cross-chain-delta/1"),
    ("small_sample:/payload/forced_precision_flags", "forbidden-report-claim-flag/1"),
    ("small_sample:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("noise_ladder:/payload/noise_ladder_rule_states", "noise-ladder-monotonic-rule-state/1"),
    ("noise_ladder:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    (
        "weak_pre_post_separation:/payload/entropy_delta_weak_minus_moderate",
        "matched-entropy-delta/1",
    ),
    (
        "weak_pre_post_separation:/payload/kendall_distance_delta_weak_minus_moderate",
        "matched-kendall-delta/1",
    ),
    (
        "weak_pre_post_separation:/payload/ineligible_strong_flags",
        "ineligible-strong-evidence-flag/1",
    ),
    ("weak_pre_post_separation:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    (
        "incomplete_time_coverage:/payload/affected_tail_entropy_delta",
        "truth-targeted-tail-entropy-delta/1",
    ),
    (
        "incomplete_time_coverage:/payload/coverage_limitation_reported",
        "required-report-claim-flag/1",
    ),
    ("incomplete_time_coverage:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("tightly_spaced_events:/payload/target_pair_precedence", "truth-target-pair-precedence/1"),
    (
        "tightly_spaced_events:/payload/arbitrary_within_pair_truth_claims",
        "forbidden-report-claim-flag/1",
    ),
    ("tightly_spaced_events:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    (
        "slow_overlapping_transitions:/payload/entropy_delta_slow_minus_narrow",
        "matched-entropy-delta/1",
    ),
    (
        "slow_overlapping_transitions:/payload/kendall_distance_delta_slow_minus_narrow",
        "matched-kendall-delta/1",
    ),
    ("slow_overlapping_transitions:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("outlier_sabotage:/payload/influence_rule_states", "influence-rule-state/1"),
    ("outlier_sabotage:/payload/bad_or_wrong_data_claim_flags", "forbidden-report-claim-flag/1"),
    ("outlier_sabotage:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("mcar_missingness:/payload/mask_digest_equal", "missingness-mask-digest-equality/1"),
    ("mcar_missingness:/payload/missing_counts_equal", "missing-count-equality/1"),
    ("mcar_missingness:/payload/prebackend_terminal_correct", "prebackend-terminal-contract/1"),
    ("mcar_missingness:/payload/predicted_removed_rows", "predicted-complete-case-removals/1"),
    ("mcar_missingness:/payload/actual_removed_rows", "actual-complete-case-removals/1"),
    (
        "mcar_missingness:/payload/preprocessing_refit_equal",
        "complete-preprocessing-refit-equality/1",
    ),
    ("mcar_missingness:/payload/backend_nan_flags", "backend-nonfinite-admission-flag/1"),
    ("mcar_missingness:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("mar_missingness:/payload/mask_digest_equal", "missingness-mask-digest-equality/1"),
    ("mar_missingness:/payload/missing_counts_equal", "missing-count-equality/1"),
    ("mar_missingness:/payload/terminal_contract_equal", "terminal-contract-equality/1"),
    ("mar_missingness:/payload/training_row_manifest_equal", "training-row-manifest-equality/1"),
    ("mar_missingness:/payload/silent_loss_flags", "silent-row-loss-flag/1"),
    ("mar_missingness:/payload/hidden_imputation_flags", "hidden-imputation-flag/1"),
    ("mar_missingness:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("correlated_duplicate_events:/payload/correlated/case_ids", "subtype-case-identities/1"),
    (
        "correlated_duplicate_events:/payload/correlated/target_pair_precedence",
        "truth-target-pair-precedence/1",
    ),
    (
        "correlated_duplicate_events:/payload/correlated/arbitrary_within_pair_truth_claims",
        "forbidden-report-claim-flag/1",
    ),
    ("correlated_duplicate_events:/payload/correlated/truth_scoring_mode", "truth-scoring-mode/1"),
    (
        "correlated_duplicate_events:/payload/exact_duplicate_post_noise/case_ids",
        "subtype-case-identities/1",
    ),
    (
        "correlated_duplicate_events:/payload/exact_duplicate_post_noise/target_pair_precedence",
        "truth-target-pair-precedence/1",
    ),
    (
        "correlated_duplicate_events:/payload/exact_duplicate_post_noise/partial_truth_scored_without_tiebreak",
        "partial-truth-scoring-without-tiebreak/1",
    ),
    (
        "correlated_duplicate_events:/payload/exact_duplicate_post_noise/arbitrary_within_pair_truth_claims",
        "forbidden-report-claim-flag/1",
    ),
    (
        "correlated_duplicate_events:/payload/exact_duplicate_post_noise/truth_scoring_mode",
        "truth-scoring-mode/1",
    ),
    (
        "minority_alternate_sequence:/payload/single_sequence_limitation_reported",
        "required-report-claim-flag/1",
    ),
    (
        "minority_alternate_sequence:/payload/entropy_delta_mixture_minus_single",
        "matched-entropy-delta/1",
    ),
    ("minority_alternate_sequence:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    (
        "opposing_sequences_50_50:/payload/opposing_pair_absolute_precedence_from_half",
        "opposing-pair-absolute-precedence-from-half/1",
    ),
    (
        "opposing_sequences_50_50:/payload/internally_concentrated_flags",
        "internal-concentration-flag/1",
    ),
    ("opposing_sequences_50_50:/payload/stronger_than_null_flags", "stronger-than-null-flag/1"),
    ("opposing_sequences_50_50:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("near_simultaneous_events:/payload/block_pair_precedence", "truth-block-pair-precedence/1"),
    ("near_simultaneous_events:/payload/block_aware_scoring", "block-aware-scoring-flag/1"),
    ("near_simultaneous_events:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    (
        "covariate_confounding:/payload/adjusted_minus_unadjusted_kendall_agreement",
        "matched-kendall-delta/1",
    ),
    (
        "covariate_confounding:/payload/reference_only_fit_flags",
        "reference-only-preprocessing-fit/1",
    ),
    ("covariate_confounding:/payload/resample_leakage_count", "resample-leakage-count/1"),
    ("covariate_confounding:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("group_boundary_sensitivity:/payload/ordered_rule_ids", "analysis-rule-identities/1"),
    (
        "group_boundary_sensitivity:/payload/group_count_accounting_equal",
        "group-count-accounting-equality/1",
    ),
    ("group_boundary_sensitivity:/payload/decision_attribution", "report-decision-attribution/1"),
    ("group_boundary_sensitivity:/payload/selected_threshold_flags", "selected-threshold-flag/1"),
    ("group_boundary_sensitivity:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("control_contamination:/payload/contamination_fraction", "declared-contamination-fraction/1"),
    ("control_contamination:/payload/kendall_agreement", "matched-kendall-agreement/1"),
    ("control_contamination:/payload/position_entropy", "matched-position-entropy/1"),
    ("control_contamination:/payload/label_manifest_equal", "label-manifest-equality/1"),
    ("control_contamination:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("heavy_tailed_skewed:/payload/hidden_modification_flags", "hidden-modification-flag/1"),
    ("heavy_tailed_skewed:/payload/suppressed_warning_flags", "suppressed-warning-flag/1"),
    ("heavy_tailed_skewed:/payload/nonfinite_admitted_flags", "nonfinite-admission-flag/1"),
    ("heavy_tailed_skewed:/payload/visible_terminal_flags", "visible-terminal-flag/1"),
    ("heavy_tailed_skewed:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    (
        "wrong_event_direction:/payload/correct_minus_wrong_kendall_agreement",
        "matched-kendall-delta/1",
    ),
    (
        "wrong_event_direction:/payload/direction_sensitivity_reported",
        "required-report-claim-flag/1",
    ),
    ("wrong_event_direction:/payload/direction_validity_claims", "forbidden-report-claim-flag/1"),
    ("wrong_event_direction:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("pure_no_signal:/payload/fpr_evidence", "false-positive-qualification-state/2"),
    ("pure_no_signal:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    ("label_permutation_null:/payload/group_counts_preserved", "group-count-preservation/1"),
    (
        "label_permutation_null:/payload/preprocessing_refit_equal",
        "complete-preprocessing-refit-equality/1",
    ),
    ("label_permutation_null:/payload/source_binding_equal", "null-source-binding-equality/1"),
    (
        "label_permutation_null:/payload/calibration_diagnostic_reported",
        "required-report-claim-flag/1",
    ),
    (
        "label_permutation_null:/payload/excluded_from_pure_no_signal_fpr_denominator",
        "null-family-denominator-exclusion/2",
    ),
    (
        "label_permutation_null:/payload/ineligible_strong_flags",
        "ineligible-strong-evidence-flag/1",
    ),
    ("label_permutation_null:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
    (
        "within_group_feature_permutation_null:/payload/group_marginals_preserved",
        "group-marginal-preservation/1",
    ),
    (
        "within_group_feature_permutation_null:/payload/missing_counts_preserved",
        "missing-count-preservation/1",
    ),
    (
        "within_group_feature_permutation_null:/payload/participant_event_alignment_changed",
        "participant-event-alignment-change/1",
    ),
    (
        "within_group_feature_permutation_null:/payload/preprocessing_refit_equal",
        "complete-preprocessing-refit-equality/1",
    ),
    (
        "within_group_feature_permutation_null:/payload/source_binding_equal",
        "null-source-binding-equality/1",
    ),
    (
        "within_group_feature_permutation_null:/payload/calibration_diagnostic_reported",
        "required-report-claim-flag/1",
    ),
    (
        "within_group_feature_permutation_null:/payload/excluded_from_pure_no_signal_fpr_denominator",
        "null-family-denominator-exclusion/2",
    ),
    (
        "within_group_feature_permutation_null:/payload/ineligible_strong_flags",
        "ineligible-strong-evidence-flag/1",
    ),
    ("within_group_feature_permutation_null:/payload/truth_scoring_mode", "truth-scoring-mode/1"),
)


def _output_schema_ref(meaning_id: str) -> str | None:
    if meaning_id.startswith("*:"):
        return None
    if meaning_id == "pure_no_signal:/payload/fpr_evidence":
        return (
            "schemas/proportional-readiness-contract.schema.json"
            "#/$defs/FalsePositiveQualificationState"
        )
    if meaning_id in {
        "label_permutation_null:/payload/excluded_from_pure_no_signal_fpr_denominator",
        "within_group_feature_permutation_null:/payload/excluded_from_pure_no_signal_fpr_denominator",
    }:
        return "schemas/scenario-family-payload.schema.json#/$defs/BoolVector"
    family_id, output_path = meaning_id.split(":", 1)
    components = output_path.removeprefix("/payload/").split("/")
    property_path = "/".join(component for name in components for component in ("properties", name))
    return (
        "schemas/scenario-family-payload.schema.json#/$defs/"
        f"{_FAMILY_PAYLOAD_DEFINITION[family_id]}/{property_path}"
    )


def _frozen_coverage_rows() -> tuple[dict[str, object], ...]:
    operation_ids_by_family = {
        family_id: tuple(f"{family_id}/{member_id}" for member_id in member_ids)
        for family_id, member_ids in _FAMILY_OPERATION_MEMBERS.items()
    }
    all_operation_ids = tuple(
        operation_id
        for family_id in _FAMILY_OPERATION_MEMBERS
        for operation_id in operation_ids_by_family[family_id]
    )
    rows: list[dict[str, object]] = []
    for ordinal, (meaning_id, derivation_id) in enumerate(_FROZEN_MEANING_DERIVATIONS, start=1):
        family_id = meaning_id.split(":", 1)[0]
        operation_group_id = "common_lifecycle" if family_id == "*" else family_id
        rows.append(
            {
                "ordinal": ordinal,
                "meaning_id": meaning_id,
                "operation_group_id": operation_group_id,
                "operation_ids": (
                    all_operation_ids if family_id == "*" else operation_ids_by_family[family_id]
                ),
                "output_schema_ref": _output_schema_ref(meaning_id),
                "derivation_id": derivation_id,
            }
        )
    if (
        len(rows) != 104
        or len({cast(str, row["meaning_id"]) for row in rows}) != 104
        or len(all_operation_ids) != 104
    ):
        _reject()
    return tuple(rows)


def _read_frozen_coverage_rows() -> tuple[dict[str, object], ...]:
    global _FROZEN_COVERAGE_ROWS_CACHE
    with _FROZEN_SOURCE_LOCK:
        if _FROZEN_COVERAGE_ROWS_CACHE is None:
            _FROZEN_COVERAGE_ROWS_CACHE = _frozen_coverage_rows()
        return _FROZEN_COVERAGE_ROWS_CACHE


@final
class _FrozenCoverageRows(Sequence[dict[str, object]]):
    @overload
    def __getitem__(self, index: int) -> dict[str, object]: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[dict[str, object], ...]: ...

    def __getitem__(
        self,
        index: int | slice,
    ) -> dict[str, object] | tuple[dict[str, object], ...]:
        return _read_frozen_coverage_rows()[index]

    def __len__(self) -> int:
        return len(_read_frozen_coverage_rows())


def _read_frozen_coverage_by_id() -> Mapping[str, dict[str, object]]:
    global _FROZEN_COVERAGE_BY_ID_CACHE
    with _FROZEN_SOURCE_LOCK:
        if _FROZEN_COVERAGE_BY_ID_CACHE is None:
            _FROZEN_COVERAGE_BY_ID_CACHE = {
                cast(str, row["meaning_id"]): row
                for row in _read_frozen_coverage_rows()
            }
        return _FROZEN_COVERAGE_BY_ID_CACHE


@final
class _FrozenCoverageById(Mapping[str, dict[str, object]]):
    def __getitem__(self, key: str) -> dict[str, object]:
        return _read_frozen_coverage_by_id()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(_read_frozen_coverage_by_id())

    def __len__(self) -> int:
        return len(_read_frozen_coverage_by_id())


_FROZEN_COVERAGE_ROWS: Final = _FrozenCoverageRows()
_FROZEN_COVERAGE_BY_ID: Final = _FrozenCoverageById()


@dataclass(frozen=True, slots=True)
class _BundleState:
    projection_bytes: bytes


@dataclass(frozen=True, slots=True)
class _ExtensionState:
    projection_bytes: bytes
    claim_projection: AuthenticatedReportClaimProjection
    meaning_bundle: MeaningEvidenceBundle


_BUNDLE_STATES: OneShotWeakRegistry[object, _BundleState]
_BUNDLE_STATES, _BUNDLE_ISSUER = create_one_shot_registry()
_EXTENSION_STATES: OneShotWeakRegistry[object, _ExtensionState]
_EXTENSION_STATES, _EXTENSION_ISSUER = create_one_shot_registry()


@final
class MeaningEvidenceBundle:
    """Opaque immutable owner of exactly 104 ordered meaning records."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> MeaningEvidenceBundle:
        raise TypeError("Meaning evidence bundles are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Meaning evidence bundles cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Meaning evidence bundles are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Meaning evidence bundles cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Meaning evidence bundles cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Meaning evidence bundles cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Meaning evidence bundles cannot be copied or serialized.")

    def __repr__(self) -> str:
        _validated_meaning_bundle(self)
        return "MeaningEvidenceBundle(<opaque>)"

    @property
    def digest(self) -> str:
        return cast(str, _validated_meaning_bundle(self)["bundle_sha256"])


@final
class AuthenticatedMeaningEvidenceExtension:
    """Opaque report extension retaining one claim projection and meaning bundle."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> AuthenticatedMeaningEvidenceExtension:
        raise TypeError("Meaning evidence extensions are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Meaning evidence extensions cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Meaning evidence extensions are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Meaning evidence extensions cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Meaning evidence extensions cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Meaning evidence extensions cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Meaning evidence extensions cannot be copied or serialized.")

    def __repr__(self) -> str:
        _validated_extension(self)
        return "AuthenticatedMeaningEvidenceExtension(<opaque>)"

    @property
    def digest(self) -> str:
        return cast(str, _validated_extension(self)["extension_sha256"])


def _string_list(value: object, *, nonempty: bool = False) -> list[str]:
    if (
        type(value) is not list
        or (nonempty and not value)
        or any(type(item) is not str or not item for item in value)
        or len(value) != len(set(value))
    ):
        _reject()
    return cast(list[str], value)


def _normalized_record(
    value: Mapping[str, object], expected: Mapping[str, object]
) -> dict[str, object]:
    record = dict(value)
    if set(record) != {
        "ordinal",
        "meaning_id",
        "operation_group_id",
        "operation_ids",
        "output_schema_ref",
        "derivation_id",
        "state",
        "value",
        "reason_codes",
        "failure_code",
        "source_record_digests",
    } or any(
        record.get(field) != expected[field]
        for field in (
            "ordinal",
            "meaning_id",
            "operation_group_id",
            "output_schema_ref",
            "derivation_id",
        )
    ):
        _reject()
    state = record.get("state")
    if state not in _MEANING_STATES:
        _reject()
    reason_codes = _string_list(record.get("reason_codes"))
    operation_ids = _string_list(record.get("operation_ids"))
    scenario_not_declared = (
        state == "NOT_APPLICABLE"
        and reason_codes == ["SCIENCE.SCENARIO_NOT_DECLARED"]
    )
    if (scenario_not_declared and operation_ids) or (
        state == "AVAILABLE" and not operation_ids
    ):
        _reject()
    source_digests = _string_list(record.get("source_record_digests"))
    if any(
        len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)
        for digest in source_digests
    ):
        _reject()
    if state == "AVAILABLE":
        if (
            record.get("value") is None
            or reason_codes
            or record.get("failure_code") is not None
            or not source_digests
        ):
            _reject()
        _validate_available_meaning_value(record, expected)
    elif (
        record.get("value") is not None
        or not reason_codes
        or (
            state in {"INVALID", "FAILED"}
            and (type(record.get("failure_code")) is not str or not record["failure_code"])
        )
        or (state in {"UNAVAILABLE", "NOT_APPLICABLE"} and record.get("failure_code") is not None)
    ):
        _reject()
    return copy.deepcopy(record)


def _validate_available_meaning_value(
    record: Mapping[str, object], expected: Mapping[str, object]
) -> None:
    value = record.get("value")
    schema_ref = expected["output_schema_ref"]
    if schema_ref is None:
        if (
            type(value) is not list
            or any(type(item) is not str or not item for item in cast(list[object], value))
            or len(cast(list[object], value)) != len(set(cast(list[object], value)))
        ):
            _reject()
        return
    if type(schema_ref) is not str or not schema_ref.startswith("schemas/"):
        _reject()
    relative_ref = schema_ref.removeprefix("schemas/")
    validator = Draft202012Validator(
        {"$ref": _SCHEMA_BASE_URI + relative_ref},
        registry=_schema_registry(),
        format_checker=_format_checker(),
    )
    try:
        errors = tuple(validator.iter_errors(value))
    except Exception:
        _reject()
    if errors or _contains_nonfinite(value):
        _reject()


def _contains_nonfinite(value: object) -> bool:
    if type(value) is float:
        return not math.isfinite(value)
    if type(value) is list:
        return any(_contains_nonfinite(item) for item in value)
    if type(value) is dict:
        return any(_contains_nonfinite(item) for item in value.values())
    return False


def validate_frozen_meaning_record(value: Mapping[str, object]) -> dict[str, object]:
    """Validate and detach one exact frozen meaning row for report reuse."""

    if not isinstance(value, Mapping):
        _reject()
    meaning_id = value.get("meaning_id")
    expected = _FROZEN_COVERAGE_BY_ID.get(cast(str, meaning_id))
    if expected is None:
        _reject()
    return _normalized_record(value, expected)


def _bundle_from_records(
    *, evidence_graph_digest: str, records: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    if (
        type(evidence_graph_digest) is not str
        or len(evidence_graph_digest) != 64
        or any(char not in "0123456789abcdef" for char in evidence_graph_digest)
        or type(records) not in {tuple, list}
        or len(records) != 104
    ):
        _reject()
    normalized = [
        _normalized_record(record, expected)
        for record, expected in zip(records, _FROZEN_COVERAGE_ROWS, strict=True)
    ]
    counts = {
        state: sum(record["state"] == state for record in normalized)
        for state in ("AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED")
    }
    preimage: dict[str, object] = {
        "schema_version": "ebm-audit-meaning-evidence-bundle/1.0",
        "contract_sha256": _CONTRACT_SHA256,
        "meaning_inventory_sha256": _INVENTORY_SHA256,
        "meaning_coverage_sha256": _COVERAGE_SHA256,
        "evidence_graph_digest": evidence_graph_digest,
        "state_counts": counts,
        "records": normalized,
        "bundle_sha256": None,
    }
    projection = copy.deepcopy(preimage)
    projection["bundle_sha256"] = structured_sha256_hex(_BUNDLE_DOMAIN, preimage)
    return projection


def _issue_meaning_evidence_bundle(
    *, evidence_graph_digest: str, records: Sequence[Mapping[str, object]]
) -> MeaningEvidenceBundle:
    projection = _bundle_from_records(evidence_graph_digest=evidence_graph_digest, records=records)
    owner = object.__new__(MeaningEvidenceBundle)
    _BUNDLE_ISSUER.bind_once(owner, _BundleState(projection_bytes=canonical_json_bytes(projection)))
    _validated_meaning_bundle(owner)
    return owner


def _validated_meaning_bundle(owner: MeaningEvidenceBundle) -> dict[str, object]:
    if type(owner) is not MeaningEvidenceBundle:
        _reject()
    try:
        state = _BUNDLE_STATES.read(owner)
        value = strict_json_loads(state.projection_bytes)
    except (OneShotRegistryError, TypeError, ValueError):
        _reject()
    if type(state) is not _BundleState or type(value) is not dict:
        _reject()
    projection = cast(dict[str, object], value)
    records = projection.get("records")
    if type(records) is not list:
        _reject()
    expected = _bundle_from_records(
        evidence_graph_digest=cast(str, projection.get("evidence_graph_digest")),
        records=cast(list[Mapping[str, object]], records),
    )
    if projection != expected or canonical_json_bytes(projection) != state.projection_bytes:
        _reject()
    _BUNDLE_STATES.require(owner, state)
    return projection


def read_meaning_evidence_bundle(owner: MeaningEvidenceBundle) -> dict[str, object]:
    """Return detached canonical records and their exact bundle digest."""

    return cast(
        dict[str, object],
        strict_json_loads(canonical_json_bytes(_validated_meaning_bundle(owner))),
    )


def _report_claim_extension_binding(
    owner: AuthenticatedReportClaimProjection,
    projection: Mapping[str, object],
) -> tuple[str, str]:
    """Return the authenticated graph and claim digests for either claim form."""

    graph_digest: object
    claim_digest: object
    if "report_claim_projection_sha256" in projection:
        graph_digest = _read_cohort_report_evidence_graph_digest(owner)
        claim_digest = projection.get("report_claim_projection_sha256")
    else:
        graph_digest = projection.get("evidence_graph_digest")
        claim_digest = projection.get("projection_sha256")
    if (
        type(graph_digest) is not str
        or len(graph_digest) != 64
        or any(char not in "0123456789abcdef" for char in graph_digest)
        or type(claim_digest) is not str
        or len(claim_digest) != 64
        or any(char not in "0123456789abcdef" for char in claim_digest)
    ):
        _reject()
    return graph_digest, claim_digest


def _issue_authenticated_meaning_evidence_extension(
    claim_projection: AuthenticatedReportClaimProjection,
    meaning_bundle: MeaningEvidenceBundle,
    *,
    scientific_evidence_digest: str,
    evidence_graph_identity: Mapping[str, object],
) -> AuthenticatedMeaningEvidenceExtension:
    claims = read_authenticated_report_claim_projection(claim_projection)
    meanings = read_meaning_evidence_bundle(meaning_bundle)
    claim_graph_digest, claim_digest = _report_claim_extension_binding(
        claim_projection,
        claims,
    )
    if (
        claim_graph_digest != meanings["evidence_graph_digest"]
        or type(scientific_evidence_digest) is not str
        or len(scientific_evidence_digest) != 64
        or any(char not in "0123456789abcdef" for char in scientific_evidence_digest)
    ):
        _reject()
    graph_identity = _normalized_evidence_graph_identity(evidence_graph_identity)
    preimage: dict[str, object] = {
        "schema_version": "ebm-audit-authenticated-meaning-evidence-extension/1.0",
        "evidence_graph_digest": meanings["evidence_graph_digest"],
        "scientific_evidence_digest": scientific_evidence_digest,
        "evidence_graph_identity": graph_identity,
        "report_claim_projection_sha256": claim_digest,
        "meaning_evidence_bundle_sha256": meanings["bundle_sha256"],
        "extension_sha256": None,
    }
    projection = copy.deepcopy(preimage)
    projection["extension_sha256"] = structured_sha256_hex(_EXTENSION_DOMAIN, preimage)
    owner = object.__new__(AuthenticatedMeaningEvidenceExtension)
    _EXTENSION_ISSUER.bind_once(
        owner,
        _ExtensionState(
            projection_bytes=canonical_json_bytes(projection),
            claim_projection=claim_projection,
            meaning_bundle=meaning_bundle,
        ),
    )
    _validated_extension(owner)
    return owner


def _validated_extension(
    owner: AuthenticatedMeaningEvidenceExtension,
) -> dict[str, object]:
    if type(owner) is not AuthenticatedMeaningEvidenceExtension:
        _reject()
    try:
        state = _EXTENSION_STATES.read(owner)
        projection = strict_json_loads(state.projection_bytes)
    except (OneShotRegistryError, TypeError, ValueError):
        _reject()
    if type(state) is not _ExtensionState or type(projection) is not dict:
        _reject()
    claims = read_authenticated_report_claim_projection(state.claim_projection)
    meanings = read_meaning_evidence_bundle(state.meaning_bundle)
    claim_graph_digest, claim_digest = _report_claim_extension_binding(
        state.claim_projection,
        claims,
    )
    preimage = {
        "schema_version": "ebm-audit-authenticated-meaning-evidence-extension/1.0",
        "evidence_graph_digest": meanings["evidence_graph_digest"],
        "scientific_evidence_digest": projection.get("scientific_evidence_digest"),
        "evidence_graph_identity": projection.get("evidence_graph_identity"),
        "report_claim_projection_sha256": claim_digest,
        "meaning_evidence_bundle_sha256": meanings["bundle_sha256"],
        "extension_sha256": None,
    }
    expected = copy.deepcopy(preimage)
    expected["extension_sha256"] = structured_sha256_hex(_EXTENSION_DOMAIN, preimage)
    if (
        claim_graph_digest != meanings["evidence_graph_digest"]
        or type(projection.get("scientific_evidence_digest")) is not str
        or len(cast(str, projection["scientific_evidence_digest"])) != 64
        or any(
            char not in "0123456789abcdef"
            for char in cast(str, projection["scientific_evidence_digest"])
        )
        or not isinstance(projection.get("evidence_graph_identity"), Mapping)
        or _normalized_evidence_graph_identity(
            cast(Mapping[str, object], projection["evidence_graph_identity"])
        )
        != projection["evidence_graph_identity"]
        or projection != expected
        or canonical_json_bytes(projection) != state.projection_bytes
    ):
        _reject()
    _EXTENSION_STATES.require(owner, state)
    return cast(dict[str, object], projection)


def _normalized_evidence_graph_identity(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {
        "scope",
        "benchmark_subject_digest",
        "operation_plan_sha256",
        "case_bindings",
        "source_record_digests",
    }:
        _reject()
    scope = value.get("scope")
    subject = value.get("benchmark_subject_digest")
    plan = value.get("operation_plan_sha256")
    bindings = value.get("case_bindings")
    source_digests = value.get("source_record_digests")
    if (
        scope not in {"PRIVATE_LOCAL_INPUT", "SCENARIO_CASE", "SCENARIO_COHORT"}
        or (subject is not None and (type(subject) is not str or not subject))
        or type(plan) is not str
        or not plan
        or type(bindings) is not list
        or type(source_digests) is not list
        or len(source_digests) != len(set(cast(list[object], source_digests)))
        or any(
            type(digest) is not str
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            for digest in cast(list[object], source_digests)
        )
    ):
        _reject()
    normalized: list[dict[str, str]] = []
    for item in bindings:
        if (
            type(item) is not dict
            or set(item)
            != {
                "family_id",
                "case_id",
                "source_contract_sha256",
                "scenario_source_sha256",
                "evidence_graph_digest",
            }
            or any(type(field) is not str or not field for field in item.values())
        ):
            _reject()
        graph_digest = cast(str, item["evidence_graph_digest"])
        if len(graph_digest) != 64 or any(char not in "0123456789abcdef" for char in graph_digest):
            _reject()
        normalized.append(cast(dict[str, str], dict(item)))
    if (
        len({item["case_id"] for item in normalized}) != len(normalized)
        or (
            scope == "PRIVATE_LOCAL_INPUT" and (subject is not None or normalized or source_digests)
        )
        or (scope == "SCENARIO_CASE" and (subject is None or plan is None or len(normalized) != 1))
        or (scope == "SCENARIO_COHORT" and (subject is None or plan is None or len(normalized) < 2))
    ):
        _reject()
    return {
        "scope": scope,
        "benchmark_subject_digest": subject,
        "operation_plan_sha256": plan,
        "case_bindings": normalized,
        "source_record_digests": list(cast(list[str], source_digests)),
    }


def read_authenticated_meaning_evidence_extension(
    owner: AuthenticatedMeaningEvidenceExtension,
) -> dict[str, object]:
    """Return one detached renderer input without recomputing claims or meanings."""

    projection = _validated_extension(owner)
    state = _EXTENSION_STATES.read(owner)
    return {
        **cast(
            dict[str, object],
            strict_json_loads(canonical_json_bytes(projection)),
        ),
        "report_claim_projection": read_authenticated_report_claim_projection(
            state.claim_projection
        ),
        "meaning_evidence_bundle": read_meaning_evidence_bundle(state.meaning_bundle),
    }


def validate_meaning_extension_science_join(
    owner: AuthenticatedMeaningEvidenceExtension,
    captured_scientific_run: object,
    sealed_scientific_evidence: object,
    *,
    expected_evidence_graph_identity: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Join one extension to exact sealed science and an optional graph identity."""

    from ebm_audit.science import CapturedScientificRun, SealedScientificEvidence
    from ebm_audit.science.capture import (
        _read_captured_scientific_run,
        _read_sealed_scientific_evidence,
    )

    if (
        type(captured_scientific_run) is not CapturedScientificRun
        or type(sealed_scientific_evidence) is not SealedScientificEvidence
    ):
        _reject()
    extension = read_authenticated_meaning_evidence_extension(owner)
    captured = _read_captured_scientific_run(captured_scientific_run)
    state = _read_sealed_scientific_evidence(sealed_scientific_evidence)
    try:
        science = strict_json_loads(state.canonical_projection_bytes)
    except (TypeError, ValueError):
        _reject()
    if type(science) is not dict:
        _reject()
    digest = science.get("scientific_evidence_digest")
    bare_digest = digest.removeprefix("sha256:") if type(digest) is str else None
    identity = extension.get("evidence_graph_identity")
    meaning_bundle = extension.get("meaning_evidence_bundle")
    meaning_records = (
        meaning_bundle.get("records") if isinstance(meaning_bundle, Mapping) else None
    )
    claim_projection = extension.get("report_claim_projection")
    claim_records = (
        claim_projection.get("records")
        if isinstance(claim_projection, Mapping)
        else None
    )
    captured_operation_ids = tuple(
        candidate.universe_id for candidate in captured.candidates
    )
    if (
        state.capture is not captured_scientific_run
        or captured.plan_digest != science.get("plan_digest")
        or not captured_operation_ids
        or any(
            type(operation_id) is not str or not operation_id
            for operation_id in captured_operation_ids
        )
        or len(captured_operation_ids) != len(set(captured_operation_ids))
        or type(meaning_records) is not list
        or type(claim_records) is not list
        or any(
            not isinstance(record, Mapping)
            or (
                tuple(cast(list[str], record.get("operation_ids")))
                and tuple(cast(list[str], record.get("operation_ids")))
                != captured_operation_ids
            )
            or (
                record.get("state") == "NOT_APPLICABLE"
                and record.get("reason_codes")
                == ["SCIENCE.SCENARIO_NOT_DECLARED"]
                and cast(list[str], record.get("operation_ids"))
            )
            for record in meaning_records
        )
        or any(
            not isinstance(record, Mapping)
            or (
                cast(list[str], record.get("operation_ids"))
                and tuple(cast(list[str], record.get("operation_ids")))
                != captured_operation_ids
            )
            for record in claim_records
        )
        or bare_digest != extension.get("scientific_evidence_digest")
        or not isinstance(identity, Mapping)
        or identity.get("operation_plan_sha256") != science.get("plan_digest")
    ):
        _reject()
    normalized_identity = _normalized_evidence_graph_identity(cast(Mapping[str, object], identity))
    if expected_evidence_graph_identity is not None and normalized_identity != (
        _normalized_evidence_graph_identity(expected_evidence_graph_identity)
    ):
        _reject()
    scope = normalized_identity["scope"]
    binding = science.get("synthetic_case_binding")
    case_bindings = cast(list[dict[str, str]], normalized_identity["case_bindings"])
    if scope == "PRIVATE_LOCAL_INPUT":
        if binding is not None:
            _reject()
    elif scope == "SCENARIO_CASE":
        if type(binding) is not dict or len(case_bindings) != 1:
            _reject()
        case = case_bindings[0]
        if case["case_id"] != binding.get("case_id") or case[
            "source_contract_sha256"
        ] != binding.get("source_contract_sha256"):
            _reject()
    elif expected_evidence_graph_identity is None:
        _reject()
    return extension


def issue_default_meaning_evidence_extension(
    *, evidence_graph_digest: str, operation_plan_sha256: str | None = None
) -> AuthenticatedMeaningEvidenceExtension:
    """Issue the honest non-challenge extension without inventing scenario evidence."""

    from ebm_audit.evaluator.report_claim_projection import (
        _REPORT_PREDICATE_ORDER,
        REPORT_CLAIM_DIRECTIVES,
        _issue_authenticated_report_claim_projection,
    )

    claims = _issue_authenticated_report_claim_projection(
        evidence_graph_digest=evidence_graph_digest,
        records=[
            {
                "predicate_id": predicate_id,
                "directive": {
                    field: REPORT_CLAIM_DIRECTIVES[predicate_id][field]
                    for field in ("rule_id", "effect", "statement_id")
                },
                "state": "UNAVAILABLE",
                "value": None,
                "reason_codes": ["REPORT.PREDICATE_MACHINE_EVIDENCE_UNAVAILABLE"],
                "failure_code": None,
                "input_record_ids": [],
                "source_record_digests": [],
                "operation_ids": [],
            }
            for predicate_id in _REPORT_PREDICATE_ORDER
        ],
    )
    meanings = _issue_meaning_evidence_bundle(
        evidence_graph_digest=evidence_graph_digest,
        records=[
            {
                **coverage,
                "operation_ids": [],
                "state": "UNAVAILABLE"
                if coverage["operation_group_id"] == "common_lifecycle"
                else "NOT_APPLICABLE",
                "value": None,
                "reason_codes": [
                    "SCIENCE.COMMON_LIFECYCLE_EVIDENCE_UNAVAILABLE"
                    if coverage["operation_group_id"] == "common_lifecycle"
                    else "SCIENCE.SCENARIO_NOT_DECLARED"
                ],
                "failure_code": None,
                "source_record_digests": [],
            }
            for coverage in _FROZEN_COVERAGE_ROWS
        ],
    )
    return _issue_authenticated_meaning_evidence_extension(
        claims,
        meanings,
        scientific_evidence_digest=evidence_graph_digest,
        evidence_graph_identity={
            "scope": "PRIVATE_LOCAL_INPUT",
            "benchmark_subject_digest": None,
            "operation_plan_sha256": operation_plan_sha256 or evidence_graph_digest,
            "case_bindings": [],
            "source_record_digests": [],
        },
    )


__all__ = [
    "AuthenticatedMeaningEvidenceExtension",
    "MeaningEvidenceBundle",
    "MeaningEvidenceBundleError",
    "MeaningState",
    "issue_default_meaning_evidence_extension",
    "read_authenticated_meaning_evidence_extension",
    "read_meaning_evidence_bundle",
    "validate_frozen_meaning_record",
    "validate_meaning_extension_science_join",
]
