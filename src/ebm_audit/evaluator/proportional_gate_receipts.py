"""Durable semantic receipts for the proportional readiness hard gates.

These receipts close facts that the generic hard-gate bundle cannot infer from
an artifact hash.  Every producer evaluates its predicate before issuing a
PASS receipt, and every validator re-evaluates the retained evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Final, Never, cast

from ebm_audit.protocol import structured_sha256_hex

_RECEIPT_DOMAIN: Final = "ebm-audit/proportional-semantic-gate-receipt/1"
_COMMON_FIELDS: Final = frozenset(
    {
        "schema_version",
        "artifact_id",
        "candidate_plan_freeze_receipt_sha256",
        "challenge_attempt_receipt_sha256",
        "finalization_handoff_sha256",
        "evidence",
        "state",
        "failure_code",
        "semantic_gate_receipt_sha256",
    }
)
_SCHEMA_BY_ARTIFACT: Final = {
    "FRESH_ENVIRONMENT_HANDOFF_RECEIPT": (
        "ebm-audit-fresh-environment-handoff-semantic-receipt/1.0"
    ),
    "SCIENTIFIC_VALIDATION_RECEIPT": (
        "ebm-audit-scientific-validation-semantic-receipt/1.0"
    ),
    "PRIVACY_SCAN_RECEIPT": "ebm-audit-privacy-scan-semantic-receipt/1.0",
    "OFFLINE_CONTAINMENT_RECEIPT": (
        "ebm-audit-offline-containment-semantic-receipt/1.0"
    ),
    "DETERMINISM_RECEIPT": "ebm-audit-determinism-semantic-receipt/1.0",
    "EXTERNAL_ACTION_AUDIT_RECEIPT": (
        "ebm-audit-external-action-audit-semantic-receipt/1.0"
    ),
}
_FRESH_STEPS: Final = (
    "clean_install",
    "adapter_scaffolding",
    "full_conformance",
    "partial_conformance",
    "canonical_audit",
    "report_inspection",
    "offline_use",
)
_OFFLINE_PHASES: Final = (
    "clean_install",
    "full_conformance",
    "partial_conformance",
    "challenge",
    "report_rendering",
    "fresh_process_finalization",
)
_PRIVACY_SCOPES: Final = (
    "default_artifact",
    "receipt",
    "log",
    "error",
    "provenance",
    "rendered_surface",
    "protected_boundary",
)
_EXTERNAL_ACTION_IDS: Final = (
    "push",
    "release",
    "outreach",
    "upload",
    "publication",
)
_CHILD_CONTRACT: Final = (
    ("known_truth_recovery", "KnownTruthRecoveryReceipt"),
    ("signal_degradation", "SignalDegradationReceipt"),
    ("non_identifiability", "NonIdentifiabilityReceipt"),
    ("outlier_sensitivity", "OutlierSensitivityReceipt"),
    ("missingness_sensitivity", "MissingnessSensitivityReceipt"),
    ("participant_influence", "ParticipantInfluenceReceipt"),
    ("duplicated_and_correlated_features", "DuplicateFeatureReceipt"),
    ("row_invariance", "RowInvarianceReceipt"),
    ("column_invariance", "ColumnInvarianceReceipt"),
    ("identifier_invariance", "IdentifierInvarianceReceipt"),
    ("different_seed_behavior", "DifferentSeedReceipt"),
    ("small_event_oracle_agreement", "SmallEventOracleReceipt"),
    ("burn_in_handling", "BurnInHandlingReceipt"),
    ("thinning_handling", "ThinningHandlingReceipt"),
    ("event_index_handling", "EventIndexHandlingReceipt"),
    ("stage_index_handling", "StageIndexHandlingReceipt"),
)
_CHILD_FIELDS: Final = frozenset(
    {
        "child_id",
        "evidence_owner",
        "ordered_input_receipt_sha256",
        "observed_facts_sha256",
        "state",
        "failure_code",
    }
)
_ZERO_FIT_CHILD_IDS: Final = (
    "row_invariance",
    "column_invariance",
    "identifier_invariance",
    "different_seed_behavior",
    "small_event_oracle_agreement",
    "burn_in_handling",
    "thinning_handling",
    "event_index_handling",
    "stage_index_handling",
)
_ZERO_FIT_SCHEMA_VERSION: Final = (
    "ebm-audit-proportional-scientific-zero-fit-predicate/1.0"
)
_SAMPLE_INDEX_DOMAIN: Final = (
    "ebm-audit/proportional-scientific-selected-sample-index/1"
)


class ProportionalSemanticGateReceiptError(ValueError):
    """A semantic gate receipt is missing, stale, or contradicted."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> Never:
    raise ProportionalSemanticGateReceiptError(code)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _sha(value: object) -> str:
    if type(value) is not str:
        _reject("SEMANTIC_GATE.SHA256")
    raw = value.removeprefix("sha256:")
    if not _is_sha256(raw):
        _reject("SEMANTIC_GATE.SHA256")
    return raw


def _mapping(value: object, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        _reject(code)
    return cast(Mapping[str, object], value)


def _list(value: object, code: str) -> list[object]:
    if type(value) is not list:
        _reject(code)
    return cast(list[object], value)


def _without_digest(value: Mapping[str, object]) -> dict[str, object]:
    return {
        key: item
        for key, item in value.items()
        if key != "semantic_gate_receipt_sha256"
    }


def _contract_cases(receipt: object) -> dict[str, Mapping[str, object]]:
    raw = _mapping(receipt, "SEMANTIC_GATE.CONTRACT_RECEIPT")
    cases = _list(raw.get("cases"), "SEMANTIC_GATE.CONTRACT_CASES")
    if (
        raw.get("receipt_schema_version") != "ebm-audit-public-contract-test/2.0"
        or raw.get("aggregate_status") != "PASS"
        or not cases
    ):
        _reject("SEMANTIC_GATE.CONTRACT_NOT_PASS")
    indexed: dict[str, Mapping[str, object]] = {}
    for item in cases:
        row = _mapping(item, "SEMANTIC_GATE.CONTRACT_CASE")
        case_id = row.get("case_id")
        if type(case_id) is not str or case_id in indexed:
            _reject("SEMANTIC_GATE.CONTRACT_CASE_ID")
        indexed[case_id] = row
    return indexed


def _case_pass(cases: Mapping[str, Mapping[str, object]], case_id: str) -> bool:
    row = cases.get(case_id)
    return row is not None and row.get("status") == "PASS"


def _meaning_index(value: object) -> dict[str, Mapping[str, object]]:
    rows = _list(value, "SEMANTIC_GATE.MEANING_ROWS")
    if len(rows) != 104:
        _reject("SEMANTIC_GATE.MEANING_COUNT")
    indexed: dict[str, Mapping[str, object]] = {}
    for item in rows:
        row = _mapping(item, "SEMANTIC_GATE.MEANING_ROW")
        meaning_id = row.get("meaning_id")
        if (
            type(meaning_id) is not str
            or meaning_id in indexed
            or row.get("state") != "AVAILABLE"
        ):
            _reject("SEMANTIC_GATE.MEANING_IDENTITY_OR_STATE")
        indexed[meaning_id] = row
    return indexed


def _value(indexed: Mapping[str, Mapping[str, object]], meaning_id: str) -> object:
    row = indexed.get(meaning_id)
    if row is None:
        _reject("SEMANTIC_GATE.MEANING_MISSING")
    return row.get("value")


def _all_equal(value: object, expected: object, *, nonempty: bool = True) -> bool:
    return (
        type(value) is list
        and (bool(value) or not nonempty)
        and all(item == expected for item in cast(list[object], value))
    )


def _all_nonnegative(value: object) -> bool:
    return (
        type(value) is list
        and bool(value)
        and all(
            type(item) in {int, float}
            and not isinstance(item, bool)
            and cast(float, item) >= 0
            for item in cast(list[object], value)
        )
    )


def _meaning_predicate(
    meanings: Mapping[str, Mapping[str, object]],
    child_id: str,
    passed: bool,
    source_ids: tuple[str, ...],
) -> tuple[bool, tuple[str, ...], str]:
    return (
        passed,
        source_ids,
        structured_sha256_hex(
            "ebm-audit/proportional-scientific-meaning-predicate-facts/1",
            {
                "child_id": child_id,
                "ordered_meaning_facts": [
                    {
                        "meaning_id": meaning_id,
                        "state": meanings[meaning_id].get("state"),
                        "value": meanings[meaning_id].get("value"),
                    }
                    for meaning_id in source_ids
                ],
            },
        ),
    )


def _scientific_meaning_predicates(
    meanings: Mapping[str, Mapping[str, object]],
) -> dict[str, tuple[bool, tuple[str, ...], str]]:
    known_inputs = (
        "easy_known_truth:/payload/order_rule_states",
        "easy_known_truth:/payload/stage_rule_states",
        "moderate_mina_shape:/payload/moderate_rule_states",
    )
    known = all(_all_equal(_value(meanings, item), "PASS") for item in known_inputs)
    signal_inputs = (
        "noise_ladder:/payload/noise_ladder_rule_states",
        "small_sample:/payload/entropy_delta_small_minus_large",
        "small_sample:/payload/cross_chain_delta_small_minus_large",
        "weak_pre_post_separation:/payload/entropy_delta_weak_minus_moderate",
        "weak_pre_post_separation:/payload/kendall_distance_delta_weak_minus_moderate",
        "weak_pre_post_separation:/payload/ineligible_strong_flags",
        "incomplete_time_coverage:/payload/affected_tail_entropy_delta",
        "incomplete_time_coverage:/payload/coverage_limitation_reported",
    )
    signal = (
        _all_equal(_value(meanings, signal_inputs[0]), "PASS")
        and all(_all_nonnegative(_value(meanings, item)) for item in signal_inputs[1:5])
        and _all_equal(_value(meanings, signal_inputs[5]), False)
        and _all_nonnegative(_value(meanings, signal_inputs[6]))
        and _all_equal(_value(meanings, signal_inputs[7]), True)
    )
    nonident_inputs = (
        "minority_alternate_sequence:/payload/single_sequence_limitation_reported",
        "opposing_sequences_50_50:/payload/internally_concentrated_flags",
        "opposing_sequences_50_50:/payload/stronger_than_null_flags",
        "near_simultaneous_events:/payload/block_aware_scoring",
    )
    nonident = (
        _all_equal(_value(meanings, nonident_inputs[0]), True)
        and _all_equal(_value(meanings, nonident_inputs[1]), False)
        and _all_equal(_value(meanings, nonident_inputs[2]), False)
        and _all_equal(_value(meanings, nonident_inputs[3]), True)
    )
    influence_id = "outlier_sabotage:/payload/influence_rule_states"
    influence = _all_equal(_value(meanings, influence_id), "PASS")
    missing_inputs = (
        "mcar_missingness:/payload/mask_digest_equal",
        "mcar_missingness:/payload/missing_counts_equal",
        "mcar_missingness:/payload/prebackend_terminal_correct",
        "mcar_missingness:/payload/preprocessing_refit_equal",
        "mar_missingness:/payload/mask_digest_equal",
        "mar_missingness:/payload/missing_counts_equal",
        "mar_missingness:/payload/terminal_contract_equal",
        "mar_missingness:/payload/training_row_manifest_equal",
    )
    missing = all(_all_equal(_value(meanings, item), True) for item in missing_inputs)
    missing = (
        missing
        and _all_equal(
            _value(meanings, "mar_missingness:/payload/silent_loss_flags"),
            False,
        )
        and _all_equal(
            _value(meanings, "mar_missingness:/payload/hidden_imputation_flags"),
            False,
        )
    )
    correlated_id = "correlated_duplicate_events:/payload/correlated/case_ids"
    duplicate_id = (
        "correlated_duplicate_events:/payload/exact_duplicate_post_noise/case_ids"
    )
    correlated_cases = _value(meanings, correlated_id)
    duplicate_cases = _value(meanings, duplicate_id)
    duplicates = (
        type(correlated_cases) is list
        and type(duplicate_cases) is list
        and len(correlated_cases) == len(set(correlated_cases)) == 6
        and len(duplicate_cases) == len(set(duplicate_cases)) == 6
        and _all_equal(
            _value(
                meanings,
                "correlated_duplicate_events:/payload/correlated/"
                "arbitrary_within_pair_truth_claims",
            ),
            False,
        )
        and _all_equal(
            _value(
                meanings,
                "correlated_duplicate_events:/payload/exact_duplicate_post_noise/"
                "partial_truth_scored_without_tiebreak",
            ),
            True,
        )
        and _all_equal(
            _value(
                meanings,
                "correlated_duplicate_events:/payload/exact_duplicate_post_noise/"
                "arbitrary_within_pair_truth_claims",
            ),
            False,
        )
    )
    return {
        "known_truth_recovery": _meaning_predicate(
            meanings,
            "known_truth_recovery",
            known,
            known_inputs,
        ),
        "signal_degradation": _meaning_predicate(
            meanings,
            "signal_degradation",
            signal,
            signal_inputs,
        ),
        "non_identifiability": _meaning_predicate(
            meanings,
            "non_identifiability",
            nonident,
            nonident_inputs,
        ),
        "outlier_sensitivity": _meaning_predicate(
            meanings,
            "outlier_sensitivity",
            influence,
            (influence_id,),
        ),
        "missingness_sensitivity": _meaning_predicate(
            meanings,
            "missingness_sensitivity",
            missing,
            missing_inputs,
        ),
        "participant_influence": _meaning_predicate(
            meanings,
            "participant_influence",
            influence,
            (influence_id,),
        ),
        "duplicated_and_correlated_features": (
            _meaning_predicate(
                meanings,
                "duplicated_and_correlated_features",
                duplicates,
                (correlated_id, duplicate_id),
            )
        ),
    }


def _exact_fields(
    value: object,
    fields: set[str],
    code: str,
) -> Mapping[str, object]:
    row = _mapping(value, code)
    if set(row) != fields:
        _reject(code)
    return row


def _positive_int(value: object, code: str) -> int:
    if type(value) is not int or value < 1:
        _reject(code)
    return value


def _nonnegative_int(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        _reject(code)
    return value


def _validate_invariance_predicate(
    child_id: str,
    evidence: Mapping[str, object],
) -> None:
    expected = {
        "schema_version",
        "predicate_id",
        "source_fixture_sha256",
        "transformed_fixture_sha256",
        "transform_sha256",
        "terminal_payload_vector_sha256",
        "result_evidence_kind",
        "baseline_fitted_result_projection_sha256",
        "transformed_fitted_result_projection_sha256",
        "baseline_authenticated_request_evidence_sha256",
        "transformed_authenticated_request_evidence_sha256",
        "baseline_authenticated_execution_evidence_sha256",
        "transformed_authenticated_execution_evidence_sha256",
        "bijection_sha256",
        "bijection_size",
        "bijection_verified",
        "positional_join_rejected",
        "join_rule_id",
    }
    if set(evidence) != expected:
        _reject(f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}")
    for field in (
        "source_fixture_sha256",
        "transformed_fixture_sha256",
        "transform_sha256",
        "terminal_payload_vector_sha256",
        "baseline_fitted_result_projection_sha256",
        "transformed_fitted_result_projection_sha256",
        "baseline_authenticated_request_evidence_sha256",
        "transformed_authenticated_request_evidence_sha256",
        "baseline_authenticated_execution_evidence_sha256",
        "transformed_authenticated_execution_evidence_sha256",
        "bijection_sha256",
    ):
        _sha(evidence.get(field))
    expected_rule = {
        "row_invariance": "participant-identifier-join/1",
        "column_invariance": "event-identifier-join/1",
        "identifier_invariance": "bijective-identifier-join/1",
    }[child_id]
    if (
        evidence.get("join_rule_id") != expected_rule
        or evidence.get("source_fixture_sha256")
        == evidence.get("transformed_fixture_sha256")
        or evidence.get("result_evidence_kind")
        != "ACTUAL_AUTHENTICATED_FITTED_RESULT_PROJECTION"
        or evidence.get("baseline_fitted_result_projection_sha256")
        != evidence.get("transformed_fitted_result_projection_sha256")
        or evidence.get("baseline_authenticated_request_evidence_sha256")
        == evidence.get("transformed_authenticated_request_evidence_sha256")
        or evidence.get("baseline_authenticated_execution_evidence_sha256")
        == evidence.get("transformed_authenticated_execution_evidence_sha256")
        or type(evidence.get("bijection_size")) is not int
        or cast(int, evidence["bijection_size"]) < 2
        or evidence.get("bijection_verified") is not True
        or evidence.get("positional_join_rejected") is not True
    ):
        _reject(f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}")


def _validate_different_seed_predicate(evidence: Mapping[str, object]) -> None:
    fields = {
        "schema_version",
        "predicate_id",
        "first_stable_identity_sha256",
        "second_stable_identity_sha256",
        "first_seed_sha256",
        "second_seed_sha256",
        "first_stochastic_fields_sha256",
        "second_stochastic_fields_sha256",
    }
    if set(evidence) != fields:
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.different_seed_behavior")
    for field in fields - {"schema_version", "predicate_id"}:
        _sha(evidence.get(field))
    if (
        evidence.get("first_stable_identity_sha256")
        != evidence.get("second_stable_identity_sha256")
        or evidence.get("first_seed_sha256") == evidence.get("second_seed_sha256")
        or evidence.get("first_stochastic_fields_sha256")
        == evidence.get("second_stochastic_fields_sha256")
    ):
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.different_seed_behavior")


def _validate_oracle_predicate(evidence: Mapping[str, object]) -> None:
    fields = {
        "schema_version",
        "predicate_id",
        "ordered_comparisons",
    }
    if set(evidence) != fields:
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.small_event_oracle_agreement")
    rows = _list(
        evidence.get("ordered_comparisons"),
        "SCIENTIFIC_VALIDATION.ZERO_FIT.small_event_oracle_agreement",
    )
    families: set[object] = set()
    identities: set[str] = set()
    for item in rows:
        row = _exact_fields(
            item,
            {
                "family_id",
                "chain_payload_sha256",
                "retained_fitted_result_sha256",
                "exhaustive_oracle_result_sha256",
                "comparison_sha256",
                "event_count",
                "compared_value_count",
                "absolute_tolerance",
                "maximum_absolute_error",
            },
            "SCIENTIFIC_VALIDATION.ZERO_FIT.small_event_oracle_agreement",
        )
        for field in (
            "chain_payload_sha256",
            "retained_fitted_result_sha256",
            "exhaustive_oracle_result_sha256",
            "comparison_sha256",
        ):
            _sha(row.get(field))
        event_count = _positive_int(
            row.get("event_count"),
            "SCIENTIFIC_VALIDATION.ZERO_FIT.small_event_oracle_agreement",
        )
        compared = _positive_int(
            row.get("compared_value_count"),
            "SCIENTIFIC_VALIDATION.ZERO_FIT.small_event_oracle_agreement",
        )
        tolerance = row.get("absolute_tolerance")
        error = row.get("maximum_absolute_error")
        chain_sha256 = cast(str, row["chain_payload_sha256"])
        if (
            row.get("family_id")
            not in {"easy_known_truth", "tightly_spaced_events"}
            or chain_sha256 in identities
            or not 2 <= event_count <= 9
            or compared < event_count
            or type(tolerance) not in {int, float}
            or isinstance(tolerance, bool)
            or cast(float, tolerance) <= 0.0
            or type(error) not in {int, float}
            or isinstance(error, bool)
            or cast(float, error) < 0.0
            or cast(float, error) > cast(float, tolerance)
            or row.get("comparison_sha256")
            != structured_sha256_hex(
            "ebm-audit/proportional-scientific-oracle-comparison/1",
            {
                    "retained_fitted_result_sha256": row.get(
                    "retained_fitted_result_sha256"
                ),
                    "exhaustive_oracle_result_sha256": row.get(
                    "exhaustive_oracle_result_sha256"
                ),
                "event_count": event_count,
                "compared_value_count": compared,
                "absolute_tolerance": tolerance,
                "maximum_absolute_error": error,
            },
        )
        ):
            _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.small_event_oracle_agreement")
        identities.add(chain_sha256)
        families.add(row.get("family_id"))
    if families != {"easy_known_truth", "tightly_spaced_events"}:
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.small_event_oracle_agreement")


def _sampling_rows(evidence: Mapping[str, object], child_id: str) -> list[object]:
    unavailable_fields = {
        "schema_version",
        "predicate_id",
        "applicability_state",
        "reason_code",
        "capability_evidence",
        "ordered_chain_accounting",
    }
    if set(evidence) == unavailable_fields:
        rows = _list(
            evidence.get("ordered_chain_accounting"),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        capability = _exact_fields(
            evidence.get("capability_evidence"),
            {
                "contract_receipt_sha256",
                "sampler_case",
                "ordered_capabilities",
            },
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        sampler_case = _exact_fields(
            capability.get("sampler_case"),
            {"case_id", "status", "required", "applicability"},
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        capabilities = _list(
            capability.get("ordered_capabilities"),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        expected_capabilities = (
            "accepted_transition_diagnostics",
            "likelihood_trace",
            "order_samples",
        )
        if (
            evidence.get("applicability_state")
            != "NOT_APPLICABLE_BY_CAPABILITY"
            or evidence.get("reason_code") != "NON_CHAIN_ALGORITHM"
            or rows
            or not _is_sha256(capability.get("contract_receipt_sha256"))
            or sampler_case.get("case_id")
            != "sampler-off-by-one-and-convergence-finalisation"
            or sampler_case.get("status") not in {"UNSUPPORTED", "NOT_APPLICABLE"}
            or sampler_case.get("required") is not True
            or sampler_case.get("applicability") != "NOT_APPLICABLE"
            or tuple(
                _mapping(
                    row,
                    f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
                ).get("capability_id")
                for row in capabilities
            )
            != expected_capabilities
            or any(
                set(
                    _mapping(
                        row,
                        f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
                    )
                )
                != {"capability_id", "declared", "disposition"}
                or _mapping(
                    row,
                    f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
                ).get("declared")
                is not False
                or _mapping(
                    row,
                    f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
                ).get("disposition")
                != "NOT_APPLICABLE"
                for row in capabilities
            )
        ):
            _reject(f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}")
        return rows
    if set(evidence) != {
        "schema_version",
        "predicate_id",
        "ordered_chain_accounting",
    }:
        _reject(f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}")
    rows = _list(
        evidence.get("ordered_chain_accounting"),
        f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
    )
    if not rows:
        _reject(f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}")
    identities: set[str] = set()
    for item in rows:
        row = _exact_fields(
            item,
            {
                "chain_payload_sha256",
                "raw_iteration_count",
                "burn_in_count",
                "thinning_interval",
                "postburn_unthinned_state_count",
                "retained_state_count",
                "selected_sample_index_sha256",
                "likelihood_indexing",
            },
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        chain_sha = _sha(row.get("chain_payload_sha256"))
        raw = _positive_int(
            row.get("raw_iteration_count"),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        burn = _nonnegative_int(
            row.get("burn_in_count"),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        thinning = _positive_int(
            row.get("thinning_interval"),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        postburn = _positive_int(
            row.get("postburn_unthinned_state_count"),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        retained = _positive_int(
            row.get("retained_state_count"),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        expected_indexes = list(range(burn, raw, thinning))
        if (
            chain_sha in identities
            or raw <= burn
            or postburn != raw - burn
            or retained != (postburn - 1) // thinning + 1
            or len(expected_indexes) != retained
            or row.get("selected_sample_index_sha256")
            != structured_sha256_hex(_SAMPLE_INDEX_DOMAIN, expected_indexes)
            or row.get("likelihood_indexing") != "post-proposal-state/1"
        ):
            _reject(f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}")
        identities.add(chain_sha)
    return rows


def build_zero_fit_predicate_evidence(
    *,
    fixture_projection: Mapping[str, object],
    full_contract_receipt: Mapping[str, object],
    terminal_payload_vector_sha256: str,
    ordered_oracle_comparisons: object,
    ordered_event_roundtrips: object,
    ordered_stage_roundtrips: object,
) -> dict[str, dict[str, object]]:
    """Build the nine scientific predicates from authenticated production facts.

    The function never invokes an adapter or Fit.  Adapter invariance and
    capability conclusions must already be present in the exact public contract
    receipt.  The other inputs are privacy-safe projections from the frozen
    public-synthetic batch and the live captured challenge owners.
    """

    schema = _ZERO_FIT_SCHEMA_VERSION
    fixture = _exact_fields(
        fixture_projection,
        {
            "schema_version",
            "source_case_id",
            "source_fixture_sha256",
            "normalized_source_fixture_sha256",
            "row_permutation",
            "column_permutation",
            "identifier_relabelling",
            "different_seed",
        },
        "SCIENTIFIC_VALIDATION.ZERO_FIT.FIXTURE",
    )
    if (
        fixture.get("schema_version")
        != "ebm-audit-proportional-zero-fit-fixture-projection/1.0"
        or type(fixture.get("source_case_id")) is not str
        or not fixture.get("source_case_id")
        or not _is_sha256(fixture.get("source_fixture_sha256"))
        or not _is_sha256(fixture.get("normalized_source_fixture_sha256"))
        or not _is_sha256(terminal_payload_vector_sha256)
    ):
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.FIXTURE")
    cases = _contract_cases(full_contract_receipt)
    for case_id in (
        "fit-different-seed-no-cache",
        "row-permutation-and-index-roundtrip",
        "feature-column-permutation-and-label-remap",
    ):
        if not _case_pass(cases, case_id):
            _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.CONTRACT_CASE")

    def fitted_result_evidence(case_id: str, child_id: str) -> Mapping[str, object]:
        case = cases[case_id]
        evidence = _mapping(
            case.get("evidence"),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        required = {
            "result_evidence_kind",
            "authenticated_result_evidence",
            "baseline_fitted_result_projection_sha256",
            "transformed_fitted_result_projection_sha256",
            "baseline_authenticated_request_evidence_sha256",
            "transformed_authenticated_request_evidence_sha256",
            "baseline_authenticated_execution_evidence_sha256",
            "transformed_authenticated_execution_evidence_sha256",
            "bijection_sha256",
            "bijection_size",
            "bijection_verified",
            "positional_join_rejected",
        }
        if (
            not required.issubset(evidence)
            or evidence.get("result_evidence_kind")
            != "ACTUAL_FITTED_RESULT_PROJECTION"
            or evidence.get("authenticated_result_evidence") is not True
        ):
            _reject(f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}")
        return evidence

    def invariance(
        child_id: str,
        fixture_key: str,
        join_rule_id: str,
        contract_case_id: str,
    ) -> dict[str, object]:
        transformed = _mapping(
            fixture.get(fixture_key),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        observed = fitted_result_evidence(contract_case_id, child_id)
        result: dict[str, object] = {
            "schema_version": schema,
            "predicate_id": child_id,
            "source_fixture_sha256": fixture["source_fixture_sha256"],
            "transformed_fixture_sha256": transformed.get(
                "transformed_fixture_sha256"
            ),
            "transform_sha256": transformed.get("transform_sha256"),
            "terminal_payload_vector_sha256": terminal_payload_vector_sha256,
            "result_evidence_kind": (
                "ACTUAL_AUTHENTICATED_FITTED_RESULT_PROJECTION"
            ),
            "baseline_fitted_result_projection_sha256": observed[
                "baseline_fitted_result_projection_sha256"
            ],
            "transformed_fitted_result_projection_sha256": observed[
                "transformed_fitted_result_projection_sha256"
            ],
            "baseline_authenticated_request_evidence_sha256": observed[
                "baseline_authenticated_request_evidence_sha256"
            ],
            "transformed_authenticated_request_evidence_sha256": observed[
                "transformed_authenticated_request_evidence_sha256"
            ],
            "baseline_authenticated_execution_evidence_sha256": observed[
                "baseline_authenticated_execution_evidence_sha256"
            ],
            "transformed_authenticated_execution_evidence_sha256": observed[
                "transformed_authenticated_execution_evidence_sha256"
            ],
            "bijection_sha256": observed["bijection_sha256"],
            "bijection_size": observed["bijection_size"],
            "bijection_verified": observed["bijection_verified"],
            "positional_join_rejected": observed["positional_join_rejected"],
            "join_rule_id": join_rule_id,
        }
        return result

    different_seed = _mapping(
        fixture.get("different_seed"),
        "SCIENTIFIC_VALIDATION.ZERO_FIT.different_seed_behavior",
    )
    capability_rows = _list(
        full_contract_receipt.get("capability_applicability"),
        "SCIENTIFIC_VALIDATION.ZERO_FIT.SAMPLING_CAPABILITY",
    )
    capability_by_id = {
        cast(str, row.get("capability_id")): row
        for item in capability_rows
        if isinstance(item, Mapping)
        for row in [cast(Mapping[str, object], item)]
        if type(row.get("capability_id")) is str
    }
    expected_capability_ids = (
        "accepted_transition_diagnostics",
        "likelihood_trace",
        "order_samples",
    )
    selected_capabilities = [
        dict(capability_by_id[capability_id])
        for capability_id in expected_capability_ids
        if capability_id in capability_by_id
    ]
    sampler_case = cases.get(
        "sampler-off-by-one-and-convergence-finalisation"
    )
    if (
        sampler_case is None
        or len(selected_capabilities) != len(expected_capability_ids)
        or sampler_case.get("status") not in {"UNSUPPORTED", "NOT_APPLICABLE"}
        or sampler_case.get("applicability") != "NOT_APPLICABLE"
        or any(
            row.get("declared") is not False
            or row.get("disposition") != "NOT_APPLICABLE"
            for row in selected_capabilities
        )
    ):
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.SAMPLING_CAPABILITY")
    contract_sha256 = structured_sha256_hex(
        "ebm-audit/proportional-scientific-contract-evidence/1",
        full_contract_receipt,
    )
    sampling_evidence: dict[str, object] = {
        "schema_version": schema,
        "predicate_id": "burn_in_handling",
        "applicability_state": "NOT_APPLICABLE_BY_CAPABILITY",
        "reason_code": "NON_CHAIN_ALGORITHM",
        "capability_evidence": {
            "contract_receipt_sha256": contract_sha256,
            "sampler_case": dict(sampler_case),
            "ordered_capabilities": selected_capabilities,
        },
        "ordered_chain_accounting": [],
    }
    evidence = {
        "row_invariance": invariance(
            "row_invariance",
            "row_permutation",
            "participant-identifier-join/1",
            "row-permutation-and-index-roundtrip",
        ),
        "column_invariance": invariance(
            "column_invariance",
            "column_permutation",
            "event-identifier-join/1",
            "feature-column-permutation-and-label-remap",
        ),
        "identifier_invariance": invariance(
            "identifier_invariance",
            "identifier_relabelling",
            "bijective-identifier-join/1",
            "row-permutation-and-index-roundtrip",
        ),
        "different_seed_behavior": {
            "schema_version": schema,
            "predicate_id": "different_seed_behavior",
            **dict(different_seed),
        },
        "small_event_oracle_agreement": {
            "schema_version": schema,
            "predicate_id": "small_event_oracle_agreement",
            "ordered_comparisons": ordered_oracle_comparisons,
        },
        "burn_in_handling": sampling_evidence,
        "thinning_handling": {
            **sampling_evidence,
            "predicate_id": "thinning_handling",
        },
        "event_index_handling": {
            "schema_version": schema,
            "predicate_id": "event_index_handling",
            "ordered_event_roundtrips": ordered_event_roundtrips,
        },
        "stage_index_handling": {
            "schema_version": schema,
            "predicate_id": "stage_index_handling",
            "ordered_stage_roundtrips": ordered_stage_roundtrips,
        },
    }
    _zero_fit_predicates(evidence)
    return evidence


def _validate_event_index_predicate(evidence: Mapping[str, object]) -> None:
    fields = {
        "schema_version",
        "predicate_id",
        "ordered_event_roundtrips",
    }
    if set(evidence) != fields:
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.event_index_handling")
    rows = _list(
        evidence.get("ordered_event_roundtrips"),
        "SCIENTIFIC_VALIDATION.ZERO_FIT.event_index_handling",
    )
    if not rows:
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.event_index_handling")
    for item in rows:
        row = _exact_fields(
            item,
            {
                "family_id",
                "chain_payload_sha256",
                "event_ids",
                "central_order_permutation",
                "central_order_event_ids",
            },
            "SCIENTIFIC_VALIDATION.ZERO_FIT.event_index_handling",
        )
        event_ids = _list(
            row.get("event_ids"),
            "SCIENTIFIC_VALIDATION.ZERO_FIT.event_index_handling",
        )
        permutation = _list(
            row.get("central_order_permutation"),
            "SCIENTIFIC_VALIDATION.ZERO_FIT.event_index_handling",
        )
        ordered_ids = _list(
            row.get("central_order_event_ids"),
            "SCIENTIFIC_VALIDATION.ZERO_FIT.event_index_handling",
        )
        if (
            row.get("family_id")
            not in {"easy_known_truth", "correlated_duplicate_events"}
            or not _is_sha256(row.get("chain_payload_sha256"))
            or len(event_ids) < 2
            or len(set(event_ids)) != len(event_ids)
            or any(type(value) is not str or not value for value in event_ids)
            or any(type(value) is not int for value in permutation)
            or sorted(cast(list[int], permutation)) != list(range(len(event_ids)))
            or ordered_ids
            != [event_ids[cast(int, index)] for index in permutation]
        ):
            _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.event_index_handling")


def _validate_stage_index_predicate(evidence: Mapping[str, object]) -> None:
    fields = {
        "schema_version",
        "predicate_id",
        "ordered_stage_roundtrips",
    }
    if set(evidence) != fields:
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.stage_index_handling")
    rows = _list(
        evidence.get("ordered_stage_roundtrips"),
        "SCIENTIFIC_VALIDATION.ZERO_FIT.stage_index_handling",
    )
    if not rows:
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.stage_index_handling")
    for item in rows:
        row = _exact_fields(
            item,
            {
                "chain_payload_sha256",
                "event_ids",
                "stage_axis_id",
                "pre_event_stage_index",
                "final_stage_index",
                "posterior_shape",
                "reference_order_permutation",
            },
            "SCIENTIFIC_VALIDATION.ZERO_FIT.stage_index_handling",
        )
        event_ids = _list(
            row.get("event_ids"),
            "SCIENTIFIC_VALIDATION.ZERO_FIT.stage_index_handling",
        )
        shape = _list(
            row.get("posterior_shape"),
            "SCIENTIFIC_VALIDATION.ZERO_FIT.stage_index_handling",
        )
        permutation = _list(
            row.get("reference_order_permutation"),
            "SCIENTIFIC_VALIDATION.ZERO_FIT.stage_index_handling",
        )
        if (
            not _is_sha256(row.get("chain_payload_sha256"))
            or len(event_ids) < 2
            or row.get("stage_axis_id") != "strict-prefix-count-v1"
            or row.get("pre_event_stage_index") != 0
            or row.get("final_stage_index") != len(event_ids)
            or len(shape) != 2
            or any(type(value) is not int or value < 1 for value in shape)
            or shape[1] != len(event_ids) + 1
            or any(type(value) is not int for value in permutation)
            or sorted(cast(list[int], permutation)) != list(range(len(event_ids)))
        ):
            _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.stage_index_handling")


def _validate_sampling_predicate(
    evidence: Mapping[str, object],
    child_id: str,
) -> None:
    _sampling_rows(evidence, child_id)


def _zero_fit_predicates(
    value: object,
) -> dict[str, tuple[bool, tuple[str, ...], str]]:
    raw = _mapping(value, "SCIENTIFIC_VALIDATION.ZERO_FIT")
    if set(raw) != set(_ZERO_FIT_CHILD_IDS):
        _reject("SCIENTIFIC_VALIDATION.ZERO_FIT.ORDER")
    validators: dict[str, Callable[[Mapping[str, object]], None]] = {
        "row_invariance": lambda item: _validate_invariance_predicate(
            "row_invariance", item
        ),
        "column_invariance": lambda item: _validate_invariance_predicate(
            "column_invariance", item
        ),
        "identifier_invariance": lambda item: _validate_invariance_predicate(
            "identifier_invariance", item
        ),
        "different_seed_behavior": _validate_different_seed_predicate,
        "small_event_oracle_agreement": _validate_oracle_predicate,
        "burn_in_handling": lambda item: _validate_sampling_predicate(
            item, "burn_in_handling"
        ),
        "thinning_handling": lambda item: _validate_sampling_predicate(
            item, "thinning_handling"
        ),
        "event_index_handling": _validate_event_index_predicate,
        "stage_index_handling": _validate_stage_index_predicate,
    }
    predicates: dict[str, tuple[bool, tuple[str, ...], str]] = {}
    for child_id in _ZERO_FIT_CHILD_IDS:
        evidence = _mapping(
            raw.get(child_id),
            f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}",
        )
        if (
            evidence.get("schema_version") != _ZERO_FIT_SCHEMA_VERSION
            or evidence.get("predicate_id") != child_id
        ):
            _reject(f"SCIENTIFIC_VALIDATION.ZERO_FIT.{child_id}")
        validators[child_id](evidence)
        predicates[child_id] = (
            True,
            (f"zero-fit:{child_id}",),
            structured_sha256_hex(
                "ebm-audit/proportional-scientific-zero-fit-predicate-facts/1",
                evidence,
            ),
        )
    return predicates


def _validate_fresh(evidence: Mapping[str, object]) -> None:
    if set(evidence) != {
        "candidate_git_commit",
        "candidate_git_tree",
        "installation",
        "full_contract_receipt",
        "partial_contract_receipt",
        "ordered_workflow_steps",
        "developer_intervention",
        "undeclared_state",
    }:
        _reject("FRESH_ENVIRONMENT.EVIDENCE_FIELDS")
    installation = _mapping(evidence.get("installation"), "FRESH_ENVIRONMENT.INSTALLATION")
    if (
        type(evidence.get("candidate_git_commit")) is not str
        or type(evidence.get("candidate_git_tree")) is not str
        or installation.get("candidate_git_commit") != evidence.get("candidate_git_commit")
        or installation.get("candidate_git_tree") != evidence.get("candidate_git_tree")
        or installation.get("network_denied_for_complete_interval") is not True
    ):
        _reject("FRESH_ENVIRONMENT.INSTALLATION")
    _contract_cases(evidence.get("full_contract_receipt"))
    _contract_cases(evidence.get("partial_contract_receipt"))
    steps = _list(evidence.get("ordered_workflow_steps"), "FRESH_ENVIRONMENT.STEPS")
    if (
        [
            _mapping(item, "FRESH_ENVIRONMENT.STEP").get("step_id")
            for item in steps
        ]
        != list(_FRESH_STEPS)
        or any(
            _mapping(item, "FRESH_ENVIRONMENT.STEP").get("state") != "PASS"
            or not _is_sha256(
                _mapping(item, "FRESH_ENVIRONMENT.STEP").get("evidence_sha256")
            )
            for item in steps
        )
        or evidence.get("developer_intervention") is not False
        or evidence.get("undeclared_state") is not False
    ):
        _reject("FRESH_ENVIRONMENT.WORKFLOW_NOT_PASS")


def _validate_scientific(evidence: Mapping[str, object]) -> None:
    if set(evidence) != {
        "meaning_evidence_bundle_sha256",
        "proportional_operation_plan_sha256",
        "ordered_public_terminal_vector_sha256",
        "ordered_meaning_results",
        "zero_fit_predicate_evidence",
        "ordered_child_receipts",
    }:
        _reject("SCIENTIFIC_VALIDATION.EVIDENCE_FIELDS")
    for field in (
        "meaning_evidence_bundle_sha256",
        "proportional_operation_plan_sha256",
        "ordered_public_terminal_vector_sha256",
    ):
        _sha(evidence.get(field))
    meanings = _meaning_index(evidence.get("ordered_meaning_results"))
    predicates = {
        **_scientific_meaning_predicates(meanings),
        **_zero_fit_predicates(evidence.get("zero_fit_predicate_evidence")),
    }
    children = _list(
        evidence.get("ordered_child_receipts"),
        "SCIENTIFIC_VALIDATION.CHILDREN",
    )
    if len(children) != len(_CHILD_CONTRACT):
        _reject("SCIENTIFIC_VALIDATION.CHILD_COUNT")
    for item, (child_id, owner) in zip(children, _CHILD_CONTRACT, strict=True):
        row = _mapping(item, "SCIENTIFIC_VALIDATION.CHILD")
        passed, source_ids, predicate_facts_sha256 = predicates[child_id]
        inputs = _list(
            row.get("ordered_input_receipt_sha256"),
            "SCIENTIFIC_VALIDATION.CHILD_INPUTS",
        )
        expected_facts = structured_sha256_hex(
            "ebm-audit/proportional-scientific-child-observed-facts/1",
            {
                "child_id": child_id,
                "source_ids": list(source_ids),
                "ordered_input_receipt_sha256": inputs,
                "predicate_facts_sha256": predicate_facts_sha256,
                "predicate_passed": passed,
            },
        )
        if (
            set(row) != _CHILD_FIELDS
            or row.get("child_id") != child_id
            or row.get("evidence_owner") != owner
            or not inputs
            or any(not _is_sha256(value) for value in inputs)
            or row.get("observed_facts_sha256") != expected_facts
            or not passed
            or row.get("state") != "PASS"
            or row.get("failure_code") is not None
        ):
            _reject(f"SCIENTIFIC_VALIDATION.CHILD.{child_id}")


def _validate_privacy(evidence: Mapping[str, object]) -> None:
    if set(evidence) != {
        "full_contract_receipt",
        "ordered_inventory",
        "no_participant_data_used",
        "protected_boundary_accessed",
    }:
        _reject("PRIVACY_SCAN.EVIDENCE_FIELDS")
    cases = _contract_cases(evidence.get("full_contract_receipt"))
    if not _case_pass(cases, "private-identifier-and-raw-value-canary-scan"):
        _reject("PRIVACY_SCAN.CANARY_NOT_PASS")
    inventory = _list(evidence.get("ordered_inventory"), "PRIVACY_SCAN.INVENTORY")
    scopes: list[object] = []
    paths: set[str] = set()
    for item in inventory:
        row = _mapping(item, "PRIVACY_SCAN.INVENTORY_ROW")
        scope = row.get("scope")
        path = row.get("relative_path")
        if (
            set(row)
            != {
                "scope",
                "relative_path",
                "artifact_sha256",
                "byte_count",
                "direct_identifier_match_count",
                "raw_biomarker_match_count",
            }
            or scope not in _PRIVACY_SCOPES
            or type(path) is not str
            or not path
            or path in paths
            or not _is_sha256(row.get("artifact_sha256"))
            or type(row.get("byte_count")) is not int
            or cast(int, row["byte_count"]) < 0
            or row.get("direct_identifier_match_count") != 0
            or row.get("raw_biomarker_match_count") != 0
        ):
            _reject("PRIVACY_SCAN.INVENTORY_ROW")
        scopes.append(scope)
        paths.add(path)
    if (
        tuple(dict.fromkeys(scopes)) != _PRIVACY_SCOPES
        or evidence.get("no_participant_data_used") is not True
        or evidence.get("protected_boundary_accessed") is not False
    ):
        _reject("PRIVACY_SCAN.INVENTORY_INCOMPLETE")


def _validate_offline(evidence: Mapping[str, object]) -> None:
    if set(evidence) != {
        "provider",
        "launcher_sha256",
        "profile_sha256",
        "command_sha256",
        "run_denial_probe_sha256",
        "finalize_denial_probe_sha256",
        "child_process_inheritance",
        "covered_phases",
    }:
        _reject("OFFLINE_CONTAINMENT.EVIDENCE_FIELDS")
    if (
        evidence.get("provider") != "macos-seatbelt"
        or evidence.get("child_process_inheritance") != "REQUIRED"
        or evidence.get("covered_phases") != list(_OFFLINE_PHASES)
    ):
        _reject("OFFLINE_CONTAINMENT.BOUNDARY")
    for field in (
        "launcher_sha256",
        "profile_sha256",
        "command_sha256",
        "run_denial_probe_sha256",
        "finalize_denial_probe_sha256",
    ):
        _sha(evidence.get(field))


def _validate_determinism(evidence: Mapping[str, object]) -> None:
    if set(evidence) != {
        "full_contract_receipt",
        "input_identity_sha256",
        "configuration_identity_sha256",
        "seed_identity_sha256",
        "environment_identity_sha256",
        "first_artifact_hashes",
        "second_artifact_hashes",
        "different_seed_child_receipt_sha256",
    }:
        _reject("DETERMINISM.EVIDENCE_FIELDS")
    cases = _contract_cases(evidence.get("full_contract_receipt"))
    if not _case_pass(cases, "fit-same-seed-repeatability") or not _case_pass(
        cases,
        "fit-different-seed-no-cache",
    ):
        _reject("DETERMINISM.CONTRACT_CASE")
    for field in (
        "input_identity_sha256",
        "configuration_identity_sha256",
        "seed_identity_sha256",
        "environment_identity_sha256",
        "different_seed_child_receipt_sha256",
    ):
        _sha(evidence.get(field))
    first = _mapping(evidence.get("first_artifact_hashes"), "DETERMINISM.ARTIFACTS")
    second = _mapping(evidence.get("second_artifact_hashes"), "DETERMINISM.ARTIFACTS")
    if (
        set(first)
        != {"report/report.json", "report/meaning-evidence.csv", "report/report.html"}
        or first != second
        or any(not _is_sha256(value) for value in first.values())
    ):
        _reject("DETERMINISM.ARTIFACT_MISMATCH")


def _validate_external(evidence: Mapping[str, object]) -> None:
    if set(evidence) != {
        "offline_containment_receipt_sha256",
        "audited_interval_sha256",
        "ordered_action_inventory",
    }:
        _reject("EXTERNAL_ACTION.EVIDENCE_FIELDS")
    _sha(evidence.get("offline_containment_receipt_sha256"))
    _sha(evidence.get("audited_interval_sha256"))
    rows = _list(evidence.get("ordered_action_inventory"), "EXTERNAL_ACTION.INVENTORY")
    if (
        [
            _mapping(row, "EXTERNAL_ACTION.ROW").get("action_id")
            for row in rows
        ]
        != list(_EXTERNAL_ACTION_IDS)
        or any(
            set(_mapping(row, "EXTERNAL_ACTION.ROW"))
            != {"action_id", "attempted", "observed_count"}
            or _mapping(row, "EXTERNAL_ACTION.ROW").get("attempted") is not False
            or _mapping(row, "EXTERNAL_ACTION.ROW").get("observed_count") != 0
            for row in rows
        )
    ):
        _reject("EXTERNAL_ACTION.INVENTORY_NOT_CLEAN")


_VALIDATORS: Final[dict[str, Callable[[Mapping[str, object]], None]]] = {
    "FRESH_ENVIRONMENT_HANDOFF_RECEIPT": _validate_fresh,
    "SCIENTIFIC_VALIDATION_RECEIPT": _validate_scientific,
    "PRIVACY_SCAN_RECEIPT": _validate_privacy,
    "OFFLINE_CONTAINMENT_RECEIPT": _validate_offline,
    "DETERMINISM_RECEIPT": _validate_determinism,
    "EXTERNAL_ACTION_AUDIT_RECEIPT": _validate_external,
}


def validate_semantic_gate_receipt(
    receipt: Mapping[str, object],
    *,
    artifact_id: str,
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
    finalization_handoff_sha256: str,
) -> str:
    """Re-evaluate one of the six retained semantic gate predicates."""

    raw = _mapping(receipt, "SEMANTIC_GATE.RECEIPT")
    schema = _SCHEMA_BY_ARTIFACT.get(artifact_id)
    validator = _VALIDATORS.get(artifact_id)
    if (
        schema is None
        or validator is None
        or set(raw) != _COMMON_FIELDS
        or raw.get("schema_version") != schema
        or raw.get("artifact_id") != artifact_id
        or raw.get("candidate_plan_freeze_receipt_sha256")
        != candidate_plan_freeze_receipt_sha256
        or raw.get("challenge_attempt_receipt_sha256")
        != challenge_attempt_receipt_sha256
        or raw.get("finalization_handoff_sha256") != finalization_handoff_sha256
        or not _is_sha256(candidate_plan_freeze_receipt_sha256)
        or not _is_sha256(challenge_attempt_receipt_sha256)
        or not _is_sha256(finalization_handoff_sha256)
        or raw.get("state") != "PASS"
        or raw.get("failure_code") is not None
    ):
        _reject("SEMANTIC_GATE.IDENTITY_OR_STATE")
    evidence = _mapping(raw.get("evidence"), "SEMANTIC_GATE.EVIDENCE")
    validator(evidence)
    expected = structured_sha256_hex(
        _RECEIPT_DOMAIN,
        _without_digest(raw),
    )
    if raw.get("semantic_gate_receipt_sha256") != expected:
        _reject("SEMANTIC_GATE.DIGEST")
    return expected


def issue_semantic_gate_receipt(
    *,
    artifact_id: str,
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
    finalization_handoff_sha256: str,
    evidence: Mapping[str, object],
) -> dict[str, object]:
    """Issue one PASS receipt only after its exact predicate succeeds."""

    schema = _SCHEMA_BY_ARTIFACT.get(artifact_id)
    if schema is None:
        _reject("SEMANTIC_GATE.ARTIFACT_ID")
    receipt: dict[str, object] = {
        "schema_version": schema,
        "artifact_id": artifact_id,
        "candidate_plan_freeze_receipt_sha256": candidate_plan_freeze_receipt_sha256,
        "challenge_attempt_receipt_sha256": challenge_attempt_receipt_sha256,
        "finalization_handoff_sha256": finalization_handoff_sha256,
        "evidence": dict(evidence),
        "state": "PASS",
        "failure_code": None,
        "semantic_gate_receipt_sha256": None,
    }
    receipt["semantic_gate_receipt_sha256"] = structured_sha256_hex(
        _RECEIPT_DOMAIN,
        _without_digest(receipt),
    )
    validate_semantic_gate_receipt(
        receipt,
        artifact_id=artifact_id,
        candidate_plan_freeze_receipt_sha256=candidate_plan_freeze_receipt_sha256,
        challenge_attempt_receipt_sha256=challenge_attempt_receipt_sha256,
        finalization_handoff_sha256=finalization_handoff_sha256,
    )
    return receipt


def build_scientific_child_receipts(
    *,
    ordered_meaning_results: Sequence[Mapping[str, object]],
    zero_fit_predicate_evidence: Mapping[str, Mapping[str, object]],
    ordered_input_receipt_sha256: Mapping[str, Sequence[str]],
) -> list[dict[str, object]]:
    """Evaluate and retain all 16 frozen child predicates in contract order."""

    meanings = _meaning_index(list(ordered_meaning_results))
    predicates = {
        **_scientific_meaning_predicates(meanings),
        **_zero_fit_predicates(zero_fit_predicate_evidence),
    }
    rows: list[dict[str, object]] = []
    for child_id, owner in _CHILD_CONTRACT:
        passed, source_ids, predicate_facts_sha256 = predicates[child_id]
        inputs = list(ordered_input_receipt_sha256.get(child_id, ()))
        if not passed or not inputs or any(not _is_sha256(value) for value in inputs):
            _reject(f"SCIENTIFIC_VALIDATION.CHILD.{child_id}")
        rows.append(
            {
                "child_id": child_id,
                "evidence_owner": owner,
                "ordered_input_receipt_sha256": inputs,
                "observed_facts_sha256": structured_sha256_hex(
                    "ebm-audit/proportional-scientific-child-observed-facts/1",
                    {
                        "child_id": child_id,
                        "source_ids": list(source_ids),
                        "ordered_input_receipt_sha256": inputs,
                        "predicate_facts_sha256": predicate_facts_sha256,
                        "predicate_passed": True,
                    },
                ),
                "state": "PASS",
                "failure_code": None,
            }
        )
    return rows


__all__ = [
    "ProportionalSemanticGateReceiptError",
    "build_scientific_child_receipts",
    "build_zero_fit_predicate_evidence",
    "issue_semantic_gate_receipt",
    "validate_semantic_gate_receipt",
]
