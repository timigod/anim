"""Genuine ordinary execution evidence joined to the public operation plan.

The public batch owns case identity.  The proportional plan owns pre-execution
operation identity.  This module owns neither set of facts.  It revalidates
both opaque owners, reads terminal and preparation facts from one live capture,
and issues only records whose complete operation join resolves exactly once.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING, Final, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256_hex
from ebm_audit.schema import validate_instance
from ebm_audit.science.capture import (
    CapturedPublicOperationEvidence,
    CapturedScientificRun,
    PreparationAuditEvidence,
    _issue_captured_public_operation_evidence,
    _issue_preparation_audit_evidence,
    _read_captured_public_operation_evidence,
    _read_preparation_audit_evidence_bundle,
)

if TYPE_CHECKING:
    from ebm_audit.evaluator.proportional_operation_plan import ProportionalOperationPlan
    from ebm_audit.evaluator.scenario_case_batch import (
        AuthenticatedScenarioCaseBatch,
        PublicBatchCasePlan,
    )
    from ebm_audit.evaluator.scenario_source_owner_manifest import _ScenarioSourceRecordInput

_TERMINAL_DOMAIN: Final = "ebm-audit/public-terminal-result/1"
_ROW_MANIFEST_DOMAIN: Final = "ebm-audit/preparation-row-instance-manifest/2"
_PREPROCESSING_DOMAIN: Final = "ebm-audit/preprocessing-execution-record/3"
_COMPLETE_REFIT_PROCEDURE_DOMAIN: Final = "ebm-audit/complete-refit-procedure/1"
_COMPLETE_REFIT_STEP_DOMAIN: Final = "ebm-audit/complete-refit-step-parameters/1"
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_TRANSFORMATION_DOMAIN: Final = "ebm-audit/executed-transformation-evidence/1"
_REFERENCE_ROLE_DOMAIN: Final = "ebm-audit/reference-fit-group-role-evidence/1"
_BOUNDARY_RULE_DOMAIN: Final = "ebm-audit/executed-boundary-rule-identity/1"
_INJECTED_TRUTH_DOMAIN: Final = (
    "ebm-audit/injected-synthetic-participant-truth-identity/1"
)
_INFLUENCE_REMOVAL_DOMAIN: Final = "ebm-audit/influence-removal-evidence/1"
_INFLUENCE_AGGREGATE_DOMAIN: Final = "ebm-audit/case-influence-aggregate/2"
_PLANNED_REMOVAL_DOMAIN: Final = "ebm-audit/planned-influence-removal-identity/1"
_INFLUENCE_RULE_VERSION: Final = (
    "influence-injected-participant-six-component-midranks/1"
)
_ALLOWED_TERMINAL_STATES: Final = frozenset(
    {
        "SUCCESS",
        "CONVERGENCE_WARN",
        "CONVERGENCE_FAILED",
        "CONVERGENCE_NOT_ASSESSABLE",
        "INVALID_INPUT",
        "UNSUPPORTED_CAPABILITY",
        "INVALID_SPECIFICATION",
        "BACKEND_ERROR",
        "TIMEOUT",
        "PRIVACY_VIOLATION",
        "PROTOCOL_ERROR",
    }
)
_COMPLETE_REFIT_STEP_IDS: Final = (
    "prepared-input binding",
    "authenticated worker invocation",
    "fit-result validation",
    "convergence derivation",
    "pairwise concentration",
    "position concentration",
)
_EXECUTION_EVIDENCE_IDENTITIES: Final = {
    "outlier_sabotage:/payload/influence_rule_states": frozenset(
        {
            "PUBLIC_BATCH_CASE_PLAN",
            "PROPORTIONAL_OPERATION_PLAN",
            "PUBLIC_TERMINAL_RESULT",
            "SYNTHETIC_TRUTH",
            "CASE_INFLUENCE_AGGREGATE",
        }
    ),
    "mcar_missingness:/payload/missing_counts_equal": frozenset(
        {
            "SYNTHETIC_TRUTH",
            "SYNTHETIC_SCIENTIFIC_DATA",
            "PREPARATION_AUDIT_EVIDENCE",
        }
    ),
    "mcar_missingness:/payload/prebackend_terminal_correct": frozenset(
        {
            "PROPORTIONAL_OPERATION_PLAN",
            "PUBLIC_TERMINAL_RESULT",
            "PREPARATION_AUDIT_EVIDENCE",
        }
    ),
    "mcar_missingness:/payload/predicted_removed_rows": frozenset(
        {"SYNTHETIC_SCIENTIFIC_DATA", "ANALYSIS_SPEC"}
    ),
    "mcar_missingness:/payload/preprocessing_refit_equal": frozenset(
        {"PROPORTIONAL_OPERATION_PLAN", "PREPROCESSING_EXECUTION_RECORD"}
    ),
    "mar_missingness:/payload/missing_counts_equal": frozenset(
        {
            "SYNTHETIC_TRUTH",
            "SYNTHETIC_SCIENTIFIC_DATA",
            "PREPARATION_AUDIT_EVIDENCE",
        }
    ),
    "mar_missingness:/payload/terminal_contract_equal": frozenset(
        {
            "PROPORTIONAL_OPERATION_PLAN",
            "PUBLIC_TERMINAL_RESULT",
            "PREPARATION_AUDIT_EVIDENCE",
        }
    ),
    "mar_missingness:/payload/training_row_manifest_equal": frozenset(
        {
            "PROPORTIONAL_OPERATION_PLAN",
            "PREPROCESSING_EXECUTION_RECORD",
            "PREPARATION_ROW_INSTANCE_MANIFEST",
        }
    ),
    "mar_missingness:/payload/silent_loss_flags": frozenset(
        {
            "PROPORTIONAL_OPERATION_PLAN",
            "PREPROCESSING_EXECUTION_RECORD",
            "PREPARATION_ROW_INSTANCE_MANIFEST",
            "EXECUTED_TRANSFORMATION_EVIDENCE",
        }
    ),
    "mar_missingness:/payload/hidden_imputation_flags": frozenset(
        {"SYNTHETIC_SCIENTIFIC_DATA", "PREPARATION_AUDIT_EVIDENCE"}
    ),
    "covariate_confounding:/payload/reference_only_fit_flags": frozenset(
        {
            "PROPORTIONAL_OPERATION_PLAN",
            "PREPROCESSING_EXECUTION_RECORD",
            "PREPARATION_ROW_INSTANCE_MANIFEST",
            "REFERENCE_FIT_GROUP_ROLE_EVIDENCE",
        }
    ),
    "covariate_confounding:/payload/resample_leakage_count": frozenset(
        {
            "PROPORTIONAL_OPERATION_PLAN",
            "PREPARATION_ROW_INSTANCE_MANIFEST",
            "REFERENCE_FIT_GROUP_ROLE_EVIDENCE",
        }
    ),
    "group_boundary_sensitivity:/payload/ordered_rule_ids": frozenset(
        {"EXECUTED_BOUNDARY_RULE_IDENTITY"}
    ),
    "group_boundary_sensitivity:/payload/group_count_accounting_equal": frozenset(
        {
            "EXECUTED_BOUNDARY_RULE_IDENTITY",
            "PREPARATION_ROW_INSTANCE_MANIFEST",
            "EXECUTED_TRANSFORMATION_EVIDENCE",
        }
    ),
    "control_contamination:/payload/label_manifest_equal": frozenset(
        {"EXECUTED_TRANSFORMATION_EVIDENCE"}
    ),
    "heavy_tailed_skewed:/payload/hidden_modification_flags": frozenset(
        {"SYNTHETIC_SCIENTIFIC_DATA", "PREPARATION_AUDIT_EVIDENCE"}
    ),
    "label_permutation_null:/payload/group_counts_preserved": frozenset(
        {"EXECUTED_TRANSFORMATION_EVIDENCE"}
    ),
    "label_permutation_null:/payload/preprocessing_refit_equal": frozenset(
        {
            "PROPORTIONAL_OPERATION_PLAN",
            "EXECUTED_TRANSFORMATION_EVIDENCE",
            "PREPROCESSING_EXECUTION_RECORD",
        }
    ),
    "label_permutation_null:/payload/source_binding_equal": frozenset(
        {
            "PUBLIC_BATCH_CASE_PLAN",
            "PROPORTIONAL_OPERATION_PLAN",
            "EXECUTED_TRANSFORMATION_EVIDENCE",
            "PUBLIC_TERMINAL_RESULT",
        }
    ),
    "label_permutation_null:/payload/excluded_from_pure_no_signal_fpr_denominator": frozenset(
        {
            "SYNTHETIC_TRUTH",
            "PROPORTIONAL_OPERATION_PLAN",
            "EXECUTED_TRANSFORMATION_EVIDENCE",
            "PUBLIC_TERMINAL_RESULT",
        }
    ),
    "within_group_feature_permutation_null:/payload/group_marginals_preserved": frozenset(
        {"EXECUTED_TRANSFORMATION_EVIDENCE"}
    ),
    "within_group_feature_permutation_null:/payload/missing_counts_preserved": frozenset(
        {"EXECUTED_TRANSFORMATION_EVIDENCE"}
    ),
    "within_group_feature_permutation_null:/payload/participant_event_alignment_changed": frozenset(
        {"EXECUTED_TRANSFORMATION_EVIDENCE"}
    ),
    "within_group_feature_permutation_null:/payload/preprocessing_refit_equal": frozenset(
        {
            "PROPORTIONAL_OPERATION_PLAN",
            "EXECUTED_TRANSFORMATION_EVIDENCE",
            "PREPROCESSING_EXECUTION_RECORD",
        }
    ),
    "within_group_feature_permutation_null:/payload/source_binding_equal": frozenset(
        {
            "PUBLIC_BATCH_CASE_PLAN",
            "PROPORTIONAL_OPERATION_PLAN",
            "EXECUTED_TRANSFORMATION_EVIDENCE",
            "PUBLIC_TERMINAL_RESULT",
        }
    ),
    (
        "within_group_feature_permutation_null:/payload/"
        "excluded_from_pure_no_signal_fpr_denominator"
    ): frozenset(
        {
            "SYNTHETIC_TRUTH",
            "PROPORTIONAL_OPERATION_PLAN",
            "EXECUTED_TRANSFORMATION_EVIDENCE",
            "PUBLIC_TERMINAL_RESULT",
        }
    ),
}


class PublicOperationEvidenceError(TypeError):
    """Raised when public execution evidence is forged, detached, or replayed."""


def _reject(message: str) -> Never:
    raise PublicOperationEvidenceError(message)


@dataclass(frozen=True, slots=True)
class _PublicOperationRecord:
    owner_class: str
    owner_schema_ref: str
    source_relative_path: str
    source_record_bytes: bytes
    natural_identity: dict[str, object]
    ordered_support_owner_sha256: tuple[str, ...]
    source_owner: object


@dataclass(slots=True)
class _PublicOperationEvidenceState:
    context: object
    batch: object
    case_plan: object
    operation_plan: object
    captured: CapturedScientificRun
    captured_evidence: CapturedPublicOperationEvidence
    records: tuple[_PublicOperationRecord, ...]
    consumed: bool
    lock: RLock


@final
class PublicOperationEvidence:
    """Opaque ordinary authority for one capture's plan-bound source records."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PublicOperationEvidence:
        raise TypeError("Public operation evidence is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Public operation evidence cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Public operation evidence is immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Public operation evidence cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Public operation evidence cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Public operation evidence cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Public operation evidence cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Public operation evidence cannot be copied or serialized.")


_STATES: OneShotWeakRegistry[PublicOperationEvidence, _PublicOperationEvidenceState]
_STATES, _ISSUER = create_one_shot_registry()


def _plan_projections(
    batch: object,
    case_plan: object,
    operation_plan: object,
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    try:
        from ebm_audit.evaluator.proportional_operation_plan import (
            _read_proportional_operation_plan,
            _read_proportional_operation_plan_entries,
        )
        from ebm_audit.evaluator.scenario_case_batch import (
            _read_public_batch_case_plan,
        )

        case = _read_public_batch_case_plan(
            cast(AuthenticatedScenarioCaseBatch, batch),
            cast(PublicBatchCasePlan, case_plan),
        )
        plan = _read_proportional_operation_plan(
            cast(AuthenticatedScenarioCaseBatch, batch),
            cast(ProportionalOperationPlan, operation_plan),
        )
        entries = _read_proportional_operation_plan_entries(
            cast(AuthenticatedScenarioCaseBatch, batch),
            cast(ProportionalOperationPlan, operation_plan),
        )
    except Exception as error:
        raise PublicOperationEvidenceError(
            "The public case or operation plan is invalid."
        ) from error
    if (
        type(case) is not dict
        or type(plan) is not dict
        or type(entries) is not tuple
        or any(type(entry) is not dict for entry in entries)
        or plan.get("ordered_entries") != list(entries)
        or plan.get("operation_count") != len(entries)
        or plan.get("ordered_operation_instance_ids")
        != [entry.get("operation_instance_id") for entry in entries]
    ):
        _reject("The public operation plan projection is invalid.")
    return case, plan, entries


def _persisted(
    record: dict[str, object],
    *,
    schema_file: str,
    definition: str,
    digest_field: str,
    digest_domain: str,
) -> dict[str, object]:
    preimage = dict(record)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage[digest_field] = None
    validate_instance(preimage, schema_file, definition=definition)
    persisted = dict(preimage)
    persisted["digest_state"] = "PERSISTED"
    persisted[digest_field] = structured_sha256_hex(digest_domain, preimage)
    validate_instance(persisted, schema_file, definition=definition)
    return persisted


def _success_bindings(
    fact: object,
    *,
    benchmark_subject_digest: object,
) -> tuple[str, str] | None:
    """Rebuild one success payload only from the privacy-safe capture fact."""

    fit_digest = getattr(fact, "fit_response_binding_sha256", None)
    payload_bytes = getattr(fact, "canonical_payload_fact_bytes", None)
    if fit_digest is None and payload_bytes is None:
        return None
    if (
        type(fit_digest) is not str
        or len(fit_digest) != 64
        or type(payload_bytes) is not bytes
        or type(benchmark_subject_digest) is not str
    ):
        _reject("Captured scientific success evidence is invalid.")
    payload_fact = strict_json_loads(payload_bytes)
    if type(payload_fact) is not dict:
        _reject("Captured scientific success evidence is invalid.")
    payload = {
        "scientific_payload_schema_version": "ebm-audit-canonical-scientific-payload/1.0",
        "benchmark_subject_digest": benchmark_subject_digest,
        **payload_fact,
    }
    validate_instance(
        payload,
        "canonical-records.schema.json",
        definition="CanonicalScientificPayload",
    )
    return fit_digest, structured_sha256_hex(
        "ebm-audit/canonical-scientific-payload/1", payload
    )


def _record(
    owner_class: str,
    schema_ref: str,
    path: str,
    source: dict[str, object],
    natural_fields: tuple[str, ...],
    owner: object,
    *,
    support: tuple[str, ...] = (),
) -> _PublicOperationRecord:
    try:
        natural_identity = {field: source[field] for field in natural_fields}
    except KeyError as error:
        raise PublicOperationEvidenceError(
            "A public operation source natural identity is incomplete."
        ) from error
    return _PublicOperationRecord(
        owner_class=owner_class,
        owner_schema_ref=schema_ref,
        source_relative_path=path,
        source_record_bytes=canonical_json_bytes(source),
        natural_identity=natural_identity,
        ordered_support_owner_sha256=support,
        source_owner=owner,
    )


def _source_owner_digest(record: _PublicOperationRecord) -> str:
    source = strict_json_loads(record.source_record_bytes)
    if type(source) is not dict:
        _reject("A public operation source record is invalid.")
    return structured_sha256_hex(
        _SOURCE_RECORD_DOMAIN,
        {
            "owner_class": record.owner_class,
            "natural_identity": record.natural_identity,
            "source_record": source,
        },
    )


def _context_truth_record(context_state: object) -> dict[str, object]:
    """Read the exact retained synthetic truth without emitting private material."""

    try:
        from ebm_audit.synthetic.audit_input import (
            _issue_synthetic_truth_scoring_evidence,
            _read_synthetic_truth_scoring_record_bytes,
        )

        input_owner = getattr(context_state, "input_owner", None)
        if input_owner is None:
            _reject("The public operation synthetic truth authority is invalid.")
        evidence = _issue_synthetic_truth_scoring_evidence(input_owner)
        value = strict_json_loads(_read_synthetic_truth_scoring_record_bytes(evidence))
    except Exception as error:
        raise PublicOperationEvidenceError(
            "The public operation synthetic truth authority is invalid."
        ) from error
    if type(value) is not dict:
        _reject("The public operation synthetic truth authority is invalid.")
    return cast(dict[str, object], value)


def _component_seed_manifest_identity(
    batch: object,
    *,
    family_id: str,
    case_id: str,
) -> tuple[str, str]:
    """Read one case seed-manifest digest and its authenticated owner digest."""

    try:
        from ebm_audit.evaluator.scenario_case_batch import (
            _authenticated_resolved_case_source_records,
        )

        records = cast(
            tuple[_ScenarioSourceRecordInput, ...],
            _authenticated_resolved_case_source_records(
                cast(AuthenticatedScenarioCaseBatch, batch),
                family_id=family_id,
                case_id=case_id,
            ),
        )
        matches = tuple(
            record
            for record in records
            if record.owner_class == "COMPONENT_SEED_MANIFEST"
        )
        if len(matches) != 1:
            _reject("The component seed manifest authority is invalid.")
        record = matches[0]
        source = strict_json_loads(record.source_record_bytes)
        natural_identity = dict(record.natural_identity)
        digest = (
            source.get("component_seed_manifest_sha256")
            if type(source) is dict
            else None
        )
        if (
            type(source) is not dict
            or type(digest) is not str
            or len(digest) != 64
            or natural_identity.get("component_seed_manifest_sha256") != digest
        ):
            _reject("The component seed manifest authority is invalid.")
        owner_digest = structured_sha256_hex(
            _SOURCE_RECORD_DOMAIN,
            {
                "owner_class": "COMPONENT_SEED_MANIFEST",
                "natural_identity": natural_identity,
                "source_record": source,
            },
        )
    except PublicOperationEvidenceError:
        raise
    except Exception as error:
        raise PublicOperationEvidenceError(
            "The component seed manifest authority is invalid."
        ) from error
    return digest, owner_digest


def _complete_refit_execution_role(entry: dict[str, object]) -> str:
    family_id = entry.get("family_id")
    member_id = entry.get("member_id")
    if family_id == "mcar_missingness":
        if type(member_id) is not str:
            _reject("The MCAR complete-refit role plan is invalid.")
        role = {
            "source_refit": "SOURCE",
            "transformed_refit": "TRANSFORMED",
        }.get(member_id)
        if role is None:
            _reject("The MCAR complete-refit role plan is invalid.")
        return role
    if member_id == "transformed_refit" or entry.get("operation_kind") in {
        "TRANSFORMATION_NULL_FIT",
        "BOUNDARY_RULE_FIT",
    }:
        return "TRANSFORMED"
    return "SOURCE"


def _validate_mcar_complete_refit_plan(
    case: dict[str, object],
    entries: tuple[dict[str, object], ...],
) -> None:
    if case.get("family_id") != "mcar_missingness":
        return
    if len(entries) != 2 or any(
        type(row.get("operation_ordinal")) is not int for row in entries
    ):
        _reject("The MCAR complete-refit operation plan is invalid.")
    ordered = tuple(sorted(entries, key=lambda row: cast(int, row["operation_ordinal"])))
    if (
        tuple(row.get("member_id") for row in ordered)
        != ("source_refit", "transformed_refit")
        or any(row.get("case_id") != case.get("case_id") for row in ordered)
        or any(row.get("family_id") != "mcar_missingness" for row in ordered)
        or cast(int, ordered[1]["operation_ordinal"])
        != cast(int, ordered[0]["operation_ordinal"]) + 1
    ):
        _reject("The MCAR complete-refit operation plan is invalid.")
    distinct_fields = (
        "operation_instance_id",
        "case_operation_join_key",
        "operation_plan_entry_sha256",
    )
    if any(ordered[0].get(field) == ordered[1].get(field) for field in distinct_fields):
        _reject("The MCAR complete-refit operation plan is replayed.")
    for entry in ordered:
        join_key = entry.get("case_operation_join_key")
        if (
            type(join_key) is not dict
            or join_key.get("benchmark_subject_digest")
            != case.get("benchmark_subject_digest")
            or join_key.get("authenticated_batch_sha256")
            != case.get("authenticated_batch_sha256")
            or join_key.get("case_id") != case.get("case_id")
            or join_key.get("operation_instance_id")
            != entry.get("operation_instance_id")
        ):
            _reject("The MCAR complete-refit operation plan is cross-bound.")


def _complete_refit_procedure_sha256() -> str:
    return structured_sha256_hex(
        _COMPLETE_REFIT_PROCEDURE_DOMAIN,
        {
            "schema_version": "ebm-audit-complete-refit-procedure/1.0",
            "digest_state": "DIGEST_PREIMAGE",
            "refit_mode": "complete_refit",
            "ordered_step_ids": list(_COMPLETE_REFIT_STEP_IDS),
            "refit_procedure_sha256": None,
        },
    )


def _complete_refit_step_records(
    fact: object,
    direct_preparation: dict[str, object],
    row_digests: dict[str, str],
) -> list[dict[str, object]]:
    """Derive the closed six-step procedure from one genuine captured Fit."""

    try:
        payload_bytes = getattr(fact, "canonical_payload_fact_bytes", None)
        response_binding_sha256 = getattr(fact, "fit_response_binding_sha256", None)
        finalized_result_sha256 = getattr(fact, "finalized_result_record_sha256", None)
        executed_request_sha256 = direct_preparation["executed_request_sha256"]
        if (
            type(payload_bytes) is not bytes
            or type(response_binding_sha256) is not str
            or type(finalized_result_sha256) is not str
        ):
            _reject("Captured complete-refit evidence is incomplete.")
        payload = strict_json_loads(payload_bytes)
        chains = payload.get("ordered_chain_payloads") if type(payload) is dict else None
        convergence = payload.get("convergence") if type(payload) is dict else None
        if (
            type(executed_request_sha256) is not str
            or type(chains) is not list
            or not chains
            or type(convergence) is not dict
            or set(row_digests) != {"INPUT", "TRAINING", "OUTPUT", "REFERENCE_FIT"}
        ):
            _reject("Captured complete-refit evidence is incomplete.")
        response_bindings: list[str] = []
        pairwise_arrays: list[object] = []
        position_arrays: list[object] = []
        for chain in chains:
            arrays = chain.get("arrays") if type(chain) is dict else None
            binding = (
                chain.get("fit_evaluator_worker_response_binding_sha256")
                if type(chain) is dict
                else None
            )
            if (
                type(arrays) is not dict
                or "pairwise_precedence" not in arrays
                or "position_probabilities" not in arrays
                or type(binding) is not str
            ):
                _reject("Captured complete-refit evidence is incomplete.")
            response_bindings.append(binding)
            pairwise_arrays.append(arrays["pairwise_precedence"])
            position_arrays.append(arrays["position_probabilities"])
        if response_bindings[0] != response_binding_sha256:
            _reject("Captured complete-refit worker evidence is detached.")
        parameter_facts: tuple[object, ...] = (
            {"executed_request_sha256": executed_request_sha256},
            {"ordered_fit_response_binding_sha256": response_bindings},
            {"finalized_result_record_sha256": finalized_result_sha256},
            {"convergence": convergence},
            {"ordered_pairwise_precedence_arrays": pairwise_arrays},
            {"ordered_position_probability_arrays": position_arrays},
        )
        manifest_pairs = (
            (row_digests["INPUT"], row_digests["TRAINING"], None),
            (
                row_digests["TRAINING"],
                row_digests["OUTPUT"],
                row_digests["TRAINING"],
            ),
            (row_digests["OUTPUT"], row_digests["OUTPUT"], None),
            (row_digests["OUTPUT"], row_digests["OUTPUT"], None),
            (row_digests["OUTPUT"], row_digests["OUTPUT"], None),
            (row_digests["OUTPUT"], row_digests["OUTPUT"], None),
        )
        operation_kinds = (
            "ROW_SELECTION",
            "TRANSFORM",
            "TRANSFORM",
            "TRANSFORM",
            "TRANSFORM",
            "TRANSFORM",
        )
        return [
            {
                "step_id": step_id,
                "operation_kind": operation_kind,
                "input_manifest_sha256": manifests[0],
                "output_manifest_sha256": manifests[1],
                "fit_population_manifest_sha256": manifests[2],
                "parameters_sha256": structured_sha256_hex(
                    _COMPLETE_REFIT_STEP_DOMAIN,
                    {"step_id": step_id, "execution_fact": parameter_fact},
                ),
            }
            for step_id, operation_kind, manifests, parameter_fact in zip(
                _COMPLETE_REFIT_STEP_IDS,
                operation_kinds,
                manifest_pairs,
                parameter_facts,
                strict=True,
            )
        ]
    except PublicOperationEvidenceError:
        raise
    except Exception as error:
        raise PublicOperationEvidenceError(
            "Captured complete-refit evidence is invalid."
        ) from error


def _metric_component(
    metric: object,
    *,
    boolean: bool = False,
) -> tuple[str, float | None, tuple[str, ...]]:
    if type(metric) is not dict:
        return "NOT_ASSESSABLE", None, ("INFLUENCE.COMPONENT_UNAVAILABLE",)
    status = metric.get("status")
    value = metric.get("value")
    reason = metric.get("reason_code")
    if status == "ASSESSABLE":
        if boolean:
            if type(value) is not bool:
                _reject("Captured influence component evidence is invalid.")
            return "ASSESSABLE", float(value), ()
        if type(value) not in {int, float}:
            _reject("Captured influence component evidence is invalid.")
        result = float(cast(int | float, value))
        if not math.isfinite(result) or result < 0:
            _reject("Captured influence component evidence is invalid.")
        return "ASSESSABLE", result, ()
    if status in {"NOT_ASSESSABLE", "NOT_APPLICABLE_BY_CAPABILITY"} and type(reason) is str:
        return "NOT_ASSESSABLE", None, (reason,)
    _reject("Captured influence component evidence is invalid.")


def _influence_components(
    fact: dict[str, object],
) -> dict[str, tuple[str, float | None, tuple[str, ...]]]:
    source = fact.get("component_records")
    if type(source) is not dict:
        return {
            component_id: (
                "NOT_ASSESSABLE",
                None,
                ("INFLUENCE.COMPONENT_UNAVAILABLE",),
            )
            for component_id in (
                "central_order_distance",
                "maximum_event_position_displacement",
                "pairwise_precedence_flips",
                "position_matrix_distance",
                "convergence_fit_change",
                "other_participants_expected_stage_distribution_change",
            )
        }
    return {
        "central_order_distance": _metric_component(
            source.get("central_order_kendall_distance")
        ),
        "maximum_event_position_displacement": _metric_component(
            source.get("maximum_normalized_event_rank_displacement")
        ),
        "pairwise_precedence_flips": _metric_component(
            source.get("strict_pairwise_majority_flip_fraction")
        ),
        "position_matrix_distance": _metric_component(
            source.get("position_matrix_distance")
        ),
        "convergence_fit_change": _metric_component(
            source.get("convergence_degradation"), boolean=True
        ),
        "other_participants_expected_stage_distribution_change": _metric_component(
            source.get("fixed_cohort_stage_wasserstein_median")
        ),
    }


def _descending_midranks(
    values: dict[int, float],
) -> dict[int, float]:
    ordered = sorted(values.items(), key=lambda item: (-item[1], item[0]))
    result: dict[int, float] = {}
    position = 0
    while position < len(ordered):
        end = position + 1
        while end < len(ordered) and ordered[end][1] == ordered[position][1]:
            end += 1
        midrank = ((position + 1) + end) / 2.0
        for tied in ordered[position:end]:
            result[tied[0]] = midrank
        position = end
    return result


def _influence_aggregate_record(
    *,
    case: dict[str, object],
    plan: dict[str, object],
    entries: tuple[dict[str, object], ...],
    terminals: dict[str, dict[str, object]],
    capture: object,
    truth: dict[str, object],
) -> dict[str, object] | None:
    if case.get("family_id") != "outlier_sabotage":
        return None
    baseline_entries = tuple(entry for entry in entries if entry.get("member_id") == "baseline")
    removal_entries = tuple(
        entry
        for entry in entries
        if type(entry.get("member_id")) is str
        and cast(str, entry["member_id"]).startswith("leave_out_")
    )
    if (
        len(baseline_entries) != 1
        or len(removal_entries) < 2
        or [entry.get("member_id") for entry in removal_entries]
        != [f"leave_out_{index:02d}" for index in range(len(removal_entries))]
    ):
        _reject("The planned influence operation set is invalid.")
    operation_fact_by_analysis: dict[str, object] = {}
    for operation_fact in getattr(capture, "operations", ()):
        analysis_sha256 = getattr(operation_fact, "analysis_spec_sha256", None)
        if (
            type(analysis_sha256) is not str
            or analysis_sha256 in operation_fact_by_analysis
        ):
            _reject("Captured influence operation evidence is invalid.")
        operation_fact_by_analysis[analysis_sha256] = operation_fact
    baseline_entry = baseline_entries[0]
    baseline_analysis_sha256 = cast(str, baseline_entry["analysis_spec_sha256"])
    baseline_operation_fact = operation_fact_by_analysis.get(
        baseline_analysis_sha256
    )
    baseline_universe_id = getattr(
        baseline_operation_fact, "operation_instance_id", None
    )
    if type(baseline_universe_id) is not str or not baseline_universe_id:
        _reject("The captured influence baseline universe is invalid.")
    outlier_truth = truth.get("outlier_truth")
    truth_digest = truth.get("truth_object_sha256")
    indexes = outlier_truth.get("participant_indexes") if type(outlier_truth) is dict else None
    if (
        type(indexes) is not list
        or len(indexes) != 1
        or type(indexes[0]) is not int
        or indexes[0] < 0
        or type(truth_digest) is not str
    ):
        _reject("The injected participant truth identity is invalid.")
    truth_identity = _persisted(
        {
            "schema_version": (
                "ebm-audit-injected-synthetic-participant-truth-identity/1.0"
            ),
            "digest_state": "DIGEST_PREIMAGE",
            "truth_object_sha256": truth_digest,
            "injected_participant_internal_index": indexes[0],
            "injected_synthetic_participant_truth_identity_sha256": None,
        },
        schema_file="scenario-evidence.schema.json",
        definition="InjectedSyntheticParticipantTruthIdentity",
        digest_field="injected_synthetic_participant_truth_identity_sha256",
        digest_domain=_INJECTED_TRUTH_DOMAIN,
    )
    fact_by_analysis: dict[str, dict[str, object]] = {}
    for encoded in getattr(capture, "influence_removal_fact_bytes", ()):
        fact = strict_json_loads(encoded)
        analysis = fact.get("removal_analysis_spec_sha256") if type(fact) is dict else None
        if type(fact) is not dict or type(analysis) is not str or analysis in fact_by_analysis:
            _reject("Captured influence removal evidence is invalid.")
        fact_by_analysis[analysis] = cast(dict[str, object], fact)
    planned_removal_analyses = {
        cast(str, entry["analysis_spec_sha256"]) for entry in removal_entries
    }
    if set(fact_by_analysis) != planned_removal_analyses:
        _reject("Captured influence removal coverage is incomplete.")
    planned_identities: list[str] = []
    component_facts: dict[int, dict[str, tuple[str, float | None, tuple[str, ...]]]] = {}
    for index, entry in enumerate(removal_entries):
        identity = structured_sha256_hex(
            _PLANNED_REMOVAL_DOMAIN,
            {
                "proportional_operation_plan_sha256": plan[
                    "proportional_operation_plan_sha256"
                ],
                "case_operation_join_key": entry["case_operation_join_key"],
                "operation_plan_entry_sha256": entry["operation_plan_entry_sha256"],
                "removed_participant_internal_index": index,
            },
        )
        planned_identities.append(identity)
        fact = fact_by_analysis.get(cast(str, entry["analysis_spec_sha256"]))
        removal_operation_fact = operation_fact_by_analysis.get(
            cast(str, entry["analysis_spec_sha256"])
        )
        if (
            fact is None
            or removal_operation_fact is None
            or fact.get("removal_slot_ordinal") != index
            or fact.get("source_analysis_spec_sha256") != baseline_analysis_sha256
            or fact.get("source_universe_id") != baseline_universe_id
            or fact.get("removal_universe_id")
            != getattr(removal_operation_fact, "operation_instance_id", None)
        ):
            _reject("Captured influence removal evidence is cross-bound.")
        component_facts[index] = _influence_components(fact)
    ranks: dict[str, dict[int, float]] = {}
    for component_id in next(iter(component_facts.values())):
        values = {
            index: cast(float, components[component_id][1])
            for index, components in component_facts.items()
            if components[component_id][0] == "ASSESSABLE"
        }
        ranks[component_id] = (
            _descending_midranks(values) if len(values) == len(removal_entries) else {}
        )
    removal_rows: list[dict[str, object]] = []
    for index, (entry, removal_identity) in enumerate(
        zip(removal_entries, planned_identities, strict=True)
    ):
        operation_id = cast(str, entry["operation_instance_id"])
        terminal = terminals.get(operation_id)
        fact = fact_by_analysis.get(cast(str, entry["analysis_spec_sha256"]))
        terminal_status = terminal.get("terminal_status") if terminal is not None else None
        execution_state = (
            "SUCCESS"
            if terminal_status in {"SUCCESS", "CONVERGENCE_WARN"}
            else ("FAILED" if terminal is not None else "MISSING")
        )
        convergence_state = (
            {
                "SUCCESS": "CONVERGENCE_PASS",
                "CONVERGENCE_WARN": "CONVERGENCE_WARN",
                "CONVERGENCE_FAILED": "CONVERGENCE_FAIL",
            }.get(terminal_status, "CONVERGENCE_NOT_ASSESSABLE")
            if type(terminal_status) is str
            else "CONVERGENCE_NOT_ASSESSABLE"
        )
        components: dict[str, object] = {}
        for component_id, (state, value, reason_codes) in component_facts[index].items():
            rank = ranks[component_id].get(index)
            components[component_id] = {
                "state": state,
                "direction": "LARGER_IS_MORE_INFLUENTIAL",
                "value": value,
                "descending_midrank": rank,
                "reason_codes": list(reason_codes),
            }
        assessable_count = sum(
            component[0] == "ASSESSABLE" for component in component_facts[index].values()
        )
        capability_state = (
            "FULL_SIX_COMPONENT"
            if assessable_count == 6
            else ("PARTIAL_COMPONENTS" if assessable_count else "NOT_ASSESSABLE")
        )
        comparability_state = (
            "ALL_COMPONENTS_COMPARABLE"
            if assessable_count == 6
            else (
                "PARTIAL_COMPONENTS_COMPARABLE"
                if assessable_count
                else "NOT_ASSESSABLE"
            )
        )
        aggregate_score: float | None = None
        if assessable_count == 6 and terminal_status == "SUCCESS":
            aggregate_total = 0.0
            for component_id in components:
                aggregate_total += (len(removal_entries) - ranks[component_id][index]) / (
                    len(removal_entries) - 1
                )
            aggregate_score = aggregate_total / 6.0
        row_reason_codes = (
            set(cast(list[str], fact.get("reason_codes", []))) if fact else set()
        )
        for _state, _value, reasons in component_facts[index].values():
            row_reason_codes.update(reasons)
        if execution_state != "SUCCESS":
            row_reason_codes.add(f"CANDIDATE.{terminal_status or 'MISSING'}")
        removal_rows.append(
            _persisted(
                {
                    "schema_version": "ebm-audit-influence-removal-evidence/1.0",
                    "digest_state": "DIGEST_PREIMAGE",
                    "removed_participant_internal_index": index,
                    "removal_identity_sha256": removal_identity,
                    "removal_result_sha256": (
                        terminal.get("finalized_result_record_sha256")
                        if terminal is not None
                        else None
                    ),
                    "execution_state": execution_state,
                    "convergence_state": convergence_state,
                    "capability_state": capability_state,
                    "comparability_state": comparability_state,
                    "components": components,
                    "aggregate_equal_weight_score": aggregate_score,
                    "reason_codes": sorted(row_reason_codes),
                    "influence_removal_evidence_sha256": None,
                },
                schema_file="scenario-evidence.schema.json",
                definition="InfluenceRemovalEvidence",
                digest_field="influence_removal_evidence_sha256",
                digest_domain=_INFLUENCE_REMOVAL_DOMAIN,
            )
        )
    baseline_terminal = terminals.get(cast(str, baseline_entry["operation_instance_id"]))
    baseline_status = (
        baseline_terminal.get("terminal_status") if baseline_terminal is not None else None
    )
    for entry in removal_entries:
        analysis_sha256 = cast(str, entry["analysis_spec_sha256"])
        terminal = terminals.get(cast(str, entry["operation_instance_id"]))
        fact = fact_by_analysis[analysis_sha256]
        if (
            terminal is None
            or fact.get("source_terminal_status") != baseline_status
            or fact.get("removal_terminal_status") != terminal.get("terminal_status")
        ):
            _reject("Captured influence terminal evidence is cross-bound.")
    return _persisted(
        {
            "schema_version": "ebm-audit-case-influence-aggregate/2.0",
            "digest_state": "DIGEST_PREIMAGE",
            "case_id": case["case_id"],
            "baseline_universe_id": baseline_universe_id,
            "influence_rule_version": _INFLUENCE_RULE_VERSION,
            "injected_participant_truth_identity": truth_identity,
            "planned_removal_identity_sha256": planned_identities,
            "ordered_removals": removal_rows,
            "baseline_result_sha256": (
                baseline_terminal.get("finalized_result_record_sha256")
                if baseline_terminal is not None
                else None
            ),
            "baseline_execution_state": (
                "SUCCESS"
                if baseline_status in {"SUCCESS", "CONVERGENCE_WARN"}
                else ("FAILED" if baseline_terminal is not None else "MISSING")
            ),
            "baseline_convergence_state": (
                {
                    "SUCCESS": "CONVERGENCE_PASS",
                    "CONVERGENCE_WARN": "CONVERGENCE_WARN",
                    "CONVERGENCE_FAILED": "CONVERGENCE_FAIL",
                }.get(baseline_status, "CONVERGENCE_NOT_ASSESSABLE")
                if type(baseline_status) is str
                else "CONVERGENCE_NOT_ASSESSABLE"
            ),
            "missing_removal_count": sum(
                row["execution_state"] == "MISSING" for row in removal_rows
            ),
            "duplicate_removal_count": 0,
            "case_influence_aggregate_sha256": None,
        },
        schema_file="scenario-evidence.schema.json",
        definition="CaseInfluenceAggregate",
        digest_field="case_influence_aggregate_sha256",
        digest_domain=_INFLUENCE_AGGREGATE_DOMAIN,
    )


def _build_records(
    owner: PublicOperationEvidence,
    *,
    context: object,
    batch: object,
    case_plan: object,
    operation_plan: object,
    captured: CapturedScientificRun,
    captured_evidence: CapturedPublicOperationEvidence,
) -> tuple[_PublicOperationRecord, ...]:
    try:
        from ebm_audit.evaluator.scenario_evidence import (
            _AuthenticatedScenarioEvidenceContext,
            _read_scenario_evidence_context,
        )

        if type(context) is not _AuthenticatedScenarioEvidenceContext:
            _reject("A live scenario evidence context is required.")
        context_state = _read_scenario_evidence_context(context)
    except PublicOperationEvidenceError:
        raise
    except Exception as error:
        raise PublicOperationEvidenceError(
            "A live scenario evidence context is required."
        ) from error
    if context_state.batch is not batch or context_state.captured_science is not captured:
        _reject("The public operation evidence context is detached.")
    case, plan, entries = _plan_projections(batch, case_plan, operation_plan)
    exact_capture, capture = _read_captured_public_operation_evidence(captured_evidence)
    if exact_capture is not captured:
        _reject("The captured operation owner is detached.")
    case_id = case.get("case_id")
    if (
        capture.synthetic_case_binding.get("case_id") != case_id
        or case.get("family_id") != context_state.identity.family_id
        or case_id != context_state.identity.case_id
        or case.get("benchmark_subject_digest")
        != context_state.identity.benchmark_subject_digest
        or plan.get("benchmark_subject_digest") != case.get("benchmark_subject_digest")
        or plan.get("authenticated_batch_sha256") != case.get("authenticated_batch_sha256")
    ):
        _reject("The capture, public case, and operation plan are cross-bound.")
    matching_entries = tuple(entry for entry in entries if entry.get("case_id") == case_id)
    _validate_mcar_complete_refit_plan(case, matching_entries)
    all_entry_by_operation: dict[str, dict[str, object]] = {}
    for entry in entries:
        operation_id = entry.get("operation_instance_id")
        if type(operation_id) is not str or operation_id in all_entry_by_operation:
            _reject("The public operation plan contains a duplicate operation identity.")
        all_entry_by_operation[operation_id] = entry
    entry_by_operation: dict[str, dict[str, object]] = {}
    entries_by_analysis: dict[str, list[dict[str, object]]] = {}
    for entry in matching_entries:
        operation_id = entry.get("operation_instance_id")
        if type(operation_id) is not str or operation_id in entry_by_operation:
            _reject("The public operation plan contains a duplicate operation identity.")
        entry_by_operation[operation_id] = entry
        analysis_sha256 = entry.get("analysis_spec_sha256")
        if type(analysis_sha256) is not str:
            _reject("The public operation plan analysis identity is invalid.")
        entries_by_analysis.setdefault(analysis_sha256, []).append(entry)

    from ebm_audit.evaluator.scenario_source_owner_manifest import _OWNER_BINDINGS

    records: list[_PublicOperationRecord] = []
    records.append(
        _record(
            "PUBLIC_BATCH_CASE_PLAN",
            _OWNER_BINDINGS["PUBLIC_BATCH_CASE_PLAN"][0],
            f"owners/01-public-batch-case-plan/{cast(int, case['case_ordinal']):08d}.json",
            case,
            _OWNER_BINDINGS["PUBLIC_BATCH_CASE_PLAN"][1],
            owner,
        )
    )
    records.append(
        _record(
            "PROPORTIONAL_OPERATION_PLAN",
            _OWNER_BINDINGS["PROPORTIONAL_OPERATION_PLAN"][0],
            "owners/02-proportional-operation-plan/00000000.json",
            plan,
            _OWNER_BINDINGS["PROPORTIONAL_OPERATION_PLAN"][1],
            owner,
        )
    )
    terminal_by_operation: dict[str, dict[str, object]] = {}
    entry_by_capture_operation: dict[str, dict[str, object]] = {}
    for fact in capture.operations:
        candidates = entries_by_analysis.get(fact.analysis_spec_sha256, [])
        if not candidates:
            _reject("A captured operation is absent from its public case plan.")
        if len(candidates) != 1:
            _reject("A captured operation does not resolve one exact plan entry.")
        entry = candidates[0]
        planned_operation_id = cast(str, entry["operation_instance_id"])
        if planned_operation_id in terminal_by_operation:
            _reject("A captured terminal plan entry was replayed.")
        capture_operation_id = fact.operation_instance_id
        if capture_operation_id is not None:
            if capture_operation_id in entry_by_capture_operation:
                _reject("A captured operation identity was replayed.")
            entry_by_capture_operation[capture_operation_id] = entry
        if (
            fact.terminal_status not in _ALLOWED_TERMINAL_STATES
            or entry.get("family_id") != case.get("family_id")
            or entry.get("case_operation_join_key")
            != {
                "benchmark_subject_digest": case.get("benchmark_subject_digest"),
                "authenticated_batch_sha256": case.get("authenticated_batch_sha256"),
                "case_id": case_id,
                "operation_instance_id": entry["operation_instance_id"],
            }
        ):
            _reject("A captured terminal does not match its exact plan entry.")
        success = fact.terminal_status in {"SUCCESS", "CONVERGENCE_WARN"}
        bindings = _success_bindings(
            fact,
            benchmark_subject_digest=case["benchmark_subject_digest"],
        )
        if success and (bindings is None or not fact.backend_invoked):
            _reject("A successful terminal lacks genuine response and payload bindings.")
        if not success and bindings is not None:
            _reject("A failed terminal contains success-only bindings.")
        terminal = _persisted(
            {
                "schema_version": "ebm-audit-public-terminal-result/1.0",
                "digest_state": "DIGEST_PREIMAGE",
                "benchmark_subject_digest": case["benchmark_subject_digest"],
                "authenticated_batch_sha256": case["authenticated_batch_sha256"],
                "captured_run_sha256": capture.captured_run_sha256,
                "case_id": case_id,
                "family_id": case["family_id"],
                "proportional_operation_plan_sha256": plan["proportional_operation_plan_sha256"],
                "operation_plan_entry_sha256": entry["operation_plan_entry_sha256"],
                "operation_ordinal": entry["operation_ordinal"],
                "operation_instance_id": entry["operation_instance_id"],
                "case_operation_join_key": entry["case_operation_join_key"],
                "terminal_status": fact.terminal_status,
                "reason_code": fact.reason_code,
                "backend_invoked": fact.backend_invoked,
                "fit_response_binding_sha256": bindings[0] if bindings else None,
                "canonical_scientific_payload_sha256": bindings[1] if bindings else None,
                "finalized_result_record_sha256": fact.finalized_result_record_sha256,
                "terminal_record_sha256": fact.terminal_record_sha256,
                "public_terminal_result_sha256": None,
            },
            schema_file="evaluator-receipts.schema.json",
            definition="PublicTerminalResult",
            digest_field="public_terminal_result_sha256",
            digest_domain=_TERMINAL_DOMAIN,
        )
        terminal_by_operation[planned_operation_id] = terminal
        terminal_owner_record = _record(
            "PUBLIC_TERMINAL_RESULT",
            _OWNER_BINDINGS["PUBLIC_TERMINAL_RESULT"][0],
            f"owners/03-public-terminal-result/{cast(int, entry['operation_ordinal']):08d}.json",
            terminal,
            _OWNER_BINDINGS["PUBLIC_TERMINAL_RESULT"][1],
            owner,
        )
        records.append(terminal_owner_record)

    if {
        cast(str, terminal["operation_instance_id"])
        for terminal in terminal_by_operation.values()
    } != set(entry_by_operation):
        _reject("The public terminal result coverage is incomplete.")

    truth_record = _context_truth_record(context_state)
    influence_aggregate = _influence_aggregate_record(
        case=case,
        plan=plan,
        entries=matching_entries,
        terminals=terminal_by_operation,
        capture=capture,
        truth=truth_record,
    )
    if influence_aggregate is not None:
        truth_owner_sha256 = structured_sha256_hex(
            _SOURCE_RECORD_DOMAIN,
            {
                "owner_class": "SYNTHETIC_TRUTH",
                "natural_identity": {
                    "truth_object_sha256": truth_record["truth_object_sha256"]
                },
                "source_record": truth_record,
            },
        )
        terminal_owner_records = tuple(
            record for record in records if record.owner_class == "PUBLIC_TERMINAL_RESULT"
        )
        records.append(
            _record(
                "CASE_INFLUENCE_AGGREGATE",
                _OWNER_BINDINGS["CASE_INFLUENCE_AGGREGATE"][0],
                "owners/04-case-influence-aggregate/00000000.json",
                influence_aggregate,
                _OWNER_BINDINGS["CASE_INFLUENCE_AGGREGATE"][1],
                owner,
                support=(
                    truth_owner_sha256,
                    *(_source_owner_digest(record) for record in terminal_owner_records),
                ),
            )
        )

    direct_by_analysis: dict[str, dict[str, object]] = {}
    for fact in capture.operations:
        if fact.direct_preparation_fact_bytes is None:
            continue
        direct = strict_json_loads(fact.direct_preparation_fact_bytes)
        if (
            type(direct) is not dict
            or direct.get("analysis_spec_sha256") != fact.analysis_spec_sha256
            or fact.analysis_spec_sha256 in direct_by_analysis
        ):
            _reject("Captured direct preparation evidence is invalid.")
        direct_by_analysis[fact.analysis_spec_sha256] = cast(dict[str, object], direct)
    if case.get("family_id") == "group_boundary_sensitivity":
        mechanism = truth_record.get("mechanism_evidence")
        rule_ids = mechanism.get("boundary_rule_ids") if type(mechanism) is dict else None
        cutoffs = (
            mechanism.get("boundary_quantile_cutoffs") if type(mechanism) is dict else None
        )
        if rule_ids != ["boundary_q50", "boundary_q35", "boundary_q65"] or (
            type(cutoffs) is not list
            or len(cutoffs) != 3
            or any(
                type(value) not in {int, float}
                or not math.isfinite(float(cast(int | float, value)))
                for value in cutoffs
            )
        ):
            _reject("The boundary rule truth identity is invalid.")
        quantile_by_rule = {
            "boundary_q50": (0.50, 0),
            "boundary_q35": (0.35, 1),
            "boundary_q65": (0.65, 2),
        }
        entries_by_member = {
            entry.get("member_id"): entry for entry in matching_entries
        }
        if set(entries_by_member) != {"q35", "q50", "q65"}:
            _reject("The boundary rule operation plan is invalid.")
        cutoff_by_rule = dict(
            zip(cast(list[str], rule_ids), cast(list[object], cutoffs), strict=True)
        )
        fact_by_analysis = {
            fact.analysis_spec_sha256: fact for fact in capture.operations
        }
        for rule_ordinal, rule_id in enumerate(
            ("boundary_q50", "boundary_q35", "boundary_q65")
        ):
            entry = entries_by_member[rule_id.removeprefix("boundary_")]
            analysis_sha256 = cast(str, entry["analysis_spec_sha256"])
            terminal = terminal_by_operation[cast(str, entry["operation_instance_id"])]
            boundary_fact = fact_by_analysis.get(analysis_sha256)
            direct = direct_by_analysis.get(analysis_sha256)
            if (
                boundary_fact is None
                or direct is None
                or terminal.get("terminal_status") not in {"SUCCESS", "CONVERGENCE_WARN"}
                or entry.get("operation_kind") != "BOUNDARY_RULE_FIT"
            ):
                continue
            terminal_record = next(
                record
                for record in records
                if record.owner_class == "PUBLIC_TERMINAL_RESULT"
                and record.natural_identity.get("case_operation_join_key")
                == entry["case_operation_join_key"]
            )
            boundary = _persisted(
                {
                    "schema_version": "ebm-audit-executed-boundary-rule-identity/1.0",
                    "digest_state": "DIGEST_PREIMAGE",
                    "benchmark_subject_digest": case["benchmark_subject_digest"],
                    "authenticated_batch_sha256": case["authenticated_batch_sha256"],
                    "case_operation_join_key": entry["case_operation_join_key"],
                    "proportional_operation_plan_sha256": plan[
                        "proportional_operation_plan_sha256"
                    ],
                    "operation_plan_entry_sha256": entry["operation_plan_entry_sha256"],
                    "family_id": case["family_id"],
                    "case_id": case_id,
                    "operation_instance_id": entry["operation_instance_id"],
                    "analysis_spec_sha256": analysis_sha256,
                    "rule_id": rule_id,
                    "cutoff_quantile": quantile_by_rule[rule_id][0],
                    "cutoff_value": cutoff_by_rule[rule_id],
                    "comparator_member_index": quantile_by_rule[rule_id][1],
                    "executed_request_sha256": direct["executed_request_sha256"],
                    "public_terminal_result_sha256": terminal[
                        "public_terminal_result_sha256"
                    ],
                    "executed_result_sha256": boundary_fact.finalized_result_record_sha256,
                    "executed_boundary_rule_identity_sha256": None,
                },
                schema_file="scenario-evidence.schema.json",
                definition="ExecutedBoundaryRuleIdentity",
                digest_field="executed_boundary_rule_identity_sha256",
                digest_domain=_BOUNDARY_RULE_DOMAIN,
            )
            records.append(
                _record(
                    "EXECUTED_BOUNDARY_RULE_IDENTITY",
                    _OWNER_BINDINGS["EXECUTED_BOUNDARY_RULE_IDENTITY"][0],
                    f"owners/04-executed-boundary-rule-identity/{rule_ordinal:08d}.json",
                    boundary,
                    _OWNER_BINDINGS["EXECUTED_BOUNDARY_RULE_IDENTITY"][1],
                    owner,
                    support=(_source_owner_digest(terminal_record),),
                )
            )

    preparation = _issue_preparation_audit_evidence(captured)
    if type(preparation) is PreparationAuditEvidence:
        preparation_records, _row_owner, row_manifests = (
            _read_preparation_audit_evidence_bundle(preparation)
        )
        rows_by_operation: dict[str, list[dict[str, object]]] = {}
        for legacy in row_manifests:
            rows_by_operation.setdefault(cast(str, legacy["operation_instance_id"]), []).append(
                legacy
            )
        component_seed_identity: tuple[str, str] | None = None
        for preparation_record in preparation_records:
            operation_id = cast(str, preparation_record["operation_instance_id"])
            preparation_entry = entry_by_capture_operation.get(operation_id)
            preparation_terminal = (
                None
                if preparation_entry is None
                else terminal_by_operation.get(
                    cast(str, preparation_entry["operation_instance_id"])
                )
            )
            if preparation_entry is None or preparation_terminal is None:
                _reject("Preparation evidence is detached from its planned terminal.")
            if preparation_record.get("analysis_spec_sha256") != preparation_entry.get(
                "analysis_spec_sha256"
            ):
                _reject("Preparation evidence is detached from its plan entry.")
            terminal_owner_record = next(
                record
                for record in records
                if record.owner_class == "PUBLIC_TERMINAL_RESULT"
                and record.natural_identity.get("case_operation_join_key")
                == preparation_terminal["case_operation_join_key"]
            )
            records.append(
                _record(
                    "PREPARATION_AUDIT_EVIDENCE",
                    _OWNER_BINDINGS["PREPARATION_AUDIT_EVIDENCE"][0],
                    "owners/04-preparation-audit-evidence/"
                    f"{cast(int, preparation_entry['operation_ordinal']):08d}.json",
                    preparation_record,
                    _OWNER_BINDINGS["PREPARATION_AUDIT_EVIDENCE"][1],
                    owner,
                    support=(_source_owner_digest(terminal_owner_record),),
                )
            )
            executed_rows: list[dict[str, object]] = []
            for legacy in rows_by_operation.get(operation_id, []):
                executed = _persisted(
                    {
                        "schema_version": "ebm-audit-preparation-row-instance-manifest/2.0",
                        "digest_state": "DIGEST_PREIMAGE",
                        "benchmark_subject_digest": case["benchmark_subject_digest"],
                        "authenticated_batch_sha256": case["authenticated_batch_sha256"],
                        "case_operation_join_key": preparation_entry["case_operation_join_key"],
                        "proportional_operation_plan_sha256": plan[
                            "proportional_operation_plan_sha256"
                        ],
                        "operation_plan_entry_sha256": preparation_entry[
                            "operation_plan_entry_sha256"
                        ],
                        "case_id": case_id,
                        "family_id": case["family_id"],
                        "operation_instance_id": preparation_entry["operation_instance_id"],
                        "row_role": legacy["row_role"],
                        "ordered_row_instances": legacy["ordered_row_instances"],
                        "row_instance_manifest_sha256": None,
                    },
                    schema_file="scenario-evidence.schema.json",
                    definition="ExecutedPreparationRowInstanceManifest",
                    digest_field="row_instance_manifest_sha256",
                    digest_domain=_ROW_MANIFEST_DOMAIN,
                )
                executed_rows.append(executed)
                executed_row_record = _record(
                    "PREPARATION_ROW_INSTANCE_MANIFEST",
                    _OWNER_BINDINGS["PREPARATION_ROW_INSTANCE_MANIFEST"][0],
                    "owners/05-preparation-row-instance-manifest/"
                    f"{cast(int, preparation_entry['operation_ordinal']):08d}-"
                    f"{cast(str, legacy['row_role']).lower()}.json",
                    executed,
                    _OWNER_BINDINGS["PREPARATION_ROW_INSTANCE_MANIFEST"][1],
                    owner,
                    support=(_source_owner_digest(terminal_owner_record),),
                )
                records.append(executed_row_record)
            row_digests = {
                cast(str, row["row_role"]): cast(str, row["row_instance_manifest_sha256"])
                for row in executed_rows
            }
            if set(row_digests) != {"INPUT", "TRAINING", "OUTPUT", "REFERENCE_FIT"}:
                _reject("Executed preparation row coverage is incomplete.")
            row_owner_records = tuple(
                record
                for record in records
                if record.owner_class == "PREPARATION_ROW_INSTANCE_MANIFEST"
                and record.natural_identity.get("case_operation_join_key")
                == preparation_entry["case_operation_join_key"]
            )
            direct = next(
                (fact for fact in capture.operations if fact.operation_instance_id == operation_id),
                None,
            )
            if direct is None or direct.direct_preparation_fact_bytes is None:
                _reject("Captured direct preparation evidence is missing.")
            direct_preparation = strict_json_loads(direct.direct_preparation_fact_bytes)
            if type(direct_preparation) is not dict or direct_preparation.get(
                "analysis_spec_sha256"
            ) != preparation_entry.get("analysis_spec_sha256"):
                _reject("Captured direct preparation evidence is detached.")
            preprocessing: dict[str, object] | None = None
            if preparation_terminal.get("terminal_status") in {"SUCCESS", "CONVERGENCE_WARN"}:
                if component_seed_identity is None:
                    component_seed_identity = _component_seed_manifest_identity(
                        batch,
                        family_id=cast(str, case["family_id"]),
                        case_id=case_id,
                    )
                component_seed_sha256, component_seed_owner_sha256 = (
                    component_seed_identity
                )
                preprocessing = _persisted(
                    {
                        "schema_version": "ebm-audit-preprocessing-execution-record/3.0",
                        "digest_state": "DIGEST_PREIMAGE",
                        "benchmark_subject_digest": case["benchmark_subject_digest"],
                        "authenticated_batch_sha256": case["authenticated_batch_sha256"],
                        "case_operation_join_key": preparation_entry["case_operation_join_key"],
                        "proportional_operation_plan_sha256": plan[
                            "proportional_operation_plan_sha256"
                        ],
                        "operation_plan_entry_sha256": preparation_entry[
                            "operation_plan_entry_sha256"
                        ],
                        "family_id": case["family_id"],
                        "case_id": case_id,
                        "operation_instance_id": preparation_entry["operation_instance_id"],
                        "analysis_spec_sha256": preparation_record[
                            "analysis_spec_sha256"
                        ],
                        "execution_role": _complete_refit_execution_role(preparation_entry),
                        "refit_mode": "complete_refit",
                        "component_seed_manifest_sha256": component_seed_sha256,
                        "input_scientific_data_sha256": preparation_record[
                            "input_scientific_data_sha256"
                        ],
                        "input_row_manifest_sha256": row_digests["INPUT"],
                        "training_row_manifest_sha256": row_digests["TRAINING"],
                        "reference_fit_row_manifest_sha256": row_digests[
                            "REFERENCE_FIT"
                        ],
                        "output_row_manifest_sha256": row_digests["OUTPUT"],
                        "ordered_step_records": _complete_refit_step_records(
                            direct,
                            cast(dict[str, object], direct_preparation),
                            row_digests,
                        ),
                        "preprocessing_parameters_sha256": direct_preparation[
                            "preprocessing_parameters_sha256"
                        ],
                        "refit_procedure_sha256": _complete_refit_procedure_sha256(),
                        "preprocessing_execution_record_sha256": None,
                    },
                    schema_file="scenario-evidence.schema.json",
                    definition="ExecutedPreprocessingExecutionRecord",
                    digest_field="preprocessing_execution_record_sha256",
                    digest_domain=_PREPROCESSING_DOMAIN,
                )
                records.append(
                    _record(
                        "PREPROCESSING_EXECUTION_RECORD",
                        _OWNER_BINDINGS["PREPROCESSING_EXECUTION_RECORD"][0],
                        "owners/06-preprocessing-execution-record/"
                        f"{cast(int, preparation_entry['operation_ordinal']):08d}.json",
                        preprocessing,
                        _OWNER_BINDINGS["PREPROCESSING_EXECUTION_RECORD"][1],
                        owner,
                        support=(
                            component_seed_owner_sha256,
                            *(
                                _source_owner_digest(record)
                                for record in row_owner_records
                            ),
                        ),
                    )
                )
            reference_fit = (
                _persisted(
                    {
                        "schema_version": ("ebm-audit-reference-fit-group-role-evidence/1.0"),
                        "digest_state": "DIGEST_PREIMAGE",
                        "benchmark_subject_digest": case["benchmark_subject_digest"],
                        "authenticated_batch_sha256": case["authenticated_batch_sha256"],
                        "case_operation_join_key": preparation_entry["case_operation_join_key"],
                        "proportional_operation_plan_sha256": plan[
                            "proportional_operation_plan_sha256"
                        ],
                        "operation_plan_entry_sha256": preparation_entry[
                            "operation_plan_entry_sha256"
                        ],
                        "family_id": case["family_id"],
                        "case_id": case_id,
                        "operation_instance_id": preparation_entry["operation_instance_id"],
                        "analysis_spec_sha256": preparation_entry["analysis_spec_sha256"],
                        "method_id": ("reference-group-ordinary-linear-residualisation/1"),
                        "preprocessing_execution_record_sha256": preprocessing[
                            "preprocessing_execution_record_sha256"
                        ],
                        "reference_fit_row_manifest_sha256": row_digests["REFERENCE_FIT"],
                        "reference_group_row_manifest_sha256": direct_preparation[
                            "reference_group_row_manifest_sha256"
                        ],
                        "at_risk_group_row_manifest_sha256": direct_preparation[
                            "at_risk_group_row_manifest_sha256"
                        ],
                        "ordered_applied_group_roles": direct_preparation[
                            "ordered_applied_group_roles"
                        ],
                        "reference_fit_group_role_evidence_sha256": None,
                    },
                    schema_file="scenario-evidence.schema.json",
                    definition="ReferenceFitGroupRoleEvidence",
                    digest_field="reference_fit_group_role_evidence_sha256",
                    digest_domain=_REFERENCE_ROLE_DOMAIN,
                )
                if preprocessing is not None
                and direct_preparation.get("reference_fit_method_id")
                == "reference-group-ordinary-linear-residualisation/1"
                else None
            )
            if reference_fit is not None:
                records.append(
                    _record(
                        "REFERENCE_FIT_GROUP_ROLE_EVIDENCE",
                        _OWNER_BINDINGS["REFERENCE_FIT_GROUP_ROLE_EVIDENCE"][0],
                        "owners/07-reference-fit-group-role-evidence/"
                        f"{cast(int, preparation_entry['operation_ordinal']):08d}.json",
                        reference_fit,
                        _OWNER_BINDINGS["REFERENCE_FIT_GROUP_ROLE_EVIDENCE"][1],
                        owner,
                        support=(_source_owner_digest(row_owner_records[-1]),),
                    )
                )
            transformation = (
                direct_preparation.get("transformation")
                if preprocessing is not None
                else None
            )
            boundary_rule_id: str | None = None
            if (
                transformation is None
                and case.get("family_id") == "group_boundary_sensitivity"
                and preparation_terminal.get("terminal_status") in {"SUCCESS", "CONVERGENCE_WARN"}
            ):
                member_id = preparation_entry.get("member_id")
                boundary_rule_id = (
                    f"boundary_{member_id}" if member_id in {"q35", "q50", "q65"} else None
                )
                preparation_projection = direct_preparation.get(
                    "preparation_projection"
                )
                if (
                    boundary_rule_id is None
                    or type(preparation_projection) is not dict
                ):
                    _reject("Captured boundary preparation evidence is invalid.")
                transformation = {
                    "method_id": boundary_rule_id,
                    "executed_parameters_sha256": structured_sha256_hex(
                        "ebm-audit/executed-boundary-rule-parameters/1",
                        {
                            "rule_id": boundary_rule_id,
                            "cutoff_quantile": {
                                "boundary_q50": 0.50,
                                "boundary_q35": 0.35,
                                "boundary_q65": 0.65,
                            }[boundary_rule_id],
                            "cutoff_value": cutoff_by_rule[boundary_rule_id],
                            "executed_request_sha256": direct_preparation[
                                "executed_request_sha256"
                            ],
                        },
                    ),
                    **cast(dict[str, object], preparation_projection),
                }
            if transformation is not None:
                if type(transformation) is not dict:
                    _reject("Captured transformation evidence is invalid.")
                source_case_id: object
                transformation_id: object
                source_operation_id: object
                source_entry: dict[str, object] | None
                if boundary_rule_id is not None:
                    source_case_id = case_id
                    transformation_id = boundary_rule_id
                    source_operation_id = preparation_entry["operation_instance_id"]
                    source_entry = preparation_entry
                else:
                    source_case_id = preparation_entry.get("source_case_id")
                    transformation_id = preparation_entry.get("transformation_id")
                    source_operation_id = (
                        "moderate_mina_shape/pair_00/signal"
                        if source_case_id is not None
                        else preparation_entry["operation_instance_id"]
                    )
                    source_entry = all_entry_by_operation.get(
                        cast(str, source_operation_id)
                    )
                if (
                    type(source_case_id) is not str
                    or type(transformation_id) is not str
                    or source_entry is None
                    or source_entry.get("case_id") != source_case_id
                ):
                    _reject("Captured transformation ancestry is invalid.")
                transformation_record = _persisted(
                    {
                        "schema_version": ("ebm-audit-executed-transformation-evidence/1.0"),
                        "digest_state": "DIGEST_PREIMAGE",
                        "benchmark_subject_digest": case["benchmark_subject_digest"],
                        "authenticated_batch_sha256": case["authenticated_batch_sha256"],
                        "case_operation_join_key": preparation_entry[
                            "case_operation_join_key"
                        ],
                        "proportional_operation_plan_sha256": plan[
                            "proportional_operation_plan_sha256"
                        ],
                        "operation_plan_entry_sha256": preparation_entry[
                            "operation_plan_entry_sha256"
                        ],
                        "family_id": case["family_id"],
                        "case_id": case_id,
                        "operation_instance_id": preparation_entry[
                            "operation_instance_id"
                        ],
                        "source_case_id": source_case_id,
                        "source_operation_instance_id": source_operation_id,
                        "output_case_id": preparation_entry.get("output_case_id")
                        or case_id,
                        "transformation_id": transformation_id,
                        "executed_parameters_sha256": transformation["executed_parameters_sha256"],
                        "source_scientific_data_sha256": transformation[
                            "source_scientific_data_sha256"
                        ],
                        "output_scientific_data_sha256": transformation[
                            "output_scientific_data_sha256"
                        ],
                        "source_axes_sha256": transformation["source_axes_sha256"],
                        "output_axes_sha256": transformation["output_axes_sha256"],
                        "source_missingness_sha256": transformation["source_missingness_sha256"],
                        "output_missingness_sha256": transformation["output_missingness_sha256"],
                        "source_labels_sha256": transformation["source_labels_sha256"],
                        "output_labels_sha256": transformation["output_labels_sha256"],
                        "source_covariates_sha256": transformation["source_covariates_sha256"],
                        "output_covariates_sha256": transformation["output_covariates_sha256"],
                        "source_participant_event_alignment_sha256": transformation[
                            "source_participant_event_alignment_sha256"
                        ],
                        "output_participant_event_alignment_sha256": transformation[
                            "output_participant_event_alignment_sha256"
                        ],
                        "source_row_manifest_sha256": row_digests["INPUT"],
                        "output_row_manifest_sha256": row_digests["OUTPUT"],
                        "data_accounting": transformation["data_accounting"],
                        "executed_transformation_evidence_sha256": None,
                    },
                    schema_file="scenario-evidence.schema.json",
                    definition="ExecutedTransformationEvidence",
                    digest_field="executed_transformation_evidence_sha256",
                    digest_domain=_TRANSFORMATION_DOMAIN,
                )
                records.append(
                    _record(
                        "EXECUTED_TRANSFORMATION_EVIDENCE",
                        _OWNER_BINDINGS["EXECUTED_TRANSFORMATION_EVIDENCE"][0],
                        "owners/08-executed-transformation-evidence/"
                        f"{cast(int, preparation_entry['operation_ordinal']):08d}.json",
                        transformation_record,
                        _OWNER_BINDINGS["EXECUTED_TRANSFORMATION_EVIDENCE"][1],
                        owner,
                        support=(
                            _source_owner_digest(terminal_owner_record),
                            *(_source_owner_digest(record) for record in row_owner_records),
                        ),
                    )
                )
    identities = [(row.owner_class, canonical_json_bytes(row.natural_identity)) for row in records]
    paths = [row.source_relative_path for row in records]
    if len(set(identities)) != len(identities) or len(set(paths)) != len(paths):
        _reject("Public operation evidence contains duplicate owner identities.")
    return tuple(records)


def _issue_public_operation_evidence(
    context: object,
    case_plan: object,
    operation_plan: object,
) -> PublicOperationEvidence:
    """Issue one exact public operation evidence owner from a live capture."""

    try:
        from ebm_audit.evaluator.scenario_evidence import (
            _AuthenticatedScenarioEvidenceContext,
            _read_scenario_evidence_context,
        )

        if type(context) is not _AuthenticatedScenarioEvidenceContext:
            _reject("Public operation evidence requires a live scenario context.")
        context_state = _read_scenario_evidence_context(context)
        batch = context_state.batch
        captured = context_state.captured_science
        captured_evidence = _issue_captured_public_operation_evidence(
            captured,
            context_state.sealed_science,
        )
    except PublicOperationEvidenceError:
        raise
    except Exception as error:
        raise PublicOperationEvidenceError(
            "Public operation capture authority is invalid."
        ) from error
    owner = object.__new__(PublicOperationEvidence)
    records = _build_records(
        owner,
        context=context,
        batch=batch,
        case_plan=case_plan,
        operation_plan=operation_plan,
        captured=captured,
        captured_evidence=captured_evidence,
    )
    _ISSUER.bind_once(
        owner,
        _PublicOperationEvidenceState(
            context=context,
            batch=batch,
            case_plan=case_plan,
            operation_plan=operation_plan,
            captured=captured,
            captured_evidence=captured_evidence,
            records=records,
            consumed=False,
            lock=RLock(),
        ),
    )
    return owner


def _validated_state(owner: PublicOperationEvidence) -> _PublicOperationEvidenceState:
    if type(owner) is not PublicOperationEvidence:
        _reject("Public operation evidence is invalid.")
    try:
        state = _STATES.read(owner)
    except OneShotRegistryError as error:
        raise PublicOperationEvidenceError("Public operation evidence is invalid.") from error
    current = _build_records(
        owner,
        context=state.context,
        batch=state.batch,
        case_plan=state.case_plan,
        operation_plan=state.operation_plan,
        captured=state.captured,
        captured_evidence=state.captured_evidence,
    )
    if current != state.records:
        _reject("Public operation evidence changed after issuance.")
    return state


def _read_public_operation_evidence_records(
    owner: PublicOperationEvidence,
) -> tuple[_PublicOperationRecord, ...]:
    """Revalidate and read exact source records without exposing capture state."""

    return _validated_state(owner).records


def _read_public_operation_evidence_owners(
    owner: PublicOperationEvidence,
) -> tuple[object, object, CapturedScientificRun]:
    """Read only the exact batch, operation-plan, and capture owners."""

    state = _validated_state(owner)
    return state.batch, state.operation_plan, state.captured


def _consume_public_operation_evidence_records(
    owner: PublicOperationEvidence,
) -> tuple[_PublicOperationRecord, ...]:
    """Consume the complete owner set once at the ordinary collector boundary."""

    state = _validated_state(owner)
    with state.lock:
        if state.consumed:
            _reject("Public operation evidence was replayed.")
        state.consumed = True
        return state.records
