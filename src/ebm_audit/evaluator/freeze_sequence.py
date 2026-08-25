"""Fail-closed public validators for benchmark and candidate freeze sequencing.

These functions validate only closed public owners.  They do not resolve a
private held-out root, authenticate an HMAC, draw a root, or authorize held-out
execution.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Final, Never

from ebm_audit.protocol import (
    backend_identity_digest,
    requested_outputs_digest,
    settings_digest,
    structured_sha256,
    structured_sha256_hex,
)
from ebm_audit.schema import SchemaValidationError, load_protocol_registry, validate_instance
from ebm_audit.universe import analysis_spec_content_id

_SCHEMA: Final = "evaluator-receipts.schema.json"
_SUBJECT_DOMAIN: Final = "ebm-audit/benchmark-subject/1"
_PROFILE_PLAN_RECEIPT_DOMAIN: Final = "ebm-audit/profile-characterization-plan-receipt/3"
_PROFILE_SYNTHETIC_EVENT_BINDING_DOMAIN: Final = "ebm-audit/profile-synthetic-event-binding/1"
_PROFILE_EXECUTION_SOURCE_MANIFEST_DOMAIN: Final = "ebm-audit/profile-execution-source-manifest/1"
_PROFILE_EXECUTION_IDENTITY_DOMAIN: Final = "ebm-audit/profile-execution-identity/1"
_BLOCKED_PROFILE_DIAGNOSTIC_DOMAIN: Final = "ebm-audit/blocked-profile-diagnostic/2"
_PRE_CANDIDATE_RECEIPT_DOMAIN: Final = "ebm-audit/pre-candidate-qualification-receipt/2"
_BENCHMARK_FREEZE_RECEIPT_DOMAIN: Final = "ebm-audit/benchmark-freeze-receipt/3"
_FREEZE_PREDICATE_EVIDENCE_OWNER_DOMAIN: Final = "ebm-audit/freeze-predicate-evidence-owner/2"
_CANDIDATE_FREEZE_RECEIPT_DOMAIN: Final = "ebm-audit/candidate-freeze-receipt/3"
_ACCEPTANCE_CANDIDATE_TRANSITION_RECEIPT_DOMAIN: Final = (
    "ebm-audit/acceptance-candidate-transition-receipt/2"
)
_BLOCKED_PRE_ROOT_DIAGNOSTIC_DOMAIN: Final = "ebm-audit/blocked-pre-root-diagnostic/1"
_CANDIDATE_TREE_DOMAIN: Final = "ebm-audit/candidate-tree/1"
_PROFILE_IDS: Final = (
    "characterization_2000",
    "characterization_5000",
    "characterization_10000",
)
_PROFILE_PROVENANCE_SOURCE_ROLES: Final = (
    "generator_sha256",
    "metrics_rules_sha256",
    "report_language_rules_sha256",
    "evaluator_source_sha256",
    "normative_authority_sha256",
)
_PROFILE_FIT_SOURCE_ROLES: Final = (
    "generation",
    "preparation",
    "seed",
    "request-execution",
    "capture",
    "metric-calculation",
)
_PROFILE_PUBLIC_SEED_DERIVATION_ID: Final = (
    "public-sha256-profile-execution-identity-event-binding-chain-u64be/2"
)
_PROFILE_REQUESTED_OUTPUTS: Final = (
    "central_order",
    "order_samples",
    "accepted_transition_diagnostics",
    "position_probabilities",
    "pairwise_precedence",
    "fitted_event_distributions",
    "evaluation_stage_posterior",
    "evaluation_hard_stages",
    "evaluation_expected_stage",
)
_PROFILE_AUTHORITY_SHA256: Final = (
    "6a6f0165f57ab44f88e62e70dfc2284ddcc909d1d1e7f191f741a681b3e0d629"
)
_PROFILE_SOURCE_EVENT_IDS: Final = tuple(f"E{ordinal:02d}" for ordinal in range(1, 10))
_PROFILE_ANALYSIS_EVENT_IDS: Final = tuple(f"e{ordinal:02d}" for ordinal in range(1, 10))
_PROFILE_TRUTH_DIRECTIONS: Final = (
    "higher",
    "lower",
    "higher",
    "lower",
    "higher",
    "lower",
    "higher",
    "lower",
    "higher",
)
_PROFILE_ANALYSIS_DIRECTIONS: Final = (
    "higher",
    "lower",
    "higher",
    "lower",
    "higher",
    "lower",
    "higher",
    "lower",
    "higher",
)
_PROFILE_EVENT_CENTERS: Final = (-2.0, -1.5, -1.0, -0.5, 0.0, 0.5, 1.0, 1.5, 2.0)
_PROFILE_BINDING_OWNER_DIGESTS: Final = (
    (
        "e963c5ee5f8d4e31642f57aa93b8ed08c10492ff76171fb8c98d43781ecc6112",
        "6f7faeb28ae2e971b5c7bdca8ed7cac938e56fbbfdb650769232e4a17b1a4619",
        "469faf80c2fc8d817068f0b6153ae198030c1cda70ae4680da2e0f0ca931cfe2",
    ),
    (
        "e963c5ee5f8d4e31642f57aa93b8ed08c10492ff76171fb8c98d43781ecc6112",
        "91667e956c274d41822f85ed5b9f7fbf5c36f0095d901cbf438822ead2491acb",
        "cf0a65b02fd726514776b5396aa079d6830acedf9118b50a353c14bd9ae99254",
    ),
    (
        "e963c5ee5f8d4e31642f57aa93b8ed08c10492ff76171fb8c98d43781ecc6112",
        "e92ac36506ec11ad4be3951aecf9c2948dceb0f67940128a6c9f71f0c1e24df7",
        "267254f3032de54de4d7dac91d7e1c405408e0054ebaa3aed9e5e92d5acf6d28",
    ),
    (
        "5f4329ea674fd758e249a3462c44493fff792b6336bbfc9d226c4538e4d78aff",
        "bb7e379c79db72b30004d4d8c54814b31d80457e1e63f0a2025c04c8923853d4",
        "e2d4b12cc956e6db6247eb90f7637b6d2918f325271f180bcd687cc70755860d",
    ),
    (
        "5f4329ea674fd758e249a3462c44493fff792b6336bbfc9d226c4538e4d78aff",
        "d8d8bc2e317401c9e91d981597e6a43b2ea34e6f049b5b00f3dae9f564346ab1",
        "e10a5d2c986e61a43b54d7938dd5a95180e9943da315b6380926d71f7fa25d42",
    ),
    (
        "5f4329ea674fd758e249a3462c44493fff792b6336bbfc9d226c4538e4d78aff",
        "d051478a6cbfc5aa566e4f07d02bf9897373ca6cdec8bdd4f27bd29c1245eb42",
        "4954a99bab691ca9e1c343b16109817dbd8fa56562b1c4eae01ab54c0d77c9f5",
    ),
)
_PROFILE_FIXED_SCIENTIFIC_INTENT: Final = {
    "spec_schema_version": "ebm-audit-analysis-spec/3.0",
    "dataset_variant_intent": {
        "source_variant_id": "baseline-input",
        "variant_kind": "baseline-input",
        "source_variant_id_ref": None,
        "method_id": "exact-input-bytes/1",
    },
    "cohort_rule": {
        "group_spec_id": "profile-groups",
        "source_kind": "label-alias",
        "public_field_ids": ["analysis-group"],
        "label_roles": [
            {"public_label_id": "at-risk", "role": "at_risk"},
            {"public_label_id": "reference", "role": "reference"},
        ],
        "role_rules": [],
        "required_roles": ["reference", "at_risk"],
    },
    "event_set": [{"event_id": event_id} for event_id in _PROFILE_ANALYSIS_EVENT_IDS],
    "event_directions": dict(
        zip(
            _PROFILE_ANALYSIS_EVENT_IDS,
            _PROFILE_ANALYSIS_DIRECTIONS,
            strict=True,
        )
    ),
    "preprocessing": [],
    "outlier_policy": {
        "policy_kind": "none",
        "threshold": None,
        "scope": "none",
        "action": "none",
        "reference_population": "none",
        "value_transformation": None,
    },
    "missingness_policy": {
        "policy": "error",
        "event_ids": list(_PROFILE_ANALYSIS_EVENT_IDS),
    },
    "covariate_adjustment": {
        "method": "none",
        "ordered_terms": [],
        "intercept": None,
        "categorical_encoding": "none",
        "minimum_reference_rows": None,
        "require_full_rank": False,
    },
    "backend": {
        "backend_schema_version": "ebm-audit-backend-spec/3.0",
        "adapter_id": "pysaebm-reference-worker",
        "expected_backend_name": "pysaebm",
        "algorithm_id": "conjugate_priors",
        "settings_classification": "public-scientific-settings/1",
        "settings": {
            "n_shuffle": 2,
            "prior_n": 1.0,
            "prior_v": 1.0,
        },
        "requested_outputs": list(_PROFILE_REQUESTED_OUTPUTS),
    },
    "mcmc": {
        "indexing_rule": "returned-post-proposal-row/1",
        "proposal_method_id": "selected-subset-full-derangement-v1",
        "proposal_settings": [{"name": "n_shuffle", "value": 2}],
        "proposal_settings_classification": "public-scientific-settings/1",
        "chain_count": 3,
        "seed_derivation_version": "hmac-sha256-u64be-v2",
        "initialization_rule": "pysaebm-seeded-datafit-order-dirichlet-init-v1",
    },
    "operation_intent": {"kind": "ordinary"},
}


class FreezeSequenceValidationError(ValueError):
    """A privacy-safe, classified freeze-sequencing rejection."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Freeze sequencing validation failed.")


def _reject(code: str) -> Never:
    raise FreezeSequenceValidationError(code)


def _validate(owner: Mapping[str, Any], definition: str, code: str) -> None:
    try:
        validate_instance(dict(owner), _SCHEMA, definition=definition)
    except SchemaValidationError:
        _reject(code)


def _digest_preimage(
    owner: Mapping[str, Any],
    *,
    digest_field: str,
    digest_state_field: str | None = None,
) -> dict[str, Any]:
    preimage = copy.deepcopy(dict(owner))
    preimage[digest_field] = None
    if digest_state_field is not None:
        preimage[digest_state_field] = "DIGEST_PREIMAGE"
    return preimage


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        _reject("FREEZE_SEQUENCE.TIMESTAMP")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _reject("FREEZE_SEQUENCE.TIMESTAMP")


def _subject_digest(subject: Mapping[str, Any]) -> str:
    return structured_sha256(_SUBJECT_DOMAIN, dict(subject))


def _fixed_scientific_intent_projection(
    analysis_spec: Mapping[str, Any],
) -> dict[str, Any]:
    """Project every fixed scientific choice, excluding budgets and worker digests."""

    backend = analysis_spec["backend"]
    backend_settings = backend["settings"]
    mcmc = analysis_spec["mcmc"]
    if not isinstance(backend, Mapping) or not isinstance(backend_settings, Mapping):
        _reject("PROFILE_PLAN.BUDGET_SPEC_BINDING")
    if not isinstance(mcmc, Mapping):
        _reject("PROFILE_PLAN.BUDGET_SPEC_BINDING")
    return {
        "spec_schema_version": analysis_spec["spec_schema_version"],
        "dataset_variant_intent": copy.deepcopy(analysis_spec["dataset_variant_intent"]),
        "cohort_rule": copy.deepcopy(analysis_spec["cohort_rule"]),
        "event_set": copy.deepcopy(analysis_spec["event_set"]),
        "event_directions": copy.deepcopy(analysis_spec["event_directions"]),
        "preprocessing": copy.deepcopy(analysis_spec["preprocessing"]),
        "outlier_policy": copy.deepcopy(analysis_spec["outlier_policy"]),
        "missingness_policy": copy.deepcopy(analysis_spec["missingness_policy"]),
        "covariate_adjustment": copy.deepcopy(analysis_spec["covariate_adjustment"]),
        "backend": {
            "backend_schema_version": backend["backend_schema_version"],
            "adapter_id": backend["adapter_id"],
            "expected_backend_name": backend["expected_backend_name"],
            "algorithm_id": backend["algorithm_id"],
            "settings_classification": backend["settings_classification"],
            "settings": {
                field: backend_settings[field] for field in ("n_shuffle", "prior_n", "prior_v")
            },
            "requested_outputs": copy.deepcopy(backend["requested_outputs"]),
        },
        "mcmc": {
            "indexing_rule": mcmc["indexing_rule"],
            "proposal_method_id": mcmc["proposal_method_id"],
            "proposal_settings": copy.deepcopy(mcmc["proposal_settings"]),
            "proposal_settings_classification": mcmc["proposal_settings_classification"],
            "chain_count": mcmc["chain_count"],
            "seed_derivation_version": mcmc["seed_derivation_version"],
            "initialization_rule": mcmc["initialization_rule"],
        },
        "operation_intent": copy.deepcopy(analysis_spec["operation_intent"]),
    }


type _AuthenticatedWorkerBinding = tuple[str, str, str, str, str, str]


def _authenticated_worker_binding_projection(
    analysis_spec: Mapping[str, Any],
) -> _AuthenticatedWorkerBinding:
    """Project the six fields that must match an authenticated worker owner."""

    backend = analysis_spec["backend"]
    mcmc = analysis_spec["mcmc"]
    if not isinstance(backend, Mapping) or not isinstance(mcmc, Mapping):
        _reject("PROFILE_PLAN.BUDGET_SPEC_BINDING")
    return (
        backend["adapter_semantics_digest"],
        backend["expected_backend_source_digest"],
        backend["capabilities_digest"],
        backend["settings_schema_digest"],
        backend["stage_semantics_digest"],
        mcmc["proposal_settings_schema_digest"],
    )


def audit_benchmark_freeze_evidence(
    receipt: Mapping[str, Any],
) -> None:
    """Audit a blocked benchmark-freeze evidence graph.

    This proves registry cardinality, typed-owner linkage, and self-hash
    consistency only.  It does not issue a benchmark freeze: the production
    evaluator that resolves current bytes, re-executes registered checks, and
    rederives predicate outcomes does not yet exist in this source surface.
    """

    _validate(receipt, "BenchmarkFreezeReceipt", "BENCHMARK_FREEZE.SCHEMA")
    expected_digest = structured_sha256_hex(
        _BENCHMARK_FREEZE_RECEIPT_DOMAIN,
        _digest_preimage(
            receipt,
            digest_field="benchmark_freeze_receipt_sha256",
        ),
    )
    if receipt["benchmark_freeze_receipt_sha256"] != expected_digest:
        _reject("BENCHMARK_FREEZE.RECEIPT_DIGEST")

    registry = load_protocol_registry()["freeze_verifier_registry"]["predicate_verifiers"]
    expected_rows = [(str(row["predicate_id"]), str(row["evidence_type"])) for row in registry]
    evidence_rows = receipt["predicate_evidence"]
    owners = receipt["predicate_evidence_owners"]
    if len(expected_rows) != 28:
        _reject("BENCHMARK_FREEZE.GOVERNING_REGISTRY")
    if [str(row["predicate_id"]) for row in evidence_rows] != [
        predicate_id for predicate_id, _ in expected_rows
    ]:
        _reject("BENCHMARK_FREEZE.PREDICATE_REGISTRY")
    if [
        (str(owner["predicate_id"]), str(owner["evidence_type"])) for owner in owners
    ] != expected_rows:
        _reject("BENCHMARK_FREEZE.OWNER_REGISTRY")

    for evidence, owner in zip(evidence_rows, owners, strict=True):
        owner_digest = structured_sha256_hex(
            _FREEZE_PREDICATE_EVIDENCE_OWNER_DOMAIN,
            _digest_preimage(owner, digest_field="evidence_owner_sha256"),
        )
        if (
            owner["evidence_owner_sha256"] != owner_digest
            or evidence["evidence_owner_sha256"] != owner_digest
            or evidence["predicate_id"] != owner["predicate_id"]
        ):
            _reject("BENCHMARK_FREEZE.OWNER_DIGEST")
        if any(item["item_kind"] != owner["evidence_type"] for item in owner["items"]):
            _reject("BENCHMARK_FREEZE.OWNER_TYPE")

    if (
        receipt["issuance_status"] != "UNAVAILABLE_AUTHORITATIVE_EVIDENCE_RESOLVER_NOT_IMPLEMENTED"
        or receipt["terminal_status"] != "BLOCKED"
        or receipt["frozen"] is not False
        or receipt["contract_status"] != "DRAFT"
    ):
        _reject("BENCHMARK_FREEZE.DECISIVE_ISSUANCE")


def validate_benchmark_freeze_receipt(
    receipt: Mapping[str, Any],
) -> None:
    """Refuse decisive benchmark-freeze issuance until authority exists."""

    audit_benchmark_freeze_evidence(receipt)
    _reject("BENCHMARK_FREEZE.AUTHORITATIVE_EVIDENCE_UNAVAILABLE")


def _audit_profile_characterization_plan_structure(
    *,
    plan_receipt: Mapping[str, Any],
    blocked_diagnostic: Mapping[str, Any],
) -> None:
    """Audit fixed profile intent and its explicit PRE_EXECUTION blocker."""

    _validate(
        plan_receipt,
        "ProfileCharacterizationPlanReceipt",
        "PROFILE_PLAN.SCHEMA",
    )
    _validate(
        blocked_diagnostic,
        "BlockedProfileDiagnostic",
        "PROFILE_PLAN.DIAGNOSTIC_SCHEMA",
    )
    plan_digest = structured_sha256_hex(
        _PROFILE_PLAN_RECEIPT_DOMAIN,
        _digest_preimage(
            plan_receipt,
            digest_field="profile_characterization_plan_receipt_sha256",
        ),
    )
    if plan_receipt["profile_characterization_plan_receipt_sha256"] != plan_digest:
        _reject("PROFILE_PLAN.DIGEST")
    diagnostic_digest = structured_sha256_hex(
        _BLOCKED_PROFILE_DIAGNOSTIC_DOMAIN,
        _digest_preimage(
            blocked_diagnostic,
            digest_field="blocked_profile_diagnostic_sha256",
        ),
    )
    if blocked_diagnostic["blocked_profile_diagnostic_sha256"] != diagnostic_digest:
        _reject("PROFILE_PLAN.DIAGNOSTIC_DIGEST")
    if blocked_diagnostic["profile_characterization_plan_receipt_sha256"] != plan_digest:
        _reject("PROFILE_PLAN.DIAGNOSTIC_BINDING")
    if _timestamp(plan_receipt["completed_at_utc"]) > _timestamp(
        blocked_diagnostic["completed_at_utc"]
    ):
        _reject("PROFILE_PLAN.TIME_ORDER")

    provenance = plan_receipt["source_provenance"]
    if [row["source_role"] for row in provenance["ordered_source_set_identities"]] != list(
        _PROFILE_PROVENANCE_SOURCE_ROLES
    ):
        _reject("PROFILE_PLAN.SOURCE_PROVENANCE")
    execution_source_manifest = plan_receipt["execution_source_manifest"]
    execution_source_preimage = _digest_preimage(
        execution_source_manifest,
        digest_field="profile_execution_source_manifest_sha256",
    )
    if (
        execution_source_manifest["profile_execution_source_manifest_sha256"]
        != structured_sha256_hex(
            _PROFILE_EXECUTION_SOURCE_MANIFEST_DOMAIN,
            execution_source_preimage,
        )
        or [row["fit_role"] for row in execution_source_manifest["ordered_entries"]]
        != list(_PROFILE_FIT_SOURCE_ROLES)
        or any(
            (paths := [entry["path"] for entry in row["ordered_files"]]) != sorted(set(paths))
            for row in execution_source_manifest["ordered_entries"]
        )
    ):
        _reject("PROFILE_PLAN.EXECUTION_SOURCE_MANIFEST")

    expected_coordinates = [
        {
            "family_id": family_id,
            "scenario_id": scenario_id,
            "replicate_index": replicate_index,
        }
        for family_id, scenario_id in (
            ("easy_known_truth", "profile-pilot"),
            ("moderate_mina_shape", "profile-pilot-57x9"),
        )
        for replicate_index in range(3)
    ]
    if plan_receipt["ordered_coordinates"] != expected_coordinates:
        _reject("PROFILE_PLAN.COORDINATE_ORDER")

    expected_mappings = [
        {
            "event_ordinal": ordinal,
            "synthetic_event_id": source_id,
            "analysis_event_id": analysis_id,
        }
        for ordinal, (source_id, analysis_id) in enumerate(
            zip(
                _PROFILE_SOURCE_EVENT_IDS,
                _PROFILE_ANALYSIS_EVENT_IDS,
                strict=True,
            )
        )
    ]
    expected_resolver_methods = {
        "event_ids": "event-ids-from-count/1",
        "event_directions": "alternating-event-directions/1",
        "event_centers": "even-event-centers/1",
    }
    binding_digests: set[str] = set()
    for binding, coordinate, owner_digests in zip(
        plan_receipt["ordered_synthetic_event_bindings"],
        expected_coordinates,
        _PROFILE_BINDING_OWNER_DIGESTS,
        strict=True,
    ):
        source_contract, parameter_manifest, generator_configuration = owner_digests
        binding_digest = structured_sha256_hex(
            _PROFILE_SYNTHETIC_EVENT_BINDING_DOMAIN,
            _digest_preimage(
                binding,
                digest_field="profile_synthetic_event_binding_sha256",
            ),
        )
        binding_digests.add(binding_digest)
        if (
            binding["profile_synthetic_event_binding_sha256"] != binding_digest
            or binding["coordinate"] != coordinate
            or binding["scenario_definitions_sha256"] != _PROFILE_AUTHORITY_SHA256
            or binding["source_contract_sha256"] != source_contract
            or binding["resolved_parameter_manifest_sha256"] != parameter_manifest
            or binding["resolved_generator_configuration_sha256"] != generator_configuration
            or binding["mapping_method_id"] != "synthetic-e-id-lowercase-machine-id/1"
            or binding["resolver_method_ids"] != expected_resolver_methods
            or binding["ordered_event_mappings"] != expected_mappings
            or binding["ordered_truth_directions"] != list(_PROFILE_TRUTH_DIRECTIONS)
            or binding["ordered_analysis_directions"] != list(_PROFILE_ANALYSIS_DIRECTIONS)
            or binding["ordered_event_centers"]
            != [{"type": "float64", "value": center} for center in _PROFILE_EVENT_CENTERS]
        ):
            _reject("PROFILE_PLAN.SYNTHETIC_EVENT_BINDING")
    if len(binding_digests) != 6:
        _reject("PROFILE_PLAN.SYNTHETIC_EVENT_BINDING")

    expected_budgets = {
        "characterization_2000": (2000, 400),
        "characterization_5000": (5000, 1000),
        "characterization_10000": (10000, 2000),
    }
    budget_rows = plan_receipt["ordered_budgets"]
    if [row["profile_id"] for row in budget_rows] != list(expected_budgets):
        _reject("PROFILE_PLAN.BUDGET_ORDER")
    subject_digests: set[str] = set()
    common_subject: dict[str, Any] | None = None
    candidate = plan_receipt["candidate"]
    backend_identity = plan_receipt["backend_identity"]
    if (
        plan_receipt["backend_identity_digest"] != backend_identity_digest(backend_identity)
        or backend_identity["environment_digest"] != plan_receipt["environment_digest"]
    ):
        _reject("PROFILE_PLAN.BACKEND_IDENTITY")
    for row in budget_rows:
        profile_id = row["profile_id"]
        raw_iterations, burn_in = expected_budgets[profile_id]
        analysis_spec = row["analysis_spec"]
        mcmc = analysis_spec["mcmc"]
        backend = analysis_spec["backend"]
        backend_settings = backend["settings"]
        if (
            row["raw_iteration_count"] != raw_iterations
            or row["burn_in_count"] != burn_in
            or row["thinning_interval"] != 10
            or row["chain_count"] != 3
            or row["analysis_spec_id"] != analysis_spec_content_id(analysis_spec)
            or mcmc is None
            or mcmc["raw_iteration_count"] != raw_iterations
            or mcmc["burn_in_count"] != burn_in
            or mcmc["thinning_interval"] != 10
            or mcmc["chain_count"] != 3
            or backend_settings["raw_iterations"] != raw_iterations
            or backend_settings["burn_in"] != burn_in
            or backend_settings["thinning"] != 10
            or backend["settings_digest"] != settings_digest(backend_settings)
            or backend["requested_outputs_digest"]
            != requested_outputs_digest("fit", backend["requested_outputs"])
        ):
            _reject("PROFILE_PLAN.BUDGET_SPEC_BINDING")
        if _fixed_scientific_intent_projection(analysis_spec) != _PROFILE_FIXED_SCIENTIFIC_INTENT:
            _reject("PROFILE_PLAN.NON_BUDGET_SPEC_DRIFT")

        subject = row["experimental_subject"]
        subject_digest = _subject_digest(subject)
        subject_digests.add(subject_digest)
        if (
            subject["backend_identity_digest"] != plan_receipt["backend_identity_digest"]
            or any(
                subject[field] != backend_identity[field]
                for field in (
                    "adapter_id",
                    "adapter_version",
                    "worker_executable_digest",
                    "worker_code_digest",
                    "backend_name",
                    "backend_version",
                    "backend_source_commit",
                    "backend_source_digest",
                    "environment_digest",
                    "algorithm_id",
                )
            )
            or subject["adapter_id"] != backend["adapter_id"]
            or subject["backend_name"] != backend["expected_backend_name"]
            or subject["backend_source_digest"] != backend["expected_backend_source_digest"]
            or subject["algorithm_id"] != backend["algorithm_id"]
            or subject["capabilities_digest"] != backend["capabilities_digest"]
            or subject["requested_outputs_digest"] != backend["requested_outputs_digest"]
            or subject["candidate_git_object_format"] != candidate["git_object_format"]
            or subject["candidate_git_commit"] != candidate["git_commit"]
            or subject["candidate_sha256"] != candidate["candidate_sha256"]
            or subject["contract_sha256"] != plan_receipt["contract_sha256"]
            or subject["environment_digest"] != plan_receipt["environment_digest"]
            or subject["settings_digest"] != backend["settings_digest"]
            or subject["benchmark_profile_id"] != profile_id
            or row["subject_acceptance_state"] != "EXPERIMENTAL"
        ):
            _reject("PROFILE_PLAN.SUBJECT_BINDING")
        subject_projection = copy.deepcopy(dict(subject))
        subject_projection.pop("settings_digest")
        subject_projection.pop("benchmark_profile_id")
        if common_subject is None:
            common_subject = subject_projection
        elif subject_projection != common_subject:
            _reject("PROFILE_PLAN.SUBJECT_DRIFT")
    if len(subject_digests) != 3:
        _reject("PROFILE_PLAN.SUBJECT_REUSE")

    expected_rotations = [
        {
            "family_id": family_id,
            "scenario_id": scenario_id,
            "replicate_index": replicate_index,
            "ordered_profile_ids": [
                _PROFILE_IDS[(replicate_index + offset) % len(_PROFILE_IDS)]
                for offset in range(len(_PROFILE_IDS))
            ],
        }
        for family_id, scenario_id in (
            ("easy_known_truth", "profile-pilot"),
            ("moderate_mina_shape", "profile-pilot-57x9"),
        )
        for replicate_index in range(3)
    ]
    execution_policy = plan_receipt["execution_policy"]
    if (
        execution_policy["fit_execution_mode"] != "FRESH_INDEPENDENT_SERIAL_PROCESSES"
        or execution_policy["cache_policy"] != "NO_READ_NO_WRITE"
        or execution_policy["checkpoint_policy"] != "NO_READ_NO_WRITE"
        or execution_policy["retry_policy"] != "DISALLOWED"
        or execution_policy["caller_supplied_seeds_allowed"] is not False
    ):
        _reject("PROFILE_PLAN.EXECUTION_POLICY")
    if execution_policy["ordered_budget_rotations"] != expected_rotations:
        _reject("PROFILE_PLAN.ROTATION_ORDER")
    expected_slots = [
        {
            **coordinate,
            "chain_ordinal": chain_ordinal,
            "chain_id": f"chain-{chain_ordinal:04d}",
        }
        for coordinate in expected_coordinates
        for chain_ordinal in range(3)
    ]
    if plan_receipt["ordered_logical_case_chain_slots"] != expected_slots:
        _reject("PROFILE_PLAN.SEED_SLOT_ORDER")

    expected_budget_relations = [
        {
            "relation_id": "characterization-5000-to-10000/1",
            "candidate_profile_id": "characterization_5000",
            "reference_profile_id": "characterization_10000",
            "comparison_direction": "CANDIDATE_TO_REFERENCE",
            "expected_same_chain_comparison_count": 18,
        },
        {
            "relation_id": "characterization-2000-to-10000/1",
            "candidate_profile_id": "characterization_2000",
            "reference_profile_id": "characterization_10000",
            "comparison_direction": "CANDIDATE_TO_REFERENCE",
            "expected_same_chain_comparison_count": 18,
        },
        {
            "relation_id": "characterization-2000-to-5000/1",
            "candidate_profile_id": "characterization_2000",
            "reference_profile_id": "characterization_5000",
            "comparison_direction": "CANDIDATE_TO_REFERENCE",
            "expected_same_chain_comparison_count": 18,
        },
    ]
    if plan_receipt["ordered_budget_relations"] != expected_budget_relations:
        _reject("PROFILE_PLAN.BUDGET_RELATIONS")

    expected_evidence_registry = {
        "registry_schema_version": "ebm-audit-profile-evidence-metric-registry/1.0",
        "ordered_evidence_category_ids": [
            "profile-terminal-core-observed-runtime-row/1",
            "profile-chain-transition-diagnostics-row/1",
            "profile-universe-convergence-classification/1",
            "profile-within-budget-cross-chain-distance-observation/1",
            "profile-same-chain-cross-budget-distance-observation/1",
            "profile-paired-runtime-ratio/1",
        ],
        "ordered_transition_observation_ids": [
            "unthinned-transition-rate/1",
            "unique-state-fraction/1",
            "maximum-repeated-state-fraction/1",
            "endpoint-zero-transition-evidence/1",
        ],
        "ordered_distance_family_ids": [
            "central-order-kendall/1",
            "position-matrix/1",
            "pairwise-precedence-matrix/1",
        ],
        "ordered_easy_metric_ids": [
            "easy-central-order-kendall-agreement/1",
            "easy-normalized-stage-mae/1",
        ],
        "ordered_moderate_descriptive_metric_ids": [
            "moderate-fixed-reference-alignment-descriptive/1",
            "moderate-normalized-stage-mae/1",
        ],
    }
    if plan_receipt["evidence_metric_registry"] != expected_evidence_registry:
        _reject("PROFILE_PLAN.EVIDENCE_REGISTRY")

    expected_cardinalities = {
        "signal_dataset_count": 6,
        "easy_signal_dataset_count": 3,
        "moderate_signal_dataset_count": 3,
        "logical_coordinate_count": 6,
        "budget_profile_count": 3,
        "profile_universe_count": 18,
        "chain_count_per_universe": 3,
        "chain_execution_count": 54,
        "budget_relation_count": 3,
        "same_chain_comparison_count_per_relation": 18,
        "paired_chain_comparison_count": 54,
        "logical_case_chain_slot_count": 18,
        "terminal_core_runtime_row_count": 54,
        "chain_transition_row_count": 54,
        "universe_convergence_classification_count": 18,
        "within_budget_cross_chain_observation_count_per_distance_family": 54,
        "within_budget_cross_chain_observation_count_all_distance_families": 162,
        "same_chain_cross_budget_observation_count_per_distance_family": 54,
        "same_chain_cross_budget_observation_count_all_distance_families": 162,
        "paired_runtime_ratio_count": 54,
        "easy_observation_count_per_metric": 9,
        "moderate_descriptive_observation_count_per_metric": 9,
    }
    if plan_receipt["expected_cardinalities"] != expected_cardinalities:
        _reject("PROFILE_PLAN.CARDINALITIES")

    execution_identity = plan_receipt["profile_execution_identity"]
    execution_identity_preimage = _digest_preimage(
        execution_identity,
        digest_field="profile_execution_identity_sha256",
    )
    expected_execution_identity_preimage = {
        "identity_schema_version": "ebm-audit-profile-execution-identity/1.0",
        "scenario_definitions_sha256": _PROFILE_AUTHORITY_SHA256,
        "profile_execution_source_manifest_sha256": execution_source_manifest[
            "profile_execution_source_manifest_sha256"
        ],
        "worker_invocation_semantics_sha256": execution_identity[
            "worker_invocation_semantics_sha256"
        ],
        "ordered_coordinates": expected_coordinates,
        "ordered_synthetic_event_binding_sha256s": [
            binding["profile_synthetic_event_binding_sha256"]
            for binding in plan_receipt["ordered_synthetic_event_bindings"]
        ],
        "ordered_analysis_spec_identities": [
            {
                "profile_id": row["profile_id"],
                "analysis_spec_id": row["analysis_spec_id"],
            }
            for row in budget_rows
        ],
        "backend_identity_digest": plan_receipt["backend_identity_digest"],
        "environment_digest": plan_receipt["environment_digest"],
        "requested_outputs_digest": budget_rows[0]["analysis_spec"]["backend"][
            "requested_outputs_digest"
        ],
        "canonicalization": plan_receipt["canonicalization"],
        "chain_count": 3,
        "public_seed_derivation_id": _PROFILE_PUBLIC_SEED_DERIVATION_ID,
        "execution_policy": plan_receipt["execution_policy"],
        "ordered_logical_case_chain_slots": expected_slots,
        "ordered_budget_relations": expected_budget_relations,
        "evidence_metric_registry": expected_evidence_registry,
        "expected_cardinalities": expected_cardinalities,
        "profile_execution_identity_sha256": None,
    }
    expected_execution_identity_sha256 = structured_sha256_hex(
        _PROFILE_EXECUTION_IDENTITY_DOMAIN,
        expected_execution_identity_preimage,
    )
    if (
        execution_identity_preimage != expected_execution_identity_preimage
        or execution_identity["profile_execution_identity_sha256"]
        != expected_execution_identity_sha256
        or plan_receipt["public_seed_policy"]["profile_execution_identity_sha256"]
        != expected_execution_identity_sha256
    ):
        _reject("PROFILE_PLAN.EXECUTION_IDENTITY")

    expected_selection_policy = {
        "policy_schema_version": "ebm-audit-profile-budget-selection-policy/2.0",
        "selection_rule_id": "quick-full-release-budget-selection/3",
        "resolver_authority": "FUTURE_PRODUCT_OWNED_PROFILE_EVIDENCE_RESOLVER",
        "release_target_profile_id": "characterization_10000",
        "release_required_components": [
            "COMPLETE_REQUIRED_CONVERGENCE_PASS_EVIDENCE",
            "REVIEWED_TRANSITION_QUALITY_PASS",
        ],
        "release_failure_outcome": "NO_SELECTION",
        "full_candidate_profile_id": "characterization_5000",
        "full_required_relation_id": "characterization-5000-to-10000/1",
        "quick_candidate_profile_id": "characterization_2000",
        "quick_prerequisite": "FULL_5000_QUALIFIED",
        "quick_required_relation_ids": [
            "characterization-2000-to-10000/1",
            "characterization-2000-to-5000/1",
        ],
        "transitive_inference_allowed": False,
        "relation_pass_required_components": [
            "COMPLETE_CANDIDATE_AND_REFERENCE_CONVERGENCE_PASS",
            "REVIEWED_TRANSITION_QUALITY_PASS",
            "ALL_DISTANCE_FAMILY_THRESHOLDS_PASS",
            "MEDIAN_OF_18_PAIRED_CANDIDATE_OVER_REFERENCE_RUNTIME_RATIOS_LT_ONE",
            "NONINFERENTIAL_PAIRED_DEVELOPMENT_SAFEGUARDS_PASS",
        ],
        "distance_aggregation_rule": ("EACH_DISTANCE_FAMILY_SEPARATELY_PER_RELATION_NEVER_POOLED"),
        "relation_distance_pass_rule": (
            "ALL_THREE_FAMILIES_EACH_REQUIRE_MEDIAN_LTE_0_10_AND_MAX_LTE_0_20"
        ),
        "median_distance_maximum": 0.1,
        "maximum_distance_maximum": 0.2,
        "transition_quality_policy": {
            "policy_schema_version": "ebm-audit-profile-transition-quality-policy/1.0",
            "review_state": "PENDING_INDEPENDENT_TRANSITION_RULE_REVIEW",
            "pre_review_selection_outcome": "NO_SELECTION",
            "future_decision_owner_type": (
                "VERSIONED_MACHINE_EXECUTABLE_INDEPENDENT_TRANSITION_QUALITY_DECISION_OWNER"
            ),
            "ordered_transition_observation_ids": [
                "unthinned-transition-rate/1",
                "unique-state-fraction/1",
                "maximum-repeated-state-fraction/1",
                "endpoint-zero-transition-evidence/1",
            ],
            "ordered_required_decision_content_ids": [
                "transition-metric-directions/1",
                "transition-per-metric-aggregation/1",
                "transition-per-metric-tolerances/1",
                "transition-endpoint-zero-rule/1",
                "transition-complete-denominators/1",
                "transition-plan-evidence-subject-binding/1",
                "transition-no-preferred-central-order-targeting/1",
            ],
            "preferred_central_order_targeting_allowed": False,
        },
        "runtime_comparison_policy": {
            "policy_schema_version": "ebm-audit-profile-runtime-comparison-policy/1.0",
            "ordered_pairing_key_fields": [
                "family_id",
                "scenario_id",
                "replicate_index",
                "chain_id",
            ],
            "expected_ratio_count_per_relation": 18,
            "ratio_numerator": "CANDIDATE_TERMINAL_CORE_OBSERVED_RUNTIME",
            "ratio_denominator": "REFERENCE_TERMINAL_CORE_OBSERVED_RUNTIME",
            "observation_validity_rule": (
                "COMPLETE_FINITE_TERMINAL_CORE_OBSERVED_NUMERATOR_AND_COMPLETE_"
                "FINITE_STRICTLY_POSITIVE_TERMINAL_CORE_OBSERVED_DENOMINATOR"
            ),
            "quantile_rule_id": "inverse-empirical-cdf/1",
            "quantile_probability": 0.5,
            "one_based_ordered_value_ordinal": 9,
            "interpolation_allowed": False,
            "pass_rule_id": ("MEDIAN_OF_18_PAIRED_CANDIDATE_OVER_REFERENCE_RUNTIME_RATIOS_LT_ONE"),
            "comparison_operator": "LT",
            "comparison_threshold": 1.0,
            "comparison_tolerance": 0.0,
            "invalid_or_equal_outcome": "RELATION_FAIL_AND_DEFAULT_UPWARD",
        },
        "easy_truth_kendall_safeguard": ("MEDIAN_PAIRED_CANDIDATE_MINUS_REFERENCE_GTE_ZERO"),
        "easy_stage_mae_safeguard": ("MEDIAN_PAIRED_CANDIDATE_MINUS_REFERENCE_LTE_ZERO"),
        "moderate_stage_mae_safeguard": ("MEDIAN_PAIRED_CANDIDATE_MINUS_REFERENCE_LTE_ZERO"),
        "moderate_alignment_use": "DESCRIPTIVE_ONLY_NOT_A_SELECTION_GATE",
        "stage_mae_population": "EXACT_GENERATED_FIXED_EVALUATION_COHORT_ROWS",
        "stage_truth_binding": "THRESHOLD_STAGE",
        "stage_axis_incompatibility_outcome": "NOT_ASSESSABLE_AND_NO_SELECTION",
        "p_values_allowed": False,
        "adaptive_extra_replicates_allowed": False,
        "ineligible_or_incomplete_behavior": (
            "MISSING_PENDING_WARN_FAIL_NOT_ASSESSABLE_BORDERLINE_INCOMPLETE_OR_"
            "UNREVIEWED_DEFAULTS_UPWARD_EXCEPT_FAILED_OR_UNREVIEWED_10000_NO_SELECTION"
        ),
    }
    if plan_receipt["selection_policy"] != expected_selection_policy:
        _reject("PROFILE_PLAN.SELECTION_POLICY")


def _audit_profile_characterization_plan_authority_bound(
    *,
    plan_receipt: Mapping[str, Any],
    blocked_diagnostic: Mapping[str, Any],
    authenticated_worker_binding: _AuthenticatedWorkerBinding,
) -> None:
    """Audit plan structure and bind every budget to one authenticated worker owner."""

    _audit_profile_characterization_plan_structure(
        plan_receipt=plan_receipt,
        blocked_diagnostic=blocked_diagnostic,
    )
    if any(
        _authenticated_worker_binding_projection(row["analysis_spec"])
        != authenticated_worker_binding
        for row in plan_receipt["ordered_budgets"]
    ):
        _reject("PROFILE_PLAN.AUTHENTICATED_WORKER_BINDING")


def _audit_blocked_qualification_diagnostic(
    qualification_receipt: Mapping[str, Any],
) -> None:
    """Check only the explicitly blocked qualification record."""

    _validate(
        qualification_receipt,
        "PreCandidateQualificationReceipt",
        "PRE_CANDIDATE.QUALIFICATION_SCHEMA",
    )
    qualification_preimage = _digest_preimage(
        qualification_receipt,
        digest_field="pre_candidate_qualification_receipt_sha256",
    )
    if (
        structured_sha256_hex(_PRE_CANDIDATE_RECEIPT_DOMAIN, qualification_preimage)
        != qualification_receipt["pre_candidate_qualification_receipt_sha256"]
    ):
        _reject("PRE_CANDIDATE.QUALIFICATION_DIGEST")
    candidate = qualification_receipt["candidate"]
    subject = qualification_receipt["benchmark_subject"]
    subject_digest = _subject_digest(subject)
    if (
        candidate["candidate_sha256"] != subject["candidate_sha256"]
        or qualification_receipt["benchmark_subject_digest"] != subject_digest
        or qualification_receipt["contract_sha256"] != subject["contract_sha256"]
    ):
        _reject("PRE_CANDIDATE.OWNER_BINDING")
    if any(
        row["development_scenario_evaluation_receipt_sha256"]
        != qualification_receipt["development_scenario_evaluation_receipt_sha256"]
        for row in qualification_receipt["predicate_evidence"]
    ):
        _reject("PRE_CANDIDATE.PREDICATE_BINDING")
    if (
        qualification_receipt["candidate_freeze_eligible"] is not False
        or qualification_receipt["qualification_resolution_status"]
        != "UNAVAILABLE_AUTHORITATIVE_FAMILY_EVIDENCE_NOT_RESOLVED"
        or qualification_receipt["terminal_status"] != "BLOCKED"
    ):
        _reject("PRE_CANDIDATE.DECISIVE_ISSUANCE")


def validate_pre_candidate_qualification(
    *,
    qualification_receipt: Mapping[str, Any],
) -> None:
    """Refuse final-candidate qualification until family evidence is resolved."""

    _audit_blocked_qualification_diagnostic(qualification_receipt)
    _reject("PRE_CANDIDATE.AUTHORITATIVE_DEVELOPMENT_EVIDENCE_UNAVAILABLE")


def audit_blocked_pre_root_diagnostic(
    *,
    benchmark_freeze_receipt: Mapping[str, Any],
    pre_candidate_qualification_receipt: Mapping[str, Any],
    candidate_freeze_receipt: Mapping[str, Any],
    acceptance_candidate_transition_receipt: Mapping[str, Any],
    final_subject: Mapping[str, Any],
    blocked_pre_root_diagnostic: Mapping[str, Any],
) -> None:
    """Audit a ROOT_NOT_DRAWN diagnostic without constructing success artifacts."""

    for owner, definition, code in (
        (
            benchmark_freeze_receipt,
            "BenchmarkFreezeReceipt",
            "PRE_ROOT.BENCHMARK_FREEZE_SCHEMA",
        ),
        (
            pre_candidate_qualification_receipt,
            "PreCandidateQualificationReceipt",
            "PRE_ROOT.QUALIFICATION_SCHEMA",
        ),
        (
            candidate_freeze_receipt,
            "CandidateFreezeReceipt",
            "PRE_ROOT.CANDIDATE_FREEZE_SCHEMA",
        ),
        (
            acceptance_candidate_transition_receipt,
            "AcceptanceCandidateTransitionReceipt",
            "PRE_ROOT.ACCEPTANCE_TRANSITION_SCHEMA",
        ),
        (final_subject, "BenchmarkSubjectIdentity", "PRE_ROOT.SUBJECT_SCHEMA"),
        (
            blocked_pre_root_diagnostic,
            "BlockedPreRootDiagnostic",
            "PRE_ROOT.DIAGNOSTIC_SCHEMA",
        ),
    ):
        _validate(owner, definition, code)

    audit_benchmark_freeze_evidence(benchmark_freeze_receipt)
    _audit_blocked_qualification_diagnostic(pre_candidate_qualification_receipt)

    benchmark_freeze_digest = structured_sha256_hex(
        _BENCHMARK_FREEZE_RECEIPT_DOMAIN,
        _digest_preimage(
            benchmark_freeze_receipt,
            digest_field="benchmark_freeze_receipt_sha256",
        ),
    )
    if benchmark_freeze_receipt["benchmark_freeze_receipt_sha256"] != benchmark_freeze_digest:
        _reject("PRE_ROOT.BENCHMARK_FREEZE_DIGEST")
    qualification_digest = structured_sha256_hex(
        _PRE_CANDIDATE_RECEIPT_DOMAIN,
        _digest_preimage(
            pre_candidate_qualification_receipt,
            digest_field="pre_candidate_qualification_receipt_sha256",
        ),
    )
    if (
        pre_candidate_qualification_receipt["pre_candidate_qualification_receipt_sha256"]
        != qualification_digest
    ):
        _reject("PRE_ROOT.QUALIFICATION_DIGEST")
    candidate_freeze_digest = structured_sha256_hex(
        _CANDIDATE_FREEZE_RECEIPT_DOMAIN,
        _digest_preimage(
            candidate_freeze_receipt,
            digest_field="candidate_freeze_receipt_sha256",
        ),
    )
    if candidate_freeze_receipt["candidate_freeze_receipt_sha256"] != candidate_freeze_digest:
        _reject("PRE_ROOT.CANDIDATE_FREEZE_DIGEST")
    transition_digest = structured_sha256_hex(
        _ACCEPTANCE_CANDIDATE_TRANSITION_RECEIPT_DOMAIN,
        _digest_preimage(
            acceptance_candidate_transition_receipt,
            digest_field="acceptance_candidate_transition_receipt_sha256",
        ),
    )
    if (
        acceptance_candidate_transition_receipt["acceptance_candidate_transition_receipt_sha256"]
        != transition_digest
    ):
        _reject("PRE_ROOT.ACCEPTANCE_TRANSITION_DIGEST")

    candidate = candidate_freeze_receipt["candidate"]
    candidate_manifest = candidate_freeze_receipt["candidate_manifest"]
    if (
        candidate["git_object_format"] != candidate_manifest["git_object_format"]
        or candidate["git_commit"] != candidate_manifest["git_commit"]
        or candidate["candidate_sha256"]
        != structured_sha256_hex(_CANDIDATE_TREE_DOMAIN, candidate_manifest)
    ):
        _reject("PRE_ROOT.CANDIDATE_MANIFEST_BINDING")
    frozen_subject = candidate_freeze_receipt["benchmark_subject"]
    subject_digest = _subject_digest(frozen_subject)
    if (
        frozen_subject != final_subject
        or candidate_freeze_receipt["benchmark_subject_digest"] != subject_digest
        or candidate_freeze_receipt["pre_candidate_qualification_receipt_sha256"]
        != qualification_digest
        or candidate_freeze_receipt["development_scenario_evaluation_receipt_sha256"]
        != pre_candidate_qualification_receipt["development_scenario_evaluation_receipt_sha256"]
        or candidate_freeze_receipt["candidate"] != pre_candidate_qualification_receipt["candidate"]
        or candidate_freeze_receipt["benchmark_subject"]
        != pre_candidate_qualification_receipt["benchmark_subject"]
        or candidate_freeze_receipt["benchmark_subject_digest"]
        != pre_candidate_qualification_receipt["benchmark_subject_digest"]
        or candidate_freeze_receipt["contract_sha256"]
        != pre_candidate_qualification_receipt["contract_sha256"]
        or final_subject["candidate_git_object_format"] != candidate["git_object_format"]
        or final_subject["candidate_git_commit"] != candidate["git_commit"]
        or final_subject["candidate_sha256"] != candidate["candidate_sha256"]
        or final_subject["contract_sha256"] != benchmark_freeze_receipt["contract_sha256"]
        or candidate_freeze_receipt["issuance_status"]
        != "UNAVAILABLE_PRE_CANDIDATE_QUALIFICATION_NOT_ISSUED"
        or candidate_freeze_receipt["candidate_frozen"] is not False
        or candidate_freeze_receipt["terminal_status"] != "BLOCKED"
    ):
        _reject("PRE_ROOT.CANDIDATE_FREEZE_QUALIFICATION_BINDING")
    if (
        acceptance_candidate_transition_receipt["pre_candidate_qualification_receipt_sha256"]
        != qualification_digest
        or acceptance_candidate_transition_receipt["candidate_freeze_receipt_sha256"]
        != candidate_freeze_digest
        or acceptance_candidate_transition_receipt["candidate"] != candidate
        or acceptance_candidate_transition_receipt["benchmark_subject_digest"] != subject_digest
        or acceptance_candidate_transition_receipt["contract_sha256"]
        != candidate_freeze_receipt["contract_sha256"]
        or acceptance_candidate_transition_receipt["transition_applied"] is not False
        or acceptance_candidate_transition_receipt["terminal_subject_acceptance_state"]
        != "EXPERIMENTAL"
        or acceptance_candidate_transition_receipt["state_operation_status"]
        != "UNAVAILABLE_AUTHORITATIVE_CAS_NOT_IMPLEMENTED"
        or acceptance_candidate_transition_receipt["terminal_status"] != "BLOCKED"
    ):
        _reject("PRE_ROOT.ACCEPTANCE_TRANSITION_BINDING")
    diagnostic_preimage = _digest_preimage(
        blocked_pre_root_diagnostic,
        digest_field="blocked_pre_root_diagnostic_sha256",
    )
    if (
        structured_sha256_hex(
            _BLOCKED_PRE_ROOT_DIAGNOSTIC_DOMAIN,
            diagnostic_preimage,
        )
        != blocked_pre_root_diagnostic["blocked_pre_root_diagnostic_sha256"]
    ):
        _reject("PRE_ROOT.DIAGNOSTIC_DIGEST")
    if (
        blocked_pre_root_diagnostic["benchmark_freeze_receipt_sha256"] != benchmark_freeze_digest
        or blocked_pre_root_diagnostic["development_scenario_evaluation_receipt_sha256"]
        != pre_candidate_qualification_receipt["development_scenario_evaluation_receipt_sha256"]
        or blocked_pre_root_diagnostic["pre_candidate_qualification_receipt_sha256"]
        != qualification_digest
        or blocked_pre_root_diagnostic["candidate_freeze_receipt_sha256"] != candidate_freeze_digest
        or blocked_pre_root_diagnostic["acceptance_candidate_transition_receipt_sha256"]
        != transition_digest
        or blocked_pre_root_diagnostic["candidate"] != candidate
        or blocked_pre_root_diagnostic["benchmark_subject_digest"] != subject_digest
        or blocked_pre_root_diagnostic["contract_sha256"]
        != benchmark_freeze_receipt["contract_sha256"]
    ):
        _reject("PRE_ROOT.DIAGNOSTIC_BINDING")
    source_fields = (
        "heldout_manifest_template_sha256",
        "generator_sha256",
        "scenario_definitions_sha256",
        "metrics_rules_sha256",
        "report_language_rules_sha256",
    )
    if any(
        blocked_pre_root_diagnostic[field] != benchmark_freeze_receipt[field]
        for field in source_fields
    ):
        _reject("PRE_ROOT.SCIENTIFIC_FREEZE_VECTOR")

    benchmark_completed = _timestamp(benchmark_freeze_receipt["completed_at_utc"])
    qualification_completed = _timestamp(pre_candidate_qualification_receipt["completed_at_utc"])
    candidate_completed = _timestamp(candidate_freeze_receipt["completed_at_utc"])
    transition_completed = _timestamp(acceptance_candidate_transition_receipt["completed_at_utc"])
    diagnostic_completed = _timestamp(blocked_pre_root_diagnostic["completed_at_utc"])
    if not (
        benchmark_completed
        <= qualification_completed
        <= candidate_completed
        < transition_completed
        <= diagnostic_completed
    ):
        _reject("PRE_ROOT.TIME_ORDER")
