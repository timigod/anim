"""Authenticated canonical source-owner manifests for scenario evidence."""

from __future__ import annotations

import copy
import hashlib
import hmac
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal, Never, SupportsIndex, cast, final
from weakref import WeakSet

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.adapters.invocation import _readback_authenticated_execution
from ebm_audit.errors import InvalidInputError, UnexpectedCoreError
from ebm_audit.evaluator.heldout_score import (
    DirectOperationPlanEntry,
    _direct_operation_plan_digest,
)
from ebm_audit.protocol import CanonicalizationError, strict_json_loads
from ebm_audit.protocol.canonical import canonical_json_bytes, structured_sha256_hex
from ebm_audit.protocol.errors import PathBoundaryError
from ebm_audit.protocol.paths import validate_relative_posix_path
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.science.capture import (
    CapturedScientificRun,
    PreparationAuditEvidence,
    PreparationRowInstanceManifests,
    ScientificEvidenceError,
    SealedScientificEvidence,
    _issue_preparation_row_instance_manifests,
    _read_captured_scientific_run,
    _read_preparation_audit_evidence,
    _read_preparation_audit_evidence_bundle,
    _read_preparation_row_instance_manifests,
    _read_sealed_scientific_evidence,
)
from ebm_audit.synthetic.audit_input import (
    SyntheticScientificDataEvidence,
    SyntheticTruthScoringEvidence,
    _bind_synthetic_scientific_data_evidence,
    _bind_synthetic_truth_scoring_evidence,
    _read_synthetic_scientific_data_evidence,
    _read_synthetic_truth_scoring_evidence,
    _read_synthetic_truth_scoring_record_bytes,
    _SyntheticMissingnessProjection,
)

if TYPE_CHECKING:
    from ebm_audit.evaluator.scenario_case_batch import AuthenticatedScenarioCaseBatch

_MANIFEST_DOMAIN: Final = "ebm-audit/scenario-source-owner-manifest/1"
_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_AUTHENTICATION_DOMAIN: Final = "ebm-audit/scenario-source-owner-authentication/1"
_PROJECTION_AUTHENTICATION_DOMAIN: Final = (
    "ebm-audit/scenario-source-owner-projection-authentication/1"
)

_PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS: Final = "PREPARATION_AUDIT_EVIDENCE"
_PREPARATION_AUDIT_EVIDENCE_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/PreparationAuditEvidence"
)
_PREPARATION_AUDIT_EVIDENCE_READER: Final = _read_preparation_audit_evidence
_PREPARATION_ROW_INSTANCE_MANIFEST_OWNER_CLASS: Final = "PREPARATION_ROW_INSTANCE_MANIFEST"
_PREPARATION_ROW_INSTANCE_MANIFEST_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/ExecutedPreparationRowInstanceManifest"
)
_PREPARATION_ROW_INSTANCE_MANIFEST_ROLES: Final = (
    "INPUT",
    "TRAINING",
    "OUTPUT",
    "REFERENCE_FIT",
)
_PREPARATION_ROW_INSTANCE_MANIFEST_DIGEST_FIELDS: Final = (
    "input_row_instance_manifest_sha256",
    "training_row_instance_manifest_sha256",
    "output_row_instance_manifest_sha256",
    "reference_fit_row_instance_manifest_sha256",
)
_PUBLIC_OPERATION_EVIDENCE_OWNER_CLASSES: Final = frozenset(
    {
        _PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS,
        _PREPARATION_ROW_INSTANCE_MANIFEST_OWNER_CLASS,
        "PUBLIC_BATCH_CASE_PLAN",
        "PROPORTIONAL_OPERATION_PLAN",
        "PUBLIC_TERMINAL_RESULT",
        "PREPROCESSING_EXECUTION_RECORD",
        "EXECUTED_TRANSFORMATION_EVIDENCE",
        "REFERENCE_FIT_GROUP_ROLE_EVIDENCE",
        "EXECUTED_BOUNDARY_RULE_IDENTITY",
        "CASE_INFLUENCE_AGGREGATE",
    }
)
_SYNTHETIC_TRUTH_OWNER_CLASS: Final = "SYNTHETIC_TRUTH"
_SYNTHETIC_TRUTH_SCHEMA_REF: Final = "schemas/synthetic-truth.schema.json"
_SYNTHETIC_SCIENTIFIC_DATA_OWNER_CLASS: Final = "SYNTHETIC_SCIENTIFIC_DATA"
_SYNTHETIC_SCIENTIFIC_DATA_SCHEMA_REF: Final = "schemas/synthetic-scientific-data.schema.json"
_SCENARIO_MATCHED_METRIC_RECORD_OWNER_CLASS: Final = "SCENARIO_MATCHED_METRIC_RECORD"
_SCENARIO_MATCHED_METRIC_RECORD_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/ScenarioMatchedMetricRecord"
)
_CANDIDATE_STRONG_EVIDENCE_DECISION_OWNER_CLASS: Final = "CANDIDATE_STRONG_EVIDENCE_DECISION"
_PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION_OWNER_CLASS: Final = (
    "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION"
)
_PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/PrivateCanonicalArrayValueProjection"
)
_FIT_RESPONSE_BINDING_OWNER_CLASS: Final = "FIT_RESPONSE_BINDING"
_CANONICAL_SCIENTIFIC_PAYLOAD_OWNER_CLASS: Final = "CANONICAL_SCIENTIFIC_PAYLOAD"
_FIT_RESPONSE_BINDING_DIGEST_DOMAIN: Final = "ebm-audit/fit-evaluator-worker-response-binding/1"
_FIT_RESPONSE_BINDING_FIELDS: Final = (
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
_SCHEMA_VERSION: Final = "ebm-audit-scenario-source-owner-manifest/1.0"
_PHASES: Final = {"DEVELOPMENT", "HELDOUT"}
_OWNER_BINDINGS: Final = {
    "SEALED_CASE_RECORD": (
        "schemas/evaluator-receipts.schema.json#/$defs/SealedCaseRecord",
        ("heldout_attempt_id", "benchmark_subject_digest", "family_id", "case_id", "comparator_id"),
    ),
    "SYNTHETIC_TRUTH": ("schemas/synthetic-truth.schema.json", ("truth_object_sha256",)),
    "SYNTHETIC_SCIENTIFIC_DATA": (
        "schemas/synthetic-scientific-data.schema.json",
        ("case_id", "generated_scientific_data_sha256"),
    ),
    "RESOLVED_GENERATOR_CONFIGURATION": (
        "schemas/synthetic-resolved-configuration.schema.json#/$defs/ResolvedGeneratorConfiguration",
        (
            "scenario_family_id",
            "variant_id",
            "replicate_index",
            "resolved_generator_configuration_sha256",
        ),
    ),
    "RESOLVED_GENERATOR_MECHANISM": (
        "schemas/synthetic-resolved-configuration.schema.json#/$defs/ResolvedGeneratorMechanism",
        ("scenario_family_id", "mechanism_kind", "resolved_generator_mechanism_sha256"),
    ),
    "COMPONENT_SEED_MANIFEST": (
        "schemas/synthetic-resolved-configuration.schema.json#/$defs/ComponentSeedManifest",
        ("case_seed", "component_seed_manifest_sha256"),
    ),
    "SEALED_RESULT_RECORD": (
        "schemas/evaluator-receipts.schema.json#/$defs/SealedResultRecord",
        ("heldout_attempt_id", "benchmark_subject_digest", "record_kind", "core_final_status"),
    ),
    "FIT_RESPONSE_BINDING": (
        "schemas/evaluator-receipts.schema.json#/$defs/FitSuccessEvaluatorWorkerResponseBinding",
        ("request_id", "response_metadata_digest", "payload_digest"),
    ),
    "CANONICAL_SCIENTIFIC_PAYLOAD": (
        "schemas/canonical-records.schema.json#/$defs/CanonicalScientificPayload",
        ("benchmark_subject_digest", "operation_instance_id"),
    ),
    "CANONICAL_ARRAY_ARTIFACT": (
        "schemas/scenario-evidence.schema.json#/$defs/CanonicalArrayArtifactOwner",
        (
            "benchmark_subject_digest",
            "family_id",
            "case_id",
            "operation_instance_id",
            "chain_execution_id",
            "member_name",
        ),
    ),
    "MATCHED_COMPARATOR_EVIDENCE": (
        "schemas/comparator-transaction.schema.json#/$defs/MatchedComparatorEvidenceManifest",
        ("benchmark_subject_digest", "matched_comparator_evidence_sha256"),
    ),
    "COMPARISON_RECORD": (
        "schemas/canonical-records.schema.json#/$defs/ComparisonRecord",
        ("comparison_id", "left_result_id", "right_result_id", "metric_id"),
    ),
    "INFLUENCE_RECORD": (
        "schemas/canonical-records.schema.json#/$defs/InfluenceRecord",
        (
            "baseline_universe_id",
            "removal_universe_id",
            "removal_spec_id",
            "influence_rule_version",
        ),
    ),
    "PARTICIPANT_EVENT_MANIFEST": (
        "schemas/canonical-records.schema.json#/$defs/ParticipantEventManifest",
        ("core_data_accounting_digest", "training_row_indexes_digest"),
    ),
    "ANALYSIS_SPEC": (
        "schemas/analysis-universe.schema.json#/$defs/AnalysisSpec",
        (
            "spec_schema_version",
            "dataset_variant_intent",
            "cohort_rule",
            "event_set",
            "event_directions",
            "preprocessing",
            "outlier_policy",
            "missingness_policy",
            "covariate_adjustment",
            "backend",
            "mcmc",
            "operation_intent",
        ),
    ),
    "BENCHMARK_OPERATION_MANIFEST": (
        "schemas/evaluator-receipts.schema.json#/$defs/BenchmarkOperationManifest",
        ("manifest_kind",),
    ),
    "PREPROCESSING_EXECUTION_RECORD": (
        "schemas/scenario-evidence.schema.json#/$defs/ExecutedPreprocessingExecutionRecord",
        (
            "case_operation_join_key",
            "execution_role",
            "proportional_operation_plan_sha256",
            "operation_plan_entry_sha256",
        ),
    ),
    "WARNING_RECORD": (
        "schemas/canonical-records.schema.json#/$defs/WarningRecord",
        ("code", "severity"),
    ),
    "SIDE_EFFECTS_RECORD": (
        "schemas/worker-protocol.schema.json#/$defs/SideEffectsRecord",
        ("schema_version", "inventory_root"),
    ),
    "REPORT_PREDICATE_OUTCOME": (
        "schemas/scenario-evidence.schema.json#/$defs/ReportPredicateOutcome",
        (
            "benchmark_subject_digest",
            "family_id",
            "predicate_id",
            "cardinality_member_id",
            "report_claim_projection_sha256",
        ),
    ),
    "CANDIDATE_STRONG_EVIDENCE_DECISION": (
        "schemas/scientific-invariant.schema.json#/$defs/CandidateStrongEvidenceDecision",
        ("benchmark_subject_digest", "rule_id", "opportunity_id"),
    ),
    "FALSE_POSITIVE_EVIDENCE_BUNDLE": (
        "schemas/scientific-invariant.schema.json#/$defs/FalsePositiveEvidenceBundle",
        ("schema_version",),
    ),
    _PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS: (
        _PREPARATION_AUDIT_EVIDENCE_SCHEMA_REF,
        ("case_id", "operation_instance_id", "analysis_spec_sha256"),
    ),
    _PREPARATION_ROW_INSTANCE_MANIFEST_OWNER_CLASS: (
        _PREPARATION_ROW_INSTANCE_MANIFEST_SCHEMA_REF,
        (
            "case_operation_join_key",
            "row_role",
            "proportional_operation_plan_sha256",
            "operation_plan_entry_sha256",
        ),
    ),
    "PUBLIC_BATCH_CASE_PLAN": (
        "schemas/evaluator-receipts.schema.json#/$defs/PublicBatchCasePlan",
        (
            "benchmark_subject_digest",
            "authenticated_batch_sha256",
            "case_ordinal",
            "case_id",
        ),
    ),
    "PROPORTIONAL_OPERATION_PLAN": (
        "schemas/evaluator-receipts.schema.json#/$defs/ProportionalOperationPlan",
        (
            "benchmark_subject_digest",
            "contract_sha256",
            "authenticated_batch_sha256",
            "proportional_operation_plan_sha256",
        ),
    ),
    "PUBLIC_TERMINAL_RESULT": (
        "schemas/evaluator-receipts.schema.json#/$defs/PublicTerminalResult",
        ("case_operation_join_key",),
    ),
    "EXECUTED_TRANSFORMATION_EVIDENCE": (
        "schemas/scenario-evidence.schema.json#/$defs/ExecutedTransformationEvidence",
        (
            "case_operation_join_key",
            "proportional_operation_plan_sha256",
            "operation_plan_entry_sha256",
        ),
    ),
    "REFERENCE_FIT_GROUP_ROLE_EVIDENCE": (
        "schemas/scenario-evidence.schema.json#/$defs/ReferenceFitGroupRoleEvidence",
        ("case_operation_join_key", "analysis_spec_sha256"),
    ),
    "EXECUTED_BOUNDARY_RULE_IDENTITY": (
        "schemas/scenario-evidence.schema.json#/$defs/ExecutedBoundaryRuleIdentity",
        ("case_operation_join_key", "rule_id", "analysis_spec_sha256"),
    ),
    "REPORT_CLAIM_PROJECTION": (
        "schemas/scenario-evidence.schema.json#/$defs/AuthenticatedReportClaimProjection",
        ("benchmark_subject_digest", "report_claim_projection_sha256"),
    ),
    _SCENARIO_MATCHED_METRIC_RECORD_OWNER_CLASS: (
        _SCENARIO_MATCHED_METRIC_RECORD_SCHEMA_REF,
        (
            "benchmark_subject_digest",
            "comparator_id",
            "source_variant_id",
            "replicate_index",
            "pair_index",
            "pairing_key",
            "left_member_id",
            "right_member_id",
            "metric_id",
        ),
    ),
    _PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION_OWNER_CLASS: (
        _PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION_SCHEMA_REF,
        (
            "canonical_array_artifact_owner_sha256",
            "member_name",
            "array_value_sha256",
        ),
    ),
    "REPORT_WARNING_LEDGER": (
        "schemas/scenario-evidence.schema.json#/$defs/PreRenderReportWarningLedger",
        ("benchmark_subject_digest", "case_id", "report_claim_projection_sha256"),
    ),
    "REPORT_TERMINAL_VISIBILITY": (
        "schemas/scenario-evidence.schema.json#/$defs/PreRenderReportTerminalVisibility",
        (
            "case_operation_join_key",
            "public_terminal_result_sha256",
            "report_claim_projection_sha256",
        ),
    ),
    "ANALYSIS_RULE_IDENTITY": (
        "schemas/scenario-evidence.schema.json#/$defs/AnalysisRuleIdentity",
        ("rule_id", "analysis_spec_sha256"),
    ),
    "CASE_INFLUENCE_AGGREGATE": (
        "schemas/scenario-evidence.schema.json#/$defs/CaseInfluenceAggregate",
        ("case_id", "baseline_universe_id", "influence_rule_version"),
    ),
}

_CURRENT_GENUINE_OWNER_CLASSES: Final = frozenset(
    {
        _PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS,
        _PREPARATION_ROW_INSTANCE_MANIFEST_OWNER_CLASS,
        _SYNTHETIC_TRUTH_OWNER_CLASS,
        _SYNTHETIC_SCIENTIFIC_DATA_OWNER_CLASS,
        "RESOLVED_GENERATOR_CONFIGURATION",
        "RESOLVED_GENERATOR_MECHANISM",
        "COMPONENT_SEED_MANIFEST",
        "ANALYSIS_SPEC",
        _FIT_RESPONSE_BINDING_OWNER_CLASS,
        _CANONICAL_SCIENTIFIC_PAYLOAD_OWNER_CLASS,
        _SCENARIO_MATCHED_METRIC_RECORD_OWNER_CLASS,
        _CANDIDATE_STRONG_EVIDENCE_DECISION_OWNER_CLASS,
        _PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION_OWNER_CLASS,
        "PUBLIC_BATCH_CASE_PLAN",
        "PROPORTIONAL_OPERATION_PLAN",
        "PUBLIC_TERMINAL_RESULT",
        "PREPROCESSING_EXECUTION_RECORD",
        "EXECUTED_TRANSFORMATION_EVIDENCE",
        "REFERENCE_FIT_GROUP_ROLE_EVIDENCE",
        "EXECUTED_BOUNDARY_RULE_IDENTITY",
        "CASE_INFLUENCE_AGGREGATE",
    }
)
_FORCED_UNAVAILABLE_OWNER_CLASSES: Final = frozenset(
    {
        "REPORT_WARNING_LEDGER",
        "REPORT_TERMINAL_VISIBILITY",
        "ANALYSIS_RULE_IDENTITY",
        # The frozen registry still names report_artifact_sha256 while the
        # current schema names report_claim_projection_sha256.  No record can
        # be present until that frozen-contract conflict is resolved.
        "REPORT_PREDICATE_OUTCOME",
    }
)


class _ScenarioSourceOwnerManifestError(RuntimeError):
    """Fail-closed rejection at the package-private source-owner boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Scenario source-owner manifest failed: {code}.")


def _reject(code: str) -> Never:
    raise _ScenarioSourceOwnerManifestError(code)


@dataclass(frozen=True, slots=True)
class _ScenarioSourceRecordInput:
    owner_class: str
    owner_schema_ref: str
    source_relative_path: str
    source_content_bytes: bytes
    source_record_bytes: bytes
    natural_identity: Mapping[str, object]
    ordered_support_owner_sha256: tuple[str, ...] = ()
    source_capability: object | None = None


@dataclass(frozen=True, slots=True)
class _PreparationRowInstanceManifestSource:
    """Exact PAE and four-role manifest capabilities retained for readback."""

    evidence: PreparationAuditEvidence
    manifests: PreparationRowInstanceManifests


@dataclass(frozen=True, slots=True)
class _PreparationSourceBundle:
    """One fully authenticated PAE bundle retained only for one transaction."""

    evidence: PreparationAuditEvidence
    manifests: PreparationRowInstanceManifests
    pae_sources: tuple[_ScenarioSourceRecordInput, ...]
    row_sources: tuple[_ScenarioSourceRecordInput, ...]


@dataclass(slots=True)
class _PreparationSourceTransactionLease:
    """Shared expiry marker that also invalidates copied contexts."""

    active: bool
    bundles: tuple[_PreparationSourceBundle, ...]


_PREPARATION_SOURCE_TRANSACTION_LEASES: ContextVar[
    tuple[_PreparationSourceTransactionLease, ...]
] = ContextVar("ebm_audit_preparation_source_transaction_leases", default=())


@dataclass(frozen=True, slots=True)
class _ScientificMeaningSourceBundle:
    owner: object
    records: tuple[_ScenarioSourceRecordInput, ...]


@dataclass(slots=True)
class _ScientificMeaningSourceTransactionLease:
    active: bool
    bundles: tuple[_ScientificMeaningSourceBundle, ...]


_SCIENTIFIC_MEANING_SOURCE_TRANSACTION_LEASES: ContextVar[
    tuple[_ScientificMeaningSourceTransactionLease, ...]
] = ContextVar("ebm_audit_scientific_meaning_source_transaction_leases", default=())


def _active_scientific_meaning_source_bundle(
    owner: object,
) -> _ScientificMeaningSourceBundle | None:
    for lease in reversed(_SCIENTIFIC_MEANING_SOURCE_TRANSACTION_LEASES.get()):
        if not lease.active:
            continue
        for bundle in lease.bundles:
            if bundle.owner is owner:
                return bundle
    return None


@dataclass(frozen=True, slots=True)
class _StoredRecord:
    owner_class: str
    owner_schema_ref: str
    source_relative_path: str
    source_content_bytes: bytes
    source_record_bytes: bytes
    natural_identity_bytes: bytes
    ordered_support_owner_sha256: tuple[str, ...]
    source_capability: object | None


@dataclass(slots=True)
class _ManifestState:
    authentication_key: bytes
    context_owner: object
    authority_origin: Literal["HELDOUT", "PUBLIC_SYNTHETIC"]
    evaluation_phase: Literal["DEVELOPMENT", "HELDOUT"]
    benchmark_subject_digest: str
    operation_plan_sha256: str
    records: tuple[_StoredRecord, ...]
    manifest_bytes: bytes
    authentication_tag: str
    consumed: bool
    lock: RLock


@final
class _AuthenticatedScenarioSourceOwnerManifest:
    """Opaque handle whose complete state remains in the private registry."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> _AuthenticatedScenarioSourceOwnerManifest:
        raise TypeError("Scenario source-owner manifests are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Scenario source-owner manifests cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Scenario source-owner manifests are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Scenario source-owner manifests cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Scenario source-owner manifests cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Scenario source-owner manifests cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Scenario source-owner manifests cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Scenario source-owner manifests cannot be copied or serialized.")


@final
class _AuthenticatedScenarioSourceOwnerProjection:
    """Opaque one-shot handle for one case-bound source-owner projection."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> _AuthenticatedScenarioSourceOwnerProjection:
        raise TypeError("Scenario source-owner projections are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Scenario source-owner projections cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Scenario source-owner projections are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Scenario source-owner projections cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Scenario source-owner projections cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Scenario source-owner projections cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Scenario source-owner projections cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Scenario source-owner projections cannot be copied or serialized.")


@dataclass(frozen=True, slots=True)
class _ScenarioSourceOwnerRecord:
    owner_class: str
    owner_schema_ref: str
    natural_identity: Mapping[str, object]
    source_record: Mapping[str, object]
    source_record_sha256: str
    ordered_support_owner_sha256: tuple[str, ...]
    source_capability: object | None


@dataclass(frozen=True, slots=True)
class _AuthenticatedSourceOwnerRecordState:
    owner_class: str
    owner_schema_ref: str
    natural_identity_bytes: bytes
    source_record_bytes: bytes
    source_record_sha256: str
    source_owner: object
    readback: Callable[[object], tuple[_ScenarioSourceRecordInput, ...]]


@final
class _AuthenticatedSourceOwnerRecordCapability:
    """Opaque proof that one record crossed the authenticated manifest boundary."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> _AuthenticatedSourceOwnerRecordCapability:
        raise TypeError("Source-owner record capabilities are privately issued.")


_AUTHENTICATED_SOURCE_OWNER_RECORD_STATES: OneShotWeakRegistry[
    _AuthenticatedSourceOwnerRecordCapability, _AuthenticatedSourceOwnerRecordState
]
(
    _AUTHENTICATED_SOURCE_OWNER_RECORD_STATES,
    _AUTHENTICATED_SOURCE_OWNER_RECORD_STATE_ISSUER,
) = create_one_shot_registry()


_MANIFEST_STATES: OneShotWeakRegistry[_AuthenticatedScenarioSourceOwnerManifest, _ManifestState]
_MANIFEST_STATES, _MANIFEST_STATE_ISSUER = create_one_shot_registry()
_ISSUER_CLAIMS: WeakSet[type[object]] = WeakSet()
_ISSUER_CLAIM_LOCK = RLock()


def _is_sha256(value: object, *, prefixed: bool = False) -> bool:
    expected_length = 71 if prefixed else 64
    offset = 7 if prefixed else 0
    return (
        type(value) is str
        and len(value) == expected_length
        and (not prefixed or value.startswith("sha256:"))
        and all(character in "0123456789abcdef" for character in value[offset:])
    )


def _identity_value_valid(value: object) -> bool:
    try:
        canonical_json_bytes(value)
    except CanonicalizationError:
        return False
    return True


def _validate_record_schema(schema_ref: str, source_record: object) -> None:
    schema_path, separator, definition = schema_ref.partition("#/$defs/")
    if not schema_path.startswith("schemas/") or (separator and not definition):
        _reject("OWNER_TYPE_BINDING_INVALID")
    try:
        validate_instance(
            source_record,
            schema_path.removeprefix("schemas/"),
            definition=definition or None,
        )
    except (SchemaValidationError, ValueError):
        _reject("SOURCE_RECORD_SCHEMA_INVALID")


def _preparation_audit_evidence_source_records(
    evidence: PreparationAuditEvidence,
    *,
    case_id: str | None = None,
) -> tuple[_ScenarioSourceRecordInput, ...]:
    """Project PAE records only through the genuine sealed capability reader."""

    if type(evidence) is not PreparationAuditEvidence or (
        case_id is not None and (type(case_id) is not str or not case_id)
    ):
        _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
    active = _active_preparation_source_bundle(evidence)
    if active is not None:
        selected = tuple(
            record
            for record in active.pae_sources
            if case_id is None or record.natural_identity.get("case_id") == case_id
        )
        if not selected or (case_id is not None and len(selected) != 1):
            _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
        return selected
    try:
        records = _PREPARATION_AUDIT_EVIDENCE_READER(evidence)
    except ScientificEvidenceError:
        _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
    return _project_preparation_audit_evidence_source_records(
        evidence,
        records,
        case_id=case_id,
    )


def _project_preparation_audit_evidence_source_records(
    evidence: PreparationAuditEvidence,
    records: tuple[dict[str, object], ...],
    *,
    case_id: str | None,
) -> tuple[_ScenarioSourceRecordInput, ...]:
    """Project already authenticated immutable PAE records without owner reread."""

    if not records:
        _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")

    projected: list[_ScenarioSourceRecordInput] = []
    for index, source_record in enumerate(records):
        if type(source_record) is not dict:
            _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
        try:
            source_record_bytes = canonical_json_bytes(source_record)
            natural_identity = {
                field: cast(str, source_record[field])
                for field in (
                    "case_id",
                    "operation_instance_id",
                    "analysis_spec_sha256",
                )
            }
        except (CanonicalizationError, KeyError):
            _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
        projected.append(
            _ScenarioSourceRecordInput(
                owner_class=_PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS,
                owner_schema_ref=_PREPARATION_AUDIT_EVIDENCE_SCHEMA_REF,
                source_relative_path=(f"owners/preparation-audit-evidence/{index:08d}.json"),
                source_content_bytes=source_record_bytes,
                source_record_bytes=source_record_bytes,
                natural_identity=natural_identity,
                source_capability=evidence,
            )
        )
    selected = tuple(
        record
        for record in projected
        if case_id is None or record.natural_identity.get("case_id") == case_id
    )
    if not selected or (case_id is not None and len(selected) != 1):
        _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
    return selected


def _preparation_row_instance_manifest_source_records(
    evidence: PreparationAuditEvidence,
    manifests: PreparationRowInstanceManifests,
    *,
    case_id: str,
) -> tuple[_ScenarioSourceRecordInput, ...]:
    """Project one exact PAE's four ordered row manifests with one support edge."""

    if (
        type(evidence) is not PreparationAuditEvidence
        or type(manifests) is not PreparationRowInstanceManifests
        or type(case_id) is not str
        or not case_id
    ):
        _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
    active = _active_preparation_source_bundle(evidence, manifests)
    if active is not None:
        selected = tuple(
            record
            for record in active.row_sources
            if strict_json_loads(record.source_record_bytes).get("case_id") == case_id
        )
        if len(selected) != len(_PREPARATION_ROW_INSTANCE_MANIFEST_ROLES):
            _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
        return selected
    try:
        if _issue_preparation_row_instance_manifests(evidence) is not manifests:
            _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
        pae_records = _PREPARATION_AUDIT_EVIDENCE_READER(evidence)
        row_records = _read_preparation_row_instance_manifests(manifests)
    except ScientificEvidenceError:
        _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")

    return _project_preparation_row_instance_manifest_source_records(
        evidence,
        manifests,
        pae_records,
        row_records,
        case_id=case_id,
    )


def _project_preparation_row_instance_manifest_source_records(
    evidence: PreparationAuditEvidence,
    manifests: PreparationRowInstanceManifests,
    pae_records: tuple[dict[str, object], ...],
    row_records: tuple[dict[str, object], ...],
    *,
    case_id: str,
) -> tuple[_ScenarioSourceRecordInput, ...]:
    """Project authenticated four-role rows without re-reading their capture."""

    matching_pae = tuple(row for row in pae_records if row.get("case_id") == case_id)
    if len(matching_pae) != 1:
        _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
    pae_record = matching_pae[0]
    operation_instance_id = pae_record.get("operation_instance_id")
    if type(operation_instance_id) is not str or not operation_instance_id:
        _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")

    pae_inputs = _project_preparation_audit_evidence_source_records(
        evidence,
        pae_records,
        case_id=case_id,
    )
    if len(pae_inputs) != 1:
        _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
    pae_input = pae_inputs[0]
    try:
        pae_source_record = strict_json_loads(pae_input.source_record_bytes)
    except CanonicalizationError:
        _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
    if type(pae_source_record) is not dict:
        _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
    pae_source_record_sha256 = structured_sha256_hex(
        _RECORD_DOMAIN,
        {
            "owner_class": pae_input.owner_class,
            "natural_identity": dict(pae_input.natural_identity),
            "source_record": pae_source_record,
        },
    )

    selected = tuple(
        (index, row)
        for index, row in enumerate(row_records)
        if row.get("case_id") == case_id
        and row.get("operation_instance_id") == operation_instance_id
    )
    if len(selected) != len(_PREPARATION_ROW_INSTANCE_MANIFEST_ROLES):
        _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
    source = _PreparationRowInstanceManifestSource(evidence, manifests)
    projected: list[_ScenarioSourceRecordInput] = []
    for role, digest_field in zip(
        _PREPARATION_ROW_INSTANCE_MANIFEST_ROLES,
        _PREPARATION_ROW_INSTANCE_MANIFEST_DIGEST_FIELDS,
        strict=True,
    ):
        matches = tuple(row for index, row in selected if row.get("row_role") == role)
        if len(matches) != 1:
            _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
        source_record = matches[0]
        digest = source_record.get("row_instance_manifest_sha256")
        if type(digest) is not str or pae_record.get(digest_field) != digest:
            _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
        try:
            source_record_bytes = canonical_json_bytes(source_record)
            natural_identity = {
                field: cast(str, source_record[field])
                for field in (
                    "case_id",
                    "operation_instance_id",
                    "row_role",
                    "row_instance_manifest_sha256",
                )
            }
        except (CanonicalizationError, KeyError):
            _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
        index = next(index for index, row in selected if row is source_record)
        projected.append(
            _ScenarioSourceRecordInput(
                owner_class=_PREPARATION_ROW_INSTANCE_MANIFEST_OWNER_CLASS,
                owner_schema_ref=_PREPARATION_ROW_INSTANCE_MANIFEST_SCHEMA_REF,
                source_relative_path=(
                    f"owners/preparation-row-instance-manifest/{index:08d}-{digest}.json"
                ),
                source_content_bytes=source_record_bytes,
                source_record_bytes=source_record_bytes,
                natural_identity=natural_identity,
                ordered_support_owner_sha256=(pae_source_record_sha256,),
                source_capability=source,
            )
        )
    return tuple(projected)


def _active_preparation_source_bundle(
    evidence: PreparationAuditEvidence,
    manifests: PreparationRowInstanceManifests | None = None,
) -> _PreparationSourceBundle | None:
    """Return one exact live transaction bundle, never an expired context copy."""

    for lease in reversed(_PREPARATION_SOURCE_TRANSACTION_LEASES.get()):
        if not lease.active:
            continue
        for bundle in lease.bundles:
            if bundle.evidence is evidence and (
                manifests is None or bundle.manifests is manifests
            ):
                return bundle
    return None


def _preparation_source_requests(
    records: tuple[_ScenarioSourceRecordInput | _StoredRecord, ...],
) -> tuple[
    tuple[PreparationAuditEvidence, PreparationRowInstanceManifests | None], ...
]:
    requests: list[
        tuple[PreparationAuditEvidence, PreparationRowInstanceManifests | None]
    ] = []
    for record in records:
        evidence: PreparationAuditEvidence | None = None
        manifests: PreparationRowInstanceManifests | None = None
        capability = record.source_capability
        if (
            record.owner_class == _PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS
            and type(capability) is PreparationAuditEvidence
        ):
            evidence = capability
        elif (
            record.owner_class == _PREPARATION_ROW_INSTANCE_MANIFEST_OWNER_CLASS
            and type(capability) is _PreparationRowInstanceManifestSource
        ):
            evidence = capability.evidence
            manifests = capability.manifests
        if evidence is None:
            continue
        match = next(
            (index for index, (owner, _manifests) in enumerate(requests) if owner is evidence),
            None,
        )
        if match is None:
            requests.append((evidence, manifests))
            continue
        previous_manifests = requests[match][1]
        if (
            previous_manifests is not None
            and manifests is not None
            and previous_manifests is not manifests
        ):
            _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
        if previous_manifests is None and manifests is not None:
            requests[match] = (evidence, manifests)
    return tuple(requests)


@contextmanager
def _preparation_source_owner_transaction(
    records: tuple[_ScenarioSourceRecordInput | _StoredRecord, ...],
) -> Iterator[None]:
    """Reuse one freshly authenticated PAE bundle only within this transaction."""

    with _preparation_source_owner_request_transaction(
        _preparation_source_requests(records)
    ):
        yield


@contextmanager
def _preparation_source_owner_evidence_transaction(
    evidences: tuple[PreparationAuditEvidence, ...],
) -> Iterator[None]:
    """Open the source transaction before its immutable records are projected."""

    if type(evidences) is not tuple or any(
        type(evidence) is not PreparationAuditEvidence for evidence in evidences
    ):
        _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
    with _preparation_source_owner_request_transaction(
        tuple((evidence, None) for evidence in evidences)
    ):
        yield


@contextmanager
def _preparation_source_owner_request_transaction(
    requests: tuple[
        tuple[PreparationAuditEvidence, PreparationRowInstanceManifests | None], ...
    ],
) -> Iterator[None]:
    """Authenticate exact requests once and expire every retained reference."""

    if not requests:
        yield
        return
    if all(
        _active_preparation_source_bundle(evidence, manifests) is not None
        for evidence, manifests in requests
    ):
        yield
        return

    bundles: list[_PreparationSourceBundle] = []
    for evidence, requested_manifests in requests:
        active = _active_preparation_source_bundle(evidence, requested_manifests)
        if active is not None:
            bundles.append(active)
            continue
        try:
            pae_records, manifests, row_records = (
                _read_preparation_audit_evidence_bundle(evidence)
            )
        except ScientificEvidenceError:
            _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
        if requested_manifests is not None and requested_manifests is not manifests:
            _reject("PREPARATION_ROW_INSTANCE_MANIFEST_INVALID")
        pae_sources = _project_preparation_audit_evidence_source_records(
            evidence,
            pae_records,
            case_id=None,
        )
        case_ids = tuple(
            cast(str, record.natural_identity["case_id"]) for record in pae_sources
        )
        row_sources = tuple(
            source
            for case_id in case_ids
            for source in _project_preparation_row_instance_manifest_source_records(
                evidence,
                manifests,
                pae_records,
                row_records,
                case_id=case_id,
            )
        )
        bundles.append(
            _PreparationSourceBundle(
                evidence=evidence,
                manifests=manifests,
                pae_sources=pae_sources,
                row_sources=row_sources,
            )
        )

    lease = _PreparationSourceTransactionLease(active=True, bundles=tuple(bundles))
    token = _PREPARATION_SOURCE_TRANSACTION_LEASES.set(
        (*_PREPARATION_SOURCE_TRANSACTION_LEASES.get(), lease)
    )
    try:
        yield
    finally:
        lease.active = False
        lease.bundles = ()
        _PREPARATION_SOURCE_TRANSACTION_LEASES.reset(token)


def _synthetic_truth_source_record(
    evidence: SyntheticTruthScoringEvidence,
    *,
    bind: bool,
) -> _ScenarioSourceRecordInput:
    if type(evidence) is not SyntheticTruthScoringEvidence:
        _reject("SYNTHETIC_TRUTH_INVALID")
    try:
        source_record_bytes = (
            _bind_synthetic_truth_scoring_evidence(evidence)
            if bind
            else _read_synthetic_truth_scoring_record_bytes(evidence)
        )
        source_record = strict_json_loads(source_record_bytes)
        if type(source_record) is not dict:
            _reject("SYNTHETIC_TRUTH_INVALID")
        digest = cast(str, source_record["truth_object_sha256"])
        facts = _read_synthetic_truth_scoring_evidence(evidence)
    except (CanonicalizationError, KeyError, SchemaValidationError, TypeError, UnexpectedCoreError):
        _reject("SYNTHETIC_TRUTH_INVALID")
    return _ScenarioSourceRecordInput(
        owner_class=_SYNTHETIC_TRUTH_OWNER_CLASS,
        owner_schema_ref=_SYNTHETIC_TRUTH_SCHEMA_REF,
        source_relative_path=(f"owners/30-synthetic-truth/{facts.family_id}/{facts.case_id}.json"),
        source_content_bytes=source_record_bytes,
        source_record_bytes=source_record_bytes,
        natural_identity={"truth_object_sha256": digest},
        source_capability=evidence,
    )


def _synthetic_truth_source_records(
    evidence: SyntheticTruthScoringEvidence,
) -> tuple[_ScenarioSourceRecordInput, ...]:
    """Bind one genuine retained generated truth into one manifest only."""

    return (_synthetic_truth_source_record(evidence, bind=True),)


def _synthetic_scientific_data_source_record(
    evidence: SyntheticScientificDataEvidence,
    *,
    bind: bool,
) -> _ScenarioSourceRecordInput:
    if type(evidence) is not SyntheticScientificDataEvidence:
        _reject("SYNTHETIC_SCIENTIFIC_DATA_INVALID")
    try:
        source_record_bytes = (
            _bind_synthetic_scientific_data_evidence(evidence)
            if bind
            else _read_synthetic_scientific_data_evidence(evidence)
        )
        source_record = strict_json_loads(source_record_bytes)
        if type(source_record) is not dict:
            _reject("SYNTHETIC_SCIENTIFIC_DATA_INVALID")
        case_id = cast(str, source_record["case_id"])
        digest = cast(str, source_record["generated_scientific_data_sha256"])
    except (CanonicalizationError, KeyError, SchemaValidationError, TypeError, UnexpectedCoreError):
        _reject("SYNTHETIC_SCIENTIFIC_DATA_INVALID")
    return _ScenarioSourceRecordInput(
        owner_class=_SYNTHETIC_SCIENTIFIC_DATA_OWNER_CLASS,
        owner_schema_ref=_SYNTHETIC_SCIENTIFIC_DATA_SCHEMA_REF,
        source_relative_path=(f"owners/20-synthetic-scientific-data/{case_id}.json"),
        source_content_bytes=source_record_bytes,
        source_record_bytes=source_record_bytes,
        natural_identity={
            "case_id": case_id,
            "generated_scientific_data_sha256": digest,
        },
        source_capability=evidence,
    )


def _synthetic_scientific_data_source_records(
    evidence: SyntheticScientificDataEvidence,
) -> tuple[_ScenarioSourceRecordInput, ...]:
    """Bind one genuine retained generated data object into one manifest only."""

    return (_synthetic_scientific_data_source_record(evidence, bind=True),)


def _resolved_case_source_records_from_batch(
    owner: object,
) -> tuple[_ScenarioSourceRecordInput, ...]:
    from ebm_audit.evaluator.scenario_case_batch import (
        AuthenticatedScenarioCaseBatch,
        _authenticated_resolved_case_source_records,
    )

    if type(owner) is not AuthenticatedScenarioCaseBatch:
        _reject("RESOLVED_CASE_SOURCE_OWNER_INVALID")
    return cast(
        tuple[_ScenarioSourceRecordInput, ...],
        _authenticated_resolved_case_source_records(owner),
    )


def _analysis_spec_source_records(
    owner: object,
) -> tuple[_ScenarioSourceRecordInput, ...]:
    """Re-read the exact baseline AnalysisSpec retained by one captured run."""

    active = _active_scientific_meaning_source_bundle(owner)
    if active is not None:
        return active.records
    if type(owner) is not CapturedScientificRun:
        _reject("ANALYSIS_SPEC_SOURCE_OWNER_INVALID")
    try:
        state = _read_captured_scientific_run(owner)
        candidates = strict_json_loads(state.plan_candidates_bytes)
    except (CanonicalizationError, ScientificEvidenceError, TypeError):
        _reject("ANALYSIS_SPEC_SOURCE_OWNER_INVALID")
    if type(candidates) is not list:
        _reject("ANALYSIS_SPEC_SOURCE_OWNER_INVALID")
    baseline = tuple(
        candidate
        for candidate in candidates
        if type(candidate) is dict
        and candidate.get("analysis_spec_id") == state.baseline_analysis_spec_id
    )
    if len(baseline) != 1:
        _reject("ANALYSIS_SPEC_SOURCE_OWNER_INVALID")
    source_record = baseline[0].get("analysis_spec")
    if type(source_record) is not dict:
        _reject("ANALYSIS_SPEC_SOURCE_OWNER_INVALID")
    try:
        source_record_bytes = canonical_json_bytes(source_record)
        natural_identity = {
            field: source_record[field] for field in _OWNER_BINDINGS["ANALYSIS_SPEC"][1]
        }
    except (CanonicalizationError, KeyError):
        _reject("ANALYSIS_SPEC_SOURCE_OWNER_INVALID")
    return (
        _ScenarioSourceRecordInput(
            owner_class="ANALYSIS_SPEC",
            owner_schema_ref=_OWNER_BINDINGS["ANALYSIS_SPEC"][0],
            source_relative_path="owners/40-analysis-spec/00000000.json",
            source_content_bytes=source_record_bytes,
            source_record_bytes=source_record_bytes,
            natural_identity=natural_identity,
            source_capability=owner,
        ),
    )


def _public_operation_evidence_source_records(
    owner: object,
) -> tuple[_ScenarioSourceRecordInput, ...]:
    """Convert one revalidated ordinary evidence owner into manifest inputs."""

    from ebm_audit.evaluator.public_operation_evidence import (
        PublicOperationEvidence,
        _read_public_operation_evidence_records,
    )

    if type(owner) is not PublicOperationEvidence:
        _reject("PUBLIC_OPERATION_EVIDENCE_INVALID")
    try:
        rows = _read_public_operation_evidence_records(owner)
        if any(row.source_owner is not owner for row in rows):
            _reject("PUBLIC_OPERATION_EVIDENCE_INVALID")
        return tuple(
            _ScenarioSourceRecordInput(
                owner_class=row.owner_class,
                owner_schema_ref=row.owner_schema_ref,
                source_relative_path=row.source_relative_path,
                source_content_bytes=row.source_record_bytes,
                source_record_bytes=row.source_record_bytes,
                natural_identity=row.natural_identity,
                ordered_support_owner_sha256=row.ordered_support_owner_sha256,
                source_capability=row.source_owner,
            )
            for row in rows
        )
    except _ScenarioSourceOwnerManifestError:
        raise
    except Exception:
        _reject("PUBLIC_OPERATION_EVIDENCE_INVALID")


def _source_record_input_sha256(record: _ScenarioSourceRecordInput) -> str:
    try:
        source_record = strict_json_loads(record.source_record_bytes)
    except CanonicalizationError:
        _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
    if type(source_record) is not dict:
        _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
    return structured_sha256_hex(
        _RECORD_DOMAIN,
        {
            "owner_class": record.owner_class,
            "natural_identity": dict(record.natural_identity),
            "source_record": source_record,
        },
    )


def _build_scientific_meaning_source_boundary() -> tuple[
    Callable[
        [object, CapturedScientificRun, SealedScientificEvidence | None],
        tuple[_ScenarioSourceRecordInput, ...],
    ],
    Callable[[object], tuple[_ScenarioSourceRecordInput, ...]],
    Callable[[object], tuple[AuthenticatedScenarioCaseBatch, CapturedScientificRun]],
]:
    """Build one opaque exact-owner path for fit bindings and canonical science."""

    @final
    class ScientificMeaningSource:
        __slots__ = ("batch", "captured")
        batch: object
        captured: CapturedScientificRun

        def __new__(cls, *_args: object, **_kwargs: object) -> ScientificMeaningSource:
            raise TypeError("Scientific meaning sources are privately issued.")

        def __init_subclass__(cls, **_kwargs: object) -> Never:
            raise TypeError("Scientific meaning sources cannot be subclassed.")

        def __setattr__(self, _name: str, _value: object) -> Never:
            raise AttributeError("Scientific meaning sources are immutable.")

        def __copy__(self) -> Never:
            raise TypeError("Scientific meaning sources cannot be copied or serialized.")

        def __deepcopy__(self, _memo: object) -> Never:
            raise TypeError("Scientific meaning sources cannot be copied or serialized.")

        def __reduce__(self) -> Never:
            raise TypeError("Scientific meaning sources cannot be copied or serialized.")

        def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
            raise TypeError("Scientific meaning sources cannot be copied or serialized.")

        def __getstate__(self) -> Never:
            raise TypeError("Scientific meaning sources cannot be copied or serialized.")

    def owners(
        value: object,
    ) -> tuple[AuthenticatedScenarioCaseBatch, CapturedScientificRun]:
        from ebm_audit.evaluator.scenario_case_batch import (
            AuthenticatedScenarioCaseBatch,
            _read_authenticated_batch_context,
        )

        if type(value) is not ScientificMeaningSource:
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        source = value
        batch = source.batch
        captured = source.captured
        if (
            type(batch) is not AuthenticatedScenarioCaseBatch
            or type(captured) is not CapturedScientificRun
        ):
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        try:
            batch_context = _read_authenticated_batch_context(batch)
            captured_state = _read_captured_scientific_run(captured)
            case_binding = strict_json_loads(captured_state.synthetic_case_binding_bytes or b"")
        except Exception:
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        if (
            type(case_binding) is not dict
            or set(case_binding)
            != {
                "case_id",
                "source_contract_sha256",
                "scenario_definitions_sha256",
            }
            or sum(
                case.case_id == case_binding.get("case_id")
                and case.source_contract_sha256 == case_binding.get("source_contract_sha256")
                and case.scenario_source_sha256 == case_binding.get("scenario_definitions_sha256")
                for case in batch_context.cases
            )
            != 1
        ):
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        return batch, captured

    def records(value: object) -> tuple[_ScenarioSourceRecordInput, ...]:
        active = _active_scientific_meaning_source_bundle(value)
        if active is not None:
            return active.records
        batch, captured = owners(value)
        from ebm_audit.evaluator.scenario_case_batch import (
            _read_authenticated_batch_context,
        )

        try:
            batch_context = _read_authenticated_batch_context(batch)
            captured_state = _read_captured_scientific_run(captured)
        except Exception:
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        baseline = tuple(
            candidate
            for candidate in captured_state.candidates
            if candidate.analysis_spec_id == captured_state.baseline_analysis_spec_id
        )
        if len(baseline) != 1:
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        candidate = baseline[0]
        if candidate.final_status not in {"SUCCESS", "CONVERGENCE_WARN"}:
            return ()
        if (
            type(candidate.universe_id) is not str
            or not candidate.universe_id
            or candidate.planned_chain_count < 1
            or candidate.planned_chain_count != candidate.finalized_terminal_chain_count
            or candidate.planned_chain_count != candidate.authenticated_available_chain_count
            or candidate.planned_chain_count != len(candidate.chains)
            or candidate.convergence_record_bytes is None
        ):
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        chains = tuple(sorted(candidate.chains, key=lambda chain: chain.chain_plan_position))
        if tuple(chain.chain_plan_position for chain in chains) != tuple(range(len(chains))):
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")

        fit_records: list[_ScenarioSourceRecordInput] = []
        canonical_chains: list[dict[str, object]] = []
        for chain in chains:
            try:
                readback = _readback_authenticated_execution(chain.execution)
                response = readback.response
                command_evidence = readback.command_evidence
                payload = response["payload"]
                result = payload["result"] if type(payload) is dict else None
                files = response["files"]
                if (
                    readback.execution is not chain.execution
                    or readback.execution_evidence_digest != chain.execution_evidence_digest
                    or canonical_json_bytes(response) != chain.response_bytes
                    or type(command_evidence) is not dict
                    or command_evidence.get("command") != "fit"
                    or command_evidence.get("status") != "SUCCESS"
                    or command_evidence.get("payload_digest_kind") != "WORKER_FIT_PAYLOAD"
                    or type(result) is not dict
                    or command_evidence.get("payload_digest")
                    != result.get("worker_fit_payload_digest")
                    or type(files) is not dict
                ):
                    _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
                binding = {
                    "binding_schema_version": ("ebm-audit-evaluator-worker-response-binding/2.0"),
                    **{
                        field: copy.deepcopy(response[field])
                        for field in _FIT_RESPONSE_BINDING_FIELDS
                    },
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
                validate_instance(
                    binding,
                    "evaluator-receipts.schema.json",
                    definition="FitSuccessEvaluatorWorkerResponseBinding",
                )
                binding_bytes = canonical_json_bytes(binding)
                binding_digest = structured_sha256_hex(
                    _FIT_RESPONSE_BINDING_DIGEST_DOMAIN,
                    binding,
                )
                fit_records.append(
                    _ScenarioSourceRecordInput(
                        owner_class=_FIT_RESPONSE_BINDING_OWNER_CLASS,
                        owner_schema_ref=_OWNER_BINDINGS[_FIT_RESPONSE_BINDING_OWNER_CLASS][0],
                        source_relative_path=(
                            f"owners/41-fit-response-binding/{chain.chain_plan_position:08d}.json"
                        ),
                        source_content_bytes=binding_bytes,
                        source_record_bytes=binding_bytes,
                        natural_identity={
                            field: binding[field]
                            for field in _OWNER_BINDINGS[_FIT_RESPONSE_BINDING_OWNER_CLASS][1]
                        },
                        source_capability=value,
                    )
                )

                chain_payload = strict_json_loads(chain.chain_payload_bytes)
                validate_instance(
                    chain_payload,
                    "canonical-records.schema.json",
                    definition="FinalChainScientificPayload",
                )
                if (
                    type(chain_payload) is not dict
                    or canonical_json_bytes(chain_payload) != chain.chain_payload_bytes
                    or chain_payload.get("chain_payload_digest") != chain.chain_payload_digest
                    or chain_payload.get("chain_plan_position") != chain.chain_plan_position
                    or chain_payload.get("chain_execution_id") != chain.chain_execution_id
                    or chain_payload.get("final_attempt_id") != chain.final_attempt_id
                    or chain_payload.get("retained_state_count") != chain.retained_state_count
                    or chain_payload.get("central_order_event_ids")
                    != list(chain.central_order_event_ids)
                    or canonical_json_bytes(chain_payload.get("central_order_method"))
                    != chain.central_order_method_bytes
                ):
                    _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
                canonical_chain = copy.deepcopy(chain_payload)
                canonical_chain["attempt_id"] = canonical_chain.pop("final_attempt_id")
                canonical_chain["fit_evaluator_worker_response_binding_sha256"] = binding_digest
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
                canonical_chains.append(cast(dict[str, object], canonical_chain))
            except _ScenarioSourceOwnerManifestError:
                raise
            except Exception:
                _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")

        try:
            convergence = strict_json_loads(candidate.convergence_record_bytes)
            if (
                type(convergence) is not dict
                or canonical_json_bytes(convergence) != candidate.convergence_record_bytes
                or convergence.get("assessment") != candidate.convergence_assessment
                or convergence.get("rule_set_version") != candidate.convergence_rule_set_version
            ):
                _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
            payload_record: dict[str, object] = {
                "scientific_payload_schema_version": ("ebm-audit-canonical-scientific-payload/1.0"),
                "benchmark_subject_digest": (batch_context.benchmark_subject_digest),
                "operation_instance_id": candidate.universe_id,
                "analysis_spec_id": candidate.analysis_spec_id,
                "universe_id": candidate.universe_id,
                "core_final_status": candidate.final_status,
                "event_ids": list(candidate.event_ids),
                "ordered_chain_payloads": canonical_chains,
                "convergence": convergence,
            }
            validate_instance(
                payload_record,
                "canonical-records.schema.json",
                definition="CanonicalScientificPayload",
            )
            payload_bytes = canonical_json_bytes(payload_record)
            analysis_record = _analysis_spec_source_records(captured)
            if len(analysis_record) != 1:
                _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
            support_digests = (
                _source_record_input_sha256(analysis_record[0]),
                *(_source_record_input_sha256(record) for record in fit_records),
            )
            payload_source = _ScenarioSourceRecordInput(
                owner_class=_CANONICAL_SCIENTIFIC_PAYLOAD_OWNER_CLASS,
                owner_schema_ref=_OWNER_BINDINGS[_CANONICAL_SCIENTIFIC_PAYLOAD_OWNER_CLASS][0],
                source_relative_path=("owners/42-canonical-scientific-payload/00000000.json"),
                source_content_bytes=payload_bytes,
                source_record_bytes=payload_bytes,
                natural_identity={
                    field: payload_record[field]
                    for field in _OWNER_BINDINGS[_CANONICAL_SCIENTIFIC_PAYLOAD_OWNER_CLASS][1]
                },
                ordered_support_owner_sha256=support_digests,
                source_capability=value,
            )
        except _ScenarioSourceOwnerManifestError:
            raise
        except Exception:
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        return (*fit_records, payload_source)

    def issue(
        batch: object,
        captured: CapturedScientificRun,
        sealed: SealedScientificEvidence | None = None,
    ) -> tuple[_ScenarioSourceRecordInput, ...]:
        if sealed is not None:
            try:
                sealed_state = _read_sealed_scientific_evidence(sealed)
            except Exception:
                _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
            if sealed_state.capture is not captured:
                _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        source = object.__new__(ScientificMeaningSource)
        object.__setattr__(source, "batch", batch)
        object.__setattr__(source, "captured", captured)
        return records(source)

    return issue, records, owners


(
    _conditional_scientific_meaning_source_records,
    _read_scientific_meaning_source_records,
    _read_scientific_meaning_source_owners,
) = _build_scientific_meaning_source_boundary()


def _scientific_source_input(
    record: _ScenarioSourceRecordInput | _StoredRecord,
) -> _ScenarioSourceRecordInput:
    if type(record) is _ScenarioSourceRecordInput:
        return record
    try:
        natural_identity = strict_json_loads(record.natural_identity_bytes)
    except CanonicalizationError:
        _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
    if type(natural_identity) is not dict:
        _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
    return _ScenarioSourceRecordInput(
        owner_class=record.owner_class,
        owner_schema_ref=record.owner_schema_ref,
        source_relative_path=record.source_relative_path,
        source_content_bytes=record.source_content_bytes,
        source_record_bytes=record.source_record_bytes,
        natural_identity=natural_identity,
        ordered_support_owner_sha256=record.ordered_support_owner_sha256,
        source_capability=record.source_capability,
    )


@contextmanager
def _scientific_meaning_source_owner_transaction(
    records: tuple[_ScenarioSourceRecordInput | _StoredRecord, ...],
) -> Iterator[None]:
    """Authenticate each scientific source owner once inside one transaction."""

    requested: list[tuple[object, tuple[_ScenarioSourceRecordInput, ...]]] = []
    for record in records:
        if record.owner_class not in {
            "ANALYSIS_SPEC",
            _FIT_RESPONSE_BINDING_OWNER_CLASS,
            _CANONICAL_SCIENTIFIC_PAYLOAD_OWNER_CLASS,
        }:
            continue
        owner = record.source_capability
        if owner is None:
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        source_input = _scientific_source_input(record)
        match = next(
            (index for index, (candidate, _rows) in enumerate(requested) if candidate is owner),
            None,
        )
        if match is None:
            requested.append((owner, (source_input,)))
        else:
            requested[match] = (owner, (*requested[match][1], source_input))
    if not requested:
        yield
        return
    if all(_active_scientific_meaning_source_bundle(owner) is not None for owner, _ in requested):
        yield
        return

    bundles: list[_ScientificMeaningSourceBundle] = []
    for owner, inputs in requested:
        active = _active_scientific_meaning_source_bundle(owner)
        if active is not None:
            bundles.append(active)
            continue
        expected = (
            _analysis_spec_source_records(owner)
            if inputs[0].owner_class == "ANALYSIS_SPEC"
            else _read_scientific_meaning_source_records(owner)
        )
        if any(record not in expected for record in inputs):
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
        bundles.append(_ScientificMeaningSourceBundle(owner=owner, records=expected))

    lease = _ScientificMeaningSourceTransactionLease(
        active=True,
        bundles=tuple(bundles),
    )
    token = _SCIENTIFIC_MEANING_SOURCE_TRANSACTION_LEASES.set(
        (*_SCIENTIFIC_MEANING_SOURCE_TRANSACTION_LEASES.get(), lease)
    )
    try:
        yield
    finally:
        lease.active = False
        lease.bundles = ()
        _SCIENTIFIC_MEANING_SOURCE_TRANSACTION_LEASES.reset(token)


def _source_record_readback(
    record: _StoredRecord,
) -> Callable[[object], tuple[_ScenarioSourceRecordInput, ...]]:
    exact_owner = record.source_capability
    if exact_owner is None:
        _reject("SOURCE_RECORD_CAPABILITY_INVALID")
    source_reader: Callable[[object], tuple[_ScenarioSourceRecordInput, ...]]
    if record.owner_class in {
        "RESOLVED_GENERATOR_CONFIGURATION",
        "RESOLVED_GENERATOR_MECHANISM",
        "COMPONENT_SEED_MANIFEST",
    }:
        source_reader = _resolved_case_source_records_from_batch
    elif record.owner_class == "ANALYSIS_SPEC":
        source_reader = _analysis_spec_source_records
    elif record.owner_class in {
        _FIT_RESPONSE_BINDING_OWNER_CLASS,
        _CANONICAL_SCIENTIFIC_PAYLOAD_OWNER_CLASS,
    }:
        source_reader = _read_scientific_meaning_source_records
    elif record.owner_class in _PUBLIC_OPERATION_EVIDENCE_OWNER_CLASSES:
        if (
            record.owner_class == _PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS
            and type(exact_owner) is PreparationAuditEvidence
        ):
            source_reader = cast(
                Callable[[object], tuple[_ScenarioSourceRecordInput, ...]],
                _preparation_audit_evidence_source_records,
            )
        else:
            source_reader = _public_operation_evidence_source_records
    else:
        _reject("SOURCE_RECORD_CAPABILITY_INVALID")

    def readback(owner: object) -> tuple[_ScenarioSourceRecordInput, ...]:
        if owner is not exact_owner:
            _reject("SOURCE_RECORD_CAPABILITY_INVALID")
        return source_reader(owner)

    return readback


def _store_record(record: _ScenarioSourceRecordInput) -> _StoredRecord:
    if type(record) is not _ScenarioSourceRecordInput:
        _reject("SOURCE_RECORD_INVALID")
    binding = _OWNER_BINDINGS.get(record.owner_class)
    if binding is None or record.owner_schema_ref != binding[0]:
        _reject("OWNER_TYPE_BINDING_INVALID")
    if (
        record.owner_class not in _CURRENT_GENUINE_OWNER_CLASSES
        or record.owner_class in _FORCED_UNAVAILABLE_OWNER_CLASSES
    ):
        _reject("SOURCE_RECORD_INVALID")
    if record.owner_class == _PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS:
        from ebm_audit.evaluator.public_operation_evidence import PublicOperationEvidence

        if type(record.source_capability) is PublicOperationEvidence:
            if record not in _public_operation_evidence_source_records(
                record.source_capability
            ):
                _reject("PUBLIC_OPERATION_EVIDENCE_INVALID")
        elif type(record.source_capability) is PreparationAuditEvidence:
            if record not in _preparation_audit_evidence_source_records(
                record.source_capability
            ):
                _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
        else:
            _reject("PREPARATION_AUDIT_EVIDENCE_INVALID")
    elif record.owner_class in (
        _PUBLIC_OPERATION_EVIDENCE_OWNER_CLASSES
        - {_PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS}
    ):
        if record not in _public_operation_evidence_source_records(record.source_capability):
            _reject("PUBLIC_OPERATION_EVIDENCE_INVALID")
    elif record.owner_class == _SYNTHETIC_TRUTH_OWNER_CLASS:
        if record != _synthetic_truth_source_record(
            cast(SyntheticTruthScoringEvidence, record.source_capability),
            bind=False,
        ):
            _reject("SYNTHETIC_TRUTH_INVALID")
    elif record.owner_class == _SYNTHETIC_SCIENTIFIC_DATA_OWNER_CLASS:
        if record != _synthetic_scientific_data_source_record(
            cast(SyntheticScientificDataEvidence, record.source_capability),
            bind=False,
        ):
            _reject("SYNTHETIC_SCIENTIFIC_DATA_INVALID")
    elif record.owner_class in {
        "RESOLVED_GENERATOR_CONFIGURATION",
        "RESOLVED_GENERATOR_MECHANISM",
        "COMPONENT_SEED_MANIFEST",
    }:
        if record not in _resolved_case_source_records_from_batch(record.source_capability):
            _reject("RESOLVED_CASE_SOURCE_OWNER_INVALID")
    elif record.owner_class == "ANALYSIS_SPEC":
        if record not in _analysis_spec_source_records(record.source_capability):
            _reject("ANALYSIS_SPEC_SOURCE_OWNER_INVALID")
    elif record.owner_class in {
        _FIT_RESPONSE_BINDING_OWNER_CLASS,
        _CANONICAL_SCIENTIFIC_PAYLOAD_OWNER_CLASS,
    }:
        if record not in _read_scientific_meaning_source_records(record.source_capability):
            _reject("SCIENTIFIC_MEANING_SOURCE_INVALID")
    elif record.owner_class == _SCENARIO_MATCHED_METRIC_RECORD_OWNER_CLASS:
        from ebm_audit.evaluator.scenario_derivation_matched_metric import (
            _scenario_matched_metric_source_record,
        )

        try:
            expected_record = _scenario_matched_metric_source_record(record.source_capability)
        except Exception:
            _reject("SCENARIO_MATCHED_METRIC_RECORD_INVALID")
        if record != expected_record:
            _reject("SCENARIO_MATCHED_METRIC_RECORD_INVALID")
    elif record.owner_class == _CANDIDATE_STRONG_EVIDENCE_DECISION_OWNER_CLASS:
        from ebm_audit.evaluator.candidate_decision import (
            _candidate_strong_evidence_decision_source_record,
        )

        try:
            expected_record = _candidate_strong_evidence_decision_source_record(
                record.source_capability,
                bind=False,
            )
        except Exception:
            _reject("CANDIDATE_STRONG_EVIDENCE_DECISION_INVALID")
        if record != expected_record:
            _reject("CANDIDATE_STRONG_EVIDENCE_DECISION_INVALID")
    elif record.owner_class == _PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION_OWNER_CLASS:
        try:
            from ebm_audit.evaluator.scenario_derivation_precedence import (
                _pairwise_precedence_source_record,
            )

            expected_record = _pairwise_precedence_source_record(record.source_capability)
        except Exception:
            from ebm_audit.evaluator.scenario_derivation_matched_metric import (
                _private_canonical_array_value_source_record,
            )

            try:
                expected_record = _private_canonical_array_value_source_record(
                    record.source_capability
                )
            except Exception:
                _reject("PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION_INVALID")
        if record != expected_record:
            _reject("PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION_INVALID")
    else:
        _reject("SOURCE_RECORD_INVALID")
    try:
        source_path = validate_relative_posix_path(record.source_relative_path)
        source_record = strict_json_loads(record.source_record_bytes)
    except (CanonicalizationError, PathBoundaryError):
        _reject("SOURCE_RECORD_INVALID")
    if (
        type(record.source_content_bytes) is not bytes
        or type(record.source_record_bytes) is not bytes
        or type(source_record) is not dict
        or canonical_json_bytes(source_record) != record.source_record_bytes
        or type(record.natural_identity) is not dict
        or set(record.natural_identity) != set(binding[1])
        or any(not _identity_value_valid(value) for value in record.natural_identity.values())
        or any(source_record.get(field) != record.natural_identity[field] for field in binding[1])
        or type(record.ordered_support_owner_sha256) is not tuple
        or any(not _is_sha256(value) for value in record.ordered_support_owner_sha256)
        or len(set(record.ordered_support_owner_sha256)) != len(record.ordered_support_owner_sha256)
    ):
        _reject("SOURCE_RECORD_INVALID")
    _validate_record_schema(binding[0], source_record)
    return _StoredRecord(
        owner_class=record.owner_class,
        owner_schema_ref=record.owner_schema_ref,
        source_relative_path=source_path,
        source_content_bytes=bytes(record.source_content_bytes),
        source_record_bytes=bytes(record.source_record_bytes),
        natural_identity_bytes=canonical_json_bytes(dict(record.natural_identity)),
        ordered_support_owner_sha256=tuple(record.ordered_support_owner_sha256),
        source_capability=record.source_capability,
    )


def _record_projection(record: _StoredRecord) -> dict[str, object]:
    try:
        source_record = strict_json_loads(record.source_record_bytes)
        natural_identity = strict_json_loads(record.natural_identity_bytes)
    except CanonicalizationError:
        _reject("SOURCE_RECORD_INVALID")
    rebuilt = _store_record(
        _ScenarioSourceRecordInput(
            owner_class=record.owner_class,
            owner_schema_ref=record.owner_schema_ref,
            source_relative_path=record.source_relative_path,
            source_content_bytes=record.source_content_bytes,
            source_record_bytes=record.source_record_bytes,
            natural_identity=cast(dict[str, object], natural_identity),
            ordered_support_owner_sha256=record.ordered_support_owner_sha256,
            source_capability=record.source_capability,
        )
    )
    if rebuilt != record:
        _reject("SOURCE_RECORD_INVALID")
    record_preimage = {
        "owner_class": record.owner_class,
        "natural_identity": natural_identity,
        "source_record": source_record,
    }
    return {
        "owner_class": record.owner_class,
        "owner_schema_ref": record.owner_schema_ref,
        "source_relative_path": record.source_relative_path,
        "source_content_sha256": hashlib.sha256(record.source_content_bytes).hexdigest(),
        "source_record_sha256": structured_sha256_hex(_RECORD_DOMAIN, record_preimage),
        "natural_identity": natural_identity,
        "ordered_support_owner_sha256": list(record.ordered_support_owner_sha256),
    }


def _freeze_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    def freeze(item: object) -> object:
        if type(item) is dict:
            return MappingProxyType({key: freeze(child) for key, child in item.items()})
        if type(item) is list:
            return tuple(freeze(child) for child in item)
        return item

    return MappingProxyType({key: freeze(item) for key, item in value.items()})


def _case_projection_records(
    records: tuple[_StoredRecord, ...],
    family_id: str,
    case_id: str,
    *,
    required_scientific_data_identities: tuple[tuple[str, str], ...] = (),
) -> tuple[_StoredRecord, ...]:
    if (
        type(family_id) is not str
        or not family_id
        or type(case_id) is not str
        or not case_id
        or type(required_scientific_data_identities) is not tuple
        or any(
            type(identity) is not tuple
            or len(identity) != 2
            or any(type(value) is not str or not value for value in identity)
            for identity in required_scientific_data_identities
        )
        or len(set(required_scientific_data_identities)) != len(required_scientific_data_identities)
    ):
        _reject("PROJECTION_BINDING_INVALID")
    references = _owner_references(records)
    digests = [cast(str, reference["source_record_sha256"]) for reference in references]
    positions = {digest: index for index, digest in enumerate(digests)}
    selected: set[int] = set()
    exact_coordinate_found = False
    correlated_truth_coordinates: list[tuple[int, str]] = []
    for index, reference in enumerate(references):
        identity = cast(dict[str, object], reference["natural_identity"])
        record_family = identity.get("family_id", identity.get("scenario_family_id"))
        record_case = identity.get("case_id")
        if reference["owner_class"] == _SYNTHETIC_TRUTH_OWNER_CLASS:
            try:
                source_record = strict_json_loads(records[index].source_record_bytes)
                scenario_identity = cast(dict[str, object], source_record)["scenario_identity"]
                if type(scenario_identity) is not dict:
                    _reject("SOURCE_RECORD_INVALID")
                record_family = scenario_identity.get("family_id")
                record_case = scenario_identity.get("case_id")
            except (CanonicalizationError, KeyError, TypeError):
                _reject("SOURCE_RECORD_INVALID")
            if family_id == "correlated_duplicate_events" and record_family == family_id:
                if type(record_case) is not str or not record_case:
                    _reject("PROJECTION_BINDING_INVALID")
                correlated_truth_coordinates.append((index, record_case))
        if record_family == family_id and record_case == case_id:
            exact_coordinate_found = True
        if (
            (
                family_id == "correlated_duplicate_events"
                and reference["owner_class"] == _SYNTHETIC_TRUTH_OWNER_CLASS
                and record_family == family_id
            )
            or (record_family is None and record_case is None)
            or (
                (record_family is None or record_family == family_id)
                and (record_case is None or record_case == case_id)
            )
        ):
            selected.add(index)
    for required_case_id, required_digest in required_scientific_data_identities:
        matches = tuple(
            index
            for index, reference in enumerate(references)
            if reference["owner_class"] == _SYNTHETIC_SCIENTIFIC_DATA_OWNER_CLASS
            and reference["natural_identity"]
            == {
                "case_id": required_case_id,
                "generated_scientific_data_sha256": required_digest,
            }
        )
        if len(matches) != 1:
            _reject("PROJECTION_BINDING_INVALID")
        selected.add(matches[0])
    if not exact_coordinate_found or (
        family_id == "correlated_duplicate_events"
        and (
            len(correlated_truth_coordinates) != 2
            or len({case for _index, case in correlated_truth_coordinates}) != 2
            or case_id not in {case for _index, case in correlated_truth_coordinates}
        )
    ):
        _reject("PROJECTION_BINDING_INVALID")
    pending = list(selected)
    while pending:
        index = pending.pop()
        supports = cast(list[str], references[index]["ordered_support_owner_sha256"])
        for digest in supports:
            support_index = positions[digest]
            if support_index not in selected:
                selected.add(support_index)
                pending.append(support_index)
    projected = tuple(record for index, record in enumerate(records) if index in selected)
    _owner_references(projected)
    return projected


def _required_missingness_record_identities(
    records: tuple[_StoredRecord, ...],
    ordered_role_identities: (tuple[tuple[str, str, str], tuple[str, str, str]] | None),
) -> tuple[tuple[str, str], ...]:
    if ordered_role_identities is None:
        return ()
    source_role, transformed_role = ordered_role_identities
    if source_role[0] != "source" or transformed_role[0] != "transformed":
        _reject("PROJECTION_BINDING_INVALID")
    manifest_identities: set[tuple[str, str]] = set()
    for reference in _owner_references(records):
        if reference["owner_class"] != _SYNTHETIC_SCIENTIFIC_DATA_OWNER_CLASS:
            continue
        natural_identity = cast(dict[str, object], reference["natural_identity"])
        manifest_identities.add(
            (
                cast(str, natural_identity["case_id"]),
                cast(str, natural_identity["generated_scientific_data_sha256"]),
            )
        )
    source_identity = source_role[1:]
    transformed_identity = transformed_role[1:]
    required = tuple(
        identity
        for identity in (source_identity, transformed_identity)
        if identity in manifest_identities
    )
    if required not in {
        (transformed_identity,),
        (source_identity, transformed_identity),
    }:
        _reject("PROJECTION_BINDING_INVALID")
    return required


def _owner_record(record: _StoredRecord) -> _ScenarioSourceOwnerRecord:
    reference = _record_projection(record)
    source_record = strict_json_loads(record.source_record_bytes)
    natural_identity = strict_json_loads(record.natural_identity_bytes)
    if type(source_record) is not dict or type(natural_identity) is not dict:
        _reject("SOURCE_RECORD_INVALID")
    capability = record.source_capability
    wrap_authenticated = record.owner_class in {
        "RESOLVED_GENERATOR_CONFIGURATION",
        "RESOLVED_GENERATOR_MECHANISM",
        "COMPONENT_SEED_MANIFEST",
        "ANALYSIS_SPEC",
        _FIT_RESPONSE_BINDING_OWNER_CLASS,
        _CANONICAL_SCIENTIFIC_PAYLOAD_OWNER_CLASS,
        "PUBLIC_BATCH_CASE_PLAN",
        "PROPORTIONAL_OPERATION_PLAN",
        "PUBLIC_TERMINAL_RESULT",
        "PREPROCESSING_EXECUTION_RECORD",
        "EXECUTED_TRANSFORMATION_EVIDENCE",
        "REFERENCE_FIT_GROUP_ROLE_EVIDENCE",
        "EXECUTED_BOUNDARY_RULE_IDENTITY",
        "CASE_INFLUENCE_AGGREGATE",
    }
    if record.owner_class in {
        _PREPARATION_AUDIT_EVIDENCE_OWNER_CLASS,
        _PREPARATION_ROW_INSTANCE_MANIFEST_OWNER_CLASS,
    }:
        from ebm_audit.evaluator.public_operation_evidence import PublicOperationEvidence

        wrap_authenticated = type(capability) is PublicOperationEvidence
    if wrap_authenticated:
        if capability is None:
            _reject("SOURCE_RECORD_CAPABILITY_INVALID")
        authenticated = object.__new__(_AuthenticatedSourceOwnerRecordCapability)
        _AUTHENTICATED_SOURCE_OWNER_RECORD_STATE_ISSUER.bind_once(
            authenticated,
            _AuthenticatedSourceOwnerRecordState(
                owner_class=record.owner_class,
                owner_schema_ref=record.owner_schema_ref,
                natural_identity_bytes=record.natural_identity_bytes,
                source_record_bytes=record.source_record_bytes,
                source_record_sha256=cast(str, reference["source_record_sha256"]),
                source_owner=capability,
                readback=_source_record_readback(record),
            ),
        )
        capability = authenticated
    return _ScenarioSourceOwnerRecord(
        owner_class=record.owner_class,
        owner_schema_ref=record.owner_schema_ref,
        natural_identity=_freeze_mapping(natural_identity),
        source_record=_freeze_mapping(source_record),
        source_record_sha256=cast(str, reference["source_record_sha256"]),
        ordered_support_owner_sha256=record.ordered_support_owner_sha256,
        source_capability=capability,
    )


def _read_authenticated_source_owner_record(
    record: _ScenarioSourceOwnerRecord,
) -> Mapping[str, object]:
    """Read one exact record issued by the authenticated manifest boundary."""

    if (
        type(record) is not _ScenarioSourceOwnerRecord
        or type(record.source_capability) is not _AuthenticatedSourceOwnerRecordCapability
    ):
        _reject("SOURCE_RECORD_CAPABILITY_INVALID")

    def thaw(value: object) -> object:
        if isinstance(value, Mapping):
            return {key: thaw(child) for key, child in value.items()}
        if type(value) is tuple:
            return [thaw(child) for child in value]
        return value

    try:
        state = _AUTHENTICATED_SOURCE_OWNER_RECORD_STATES.read(record.source_capability)
        natural_identity = cast(dict[str, object], thaw(record.natural_identity))
        source_record = cast(dict[str, object], thaw(record.source_record))
        natural_identity_bytes = canonical_json_bytes(natural_identity)
        source_record_bytes = canonical_json_bytes(source_record)
    except (OneShotRegistryError, CanonicalizationError, TypeError, ValueError):
        _reject("SOURCE_RECORD_CAPABILITY_INVALID")
    if (
        state.owner_class != record.owner_class
        or state.owner_schema_ref != record.owner_schema_ref
        or state.natural_identity_bytes != natural_identity_bytes
        or state.source_record_bytes != source_record_bytes
        or state.source_record_sha256 != record.source_record_sha256
        or record.source_record_sha256
        != structured_sha256_hex(
            _RECORD_DOMAIN,
            {
                "owner_class": record.owner_class,
                "natural_identity": natural_identity,
                "source_record": source_record,
            },
        )
    ):
        _reject("SOURCE_RECORD_CAPABILITY_INVALID")
    try:
        candidates = state.readback(state.source_owner)
    except Exception:
        _reject("SOURCE_RECORD_CAPABILITY_INVALID")
    matching = 0
    for candidate in candidates:
        try:
            candidate_record = strict_json_loads(candidate.source_record_bytes)
        except CanonicalizationError:
            _reject("SOURCE_RECORD_CAPABILITY_INVALID")
        if (
            candidate.owner_class == record.owner_class
            and candidate.owner_schema_ref == record.owner_schema_ref
            and dict(candidate.natural_identity) == natural_identity
            and candidate_record == source_record
            and candidate.ordered_support_owner_sha256 == record.ordered_support_owner_sha256
            and candidate.source_capability is state.source_owner
        ):
            matching += 1
    if matching != 1:
        _reject("SOURCE_RECORD_CAPABILITY_INVALID")
    return MappingProxyType(source_record)


def _read_authenticated_source_owner_source(
    record: _ScenarioSourceOwnerRecord,
) -> object:
    """Return the exact retained owner after full source-record readback."""

    _read_authenticated_source_owner_record(record)
    try:
        return _AUTHENTICATED_SOURCE_OWNER_RECORD_STATES.read(
            cast(_AuthenticatedSourceOwnerRecordCapability, record.source_capability)
        ).source_owner
    except OneShotRegistryError:
        _reject("SOURCE_RECORD_CAPABILITY_INVALID")


def _owner_references(records: tuple[_StoredRecord, ...]) -> list[dict[str, object]]:
    if not records:
        _reject("SOURCE_RECORDS_EMPTY")
    references = [_record_projection(record) for record in records]
    paths = [cast(str, row["source_relative_path"]) for row in references]
    digests = [cast(str, row["source_record_sha256"]) for row in references]
    identities = [
        canonical_json_bytes([row["owner_class"], row["natural_identity"]]) for row in references
    ]
    if (
        len(set(paths)) != len(paths)
        or len(set(digests)) != len(digests)
        or len(set(identities)) != len(identities)
    ):
        _reject("SOURCE_RECORD_ORDER_INVALID")
    positions = {digest: index for index, digest in enumerate(digests)}
    for index, row in enumerate(references):
        supports = cast(list[str], row["ordered_support_owner_sha256"])
        try:
            support_positions = [positions[digest] for digest in supports]
        except KeyError:
            _reject("SUPPORT_OWNER_INVALID")
        if support_positions != sorted(support_positions) or any(
            position >= index for position in support_positions
        ):
            _reject("SUPPORT_OWNER_ORDER_INVALID")
    return references


def _manifest_projection(
    *,
    evaluation_phase: str,
    benchmark_subject_digest: str,
    operation_plan_sha256: str,
    records: tuple[_StoredRecord, ...],
) -> dict[str, object]:
    if (
        evaluation_phase not in _PHASES
        or not _is_sha256(benchmark_subject_digest, prefixed=True)
        or not _is_sha256(operation_plan_sha256)
    ):
        _reject("MANIFEST_BINDING_INVALID")
    preimage: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "digest_state": "DIGEST_PREIMAGE",
        "evaluation_phase": evaluation_phase,
        "benchmark_subject_digest": benchmark_subject_digest,
        "operation_plan_sha256": operation_plan_sha256,
        "ordered_owner_references": _owner_references(records),
        "scenario_source_owner_manifest_sha256": None,
    }
    digest = structured_sha256_hex(_MANIFEST_DOMAIN, preimage)
    preimage["digest_state"] = "PERSISTED"
    preimage["scenario_source_owner_manifest_sha256"] = digest
    return preimage


def _authentication_tag(key: bytes, manifest_bytes: bytes) -> str:
    return hmac.new(
        key,
        _AUTHENTICATION_DOMAIN.encode("ascii") + b"\0" + manifest_bytes,
        hashlib.sha256,
    ).hexdigest()


def _projection_bytes(
    *,
    evaluation_phase: str,
    benchmark_subject_digest: str,
    operation_plan_sha256: str,
    family_id: str,
    case_id: str,
    records: tuple[_StoredRecord, ...],
    missingness_pair: (
        tuple[_SyntheticMissingnessProjection, _SyntheticMissingnessProjection] | None
    ),
) -> bytes:
    binding = {
        "evaluation_phase": evaluation_phase,
        "benchmark_subject_digest": benchmark_subject_digest,
        "operation_plan_sha256": operation_plan_sha256,
        "family_id": family_id,
        "case_id": case_id,
    }
    projection: dict[str, object] = {
        "binding": binding,
        "ordered_owner_records": [_record_projection(record) for record in records],
    }
    if missingness_pair is not None:
        projection["ordered_missingness_roles"] = [
            {
                "role": role,
                "case_id": value.case_id,
                "generated_scientific_data_sha256": (value.generated_scientific_data_sha256),
                "dimensions": list(value.dimensions),
                "participant_internal_indexes": list(value.participant_internal_indexes),
                "event_ids": list(value.event_ids),
                "analysis_group_labels": list(value.analysis_group_labels),
                "missingness_mask": [list(row) for row in value.missingness_mask],
            }
            for role, value in zip(("source", "transformed"), missingness_pair, strict=True)
        ]
    return canonical_json_bytes(projection)


_IssueCaseSourceOwnerProjection = Callable[
    [
        object,
        _AuthenticatedScenarioSourceOwnerManifest,
        tuple[DirectOperationPlanEntry, ...],
        str,
        str,
    ],
    _AuthenticatedScenarioSourceOwnerProjection,
]
_ReadCaseSourceOwnerProjection = Callable[
    [object, _AuthenticatedScenarioSourceOwnerProjection, tuple[DirectOperationPlanEntry, ...]],
    tuple[_ScenarioSourceOwnerRecord, ...],
]
_ReadCaseSourceOwnerIdentityProjection = Callable[
    [object, _AuthenticatedScenarioSourceOwnerProjection, tuple[DirectOperationPlanEntry, ...]],
    tuple[tuple[str, Mapping[str, object]], ...],
]
_ReadCaseSourceOwnerMissingnessProjection = Callable[
    [object, _AuthenticatedScenarioSourceOwnerProjection],
    tuple[_SyntheticMissingnessProjection, _SyntheticMissingnessProjection],
]
_CASE_SOURCE_OWNER_PROJECTION_BOUNDARIES: dict[
    type[object],
    tuple[
        _IssueCaseSourceOwnerProjection,
        _ReadCaseSourceOwnerProjection,
        _ReadCaseSourceOwnerIdentityProjection,
        _ReadCaseSourceOwnerMissingnessProjection,
    ],
] = {}


def _issue_case_source_owner_projection(
    context_owner: object,
    manifest: _AuthenticatedScenarioSourceOwnerManifest,
    plan: tuple[DirectOperationPlanEntry, ...],
    family_id: str,
    case_id: str,
) -> _AuthenticatedScenarioSourceOwnerProjection:
    boundary = _CASE_SOURCE_OWNER_PROJECTION_BOUNDARIES.get(type(context_owner))
    if boundary is None:
        _reject("MANIFEST_ISSUER_INVALID")
    return boundary[0](context_owner, manifest, plan, family_id, case_id)


def _read_case_source_owner_projection(
    context_owner: object,
    projection: _AuthenticatedScenarioSourceOwnerProjection,
    plan: tuple[DirectOperationPlanEntry, ...],
) -> tuple[_ScenarioSourceOwnerRecord, ...]:
    boundary = _CASE_SOURCE_OWNER_PROJECTION_BOUNDARIES.get(type(context_owner))
    if boundary is None:
        _reject("MANIFEST_ISSUER_INVALID")
    return boundary[1](context_owner, projection, plan)


def _read_case_source_owner_identity_projection(
    context_owner: object,
    projection: _AuthenticatedScenarioSourceOwnerProjection,
    plan: tuple[DirectOperationPlanEntry, ...],
) -> tuple[tuple[str, Mapping[str, object]], ...]:
    boundary = _CASE_SOURCE_OWNER_PROJECTION_BOUNDARIES.get(type(context_owner))
    if boundary is None:
        _reject("MANIFEST_ISSUER_INVALID")
    return boundary[2](context_owner, projection, plan)


def _read_case_source_owner_missingness_projection(
    context_owner: object,
    projection: _AuthenticatedScenarioSourceOwnerProjection,
) -> tuple[_SyntheticMissingnessProjection, _SyntheticMissingnessProjection]:
    boundary = _CASE_SOURCE_OWNER_PROJECTION_BOUNDARIES.get(type(context_owner))
    if boundary is None:
        _reject("MANIFEST_ISSUER_INVALID")
    return boundary[3](context_owner, projection)


def _claim_scenario_source_owner_manifest_boundary[T](
    *,
    owner_type: type[T],
    authenticated_context: Callable[[T], tuple[bytes, str]],
    authority_origin: Literal["HELDOUT", "PUBLIC_SYNTHETIC"] = "HELDOUT",
    missingness_pair: (
        Callable[
            [T, str, str, tuple[object, ...]],
            tuple[_SyntheticMissingnessProjection, _SyntheticMissingnessProjection] | None,
        ]
        | None
    ) = None,
) -> tuple[
    Callable[
        [
            T,
            Literal["DEVELOPMENT", "HELDOUT"],
            tuple[DirectOperationPlanEntry, ...],
            tuple[_ScenarioSourceRecordInput, ...],
        ],
        _AuthenticatedScenarioSourceOwnerManifest,
    ],
    Callable[
        [T, _AuthenticatedScenarioSourceOwnerManifest, tuple[DirectOperationPlanEntry, ...]],
        dict[str, object],
    ],
]:
    """Give one exact authenticated authority owner its issue/read capability."""

    module_name = owner_type.__module__
    module = sys.modules.get(module_name)
    module_path = getattr(module, "__file__", None)
    if authority_origin == "HELDOUT":
        expected_path = Path(__file__).resolve().parents[3] / "evaluator" / "run_benchmark.py"
        expected_owner_name = "_AuthenticatedHeldoutAttempt"
        expected_context_name = "_scenario_source_owner_manifest_context"
        expected_missingness_name = None
    elif authority_origin == "PUBLIC_SYNTHETIC":
        expected_path = Path(__file__).resolve().parent / "scenario_case_batch.py"
        expected_owner_name = "AuthenticatedScenarioCaseBatch"
        expected_context_name = "_public_synthetic_manifest_context"
        expected_missingness_name = "_bind_public_synthetic_missingness_pair"
    else:
        _reject("MANIFEST_ISSUER_INVALID")
    try:
        authentic = (
            type(module_path) is str
            and Path(module_path).resolve(strict=True) == expected_path
            and Path(authenticated_context.__code__.co_filename).resolve(strict=True)
            == expected_path
            and authenticated_context.__module__ == module_name
            and getattr(module, expected_owner_name, None) is owner_type
            and getattr(module, expected_context_name, None) is authenticated_context
            and (
                (expected_missingness_name is None and missingness_pair is None)
                or (
                    expected_missingness_name is not None
                    and missingness_pair is not None
                    and Path(missingness_pair.__code__.co_filename).resolve(strict=True)
                    == expected_path
                    and missingness_pair.__module__ == module_name
                    and getattr(module, expected_missingness_name, None) is missingness_pair
                )
            )
        )
    except (AttributeError, OSError, TypeError):
        authentic = False
    claimed_owner_type = cast(type[object], owner_type)
    with _ISSUER_CLAIM_LOCK:
        if not authentic or claimed_owner_type in _ISSUER_CLAIMS:
            _reject("MANIFEST_ISSUER_INVALID")
        _ISSUER_CLAIMS.add(claimed_owner_type)

    @dataclass(slots=True)
    class ProjectionState:
        authentication_key: bytes
        context_owner: T
        authority_origin: Literal["HELDOUT", "PUBLIC_SYNTHETIC"]
        evaluation_phase: Literal["DEVELOPMENT", "HELDOUT"]
        benchmark_subject_digest: str
        operation_plan_sha256: str
        family_id: str
        case_id: str
        records: tuple[_StoredRecord, ...]
        missingness_pair: (
            tuple[_SyntheticMissingnessProjection, _SyntheticMissingnessProjection] | None
        )
        ordered_missingness_role_identities: (
            tuple[tuple[str, str, str], tuple[str, str, str]] | None
        )
        projection_bytes: bytes
        authentication_tag: str
        consumed: bool
        identity_consumed: bool
        missingness_consumed: bool
        lock: RLock

    projection_states: OneShotWeakRegistry[
        _AuthenticatedScenarioSourceOwnerProjection, ProjectionState
    ]
    projection_states, projection_state_issuer = create_one_shot_registry()
    expected_phase: Literal["DEVELOPMENT", "HELDOUT"] = (
        "HELDOUT" if authority_origin == "HELDOUT" else "DEVELOPMENT"
    )

    def issue(
        context_owner: T,
        evaluation_phase: Literal["DEVELOPMENT", "HELDOUT"],
        plan: tuple[DirectOperationPlanEntry, ...],
        records: tuple[_ScenarioSourceRecordInput, ...],
    ) -> _AuthenticatedScenarioSourceOwnerManifest:
        if (
            type(context_owner) is not owner_type
            or type(records) is not tuple
            or evaluation_phase != expected_phase
        ):
            _reject("MANIFEST_CONTEXT_INVALID")
        authentication_key, subject_digest = authenticated_context(context_owner)
        if type(authentication_key) is not bytes or len(authentication_key) != 32:
            _reject("MANIFEST_CONTEXT_INVALID")
        with _preparation_source_owner_transaction(records):
            with _scientific_meaning_source_owner_transaction(records):
                stored_records = tuple(_store_record(record) for record in records)
                operation_plan_sha256 = _direct_operation_plan_digest(plan)
                projection = _manifest_projection(
                    evaluation_phase=evaluation_phase,
                    benchmark_subject_digest=subject_digest,
                    operation_plan_sha256=operation_plan_sha256,
                    records=stored_records,
                )
                manifest_bytes = canonical_json_bytes(projection)
        owner = object.__new__(_AuthenticatedScenarioSourceOwnerManifest)
        _MANIFEST_STATE_ISSUER.bind_once(
            owner,
            _ManifestState(
                authentication_key=bytes(authentication_key),
                context_owner=context_owner,
                authority_origin=authority_origin,
                evaluation_phase=evaluation_phase,
                benchmark_subject_digest=subject_digest,
                operation_plan_sha256=operation_plan_sha256,
                records=stored_records,
                manifest_bytes=manifest_bytes,
                authentication_tag=_authentication_tag(authentication_key, manifest_bytes),
                consumed=False,
                lock=RLock(),
            ),
        )
        return owner

    def consume_manifest(
        context_owner: T,
        manifest: _AuthenticatedScenarioSourceOwnerManifest,
        plan: tuple[DirectOperationPlanEntry, ...],
        *,
        projection_coordinate: tuple[str, str] | None = None,
    ) -> _ManifestState:
        if (
            type(context_owner) is not owner_type
            or type(manifest) is not _AuthenticatedScenarioSourceOwnerManifest
        ):
            _reject("MANIFEST_OWNER_INVALID")
        try:
            state = _MANIFEST_STATES.read(manifest)
        except OneShotRegistryError:
            _reject("MANIFEST_OWNER_INVALID")
        with state.lock:
            if state.consumed:
                _reject("MANIFEST_ALREADY_CONSUMED")
            state.consumed = True
            with _preparation_source_owner_transaction(state.records):
                with _scientific_meaning_source_owner_transaction(state.records):
                    if projection_coordinate is not None:
                        _case_projection_records(state.records, *projection_coordinate)
                    key, subject_digest = authenticated_context(context_owner)
                    expected = _manifest_projection(
                        evaluation_phase=state.evaluation_phase,
                        benchmark_subject_digest=state.benchmark_subject_digest,
                        operation_plan_sha256=state.operation_plan_sha256,
                        records=state.records,
                    )
                    if (
                        state.context_owner is not context_owner
                        or state.authority_origin != authority_origin
                        or state.evaluation_phase != expected_phase
                        or type(key) is not bytes
                        or len(key) != 32
                        or not hmac.compare_digest(state.authentication_key, key)
                        or not hmac.compare_digest(
                            state.benchmark_subject_digest, subject_digest
                        )
                        or not hmac.compare_digest(
                            state.operation_plan_sha256,
                            _direct_operation_plan_digest(plan),
                        )
                        or canonical_json_bytes(expected) != state.manifest_bytes
                        or not hmac.compare_digest(
                            state.authentication_tag,
                            _authentication_tag(key, state.manifest_bytes),
                        )
                    ):
                        _reject("MANIFEST_AUTHENTICATION_FAILED")
            return state

    def read(
        context_owner: T,
        manifest: _AuthenticatedScenarioSourceOwnerManifest,
        plan: tuple[DirectOperationPlanEntry, ...],
    ) -> dict[str, object]:
        state = consume_manifest(context_owner, manifest, plan)
        with state.lock:
            try:
                value = strict_json_loads(state.manifest_bytes)
            except CanonicalizationError:
                _reject("MANIFEST_AUTHENTICATION_FAILED")
            if type(value) is not dict:
                _reject("MANIFEST_AUTHENTICATION_FAILED")
            return copy.deepcopy(cast(dict[str, object], value))

    def issue_projection(
        context_owner: object,
        manifest: _AuthenticatedScenarioSourceOwnerManifest,
        plan: tuple[DirectOperationPlanEntry, ...],
        family_id: str,
        case_id: str,
    ) -> _AuthenticatedScenarioSourceOwnerProjection:
        if type(context_owner) is not owner_type:
            _reject("PROJECTION_OWNER_INVALID")
        if (
            type(family_id) is not str
            or not family_id
            or type(case_id) is not str
            or not case_id
            or not any(entry.family_id == family_id for entry in plan)
        ):
            _reject("PROJECTION_BINDING_INVALID")
        manifest_state = consume_manifest(
            context_owner,
            manifest,
            plan,
            projection_coordinate=(family_id, case_id),
        )
        projected_missingness_pair = None
        ordered_missingness_role_identities = None
        if missingness_pair is not None:
            evidence_owners = tuple(
                record.source_capability
                for record in manifest_state.records
                if record.owner_class == _SYNTHETIC_SCIENTIFIC_DATA_OWNER_CLASS
            )
            try:
                projected_missingness_pair = missingness_pair(
                    context_owner, family_id, case_id, evidence_owners
                )
            except (
                InvalidInputError,
                OneShotRegistryError,
                TypeError,
                UnexpectedCoreError,
            ):
                _reject("PROJECTION_BINDING_INVALID")
            if projected_missingness_pair is not None:
                if (
                    type(projected_missingness_pair) is not tuple
                    or len(projected_missingness_pair) != 2
                    or any(
                        type(value) is not _SyntheticMissingnessProjection
                        for value in projected_missingness_pair
                    )
                ):
                    _reject("PROJECTION_BINDING_INVALID")
                ordered_missingness_role_identities = cast(
                    tuple[tuple[str, str, str], tuple[str, str, str]],
                    tuple(
                        (role, value.case_id, value.generated_scientific_data_sha256)
                        for role, value in zip(
                            ("source", "transformed"),
                            projected_missingness_pair,
                            strict=True,
                        )
                    ),
                )
                if (
                    ordered_missingness_role_identities[0][1:]
                    == ordered_missingness_role_identities[1][1:]
                ):
                    _reject("PROJECTION_BINDING_INVALID")
        selected_records = _case_projection_records(
            manifest_state.records,
            family_id,
            case_id,
            required_scientific_data_identities=_required_missingness_record_identities(
                manifest_state.records,
                ordered_missingness_role_identities,
            ),
        )
        projection_bytes = _projection_bytes(
            evaluation_phase=manifest_state.evaluation_phase,
            benchmark_subject_digest=manifest_state.benchmark_subject_digest,
            operation_plan_sha256=manifest_state.operation_plan_sha256,
            family_id=family_id,
            case_id=case_id,
            records=selected_records,
            missingness_pair=projected_missingness_pair,
        )
        projection = object.__new__(_AuthenticatedScenarioSourceOwnerProjection)
        projection_state_issuer.bind_once(
            projection,
            ProjectionState(
                authentication_key=manifest_state.authentication_key,
                context_owner=context_owner,
                authority_origin=authority_origin,
                evaluation_phase=manifest_state.evaluation_phase,
                benchmark_subject_digest=manifest_state.benchmark_subject_digest,
                operation_plan_sha256=manifest_state.operation_plan_sha256,
                family_id=family_id,
                case_id=case_id,
                records=selected_records,
                missingness_pair=projected_missingness_pair,
                ordered_missingness_role_identities=ordered_missingness_role_identities,
                projection_bytes=projection_bytes,
                authentication_tag=_authentication_tag(
                    manifest_state.authentication_key,
                    _PROJECTION_AUTHENTICATION_DOMAIN.encode("ascii") + b"\0" + projection_bytes,
                ),
                consumed=False,
                identity_consumed=False,
                missingness_consumed=False,
                lock=RLock(),
            ),
        )
        return projection

    def authenticate_projection(
        context_owner: object,
        state: ProjectionState,
        plan: tuple[DirectOperationPlanEntry, ...] | None,
    ) -> tuple[_StoredRecord, ...]:
        key, subject_digest = authenticated_context(cast(T, context_owner))
        expected_bytes = _projection_bytes(
            evaluation_phase=state.evaluation_phase,
            benchmark_subject_digest=state.benchmark_subject_digest,
            operation_plan_sha256=state.operation_plan_sha256,
            family_id=state.family_id,
            case_id=state.case_id,
            records=state.records,
            missingness_pair=state.missingness_pair,
        )
        if (
            state.context_owner is not context_owner
            or state.authority_origin != authority_origin
            or state.evaluation_phase != expected_phase
            or type(key) is not bytes
            or len(key) != 32
            or not hmac.compare_digest(state.authentication_key, key)
            or not hmac.compare_digest(state.benchmark_subject_digest, subject_digest)
            or (
                plan is not None
                and not hmac.compare_digest(
                    state.operation_plan_sha256, _direct_operation_plan_digest(plan)
                )
            )
            or expected_bytes != state.projection_bytes
            or not hmac.compare_digest(
                state.authentication_tag,
                _authentication_tag(
                    key,
                    _PROJECTION_AUTHENTICATION_DOMAIN.encode("ascii")
                    + b"\0"
                    + state.projection_bytes,
                ),
            )
        ):
            _reject("PROJECTION_AUTHENTICATION_FAILED")
        selected_records = _case_projection_records(
            state.records,
            state.family_id,
            state.case_id,
            required_scientific_data_identities=_required_missingness_record_identities(
                state.records,
                state.ordered_missingness_role_identities,
            ),
        )
        if selected_records != state.records:
            _reject("PROJECTION_AUTHENTICATION_FAILED")
        expected_role_identities = (
            None
            if state.missingness_pair is None
            else cast(
                tuple[tuple[str, str, str], tuple[str, str, str]],
                tuple(
                    (role, value.case_id, value.generated_scientific_data_sha256)
                    for role, value in zip(
                        ("source", "transformed"), state.missingness_pair, strict=True
                    )
                ),
            )
        )
        if expected_role_identities != state.ordered_missingness_role_identities:
            _reject("PROJECTION_AUTHENTICATION_FAILED")
        return selected_records

    def read_projection(
        context_owner: object,
        projection: _AuthenticatedScenarioSourceOwnerProjection,
        plan: tuple[DirectOperationPlanEntry, ...],
    ) -> tuple[_ScenarioSourceOwnerRecord, ...]:
        if (
            type(context_owner) is not owner_type
            or type(projection) is not _AuthenticatedScenarioSourceOwnerProjection
        ):
            _reject("PROJECTION_OWNER_INVALID")
        try:
            state = projection_states.read(projection)
        except OneShotRegistryError:
            _reject("PROJECTION_OWNER_INVALID")
        with state.lock:
            if state.consumed:
                _reject("PROJECTION_ALREADY_CONSUMED")
            state.consumed = True
            selected_records = authenticate_projection(context_owner, state, plan)
            return tuple(_owner_record(record) for record in selected_records)

    def read_identity_projection(
        context_owner: object,
        projection: _AuthenticatedScenarioSourceOwnerProjection,
        plan: tuple[DirectOperationPlanEntry, ...],
    ) -> tuple[tuple[str, Mapping[str, object]], ...]:
        if (
            type(context_owner) is not owner_type
            or type(projection) is not _AuthenticatedScenarioSourceOwnerProjection
        ):
            _reject("PROJECTION_OWNER_INVALID")
        try:
            state = projection_states.read(projection)
        except OneShotRegistryError:
            _reject("PROJECTION_OWNER_INVALID")
        with state.lock:
            if state.consumed or state.identity_consumed:
                _reject("PROJECTION_ALREADY_CONSUMED")
            state.identity_consumed = True
            selected_records = authenticate_projection(context_owner, state, plan)
            identities: list[tuple[str, Mapping[str, object]]] = []
            for record in selected_records:
                try:
                    natural_identity = strict_json_loads(record.natural_identity_bytes)
                except CanonicalizationError:
                    _reject("SOURCE_RECORD_INVALID")
                if type(natural_identity) is not dict:
                    _reject("SOURCE_RECORD_INVALID")
                identities.append(
                    (
                        record.owner_class,
                        _freeze_mapping(natural_identity),
                    )
                )
            return tuple(identities)

    def read_missingness_projection(
        context_owner: object,
        projection: _AuthenticatedScenarioSourceOwnerProjection,
    ) -> tuple[_SyntheticMissingnessProjection, _SyntheticMissingnessProjection]:
        if (
            type(context_owner) is not owner_type
            or type(projection) is not _AuthenticatedScenarioSourceOwnerProjection
        ):
            _reject("PROJECTION_OWNER_INVALID")
        try:
            state = projection_states.read(projection)
        except OneShotRegistryError:
            _reject("PROJECTION_OWNER_INVALID")
        with state.lock:
            if state.consumed or state.missingness_consumed:
                _reject("PROJECTION_ALREADY_CONSUMED")
            state.missingness_consumed = True
            authenticate_projection(context_owner, state, None)
            if state.missingness_pair is None:
                _reject("PROJECTION_BINDING_INVALID")
            return state.missingness_pair

    if claimed_owner_type in _CASE_SOURCE_OWNER_PROJECTION_BOUNDARIES:
        _reject("MANIFEST_ISSUER_INVALID")
    _CASE_SOURCE_OWNER_PROJECTION_BOUNDARIES[claimed_owner_type] = (
        issue_projection,
        read_projection,
        read_identity_projection,
        read_missingness_projection,
    )

    return issue, read


__all__: list[str] = []
