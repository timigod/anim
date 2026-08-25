"""One opaque authenticated owner for an exact public-synthetic scenario graph."""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Final, Literal, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.evaluator.heldout_score import (
    DirectOperationPlanEntry,
    _direct_operation_plan_digest,
)
from ebm_audit.evaluator.scenario_case_batch import (
    AuthenticatedScenarioCaseBatch,
    _AuthenticatedCaseContext,
    _read_authenticated_batch_context,
)
from ebm_audit.evaluator.scenario_source_owner_manifest import (
    _CURRENT_GENUINE_OWNER_CLASSES,
    _FORCED_UNAVAILABLE_OWNER_CLASSES,
    _OWNER_BINDINGS,
    _PUBLIC_OPERATION_EVIDENCE_OWNER_CLASSES,
    _AuthenticatedScenarioSourceOwnerProjection,
    _AuthenticatedSourceOwnerRecordCapability,
    _owner_record,
    _preparation_audit_evidence_source_records,
    _preparation_row_instance_manifest_source_records,
    _PreparationRowInstanceManifestSource,
    _read_authenticated_source_owner_record,
    _read_authenticated_source_owner_source,
    _read_scientific_meaning_source_owners,
    _ScenarioSourceOwnerRecord,
    _ScenarioSourceRecordInput,
    _store_record,
    _synthetic_scientific_data_source_record,
    _synthetic_truth_source_record,
)
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256_hex,
)
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.science.capture import (
    CapturedScientificRun,
    PreparationAuditEvidence,
    PreparationRowInstanceManifests,
    SealedScientificEvidence,
    _issue_preparation_audit_evidence,
    _read_captured_scientific_run,
    _read_sealed_scientific_evidence,
    project_scientific_evidence,
)
from ebm_audit.synthetic.audit_input import (
    SealedPublicSyntheticAuditInput,
    SyntheticEvaluationTruthEvidence,
    SyntheticScientificDataEvidence,
    SyntheticTruthScoringEvidence,
    _read_public_synthetic_batch_input_owner,
    _resolve_public_synthetic_audit_input,
    _resolve_synthetic_evaluation_truth_evidence,
)

_COLLECTED_OPERATION_EVIDENCE_SCHEMA_VERSION: Final = "ebm-audit-collected-operation-evidence/1.0"
_COLLECTED_OPERATION_EVIDENCE_DOMAIN: Final = "ebm-audit/collected-operation-evidence/1"
_SOURCE_OWNER_REGISTRY_DOMAIN: Final = "ebm-audit/source-owner-registry/1"
_SCENARIO_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_PRIVATE_ARRAY_OWNER_CLASS: Final = "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION"
_ACTIVE_CONTEXT_READ: ContextVar[
    tuple[object, _ScenarioEvidenceContextState | _PublicSyntheticTruthContextState] | None
] = ContextVar("ebm_audit_active_scenario_context_read", default=None)
_SELF_DIGEST_BINDINGS: Final = MappingProxyType(
    {
        "SYNTHETIC_TRUTH": (
            "truth_object_sha256",
            "ebm-audit/synthetic-truth/1",
        ),
        "SYNTHETIC_SCIENTIFIC_DATA": (
            "generated_scientific_data_sha256",
            "ebm-audit/generated-scientific-data/1",
        ),
        "RESOLVED_GENERATOR_CONFIGURATION": (
            "resolved_generator_configuration_sha256",
            "ebm-audit/resolved-generator-configuration/1",
        ),
        "RESOLVED_GENERATOR_MECHANISM": (
            "resolved_generator_mechanism_sha256",
            "ebm-audit/resolved-generator-mechanism/1",
        ),
        "COMPONENT_SEED_MANIFEST": (
            "component_seed_manifest_sha256",
            "ebm-audit/component-seed-manifest/1",
        ),
        "MATCHED_COMPARATOR_EVIDENCE": (
            "matched_comparator_evidence_sha256",
            "ebm-audit/matched-comparator-evidence-manifest/1",
        ),
        "CANONICAL_ARRAY_ARTIFACT": (
            "canonical_array_artifact_owner_sha256",
            "ebm-audit/canonical-array-artifact-owner/1",
        ),
        "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION": (
            "private_canonical_array_value_projection_sha256",
            "ebm-audit/private-canonical-array-value-projection/1",
        ),
        "PREPARATION_AUDIT_EVIDENCE": (
            "preparation_audit_evidence_sha256",
            "ebm-audit/preparation-audit-evidence/2",
        ),
        "PREPROCESSING_EXECUTION_RECORD": (
            "preprocessing_execution_record_sha256",
            "ebm-audit/preprocessing-execution-record/3",
        ),
        "SCENARIO_MATCHED_METRIC_RECORD": (
            "scenario_matched_metric_record_sha256",
            "ebm-audit/scenario-matched-metric-record/2",
        ),
        "REPORT_PREDICATE_OUTCOME": (
            "report_predicate_outcome_sha256",
            "ebm-audit/report-predicate-outcome/1",
        ),
        "PREPARATION_ROW_INSTANCE_MANIFEST": (
            "row_instance_manifest_sha256",
            "ebm-audit/preparation-row-instance-manifest/2",
        ),
        "ANALYSIS_RULE_IDENTITY": (
            "analysis_rule_identity_sha256",
            "ebm-audit/analysis-rule-identity/1",
        ),
        "CASE_INFLUENCE_AGGREGATE": (
            "case_influence_aggregate_sha256",
            "ebm-audit/case-influence-aggregate/2",
        ),
        "PUBLIC_BATCH_CASE_PLAN": (
            "public_batch_case_plan_sha256",
            "ebm-audit/public-batch-case-plan/1",
        ),
        "PROPORTIONAL_OPERATION_PLAN": (
            "proportional_operation_plan_sha256",
            "ebm-audit/proportional-operation-plan/1",
        ),
        "PUBLIC_TERMINAL_RESULT": (
            "public_terminal_result_sha256",
            "ebm-audit/public-terminal-result/1",
        ),
        "EXECUTED_TRANSFORMATION_EVIDENCE": (
            "executed_transformation_evidence_sha256",
            "ebm-audit/executed-transformation-evidence/1",
        ),
        "REFERENCE_FIT_GROUP_ROLE_EVIDENCE": (
            "reference_fit_group_role_evidence_sha256",
            "ebm-audit/reference-fit-group-role-evidence/1",
        ),
        "EXECUTED_BOUNDARY_RULE_IDENTITY": (
            "executed_boundary_rule_identity_sha256",
            "ebm-audit/executed-boundary-rule-identity/1",
        ),
    }
)


class ScenarioEvidenceContextError(TypeError):
    """Raised when one retained scenario-evidence graph is absent or detached."""


class CollectedOperationEvidenceError(TypeError):
    """Raised when collected operation evidence is forged, detached, or replayed."""


def _reject() -> Never:
    raise ScenarioEvidenceContextError(
        "Authenticated scenario evidence context failed closed validation."
    )


def _reject_collection() -> Never:
    raise CollectedOperationEvidenceError("Collected operation evidence failed closed validation.")


@dataclass(frozen=True, slots=True)
class _ScenarioEvidenceIdentity:
    benchmark_subject_digest: str
    family_id: str
    case_id: str
    source_contract_sha256: str
    scenario_source_sha256: str
    input_owner_digest: str
    truth_evidence_digest: str
    scientific_evidence_digest: str
    evidence_graph_digest: str


@dataclass(frozen=True, slots=True)
class _ScenarioEvidenceContextState:
    batch: AuthenticatedScenarioCaseBatch
    input_owner: SealedPublicSyntheticAuditInput
    truth: SyntheticEvaluationTruthEvidence
    captured_science: CapturedScientificRun
    sealed_science: SealedScientificEvidence
    source_projection: _AuthenticatedScenarioSourceOwnerProjection
    case: _AuthenticatedCaseContext
    identity: _ScenarioEvidenceIdentity


@dataclass(frozen=True, slots=True)
class _PublicSyntheticTruthIdentity:
    benchmark_subject_digest: str
    family_id: str
    case_id: str
    source_contract_sha256: str
    scenario_source_sha256: str
    input_owner_digest: str


@dataclass(frozen=True, slots=True)
class _PublicSyntheticTruthContextState:
    batch: AuthenticatedScenarioCaseBatch
    input_owner: SealedPublicSyntheticAuditInput
    source_projection: _AuthenticatedScenarioSourceOwnerProjection
    operation_plan_sha256: str
    case: _AuthenticatedCaseContext
    identity: _PublicSyntheticTruthIdentity


@dataclass(frozen=True, slots=True)
class _CollectedSourceEvidenceRecord:
    """One detached, privacy-safe record identity in manifest order."""

    owner_class: str
    owner_schema_ref: str
    natural_identity: Mapping[str, object]
    source_record_sha256: str
    domain_self_digests: Mapping[str, str]
    ordered_support_owner_sha256: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _CollectedOperationEvidenceProjection:
    """Detached read-only projection of one collector-owned operation graph."""

    schema_version: str
    benchmark_subject_digest: str
    family_id: str
    case_id: str
    source_contract_sha256: str
    scenario_source_sha256: str
    input_owner_digest: str
    truth_evidence_digest: str
    operation_plan_sha256: str
    scientific_plan_digest: str
    scientific_terminal_index_digest: str
    scientific_evidence_digest: str
    evidence_graph_digest: str
    source_owner_registry_sha256: str
    ordered_source_records: tuple[_CollectedSourceEvidenceRecord, ...]
    unavailable_owner_classes: tuple[str, ...]
    collected_operation_evidence_sha256: str


@dataclass(slots=True)
class _CollectedOperationEvidenceState:
    context: _AuthenticatedScenarioEvidenceContext
    source_records: tuple[_ScenarioSourceOwnerRecord, ...]
    source_identities: tuple[tuple[str, Mapping[str, object]], ...]
    projection_bytes: bytes
    consumed: bool
    lock: RLock


_CONTEXT_STATES: OneShotWeakRegistry[object, _ScenarioEvidenceContextState]
_CONTEXT_STATES, _CONTEXT_ISSUER = create_one_shot_registry()
_PUBLIC_TRUTH_CONTEXT_STATES: OneShotWeakRegistry[object, _PublicSyntheticTruthContextState]
_PUBLIC_TRUTH_CONTEXT_STATES, _PUBLIC_TRUTH_CONTEXT_ISSUER = create_one_shot_registry()

_AuthenticateSourceProjection = Callable[
    [
        object,
        _AuthenticatedScenarioSourceOwnerProjection,
        str,
        str,
        str,
        str | None,
        str | None,
    ],
    str | None,
]
_ReadSourceProjection = Callable[
    [
        object,
        _AuthenticatedScenarioSourceOwnerProjection,
        str,
        str,
        str,
    ],
    tuple[_ScenarioSourceOwnerRecord, ...],
]
_ReadSourceIdentityProjection = Callable[
    [
        object,
        _AuthenticatedScenarioSourceOwnerProjection,
        str,
        str,
        str,
    ],
    tuple[tuple[str, Mapping[str, object]], ...],
]
_ValidateScenarioContextProvenance = Callable[
    [
        object,
        _AuthenticatedScenarioSourceOwnerProjection,
        str,
        str,
        str,
        Literal["HELDOUT", "PUBLIC_SYNTHETIC"],
        object,
    ],
    None,
]
_SCENARIO_SOURCE_OWNER_PROJECTION_BOUNDARY: (
    tuple[
        _AuthenticateSourceProjection,
        _ReadSourceProjection,
        _ReadSourceIdentityProjection,
    ]
    | None
) = None


@final
class _AuthenticatedScenarioEvidenceContext:
    """Opaque package-private owner of one revalidated scenario-evidence graph."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _AuthenticatedScenarioEvidenceContext:
        raise TypeError("Scenario evidence contexts are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Scenario evidence contexts cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Scenario evidence contexts are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Scenario evidence contexts cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Scenario evidence contexts cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Scenario evidence contexts cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Scenario evidence contexts cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Scenario evidence contexts cannot be copied or serialized.")

    def __repr__(self) -> str:
        _read_scenario_evidence_context(self)
        return "_AuthenticatedScenarioEvidenceContext(<opaque>)"


@final
class _AuthenticatedPublicSyntheticTruthContext:
    """Opaque pre-fit context for public synthetic truth-scoring validation."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> _AuthenticatedPublicSyntheticTruthContext:
        raise TypeError("Public synthetic truth contexts are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Public synthetic truth contexts cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Public synthetic truth contexts are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Public synthetic truth contexts cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Public synthetic truth contexts cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Public synthetic truth contexts cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Public synthetic truth contexts cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Public synthetic truth contexts cannot be copied or serialized.")


@final
class _CollectedOperationEvidence:
    """Opaque consume-once owner of one genuine collected operation graph."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _CollectedOperationEvidence:
        raise TypeError("Collected operation evidence is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Collected operation evidence cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Collected operation evidence is immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Collected operation evidence cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Collected operation evidence cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Collected operation evidence cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Collected operation evidence cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Collected operation evidence cannot be copied or serialized.")

    def __repr__(self) -> str:
        _validated_collected_operation_evidence_state(self)
        return "_CollectedOperationEvidence(<opaque>)"


_COLLECTED_OPERATION_EVIDENCE_STATES: OneShotWeakRegistry[
    _CollectedOperationEvidence, _CollectedOperationEvidenceState
]
(
    _COLLECTED_OPERATION_EVIDENCE_STATES,
    _COLLECTED_OPERATION_EVIDENCE_ISSUER,
) = create_one_shot_registry()


def _claim_scenario_source_owner_projection_boundary[T](
    *,
    owner_type: type[T],
    authenticate_projection: _AuthenticateSourceProjection,
    read_projection: _ReadSourceProjection,
    read_identity_projection: _ReadSourceIdentityProjection,
) -> _ValidateScenarioContextProvenance:
    """Install the exact evaluator runner's projection bridge once."""

    module_name = owner_type.__module__
    module = sys.modules.get(module_name)
    module_path = getattr(module, "__file__", None)
    expected_path = Path(__file__).resolve().parents[3] / "evaluator" / "run_benchmark.py"
    try:
        authentic = (
            type(module_path) is str
            and Path(module_path).resolve(strict=True) == expected_path
            and Path(authenticate_projection.__code__.co_filename).resolve(strict=True)
            == expected_path
            and Path(read_projection.__code__.co_filename).resolve(strict=True) == expected_path
            and Path(read_identity_projection.__code__.co_filename).resolve(strict=True)
            == expected_path
            and authenticate_projection.__module__ == module_name
            and read_projection.__module__ == module_name
            and read_identity_projection.__module__ == module_name
            and getattr(module, "_AuthenticatedHeldoutAttempt", None) is owner_type
            and getattr(module, "_authenticate_scenario_source_owner_projection", None)
            is authenticate_projection
            and getattr(module, "_read_scenario_source_owner_projection", None) is read_projection
            and getattr(module, "_read_scenario_source_owner_identity_projection", None)
            is read_identity_projection
        )
    except (AttributeError, OSError, TypeError):
        authentic = False
    global _SCENARIO_SOURCE_OWNER_PROJECTION_BOUNDARY
    if not authentic or _SCENARIO_SOURCE_OWNER_PROJECTION_BOUNDARY is not None:
        _reject()
    _SCENARIO_SOURCE_OWNER_PROJECTION_BOUNDARY = (
        authenticate_projection,
        read_projection,
        read_identity_projection,
    )

    def validate_context_provenance(
        context: object,
        projection: _AuthenticatedScenarioSourceOwnerProjection,
        benchmark_subject_digest: str,
        family_id: str,
        case_id: str,
        authority_origin: Literal["HELDOUT", "PUBLIC_SYNTHETIC"],
        authority_owner: object,
    ) -> None:
        try:
            if type(context) is _AuthenticatedScenarioEvidenceContext:
                state = _CONTEXT_STATES.read(context)
                if not (
                    type(state) is _ScenarioEvidenceContextState
                    and (
                        authority_origin == "HELDOUT"
                        or (
                            authority_origin == "PUBLIC_SYNTHETIC"
                            and state.batch is authority_owner
                        )
                    )
                    and state.source_projection is projection
                    and state.identity.benchmark_subject_digest == benchmark_subject_digest
                    and state.identity.family_id == family_id
                    and state.identity.case_id == case_id
                ):
                    _reject()
                _CONTEXT_STATES.require(context, state)
                return
            if type(context) is _AuthenticatedPublicSyntheticTruthContext:
                public_state = _PUBLIC_TRUTH_CONTEXT_STATES.read(context)
                if not (
                    authority_origin == "PUBLIC_SYNTHETIC"
                    and type(public_state) is _PublicSyntheticTruthContextState
                    and public_state.batch is authority_owner
                    and public_state.source_projection is projection
                    and public_state.identity.benchmark_subject_digest == benchmark_subject_digest
                    and public_state.identity.family_id == family_id
                    and public_state.identity.case_id == case_id
                ):
                    _reject()
                _PUBLIC_TRUTH_CONTEXT_STATES.require(context, public_state)
                return
            _reject()
        except (OneShotRegistryError, KeyError, TypeError):
            _reject()

    return validate_context_provenance


def _authenticate_source_projection(
    context: object,
    projection: _AuthenticatedScenarioSourceOwnerProjection,
    identity: _ScenarioEvidenceIdentity | _PublicSyntheticTruthIdentity,
) -> str | None:
    boundary = _SCENARIO_SOURCE_OWNER_PROJECTION_BOUNDARY
    if boundary is None:
        _reject()
    try:
        operation_plan_sha256 = boundary[0](
            context,
            projection,
            identity.benchmark_subject_digest,
            identity.family_id,
            identity.case_id,
            (
                identity.scientific_evidence_digest
                if type(identity) is _ScenarioEvidenceIdentity
                else None
            ),
            (
                identity.evidence_graph_digest
                if type(identity) is _ScenarioEvidenceIdentity
                else None
            ),
        )
        return operation_plan_sha256
    except ScenarioEvidenceContextError:
        raise
    except Exception:
        _reject()


def _public_synthetic_truth_graph(
    batch: AuthenticatedScenarioCaseBatch,
    input_owner: SealedPublicSyntheticAuditInput,
) -> tuple[_AuthenticatedCaseContext, _PublicSyntheticTruthIdentity]:
    """Revalidate the minimal public batch/input graph needed before fitting."""

    try:
        batch_context = _read_authenticated_batch_context(batch)
        input_state = _resolve_public_synthetic_audit_input(input_owner)
        if _read_public_synthetic_batch_input_owner(input_owner) is not batch:
            _reject()
        resolved_case = input_state.resolved_case
        matches = tuple(
            case
            for case in batch_context.cases
            if (
                case.family_id == resolved_case.coordinate.family_id
                and case.case_id == resolved_case.case_id
                and case.source_contract_sha256 == resolved_case.source_contract_sha256
                and case.scenario_source_sha256 == resolved_case.scenario_definitions_sha256
            )
        )
        input_projection = strict_json_loads(input_state.projection_bytes)
        if len(matches) != 1 or type(input_projection) is not dict:
            _reject()
        case = matches[0]
        identity = _PublicSyntheticTruthIdentity(
            benchmark_subject_digest=batch_context.benchmark_subject_digest,
            family_id=case.family_id,
            case_id=case.case_id,
            source_contract_sha256=case.source_contract_sha256,
            scenario_source_sha256=case.scenario_source_sha256,
            input_owner_digest=cast(str, input_projection["input_owner_digest"]),
        )
        if any(
            type(value) is not str or not value
            for value in (
                identity.benchmark_subject_digest,
                identity.family_id,
                identity.case_id,
                identity.source_contract_sha256,
                identity.scenario_source_sha256,
                identity.input_owner_digest,
            )
        ):
            _reject()
        return case, identity
    except ScenarioEvidenceContextError:
        raise
    except Exception:
        _reject()


def _bind_public_synthetic_truth_context(
    batch: AuthenticatedScenarioCaseBatch,
    input_owner: SealedPublicSyntheticAuditInput,
    source_projection: _AuthenticatedScenarioSourceOwnerProjection,
    plan: tuple[DirectOperationPlanEntry, ...],
) -> _AuthenticatedPublicSyntheticTruthContext:
    """Bind one exact public batch input to its one-shot truth-owner projection."""

    if (
        type(batch) is not AuthenticatedScenarioCaseBatch
        or type(input_owner) is not SealedPublicSyntheticAuditInput
        or type(source_projection) is not _AuthenticatedScenarioSourceOwnerProjection
        or type(plan) is not tuple
        or not plan
    ):
        _reject()
    case, identity = _public_synthetic_truth_graph(batch, input_owner)
    operation_plan_sha256 = _direct_operation_plan_digest(plan)
    owner = object.__new__(_AuthenticatedPublicSyntheticTruthContext)
    _PUBLIC_TRUTH_CONTEXT_ISSUER.bind_once(
        owner,
        _PublicSyntheticTruthContextState(
            batch=batch,
            input_owner=input_owner,
            source_projection=source_projection,
            operation_plan_sha256=operation_plan_sha256,
            case=case,
            identity=identity,
        ),
    )
    if _authenticate_source_projection(owner, source_projection, identity) != operation_plan_sha256:
        _reject()
    return owner


def _read_public_synthetic_truth_context(
    owner: _AuthenticatedPublicSyntheticTruthContext,
) -> _PublicSyntheticTruthContextState:
    if type(owner) is not _AuthenticatedPublicSyntheticTruthContext:
        _reject()
    try:
        active = _ACTIVE_CONTEXT_READ.get()
        if active is not None and active[0] is owner:
            state = active[1]
            if type(state) is not _PublicSyntheticTruthContextState:
                _reject()
            _PUBLIC_TRUTH_CONTEXT_STATES.require(owner, state)
            return state
        state = _PUBLIC_TRUTH_CONTEXT_STATES.read(owner)
        if type(state) is not _PublicSyntheticTruthContextState:
            _reject()
        case, identity = _public_synthetic_truth_graph(state.batch, state.input_owner)
        if case != state.case or identity != state.identity:
            _reject()
        if (
            _authenticate_source_projection(owner, state.source_projection, identity)
            != state.operation_plan_sha256
        ):
            _reject()
        _PUBLIC_TRUTH_CONTEXT_STATES.require(owner, state)
        return state
    except (OneShotRegistryError, KeyError, TypeError):
        _reject()


@contextmanager
def _authenticated_scenario_context_read_scope(
    owner: _AuthenticatedScenarioEvidenceContext | _AuthenticatedPublicSyntheticTruthContext,
):
    """Reuse one authenticated immutable context only within one consumer call."""

    active = _ACTIVE_CONTEXT_READ.get()
    if active is not None and active[0] is owner:
        yield
        return
    if type(owner) is _AuthenticatedScenarioEvidenceContext:
        state = _read_scenario_evidence_context(owner)
    elif type(owner) is _AuthenticatedPublicSyntheticTruthContext:
        state = _read_public_synthetic_truth_context(owner)
    else:
        _reject()
    token = _ACTIVE_CONTEXT_READ.set((owner, state))
    try:
        yield
    finally:
        _ACTIVE_CONTEXT_READ.reset(token)


def _public_digest(value: str) -> str:
    if value.startswith("sha256:"):
        return value
    return f"sha256:{value}"


def _exact_case_binding(case: _AuthenticatedCaseContext) -> dict[str, str]:
    return {
        "case_id": case.case_id,
        "source_contract_sha256": case.source_contract_sha256,
        "scenario_definitions_sha256": case.scenario_source_sha256,
    }


def _report_case_binding(case: _AuthenticatedCaseContext) -> dict[str, str]:
    return {
        "case_id": case.case_id,
        "source_contract_sha256": _public_digest(case.source_contract_sha256),
        "scenario_definitions_sha256": _public_digest(case.scenario_source_sha256),
    }


def _joined_graph(
    batch: AuthenticatedScenarioCaseBatch,
    input_owner: SealedPublicSyntheticAuditInput,
    truth: SyntheticEvaluationTruthEvidence,
    captured_science: CapturedScientificRun,
    sealed_science: SealedScientificEvidence,
) -> tuple[_AuthenticatedCaseContext, _ScenarioEvidenceIdentity]:
    try:
        batch_context = _read_authenticated_batch_context(batch)
        input_state = _resolve_public_synthetic_audit_input(input_owner)
        truth_state = _resolve_synthetic_evaluation_truth_evidence(truth)
        captured_state = _read_captured_scientific_run(captured_science)
        sealed_state = _read_sealed_scientific_evidence(sealed_science)
        scientific = project_scientific_evidence(sealed_science)

        resolved_case = input_state.resolved_case
        matches = tuple(
            case
            for case in batch_context.cases
            if (
                case.family_id == resolved_case.coordinate.family_id
                and case.case_id == resolved_case.case_id
                and case.source_contract_sha256 == resolved_case.source_contract_sha256
                and case.scenario_source_sha256 == resolved_case.scenario_definitions_sha256
            )
        )
        if len(matches) != 1:
            _reject()
        case = matches[0]
        exact_case_binding = _exact_case_binding(case)
        captured_binding = (
            None
            if captured_state.synthetic_case_binding_bytes is None
            else strict_json_loads(captured_state.synthetic_case_binding_bytes)
        )
        if (
            truth_state.input_owner is not input_owner
            or sealed_state.capture is not captured_science
            or captured_binding != exact_case_binding
            or scientific.get("synthetic_case_binding") != exact_case_binding
        ):
            _reject()

        input_projection = strict_json_loads(input_state.projection_bytes)
        truth_projection = strict_json_loads(truth_state.material.projection_bytes)
        if type(input_projection) is not dict or type(truth_projection) is not dict:
            _reject()
        identity_preimage = {
            "benchmark_subject_digest": batch_context.benchmark_subject_digest,
            "family_id": case.family_id,
            "case_id": case.case_id,
            "source_contract_sha256": case.source_contract_sha256,
            "scenario_source_sha256": case.scenario_source_sha256,
            "input_owner_digest": cast(str, input_projection["input_owner_digest"]),
            "truth_evidence_digest": cast(str, truth_projection["evidence_digest"]),
            "scientific_evidence_digest": cast(str, scientific["scientific_evidence_digest"]),
        }
        identity = _ScenarioEvidenceIdentity(
            benchmark_subject_digest=batch_context.benchmark_subject_digest,
            family_id=case.family_id,
            case_id=case.case_id,
            source_contract_sha256=case.source_contract_sha256,
            scenario_source_sha256=case.scenario_source_sha256,
            input_owner_digest=cast(str, input_projection["input_owner_digest"]),
            truth_evidence_digest=cast(str, truth_projection["evidence_digest"]),
            scientific_evidence_digest=cast(str, scientific["scientific_evidence_digest"]),
            evidence_graph_digest=structured_sha256_hex(
                "ebm-audit/scenario-evidence-graph/1", identity_preimage
            ),
        )
        if any(
            type(value) is not str or not value
            for value in (
                identity.benchmark_subject_digest,
                identity.family_id,
                identity.case_id,
                identity.source_contract_sha256,
                identity.scenario_source_sha256,
                identity.input_owner_digest,
                identity.truth_evidence_digest,
                identity.scientific_evidence_digest,
                identity.evidence_graph_digest,
            )
        ):
            _reject()
        return case, identity
    except ScenarioEvidenceContextError:
        raise
    except Exception:
        _reject()


def _bind_scenario_evidence_context(
    batch: AuthenticatedScenarioCaseBatch,
    input_owner: SealedPublicSyntheticAuditInput,
    truth: SyntheticEvaluationTruthEvidence,
    captured_science: CapturedScientificRun,
    sealed_science: SealedScientificEvidence,
    source_projection: _AuthenticatedScenarioSourceOwnerProjection,
) -> _AuthenticatedScenarioEvidenceContext:
    """Bind one exact case from the ordinary transaction's validated components."""

    if (
        type(batch) is not AuthenticatedScenarioCaseBatch
        or type(input_owner) is not SealedPublicSyntheticAuditInput
        or type(truth) is not SyntheticEvaluationTruthEvidence
        or type(captured_science) is not CapturedScientificRun
        or type(sealed_science) is not SealedScientificEvidence
        or type(source_projection) is not _AuthenticatedScenarioSourceOwnerProjection
    ):
        _reject()
    case, identity = _joined_graph(
        batch,
        input_owner,
        truth,
        captured_science,
        sealed_science,
    )
    owner = object.__new__(_AuthenticatedScenarioEvidenceContext)
    _CONTEXT_ISSUER.bind_once(
        owner,
        _ScenarioEvidenceContextState(
            batch=batch,
            input_owner=input_owner,
            truth=truth,
            captured_science=captured_science,
            sealed_science=sealed_science,
            source_projection=source_projection,
            case=case,
            identity=identity,
        ),
    )
    _authenticate_source_projection(owner, source_projection, identity)
    return owner


def _read_scenario_evidence_context(
    owner: _AuthenticatedScenarioEvidenceContext,
) -> _ScenarioEvidenceContextState:
    """Return retained owners and safe identity only after complete revalidation."""

    if type(owner) is not _AuthenticatedScenarioEvidenceContext:
        _reject()
    try:
        active = _ACTIVE_CONTEXT_READ.get()
        if active is not None and active[0] is owner:
            state = active[1]
            if type(state) is not _ScenarioEvidenceContextState:
                _reject()
            _CONTEXT_STATES.require(owner, state)
            return state
        state = _CONTEXT_STATES.read(owner)
        if type(state) is not _ScenarioEvidenceContextState:
            _reject()
        case, identity = _joined_graph(
            state.batch,
            state.input_owner,
            state.truth,
            state.captured_science,
            state.sealed_science,
        )
        if case != state.case or identity != state.identity:
            _reject()
        _authenticate_source_projection(owner, state.source_projection, identity)
        _CONTEXT_STATES.require(owner, state)
        return state
    except (OneShotRegistryError, KeyError, TypeError):
        _reject()


def _read_authenticated_scenario_case(
    owner: _AuthenticatedScenarioEvidenceContext,
) -> tuple[AuthenticatedScenarioCaseBatch, _AuthenticatedCaseContext]:
    state = _read_scenario_evidence_context(owner)
    return state.batch, state.case


def _read_sealed_synthetic_audit_input(
    owner: _AuthenticatedScenarioEvidenceContext,
) -> SealedPublicSyntheticAuditInput:
    state = _read_scenario_evidence_context(owner)
    return state.input_owner


def _read_synthetic_truth_evidence(
    owner: _AuthenticatedScenarioEvidenceContext,
) -> SyntheticEvaluationTruthEvidence:
    state = _read_scenario_evidence_context(owner)
    return state.truth


def _read_captured_scientific_run_owner(
    owner: _AuthenticatedScenarioEvidenceContext,
) -> CapturedScientificRun:
    state = _read_scenario_evidence_context(owner)
    return state.captured_science


def _read_sealed_scientific_evidence_owner(
    owner: _AuthenticatedScenarioEvidenceContext,
) -> SealedScientificEvidence:
    state = _read_scenario_evidence_context(owner)
    return state.sealed_science


def _read_scenario_evidence_graph_digest(
    owner: _AuthenticatedScenarioEvidenceContext,
) -> str:
    """Return the canonical digest of the fully revalidated pre-report graph."""

    return _read_scenario_evidence_context(owner).identity.evidence_graph_digest


def _plain_mapping(value: Mapping[str, object]) -> dict[str, object]:
    def thaw(item: object) -> object:
        if isinstance(item, Mapping):
            return {key: thaw(child) for key, child in item.items()}
        if type(item) is tuple:
            return [thaw(child) for child in item]
        return item

    try:
        decoded = strict_json_loads(canonical_json_bytes(thaw(value)))
    except CanonicalizationError:
        _reject_collection()
    if type(decoded) is not dict:
        _reject_collection()
    return cast(dict[str, object], decoded)


def _freeze_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    """Detach and recursively freeze one canonical structured identity."""

    def freeze(item: object) -> object:
        if isinstance(item, Mapping):
            return MappingProxyType({key: freeze(child) for key, child in item.items()})
        if type(item) in {list, tuple}:
            return tuple(freeze(child) for child in cast(list[object] | tuple[object, ...], item))
        return item

    return MappingProxyType({key: freeze(item) for key, item in value.items()})


def _source_owner_registry_projection() -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    for owner_class, binding in _OWNER_BINDINGS.items():
        if (
            type(owner_class) is not str
            or not owner_class
            or type(binding) is not tuple
            or len(binding) != 2
            or type(binding[0]) is not str
            or not binding[0]
            or type(binding[1]) is not tuple
            or not binding[1]
            or any(type(field) is not str or not field for field in binding[1])
        ):
            _reject_collection()
        rows.append(
            {
                "owner_class": owner_class,
                "owner_schema_ref": binding[0],
                "natural_identity_fields": list(binding[1]),
            }
        )
    if not rows or len({cast(str, row["owner_class"]) for row in rows}) != len(rows):
        _reject_collection()
    return tuple(rows)


def _source_owner_registry_sha256() -> str:
    return structured_sha256_hex(
        _SOURCE_OWNER_REGISTRY_DOMAIN,
        {"ordered_owner_bindings": list(_source_owner_registry_projection())},
    )


def _validate_source_record_schema(
    owner_schema_ref: str,
    source_record: dict[str, object],
) -> None:
    schema_path, separator, definition = owner_schema_ref.partition("#/$defs/")
    if not schema_path.startswith("schemas/") or (separator and not definition):
        _reject_collection()
    try:
        validate_instance(
            source_record,
            schema_path.removeprefix("schemas/"),
            definition=definition or None,
        )
    except (SchemaValidationError, ValueError):
        _reject_collection()


def _domain_self_digests(
    owner_class: str,
    source_record: dict[str, object],
) -> Mapping[str, str]:
    binding = _SELF_DIGEST_BINDINGS.get(owner_class)
    if binding is None:
        return MappingProxyType({})
    field, domain = binding
    if field not in source_record:
        _reject_collection()
    digest = source_record.get(field)
    if type(digest) is not str or len(digest) != 64:
        _reject_collection()
    preimage = dict(source_record)
    preimage[field] = None
    if "digest_state" in preimage:
        if preimage["digest_state"] != "PERSISTED":
            _reject_collection()
        preimage["digest_state"] = "DIGEST_PREIMAGE"
    if structured_sha256_hex(domain, preimage) != digest:
        _reject_collection()
    return MappingProxyType({field: digest})


def _revalidate_source_capability(
    record: _ScenarioSourceOwnerRecord,
    source_record: dict[str, object],
) -> None:
    capability = record.source_capability
    if capability is None:
        _reject_collection()
    candidates: tuple[_ScenarioSourceRecordInput, ...]
    try:
        authenticated_public_record = (
            record.owner_class in _PUBLIC_OPERATION_EVIDENCE_OWNER_CLASSES
            and type(capability) is _AuthenticatedSourceOwnerRecordCapability
        )
        if record.owner_class in {
            "RESOLVED_GENERATOR_CONFIGURATION",
            "RESOLVED_GENERATOR_MECHANISM",
            "COMPONENT_SEED_MANIFEST",
            "ANALYSIS_SPEC",
            "FIT_RESPONSE_BINDING",
            "CANONICAL_SCIENTIFIC_PAYLOAD",
        } or authenticated_public_record:
            if type(capability) is not _AuthenticatedSourceOwnerRecordCapability:
                _reject_collection()
            if _plain_mapping(_read_authenticated_source_owner_record(record)) != source_record:
                _reject_collection()
            if authenticated_public_record:
                from ebm_audit.evaluator.public_operation_evidence import (
                    PublicOperationEvidence,
                    _read_public_operation_evidence_records,
                )

                source_owner = _read_authenticated_source_owner_source(record)
                if type(source_owner) is not PublicOperationEvidence:
                    _reject_collection()
                rows = _read_public_operation_evidence_records(source_owner)
                if sum(
                    row.owner_class == record.owner_class
                    and row.owner_schema_ref == record.owner_schema_ref
                    and row.natural_identity == dict(record.natural_identity)
                    and strict_json_loads(row.source_record_bytes) == source_record
                    and row.ordered_support_owner_sha256
                    == record.ordered_support_owner_sha256
                    and row.source_owner is source_owner
                    for row in rows
                ) != 1:
                    _reject_collection()
            return
        if record.owner_class == "SYNTHETIC_TRUTH":
            if type(capability) is not SyntheticTruthScoringEvidence:
                _reject_collection()
            candidates = (_synthetic_truth_source_record(capability, bind=False),)
        elif record.owner_class == "SYNTHETIC_SCIENTIFIC_DATA":
            if type(capability) is not SyntheticScientificDataEvidence:
                _reject_collection()
            candidates = (_synthetic_scientific_data_source_record(capability, bind=False),)
        elif record.owner_class == "PREPARATION_AUDIT_EVIDENCE":
            if type(capability) is not PreparationAuditEvidence:
                _reject_collection()
            candidates = _preparation_audit_evidence_source_records(capability)
        elif record.owner_class == "PREPARATION_ROW_INSTANCE_MANIFEST":
            if (
                type(capability) is not _PreparationRowInstanceManifestSource
                or type(capability.evidence) is not PreparationAuditEvidence
                or type(capability.manifests) is not PreparationRowInstanceManifests
            ):
                _reject_collection()
            candidates = _preparation_row_instance_manifest_source_records(
                capability.evidence,
                capability.manifests,
                case_id=cast(str, record.natural_identity.get("case_id")),
            )
        elif record.owner_class == "SCENARIO_MATCHED_METRIC_RECORD":
            from ebm_audit.evaluator.scenario_derivation_matched_metric import (
                _scenario_matched_metric_source_record,
            )

            candidates = (_scenario_matched_metric_source_record(capability),)
        elif record.owner_class == "CANDIDATE_STRONG_EVIDENCE_DECISION":
            from ebm_audit.evaluator.candidate_decision import (
                _candidate_strong_evidence_decision_source_record,
            )

            candidates = (
                _candidate_strong_evidence_decision_source_record(
                    capability,
                    bind=False,
                ),
            )
        elif record.owner_class == _PRIVATE_ARRAY_OWNER_CLASS:
            try:
                from ebm_audit.evaluator.scenario_derivation_precedence import (
                    _pairwise_precedence_source_record,
                )

                candidate = _pairwise_precedence_source_record(capability)
            except Exception:
                from ebm_audit.evaluator.scenario_derivation_matched_metric import (
                    _private_canonical_array_value_source_record,
                )

                candidate = _private_canonical_array_value_source_record(capability)
            candidates = (candidate,)
        else:
            _reject_collection()
    except CollectedOperationEvidenceError:
        raise
    except Exception:
        _reject_collection()
    if type(candidates) is not tuple or not candidates:
        _reject_collection()
    matching = 0
    for candidate in candidates:
        if type(candidate) is not _ScenarioSourceRecordInput:
            _reject_collection()
        try:
            candidate_source_record = strict_json_loads(candidate.source_record_bytes)
        except CanonicalizationError:
            _reject_collection()
        if type(capability) is _PreparationRowInstanceManifestSource:
            candidate_capability = candidate.source_capability
            capability_matches = (
                type(candidate_capability) is _PreparationRowInstanceManifestSource
                and candidate_capability.evidence is capability.evidence
                and candidate_capability.manifests is capability.manifests
            )
        else:
            capability_matches = candidate.source_capability is capability
        if (
            candidate.owner_class == record.owner_class
            and candidate.owner_schema_ref == record.owner_schema_ref
            and dict(candidate.natural_identity) == dict(record.natural_identity)
            and candidate_source_record == source_record
            and candidate.ordered_support_owner_sha256 == record.ordered_support_owner_sha256
            and capability_matches
        ):
            matching += 1
    if matching != 1:
        _reject_collection()


def _collected_source_record(
    record: _ScenarioSourceOwnerRecord,
    prior_source_record_sha256: frozenset[str],
) -> _CollectedSourceEvidenceRecord:
    if (
        type(record) is not _ScenarioSourceOwnerRecord
        or not isinstance(record.natural_identity, Mapping)
        or not isinstance(record.source_record, Mapping)
        or type(record.source_record_sha256) is not str
        or len(record.source_record_sha256) != 64
        or type(record.ordered_support_owner_sha256) is not tuple
        or len(set(record.ordered_support_owner_sha256)) != len(record.ordered_support_owner_sha256)
        or any(
            type(digest) is not str or len(digest) != 64 or digest not in prior_source_record_sha256
            for digest in record.ordered_support_owner_sha256
        )
    ):
        _reject_collection()
    binding = _OWNER_BINDINGS.get(record.owner_class)
    if (
        binding is None
        or record.owner_schema_ref != binding[0]
        or record.owner_class not in _CURRENT_GENUINE_OWNER_CLASSES
        or record.owner_class in _FORCED_UNAVAILABLE_OWNER_CLASSES
        or record.source_capability is None
    ):
        _reject_collection()
    source_record = _plain_mapping(record.source_record)
    natural_identity = _plain_mapping(record.natural_identity)
    if set(natural_identity) != set(binding[1]) or any(
        source_record.get(field) != value for field, value in natural_identity.items()
    ):
        _reject_collection()
    _validate_source_record_schema(record.owner_schema_ref, source_record)
    if record.source_record_sha256 != structured_sha256_hex(
        _SCENARIO_SOURCE_RECORD_DOMAIN,
        {
            "owner_class": record.owner_class,
            "natural_identity": natural_identity,
            "source_record": source_record,
        },
    ):
        _reject_collection()
    _revalidate_source_capability(record, source_record)
    if record.owner_class == _PRIVATE_ARRAY_OWNER_CLASS:
        safe_identity = {
            "member_name": natural_identity.get("member_name"),
            "array_value_sha256": natural_identity.get("array_value_sha256"),
        }
    elif record.owner_class == "COMPONENT_SEED_MANIFEST":
        safe_identity = {
            "component_seed_manifest_sha256": natural_identity.get("component_seed_manifest_sha256")
        }
    else:
        safe_identity = natural_identity
    if any(type(key) is not str or not key for key in safe_identity):
        _reject_collection()
    try:
        canonical_json_bytes(safe_identity)
    except CanonicalizationError:
        _reject_collection()
    return _CollectedSourceEvidenceRecord(
        owner_class=record.owner_class,
        owner_schema_ref=record.owner_schema_ref,
        natural_identity=_freeze_mapping(safe_identity),
        source_record_sha256=record.source_record_sha256,
        domain_self_digests=_domain_self_digests(record.owner_class, source_record),
        ordered_support_owner_sha256=record.ordered_support_owner_sha256,
    )


def _collected_projection_dict(
    context: _AuthenticatedScenarioEvidenceContext,
    source_records: tuple[_ScenarioSourceOwnerRecord, ...],
    source_identities: tuple[tuple[str, Mapping[str, object]], ...],
) -> dict[str, object]:
    try:
        context_state = _read_scenario_evidence_context(context)
        batch = _read_authenticated_batch_context(context_state.batch)
        input_state = _resolve_public_synthetic_audit_input(context_state.input_owner)
        truth_state = _resolve_synthetic_evaluation_truth_evidence(context_state.truth)
        captured = _read_captured_scientific_run(context_state.captured_science)
        sealed = _read_sealed_scientific_evidence(context_state.sealed_science)
        scientific = project_scientific_evidence(context_state.sealed_science)
        operation_plan_sha256 = _authenticate_source_projection(
            context,
            context_state.source_projection,
            context_state.identity,
        )
    except CollectedOperationEvidenceError:
        raise
    except Exception:
        _reject_collection()
    if (
        truth_state.input_owner is not context_state.input_owner
        or sealed.capture is not context_state.captured_science
        or type(operation_plan_sha256) is not str
        or len(operation_plan_sha256) != 64
        or scientific.get("plan_digest") != captured.plan_digest
        or scientific.get("terminal_index_digest") != captured.terminal_index_digest
        or scientific.get("scientific_evidence_digest") != sealed.evidence_digest
        or scientific.get("scientific_evidence_digest")
        != context_state.identity.scientific_evidence_digest
        or input_state is None
        or batch.benchmark_subject_digest != context_state.identity.benchmark_subject_digest
        or type(source_records) is not tuple
        or not source_records
        or type(source_identities) is not tuple
        or len(source_identities) != len(source_records)
    ):
        _reject_collection()
    collected_records: list[_CollectedSourceEvidenceRecord] = []
    prior: set[str] = set()
    for record, identity_projection in zip(source_records, source_identities, strict=True):
        if (
            type(identity_projection) is not tuple
            or len(identity_projection) != 2
            or identity_projection[0] != record.owner_class
            or dict(identity_projection[1]) != dict(record.natural_identity)
        ):
            _reject_collection()
        if (
            record.owner_class
            in {
                "RESOLVED_GENERATOR_CONFIGURATION",
                "RESOLVED_GENERATOR_MECHANISM",
                "COMPONENT_SEED_MANIFEST",
            }
            and _read_authenticated_source_owner_source(record) is not context_state.batch
        ):
            _reject_collection()
        if (
            record.owner_class == "ANALYSIS_SPEC"
            and _read_authenticated_source_owner_source(record)
            is not context_state.captured_science
        ):
            _reject_collection()
        if record.owner_class in {
            "FIT_RESPONSE_BINDING",
            "CANONICAL_SCIENTIFIC_PAYLOAD",
        }:
            try:
                scientific_source = _read_authenticated_source_owner_source(record)
                source_batch, source_capture = _read_scientific_meaning_source_owners(
                    scientific_source
                )
            except Exception:
                _reject_collection()
            if (
                source_batch is not context_state.batch
                or source_capture is not context_state.captured_science
            ):
                _reject_collection()
        if (
            record.owner_class == "PREPARATION_AUDIT_EVIDENCE"
            and type(record.source_capability) is PreparationAuditEvidence
        ):
            try:
                expected_preparation = _issue_preparation_audit_evidence(
                    context_state.captured_science
                )
            except Exception:
                _reject_collection()
            if expected_preparation is not record.source_capability:
                _reject_collection()
        if record.owner_class in _PUBLIC_OPERATION_EVIDENCE_OWNER_CLASSES and not (
            record.owner_class == "PREPARATION_AUDIT_EVIDENCE"
            and type(record.source_capability) is PreparationAuditEvidence
        ):
            try:
                from ebm_audit.evaluator.public_operation_evidence import (
                    PublicOperationEvidence,
                    _read_public_operation_evidence_owners,
                )

                capability = _read_authenticated_source_owner_source(record)
                if type(capability) is not PublicOperationEvidence:
                    _reject_collection()
                source_operation_batch, _operation_plan, source_capture = (
                    _read_public_operation_evidence_owners(capability)
                )
                if (
                    source_operation_batch is not context_state.batch
                    or source_capture is not context_state.captured_science
                ):
                    _reject_collection()
            except Exception:
                _reject_collection()
        collected = _collected_source_record(record, frozenset(prior))
        if collected.source_record_sha256 in prior:
            _reject_collection()
        prior.add(collected.source_record_sha256)
        collected_records.append(collected)
    owner_classes = {record.owner_class for record in collected_records}
    if owner_classes & _FORCED_UNAVAILABLE_OWNER_CLASSES:
        _reject_collection()
    unavailable = tuple(
        cast(str, row["owner_class"])
        for row in _source_owner_registry_projection()
        if row["owner_class"] not in owner_classes
    )
    if not _FORCED_UNAVAILABLE_OWNER_CLASSES.issubset(unavailable):
        _reject_collection()
    projection: dict[str, object] = {
        "schema_version": _COLLECTED_OPERATION_EVIDENCE_SCHEMA_VERSION,
        "benchmark_subject_digest": context_state.identity.benchmark_subject_digest,
        "family_id": context_state.identity.family_id,
        "case_id": context_state.identity.case_id,
        "source_contract_sha256": context_state.identity.source_contract_sha256,
        "scenario_source_sha256": context_state.identity.scenario_source_sha256,
        "input_owner_digest": context_state.identity.input_owner_digest,
        "truth_evidence_digest": context_state.identity.truth_evidence_digest,
        "operation_plan_sha256": operation_plan_sha256,
        "scientific_plan_digest": captured.plan_digest,
        "scientific_terminal_index_digest": captured.terminal_index_digest,
        "scientific_evidence_digest": sealed.evidence_digest,
        "evidence_graph_digest": context_state.identity.evidence_graph_digest,
        "source_owner_registry_sha256": _source_owner_registry_sha256(),
        "ordered_source_records": [
            {
                "owner_class": record.owner_class,
                "owner_schema_ref": record.owner_schema_ref,
                "natural_identity": _plain_mapping(record.natural_identity),
                "source_record_sha256": record.source_record_sha256,
                "domain_self_digests": dict(record.domain_self_digests),
                "ordered_support_owner_sha256": list(record.ordered_support_owner_sha256),
            }
            for record in collected_records
        ],
        "unavailable_owner_classes": list(unavailable),
        "collected_operation_evidence_sha256": None,
    }
    projection["collected_operation_evidence_sha256"] = structured_sha256_hex(
        _COLLECTED_OPERATION_EVIDENCE_DOMAIN,
        projection,
    )
    return projection


def _collect_operation_evidence(
    context: _AuthenticatedScenarioEvidenceContext,
    operation_evidence: object | None = None,
    /,
) -> _CollectedOperationEvidence:
    """Consume one genuine source projection into one private collector owner."""

    if type(context) is not _AuthenticatedScenarioEvidenceContext:
        _reject_collection()
    try:
        context_state = _read_scenario_evidence_context(context)
        source_identities = _read_context_source_owner_identities(context, context_state)
        source_records = _read_context_source_owner_records(context, context_state)
        if operation_evidence is not None:
            from ebm_audit.evaluator.public_operation_evidence import (
                PublicOperationEvidence,
                _consume_public_operation_evidence_records,
                _read_public_operation_evidence_owners,
            )

            if type(operation_evidence) is not PublicOperationEvidence:
                _reject_collection()
            source_batch, _operation_plan, source_capture = _read_public_operation_evidence_owners(
                operation_evidence
            )
            if (
                source_batch is not context_state.batch
                or source_capture is not context_state.captured_science
            ):
                _reject_collection()
            public_rows = _consume_public_operation_evidence_records(operation_evidence)
            public_records = tuple(
                _owner_record(
                    _store_record(
                        _ScenarioSourceRecordInput(
                            owner_class=row.owner_class,
                            owner_schema_ref=row.owner_schema_ref,
                            source_relative_path=row.source_relative_path,
                            source_content_bytes=row.source_record_bytes,
                            source_record_bytes=row.source_record_bytes,
                            natural_identity=row.natural_identity,
                            ordered_support_owner_sha256=(row.ordered_support_owner_sha256),
                            source_capability=row.source_owner,
                        )
                    )
                )
                for row in public_rows
            )
            public_identities = tuple(
                (record.owner_class, record.natural_identity) for record in public_records
            )
            all_identities = [
                (owner_class, canonical_json_bytes(dict(identity)))
                for owner_class, identity in (*source_identities, *public_identities)
            ]
            if len(set(all_identities)) != len(all_identities):
                _reject_collection()
            source_records = (*source_records, *public_records)
            source_identities = (*source_identities, *public_identities)
        projection = _collected_projection_dict(
            context,
            source_records,
            source_identities,
        )
        projection_bytes = canonical_json_bytes(projection)
    except CollectedOperationEvidenceError:
        raise
    except Exception:
        _reject_collection()
    owner = object.__new__(_CollectedOperationEvidence)
    _COLLECTED_OPERATION_EVIDENCE_ISSUER.bind_once(
        owner,
        _CollectedOperationEvidenceState(
            context=context,
            source_records=source_records,
            source_identities=source_identities,
            projection_bytes=projection_bytes,
            consumed=False,
            lock=RLock(),
        ),
    )
    _validated_collected_operation_evidence_state(owner)
    return owner


def _validated_collected_operation_evidence_state(
    owner: _CollectedOperationEvidence,
) -> _CollectedOperationEvidenceState:
    if type(owner) is not _CollectedOperationEvidence:
        _reject_collection()
    try:
        state = _COLLECTED_OPERATION_EVIDENCE_STATES.read(owner)
        if type(state) is not _CollectedOperationEvidenceState:
            _reject_collection()
        expected = _collected_projection_dict(
            state.context,
            state.source_records,
            state.source_identities,
        )
        if canonical_json_bytes(expected) != state.projection_bytes:
            _reject_collection()
        _COLLECTED_OPERATION_EVIDENCE_STATES.require(owner, state)
        return state
    except CollectedOperationEvidenceError:
        raise
    except Exception:
        _reject_collection()


def _read_collected_operation_evidence(
    owner: _CollectedOperationEvidence,
    context: _AuthenticatedScenarioEvidenceContext,
    /,
) -> _CollectedOperationEvidenceProjection:
    """Consume one owner and return a detached privacy-safe read-only projection."""

    state = _validated_collected_operation_evidence_state(owner)
    with state.lock:
        if state.consumed or type(context) is not _AuthenticatedScenarioEvidenceContext:
            _reject_collection()
        if state.context is not context:
            _reject_collection()
        try:
            projection = strict_json_loads(state.projection_bytes)
        except CanonicalizationError:
            _reject_collection()
        if type(projection) is not dict:
            _reject_collection()
        rows = projection.get("ordered_source_records")
        unavailable = projection.get("unavailable_owner_classes")
        if type(rows) is not list or type(unavailable) is not list:
            _reject_collection()
        collected_rows: list[_CollectedSourceEvidenceRecord] = []
        for row in rows:
            if type(row) is not dict:
                _reject_collection()
            natural_identity = row.get("natural_identity")
            self_digests = row.get("domain_self_digests")
            supports = row.get("ordered_support_owner_sha256")
            if (
                type(natural_identity) is not dict
                or type(self_digests) is not dict
                or type(supports) is not list
            ):
                _reject_collection()
            collected_rows.append(
                _CollectedSourceEvidenceRecord(
                    owner_class=cast(str, row["owner_class"]),
                    owner_schema_ref=cast(str, row["owner_schema_ref"]),
                    natural_identity=_freeze_mapping(natural_identity),
                    source_record_sha256=cast(str, row["source_record_sha256"]),
                    domain_self_digests=MappingProxyType(cast(dict[str, str], dict(self_digests))),
                    ordered_support_owner_sha256=cast(tuple[str, ...], tuple(supports)),
                )
            )
        state.consumed = True
        return _CollectedOperationEvidenceProjection(
            schema_version=cast(str, projection["schema_version"]),
            benchmark_subject_digest=cast(str, projection["benchmark_subject_digest"]),
            family_id=cast(str, projection["family_id"]),
            case_id=cast(str, projection["case_id"]),
            source_contract_sha256=cast(str, projection["source_contract_sha256"]),
            scenario_source_sha256=cast(str, projection["scenario_source_sha256"]),
            input_owner_digest=cast(str, projection["input_owner_digest"]),
            truth_evidence_digest=cast(str, projection["truth_evidence_digest"]),
            operation_plan_sha256=cast(str, projection["operation_plan_sha256"]),
            scientific_plan_digest=cast(str, projection["scientific_plan_digest"]),
            scientific_terminal_index_digest=cast(
                str, projection["scientific_terminal_index_digest"]
            ),
            scientific_evidence_digest=cast(str, projection["scientific_evidence_digest"]),
            evidence_graph_digest=cast(str, projection["evidence_graph_digest"]),
            source_owner_registry_sha256=cast(str, projection["source_owner_registry_sha256"]),
            ordered_source_records=tuple(collected_rows),
            unavailable_owner_classes=cast(tuple[str, ...], tuple(unavailable)),
            collected_operation_evidence_sha256=cast(
                str, projection["collected_operation_evidence_sha256"]
            ),
        )


def _read_scenario_source_owner_records(
    owner: _AuthenticatedScenarioEvidenceContext,
) -> tuple[_ScenarioSourceOwnerRecord, ...]:
    """Consume and return the exact case's authenticated source-owner records once."""

    state = _read_scenario_evidence_context(owner)
    return _read_context_source_owner_records(owner, state)


def _read_scenario_source_owner_identities(
    owner: _AuthenticatedScenarioEvidenceContext,
) -> tuple[tuple[str, Mapping[str, object]], ...]:
    """Consume and return only fresh immutable source-owner identity facts once."""

    state = _read_scenario_evidence_context(owner)
    return _read_context_source_owner_identities(owner, state)


def _read_context_source_owner_identities(
    owner: object,
    state: _ScenarioEvidenceContextState | _PublicSyntheticTruthContextState,
) -> tuple[tuple[str, Mapping[str, object]], ...]:
    boundary = _SCENARIO_SOURCE_OWNER_PROJECTION_BOUNDARY
    if boundary is None:
        _reject()
    try:
        facts = boundary[2](
            owner,
            state.source_projection,
            state.identity.benchmark_subject_digest,
            state.identity.family_id,
            state.identity.case_id,
        )
        if type(facts) is not tuple or not facts:
            _reject()
        copied: list[tuple[str, Mapping[str, object]]] = []
        seen: set[bytes] = set()
        for fact in facts:
            if type(fact) is not tuple or len(fact) != 2:
                _reject()
            owner_class, natural_identity = fact
            if (
                type(owner_class) is not str
                or not owner_class
                or type(natural_identity) is not MappingProxyType
                or not natural_identity
            ):
                _reject()
            identity = _plain_mapping(natural_identity)
            if any(type(key) is not str or not key for key in identity):
                _reject()
            identity_key = canonical_json_bytes([owner_class, identity])
            if identity_key in seen:
                _reject()
            seen.add(identity_key)
            copied.append((owner_class, _freeze_mapping(identity)))
        return tuple(copied)
    except ScenarioEvidenceContextError:
        raise
    except Exception:
        _reject()


def _read_context_source_owner_records(
    owner: object,
    state: _ScenarioEvidenceContextState | _PublicSyntheticTruthContextState,
) -> tuple[_ScenarioSourceOwnerRecord, ...]:
    boundary = _SCENARIO_SOURCE_OWNER_PROJECTION_BOUNDARY
    if boundary is None:
        _reject()
    try:
        records = boundary[1](
            owner,
            state.source_projection,
            state.identity.benchmark_subject_digest,
            state.identity.family_id,
            state.identity.case_id,
        )
        if type(records) is not tuple or not records:
            _reject()
        exact_coordinate_found = False
        for record in records:
            if (
                type(record) is not _ScenarioSourceOwnerRecord
                or not isinstance(record.natural_identity, Mapping)
                or not isinstance(record.source_record, Mapping)
            ):
                _reject()
            family_id = record.natural_identity.get(
                "family_id", record.natural_identity.get("scenario_family_id")
            )
            case_id = record.natural_identity.get("case_id")
            if record.owner_class == "SYNTHETIC_TRUTH":
                scenario_identity = record.source_record.get("scenario_identity")
                if not isinstance(scenario_identity, Mapping):
                    _reject()
                family_id = scenario_identity.get("family_id")
                case_id = scenario_identity.get("case_id")
            if family_id == state.identity.family_id and case_id == state.identity.case_id:
                exact_coordinate_found = True
        if not exact_coordinate_found:
            _reject()
        return records
    except ScenarioEvidenceContextError:
        raise
    except Exception:
        _reject()


def _read_truth_scoring_context(
    owner: object,
) -> _ScenarioEvidenceContextState | _PublicSyntheticTruthContextState:
    """Read either complete evidence or the bounded public pre-fit truth context."""

    if type(owner) is _AuthenticatedScenarioEvidenceContext:
        return _read_scenario_evidence_context(owner)
    if type(owner) is _AuthenticatedPublicSyntheticTruthContext:
        return _read_public_synthetic_truth_context(owner)
    _reject()


def _read_truth_scoring_input(owner: object) -> SealedPublicSyntheticAuditInput:
    return _read_truth_scoring_context(owner).input_owner


def _read_truth_scoring_source_owner_records(
    owner: object,
) -> tuple[_ScenarioSourceOwnerRecord, ...]:
    return _read_context_source_owner_records(owner, _read_truth_scoring_context(owner))


def _read_truth_scoring_source_owner_identities(
    owner: object,
) -> tuple[tuple[str, Mapping[str, object]], ...]:
    return _read_context_source_owner_identities(
        owner,
        _read_truth_scoring_context(owner),
    )


__all__: list[str] = []
