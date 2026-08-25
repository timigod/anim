"""Fail-closed internal coverage projector for authenticated family evidence."""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.config.strict_yaml import StrictYamlError, load_strict_yaml_bytes
from ebm_audit.errors import InvalidInputError
from ebm_audit.evaluator.authenticated_plan_row_compiler import (
    AuthenticatedDirectOperationPlan,
    AuthenticatedPlanRowBindingReceipt,
    _read_authenticated_unprepared_plan_row_binding,
)
from ebm_audit.evaluator.heldout_score import _direct_operation_plan_digest
from ebm_audit.evaluator.meaning_evidence_bundle import _frozen_evaluator_source_bytes
from ebm_audit.evaluator.report_predicate_outcome import (
    ReportPredicateOutcome,
    ReportPredicateOutcomeError,
    _cardinality_members,
    _policies_for,
    _read_report_predicate_outcome,
    _read_report_predicate_outcome_context,
)
from ebm_audit.evaluator.scenario_derivation_actual_removed_rows import (
    HANDLERS as _ACTUAL_REMOVED_ROWS_HANDLERS,
)
from ebm_audit.evaluator.scenario_derivation_analysis_rule_identity import (
    HANDLERS as _ANALYSIS_RULE_IDENTITY_HANDLERS,
)
from ebm_audit.evaluator.scenario_derivation_candidate_strong import (
    HANDLERS as _CANDIDATE_STRONG_HANDLERS,
)
from ebm_audit.evaluator.scenario_derivation_false_positive import (
    HANDLERS as _FALSE_POSITIVE_HANDLERS,
)
from ebm_audit.evaluator.scenario_derivation_handler_protocol import (
    Handler,
    HandlerKey,
    HandlerRequest,
    HandlerResult,
)
from ebm_audit.evaluator.scenario_derivation_matched_metric import (
    _SELECTORS as _MATCHED_METRIC_SELECTORS,
)
from ebm_audit.evaluator.scenario_derivation_matched_metric import (
    HANDLERS as _MATCHED_METRIC_HANDLERS,
)
from ebm_audit.evaluator.scenario_derivation_missingness import (
    _MAR_MASK_KEY,
    _MCAR_MASK_KEY,
    _MISSING_COUNT_PRESERVATION_KEY,
)
from ebm_audit.evaluator.scenario_derivation_missingness import (
    HANDLERS as _MISSINGNESS_HANDLERS,
)
from ebm_audit.evaluator.scenario_derivation_nonfinite_admission import (
    HANDLERS as _NONFINITE_ADMISSION_HANDLERS,
)
from ebm_audit.evaluator.scenario_derivation_precedence import (
    HANDLERS as _PRECEDENCE_HANDLERS,
)
from ebm_audit.evaluator.scenario_derivation_report_predicate import (
    HANDLERS as _REPORT_PREDICATE_HANDLERS,
)
from ebm_audit.evaluator.scenario_derivation_truth_scoring import (
    HANDLERS as _TRUTH_SCORING_HANDLERS,
)
from ebm_audit.evaluator.scenario_evidence import (
    ScenarioEvidenceContextError,
    _AuthenticatedPublicSyntheticTruthContext,
    _AuthenticatedScenarioEvidenceContext,
    _read_authenticated_scenario_case,
    _read_public_synthetic_truth_context,
    _read_scenario_evidence_context,
    _read_scenario_source_owner_identities,
    _read_scenario_source_owner_records,
    _read_truth_scoring_source_owner_identities,
    _read_truth_scoring_source_owner_records,
)
from ebm_audit.evaluator.scenario_source_owner_manifest import (
    _read_case_source_owner_missingness_projection,
    _ScenarioSourceOwnerRecord,
)
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256_hex,
)
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.synthetic.audit_input import (
    SyntheticTruthScoringEvidence,
    _authenticate_public_synthetic_unprepared_result,
    _read_synthetic_truth_scoring_input_owner,
    _SyntheticMissingnessProjection,
)

_MAXIMUM_REGISTRY_BYTES: Final = 16 * 1024 * 1024
_AVAILABLE_OWNER_CLASSES: Final = frozenset(
    {
        "SYNTHETIC_TRUTH",
        "SYNTHETIC_SCIENTIFIC_DATA",
        "SCENARIO_MATCHED_METRIC_RECORD",
        "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
        "CANDIDATE_STRONG_EVIDENCE_DECISION",
    }
)
_OWNER_UNAVAILABLE: Final = "SCENARIO.DERIVATION_OWNER_UNAVAILABLE"
_REPORT_UNAVAILABLE: Final = "SCENARIO.REPORT_PREDICATE_NOT_ASSESSABLE"
_VALIDATOR_UNAVAILABLE: Final = "SCENARIO.DERIVATION_VALIDATOR_UNIMPLEMENTED"
_FAMILY_UNAVAILABLE: Final = "SCENARIO.FAMILY_PAYLOAD_NOT_ASSESSABLE"
_REPORT_OWNER_CLASS: Final = "REPORT_PREDICATE_OUTCOME"
_REPORT_OWNER_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/ReportPredicateOutcome"
)
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_PUBLIC_TRUTH_ALLOWED_DERIVATION_IDS: Final = frozenset({"truth-scoring-mode/1"})
_PUBLIC_TRUTH_ALLOWED_HANDLER_KEYS: Final = frozenset({_MCAR_MASK_KEY, _MAR_MASK_KEY})
_CORRELATED_TRUTH_SELECTORS: Final = frozenset(
    {
        "correlated-subtype-truth/1",
        "exact-duplicate-subtype-truth/1",
    }
)


def _reject(code: str) -> Never:
    raise InvalidInputError(
        f"EVALUATOR.FAMILY_EVIDENCE_PROJECTOR_{code}",
        "Authenticated family evidence projection failed closed validation.",
    )


@dataclass(frozen=True, slots=True)
class _OwnerSlotSpec:
    owner_class: str
    cardinality: str
    selector: str


@dataclass(frozen=True, slots=True)
class _OutputSpec:
    output_path: str
    derivation_id: str
    owner_slots: tuple[_OwnerSlotSpec, ...]


@dataclass(frozen=True, slots=True)
class _FamilySpec:
    family_id: str
    predicate_id: str
    outputs: tuple[_OutputSpec, ...]


@dataclass(frozen=True, slots=True)
class _CompiledCoverage:
    families: tuple[_FamilySpec, ...]
    output_count: int


@dataclass(frozen=True, slots=True)
class _UnavailableOwnerSlot:
    output_path: str
    owner_class: str
    cardinality: str
    selector: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class _FamilyEvidenceView:
    family_id: str
    predicate_id: str
    case_id: str
    evidence_state: Literal["ASSESSABLE", "NOT_ASSESSABLE"]
    payload: dict[str, object] | None
    covered_output_count: int
    unavailable_output_count: int
    missing_owner_slots: tuple[_UnavailableOwnerSlot, ...]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _FamilyEvidenceState:
    projection_bytes: bytes
    coverage: _CompiledCoverage
    context: _AuthenticatedScenarioEvidenceContext | _AuthenticatedPublicSyntheticTruthContext
    authenticated_plan: AuthenticatedDirectOperationPlan | None
    binding_receipt: AuthenticatedPlanRowBindingReceipt | None
    public_truth_source: SyntheticTruthScoringEvidence | None
    report_outcomes: tuple[ReportPredicateOutcome, ...]
    handler_results: tuple[HandlerResult, ...]
    registered_handler_keys: tuple[HandlerKey, ...]
    incomplete_handler_slots: tuple[tuple[HandlerKey, tuple[_OwnerSlotSpec, ...]], ...]


@dataclass(frozen=True, slots=True)
class _HandlerExecution:
    results: tuple[HandlerResult, ...]
    registered_keys: tuple[HandlerKey, ...]
    incomplete_slots: tuple[tuple[HandlerKey, tuple[_OwnerSlotSpec, ...]], ...]


@dataclass(frozen=True, slots=True)
class _OwnerResolverRequest:
    key: HandlerKey
    slot_index: int
    slot: tuple[str, str, str]
    family_id: str
    case_id: str
    owner_natural_identities: tuple[Mapping[str, object], ...]


@dataclass(frozen=True, slots=True)
class _OwnerResolverResult:
    key: HandlerKey
    slot_index: int
    slot: tuple[str, str, str]
    expected_natural_identities: tuple[Mapping[str, object], ...]


type _OwnerResolver = Callable[[_OwnerResolverRequest], _OwnerResolverResult]


@dataclass(frozen=True, slots=True)
class _ResolverRegistration:
    key: HandlerKey
    slot_index: int
    slot: tuple[str, str, str]
    resolver: _OwnerResolver


@dataclass(frozen=True, slots=True)
class _HandlerRegistration:
    key: HandlerKey
    handler: Handler
    resolvers: tuple[_ResolverRegistration, ...]


_FAMILY_EVIDENCE_STATES: OneShotWeakRegistry[object, _FamilyEvidenceState]
_FAMILY_EVIDENCE_STATES, _FAMILY_EVIDENCE_ISSUER = create_one_shot_registry()


@final
class _FamilyEvidenceProjection:
    """Opaque one-shot owner of one authenticated family evidence projection."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _FamilyEvidenceProjection:
        raise TypeError("Family evidence projections are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Family evidence projections cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Family evidence projections are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Family evidence projections cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Family evidence projections cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Family evidence projections cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Family evidence projections cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Family evidence projections cannot be copied or serialized.")

    def __repr__(self) -> str:
        _read_family_evidence_projection(self)
        return "_FamilyEvidenceProjection(<opaque>)"


def _compiled_coverage() -> _CompiledCoverage:
    """Compile the two frozen public registries without retaining mutable input."""

    predicate_registry_bytes, _proportional_contract_bytes, registry_bytes = (
        _frozen_evaluator_source_bytes()
    )
    try:
        registry_value = strict_json_loads(registry_bytes)
        contract_value = load_strict_yaml_bytes(
            predicate_registry_bytes,
            maximum_bytes=_MAXIMUM_REGISTRY_BYTES,
        )
    except (CanonicalizationError, StrictYamlError):
        _reject("REGISTRY_READ")
    try:
        validate_instance(registry_value, "scenario-derivation-registry.schema.json")
    except SchemaValidationError:
        _reject("DERIVATION_REGISTRY")
    if type(registry_value) is not dict or type(contract_value) is not dict:
        _reject("REGISTRY_SHAPE")
    registry = cast(dict[str, Any], registry_value)
    predicate_registry = contract_value.get("scenario_predicate_registry")
    try:
        validate_instance(predicate_registry, "scenario-predicate.schema.json")
    except SchemaValidationError:
        _reject("PREDICATE_REGISTRY")
    families_value = registry.get("families")
    family_order = registry.get("family_order")
    semantic = registry.get("semantic_validation")
    predicate_rows = (
        predicate_registry.get("predicates") if type(predicate_registry) is dict else None
    )
    if (
        type(families_value) is not list
        or type(family_order) is not list
        or type(semantic) is not dict
        or type(predicate_rows) is not list
        or semantic.get("covered_family_output_count") != 102
        or type(semantic.get("implemented_output_validators")) is not list
        or semantic.get("default_validator_implementation_status") != "UNIMPLEMENTED"
        or semantic.get("scientific_pass_eligible") is not False
    ):
        _reject("SEMANTIC_REGISTRY")
    predicate_identity = tuple(
        (row.get("family_id"), row.get("predicate_id"))
        for row in predicate_rows
        if type(row) is dict
    )
    compiled: list[_FamilySpec] = []
    for family_value in families_value:
        if type(family_value) is not dict:
            _reject("FAMILY_SHAPE")
        family = cast(dict[str, Any], family_value)
        outputs_value = family.get("outputs")
        if type(outputs_value) is not list:
            _reject("OUTPUT_SHAPE")
        outputs: list[_OutputSpec] = []
        for output_value in outputs_value:
            if type(output_value) is not dict:
                _reject("OUTPUT_SHAPE")
            output = cast(dict[str, Any], output_value)
            slots_value = output.get("owner_slots")
            if type(slots_value) is not list:
                _reject("SLOT_SHAPE")
            slots = tuple(
                _OwnerSlotSpec(
                    owner_class=cast(str, slot["owner_class"]),
                    cardinality=cast(str, slot["cardinality"]),
                    selector=cast(str, slot["selector"]),
                )
                for slot in slots_value
                if type(slot) is dict
            )
            if len(slots) != len(slots_value):
                _reject("SLOT_SHAPE")
            outputs.append(
                _OutputSpec(
                    output_path=cast(str, output["output_path"]),
                    derivation_id=cast(str, output["derivation_id"]),
                    owner_slots=slots,
                )
            )
        compiled.append(
            _FamilySpec(
                family_id=cast(str, family["family_id"]),
                predicate_id=cast(str, family["predicate_id"]),
                outputs=tuple(outputs),
            )
        )
    families = tuple(compiled)
    if (
        tuple(family.family_id for family in families) != tuple(family_order)
        or tuple((family.family_id, family.predicate_id) for family in families)
        != predicate_identity
        or len(families) != 23
        or sum(len(family.outputs) for family in families) != 102
    ):
        _reject("COVERAGE")
    return _CompiledCoverage(families=families, output_count=102)


def _family_for(coverage: _CompiledCoverage, family_id: str) -> _FamilySpec:
    matches = tuple(family for family in coverage.families if family.family_id == family_id)
    if len(matches) != 1:
        _reject("FAMILY")
    return matches[0]


def _projection_case(
    context: (_AuthenticatedScenarioEvidenceContext | _AuthenticatedPublicSyntheticTruthContext),
) -> Any:
    if type(context) is _AuthenticatedScenarioEvidenceContext:
        return _read_authenticated_scenario_case(context)[1]
    if type(context) is _AuthenticatedPublicSyntheticTruthContext:
        return _read_public_synthetic_truth_context(context).case
    _reject("CONTEXT")


def _validated_report_outcomes(
    context: (_AuthenticatedScenarioEvidenceContext | _AuthenticatedPublicSyntheticTruthContext),
    outcomes: tuple[ReportPredicateOutcome, ...],
) -> dict[tuple[str, str], dict[str, object]]:
    if type(context) is _AuthenticatedPublicSyntheticTruthContext:
        _read_public_synthetic_truth_context(context)
        if outcomes != ():
            _reject("REPORT_COVERAGE")
        return {}
    if type(context) is not _AuthenticatedScenarioEvidenceContext:
        _reject("CONTEXT")
    case = _read_authenticated_scenario_case(context)[1]
    expected = tuple(
        (policy.predicate_id, member_id)
        for policy in _policies_for(case)
        for member_id in _cardinality_members(policy, case)
    )
    if type(outcomes) is not tuple or len(outcomes) != len(expected):
        _reject("REPORT_COVERAGE")
    projections: dict[tuple[str, str], dict[str, object]] = {}
    for outcome, identity in zip(outcomes, expected, strict=True):
        if (
            type(outcome) is not ReportPredicateOutcome
            or _read_report_predicate_outcome_context(outcome) is not context
        ):
            _reject("REPORT_CONTEXT")
        projection = _read_report_predicate_outcome(outcome)
        observed = (
            projection.get("predicate_id"),
            projection.get("cardinality_member_id"),
        )
        if observed != identity or observed in projections:
            _reject("REPORT_IDENTITY")
        projections[observed] = projection
    return projections


def _missing_slot(
    output: _OutputSpec,
    slot: _OwnerSlotSpec,
    reason_code: str,
) -> _UnavailableOwnerSlot:
    try:
        validate_instance(
            {
                "output_path": output.output_path,
                "owner_class": slot.owner_class,
                "reason_code": reason_code,
            },
            "scenario-evidence.schema.json",
            definition="MissingOwnerSlot",
        )
    except SchemaValidationError:
        _reject("MISSING_SLOT")
    return _UnavailableOwnerSlot(
        output_path=output.output_path,
        owner_class=slot.owner_class,
        cardinality=slot.cardinality,
        selector=slot.selector,
        reason_code=reason_code,
    )


def _handler_key(family: _FamilySpec, output: _OutputSpec) -> HandlerKey:
    return (
        "FAMILY_OUTPUT",
        family.family_id,
        output.output_path,
        output.derivation_id,
        tuple((slot.owner_class, slot.cardinality, slot.selector) for slot in output.owner_slots),
    )


def _compiled_handler_keys(coverage: _CompiledCoverage) -> tuple[HandlerKey, ...]:
    keys = tuple(
        _handler_key(family, output) for family in coverage.families for output in family.outputs
    )
    if len(keys) != coverage.output_count or len(set(keys)) != len(keys):
        _reject("HANDLER_KEYS")
    return keys


_HISTORICAL_DECLARED_HANDLERS: Final[tuple[tuple[HandlerKey, Handler], ...]] = (
    *_FALSE_POSITIVE_HANDLERS,
    *_TRUTH_SCORING_HANDLERS,
    *_MISSINGNESS_HANDLERS,
    *_NONFINITE_ADMISSION_HANDLERS,
    *_ACTUAL_REMOVED_ROWS_HANDLERS,
    *_ANALYSIS_RULE_IDENTITY_HANDLERS,
    *_CANDIDATE_STRONG_HANDLERS,
    *_REPORT_PREDICATE_HANDLERS,
    *_MATCHED_METRIC_HANDLERS,
    *_PRECEDENCE_HANDLERS,
)

_EXECUTED_ANALYSIS_RULE_KEY: Final[HandlerKey] = (
    "FAMILY_OUTPUT",
    "group_boundary_sensitivity",
    "/payload/ordered_rule_ids",
    "analysis-rule-identities/1",
    (
        (
            "EXECUTED_BOUNDARY_RULE_IDENTITY",
            "ONE_PER_DECLARED_RULE",
            "executed-boundary-rule-plan-order/1",
        ),
    ),
)
_EXECUTED_MISSING_COUNT_PRESERVATION_KEY: Final[HandlerKey] = (
    "FAMILY_OUTPUT",
    "within_group_feature_permutation_null",
    "/payload/missing_counts_preserved",
    "missing-count-preservation/1",
    (
        (
            "EXECUTED_TRANSFORMATION_EVIDENCE",
            "ONE_PER_CASE",
            "same-case-feature-permutation-transformation/1",
        ),
    ),
)


def _handle_executed_analysis_rule_identities(request: HandlerRequest) -> HandlerResult:
    key = _EXECUTED_ANALYSIS_RULE_KEY
    reason_code = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
    try:
        if type(request) is not HandlerRequest or request.key != key:
            raise ValueError
        if len(request.owner_projections) != 1 or len(request.owner_projections[0]) != 3:
            raise ValueError
        context = _read_scenario_evidence_context(request.context)
        expected = (
            ("boundary_q50", 0.50, 0),
            ("boundary_q35", 0.35, 1),
            ("boundary_q65", 0.65, 2),
        )
        rule_ids: list[str] = []
        for record, (rule_id, quantile, member_index) in zip(
            request.owner_projections[0], expected, strict=True
        ):
            source = _plain_json(record.source_record)
            natural_identity = _plain_json(record.natural_identity)
            if type(source) is not dict or type(natural_identity) is not dict:
                raise ValueError
            validate_instance(
                source,
                "scenario-evidence.schema.json",
                definition="ExecutedBoundaryRuleIdentity",
            )
            if (
                record.owner_class != "EXECUTED_BOUNDARY_RULE_IDENTITY"
                or record.owner_schema_ref
                != "schemas/scenario-evidence.schema.json#/$defs/ExecutedBoundaryRuleIdentity"
                or source.get("family_id") != context.identity.family_id
                or source.get("case_id") != context.identity.case_id
                or source.get("rule_id") != rule_id
                or source.get("cutoff_quantile") != quantile
                or source.get("comparator_member_index") != member_index
                or natural_identity
                != {
                    "case_operation_join_key": source.get("case_operation_join_key"),
                    "rule_id": rule_id,
                    "analysis_spec_sha256": source.get("analysis_spec_sha256"),
                }
                or record.source_record_sha256
                != structured_sha256_hex(
                    _SOURCE_RECORD_DOMAIN,
                    {
                        "owner_class": record.owner_class,
                        "natural_identity": natural_identity,
                        "source_record": source,
                    },
                )
            ):
                raise ValueError
            rule_ids.append(rule_id)
        return HandlerResult(key, "PASS", rule_ids, ())
    except Exception:
        return HandlerResult(key, "FAIL", None, (reason_code,))


_LEGACY_MISSING_COUNT_PRESERVATION_HANDLER: Final = dict(_MISSINGNESS_HANDLERS)[
    _MISSING_COUNT_PRESERVATION_KEY
]


def _handle_executed_missing_count_preservation(request: HandlerRequest) -> HandlerResult:
    key = _EXECUTED_MISSING_COUNT_PRESERVATION_KEY
    if type(request) is not HandlerRequest or request.key != key:
        return HandlerResult(
            key,
            "FAIL",
            None,
            ("SCENARIO.DERIVATION_REQUEST_INVALID",),
        )
    legacy = _LEGACY_MISSING_COUNT_PRESERVATION_HANDLER(
        HandlerRequest(
            key=_MISSING_COUNT_PRESERVATION_KEY,
            context=request.context,
            owner_projections=request.owner_projections,
        )
    )
    return HandlerResult(key, legacy.state, legacy.value, legacy.reason_codes)


_ADAPTED_CURRENT_HANDLERS: Final[tuple[tuple[HandlerKey, Handler], ...]] = (
    (_EXECUTED_ANALYSIS_RULE_KEY, _handle_executed_analysis_rule_identities),
    (
        _EXECUTED_MISSING_COUNT_PRESERVATION_KEY,
        _handle_executed_missing_count_preservation,
    ),
)

# Registry 2.1 retained 62 exact runtime identities.  Three historical
# declarations no longer have those identities: analysis-rule identity and
# missing-count preservation have replacement public owner slots, while the
# old false-positive bundle has been replaced by a report-dependent
# qualification state.  Keep the reusable implementations importable in their
# owning modules, but do not register them under a different identity or imply
# that their new ordinary owners exist.
_DECLARED_HANDLERS: Final[tuple[tuple[HandlerKey, Handler], ...]] = tuple(
    declaration
    for declaration in _HISTORICAL_DECLARED_HANDLERS
    if declaration[0] in _compiled_handler_keys(_compiled_coverage())
) + _ADAPTED_CURRENT_HANDLERS


def _adapt_declared_handler(declared_key: HandlerKey, handler: Handler) -> Handler:
    def adapted(request: HandlerRequest) -> HandlerResult:
        if type(request) is not HandlerRequest or request.key != declared_key:
            _reject("HANDLER_REQUEST_KEY")
        result = handler(request)
        if type(result) is not HandlerResult or result.key is not declared_key:
            _reject("HANDLER_RESULT_KEY")
        return HandlerResult(
            key=request.key,
            state=_literal_handler_state(result.state),
            value=_plain_json(result.value),
            reason_codes=result.reason_codes,
        )

    return adapted


def _resolve_source_owner_identities(
    request: _OwnerResolverRequest,
) -> _OwnerResolverResult:
    return _OwnerResolverResult(
        key=request.key,
        slot_index=request.slot_index,
        slot=request.slot,
        expected_natural_identities=request.owner_natural_identities,
    )


def _resolve_matched_metric_record(
    request: _OwnerResolverRequest,
) -> _OwnerResolverResult:
    selector = request.slot[2]
    try:
        roles, metric_id, _mode = _MATCHED_METRIC_SELECTORS[selector]
    except KeyError:
        _reject("SLOT_RESOLUTION")
    expected = tuple(
        identity
        for identity in request.owner_natural_identities
        if identity.get("metric_id") == metric_id
        and {identity.get("left_member_id"), identity.get("right_member_id")} == set(roles)
    )
    return _OwnerResolverResult(
        key=request.key,
        slot_index=request.slot_index,
        slot=request.slot,
        expected_natural_identities=expected,
    )


def _build_derivation_handler_registry(
    compiled_keys: tuple[HandlerKey, ...],
    declared_handlers: tuple[tuple[HandlerKey, Handler], ...],
) -> MappingProxyType[HandlerKey, _HandlerRegistration | None]:
    if (
        type(compiled_keys) is not tuple
        or len(compiled_keys) != 102
        or len(set(compiled_keys)) != len(compiled_keys)
        or type(declared_handlers) is not tuple
        or len(declared_handlers) != 64
    ):
        _reject("HANDLER_DECLARATIONS")
    compiled_key_set = set(compiled_keys)
    handlers_by_key: dict[HandlerKey, Handler] = {}
    for declaration in declared_handlers:
        if type(declaration) is not tuple or len(declaration) != 2:
            _reject("HANDLER_DECLARATIONS")
        declared_key, handler = declaration
        if (
            declared_key in handlers_by_key
            or declared_key not in compiled_key_set
            or not callable(handler)
        ):
            _reject("HANDLER_DECLARATIONS")
        handlers_by_key[declared_key] = handler
    registry: dict[HandlerKey, _HandlerRegistration | None] = {}
    for compiled_key in compiled_keys:
        declared_handler = handlers_by_key.get(compiled_key)
        if declared_handler is None:
            registry[compiled_key] = None
            continue
        declared_key = next(key for key in handlers_by_key if key == compiled_key)
        registry[compiled_key] = _HandlerRegistration(
            key=compiled_key,
            handler=_adapt_declared_handler(declared_key, declared_handler),
            resolvers=tuple(
                _ResolverRegistration(
                    key=compiled_key,
                    slot_index=index,
                    slot=slot,
                    resolver=(
                        _resolve_report_predicate_outcome
                        if slot[0] == "REPORT_PREDICATE_OUTCOME"
                        else _resolve_matched_metric_record
                        if slot[0] == "SCENARIO_MATCHED_METRIC_RECORD"
                        else _resolve_source_owner_identities
                    ),
                )
                for index, slot in enumerate(compiled_key[4])
            ),
        )
    if sum(registration is not None for registration in registry.values()) != 64:
        _reject("HANDLER_DECLARATIONS")
    return MappingProxyType(registry)


def _plain_json(value: object, active_container_ids: set[int] | None = None) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("handler values must contain only finite floats")
        return value
    if not isinstance(value, Mapping) and type(value) not in (list, tuple):
        raise TypeError("handler values must contain only JSON-like values")
    if active_container_ids is None:
        active_container_ids = set()
    container_id = id(value)
    if container_id in active_container_ids:
        raise ValueError("handler values must not contain cycles")
    active_container_ids.add(container_id)
    try:
        if isinstance(value, Mapping):
            if any(type(key) is not str for key in value):
                raise TypeError("handler value object keys must be strings")
            return {
                cast(str, key): _plain_json(child, active_container_ids)
                for key, child in value.items()
            }
        return [
            _plain_json(child, active_container_ids)
            for child in cast(list[object] | tuple[object, ...], value)
        ]
    finally:
        active_container_ids.remove(container_id)


def _literal_handler_state(value: object) -> Literal["PASS", "FAIL"]:
    if type(value) is not str or value not in ("PASS", "FAIL"):
        _reject("HANDLER_RESULT")
    return "PASS" if value == "PASS" else "FAIL"


def _validated_handler_registry(
    coverage: _CompiledCoverage,
) -> Mapping[HandlerKey, _HandlerRegistration | None]:
    expected_keys = _compiled_handler_keys(coverage)
    registry = _DERIVATION_HANDLER_REGISTRY
    if type(registry) is not MappingProxyType or tuple(registry) != expected_keys:
        _reject("HANDLER_REGISTRY")
    for key in expected_keys:
        registration = registry[key]
        if registration is None:
            continue
        if (
            type(registration) is not _HandlerRegistration
            or registration.key != key
            or not callable(registration.handler)
            or type(registration.resolvers) is not tuple
            or len(registration.resolvers) != len(key[4])
        ):
            _reject("HANDLER_REGISTRY")
        for index, (slot, resolver) in enumerate(zip(key[4], registration.resolvers, strict=True)):
            if (
                type(resolver) is not _ResolverRegistration
                or resolver.key != key
                or type(resolver.slot_index) is not int
                or resolver.slot_index != index
                or type(resolver.slot) is not tuple
                or resolver.slot != slot
                or not callable(resolver.resolver)
            ):
                _reject("HANDLER_REGISTRY")
    if len(expected_keys) == 102 and (
        sum(registration is not None for registration in registry.values()) != 64
        or sum(registration is None for registration in registry.values()) != 38
    ):
        _reject("HANDLER_REGISTRY")
    return registry


def _set_payload_value(payload: dict[str, object], output_path: str, value: object) -> None:
    prefix = "/payload/"
    if not output_path.startswith(prefix):
        _reject("OUTPUT_PATH")
    parts = output_path.removeprefix(prefix).split("/")
    if not parts or any(not part for part in parts):
        _reject("OUTPUT_PATH")
    target = payload
    for part in parts[:-1]:
        child = target.get(part)
        if child is None:
            nested: dict[str, object] = {}
            target[part] = nested
            target = nested
        elif type(child) is dict:
            target = cast(dict[str, object], child)
        else:
            _reject("OUTPUT_PATH")
    if parts[-1] in target:
        _reject("OUTPUT_PATH")
    try:
        target[parts[-1]] = _plain_json(value)
    except Exception:
        _reject("HANDLER_RESULT")


def _record_coordinate(
    record: _ScenarioSourceOwnerRecord,
) -> tuple[str | None, str | None]:
    mappings: list[Mapping[str, object]] = [record.natural_identity, record.source_record]
    scenario_identity = record.source_record.get("scenario_identity")
    if isinstance(scenario_identity, Mapping):
        mappings.append(cast(Mapping[str, object], scenario_identity))
    family_values = {
        value
        for mapping in mappings
        for value in (mapping.get("family_id", mapping.get("scenario_family_id")),)
        if type(value) is str
    }
    case_values = {
        value for mapping in mappings for value in (mapping.get("case_id"),) if type(value) is str
    }
    ordered_case_ids = record.source_record.get("ordered_case_ids")
    if type(ordered_case_ids) is tuple and len(ordered_case_ids) == 1:
        ordered_case_id = ordered_case_ids[0]
        if type(ordered_case_id) is str:
            case_values.add(ordered_case_id)
    if len(family_values) > 1 or len(case_values) > 1:
        _reject("SLOT_COORDINATE")
    return (
        next(iter(family_values), None),
        next(iter(case_values), None),
    )


def _report_slot_identities(
    report_by_identity: Mapping[tuple[str, str], dict[str, object]],
    selector: str,
) -> tuple[tuple[str, str], ...]:
    return tuple(identity for identity in report_by_identity if identity[0] == selector)


_REPORT_NATURAL_IDENTITY_FIELDS: Final = (
    "benchmark_subject_digest",
    "family_id",
    "predicate_id",
    "cardinality_member_id",
    "report_artifact_sha256",
)


def _report_natural_identity(projection: Mapping[str, object]) -> dict[str, str]:
    identity = {field: projection.get(field) for field in _REPORT_NATURAL_IDENTITY_FIELDS}
    if any(type(value) is not str or not value for value in identity.values()):
        _reject("REPORT_IDENTITY")
    return cast(dict[str, str], identity)


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {cast(str, key): _freeze_json(child) for key, child in value.items()}
        )
    if type(value) is list:
        return tuple(_freeze_json(child) for child in cast(list[object], value))
    return value


def _report_source_records(
    report_outcomes: tuple[ReportPredicateOutcome, ...],
) -> tuple[_ScenarioSourceOwnerRecord, ...]:
    records: list[_ScenarioSourceOwnerRecord] = []
    for outcome in report_outcomes:
        projection = _read_report_predicate_outcome(outcome)
        identity = _report_natural_identity(projection)
        frozen_projection = _freeze_json(projection)
        if type(frozen_projection) is not MappingProxyType:
            _reject("REPORT_IDENTITY")
        records.append(
            _ScenarioSourceOwnerRecord(
                owner_class=_REPORT_OWNER_CLASS,
                owner_schema_ref=_REPORT_OWNER_SCHEMA_REF,
                natural_identity=MappingProxyType(identity),
                source_record=cast(Mapping[str, object], frozen_projection),
                source_record_sha256=structured_sha256_hex(
                    _SOURCE_RECORD_DOMAIN,
                    {
                        "owner_class": _REPORT_OWNER_CLASS,
                        "natural_identity": identity,
                        "source_record": projection,
                    },
                ),
                ordered_support_owner_sha256=(),
                source_capability=outcome,
            )
        )
    return tuple(records)


def _natural_identity_value(value: object) -> bool:
    try:
        canonical_json_bytes(_plain_json(value))
    except (CanonicalizationError, TypeError, ValueError):
        return False
    return True


def _validated_source_owner_identities(
    value: object,
) -> tuple[tuple[str, Mapping[str, object]], ...]:
    if type(value) is not tuple or not value:
        _reject("OWNER_IDENTITIES")
    validated: list[tuple[str, Mapping[str, object]]] = []
    seen: set[tuple[str, bytes]] = set()
    for row in value:
        if type(row) is not tuple or len(row) != 2:
            _reject("OWNER_IDENTITIES")
        owner_class, identity = row
        if (
            type(owner_class) is not str
            or not owner_class
            or type(identity) is not MappingProxyType
            or not identity
            or any(type(key) is not str for key in identity)
            or any(not _natural_identity_value(item) for item in identity.values())
        ):
            _reject("OWNER_IDENTITIES")
        detached = dict(identity)
        try:
            identity_bytes = canonical_json_bytes(_plain_json(detached))
        except (CanonicalizationError, TypeError, ValueError):
            _reject("OWNER_IDENTITIES")
        identity_key = (owner_class, identity_bytes)
        if identity_key in seen:
            _reject("OWNER_IDENTITIES")
        seen.add(identity_key)
        validated.append((owner_class, MappingProxyType(detached)))
    return tuple(validated)


def _validated_report_source_records(
    records: tuple[_ScenarioSourceOwnerRecord, ...],
    report_by_identity: Mapping[tuple[str, str], dict[str, object]],
    *,
    family_id: str,
    case_id: str,
) -> None:
    expected = tuple(
        _report_natural_identity(projection) for projection in report_by_identity.values()
    )
    expected_bytes = tuple(canonical_json_bytes(identity) for identity in expected)
    report_records = tuple(
        record for record in records if record.owner_class == "REPORT_PREDICATE_OUTCOME"
    )
    observed_positions: list[int] = []
    observed_bytes: list[bytes] = []
    for record in report_records:
        identity = dict(record.natural_identity)
        try:
            identity_bytes = canonical_json_bytes(identity)
            position = expected_bytes.index(identity_bytes)
        except (CanonicalizationError, ValueError):
            _reject("REPORT_IDENTITY")
        observed_family, observed_case = _record_coordinate(record)
        if (
            identity != expected[position]
            or observed_family != family_id
            or observed_case != case_id
            or any(
                record.source_record.get(field) != value
                for field, value in expected[position].items()
            )
            or record.source_record.get("ordered_case_ids") != (case_id,)
        ):
            _reject("REPORT_IDENTITY")
        observed_positions.append(position)
        observed_bytes.append(identity_bytes)
    if (
        observed_positions != sorted(observed_positions)
        or len(set(observed_positions)) != len(observed_positions)
        or len(set(observed_bytes)) != len(observed_bytes)
    ):
        _reject("REPORT_IDENTITY")


def _resolve_report_predicate_outcome(
    request: _OwnerResolverRequest,
) -> _OwnerResolverResult:
    selector = request.slot[2]
    expected = tuple(
        identity
        for identity in request.owner_natural_identities
        if identity.get("predicate_id") == selector
    )
    return _OwnerResolverResult(
        key=request.key,
        slot_index=request.slot_index,
        slot=request.slot,
        expected_natural_identities=expected,
    )


_COMPILED_HANDLER_KEYS: Final = _compiled_handler_keys(_compiled_coverage())
_DERIVATION_HANDLER_REGISTRY: Final[Mapping[HandlerKey, _HandlerRegistration | None]] = (
    _build_derivation_handler_registry(_COMPILED_HANDLER_KEYS, _DECLARED_HANDLERS)
)


def _validated_resolver_result(
    request: _OwnerResolverRequest,
    registration: _ResolverRegistration,
) -> _OwnerResolverResult:
    try:
        resolved = registration.resolver(request)
    except Exception:
        _reject("SLOT_RESOLUTION")
    if (
        type(resolved) is not _OwnerResolverResult
        or resolved.key is not request.key
        or type(resolved.slot_index) is not int
        or resolved.slot_index != request.slot_index
        or resolved.slot is not request.slot
        or type(resolved.expected_natural_identities) is not tuple
    ):
        _reject("SLOT_RESOLUTION")
    try:
        expected_identities = tuple(
            dict(identity)
            for identity in resolved.expected_natural_identities
            if isinstance(identity, Mapping)
            and all(type(key) is str for key in identity)
            and all(_natural_identity_value(value) for value in identity.values())
        )
        expected_identity_bytes = tuple(
            canonical_json_bytes(identity) for identity in expected_identities
        )
    except (CanonicalizationError, TypeError, ValueError):
        _reject("SLOT_RESOLUTION")
    if len(expected_identity_bytes) != len(resolved.expected_natural_identities) or len(
        set(expected_identity_bytes)
    ) != len(expected_identity_bytes):
        _reject("SLOT_RESOLUTION")
    requested_identities = (
        tuple(
            identity
            for identity in request.owner_natural_identities
            if identity.get("predicate_id") == request.slot[2]
        )
        if request.slot[0] == "REPORT_PREDICATE_OUTCOME"
        else request.owner_natural_identities
    )
    try:
        requested_identity_bytes = tuple(
            canonical_json_bytes(dict(identity)) for identity in requested_identities
        )
    except (CanonicalizationError, TypeError, ValueError):
        _reject("SLOT_RESOLUTION")
    if expected_identity_bytes != requested_identity_bytes:
        _reject("SLOT_RESOLUTION")
    return _OwnerResolverResult(
        key=request.key,
        slot_index=request.slot_index,
        slot=request.slot,
        expected_natural_identities=tuple(
            MappingProxyType(identity) for identity in expected_identities
        ),
    )


def _projector_selected_records(
    request: _OwnerResolverRequest,
    resolved: _OwnerResolverResult,
    records: tuple[_ScenarioSourceOwnerRecord, ...],
    report_by_identity: Mapping[tuple[str, str], dict[str, object]],
) -> tuple[_ScenarioSourceOwnerRecord, ...]:
    expected_identities = tuple(dict(identity) for identity in resolved.expected_natural_identities)
    expected_identity_bytes = tuple(
        canonical_json_bytes(identity) for identity in expected_identities
    )
    exact_report_expected: tuple[dict[str, str], ...] | None = None
    if request.slot[0] == "REPORT_PREDICATE_OUTCOME":
        exact_report_expected = tuple(
            _report_natural_identity(report_by_identity[identity])
            for identity in _report_slot_identities(report_by_identity, request.slot[2])
        )
        if expected_identities != exact_report_expected:
            _reject("REPORT_IDENTITY")
    owner_records = tuple(record for record in records if record.owner_class == request.slot[0])
    matching_records = (
        tuple(
            record
            for record in owner_records
            if record.natural_identity.get("predicate_id") == request.slot[2]
        )
        if exact_report_expected is not None
        else owner_records
    )
    if not matching_records:
        return ()
    try:
        observed_identity_bytes = tuple(
            canonical_json_bytes(dict(record.natural_identity)) for record in matching_records
        )
    except (CanonicalizationError, TypeError, ValueError):
        _reject("SLOT_RECORDS")
    if observed_identity_bytes != expected_identity_bytes:
        _reject("SLOT_RECORDS")
    for record, expected_identity in zip(matching_records, expected_identities, strict=True):
        if record.owner_class != request.slot[0]:
            _reject("SLOT_RECORDS")
        if dict(record.natural_identity) != expected_identity:
            _reject("SLOT_RECORDS")
    correlated_truth_slot = (
        request.slot[0] == "SYNTHETIC_TRUTH" and request.slot[2] in _CORRELATED_TRUTH_SELECTORS
    )
    if correlated_truth_slot:
        coordinates = tuple(_record_coordinate(record) for record in matching_records)
        case_ids = tuple(case_id for _family_id, case_id in coordinates)
        if (
            request.family_id != "correlated_duplicate_events"
            or len(coordinates) != 2
            or any(family_id != request.family_id for family_id, _case_id in coordinates)
            or any(type(case_id) is not str or not case_id for case_id in case_ids)
            or len(set(case_ids)) != 2
            or request.case_id not in case_ids
        ):
            _reject("SLOT_COORDINATE")
    elif request.slot[0] not in {
        "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION",
        "CANDIDATE_STRONG_EVIDENCE_DECISION",
    }:
        for record in matching_records:
            if record.owner_class == "ANALYSIS_RULE_IDENTITY":
                continue
            observed_family, observed_case = _record_coordinate(record)
            exact_scientific_data_case = (
                record.owner_class == "SYNTHETIC_SCIENTIFIC_DATA"
                and observed_family is None
                and observed_case == request.case_id
            )
            if not exact_scientific_data_case and (
                observed_family != request.family_id or observed_case != request.case_id
            ):
                _reject("SLOT_COORDINATE")
    if exact_report_expected is not None:
        for record, report_identity in zip(matching_records, exact_report_expected, strict=True):
            if (
                dict(record.natural_identity) != report_identity
                or any(
                    record.source_record.get(field) != value
                    for field, value in report_identity.items()
                )
                or record.source_record.get("ordered_case_ids") != (request.case_id,)
            ):
                _reject("REPORT_IDENTITY")
    return matching_records


def _execute_registered_handlers(
    context: (_AuthenticatedScenarioEvidenceContext | _AuthenticatedPublicSyntheticTruthContext),
    family: _FamilySpec,
    registry: Mapping[HandlerKey, _HandlerRegistration | None],
    report_by_identity: Mapping[tuple[str, str], dict[str, object]],
    report_outcomes: tuple[ReportPredicateOutcome, ...],
    case_id: str,
) -> _HandlerExecution:
    registered = tuple(
        (registration.key, output, registration)
        for output in family.outputs
        if (registration := registry[_handler_key(family, output)]) is not None
        and (
            type(context) is _AuthenticatedScenarioEvidenceContext
            or output.derivation_id in _PUBLIC_TRUTH_ALLOWED_DERIVATION_IDS
            or registration.key in _PUBLIC_TRUTH_ALLOWED_HANDLER_KEYS
        )
    )
    registered_keys = tuple(key for key, _output, _handler in registered)
    if not registered:
        return _HandlerExecution((), (), ())

    try:
        source_owner_identities = _validated_source_owner_identities(
            _read_scenario_source_owner_identities(context)
            if type(context) is _AuthenticatedScenarioEvidenceContext
            else _read_truth_scoring_source_owner_identities(context)
        )
    except ScenarioEvidenceContextError:
        _reject("OWNER_GRAPH")
    missingness_pair: (
        tuple[_SyntheticMissingnessProjection, _SyntheticMissingnessProjection] | None
    ) = None
    if _EXECUTED_MISSING_COUNT_PRESERVATION_KEY in registered_keys:
        try:
            if type(context) is not _AuthenticatedScenarioEvidenceContext:
                _reject("OWNER_GRAPH")
            context_state = _read_scenario_evidence_context(context)
            missingness_pair = _read_case_source_owner_missingness_projection(
                context_state.batch, context_state.source_projection
            )
        except Exception:
            _reject("OWNER_GRAPH")
        if (
            type(missingness_pair) is not tuple
            or len(missingness_pair) != 2
            or any(
                type(projection) is not _SyntheticMissingnessProjection
                for projection in missingness_pair
            )
        ):
            _reject("OWNER_GRAPH")
    report_owner_identities = tuple(
        MappingProxyType(_report_natural_identity(projection))
        for projection in report_by_identity.values()
    )
    resolved_registrations: list[
        tuple[
            HandlerKey,
            _OutputSpec,
            _HandlerRegistration,
            tuple[tuple[_OwnerResolverRequest, _OwnerResolverResult], ...],
        ]
    ] = []
    for key, output, registration in registered:
        resolver_results: list[tuple[_OwnerResolverRequest, _OwnerResolverResult]] = []
        for index, _slot in enumerate(output.owner_slots):
            resolver_registration = registration.resolvers[index]
            owner_class = resolver_registration.slot[0]
            owner_natural_identities = (
                report_owner_identities
                if owner_class == "REPORT_PREDICATE_OUTCOME"
                else tuple(
                    identity
                    for identity_owner_class, identity in source_owner_identities
                    if missingness_pair is not None
                    and key == _MISSING_COUNT_PRESERVATION_KEY
                    and identity_owner_class == owner_class
                    and identity
                    == {
                        "case_id": missingness_pair[index].case_id,
                        "generated_scientific_data_sha256": (
                            missingness_pair[index].generated_scientific_data_sha256
                        ),
                    }
                )
                if key == _MISSING_COUNT_PRESERVATION_KEY
                else tuple(
                    identity
                    for identity_owner_class, identity in source_owner_identities
                    if identity_owner_class == owner_class
                )
            )
            request = _OwnerResolverRequest(
                key=key,
                slot_index=index,
                slot=resolver_registration.slot,
                family_id=family.family_id,
                case_id=case_id,
                owner_natural_identities=owner_natural_identities,
            )
            resolver_results.append(
                (
                    request,
                    _validated_resolver_result(request, resolver_registration),
                )
            )
        resolved_registrations.append((key, output, registration, tuple(resolver_results)))

    try:
        records = (
            *(
                _read_scenario_source_owner_records(context)
                if type(context) is _AuthenticatedScenarioEvidenceContext
                else _read_truth_scoring_source_owner_records(context)
            ),
            *_report_source_records(report_outcomes),
        )
    except ScenarioEvidenceContextError:
        _reject("OWNER_GRAPH")
    _validated_report_source_records(
        records,
        report_by_identity,
        family_id=family.family_id,
        case_id=case_id,
    )
    resolved: list[
        tuple[
            HandlerKey,
            Handler,
            tuple[tuple[_ScenarioSourceOwnerRecord, ...], ...],
        ]
    ] = []
    incomplete: list[tuple[HandlerKey, tuple[_OwnerSlotSpec, ...]]] = []
    for key, output, registration, validated_resolver_results in resolved_registrations:
        owner_projections: tuple[tuple[_ScenarioSourceOwnerRecord, ...], ...]
        if key == _EXECUTED_MISSING_COUNT_PRESERVATION_KEY:
            if missingness_pair is None:
                _reject("OWNER_GRAPH")
            selected_transformation = tuple(
                _projector_selected_records(
                    request,
                    resolver_result,
                    records,
                    report_by_identity,
                )
                for request, resolver_result in validated_resolver_results
            )
            if len(selected_transformation) != 1 or len(selected_transformation[0]) != 1:
                _reject("OWNER_GRAPH")
            owner_projections = tuple(
                cast(
                    tuple[_ScenarioSourceOwnerRecord, ...],
                    (projection,),
                )
                for projection in missingness_pair
            )
        else:
            owner_projections = tuple(
                _projector_selected_records(
                    request,
                    resolver_result,
                    records,
                    report_by_identity,
                )
                for request, resolver_result in validated_resolver_results
            )
        missing_slots = tuple(
            slot
            for slot, projection in zip(output.owner_slots, owner_projections, strict=True)
            if not projection
        )
        if missing_slots:
            incomplete.append((key, missing_slots))
        else:
            resolved.append((key, registration.handler, owner_projections))

    results: list[HandlerResult] = []
    for key, handler, owner_projections in resolved:
        try:
            result = handler(
                HandlerRequest(
                    key=key,
                    context=cast(_AuthenticatedScenarioEvidenceContext, context),
                    owner_projections=owner_projections,
                )
            )
        except Exception:
            _reject("HANDLER_EXECUTION")
        if type(result) is not HandlerResult or result.key is not key:
            _reject("HANDLER_RESULT")
        try:
            state = _literal_handler_state(result.state)
            results.append(
                HandlerResult(
                    key=key,
                    state=state,
                    value=_plain_json(result.value),
                    reason_codes=result.reason_codes,
                )
            )
        except Exception:
            _reject("HANDLER_RESULT")
    if len(results) + len(incomplete) != len(registered):
        _reject("HANDLER_COVERAGE")
    return _HandlerExecution(tuple(results), registered_keys, tuple(incomplete))


def _projection_value(
    context: (_AuthenticatedScenarioEvidenceContext | _AuthenticatedPublicSyntheticTruthContext),
    report_outcomes: tuple[ReportPredicateOutcome, ...],
    handler_results: tuple[HandlerResult, ...] = (),
    registered_handler_keys: tuple[HandlerKey, ...] = (),
    incomplete_handler_slots: tuple[tuple[HandlerKey, tuple[_OwnerSlotSpec, ...]], ...] = (),
    *,
    coverage: _CompiledCoverage | None = None,
) -> dict[str, object]:
    """Recompute the exact canonical NA projection from authenticated owners."""

    if type(context) not in {
        _AuthenticatedScenarioEvidenceContext,
        _AuthenticatedPublicSyntheticTruthContext,
    }:
        _reject("CONTEXT")
    case = _projection_case(context)
    exact_coverage = _compiled_coverage() if coverage is None else coverage
    if type(exact_coverage) is not _CompiledCoverage:
        _reject("COVERAGE")
    family = _family_for(exact_coverage, case.family_id)
    report_by_identity = _validated_report_outcomes(context, report_outcomes)
    outputs_by_key = {_handler_key(family, output): output for output in family.outputs}
    if (
        type(handler_results) is not tuple
        or type(registered_handler_keys) is not tuple
        or type(incomplete_handler_slots) is not tuple
        or len(set(registered_handler_keys)) != len(registered_handler_keys)
        or any(key not in outputs_by_key for key in registered_handler_keys)
    ):
        _reject("HANDLER_RESULT")
    results_by_key: dict[HandlerKey, HandlerResult] = {}
    for stored_result in handler_results:
        if (
            type(stored_result) is not HandlerResult
            or stored_result.key in results_by_key
            or stored_result.key not in registered_handler_keys
        ):
            _reject("HANDLER_RESULT")
        try:
            normalized_result = HandlerResult(
                key=stored_result.key,
                state=_literal_handler_state(stored_result.state),
                value=_plain_json(stored_result.value),
                reason_codes=stored_result.reason_codes,
            )
        except Exception:
            _reject("HANDLER_RESULT")
        results_by_key[stored_result.key] = normalized_result
    incomplete_by_key: dict[HandlerKey, tuple[_OwnerSlotSpec, ...]] = {}
    for item in incomplete_handler_slots:
        if type(item) is not tuple or len(item) != 2:
            _reject("HANDLER_RESULT")
        key, slots = item
        output = outputs_by_key.get(key)
        if (
            output is None
            or key not in registered_handler_keys
            or key in incomplete_by_key
            or key in results_by_key
            or type(slots) is not tuple
            or not slots
            or any(type(slot) is not _OwnerSlotSpec for slot in slots)
            or tuple(slot for slot in output.owner_slots if slot in slots) != slots
            or len(set(slots)) != len(slots)
        ):
            _reject("HANDLER_RESULT")
        incomplete_by_key[key] = slots
    if set(results_by_key) | set(incomplete_by_key) != set(registered_handler_keys):
        _reject("HANDLER_COVERAGE")
    missing: list[_UnavailableOwnerSlot] = []
    unavailable_outputs = 0
    payload: dict[str, object] = {}
    reason_codes: list[str] = []
    validator_unavailable = False
    for output in family.outputs:
        output_missing: list[_UnavailableOwnerSlot] = []
        key = _handler_key(family, output)
        result = results_by_key.get(key)
        incomplete_slots = incomplete_by_key.get(key, ())
        if incomplete_slots:
            output_missing.extend(
                _missing_slot(output, slot, _OWNER_UNAVAILABLE) for slot in incomplete_slots
            )
            reason_codes.append(_OWNER_UNAVAILABLE)
        elif key not in registered_handler_keys:
            validator_unavailable = True
            for slot in output.owner_slots:
                if slot.owner_class == "REPORT_PREDICATE_OUTCOME":
                    identities = _report_slot_identities(report_by_identity, slot.selector)
                    matching = tuple(report_by_identity[identity] for identity in identities)
                    if not identities:
                        output_missing.append(_missing_slot(output, slot, _OWNER_UNAVAILABLE))
                    elif any(
                        projection.get("derived_state") == "NOT_ASSESSABLE"
                        for projection in matching
                    ):
                        output_missing.append(_missing_slot(output, slot, _REPORT_UNAVAILABLE))
                elif slot.owner_class not in _AVAILABLE_OWNER_CLASSES:
                    output_missing.append(_missing_slot(output, slot, _OWNER_UNAVAILABLE))
            reason_codes.extend(slot.reason_code for slot in output_missing)
        if not output_missing and key not in registered_handler_keys:
            output_missing.append(
                _missing_slot(output, output.owner_slots[0], _VALIDATOR_UNAVAILABLE)
            )
        elif not output_missing and result is not None and result.state == "FAIL":
            output_missing.append(
                _missing_slot(output, output.owner_slots[0], result.reason_codes[0])
            )
            reason_codes.extend(result.reason_codes)
        elif not output_missing and result is not None:
            _set_payload_value(payload, output.output_path, result.value)
        missing.extend(output_missing)
        unavailable_outputs += int(bool(output_missing))
    if unavailable_outputs == 0:
        if missing or len(results_by_key) != len(family.outputs):
            _reject("UNEXPECTED_ASSESSABLE")
        try:
            validate_instance(
                payload,
                "scenario-family-payload.schema.json",
                definition="FamilyPayload",
            )
        except SchemaValidationError:
            _reject("FAMILY_PAYLOAD")
        evidence_state = "ASSESSABLE"
        projected_payload: dict[str, object] | None = payload
        projected_reason_codes: list[str] = []
    else:
        if not missing:
            _reject("UNEXPECTED_ASSESSABLE")
        evidence_state = "NOT_ASSESSABLE"
        projected_payload = None
        projected_reason_codes = list(
            dict.fromkeys(
                [
                    _FAMILY_UNAVAILABLE,
                    *reason_codes,
                    *([_VALIDATOR_UNAVAILABLE] if validator_unavailable else []),
                ]
            )
        )
    return {
        "family_id": family.family_id,
        "predicate_id": family.predicate_id,
        "case_id": case.case_id,
        "evidence_state": evidence_state,
        "payload": projected_payload,
        "covered_output_count": len(family.outputs),
        "unavailable_output_count": unavailable_outputs,
        "missing_owner_slots": [
            {
                "output_path": slot.output_path,
                "owner_class": slot.owner_class,
                "cardinality": slot.cardinality,
                "selector": slot.selector,
                "reason_code": slot.reason_code,
            }
            for slot in missing
        ],
        "reason_codes": projected_reason_codes,
    }


def _validated_family_evidence_projection(
    owner: _FamilyEvidenceProjection,
) -> dict[str, object]:
    if type(owner) is not _FamilyEvidenceProjection:
        _reject("OWNER")
    try:
        state = _FAMILY_EVIDENCE_STATES.read(owner)
        if type(state) is not _FamilyEvidenceState:
            _reject("OWNER_STATE")
        _validate_projection_transaction_binding(
            state.context,
            state.authenticated_plan,
            state.binding_receipt,
            state.public_truth_source,
        )
        value = strict_json_loads(state.projection_bytes)
        expected = _projection_value(
            state.context,
            state.report_outcomes,
            state.handler_results,
            state.registered_handler_keys,
            state.incomplete_handler_slots,
            coverage=state.coverage,
        )
    except (
        CanonicalizationError,
        OneShotRegistryError,
        ReportPredicateOutcomeError,
        ScenarioEvidenceContextError,
    ):
        _reject("OWNER_GRAPH")
    if (
        type(value) is not dict
        or value != expected
        or canonical_json_bytes(value) != state.projection_bytes
    ):
        _reject("OWNER_PROJECTION")
    return cast(dict[str, object], value)


def _projection_view(value: dict[str, object]) -> _FamilyEvidenceView:
    missing_value = cast(list[dict[str, str]], value["missing_owner_slots"])
    return _FamilyEvidenceView(
        family_id=cast(str, value["family_id"]),
        predicate_id=cast(str, value["predicate_id"]),
        case_id=cast(str, value["case_id"]),
        evidence_state=cast(
            Literal["ASSESSABLE", "NOT_ASSESSABLE"],
            value["evidence_state"],
        ),
        payload=cast(dict[str, object] | None, value["payload"]),
        covered_output_count=cast(int, value["covered_output_count"]),
        unavailable_output_count=cast(int, value["unavailable_output_count"]),
        missing_owner_slots=tuple(
            _UnavailableOwnerSlot(
                output_path=slot["output_path"],
                owner_class=slot["owner_class"],
                cardinality=slot["cardinality"],
                selector=slot["selector"],
                reason_code=slot["reason_code"],
            )
            for slot in missing_value
        ),
        reason_codes=tuple(cast(list[str], value["reason_codes"])),
    )


def _project_family_evidence(
    context: _AuthenticatedScenarioEvidenceContext,
    report_outcomes: tuple[ReportPredicateOutcome, ...],
) -> _FamilyEvidenceProjection:
    """Issue one opaque owner for the exact authenticated family projection."""

    if type(context) is not _AuthenticatedScenarioEvidenceContext:
        _reject("CONTEXT")
    return _issue_family_evidence_projection(context, report_outcomes)


def _project_public_synthetic_truth_family_evidence(
    context: _AuthenticatedPublicSyntheticTruthContext,
    authenticated_plan: AuthenticatedDirectOperationPlan,
    binding_receipt: AuthenticatedPlanRowBindingReceipt,
    truth_source: SyntheticTruthScoringEvidence,
) -> _FamilyEvidenceProjection:
    """Project only source truth after an ordinary typed-unprepared transaction."""

    if type(context) is not _AuthenticatedPublicSyntheticTruthContext:
        _reject("CONTEXT")
    return _issue_family_evidence_projection(
        context,
        (),
        authenticated_plan=authenticated_plan,
        binding_receipt=binding_receipt,
        public_truth_source=truth_source,
    )


def _validate_projection_transaction_binding(
    context: _AuthenticatedScenarioEvidenceContext | _AuthenticatedPublicSyntheticTruthContext,
    authenticated_plan: AuthenticatedDirectOperationPlan | None,
    binding_receipt: AuthenticatedPlanRowBindingReceipt | None,
    public_truth_source: SyntheticTruthScoringEvidence | None,
) -> None:
    if type(context) is _AuthenticatedScenarioEvidenceContext:
        if any(
            value is not None
            for value in (authenticated_plan, binding_receipt, public_truth_source)
        ):
            _reject("TRANSACTION_BINDING")
        return
    if (
        type(context) is not _AuthenticatedPublicSyntheticTruthContext
        or type(authenticated_plan) is not AuthenticatedDirectOperationPlan
        or type(binding_receipt) is not AuthenticatedPlanRowBindingReceipt
        or type(public_truth_source) is not SyntheticTruthScoringEvidence
    ):
        _reject("TRANSACTION_BINDING")
    try:
        context_state = _read_public_synthetic_truth_context(context)
        plan, authorization = _read_authenticated_unprepared_plan_row_binding(
            cast(AuthenticatedDirectOperationPlan, authenticated_plan),
            binding_receipt,
        )
        _authenticate_public_synthetic_unprepared_result(
            context_state.input_owner,
            authorization,
        )
        valid = (
            context_state.operation_plan_sha256 == _direct_operation_plan_digest(plan)
            and _read_synthetic_truth_scoring_input_owner(public_truth_source)
            is context_state.input_owner
        )
    except TypeError:
        valid = False
    if not valid:
        _reject("TRANSACTION_BINDING")


def _issue_family_evidence_projection(
    context: (_AuthenticatedScenarioEvidenceContext | _AuthenticatedPublicSyntheticTruthContext),
    report_outcomes: tuple[ReportPredicateOutcome, ...],
    *,
    authenticated_plan: AuthenticatedDirectOperationPlan | None = None,
    binding_receipt: AuthenticatedPlanRowBindingReceipt | None = None,
    public_truth_source: SyntheticTruthScoringEvidence | None = None,
) -> _FamilyEvidenceProjection:
    _validate_projection_transaction_binding(
        context,
        authenticated_plan,
        binding_receipt,
        public_truth_source,
    )
    case = _projection_case(context)
    coverage = _compiled_coverage()
    family = _family_for(coverage, case.family_id)
    report_by_identity = _validated_report_outcomes(context, report_outcomes)
    registry = _validated_handler_registry(coverage)
    execution = _execute_registered_handlers(
        context,
        family,
        registry,
        report_by_identity,
        report_outcomes,
        case.case_id,
    )
    projection = _projection_value(
        context,
        report_outcomes,
        execution.results,
        execution.registered_keys,
        execution.incomplete_slots,
        coverage=coverage,
    )
    owner = object.__new__(_FamilyEvidenceProjection)
    _FAMILY_EVIDENCE_ISSUER.bind_once(
        owner,
        _FamilyEvidenceState(
            projection_bytes=canonical_json_bytes(projection),
            coverage=coverage,
            context=context,
            authenticated_plan=authenticated_plan,
            binding_receipt=binding_receipt,
            public_truth_source=public_truth_source,
            report_outcomes=report_outcomes,
            handler_results=execution.results,
            registered_handler_keys=execution.registered_keys,
            incomplete_handler_slots=execution.incomplete_slots,
        ),
    )
    _validated_family_evidence_projection(owner)
    return owner


def _read_family_evidence_projection(
    owner: _FamilyEvidenceProjection,
) -> _FamilyEvidenceView:
    """Return a fresh typed view after exact owner-graph recomputation."""

    return _projection_view(_validated_family_evidence_projection(owner))


__all__: list[str] = []
