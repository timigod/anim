"""Frozen truth-scoring-mode derivations from retained generated truth."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Never

from ebm_audit.errors import InvalidInputError, UnexpectedCoreError
from ebm_audit.evaluator.scenario_case_batch import _read_authenticated_batch_context
from ebm_audit.evaluator.scenario_derivation_handler_protocol import (
    Handler,
    HandlerKey,
    HandlerRequest,
    HandlerResult,
)
from ebm_audit.evaluator.scenario_evidence import (
    ScenarioEvidenceContextError,
    _read_truth_scoring_context,
)
from ebm_audit.evaluator.scenario_source_owner_manifest import _ScenarioSourceOwnerRecord
from ebm_audit.protocol.canonical import canonical_json_bytes, structured_sha256_hex
from ebm_audit.synthetic.audit_input import (
    SyntheticTruthScoringEvidence,
    _read_public_synthetic_batch_input_owner,
    _read_synthetic_truth_scoring_evidence,
    _read_synthetic_truth_scoring_input_owner,
    _read_synthetic_truth_scoring_record_bytes,
    _SyntheticTruthScoringFacts,
)

_OWNER_CLASS: Final = "SYNTHETIC_TRUTH"
_OWNER_SCHEMA_REF: Final = "schemas/synthetic-truth.schema.json"
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_SAME_CASE_SLOT: Final = ((_OWNER_CLASS, "ONE_PER_CASE", "same-case-truth/1"),)
_CORRELATED_SLOT: Final = ((_OWNER_CLASS, "ONE_PER_SUBTYPE_CASE", "correlated-subtype-truth/1"),)
_EXACT_DUPLICATE_SLOT: Final = (
    (_OWNER_CLASS, "ONE_PER_SUBTYPE_CASE", "exact-duplicate-subtype-truth/1"),
)

_REQUEST_INVALID: Final = "SCENARIO.DERIVATION_REQUEST_INVALID"
_OWNER_COVERAGE_INVALID: Final = "SCENARIO.DERIVATION_OWNER_COVERAGE_INVALID"
_OWNER_BINDING_INVALID: Final = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
_SCIENTIFIC_VALIDATION_FAILED: Final = "SCENARIO.DERIVATION_VALIDATION_FAILED"


@dataclass(frozen=True, slots=True)
class _HandlerSpec:
    key: HandlerKey
    expected_truth_kind: str
    expected_reason: str | None
    expected_mode: str
    expected_subtype: str | None = None


def _key(
    family_id: str,
    output_path: str = "/payload/truth_scoring_mode",
    owner_slots: tuple[tuple[str, str, str], ...] = _SAME_CASE_SLOT,
) -> HandlerKey:
    return (
        "FAMILY_OUTPUT",
        family_id,
        output_path,
        "truth-scoring-mode/1",
        owner_slots,
    )


_STRICT_FAMILIES: Final = (
    "easy_known_truth",
    "moderate_mina_shape",
    "small_sample",
    "noise_ladder",
    "weak_pre_post_separation",
    "incomplete_time_coverage",
    "tightly_spaced_events",
    "slow_overlapping_transitions",
    "outlier_sabotage",
    "mcar_missingness",
    "mar_missingness",
    "covariate_confounding",
    "group_boundary_sensitivity",
    "control_contamination",
    "heavy_tailed_skewed",
    "wrong_event_direction",
)
_SPECS: Final[tuple[_HandlerSpec, ...]] = (
    *(
        _HandlerSpec(_key(family_id), "STRICT_TOTAL_ORDER", None, "STRICT_TOTAL_ORDER")
        for family_id in _STRICT_FAMILIES
    ),
    _HandlerSpec(
        _key(
            "correlated_duplicate_events",
            "/payload/correlated/truth_scoring_mode",
            _CORRELATED_SLOT,
        ),
        "STRICT_TOTAL_ORDER",
        None,
        "STRICT_TOTAL_ORDER",
        "CORRELATED",
    ),
    _HandlerSpec(
        _key(
            "correlated_duplicate_events",
            "/payload/exact_duplicate_post_noise/truth_scoring_mode",
            _EXACT_DUPLICATE_SLOT,
        ),
        "PARTIAL_ORDER",
        "EXACT_DUPLICATE",
        "PARTIAL_ORDER_EQUIVALENCE",
        "EXACT_DUPLICATE_POST_NOISE",
    ),
    _HandlerSpec(
        _key("minority_alternate_sequence"),
        "MIXTURE_OF_STRICT_ORDERS",
        "MINORITY_ALTERNATE_SEQUENCE",
        "MIXTURE_NON_IDENTIFIABLE",
    ),
    _HandlerSpec(
        _key("opposing_sequences_50_50"),
        "MIXTURE_OF_STRICT_ORDERS",
        "OPPOSING_SEQUENCES",
        "MIXTURE_NON_IDENTIFIABLE",
    ),
    _HandlerSpec(
        _key("near_simultaneous_events"),
        "PARTIAL_ORDER",
        "EQUIVALENCE_BLOCK",
        "PARTIAL_ORDER_EQUIVALENCE",
    ),
    _HandlerSpec(
        _key("pure_no_signal"),
        "NONE",
        "PURE_NO_SIGNAL",
        "NO_RECOVERABLE_SIGNAL",
    ),
    _HandlerSpec(
        _key("label_permutation_null"),
        "NONE",
        "REFITTED_NULL_TRANSFORMATION",
        "REFITTED_NULL_TRANSFORMATION",
    ),
    _HandlerSpec(
        _key("within_group_feature_permutation_null"),
        "NONE",
        "REFITTED_NULL_TRANSFORMATION",
        "REFITTED_NULL_TRANSFORMATION",
    ),
)


class _DerivationFailure(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason_code: str) -> Never:
    raise _DerivationFailure(reason_code)


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _json_value(child) for key, child in value.items()}
    if type(value) is tuple:
        return [_json_value(child) for child in value]
    return value


def _derived_mode(facts: object) -> str:
    truth_kind = getattr(facts, "truth_kind", None)
    reason = getattr(facts, "non_identifiability_reason", None)
    block_sizes = getattr(facts, "equivalence_block_sizes", None)
    identifiable = getattr(facts, "strict_order_identifiable", None)
    recoverable = getattr(facts, "recoverable_signal", None)
    if (
        truth_kind == "STRICT_TOTAL_ORDER"
        and reason is None
        and block_sizes == ()
        and identifiable is True
        and recoverable is True
    ):
        return "STRICT_TOTAL_ORDER"
    if (
        truth_kind == "PARTIAL_ORDER"
        and reason in {"EQUIVALENCE_BLOCK", "EXACT_DUPLICATE"}
        and type(block_sizes) is tuple
        and bool(block_sizes)
        and all(type(size) is int and size >= 2 for size in block_sizes)
        and identifiable is False
        and recoverable is True
    ):
        return "PARTIAL_ORDER_EQUIVALENCE"
    if (
        truth_kind == "MIXTURE_OF_STRICT_ORDERS"
        and reason in {"MINORITY_ALTERNATE_SEQUENCE", "OPPOSING_SEQUENCES"}
        and block_sizes == ()
        and identifiable is False
        and recoverable is True
    ):
        return "MIXTURE_NON_IDENTIFIABLE"
    if (
        truth_kind == "NONE"
        and reason in {"PURE_NO_SIGNAL", "REFITTED_NULL_TRANSFORMATION"}
        and block_sizes == ()
        and identifiable is False
        and recoverable is False
    ):
        return (
            "NO_RECOVERABLE_SIGNAL"
            if reason == "PURE_NO_SIGNAL"
            else "REFITTED_NULL_TRANSFORMATION"
        )
    _fail(_OWNER_BINDING_INVALID)


def _validated_truth_record(
    context_owner: object,
    owner_record: object,
) -> tuple[_SyntheticTruthScoringFacts, str | None]:
    context = _read_truth_scoring_context(context_owner)
    if type(owner_record) is not _ScenarioSourceOwnerRecord:
        _fail(_OWNER_BINDING_INVALID)
    evidence = owner_record.source_capability
    if type(evidence) is not SyntheticTruthScoringEvidence:
        _fail(_OWNER_COVERAGE_INVALID)
    facts = _read_synthetic_truth_scoring_evidence(evidence)
    genuine_source_record_bytes = _read_synthetic_truth_scoring_record_bytes(evidence)
    input_owner = _read_synthetic_truth_scoring_input_owner(evidence)
    try:
        batch_context = _read_authenticated_batch_context(context.batch)
        input_batch = _read_public_synthetic_batch_input_owner(input_owner)
    except (InvalidInputError, TypeError, UnexpectedCoreError, ValueError):
        _fail(_OWNER_BINDING_INVALID)
    matching_cases = tuple(
        case
        for case in batch_context.cases
        if case.family_id == facts.family_id and case.case_id == facts.case_id
    )
    if input_batch is not context.batch or len(matching_cases) != 1:
        _fail(_OWNER_BINDING_INVALID)
    source_record = owner_record.source_record
    natural_identity = owner_record.natural_identity
    if not isinstance(source_record, Mapping) or not isinstance(natural_identity, Mapping):
        _fail(_OWNER_BINDING_INVALID)
    source_record_value = _json_value(source_record)
    if type(source_record_value) is not dict:
        _fail(_OWNER_BINDING_INVALID)
    scenario = source_record.get("scenario_identity")
    order = source_record.get("order_truth")
    if not isinstance(scenario, Mapping) or not isinstance(order, Mapping):
        _fail(_OWNER_BINDING_INVALID)
    expected_identity = {"truth_object_sha256": facts.truth_object_sha256}
    if (
        owner_record.owner_class != _OWNER_CLASS
        or owner_record.owner_schema_ref != _OWNER_SCHEMA_REF
        or owner_record.ordered_support_owner_sha256 != ()
        or owner_record.source_capability is not evidence
        or dict(natural_identity) != expected_identity
        or canonical_json_bytes(source_record_value) != genuine_source_record_bytes
        or source_record.get("truth_object_sha256") != facts.truth_object_sha256
        or scenario.get("family_id") != facts.family_id
        or scenario.get("case_id") != facts.case_id
        or facts.family_id != context.identity.family_id
        or order.get("truth_kind") != facts.truth_kind
        or order.get("non_identifiability_reason") != facts.non_identifiability_reason
        or owner_record.source_record_sha256
        != structured_sha256_hex(
            _SOURCE_RECORD_DOMAIN,
            {
                "owner_class": _OWNER_CLASS,
                "natural_identity": expected_identity,
                "source_record": source_record_value,
            },
        )
    ):
        _fail(_OWNER_BINDING_INVALID)
    return facts, matching_cases[0].subtype


def _validated_mode(request: HandlerRequest, spec: _HandlerSpec) -> str:
    if type(request) is not HandlerRequest or request.key != spec.key:
        _fail(_REQUEST_INVALID)
    if (
        type(request.owner_projections) is not tuple
        or len(request.owner_projections) != 1
        or type(request.owner_projections[0]) is not tuple
    ):
        _fail(_OWNER_BINDING_INVALID)
    context = _read_truth_scoring_context(request.context)
    if context.identity.family_id != spec.key[1]:
        _fail(_OWNER_BINDING_INVALID)
    owner_records = request.owner_projections[0]
    if spec.expected_subtype is None:
        if len(owner_records) != 1:
            _fail(_OWNER_COVERAGE_INVALID)
        facts, subtype = _validated_truth_record(request.context, owner_records[0])
        if facts.case_id != context.identity.case_id or subtype is not None:
            _fail(_OWNER_BINDING_INVALID)
    else:
        expected_subtypes = {"CORRELATED", "EXACT_DUPLICATE_POST_NOISE"}
        if (
            context.identity.family_id != "correlated_duplicate_events"
            or context.case.subtype not in expected_subtypes
            or len(owner_records) != 2
        ):
            _fail(_OWNER_COVERAGE_INVALID)
        validated = tuple(
            _validated_truth_record(request.context, owner_record)
            for owner_record in owner_records
        )
        observed_subtypes = tuple(subtype for _facts, subtype in validated)
        observed_case_ids = tuple(facts.case_id for facts, _subtype in validated)
        if (
            set(observed_subtypes) != expected_subtypes
            or len(set(observed_subtypes)) != 2
            or len(set(observed_case_ids)) != 2
            or context.identity.case_id not in observed_case_ids
        ):
            _fail(_OWNER_BINDING_INVALID)
        matches = tuple(
            facts
            for facts, subtype in validated
            if subtype == spec.expected_subtype
        )
        if len(matches) != 1:
            _fail(_OWNER_BINDING_INVALID)
        facts = matches[0]
    if (
        facts.truth_kind != spec.expected_truth_kind
        or facts.non_identifiability_reason != spec.expected_reason
    ):
        _fail(_OWNER_BINDING_INVALID)
    mode = _derived_mode(facts)
    if mode != spec.expected_mode:
        _fail(_OWNER_BINDING_INVALID)
    return mode


def _handle(request: HandlerRequest, spec: _HandlerSpec) -> HandlerResult:
    try:
        return HandlerResult(
            key=spec.key,
            state="PASS",
            value=_validated_mode(request, spec),
            reason_codes=(),
        )
    except _DerivationFailure as error:
        reason_code = error.reason_code
    except (ScenarioEvidenceContextError, TypeError, UnexpectedCoreError, ValueError):
        reason_code = _SCIENTIFIC_VALIDATION_FAILED
    return HandlerResult(
        key=spec.key,
        state="FAIL",
        value=None,
        reason_codes=(reason_code,),
    )


def _handler(spec: _HandlerSpec) -> Handler:
    def handle(request: HandlerRequest) -> HandlerResult:
        return _handle(request, spec)

    return handle


HANDLERS: tuple[tuple[HandlerKey, Handler], ...] = tuple(
    (spec.key, _handler(spec)) for spec in _SPECS
)

__all__ = ["HANDLERS"]
