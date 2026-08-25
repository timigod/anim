"""Frozen report-predicate derivations from already projected owner records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, Never

from ebm_audit.evaluator.report_predicate_outcome import (
    ReportPredicateOutcome,
    _read_report_predicate_outcome,
    _read_report_predicate_outcome_context,
)
from ebm_audit.evaluator.scenario_derivation_handler_protocol import (
    Handler,
    HandlerKey,
    HandlerRequest,
    HandlerResult,
)
from ebm_audit.evaluator.scenario_evidence import (
    _read_scenario_evidence_context,
    _read_sealed_synthetic_audit_input,
)
from ebm_audit.evaluator.scenario_source_owner_manifest import _ScenarioSourceOwnerRecord
from ebm_audit.protocol import strict_json_loads
from ebm_audit.protocol.canonical import structured_sha256_hex
from ebm_audit.synthetic.audit_input import (
    SyntheticTruthScoringEvidence,
    _issue_synthetic_truth_scoring_evidence,
    _read_synthetic_truth_scoring_evidence,
    _read_synthetic_truth_scoring_record_bytes,
)

_REPORT_OWNER_CLASS: Final = "REPORT_PREDICATE_OUTCOME"
_REPORT_OWNER_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/ReportPredicateOutcome"
)
_TRUTH_OWNER_CLASS: Final = "SYNTHETIC_TRUTH"
_TRUTH_OWNER_SCHEMA_REF: Final = "schemas/synthetic-truth.schema.json"
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"

_REQUEST_INVALID: Final = "SCENARIO.DERIVATION_REQUEST_INVALID"
_OWNER_COVERAGE_INVALID: Final = "SCENARIO.DERIVATION_OWNER_COVERAGE_INVALID"
_OWNER_BINDING_INVALID: Final = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
_VALIDATION_FAILED: Final = "SCENARIO.DERIVATION_VALIDATION_FAILED"

_FORBIDDEN_REASON: Final = "REPORT.PREDICATE_FORBIDDEN_CONDITION_PRESENT"
_REQUIRED_REASON: Final = "REPORT.PREDICATE_REQUIRED_CONDITION_ABSENT"

type _ReportKind = Literal["FORBIDDEN_TRUE", "REQUIRED_TRUE"]


@dataclass(frozen=True, slots=True)
class _HandlerSpec:
    key: HandlerKey
    predicate_id: str
    report_kind: _ReportKind
    expected_subtype: str | None = None
    truth_reason: str | None = None


def _report_slot(cardinality: str, selector: str) -> tuple[str, str, str]:
    return (_REPORT_OWNER_CLASS, cardinality, selector)


def _truth_slot(cardinality: str, selector: str) -> tuple[str, str, str]:
    return (_TRUTH_OWNER_CLASS, cardinality, selector)


def _key(
    family_id: str,
    output_path: str,
    derivation_id: str,
    slots: tuple[tuple[str, str, str], ...],
) -> HandlerKey:
    return ("FAMILY_OUTPUT", family_id, output_path, derivation_id, slots)


_SPECS: Final[tuple[_HandlerSpec, ...]] = (
    _HandlerSpec(
        _key(
            "small_sample",
            "/payload/forced_precision_flags",
            "forbidden-report-claim-flag/1",
            (_report_slot("ONE_PER_CASE", "forced-precision-report-predicate/1"),),
        ),
        "forced-precision-report-predicate/1",
        "FORBIDDEN_TRUE",
    ),
    _HandlerSpec(
        _key(
            "incomplete_time_coverage",
            "/payload/coverage_limitation_reported",
            "required-report-claim-flag/1",
            (_report_slot("ONE_PER_CASE", "coverage-limitation-report-predicate/1"),),
        ),
        "coverage-limitation-report-predicate/1",
        "REQUIRED_TRUE",
    ),
    _HandlerSpec(
        _key(
            "tightly_spaced_events",
            "/payload/arbitrary_within_pair_truth_claims",
            "forbidden-report-claim-flag/1",
            (_report_slot("ONE_PER_CASE", "within-pair-precision-report-predicate/1"),),
        ),
        "within-pair-precision-report-predicate/1",
        "FORBIDDEN_TRUE",
    ),
    _HandlerSpec(
        _key(
            "outlier_sabotage",
            "/payload/bad_or_wrong_data_claim_flags",
            "forbidden-report-claim-flag/1",
            (_report_slot("ONE_PER_CASE", "bad-data-report-predicate/1"),),
        ),
        "bad-data-report-predicate/1",
        "FORBIDDEN_TRUE",
    ),
    _HandlerSpec(
        _key(
            "correlated_duplicate_events",
            "/payload/correlated/arbitrary_within_pair_truth_claims",
            "forbidden-report-claim-flag/1",
            (
                _report_slot(
                    "ONE_PER_SUBTYPE_CASE", "correlated-within-pair-report/1"
                ),
            ),
        ),
        "correlated-within-pair-report/1",
        "FORBIDDEN_TRUE",
        "CORRELATED",
    ),
    _HandlerSpec(
        _key(
            "correlated_duplicate_events",
            "/payload/exact_duplicate_post_noise/partial_truth_scored_without_tiebreak",
            "partial-truth-scoring-without-tiebreak/1",
            (
                _truth_slot(
                    "ONE_PER_SUBTYPE_CASE", "exact-duplicate-subtype-truth/1"
                ),
                _report_slot(
                    "ONE_PER_SUBTYPE_CASE", "partial-truth-scoring-report/1"
                ),
            ),
        ),
        "partial-truth-scoring-report/1",
        "REQUIRED_TRUE",
        "EXACT_DUPLICATE_POST_NOISE",
        "EXACT_DUPLICATE",
    ),
    _HandlerSpec(
        _key(
            "correlated_duplicate_events",
            "/payload/exact_duplicate_post_noise/arbitrary_within_pair_truth_claims",
            "forbidden-report-claim-flag/1",
            (
                _report_slot(
                    "ONE_PER_SUBTYPE_CASE", "exact-duplicate-within-pair-report/1"
                ),
            ),
        ),
        "exact-duplicate-within-pair-report/1",
        "FORBIDDEN_TRUE",
        "EXACT_DUPLICATE_POST_NOISE",
    ),
    _HandlerSpec(
        _key(
            "minority_alternate_sequence",
            "/payload/single_sequence_limitation_reported",
            "required-report-claim-flag/1",
            (_report_slot("ONE_PER_CASE", "single-sequence-limitation-report/1"),),
        ),
        "single-sequence-limitation-report/1",
        "REQUIRED_TRUE",
    ),
    _HandlerSpec(
        _key(
            "opposing_sequences_50_50",
            "/payload/internally_concentrated_flags",
            "internal-concentration-flag/1",
            (_report_slot("ONE_PER_CASE", "precision-report-predicate/1"),),
        ),
        "precision-report-predicate/1",
        "FORBIDDEN_TRUE",
    ),
    _HandlerSpec(
        _key(
            "near_simultaneous_events",
            "/payload/block_aware_scoring",
            "block-aware-scoring-flag/1",
            (
                _truth_slot("ONE_PER_CASE", "declared-equivalence-block/1"),
                _report_slot("ONE_PER_CASE", "block-scoring-report-predicate/1"),
            ),
        ),
        "block-scoring-report-predicate/1",
        "REQUIRED_TRUE",
        truth_reason="EQUIVALENCE_BLOCK",
    ),
    _HandlerSpec(
        _key(
            "wrong_event_direction",
            "/payload/direction_sensitivity_reported",
            "required-report-claim-flag/1",
            (_report_slot("ONE_PER_CASE", "direction-sensitivity-report/1"),),
        ),
        "direction-sensitivity-report/1",
        "REQUIRED_TRUE",
    ),
    _HandlerSpec(
        _key(
            "wrong_event_direction",
            "/payload/direction_validity_claims",
            "forbidden-report-claim-flag/1",
            (_report_slot("ONE_PER_CASE", "direction-validity-report/1"),),
        ),
        "direction-validity-report/1",
        "FORBIDDEN_TRUE",
    ),
    _HandlerSpec(
        _key(
            "label_permutation_null",
            "/payload/calibration_diagnostic_reported",
            "required-report-claim-flag/1",
            (_report_slot("ONE_PER_CASE", "null-calibration-report/1"),),
        ),
        "null-calibration-report/1",
        "REQUIRED_TRUE",
    ),
    _HandlerSpec(
        _key(
            "within_group_feature_permutation_null",
            "/payload/calibration_diagnostic_reported",
            "required-report-claim-flag/1",
            (_report_slot("ONE_PER_CASE", "null-calibration-report/1"),),
        ),
        "null-calibration-report/1",
        "REQUIRED_TRUE",
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


def _source_record_digest(
    owner_class: str,
    natural_identity: Mapping[str, object],
    source_record: Mapping[str, object],
) -> str:
    return structured_sha256_hex(
        _SOURCE_RECORD_DOMAIN,
        {
            "owner_class": owner_class,
            "natural_identity": dict(natural_identity),
            "source_record": dict(source_record),
        },
    )


def _report_value(
    request: HandlerRequest,
    spec: _HandlerSpec,
    record: _ScenarioSourceOwnerRecord,
    *,
    benchmark_subject_digest: str,
    case_id: str,
) -> bool:
    capability = record.source_capability
    if type(capability) is not ReportPredicateOutcome:
        _fail(_OWNER_BINDING_INVALID)
    if _read_report_predicate_outcome_context(capability) is not request.context:
        _fail(_OWNER_BINDING_INVALID)
    projection = _read_report_predicate_outcome(capability)
    identity_fields = (
        "benchmark_subject_digest",
        "family_id",
        "predicate_id",
        "cardinality_member_id",
        "report_artifact_sha256",
    )
    natural_identity = {field: projection.get(field) for field in identity_fields}
    source_record = _json_value(record.source_record)
    record_identity = _json_value(record.natural_identity)
    if (
        type(source_record) is not dict
        or type(record_identity) is not dict
        or record.owner_class != _REPORT_OWNER_CLASS
        or record.owner_schema_ref != _REPORT_OWNER_SCHEMA_REF
        or record_identity != natural_identity
        or source_record != projection
        or record.ordered_support_owner_sha256 != ()
        or record.source_record_sha256
        != _source_record_digest(_REPORT_OWNER_CLASS, natural_identity, projection)
        or projection.get("benchmark_subject_digest") != benchmark_subject_digest
        or projection.get("family_id") != spec.key[1]
        or projection.get("predicate_id") != spec.predicate_id
        or projection.get("cardinality_member_id") != case_id
        or projection.get("ordered_case_ids") != [case_id]
    ):
        _fail(_OWNER_BINDING_INVALID)

    claim_id = spec.predicate_id.replace("/", ":")
    semantics = (
        projection.get("derived_state"),
        projection.get("matching_claim_ids"),
        projection.get("forbidden_claim_count"),
        projection.get("reason_codes"),
    )
    if spec.report_kind == "FORBIDDEN_TRUE":
        if semantics == ("PASS", [], 0, []):
            return False
        if semantics == ("FAIL", [claim_id], 1, [_FORBIDDEN_REASON]):
            return True
    else:
        if semantics == ("PASS", [claim_id], 0, []):
            return True
        if semantics == ("FAIL", [], 0, [_REQUIRED_REASON]):
            return False
    _fail(_OWNER_BINDING_INVALID)


def _validate_truth(
    request: HandlerRequest,
    spec: _HandlerSpec,
    record: _ScenarioSourceOwnerRecord,
    *,
    case_id: str,
) -> None:
    evidence = _issue_synthetic_truth_scoring_evidence(
        _read_sealed_synthetic_audit_input(request.context)
    )
    if (
        type(evidence) is not SyntheticTruthScoringEvidence
        or record.source_capability is not evidence
    ):
        _fail(_OWNER_BINDING_INVALID)
    facts = _read_synthetic_truth_scoring_evidence(evidence)
    genuine_record = strict_json_loads(_read_synthetic_truth_scoring_record_bytes(evidence))
    source_record = _json_value(record.source_record)
    record_identity = _json_value(record.natural_identity)
    natural_identity = {"truth_object_sha256": facts.truth_object_sha256}
    if (
        type(genuine_record) is not dict
        or type(source_record) is not dict
        or type(record_identity) is not dict
        or record.owner_class != _TRUTH_OWNER_CLASS
        or record.owner_schema_ref != _TRUTH_OWNER_SCHEMA_REF
        or record_identity != natural_identity
        or source_record != genuine_record
        or record.ordered_support_owner_sha256 != ()
        or record.source_record_sha256
        != _source_record_digest(_TRUTH_OWNER_CLASS, natural_identity, genuine_record)
        or facts.family_id != spec.key[1]
        or facts.case_id != case_id
        or facts.truth_kind != "PARTIAL_ORDER"
        or facts.non_identifiability_reason != spec.truth_reason
        or type(facts.equivalence_block_sizes) is not tuple
        or not facts.equivalence_block_sizes
        or any(
            type(size) is not int or size < 2 for size in facts.equivalence_block_sizes
        )
        or facts.strict_order_identifiable is not False
        or facts.recoverable_signal is not True
    ):
        _fail(_OWNER_BINDING_INVALID)


def _validated_value(request: HandlerRequest, spec: _HandlerSpec) -> tuple[bool, ...]:
    if type(request) is not HandlerRequest or request.key != spec.key:
        _fail(_REQUEST_INVALID)
    projections = request.owner_projections
    if (
        type(projections) is not tuple
        or len(projections) != len(spec.key[4])
        or any(type(slot) is not tuple or len(slot) != 1 for slot in projections)
        or any(type(slot[0]) is not _ScenarioSourceOwnerRecord for slot in projections)
    ):
        _fail(_OWNER_COVERAGE_INVALID)
    records = tuple(slot[0] for slot in projections)
    if (
        len({id(record) for record in records}) != len(records)
        or len({record.source_record_sha256 for record in records}) != len(records)
    ):
        _fail(_OWNER_COVERAGE_INVALID)

    context = _read_scenario_evidence_context(request.context)
    if (
        context.identity.family_id != spec.key[1]
        or context.identity.case_id != context.case.case_id
        or context.case.subtype != spec.expected_subtype
    ):
        _fail(_OWNER_BINDING_INVALID)
    report_index = 0
    if spec.truth_reason is not None:
        _validate_truth(request, spec, records[0], case_id=context.identity.case_id)
        report_index = 1
    value = _report_value(
        request,
        spec,
        records[report_index],
        benchmark_subject_digest=context.identity.benchmark_subject_digest,
        case_id=context.identity.case_id,
    )
    return (value,)


def _handle(request: HandlerRequest, spec: _HandlerSpec) -> HandlerResult:
    try:
        return HandlerResult(spec.key, "PASS", _validated_value(request, spec), ())
    except _DerivationFailure as error:
        reason_code = error.reason_code
    except Exception:
        reason_code = _VALIDATION_FAILED
    return HandlerResult(spec.key, "FAIL", None, (reason_code,))


def _handler(spec: _HandlerSpec) -> Handler:
    def handle(request: HandlerRequest) -> HandlerResult:
        return _handle(request, spec)

    return handle


HANDLERS: tuple[tuple[HandlerKey, Handler], ...] = tuple(
    (spec.key, _handler(spec)) for spec in _SPECS
)

__all__ = ["HANDLERS"]
