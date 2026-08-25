"""Candidate strong-evidence flags from context-bound decision owners."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Never

from ebm_audit.evaluator.candidate_decision import (
    _ContextBoundCandidateStrongEvidenceDecision,
    _read_context_bound_candidate_strong_evidence_decision,
)
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
from ebm_audit.evaluator.scenario_evidence import _read_scenario_evidence_context
from ebm_audit.evaluator.scenario_source_owner_manifest import _ScenarioSourceOwnerRecord
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads
from ebm_audit.protocol.canonical import structured_sha256_hex

_DECISION_OWNER_CLASS: Final = "CANDIDATE_STRONG_EVIDENCE_DECISION"
_DECISION_SCHEMA_REF: Final = (
    "schemas/scientific-invariant.schema.json#/$defs/CandidateStrongEvidenceDecision"
)
_REPORT_OWNER_CLASS: Final = "REPORT_PREDICATE_OUTCOME"
_REPORT_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/ReportPredicateOutcome"
)
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_RULE_ID: Final = "candidate-strong-evidence/v1"
_REPORT_PREDICATE_ID: Final = "same-case-rendered-strong-label/1"
_REPORT_RECORD_PREDICATE_ID: Final = "INELIGIBLE_STRONG_LABEL/v1"
_REPORT_CLAIM_ID: Final = _REPORT_RECORD_PREDICATE_ID.replace("/", ":")
_FORBIDDEN_REASON: Final = "REPORT.PREDICATE_FORBIDDEN_CONDITION_PRESENT"

_REQUEST_INVALID: Final = "SCENARIO.DERIVATION_REQUEST_INVALID"
_OWNER_COVERAGE_INVALID: Final = "SCENARIO.DERIVATION_OWNER_COVERAGE_INVALID"
_OWNER_BINDING_INVALID: Final = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
_VALIDATION_FAILED: Final = "SCENARIO.DERIVATION_VALIDATION_FAILED"

_ROWS: Final = (
    (
        "weak_pre_post_separation",
        "/payload/ineligible_strong_flags",
        "ineligible-strong-evidence-flag/1",
        "INELIGIBLE",
    ),
    (
        "opposing_sequences_50_50",
        "/payload/stronger_than_null_flags",
        "stronger-than-null-flag/1",
        "STRONGER",
    ),
    (
        "label_permutation_null",
        "/payload/ineligible_strong_flags",
        "ineligible-strong-evidence-flag/1",
        "INELIGIBLE",
    ),
    (
        "within_group_feature_permutation_null",
        "/payload/ineligible_strong_flags",
        "ineligible-strong-evidence-flag/1",
        "INELIGIBLE",
    ),
)


class _CandidateStrongDerivationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> Never:
    raise _CandidateStrongDerivationError(code)


def _plain(value: object) -> object:
    def thaw(item: object) -> object:
        if isinstance(item, Mapping):
            return {key: thaw(child) for key, child in item.items()}
        if type(item) is tuple:
            return [thaw(child) for child in item]
        return item

    try:
        return strict_json_loads(canonical_json_bytes(thaw(value)))
    except Exception:
        _fail(_OWNER_BINDING_INVALID)


def _key(row: tuple[str, str, str, str]) -> HandlerKey:
    family_id, output_path, derivation_id, mode = row
    slots: tuple[tuple[str, str, str], ...] = (
        (
            _DECISION_OWNER_CLASS,
            "ONE_PER_CASE",
            "same-case-strong-decision/1"
            if mode == "STRONGER"
            else "same-case-eligibility-decision/1",
        ),
    )
    if mode == "INELIGIBLE":
        slots += (
            (
                _REPORT_OWNER_CLASS,
                "ONE_PER_CASE",
                "same-case-rendered-strong-label/1",
            ),
        )
    return ("FAMILY_OUTPUT", family_id, output_path, derivation_id, slots)


def _source_record_digest(
    owner_class: str,
    identity: Mapping[str, object],
    record: Mapping[str, object],
) -> str:
    return structured_sha256_hex(
        _SOURCE_RECORD_DOMAIN,
        {
            "owner_class": owner_class,
            "natural_identity": dict(identity),
            "source_record": dict(record),
        },
    )


def _decision_state(
    request: HandlerRequest,
    record: _ScenarioSourceOwnerRecord,
    *,
    benchmark_subject_digest: str,
    case_id: str,
) -> str:
    if (
        type(record) is not _ScenarioSourceOwnerRecord
        or record.owner_class != _DECISION_OWNER_CLASS
        or record.owner_schema_ref != _DECISION_SCHEMA_REF
        or type(record.source_capability)
        is not _ContextBoundCandidateStrongEvidenceDecision
        or record.ordered_support_owner_sha256 != ()
    ):
        _fail(_OWNER_BINDING_INVALID)
    projection = _read_context_bound_candidate_strong_evidence_decision(
        record.source_capability,
        request.context,
    )
    identity = {
        field: projection.get(field)
        for field in ("benchmark_subject_digest", "rule_id", "opportunity_id")
    }
    if (
        _plain(record.natural_identity) != identity
        or _plain(record.source_record) != projection
        or record.source_record_sha256
        != _source_record_digest(_DECISION_OWNER_CLASS, identity, projection)
        or projection.get("benchmark_subject_digest") != benchmark_subject_digest
        or projection.get("rule_id") != _RULE_ID
        or projection.get("opportunity_id") != case_id
    ):
        _fail(_OWNER_BINDING_INVALID)
    state = projection.get("state")
    if state == "CANDIDATE_STRONG_EVIDENCE_NOT_ASSESSABLE":
        _fail(_OWNER_BINDING_INVALID)
    if state not in {
        "CANDIDATE_STRONG_EVIDENCE",
        "CANDIDATE_NOT_STRONG_EVIDENCE",
    }:
        _fail(_OWNER_BINDING_INVALID)
    return state


def _rendered_strong_label(
    request: HandlerRequest,
    record: _ScenarioSourceOwnerRecord,
    *,
    family_id: str,
    benchmark_subject_digest: str,
    case_id: str,
) -> bool:
    if (
        type(record) is not _ScenarioSourceOwnerRecord
        or record.owner_class != _REPORT_OWNER_CLASS
        or record.owner_schema_ref != _REPORT_SCHEMA_REF
        or type(record.source_capability) is not ReportPredicateOutcome
        or record.ordered_support_owner_sha256 != ()
        or _read_report_predicate_outcome_context(record.source_capability)
        is not request.context
    ):
        _fail(_OWNER_BINDING_INVALID)
    projection = _read_report_predicate_outcome(record.source_capability)
    identity = {
        field: projection.get(field)
        for field in (
            "benchmark_subject_digest",
            "family_id",
            "predicate_id",
            "cardinality_member_id",
            "report_artifact_sha256",
        )
    }
    if (
        _plain(record.natural_identity) != identity
        or _plain(record.source_record) != projection
        or record.source_record_sha256
        != _source_record_digest(_REPORT_OWNER_CLASS, identity, projection)
        or projection.get("benchmark_subject_digest") != benchmark_subject_digest
        or projection.get("family_id") != family_id
        or projection.get("predicate_id") != _REPORT_PREDICATE_ID
        or projection.get("cardinality_member_id") != case_id
        or projection.get("ordered_case_ids") != [case_id]
    ):
        _fail(_OWNER_BINDING_INVALID)
    semantics = (
        projection.get("derived_state"),
        projection.get("matching_claim_ids"),
        projection.get("forbidden_claim_count"),
        projection.get("reason_codes"),
    )
    if semantics == ("PASS", [], 0, []):
        return False
    if semantics == ("FAIL", [_REPORT_CLAIM_ID], 1, [_FORBIDDEN_REASON]):
        return True
    _fail(_OWNER_BINDING_INVALID)


def _value(request: HandlerRequest, row: tuple[str, str, str, str]) -> tuple[bool, ...]:
    key = _key(row)
    if type(request) is not HandlerRequest or request.key != key:
        _fail(_REQUEST_INVALID)
    expected_slots = 1 if row[-1] == "STRONGER" else 2
    if (
        type(request.owner_projections) is not tuple
        or len(request.owner_projections) != expected_slots
        or any(type(slot) is not tuple or len(slot) != 1 for slot in request.owner_projections)
    ):
        _fail(_OWNER_COVERAGE_INVALID)
    records = tuple(slot[0] for slot in request.owner_projections)
    if (
        any(type(record) is not _ScenarioSourceOwnerRecord for record in records)
        or len({id(record) for record in records}) != len(records)
        or len({record.source_record_sha256 for record in records}) != len(records)
    ):
        _fail(_OWNER_COVERAGE_INVALID)
    context = _read_scenario_evidence_context(request.context)
    if (
        context.identity.family_id != row[0]
        or context.identity.case_id != context.case.case_id
    ):
        _fail(_OWNER_BINDING_INVALID)
    state = _decision_state(
        request,
        records[0],
        benchmark_subject_digest=context.identity.benchmark_subject_digest,
        case_id=context.identity.case_id,
    )
    if row[-1] == "STRONGER":
        return (state == "CANDIDATE_STRONG_EVIDENCE",)
    rendered = _rendered_strong_label(
        request,
        records[1],
        family_id=row[0],
        benchmark_subject_digest=context.identity.benchmark_subject_digest,
        case_id=context.identity.case_id,
    )
    return (rendered and state != "CANDIDATE_STRONG_EVIDENCE",)


def _handle(request: HandlerRequest, row: tuple[str, str, str, str]) -> HandlerResult:
    key = _key(row)
    try:
        return HandlerResult(key, "PASS", _value(request, row), ())
    except _CandidateStrongDerivationError as error:
        reason = error.code
    except Exception:
        reason = _VALIDATION_FAILED
    return HandlerResult(key, "FAIL", None, (reason,))


def _handler(row: tuple[str, str, str, str]) -> Handler:
    def handle(request: HandlerRequest) -> HandlerResult:
        return _handle(request, row)

    return handle


HANDLERS: tuple[tuple[HandlerKey, Handler], ...] = tuple(
    (_key(row), _handler(row)) for row in _ROWS
)

__all__ = ["HANDLERS"]
