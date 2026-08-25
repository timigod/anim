"""Complete false-positive evidence derivation from authenticated source owners."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Final, Never, cast

from ebm_audit.errors import InvalidInputError
from ebm_audit.evaluator.scenario_derivation_handler_protocol import (
    Handler,
    HandlerKey,
    HandlerRequest,
    HandlerResult,
)
from ebm_audit.evaluator.scenario_evidence import (
    ScenarioEvidenceContextError,
    _read_scenario_evidence_context,
)
from ebm_audit.evaluator.scenario_predicates import _validate_fpr_bundle
from ebm_audit.evaluator.scenario_source_owner_manifest import (
    _ScenarioSourceOwnerRecord,
)
from ebm_audit.protocol.canonical import structured_sha256_hex

_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_SEALED_CASE_MANIFEST_DOMAIN: Final = "ebm-audit/sealed-case-manifest/1"
_BUNDLE_SCHEMA_REF: Final = (
    "schemas/scientific-invariant.schema.json#/$defs/FalsePositiveEvidenceBundle"
)
_DECISION_SCHEMA_REF: Final = (
    "schemas/scientific-invariant.schema.json#/$defs/CandidateStrongEvidenceDecision"
)
_BUNDLE_OWNER_CLASS: Final = "FALSE_POSITIVE_EVIDENCE_BUNDLE"
_DECISION_OWNER_CLASS: Final = "CANDIDATE_STRONG_EVIDENCE_DECISION"
_EXPECTED_DECISION_COUNT: Final = 60
_AUTHENTICATED_CONTEXT_READER: Final = _read_scenario_evidence_context

_HANDLER_KEY: Final[HandlerKey] = (
    "FAMILY_OUTPUT",
    "pure_no_signal",
    "/payload/fpr_evidence",
    "complete-false-positive-evidence/1",
    (
        (
            _BUNDLE_OWNER_CLASS,
            "EXACTLY_ONE",
            "same-subject-pure-null-fpr-bundle/1",
        ),
        (
            _DECISION_OWNER_CLASS,
            "ONE_PER_OPPORTUNITY",
            "opportunity-manifest-order/1",
        ),
    ),
)

_REQUEST_INVALID: Final = "SCENARIO.DERIVATION_REQUEST_INVALID"
_OWNER_COVERAGE_INVALID: Final = "SCENARIO.DERIVATION_OWNER_COVERAGE_INVALID"
_OWNER_BINDING_INVALID: Final = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
_SCIENTIFIC_VALIDATION_FAILED: Final = "SCENARIO.DERIVATION_VALIDATION_FAILED"
_AGGREGATE_FAILED: Final = "SCENARIO.DERIVATION_AGGREGATE_FAILED"


class _DerivationFailure(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason_code: str) -> Never:
    raise _DerivationFailure(reason_code)


def _plain_json(value: object) -> object:
    """Copy one immutable owner projection to an exact plain JSON value."""

    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _fail(_OWNER_BINDING_INVALID)
        return value
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            _fail(_OWNER_BINDING_INVALID)
        return {key: _plain_json(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        sequence = cast(list[object] | tuple[object, ...], value)
        return [_plain_json(item) for item in sequence]
    _fail(_OWNER_BINDING_INVALID)


def _record_value(
    record: object,
    *,
    owner_class: str,
    schema_ref: str,
) -> tuple[dict[str, object], dict[str, object]]:
    if type(record) is not _ScenarioSourceOwnerRecord:
        _fail(_OWNER_BINDING_INVALID)
    if (
        record.owner_class != owner_class
        or record.owner_schema_ref != schema_ref
        or type(record.source_record_sha256) is not str
        or len(record.source_record_sha256) != 64
        or record.ordered_support_owner_sha256 != ()
        or record.source_capability is not None
    ):
        _fail(_OWNER_BINDING_INVALID)
    natural_identity = _plain_json(record.natural_identity)
    source_record = _plain_json(record.source_record)
    if type(natural_identity) is not dict or type(source_record) is not dict:
        _fail(_OWNER_BINDING_INVALID)
    expected_digest = structured_sha256_hex(
        _SOURCE_RECORD_DOMAIN,
        {
            "owner_class": owner_class,
            "natural_identity": natural_identity,
            "source_record": source_record,
        },
    )
    if record.source_record_sha256 != expected_digest:
        _fail(_OWNER_BINDING_INVALID)
    return (
        cast(dict[str, object], natural_identity),
        cast(dict[str, object], source_record),
    )


def _validated_inputs(
    request: HandlerRequest,
) -> tuple[dict[str, object], tuple[dict[str, object], ...], str]:
    if type(request) is not HandlerRequest or request.key != _HANDLER_KEY:
        _fail(_REQUEST_INVALID)
    projections = request.owner_projections
    if (
        type(projections) is not tuple
        or len(projections) != 2
        or type(projections[0]) is not tuple
        or type(projections[1]) is not tuple
    ):
        _fail(_OWNER_BINDING_INVALID)
    bundle_records, decision_records = projections
    if len(bundle_records) != 1 or len(decision_records) != _EXPECTED_DECISION_COUNT:
        _fail(_OWNER_COVERAGE_INVALID)
    if _read_scenario_evidence_context is not _AUTHENTICATED_CONTEXT_READER:
        _fail(_OWNER_BINDING_INVALID)

    context = _AUTHENTICATED_CONTEXT_READER(request.context)
    if context.identity.family_id != "pure_no_signal":
        _fail(_OWNER_BINDING_INVALID)
    subject_digest = context.identity.benchmark_subject_digest

    bundle_identity, bundle = _record_value(
        bundle_records[0],
        owner_class=_BUNDLE_OWNER_CLASS,
        schema_ref=_BUNDLE_SCHEMA_REF,
    )
    if bundle_identity != {"schema_version": bundle.get("schema_version")}:
        _fail(_OWNER_BINDING_INVALID)

    decisions: list[dict[str, object]] = []
    decision_opportunity_ids: list[str] = []
    for record in decision_records:
        natural_identity, decision = _record_value(
            record,
            owner_class=_DECISION_OWNER_CLASS,
            schema_ref=_DECISION_SCHEMA_REF,
        )
        expected_identity = {
            "benchmark_subject_digest": decision.get("benchmark_subject_digest"),
            "rule_id": decision.get("rule_id"),
            "opportunity_id": decision.get("opportunity_id"),
        }
        opportunity_id = decision.get("opportunity_id")
        if (
            natural_identity != expected_identity
            or type(opportunity_id) is not str
            or opportunity_id in decision_opportunity_ids
        ):
            _fail(_OWNER_BINDING_INVALID)
        decisions.append(decision)
        decision_opportunity_ids.append(opportunity_id)

    identity = bundle.get("null_calibration_identity")
    nested_decisions = bundle.get("ordered_candidate_decisions")
    opportunity_manifest = bundle.get("opportunity_manifest")
    opportunities = (
        opportunity_manifest.get("ordered_opportunities")
        if type(opportunity_manifest) is dict
        else None
    )
    opportunity_ids = (
        [opportunity.get("opportunity_id") for opportunity in opportunities]
        if type(opportunities) is list
        and all(type(opportunity) is dict for opportunity in opportunities)
        else None
    )
    if (
        type(opportunity_ids) is not list
        or len(opportunity_ids) != _EXPECTED_DECISION_COUNT
        or any(type(opportunity_id) is not str for opportunity_id in opportunity_ids)
        or len(set(opportunity_ids)) != _EXPECTED_DECISION_COUNT
        or opportunity_ids != decision_opportunity_ids
    ):
        _fail(_OWNER_BINDING_INVALID)
    if (
        type(identity) is not dict
        or identity.get("benchmark_subject_digest") != subject_digest
        or type(nested_decisions) is not list
        or nested_decisions != decisions
        or any(decision.get("benchmark_subject_digest") != subject_digest for decision in decisions)
    ):
        _fail(_OWNER_BINDING_INVALID)
    return bundle, tuple(decisions), subject_digest


def _handle(request: HandlerRequest) -> HandlerResult:
    try:
        bundle, _decisions, subject_digest = _validated_inputs(request)
        sealed_case_manifest = bundle.get("sealed_case_manifest")
        if type(sealed_case_manifest) is not dict:
            _fail(_OWNER_BINDING_INVALID)
        manifest_digest = structured_sha256_hex(
            _SEALED_CASE_MANIFEST_DOMAIN,
            sealed_case_manifest,
        )
        aggregate_state, states = _validate_fpr_bundle(
            bundle,
            {
                "benchmark_subject_digest": subject_digest,
                "sealed_case_manifest_sha256": manifest_digest,
            },
        )
        if (
            aggregate_state != "PASS"
            or len(states) != _EXPECTED_DECISION_COUNT
            or any(
                state
                not in {
                    "CANDIDATE_STRONG_EVIDENCE",
                    "CANDIDATE_NOT_STRONG_EVIDENCE",
                }
                for state in states
            )
        ):
            _fail(_AGGREGATE_FAILED)
        return HandlerResult(
            key=_HANDLER_KEY,
            state="PASS",
            value=bundle,
            reason_codes=(),
        )
    except _DerivationFailure as error:
        reason_code = error.reason_code
    except (InvalidInputError, ScenarioEvidenceContextError, KeyError, TypeError, ValueError):
        reason_code = _SCIENTIFIC_VALIDATION_FAILED
    return HandlerResult(
        key=_HANDLER_KEY,
        state="FAIL",
        value=None,
        reason_codes=(reason_code,),
    )


HANDLERS: tuple[tuple[HandlerKey, Handler], ...] = ((_HANDLER_KEY, _handle),)

__all__ = ["HANDLERS"]
