"""Frozen analysis-rule identity derivation from authenticated owner records."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Final, Never, TypeGuard, cast

from ebm_audit.evaluator.scenario_derivation_handler_protocol import (
    Handler,
    HandlerKey,
    HandlerRequest,
    HandlerResult,
)
from ebm_audit.evaluator.scenario_evidence import _read_scenario_evidence_context
from ebm_audit.evaluator.scenario_source_owner_manifest import _ScenarioSourceOwnerRecord
from ebm_audit.protocol.canonical import structured_sha256_hex
from ebm_audit.schema import SchemaValidationError, validate_instance

_OWNER_CLASS: Final = "ANALYSIS_RULE_IDENTITY"
_OWNER_SCHEMA_REF: Final = "schemas/scenario-evidence.schema.json#/$defs/AnalysisRuleIdentity"
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_IDENTITY_DOMAIN: Final = "ebm-audit/analysis-rule-identity/1"
_SCHEMA_VERSION: Final = "ebm-audit-analysis-rule-identity/1.0"

_REQUEST_INVALID: Final = "SCENARIO.DERIVATION_REQUEST_INVALID"
_OWNER_COVERAGE_INVALID: Final = "SCENARIO.DERIVATION_OWNER_COVERAGE_INVALID"
_OWNER_BINDING_INVALID: Final = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
_VALIDATION_FAILED: Final = "SCENARIO.DERIVATION_VALIDATION_FAILED"

_RULE_QUANTILES: Final = (
    ("boundary_q50", 0.50),
    ("boundary_q35", 0.35),
    ("boundary_q65", 0.65),
)

_KEY: Final[HandlerKey] = (
    "FAMILY_OUTPUT",
    "group_boundary_sensitivity",
    "/payload/ordered_rule_ids",
    "analysis-rule-identities/1",
    (("ANALYSIS_RULE_IDENTITY", "ONE_PER_DECLARED_RULE", "boundary-rule-plan-order/1"),),
)


class _DerivationFailure(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason_code: str) -> Never:
    raise _DerivationFailure(reason_code)


def _is_sha256(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _plain_mapping(value: Mapping[str, object]) -> dict[str, object]:
    return {key: tuple(child) if type(child) is tuple else child for key, child in value.items()}


def _identity_digest(source_record: dict[str, object]) -> str:
    return structured_sha256_hex(
        _IDENTITY_DOMAIN,
        {
            key: value
            for key, value in source_record.items()
            if key != "analysis_rule_identity_sha256"
        },
    )


def _source_record_digest(
    natural_identity: dict[str, object],
    source_record: dict[str, object],
) -> str:
    return structured_sha256_hex(
        _SOURCE_RECORD_DOMAIN,
        {
            "owner_class": _OWNER_CLASS,
            "natural_identity": natural_identity,
            "source_record": source_record,
        },
    )


def _validated_value(request: HandlerRequest) -> tuple[str, ...]:
    if type(request) is not HandlerRequest or request.key != _KEY:
        _fail(_REQUEST_INVALID)
    projections = request.owner_projections
    if (
        type(projections) is not tuple
        or len(projections) != 1
        or type(projections[0]) is not tuple
        or len(projections[0]) != len(_RULE_QUANTILES)
        or any(type(record) is not _ScenarioSourceOwnerRecord for record in projections[0])
    ):
        _fail(_OWNER_COVERAGE_INVALID)

    context = _read_scenario_evidence_context(request.context)
    if (
        context.identity.family_id != _KEY[1]
        or context.identity.case_id != context.case.case_id
        or context.case.subtype is not None
    ):
        _fail(_OWNER_BINDING_INVALID)

    records = projections[0]
    if len({id(record) for record in records}) != len(records) or len(
        {record.source_record_sha256 for record in records}
    ) != len(records):
        _fail(_OWNER_COVERAGE_INVALID)

    analysis_spec_sha256: str | None = None
    comparator_indexes: set[int] = set()
    rule_ids: list[str] = []
    expected_fields = {
        "schema_version",
        "rule_id",
        "cutoff_quantile",
        "cutoff_value",
        "comparator_member_index",
        "analysis_spec_sha256",
        "analysis_rule_identity_sha256",
    }
    for record, (expected_rule_id, expected_quantile) in zip(records, _RULE_QUANTILES, strict=True):
        source_record = _plain_mapping(record.source_record)
        natural_identity = _plain_mapping(record.natural_identity)
        try:
            validate_instance(
                source_record,
                "scenario-evidence.schema.json",
                definition="AnalysisRuleIdentity",
            )
        except SchemaValidationError:
            _fail(_OWNER_BINDING_INVALID)
        record_analysis_spec_sha256 = source_record.get("analysis_spec_sha256")
        comparator_member_index = source_record.get("comparator_member_index")
        cutoff_value = source_record.get("cutoff_value")
        expected_identity = {
            "rule_id": expected_rule_id,
            "analysis_spec_sha256": record_analysis_spec_sha256,
        }
        if (
            record.owner_class != _OWNER_CLASS
            or record.owner_schema_ref != _OWNER_SCHEMA_REF
            or record.ordered_support_owner_sha256 != ()
            or record.source_capability is not None
            or set(source_record) != expected_fields
            or source_record.get("schema_version") != _SCHEMA_VERSION
            or source_record.get("rule_id") != expected_rule_id
            or type(source_record.get("cutoff_quantile")) is not float
            or source_record.get("cutoff_quantile") != expected_quantile
            or type(cutoff_value) not in (int, float)
            or not math.isfinite(cast(float, cutoff_value))
            or type(comparator_member_index) is not int
            or comparator_member_index < 0
            or not _is_sha256(record_analysis_spec_sha256)
            or natural_identity != expected_identity
            or source_record.get("analysis_rule_identity_sha256") != _identity_digest(source_record)
            or record.source_record_sha256 != _source_record_digest(natural_identity, source_record)
        ):
            _fail(_OWNER_BINDING_INVALID)
        if analysis_spec_sha256 is not None and record_analysis_spec_sha256 != analysis_spec_sha256:
            _fail(_OWNER_BINDING_INVALID)
        analysis_spec_sha256 = record_analysis_spec_sha256
        if comparator_member_index in comparator_indexes:
            _fail(_OWNER_BINDING_INVALID)
        comparator_indexes.add(comparator_member_index)
        rule_ids.append(expected_rule_id)

    return tuple(rule_ids)


def _handle(request: HandlerRequest) -> HandlerResult:
    try:
        return HandlerResult(_KEY, "PASS", _validated_value(request), ())
    except _DerivationFailure as error:
        reason_code = error.reason_code
    except Exception:
        reason_code = _VALIDATION_FAILED
    return HandlerResult(_KEY, "FAIL", None, (reason_code,))


HANDLERS: tuple[tuple[HandlerKey, Handler], ...] = ((_KEY, _handle),)

__all__ = ["HANDLERS"]
