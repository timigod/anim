"""Frozen actual-row-removal derivation from authenticated PAE v2 owners."""

import math
from collections.abc import Mapping
from typing import Final, Never, cast

from ebm_audit.evaluator.scenario_derivation_handler_protocol import (
    Handler,
    HandlerKey,
    HandlerRequest,
    HandlerResult,
)
from ebm_audit.evaluator.scenario_evidence import (
    ScenarioEvidenceContextError,
    _read_captured_scientific_run_owner,
    _read_scenario_evidence_context,
)
from ebm_audit.evaluator.scenario_source_owner_manifest import (
    _ScenarioSourceOwnerRecord,
)
from ebm_audit.protocol.canonical import structured_sha256_hex
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.science.capture import (
    PreparationAuditEvidence,
    ScientificEvidenceError,
    _issue_preparation_audit_evidence,
    _read_preparation_audit_evidence,
)

_OWNER_CLASS: Final = "PREPARATION_AUDIT_EVIDENCE"
_OWNER_SCHEMA_REF: Final = "schemas/scenario-evidence.schema.json#/$defs/PreparationAuditEvidence"
_OWNER_SLOT = ((_OWNER_CLASS, "ONE_PER_CASE", "same-case-preparation-audit/1"),)
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_PAE_DOMAIN: Final = "ebm-audit/preparation-audit-evidence/2"
_AUTHENTICATED_CONTEXT_READER: Final = _read_scenario_evidence_context
_CAPTURE_OWNER_READER: Final = _read_captured_scientific_run_owner
_PAE_ISSUER: Final = _issue_preparation_audit_evidence
_PAE_READER: Final = _read_preparation_audit_evidence

_HANDLER_KEY: Final[HandlerKey] = (
    "FAMILY_OUTPUT",
    "mcar_missingness",
    "/payload/actual_removed_rows",
    "actual-complete-case-removals/1",
    _OWNER_SLOT,
)

_REQUEST_INVALID: Final = "SCENARIO.DERIVATION_REQUEST_INVALID"
_OWNER_COVERAGE_INVALID: Final = "SCENARIO.DERIVATION_OWNER_COVERAGE_INVALID"
_OWNER_BINDING_INVALID: Final = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
_SCIENTIFIC_VALIDATION_FAILED: Final = "SCENARIO.DERIVATION_VALIDATION_FAILED"


class _DerivationFailure(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason_code: str) -> Never:
    raise _DerivationFailure(reason_code)


def _plain_json(value: object) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _fail(_OWNER_BINDING_INVALID)
        return value
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        if any(type(key) is not str for key in mapping):
            _fail(_OWNER_BINDING_INVALID)
        return {cast(str, key): _plain_json(item) for key, item in mapping.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(item) for item in cast(list[object] | tuple[object, ...], value)]
    _fail(_OWNER_BINDING_INVALID)


def _validated_records(request: HandlerRequest) -> tuple[dict[str, object], ...]:
    if type(request) is not HandlerRequest or request.key != _HANDLER_KEY:
        _fail(_REQUEST_INVALID)
    if type(request.owner_projections) is not tuple:
        _fail(_OWNER_BINDING_INVALID)
    if len(request.owner_projections) != 1:
        _fail(_OWNER_COVERAGE_INVALID)
    if type(request.owner_projections[0]) is not tuple:
        _fail(_OWNER_BINDING_INVALID)
    context = _AUTHENTICATED_CONTEXT_READER(request.context)
    if context.identity.family_id != _HANDLER_KEY[1]:
        _fail(_OWNER_BINDING_INVALID)

    evidence = _PAE_ISSUER(_CAPTURE_OWNER_READER(request.context))
    if type(evidence) is not PreparationAuditEvidence:
        _fail(_OWNER_COVERAGE_INVALID)
    genuine_records = _PAE_READER(evidence)
    owner_records = request.owner_projections[0]
    if len(owner_records) != len(genuine_records) or not owner_records:
        _fail(_OWNER_COVERAGE_INVALID)
    if any(type(record) is not _ScenarioSourceOwnerRecord for record in owner_records):
        _fail(_OWNER_BINDING_INVALID)

    validated: list[dict[str, object]] = []
    seen_identities: set[tuple[str, str, str]] = set()
    for owner_record, genuine_record in zip(owner_records, genuine_records, strict=True):
        source_record_value = _plain_json(owner_record.source_record)
        natural_identity_value = _plain_json(owner_record.natural_identity)
        if type(source_record_value) is not dict or type(natural_identity_value) is not dict:
            _fail(_OWNER_BINDING_INVALID)
        source_record = cast(dict[str, object], source_record_value)
        natural_identity = cast(dict[str, object], natural_identity_value)
        expected_identity = {
            field: source_record.get(field)
            for field in ("case_id", "operation_instance_id", "analysis_spec_sha256")
        }
        digest_preimage = dict(source_record)
        digest = digest_preimage.get("preparation_audit_evidence_sha256")
        digest_preimage["digest_state"] = "DIGEST_PREIMAGE"
        digest_preimage["preparation_audit_evidence_sha256"] = None
        identity_tuple = (
            cast(str, expected_identity["case_id"]),
            cast(str, expected_identity["operation_instance_id"]),
            cast(str, expected_identity["analysis_spec_sha256"]),
        )
        if (
            owner_record.owner_class != _OWNER_CLASS
            or owner_record.owner_schema_ref != _OWNER_SCHEMA_REF
            or owner_record.source_capability is not evidence
            or source_record != genuine_record
            or natural_identity != expected_identity
            or source_record.get("case_id") != context.identity.case_id
            or source_record.get("schema_version") != "ebm-audit-preparation-audit-evidence/2.0"
            or source_record.get("digest_state") != "PERSISTED"
            or type(digest) is not str
            or digest != structured_sha256_hex(_PAE_DOMAIN, digest_preimage)
            or owner_record.source_record_sha256
            != structured_sha256_hex(
                _SOURCE_RECORD_DOMAIN,
                {
                    "owner_class": _OWNER_CLASS,
                    "natural_identity": natural_identity,
                    "source_record": source_record,
                },
            )
            or identity_tuple in seen_identities
        ):
            _fail(_OWNER_BINDING_INVALID)
        validate_instance(
            source_record,
            "scenario-evidence.schema.json",
            definition="PreparationAuditEvidence",
        )
        seen_identities.add(identity_tuple)
        validated.append(source_record)
    return tuple(validated)


def _handle(request: HandlerRequest) -> HandlerResult:
    try:
        values: list[int] = []
        for record in _validated_records(request):
            data_accounting = record["data_accounting"]
            if type(data_accounting) is not dict:
                _fail(_SCIENTIFIC_VALIDATION_FAILED)
            removed_participants = cast(dict[str, object], data_accounting).get(
                "removed_participants"
            )
            if type(removed_participants) is not int or removed_participants < 0:
                _fail(_SCIENTIFIC_VALIDATION_FAILED)
            values.append(removed_participants)
        return HandlerResult(key=_HANDLER_KEY, state="PASS", value=values, reason_codes=())
    except _DerivationFailure as error:
        reason_code = error.reason_code
    except (
        KeyError,
        ScenarioEvidenceContextError,
        SchemaValidationError,
        ScientificEvidenceError,
        TypeError,
        ValueError,
    ):
        reason_code = _SCIENTIFIC_VALIDATION_FAILED
    return HandlerResult(
        key=_HANDLER_KEY,
        state="FAIL",
        value=None,
        reason_codes=(reason_code,),
    )


HANDLERS: tuple[tuple[HandlerKey, Handler], ...] = ((_HANDLER_KEY, _handle),)

__all__ = ["HANDLERS"]
