"""Frozen missingness equality derivations from authenticated source owners."""

from __future__ import annotations

import hashlib
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
    _AuthenticatedPublicSyntheticTruthContext,
    _AuthenticatedScenarioEvidenceContext,
    _PublicSyntheticTruthContextState,
    _read_public_synthetic_truth_context,
    _read_scenario_evidence_context,
    _read_sealed_synthetic_audit_input,
    _read_truth_scoring_input,
    _ScenarioEvidenceContextState,
)
from ebm_audit.evaluator.scenario_source_owner_manifest import _ScenarioSourceOwnerRecord
from ebm_audit.protocol import CanonicalizationError, strict_json_loads
from ebm_audit.protocol.canonical import structured_sha256_hex
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.synthetic.audit_input import (
    SealedPublicSyntheticAuditInput,
    SyntheticScientificDataEvidence,
    SyntheticTruthScoringEvidence,
    _issue_synthetic_scientific_data_evidence,
    _issue_synthetic_truth_scoring_evidence,
    _read_synthetic_scientific_data_evidence,
    _read_synthetic_truth_scoring_record_bytes,
    _SyntheticMissingnessProjection,
)

_TRUTH_CLASS: Final = "SYNTHETIC_TRUTH"
_TRUTH_SCHEMA: Final = "schemas/synthetic-truth.schema.json"
_DATA_CLASS: Final = "SYNTHETIC_SCIENTIFIC_DATA"
_DATA_SCHEMA: Final = "schemas/synthetic-scientific-data.schema.json"
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"

_MASK_SLOTS = (
    (_TRUTH_CLASS, "ONE_PER_CASE", "same-case-truth/1"),
    (_DATA_CLASS, "ONE_PER_CASE", "same-case-scientific-data/1"),
)
_MISSING_COUNT_PRESERVATION_SLOTS = (
    (_DATA_CLASS, "ONE_PER_CASE", "same-case-source-data/1"),
    (_DATA_CLASS, "ONE_PER_CASE", "same-case-transformed-data/1"),
)


def _key(family_id: str, output_path: str, derivation_id: str) -> HandlerKey:
    return (
        "FAMILY_OUTPUT",
        family_id,
        output_path,
        derivation_id,
        _MASK_SLOTS,
    )


_MCAR_MASK_KEY: Final[HandlerKey] = _key(
    "mcar_missingness", "/payload/mask_digest_equal", "missingness-mask-digest-equality/1"
)
_MAR_MASK_KEY: Final[HandlerKey] = _key(
    "mar_missingness", "/payload/mask_digest_equal", "missingness-mask-digest-equality/1"
)
_MISSING_COUNT_PRESERVATION_KEY: Final[HandlerKey] = (
    "FAMILY_OUTPUT",
    "within_group_feature_permutation_null",
    "/payload/missing_counts_preserved",
    "missing-count-preservation/1",
    _MISSING_COUNT_PRESERVATION_SLOTS,
)

_REQUEST_INVALID: Final = "SCENARIO.DERIVATION_REQUEST_INVALID"
_OWNER_COVERAGE_INVALID: Final = "SCENARIO.DERIVATION_OWNER_COVERAGE_INVALID"
_OWNER_BINDING_INVALID: Final = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
_SCIENTIFIC_VALIDATION_FAILED: Final = "SCENARIO.DERIVATION_VALIDATION_FAILED"

_TRUTH_ISSUER: Final = _issue_synthetic_truth_scoring_evidence
_TRUTH_READER: Final = _read_synthetic_truth_scoring_record_bytes
_DATA_ISSUER: Final = _issue_synthetic_scientific_data_evidence
_DATA_READER: Final = _read_synthetic_scientific_data_evidence


class _DerivationFailure(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason_code: str) -> Never:
    raise _DerivationFailure(reason_code)


def _read_missingness_context(
    owner: object,
) -> _ScenarioEvidenceContextState | _PublicSyntheticTruthContextState:
    if type(owner) is _AuthenticatedScenarioEvidenceContext:
        return _read_scenario_evidence_context(owner)
    if type(owner) is _AuthenticatedPublicSyntheticTruthContext:
        return _read_public_synthetic_truth_context(owner)
    raise ScenarioEvidenceContextError(
        "Missingness derivation requires an authenticated scenario or truth context."
    )


def _read_missingness_input(owner: object) -> SealedPublicSyntheticAuditInput:
    if type(owner) is _AuthenticatedScenarioEvidenceContext:
        return _read_sealed_synthetic_audit_input(owner)
    if type(owner) is _AuthenticatedPublicSyntheticTruthContext:
        return _read_truth_scoring_input(owner)
    raise ScenarioEvidenceContextError(
        "Missingness derivation requires an authenticated scenario or truth context."
    )


_CONTEXT_READER: Final = _read_missingness_context
_INPUT_READER: Final = _read_missingness_input


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


def _source_digest(owner_class: str, identity: dict[str, object], record: dict[str, object]) -> str:
    return structured_sha256_hex(
        _SOURCE_RECORD_DOMAIN,
        {"owner_class": owner_class, "natural_identity": identity, "source_record": record},
    )


def _validate_owner(
    owner: _ScenarioSourceOwnerRecord,
    *,
    owner_class: str,
    schema_ref: str,
    capability: object,
    genuine_record: dict[str, object],
    identity: dict[str, object],
) -> dict[str, object]:
    source = _plain_json(owner.source_record)
    natural_identity = _plain_json(owner.natural_identity)
    if (
        type(source) is not dict
        or type(natural_identity) is not dict
        or owner.owner_class != owner_class
        or owner.owner_schema_ref != schema_ref
        or owner.source_capability is not capability
        or source != genuine_record
        or natural_identity != identity
        or owner.source_record_sha256 != _source_digest(owner_class, identity, source)
    ):
        _fail(_OWNER_BINDING_INVALID)
    return source


def _validated_records(
    request: HandlerRequest, key: HandlerKey
) -> tuple[dict[str, object], dict[str, object]]:
    expected_slot_count = len(key[4])
    if type(request) is not HandlerRequest or request.key != key:
        _fail(_REQUEST_INVALID)
    if type(request.owner_projections) is not tuple:
        _fail(_OWNER_BINDING_INVALID)
    if len(request.owner_projections) != expected_slot_count:
        _fail(_OWNER_COVERAGE_INVALID)
    for projection in request.owner_projections:
        if type(projection) is not tuple:
            _fail(_OWNER_BINDING_INVALID)
        if len(projection) != 1:
            _fail(_OWNER_COVERAGE_INVALID)
        if type(projection[0]) is not _ScenarioSourceOwnerRecord:
            _fail(_OWNER_BINDING_INVALID)

    context = _CONTEXT_READER(request.context)
    family_id = cast(str, key[1])
    if context.identity.family_id != family_id:
        _fail(_OWNER_BINDING_INVALID)
    input_owner = _INPUT_READER(request.context)
    truth_evidence = _TRUTH_ISSUER(input_owner)
    data_evidence = _DATA_ISSUER(input_owner)
    if (
        type(truth_evidence) is not SyntheticTruthScoringEvidence
        or type(data_evidence) is not SyntheticScientificDataEvidence
    ):
        _fail(_OWNER_COVERAGE_INVALID)
    truth_bytes = _TRUTH_READER(truth_evidence)
    data_bytes = _DATA_READER(data_evidence)
    truth_genuine = strict_json_loads(truth_bytes)
    data_genuine = strict_json_loads(data_bytes)
    if type(truth_genuine) is not dict or type(data_genuine) is not dict:
        _fail(_OWNER_BINDING_INVALID)

    truth_owner = request.owner_projections[0][0]
    data_owner = request.owner_projections[1][0]
    truth_digest = truth_genuine.get("truth_object_sha256")
    data_digest = data_genuine.get("generated_scientific_data_sha256")
    if type(truth_digest) is not str or type(data_digest) is not str:
        _fail(_OWNER_BINDING_INVALID)
    truth = _validate_owner(
        truth_owner,
        owner_class=_TRUTH_CLASS,
        schema_ref=_TRUTH_SCHEMA,
        capability=truth_evidence,
        genuine_record=truth_genuine,
        identity={"truth_object_sha256": truth_digest},
    )
    data = _validate_owner(
        data_owner,
        owner_class=_DATA_CLASS,
        schema_ref=_DATA_SCHEMA,
        capability=data_evidence,
        genuine_record=data_genuine,
        identity={
            "case_id": data_genuine.get("case_id"),
            "generated_scientific_data_sha256": data_digest,
        },
    )
    validate_instance(truth, "synthetic-truth.schema.json")
    validate_instance(data, "synthetic-scientific-data.schema.json")
    scenario = truth.get("scenario_identity")
    missingness = truth.get("missingness_truth")
    if (
        type(scenario) is not dict
        or type(missingness) is not dict
        or scenario.get("family_id") != family_id
        or scenario.get("case_id") != context.identity.case_id
        or data.get("case_id") != context.identity.case_id
        or missingness.get("family") != ("MCAR" if family_id == "mcar_missingness" else "MAR")
    ):
        _fail(_OWNER_BINDING_INVALID)

    return truth, data


def _dimensions(value: object) -> tuple[int, int]:
    if type(value) is not dict:
        _fail(_OWNER_BINDING_INVALID)
    participant_count = value.get("participant_count")
    event_count = value.get("event_count")
    if type(participant_count) is not int or type(event_count) is not int:
        _fail(_OWNER_BINDING_INVALID)
    return participant_count, event_count


def _mask_layout(value: object) -> tuple[tuple[int, ...], bytes]:
    if type(value) is not list or not value:
        _fail(_OWNER_BINDING_INVALID)
    flattened: list[int] = []
    width: int | None = None
    for row in value:
        if type(row) is not list or not row:
            _fail(_OWNER_BINDING_INVALID)
        if width is None:
            width = len(row)
        if len(row) != width or any(type(cell) is not bool for cell in row):
            _fail(_OWNER_BINDING_INVALID)
        flattened.extend(int(cell) for cell in row)
    row_structure = tuple(len(row) for row in value)
    return row_structure, bytes(flattened)


def _handle(request: HandlerRequest, key: HandlerKey) -> HandlerResult:
    try:
        truth, data = _validated_records(request, key)
        missingness = cast(dict[str, object], truth["missingness_truth"])
        truth_dimensions = _dimensions(truth["dimensions"])
        data_dimensions = _dimensions(data["dimensions"])
        truth_rows, truth_mask = _mask_layout(missingness["mask"])
        data_rows, data_mask = _mask_layout(data["missingness_mask"])
        artifact_digests = truth["artifact_digests"]
        if type(artifact_digests) is not dict:
            _fail(_OWNER_BINDING_INVALID)
        value = [
            truth_dimensions == data_dimensions
            and truth_rows == data_rows
            and truth_rows == (truth_dimensions[1],) * truth_dimensions[0]
            and data_rows == (data_dimensions[1],) * data_dimensions[0]
            and artifact_digests.get("missingness_mask_sha256")
            == hashlib.sha256(truth_mask).hexdigest()
            == hashlib.sha256(data_mask).hexdigest()
        ]
        return HandlerResult(key=key, state="PASS", value=value, reason_codes=())
    except _DerivationFailure as error:
        reason_code = error.reason_code
    except (
        CanonicalizationError,
        KeyError,
        ScenarioEvidenceContextError,
        SchemaValidationError,
        TypeError,
        ValueError,
    ):
        reason_code = _SCIENTIFIC_VALIDATION_FAILED
    return HandlerResult(key=key, state="FAIL", value=None, reason_codes=(reason_code,))


def _handle_mcar_mask(request: HandlerRequest) -> HandlerResult:
    return _handle(request, _MCAR_MASK_KEY)


def _handle_mar_mask(request: HandlerRequest) -> HandlerResult:
    return _handle(request, _MAR_MASK_KEY)


def _validated_missingness_projection(
    value: object,
) -> _SyntheticMissingnessProjection:
    if type(value) is not _SyntheticMissingnessProjection:
        _fail(_OWNER_BINDING_INVALID)
    participant_count, event_count = value.dimensions
    if (
        type(value.case_id) is not str
        or not value.case_id
        or type(value.generated_scientific_data_sha256) is not str
        or len(value.generated_scientific_data_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in value.generated_scientific_data_sha256
        )
        or type(value.dimensions) is not tuple
        or len(value.dimensions) != 2
        or type(participant_count) is not int
        or participant_count < 1
        or type(event_count) is not int
        or event_count < 1
        or type(value.participant_internal_indexes) is not tuple
        or len(value.participant_internal_indexes) != participant_count
        or any(
            type(index) is not int or index < 0
            for index in value.participant_internal_indexes
        )
        or len(set(value.participant_internal_indexes)) != participant_count
        or type(value.event_ids) is not tuple
        or len(value.event_ids) != event_count
        or any(type(event_id) is not str or not event_id for event_id in value.event_ids)
        or len(set(value.event_ids)) != event_count
        or type(value.analysis_group_labels) is not tuple
        or len(value.analysis_group_labels) != participant_count
        or any(
            label not in ("reference", "at_risk")
            for label in value.analysis_group_labels
        )
        or type(value.missingness_mask) is not tuple
        or len(value.missingness_mask) != participant_count
        or any(
            type(row) is not tuple
            or len(row) != event_count
            or any(type(cell) is not bool for cell in row)
            for row in value.missingness_mask
        )
    ):
        _fail(_OWNER_BINDING_INVALID)
    return value


def _preservation_projections(
    request: HandlerRequest,
) -> tuple[_SyntheticMissingnessProjection, _SyntheticMissingnessProjection]:
    key = _MISSING_COUNT_PRESERVATION_KEY
    if type(request) is not HandlerRequest or request.key != key:
        _fail(_REQUEST_INVALID)
    if type(request.owner_projections) is not tuple or len(request.owner_projections) != 2:
        _fail(_OWNER_COVERAGE_INVALID)

    context = _CONTEXT_READER(request.context)
    family_id = cast(str, key[1])
    if context.identity.family_id != family_id:
        _fail(_OWNER_BINDING_INVALID)

    projections: list[_SyntheticMissingnessProjection] = []
    for owner_projection in request.owner_projections:
        if type(owner_projection) is not tuple:
            _fail(_OWNER_BINDING_INVALID)
        if len(owner_projection) != 1:
            _fail(_OWNER_COVERAGE_INVALID)
        projections.append(_validated_missingness_projection(owner_projection[0]))
    source, transformed = projections
    if (
        source is transformed
        or source == transformed
        or source.case_id == transformed.case_id
        or source.case_id == context.identity.case_id
        or transformed.case_id != context.identity.case_id
    ):
        _fail(_OWNER_BINDING_INVALID)
    return source, transformed


def _preservation_axes(
    projection: _SyntheticMissingnessProjection,
) -> tuple[tuple[int, int], tuple[int, ...], tuple[str, ...], tuple[str, ...]]:
    return (
        projection.dimensions,
        projection.participant_internal_indexes,
        projection.event_ids,
        projection.analysis_group_labels,
    )


def _missing_count_structure(
    projection: _SyntheticMissingnessProjection,
) -> tuple[int, tuple[tuple[str, int], ...], tuple[tuple[str, int], ...]]:
    group_order = sorted(
        set(projection.analysis_group_labels), key=lambda label: label.encode("utf-8")
    )
    return (
        sum(cell for row in projection.missingness_mask for cell in row),
        tuple(
            (
                group,
                sum(
                    cell
                    for label, row in zip(
                        projection.analysis_group_labels,
                        projection.missingness_mask,
                        strict=True,
                    )
                    if label == group
                    for cell in row
                ),
            )
            for group in group_order
        ),
        tuple(
            (
                event_id,
                sum(row[event_index] for row in projection.missingness_mask),
            )
            for event_index, event_id in enumerate(projection.event_ids)
        ),
    )


def _handle_missing_count_preservation(request: HandlerRequest) -> HandlerResult:
    key = _MISSING_COUNT_PRESERVATION_KEY
    try:
        source, transformed = _preservation_projections(request)
        source_axes = _preservation_axes(source)
        transformed_axes = _preservation_axes(transformed)
        value = (
            source_axes == transformed_axes
            and _missing_count_structure(source) == _missing_count_structure(transformed)
        )
        return HandlerResult(key=key, state="PASS", value=value, reason_codes=())
    except _DerivationFailure as error:
        reason_code = error.reason_code
    except (
        CanonicalizationError,
        KeyError,
        ScenarioEvidenceContextError,
        SchemaValidationError,
        TypeError,
        ValueError,
    ):
        reason_code = _SCIENTIFIC_VALIDATION_FAILED
    return HandlerResult(key=key, state="FAIL", value=None, reason_codes=(reason_code,))


HANDLERS: tuple[tuple[HandlerKey, Handler], ...] = (
    (_MCAR_MASK_KEY, _handle_mcar_mask),
    (_MAR_MASK_KEY, _handle_mar_mask),
    (_MISSING_COUNT_PRESERVATION_KEY, _handle_missing_count_preservation),
)

__all__ = ["HANDLERS"]
