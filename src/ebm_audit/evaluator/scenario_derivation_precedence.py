"""Capture-backed pairwise-precedence projections and frozen handlers."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Never, SupportsIndex, cast, final

import numpy as np

from ebm_audit._capability_registry import OneShotWeakRegistry, create_one_shot_registry
from ebm_audit.evaluator.scenario_derivation_handler_protocol import (
    Handler,
    HandlerKey,
    HandlerRequest,
    HandlerResult,
)
from ebm_audit.evaluator.scenario_evidence import _read_scenario_evidence_context
from ebm_audit.evaluator.scenario_source_owner_manifest import (
    _read_authenticated_source_owner_record,
    _ScenarioSourceOwnerRecord,
    _ScenarioSourceRecordInput,
)
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads
from ebm_audit.protocol.canonical import structured_sha256_hex
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.science import CapturedScientificRun
from ebm_audit.science.capture import _CapturedScientificRunState, _read_captured_scientific_run
from ebm_audit.synthetic.audit_input import (
    SyntheticTruthScoringEvidence,
    _read_synthetic_truth_scoring_record_bytes,
)

_PRIVATE_OWNER_CLASS: Final = "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION"
_PRIVATE_OWNER_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/PrivateCanonicalArrayValueProjection"
)
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_PRIVATE_PROJECTION_DOMAIN: Final = "ebm-audit/private-canonical-array-value-projection/1"
_ARRAY_VALUE_DOMAIN: Final = "ebm-audit/canonical-array-value/1"
_ARRAY_ARTIFACT_DOMAIN: Final = "ebm-audit/canonical-array-artifact-owner/1"
_TRUTH_DOMAIN: Final = "ebm-audit/synthetic-truth/1"
_MEMBER_NAME: Final = "pairwise_precedence"
_DTYPE: Final = "float64"
_AXES: Final = ("event", "event")

_REQUEST_INVALID: Final = "SCENARIO.DERIVATION_REQUEST_INVALID"
_OWNER_COVERAGE_INVALID: Final = "SCENARIO.DERIVATION_OWNER_COVERAGE_INVALID"
_OWNER_BINDING_INVALID: Final = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
_VALIDATION_FAILED: Final = "SCENARIO.DERIVATION_VALIDATION_FAILED"


class _PrecedenceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> Never:
    raise _PrecedenceError(code)


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


def _mapping(value: object) -> dict[str, object]:
    detached = _plain(value)
    if type(detached) is not dict:
        _fail(_OWNER_BINDING_INVALID)
    return cast(dict[str, object], detached)


def _validate(value: object, schema: str, definition: str | None = None) -> None:
    try:
        validate_instance(value, schema, definition=definition)
    except SchemaValidationError:
        _fail(_OWNER_BINDING_INVALID)


def _self_digest(record: Mapping[str, object], field: str, domain: str) -> str:
    preimage = _mapping(record)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage[field] = None
    return structured_sha256_hex(domain, preimage)


def _source_record_digest(
    owner_class: str,
    identity: Mapping[str, object],
    record: Mapping[str, object],
) -> str:
    return structured_sha256_hex(
        _SOURCE_RECORD_DOMAIN,
        {"owner_class": owner_class, "natural_identity": identity, "source_record": record},
    )


@dataclass(frozen=True, slots=True)
class _PairwiseProjectionView:
    record: Mapping[str, object]
    artifact: Mapping[str, object]
    benchmark_subject_digest: str
    family_id: str
    case_id: str
    operation_instance_id: str
    chain_execution_id: str
    event_ids: tuple[str, ...]
    values: tuple[tuple[float, ...], ...]


@dataclass(frozen=True, slots=True)
class _PairwiseProjectionState:
    capture: CapturedScientificRun
    artifact_record: _ScenarioSourceOwnerRecord
    record_bytes: bytes


@final
class _CaptureBackedPairwisePrecedenceProjection:
    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> _CaptureBackedPairwisePrecedenceProjection:
        raise TypeError("Private pairwise-precedence projections are privately issued.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Private pairwise-precedence projections cannot be serialized.")


_PROJECTION_STATES: OneShotWeakRegistry[
    _CaptureBackedPairwisePrecedenceProjection, _PairwiseProjectionState
]
_PROJECTION_STATES, _PROJECTION_STATE_ISSUER = create_one_shot_registry()


def _authenticated_artifact(record: _ScenarioSourceOwnerRecord) -> dict[str, object]:
    try:
        authenticated = _read_authenticated_source_owner_record(record)
    except Exception:
        _fail(_OWNER_BINDING_INVALID)
    artifact = _mapping(authenticated)
    if (
        record.owner_class != "CANONICAL_ARRAY_ARTIFACT"
        or record.owner_schema_ref
        != "schemas/scenario-evidence.schema.json#/$defs/CanonicalArrayArtifactOwner"
    ):
        _fail(_OWNER_BINDING_INVALID)
    _validate(artifact, "scenario-evidence.schema.json", "CanonicalArrayArtifactOwner")
    if artifact.get("digest_state") != "PERSISTED" or artifact.get(
        "canonical_array_artifact_owner_sha256"
    ) != _self_digest(
        artifact,
        "canonical_array_artifact_owner_sha256",
        _ARRAY_ARTIFACT_DOMAIN,
    ):
        _fail(_OWNER_BINDING_INVALID)
    return artifact


def _pairwise_matrix(snapshot: object) -> tuple[tuple[float, ...], ...]:
    try:
        array = snapshot._array()  # type: ignore[attr-defined]
    except Exception:
        _fail(_OWNER_BINDING_INVALID)
    if (
        type(array) is not np.ndarray
        or array.dtype != np.dtype("float64")
        or array.ndim != 2
        or array.shape[0] != array.shape[1]
        or array.shape[0] < 2
        or not np.isfinite(array).all()
    ):
        _fail(_OWNER_BINDING_INVALID)
    values = tuple(tuple(float(value) for value in row) for row in array.tolist())
    for row_index, row in enumerate(values):
        for column_index, value in enumerate(row):
            if not 0.0 <= value <= 1.0:
                _fail(_OWNER_BINDING_INVALID)
            if row_index == column_index:
                if value != 0.5:
                    _fail(_OWNER_BINDING_INVALID)
            elif value + values[column_index][row_index] != 1.0:
                _fail(_OWNER_BINDING_INVALID)
    return values


def _derive_pairwise_projection(
    capture_state: _CapturedScientificRunState,
    artifact_record: _ScenarioSourceOwnerRecord,
) -> _PairwiseProjectionView:
    artifact = _authenticated_artifact(artifact_record)
    try:
        binding_bytes = capture_state.synthetic_case_binding_bytes
        if type(binding_bytes) is not bytes:
            _fail(_OWNER_BINDING_INVALID)
        binding = _mapping(strict_json_loads(binding_bytes))
        candidates = tuple(
            candidate
            for candidate in capture_state.candidates
            if candidate.universe_id == artifact.get("operation_instance_id")
        )
    except Exception:
        _fail(_OWNER_BINDING_INVALID)
    if len(candidates) != 1:
        _fail(_OWNER_BINDING_INVALID)
    candidate = candidates[0]
    chains = tuple(
        chain
        for chain in candidate.chains
        if chain.chain_execution_id == artifact.get("chain_execution_id")
    )
    if len(chains) != 1:
        _fail(_OWNER_BINDING_INVALID)
    chain = chains[0]
    snapshots = tuple(snapshot for snapshot in chain.arrays if snapshot.name == _MEMBER_NAME)
    if len(snapshots) != 1:
        _fail(_OWNER_BINDING_INVALID)
    snapshot = snapshots[0]
    try:
        catalog = _mapping(strict_json_loads(snapshot.catalog_bytes))
        chain_payload = _mapping(strict_json_loads(chain.chain_payload_bytes))
        values = _pairwise_matrix(snapshot)
        event_ids = tuple(cast(Sequence[str], candidate.event_ids))
        raw_bytes = bytes(snapshot.private_array_bytes)
    except Exception:
        _fail(_OWNER_BINDING_INVALID)
    expected_shape = (len(event_ids), len(event_ids))
    value_digest = structured_sha256_hex(
        _ARRAY_VALUE_DOMAIN,
        {
            "member_name": _MEMBER_NAME,
            "dtype": _DTYPE,
            "shape": list(expected_shape),
            "semantic_version": catalog.get("semantic_version"),
            "axes": list(_AXES),
            "values": [list(row) for row in values],
        },
    )
    artifact_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if (
        type(binding.get("case_id")) is not str
        or artifact.get("case_id") != binding.get("case_id")
        or candidate.final_status != "SUCCESS"
        or tuple(event_ids) == ()
        or len(set(event_ids)) != len(event_ids)
        or artifact.get("chain_execution_id") != chain.chain_execution_id
        or artifact.get("attempt_id") != chain.final_attempt_id
        or artifact.get("chain_id") != chain_payload.get("chain_id")
        or artifact.get("member_name") != _MEMBER_NAME
        or artifact.get("fit_payload_array_pointer") != "/array_catalog/pairwise_precedence"
        or artifact.get("canonical_payload_array_pointer")
        != f"/ordered_chain_payloads/{chain.chain_plan_position}/arrays/pairwise_precedence"
        or artifact.get("dtype") != _DTYPE
        or tuple(cast(Sequence[int], artifact.get("shape"))) != expected_shape
        or artifact.get("shape") != catalog.get("shape")
        or artifact.get("semantic_version") != catalog.get("semantic_version")
        or catalog.get("member_name") != _MEMBER_NAME
        or catalog.get("dtype") != _DTYPE
        or catalog.get("byte_length") != len(raw_bytes)
        or catalog.get("array_digest") != "sha256:" + artifact_sha256
        or artifact.get("artifact_byte_length") != len(raw_bytes)
        or artifact.get("artifact_sha256") != artifact_sha256
        or artifact.get("array_value_sha256") != value_digest
        or snapshot.shape != expected_shape
    ):
        _fail(_OWNER_BINDING_INVALID)
    projection: dict[str, object] = {
        "schema_version": "ebm-audit-private-canonical-array-value-projection/1.0",
        "canonical_array_artifact_owner_sha256": artifact[
            "canonical_array_artifact_owner_sha256"
        ],
        "member_name": _MEMBER_NAME,
        "dtype": _DTYPE,
        "shape": list(expected_shape),
        "semantic_version": artifact["semantic_version"],
        "axes": list(_AXES),
        "array_value_sha256": value_digest,
    }
    projection["private_canonical_array_value_projection_sha256"] = structured_sha256_hex(
        _PRIVATE_PROJECTION_DOMAIN, projection
    )
    _validate(projection, "scenario-evidence.schema.json", "PrivateCanonicalArrayValueProjection")
    return _PairwiseProjectionView(
        record=MappingProxyType(projection),
        artifact=MappingProxyType(artifact),
        benchmark_subject_digest=cast(str, artifact["benchmark_subject_digest"]),
        family_id=cast(str, artifact["family_id"]),
        case_id=cast(str, artifact["case_id"]),
        operation_instance_id=cast(str, artifact["operation_instance_id"]),
        chain_execution_id=cast(str, artifact["chain_execution_id"]),
        event_ids=event_ids,
        values=values,
    )


def _issue_pairwise_precedence_projection(
    capture: CapturedScientificRun,
    artifact_record: _ScenarioSourceOwnerRecord,
) -> _CaptureBackedPairwisePrecedenceProjection:
    if type(capture) is not CapturedScientificRun:
        _fail(_OWNER_BINDING_INVALID)
    try:
        capture_state = _read_captured_scientific_run(capture)
    except Exception:
        _fail(_OWNER_BINDING_INVALID)
    view = _derive_pairwise_projection(capture_state, artifact_record)
    owner = object.__new__(_CaptureBackedPairwisePrecedenceProjection)
    _PROJECTION_STATE_ISSUER.bind_once(
        owner,
        _PairwiseProjectionState(
            capture=capture,
            artifact_record=artifact_record,
            record_bytes=canonical_json_bytes(dict(view.record)),
        ),
    )
    return owner


def _read_pairwise_precedence_projection(owner: object) -> _PairwiseProjectionView:
    if type(owner) is not _CaptureBackedPairwisePrecedenceProjection:
        _fail(_OWNER_BINDING_INVALID)
    try:
        state = _PROJECTION_STATES.read(owner)
        capture_state = _read_captured_scientific_run(state.capture)
    except Exception:
        _fail(_OWNER_BINDING_INVALID)
    view = _derive_pairwise_projection(capture_state, state.artifact_record)
    if canonical_json_bytes(dict(view.record)) != state.record_bytes:
        _fail(_OWNER_BINDING_INVALID)
    return view


def _pairwise_precedence_source_record(owner: object) -> _ScenarioSourceRecordInput:
    view = _read_pairwise_precedence_projection(owner)
    record = dict(view.record)
    identity = {
        field: cast(str, record[field])
        for field in (
            "canonical_array_artifact_owner_sha256",
            "member_name",
            "array_value_sha256",
        )
    }
    record_bytes = canonical_json_bytes(record)
    return _ScenarioSourceRecordInput(
        owner_class=_PRIVATE_OWNER_CLASS,
        owner_schema_ref=_PRIVATE_OWNER_SCHEMA_REF,
        source_relative_path=(
            "owners/private-canonical-array-values/"
            f"{record['private_canonical_array_value_projection_sha256']}.json"
        ),
        source_content_bytes=record_bytes,
        source_record_bytes=record_bytes,
        natural_identity=identity,
        source_capability=owner,
    )


_KEY_ROWS: Final = (
    (
        "tightly_spaced_events",
        "/payload/target_pair_precedence",
        "truth-target-pair-precedence/1",
        "declared-target-pair/1",
        "same-case-pairwise-precedence/1",
        "TARGET",
    ),
    (
        "correlated_duplicate_events",
        "/payload/correlated/target_pair_precedence",
        "truth-target-pair-precedence/1",
        "correlated-subtype-truth/1",
        "correlated-subtype-pairwise-array/1",
        "CORRELATED_TARGET",
    ),
    (
        "correlated_duplicate_events",
        "/payload/exact_duplicate_post_noise/target_pair_precedence",
        "truth-target-pair-precedence/1",
        "exact-duplicate-subtype-truth/1",
        "exact-duplicate-subtype-pairwise-array/1",
        "EXACT_DUPLICATE_TARGET",
    ),
    (
        "opposing_sequences_50_50",
        "/payload/opposing_pair_absolute_precedence_from_half",
        "opposing-pair-absolute-precedence-from-half/1",
        "declared-opposing-relations/1",
        "same-case-pairwise-precedence/1",
        "OPPOSING",
    ),
    (
        "near_simultaneous_events",
        "/payload/block_pair_precedence",
        "truth-block-pair-precedence/1",
        "declared-equivalence-block/1",
        "same-case-pairwise-precedence/1",
        "BLOCK",
    ),
)


def _key(row: tuple[str, str, str, str, str, str]) -> HandlerKey:
    family_id, output_path, derivation_id, truth_selector, array_selector, _mode = row
    cardinality = (
        "ONE_PER_SUBTYPE_CASE"
        if family_id == "correlated_duplicate_events"
        else "ONE_PER_CASE"
    )
    return (
        "FAMILY_OUTPUT",
        family_id,
        output_path,
        derivation_id,
        (
            ("SYNTHETIC_TRUTH", cardinality, truth_selector),
            (_PRIVATE_OWNER_CLASS, cardinality, array_selector),
        ),
    )


def _truth_record(record: _ScenarioSourceOwnerRecord) -> dict[str, object]:
    if (
        type(record) is not _ScenarioSourceOwnerRecord
        or record.owner_class != "SYNTHETIC_TRUTH"
        or record.owner_schema_ref != "schemas/synthetic-truth.schema.json"
        or type(record.source_capability) is not SyntheticTruthScoringEvidence
    ):
        _fail(_OWNER_BINDING_INVALID)
    try:
        trusted_bytes = _read_synthetic_truth_scoring_record_bytes(record.source_capability)
    except Exception:
        _fail(_OWNER_BINDING_INVALID)
    truth = _mapping(record.source_record)
    _validate(truth, "synthetic-truth.schema.json")
    truth_digest = truth.get("truth_object_sha256")
    identity = {"truth_object_sha256": truth_digest}
    if (
        trusted_bytes != canonical_json_bytes(truth)
        or truth.get("digest_state") != "PERSISTED"
        or truth_digest != _self_digest(truth, "truth_object_sha256", _TRUTH_DOMAIN)
        or dict(record.natural_identity) != identity
        or record.source_record_sha256
        != _source_record_digest("SYNTHETIC_TRUTH", identity, truth)
    ):
        _fail(_OWNER_BINDING_INVALID)
    return truth


def _projection_record(record: _ScenarioSourceOwnerRecord) -> _PairwiseProjectionView:
    if (
        type(record) is not _ScenarioSourceOwnerRecord
        or record.owner_class != _PRIVATE_OWNER_CLASS
        or record.owner_schema_ref != _PRIVATE_OWNER_SCHEMA_REF
        or type(record.source_capability) is not _CaptureBackedPairwisePrecedenceProjection
    ):
        _fail(_OWNER_BINDING_INVALID)
    view = _read_pairwise_precedence_projection(record.source_capability)
    public = dict(view.record)
    identity = {
        field: public[field]
        for field in (
            "canonical_array_artifact_owner_sha256",
            "member_name",
            "array_value_sha256",
        )
    }
    if (
        dict(record.natural_identity) != identity
        or _mapping(record.source_record) != public
        or record.source_record_sha256
        != _source_record_digest(_PRIVATE_OWNER_CLASS, identity, public)
        or record.ordered_support_owner_sha256 != ()
    ):
        _fail(_OWNER_BINDING_INVALID)
    return view


def _truth_coordinate(truth: Mapping[str, object]) -> tuple[str, str]:
    scenario = truth.get("scenario_identity")
    if not isinstance(scenario, Mapping):
        _fail(_OWNER_BINDING_INVALID)
    family_id = scenario.get("family_id")
    case_id = scenario.get("case_id")
    if type(family_id) is not str or type(case_id) is not str:
        _fail(_OWNER_BINDING_INVALID)
    return family_id, case_id


def _selected_owners(
    request: HandlerRequest,
) -> tuple[dict[str, object], _PairwiseProjectionView]:
    if (
        type(request.owner_projections) is not tuple
        or len(request.owner_projections) != 2
        or any(type(projection) is not tuple for projection in request.owner_projections)
    ):
        _fail(_OWNER_COVERAGE_INVALID)
    context = _read_scenario_evidence_context(request.context)
    truth_candidates = tuple(_truth_record(record) for record in request.owner_projections[0])
    truths = tuple(
        truth
        for truth in truth_candidates
        if _truth_coordinate(truth)
        == (context.identity.family_id, context.identity.case_id)
    )
    projection_candidates = tuple(
        _projection_record(record) for record in request.owner_projections[1]
    )
    projections = tuple(
        projection
        for projection in projection_candidates
        if (
            projection.family_id,
            projection.case_id,
            projection.benchmark_subject_digest,
        )
        == (
            context.identity.family_id,
            context.identity.case_id,
            context.identity.benchmark_subject_digest,
        )
    )
    if len(truths) != 1 or len(projections) != 1:
        _fail(_OWNER_COVERAGE_INVALID)
    truth, projection = truths[0], projections[0]
    event_truth = truth.get("event_truth")
    if not isinstance(event_truth, Mapping):
        _fail(_OWNER_BINDING_INVALID)
    event_ids = tuple(cast(Sequence[str], event_truth.get("event_ids")))
    if (
        event_ids != projection.event_ids
        or len(event_ids) < 2
        or len(set(event_ids)) != len(event_ids)
    ):
        _fail(_OWNER_BINDING_INVALID)
    return truth, projection


def _target_value(
    truth: Mapping[str, object],
    projection: _PairwiseProjectionView,
    *,
    mode: str,
) -> tuple[float, ...]:
    order_truth = truth.get("order_truth")
    mechanism = truth.get("mechanism_evidence")
    if not isinstance(order_truth, Mapping) or not isinstance(mechanism, Mapping):
        _fail(_OWNER_BINDING_INVALID)
    target = tuple(cast(Sequence[str], mechanism.get("target_pair_event_ids")))
    blocks = tuple(
        tuple(block)
        for block in cast(Sequence[Sequence[str]], order_truth.get("partial_order_blocks"))
    )
    reason = order_truth.get("non_identifiability_reason")
    if (
        len(target) != 2
        or len(set(target)) != 2
        or any(event_id not in projection.event_ids for event_id in target)
    ):
        _fail(_OWNER_BINDING_INVALID)
    if mode in {"TARGET", "CORRELATED_TARGET"}:
        strict_order = tuple(cast(Sequence[str], order_truth.get("strict_order")))
        if (
            order_truth.get("truth_kind") != "STRICT_TOTAL_ORDER"
            or order_truth.get("strict_order_identifiable") is not True
            or strict_order != projection.event_ids
            or reason is not None
        ):
            _fail(_OWNER_BINDING_INVALID)
    elif (
        mode != "EXACT_DUPLICATE_TARGET"
        or order_truth.get("truth_kind") != "PARTIAL_ORDER"
        or order_truth.get("strict_order_identifiable") is not False
        or reason != "EXACT_DUPLICATE"
        or sum(set(block) == set(target) for block in blocks) != 1
    ):
        _fail(_OWNER_BINDING_INVALID)
    indexes = {event_id: index for index, event_id in enumerate(projection.event_ids)}
    return (projection.values[indexes[target[0]]][indexes[target[1]]],)


def _opposing_values(
    truth: Mapping[str, object],
    projection: _PairwiseProjectionView,
) -> tuple[float, ...]:
    order_truth = truth.get("order_truth")
    subgroup_truth = truth.get("subgroup_truth")
    if not isinstance(order_truth, Mapping) or not isinstance(subgroup_truth, Mapping):
        _fail(_OWNER_BINDING_INVALID)
    orders = tuple(
        tuple(order)
        for order in cast(Sequence[Sequence[str]], subgroup_truth.get("subgroup_orders"))
    )
    events = tuple(sorted(projection.event_ids, key=lambda value: value.encode("utf-8")))
    pairs = tuple(
        (events[left], events[right])
        for left in range(len(events))
        for right in range(left + 1, len(events))
    )
    if (
        order_truth.get("truth_kind") != "MIXTURE_OF_STRICT_ORDERS"
        or order_truth.get("non_identifiability_reason") != "OPPOSING_SEQUENCES"
        or len(orders) != 2
        or any(set(order) != set(events) or len(order) != len(events) for order in orders)
        or not pairs
    ):
        _fail(_OWNER_BINDING_INVALID)
    positions = tuple({event_id: index for index, event_id in enumerate(order)} for order in orders)
    if any(
        (positions[0][left] < positions[0][right])
        == (positions[1][left] < positions[1][right])
        for left, right in pairs
    ):
        _fail(_OWNER_BINDING_INVALID)
    matrix_indexes = {event_id: index for index, event_id in enumerate(projection.event_ids)}
    return tuple(
        abs(projection.values[matrix_indexes[left]][matrix_indexes[right]] - 0.5)
        for left, right in pairs
    )


def _block_values(
    truth: Mapping[str, object],
    projection: _PairwiseProjectionView,
) -> tuple[float, ...]:
    order_truth = truth.get("order_truth")
    mechanism = truth.get("mechanism_evidence")
    if not isinstance(order_truth, Mapping) or not isinstance(mechanism, Mapping):
        _fail(_OWNER_BINDING_INVALID)
    blocks = tuple(
        tuple(block)
        for block in cast(Sequence[Sequence[str]], order_truth.get("partial_order_blocks"))
    )
    declared = tuple(cast(Sequence[str], mechanism.get("equivalence_block_event_ids")))
    if (
        order_truth.get("truth_kind") != "PARTIAL_ORDER"
        or order_truth.get("non_identifiability_reason") != "EQUIVALENCE_BLOCK"
        or len(declared) < 2
        or len(set(declared)) != len(declared)
        or sum(set(block) == set(declared) for block in blocks) != 1
        or any(
            len(block) < 2
            or len(set(block)) != len(block)
            or any(event_id not in projection.event_ids for event_id in block)
            for block in blocks
        )
    ):
        _fail(_OWNER_BINDING_INVALID)
    pairs = tuple(
        pair
        for block in blocks
        for pair in (
            (events[left], events[right])
            for events in (tuple(sorted(block, key=lambda value: value.encode("utf-8"))),)
            for left in range(len(events))
            for right in range(left + 1, len(events))
        )
    )
    if not pairs:
        _fail(_OWNER_BINDING_INVALID)
    indexes = {event_id: index for index, event_id in enumerate(projection.event_ids)}
    return tuple(projection.values[indexes[left]][indexes[right]] for left, right in pairs)


def _handler(request: HandlerRequest) -> HandlerResult:
    try:
        key_by_row = {_key(row): row for row in _KEY_ROWS}
        if type(request) is not HandlerRequest or request.key not in key_by_row:
            _fail(_REQUEST_INVALID)
        row = key_by_row[request.key]
        truth, projection = _selected_owners(request)
        mode = row[-1]
        if mode in {"TARGET", "CORRELATED_TARGET", "EXACT_DUPLICATE_TARGET"}:
            value = _target_value(truth, projection, mode=mode)
        elif mode == "OPPOSING":
            value = _opposing_values(truth, projection)
        elif mode == "BLOCK":
            value = _block_values(truth, projection)
        else:
            _fail(_REQUEST_INVALID)
        if any(not math.isfinite(item) for item in value):
            _fail(_OWNER_BINDING_INVALID)
        return HandlerResult(request.key, "PASS", value, ())
    except _PrecedenceError as error:
        reason = error.code
    except Exception:
        reason = _VALIDATION_FAILED
    return HandlerResult(request.key, "FAIL", None, (reason,))


HANDLERS: tuple[tuple[HandlerKey, Handler], ...] = tuple(
    (key, _handler) for key in map(_key, _KEY_ROWS)
)

__all__ = ["HANDLERS"]
