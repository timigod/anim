"""Private matched-metric issuance and frozen family-output handlers."""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
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
from ebm_audit.metrics import normalized_kendall_distance, position_event_summaries, position_matrix
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads
from ebm_audit.protocol.canonical import structured_sha256_hex
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.science._evidence_records import _within_entropy_metrics
from ebm_audit.synthetic.audit_input import (
    SyntheticTruthScoringEvidence,
    _read_synthetic_truth_scoring_record_bytes,
)

_OWNER_CLASS: Final = "SCENARIO_MATCHED_METRIC_RECORD"
_OWNER_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/ScenarioMatchedMetricRecord"
)
_PRIVATE_OWNER_CLASS: Final = "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION"
_PRIVATE_OWNER_SCHEMA_REF: Final = (
    "schemas/scenario-evidence.schema.json#/$defs/PrivateCanonicalArrayValueProjection"
)
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_RECORD_DOMAIN: Final = "ebm-audit/scenario-matched-metric-record/2"
_PRIVATE_PROJECTION_DOMAIN: Final = "ebm-audit/private-canonical-array-value-projection/1"
_ARRAY_VALUE_DOMAIN: Final = "ebm-audit/canonical-array-value/1"
_ARRAY_ARTIFACT_DOMAIN: Final = "ebm-audit/canonical-array-artifact-owner/1"
_SEALED_RESULT_DOMAIN: Final = "ebm-audit/sealed-result-record/1"
_PAYLOAD_DOMAIN: Final = "ebm-audit/canonical-scientific-payload/1"
_TRUTH_DOMAIN: Final = "ebm-audit/synthetic-truth/1"
_MATCHED_MANIFEST_DOMAIN: Final = "ebm-audit/matched-comparator-evidence-manifest/1"
_MATCHED_PLAN_DOMAIN: Final = "ebm-audit/matched-comparator-plan-evidence/1"
_ENTROPY_METRIC: Final = "within-fit-mean-normalized-position-entropy/1"
_KENDALL_METRIC: Final = "central-order-kendall-distance/1"
_SCHEMA_VERSION: Final = "ebm-audit-scenario-matched-metric-record/2.0"
_UNAVAILABLE_REASON: Final = "SCENARIO.MATCHED_METRIC_NOT_ASSESSABLE"

_REQUEST_INVALID: Final = "SCENARIO.DERIVATION_REQUEST_INVALID"
_OWNER_COVERAGE_INVALID: Final = "SCENARIO.DERIVATION_OWNER_COVERAGE_INVALID"
_OWNER_BINDING_INVALID: Final = "SCENARIO.DERIVATION_OWNER_BINDING_INVALID"
_OWNER_UNAVAILABLE: Final = "SCENARIO.DERIVATION_OWNER_UNAVAILABLE"
_VALIDATION_FAILED: Final = "SCENARIO.DERIVATION_VALIDATION_FAILED"


class _MatchedMetricError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> Never:
    raise _MatchedMetricError(code)


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


def _finite(value: object) -> float:
    if type(value) not in (int, float) or not math.isfinite(cast(float, value)):
        _fail(_OWNER_BINDING_INVALID)
    return float(cast(int | float, value))


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
class _PrivateProjectionState:
    record_bytes: bytes
    artifact_record: _ScenarioSourceOwnerRecord
    values: tuple[object, ...]


@final
class _PrivateCanonicalArrayValueProjection:
    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _PrivateCanonicalArrayValueProjection:
        raise TypeError("Private canonical array projections are privately issued.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Private canonical array projections cannot be serialized.")


_PRIVATE_STATES: OneShotWeakRegistry[_PrivateCanonicalArrayValueProjection, _PrivateProjectionState]
_PRIVATE_STATES, _PRIVATE_STATE_ISSUER = create_one_shot_registry()


@dataclass(frozen=True, slots=True)
class _MatchedMetricRecordState:
    record_bytes: bytes
    member_case_ids: tuple[str, str]


@final
class ScenarioMatchedMetricRecord:
    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ScenarioMatchedMetricRecord:
        raise TypeError("Scenario matched metric records are privately issued.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Scenario matched metric records cannot be serialized.")


_RECORD_STATES: OneShotWeakRegistry[ScenarioMatchedMetricRecord, _MatchedMetricRecordState]
_RECORD_STATES, _RECORD_STATE_ISSUER = create_one_shot_registry()


def _validated_authenticated_record(
    record: _ScenarioSourceOwnerRecord,
    owner_class: str,
    schema_ref: str,
    schema: str,
    definition: str | None = None,
) -> dict[str, object]:
    try:
        authenticated = _read_authenticated_source_owner_record(record)
    except Exception:
        _fail(_OWNER_BINDING_INVALID)
    value = _mapping(authenticated)
    if record.owner_class != owner_class or record.owner_schema_ref != schema_ref:
        _fail(_OWNER_BINDING_INVALID)
    _validate(value, schema, definition)
    return value


def _nested_shape(values: tuple[object, ...]) -> tuple[int, ...]:
    if not values:
        _fail(_OWNER_BINDING_INVALID)
    if all(type(value) is int for value in values):
        return (len(values),)
    if not all(type(value) is tuple for value in values):
        _fail(_OWNER_BINDING_INVALID)
    rows = cast(tuple[tuple[object, ...], ...], values)
    if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
        _fail(_OWNER_BINDING_INVALID)
    if any(type(value) is not int for row in rows for value in row):
        _fail(_OWNER_BINDING_INVALID)
    return len(rows), len(rows[0])


def _int32_bytes(values: tuple[object, ...]) -> bytes:
    flattened: Sequence[object]
    if all(type(value) is int for value in values):
        flattened = values
    else:
        flattened = tuple(
            value for row in cast(tuple[tuple[object, ...], ...], values) for value in row
        )
    integers = cast(Sequence[int], flattened)
    if any(value < -(2**31) or value >= 2**31 for value in integers):
        _fail(_OWNER_BINDING_INVALID)
    return b"".join(struct.pack("<i", value) for value in integers)


def _array_json_values(values: tuple[object, ...]) -> list[object]:
    return [
        list(cast(tuple[int, ...], value)) if type(value) is tuple else value for value in values
    ]


def _issue_private_canonical_array_value_projection(
    artifact_owner: _ScenarioSourceOwnerRecord,
    values: tuple[object, ...],
) -> _PrivateCanonicalArrayValueProjection:
    artifact = _validated_authenticated_record(
        artifact_owner,
        "CANONICAL_ARRAY_ARTIFACT",
        "schemas/scenario-evidence.schema.json#/$defs/CanonicalArrayArtifactOwner",
        "scenario-evidence.schema.json",
        "CanonicalArrayArtifactOwner",
    )
    if type(values) is not tuple:
        _fail(_OWNER_BINDING_INVALID)
    shape = _nested_shape(values)
    member_name = artifact.get("member_name")
    expected_shape = (len(values),) if member_name == "central_order_permutation" else shape
    axes = ("event",) if member_name == "central_order_permutation" else ("state", "event")
    value_bytes = _int32_bytes(values)
    if (
        artifact.get("digest_state") != "PERSISTED"
        or artifact.get("dtype") != "int32"
        or tuple(cast(list[object], artifact.get("shape"))) != expected_shape
        or artifact.get("artifact_byte_length") != len(value_bytes)
        or artifact.get("artifact_sha256") != hashlib.sha256(value_bytes).hexdigest()
        or artifact.get("canonical_array_artifact_owner_sha256")
        != _self_digest(artifact, "canonical_array_artifact_owner_sha256", _ARRAY_ARTIFACT_DOMAIN)
    ):
        _fail(_OWNER_BINDING_INVALID)
    value_digest = structured_sha256_hex(
        _ARRAY_VALUE_DOMAIN,
        {
            "member_name": member_name,
            "dtype": "int32",
            "shape": list(expected_shape),
            "semantic_version": artifact.get("semantic_version"),
            "axes": list(axes),
            "values": _array_json_values(values),
        },
    )
    if artifact.get("array_value_sha256") != value_digest:
        _fail(_OWNER_BINDING_INVALID)
    projection = {
        "schema_version": "ebm-audit-private-canonical-array-value-projection/1.0",
        "canonical_array_artifact_owner_sha256": artifact["canonical_array_artifact_owner_sha256"],
        "member_name": member_name,
        "dtype": "int32",
        "shape": list(expected_shape),
        "semantic_version": artifact["semantic_version"],
        "axes": list(axes),
        "array_value_sha256": value_digest,
    }
    projection["private_canonical_array_value_projection_sha256"] = structured_sha256_hex(
        _PRIVATE_PROJECTION_DOMAIN, projection
    )
    _validate(
        projection,
        "scenario-evidence.schema.json",
        "PrivateCanonicalArrayValueProjection",
    )
    owner = object.__new__(_PrivateCanonicalArrayValueProjection)
    _PRIVATE_STATE_ISSUER.bind_once(
        owner,
        _PrivateProjectionState(
            record_bytes=canonical_json_bytes(projection),
            artifact_record=artifact_owner,
            values=values,
        ),
    )
    return owner


def _read_private_projection(
    owner: object,
) -> tuple[dict[str, object], dict[str, object], tuple[object, ...]]:
    if type(owner) is not _PrivateCanonicalArrayValueProjection:
        _fail(_OWNER_BINDING_INVALID)
    try:
        state = _PRIVATE_STATES.read(owner)
    except OneShotRegistryError:
        _fail(_OWNER_BINDING_INVALID)
    record = _mapping(strict_json_loads(state.record_bytes))
    artifact = _validated_authenticated_record(
        state.artifact_record,
        "CANONICAL_ARRAY_ARTIFACT",
        "schemas/scenario-evidence.schema.json#/$defs/CanonicalArrayArtifactOwner",
        "scenario-evidence.schema.json",
        "CanonicalArrayArtifactOwner",
    )
    _validate(record, "scenario-evidence.schema.json", "PrivateCanonicalArrayValueProjection")
    preimage = {
        key: value
        for key, value in record.items()
        if key != "private_canonical_array_value_projection_sha256"
    }
    if record.get("private_canonical_array_value_projection_sha256") != structured_sha256_hex(
        _PRIVATE_PROJECTION_DOMAIN, preimage
    ):
        _fail(_OWNER_BINDING_INVALID)
    return record, artifact, state.values


def _private_canonical_array_value_source_record(owner: object) -> _ScenarioSourceRecordInput:
    record, _artifact, _values = _read_private_projection(owner)
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


def _matched_manifest(record: _ScenarioSourceOwnerRecord) -> dict[str, object]:
    value = _validated_authenticated_record(
        record,
        "MATCHED_COMPARATOR_EVIDENCE",
        "schemas/comparator-transaction.schema.json#/$defs/MatchedComparatorEvidenceManifest",
        "comparator-transaction.schema.json",
        "MatchedComparatorEvidenceManifest",
    )
    if value.get("digest_state") != "PERSISTED" or value.get(
        "matched_comparator_evidence_sha256"
    ) != _self_digest(value, "matched_comparator_evidence_sha256", _MATCHED_MANIFEST_DOMAIN):
        _fail(_OWNER_BINDING_INVALID)
    return value


def _member_case(member: Mapping[str, object]) -> str:
    generated = member.get("member_generated_scientific_data")
    if not isinstance(generated, Mapping) or type(generated.get("case_id")) is not str:
        _fail(_OWNER_BINDING_INVALID)
    return cast(str, generated["case_id"])


def _selected_pair(
    manifest: Mapping[str, object], artifacts: tuple[dict[str, object], dict[str, object]]
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    plans = cast(list[dict[str, object]], manifest.get("plan_evidence"))
    members = cast(list[dict[str, object]], manifest.get("member_evidence"))
    artifact_cases = {cast(str, artifact.get("case_id")) for artifact in artifacts}
    candidates: list[tuple[dict[str, object], dict[str, dict[str, object]]]] = []
    for plan in plans:
        plan_members = tuple(cast(list[str], plan.get("ordered_member_ids")))
        matching = {
            cast(str, member.get("member_id")): member
            for member in members
            if all(
                member.get(field) == plan.get(field)
                for field in (
                    "comparator_id",
                    "source_variant_id",
                    "replicate_index",
                    "pair_index",
                    "pairing_key",
                )
            )
        }
        if (
            len(plan_members) == 2
            and set(matching) == set(plan_members)
            and {_member_case(member) for member in matching.values()} == artifact_cases
        ):
            candidates.append((plan, matching))
    if len(candidates) != 1:
        _fail(_OWNER_BINDING_INVALID)
    plan, members_by_id = candidates[0]
    pairing_key = (
        f"{plan.get('comparator_id')}/{plan.get('source_variant_id')}/{plan.get('replicate_index')}"
    )
    if plan.get("pairing_key") != pairing_key:
        _fail(_OWNER_BINDING_INVALID)
    plan_digest = structured_sha256_hex(_MATCHED_PLAN_DOMAIN, plan)
    shared_chain_identities: set[tuple[object, object, object]] = set()
    for member_id, member in members_by_id.items():
        chain_bindings = cast(list[dict[str, object]], member.get("chain_bindings"))
        selected_operations = tuple(
            operation
            for operation in cast(list[dict[str, object]], plan.get("ordered_operations"))
            if operation.get("member_id") == member_id
            or (
                type(operation.get("member_index")) is int
                and cast(list[str], plan["ordered_member_ids"])[
                    cast(int, operation["member_index"])
                ]
                == member_id
            )
        )
        if (
            member.get("evidence_state") != "PASS"
            or member.get("benchmark_subject_digest") != manifest.get("benchmark_subject_digest")
            or member.get("matched_comparator_plan_evidence") != plan
            or member.get("matched_comparator_plan_evidence_sha256") != plan_digest
            or (tuple(cast(list[object], member.get("ordered_operation_evidence")))
            and tuple(
                cast(dict[str, object], row).get("operation")
                for row in cast(list[object], member.get("ordered_operation_evidence"))
            )
            != selected_operations)
            or len(chain_bindings) != 4
            or tuple(row.get("chain_index") for row in chain_bindings) != (0, 1, 2, 3)
            or any(
                row.get("equal") is not True
                or row.get("source_chain_seed") != row.get("member_chain_seed")
                for row in chain_bindings
            )
        ):
            _fail(_OWNER_BINDING_INVALID)
        shared_chain_identities.update(
            (
                row.get("backend_identity_digest"),
                row.get("settings_digest"),
                row.get("environment_digest"),
            )
            for row in chain_bindings
        )
    if len(shared_chain_identities) != 1:
        _fail(_OWNER_BINDING_INVALID)
    return plan, members_by_id


def _validated_truth(
    record: _ScenarioSourceOwnerRecord,
) -> tuple[dict[str, object], tuple[str, ...]]:
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
    if trusted_bytes != canonical_json_bytes(truth):
        _fail(_OWNER_BINDING_INVALID)
    _validate(truth, "synthetic-truth.schema.json")
    truth_sha = truth.get("truth_object_sha256")
    order_truth = truth.get("order_truth")
    if (
        truth.get("digest_state") != "PERSISTED"
        or truth_sha != _self_digest(truth, "truth_object_sha256", _TRUTH_DOMAIN)
        or dict(record.natural_identity) != {"truth_object_sha256": truth_sha}
        or not isinstance(order_truth, Mapping)
        or order_truth.get("truth_kind") != "STRICT_TOTAL_ORDER"
        or order_truth.get("strict_order_identifiable") is not True
    ):
        _fail(_OWNER_BINDING_INVALID)
    strict_order = tuple(cast(Sequence[str], order_truth.get("strict_order")))
    if len(strict_order) < 2 or len(set(strict_order)) != len(strict_order):
        _fail(_OWNER_BINDING_INVALID)
    return truth, strict_order


def _operand(
    *,
    member_id: str,
    member: Mapping[str, object],
    sealed_records: tuple[_ScenarioSourceOwnerRecord, ...],
    payload_records: tuple[_ScenarioSourceOwnerRecord, ...],
    private_projection: _PrivateCanonicalArrayValueProjection,
    metric_id: str,
    truth_order: tuple[str, ...] | None,
) -> tuple[dict[str, object], float | None]:
    projection, artifact, values = _read_private_projection(private_projection)
    if _member_case(member) != artifact.get("case_id"):
        _fail(_OWNER_BINDING_INVALID)
    sealed_matches = tuple(
        _validated_authenticated_record(
            record,
            "SEALED_RESULT_RECORD",
            "schemas/evaluator-receipts.schema.json#/$defs/SealedResultRecord",
            "evaluator-receipts.schema.json",
            "ScientificSuccessSealedResult",
        )
        for record in sealed_records
        if record.source_record.get("operation_instance_id")
        == artifact.get("operation_instance_id")
        and record.source_record.get("chain_execution_id") == artifact.get("chain_execution_id")
    )
    payload_matches = tuple(
        _validated_authenticated_record(
            record,
            "CANONICAL_SCIENTIFIC_PAYLOAD",
            "schemas/canonical-records.schema.json#/$defs/CanonicalScientificPayload",
            "canonical-records.schema.json",
            "CanonicalScientificPayload",
        )
        for record in payload_records
        if record.source_record.get("operation_instance_id")
        == artifact.get("operation_instance_id")
    )
    if len(sealed_matches) != 1 or len(payload_matches) != 1:
        _fail(_OWNER_BINDING_INVALID)
    sealed, payload = sealed_matches[0], payload_matches[0]
    sealed_digest = structured_sha256_hex(_SEALED_RESULT_DOMAIN, sealed)
    payload_digest = structured_sha256_hex(_PAYLOAD_DOMAIN, payload)
    chains = cast(list[dict[str, object]], payload.get("ordered_chain_payloads"))
    if not chains:
        _fail(_OWNER_BINDING_INVALID)
    chain = chains[0]
    member_name = (
        "order_state_chain" if metric_id == _ENTROPY_METRIC else "central_order_permutation"
    )
    descriptor = cast(dict[str, object], cast(dict[str, object], chain.get("arrays"))[member_name])
    pointer = f"/ordered_chain_payloads/0/arrays/{member_name}"
    if (
        sealed.get("benchmark_subject_digest") != payload.get("benchmark_subject_digest")
        or sealed.get("benchmark_subject_digest") != artifact.get("benchmark_subject_digest")
        or sealed.get("operation_instance_id") != payload.get("operation_instance_id")
        or sealed.get("canonical_scientific_payload_sha256") != payload_digest
        or artifact.get("sealed_result_record_sha256") != sealed_digest
        or artifact.get("canonical_scientific_payload_sha256") != payload_digest
        or artifact.get("canonical_payload_array_pointer") != pointer
        or artifact.get("member_name") != member_name
        or projection.get("member_name") != member_name
        or chain.get("chain_execution_id") != sealed.get("chain_execution_id")
        or chain.get("attempt_id") != sealed.get("attempt_id")
        or chain.get("chain_id") != sealed.get("chain_id")
        or chain.get("seed") != sealed.get("seed")
        or artifact.get("chain_execution_id") != chain.get("chain_execution_id")
        or artifact.get("attempt_id") != chain.get("attempt_id")
        or artifact.get("chain_id") != chain.get("chain_id")
        or artifact.get("fit_response_binding_sha256")
        != chain.get("fit_evaluator_worker_response_binding_sha256")
        or descriptor.get("member_name") != member_name
        or descriptor.get("dtype") != artifact.get("dtype")
        or descriptor.get("shape") != artifact.get("shape")
        or descriptor.get("semantic_version") != artifact.get("semantic_version")
        or descriptor.get("array_digest") != "sha256:" + cast(str, artifact.get("artifact_sha256"))
        or projection.get("canonical_array_artifact_owner_sha256")
        != artifact.get("canonical_array_artifact_owner_sha256")
        or projection.get("array_value_sha256") != artifact.get("array_value_sha256")
    ):
        _fail(_OWNER_BINDING_INVALID)
    event_ids = tuple(cast(list[str], payload.get("event_ids")))
    value: float | None = None
    available = (
        sealed.get("core_final_status") == "SUCCESS"
        and sealed.get("convergence_assessment") == "CONVERGENCE_PASS"
        and payload.get("core_final_status") == "SUCCESS"
    )
    if available:
        if metric_id == _ENTROPY_METRIC:
            rows = cast(tuple[tuple[int, ...], ...], values)
            if any(sorted(row) != list(range(len(event_ids))) for row in rows):
                _fail(_OWNER_BINDING_INVALID)
            orders = tuple(tuple(event_ids[index] for index in row) for row in rows)
            matrix = position_matrix(orders, event_ids)
            if matrix.status != "ASSESSABLE" or matrix.value is None:
                _fail(_OWNER_BINDING_INVALID)
            summaries = position_event_summaries(
                matrix.value,
                event_ids=event_ids,
                quantile_probabilities=(0.10, 0.25, 0.75, 0.90),
            )
            mean_entropy, _ = _within_entropy_metrics(summaries)
            value = _finite(mean_entropy.get("value"))
        else:
            indexes = cast(tuple[int, ...], values)
            if truth_order is None or sorted(indexes) != list(range(len(event_ids))):
                _fail(_OWNER_BINDING_INVALID)
            inferred = tuple(event_ids[index] for index in indexes)
            if set(inferred) != set(truth_order):
                _fail(_OWNER_BINDING_INVALID)
            result = normalized_kendall_distance(inferred, truth_order)
            if result.status != "ASSESSABLE" or result.value is None:
                _fail(_OWNER_BINDING_INVALID)
            value = _finite(result.value)
    operand = {
        "sealed_result_record_sha256": sealed_digest,
        "canonical_scientific_payload_sha256": payload_digest,
        "operation_instance_id": sealed["operation_instance_id"],
        "reference_chain_plan_position": 0,
        "reference_chain_execution_id": sealed["chain_execution_id"],
        "metric_source_member_name": member_name,
        "canonical_payload_array_pointer": pointer,
        "canonical_array_digest": descriptor["array_digest"],
        "canonical_array_artifact_owner_sha256": artifact["canonical_array_artifact_owner_sha256"],
        "private_canonical_array_value_projection_sha256": projection[
            "private_canonical_array_value_projection_sha256"
        ],
        "array_value_sha256": projection["array_value_sha256"],
        "recomputed_value": value,
    }
    return operand, value


def _issue_scenario_matched_metric_record(
    matched_comparator_evidence: _ScenarioSourceOwnerRecord,
    sealed_results: tuple[_ScenarioSourceOwnerRecord, ...],
    canonical_payloads: tuple[_ScenarioSourceOwnerRecord, ...],
    private_projections: tuple[_PrivateCanonicalArrayValueProjection, ...],
    synthetic_truth: _ScenarioSourceOwnerRecord | None = None,
) -> ScenarioMatchedMetricRecord:
    if (
        type(sealed_results) is not tuple
        or len(sealed_results) != 2
        or type(canonical_payloads) is not tuple
        or len(canonical_payloads) != 2
        or type(private_projections) is not tuple
        or len(private_projections) != 2
        or len({id(owner) for owner in private_projections}) != 2
    ):
        _fail(_OWNER_COVERAGE_INVALID)
    manifest = _matched_manifest(matched_comparator_evidence)
    private_states = tuple(_read_private_projection(owner) for owner in private_projections)
    artifacts = cast(
        tuple[dict[str, object], dict[str, object]], tuple(row[1] for row in private_states)
    )
    member_names = {
        projection.get("member_name") for projection, _artifact, _values in private_states
    }
    if member_names == {"order_state_chain"}:
        metric_id = _ENTROPY_METRIC
    elif member_names == {"central_order_permutation"}:
        metric_id = _KENDALL_METRIC
    else:
        _fail(_OWNER_BINDING_INVALID)
    truth_sha: str | None = None
    truth_order: tuple[str, ...] | None = None
    if metric_id == _KENDALL_METRIC:
        if synthetic_truth is None:
            _fail(_OWNER_BINDING_INVALID)
        truth, truth_order = _validated_truth(synthetic_truth)
        truth_sha = cast(str, truth["truth_object_sha256"])
    elif synthetic_truth is not None:
        _fail(_OWNER_BINDING_INVALID)
    plan, members = _selected_pair(manifest, artifacts)
    ordered_member_ids = tuple(cast(list[str], plan["ordered_member_ids"]))
    projection_by_case = {
        cast(str, artifact["case_id"]): owner
        for owner, (_projection, artifact, _values) in zip(
            private_projections, private_states, strict=True
        )
    }
    operands: list[dict[str, object]] = []
    values: list[float | None] = []
    for member_id in ordered_member_ids:
        member = members[member_id]
        operand, value = _operand(
            member_id=member_id,
            member=member,
            sealed_records=sealed_results,
            payload_records=canonical_payloads,
            private_projection=projection_by_case[_member_case(member)],
            metric_id=metric_id,
            truth_order=truth_order,
        )
        operands.append(operand)
        values.append(value)
    assessable = all(value is not None for value in values)
    derived = cast(float, values[0]) - cast(float, values[1]) if assessable else None
    if derived is not None and not math.isfinite(derived):
        _fail(_OWNER_BINDING_INVALID)
    record: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "digest_state": "DIGEST_PREIMAGE",
        "benchmark_subject_digest": manifest["benchmark_subject_digest"],
        "comparator_id": plan["comparator_id"],
        "source_variant_id": plan["source_variant_id"],
        "replicate_index": plan["replicate_index"],
        "pair_index": plan["pair_index"],
        "pairing_key": plan["pairing_key"],
        "left_member_id": ordered_member_ids[0],
        "right_member_id": ordered_member_ids[1],
        "metric_id": metric_id,
        "left": operands[0],
        "right": operands[1],
        "truth_sha256": truth_sha,
        "derived_value": derived,
        "status": "ASSESSABLE" if assessable else "NOT_ASSESSABLE",
        "reason_codes": [] if assessable else [_UNAVAILABLE_REASON],
        "scenario_matched_metric_record_sha256": None,
    }
    digest = structured_sha256_hex(_RECORD_DOMAIN, record)
    record["digest_state"] = "PERSISTED"
    record["scenario_matched_metric_record_sha256"] = digest
    _validate(record, "scenario-evidence.schema.json", "ScenarioMatchedMetricRecord")
    owner = object.__new__(ScenarioMatchedMetricRecord)
    _RECORD_STATE_ISSUER.bind_once(
        owner,
        _MatchedMetricRecordState(
            record_bytes=canonical_json_bytes(record),
            member_case_ids=cast(
                tuple[str, str], tuple(_member_case(members[role]) for role in ordered_member_ids)
            ),
        ),
    )
    return owner


def _read_scenario_matched_metric_record(owner: object) -> dict[str, object]:
    if type(owner) is not ScenarioMatchedMetricRecord:
        _fail(_OWNER_BINDING_INVALID)
    try:
        state = _RECORD_STATES.read(owner)
    except OneShotRegistryError:
        _fail(_OWNER_BINDING_INVALID)
    record = _mapping(strict_json_loads(state.record_bytes))
    _validate(record, "scenario-evidence.schema.json", "ScenarioMatchedMetricRecord")
    if record.get("digest_state") != "PERSISTED" or record.get(
        "scenario_matched_metric_record_sha256"
    ) != _self_digest(record, "scenario_matched_metric_record_sha256", _RECORD_DOMAIN):
        _fail(_OWNER_BINDING_INVALID)
    left = cast(dict[str, object], record["left"])
    right = cast(dict[str, object], record["right"])
    if record["status"] == "ASSESSABLE":
        left_value = _finite(left.get("recomputed_value"))
        right_value = _finite(right.get("recomputed_value"))
        if _finite(record.get("derived_value")) != left_value - right_value:
            _fail(_OWNER_BINDING_INVALID)
    return record


def _read_scenario_matched_metric_case_ids(owner: object) -> tuple[str, str]:
    _read_scenario_matched_metric_record(owner)
    try:
        state = _RECORD_STATES.read(cast(ScenarioMatchedMetricRecord, owner))
    except OneShotRegistryError:
        _fail(_OWNER_BINDING_INVALID)
    if (
        type(state.member_case_ids) is not tuple
        or len(state.member_case_ids) != 2
        or len(set(state.member_case_ids)) != 2
        or any(type(case_id) is not str or not case_id for case_id in state.member_case_ids)
    ):
        _fail(_OWNER_BINDING_INVALID)
    return state.member_case_ids


def _scenario_matched_metric_source_record(owner: object) -> _ScenarioSourceRecordInput:
    record = _read_scenario_matched_metric_record(owner)
    identity = {
        field: cast(str | int, record[field])
        for field in (
            "benchmark_subject_digest",
            "comparator_id",
            "source_variant_id",
            "replicate_index",
            "pair_index",
            "pairing_key",
            "left_member_id",
            "right_member_id",
            "metric_id",
        )
    }
    record_bytes = canonical_json_bytes(record)
    return _ScenarioSourceRecordInput(
        owner_class=_OWNER_CLASS,
        owner_schema_ref=_OWNER_SCHEMA_REF,
        source_relative_path=(
            f"owners/scenario-matched-metric/{record['scenario_matched_metric_record_sha256']}.json"
        ),
        source_content_bytes=record_bytes,
        source_record_bytes=record_bytes,
        natural_identity=identity,
        source_capability=owner,
    )


_SELECTORS: Final = {
    "small-vs-large-entropy-comparison/1": (("small", "large"), _ENTROPY_METRIC, "DELTA"),
    "weak-vs-moderate-entropy/1": (("weak", "moderate"), _ENTROPY_METRIC, "DELTA"),
    "slow-vs-narrow-entropy/1": (("slow", "narrow"), _ENTROPY_METRIC, "DELTA"),
    "mixture-vs-single-entropy/1": (("mixture", "single"), _ENTROPY_METRIC, "DELTA"),
    "weak-vs-moderate-kendall/1": (("weak", "moderate"), _KENDALL_METRIC, "DELTA"),
    "slow-vs-narrow-kendall/1": (("slow", "narrow"), _KENDALL_METRIC, "DELTA"),
    "adjusted-vs-unadjusted-kendall/1": (
        ("adjusted", "unadjusted"),
        _KENDALL_METRIC,
        "AGREEMENT_DELTA",
    ),
    "contaminated-vs-clean-kendall/1": (
        ("contaminated", "clean"),
        _KENDALL_METRIC,
        "LEFT_AGREEMENT",
    ),
    "contaminated-vs-clean-entropy/1": (("contaminated", "clean"), _ENTROPY_METRIC, "LEFT"),
    "correct-vs-wrong-direction-kendall/1": (
        ("correct", "wrong"),
        _KENDALL_METRIC,
        "AGREEMENT_DELTA",
    ),
}


_KEY_ROWS: Final = (
    (
        "small_sample",
        "/payload/entropy_delta_small_minus_large",
        "matched-entropy-delta/1",
        "small-vs-large-entropy-comparison/1",
    ),
    (
        "weak_pre_post_separation",
        "/payload/entropy_delta_weak_minus_moderate",
        "matched-entropy-delta/1",
        "weak-vs-moderate-entropy/1",
    ),
    (
        "weak_pre_post_separation",
        "/payload/kendall_distance_delta_weak_minus_moderate",
        "matched-kendall-delta/1",
        "weak-vs-moderate-kendall/1",
    ),
    (
        "slow_overlapping_transitions",
        "/payload/entropy_delta_slow_minus_narrow",
        "matched-entropy-delta/1",
        "slow-vs-narrow-entropy/1",
    ),
    (
        "slow_overlapping_transitions",
        "/payload/kendall_distance_delta_slow_minus_narrow",
        "matched-kendall-delta/1",
        "slow-vs-narrow-kendall/1",
    ),
    (
        "minority_alternate_sequence",
        "/payload/entropy_delta_mixture_minus_single",
        "matched-entropy-delta/1",
        "mixture-vs-single-entropy/1",
    ),
    (
        "covariate_confounding",
        "/payload/adjusted_minus_unadjusted_kendall_agreement",
        "matched-kendall-delta/1",
        "adjusted-vs-unadjusted-kendall/1",
    ),
    (
        "control_contamination",
        "/payload/kendall_agreement",
        "matched-kendall-agreement/1",
        "contaminated-vs-clean-kendall/1",
    ),
    (
        "control_contamination",
        "/payload/position_entropy",
        "matched-position-entropy/1",
        "contaminated-vs-clean-entropy/1",
    ),
    (
        "wrong_event_direction",
        "/payload/correct_minus_wrong_kendall_agreement",
        "matched-kendall-delta/1",
        "correct-vs-wrong-direction-kendall/1",
    ),
)


def _key(row: tuple[str, str, str, str]) -> HandlerKey:
    family_id, output_path, derivation_id, selector = row
    return (
        "FAMILY_OUTPUT",
        family_id,
        output_path,
        derivation_id,
        ((_OWNER_CLASS, "ONE_PER_CASE", selector),),
    )


def _handler(request: HandlerRequest) -> HandlerResult:
    try:
        if type(request) is not HandlerRequest or request.key not in tuple(map(_key, _KEY_ROWS)):
            _fail(_REQUEST_INVALID)
        if (
            type(request.owner_projections) is not tuple
            or len(request.owner_projections) != 1
            or type(request.owner_projections[0]) is not tuple
            or len(request.owner_projections[0]) != 1
        ):
            _fail(_OWNER_COVERAGE_INVALID)
        source = request.owner_projections[0][0]
        if type(source) is not _ScenarioSourceOwnerRecord:
            _fail(_OWNER_BINDING_INVALID)
        record = _read_scenario_matched_metric_record(source.source_capability)
        member_case_ids = _read_scenario_matched_metric_case_ids(source.source_capability)
        identity = {
            field: record[field]
            for field in (
                "benchmark_subject_digest",
                "comparator_id",
                "source_variant_id",
                "replicate_index",
                "pair_index",
                "pairing_key",
                "left_member_id",
                "right_member_id",
                "metric_id",
            )
        }
        context = _read_scenario_evidence_context(request.context)
        selector = request.key[4][0][2]
        roles, metric_id, mode = _SELECTORS[selector]
        if (
            source.owner_class != _OWNER_CLASS
            or source.owner_schema_ref != _OWNER_SCHEMA_REF
            or dict(source.natural_identity) != identity
            or source.source_record_sha256 != _source_record_digest(_OWNER_CLASS, identity, record)
            or source.ordered_support_owner_sha256 != ()
            or context.identity.family_id != request.key[1]
            or context.identity.benchmark_subject_digest != record["benchmark_subject_digest"]
            or context.identity.case_id not in member_case_ids
            or record["metric_id"] != metric_id
            or {record["left_member_id"], record["right_member_id"]} != set(roles)
        ):
            _fail(_OWNER_BINDING_INVALID)
        if record["status"] != "ASSESSABLE":
            _fail(_OWNER_UNAVAILABLE)
        values = {
            cast(str, record["left_member_id"]): _finite(
                cast(dict[str, object], record["left"])["recomputed_value"]
            ),
            cast(str, record["right_member_id"]): _finite(
                cast(dict[str, object], record["right"])["recomputed_value"]
            ),
        }
        named_left, named_right = roles
        if mode == "DELTA":
            value = values[named_left] - values[named_right]
        elif mode == "AGREEMENT_DELTA":
            value = (1.0 - values[named_left]) - (1.0 - values[named_right])
        elif mode == "LEFT_AGREEMENT":
            value = 1.0 - values[named_left]
        else:
            value = values[named_left]
        return HandlerResult(request.key, "PASS", _finite(value), ())
    except _MatchedMetricError as error:
        reason = error.code
    except Exception:
        reason = _VALIDATION_FAILED
    return HandlerResult(request.key, "FAIL", None, (reason,))


HANDLERS: tuple[tuple[HandlerKey, Handler], ...] = tuple(
    (key, _handler) for key in map(_key, _KEY_ROWS)
)

__all__ = ["HANDLERS"]
