"""One-shot preparation-owned participant-influence input receipt.

Preparation validates the complete canonical Plan/3, PreparationReceipt/2,
origin-comparison graph, and ordered v1 influence bindings before publishing
this opaque capability. Downstream code may retain the immutable snapshot, but
cannot re-enter preparation or supply a replacement snapshot.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Never, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.protocol import (
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.schema import SchemaValidationError, validate_instance

from .identities import (
    _plan_preimage,
    _receipt_preimage,
    analysis_plan_digest,
    preparation_receipt_digest,
)

_BINDING_DOMAIN = "ebm-audit/influence-preparation-evidence-input/1"
_BINDINGS_DOMAIN = "ebm-audit/captured-influence-preparation-bindings/1"
_BINDING_SCHEMA_VERSION = "ebm-audit-influence-preparation-evidence-input/1.0"
_STAGE_BINDING_DOMAIN = "ebm-audit/stage-preparation-evidence-input/1"
_STAGE_BINDINGS_DOMAIN = "ebm-audit/captured-stage-preparation-bindings/1"
_STAGE_BINDING_SCHEMA_VERSION = "ebm-audit-stage-preparation-evidence-input/1.0"
_PREPARATION_STATES = frozenset(
    {
        "PREPARED",
        "PLAN_INELIGIBLE",
        "PREPARATION_INVALID",
        "PREPARATION_UNSUPPORTED",
    }
)


@dataclass(frozen=True, repr=False)
class _InfluencePreparationInputSnapshot:
    plan_bytes: bytes
    preparation_receipt_bytes: bytes
    plan_digest: str
    preparation_receipt_digest: str
    baseline_analysis_spec_id: str
    baseline_candidate_bytes: bytes
    plan_candidates_bytes: bytes
    origin_comparison_edges_bytes: bytes
    binding_bytes: tuple[bytes, ...]
    bindings_digest: str
    stage_binding_bytes: tuple[bytes, ...]
    stage_bindings_digest: str


@final
class _InfluencePreparationInputReceipt:
    """Opaque key for one immutable preparation-owned input snapshot."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> _InfluencePreparationInputReceipt:
        raise TypeError("Influence preparation receipts are issued by preparation.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Influence preparation receipts cannot be subclassed.")

    def __copy__(self) -> Never:
        raise TypeError("Influence preparation receipts cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Influence preparation receipts cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Influence preparation receipts cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: object) -> Never:
        raise TypeError("Influence preparation receipts cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Influence preparation receipts cannot be copied or serialized.")


_RECEIPT_STATES: OneShotWeakRegistry[
    _InfluencePreparationInputReceipt,
    _InfluencePreparationInputSnapshot,
]
_RECEIPT_STATE_ISSUER: OneShotRegistryIssuer[
    _InfluencePreparationInputReceipt,
    _InfluencePreparationInputSnapshot,
]
_RECEIPT_STATES, _RECEIPT_STATE_ISSUER = create_one_shot_registry()


def _is_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _closed_mapping(value: bytes, *, description: str) -> dict[str, Any]:
    decoded = strict_json_loads(value)
    if type(decoded) is not dict or canonical_json_bytes(decoded) != value:
        raise TypeError(description)
    return cast(dict[str, Any], decoded)


def _validate_binding(
    binding_bytes: bytes,
    *,
    candidate: Mapping[str, Any],
    operation: Mapping[str, Any],
    receipt_record: Mapping[str, Any],
) -> dict[str, object]:
    binding = _closed_mapping(
        binding_bytes,
        description="Influence preparation binding storage is invalid.",
    )
    preimage = dict(binding)
    supplied_digest = preimage.pop("binding_digest", None)
    aliases = binding.get("removed_aliases")
    reasons = binding.get("preparation_reason_rows")
    removal_kind = operation.get("removal_kind")
    fixed_digest = binding.get("fixed_evaluation_cohort_digest")
    fixed_count = binding.get("fixed_evaluation_cohort_count")
    if (
        set(binding)
        != {
            "binding_schema_version",
            "candidate_ordinal",
            "analysis_spec_id",
            "source_analysis_spec_id",
            "removal_method_id",
            "removal_kind",
            "removal_slot_ordinal",
            "named_group_spec_id",
            "removed_aliases",
            "preparation_state",
            "preparation_reason_rows",
            "fixed_evaluation_cohort_digest",
            "fixed_evaluation_cohort_count",
            "binding_digest",
        }
        or binding.get("binding_schema_version") != _BINDING_SCHEMA_VERSION
        or (
            binding.get("candidate_ordinal"),
            binding.get("analysis_spec_id"),
            binding.get("source_analysis_spec_id"),
            binding.get("removal_method_id"),
            binding.get("removal_kind"),
            binding.get("removal_slot_ordinal"),
            binding.get("named_group_spec_id"),
        )
        != (
            candidate.get("candidate_ordinal"),
            candidate.get("analysis_spec_id"),
            operation.get("source_analysis_spec_id"),
            operation.get("removal_method_id"),
            removal_kind,
            operation.get("removal_slot_ordinal"),
            operation.get("named_group_spec_id"),
        )
        or binding.get("preparation_state") != receipt_record.get("state")
        or binding.get("preparation_state") not in _PREPARATION_STATES
        or reasons != receipt_record.get("reasons")
        or type(reasons) is not list
        or any(
            type(reason) is not dict
            or set(reason) != {"reason_code", "rule_id"}
            or type(reason.get("reason_code")) is not str
            or type(reason.get("rule_id")) is not str
            for reason in reasons
        )
        or type(aliases) is not list
        or any(
            type(alias) is not str
            or not alias.startswith("P-")
            or not alias[2:].isdigit()
            or len(alias[2:]) < 3
            for alias in aliases
        )
        or len(set(cast(list[str], aliases))) != len(aliases)
        or (removal_kind == "leave-one-participant-out" and len(aliases) not in {0, 1})
        or (removal_kind == "named-group-removal" and aliases != [])
        or removal_kind
        not in {
            "leave-one-participant-out",
            "named-group-removal",
        }
        or (
            binding.get("preparation_state") == "PREPARED"
            and (
                removal_kind != "leave-one-participant-out"
                or len(aliases) != 1
                or not _is_digest(fixed_digest)
                or type(fixed_count) is not int
                or fixed_count < 0
            )
        )
        or (
            binding.get("preparation_state") != "PREPARED"
            and (fixed_digest is not None or fixed_count is not None)
        )
        or supplied_digest != structured_sha256(_BINDING_DOMAIN, preimage)
    ):
        raise TypeError("Influence preparation binding storage is invalid.")
    return cast(dict[str, object], binding)


def _is_private_unit_binding(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 76
        and value.startswith("hmac-sha256:")
        and all(character in "0123456789abcdef" for character in value[12:])
    )


def _validate_stage_binding(
    binding_bytes: bytes,
    *,
    candidate: Mapping[str, Any],
    receipt_record: Mapping[str, Any],
) -> dict[str, object]:
    """Validate one private fixed-evaluation-cohort row binding."""

    binding = _closed_mapping(
        binding_bytes,
        description="Stage preparation binding storage is invalid.",
    )
    preimage = dict(binding)
    supplied_digest = preimage.pop("binding_digest", None)
    reasons = binding.get("preparation_reason_rows")
    evaluation_digest = binding.get("evaluation_membership_digest")
    evaluation_count = binding.get("evaluation_participant_count")
    units = binding.get("evaluation_units")
    if (
        set(binding)
        != {
            "binding_schema_version",
            "candidate_ordinal",
            "candidate_id",
            "analysis_spec_id",
            "preparation_state",
            "preparation_reason_rows",
            "evaluation_membership_digest",
            "evaluation_participant_count",
            "evaluation_units",
            "binding_digest",
        }
        or binding.get("binding_schema_version") != _STAGE_BINDING_SCHEMA_VERSION
        or (
            binding.get("candidate_ordinal"),
            binding.get("candidate_id"),
            binding.get("analysis_spec_id"),
        )
        != (
            candidate.get("candidate_ordinal"),
            candidate.get("candidate_id"),
            candidate.get("analysis_spec_id"),
        )
        or binding.get("preparation_state") != receipt_record.get("state")
        or binding.get("preparation_state") not in _PREPARATION_STATES
        or reasons != receipt_record.get("reasons")
        or type(reasons) is not list
        or any(
            type(reason) is not dict
            or set(reason) != {"reason_code", "rule_id"}
            or type(reason.get("reason_code")) is not str
            or type(reason.get("rule_id")) is not str
            for reason in reasons
        )
        or type(units) is not list
        or supplied_digest != structured_sha256(_STAGE_BINDING_DOMAIN, preimage)
    ):
        raise TypeError("Stage preparation binding storage is invalid.")
    exact_units = cast(list[object], units)
    if binding.get("preparation_state") == "PREPARED":
        if (
            not _is_digest(evaluation_digest)
            or type(evaluation_count) is not int
            or evaluation_count < 1
            or len(exact_units) != evaluation_count
            or any(
                type(unit) is not dict
                or set(unit)
                != {
                    "evaluation_row_index",
                    "evaluation_unit_binding",
                    "role",
                }
                or type(unit.get("evaluation_row_index")) is not int
                or cast(int, unit["evaluation_row_index"]) < 0
                or not _is_private_unit_binding(unit.get("evaluation_unit_binding"))
                or unit.get("role") not in {"reference", "at_risk"}
                for unit in exact_units
            )
        ):
            raise TypeError("Stage preparation binding storage is invalid.")
        unit_rows = cast(list[dict[str, object]], exact_units)
        row_indexes = [unit["evaluation_row_index"] for unit in unit_rows]
        private_bindings = [unit["evaluation_unit_binding"] for unit in unit_rows]
        if (
            len(set(row_indexes)) != len(row_indexes)
            or len(set(private_bindings)) != len(private_bindings)
        ):
            raise TypeError("Stage preparation binding storage is invalid.")
    elif evaluation_digest is not None or evaluation_count is not None or exact_units:
        raise TypeError("Stage preparation binding storage is invalid.")
    return cast(dict[str, object], binding)


def _validated_snapshot(
    *,
    plan_bytes: bytes,
    preparation_receipt_bytes: bytes,
    binding_bytes: tuple[bytes, ...],
    bindings_digest: str,
    stage_binding_bytes: tuple[bytes, ...],
    stage_bindings_digest: str,
) -> _InfluencePreparationInputSnapshot:
    if (
        type(plan_bytes) is not bytes
        or type(preparation_receipt_bytes) is not bytes
        or type(binding_bytes) is not tuple
        or any(type(value) is not bytes for value in binding_bytes)
        or not _is_digest(bindings_digest)
        or type(stage_binding_bytes) is not tuple
        or any(type(value) is not bytes for value in stage_binding_bytes)
        or not _is_digest(stage_bindings_digest)
    ):
        raise TypeError("Influence preparation receipt storage is invalid.")
    plan = _closed_mapping(
        plan_bytes,
        description="Influence preparation Plan/3 storage is invalid.",
    )
    receipt = _closed_mapping(
        preparation_receipt_bytes,
        description="Influence preparation receipt storage is invalid.",
    )
    try:
        validate_instance(
            plan,
            "analysis-universe.schema.json",
            definition="AnalysisPlan",
        )
        validate_instance(
            receipt,
            "analysis-universe.schema.json",
            definition="PreparationReceipt",
        )
    except SchemaValidationError:
        raise TypeError("Influence preparation receipt storage is invalid.") from None
    plan_digest = plan.get("plan_digest")
    receipt_digest = receipt.get("receipt_digest")
    baseline_analysis_spec_id = plan.get("baseline_analysis_spec_id")
    candidates_value = plan.get("candidates")
    edges_value = plan.get("origin_comparison_edges")
    records_value = receipt.get("records")
    if (
        not _is_digest(plan_digest)
        or not _is_digest(receipt_digest)
        or not _is_digest(baseline_analysis_spec_id)
        or plan_digest != analysis_plan_digest(_plan_preimage(plan))
        or receipt_digest != preparation_receipt_digest(_receipt_preimage(receipt))
        or receipt.get("plan_digest") != plan_digest
        or type(candidates_value) is not list
        or type(edges_value) is not list
        or type(records_value) is not list
        or len(records_value) != len(candidates_value)
    ):
        raise TypeError("Influence preparation receipt storage is invalid.")
    candidates = cast(list[object], candidates_value)
    edges = cast(list[object], edges_value)
    records = cast(list[object], records_value)
    exact_baseline_analysis_spec_id = cast(str, baseline_analysis_spec_id)
    candidate_ids: list[str] = []
    influence_candidates: list[tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]] = []
    origin_ids_by_analysis_spec_id: dict[str, tuple[str, ...]] = {}
    for ordinal, (candidate_value, record_value) in enumerate(
        zip(candidates, records, strict=True)
    ):
        if type(candidate_value) is not dict or type(record_value) is not dict:
            raise TypeError("Influence preparation candidate storage is invalid.")
        candidate = cast(dict[str, Any], candidate_value)
        record = cast(dict[str, Any], record_value)
        analysis_spec_id = candidate.get("analysis_spec_id")
        analysis_spec = candidate.get("analysis_spec")
        operation = analysis_spec.get("operation_intent") if type(analysis_spec) is dict else None
        if (
            candidate.get("candidate_ordinal") != ordinal
            or not _is_digest(analysis_spec_id)
            or type(operation) is not dict
            or (
                record.get("candidate_ordinal"),
                record.get("candidate_id"),
                record.get("analysis_spec_id"),
            )
            != (
                candidate.get("candidate_ordinal"),
                candidate.get("candidate_id"),
                analysis_spec_id,
            )
        ):
            raise TypeError("Influence preparation candidate storage is invalid.")
        exact_analysis_spec_id = cast(str, analysis_spec_id)
        candidate_ids.append(exact_analysis_spec_id)
        duplicate_origins = candidate.get("duplicate_origins")
        if type(duplicate_origins) is not list:
            raise TypeError("Influence preparation candidate storage is invalid.")
        origins = [
            candidate.get("primary_origin"),
            *cast(list[object], duplicate_origins),
        ]
        if any(
            type(origin) is not dict or not _is_digest(origin.get("origin_id"))
            for origin in origins
        ):
            raise TypeError("Influence preparation candidate storage is invalid.")
        origin_ids_by_analysis_spec_id[exact_analysis_spec_id] = tuple(
            cast(str, cast(dict[str, Any], origin)["origin_id"]) for origin in origins
        )
        if operation.get("kind") == "influence":
            influence_candidates.append((candidate, operation, record))
    if (
        len(candidate_ids) != len(set(candidate_ids))
        or candidate_ids.count(exact_baseline_analysis_spec_id) != 1
        or any(type(edge) is not dict for edge in edges)
    ):
        raise TypeError("Influence preparation candidate storage is invalid.")
    baseline_candidate = cast(
        dict[str, Any],
        candidates[candidate_ids.index(exact_baseline_analysis_spec_id)],
    )
    edge_by_origin_id: dict[str, dict[str, Any]] = {}
    for edge_value in edges:
        edge = cast(dict[str, Any], edge_value)
        origin_id = edge.get("origin_id")
        if not _is_digest(origin_id) or origin_id in edge_by_origin_id:
            raise TypeError("Influence preparation comparison storage is invalid.")
        edge_by_origin_id[cast(str, origin_id)] = edge
    exact_origin_ids = {
        origin_id
        for origin_ids in origin_ids_by_analysis_spec_id.values()
        for origin_id in origin_ids
    }
    if set(edge_by_origin_id) != exact_origin_ids:
        raise TypeError("Influence preparation comparison storage is invalid.")
    influence_operations = {
        cast(str, candidate["analysis_spec_id"]): operation
        for candidate, operation, _record in influence_candidates
    }
    for analysis_spec_id, origin_ids in origin_ids_by_analysis_spec_id.items():
        operation = influence_operations.get(analysis_spec_id)
        for origin_id in origin_ids:
            edge = edge_by_origin_id[origin_id]
            if edge.get("subject_analysis_spec_id") != analysis_spec_id or (
                operation is not None
                and edge.get("comparator_analysis_spec_id")
                != operation.get("source_analysis_spec_id")
            ):
                raise TypeError("Influence preparation comparison storage is invalid.")
    if len(binding_bytes) != len(influence_candidates):
        raise TypeError("Influence preparation binding coverage is invalid.")
    decoded_bindings = [
        _validate_binding(
            exact_binding_bytes,
            candidate=candidate,
            operation=operation,
            receipt_record=record,
        )
        for exact_binding_bytes, (candidate, operation, record) in zip(
            binding_bytes,
            influence_candidates,
            strict=True,
        )
    ]
    if structured_sha256(_BINDINGS_DOMAIN, decoded_bindings) != bindings_digest or [
        binding["analysis_spec_id"] for binding in decoded_bindings
    ] != [candidate["analysis_spec_id"] for candidate, _operation, _record in influence_candidates]:
        raise TypeError("Influence preparation binding coverage is invalid.")
    if len(stage_binding_bytes) != len(candidates):
        raise TypeError("Stage preparation binding coverage is invalid.")
    decoded_stage_bindings = [
        _validate_stage_binding(
            exact_binding_bytes,
            candidate=cast(Mapping[str, Any], candidate),
            receipt_record=cast(Mapping[str, Any], record),
        )
        for exact_binding_bytes, candidate, record in zip(
            stage_binding_bytes,
            candidates,
            records,
            strict=True,
        )
    ]
    if (
        structured_sha256(_STAGE_BINDINGS_DOMAIN, decoded_stage_bindings)
        != stage_bindings_digest
        or [binding["analysis_spec_id"] for binding in decoded_stage_bindings]
        != [candidate_id for candidate_id in candidate_ids]
    ):
        raise TypeError("Stage preparation binding coverage is invalid.")
    return _InfluencePreparationInputSnapshot(
        plan_bytes=plan_bytes,
        preparation_receipt_bytes=preparation_receipt_bytes,
        plan_digest=cast(str, plan_digest),
        preparation_receipt_digest=cast(str, receipt_digest),
        baseline_analysis_spec_id=exact_baseline_analysis_spec_id,
        baseline_candidate_bytes=canonical_json_bytes(baseline_candidate),
        plan_candidates_bytes=canonical_json_bytes(candidates),
        origin_comparison_edges_bytes=canonical_json_bytes(edges),
        binding_bytes=binding_bytes,
        bindings_digest=bindings_digest,
        stage_binding_bytes=stage_binding_bytes,
        stage_bindings_digest=stage_bindings_digest,
    )


def _issue_influence_preparation_input_receipt(
    *,
    plan_bytes: object,
    preparation_receipt_bytes: object,
    binding_bytes: object,
    stage_binding_bytes: object,
) -> _InfluencePreparationInputReceipt:
    """Validate once and issue one opaque receipt for the exact snapshot."""

    if (
        type(plan_bytes) is not bytes
        or type(preparation_receipt_bytes) is not bytes
        or type(binding_bytes) is not tuple
        or any(type(value) is not bytes for value in binding_bytes)
        or type(stage_binding_bytes) is not tuple
        or any(type(value) is not bytes for value in stage_binding_bytes)
    ):
        raise TypeError("Influence preparation receipt inputs are invalid.")
    exact_bindings = cast(tuple[bytes, ...], binding_bytes)
    exact_stage_bindings = cast(tuple[bytes, ...], stage_binding_bytes)
    decoded_bindings = [
        cast(dict[str, object], strict_json_loads(value)) for value in exact_bindings
    ]
    decoded_stage_bindings = [
        cast(dict[str, object], strict_json_loads(value)) for value in exact_stage_bindings
    ]
    snapshot = _validated_snapshot(
        plan_bytes=plan_bytes,
        preparation_receipt_bytes=preparation_receipt_bytes,
        binding_bytes=exact_bindings,
        bindings_digest=structured_sha256(_BINDINGS_DOMAIN, decoded_bindings),
        stage_binding_bytes=exact_stage_bindings,
        stage_bindings_digest=structured_sha256(
            _STAGE_BINDINGS_DOMAIN,
            decoded_stage_bindings,
        ),
    )
    receipt = object.__new__(_InfluencePreparationInputReceipt)
    _RECEIPT_STATE_ISSUER.bind_once(receipt, snapshot)
    _RECEIPT_STATES.require(receipt, snapshot)
    return receipt


def _read_influence_preparation_input_receipt(
    value: object,
) -> _InfluencePreparationInputSnapshot:
    """Read the retained snapshot without revalidating or calling preparation."""

    if type(value) is not _InfluencePreparationInputReceipt:
        raise TypeError("A genuine influence preparation receipt is required.")
    try:
        state = _RECEIPT_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine influence preparation receipt is required.") from None
    _RECEIPT_STATES.require(value, state)
    if type(state) is not _InfluencePreparationInputSnapshot:
        raise TypeError("A genuine influence preparation receipt is required.")
    _RECEIPT_STATES.require(value, state)
    return state


__all__: tuple[str, ...] = ()
