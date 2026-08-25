"""Authenticated pre-execution planning for the frozen 104-operation challenge."""

from __future__ import annotations

import copy
import re
import weakref
from dataclasses import dataclass
from threading import RLock
from typing import Any, Final, Literal, Never, SupportsIndex, cast, final
from weakref import WeakKeyDictionary

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.config.strict_yaml import StrictYamlError, load_strict_yaml_bytes
from ebm_audit.errors import InvalidInputError
from ebm_audit.evaluator.scenario_case_batch import (
    AuthenticatedScenarioCaseBatch,
    PublicBatchCasePlan,
    _read_authenticated_batch_candidate_sha256,
    _read_authenticated_batch_context,
    _read_public_batch_case_plan_analysis_spec_ids,
    _read_public_batch_case_plan_set,
    _validated_batch_projection,
)
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256_hex,
)
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.universe.identities import analysis_spec_content_id

_CONTRACT_DOMAIN: Final = "ebm-audit/proportional-benchmark-contract/1"
_ENTRY_DOMAIN: Final = "ebm-audit/proportional-operation-plan-entry/1"
_PLAN_DOMAIN: Final = "ebm-audit/proportional-operation-plan/1"
_PARAMETER_DOMAIN: Final = "ebm-audit/proportional-planned-parameter/1"
_EXPECTED_CONTRACT_VERSION: Final = "0.2.3"
_EXPECTED_CONTRACT_SCHEMA_VERSION: Final = (
    "ebm-audit-proportional-benchmark-contract/v3"
)
_EXPECTED_OPERATION_COUNT: Final = 104
_EXPECTED_CASE_COUNT: Final = 57
_EXPECTED_MCAR_OPERATION_IDS: Final = (
    "mcar_missingness/source_refit",
    "mcar_missingness/transformed_refit",
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_OPERATION_ID = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:+-]*(/[A-Za-z0-9][A-Za-z0-9._:+-]*)+$"
)
_OperationKind = Literal[
    "ORDINARY_FIT",
    "MATCHED_COMPARATOR_FIT",
    "TRANSFORMATION_NULL_FIT",
    "RESAMPLE_FIT",
    "REMOVAL_REFIT",
    "BOUNDARY_RULE_FIT",
]


def _reject(code: str) -> Never:
    raise InvalidInputError(
        f"EVALUATOR.PROPORTIONAL_OPERATION_PLAN_{code}",
        "The authenticated proportional operation plan failed closed validation.",
    )


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _raw_sha256(value: object, *, code: str) -> str:
    raw = value.removeprefix("sha256:") if type(value) is str else None
    if not _is_sha256(raw):
        _reject(code)
    return cast(str, raw)


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class ProportionalPlannedParameter:
    """One immutable, canonical pre-execution parameter value."""

    parameter_id: str
    parameter_bytes: bytes


@dataclass(frozen=True, slots=True)
class ProportionalOperationIntent:
    """One immutable pre-execution operation request; it contains no result facts."""

    operation_instance_id: str
    case_plan: PublicBatchCasePlan
    analysis_spec_bytes: bytes
    operation_kind: _OperationKind
    source_case_plan: PublicBatchCasePlan | None = None
    output_case_plan: PublicBatchCasePlan | None = None
    transformation_id: str | None = None
    resample_id: str | None = None
    removal_id: str | None = None
    refit_id: str | None = None
    planned_parameters: tuple[ProportionalPlannedParameter, ...] = ()


@dataclass(frozen=True, slots=True)
class _PlanState:
    projection_bytes: bytes
    batch: AuthenticatedScenarioCaseBatch
    case_plans: tuple[PublicBatchCasePlan, ...]
    contract_bytes: bytes
    operation_intents: tuple[ProportionalOperationIntent, ...]


_PLAN_STATES: OneShotWeakRegistry[object, _PlanState]
_PLAN_STATES, _PLAN_ISSUER = create_one_shot_registry()
_PLAN_BY_BATCH: WeakKeyDictionary[
    AuthenticatedScenarioCaseBatch,
    weakref.ReferenceType[ProportionalOperationPlan],
] = WeakKeyDictionary()
_PLAN_BY_BATCH_LOCK = RLock()


class _OpaquePlanOwner:
    __slots__ = ()

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Proportional operation plans are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Proportional operation plans cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Proportional operation plans cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Proportional operation plans cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Proportional operation plans cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Proportional operation plans cannot be copied or serialized.")


@final
class ProportionalOperationPlan(_OpaquePlanOwner):
    """Opaque authenticated owner of the exact pre-execution operation plan."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ProportionalOperationPlan:
        raise TypeError("Proportional operation plans are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Proportional operation plans cannot be subclassed.")

    @property
    def digest(self) -> str:
        try:
            state = _PLAN_STATES.read(self)
            projection = strict_json_loads(state.projection_bytes)
        except (CanonicalizationError, OneShotRegistryError):
            _reject("OWNER")
        if type(projection) is not dict or not _is_sha256(
            projection.get("proportional_operation_plan_sha256")
        ):
            _reject("OWNER")
        return cast(str, projection["proportional_operation_plan_sha256"])


def _contract_projection(contract_bytes: bytes) -> tuple[dict[str, object], tuple[str, ...]]:
    if type(contract_bytes) is not bytes or not contract_bytes:
        _reject("CONTRACT")
    try:
        value = load_strict_yaml_bytes(contract_bytes, maximum_bytes=16 * 1024 * 1024)
    except StrictYamlError:
        _reject("CONTRACT")
    if type(value) is not dict:
        _reject("CONTRACT")
    contract = cast(dict[str, object], value)
    claimed_digest = contract.get("contract_sha256")
    preimage = copy.deepcopy(contract)
    preimage["contract_sha256"] = None
    challenge = contract.get("challenge")
    ledger = challenge.get("fit_ledger") if type(challenge) is dict else None
    if (
        contract.get("schema_version") != _EXPECTED_CONTRACT_SCHEMA_VERSION
        or contract.get("contract_version") != _EXPECTED_CONTRACT_VERSION
        or contract.get("contract_status") != "FROZEN"
        or contract.get("frozen") is not True
        or not _is_sha256(claimed_digest)
        or structured_sha256_hex(_CONTRACT_DOMAIN, preimage) != claimed_digest
        or type(challenge) is not dict
        or challenge.get("fit_ceiling") != _EXPECTED_OPERATION_COUNT
        or challenge.get("attempt_limit_per_candidate") != 1
        or type(ledger) is not list
    ):
        _reject("CONTRACT")
    operation_ids: list[str] = []
    family_ids: list[str] = []
    for row in ledger:
        if type(row) is not dict:
            _reject("CONTRACT")
        family_id = row.get("family_id")
        member_ids = row.get("member_ids")
        fit_count = row.get("fit_count")
        if (
            not _identifier(family_id)
            or type(member_ids) is not list
            or not member_ids
            or fit_count != len(member_ids)
            or any(type(member_id) is not str or not member_id for member_id in member_ids)
        ):
            _reject("CONTRACT")
        family_ids.append(cast(str, family_id))
        operation_ids.extend(f"{family_id}/{member_id}" for member_id in member_ids)
    if (
        len(family_ids) != 23
        or len(set(family_ids)) != len(family_ids)
        or len(operation_ids) != _EXPECTED_OPERATION_COUNT
        or len(set(operation_ids)) != len(operation_ids)
        or any(_OPERATION_ID.fullmatch(operation_id) is None for operation_id in operation_ids)
        or tuple(
            operation_id
            for operation_id in operation_ids
            if operation_id.split("/", 1)[0] == "mcar_missingness"
        )
        != _EXPECTED_MCAR_OPERATION_IDS
        or operation_ids[1:49]
        != [
            f"moderate_mina_shape/pair_{pair_index:02d}/{member}"
            for pair_index in range(24)
            for member in ("signal", "matched_pure_no_signal")
        ]
        or challenge.get("shared_fit_rules", {}).get("moderate_source_operation_id")
        != "moderate_mina_shape/pair_00/signal"
    ):
        _reject("CONTRACT")
    return contract, tuple(operation_ids)


def _analysis_spec_identity(exact_bytes: bytes) -> tuple[str, str]:
    if type(exact_bytes) is not bytes or not exact_bytes:
        _reject("ANALYSIS_SPEC")
    try:
        value = strict_json_loads(exact_bytes)
        if type(value) is not dict or canonical_json_bytes(value) != exact_bytes:
            _reject("ANALYSIS_SPEC")
        validate_instance(
            value,
            "analysis-universe.schema.json",
            definition="AnalysisSpec",
        )
        public_id = analysis_spec_content_id(cast(dict[str, Any], value))
    except (CanonicalizationError, SchemaValidationError, TypeError, ValueError):
        _reject("ANALYSIS_SPEC")
    if not public_id.startswith("sha256:") or not _is_sha256(
        public_id.removeprefix("sha256:")
    ):
        _reject("ANALYSIS_SPEC")
    return public_id, public_id.removeprefix("sha256:")


def _parameter_projection(
    parameters: tuple[ProportionalPlannedParameter, ...],
) -> list[dict[str, object]]:
    if (
        type(parameters) is not tuple
        or any(type(parameter) is not ProportionalPlannedParameter for parameter in parameters)
        or len({parameter.parameter_id for parameter in parameters}) != len(parameters)
    ):
        _reject("PARAMETERS")
    projected: list[dict[str, object]] = []
    for parameter in parameters:
        try:
            value = strict_json_loads(parameter.parameter_bytes)
            if canonical_json_bytes(value) != parameter.parameter_bytes:
                _reject("PARAMETERS")
        except (CanonicalizationError, TypeError):
            _reject("PARAMETERS")
        if not _identifier(parameter.parameter_id):
            _reject("PARAMETERS")
        projected.append(
            {
                "parameter_id": parameter.parameter_id,
                "parameter_sha256": structured_sha256_hex(
                    _PARAMETER_DOMAIN,
                    {"parameter_id": parameter.parameter_id, "value": value},
                ),
            }
        )
    return projected


def _ordered_case_selection(
    batch: AuthenticatedScenarioCaseBatch,
    case_plans: tuple[PublicBatchCasePlan, ...],
) -> tuple[
    tuple[dict[str, object], ...],
    dict[str, tuple[PublicBatchCasePlan, ...]],
    dict[int, str | None],
]:
    if (
        type(case_plans) is not tuple
        or any(type(owner) is not PublicBatchCasePlan for owner in case_plans)
        or len({id(owner) for owner in case_plans}) != len(case_plans)
    ):
        _reject("CASE_COVERAGE")
    rows = _read_public_batch_case_plan_set(batch, case_plans)
    context = _read_authenticated_batch_context(batch)
    if len(rows) != _EXPECTED_CASE_COUNT or len(context.cases) != len(rows):
        _reject("CASE_COVERAGE")
    by_family_lists: dict[str, list[PublicBatchCasePlan]] = {}
    subtype_by_owner_id: dict[int, str | None] = {}
    for owner, row, case_context in zip(case_plans, rows, context.cases, strict=True):
        if (
            row["case_id"] != case_context.case_id
            or row["family_id"] != case_context.family_id
        ):
            _reject("CASE_BINDING")
        by_family_lists.setdefault(case_context.family_id, []).append(owner)
        subtype_by_owner_id[id(owner)] = case_context.subtype
    if len(by_family_lists.get("moderate_mina_shape", ())) != 24:
        _reject("MODERATE_CASE_COVERAGE")
    correlated = tuple(
        owner
        for owner in by_family_lists.get("correlated_duplicate_events", ())
        if subtype_by_owner_id[id(owner)] == "CORRELATED"
    )
    exact = tuple(
        owner
        for owner in by_family_lists.get("correlated_duplicate_events", ())
        if subtype_by_owner_id[id(owner)] == "EXACT_DUPLICATE_POST_NOISE"
    )
    if len(correlated) != 6 or len(exact) != 6:
        _reject("SUBTYPE_CASE_COVERAGE")
    if tuple(by_family_lists["correlated_duplicate_events"]) != correlated + exact:
        _reject("SUBTYPE_CASE_ORDER")
    ordered_by_family = {
        family_id: tuple(owners) for family_id, owners in by_family_lists.items()
    }
    return rows, ordered_by_family, subtype_by_owner_id


def _expected_case_plan(
    operation_id: str,
    by_family: dict[str, tuple[PublicBatchCasePlan, ...]],
) -> PublicBatchCasePlan:
    family_id, member_id = operation_id.split("/", 1)
    owners = by_family.get(family_id, ())
    if family_id == "moderate_mina_shape":
        parts = member_id.split("/")
        if len(parts) != 2 or not parts[0].startswith("pair_"):
            _reject("MODERATE_PAIR")
        try:
            pair_index = int(parts[0].removeprefix("pair_"))
        except ValueError:
            _reject("MODERATE_PAIR")
        if not 0 <= pair_index < 24 or len(owners) != 24:
            _reject("MODERATE_PAIR")
        return owners[pair_index]
    if family_id == "correlated_duplicate_events":
        prefix, _, index_text = member_id.rpartition("_")
        try:
            member_index = int(index_text)
        except ValueError:
            _reject("SUBTYPE_CASE_ORDER")
        if prefix not in {"correlated", "exact_duplicate"} or not 0 <= member_index < 6:
            _reject("SUBTYPE_CASE_ORDER")
        offset = 0 if prefix == "correlated" else 6
        if len(owners) != 12:
            _reject("SUBTYPE_CASE_ORDER")
        return owners[offset + member_index]
    if len(owners) != 1:
        _reject("FAMILY_CASE_COVERAGE")
    return owners[0]


def _member_and_pair(operation_id: str) -> tuple[str, str | None]:
    family_id, member_path = operation_id.split("/", 1)
    if family_id == "moderate_mina_shape":
        pair_id, member_id = member_path.split("/", 1)
        return member_id, pair_id
    return member_path, None


def _validate_intent_shape(intent: ProportionalOperationIntent) -> None:
    if (
        type(intent) is not ProportionalOperationIntent
        or _OPERATION_ID.fullmatch(intent.operation_instance_id) is None
        or type(intent.case_plan) is not PublicBatchCasePlan
        or intent.operation_kind
        not in {
            "ORDINARY_FIT",
            "MATCHED_COMPARATOR_FIT",
            "TRANSFORMATION_NULL_FIT",
            "RESAMPLE_FIT",
            "REMOVAL_REFIT",
            "BOUNDARY_RULE_FIT",
        }
        or any(
            value is not None and not _identifier(value)
            for value in (
                intent.transformation_id,
                intent.resample_id,
                intent.removal_id,
                intent.refit_id,
            )
        )
        or (
            intent.source_case_plan is not None
            and type(intent.source_case_plan) is not PublicBatchCasePlan
        )
        or (
            intent.output_case_plan is not None
            and type(intent.output_case_plan) is not PublicBatchCasePlan
        )
    ):
        _reject("INTENT")
    if intent.operation_kind == "TRANSFORMATION_NULL_FIT" and (
        intent.transformation_id is None
        or intent.refit_id is None
        or intent.source_case_plan is None
        or intent.output_case_plan is None
    ):
        _reject("TRANSFORMATION_INTENT")
    if intent.operation_kind == "RESAMPLE_FIT" and intent.resample_id is None:
        _reject("RESAMPLE_INTENT")
    if intent.operation_kind == "REMOVAL_REFIT" and (
        intent.removal_id is None or intent.refit_id is None
    ):
        _reject("REMOVAL_INTENT")


def _validate_mcar_pair(entries: list[dict[str, object]]) -> None:
    mcar_entries = tuple(
        entry for entry in entries if entry.get("family_id") == "mcar_missingness"
    )
    if len(mcar_entries) != 2:
        _reject("MCAR_PAIR")
    source_entry, transformed_entry = mcar_entries
    source_ordinal = source_entry.get("operation_ordinal")
    transformed_ordinal = transformed_entry.get("operation_ordinal")
    source_hash = source_entry.get("operation_plan_entry_sha256")
    transformed_hash = transformed_entry.get("operation_plan_entry_sha256")
    if (
        tuple(entry.get("operation_instance_id") for entry in mcar_entries)
        != _EXPECTED_MCAR_OPERATION_IDS
        or type(source_ordinal) is not int
        or type(transformed_ordinal) is not int
        or transformed_ordinal != source_ordinal + 1
        or any(
            source_entry.get(field) != transformed_entry.get(field)
            for field in (
                "benchmark_subject_digest",
                "authenticated_batch_sha256",
                "case_ordinal",
                "case_id",
                "family_id",
            )
        )
        or not _is_sha256(source_hash)
        or not _is_sha256(transformed_hash)
        or source_hash == transformed_hash
    ):
        _reject("MCAR_PAIR")
    for entry in mcar_entries:
        join_key = entry.get("case_operation_join_key")
        if type(join_key) is not dict or join_key != {
            "benchmark_subject_digest": entry.get("benchmark_subject_digest"),
            "authenticated_batch_sha256": entry.get("authenticated_batch_sha256"),
            "case_id": entry.get("case_id"),
            "operation_instance_id": entry.get("operation_instance_id"),
        }:
            _reject("MCAR_PAIR")
    if source_entry["case_operation_join_key"] == transformed_entry["case_operation_join_key"]:
        _reject("MCAR_PAIR")


def _build_plan_projection(
    batch: AuthenticatedScenarioCaseBatch,
    case_plans: tuple[PublicBatchCasePlan, ...],
    contract_bytes: bytes,
    operation_intents: tuple[ProportionalOperationIntent, ...],
) -> dict[str, object]:
    contract, expected_operation_ids = _contract_projection(contract_bytes)
    case_rows, by_family, subtype_by_owner_id = _ordered_case_selection(batch, case_plans)
    expected_family_order = tuple(
        dict.fromkeys(operation_id.split("/", 1)[0] for operation_id in expected_operation_ids)
    )
    if (
        type(operation_intents) is not tuple
        or len(operation_intents) != _EXPECTED_OPERATION_COUNT
        or any(type(intent) is not ProportionalOperationIntent for intent in operation_intents)
        or tuple(intent.operation_instance_id for intent in operation_intents)
        != expected_operation_ids
        or tuple(by_family) != expected_family_order
    ):
        _reject("OPERATION_ORDER")
    row_by_owner_id = {
        id(owner): row for owner, row in zip(case_plans, case_rows, strict=True)
    }
    intent_analysis_ids: dict[int, list[str]] = {id(owner): [] for owner in case_plans}
    entries: list[dict[str, object]] = []
    moderate_source_owner = by_family["moderate_mina_shape"][0]
    for operation_ordinal, intent in enumerate(operation_intents):
        _validate_intent_shape(intent)
        expected_case = _expected_case_plan(intent.operation_instance_id, by_family)
        if intent.case_plan is not expected_case:
            _reject("CASE_SELECTION")
        case_row = row_by_owner_id.get(id(intent.case_plan))
        source_row = (
            row_by_owner_id.get(id(intent.source_case_plan))
            if intent.source_case_plan is not None
            else None
        )
        output_row = (
            row_by_owner_id.get(id(intent.output_case_plan))
            if intent.output_case_plan is not None
            else None
        )
        if case_row is None or (
            intent.source_case_plan is not None and source_row is None
        ) or (intent.output_case_plan is not None and output_row is None):
            _reject("CROSS_BOUND_CASE")
        family_id = intent.operation_instance_id.split("/", 1)[0]
        if case_row["family_id"] != family_id:
            _reject("CASE_FAMILY")
        if family_id in {
            "label_permutation_null",
            "within_group_feature_permutation_null",
        } and (
            intent.operation_kind != "TRANSFORMATION_NULL_FIT"
            or intent.source_case_plan is not moderate_source_owner
            or intent.output_case_plan is not intent.case_plan
        ):
            _reject("SHARED_SOURCE")
        public_analysis_id, analysis_sha256 = _analysis_spec_identity(
            intent.analysis_spec_bytes
        )
        intent_analysis_ids[id(intent.case_plan)].append(public_analysis_id)
        member_id, pair_id = _member_and_pair(intent.operation_instance_id)
        join_key = {
            "benchmark_subject_digest": case_row["benchmark_subject_digest"],
            "authenticated_batch_sha256": case_row["authenticated_batch_sha256"],
            "case_id": case_row["case_id"],
            "operation_instance_id": intent.operation_instance_id,
        }
        preimage: dict[str, object] = {
            "schema_version": "ebm-audit-proportional-operation-plan-entry/1.0",
            "digest_state": "DIGEST_PREIMAGE",
            "benchmark_subject_digest": case_row["benchmark_subject_digest"],
            "authenticated_batch_sha256": case_row["authenticated_batch_sha256"],
            "case_ordinal": case_row["case_ordinal"],
            "case_id": case_row["case_id"],
            "family_id": family_id,
            "scenario_subtype_id": subtype_by_owner_id[id(intent.case_plan)],
            "source_variant_id": case_row["source_variant_id"],
            "replicate_index": case_row["replicate_index"],
            "operation_ordinal": operation_ordinal,
            "operation_instance_id": intent.operation_instance_id,
            "case_operation_join_key": join_key,
            "operation_kind": intent.operation_kind,
            "member_id": member_id,
            "pair_id": pair_id,
            "analysis_spec_sha256": analysis_sha256,
            "source_case_id": source_row["case_id"] if source_row is not None else None,
            "output_case_id": output_row["case_id"] if output_row is not None else None,
            "transformation_id": intent.transformation_id,
            "resample_id": intent.resample_id,
            "removal_id": intent.removal_id,
            "refit_id": intent.refit_id,
            "planned_parameter_identities": _parameter_projection(
                intent.planned_parameters
            ),
            "operation_plan_entry_sha256": None,
        }
        entry = {
            **preimage,
            "digest_state": "PERSISTED",
            "operation_plan_entry_sha256": structured_sha256_hex(
                _ENTRY_DOMAIN,
                preimage,
            ),
        }
        try:
            validate_instance(
                entry,
                "evaluator-receipts.schema.json",
                definition="ProportionalOperationPlanEntry",
            )
        except SchemaValidationError:
            _reject("ENTRY_SCHEMA")
        entries.append(entry)

    _validate_mcar_pair(entries)

    for owner in case_plans:
        if tuple(intent_analysis_ids[id(owner)]) != (
            _read_public_batch_case_plan_analysis_spec_ids(batch, owner)
        ):
            _reject("ANALYSIS_SPEC_COVERAGE")

    batch_projection = _validated_batch_projection(batch)
    context = _read_authenticated_batch_context(batch)
    first_case = case_rows[0]
    candidate_sha256 = _read_authenticated_batch_candidate_sha256(batch)
    if (
        not _is_sha256(candidate_sha256)
        or first_case["benchmark_subject_digest"] != context.benchmark_subject_digest
    ):
        _reject("CANDIDATE")
    preimage = {
        "schema_version": "ebm-audit-proportional-operation-plan/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "contract_version": contract["contract_version"],
        "contract_schema_version": contract["schema_version"],
        "benchmark_subject_digest": context.benchmark_subject_digest,
        "contract_sha256": contract["contract_sha256"],
        "candidate_sha256": candidate_sha256,
        "authenticated_batch_sha256": _raw_sha256(
            batch_projection["case_batch_sha256"],
            code="BATCH",
        ),
        "expected_fit_count": _EXPECTED_OPERATION_COUNT,
        "operation_count": len(entries),
        "ordered_operation_instance_ids": list(expected_operation_ids),
        "ordered_entries": entries,
        "proportional_operation_plan_sha256": None,
    }
    plan = {
        **preimage,
        "digest_state": "PERSISTED",
        "proportional_operation_plan_sha256": structured_sha256_hex(
            _PLAN_DOMAIN,
            preimage,
        ),
    }
    try:
        validate_instance(
            plan,
            "evaluator-receipts.schema.json",
            definition="ProportionalOperationPlan",
        )
    except SchemaValidationError:
        _reject("PLAN_SCHEMA")
    return plan


def _issue_proportional_operation_plan(
    batch: AuthenticatedScenarioCaseBatch,
    case_plans: tuple[PublicBatchCasePlan, ...],
    contract_bytes: bytes,
    operation_intents: tuple[ProportionalOperationIntent, ...],
) -> ProportionalOperationPlan:
    """Issue the one authenticated pre-execution plan for an exact public batch."""

    if type(batch) is not AuthenticatedScenarioCaseBatch:
        _reject("BATCH")
    projection = _build_plan_projection(
        batch,
        case_plans,
        contract_bytes,
        operation_intents,
    )
    projection_bytes = canonical_json_bytes(projection)
    with _PLAN_BY_BATCH_LOCK:
        owner_reference = _PLAN_BY_BATCH.get(batch)
        existing = owner_reference() if owner_reference is not None else None
        if existing is not None:
            try:
                state = _PLAN_STATES.read(existing)
            except OneShotRegistryError:
                _reject("OWNER")
            if (
                state.projection_bytes != projection_bytes
                or state.case_plans != case_plans
                or state.contract_bytes != contract_bytes
                or state.operation_intents != operation_intents
            ):
                _reject("REISSUE")
            return existing
        owner = object.__new__(ProportionalOperationPlan)
        _PLAN_ISSUER.bind_once(
            owner,
            _PlanState(
                projection_bytes=projection_bytes,
                batch=batch,
                case_plans=case_plans,
                contract_bytes=bytes(contract_bytes),
                operation_intents=operation_intents,
            ),
        )
        _PLAN_BY_BATCH[batch] = weakref.ref(owner)
        return owner


def _read_proportional_operation_plan(
    batch: AuthenticatedScenarioCaseBatch,
    owner: ProportionalOperationPlan,
) -> dict[str, object]:
    """Read the exact plan after reconstructing every pre-execution binding."""

    if (
        type(batch) is not AuthenticatedScenarioCaseBatch
        or type(owner) is not ProportionalOperationPlan
    ):
        _reject("OWNER")
    try:
        state = _PLAN_STATES.read(owner)
        value = strict_json_loads(state.projection_bytes)
    except (CanonicalizationError, OneShotRegistryError):
        _reject("OWNER")
    if state.batch is not batch or type(value) is not dict:
        _reject("OWNER")
    rebuilt = _build_plan_projection(
        batch,
        state.case_plans,
        state.contract_bytes,
        state.operation_intents,
    )
    if value != rebuilt or canonical_json_bytes(value) != state.projection_bytes:
        _reject("BINDING")
    return cast(dict[str, object], strict_json_loads(canonical_json_bytes(value)))


def _read_proportional_operation_plan_entries(
    batch: AuthenticatedScenarioCaseBatch,
    owner: ProportionalOperationPlan,
) -> tuple[dict[str, object], ...]:
    """Return all 104 entries in authenticated operation ordinal order."""

    projection = _read_proportional_operation_plan(batch, owner)
    entries = projection.get("ordered_entries")
    if type(entries) is not list or len(entries) != _EXPECTED_OPERATION_COUNT:
        _reject("ENTRY_COVERAGE")
    return tuple(cast(dict[str, object], entry) for entry in entries)


def _resolve_proportional_operation_plan_entry(
    batch: AuthenticatedScenarioCaseBatch,
    owner: ProportionalOperationPlan,
    case_operation_join_key: dict[str, object],
) -> dict[str, object]:
    """Resolve one exact entry for a later terminal-result left join."""

    if type(case_operation_join_key) is not dict:
        _reject("JOIN_KEY")
    matches = tuple(
        entry
        for entry in _read_proportional_operation_plan_entries(batch, owner)
        if entry.get("case_operation_join_key") == case_operation_join_key
    )
    if len(matches) != 1:
        _reject("JOIN_KEY")
    return matches[0]


__all__: list[str] = []
