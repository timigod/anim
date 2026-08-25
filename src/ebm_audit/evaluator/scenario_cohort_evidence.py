"""Authenticated non-report cohort ownership for the proportional plan.

The cohort binds every contribution to one live proportional plan entry and to
the genuine collector owner that supplied the operation evidence.  Matched
comparators are cross-operation owners: their manifest, member rows, terminals,
payloads, and support edges are checked before a derived capability is issued.
No report model or rendered artifact is accepted at this boundary.
"""

from __future__ import annotations

import copy
import re
import weakref
from collections.abc import Mapping
from dataclasses import dataclass
from threading import RLock
from typing import Final, Literal, Never, SupportsIndex, cast, final
from weakref import WeakKeyDictionary

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.evaluator.grouped_meaning_derivations import (
    ValidatedGraphCardinalityDeclaration,
    ValidatedGraphOperationOutcome,
    ValidatedGraphSourceRecord,
    ValidatedMeaningGraph,
    _seal_and_validate_graph,
    frozen_operation_ids,
    frozen_slot_requirements,
)
from ebm_audit.evaluator.meaning_evidence_bundle import (
    _CONTRACT_SHA256,
    _COVERAGE_SHA256,
    _FAMILY_OPERATION_MEMBERS,
    _INVENTORY_SHA256,
)
from ebm_audit.evaluator.proportional_operation_plan import (
    ProportionalOperationPlan,
    _read_proportional_operation_plan,
)
from ebm_audit.evaluator.public_operation_evidence import (
    PublicOperationEvidence,
    _read_public_operation_evidence_owners,
)
from ebm_audit.evaluator.scenario_case_batch import (
    AuthenticatedScenarioCaseBatch,
    PublicBatchCasePlan,
    _AuthenticatedCaseContext,
    _read_authenticated_batch_context,
    _read_public_batch_case_plan,
    _read_public_batch_case_plan_analysis_spec_ids,
    _read_public_batch_case_plan_set,
)
from ebm_audit.evaluator.scenario_evidence import (
    CollectedOperationEvidenceError,
    _AuthenticatedScenarioEvidenceContext,
    _CollectedOperationEvidence,
    _CollectedOperationEvidenceProjection,
    _read_collected_operation_evidence,
    _validated_collected_operation_evidence_state,
)
from ebm_audit.evaluator.scenario_source_owner_manifest import (
    _read_authenticated_source_owner_source,
    _ScenarioSourceOwnerRecord,
)
from ebm_audit.protocol import (
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256,
    structured_sha256_hex,
)
from ebm_audit.universe.identities import analysis_spec_content_id

type OperationTerminalState = Literal[
    "AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED"
]

_MANIFEST_SCHEMA_VERSION: Final = "ebm-audit-challenge-operation-manifest/2.0"
_CONTRIBUTION_SCHEMA_VERSION: Final = "ebm-audit-operation-meaning-contribution/2.0"
_COHORT_SCHEMA_VERSION: Final = "ebm-audit-sealed-scenario-cohort-evidence/2.0"
_MATCHED_SCHEMA_VERSION: Final = "ebm-audit-matched-comparator-evidence-manifest/1.0"
_MANIFEST_DOMAIN: Final = "ebm-audit/challenge-operation-manifest/2"
_CONTRIBUTION_DOMAIN: Final = "ebm-audit/operation-meaning-contribution/2"
_COHORT_DOMAIN: Final = "ebm-audit/sealed-scenario-cohort-evidence/2"
_MATCHED_MANIFEST_DOMAIN: Final = "ebm-audit/matched-comparator-evidence-manifest/1"
_MATCHED_PLAN_DOMAIN: Final = "ebm-audit/matched-comparator-plan-evidence/1"
_CANONICAL_SCIENTIFIC_PAYLOAD_DOMAIN: Final = (
    "ebm-audit/canonical-scientific-payload/1"
)
_PLAN_DOMAIN: Final = "ebm-audit/proportional-operation-plan/1"
_ENTRY_DOMAIN: Final = "ebm-audit/proportional-operation-plan-entry/1"
_NATURAL_DOMAIN: Final = "ebm-audit/challenge-case-natural-identity/2"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TERMINAL_STATES: Final = frozenset(
    {"AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED"}
)
_COMPARATOR_FAMILIES: Final = frozenset(
    {"moderate_mina_shape", "small_sample", "noise_ladder", "incomplete_time_coverage"}
)
_SUPPORT_ONLY_OWNER_CLASSES: Final = frozenset({"ANALYSIS_SPEC", "FIT_RESPONSE_BINDING"})
_SUPPORT_ONLY_CARDINALITY: Final = "SUPPORT_ONLY"
_SUPPORT_ONLY_SELECTOR: Final = "authenticated-support-owner/1"
_MCAR_ANALYSIS_SPEC_SELECTOR: Final = "same-operation-analysis-spec/1"
_MCAR_ANALYSIS_SPEC_OPERATION_ID: Final = "mcar_missingness/source_refit"


class ScenarioCohortEvidenceError(TypeError):
    """Raised when non-report cohort evidence fails closed validation."""


def _reject(message: str) -> Never:
    raise ScenarioCohortEvidenceError(message)


def _is_hex(value: object) -> bool:
    return type(value) is str and _HEX.fullmatch(value) is not None


def _is_digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _bare_hex(value: object) -> str:
    if type(value) is not str:
        _reject("A digest is invalid.")
    raw = value.removeprefix("sha256:")
    if not _is_hex(raw):
        _reject("A digest is invalid.")
    return raw


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_plain(item) for item in value]
    if type(value) is list:
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class _PlanRow:
    ordinal: int
    operation_id: str
    family_id: str
    member_id: str
    case_id: str
    source_contract_sha256: str
    scenario_source_sha256: str
    analysis_spec_sha256: str
    operation_plan_entry_sha256: str
    case_operation_join_key: Mapping[str, object]
    case_natural_identity_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "ordinal": self.ordinal,
            "operation_id": self.operation_id,
            "family_id": self.family_id,
            "member_id": self.member_id,
            "case_id": self.case_id,
            "source_contract_sha256": self.source_contract_sha256,
            "scenario_source_sha256": self.scenario_source_sha256,
            "analysis_spec_sha256": self.analysis_spec_sha256,
            "operation_plan_entry_sha256": self.operation_plan_entry_sha256,
            "case_operation_join_key": _plain(self.case_operation_join_key),
            "case_natural_identity_sha256": self.case_natural_identity_sha256,
        }


@dataclass(frozen=True, slots=True)
class _ManifestState:
    batch: AuthenticatedScenarioCaseBatch
    operation_plan: ProportionalOperationPlan
    rows: tuple[_PlanRow, ...]
    projection_bytes: bytes


@dataclass(frozen=True, slots=True)
class _MatchedComparatorState:
    batch: AuthenticatedScenarioCaseBatch
    operation_plan: ProportionalOperationPlan
    operation_ids: tuple[str, ...]
    projections: tuple[_CollectedOperationEvidenceProjection, ...]
    source_records: tuple[tuple[_ScenarioSourceOwnerRecord, ...], ...]
    manifest_records: tuple[_ScenarioSourceOwnerRecord, ...]
    projection_bytes: bytes


@dataclass(frozen=True, slots=True)
class _AdmittedCollectorState:
    batch: AuthenticatedScenarioCaseBatch
    operation_plan: ProportionalOperationPlan
    case_plan: PublicBatchCasePlan
    context: _AuthenticatedScenarioEvidenceContext
    projection: _CollectedOperationEvidenceProjection
    source_records: tuple[_ScenarioSourceOwnerRecord, ...]
    operation_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RetainedGraphSource:
    record: _ScenarioSourceOwnerRecord
    family_id: str
    case_id: str
    operation_ids: tuple[str, ...]


@dataclass(slots=True)
class _ContributionState:
    manifest: AuthenticatedChallengeOperationManifest
    row: _PlanRow
    source_owner: _CollectedOperationEvidence | AuthenticatedMatchedComparatorEvidence
    evidence_context: _AuthenticatedScenarioEvidenceContext | None
    collected_projection: _CollectedOperationEvidenceProjection
    source_records: tuple[_ScenarioSourceOwnerRecord, ...]
    projection: dict[str, object]
    status: Literal["LIVE", "CONSUMED"]
    lock: RLock


@dataclass(slots=True)
class _AccumulatorState:
    manifest: AuthenticatedChallengeOperationManifest
    contributions: dict[str, AuthenticatedOperationMeaningContribution]
    status: Literal["OPEN", "SEALED"]
    lock: RLock


@dataclass(frozen=True, slots=True)
class _CohortState:
    manifest: AuthenticatedChallengeOperationManifest
    contributions: tuple[AuthenticatedOperationMeaningContribution, ...]
    projection_bytes: bytes


class _OpaqueOwner:
    __slots__ = ()

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Authenticated cohort owners are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Authenticated cohort owners cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Authenticated cohort owners cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Authenticated cohort owners cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Authenticated cohort owners cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Authenticated cohort owners cannot be copied or serialized.")


@final
class AuthenticatedChallengeOperationManifest(_OpaqueOwner):
    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> AuthenticatedChallengeOperationManifest:
        raise TypeError("Challenge operation manifests are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Challenge operation manifests cannot be subclassed.")

    @property
    def digest(self) -> str:
        return cast(str, _validated_manifest_projection(self)["manifest_sha256"])


@final
class AuthenticatedMatchedComparatorEvidence(_OpaqueOwner):
    """Opaque cross-operation comparator evidence capability."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> AuthenticatedMatchedComparatorEvidence:
        raise TypeError("Matched comparator evidence is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Matched comparator evidence cannot be subclassed.")

    @property
    def digest(self) -> str:
        return cast(
            str,
            _read_authenticated_matched_comparator_evidence(self)[
                "matched_comparator_evidence_sha256"
            ],
        )


@final
class AuthenticatedOperationMeaningContribution(_OpaqueOwner):
    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> AuthenticatedOperationMeaningContribution:
        raise TypeError("Operation meaning contributions are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Operation meaning contributions cannot be subclassed.")

    @property
    def digest(self) -> str:
        return cast(str, _validated_contribution_projection(self)["contribution_sha256"])


@final
class AuthenticatedMeaningCohortAccumulator(_OpaqueOwner):
    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> AuthenticatedMeaningCohortAccumulator:
        raise TypeError("Meaning cohort accumulators are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Meaning cohort accumulators cannot be subclassed.")


@final
class SealedScenarioCohortEvidence(_OpaqueOwner):
    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> SealedScenarioCohortEvidence:
        raise TypeError("Scenario cohort evidence is privately sealed.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Scenario cohort evidence cannot be subclassed.")

    @property
    def digest(self) -> str:
        return cast(str, _validated_cohort_projection(self)["cohort_sha256"])


_MANIFEST_STATES: OneShotWeakRegistry[AuthenticatedChallengeOperationManifest, _ManifestState]
_MANIFEST_STATES, _MANIFEST_ISSUER = create_one_shot_registry()
_MANIFEST_BY_PLAN: WeakKeyDictionary[
    ProportionalOperationPlan,
    weakref.ReferenceType[AuthenticatedChallengeOperationManifest],
] = WeakKeyDictionary()
_MANIFEST_BY_PLAN_LOCK = RLock()
_ADMITTED_COLLECTORS: WeakKeyDictionary[_CollectedOperationEvidence, _AdmittedCollectorState] = (
    WeakKeyDictionary()
)
_ADMITTED_COLLECTORS_LOCK = RLock()
_MATCHED_STATES: OneShotWeakRegistry[
    AuthenticatedMatchedComparatorEvidence, _MatchedComparatorState
]
_MATCHED_STATES, _MATCHED_ISSUER = create_one_shot_registry()
_MATCHED_BY_PLAN: WeakKeyDictionary[
    ProportionalOperationPlan,
    weakref.ReferenceType[AuthenticatedMatchedComparatorEvidence],
] = WeakKeyDictionary()
_MATCHED_BY_PLAN_LOCK = RLock()
_CONTRIBUTION_STATES: OneShotWeakRegistry[
    AuthenticatedOperationMeaningContribution, _ContributionState
]
_CONTRIBUTION_STATES, _CONTRIBUTION_ISSUER = create_one_shot_registry()
_ACCUMULATOR_STATES: OneShotWeakRegistry[AuthenticatedMeaningCohortAccumulator, _AccumulatorState]
_ACCUMULATOR_STATES, _ACCUMULATOR_ISSUER = create_one_shot_registry()
_COHORT_STATES: OneShotWeakRegistry[SealedScenarioCohortEvidence, _CohortState]
_COHORT_STATES, _COHORT_ISSUER = create_one_shot_registry()
_ISSUED_GRAPH_COHORTS: WeakKeyDictionary[SealedScenarioCohortEvidence, bool] = (
    WeakKeyDictionary()
)
_ISSUED_GRAPH_COHORTS_LOCK = RLock()


def _plan_preimage(plan: Mapping[str, object]) -> dict[str, object]:
    value = copy.deepcopy(dict(plan))
    value["digest_state"] = "DIGEST_PREIMAGE"
    value["proportional_operation_plan_sha256"] = None
    return value


def _entry_preimage(entry: Mapping[str, object]) -> dict[str, object]:
    value = copy.deepcopy(dict(entry))
    value["digest_state"] = "DIGEST_PREIMAGE"
    value["operation_plan_entry_sha256"] = None
    return value


def _case_map(batch: AuthenticatedScenarioCaseBatch) -> dict[str, _AuthenticatedCaseContext]:
    cases = _read_authenticated_batch_context(batch).cases
    result: dict[str, _AuthenticatedCaseContext] = {}
    for case in cases:
        if case.case_id in result:
            _reject("Authenticated case identities are ambiguous.")
        result[case.case_id] = case
    return result


def _plan_rows(
    batch: AuthenticatedScenarioCaseBatch,
    operation_plan: ProportionalOperationPlan,
) -> tuple[dict[str, object], tuple[_PlanRow, ...]]:
    if (
        type(batch) is not AuthenticatedScenarioCaseBatch
        or type(operation_plan) is not ProportionalOperationPlan
    ):
        _reject("A live proportional operation plan is required.")
    try:
        plan = _read_proportional_operation_plan(batch, operation_plan)
    except Exception as error:
        raise ScenarioCohortEvidenceError("The proportional plan failed revalidation.") from error
    operation_ids = frozen_operation_ids()
    entries = plan.get("ordered_entries")
    plan_digest = plan.get("proportional_operation_plan_sha256")
    if (
        plan.get("digest_state") != "PERSISTED"
        or plan.get("operation_count") != len(operation_ids)
        or plan.get("expected_fit_count") != len(operation_ids)
        or plan.get("ordered_operation_instance_ids") != list(operation_ids)
        or type(entries) is not list
        or len(entries) != len(operation_ids)
        or not _is_hex(plan_digest)
        or structured_sha256_hex(_PLAN_DOMAIN, _plan_preimage(plan)) != plan_digest
    ):
        _reject("The proportional plan does not contain exact ordered 104 entries.")
    subject = plan.get("benchmark_subject_digest")
    batch_sha = plan.get("authenticated_batch_sha256")
    if not _is_digest(subject) or not _is_hex(batch_sha):
        _reject("The proportional plan identity is invalid.")
    cases = _case_map(batch)
    rows: list[_PlanRow] = []
    hashes: set[str] = set()
    joins: set[bytes] = set()
    for ordinal, (operation_id, raw) in enumerate(zip(operation_ids, entries, strict=True)):
        if type(raw) is not dict:
            _reject("A proportional plan entry is invalid.")
        entry = cast(dict[str, object], raw)
        family_id, member_path = operation_id.split("/", 1)
        member_id = (
            member_path.split("/", 1)[1] if family_id == "moderate_mina_shape" else member_path
        )
        case_id = entry.get("case_id")
        join_key = entry.get("case_operation_join_key")
        entry_digest = entry.get("operation_plan_entry_sha256")
        expected_join = {
            "benchmark_subject_digest": subject,
            "authenticated_batch_sha256": batch_sha,
            "case_id": case_id,
            "operation_instance_id": operation_id,
        }
        if (
            entry.get("digest_state") != "PERSISTED"
            or entry.get("operation_ordinal") != ordinal
            or entry.get("operation_instance_id") != operation_id
            or entry.get("family_id") != family_id
            or entry.get("member_id") != member_id
            or type(case_id) is not str
            or not _is_hex(entry.get("analysis_spec_sha256"))
            or not _is_hex(entry_digest)
            or structured_sha256_hex(_ENTRY_DOMAIN, _entry_preimage(entry)) != entry_digest
            or join_key != expected_join
        ):
            _reject("A plan entry hash or join key is invalid.")
        case = cases.get(case_id)
        if case is None or case.family_id != family_id:
            _reject("A plan entry is detached from its authenticated case.")
        join_bytes = canonical_json_bytes(join_key)
        if entry_digest in hashes or join_bytes in joins:
            _reject("A plan entry hash or join key was replayed.")
        hashes.add(entry_digest)
        joins.add(join_bytes)
        source_contract = _bare_hex(case.source_contract_sha256)
        scenario_source = _bare_hex(case.scenario_source_sha256)
        natural = structured_sha256(
            _NATURAL_DOMAIN,
            {
                "case_id": case_id,
                "source_contract_sha256": source_contract,
                "scenario_source_sha256": scenario_source,
                "analysis_spec_sha256": entry["analysis_spec_sha256"],
                "operation_plan_entry_sha256": entry_digest,
                "case_operation_join_key": join_key,
            },
        )
        rows.append(
            _PlanRow(
                ordinal=ordinal,
                operation_id=operation_id,
                family_id=family_id,
                member_id=member_id,
                case_id=case_id,
                source_contract_sha256=source_contract,
                scenario_source_sha256=scenario_source,
                analysis_spec_sha256=cast(str, entry["analysis_spec_sha256"]),
                operation_plan_entry_sha256=entry_digest,
                case_operation_join_key=cast(Mapping[str, object], join_key),
                case_natural_identity_sha256=natural,
            )
        )
    return plan, tuple(rows)


def _manifest_dict(plan: Mapping[str, object], rows: tuple[_PlanRow, ...]) -> dict[str, object]:
    return {
        "schema_version": _MANIFEST_SCHEMA_VERSION,
        "benchmark_subject_digest": plan["benchmark_subject_digest"],
        "authenticated_batch_sha256": plan["authenticated_batch_sha256"],
        "candidate_sha256": plan["candidate_sha256"],
        "contract_sha256": plan["contract_sha256"],
        "proportional_operation_plan_sha256": plan["proportional_operation_plan_sha256"],
        "meaning_contract_sha256": _CONTRACT_SHA256,
        "meaning_inventory_sha256": _INVENTORY_SHA256,
        "meaning_coverage_sha256": _COVERAGE_SHA256,
        "expected_operation_count": len(rows),
        "ordered_operations": [row.as_dict() for row in rows],
        "ordered_operation_plan_entry_sha256": [row.operation_plan_entry_sha256 for row in rows],
        "ordered_case_operation_join_keys": [_plain(row.case_operation_join_key) for row in rows],
        "manifest_sha256": None,
    }


def _issue_authenticated_challenge_operation_manifest(
    batch: AuthenticatedScenarioCaseBatch,
    operation_plan: ProportionalOperationPlan,
    /,
) -> AuthenticatedChallengeOperationManifest:
    plan, rows = _plan_rows(batch, operation_plan)
    projection = _manifest_dict(plan, rows)
    projection["manifest_sha256"] = structured_sha256(_MANIFEST_DOMAIN, projection)
    projection_bytes = canonical_json_bytes(projection)
    with _MANIFEST_BY_PLAN_LOCK:
        retained = _MANIFEST_BY_PLAN.get(operation_plan)
        existing = retained() if retained is not None else None
        if existing is not None:
            state = _manifest_state(existing)
            if state.batch is not batch or state.projection_bytes != projection_bytes:
                _reject("The proportional plan manifest was cross-bound on reissue.")
            return existing
        owner = object.__new__(AuthenticatedChallengeOperationManifest)
        _MANIFEST_ISSUER.bind_once(
            owner, _ManifestState(batch, operation_plan, rows, projection_bytes)
        )
        _MANIFEST_BY_PLAN[operation_plan] = weakref.ref(owner)
    _validated_manifest_projection(owner)
    return owner


def _manifest_for_plan(
    batch: AuthenticatedScenarioCaseBatch,
    operation_plan: ProportionalOperationPlan,
) -> AuthenticatedChallengeOperationManifest:
    with _MANIFEST_BY_PLAN_LOCK:
        retained = _MANIFEST_BY_PLAN.get(operation_plan)
        owner = retained() if retained is not None else None
    if owner is None:
        _reject("The proportional plan manifest must be issued before collection.")
    state = _manifest_state(owner)
    if state.batch is not batch:
        _reject("The proportional plan manifest is cross-batch.")
    _validated_manifest_projection(owner)
    return owner


def _manifest_state(owner: AuthenticatedChallengeOperationManifest) -> _ManifestState:
    if type(owner) is not AuthenticatedChallengeOperationManifest:
        _reject("A genuine challenge operation manifest is required.")
    try:
        state = _MANIFEST_STATES.read(owner)
    except OneShotRegistryError as error:
        raise ScenarioCohortEvidenceError(
            "A genuine challenge operation manifest is required."
        ) from error
    if type(state) is not _ManifestState:
        _reject("A genuine challenge operation manifest is required.")
    return state


def _validated_manifest_projection(
    owner: AuthenticatedChallengeOperationManifest,
) -> dict[str, object]:
    state = _manifest_state(owner)
    plan, rows = _plan_rows(state.batch, state.operation_plan)
    if rows != state.rows:
        _reject("The challenge manifest is detached from the live proportional plan.")
    retained = strict_json_loads(state.projection_bytes)
    if type(retained) is not dict:
        _reject("The challenge operation manifest is invalid.")
    projection = cast(dict[str, object], retained)
    expected = _manifest_dict(plan, rows)
    digest = projection.get("manifest_sha256")
    expected["manifest_sha256"] = digest
    preimage = copy.deepcopy(projection)
    preimage["manifest_sha256"] = None
    if (
        projection != expected
        or not _is_digest(digest)
        or structured_sha256(_MANIFEST_DOMAIN, preimage) != digest
        or canonical_json_bytes(projection) != state.projection_bytes
    ):
        _reject("The challenge operation manifest is invalid.")
    return projection


def _read_authenticated_challenge_operation_manifest(
    owner: AuthenticatedChallengeOperationManifest,
) -> dict[str, object]:
    return cast(
        dict[str, object],
        strict_json_loads(canonical_json_bytes(_validated_manifest_projection(owner))),
    )


def _manifest_row(owner: AuthenticatedChallengeOperationManifest, operation_id: str) -> _PlanRow:
    rows = _manifest_state(owner).rows
    _validated_manifest_projection(owner)
    matches = tuple(row for row in rows if row.operation_id == operation_id)
    if len(matches) != 1:
        _reject("The operation is absent from the authenticated proportional plan.")
    return matches[0]


def _source_records_for_owner(
    owner: _CollectedOperationEvidence,
) -> tuple[_ScenarioSourceOwnerRecord, ...]:
    try:
        state = _validated_collected_operation_evidence_state(owner)
    except Exception as error:
        raise ScenarioCohortEvidenceError(
            "A genuine collected operation owner is required."
        ) from error
    return tuple(state.source_records)


def _collector_projection(
    owner: _CollectedOperationEvidence, context: _AuthenticatedScenarioEvidenceContext
) -> tuple[_CollectedOperationEvidenceProjection, tuple[_ScenarioSourceOwnerRecord, ...]]:
    records = _source_records_for_owner(owner)
    try:
        projection = _read_collected_operation_evidence(owner, context)
    except (CollectedOperationEvidenceError, TypeError) as error:
        raise ScenarioCohortEvidenceError(
            "Collected operation evidence was replayed or detached."
        ) from error
    return projection, records


def _record_source_digest(record: _ScenarioSourceOwnerRecord) -> str:
    if not _is_hex(record.source_record_sha256):
        _reject("A collected source-record digest is invalid.")
    return record.source_record_sha256


def _record_value(record: _ScenarioSourceOwnerRecord) -> dict[str, object]:
    # Collector projections intentionally hide raw values.  The authenticated
    # owner state retains the source records; this hook is used only by the
    # cross-operation issuer before it releases its opaque capability.
    source = getattr(record, "source_record", None)
    if not isinstance(source, Mapping):
        _reject("A collected source owner lacks authenticated source facts.")
    return cast(dict[str, object], _plain(source))


def _validate_matched_manifest(
    value: Mapping[str, object],
    records: tuple[_ScenarioSourceOwnerRecord, ...],
    expected_subject: str,
    expected_row: _PlanRow,
) -> None:
    if (
        value.get("schema_version") != _MATCHED_SCHEMA_VERSION
        or value.get("digest_state") != "PERSISTED"
        or value.get("benchmark_subject_digest") != expected_subject
    ):
        _reject("Matched comparator manifest identity is invalid.")
    digest = value.get("matched_comparator_evidence_sha256")
    preimage = copy.deepcopy(dict(value))
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage["matched_comparator_evidence_sha256"] = None
    if not _is_hex(digest) or structured_sha256_hex(_MATCHED_MANIFEST_DOMAIN, preimage) != digest:
        _reject("Matched comparator manifest digest is invalid.")
    plans = value.get("plan_evidence")
    members = value.get("member_evidence")
    if type(plans) is not list or not plans or type(members) is not list or not members:
        _reject("Matched comparator manifest member coverage is incomplete.")
    plan_member_ids: set[str] = set()
    for plan in plans:
        if type(plan) is not dict:
            _reject("Matched comparator plan evidence is invalid.")
        pairing_key = plan.get("pairing_key")
        expected_pairing = "/".join(
            (
                str(plan.get("comparator_id")),
                str(plan.get("source_variant_id")),
                str(plan.get("replicate_index")),
            )
        )
        ordered_members = plan.get("ordered_member_ids")
        if (
            pairing_key != expected_pairing
            or type(ordered_members) is not list
            or len(ordered_members) < 2
            or len(set(ordered_members)) != len(ordered_members)
        ):
            _reject("Matched comparator plan member order is invalid.")
        plan_member_ids.update(cast(list[str], ordered_members))
        plan_hash = structured_sha256_hex(_MATCHED_PLAN_DOMAIN, plan)
        matching = [
            member
            for member in members
            if type(member) is dict and member.get("matched_comparator_plan_evidence") == plan
        ]
        if {cast(str, member.get("member_id")) for member in matching} != set(
            cast(list[str], ordered_members)
        ):
            _reject("Matched comparator member coverage is incomplete.")
        member_ids: set[str] = set()
        shared_chains: set[tuple[object, object, object]] = set()
        for member in matching:
            if (
                member.get("evidence_state") != "PASS"
                or member.get("benchmark_subject_digest") != expected_subject
                or member.get("matched_comparator_plan_evidence_sha256") != plan_hash
            ):
                _reject("Matched comparator member evidence is detached.")
            chain_bindings = member.get("chain_bindings")
            if (
                type(chain_bindings) is not list
                or len(chain_bindings) != 4
                or [row.get("chain_index") for row in chain_bindings if type(row) is dict]
                != [0, 1, 2, 3]
            ):
                _reject("Matched comparator four-chain bindings are incomplete.")
            for chain in chain_bindings:
                if (
                    type(chain) is not dict
                    or chain.get("equal") is not True
                    or chain.get("source_chain_seed") != chain.get("member_chain_seed")
                ):
                    _reject("Matched comparator chain equality is invalid.")
                shared_chains.add(
                    (
                        chain.get("backend_identity_digest"),
                        chain.get("settings_digest"),
                        chain.get("environment_digest"),
                    )
                )
            operations = member.get("ordered_operation_evidence")
            planned_operations = plan.get("ordered_operations")
            if type(operations) is not list or type(planned_operations) is not list:
                _reject("Matched comparator operation evidence is missing.")
            member_id = member.get("member_id")
            selected_operations: list[dict[str, object]] = []
            for planned_operation in planned_operations:
                if type(planned_operation) is not dict:
                    _reject("Matched comparator planned operation is invalid.")
                target_member = planned_operation.get("member_id")
                member_index = planned_operation.get("member_index")
                if target_member is None and type(member_index) is int:
                    if member_index < 0 or member_index >= len(ordered_members):
                        _reject("Matched comparator planned operation is detached.")
                    target_member = ordered_members[member_index]
                if target_member == member_id:
                    selected_operations.append(planned_operation)
            if len(operations) != len(selected_operations):
                _reject("Matched comparator operation evidence is incomplete.")
            seen_sequences: set[int] = set()
            for operation, planned_operation in zip(
                operations, selected_operations, strict=True
            ):
                if (
                    type(operation) is not dict
                    or operation.get("pairing_key") != pairing_key
                    or type(operation.get("sequence")) is not int
                    or operation.get("sequence") in seen_sequences
                    or operation.get("sequence") != planned_operation.get("sequence")
                    or operation.get("operation") != planned_operation
                ):
                    _reject("Matched comparator operation evidence is replayed.")
                seen_sequences.add(cast(int, operation.get("sequence")))
            if type(member_id) is not str or member_id in member_ids:
                _reject("Matched comparator member identity is duplicated.")
            member_ids.add(member_id)
        if len(shared_chains) != 1:
            _reject("Matched comparator chains do not share execution identity.")
    if (
        expected_row.family_id not in _COMPARATOR_FAMILIES
        or expected_row.operation_id.split("/", 1)[0] != expected_row.family_id
        or not plan_member_ids
    ):
        _reject("Matched comparator family is not admitted.")
    owner_digests = {_record_source_digest(record) for record in records}
    expected_join = canonical_json_bytes(_plain(expected_row.case_operation_join_key))
    retained = tuple(
        record
        for record in records
        if record.owner_class in {"PUBLIC_TERMINAL_RESULT", "CANONICAL_SCIENTIFIC_PAYLOAD"}
        and (
            record.natural_identity.get("operation_instance_id") == expected_row.operation_id
            or _record_value(record).get("operation_instance_id") == expected_row.operation_id
        )
    )
    terminals = tuple(
        record
        for record in retained
        if record.owner_class == "PUBLIC_TERMINAL_RESULT"
        and _record_value(record).get("operation_plan_entry_sha256")
        == expected_row.operation_plan_entry_sha256
        and canonical_json_bytes(
            _plain(record.natural_identity.get("case_operation_join_key"))
        )
        == expected_join
        and canonical_json_bytes(_plain(_record_value(record).get("case_operation_join_key")))
        == expected_join
    )
    if len(terminals) != 1:
        _reject("Matched comparator terminal or payload evidence is detached from its plan row.")
    for record in retained:
        if not set(record.ordered_support_owner_sha256).issubset(owner_digests):
            _reject("Matched comparator support edge is forged.")


def _issue_authenticated_matched_comparator_evidence(
    batch: AuthenticatedScenarioCaseBatch,
    operation_plan: ProportionalOperationPlan,
    collected_owners: tuple[_CollectedOperationEvidence, ...],
    /,
) -> AuthenticatedMatchedComparatorEvidence:
    """Issue one cross-operation capability from already admitted case owners."""

    if (
        type(batch) is not AuthenticatedScenarioCaseBatch
        or type(operation_plan) is not ProportionalOperationPlan
        or type(collected_owners) is not tuple
        or not collected_owners
        or any(type(owner) is not _CollectedOperationEvidence for owner in collected_owners)
        or len({id(owner) for owner in collected_owners}) != len(collected_owners)
    ):
        _reject("A live proportional plan and ordered collected owners are required.")
    plan, plan_rows = _plan_rows(batch, operation_plan)
    plan_sha256 = cast(str, plan["proportional_operation_plan_sha256"])
    required_rows = tuple(row for row in plan_rows if row.family_id in _COMPARATOR_FAMILIES)
    projections: list[_CollectedOperationEvidenceProjection] = []
    source_records: list[tuple[_ScenarioSourceOwnerRecord, ...]] = []
    operation_ids: list[str] = []
    with _ADMITTED_COLLECTORS_LOCK:
        admitted = tuple(_ADMITTED_COLLECTORS.get(owner) for owner in collected_owners)
    if any(state is None for state in admitted):
        _reject("Matched comparator owners must pass proportional admission first.")
    for state_value in admitted:
        state = cast(_AdmittedCollectorState, state_value)
        if state.batch is not batch or state.operation_plan is not operation_plan:
            _reject("Matched comparator evidence is cross-plan.")
        for operation_id in state.operation_ids:
            if operation_id.split("/", 1)[0] not in _COMPARATOR_FAMILIES:
                _reject("Matched comparator evidence includes an unrelated family.")
            operation_ids.append(operation_id)
            projections.append(state.projection)
            source_records.append(state.source_records)
    if tuple(operation_ids) != tuple(row.operation_id for row in required_rows):
        _reject("Comparator evidence is missing, reordered, or cross-plan.")
    manifests: list[_ScenarioSourceOwnerRecord] = []
    for row, records, collected_projection in zip(
        required_rows,
        source_records,
        projections,
        strict=True,
    ):
        candidates = tuple(
            record for record in records if record.owner_class == "MATCHED_COMPARATOR_EVIDENCE"
        )
        if len(candidates) != 1:
            _reject("One exact matched comparator manifest is required per operation.")
        manifest_record = candidates[0]
        manifest = _record_value(manifest_record)
        _validate_matched_manifest(
            manifest,
            records,
            collected_projection.benchmark_subject_digest,
            row,
        )
        manifests.append(manifest_record)
    comparator_projection = {
        "schema_version": "ebm-audit-authenticated-matched-comparator-capability/1.0",
        "proportional_operation_plan_sha256": plan_sha256,
        "operation_ids": operation_ids,
        "manifest_digests": [
            _record_value(manifest)["matched_comparator_evidence_sha256"] for manifest in manifests
        ],
        "matched_comparator_evidence_sha256": None,
    }
    comparator_projection["matched_comparator_evidence_sha256"] = structured_sha256(
        "ebm-audit/authenticated-matched-comparator-capability/1", comparator_projection
    )
    owner = object.__new__(AuthenticatedMatchedComparatorEvidence)
    _MATCHED_ISSUER.bind_once(
        owner,
        _MatchedComparatorState(
            batch,
            operation_plan,
            tuple(operation_ids),
            tuple(projections),
            tuple(source_records),
            tuple(manifests),
            canonical_json_bytes(comparator_projection),
        ),
    )
    _read_authenticated_matched_comparator_evidence(owner)
    with _MATCHED_BY_PLAN_LOCK:
        retained = _MATCHED_BY_PLAN.get(operation_plan)
        existing = retained() if retained is not None else None
        if existing is not None:
            _reject("Matched comparator evidence was replayed for one proportional plan.")
        _MATCHED_BY_PLAN[operation_plan] = weakref.ref(owner)
    return owner


def _matched_state(owner: AuthenticatedMatchedComparatorEvidence) -> _MatchedComparatorState:
    if type(owner) is not AuthenticatedMatchedComparatorEvidence:
        _reject("A genuine matched comparator capability is required.")
    try:
        state = _MATCHED_STATES.read(owner)
    except OneShotRegistryError as error:
        raise ScenarioCohortEvidenceError(
            "A genuine matched comparator capability is required."
        ) from error
    if type(state) is not _MatchedComparatorState:
        _reject("A genuine matched comparator capability is required.")
    return state


def _read_authenticated_matched_comparator_evidence(
    owner: AuthenticatedMatchedComparatorEvidence,
) -> dict[str, object]:
    state = _matched_state(owner)
    _plan, rows = _plan_rows(state.batch, state.operation_plan)
    if state.operation_ids != tuple(
        row.operation_id for row in rows if row.family_id in _COMPARATOR_FAMILIES
    ):
        _reject("Matched comparator capability is detached from its live plan.")
    retained = strict_json_loads(state.projection_bytes)
    if type(retained) is not dict:
        _reject("Matched comparator capability is invalid.")
    projection = cast(dict[str, object], retained)
    digest = projection.get("matched_comparator_evidence_sha256")
    preimage = copy.deepcopy(projection)
    preimage["matched_comparator_evidence_sha256"] = None
    if (
        not _is_digest(digest)
        or structured_sha256("ebm-audit/authenticated-matched-comparator-capability/1", preimage)
        != digest
        or canonical_json_bytes(projection) != state.projection_bytes
    ):
        _reject("Matched comparator capability is invalid.")
    return cast(dict[str, object], strict_json_loads(canonical_json_bytes(projection)))


def _read_authenticated_matched_comparator_source_records(
    owner: AuthenticatedMatchedComparatorEvidence,
) -> tuple[_ScenarioSourceOwnerRecord, ...]:
    """Return derived records that retain the cross-operation capability."""

    state = _matched_state(owner)
    _read_authenticated_matched_comparator_evidence(owner)
    return tuple(
        _ScenarioSourceOwnerRecord(
            owner_class=record.owner_class,
            owner_schema_ref=record.owner_schema_ref,
            natural_identity=record.natural_identity,
            source_record=record.source_record,
            source_record_sha256=record.source_record_sha256,
            ordered_support_owner_sha256=record.ordered_support_owner_sha256,
            source_capability=owner,
        )
        for record in state.manifest_records
    )


def _source_digests(records: tuple[_ScenarioSourceOwnerRecord, ...]) -> tuple[str, ...]:
    digests = tuple(_record_source_digest(record) for record in records)
    if len(digests) != len(set(digests)):
        _reject("Collected source-record digests were replayed.")
    return digests


def _contribution_source(
    source_owner: _CollectedOperationEvidence | AuthenticatedMatchedComparatorEvidence,
    context: _AuthenticatedScenarioEvidenceContext | None,
    operation_id: str,
) -> tuple[_CollectedOperationEvidenceProjection, tuple[_ScenarioSourceOwnerRecord, ...]]:
    if type(source_owner) is AuthenticatedMatchedComparatorEvidence:
        state = _matched_state(source_owner)
        matches = tuple(
            (projection, records)
            for candidate, projection, records in zip(
                state.operation_ids, state.projections, state.source_records, strict=True
            )
            if candidate == operation_id
        )
        if len(matches) != 1:
            _reject("Matched comparator operation is absent from its capability.")
        return matches[0]
    if (
        type(source_owner) is not _CollectedOperationEvidence
        or type(context) is not _AuthenticatedScenarioEvidenceContext
    ):
        _reject("A genuine collected operation owner and context are required.")
    return _collector_projection(source_owner, context)


def _terminal_state(record: _ScenarioSourceOwnerRecord) -> OperationTerminalState:
    status = record.source_record.get("terminal_status")
    if status in {"SUCCESS", "CONVERGENCE_WARN"}:
        return "AVAILABLE"
    if status in {"UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED"}:
        return cast(OperationTerminalState, status)
    return "FAILED"


def _contribution_dict(
    manifest: AuthenticatedChallengeOperationManifest,
    row: _PlanRow,
    collected: _CollectedOperationEvidenceProjection,
    records: tuple[_ScenarioSourceOwnerRecord, ...],
    terminal_state: OperationTerminalState,
) -> dict[str, object]:
    manifest_projection = _validated_manifest_projection(manifest)
    if (
        collected.case_id != row.case_id
        or collected.family_id != row.family_id
        or _bare_hex(collected.source_contract_sha256) != row.source_contract_sha256
        or _bare_hex(collected.scenario_source_sha256) != row.scenario_source_sha256
        or terminal_state not in _TERMINAL_STATES
    ):
        _reject("Collected operation evidence is detached from its plan row.")
    contribution: dict[str, object] = {
        "schema_version": _CONTRIBUTION_SCHEMA_VERSION,
        "manifest_sha256": manifest_projection["manifest_sha256"],
        "proportional_operation_plan_sha256": manifest_projection[
            "proportional_operation_plan_sha256"
        ],
        "operation_id": row.operation_id,
        "row_ordinal": row.ordinal,
        "case_id": row.case_id,
        "family_id": row.family_id,
        "member_id": row.member_id,
        "operation_plan_entry_sha256": row.operation_plan_entry_sha256,
        "case_operation_join_key": _plain(row.case_operation_join_key),
        "collected_operation_evidence_sha256": (collected.collected_operation_evidence_sha256),
        "scientific_plan_digest": collected.scientific_plan_digest,
        "scientific_terminal_index_digest": collected.scientific_terminal_index_digest,
        "scientific_evidence_digest": collected.scientific_evidence_digest,
        "ordered_source_record_digests": list(_source_digests(records)),
        "terminal_state": terminal_state,
        "contribution_sha256": None,
    }
    contribution["contribution_sha256"] = structured_sha256(_CONTRIBUTION_DOMAIN, contribution)
    return contribution


def _bind_contribution(
    manifest: AuthenticatedChallengeOperationManifest,
    row: _PlanRow,
    source_owner: _CollectedOperationEvidence | AuthenticatedMatchedComparatorEvidence,
    context: _AuthenticatedScenarioEvidenceContext | None,
    collected: _CollectedOperationEvidenceProjection,
    records: tuple[_ScenarioSourceOwnerRecord, ...],
    contribution: dict[str, object],
) -> AuthenticatedOperationMeaningContribution:
    owner = object.__new__(AuthenticatedOperationMeaningContribution)
    _CONTRIBUTION_ISSUER.bind_once(
        owner,
        _ContributionState(
            manifest,
            row,
            source_owner,
            context,
            collected,
            records,
            contribution,
            "LIVE",
            RLock(),
        ),
    )
    _validated_contribution_projection(owner)
    return owner


def _accept_collected_case_operation_evidence(
    batch: AuthenticatedScenarioCaseBatch,
    operation_plan: ProportionalOperationPlan,
    case_plan: PublicBatchCasePlan,
    context: _AuthenticatedScenarioEvidenceContext,
    collected: _CollectedOperationEvidence,
    /,
) -> tuple[AuthenticatedOperationMeaningContribution, ...]:
    """Consume one case collector once and atomically issue all plan contributions."""

    if (
        type(batch) is not AuthenticatedScenarioCaseBatch
        or type(operation_plan) is not ProportionalOperationPlan
        or type(case_plan) is not PublicBatchCasePlan
        or type(context) is not _AuthenticatedScenarioEvidenceContext
        or type(collected) is not _CollectedOperationEvidence
    ):
        _reject("Exact proportional case evidence capabilities are required.")
    plan, all_rows = _plan_rows(batch, operation_plan)
    manifest = _manifest_for_plan(batch, operation_plan)
    case_projection = _read_public_batch_case_plan(batch, case_plan)
    case_id = case_projection.get("case_id")
    family_id = case_projection.get("family_id")
    rows = tuple(row for row in all_rows if row.case_id == case_id)
    expected_analysis = tuple(
        _bare_hex(value)
        for value in _read_public_batch_case_plan_analysis_spec_ids(batch, case_plan)
    )
    if (
        type(case_id) is not str
        or type(family_id) is not str
        or not rows
        or len(rows) > 9
        or any(row.family_id != family_id for row in rows)
        or tuple(row.analysis_spec_sha256 for row in rows) != expected_analysis
    ):
        _reject("The case plan does not select its exact proportional operations.")
    collector_state = _validated_collected_operation_evidence_state(collected)
    if collector_state.context is not context or collector_state.consumed:
        _reject("Collected case evidence is detached or replayed.")
    records = tuple(collector_state.source_records)
    plan_records = tuple(
        record for record in records if record.owner_class == "PROPORTIONAL_OPERATION_PLAN"
    )
    case_records = tuple(
        record for record in records if record.owner_class == "PUBLIC_BATCH_CASE_PLAN"
    )
    if len(plan_records) != 1 or len(case_records) != 1:
        _reject("Collected case evidence lacks exact public plan owners.")
    try:
        operation_evidence = _read_authenticated_source_owner_source(plan_records[0])
        source_batch, source_plan, _capture = _read_public_operation_evidence_owners(
            cast(PublicOperationEvidence, operation_evidence)
        )
    except Exception as error:
        raise ScenarioCohortEvidenceError(
            "The collected proportional plan owner is not authentic."
        ) from error
    if (
        type(operation_evidence) is not PublicOperationEvidence
        or source_batch is not batch
        or source_plan is not operation_plan
        or _record_value(plan_records[0]) != plan
        or _record_value(case_records[0]) != case_projection
    ):
        _reject("Collected case evidence is cross-plan or cross-case.")
    terminals = tuple(
        record for record in records if record.owner_class == "PUBLIC_TERMINAL_RESULT"
    )
    by_join: dict[bytes, _ScenarioSourceOwnerRecord] = {}
    for terminal in terminals:
        join = terminal.natural_identity.get("case_operation_join_key")
        if not isinstance(join, Mapping):
            _reject("A public terminal lacks its case-operation join key.")
        encoded = canonical_json_bytes(_plain(join))
        if encoded in by_join:
            _reject("A public terminal plan entry was replayed.")
        by_join[encoded] = terminal
    expected_join_bytes = tuple(
        canonical_json_bytes(_plain(row.case_operation_join_key)) for row in rows
    )
    if set(by_join) != set(expected_join_bytes):
        _reject("Public terminal coverage is missing or contains an extra plan entry.")
    plan_sha = plan["proportional_operation_plan_sha256"]
    for row, join_bytes in zip(rows, expected_join_bytes, strict=True):
        terminal_source = _record_value(by_join[join_bytes])
        if (
            terminal_source.get("proportional_operation_plan_sha256") != plan_sha
            or terminal_source.get("operation_plan_entry_sha256") != row.operation_plan_entry_sha256
            or terminal_source.get("analysis_spec_sha256", row.analysis_spec_sha256)
            != row.analysis_spec_sha256
        ):
            _reject("A public terminal is detached from its proportional plan entry.")
    collected_projection = _read_collected_operation_evidence(collected, context)
    if collected_projection.case_id != case_id or collected_projection.family_id != family_id:
        _reject("The consumed collector projection is cross-case.")
    prepared = tuple(
        (
            row,
            _contribution_dict(
                manifest,
                row,
                collected_projection,
                records,
                _terminal_state(by_join[join_bytes]),
            ),
        )
        for row, join_bytes in zip(rows, expected_join_bytes, strict=True)
    )
    contributions = tuple(
        _bind_contribution(
            manifest,
            row,
            collected,
            context,
            collected_projection,
            records,
            contribution,
        )
        for row, contribution in prepared
    )
    with _ADMITTED_COLLECTORS_LOCK:
        if collected in _ADMITTED_COLLECTORS:
            _reject("Collected case evidence admission was replayed.")
        _ADMITTED_COLLECTORS[collected] = _AdmittedCollectorState(
            batch=batch,
            operation_plan=operation_plan,
            case_plan=case_plan,
            context=context,
            projection=collected_projection,
            source_records=records,
            operation_ids=tuple(row.operation_id for row in rows),
        )
    return contributions


def _validated_contribution_state(
    owner: AuthenticatedOperationMeaningContribution,
) -> _ContributionState:
    if type(owner) is not AuthenticatedOperationMeaningContribution:
        _reject("A genuine operation contribution is required.")
    try:
        state = _CONTRIBUTION_STATES.read(owner)
    except OneShotRegistryError as error:
        raise ScenarioCohortEvidenceError(
            "A genuine operation contribution is required."
        ) from error
    if type(state) is not _ContributionState:
        _reject("A genuine operation contribution is required.")
    return state


def _validated_contribution_projection(
    owner: AuthenticatedOperationMeaningContribution,
) -> dict[str, object]:
    state = _validated_contribution_state(owner)
    expected = _issue_projection_for_validation(state)
    retained = state.projection
    if retained != expected or not _is_digest(retained.get("contribution_sha256")):
        _reject("The operation contribution is invalid.")
    return retained


def _issue_projection_for_validation(state: _ContributionState) -> dict[str, object]:
    if type(state.source_owner) is _CollectedOperationEvidence:
        collector_state = _validated_collected_operation_evidence_state(state.source_owner)
        if (
            collector_state.context is not state.evidence_context
            or not collector_state.consumed
            or tuple(collector_state.source_records) != state.source_records
        ):
            _reject("The retained collected operation owner is detached.")
    else:
        matched_state = _matched_state(state.source_owner)
        _read_authenticated_matched_comparator_evidence(state.source_owner)
        matches = tuple(
            (projection, records)
            for operation_id, projection, records in zip(
                matched_state.operation_ids,
                matched_state.projections,
                matched_state.source_records,
                strict=True,
            )
            if operation_id == state.row.operation_id
        )
        if len(matches) != 1 or matches[0] != (
            state.collected_projection,
            state.source_records,
        ):
            _reject("The retained matched comparator owner is detached.")
    expected = _contribution_dict(
        state.manifest,
        state.row,
        state.collected_projection,
        state.source_records,
        cast(OperationTerminalState, state.projection["terminal_state"]),
    )
    if expected != state.projection:
        _reject("The operation contribution digest is invalid.")
    return expected


def _read_authenticated_operation_meaning_contribution(
    owner: AuthenticatedOperationMeaningContribution,
) -> dict[str, object]:
    return cast(
        dict[str, object],
        strict_json_loads(canonical_json_bytes(_validated_contribution_projection(owner))),
    )


def _issue_authenticated_meaning_cohort_accumulator(
    manifest: AuthenticatedChallengeOperationManifest, /
) -> AuthenticatedMeaningCohortAccumulator:
    _validated_manifest_projection(manifest)
    owner = object.__new__(AuthenticatedMeaningCohortAccumulator)
    _ACCUMULATOR_ISSUER.bind_once(owner, _AccumulatorState(manifest, {}, "OPEN", RLock()))
    return owner


def _accumulator_state(owner: AuthenticatedMeaningCohortAccumulator) -> _AccumulatorState:
    if type(owner) is not AuthenticatedMeaningCohortAccumulator:
        _reject("A genuine meaning cohort accumulator is required.")
    try:
        state = _ACCUMULATOR_STATES.read(owner)
    except OneShotRegistryError as error:
        raise ScenarioCohortEvidenceError(
            "A genuine meaning cohort accumulator is required."
        ) from error
    return state


def _validated_accumulator_state(owner: AuthenticatedMeaningCohortAccumulator) -> _AccumulatorState:
    state = _accumulator_state(owner)
    _validated_manifest_projection(state.manifest)
    expected = {row.operation_id for row in _manifest_state(state.manifest).rows}
    if not set(state.contributions).issubset(expected):
        _reject("The meaning cohort contains an unknown operation.")
    for operation_id, contribution in state.contributions.items():
        if _validated_contribution_projection(contribution).get("operation_id") != operation_id:
            _reject("The meaning cohort contains detached evidence.")
        if _validated_contribution_state(contribution).status != "CONSUMED":
            _reject("The meaning cohort contains unconsumed evidence.")
    return state


def _add_authenticated_operation_meaning_contribution(
    accumulator: AuthenticatedMeaningCohortAccumulator,
    contribution: AuthenticatedOperationMeaningContribution,
    /,
) -> None:
    state = _accumulator_state(accumulator)
    projection = _validated_contribution_projection(contribution)
    contribution_state = _validated_contribution_state(contribution)
    operation_id = cast(str, projection["operation_id"])
    if contribution_state.manifest is not state.manifest:
        _reject("A cross-plan operation contribution was rejected.")
    with state.lock, contribution_state.lock:
        if state.status != "OPEN" or operation_id in state.contributions:
            _reject("A duplicate or sealed operation contribution was rejected.")
        if contribution_state.status != "LIVE":
            _reject("An operation contribution replay was rejected.")
        contribution_state.status = "CONSUMED"
        state.contributions[operation_id] = contribution


def _cohort_projection(
    manifest: AuthenticatedChallengeOperationManifest,
    contributions: tuple[AuthenticatedOperationMeaningContribution, ...],
) -> dict[str, object]:
    manifest_projection = _validated_manifest_projection(manifest)
    rows = tuple(_validated_contribution_projection(owner) for owner in contributions)
    operation_ids = frozen_operation_ids()
    if tuple(row.get("operation_id") for row in rows) != operation_ids:
        _reject("The scenario cohort operation closure is incomplete.")
    if [row.get("operation_plan_entry_sha256") for row in rows] != manifest_projection[
        "ordered_operation_plan_entry_sha256"
    ] or [row.get("case_operation_join_key") for row in rows] != manifest_projection[
        "ordered_case_operation_join_keys"
    ]:
        _reject("The scenario cohort plan-entry closure is detached.")
    return {
        "schema_version": _COHORT_SCHEMA_VERSION,
        "manifest_sha256": manifest_projection["manifest_sha256"],
        "proportional_operation_plan_sha256": manifest_projection[
            "proportional_operation_plan_sha256"
        ],
        "operation_count": len(rows),
        "ordered_operation_ids": list(operation_ids),
        "ordered_operation_plan_entry_sha256": [row["operation_plan_entry_sha256"] for row in rows],
        "ordered_case_operation_join_keys": [row["case_operation_join_key"] for row in rows],
        "ordered_contribution_digests": [row["contribution_sha256"] for row in rows],
        "ordered_collected_operation_evidence_sha256": [
            row["collected_operation_evidence_sha256"] for row in rows
        ],
        "ordered_source_record_digest_sets": [row["ordered_source_record_digests"] for row in rows],
        "terminal_state_ledger": [
            {
                "operation_id": row["operation_id"],
                "case_id": row["case_id"],
                "state": row["terminal_state"],
            }
            for row in rows
        ],
        "cohort_sha256": None,
    }


def _seal_authenticated_scenario_cohort_evidence(
    accumulator: AuthenticatedMeaningCohortAccumulator, /
) -> SealedScenarioCohortEvidence:
    state = _validated_accumulator_state(accumulator)
    expected_ids = tuple(row.operation_id for row in _manifest_state(state.manifest).rows)
    if state.status != "OPEN" or set(state.contributions) != set(expected_ids):
        _reject("All frozen operation contributions are required before sealing.")
    contributions = tuple(state.contributions[operation_id] for operation_id in expected_ids)
    projection = _cohort_projection(state.manifest, contributions)
    projection["cohort_sha256"] = structured_sha256(_COHORT_DOMAIN, projection)
    owner = object.__new__(SealedScenarioCohortEvidence)
    _COHORT_ISSUER.bind_once(
        owner, _CohortState(state.manifest, contributions, canonical_json_bytes(projection))
    )
    state.status = "SEALED"
    _validated_cohort_projection(owner)
    return owner


def _validated_cohort_projection(owner: SealedScenarioCohortEvidence) -> dict[str, object]:
    if type(owner) is not SealedScenarioCohortEvidence:
        _reject("Genuine sealed scenario cohort evidence is required.")
    try:
        state = _COHORT_STATES.read(owner)
    except OneShotRegistryError as error:
        raise ScenarioCohortEvidenceError(
            "Genuine sealed scenario cohort evidence is required."
        ) from error
    retained = strict_json_loads(state.projection_bytes)
    if type(retained) is not dict:
        _reject("The sealed scenario cohort evidence is invalid.")
    projection = cast(dict[str, object], retained)
    expected = _cohort_projection(state.manifest, state.contributions)
    digest = projection.get("cohort_sha256")
    expected["cohort_sha256"] = digest
    preimage = copy.deepcopy(projection)
    preimage["cohort_sha256"] = None
    if (
        projection != expected
        or not _is_digest(digest)
        or structured_sha256(_COHORT_DOMAIN, preimage) != digest
        or canonical_json_bytes(projection) != state.projection_bytes
    ):
        _reject("The sealed scenario cohort evidence is invalid.")
    return projection


def _read_sealed_scenario_cohort_evidence(owner: SealedScenarioCohortEvidence) -> dict[str, object]:
    return cast(
        dict[str, object],
        strict_json_loads(canonical_json_bytes(_validated_cohort_projection(owner))),
    )


def _same_public_source_facts(
    left: _ScenarioSourceOwnerRecord,
    right: _ScenarioSourceOwnerRecord,
) -> bool:
    return (
        left.owner_class == right.owner_class
        and left.owner_schema_ref == right.owner_schema_ref
        and _plain(left.natural_identity) == _plain(right.natural_identity)
        and _plain(left.source_record) == _plain(right.source_record)
        and left.source_record_sha256 == right.source_record_sha256
        and left.ordered_support_owner_sha256 == right.ordered_support_owner_sha256
    )


def _private_graph_value(record: _ScenarioSourceOwnerRecord) -> object | None:
    if record.owner_class != "PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION":
        return None
    try:
        from ebm_audit.evaluator.scenario_derivation_matched_metric import (
            _read_private_projection,
        )

        return _read_private_projection(record.source_capability)[2]
    except Exception:
        try:
            from ebm_audit.evaluator.scenario_derivation_precedence import (
                _projection_record,
            )

            return _projection_record(record).values
        except Exception as error:
            raise ScenarioCohortEvidenceError(
                "A private canonical array value failed authenticated readback."
            ) from error


def _source_operation_id(source: _RetainedGraphSource) -> str | None:
    value = source.record.source_record.get("operation_instance_id")
    if type(value) is str and value in source.operation_ids:
        return value
    join = source.record.source_record.get("case_operation_join_key")
    if isinstance(join, Mapping):
        value = join.get("operation_instance_id")
        if type(value) is str and value in source.operation_ids:
            return value
    return source.operation_ids[0] if source.operation_ids else None


def _cardinality_member_key(
    source: _RetainedGraphSource,
    cardinality: str,
) -> str:
    record = source.record
    operation_id = _source_operation_id(source)
    if cardinality in {"ONE_PER_CASE", "ONE_PER_PLANNED_CASE", "ONE_PER_SUBTYPE_CASE"}:
        return f"case:{source.case_id}"
    if cardinality == "ONE_PER_DECLARED_RULE":
        rule_id = record.natural_identity.get(
            "rule_id", record.natural_identity.get("cardinality_member_id")
        )
        if type(rule_id) is str and rule_id:
            return f"rule:{rule_id}"
    if cardinality == "ALL_PLANNED_OPERATIONS" and operation_id is not None:
        return operation_id
    parts: list[str] = []
    if operation_id is not None:
        parts.extend(operation_id.split("/")[1:])
    for value in (
        record.source_record.get("member_name"),
        record.natural_identity.get("member_id"),
        record.natural_identity.get("chain_execution_id"),
    ):
        if type(value) is str and value and value not in parts:
            parts.append(value)
    if not parts:
        parts.append(source.case_id)
    parts.append(record.source_record_sha256[:12])
    return "/".join(parts)


def _deduplicated_sources(
    sources: tuple[_RetainedGraphSource, ...],
) -> tuple[_RetainedGraphSource, ...]:
    retained: dict[str, _RetainedGraphSource] = {}
    for source in sources:
        digest = _record_source_digest(source.record)
        previous = retained.get(digest)
        if previous is None:
            retained[digest] = source
        elif not _same_public_source_facts(previous.record, source.record):
            _reject("One source digest names divergent retained owner facts.")
    return tuple(retained.values())


def _mcar_source_analysis_spec(
    sources: tuple[_RetainedGraphSource, ...],
    family_id: str,
    primary_case_id: str,
    plan_rows: tuple[_PlanRow, ...],
) -> tuple[_RetainedGraphSource, ...]:
    relevant_rows = tuple(
        row
        for row in plan_rows
        if row.operation_id == _MCAR_ANALYSIS_SPEC_OPERATION_ID
    )
    if len(relevant_rows) != 1:
        _reject("The MCAR source analysis-spec plan row is missing or ambiguous.")
    row = relevant_rows[0]
    join = row.case_operation_join_key
    if (
        family_id != "mcar_missingness"
        or row.family_id != family_id
        or row.member_id != "source_refit"
        or row.case_id != primary_case_id
        or not _is_hex(row.analysis_spec_sha256)
        or not _is_hex(row.operation_plan_entry_sha256)
        or not isinstance(join, Mapping)
        or join.get("case_id") != row.case_id
        or join.get("operation_instance_id") != row.operation_id
        or not _is_digest(join.get("benchmark_subject_digest"))
        or not _is_hex(join.get("authenticated_batch_sha256"))
    ):
        _reject("The MCAR source analysis-spec plan row is detached.")

    expected_id = f"sha256:{row.analysis_spec_sha256}"
    matches: list[_RetainedGraphSource] = []
    for source in sources:
        if (
            source.record.owner_class != "ANALYSIS_SPEC"
            or source.family_id != family_id
            or source.case_id != primary_case_id
        ):
            continue
        try:
            public_id = analysis_spec_content_id(_record_value(source.record))
        except Exception as error:
            raise ScenarioCohortEvidenceError(
                "A same-operation analysis spec failed content-identity validation."
            ) from error
        if not _is_digest(public_id):
            _reject("A same-operation analysis spec has an invalid content identity.")
        if public_id != expected_id:
            continue
        if row.operation_id not in source.operation_ids:
            _reject("A same-operation analysis spec is detached from its MCAR plan row.")
        matches.append(source)
    if len(matches) != 1:
        _reject("One exact MCAR source analysis spec is required.")
    return tuple(matches)


def _slot_sources(
    sources: tuple[_RetainedGraphSource, ...],
    family_id: str,
    primary_case_id: str,
    owner_class: str,
    cardinality: str,
    selector: str,
    plan_rows: tuple[_PlanRow, ...] = (),
) -> tuple[_RetainedGraphSource, ...]:
    if (
        owner_class == "ANALYSIS_SPEC"
        and cardinality == "ONE_PER_CASE"
        and selector == _MCAR_ANALYSIS_SPEC_SELECTOR
    ):
        return _mcar_source_analysis_spec(
            sources,
            family_id,
            primary_case_id,
            plan_rows,
        )
    candidates = tuple(source for source in sources if source.record.owner_class == owner_class)
    global_slot = (
        owner_class == "PROPORTIONAL_OPERATION_PLAN" and cardinality == "EXACTLY_ONE"
    ) or (
        owner_class == "PUBLIC_BATCH_CASE_PLAN"
        and cardinality == "ONE_PER_PLANNED_CASE"
        and selector == "public-batch-case-plan-case-ordinal-order/1"
    ) or (
        owner_class == "PUBLIC_TERMINAL_RESULT"
        and cardinality == "ALL_PLANNED_OPERATIONS"
        and selector == "left-join-case-operation-key-and-entry-hash/1"
    )
    if global_slot:
        return _deduplicated_sources(candidates)
    family_sources = tuple(source for source in candidates if source.family_id == family_id)
    if cardinality in {"ONE_PER_CASE", "EXACTLY_ONE", "ONE_PER_DECLARED_RULE"}:
        primary = tuple(source for source in family_sources if source.case_id == primary_case_id)
        return _deduplicated_sources(primary or family_sources[:1])
    return _deduplicated_sources(family_sources)


def _graph_source_record(
    source: _RetainedGraphSource,
    cardinality: str,
    selector: str,
    orientation: str | None,
) -> ValidatedGraphSourceRecord:
    record = source.record
    return ValidatedGraphSourceRecord(
        owner_class=record.owner_class,
        owner_schema_ref=record.owner_schema_ref,
        cardinality=cardinality,
        selector=selector,
        orientation=orientation,
        natural_identity=cast(Mapping[str, str | int | bool | None], record.natural_identity),
        source_record=record.source_record,
        source_record_sha256=_record_source_digest(record),
        ordered_support_owner_sha256=record.ordered_support_owner_sha256,
        private_value=_private_graph_value(record),
    )


def _family_graph_sources(
    sources: tuple[_RetainedGraphSource, ...],
    family_id: str,
    primary_case_id: str,
    plan_rows: tuple[_PlanRow, ...] = (),
) -> tuple[
    tuple[ValidatedGraphSourceRecord, ...],
    tuple[ValidatedGraphCardinalityDeclaration, ...],
]:
    graph_records: list[ValidatedGraphSourceRecord] = []
    declarations: list[ValidatedGraphCardinalityDeclaration] = []
    selected_payload_sources: list[_RetainedGraphSource] = []
    seen_slots: set[tuple[str, str, str, str | None]] = set()
    for _meaning_id, owner_class, cardinality, selector, orientation in frozen_slot_requirements(
        family_id
    ):
        slot = (owner_class, cardinality, selector, orientation)
        if slot in seen_slots:
            continue
        seen_slots.add(slot)
        selected = _slot_sources(
            sources,
            family_id,
            primary_case_id,
            owner_class,
            cardinality,
            selector,
            plan_rows,
        )
        aliases = tuple(
            _graph_source_record(source, cardinality, selector, orientation)
            for source in selected
        )
        graph_records.extend(aliases)
        if owner_class == "CANONICAL_SCIENTIFIC_PAYLOAD":
            selected_payload_sources.extend(selected)
        if cardinality in {
            "EXACT_MATCHED_SET",
            "ONE_PER_CASE",
            "ONE_PER_PLANNED_CASE",
            "ONE_PER_SUBTYPE_CASE",
            "ONE_PER_DECLARED_RULE",
            "ONE_PER_COMPARATOR_MEMBER",
            "ALL_CASE_ARRAYS",
            "ALL_CASE_WARNINGS",
            "ALL_PLANNED_OPERATIONS",
        } and (aliases or cardinality == "ALL_CASE_WARNINGS"):
            keys = tuple(_cardinality_member_key(source, cardinality) for source in selected)
            if len(keys) != len(set(keys)):
                _reject("A frozen cardinality assignment is ambiguous.")
            declarations.append(
                ValidatedGraphCardinalityDeclaration(
                    owner_class=owner_class,
                    cardinality=cardinality,
                    selector=selector,
                    ordered_member_keys=keys,
                    ordered_source_record_sha256=tuple(
                        record.source_record_sha256 for record in aliases
                    ),
                )
            )
    support_digests = tuple(
        digest
        for record in graph_records
        for digest in record.ordered_support_owner_sha256
    )
    if support_digests:
        aliases_by_digest: dict[str, list[_RetainedGraphSource]] = {}
        for source in sources:
            digest = _record_source_digest(source.record)
            digest_aliases = aliases_by_digest.setdefault(digest, [])
            if digest_aliases and not _same_public_source_facts(
                digest_aliases[0].record,
                source.record,
            ):
                _reject("A graph support digest names divergent owner facts.")
            digest_aliases.append(source)
        support_source_by_digest: dict[str, _RetainedGraphSource] = {}
        for payload_source in selected_payload_sources:
            context_key = (payload_source.family_id, payload_source.case_id)
            for digest in payload_source.record.ordered_support_owner_sha256:
                support_aliases = aliases_by_digest.get(digest)
                if support_aliases is None:
                    _reject("A graph source support edge names an unavailable owner.")
                exact_context = tuple(
                    source
                    for source in support_aliases
                    if (source.family_id, source.case_id) == context_key
                )
                if not exact_context:
                    _reject("A graph source support edge crosses case ownership.")
                support_source = exact_context[0]
                if support_source.record.owner_class not in _SUPPORT_ONLY_OWNER_CLASSES:
                    _reject("A graph source support edge names an unsupported owner class.")
                if support_source.record.ordered_support_owner_sha256:
                    _reject("A support-only owner cannot retain recursive support edges.")
                support_source_by_digest.setdefault(digest, support_source)
        retained_digests = {
            record.source_record_sha256 for record in graph_records
        }
        for digest, support_source in support_source_by_digest.items():
            if digest in retained_digests:
                continue
            graph_records.append(
                _graph_source_record(
                    support_source,
                    _SUPPORT_ONLY_CARDINALITY,
                    _SUPPORT_ONLY_SELECTOR,
                    None,
                )
            )
            retained_digests.add(digest)
    return tuple(graph_records), tuple(declarations)


def _terminal_record_for_row(
    row: _PlanRow,
    records: tuple[_ScenarioSourceOwnerRecord, ...],
) -> _ScenarioSourceOwnerRecord:
    expected_join = canonical_json_bytes(_plain(row.case_operation_join_key))
    matches = tuple(
        record
        for record in records
        if record.owner_class == "PUBLIC_TERMINAL_RESULT"
        and canonical_json_bytes(_plain(record.natural_identity.get("case_operation_join_key")))
        == expected_join
    )
    if len(matches) != 1:
        _reject("One exact public terminal is required per proportional plan row.")
    return matches[0]


def _retained_record_operation_ids(
    record: _ScenarioSourceOwnerRecord,
    records: tuple[_ScenarioSourceOwnerRecord, ...],
    collector_operation_ids: tuple[str, ...],
    plan_rows: tuple[_PlanRow, ...],
    family_id: str,
    case_id: str,
    operation_plan_sha256: str,
) -> tuple[str, ...]:
    """Bind a canonical payload to its exact public terminal and plan row."""

    if record.owner_class != "CANONICAL_SCIENTIFIC_PAYLOAD":
        return collector_operation_ids
    payload_sha256 = structured_sha256_hex(
        _CANONICAL_SCIENTIFIC_PAYLOAD_DOMAIN,
        _plain(record.source_record),
    )
    matched_rows: list[_PlanRow] = []
    for row in plan_rows:
        if row.operation_id not in collector_operation_ids:
            continue
        terminal = _terminal_record_for_row(row, records)
        terminal_source = terminal.source_record
        if terminal_source.get("canonical_scientific_payload_sha256") != payload_sha256:
            continue
        expected_join = canonical_json_bytes(_plain(row.case_operation_join_key))
        if (
            row.family_id != family_id
            or row.case_id != case_id
            or terminal_source.get("operation_instance_id") != row.operation_id
            or terminal_source.get("family_id") != family_id
            or terminal_source.get("case_id") != case_id
            or terminal_source.get("proportional_operation_plan_sha256")
            != operation_plan_sha256
            or terminal_source.get("operation_plan_entry_sha256")
            != row.operation_plan_entry_sha256
            or terminal_source.get("operation_ordinal") != row.ordinal
            or canonical_json_bytes(_plain(terminal_source.get("case_operation_join_key")))
            != expected_join
        ):
            _reject("A canonical payload terminal is detached from its public plan row.")
        matched_rows.append(row)
    if len(matched_rows) != 1:
        _reject("A canonical payload must resolve exactly one public operation terminal.")
    return (matched_rows[0].operation_id,)


def _operation_outcome(
    row: _PlanRow,
    terminal: _ScenarioSourceOwnerRecord,
) -> ValidatedGraphOperationOutcome:
    terminal_state = _terminal_state(terminal)
    state: Literal["SUCCESS", "UNAVAILABLE", "INVALID", "FAILED"]
    failure_code: str | None = None
    if terminal_state == "AVAILABLE":
        state = "SUCCESS"
    elif terminal_state in {"UNAVAILABLE", "NOT_APPLICABLE"}:
        state = "UNAVAILABLE"
    elif terminal_state == "INVALID":
        state = "INVALID"
        failure_code = "EVIDENCE.OWNER_INVALID"
    else:
        state = "FAILED"
        failure_code = "SCIENCE.APPLICABLE_OPERATION_FAILED"
    return ValidatedGraphOperationOutcome(
        operation_id=row.operation_id,
        family_id=row.family_id,
        case_id=row.case_id,
        state=state,
        failure_code=failure_code,
        source_record_sha256=_record_source_digest(terminal),
    )


def _issue_validated_meaning_graphs_from_sealed_cohort(
    sealed: SealedScenarioCohortEvidence,
    /,
) -> tuple[ValidatedMeaningGraph, ...]:
    """Consume one sealed cohort into exact pre-report family graphs once."""

    projection = _validated_cohort_projection(sealed)
    state = _COHORT_STATES.read(sealed)
    manifest_state = _manifest_state(state.manifest)
    _validated_manifest_projection(state.manifest)
    batch = manifest_state.batch
    operation_plan = manifest_state.operation_plan
    plan, plan_rows = _plan_rows(batch, operation_plan)
    if tuple(row.operation_id for row in plan_rows) != frozen_operation_ids():
        _reject("The sealed cohort is detached from the frozen operation order.")
    with _ISSUED_GRAPH_COHORTS_LOCK:
        if _ISSUED_GRAPH_COHORTS.get(sealed) is True:
            _reject("Sealed cohort graph issuance was replayed.")

    collectors: list[_AdmittedCollectorState] = []
    seen_collectors: set[int] = set()
    for contribution in state.contributions:
        _validated_contribution_projection(contribution)
        contribution_state = _validated_contribution_state(contribution)
        if type(contribution_state.source_owner) is not _CollectedOperationEvidence:
            _reject("A sealed cohort contribution lost its admitted collector owner.")
        collected = contribution_state.source_owner
        if id(collected) in seen_collectors:
            continue
        seen_collectors.add(id(collected))
        with _ADMITTED_COLLECTORS_LOCK:
            admitted = _ADMITTED_COLLECTORS.get(collected)
        if (
            admitted is None
            or admitted.batch is not batch
            or admitted.operation_plan is not operation_plan
            or admitted.projection != contribution_state.collected_projection
            or admitted.source_records != contribution_state.source_records
        ):
            _reject("A sealed cohort collector is detached from proportional admission.")
        collectors.append(admitted)

    planned_case_ids = tuple(dict.fromkeys(row.case_id for row in plan_rows))
    by_case = {collector.projection.case_id: collector for collector in collectors}
    if len(by_case) != len(collectors) or tuple(by_case) != planned_case_ids:
        _reject("The sealed cohort case-collector closure is incomplete or reordered.")
    case_plans = tuple(by_case[case_id].case_plan for case_id in planned_case_ids)
    try:
        case_plan_projections = _read_public_batch_case_plan_set(batch, case_plans)
    except Exception as error:
        raise ScenarioCohortEvidenceError(
            "The sealed cohort case-plan set failed authenticated readback."
        ) from error
    if tuple(item.get("case_id") for item in case_plan_projections) != planned_case_ids:
        _reject("The sealed cohort case-plan order is detached from the live plan.")

    with _MATCHED_BY_PLAN_LOCK:
        matched_ref = _MATCHED_BY_PLAN.get(operation_plan)
        matched = matched_ref() if matched_ref is not None else None
    if matched is None:
        _reject("Cohort-issued matched comparator evidence is required before derivation.")
    _read_authenticated_matched_comparator_evidence(matched)
    matched_state = _matched_state(matched)

    operation_plan_sha256 = cast(str, plan["proportional_operation_plan_sha256"])
    retained_sources: list[_RetainedGraphSource] = []
    for collector in collectors:
        for record in collector.source_records:
            retained_sources.append(
                _RetainedGraphSource(
                    record=record,
                    family_id=collector.projection.family_id,
                    case_id=collector.projection.case_id,
                    operation_ids=_retained_record_operation_ids(
                        record,
                        collector.source_records,
                        collector.operation_ids,
                        plan_rows,
                        collector.projection.family_id,
                        collector.projection.case_id,
                        operation_plan_sha256,
                    ),
                )
            )
    for operation_id, record in zip(
        matched_state.operation_ids,
        _read_authenticated_matched_comparator_source_records(matched),
        strict=True,
    ):
        row = next(item for item in plan_rows if item.operation_id == operation_id)
        retained_sources.append(
            _RetainedGraphSource(record, row.family_id, row.case_id, (operation_id,))
        )
    sources = tuple(retained_sources)
    terminals = tuple(
        _terminal_record_for_row(row, by_case[row.case_id].source_records) for row in plan_rows
    )
    outcomes = tuple(
        _operation_outcome(row, terminal)
        for row, terminal in zip(plan_rows, terminals, strict=True)
    )
    valid_case_ids = tuple(
        case_id
        for case_id in planned_case_ids
        if all(
            outcome.state == "SUCCESS"
            for row, outcome in zip(plan_rows, outcomes, strict=True)
            if row.case_id == case_id
        )
    )
    subject = cast(str, plan["benchmark_subject_digest"])
    plan_sha256 = operation_plan_sha256
    graphs: list[ValidatedMeaningGraph] = []
    for family_id in _FAMILY_OPERATION_MEMBERS:
        family_rows = tuple(row for row in plan_rows if row.family_id == family_id)
        if not family_rows:
            _reject("A frozen family is absent from the sealed cohort.")
        primary = family_rows[0]
        graph_sources, declarations = _family_graph_sources(
            sources,
            family_id,
            primary.case_id,
            plan_rows,
        )
        graph = ValidatedMeaningGraph(
            evidence_graph_digest="0" * 64,
            benchmark_subject_digest=subject,
            family_id=family_id,
            case_id=primary.case_id,
            source_contract_sha256=primary.source_contract_sha256,
            scenario_source_sha256=primary.scenario_source_sha256,
            operation_plan_sha256=plan_sha256,
            operation_ids=frozen_operation_ids(),
            planned_case_ids=planned_case_ids,
            valid_case_ids=valid_case_ids,
            capability_mode="FULL",
            declared_model_shape="APPLICABLE",
            operation_outcomes=outcomes,
            source_records=graph_sources,
            cardinality_declarations=declarations,
            report_claims=(),
        )
        try:
            graph = _seal_and_validate_graph(graph)
        except Exception as error:
            raise ScenarioCohortEvidenceError(
                f"The sealed cohort graph for {family_id} failed validation."
            ) from error
        graphs.append(graph)
    result = tuple(graphs)
    if (
        tuple(graph.family_id for graph in result) != tuple(_FAMILY_OPERATION_MEMBERS)
        or len(result) != 23
        or projection.get("operation_count") != 104
    ):
        _reject("The sealed cohort family graph closure is incomplete.")
    with _ISSUED_GRAPH_COHORTS_LOCK:
        if _ISSUED_GRAPH_COHORTS.get(sealed) is True:
            _reject("Sealed cohort graph issuance was replayed.")
        _ISSUED_GRAPH_COHORTS[sealed] = True
    return result


__all__: list[str] = []
