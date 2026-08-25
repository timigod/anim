"""Authenticated pre-report claims derived from validated ordinary evidence."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType
from typing import Final, Literal, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256_hex
from ebm_audit.schema import SchemaValidationError, validate_instance

type ClaimState = Literal["AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED"]
type _ReportTransactionLifecycle = Literal["OPEN", "CONSUMING", "CONSUMED", "FAILED"]

_CLAIM_DOMAIN: Final = "ebm-audit/authenticated-report-claim-projection/1"
_NON_REPORT_RECORD_DOMAIN: Final = "ebm-audit/non-report-meaning-record/1"
_REPORT_PREDICATE_ORDER: Final = (
    "KNOWN_POOR_ORDER_RECOVERY/v1",
    "KNOWN_POOR_STAGE_RECOVERY/v1",
    "KNOWN_POOR_RECOVERY/v1",
    "PRECISE_ORDER_OUTPUT/v1",
    "FORCED_PRECISION/v1",
    "INELIGIBLE_STRONG_LABEL/v1",
    "COVERAGE_LIMITATION_REPORTED/v1",
    "forced-precision-report-predicate/1",
    "coverage-limitation-report-predicate/1",
    "within-pair-precision-report-predicate/1",
    "bad-data-report-predicate/1",
    "correlated-within-pair-report/1",
    "partial-truth-scoring-report/1",
    "exact-duplicate-within-pair-report/1",
    "single-sequence-limitation-report/1",
    "precision-report-predicate/1",
    "block-scoring-report-predicate/1",
    "boundary-attribution-report/1",
    "threshold-selection-report/1",
    "direction-sensitivity-report/1",
    "direction-validity-report/1",
    "null-calibration-report/1",
    "fpr-denominator-report/1",
)
_CLAIM_STATES: Final = frozenset(
    {"AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "INVALID", "FAILED"}
)
_OBSERVE_DIRECTIVE: Final = MappingProxyType(
    {
        "rule_id": "report.claim-observation/1",
        "effect": "OBSERVE",
        "statement_id": "REPORT.CLAIM_OBSERVED",
        "statement_text": None,
        "forbidden_phrases": (),
        "families": (),
    }
)


def _directive(
    rule_id: str,
    effect: Literal["REQUIRE", "FORBID"],
    statement_id: str,
    *,
    families: tuple[str, ...],
    statement_text: str | None = None,
    forbidden_phrases: tuple[str, ...] = (),
) -> Mapping[str, object]:
    return MappingProxyType(
        {
            "rule_id": rule_id,
            "effect": effect,
            "statement_id": statement_id,
            "statement_text": statement_text,
            "forbidden_phrases": forbidden_phrases,
            "families": families,
        }
    )


_DIRECTIVES: dict[str, Mapping[str, object]] = {
    predicate_id: _OBSERVE_DIRECTIVE for predicate_id in _REPORT_PREDICATE_ORDER
}
_DIRECTIVES.update(
    {
        "forced-precision-report-predicate/1": _directive(
            "report.forbid-forced-precision/1",
            "FORBID",
            "REPORT.NO_FORCED_PRECISION",
            families=("small_sample",),
            forbidden_phrases=("precise event order", "exact event order"),
        ),
        "INELIGIBLE_STRONG_LABEL/v1": _directive(
            "report.forbid-ineligible-strong-label/1",
            "FORBID",
            "REPORT.NO_INELIGIBLE_STRONG_LABEL",
            families=(
                "weak_pre_post_separation",
                "label_permutation_null",
                "within_group_feature_permutation_null",
            ),
            forbidden_phrases=("strong evidence", "definitive evidence"),
        ),
        "coverage-limitation-report-predicate/1": _directive(
            "report.require-coverage-limitation/1",
            "REQUIRE",
            "REPORT.COVERAGE_LIMITATION",
            families=("incomplete_time_coverage",),
            statement_text=(
                "Incomplete time coverage limits interpretation of the affected event tail."
            ),
        ),
        "within-pair-precision-report-predicate/1": _directive(
            "report.forbid-within-pair-precision/1",
            "FORBID",
            "REPORT.NO_WITHIN_PAIR_PRECISION",
            families=("tightly_spaced_events",),
            forbidden_phrases=("resolved within-pair order",),
        ),
        "bad-data-report-predicate/1": _directive(
            "report.forbid-bad-data-causation/1",
            "FORBID",
            "REPORT.NO_BAD_DATA_CAUSATION",
            families=("outlier_sabotage",),
            forbidden_phrases=("bad data caused", "wrong data caused"),
        ),
        "correlated-within-pair-report/1": _directive(
            "report.forbid-correlated-within-pair-precision/1",
            "FORBID",
            "REPORT.NO_CORRELATED_WITHIN_PAIR_PRECISION",
            families=("correlated_duplicate_events",),
            forbidden_phrases=("resolved correlated pair order",),
        ),
        "partial-truth-scoring-report/1": _directive(
            "report.require-partial-truth-scoring/1",
            "REQUIRE",
            "REPORT.PARTIAL_TRUTH_SCORING",
            families=("correlated_duplicate_events",),
            statement_text=(
                "Exact duplicates are scored as partial truth without an arbitrary tie-break."
            ),
        ),
        "exact-duplicate-within-pair-report/1": _directive(
            "report.forbid-exact-duplicate-order/1",
            "FORBID",
            "REPORT.NO_EXACT_DUPLICATE_ORDER",
            families=("correlated_duplicate_events",),
            forbidden_phrases=("resolved exact-duplicate order",),
        ),
        "single-sequence-limitation-report/1": _directive(
            "report.require-single-sequence-limitation/1",
            "REQUIRE",
            "REPORT.SINGLE_SEQUENCE_LIMITATION",
            families=("minority_alternate_sequence",),
            statement_text=(
                "A single sequence cannot represent the declared alternate-sequence mixture."
            ),
        ),
        "precision-report-predicate/1": _directive(
            "report.forbid-opposing-precision/1",
            "FORBID",
            "REPORT.NO_OPPOSING_SEQUENCE_PRECISION",
            families=("opposing_sequences_50_50",),
            forbidden_phrases=("precise consensus sequence",),
        ),
        "block-scoring-report-predicate/1": _directive(
            "report.require-block-scoring/1",
            "REQUIRE",
            "REPORT.BLOCK_AWARE_SCORING",
            families=("near_simultaneous_events",),
            statement_text="Near-simultaneous events use block-aware scoring.",
        ),
        "boundary-attribution-report/1": _directive(
            "report.require-boundary-attribution/1",
            "REQUIRE",
            "REPORT.BOUNDARY_ATTRIBUTION",
            families=("group_boundary_sensitivity",),
            statement_text=(
                "Boundary sensitivity is descriptive and is attributed to the declared "
                "grouping rule."
            ),
        ),
        "threshold-selection-report/1": _directive(
            "report.forbid-selected-threshold/1",
            "FORBID",
            "REPORT.NO_SELECTED_THRESHOLD",
            families=("group_boundary_sensitivity",),
            forbidden_phrases=("optimal threshold", "selected threshold"),
        ),
        "direction-sensitivity-report/1": _directive(
            "report.require-direction-sensitivity/1",
            "REQUIRE",
            "REPORT.DIRECTION_SENSITIVITY",
            families=("wrong_event_direction",),
            statement_text="The result is sensitive to the declared event direction.",
        ),
        "direction-validity-report/1": _directive(
            "report.forbid-direction-validity/1",
            "FORBID",
            "REPORT.NO_DIRECTION_VALIDITY_CLAIM",
            families=("wrong_event_direction",),
            forbidden_phrases=("direction is clinically valid", "direction is biologically valid"),
        ),
        "null-calibration-report/1": _directive(
            "report.require-null-calibration/1",
            "REQUIRE",
            "REPORT.NULL_CALIBRATION",
            families=(
                "pure_no_signal",
                "label_permutation_null",
                "within_group_feature_permutation_null",
            ),
            statement_text=(
                "Null calibration is reported as a diagnostic and not as recovered disease order."
            ),
        ),
        "fpr-denominator-report/1": _directive(
            "report.require-null-denominator-exclusion/1",
            "REQUIRE",
            "REPORT.NULL_DENOMINATOR_EXCLUSION",
            families=("label_permutation_null", "within_group_feature_permutation_null"),
            statement_text=(
                "Transformed-null cases are excluded from the pure-no-signal false-positive "
                "denominator."
            ),
        ),
    }
)
REPORT_CLAIM_DIRECTIVES: Final = MappingProxyType(_DIRECTIVES)


class ReportClaimProjectionError(TypeError):
    """Raised when a pre-report claim projection is forged or detached."""


def _reject() -> Never:
    raise ReportClaimProjectionError(
        "Authenticated report claim projection failed closed validation."
    )


@dataclass(frozen=True, slots=True)
class _ClaimProjectionState:
    projection_bytes: bytes
    claim_records_bytes: bytes | None = None
    non_report_records_bytes: bytes | None = None
    sealed_cohort: object | None = None
    batch_owner: object | None = None
    ordered_case_contexts: tuple[object, ...] = ()
    ordered_warning_records: tuple[tuple[str, object], ...] = ()
    ordered_terminal_records: tuple[object, ...] = ()
    cohort_sha256: str | None = None
    evidence_graph_digest: str | None = None
    claim_digest: str | None = None


_CLAIM_PROJECTION_STATES: OneShotWeakRegistry[object, _ClaimProjectionState]
_CLAIM_PROJECTION_STATES, _CLAIM_PROJECTION_ISSUER = create_one_shot_registry()


@dataclass(slots=True)
class _CohortReportTransactionState:
    snapshot_bytes: bytes
    claim_projection: AuthenticatedReportClaimProjection
    sealed_cohort: object
    batch_owner: object
    ordered_case_contexts: tuple[object, ...]
    ordered_warning_records: tuple[tuple[str, object], ...]
    ordered_terminal_records: tuple[object, ...]
    lifecycle: _ReportTransactionLifecycle
    lock: RLock


@dataclass(frozen=True, slots=True)
class _CohortReportTransactionSnapshot:
    claim_projection: AuthenticatedReportClaimProjection
    batch_owner: object
    claim_projection_value: dict[str, object]
    claim_records: tuple[dict[str, object], ...]
    ordered_case_contexts: tuple[dict[str, object], ...]
    genuine_case_contexts: tuple[object, ...]
    ordered_warning_records: tuple[tuple[str, str], ...]
    ordered_terminal_records: tuple[tuple[str, dict[str, object]], ...]
    cohort_sha256: str
    evidence_graph_digest: str
    claim_digest: str
    benchmark_subject_digest: str
    rule_registry_sha256: str


_COHORT_REPORT_TRANSACTION_STATES: OneShotWeakRegistry[
    object, _CohortReportTransactionState
]
(
    _COHORT_REPORT_TRANSACTION_STATES,
    _COHORT_REPORT_TRANSACTION_ISSUER,
) = create_one_shot_registry()


@final
class AuthenticatedReportClaimProjection:
    """Opaque immutable owner of the complete ordered report-claim surface."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> AuthenticatedReportClaimProjection:
        raise TypeError("Report claim projections are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Report claim projections cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Report claim projections are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Report claim projections cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Report claim projections cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Report claim projections cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Report claim projections cannot be copied or serialized.")

    def __repr__(self) -> str:
        _validated_claim_projection(self)
        return "AuthenticatedReportClaimProjection(<opaque>)"

    @property
    def digest(self) -> str:
        projection = _validated_claim_projection(self)
        return cast(
            str,
            projection.get("report_claim_projection_sha256") or projection["projection_sha256"],
        )


@final
class _CohortReportTransaction:
    """Opaque one-use owner of one frozen cohort report snapshot."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _CohortReportTransaction:
        raise TypeError("Cohort report transactions are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Cohort report transactions cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Cohort report transactions are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Cohort report transactions cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Cohort report transactions cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Cohort report transactions cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Cohort report transactions cannot be copied or serialized.")

    def __repr__(self) -> str:
        return "_CohortReportTransaction(<opaque>)"


def _string_list(value: object, *, nonempty: bool = False) -> list[str]:
    if (
        type(value) is not list
        or (nonempty and not value)
        or any(type(item) is not str or not item for item in value)
        or len(value) != len(set(value))
    ):
        _reject()
    return cast(list[str], value)


def _validated_claim_record(value: object, predicate_id: str) -> dict[str, object]:
    if type(value) is not dict:
        _reject()
    record = cast(dict[str, object], value)
    if (
        set(record)
        != {
            "predicate_id",
            "directive",
            "state",
            "value",
            "reason_codes",
            "failure_code",
            "input_record_ids",
            "source_record_digests",
            "operation_ids",
        }
        or record.get("predicate_id") != predicate_id
    ):
        _reject()
    directive = record.get("directive")
    catalog = REPORT_CLAIM_DIRECTIVES[predicate_id]
    expected_directive = {field: catalog[field] for field in ("rule_id", "effect", "statement_id")}
    if directive != expected_directive:
        _reject()
    state = record.get("state")
    if state not in _CLAIM_STATES:
        _reject()
    reason_codes = _string_list(record.get("reason_codes"))
    _string_list(record.get("input_record_ids"))
    source_digests = _string_list(record.get("source_record_digests"))
    _string_list(record.get("operation_ids"))
    if any(
        len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)
        for digest in source_digests
    ):
        _reject()
    if state == "AVAILABLE":
        if (
            type(record.get("value")) is not bool
            or reason_codes
            or record.get("failure_code") is not None
            or not source_digests
        ):
            _reject()
    elif (
        record.get("value") is not None
        or not reason_codes
        or (
            state in {"INVALID", "FAILED"}
            and (type(record.get("failure_code")) is not str or not record["failure_code"])
        )
        or (state in {"UNAVAILABLE", "NOT_APPLICABLE"} and record.get("failure_code") is not None)
    ):
        _reject()
    return copy.deepcopy(record)


def _projection_from_records(
    *, evidence_graph_digest: str, records: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    if (
        type(evidence_graph_digest) is not str
        or len(evidence_graph_digest) != 64
        or any(char not in "0123456789abcdef" for char in evidence_graph_digest)
        or type(records) not in {tuple, list}
        or len(records) != len(_REPORT_PREDICATE_ORDER)
    ):
        _reject()
    normalized = [
        _validated_claim_record(dict(record), predicate_id)
        for record, predicate_id in zip(records, _REPORT_PREDICATE_ORDER, strict=True)
    ]
    preimage: dict[str, object] = {
        "schema_version": "ebm-audit-authenticated-report-claim-projection/1.0",
        "evidence_graph_digest": evidence_graph_digest,
        "records": normalized,
        "projection_sha256": None,
    }
    projection = copy.deepcopy(preimage)
    projection["projection_sha256"] = structured_sha256_hex(_CLAIM_DOMAIN, preimage)
    return projection


def _issue_authenticated_report_claim_projection(
    *, evidence_graph_digest: str, records: Sequence[Mapping[str, object]]
) -> AuthenticatedReportClaimProjection:
    """Issue one projection after its complete record order and shape validate."""

    projection = _projection_from_records(
        evidence_graph_digest=evidence_graph_digest,
        records=records,
    )
    owner = object.__new__(AuthenticatedReportClaimProjection)
    _CLAIM_PROJECTION_ISSUER.bind_once(
        owner,
        _ClaimProjectionState(projection_bytes=canonical_json_bytes(projection)),
    )
    _validated_claim_projection(owner)
    return owner


def _issue_scenario_report_claim_projection(
    *,
    evidence_graph_digest: str,
    family_id: str,
    operation_ids: tuple[str, ...],
    source_records: tuple[object, ...],
) -> AuthenticatedReportClaimProjection:
    """Derive the closed scenario-language claims from authenticated records."""

    from ebm_audit.evaluator.scenario_source_owner_manifest import (
        _ScenarioSourceOwnerRecord,
    )

    if (
        type(family_id) is not str
        or not family_id
        or type(operation_ids) is not tuple
        or not operation_ids
        or any(type(value) is not str or not value for value in operation_ids)
        or len(operation_ids) != len(set(operation_ids))
        or type(source_records) is not tuple
        or not source_records
        or any(type(record) is not _ScenarioSourceOwnerRecord for record in source_records)
    ):
        _reject()
    records = cast(tuple[_ScenarioSourceOwnerRecord, ...], source_records)
    exact_truth = tuple(
        record
        for record in records
        if record.owner_class == "SYNTHETIC_TRUTH"
        and (
            cast(Mapping[str, object], record.source_record["scenario_identity"]).get("family_id")
            if isinstance(record.source_record.get("scenario_identity"), Mapping)
            else None
        )
        == family_id
    )
    source_digests = tuple(record.source_record_sha256 for record in records)
    if (
        not exact_truth
        or len(source_digests) != len(set(source_digests))
        or any(
            len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)
            for digest in source_digests
        )
    ):
        _reject()
    claim_records: list[dict[str, object]] = []
    for predicate_id in _REPORT_PREDICATE_ORDER:
        catalog = REPORT_CLAIM_DIRECTIVES[predicate_id]
        directive = {field: catalog[field] for field in ("rule_id", "effect", "statement_id")}
        if family_id in cast(tuple[str, ...], catalog["families"]):
            effect = cast(str, catalog["effect"])
            claim_records.append(
                {
                    "predicate_id": predicate_id,
                    "directive": directive,
                    "state": "AVAILABLE",
                    "value": effect == "REQUIRE",
                    "reason_codes": [],
                    "failure_code": None,
                    "input_record_ids": list(source_digests),
                    "source_record_digests": list(source_digests),
                    "operation_ids": list(operation_ids),
                }
            )
        else:
            claim_records.append(
                {
                    "predicate_id": predicate_id,
                    "directive": directive,
                    "state": "UNAVAILABLE",
                    "value": None,
                    "reason_codes": ["REPORT.PREDICATE_NOT_REQUIRED_FOR_DECLARED_SCENARIO"],
                    "failure_code": None,
                    "input_record_ids": [],
                    "source_record_digests": [],
                    "operation_ids": list(operation_ids),
                }
            )
    return _issue_authenticated_report_claim_projection(
        evidence_graph_digest=evidence_graph_digest,
        records=claim_records,
    )


@dataclass(frozen=True, slots=True)
class _CohortReportAuthority:
    cohort_projection: Mapping[str, object]
    batch_owner: object
    benchmark_subject_digest: str
    rule_registry_sha256: str
    ordered_case_contexts: tuple[object, ...]
    ordered_warning_records: tuple[tuple[str, object], ...]
    ordered_terminal_records: tuple[object, ...]
    source_record_digests: frozenset[str]


def _cohort_report_authority(
    sealed_cohort: object,
    *,
    expected_cohort_sha256: str | None = None,
) -> _CohortReportAuthority:
    """Recover report-only owners from one complete sealed cohort capability."""

    from ebm_audit.evaluator import scenario_cohort_evidence as cohort_module
    from ebm_audit.evaluator.grouped_meaning_derivations import frozen_operation_ids
    from ebm_audit.evaluator.scenario_case_batch import _read_authenticated_batch_context
    from ebm_audit.evaluator.scenario_source_owner_manifest import (
        _read_authenticated_source_owner_record,
    )

    if type(sealed_cohort) is not cohort_module.SealedScenarioCohortEvidence:
        _reject()
    try:
        projection = cohort_module._read_sealed_scenario_cohort_evidence(sealed_cohort)
        state = cohort_module._COHORT_STATES.read(sealed_cohort)
        manifest_state = cohort_module._MANIFEST_STATES.read(state.manifest)
        batch_context = _read_authenticated_batch_context(manifest_state.batch)
    except (OneShotRegistryError, TypeError, ValueError):
        _reject()
    operation_ids = frozen_operation_ids()
    if (
        projection.get("operation_count") != len(operation_ids)
        or projection.get("ordered_operation_ids") != list(operation_ids)
        or type(projection.get("cohort_sha256")) is not str
        or (
            expected_cohort_sha256 is not None
            and projection["cohort_sha256"] != expected_cohort_sha256
        )
        or type(batch_context.benchmark_subject_digest) is not str
        or not batch_context.benchmark_subject_digest.startswith("sha256:")
        or type(batch_context.report_rule_registry_sha256) is not str
        or len(batch_context.report_rule_registry_sha256) != 64
    ):
        _reject()

    warnings: list[tuple[str, object]] = []
    terminals_by_operation: dict[str, object] = {}
    all_digests: set[str] = set()
    seen_warnings: set[tuple[str, str]] = set()
    for contribution in state.contributions:
        try:
            contribution_state = cohort_module._validated_contribution_state(contribution)
            cohort_module._validated_contribution_projection(contribution)
        except (OneShotRegistryError, TypeError, ValueError):
            _reject()
        if contribution_state.manifest is not state.manifest:
            _reject()
        for record in contribution_state.source_records:
            try:
                source = _read_authenticated_source_owner_record(record)
            except (TypeError, ValueError):
                _reject()
            digest = record.source_record_sha256
            if (
                type(digest) is not str
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                _reject()
            all_digests.add(digest)
            if record.owner_class == "WARNING_RECORD":
                warning_key = (contribution_state.row.case_id, digest)
                if warning_key not in seen_warnings:
                    seen_warnings.add(warning_key)
                    warnings.append((contribution_state.row.case_id, record))
            elif record.owner_class == "PUBLIC_TERMINAL_RESULT":
                operation_id = source.get("operation_instance_id")
                terminal_digest = source.get("public_terminal_result_sha256")
                if (
                    type(operation_id) is not str
                    or operation_id not in operation_ids
                    or type(terminal_digest) is not str
                    or len(terminal_digest) != 64
                ):
                    _reject()
                existing = terminals_by_operation.get(operation_id)
                if existing is not None and existing != record:
                    _reject()
                terminals_by_operation[operation_id] = record
    if set(terminals_by_operation) != set(operation_ids):
        _reject()
    return _CohortReportAuthority(
        cohort_projection=projection,
        batch_owner=manifest_state.batch,
        benchmark_subject_digest=batch_context.benchmark_subject_digest,
        rule_registry_sha256=batch_context.report_rule_registry_sha256,
        ordered_case_contexts=tuple(batch_context.cases),
        ordered_warning_records=tuple(warnings),
        ordered_terminal_records=tuple(terminals_by_operation[item] for item in operation_ids),
        source_record_digests=frozenset(all_digests),
    )


def _non_report_meaning_ids() -> tuple[str, ...]:
    from ebm_audit.evaluator.grouped_meaning_derivations import (
        _FROZEN_SPECS,
        _REPORT_DEPENDENT_MEANINGS,
    )

    result = tuple(
        spec.meaning_id
        for spec in _FROZEN_SPECS
        if spec.meaning_id not in _REPORT_DEPENDENT_MEANINGS
    )
    if len(result) != 80:
        _reject()
    return result


def _meaning_operation_ids(meaning_id: str) -> tuple[str, ...]:
    from ebm_audit.evaluator.grouped_meaning_derivations import frozen_operation_ids

    operations = frozen_operation_ids()
    if meaning_id.startswith("*:"):
        return operations
    family_id = meaning_id.split(":", 1)[0]
    selected = tuple(item for item in operations if item.split("/", 1)[0] == family_id)
    if not selected:
        _reject()
    return selected


def _normalized_non_report_result(value: object, expected_id: str) -> dict[str, object]:
    from ebm_audit.evaluator.grouped_meaning_derivations import GroupedMeaningResult

    if type(value) is not GroupedMeaningResult or value.meaning_id != expected_id:
        _reject()
    state = value.state
    reasons = list(value.reason_codes)
    sources = list(value.source_record_digests)
    if (
        state not in _CLAIM_STATES
        or len(reasons) != len(set(reasons))
        or any(type(reason) is not str or not reason for reason in reasons)
        or len(sources) != len(set(sources))
        or any(
            type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in sources
        )
    ):
        _reject()
    if state == "AVAILABLE":
        if value.value is None or reasons or value.failure_code is not None or not sources:
            _reject()
    elif (
        value.value is not None
        or not reasons
        or (
            state in {"INVALID", "FAILED"}
            and (type(value.failure_code) is not str or not value.failure_code)
        )
        or (state in {"UNAVAILABLE", "NOT_APPLICABLE"} and value.failure_code is not None)
    ):
        _reject()
    preimage: dict[str, object] = {
        "meaning_id": expected_id,
        "operation_ids": list(_meaning_operation_ids(expected_id)),
        "state": state,
        "value": copy.deepcopy(value.value),
        "reason_codes": reasons,
        "failure_code": value.failure_code,
        "source_record_digests": sources,
        "meaning_record_sha256": None,
    }
    record = copy.deepcopy(preimage)
    record["meaning_record_sha256"] = structured_sha256_hex(_NON_REPORT_RECORD_DOMAIN, preimage)
    return record


def _normalize_non_report_results(values: Sequence[object]) -> tuple[dict[str, object], ...]:
    expected = _non_report_meaning_ids()
    if type(values) not in {tuple, list} or len(values) != len(expected):
        _reject()
    return tuple(
        _normalized_non_report_result(value, meaning_id)
        for value, meaning_id in zip(values, expected, strict=True)
    )


def _validate_retained_non_report_records(value: object) -> tuple[dict[str, object], ...]:
    expected = _non_report_meaning_ids()
    if type(value) is not list or len(value) != len(expected):
        _reject()
    records: list[dict[str, object]] = []
    required = {
        "meaning_id",
        "operation_ids",
        "state",
        "value",
        "reason_codes",
        "failure_code",
        "source_record_digests",
        "meaning_record_sha256",
    }
    for raw, meaning_id in zip(value, expected, strict=True):
        if type(raw) is not dict or set(raw) != required or raw.get("meaning_id") != meaning_id:
            _reject()
        record = cast(dict[str, object], raw)
        if record.get("operation_ids") != list(_meaning_operation_ids(meaning_id)):
            _reject()
        preimage = copy.deepcopy(record)
        digest = preimage.pop("meaning_record_sha256", None)
        preimage["meaning_record_sha256"] = None
        if (
            type(digest) is not str
            or structured_sha256_hex(_NON_REPORT_RECORD_DOMAIN, preimage) != digest
        ):
            _reject()
        records.append(copy.deepcopy(record))
    return tuple(records)


def _claim_input_state(records: Sequence[Mapping[str, object]]) -> ClaimState:
    states = tuple(record.get("state") for record in records)
    if not states:
        return "NOT_APPLICABLE"
    if "INVALID" in states:
        return "INVALID"
    if "FAILED" in states:
        return "FAILED"
    if "UNAVAILABLE" in states:
        return "UNAVAILABLE"
    if all(state == "NOT_APPLICABLE" for state in states):
        return "NOT_APPLICABLE"
    if all(state in {"AVAILABLE", "NOT_APPLICABLE"} for state in states):
        return "AVAILABLE"
    _reject()


def _cohort_claim_records(
    non_report_records: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    from ebm_audit.evaluator.grouped_meaning_derivations import (
        _REPORT_PREDICATE_BY_MEANING,
    )

    records_by_family: dict[str, list[Mapping[str, object]]] = {}
    for record in non_report_records:
        family = cast(str, record["meaning_id"]).split(":", 1)[0]
        if family != "*":
            records_by_family.setdefault(family, []).append(record)
    targets_by_predicate: dict[str, list[str]] = {}
    for meaning_id, predicate_id in _REPORT_PREDICATE_BY_MEANING.items():
        targets_by_predicate.setdefault(predicate_id, []).append(meaning_id)

    result: list[dict[str, object]] = []
    for predicate_id in _REPORT_PREDICATE_ORDER:
        directive = REPORT_CLAIM_DIRECTIVES[predicate_id]
        target_ids = targets_by_predicate.get(predicate_id, [])
        families = tuple(dict.fromkeys(item.split(":", 1)[0] for item in target_ids))
        inputs = tuple(
            record for family in families for record in records_by_family.get(family, [])
        )
        state = _claim_input_state(inputs)
        effect = cast(str, directive["effect"])
        if not target_ids or effect == "OBSERVE":
            state = "NOT_APPLICABLE"
        value: bool | None = effect == "REQUIRE" if state == "AVAILABLE" else None
        failure_code: str | None = None
        if state == "INVALID":
            failure_code = "REPORT.PREDICATE_INPUT_INVALID"
        elif state == "FAILED":
            failure_code = "REPORT.PREDICATE_INPUT_FAILED"
        reason_by_state = {
            "UNAVAILABLE": "REPORT.PREDICATE_INPUT_UNAVAILABLE",
            "NOT_APPLICABLE": "REPORT.PREDICATE_NOT_APPLICABLE",
            "INVALID": "REPORT.PREDICATE_INPUT_INVALID",
            "FAILED": "REPORT.PREDICATE_INPUT_FAILED",
        }
        input_ids = [cast(str, record["meaning_record_sha256"]) for record in inputs]
        source_digests = list(
            dict.fromkeys(
                digest
                for record in inputs
                for digest in cast(list[str], record["source_record_digests"])
            )
        )
        operation_ids = list(
            dict.fromkeys(
                operation_id
                for family in families
                for operation_id in _meaning_operation_ids(f"{family}:/placeholder")
            )
        )
        result.append(
            {
                "predicate_id": predicate_id,
                "directive": {
                    field: directive[field] for field in ("rule_id", "effect", "statement_id")
                },
                "state": state,
                "value": value,
                "reason_codes": [] if state == "AVAILABLE" else [reason_by_state[state]],
                "failure_code": failure_code,
                "input_record_ids": input_ids,
                "source_record_digests": source_digests,
                "operation_ids": operation_ids,
            }
        )
    return tuple(
        _validated_claim_record(record, predicate_id)
        for record, predicate_id in zip(result, _REPORT_PREDICATE_ORDER, strict=True)
    )


def _frozen_claim_projection(
    authority: _CohortReportAuthority,
    non_report_records: Sequence[Mapping[str, object]],
    claim_records: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    warning_digests = [
        cast(str, getattr(record, "source_record_sha256", None))
        for _case_id, record in authority.ordered_warning_records
    ]
    terminal_digests = [
        cast(
            str,
            cast(Mapping[str, object], getattr(record, "source_record", {}))[
                "public_terminal_result_sha256"
            ],
        )
        for record in authority.ordered_terminal_records
    ]
    proposed_claim_ids = [
        cast(str, record["predicate_id"]).replace("/", ":")
        for record in claim_records
        if record["state"] == "AVAILABLE" and record["value"] is True
    ]
    preimage: dict[str, object] = {
        "schema_version": "ebm-audit-authenticated-report-claim-projection/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "benchmark_subject_digest": authority.benchmark_subject_digest,
        "rule_registry_sha256": authority.rule_registry_sha256,
        "ordered_non_report_meaning_record_sha256": [
            record["meaning_record_sha256"] for record in non_report_records
        ],
        "ordered_warning_record_sha256": warning_digests,
        "ordered_public_terminal_result_sha256": terminal_digests,
        "ordered_proposed_claim_ids": proposed_claim_ids,
        "report_claim_projection_sha256": None,
    }
    projection = copy.deepcopy(preimage)
    projection["digest_state"] = "PERSISTED"
    projection["report_claim_projection_sha256"] = structured_sha256_hex(_CLAIM_DOMAIN, preimage)
    try:
        validate_instance(
            projection,
            "scenario-evidence.schema.json",
            definition="AuthenticatedReportClaimProjection",
        )
    except SchemaValidationError:
        _reject()
    return projection


@dataclass(frozen=True, slots=True)
class _ConstructedCohortClaim:
    owner: AuthenticatedReportClaimProjection
    projection_bytes: bytes
    claim_records_bytes: bytes
    non_report_records_bytes: bytes
    cohort_sha256: str
    evidence_graph_digest: str
    claim_digest: str


def _case_context_snapshot(value: object) -> dict[str, object]:
    from ebm_audit.evaluator.scenario_case_batch import _AuthenticatedCaseContext

    if type(value) is not _AuthenticatedCaseContext:
        _reject()
    return {
        "family_id": value.family_id,
        "case_id": value.case_id,
        "source_contract_sha256": value.source_contract_sha256,
        "scenario_source_sha256": value.scenario_source_sha256,
        "subtype": value.subtype,
        "boundary_rule_ids": list(value.boundary_rule_ids),
    }


def _warning_record_snapshot(case_id: str, value: object) -> dict[str, object]:
    digest = getattr(value, "source_record_sha256", None)
    if type(case_id) is not str or not case_id or not _is_bare_digest(digest):
        _reject()
    return {"case_id": case_id, "source_record_sha256": digest}


def _terminal_record_snapshot(value: object) -> dict[str, object]:
    digest = getattr(value, "source_record_sha256", None)
    source = getattr(value, "source_record", None)
    if not _is_bare_digest(digest) or not isinstance(source, Mapping):
        _reject()
    try:
        detached_source = strict_json_loads(canonical_json_bytes(dict(source)))
    except (TypeError, ValueError):
        _reject()
    if type(detached_source) is not dict:
        _reject()
    return {
        "source_record_sha256": digest,
        "source_record": detached_source,
    }


def _is_bare_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _construct_cohort_claim(
    sealed_cohort: object,
    non_report_results: Sequence[object],
    authority: _CohortReportAuthority,
) -> _ConstructedCohortClaim:
    """Construct and bind one claim owner without re-reading its authority."""

    records = _normalize_non_report_results(non_report_results)
    if any(
        digest not in authority.source_record_digests
        for record in records
        for digest in cast(list[str], record["source_record_digests"])
    ):
        _reject()
    cohort_sha256 = authority.cohort_projection.get("cohort_sha256")
    if (
        type(cohort_sha256) is not str
        or not cohort_sha256.startswith("sha256:")
        or not _is_bare_digest(cohort_sha256.removeprefix("sha256:"))
    ):
        _reject()
    evidence_graph_digest = cohort_sha256.removeprefix("sha256:")
    claims = _cohort_claim_records(records)
    projection = _frozen_claim_projection(authority, records, claims)
    claim_digest = projection.get("report_claim_projection_sha256")
    if not _is_bare_digest(claim_digest):
        _reject()
    projection_bytes = canonical_json_bytes(projection)
    claim_records_bytes = canonical_json_bytes(list(claims))
    non_report_records_bytes = canonical_json_bytes(list(records))
    owner = object.__new__(AuthenticatedReportClaimProjection)
    _CLAIM_PROJECTION_ISSUER.bind_once(
        owner,
        _ClaimProjectionState(
            projection_bytes=projection_bytes,
            claim_records_bytes=claim_records_bytes,
            non_report_records_bytes=non_report_records_bytes,
            sealed_cohort=sealed_cohort,
            batch_owner=authority.batch_owner,
            ordered_case_contexts=authority.ordered_case_contexts,
            ordered_warning_records=authority.ordered_warning_records,
            ordered_terminal_records=authority.ordered_terminal_records,
            cohort_sha256=cohort_sha256,
            evidence_graph_digest=evidence_graph_digest,
            claim_digest=cast(str, claim_digest),
        ),
    )
    return _ConstructedCohortClaim(
        owner=owner,
        projection_bytes=projection_bytes,
        claim_records_bytes=claim_records_bytes,
        non_report_records_bytes=non_report_records_bytes,
        cohort_sha256=cohort_sha256,
        evidence_graph_digest=evidence_graph_digest,
        claim_digest=cast(str, claim_digest),
    )


def _cohort_report_transaction_bytes(
    constructed: _ConstructedCohortClaim,
    authority: _CohortReportAuthority,
) -> bytes:
    try:
        projection = strict_json_loads(constructed.projection_bytes)
        claim_records = strict_json_loads(constructed.claim_records_bytes)
        non_report_records = strict_json_loads(constructed.non_report_records_bytes)
    except (TypeError, ValueError):
        _reject()
    return canonical_json_bytes(
        {
            "schema_version": "ebm-audit-private-cohort-report-transaction/1.0",
            "cohort_sha256": constructed.cohort_sha256,
            "evidence_graph_digest": constructed.evidence_graph_digest,
            "report_claim_projection_sha256": constructed.claim_digest,
            "claim_projection": projection,
            "claim_records": claim_records,
            "non_report_records": non_report_records,
            "batch": {
                "benchmark_subject_digest": authority.benchmark_subject_digest,
                "report_rule_registry_sha256": authority.rule_registry_sha256,
            },
            "ordered_case_contexts": [
                _case_context_snapshot(value) for value in authority.ordered_case_contexts
            ],
            "ordered_warning_records": [
                _warning_record_snapshot(case_id, value)
                for case_id, value in authority.ordered_warning_records
            ],
            "ordered_terminal_records": [
                _terminal_record_snapshot(value) for value in authority.ordered_terminal_records
            ],
        }
    )


def _issue_cohort_report_transaction(
    sealed_cohort: object,
    non_report_results: Sequence[object],
) -> _CohortReportTransaction:
    """Freeze one trusted report snapshot from exactly one authority pass."""

    authority = _cohort_report_authority(sealed_cohort)
    constructed = _construct_cohort_claim(sealed_cohort, non_report_results, authority)
    transaction = object.__new__(_CohortReportTransaction)
    _COHORT_REPORT_TRANSACTION_ISSUER.bind_once(
        transaction,
        _CohortReportTransactionState(
            snapshot_bytes=_cohort_report_transaction_bytes(constructed, authority),
            claim_projection=constructed.owner,
            sealed_cohort=sealed_cohort,
            batch_owner=authority.batch_owner,
            ordered_case_contexts=authority.ordered_case_contexts,
            ordered_warning_records=authority.ordered_warning_records,
            ordered_terminal_records=authority.ordered_terminal_records,
            lifecycle="OPEN",
            lock=RLock(),
        ),
    )
    return transaction


def _issue_cohort_report_claim_projection(
    sealed_cohort: object,
    non_report_results: Sequence[object],
    *,
    expected_cohort_sha256: str | None = None,
) -> AuthenticatedReportClaimProjection:
    """Issue the sole pre-render projection after exact 80-row closure."""

    authority = _cohort_report_authority(
        sealed_cohort, expected_cohort_sha256=expected_cohort_sha256
    )
    constructed = _construct_cohort_claim(sealed_cohort, non_report_results, authority)
    _validated_claim_projection(constructed.owner)
    return constructed.owner


def _validated_cohort_report_transaction_snapshot(
    state: _CohortReportTransactionState,
) -> _CohortReportTransactionSnapshot:
    """Validate only frozen local bytes and identities; never re-read cohort authority."""

    try:
        payload = strict_json_loads(state.snapshot_bytes)
        claim_state = _CLAIM_PROJECTION_STATES.read(state.claim_projection)
    except (OneShotRegistryError, TypeError, ValueError):
        _reject()
    required = {
        "schema_version",
        "cohort_sha256",
        "evidence_graph_digest",
        "report_claim_projection_sha256",
        "claim_projection",
        "claim_records",
        "non_report_records",
        "batch",
        "ordered_case_contexts",
        "ordered_warning_records",
        "ordered_terminal_records",
    }
    if (
        type(payload) is not dict
        or set(payload) != required
        or payload.get("schema_version")
        != "ebm-audit-private-cohort-report-transaction/1.0"
        or type(claim_state) is not _ClaimProjectionState
        or claim_state.sealed_cohort is not state.sealed_cohort
        or claim_state.batch_owner is not state.batch_owner
        or claim_state.ordered_case_contexts != state.ordered_case_contexts
        or claim_state.ordered_warning_records != state.ordered_warning_records
        or claim_state.ordered_terminal_records != state.ordered_terminal_records
        or claim_state.claim_records_bytes is None
        or claim_state.non_report_records_bytes is None
        or canonical_json_bytes(payload) != state.snapshot_bytes
    ):
        _reject()
    cohort_sha256 = payload.get("cohort_sha256")
    evidence_graph_digest = payload.get("evidence_graph_digest")
    claim_digest = payload.get("report_claim_projection_sha256")
    projection = payload.get("claim_projection")
    raw_claim_records = payload.get("claim_records")
    raw_non_report_records = payload.get("non_report_records")
    batch = payload.get("batch")
    if (
        type(cohort_sha256) is not str
        or not cohort_sha256.startswith("sha256:")
        or not _is_bare_digest(evidence_graph_digest)
        or cohort_sha256.removeprefix("sha256:") != evidence_graph_digest
        or not _is_bare_digest(claim_digest)
        or type(projection) is not dict
        or type(raw_claim_records) is not list
        or type(batch) is not dict
        or set(batch) != {"benchmark_subject_digest", "report_rule_registry_sha256"}
        or type(batch.get("benchmark_subject_digest")) is not str
        or not cast(str, batch["benchmark_subject_digest"]).startswith("sha256:")
        or not _is_bare_digest(batch.get("report_rule_registry_sha256"))
        or claim_state.projection_bytes != canonical_json_bytes(projection)
        or claim_state.claim_records_bytes != canonical_json_bytes(raw_claim_records)
        or claim_state.non_report_records_bytes != canonical_json_bytes(raw_non_report_records)
        or claim_state.cohort_sha256 != cohort_sha256
        or claim_state.evidence_graph_digest != evidence_graph_digest
        or claim_state.claim_digest != claim_digest
    ):
        _reject()
    non_report_records = _validate_retained_non_report_records(raw_non_report_records)
    if len(raw_claim_records) != len(_REPORT_PREDICATE_ORDER):
        _reject()
    claim_records = tuple(
        _validated_claim_record(value, predicate_id)
        for value, predicate_id in zip(
            raw_claim_records, _REPORT_PREDICATE_ORDER, strict=True
        )
    )
    if claim_records != _cohort_claim_records(non_report_records):
        _reject()
    projection_value = cast(dict[str, object], projection)
    preimage = copy.deepcopy(projection_value)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage["report_claim_projection_sha256"] = None
    try:
        validate_instance(
            projection_value,
            "scenario-evidence.schema.json",
            definition="AuthenticatedReportClaimProjection",
        )
    except SchemaValidationError:
        _reject()
    if (
        projection_value.get("report_claim_projection_sha256") != claim_digest
        or structured_sha256_hex(_CLAIM_DOMAIN, preimage) != claim_digest
        or projection_value.get("benchmark_subject_digest")
        != batch["benchmark_subject_digest"]
        or projection_value.get("rule_registry_sha256")
        != batch["report_rule_registry_sha256"]
        or projection_value.get("ordered_non_report_meaning_record_sha256")
        != [value["meaning_record_sha256"] for value in non_report_records]
    ):
        _reject()

    raw_cases = payload.get("ordered_case_contexts")
    raw_warnings = payload.get("ordered_warning_records")
    raw_terminals = payload.get("ordered_terminal_records")
    if (
        type(raw_cases) is not list
        or type(raw_warnings) is not list
        or type(raw_terminals) is not list
        or raw_cases
        != [_case_context_snapshot(value) for value in state.ordered_case_contexts]
        or raw_warnings
        != [
            _warning_record_snapshot(case_id, value)
            for case_id, value in state.ordered_warning_records
        ]
        or raw_terminals
        != [_terminal_record_snapshot(value) for value in state.ordered_terminal_records]
    ):
        _reject()
    warning_snapshots: list[tuple[str, str]] = []
    for value in raw_warnings:
        if (
            type(value) is not dict
            or set(value) != {"case_id", "source_record_sha256"}
            or type(value.get("case_id")) is not str
            or not _is_bare_digest(value.get("source_record_sha256"))
        ):
            _reject()
        warning_snapshots.append(
            (cast(str, value["case_id"]), cast(str, value["source_record_sha256"]))
        )
    terminal_snapshots: list[tuple[str, dict[str, object]]] = []
    for value in raw_terminals:
        if (
            type(value) is not dict
            or set(value) != {"source_record_sha256", "source_record"}
            or not _is_bare_digest(value.get("source_record_sha256"))
            or type(value.get("source_record")) is not dict
        ):
            _reject()
        terminal_snapshots.append(
            (
                cast(str, value["source_record_sha256"]),
                copy.deepcopy(cast(dict[str, object], value["source_record"])),
            )
        )
    if (
        projection_value.get("ordered_warning_record_sha256")
        != [digest for _case_id, digest in warning_snapshots]
        or projection_value.get("ordered_public_terminal_result_sha256")
        != [source.get("public_terminal_result_sha256") for _digest, source in terminal_snapshots]
    ):
        _reject()
    return _CohortReportTransactionSnapshot(
        claim_projection=state.claim_projection,
        batch_owner=state.batch_owner,
        claim_projection_value=copy.deepcopy(projection_value),
        claim_records=claim_records,
        ordered_case_contexts=tuple(copy.deepcopy(raw_cases)),
        genuine_case_contexts=state.ordered_case_contexts,
        ordered_warning_records=tuple(warning_snapshots),
        ordered_terminal_records=tuple(terminal_snapshots),
        cohort_sha256=cohort_sha256,
        evidence_graph_digest=cast(str, evidence_graph_digest),
        claim_digest=cast(str, claim_digest),
        benchmark_subject_digest=cast(str, batch["benchmark_subject_digest"]),
        rule_registry_sha256=cast(str, batch["report_rule_registry_sha256"]),
    )


def _begin_cohort_report_transaction(
    transaction: _CohortReportTransaction,
) -> _CohortReportTransactionSnapshot:
    if type(transaction) is not _CohortReportTransaction:
        _reject()
    try:
        state = _COHORT_REPORT_TRANSACTION_STATES.read(transaction)
    except OneShotRegistryError:
        _reject()
    if type(state) is not _CohortReportTransactionState:
        _reject()
    with state.lock:
        if state.lifecycle != "OPEN":
            _reject()
        state.lifecycle = "CONSUMING"
    try:
        return _validated_cohort_report_transaction_snapshot(state)
    except BaseException:
        with state.lock:
            state.lifecycle = "FAILED"
        raise


def _complete_cohort_report_transaction(transaction: _CohortReportTransaction) -> None:
    try:
        state = _COHORT_REPORT_TRANSACTION_STATES.read(transaction)
    except OneShotRegistryError:
        _reject()
    if type(state) is not _CohortReportTransactionState:
        _reject()
    with state.lock:
        if state.lifecycle != "CONSUMING":
            state.lifecycle = "FAILED"
            _reject()
        state.lifecycle = "CONSUMED"


def _fail_cohort_report_transaction(transaction: _CohortReportTransaction) -> None:
    try:
        state = _COHORT_REPORT_TRANSACTION_STATES.read(transaction)
    except OneShotRegistryError:
        _reject()
    if type(state) is not _CohortReportTransactionState:
        _reject()
    with state.lock:
        if state.lifecycle != "CONSUMED":
            state.lifecycle = "FAILED"


def _read_consumed_cohort_report_transaction(
    transaction: _CohortReportTransaction,
) -> tuple[AuthenticatedReportClaimProjection, str, str, str]:
    """Return only immutable binding identities after one successful consumption."""

    if type(transaction) is not _CohortReportTransaction:
        _reject()
    try:
        state = _COHORT_REPORT_TRANSACTION_STATES.read(transaction)
    except OneShotRegistryError:
        _reject()
    if type(state) is not _CohortReportTransactionState:
        _reject()
    with state.lock:
        if state.lifecycle != "CONSUMED":
            _reject()
    try:
        snapshot = _validated_cohort_report_transaction_snapshot(state)
    except BaseException:
        with state.lock:
            state.lifecycle = "FAILED"
        raise
    return (
        snapshot.claim_projection,
        snapshot.cohort_sha256,
        snapshot.evidence_graph_digest,
        snapshot.claim_digest,
    )


def _validated_claim_projection(
    owner: AuthenticatedReportClaimProjection,
) -> dict[str, object]:
    if type(owner) is not AuthenticatedReportClaimProjection:
        _reject()
    try:
        state = _CLAIM_PROJECTION_STATES.read(owner)
        value = strict_json_loads(state.projection_bytes)
    except (OneShotRegistryError, TypeError, ValueError):
        _reject()
    if type(state) is not _ClaimProjectionState or type(value) is not dict:
        _reject()
    projection = cast(dict[str, object], value)
    if state.sealed_cohort is not None:
        if (
            state.non_report_records_bytes is None
            or state.claim_records_bytes is None
            or state.batch_owner is None
        ):
            _reject()
        try:
            retained_records = strict_json_loads(state.non_report_records_bytes)
            retained_claims = strict_json_loads(state.claim_records_bytes)
        except (TypeError, ValueError):
            _reject()
        records = _validate_retained_non_report_records(retained_records)
        if type(retained_claims) is not list or len(retained_claims) != len(
            _REPORT_PREDICATE_ORDER
        ):
            _reject()
        claims = tuple(
            _validated_claim_record(record, predicate_id)
            for record, predicate_id in zip(retained_claims, _REPORT_PREDICATE_ORDER, strict=True)
        )
        if claims != _cohort_claim_records(records):
            _reject()
        authority = _cohort_report_authority(state.sealed_cohort)
        cohort_sha256 = authority.cohort_projection.get("cohort_sha256")
        claim_digest = projection.get("report_claim_projection_sha256")
        if (
            authority.batch_owner is not state.batch_owner
            or authority.ordered_case_contexts != state.ordered_case_contexts
            or authority.ordered_warning_records != state.ordered_warning_records
            or authority.ordered_terminal_records != state.ordered_terminal_records
            or type(cohort_sha256) is not str
            or not cohort_sha256.startswith("sha256:")
            or state.cohort_sha256 != cohort_sha256
            or state.evidence_graph_digest != cohort_sha256.removeprefix("sha256:")
            or state.claim_digest != claim_digest
            or any(
                digest not in authority.source_record_digests
                for record in records
                for digest in cast(list[str], record["source_record_digests"])
            )
        ):
            _reject()
        expected = _frozen_claim_projection(authority, records, claims)
        if projection != expected or canonical_json_bytes(projection) != state.projection_bytes:
            _reject()
        _CLAIM_PROJECTION_STATES.require(owner, state)
        return projection
    legacy_records = projection.get("records")
    if type(legacy_records) is not list:
        _reject()
    expected = _projection_from_records(
        evidence_graph_digest=cast(str, projection.get("evidence_graph_digest")),
        records=cast(list[Mapping[str, object]], legacy_records),
    )
    if projection != expected or canonical_json_bytes(projection) != state.projection_bytes:
        _reject()
    _CLAIM_PROJECTION_STATES.require(owner, state)
    return projection


def _read_authenticated_report_claim_records(
    owner: AuthenticatedReportClaimProjection,
) -> tuple[dict[str, object], ...]:
    """Return the exact retained claim records after projection revalidation."""

    projection = _validated_claim_projection(owner)
    state = _CLAIM_PROJECTION_STATES.read(owner)
    if state.claim_records_bytes is None:
        value = projection.get("records")
    else:
        value = strict_json_loads(state.claim_records_bytes)
    if type(value) is not list or len(value) != len(_REPORT_PREDICATE_ORDER):
        _reject()
    return tuple(
        _validated_claim_record(record, predicate_id)
        for record, predicate_id in zip(value, _REPORT_PREDICATE_ORDER, strict=True)
    )


def _read_cohort_report_claim_authority(
    owner: AuthenticatedReportClaimProjection,
) -> tuple[
    object,
    tuple[object, ...],
    tuple[tuple[str, object], ...],
    tuple[object, ...],
]:
    """Return retained cohort-only report inputs after complete revalidation."""

    _validated_claim_projection(owner)
    state = _CLAIM_PROJECTION_STATES.read(owner)
    if state.sealed_cohort is None or state.batch_owner is None:
        _reject()
    return (
        state.batch_owner,
        state.ordered_case_contexts,
        state.ordered_warning_records,
        state.ordered_terminal_records,
    )


def _read_cohort_report_evidence_graph_digest(
    owner: AuthenticatedReportClaimProjection,
) -> str:
    """Return the sealed cohort digest as the report graph identity."""

    _validated_claim_projection(owner)
    state = _CLAIM_PROJECTION_STATES.read(owner)
    if state.sealed_cohort is None or not _is_bare_digest(state.evidence_graph_digest):
        _reject()
    return cast(str, state.evidence_graph_digest)


def read_authenticated_report_claim_projection(
    owner: AuthenticatedReportClaimProjection,
) -> dict[str, object]:
    """Return a detached canonical projection after complete revalidation."""

    return cast(
        dict[str, object],
        strict_json_loads(canonical_json_bytes(_validated_claim_projection(owner))),
    )


__all__ = [
    "AuthenticatedReportClaimProjection",
    "ClaimState",
    "ReportClaimProjectionError",
    "read_authenticated_report_claim_projection",
]
