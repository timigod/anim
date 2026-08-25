"""Opaque report-predicate outcomes joined to one authenticated scenario case."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.evaluator.grouped_meaning_derivations import (
    _REPORT_PREDICATE_BY_MEANING,
)
from ebm_audit.evaluator.report_claim_projection import (
    REPORT_CLAIM_DIRECTIVES,
    AuthenticatedReportClaimProjection,
    ReportClaimProjectionError,
    _begin_cohort_report_transaction,
    _CohortReportTransaction,
    _complete_cohort_report_transaction,
    _fail_cohort_report_transaction,
    _read_authenticated_report_claim_records,
    _read_cohort_report_claim_authority,
    _read_cohort_report_evidence_graph_digest,
    read_authenticated_report_claim_projection,
)
from ebm_audit.evaluator.scenario_case_batch import (
    AuthenticatedScenarioCaseBatch,
    _AuthenticatedCaseContext,
    _read_authenticated_batch_context,
)
from ebm_audit.evaluator.scenario_evidence import (
    ScenarioEvidenceContextError,
    _AuthenticatedScenarioEvidenceContext,
    _read_authenticated_scenario_case,
    _read_scenario_evidence_graph_digest,
)
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256_hex,
)
from ebm_audit.schema import SchemaValidationError, validate_instance

_OUTCOME_DOMAIN: Final = "ebm-audit/report-predicate-outcome/1"
_SOURCE_RECORD_DOMAIN: Final = "ebm-audit/scenario-source-record/1"
_WARNING_LEDGER_DOMAIN: Final = "ebm-audit/report-warning-ledger/2"
_TERMINAL_VISIBILITY_DOMAIN: Final = "ebm-audit/report-terminal-visibility/2"
_NOT_ASSESSABLE_REASON: Final = "REPORT.PREDICATE_MACHINE_EVIDENCE_UNAVAILABLE"
_FORBIDDEN_REASON: Final = "REPORT.PREDICATE_FORBIDDEN_CONDITION_PRESENT"
_REQUIRED_REASON: Final = "REPORT.PREDICATE_REQUIRED_CONDITION_ABSENT"
_Cardinality = Literal["ONE_PER_CASE", "ONE_PER_SUBTYPE_CASE", "ONE_PER_DECLARED_RULE"]
_Subtype = Literal["CORRELATED", "EXACT_DUPLICATE_POST_NOISE"]
_PredicateKind = Literal["FORBIDDEN_TRUE", "REQUIRED_TRUE"]


class ReportPredicateOutcomeError(TypeError):
    """Raised when report outcome authority is absent, detached, or inconsistent."""


def _reject() -> Never:
    raise ReportPredicateOutcomeError(
        "Authenticated report predicate outcome evidence failed closed validation."
    )


@dataclass(frozen=True, slots=True)
class _SelectorPolicy:
    family_id: str
    output_path: str
    predicate_id: str
    cardinality: _Cardinality
    kind: _PredicateKind
    subtype: _Subtype | None = None
    report_record_predicate_id: str | None = None


_SELECTOR_POLICY: Final = (
    _SelectorPolicy(
        "small_sample",
        "/payload/forced_precision_flags",
        "forced-precision-report-predicate/1",
        "ONE_PER_CASE",
        "FORBIDDEN_TRUE",
    ),
    _SelectorPolicy(
        "weak_pre_post_separation",
        "/payload/ineligible_strong_flags",
        "same-case-rendered-strong-label/1",
        "ONE_PER_CASE",
        "FORBIDDEN_TRUE",
        report_record_predicate_id="INELIGIBLE_STRONG_LABEL/v1",
    ),
    _SelectorPolicy(
        "incomplete_time_coverage",
        "/payload/coverage_limitation_reported",
        "coverage-limitation-report-predicate/1",
        "ONE_PER_CASE",
        "REQUIRED_TRUE",
    ),
    _SelectorPolicy(
        "tightly_spaced_events",
        "/payload/arbitrary_within_pair_truth_claims",
        "within-pair-precision-report-predicate/1",
        "ONE_PER_CASE",
        "FORBIDDEN_TRUE",
    ),
    _SelectorPolicy(
        "outlier_sabotage",
        "/payload/bad_or_wrong_data_claim_flags",
        "bad-data-report-predicate/1",
        "ONE_PER_CASE",
        "FORBIDDEN_TRUE",
    ),
    _SelectorPolicy(
        "correlated_duplicate_events",
        "/payload/correlated/arbitrary_within_pair_truth_claims",
        "correlated-within-pair-report/1",
        "ONE_PER_SUBTYPE_CASE",
        "FORBIDDEN_TRUE",
        "CORRELATED",
    ),
    _SelectorPolicy(
        "correlated_duplicate_events",
        "/payload/exact_duplicate_post_noise/partial_truth_scored_without_tiebreak",
        "partial-truth-scoring-report/1",
        "ONE_PER_SUBTYPE_CASE",
        "REQUIRED_TRUE",
        "EXACT_DUPLICATE_POST_NOISE",
    ),
    _SelectorPolicy(
        "correlated_duplicate_events",
        "/payload/exact_duplicate_post_noise/arbitrary_within_pair_truth_claims",
        "exact-duplicate-within-pair-report/1",
        "ONE_PER_SUBTYPE_CASE",
        "FORBIDDEN_TRUE",
        "EXACT_DUPLICATE_POST_NOISE",
    ),
    _SelectorPolicy(
        "minority_alternate_sequence",
        "/payload/single_sequence_limitation_reported",
        "single-sequence-limitation-report/1",
        "ONE_PER_CASE",
        "REQUIRED_TRUE",
    ),
    _SelectorPolicy(
        "opposing_sequences_50_50",
        "/payload/internally_concentrated_flags",
        "precision-report-predicate/1",
        "ONE_PER_CASE",
        "FORBIDDEN_TRUE",
    ),
    _SelectorPolicy(
        "near_simultaneous_events",
        "/payload/block_aware_scoring",
        "block-scoring-report-predicate/1",
        "ONE_PER_CASE",
        "REQUIRED_TRUE",
    ),
    _SelectorPolicy(
        "group_boundary_sensitivity",
        "/payload/decision_attribution",
        "boundary-attribution-report/1",
        "ONE_PER_DECLARED_RULE",
        "REQUIRED_TRUE",
    ),
    _SelectorPolicy(
        "group_boundary_sensitivity",
        "/payload/selected_threshold_flags",
        "threshold-selection-report/1",
        "ONE_PER_DECLARED_RULE",
        "FORBIDDEN_TRUE",
    ),
    _SelectorPolicy(
        "wrong_event_direction",
        "/payload/direction_sensitivity_reported",
        "direction-sensitivity-report/1",
        "ONE_PER_CASE",
        "REQUIRED_TRUE",
    ),
    _SelectorPolicy(
        "wrong_event_direction",
        "/payload/direction_validity_claims",
        "direction-validity-report/1",
        "ONE_PER_CASE",
        "FORBIDDEN_TRUE",
    ),
    _SelectorPolicy(
        "pure_no_signal",
        "/payload/fpr_evidence",
        "null-calibration-report/1",
        "ONE_PER_CASE",
        "REQUIRED_TRUE",
    ),
    _SelectorPolicy(
        "label_permutation_null",
        "/payload/calibration_diagnostic_reported",
        "null-calibration-report/1",
        "ONE_PER_CASE",
        "REQUIRED_TRUE",
    ),
    _SelectorPolicy(
        "label_permutation_null",
        "/payload/ineligible_strong_flags",
        "same-case-rendered-strong-label/1",
        "ONE_PER_CASE",
        "FORBIDDEN_TRUE",
        report_record_predicate_id="INELIGIBLE_STRONG_LABEL/v1",
    ),
    _SelectorPolicy(
        "within_group_feature_permutation_null",
        "/payload/calibration_diagnostic_reported",
        "null-calibration-report/1",
        "ONE_PER_CASE",
        "REQUIRED_TRUE",
    ),
    _SelectorPolicy(
        "within_group_feature_permutation_null",
        "/payload/ineligible_strong_flags",
        "same-case-rendered-strong-label/1",
        "ONE_PER_CASE",
        "FORBIDDEN_TRUE",
        report_record_predicate_id="INELIGIBLE_STRONG_LABEL/v1",
    ),
)

_SELECTOR_POLICY_BY_MEANING: Final = {
    f"{policy.family_id}:{policy.output_path}": (
        policy.report_record_predicate_id or policy.predicate_id
    )
    for policy in _SELECTOR_POLICY
}
if (
    len(_SELECTOR_POLICY_BY_MEANING) != len(_SELECTOR_POLICY)
    or _SELECTOR_POLICY_BY_MEANING != _REPORT_PREDICATE_BY_MEANING
):
    raise RuntimeError("Report selector policy does not match the frozen meaning map.")


def _selector_policy_projection() -> tuple[dict[str, object], ...]:
    """Return the closed policy fields checked against the source registry in tests."""

    return tuple(
        {
            "family_id": policy.family_id,
            "output_path": policy.output_path,
            "predicate_id": policy.predicate_id,
            "cardinality": policy.cardinality,
            "subtype": policy.subtype,
        }
        for policy in _SELECTOR_POLICY
    )


@dataclass(frozen=True, slots=True)
class _OutcomeState:
    projection_bytes: bytes
    claim_projection: AuthenticatedReportClaimProjection
    batch_owner: AuthenticatedScenarioCaseBatch
    case: _AuthenticatedCaseContext
    context: _AuthenticatedScenarioEvidenceContext | None = None


_OUTCOME_STATES: OneShotWeakRegistry[object, _OutcomeState]
_OUTCOME_STATES, _OUTCOME_ISSUER = create_one_shot_registry()


@final
class ReportPredicateOutcome:
    """Immutable one-shot owner of one corrected report predicate identity."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ReportPredicateOutcome:
        raise TypeError("Report predicate outcomes are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Report predicate outcomes cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Report predicate outcomes are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Report predicate outcomes cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Report predicate outcomes cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Report predicate outcomes cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Report predicate outcomes cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Report predicate outcomes cannot be copied or serialized.")

    def __repr__(self) -> str:
        return "ReportPredicateOutcome(<opaque>)"

    @property
    def digest(self) -> str:
        return cast(str, _validated_outcome_projection(self)["report_predicate_outcome_sha256"])

    @property
    def identity(self) -> dict[str, str]:
        projection = _validated_outcome_projection(self)
        return {
            "benchmark_subject_digest": cast(str, projection["benchmark_subject_digest"]),
            "family_id": cast(str, projection["family_id"]),
            "predicate_id": cast(str, projection["predicate_id"]),
            "cardinality_member_id": cast(str, projection["cardinality_member_id"]),
            "report_claim_projection_sha256": cast(
                str, projection["report_claim_projection_sha256"]
            ),
        }


def _policies_for(case: _AuthenticatedCaseContext) -> tuple[_SelectorPolicy, ...]:
    policies = tuple(
        policy
        for policy in _SELECTOR_POLICY
        if policy.family_id == case.family_id
        and (policy.subtype is None or policy.subtype == case.subtype)
    )
    if case.family_id == "correlated_duplicate_events" and case.subtype is None:
        _reject()
    return policies


def _cardinality_members(
    policy: _SelectorPolicy,
    case: _AuthenticatedCaseContext,
) -> tuple[str, ...]:
    if policy.cardinality in {"ONE_PER_CASE", "ONE_PER_SUBTYPE_CASE"}:
        return (case.case_id,)
    if policy.cardinality == "ONE_PER_DECLARED_RULE" and case.boundary_rule_ids:
        return case.boundary_rule_ids
    _reject()


def _report_predicate_record(
    claim_records: tuple[dict[str, object], ...],
    policy: _SelectorPolicy,
) -> dict[str, object]:
    """Select one exact authenticated pre-report claim record."""

    report_record_predicate_id = policy.report_record_predicate_id or policy.predicate_id
    matches = tuple(
        record
        for record in claim_records
        if record.get("predicate_id") == report_record_predicate_id
    )
    if len(matches) != 1:
        _reject()
    record = matches[0]
    required = {
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
    state = record.get("state")
    value = record.get("value")
    reason_codes = record.get("reason_codes")
    input_record_ids = record.get("input_record_ids")
    directive = record.get("directive")
    expected_directive = REPORT_CLAIM_DIRECTIVES.get(report_record_predicate_id)
    if (
        set(record) != required
        or record.get("predicate_id") != report_record_predicate_id
        or type(directive) is not dict
        or expected_directive is None
        or directive
        != {field: expected_directive[field] for field in ("rule_id", "effect", "statement_id")}
        or type(reason_codes) is not list
        or any(type(reason) is not str for reason in reason_codes)
        or len(reason_codes) != len(set(reason_codes))
        or type(input_record_ids) is not list
        or any(type(record_id) is not str or not record_id for record_id in input_record_ids)
        or len(input_record_ids) != len(set(input_record_ids))
    ):
        _reject()
    if state == "AVAILABLE":
        if type(value) is not bool or reason_codes or record.get("failure_code") is not None:
            _reject()
    elif state in {"UNAVAILABLE", "NOT_APPLICABLE"}:
        if value is not None or not reason_codes or record.get("failure_code") is not None:
            _reject()
    elif state in {"INVALID", "FAILED"}:
        if (
            value is not None
            or not reason_codes
            or type(record.get("failure_code")) is not str
            or not record["failure_code"]
        ):
            _reject()
    else:
        _reject()
    return record


def _derived_outcome_fields(
    record: dict[str, object],
    policy: _SelectorPolicy,
) -> tuple[str, list[str], int, list[str]]:
    """Apply only frozen selector polarity to one report-owned boolean."""

    if record["state"] in {"UNAVAILABLE", "NOT_APPLICABLE"}:
        return "NOT_ASSESSABLE", [], 0, cast(list[str], record["reason_codes"])
    if record["state"] in {"INVALID", "FAILED"}:
        failure_code = cast(str, record["failure_code"])
        reason_codes = list(
            dict.fromkeys((failure_code, *cast(list[str], record["reason_codes"])))
        )
        return (
            "FAIL",
            [],
            0,
            reason_codes,
        )
    value = record["value"]
    if type(value) is not bool:
        _reject()
    matching_claim_ids = [cast(str, record["predicate_id"]).replace("/", ":")] if value else []
    if policy.kind == "FORBIDDEN_TRUE":
        if value:
            return "FAIL", matching_claim_ids, 1, [_FORBIDDEN_REASON]
        return "PASS", [], 0, []
    if value:
        return "PASS", matching_claim_ids, 0, []
    return "FAIL", [], 0, [_REQUIRED_REASON]


def _outcome_projection(
    *,
    batch_owner: AuthenticatedScenarioCaseBatch,
    case: _AuthenticatedCaseContext,
    claim_owner: AuthenticatedReportClaimProjection,
    policy: _SelectorPolicy,
    cardinality_member_id: str,
) -> dict[str, object]:
    batch = _read_authenticated_batch_context(batch_owner)
    claims = read_authenticated_report_claim_projection(claim_owner)
    claim_records = _read_authenticated_report_claim_records(claim_owner)
    claim_schema_version = claims.get("schema_version")
    cohort_projection = "report_claim_projection_sha256" in claims
    evidence_graph_digest: object
    claim_digest: object
    if type(claim_schema_version) is not str or not claim_schema_version:
        _reject()
    if cohort_projection:
        evidence_graph_digest = _read_cohort_report_evidence_graph_digest(claim_owner)
        claim_digest = claims.get("report_claim_projection_sha256")
        if (
            claims.get("benchmark_subject_digest") != batch.benchmark_subject_digest
            or claims.get("rule_registry_sha256") != batch.report_rule_registry_sha256
        ):
            _reject()
    else:
        evidence_graph_digest = claims.get("evidence_graph_digest")
        claim_digest = claims.get("projection_sha256")
    if type(evidence_graph_digest) is not str or type(claim_digest) is not str:
        _reject()
    return _outcome_projection_from_snapshot(
        case=case,
        policy=policy,
        cardinality_member_id=cardinality_member_id,
        claim_records=claim_records,
        claim_schema_version=claim_schema_version,
        evidence_graph_digest=evidence_graph_digest,
        claim_digest=claim_digest,
        benchmark_subject_digest=batch.benchmark_subject_digest,
        rule_registry_sha256=batch.report_rule_registry_sha256,
    )


def _outcome_projection_from_snapshot(
    *,
    case: _AuthenticatedCaseContext,
    policy: _SelectorPolicy,
    cardinality_member_id: str,
    claim_records: tuple[dict[str, object], ...],
    claim_schema_version: str,
    evidence_graph_digest: str,
    claim_digest: str,
    benchmark_subject_digest: str,
    rule_registry_sha256: str,
) -> dict[str, object]:
    """Derive one outcome from already-frozen transaction values."""

    if (
        type(case) is not _AuthenticatedCaseContext
        or type(policy) is not _SelectorPolicy
        or type(cardinality_member_id) is not str
        or not cardinality_member_id
        or type(claim_schema_version) is not str
        or not claim_schema_version
        or type(evidence_graph_digest) is not str
        or type(claim_digest) is not str
        or type(benchmark_subject_digest) is not str
        or type(rule_registry_sha256) is not str
    ):
        _reject()
    predicate_record = _report_predicate_record(claim_records, policy)
    derived_state, matching_claim_ids, forbidden_claim_count, reason_codes = (
        _derived_outcome_fields(predicate_record, policy)
    )
    return {
        "schema_version": "ebm-audit-report-predicate-outcome/1.0",
        "digest_state": "PERSISTED",
        "evidence_graph_digest": evidence_graph_digest,
        "benchmark_subject_digest": benchmark_subject_digest,
        "family_id": case.family_id,
        "predicate_id": policy.predicate_id,
        "cardinality_member_id": cardinality_member_id,
        "report_claim_projection_sha256": claim_digest,
        "report_claim_projection_schema_version": claim_schema_version,
        "report_rule_registry_sha256": rule_registry_sha256,
        "ordered_case_ids": [case.case_id],
        "derived_state": derived_state,
        "matching_claim_ids": matching_claim_ids,
        "forbidden_claim_count": forbidden_claim_count,
        "reason_codes": reason_codes,
        "report_predicate_outcome_sha256": None,
    }


def _bind_outcome_projection(
    *,
    projection: dict[str, object],
    claim_projection: AuthenticatedReportClaimProjection,
    batch_owner: AuthenticatedScenarioCaseBatch,
    case: _AuthenticatedCaseContext,
    context: _AuthenticatedScenarioEvidenceContext | None = None,
) -> tuple[ReportPredicateOutcome, dict[str, object]]:
    """Validate and bind locally derived bytes without invoking an external reader."""

    preimage = copy.deepcopy(projection)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage["report_predicate_outcome_sha256"] = None
    projection["report_predicate_outcome_sha256"] = structured_sha256_hex(
        _OUTCOME_DOMAIN,
        preimage,
    )
    try:
        validate_instance(
            projection,
            "scenario-evidence.schema.json",
            definition="ReportPredicateOutcome",
        )
        projection_bytes = canonical_json_bytes(projection)
        detached = strict_json_loads(projection_bytes)
    except (CanonicalizationError, SchemaValidationError):
        _reject()
    if type(detached) is not dict or detached != projection:
        _reject()
    detached_value = cast(dict[str, object], detached)
    digest = detached_value.get("report_predicate_outcome_sha256")
    digest_preimage = copy.deepcopy(detached_value)
    digest_preimage["digest_state"] = "DIGEST_PREIMAGE"
    digest_preimage["report_predicate_outcome_sha256"] = None
    if (
        type(digest) is not str
        or structured_sha256_hex(_OUTCOME_DOMAIN, digest_preimage) != digest
        or canonical_json_bytes(detached_value) != projection_bytes
    ):
        _reject()
    owner = object.__new__(ReportPredicateOutcome)
    _OUTCOME_ISSUER.bind_once(
        owner,
        _OutcomeState(
            projection_bytes=projection_bytes,
            claim_projection=claim_projection,
            batch_owner=batch_owner,
            case=case,
            context=context,
        ),
    )
    return owner, detached_value


def _validated_outcome_projection(owner: ReportPredicateOutcome) -> dict[str, object]:
    if type(owner) is not ReportPredicateOutcome:
        _reject()
    try:
        state = _OUTCOME_STATES.read(owner)
        if type(state) is not _OutcomeState:
            _reject()
        value = strict_json_loads(state.projection_bytes)
        read_authenticated_report_claim_projection(state.claim_projection)
    except (
        CanonicalizationError,
        OneShotRegistryError,
        ReportClaimProjectionError,
        ScenarioEvidenceContextError,
    ):
        _reject()
    if type(value) is not dict:
        _reject()
    projection = cast(dict[str, object], value)
    if state.context is not None:
        try:
            upstream_batch, upstream_case = _read_authenticated_scenario_case(state.context)
        except ScenarioEvidenceContextError:
            _reject()
        if upstream_batch is not state.batch_owner or upstream_case != state.case:
            _reject()
        case = upstream_case
    else:
        try:
            upstream_batch_value, case_values, _warnings, _terminals = (
                _read_cohort_report_claim_authority(state.claim_projection)
            )
        except ReportClaimProjectionError:
            _reject()
        matching_cases = tuple(value for value in case_values if value == state.case)
        if (
            upstream_batch_value is not state.batch_owner
            or len(matching_cases) != 1
            or type(matching_cases[0]) is not _AuthenticatedCaseContext
        ):
            _reject()
        case = matching_cases[0]
    policy_matches = tuple(
        policy
        for policy in _policies_for(case)
        if policy.predicate_id == projection.get("predicate_id")
        and projection.get("cardinality_member_id") in _cardinality_members(policy, case)
    )
    if len(policy_matches) != 1:
        _reject()
    expected = _outcome_projection(
        batch_owner=state.batch_owner,
        case=case,
        claim_owner=state.claim_projection,
        policy=policy_matches[0],
        cardinality_member_id=cast(str, projection["cardinality_member_id"]),
    )
    digest = projection.get("report_predicate_outcome_sha256")
    preimage = copy.deepcopy(projection)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage["report_predicate_outcome_sha256"] = None
    expected["report_predicate_outcome_sha256"] = digest
    try:
        validate_instance(
            projection,
            "scenario-evidence.schema.json",
            definition="ReportPredicateOutcome",
        )
    except SchemaValidationError:
        _reject()
    if (
        projection != expected
        or type(digest) is not str
        or structured_sha256_hex(_OUTCOME_DOMAIN, preimage) != digest
        or canonical_json_bytes(projection) != state.projection_bytes
    ):
        _reject()
    return projection


def _issue_report_predicate_outcomes(
    context: _AuthenticatedScenarioEvidenceContext,
    claim_projection: AuthenticatedReportClaimProjection,
) -> tuple[ReportPredicateOutcome, ...]:
    """Issue only the matched case family's frozen report-selector owners."""

    if (
        type(context) is not _AuthenticatedScenarioEvidenceContext
        or type(claim_projection) is not AuthenticatedReportClaimProjection
    ):
        _reject()
    try:
        batch_owner, case = _read_authenticated_scenario_case(context)
        claims = read_authenticated_report_claim_projection(claim_projection)
        if claims.get("evidence_graph_digest") != _read_scenario_evidence_graph_digest(context):
            _reject()
    except (ReportClaimProjectionError, ScenarioEvidenceContextError):
        _reject()
    policies = _policies_for(case)
    outcomes: list[ReportPredicateOutcome] = []
    for policy in policies:
        for member_id in _cardinality_members(policy, case):
            projection = _outcome_projection(
                batch_owner=batch_owner,
                case=case,
                claim_owner=claim_projection,
                policy=policy,
                cardinality_member_id=member_id,
            )
            owner, _detached = _bind_outcome_projection(
                projection=projection,
                claim_projection=claim_projection,
                batch_owner=batch_owner,
                case=case,
                context=context,
            )
            _validated_outcome_projection(owner)
            outcomes.append(owner)
    return tuple(outcomes)


def _issue_cohort_report_predicate_outcomes(
    claim_projection: AuthenticatedReportClaimProjection,
) -> tuple[ReportPredicateOutcome, ...]:
    """Issue every frozen predicate outcome from one complete cohort claim owner."""

    if type(claim_projection) is not AuthenticatedReportClaimProjection:
        _reject()
    try:
        batch_owner_value, case_values, _warnings, _terminals = _read_cohort_report_claim_authority(
            claim_projection
        )
    except ReportClaimProjectionError:
        _reject()
    if type(batch_owner_value) is not AuthenticatedScenarioCaseBatch:
        _reject()
    batch_owner = batch_owner_value
    outcomes: list[ReportPredicateOutcome] = []
    for case_value in case_values:
        if type(case_value) is not _AuthenticatedCaseContext:
            _reject()
        case = case_value
        for policy in _policies_for(case):
            for member_id in _cardinality_members(policy, case):
                projection = _outcome_projection(
                    batch_owner=batch_owner,
                    case=case,
                    claim_owner=claim_projection,
                    policy=policy,
                    cardinality_member_id=member_id,
                )
                owner, _detached = _bind_outcome_projection(
                    projection=projection,
                    claim_projection=claim_projection,
                    batch_owner=batch_owner,
                    case=case,
                )
                _validated_outcome_projection(owner)
                outcomes.append(owner)
    return tuple(outcomes)


def _read_report_predicate_outcome(owner: ReportPredicateOutcome) -> dict[str, object]:
    """Return a fresh safe projection after complete owner-graph revalidation."""

    return cast(
        dict[str, object],
        strict_json_loads(canonical_json_bytes(_validated_outcome_projection(owner))),
    )


def _read_report_predicate_outcome_context(
    owner: ReportPredicateOutcome,
) -> _AuthenticatedScenarioEvidenceContext:
    """Return the exact retained context only after full outcome revalidation."""

    _validated_outcome_projection(owner)
    try:
        state = _OUTCOME_STATES.read(owner)
    except OneShotRegistryError:
        _reject()
    if type(state) is not _OutcomeState:
        _reject()
    if state.context is None:
        _reject()
    return state.context


def _graph_source_record(
    *,
    owner_class: str,
    owner_schema_ref: str,
    cardinality: str,
    selector: str,
    natural_identity: dict[str, object],
    source_record: dict[str, object],
    support_digests: tuple[str, ...],
) -> object:
    from ebm_audit.evaluator.grouped_meaning_derivations import (
        ValidatedGraphSourceRecord,
    )

    wrapper_digest = structured_sha256_hex(
        _SOURCE_RECORD_DOMAIN,
        {
            "owner_class": owner_class,
            "natural_identity": natural_identity,
            "source_record": source_record,
        },
    )
    return ValidatedGraphSourceRecord(
        owner_class=owner_class,
        owner_schema_ref=owner_schema_ref,
        cardinality=cardinality,
        selector=selector,
        orientation=None,
        natural_identity=cast(dict[str, str | int | bool | None], natural_identity),
        source_record=source_record,
        source_record_sha256=wrapper_digest,
        ordered_support_owner_sha256=support_digests,
    )


def _claim_projection_graph_source_record(
    *,
    projection: dict[str, object],
) -> object:
    subject = projection.get("benchmark_subject_digest")
    claim_digest = projection.get("report_claim_projection_sha256")
    if type(subject) is not str or type(claim_digest) is not str:
        _reject()
    return _graph_source_record(
        owner_class="REPORT_CLAIM_PROJECTION",
        owner_schema_ref=(
            "schemas/scenario-evidence.schema.json#/$defs/AuthenticatedReportClaimProjection"
        ),
        cardinality="EXACTLY_ONE",
        selector="authenticated-report-claim-projection/1",
        natural_identity={
            "benchmark_subject_digest": subject,
            "report_claim_projection_sha256": claim_digest,
        },
        source_record=projection,
        support_digests=(),
    )


def _report_warning_ledger_record(
    *,
    benchmark_subject_digest: str,
    case_id: str,
    claim_digest: str,
    claim_owner_digest: str,
    warning_digests: tuple[str, ...],
) -> object:
    source: dict[str, object] = {
        "schema_version": "ebm-audit-report-warning-ledger/2.0",
        "benchmark_subject_digest": benchmark_subject_digest,
        "case_id": case_id,
        "report_claim_projection_sha256": claim_digest,
        "ordered_warning_record_sha256": list(warning_digests),
        "warning_count": len(warning_digests),
        "report_warning_ledger_sha256": None,
    }
    source["report_warning_ledger_sha256"] = structured_sha256_hex(_WARNING_LEDGER_DOMAIN, source)
    try:
        validate_instance(
            source,
            "scenario-evidence.schema.json",
            definition="PreRenderReportWarningLedger",
        )
    except SchemaValidationError:
        _reject()
    return _graph_source_record(
        owner_class="REPORT_WARNING_LEDGER",
        owner_schema_ref=(
            "schemas/scenario-evidence.schema.json#/$defs/PreRenderReportWarningLedger"
        ),
        cardinality="ONE_PER_CASE",
        selector="same-case-report-warning-ledger/1",
        natural_identity={
            "benchmark_subject_digest": benchmark_subject_digest,
            "case_id": case_id,
            "report_claim_projection_sha256": claim_digest,
        },
        source_record=source,
        support_digests=(claim_owner_digest, *warning_digests),
    )


def _report_terminal_visibility_record(
    *,
    benchmark_subject_digest: str,
    claim_digest: str,
    claim_owner_digest: str,
    terminal: object,
) -> object:
    source_value = getattr(terminal, "source_record", None)
    if not isinstance(source_value, Mapping):
        _reject()
    terminal_source = dict(source_value)
    terminal_owner_digest = getattr(terminal, "source_record_sha256", None)
    if type(terminal_owner_digest) is not str:
        _reject()
    return _report_terminal_visibility_record_from_snapshot(
        benchmark_subject_digest=benchmark_subject_digest,
        claim_digest=claim_digest,
        claim_owner_digest=claim_owner_digest,
        terminal_owner_digest=terminal_owner_digest,
        terminal_source=terminal_source,
    )


def _report_terminal_visibility_record_from_snapshot(
    *,
    benchmark_subject_digest: str,
    claim_digest: str,
    claim_owner_digest: str,
    terminal_owner_digest: str,
    terminal_source: dict[str, object],
) -> object:
    """Build terminal visibility from canonical transaction bytes."""

    required = (
        "case_id",
        "operation_instance_id",
        "case_operation_join_key",
        "proportional_operation_plan_sha256",
        "operation_plan_entry_sha256",
        "public_terminal_result_sha256",
        "terminal_record_sha256",
    )
    if any(field not in terminal_source for field in required):
        _reject()
    source: dict[str, object] = {
        "schema_version": "ebm-audit-report-terminal-visibility/2.0",
        "benchmark_subject_digest": benchmark_subject_digest,
        **{field: copy.deepcopy(terminal_source[field]) for field in required},
        "report_claim_projection_sha256": claim_digest,
        "terminal_count": 1,
        "report_terminal_visibility_sha256": None,
    }
    source["report_terminal_visibility_sha256"] = structured_sha256_hex(
        _TERMINAL_VISIBILITY_DOMAIN, source
    )
    try:
        validate_instance(
            source,
            "scenario-evidence.schema.json",
            definition="PreRenderReportTerminalVisibility",
        )
    except SchemaValidationError:
        _reject()
    if type(terminal_owner_digest) is not str:
        _reject()
    return _graph_source_record(
        owner_class="REPORT_TERMINAL_VISIBILITY",
        owner_schema_ref=(
            "schemas/scenario-evidence.schema.json#/$defs/PreRenderReportTerminalVisibility"
        ),
        cardinality="ONE_PER_CASE",
        selector="same-case-report-terminal-visibility/1",
        natural_identity={
            "case_operation_join_key": copy.deepcopy(terminal_source["case_operation_join_key"]),
            "public_terminal_result_sha256": terminal_source["public_terminal_result_sha256"],
            "report_claim_projection_sha256": claim_digest,
        },
        source_record=source,
        support_digests=(
            claim_owner_digest,
            terminal_owner_digest,
        ),
    )


def _case_from_report_transaction(value: dict[str, object]) -> _AuthenticatedCaseContext:
    required = {
        "family_id",
        "case_id",
        "source_contract_sha256",
        "scenario_source_sha256",
        "subtype",
        "boundary_rule_ids",
    }
    boundary_rule_ids = value.get("boundary_rule_ids")
    if (
        set(value) != required
        or type(value.get("family_id")) is not str
        or not value["family_id"]
        or type(value.get("case_id")) is not str
        or not value["case_id"]
        or type(value.get("source_contract_sha256")) is not str
        or type(value.get("scenario_source_sha256")) is not str
        or (
            value.get("subtype") is not None
            and type(value.get("subtype")) is not str
        )
        or type(boundary_rule_ids) is not list
        or any(type(item) is not str or not item for item in boundary_rule_ids)
        or len(boundary_rule_ids) != len(set(boundary_rule_ids))
    ):
        _reject()
    return _AuthenticatedCaseContext(
        family_id=cast(str, value["family_id"]),
        case_id=cast(str, value["case_id"]),
        source_contract_sha256=cast(str, value["source_contract_sha256"]),
        scenario_source_sha256=cast(str, value["scenario_source_sha256"]),
        subtype=cast(str | None, value["subtype"]),
        boundary_rule_ids=tuple(cast(list[str], boundary_rule_ids)),
    )


def _issue_cohort_report_graph_inputs(
    transaction: _CohortReportTransaction,
) -> tuple[tuple[str, tuple[object, ...], tuple[object, ...]], ...]:
    """Consume one frozen transaction and project report sources in exact order."""

    snapshot = _begin_cohort_report_transaction(transaction)
    try:
        if type(snapshot.batch_owner) is not AuthenticatedScenarioCaseBatch:
            _reject()
        claim_projection = snapshot.claim_projection
        projection = copy.deepcopy(snapshot.claim_projection_value)
        claim_schema_version = projection.get("schema_version")
        if (
            type(claim_schema_version) is not str
            or projection.get("report_claim_projection_sha256") != snapshot.claim_digest
            or projection.get("benchmark_subject_digest")
            != snapshot.benchmark_subject_digest
            or projection.get("rule_registry_sha256") != snapshot.rule_registry_sha256
        ):
            _reject()
        claim_source = _claim_projection_graph_source_record(projection=projection)
        claim_owner_digest = getattr(claim_source, "source_record_sha256", None)
        if type(claim_owner_digest) is not str:
            _reject()
        if len(snapshot.ordered_case_contexts) != len(snapshot.genuine_case_contexts):
            _reject()
        cases_list: list[_AuthenticatedCaseContext] = []
        for case_value, genuine_case in zip(
            snapshot.ordered_case_contexts,
            snapshot.genuine_case_contexts,
            strict=True,
        ):
            reconstructed = _case_from_report_transaction(case_value)
            if (
                type(genuine_case) is not _AuthenticatedCaseContext
                or reconstructed != genuine_case
            ):
                _reject()
            cases_list.append(genuine_case)
        cases = tuple(cases_list)
        warning_by_case: dict[str, list[str]] = {}
        for case_id, digest in snapshot.ordered_warning_records:
            warning_by_case.setdefault(case_id, []).append(digest)
        terminal_by_case: dict[str, list[tuple[str, dict[str, object]]]] = {}
        for terminal_owner_digest, terminal_source in snapshot.ordered_terminal_records:
            terminal_case_id = terminal_source.get("case_id")
            if type(terminal_case_id) is not str:
                _reject()
            terminal_by_case.setdefault(terminal_case_id, []).append(
                (terminal_owner_digest, terminal_source)
            )

        outcome_records_by_case: dict[str, list[object]] = {}
        outcome_owners: list[ReportPredicateOutcome] = []
        for case in cases:
            for policy in _policies_for(case):
                for member_id in _cardinality_members(policy, case):
                    outcome_projection = _outcome_projection_from_snapshot(
                        case=case,
                        policy=policy,
                        cardinality_member_id=member_id,
                        claim_records=snapshot.claim_records,
                        claim_schema_version=claim_schema_version,
                        evidence_graph_digest=snapshot.evidence_graph_digest,
                        claim_digest=snapshot.claim_digest,
                        benchmark_subject_digest=snapshot.benchmark_subject_digest,
                        rule_registry_sha256=snapshot.rule_registry_sha256,
                    )
                    outcome_owner, source = _bind_outcome_projection(
                        projection=outcome_projection,
                        claim_projection=claim_projection,
                        batch_owner=snapshot.batch_owner,
                        case=case,
                    )
                    outcome_owners.append(outcome_owner)
                    if (
                        source.get("report_claim_projection_sha256")
                        != snapshot.claim_digest
                        or source.get("evidence_graph_digest")
                        != snapshot.evidence_graph_digest
                        or source.get("ordered_case_ids") != [case.case_id]
                    ):
                        _reject()
                    outcome_records_by_case.setdefault(case.case_id, []).append(
                        _graph_source_record(
                            owner_class="REPORT_PREDICATE_OUTCOME",
                            owner_schema_ref=(
                                "schemas/scenario-evidence.schema.json#/$defs/"
                                "ReportPredicateOutcome"
                            ),
                            cardinality=policy.cardinality,
                            selector=policy.predicate_id,
                            natural_identity={
                                field: copy.deepcopy(source[field])
                                for field in (
                                    "benchmark_subject_digest",
                                    "family_id",
                                    "predicate_id",
                                    "cardinality_member_id",
                                    "report_claim_projection_sha256",
                                )
                            },
                            source_record=source,
                            support_digests=(claim_owner_digest,),
                        )
                    )

        result: list[tuple[str, tuple[object, ...], tuple[object, ...]]] = []
        for case in cases:
            sources = list(outcome_records_by_case.get(case.case_id, ()))
            if case.family_id == "heavy_tailed_skewed":
                sources.append(
                    _report_warning_ledger_record(
                        benchmark_subject_digest=snapshot.benchmark_subject_digest,
                        case_id=case.case_id,
                        claim_digest=snapshot.claim_digest,
                        claim_owner_digest=claim_owner_digest,
                        warning_digests=tuple(warning_by_case.get(case.case_id, ())),
                    )
                )
                sources.extend(
                    _report_terminal_visibility_record_from_snapshot(
                        benchmark_subject_digest=snapshot.benchmark_subject_digest,
                        claim_digest=snapshot.claim_digest,
                        claim_owner_digest=claim_owner_digest,
                        terminal_owner_digest=terminal_owner_digest,
                        terminal_source=terminal_source,
                    )
                    for terminal_owner_digest, terminal_source in terminal_by_case.get(
                        case.case_id, ()
                    )
                )
            if sources:
                sources.insert(0, claim_source)
            result.append((case.case_id, tuple(sources), ()))
        final_result = tuple(result)
        _complete_cohort_report_transaction(transaction)
        return final_result
    except BaseException:
        _fail_cohort_report_transaction(transaction)
        raise


__all__: list[str] = []
