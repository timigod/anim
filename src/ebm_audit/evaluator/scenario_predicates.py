"""Closed, digest-bound evaluation of the 23 synthetic scenario families.

The public evaluator consumes opaque owners, not caller-provided outcomes.  The
evidence projector is responsible for deriving each payload from ordinary audit
evidence before issuing the package-private evidence owner defined here.
"""

from __future__ import annotations

import copy
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.errors import InvalidInputError
from ebm_audit.evaluator.candidate_decision import (
    validate_candidate_strong_evidence_decision,
)
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256,
    structured_sha256_hex,
)
from ebm_audit.schema import SchemaValidationError, validate_instance

Outcome = Literal["PASS", "WARN", "FAIL"]

_REGISTRY_DOMAIN: Final = "ebm-audit/scenario-predicate-registry/1"
_PAYLOAD_DOMAIN: Final = "ebm-audit/scenario-predicate-payload/1"
_EVIDENCE_DOMAIN: Final = "ebm-audit/scenario-predicate-evidence-owner/1"
_RESULT_DOMAIN: Final = "ebm-audit/scenario-predicate-result/1"
_MANIFEST_DOMAIN: Final = "ebm-audit/sealed-case-manifest/1"
_TRUTH_DOMAIN: Final = "ebm-audit/synthetic-truth/1"
_IDENTITY_DOMAIN: Final = "ebm-audit/null-calibration-identity/1"
_OPPORTUNITY_DOMAIN: Final = "ebm-audit/false-positive-opportunity-manifest/1"
_DECISION_DOMAIN: Final = "ebm-audit/candidate-strong-evidence-decision/1"
_PAYLOAD_REF_PREFIX: Final = "schemas/scenario-family-payload.schema.json#/$defs/"
_OWNER_TOKEN: Final = object()


def _reject(code: str) -> Never:
    raise InvalidInputError(
        f"EVALUATOR.SCENARIO_PREDICATE_{code}",
        "Scenario predicate evidence failed closed validation.",
    )


def _json_copy(value: object) -> object:
    try:
        return strict_json_loads(canonical_json_bytes(value))
    except CanonicalizationError:
        _reject("JSON")


@dataclass(frozen=True, slots=True)
class _Predicate:
    family_id: str
    predicate_id: str
    evidence_definition: str
    algorithm: str
    parameters: dict[str, object]


class ScenarioPredicateRegistry:
    """Opaque, immutable compiled form of the frozen predicate registry."""

    __slots__ = ("_canonical_bytes", "_digest", "_predicates")

    def __init__(
        self,
        *,
        owner_token: object,
        canonical_bytes: bytes,
        digest: str,
        predicates: tuple[_Predicate, ...],
    ) -> None:
        if owner_token is not _OWNER_TOKEN:
            _reject("REGISTRY_FORGERY")
        self._canonical_bytes = canonical_bytes
        self._digest = digest
        self._predicates = predicates

    @property
    def digest(self) -> str:
        return self._digest


class ScenarioPredicateEvidence:
    """Opaque family payload issued only after exact schema validation."""

    __slots__ = (
        "_evidence_digest",
        "_family_id",
        "_payload_bytes",
        "_payload_digest",
        "_planned_case_ids",
        "_provenance_bytes",
    )

    def __init__(
        self,
        *,
        owner_token: object,
        family_id: str,
        payload_bytes: bytes,
        payload_digest: str,
        planned_case_ids: tuple[str, ...],
        provenance_bytes: bytes | None,
        evidence_digest: str,
    ) -> None:
        if owner_token is not _OWNER_TOKEN:
            _reject("EVIDENCE_FORGERY")
        self._family_id = family_id
        self._payload_bytes = payload_bytes
        self._payload_digest = payload_digest
        self._planned_case_ids = planned_case_ids
        self._provenance_bytes = provenance_bytes
        self._evidence_digest = evidence_digest

    @property
    def family_id(self) -> str:
        return self._family_id

    @property
    def digest(self) -> str:
        return self._evidence_digest


_RESULT_STATES: OneShotWeakRegistry[object, bytes]


@final
class ScenarioPredicateResult:
    """Opaque result whose complete digest preimage is checked on every readback."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ScenarioPredicateResult:
        raise TypeError("Scenario predicate results are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Scenario predicate results cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Scenario predicate results are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Scenario predicate results cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Scenario predicate results cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Scenario predicate results cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Scenario predicate results cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Scenario predicate results cannot be copied or serialized.")

    @property
    def family_id(self) -> str:
        return cast(str, _validated_result_projection(self)["family_id"])

    @property
    def predicate_id(self) -> str:
        return cast(str, _validated_result_projection(self)["predicate_id"])

    @property
    def outcome(self) -> Outcome:
        return cast(Outcome, _validated_result_projection(self)["outcome"])

    @property
    def predicate_registry_sha256(self) -> str:
        return cast(str, _validated_result_projection(self)["predicate_registry_sha256"])

    @property
    def payload_sha256(self) -> str:
        return cast(str, _validated_result_projection(self)["payload_sha256"])

    @property
    def evidence_owner_sha256(self) -> str:
        return cast(str, _validated_result_projection(self)["evidence_owner_sha256"])

    @property
    def result_sha256(self) -> str:
        return cast(str, _validated_result_projection(self)["result_sha256"])


def _validated_result_projection(result: ScenarioPredicateResult) -> dict[str, object]:
    if type(result) is not ScenarioPredicateResult:
        _reject("RESULT_OWNER")
    try:
        result_bytes = _RESULT_STATES.read(result)
        value = strict_json_loads(result_bytes)
    except (CanonicalizationError, OneShotRegistryError):
        _reject("RESULT_BYTES")
    required = {
        "family_id",
        "predicate_id",
        "outcome",
        "predicate_registry_sha256",
        "payload_sha256",
        "evidence_owner_sha256",
        "result_sha256",
    }
    if type(value) is not dict or set(value) != required:
        _reject("RESULT_PREIMAGE")
    projection = cast(dict[str, object], value)
    digest = projection["result_sha256"]
    preimage = copy.deepcopy(projection)
    preimage["result_sha256"] = None
    if (
        any(
            type(projection[field]) is not str or not projection[field]
            for field in required - {"outcome"}
        )
        or projection["outcome"] not in {"PASS", "WARN", "FAIL"}
        or type(digest) is not str
        or structured_sha256(_RESULT_DOMAIN, preimage) != digest
        or canonical_json_bytes(projection) != result_bytes
    ):
        _reject("RESULT_BINDING")
    return projection


def compile_scenario_predicate_registry(value: object) -> ScenarioPredicateRegistry:
    """Validate and compile the exact frozen registry subsection."""

    copied = _json_copy(value)
    try:
        validate_instance(copied, "scenario-predicate.schema.json")
        canonical = canonical_json_bytes(copied)
    except (CanonicalizationError, SchemaValidationError):
        _reject("REGISTRY")
    registry = cast(dict[str, object], copied)
    rows = cast(list[dict[str, object]], registry["predicates"])
    predicates: list[_Predicate] = []
    for row in rows:
        reference = cast(str, row["evidence_schema_ref"])
        if not reference.startswith(_PAYLOAD_REF_PREFIX):
            _reject("REGISTRY_REFERENCE")
        predicates.append(
            _Predicate(
                family_id=cast(str, row["family_id"]),
                predicate_id=cast(str, row["predicate_id"]),
                evidence_definition=reference.removeprefix(_PAYLOAD_REF_PREFIX),
                algorithm=cast(str, row["algorithm"]),
                parameters=cast(dict[str, object], _json_copy(row["parameters"])),
            )
        )
    return ScenarioPredicateRegistry(
        owner_token=_OWNER_TOKEN,
        canonical_bytes=canonical,
        digest=structured_sha256_hex(_REGISTRY_DOMAIN, copied),
        predicates=tuple(predicates),
    )


def _predicate_for(
    registry: ScenarioPredicateRegistry,
    family_id: str,
) -> _Predicate:
    if type(registry) is not ScenarioPredicateRegistry:
        _reject("REGISTRY_OWNER")
    matches = tuple(row for row in registry._predicates if row.family_id == family_id)
    if len(matches) != 1:
        _reject("FAMILY")
    return matches[0]


def _issue_scenario_predicate_evidence(
    registry: ScenarioPredicateRegistry,
    *,
    family_id: str,
    payload: Mapping[str, object],
    expected_case_ids: Sequence[str],
    valid_case_ids: Sequence[str],
    provenance: Mapping[str, object] | None = None,
) -> ScenarioPredicateEvidence:
    """Package-private issuance boundary used by the evidence projector."""

    predicate = _predicate_for(registry, family_id)
    if (
        type(expected_case_ids) not in {list, tuple}
        or type(valid_case_ids) not in {list, tuple}
        or not expected_case_ids
        or any(type(case_id) is not str or not case_id for case_id in expected_case_ids)
        or len(set(expected_case_ids)) != len(expected_case_ids)
        or list(valid_case_ids) != list(expected_case_ids)
    ):
        _reject("CASE_COVERAGE")
    planned_case_ids = tuple(expected_case_ids)
    copied = _json_copy(payload)
    try:
        validate_instance(
            copied,
            "scenario-family-payload.schema.json",
            definition=predicate.evidence_definition,
        )
        payload_bytes = canonical_json_bytes(copied)
    except (CanonicalizationError, SchemaValidationError):
        _reject("PAYLOAD_SCHEMA")
    if provenance is None:
        provenance_copy = None
        provenance_bytes = None
    else:
        provenance_copy = _json_copy(provenance)
        try:
            provenance_bytes = canonical_json_bytes(provenance_copy)
        except CanonicalizationError:
            _reject("PROVENANCE")
    if family_id == "pure_no_signal" and provenance_copy is None:
        _reject("PURE_NULL_PROVENANCE")
    if family_id != "pure_no_signal" and provenance_copy is not None:
        _reject("UNEXPECTED_PROVENANCE")
    payload_digest = structured_sha256(_PAYLOAD_DOMAIN, copied)
    evidence_digest = structured_sha256(
        _EVIDENCE_DOMAIN,
        {
            "family_id": family_id,
            "planned_case_ids": list(planned_case_ids),
            "payload_sha256": payload_digest,
            "provenance": provenance_copy,
            "predicate_registry_sha256": registry.digest,
        },
    )
    return ScenarioPredicateEvidence(
        owner_token=_OWNER_TOKEN,
        family_id=family_id,
        payload_bytes=payload_bytes,
        payload_digest=payload_digest,
        planned_case_ids=planned_case_ids,
        provenance_bytes=provenance_bytes,
        evidence_digest=evidence_digest,
    )


def _median(values: Sequence[float | int]) -> float | int:
    if not values or any(
        type(value) not in {float, int} or not math.isfinite(value) for value in values
    ):
        _reject("NUMERIC")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.5 * len(ordered)) - 1)]


def _mean(values: Sequence[float | int]) -> float:
    if not values or any(
        type(value) not in {float, int} or not math.isfinite(value) for value in values
    ):
        _reject("NUMERIC")
    return math.fsum(values) / len(values)


def _fraction(values: Sequence[object], predicate: object) -> float:
    if not values or not callable(predicate):
        _reject("VECTOR")
    return math.fsum(1.0 for value in values if predicate(value)) / len(values)


def _average_ranks(values: Sequence[float | int]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda row: row[1])
    ranks = [0.0] * len(values)
    start = 0
    while start < len(indexed):
        end = start + 1
        while end < len(indexed) and indexed[end][1] == indexed[start][1]:
            end += 1
        rank = ((start + 1) + end) / 2
        for index, _ in indexed[start:end]:
            ranks[index] = rank
        start = end
    return ranks


def _spearman(left: Sequence[float | int], right: Sequence[float | int]) -> float:
    if len(left) != len(right) or len(left) < 2:
        _reject("SPEARMAN")
    left_rank, right_rank = _average_ranks(left), _average_ranks(right)
    left_mean, right_mean = _mean(left_rank), _mean(right_rank)
    numerator = math.fsum(
        (a - left_mean) * (b - right_mean) for a, b in zip(left_rank, right_rank, strict=True)
    )
    denominator = math.sqrt(
        math.fsum((a - left_mean) ** 2 for a in left_rank)
        * math.fsum((b - right_mean) ** 2 for b in right_rank)
    )
    if denominator == 0:
        _reject("SPEARMAN")
    return numerator / denominator


def _interval_fraction(values: Sequence[float | int], interval: Sequence[object]) -> float:
    low, high = cast(Sequence[float | int], interval)
    return _fraction(values, lambda value: low <= cast(float, value) <= high)


def _clopper_pearson_upper(successes: int, total: int = 60) -> float:
    if successes == total:
        return 1.0
    low, high = 0.0, 1.0
    for _ in range(100):
        midpoint = (low + high) / 2
        cdf = math.fsum(
            math.comb(total, k) * midpoint**k * (1 - midpoint) ** (total - k)
            for k in range(successes + 1)
        )
        if cdf > 0.05:
            low = midpoint
        else:
            high = midpoint
    return (low + high) / 2


def _pure_truth_eligible(truth: Mapping[str, object]) -> bool:
    scenario = cast(dict[str, object], truth["scenario_identity"])
    eligibility = cast(dict[str, object], truth["fpr_eligibility"])
    order = cast(dict[str, object], truth["order_truth"])
    return (
        scenario["family_id"] == "pure_no_signal"
        and eligibility["eligible"] is True
        and eligibility["reason_code"] == "PURE_NO_SIGNAL_INDEPENDENT_OPPORTUNITY"
        and order["truth_kind"] == "NONE"
        and order["strict_order_identifiable"] is False
        and order["recoverable_signal"] is False
        and order["non_identifiability_reason"] == "PURE_NO_SIGNAL"
    )


def _validate_fpr_bundle(
    bundle: Mapping[str, object],
    provenance: Mapping[str, object],
) -> tuple[Outcome, tuple[str, ...]]:
    try:
        validate_instance(
            bundle,
            "scientific-invariant.schema.json",
            definition="FalsePositiveEvidenceBundle",
        )
    except SchemaValidationError:
        _reject("FPR_SCHEMA")
    identity = cast(dict[str, object], bundle["null_calibration_identity"])
    identity_digest = structured_sha256(_IDENTITY_DOMAIN, identity)
    subject_digest = cast(str, identity["benchmark_subject_digest"])
    manifest = cast(dict[str, object], bundle["sealed_case_manifest"])
    manifest_digest = structured_sha256_hex(_MANIFEST_DOMAIN, manifest)
    if (
        provenance.get("sealed_case_manifest_sha256") != manifest_digest
        or provenance.get("benchmark_subject_digest") != subject_digest
        or manifest["benchmark_subject_digest"] != subject_digest
    ):
        _reject("FPR_PROVENANCE")
    cases = cast(list[dict[str, object]], manifest["cases"])
    natural_ids = tuple(
        (row["family_id"], row["variant_index"], row["replicate_index"]) for row in cases
    )
    if (
        len(cases) != 60
        or len(set(natural_ids)) != 60
        or any(
            row["family_id"] != "pure_no_signal"
            or row["benchmark_subject_digest"] != subject_digest
            for row in cases
        )
    ):
        _reject("FPR_CASES")
    truths = cast(list[dict[str, object]], bundle["ordered_truth_objects"])
    for case, truth in zip(cases, truths, strict=True):
        preimage = copy.deepcopy(truth)
        preimage["digest_state"] = "DIGEST_PREIMAGE"
        preimage["truth_object_sha256"] = None
        truth_digest = structured_sha256_hex(_TRUTH_DOMAIN, preimage)
        scenario = cast(dict[str, object], truth["scenario_identity"])
        if (
            truth["digest_state"] != "PERSISTED"
            or truth["truth_object_sha256"] != truth_digest
            or case["truth_object_sha256"] != truth_digest
            or scenario["family_id"] != case["family_id"]
            or scenario["replicate_index"] != case["replicate_index"]
            or not _pure_truth_eligible(truth)
        ):
            _reject("FPR_TRUTH")
    opportunity_manifest = cast(dict[str, object], bundle["opportunity_manifest"])
    opportunities = cast(list[dict[str, object]], opportunity_manifest["ordered_opportunities"])
    if (
        opportunity_manifest["sealed_case_manifest_sha256"] != manifest_digest
        or opportunity_manifest["benchmark_subject_digest"] != subject_digest
        or opportunity_manifest["null_calibration_identity_digest"] != identity_digest
        or [row["opportunity_index"] for row in opportunities] != list(range(60))
        or [row["sealed_case_manifest_index"] for row in opportunities] != list(range(60))
    ):
        _reject("FPR_OPPORTUNITIES")
    opportunity_ids = [cast(str, row["opportunity_id"]) for row in opportunities]
    if len(set(opportunity_ids)) != 60:
        _reject("FPR_OPPORTUNITIES")
    decisions = cast(list[dict[str, object]], bundle["ordered_candidate_decisions"])
    if [row["opportunity_id"] for row in decisions] != opportunity_ids:
        _reject("FPR_DECISIONS")
    states: list[str] = []
    for opportunity, decision in zip(opportunities, decisions, strict=True):
        try:
            validated = validate_candidate_strong_evidence_decision(decision)
        except InvalidInputError:
            _reject("FPR_DECISION_DERIVATION")
        decision_state = validated.state
        if (
            opportunity["null_calibration_identity_digest"] != identity_digest
            or decision["null_calibration_identity"] != identity
            or decision["benchmark_subject_digest"] != subject_digest
            or opportunity["candidate_decision_sha256"]
            != structured_sha256_hex(_DECISION_DOMAIN, decision)
            or opportunity["candidate_decision_state"] != decision_state
        ):
            _reject("FPR_DECISION_BINDING")
        states.append(decision_state)
    manifest_preimage = copy.deepcopy(opportunity_manifest)
    manifest_preimage["digest_state"] = "DIGEST_PREIMAGE"
    manifest_preimage["false_positive_opportunity_manifest_sha256"] = None
    opportunity_digest = structured_sha256_hex(_OPPORTUNITY_DOMAIN, manifest_preimage)
    if (
        opportunity_manifest["digest_state"] != "PERSISTED"
        or opportunity_manifest["false_positive_opportunity_manifest_sha256"] != opportunity_digest
    ):
        _reject("FPR_OPPORTUNITY_DIGEST")
    evaluation = cast(dict[str, object], bundle["evaluation"])
    positives = states.count("CANDIDATE_STRONG_EVIDENCE")
    not_assessable = states.count("CANDIDATE_STRONG_EVIDENCE_NOT_ASSESSABLE")
    valid = 60 - not_assessable
    rate = positives / 60
    bound = _clopper_pearson_upper(positives)
    aggregate_state: Outcome = (
        "PASS" if valid == 60 and not_assessable == 0 and rate <= 0.05 and bound <= 0.05 else "FAIL"
    )
    expected = (
        positives,
        not_assessable,
        valid,
        rate,
        bound,
        aggregate_state,
    )
    actual = (
        evaluation["false_positive_count"],
        evaluation["not_assessable_count"],
        evaluation["valid_opportunity_count"],
        evaluation["point_false_positive_rate"],
        evaluation["clopper_pearson_upper_bound"],
        evaluation["state"],
    )
    if (
        evaluation["false_positive_opportunity_manifest_sha256"] != opportunity_digest
        or evaluation["benchmark_subject_digest"] != subject_digest
        or evaluation["null_calibration_identity_digest"] != identity_digest
        or any(
            abs(cast(float, observed) - cast(float, derived)) > 1e-15
            if type(observed) is float or type(derived) is float
            else observed != derived
            for observed, derived in zip(actual, expected, strict=True)
        )
    ):
        _reject("FPR_EVALUATION")
    return aggregate_state, tuple(states)


def _evaluate_payload(
    predicate: _Predicate,
    payload: Mapping[str, object],
    provenance: Mapping[str, object] | None,
) -> Outcome:
    p = predicate.parameters
    algorithm = predicate.algorithm
    if algorithm == "BOTH_RULE_STATES_PASS_ELSE_BOTH_AT_LEAST_WARN":
        states = cast(list[str], payload["order_rule_states"]) + cast(
            list[str], payload["stage_rule_states"]
        )
        if any(state in {"FAIL", "NOT_ASSESSABLE"} for state in states):
            return "FAIL"
        return "PASS" if all(state == "PASS" for state in states) else "WARN"
    if algorithm == "AGGREGATE_RULE_STATE_VECTOR":
        states = cast(list[str], payload[cast(str, p["field"])])
        if any(state in {"FAIL", "NOT_ASSESSABLE"} for state in states):
            return "FAIL"
        return "PASS" if all(state == "PASS" for state in states) else "WARN"
    if algorithm == "PAIRED_MEDIANS_AND_NO_TRUE_FLAGS":
        if "forced_precision_flags" in payload:
            left = cast(list[float], payload["entropy_delta_small_minus_large"])
            right = cast(list[float], payload["cross_chain_delta_small_minus_large"])
            flags = cast(list[bool], payload["forced_precision_flags"])
            pass_left, pass_right = p["pass_entropy_delta_min"], p["pass_cross_chain_delta_min"]
            warn_left, warn_right = p["warn_entropy_delta_min"], p["warn_cross_chain_delta_min"]
        else:
            left = cast(list[float], payload["entropy_delta_weak_minus_moderate"])
            right = cast(list[float], payload["kendall_distance_delta_weak_minus_moderate"])
            flags = cast(list[bool], payload["ineligible_strong_flags"])
            pass_left, pass_right = p["pass_entropy_delta_min"], p["pass_kendall_delta_min"]
            warn_left, warn_right = p["warn_entropy_delta_min"], p["warn_kendall_delta_min"]
        if any(flags):
            return "FAIL"
        if _median(left) >= cast(float, pass_left) and _median(right) >= cast(float, pass_right):
            return "PASS"
        return (
            "WARN"
            if _median(left) >= cast(float, warn_left) and _median(right) >= cast(float, warn_right)
            else "FAIL"
        )
    if algorithm == "MEDIAN_AND_ALL_TRUE":
        if not all(cast(list[bool], payload["coverage_limitation_reported"])):
            return "FAIL"
        value = _median(cast(list[float], payload["affected_tail_entropy_delta"]))
        if value >= cast(float, p["pass_median_delta_min"]):
            return "PASS"
        return "WARN" if value >= cast(float, p["warn_median_delta_min"]) else "FAIL"
    if algorithm == "TARGET_PAIR_AMBIGUITY_AND_NO_FALSE_PRECISION":
        if any(cast(list[bool], payload["arbitrary_within_pair_truth_claims"])):
            return "FAIL"
        values = cast(list[float], payload["target_pair_precedence"])
        if _interval_fraction(values, cast(list[object], p["pass_precedence_interval"])) >= cast(
            float, p["pass_fraction_min"]
        ):
            return "PASS"
        return (
            "WARN"
            if _interval_fraction(values, cast(list[object], p["warn_precedence_interval"]))
            >= cast(float, p["warn_fraction_min"])
            else "FAIL"
        )
    if algorithm == "PAIRED_MEDIANS":
        left_median = _median(cast(list[float], payload["entropy_delta_slow_minus_narrow"]))
        right_median = _median(
            cast(list[float], payload["kendall_distance_delta_slow_minus_narrow"])
        )
        if left_median >= cast(float, p["pass_entropy_delta_min"]) and right_median >= cast(
            float, p["pass_kendall_delta_min"]
        ):
            return "PASS"
        return (
            "WARN"
            if left_median >= cast(float, p["warn_entropy_delta_min"])
            and right_median >= cast(float, p["warn_kendall_delta_min"])
            else "FAIL"
        )
    if algorithm == "RULE_STATE_VECTOR_AND_NO_TRUE_FLAGS":
        states = cast(list[str], payload[cast(str, p["state_field"])])
        flags = cast(list[bool], payload[cast(str, p["claim_flag_field"])])
        if any(state in {"FAIL", "NOT_ASSESSABLE"} for state in states) or any(flags):
            return "FAIL"
        return "PASS" if all(state == "PASS" for state in states) else "WARN"
    if algorithm == "MCAR_EXACT_ACCOUNTING":
        passed = all(
            all(cast(list[bool], payload[key]))
            for key in (
                "mask_digest_equal",
                "missing_counts_equal",
                "prebackend_terminal_correct",
                "preprocessing_refit_equal",
            )
        )
        return (
            "PASS"
            if passed
            and payload["predicted_removed_rows"] == payload["actual_removed_rows"]
            and not any(cast(list[bool], payload["backend_nan_flags"]))
            else "FAIL"
        )
    if algorithm == "MAR_EXACT_ACCOUNTING":
        passed = all(
            all(cast(list[bool], payload[key]))
            for key in (
                "mask_digest_equal",
                "missing_counts_equal",
                "terminal_contract_equal",
                "training_row_manifest_equal",
            )
        )
        return (
            "PASS"
            if passed
            and not any(cast(list[bool], payload["silent_loss_flags"]))
            and not any(cast(list[bool], payload["hidden_imputation_flags"]))
            else "FAIL"
        )
    if algorithm == "SUBTYPE_AMBIGUITY_AND_NO_FALSE_PRECISION":
        correlated = cast(dict[str, object], payload["correlated"])
        duplicate = cast(dict[str, object], payload["exact_duplicate_post_noise"])
        honesty = (
            not any(cast(list[bool], correlated["arbitrary_within_pair_truth_claims"]))
            and not any(cast(list[bool], duplicate["arbitrary_within_pair_truth_claims"]))
            and all(cast(list[bool], duplicate["partial_truth_scored_without_tiebreak"]))
        )
        if not honesty:
            return "FAIL"
        corr = cast(list[float], correlated["target_pair_precedence"])
        dup = cast(list[float], duplicate["target_pair_precedence"])
        corr_pass = _interval_fraction(
            corr, cast(list[object], p["correlated_pass_precedence_interval"])
        ) >= cast(float, p["correlated_pass_fraction_min"])
        dup_pass = _interval_fraction(
            dup, cast(list[object], p["exact_duplicate_pass_precedence_interval"])
        ) >= cast(float, p["exact_duplicate_pass_fraction_min"])
        if corr_pass and dup_pass:
            return "PASS"
        corr_warn = _interval_fraction(
            corr, cast(list[object], p["correlated_warn_precedence_interval"])
        ) >= cast(float, p["correlated_warn_fraction_min"])
        dup_warn = _interval_fraction(
            dup, cast(list[object], p["exact_duplicate_warn_precedence_interval"])
        ) >= cast(float, p["exact_duplicate_warn_fraction_min"])
        return "WARN" if corr_warn and dup_warn else "FAIL"
    if algorithm == "LIMITATION_ALL_TRUE_AND_MEDIAN_DELTA":
        if not all(cast(list[bool], payload["single_sequence_limitation_reported"])):
            return "FAIL"
        return (
            "PASS"
            if _median(cast(list[float], payload["entropy_delta_mixture_minus_single"]))
            >= cast(float, p["pass_median_entropy_delta_min"])
            else "WARN"
        )
    if algorithm == "NONIDENTIFIABLE_MEAN_HALF_DISTANCE_AND_NO_STRONG_FLAGS":
        if any(cast(list[bool], payload["internally_concentrated_flags"])) or any(
            cast(list[bool], payload["stronger_than_null_flags"])
        ):
            return "FAIL"
        value = _mean(cast(list[float], payload["opposing_pair_absolute_precedence_from_half"]))
        if value <= cast(float, p["pass_mean_half_distance_max"]):
            return "PASS"
        return "WARN" if value <= cast(float, p["warn_mean_half_distance_max"]) else "FAIL"
    if algorithm == "PARTIAL_BLOCK_PRECEDENCE_FRACTION":
        if not all(cast(list[bool], payload["block_aware_scoring"])):
            return "FAIL"
        values = cast(list[float], payload["block_pair_precedence"])
        if _interval_fraction(values, cast(list[object], p["pass_interval"])) >= cast(
            float, p["pass_fraction_min"]
        ):
            return "PASS"
        return (
            "WARN"
            if _interval_fraction(values, cast(list[object], p["warn_interval"]))
            >= cast(float, p["warn_fraction_min"])
            else "FAIL"
        )
    if algorithm == "COVARIATE_PAIRED_AND_NO_LEAKAGE":
        values = cast(list[float], payload["adjusted_minus_unadjusted_kendall_agreement"])
        if not all(cast(list[bool], payload["reference_only_fit_flags"])) or any(
            cast(list[int], payload["resample_leakage_count"])
        ):
            return "FAIL"
        if _median(values) >= cast(float, p["pass_median_delta_min"]) and _fraction(
            values, lambda value: cast(float, value) > 0
        ) >= cast(float, p["pass_positive_fraction_min"]):
            return "PASS"
        return "WARN" if _median(values) >= cast(float, p["warn_median_delta_min"]) else "FAIL"
    if algorithm == "EXACT_BOUNDARY_ACCOUNTING":
        passed = (
            payload["ordered_rule_ids"] == ["boundary_q50", "boundary_q35", "boundary_q65"]
            and all(cast(list[bool], payload["group_count_accounting_equal"]))
            and all(
                value == "DESCRIPTIVE_ASSOCIATION"
                for value in cast(list[str], payload["decision_attribution"])
            )
            and not any(cast(list[bool], payload["selected_threshold_flags"]))
        )
        return "PASS" if passed else "FAIL"
    if algorithm == "SPEARMAN_TRENDS_AND_ALL_LABEL_BINDINGS":
        if not all(cast(list[bool], payload["label_manifest_equal"])):
            return "FAIL"
        kendall_rho = _spearman(
            cast(list[float], payload["contamination_fraction"]),
            cast(list[float], payload["kendall_agreement"]),
        )
        entropy_rho = _spearman(
            cast(list[float], payload["contamination_fraction"]),
            cast(list[float], payload["position_entropy"]),
        )
        if kendall_rho <= cast(float, p["pass_kendall_rho_max"]) and entropy_rho >= cast(
            float, p["pass_entropy_rho_min"]
        ):
            return "PASS"
        return (
            "WARN"
            if kendall_rho <= cast(float, p["warn_kendall_rho_max"])
            and entropy_rho >= cast(float, p["warn_entropy_rho_min"])
            else "FAIL"
        )
    if algorithm == "ZERO_HIDDEN_CHANGES_AND_COMPLETE_TERMINALS":
        passed = all(
            not any(cast(list[bool], payload[key]))
            for key in (
                "hidden_modification_flags",
                "suppressed_warning_flags",
                "nonfinite_admitted_flags",
            )
        )
        return (
            "PASS"
            if passed and all(cast(list[bool], payload["visible_terminal_flags"]))
            else "FAIL"
        )
    if algorithm == "DIRECTION_PAIRED_AND_NO_VALIDITY_CLAIMS":
        values = cast(list[float], payload["correct_minus_wrong_kendall_agreement"])
        report_fraction = _fraction(
            cast(list[bool], payload["direction_sensitivity_reported"]), bool
        )
        if any(cast(list[bool], payload["direction_validity_claims"])):
            return "FAIL"
        if _median(values) >= cast(float, p["pass_median_delta_min"]) and report_fraction >= cast(
            float, p["pass_report_fraction_min"]
        ):
            return "PASS"
        return (
            "WARN"
            if _median(values) >= cast(float, p["warn_median_delta_min"])
            and report_fraction >= cast(float, p["warn_report_fraction_min"])
            else "FAIL"
        )
    if algorithm == "DERIVE_COMPLETE_FPR_EVIDENCE":
        if provenance is None:
            _reject("PURE_NULL_PROVENANCE")
        fpr_state, fpr_states = _validate_fpr_bundle(
            cast(dict[str, object], payload["fpr_evidence"]), provenance
        )
        passed = (
            len(fpr_states) == cast(int, p["opportunity_count"])
            and fpr_states.count("CANDIDATE_STRONG_EVIDENCE_NOT_ASSESSABLE")
            <= cast(int, p["not_assessable_count_max"])
            and fpr_state == "PASS"
        )
        return "PASS" if passed else "FAIL"
    if algorithm == "ALL_TRANSFORMATION_INVARIANTS_AND_NO_INELIGIBLE_STRONG":
        passed = all(
            all(cast(list[bool], payload[key]))
            for key in (
                "group_counts_preserved",
                "preprocessing_refit_equal",
                "source_binding_equal",
                "calibration_diagnostic_reported",
                "excluded_from_pure_no_signal_fpr_denominator",
            )
        ) and not any(cast(list[bool], payload["ineligible_strong_flags"]))
        return "PASS" if passed else "FAIL"
    if algorithm == "ALL_FEATURE_TRANSFORMATION_INVARIANTS_AND_NO_INELIGIBLE_STRONG":
        passed = all(
            all(cast(list[bool], payload[key]))
            for key in (
                "group_marginals_preserved",
                "missing_counts_preserved",
                "participant_event_alignment_changed",
                "preprocessing_refit_equal",
                "source_binding_equal",
                "calibration_diagnostic_reported",
                "excluded_from_pure_no_signal_fpr_denominator",
            )
        ) and not any(cast(list[bool], payload["ineligible_strong_flags"]))
        return "PASS" if passed else "FAIL"
    _reject("ALGORITHM")


def _build_result_evaluator() -> tuple[
    OneShotWeakRegistry[object, bytes],
    Callable[
        [ScenarioPredicateRegistry, ScenarioPredicateEvidence],
        ScenarioPredicateResult,
    ],
]:
    result_states: OneShotWeakRegistry[object, bytes]
    result_states, result_state_issuer = create_one_shot_registry()

    def evaluate_scenario_predicate(
        registry: ScenarioPredicateRegistry,
        evidence: ScenarioPredicateEvidence,
    ) -> ScenarioPredicateResult:
        """Evaluate one sealed family payload and return a digest-bound result."""

        if type(evidence) is not ScenarioPredicateEvidence:
            _reject("EVIDENCE_OWNER")
        predicate = _predicate_for(registry, evidence._family_id)
        try:
            payload = strict_json_loads(evidence._payload_bytes)
            provenance = (
                None
                if evidence._provenance_bytes is None
                else strict_json_loads(evidence._provenance_bytes)
            )
        except CanonicalizationError:
            _reject("OWNER_BYTES")
        if (
            type(payload) is not dict
            or structured_sha256(_PAYLOAD_DOMAIN, payload) != evidence._payload_digest
        ):
            _reject("OWNER_BINDING")
        outcome = _evaluate_payload(
            predicate,
            cast(dict[str, object], payload),
            cast(dict[str, object] | None, provenance),
        )
        projection = {
            "family_id": predicate.family_id,
            "predicate_id": predicate.predicate_id,
            "outcome": outcome,
            "predicate_registry_sha256": registry.digest,
            "payload_sha256": evidence._payload_digest,
            "evidence_owner_sha256": evidence.digest,
            "result_sha256": None,
        }
        projection["result_sha256"] = structured_sha256(_RESULT_DOMAIN, projection)
        result = object.__new__(ScenarioPredicateResult)
        result_state_issuer.bind_once(result, canonical_json_bytes(projection))
        return result

    return result_states, evaluate_scenario_predicate


(_RESULT_STATES, evaluate_scenario_predicate) = _build_result_evaluator()
del _build_result_evaluator


__all__ = [
    "ScenarioPredicateEvidence",
    "ScenarioPredicateRegistry",
    "ScenarioPredicateResult",
    "compile_scenario_predicate_registry",
    "evaluate_scenario_predicate",
]
