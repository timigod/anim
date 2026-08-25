"""Pure pre-authorization candidate strong-evidence evaluation.

This module derives evaluator evidence only.  It has no held-out calibration,
backend-acceptance, production-null, reporting, or report-authorization input.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING, Any, Final, Never, SupportsIndex, cast, final
from weakref import WeakSet

from ebm_audit._capability_registry import OneShotWeakRegistry, create_one_shot_registry
from ebm_audit.errors import InvalidInputError
from ebm_audit.metrics import empirical_null_comparison
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.science._frozen_derivation import build_frozen_derivation_graph

if TYPE_CHECKING:
    from ebm_audit.evaluator.scenario_source_owner_manifest import (
        _ScenarioSourceRecordInput,
    )

_SCHEMA_NAME: Final = "scientific-invariant.schema.json"
_IDENTITY_DEFINITION: Final = "NullCalibrationIdentity"
_OBSERVED_DEFINITION: Final = "CandidateObservedFitEvidence"
_NULL_DEFINITION: Final = "CandidateNullFitEvidence"
_DECISION_DEFINITION: Final = "CandidateStrongEvidenceDecision"

_IDENTITY_DOMAIN: Final = "ebm-audit/null-calibration-identity/1"
_REFIT_STEPS_DOMAIN: Final = "ebm-audit/refit-steps/1"
_DECISION_DOMAIN: Final = "ebm-audit/candidate-strong-evidence-decision/1"
_SCHEMA_VERSION: Final = "ebm-audit-candidate-strong-evidence-decision/1.0"
_RULE_ID: Final = "candidate-strong-evidence/v1"
_SAFE_INTEGER_MAX: Final = 9_007_199_254_740_991

_NULL_FAMILIES: Final = (
    "pure_no_signal",
    "label_permutation_null",
    "within_group_feature_permutation_null",
)
_STATISTICS: Final = (
    ("pairwise_concentration/v1", "pairwise_concentration"),
    ("position_concentration/v1", "position_concentration"),
)
_FAILED_PRECONDITION_ORDER: Final = (
    "OBSERVED_FIT_NOT_SUCCESS",
    "OBSERVED_CONVERGENCE_NOT_PASS",
    "NULL_FIT_COUNT_NOT_59",
    "NULL_FIT_NOT_SUCCESS",
    "NULL_CONVERGENCE_NOT_PASS",
    "NONFINITE_STATISTIC",
    "NULL_CALIBRATION_IDENTITY_MISMATCH",
    "REFIT_STEPS_DIFFER",
    "MISSING_OR_DUPLICATE_EVIDENCE",
    "HARD_FAILURE",
)
_EXPECTED_SLOTS: Final = tuple(
    (family, replicate_index) for family in _NULL_FAMILIES for replicate_index in range(59)
)
_FIT_NUMERIC_FIELDS: Final = (
    "pairwise_concentration",
    "position_concentration",
)
_TEST_NULLABLE_NUMERIC_FIELDS: Final = (
    "observed_statistic",
    "p_empirical",
    "null_median",
    "null_effect",
)
_TEST_INTEGER_FIELDS: Final = (
    "null_replicate_count",
    "null_success_count",
    "null_convergence_pass_count",
    "null_exceedance_count",
)

_VALIDATE_INSTANCE = validate_instance
_CANONICAL_JSON_BYTES = canonical_json_bytes
_STRICT_JSON_LOADS = strict_json_loads
_STRUCTURED_SHA256 = structured_sha256
_EMPIRICAL_NULL_COMPARISON = empirical_null_comparison
_ISFINITE = math.isfinite


@dataclass(frozen=True, repr=False, slots=True, weakref_slot=True)
class CandidateStrongEvidenceDecision:
    """Immutable canonical decision plus its domain-separated digest."""

    canonical_bytes: bytes
    decision_sha256: str
    state: str
    failed_precondition_codes: tuple[str, ...]

    def as_dict(
        self,
        _decode: Callable[[bytes | bytearray | memoryview], Any] = _STRICT_JSON_LOADS,
    ) -> dict[str, object]:
        """Return a detached plain-dict projection of the canonical bytes."""

        decoded = _decode(self.canonical_bytes)
        if type(decoded) is not dict:
            raise RuntimeError("Canonical candidate decision bytes have an invalid shape.")
        return cast(dict[str, object], decoded)


def _invalid_input(code: str, message: str) -> InvalidInputError:
    return InvalidInputError(code, message)


def _canonical_bytes(value: object) -> bytes:
    try:
        return _CANONICAL_JSON_BYTES(value)
    except CanonicalizationError:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_JSON",
            "Candidate-decision input is outside the canonical JSON data model.",
        ) from None


def _structured_digest(domain: str, value: object) -> str:
    try:
        return _STRUCTURED_SHA256(domain, value)
    except CanonicalizationError:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_JSON",
            "Candidate-decision input is outside the canonical JSON data model.",
        ) from None


def _copy_json_value(value: object) -> object:
    value_type = type(value)
    if value is None or value_type in {bool, float, int, str}:
        return value
    if value_type is list:
        return [_copy_json_value(child) for child in cast(list[object], value)]
    if value_type is dict:
        return {
            cast(str, key): _copy_json_value(child)
            for key, child in cast(dict[object, object], value).items()
        }
    raise _invalid_input(
        "EVALUATOR.CANDIDATE_DECISION_TYPE",
        "Candidate-decision input contains an unsupported value type.",
    )


def _copy_object(value: Mapping[str, object]) -> dict[str, object]:
    if type(value) is not dict:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_TYPE",
            "Candidate-decision objects must be plain dictionaries.",
        )
    copied = _copy_json_value(value)
    if type(copied) is not dict:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_TYPE",
            "Candidate-decision object input has an invalid shape.",
        )
    return cast(dict[str, object], copied)


def _strict_nullable_number(value: object) -> bool:
    if value is None:
        return False
    if type(value) not in {float, int}:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_NUMERIC_TYPE",
            "Candidate-decision numeric fields require exact built-in numeric types.",
        )
    if type(value) is int and abs(value) > _SAFE_INTEGER_MAX:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_JSON",
            "Candidate-decision integers must be in the canonical JSON safe range.",
        )
    if not _ISFINITE(cast(float | int, value)):
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_NONFINITE",
            "Candidate-decision numeric fields must be finite.",
        )
    return True


def _validate_fit_semantics(record: dict[str, object], *, null_fit: bool) -> None:
    for field_name in _FIT_NUMERIC_FIELDS:
        _strict_nullable_number(record[field_name])
    if type(record["hard_failure"]) is not bool:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_BOOLEAN_TYPE",
            "Candidate-decision boolean fields require exact built-in booleans.",
        )
    if null_fit and type(record["replicate_index"]) is not int:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_NUMERIC_TYPE",
            "Candidate-decision integer fields require exact built-in integers.",
        )


def _refit_steps_record(record: dict[str, object]) -> dict[str, object]:
    refit_steps = record["refit_steps_evidence"]
    if type(refit_steps) is not dict:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_REFIT_STEPS_TYPE",
            "Candidate refit-steps evidence must be a plain dictionary.",
        )
    return cast(dict[str, object], refit_steps)


def _validate_refit_steps_digest(record: dict[str, object]) -> dict[str, object]:
    refit_steps = _refit_steps_record(record)
    preimage = dict(refit_steps)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage["refit_steps_digest"] = None
    expected_digest = _structured_digest(_REFIT_STEPS_DOMAIN, preimage)
    if refit_steps["refit_steps_digest"] != expected_digest:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_REFIT_STEPS_DIGEST",
            "Candidate refit-steps evidence digest does not match its preimage.",
        )
    return refit_steps


def _validate_operation_role(
    record: dict[str, object],
    *,
    opportunity_id: str,
    null_fit: bool,
) -> None:
    operation = record["operation_role_evidence"]
    if type(operation) is not dict:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_OPERATION_ROLE_TYPE",
            "Candidate operation-role evidence must be a plain dictionary.",
        )
    operation_record = cast(dict[str, object], operation)
    expected_role = "NULL" if null_fit else "OBSERVED"
    role_matches = (
        operation_record["operation_role"] == expected_role
        and operation_record["opportunity_id"] == opportunity_id
    )
    if null_fit:
        role_matches = (
            role_matches
            and operation_record["null_family_id"] == record["null_family_id"]
            and operation_record["replicate_index"] == record["replicate_index"]
        )
    else:
        role_matches = (
            role_matches
            and operation_record["null_family_id"] is None
            and operation_record["replicate_index"] is None
        )
    if not role_matches:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_OPERATION_ROLE_MISMATCH",
            "Candidate operation-role evidence does not match its fit slot.",
        )


def _validate_test_semantics(test: dict[str, object]) -> None:
    for field_name in _TEST_NULLABLE_NUMERIC_FIELDS:
        _strict_nullable_number(test[field_name])
    ordered = test["ordered_null_statistics"]
    if type(ordered) is not list:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_TYPE",
            "Candidate-decision ordered statistics must be a plain list.",
        )
    for value in cast(list[object], ordered):
        _strict_nullable_number(value)
    for field_name in _TEST_INTEGER_FIELDS:
        if type(test[field_name]) is not int:
            raise _invalid_input(
                "EVALUATOR.CANDIDATE_DECISION_NUMERIC_TYPE",
                "Candidate-decision integer fields require exact built-in integers.",
            )
    for field_name in ("identity_match", "refit_steps_equal"):
        if type(test[field_name]) is not bool:
            raise _invalid_input(
                "EVALUATOR.CANDIDATE_DECISION_BOOLEAN_TYPE",
                "Candidate-decision boolean fields require exact built-in booleans.",
            )


def _validate_decision_semantics(decision: dict[str, object]) -> None:
    identity = decision["null_calibration_identity"]
    observed = decision["observed_fit_evidence"]
    nulls = decision["ordered_null_fit_evidence"]
    tests = decision["ordered_tests"]
    codes = decision["failed_precondition_codes"]
    if (
        type(identity) is not dict
        or type(observed) is not dict
        or type(nulls) is not list
        or type(tests) is not list
        or type(codes) is not list
    ):
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_TYPE",
            "Candidate-decision nested collections must use plain JSON container types.",
        )
    _validate_fit_semantics(cast(dict[str, object], observed), null_fit=False)
    for row in cast(list[object], nulls):
        if type(row) is not dict:
            raise _invalid_input(
                "EVALUATOR.CANDIDATE_DECISION_TYPE",
                "Candidate-decision null-fit evidence must contain plain dictionaries.",
            )
        _validate_fit_semantics(cast(dict[str, object], row), null_fit=True)
    for test in cast(list[object], tests):
        if type(test) is not dict:
            raise _invalid_input(
                "EVALUATOR.CANDIDATE_DECISION_TYPE",
                "Candidate-decision tests must contain plain dictionaries.",
            )
        _validate_test_semantics(cast(dict[str, object], test))


def _null_calibration_identity_digest(
    null_calibration_identity: Mapping[str, object],
) -> str:
    identity = _copy_object(null_calibration_identity)
    return _structured_digest(_IDENTITY_DOMAIN, identity)


def _test_record(
    *,
    expected_family: str,
    statistic_id: str,
    statistic_field: str,
    observed: dict[str, object],
    family_slots: tuple[dict[str, object] | None, ...],
    family_claim_rows: tuple[dict[str, object], ...],
    global_slots_match: bool,
    identity_digest: str,
    benchmark_subject_digest: str,
) -> tuple[dict[str, object], bool]:
    observed_value = observed[statistic_field]
    null_values = [None if row is None else row[statistic_field] for row in family_slots]
    null_success_count = sum(
        row is not None and row["fit_state"] == "SUCCESS" for row in family_slots
    )
    null_convergence_pass_count = sum(
        row is not None and row["convergence_state"] == "CONVERGENCE_PASS" for row in family_slots
    )
    identity_match = (
        _refit_steps_record(observed)["null_calibration_identity_digest"]
        == identity_digest
        and observed["benchmark_subject_digest"] == benchmark_subject_digest
        and all(
            _refit_steps_record(row)["null_calibration_identity_digest"]
            == identity_digest
            and row["benchmark_subject_digest"] == benchmark_subject_digest
            for row in family_claim_rows
        )
    )
    refit_steps_equal = all(
        _refit_steps_record(row)["refit_steps_digest"]
        == _refit_steps_record(observed)["refit_steps_digest"]
        for row in family_claim_rows
    )
    inputs_finite = _strict_nullable_number(observed_value) and all(
        _strict_nullable_number(value) for value in null_values
    )
    assessable = (
        global_slots_match
        and all(row is not None for row in family_slots)
        and observed["fit_state"] == "SUCCESS"
        and observed["convergence_state"] == "CONVERGENCE_PASS"
        and observed["hard_failure"] is False
        and null_success_count == 59
        and null_convergence_pass_count == 59
        and all(row["hard_failure"] is False for row in family_claim_rows)
        and identity_match
        and refit_steps_equal
        and inputs_finite
    )
    exceedance_count = 0
    p_empirical: float | None = None
    null_median: float | None = None
    null_effect: float | None = None
    criterion_state = "NOT_ASSESSABLE"
    numeric_derivation_failure = False
    if assessable:
        observed_number = cast(float | int, observed_value)
        numeric_nulls = cast(list[float | int], null_values)
        exceedance_count = sum(value >= observed_number for value in numeric_nulls)
        p_result, effect_result = _EMPIRICAL_NULL_COMPARISON(
            observed_number,
            numeric_nulls,
        )
        ordered_values = sorted(float(value) for value in numeric_nulls)
        median_value = ordered_values[29]
        p_is_valid = (
            p_result.status == "ASSESSABLE"
            and type(p_result.value) is float
            and _ISFINITE(p_result.value)
            and p_result.value == (1.0 + exceedance_count) / 60.0
        )
        if p_is_valid:
            p_value = cast(float, p_result.value)
            p_empirical = p_value
            null_median = median_value
            if (
                effect_result.status == "ASSESSABLE"
                and type(effect_result.value) is float
                and _ISFINITE(effect_result.value)
                and effect_result.value == float(observed_number) - median_value
            ):
                null_effect = effect_result.value
                criterion_state = (
                    "STRONG_CRITERION"
                    if null_effect > 0.0 and p_value <= 0.05
                    else "NOT_STRONG_CRITERION"
                )
            else:
                numeric_derivation_failure = True
        else:
            numeric_derivation_failure = True
            null_median = median_value
    return (
        {
            "null_family_id": expected_family,
            "statistic_id": statistic_id,
            "observed_statistic": observed_value,
            "ordered_null_statistics": null_values,
            "null_replicate_count": 59,
            "null_success_count": null_success_count,
            "null_convergence_pass_count": null_convergence_pass_count,
            "null_exceedance_count": exceedance_count,
            "p_empirical": p_empirical,
            "null_median": null_median,
            "null_effect": null_effect,
            "identity_match": identity_match,
            "refit_steps_equal": refit_steps_equal,
            "criterion_state": criterion_state,
        },
        numeric_derivation_failure,
    )


def _derive_candidate_strong_evidence_decision(
    null_calibration_identity: Mapping[str, object],
    opportunity_id: str,
    observed_fit_evidence: Mapping[str, object],
    ordered_null_fit_evidence: Sequence[Mapping[str, object]],
) -> CandidateStrongEvidenceDecision:
    if type(ordered_null_fit_evidence) not in {list, tuple}:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_NULL_FIT_CONTAINER",
            "Ordered null-fit evidence must be a plain list or tuple.",
        )
    if len(ordered_null_fit_evidence) != 177:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_NULL_FIT_TOTAL",
            "Candidate evaluation requires exactly 177 ordered null-fit records.",
        )
    if type(opportunity_id) is not str:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_OPPORTUNITY_ID",
            "Candidate opportunity ID must be a string.",
        )

    identity = _copy_object(null_calibration_identity)
    observed = _copy_object(observed_fit_evidence)
    _validate_fit_semantics(observed, null_fit=False)
    null_rows: list[dict[str, object]] = []
    for row in ordered_null_fit_evidence:
        copied_row = _copy_object(row)
        _validate_fit_semantics(copied_row, null_fit=True)
        null_rows.append(copied_row)

    identity_digest = _structured_digest(_IDENTITY_DOMAIN, identity)
    observed_refit_steps = _validate_refit_steps_digest(observed)
    _validate_operation_role(
        observed,
        opportunity_id=opportunity_id,
        null_fit=False,
    )
    null_refit_steps: list[dict[str, object]] = []
    for row in null_rows:
        null_refit_steps.append(_validate_refit_steps_digest(row))
        _validate_operation_role(
            row,
            opportunity_id=opportunity_id,
            null_fit=True,
        )
    benchmark_subject_digest = cast(str, identity["benchmark_subject_digest"])
    actual_slots = tuple(
        (cast(str, row["null_family_id"]), cast(int, row["replicate_index"])) for row in null_rows
    )
    family_counts = tuple(
        sum(row["null_family_id"] == family for row in null_rows) for family in _NULL_FAMILIES
    )
    slot_order_matches = actual_slots == _EXPECTED_SLOTS
    observed_identity_matches = (
        observed_refit_steps["null_calibration_identity_digest"] == identity_digest
        and observed["benchmark_subject_digest"] == benchmark_subject_digest
    )
    all_identity_matches = observed_identity_matches and all(
        refit_steps["null_calibration_identity_digest"] == identity_digest
        and row["benchmark_subject_digest"] == benchmark_subject_digest
        for row, refit_steps in zip(null_rows, null_refit_steps, strict=True)
    )
    all_refit_steps_equal = all(
        refit_steps["refit_steps_digest"] == observed_refit_steps["refit_steps_digest"]
        for refit_steps in null_refit_steps
    )
    all_statistics_finite = all(
        _strict_nullable_number(observed[field_name]) for field_name in _FIT_NUMERIC_FIELDS
    ) and all(
        _strict_nullable_number(row[field_name])
        for row in null_rows
        for field_name in _FIT_NUMERIC_FIELDS
    )

    failed: set[str] = set()
    if observed["fit_state"] != "SUCCESS":
        failed.add("OBSERVED_FIT_NOT_SUCCESS")
    if observed["convergence_state"] != "CONVERGENCE_PASS":
        failed.add("OBSERVED_CONVERGENCE_NOT_PASS")
    if any(count != 59 for count in family_counts):
        failed.add("NULL_FIT_COUNT_NOT_59")
    if any(row["fit_state"] != "SUCCESS" for row in null_rows):
        failed.add("NULL_FIT_NOT_SUCCESS")
    if any(row["convergence_state"] != "CONVERGENCE_PASS" for row in null_rows):
        failed.add("NULL_CONVERGENCE_NOT_PASS")
    if not all_statistics_finite:
        failed.add("NONFINITE_STATISTIC")
    if not all_identity_matches:
        failed.add("NULL_CALIBRATION_IDENTITY_MISMATCH")
    if not all_refit_steps_equal:
        failed.add("REFIT_STEPS_DIFFER")
    if not slot_order_matches:
        failed.add("MISSING_OR_DUPLICATE_EVIDENCE")
    if observed["hard_failure"] is True or any(row["hard_failure"] is True for row in null_rows):
        failed.add("HARD_FAILURE")

    tests: list[dict[str, object]] = []
    numeric_derivation_failure = False
    for family in _NULL_FAMILIES:
        family_claim_rows = tuple(row for row in null_rows if row["null_family_id"] == family)
        family_slots = tuple(
            matching_rows[0] if len(matching_rows) == 1 else None
            for replicate_index in range(59)
            for matching_rows in (
                tuple(
                    row for row in family_claim_rows if row["replicate_index"] == replicate_index
                ),
            )
        )
        for statistic_id, statistic_field in _STATISTICS:
            test, test_numeric_failure = _test_record(
                expected_family=family,
                statistic_id=statistic_id,
                statistic_field=statistic_field,
                observed=observed,
                family_slots=family_slots,
                family_claim_rows=family_claim_rows,
                global_slots_match=slot_order_matches,
                identity_digest=identity_digest,
                benchmark_subject_digest=benchmark_subject_digest,
            )
            tests.append(test)
            numeric_derivation_failure = numeric_derivation_failure or test_numeric_failure

    if numeric_derivation_failure:
        failed.add("NONFINITE_STATISTIC")

    failed_codes = tuple(code for code in _FAILED_PRECONDITION_ORDER if code in failed)
    if failed_codes:
        state = "CANDIDATE_STRONG_EVIDENCE_NOT_ASSESSABLE"
    elif all(test["criterion_state"] == "STRONG_CRITERION" for test in tests):
        state = "CANDIDATE_STRONG_EVIDENCE"
    else:
        state = "CANDIDATE_NOT_STRONG_EVIDENCE"
    projection: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "rule_id": _RULE_ID,
        "benchmark_subject_digest": benchmark_subject_digest,
        "null_calibration_identity": identity,
        "null_calibration_identity_digest": identity_digest,
        "opportunity_id": opportunity_id,
        "observed_fit_state": observed["fit_state"],
        "observed_convergence_state": observed["convergence_state"],
        "observed_fit_evidence": observed,
        "ordered_null_fit_evidence": null_rows,
        "ordered_tests": tests,
        "failed_precondition_codes": list(failed_codes),
        "state": state,
    }
    _validate_decision_semantics(projection)
    canonical_bytes = _canonical_bytes(projection)
    decision_sha256 = _structured_digest(_DECISION_DOMAIN, projection)
    return CandidateStrongEvidenceDecision(
        canonical_bytes=canonical_bytes,
        decision_sha256=decision_sha256,
        state=state,
        failed_precondition_codes=failed_codes,
    )


def _candidate_strong_evidence_decision_digest(
    decision: Mapping[str, object] | CandidateStrongEvidenceDecision,
) -> str:
    if type(decision) is CandidateStrongEvidenceDecision:
        decoded = _STRICT_JSON_LOADS(decision.canonical_bytes)
        if type(decoded) is not dict or _canonical_bytes(decoded) != decision.canonical_bytes:
            raise _invalid_input(
                "EVALUATOR.CANDIDATE_DECISION_CANONICAL_BYTES",
                "Candidate-decision canonical bytes are invalid.",
            )
        projection = cast(dict[str, object], decoded)
    else:
        projection = _copy_object(cast(Mapping[str, object], decision))
    _validate_decision_semantics(projection)
    return _structured_digest(_DECISION_DOMAIN, projection)


def _copy_candidate_strong_evidence_decision(
    decision: Mapping[str, object],
) -> dict[str, object]:
    projection = _copy_object(decision)
    _validate_decision_semantics(projection)
    return projection


_CANDIDATE_DECISION_DERIVATION = build_frozen_derivation_graph(
    globals(),
    module_name=__name__,
    root_names=(
        "_null_calibration_identity_digest",
        "_derive_candidate_strong_evidence_decision",
        "_candidate_strong_evidence_decision_digest",
        "_copy_candidate_strong_evidence_decision",
    ),
    record_type_names=(),
)

_FROZEN_IDENTITY_DIGEST = _CANDIDATE_DECISION_DERIVATION.functions[
    "_null_calibration_identity_digest"
]
_FROZEN_DERIVE = _CANDIDATE_DECISION_DERIVATION.functions[
    "_derive_candidate_strong_evidence_decision"
]
_FROZEN_DECISION_DIGEST = _CANDIDATE_DECISION_DERIVATION.functions[
    "_candidate_strong_evidence_decision_digest"
]
_FROZEN_DECISION_COPY = _CANDIDATE_DECISION_DERIVATION.functions[
    "_copy_candidate_strong_evidence_decision"
]


def _build_candidate_decision_api(
    *,
    validate_schema: Callable[..., None],
    schema_error_type: type[SchemaValidationError],
    invalid_input_type: type[InvalidInputError],
    strict_loads: Callable[[bytes | bytearray | memoryview], Any],
    canonical_bytes: Callable[[object], bytes],
    canonical_error_type: type[CanonicalizationError],
    result_type: type[CandidateStrongEvidenceDecision],
    frozen_identity_digest: Callable[[Mapping[str, object]], str],
    frozen_derive: Callable[
        [
            Mapping[str, object],
            str,
            Mapping[str, object],
            Sequence[Mapping[str, object]],
        ],
        CandidateStrongEvidenceDecision,
    ],
    frozen_decision_digest: Callable[
        [Mapping[str, object] | CandidateStrongEvidenceDecision],
        str,
    ],
    frozen_decision_copy: Callable[[Mapping[str, object]], dict[str, object]],
) -> tuple[
    Callable[[Mapping[str, object]], str],
    Callable[
        [
            Mapping[str, object],
            str,
            Mapping[str, object],
            Sequence[Mapping[str, object]],
        ],
        CandidateStrongEvidenceDecision,
    ],
    Callable[[Mapping[str, object] | CandidateStrongEvidenceDecision], str],
    Callable[
        [Mapping[str, object] | CandidateStrongEvidenceDecision],
        CandidateStrongEvidenceDecision,
    ],
]:
    """Capture validation leaves once around the source-frozen calculation."""

    schema_name = _SCHEMA_NAME
    identity_definition = _IDENTITY_DEFINITION
    observed_definition = _OBSERVED_DEFINITION
    null_definition = _NULL_DEFINITION
    decision_definition = _DECISION_DEFINITION

    def invalid(code: str, message: str) -> InvalidInputError:
        return invalid_input_type(code, message)

    def schema(value: object, definition: str) -> None:
        try:
            validate_schema(value, schema_name, definition=definition)
        except schema_error_type:
            raise invalid(
                "EVALUATOR.CANDIDATE_DECISION_SCHEMA",
                "Candidate-decision input failed its closed schema.",
            ) from None

    def canonical(value: object) -> bytes:
        try:
            return canonical_bytes(value)
        except canonical_error_type:
            raise invalid(
                "EVALUATOR.CANDIDATE_DECISION_JSON",
                "Candidate-decision input is outside the canonical JSON data model.",
            ) from None

    def decode(value: bytes) -> dict[str, object]:
        try:
            decoded = strict_loads(value)
        except canonical_error_type:
            raise invalid(
                "EVALUATOR.CANDIDATE_DECISION_CANONICAL_BYTES",
                "Candidate-decision canonical bytes are invalid.",
            ) from None
        if type(decoded) is not dict or canonical(decoded) != value:
            raise invalid(
                "EVALUATOR.CANDIDATE_DECISION_CANONICAL_BYTES",
                "Candidate-decision canonical bytes are invalid.",
            )
        return cast(dict[str, object], decoded)

    def identity_digest(identity: Mapping[str, object]) -> str:
        schema(identity, identity_definition)
        return frozen_identity_digest(identity)

    def derive(
        null_calibration_identity: Mapping[str, object],
        opportunity_id: str,
        observed_fit_evidence: Mapping[str, object],
        ordered_null_fit_evidence: Sequence[Mapping[str, object]],
    ) -> CandidateStrongEvidenceDecision:
        if type(ordered_null_fit_evidence) not in {list, tuple}:
            raise invalid(
                "EVALUATOR.CANDIDATE_NULL_FIT_CONTAINER",
                "Ordered null-fit evidence must be a plain list or tuple.",
            )
        if len(ordered_null_fit_evidence) != 177:
            raise invalid(
                "EVALUATOR.CANDIDATE_NULL_FIT_TOTAL",
                "Candidate evaluation requires exactly 177 ordered null-fit records.",
            )
        schema(null_calibration_identity, identity_definition)
        schema(observed_fit_evidence, observed_definition)
        for row in ordered_null_fit_evidence:
            schema(row, null_definition)
        result = frozen_derive(
            null_calibration_identity,
            opportunity_id,
            observed_fit_evidence,
            ordered_null_fit_evidence,
        )
        schema(result.as_dict(), decision_definition)
        return result

    def decision_digest(
        decision: Mapping[str, object] | CandidateStrongEvidenceDecision,
    ) -> str:
        if type(decision) is result_type:
            projection = decode(decision.canonical_bytes)
        else:
            schema(decision, decision_definition)
            projection = frozen_decision_copy(cast(Mapping[str, object], decision))
        schema(projection, decision_definition)
        return frozen_decision_digest(projection)

    def validate(
        decision: Mapping[str, object] | CandidateStrongEvidenceDecision,
    ) -> CandidateStrongEvidenceDecision:
        supplied_digest: str | None = None
        if type(decision) is result_type:
            decoded = decode(decision.canonical_bytes)
            schema(decoded, decision_definition)
            projection = frozen_decision_copy(decoded)
            supplied_digest = decision.decision_sha256
            if decision.state != projection.get("state") or list(
                decision.failed_precondition_codes
            ) != projection.get("failed_precondition_codes"):
                raise invalid(
                    "EVALUATOR.CANDIDATE_DECISION_DERIVATION_MISMATCH",
                    "Candidate-decision computed fields do not match their evidence.",
                )
        else:
            schema(decision, decision_definition)
            projection = frozen_decision_copy(cast(Mapping[str, object], decision))
        schema(projection, decision_definition)
        expected = derive(
            cast(dict[str, object], projection["null_calibration_identity"]),
            cast(str, projection["opportunity_id"]),
            cast(dict[str, object], projection["observed_fit_evidence"]),
            cast(list[dict[str, object]], projection["ordered_null_fit_evidence"]),
        )
        if canonical(projection) != expected.canonical_bytes or (
            supplied_digest is not None and supplied_digest != expected.decision_sha256
        ):
            raise invalid(
                "EVALUATOR.CANDIDATE_DECISION_DERIVATION_MISMATCH",
                "Candidate-decision computed fields do not match their evidence.",
            )
        return expected

    return identity_digest, derive, decision_digest, validate


(
    null_calibration_identity_digest,
    _derive_candidate_strong_evidence_decision_api,
    candidate_strong_evidence_decision_digest,
    validate_candidate_strong_evidence_decision,
) = _build_candidate_decision_api(
    validate_schema=validate_instance,
    schema_error_type=SchemaValidationError,
    invalid_input_type=InvalidInputError,
    strict_loads=strict_json_loads,
    canonical_bytes=canonical_json_bytes,
    canonical_error_type=CanonicalizationError,
    result_type=CandidateStrongEvidenceDecision,
    frozen_identity_digest=_FROZEN_IDENTITY_DIGEST,
    frozen_derive=_FROZEN_DERIVE,
    frozen_decision_digest=_FROZEN_DECISION_DIGEST,
    frozen_decision_copy=_FROZEN_DECISION_COPY,
)


@dataclass(frozen=True, slots=True)
class _DerivedDecisionProvenance:
    canonical_bytes: bytes
    decision_sha256: str


_GENUINE_DERIVED_DECISIONS: OneShotWeakRegistry[
    CandidateStrongEvidenceDecision, _DerivedDecisionProvenance
]
_GENUINE_DERIVED_DECISIONS, _GENUINE_DERIVED_DECISION_ISSUER = (
    create_one_shot_registry()
)


def derive_candidate_strong_evidence_decision(
    null_calibration_identity: Mapping[str, object],
    opportunity_id: str,
    observed_fit_evidence: Mapping[str, object],
    ordered_null_fit_evidence: Sequence[Mapping[str, object]],
) -> CandidateStrongEvidenceDecision:
    decision = _derive_candidate_strong_evidence_decision_api(
        null_calibration_identity,
        opportunity_id,
        observed_fit_evidence,
        ordered_null_fit_evidence,
    )
    _GENUINE_DERIVED_DECISION_ISSUER.bind_once(
        decision,
        _DerivedDecisionProvenance(
            canonical_bytes=decision.canonical_bytes,
            decision_sha256=decision.decision_sha256,
        ),
    )
    return decision


@dataclass(frozen=True, slots=True)
class _ContextBoundDecisionState:
    context: object
    decision: CandidateStrongEvidenceDecision
    projection_bytes: bytes
    benchmark_subject_digest: str
    family_id: str
    case_id: str
    opportunity_id: str


@final
class _ContextBoundCandidateStrongEvidenceDecision:
    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> _ContextBoundCandidateStrongEvidenceDecision:
        raise TypeError("Context-bound candidate decisions are privately issued.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Context-bound candidate decisions cannot be serialized.")


_CONTEXT_BOUND_DECISIONS: OneShotWeakRegistry[
    _ContextBoundCandidateStrongEvidenceDecision, _ContextBoundDecisionState
]
_CONTEXT_BOUND_DECISIONS, _CONTEXT_BOUND_DECISION_ISSUER = create_one_shot_registry()
_SOURCE_BINDING_LOCK = RLock()
_SOURCE_BOUND_DECISIONS: WeakSet[_ContextBoundCandidateStrongEvidenceDecision] = WeakSet()


def _validated_context_bound_candidate_decision(
    owner: object,
    context: object,
) -> dict[str, object]:
    from ebm_audit.evaluator.scenario_evidence import (
        _AuthenticatedScenarioEvidenceContext,
        _read_scenario_evidence_context,
    )

    if (
        type(owner) is not _ContextBoundCandidateStrongEvidenceDecision
        or type(context) is not _AuthenticatedScenarioEvidenceContext
    ):
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_CONTEXT",
            "Candidate-decision capability is not bound to an authenticated context.",
        )
    try:
        state = _CONTEXT_BOUND_DECISIONS.read(owner)
        validated = validate_candidate_strong_evidence_decision(state.decision)
        context_state = _read_scenario_evidence_context(context)
        projection = validated.as_dict()
    except Exception:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_CONTEXT",
            "Candidate-decision capability failed closed validation.",
        ) from None
    if (
        state.context is not context
        or validated.canonical_bytes != state.projection_bytes
        or projection.get("benchmark_subject_digest")
        != context_state.identity.benchmark_subject_digest
        or projection.get("benchmark_subject_digest") != state.benchmark_subject_digest
        or context_state.identity.family_id != state.family_id
        or context_state.identity.case_id != state.case_id
        or projection.get("opportunity_id") != state.opportunity_id
        or state.opportunity_id != state.case_id
    ):
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_CONTEXT",
            "Candidate-decision capability does not match its authenticated context.",
        )
    return projection


def _issue_context_bound_candidate_strong_evidence_decision(
    context: object,
    decision: CandidateStrongEvidenceDecision,
) -> _ContextBoundCandidateStrongEvidenceDecision:
    from ebm_audit.evaluator.scenario_evidence import (
        _AuthenticatedScenarioEvidenceContext,
        _read_scenario_evidence_context,
    )

    if (
        type(context) is not _AuthenticatedScenarioEvidenceContext
        or type(decision) is not CandidateStrongEvidenceDecision
    ):
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_CONTEXT",
            "Candidate-decision issuance requires genuine validated owners.",
        )
    try:
        provenance = _GENUINE_DERIVED_DECISIONS.read(decision)
    except Exception:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_CONTEXT",
            "Candidate-decision issuance rejects caller-created decision objects.",
        ) from None
    if (
        provenance.canonical_bytes != decision.canonical_bytes
        or provenance.decision_sha256 != decision.decision_sha256
    ):
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_CONTEXT",
            "Candidate-decision issuance rejects changed derived evidence.",
        )
    validated = validate_candidate_strong_evidence_decision(decision)
    context_state = _read_scenario_evidence_context(context)
    projection = validated.as_dict()
    opportunity_id = projection.get("opportunity_id")
    if (
        projection.get("benchmark_subject_digest")
        != context_state.identity.benchmark_subject_digest
        or type(opportunity_id) is not str
        or opportunity_id != context_state.identity.case_id
    ):
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_CONTEXT",
            "Candidate-decision identity does not match its authenticated case.",
        )
    owner = object.__new__(_ContextBoundCandidateStrongEvidenceDecision)
    _CONTEXT_BOUND_DECISION_ISSUER.bind_once(
        owner,
        _ContextBoundDecisionState(
            context=context,
            decision=decision,
            projection_bytes=validated.canonical_bytes,
            benchmark_subject_digest=context_state.identity.benchmark_subject_digest,
            family_id=context_state.identity.family_id,
            case_id=context_state.identity.case_id,
            opportunity_id=opportunity_id,
        ),
    )
    _validated_context_bound_candidate_decision(owner, context)
    return owner


def _read_context_bound_candidate_strong_evidence_decision(
    owner: object,
    context: object,
) -> dict[str, object]:
    return _validated_context_bound_candidate_decision(owner, context)


def _candidate_strong_evidence_decision_source_record(
    owner: object,
    *,
    bind: bool = True,
) -> _ScenarioSourceRecordInput:
    from ebm_audit.evaluator.scenario_source_owner_manifest import (
        _ScenarioSourceRecordInput,
    )

    if type(owner) is not _ContextBoundCandidateStrongEvidenceDecision:
        raise _invalid_input(
            "EVALUATOR.CANDIDATE_DECISION_CONTEXT",
            "Candidate-decision source owner is invalid.",
        )
    state = _CONTEXT_BOUND_DECISIONS.read(owner)
    projection = _validated_context_bound_candidate_decision(owner, state.context)
    if bind:
        with _SOURCE_BINDING_LOCK:
            if owner in _SOURCE_BOUND_DECISIONS:
                raise _invalid_input(
                    "EVALUATOR.CANDIDATE_DECISION_REPLAY",
                    "Candidate-decision source owner was already bound.",
                )
            _SOURCE_BOUND_DECISIONS.add(owner)
    identity = {
        field: cast(str, projection[field])
        for field in ("benchmark_subject_digest", "rule_id", "opportunity_id")
    }
    return _ScenarioSourceRecordInput(
        owner_class="CANDIDATE_STRONG_EVIDENCE_DECISION",
        owner_schema_ref=(
            "schemas/scientific-invariant.schema.json"
            "#/$defs/CandidateStrongEvidenceDecision"
        ),
        source_relative_path=(
            "owners/candidate-strong-evidence-decisions/"
            f"{state.decision.decision_sha256}.json"
        ),
        source_content_bytes=state.projection_bytes,
        source_record_bytes=state.projection_bytes,
        natural_identity=identity,
        source_capability=owner,
    )

__all__ = [
    "CandidateStrongEvidenceDecision",
    "candidate_strong_evidence_decision_digest",
    "derive_candidate_strong_evidence_decision",
    "null_calibration_identity_digest",
    "validate_candidate_strong_evidence_decision",
]
