"""Frozen fixed-cohort participant-stage comparison derivation.

One derivation owns both representations of the result:

* canonical private bytes retaining every fixed-cohort participant result; and
* a privacy-safe public projection containing only provenance, counts, and
  aggregate metrics.

The private record is never returned through the public science projection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from math import fsum as _math_fsum
from math import isfinite as _math_isfinite
from typing import Final, Literal, cast

from ebm_audit.metrics import (
    StageComparisonIdentity,
    cohort_normalized_stage_wasserstein,
    empirical_quantile,
    normalized_stage_jensen_shannon_distance,
    normalized_stage_wasserstein,
    stage_expected_movement,
    stage_map_agreement,
    strict_order_comparison,
)
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256

from ._frozen_derivation import build_frozen_derivation_graph

STAGE_COMPARISON_SCHEMA_VERSION: Final = "ebm-audit-stage-comparison/2.0"
STAGE_COMPARISON_RULE_ID: Final = "fixed-evaluation-cohort-native-stage-comparison/2"
PRIVATE_STAGE_COMPARISON_SCHEMA_VERSION: Final = "ebm-audit-private-stage-comparison-evidence/1.0"
PRIVATE_STAGE_COMPARISON_DIGEST_DOMAIN: Final = "ebm-audit/private-stage-comparison-evidence/1"
PARTICIPANT_SELECTION_SOURCE: Final = "FIXED_EVALUATION_COHORT"
STAGE_QUANTILE_RULE_ID: Final = "inverse-empirical-cdf/1"

_CAPABILITY_REASON: Final = "STAGING.FIXED_COHORT_UNAVAILABLE"
_NON_EQUIVALENT_REASON: Final = "COMPARISON.SEMANTICALLY_NON_EQUIVALENT"
_SEMANTICS_UNAVAILABLE_REASON: Final = "STAGE.SEMANTICS_NOT_ASSESSABLE"
_INPUT_UNAVAILABLE_REASON: Final = "STAGE.INPUT_NOT_ASSESSABLE"
_PRIVATE_INPUT_REASON: Final = "STAGE.INVALID_PRIVATE_INPUT"
_COHORT_MISMATCH_REASON: Final = "STAGE.EVALUATION_COHORT_MISMATCH"
_ROW_MISMATCH_REASON: Final = "STAGE.EVALUATION_ROW_ALIGNMENT_MISMATCH"
_BINDING_MISMATCH_REASON: Final = "STAGE.EVALUATION_UNIT_BINDING_MISMATCH"
_INCOMPLETE_DERIVATION_REASON: Final = "STAGE.INCOMPLETE_FIXED_COHORT_DERIVATION"

_SAFE_INTEGER_MAX: Final = 9_007_199_254_740_991
_SHA256_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PRIVATE_UNIT_PATTERN: Final = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
_REASON_PATTERN: Final = re.compile(r"[A-Z][A-Z0-9]*(?:\.[A-Z][A-Z0-9_]*)+\Z")

_QUANTILE_PROBABILITIES: Final = (0.10, 0.25, 0.50, 0.75, 0.90)
_METRIC_IDS: Final = (
    "fixed-cohort-stage-wasserstein-median/1",
    "fixed-cohort-stage-wasserstein-maximum/1",
    "mean-left-expected-stage/1",
    "mean-right-expected-stage/1",
    "mean-signed-expected-stage-change/1",
    "mean-absolute-expected-stage-change/1",
    "mean-normalized-absolute-expected-stage-change/1",
    "map-stage-agreement-fraction/1",
    "mean-normalized-stage-wasserstein/1",
    "cohort-normalized-stage-wasserstein/1",
    "mean-normalized-stage-jensen-shannon/1",
)

type _Availability = Literal[
    "AVAILABLE",
    "NOT_APPLICABLE_BY_CAPABILITY",
    "NOT_ASSESSABLE",
]
type _SemanticComparability = Literal[
    "COMPARABLE",
    "SEMANTICALLY_NON_EQUIVALENT",
    "NOT_ASSESSABLE",
]
type _MetricStatus = Literal[
    "ASSESSABLE",
    "NOT_APPLICABLE_BY_CAPABILITY",
    "NOT_ASSESSABLE",
]


class _StageComparisonInputError(ValueError):
    """A private comparison input violates its closed structural contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, repr=False, slots=True)
class _StageComparisonSideInput:
    """One authenticated side of a fixed-cohort stage comparison.

    Row identities, array digests, unit bindings, and posteriors are private
    source evidence. The stage-reference and headline orders are safe public
    provenance only after the capture boundary has authenticated them.
    """

    availability: _Availability
    availability_reason_code: str | None
    ordered_event_ids: tuple[str, ...]
    ordered_event_directions: tuple[Literal["higher", "lower"], ...]
    stage_semantics_digest: str | None
    stage_model_reference_digest: str | None
    reference_order_event_ids: tuple[str, ...] | None
    headline_central_order_event_ids: tuple[str, ...] | None
    evaluation_cohort_digest: str | None = field(repr=False)
    evaluation_row_indexes_digest: str | None = field(repr=False)
    evaluation_stage_posterior_digest: str | None = field(repr=False)
    evaluation_row_indexes: tuple[int, ...] | None = field(repr=False)
    evaluation_unit_bindings: tuple[str, ...] | None = field(repr=False)
    evaluation_stage_posteriors: tuple[tuple[float, ...], ...] | None = field(repr=False)


@dataclass(frozen=True, repr=False, slots=True)
class _DerivedStageComparison:
    """Canonical private evidence and its separate public projection."""

    private_evidence_bytes: bytes
    private_evidence_digest: str
    public_projection_bytes: bytes


def _raise_input(code: str) -> None:
    raise _StageComparisonInputError(code)


def _valid_reason(value: object) -> bool:
    return type(value) is str and _REASON_PATTERN.fullmatch(value) is not None


def _valid_digest(value: object) -> bool:
    return type(value) is str and _SHA256_PATTERN.fullmatch(value) is not None


def _valid_event_order(
    value: object,
    *,
    event_ids: tuple[str, ...],
) -> bool:
    if type(value) is not tuple:
        return False
    exact = cast(tuple[object, ...], value)
    if any(type(event_id) is not str for event_id in exact):
        return False
    comparison = strict_order_comparison(
        cast(tuple[str, ...], exact),
        event_ids,
    )
    return (
        comparison.common_event_count == len(event_ids)
        and not comparison.events_only_in_left
        and not comparison.events_only_in_right
        and len(exact) == len(event_ids)
    )


def _validate_public_side(side: object) -> _StageComparisonSideInput:
    if type(side) is not _StageComparisonSideInput:
        _raise_input("STAGE.INVALID_INPUT_TYPE")
    exact = cast(_StageComparisonSideInput, side)
    if exact.availability not in {
        "AVAILABLE",
        "NOT_APPLICABLE_BY_CAPABILITY",
        "NOT_ASSESSABLE",
    }:
        _raise_input("STAGE.INVALID_AVAILABILITY")
    if type(exact.ordered_event_ids) is not tuple or not exact.ordered_event_ids:
        _raise_input("STAGE.INVALID_EVENT_SEMANTICS")
    accounting = strict_order_comparison(
        exact.ordered_event_ids,
        exact.ordered_event_ids,
    )
    if (
        accounting.common_event_count != len(exact.ordered_event_ids)
        or accounting.events_only_in_left
        or accounting.events_only_in_right
    ):
        _raise_input("STAGE.INVALID_EVENT_SEMANTICS")
    if (
        type(exact.ordered_event_directions) is not tuple
        or len(exact.ordered_event_directions) != len(exact.ordered_event_ids)
        or any(direction not in {"higher", "lower"} for direction in exact.ordered_event_directions)
    ):
        _raise_input("STAGE.INVALID_EVENT_SEMANTICS")
    if exact.stage_semantics_digest is not None and not _valid_digest(exact.stage_semantics_digest):
        _raise_input("STAGE.INVALID_STAGE_SEMANTICS_DIGEST")
    if exact.availability == "AVAILABLE":
        if (
            exact.availability_reason_code is not None
            or exact.stage_semantics_digest is None
            or not _valid_digest(exact.stage_model_reference_digest)
            or not _valid_event_order(
                exact.reference_order_event_ids,
                event_ids=exact.ordered_event_ids,
            )
            or not _valid_event_order(
                exact.headline_central_order_event_ids,
                event_ids=exact.ordered_event_ids,
            )
            or exact.evaluation_cohort_digest is None
            or exact.evaluation_row_indexes_digest is None
            or exact.evaluation_stage_posterior_digest is None
            or exact.evaluation_row_indexes is None
            or exact.evaluation_unit_bindings is None
            or exact.evaluation_stage_posteriors is None
        ):
            _raise_input("STAGE.INCONSISTENT_AVAILABLE_INPUT")
    else:
        if not _valid_reason(exact.availability_reason_code):
            _raise_input("STAGE.INVALID_AVAILABILITY_REASON")
        if exact.availability == "NOT_APPLICABLE_BY_CAPABILITY" and (
            exact.availability_reason_code != _CAPABILITY_REASON
        ):
            _raise_input("STAGE.INVALID_CAPABILITY_REASON")
        if any(
            value is not None
            for value in (
                exact.stage_model_reference_digest,
                exact.reference_order_event_ids,
                exact.headline_central_order_event_ids,
                exact.evaluation_cohort_digest,
                exact.evaluation_row_indexes_digest,
                exact.evaluation_stage_posterior_digest,
                exact.evaluation_row_indexes,
                exact.evaluation_unit_bindings,
                exact.evaluation_stage_posteriors,
            )
        ):
            _raise_input("STAGE.INCONSISTENT_UNAVAILABLE_INPUT")
    return exact


def _private_input_is_well_formed(side: _StageComparisonSideInput) -> bool:
    cohort_digest = side.evaluation_cohort_digest
    row_digest = side.evaluation_row_indexes_digest
    posterior_digest = side.evaluation_stage_posterior_digest
    row_indexes = side.evaluation_row_indexes
    unit_bindings = side.evaluation_unit_bindings
    posteriors = side.evaluation_stage_posteriors
    return not (
        not _valid_digest(cohort_digest)
        or not _valid_digest(row_digest)
        or not _valid_digest(posterior_digest)
        or type(row_indexes) is not tuple
        or type(unit_bindings) is not tuple
        or type(posteriors) is not tuple
        or len(row_indexes) != len(unit_bindings)
        or len(row_indexes) != len(posteriors)
        or any(
            type(index) is not int or not 0 <= index <= _SAFE_INTEGER_MAX for index in row_indexes
        )
        or len(set(row_indexes)) != len(row_indexes)
        or any(
            type(binding) is not str or _PRIVATE_UNIT_PATTERN.fullmatch(binding) is None
            for binding in unit_bindings
        )
        or len(set(unit_bindings)) != len(unit_bindings)
        or any(type(row) is not tuple for row in posteriors)
        or any(
            len(row) != len(side.ordered_event_ids) + 1
            or any(
                type(value) not in {int, float}
                or not _math_isfinite(float(cast(int | float, value)))
                for value in row
            )
            for row in posteriors
        )
    )


def _declared_availability(
    left: _StageComparisonSideInput,
    right: _StageComparisonSideInput,
) -> tuple[_Availability, str | None]:
    statuses = {left.availability, right.availability}
    if statuses == {"AVAILABLE"}:
        return "AVAILABLE", None
    if "NOT_ASSESSABLE" in statuses:
        return "NOT_ASSESSABLE", _INPUT_UNAVAILABLE_REASON
    return "NOT_APPLICABLE_BY_CAPABILITY", _CAPABILITY_REASON


def _semantic_comparability(
    left: _StageComparisonSideInput,
    right: _StageComparisonSideInput,
    *,
    same_ordered_event_ids: bool,
    same_event_direction_bindings: bool,
) -> tuple[_SemanticComparability, str | None, bool | None]:
    left_digest = left.stage_semantics_digest
    right_digest = right.stage_semantics_digest
    same_stage_semantics = (
        left_digest == right_digest
        if left_digest is not None and right_digest is not None
        else None
    )
    if (
        not same_ordered_event_ids
        or not same_event_direction_bindings
        or same_stage_semantics is False
    ):
        return "SEMANTICALLY_NON_EQUIVALENT", _NON_EQUIVALENT_REASON, same_stage_semantics
    if same_stage_semantics is None:
        return "NOT_ASSESSABLE", _SEMANTICS_UNAVAILABLE_REASON, None
    return "COMPARABLE", None, True


def _metric_rows(
    status: _MetricStatus,
    *,
    reason_code: str | None,
    values: tuple[float, ...] | None = None,
) -> list[dict[str, object]]:
    if status == "ASSESSABLE":
        if values is None or len(values) != len(_METRIC_IDS) or reason_code is not None:
            raise AssertionError("Assessable stage metrics require every finite value.")
        return [
            {
                "metric_id": metric_id,
                "status": status,
                "value": value,
                "reason_code": None,
            }
            for metric_id, value in zip(_METRIC_IDS, values, strict=True)
        ]
    if values is not None or reason_code is None:
        raise AssertionError("Unavailable stage metrics require one typed reason.")
    return [
        {
            "metric_id": metric_id,
            "status": status,
            "value": None,
            "reason_code": reason_code,
        }
        for metric_id in _METRIC_IDS
    ]


def _side_public_provenance(
    side: _StageComparisonSideInput,
    *,
    prefix: str,
) -> dict[str, object]:
    reference_order = side.reference_order_event_ids
    headline_order = side.headline_central_order_event_ids
    return {
        f"{prefix}_stage_model_reference_digest": side.stage_model_reference_digest,
        f"{prefix}_stage_reference_order_event_ids": (
            None if reference_order is None else list(reference_order)
        ),
        f"{prefix}_headline_central_order_event_ids": (
            None if headline_order is None else list(headline_order)
        ),
        f"{prefix}_stage_reference_order_matches_headline": (
            None
            if reference_order is None or headline_order is None
            else reference_order == headline_order
        ),
    }


def _base_record(
    left: _StageComparisonSideInput,
    right: _StageComparisonSideInput,
) -> tuple[dict[str, object], _SemanticComparability, str | None]:
    accounting = strict_order_comparison(
        left.ordered_event_ids,
        right.ordered_event_ids,
    )
    same_event_set = (
        not accounting.events_only_in_left
        and not accounting.events_only_in_right
        and accounting.common_event_count == len(left.ordered_event_ids)
        and accounting.common_event_count == len(right.ordered_event_ids)
    )
    same_ordered_event_ids = left.ordered_event_ids == right.ordered_event_ids
    same_event_direction_bindings = (
        same_ordered_event_ids and left.ordered_event_directions == right.ordered_event_directions
    )
    comparability, comparability_reason, same_stage_semantics = _semantic_comparability(
        left,
        right,
        same_ordered_event_ids=same_ordered_event_ids,
        same_event_direction_bindings=same_event_direction_bindings,
    )
    return (
        {
            "record_schema_version": STAGE_COMPARISON_SCHEMA_VERSION,
            "rule_id": STAGE_COMPARISON_RULE_ID,
            "left_availability": left.availability,
            "left_availability_reason_code": left.availability_reason_code,
            "right_availability": right.availability,
            "right_availability_reason_code": right.availability_reason_code,
            **_side_public_provenance(left, prefix="left"),
            **_side_public_provenance(right, prefix="right"),
            "left_ordered_event_ids": list(left.ordered_event_ids),
            "right_ordered_event_ids": list(right.ordered_event_ids),
            "common_event_ids": list(accounting.common_event_ids),
            "common_event_count": accounting.common_event_count,
            "left_only_event_ids": list(accounting.events_only_in_left),
            "right_only_event_ids": list(accounting.events_only_in_right),
            "same_event_set": same_event_set,
            "same_ordered_event_ids": same_ordered_event_ids,
            "same_event_direction_bindings": same_event_direction_bindings,
            "same_stage_semantics": same_stage_semantics,
            "semantic_comparability": comparability,
            "semantic_comparability_reason_code": comparability_reason,
            "participant_selection_source": PARTICIPANT_SELECTION_SOURCE,
            "quantile_rule_id": STAGE_QUANTILE_RULE_ID,
        },
        comparability,
        comparability_reason,
    )


def _empty_quantiles() -> dict[str, None]:
    return {
        "q10": None,
        "q25": None,
        "q50": None,
        "q75": None,
        "q90": None,
    }


def _unavailable_record(
    base: dict[str, object],
    *,
    availability: _Availability,
    availability_reason_code: str | None,
    metric_status: _MetricStatus,
    metric_reason_code: str,
    same_evaluation_cohort: bool | None = None,
    same_evaluation_row_indexes: bool | None = None,
    same_evaluation_unit_bindings: bool | None = None,
    evaluation_cohort_digest: str | None = None,
    cohort_denominator_count: int | None = None,
    valid_participant_count: int | None = None,
    missing_participant_count: int | None = None,
) -> dict[str, object]:
    return {
        **base,
        "availability": availability,
        "availability_reason_code": availability_reason_code,
        "same_evaluation_cohort": same_evaluation_cohort,
        "same_evaluation_row_indexes": same_evaluation_row_indexes,
        "same_evaluation_unit_bindings": same_evaluation_unit_bindings,
        "evaluation_cohort_digest": evaluation_cohort_digest,
        "evaluation_cohort_count": cohort_denominator_count,
        "cohort_denominator_count": cohort_denominator_count,
        "valid_participant_count": valid_participant_count,
        "missing_participant_count": missing_participant_count,
        "normalized_stage_wasserstein_quantiles": _empty_quantiles(),
        "normalized_stage_wasserstein_iqr": None,
        "metric_status": metric_status,
        "metric_reason_code": metric_reason_code,
        "metrics": _metric_rows(metric_status, reason_code=metric_reason_code),
    }


def _metric_value(result: object) -> tuple[float | None, str | None]:
    status = getattr(result, "status", None)
    value = getattr(result, "value", None)
    reason_code = getattr(result, "reason_code", None)
    if (
        status == "ASSESSABLE"
        and type(value) in {int, float}
        and _math_isfinite(float(cast(int | float, value)))
        and reason_code is None
    ):
        return float(cast(int | float, value)), None
    if status == "NOT_ASSESSABLE" and value is None and _valid_reason(reason_code):
        return None, cast(str, reason_code)
    return None, "STAGE.INVALID_METRIC_RESULT"


def _private_metric(result: object) -> dict[str, object]:
    value, reason_code = _metric_value(result)
    return {
        "status": "ASSESSABLE" if reason_code is None else "NOT_ASSESSABLE",
        "value": value,
        "reason_code": reason_code,
    }


def _private_map(result: object) -> dict[str, object]:
    status = getattr(result, "status", None)
    reason_code = getattr(result, "reason_code", None)
    if status == "ASSESSABLE":
        return {
            "status": status,
            "left_map_stage": getattr(result, "left_map_stage", None),
            "right_map_stage": getattr(result, "right_map_stage", None),
            "left_tied_stages": list(getattr(result, "left_tied_stages", ())),
            "right_tied_stages": list(getattr(result, "right_tied_stages", ())),
            "left_has_tie": getattr(result, "left_has_tie", None),
            "right_has_tie": getattr(result, "right_has_tie", None),
            "agreement": getattr(result, "agreement", None),
            "reason_code": None,
        }
    return {
        "status": "NOT_ASSESSABLE",
        "left_map_stage": None,
        "right_map_stage": None,
        "left_tied_stages": [],
        "right_tied_stages": [],
        "left_has_tie": None,
        "right_has_tie": None,
        "agreement": None,
        "reason_code": (
            reason_code if _valid_reason(reason_code) else "STAGE.INVALID_METRIC_RESULT"
        ),
    }


def _mean(values: tuple[float, ...]) -> float:
    return _math_fsum(values) / len(values)


def _quantile(values: tuple[float, ...], probability: float) -> float:
    value, reason_code = _metric_value(empirical_quantile(values, probability))
    if reason_code is not None or value is None:
        raise AssertionError("Validated finite stage values require an empirical quantile.")
    return value


def _seal_stage_result(
    *,
    left: _StageComparisonSideInput,
    right: _StageComparisonSideInput,
    public_preimage: dict[str, object],
    participant_results: list[dict[str, object]],
) -> _DerivedStageComparison:
    private_preimage: dict[str, object] = {
        "private_evidence_schema_version": PRIVATE_STAGE_COMPARISON_SCHEMA_VERSION,
        "rule_id": STAGE_COMPARISON_RULE_ID,
        "participant_selection_source": PARTICIPANT_SELECTION_SOURCE,
        "quantile_rule_id": STAGE_QUANTILE_RULE_ID,
        "left_source": {
            "stage_model_reference_digest": left.stage_model_reference_digest,
            "evaluation_cohort_digest": left.evaluation_cohort_digest,
            "evaluation_row_indexes_digest": left.evaluation_row_indexes_digest,
            "evaluation_stage_posterior_digest": (left.evaluation_stage_posterior_digest),
        },
        "right_source": {
            "stage_model_reference_digest": right.stage_model_reference_digest,
            "evaluation_cohort_digest": right.evaluation_cohort_digest,
            "evaluation_row_indexes_digest": right.evaluation_row_indexes_digest,
            "evaluation_stage_posterior_digest": (right.evaluation_stage_posterior_digest),
        },
        "participant_results": participant_results,
        "public_projection_preimage": public_preimage,
    }
    private_digest = structured_sha256(
        PRIVATE_STAGE_COMPARISON_DIGEST_DOMAIN,
        private_preimage,
    )
    public_projection = {
        **public_preimage,
        "private_evidence_digest": private_digest,
    }
    return _DerivedStageComparison(
        private_evidence_bytes=canonical_json_bytes(
            {
                **private_preimage,
                "private_evidence_digest": private_digest,
            }
        ),
        private_evidence_digest=private_digest,
        public_projection_bytes=canonical_json_bytes(public_projection),
    )


def derive_stage_comparison_owner(
    left: _StageComparisonSideInput,
    right: _StageComparisonSideInput,
) -> _DerivedStageComparison:
    """Derive private participant evidence and its public projection exactly once."""

    checked_left = _validate_public_side(left)
    checked_right = _validate_public_side(right)
    base, comparability, comparability_reason = _base_record(checked_left, checked_right)
    availability, availability_reason = _declared_availability(checked_left, checked_right)
    if availability != "AVAILABLE":
        metric_status: _MetricStatus = (
            "NOT_APPLICABLE_BY_CAPABILITY"
            if availability == "NOT_APPLICABLE_BY_CAPABILITY"
            else "NOT_ASSESSABLE"
        )
        return _seal_stage_result(
            left=checked_left,
            right=checked_right,
            public_preimage=_unavailable_record(
                base,
                availability=availability,
                availability_reason_code=availability_reason,
                metric_status=metric_status,
                metric_reason_code=cast(str, availability_reason),
            ),
            participant_results=[],
        )

    if not _private_input_is_well_formed(checked_left) or not _private_input_is_well_formed(
        checked_right
    ):
        return _seal_stage_result(
            left=checked_left,
            right=checked_right,
            public_preimage=_unavailable_record(
                base,
                availability="NOT_ASSESSABLE",
                availability_reason_code=_PRIVATE_INPUT_REASON,
                metric_status="NOT_ASSESSABLE",
                metric_reason_code=_PRIVATE_INPUT_REASON,
            ),
            participant_results=[],
        )

    left_cohort_digest = cast(str, checked_left.evaluation_cohort_digest)
    right_cohort_digest = cast(str, checked_right.evaluation_cohort_digest)
    left_row_indexes = cast(tuple[int, ...], checked_left.evaluation_row_indexes)
    right_row_indexes = cast(tuple[int, ...], checked_right.evaluation_row_indexes)
    left_bindings = cast(tuple[str, ...], checked_left.evaluation_unit_bindings)
    right_bindings = cast(tuple[str, ...], checked_right.evaluation_unit_bindings)
    same_cohort = left_cohort_digest == right_cohort_digest
    same_rows = left_row_indexes == right_row_indexes
    same_bindings = left_bindings == right_bindings
    if comparability != "COMPARABLE":
        reason = cast(str, comparability_reason)
        return _seal_stage_result(
            left=checked_left,
            right=checked_right,
            public_preimage=_unavailable_record(
                base,
                availability="AVAILABLE",
                availability_reason_code=None,
                metric_status="NOT_ASSESSABLE",
                metric_reason_code=reason,
                same_evaluation_cohort=same_cohort,
                same_evaluation_row_indexes=same_rows,
                same_evaluation_unit_bindings=same_bindings,
            ),
            participant_results=[],
        )
    for same, reason in (
        (same_cohort, _COHORT_MISMATCH_REASON),
        (same_rows, _ROW_MISMATCH_REASON),
        (same_bindings, _BINDING_MISMATCH_REASON),
    ):
        if not same:
            return _seal_stage_result(
                left=checked_left,
                right=checked_right,
                public_preimage=_unavailable_record(
                    base,
                    availability="AVAILABLE",
                    availability_reason_code=None,
                    metric_status="NOT_ASSESSABLE",
                    metric_reason_code=reason,
                    same_evaluation_cohort=same_cohort,
                    same_evaluation_row_indexes=same_rows,
                    same_evaluation_unit_bindings=same_bindings,
                ),
                participant_results=[],
            )
    if not left_row_indexes:
        return _seal_stage_result(
            left=checked_left,
            right=checked_right,
            public_preimage=_unavailable_record(
                base,
                availability="AVAILABLE",
                availability_reason_code=None,
                metric_status="NOT_ASSESSABLE",
                metric_reason_code="STAGE.EMPTY_EVALUATION_COHORT",
                same_evaluation_cohort=same_cohort,
                same_evaluation_row_indexes=same_rows,
                same_evaluation_unit_bindings=same_bindings,
            ),
            participant_results=[],
        )

    left_posteriors = cast(
        tuple[tuple[float, ...], ...],
        checked_left.evaluation_stage_posteriors,
    )
    right_posteriors = cast(
        tuple[tuple[float, ...], ...],
        checked_right.evaluation_stage_posteriors,
    )
    left_identities = tuple(
        StageComparisonIdentity(
            event_ids=checked_left.ordered_event_ids,
            event_directions=checked_left.ordered_event_directions,
            stage_semantics_digest=cast(str, checked_left.stage_semantics_digest),
            evaluation_cohort_digest=left_cohort_digest,
            evaluation_row_index=row_index,
            evaluation_unit_binding=unit_binding,
        )
        for row_index, unit_binding in zip(left_row_indexes, left_bindings, strict=True)
    )
    right_identities = tuple(
        StageComparisonIdentity(
            event_ids=checked_right.ordered_event_ids,
            event_directions=checked_right.ordered_event_directions,
            stage_semantics_digest=cast(str, checked_right.stage_semantics_digest),
            evaluation_cohort_digest=right_cohort_digest,
            evaluation_row_index=row_index,
            evaluation_unit_binding=unit_binding,
        )
        for row_index, unit_binding in zip(right_row_indexes, right_bindings, strict=True)
    )

    participant_results: list[dict[str, object]] = []
    metric_values_by_name: dict[str, list[float]] = {
        "left_expected_stage": [],
        "right_expected_stage": [],
        "signed_expected_stage_change": [],
        "absolute_expected_stage_change": [],
        "normalized_absolute_expected_stage_change": [],
        "normalized_stage_wasserstein": [],
        "normalized_stage_jensen_shannon": [],
    }
    map_agreements: list[float] = []
    for (
        row_index,
        unit_binding,
        left_posterior,
        right_posterior,
        left_identity,
        right_identity,
    ) in zip(
        left_row_indexes,
        left_bindings,
        left_posteriors,
        right_posteriors,
        left_identities,
        right_identities,
        strict=True,
    ):
        movement = stage_expected_movement(
            left_posterior,
            right_posterior,
            left_identity=left_identity,
            right_identity=right_identity,
        )
        wasserstein = normalized_stage_wasserstein(
            left_posterior,
            right_posterior,
            left_identity=left_identity,
            right_identity=right_identity,
        )
        js_distance = normalized_stage_jensen_shannon_distance(
            left_posterior,
            right_posterior,
            left_identity=left_identity,
            right_identity=right_identity,
        )
        map_result = stage_map_agreement(
            left_posterior,
            right_posterior,
            left_identity=left_identity,
            right_identity=right_identity,
        )
        component_results = {
            "left_expected_stage": movement.left_expected_stage,
            "right_expected_stage": movement.right_expected_stage,
            "signed_expected_stage_change": movement.signed_expected_stage_change,
            "absolute_expected_stage_change": movement.absolute_expected_stage_change,
            "normalized_absolute_expected_stage_change": (
                movement.normalized_absolute_expected_stage_change
            ),
            "normalized_stage_wasserstein": wasserstein,
            "normalized_stage_jensen_shannon": js_distance,
        }
        values_and_reasons = {
            name: _metric_value(result) for name, result in component_results.items()
        }
        map_private = _private_map(map_result)
        reasons = [reason for _value, reason in values_and_reasons.values() if reason is not None]
        if map_private["status"] != "ASSESSABLE":
            reasons.append(cast(str, map_private["reason_code"]))
        participant_status = "ASSESSABLE" if not reasons else "NOT_ASSESSABLE"
        participant_reason = None if not reasons else reasons[0]
        participant_results.append(
            {
                "evaluation_row_index": row_index,
                "evaluation_unit_binding": unit_binding,
                "status": participant_status,
                "reason_code": participant_reason,
                "expected_stage_movement": {
                    name: _private_metric(result)
                    for name, result in component_results.items()
                    if name
                    not in {
                        "normalized_stage_wasserstein",
                        "normalized_stage_jensen_shannon",
                    }
                },
                "normalized_stage_wasserstein": _private_metric(wasserstein),
                "map_stage_agreement": map_private,
                "normalized_stage_jensen_shannon": _private_metric(js_distance),
            }
        )
        if participant_status == "ASSESSABLE":
            for name, (value, metric_reason) in values_and_reasons.items():
                assert metric_reason is None
                assert value is not None
                metric_values_by_name[name].append(value)
            agreement = map_private["agreement"]
            assert type(agreement) is bool
            map_agreements.append(float(agreement))

    denominator_count = len(left_row_indexes)
    valid_count = len(map_agreements)
    missing_count = denominator_count - valid_count
    if missing_count:
        return _seal_stage_result(
            left=checked_left,
            right=checked_right,
            public_preimage=_unavailable_record(
                base,
                availability="AVAILABLE",
                availability_reason_code=None,
                metric_status="NOT_ASSESSABLE",
                metric_reason_code=_INCOMPLETE_DERIVATION_REASON,
                evaluation_cohort_digest=left_cohort_digest,
                cohort_denominator_count=denominator_count,
                valid_participant_count=valid_count,
                missing_participant_count=missing_count,
                same_evaluation_cohort=same_cohort,
                same_evaluation_row_indexes=same_rows,
                same_evaluation_unit_bindings=same_bindings,
            ),
            participant_results=participant_results,
        )

    wasserstein_values = tuple(metric_values_by_name["normalized_stage_wasserstein"])
    quantiles = tuple(
        _quantile(wasserstein_values, probability) for probability in _QUANTILE_PROBABILITIES
    )
    maximum = _quantile(wasserstein_values, 1.0)
    cohort_wasserstein, cohort_reason = _metric_value(
        cohort_normalized_stage_wasserstein(
            left_posteriors,
            right_posteriors,
            left_identities=left_identities,
            right_identities=right_identities,
        )
    )
    if cohort_reason is not None or cohort_wasserstein is None:
        raise AssertionError("A complete valid cohort requires cohort Wasserstein.")

    metric_values = (
        quantiles[2],
        maximum,
        _mean(tuple(metric_values_by_name["left_expected_stage"])),
        _mean(tuple(metric_values_by_name["right_expected_stage"])),
        _mean(tuple(metric_values_by_name["signed_expected_stage_change"])),
        _mean(tuple(metric_values_by_name["absolute_expected_stage_change"])),
        _mean(tuple(metric_values_by_name["normalized_absolute_expected_stage_change"])),
        _mean(tuple(map_agreements)),
        _mean(wasserstein_values),
        cohort_wasserstein,
        _mean(tuple(metric_values_by_name["normalized_stage_jensen_shannon"])),
    )
    public_preimage = {
        **base,
        "availability": "AVAILABLE",
        "availability_reason_code": None,
        "same_evaluation_cohort": same_cohort,
        "same_evaluation_row_indexes": same_rows,
        "same_evaluation_unit_bindings": same_bindings,
        "evaluation_cohort_digest": left_cohort_digest,
        "evaluation_cohort_count": denominator_count,
        "cohort_denominator_count": denominator_count,
        "valid_participant_count": valid_count,
        "missing_participant_count": missing_count,
        "normalized_stage_wasserstein_quantiles": {
            "q10": quantiles[0],
            "q25": quantiles[1],
            "q50": quantiles[2],
            "q75": quantiles[3],
            "q90": quantiles[4],
        },
        "normalized_stage_wasserstein_iqr": quantiles[3] - quantiles[1],
        "metric_status": "ASSESSABLE",
        "metric_reason_code": None,
        "metrics": _metric_rows(
            "ASSESSABLE",
            reason_code=None,
            values=metric_values,
        ),
    }
    return _seal_stage_result(
        left=checked_left,
        right=checked_right,
        public_preimage=public_preimage,
        participant_results=participant_results,
    )


def derive_stage_comparison(
    left: _StageComparisonSideInput,
    right: _StageComparisonSideInput,
) -> dict[str, object]:
    """Return only the privacy-safe projection of the frozen owner derivation."""

    derived = derive_stage_comparison_owner(left, right)
    projection = strict_json_loads(derived.public_projection_bytes)
    if type(projection) is not dict:
        raise AssertionError("Canonical stage comparison projection must be an object.")
    return cast(dict[str, object], projection)


_STAGE_COMPARISON_DERIVATION = build_frozen_derivation_graph(
    globals(),
    module_name=__name__,
    root_names=("derive_stage_comparison", "derive_stage_comparison_owner"),
    record_type_names=("_StageComparisonSideInput", "_DerivedStageComparison"),
)
for _function_name, _frozen_function in _STAGE_COMPARISON_DERIVATION.functions.items():
    globals()[_function_name] = _frozen_function
for _record_type_name, _frozen_record_type in _STAGE_COMPARISON_DERIVATION.record_types.items():
    globals()[_record_type_name] = _frozen_record_type
del _function_name
del _frozen_function
del _record_type_name
del _frozen_record_type
del build_frozen_derivation_graph
