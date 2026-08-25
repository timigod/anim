"""Exact permutation oracle for already-fitted event likelihoods.

This module deliberately does not fit mixture distributions. It consumes two
finite log-likelihood matrices whose columns are already aligned and oriented:
one under the not-abnormal state and one under the abnormal state.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal, overload

import numpy as np
import numpy.typing as npt

from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import canonical_json_bytes

FloatArray = npt.NDArray[np.float64]
EventDirection = Literal["higher", "lower"]

# Nine events means 362,880 orders. The supported ceiling remains deliberately
# small and must be revisited only with an explicit runtime/memory proof.
MAX_EXACT_EVENTS = 9
MAX_MATERIALIZED_EXACT_EVENTS = 8
BEST_ORDER_TIE_RULE_ID = "binary64-exact-max-equality/1"
ORDER_PRIOR_ID = "uniform-over-all-event-permutations/1"
STAGE_PRIOR_POLICY_ID = "positive-sum-within-1e-12-then-binary64-normalize/1"
_PRIOR_SUM_TOLERANCE = 1e-12
# This bound keeps the largest supported 57-participant, nine-event working
# set below 32 MiB while amortising the Python cost of exact enumeration.
_ORDER_CHUNK_SIZE = 2_048


@dataclass(frozen=True)
class ExactOracleInput:
    """Closed fixed-likelihood input to the exact oracle."""

    event_ids: tuple[str, ...]
    event_directions: tuple[EventDirection, ...]
    log_p_not_abnormal: FloatArray
    log_p_abnormal: FloatArray
    stage_prior: FloatArray


@dataclass(frozen=True, slots=True)
class OrderPosterior:
    """One lexicographically enumerated order and its exact weight."""

    order: tuple[str, ...]
    order_log_likelihood: float
    posterior_probability: float


@dataclass(frozen=True)
class ExactOracleResult:
    """Exact order and participant-stage summaries."""

    order_prior_id: str
    stage_prior_policy_id: str
    best_order_tie_rule_id: str
    canonical_best_order: tuple[str, ...]
    best_order_count: int
    best_order_log_likelihood: float
    log_evidence_over_orders: float
    ordered_order_posteriors: tuple[OrderPosterior, ...]
    position_probabilities: FloatArray
    pairwise_precedence: FloatArray
    canonical_best_order_stage_posteriors: FloatArray


@dataclass(frozen=True)
class _CompactExactOracleResult:
    """Exact summaries without the public per-order posterior materialization."""

    order_prior_id: str
    stage_prior_policy_id: str
    best_order_tie_rule_id: str
    canonical_best_order: tuple[str, ...]
    best_order_count: int
    best_order_log_likelihood: float
    log_evidence_over_orders: float
    position_probabilities: FloatArray
    pairwise_precedence: FloatArray
    canonical_best_order_stage_posteriors: FloatArray


def _invalid(code: str, message: str) -> InvalidInputError:
    return InvalidInputError(code, message)


def _as_owned_float64_matrix(value: object, *, field: str) -> FloatArray:
    try:
        array = np.asarray(value, dtype=np.float64)
    except (TypeError, ValueError, OverflowError):
        raise _invalid(
            f"ORACLE.{field.upper()}_TYPE",
            "An oracle likelihood input is not a finite numeric matrix.",
        ) from None
    if array.ndim != 2 or not np.all(np.isfinite(array)):
        raise _invalid(
            f"ORACLE.{field.upper()}_SHAPE",
            "An oracle likelihood input is not a finite numeric matrix.",
        )
    return np.array(array, dtype=np.float64, copy=True, order="C")


def _as_owned_stage_prior(value: object, *, event_count: int) -> FloatArray:
    try:
        prior = np.asarray(value, dtype=np.float64)
    except (TypeError, ValueError, OverflowError):
        raise _invalid(
            "ORACLE.STAGE_PRIOR_TYPE",
            "The oracle stage prior must be a finite positive vector.",
        ) from None
    prior_sum = float(np.sum(prior, dtype=np.float64)) if prior.ndim == 1 else math.nan
    if (
        prior.ndim != 1
        or prior.shape != (event_count + 1,)
        or not np.all(np.isfinite(prior))
        or not np.all(prior > 0.0)
        or abs(prior_sum - 1.0) > _PRIOR_SUM_TOLERANCE
    ):
        raise _invalid(
            "ORACLE.STAGE_PRIOR_INVALID",
            (
                "The oracle stage prior must contain one positive probability per stage "
                "and sum to one."
            ),
        )
    # The tolerance is an input-acceptance rule, not permission to use an
    # unnormalised probability vector. Normalize once, deterministically, in
    # binary64 before any likelihood calculation.
    return np.array(prior / prior_sum, dtype=np.float64, copy=True, order="C")


def _validate_input(
    value: ExactOracleInput,
    *,
    max_event_count: int = MAX_MATERIALIZED_EXACT_EVENTS,
) -> ExactOracleInput:
    event_ids = tuple(value.event_ids)
    event_count = len(event_ids)
    if event_count < 2 or event_count > max_event_count or len(set(event_ids)) != event_count:
        limit_label = {8: "eight", 9: "nine"}.get(max_event_count, str(max_event_count))
        raise _invalid(
            "ORACLE.EVENT_IDS_INVALID",
            (
                "The exact oracle requires between two and "
                f"{limit_label} unique event identifiers."
            ),
        )
    if any(not isinstance(event_id, str) or not event_id for event_id in event_ids):
        raise _invalid(
            "ORACLE.EVENT_IDS_INVALID",
            "The exact oracle requires between two and nine unique event identifiers.",
        )
    try:
        canonical_json_bytes(list(event_ids))
    except Exception:
        raise _invalid(
            "ORACLE.EVENT_IDS_INVALID",
            "The oracle event identifiers are outside the canonical string contract.",
        ) from None

    directions = tuple(value.event_directions)
    if len(directions) != event_count or any(
        direction not in {"higher", "lower"} for direction in directions
    ):
        raise _invalid(
            "ORACLE.EVENT_DIRECTIONS_INVALID",
            "Oracle direction metadata must align one-for-one with the event identifiers.",
        )

    normal = _as_owned_float64_matrix(value.log_p_not_abnormal, field="log_p_not_abnormal")
    abnormal = _as_owned_float64_matrix(value.log_p_abnormal, field="log_p_abnormal")
    if normal.shape != abnormal.shape or normal.shape[0] < 1 or normal.shape[1] != event_count:
        raise _invalid(
            "ORACLE.LIKELIHOOD_DIMENSIONS",
            (
                "The two oracle likelihood matrices must have identical "
                "participant-by-event dimensions."
            ),
        )
    prior = _as_owned_stage_prior(value.stage_prior, event_count=event_count)
    return ExactOracleInput(
        event_ids=event_ids,
        event_directions=directions,
        log_p_not_abnormal=normal,
        log_p_abnormal=abnormal,
        stage_prior=prior,
    )


def _logsumexp(values: FloatArray, *, axis: int | None = None) -> FloatArray | float:
    maximum = np.max(values, axis=axis, keepdims=True)
    shifted = np.exp(values - maximum)
    result = maximum + np.log(np.sum(shifted, axis=axis, keepdims=True))
    if axis is None:
        return float(result.squeeze())
    return np.asarray(np.squeeze(result, axis=axis), dtype=np.float64)


def _order_invariant_likelihood_terms(
    normal: FloatArray,
    abnormal: FloatArray,
) -> tuple[FloatArray, FloatArray]:
    # Extreme but finite user inputs may overflow a float64 reduction. Handle
    # that locally and turn it into a typed failure when a stage score is used;
    # do not alter the process-wide warning policy.
    with np.errstate(over="ignore", invalid="ignore"):
        base = np.asarray(np.sum(normal, axis=1, dtype=np.float64), dtype=np.float64)
        abnormal_minus_normal = np.asarray(abnormal - normal, dtype=np.float64)
    return base, abnormal_minus_normal


def _stage_log_scores(
    base: FloatArray,
    abnormal_minus_normal: FloatArray,
    order_indexes: tuple[int, ...],
    log_stage_prior: FloatArray,
) -> FloatArray:
    with np.errstate(over="ignore", invalid="ignore"):
        increments = abnormal_minus_normal[:, order_indexes]
        prefix = np.cumsum(increments, axis=1, dtype=np.float64)
    participant_count = base.shape[0]
    scores = np.empty((participant_count, len(order_indexes) + 1), dtype=np.float64)
    scores[:, 0] = base + log_stage_prior[0]
    scores[:, 1:] = base[:, None] + prefix + log_stage_prior[None, 1:]
    if not np.all(np.isfinite(scores)):
        raise _invalid(
            "ORACLE.NUMERIC_RANGE",
            "The finite oracle inputs produced a non-finite intermediate calculation.",
        )
    return scores


def _normalized_rows(log_scores: FloatArray) -> FloatArray:
    normalizers = np.asarray(_logsumexp(log_scores, axis=1), dtype=np.float64)
    return np.asarray(np.exp(log_scores - normalizers[:, None]), dtype=np.float64)


def _exact_maximizer_indexes(values: FloatArray) -> npt.NDArray[np.intp]:
    """Return only binary64 values exactly equal to the observed maximum."""

    maximum = np.max(values)
    return np.flatnonzero(values == maximum)


def _permutation_index_chunks(
    lexicographic_input_indexes: tuple[int, ...],
) -> Iterator[npt.NDArray[np.intp]]:
    """Yield bounded arrays of permutations without changing their order."""

    permutations = itertools.permutations(lexicographic_input_indexes)

    def chunks() -> Iterator[npt.NDArray[np.intp]]:
        while True:
            rows = tuple(itertools.islice(permutations, _ORDER_CHUNK_SIZE))
            if not rows:
                return
            yield np.asarray(rows, dtype=np.intp)

    return chunks()


def _chunk_order_log_likelihoods(
    base: FloatArray,
    abnormal_minus_normal: FloatArray,
    order_indexes: npt.NDArray[np.intp],
    log_stage_prior: FloatArray,
) -> FloatArray:
    """Evaluate one bounded lexicographic permutation chunk exactly."""

    participant_count = base.shape[0]
    chunk_count, event_count = order_indexes.shape
    with np.errstate(over="ignore", invalid="ignore"):
        # Advanced indexing places its owned buffer behind a transposed view.
        # Copy to C order so each chunk is released at call exit instead of
        # retaining that hidden buffer through NumPy's iterator machinery.
        prefixes = np.array(
            abnormal_minus_normal[:, order_indexes],
            dtype=np.float64,
            copy=True,
            order="C",
        )
        prefixes = np.cumsum(prefixes, axis=2, dtype=np.float64)
        scores = np.empty(
            (participant_count, chunk_count, event_count + 1),
            dtype=np.float64,
        )
        scores[:, :, 0] = base[:, None] + log_stage_prior[0]
        scores[:, :, 1:] = (
            base[:, None, None] + prefixes + log_stage_prior[None, None, 1:]
        )
    if not np.all(np.isfinite(scores)):
        raise _invalid(
            "ORACLE.NUMERIC_RANGE",
            "The finite oracle inputs produced a non-finite intermediate calculation.",
        )

    maxima = np.max(scores, axis=2)
    scores -= maxima[:, :, None]
    np.exp(scores, out=scores)
    participant_log_likelihoods = maxima + np.log(
        np.sum(scores, axis=2, dtype=np.float64)
    )
    order_log_likelihoods = np.asarray(
        np.sum(participant_log_likelihoods, axis=0, dtype=np.float64),
        dtype=np.float64,
    )
    if not np.all(np.isfinite(order_log_likelihoods)):
        raise _invalid(
            "ORACLE.NUMERIC_RANGE",
            "The finite oracle inputs produced a non-finite intermediate calculation.",
        )
    return order_log_likelihoods


def _compensated_add(
    total: FloatArray,
    compensation: FloatArray,
    indexes: tuple[int, ...],
    increment: float,
) -> None:
    adjusted = increment - float(compensation[indexes])
    updated = float(total[indexes]) + adjusted
    compensation[indexes] = updated - float(total[indexes]) - adjusted
    total[indexes] = updated


@overload
def _solve_exact_oracle(
    value: ExactOracleInput,
    *,
    materialize_order_posteriors: Literal[True],
) -> ExactOracleResult: ...


@overload
def _solve_exact_oracle(
    value: ExactOracleInput,
    *,
    materialize_order_posteriors: Literal[False],
) -> _CompactExactOracleResult: ...


def _solve_exact_oracle(
    value: ExactOracleInput,
    *,
    materialize_order_posteriors: bool,
) -> ExactOracleResult | _CompactExactOracleResult:
    validated = _validate_input(
        value,
        max_event_count=(
            MAX_MATERIALIZED_EXACT_EVENTS if materialize_order_posteriors else MAX_EXACT_EVENTS
        ),
    )
    event_ids = validated.event_ids
    event_count = len(event_ids)
    input_index = {event_id: index for index, event_id in enumerate(event_ids)}
    lexicographic_event_ids = tuple(sorted(event_ids))
    lexicographic_input_indexes = tuple(
        input_index[event_id] for event_id in lexicographic_event_ids
    )
    order_count = math.factorial(event_count)
    log_stage_prior = np.log(validated.stage_prior)
    base, abnormal_minus_normal = _order_invariant_likelihood_terms(
        validated.log_p_not_abnormal,
        validated.log_p_abnormal,
    )

    order_log_likelihoods = np.empty(order_count, dtype=np.float64)
    order_offset = 0
    for order_indexes in _permutation_index_chunks(lexicographic_input_indexes):
        chunk_log_likelihoods = _chunk_order_log_likelihoods(
            base,
            abnormal_minus_normal,
            order_indexes,
            log_stage_prior,
        )
        next_offset = order_offset + order_indexes.shape[0]
        order_log_likelihoods[order_offset:next_offset] = chunk_log_likelihoods
        order_offset = next_offset
    if order_offset != order_count:
        raise RuntimeError("The exact permutation enumeration ended at the wrong count.")

    log_order_posterior_normalizer = float(_logsumexp(order_log_likelihoods))
    order_posterior = np.asarray(
        np.exp(order_log_likelihoods - log_order_posterior_normalizer),
        dtype=np.float64,
    )
    if not np.all(np.isfinite(order_posterior)):
        raise _invalid(
            "ORACLE.NUMERIC_RANGE",
            "The finite oracle inputs produced a non-finite intermediate calculation.",
        )
    log_uniform_order_prior = -math.lgamma(event_count + 1)
    log_evidence = log_order_posterior_normalizer + log_uniform_order_prior

    best_log_likelihood = float(np.max(order_log_likelihoods))
    best_indexes = _exact_maximizer_indexes(order_log_likelihoods)
    # Permutations are lexicographic, so the first exact maximizer is the
    # canonical best order without a tolerance-based invention of extra ties.
    canonical_best_index = int(best_indexes[0])
    canonical_best_order = next(
        itertools.islice(
            itertools.permutations(lexicographic_event_ids),
            canonical_best_index,
            canonical_best_index + 1,
        )
    )

    position = np.zeros((event_count, event_count), dtype=np.float64)
    position_compensation = np.zeros((event_count, event_count), dtype=np.float64)
    pairwise = np.zeros((event_count, event_count), dtype=np.float64)
    pairwise_compensation = np.zeros((event_count, event_count), dtype=np.float64)
    np.fill_diagonal(pairwise, 0.5)
    posterior_rows: list[OrderPosterior] | None = [] if materialize_order_posteriors else None
    posterior_row_offset = 0
    for order_indexes in _permutation_index_chunks(lexicographic_input_indexes):
        next_offset = posterior_row_offset + order_indexes.shape[0]
        probabilities = order_posterior[posterior_row_offset:next_offset]
        inverse_positions = np.argsort(order_indexes, axis=1)
        for input_event_index in range(event_count):
            for order_position in range(event_count):
                increment = float(
                    np.sum(
                        probabilities[order_indexes[:, order_position] == input_event_index],
                        dtype=np.float64,
                    )
                )
                _compensated_add(
                    position,
                    position_compensation,
                    (input_event_index, order_position),
                    increment,
                )
        for left_index in range(event_count):
            for right_index in range(left_index + 1, event_count):
                left_before = inverse_positions[:, left_index] < inverse_positions[:, right_index]
                before_increment = float(np.sum(probabilities[left_before], dtype=np.float64))
                after_increment = float(np.sum(probabilities[~left_before], dtype=np.float64))
                _compensated_add(
                    pairwise,
                    pairwise_compensation,
                    (left_index, right_index),
                    before_increment,
                )
                _compensated_add(
                    pairwise,
                    pairwise_compensation,
                    (right_index, left_index),
                    after_increment,
                )
        if posterior_rows is not None:
            posterior_rows.extend(
                OrderPosterior(
                    order=tuple(event_ids[int(index)] for index in order_indexes[row_index]),
                    order_log_likelihood=float(
                        order_log_likelihoods[posterior_row_offset + row_index]
                    ),
                    posterior_probability=float(probabilities[row_index]),
                )
                for row_index in range(order_indexes.shape[0])
            )
        posterior_row_offset = next_offset
    if posterior_row_offset != order_count:
        raise RuntimeError("The exact posterior enumeration ended at the wrong count.")

    # Compensated chunk sums can finish one ulp outside the closed probability
    # interval.  Re-express every off-diagonal pair from its two accumulated
    # complementary masses so the wire result preserves the exact probability
    # identity as well as the protocol's closed numeric range.
    position = np.clip(position, 0.0, 1.0)
    for left_index in range(event_count):
        for right_index in range(left_index + 1, event_count):
            total = pairwise[left_index, right_index] + pairwise[right_index, left_index]
            if not np.isfinite(total) or total <= 0.0:
                raise _invalid(
                    "ORACLE.NUMERIC_RANGE",
                    "The finite oracle inputs produced an invalid probability mass.",
                )
            probability = float(
                np.clip(pairwise[left_index, right_index] / total, 0.0, 1.0)
            )
            pairwise[left_index, right_index] = probability
            pairwise[right_index, left_index] = 1.0 - probability
    np.fill_diagonal(pairwise, 0.5)

    best_column_indexes = tuple(input_index[event_id] for event_id in canonical_best_order)
    best_stage_scores = _stage_log_scores(
        base,
        abnormal_minus_normal,
        best_column_indexes,
        log_stage_prior,
    )
    best_stage_posteriors = _normalized_rows(best_stage_scores)

    if posterior_rows is None:
        return _CompactExactOracleResult(
            order_prior_id=ORDER_PRIOR_ID,
            stage_prior_policy_id=STAGE_PRIOR_POLICY_ID,
            best_order_tie_rule_id=BEST_ORDER_TIE_RULE_ID,
            canonical_best_order=canonical_best_order,
            best_order_count=int(best_indexes.size),
            best_order_log_likelihood=best_log_likelihood,
            log_evidence_over_orders=float(log_evidence),
            position_probabilities=position,
            pairwise_precedence=pairwise,
            canonical_best_order_stage_posteriors=best_stage_posteriors,
        )

    return ExactOracleResult(
        order_prior_id=ORDER_PRIOR_ID,
        stage_prior_policy_id=STAGE_PRIOR_POLICY_ID,
        best_order_tie_rule_id=BEST_ORDER_TIE_RULE_ID,
        canonical_best_order=canonical_best_order,
        best_order_count=int(best_indexes.size),
        best_order_log_likelihood=best_log_likelihood,
        log_evidence_over_orders=float(log_evidence),
        ordered_order_posteriors=tuple(posterior_rows),
        position_probabilities=position,
        pairwise_precedence=pairwise,
        canonical_best_order_stage_posteriors=best_stage_posteriors,
    )


def _solve_exact_oracle_compact(value: ExactOracleInput) -> _CompactExactOracleResult:
    """Return exact summaries without allocating one object per enumerated order."""

    return _solve_exact_oracle(value, materialize_order_posteriors=False)


def solve_exact_oracle(value: ExactOracleInput) -> ExactOracleResult:
    """Enumerate every order and return exact fixed-likelihood summaries.

    Direction metadata is validated for alignment but intentionally not applied:
    the supplied likelihoods are already oriented normal-versus-abnormal
    evidence. The calculation is deterministic and consumes no random state.
    """

    return _solve_exact_oracle(value, materialize_order_posteriors=True)
