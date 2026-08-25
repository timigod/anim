"""Exact order posterior for the locked ``kde_ebm`` probability target.

The implementation is independent of the optional backend.  It consumes only
an ephemeral, already-fitted probability-density matrix whose columns are in
the supplied canonical event order.  No participant-level input or per-order
score is retained in the returned result.

The order score deliberately mirrors ``kde_ebm`` 0.0.3 at source commit
``3ad8b648a4a2d0a8df0707f382b54c4ebef0805c``:

* a uniform mixture over stages ``0..N``;
* binary64 probability-domain products and reductions; and
* ``1e-250`` added immediately before the participant-level logarithm.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import canonical_json_bytes

FloatArray = npt.NDArray[np.float64]

MAX_EXACT_KDE_EVENTS = 9
KDE_EBM_PROBABILITY_FLOOR = 1e-250
KDE_EBM_PAIRWISE_MASS_TOLERANCE = 1e-12
KDE_EBM_TARGET_ARITHMETIC_ID = (
    "kde-ebm-0.0.3-uniform-order-posterior-binary64-uniform-stage-plus-1e-250/2"
)


@dataclass(frozen=True, slots=True)
class ExactKdeTargetResult:
    """Participant-free exact summaries of one fixed KDE target."""

    event_ids: tuple[str, ...]
    order_count: int
    target_arithmetic_id: str
    position_probabilities: FloatArray
    pairwise_precedence: FloatArray
    even_permutation_mass: float


def _invalid(code: str, message: str) -> InvalidInputError:
    return InvalidInputError(code, message)


def _validate_event_ids(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise _invalid(
            "KDE_TARGET.EVENT_IDS_INVALID",
            "The exact KDE target requires between two and nine unique event identifiers.",
        )
    try:
        event_ids = tuple(value)
    except TypeError:
        raise _invalid(
            "KDE_TARGET.EVENT_IDS_INVALID",
            "The exact KDE target requires between two and nine unique event identifiers.",
        ) from None
    event_count = len(event_ids)
    identifiers_valid = all(isinstance(event_id, str) and bool(event_id) for event_id in event_ids)
    if event_count < 2 or event_count > MAX_EXACT_KDE_EVENTS or not identifiers_valid:
        raise _invalid(
            "KDE_TARGET.EVENT_IDS_INVALID",
            "The exact KDE target requires between two and nine unique event identifiers.",
        )
    if len(set(event_ids)) != event_count:
        raise _invalid(
            "KDE_TARGET.EVENT_IDS_INVALID",
            "The exact KDE target requires between two and nine unique event identifiers.",
        )
    try:
        canonical_json_bytes(list(event_ids))
    except Exception:
        raise _invalid(
            "KDE_TARGET.EVENT_IDS_INVALID",
            "The event identifiers are outside the canonical string contract.",
        ) from None
    return event_ids


def _validate_probability_matrix(
    value: object,
    *,
    event_count: int,
) -> FloatArray:
    try:
        matrix = np.asarray(value, dtype=np.float64)
    except (OverflowError, TypeError, ValueError):
        raise _invalid(
            "KDE_TARGET.PROBABILITY_MATRIX_TYPE",
            "The fixed KDE target is not a finite numeric probability matrix.",
        ) from None
    if (
        matrix.ndim != 3
        or matrix.shape[0] < 1
        or matrix.shape[1] != event_count
        or matrix.shape[2] != 2
    ):
        raise _invalid(
            "KDE_TARGET.PROBABILITY_MATRIX_DIMENSIONS",
            (
                "The fixed KDE target must have one or more rows and exact "
                "row-by-event-by-two dimensions."
            ),
        )
    if not np.all(np.isfinite(matrix)) or np.any(matrix < 0.0):
        raise _invalid(
            "KDE_TARGET.PROBABILITY_MATRIX_VALUES",
            "The fixed KDE target must contain finite non-negative component densities.",
        )
    result = np.array(matrix, dtype=np.float64, copy=True, order="C")
    result.setflags(write=False)
    return result


def _upstream_binary64_order_score(
    probability_matrix: FloatArray,
    order_indexes: tuple[int, ...],
) -> float:
    """Reproduce the locked upstream order-score operation sequence."""

    event_count = len(order_indexes)
    indexes = np.asarray(order_indexes, dtype=np.intp)
    p_yes = np.array(probability_matrix[:, indexes, 1], dtype=np.float64, copy=True)
    p_no = np.array(probability_matrix[:, indexes, 0], dtype=np.float64, copy=True)
    participant_count = probability_matrix.shape[0]
    stage_likelihoods = np.zeros(
        (participant_count, event_count + 1),
        dtype=np.float64,
    )
    with np.errstate(over="ignore", invalid="ignore"):
        for stage in range(event_count + 1):
            stage_likelihoods[:, stage] = np.prod(
                p_yes[:, :stage],
                axis=1,
            ) * np.prod(
                p_no[:, stage:event_count],
                axis=1,
            )
        participant_log_likelihoods = np.log(
            np.sum(
                (1.0 / (event_count + 1)) * stage_likelihoods,
                axis=1,
            )
            + KDE_EBM_PROBABILITY_FLOOR
        )
        score = float(np.sum(participant_log_likelihoods))
    if not math.isfinite(score):
        raise _invalid(
            "KDE_TARGET.NUMERIC_RANGE",
            "The finite KDE target produced a non-finite binary64 order score.",
        )
    return score


def _is_even_permutation(order_indexes: tuple[int, ...]) -> bool:
    odd = False
    for left_position, left_event in enumerate(order_indexes):
        for right_event in order_indexes[left_position + 1 :]:
            if left_event > right_event:
                odd = not odd
    return not odd


def _compensated_add(
    total: FloatArray,
    compensation: FloatArray,
    row: int,
    column: int,
    value: float,
) -> None:
    increment = value - compensation[row, column]
    updated = total[row, column] + increment
    compensation[row, column] = updated - total[row, column] - increment
    total[row, column] = updated


def _enumerate_exact_order_distribution(
    probability_matrix: FloatArray,
) -> tuple[FloatArray, FloatArray]:
    """Return ephemeral scores and posterior in ``itertools.permutations`` order.

    The caller must supply the already-validated fixed target. This narrow
    internal seam lets the locked-source score and normalization be checked
    directly without adding per-order rows to the product result.
    """

    event_count = int(probability_matrix.shape[1])
    canonical_indexes = tuple(range(event_count))
    order_count = math.factorial(event_count)
    order_scores = np.empty(order_count, dtype=np.float64)

    for order_index, ordering in enumerate(itertools.permutations(canonical_indexes)):
        order_scores[order_index] = _upstream_binary64_order_score(
            probability_matrix,
            ordering,
        )

    maximum_score = float(np.max(order_scores))
    with np.errstate(over="ignore", under="ignore", invalid="ignore"):
        unnormalized = np.exp(order_scores - maximum_score)
        normalizer = float(np.sum(unnormalized))
        order_posterior = np.asarray(unnormalized / normalizer, dtype=np.float64)
    if (
        not math.isfinite(normalizer)
        or normalizer <= 0.0
        or not np.all(np.isfinite(order_posterior))
    ):
        raise _invalid(
            "KDE_TARGET.NUMERIC_RANGE",
            "The finite KDE target produced a non-normalizable order posterior.",
        )

    order_scores.setflags(write=False)
    order_posterior.setflags(write=False)
    return order_scores, order_posterior


def solve_exact_kde_target(
    probability_matrix: object,
    *,
    event_ids: Sequence[str],
) -> ExactKdeTargetResult:
    """Enumerate all supported orders and return the exact fixed-target posterior.

    ``event_ids[i]`` names probability-matrix column ``i`` and therefore fixes
    the parity reference order.  The result contains only aggregate posterior
    summaries; it does not expose a preferred order or participant-level data.
    """

    validated_event_ids = _validate_event_ids(event_ids)
    event_count = len(validated_event_ids)
    probabilities = _validate_probability_matrix(
        probability_matrix,
        event_count=event_count,
    )
    canonical_indexes = tuple(range(event_count))
    order_scores, order_posterior = _enumerate_exact_order_distribution(probabilities)
    order_count = int(order_scores.shape[0])

    position = np.zeros((event_count, event_count), dtype=np.float64)
    position_compensation = np.zeros((event_count, event_count), dtype=np.float64)
    pairwise = np.zeros((event_count, event_count), dtype=np.float64)
    pairwise_compensation = np.zeros((event_count, event_count), dtype=np.float64)
    even_mass = 0.0
    even_mass_compensation = 0.0

    for order_index, ordering in enumerate(itertools.permutations(canonical_indexes)):
        probability = float(order_posterior[order_index])
        positions = [0] * event_count
        for order_position, event_index in enumerate(ordering):
            positions[event_index] = order_position
            _compensated_add(
                position,
                position_compensation,
                event_index,
                order_position,
                probability,
            )
        for first_event in range(event_count):
            for second_event in range(first_event + 1, event_count):
                if positions[first_event] < positions[second_event]:
                    _compensated_add(
                        pairwise,
                        pairwise_compensation,
                        first_event,
                        second_event,
                        probability,
                    )
        if _is_even_permutation(ordering):
            increment = probability - even_mass_compensation
            updated_even_mass = even_mass + increment
            even_mass_compensation = updated_even_mass - even_mass - increment
            even_mass = updated_even_mass

    for first_event in range(event_count):
        for second_event in range(first_event + 1, event_count):
            upper_mass = float(pairwise[first_event, second_event])
            if (
                not math.isfinite(upper_mass)
                or upper_mass < -KDE_EBM_PAIRWISE_MASS_TOLERANCE
                or upper_mass > 1.0 + KDE_EBM_PAIRWISE_MASS_TOLERANCE
            ):
                raise _invalid(
                    "KDE_TARGET.NUMERIC_RANGE",
                    "The exact KDE target produced pairwise mass outside its binary64 tolerance.",
                )
            upper_mass = min(1.0, max(0.0, upper_mass))
            pairwise[first_event, second_event] = upper_mass
            pairwise[second_event, first_event] = 1.0 - upper_mass
    np.fill_diagonal(pairwise, 0.5)

    position.setflags(write=False)
    pairwise.setflags(write=False)
    return ExactKdeTargetResult(
        event_ids=validated_event_ids,
        order_count=order_count,
        target_arithmetic_id=KDE_EBM_TARGET_ARITHMETIC_ID,
        position_probabilities=position,
        pairwise_precedence=pairwise,
        even_permutation_mass=float(even_mass),
    )
