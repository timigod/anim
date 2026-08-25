"""Pure KDE profile transition-quality calculations against an exact target.

This module is deliberately not an evidence or receipt owner.  It accepts
already-authenticated arrays from a future live owner, snapshots and validates
their numeric contents, and returns deterministic calculations only.  It
cannot authenticate a fit, persist evidence, issue a pass receipt, or select a
profile budget.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, Literal, cast

import numpy as np
from numpy.typing import NDArray

from ._numeric import _NUMERIC_KERNEL

KdeProfileBudget = Literal[2000, 5000, 10000]
KdeProfileTransitionStatus = Literal["PROFILE_QUALIFIED", "PROFILE_UNQUALIFIED"]
KdeProfileFamily = Literal["POSITION", "PAIRWISE_PRECEDENCE", "EVEN_PARITY"]
ConvergenceAssessment = Literal[
    "CONVERGENCE_PASS",
    "CONVERGENCE_WARN",
    "CONVERGENCE_FAIL",
    "CONVERGENCE_NOT_ASSESSABLE",
]

KDE_PROFILE_TRANSITION_RULE_ID: Final = "kde-profile-exact-target-transition-quality/1"
KDE_PROFILE_EVENT_COUNT: Final = 9
KDE_PROFILE_CHAIN_COUNT_PER_BUDGET: Final = 18
KDE_PROFILE_Z: Final = 3.524846146812584
KDE_PROFILE_MEDIAN_MAX: Final = 0.10
KDE_PROFILE_MAXIMUM_MAX: Final = 0.20
KDE_PROFILE_BUDGETS: Final[tuple[KdeProfileBudget, ...]] = (2000, 5000, 10000)
KDE_PROFILE_RETAINED_COUNTS: Final[tuple[tuple[KdeProfileBudget, int], ...]] = (
    (2000, 160),
    (5000, 400),
    (10000, 800),
)

_TARGET_SUM_TOLERANCE: Final = 1e-12
_INVALID_MESSAGE: Final = "KDE profile transition-quality inputs are invalid."
_VALID_CONVERGENCE_ASSESSMENTS: Final[frozenset[str]] = frozenset(
    {
        "CONVERGENCE_PASS",
        "CONVERGENCE_WARN",
        "CONVERGENCE_FAIL",
        "CONVERGENCE_NOT_ASSESSABLE",
    }
)


class InvalidKdeProfileTransitionCalculation(ValueError):
    """A fail-closed malformed or incomplete transition-quality calculation."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(_INVALID_MESSAGE)


@dataclass(frozen=True, slots=True)
class KdeProfileChainInput:
    """One authenticated chain projection supplied by a future live owner.

    ``retained_order_states`` and ``unthinned_postburn_order_states`` encode
    permutations as zero-based event indexes aligned with ``event_ids``.
    Caller-authored digests, summaries, and transition counts are intentionally
    absent: this calculator derives every numeric result from the arrays.
    """

    budget: int
    chain_slot: int
    event_ids: tuple[str, ...]
    retained_order_states: object = field(repr=False)
    unthinned_postburn_order_states: object = field(repr=False)
    exact_position_probabilities: object = field(repr=False)
    exact_pairwise_precedence: object = field(repr=False)
    exact_even_parity_probability: object = field(repr=False)
    universe_convergence_assessment: str


@dataclass(frozen=True, slots=True)
class IndicatorQualityScore:
    """Exact-target error envelope for one binary indicator series."""

    retained_count: int
    full_mean: float
    exact_target: float
    full_absolute_error: float
    geyer_ims_mcse: float
    full_error_upper_bound: float
    first_half_absolute_error: float
    second_half_absolute_error: float
    score: float


@dataclass(frozen=True, slots=True)
class KdeProfileTransitionDiagnostics:
    """Visible unthinned state-chain arithmetic with no raw-rate threshold."""

    state_count: int
    transition_opportunity_count: int
    transition_count: int
    transition_rate: float
    unique_state_count: int
    unique_state_fraction: float
    repeated_state_run_lengths: tuple[int, ...]
    max_repeated_state_run_length: int
    max_repeated_state_fraction: float
    endpoint_order: tuple[int, ...]
    endpoint_changed_position_count: int
    zero_transition: bool


@dataclass(frozen=True, slots=True)
class KdeProfileChainQuality:
    """The three non-pooled exact-target scores for one chain."""

    chain_slot: int
    position_score: float
    pairwise_precedence_score: float
    even_parity_score: float
    transition_diagnostics: KdeProfileTransitionDiagnostics
    convergence_assessment: ConvergenceAssessment


@dataclass(frozen=True, slots=True)
class KdeProfileFamilySummary:
    """One 18-chain family summary under the frozen threshold boundaries."""

    family: KdeProfileFamily
    chain_count: int
    inverse_empirical_cdf_median: float
    maximum: float
    status: KdeProfileTransitionStatus


@dataclass(frozen=True, slots=True)
class KdeProfileBudgetTransitionQuality:
    """One budget's transition-only outcome, never a profile selection."""

    budget: KdeProfileBudget
    retained_count_per_chain: int
    chain_count: int
    family_summaries: tuple[KdeProfileFamilySummary, ...]
    chain_quality: tuple[KdeProfileChainQuality, ...]
    all_chains_have_positive_unthinned_transitions: bool
    all_universe_convergence_gates_pass: bool
    distinct_zero_transition_endpoint_count: int
    status: KdeProfileTransitionStatus
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class KdeProfileTransitionQualityResult:
    """Ordered per-budget calculations with no receipt or selection authority."""

    rule_id: str
    budget_results: tuple[KdeProfileBudgetTransitionQuality, ...]
    all_budget_transition_statuses: tuple[KdeProfileTransitionStatus, ...]


@dataclass(frozen=True, slots=True)
class _AdmittedChain:
    budget: KdeProfileBudget
    chain_slot: int
    retained_states: NDArray[np.int64]
    unthinned_states: NDArray[np.int64]
    exact_position: NDArray[np.float64]
    exact_pairwise: NDArray[np.float64]
    exact_even_parity: float
    convergence_assessment: ConvergenceAssessment


@dataclass(frozen=True, slots=True)
class _IndicatorSeriesStatistics:
    retained_count: int
    full_mean: float
    first_half_mean: float
    second_half_mean: float
    geyer_ims_mcse: float


def _invalid(code: str) -> InvalidKdeProfileTransitionCalculation:
    return InvalidKdeProfileTransitionCalculation(code)


def _retained_count_for_budget(budget: KdeProfileBudget) -> int:
    for candidate, count in KDE_PROFILE_RETAINED_COUNTS:
        if budget == candidate:
            return count
    raise AssertionError("The closed budget registry is inconsistent.")


def _admit_budget(value: object) -> KdeProfileBudget:
    if type(value) is not int or value not in KDE_PROFILE_BUDGETS:
        raise _invalid("KDE_PROFILE.BUDGET")
    return value


def _admit_chain_slot(value: object) -> int:
    if (
        type(value) is not int
        or value < 0
        or value >= KDE_PROFILE_CHAIN_COUNT_PER_BUDGET
    ):
        raise _invalid("KDE_PROFILE.CHAIN_SLOT")
    return value


def _admit_event_ids(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) != KDE_PROFILE_EVENT_COUNT:
        raise _invalid("KDE_PROFILE.EVENT_IDS")
    event_ids = cast(tuple[object, ...], value)
    if any(
        type(event_id) is not str
        or event_id == ""
        or event_id != event_id.strip()
        for event_id in event_ids
    ):
        raise _invalid("KDE_PROFILE.EVENT_IDS")
    admitted = cast(tuple[str, ...], event_ids)
    if len(set(admitted)) != KDE_PROFILE_EVENT_COUNT:
        raise _invalid("KDE_PROFILE.EVENT_IDS")
    return admitted


def _admit_permutation_chain(
    value: object,
    *,
    required_count: int | None,
    code: str,
) -> NDArray[np.int64]:
    source = _NUMERIC_KERNEL.strict_integer_array(value)
    if source is None or source.ndim != 2 or source.shape[1] != KDE_PROFILE_EVENT_COUNT:
        raise _invalid(code)
    if required_count is None:
        if source.shape[0] < 2:
            raise _invalid(code)
    elif source.shape[0] != required_count:
        raise _invalid("KDE_PROFILE.RETAINED_DENOMINATOR")
    if not np.all((source >= 0) & (source < KDE_PROFILE_EVENT_COUNT)):
        raise _invalid(code)
    snapshot = np.array(source, dtype=np.int64, order="C", copy=True)
    target = np.arange(KDE_PROFILE_EVENT_COUNT, dtype=np.int64)
    if not np.all(np.sort(snapshot, axis=1, kind="stable") == target):
        raise _invalid(code)
    return snapshot


def _admit_probability_matrix(
    value: object,
    *,
    field_code: str,
) -> NDArray[np.float64]:
    source = _NUMERIC_KERNEL.strict_float_array(value)
    expected_shape = (KDE_PROFILE_EVENT_COUNT, KDE_PROFILE_EVENT_COUNT)
    if source is None or source.shape != expected_shape:
        raise _invalid(field_code)
    snapshot = np.array(source, dtype=np.float64, order="C", copy=True)
    if not np.all((snapshot >= 0.0) & (snapshot <= 1.0)):
        raise _invalid(field_code)
    return snapshot


def _admit_position_target(value: object) -> NDArray[np.float64]:
    target = _admit_probability_matrix(
        value,
        field_code="KDE_PROFILE.EXACT_POSITION_TARGET",
    )
    row_sums = tuple(math.fsum(float(item) for item in row) for row in target)
    column_sums = tuple(
        math.fsum(float(item) for item in target[:, column])
        for column in range(KDE_PROFILE_EVENT_COUNT)
    )
    if any(abs(total - 1.0) > _TARGET_SUM_TOLERANCE for total in (*row_sums, *column_sums)):
        raise _invalid("KDE_PROFILE.EXACT_POSITION_TARGET")
    return target


def _admit_pairwise_target(value: object) -> NDArray[np.float64]:
    target = _admit_probability_matrix(
        value,
        field_code="KDE_PROFILE.EXACT_PAIRWISE_TARGET",
    )
    for left in range(KDE_PROFILE_EVENT_COUNT):
        if abs(float(target[left, left]) - 0.5) > _TARGET_SUM_TOLERANCE:
            raise _invalid("KDE_PROFILE.EXACT_PAIRWISE_TARGET")
        for right in range(left + 1, KDE_PROFILE_EVENT_COUNT):
            if (
                abs(float(target[left, right]) + float(target[right, left]) - 1.0)
                > _TARGET_SUM_TOLERANCE
            ):
                raise _invalid("KDE_PROFILE.EXACT_PAIRWISE_TARGET")
    return target


def _admit_probability_scalar(value: object, *, code: str) -> float:
    source = _NUMERIC_KERNEL.strict_float_array(value)
    if source is None or source.ndim != 0:
        raise _invalid(code)
    target = float(source)
    if not 0.0 <= target <= 1.0:
        raise _invalid(code)
    return target


def _admit_convergence_assessment(value: object) -> ConvergenceAssessment:
    if type(value) is not str or value not in _VALID_CONVERGENCE_ASSESSMENTS:
        raise _invalid("KDE_PROFILE.CONVERGENCE_ASSESSMENT")
    return cast(ConvergenceAssessment, value)


def _admit_chain(value: object) -> _AdmittedChain:
    if type(value) is not KdeProfileChainInput:
        raise _invalid("KDE_PROFILE.CHAIN_INPUT")
    budget = _admit_budget(value.budget)
    _admit_event_ids(value.event_ids)
    retained_count = _retained_count_for_budget(budget)
    return _AdmittedChain(
        budget=budget,
        chain_slot=_admit_chain_slot(value.chain_slot),
        retained_states=_admit_permutation_chain(
            value.retained_order_states,
            required_count=retained_count,
            code="KDE_PROFILE.RETAINED_STATES",
        ),
        unthinned_states=_admit_permutation_chain(
            value.unthinned_postburn_order_states,
            required_count=None,
            code="KDE_PROFILE.UNTHINNED_STATES",
        ),
        exact_position=_admit_position_target(value.exact_position_probabilities),
        exact_pairwise=_admit_pairwise_target(value.exact_pairwise_precedence),
        exact_even_parity=_admit_probability_scalar(
            value.exact_even_parity_probability,
            code="KDE_PROFILE.EXACT_PARITY_TARGET",
        ),
        convergence_assessment=_admit_convergence_assessment(
            value.universe_convergence_assessment
        ),
    )


def _admit_binary_series(value: object) -> NDArray[np.float64]:
    source = _NUMERIC_KERNEL.strict_float_array(value)
    if (
        source is None
        or source.ndim != 1
        or source.size < 2
        or source.size % 2 != 0
        or not np.all((source == 0.0) | (source == 1.0))
    ):
        raise _invalid("KDE_PROFILE.BINARY_INDICATOR_SERIES")
    return np.array(source, dtype=np.float64, order="C", copy=True)


def _geyer_ims_mcse_snapshot(indicators: NDArray[np.float64]) -> float:
    count = int(indicators.size)
    mean = math.fsum(float(value) for value in indicators) / count
    centered = indicators - mean
    autocovariance = np.correlate(centered, centered, mode="full")[count - 1 :] / count
    gamma_zero = float(autocovariance[0])

    monotone_pairs: list[float] = []
    previous_pair = math.inf
    pair_index = 0
    while 2 * pair_index + 1 < count:
        pair_sum = float(
            autocovariance[2 * pair_index] + autocovariance[2 * pair_index + 1]
        )
        if pair_sum <= 0.0:
            break
        monotone_pair = min(previous_pair, pair_sum)
        monotone_pairs.append(monotone_pair)
        previous_pair = monotone_pair
        pair_index += 1

    long_run_variance = max(
        0.0,
        math.fsum((-gamma_zero, 2.0 * math.fsum(monotone_pairs))),
    )
    return math.sqrt(long_run_variance / count)


def geyer_initial_monotone_sequence_mcse(indicators: object) -> float:
    """Return the frozen Geyer-IMS MCSE for one even binary indicator series."""

    return _geyer_ims_mcse_snapshot(_admit_binary_series(indicators))


def _indicator_statistics(
    indicators: NDArray[np.float64],
) -> _IndicatorSeriesStatistics:
    count = int(indicators.size)
    half = count // 2
    return _IndicatorSeriesStatistics(
        retained_count=count,
        full_mean=math.fsum(float(value) for value in indicators) / count,
        first_half_mean=math.fsum(float(value) for value in indicators[:half]) / half,
        second_half_mean=math.fsum(float(value) for value in indicators[half:]) / half,
        geyer_ims_mcse=_geyer_ims_mcse_snapshot(indicators),
    )


def _score_from_statistics(
    statistics: _IndicatorSeriesStatistics,
    *,
    exact_target: float,
) -> IndicatorQualityScore:
    full_error = abs(statistics.full_mean - exact_target)
    first_error = abs(statistics.first_half_mean - exact_target)
    second_error = abs(statistics.second_half_mean - exact_target)
    upper_error = math.fsum((full_error, KDE_PROFILE_Z * statistics.geyer_ims_mcse))
    score = max(upper_error, first_error, second_error)
    if not math.isfinite(score):
        raise _invalid("KDE_PROFILE.NONFINITE_SCORE")
    return IndicatorQualityScore(
        retained_count=statistics.retained_count,
        full_mean=statistics.full_mean,
        exact_target=exact_target,
        full_absolute_error=full_error,
        geyer_ims_mcse=statistics.geyer_ims_mcse,
        full_error_upper_bound=upper_error,
        first_half_absolute_error=first_error,
        second_half_absolute_error=second_error,
        score=score,
    )


def calculate_indicator_quality(
    indicators: object,
    *,
    exact_target: object,
) -> IndicatorQualityScore:
    """Calculate the full-plus-MCSE and split-half exact-target envelope."""

    admitted = _admit_binary_series(indicators)
    target = _admit_probability_scalar(
        exact_target,
        code="KDE_PROFILE.EXACT_INDICATOR_TARGET",
    )
    return _score_from_statistics(_indicator_statistics(admitted), exact_target=target)


def summarize_kde_profile_family(
    family: KdeProfileFamily,
    scores: Sequence[float],
) -> KdeProfileFamilySummary:
    """Summarize exactly 18 finite non-negative scores without interpolation."""

    if type(family) is not str or family not in {
        "POSITION",
        "PAIRWISE_PRECEDENCE",
        "EVEN_PARITY",
    }:
        raise _invalid("KDE_PROFILE.FAMILY")
    source = _NUMERIC_KERNEL.strict_float_array(scores)
    if (
        source is None
        or source.ndim != 1
        or source.size != KDE_PROFILE_CHAIN_COUNT_PER_BUDGET
        or np.any(source < 0.0)
    ):
        raise _invalid("KDE_PROFILE.FAMILY_SCORES")
    ordered = np.sort(np.array(source, dtype=np.float64, copy=True), kind="stable")
    median = float(ordered[8])
    maximum = float(ordered[-1])
    status: KdeProfileTransitionStatus = (
        "PROFILE_QUALIFIED"
        if median <= KDE_PROFILE_MEDIAN_MAX and maximum <= KDE_PROFILE_MAXIMUM_MAX
        else "PROFILE_UNQUALIFIED"
    )
    return KdeProfileFamilySummary(
        family=family,
        chain_count=KDE_PROFILE_CHAIN_COUNT_PER_BUDGET,
        inverse_empirical_cdf_median=median,
        maximum=maximum,
        status=status,
    )


def _transition_diagnostics(
    states: NDArray[np.int64],
) -> KdeProfileTransitionDiagnostics:
    state_count = int(states.shape[0])
    changed = np.any(states[1:] != states[:-1], axis=1)
    transition_count = int(np.count_nonzero(changed))
    transition_opportunities = state_count - 1

    unique_state_count = len({tuple(int(value) for value in row) for row in states})
    runs: list[int] = []
    current_run = 1
    for did_change in changed:
        if bool(did_change):
            runs.append(current_run)
            current_run = 1
        else:
            current_run += 1
    runs.append(current_run)
    maximum_run = max(runs)
    endpoint = tuple(int(value) for value in states[-1])
    endpoint_changed_positions = int(np.count_nonzero(states[-1] != states[0]))
    return KdeProfileTransitionDiagnostics(
        state_count=state_count,
        transition_opportunity_count=transition_opportunities,
        transition_count=transition_count,
        transition_rate=transition_count / transition_opportunities,
        unique_state_count=unique_state_count,
        unique_state_fraction=unique_state_count / state_count,
        repeated_state_run_lengths=tuple(runs),
        max_repeated_state_run_length=maximum_run,
        max_repeated_state_fraction=maximum_run / state_count,
        endpoint_order=endpoint,
        endpoint_changed_position_count=endpoint_changed_positions,
        zero_transition=transition_count == 0,
    )


def _indicator_matrices(
    states: NDArray[np.int64],
) -> tuple[NDArray[np.float64], NDArray[np.float64], NDArray[np.float64]]:
    positions = np.argsort(states, axis=1, kind="stable")
    position_indicators = (
        positions[:, :, np.newaxis]
        == np.arange(KDE_PROFILE_EVENT_COUNT, dtype=np.int64)[np.newaxis, np.newaxis, :]
    ).reshape(states.shape[0], KDE_PROFILE_EVENT_COUNT**2)

    left, right = np.triu_indices(KDE_PROFILE_EVENT_COUNT, k=1)
    pairwise_indicators = positions[:, left] < positions[:, right]

    inversion_count = np.zeros(states.shape[0], dtype=np.int64)
    for left_index in range(KDE_PROFILE_EVENT_COUNT):
        for right_index in range(left_index + 1, KDE_PROFILE_EVENT_COUNT):
            inversion_count += states[:, left_index] > states[:, right_index]
    even_parity = inversion_count % 2 == 0
    return (
        position_indicators.astype(np.float64, copy=False),
        pairwise_indicators.astype(np.float64, copy=False),
        even_parity.astype(np.float64, copy=False),
    )


def _chain_quality(chain: _AdmittedChain) -> KdeProfileChainQuality:
    position, pairwise, parity = _indicator_matrices(chain.retained_states)
    left, right = np.triu_indices(KDE_PROFILE_EVENT_COUNT, k=1)
    position_targets = chain.exact_position.reshape(KDE_PROFILE_EVENT_COUNT**2)
    pairwise_targets = chain.exact_pairwise[left, right]

    statistics_cache: dict[bytes, _IndicatorSeriesStatistics] = {}

    def score(indicators: NDArray[np.float64], target: float) -> float:
        key = indicators.tobytes(order="C")
        statistics = statistics_cache.get(key)
        if statistics is None:
            statistics = _indicator_statistics(indicators)
            statistics_cache[key] = statistics
        return _score_from_statistics(statistics, exact_target=target).score

    position_score = max(
        score(position[:, coordinate], float(position_targets[coordinate]))
        for coordinate in range(KDE_PROFILE_EVENT_COUNT**2)
    )
    pairwise_score = max(
        score(pairwise[:, coordinate], float(pairwise_targets[coordinate]))
        for coordinate in range(len(left))
    )
    parity_score = score(parity, chain.exact_even_parity)
    return KdeProfileChainQuality(
        chain_slot=chain.chain_slot,
        position_score=position_score,
        pairwise_precedence_score=pairwise_score,
        even_parity_score=parity_score,
        transition_diagnostics=_transition_diagnostics(chain.unthinned_states),
        convergence_assessment=chain.convergence_assessment,
    )


def _budget_quality(
    budget: KdeProfileBudget,
    chains: tuple[_AdmittedChain, ...],
) -> KdeProfileBudgetTransitionQuality:
    chain_quality = tuple(_chain_quality(chain) for chain in chains)
    family_summaries = (
        summarize_kde_profile_family(
            "POSITION",
            tuple(item.position_score for item in chain_quality),
        ),
        summarize_kde_profile_family(
            "PAIRWISE_PRECEDENCE",
            tuple(item.pairwise_precedence_score for item in chain_quality),
        ),
        summarize_kde_profile_family(
            "EVEN_PARITY",
            tuple(item.even_parity_score for item in chain_quality),
        ),
    )
    all_positive = all(
        item.transition_diagnostics.transition_count > 0 for item in chain_quality
    )
    all_convergence_pass = all(
        item.convergence_assessment == "CONVERGENCE_PASS" for item in chain_quality
    )
    all_families_qualified = all(
        item.status == "PROFILE_QUALIFIED" for item in family_summaries
    )
    reason_codes: list[str] = []
    if not all_positive:
        reason_codes.append("ZERO_UNTHINNED_TRANSITIONS")
    if not all_convergence_pass:
        reason_codes.append("UNIVERSE_CONVERGENCE_NOT_PASS")
    for summary in family_summaries:
        if summary.status == "PROFILE_UNQUALIFIED":
            reason_codes.append(f"{summary.family}_QUALITY_UNQUALIFIED")

    zero_transition_endpoints = {
        item.transition_diagnostics.endpoint_order
        for item in chain_quality
        if item.transition_diagnostics.zero_transition
    }
    status: KdeProfileTransitionStatus = (
        "PROFILE_QUALIFIED"
        if all_positive and all_convergence_pass and all_families_qualified
        else "PROFILE_UNQUALIFIED"
    )
    return KdeProfileBudgetTransitionQuality(
        budget=budget,
        retained_count_per_chain=_retained_count_for_budget(budget),
        chain_count=KDE_PROFILE_CHAIN_COUNT_PER_BUDGET,
        family_summaries=family_summaries,
        chain_quality=chain_quality,
        all_chains_have_positive_unthinned_transitions=all_positive,
        all_universe_convergence_gates_pass=all_convergence_pass,
        distinct_zero_transition_endpoint_count=len(zero_transition_endpoints),
        status=status,
        reason_codes=tuple(reason_codes),
    )


def calculate_kde_profile_transition_quality(
    chains: Sequence[KdeProfileChainInput],
) -> KdeProfileTransitionQualityResult:
    """Calculate the closed 54-chain KDE profile transition-quality matrix.

    The output is transition-only.  Even when a budget is
    ``PROFILE_QUALIFIED``, a genuine outer evidence owner must independently
    apply convergence, relation, runtime, truth/stage, and selection contracts.
    """

    if isinstance(chains, (str, bytes)):
        raise _invalid("KDE_PROFILE.CHAIN_ROSTER")
    try:
        submitted = tuple(chains)
    except TypeError:
        raise _invalid("KDE_PROFILE.CHAIN_ROSTER") from None
    expected_total = len(KDE_PROFILE_BUDGETS) * KDE_PROFILE_CHAIN_COUNT_PER_BUDGET
    if len(submitted) != expected_total:
        raise _invalid("KDE_PROFILE.CHAIN_ROSTER")

    admitted = tuple(_admit_chain(chain) for chain in submitted)
    by_coordinate: dict[tuple[KdeProfileBudget, int], _AdmittedChain] = {}
    for chain in admitted:
        coordinate = (chain.budget, chain.chain_slot)
        if coordinate in by_coordinate:
            raise _invalid("KDE_PROFILE.DUPLICATE_CHAIN")
        by_coordinate[coordinate] = chain

    expected_coordinates = {
        (budget, slot)
        for budget in KDE_PROFILE_BUDGETS
        for slot in range(KDE_PROFILE_CHAIN_COUNT_PER_BUDGET)
    }
    if set(by_coordinate) != expected_coordinates:
        raise _invalid("KDE_PROFILE.CHAIN_ROSTER")

    budget_results = tuple(
        _budget_quality(
            budget,
            tuple(
                by_coordinate[(budget, slot)]
                for slot in range(KDE_PROFILE_CHAIN_COUNT_PER_BUDGET)
            ),
        )
        for budget in KDE_PROFILE_BUDGETS
    )
    return KdeProfileTransitionQualityResult(
        rule_id=KDE_PROFILE_TRANSITION_RULE_ID,
        budget_results=budget_results,
        all_budget_transition_statuses=tuple(
            result.status for result in budget_results
        ),
    )
