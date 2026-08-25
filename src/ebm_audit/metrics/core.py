"""Pure float64 implementations of the versioned metric contract.

These functions never turn an unavailable or malformed comparison into a
numeric zero.  A scalar or matrix is either assessable, or it carries a typed
reason explaining why it is absent.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Sequence
from dataclasses import FrozenInstanceError, dataclass, field
from typing import Any, Final, Literal

import numpy as np
from numpy.typing import NDArray

from ._numeric import _ISINSTANCE_OP, _NUMERIC_KERNEL, _IsInstanceOp

MetricStatus = Literal["ASSESSABLE", "NOT_ASSESSABLE"]
ScalarMetricMetadata = Literal["DEGENERATE_ONE_EVENT"]
PairwiseMajorityRelation = Literal["A_BEFORE_B", "B_BEFORE_A", "TIED"]
StrictPairwiseMajorityRelation = Literal["A_BEFORE_B", "B_BEFORE_A"]
FloatArray = NDArray[np.float64]
_OrderAccounting = tuple[
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]

# Frozen contract tolerance for accepting binary64 round-off at mathematical
# [0, 1] and [-1, 1] endpoints.  A larger excursion is never silently clipped.
METRIC_ABSOLUTE_TOLERANCE: Final = 1e-12
_SAFE_INTEGER_MAX: Final = 9_007_199_254_740_991
_SHA256_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PRIVATE_UNIT_PATTERN: Final = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
_MACHINE_ID_PATTERN: Final = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z", flags=re.ASCII)


@dataclass(frozen=True, slots=True)
class ScalarMetricResult:
    """One finite scalar, or an explicit typed absence."""

    status: MetricStatus
    value: float | int | bool | None
    reason_code: str | None
    metadata_code: ScalarMetricMetadata | None = None

    def __post_init__(self) -> None:
        if self.status not in {"ASSESSABLE", "NOT_ASSESSABLE"}:
            raise ValueError("A scalar metric has an unknown status.")
        if self.status == "ASSESSABLE":
            if self.value is None or self.reason_code is not None:
                raise ValueError("An assessable scalar requires one value and no reason.")
            if not isinstance(self.value, (float, int, bool)):
                raise ValueError("An assessable scalar must contain a numeric or boolean value.")
            if isinstance(self.value, float) and not math.isfinite(self.value):
                raise ValueError("An assessable scalar must be finite.")
            if self.metadata_code not in {None, "DEGENERATE_ONE_EVENT"}:
                raise ValueError("An assessable scalar has an unknown metadata code.")
            return
        if self.value is not None or self.reason_code is None or self.metadata_code is not None:
            raise ValueError(
                "An unassessable scalar requires no value, one reason, and no metadata."
            )


@dataclass(frozen=True, slots=True)
class MatrixMetricResult:
    """One finite float64 matrix, or an explicit typed absence."""

    status: MetricStatus
    value: FloatArray | None
    reason_code: str | None

    def __post_init__(self) -> None:
        if self.status not in {"ASSESSABLE", "NOT_ASSESSABLE"}:
            raise ValueError("A matrix metric has an unknown status.")
        if self.status == "ASSESSABLE":
            if self.value is None or self.reason_code is not None:
                raise ValueError("An assessable matrix requires one value and no reason.")
            if not isinstance(self.value, np.ndarray) or self.value.dtype != np.float64:
                raise ValueError("An assessable matrix must contain finite float64 values.")
            copied = np.array(self.value, dtype=np.float64, order="C", copy=True)
            if not np.all(np.isfinite(copied)):
                raise ValueError("An assessable matrix must contain finite float64 values.")
            # Back with immutable bytes, not merely writeable=False on an owning
            # ndarray (whose flag a caller could turn back on).
            frozen = np.frombuffer(copied.tobytes(order="C"), dtype=np.float64).reshape(
                copied.shape
            )
            object.__setattr__(self, "value", frozen)
            return
        if self.value is not None or self.reason_code is None:
            raise ValueError("An unassessable matrix requires no value and one reason.")


@dataclass(frozen=True, slots=True)
class StageComparisonIdentity:
    """Closed, privacy-safe identity required for one posterior comparison.

    ``event_directions`` is positionally aligned with ``event_ids``.  The row
    index and privacy-safe unit binding identify the exact participant inside
    the fixed evaluation cohort; raw participant identifiers are forbidden.
    Values are validated by every stage comparison function, so malformed or
    mismatched identities produce a typed absence instead of an exception.
    """

    event_ids: tuple[str, ...]
    event_directions: tuple[Literal["higher", "lower"], ...]
    stage_semantics_digest: str
    evaluation_cohort_digest: str
    evaluation_row_index: int
    evaluation_unit_binding: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class OrderComparison:
    """Complete strict-order comparison, including event-set accounting."""

    common_event_ids: tuple[str, ...]
    common_event_count: int
    events_only_in_left: tuple[str, ...]
    events_only_in_right: tuple[str, ...]
    kendall_distance: ScalarMetricResult
    footrule_distance: ScalarMetricResult


@dataclass(frozen=True, slots=True)
class EventRankShift:
    """One event's rank movement after restriction to the common event set."""

    event_id: str
    left_rank: int
    right_rank: int
    absolute_rank_shift: int
    normalized_rank_shift: float


@dataclass(frozen=True, slots=True)
class RankShiftComparison:
    """Per-event shifts with complete event-set accounting."""

    common_event_ids: tuple[str, ...]
    common_event_count: int
    events_only_in_left: tuple[str, ...]
    events_only_in_right: tuple[str, ...]
    shifts: tuple[EventRankShift, ...]
    maximum_normalized_rank_shift: ScalarMetricResult


@dataclass(frozen=True, slots=True)
class TopKStabilityComparison:
    """Predeclared top-k overlap and endpoint stability on common events."""

    common_event_ids: tuple[str, ...]
    common_event_count: int
    events_only_in_left: tuple[str, ...]
    events_only_in_right: tuple[str, ...]
    k: int | None
    top_k_overlap: ScalarMetricResult
    top_k_jaccard: ScalarMetricResult
    first_event_stable: ScalarMetricResult
    last_event_stable: ScalarMetricResult


@dataclass(frozen=True, slots=True)
class PositionQuantile:
    """One requested inverse-empirical-CDF event-position quantile."""

    probability: float
    position: int


@dataclass(frozen=True, slots=True)
class EventPositionSummary:
    """Immutable probability and location summary for one event."""

    event_id: str
    probability_by_position: tuple[float, ...]
    expected_position: float
    median_position: int
    quantiles: tuple[PositionQuantile, ...]
    normalized_entropy: float
    metadata_code: ScalarMetricMetadata | None = None


@dataclass(frozen=True, slots=True)
class PositionSummaryResult:
    """Per-event position summaries, or one typed absence."""

    status: MetricStatus
    value: tuple[EventPositionSummary, ...] | None
    reason_code: str | None

    def __post_init__(self) -> None:
        if self.status == "ASSESSABLE":
            if self.value is None or self.reason_code is not None:
                raise ValueError("Assessable position summaries require values and no reason.")
            return
        if self.status == "NOT_ASSESSABLE":
            if self.value is not None or self.reason_code is None:
                raise ValueError("Unassessable position summaries require no value and one reason.")
            return
        raise ValueError("Position summaries have an unknown status.")


@dataclass(frozen=True, slots=True)
class PairwiseMajority:
    """One canonical event pair's strict-majority relation."""

    event_a_id: str
    event_b_id: str
    probability_a_before_b: float
    relation: PairwiseMajorityRelation


@dataclass(frozen=True, slots=True)
class PairwiseMajorityResult:
    """Canonical strict-majority relations, or one typed absence."""

    status: MetricStatus
    value: tuple[PairwiseMajority, ...] | None
    reason_code: str | None

    def __post_init__(self) -> None:
        if self.status == "ASSESSABLE":
            if self.value is None or self.reason_code is not None:
                raise ValueError("Assessable pairwise relations require values and no reason.")
            return
        if self.status == "NOT_ASSESSABLE":
            if self.value is not None or self.reason_code is None:
                raise ValueError("Unassessable pairwise relations require no value and one reason.")
            return
        raise ValueError("Pairwise relations have an unknown status.")


@dataclass(frozen=True, slots=True)
class PairwiseMajorityFlip:
    """One opposing strict majority in canonical UTF-8 event orientation."""

    event_a_id: str
    event_b_id: str
    left_probability_a_before_b: float
    right_probability_a_before_b: float
    left_relation: StrictPairwiseMajorityRelation
    right_relation: StrictPairwiseMajorityRelation


@dataclass(frozen=True, slots=True)
class PairwiseMajorityComparison:
    """Strict-majority flips with the complete common-pair denominator."""

    common_event_ids: tuple[str, ...]
    common_event_count: int
    events_only_in_left: tuple[str, ...]
    events_only_in_right: tuple[str, ...]
    strict_pairwise_majority_flip_denominator: int | None
    flips: tuple[PairwiseMajorityFlip, ...]
    flip_count: ScalarMetricResult
    flip_fraction: ScalarMetricResult


@dataclass(frozen=True, slots=True)
class StageExpectedMovement:
    """Expected-stage movement for one semantically aligned participant."""

    left_expected_stage: ScalarMetricResult
    right_expected_stage: ScalarMetricResult
    signed_expected_stage_change: ScalarMetricResult
    absolute_expected_stage_change: ScalarMetricResult
    normalized_absolute_expected_stage_change: ScalarMetricResult


@dataclass(frozen=True, slots=True)
class StageMapAgreement:
    """Tie-preserving MAP evidence for one participant."""

    status: MetricStatus
    left_map_stage: int | None
    right_map_stage: int | None
    left_tied_stages: tuple[int, ...]
    right_tied_stages: tuple[int, ...]
    left_has_tie: bool | None
    right_has_tie: bool | None
    agreement: bool | None
    reason_code: str | None

    def __post_init__(self) -> None:
        if self.status == "ASSESSABLE":
            if (
                self.left_map_stage is None
                or self.right_map_stage is None
                or not self.left_tied_stages
                or not self.right_tied_stages
                or self.left_has_tie is None
                or self.right_has_tie is None
                or self.agreement is None
                or self.reason_code is not None
            ):
                raise ValueError("Assessable MAP agreement requires complete tie evidence.")
            return
        if self.status == "NOT_ASSESSABLE":
            if (
                self.left_map_stage is not None
                or self.right_map_stage is not None
                or self.left_tied_stages
                or self.right_tied_stages
                or self.left_has_tie is not None
                or self.right_has_tie is not None
                or self.agreement is not None
                or self.reason_code is None
            ):
                raise ValueError("Unassessable MAP agreement requires only one reason.")
            return
        raise ValueError("MAP agreement has an unknown status.")


@dataclass(frozen=True, slots=True)
class CohortStageMapAgreement:
    """Mean MAP equality with every participant's retained tie evidence."""

    status: MetricStatus
    value: float | None
    participant_agreements: tuple[StageMapAgreement, ...] | None
    reason_code: str | None

    def __post_init__(self) -> None:
        if self.status == "ASSESSABLE":
            if (
                self.value is None
                or self.participant_agreements is None
                or self.reason_code is not None
            ):
                raise ValueError("Assessable cohort MAP agreement requires values and no reason.")
            return
        if self.status == "NOT_ASSESSABLE":
            if (
                self.value is not None
                or self.participant_agreements is not None
                or self.reason_code is None
            ):
                raise ValueError(
                    "Unassessable cohort MAP agreement requires no value and one reason."
                )
            return
        raise ValueError("Cohort MAP agreement has an unknown status.")


@dataclass(frozen=True, slots=True)
class _FrozenDataclassMethods:
    eq: Callable[[object, object], object]
    hash: Callable[[object], int]
    setattr: Callable[[object, str, object], None]
    delattr: Callable[[object, str], None]


def _build_frozen_dataclass_methods(
    *,
    class_type: type[Any],
    field_names: tuple[str, ...],
    frozenset_op: Callable[..., frozenset[str]],
    frozen_instance_error_type: type[FrozenInstanceError],
    getattr_op: Callable[..., Any],
    hash_op: Callable[[object], int],
    not_implemented: object,
    super_op: Callable[..., Any],
    tuple_type: type[tuple[Any, ...]],
    type_op: Callable[[object], type[Any]],
) -> _FrozenDataclassMethods:
    frozen_field_names = frozenset_op(field_names)

    def __eq__(self: object, other: object) -> object:
        if other.__class__ is self.__class__:
            return tuple_type(getattr_op(self, name) for name in field_names) == tuple_type(
                getattr_op(other, name) for name in field_names
            )
        return not_implemented

    def __hash__(self: object) -> int:
        return hash_op(tuple_type(getattr_op(self, name) for name in field_names))

    def __setattr__(self: object, name: str, value: object) -> None:
        if type_op(self) is class_type or name in frozen_field_names:
            raise frozen_instance_error_type(f"cannot assign to field {name!r}")
        super_op(class_type, self).__setattr__(name, value)

    def __delattr__(self: object, name: str) -> None:
        if type_op(self) is class_type or name in frozen_field_names:
            raise frozen_instance_error_type(f"cannot delete field {name!r}")
        super_op(class_type, self).__delattr__(name)

    return _FrozenDataclassMethods(
        eq=__eq__,
        hash=__hash__,
        setattr=__setattr__,
        delattr=__delattr__,
    )


@dataclass(frozen=True, slots=True)
class _MetricClassHooks:
    scalar_metric_result_post_init: Callable[[ScalarMetricResult], None]
    matrix_metric_result_post_init: Callable[[MatrixMetricResult], None]
    position_summary_result_post_init: Callable[[PositionSummaryResult], None]
    pairwise_majority_result_post_init: Callable[[PairwiseMajorityResult], None]
    stage_map_agreement_post_init: Callable[[StageMapAgreement], None]
    cohort_stage_map_agreement_post_init: Callable[[CohortStageMapAgreement], None]


def _build_metric_class_hooks(
    *,
    all_op: Callable[..., Any],
    bool_type: type[bool],
    float64_type: type[np.float64],
    float_type: type[float],
    frombuffer_op: Callable[..., Any],
    int_type: type[int],
    isfinite_op: Callable[..., Any],
    isinstance_op: _IsInstanceOp,
    math_isfinite: Callable[..., bool],
    ndarray_type: type[np.ndarray[Any, Any]],
    numpy_array_op: Callable[..., Any],
    object_setattr_op: Callable[[object, str, object], None],
    value_error_type: type[ValueError],
) -> _MetricClassHooks:
    def scalar_metric_result_post_init(self: ScalarMetricResult) -> None:
        if self.status not in {"ASSESSABLE", "NOT_ASSESSABLE"}:
            raise value_error_type("A scalar metric has an unknown status.")
        if self.status == "ASSESSABLE":
            if self.value is None or self.reason_code is not None:
                raise value_error_type("An assessable scalar requires one value and no reason.")
            if (
                not isinstance_op(self.value, float_type)
                and not isinstance_op(self.value, int_type)
                and not isinstance_op(self.value, bool_type)
            ):
                raise value_error_type(
                    "An assessable scalar must contain a numeric or boolean value."
                )
            if isinstance_op(self.value, float_type) and not math_isfinite(self.value):
                raise value_error_type("An assessable scalar must be finite.")
            if self.metadata_code not in {None, "DEGENERATE_ONE_EVENT"}:
                raise value_error_type("An assessable scalar has an unknown metadata code.")
            return
        if self.value is not None or self.reason_code is None or self.metadata_code is not None:
            raise value_error_type(
                "An unassessable scalar requires no value, one reason, and no metadata."
            )

    def matrix_metric_result_post_init(self: MatrixMetricResult) -> None:
        if self.status not in {"ASSESSABLE", "NOT_ASSESSABLE"}:
            raise value_error_type("A matrix metric has an unknown status.")
        if self.status == "ASSESSABLE":
            value = self.value
            if value is None or self.reason_code is not None:
                raise value_error_type("An assessable matrix requires one value and no reason.")
            if not isinstance_op(value, ndarray_type) or value.dtype != float64_type:
                raise value_error_type("An assessable matrix must contain finite float64 values.")
            copied: FloatArray = numpy_array_op(value, dtype=float64_type, order="C", copy=True)
            if not all_op(isfinite_op(copied)):
                raise value_error_type("An assessable matrix must contain finite float64 values.")
            frozen: FloatArray = frombuffer_op(
                copied.tobytes(order="C"), dtype=float64_type
            ).reshape(copied.shape)
            object_setattr_op(self, "value", frozen)
            return
        if self.value is not None or self.reason_code is None:
            raise value_error_type("An unassessable matrix requires no value and one reason.")

    def position_summary_result_post_init(self: PositionSummaryResult) -> None:
        if self.status == "ASSESSABLE":
            if self.value is None or self.reason_code is not None:
                raise value_error_type(
                    "Assessable position summaries require values and no reason."
                )
            return
        if self.status == "NOT_ASSESSABLE":
            if self.value is not None or self.reason_code is None:
                raise value_error_type(
                    "Unassessable position summaries require no value and one reason."
                )
            return
        raise value_error_type("Position summaries have an unknown status.")

    def pairwise_majority_result_post_init(self: PairwiseMajorityResult) -> None:
        if self.status == "ASSESSABLE":
            if self.value is None or self.reason_code is not None:
                raise value_error_type(
                    "Assessable pairwise relations require values and no reason."
                )
            return
        if self.status == "NOT_ASSESSABLE":
            if self.value is not None or self.reason_code is None:
                raise value_error_type(
                    "Unassessable pairwise relations require no value and one reason."
                )
            return
        raise value_error_type("Pairwise relations have an unknown status.")

    def stage_map_agreement_post_init(self: StageMapAgreement) -> None:
        if self.status == "ASSESSABLE":
            if (
                self.left_map_stage is None
                or self.right_map_stage is None
                or not self.left_tied_stages
                or not self.right_tied_stages
                or self.left_has_tie is None
                or self.right_has_tie is None
                or self.agreement is None
                or self.reason_code is not None
            ):
                raise value_error_type("Assessable MAP agreement requires complete tie evidence.")
            return
        if self.status == "NOT_ASSESSABLE":
            if (
                self.left_map_stage is not None
                or self.right_map_stage is not None
                or self.left_tied_stages
                or self.right_tied_stages
                or self.left_has_tie is not None
                or self.right_has_tie is not None
                or self.agreement is not None
                or self.reason_code is None
            ):
                raise value_error_type("Unassessable MAP agreement requires only one reason.")
            return
        raise value_error_type("MAP agreement has an unknown status.")

    def cohort_stage_map_agreement_post_init(self: CohortStageMapAgreement) -> None:
        if self.status == "ASSESSABLE":
            if (
                self.value is None
                or self.participant_agreements is None
                or self.reason_code is not None
            ):
                raise value_error_type(
                    "Assessable cohort MAP agreement requires values and no reason."
                )
            return
        if self.status == "NOT_ASSESSABLE":
            if (
                self.value is not None
                or self.participant_agreements is not None
                or self.reason_code is None
            ):
                raise value_error_type(
                    "Unassessable cohort MAP agreement requires no value and one reason."
                )
            return
        raise value_error_type("Cohort MAP agreement has an unknown status.")

    return _MetricClassHooks(
        scalar_metric_result_post_init=scalar_metric_result_post_init,
        matrix_metric_result_post_init=matrix_metric_result_post_init,
        position_summary_result_post_init=position_summary_result_post_init,
        pairwise_majority_result_post_init=pairwise_majority_result_post_init,
        stage_map_agreement_post_init=stage_map_agreement_post_init,
        cohort_stage_map_agreement_post_init=cohort_stage_map_agreement_post_init,
    )


_METRIC_CLASS_HOOKS = _build_metric_class_hooks(
    all_op=np.all,
    bool_type=bool,
    float64_type=np.float64,
    float_type=float,
    frombuffer_op=np.frombuffer,
    int_type=int,
    isfinite_op=np.isfinite,
    isinstance_op=_ISINSTANCE_OP,
    math_isfinite=math.isfinite,
    ndarray_type=np.ndarray,
    numpy_array_op=np.array,
    object_setattr_op=object.__setattr__,
    value_error_type=ValueError,
)

_POST_INIT_HOOKS = (
    (ScalarMetricResult, _METRIC_CLASS_HOOKS.scalar_metric_result_post_init),
    (MatrixMetricResult, _METRIC_CLASS_HOOKS.matrix_metric_result_post_init),
    (PositionSummaryResult, _METRIC_CLASS_HOOKS.position_summary_result_post_init),
    (PairwiseMajorityResult, _METRIC_CLASS_HOOKS.pairwise_majority_result_post_init),
    (StageMapAgreement, _METRIC_CLASS_HOOKS.stage_map_agreement_post_init),
    (CohortStageMapAgreement, _METRIC_CLASS_HOOKS.cohort_stage_map_agreement_post_init),
)
for _post_init_class, _post_init_hook in _POST_INIT_HOOKS:
    _post_init_hook.__name__ = "__post_init__"
    _post_init_hook.__qualname__ = f"{_post_init_class.__qualname__}.__post_init__"
    _post_init_hook.__module__ = __name__
    setattr(_post_init_class, "__post_init__", _post_init_hook)  # noqa: B010

_FROZEN_METRIC_CLASSES = (
    ScalarMetricResult,
    MatrixMetricResult,
    StageComparisonIdentity,
    OrderComparison,
    EventRankShift,
    RankShiftComparison,
    TopKStabilityComparison,
    PositionQuantile,
    EventPositionSummary,
    PositionSummaryResult,
    PairwiseMajority,
    PairwiseMajorityResult,
    PairwiseMajorityFlip,
    PairwiseMajorityComparison,
    StageExpectedMovement,
    StageMapAgreement,
    CohortStageMapAgreement,
)
for _frozen_class_type in _FROZEN_METRIC_CLASSES:
    _frozen_methods = _build_frozen_dataclass_methods(
        class_type=_frozen_class_type,
        field_names=tuple(_frozen_class_type.__dataclass_fields__),
        frozenset_op=frozenset,
        frozen_instance_error_type=FrozenInstanceError,
        getattr_op=getattr,
        hash_op=hash,
        not_implemented=NotImplemented,
        super_op=super,
        tuple_type=tuple,
        type_op=type,
    )
    for _method_name, _method in (
        ("__eq__", _frozen_methods.eq),
        ("__hash__", _frozen_methods.hash),
        ("__setattr__", _frozen_methods.setattr),
        ("__delattr__", _frozen_methods.delattr),
    ):
        _method.__name__ = _method_name
        _method.__qualname__ = f"{_frozen_class_type.__qualname__}.{_method_name}"
        _method.__module__ = __name__
        setattr(_frozen_class_type, _method_name, _method)


@dataclass(frozen=True, slots=True)
class _MetricKernel:
    """Exact import-time metric operations shared by science derivation."""

    _assessable: Callable[..., ScalarMetricResult]
    _not_assessable: Callable[..., ScalarMetricResult]
    _matrix: Callable[..., MatrixMetricResult]
    _no_matrix: Callable[..., MatrixMetricResult]
    _finite_vector: Callable[..., FloatArray | None]
    _finite_real_scalar: Callable[..., float | None]
    _bounded_unit: Callable[..., ScalarMetricResult]
    _bounded_signed_unit: Callable[..., ScalarMetricResult]
    _valid_order: Callable[..., tuple[str, ...] | None]
    _same_event_order_inputs: Callable[..., tuple[tuple[str, ...], tuple[str, ...]] | None]
    empirical_quantile: Callable[..., ScalarMetricResult]
    normalized_kendall_distance: Callable[..., ScalarMetricResult]
    normalized_spearman_footrule_distance: Callable[..., ScalarMetricResult]
    strict_order_comparison: Callable[..., OrderComparison]
    _common_order_accounting: Callable[..., _OrderAccounting | None]
    per_event_rank_shifts: Callable[..., RankShiftComparison]
    top_k_stability: Callable[..., TopKStabilityComparison]
    position_matrix: Callable[..., MatrixMetricResult]
    _valid_position_matrix: Callable[..., FloatArray | None]
    position_matrix_distance: Callable[..., ScalarMetricResult]
    position_concentration: Callable[..., ScalarMetricResult]
    _position_quantile: Callable[..., int]
    position_event_summaries: Callable[..., PositionSummaryResult]
    pairwise_precedence_matrix: Callable[..., MatrixMetricResult]
    _valid_pairwise_matrix: Callable[..., FloatArray | None]
    pairwise_matrix_distance: Callable[..., ScalarMetricResult]
    pairwise_concentration: Callable[..., ScalarMetricResult]
    _strict_pairwise_relation: Callable[..., PairwiseMajorityRelation]
    strict_pairwise_majority_relations: Callable[..., PairwiseMajorityResult]
    strict_pairwise_majority_flips: Callable[..., PairwiseMajorityComparison]
    _valid_stage_distribution: Callable[..., FloatArray | None]
    expected_stage: Callable[..., ScalarMetricResult]
    _valid_stage_identity: Callable[..., tuple[object, ...] | None]
    _validated_stage_pair: Callable[
        ..., tuple[FloatArray | None, FloatArray | None, int | None, str | None]
    ]
    normalized_stage_wasserstein: Callable[..., ScalarMetricResult]
    stage_expected_movement: Callable[..., StageExpectedMovement]
    _map_tied_stages: Callable[..., tuple[int, ...]]
    _map_agreement_from_values: Callable[..., StageMapAgreement]
    stage_map_agreement: Callable[..., StageMapAgreement]
    normalized_stage_jensen_shannon_distance: Callable[..., ScalarMetricResult]
    _valid_stage_identity_sequence: Callable[..., tuple[tuple[object, ...], ...] | None]
    _valid_stage_posterior_matrix: Callable[..., FloatArray | None]
    _validated_stage_cohort_pair: Callable[
        ..., tuple[FloatArray | None, FloatArray | None, int | None, str | None]
    ]
    cohort_stage_map_agreement: Callable[..., CohortStageMapAgreement]
    cohort_normalized_stage_wasserstein: Callable[..., ScalarMetricResult]
    normalized_known_truth_stage_mae: Callable[..., ScalarMetricResult]
    cohort_stage_distribution: Callable[..., MatrixMetricResult]
    empirical_null_comparison: Callable[..., tuple[ScalarMetricResult, ScalarMetricResult]]
    _average_ranks: Callable[..., FloatArray]
    spearman_rank_correlation: Callable[..., ScalarMetricResult]


def _build_metric_kernel(
    *,
    abs_op: Callable[..., Any],
    any_op: Callable[..., Any],
    bool_type: type[bool],
    bytes_type: type[bytes],
    enumerate_op: Callable[..., Any],
    float_type: type[float],
    int_type: type[int],
    isinstance_op: _IsInstanceOp,
    len_op: Callable[..., int],
    max_op: Callable[..., Any],
    min_op: Callable[..., Any],
    range_op: Callable[..., Any],
    set_op: Callable[..., Any],
    sorted_op: Callable[..., Any],
    str_type: type[str],
    sum_op: Callable[..., Any],
    tuple_type: type[tuple[Any, ...]],
    zip_op: Callable[..., Any],
    strict_float_array_op: Callable[[object], FloatArray | None],
    strict_integer_array_op: Callable[[object], NDArray[np.integer] | None],
    sequence_type: type[Any],
    scalar_metric_result_type: type[ScalarMetricResult],
    matrix_metric_result_type: type[MatrixMetricResult],
    stage_comparison_identity_type: type[StageComparisonIdentity],
    order_comparison_type: type[OrderComparison],
    event_rank_shift_type: type[EventRankShift],
    rank_shift_comparison_type: type[RankShiftComparison],
    top_k_stability_comparison_type: type[TopKStabilityComparison],
    position_quantile_type: type[PositionQuantile],
    event_position_summary_type: type[EventPositionSummary],
    position_summary_result_type: type[PositionSummaryResult],
    pairwise_majority_type: type[PairwiseMajority],
    pairwise_majority_result_type: type[PairwiseMajorityResult],
    pairwise_majority_flip_type: type[PairwiseMajorityFlip],
    pairwise_majority_comparison_type: type[PairwiseMajorityComparison],
    stage_expected_movement_type: type[StageExpectedMovement],
    stage_map_agreement_type: type[StageMapAgreement],
    cohort_stage_map_agreement_type: type[CohortStageMapAgreement],
    metric_absolute_tolerance: float,
    safe_integer_max: int,
    sha256_pattern: re.Pattern[str],
    private_unit_pattern: re.Pattern[str],
    machine_id_pattern: re.Pattern[str],
    np_abs: Callable[..., Any],
    np_all: Callable[..., Any],
    np_allclose: Callable[..., Any],
    np_any: Callable[..., Any],
    np_arange: Callable[..., Any],
    np_argsort: Callable[..., Any],
    np_asarray: Callable[..., Any],
    np_count_nonzero: Callable[..., Any],
    np_cumsum: Callable[..., Any],
    np_diag: Callable[..., Any],
    np_dot: Callable[..., Any],
    np_empty: Callable[..., Any],
    np_fill_diagonal: Callable[..., Any],
    np_flatnonzero: Callable[..., Any],
    np_float64: type[np.float64],
    np_isfinite: Callable[..., Any],
    np_log: Callable[..., Any],
    np_max: Callable[..., Any],
    np_mean: Callable[..., Any],
    np_searchsorted: Callable[..., Any],
    np_sort: Callable[..., Any],
    np_sum: Callable[..., Any],
    np_triu_indices: Callable[..., Any],
    np_zeros: Callable[..., Any],
    np_zeros_like: Callable[..., Any],
    math_ceil: Callable[[float], int],
    math_comb: Callable[[int, int], int],
    math_floor: Callable[[float], int],
    math_isclose: Callable[..., bool],
    math_isfinite: Callable[[float], bool],
    math_log: Callable[[float], float],
    math_sqrt: Callable[[float], float],
) -> _MetricKernel:
    def _assessable(
        value: float | int | bool, *, metadata_code: ScalarMetricMetadata | None = None
    ) -> ScalarMetricResult:
        return scalar_metric_result_type("ASSESSABLE", value, None, metadata_code)

    def _not_assessable(reason_code: str) -> ScalarMetricResult:
        return scalar_metric_result_type("NOT_ASSESSABLE", None, reason_code)

    def _matrix(value: FloatArray) -> MatrixMetricResult:
        return matrix_metric_result_type("ASSESSABLE", value, None)

    def _no_matrix(reason_code: str) -> MatrixMetricResult:
        return matrix_metric_result_type("NOT_ASSESSABLE", None, reason_code)

    def _finite_vector(values: Sequence[float] | FloatArray) -> FloatArray | None:
        array = strict_float_array_op(values)
        if array is None:
            return None
        if array.ndim != 1 or not np_all(np_isfinite(array)):
            return None
        return array

    def _finite_real_scalar(value: object) -> float | None:
        array = strict_float_array_op(value)
        if array is None or array.ndim != 0:
            return None
        converted = float_type(array)
        if not math_isfinite(converted):
            return None
        return converted

    def _bounded_unit(value: object, *, reason_code: str) -> ScalarMetricResult:
        """Return a unit value, allowing only 1e-12 of endpoint round-off."""

        converted = _finite_real_scalar(value)
        if converted is None:
            return _not_assessable(reason_code)
        if converted < -metric_absolute_tolerance or converted > 1.0 + metric_absolute_tolerance:
            return _not_assessable(reason_code)
        return _assessable(min_op(1.0, max_op(0.0, converted)))

    def _bounded_signed_unit(value: object, *, reason_code: str) -> ScalarMetricResult:
        """Return a signed-unit value with the same frozen endpoint tolerance."""

        converted = _finite_real_scalar(value)
        if converted is None:
            return _not_assessable(reason_code)
        if (
            converted < -1.0 - metric_absolute_tolerance
            or converted > 1.0 + metric_absolute_tolerance
        ):
            return _not_assessable(reason_code)
        return _assessable(min_op(1.0, max_op(-1.0, converted)))

    def _valid_order(order: object) -> tuple[str, ...] | None:
        if (
            isinstance_op(order, str_type)
            or isinstance_op(order, bytes_type)
            or not isinstance_op(order, sequence_type)
        ):
            return None
        values = tuple_type(order)
        if not values or any_op(
            not isinstance_op(event_id, str_type) or machine_id_pattern.fullmatch(event_id) is None
            for event_id in values
        ):
            return None
        if len_op(set_op(values)) != len_op(values):
            return None
        return values

    def _same_event_order_inputs(
        left: Sequence[str], right: Sequence[str]
    ) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
        left_order = _valid_order(left)
        right_order = _valid_order(right)
        if left_order is None or right_order is None or set_op(left_order) != set_op(right_order):
            return None
        return left_order, right_order

    def empirical_quantile(values: Sequence[float], probability: float) -> ScalarMetricResult:
        """Return ``x[max_op(0, ceil(p*n)-1)]`` without interpolation."""

        array = _finite_vector(values)
        if array is None:
            return _not_assessable("METRIC.NONFINITE_OR_INVALID_VALUES")
        if array.size == 0:
            return _not_assessable("METRIC.EMPTY_VALUES")
        checked_probability = _finite_real_scalar(probability)
        if checked_probability is None or not 0.0 <= checked_probability <= 1.0:
            return _not_assessable("METRIC.INVALID_QUANTILE_PROBABILITY")
        ordered = np_sort(array, kind="stable")
        index = max_op(0, math_ceil(checked_probability * ordered.size) - 1)
        return _assessable(float_type(ordered[index]))

    def normalized_kendall_distance(
        left: Sequence[str], right: Sequence[str]
    ) -> ScalarMetricResult:
        """Return normalized inversion distance for two equal event sets."""

        validated = _same_event_order_inputs(left, right)
        if validated is None:
            return _not_assessable("ORDER.INVALID_OR_DIFFERENT_EVENT_SETS")
        left_order, right_order = validated
        count = len_op(left_order)
        if count < 2:
            return _not_assessable("ORDER.FEWER_THAN_TWO_COMMON_EVENTS")
        right_rank = {event_id: index for index, event_id in enumerate_op(right_order)}
        discordant = 0
        for first_index in range_op(count - 1):
            for second_index in range_op(first_index + 1, count):
                if right_rank[left_order[first_index]] > right_rank[left_order[second_index]]:
                    discordant += 1
        return _bounded_unit(
            discordant / math_comb(count, 2), reason_code="ORDER.NUMERIC_BOUND_VIOLATION"
        )

    def normalized_spearman_footrule_distance(
        left: Sequence[str], right: Sequence[str]
    ) -> ScalarMetricResult:
        """Return normalized Spearman footrule distance for equal event sets."""

        validated = _same_event_order_inputs(left, right)
        if validated is None:
            return _not_assessable("ORDER.INVALID_OR_DIFFERENT_EVENT_SETS")
        left_order, right_order = validated
        count = len_op(left_order)
        if count < 2:
            return _not_assessable("ORDER.FEWER_THAN_TWO_COMMON_EVENTS")
        right_rank = {event_id: index for index, event_id in enumerate_op(right_order)}
        numerator = sum_op(
            abs_op(left_index - right_rank[event_id])
            for left_index, event_id in enumerate_op(left_order)
        )
        return _bounded_unit(
            numerator / math_floor(count * count / 2),
            reason_code="ORDER.NUMERIC_BOUND_VIOLATION",
        )

    def strict_order_comparison(left: Sequence[str], right: Sequence[str]) -> OrderComparison:
        """Compare orders on their common set and retain all omitted event IDs."""

        left_order = _valid_order(left)
        right_order = _valid_order(right)
        if left_order is None or right_order is None:
            unavailable = _not_assessable("ORDER.INVALID_ORDER")
            return order_comparison_type((), 0, (), (), unavailable, unavailable)

        left_set = set_op(left_order)
        right_set = set_op(right_order)
        common_in_left_order = tuple_type(
            event_id for event_id in left_order if event_id in right_set
        )
        common_in_right_order = tuple_type(
            event_id for event_id in right_order if event_id in left_set
        )
        canonical_common = tuple_type(
            sorted_op(left_set & right_set, key=lambda value: value.encode("utf-8"))
        )
        left_only = tuple_type(
            sorted_op(left_set - right_set, key=lambda value: value.encode("utf-8"))
        )
        right_only = tuple_type(
            sorted_op(right_set - left_set, key=lambda value: value.encode("utf-8"))
        )
        if len_op(canonical_common) < 2:
            unavailable = _not_assessable("ORDER.FEWER_THAN_TWO_COMMON_EVENTS")
            return order_comparison_type(
                canonical_common,
                len_op(canonical_common),
                left_only,
                right_only,
                unavailable,
                unavailable,
            )
        return order_comparison_type(
            canonical_common,
            len_op(canonical_common),
            left_only,
            right_only,
            normalized_kendall_distance(common_in_left_order, common_in_right_order),
            normalized_spearman_footrule_distance(common_in_left_order, common_in_right_order),
        )

    def _common_order_accounting(
        left: Sequence[str],
        right: Sequence[str],
    ) -> _OrderAccounting | None:
        left_order = _valid_order(left)
        right_order = _valid_order(right)
        if left_order is None or right_order is None:
            return None
        left_set = set_op(left_order)
        right_set = set_op(right_order)
        common_set = left_set & right_set
        return (
            tuple_type(event_id for event_id in left_order if event_id in common_set),
            tuple_type(event_id for event_id in right_order if event_id in common_set),
            tuple_type(sorted_op(common_set, key=lambda value: value.encode("utf-8"))),
            tuple_type(sorted_op(left_set - right_set, key=lambda value: value.encode("utf-8"))),
            tuple_type(sorted_op(right_set - left_set, key=lambda value: value.encode("utf-8"))),
        )

    def per_event_rank_shifts(
        left: Sequence[str],
        right: Sequence[str],
    ) -> RankShiftComparison:
        """Return common-set rank shifts in canonical event-ID order."""

        accounting = _common_order_accounting(left, right)
        if accounting is None:
            unavailable = _not_assessable("ORDER.INVALID_ORDER")
            return rank_shift_comparison_type((), 0, (), (), (), unavailable)
        left_common, right_common, common_ids, left_only, right_only = accounting
        if len_op(common_ids) < 2:
            unavailable = _not_assessable("ORDER.FEWER_THAN_TWO_COMMON_EVENTS")
            return rank_shift_comparison_type(
                common_ids,
                len_op(common_ids),
                left_only,
                right_only,
                (),
                unavailable,
            )

        left_rank = {event_id: index for index, event_id in enumerate_op(left_common)}
        right_rank = {event_id: index for index, event_id in enumerate_op(right_common)}
        normalizer = len_op(common_ids) - 1
        shifts = tuple_type(
            event_rank_shift_type(
                event_id=event_id,
                left_rank=left_rank[event_id],
                right_rank=right_rank[event_id],
                absolute_rank_shift=abs_op(left_rank[event_id] - right_rank[event_id]),
                normalized_rank_shift=abs_op(left_rank[event_id] - right_rank[event_id])
                / normalizer,
            )
            for event_id in common_ids
        )
        maximum = max_op(shift.normalized_rank_shift for shift in shifts)
        return rank_shift_comparison_type(
            common_ids,
            len_op(common_ids),
            left_only,
            right_only,
            shifts,
            _bounded_unit(maximum, reason_code="ORDER.NUMERIC_BOUND_VIOLATION"),
        )

    def top_k_stability(
        left: Sequence[str],
        right: Sequence[str],
        *,
        k: int,
    ) -> TopKStabilityComparison:
        """Return predeclared top-k overlap/Jaccard and endpoint equality."""

        accounting = _common_order_accounting(left, right)
        if accounting is None:
            unavailable = _not_assessable("ORDER.INVALID_ORDER")
            return top_k_stability_comparison_type(
                (),
                0,
                (),
                (),
                None,
                unavailable,
                unavailable,
                unavailable,
                unavailable,
            )
        left_common, right_common, common_ids, left_only, right_only = accounting
        if len_op(common_ids) < 2:
            unavailable = _not_assessable("ORDER.FEWER_THAN_TWO_COMMON_EVENTS")
            return top_k_stability_comparison_type(
                common_ids,
                len_op(common_ids),
                left_only,
                right_only,
                None,
                unavailable,
                unavailable,
                unavailable,
                unavailable,
            )
        if (
            isinstance_op(k, bool_type)
            or not isinstance_op(k, int_type)
            or not 1 <= k <= len_op(common_ids)
        ):
            unavailable = _not_assessable("ORDER.INVALID_TOP_K")
            return top_k_stability_comparison_type(
                common_ids,
                len_op(common_ids),
                left_only,
                right_only,
                None,
                unavailable,
                unavailable,
                unavailable,
                unavailable,
            )

        left_top = set_op(left_common[:k])
        right_top = set_op(right_common[:k])
        intersection_count = len_op(left_top & right_top)
        union_count = len_op(left_top | right_top)
        return top_k_stability_comparison_type(
            common_ids,
            len_op(common_ids),
            left_only,
            right_only,
            k,
            _bounded_unit(
                intersection_count / k,
                reason_code="ORDER.NUMERIC_BOUND_VIOLATION",
            ),
            _bounded_unit(
                intersection_count / union_count,
                reason_code="ORDER.NUMERIC_BOUND_VIOLATION",
            ),
            _assessable(left_common[0] == right_common[0]),
            _assessable(left_common[-1] == right_common[-1]),
        )

    def position_matrix(
        order_samples: Sequence[Sequence[str]], event_ids: Sequence[str]
    ) -> MatrixMetricResult:
        """Build an event-by-position probability matrix from valid order samples."""

        canonical_events = _valid_order(event_ids)
        if canonical_events is None:
            return _no_matrix("POSITION.INVALID_EVENT_SET")
        if not order_samples:
            return _no_matrix("POSITION.NO_ORDER_SAMPLES")
        event_set = set_op(canonical_events)
        counts = np_zeros((len_op(canonical_events), len_op(canonical_events)), dtype=np_float64)
        event_row = {event_id: index for index, event_id in enumerate_op(canonical_events)}
        for sample in order_samples:
            order = _valid_order(sample)
            if order is None or set_op(order) != event_set:
                return _no_matrix("POSITION.INVALID_ORDER_SAMPLE")
            for position, event_id in enumerate_op(order):
                counts[event_row[event_id], position] += 1.0
        counts /= float_type(len_op(order_samples))
        return _matrix(counts)

    def _valid_position_matrix(matrix: object) -> FloatArray | None:
        array = strict_float_array_op(matrix)
        if array is None:
            return None
        if (
            array.ndim != 2
            or array.shape[0] == 0
            or array.shape[0] != array.shape[1]
            or not np_all(np_isfinite(array))
            or np_any(array < 0.0)
            or np_any(array > 1.0)
            or not np_allclose(array.sum(axis=0), 1.0, atol=metric_absolute_tolerance, rtol=0.0)
            or not np_allclose(array.sum(axis=1), 1.0, atol=metric_absolute_tolerance, rtol=0.0)
        ):
            return None
        return array

    def position_matrix_distance(
        left: object,
        right: object,
        *,
        left_event_ids: Sequence[str],
        right_event_ids: Sequence[str],
    ) -> ScalarMetricResult:
        """Return mean row TV distance only for the exact same ordered event IDs."""

        left_ids = _valid_order(left_event_ids)
        right_ids = _valid_order(right_event_ids)
        if left_ids is None or right_ids is None:
            return _not_assessable("POSITION.INVALID_EVENT_SET")
        if left_ids != right_ids:
            return _not_assessable("POSITION.EVENT_IDENTITY_MISMATCH")
        left_matrix = _valid_position_matrix(left)
        right_matrix = _valid_position_matrix(right)
        if left_matrix is None or right_matrix is None:
            return _not_assessable("POSITION.INVALID_MATRIX")
        expected_shape = (len_op(left_ids), len_op(left_ids))
        if left_matrix.shape != expected_shape or right_matrix.shape != expected_shape:
            return _not_assessable("POSITION.EVENT_IDENTITY_MISMATCH")
        distance = np_mean(0.5 * np_sum(np_abs(left_matrix - right_matrix), axis=1))
        return _bounded_unit(distance, reason_code="POSITION.NUMERIC_BOUND_VIOLATION")

    def position_concentration(matrix: object) -> ScalarMetricResult:
        """Return one minus mean normalized event-position entropy."""

        probability = _valid_position_matrix(matrix)
        if probability is None:
            return _not_assessable("POSITION.INVALID_MATRIX")
        event_count = probability.shape[0]
        if event_count == 1:
            return _assessable(1.0, metadata_code="DEGENERATE_ONE_EVENT")
        positive = probability > 0.0
        entropy_terms = np_zeros_like(probability)
        entropy_terms[positive] = probability[positive] * np_log(probability[positive])
        normalized_entropies = -entropy_terms.sum(axis=1) / math_log(event_count)
        return _bounded_unit(
            1.0 - np_mean(normalized_entropies),
            reason_code="POSITION.NUMERIC_BOUND_VIOLATION",
        )

    def _position_quantile(probabilities: FloatArray, probability: float) -> int:
        supported_positions = np_flatnonzero(probabilities > 0.0)
        if probability == 0.0:
            return int_type(supported_positions[0])
        cumulative = np_cumsum(probabilities, dtype=np_float64)
        index = int_type(np_searchsorted(cumulative, probability, side="left"))
        if index == probabilities.size:
            # The matrix validator admits at most the frozen normalization
            # tolerance.  An accepted CDF can therefore finish microscopically
            # below p=1; the greatest position with positive empirical support
            # owns that round-off tail rather than a zero-probability cell.
            return int_type(supported_positions[-1])
        return index

    def position_event_summaries(
        matrix: object,
        *,
        event_ids: Sequence[str],
        quantile_probabilities: Sequence[float],
    ) -> PositionSummaryResult:
        """Return per-event expected, median, quantile, and entropy summaries."""

        canonical_events = _valid_order(event_ids)
        if canonical_events is None:
            return position_summary_result_type(
                "NOT_ASSESSABLE",
                None,
                "POSITION.INVALID_EVENT_SET",
            )
        probability = _valid_position_matrix(matrix)
        if probability is None:
            return position_summary_result_type(
                "NOT_ASSESSABLE",
                None,
                "POSITION.INVALID_MATRIX",
            )
        expected_shape = (len_op(canonical_events), len_op(canonical_events))
        if probability.shape != expected_shape:
            return position_summary_result_type(
                "NOT_ASSESSABLE",
                None,
                "POSITION.EVENT_IDENTITY_MISMATCH",
            )
        requested_quantiles = _finite_vector(quantile_probabilities)
        if (
            requested_quantiles is None
            or np_any(requested_quantiles < 0.0)
            or np_any(requested_quantiles > 1.0)
        ):
            return position_summary_result_type(
                "NOT_ASSESSABLE",
                None,
                "METRIC.INVALID_QUANTILE_PROBABILITY",
            )

        event_count = len_op(canonical_events)
        positions = np_arange(event_count, dtype=np_float64)
        summaries: list[EventPositionSummary] = []
        for event_id, row in zip_op(canonical_events, probability, strict=True):
            expectation = _finite_real_scalar(np_dot(positions, row))
            if expectation is None:
                return position_summary_result_type(
                    "NOT_ASSESSABLE",
                    None,
                    "POSITION.NUMERIC_OVERFLOW",
                )
            if event_count == 1:
                normalized_entropy = 0.0
                metadata_code: ScalarMetricMetadata | None = "DEGENERATE_ONE_EVENT"
            else:
                positive = row > 0.0
                entropy = -float_type(np_sum(row[positive] * np_log(row[positive])))
                bounded_entropy = _bounded_unit(
                    entropy / math_log(event_count),
                    reason_code="POSITION.NUMERIC_BOUND_VIOLATION",
                )
                if bounded_entropy.status != "ASSESSABLE":
                    return position_summary_result_type(
                        "NOT_ASSESSABLE",
                        None,
                        bounded_entropy.reason_code,
                    )
                assert isinstance_op(bounded_entropy.value, float_type)
                normalized_entropy = bounded_entropy.value
                metadata_code = None

            summaries.append(
                event_position_summary_type(
                    event_id=event_id,
                    probability_by_position=tuple_type(float_type(value) for value in row),
                    expected_position=expectation,
                    median_position=_position_quantile(row, 0.5),
                    quantiles=tuple_type(
                        position_quantile_type(
                            probability=float_type(requested_probability),
                            position=_position_quantile(row, float_type(requested_probability)),
                        )
                        for requested_probability in requested_quantiles
                    ),
                    normalized_entropy=normalized_entropy,
                    metadata_code=metadata_code,
                )
            )
        return position_summary_result_type("ASSESSABLE", tuple_type(summaries), None)

    def pairwise_precedence_matrix(
        order_samples: Sequence[Sequence[str]], event_ids: Sequence[str]
    ) -> MatrixMetricResult:
        """Build a pairwise-before probability matrix from valid order samples."""

        canonical_events = _valid_order(event_ids)
        if canonical_events is None:
            return _no_matrix("PAIRWISE.INVALID_EVENT_SET")
        if not order_samples:
            return _no_matrix("PAIRWISE.NO_ORDER_SAMPLES")
        event_set = set_op(canonical_events)
        event_count = len_op(canonical_events)
        counts = np_zeros((event_count, event_count), dtype=np_float64)
        for sample in order_samples:
            order = _valid_order(sample)
            if order is None or set_op(order) != event_set:
                return _no_matrix("PAIRWISE.INVALID_ORDER_SAMPLE")
            rank = {event_id: position for position, event_id in enumerate_op(order)}
            for left_index in range_op(event_count - 1):
                for right_index in range_op(left_index + 1, event_count):
                    if rank[canonical_events[left_index]] < rank[canonical_events[right_index]]:
                        counts[left_index, right_index] += 1.0
                    else:
                        counts[right_index, left_index] += 1.0
        counts /= float_type(len_op(order_samples))
        np_fill_diagonal(counts, 0.5)
        return _matrix(counts)

    def _valid_pairwise_matrix(matrix: object) -> FloatArray | None:
        array = strict_float_array_op(matrix)
        if array is None:
            return None
        if (
            array.ndim != 2
            or array.shape[0] < 2
            or array.shape[0] != array.shape[1]
            or not np_all(np_isfinite(array))
            or np_any(array < 0.0)
            or np_any(array > 1.0)
            or not np_allclose(np_diag(array), 0.5, atol=metric_absolute_tolerance, rtol=0.0)
            or not np_allclose(array + array.T, 1.0, atol=metric_absolute_tolerance, rtol=0.0)
        ):
            return None
        return array

    def pairwise_matrix_distance(
        left: object,
        right: object,
        *,
        left_event_ids: Sequence[str],
        right_event_ids: Sequence[str],
    ) -> ScalarMetricResult:
        """Return pair distance only for the exact same ordered event IDs."""

        left_ids = _valid_order(left_event_ids)
        right_ids = _valid_order(right_event_ids)
        if left_ids is None or right_ids is None:
            return _not_assessable("PAIRWISE.INVALID_EVENT_SET")
        if left_ids != right_ids:
            return _not_assessable("PAIRWISE.EVENT_IDENTITY_MISMATCH")
        left_matrix = _valid_pairwise_matrix(left)
        right_matrix = _valid_pairwise_matrix(right)
        if left_matrix is None or right_matrix is None:
            return _not_assessable("PAIRWISE.INVALID_MATRIX")
        expected_shape = (len_op(left_ids), len_op(left_ids))
        if left_matrix.shape != expected_shape or right_matrix.shape != expected_shape:
            return _not_assessable("PAIRWISE.EVENT_IDENTITY_MISMATCH")
        indexes = np_triu_indices(left_matrix.shape[0], k=1)
        distance = np_mean(np_abs(left_matrix[indexes] - right_matrix[indexes]))
        return _bounded_unit(distance, reason_code="PAIRWISE.NUMERIC_BOUND_VIOLATION")

    def pairwise_concentration(matrix: object) -> ScalarMetricResult:
        """Return mean strictness of pairwise-before probabilities."""

        probability = _valid_pairwise_matrix(matrix)
        if probability is None:
            return _not_assessable("PAIRWISE.INVALID_MATRIX")
        indexes = np_triu_indices(probability.shape[0], k=1)
        concentration = np_mean(2.0 * np_abs(probability[indexes] - 0.5))
        return _bounded_unit(concentration, reason_code="PAIRWISE.NUMERIC_BOUND_VIOLATION")

    def _strict_pairwise_relation(probability_a_before_b: float) -> PairwiseMajorityRelation:
        if probability_a_before_b > 0.5 + metric_absolute_tolerance:
            return "A_BEFORE_B"
        if probability_a_before_b < 0.5 - metric_absolute_tolerance:
            return "B_BEFORE_A"
        return "TIED"

    def strict_pairwise_majority_relations(
        matrix: object,
        *,
        event_ids: Sequence[str],
    ) -> PairwiseMajorityResult:
        """Classify every canonical event pair using the frozen strict tolerance."""

        canonical_events = _valid_order(event_ids)
        if canonical_events is None:
            return pairwise_majority_result_type(
                "NOT_ASSESSABLE",
                None,
                "PAIRWISE.INVALID_EVENT_SET",
            )
        if len_op(canonical_events) < 2:
            return pairwise_majority_result_type(
                "NOT_ASSESSABLE",
                None,
                "PAIRWISE.FEWER_THAN_TWO_COMMON_EVENTS",
            )
        probability = _valid_pairwise_matrix(matrix)
        if probability is None:
            return pairwise_majority_result_type(
                "NOT_ASSESSABLE",
                None,
                "PAIRWISE.INVALID_MATRIX",
            )
        expected_shape = (len_op(canonical_events), len_op(canonical_events))
        if probability.shape != expected_shape:
            return pairwise_majority_result_type(
                "NOT_ASSESSABLE",
                None,
                "PAIRWISE.EVENT_IDENTITY_MISMATCH",
            )

        event_index = {event_id: index for index, event_id in enumerate_op(canonical_events)}
        sorted_events = tuple_type(
            sorted_op(canonical_events, key=lambda event_id: event_id.encode("utf-8"))
        )
        relations: list[PairwiseMajority] = []
        for event_a_index in range_op(len_op(sorted_events) - 1):
            event_a_id = sorted_events[event_a_index]
            for event_b_id in sorted_events[event_a_index + 1 :]:
                value = float_type(probability[event_index[event_a_id], event_index[event_b_id]])
                relations.append(
                    pairwise_majority_type(
                        event_a_id=event_a_id,
                        event_b_id=event_b_id,
                        probability_a_before_b=value,
                        relation=_strict_pairwise_relation(value),
                    )
                )
        return pairwise_majority_result_type("ASSESSABLE", tuple_type(relations), None)

    def strict_pairwise_majority_flips(
        left: object,
        right: object,
        *,
        left_event_ids: Sequence[str],
        right_event_ids: Sequence[str],
    ) -> PairwiseMajorityComparison:
        """Return only opposing strict majorities; ties are retained as non-flips."""

        left_ids = _valid_order(left_event_ids)
        right_ids = _valid_order(right_event_ids)
        if left_ids is None or right_ids is None:
            unavailable = _not_assessable("PAIRWISE.INVALID_EVENT_SET")
            return pairwise_majority_comparison_type(
                (), 0, (), (), None, (), unavailable, unavailable
            )

        left_set = set_op(left_ids)
        right_set = set_op(right_ids)
        common_ids = tuple_type(
            sorted_op(left_set & right_set, key=lambda event_id: event_id.encode("utf-8"))
        )
        left_only = tuple_type(
            sorted_op(left_set - right_set, key=lambda event_id: event_id.encode("utf-8"))
        )
        right_only = tuple_type(
            sorted_op(right_set - left_set, key=lambda event_id: event_id.encode("utf-8"))
        )
        if len_op(common_ids) < 2:
            unavailable = _not_assessable("PAIRWISE.FEWER_THAN_TWO_COMMON_EVENTS")
            return pairwise_majority_comparison_type(
                common_ids,
                len_op(common_ids),
                left_only,
                right_only,
                None,
                (),
                unavailable,
                unavailable,
            )

        left_probability = _valid_pairwise_matrix(left)
        right_probability = _valid_pairwise_matrix(right)
        if left_probability is None or right_probability is None:
            unavailable = _not_assessable("PAIRWISE.INVALID_MATRIX")
            return pairwise_majority_comparison_type(
                common_ids,
                len_op(common_ids),
                left_only,
                right_only,
                None,
                (),
                unavailable,
                unavailable,
            )
        if left_probability.shape != (
            len_op(left_ids),
            len_op(left_ids),
        ) or right_probability.shape != (
            len_op(right_ids),
            len_op(right_ids),
        ):
            unavailable = _not_assessable("PAIRWISE.EVENT_IDENTITY_MISMATCH")
            return pairwise_majority_comparison_type(
                common_ids,
                len_op(common_ids),
                left_only,
                right_only,
                None,
                (),
                unavailable,
                unavailable,
            )

        left_index = {event_id: index for index, event_id in enumerate_op(left_ids)}
        right_index = {event_id: index for index, event_id in enumerate_op(right_ids)}
        flips: list[PairwiseMajorityFlip] = []
        for event_a_index in range_op(len_op(common_ids) - 1):
            event_a_id = common_ids[event_a_index]
            for event_b_id in common_ids[event_a_index + 1 :]:
                left_value = float_type(
                    left_probability[left_index[event_a_id], left_index[event_b_id]]
                )
                right_value = float_type(
                    right_probability[right_index[event_a_id], right_index[event_b_id]]
                )
                left_relation = _strict_pairwise_relation(left_value)
                right_relation = _strict_pairwise_relation(right_value)
                if (
                    left_relation == "TIED"
                    or right_relation == "TIED"
                    or left_relation == right_relation
                ):
                    continue
                flips.append(
                    pairwise_majority_flip_type(
                        event_a_id=event_a_id,
                        event_b_id=event_b_id,
                        left_probability_a_before_b=left_value,
                        right_probability_a_before_b=right_value,
                        left_relation=left_relation,
                        right_relation=right_relation,
                    )
                )

        denominator = math_comb(len_op(common_ids), 2)
        flip_count = len_op(flips)
        return pairwise_majority_comparison_type(
            common_ids,
            len_op(common_ids),
            left_only,
            right_only,
            denominator,
            tuple_type(flips),
            _assessable(flip_count),
            _bounded_unit(
                flip_count / denominator,
                reason_code="PAIRWISE.NUMERIC_BOUND_VIOLATION",
            ),
        )

    def _valid_stage_distribution(distribution: object) -> FloatArray | None:
        values = strict_float_array_op(distribution)
        if values is None:
            return None
        if (
            values.ndim != 1
            or values.size < 2
            or not np_all(np_isfinite(values))
            or np_any(values < 0.0)
            or np_any(values > 1.0)
            or not math_isclose(
                float_type(values.sum()),
                1.0,
                abs_tol=metric_absolute_tolerance,
                rel_tol=0.0,
            )
        ):
            return None
        return values

    def expected_stage(distribution: object) -> ScalarMetricResult:
        """Return the expected zero-based canonical stage."""

        values = _valid_stage_distribution(distribution)
        if values is None:
            return _not_assessable("STAGE.INVALID_POSTERIOR")
        stages = np_arange(values.size, dtype=np_float64)
        expectation = _finite_real_scalar(np_dot(stages, values))
        if expectation is None:
            return _not_assessable("STAGE.NUMERIC_OVERFLOW")
        return _assessable(expectation)

    def _valid_stage_identity(identity: object) -> tuple[object, ...] | None:
        if not isinstance_op(identity, stage_comparison_identity_type):
            return None
        event_ids = _valid_order(identity.event_ids)
        if event_ids is None:
            return None
        if (
            isinstance_op(identity.event_directions, str_type)
            or isinstance_op(identity.event_directions, bytes_type)
            or not isinstance_op(identity.event_directions, sequence_type)
        ):
            return None
        event_directions = tuple_type(identity.event_directions)
        if len_op(event_directions) != len_op(event_ids) or any_op(
            direction not in {"higher", "lower"} for direction in event_directions
        ):
            return None
        if (
            not isinstance_op(identity.stage_semantics_digest, str_type)
            or sha256_pattern.fullmatch(identity.stage_semantics_digest) is None
        ):
            return None
        if (
            not isinstance_op(identity.evaluation_cohort_digest, str_type)
            or sha256_pattern.fullmatch(identity.evaluation_cohort_digest) is None
        ):
            return None
        if (
            isinstance_op(identity.evaluation_row_index, bool_type)
            or not isinstance_op(identity.evaluation_row_index, int_type)
            or not 0 <= identity.evaluation_row_index <= safe_integer_max
        ):
            return None
        if (
            not isinstance_op(identity.evaluation_unit_binding, str_type)
            or private_unit_pattern.fullmatch(identity.evaluation_unit_binding) is None
        ):
            return None
        return (
            event_ids,
            event_directions,
            identity.stage_semantics_digest,
            identity.evaluation_cohort_digest,
            identity.evaluation_row_index,
            identity.evaluation_unit_binding,
        )

    def _validated_stage_pair(
        left: object,
        right: object,
        *,
        left_identity: StageComparisonIdentity,
        right_identity: StageComparisonIdentity,
    ) -> tuple[FloatArray | None, FloatArray | None, int | None, str | None]:
        left_comparison_identity = _valid_stage_identity(left_identity)
        right_comparison_identity = _valid_stage_identity(right_identity)
        if (
            left_comparison_identity is None
            or right_comparison_identity is None
            or left_comparison_identity != right_comparison_identity
        ):
            return None, None, None, "STAGE.SEMANTICS_MISMATCH"
        left_values = _valid_stage_distribution(left)
        right_values = _valid_stage_distribution(right)
        if left_values is None or right_values is None:
            return None, None, None, "STAGE.INVALID_POSTERIOR"
        event_ids = left_comparison_identity[0]
        assert isinstance_op(event_ids, tuple_type)
        expected_shape = (len_op(event_ids) + 1,)
        if left_values.shape != expected_shape or right_values.shape != expected_shape:
            return None, None, None, "STAGE.SEMANTICS_MISMATCH"
        return left_values, right_values, len_op(event_ids), None

    def normalized_stage_wasserstein(
        left: object,
        right: object,
        *,
        left_identity: StageComparisonIdentity,
        right_identity: StageComparisonIdentity,
    ) -> ScalarMetricResult:
        """Compare stages only when semantics and the exact evaluation unit match."""

        left_values, right_values, event_count, reason_code = _validated_stage_pair(
            left,
            right,
            left_identity=left_identity,
            right_identity=right_identity,
        )
        if reason_code is not None:
            return _not_assessable(reason_code)
        assert left_values is not None
        assert right_values is not None
        assert event_count is not None
        distance = np_sum(np_abs(np_cumsum(left_values)[:-1] - np_cumsum(right_values)[:-1]))
        return _bounded_unit(
            distance / event_count,
            reason_code="STAGE.NUMERIC_BOUND_VIOLATION",
        )

    def stage_expected_movement(
        left: object,
        right: object,
        *,
        left_identity: StageComparisonIdentity,
        right_identity: StageComparisonIdentity,
    ) -> StageExpectedMovement:
        """Return signed, absolute, and event-count-normalized expected movement."""

        left_values, right_values, event_count, reason_code = _validated_stage_pair(
            left,
            right,
            left_identity=left_identity,
            right_identity=right_identity,
        )
        if reason_code is not None:
            unavailable = _not_assessable(reason_code)
            return stage_expected_movement_type(
                unavailable,
                unavailable,
                unavailable,
                unavailable,
                unavailable,
            )
        assert left_values is not None
        assert right_values is not None
        assert event_count is not None
        stages = np_arange(event_count + 1, dtype=np_float64)
        left_expected = _finite_real_scalar(np_dot(stages, left_values))
        right_expected = _finite_real_scalar(np_dot(stages, right_values))
        if left_expected is None or right_expected is None:
            unavailable = _not_assessable("STAGE.NUMERIC_OVERFLOW")
            return stage_expected_movement_type(
                unavailable,
                unavailable,
                unavailable,
                unavailable,
                unavailable,
            )
        signed_change = _finite_real_scalar(right_expected - left_expected)
        if signed_change is None:
            return stage_expected_movement_type(
                _assessable(left_expected),
                _assessable(right_expected),
                _not_assessable("STAGE.NUMERIC_OVERFLOW"),
                _not_assessable("STAGE.NUMERIC_OVERFLOW"),
                _not_assessable("STAGE.NUMERIC_OVERFLOW"),
            )
        absolute_change = abs_op(signed_change)
        return stage_expected_movement_type(
            _assessable(left_expected),
            _assessable(right_expected),
            _assessable(signed_change),
            _assessable(absolute_change),
            _bounded_unit(
                absolute_change / event_count,
                reason_code="STAGE.NUMERIC_BOUND_VIOLATION",
            ),
        )

    def _map_tied_stages(values: FloatArray) -> tuple[int, ...]:
        maximum = float_type(np_max(values))
        return tuple_type(
            int_type(stage)
            for stage in np_flatnonzero(np_abs(values - maximum) <= metric_absolute_tolerance)
        )

    def _map_agreement_from_values(left: FloatArray, right: FloatArray) -> StageMapAgreement:
        left_tied = _map_tied_stages(left)
        right_tied = _map_tied_stages(right)
        left_map = left_tied[0]
        right_map = right_tied[0]
        return stage_map_agreement_type(
            status="ASSESSABLE",
            left_map_stage=left_map,
            right_map_stage=right_map,
            left_tied_stages=left_tied,
            right_tied_stages=right_tied,
            left_has_tie=len_op(left_tied) > 1,
            right_has_tie=len_op(right_tied) > 1,
            agreement=left_map == right_map,
            reason_code=None,
        )

    def stage_map_agreement(
        left: object,
        right: object,
        *,
        left_identity: StageComparisonIdentity,
        right_identity: StageComparisonIdentity,
    ) -> StageMapAgreement:
        """Return smallest-tied-stage MAP equality and complete tied-stage sets."""

        left_values, right_values, _, reason_code = _validated_stage_pair(
            left,
            right,
            left_identity=left_identity,
            right_identity=right_identity,
        )
        if reason_code is not None:
            return stage_map_agreement_type(
                status="NOT_ASSESSABLE",
                left_map_stage=None,
                right_map_stage=None,
                left_tied_stages=(),
                right_tied_stages=(),
                left_has_tie=None,
                right_has_tie=None,
                agreement=None,
                reason_code=reason_code,
            )
        assert left_values is not None
        assert right_values is not None
        return _map_agreement_from_values(left_values, right_values)

    def normalized_stage_jensen_shannon_distance(
        left: object,
        right: object,
        *,
        left_identity: StageComparisonIdentity,
        right_identity: StageComparisonIdentity,
    ) -> ScalarMetricResult:
        """Return the optional normalized Jensen-Shannon distance complement."""

        left_values, right_values, _, reason_code = _validated_stage_pair(
            left,
            right,
            left_identity=left_identity,
            right_identity=right_identity,
        )
        if reason_code is not None:
            return _not_assessable(reason_code)
        assert left_values is not None
        assert right_values is not None
        midpoint = (left_values + right_values) / 2.0
        left_positive = left_values > 0.0
        right_positive = right_values > 0.0
        divergence = 0.5 * float_type(
            np_sum(
                left_values[left_positive]
                * np_log(left_values[left_positive] / midpoint[left_positive])
            )
            + np_sum(
                right_values[right_positive]
                * np_log(right_values[right_positive] / midpoint[right_positive])
            )
        )
        if not math_isfinite(divergence) or divergence < -metric_absolute_tolerance:
            return _not_assessable("STAGE.NUMERIC_BOUND_VIOLATION")
        distance = math_sqrt(max_op(0.0, divergence) / math_log(2.0))
        return _bounded_unit(
            distance,
            reason_code="STAGE.NUMERIC_BOUND_VIOLATION",
        )

    def _valid_stage_identity_sequence(
        identities: object,
    ) -> tuple[tuple[object, ...], ...] | None:
        if (
            isinstance_op(identities, str_type)
            or isinstance_op(identities, bytes_type)
            or not isinstance_op(identities, sequence_type)
        ):
            return None
        normalized = tuple_type(_valid_stage_identity(identity) for identity in identities)
        if not normalized or any_op(identity is None for identity in normalized):
            return None
        checked = tuple_type(identity for identity in normalized if identity is not None)
        cohort_semantics = checked[0][:4]
        if any_op(identity[:4] != cohort_semantics for identity in checked[1:]):
            return None
        row_indexes = tuple_type(identity[4] for identity in checked)
        unit_bindings = tuple_type(identity[5] for identity in checked)
        if len_op(set_op(row_indexes)) != len_op(row_indexes) or len_op(
            set_op(unit_bindings)
        ) != len_op(unit_bindings):
            return None
        return checked

    def _valid_stage_posterior_matrix(posteriors: object) -> FloatArray | None:
        matrix = strict_float_array_op(posteriors)
        if matrix is None or matrix.ndim != 2 or matrix.shape[0] == 0 or matrix.shape[1] < 2:
            return None
        if any_op(_valid_stage_distribution(row) is None for row in matrix):
            return None
        return matrix

    def _validated_stage_cohort_pair(
        left: object,
        right: object,
        *,
        left_identities: Sequence[StageComparisonIdentity],
        right_identities: Sequence[StageComparisonIdentity],
    ) -> tuple[FloatArray | None, FloatArray | None, int | None, str | None]:
        left_identity_values = _valid_stage_identity_sequence(left_identities)
        right_identity_values = _valid_stage_identity_sequence(right_identities)
        if (
            left_identity_values is None
            or right_identity_values is None
            or left_identity_values != right_identity_values
        ):
            return None, None, None, "STAGE.SEMANTICS_MISMATCH"
        event_ids = left_identity_values[0][0]
        assert isinstance_op(event_ids, tuple_type)
        left_values = _valid_stage_posterior_matrix(left)
        right_values = _valid_stage_posterior_matrix(right)
        if left_values is None or right_values is None:
            return None, None, None, "STAGE.INVALID_POSTERIOR_MATRIX"
        expected_shape = (len_op(left_identity_values), len_op(event_ids) + 1)
        if left_values.shape != expected_shape or right_values.shape != expected_shape:
            return None, None, None, "STAGE.SEMANTICS_MISMATCH"
        return left_values, right_values, len_op(event_ids), None

    def cohort_stage_map_agreement(
        left: object,
        right: object,
        *,
        left_identities: Sequence[StageComparisonIdentity],
        right_identities: Sequence[StageComparisonIdentity],
    ) -> CohortStageMapAgreement:
        """Return mean MAP equality while retaining every participant's ties."""

        left_values, right_values, _, reason_code = _validated_stage_cohort_pair(
            left,
            right,
            left_identities=left_identities,
            right_identities=right_identities,
        )
        if reason_code is not None:
            return cohort_stage_map_agreement_type("NOT_ASSESSABLE", None, None, reason_code)
        assert left_values is not None
        assert right_values is not None
        participant_results = tuple_type(
            _map_agreement_from_values(left_row, right_row)
            for left_row, right_row in zip_op(left_values, right_values, strict=True)
        )
        agreement = sum_op(result.agreement is True for result in participant_results) / len_op(
            participant_results
        )
        bounded = _bounded_unit(
            agreement,
            reason_code="STAGE.NUMERIC_BOUND_VIOLATION",
        )
        if bounded.status != "ASSESSABLE":
            return cohort_stage_map_agreement_type(
                "NOT_ASSESSABLE", None, None, bounded.reason_code
            )
        assert isinstance_op(bounded.value, float_type)
        return cohort_stage_map_agreement_type(
            "ASSESSABLE", bounded.value, participant_results, None
        )

    def cohort_normalized_stage_wasserstein(
        left: object,
        right: object,
        *,
        left_identities: Sequence[StageComparisonIdentity],
        right_identities: Sequence[StageComparisonIdentity],
    ) -> ScalarMetricResult:
        """Compare mean fixed-cohort posteriors with normalized ordinal Wasserstein."""

        left_values, right_values, event_count, reason_code = _validated_stage_cohort_pair(
            left,
            right,
            left_identities=left_identities,
            right_identities=right_identities,
        )
        if reason_code is not None:
            return _not_assessable(reason_code)
        assert left_values is not None
        assert right_values is not None
        assert event_count is not None
        left_cohort = np_mean(left_values, axis=0, dtype=np_float64)
        right_cohort = np_mean(right_values, axis=0, dtype=np_float64)
        distance = np_sum(np_abs(np_cumsum(left_cohort)[:-1] - np_cumsum(right_cohort)[:-1]))
        return _bounded_unit(
            distance / event_count,
            reason_code="STAGE.NUMERIC_BOUND_VIOLATION",
        )

    def normalized_known_truth_stage_mae(
        posteriors: object,
        truth_stages: object,
        *,
        fitted_identities: Sequence[StageComparisonIdentity],
        truth_identities: Sequence[StageComparisonIdentity],
    ) -> ScalarMetricResult:
        """Return normalized expected-stage MAE for compatible synthetic truth."""

        fitted_identity_values = _valid_stage_identity_sequence(fitted_identities)
        truth_identity_values = _valid_stage_identity_sequence(truth_identities)
        if (
            fitted_identity_values is None
            or truth_identity_values is None
            or fitted_identity_values != truth_identity_values
        ):
            return _not_assessable("STAGE.SEMANTICS_MISMATCH")
        event_ids = fitted_identity_values[0][0]
        assert isinstance_op(event_ids, tuple_type)
        posterior_values = _valid_stage_posterior_matrix(posteriors)
        if posterior_values is None:
            return _not_assessable("STAGE.INVALID_POSTERIOR_MATRIX")
        expected_shape = (len_op(fitted_identity_values), len_op(event_ids) + 1)
        if posterior_values.shape != expected_shape:
            return _not_assessable("STAGE.SEMANTICS_MISMATCH")
        truth_values = strict_integer_array_op(truth_stages)
        if (
            truth_values is None
            or truth_values.ndim != 1
            or truth_values.shape[0] != posterior_values.shape[0]
            or np_any(truth_values < 0)
            or np_any(truth_values > len_op(event_ids))
        ):
            return _not_assessable("STAGE.INVALID_TRUTH_STAGES")
        stages = np_arange(len_op(event_ids) + 1, dtype=np_float64)
        expectations = posterior_values @ stages
        score = np_mean(np_abs(expectations - truth_values.astype(np_float64))) / len_op(event_ids)
        return _bounded_unit(
            score,
            reason_code="STAGE.NUMERIC_BOUND_VIOLATION",
        )

    def cohort_stage_distribution(
        posteriors: object,
    ) -> MatrixMetricResult:
        """Return a one-row matrix containing the mean participant posterior."""

        matrix = strict_float_array_op(posteriors)
        if matrix is None:
            return _no_matrix("STAGE.INVALID_POSTERIOR_MATRIX")
        if matrix.ndim != 2 or matrix.shape[0] == 0 or matrix.shape[1] < 2:
            return _no_matrix("STAGE.INVALID_POSTERIOR_MATRIX")
        if any_op(_valid_stage_distribution(row) is None for row in matrix):
            return _no_matrix("STAGE.INVALID_POSTERIOR_MATRIX")
        cohort = np_asarray(
            np_mean(matrix, axis=0, keepdims=True, dtype=np_float64), dtype=np_float64
        )
        return _matrix(cohort)

    def empirical_null_comparison(
        observed: float, null_values: Sequence[float]
    ) -> tuple[ScalarMetricResult, ScalarMetricResult]:
        """Return plus-one empirical p-value and observed-minus-null-median effect."""

        values = _finite_vector(null_values)
        observed_value = _finite_real_scalar(observed)
        if observed_value is None or values is None:
            unavailable = _not_assessable("NULL.NONFINITE_STATISTIC")
            return unavailable, unavailable
        if values.size == 0:
            unavailable = _not_assessable("NULL.NO_REPLICATES")
            return unavailable, unavailable
        exceedances = int_type(np_count_nonzero(values >= observed_value))
        empirical_p = (1.0 + exceedances) / (values.size + 1.0)
        median = empirical_quantile(values.tolist(), 0.5)
        assert isinstance_op(median.value, float_type)
        p_result = _bounded_unit(empirical_p, reason_code="NULL.NUMERIC_BOUND_VIOLATION")
        effect = observed_value - median.value
        if not math_isfinite(effect):
            return p_result, _not_assessable("NULL.EFFECT_OVERFLOW")
        return p_result, _assessable(effect)

    def _average_ranks(values: FloatArray) -> FloatArray:
        order = np_argsort(values, kind="stable")
        ranks: FloatArray = np_empty(values.size, dtype=np_float64)
        start = 0
        while start < values.size:
            end = start + 1
            while end < values.size and values[order[end]] == values[order[start]]:
                end += 1
            average_one_based_rank = ((start + 1) + end) / 2.0
            ranks[order[start:end]] = average_one_based_rank
            start = end
        return ranks

    def spearman_rank_correlation(
        left: Sequence[float], right: Sequence[float]
    ) -> ScalarMetricResult:
        """Return Pearson correlation of average-rank vectors."""

        left_values = _finite_vector(left)
        right_values = _finite_vector(right)
        if left_values is None or right_values is None:
            return _not_assessable("CORRELATION.NONFINITE_OR_INVALID_VALUES")
        if left_values.size != right_values.size or left_values.size < 2:
            return _not_assessable("CORRELATION.INSUFFICIENT_PAIRS")
        left_ranks = _average_ranks(left_values)
        right_ranks = _average_ranks(right_values)
        left_centered = left_ranks - np_mean(left_ranks)
        right_centered = right_ranks - np_mean(right_ranks)
        denominator = math_sqrt(
            float_type(
                np_dot(left_centered, left_centered) * np_dot(right_centered, right_centered)
            )
        )
        if denominator == 0.0:
            return _not_assessable("CORRELATION.CONSTANT_RANK_VECTOR")
        correlation = np_dot(left_centered, right_centered) / denominator
        return _bounded_signed_unit(
            correlation,
            reason_code="CORRELATION.NUMERIC_BOUND_VIOLATION",
        )

    return _MetricKernel(
        _assessable=_assessable,
        _not_assessable=_not_assessable,
        _matrix=_matrix,
        _no_matrix=_no_matrix,
        _finite_vector=_finite_vector,
        _finite_real_scalar=_finite_real_scalar,
        _bounded_unit=_bounded_unit,
        _bounded_signed_unit=_bounded_signed_unit,
        _valid_order=_valid_order,
        _same_event_order_inputs=_same_event_order_inputs,
        empirical_quantile=empirical_quantile,
        normalized_kendall_distance=normalized_kendall_distance,
        normalized_spearman_footrule_distance=normalized_spearman_footrule_distance,
        strict_order_comparison=strict_order_comparison,
        _common_order_accounting=_common_order_accounting,
        per_event_rank_shifts=per_event_rank_shifts,
        top_k_stability=top_k_stability,
        position_matrix=position_matrix,
        _valid_position_matrix=_valid_position_matrix,
        position_matrix_distance=position_matrix_distance,
        position_concentration=position_concentration,
        _position_quantile=_position_quantile,
        position_event_summaries=position_event_summaries,
        pairwise_precedence_matrix=pairwise_precedence_matrix,
        _valid_pairwise_matrix=_valid_pairwise_matrix,
        pairwise_matrix_distance=pairwise_matrix_distance,
        pairwise_concentration=pairwise_concentration,
        _strict_pairwise_relation=_strict_pairwise_relation,
        strict_pairwise_majority_relations=strict_pairwise_majority_relations,
        strict_pairwise_majority_flips=strict_pairwise_majority_flips,
        _valid_stage_distribution=_valid_stage_distribution,
        expected_stage=expected_stage,
        _valid_stage_identity=_valid_stage_identity,
        _validated_stage_pair=_validated_stage_pair,
        normalized_stage_wasserstein=normalized_stage_wasserstein,
        stage_expected_movement=stage_expected_movement,
        _map_tied_stages=_map_tied_stages,
        _map_agreement_from_values=_map_agreement_from_values,
        stage_map_agreement=stage_map_agreement,
        normalized_stage_jensen_shannon_distance=normalized_stage_jensen_shannon_distance,
        _valid_stage_identity_sequence=_valid_stage_identity_sequence,
        _valid_stage_posterior_matrix=_valid_stage_posterior_matrix,
        _validated_stage_cohort_pair=_validated_stage_cohort_pair,
        cohort_stage_map_agreement=cohort_stage_map_agreement,
        cohort_normalized_stage_wasserstein=cohort_normalized_stage_wasserstein,
        normalized_known_truth_stage_mae=normalized_known_truth_stage_mae,
        cohort_stage_distribution=cohort_stage_distribution,
        empirical_null_comparison=empirical_null_comparison,
        _average_ranks=_average_ranks,
        spearman_rank_correlation=spearman_rank_correlation,
    )


_METRIC_KERNEL = _build_metric_kernel(
    abs_op=abs,
    any_op=any,
    bool_type=bool,
    bytes_type=bytes,
    enumerate_op=enumerate,
    float_type=float,
    int_type=int,
    isinstance_op=_ISINSTANCE_OP,
    len_op=len,
    max_op=max,
    min_op=min,
    range_op=range,
    set_op=set,
    sorted_op=sorted,
    str_type=str,
    sum_op=sum,
    tuple_type=tuple,
    zip_op=zip,
    strict_float_array_op=_NUMERIC_KERNEL.strict_float_array,
    strict_integer_array_op=_NUMERIC_KERNEL.strict_integer_array,
    sequence_type=Sequence,
    scalar_metric_result_type=ScalarMetricResult,
    matrix_metric_result_type=MatrixMetricResult,
    stage_comparison_identity_type=StageComparisonIdentity,
    order_comparison_type=OrderComparison,
    event_rank_shift_type=EventRankShift,
    rank_shift_comparison_type=RankShiftComparison,
    top_k_stability_comparison_type=TopKStabilityComparison,
    position_quantile_type=PositionQuantile,
    event_position_summary_type=EventPositionSummary,
    position_summary_result_type=PositionSummaryResult,
    pairwise_majority_type=PairwiseMajority,
    pairwise_majority_result_type=PairwiseMajorityResult,
    pairwise_majority_flip_type=PairwiseMajorityFlip,
    pairwise_majority_comparison_type=PairwiseMajorityComparison,
    stage_expected_movement_type=StageExpectedMovement,
    stage_map_agreement_type=StageMapAgreement,
    cohort_stage_map_agreement_type=CohortStageMapAgreement,
    metric_absolute_tolerance=METRIC_ABSOLUTE_TOLERANCE,
    safe_integer_max=_SAFE_INTEGER_MAX,
    sha256_pattern=_SHA256_PATTERN,
    private_unit_pattern=_PRIVATE_UNIT_PATTERN,
    machine_id_pattern=_MACHINE_ID_PATTERN,
    np_abs=np.abs,
    np_all=np.all,
    np_allclose=np.allclose,
    np_any=np.any,
    np_arange=np.arange,
    np_argsort=np.argsort,
    np_asarray=np.asarray,
    np_count_nonzero=np.count_nonzero,
    np_cumsum=np.cumsum,
    np_diag=np.diag,
    np_dot=np.dot,
    np_empty=np.empty,
    np_fill_diagonal=np.fill_diagonal,
    np_flatnonzero=np.flatnonzero,
    np_float64=np.float64,
    np_isfinite=np.isfinite,
    np_log=np.log,
    np_max=np.max,
    np_mean=np.mean,
    np_searchsorted=np.searchsorted,
    np_sort=np.sort,
    np_sum=np.sum,
    np_triu_indices=np.triu_indices,
    np_zeros=np.zeros,
    np_zeros_like=np.zeros_like,
    math_ceil=math.ceil,
    math_comb=math.comb,
    math_floor=math.floor,
    math_isclose=math.isclose,
    math_isfinite=math.isfinite,
    math_log=math.log,
    math_sqrt=math.sqrt,
)

for _operation_name in _MetricKernel.__dataclass_fields__:
    _operation = getattr(_METRIC_KERNEL, _operation_name)
    _operation.__name__ = _operation_name
    _operation.__qualname__ = _operation_name
    _operation.__module__ = __name__

strict_float_array = _NUMERIC_KERNEL.strict_float_array
strict_integer_array = _NUMERIC_KERNEL.strict_integer_array
_assessable = _METRIC_KERNEL._assessable
_not_assessable = _METRIC_KERNEL._not_assessable
_matrix = _METRIC_KERNEL._matrix
_no_matrix = _METRIC_KERNEL._no_matrix
_finite_vector = _METRIC_KERNEL._finite_vector
_finite_real_scalar = _METRIC_KERNEL._finite_real_scalar
_bounded_unit = _METRIC_KERNEL._bounded_unit
_bounded_signed_unit = _METRIC_KERNEL._bounded_signed_unit
_valid_order = _METRIC_KERNEL._valid_order
_same_event_order_inputs = _METRIC_KERNEL._same_event_order_inputs
empirical_quantile = _METRIC_KERNEL.empirical_quantile
normalized_kendall_distance = _METRIC_KERNEL.normalized_kendall_distance
normalized_spearman_footrule_distance = _METRIC_KERNEL.normalized_spearman_footrule_distance
strict_order_comparison = _METRIC_KERNEL.strict_order_comparison
_common_order_accounting = _METRIC_KERNEL._common_order_accounting
per_event_rank_shifts = _METRIC_KERNEL.per_event_rank_shifts
top_k_stability = _METRIC_KERNEL.top_k_stability
position_matrix = _METRIC_KERNEL.position_matrix
_valid_position_matrix = _METRIC_KERNEL._valid_position_matrix
position_matrix_distance = _METRIC_KERNEL.position_matrix_distance
position_concentration = _METRIC_KERNEL.position_concentration
_position_quantile = _METRIC_KERNEL._position_quantile
position_event_summaries = _METRIC_KERNEL.position_event_summaries
pairwise_precedence_matrix = _METRIC_KERNEL.pairwise_precedence_matrix
_valid_pairwise_matrix = _METRIC_KERNEL._valid_pairwise_matrix
pairwise_matrix_distance = _METRIC_KERNEL.pairwise_matrix_distance
pairwise_concentration = _METRIC_KERNEL.pairwise_concentration
_strict_pairwise_relation = _METRIC_KERNEL._strict_pairwise_relation
strict_pairwise_majority_relations = _METRIC_KERNEL.strict_pairwise_majority_relations
strict_pairwise_majority_flips = _METRIC_KERNEL.strict_pairwise_majority_flips
_valid_stage_distribution = _METRIC_KERNEL._valid_stage_distribution
expected_stage = _METRIC_KERNEL.expected_stage
_valid_stage_identity = _METRIC_KERNEL._valid_stage_identity
_validated_stage_pair = _METRIC_KERNEL._validated_stage_pair
normalized_stage_wasserstein = _METRIC_KERNEL.normalized_stage_wasserstein
stage_expected_movement = _METRIC_KERNEL.stage_expected_movement
_map_tied_stages = _METRIC_KERNEL._map_tied_stages
_map_agreement_from_values = _METRIC_KERNEL._map_agreement_from_values
stage_map_agreement = _METRIC_KERNEL.stage_map_agreement
normalized_stage_jensen_shannon_distance = _METRIC_KERNEL.normalized_stage_jensen_shannon_distance
_valid_stage_identity_sequence = _METRIC_KERNEL._valid_stage_identity_sequence
_valid_stage_posterior_matrix = _METRIC_KERNEL._valid_stage_posterior_matrix
_validated_stage_cohort_pair = _METRIC_KERNEL._validated_stage_cohort_pair
cohort_stage_map_agreement = _METRIC_KERNEL.cohort_stage_map_agreement
cohort_normalized_stage_wasserstein = _METRIC_KERNEL.cohort_normalized_stage_wasserstein
normalized_known_truth_stage_mae = _METRIC_KERNEL.normalized_known_truth_stage_mae
cohort_stage_distribution = _METRIC_KERNEL.cohort_stage_distribution
empirical_null_comparison = _METRIC_KERNEL.empirical_null_comparison
_average_ranks = _METRIC_KERNEL._average_ranks
spearman_rank_correlation = _METRIC_KERNEL.spearman_rank_correlation
