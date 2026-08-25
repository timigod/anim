"""Core-owned convergence derivation from raw per-chain scientific arrays.

The public worker boundary does not own convergence classification.  This
module admits the raw arrays required by the proposed v0.1 rule, recomputes all
diagnostics, and emits the canonical ``ConvergenceRecord`` shape.  It never
accepts a worker-supplied assessment or diagnostic summary.
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
from .core import (
    _METRIC_KERNEL,
    METRIC_ABSOLUTE_TOLERANCE,
    ScalarMetricResult,
    _build_frozen_dataclass_methods,
)

ConvergenceAssessment = Literal[
    "CONVERGENCE_PASS",
    "CONVERGENCE_WARN",
    "CONVERGENCE_FAIL",
    "CONVERGENCE_NOT_ASSESSABLE",
]
type ConvergenceRecord = dict[str, object]
type _ArtifactStatus = Literal["VALID", "MISSING", "INVALID"]
type _ConvergenceRuleValues = tuple[
    str,
    str,
    str,
    int,
    int,
    float,
    float,
    float,
    float,
    float,
    float,
    bool,
    bool,
    str,
]

_SHA256_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MACHINE_ID_PATTERN: Final = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z", flags=re.ASCII)
_INTEGRITY_MESSAGE: Final = "Convergence inputs failed integrity validation."
_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
_LIKELIHOOD_ZERO_SCALE: Final = 1e-12
_LIKELIHOOD_EQUALITY_TOLERANCE: Final = 1e-12


@dataclass(frozen=True, slots=True)
class ConvergenceRule:
    """The one core-owned per-run convergence rule.

    The rule is frozen after unmodified-backend characterization.
    It is deliberately not a caller argument: callers cannot select thresholds
    or relabel the resulting assessment.
    """

    rule_schema_version: str
    rule_id: str
    rule_status: str
    assessable_min_independent_chains: int
    assessable_min_unthinned_postburn_states_per_chain: int
    pass_transition_rate_exclusive_min: float
    pass_median_position_distance_max: float
    pass_max_position_distance_max: float
    pass_median_precedence_distance_max: float
    fail_combined_max_position_distance_over: float
    fail_combined_max_kendall_distance_over: float
    fail_invalid_or_nonfinite_samples: bool
    fail_stuck_chains_in_distinct_states: bool
    likelihood_drift_role: str


_CONVERGENCE_RULE_VALUES: Final[_ConvergenceRuleValues] = (
    "ebm-audit-convergence-rule/1.0",
    "per-run-convergence-proposal-v0.1",
    "FROZEN_AFTER_UNMODIFIED_BACKEND_CHARACTERIZATION",
    3,
    500,
    0.0,
    0.10,
    0.20,
    0.10,
    0.35,
    0.50,
    True,
    True,
    "DESCRIPTIVE_ONLY_NO_CLASSIFICATION_EFFECT",
)
CONVERGENCE_RULE: Final = ConvergenceRule(*_CONVERGENCE_RULE_VALUES)


class ConvergenceIntegrityError(ValueError):
    """A privacy-safe failure to admit one convergence input set."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(_INTEGRITY_MESSAGE)


@dataclass(frozen=True, slots=True)
class ConvergenceChainInput:
    """Raw core inputs for one chain in frozen chain-plan order.

    The caller supplies the complete unthinned post-burn arrays plus the sealed
    thinning interval and state counts, never a retained order chain or central
    order.
    """

    chain_execution_id: str = field(repr=False)
    event_ids: tuple[str, ...] = field(repr=False)
    thinning_interval: object = field(repr=False)
    postburn_unthinned_state_count: object = field(repr=False)
    retained_state_count: object = field(repr=False)
    postburn_order_state_chain: object = field(repr=False)
    position_probabilities: object = field(repr=False)
    pairwise_precedence: object = field(repr=False)
    postburn_likelihood_trace: object | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class StateChainDiagnostics:
    """Diagnostics derived from one unthinned post-burn permutation chain."""

    state_count: int
    transition_count: int
    transition_rate: ScalarMetricResult
    unique_state_count: int
    unique_state_fraction: ScalarMetricResult
    repeated_state_run_lengths: tuple[int, ...]
    max_repeated_state_fraction: ScalarMetricResult


@dataclass(frozen=True, slots=True)
class _AdmittedChain:
    chain_execution_id: str
    event_ids: tuple[str, ...]
    thinning_interval: int
    order_state_status: _ArtifactStatus
    unthinned_order_states: NDArray[np.int64] | None
    retained_order_states: NDArray[np.int64] | None
    central_order: NDArray[np.int64] | None
    position_status: _ArtifactStatus
    position_probabilities: NDArray[np.float64] | None
    precedence_status: _ArtifactStatus
    pairwise_precedence: NDArray[np.float64] | None
    unthinned_likelihood_trace: NDArray[np.float64] | None
    diagnostics: StateChainDiagnostics | None


@dataclass(frozen=True, slots=True)
class _ConvergenceClassHooks:
    convergence_integrity_error_init: Callable[[ConvergenceIntegrityError, str], None]


def _build_convergence_class_hooks(
    *,
    integrity_message: str,
    value_error_init: Callable[[ValueError, object], None],
) -> _ConvergenceClassHooks:
    def convergence_integrity_error_init(self: ConvergenceIntegrityError, code: str) -> None:
        self.code = code
        value_error_init(self, integrity_message)

    return _ConvergenceClassHooks(convergence_integrity_error_init=convergence_integrity_error_init)


_CONVERGENCE_CLASS_HOOKS = _build_convergence_class_hooks(
    integrity_message=_INTEGRITY_MESSAGE,
    value_error_init=ValueError.__init__,
)
_convergence_integrity_error_init = _CONVERGENCE_CLASS_HOOKS.convergence_integrity_error_init
_convergence_integrity_error_init.__name__ = "__init__"
_convergence_integrity_error_init.__qualname__ = "ConvergenceIntegrityError.__init__"
_convergence_integrity_error_init.__module__ = __name__
setattr(  # noqa: B010
    ConvergenceIntegrityError,
    "__init__",
    _convergence_integrity_error_init,
)

_FROZEN_CONVERGENCE_CLASSES = (
    ConvergenceRule,
    ConvergenceChainInput,
    StateChainDiagnostics,
    _AdmittedChain,
)
for _class_type in _FROZEN_CONVERGENCE_CLASSES:
    _frozen_methods = _build_frozen_dataclass_methods(
        class_type=_class_type,
        field_names=tuple(_class_type.__dataclass_fields__),
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
        _method.__qualname__ = f"{_class_type.__qualname__}.{_method_name}"
        _method.__module__ = __name__
        setattr(_class_type, _method_name, _method)


@dataclass(frozen=True, slots=True)
class _ConvergenceKernel:
    """Exact import-time convergence operations shared by science derivation."""

    _integrity: Callable[..., ConvergenceIntegrityError]
    _assessable: Callable[..., ScalarMetricResult]
    _not_assessable: Callable[..., ScalarMetricResult]
    _source_array: Callable[..., NDArray[np.generic] | None]
    _permutation_chain: Callable[..., NDArray[np.integer] | None]
    state_chain_diagnostics: Callable[..., StateChainDiagnostics | None]
    likelihood_split_half_drift: Callable[..., ScalarMetricResult]
    _event_ids: Callable[..., tuple[str, ...] | None]
    _chain_identity: Callable[..., tuple[str, tuple[str, ...]]]
    _positive_safe_integer: Callable[..., int]
    _sampling_accounting: Callable[..., tuple[int, int, int]]
    _snapshot_int64: Callable[..., NDArray[np.int64]]
    _snapshot_float64: Callable[..., NDArray[np.float64]]
    _retain_order_states: Callable[..., NDArray[np.int64]]
    _admit_order_states: Callable[..., tuple[_ArtifactStatus, NDArray[np.int64] | None]]
    _admit_position_matrix: Callable[..., tuple[_ArtifactStatus, NDArray[np.float64] | None]]
    _admit_precedence_matrix: Callable[..., tuple[_ArtifactStatus, NDArray[np.float64] | None]]
    _admit_likelihood_trace: Callable[..., NDArray[np.float64] | None]
    _derive_central_order: Callable[..., NDArray[np.int64]]
    _admit_chain: Callable[..., _AdmittedChain]
    _chain_metric: Callable[..., dict[str, object]]
    _sampling_accounting_row: Callable[..., dict[str, object]]
    _chain_metric_result: Callable[..., dict[str, object]]
    _endpoint_event_ids: Callable[..., tuple[str, ...]]
    _distinct_zero_transition_endpoints: Callable[..., int]
    _metric_value: Callable[..., float]
    _optional_metric_value: Callable[..., float | None]
    _pairwise_summary: Callable[..., dict[str, object]]
    _classify: Callable[..., tuple[ConvergenceAssessment, list[str]]]
    _summary_distance: Callable[..., float]
    is_canonical_non_sampling_convergence_record: Callable[[object], bool]
    derive_convergence_record: Callable[..., ConvergenceRecord]


def _build_convergence_kernel(
    *,
    abs_op: Callable[..., Any],
    all_op: Callable[..., Any],
    any_op: Callable[..., Any],
    assertion_error_type: type[AssertionError],
    bool_type: type[bool],
    bytes_type: type[bytes],
    dict_type: type[dict[Any, Any]],
    enumerate_op: Callable[..., Any],
    exception_type: type[Exception],
    float_type: type[float],
    frozenset_op: Callable[..., frozenset[Any]],
    int_type: type[int],
    isinstance_op: _IsInstanceOp,
    len_op: Callable[..., int],
    list_type: type[list[Any]],
    max_op: Callable[..., Any],
    min_op: Callable[..., Any],
    set_op: Callable[..., Any],
    str_type: type[str],
    tuple_type: type[tuple[Any, ...]],
    type_op: Callable[[object], type[Any]],
    zip_op: Callable[..., Any],
    strict_float_array_op: Callable[[object], NDArray[np.float64] | None],
    strict_integer_array_op: Callable[[object], NDArray[np.integer] | None],
    empirical_quantile_op: Callable[..., ScalarMetricResult],
    normalized_kendall_distance_op: Callable[..., ScalarMetricResult],
    pairwise_matrix_distance_op: Callable[..., ScalarMetricResult],
    position_matrix_distance_op: Callable[..., ScalarMetricResult],
    sequence_type: type[Any],
    convergence_integrity_error_type: type[ConvergenceIntegrityError],
    scalar_metric_result_type: type[ScalarMetricResult],
    convergence_chain_input_type: type[ConvergenceChainInput],
    state_chain_diagnostics_type: type[StateChainDiagnostics],
    admitted_chain_type: type[_AdmittedChain],
    convergence_rule_type: type[ConvergenceRule],
    convergence_rule_values: _ConvergenceRuleValues,
    metric_absolute_tolerance: float,
    sha256_pattern: re.Pattern[str],
    machine_id_pattern: re.Pattern[str],
    max_safe_integer: int,
    likelihood_zero_scale: float,
    likelihood_equality_tolerance: float,
    masked_array_type: type[np.ma.MaskedArray[Any, Any]],
    np_all: Callable[..., Any],
    np_allclose: Callable[..., Any],
    np_any: Callable[..., Any],
    np_arange: Callable[..., Any],
    np_array_equal: Callable[..., Any],
    np_asarray: Callable[..., Any],
    np_count_nonzero: Callable[..., Any],
    np_diag: Callable[..., Any],
    np_dtype: Callable[..., Any],
    np_float64: type[np.float64],
    np_frombuffer: Callable[..., Any],
    np_int64: type[np.int64],
    np_isfinite: Callable[..., Any],
    np_sort: Callable[..., Any],
    math_fsum: Callable[..., float],
    math_isfinite: Callable[[float], bool],
    math_sqrt: Callable[[float], float],
) -> _ConvergenceKernel:
    convergence_rule = convergence_rule_type(*convergence_rule_values)

    def _integrity(code: str) -> ConvergenceIntegrityError:
        return convergence_integrity_error_type(code)

    def _assessable(value: float | int) -> ScalarMetricResult:
        return scalar_metric_result_type("ASSESSABLE", value, None)

    def _not_assessable(reason_code: str) -> ScalarMetricResult:
        return scalar_metric_result_type("NOT_ASSESSABLE", None, reason_code)

    def _source_array(value: object) -> NDArray[np.generic] | None:
        """Inspect an array without dtype conversion or mask/bool erasure."""

        if isinstance_op(value, masked_array_type):
            return None
        try:
            array: NDArray[np.generic] = np_asarray(value)
        except exception_type:
            return None
        if array.dtype.kind == "b":
            return None
        return array

    def _permutation_chain(order_states: object) -> NDArray[np.integer] | None:
        values = strict_integer_array_op(order_states)
        if values is None:
            return None
        if values.ndim != 2 or values.shape[0] == 0 or values.shape[1] < 2:
            return None
        target = np_arange(values.shape[1], dtype=values.dtype)
        if any_op(not np_array_equal(np_sort(row, kind="stable"), target) for row in values):
            return None
        return values

    def state_chain_diagnostics(order_states: object) -> StateChainDiagnostics | None:
        """Derive transitions, unique states, and repeated runs from raw states.

        ``None`` means the supplied object is not a finite integer permutation
        chain. Invalid chains are result-integrity failures, not numeric zeros.
        """

        chain = _permutation_chain(order_states)
        if chain is None:
            return None
        state_count = int_type(chain.shape[0])
        changed = np_any(chain[1:] != chain[:-1], axis=1)
        transition_count = int_type(np_count_nonzero(changed))
        if state_count < 2:
            transition_rate = _not_assessable("CONVERGENCE.INSUFFICIENT_STATE_CHAIN_LENGTH")
        else:
            transition_rate = _assessable(transition_count / (state_count - 1))

        unique_state_count = len_op({tuple_type(int_type(value) for value in row) for row in chain})
        unique_state_fraction = _assessable(unique_state_count / state_count)
        runs: list[int] = []
        current_run = 1
        for did_change in changed:
            if bool_type(did_change):
                runs.append(current_run)
                current_run = 1
            else:
                current_run += 1
        runs.append(current_run)
        maximum_fraction = _assessable(max_op(runs) / state_count)
        return state_chain_diagnostics_type(
            state_count=state_count,
            transition_count=transition_count,
            transition_rate=transition_rate,
            unique_state_count=unique_state_count,
            unique_state_fraction=unique_state_fraction,
            repeated_state_run_lengths=tuple_type(runs),
            max_repeated_state_fraction=maximum_fraction,
        )

    def likelihood_split_half_drift(likelihood_trace: object) -> ScalarMetricResult:
        """Derive the descriptive split-half drift using unbiased within-half variance."""

        values = strict_float_array_op(likelihood_trace)
        if values is None:
            return _not_assessable("NONFINITE_RAW_LIKELIHOOD")
        if values.ndim != 1 or not np_all(np_isfinite(values)):
            return _not_assessable("NONFINITE_RAW_LIKELIHOOD")
        half_length = values.size // 2
        if half_length < 2:
            return _not_assessable("INSUFFICIENT_TRACE_LENGTH")
        absolute_scale = max_op(abs_op(float_type(value)) for value in values)
        if absolute_scale == 0.0:
            return _assessable(0.0)

        # A common positive scale leaves the requested standardized drift
        # unchanged while keeping every mean and squared deviation in a safe
        # numeric range. Python scalar arithmetic is used deliberately here so
        # finite input extremes cannot emit NumPy overflow warnings.
        scaled = tuple_type(float_type(value) / absolute_scale for value in values)
        first = scaled[:half_length]
        last = scaled[-half_length:]
        first_mean = math_fsum(first) / half_length
        last_mean = math_fsum(last) / half_length
        first_variance = math_fsum((value - first_mean) ** 2 for value in first) / (half_length - 1)
        last_variance = math_fsum((value - last_mean) ** 2 for value in last) / (half_length - 1)
        pooled_scale_scaled = math_sqrt(0.5 * (first_variance + last_variance))
        mean_difference_scaled = abs_op(last_mean - first_mean)
        pooled_scale = absolute_scale * pooled_scale_scaled
        mean_difference = absolute_scale * mean_difference_scaled
        if pooled_scale < likelihood_zero_scale:
            if mean_difference <= likelihood_equality_tolerance:
                return _assessable(0.0)
            return _not_assessable("ZERO_SCALE_UNEQUAL_HALVES")
        return _assessable(mean_difference_scaled / pooled_scale_scaled)

    def _event_ids(value: object) -> tuple[str, ...] | None:
        if (
            isinstance_op(value, str_type)
            or isinstance_op(value, bytes_type)
            or not isinstance_op(value, sequence_type)
        ):
            return None
        try:
            event_ids = tuple_type(value)
            unique_event_count = len_op(set_op(event_ids))
        except exception_type:
            return None
        if len_op(event_ids) < 2 or unique_event_count != len_op(event_ids):
            return None
        if any_op(
            not isinstance_op(event_id, str_type) or machine_id_pattern.fullmatch(event_id) is None
            for event_id in event_ids
        ):
            return None
        return event_ids

    def _chain_identity(value: object) -> tuple[str, tuple[str, ...]]:
        if not isinstance_op(value, convergence_chain_input_type):
            raise _integrity("CONVERGENCE.CHAIN_INPUT")
        if (
            not isinstance_op(value.chain_execution_id, str_type)
            or sha256_pattern.fullmatch(value.chain_execution_id) is None
        ):
            raise _integrity("CONVERGENCE.CHAIN_ID")
        event_ids = _event_ids(value.event_ids)
        if event_ids is None:
            raise _integrity("CONVERGENCE.EVENT_IDENTITY")
        return value.chain_execution_id, event_ids

    def _positive_safe_integer(value: object, *, integrity_code: str) -> int:
        if type_op(value) is not int_type:
            raise _integrity(integrity_code)
        converted: int = int_type(value)
        if not 1 <= converted <= max_safe_integer:
            raise _integrity(integrity_code)
        return converted

    def _sampling_accounting(
        value: ConvergenceChainInput,
    ) -> tuple[int, int, int]:
        thinning_interval = _positive_safe_integer(
            value.thinning_interval,
            integrity_code="CONVERGENCE.THINNING_INTERVAL",
        )
        declared_unthinned = value.postburn_unthinned_state_count
        declared_retained = value.retained_state_count
        unthinned_count = _positive_safe_integer(
            declared_unthinned,
            integrity_code="CONVERGENCE.SAMPLING_ACCOUNTING",
        )
        retained_count = _positive_safe_integer(
            declared_retained,
            integrity_code="CONVERGENCE.SAMPLING_ACCOUNTING",
        )
        expected_retained = (unthinned_count - 1) // thinning_interval + 1
        if retained_count != expected_retained:
            raise _integrity("CONVERGENCE.SAMPLING_ACCOUNTING")
        return thinning_interval, unthinned_count, retained_count

    def _snapshot_int64(source: NDArray[np.generic]) -> NDArray[np.int64]:
        snapshot: NDArray[np.int64] = np_frombuffer(
            source.tobytes(order="C"), dtype=np_int64
        ).reshape(source.shape)
        return snapshot

    def _snapshot_float64(source: NDArray[np.generic]) -> NDArray[np.float64]:
        snapshot: NDArray[np.float64] = np_frombuffer(
            source.tobytes(order="C"), dtype=np_float64
        ).reshape(source.shape)
        return snapshot

    def _retain_order_states(
        unthinned_order_states: NDArray[np.int64], *, thinning_interval: int
    ) -> NDArray[np.int64]:
        """Return the immutable exact zero-based stride projection."""

        return _snapshot_int64(unthinned_order_states[::thinning_interval])

    def _admit_order_states(
        value: object, *, event_count: int
    ) -> tuple[_ArtifactStatus, NDArray[np.int64] | None]:
        if value is None:
            return "MISSING", None
        source = _source_array(value)
        if source is None or source.dtype != np_dtype(np_int64) or source.ndim != 2:
            return "INVALID", None
        if source.shape == (0, event_count):
            return "MISSING", None
        if source.shape[0] == 0 or source.shape[1] != event_count:
            return "INVALID", None
        values = _snapshot_int64(source)
        target = np_arange(event_count, dtype=np_int64)
        if any_op(not np_array_equal(np_sort(row, kind="stable"), target) for row in values):
            return "INVALID", None
        return "VALID", values

    def _admit_position_matrix(
        value: object, *, event_count: int
    ) -> tuple[_ArtifactStatus, NDArray[np.float64] | None]:
        if value is None:
            return "MISSING", None
        source = _source_array(value)
        if (
            source is None
            or source.dtype != np_dtype(np_float64)
            or source.shape != (event_count, event_count)
        ):
            return "INVALID", None
        matrix = _snapshot_float64(source)
        if (
            not np_all(np_isfinite(matrix))
            or np_any(matrix < 0.0)
            or np_any(matrix > 1.0)
            or not np_allclose(matrix.sum(axis=0), 1.0, atol=metric_absolute_tolerance, rtol=0.0)
            or not np_allclose(matrix.sum(axis=1), 1.0, atol=metric_absolute_tolerance, rtol=0.0)
        ):
            return "INVALID", None
        return "VALID", matrix

    def _admit_precedence_matrix(
        value: object, *, event_count: int
    ) -> tuple[_ArtifactStatus, NDArray[np.float64] | None]:
        if value is None:
            return "MISSING", None
        source = _source_array(value)
        if (
            source is None
            or source.dtype != np_dtype(np_float64)
            or source.shape != (event_count, event_count)
        ):
            return "INVALID", None
        matrix = _snapshot_float64(source)
        if (
            not np_all(np_isfinite(matrix))
            or np_any(matrix < 0.0)
            or np_any(matrix > 1.0)
            or not np_allclose(np_diag(matrix), 0.5, atol=metric_absolute_tolerance, rtol=0.0)
            or not np_allclose(matrix + matrix.T, 1.0, atol=metric_absolute_tolerance, rtol=0.0)
        ):
            return "INVALID", None
        return "VALID", matrix

    def _admit_likelihood_trace(value: object) -> NDArray[np.float64] | None:
        if value is None:
            return None
        source = _source_array(value)
        if source is None or source.dtype != np_dtype(np_float64) or source.ndim != 1:
            raise _integrity("CONVERGENCE.LIKELIHOOD_TRACE")
        return _snapshot_float64(source)

    def _derive_central_order(
        order_states: NDArray[np.int64], event_ids: tuple[str, ...]
    ) -> NDArray[np.int64]:
        """Return the retained-state mode with the frozen event-ID tie break."""

        counts: dict[tuple[int, ...], int] = {}
        for row in order_states:
            state = tuple_type(int_type(value) for value in row)
            counts[state] = counts.get(state, 0) + 1
        maximum_count = max_op(counts.values())
        candidates = (state for state, count in counts.items() if count == maximum_count)
        selected = min_op(
            candidates, key=lambda state: tuple_type(event_ids[index] for index in state)
        )
        source = np_asarray(selected, dtype=np_int64)
        return _snapshot_int64(source)

    def _admit_chain(
        value: ConvergenceChainInput,
        *,
        chain_execution_id: str,
        event_ids: tuple[str, ...],
    ) -> _AdmittedChain:
        event_count = len_op(event_ids)
        thinning_interval, declared_unthinned, declared_retained = _sampling_accounting(value)
        order_status, unthinned_order_states = _admit_order_states(
            value.postburn_order_state_chain, event_count=event_count
        )
        retained_order_states: NDArray[np.int64] | None = None
        if unthinned_order_states is not None:
            retained_order_states = _retain_order_states(
                unthinned_order_states,
                thinning_interval=thinning_interval,
            )
            if declared_unthinned != int_type(
                unthinned_order_states.shape[0]
            ) or declared_retained != int_type(retained_order_states.shape[0]):
                raise _integrity("CONVERGENCE.SAMPLING_ACCOUNTING")
        diagnostics = (
            state_chain_diagnostics(unthinned_order_states)
            if unthinned_order_states is not None
            else None
        )
        central_order = (
            _derive_central_order(retained_order_states, event_ids)
            if retained_order_states is not None
            else None
        )
        position_status, position = _admit_position_matrix(
            value.position_probabilities, event_count=event_count
        )
        precedence_status, precedence = _admit_precedence_matrix(
            value.pairwise_precedence, event_count=event_count
        )
        likelihood = _admit_likelihood_trace(value.postburn_likelihood_trace)
        if likelihood is not None and likelihood.size != declared_unthinned:
            raise _integrity("CONVERGENCE.LIKELIHOOD_TRACE_LENGTH")
        return admitted_chain_type(
            chain_execution_id=chain_execution_id,
            event_ids=event_ids,
            thinning_interval=thinning_interval,
            order_state_status=order_status,
            unthinned_order_states=unthinned_order_states,
            retained_order_states=retained_order_states,
            central_order=central_order,
            position_status=position_status,
            position_probabilities=position,
            precedence_status=precedence_status,
            pairwise_precedence=precedence,
            unthinned_likelihood_trace=likelihood,
            diagnostics=diagnostics,
        )

    def _chain_metric(chain_id: str, value: float | int | None) -> dict[str, object]:
        return {"chain_execution_id": chain_id, "value": value}

    def _sampling_accounting_row(chain: _AdmittedChain) -> dict[str, object]:
        return {
            "chain_execution_id": chain.chain_execution_id,
            "order_state_status": chain.order_state_status,
            "thinning_interval": chain.thinning_interval,
            "postburn_unthinned_state_count": (
                int_type(chain.unthinned_order_states.shape[0])
                if chain.unthinned_order_states is not None
                else None
            ),
            "retained_state_count": (
                int_type(chain.retained_order_states.shape[0])
                if chain.retained_order_states is not None
                else None
            ),
        }

    def _chain_metric_result(
        chain_id: str, result: ScalarMetricResult, *, trace_length: int
    ) -> dict[str, object]:
        return {
            "chain_execution_id": chain_id,
            "trace_length": trace_length,
            "status": result.status,
            "value": result.value,
            "reason_code": result.reason_code,
        }

    def _endpoint_event_ids(chain: _AdmittedChain) -> tuple[str, ...]:
        if chain.unthinned_order_states is None:
            raise assertion_error_type("Core endpoint input is unavailable.")
        return tuple_type(
            chain.event_ids[int_type(index)] for index in chain.unthinned_order_states[-1]
        )

    def _distinct_zero_transition_endpoints(chains: tuple[_AdmittedChain, ...]) -> int:
        endpoints: set[tuple[str, ...]] = set_op()
        for chain in chains:
            if chain.diagnostics is None:
                raise assertion_error_type("Core endpoint diagnostics are unavailable.")
            if chain.diagnostics.transition_count == 0:
                endpoints.add(_endpoint_event_ids(chain))
        return len_op(endpoints)

    def _metric_value(result: ScalarMetricResult, *, integrity_code: str) -> float:
        value = result.value
        if result.status != "ASSESSABLE" or (
            not isinstance_op(value, float_type) and not isinstance_op(value, int_type)
        ):
            raise _integrity(integrity_code)
        converted = float_type(value)
        if not math_isfinite(converted):
            raise _integrity(integrity_code)
        return converted

    def _optional_metric_value(
        result: ScalarMetricResult, *, integrity_code: str
    ) -> float | int | None:
        if result.status == "NOT_ASSESSABLE" and result.value is None:
            return None
        return _metric_value(result, integrity_code=integrity_code)

    def _pairwise_summary(
        metric_id: str,
        chains: tuple[_AdmittedChain, ...],
        distance: object,
    ) -> dict[str, object]:
        pairs: list[dict[str, object]] = []
        values: list[float] = []
        for left_index, left in enumerate_op(chains[:-1]):
            for right in chains[left_index + 1 :]:
                if distance == "central":
                    if left.central_order is None or right.central_order is None:
                        raise assertion_error_type("Core central-order input is unavailable.")
                    left_order = tuple_type(
                        left.event_ids[int_type(index)] for index in left.central_order
                    )
                    right_order = tuple_type(
                        right.event_ids[int_type(index)] for index in right.central_order
                    )
                    result = normalized_kendall_distance_op(left_order, right_order)
                elif distance == "position":
                    if left.position_probabilities is None or right.position_probabilities is None:
                        raise assertion_error_type("Core position input is unavailable.")
                    result = position_matrix_distance_op(
                        left.position_probabilities,
                        right.position_probabilities,
                        left_event_ids=left.event_ids,
                        right_event_ids=right.event_ids,
                    )
                elif distance == "precedence":
                    if left.pairwise_precedence is None or right.pairwise_precedence is None:
                        raise assertion_error_type("Core precedence input is unavailable.")
                    result = pairwise_matrix_distance_op(
                        left.pairwise_precedence,
                        right.pairwise_precedence,
                        left_event_ids=left.event_ids,
                        right_event_ids=right.event_ids,
                    )
                else:  # pragma: no cover - all callers are fixed below
                    raise assertion_error_type("Unknown core-owned convergence distance.")
                value = _metric_value(result, integrity_code="CONVERGENCE.DISTANCE_DERIVATION")
                pairs.append(
                    {
                        "left_chain_execution_id": left.chain_execution_id,
                        "right_chain_execution_id": right.chain_execution_id,
                        "distance": value,
                    }
                )
                values.append(value)
        return {
            "metric_id": metric_id,
            "pairs": pairs,
            "median_distance": (
                _metric_value(
                    empirical_quantile_op(values, 0.5),
                    integrity_code="CONVERGENCE.DISTANCE_QUANTILE_DERIVATION",
                )
                if values
                else None
            ),
            "maximum_distance": max_op(values) if values else None,
        }

    def _classify(
        chains: tuple[_AdmittedChain, ...],
        central_summary: dict[str, object] | None,
        position_summary: dict[str, object] | None,
        precedence_summary: dict[str, object] | None,
    ) -> tuple[ConvergenceAssessment, list[str]]:
        """Apply the fixed priority order and return at most one governing reason."""

        rule = convergence_rule
        if any_op(chain.order_state_status == "INVALID" for chain in chains):
            return "CONVERGENCE_FAIL", ["CONVERGENCE.INVALID_ORDER_SAMPLES"]
        if any_op(
            chain.position_status == "INVALID" or chain.precedence_status == "INVALID"
            for chain in chains
        ):
            return "CONVERGENCE_FAIL", ["CONVERGENCE.INVALID_REQUIRED_DIAGNOSTIC"]
        if len_op(chains) < rule.assessable_min_independent_chains:
            return (
                "CONVERGENCE_NOT_ASSESSABLE",
                ["CONVERGENCE.INSUFFICIENT_INDEPENDENT_CHAINS"],
            )
        if any_op(chain.order_state_status == "MISSING" for chain in chains):
            return "CONVERGENCE_NOT_ASSESSABLE", ["CONVERGENCE.MISSING_ORDER_SAMPLES"]
        if any_op(
            chain.position_status == "MISSING" or chain.precedence_status == "MISSING"
            for chain in chains
        ):
            return (
                "CONVERGENCE_NOT_ASSESSABLE",
                ["CONVERGENCE.REQUIRED_CROSS_CHAIN_DIAGNOSTIC_UNAVAILABLE"],
            )
        if any_op(
            chain.diagnostics is not None
            and chain.diagnostics.state_count
            < rule.assessable_min_unthinned_postburn_states_per_chain
            for chain in chains
        ):
            return "CONVERGENCE_NOT_ASSESSABLE", ["CONVERGENCE.INSUFFICIENT_POSTBURN_STATES"]

        if _distinct_zero_transition_endpoints(chains) >= 2:
            return "CONVERGENCE_FAIL", ["CONVERGENCE.STUCK_CHAINS_IN_DISTINCT_STATES"]

        if central_summary is None or position_summary is None or precedence_summary is None:
            raise assertion_error_type("Classifiable cross-chain diagnostics are unavailable.")
        central_maximum = _summary_distance(central_summary, "maximum_distance")
        position_maximum = _summary_distance(position_summary, "maximum_distance")
        position_median = _summary_distance(position_summary, "median_distance")
        precedence_median = _summary_distance(precedence_summary, "median_distance")
        if (
            position_maximum > rule.fail_combined_max_position_distance_over
            and central_maximum > rule.fail_combined_max_kendall_distance_over
        ):
            return "CONVERGENCE_FAIL", ["CONVERGENCE.CROSS_CHAIN_DISAGREEMENT"]

        transition_rates: list[float] = []
        for chain in chains:
            if chain.diagnostics is None:
                raise assertion_error_type("Classifiable transition diagnostics are unavailable.")
            transition_rates.append(
                _metric_value(
                    chain.diagnostics.transition_rate,
                    integrity_code="CONVERGENCE.TRANSITION_FRACTION",
                )
            )
        if (
            all_op(value > rule.pass_transition_rate_exclusive_min for value in transition_rates)
            and position_median <= rule.pass_median_position_distance_max
            and position_maximum <= rule.pass_max_position_distance_max
            and precedence_median <= rule.pass_median_precedence_distance_max
        ):
            return "CONVERGENCE_PASS", []
        return "CONVERGENCE_WARN", ["CONVERGENCE.PASS_THRESHOLDS_NOT_MET"]

    def _summary_distance(summary: dict[str, object], field_name: str) -> float:
        value = summary.get(field_name)
        if not isinstance_op(value, float_type) or not math_isfinite(value):
            raise _integrity("CONVERGENCE.CROSS_CHAIN_DIAGNOSTICS")
        return value

    def _immutable_json_projection(value: object) -> object:
        if isinstance_op(value, dict_type):
            return (
                dict_type,
                frozenset_op(
                    (key, _immutable_json_projection(item))
                    for key, item in value.items()
                ),
            )
        if isinstance_op(value, list_type):
            return (
                list_type,
                tuple_type(_immutable_json_projection(item) for item in value),
            )
        return (None, value)

    canonical_non_sampling_record = _immutable_json_projection(
        {
            "assessment": "NOT_APPLICABLE",
            "rule_set_version": convergence_rule.rule_id,
            "sampling_accounting_by_chain": [],
            "actual_transition_fraction_by_chain": [],
            "unique_state_count_by_chain": [],
            "unique_state_fraction_by_chain": [],
            "repeated_state_run_summary": None,
            "likelihood_trace_summary": {
                "status": "NOT_APPLICABLE_BY_CAPABILITY",
                "value": None,
                "reason_code": "LIKELIHOOD_TRACE_UNAVAILABLE",
                "split_half_drift_by_chain": [],
            },
            "central_order_chain_distances": None,
            "position_matrix_chain_distances": None,
            "precedence_matrix_chain_distances": None,
            "budget_stability_summary": None,
            "reasons": ["CONVERGENCE.NOT_APPLICABLE_NON_SAMPLING"],
        }
    )

    def is_canonical_non_sampling_convergence_record(value: object) -> bool:
        """Recognize only the finalizer-authored exact non-sampling record."""

        if type_op(value) is not dict_type:
            return False
        try:
            return _immutable_json_projection(value) == canonical_non_sampling_record
        except exception_type:
            return False

    def derive_convergence_record(chains: Sequence[ConvergenceChainInput]) -> ConvergenceRecord:
        """Derive and classify one run from raw chain arrays only.

        ``chains`` is in frozen chain-plan order. Missing and invalid scientific
        arrays become typed convergence results. Structurally impossible identity,
        binding, or likelihood-capability inputs raise
        :class:`ConvergenceIntegrityError`; values and identifiers are never
        included in the error text.
        """

        if (
            isinstance_op(chains, str_type)
            or isinstance_op(chains, bytes_type)
            or not isinstance_op(chains, sequence_type)
        ):
            raise _integrity("CONVERGENCE.CHAIN_SET")
        try:
            supplied_chains = tuple_type(chains)
        except exception_type:
            raise _integrity("CONVERGENCE.CHAIN_SET") from None
        identities = tuple_type(_chain_identity(chain) for chain in supplied_chains)
        if identities:
            chain_ids = tuple_type(identity[0] for identity in identities)
            if len_op(set_op(chain_ids)) != len_op(chain_ids):
                raise _integrity("CONVERGENCE.CHAIN_IDENTITY")
            expected_events = identities[0][1]
            if any_op(event_ids != expected_events for _, event_ids in identities[1:]):
                raise _integrity("CONVERGENCE.EVENT_IDENTITY")
            admitted = tuple_type(
                _admit_chain(
                    chain,
                    chain_execution_id=chain_execution_id,
                    event_ids=event_ids,
                )
                for chain, (chain_execution_id, event_ids) in zip_op(
                    supplied_chains, identities, strict=True
                )
            )
            if any_op(
                chain.thinning_interval != admitted[0].thinning_interval for chain in admitted[1:]
            ):
                raise _integrity("CONVERGENCE.THINNING_IDENTITY")
        else:
            admitted = ()

        has_likelihood = tuple_type(
            chain.unthinned_likelihood_trace is not None for chain in admitted
        )
        if any_op(has_likelihood) and not all_op(has_likelihood):
            raise _integrity("CONVERGENCE.LIKELIHOOD_CAPABILITY")

        central_summary = (
            _pairwise_summary("central-order-kendall/1", admitted, "central")
            if admitted and all_op(chain.central_order is not None for chain in admitted)
            else None
        )
        position_summary = (
            _pairwise_summary("position-matrix/1", admitted, "position")
            if admitted and all_op(chain.position_probabilities is not None for chain in admitted)
            else None
        )
        precedence_summary = (
            _pairwise_summary("pairwise-precedence-matrix/1", admitted, "precedence")
            if admitted and all_op(chain.pairwise_precedence is not None for chain in admitted)
            else None
        )
        assessment, reasons = _classify(
            admitted, central_summary, position_summary, precedence_summary
        )

        transition_fractions = [
            (
                _optional_metric_value(
                    chain.diagnostics.transition_rate,
                    integrity_code="CONVERGENCE.TRANSITION_FRACTION",
                )
                if chain.diagnostics is not None
                else None
            )
            for chain in admitted
        ]
        unique_fractions = [
            (
                _metric_value(
                    chain.diagnostics.unique_state_fraction,
                    integrity_code="CONVERGENCE.UNIQUE_STATE_FRACTION",
                )
                if chain.diagnostics is not None
                else None
            )
            for chain in admitted
        ]
        likelihood_summary: dict[str, object]
        if has_likelihood and all_op(has_likelihood):
            likelihood_summary = {
                "status": "AVAILABLE",
                "value": None,
                "reason_code": None,
                "split_half_drift_by_chain": [
                    _chain_metric_result(
                        chain.chain_execution_id,
                        likelihood_split_half_drift(chain.unthinned_likelihood_trace),
                        trace_length=int_type(chain.unthinned_likelihood_trace.size),
                    )
                    for chain in admitted
                    if chain.unthinned_likelihood_trace is not None
                ],
            }
        else:
            likelihood_summary = {
                "status": "NOT_APPLICABLE_BY_CAPABILITY",
                "value": None,
                "reason_code": "LIKELIHOOD_TRACE_UNAVAILABLE",
                "split_half_drift_by_chain": [],
            }

        return {
            "assessment": assessment,
            "rule_set_version": convergence_rule.rule_id,
            "sampling_accounting_by_chain": [_sampling_accounting_row(chain) for chain in admitted],
            "actual_transition_fraction_by_chain": [
                _chain_metric(chain.chain_execution_id, fraction)
                for chain, fraction in zip_op(admitted, transition_fractions, strict=True)
            ],
            "unique_state_count_by_chain": [
                _chain_metric(
                    chain.chain_execution_id,
                    chain.diagnostics.unique_state_count if chain.diagnostics is not None else None,
                )
                for chain in admitted
            ],
            "unique_state_fraction_by_chain": [
                _chain_metric(chain.chain_execution_id, fraction)
                for chain, fraction in zip_op(admitted, unique_fractions, strict=True)
            ],
            "repeated_state_run_summary": (
                {
                    "maximum_run_length_by_chain": [
                        _chain_metric(
                            chain.chain_execution_id,
                            max_op(chain.diagnostics.repeated_state_run_lengths),
                        )
                        for chain in admitted
                        if chain.diagnostics is not None
                    ],
                    "max_repeated_state_fraction_by_chain": [
                        _chain_metric(
                            chain.chain_execution_id,
                            _metric_value(
                                chain.diagnostics.max_repeated_state_fraction,
                                integrity_code="CONVERGENCE.MAX_REPEATED_STATE_FRACTION",
                            ),
                        )
                        for chain in admitted
                        if chain.diagnostics is not None
                    ],
                    "transition_count_by_chain": [
                        _chain_metric(
                            chain.chain_execution_id,
                            chain.diagnostics.transition_count,
                        )
                        for chain in admitted
                        if chain.diagnostics is not None
                    ],
                    "transition_fraction_by_chain": [
                        _chain_metric(chain.chain_execution_id, fraction)
                        for chain, fraction in zip_op(admitted, transition_fractions, strict=True)
                    ],
                    "endpoint_order_by_chain": [
                        {
                            "chain_execution_id": chain.chain_execution_id,
                            "transition_count": chain.diagnostics.transition_count,
                            "endpoint_event_ids": list_type(_endpoint_event_ids(chain)),
                        }
                        for chain in admitted
                        if chain.diagnostics is not None
                    ],
                    "distinct_zero_transition_endpoint_count": (
                        _distinct_zero_transition_endpoints(admitted)
                    ),
                }
                if admitted and all_op(chain.diagnostics is not None for chain in admitted)
                else None
            ),
            "likelihood_trace_summary": likelihood_summary,
            "central_order_chain_distances": central_summary,
            "position_matrix_chain_distances": position_summary,
            "precedence_matrix_chain_distances": precedence_summary,
            "budget_stability_summary": None,
            "reasons": reasons,
        }

    return _ConvergenceKernel(
        _integrity=_integrity,
        _assessable=_assessable,
        _not_assessable=_not_assessable,
        _source_array=_source_array,
        _permutation_chain=_permutation_chain,
        state_chain_diagnostics=state_chain_diagnostics,
        likelihood_split_half_drift=likelihood_split_half_drift,
        _event_ids=_event_ids,
        _chain_identity=_chain_identity,
        _positive_safe_integer=_positive_safe_integer,
        _sampling_accounting=_sampling_accounting,
        _snapshot_int64=_snapshot_int64,
        _snapshot_float64=_snapshot_float64,
        _retain_order_states=_retain_order_states,
        _admit_order_states=_admit_order_states,
        _admit_position_matrix=_admit_position_matrix,
        _admit_precedence_matrix=_admit_precedence_matrix,
        _admit_likelihood_trace=_admit_likelihood_trace,
        _derive_central_order=_derive_central_order,
        _admit_chain=_admit_chain,
        _chain_metric=_chain_metric,
        _sampling_accounting_row=_sampling_accounting_row,
        _chain_metric_result=_chain_metric_result,
        _endpoint_event_ids=_endpoint_event_ids,
        _distinct_zero_transition_endpoints=_distinct_zero_transition_endpoints,
        _metric_value=_metric_value,
        _optional_metric_value=_optional_metric_value,
        _pairwise_summary=_pairwise_summary,
        _classify=_classify,
        _summary_distance=_summary_distance,
        is_canonical_non_sampling_convergence_record=(
            is_canonical_non_sampling_convergence_record
        ),
        derive_convergence_record=derive_convergence_record,
    )


_CONVERGENCE_KERNEL = _build_convergence_kernel(
    abs_op=abs,
    all_op=all,
    any_op=any,
    assertion_error_type=AssertionError,
    bool_type=bool,
    bytes_type=bytes,
    dict_type=dict,
    enumerate_op=enumerate,
    exception_type=Exception,
    float_type=float,
    frozenset_op=frozenset,
    int_type=int,
    isinstance_op=_ISINSTANCE_OP,
    len_op=len,
    list_type=list,
    max_op=max,
    min_op=min,
    set_op=set,
    str_type=str,
    tuple_type=tuple,
    type_op=type,
    zip_op=zip,
    strict_float_array_op=_NUMERIC_KERNEL.strict_float_array,
    strict_integer_array_op=_NUMERIC_KERNEL.strict_integer_array,
    empirical_quantile_op=_METRIC_KERNEL.empirical_quantile,
    normalized_kendall_distance_op=_METRIC_KERNEL.normalized_kendall_distance,
    pairwise_matrix_distance_op=_METRIC_KERNEL.pairwise_matrix_distance,
    position_matrix_distance_op=_METRIC_KERNEL.position_matrix_distance,
    sequence_type=Sequence,
    convergence_integrity_error_type=ConvergenceIntegrityError,
    scalar_metric_result_type=ScalarMetricResult,
    convergence_chain_input_type=ConvergenceChainInput,
    state_chain_diagnostics_type=StateChainDiagnostics,
    admitted_chain_type=_AdmittedChain,
    convergence_rule_type=ConvergenceRule,
    convergence_rule_values=_CONVERGENCE_RULE_VALUES,
    metric_absolute_tolerance=METRIC_ABSOLUTE_TOLERANCE,
    sha256_pattern=_SHA256_PATTERN,
    machine_id_pattern=_MACHINE_ID_PATTERN,
    max_safe_integer=_MAX_SAFE_INTEGER,
    likelihood_zero_scale=_LIKELIHOOD_ZERO_SCALE,
    likelihood_equality_tolerance=_LIKELIHOOD_EQUALITY_TOLERANCE,
    masked_array_type=np.ma.MaskedArray,
    np_all=np.all,
    np_allclose=np.allclose,
    np_any=np.any,
    np_arange=np.arange,
    np_array_equal=np.array_equal,
    np_asarray=np.asarray,
    np_count_nonzero=np.count_nonzero,
    np_diag=np.diag,
    np_dtype=np.dtype,
    np_float64=np.float64,
    np_frombuffer=np.frombuffer,
    np_int64=np.int64,
    np_isfinite=np.isfinite,
    np_sort=np.sort,
    math_fsum=math.fsum,
    math_isfinite=math.isfinite,
    math_sqrt=math.sqrt,
)

for _operation_name in _ConvergenceKernel.__dataclass_fields__:
    _operation = getattr(_CONVERGENCE_KERNEL, _operation_name)
    _operation.__name__ = _operation_name
    _operation.__qualname__ = _operation_name
    _operation.__module__ = __name__

strict_float_array = _NUMERIC_KERNEL.strict_float_array
strict_integer_array = _NUMERIC_KERNEL.strict_integer_array
empirical_quantile = _METRIC_KERNEL.empirical_quantile
normalized_kendall_distance = _METRIC_KERNEL.normalized_kendall_distance
pairwise_matrix_distance = _METRIC_KERNEL.pairwise_matrix_distance
position_matrix_distance = _METRIC_KERNEL.position_matrix_distance
_integrity = _CONVERGENCE_KERNEL._integrity
_assessable = _CONVERGENCE_KERNEL._assessable
_not_assessable = _CONVERGENCE_KERNEL._not_assessable
_source_array = _CONVERGENCE_KERNEL._source_array
_permutation_chain = _CONVERGENCE_KERNEL._permutation_chain
state_chain_diagnostics = _CONVERGENCE_KERNEL.state_chain_diagnostics
likelihood_split_half_drift = _CONVERGENCE_KERNEL.likelihood_split_half_drift
_event_ids = _CONVERGENCE_KERNEL._event_ids
_chain_identity = _CONVERGENCE_KERNEL._chain_identity
_positive_safe_integer = _CONVERGENCE_KERNEL._positive_safe_integer
_sampling_accounting = _CONVERGENCE_KERNEL._sampling_accounting
_snapshot_int64 = _CONVERGENCE_KERNEL._snapshot_int64
_snapshot_float64 = _CONVERGENCE_KERNEL._snapshot_float64
_retain_order_states = _CONVERGENCE_KERNEL._retain_order_states
_admit_order_states = _CONVERGENCE_KERNEL._admit_order_states
_admit_position_matrix = _CONVERGENCE_KERNEL._admit_position_matrix
_admit_precedence_matrix = _CONVERGENCE_KERNEL._admit_precedence_matrix
_admit_likelihood_trace = _CONVERGENCE_KERNEL._admit_likelihood_trace
_derive_central_order = _CONVERGENCE_KERNEL._derive_central_order
_admit_chain = _CONVERGENCE_KERNEL._admit_chain
_chain_metric = _CONVERGENCE_KERNEL._chain_metric
_sampling_accounting_row = _CONVERGENCE_KERNEL._sampling_accounting_row
_chain_metric_result = _CONVERGENCE_KERNEL._chain_metric_result
_endpoint_event_ids = _CONVERGENCE_KERNEL._endpoint_event_ids
_distinct_zero_transition_endpoints = _CONVERGENCE_KERNEL._distinct_zero_transition_endpoints
_metric_value = _CONVERGENCE_KERNEL._metric_value
_optional_metric_value = _CONVERGENCE_KERNEL._optional_metric_value
_pairwise_summary = _CONVERGENCE_KERNEL._pairwise_summary
_classify = _CONVERGENCE_KERNEL._classify
_summary_distance = _CONVERGENCE_KERNEL._summary_distance
is_canonical_non_sampling_convergence_record = (
    _CONVERGENCE_KERNEL.is_canonical_non_sampling_convergence_record
)
derive_convergence_record = _CONVERGENCE_KERNEL.derive_convergence_record
