"""One strict numeric admission boundary shared by every scientific metric."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, TypeGuard, cast

import numpy as np
from numpy.typing import NDArray

FloatArray = NDArray[np.float64]
IntegerArray = NDArray[np.integer]


class _AnyOp(Protocol):
    def __call__(self, values: Iterable[object], /) -> bool: ...


class _IsInstanceOp(Protocol):
    __module__: str
    __name__: str
    __qualname__: str

    def __call__[T](self, value: object, class_info: type[T], /) -> TypeGuard[T]: ...


def _make_isinstance_op(
    isinstance_builtin: Callable[..., bool],
) -> _IsInstanceOp:
    """Return a typed exact binding to the import-time ``isinstance`` builtin."""

    def isinstance_op[T](value: object, class_info: type[T], /) -> TypeGuard[T]:
        return isinstance_builtin(value, class_info)

    return cast(_IsInstanceOp, isinstance_op)


_ISINSTANCE_OP = _make_isinstance_op(isinstance)
_ISINSTANCE_OP.__name__ = "_ISINSTANCE_OP"
_ISINSTANCE_OP.__qualname__ = "_ISINSTANCE_OP"
_ISINSTANCE_OP.__module__ = __name__


@dataclass(frozen=True, slots=True)
class _NumericKernel:
    """Exact import-time operations for the shared numeric admission boundary."""

    _contains_forbidden_leaf: Callable[..., bool]
    _strict_source_array: Callable[..., NDArray[np.generic] | None]
    strict_float_array: Callable[[object], FloatArray | None]
    strict_integer_array: Callable[[object], IntegerArray | None]


def _build_numeric_kernel(
    *,
    any_op: _AnyOp,
    bool_type: type[bool],
    bytes_type: type[bytes],
    frozenset_op: Callable[..., frozenset[Any]],
    id_op: Callable[[object], int],
    isinstance_op: _IsInstanceOp,
    overflow_error_type: type[OverflowError],
    recursion_error_type: type[RecursionError],
    set_op: Callable[[], set[int]],
    str_type: type[str],
    type_error_type: type[TypeError],
    value_error_type: type[ValueError],
    sequence_type: type[Any],
    masked_array_type: type[np.ma.MaskedArray[Any, Any]],
    numpy_bool_type: type[np.bool_],
    ndarray_type: type[np.ndarray[Any, Any]],
    asarray: Callable[[object], NDArray[np.generic]],
    all_values: Callable[..., Any],
    isfinite: Callable[..., Any],
    float64_type: type[np.float64],
) -> _NumericKernel:
    def _contains_forbidden_leaf(
        values: object,
        *,
        seen_container_ids: set[int] | None = None,
    ) -> bool:
        """Inspect original leaves before NumPy can erase bool or mask semantics."""

        if isinstance_op(values, masked_array_type):
            return True
        if isinstance_op(values, bool_type) or isinstance_op(values, numpy_bool_type):
            return True
        if isinstance_op(values, ndarray_type):
            if values.dtype.kind == "b":
                return True
            if values.dtype.kind != "O":
                return False
            return any_op(_contains_forbidden_leaf(item) for item in values.flat)
        if (
            isinstance_op(values, str_type)
            or isinstance_op(values, bytes_type)
            or not isinstance_op(values, sequence_type)
        ):
            return False

        if seen_container_ids is None:
            seen_container_ids = set_op()
        container_id = id_op(values)
        if container_id in seen_container_ids:
            return False
        seen_container_ids.add(container_id)
        try:
            return any_op(
                _contains_forbidden_leaf(item, seen_container_ids=seen_container_ids)
                for item in values
            )
        finally:
            seen_container_ids.remove(container_id)

    def _strict_source_array(
        values: object,
        *,
        allowed_kinds: frozenset[str],
    ) -> NDArray[np.generic] | None:
        try:
            if _contains_forbidden_leaf(values):
                return None
        except (type_error_type, value_error_type, recursion_error_type):
            return None
        try:
            source = asarray(values)
        except (type_error_type, value_error_type, overflow_error_type):
            return None
        if source.dtype.kind not in allowed_kinds:
            return None
        if source.dtype.kind == "f" and not all_values(isfinite(source)):
            return None
        return source

    def strict_float_array(values: object) -> FloatArray | None:
        """Admit only real integer/float input and return finite float64 values."""

        source = _strict_source_array(values, allowed_kinds=frozenset_op({"i", "u", "f"}))
        if source is None:
            return None
        try:
            array = source.astype(float64_type, copy=False)
        except (type_error_type, value_error_type, overflow_error_type):
            return None
        if not all_values(isfinite(array)):
            return None
        return array

    def strict_integer_array(values: object) -> IntegerArray | None:
        """Admit only unmasked, non-boolean signed or unsigned integer values."""

        source = _strict_source_array(values, allowed_kinds=frozenset_op({"i", "u"}))
        if source is None:
            return None
        return source  # type: ignore[return-value]

    return _NumericKernel(
        _contains_forbidden_leaf=_contains_forbidden_leaf,
        _strict_source_array=_strict_source_array,
        strict_float_array=strict_float_array,
        strict_integer_array=strict_integer_array,
    )


_NUMERIC_KERNEL = _build_numeric_kernel(
    any_op=any,
    bool_type=bool,
    bytes_type=bytes,
    frozenset_op=frozenset,
    id_op=id,
    isinstance_op=_ISINSTANCE_OP,
    overflow_error_type=OverflowError,
    recursion_error_type=RecursionError,
    set_op=set,
    str_type=str,
    type_error_type=TypeError,
    value_error_type=ValueError,
    sequence_type=Sequence,
    masked_array_type=np.ma.MaskedArray,
    numpy_bool_type=np.bool_,
    ndarray_type=np.ndarray,
    asarray=np.asarray,
    all_values=np.all,
    isfinite=np.isfinite,
    float64_type=np.float64,
)

for _operation_name in _NumericKernel.__dataclass_fields__:
    _operation = getattr(_NUMERIC_KERNEL, _operation_name)
    _operation.__name__ = _operation_name
    _operation.__qualname__ = _operation_name
    _operation.__module__ = __name__

_contains_forbidden_leaf = _NUMERIC_KERNEL._contains_forbidden_leaf
_strict_source_array = _NUMERIC_KERNEL._strict_source_array
strict_float_array = _NUMERIC_KERNEL.strict_float_array
strict_integer_array = _NUMERIC_KERNEL.strict_integer_array
