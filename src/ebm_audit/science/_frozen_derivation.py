"""Import-time lock for the analyst-decision calculation graph.

The analyst-decision source is intentionally written as ordinary module-level
functions so that its numerical rules remain readable.  This module snapshots
that source once, rejects dynamic or mutable dependencies, recreates every
reachable project-local function against one private globals dictionary, and
creates private immutable record types.  Later replacement or deletion of a
module alias therefore cannot change the calculation used by the capture
boundary.

This is a calculation-integrity boundary, not a claim to protect a compromised
Python interpreter or deliberate mutation through a hidden function's
``__globals__`` dictionary.
"""

from __future__ import annotations

import builtins
import dis
import functools
import json
import operator
import sys
import types
from collections.abc import Callable, Mapping
from dataclasses import MISSING, FrozenInstanceError, dataclass, fields, is_dataclass
from re import Pattern
from types import (
    BuiltinFunctionType,
    CellType,
    CodeType,
    FunctionType,
    MappingProxyType,
    MemberDescriptorType,
    MethodType,
    ModuleType,
)
from typing import Any, ClassVar, Final, Literal, cast

import numpy as np

FROZEN_DERIVATION_GRAPH_RULE_ID: Final = "private-import-time-scientific-derivation-graph/1"
FROZEN_ANALYST_DERIVATION_RULE_ID: Final = "private-import-time-analyst-decision-derivation/1"
_FORBIDDEN_DYNAMIC_GLOBAL_NAMES: Final = frozenset(
    {
        "__import__",
        "eval",
        "exec",
        "globals",
        "locals",
        "vars",
    }
)
_FORBIDDEN_INSTRUCTIONS: Final = frozenset(
    {
        "IMPORT_FROM",
        "IMPORT_NAME",
        "IMPORT_STAR",
        "LOAD_FROM_DICT_OR_GLOBALS",
        "LOAD_NAME",
    }
)
_IMMUTABLE_SCALAR_TYPES: Final = (bool, bytes, float, int, str, type(None))
_APPROVED_NUMPY_CALLABLE_TYPES: Final = (np.ufunc, type(np.sort))
_NUMPY_ARRAY_FUNCTION_DISPATCHER_TYPE: Final = type(np.sort)
_JSON_SCANNER_TYPE: Final = type(cast(Any, json.JSONDecoder()).scan_once)
_OPERATOR_METHODCALLER_TYPE: Final = type(operator.methodcaller("items"))
_LRU_CACHE_WRAPPER_TYPE: Final = type(functools.lru_cache(maxsize=1)(lambda: None))
_APPROVED_TYPING_SENTINEL_TYPES: Final[tuple[type[Any], ...]] = (
    type(ClassVar),
    type(Literal),
)
_RE_COMPILER_DIS: Final = cast(
    FunctionType,
    vars(sys.modules["re._compiler"])["dis"],
)
_RE_RUNTIME_CACHES: Final = (
    vars(sys.modules["re"])["_cache"],
    vars(sys.modules["re"])["_cache2"],
)
_LAZY_ANNOTATION_NAMESPACE_KEYS: Final = frozenset(
    {
        "__annotate_func__",
        "__annotations_cache__",
    }
)
_MISSING: Final = object()


class FrozenAnalystDerivationError(RuntimeError):
    """Raised during import when the analyst calculation cannot be locked."""


class _LockedRecordType(type):
    """Reject ordinary mutation of private calculation record classes."""

    def __setattr__(cls, name: str, value: object) -> None:
        if cast(Mapping[str, object], type.__getattribute__(cls, "__dict__")).get(
            "_frozen_derivation_locked",
            False,
        ):
            raise TypeError("Frozen analyst-decision record classes cannot be modified.")
        type.__setattr__(cls, name, value)

    def __delattr__(cls, name: str) -> None:
        if cast(Mapping[str, object], type.__getattribute__(cls, "__dict__")).get(
            "_frozen_derivation_locked",
            False,
        ):
            raise TypeError("Frozen analyst-decision record classes cannot be modified.")
        type.__delattr__(cls, name)


@dataclass(frozen=True, slots=True)
class _FunctionSnapshot:
    source: FunctionType
    code: CodeType
    defaults_object: tuple[object, ...] | None
    defaults: tuple[object, ...] | None
    keyword_defaults_object: dict[str, object] | None
    keyword_defaults: Mapping[str, object] | None
    annotations_object: dict[str, object]
    annotations: Mapping[str, object]
    name: str
    qualname: str
    module: str
    doc: str | None
    global_names: frozenset[str]


@dataclass(frozen=True, slots=True)
class _GlobalAccess:
    name: str
    attribute_path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _StaticImportAccess:
    module_name: str
    imported_names: tuple[str, ...]
    attribute_paths: tuple[tuple[str, ...], ...]


@dataclass(frozen=True, slots=True)
class FrozenDerivationGraph:
    """The exact private operations and record types used by one calculation."""

    rule_id: str
    functions: Mapping[str, FunctionType]
    record_types: Mapping[str, type[Any]]
    assert_dependencies_current: Callable[[], None]


@dataclass(frozen=True, slots=True)
class FrozenAnalystDerivation:
    """The exact private operations and record types used by capture."""

    rule_id: str
    functions: Mapping[str, FunctionType]
    record_types: Mapping[str, type[Any]]
    derive_analyst_decision_evidence: Callable[..., Any]
    validate_analyst_decision_semantics: Callable[..., Any]
    canonical_origin_attempt_type: type[Any]
    canonical_numeric_comparison_type: type[Any]
    canonical_analyst_aggregate_type: type[Any]
    canonical_analyst_layer_type: type[Any]
    canonical_analyst_bundle_type: type[Any]
    analyst_origin_input_type: type[Any]
    analyst_candidate_input_type: type[Any]
    assert_dependencies_current: Callable[[], None]


def _instructions(code: CodeType) -> tuple[dis.Instruction, ...]:
    collected = list(dis.get_instructions(code))
    for constant in code.co_consts:
        if isinstance(constant, CodeType):
            collected.extend(_instructions(constant))
    return tuple(collected)


def _validate_code(code: CodeType) -> frozenset[str]:
    instructions = _instructions(code)
    forbidden_opcodes = {
        instruction.opname
        for instruction in instructions
        if instruction.opname in _FORBIDDEN_INSTRUCTIONS
    }
    if forbidden_opcodes:
        raise FrozenAnalystDerivationError(
            "Analyst-decision calculation contains a dynamic name or runtime import."
        )
    loaded_names = frozenset(
        instruction.argval
        for instruction in instructions
        if instruction.opname == "LOAD_GLOBAL" and type(instruction.argval) is str
    )
    if loaded_names & _FORBIDDEN_DYNAMIC_GLOBAL_NAMES:
        raise FrozenAnalystDerivationError(
            "Analyst-decision calculation contains dynamic global access."
        )
    return loaded_names


def _is_immutable_value(value: object) -> bool:
    if type(value) in _IMMUTABLE_SCALAR_TYPES or value is Ellipsis or value is NotImplemented:
        return True
    if type(value) is tuple:
        return all(_is_immutable_value(child) for child in cast(tuple[object, ...], value))
    if type(value) is frozenset:
        return all(_is_immutable_value(child) for child in cast(frozenset[object], value))
    return False


def _validate_external_function_leaf(
    function: FunctionType,
    *,
    seen: set[int],
) -> None:
    identity = id(function)
    if identity in seen:
        return
    seen.add(identity)
    loaded_names = _validate_code(function.__code__)
    resolved_globals = {
        name for name in loaded_names if name in function.__globals__ and name != "__builtins__"
    }
    function_module = function.__module__
    if (
        resolved_globals
        and type(function_module) is str
        and function_module.startswith("ebm_audit.")
    ):
        raise FrozenAnalystDerivationError(
            "A retained calculation wrapper still reads mutable module globals."
        )
    defaults = function.__defaults__ or ()
    keyword_defaults = function.__kwdefaults__ or {}
    if not all(_is_immutable_value(value) for value in defaults) or not all(
        _is_immutable_value(value) for value in keyword_defaults.values()
    ):
        raise FrozenAnalystDerivationError("A retained calculation wrapper has mutable defaults.")
    for cell in function.__closure__ or ():
        _validate_leaf_value(cell.cell_contents, seen=seen)


def _validate_leaf_value(value: object, *, seen: set[int]) -> None:
    if _is_immutable_value(value):
        return
    if isinstance(value, ModuleType):
        raise FrozenAnalystDerivationError(
            "The analyst-decision calculation must not retain a module object."
        )
    if type(value) is FunctionType:
        _validate_external_function_leaf(value, seen=seen)
        return
    if isinstance(value, (BuiltinFunctionType, type)):
        return
    if isinstance(value, Pattern):
        return
    if type(value) is MappingProxyType:
        for key, child in cast(Mapping[object, object], value).items():
            _validate_leaf_value(key, seen=seen)
            _validate_leaf_value(child, seen=seen)
        return
    if is_dataclass(value) and not isinstance(value, type):
        parameters = getattr(type(value), "__dataclass_params__", None)
        if parameters is None or not bool(getattr(parameters, "frozen", False)):
            raise FrozenAnalystDerivationError("A retained calculation object is not immutable.")
        for field in fields(value):
            _validate_leaf_value(getattr(value, field.name), seen=seen)
        return
    if type(value) in _APPROVED_NUMPY_CALLABLE_TYPES or value is Literal:
        return
    if callable(value):
        raise FrozenAnalystDerivationError("An unsupported calculation wrapper was retained.")
    raise FrozenAnalystDerivationError(
        "The analyst-decision calculation retained an unsupported dependency."
    )


def _snapshot_dependency(value: object) -> object:
    if type(value) in _IMMUTABLE_SCALAR_TYPES or value is Ellipsis or value is NotImplemented:
        return value
    if type(value) is tuple:
        return tuple(_snapshot_dependency(child) for child in cast(tuple[object, ...], value))
    if type(value) is frozenset:
        return frozenset(_snapshot_dependency(child) for child in cast(frozenset[object], value))
    if isinstance(value, (bytearray, dict, list, set, ModuleType)):
        raise FrozenAnalystDerivationError(
            "The analyst-decision calculation retained mutable state."
        )
    _validate_leaf_value(value, seen=set())
    return value


def _snapshot_function(
    function: FunctionType,
    *,
    module_name: str,
    source_namespace: dict[str, object],
) -> _FunctionSnapshot:
    if (
        function.__module__ != module_name
        or function.__globals__ is not source_namespace
        or function.__closure__ is not None
    ):
        raise FrozenAnalystDerivationError(
            "Analyst-decision source functions must be exact module-level functions."
        )
    global_names = _validate_code(function.__code__)
    defaults_object = function.__defaults__
    defaults = None if defaults_object is None else tuple(defaults_object)
    keyword_defaults_object = function.__kwdefaults__
    keyword_defaults = (
        None if keyword_defaults_object is None else MappingProxyType(dict(keyword_defaults_object))
    )
    if not all(_is_immutable_value(value) for value in defaults or ()) or not all(
        _is_immutable_value(value) for value in (keyword_defaults or {}).values()
    ):
        raise FrozenAnalystDerivationError(
            "Analyst-decision source functions must use immutable defaults."
        )
    annotations_object = function.__annotations__
    annotations = MappingProxyType(dict(annotations_object))
    if not all(_is_immutable_value(value) for value in annotations.values()):
        raise FrozenAnalystDerivationError(
            "Analyst-decision source annotations must have immutable values."
        )
    return _FunctionSnapshot(
        source=function,
        code=function.__code__,
        defaults_object=defaults_object,
        defaults=defaults,
        keyword_defaults_object=keyword_defaults_object,
        keyword_defaults=keyword_defaults,
        annotations_object=annotations_object,
        annotations=annotations,
        name=function.__name__,
        qualname=function.__qualname__,
        module=function.__module__,
        doc=function.__doc__,
        global_names=global_names,
    )


def _private_record_type(source: type[Any]) -> type[Any]:
    source_fields = fields(source)
    if (
        not is_dataclass(source)
        or not bool(
            getattr(
                getattr(source, "__dataclass_params__", None),
                "frozen",
                False,
            )
        )
        or any(
            field.default is not MISSING or field.default_factory is not MISSING
            for field in source_fields
        )
    ):
        raise FrozenAnalystDerivationError(
            "Analyst-decision record types must be frozen dataclasses without defaults."
        )
    field_names = tuple(field.name for field in source_fields)
    annotations = {field.name: field.type for field in source_fields}

    def populate(namespace: dict[str, object]) -> None:
        namespace.update(
            {
                "__annotations__": annotations,
                "__module__": source.__module__,
            }
        )

    raw_type = types.new_class(
        source.__name__,
        (),
        {"metaclass": _LockedRecordType},
        populate,
    )
    private_type: type[Any] = dataclass(
        init=False,
        frozen=True,
        repr=False,
        slots=True,
    )(raw_type)
    object_setattr = object.__setattr__
    type_op = type
    tuple_op = tuple
    getattr_op = getattr
    hash_op = hash
    len_op = len
    set_op = set
    zip_op = zip
    type_error = TypeError
    frozen_instance_error = FrozenInstanceError
    not_implemented = NotImplemented

    def __init__(self: object, *args: object, **kwargs: object) -> None:
        if len_op(args) > len_op(field_names):
            raise type_error("Too many positional fields for analyst-decision record.")
        supplied = set_op()
        for name, value in zip_op(field_names[: len_op(args)], args, strict=True):
            object_setattr(self, name, value)
            supplied.add(name)
        for name in field_names[len_op(args) :]:
            if name not in kwargs:
                raise type_error("Missing required analyst-decision record field.")
            object_setattr(self, name, kwargs.pop(name))
            supplied.add(name)
        if kwargs:
            raise type_error("Unexpected analyst-decision record field.")
        if len_op(supplied) != len_op(field_names):
            raise type_error("Invalid analyst-decision record fields.")

    def __eq__(self: object, other: object) -> bool | Any:
        if type_op(self) is not type_op(other):
            return not_implemented
        return tuple_op(getattr_op(self, name) for name in field_names) == tuple_op(
            getattr_op(other, name) for name in field_names
        )

    def __hash__(self: object) -> int:
        return hash_op(tuple_op(getattr_op(self, name) for name in field_names))

    def __setattr__(self: object, _name: str, _value: object) -> None:
        raise frozen_instance_error("Cannot assign to a frozen analyst-decision record.")

    def __delattr__(self: object, _name: str) -> None:
        raise frozen_instance_error("Cannot delete from a frozen analyst-decision record.")

    for method_name, method in (
        ("__init__", __init__),
        ("__eq__", __eq__),
        ("__hash__", __hash__),
        ("__setattr__", __setattr__),
        ("__delattr__", __delattr__),
    ):
        method.__name__ = method_name
        method.__qualname__ = f"{source.__qualname__}.{method_name}"
        method.__module__ = source.__module__
        type.__setattr__(private_type, method_name, method)
    type.__setattr__(private_type, "__name__", source.__name__)
    type.__setattr__(private_type, "__qualname__", source.__qualname__)
    type.__setattr__(private_type, "__module__", source.__module__)
    type.__setattr__(private_type, "__match_args__", field_names)
    type.__setattr__(private_type, "_frozen_derivation_locked", True)
    return private_type


def _global_accesses(code: CodeType) -> tuple[_GlobalAccess, ...]:
    accesses: list[_GlobalAccess] = []
    pending = [code]
    while pending:
        current = pending.pop()
        instructions = tuple(dis.get_instructions(current))
        for index, instruction in enumerate(instructions):
            if instruction.opname != "LOAD_GLOBAL" or type(instruction.argval) is not str:
                continue
            attribute_path: list[str] = []
            for following in instructions[index + 1 :]:
                if following.opname not in {"LOAD_ATTR", "LOAD_METHOD"}:
                    break
                if type(following.argval) is not str:
                    break
                attribute_path.append(following.argval)
            accesses.append(
                _GlobalAccess(
                    name=instruction.argval,
                    attribute_path=tuple(attribute_path),
                )
            )
        pending.extend(constant for constant in current.co_consts if isinstance(constant, CodeType))
    return tuple(accesses)


def _static_import_accesses(code: CodeType) -> tuple[_StaticImportAccess, ...]:
    accesses: list[_StaticImportAccess] = []
    pending = [code]
    while pending:
        current = pending.pop()
        instructions = tuple(dis.get_instructions(current))
        for index, instruction in enumerate(instructions):
            if instruction.opname != "IMPORT_NAME" or type(instruction.argval) is not str:
                continue
            imported_names: list[str] = []
            for following in instructions[index + 1 :]:
                if following.opname != "IMPORT_FROM":
                    break
                if type(following.argval) is not str:
                    break
                imported_names.append(following.argval)
            attribute_paths: list[tuple[str, ...]] = []
            if not imported_names:
                store = instructions[index + 1] if index + 1 < len(instructions) else None
                if (
                    store is None
                    or store.opname not in {"STORE_FAST", "STORE_NAME"}
                    or type(store.argval) is not str
                ):
                    raise FrozenAnalystDerivationError(
                        "The dependency guard found unsupported runtime import binding."
                    )
                for load_index, load in enumerate(instructions):
                    if not load.opname.startswith("LOAD_FAST") or load.argval != store.argval:
                        continue
                    path: list[str] = []
                    for following in instructions[load_index + 1 :]:
                        if following.opname not in {"LOAD_ATTR", "LOAD_METHOD"}:
                            break
                        if type(following.argval) is not str:
                            break
                        path.append(following.argval)
                    if not path:
                        raise FrozenAnalystDerivationError(
                            "The dependency guard found dynamic runtime import use."
                        )
                    attribute_paths.append(tuple(path))
            accesses.append(
                _StaticImportAccess(
                    module_name=instruction.argval,
                    imported_names=tuple(imported_names),
                    attribute_paths=tuple(attribute_paths),
                )
            )
        pending.extend(constant for constant in current.co_consts if isinstance(constant, CodeType))
    return tuple(accesses)


def _identity_sequence_check(
    value: list[object] | tuple[object, ...],
    expected: tuple[object, ...],
) -> Callable[[], bool]:
    def check() -> bool:
        return len(value) == len(expected) and all(
            observed is retained for observed, retained in zip(value, expected, strict=True)
        )

    return check


def _identity_mapping_check(
    value: Mapping[object, object],
    expected: tuple[tuple[object, object], ...],
) -> Callable[[], bool]:
    def check() -> bool:
        observed = tuple(value.items())
        return len(observed) == len(expected) and all(
            observed_key is expected_key and observed_value is expected_value
            for (observed_key, observed_value), (expected_key, expected_value) in zip(
                observed,
                expected,
                strict=True,
            )
        )

    return check


def _identity_set_check(
    value: set[object],
    expected: tuple[object, ...],
) -> Callable[[], bool]:
    def check() -> bool:
        return len(value) == len(expected) and all(
            any(observed is retained for observed in value) for retained in expected
        )

    return check


def _dict_slot_check(
    namespace: dict[str, object],
    name: str,
    expected: object,
) -> Callable[[], bool]:
    def check() -> bool:
        return namespace.get(name, _MISSING) is expected

    return check


def _mapping_slot_check(
    namespace: Mapping[str, object],
    name: str,
    expected: object,
) -> Callable[[], bool]:
    def check() -> bool:
        return namespace.get(name, _MISSING) is expected

    return check


def _function_state_check(
    function: FunctionType,
    *,
    code: CodeType,
    globals_namespace: dict[str, object],
    defaults: tuple[object, ...] | None,
    keyword_defaults: dict[str, object] | None,
    closure: tuple[CellType, ...] | None,
) -> Callable[[], bool]:
    def check() -> bool:
        return (
            function.__code__ is code
            and function.__globals__ is globals_namespace
            and function.__defaults__ is defaults
            and function.__kwdefaults__ is keyword_defaults
            and function.__closure__ is closure
        )

    return check


def _cell_contents(cell: CellType) -> object:
    try:
        return cell.cell_contents
    except ValueError:
        return _MISSING


def _cell_check(cell: CellType, expected: object) -> Callable[[], bool]:
    def check() -> bool:
        return _cell_contents(cell) is expected

    return check


def _instance_dictionary(value: object) -> dict[object, object] | None:
    try:
        namespace = object.__getattribute__(value, "__dict__")
    except AttributeError:
        return None
    if type(namespace) is not dict:
        return None
    return cast(dict[object, object], namespace)


def _instance_dictionary_check(
    value: object,
    expected: dict[object, object],
) -> Callable[[], bool]:
    def check() -> bool:
        return _instance_dictionary(value) is expected

    return check


def _instance_slot_check(
    value: object,
    name: str,
    expected: object,
) -> Callable[[], bool]:
    def check() -> bool:
        try:
            observed = object.__getattribute__(value, name)
        except AttributeError:
            observed = _MISSING
        return observed is expected

    return check


def _instance_type_check(
    value: object,
    expected: type[Any],
) -> Callable[[], bool]:
    def check() -> bool:
        return type(value) is expected

    return check


def _type_mro_check(
    value: type[Any],
    expected: tuple[type[Any], ...],
) -> Callable[[], bool]:
    def check() -> bool:
        observed = type.__getattribute__(value, "__mro__")
        return len(observed) == len(expected) and all(
            current is retained for current, retained in zip(observed, expected, strict=True)
        )

    return check


def _type_namespace(value: type[Any]) -> Mapping[str, object]:
    return cast(Mapping[str, object], type.__getattribute__(value, "__dict__"))


def _stable_type_namespace_items(
    value: type[Any],
) -> tuple[tuple[object, object], ...]:
    # Python 3.14 materialises these two interpreter-owned annotation cache
    # entries on first annotation access.  They are bookkeeping, not executable
    # class definitions.  Any annotation mapping actually reached by a guarded
    # calculation is retained separately through that attribute access.
    return tuple(
        (name, retained)
        for name, retained in _type_namespace(value).items()
        if name not in _LAZY_ANNOTATION_NAMESPACE_KEYS
    )


def _type_namespace_check(
    value: type[Any],
    expected: tuple[tuple[object, object], ...],
) -> Callable[[], bool]:
    def check() -> bool:
        observed = _stable_type_namespace_items(value)
        return len(observed) == len(expected) and all(
            observed_key is expected_key and observed_value is expected_value
            for (observed_key, observed_value), (expected_key, expected_value) in zip(
                observed,
                expected,
                strict=True,
            )
        )

    return check


class _DependencyManifestBuilder:
    """Build identity-only checks without invoking dependency-defined hooks."""

    def __init__(self) -> None:
        self._checks: list[Callable[[], bool]] = []
        self._seen: set[int] = set()
        self._module_slots: set[tuple[int, str]] = set()

    def build(self, roots: tuple[object, ...]) -> Callable[[], None]:
        self._visit_sequence(roots)
        checks = tuple(self._checks)

        def assert_dependencies_current() -> None:
            try:
                current = all(check() for check in checks)
            except Exception:
                current = False
            if not current:
                raise FrozenAnalystDerivationError("A frozen calculation dependency changed.")

        return assert_dependencies_current

    def _visit(self, value: object) -> None:
        identity = id(value)
        if identity in self._seen:
            return
        self._seen.add(identity)

        if type(value) is FunctionType:
            self._visit_function(value)
            return
        if type(value) is _NUMPY_ARRAY_FUNCTION_DISPATCHER_TYPE:
            self._visit_numpy_dispatcher(value)
            return
        if type(value) is _LRU_CACHE_WRAPPER_TYPE:
            self._visit_lru_cache_wrapper(value)
            return
        if type(value) is MethodType:
            method = value
            self._visit(method.__func__)
            self._visit(method.__self__)
            return
        if type(value) is ModuleType:
            raise FrozenAnalystDerivationError(
                "The dependency guard cannot retain a module dynamically."
            )
        if isinstance(value, type):
            self._visit_type(cast(type[Any], value))
            return
        if type(value) is tuple:
            self._visit_sequence(cast(tuple[object, ...], value))
            return
        if type(value) is list:
            self._visit_sequence(cast(list[object], value))
            return
        if type(value) is dict:
            self._visit_mapping(cast(dict[object, object], value))
            return
        if type(value) is MappingProxyType:
            self._visit_mapping(cast(Mapping[object, object], value))
            return
        if type(value) is frozenset:
            for child in cast(frozenset[object], value):
                self._visit(child)
            return
        if type(value) is set:
            expected = tuple(cast(set[object], value))
            self._checks.append(_identity_set_check(cast(set[object], value), expected))
            for child in expected:
                self._visit(child)
            return
        if type(value) in {classmethod, staticmethod, property}:
            return
        if type(value) in _IMMUTABLE_SCALAR_TYPES or value is Ellipsis or value is NotImplemented:
            return
        if isinstance(value, (BuiltinFunctionType, CodeType, Pattern, np.ufunc)):
            return
        if callable(value):
            if (
                type(value) in {_JSON_SCANNER_TYPE, _OPERATOR_METHODCALLER_TYPE}
                or type(value) in _APPROVED_TYPING_SENTINEL_TYPES
            ):
                return
            raise FrozenAnalystDerivationError(
                "The dependency guard found an unsupported callable object."
            )

        namespace = _instance_dictionary(value)
        if namespace is not None:
            self._checks.append(_instance_dictionary_check(value, namespace))
            self._visit_mapping(namespace)
            self._visit_type(type(value))
            self._visit_slots(value)
            return
        self._visit_type(type(value))
        self._visit_slots(value)
        # Opaque extension values (for example NumPy dtypes) are identity leaves.

    def _visit_sequence(self, value: list[object] | tuple[object, ...]) -> None:
        expected = tuple(value)
        self._checks.append(_identity_sequence_check(value, expected))
        for child in expected:
            self._visit(child)

    def _visit_mapping(self, value: Mapping[object, object]) -> None:
        if any(value is cache for cache in _RE_RUNTIME_CACHES):
            # ``re`` changes these process-wide caches during ordinary imports.
            # The owning module slot and every executable regex dependency stay
            # identity-locked; cache contents are not program definitions.
            return
        expected = tuple(value.items())
        self._checks.append(_identity_mapping_check(value, expected))
        for key, child in expected:
            self._visit(key)
            self._visit(child)

    def _visit_type(self, value: type[Any]) -> None:
        for class_type in type.__getattribute__(value, "__mro__"):
            expected = _stable_type_namespace_items(class_type)
            self._checks.append(_type_namespace_check(class_type, expected))

    def _visit_slots(self, value: object) -> None:
        for class_type in type(value).__mro__:
            namespace = _type_namespace(class_type)
            for name, descriptor in namespace.items():
                if type(descriptor) is not MemberDescriptorType:
                    continue
                try:
                    retained = object.__getattribute__(value, name)
                except AttributeError:
                    retained = _MISSING
                self._checks.append(_instance_slot_check(value, name, retained))
                if retained is not _MISSING:
                    self._visit(retained)

    def _visit_function(
        self,
        function: FunctionType,
    ) -> None:
        code = function.__code__
        globals_namespace = function.__globals__
        defaults = function.__defaults__
        keyword_defaults = function.__kwdefaults__
        closure = function.__closure__
        self._checks.append(
            _function_state_check(
                function,
                code=code,
                globals_namespace=globals_namespace,
                defaults=defaults,
                keyword_defaults=keyword_defaults,
                closure=closure,
            )
        )
        # ``re._compiler.compile`` names this diagnostic-only function even
        # when no DEBUG flag is admitted. Its exact slot, function, and code
        # identities are already attested; its printing implementation is not
        # part of any authoritative calculation path.
        if function is _RE_COMPILER_DIS:
            return
        self._validate_dependency_code(function)
        if defaults is not None:
            self._visit_sequence(defaults)
        if keyword_defaults is not None:
            self._visit_mapping(cast(dict[object, object], keyword_defaults))
        if closure is not None:
            for cell in closure:
                retained = _cell_contents(cell)
                self._checks.append(_cell_check(cell, retained))
                if retained is not _MISSING:
                    self._visit(retained)
        for access in _global_accesses(code):
            self._visit_global(function, access)

    def _validate_dependency_code(
        self,
        function: FunctionType,
    ) -> None:
        instructions = _instructions(function.__code__)
        loaded_names = {
            instruction.argval
            for instruction in instructions
            if instruction.opname == "LOAD_GLOBAL" and type(instruction.argval) is str
        }
        if loaded_names & _FORBIDDEN_DYNAMIC_GLOBAL_NAMES:
            raise FrozenAnalystDerivationError("The dependency guard found dynamic global access.")
        forbidden = {
            instruction.opname
            for instruction in instructions
            if instruction.opname in _FORBIDDEN_INSTRUCTIONS
            and instruction.opname not in {"IMPORT_FROM", "IMPORT_NAME"}
        }
        if forbidden:
            raise FrozenAnalystDerivationError(
                "The dependency guard found dynamic name resolution."
            )
        import_accesses = _static_import_accesses(function.__code__)
        if not import_accesses:
            return
        for access in import_accesses:
            self._visit_static_import(function, access)

    def _visit_static_import(
        self,
        function: FunctionType,
        access: _StaticImportAccess,
    ) -> None:
        module = sys.modules.get(access.module_name)
        if type(module) is not ModuleType:
            raise FrozenAnalystDerivationError(
                "The dependency guard found an unloaded runtime import target."
            )
        retained_module = module
        self._checks.append(
            _dict_slot_check(
                cast(dict[str, object], sys.modules),
                access.module_name,
                retained_module,
            )
        )
        builtins_value = function.__globals__.get("__builtins__", builtins)
        if type(builtins_value) is ModuleType:
            builtins_dictionary = vars(builtins_value)
            import_leaf = builtins_dictionary.get("__import__", _MISSING)
            if import_leaf is _MISSING:
                raise FrozenAnalystDerivationError(
                    "The dependency guard found no runtime import operation."
                )
            self._checks.append(_dict_slot_check(builtins_dictionary, "__import__", import_leaf))
        elif type(builtins_value) in {dict, MappingProxyType}:
            builtins_mapping = cast(Mapping[str, object], builtins_value)
            import_leaf = builtins_mapping.get("__import__", _MISSING)
            if import_leaf is _MISSING:
                raise FrozenAnalystDerivationError(
                    "The dependency guard found no runtime import operation."
                )
            self._checks.append(_mapping_slot_check(builtins_mapping, "__import__", import_leaf))
        else:
            raise FrozenAnalystDerivationError(
                "The dependency guard found an unsupported builtins namespace."
            )
        module_namespace = vars(retained_module)
        for name in access.imported_names:
            retained = module_namespace.get(name, _MISSING)
            if retained is _MISSING:
                raise FrozenAnalystDerivationError(
                    "The dependency guard found an unresolved runtime import name."
                )
            self._checks.append(_dict_slot_check(module_namespace, name, retained))
            self._visit(retained)
        if access.attribute_paths:
            top_level_name = access.module_name.partition(".")[0]
            top_level_module = sys.modules.get(top_level_name)
            if type(top_level_module) is not ModuleType:
                raise FrozenAnalystDerivationError(
                    "The dependency guard found an unloaded runtime import binding."
                )
            self._checks.append(
                _dict_slot_check(
                    cast(dict[str, object], sys.modules),
                    top_level_name,
                    top_level_module,
                )
            )
            for path in access.attribute_paths:
                self._visit_static_module_access(top_level_module, path)

    def _visit_global(self, function: FunctionType, access: _GlobalAccess) -> None:
        globals_namespace = function.__globals__
        if access.name in globals_namespace:
            retained = globals_namespace[access.name]
            self._checks.append(_dict_slot_check(globals_namespace, access.name, retained))
        else:
            retained = self._resolve_builtin(function, access.name)
            self._checks.append(
                self._global_remains_unshadowed_check(
                    globals_namespace,
                    access.name,
                )
            )
        if type(retained) is ModuleType:
            self._visit_static_module_access(retained, access.attribute_path)
        else:
            self._visit(retained)

    def _resolve_builtin(self, function: FunctionType, name: str) -> object:
        globals_namespace = function.__globals__
        builtins_value = globals_namespace.get("__builtins__", builtins)
        if type(builtins_value) is ModuleType:
            dictionary = vars(builtins_value)
            retained = dictionary.get(name, _MISSING)
            if retained is _MISSING:
                raise FrozenAnalystDerivationError(
                    "The dependency guard found an unresolved global."
                )
            self._checks.append(_dict_slot_check(dictionary, name, retained))
            return retained
        if type(builtins_value) in {dict, MappingProxyType}:
            mapping = cast(Mapping[str, object], builtins_value)
            retained = mapping.get(name, _MISSING)
            if retained is _MISSING:
                raise FrozenAnalystDerivationError(
                    "The dependency guard found an unresolved global."
                )
            self._checks.append(_mapping_slot_check(mapping, name, retained))
            return retained
        raise FrozenAnalystDerivationError(
            "The dependency guard found an unsupported builtins namespace."
        )

    @staticmethod
    def _global_remains_unshadowed_check(
        namespace: dict[str, object],
        name: str,
    ) -> Callable[[], bool]:
        def check() -> bool:
            return name not in namespace

        return check

    def _visit_static_module_access(
        self,
        module: ModuleType,
        attribute_path: tuple[str, ...],
    ) -> None:
        if not attribute_path:
            raise FrozenAnalystDerivationError("The dependency guard found dynamic module access.")
        current: object = module
        for attribute in attribute_path:
            if type(current) is not ModuleType:
                break
            namespace = vars(current)
            slot = (id(current), attribute)
            retained = namespace.get(attribute, _MISSING)
            if retained is _MISSING:
                raise FrozenAnalystDerivationError(
                    "The dependency guard found an unresolved module attribute."
                )
            if slot not in self._module_slots:
                self._module_slots.add(slot)
                self._checks.append(_dict_slot_check(namespace, attribute, retained))
            current = retained
        if type(current) is ModuleType:
            raise FrozenAnalystDerivationError(
                "The dependency guard found incomplete static module access."
            )
        self._visit(current)

    def _visit_numpy_dispatcher(self, value: object) -> None:
        implementation = object.__getattribute__(value, "_implementation")
        wrapped = object.__getattribute__(value, "__wrapped__")

        def check() -> bool:
            return (
                object.__getattribute__(value, "_implementation") is implementation
                and object.__getattribute__(value, "__wrapped__") is wrapped
            )

        self._checks.append(check)
        self._visit(implementation)
        self._visit(wrapped)

    def _visit_lru_cache_wrapper(self, value: object) -> None:
        wrapped = object.__getattribute__(value, "__wrapped__")
        cache_parameters = object.__getattribute__(value, "cache_parameters")
        expected_parameters = cache_parameters()
        if type(expected_parameters) is not dict or set(expected_parameters) != {
            "maxsize",
            "typed",
        }:
            raise FrozenAnalystDerivationError(
                "The dependency guard found unsupported cache configuration."
            )
        expected_maxsize = expected_parameters["maxsize"]
        expected_typed = expected_parameters["typed"]
        if (expected_maxsize is not None and type(expected_maxsize) is not int) or type(
            expected_typed
        ) is not bool:
            raise FrozenAnalystDerivationError(
                "The dependency guard found unsupported cache configuration."
            )

        def check() -> bool:
            try:
                current = cache_parameters()
            except Exception:
                return False
            return (
                object.__getattribute__(value, "__wrapped__") is wrapped
                and type(current) is dict
                and current.get("maxsize") == expected_maxsize
                and current.get("typed") is expected_typed
                and len(current) == 2
            )

        self._checks.append(check)
        self._visit(wrapped)


def build_frozen_dependency_guard(
    roots: tuple[object, ...],
) -> Callable[[], None]:
    """Attest code and immutable state reachable from ``roots``."""

    return _DependencyManifestBuilder().build(roots)


def _guard_dependency_root(
    function: FunctionType,
    assert_dependencies_current: Callable[[], None],
) -> FunctionType:
    def guarded(*args: object, **kwargs: object) -> object:
        assert_dependencies_current()
        try:
            return function(*args, **kwargs)
        finally:
            assert_dependencies_current()

    guarded.__name__ = function.__name__
    guarded.__qualname__ = function.__qualname__
    guarded.__module__ = function.__module__
    guarded.__doc__ = function.__doc__
    guarded.__annotations__ = dict(function.__annotations__)
    return cast(FunctionType, guarded)


def build_frozen_derivation_graph(
    source_namespace: dict[str, object],
    *,
    module_name: str,
    root_names: tuple[str, ...],
    record_type_names: tuple[str, ...],
    additional_dependency_roots: tuple[object, ...] = (),
) -> FrozenDerivationGraph:
    """Snapshot, recreate, and transitively attest one calculation graph."""

    if source_namespace.get("__name__") != module_name:
        raise FrozenAnalystDerivationError(
            "Analyst-decision derivation source identity is invalid."
        )
    initial_namespace = dict(source_namespace)
    source_record_types: dict[str, type[Any]] = {}
    for name in record_type_names:
        value = initial_namespace.get(name, _MISSING)
        if not isinstance(value, type):
            raise FrozenAnalystDerivationError("Analyst-decision record source is missing.")
        source_record_types[name] = cast(type[Any], value)

    root_sources: dict[str, FunctionType] = {}
    snapshots: dict[FunctionType, _FunctionSnapshot] = {}
    pending: list[FunctionType] = []
    for name in root_names:
        value = initial_namespace.get(name, _MISSING)
        if type(value) is not FunctionType:
            raise FrozenAnalystDerivationError("Analyst-decision derivation root is missing.")
        root_sources[name] = value
        pending.append(value)

    used_namespace_values: dict[str, object] = {}
    while pending:
        function = pending.pop()
        if function in snapshots:
            continue
        snapshot = _snapshot_function(
            function,
            module_name=module_name,
            source_namespace=source_namespace,
        )
        snapshots[function] = snapshot
        for name in snapshot.global_names:
            if name in initial_namespace:
                dependency = initial_namespace[name]
                used_namespace_values.setdefault(name, dependency)
                if type(dependency) is FunctionType and dependency.__module__ == module_name:
                    pending.append(dependency)
                    continue
                if isinstance(dependency, type) and dependency in source_record_types.values():
                    continue
                _snapshot_dependency(dependency)
            elif name not in vars(builtins):
                raise FrozenAnalystDerivationError(
                    "Analyst-decision calculation has an unresolved global name."
                )

    private_record_types = {
        name: _private_record_type(source) for name, source in source_record_types.items()
    }
    private_builtins = MappingProxyType(
        {
            name: value
            for name, value in vars(builtins).items()
            if any(name in snapshot.global_names for snapshot in snapshots.values())
        }
    )
    private_globals: dict[str, object] = {
        "__builtins__": private_builtins,
        "__name__": module_name,
        "__package__": module_name.rpartition(".")[0],
    }
    clones: dict[FunctionType, FunctionType] = {}
    for source, snapshot in snapshots.items():
        clone = FunctionType(
            snapshot.code,
            private_globals,
            snapshot.name,
            snapshot.defaults,
        )
        clone.__kwdefaults__ = (
            None if snapshot.keyword_defaults is None else dict(snapshot.keyword_defaults)
        )
        clone.__annotations__ = dict(snapshot.annotations)
        clone.__qualname__ = snapshot.qualname
        clone.__module__ = snapshot.module
        clone.__doc__ = snapshot.doc
        clones[source] = clone

    source_type_to_private = {
        source_record_types[name]: private_record_types[name] for name in record_type_names
    }
    for name, dependency in used_namespace_values.items():
        if type(dependency) is FunctionType and dependency in clones:
            private_globals[name] = clones[dependency]
        elif isinstance(dependency, type) and dependency in source_type_to_private:
            private_globals[name] = source_type_to_private[dependency]
        else:
            private_globals[name] = _snapshot_dependency(dependency)

    for source, snapshot in snapshots.items():
        if (
            source.__code__ is not snapshot.code
            or source.__defaults__ is not snapshot.defaults_object
            or source.__kwdefaults__ is not snapshot.keyword_defaults_object
            or source.__annotations__ is not snapshot.annotations_object
            or (
                source.__kwdefaults__ is not None
                and dict(source.__kwdefaults__) != dict(snapshot.keyword_defaults or {})
            )
            or dict(source.__annotations__) != dict(snapshot.annotations)
        ):
            raise FrozenAnalystDerivationError(
                "Analyst-decision source changed while its calculation was locked."
            )
    for name, dependency in used_namespace_values.items():
        if source_namespace.get(name, _MISSING) is not dependency:
            raise FrozenAnalystDerivationError(
                "Analyst-decision dependency changed while its calculation was locked."
            )
    for name, source in root_sources.items():
        if source_namespace.get(name, _MISSING) is not source:
            raise FrozenAnalystDerivationError(
                "Analyst-decision root changed while its calculation was locked."
            )
    for name, source_type in source_record_types.items():
        if source_namespace.get(name, _MISSING) is not source_type:
            raise FrozenAnalystDerivationError(
                "Analyst-decision record type changed while its calculation was locked."
            )

    functions_by_name = {snapshot.name: clones[source] for source, snapshot in snapshots.items()}
    frozen_roots = tuple(functions_by_name[name] for name in root_names)
    assert_dependencies_current = build_frozen_dependency_guard(
        (
            *frozen_roots,
            *additional_dependency_roots,
        )
    )
    for root_name, frozen_root in zip(root_names, frozen_roots, strict=True):
        functions_by_name[root_name] = _guard_dependency_root(
            frozen_root,
            assert_dependencies_current,
        )
    functions = MappingProxyType(functions_by_name)
    record_types = MappingProxyType(private_record_types)
    return FrozenDerivationGraph(
        rule_id=FROZEN_DERIVATION_GRAPH_RULE_ID,
        functions=functions,
        record_types=record_types,
        assert_dependencies_current=assert_dependencies_current,
    )


def build_frozen_analyst_derivation(
    source_namespace: dict[str, object],
    *,
    module_name: str,
    root_names: tuple[str, ...],
    record_type_names: tuple[str, ...],
    additional_dependency_roots: tuple[object, ...] = (),
) -> FrozenAnalystDerivation:
    """Build the analyst calculation with its stable typed interface."""

    graph = build_frozen_derivation_graph(
        source_namespace,
        module_name=module_name,
        root_names=root_names,
        record_type_names=record_type_names,
        additional_dependency_roots=additional_dependency_roots,
    )
    functions = graph.functions
    record_types = graph.record_types
    guarded_derive = functions["_derive_analyst_decision_evidence"]
    guarded_validate = functions["_validate_analyst_decision_semantics"]
    return FrozenAnalystDerivation(
        rule_id=FROZEN_ANALYST_DERIVATION_RULE_ID,
        functions=functions,
        record_types=record_types,
        derive_analyst_decision_evidence=guarded_derive,
        validate_analyst_decision_semantics=guarded_validate,
        canonical_origin_attempt_type=record_types["_CanonicalOriginComparisonAttempt"],
        canonical_numeric_comparison_type=record_types["_CanonicalOriginNumericComparisonRecord"],
        canonical_analyst_aggregate_type=record_types["_CanonicalAnalystDecisionAggregate"],
        canonical_analyst_layer_type=record_types["_CanonicalAnalystDecisionLayerEvidence"],
        canonical_analyst_bundle_type=record_types["_CanonicalAnalystDecisionEvidenceBundle"],
        analyst_origin_input_type=record_types["_AnalystDecisionOriginInput"],
        analyst_candidate_input_type=record_types["_AnalystDecisionCandidateInput"],
        assert_dependencies_current=graph.assert_dependencies_current,
    )


__all__ = [
    "FROZEN_ANALYST_DERIVATION_RULE_ID",
    "FROZEN_DERIVATION_GRAPH_RULE_ID",
    "FrozenAnalystDerivation",
    "FrozenAnalystDerivationError",
    "FrozenDerivationGraph",
    "build_frozen_derivation_graph",
]
