"""Strict JSON parsing, RFC 8785 bytes, and SHA-256 primitives."""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, TypeGuard, cast

import rfc8785

from .errors import CanonicalizationError

MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_JSON_DEPTH = 128
_MAX_JSON_NODES = 1_000_000

type _ObjectPairsHook = Callable[[list[tuple[str, Any]]], dict[str, Any]]
type _ParseConstant = Callable[[str], Any]


class _HexDigest(Protocol):
    def hexdigest(self) -> str: ...


class _Sha256(Protocol):
    def __call__(self, data: bytes, /) -> _HexDigest: ...


class _JsonLoads(Protocol):
    def __call__(
        self,
        data: str,
        *,
        object_pairs_hook: _ObjectPairsHook,
        parse_constant: _ParseConstant,
    ) -> Any: ...


class _BytesLeaf(Protocol):
    def __call__(self, value: bytes | bytearray | memoryview, /) -> bytes: ...


class _IsInstanceLeaf(Protocol):
    def __call__[T](self, value: object, class_info: type[T], /) -> TypeGuard[T]: ...


class _StableFunctionMetadata(Protocol):
    __module__: str
    __name__: str
    __qualname__: str


class _ValidateJsonValue(_StableFunctionMetadata, Protocol):
    def __call__(
        self,
        value: object,
        *,
        depth: int = 0,
        seen: set[int] | None = None,
        counter: list[int] | None = None,
    ) -> None: ...


class _StrictJsonLoadsOperation(_StableFunctionMetadata, Protocol):
    def __call__(self, data: bytes | bytearray | memoryview) -> Any: ...


class _CanonicalJsonBytesOperation(_StableFunctionMetadata, Protocol):
    def __call__(self, value: object) -> bytes: ...


class _StructuredSha256Operation(_StableFunctionMetadata, Protocol):
    def __call__(self, domain: str, value: object) -> str: ...


class _DomainSeparatedBytesSha256Operation(_StableFunctionMetadata, Protocol):
    def __call__(
        self,
        domain: str,
        data: bytes | bytearray | memoryview,
    ) -> str: ...


class _ExactFileSha256Operation(_StableFunctionMetadata, Protocol):
    def __call__(self, data: bytes | bytearray | memoryview) -> str: ...


type _CanonicalDumps = Callable[[object], bytes]
type _ValidateString = Callable[[str], None]
type _ValidateDomain = Callable[[str], bytes]


@dataclass(frozen=True, slots=True)
class _CanonicalOperations:
    """The exact callable graph authorized at module import time."""

    reject_duplicate_object_keys: _ObjectPairsHook
    reject_non_json_constant: _ParseConstant
    validate_string: _ValidateString
    validate_json_value: _ValidateJsonValue
    strict_json_loads: _StrictJsonLoadsOperation
    canonical_json_bytes: _CanonicalJsonBytesOperation
    validate_domain: _ValidateDomain
    structured_sha256: _StructuredSha256Operation
    structured_sha256_hex: _StructuredSha256Operation
    domain_separated_bytes_sha256: _DomainSeparatedBytesSha256Operation
    exact_file_sha256: _ExactFileSha256Operation


def _make_canonical_operations(
    *,
    sha256_leaf: _Sha256,
    json_loads_leaf: _JsonLoads,
    json_decode_error_type: type[Exception],
    isfinite_leaf: Callable[[float], bool],
    is_normalized_leaf: Callable[[str, str], bool],
    canonical_dumps_leaf: _CanonicalDumps,
    rfc8785_error_type: type[Exception],
    mapping_type: type[Mapping[Any, Any]],
    error_type: type[CanonicalizationError],
    abs_leaf: Callable[[int], int],
    any_leaf: Callable[[Iterable[bool]], bool],
    bool_type: type[bool],
    bytes_leaf: _BytesLeaf,
    float_type: type[float],
    id_leaf: Callable[[object], int],
    int_type: type[int],
    isinstance_leaf: _IsInstanceLeaf,
    list_type: type[list[Any]],
    ord_leaf: Callable[[str], int],
    recursion_error_type: type[Exception],
    set_leaf: Callable[[], set[int]],
    str_type: type[str],
    type_error_type: type[Exception],
    unicode_decode_error_type: type[Exception],
    unicode_encode_error_type: type[Exception],
    value_error_type: type[Exception],
    max_safe_integer: int,
    max_json_depth: int,
    max_json_nodes: int,
) -> _CanonicalOperations:
    """Build one explicit closure graph from immutable external leaf bindings.

    Rebinding names in this project module cannot affect the returned
    operations.  Callers that require same-process calculation integrity must
    additionally attest the transitive Python dependencies owned by the exact
    external ``json.loads`` and ``rfc8785.dumps`` leaves; the scientific
    evidence boundary does so before and after authoritative derivation.
    """

    def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise error_type("JSON object contains a duplicate key.")
            result[key] = value
        return result

    def _reject_non_json_constant(_value: str) -> Any:
        raise error_type("JSON contains a non-finite numeric constant.")

    def _validate_string(value: str) -> None:
        if not is_normalized_leaf("NFC", value):
            raise error_type("JSON strings and object keys must already be NFC.")
        if any_leaf(0xD800 <= ord_leaf(character) <= 0xDFFF for character in value):
            raise error_type("JSON strings must not contain surrogate code points.")

    def _validate_json_value(
        value: object,
        *,
        depth: int = 0,
        seen: set[int] | None = None,
        counter: list[int] | None = None,
    ) -> None:
        if depth > max_json_depth:
            raise error_type("JSON nesting exceeds the supported bound.")
        if seen is None:
            seen = set_leaf()
        if counter is None:
            counter = [0]
        counter[0] += 1
        if counter[0] > max_json_nodes:
            raise error_type("JSON value exceeds the supported node bound.")

        if value is None or isinstance_leaf(value, bool_type):
            return
        if isinstance_leaf(value, str_type):
            _validate_string(value)
            return
        if isinstance_leaf(value, int_type):
            if abs_leaf(value) > max_safe_integer:
                raise error_type("JSON integer is outside the interoperable safe range.")
            return
        if isinstance_leaf(value, float_type):
            if not isfinite_leaf(value):
                raise error_type("JSON numbers must be finite.")
            return
        if isinstance_leaf(value, list_type):
            identity = id_leaf(value)
            if identity in seen:
                raise error_type("Cyclic containers are not valid JSON.")
            seen.add(identity)
            try:
                for item in value:
                    _validate_json_value(
                        item,
                        depth=depth + 1,
                        seen=seen,
                        counter=counter,
                    )
            finally:
                seen.remove(identity)
            return
        if isinstance_leaf(value, mapping_type):
            identity = id_leaf(value)
            if identity in seen:
                raise error_type("Cyclic containers are not valid JSON.")
            seen.add(identity)
            try:
                for key, item in value.items():
                    if not isinstance_leaf(key, str_type):
                        raise error_type("JSON object keys must be strings.")
                    _validate_string(key)
                    _validate_json_value(
                        item,
                        depth=depth + 1,
                        seen=seen,
                        counter=counter,
                    )
            finally:
                seen.remove(identity)
            return
        raise error_type("Value is outside the JSON data model.")

    def strict_json_loads(data: bytes | bytearray | memoryview) -> Any:
        """Parse UTF-8 JSON with duplicate, finite-number, NFC, and range checks."""

        raw = bytes_leaf(data)
        if raw.startswith(b"\xef\xbb\xbf"):
            raise error_type("JSON must not contain a byte-order mark.")
        try:
            text = raw.decode("utf-8", errors="strict")
            value = json_loads_leaf(
                text,
                object_pairs_hook=_reject_duplicate_object_keys,
                parse_constant=_reject_non_json_constant,
            )
        except error_type:
            raise
        except (
            unicode_decode_error_type,
            json_decode_error_type,
            recursion_error_type,
        ) as exc:
            raise error_type("Input is not valid strict UTF-8 JSON.") from exc
        _validate_json_value(value)
        return value

    def canonical_json_bytes(value: object) -> bytes:
        """Return RFC 8785 JCS bytes after the project's strict JSON checks."""

        _validate_json_value(value)
        try:
            return canonical_dumps_leaf(value)
        except (rfc8785_error_type, type_error_type, value_error_type) as exc:
            raise error_type("Value cannot be represented as RFC 8785 JSON.") from exc

    def _validate_domain(domain: str) -> bytes:
        if not domain or "\x00" in domain:
            raise error_type("Digest domain must be non-empty ASCII without NUL.")
        try:
            return domain.encode("ascii", errors="strict")
        except unicode_encode_error_type as exc:
            raise error_type("Digest domain must be ASCII.") from exc

    def structured_sha256(domain: str, value: object) -> str:
        """Return ``Sha256Digest`` for ``ASCII(domain) || NUL || JCS(value)``."""

        digest = sha256_leaf(_validate_domain(domain) + b"\x00" + canonical_json_bytes(value))
        return f"sha256:{digest.hexdigest()}"

    def structured_sha256_hex(domain: str, value: object) -> str:
        """Return raw ``Sha256Hex`` for a registered evaluator field only."""

        digest = sha256_leaf(_validate_domain(domain) + b"\x00" + canonical_json_bytes(value))
        return digest.hexdigest()

    def domain_separated_bytes_sha256(
        domain: str,
        data: bytes | bytearray | memoryview,
    ) -> str:
        """Hash exact bytes under a registered non-structured domain."""

        digest = sha256_leaf(_validate_domain(domain) + b"\x00" + bytes_leaf(data))
        return f"sha256:{digest.hexdigest()}"

    def exact_file_sha256(data: bytes | bytearray | memoryview) -> str:
        """Return the prefixed SHA-256 of exact file bytes, without a domain."""

        return f"sha256:{sha256_leaf(bytes_leaf(data)).hexdigest()}"

    return _CanonicalOperations(
        reject_duplicate_object_keys=_reject_duplicate_object_keys,
        reject_non_json_constant=_reject_non_json_constant,
        validate_string=_validate_string,
        validate_json_value=_validate_json_value,
        strict_json_loads=strict_json_loads,
        canonical_json_bytes=canonical_json_bytes,
        validate_domain=_validate_domain,
        structured_sha256=structured_sha256,
        structured_sha256_hex=structured_sha256_hex,
        domain_separated_bytes_sha256=domain_separated_bytes_sha256,
        exact_file_sha256=exact_file_sha256,
    )


_CANONICAL_OPERATIONS = _make_canonical_operations(
    sha256_leaf=cast(_Sha256, hashlib.sha256),
    json_loads_leaf=cast(_JsonLoads, json.loads),
    json_decode_error_type=json.JSONDecodeError,
    isfinite_leaf=math.isfinite,
    is_normalized_leaf=cast(Callable[[str, str], bool], unicodedata.is_normalized),
    canonical_dumps_leaf=cast(_CanonicalDumps, rfc8785.dumps),
    rfc8785_error_type=rfc8785.CanonicalizationError,
    mapping_type=cast(Any, Mapping),
    error_type=CanonicalizationError,
    abs_leaf=cast(Callable[[int], int], abs),
    any_leaf=cast(Callable[[Iterable[bool]], bool], any),
    bool_type=bool,
    bytes_leaf=cast(_BytesLeaf, bytes),
    float_type=float,
    id_leaf=id,
    int_type=int,
    isinstance_leaf=cast(_IsInstanceLeaf, isinstance),
    list_type=list,
    ord_leaf=ord,
    recursion_error_type=RecursionError,
    set_leaf=cast(Callable[[], set[int]], set),
    str_type=str,
    type_error_type=TypeError,
    unicode_decode_error_type=UnicodeDecodeError,
    unicode_encode_error_type=UnicodeEncodeError,
    value_error_type=ValueError,
    max_safe_integer=MAX_SAFE_INTEGER,
    max_json_depth=_MAX_JSON_DEPTH,
    max_json_nodes=_MAX_JSON_NODES,
)


def _set_stable_function_metadata(operation: object, name: str) -> None:
    function = cast(_StableFunctionMetadata, operation)
    function.__module__ = __name__
    function.__name__ = name
    function.__qualname__ = name


_set_stable_function_metadata(
    _CANONICAL_OPERATIONS.reject_duplicate_object_keys,
    "_reject_duplicate_object_keys",
)
_set_stable_function_metadata(
    _CANONICAL_OPERATIONS.reject_non_json_constant,
    "_reject_non_json_constant",
)
_set_stable_function_metadata(_CANONICAL_OPERATIONS.validate_string, "_validate_string")
_set_stable_function_metadata(_CANONICAL_OPERATIONS.validate_json_value, "_validate_json_value")
_set_stable_function_metadata(_CANONICAL_OPERATIONS.strict_json_loads, "strict_json_loads")
_set_stable_function_metadata(_CANONICAL_OPERATIONS.canonical_json_bytes, "canonical_json_bytes")
_set_stable_function_metadata(_CANONICAL_OPERATIONS.validate_domain, "_validate_domain")
_set_stable_function_metadata(_CANONICAL_OPERATIONS.structured_sha256, "structured_sha256")
_set_stable_function_metadata(
    _CANONICAL_OPERATIONS.structured_sha256_hex,
    "structured_sha256_hex",
)
_set_stable_function_metadata(
    _CANONICAL_OPERATIONS.domain_separated_bytes_sha256,
    "domain_separated_bytes_sha256",
)
_set_stable_function_metadata(_CANONICAL_OPERATIONS.exact_file_sha256, "exact_file_sha256")

# Preserve the module's established names and signatures while making every
# authoritative operation independent of subsequent module-global rebinding.
_reject_duplicate_object_keys = _CANONICAL_OPERATIONS.reject_duplicate_object_keys
_reject_non_json_constant = _CANONICAL_OPERATIONS.reject_non_json_constant
_validate_string = _CANONICAL_OPERATIONS.validate_string
_validate_json_value = _CANONICAL_OPERATIONS.validate_json_value
strict_json_loads = _CANONICAL_OPERATIONS.strict_json_loads
canonical_json_bytes = _CANONICAL_OPERATIONS.canonical_json_bytes
_validate_domain = _CANONICAL_OPERATIONS.validate_domain
structured_sha256 = _CANONICAL_OPERATIONS.structured_sha256
structured_sha256_hex = _CANONICAL_OPERATIONS.structured_sha256_hex
domain_separated_bytes_sha256 = _CANONICAL_OPERATIONS.domain_separated_bytes_sha256
exact_file_sha256 = _CANONICAL_OPERATIONS.exact_file_sha256
