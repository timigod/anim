"""Exact-byte, role-neutral admission for private CSV source tables.

This module is deliberately earlier than scientific dataset construction.  It
binds exact bytes to one complete physical CSV contract and parses every cell,
including columns that a later configuration may declare ignored.  It does not
accept column roles, select rows, transform values, or retain the source bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import struct
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Protocol, Self, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import canonical_json_bytes, exact_file_sha256, structured_sha256
from ebm_audit.protocol.canonical import MAX_SAFE_INTEGER
from ebm_audit.protocol.errors import CanonicalizationError
from ebm_audit.schema import SchemaValidationError, validate_instance

_PARSER_VERSION: Final = "strict-utf8-csv-source-admission/2"
_INPUT_FORMAT_DOMAIN: Final = "ebm-audit/input-format/1"
_COLUMN_DOMAIN: Final = "ebm-audit/source-admission-column/2"
_TABLE_DOMAIN: Final = "ebm-audit/source-admission-table/2"
_ADMISSION_DOMAIN: Final = "ebm-audit/source-admission/2"

# These bounds are parser-version semantics.  The source ceiling reserves a
# conservative ten source-size copies for caller bytes, the exact copy, the
# worst compact-Unicode width, and transient record/field strings, plus the
# complete retained-table/snapshot budget and fixed parser headroom.
_MAX_ADMISSION_PEAK_BYTES: Final = 256 * 1024 * 1024
_MAX_SOURCE_BYTES: Final = 12 * 1024 * 1024
_SOURCE_PEAK_MULTIPLIER: Final = 10
_ADMISSION_FIXED_PEAK_BYTES: Final = 8 * 1024 * 1024
_MAX_FIELD_BYTES: Final = 1024 * 1024
_MAX_NUMERIC_TOKEN_BYTES: Final = 256
_MAX_COLUMNS: Final = 4096
_MAX_ROWS: Final = 1_000_000
_MAX_CELLS: Final = 1_000_000
_MAX_FORMAT_TOKENS: Final = 4096
_MAX_COLUMN_NAME_BYTES: Final = 4096
_MAX_ESTIMATED_RETAINED_TABLE_BYTES: Final = 128 * 1024 * 1024
_ESTIMATED_RETAINED_CELL_BYTES: Final = 160
_DIGEST_CHUNK_BYTES: Final = 64 * 1024
# Enforced by the tracemalloc regression over the declared 50 KiB numeric
# fixture.  The deterministic retained-table budget above is the runtime gate.
_MAX_MEASURED_PEAK_AMPLIFICATION: Final = 32.0
_MAX_MEASURED_PEAK_BYTES: Final = 2 * 1024 * 1024

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INTEGER = re.compile(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)\Z")
_FLOAT64 = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
_FORMAT_KEYS = frozenset(
    {
        "kind",
        "encoding",
        "delimiter",
        "quote_character",
        "header",
        "line_ending",
        "allow_quoted_newlines",
        "trim_whitespace",
        "locale",
        "infer_types",
        "implicit_na_tokens",
        "missing_tokens",
        "true_tokens",
        "false_tokens",
        "columns",
    }
)
_COLUMN_KEYS = frozenset({"source_column", "physical_type"})
_PHYSICAL_TYPES = frozenset({"string", "integer", "float64", "boolean"})
_REJECTION_CODES: Final = frozenset(
    {
        "DATA.SOURCE_BLANK_RECORD",
        "DATA.SOURCE_BOM",
        "DATA.SOURCE_BOOLEAN_TOKEN",
        "DATA.SOURCE_BYTES_TYPE",
        "DATA.SOURCE_BYTE_BOUND",
        "DATA.SOURCE_BYTE_DIGEST_MISMATCH",
        "DATA.SOURCE_CELL_BOUND",
        "DATA.SOURCE_COLUMN_BOUND",
        "DATA.SOURCE_CSV_QUOTE",
        "DATA.SOURCE_DATA_ROWS_MISSING",
        "DATA.SOURCE_EXPECTED_DIGEST",
        "DATA.SOURCE_FIELD_BOUND",
        "DATA.SOURCE_FLOAT_FORMAT",
        "DATA.SOURCE_FLOAT_NONFINITE",
        "DATA.SOURCE_FLOAT_UNDERFLOW",
        "DATA.SOURCE_FORMAT",
        "DATA.SOURCE_FORMAT_BOUND",
        "DATA.SOURCE_HEADER_DUPLICATE",
        "DATA.SOURCE_HEADER_EXTRA_COLUMN",
        "DATA.SOURCE_HEADER_MISMATCH",
        "DATA.SOURCE_HEADER_MISSING",
        "DATA.SOURCE_HEADER_MISSING_COLUMN",
        "DATA.SOURCE_HEADER_REORDERED",
        "DATA.SOURCE_INTEGER_FORMAT",
        "DATA.SOURCE_INTEGER_RANGE",
        "DATA.SOURCE_INTERNAL_CONTRACT",
        "DATA.SOURCE_LINE_ENDING",
        "DATA.SOURCE_NON_NFC",
        "DATA.SOURCE_RAGGED_ROW",
        "DATA.SOURCE_ROW_BOUND",
        "DATA.SOURCE_TABLE_MEMORY_BOUND",
        "DATA.SOURCE_UTF8",
    }
)
_MAPPING_PROXY_TYPE: Final[type] = type(MappingProxyType({}))


class _AdmissionRejected(Exception):
    """Internal code-only rejection consumed before the public boundary returns."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__()


class _DigestWriter(Protocol):
    def update(self, data: bytes | bytearray | memoryview, /) -> None: ...


class _MissingValue:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<missing>"


_MISSING: Final = _MissingValue()


@dataclass(frozen=True, slots=True, repr=False)
class _PrivateColumn:
    source_column: str
    physical_type: str
    values: tuple[object, ...]

    def __repr__(self) -> str:
        return "_PrivateColumn(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _CapabilitySnapshot:
    admission_id: str
    byte_digest: str
    parsed_table_digest: str
    input_format_digest: str
    byte_length: int
    row_count: int
    column_count: int
    private_table: Mapping[str, tuple[object, ...]]


@dataclass(frozen=True, slots=True)
class _SanitizedControlFlow:
    kind: str
    exit_code: int | None = None


@final
class ValidatedSourceAdmission:
    """Immutable capability proving one exact source passed physical admission.

    Construction is private to :func:`_admit_exact_source_bytes`.  The only
    public facts are content identities and aggregate sizes; parsed values and
    source names exist only in the closure-held registry entry associated with
    the capability object.
    """

    __slots__ = (
        "__weakref__",
        "_admission_id",
        "_byte_digest",
        "_byte_length",
        "_column_count",
        "_input_format_digest",
        "_parsed_table_digest",
        "_row_count",
    )
    _admission_id: str
    _byte_digest: str
    _byte_length: int
    _column_count: int
    _input_format_digest: str
    _parsed_table_digest: str
    _row_count: int

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> Self:
        raise TypeError("Validated source admissions cannot be constructed directly.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Validated source admissions cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Validated source admissions are immutable.")

    @property
    def admission_id(self) -> str:
        return self._admission_id

    @property
    def byte_digest(self) -> str:
        return self._byte_digest

    @property
    def parsed_table_digest(self) -> str:
        return self._parsed_table_digest

    @property
    def input_format_digest(self) -> str:
        return self._input_format_digest

    @property
    def byte_length(self) -> int:
        return self._byte_length

    @property
    def row_count(self) -> int:
        return self._row_count

    @property
    def column_count(self) -> int:
        return self._column_count

    def __copy__(self) -> ValidatedSourceAdmission:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> ValidatedSourceAdmission:
        memo[id(self)] = self
        return self

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Validated source admissions cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Validated source admissions cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Validated source admissions cannot be serialized.")

    def __repr__(self) -> str:
        return (
            "ValidatedSourceAdmission("
            f"admission_id={self.admission_id!r}, "
            f"byte_length={self.byte_length}, row_count={self.row_count}, "
            f"column_count={self.column_count}, private=<redacted>)"
        )


def _invalid(code: str) -> _AdmissionRejected:
    return _AdmissionRejected(code)


def _utf8_width(character: str) -> int:
    codepoint = ord(character)
    if codepoint <= 0x7F:
        return 1
    if codepoint <= 0x7FF:
        return 2
    if codepoint <= 0xFFFF:
        return 3
    return 4


def _bounded_nfc_text(value: object, *, maximum_bytes: int) -> str:
    if type(value) is not str:
        raise _invalid("DATA.SOURCE_FORMAT")
    text = value
    if not unicodedata.is_normalized("NFC", text):
        raise _invalid("DATA.SOURCE_FORMAT")
    try:
        encoded = text.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _invalid("DATA.SOURCE_FORMAT") from None
    if len(encoded) > maximum_bytes:
        raise _invalid("DATA.SOURCE_FORMAT_BOUND")
    return text


def _exact_string_key_dict(value: object, *, expected_keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict:
        raise _invalid("DATA.SOURCE_FORMAT")
    untyped = cast(dict[object, object], value)
    keys = tuple(untyped)
    if len(keys) != len(expected_keys) or any(type(key) is not str for key in keys):
        raise _invalid("DATA.SOURCE_FORMAT")
    typed = cast(dict[str, object], untyped)
    if frozenset(typed) != expected_keys:
        raise _invalid("DATA.SOURCE_FORMAT")
    return typed


def _string_list(value: object, *, nonempty: bool = False) -> list[str]:
    if type(value) is not list:
        raise _invalid("DATA.SOURCE_FORMAT")
    raw_values = cast(list[object], value)
    if nonempty and not raw_values:
        raise _invalid("DATA.SOURCE_FORMAT")
    if len(raw_values) > _MAX_FORMAT_TOKENS:
        raise _invalid("DATA.SOURCE_FORMAT_BOUND")
    result = [_bounded_nfc_text(item, maximum_bytes=_MAX_FIELD_BYTES) for item in raw_values]
    if len(set(result)) != len(result):
        raise _invalid("DATA.SOURCE_FORMAT")
    return result


def _normalize_csv_format(csv_format: Mapping[str, object]) -> dict[str, object]:
    format_values = _exact_string_key_dict(csv_format, expected_keys=_FORMAT_KEYS)

    delimiter = _bounded_nfc_text(format_values["delimiter"], maximum_bytes=4)
    quote = _bounded_nfc_text(format_values["quote_character"], maximum_bytes=4)
    if (
        len(delimiter) != 1
        or len(quote) != 1
        or delimiter == quote
        or delimiter in "\r\n"
        or quote in "\r\n"
    ):
        raise _invalid("DATA.SOURCE_FORMAT")
    if (
        type(format_values["kind"]) is not str
        or format_values["kind"] != "csv"
        or type(format_values["encoding"]) is not str
        or format_values["encoding"] != "utf-8"
        or format_values["header"] is not True
        or type(format_values["line_ending"]) is not str
        or format_values["line_ending"] not in {"lf", "crlf"}
        or format_values["allow_quoted_newlines"] is not False
        or format_values["trim_whitespace"] is not False
        or format_values["locale"] is not None
        or format_values["infer_types"] is not False
        or format_values["implicit_na_tokens"] is not False
    ):
        raise _invalid("DATA.SOURCE_FORMAT")

    missing_tokens = _string_list(format_values["missing_tokens"])
    true_tokens = _string_list(format_values["true_tokens"], nonempty=True)
    false_tokens = _string_list(format_values["false_tokens"], nonempty=True)
    if (
        set(missing_tokens) & (set(true_tokens) | set(false_tokens))
        or set(true_tokens) & set(false_tokens)
        or len(missing_tokens) + len(true_tokens) + len(false_tokens) > _MAX_FORMAT_TOKENS
    ):
        raise _invalid("DATA.SOURCE_FORMAT")

    raw_columns_value = format_values["columns"]
    if type(raw_columns_value) is not list:
        raise _invalid("DATA.SOURCE_FORMAT")
    raw_columns = cast(list[object], raw_columns_value)
    if not raw_columns:
        raise _invalid("DATA.SOURCE_FORMAT")
    if len(raw_columns) > _MAX_COLUMNS:
        raise _invalid("DATA.SOURCE_FORMAT_BOUND")
    columns: list[dict[str, str]] = []
    names: list[str] = []
    for raw_column in raw_columns:
        column_values = _exact_string_key_dict(raw_column, expected_keys=_COLUMN_KEYS)
        source_column = _bounded_nfc_text(
            column_values["source_column"], maximum_bytes=_MAX_COLUMN_NAME_BYTES
        )
        physical_type_value = column_values["physical_type"]
        if not source_column or type(physical_type_value) is not str:
            raise _invalid("DATA.SOURCE_FORMAT")
        physical_type = physical_type_value
        if physical_type not in _PHYSICAL_TYPES:
            raise _invalid("DATA.SOURCE_FORMAT")
        names.append(source_column)
        columns.append({"source_column": source_column, "physical_type": physical_type})
    if len(set(names)) != len(names):
        raise _invalid("DATA.SOURCE_FORMAT")

    normalized: dict[str, object] = {
        "kind": "csv",
        "encoding": "utf-8",
        "delimiter": delimiter,
        "quote_character": quote,
        "header": True,
        "line_ending": format_values["line_ending"],
        "allow_quoted_newlines": False,
        "trim_whitespace": False,
        "locale": None,
        "infer_types": False,
        "implicit_na_tokens": False,
        "missing_tokens": missing_tokens,
        "true_tokens": true_tokens,
        "false_tokens": false_tokens,
        "columns": columns,
    }
    try:
        validate_instance(normalized, "audit-config.schema.json", definition="CsvFormat")
        canonical_json_bytes(normalized)
    except (CanonicalizationError, SchemaValidationError, TypeError, ValueError):
        raise _invalid("DATA.SOURCE_FORMAT") from None
    return normalized


def _validate_line_endings(text: str, line_ending: str) -> str:
    if line_ending == "lf":
        if "\r" in text:
            raise _invalid("DATA.SOURCE_LINE_ENDING")
        return "\n"
    for index, character in enumerate(text):
        if character == "\r":
            if index + 1 >= len(text) or text[index + 1] != "\n":
                raise _invalid("DATA.SOURCE_LINE_ENDING")
        elif character == "\n" and (index == 0 or text[index - 1] != "\r"):
            raise _invalid("DATA.SOURCE_LINE_ENDING")
    return "\r\n"


def _records(text: str, separator: str) -> Iterator[str]:
    start = 0
    while True:
        end = text.find(separator, start)
        if end < 0:
            if start < len(text):
                yield text[start:]
            return
        yield text[start:end]
        start = end + len(separator)
        if start == len(text):
            return


def _check_field_growth(current_bytes: int, character: str) -> int:
    result = current_bytes + _utf8_width(character)
    if result > _MAX_FIELD_BYTES:
        raise _invalid("DATA.SOURCE_FIELD_BOUND")
    return result


def _parse_record(record: str, *, delimiter: str, quote: str) -> list[str]:
    fields: list[str] = []
    index = 0
    length = len(record)
    while True:
        if len(fields) >= _MAX_COLUMNS:
            raise _invalid("DATA.SOURCE_COLUMN_BOUND")
        field_bytes = 0
        if index < length and record[index] == quote:
            field_bytes = _check_field_growth(field_bytes, quote)
            index += 1
            characters: list[str] = []
            closed = False
            while index < length:
                character = record[index]
                field_bytes = _check_field_growth(field_bytes, character)
                if character == quote:
                    if index + 1 < length and record[index + 1] == quote:
                        field_bytes = _check_field_growth(field_bytes, quote)
                        characters.append(quote)
                        index += 2
                        continue
                    closed = True
                    index += 1
                    break
                characters.append(character)
                index += 1
            if not closed:
                raise _invalid("DATA.SOURCE_CSV_QUOTE")
            if index < length and record[index] != delimiter:
                raise _invalid("DATA.SOURCE_CSV_QUOTE")
            fields.append("".join(characters))
        else:
            start = index
            while index < length and record[index] != delimiter:
                character = record[index]
                if character == quote:
                    raise _invalid("DATA.SOURCE_CSV_QUOTE")
                field_bytes = _check_field_growth(field_bytes, character)
                index += 1
            fields.append(record[start:index])

        if index == length:
            return fields
        index += 1
        if index == length:
            if len(fields) >= _MAX_COLUMNS:
                raise _invalid("DATA.SOURCE_COLUMN_BOUND")
            fields.append("")
            return fields


def _parse_integer(token: str) -> int:
    if len(token) > _MAX_NUMERIC_TOKEN_BYTES or _INTEGER.fullmatch(token) is None:
        raise _invalid("DATA.SOURCE_INTEGER_FORMAT")
    try:
        value = int(token, 10)
    except ValueError:
        raise _invalid("DATA.SOURCE_INTEGER_FORMAT") from None
    if abs(value) > MAX_SAFE_INTEGER:
        raise _invalid("DATA.SOURCE_INTEGER_RANGE")
    return value


def _parse_float64(token: str) -> float:
    if len(token) > _MAX_NUMERIC_TOKEN_BYTES or _FLOAT64.fullmatch(token) is None:
        raise _invalid("DATA.SOURCE_FLOAT_FORMAT")
    try:
        value = float(token)
    except (OverflowError, ValueError):
        raise _invalid("DATA.SOURCE_FLOAT_FORMAT") from None
    if not math.isfinite(value):
        raise _invalid("DATA.SOURCE_FLOAT_NONFINITE")
    mantissa = token.split("e", 1)[0].split("E", 1)[0]
    mathematically_nonzero = any(character in "123456789" for character in mantissa)
    if value == 0.0 and mathematically_nonzero:
        raise _invalid("DATA.SOURCE_FLOAT_UNDERFLOW")
    return value


def _parse_value(
    token: str,
    *,
    physical_type: str,
    missing_tokens: frozenset[str],
    true_tokens: frozenset[str],
    false_tokens: frozenset[str],
) -> object:
    if token in missing_tokens:
        return _MISSING
    if physical_type == "string":
        return token
    if physical_type == "integer":
        return _parse_integer(token)
    if physical_type == "float64":
        return _parse_float64(token)
    if physical_type == "boolean":
        if token in true_tokens:
            return True
        if token in false_tokens:
            return False
        raise _invalid("DATA.SOURCE_BOOLEAN_TOKEN")
    raise _invalid("DATA.SOURCE_FORMAT")


def _update_frame(
    digest: _DigestWriter,
    *,
    tag: bytes,
    payload: bytes,
    chunk_bytes: int,
) -> None:
    """Add one unambiguous ``u16 tag-length/tag/u64 payload-length/payload`` frame."""

    if (
        type(tag) is not bytes
        or not tag
        or len(tag) > 0xFFFF
        or type(payload) is not bytes
        or type(chunk_bytes) is not int
        or chunk_bytes <= 0
    ):
        raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT")
    digest.update(struct.pack(">H", len(tag)))
    digest.update(tag)
    digest.update(struct.pack(">Q", len(payload)))
    view = memoryview(payload)
    for start in range(0, len(view), chunk_bytes):
        digest.update(view[start : start + chunk_bytes])


def _exact_column_missing_count(column: _PrivateColumn, *, row_count: int) -> int:
    if (
        type(column) is not _PrivateColumn
        or type(column.source_column) is not str
        or not column.source_column
        or type(column.physical_type) is not str
        or column.physical_type not in _PHYSICAL_TYPES
        or type(column.values) is not tuple
        or len(column.values) != row_count
    ):
        raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT")
    try:
        _bounded_nfc_text(column.source_column, maximum_bytes=_MAX_COLUMN_NAME_BYTES)
    except _AdmissionRejected:
        raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT") from None

    missing_count = 0
    for value in column.values:
        if value is _MISSING:
            missing_count += 1
        elif column.physical_type == "string":
            try:
                _bounded_nfc_text(value, maximum_bytes=_MAX_FIELD_BYTES)
            except _AdmissionRejected:
                raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT") from None
        elif column.physical_type == "integer":
            if type(value) is not int or abs(value) > MAX_SAFE_INTEGER:
                raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT")
        elif column.physical_type == "float64":
            if type(value) is not float or not math.isfinite(value):
                raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT")
        elif column.physical_type == "boolean":
            if type(value) is not bool:
                raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT")
        else:
            raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT")
    return missing_count


def _framed_column_digest(
    column_index: int,
    column: _PrivateColumn,
    *,
    row_count: int,
    chunk_bytes: int = _DIGEST_CHUNK_BYTES,
) -> tuple[str, int]:
    """Hash one validated column without materializing a per-cell object graph."""

    if (
        type(column_index) is not int
        or not 0 <= column_index < _MAX_COLUMNS
        or type(row_count) is not int
        or not 0 < row_count <= _MAX_ROWS
    ):
        raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT")
    missing_count = _exact_column_missing_count(column, row_count=row_count)
    digest = hashlib.sha256(_COLUMN_DOMAIN.encode("ascii") + b"\x00")
    frames = (
        (b"schema", b"ebm-audit-source-admission-column/2.0"),
        (b"column-index", struct.pack(">Q", column_index)),
        (b"source-column", column.source_column.encode("utf-8", errors="strict")),
        (b"physical-type", column.physical_type.encode("ascii", errors="strict")),
        (b"row-count", struct.pack(">Q", row_count)),
        (b"missing-count", struct.pack(">Q", missing_count)),
    )
    for tag, payload in frames:
        _update_frame(digest, tag=tag, payload=payload, chunk_bytes=chunk_bytes)
    for value in column.values:
        if value is _MISSING:
            tag, payload = b"value:missing", b""
        elif column.physical_type == "string":
            tag = b"value:string"
            payload = cast(str, value).encode("utf-8", errors="strict")
        elif column.physical_type == "integer":
            tag = b"value:integer"
            payload = struct.pack(">q", cast(int, value))
        elif column.physical_type == "float64":
            tag = b"value:float64"
            payload = struct.pack(">d", cast(float, value))
        else:
            tag = b"value:boolean"
            payload = b"\x01" if cast(bool, value) else b"\x00"
        _update_frame(digest, tag=tag, payload=payload, chunk_bytes=chunk_bytes)
    return f"sha256:{digest.hexdigest()}", missing_count


def _table_identity(
    columns: tuple[_PrivateColumn, ...], row_count: int, input_format_digest: str
) -> tuple[str, tuple[str, ...]]:
    if (
        type(columns) is not tuple
        or not 0 < len(columns) <= _MAX_COLUMNS
        or type(row_count) is not int
        or not 0 < row_count <= _MAX_ROWS
        or type(input_format_digest) is not str
        or _DIGEST.fullmatch(input_format_digest) is None
    ):
        raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT")
    column_identities = tuple(
        _framed_column_digest(column_index, column, row_count=row_count)
        for column_index, column in enumerate(columns)
    )
    column_digests = tuple(identity[0] for identity in column_identities)
    preimage = {
        "table_preimage_schema_version": "ebm-audit-source-admission-table/2.0",
        "parser_version": _PARSER_VERSION,
        "input_format_digest": input_format_digest,
        "row_count": row_count,
        "column_count": len(columns),
        "ordered_columns": [
            {
                "column_index": index,
                "physical_type": column.physical_type,
                "row_count": row_count,
                "missing_count": column_identities[index][1],
                "content_digest": column_digests[index],
            }
            for index, column in enumerate(columns)
        ],
    }
    try:
        validate_instance(
            preimage,
            "canonical-records.schema.json",
            definition="SourceAdmissionTableDigestPreimage",
        )
        return structured_sha256(_TABLE_DOMAIN, preimage), column_digests
    except (CanonicalizationError, SchemaValidationError, TypeError, ValueError):
        raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT") from None


def _admission_preimage(
    *,
    byte_digest: str,
    byte_length: int,
    input_format_digest: str,
    parsed_table_digest: str,
    row_count: int,
    column_count: int,
) -> dict[str, object]:
    return {
        "admission_preimage_schema_version": "ebm-audit-source-admission/2.0",
        "parser_version": _PARSER_VERSION,
        "byte_digest": byte_digest,
        "byte_length": byte_length,
        "input_format_digest": input_format_digest,
        "parsed_table_digest": parsed_table_digest,
        "row_count": row_count,
        "column_count": column_count,
    }


def _admission_id(preimage: Mapping[str, object]) -> str:
    try:
        validate_instance(
            preimage,
            "canonical-records.schema.json",
            definition="SourceAdmissionDigestPreimage",
        )
        return structured_sha256(_ADMISSION_DOMAIN, preimage)
    except (CanonicalizationError, SchemaValidationError, TypeError, ValueError):
        raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT") from None


def _parse_exact_source_bytes(
    exact_bytes: bytes | bytearray | memoryview,
    *,
    expected_byte_digest: str,
    csv_format: Mapping[str, object],
) -> tuple[
    str,
    str,
    str,
    str,
    int,
    int,
    int,
    Mapping[str, tuple[object, ...]],
]:
    """Parse exact bytes into the sole private source-admission capability.

    This entry point is internal by design.  Configuration verification may
    call it only after resolving the private input path and complete format
    mapping.  It accepts no arbitrary table and no scientific role mapping.
    """

    if type(exact_bytes) not in (bytes, bytearray, memoryview):
        raise _invalid("DATA.SOURCE_BYTES_TYPE")
    byte_length = exact_bytes.nbytes if type(exact_bytes) is memoryview else len(exact_bytes)
    estimated_peak_bytes = (
        byte_length * _SOURCE_PEAK_MULTIPLIER
        + _MAX_ESTIMATED_RETAINED_TABLE_BYTES
        + _ADMISSION_FIXED_PEAK_BYTES
    )
    if (
        byte_length <= 0
        or byte_length > _MAX_SOURCE_BYTES
        or estimated_peak_bytes > _MAX_ADMISSION_PEAK_BYTES
    ):
        raise _invalid("DATA.SOURCE_BYTE_BOUND")
    if type(expected_byte_digest) is not str or _DIGEST.fullmatch(expected_byte_digest) is None:
        raise _invalid("DATA.SOURCE_EXPECTED_DIGEST")
    normalized_format = _normalize_csv_format(csv_format)
    try:
        input_format_digest = structured_sha256(_INPUT_FORMAT_DOMAIN, normalized_format)
    except (CanonicalizationError, TypeError, ValueError):
        raise _invalid("DATA.SOURCE_INTERNAL_CONTRACT") from None

    try:
        raw = bytes(exact_bytes)
    except (BufferError, TypeError, ValueError):
        raise _invalid("DATA.SOURCE_BYTES_TYPE") from None
    if len(raw) != byte_length:
        raise _invalid("DATA.SOURCE_BYTE_BOUND")
    byte_digest = exact_file_sha256(raw)
    if not hmac.compare_digest(byte_digest, expected_byte_digest):
        raise _invalid("DATA.SOURCE_BYTE_DIGEST_MISMATCH")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _invalid("DATA.SOURCE_BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _invalid("DATA.SOURCE_UTF8") from None
    if not unicodedata.is_normalized("NFC", text):
        raise _invalid("DATA.SOURCE_NON_NFC")
    separator = _validate_line_endings(text, cast(str, normalized_format["line_ending"]))
    if not text:
        raise _invalid("DATA.SOURCE_HEADER_MISSING")

    columns_format = cast(list[dict[str, str]], normalized_format["columns"])
    expected_header = tuple(column["source_column"] for column in columns_format)
    delimiter = cast(str, normalized_format["delimiter"])
    quote = cast(str, normalized_format["quote_character"])
    records = _records(text, separator)
    try:
        header_record = next(records)
    except StopIteration:
        raise _invalid("DATA.SOURCE_HEADER_MISSING") from None
    if not header_record:
        raise _invalid("DATA.SOURCE_HEADER_MISSING")
    header = _parse_record(header_record, delimiter=delimiter, quote=quote)
    if len(set(header)) != len(header):
        raise _invalid("DATA.SOURCE_HEADER_DUPLICATE")
    if len(header) < len(expected_header):
        raise _invalid("DATA.SOURCE_HEADER_MISSING_COLUMN")
    if len(header) > len(expected_header):
        raise _invalid("DATA.SOURCE_HEADER_EXTRA_COLUMN")
    if tuple(header) != expected_header:
        if set(header) == set(expected_header):
            raise _invalid("DATA.SOURCE_HEADER_REORDERED")
        raise _invalid("DATA.SOURCE_HEADER_MISMATCH")

    missing_tokens = frozenset(cast(list[str], normalized_format["missing_tokens"]))
    true_tokens = frozenset(cast(list[str], normalized_format["true_tokens"]))
    false_tokens = frozenset(cast(list[str], normalized_format["false_tokens"]))
    column_values: list[list[object]] = [[] for _column in columns_format]
    row_count = 0
    estimated_retained_table_bytes = 0
    for record in records:
        if not record:
            raise _invalid("DATA.SOURCE_BLANK_RECORD")
        if row_count >= _MAX_ROWS:
            raise _invalid("DATA.SOURCE_ROW_BOUND")
        if (row_count + 1) * len(columns_format) > _MAX_CELLS:
            raise _invalid("DATA.SOURCE_CELL_BOUND")
        fields = _parse_record(record, delimiter=delimiter, quote=quote)
        if len(fields) != len(columns_format):
            raise _invalid("DATA.SOURCE_RAGGED_ROW")
        for index, (field, column_format) in enumerate(zip(fields, columns_format, strict=True)):
            estimated_cell_bytes = _ESTIMATED_RETAINED_CELL_BYTES + sum(
                _utf8_width(character) for character in field
            )
            if (
                estimated_cell_bytes
                > _MAX_ESTIMATED_RETAINED_TABLE_BYTES - estimated_retained_table_bytes
            ):
                raise _invalid("DATA.SOURCE_TABLE_MEMORY_BOUND")
            parsed_value = _parse_value(
                field,
                physical_type=column_format["physical_type"],
                missing_tokens=missing_tokens,
                true_tokens=true_tokens,
                false_tokens=false_tokens,
            )
            column_values[index].append(parsed_value)
            estimated_retained_table_bytes += estimated_cell_bytes
        row_count += 1
    if row_count == 0:
        raise _invalid("DATA.SOURCE_DATA_ROWS_MISSING")

    columns = tuple(
        _PrivateColumn(
            source_column=column_format["source_column"],
            physical_type=column_format["physical_type"],
            values=tuple(column_values[index]),
        )
        for index, column_format in enumerate(columns_format)
    )
    parsed_table_digest, _column_digests = _table_identity(columns, row_count, input_format_digest)
    preimage = _admission_preimage(
        byte_digest=byte_digest,
        byte_length=byte_length,
        input_format_digest=input_format_digest,
        parsed_table_digest=parsed_table_digest,
        row_count=row_count,
        column_count=len(columns),
    )
    admission_id = _admission_id(preimage)
    private_table = MappingProxyType(
        {
            column.source_column: (
                column.values
                if not any(value is _MISSING for value in column.values)
                else tuple(math.nan if value is _MISSING else value for value in column.values)
            )
            for column in columns
        }
    )
    return (
        admission_id,
        byte_digest,
        parsed_table_digest,
        input_format_digest,
        byte_length,
        row_count,
        len(columns),
        private_table,
    )


class _AdmitExactSourceBytes(Protocol):
    def __call__(
        self,
        exact_bytes: bytes | bytearray | memoryview,
        *,
        expected_byte_digest: str,
        csv_format: Mapping[str, object],
    ) -> ValidatedSourceAdmission: ...


class _PrivateSourceTable(Protocol):
    def __call__(self, admission: ValidatedSourceAdmission) -> Mapping[str, tuple[object, ...]]: ...


def _build_source_admission_boundary() -> tuple[_AdmitExactSourceBytes, _PrivateSourceTable]:
    parse_exact_source_bytes = _parse_exact_source_bytes
    registry: OneShotWeakRegistry[ValidatedSourceAdmission, _CapabilitySnapshot]
    issuer: OneShotRegistryIssuer[ValidatedSourceAdmission, _CapabilitySnapshot]
    registry, issuer = create_one_shot_registry()
    invalid_capability = object()
    admission_success = object()
    projection_success = object()

    def try_admit(
        exact_bytes: bytes | bytearray | memoryview,
        *,
        expected_byte_digest: str,
        csv_format: Mapping[str, object],
    ) -> tuple[object, ValidatedSourceAdmission] | str | _SanitizedControlFlow:
        try:
            (
                admission_id,
                byte_digest,
                parsed_table_digest,
                input_format_digest,
                byte_length,
                row_count,
                column_count,
                private_table,
            ) = parse_exact_source_bytes(
                exact_bytes,
                expected_byte_digest=expected_byte_digest,
                csv_format=csv_format,
            )
            admission = object.__new__(ValidatedSourceAdmission)
            object.__setattr__(admission, "_admission_id", admission_id)
            object.__setattr__(admission, "_byte_digest", byte_digest)
            object.__setattr__(admission, "_parsed_table_digest", parsed_table_digest)
            object.__setattr__(admission, "_input_format_digest", input_format_digest)
            object.__setattr__(admission, "_byte_length", byte_length)
            object.__setattr__(admission, "_row_count", row_count)
            object.__setattr__(admission, "_column_count", column_count)
            issuer.bind_once(
                admission,
                _CapabilitySnapshot(
                    admission_id=admission_id,
                    byte_digest=byte_digest,
                    parsed_table_digest=parsed_table_digest,
                    input_format_digest=input_format_digest,
                    byte_length=byte_length,
                    row_count=row_count,
                    column_count=column_count,
                    private_table=private_table,
                ),
            )
            return admission_success, admission
        except _AdmissionRejected as rejected:
            if type(rejected) is not _AdmissionRejected:
                return "DATA.SOURCE_INTERNAL_CONTRACT"
            try:
                rejection_code = rejected.code
            except BaseException:
                return "DATA.SOURCE_INTERNAL_CONTRACT"
            if type(rejection_code) is not str or rejection_code not in _REJECTION_CODES:
                return "DATA.SOURCE_INTERNAL_CONTRACT"
            return rejection_code
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                return _SanitizedControlFlow("keyboard_interrupt")
            if type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                return _SanitizedControlFlow("system_exit", safe_exit_code)
            if type(stopped) is GeneratorExit:
                return _SanitizedControlFlow("generator_exit")
            return "DATA.SOURCE_INTERNAL_CONTRACT"

    def admit_exact_source_bytes(
        exact_bytes: bytes | bytearray | memoryview,
        *,
        expected_byte_digest: str,
        csv_format: Mapping[str, object],
    ) -> ValidatedSourceAdmission:
        try:
            outcome: tuple[object, ValidatedSourceAdmission] | str | _SanitizedControlFlow = (
                try_admit(
                    exact_bytes,
                    expected_byte_digest=expected_byte_digest,
                    csv_format=csv_format,
                )
            )
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                outcome = _SanitizedControlFlow("keyboard_interrupt")
            elif type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                outcome = _SanitizedControlFlow("system_exit", safe_exit_code)
            elif type(stopped) is GeneratorExit:
                outcome = _SanitizedControlFlow("generator_exit")
            else:
                outcome = "DATA.SOURCE_INTERNAL_CONTRACT"
        finally:
            del exact_bytes
            del expected_byte_digest
            del csv_format
        if type(outcome) is _SanitizedControlFlow:
            if outcome.kind == "keyboard_interrupt":
                raise KeyboardInterrupt
            if outcome.kind == "system_exit":
                raise SystemExit(outcome.exit_code)
            raise GeneratorExit
        if type(outcome) is str:
            raise InvalidInputError(
                outcome,
                "Source bytes do not satisfy the declared physical input contract.",
            )
        valid_success = False
        marker: object = None
        admission: object = None
        if type(outcome) is tuple and len(outcome) == 2:
            marker, admission = outcome
            if marker is admission_success and type(admission) is ValidatedSourceAdmission:
                try:
                    valid_success = registry.get(admission) is not None
                except BaseException:
                    valid_success = False
        if not valid_success:
            del outcome
            del marker
            del admission
            raise InvalidInputError(
                "DATA.SOURCE_INTERNAL_CONTRACT",
                "Source bytes do not satisfy the declared physical input contract.",
            )
        return cast(ValidatedSourceAdmission, admission)

    def try_private_source_table(
        admission: ValidatedSourceAdmission,
    ) -> tuple[object, Mapping[str, tuple[object, ...]]] | object | _SanitizedControlFlow:
        try:
            if type(admission) is not ValidatedSourceAdmission:
                return invalid_capability
            snapshot = registry.get(admission)
            if snapshot is None:
                return invalid_capability
            if (
                type(admission._admission_id) is not str
                or type(admission._byte_digest) is not str
                or type(admission._parsed_table_digest) is not str
                or type(admission._input_format_digest) is not str
                or type(admission._byte_length) is not int
                or type(admission._row_count) is not int
                or type(admission._column_count) is not int
            ):
                return invalid_capability
            valid = (
                admission._admission_id == snapshot.admission_id
                and admission._byte_digest == snapshot.byte_digest
                and admission._parsed_table_digest == snapshot.parsed_table_digest
                and admission._input_format_digest == snapshot.input_format_digest
                and admission._byte_length == snapshot.byte_length
                and admission._row_count == snapshot.row_count
                and admission._column_count == snapshot.column_count
            )
            if not valid:
                return invalid_capability
            return projection_success, snapshot.private_table
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                return _SanitizedControlFlow("keyboard_interrupt")
            if type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                return _SanitizedControlFlow("system_exit", safe_exit_code)
            if type(stopped) is GeneratorExit:
                return _SanitizedControlFlow("generator_exit")
            return invalid_capability

    def private_source_table(
        admission: ValidatedSourceAdmission,
    ) -> Mapping[str, tuple[object, ...]]:
        """Return the immutable projection only for a registered exact-byte parse."""

        try:
            outcome: (
                tuple[object, Mapping[str, tuple[object, ...]]] | object | _SanitizedControlFlow
            ) = try_private_source_table(admission)
        except BaseException as stopped:
            if type(stopped) is KeyboardInterrupt:
                outcome = _SanitizedControlFlow("keyboard_interrupt")
            elif type(stopped) is SystemExit:
                stopped_code = stopped.code
                safe_exit_code = (
                    stopped_code if stopped_code is None or type(stopped_code) is int else 1
                )
                outcome = _SanitizedControlFlow("system_exit", safe_exit_code)
            elif type(stopped) is GeneratorExit:
                outcome = _SanitizedControlFlow("generator_exit")
            else:
                outcome = invalid_capability
        finally:
            del admission
        if type(outcome) is _SanitizedControlFlow:
            if outcome.kind == "keyboard_interrupt":
                raise KeyboardInterrupt
            if outcome.kind == "system_exit":
                raise SystemExit(outcome.exit_code)
            raise GeneratorExit
        marker: object = None
        table: object = None
        valid_success = False
        if type(outcome) is tuple and len(outcome) == 2:
            marker, table = outcome
            if marker is projection_success and type(table) is _MAPPING_PROXY_TYPE:
                valid_success = True
        if valid_success:
            return cast(Mapping[str, tuple[object, ...]], table)
        del outcome
        del marker
        del table
        raise TypeError("A valid source admission capability is required.")

    return admit_exact_source_bytes, private_source_table


_admit_exact_source_bytes, _private_source_table = _build_source_admission_boundary()
del _build_source_admission_boundary
globals().pop("_parse_exact_source_bytes", None)


__all__ = ["ValidatedSourceAdmission"]
