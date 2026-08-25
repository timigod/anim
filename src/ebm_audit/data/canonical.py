"""Fail-closed canonical ingestion for private participant-level tables.

The raw table, source names, private identifiers, keyed participant tokens, and
row mapping remain inside the private result half.  The public view contains
only stable machine IDs, approved aliases, aggregate accounting, and digests.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import cast

import numpy as np
from numpy.typing import NDArray

from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import canonical_json_bytes, exact_file_sha256, structured_sha256
from ebm_audit.protocol.canonical import MAX_SAFE_INTEGER
from ebm_audit.protocol.errors import CanonicalizationError
from ebm_audit.schema import SchemaValidationError, validate_instance

from .identity import (
    ParticipantIdentityError,
    PrivateParticipantId,
    _NamespaceKey,
    build_identity_map,
    generate_namespace_key,
    validate_participant_private_id,
)
from .models import (
    AccountingOperation,
    ArrayCatalogEntry,
    AuxiliaryColumnBinding,
    CanonicalArray,
    CanonicalDataset,
    CanonicalDatasetView,
    ComponentDigests,
    DataAccounting,
    PrivateCanonicalDatasetState,
    PrivateCodebook,
)
from .source_admission import (
    _PARSER_VERSION,
    ValidatedSourceAdmission,
    _private_source_table,
)

_SOURCE_COLUMN_DOMAIN = "ebm-audit/canonical-source-column/1"
_SOURCE_TABLE_DOMAIN = "ebm-audit/canonical-source-table/1"
_SELECTED_ROW_MANIFEST_DOMAIN = "ebm-audit/selected-row-manifest/1"
_CATEGORICAL_CODEBOOK_DOMAIN = "ebm-audit/categorical-codebook/1"
_ARRAY_DOMAIN = "ebm-audit/array/1"
_DATA_ACCOUNTING_DOMAIN = "ebm-audit/data-accounting/1"
_SCIENTIFIC_DATA_DOMAIN = "ebm-audit/scientific-data/1"
_EXACT_FILE_ADMISSION_DOMAIN = b"ebm-audit/exact-file-admission-proof/2"
_SOURCE_ADMISSION_DOMAIN = "ebm-audit/source-admission/2"

_CANONICAL_REJECTION_CODES = frozenset(
    {
        "DATA.ACCOUNTING_INVALID",
        "DATA.ARRAY_INVALID",
        "DATA.CANONICAL_VIEW_INVALID",
        "DATA.COMPLETE_CASE_REMOVAL",
        "DATA.COMPONENT_DIGEST_INVALID",
        "DATA.CONSTANT_EVENT",
        "DATA.COVARIATE_INVALID",
        "DATA.DESCRIPTOR_INVALID",
        "DATA.EVENT_DIRECTION_UNRESOLVED",
        "DATA.EVENT_IDENTITY_AMBIGUOUS",
        "DATA.EVENT_VALUE_INVALID",
        "DATA.EXACT_FILE_ADMISSION_INVALID",
        "DATA.GROUP_INSUFFICIENT",
        "DATA.GROUP_INVALID",
        "DATA.GROUP_RULE_INVALID",
        "DATA.INGESTION_BINDING_INVALID",
        "DATA.METADATA_INVALID",
        "DATA.MISSINGNESS_POLICY_CONFLICT",
        "DATA.MISSING_EVENT_VALUE",
        "DATA.NEAR_CONSTANT_EVENT",
        "DATA.NO_SELECTED_ROWS",
        "DATA.PRIVATE_ID_INVALID",
        "DATA.ROLE_CLOSURE",
        "DATA.ROW_INDEX_INVALID",
        "DATA.ROW_MANIFEST_INVALID",
        "DATA.SCIENTIFIC_PREIMAGE_INVALID",
        "DATA.SOURCE_DIGEST_MISMATCH",
        "DATA.SUSPECT_IDENTIFIER_EVENT",
        "DATA.TABLE_INVALID",
        "DATA.TYPE_INVALID",
        "DATA.UNIVERSE_DECISION_INVALID",
    }
)
_CANONICAL_REJECTION_MESSAGE = "Canonical data was rejected."
_CANONICAL_INTERNAL_CODE = "DATA.INGESTION_INTERNAL_CONTRACT"
_CANONICAL_INTERNAL_MESSAGE = "Canonical data processing failed its closed internal contract."

_ALIAS_NAMESPACE_METHOD = "hmac-sorted-alias-v1"
_PARTICIPANT_TOKEN_METHOD = "hmac-sha256-typed-private-id/1"
_ROLE_CODES = MappingProxyType({"reference": 0, "at_risk": 1})
_IDENTIFIER_NAME = re.compile(
    r"(?:^|[^a-z0-9])(?:id|identifier|mrn|participant|patient|record|subject|case)"
    r"(?:$|[^a-z0-9])"
)
_IDENTIFIER_COMPACT_NAME = re.compile(
    r"(?:id|identifier|mrn)$|^(?:participant|patient|record|subject|case)(?:id|number|no)$"
)

type TaggedScalarKey = tuple[str, str | int | bool]


@dataclass(frozen=True, slots=True)
class _CanonicalSuccess[T]:
    value: T


@dataclass(frozen=True, slots=True)
class _CanonicalFailure:
    code: str
    safe_message: str


@dataclass(frozen=True, slots=True)
class _CanonicalControlFlow:
    kind: str
    exit_code: int | None = None


@dataclass(frozen=True, slots=True)
class _SourceAdmission:
    columns: Mapping[str, tuple[object, ...]] = field(repr=False)
    source_row_indexes: tuple[int, ...] = field(repr=False)
    object_dtype_columns: frozenset[str] = field(repr=False)
    column_preimages: tuple[Mapping[str, object], ...] = field(repr=False)
    table_preimage: Mapping[str, object] = field(repr=False)
    table_digest: str
    row_count: int


def _invalid(code: str, message: str) -> InvalidInputError:
    return InvalidInputError(code, message)


def _capture_canonical_operation[T](
    operation: Callable[[], T],
) -> _CanonicalSuccess[T] | _CanonicalFailure | _CanonicalControlFlow:
    """Close sensitive operation frames before a public failure is raised."""

    try:
        return _CanonicalSuccess(operation())
    except BaseException as stopped:
        if type(stopped) is KeyboardInterrupt:
            return _CanonicalControlFlow("keyboard_interrupt")
        if type(stopped) is SystemExit:
            stopped_code = stopped.code
            safe_exit_code = (
                stopped_code if stopped_code is None or type(stopped_code) is int else 1
            )
            return _CanonicalControlFlow("system_exit", safe_exit_code)
        if type(stopped) is GeneratorExit:
            return _CanonicalControlFlow("generator_exit")
        if type(stopped) is InvalidInputError:
            code = stopped.code
            if type(code) is str and code in _CANONICAL_REJECTION_CODES:
                return _CanonicalFailure(code, _CANONICAL_REJECTION_MESSAGE)
        return _CanonicalFailure(
            _CANONICAL_INTERNAL_CODE,
            _CANONICAL_INTERNAL_MESSAGE,
        )


def _finish_canonical_operation[T](
    outcome: _CanonicalSuccess[T] | _CanonicalFailure | _CanonicalControlFlow,
) -> T:
    if type(outcome) is _CanonicalControlFlow:
        if outcome.kind == "keyboard_interrupt":
            raise KeyboardInterrupt
        if outcome.kind == "system_exit":
            raise SystemExit(outcome.exit_code)
        raise GeneratorExit
    if type(outcome) is _CanonicalFailure:
        raise InvalidInputError(outcome.code, outcome.safe_message)
    if isinstance(outcome, _CanonicalSuccess):
        return outcome.value
    raise InvalidInputError(
        _CANONICAL_INTERNAL_CODE,
        _CANONICAL_INTERNAL_MESSAGE,
    )


def _validate_schema(value: object, definition: str, code: str, message: str) -> None:
    try:
        validate_instance(value, "canonical-records.schema.json", definition=definition)
    except SchemaValidationError:
        raise _invalid(code, message) from None


def _validate_json_descriptor(descriptor: Mapping[str, object]) -> None:
    _validate_schema(
        descriptor,
        "AuditDataset",
        "DATA.DESCRIPTOR_INVALID",
        "The audit dataset descriptor is invalid.",
    )
    try:
        canonical_json_bytes(descriptor)
    except CanonicalizationError:
        raise _invalid(
            "DATA.DESCRIPTOR_INVALID",
            "The audit dataset descriptor is not canonical strict JSON.",
        ) from None


def _mapping(value: object, *, code: str, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _invalid(code, message)
    return cast(Mapping[str, object], value)


def _record_sequence(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list):
        raise _invalid("DATA.DESCRIPTOR_INVALID", "The audit dataset descriptor is invalid.")
    return tuple(
        _mapping(
            item,
            code="DATA.DESCRIPTOR_INVALID",
            message="The audit dataset descriptor is invalid.",
        )
        for item in value
    )


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _invalid("DATA.DESCRIPTOR_INVALID", "The audit dataset descriptor is invalid.")
    return tuple(cast(list[str], value))


def _nfc_string(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not unicodedata.is_normalized("NFC", value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise _invalid("DATA.TABLE_INVALID", "A source column name is invalid.")
    return value


def _typed_key_from_value(value: object) -> TaggedScalarKey:
    if isinstance(value, (bool, np.bool_)):
        return "boolean", bool(value)
    if isinstance(value, str):
        return "string", value
    if isinstance(value, np.str_):
        return "string", str(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer", value
    if isinstance(value, np.integer) and not isinstance(value, np.bool_):
        return "integer", int(value)
    raise _invalid("DATA.TYPE_INVALID", "A typed scalar has an invalid value type.")


def _typed_key_from_record(record: Mapping[str, object]) -> TaggedScalarKey:
    scalar_type = record.get("type")
    value = record.get("value")
    if scalar_type == "string" and isinstance(value, str):
        return "string", value
    if scalar_type == "integer" and isinstance(value, int) and not isinstance(value, bool):
        return "integer", value
    if scalar_type == "boolean" and isinstance(value, bool):
        return "boolean", value
    raise _invalid("DATA.DESCRIPTOR_INVALID", "A declared typed scalar is invalid.")


def _comparison_key_from_record(
    record: Mapping[str, object],
) -> tuple[str, str | int | bool | float]:
    scalar_type = record.get("type")
    value = record.get("value")
    if scalar_type == "float64" and isinstance(value, (int, float)) and not isinstance(value, bool):
        result = float(value)
        if not math.isfinite(result):
            raise _invalid("DATA.GROUP_RULE_INVALID", "A group comparison value is invalid.")
        return "float64", result
    scalar_type_key, scalar_value = _typed_key_from_record(record)
    return scalar_type_key, scalar_value


def _comparison_key_from_value(value: object) -> tuple[str, str | int | bool | float]:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _invalid("DATA.GROUP_RULE_INVALID", "A group comparison value is invalid.")
        return "float64", value
    scalar_type, scalar_value = _typed_key_from_value(value)
    return scalar_type, scalar_value


def _normalize_source_scalar(value: object) -> tuple[object, dict[str, object]]:
    if isinstance(value, (bool, np.bool_)):
        normalized = bool(value)
        return normalized, {"type": "boolean", "value": normalized}
    if isinstance(value, str):
        normalized_string = value
    elif isinstance(value, np.str_):
        normalized_string = str(value)
    else:
        normalized_string = ""
    if isinstance(value, (str, np.str_)):
        if not unicodedata.is_normalized("NFC", normalized_string) or any(
            0xD800 <= ord(character) <= 0xDFFF for character in normalized_string
        ):
            raise _invalid("DATA.TABLE_INVALID", "A source string is not valid canonical text.")
        return normalized_string, {"type": "string", "value": normalized_string}
    if isinstance(value, int) and not isinstance(value, bool):
        normalized_integer = value
    elif isinstance(value, np.integer) and not isinstance(value, np.bool_):
        normalized_integer = int(value)
    else:
        normalized_integer = None
    if normalized_integer is not None:
        if abs(normalized_integer) > MAX_SAFE_INTEGER:
            raise _invalid("DATA.TABLE_INVALID", "A source integer is outside the safe range.")
        return normalized_integer, {"type": "integer", "value": normalized_integer}
    if isinstance(value, float):
        normalized_float = value
    elif isinstance(value, np.floating):
        if value.dtype.itemsize > 8:
            raise _invalid("DATA.TABLE_INVALID", "A source floating value is unsupported.")
        normalized_float = float(value)
    else:
        raise _invalid("DATA.TABLE_INVALID", "A source cell has an unsupported scalar type.")
    if math.isnan(normalized_float):
        return math.nan, {"type": "missing", "value": None}
    if not math.isfinite(normalized_float):
        raise _invalid("DATA.TABLE_INVALID", "An infinite source value is invalid.")
    return normalized_float, {"type": "float64", "value": normalized_float}


def _source_scalar_from_record(record: Mapping[str, object]) -> object:
    scalar_type = record.get("type")
    value = record.get("value")
    if scalar_type == "missing" and value is None:
        return math.nan
    if scalar_type == "boolean" and isinstance(value, bool):
        return value
    if scalar_type == "string" and isinstance(value, str):
        return value
    if scalar_type == "integer" and isinstance(value, int) and not isinstance(value, bool):
        return value
    if scalar_type == "float64" and isinstance(value, (int, float)) and not isinstance(value, bool):
        floating = float(value)
        if math.isfinite(floating):
            return floating
    raise _invalid("DATA.INGESTION_BINDING_INVALID", "A bound source scalar is invalid.")


def _column_values(value: object) -> tuple[tuple[object, ...], bool]:
    object_dtype = False
    if isinstance(value, np.ndarray):
        if value.ndim != 1:
            raise _invalid("DATA.TABLE_INVALID", "Every source column must be one-dimensional.")
        object_dtype = value.dtype.kind == "O"
        raw_values = tuple(value.tolist())
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        raw_values = tuple(value)
    else:
        raise _invalid("DATA.TABLE_INVALID", "Every source column must be a finite sequence.")
    normalized: list[object] = []
    for raw_value in raw_values:
        scalar, _record = _normalize_source_scalar(raw_value)
        normalized.append(scalar)
    return tuple(normalized), object_dtype


def _source_row_index_tuple(value: object, row_count: int) -> tuple[int, ...]:
    if isinstance(value, np.ndarray):
        if value.ndim != 1:
            raise _invalid("DATA.ROW_INDEX_INVALID", "The source-row sidecar is invalid.")
        raw = tuple(value.tolist())
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        raw = tuple(value)
    else:
        raise _invalid("DATA.ROW_INDEX_INVALID", "The source-row sidecar is invalid.")
    indexes: list[int] = []
    for item in raw:
        if isinstance(item, bool) or not isinstance(item, (int, np.integer)):
            raise _invalid("DATA.ROW_INDEX_INVALID", "The source-row sidecar is invalid.")
        indexes.append(int(item))
    result = tuple(indexes)
    if len(result) != row_count or set(result) != set(range(row_count)):
        raise _invalid(
            "DATA.ROW_INDEX_INVALID",
            "The source-row sidecar must be an exact permutation of the source rows.",
        )
    return result


def _declared_roles(descriptor: Mapping[str, object]) -> Mapping[str, str]:
    source_names = _string_sequence(descriptor["source_column_names"])
    roles: dict[str, str] = {}

    def assign(source_column: object, role: str) -> None:
        column = _nfc_string(source_column)
        if column in roles:
            raise _invalid(
                "DATA.ROLE_CLOSURE",
                "A source column has more than one declared role.",
            )
        roles[column] = role

    assign(descriptor["participant_private_id_column"], "participant-private-id")
    for event in _record_sequence(descriptor["event_specs"]):
        assign(event["source_column"], "event")
    group = _mapping(
        descriptor["group_spec"],
        code="DATA.DESCRIPTOR_INVALID",
        message="The audit dataset descriptor is invalid.",
    )
    group_source = _mapping(
        group["source_column_or_rule"],
        code="DATA.DESCRIPTOR_INVALID",
        message="The audit dataset descriptor is invalid.",
    )
    if group["source"] == "column":
        assign(group_source["source_column"], "group")
    else:
        for source_column in _string_sequence(group_source["source_columns"]):
            assign(source_column, "group")
    for covariate in _record_sequence(descriptor["covariate_specs"]):
        assign(covariate["source_column"], "covariate")
    for metadata in _record_sequence(descriptor["metadata_specs"]):
        assign(metadata["source_column"], "metadata")
    for ignored in _record_sequence(descriptor["ignored_columns"]):
        assign(ignored["source_column"], "ignored")
    if set(roles) != set(source_names) or len(roles) != len(source_names):
        raise _invalid(
            "DATA.ROLE_CLOSURE",
            "Every source column must have exactly one declared role.",
        )
    return MappingProxyType(roles)


def _validate_descriptor_cross_fields(descriptor: Mapping[str, object]) -> Mapping[str, str]:
    roles = _declared_roles(descriptor)
    event_specs = _record_sequence(descriptor["event_specs"])
    event_ids = tuple(cast(str, event["event_id"]) for event in event_specs)
    event_sources = tuple(cast(str, event["source_column"]) for event in event_specs)
    display_names = tuple(cast(str, event["display_name"]) for event in event_specs)
    effective_aliases = tuple(
        cast(str, event["privacy_sensitive_display_override"])
        if event["privacy_sensitive_display_override"] is not None
        else cast(str, event["display_name"])
        for event in event_specs
    )
    if (
        len(set(event_ids)) != len(event_ids)
        or len(set(event_sources)) != len(event_sources)
        or len(set(display_names)) != len(display_names)
        or len(set(effective_aliases)) != len(effective_aliases)
    ):
        raise _invalid(
            "DATA.EVENT_IDENTITY_AMBIGUOUS",
            "Event identifiers, source roles, and display aliases must be unambiguous.",
        )
    alias_owner: dict[str, str] = {}
    for event in event_specs:
        event_id = cast(str, event["event_id"])
        aliases = {cast(str, event["display_name"])}
        override = event["privacy_sensitive_display_override"]
        if isinstance(override, str):
            aliases.add(override)
        for alias in aliases:
            previous_owner = alias_owner.setdefault(alias, event_id)
            if previous_owner != event_id:
                raise _invalid(
                    "DATA.EVENT_IDENTITY_AMBIGUOUS",
                    "Event identifiers, source roles, and display aliases must be unambiguous.",
                )
    covariates = _record_sequence(descriptor["covariate_specs"])
    covariate_ids = tuple(cast(str, item["covariate_id"]) for item in covariates)
    if len(set(covariate_ids)) != len(covariate_ids):
        raise _invalid("DATA.COVARIATE_INVALID", "Covariate identifiers must be unique.")
    metadata_specs = _record_sequence(descriptor["metadata_specs"])
    metadata_ids = tuple(cast(str, item["metadata_id"]) for item in metadata_specs)
    if len(set(metadata_ids)) != len(metadata_ids):
        raise _invalid("DATA.METADATA_INVALID", "Metadata identifiers must be unique.")
    ignored = _record_sequence(descriptor["ignored_columns"])
    if any(not cast(str, item["reason"]).strip() for item in ignored):
        raise _invalid("DATA.ROLE_CLOSURE", "Every ignored source column needs a reason.")
    policy = descriptor["missingness_policy"]
    if any(event["missingness_declaration"] != policy for event in event_specs):
        raise _invalid(
            "DATA.MISSINGNESS_POLICY_CONFLICT",
            "Event missingness declarations must agree with the dataset policy.",
        )
    group = _mapping(
        descriptor["group_spec"],
        code="DATA.DESCRIPTOR_INVALID",
        message="The audit dataset descriptor is invalid.",
    )
    group_source = _mapping(
        group["source_column_or_rule"],
        code="DATA.DESCRIPTOR_INVALID",
        message="The audit dataset descriptor is invalid.",
    )
    required_roles = set(_string_sequence(group["required_roles"]))
    if group["source"] == "column":
        label_roles = {cast(str, item["role"]) for item in _record_sequence(group["label_to_role"])}
        if label_roles != required_roles:
            raise _invalid(
                "DATA.GROUP_INVALID",
                "Column group labels must exactly cover the required roles.",
            )
    else:
        role_rules = _record_sequence(group_source["role_rules"])
        rule_roles = tuple(cast(str, rule["role"]) for rule in role_rules)
        if len(set(rule_roles)) != len(rule_roles) or set(rule_roles) != required_roles:
            raise _invalid(
                "DATA.GROUP_RULE_INVALID",
                "Declarative group rules must exactly cover the required roles.",
            )
        used_columns: set[str] = set()
        for rule in role_rules:
            for clause in _record_sequence(rule["clauses"]):
                used_columns.add(cast(str, clause["source_column"]))
        if used_columns != set(_string_sequence(group_source["source_columns"])):
            raise _invalid(
                "DATA.GROUP_RULE_INVALID",
                "Declarative group rules must use exactly their declared source columns.",
            )
    return roles


def _admit_source(
    descriptor: Mapping[str, object],
    table: Mapping[str, object],
    source_row_indexes: object,
) -> _SourceAdmission:
    if not isinstance(table, Mapping):
        raise _invalid("DATA.TABLE_INVALID", "The supplied source table is invalid.")
    roles = _validate_descriptor_cross_fields(descriptor)
    source_names = _string_sequence(descriptor["source_column_names"])
    if any(not unicodedata.is_normalized("NFC", name) for name in source_names):
        raise _invalid("DATA.TABLE_INVALID", "A source column name is not Unicode NFC.")
    if any(not isinstance(key, str) for key in table) or set(table) != set(source_names):
        raise _invalid(
            "DATA.TABLE_INVALID",
            "The supplied table columns do not match the closed descriptor.",
        )
    row_count = cast(int, descriptor["source_table_row_count"])
    indexes = _source_row_index_tuple(source_row_indexes, row_count)
    canonical_positions = tuple(sorted(range(row_count), key=indexes.__getitem__))
    columns: dict[str, tuple[object, ...]] = {}
    object_dtype_columns: set[str] = set()
    catalog: list[dict[str, object]] = []
    column_preimages: list[dict[str, object]] = []
    for source_name in source_names:
        values, object_dtype = _column_values(table[source_name])
        if len(values) != row_count:
            raise _invalid(
                "DATA.TABLE_INVALID",
                "Every source column must match the declared row count.",
            )
        if object_dtype:
            object_dtype_columns.add(source_name)
        columns[source_name] = values
        ordered_records: list[dict[str, object]] = []
        observed_types: set[str] = set()
        missing_count = 0
        for position in canonical_positions:
            _normalized, record = _normalize_source_scalar(values[position])
            ordered_records.append(record)
            scalar_type = cast(str, record["type"])
            if scalar_type == "missing":
                missing_count += 1
            else:
                observed_types.add(scalar_type)
        logical_type = (
            next(iter(observed_types)) if len(observed_types) == 1 else "mixed-source-scalar"
        )
        column_preimage: dict[str, object] = {
            "column_preimage_schema_version": "ebm-audit-canonical-source-column/1.0",
            "source_column": source_name,
            "ordered_values": ordered_records,
        }
        _validate_schema(
            column_preimage,
            "CanonicalSourceColumnDigestPreimage",
            "DATA.TABLE_INVALID",
            "A source column cannot be represented canonically.",
        )
        column_preimages.append(column_preimage)
        catalog.append(
            {
                "source_column": source_name,
                "declared_role": roles[source_name],
                "logical_type": logical_type,
                "encoding_method": "typed-scalar-vector/1",
                "row_count": row_count,
                "missing_count": missing_count,
                "content_digest": structured_sha256(_SOURCE_COLUMN_DOMAIN, column_preimage),
            }
        )
    table_preimage: dict[str, object] = {
        "table_preimage_schema_version": "ebm-audit-canonical-source-table/1.0",
        "row_count": row_count,
        "ordered_columns": catalog,
    }
    _validate_schema(
        table_preimage,
        "CanonicalSourceTableDigestPreimage",
        "DATA.TABLE_INVALID",
        "The source table cannot be represented canonically.",
    )
    if len({entry["source_column"] for entry in catalog}) != len(catalog):
        raise _invalid("DATA.TABLE_INVALID", "The source-column catalog is ambiguous.")
    return _SourceAdmission(
        columns=MappingProxyType(columns),
        source_row_indexes=indexes,
        object_dtype_columns=frozenset(object_dtype_columns),
        column_preimages=tuple(MappingProxyType(item) for item in column_preimages),
        table_preimage=MappingProxyType(table_preimage),
        table_digest=structured_sha256(_SOURCE_TABLE_DOMAIN, table_preimage),
        row_count=row_count,
    )


def _compute_source_table_content_digest(
    descriptor: Mapping[str, object],
    table: Mapping[str, object],
    *,
    source_row_indexes: Sequence[int] | NDArray[np.int32] | NDArray[np.int64],
) -> str:
    """Compute the descriptor-role-bound, row-order-invariant source-table digest."""

    _validate_json_descriptor(descriptor)
    if not isinstance(table, Mapping):
        raise _invalid("DATA.TABLE_INVALID", "The supplied source table is invalid.")
    return _admit_source(descriptor, table, source_row_indexes).table_digest


def compute_source_table_content_digest(
    descriptor: Mapping[str, object],
    table: Mapping[str, object],
    *,
    source_row_indexes: Sequence[int] | NDArray[np.int32] | NDArray[np.int64],
) -> str:
    """Compute the canonical-table digest without retaining failure-frame values."""

    outcome = _capture_canonical_operation(
        lambda: _compute_source_table_content_digest(
            descriptor,
            table,
            source_row_indexes=source_row_indexes,
        )
    )
    descriptor = MappingProxyType({})
    table = MappingProxyType({})
    source_row_indexes = ()
    return _finish_canonical_operation(outcome)


def _private_identifier(value: object) -> PrivateParticipantId:
    try:
        identifier = validate_participant_private_id(value)
    except ParticipantIdentityError:
        raise _invalid("DATA.PRIVATE_ID_INVALID", "A private participant ID is invalid.") from None
    return identifier


def _numeric_cell(value: object, *, code: str, message: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _invalid(code, message)
    result = float(value)
    if math.isinf(result):
        raise _invalid(code, message)
    return result


def _event_matrix(
    admission: _SourceAdmission,
    event_specs: tuple[Mapping[str, object], ...],
) -> NDArray[np.float64]:
    columns: list[NDArray[np.float64]] = []
    for event in event_specs:
        source_column = cast(str, event["source_column"])
        if source_column in admission.object_dtype_columns:
            raise _invalid(
                "DATA.EVENT_VALUE_INVALID",
                "An event column has an unsupported object dtype.",
            )
        values = [
            _numeric_cell(
                value,
                code="DATA.EVENT_VALUE_INVALID",
                message="Event cells must be strict real numeric values or IEEE NaN.",
            )
            for value in admission.columns[source_column]
        ]
        columns.append(np.asarray(values, dtype=np.float64))
    return np.column_stack(columns).astype(np.float64, copy=False)


def _identifier_name_risk(source_column: str) -> bool:
    lowered = source_column.casefold()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    return (
        _IDENTIFIER_NAME.search(lowered) is not None
        or _IDENTIFIER_COMPACT_NAME.search(compact) is not None
    )


def _validate_identifier_event_risk(
    matrix: NDArray[np.float64], event_specs: tuple[Mapping[str, object], ...]
) -> None:
    for index, event in enumerate(event_specs):
        if cast(bool, event["identifier_risk_reviewed"]):
            continue
        values = matrix[:, index]
        finite = np.isfinite(values)
        integer_like_unique = (
            bool(finite.all())
            and bool(np.equal(values, np.floor(values)).all())
            and len(np.unique(values)) == len(values)
        )
        if integer_like_unique or _identifier_name_risk(cast(str, event["source_column"])):
            raise _invalid(
                "DATA.SUSPECT_IDENTIFIER_EVENT",
                "A selected event looks like an identifier and requires explicit review.",
            )


def _group_roles(descriptor: Mapping[str, object], admission: _SourceAdmission) -> tuple[str, ...]:
    group = _mapping(
        descriptor["group_spec"],
        code="DATA.DESCRIPTOR_INVALID",
        message="The audit dataset descriptor is invalid.",
    )
    source = _mapping(
        group["source_column_or_rule"],
        code="DATA.DESCRIPTOR_INVALID",
        message="The audit dataset descriptor is invalid.",
    )
    if group["source"] == "column":
        labels = _record_sequence(group["label_to_role"])
        label_map: dict[TaggedScalarKey, str] = {}
        for item in labels:
            key = _typed_key_from_record(
                _mapping(
                    item["label"],
                    code="DATA.DESCRIPTOR_INVALID",
                    message="A declared group label is invalid.",
                )
            )
            if key in label_map:
                raise _invalid("DATA.GROUP_INVALID", "Declared group labels must be unique.")
            label_map[key] = cast(str, item["role"])
        result: list[str] = []
        for value in admission.columns[cast(str, source["source_column"])]:
            if isinstance(value, float) and math.isnan(value):
                raise _invalid("DATA.GROUP_INVALID", "Group values must be complete and known.")
            try:
                key = _typed_key_from_value(value)
            except InvalidInputError:
                raise _invalid(
                    "DATA.GROUP_INVALID", "Group values must be complete and known."
                ) from None
            role = label_map.get(key)
            if role is None:
                raise _invalid("DATA.GROUP_INVALID", "Group values must be complete and known.")
            result.append(role)
        return tuple(result)

    role_rules = _record_sequence(source["role_rules"])
    result = []
    for row_index in range(admission.row_count):
        matched_roles: list[str] = []
        for rule in role_rules:
            clauses = _record_sequence(rule["clauses"])
            if all(_clause_matches(clause, admission, row_index) for clause in clauses):
                matched_roles.append(cast(str, rule["role"]))
        if len(matched_roles) != 1:
            raise _invalid(
                "DATA.GROUP_INVALID",
                "Every participant must match exactly one declared group role.",
            )
        result.append(matched_roles[0])
    return tuple(result)


def _clause_matches(
    clause: Mapping[str, object], admission: _SourceAdmission, row_index: int
) -> bool:
    value = admission.columns[cast(str, clause["source_column"])][row_index]
    if isinstance(value, float) and math.isnan(value):
        return False
    threshold_record = _mapping(
        clause["value"],
        code="DATA.DESCRIPTOR_INVALID",
        message="A declared group rule is invalid.",
    )
    threshold_type, threshold = _comparison_key_from_record(threshold_record)
    operator = cast(str, clause["operator"])
    if operator == "eq":
        try:
            return _comparison_key_from_value(value) == (threshold_type, threshold)
        except InvalidInputError:
            return False
    if (
        isinstance(value, bool)
        or isinstance(threshold, bool)
        or isinstance(value, str)
        or isinstance(threshold, str)
    ):
        raise _invalid("DATA.GROUP_RULE_INVALID", "A group rule uses an invalid comparison.")
    if not isinstance(value, (int, float)) or not isinstance(threshold, (int, float)):
        raise _invalid("DATA.GROUP_RULE_INVALID", "A group rule uses an invalid comparison.")
    left = float(value)
    right = float(threshold)
    if operator == "lt":
        return left < right
    if operator == "lte":
        return left <= right
    if operator == "gt":
        return left > right
    if operator == "gte":
        return left >= right
    raise _invalid("DATA.GROUP_RULE_INVALID", "A group rule uses an invalid operator.")


def _covariates(
    descriptor: Mapping[str, object], admission: _SourceAdmission
) -> tuple[
    dict[str, NDArray[np.float64] | NDArray[np.int32]],
    dict[str, PrivateCodebook],
    dict[str, str],
    NDArray[np.bool_],
]:
    arrays: dict[str, NDArray[np.float64] | NDArray[np.int32]] = {}
    codebooks: dict[str, PrivateCodebook] = {}
    codebook_digests: dict[str, str] = {}
    remove = np.zeros(admission.row_count, dtype=np.bool_)
    for spec in _record_sequence(descriptor["covariate_specs"]):
        array_name = f"covariate.{cast(str, spec['covariate_id'])}"
        values = admission.columns[cast(str, spec["source_column"])]
        missing = np.asarray(
            [isinstance(value, float) and math.isnan(value) for value in values],
            dtype=np.bool_,
        )
        missingness = cast(str, spec["missingness"])
        if bool(missing.any()):
            if missingness == "complete-case":
                remove |= missing
            else:
                raise _invalid(
                    "DATA.COVARIATE_INVALID",
                    "A required covariate contains an unresolved missing value.",
                )
        if spec["kind"] == "continuous":
            arrays[array_name] = np.asarray(
                [
                    _numeric_cell(
                        value,
                        code="DATA.COVARIATE_INVALID",
                        message="A continuous covariate must contain strict numeric values.",
                    )
                    for value in values
                ],
                dtype=np.float64,
            )
            continue
        level_records = _record_sequence(spec["level_order"])
        keys: list[TaggedScalarKey] = []
        private_levels: list[Mapping[str, object]] = []
        for level in level_records:
            key = _typed_key_from_record(level)
            if key in keys:
                raise _invalid(
                    "DATA.COVARIATE_INVALID",
                    "Categorical covariate levels must be unique by exact type.",
                )
            keys.append(key)
            private_levels.append(MappingProxyType(dict(level)))
        code_by_level = {key: index for index, key in enumerate(keys)}
        codes: list[int] = []
        for value, is_missing in zip(values, missing, strict=True):
            if bool(is_missing):
                codes.append(-1)
                continue
            try:
                key = _typed_key_from_value(value)
            except InvalidInputError:
                raise _invalid(
                    "DATA.COVARIATE_INVALID", "A categorical covariate value is undeclared."
                ) from None
            if key not in code_by_level:
                raise _invalid(
                    "DATA.COVARIATE_INVALID", "A categorical covariate value is undeclared."
                )
            codes.append(code_by_level[key])
        arrays[array_name] = np.asarray(codes, dtype=np.int32)
        codebook_preimage: dict[str, object] = {
            "codebook_schema_version": "ebm-audit-categorical-codebook/1.0",
            "array_name": array_name,
            "ordered_levels": [dict(level) for level in level_records],
        }
        _validate_schema(
            codebook_preimage,
            "CategoricalCodebookDigestPreimage",
            "DATA.COVARIATE_INVALID",
            "A categorical covariate codebook is invalid.",
        )
        codebooks[array_name] = tuple(private_levels)
        codebook_digests[array_name] = structured_sha256(
            _CATEGORICAL_CODEBOOK_DOMAIN, codebook_preimage
        )
    return arrays, codebooks, codebook_digests, remove


def _metadata(
    descriptor: Mapping[str, object], admission: _SourceAdmission
) -> dict[str, NDArray[np.float64] | NDArray[np.int64] | NDArray[np.bool_]]:
    arrays: dict[str, NDArray[np.float64] | NDArray[np.int64] | NDArray[np.bool_]] = {}
    for spec in _record_sequence(descriptor["metadata_specs"]):
        array_name = f"metadata.{cast(str, spec['metadata_id'])}"
        values = admission.columns[cast(str, spec["source_column"])]
        kind = cast(str, spec["kind"])
        if kind == "continuous":
            continuous = np.asarray(
                [
                    _numeric_cell(
                        value,
                        code="DATA.METADATA_INVALID",
                        message="Continuous metadata must contain strict numeric values.",
                    )
                    for value in values
                ],
                dtype=np.float64,
            )
            if spec["missingness"] == "error" and bool(np.isnan(continuous).any()):
                raise _invalid(
                    "DATA.METADATA_INVALID",
                    "A metadata column contains an unresolved missing value.",
                )
            arrays[array_name] = continuous
        elif kind == "integer":
            if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
                raise _invalid(
                    "DATA.METADATA_INVALID", "Integer metadata must contain exact integers."
                )
            arrays[array_name] = np.asarray(cast(tuple[int, ...], values), dtype=np.int64)
        else:
            if any(not isinstance(value, bool) for value in values):
                raise _invalid(
                    "DATA.METADATA_INVALID", "Boolean metadata must contain exact booleans."
                )
            arrays[array_name] = np.asarray(cast(tuple[bool, ...], values), dtype=np.bool_)
    return arrays


def _auxiliary_columns(
    descriptor: Mapping[str, object], codebook_digests: Mapping[str, str]
) -> tuple[AuxiliaryColumnBinding, ...]:
    covariates: list[AuxiliaryColumnBinding] = []
    for spec in _record_sequence(descriptor["covariate_specs"]):
        array_name = f"covariate.{cast(str, spec['covariate_id'])}"
        kind = cast(str, spec["kind"])
        codebook_digest: str | None = None
        if kind == "categorical":
            try:
                codebook_digest = codebook_digests[array_name]
            except KeyError:
                raise _invalid(
                    "DATA.COVARIATE_INVALID",
                    "A categorical covariate codebook binding is missing.",
                ) from None
        covariates.append(
            AuxiliaryColumnBinding(
                array_name=array_name,
                role="covariate",
                kind=kind,
                missingness=cast(str, spec["missingness"]),
                codebook_digest=codebook_digest,
            )
        )
    metadata = tuple(
        AuxiliaryColumnBinding(
            array_name=f"metadata.{cast(str, spec['metadata_id'])}",
            role="metadata",
            kind=cast(str, spec["kind"]),
            missingness=cast(str, spec["missingness"]),
            codebook_digest=None,
        )
        for spec in _record_sequence(descriptor["metadata_specs"])
    )
    return tuple(covariates) + metadata


def _categorical_preimages(
    codebooks: Mapping[str, PrivateCodebook],
) -> list[dict[str, object]]:
    return [
        {
            "codebook_schema_version": "ebm-audit-categorical-codebook/1.0",
            "array_name": name,
            "ordered_levels": [dict(level) for level in levels],
        }
        for name, levels in codebooks.items()
    ]


def _freeze_array(value: NDArray[np.generic]) -> CanonicalArray:
    array = np.asarray(value)
    if array.dtype.name not in {"bool", "int32", "int64", "float64"}:
        raise _invalid("DATA.ARRAY_INVALID", "A canonical data array has an invalid dtype.")
    canonical = np.ascontiguousarray(array, dtype=array.dtype.newbyteorder("<"))
    if canonical.dtype.name == "float64":
        canonical = canonical.copy()
        floating = cast(NDArray[np.float64], canonical)
        floating[np.isnan(floating)] = np.nan
    raw = canonical.tobytes(order="C")
    frozen = np.frombuffer(raw, dtype=canonical.dtype).reshape(canonical.shape)
    return cast(CanonicalArray, frozen)


def _catalog_entry(
    member_name: str, array: CanonicalArray, semantic_version: str
) -> ArrayCatalogEntry:
    raw = array.tobytes(order="C")
    preimage: dict[str, object] = {
        "member_name": member_name,
        "dtype": array.dtype.name,
        "shape": list(array.shape),
        "semantic_version": semantic_version,
        "byte_length": len(raw),
        "array_bytes_sha256": exact_file_sha256(raw),
    }
    entry = ArrayCatalogEntry(
        member_name=member_name,
        dtype=array.dtype.name,
        shape=tuple(array.shape),
        semantic_version=semantic_version,
        byte_length=len(raw),
        array_digest=structured_sha256(_ARRAY_DOMAIN, preimage),
    )
    _validate_schema(
        entry.to_record(),
        "ArrayCatalogEntry",
        "DATA.ARRAY_INVALID",
        "A canonical array catalog entry is invalid.",
    )
    return entry


def _selected_positions(
    identity_ids: tuple[PrivateParticipantId, ...],
    source_positions: tuple[int, ...],
    identity_map_rows: Sequence[object],
) -> tuple[int, ...]:
    position_by_id = {
        _typed_key_from_value(identifier): position
        for identifier, position in zip(identity_ids, source_positions, strict=True)
    }
    ordered: list[int] = []
    for row in identity_map_rows:
        private_id = getattr(row, "participant_private_id", None)
        ordered.append(position_by_id[_typed_key_from_value(private_id)])
    return tuple(ordered)


def _event_variation_is_valid(
    event_values: NDArray[np.float64], event_ids: tuple[str, ...]
) -> None:
    for index, _event_id in enumerate(event_ids):
        finite = event_values[:, index][np.isfinite(event_values[:, index])]
        if len(finite) == 0 or bool(np.equal(finite, finite[0]).all()):
            raise _invalid(
                "DATA.CONSTANT_EVENT", "A selected event is constant or has no finite signal."
            )
        value_range = float(np.max(finite) - np.min(finite))
        scale = max(1.0, float(np.max(np.abs(finite))))
        if value_range <= 1e-12 * scale:
            raise _invalid(
                "DATA.NEAR_CONSTANT_EVENT",
                "A selected event is near-constant under near-constant-range/1.",
            )


def _selected_row_manifest(
    variant_id: str, source_row_count: int, source_indexes: tuple[int, ...]
) -> tuple[dict[str, object], str]:
    participant_count = len(source_indexes)
    record: dict[str, object] = {
        "row_manifest_schema_version": "ebm-audit-selected-row-manifest/1.0",
        "variant_id": variant_id,
        "source_row_count": source_row_count,
        "ordered_internal_row_indexes": list(range(participant_count)),
        "source_row_index_by_internal_index": list(source_indexes),
    }
    _validate_schema(
        record,
        "SelectedRowManifestDigestPreimage",
        "DATA.ROW_MANIFEST_INVALID",
        "The selected-row manifest is invalid.",
    )
    if (
        tuple(cast(list[int], record["ordered_internal_row_indexes"]))
        != tuple(range(participant_count))
        or len(set(source_indexes)) != participant_count
        or any(index < 0 or index >= source_row_count for index in source_indexes)
    ):
        raise _invalid("DATA.ROW_MANIFEST_INVALID", "The selected-row manifest is invalid.")
    return record, structured_sha256(_SELECTED_ROW_MANIFEST_DOMAIN, record)


def _accounting(
    *,
    input_participants: int,
    output_participants: int,
    event_count: int,
    input_missing_cells: int,
    output_missing_cells: int,
    affected_event_ids: tuple[str, ...],
    affected_auxiliary_array_names: tuple[str, ...],
    universe_decision_id: str,
    missingness_digest: str,
    source_table_digest: str,
    selected_row_manifest_digest: str,
) -> DataAccounting:
    removed = input_participants - output_participants
    operations: tuple[AccountingOperation, ...] = ()
    if removed:
        operations = (
            AccountingOperation(
                operation_id="complete-case-removal",
                method_id="complete-case-v1",
                universe_decision_id=universe_decision_id,
                reason_code="DATA.COMPLETE_CASE_REMOVAL",
                rationale="Rows with missing required analysis cells were removed as declared.",
                participant_count=removed,
                event_count=event_count,
                cell_count=removed * event_count,
                affected_event_ids=affected_event_ids,
                affected_auxiliary_array_names=affected_auxiliary_array_names,
                parameter_digest=missingness_digest,
                input_digest=source_table_digest,
                output_digest=selected_row_manifest_digest,
            ),
        )
    accounting = DataAccounting(
        input_participants=input_participants,
        output_participants=output_participants,
        input_events=event_count,
        output_events=event_count,
        input_missing_cells=input_missing_cells,
        output_missing_cells=output_missing_cells,
        removed_participants=removed,
        operations=operations,
    )
    record = accounting.to_record()
    _validate_schema(
        record,
        "DataAccounting",
        "DATA.ACCOUNTING_INVALID",
        "The canonical data accounting record is invalid.",
    )
    if (
        accounting.input_participants
        + accounting.added_participant_instances
        - accounting.removed_participants
        != accounting.output_participants
        or accounting.input_events - accounting.output_events != accounting.removed_events
    ):
        raise _invalid("DATA.ACCOUNTING_INVALID", "The data-accounting arithmetic is invalid.")
    return accounting


def _validate_sha(value: str, code: str, message: str) -> None:
    _validate_schema(value, "Sha256Digest", code, message)


def _source_admission_preimage(
    admission: ValidatedSourceAdmission,
) -> dict[str, object]:
    preimage: dict[str, object] = {
        "admission_preimage_schema_version": "ebm-audit-source-admission/2.0",
        "parser_version": _PARSER_VERSION,
        "byte_digest": admission.byte_digest,
        "byte_length": admission.byte_length,
        "input_format_digest": admission.input_format_digest,
        "parsed_table_digest": admission.parsed_table_digest,
        "row_count": admission.row_count,
        "column_count": admission.column_count,
    }
    _validate_schema(
        preimage,
        "SourceAdmissionDigestPreimage",
        "DATA.EXACT_FILE_ADMISSION_INVALID",
        "The source admission digest preimage is invalid.",
    )
    if structured_sha256(_SOURCE_ADMISSION_DOMAIN, preimage) != admission.admission_id:
        raise _invalid(
            "DATA.EXACT_FILE_ADMISSION_INVALID",
            "The source admission identity is invalid.",
        )
    return preimage


def _exact_file_admission_proof(
    *,
    source_admission_id: str,
    source_admission_preimage: Mapping[str, object],
    exact_file_digest: str,
    canonical_source_table_digest: str,
    namespace_key_id_digest: str,
    namespace_key: object,
) -> dict[str, object]:
    """Seal one trusted exact-byte/table admission without retaining source bytes."""

    if not isinstance(namespace_key, _NamespaceKey):
        raise _invalid(
            "DATA.PRIVATE_ID_INVALID", "The private participant identity map is invalid."
        )
    try:
        key = namespace_key._validated_bytes()
    except (AttributeError, ParticipantIdentityError, TypeError):
        raise _invalid(
            "DATA.PRIVATE_ID_INVALID", "The private participant identity map is invalid."
        ) from None
    proof: dict[str, object] = {
        "proof_schema_version": "ebm-audit-exact-file-admission-proof/2.0",
        "method_id": "hmac-sha256-private-namespace-key/1",
        "source_admission_id": source_admission_id,
        "source_admission": dict(source_admission_preimage),
        "exact_file_digest": exact_file_digest,
        "canonical_source_table_digest": canonical_source_table_digest,
        "namespace_key_id_digest": namespace_key_id_digest,
    }
    message = _EXACT_FILE_ADMISSION_DOMAIN + b"\x00" + canonical_json_bytes(proof)
    proof["proof_mac"] = f"hmac-sha256:{hmac.new(key, message, hashlib.sha256).hexdigest()}"
    return proof


def _ingest_canonical_table_audit_dataset(
    descriptor: Mapping[str, object],
    table: Mapping[str, object],
    *,
    source_row_indexes: Sequence[int] | NDArray[np.int32] | NDArray[np.int64],
    component_digests: ComponentDigests,
    universe_decision_id: str,
    namespace_key: object | None = None,
) -> CanonicalDataset:
    """Canonicalize one caller-owned table under ``canonical-table/1``."""

    _validate_json_descriptor(descriptor)
    if not isinstance(table, Mapping):
        raise _invalid("DATA.TABLE_INVALID", "The supplied source table is invalid.")
    variant = _mapping(
        descriptor["variant"],
        code="DATA.DESCRIPTOR_INVALID",
        message="The audit dataset descriptor is invalid.",
    )
    if variant["source_digest_method"] != "canonical-table/1":
        raise _invalid(
            "DATA.DESCRIPTOR_INVALID",
            "Programmatic table ingestion requires canonical-table/1.",
        )
    admission = _admit_source(descriptor, table, source_row_indexes)
    return _ingest_admitted_audit_dataset(
        descriptor,
        admission,
        component_digests=component_digests,
        universe_decision_id=universe_decision_id,
        namespace_key=namespace_key,
        source_admission_id=None,
    )


def ingest_canonical_table_audit_dataset(
    descriptor: Mapping[str, object],
    table: Mapping[str, object],
    *,
    source_row_indexes: Sequence[int] | NDArray[np.int32] | NDArray[np.int64],
    component_digests: ComponentDigests,
    universe_decision_id: str,
    namespace_key: object | None = None,
) -> CanonicalDataset:
    """Canonicalize a programmatic table without retaining failure-frame values."""

    outcome = _capture_canonical_operation(
        lambda: _ingest_canonical_table_audit_dataset(
            descriptor,
            table,
            source_row_indexes=source_row_indexes,
            component_digests=component_digests,
            universe_decision_id=universe_decision_id,
            namespace_key=namespace_key,
        )
    )
    descriptor = MappingProxyType({})
    table = MappingProxyType({})
    source_row_indexes = ()
    component_digests = cast(ComponentDigests, None)
    universe_decision_id = ""
    namespace_key = None
    return _finish_canonical_operation(outcome)


def _ingest_exact_file_audit_dataset(
    descriptor: Mapping[str, object],
    source_admission: ValidatedSourceAdmission,
    *,
    component_digests: ComponentDigests,
    universe_decision_id: str,
    namespace_key: object | None = None,
) -> CanonicalDataset:
    """Canonicalize the sole private table owned by an exact-file admission."""

    _validate_json_descriptor(descriptor)
    variant = _mapping(
        descriptor["variant"],
        code="DATA.DESCRIPTOR_INVALID",
        message="The audit dataset descriptor is invalid.",
    )
    if variant["source_digest_method"] != "exact-file/1":
        raise _invalid(
            "DATA.DESCRIPTOR_INVALID",
            "Source-admission ingestion requires exact-file/1.",
        )
    try:
        table = _private_source_table(source_admission)
    except TypeError:
        raise _invalid(
            "DATA.EXACT_FILE_ADMISSION_INVALID",
            "A valid source admission capability is required.",
        ) from None
    if source_admission.byte_digest != variant["source_digest"]:
        raise _invalid(
            "DATA.SOURCE_DIGEST_MISMATCH",
            "The exact-file source digest does not match the admission capability.",
        )
    if source_admission.row_count != descriptor[
        "source_table_row_count"
    ] or source_admission.column_count != len(_string_sequence(descriptor["source_column_names"])):
        raise _invalid(
            "DATA.EXACT_FILE_ADMISSION_INVALID",
            "The source admission shape does not match the dataset descriptor.",
        )
    admission = _admit_source(
        descriptor,
        table,
        tuple(range(source_admission.row_count)),
    )
    return _ingest_admitted_audit_dataset(
        descriptor,
        admission,
        component_digests=component_digests,
        universe_decision_id=universe_decision_id,
        namespace_key=namespace_key,
        source_admission_id=source_admission.admission_id,
        source_admission_preimage=_source_admission_preimage(source_admission),
    )


def ingest_exact_file_audit_dataset(
    descriptor: Mapping[str, object],
    source_admission: ValidatedSourceAdmission,
    *,
    component_digests: ComponentDigests,
    universe_decision_id: str,
    namespace_key: object | None = None,
) -> CanonicalDataset:
    """Canonicalize an admitted exact file without retaining failure-frame values."""

    outcome = _capture_canonical_operation(
        lambda: _ingest_exact_file_audit_dataset(
            descriptor,
            source_admission,
            component_digests=component_digests,
            universe_decision_id=universe_decision_id,
            namespace_key=namespace_key,
        )
    )
    descriptor = MappingProxyType({})
    source_admission = cast(ValidatedSourceAdmission, None)
    component_digests = cast(ComponentDigests, None)
    universe_decision_id = ""
    namespace_key = None
    return _finish_canonical_operation(outcome)


def _ingest_admitted_audit_dataset(
    descriptor: Mapping[str, object],
    admission: _SourceAdmission,
    *,
    component_digests: ComponentDigests,
    universe_decision_id: str,
    namespace_key: object | None,
    source_admission_id: str | None,
    source_admission_preimage: Mapping[str, object] | None = None,
) -> CanonicalDataset:
    """Build canonical scientific state from one already-owned source table."""

    if not isinstance(component_digests, ComponentDigests):
        raise _invalid(
            "DATA.COMPONENT_DIGEST_INVALID",
            "Scientific component digests must use the closed typed input.",
        )
    _validate_sha(
        universe_decision_id,
        "DATA.UNIVERSE_DECISION_INVALID",
        "The universe decision identity is invalid.",
    )
    if admission.table_digest != descriptor["source_table_content_digest"]:
        raise _invalid(
            "DATA.SOURCE_DIGEST_MISMATCH",
            "The source table does not match its declared canonical content digest.",
        )
    variant = _mapping(
        descriptor["variant"],
        code="DATA.DESCRIPTOR_INVALID",
        message="The audit dataset descriptor is invalid.",
    )
    source_digest = cast(str, variant["source_digest"])
    if variant["source_digest_method"] == "canonical-table/1":
        if (
            source_admission_id is not None
            or source_admission_preimage is not None
            or source_digest != admission.table_digest
        ):
            raise _invalid(
                "DATA.SOURCE_DIGEST_MISMATCH",
                "The canonical-table source digest does not match the admitted table.",
            )
    elif source_admission_id is None or source_admission_preimage is None:
        raise _invalid(
            "DATA.EXACT_FILE_ADMISSION_INVALID",
            "Exact-file ingestion requires a valid source admission capability.",
        )

    private_id_column = cast(str, descriptor["participant_private_id_column"])
    private_ids = tuple(
        _private_identifier(value) for value in admission.columns[private_id_column]
    )
    typed_ids = tuple(_typed_key_from_value(value) for value in private_ids)
    if len(set(typed_ids)) != admission.row_count:
        raise _invalid("DATA.PRIVATE_ID_INVALID", "Private participant IDs must be unique.")

    event_specs = _record_sequence(descriptor["event_specs"])
    directions = tuple(cast(str, event["abnormal_direction"]) for event in event_specs)
    if any(direction == "REQUIRES_CONFIRMATION" for direction in directions):
        raise _invalid(
            "DATA.EVENT_DIRECTION_UNRESOLVED",
            "Every selected event direction must be confirmed before canonical ingestion.",
        )
    event_ids = tuple(cast(str, event["event_id"]) for event in event_specs)
    event_values = _event_matrix(admission, event_specs)
    _validate_identifier_event_risk(event_values, event_specs)
    missingness_mask = np.isnan(event_values)
    input_missing_cells = int(np.count_nonzero(missingness_mask))

    group_roles = _group_roles(descriptor, admission)
    covariates, codebooks, codebook_digests, covariate_remove = _covariates(descriptor, admission)
    metadata = _metadata(descriptor, admission)

    remove = covariate_remove.copy()
    missingness_policy = cast(str, descriptor["missingness_policy"])
    if missingness_policy == "error" and input_missing_cells:
        raise _invalid(
            "DATA.MISSING_EVENT_VALUE",
            "Selected event cells contain missing values under the error policy.",
        )
    if missingness_policy == "complete-case":
        remove |= np.any(missingness_mask, axis=1)
    selected_positions = tuple(
        position for position in range(admission.row_count) if not bool(remove[position])
    )
    if not selected_positions:
        raise _invalid("DATA.NO_SELECTED_ROWS", "No participants remain after declared selection.")

    required_roles = set(
        _string_sequence(
            _mapping(
                descriptor["group_spec"],
                code="DATA.DESCRIPTOR_INVALID",
                message="The audit dataset descriptor is invalid.",
            )["required_roles"]
        )
    )
    selected_role_set = {group_roles[position] for position in selected_positions}
    if not required_roles.issubset(selected_role_set):
        raise _invalid(
            "DATA.GROUP_INSUFFICIENT",
            "A required analysis group has no selected participants.",
        )

    selected_ids = tuple(private_ids[position] for position in selected_positions)
    effective_key = namespace_key if namespace_key is not None else generate_namespace_key()
    try:
        identity_map = build_identity_map(
            selected_ids,
            dataset_variant_id=cast(str, variant["variant_id"]),
            namespace_key=cast(_NamespaceKey, effective_key),
        )
    except ParticipantIdentityError:
        raise _invalid(
            "DATA.PRIVATE_ID_INVALID", "The private participant identity map is invalid."
        ) from None
    ordered_source_positions = _selected_positions(
        selected_ids, selected_positions, identity_map.rows
    )
    selected_event_values = event_values[list(ordered_source_positions), :]
    _event_variation_is_valid(selected_event_values, event_ids)

    arrays: dict[str, CanonicalArray] = {
        "participant_internal_indexes": _freeze_array(
            np.arange(len(ordered_source_positions), dtype=np.int64)
        ),
        "event_values": _freeze_array(selected_event_values),
        "missingness_mask": _freeze_array(np.isnan(selected_event_values)),
        "group_role_codes": _freeze_array(
            np.asarray(
                [_ROLE_CODES[group_roles[position]] for position in ordered_source_positions],
                dtype=np.int32,
            )
        ),
    }
    for name, values in covariates.items():
        arrays[name] = _freeze_array(values[list(ordered_source_positions)])
    for name, metadata_values in metadata.items():
        arrays[name] = _freeze_array(metadata_values[list(ordered_source_positions)])

    semantics = {
        "participant_internal_indexes": "participant-internal-index/1",
        "event_values": "event-value-matrix/1",
        "missingness_mask": "event-missingness-mask/1",
        "group_role_codes": "group-role-code/1",
    }
    catalog: dict[str, ArrayCatalogEntry] = {}
    for name, array in arrays.items():
        if name.startswith("covariate."):
            semantic_version = "covariate-column/1"
        elif name.startswith("metadata."):
            semantic_version = "metadata-column/1"
        else:
            semantic_version = semantics[name]
        catalog[name] = _catalog_entry(name, array, semantic_version)

    source_indexes_by_internal = tuple(
        admission.source_row_indexes[position] for position in ordered_source_positions
    )
    row_manifest, row_manifest_digest = _selected_row_manifest(
        cast(str, variant["variant_id"]), admission.row_count, source_indexes_by_internal
    )
    affected_event_ids = tuple(
        event_ids[index]
        for index in range(len(event_ids))
        if bool(np.any(missingness_mask[list(np.flatnonzero(remove)), index]))
    )
    missing_count_by_source = {
        cast(str, entry["source_column"]): cast(int, entry["missing_count"])
        for entry in cast(list[dict[str, object]], admission.table_preimage["ordered_columns"])
    }
    affected_auxiliary_array_names = tuple(
        f"covariate.{cast(str, spec['covariate_id'])}"
        for spec in _record_sequence(descriptor["covariate_specs"])
        if spec["missingness"] == "complete-case"
        and missing_count_by_source[cast(str, spec["source_column"])] > 0
    )
    output_missing_cells = int(np.count_nonzero(np.isnan(selected_event_values)))
    accounting = _accounting(
        input_participants=admission.row_count,
        output_participants=len(ordered_source_positions),
        event_count=len(event_ids),
        input_missing_cells=input_missing_cells,
        output_missing_cells=output_missing_cells,
        affected_event_ids=affected_event_ids,
        affected_auxiliary_array_names=affected_auxiliary_array_names,
        universe_decision_id=universe_decision_id,
        missingness_digest=component_digests.missingness_digest,
        source_table_digest=admission.table_digest,
        selected_row_manifest_digest=row_manifest_digest,
    )
    accounting_digest = structured_sha256(_DATA_ACCOUNTING_DOMAIN, accounting.to_record())
    required_covariates = tuple(
        f"covariate.{cast(str, spec['covariate_id'])}"
        for spec in _record_sequence(descriptor["covariate_specs"])
    )
    required_metadata = tuple(
        f"metadata.{cast(str, spec['metadata_id'])}"
        for spec in _record_sequence(descriptor["metadata_specs"])
    )
    auxiliary_columns = _auxiliary_columns(descriptor, codebook_digests)
    view = CanonicalDatasetView(
        variant_id=cast(str, variant["variant_id"]),
        participant_count=len(ordered_source_positions),
        event_count=len(event_ids),
        participant_internal_indexes=tuple(range(len(ordered_source_positions))),
        participant_aliases=tuple(row.participant_alias for row in identity_map.rows),
        event_ids=event_ids,
        event_directions=tuple(direction for direction in directions),
        required_covariate_array_names=required_covariates,
        required_metadata_array_names=required_metadata,
        auxiliary_columns=auxiliary_columns,
        array_catalog=catalog,
        source_row_manifest_digest=row_manifest_digest,
        data_accounting=accounting,
    )
    _validate_schema(
        view.to_record(),
        "CanonicalDatasetView",
        "DATA.CANONICAL_VIEW_INVALID",
        "The canonical dataset view is invalid.",
    )

    scientific_preimage: dict[str, object] = {
        "scientific_data_preimage_schema_version": "ebm-audit-scientific-data-preimage/1.0",
        "dataset_schema_version": "ebm-audit-dataset/1.0",
        "view_schema_version": "ebm-audit-canonical-dataset-view/1.0",
        "variant_id": view.variant_id,
        "source_digest": source_digest,
        "alias_namespace_method_version": _ALIAS_NAMESPACE_METHOD,
        "participant_token_method_version": _PARTICIPANT_TOKEN_METHOD,
        "ordered_participant_tokens": [row.participant_private_token for row in identity_map.rows],
        "ordered_internal_row_indexes": list(view.participant_internal_indexes),
        "selected_row_manifest_digest": row_manifest_digest,
        "event_ids": list(event_ids),
        "event_directions": list(view.event_directions),
        "required_covariate_array_names": list(required_covariates),
        "required_metadata_array_names": list(required_metadata),
        "auxiliary_columns": [binding.to_record() for binding in auxiliary_columns],
        "array_catalog": {name: entry.to_record() for name, entry in catalog.items()},
        "preprocessing_digest": component_digests.preprocessing_digest,
        "missingness_digest": component_digests.missingness_digest,
        "outlier_digest": component_digests.outlier_digest,
        "cohort_digest": component_digests.cohort_digest,
        "covariate_adjustment_digest": component_digests.covariate_adjustment_digest,
        "data_accounting_digest": accounting_digest,
        "participant_count": view.participant_count,
        "event_count": view.event_count,
        "cell_count": view.participant_count * view.event_count,
    }
    _validate_schema(
        scientific_preimage,
        "ScientificDataDigestPreimage",
        "DATA.SCIENTIFIC_PREIMAGE_INVALID",
        "The scientific data digest preimage is invalid.",
    )
    scientific_data_digest = structured_sha256(_SCIENTIFIC_DATA_DOMAIN, scientific_preimage)
    categorical_preimages = _categorical_preimages(codebooks)
    exact_file_admission_proof: dict[str, object] | None = None
    if variant["source_digest_method"] == "exact-file/1":
        assert source_admission_id is not None
        assert source_admission_preimage is not None
        exact_file_admission_proof = _exact_file_admission_proof(
            source_admission_id=source_admission_id,
            source_admission_preimage=source_admission_preimage,
            exact_file_digest=source_digest,
            canonical_source_table_digest=admission.table_digest,
            namespace_key_id_digest=identity_map.alias_namespace_id,
            namespace_key=effective_key,
        )
    ingestion_binding: dict[str, object] = {
        "binding_schema_version": "ebm-audit-canonical-ingestion-binding/2.0",
        "audit_dataset": cast(dict[str, object], _mutable_json(descriptor)),
        "canonical_source_columns": [
            cast(dict[str, object], _mutable_json(preimage))
            for preimage in admission.column_preimages
        ],
        "canonical_source_table": cast(dict[str, object], _mutable_json(admission.table_preimage)),
        "selected_row_manifest": row_manifest,
        "categorical_codebooks": categorical_preimages,
        "exact_file_admission_proof": exact_file_admission_proof,
        "canonical_view": view.to_record(),
        "scientific_data_preimage": scientific_preimage,
        "scientific_data_digest": scientific_data_digest,
    }
    _validate_schema(
        ingestion_binding,
        "CanonicalIngestionBinding",
        "DATA.INGESTION_BINDING_INVALID",
        "The private canonical ingestion binding is invalid.",
    )
    private = PrivateCanonicalDatasetState(
        identity_map=identity_map,
        namespace_key=effective_key,
        component_digests=component_digests,
        universe_decision_id=universe_decision_id,
        arrays=arrays,
        categorical_covariate_codebooks=codebooks,
        source_row_manifest=row_manifest,
        scientific_data_preimage=scientific_preimage,
        canonical_ingestion_binding=ingestion_binding,
    )
    result = CanonicalDataset(
        view=view,
        scientific_data_digest=scientific_data_digest,
        source_table_content_digest=admission.table_digest,
        private=private,
    )
    _validate_canonical_dataset(result)
    return result


def _mutable_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _mutable_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_mutable_json(item) for item in value]
    return value


def _validate_canonical_dataset(dataset: CanonicalDataset) -> None:
    """Recompute all ingestion-owned identities and closed cross-field invariants."""

    if not isinstance(dataset, CanonicalDataset):
        raise _invalid("DATA.CANONICAL_VIEW_INVALID", "The canonical dataset is invalid.")
    binding_value = _mutable_json(dataset.private.canonical_ingestion_binding)
    _validate_schema(
        binding_value,
        "CanonicalIngestionBinding",
        "DATA.INGESTION_BINDING_INVALID",
        "The private canonical ingestion binding is invalid.",
    )
    binding = cast(dict[str, object], binding_value)
    descriptor = _mapping(
        binding["audit_dataset"],
        code="DATA.INGESTION_BINDING_INVALID",
        message="The private canonical ingestion binding is invalid.",
    )
    _validate_descriptor_cross_fields(descriptor)
    view = dataset.view
    try:
        rebuilt_identity_map = build_identity_map(
            tuple(row.participant_private_id for row in dataset.private.identity_map.rows),
            dataset_variant_id=view.variant_id,
            namespace_key=cast(_NamespaceKey, dataset.private.namespace_key),
        )
    except ParticipantIdentityError:
        raise _invalid(
            "DATA.PRIVATE_ID_INVALID", "The private participant identity map is invalid."
        ) from None
    if rebuilt_identity_map != dataset.private.identity_map:
        raise _invalid(
            "DATA.PRIVATE_ID_INVALID", "The private participant identity map is inconsistent."
        )
    _validate_schema(
        view.to_record(),
        "CanonicalDatasetView",
        "DATA.CANONICAL_VIEW_INVALID",
        "The canonical dataset view is invalid.",
    )
    expected_names = {
        "participant_internal_indexes",
        "event_values",
        "missingness_mask",
        "group_role_codes",
        *view.required_covariate_array_names,
        *view.required_metadata_array_names,
    }
    if set(dataset.private.arrays) != expected_names or set(view.array_catalog) != expected_names:
        raise _invalid("DATA.CANONICAL_VIEW_INVALID", "The canonical array catalog is not closed.")
    expected_auxiliary_names = (
        view.required_covariate_array_names + view.required_metadata_array_names
    )
    observed_auxiliary_names = tuple(item.array_name for item in view.auxiliary_columns)
    if observed_auxiliary_names != expected_auxiliary_names or len(
        set(observed_auxiliary_names)
    ) != len(observed_auxiliary_names):
        raise _invalid(
            "DATA.CANONICAL_VIEW_INVALID",
            "The canonical auxiliary-column binding is not exact.",
        )
    expected_shapes = {
        "participant_internal_indexes": (view.participant_count,),
        "event_values": (view.participant_count, view.event_count),
        "missingness_mask": (view.participant_count, view.event_count),
        "group_role_codes": (view.participant_count,),
    }
    for name in view.required_covariate_array_names + view.required_metadata_array_names:
        expected_shapes[name] = (view.participant_count,)
    for name, array in dataset.private.arrays.items():
        expected_byte_order = "|" if array.dtype.name == "bool" else "<"
        if (
            array.flags.writeable
            or not array.flags.c_contiguous
            or array.dtype.byteorder != expected_byte_order
            or tuple(array.shape) != expected_shapes[name]
        ):
            raise _invalid("DATA.ARRAY_INVALID", "A canonical array is mutable or misaligned.")
        expected_semantic_version = (
            "covariate-column/1"
            if name.startswith("covariate.")
            else "metadata-column/1"
            if name.startswith("metadata.")
            else {
                "participant_internal_indexes": "participant-internal-index/1",
                "event_values": "event-value-matrix/1",
                "missingness_mask": "event-missingness-mask/1",
                "group_role_codes": "group-role-code/1",
            }[name]
        )
        if view.array_catalog[name].semantic_version != expected_semantic_version:
            raise _invalid("DATA.ARRAY_INVALID", "A canonical array semantic version is invalid.")
        observed = _catalog_entry(name, array, view.array_catalog[name].semantic_version)
        if observed != view.array_catalog[name]:
            raise _invalid("DATA.ARRAY_INVALID", "A canonical array digest does not match.")
    for auxiliary in view.auxiliary_columns:
        auxiliary_array = dataset.private.arrays[auxiliary.array_name]
        expected_dtype = {
            ("covariate", "continuous"): "float64",
            ("covariate", "categorical"): "int32",
            ("metadata", "continuous"): "float64",
            ("metadata", "integer"): "int64",
            ("metadata", "boolean"): "bool",
        }.get((auxiliary.role, auxiliary.kind))
        if expected_dtype is None or auxiliary_array.dtype.name != expected_dtype:
            raise _invalid(
                "DATA.CANONICAL_VIEW_INVALID",
                "An auxiliary column has an inconsistent role, kind, or dtype.",
            )
    indexes = dataset.private.arrays["participant_internal_indexes"]
    if (
        indexes.dtype.name != "int64"
        or dataset.private.arrays["event_values"].dtype.name != "float64"
        or dataset.private.arrays["missingness_mask"].dtype.name != "bool"
        or dataset.private.arrays["group_role_codes"].dtype.name != "int32"
    ):
        raise _invalid("DATA.ARRAY_INVALID", "A required canonical array dtype is invalid.")
    if not np.array_equal(indexes, np.arange(view.participant_count, dtype=np.int64)):
        raise _invalid(
            "DATA.CANONICAL_VIEW_INVALID", "Participant internal indexes are not contiguous."
        )
    event_values = cast(NDArray[np.float64], dataset.private.arrays["event_values"])
    missingness = cast(NDArray[np.bool_], dataset.private.arrays["missingness_mask"])
    if bool(np.isinf(event_values).any()) or not np.array_equal(
        missingness, np.isnan(event_values)
    ):
        raise _invalid("DATA.ARRAY_INVALID", "Event values and missingness are inconsistent.")
    _event_variation_is_valid(event_values, view.event_ids)
    group_codes = dataset.private.arrays["group_role_codes"]
    if not bool(np.isin(group_codes, np.asarray([0, 1], dtype=np.int32)).all()):
        raise _invalid("DATA.GROUP_INVALID", "The canonical group-role codes are invalid.")
    if (
        view.participant_internal_indexes != tuple(range(view.participant_count))
        or len(view.participant_aliases) != view.participant_count
        or len(view.event_ids) != view.event_count
        or len(view.event_directions) != view.event_count
    ):
        raise _invalid("DATA.CANONICAL_VIEW_INVALID", "Canonical view axes are inconsistent.")

    row_manifest = _mutable_json(dataset.private.source_row_manifest)
    _validate_schema(
        row_manifest,
        "SelectedRowManifestDigestPreimage",
        "DATA.ROW_MANIFEST_INVALID",
        "The selected-row manifest is invalid.",
    )
    if structured_sha256(_SELECTED_ROW_MANIFEST_DOMAIN, row_manifest) != (
        view.source_row_manifest_digest
    ):
        raise _invalid("DATA.ROW_MANIFEST_INVALID", "The selected-row manifest digest differs.")
    row_record = cast(dict[str, object], row_manifest)
    descriptor_variant = _mapping(
        descriptor["variant"],
        code="DATA.INGESTION_BINDING_INVALID",
        message="The private canonical ingestion binding is invalid.",
    )
    if (
        row_record["variant_id"] != descriptor_variant["variant_id"]
        or row_record["variant_id"] != view.variant_id
        or row_record["source_row_count"] != descriptor["source_table_row_count"]
    ):
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "The selected-row manifest axes do not match their owners.",
        )
    if row_record["ordered_internal_row_indexes"] != list(range(view.participant_count)):
        raise _invalid("DATA.ROW_MANIFEST_INVALID", "The selected-row manifest is misaligned.")
    source_rows = cast(list[int], row_record["source_row_index_by_internal_index"])
    source_row_count = cast(int, row_record["source_row_count"])
    if (
        len(source_rows) != view.participant_count
        or len(set(source_rows)) != len(source_rows)
        or any(row < 0 or row >= source_row_count for row in source_rows)
    ):
        raise _invalid("DATA.ROW_MANIFEST_INVALID", "The selected-row manifest is misaligned.")

    declared_codebook_digests = {
        auxiliary.array_name: auxiliary.codebook_digest
        for auxiliary in view.auxiliary_columns
        if auxiliary.kind == "categorical"
    }
    if set(dataset.private.categorical_covariate_codebooks) != set(declared_codebook_digests):
        raise _invalid("DATA.COVARIATE_INVALID", "Categorical codebook closure differs.")
    for name, levels in dataset.private.categorical_covariate_codebooks.items():
        preimage: dict[str, object] = {
            "codebook_schema_version": "ebm-audit-categorical-codebook/1.0",
            "array_name": name,
            "ordered_levels": [dict(level) for level in levels],
        }
        _validate_schema(
            preimage,
            "CategoricalCodebookDigestPreimage",
            "DATA.COVARIATE_INVALID",
            "A categorical codebook is invalid.",
        )
        if (
            structured_sha256(_CATEGORICAL_CODEBOOK_DOMAIN, preimage)
            != (declared_codebook_digests[name])
        ):
            raise _invalid("DATA.COVARIATE_INVALID", "A categorical codebook digest differs.")

    accounting_record = view.data_accounting.to_record()
    _validate_schema(
        accounting_record,
        "DataAccounting",
        "DATA.ACCOUNTING_INVALID",
        "The data accounting record is invalid.",
    )
    descriptor_event_count = len(_record_sequence(descriptor["event_specs"]))
    if (
        view.data_accounting.input_events != descriptor_event_count
        or view.data_accounting.output_events != descriptor_event_count
    ):
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "The data-accounting event axis does not match the dataset descriptor.",
        )
    if (
        view.data_accounting.output_participants != view.participant_count
        or view.data_accounting.output_events != view.event_count
        or view.data_accounting.removed_participants
        != view.data_accounting.input_participants - view.participant_count
        or view.data_accounting.output_missing_cells != int(np.count_nonzero(missingness))
    ):
        raise _invalid("DATA.ACCOUNTING_INVALID", "The data accounting record is inconsistent.")

    scientific_preimage_value = _mutable_json(dataset.private.scientific_data_preimage)
    _validate_schema(
        scientific_preimage_value,
        "ScientificDataDigestPreimage",
        "DATA.SCIENTIFIC_PREIMAGE_INVALID",
        "The scientific data digest preimage is invalid.",
    )
    record = cast(dict[str, object], scientific_preimage_value)
    component_digests = dataset.private.component_digests
    if not isinstance(component_digests, ComponentDigests):
        raise _invalid(
            "DATA.COMPONENT_DIGEST_INVALID",
            "Scientific component digests must use the closed typed input.",
        )
    _validate_sha(
        dataset.private.universe_decision_id,
        "DATA.UNIVERSE_DECISION_INVALID",
        "The universe decision identity is invalid.",
    )
    expected_catalog = {name: entry.to_record() for name, entry in view.array_catalog.items()}
    expected_tokens = [row.participant_private_token for row in dataset.private.identity_map.rows]
    if (
        record["variant_id"] != view.variant_id
        or record["alias_namespace_method_version"] != _ALIAS_NAMESPACE_METHOD
        or record["participant_token_method_version"] != _PARTICIPANT_TOKEN_METHOD
        or record["ordered_internal_row_indexes"] != list(view.participant_internal_indexes)
        or record["ordered_participant_tokens"] != expected_tokens
        or record["selected_row_manifest_digest"] != view.source_row_manifest_digest
        or record["event_ids"] != list(view.event_ids)
        or record["event_directions"] != list(view.event_directions)
        or record["required_covariate_array_names"] != list(view.required_covariate_array_names)
        or record["required_metadata_array_names"] != list(view.required_metadata_array_names)
        or record["auxiliary_columns"]
        != [binding.to_record() for binding in view.auxiliary_columns]
        or record["array_catalog"] != expected_catalog
        or record["preprocessing_digest"] != component_digests.preprocessing_digest
        or record["missingness_digest"] != component_digests.missingness_digest
        or record["outlier_digest"] != component_digests.outlier_digest
        or record["cohort_digest"] != component_digests.cohort_digest
        or record["covariate_adjustment_digest"] != component_digests.covariate_adjustment_digest
        or record["data_accounting_digest"]
        != structured_sha256(_DATA_ACCOUNTING_DOMAIN, accounting_record)
        or record["participant_count"] != view.participant_count
        or record["event_count"] != view.event_count
        or record["cell_count"] != view.participant_count * view.event_count
    ):
        raise _invalid(
            "DATA.SCIENTIFIC_PREIMAGE_INVALID",
            "The scientific data digest preimage is inconsistent.",
        )
    if structured_sha256(_SCIENTIFIC_DATA_DOMAIN, record) != dataset.scientific_data_digest:
        raise _invalid("DATA.SCIENTIFIC_PREIMAGE_INVALID", "The scientific data digest differs.")
    _validate_sha(
        dataset.source_table_content_digest,
        "DATA.SOURCE_DIGEST_MISMATCH",
        "The source table content digest is invalid.",
    )

    source_table = _mapping(
        binding["canonical_source_table"],
        code="DATA.INGESTION_BINDING_INVALID",
        message="The private canonical ingestion binding is invalid.",
    )
    source_catalog = _record_sequence(source_table["ordered_columns"])
    source_names = _string_sequence(descriptor["source_column_names"])
    source_column_preimages = _record_sequence(binding["canonical_source_columns"])
    if (
        tuple(cast(str, entry["source_column"]) for entry in source_catalog) != source_names
        or tuple(cast(str, preimage["source_column"]) for preimage in source_column_preimages)
        != source_names
        or source_table["row_count"] != descriptor["source_table_row_count"]
        or any(entry["row_count"] != source_table["row_count"] for entry in source_catalog)
        or any(
            cast(int, entry["missing_count"]) > cast(int, entry["row_count"])
            for entry in source_catalog
        )
    ):
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "The source catalog does not exactly match the dataset descriptor.",
        )
    replayed_columns: dict[str, tuple[object, ...]] = {}
    for source_preimage, catalog_entry in zip(source_column_preimages, source_catalog, strict=True):
        ordered_records = _record_sequence(source_preimage["ordered_values"])
        if len(ordered_records) != cast(int, source_table["row_count"]):
            raise _invalid(
                "DATA.INGESTION_BINDING_INVALID",
                "A bound source column has the wrong row count.",
            )
        observed_types = {
            cast(str, item["type"]) for item in ordered_records if item["type"] != "missing"
        }
        logical_type = (
            next(iter(observed_types)) if len(observed_types) == 1 else "mixed-source-scalar"
        )
        missing_count = sum(item["type"] == "missing" for item in ordered_records)
        if (
            structured_sha256(_SOURCE_COLUMN_DOMAIN, source_preimage)
            != catalog_entry["content_digest"]
            or catalog_entry["logical_type"] != logical_type
            or catalog_entry["missing_count"] != missing_count
        ):
            raise _invalid(
                "DATA.INGESTION_BINDING_INVALID",
                "A bound source column digest or catalog fact differs.",
            )
        replayed_columns[cast(str, source_preimage["source_column"])] = tuple(
            _source_scalar_from_record(item) for item in ordered_records
        )
    roles = _declared_roles(descriptor)
    if any(
        entry["declared_role"] != roles[cast(str, entry["source_column"])]
        for entry in source_catalog
    ):
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "The source catalog role partition does not match the descriptor.",
        )
    recomputed_source_table_digest = structured_sha256(_SOURCE_TABLE_DOMAIN, source_table)
    if (
        recomputed_source_table_digest != dataset.source_table_content_digest
        or recomputed_source_table_digest != descriptor["source_table_content_digest"]
    ):
        raise _invalid("DATA.SOURCE_DIGEST_MISMATCH", "The bound source table digest differs.")
    replay_admission = _SourceAdmission(
        columns=MappingProxyType(replayed_columns),
        source_row_indexes=tuple(range(cast(int, source_table["row_count"]))),
        object_dtype_columns=frozenset(),
        column_preimages=tuple(source_column_preimages),
        table_preimage=source_table,
        table_digest=recomputed_source_table_digest,
        row_count=cast(int, source_table["row_count"]),
    )
    variant = _mapping(
        descriptor["variant"],
        code="DATA.INGESTION_BINDING_INVALID",
        message="The private canonical ingestion binding is invalid.",
    )
    if (
        variant["source_digest_method"] == "canonical-table/1"
        and variant["source_digest"] != recomputed_source_table_digest
    ):
        raise _invalid(
            "DATA.SOURCE_DIGEST_MISMATCH", "The canonical variant source digest differs."
        )
    proof_value = binding["exact_file_admission_proof"]
    if variant["source_digest_method"] == "exact-file/1":
        proof = _mapping(
            proof_value,
            code="DATA.EXACT_FILE_ADMISSION_INVALID",
            message="The exact-file admission proof is invalid.",
        )
        source_admission_preimage = _mapping(
            proof["source_admission"],
            code="DATA.EXACT_FILE_ADMISSION_INVALID",
            message="The source admission digest preimage is invalid.",
        )
        recomputed_source_admission_id = structured_sha256(
            _SOURCE_ADMISSION_DOMAIN, dict(source_admission_preimage)
        )
        if (
            proof["source_admission_id"] != recomputed_source_admission_id
            or source_admission_preimage["byte_digest"] != proof["exact_file_digest"]
            or source_admission_preimage["byte_digest"] != variant["source_digest"]
            or source_admission_preimage["row_count"] != descriptor["source_table_row_count"]
            or source_admission_preimage["column_count"] != len(source_names)
        ):
            raise _invalid(
                "DATA.EXACT_FILE_ADMISSION_INVALID",
                "The exact-file proof does not match its source admission or descriptor.",
            )
        expected_proof = _exact_file_admission_proof(
            source_admission_id=recomputed_source_admission_id,
            source_admission_preimage=source_admission_preimage,
            exact_file_digest=cast(str, variant["source_digest"]),
            canonical_source_table_digest=recomputed_source_table_digest,
            namespace_key_id_digest=dataset.private.identity_map.alias_namespace_id,
            namespace_key=dataset.private.namespace_key,
        )
        if not hmac.compare_digest(
            canonical_json_bytes(proof), canonical_json_bytes(expected_proof)
        ):
            raise _invalid(
                "DATA.EXACT_FILE_ADMISSION_INVALID",
                "The exact-file admission proof does not bind this canonical source table.",
            )
    elif proof_value is not None:
        raise _invalid(
            "DATA.EXACT_FILE_ADMISSION_INVALID",
            "Canonical-table variants must not carry an exact-file admission proof.",
        )
    if variant["variant_id"] != view.variant_id:
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "The dataset variant does not match the canonical view.",
        )
    event_specs = _record_sequence(descriptor["event_specs"])
    descriptor_event_ids = tuple(cast(str, event["event_id"]) for event in event_specs)
    descriptor_directions = tuple(cast(str, event["abnormal_direction"]) for event in event_specs)
    covariate_specs = _record_sequence(descriptor["covariate_specs"])
    metadata_specs = _record_sequence(descriptor["metadata_specs"])
    expected_covariate_names = tuple(
        f"covariate.{cast(str, spec['covariate_id'])}" for spec in covariate_specs
    )
    expected_metadata_names = tuple(
        f"metadata.{cast(str, spec['metadata_id'])}" for spec in metadata_specs
    )
    if (
        descriptor_event_ids != view.event_ids
        or descriptor_directions != view.event_directions
        or expected_covariate_names != view.required_covariate_array_names
        or expected_metadata_names != view.required_metadata_array_names
    ):
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "The canonical view axes do not match the dataset descriptor.",
        )
    replayed = replay_admission
    if _mutable_json(replayed.table_preimage) != _mutable_json(source_table):
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "The bound source-column digests do not match the source-table catalog.",
        )
    replay_private_ids = tuple(
        _private_identifier(value)
        for value in replayed.columns[cast(str, descriptor["participant_private_id_column"])]
    )
    if len({_typed_key_from_value(value) for value in replay_private_ids}) != replayed.row_count:
        raise _invalid("DATA.PRIVATE_ID_INVALID", "Private participant IDs must be unique.")
    replay_event_values = _event_matrix(replayed, event_specs)
    _validate_identifier_event_risk(replay_event_values, event_specs)
    replay_missingness = np.isnan(replay_event_values)
    replay_group_roles = _group_roles(descriptor, replayed)
    (
        replay_covariates,
        replay_codebooks,
        _replay_codebook_digests,
        replay_covariate_remove,
    ) = _covariates(descriptor, replayed)
    replay_metadata = _metadata(descriptor, replayed)
    replay_remove = replay_covariate_remove.copy()
    if descriptor["missingness_policy"] == "error" and bool(replay_missingness.any()):
        raise _invalid(
            "DATA.MISSING_EVENT_VALUE",
            "Selected event cells contain missing values under the error policy.",
        )
    if descriptor["missingness_policy"] == "complete-case":
        replay_remove |= np.any(replay_missingness, axis=1)
    replay_selected_positions = tuple(
        position for position in range(replayed.row_count) if not bool(replay_remove[position])
    )
    if not replay_selected_positions:
        raise _invalid("DATA.NO_SELECTED_ROWS", "No participants remain after declared selection.")
    replay_selected_ids = tuple(
        replay_private_ids[position] for position in replay_selected_positions
    )
    try:
        replay_identity_map = build_identity_map(
            replay_selected_ids,
            dataset_variant_id=view.variant_id,
            namespace_key=cast(_NamespaceKey, dataset.private.namespace_key),
        )
    except ParticipantIdentityError:
        raise _invalid(
            "DATA.PRIVATE_ID_INVALID", "The private participant identity map is invalid."
        ) from None
    replay_ordered_positions = _selected_positions(
        replay_selected_ids,
        replay_selected_positions,
        replay_identity_map.rows,
    )
    replay_selected_events = replay_event_values[list(replay_ordered_positions), :]
    _event_variation_is_valid(replay_selected_events, descriptor_event_ids)
    replay_arrays: dict[str, CanonicalArray] = {
        "participant_internal_indexes": _freeze_array(
            np.arange(len(replay_ordered_positions), dtype=np.int64)
        ),
        "event_values": _freeze_array(replay_selected_events),
        "missingness_mask": _freeze_array(np.isnan(replay_selected_events)),
        "group_role_codes": _freeze_array(
            np.asarray(
                [
                    _ROLE_CODES[replay_group_roles[position]]
                    for position in replay_ordered_positions
                ],
                dtype=np.int32,
            )
        ),
    }
    for name, covariate_values in replay_covariates.items():
        replay_arrays[name] = _freeze_array(covariate_values[list(replay_ordered_positions)])
    for name, metadata_values in replay_metadata.items():
        replay_arrays[name] = _freeze_array(metadata_values[list(replay_ordered_positions)])
    if set(replay_arrays) != set(dataset.private.arrays) or any(
        expected.dtype != dataset.private.arrays[name].dtype
        or expected.shape != dataset.private.arrays[name].shape
        or expected.tobytes(order="C") != dataset.private.arrays[name].tobytes(order="C")
        for name, expected in replay_arrays.items()
    ):
        raise _invalid(
            "DATA.ARRAY_INVALID",
            "A canonical array does not match the replayed source derivation.",
        )
    if replay_identity_map != dataset.private.identity_map:
        raise _invalid(
            "DATA.PRIVATE_ID_INVALID",
            "The identity map does not match the replayed source derivation.",
        )
    replay_source_indexes = tuple(
        replayed.source_row_indexes[position] for position in replay_ordered_positions
    )
    replay_manifest, replay_manifest_digest = _selected_row_manifest(
        view.variant_id, replayed.row_count, replay_source_indexes
    )
    if replay_manifest != row_record or replay_manifest_digest != view.source_row_manifest_digest:
        raise _invalid(
            "DATA.ROW_MANIFEST_INVALID",
            "The selected-row manifest does not match the replayed source derivation.",
        )
    if _categorical_preimages(replay_codebooks) != _categorical_preimages(
        dataset.private.categorical_covariate_codebooks
    ):
        raise _invalid(
            "DATA.COVARIATE_INVALID",
            "The categorical codebooks do not match the replayed source derivation.",
        )
    replay_removed_positions = list(np.flatnonzero(replay_remove))
    replay_affected_event_ids = tuple(
        descriptor_event_ids[index]
        for index in range(len(descriptor_event_ids))
        if bool(np.any(replay_missingness[replay_removed_positions, index]))
    )
    replay_missing_count_by_source = {
        cast(str, entry["source_column"]): cast(int, entry["missing_count"])
        for entry in _record_sequence(replayed.table_preimage["ordered_columns"])
    }
    replay_affected_auxiliary_names = tuple(
        name
        for name, spec in zip(expected_covariate_names, covariate_specs, strict=True)
        if spec["missingness"] == "complete-case"
        and replay_missing_count_by_source[cast(str, spec["source_column"])] > 0
    )
    replay_accounting = _accounting(
        input_participants=replayed.row_count,
        output_participants=len(replay_ordered_positions),
        event_count=len(descriptor_event_ids),
        input_missing_cells=int(np.count_nonzero(replay_missingness)),
        output_missing_cells=int(np.count_nonzero(np.isnan(replay_selected_events))),
        affected_event_ids=replay_affected_event_ids,
        affected_auxiliary_array_names=replay_affected_auxiliary_names,
        universe_decision_id=dataset.private.universe_decision_id,
        missingness_digest=component_digests.missingness_digest,
        source_table_digest=replayed.table_digest,
        selected_row_manifest_digest=replay_manifest_digest,
    )
    if replay_accounting != view.data_accounting:
        raise _invalid(
            "DATA.ACCOUNTING_INVALID",
            "Data accounting does not match the replayed source derivation.",
        )

    input_event_missing_cells = sum(
        cast(int, entry["missing_count"])
        for entry in source_catalog
        if entry["declared_role"] == "event"
    )
    if (
        view.data_accounting.input_missing_cells != input_event_missing_cells
        or view.data_accounting.input_missing_cells < view.data_accounting.output_missing_cells
        or view.data_accounting.input_missing_cells - view.data_accounting.output_missing_cells
        > view.data_accounting.removed_participants * view.event_count
        or (
            descriptor["missingness_policy"] in {"error", "complete-case"}
            and bool(missingness.any())
        )
        or view.data_accounting.flagged_cells != 0
        or view.data_accounting.masked_cells != 0
        or view.data_accounting.transformed_cells != 0
        or view.data_accounting.removed_events != 0
    ):
        raise _invalid(
            "DATA.ACCOUNTING_INVALID",
            "The canonical data accounting does not match source missingness.",
        )
    expected_auxiliary_records = [
        {
            "array_name": name,
            "role": "covariate",
            "kind": spec["kind"],
            "missingness": spec["missingness"],
            "codebook_digest": declared_codebook_digests.get(name),
        }
        for name, spec in zip(expected_covariate_names, covariate_specs, strict=True)
    ] + [
        {
            "array_name": name,
            "role": "metadata",
            "kind": spec["kind"],
            "missingness": spec["missingness"],
            "codebook_digest": None,
        }
        for name, spec in zip(expected_metadata_names, metadata_specs, strict=True)
    ]
    if [item.to_record() for item in view.auxiliary_columns] != expected_auxiliary_records:
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "Auxiliary-column meaning does not match the dataset descriptor.",
        )
    for name, spec in zip(expected_covariate_names, covariate_specs, strict=True):
        array = dataset.private.arrays[name]
        if spec["kind"] == "continuous":
            continuous = cast(NDArray[np.float64], array)
            if not bool(np.isfinite(continuous).all()):
                raise _invalid(
                    "DATA.COVARIATE_INVALID",
                    "A canonical continuous covariate is not complete and finite.",
                )
            continue
        levels = dataset.private.categorical_covariate_codebooks[name]
        declared_levels = _record_sequence(spec["level_order"])
        if [dict(level) for level in levels] != [dict(level) for level in declared_levels]:
            raise _invalid(
                "DATA.COVARIATE_INVALID",
                "A categorical codebook does not match its covariate declaration.",
            )
        codes = cast(NDArray[np.int32], array)
        if not bool(((codes >= 0) & (codes < len(levels))).all()):
            raise _invalid("DATA.COVARIATE_INVALID", "A categorical covariate code is undeclared.")
    for name, spec in zip(expected_metadata_names, metadata_specs, strict=True):
        if spec["kind"] != "continuous":
            continue
        continuous_metadata = cast(NDArray[np.float64], dataset.private.arrays[name])
        if bool(np.isinf(continuous_metadata).any()) or (
            spec["missingness"] == "error" and bool(np.isnan(continuous_metadata).any())
        ):
            raise _invalid(
                "DATA.METADATA_INVALID",
                "A canonical continuous metadata column violates its missingness declaration.",
            )
    group_spec = _mapping(
        descriptor["group_spec"],
        code="DATA.INGESTION_BINDING_INVALID",
        message="The private canonical ingestion binding is invalid.",
    )
    required_group_codes = {
        _ROLE_CODES[role] for role in _string_sequence(group_spec["required_roles"])
    }
    if not required_group_codes.issubset(set(cast(NDArray[np.int32], group_codes).tolist())):
        raise _invalid(
            "DATA.GROUP_INSUFFICIENT",
            "A required analysis group has no canonical participants.",
        )
    if (
        view.participant_aliases
        != tuple(row.participant_alias for row in dataset.private.identity_map.rows)
        or tuple(row.participant_internal_index for row in dataset.private.identity_map.rows)
        != tuple(range(view.participant_count))
        or row_record["variant_id"] != view.variant_id
        or row_record["source_row_count"] != descriptor["source_table_row_count"]
        or view.data_accounting.input_participants != descriptor["source_table_row_count"]
        or view.data_accounting.input_events != len(event_specs)
        or view.data_accounting.output_events != len(event_specs)
    ):
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "Identity, row-manifest, or accounting axes do not match the descriptor.",
        )
    operations = view.data_accounting.operations
    removed_count = view.data_accounting.removed_participants
    removal_is_declared = descriptor["missingness_policy"] == "complete-case" or any(
        spec["missingness"] == "complete-case" for spec in covariate_specs
    )
    if removed_count and not removal_is_declared:
        raise _invalid(
            "DATA.ACCOUNTING_INVALID",
            "Participant removal is not authorized by a complete-case declaration.",
        )
    if removed_count == 0 and operations:
        raise _invalid(
            "DATA.ACCOUNTING_INVALID", "Unchanged input has an unexpected accounting operation."
        )
    if removed_count:
        missing_by_source = {
            cast(str, entry["source_column"]): cast(int, entry["missing_count"])
            for entry in source_catalog
        }
        all_missing_event_ids = tuple(
            cast(str, event["event_id"])
            for event in event_specs
            if missing_by_source[cast(str, event["source_column"])] > 0
        )
        expected_affected_event_ids = (
            all_missing_event_ids
            if descriptor["missingness_policy"] == "complete-case"
            else ()
            if descriptor["missingness_policy"] == "error"
            else None
        )
        expected_affected_auxiliary_names = tuple(
            name
            for name, spec in zip(expected_covariate_names, covariate_specs, strict=True)
            if spec["missingness"] == "complete-case"
            and missing_by_source[cast(str, spec["source_column"])] > 0
        )
        if len(operations) != 1:
            raise _invalid(
                "DATA.ACCOUNTING_INVALID",
                "Participant removal requires one exact accounting operation.",
            )
        operation = operations[0]
        if (
            operation.operation_id != "complete-case-removal"
            or operation.method_id != "complete-case-v1"
            or operation.reason_code != "DATA.COMPLETE_CASE_REMOVAL"
            or operation.rationale
            != "Rows with missing required analysis cells were removed as declared."
            or operation.participant_count != removed_count
            or operation.event_count != view.event_count
            or operation.cell_count != removed_count * view.event_count
            or (
                expected_affected_event_ids is not None
                and operation.affected_event_ids != expected_affected_event_ids
            )
            or any(
                event_id not in all_missing_event_ids for event_id in operation.affected_event_ids
            )
            or operation.affected_event_ids
            != tuple(
                event_id
                for event_id in all_missing_event_ids
                if event_id in set(operation.affected_event_ids)
            )
            or operation.affected_auxiliary_array_names != expected_affected_auxiliary_names
            or operation.parameter_digest != record["missingness_digest"]
            or operation.input_digest != recomputed_source_table_digest
            or operation.output_digest != view.source_row_manifest_digest
            or operation.universe_decision_id != dataset.private.universe_decision_id
        ):
            raise _invalid(
                "DATA.ACCOUNTING_INVALID",
                "The participant-removal accounting operation is inconsistent.",
            )
    categorical_preimages = _categorical_preimages(dataset.private.categorical_covariate_codebooks)
    if (
        binding["selected_row_manifest"] != row_manifest
        or binding["categorical_codebooks"] != categorical_preimages
        or binding["canonical_view"] != view.to_record()
        or binding["scientific_data_preimage"] != record
        or binding["scientific_data_digest"] != dataset.scientific_data_digest
        or record["source_digest"] != variant["source_digest"]
    ):
        raise _invalid(
            "DATA.INGESTION_BINDING_INVALID",
            "The private canonical ingestion binding is internally inconsistent.",
        )


def validate_canonical_dataset(dataset: CanonicalDataset) -> None:
    """Validate a canonical dataset without retaining it in failure frames."""

    outcome = _capture_canonical_operation(lambda: _validate_canonical_dataset(dataset))
    dataset = cast(CanonicalDataset, None)
    _finish_canonical_operation(outcome)


__all__ = [
    "AccountingOperation",
    "ArrayCatalogEntry",
    "AuxiliaryColumnBinding",
    "CanonicalDataset",
    "CanonicalDatasetView",
    "ComponentDigests",
    "DataAccounting",
    "PrivateCanonicalDatasetState",
    "compute_source_table_content_digest",
    "ingest_canonical_table_audit_dataset",
    "ingest_exact_file_audit_dataset",
    "validate_canonical_dataset",
]
