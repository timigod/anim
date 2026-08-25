"""Fail-closed Draft 2020-12 validation for the packaged contracts."""

from __future__ import annotations

import math
import re
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from hashlib import sha256
from threading import RLock
from typing import Any, cast
from unicodedata import category, is_normalized

import rfc8785
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)
from referencing import Registry, Resource

from .catalog import SCHEMA_FILENAMES, load_schema

_SCHEMA_BASE_URI = "https://schemas.ebm-audit.invalid/"
_SUCCESSFUL_VALIDATION_CACHE_LIMIT = 4096
_SUCCESSFUL_VALIDATION_CACHE: OrderedDict[tuple[str, str | None, bytes], None] = OrderedDict()
_SUCCESSFUL_VALIDATION_CACHE_LOCK = RLock()
_RFC3339_DATE_TIME = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
    r"[Tt](?P<hour>[01][0-9]|2[0-3]):(?P<minute>[0-5][0-9]):"
    r"(?P<second>[0-5][0-9]|60)(?:\.[0-9]+)?"
    r"(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)


@dataclass(frozen=True, slots=True)
class SchemaViolation:
    """A privacy-safe schema failure without the rejected value."""

    instance_location: str
    schema_keyword: str
    schema_location: str


class SchemaValidationError(ValueError):
    """Raised when a value does not satisfy its exact closed schema."""

    def __init__(
        self,
        *,
        schema_name: str,
        definition: str | None,
        violations: Sequence[SchemaViolation],
    ) -> None:
        self.schema_name = schema_name
        self.definition = definition
        self.violations = tuple(violations)
        owner = schema_name if definition is None else f"{schema_name}#/$defs/{definition}"
        first = self.violations[0] if self.violations else None
        suffix = ""
        if first is not None:
            suffix = f" First failure: {first.schema_keyword} at {first.instance_location}."
        super().__init__(
            f"Value failed closed schema validation for {owner} "
            f"({len(self.violations)} violation(s)).{suffix}"
        )


def _format_checker() -> FormatChecker:
    checker = FormatChecker()

    def _unicode_nfc(value: object) -> bool:
        return isinstance(value, str) and is_normalized("NFC", value)

    def _participant_private_id_text(value: object) -> bool:
        if (
            not isinstance(value, str)
            or not value
            or value.isspace()
            or not is_normalized("NFC", value)
        ):
            return False
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return False
        return all(category(character) not in {"Cc", "Cf", "Cs"} for character in value)

    def _rfc3339_date_time(value: object) -> bool:
        if not isinstance(value, str):
            return False
        match = _RFC3339_DATE_TIME.fullmatch(value)
        if match is None:
            return False
        date.fromisoformat(match.group("date"))
        if match.group("second") == "60":
            return match.group("hour") == "23" and match.group("minute") == "59"
        return True

    def _finite_number(value: object) -> bool:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        try:
            return math.isfinite(float(value))
        except (OverflowError, TypeError, ValueError):
            return False

    checker.checks("unicode-nfc", raises=(TypeError,))(_unicode_nfc)
    checker.checks("participant-private-id-text")(_participant_private_id_text)
    checker.checks("date-time", raises=(TypeError, ValueError))(_rfc3339_date_time)
    checker.checks("finite-number")(_finite_number)

    return checker


@lru_cache(maxsize=1)
def _schema_registry() -> Registry[Any]:
    pairs: list[tuple[str, Resource[Any]]] = []
    for name in SCHEMA_FILENAMES:
        schema = load_schema(name)
        pairs.append((_SCHEMA_BASE_URI + name, Resource.from_contents(schema)))
    return Registry().with_resources(pairs).crawl()


def _validation_schema(schema_name: str, definition: str | None) -> dict[str, Any]:
    schema = load_schema(schema_name)
    if definition is None:
        return {"$schema": schema["$schema"], "$ref": _SCHEMA_BASE_URI + schema_name}
    definitions = schema.get("$defs")
    if not isinstance(definitions, Mapping) or definition not in definitions:
        raise ValueError("Unknown schema definition.")
    return {
        "$schema": schema["$schema"],
        "$ref": f"{_SCHEMA_BASE_URI}{schema_name}#/$defs/{definition}",
    }


def _safe_instance_location(path: Iterable[object]) -> str:
    # Do not echo mapping keys: a malformed mapping key could be a private ID or
    # raw source label. Sequence indexes are safe and useful for diagnosis.
    segments = [f"[{part}]" if isinstance(part, int) else "<field>" for part in path]
    return "$" + "".join(segments)


def _schema_location(path: Iterable[object]) -> str:
    segments = [str(part).replace("~", "~0").replace("/", "~1") for part in path]
    return "#/" + "/".join(segments) if segments else "#"


def _leaf_errors(error: ValidationError) -> Iterable[ValidationError]:
    if not error.context:
        yield error
        return
    for child in error.context:
        yield from _leaf_errors(child)


def collect_validation_errors(
    instance: object,
    schema_name: str,
    *,
    definition: str | None = None,
) -> tuple[SchemaViolation, ...]:
    """Return deterministic, privacy-safe violations for one exact contract."""

    cache_key: tuple[str, str | None, bytes] | None = None
    with suppress(rfc8785.CanonicalizationError, OverflowError, TypeError, ValueError):
        cache_key = (
            schema_name,
            definition,
            sha256(rfc8785.dumps(cast(Any, instance))).digest(),
        )
    if cache_key is not None:
        with _SUCCESSFUL_VALIDATION_CACHE_LOCK:
            if cache_key in _SUCCESSFUL_VALIDATION_CACHE:
                _SUCCESSFUL_VALIDATION_CACHE.move_to_end(cache_key)
                return ()

    validator = Draft202012Validator(
        _validation_schema(schema_name, definition),
        registry=_schema_registry(),
        format_checker=_format_checker(),
    )
    leaves: list[ValidationError] = []
    for error in validator.iter_errors(instance):
        leaves.extend(_leaf_errors(error))
    leaves.sort(
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            tuple(str(part) for part in error.absolute_schema_path),
            str(error.validator),
        )
    )
    if not leaves and cache_key is not None:
        with _SUCCESSFUL_VALIDATION_CACHE_LOCK:
            _SUCCESSFUL_VALIDATION_CACHE[cache_key] = None
            _SUCCESSFUL_VALIDATION_CACHE.move_to_end(cache_key)
            while len(_SUCCESSFUL_VALIDATION_CACHE) > _SUCCESSFUL_VALIDATION_CACHE_LIMIT:
                _SUCCESSFUL_VALIDATION_CACHE.popitem(last=False)
    return tuple(
        SchemaViolation(
            instance_location=_safe_instance_location(error.absolute_path),
            schema_keyword=str(error.validator or "reference"),
            schema_location=_schema_location(error.absolute_schema_path),
        )
        for error in leaves
    )


def validate_instance(
    instance: object,
    schema_name: str,
    *,
    definition: str | None = None,
) -> None:
    """Validate against the exact schema and raise a safe closed failure."""

    violations = collect_validation_errors(instance, schema_name, definition=definition)
    if violations:
        raise SchemaValidationError(
            schema_name=schema_name,
            definition=definition,
            violations=violations,
        )


def _iter_nested_settings_schemas(schema: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    yield schema
    schema_type = schema.get("type")
    if schema_type == "object":
        properties = schema.get("properties", {})
        if isinstance(properties, Mapping):
            for child in properties.values():
                if isinstance(child, Mapping):
                    yield from _iter_nested_settings_schemas(child)
    elif schema_type == "array":
        items = schema.get("items")
        if isinstance(items, Mapping):
            yield from _iter_nested_settings_schemas(items)


def validate_settings_schema(schema: object) -> None:
    """Validate the inline closed settings schema and its required-key rule."""

    validate_instance(
        schema,
        "worker-protocol.schema.json",
        definition="ClosedSettingsSchema",
    )
    assert isinstance(schema, Mapping)  # established by the schema above
    for nested in _iter_nested_settings_schemas(schema):
        if nested.get("type") != "object":
            continue
        required = nested.get("required", [])
        properties = nested.get("properties", {})
        if not isinstance(required, list) or not isinstance(properties, Mapping):
            raise SchemaValidationError(
                schema_name="worker-protocol.schema.json",
                definition="ClosedSettingsSchema",
                violations=(SchemaViolation("$", "required", "#/$runtime-required-subset"),),
            )
        if any(name not in properties for name in required):
            raise SchemaValidationError(
                schema_name="worker-protocol.schema.json",
                definition="ClosedSettingsSchema",
                violations=(SchemaViolation("$", "required", "#/$runtime-required-subset"),),
            )


def validate_settings(settings: object, settings_schema: object) -> None:
    """Validate settings against an already validated inline schema, offline."""

    validate_settings_schema(settings_schema)
    assert isinstance(settings_schema, Mapping)
    validator = Draft202012Validator(settings_schema, format_checker=_format_checker())
    errors = tuple(validator.iter_errors(settings))
    if errors:
        violations = tuple(
            SchemaViolation(
                _safe_instance_location(error.absolute_path),
                str(error.validator or "reference"),
                _schema_location(error.absolute_schema_path),
            )
            for error in errors
        )
        raise SchemaValidationError(
            schema_name="inline-worker-settings-schema",
            definition=None,
            violations=violations,
        )
