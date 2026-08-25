"""Exact packaged schemas and fail-closed JSON Schema validation."""

from __future__ import annotations

from .catalog import (
    RESOURCE_FILENAMES,
    ResourceNotFoundError,
    load_protocol_registry,
    load_resource_json,
    load_schema,
    resource_bytes,
    schema_bytes,
)
from .validation import (
    SchemaValidationError,
    SchemaViolation,
    collect_validation_errors,
    validate_instance,
    validate_settings,
    validate_settings_schema,
)

__all__ = [
    "RESOURCE_FILENAMES",
    "ResourceNotFoundError",
    "SchemaValidationError",
    "SchemaViolation",
    "collect_validation_errors",
    "load_protocol_registry",
    "load_resource_json",
    "load_schema",
    "resource_bytes",
    "schema_bytes",
    "validate_instance",
    "validate_settings",
    "validate_settings_schema",
]

