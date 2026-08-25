"""Load the normative schema bytes from package resources.

The wheel build force-includes the repository's tracked ``schemas/`` directory
at ``ebm_audit/schemas``. Source-tree execution falls back to that same
tracked directory. There is no generated or hand-maintained second copy.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any


class ResourceNotFoundError(RuntimeError):
    """Raised when a required normative resource is unavailable."""


# Closed resource vocabulary for this protocol version. Keeping this list
# explicit prevents a caller-controlled path from becoming a resource lookup.
RESOURCE_FILENAMES: tuple[str, ...] = (
    "analysis-universe.schema.json",
    "analyst-decision-evidence.schema.json",
    "audit-config.schema.json",
    "baseline-reference-bundle.schema.json",
    "baseline-reference-validation-receipt.schema.json",
    "canonical-records.schema.json",
    "cli-lifecycle-registry.json",
    "comparator-transaction.schema.json",
    "development-candidate-source-receipt.schema.json",
    "development-null-receipt.schema.json",
    "evaluator-receipts.schema.json",
    "influence-evidence.schema.json",
    "matched-moderate-source.schema.json",
    "null-evidence.schema.json",
    "participant-stage-comparison.schema.json",
    "profile-characterization-run.schema.json",
    "profile-plan-provenance.schema.json",
    "protocol-registry.json",
    "report-input.schema.json",
    "report-model.schema.json",
    "report.schema.json",
    "run-artifacts.schema.json",
    "run-status.schema.json",
    "sampling-evidence.schema.json",
    "scenario-derivation-registry.schema.json",
    "scenario-evidence.schema.json",
    "scenario-family-payload.schema.json",
    "scenario-fixture-contract.schema.json",
    "scenario-fixture-evidence.schema.json",
    "scenario-fixture-predicate.schema.json",
    "scenario-predicate.schema.json",
    "scientific-invariant-counterexample.schema.json",
    "scientific-invariant.schema.json",
    "source-set-manifest.schema.json",
    "synthetic-resolved-configuration.schema.json",
    "synthetic-scientific-data.schema.json",
    "synthetic-truth.schema.json",
    "worker-protocol.schema.json",
)

SCHEMA_FILENAMES: tuple[str, ...] = tuple(
    name for name in RESOURCE_FILENAMES if name.endswith(".schema.json")
)


def _source_schema_directory() -> Path | None:
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "schemas"
        if (candidate / "worker-protocol.schema.json").is_file():
            return candidate
    return None


def resource_bytes(name: str) -> bytes:
    """Return exact tracked/package bytes for one closed resource name."""

    if name not in RESOURCE_FILENAMES:
        raise ResourceNotFoundError("Unknown normative resource name.")

    packaged = resources.files("ebm_audit").joinpath("schemas", name)
    try:
        if packaged.is_file():
            return packaged.read_bytes()
    except (FileNotFoundError, OSError, TypeError):
        # A source checkout has no duplicated resource directory. Fall through
        # to the tracked repository schema bytes.
        pass

    source_directory = _source_schema_directory()
    if source_directory is None:
        raise ResourceNotFoundError("Required normative resource is unavailable.")
    candidate = source_directory / name
    try:
        return candidate.read_bytes()
    except OSError as exc:
        raise ResourceNotFoundError("Required normative resource is unreadable.") from exc


def schema_bytes(name: str) -> bytes:
    """Return exact bytes for a closed JSON Schema resource."""

    if name not in SCHEMA_FILENAMES:
        raise ResourceNotFoundError("Unknown JSON Schema resource name.")
    return resource_bytes(name)


def _decode_json_bytes(data: bytes) -> Any:
    if data.startswith(b"\xef\xbb\xbf"):
        raise ResourceNotFoundError("Normative JSON resources must not contain a BOM.")
    try:
        text = data.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ResourceNotFoundError("Normative JSON resource is invalid.") from exc


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> Any:
    raise ValueError(f"non-JSON numeric constant: {value}")


def load_resource_json(name: str) -> Any:
    """Parse one exact resource into a fresh JSON value."""

    return _decode_json_bytes(resource_bytes(name))


def load_schema(name: str) -> dict[str, Any]:
    """Load one exact schema into a fresh mapping."""

    value = _decode_json_bytes(schema_bytes(name))
    if not isinstance(value, dict):
        raise ResourceNotFoundError("Normative JSON Schema root must be an object.")
    return value


def load_protocol_registry() -> dict[str, Any]:
    """Load the complete closed worker protocol registry."""

    value = load_resource_json("protocol-registry.json")
    if not isinstance(value, dict):
        raise ResourceNotFoundError("Protocol registry root must be an object.")
    return value
