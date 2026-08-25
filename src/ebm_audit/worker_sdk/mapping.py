"""Canonical admission for researcher-authored Fit results."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ebm_audit.protocol import strict_json_loads
from ebm_audit.workers.arrays import (
    array_catalog_entry,
    canonical_array,
    load_catalogued_npz_arrays,
)
from ebm_audit.workers.types import WorkerFailure, WorkerSuccess

from .records import (
    SDKValidationError,
    WarningRecord,
    _mapping_from_bytes,
    _validated_bytes,
)


def map_fit_result(
    source: Mapping[str, Any] | Path,
    *,
    arrays: Mapping[str, Any] | None = None,
    array_archive: Path | None = None,
    warnings: Iterable[WarningRecord | Mapping[str, Any]] | None = None,
) -> WorkerSuccess | WorkerFailure:
    """Map an in-memory or local JSON Fit payload to the worker callback types.

    The input is an exact ``FitSuccessPayload`` mapping. Canonical validation
    rejects unknown or malformed fields; no defaults are added, so every
    supplied field is preserved and every absent field remains absent.

    Raw arrays are never embedded in JSON. For a local JSON payload, pass its
    NPZ companion explicitly as ``array_archive``. In-memory callers may pass
    ``arrays`` instead; the two array inputs are mutually exclusive. Every
    supplied array must exactly match the payload's closed ``array_catalog``.
    """

    try:
        value: object = (
            strict_json_loads(source.read_bytes()) if isinstance(source, Path) else source
        )
        if not isinstance(value, Mapping):
            raise SDKValidationError(
                phase="fit-result-validation",
                field="fit_result",
            )
        encoded = _validated_bytes(
            value,
            schema_name="worker-protocol.schema.json",
            definition="FitSuccessPayload",
            phase="fit-result-validation",
            field="fit_result",
        )
        payload = _mapping_from_bytes(encoded)
        result = payload.get("result")
        if not isinstance(result, Mapping):
            raise SDKValidationError(
                phase="fit-result-validation",
                field="fit_result.result",
            )
        catalog = result.get("array_catalog")
        if not isinstance(catalog, Mapping):
            raise SDKValidationError(
                phase="fit-result-validation",
                field="fit_result.result.array_catalog",
            )
        if arrays is not None and array_archive is not None:
            raise SDKValidationError(
                phase="fit-result-validation",
                field="fit_result.arrays",
            )
        if catalog and arrays is None and array_archive is None:
            raise SDKValidationError(
                phase="fit-result-validation",
                field="fit_result.arrays",
            )

        mapped_arrays: dict[str, Any] | None = None
        if array_archive is not None:
            mapped_arrays = load_catalogued_npz_arrays(
                array_archive,
                catalog=catalog,
            )
        elif arrays is not None:
            if set(arrays) != set(catalog):
                raise SDKValidationError(
                    phase="fit-result-validation",
                    field="fit_result.arrays",
                )
            mapped_arrays = {}
            for name, supplied in arrays.items():
                declared = catalog.get(name)
                if not isinstance(declared, Mapping):
                    raise SDKValidationError(
                        phase="fit-result-validation",
                        field="fit_result.arrays",
                    )
                semantic_version = declared.get("semantic_version")
                if not isinstance(semantic_version, str):
                    raise SDKValidationError(
                        phase="fit-result-validation",
                        field="fit_result.arrays",
                    )
                array = canonical_array(supplied)
                observed = array_catalog_entry(
                    name,
                    array,
                    semantic_version=semantic_version,
                )
                if observed != dict(declared):
                    raise SDKValidationError(
                        phase="fit-result-validation",
                        field="fit_result.arrays",
                    )
                mapped_arrays[name] = array

        mapped_warnings: tuple[Mapping[str, Any], ...] | None = None
        if warnings is not None:
            admitted_warnings: list[Mapping[str, Any]] = []
            for warning in warnings:
                warning_mapping = (
                    warning.to_mapping() if isinstance(warning, WarningRecord) else warning
                )
                warning_bytes = _validated_bytes(
                    warning_mapping,
                    schema_name="canonical-records.schema.json",
                    definition="WarningRecord",
                    phase="fit-result-validation",
                    field="fit_result.warnings",
                )
                admitted_warnings.append(_mapping_from_bytes(warning_bytes))
            mapped_warnings = tuple(admitted_warnings)
    except Exception:
        return WorkerFailure(
            status="PROTOCOL_ERROR",
            code="FIT.RESULT_INVALID",
            safe_message="The Fit result does not match the canonical schema.",
            phase="fit-result-validation",
        )
    if mapped_arrays is None and mapped_warnings is None:
        return WorkerSuccess(payload=payload)
    return WorkerSuccess(
        payload=payload,
        arrays={} if mapped_arrays is None else mapped_arrays,
        warnings=() if mapped_warnings is None else mapped_warnings,
    )
