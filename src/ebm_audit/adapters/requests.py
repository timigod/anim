"""Exact request-owner helpers for ``ebm-audit-worker/v2``."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from ebm_audit.protocol import (
    adapter_semantics_digest,
    backend_identity_digest,
    capabilities_digest,
    deterministic_fit_request_id,
    execution_input_projection_digest,
    scientific_requested_outputs_digest,
    stage_semantics_digest,
    structured_sha256,
)
from ebm_audit.protocol import (
    requested_outputs_digest as protocol_requested_outputs_digest,
)
from ebm_audit.protocol import (
    settings_digest as protocol_settings_digest,
)
from ebm_audit.workers.arrays import array_catalog_entry


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def requested_outputs_digest(command: str, requested_outputs: list[str]) -> str:
    return protocol_requested_outputs_digest(command, requested_outputs)


def settings_digest(settings: Mapping[str, Any]) -> str:
    return protocol_settings_digest(settings)


def _data_accounting(
    dataset: Mapping[str, Any],
    arrays: Mapping[str, Any],
) -> dict[str, Any]:
    """Account for the immutable training input without transforming it."""

    np = __import__("numpy")
    missing = 0
    for name in ("train_values", "evaluation_values", "stage_values"):
        value = arrays.get(name)
        if value is not None:
            missing += int(value.size - np.isfinite(value).sum())
    participant_count = int(dataset["participant_count"])
    event_count = int(dataset["event_count"])
    return {
        "accounting_schema_version": "ebm-audit-data-accounting/2.0",
        "input_participants": participant_count,
        "output_participants": participant_count,
        "input_events": event_count,
        "output_events": event_count,
        "input_missing_cells": missing,
        "output_missing_cells": missing,
        "flagged_cells": 0,
        "masked_cells": 0,
        "transformed_cells": 0,
        "added_participant_instances": 0,
        "removed_participants": 0,
        "removed_events": 0,
        "operations": [],
    }


def build_execution_input_projection(
    payload: Mapping[str, Any],
    *,
    arrays: Mapping[str, Any],
    files: Mapping[str, Mapping[str, Any]],
    core_code_digest: str,
    selected_backend_identity: Mapping[str, Any],
    capabilities: Mapping[str, Any],
    stage_semantics_definition: Mapping[str, Any],
    adapter_semantics: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    """Build the one v2 validate/fit wire owner and its exact digest.

    This is a trusted-worker repeatability contract.  The worker shell and
    backend callback share a process; the projection does not claim hostile-
    code isolation.
    """

    dataset = dict(payload["dataset"])
    projection = {
        "projection_schema_version": "ebm-audit-execution-input-projection/2.0",
        "trust_boundary": "TRUSTED_WORKER_SHARED_PROCESS_REPEATABILITY_ONLY",
        "offline": True,
        "core_code_digest": core_code_digest,
        "config_digest": payload["config_digest"],
        "input_files": {name: dict(record) for name, record in files.items()},
        "dataset": dataset,
        "data_accounting": _data_accounting(dataset, arrays),
        "preprocessing_manifest_digest": dataset["preprocessing_manifest_digest"],
        "algorithm_id": payload["algorithm_id"],
        "settings": dict(payload["settings"]),
        "settings_digest": payload["settings_digest"],
        "requested_outputs": list(payload["requested_outputs"]),
        "requested_outputs_digest": scientific_requested_outputs_digest(
            payload["requested_outputs"]
        ),
        "selected_backend_identity": dict(selected_backend_identity),
        "selected_backend_identity_digest": backend_identity_digest(
            selected_backend_identity
        ),
        "capabilities": dict(capabilities),
        "capabilities_digest": capabilities_digest(capabilities),
        "stage_semantics_definition": dict(stage_semantics_definition),
        "stage_semantics_digest": stage_semantics_digest(stage_semantics_definition),
        "adapter_semantics": dict(adapter_semantics),
        "adapter_semantics_digest": adapter_semantics_digest(adapter_semantics),
    }
    candidate_provenance_binding = payload.get("candidate_provenance_binding")
    if candidate_provenance_binding is not None:
        if not isinstance(candidate_provenance_binding, Mapping):
            raise TypeError("Candidate provenance binding must be a mapping.")
        projection["candidate_provenance_binding"] = dict(candidate_provenance_binding)
    return projection, execution_input_projection_digest(projection)


def build_wire_scientific_payload(
    command: str,
    payload: Mapping[str, Any],
    *,
    execution_input_projection: Mapping[str, Any],
    execution_input_projection_digest_value: str,
) -> dict[str, Any]:
    """Move model inputs into their sole v2 wire owner without aliases."""

    common = {
        "execution_input_projection": dict(execution_input_projection),
        "execution_input_projection_digest": execution_input_projection_digest_value,
    }
    if command == "validate":
        return common
    if command == "stage":
        return {
            "scientific_input_schema_version": "ebm-audit-stage-scientific-input/2.0",
            "seed": payload["seed"],
            "stage_call_id": payload["stage_call_id"],
            "fitted_artifact": dict(payload["fitted_artifact"]),
            **common,
        }
    if command != "fit":
        raise ValueError("Only validate, fit, and stage have v2 scientific wire payloads.")
    return {
        "scientific_input_schema_version": "ebm-audit-backend-fit-scientific-input/2.0",
        "universe_id": payload["universe_id"],
        "chain_execution_id": payload["chain_execution_id"],
        "attempt_id": payload["attempt_id"],
        "attempt_ordinal": payload["attempt_ordinal"],
        "seed": payload["seed"],
        "chain_id": payload["chain_id"],
        **common,
    }


def fixture_dataset_descriptor(
    arrays: Mapping[str, Any],
    *,
    event_ids: list[str],
    event_directions: list[str],
    group_codebook: Mapping[str, str],
    stage_semantics_digest_value: str,
) -> dict[str, Any]:
    """Build a clearly labelled synthetic structural dataset descriptor.

    This helper is for fixture and custom-worker contract tests only. It does
    not create a production scientific-data owner or participant mapping.
    """

    train_values = arrays["train_values"]
    participant_count = int(train_values.shape[0])
    catalog = {
        name: array_catalog_entry(
            name,
            value,
            semantic_version={
                "train_values": "synthetic-event-matrix/1",
                "training_row_indexes": "contiguous-internal-row-index/1",
                "train_group_codes": "canonical-group-code/1",
            }[name],
        )
        for name, value in arrays.items()
    }
    scientific_data_digest = structured_sha256(
        "ebm-audit/fixture-scientific-data/1",
        {
            "label": "synthetic-structure-only",
            "participant_count": participant_count,
            "event_ids": event_ids,
            "array_catalog": catalog,
        },
    )
    return {
        "variant_id": "synthetic-structure-only",
        "participant_count": participant_count,
        "evaluation_participant_count": 0,
        "event_count": len(event_ids),
        "event_ids": event_ids,
        "event_directions": event_directions,
        "group_codebook": dict(group_codebook),
        "training_row_index_array": "training_row_indexes",
        "evaluation_row_index_array": None,
        "array_catalog": catalog,
        "stage_semantics": "strict-prefix-count/1",
        "stage_semantics_digest": stage_semantics_digest_value,
        "preprocessing_manifest_digest": structured_sha256(
            "ebm-audit/fixture-preprocessing-manifest/1",
            {"label": "no-preprocessing", "operation_count": 0},
        ),
        "scientific_data_digest": scientific_data_digest,
    }


def base_request(
    *,
    command: str,
    payload_schema_version: str | None,
    payload: Mapping[str, Any],
    core_code_digest: str,
    files: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "protocol_version": "ebm-audit-worker/v2",
        "request_schema_version": "ebm-audit-worker-request/2.0",
        "payload_schema_version": payload_schema_version,
        "command": command,
        "request_id": (
            deterministic_fit_request_id(str(payload["attempt_id"]))
            if command == "fit"
            else str(uuid.uuid4())
        ),
        "request_metadata_digest": None,
        "scientific_request_digest": None,
        "created_at_utc": utc_now(),
        "offline": True,
        "core_code_digest": core_code_digest,
        "payload": dict(payload),
        "files": {key: dict(value) for key, value in files.items()},
    }
