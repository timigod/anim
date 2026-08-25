"""Small operator-facing adapter operations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ebm_audit.errors import WorkerProtocolError
from ebm_audit.protocol import (
    capabilities_digest,
    expected_identity_pin,
    requested_output_registry_digest,
    self_test_check_registry_digest,
    settings_schema_digest,
)
from ebm_audit.schema import validate_settings_schema

from .config import WorkerCommand
from .invocation import WorkerInvoker


def describe_worker(
    worker: WorkerCommand,
    *,
    timeout_seconds: float = 30.0,
    selected_algorithm_id: str | None = None,
    expected_identity: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    execution = WorkerInvoker(
        worker,
        timeout_seconds=timeout_seconds,
        expected_identity=expected_identity,
    ).invoke(
        command="describe",
        payload_schema_version=None,
        payload={"expected_identity": expected_identity},
    )
    response = execution.response
    if response["status"] != "SUCCESS":
        raise WorkerProtocolError(
            "BACKEND.DESCRIBE_FAILED",
            "The worker returned a typed failure while describing itself.",
        )
    payload = response.get("payload")
    if not isinstance(payload, Mapping) or not isinstance(payload.get("result"), Mapping):
        raise WorkerProtocolError(
            "PROTOCOL.DESCRIBE_PAYLOAD",
            "The successful describe response is missing its closed result.",
        )
    result = dict(payload["result"])
    try:
        if result["requested_output_registry_digest"] != requested_output_registry_digest():
            raise ValueError
        if result["self_test_check_registry_digest"] != self_test_check_registry_digest():
            raise ValueError
        algorithms = result["supported_algorithms"]
        algorithm_ids = [algorithm["algorithm_id"] for algorithm in algorithms]
        if len(algorithm_ids) != len(set(algorithm_ids)):
            raise ValueError
        for algorithm in algorithms:
            if algorithm["capabilities_digest"] != capabilities_digest(algorithm["capabilities"]):
                raise ValueError
            if algorithm["settings_schema_digest"] != settings_schema_digest(
                algorithm["settings_schema"]
            ):
                raise ValueError
            validate_settings_schema(algorithm["settings_schema"])
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.DESCRIBE_OWNER_DIGEST",
            "The worker description does not match its complete local owners.",
        ) from None
    base_identity = dict(response["backend_identity"])
    available_pins = [
        {
            "algorithm_id": algorithm["algorithm_id"],
            "expected_identity": expected_identity_pin(
                base_identity,
                algorithm_id=str(algorithm["algorithm_id"]),
                algorithm_capabilities_digest=str(algorithm["capabilities_digest"]),
            ),
        }
        for algorithm in result["supported_algorithms"]
    ]
    selected = [row for row in available_pins if row["algorithm_id"] == selected_algorithm_id]
    if selected_algorithm_id is not None and len(selected) != 1:
        raise WorkerProtocolError(
            "PROTOCOL.DESCRIBE_COMMAND_OWNER",
            "The configured algorithm is absent from the worker description.",
        )
    return {
        "describe_receipt_schema_version": "ebm-audit-adapter-describe/1.0",
        "backend_identity": base_identity,
        "description": result,
        "available_expected_identities": available_pins,
        "selected_algorithm_id": selected_algorithm_id,
        "selected_expected_identity": None if not selected else selected[0]["expected_identity"],
    }
