"""Exercise each project adversary directly, retaining exact rejection codes."""

from __future__ import annotations

import pytest

from ebm_audit.adapters.contract import _adversary_command
from ebm_audit.adapters.invocation import WorkerInvoker
from ebm_audit.errors import AuditError


@pytest.mark.parametrize(
    ("mode", "expected_code", "timeout"),
    [
        ("malformed-json", "PROTOCOL.RESPONSE_SCHEMA", 30.0),
        ("wrong-version", "PROTOCOL.RESPONSE_SCHEMA", 30.0),
        ("timeout-after-response", "TIMEOUT.WORKER_DEADLINE", 1.0),
        ("nonzero-after-response", "BACKEND.WORKER_PROCESS_FAILED", 30.0),
        ("partial-response", "BACKEND.WORKER_PROCESS_FAILED", 30.0),
        ("extra-work-file", "PROTOCOL.SIDE_EFFECT_INVENTORY", 30.0),
        ("nested-response-marker", "PROTOCOL.RESPONSE_SCHEMA", 30.0),
        ("caught-outside-write-attempt", "PRIVACY.OUTSIDE_WRITE_ATTEMPT", 30.0),
        ("caught-network-attempt", "PRIVACY.NETWORK_ATTEMPT", 30.0),
        ("mutate-request", "PRIVACY.OUTSIDE_WRITE_ATTEMPT", 30.0),
        ("tamper-warnings", "PROTOCOL.RESPONSE_SCHEMA", 30.0),
    ],
)
def test_core_adversary_rejection_code(mode, expected_code, timeout):
    with pytest.raises(AuditError) as caught:
        WorkerInvoker(
            _adversary_command(mode), timeout_seconds=timeout
        )._invoke_contract_harness(
            command="describe",
            payload_schema_version=None,
            payload={"expected_identity": None},
        )
    assert caught.value.code == expected_code
