"""Exercise each project adversary directly, retaining exact rejection codes."""

from __future__ import annotations

import pytest

import ebm_audit.adapters.invocation as invocation
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
def test_core_adversary_rejection_code(mode, expected_code, timeout, monkeypatch):
    # Only fixed startup classifications may escape this synthetic probe;
    # diagnostic bytes remain inside the normal bounded stream collector.
    markers = (
        b"ModuleNotFoundError", b"ImportError", b"PermissionError",
        b"FileNotFoundError", b"AttributeError", b"RuntimeError", b"ValueError",
        b"TypeError", b"SyntaxError", b"NameError", b"numpy", b"yaml",
        b"jsonschema", b"ebm_audit", b"libpython", b"bwrap:",
    )
    observed = set()
    initialize = invocation._StreamDigestCollector.__init__

    class Probe:
        def __init__(self, stream):
            self.stream = stream

        def read(self, size):
            block = self.stream.read(size)
            observed.update(marker.decode("ascii") for marker in markers if marker in block)
            return block

        def close(self):
            self.stream.close()

    def initialize_probe(collector, stream, **kwargs):
        initialize(collector, Probe(stream), **kwargs)

    monkeypatch.setattr(invocation._StreamDigestCollector, "__init__", initialize_probe)
    with pytest.raises(AuditError) as caught:
        WorkerInvoker(
            _adversary_command(mode), timeout_seconds=timeout
        )._invoke_contract_harness(
            command="describe",
            payload_schema_version=None,
            payload={"expected_identity": None},
        )
    assert caught.value.code == expected_code, (sorted(observed), caught.value.details)
