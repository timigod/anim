"""Public SYNTHETIC-ONLY protocol example for generated adapters."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ebm_audit.workers.identity import WorkerIdentityMaterial, build_fixture_identity
from ebm_audit.workers.structural import DeterministicMcmcFixtureBackend


def build_synthetic_protocol_identity(
    *,
    adapter_id: str,
    backend_name: str,
    code_paths: Iterable[Path],
) -> WorkerIdentityMaterial:
    """Build fixture identity for the SYNTHETIC-ONLY protocol example."""

    return build_fixture_identity(
        adapter_id=adapter_id,
        backend_name=backend_name,
        code_paths=code_paths,
    )


class SyntheticProtocolExampleBackend(DeterministicMcmcFixtureBackend):
    """Non-scientific protocol example; this is not an EBM."""

    @property
    def describe_result(self) -> Mapping[str, Any]:
        result = dict(super().describe_result)
        result["worker_limitations"] = [
            "SYNTHETIC-ONLY deterministic protocol example; this is not an EBM.",
            "Protocol conformance is not scientific acceptance.",
            "Replace the complete backend declaration and callbacks for a real integration.",
        ]
        return result
