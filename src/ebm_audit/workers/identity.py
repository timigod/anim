"""Explicit development-fixture worker identities.

This creates structurally complete protocol identities. It is not a dependency
or licence receipt and must never be used to accept a scientific backend.
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ebm_audit.protocol import exact_file_sha256, structured_sha256


def _domain_bytes_digest(domain: str, data: bytes) -> str:
    digest = hashlib.sha256(domain.encode("ascii") + b"\x00" + data).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True)
class WorkerIdentityMaterial:
    adapter_id: str
    adapter_version: str
    backend_name: str
    backend_version: str | None
    worker_executable_digest: str
    worker_code_digest: str
    environment_digest: str
    backend_source_digest: str | None = None
    backend_source_commit: str | None = None

    def for_algorithm(self, algorithm_id: str | None) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "worker_executable_digest": self.worker_executable_digest,
            "worker_code_digest": self.worker_code_digest,
            "backend_name": self.backend_name,
            "backend_version": self.backend_version,
            "backend_source_commit": self.backend_source_commit,
            "backend_source_digest": self.backend_source_digest,
            "environment_digest": self.environment_digest,
            "algorithm_id": algorithm_id,
            "identity_evidence": [
                {
                    "kind": "fixture-worker-code",
                    "digest": self.worker_code_digest,
                    "note": "Non-scientific deterministic contract fixture only.",
                }
            ],
        }


def build_fixture_identity(
    *,
    adapter_id: str,
    backend_name: str,
    code_paths: Iterable[Path],
    adapter_version: str = "0.1.0",
) -> WorkerIdentityMaterial:
    executable = Path(sys.executable).resolve()
    executable_bytes = executable.read_bytes()
    worker_executable_digest = _domain_bytes_digest(
        "ebm-audit/worker-executable/1", executable_bytes
    )

    resolved_paths = sorted(
        {path.resolve() for path in code_paths},
        key=lambda item: item.name.encode("utf-8", errors="strict"),
    )
    manifest_names = [path.name for path in resolved_paths]
    if len(manifest_names) != len(set(manifest_names)):
        raise ValueError(
            "Fixture worker identity paths must have unique privacy-safe basenames."
        )
    code_manifest = {
        "manifest_schema_version": "ebm-audit-worker-code-manifest/1.0",
        "entries": [
            {
                "relative_path": path.name,
                "byte_length": path.stat().st_size,
                "sha256": exact_file_sha256(path.read_bytes()),
            }
            for path in resolved_paths
        ],
    }
    worker_code_digest = structured_sha256("ebm-audit/worker-code/1", code_manifest)
    environment_identity = {
        "environment_schema_version": "ebm-audit-environment/1.0",
        "runtime": {
            "implementation": platform.python_implementation().lower(),
            "version": platform.python_version(),
            "executable_digest": worker_executable_digest,
            "launch_manifest_digest": None,
        },
        "platform": {
            "os": platform.system().lower(),
            "architecture": platform.machine().lower() or "unknown",
            "abi": sys.implementation.cache_tag or "unknown",
        },
        # This describes the fixture runtime only. A real backend must replace it
        # with its reviewed lock and complete installed-file inventory.
        "lock_digest": structured_sha256(
            "ebm-audit/fixture-runtime-lock/1",
            {
                "python": platform.python_version(),
                "numpy_required": True,
                "offline": os.environ.get("EBM_AUDIT_OFFLINE") == "1",
            },
        ),
        "installed_distributions": [],
        "native_libraries": [],
    }
    environment_digest = structured_sha256("ebm-audit/environment/1", environment_identity)
    # Keep the unused exact-file helper visible in the identity module's owned
    # imports: it documents that executable/component digests are distinct.
    _ = exact_file_sha256(executable_bytes)
    return WorkerIdentityMaterial(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        backend_name=backend_name,
        backend_version="fixture-1",
        worker_executable_digest=worker_executable_digest,
        worker_code_digest=worker_code_digest,
        environment_digest=environment_digest,
    )
