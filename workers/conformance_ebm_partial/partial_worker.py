#!/usr/bin/env python3
"""Entry point for the partial-capability SYNTHETIC-ONLY conformance EBM."""

from __future__ import annotations

from pathlib import Path

from partial_model import PartialExactConformanceBackend, PartialSyntheticOnlyConformanceBackend

import ebm_audit.synthetic.conformance as conformance_generator
from ebm_audit.worker_sdk import WorkerApplication, build_synthetic_protocol_identity


def main() -> int:
    full_model_path = Path(__file__).resolve().parents[1] / "conformance_ebm" / "model.py"
    identity = build_synthetic_protocol_identity(
        adapter_id="synthetic-only-conformance-ebm-partial",
        backend_name="project-owned-synthetic-only-conformance-ebm-partial",
        code_paths=[
            Path(__file__).resolve(),
            Path(__file__).with_name("partial_model.py"),
            full_model_path,
            Path(conformance_generator.__file__).resolve(),
        ],
    )
    backend = PartialSyntheticOnlyConformanceBackend(
        delegate=PartialExactConformanceBackend(identity)
    )
    return WorkerApplication(backend).run()


if __name__ == "__main__":
    raise SystemExit(main())
