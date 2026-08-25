#!/usr/bin/env python3
"""Entry point for the project-owned SYNTHETIC-ONLY conformance EBM."""

from __future__ import annotations

from pathlib import Path

from model import SyntheticOnlyConformanceBackend

import ebm_audit.synthetic.conformance as conformance_generator
from ebm_audit.worker_sdk import WorkerApplication, build_synthetic_protocol_identity


def main() -> int:
    identity = build_synthetic_protocol_identity(
        adapter_id="synthetic-only-conformance-ebm",
        backend_name="project-owned-synthetic-only-conformance-ebm",
        code_paths=[
            Path(__file__).resolve(),
            Path(__file__).with_name("model.py"),
            Path(conformance_generator.__file__).resolve(),
        ],
    )
    return WorkerApplication(SyntheticOnlyConformanceBackend(identity)).run()


if __name__ == "__main__":
    raise SystemExit(main())
