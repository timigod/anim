#!/usr/bin/env python3
"""Standalone non-scientific transport demonstration using the worker SDK."""

from __future__ import annotations

from pathlib import Path

from model import CustomWorkerExampleBackend

import ebm_audit.workers as worker_sdk
from ebm_audit.workers import WorkerApplication
from ebm_audit.workers.identity import build_fixture_identity


def main() -> int:
    sdk_root = Path(worker_sdk.__file__).resolve().parent
    identity = build_fixture_identity(
        adapter_id="custom-worker-template",
        backend_name="custom-worker-example-non-scientific",
        code_paths=[
            Path(__file__).resolve(),
            Path(__file__).with_name("model.py"),
            *sdk_root.glob("*.py"),
        ],
    )
    return WorkerApplication(CustomWorkerExampleBackend(identity)).run()


if __name__ == "__main__":
    raise SystemExit(main())
