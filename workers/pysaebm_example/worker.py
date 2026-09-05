#!/usr/bin/env python3
"""Offline generic worker entry point for the optional real pysaebm example."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source-dir", type=Path, required=True)
    arguments, protocol_arguments = parser.parse_known_args()
    # Explicit Python execution of unchanged upstream functions avoids JIT cache
    # writes and compilation. No data loader or pysaebm package __init__ is imported.
    os.environ["NUMBA_DISABLE_JIT"] = "1"
    sys.dont_write_bytecode = True
    try:
        from identity import build_identity
        from model import PysaebmBackend
        from provision import verify_source

        from ebm_audit.worker_sdk import WorkerApplication

        manifest = verify_source(arguments.source_dir)
        backend = PysaebmBackend(build_identity(manifest), arguments.source_dir)
    except Exception:
        sys.stderr.write("EXAMPLE.SETUP_INVALID: verify pinned sources and worker requirements.\n")
        return 2
    return WorkerApplication(backend).run(protocol_arguments)


if __name__ == "__main__":
    raise SystemExit(main())
