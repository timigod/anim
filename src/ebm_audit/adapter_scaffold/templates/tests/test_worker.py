from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_generated_worker_describes_as_synthetic_only() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "ebm_audit",
            "adapter",
            "describe",
            "--worker-config",
            str(PROJECT_ROOT / "worker.yaml"),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    limitations = receipt["description"]["worker_limitations"]
    assert any("SYNTHETIC-ONLY" in message for message in limitations)
    assert all("participant" not in message.lower() for message in limitations)
