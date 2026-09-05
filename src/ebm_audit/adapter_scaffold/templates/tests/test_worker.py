"""Run the generated starter through the public CLI with synthetic fixtures only."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def cli(*arguments: str) -> tuple[int, dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, "-m", "ebm_audit", "adapter", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=180,
    )
    assert completed.stdout, "The CLI must return a structured operator receipt."
    return completed.returncode, json.loads(completed.stdout)


@pytest.fixture
def worker_config(tmp_path: Path) -> Path:
    # Each test owns a copy: checks cannot rewrite the user's actual worker.
    for name in ("worker.py", "synthetic_example.py"):
        shutil.copyfile(PROJECT_ROOT / name, tmp_path / name)
    path = tmp_path / "worker.json"
    path.write_text(
        json.dumps(
            {
                "worker": {"argv": [sys.executable, str(tmp_path / "worker.py")]},
                "algorithm_id": "fixture-strict-sequence",
                "settings": {},
                "expected_identity": None,
            }
        )
    )
    return path


def test_generated_worker_describes_as_synthetic_only(worker_config: Path) -> None:
    code, receipt = cli("describe", "--worker-config", str(worker_config))
    assert code == 0
    limitations = receipt["description"]["worker_limitations"]
    assert any("SYNTHETIC-ONLY" in message for message in limitations)
    assert receipt["selected_expected_identity"] is not None


def test_unpinned_check_stays_unavailable(worker_config: Path) -> None:
    code, receipt = cli("check", "--worker-config", str(worker_config))
    assert code != 0 and receipt["status"] == "UNAVAILABLE"
    assert receipt["conformance"] is None
    assert receipt["diagnostics"][0]["code"] == "SPEC.ADAPTER_IDENTITY_UNPINNED"


def test_pin_is_idempotent_and_real_synthetic_fits_conform(worker_config: Path) -> None:
    assert cli("pin", "--worker-config", str(worker_config))[0] == 0
    pinned = worker_config.read_bytes()
    code, receipt = cli("pin", "--worker-config", str(worker_config))
    assert code == 0 and receipt["disposition"] == "ALREADY_PINNED"
    assert worker_config.read_bytes() == pinned
    code, checked = cli("check", "--worker-config", str(worker_config))
    assert code == 0 and checked["status"] == "PASS"
    checks = {row["check_id"]: row for row in checked["conformance"]["checks"]}
    for name in (
        "fit-same-seed-repeatability",
        "full-range-canonical-seeds",
        "unknown-setting-rejected",
        "unavailable-output-rejected",
        "row-permutation-and-index-roundtrip",
        "complete-result-invariant-matrix",
    ):
        assert checks[name]["result"] == "PASS"
    assert checked["scientific_acceptance"] == "NOT_ASSESSED"


def test_source_drift_does_not_silently_replace_the_pin(worker_config: Path) -> None:
    assert cli("pin", "--worker-config", str(worker_config))[0] == 0
    pinned = worker_config.read_bytes()
    source = worker_config.with_name("worker.py")
    source.write_text(source.read_text() + "\n# Deliberate synthetic identity-drift test.\n")
    code, receipt = cli("check", "--worker-config", str(worker_config))
    assert code != 0 and receipt["status"] == "FAIL"
    assert worker_config.read_bytes() == pinned
