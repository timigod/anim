"""Onboarding checks with actual worker subprocesses and safe failure receipts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ebm_audit.adapter_scaffold import initialize_adapter_scaffold
from ebm_audit.adapter_tools import check_adapter, negotiate_capabilities, pin_adapter
from ebm_audit.adapters.config import WorkerConfig
from ebm_audit.adapters.service import describe_worker
from ebm_audit.errors import InvalidInputError


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "starter"
    initialize_adapter_scaffold(root)
    return root


def test_generated_suite_runs_from_scaffold(project: Path, tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            str(project / "tests/test_worker.py"),
            "--basetemp",
            str(tmp_path / "generated-tests"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=240,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "4 passed" in completed.stdout


def test_pin_new_config_preserves_original_and_occupied_output(project: Path) -> None:
    path = project / "worker.yaml"
    original = path.read_bytes()
    output = project / "pinned.yaml"
    receipt = pin_adapter(path, output=output)
    assert receipt["disposition"] == "CREATED"
    assert path.read_bytes() == original
    assert WorkerConfig.from_yaml(output).expected_identity == receipt["expected_identity"]
    assert output.stat().st_mode & 0o777 == 0o600
    pinned = output.read_bytes()
    with pytest.raises(InvalidInputError):
        pin_adapter(path, output=output)
    assert output.read_bytes() == pinned


def test_pin_rejects_symlink_and_hardlink(project: Path) -> None:
    target = project / "worker.yaml"
    before = target.read_bytes()
    linked = project / "linked.yaml"
    linked.symlink_to(target)
    with pytest.raises(InvalidInputError):
        pin_adapter(linked)
    hard = project / "hard.yaml"
    os.link(target, hard)
    with pytest.raises(InvalidInputError):
        pin_adapter(hard)
    assert target.read_bytes() == before


def test_concurrent_config_edit_is_not_overwritten(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ebm_audit.adapter_tools as tools

    path = project / "worker.yaml"
    original_describe = tools.describe_worker

    def edit_during_describe(*args: object, **kwargs: object) -> object:
        result = original_describe(*args, **kwargs)
        path.write_bytes(b"# another writer\n" + path.read_bytes())
        return result

    monkeypatch.setattr(tools, "describe_worker", edit_during_describe)
    with pytest.raises(InvalidInputError, match="configuration changed"):
        pin_adapter(path)
    assert path.read_bytes().startswith(b"# another writer\n")


def test_negotiation_preserves_unavailable_fixed_staging(project: Path) -> None:
    config = WorkerConfig.from_yaml(project / "worker.yaml")
    description = describe_worker(config.worker, selected_algorithm_id=config.algorithm_id)
    algorithm = description["description"]["supported_algorithms"][0]
    # The frozen exception applies only when fixed-cohort staging is the sole
    # missing capability. If posterior support is also absent, it is unsupported.
    assert (
        negotiate_capabilities(algorithm, requested_outputs=["evaluation_stage_posterior"])[
            "requested_outputs"
        ][0]["status"]
        == "UNSUPPORTED"
    )
    algorithm["capabilities"]["participant_stage_posterior"] = True
    receipt = negotiate_capabilities(
        algorithm,
        requested_outputs=["central_order", "evaluation_stage_posterior"],
        required_capabilities=["deterministic_seed", "portable_fitted_model_artifact"],
    )
    assert receipt["status"] == "UNSUPPORTED"
    absent = receipt["requested_outputs"][1]
    assert absent["status"] == "NOT_APPLICABLE_BY_CAPABILITY"
    assert absent["value"] is None
    assert absent["reason_code"] == "STAGING.FIXED_COHORT_UNAVAILABLE"
    assert receipt["required_capabilities"][1]["status"] == "UNSUPPORTED"
    with pytest.raises(InvalidInputError):
        negotiate_capabilities(algorithm, requested_outputs=["unrecognized-private-canary"])


def test_invalid_settings_diagnostic_does_not_echo_keys_or_values(project: Path) -> None:
    path = project / "worker.yaml"
    config = WorkerConfig.from_yaml(path)
    path.write_text(
        json.dumps(
            {
                "worker": {"argv": list(config.worker.argv)},
                "algorithm_id": config.algorithm_id,
                "settings": {"private-canary-key": "private-canary-value"},
                "expected_identity": None,
            }
        )
    )
    receipt = check_adapter(path)
    assert receipt["status"] == "INVALID" and receipt["exit_code"] == 10
    assert receipt["conformance"] is None
    assert "private-canary" not in json.dumps(receipt)
    assert "settings_schema" in receipt["diagnostics"][0]["remediation"][0]


def test_unknown_requirements_are_safe_and_non_successful(project: Path) -> None:
    receipt = check_adapter(project / "worker.yaml", required_capabilities=["private-canary"])
    assert receipt["status"] == "INVALID"
    assert "private-canary" not in json.dumps(receipt)
