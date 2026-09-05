"""Real ordinary CLI replay of explicit synthetic failure and recovery states."""

from __future__ import annotations

import copy
import json

import pytest

from ebm_audit.artifacts import ensure_private_directory
from ebm_audit.cli import main
from ebm_audit.cli_workflows import _conformance_demo_config, _conformance_worker_path, run_audit
from ebm_audit.errors import InvalidInputError, UnexpectedCoreError
from ebm_audit.protocol import canonical_json_bytes, structured_sha256
from ebm_audit.replay import (
    environment_digest,
    load_replay_manifest,
    read_private_json,
    rerun_audit,
)
from ebm_audit.runner import ExecutionCancelled, ExecutionControl


@pytest.fixture
def ordinary_config(tmp_path):
    tmp_path.chmod(0o700)
    ensure_private_directory(tmp_path / "support")
    with _conformance_worker_path() as worker:
        config, _ = _conformance_demo_config(tmp_path / "support", worker_path=worker)
        yield config


def _read(path):
    return json.loads(path.read_text())


def _manifest(config):
    return config.parent / "ebm-audit-demo.operations/replay.json"


def _run(config):
    # Ordinary input deliberately lacks the conformance command's ephemeral
    # provenance. Its true typed rejection must survive replay, never become
    # a success or absent candidate. A separate optional-backend smoke proves Fit.
    result, code = run_audit(config, profile_id="quick", timeout_seconds=30.0)
    assert code == 10
    assert result["terminal_status_counts"]["INVALID_INPUT"] == 1
    return result


def test_real_cli_replay_preserves_candidate_failure_and_prior_bytes(ordinary_config, capsys):
    config = ordinary_config
    assert main(["run", "--config", str(config), "--offline", "--progress"]) == 10
    first_output = capsys.readouterr()
    first = json.loads(first_output.out)
    assert first["terminal_status_counts"]["INVALID_INPUT"] == 1
    assert '"phase": "COMPLETED"' in first_output.err
    original_status = config.parent / "ebm-audit-demo/run-status.json"
    before = original_status.read_bytes()
    original = load_replay_manifest(_manifest(config))
    assert (
        main(
            [
                "rerun",
                "--manifest",
                str(_manifest(config)),
                "--config",
                str(config),
                "--run-root",
                "retry",
                "--offline",
            ]
        )
        == 10
    )
    second = json.loads(capsys.readouterr().out)
    assert second["terminal_status_counts"] == first["terminal_status_counts"]
    assert second["plan_digest"] == first["plan_digest"]
    assert original_status.read_bytes() == before
    replayed = load_replay_manifest(config.parent / "retry.operations/replay.json")
    assert replayed["bindings"] == original["bindings"]
    assert replayed["parent_manifest_digest"] == original["manifest_digest"]
    assert replayed["source_run_root_id"] != original["source_run_root_id"]
    assert _read(config.parent / "retry.operations/attempt-status.json")["state"] == "FINISHED"
    assert not list(config.parent.glob(".anim-replay-*.json"))


@pytest.mark.parametrize("change", ["seed", "input", "worker", "environment"])
def test_drift_refused_before_candidate_execution(ordinary_config, capsys, monkeypatch, change):
    config = ordinary_config
    _run(config)
    value = _read(config)
    if change == "seed":
        value["randomness"]["master_seed"] = "fedcba9876543210"
        config.write_bytes(canonical_json_bytes(value))
    elif change == "input":
        target = config.parent / value["input"]["path"]
        target.write_bytes(target.read_bytes() + b"\n")
    elif change == "worker":
        target = config.parent / value["worker"]["config_path"]
        target.write_bytes(target.read_bytes() + b"\n")
    else:
        monkeypatch.setattr("ebm_audit.replay.environment_digest", lambda: "sha256:" + "f" * 64)
    assert (
        main(
            [
                "rerun",
                "--manifest",
                str(_manifest(config)),
                "--config",
                str(config),
                "--run-root",
                "drift",
                "--offline",
            ]
        )
        == 10
    )
    output = capsys.readouterr()
    error = json.loads(output.err)["error"]
    assert error["code"] == "REPLAY.DRIFT" or error["code"].startswith("CONFIG.")
    assert str(config) not in output.err
    assert not (config.parent / "drift/results").exists()
    assert not list(config.parent.glob(".anim-replay-*.json"))


def test_cancelled_attempt_can_be_replayed_without_rehydration(ordinary_config):
    config = ordinary_config
    control = ExecutionControl(progress_callback=lambda event: control.request_cancel())
    with pytest.raises(ExecutionCancelled):
        run_audit(config, profile_id="quick", timeout_seconds=30.0, execution_control=control)
    sidecar = config.parent / "ebm-audit-demo.operations/attempt-status.json"
    before = sidecar.read_bytes()
    assert _read(sidecar)["state"] == "CANCELLED"
    assert not (config.parent / "ebm-audit-demo/run-status.json").exists()
    result, code = rerun_audit(
        _manifest(config), config, run_root="recovered", timeout_seconds=30.0
    )
    assert code == 10
    assert result["terminal_status_counts"]["INVALID_INPUT"] == 1
    assert _read(config.parent / "recovered.operations/attempt-status.json")["state"] == "FINISHED"
    assert sidecar.read_bytes() == before


def test_failure_at_final_gate_is_not_recorded_as_finished(ordinary_config, monkeypatch):
    def reject(*args):
        raise UnexpectedCoreError("TEST.FINAL_GATE", "Synthetic final gate failed.")

    monkeypatch.setattr("ebm_audit.cli_workflows._complete_ordinary_audit_transaction", reject)
    with pytest.raises(UnexpectedCoreError):
        run_audit(ordinary_config, profile_id="quick", timeout_seconds=30.0)
    status = ordinary_config.parent / "ebm-audit-demo.operations/attempt-status.json"
    assert _read(status)["state"] == "FAILED"


def test_runtime_fingerprint_binds_worker_sdk_and_offline_bootstrap(tmp_path, monkeypatch):
    import ebm_audit.adapters.invocation as invocation

    package = tmp_path / "ebm_audit"
    (package / "workers").mkdir(parents=True)
    sdk = package / "workers/transport.py"
    sdk.write_text("first SDK bytes")
    bootstrap = tmp_path / "sitecustomize.py"
    bootstrap.write_text("first offline guard")
    original = invocation._core_code_manifest
    monkeypatch.setattr(
        invocation,
        "_core_code_manifest",
        lambda: original(
            package_root=package,
            sitecustomize_path=bootstrap,
            resource_reader=lambda name: b"{}",
        ),
    )
    first = environment_digest()
    sdk.write_text("changed SDK bytes")
    second = environment_digest()
    bootstrap.write_text("changed offline guard")
    assert first != second != environment_digest()


def test_replay_never_overwrites_an_existing_run(ordinary_config, capsys):
    config = ordinary_config
    _run(config)
    before = (config.parent / "ebm-audit-demo/run-status.json").read_bytes()
    assert (
        main(
            [
                "rerun",
                "--manifest",
                str(_manifest(config)),
                "--config",
                str(config),
                "--run-root",
                "ebm-audit-demo",
                "--offline",
            ]
        )
        == 10
    )
    assert "error" in json.loads(capsys.readouterr().err)
    assert (config.parent / "ebm-audit-demo/run-status.json").read_bytes() == before


def _record():
    record = {
        "schema_version": "anim-replay/1",
        "bindings": {
            name: "sha256:" + "0" * 64
            for name in (
                "configuration_digest",
                "input_digest",
                "worker_config_digest",
                "worker_identity_digest",
                "file_roles_digest",
                "randomness_digest",
                "environment_digest",
            )
        },
        "plan_digest": "sha256:" + "0" * 64,
        "source_run_root_id": "sha256:" + "0" * 64,
        "parent_manifest_digest": None,
    }
    record["bindings"]["profile_id"] = "quick"
    record["manifest_digest"] = structured_sha256("anim/replay/1", record)
    return record


def test_strict_recipe_validation_and_privacy(tmp_path):
    good = _record()
    cases = [b"{}", b'{"private-canary":1,"private-canary":2}', b"[]", b"[NaN]"]
    for change in ("extra", "profile", "hash", "missing"):
        value = copy.deepcopy(good)
        if change == "extra":
            value["private-canary"] = "private-canary"
        elif change == "profile":
            value["bindings"]["profile_id"] = "private-canary"
        elif change == "hash":
            value["bindings"]["input_digest"] = "sha256:" + "f" * 64
        else:
            del value["bindings"]["worker_identity_digest"]
        cases.append(json.dumps(value).encode())
    path = tmp_path / "recipe.json"
    for raw in cases:
        path.write_bytes(raw)
        path.chmod(0o600)
        with pytest.raises(InvalidInputError) as failure:
            load_replay_manifest(path)
        assert failure.value.code == "REPLAY.INVALID"
        assert "private-canary" not in str(failure.value)
    path.write_bytes(canonical_json_bytes(good))
    assert load_replay_manifest(path) == good


def test_private_reader_rejects_links_public_files_and_size(tmp_path):
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    target.chmod(0o600)
    linked = tmp_path / "link.json"
    linked.symlink_to(target)
    with pytest.raises(InvalidInputError):
        read_private_json(linked)
    parent = tmp_path / "linked-parent"
    parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(InvalidInputError):
        read_private_json(parent / "target.json")
    target.chmod(0o644)
    with pytest.raises(InvalidInputError):
        read_private_json(target)
    target.chmod(0o600)
    with pytest.raises(InvalidInputError):
        read_private_json(target, maximum_bytes=1)


def test_operations_collision_is_not_reused(ordinary_config, capsys):
    config = ordinary_config
    directory = config.parent / "ebm-audit-demo.operations"
    directory.mkdir(mode=0o700)
    assert main(["run", "--config", str(config), "--offline"]) == 10
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "REPLAY.OUTPUT_EXISTS"
    assert not list(directory.iterdir())
