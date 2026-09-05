"""Opt-in end-to-end inference and replay, using only provisioned public code."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ebm_audit.adapters.requests import settings_digest
from ebm_audit.protocol import canonical_json_bytes
from ebm_audit.reporting import ReportInspectionError, compare_reports, inspect_report


def test_real_central_order_only_run_rerun_and_typed_missing_chain(tmp_path):
    source = os.environ.get("ANIM_PYSAEBM_SOURCE_DIR")
    if not source:
        pytest.skip("Requires four previously provisioned public pysaebm source files.")
    import importlib.util

    if any(importlib.util.find_spec(name) is None for name in ("scipy", "sklearn", "numba")):
        pytest.skip("Optional example worker dependencies are not installed.")
    root = tmp_path / "ordinary"
    generator = Path(__file__).resolve().parents[2] / "workers/pysaebm_example/synthetic_smoke.py"
    generated = subprocess.run(
        [sys.executable, str(generator), str(root), "--source-dir", source],
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr.decode()
    config = root / "audit.json"
    value = json.loads(config.read_text())
    value["output"]["root"] = "first"
    config.write_bytes(canonical_json_bytes(value))
    first_call = subprocess.run(
        [
            sys.executable,
            "-m",
            "ebm_audit",
            "run",
            "--config",
            str(config),
            "--offline",
            "--timeout",
            "90",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert first_call.returncode == 12, first_call.stderr
    first = json.loads(first_call.stdout)
    assert first["success_count"] == 2
    assert first["candidate_execution_status"] == "COMPLETE"
    report = json.loads((root / "first/report/report.json").read_text())
    numeric = report["analyst_decision_evidence"]["numeric_records"]
    assert len(numeric) == 1
    assert numeric[0]["numeric_status"] == "NOT_ASSESSABLE"
    assert numeric[0]["reason_code"] == "ANALYST_DECISION.REFERENCE_CHAIN_UNAVAILABLE"
    assert numeric[0]["metric_bundle"]["kendall_distance"]["value"] is None
    before = (root / "first/run-status.json").read_bytes()
    second_call = subprocess.run(
        [
            sys.executable,
            "-m",
            "ebm_audit",
            "rerun",
            "--manifest",
            str(root / "first.operations/replay.json"),
            "--config",
            str(config),
            "--run-root",
            "second",
            "--offline",
            "--timeout",
            "90",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert second_call.returncode == 12, second_call.stderr
    second = json.loads(second_call.stdout)
    assert second["success_count"] == 2
    assert (root / "first/run-status.json").read_bytes() == before
    comparison = compare_reports(root / "first", root / "second")
    assert comparison["state"] == "UNCHANGED"
    assert comparison["replay_comparability"] == "SAME_BINDINGS"
    inspection = inspect_report(root / "first")
    assert inspection["scientific_rehydration"] is False
    objective = inspection["objective_summary"]
    assert objective["kind"] == "NATIVE_CENTRAL_ORDER_ONLY"
    assert objective["sampled_order_uncertainty"] is False
    assert len(objective["comparisons"]) == 1
    assert objective["unchanged_count"] + objective["moved_count"] == 1
    assert objective["unavailable_count"] == 0
    assert 0 <= objective["minimum_kendall_distance"] <= objective["maximum_kendall_distance"] <= 1
    html = (root / "first/report/report.html").read_text()
    assert 'id="native-objective-summary"' in html
    assert "Native central orders across declared choices" in html
    assert "Associations are descriptive only." in html
    assert len(comparison["objective_order_distances"]) == 2
    assert all(
        row["kendall_distance"] == 0 and row["sampled_order_uncertainty"] is False
        for row in comparison["objective_order_distances"]
    )
    # Change one predeclared search budget through the genuine public backend.
    # A different configuration may recover the same order; membership and
    # replay bindings must still disclose the change without inventing movement.
    changed_config = json.loads(config.read_text())
    changed_config["output"]["root"] = "third"
    experiment = changed_config["experiments"]["sets"][1]
    choice = experiment["axes"][0]["choices"][1]
    choice["choice_id"] = "iterations-256"
    backend = choice["assignments"][0]["value"]
    backend["settings"]["iterations"] = 256
    backend["settings_digest"] = settings_digest(backend["settings"])
    experiment["members"][0]["member_id"] = "iterations-256"
    experiment["members"][0]["axis_choices"][0]["choice_id"] = "iterations-256"
    config.write_bytes(canonical_json_bytes(changed_config))
    third_call = subprocess.run(
        [
            sys.executable,
            "-m",
            "ebm_audit",
            "run",
            "--config",
            str(config),
            "--offline",
            "--timeout",
            "90",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert third_call.returncode == 12, third_call.stderr
    assert json.loads(third_call.stdout)["success_count"] == 2
    changed = compare_reports(root / "first", root / "third")
    assert changed["state"] == "CHANGED"
    assert changed["replay_comparability"] == "DECLARED_BINDINGS_CHANGED"
    assert changed["candidate_membership"]["added"]
    assert changed["candidate_membership"]["removed"]
    assert changed["sections"]["objective_orders"]["state"] == "CHANGED"
    assert (root / "first/run-status.json").read_bytes() == before
    # Operational metadata cannot be silently attached to the wrong scientific run.
    recipe = root / "second.operations/replay.json"
    wrong = json.loads(recipe.read_text())
    wrong["source_run_root_id"] = "sha256:" + "0" * 64
    recipe.write_bytes(canonical_json_bytes(wrong))
    with pytest.raises(ReportInspectionError):
        inspect_report(root / "second")
