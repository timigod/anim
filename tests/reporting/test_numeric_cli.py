"""Numeric report plumbing using the existing, explicitly non-scientific fixture.

The custom worker's declared deterministic trace is transport test data. These
tests provide no evidence of genuine-backend or scientific acceptance.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

from ebm_audit.adapters.requests import requested_outputs_digest
from ebm_audit.cli_workflows import _conformance_demo_config
from ebm_audit.protocol import canonical_json_bytes
from ebm_audit.reporting import compare_reports, inspect_report

REPO = Path(__file__).resolve().parents[2]


def transport_config(root: Path) -> Path:
    root.chmod(0o700)
    support = root / "fixture-support-82a1"
    support.mkdir(mode=0o700)
    config_path, _ = _conformance_demo_config(
        support,
        worker_path=REPO / "examples/custom_worker/worker.py",
        capability_profile="orders-only",
    )
    config = json.loads(config_path.read_text())
    backend = config["baseline_analysis"]["backend"]
    requested = [
        "central_order",
        "order_samples",
        "likelihood_trace",
        "accepted_transition_diagnostics",
        "position_probabilities",
        "pairwise_precedence",
    ]
    backend["requested_outputs"] = requested
    backend["requested_outputs_digest"] = requested_outputs_digest("fit", requested)
    baseline = config["baseline_analysis"]["mcmc"]
    alternative = {**baseline, "chain_count": 2}
    experiment = copy.deepcopy(config["experiments"]["sets"][0])
    experiment.update(
        experiment_set_id="fixture-chains",
        mode="one-axis",
        rationale="Synthetic transport-only comparison, not scientific acceptance.",
    )
    experiment["axes"] = [
        {
            "axis_id": "fixture-chain-count",
            "semantic_target": "mcmc",
            "owned_analysis_spec_paths": ["/mcmc"],
            "baseline_choice_id": "one-chain",
            "rationale": "Predeclared transport fixture chain count.",
            "choices": [
                {
                    "choice_id": name,
                    "assignments": [{"path": "/mcmc", "value": value}],
                    "rationale": "Predeclared transport fixture setting.",
                }
                for name, value in (("one-chain", baseline), ("two-chains", alternative))
            ],
        }
    ]
    experiment["members"] = [
        {
            "member_id": "two-chains",
            "axis_choices": [{"axis_id": "fixture-chain-count", "choice_id": "two-chains"}],
            "rationale": "Predeclared transport fixture alternative.",
        }
    ]
    config["experiments"]["sets"].append(experiment)
    config["output"]["root"] = "numeric-a"
    config_path.write_bytes(canonical_json_bytes(config))
    config_path.chmod(0o600)
    return config_path


def run_cli(config: Path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ebm_audit",
            "run",
            "--config",
            str(config),
            "--profile",
            "quick",
            "--offline",
        ],
        cwd=REPO,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode in {12, 15}, result.stdout + result.stderr
    status = json.loads(result.stdout)
    assert status["audit_report_status"] == "INCOMPLETE"


def test_real_trace_metric_and_stage_absence_cli(tmp_path):
    config_path = transport_config(tmp_path)
    run_cli(config_path)
    first = tmp_path / "numeric-a"
    report = inspect_report(first)
    metrics = report["summary"]["magnitudes"]
    order = next(row for row in metrics if row["metric_id"] == "central-order-kendall-distance/1")
    # The declared 1/2-chain fixture correctly fails the frozen minimum-three
    # convergence requirement. Never reinterpret it as assessable uncertainty.
    assert order["assessable_count"] == 0
    assert order["state"] == "NOT_ASSESSABLE"
    assert order["minimum"] is None
    assert any(row["state"] == "AVAILABLE" for row in report["objective_orders"])
    stage = next(
        row for row in metrics if row["metric_id"] == "mean-absolute-expected-stage-change/1"
    )
    assert stage["state"] == "NOT_ASSESSABLE"
    assert stage["minimum"] is None
    assert report["summary"]["declared_choice_associations"]
    page = (first / "report/report.html").read_text()
    assert "order comparisons had zero difference" in page
    assert "Decision 1 / Option 1" in page
    assert "Order distance (Kendall)" in page
    assert "Stable or concentrated orders can occur on no-signal data" in page
    config = json.loads(config_path.read_text())
    config["output"]["root"] = "numeric-b"
    config_path.write_bytes(canonical_json_bytes(config))
    run_cli(config_path)
    comparison = compare_reports(first, tmp_path / "numeric-b")
    assert comparison["state"] == "UNCHANGED"
    assert comparison["sections"]["event_orders"]["state"] == "UNCHANGED"
    assert comparison["objective_order_distances"]
    assert all(row["kendall_distance"] == 0 for row in comparison["objective_order_distances"])
    # A predeclared different chain count changes candidate identity. Do not
    # demand a movement: an unchanged scientific value is a valid outcome.
    config["output"]["root"] = "numeric-c"
    choice = config["experiments"]["sets"][1]["axes"][0]["choices"][1]
    choice["assignments"][0]["value"]["chain_count"] = 3
    config_path.write_bytes(canonical_json_bytes(config))
    run_cli(config_path)
    changed = compare_reports(first, tmp_path / "numeric-c")
    assert changed["state"] == "CHANGED"
    assert changed["candidate_membership"]["added"]
    assert changed["candidate_membership"]["removed"]
