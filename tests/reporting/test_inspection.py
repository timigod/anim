"""Synthetic public CLI runs and adversarial copies; no participant fixtures."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ebm_audit.protocol import canonical_json_bytes, exact_file_sha256, structured_sha256
from ebm_audit.reporting import ReportInspectionError, compare_reports, inspect_report
from ebm_audit.reporting.claims import MANDATORY_OPENING, NULL_SAFE_FALLBACK, claim_is_allowed
from ebm_audit.reporting.render import ReportUnavailableError, render_report_from_run_dir
from ebm_audit.reporting.summary import decision_summary, decision_summary_html

CANARY = "PRIVATE-CANARY-<script>LEAK@example.invalid</script>"
REPO = Path(__file__).resolve().parents[2]


def cli(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ebm_audit", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )


@pytest.fixture(scope="module")
def demos(tmp_path_factory):
    runs = []
    for name, profile in (("same-a", "full"), ("same-b", "full"), ("changed", "partial")):
        cwd = tmp_path_factory.mktemp(name)
        cwd.chmod(0o700)
        result = cli(cwd, "demo", "--conformance-ebm", "--capability-profile", profile)
        assert result.returncode == 12, result.stdout + result.stderr
        status = json.loads(result.stdout)
        assert status["candidate_execution_status"] == "COMPLETE"
        assert status["audit_report_status"] == "INCOMPLETE"
        runs.append(cwd / "ebm-audit-demo")
    return runs


@pytest.fixture
def saved(demos, tmp_path):
    destination = tmp_path / "saved"
    shutil.copytree(demos[0], destination)
    return destination


def read(run, relative="report/report.json"):
    return json.loads((run / relative).read_text())


def bind(run, relative, value):
    """Explicit synthetic adversarial fixture; this is not scientific issuance."""
    raw = canonical_json_bytes(value)
    (run / relative).write_bytes(raw)
    status = read(run, "run-status.json")
    for row in status["report_artifacts"]:
        if row["path"] == relative:
            row["sha256"] = exact_file_sha256(raw)
    for row in status["publication"]["inventory"]:
        if row["path"] == relative:
            row.update(sha256=exact_file_sha256(raw), byte_length=len(raw))
    status["publication"]["inventory_digest"] = structured_sha256(
        "ebm-audit/run-publication-inventory/1", status["publication"]["inventory"]
    )
    (run / "run-status.json").write_bytes(canonical_json_bytes(status))


def test_real_cli_same_input_and_capability_change(demos):
    left, same, changed = demos
    result = cli(REPO, "summary", "--run-dir", str(left))
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout)
    assert summary["inspection_state"] == "BOUND_ARTIFACT_INSPECTION"
    assert summary["scientific_rehydration"] is False
    result = cli(REPO, "diff", "--left", str(left), "--right", str(same))
    assert result.returncode == 0, result.stdout + result.stderr
    comparison = json.loads(result.stdout)
    assert comparison["state"] == "UNCHANGED"
    assert comparison["replay_comparability"] == "MISSING_REPLAY_BINDINGS"
    result = cli(REPO, "diff", "--left", str(left), "--right", str(changed))
    assert result.returncode == 0, result.stdout + result.stderr
    comparison = json.loads(result.stdout)
    assert comparison["state"] == "CHANGED"
    assert comparison["sections"]["capability_evidence"]["state"] == "CHANGED"
    assert comparison["candidate_membership"]["added"]
    assert comparison["candidate_membership"]["removed"]


def test_real_html_summary_and_frozen_scientific_boundary(demos):
    run = demos[0]
    rendered = (run / "report/report.html").read_text()
    assert '<section id="decision-summary"' in rendered
    assert "No assessable comparison magnitudes" in rendered
    assert "Science completion: BLOCKED" in rendered
    assert "NULL_CALIBRATION_NOT_VALIDATED" in rendered
    assert MANDATORY_OPENING in rendered
    assert NULL_SAFE_FALLBACK in rendered
    assert "http://" not in decision_summary_html(read(run))
    assert claim_is_allowed(decision_summary_html(read(run)))
    assert "<script" not in rendered
    assert "PARTIALLY_IMPLEMENTED" in rendered
    assert "NOT_ASSESSABLE" in json.dumps(inspect_report(run))
    with pytest.raises(ReportUnavailableError):
        render_report_from_run_dir(run, run / "unrequested-output")


@pytest.mark.parametrize(
    "relative",
    ["report/report.json", "report/report.html", "evidence/scientific-evidence-projection.json"],
)
def test_artifact_tamper_fails_without_echo(saved, relative):
    (saved / relative).write_text(CANARY)
    with pytest.raises(ReportInspectionError) as error:
        inspect_report(saved)
    assert CANARY not in str(error.value)
    result = cli(REPO, "summary", "--run-dir", str(saved))
    assert result.returncode != 0
    assert CANARY not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "raw",
    [b"{}", b"[]", b'{"x":1,"x":2}', b'{"x":NaN}', b"[" * 10000, b"null"],
    ids=["object", "array", "duplicate", "nonfinite", "deep", "null"],
)
def test_arbitrary_or_malformed_status_rejected(saved, raw):
    (saved / "run-status.json").write_bytes(raw)
    with pytest.raises(ReportInspectionError):
        inspect_report(saved)


def test_schema_invalid_report_even_when_rehashed(saved):
    value = read(saved)
    value[CANARY] = CANARY
    bind(saved, "report/report.json", value)
    with pytest.raises(ReportInspectionError) as error:
        inspect_report(saved)
    assert CANARY not in str(error.value)


def test_status_identity_mismatch_rejected(saved):
    status = read(saved, "run-status.json")
    status["plan_digest"] = "sha256:" + "0" * 64
    (saved / "run-status.json").write_bytes(canonical_json_bytes(status))
    with pytest.raises(ReportInspectionError):
        inspect_report(saved)


@pytest.mark.parametrize("kind", ["file", "directory", "ancestor", "fifo", "oversize"])
def test_bounded_nonsymlink_regular_files(saved, tmp_path, kind):
    target = saved / "report/report.json"
    if kind == "file":
        target.unlink()
        target.symlink_to(saved / "run-status.json")
    elif kind == "directory":
        original = saved / "report"
        original.rename(saved / "report-original")
        original.symlink_to(saved / "report-original", target_is_directory=True)
    elif kind == "ancestor":
        alias = tmp_path / "alias"
        alias.symlink_to(saved, target_is_directory=True)
        saved = alias
    elif kind == "fifo":
        target.unlink()
        os.mkfifo(target)
    else:
        with target.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(ReportInspectionError):
        inspect_report(saved)


def test_implementation_status_change_is_not_hidden_by_counts(saved, demos):
    value = read(saved)
    row = value["uncertainty_layers"][0]
    row["implementation_status"] = "PARTIALLY_IMPLEMENTED"
    bind(saved, "report/report.json", value)
    comparison = compare_reports(demos[0], saved)
    assert comparison["state"] == "CHANGED"
    changes = comparison["sections"]["uncertainty_layers"]["changes"]
    assert any(row["path"].endswith("/implementation_status") for row in changes)


def test_private_canary_prose_and_identities_never_escape(saved):
    value = read(saved)
    value["analyst_decision_evidence"]["attempts"][0]["analysis_declaration_id"] = CANARY
    bind(saved, "report/report.json", value)
    public = inspect_report(saved)
    assert CANARY not in json.dumps(public)
    science = read(saved, "evidence/scientific-evidence-projection.json")
    science["candidate_records"][0]["event_semantics"]["ordered_event_ids"][0] = CANARY
    bind(saved, "evidence/scientific-evidence-projection.json", science)
    with pytest.raises(ReportInspectionError):
        inspect_report(saved)  # Event identities must also match the bound canonical result.
    value["analyst_decision_evidence"]["attempts"][0]["axis_choices"] = [
        {"axis_id": CANARY, "choice_id": CANARY}
    ]
    assert CANARY not in decision_summary_html(value)


def test_candidate_status_swaps_with_unchanged_counts_are_detected(saved, tmp_path, monkeypatch):
    # Comparison-unit fixture derived from a genuinely inspected run. No forged
    # persisted candidate is admitted through the artifact reader.
    before = inspect_report(saved)
    rows = before["sections"]["candidate_records"]
    rows.append(copy.deepcopy(rows[0]))
    rows[1].update(
        candidate_ordinal=1,
        candidate_id="sha256:" + "1" * 64,
        analysis_spec_id="sha256:" + "1" * 64,
        final_status="TIMEOUT",
    )
    after = copy.deepcopy(before)
    rows = after["sections"]["candidate_records"]
    rows[0]["final_status"], rows[1]["final_status"] = "TIMEOUT", "SUCCESS"
    import ebm_audit.reporting.inspection as module

    monkeypatch.setattr(module, "inspect_report", lambda p: before if p.name == "before" else after)
    comparison = compare_reports(tmp_path / "before", tmp_path / "after")
    assert comparison["candidate_membership"]["added"] == []
    changes = comparison["candidate_membership"]["changes"]
    assert sum(row["path"].endswith("/final_status") for row in changes) == 2


def test_summary_exact_magnitudes_and_choice_associations(saved):
    # Small adversarial report copy exercises display rules, not scientific issuance.
    report = read(saved)
    record = {
        "numeric_comparison_digest": "sha256:" + "9" * 64,
        "metric_bundle": {
            "same": {
                "metric_id": "central-order-kendall-distance/1",
                "status": "ASSESSABLE",
                "value": 0.0,
            },
            "moved": {
                "metric_id": "central-order-kendall-distance/1",
                "status": "ASSESSABLE",
                "value": 0.25,
            },
            "absent": {
                "metric_id": "central-order-kendall-distance/1",
                "status": "NOT_ASSESSABLE",
                "value": None,
            },
            "stage": {
                "metric_id": "mean-absolute-expected-stage-change/1",
                "status": "ASSESSABLE",
                "value": 0.5,
            },
        },
    }
    report["analyst_decision_evidence"]["numeric_records"] = [record]
    attempt = report["analyst_decision_evidence"]["attempts"][0]
    attempt.update(
        numeric_comparison_digest=record["numeric_comparison_digest"],
        axis_choices=[{"axis_id": CANARY, "choice_id": CANARY}],
    )
    summary = decision_summary(report)
    order = next(
        row
        for row in summary["magnitudes"]
        if row["metric_id"] == "central-order-kendall-distance/1"
    )
    assert (order["unchanged_count"], order["moved_count"], order["unavailable_count"]) == (1, 1, 1)
    assert (order["minimum"], order["maximum"]) == (0, 0.25)
    assert summary["declared_choice_associations"][0]["association"] == "DESCRIPTIVE_ASSOCIATION"
    assert CANARY not in json.dumps(summary)
    assert CANARY not in decision_summary_html(report)
    assert "0.25" in decision_summary_html(report)


def test_order_permutation_and_numeric_change_detected(saved, demos):
    science = read(saved, "evidence/scientific-evidence-projection.json")
    candidate = science["candidate_records"][0]
    events = candidate["event_semantics"]["ordered_event_ids"]
    candidate["within_fit"]["headline_order_event_ids"] = list(reversed(events))
    candidate["chain"]["metric_summaries"][0]["maximum_distance"] = 0.5
    bind(saved, "evidence/scientific-evidence-projection.json", science)
    comparison = compare_reports(demos[0], saved)
    assert comparison["sections"]["event_orders"]["state"] == "CHANGED"
    assert comparison["sections"]["candidate_metrics"]["state"] == "CHANGED"
    assert events[0] not in json.dumps(comparison)


@pytest.mark.parametrize("alter", ["none", "tamper", "wrong-run", "symlink"])
def test_replay_sidecar_digest_and_run_binding(saved, alter):
    status = read(saved, "run-status.json")
    root = saved.with_name(saved.name + ".operations")
    root.mkdir(mode=0o700)
    record = {
        "schema_version": "anim-replay/1",
        "bindings": {
            key: "sha256:" + "1" * 64
            for key in (
                "configuration_digest",
                "input_digest",
                "worker_config_digest",
                "worker_identity_digest",
                "file_roles_digest",
                "randomness_digest",
                "environment_digest",
            )
        },
        "plan_digest": status["plan_digest"],
        "source_run_root_id": status["publication"]["staging_run_root_id"],
        "parent_manifest_digest": None,
    }
    record["bindings"]["profile_id"] = "quick"
    if alter == "wrong-run":
        record["source_run_root_id"] = "sha256:" + "2" * 64
    record["manifest_digest"] = structured_sha256("anim/replay/1", record)
    if alter == "tamper":
        record["bindings"]["input_digest"] = "sha256:" + "2" * 64
    target = root / "replay.json"
    target.write_bytes(canonical_json_bytes(record))
    target.chmod(0o600)
    if alter == "symlink":
        target.rename(root / "original.json")
        target.symlink_to(root / "original.json")
    if alter == "none":
        assert inspect_report(saved)["replay"]["state"] == "AVAILABLE"
        assert compare_reports(saved, saved)["replay_comparability"] == "SAME_BINDINGS"
    else:
        with pytest.raises(ReportInspectionError):
            inspect_report(saved)


def test_native_objective_order_permutation_is_distinct_from_samples(saved, demos):
    relative = "results/candidate-00000000.json"
    record = read(saved, relative)
    chain = record["body"]["chain_results"][0]
    chain["central_order_event_ids"].reverse()
    chain["central_order_permutation"].reverse()
    record["result_id"] = structured_sha256(
        "ebm-audit/result-record/2", {key: record[key] for key in ("result_schema_version", "body")}
    )
    bind(saved, relative, record)
    science = read(saved, "evidence/scientific-evidence-projection.json")
    science["candidate_records"][0]["result_id"] = record["result_id"]
    bind(saved, "evidence/scientific-evidence-projection.json", science)
    result = compare_reports(demos[0], saved)
    assert result["sections"]["objective_orders"]["state"] == "CHANGED"
    assert result["sections"]["event_orders"]["state"] == "UNCHANGED"
    metric = result["objective_order_distances"][0]
    assert metric["kendall_distance"] == 1.0
    assert metric["footrule_distance"] == 1.0
    assert metric["sampled_order_uncertainty"] is False
    assert inspect_report(saved)["event_orders"][0]["status"] == "NOT_ASSESSABLE"


def test_native_result_tamper_and_schema_mismatch_fail(saved):
    relative = "results/candidate-00000000.json"
    record = read(saved, relative)
    record[CANARY] = CANARY
    bind(saved, relative, record)
    with pytest.raises(ReportInspectionError) as error:
        inspect_report(saved)
    assert CANARY not in str(error.value)


def test_native_order_direction_semantics_are_not_interchangeable(saved):
    from ebm_audit.reporting.objective_orders import objective_order_distances

    original = inspect_report(saved)["objective_orders"]
    changed = copy.deepcopy(original)
    changed[0]["event_semantics_digest"] = "sha256:" + "f" * 64
    comparison = objective_order_distances(original, changed)[0]
    assert comparison["state"] == "NOT_COMPARABLE"
    assert comparison["kendall_distance"] is None
    assert comparison["sampled_order_uncertainty"] is False


def test_hash_shaped_event_and_choice_labels_are_still_projected_as_identities():
    from ebm_audit.reporting.inspection import safe_projection

    label = "sha256:" + "e" * 64
    assert safe_projection(label, key="event_id") != label
    assert safe_projection(label, key="choice_id") != label
    assert safe_projection(label, key="plan_digest") == label
