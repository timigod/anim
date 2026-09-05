"""Generate an ordinary, fully synthetic AuditConfig for the real example worker.

The same saved CSV/config can be used with the public run, rerun, and diff
commands. No conformance-only admission hook or scientific acceptance is used.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from importlib import resources
from pathlib import Path

import numpy as np
from model import ALGORITHM_ID, DEFAULT_SETTINGS

from ebm_audit.adapter_tools import pin_adapter
from ebm_audit.adapters.config import WorkerConfig
from ebm_audit.adapters.requests import requested_outputs_digest, settings_digest
from ebm_audit.adapters.service import describe_worker
from ebm_audit.artifacts.store import ensure_private_directory, write_private_new
from ebm_audit.config.loader import parse_audit_config
from ebm_audit.protocol import canonical_json_bytes, exact_file_sha256


def generate(root: Path, source_dir: Path, *, compare: bool = True) -> Path:
    root = root.absolute()
    if root.exists() or root.is_symlink():
        raise ValueError("EXAMPLE.OUTPUT_EXISTS: use a fresh destination.")
    ensure_private_directory(root)
    # Weak, synthetic stage-prefix signal plus noise. The generation seed and
    # choices are fixed before fitting; no outcomes are screened for selection.
    rng = np.random.default_rng(20260905)
    stages = np.array([0] * 12 + list(range(1, 4)) * 12)
    values = 1.5 * (stages[:, None] > np.arange(3)) + rng.normal(0, 1, (48, 3))
    event_ids = ["synthetic-event-a", "synthetic-event-b", "synthetic-event-c"]
    lines = ["participant_code,group,event_01,event_02,event_03"]
    for i, row in enumerate(values):
        group = "reference" if i < 12 else "at-risk"
        lines.append(",".join([f"synthetic-row-{i:03d}", group, *[repr(float(v)) for v in row]]))
    input_bytes = ("\n".join(lines) + "\n").encode("ascii")
    # A long private basename such as "synthetic" collides with public synthetic
    # semantics in the frozen privacy scan. Use a distinct local filename.
    write_private_new(root / "rows-07a19.csv", input_bytes)
    worker_path = root / "worker.json"
    write_private_new(
        worker_path,
        canonical_json_bytes(
            {
                "worker": {
                    "argv": [
                        str(Path(sys.executable).absolute()),
                        str(Path(__file__).with_name("worker.py").resolve()),
                        "--source-dir",
                        str(source_dir.resolve()),
                    ]
                },
                "algorithm_id": ALGORITHM_ID,
                "settings": DEFAULT_SETTINGS,
                "expected_identity": None,
            }
        ),
    )
    pin_adapter(worker_path)
    worker = WorkerConfig.from_yaml(worker_path)
    description = describe_worker(
        worker.worker,
        selected_algorithm_id=worker.algorithm_id,
        expected_identity=worker.expected_identity,
    )
    algorithm = description["description"]["supported_algorithms"][0]
    expected = description["selected_expected_identity"]
    template = resources.files("ebm_audit").joinpath("examples/config/synthetic.audit.yaml")
    if template.is_file():
        template_bytes = template.read_bytes()
    else:
        template_bytes = (
            Path(__file__).resolve().parents[2] / "examples/config/synthetic.audit.yaml"
        ).read_bytes()
    config = copy.deepcopy(parse_audit_config(template_bytes))
    config.pop("development_scenario_authority", None)
    config["template"]["note"] = (
        "Locally generated synthetic-only pysaebm example. No clinical claim."
    )
    digest = exact_file_sha256(input_bytes)
    config["input"].update(path="rows-07a19.csv", expected_byte_digest=digest)
    config["input"]["format"]["columns"] = [
        {"source_column": "participant_code", "physical_type": "string"},
        {"source_column": "group", "physical_type": "string"},
        *[{"source_column": f"event_{i + 1:02d}", "physical_type": "float64"} for i in range(3)],
    ]
    config["input"]["variant"].update(
        source_digest=digest,
        provenance_note="Fixed PCG64 seed 20260905; synthetic stage-prefix means plus noise.",
        synthetic_truth_digest=None,
        created_by="researcher",
    )
    base_event = config["column_roles"]["events"][0]
    config["column_roles"]["events"] = [
        {
            **base_event,
            "event_id": event_id,
            "display_name": f"Synthetic event {i + 1}",
            "source_column": f"event_{i + 1:02d}",
            "abnormal_direction": "higher",
        }
        for i, event_id in enumerate(event_ids)
    ]
    for name in ("covariates", "metadata", "ignored_columns"):
        config["column_roles"][name] = []
    config["worker"].update(
        config_path="worker.json",
        worker_config_digest=exact_file_sha256(worker_path.read_bytes()),
        worker_identity_digest=expected["selected_backend_identity_digest"],
    )
    baseline = config["baseline_analysis"]
    baseline["event_set"] = [{"event_id": event_id} for event_id in event_ids]
    baseline["event_directions"] = dict.fromkeys(event_ids, "higher")
    baseline["missingness_policy"]["event_ids"] = event_ids
    baseline["mcmc"] = None
    identity = expected["base_backend_identity"]
    baseline["backend"].update(
        adapter_id=identity["adapter_id"],
        expected_backend_name=identity["backend_name"],
        expected_backend_source_digest=identity["backend_source_digest"],
        algorithm_id=ALGORITHM_ID,
        **{
            name: algorithm[name]
            for name in (
                "adapter_semantics_digest",
                "capabilities_digest",
                "settings_schema_digest",
                "stage_semantics_digest",
            )
        },
        settings=DEFAULT_SETTINGS,
        settings_digest=settings_digest(DEFAULT_SETTINGS),
        requested_outputs=["central_order"],
        requested_outputs_digest=requested_outputs_digest("fit", ["central_order"]),
    )
    config["source_variants"] = config["source_variants"][:1]
    config["experiments"]["sets"] = [config["experiments"]["sets"][0]]
    if compare:
        alternative = copy.deepcopy(baseline["backend"])
        alternative["settings"]["iterations"] = 128
        alternative["settings_digest"] = settings_digest(alternative["settings"])
        config["experiments"]["sets"].append(
            {
                "experiment_set_id": "search-budget",
                "mode": "one-axis",
                "enabled": True,
                "rationale": "Predeclared synthetic search budgets; no causal attribution.",
                "axes": [
                    {
                        "axis_id": "search-budget",
                        "semantic_target": "backend-settings",
                        "owned_analysis_spec_paths": ["/backend"],
                        "baseline_choice_id": "iterations-64",
                        "rationale": "Vary the explicit upstream native search budget.",
                        "choices": [
                            {
                                "choice_id": label,
                                "assignments": [{"path": "/backend", "value": value}],
                                "rationale": "Predeclared native search budget.",
                            }
                            for label, value in [
                                ("iterations-64", baseline["backend"]),
                                ("iterations-128", alternative),
                            ]
                        ],
                    }
                ],
                "members": [
                    {
                        "member_id": "iterations-128",
                        "axis_choices": [
                            {"axis_id": "search-budget", "choice_id": "iterations-128"}
                        ],
                        "rationale": "One changed native search budget.",
                    }
                ],
                "bootstrap": None,
                "subsample": None,
                "influence": None,
                "null_families": [],
            }
        )
    for profile in config["profiles"].values():
        profile.update(
            bootstrap_replicates=0,
            subsample_replicates=0,
            influence_max_removals=0,
            null_replicates_per_family=0,
            max_parallel_workers=1,
        )
    config["output"]["root"] = "runs"
    content = canonical_json_bytes(config)
    parse_audit_config(content)
    path = root / "audit.json"
    write_private_new(path, content)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--baseline-only", action="store_true")
    args = parser.parse_args()
    generate(args.output_dir, args.source_dir, compare=not args.baseline_only)
    print(json.dumps({"status": "PASS", "config": "audit.json", "data": "SYNTHETIC_ONLY"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
