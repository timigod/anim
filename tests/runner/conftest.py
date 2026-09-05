"""Fresh synthetic authorities for execution tests; no persisted-result replay."""

from __future__ import annotations

import copy
import json
import sys
from contextlib import ExitStack
from pathlib import Path

import pytest

from ebm_audit.adapters import WorkerInvoker
from ebm_audit.cli_workflows import (
    _conformance_demo_config,
    _conformance_worker_path,
    authorized_description,
)
from ebm_audit.config import authorize_plan_candidates, load_audit_config
from ebm_audit.data import prepare_audit_dataset
from ebm_audit.results import open_result_persistence_journal
from ebm_audit.universe import (
    compile_analysis_plan,
    issue_planning_authority,
    issue_public_intent_manifest,
)
from ebm_audit.universe.preparation import (
    _conformance_demo_provenance,
    _prepare_analysis_plan,
)


@pytest.fixture
def synthetic_execution(tmp_path, request):
    if sys.platform == "win32":
        pytest.skip("Worker execution is unsupported on Windows.")
    if sys.platform == "linux" and not Path("/usr/bin/bwrap").is_file():
        pytest.skip("Linux worker execution requires bubblewrap containment.")
    with ExitStack() as stack:
        worker_path = stack.enter_context(_conformance_worker_path())
        support = tmp_path / "support"
        support.mkdir(mode=0o700)
        config_path, provenance = _conformance_demo_config(support, worker_path=worker_path)
        config = json.loads(config_path.read_bytes())
        template = json.loads(
            (Path(__file__).parents[2] / "examples/config/synthetic.audit.yaml").read_bytes()
        )
        experiment = next(
            row for row in template["experiments"]["sets"] if row["mode"] == "full-factorial"
        )
        axis = next(row for row in experiment["axes"] if row["axis_id"] == "outlier-choice")
        extra = copy.deepcopy(axis["choices"][1])
        extra["choice_id"] = "second-flag-only"
        extra["assignments"][0]["value"]["threshold"] = 1.5
        axis["choices"].append(extra)
        experiment["axes"] = [axis]
        experiment["mode"] = "one-axis"
        experiment["enabled"] = True
        experiment["members"] = [
            {
                "member_id": choice["choice_id"],
                "axis_choices": [
                    {"axis_id": axis["axis_id"], "choice_id": choice["choice_id"]}
                ],
                "rationale": "Synthetic non-mutating flag-only choice.",
            }
            for choice in axis["choices"][1:]
        ]
        conformance_single = getattr(request, "param", False)
        if not conformance_single:
            config["experiments"]["sets"].append(experiment)
        for profile in config["profiles"].values():
            profile["max_parallel_workers"] = 2
        config_path.write_text(json.dumps(config))
        authorized, _verified, worker_config, description = stack.enter_context(
            authorized_description(load_audit_config(config_path), timeout_seconds=30.0)
        )
        prepared = prepare_audit_dataset(authorized)
        authority = issue_planning_authority(
            authorized,
            prepared,
            (description,),
            public_intent_manifest=issue_public_intent_manifest(authorized, (description,)),
            profile_id="quick",
        )
        plan = compile_analysis_plan(authority)
        if conformance_single:
            transaction = _prepare_analysis_plan(
                authority,
                conformance_demo_provenance=_conformance_demo_provenance(provenance),
            )
        else:
            transaction = authority.prepare()
        store = authorized.open_output_store()
        journal = open_result_persistence_journal(
            store, authorize_plan_candidates(authority), transaction
        )
        invoker = WorkerInvoker(
            worker_config.worker,
            expected_identity=worker_config.expected_identity,
            timeout_seconds=30.0,
        )
        yield transaction, invoker, journal, plan, store
