"""Opt-in real upstream checks, requiring previously provisioned exact sources.

No network or upstream dataset loader runs during these tests. Native modules
run in a child process, as they do behind the real worker boundary: importing
them must not mutate the auditor's scientific dependency graph in pytest.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "workers/pysaebm_example"


@pytest.fixture(scope="module")
def source_dir() -> Path:
    value = os.environ.get("ANIM_PYSAEBM_SOURCE_DIR")
    if not value:
        pytest.skip("Set ANIM_PYSAEBM_SOURCE_DIR to the four previously provisioned source files.")
    for name in ("scipy", "sklearn", "numba"):
        # Discover optional dependencies without importing them into the shared
        # auditor process. A broken installed dependency will fail in the child.
        if importlib.util.find_spec(name) is None:
            pytest.skip(f"The optional worker dependency {name} is not installed.")
    path = Path(value).resolve()
    assert path.is_dir()
    return path


def _run_native_check(code: str, source_dir: Path, *paths: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            textwrap.dedent(code),
            str(EXAMPLE),
            str(source_dir),
            *map(str, paths),
        ],
        cwd=ROOT,
        # Setting this before imports matches worker.py without leaking either
        # os.environ or numba.config changes into subsequent in-process audits.
        env={**os.environ, "NUMBA_DISABLE_JIT": "1"},
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_real_native_inference_recovers_strong_synthetic_order_and_maps_axes(
    source_dir: Path,
) -> None:
    _run_native_check(
        """
        import sys
        from pathlib import Path
        sys.path.insert(0, sys.argv[1])
        import numpy as np
        from model import load_upstream, fit_central_order

        mh, utils = load_upstream(Path(sys.argv[2]))
        rng = np.random.default_rng(5306)
        stages = np.asarray([0] * 16 + list(range(1, 4)) * 16)
        # Known sequence c -> a -> b, expressed in original column order a,b,c.
        x = 5.0 * (stages[:, None] >= np.array([2, 3, 1])) + rng.normal(0, 0.3, (64, 3))
        y = np.asarray(stages > 0, dtype=np.int32)
        settings = {"iterations": 128, "prior_n": 1.0, "prior_v": 1.0}
        ids = ["event-a", "event-b", "event-c"]
        first = fit_central_order(
            mh, utils, x, y, ids, ["higher"] * 3, settings, "ffffffffffffffff"
        )
        assert first.tolist() == [2, 0, 1]
        rows, columns = rng.permutation(64), [2, 0, 1]
        remapped = fit_central_order(
            mh, utils, x[rows][:, columns], y[rows], [ids[i] for i in columns],
            ["higher"] * 3, settings, "ffffffffffffffff",
        )
        assert [columns[i] for i in remapped] == first.tolist()
        assert mh.metropolis_hastings.__module__ == "pysaebm.mh"
        assert utils.compute_total_ln_likelihood_and_stage_likelihoods.__module__ == "pysaebm.utils"
        """,
        source_dir,
    )


def test_source_manifest_has_exact_version_license_and_rejects_drift(
    source_dir: Path, tmp_path: Path
) -> None:
    _run_native_check(
        """
        import shutil
        import sys
        from pathlib import Path
        sys.path.insert(0, sys.argv[1])
        from provision import verify_source

        manifest = verify_source(Path(sys.argv[2]))
        assert manifest["version"] == "7.7.9" and manifest["license"] == "MIT"
        assert manifest["commit"] == "54521a9adfedf58facd7bafd741a14d9ed110d2a"
        assert {r["path"] for r in manifest["files"]} == {
            "LICENSE",
            "pyproject.toml",
            "pysaebm/mh.py",
            "pysaebm/utils.py",
        }
        target = Path(sys.argv[3]) / "source"
        shutil.copytree(Path(sys.argv[2]), target)
        (target / "pysaebm/mh.py").write_text("raise RuntimeError('must not execute')\\n")
        try:
            verify_source(target)
        except ValueError as error:
            assert "SOURCE_DRIFT" in str(error)
        else:
            raise AssertionError("Changed upstream source was not rejected.")
        """,
        source_dir,
        tmp_path,
    )


def test_real_worker_pin_and_full_synthetic_conformance(source_dir: Path, tmp_path: Path) -> None:
    config = tmp_path / "worker.json"
    config.write_text(
        json.dumps(
            {
                "worker": {
                    "argv": [
                        sys.executable,
                        str(EXAMPLE / "worker.py"),
                        "--source-dir",
                        str(source_dir),
                    ]
                },
                "algorithm_id": "pysaebm-hard-kmeans-central-order",
                "settings": {"iterations": 32, "prior_n": 1.0, "prior_v": 1.0},
                "expected_identity": None,
            }
        )
    )
    from ebm_audit.adapter_tools import check_adapter, pin_adapter

    pin_adapter(config)
    receipt = check_adapter(config)
    assert receipt["status"] == "PASS", receipt["diagnostics"]
    assert receipt["scientific_acceptance"] == "NOT_ASSESSED"
    capabilities = receipt["conformance"]["declared_capabilities"]["capabilities"]
    assert capabilities["order_samples"] is False
    assert capabilities["participant_stage_posterior"] is False
    assert capabilities["likelihood_trace"] is False


def test_ordinary_config_is_generated_without_conformance_admission(
    source_dir: Path, tmp_path: Path
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(EXAMPLE / "synthetic_smoke.py"),
            str(tmp_path / "ordinary"),
            "--source-dir",
            str(source_dir),
        ],
        capture_output=True,
        check=False,
        timeout=90,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    config = json.loads((tmp_path / "ordinary/audit.json").read_bytes())
    assert config["input"]["variant"]["is_synthetic"] is True
    assert config["input"]["variant"]["synthetic_truth_digest"] is None
    assert len(config["experiments"]["sets"]) == 2
    assert config["baseline_analysis"]["mcmc"] is None
    assert "development_scenario_authority" not in config
