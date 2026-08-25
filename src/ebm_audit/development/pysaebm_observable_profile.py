"""One narrow bridge from the sealed pySaEBM profile plan to its fixed executor."""

from __future__ import annotations

import copy
import os
import re
from collections.abc import Mapping
from contextlib import suppress
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Final, cast

from ebm_audit.adapters import WorkerCommand, describe_worker
from ebm_audit.config import ResolvedAuditConfig, load_audit_config
from ebm_audit.evaluator import (
    SealedProfileCharacterizationPlan,
    authenticate_profile_characterization_authority,
    derive_profile_plan_provenance,
    derive_profile_public_seed,
    issue_profile_characterization_plan,
    project_profile_characterization_plan,
    project_profile_plan_provenance,
)
from ebm_audit.evaluator.profile_evidence import (
    issue_profile_characterization_live_evidence,
    project_profile_characterization_live_evidence,
)
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
)
from ebm_audit.runner.profile_characterization_run import run_profile_characterization

_ROOT: Final = Path(__file__).resolve().parents[3]
_MANIFEST: Final = _ROOT / "examples/development/pysaebm-observable-outcome-profile.json"
_WORKER_ROOT: Final = _ROOT / "workers/pysaebm"
_EXPECTED_MANIFEST_FIELDS: Final = {
    "schema_version",
    "subject_id",
    "data_classification",
    "execution_status",
    "adr_relative_path",
    "authority_relative_path",
    "source_template_relative_path",
    "output_relative_path",
    "plan_completed_at_utc",
    "diagnostic_completed_at_utc",
    "worker_timeout_seconds",
}
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}")
_GIT_COMMIT_RE: Final = re.compile(r"[0-9a-f]{40,64}")
_PREFLIGHT_NAME: Final = "preflight-manifest.json"
_ACCEPTANCE_NAME: Final = "preflight-acceptance.json"


class PysaebmObservableProfileError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("The pySaEBM observable profile cannot proceed.")


def _fail(code: str) -> PysaebmObservableProfileError:
    return PysaebmObservableProfileError(code)


def _closed_relative(value: object) -> Path:
    if not isinstance(value, str):
        raise _fail("PYSAEBM_PROFILE.MANIFEST")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise _fail("PYSAEBM_PROFILE.MANIFEST")
    return _ROOT.joinpath(*relative.parts)


def _manifest() -> dict[str, Any]:
    try:
        value = strict_json_loads(_MANIFEST.read_bytes())
    except (OSError, TypeError, ValueError):
        raise _fail("PYSAEBM_PROFILE.MANIFEST") from None
    if (
        type(value) is not dict
        or set(value) != _EXPECTED_MANIFEST_FIELDS
        or value.get("schema_version") != "ebm-audit-pysaebm-observable-profile/1.0"
        or value.get("subject_id") != "pysaebm-observable-outcome-profile-v1"
        or value.get("data_classification") != "SYNTHETIC_ONLY"
        or value.get("execution_status") != "PRIVATE_ACCEPTANCE_REQUIRED"
        or value.get("worker_timeout_seconds") != 300.0
    ):
        raise _fail("PYSAEBM_PROFILE.MANIFEST")
    for field in ("adr_relative_path", "authority_relative_path", "source_template_relative_path"):
        if not _closed_relative(value[field]).is_file():
            raise _fail("PYSAEBM_PROFILE.MANIFEST")
    output = PurePosixPath(cast(str, value["output_relative_path"]))
    if output.parts[:2] != ("outputs", "private"):
        raise _fail("PYSAEBM_PROFILE.MANIFEST")
    return cast(dict[str, Any], value)


def _write_private_exact(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if path.exists():
        try:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
                raise _fail("PYSAEBM_PROFILE.OUTPUT_CONFLICT")
        except OSError:
            raise _fail("PYSAEBM_PROFILE.OUTPUT_CONFLICT") from None
        return
    try:
        path.write_bytes(content)
        path.chmod(0o600)
    except OSError:
        raise _fail("PYSAEBM_PROFILE.OUTPUT_WRITE") from None


def _write_private_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise _fail("PYSAEBM_PROFILE.ACCEPTANCE_ALREADY_EXISTS") from None
    except OSError:
        raise _fail("PYSAEBM_PROFILE.OUTPUT_WRITE") from None
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
    except OSError:
        with suppress(OSError):
            path.unlink()
        raise _fail("PYSAEBM_PROFILE.OUTPUT_WRITE") from None


def _read_private_exact(path: Path, code: str) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise _fail(code)
        return path.read_bytes()
    except OSError:
        raise _fail(code) from None


def _worker() -> WorkerCommand:
    return WorkerCommand.from_tokens(
        (
            os.fspath(_WORKER_ROOT / ".venv/bin/python"),
            os.fspath(_WORKER_ROOT / "worker.py"),
        )
    )


def _runtime_config(
    *,
    manifest: Mapping[str, Any],
    candidate_root: Path,
    worker: WorkerCommand,
    expected_identity: Mapping[str, Any],
) -> Path:
    authority_bytes = _closed_relative(manifest["authority_relative_path"]).read_bytes()
    worker_bytes = canonical_json_bytes(
        {
            "worker": {"argv": list(worker.argv)},
            "algorithm_id": "conjugate_priors",
            "settings": {},
            "expected_identity": dict(expected_identity),
        }
    )
    template = strict_json_loads(
        _closed_relative(manifest["source_template_relative_path"]).read_bytes()
    )
    if type(template) is not dict:
        raise _fail("PYSAEBM_PROFILE.SOURCE_TEMPLATE")
    config = copy.deepcopy(template)
    config["worker"]["config_path"] = "worker.json"
    config["worker"]["worker_config_digest"] = exact_file_sha256(worker_bytes)
    config["worker"]["worker_identity_digest"] = expected_identity[
        "selected_backend_identity_digest"
    ]
    config["development_scenario_authority"] = {
        "path": "authority.json",
        "expected_byte_digest": exact_file_sha256(authority_bytes),
    }
    config["output"]["root"] = "results"
    source_root = candidate_root / "source"
    _write_private_exact(source_root / "authority.json", authority_bytes)
    _write_private_exact(source_root / "worker.json", worker_bytes)
    config_path = source_root / "audit.json"
    _write_private_exact(config_path, canonical_json_bytes(config))
    return config_path


def _seed_roster(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    identity = cast(Mapping[str, Any], plan["profile_execution_identity"])
    execution_sha = cast(str, identity["profile_execution_identity_sha256"])
    bindings = {
        (
            row["coordinate"]["family_id"],
            row["coordinate"]["scenario_id"],
            row["coordinate"]["replicate_index"],
        ): row["profile_synthetic_event_binding_sha256"]
        for row in cast(list[dict[str, Any]], plan["ordered_synthetic_event_bindings"])
    }
    rows = []
    for slot in cast(list[dict[str, Any]], plan["ordered_logical_case_chain_slots"]):
        coordinate = (slot["family_id"], slot["scenario_id"], slot["replicate_index"])
        rows.append(
            {
                **slot,
                "seed": derive_profile_public_seed(
                    profile_execution_identity_sha256=execution_sha,
                    profile_synthetic_event_binding_sha256=cast(str, bindings[coordinate]),
                    chain_id=cast(str, slot["chain_id"]),
                ),
                "paired_across_all_three_budgets": True,
            }
        )
    if len(rows) != 18 or len({row["seed"] for row in rows}) != 18:
        raise _fail("PYSAEBM_PROFILE.SEED_ROSTER")
    return rows


def _materialize_preflight() -> tuple[
    dict[str, Any],
    bytes,
    SealedProfileCharacterizationPlan,
    Path,
    ResolvedAuditConfig,
]:
    manifest = _manifest()
    provenance = derive_profile_plan_provenance()
    attestation = project_profile_plan_provenance(provenance)["attestation"]
    candidate_root = _closed_relative(manifest["output_relative_path"]) / cast(
        str, attestation["git_commit"]
    )
    timeout_seconds = cast(float, manifest["worker_timeout_seconds"])
    worker = _worker()
    discovery = describe_worker(
        worker,
        timeout_seconds=timeout_seconds,
        selected_algorithm_id="conjugate_priors",
    )
    expected = discovery.get("selected_expected_identity")
    if not isinstance(expected, Mapping):
        raise _fail("PYSAEBM_PROFILE.WORKER_IDENTITY")
    config_path = _runtime_config(
        manifest=manifest,
        candidate_root=candidate_root,
        worker=worker,
        expected_identity=expected,
    )
    authority_bytes = _closed_relative(manifest["authority_relative_path"]).read_bytes()
    authority = authenticate_profile_characterization_authority(
        exact_authority_bytes=authority_bytes,
        worker=worker,
        timeout_seconds=timeout_seconds,
    )
    plan_owner = issue_profile_characterization_plan(
        authority,
        provenance_owner=provenance,
        canonicalization={
            "schema_version": "ebm-audit-canonicalization-identity/1.0",
            "json_parser_id": "stdlib-json",
            "json_parser_version": "3.12",
            "yaml_parser_id": None,
            "yaml_parser_version": None,
            "canonicalizer_id": "RFC8785-JCS",
            "canonicalizer_version": "rfc8785-0.1.4",
            "unicode_policy": "REJECT_NON_NFC",
            "integer_policy": "I-JSON_SAFE_INTEGER_OR_TYPED_HEX",
        },
        plan_completed_at_utc=cast(str, manifest["plan_completed_at_utc"]),
        diagnostic_completed_at_utc=cast(str, manifest["diagnostic_completed_at_utc"]),
    )
    projection = project_profile_characterization_plan(plan_owner)
    plan = projection["plan_receipt"]
    preflight = {
        "schema_version": "ebm-audit-pysaebm-observable-preflight/1.0",
        "subject_id": manifest["subject_id"],
        "execution_status": manifest["execution_status"],
        "fit_count": 54,
        "result_universe_count": 18,
        "coordinate_count": 6,
        "seed_roster": _seed_roster(plan),
        "sealed_plan": projection,
    }
    assert_no_direct_identifier_fields(preflight)
    preflight_bytes = canonical_json_bytes(preflight)
    return (
        preflight,
        preflight_bytes,
        plan_owner,
        candidate_root,
        load_audit_config(config_path),
    )


def _plan_receipt_sha256(preflight: Mapping[str, Any]) -> str:
    try:
        value = preflight["sealed_plan"]["plan_receipt"][
            "profile_characterization_plan_receipt_sha256"
        ]
    except (KeyError, TypeError):
        raise _fail("PYSAEBM_PROFILE.PREFLIGHT_IDENTITY") from None
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise _fail("PYSAEBM_PROFILE.PREFLIGHT_IDENTITY")
    return value


def _candidate_commit(preflight: Mapping[str, Any]) -> str:
    try:
        value = preflight["sealed_plan"]["plan_receipt"]["candidate"]["git_commit"]
    except (KeyError, TypeError):
        raise _fail("PYSAEBM_PROFILE.PREFLIGHT_IDENTITY") from None
    if not isinstance(value, str) or _GIT_COMMIT_RE.fullmatch(value) is None:
        raise _fail("PYSAEBM_PROFILE.PREFLIGHT_IDENTITY")
    return value


def _assert_reviewed_preflight(
    *,
    preflight: Mapping[str, Any],
    preflight_bytes: bytes,
    candidate_root: Path,
) -> tuple[str, str, str]:
    stored_bytes = _read_private_exact(
        candidate_root / _PREFLIGHT_NAME,
        "PYSAEBM_PROFILE.PRE_EXECUTION_REVIEW_REQUIRED",
    )
    if stored_bytes != preflight_bytes:
        raise _fail("PYSAEBM_PROFILE.REVIEWED_PREFLIGHT_MISMATCH")
    return (
        _candidate_commit(preflight),
        sha256(stored_bytes).hexdigest(),
        _plan_receipt_sha256(preflight),
    )


def _expected_acceptance(
    *,
    subject_id: object,
    candidate_commit: str,
    preflight_sha256: str,
    plan_receipt_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": "ebm-audit-pysaebm-observable-acceptance/1.0",
        "subject_id": subject_id,
        "decision": "GO",
        "candidate_git_commit": candidate_commit,
        "preflight_manifest_sha256": preflight_sha256,
        "profile_characterization_plan_receipt_sha256": plan_receipt_sha256,
    }


def preflight_pysaebm_observable_profile() -> dict[str, Any]:
    preflight, preflight_bytes, _plan, candidate_root, _config = _materialize_preflight()
    _write_private_exact(candidate_root / _PREFLIGHT_NAME, preflight_bytes)
    return {
        "status": "READY_FOR_INDEPENDENT_PRE_EXECUTION_REVIEW",
        "subject_id": preflight["subject_id"],
        "fit_count": preflight["fit_count"],
        "seed_count": len(cast(list[Any], preflight["seed_roster"])),
        "candidate_git_commit": _candidate_commit(preflight),
        "preflight_manifest_sha256": sha256(preflight_bytes).hexdigest(),
        "plan_receipt_sha256": _plan_receipt_sha256(preflight),
    }


def accept_pysaebm_observable_profile(
    *,
    reviewed_preflight_sha256: str,
    reviewed_plan_receipt_sha256: str,
) -> dict[str, Any]:
    if (
        _SHA256_RE.fullmatch(reviewed_preflight_sha256) is None
        or _SHA256_RE.fullmatch(reviewed_plan_receipt_sha256) is None
    ):
        raise _fail("PYSAEBM_PROFILE.REVIEW_IDENTITY")
    preflight, preflight_bytes, _plan, candidate_root, _config = _materialize_preflight()
    candidate_commit, preflight_sha256, plan_receipt_sha256 = _assert_reviewed_preflight(
        preflight=preflight,
        preflight_bytes=preflight_bytes,
        candidate_root=candidate_root,
    )
    if (
        preflight_sha256 != reviewed_preflight_sha256
        or plan_receipt_sha256 != reviewed_plan_receipt_sha256
    ):
        raise _fail("PYSAEBM_PROFILE.REVIEWED_PREFLIGHT_MISMATCH")
    acceptance = _expected_acceptance(
        subject_id=preflight["subject_id"],
        candidate_commit=candidate_commit,
        preflight_sha256=preflight_sha256,
        plan_receipt_sha256=plan_receipt_sha256,
    )
    assert_no_direct_identifier_fields(acceptance)
    _write_private_once(
        candidate_root / _ACCEPTANCE_NAME,
        canonical_json_bytes(acceptance),
    )
    return acceptance


def run_pysaebm_observable_profile() -> dict[str, Any]:
    preflight, preflight_bytes, plan_owner, candidate_root, source_config = _materialize_preflight()
    candidate_commit, preflight_sha256, plan_receipt_sha256 = _assert_reviewed_preflight(
        preflight=preflight,
        preflight_bytes=preflight_bytes,
        candidate_root=candidate_root,
    )
    expected_acceptance = _expected_acceptance(
        subject_id=preflight["subject_id"],
        candidate_commit=candidate_commit,
        preflight_sha256=preflight_sha256,
        plan_receipt_sha256=plan_receipt_sha256,
    )
    acceptance_bytes = _read_private_exact(
        candidate_root / _ACCEPTANCE_NAME,
        "PYSAEBM_PROFILE.PRE_EXECUTION_REVIEW_REQUIRED",
    )
    try:
        acceptance = strict_json_loads(acceptance_bytes)
    except (TypeError, ValueError):
        raise _fail("PYSAEBM_PROFILE.ACCEPTANCE_MISMATCH") from None
    if acceptance != expected_acceptance or acceptance_bytes != canonical_json_bytes(
        expected_acceptance
    ):
        raise _fail("PYSAEBM_PROFILE.ACCEPTANCE_MISMATCH")
    results = source_config.private_paths.output_root
    if results.exists() or any(results.parent.glob(".ebm-audit-stage-*")):
        raise _fail("PYSAEBM_PROFILE.RETRY_DISALLOWED")
    completion = run_profile_characterization(plan_owner, source_config)
    evidence = project_profile_characterization_live_evidence(
        issue_profile_characterization_live_evidence(completion)
    )
    _write_private_exact(candidate_root / "live-evidence.json", canonical_json_bytes(evidence))
    return evidence


__all__ = [
    "PysaebmObservableProfileError",
    "accept_pysaebm_observable_profile",
    "preflight_pysaebm_observable_profile",
    "run_pysaebm_observable_profile",
]
