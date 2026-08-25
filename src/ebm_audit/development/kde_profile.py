from __future__ import annotations

import copy
import hashlib
import math
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final, cast

import numpy as np
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from numpy.typing import NDArray

from ebm_audit.adapters import WorkerInvoker
from ebm_audit.development._worker_v2 import (
    GMM_MEMBER,
    TARGET_PAIRWISE_MEMBER,
    TARGET_POSITION_MEMBER,
    ExpectedProjectionContext,
    WorkerV2DevelopmentError,
    WorkerV2NegativeResponseError,
    authenticated_invoker,
    authenticated_warning_records,
    clean_git_candidate,
    invoke_validated_fit,
    project_warnings,
    publish_receipt,
    regular_file_bytes,
    strict_json_object,
    strict_retained_arrays,
    terminal_failure,
    transition_quality,
    verify_execution_record,
    verify_independent_target,
    verify_worker_identity,
)
from ebm_audit.protocol import (
    canonical_json_bytes,
    structured_sha256,
    validate_relative_posix_path,
)
from ebm_audit.synthetic.authority import load_scenario_authority
from ebm_audit.synthetic.generator import generate_synthetic_case
from ebm_audit.synthetic.models import CaseCoordinate
from ebm_audit.synthetic.resolver import resolve_development_case
from ebm_audit.workers.arrays import array_catalog_entry

_ROOT: Path = Path(__file__).resolve().parents[3]
_MANIFEST_RELATIVE: Final = "examples/development/kde-profile-development-manifest.json"
_MANIFEST_SHA256: Final = "sha256:12773086136bc56ae6a8dfd2e29cb01717f579e1d0c0c5a0fd6fdc6a454e6699"
_EVIDENCE_NAME: Final = "kde-profile-development-evidence.json"
_QUALIFICATION_NAME: Final = "kde-profile-development-qualification.json"
_QUALITY_NAME: Final = "transition-quality.json"
_ALGORITHM_ID: Final = "gmm-unconstrained-global-transposition-uniform-stage-v1"
_RECEIPT_DOMAIN: Final = "ebm-audit/kde-profile-development-evidence/9"
_ATTEMPT_DOMAIN: Final = "ebm-audit/kde-profile-development-attempt-record/1"
_QUALITY_DOMAIN: Final = "ebm-audit/kde-profile-development-transition-quality/1"
_QUALIFICATION_RECEIPT_DOMAIN: Final = "ebm-audit/kde-profile-development-qualification/1"
_QUALIFICATION_PURPOSE: Final = "CANDIDATE_QUALIFICATION"


class KdeProfileDevelopmentError(ValueError):
    def __init__(
        self,
        code: str,
        callback_failure: Mapping[str, Any] | None = None,
        payload_finalization_failure: Mapping[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.callback_failure = (
            None if callback_failure is None else copy.deepcopy(dict(callback_failure))
        )
        self.payload_finalization_failure = (
            None
            if payload_finalization_failure is None
            else copy.deepcopy(dict(payload_finalization_failure))
        )
        super().__init__("KDE synthetic profile development evidence is invalid.")


def _fail(
    code: str,
    callback_failure: Mapping[str, Any] | None = None,
    payload_finalization_failure: Mapping[str, Any] | None = None,
) -> KdeProfileDevelopmentError:
    return KdeProfileDevelopmentError(code, callback_failure, payload_finalization_failure)


def _strict_json(raw: bytes) -> dict[str, Any]:
    try:
        return strict_json_object(raw)
    except WorkerV2DevelopmentError as error:
        raise _fail("KDE_PROFILE." + error.code.removeprefix("WORKER_V2.")) from None


def _regular_bytes(relative: str, expected: str | None = None) -> bytes:
    try:
        return regular_file_bytes(_ROOT, relative, expected)
    except WorkerV2DevelopmentError as error:
        raise _fail("KDE_PROFILE." + error.code.removeprefix("WORKER_V2.")) from None


def _derived_seed(manifest: Mapping[str, Any], purpose: object, label: object) -> str:
    generation = manifest.get("seed_roster_generation")
    if (
        not isinstance(generation, Mapping)
        or generation.get("method_id") != "structured-sha256-first-64-bits-v1"
        or generation.get("domain") != "ebm-audit/kde-profile-development-seed/15"
        or generation.get("preimage_fields") != ["purpose", "label", "retired_manifest_sha256"]
        or generation.get("output_rule") != "first-16-lowercase-hex-of-structured-sha256"
        or generation.get("retired_manifest_sha256")
        != "sha256:8e09a6c6f313d13ce4f64e6a078a06c4263510f467b69401b45c7108b38f6ef2"
        or generation.get("retired_roster_status") != "RETIRED_UNSCREENED_CUMULATIVE"
        or generation.get("result_screening") != "NONE"
        or not isinstance(purpose, str)
        or not isinstance(label, str)
    ):
        raise _fail("KDE_PROFILE.SEED_DERIVATION")
    return structured_sha256(
        str(generation["domain"]),
        {
            "purpose": purpose,
            "label": label,
            "retired_manifest_sha256": generation["retired_manifest_sha256"],
        },
    )[7:23]


def _seed_is_valid(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 16
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True)
class Plan:
    manifest: Mapping[str, Any]
    authority_bytes: bytes
    evidence_schema: Mapping[str, Any]
    rows: tuple[Mapping[str, Any], ...]
    qualification_rows: tuple[Mapping[str, Any], ...]
    output_directory: Path
    qualification_output_directory: Path

    @classmethod
    def load(cls) -> Plan:
        manifest = _strict_json(_regular_bytes(_MANIFEST_RELATIVE, _MANIFEST_SHA256))
        if manifest.get("schema_version") != "ebm-audit-kde-profile-development-manifest/3.0":
            raise _fail("KDE_PROFILE.MANIFEST_VERSION")
        authority = cast(Mapping[str, Any], manifest["scenario_authority"])
        schema = cast(Mapping[str, Any], manifest["evidence_schema"])
        output = validate_relative_posix_path(str(manifest["evidence_output_relative_path"]))
        retired_paths = manifest.get("retired_output_relative_paths")
        if PurePosixPath(output).parts[:2] != ("outputs", "private"):
            raise _fail("KDE_PROFILE.MANIFEST_PATHS")
        rows = tuple(_manifest_rows(manifest))
        qualification_rows = tuple(_qualification_rows(manifest))
        qualification = cast(Mapping[str, Any], manifest["qualification"])
        qualification_output = validate_relative_posix_path(
            str(qualification["output_relative_path"])
        )
        if (
            PurePosixPath(qualification_output).parts[:2] != ("outputs", "private")
            or qualification_output == output
            or not isinstance(retired_paths, list)
            or set(retired_paths)
            != {
                "outputs/private/kde-profile-development-v1",
                "outputs/private/kde-profile-development-v1-interrupted-93de0a6-foreground-5min",
                "outputs/private/kde-profile-development-v2",
                "outputs/private/kde-profile-development-diagnostic-v2",
                "outputs/private/kde-profile-development-v3",
                "outputs/private/kde-profile-development-diagnostic-v3",
                "outputs/private/kde-profile-development-v4",
                "outputs/private/kde-profile-development-diagnostic-v4",
                "outputs/private/kde-profile-development-v5",
                "outputs/private/kde-profile-development-diagnostic-v5-discovery",
                "outputs/private/kde-profile-development-v6",
                "outputs/private/kde-profile-development-diagnostic-v6-discovery",
                "outputs/private/kde-profile-development-v7",
                "outputs/private/kde-profile-development-diagnostic-v7-discovery",
                "outputs/private/kde-profile-development-v8",
                "outputs/private/kde-profile-development-qualification-v8",
                "outputs/private/kde-profile-development-v9",
                "outputs/private/kde-profile-development-qualification-v9",
                "outputs/private/kde-profile-development-v10",
                "outputs/private/kde-profile-development-qualification-v10",
                "outputs/private/kde-profile-development-v11",
                "outputs/private/kde-profile-development-qualification-v11",
                "outputs/private/kde-profile-development-v12",
                "outputs/private/kde-profile-development-qualification-v12",
                "outputs/private/kde-profile-development-v13",
                "outputs/private/kde-profile-development-qualification-v13",
                "outputs/private/kde-profile-development-v14",
                "outputs/private/kde-profile-development-qualification-v14",
            }
            or qualification_output in retired_paths
            or output in retired_paths
        ):
            raise _fail("KDE_PROFILE.MANIFEST_PATHS")
        return cls(
            manifest,
            _regular_bytes(str(authority["relative_path"]), str(authority["exact_byte_sha256"])),
            _strict_json(
                _regular_bytes(str(schema["relative_path"]), str(schema["exact_byte_sha256"]))
            ),
            rows,
            qualification_rows,
            _ROOT.joinpath(*PurePosixPath(output).parts),
            _ROOT.joinpath(*PurePosixPath(qualification_output).parts),
        )


def _manifest_rows(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    budgets = {int(row["budget"]): row for row in cast(list[dict[str, Any]], manifest["budgets"])}
    roster = cast(list[dict[str, Any]], manifest["seed_roster"])
    seeds = {
        (row["family_id"], row["variant_id"], row["replicate_index"], row["chain_id"]): row["seed"]
        for row in roster
    }
    labels = {
        (row["family_id"], row["variant_id"], row["replicate_index"], row["chain_id"]): row["label"]
        for row in roster
    }
    generation = cast(Mapping[str, Any], manifest.get("seed_roster_generation", {}))
    profile_purpose = generation.get("profile_seed_purpose")
    retired = cast(list[object], generation.get("retired_seed_roster", []))
    retired_set = set(retired)
    if (
        len(roster) != 18
        or len(seeds) != 18
        or profile_purpose != "PROFILE_RESERVATION"
        or len(retired) != 254
        or len(retired_set) != 254
        or not all(_seed_is_valid(seed) for seed in retired)
        or any(
            row.get("label")
            != (
                f"profile/{row['family_id']}/{row['variant_id']}/"
                f"replicate-{row['replicate_index']}/chain-{row['chain_id']}/v15"
            )
            or row.get("seed") != _derived_seed(manifest, profile_purpose, row.get("label"))
            for row in roster
        )
    ):
        raise _fail("KDE_PROFILE.MANIFEST_ROSTER")
    rows: list[dict[str, Any]] = []
    rotations = cast(list[list[int]], manifest["replicate_budget_rotation"])
    for coordinate_index, coordinate in enumerate(
        cast(list[dict[str, Any]], manifest["coordinates"])
    ):
        for budget in rotations[int(coordinate["replicate_index"])]:
            owner = budgets[budget]
            for chain in cast(list[int], manifest["chain_ids"]):
                seed = seeds.get(
                    (
                        coordinate["family_id"],
                        coordinate["variant_id"],
                        coordinate["replicate_index"],
                        chain,
                    )
                )
                universe = structured_sha256(
                    "ebm-audit/kde-profile-development-universe/4",
                    {
                        "manifest_sha256": _MANIFEST_SHA256,
                        "purpose": profile_purpose,
                        "row_label": labels.get(
                            (
                                coordinate["family_id"],
                                coordinate["variant_id"],
                                coordinate["replicate_index"],
                                chain,
                            )
                        ),
                        "coordinate": coordinate,
                        "budget": budget,
                    },
                )
                execution = structured_sha256(
                    "ebm-audit/kde-profile-development-chain/4",
                    {"universe_id": universe, "chain_id": chain, "seed": seed},
                )
                rows.append(
                    {
                        "serial_position": len(rows),
                        **coordinate,
                        "budget": budget,
                        "chain_id": chain,
                        "chain_slot": coordinate_index * 3 + chain,
                        "seed": seed,
                        "universe_id": universe,
                        "chain_execution_id": execution,
                        "attempt_id": structured_sha256(
                            "ebm-audit/kde-profile-development-attempt/4",
                            {"chain_execution_id": execution, "attempt_ordinal": 0},
                        ),
                        "attempt_ordinal": 0,
                        "settings": copy.deepcopy(owner["settings"]),
                        "settings_digest": owner["settings_digest"],
                        "requested_outputs_digest": manifest["requested_outputs_digest"],
                    }
                )
    if (
        len(rows) != 54
        or len(seeds) != 18
        or len(set(seeds.values())) != 18
        or not all(_seed_is_valid(seed) for seed in seeds.values())
        or not set(seeds.values()).isdisjoint(retired_set)
        or any(row["seed"] is None for row in rows)
        or len({row["chain_execution_id"] for row in rows}) != 54
    ):
        raise _fail("KDE_PROFILE.MANIFEST_ROSTER")
    return rows


def _qualification_rows(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    qualification = cast(Mapping[str, Any], manifest.get("qualification", {}))
    definitions = cast(list[Mapping[str, Any]], qualification.get("rows", []))
    coordinates = cast(list[Mapping[str, Any]], manifest["coordinates"])
    budgets = {int(row["budget"]): row for row in cast(list[dict[str, Any]], manifest["budgets"])}
    expected_coordinates = [coordinates[0], coordinates[3]]
    retired = cast(list[object], manifest["seed_roster_generation"]["retired_seed_roster"])
    purpose = manifest["seed_roster_generation"].get("qualification_seed_purpose")
    labels = [
        "qualification/easy_known_truth/profile-pilot/replicate-0/budget-2000/chain-0/v15",
        "qualification/moderate_mina_shape/profile-pilot-57x9/replicate-0/budget-2000/chain-0/v15",
    ]
    if (
        len(coordinates) < 4
        or qualification.get("purpose") != _QUALIFICATION_PURPOSE
        or purpose != _QUALIFICATION_PURPOSE
        or len(definitions) != 2
        or any(
            dict(definition.get("coordinate", {})) != dict(expected_coordinates[index])
            or definition.get("label") != labels[index]
            or definition.get("seed") != _derived_seed(manifest, purpose, labels[index])
            or definition.get("budget") != 2000
            or definition.get("chain_id") != 0
            or not _seed_is_valid(definition.get("seed"))
            for index, definition in enumerate(definitions)
        )
        or len({definition.get("seed") for definition in definitions}) != 2
        or any(definition.get("seed") in retired for definition in definitions)
        or any(
            definition.get("seed") in {row["seed"] for row in manifest["seed_roster"]}
            for definition in definitions
        )
        or qualification.get("record_name") != _QUALIFICATION_NAME
    ):
        raise _fail("KDE_PROFILE.QUALIFICATION_DEFINITION")
    rows: list[dict[str, Any]] = []
    for serial, definition in enumerate(definitions):
        coordinate = cast(Mapping[str, Any], definition["coordinate"])
        universe = structured_sha256(
            "ebm-audit/kde-profile-development-qualification-universe/2",
            {
                "manifest_sha256": _MANIFEST_SHA256,
                "purpose": _QUALIFICATION_PURPOSE,
                "row_label": labels[serial],
                "coordinate": coordinate,
                "budget": 2000,
            },
        )
        execution = structured_sha256(
            "ebm-audit/kde-profile-development-qualification-chain/2",
            {"universe_id": universe, "chain_id": 0, "seed": definition["seed"]},
        )
        rows.append(
            {
                "serial_position": serial,
                **copy.deepcopy(dict(coordinate)),
                "budget": 2000,
                "chain_id": 0,
                "chain_slot": serial,
                "seed": definition["seed"],
                "universe_id": universe,
                "chain_execution_id": execution,
                "attempt_id": structured_sha256(
                    "ebm-audit/kde-profile-development-qualification-attempt/1",
                    {"chain_execution_id": execution, "attempt_ordinal": 0},
                ),
                "attempt_ordinal": 0,
                "settings": copy.deepcopy(budgets[2000]["settings"]),
                "settings_digest": budgets[2000]["settings_digest"],
                "requested_outputs_digest": manifest["requested_outputs_digest"],
            }
        )
    return rows


def _candidate() -> dict[str, str]:
    try:
        return clean_git_candidate(_ROOT)
    except WorkerV2DevelopmentError as error:
        raise _fail("KDE_PROFILE." + error.code.removeprefix("WORKER_V2.")) from None


def _verify_candidate(value: object) -> None:
    if not isinstance(value, Mapping) or dict(value) != _candidate():
        raise _fail("KDE_PROFILE.CANDIDATE_IDENTITY")


def _worker(
    plan: Plan,
) -> tuple[WorkerInvoker, dict[str, str], ExpectedProjectionContext]:
    worker = cast(Mapping[str, Any], plan.manifest["worker"])
    root_value = os.environ.get(str(worker["executable_root_environment_variable"]))
    if not root_value:
        raise _fail("KDE_PROFILE.STAGE_B_ROOT_REQUIRED")
    root, entrypoint = Path(root_value), _ROOT / str(worker["entrypoint_relative_path"])
    interpreter = root / "bin/python"
    if (
        not root.is_absolute()
        or root.is_symlink()
        or not root.is_dir()
        or not interpreter.is_file()
        or entrypoint.is_symlink()
        or not entrypoint.is_file()
    ):
        raise _fail("KDE_PROFILE.STAGE_B_ROOT_INVALID")
    identity = cast(Mapping[str, Any], worker["identity"])
    try:
        invoker, description_digest, expected_context = authenticated_invoker(
            interpreter=interpreter,
            entrypoint=entrypoint,
            timeout_seconds=float(worker["timeout_seconds"]),
            algorithm_id=_ALGORITHM_ID,
            expected_identity=identity,
            gate1_receipt_digest=str(identity["gate1_receipt_digest"]),
        )
    except WorkerV2DevelopmentError:
        raise _fail("KDE_PROFILE.WORKER_IDENTITY") from None
    projection = {
        key: str(identity[key]) for key in plan.manifest["worker_identity_receipt_fields"]
    }
    projection["authenticated_description_response_metadata_digest"] = description_digest
    return invoker, projection, expected_context


@dataclass(frozen=True, slots=True)
class _Dataset:
    arrays: Mapping[str, NDArray[Any]]
    descriptor: Mapping[str, Any]
    values: NDArray[np.float64]


def _dataset(plan: Plan, row: Mapping[str, Any]) -> _Dataset:
    authority = load_scenario_authority(plan.authority_bytes)
    case = resolve_development_case(
        authority,
        CaseCoordinate(
            family_id=str(row["family_id"]),
            variant_id=str(row["variant_id"]),
            replicate_index=int(row["replicate_index"]),
        ),
    )
    artifacts = generate_synthetic_case(authority, case)
    data = artifacts.scientific_data
    source_ids = cast(list[str], data["event_ids"])
    directions = cast(list[str], data["event_directions"])
    labels = cast(list[str], data["analysis_group_labels"])
    values = np.array(artifacts.perturbed_values, dtype=np.float64, order="C", copy=True)
    if (
        source_ids != [f"E{index:02d}" for index in range(1, 10)]
        or len(directions) != 9
        or values.ndim != 2
        or values.shape[1] != 9
        or not np.all(np.isfinite(values))
        or set(labels) != {"reference", "at_risk"}
    ):
        raise _fail("KDE_PROFILE.GENERATED_VALUES")
    for index, direction in enumerate(directions):
        if direction == "lower":
            values[:, index] *= -1
        elif direction != "higher":
            raise _fail("KDE_PROFILE.GENERATED_DIRECTION")
    groups = np.asarray([0 if label == "reference" else 1 for label in labels], dtype=np.int32)
    count = values.shape[0]
    arrays: dict[str, NDArray[Any]] = {
        "train_values": values,
        "training_row_indexes": np.arange(count, dtype=np.int64),
        "train_group_codes": groups,
        "evaluation_values": np.array(values, copy=True, order="C"),
        "evaluation_row_indexes": np.arange(count, dtype=np.int64),
        "evaluation_group_codes": np.array(groups, copy=True),
    }
    semantics = {
        "train_values": "synthetic-event-matrix/1",
        "training_row_indexes": "contiguous-internal-row-index/1",
        "train_group_codes": "canonical-group-code/1",
        "evaluation_values": "synthetic-evaluation-event-matrix/1",
        "evaluation_row_indexes": "contiguous-internal-row-index/1",
        "evaluation_group_codes": "canonical-group-code/1",
    }
    catalog = {
        name: array_catalog_entry(name, array, semantic_version=semantics[name])
        for name, array in arrays.items()
    }
    generated = "sha256:" + str(data["generated_scientific_data_sha256"])
    descriptor = {
        "variant_id": (
            f"kde-profile-{row['family_id']}-{row['variant_id']}-r{row['replicate_index']}"
        ),
        "participant_count": count,
        "evaluation_participant_count": count,
        "event_count": 9,
        "event_ids": [event.lower() for event in source_ids],
        "event_directions": ["higher"] * 9,
        "group_codebook": {"0": "reference", "1": "at_risk"},
        "training_row_index_array": "training_row_indexes",
        "evaluation_row_index_array": "evaluation_row_indexes",
        "array_catalog": catalog,
        "stage_semantics": "strict-prefix-count/1",
        "stage_semantics_digest": plan.manifest["stage_semantics_digest"],
        "preprocessing_manifest_digest": structured_sha256(
            "ebm-audit/kde-profile-development-preprocessing/1",
            {
                "generated_data_digest": generated,
                "source_directions": directions,
                "analysis_directions": ["higher"] * 9,
            },
        ),
        "scientific_data_digest": structured_sha256(
            "ebm-audit/kde-profile-development-data/1",
            {"generated_data_digest": generated, "array_catalog": catalog},
        ),
    }
    return _Dataset(arrays, descriptor, values)


def _warnings(plan: Plan, value: object) -> list[dict[str, Any]]:
    registry = cast(Mapping[str, list[str]], plan.manifest["warning_projection_count_keys"])
    try:
        return project_warnings(registry, value)
    except WorkerV2DevelopmentError as error:
        raise _fail("KDE_PROFILE." + error.code.removeprefix("WORKER_V2.")) from None


def _payloads(
    plan: Plan,
    row: Mapping[str, Any],
    dataset: _Dataset,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    config = structured_sha256(
        "ebm-audit/kde-profile-development-config/1",
        {
            "manifest_sha256": _MANIFEST_SHA256,
            "family_id": row["family_id"],
            "variant_id": row["variant_id"],
            "replicate_index": row["replicate_index"],
            "scientific_data_digest": dataset.descriptor["scientific_data_digest"],
        },
    )
    common = {
        "algorithm_id": _ALGORITHM_ID,
        "settings": copy.deepcopy(row["settings"]),
        "settings_digest": row["settings_digest"],
        "config_digest": config,
        "requested_outputs": copy.deepcopy(plan.manifest["requested_outputs"]),
        "requested_outputs_digest": row["requested_outputs_digest"],
        "dataset": copy.deepcopy(dataset.descriptor),
    }
    fit = {
        "universe_id": row["universe_id"],
        "chain_execution_id": row["chain_execution_id"],
        "attempt_id": row["attempt_id"],
        "attempt_ordinal": 0,
        **common,
        "seed": row["seed"],
        "chain_id": f"kde-profile-chain-{row['chain_id']}",
    }
    return common, fit, config


def _fit_one(
    plan: Plan,
    invoker: WorkerInvoker,
    row: Mapping[str, Any],
    dataset: _Dataset,
    *,
    expected_context: ExpectedProjectionContext,
    completed_response: list[bool] | None = None,
) -> dict[str, Any]:
    common, fit, config = _payloads(plan, row, dataset)
    try:
        execution, evidence = invoke_validated_fit(
            invoker,
            common_payload=common,
            fit_payload=fit,
            arrays=dataset.arrays,
            expected_context=expected_context,
            fit_response_returned=completed_response,
        )
        if completed_response is not None:
            completed_response[0] = True
        warning_records = authenticated_warning_records(execution)
    except WorkerV2NegativeResponseError as error:
        raise _fail(
            error.code,
            error.callback_failure,
            error.payload_finalization_failure,
        ) from None
    except WorkerV2DevelopmentError as error:
        raise _fail("KDE_PROFILE." + error.code.removeprefix("WORKER_V2.")) from None
    result, arrays = execution.response["payload"]["result"], execution.arrays
    catalog = cast(Mapping[str, Mapping[str, Any]], result["array_catalog"])
    return {
        **{key: row[key] for key in row if key != "settings"},
        "status": "SUCCESS",
        "participant_count": dataset.descriptor["participant_count"],
        "dataset_scientific_data_digest": dataset.descriptor["scientific_data_digest"],
        "config_digest": config,
        **evidence,
        "array_catalog": copy.deepcopy(dict(catalog)),
        "participant_free_arrays": {
            name: np.asarray(arrays[name]).tolist()
            for name in plan.manifest["retained_participant_free_array_members"]
        },
        "transition_diagnostics": {
            "actual_transition_count": result["actual_transition_count"],
            "actual_transition_fraction": result["actual_transition_fraction"],
        },
        "exact_fixed_target_reference": copy.deepcopy(result["exact_fixed_target_reference"]),
        "core_runtime_seconds": execution.core_runtime_seconds,
        "warning_projection": _warnings(plan, warning_records),
    }


@dataclass(frozen=True, slots=True)
class _Capture:
    attempt: Mapping[str, Any]
    retained: NDArray[np.int64]
    unthinned: NDArray[np.int64]
    position: NDArray[np.float64]
    pairwise: NDArray[np.float64]
    target_position: NDArray[np.float64]
    target_pairwise: NDArray[np.float64]
    target_even: float


@dataclass(frozen=True, slots=True)
class _TargetProof:
    gmm: NDArray[np.float64]
    position: NDArray[np.float64]
    pairwise: NDArray[np.float64]
    reference_digest: str


def _parse_attempt(
    plan: Plan,
    expected: Mapping[str, Any],
    attempt: Mapping[str, Any],
    dataset: _Dataset,
    target_cache: dict[tuple[str, str, int, int], _TargetProof],
    expected_context: ExpectedProjectionContext,
) -> _Capture:
    if (
        any(attempt.get(key) != expected[key] for key in expected if key != "settings")
        or attempt.get("status") != "SUCCESS"
        or attempt.get("participant_count") != dataset.descriptor["participant_count"]
        or attempt.get("dataset_scientific_data_digest")
        != dataset.descriptor["scientific_data_digest"]
    ):
        raise _fail("KDE_PROFILE.ATTEMPT_ROSTER")
    catalog, retained = attempt.get("array_catalog"), attempt.get("participant_free_arrays")
    expected_catalog = set(plan.manifest["expected_response_array_members"])
    retained_names = cast(list[str], plan.manifest["retained_participant_free_array_members"])
    if (
        not isinstance(catalog, Mapping)
        or set(catalog) != expected_catalog
        or any(
            not isinstance(entry, Mapping) or entry.get("member_name") != name
            for name, entry in catalog.items()
        )
        or not isinstance(retained, Mapping)
        or set(retained) != set(retained_names)
    ):
        raise _fail("KDE_PROFILE.FIT_CATALOG")
    common, fit, config = _payloads(plan, expected, dataset)
    if attempt.get("config_digest") != config:
        raise _fail("KDE_PROFILE.CONFIG")
    try:
        validate_digest = verify_execution_record(
            attempt.get("validation_evidence"),
            command="validate",
            expected_payload=common,
            arrays=dataset.arrays,
            expected_context=expected_context,
        )
        fit_digest = verify_execution_record(
            attempt.get("fit_evidence"),
            command="fit",
            expected_payload=fit,
            arrays=dataset.arrays,
            expected_context=expected_context,
        )
        arrays = strict_retained_arrays(attempt, retained_names)
    except WorkerV2DevelopmentError as error:
        raise _fail("KDE_PROFILE." + error.code.removeprefix("WORKER_V2.")) from None
    if validate_digest != fit_digest:
        raise _fail("KDE_PROFILE.VALIDATE_FIT_BINDING")
    warnings = attempt.get("warning_projection")
    runtime = attempt.get("core_runtime_seconds")
    if (
        not isinstance(warnings, list)
        or _warnings(plan, warnings) != warnings
        or isinstance(runtime, bool)
        or not isinstance(runtime, (int, float))
        or not math.isfinite(float(runtime))
        or float(runtime) < 0.0
    ):
        raise _fail("KDE_PROFILE.TERMINAL_FIELDS")
    changed = int(np.count_nonzero(arrays["postburn_state_change_mask"]))
    mask_size = int(arrays["postburn_state_change_mask"].size)
    if attempt.get("transition_diagnostics") != {
        "actual_transition_count": changed,
        "actual_transition_fraction": changed / mask_size,
    }:
        raise _fail("KDE_PROFILE.TRANSITION_DIAGNOSTICS")
    retained_chain = np.asarray(arrays["order_state_chain"], dtype=np.int64)
    unthinned = np.asarray(arrays["postburn_order_state_chain"], dtype=np.int64)
    budget, burn = int(expected["budget"]), int(expected["settings"]["burn_in"])
    if retained_chain.shape != ((budget - burn) // 10, 9) or unthinned.shape != (
        budget - burn,
        9,
    ):
        raise _fail("KDE_PROFILE.CHAIN_DENOMINATOR")
    key = (
        str(expected["family_id"]),
        str(expected["variant_id"]),
        int(expected["replicate_index"]),
        int(expected["chain_id"]),
    )
    reference = cast(Mapping[str, Any], attempt["exact_fixed_target_reference"])
    if key not in target_cache:
        try:
            reference_digest, _gmm_digest = verify_independent_target(
                values=dataset.values,
                groups=np.asarray(dataset.arrays["train_group_codes"]),
                arrays=arrays,
                catalog=catalog,
                reference_value=reference,
            )
        except WorkerV2DevelopmentError as error:
            raise _fail("KDE_PROFILE." + error.code.removeprefix("WORKER_V2.")) from None
        target_cache[key] = _TargetProof(
            np.array(arrays[GMM_MEMBER], copy=True),
            np.array(arrays[TARGET_POSITION_MEMBER], copy=True),
            np.array(arrays[TARGET_PAIRWISE_MEMBER], copy=True),
            reference_digest,
        )
    else:
        proof = target_cache[key]
        if (
            not np.array_equal(proof.gmm, arrays[GMM_MEMBER])
            or not np.array_equal(proof.position, arrays[TARGET_POSITION_MEMBER])
            or not np.array_equal(proof.pairwise, arrays[TARGET_PAIRWISE_MEMBER])
            or proof.reference_digest != reference.get("exact_fixed_target_reference_digest")
        ):
            raise _fail("KDE_PROFILE.PAIRED_TARGET")
    return _Capture(
        attempt,
        retained_chain,
        unthinned,
        np.asarray(arrays["position_probabilities"], dtype=np.float64),
        np.asarray(arrays["pairwise_precedence"], dtype=np.float64),
        np.asarray(arrays[TARGET_POSITION_MEMBER], dtype=np.float64),
        np.asarray(arrays[TARGET_PAIRWISE_MEMBER], dtype=np.float64),
        float(reference["even_permutation_mass"]),
    )


def _schema_bytes(plan: Plan, value: Mapping[str, Any], definition: str | None = None) -> bytes:
    schema = plan.evidence_schema
    selected = (
        schema if definition is None else cast(Mapping[str, Any], schema["$defs"])[definition]
    )
    validator = Draft202012Validator(schema).evolve(schema=selected)
    if list(validator.iter_errors(value)):
        raise _fail("KDE_PROFILE.EVIDENCE_SCHEMA")
    return canonical_json_bytes(value)


def _reference(
    serial: int, filename: str, digest_name: str, record_digest: str, raw: bytes
) -> dict[str, Any]:
    return {
        "serial_position": serial,
        "relative_filename": filename,
        digest_name: record_digest,
        "canonical_file_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "byte_length": len(raw),
    }


def _attempt_artifact(
    plan: Plan, attempt: Mapping[str, Any]
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    preimage = {
        **copy.deepcopy(dict(attempt)),
        "manifest_sha256": _MANIFEST_SHA256,
        "attempt_record_digest": None,
    }
    artifact = copy.deepcopy(preimage)
    artifact["attempt_record_digest"] = structured_sha256(_ATTEMPT_DOMAIN, preimage)
    raw = _schema_bytes(plan, artifact, "attemptArtifact")
    serial = int(artifact["serial_position"])
    name = f"attempt-{serial:03d}.json"
    return (
        artifact,
        raw,
        _reference(
            serial, name, "attempt_record_digest", str(artifact["attempt_record_digest"]), raw
        ),
    )


def _quality_artifact(
    plan: Plan, quality: Mapping[str, Any]
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    preimage = {
        "manifest_sha256": _MANIFEST_SHA256,
        "transition_quality": copy.deepcopy(dict(quality)),
        "transition_quality_record_digest": None,
    }
    artifact = copy.deepcopy(preimage)
    artifact["transition_quality_record_digest"] = structured_sha256(_QUALITY_DOMAIN, preimage)
    raw = _schema_bytes(plan, artifact, "transitionQualityArtifact")
    return (
        artifact,
        raw,
        _reference(
            54,
            _QUALITY_NAME,
            "transition_quality_record_digest",
            str(artifact["transition_quality_record_digest"]),
            raw,
        ),
    )


def _receipt(
    plan: Plan,
    references: Sequence[Mapping[str, Any]],
    *,
    worker_identity: Mapping[str, Any],
    candidate_identity: Mapping[str, Any],
    transition_quality_reference: Mapping[str, Any] | None,
    terminal_failure: Mapping[str, Any] | None,
) -> dict[str, Any]:
    ready = (
        len(references) == 54
        and transition_quality_reference is not None
        and terminal_failure is None
    )
    preimage = {
        **copy.deepcopy(plan.manifest["evidence_receipt_boundary"]),
        "manifest_sha256": _MANIFEST_SHA256,
        "status": "READY_FOR_INDEPENDENT_OUTER_REVIEW" if ready else "DO_NOT_ADVANCE",
        "observed_attempt_count": len(references),
        "candidate_identity": copy.deepcopy(dict(candidate_identity)),
        "worker_identity": {
            "identity_kind": "AUTHENTICATED",
            **copy.deepcopy(dict(worker_identity)),
        },
        "attempt_references": copy.deepcopy(list(references)),
        "transition_quality_reference": (
            copy.deepcopy(dict(transition_quality_reference))
            if transition_quality_reference is not None and ready
            else None
        ),
        "terminal_failure": None
        if terminal_failure is None
        else copy.deepcopy(dict(terminal_failure)),
        "receipt_digest": None,
    }
    receipt = copy.deepcopy(preimage)
    receipt["receipt_digest"] = structured_sha256(_RECEIPT_DOMAIN, preimage)
    return receipt


def _maximum_quality(plan: Plan) -> dict[str, Any]:
    position = np.eye(9, dtype=np.float64)
    pairwise = np.triu(np.ones((9, 9), dtype=np.float64), 1)
    np.fill_diagonal(pairwise, 0.5)
    captures = []
    for row in plan.rows:
        count = int(row["budget"]) - int(row["settings"]["burn_in"])
        states = np.tile(np.arange(9, dtype=np.int64), (count, 1))
        states[1::2, :2] = [1, 0]
        captures.append(
            _Capture(row, states[::10], states, position, pairwise, position, pairwise, 0.5)
        )
    return transition_quality(captures)


def _maximum_attempt(plan: Plan, row: Mapping[str, Any], dataset: _Dataset) -> dict[str, Any]:
    count = int(row["budget"]) - int(row["settings"]["burn_in"])
    square, digest = [[0.0] * 9] * 9, "sha256:" + "0" * 64
    arrays = {
        "central_order_permutation": [0] * 9,
        "postburn_order_state_chain": [[0] * 9] * count,
        "order_state_chain": [[0] * 9] * (count // 10),
        "postburn_state_change_mask": [False] * count,
        "position_probabilities": square,
        "pairwise_precedence": square,
        GMM_MEMBER: [[0.0] * 5] * 9,
        TARGET_POSITION_MEMBER: square,
        TARGET_PAIRWISE_MEMBER: square,
    }
    catalog = {
        name: {
            "member_name": name,
            "dtype": "float64",
            "shape": [1],
            "semantic_version": "maximum-envelope/1",
            "byte_length": 8,
            "array_digest": digest,
        }
        for name in plan.manifest["expected_response_array_members"]
    }
    evidence = {
        "scientific_request_projection": {},
        "scientific_request_digest": digest,
        "request_evidence_projection": {},
        "request_evidence_digest": digest,
        "execution_evidence_projection": {},
        "execution_evidence_digest": digest,
    }
    reference = {
        "exact_fixed_target_reference_schema_version": "ebm-audit-exact-fixed-target-reference/1.0",
        "requested_output_id": "exact_fixed_order_target",
        "target_arithmetic_id": "maximum-envelope/1",
        "native_probability_matrix_shape": [int(dataset.descriptor["participant_count"]), 9, 2],
        "native_probability_matrix_dtype": "float64",
        "native_probability_matrix_order": "C",
        "native_probability_matrix_digest": digest,
        "event_ids": [f"e{index:02d}" for index in range(1, 10)],
        "component_axis": ["non-event-density", "event-density"],
        "order_count": 362880,
        "position_probabilities_binding": {
            "member_name": TARGET_POSITION_MEMBER,
            "array_digest": digest,
        },
        "pairwise_precedence_binding": {
            "member_name": TARGET_PAIRWISE_MEMBER,
            "array_digest": digest,
        },
        "even_permutation_mass": 1.0,
        "exact_fixed_target_reference_digest": digest,
    }
    return {
        **{key: value for key, value in row.items() if key != "settings"},
        "status": "SUCCESS",
        "participant_count": dataset.descriptor["participant_count"],
        "dataset_scientific_data_digest": dataset.descriptor["scientific_data_digest"],
        "config_digest": _payloads(plan, row, dataset)[2],
        "validation_evidence": evidence,
        "fit_evidence": evidence,
        "array_catalog": catalog,
        "participant_free_arrays": arrays,
        "transition_diagnostics": {
            "actual_transition_count": count,
            "actual_transition_fraction": 1.0,
        },
        "exact_fixed_target_reference": reference,
        "core_runtime_seconds": float(2**53 - 1),
        "warning_projection": [
            {"code": code, "severity": "WARNING", "counts": {key: 2**53 - 1 for key in keys}}
            for code, keys in plan.manifest["warning_projection_count_keys"].items()
        ],
    }


def _envelope_gate(
    plan: Plan,
    candidate: Mapping[str, Any],
    worker: Mapping[str, Any],
    datasets: Mapping[tuple[str, str, int], _Dataset],
) -> None:
    references = [
        _attempt_artifact(
            plan,
            _maximum_attempt(
                plan,
                row,
                datasets[
                    (str(row["family_id"]), str(row["variant_id"]), int(row["replicate_index"]))
                ],
            ),
        )[2]
        for row in plan.rows
    ]
    quality = _quality_artifact(plan, _maximum_quality(plan))[2]
    _schema_bytes(
        plan,
        _receipt(
            plan,
            references,
            worker_identity=worker,
            candidate_identity=candidate,
            transition_quality_reference=quality,
            terminal_failure=None,
        ),
    )


def _datasets(plan: Plan) -> dict[tuple[str, str, int], _Dataset]:
    return {
        (str(row["family_id"]), str(row["variant_id"]), int(row["replicate_index"])): _dataset(
            plan, row
        )
        for row in plan.rows[::9]
    }


def _verify_receipt(
    plan: Plan,
    receipt: Mapping[str, Any],
    expected_context: ExpectedProjectionContext,
    prospective: Mapping[str, bytes] | None = None,
) -> None:
    prospective = prospective or {}
    receipt_raw = _schema_bytes(plan, receipt)
    preimage = copy.deepcopy(dict(receipt))
    supplied = preimage["receipt_digest"]
    preimage["receipt_digest"] = None
    if supplied != structured_sha256(_RECEIPT_DOMAIN, preimage):
        raise _fail("KDE_PROFILE.RECEIPT_DIGEST")
    _verify_candidate(receipt["candidate_identity"])
    try:
        worker_identity = dict(cast(Mapping[str, Any], receipt["worker_identity"]))
        if worker_identity.pop("identity_kind", None) != "AUTHENTICATED":
            raise WorkerV2DevelopmentError("identity is not authenticated")
        verify_worker_identity(
            worker_identity,
            expected=cast(Mapping[str, Any], plan.manifest["worker"]["identity"]),
            fields=cast(list[str], plan.manifest["worker_identity_receipt_fields"]),
        )
    except WorkerV2DevelopmentError:
        raise _fail("KDE_PROFILE.WORKER_IDENTITY") from None
    references = cast(list[Mapping[str, Any]], receipt["attempt_references"])
    quality_reference = receipt["transition_quality_reference"]
    if (
        receipt["manifest_sha256"] != _MANIFEST_SHA256
        or receipt["observed_attempt_count"] != len(references)
        or len(references) > 54
    ):
        raise _fail("KDE_PROFILE.RECEIPT_COUNTS")
    expected_names = {_EVIDENCE_NAME, *(str(row["relative_filename"]) for row in references)}
    if isinstance(quality_reference, Mapping):
        expected_names.add(str(quality_reference["relative_filename"]))
    try:
        entries = list(plan.output_directory.iterdir())
    except OSError:
        raise _fail("KDE_PROFILE.EVIDENCE_PATH") from None
    if plan.output_directory.is_symlink() or {
        entry.name for entry in entries
    } != expected_names - set(prospective):
        raise _fail("KDE_PROFILE.EVIDENCE_PATH")

    def read(name: str) -> bytes:
        if name in prospective:
            return prospective[name]
        path = plan.output_directory / name
        if path.is_symlink() or not path.is_file():
            raise _fail("KDE_PROFILE.EVIDENCE_PATH")
        try:
            return path.read_bytes()
        except OSError:
            raise _fail("KDE_PROFILE.EVIDENCE_PATH") from None

    if read(_EVIDENCE_NAME) != receipt_raw:
        raise _fail("KDE_PROFILE.NONCANONICAL_FILE")
    datasets = _datasets(plan)
    cache: dict[tuple[str, str, int, int], _TargetProof] = {}
    captures: list[_Capture] = []
    for expected, reference in zip(plan.rows, references, strict=False):
        serial = int(expected["serial_position"])
        name = f"attempt-{serial:03d}.json"
        if reference.get("serial_position") != serial or reference.get("relative_filename") != name:
            raise _fail("KDE_PROFILE.ATTEMPT_REFERENCE")
        raw = read(name)
        attempt = _strict_json(raw)
        base = {
            key: value
            for key, value in attempt.items()
            if key not in {"manifest_sha256", "attempt_record_digest"}
        }
        if (attempt, raw, reference) != _attempt_artifact(plan, base):
            raise _fail("KDE_PROFILE.ATTEMPT_ARTIFACT")
        key = (
            str(expected["family_id"]),
            str(expected["variant_id"]),
            int(expected["replicate_index"]),
        )
        captures.append(
            _parse_attempt(
                plan,
                expected,
                attempt,
                datasets[key],
                cache,
                expected_context,
            )
        )
    ready = receipt["status"] == "READY_FOR_INDEPENDENT_OUTER_REVIEW"
    failure = receipt["terminal_failure"]
    if ready:
        if (
            len(references) != 54
            or failure is not None
            or not isinstance(quality_reference, Mapping)
        ):
            raise _fail("KDE_PROFILE.READY_INVARIANT")
        raw = read(_QUALITY_NAME)
        quality_artifact = _strict_json(raw)
        if (
            not isinstance(quality_artifact.get("transition_quality"), Mapping)
            or (quality_artifact, raw, quality_reference)
            != _quality_artifact(plan, quality_artifact["transition_quality"])
            or quality_artifact.get("transition_quality") != transition_quality(captures)
        ):
            raise _fail("KDE_PROFILE.TRANSITION_QUALITY")
    elif (
        quality_reference is not None
        or not isinstance(failure, Mapping)
        or failure.get("completed_fit_count") != len(references)
    ):
        raise _fail("KDE_PROFILE.FAILURE_INVARIANT")


def _assert_new_start_boundaries_absent(plan: Plan) -> None:
    if os.path.lexists(plan.output_directory) or os.path.lexists(
        plan.qualification_output_directory
    ):
        raise _fail("KDE_PROFILE.OUTPUT_EXISTS")


def _preflight() -> tuple[Plan, dict[str, str]]:
    """Perform only deterministic checks that are safe before reservation."""
    return Plan.load(), _candidate()


def preflight_kde_profile_development() -> dict[str, Any]:
    plan, candidate = _preflight()
    _assert_new_start_boundaries_absent(plan)
    return {
        "schema_version": "ebm-audit-kde-profile-development-preflight/1.0",
        "data_classification": "SYNTHETIC_ONLY",
        "manifest_sha256": _MANIFEST_SHA256,
        "attempt_count": len(plan.rows),
        "candidate_identity": dict(candidate),
    }


def verify_kde_profile_worker_readiness() -> dict[str, Any]:
    """Authenticate the fit-disabled Worker without reserving scientific state."""

    plan, candidate = _preflight()
    _assert_new_start_boundaries_absent(plan)
    _invoker, worker_identity, _expected_context = _worker(plan)
    return {
        "schema_version": "ebm-audit-kde-profile-worker-readiness/1.0",
        "data_classification": "SYNTHETIC_ONLY",
        "manifest_sha256": _MANIFEST_SHA256,
        "candidate_identity": dict(candidate),
        "worker_identity": {"identity_kind": "AUTHENTICATED", **worker_identity},
        "fit_enabled": False,
        "selection_authority": "NONE",
        "acceptance_authority": "NONE",
    }


def _assert_profile_start_ready(
    plan: Plan,
    candidate: Mapping[str, Any],
    worker_identity: Mapping[str, Any],
) -> None:
    if os.path.lexists(plan.output_directory):
        raise _fail("KDE_PROFILE.OUTPUT_EXISTS")
    if not _required_profile_families(plan):
        raise _fail("KDE_PROFILE.PROFILE_FAMILY_DEFINITION")
    _verify_qualification_receipt(plan, candidate, worker_identity)


def _required_profile_families(plan: Plan) -> frozenset[tuple[str, str]]:
    coordinates = cast(Sequence[Mapping[str, Any]], plan.manifest.get("coordinates", ()))
    return frozenset(
        (str(coordinate["family_id"]), str(coordinate["variant_id"])) for coordinate in coordinates
    )


def run_kde_profile_development() -> dict[str, Any]:
    plan, candidate = _preflight()
    if os.path.lexists(plan.output_directory):
        raise _fail("KDE_PROFILE.OUTPUT_EXISTS")
    invoker, worker_identity, expected_context = _worker(plan)
    _assert_profile_start_ready(plan, candidate, worker_identity)
    datasets = _datasets(plan)
    _envelope_gate(plan, candidate, worker_identity, datasets)
    plan.output_directory.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    _assert_profile_start_ready(plan, candidate, worker_identity)
    plan.output_directory.mkdir(mode=0o700)
    attempts: list[Mapping[str, Any]] = []
    captures: list[_Capture] = []
    cache: dict[tuple[str, str, int, int], _TargetProof] = {}
    terminal: Mapping[str, Any] | None = None
    phase = "FIT"
    try:
        for row in plan.rows:
            key = (
                str(row["family_id"]),
                str(row["variant_id"]),
                int(row["replicate_index"]),
            )
            attempt = _fit_one(
                plan,
                invoker,
                row,
                datasets[key],
                expected_context=expected_context,
            )
            phase = "ATTEMPT_VALIDATION"
            capture = _parse_attempt(
                plan,
                row,
                attempt,
                datasets[key],
                cache,
                expected_context,
            )
            phase = "ATTEMPT_ARTIFACT_FINALIZATION"
            captures.append(capture)
            _, raw, reference = _attempt_artifact(plan, attempt)
            publish_receipt(plan.output_directory, str(reference["relative_filename"]), raw)
            attempts.append(reference)
            phase = "FIT"
    except Exception as error:
        terminal = _terminal_receipt_failure(error, phase, len(attempts))
    quality_reference: Mapping[str, Any] | None = None
    if terminal is None:
        try:
            phase = "TRANSITION_QUALITY"
            _, quality_raw, quality_reference = _quality_artifact(
                plan, transition_quality(captures)
            )
            phase = "READY_RECEIPT_BUILD"
            receipt = _receipt(
                plan,
                attempts,
                worker_identity=worker_identity,
                candidate_identity=candidate,
                transition_quality_reference=quality_reference,
                terminal_failure=None,
            )
            receipt_raw = _schema_bytes(plan, receipt)
            _verify_receipt(
                plan,
                receipt,
                expected_context,
                {_EVIDENCE_NAME: receipt_raw, _QUALITY_NAME: quality_raw},
            )
            phase = "TRANSITION_QUALITY"
            publish_receipt(plan.output_directory, _QUALITY_NAME, quality_raw)
        except Exception as error:
            terminal = terminal_failure(error, phase, None)
    if terminal is not None:
        receipt = _receipt(
            plan,
            attempts,
            worker_identity=worker_identity,
            candidate_identity=candidate,
            transition_quality_reference=None,
            terminal_failure=terminal,
        )
        receipt_raw = _schema_bytes(plan, receipt)
        _verify_receipt(
            plan,
            receipt,
            expected_context,
            {_EVIDENCE_NAME: receipt_raw},
        )
    publish_receipt(plan.output_directory, _EVIDENCE_NAME, receipt_raw)
    return receipt


def _qualification_receipt(
    plan: Plan,
    *,
    candidate_identity: Mapping[str, Any],
    worker_identity: Mapping[str, Any],
    completed_fit_count: int,
    terminal_failure_value: Mapping[str, Any] | None,
) -> dict[str, Any]:
    preimage = {
        **copy.deepcopy(plan.manifest["evidence_receipt_boundary"]),
        "manifest_sha256": _MANIFEST_SHA256,
        "status": "DO_NOT_ADVANCE",
        "observed_attempt_count": completed_fit_count,
        "candidate_identity": copy.deepcopy(dict(candidate_identity)),
        "worker_identity": copy.deepcopy(dict(worker_identity)),
        "attempt_references": [],
        "transition_quality_reference": None,
        "terminal_failure": None
        if terminal_failure_value is None
        else copy.deepcopy(dict(terminal_failure_value)),
        "receipt_digest": None,
    }
    result = copy.deepcopy(preimage)
    result["receipt_digest"] = structured_sha256(
        _QUALIFICATION_RECEIPT_DOMAIN,
        {
            "receipt": preimage,
            "ordered_qualification_attempt_ids": [
                row["attempt_id"] for row in plan.qualification_rows
            ],
        },
    )
    return result


def _verify_qualification_receipt(
    plan: Plan,
    candidate: Mapping[str, Any],
    worker_identity: Mapping[str, Any],
) -> dict[str, Any]:
    directory = plan.qualification_output_directory
    try:
        entries = list(directory.iterdir())
    except OSError:
        raise _fail("KDE_PROFILE.QUALIFICATION_REQUIRED") from None
    if directory.is_symlink() or {entry.name for entry in entries} != {_QUALIFICATION_NAME}:
        raise _fail("KDE_PROFILE.QUALIFICATION_PATH")
    path = directory / _QUALIFICATION_NAME
    if path.is_symlink() or not path.is_file():
        raise _fail("KDE_PROFILE.QUALIFICATION_PATH")
    try:
        raw = path.read_bytes()
    except OSError:
        raise _fail("KDE_PROFILE.QUALIFICATION_PATH") from None
    receipt = _strict_json(raw)
    if _schema_bytes(plan, receipt) != raw:
        raise _fail("KDE_PROFILE.QUALIFICATION_NONCANONICAL")
    preimage = copy.deepcopy(receipt)
    supplied_digest = preimage["receipt_digest"]
    preimage["receipt_digest"] = None
    expected_digest = structured_sha256(
        _QUALIFICATION_RECEIPT_DOMAIN,
        {
            "receipt": preimage,
            "ordered_qualification_attempt_ids": [
                row["attempt_id"] for row in plan.qualification_rows
            ],
        },
    )
    if (
        supplied_digest != expected_digest
        or receipt.get("manifest_sha256") != _MANIFEST_SHA256
        or receipt.get("status") != "DO_NOT_ADVANCE"
        or receipt.get("expected_attempt_count")
        != plan.manifest["evidence_receipt_boundary"]["expected_attempt_count"]
        or receipt.get("observed_attempt_count") != 2
        or receipt.get("attempt_references") != []
        or receipt.get("transition_quality_reference") is not None
        or receipt.get("terminal_failure") is not None
        or receipt.get("candidate_identity") != candidate
        or [int(row["serial_position"]) for row in plan.qualification_rows] != [0, 1]
    ):
        raise _fail("KDE_PROFILE.QUALIFICATION_MISMATCH")
    _verify_candidate(receipt["candidate_identity"])
    try:
        identity = cast(Mapping[str, Any], plan.manifest["worker"]["identity"])
        fields = cast(list[str], plan.manifest["worker_identity_receipt_fields"])
        verify_worker_identity(worker_identity, expected=identity, fields=fields)
        projected_worker = dict(cast(Mapping[str, Any], receipt["worker_identity"]))
        if projected_worker.pop("identity_kind", None) != "AUTHENTICATED":
            raise WorkerV2DevelopmentError("identity is not authenticated")
        verify_worker_identity(
            projected_worker,
            expected=identity,
            fields=fields,
        )
    except WorkerV2DevelopmentError:
        raise _fail("KDE_PROFILE.WORKER_IDENTITY") from None
    return receipt


def _terminal_receipt_failure(
    error: Exception, phase: str, completed_fit_count: int
) -> dict[str, Any]:
    projected = terminal_failure(error, phase, completed_fit_count)
    result: dict[str, Any] = {
        "failure_code": projected["failure_code"],
        "phase": phase,
        "completed_fit_count": completed_fit_count,
    }
    if "semantic_rule" in projected:
        result["semantic_rule"] = projected["semantic_rule"]
    if "callback_failure" in projected:
        result["callback_failure"] = projected["callback_failure"]
    if "payload_finalization_failure" in projected:
        result["payload_finalization_failure"] = projected["payload_finalization_failure"]
    return result


def run_kde_profile_development_qualification() -> dict[str, Any]:
    plan, candidate = _preflight()
    _assert_new_start_boundaries_absent(plan)
    invoker, authenticated_identity, expected_context = _worker(plan)
    worker_identity = {"identity_kind": "AUTHENTICATED", **authenticated_identity}
    _assert_new_start_boundaries_absent(plan)
    plan.qualification_output_directory.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    _assert_new_start_boundaries_absent(plan)
    plan.qualification_output_directory.mkdir(mode=0o700)

    completed_fit_count = 0
    phase = "DATASET_PREPARATION"
    try:
        datasets = _datasets(plan)
        phase = "ENVELOPE_VALIDATION"
        _envelope_gate(plan, candidate, worker_identity, datasets)
        target_cache: dict[tuple[str, str, int, int], _TargetProof] = {}
        for row in plan.qualification_rows:
            key = (
                str(row["family_id"]),
                str(row["variant_id"]),
                int(row["replicate_index"]),
            )
            completed_response = [False]
            phase = "FIT"
            try:
                attempt = _fit_one(
                    plan,
                    invoker,
                    row,
                    datasets[key],
                    expected_context=expected_context,
                    completed_response=completed_response,
                )
            finally:
                completed_fit_count += int(completed_response[0])
            phase = "ATTEMPT_VALIDATION"
            _parse_attempt(
                plan,
                row,
                attempt,
                datasets[key],
                target_cache,
                expected_context,
            )
        phase = "RECEIPT_CONSTRUCTION"
        receipt = _qualification_receipt(
            plan,
            candidate_identity=candidate,
            worker_identity=worker_identity,
            completed_fit_count=completed_fit_count,
            terminal_failure_value=None,
        )
        _schema_bytes(plan, receipt)
        phase = "RECEIPT_PUBLICATION"
        publish_receipt(
            plan.qualification_output_directory,
            _QUALIFICATION_NAME,
            canonical_json_bytes(receipt),
        )
        _verify_qualification_receipt(plan, candidate, authenticated_identity)
        return receipt
    except Exception as error:
        if phase == "RECEIPT_PUBLICATION":
            raise
        terminal = _terminal_receipt_failure(error, phase, completed_fit_count)
        phase = "RECEIPT_CONSTRUCTION"
        receipt = _qualification_receipt(
            plan,
            candidate_identity=candidate,
            worker_identity=worker_identity,
            completed_fit_count=completed_fit_count,
            terminal_failure_value=terminal,
        )
        _schema_bytes(plan, receipt)
        phase = "RECEIPT_PUBLICATION"
        publish_receipt(
            plan.qualification_output_directory,
            _QUALIFICATION_NAME,
            canonical_json_bytes(receipt),
        )
        return receipt


def verify_kde_profile_development_evidence() -> dict[str, Any]:
    plan = Plan.load()
    path = plan.output_directory / _EVIDENCE_NAME
    if path.is_symlink() or not path.is_file():
        raise _fail("KDE_PROFILE.EVIDENCE_PATH")
    receipt = _strict_json(path.read_bytes())
    _invoker, _worker_identity, expected_context = _worker(plan)
    _verify_receipt(plan, receipt, expected_context)
    return copy.deepcopy(receipt)
