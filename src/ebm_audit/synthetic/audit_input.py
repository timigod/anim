"""Authorized public-synthetic cases admitted through the ordinary input path.

This module is deliberately independent of development-null and evaluator
domains.  Those domains resolve their own genuine parent owner, then cross the
private issuer seam with canonical parent-binding bytes and one exact
AnalysisSpec.  No public constructor accepts a mapping, seed, generated table,
truth array, or participant-unit binding.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import math
import os
import stat
import struct
import sys
import weakref
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any, Final, Literal, Never, SupportsIndex, cast, final
from weakref import WeakSet

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.adapters import WorkerConfig, normalize_worker_timeout_seconds
from ebm_audit.artifacts import StagedOutputTransaction
from ebm_audit.config import (
    RunEligibleAuditConfig,
    VerifiedAuditConfigFiles,
    authorize_audit_config_run,
    load_audit_config,
    parse_audit_config,
    verify_audit_config_files,
)
from ebm_audit.config.models import ResolvedAuditConfig
from ebm_audit.config.verification import (
    _MAX_WORKER_CONFIG_BYTES,
    _open_private_root,
    _read_private_file,
)
from ebm_audit.data import PreparedAuditDataset, prepare_audit_dataset
from ebm_audit.data.preparation import _private_prepared_dataset
from ebm_audit.errors import InvalidInputError, UnexpectedCoreError
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import (
    backend_identity_digest,
    canonical_json_bytes,
    exact_file_sha256,
    expected_identity_pin_digest,
    settings_digest,
    strict_json_loads,
    structured_sha256,
    structured_sha256_hex,
)
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.universe.identities import (
    _expected_operation_seed,
    _private_evaluation_membership_digest,
    analysis_spec_content_id,
)
from ebm_audit.universe.preparation import (
    PreparedExecutionAuthorization,
    UnpreparedResultAuthorization,
    _resolve_prepared_execution_authorization,
    _resolve_unprepared_result_authorization,
)

from .authority import ScenarioAuthority, load_scenario_authority
from .generator import _generate_already_authorized_case, generate_synthetic_case
from .models import (
    AuthenticatedSourceOwner,
    CaseCoordinate,
    ReplayReceipt,
    ResolvedSyntheticCase,
    RetainedGeneratorInvalid,
    SyntheticCaseArtifacts,
)
from .replay import _replay_already_authorized_case, replay_synthetic_case
from .resolver import (
    _resolve_authenticated_heldout_case,
    resolve_development_case,
    verify_exact_resolution,
)

_MAX_AUTHORITY_BYTES: Final = 8 * 1024 * 1024
_PRIVATE_ROOT: Final = "_public-synthetic-audit-input"
_PRIVATE_CONFIG: Final = "audit.json"
_PRIVATE_CSV: Final = "source.csv"
_PRIVATE_WORKER: Final = "worker.json"
_PARENT_BINDING_DOMAIN: Final = "ebm-audit/development-case-parent-binding/1"
_CASE_DIRECTORY_DOMAIN: Final = "ebm-audit/development-case-private-directory/1"
_SLOT_DIRECTORY_DOMAIN: Final = "ebm-audit/development-case-private-slot/1"
_REPLAY_RECEIPT_DOMAIN: Final = "ebm-audit/synthetic-replay-receipt/1"
_REPLAY_LEDGER_DOMAIN: Final = "ebm-audit/synthetic-replay-stage-ledger/1"
_MAPPING_DOMAIN: Final = "ebm-audit/public-synthetic-csv-mapping/3"
_INPUT_PROJECTION_DOMAIN: Final = "ebm-audit/public-synthetic-audit-input/3"
_PREPARATION_BINDING_DOMAIN: Final = "ebm-audit/public-synthetic-preparation-binding/1"
_TRUTH_ROWS_DOMAIN: Final = "ebm-audit/synthetic-evaluation-truth-rows/1"
_TRUTH_COHORT_DOMAIN: Final = "ebm-audit/synthetic-evaluation-truth-cohort/1"
_TRUTH_EVENT_MAP_DOMAIN: Final = "ebm-audit/synthetic-evaluation-truth-event-map/1"
_TRUTH_DIRECTION_DOMAIN: Final = "ebm-audit/synthetic-evaluation-truth-directions/1"
_TRUTH_AXIS_DOMAIN: Final = "ebm-audit/synthetic-evaluation-truth-axis/1"
_TRUTH_PROJECTION_DOMAIN: Final = "ebm-audit/synthetic-evaluation-truth-evidence/1"
_PROFILE_SYNTHETIC_EVENT_BINDING_DOMAIN: Final = "ebm-audit/profile-synthetic-event-binding/1"
_PROFILE_RESERVED_SEED_DOMAIN: Final = "ebm-audit/profile-reserved-seed-placeholder/2"
_PROFILE_PARTICIPANT_NAMESPACE_DOMAIN: Final = "ebm-audit/profile-participant-namespace/1"
_BENCHMARK_EXECUTION_IDENTITY_DOMAIN: Final = "ebm-audit/benchmark-execution-identity/1"
_BENCHMARK_EXECUTION_SEED_DOMAIN: Final = "ebm-audit/benchmark-execution-placeholder/1"
_BENCHMARK_PARTICIPANT_NAMESPACE_DOMAIN: Final = "ebm-audit/benchmark-participant-namespace/1"
_PUBLIC_BATCH_EXECUTION_IDENTITY_DOMAIN: Final = "ebm-audit/public-batch-execution-identity/1"
_PUBLIC_BATCH_EXECUTION_SEED_DOMAIN: Final = "ebm-audit/public-batch-execution-placeholder/1"
_PUBLIC_BATCH_PARTICIPANT_NAMESPACE_DOMAIN: Final = (
    "ebm-audit/public-batch-participant-namespace/1"
)
_PROFILE_EXECUTION_SOURCE_MANIFEST_DOMAIN: Final = "ebm-audit/profile-execution-source-manifest/1"
# This versions the configured later seed expansion, not the reserved placeholder.
# The no-fit placeholder has its own independently versioned domain above.
_PROFILE_SEED_DERIVATION_VERSION: Final = "hmac-sha256-u64be-v2"
_PROFILE_SEED_AUTHORITY_STATE: Final = "RESERVED_PLACEHOLDER_NOT_CHAIN_SEED_AUTHORITY"
_PROFILE_SEED_MATRIX_REQUIREMENT: Final = "MANDATORY_PROFILE_SEED_MATRIX"
_INPUT_MAPPING_RULE_ID: Final = "public-synthetic-csv-and-analysis-catalog/3"
_TRUTH_RULE_ID: Final = "generator-threshold-stage-to-mapped-strict-prefix/1"
_STAGE_SEMANTICS: Final = "strict-prefix-count/1"
_THRESHOLD_STAGE: Final = "THRESHOLD_STAGE"
_GROUP_BINDINGS: Final = (
    ("reference", "development-label-0001", "reference"),
    ("at_risk", "development-label-0002", "at_risk"),
)


def _invalid(code: str) -> InvalidInputError:
    return InvalidInputError(code, "The public synthetic audit input is invalid.")


def _integrity(code: str) -> UnexpectedCoreError:
    return UnexpectedCoreError(
        code,
        "Public synthetic evidence changed after its exact owner was issued.",
    )


def _digest(value: object, *, code: str) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise _invalid(code)
    return value


def _public_digest_from_generator_hex(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_GENERATOR_DIGEST_INVALID")
    return "sha256:" + value


def _closed_mapping_bytes(value: bytes, *, code: str) -> tuple[bytes, dict[str, Any]]:
    if type(value) is not bytes:
        raise _invalid(code)
    try:
        parsed = strict_json_loads(value)
    except (TypeError, ValueError):
        raise _invalid(code) from None
    if type(parsed) is not dict or canonical_json_bytes(parsed) != value:
        raise _invalid(code)
    return value, cast(dict[str, Any], parsed)


def _coordinate_record(coordinate: CaseCoordinate) -> dict[str, object]:
    if (
        type(coordinate) is not CaseCoordinate
        or type(coordinate.family_id) is not str
        or not coordinate.family_id
        or type(coordinate.variant_id) is not str
        or not coordinate.variant_id
        or type(coordinate.replicate_index) is not int
        or coordinate.replicate_index < 0
        or coordinate.resolution_mode != "DEVELOPMENT_VARIANT"
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_COORDINATE_INVALID")
    return {
        "family_id": coordinate.family_id,
        "variant_id": coordinate.variant_id,
        "replicate_index": coordinate.replicate_index,
        "resolution_mode": coordinate.resolution_mode,
    }


def _public_batch_coordinate_record(coordinate: CaseCoordinate) -> dict[str, object]:
    if (
        type(coordinate) is not CaseCoordinate
        or type(coordinate.family_id) is not str
        or not coordinate.family_id
        or type(coordinate.variant_id) is not str
        or not coordinate.variant_id
        or type(coordinate.replicate_index) is not int
        or coordinate.replicate_index < 0
        or coordinate.resolution_mode
        not in {"DEVELOPMENT_VARIANT", "TRANSFORMED_SOURCE"}
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_COORDINATE_INVALID")
    return {
        "family_id": coordinate.family_id,
        "variant_id": coordinate.variant_id,
        "replicate_index": coordinate.replicate_index,
        "resolution_mode": coordinate.resolution_mode,
    }


def _heldout_coordinate_record(coordinate: CaseCoordinate) -> dict[str, object]:
    if (
        type(coordinate) is not CaseCoordinate
        or type(coordinate.family_id) is not str
        or not coordinate.family_id
        or type(coordinate.variant_id) is not str
        or not coordinate.variant_id
        or type(coordinate.replicate_index) is not int
        or coordinate.replicate_index < 0
        or coordinate.resolution_mode not in {"HELDOUT_RANGE", "TRANSFORMED_SOURCE"}
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_COORDINATE_INVALID")
    return {
        "family_id": coordinate.family_id,
        "variant_id": coordinate.variant_id,
        "replicate_index": coordinate.replicate_index,
        "resolution_mode": coordinate.resolution_mode,
    }


def _read_declared_bytes(
    resolved: ResolvedAuditConfig,
    relative_path: str,
    *,
    expected_digest: str,
    maximum_bytes: int,
) -> bytes:
    root = _open_private_root(resolved.private_paths.source_config.parent)
    try:
        digest, _identity, content = _read_private_file(
            root,
            relative_path,
            maximum_bytes=maximum_bytes,
            retain_bytes=True,
        )
    finally:
        os.close(root)
    if content is None or digest != expected_digest:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_DECLARED_FILE_MISMATCH")
    return content


def _read_exact_source_inputs(
    resolved: ResolvedAuditConfig,
) -> tuple[bytes, bytes, bytes]:
    if type(resolved) is not ResolvedAuditConfig:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_SOURCE_CONFIG_INVALID")
    config = resolved.private_config
    descriptor = config.get("development_scenario_authority")
    worker = config.get("worker")
    if (
        type(descriptor) is not dict
        or set(descriptor) != {"path", "expected_byte_digest"}
        or type(worker) is not dict
        or resolved.private_paths.development_scenario_authority is None
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_AUTHORITY_UNDECLARED")
    source_name = resolved.private_paths.source_config.name
    root = _open_private_root(resolved.private_paths.source_config.parent)
    try:
        _config_digest, _identity, config_bytes = _read_private_file(
            root,
            source_name,
            maximum_bytes=2 * 1024 * 1024,
            retain_bytes=True,
        )
    finally:
        os.close(root)
    if config_bytes is None or parse_audit_config(config_bytes) != config:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_SOURCE_CONFIG_CHANGED")
    authority_bytes = _read_declared_bytes(
        resolved,
        cast(str, descriptor["path"]),
        expected_digest=cast(str, descriptor["expected_byte_digest"]),
        maximum_bytes=_MAX_AUTHORITY_BYTES,
    )
    worker_bytes = _read_declared_bytes(
        resolved,
        cast(str, worker["config_path"]),
        expected_digest=cast(str, worker["worker_config_digest"]),
        maximum_bytes=_MAX_WORKER_CONFIG_BYTES,
    )
    return config_bytes, authority_bytes, worker_bytes


@dataclass(frozen=True, slots=True)
class _ClosedReplayReceipt:
    compared_stage_count: int
    stage_ledger_digest: str
    receipt_digest: str


def _close_replay_receipt(
    receipt: ReplayReceipt,
    artifacts: SyntheticCaseArtifacts,
) -> _ClosedReplayReceipt:
    if (
        type(receipt) is not ReplayReceipt
        or receipt.status != "MATCH"
        or receipt.first_mismatch_stage is not None
        or receipt.expected_stage_sha256 is not None
        or receipt.candidate_stage_sha256 is not None
        or receipt.data_match is not True
        or receipt.truth_match is not True
        or receipt.compared_stage_count != len(artifacts.stage_snapshots)
        or receipt.compared_stage_count < 1
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_REPLAY_FAILED")
    ledger = [
        {
            "stage_index": row.stage_index,
            "stage_id": row.stage_id,
            "output_sha256": row.output_sha256,
        }
        for row in artifacts.stage_snapshots
    ]
    stage_ledger_digest = structured_sha256(_REPLAY_LEDGER_DOMAIN, ledger)
    preimage = {
        "status": "MATCH",
        "compared_stage_count": receipt.compared_stage_count,
        "data_match": True,
        "truth_match": True,
        "stage_ledger_digest": stage_ledger_digest,
    }
    return _ClosedReplayReceipt(
        compared_stage_count=receipt.compared_stage_count,
        stage_ledger_digest=stage_ledger_digest,
        receipt_digest=structured_sha256(_REPLAY_RECEIPT_DOMAIN, preimage),
    )


def _float_token(value: object) -> str:
    if type(value) not in {int, float}:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_DATA_INVALID")
    token = repr(float(cast(float, value)))
    if token in {"nan", "inf", "-inf"}:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_DATA_INVALID")
    return token


def _serialize_generated_csv(
    artifacts: SyntheticCaseArtifacts,
    *,
    participant_namespace: str | None,
) -> tuple[bytes, dict[str, Any]]:
    """Serialize only generator-owned values under one fixed mapping rule."""

    data = artifacts.scientific_data
    values = data.get("values")
    masks = data.get("missingness_mask")
    labels = data.get("analysis_group_labels")
    event_ids = data.get("event_ids")
    directions = data.get("event_directions")
    covariate_ids = data.get("covariate_ids")
    covariates = data.get("covariate_values")
    dimensions = data.get("dimensions")
    if (
        (
            participant_namespace is not None
            and (
                type(participant_namespace) is not str
                or len(participant_namespace) != 64
                or any(character not in "0123456789abcdef" for character in participant_namespace)
            )
        )
        or type(values) is not list
        or type(masks) is not list
        or type(labels) is not list
        or type(event_ids) is not list
        or type(directions) is not list
        or type(covariate_ids) is not list
        or type(covariates) is not list
        or type(dimensions) is not dict
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_DATA_INVALID")
    participant_count = dimensions.get("participant_count")
    event_count = dimensions.get("event_count")
    covariate_count = len(covariate_ids)
    if (
        type(participant_count) is not int
        or type(event_count) is not int
        or participant_count < 2
        or event_count < 2
        or len(values) != participant_count
        or len(masks) != participant_count
        or len(labels) != participant_count
        or len(covariates) != participant_count
        or len(event_ids) != event_count
        or len(directions) != event_count
        or any(type(event_id) is not str or not event_id for event_id in event_ids)
        or any(direction not in {"higher", "lower"} for direction in directions)
        or any(type(covariate_id) is not str or not covariate_id for covariate_id in covariate_ids)
        or len(set(event_ids)) != event_count
        or len(set(covariate_ids)) != covariate_count
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_DATA_INVALID")
    event_columns = [f"event_{index + 1:04d}" for index in range(event_count)]
    covariate_columns = [f"covariate_{index + 1:04d}" for index in range(covariate_count)]
    event_aliases = [f"development-event-{index + 1:04d}" for index in range(event_count)]
    covariate_aliases = [
        f"development-covariate-{index + 1:04d}" for index in range(covariate_count)
    ]
    participant_ids = (
        [f"development-participant-{index + 1:08d}" for index in range(participant_count)]
        if participant_namespace is None
        else [
            f"synthetic-{participant_namespace}-participant-{index + 1:08d}"
            for index in range(participant_count)
        ]
    )
    private_label_by_synthetic = {
        synthetic_label: private_label for synthetic_label, private_label, _role in _GROUP_BINDINGS
    }
    stream = io.StringIO(newline="")
    writer = csv.writer(
        stream,
        delimiter=",",
        quotechar='"',
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
        strict=True,
    )
    writer.writerow(["participant_code", "analysis_group", *event_columns, *covariate_columns])
    missing_cell_count = 0
    for index in range(participant_count):
        row_values = values[index]
        row_masks = masks[index]
        row_covariates = covariates[index]
        label = labels[index]
        if (
            type(row_values) is not list
            or type(row_masks) is not list
            or type(row_covariates) is not list
            or len(row_values) != event_count
            or len(row_masks) != event_count
            or len(row_covariates) != covariate_count
            or label not in private_label_by_synthetic
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_DATA_INVALID")
        event_tokens: list[str] = []
        for value, masked in zip(row_values, row_masks, strict=True):
            if type(masked) is not bool or (value is None) is not masked:
                raise _invalid("SYNTHETIC.AUDIT_INPUT_DATA_INVALID")
            if masked:
                missing_cell_count += 1
                event_tokens.append("")
            else:
                event_tokens.append(_float_token(value))
        writer.writerow(
            [
                participant_ids[index],
                private_label_by_synthetic[label],
                *event_tokens,
                *(_float_token(value) for value in row_covariates),
            ]
        )
    mapping = {
        "mapping_schema_version": "ebm-audit-public-synthetic-csv-mapping/3.0",
        "mapping_rule_id": _INPUT_MAPPING_RULE_ID,
        "participant_column": "participant_code",
        "group_column": "analysis_group",
        "participant_bindings": [
            {
                "generator_participant_index": index,
                "participant_private_id": private_id,
            }
            for index, private_id in enumerate(participant_ids)
        ],
        "group_bindings": [
            {
                "synthetic_group_label": synthetic_label,
                "private_group_label": private_label,
                "role": role,
            }
            for synthetic_label, private_label, role in _GROUP_BINDINGS
        ],
        "event_bindings": [
            {
                "event_id": event_alias,
                "synthetic_event_id": event_id,
                "source_column": column,
                "source_truth_direction": direction,
                "analysis_direction": direction,
            }
            for event_alias, event_id, column, direction in zip(
                event_aliases,
                event_ids,
                event_columns,
                directions,
                strict=True,
            )
        ],
        "covariate_bindings": [
            {
                "covariate_id": covariate_alias,
                "synthetic_covariate_id": covariate_id,
                "source_column": column,
            }
            for covariate_alias, covariate_id, column in zip(
                covariate_aliases,
                covariate_ids,
                covariate_columns,
                strict=True,
            )
        ],
        "participant_count": participant_count,
        "event_count": event_count,
        "covariate_count": covariate_count,
        "missing_cell_count": missing_cell_count,
        "serialization_rule": "utf8-csv-lf-python-shortest-roundtrip-float64/1",
    }
    return stream.getvalue().encode("utf-8"), mapping


def _expected_catalog_fields(mapping: Mapping[str, Any]) -> dict[str, Any]:
    event_bindings = cast(list[dict[str, str]], mapping["event_bindings"])
    profile_catalog = mapping.get("profile_analysis_catalog")
    if isinstance(profile_catalog, Mapping):
        return {
            "dataset_variant_intent": copy.deepcopy(
                cast(Mapping[str, Any], profile_catalog["dataset_variant_intent"])
            ),
            "cohort_rule": copy.deepcopy(cast(Mapping[str, Any], profile_catalog["cohort_rule"])),
            "event_set": copy.deepcopy(cast(list[dict[str, Any]], profile_catalog["event_set"])),
            "event_directions": copy.deepcopy(
                cast(Mapping[str, str], profile_catalog["event_directions"])
            ),
            "event_ids": [row["event_id"] for row in event_bindings],
        }
    return {
        "dataset_variant_intent": {
            "source_variant_id": "development-null-input",
            "variant_kind": "baseline-input",
            "source_variant_id_ref": None,
            "method_id": "exact-input-bytes/1",
        },
        "cohort_rule": {
            "group_spec_id": "development-null-groups",
            "source_kind": "label-alias",
            "public_field_ids": ["analysis-group"],
            "label_roles": [
                {"public_label_id": "group-at-risk", "role": "at_risk"},
                {"public_label_id": "group-reference", "role": "reference"},
            ],
            "role_rules": [],
            "required_roles": ["reference", "at_risk"],
        },
        "event_set": [{"event_id": row["event_id"]} for row in event_bindings],
        "event_directions": {row["event_id"]: row["analysis_direction"] for row in event_bindings},
        "event_ids": [row["event_id"] for row in event_bindings],
    }


def _compile_input_analysis_spec(
    source_spec: Mapping[str, Any],
    mapping: Mapping[str, Any],
) -> dict[str, Any]:
    """Replace only the catalog fields fixed by mapping rule version 1."""

    expected = _expected_catalog_fields(mapping)
    spec = copy.deepcopy(dict(source_spec))
    spec["dataset_variant_intent"] = expected["dataset_variant_intent"]
    spec["cohort_rule"] = expected["cohort_rule"]
    spec["event_set"] = expected["event_set"]
    spec["event_directions"] = expected["event_directions"]
    missingness = spec.get("missingness_policy")
    if not isinstance(missingness, Mapping):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_ANALYSIS_SPEC_INVALID")
    spec["missingness_policy"] = {
        **copy.deepcopy(dict(missingness)),
        "event_ids": expected["event_ids"],
    }
    spec["operation_intent"] = {"kind": "ordinary"}
    try:
        analysis_spec_content_id(spec)
    except (SchemaValidationError, TypeError, ValueError):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_ANALYSIS_SPEC_INVALID") from None
    return spec


def _apply_profile_analysis_catalog(
    mapping: dict[str, Any],
    analysis_spec: Mapping[str, Any],
) -> None:
    """Bind physical columns to the plan's analysis vocabulary, not truth direction."""

    event_set = analysis_spec.get("event_set")
    directions = analysis_spec.get("event_directions")
    cohort_rule = analysis_spec.get("cohort_rule")
    variant = analysis_spec.get("dataset_variant_intent")
    if (
        not isinstance(event_set, list)
        or not isinstance(directions, Mapping)
        or not isinstance(cohort_rule, Mapping)
        or not isinstance(variant, Mapping)
        or len(event_set) != len(cast(list[object], mapping["event_bindings"]))
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_CATALOG_INVALID")
    event_ids = [row.get("event_id") if isinstance(row, Mapping) else None for row in event_set]
    if (
        any(type(event_id) is not str or not event_id for event_id in event_ids)
        or set(directions) != set(cast(list[str], event_ids))
        or any(direction not in {"higher", "lower"} for direction in directions.values())
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_CATALOG_INVALID")
    for binding, event_id in zip(mapping["event_bindings"], event_ids, strict=True):
        if not isinstance(binding, dict):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_CATALOG_INVALID")
        binding["event_id"] = event_id
        binding["analysis_direction"] = directions[event_id]
    mapping["profile_analysis_catalog"] = {
        "dataset_variant_intent": copy.deepcopy(dict(variant)),
        "cohort_rule": copy.deepcopy(dict(cohort_rule)),
        "event_set": copy.deepcopy(event_set),
        "event_directions": copy.deepcopy(dict(directions)),
    }


def _validate_analysis_spec_for_mapping(
    analysis_spec: Mapping[str, Any],
    mapping: Mapping[str, Any],
    *,
    baseline_analysis_spec_id: str | None = None,
) -> None:
    expected = _expected_catalog_fields(mapping)
    missingness = analysis_spec.get("missingness_policy")
    covariate = analysis_spec.get("covariate_adjustment")
    operation = analysis_spec.get("operation_intent")
    variant = analysis_spec.get("dataset_variant_intent")
    operation_kind = operation.get("kind") if isinstance(operation, Mapping) else None
    expected_variant = cast(Mapping[str, Any], expected["dataset_variant_intent"])
    if operation_kind == "ordinary":
        variant_matches = variant == expected_variant
    elif operation_kind in {"bootstrap", "subsample", "influence", "null"}:
        variant_matches = (
            isinstance(operation, Mapping)
            and isinstance(variant, Mapping)
            and baseline_analysis_spec_id is not None
            and operation.get("source_analysis_spec_id") == baseline_analysis_spec_id
            and operation.get("source_variant_id") == expected_variant["source_variant_id"]
            and variant.get("source_variant_id_ref") == expected_variant["source_variant_id"]
        )
    else:
        variant_matches = False
    covariate_ids = {
        row["covariate_id"] for row in cast(list[dict[str, str]], mapping["covariate_bindings"])
    }
    if (
        not variant_matches
        or analysis_spec.get("cohort_rule") != expected["cohort_rule"]
        or analysis_spec.get("event_set") != expected["event_set"]
        or analysis_spec.get("event_directions") != expected["event_directions"]
        or not isinstance(missingness, Mapping)
        or missingness.get("event_ids") != expected["event_ids"]
        or missingness.get("policy") not in {"error", "complete-case", "external-variant"}
        or not isinstance(covariate, Mapping)
        or type(covariate.get("ordered_terms")) is not list
        or not set(cast(list[str], covariate["ordered_terms"])).issubset(covariate_ids)
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_ANALYSIS_SPEC_CATALOG_MISMATCH")


def _derived_profile_worker_config_bytes(
    source_worker_config: WorkerConfig,
    analysis_spec: Mapping[str, Any],
) -> bytes:
    """Join source-owned worker identity to Plan-owned budget-zero settings."""

    backend = analysis_spec.get("backend")
    if (
        type(source_worker_config) is not WorkerConfig
        or source_worker_config.expected_identity is None
        or not isinstance(backend, Mapping)
        or not isinstance(backend.get("settings"), Mapping)
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_WORKER_CONFIG_INVALID")
    settings = cast(Mapping[str, Any], backend["settings"])
    if backend.get("algorithm_id") != source_worker_config.algorithm_id or backend.get(
        "settings_digest"
    ) != settings_digest(settings):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_WORKER_CONFIG_INVALID")
    derived_bytes = canonical_json_bytes(
        {
            "worker": {"argv": list(source_worker_config.worker.argv)},
            "algorithm_id": source_worker_config.algorithm_id,
            "settings": copy.deepcopy(dict(settings)),
            "expected_identity": copy.deepcopy(dict(source_worker_config.expected_identity)),
        }
    )
    try:
        derived = WorkerConfig.from_yaml_bytes(derived_bytes)
    except InvalidInputError:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_WORKER_CONFIG_INVALID") from None
    if (
        derived.worker != source_worker_config.worker
        or derived.algorithm_id != source_worker_config.algorithm_id
        or canonical_json_bytes(derived.expected_identity)
        != canonical_json_bytes(source_worker_config.expected_identity)
        or canonical_json_bytes(derived.settings) != canonical_json_bytes(settings)
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_WORKER_CONFIG_INVALID")
    return derived_bytes


def _derived_config(
    source: Mapping[str, Any],
    artifacts: SyntheticCaseArtifacts,
    csv_bytes: bytes,
    mapping: Mapping[str, Any],
    analysis_spec: Mapping[str, Any],
    worker_config_digest: str,
    reserved_profile_seed_placeholder: str,
    custom_analysis_specs: tuple[Mapping[str, Any], ...] = (),
) -> dict[str, Any]:
    group_bindings = cast(list[dict[str, str]], mapping["group_bindings"])
    event_bindings = cast(list[dict[str, str]], mapping["event_bindings"])
    covariate_bindings = cast(list[dict[str, str]], mapping["covariate_bindings"])
    input_digest = exact_file_sha256(csv_bytes)
    truth_digest = _public_digest_from_generator_hex(artifacts.truth["truth_object_sha256"])
    baseline = copy.deepcopy(dict(analysis_spec))
    _validate_analysis_spec_for_mapping(baseline, mapping)
    missingness_policy = cast(Mapping[str, Any], baseline["missingness_policy"])
    profiles = copy.deepcopy(cast(dict[str, Any], source["profiles"]))
    for profile in profiles.values():
        profile["bootstrap_replicates"] = 0
        profile["subsample_replicates"] = 0
        profile["influence_max_removals"] = 0
        profile["null_replicates_per_family"] = 0
    source_variant_id = (
        "baseline-input" if "profile_analysis_catalog" in mapping else "development-null-input"
    )
    source_variants = [
        {
            "source_variant_id": source_variant_id,
            "variant_kind": "baseline-input",
            "source_variant_id_ref": None,
            "method_id": "exact-input-bytes/1",
            "rationale": "The exact generated and independently replayed table.",
        }
    ]
    source_variant_by_id = {source_variant_id: source_variants[0]}
    for spec in custom_analysis_specs:
        intent = cast(Mapping[str, Any], spec["dataset_variant_intent"])
        derived_variant_id = cast(str, intent["source_variant_id"])
        if derived_variant_id == source_variant_id:
            continue
        row = {
            **copy.deepcopy(dict(intent)),
            "rationale": "Exact sealed derived AnalysisSpec source lineage.",
        }
        previous = source_variant_by_id.get(derived_variant_id)
        if previous is not None and canonical_json_bytes(previous) != canonical_json_bytes(row):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_ANALYSIS_SPEC_CATALOG_MISMATCH")
        if previous is None:
            source_variants.append(row)
            source_variant_by_id[derived_variant_id] = row
    ordinary_custom_specs = [
        spec
        for spec in custom_analysis_specs
        if cast(Mapping[str, Any], spec["operation_intent"])["kind"] == "ordinary"
    ]
    derived_specs_by_kind: dict[str, list[Mapping[str, Any]]] = {
        "bootstrap": [],
        "subsample": [],
        "influence": [],
        "null": [],
    }
    for spec in custom_analysis_specs:
        kind = cast(str, cast(Mapping[str, Any], spec["operation_intent"])["kind"])
        if kind != "ordinary":
            derived_specs_by_kind[kind].append(spec)
    if (
        derived_specs_by_kind["subsample"]
        or any(len(rows) > 1 for rows in derived_specs_by_kind.values())
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_ANALYSIS_SPEC_CATALOG_MISMATCH")

    experiment_sets: list[dict[str, Any]] = [
        {
            "experiment_set_id": "baseline",
            "mode": "baseline",
            "enabled": True,
            "rationale": "The fixed first profile AnalysisSpec over this generated input.",
            "axes": [],
            "members": [],
            "bootstrap": None,
            "subsample": None,
            "influence": None,
            "null_families": [],
        }
    ]
    if ordinary_custom_specs:
        experiment_sets.append(
            {
                "experiment_set_id": "profile-ordinary-specifications",
                "mode": "custom",
                "enabled": True,
                "rationale": "Exact sealed ordinary profile AnalysisSpecs.",
                "axes": [],
                "members": [
                    {
                        "member_id": f"profile-ordinary-{ordinal + 2}",
                        "analysis_spec": copy.deepcopy(dict(spec)),
                        "analysis_spec_id": analysis_spec_content_id(spec),
                        "rationale": "Exact sealed ordinary profile AnalysisSpec.",
                    }
                    for ordinal, spec in enumerate(ordinary_custom_specs)
                ],
                "bootstrap": None,
                "subsample": None,
                "influence": None,
                "null_families": [],
            }
        )
    if derived_specs_by_kind["bootstrap"]:
        operation = cast(
            Mapping[str, Any],
            derived_specs_by_kind["bootstrap"][0]["operation_intent"],
        )
        experiment_sets.append(
            {
                "experiment_set_id": "profile-bootstrap",
                "mode": "bootstrap",
                "enabled": True,
                "rationale": "One exact sealed participant-bootstrap refit.",
                "axes": [],
                "members": [],
                "bootstrap": {
                    "source_analysis_spec_ids": [operation["source_analysis_spec_id"]],
                    "source_variant_id": operation["source_variant_id"],
                    "derived_source_variant_id": operation["derived_source_variant_id"],
                    "sampling_method_id": operation["sampling_method_id"],
                    "sampling_design": operation["sampling_design"],
                    "strata_group_spec_ids": copy.deepcopy(
                        operation["strata_group_spec_ids"]
                    ),
                    "refit_preprocessing": operation["refit_preprocessing"],
                    "fixed_evaluation_cohort_policy": operation[
                        "fixed_evaluation_cohort_policy"
                    ],
                },
                "subsample": None,
                "influence": None,
                "null_families": [],
            }
        )
    if derived_specs_by_kind["influence"]:
        operation = cast(
            Mapping[str, Any],
            derived_specs_by_kind["influence"][0]["operation_intent"],
        )
        if operation["removal_slot_ordinal"] != 0:
            raise _invalid("SYNTHETIC.AUDIT_INPUT_ANALYSIS_SPEC_CATALOG_MISMATCH")
        experiment_sets.append(
            {
                "experiment_set_id": "profile-influence",
                "mode": "influence",
                "enabled": True,
                "rationale": "One exact declared participant-removal refit.",
                "axes": [],
                "members": [],
                "bootstrap": None,
                "subsample": None,
                "influence": {
                    "source_analysis_spec_ids": [operation["source_analysis_spec_id"]],
                    "source_variant_id": operation["source_variant_id"],
                    "derived_source_variant_id": operation["derived_source_variant_id"],
                    "removal_method_id": operation["removal_method_id"],
                    "removal_kind": operation["removal_kind"],
                    "named_group_spec_ids": [],
                    "removal_selection": {
                        "selection_rule_id": (
                            "first-private-canonical-membership-slots/1"
                        ),
                        "selected_removal_count": 1,
                    },
                    "refit_preprocessing": operation["refit_preprocessing"],
                    "fixed_non_removed_cohort_policy": operation[
                        "fixed_non_removed_cohort_policy"
                    ],
                },
                "null_families": [],
            }
        )
    if derived_specs_by_kind["null"]:
        operation = cast(
            Mapping[str, Any],
            derived_specs_by_kind["null"][0]["operation_intent"],
        )
        experiment_sets.append(
            {
                "experiment_set_id": "profile-null",
                "mode": "null",
                "enabled": True,
                "rationale": "One exact sealed pure-no-signal refit.",
                "axes": [],
                "members": [],
                "bootstrap": None,
                "subsample": None,
                "influence": None,
                "null_families": [
                    {
                        "null_family_id": operation["null_family_id"],
                        "source_analysis_spec_ids": [operation["source_analysis_spec_id"]],
                        "source_variant_id": operation["source_variant_id"],
                        "derived_source_variant_id": operation[
                            "derived_source_variant_id"
                        ],
                        "null_method_id": operation["null_method_id"],
                        "transformation": operation["transformation"],
                        "within_group_spec_id": operation["within_group_spec_id"],
                        "refit_preprocessing": operation["refit_preprocessing"],
                        "preserves_group_conditional_event_marginals": operation[
                            "preserves_group_conditional_event_marginals"
                        ],
                        "rationale": "Exact sealed null transformation.",
                    }
                ],
            }
        )
    for profile in profiles.values():
        profile["bootstrap_replicates"] = int(bool(derived_specs_by_kind["bootstrap"]))
        profile["influence_max_removals"] = int(bool(derived_specs_by_kind["influence"]))
        profile["null_replicates_per_family"] = int(bool(derived_specs_by_kind["null"]))
    group_spec_id = cast(Mapping[str, Any], baseline["cohort_rule"])["group_spec_id"]
    return {
        "config_schema_version": "ebm-audit-config/0.3",
        "template": {
            "kind": "synthetic",
            "contains_real_rows": False,
            "status": "CONFIRMED_LOCAL_CONFIGURATION",
            "note": "Generated authorized public-synthetic input.",
        },
        "offline": True,
        "input": {
            "path": _PRIVATE_CSV,
            "byte_digest_method": "sha256-exact-file-bytes/1",
            "expected_byte_digest": input_digest,
            "format": {
                "kind": "csv",
                "encoding": "utf-8",
                "delimiter": ",",
                "quote_character": '"',
                "header": True,
                "line_ending": "lf",
                "allow_quoted_newlines": False,
                "trim_whitespace": False,
                "locale": None,
                "infer_types": False,
                "implicit_na_tokens": False,
                "missing_tokens": [""],
                "true_tokens": ["true"],
                "false_tokens": ["false"],
                "columns": [
                    {"source_column": "participant_code", "physical_type": "string"},
                    {"source_column": "analysis_group", "physical_type": "string"},
                    *[
                        {"source_column": row["source_column"], "physical_type": "float64"}
                        for row in event_bindings
                    ],
                    *[
                        {"source_column": row["source_column"], "physical_type": "float64"}
                        for row in covariate_bindings
                    ],
                ],
            },
            "variant": {
                "variant_schema_version": "ebm-audit-data-variant/2.0",
                "variant_id": source_variant_id,
                "label": "Generated authorized public-synthetic input",
                "source_digest": input_digest,
                "source_digest_method": "exact-file/1",
                "provenance_note": "Project-owned offline public synthetic generator.",
                "created_by": "auditor-synthetic-generator",
                "synthetic_truth_digest": truth_digest,
                "is_synthetic": True,
                "externally_completed_or_transformed": False,
            },
        },
        "column_roles": {
            "participant_id_column": "participant_code",
            "events": [
                {
                    "schema_version": "ebm-audit-event/1.0",
                    "event_id": row["event_id"],
                    "display_name": f"Synthetic development event {index + 1:02d}",
                    "source_column": row["source_column"],
                    "category": "synthetic",
                    "unit": None,
                    "abnormal_direction": row["analysis_direction"],
                    "permitted_transformations": ["none"],
                    "missingness_declaration": missingness_policy["policy"],
                    "feature_sensitivity_eligible": True,
                    "identifier_risk_reviewed": True,
                    "public_source_note": "Project-owned synthetic event.",
                    "privacy_sensitive_display_override": None,
                }
                for index, row in enumerate(event_bindings)
            ],
            "groups": [
                {
                    "group_spec_id": group_spec_id,
                    "source": "column",
                    "source_column_or_rule": {
                        "kind": "column",
                        "source_column": "analysis_group",
                    },
                    "label_to_role": [
                        {
                            "label": {
                                "type": "string",
                                "value": row["private_group_label"],
                            },
                            "role": row["role"],
                        }
                        for row in group_bindings
                    ],
                    "required_roles": ["reference", "at_risk"],
                    "rationale": "Exact generated development analysis groups.",
                }
            ],
            "covariates": [
                {
                    "covariate_id": row["covariate_id"],
                    "source_column": row["source_column"],
                    "kind": "continuous",
                    "level_order": None,
                    "missingness": "error",
                }
                for row in covariate_bindings
            ],
            "metadata": [],
            "ignored_columns": [],
        },
        "external_missingness_variant": {
            "status": "NOT_DECLARED",
            "path": None,
            "byte_digest": None,
        },
        "worker": {
            **copy.deepcopy(cast(dict[str, Any], source["worker"])),
            "config_path": _PRIVATE_WORKER,
            "worker_config_digest": worker_config_digest,
        },
        "baseline_reference": {
            "status": "NOT_SUPPLIED",
            "path": None,
            "byte_digest": None,
            "interpretation": "No participant-level or published order reference is supplied.",
        },
        "baseline_analysis": baseline,
        "source_variants": source_variants,
        "experiments": {
            "allow_full_factorial": False,
            "full_factorial_override_rationale": None,
            "sets": experiment_sets,
        },
        "profiles": profiles,
        "randomness": {
            "master_seed": reserved_profile_seed_placeholder,
            "seed_derivation_version": _PROFILE_SEED_DERIVATION_VERSION,
        },
        "output": {
            "root": "unused-output",
            "layout_version": "ebm-audit-run-layout/1",
            "overwrite": False,
            "private_directory_mode": "0700",
        },
    }


def _same_finite_float64(expected: object, observed: object) -> bool:
    if type(expected) not in {int, float} or type(observed) is not float:
        return False
    expected_float = float(cast(int | float, expected))
    return (
        math.isfinite(expected_float)
        and math.isfinite(observed)
        and struct.pack(">d", expected_float) == struct.pack(">d", observed)
    )


def _assert_exact_generated_prepared_semantics(
    prepared: PreparedAuditDataset,
    artifacts: SyntheticCaseArtifacts,
    mapping: Mapping[str, Any],
) -> None:
    state = _private_prepared_dataset(prepared)
    catalog = state.catalog
    table = state.private_table
    data = artifacts.scientific_data
    values = data.get("values")
    masks = data.get("missingness_mask")
    labels = data.get("analysis_group_labels")
    event_ids = data.get("event_ids")
    directions = data.get("event_directions")
    covariate_ids = data.get("covariate_ids")
    covariates = data.get("covariate_values")
    dimensions = data.get("dimensions")
    event_bindings = mapping.get("event_bindings")
    covariate_bindings = mapping.get("covariate_bindings")
    participant_bindings = mapping.get("participant_bindings")
    group_bindings = mapping.get("group_bindings")
    event_specs = catalog.get("event_specs")
    group_specs = catalog.get("group_specs")
    covariate_specs = catalog.get("covariate_specs")
    physical_columns = catalog.get("physical_columns")
    participant_count = mapping.get("participant_count")
    event_count = mapping.get("event_count")
    covariate_count = mapping.get("covariate_count")
    if (
        type(values) is not list
        or type(masks) is not list
        or type(labels) is not list
        or type(event_ids) is not list
        or type(directions) is not list
        or type(covariate_ids) is not list
        or type(covariates) is not list
        or type(dimensions) is not dict
        or type(event_bindings) is not list
        or type(covariate_bindings) is not list
        or type(participant_bindings) is not list
        or group_bindings
        != [
            {
                "synthetic_group_label": synthetic_label,
                "private_group_label": private_label,
                "role": role,
            }
            for synthetic_label, private_label, role in _GROUP_BINDINGS
        ]
        or type(event_specs) is not tuple
        or type(group_specs) is not tuple
        or type(covariate_specs) is not tuple
        or type(physical_columns) is not tuple
        or type(participant_count) is not int
        or type(event_count) is not int
        or type(covariate_count) is not int
        or dimensions.get("participant_count") != participant_count
        or dimensions.get("event_count") != event_count
        or len(values) != participant_count
        or len(masks) != participant_count
        or len(labels) != participant_count
        or len(covariates) != participant_count
        or len(event_ids) != event_count
        or len(directions) != event_count
        or len(covariate_ids) != covariate_count
        or len(participant_bindings) != participant_count
        or len(event_bindings) != event_count
        or len(covariate_bindings) != covariate_count
        or len(event_specs) != event_count
        or len(group_specs) != 1
        or len(covariate_specs) != covariate_count
        or catalog.get("source_table_row_count") != participant_count
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PREPARED_SEMANTICS_MISMATCH")
    participant_column = cast(str, mapping["participant_column"])
    group_column = cast(str, mapping["group_column"])
    expected_private_ids = tuple(
        cast(str, row["participant_private_id"]) for row in participant_bindings
    )
    private_label_by_synthetic = {
        synthetic_label: private_label for synthetic_label, private_label, _role in _GROUP_BINDINGS
    }
    expected_columns = (
        participant_column,
        group_column,
        *(cast(str, row["source_column"]) for row in event_bindings),
        *(cast(str, row["source_column"]) for row in covariate_bindings),
    )
    if (
        tuple(table) != expected_columns
        or tuple(cast(Mapping[str, Any], row).get("source_column") for row in physical_columns)
        != expected_columns
        or tuple(table[participant_column]) != expected_private_ids
        or tuple(table[group_column])
        != tuple(private_label_by_synthetic[label] for label in labels)
        or any(len(column) != participant_count for column in table.values())
        or tuple(
            cast(Mapping[str, Any], row).get("generator_participant_index")
            for row in participant_bindings
        )
        != tuple(range(participant_count))
        or mapping.get("missing_cell_count")
        != sum(1 for row in masks if type(row) is list for missing in row if missing is True)
        or set(labels) != {"reference", "at_risk"}
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PREPARED_SEMANTICS_MISMATCH")
    for event_index, (binding, spec) in enumerate(zip(event_bindings, event_specs, strict=True)):
        if (
            not isinstance(binding, Mapping)
            or not isinstance(spec, Mapping)
            or binding.get("synthetic_event_id") != event_ids[event_index]
            or binding.get("source_truth_direction") != directions[event_index]
            or spec.get("event_id") != binding.get("event_id")
            or spec.get("source_column") != binding.get("source_column")
            or spec.get("abnormal_direction") != binding.get("analysis_direction")
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PREPARED_SEMANTICS_MISMATCH")
        for row_index, observed in enumerate(table[cast(str, binding["source_column"])]):
            expected = cast(list[object], values[row_index])[event_index]
            masked = cast(list[object], masks[row_index])[event_index]
            if type(masked) is not bool:
                raise _invalid("SYNTHETIC.AUDIT_INPUT_PREPARED_SEMANTICS_MISMATCH")
            if masked:
                if expected is not None or type(observed) is not float or not math.isnan(observed):
                    raise _invalid("SYNTHETIC.AUDIT_INPUT_PREPARED_SEMANTICS_MISMATCH")
            elif expected is None or not _same_finite_float64(expected, observed):
                raise _invalid("SYNTHETIC.AUDIT_INPUT_PREPARED_SEMANTICS_MISMATCH")
    for covariate_index, (binding, spec) in enumerate(
        zip(covariate_bindings, covariate_specs, strict=True)
    ):
        if (
            not isinstance(binding, Mapping)
            or not isinstance(spec, Mapping)
            or binding.get("synthetic_covariate_id") != covariate_ids[covariate_index]
            or spec.get("covariate_id") != binding.get("covariate_id")
            or spec.get("source_column") != binding.get("source_column")
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PREPARED_SEMANTICS_MISMATCH")
        for row_index, observed in enumerate(table[cast(str, binding["source_column"])]):
            expected = cast(list[object], covariates[row_index])[covariate_index]
            if not _same_finite_float64(expected, observed):
                raise _invalid("SYNTHETIC.AUDIT_INPUT_PREPARED_SEMANTICS_MISMATCH")
    group_spec = cast(Mapping[str, Any], group_specs[0])
    group_source = group_spec.get("source_column_or_rule")
    label_to_role = group_spec.get("label_to_role")
    observed_roles = (
        tuple(
            (
                cast(Mapping[str, Any], cast(Mapping[str, Any], row)["label"])["value"],
                cast(Mapping[str, Any], row)["role"],
            )
            for row in label_to_role
        )
        if type(label_to_role) is tuple
        else ()
    )
    if (
        not isinstance(group_source, Mapping)
        or group_spec.get("group_spec_id")
        != cast(Mapping[str, Any], _expected_catalog_fields(mapping)["cohort_rule"])[
            "group_spec_id"
        ]
        or group_source.get("source_column") != group_column
        or observed_roles
        != tuple((private_label, role) for _label, private_label, role in _GROUP_BINDINGS)
        or group_spec.get("required_roles") != ("reference", "at_risk")
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PREPARED_SEMANTICS_MISMATCH")


@dataclass(slots=True, repr=False)
class _AuthorizationState:
    origin: Literal["DEVELOPMENT_PROFILE", "PUBLIC_SYNTHETIC_BATCH", "HELDOUT_BENCHMARK"]
    execution_owner: object
    execution_receipt_sha256: str
    execution_identity_sha256: str
    source_config: ResolvedAuditConfig
    source_config_bytes: bytes
    authority_bytes: bytes
    worker_bytes: bytes
    coordinate: CaseCoordinate
    coordinate_bytes: bytes
    coordinate_ordinal: int
    analysis_spec_bytes: tuple[bytes, ...]
    analysis_spec_ids: tuple[str, ...]
    profile_synthetic_event_binding_bytes: bytes | None
    execution_seed_placeholder: str
    participant_namespace: str
    profile_seed_authority_state: str | None
    profile_seed_matrix_requirement: str | None
    heldout_attempt_id: str | None
    benchmark_subject_digest: str | None
    heldout_resolver_capability: object | None
    benchmark_issuer_owner: object | None
    public_batch_case: ResolvedSyntheticCase | None
    authorized_output_path: Path
    case_directory: str
    slot_directory: str
    lock: RLock
    consumed: bool = False


@final
class SealedDevelopmentCaseExecutionAuthorization:
    """Compatibility export for a private one-use profile-case authority."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Development case authorizations are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Development case authorizations cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Development case authorizations are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Development case authorizations cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Development case authorizations cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Development case authorizations cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Development case authorizations cannot be serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Development case authorizations cannot be serialized.")

    def __repr__(self) -> str:
        _authorization_state(self)
        return "SealedDevelopmentCaseExecutionAuthorization(<opaque one-use authority>)"


_AUTHORIZATION_STATES: OneShotWeakRegistry[
    SealedDevelopmentCaseExecutionAuthorization,
    _AuthorizationState,
]
_AUTHORIZATION_STATE_ISSUER: OneShotRegistryIssuer[
    SealedDevelopmentCaseExecutionAuthorization,
    _AuthorizationState,
]
(_AUTHORIZATION_STATES, _AUTHORIZATION_STATE_ISSUER) = create_one_shot_registry()


def _authorization_state(value: object) -> _AuthorizationState:
    if type(value) is not SealedDevelopmentCaseExecutionAuthorization:
        raise TypeError("A genuine development case execution authorization is required.")
    try:
        state = _AUTHORIZATION_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine development case execution authorization is required.") from None
    if type(state) is not _AuthorizationState:
        raise TypeError("Development case execution authorization storage is invalid.")
    _AUTHORIZATION_STATES.require(value, state)
    return state


_BENCHMARK_ISSUER_CLAIMS: WeakSet[type[object]] = WeakSet()
_BENCHMARK_ISSUER_CLAIM_LOCK = RLock()


@dataclass(frozen=True, repr=False)
class _BenchmarkIssuerState:
    owner_type: type[object]
    attempt_material: Callable[
        [object],
        tuple[bytes, str, str, str, Mapping[str, object]],
    ]
    manifest_context: Callable[[object], tuple[bytes, str]]


@final
class _BenchmarkCaseExecutionAuthorizationIssuer:
    """Opaque evaluator-owned issuer for authenticated held-out cases."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> Never:
        raise TypeError("Benchmark authorization issuers are privately claimed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Benchmark authorization issuers are immutable.")

    def __call__(
        self,
        execution_owner: object,
        source_config: ResolvedAuditConfig,
        coordinate: CaseCoordinate,
        variant_index: int,
        resolver_capability: object,
        analysis_spec_bytes: tuple[bytes, ...],
        output_path: Path,
    ) -> SealedDevelopmentCaseExecutionAuthorization:
        return _issue_benchmark_case_execution_authorization(
            self,
            execution_owner,
            source_config,
            coordinate,
            variant_index,
            resolver_capability,
            analysis_spec_bytes,
            output_path,
        )

    def __repr__(self) -> str:
        _benchmark_issuer_state(self)
        return "_BenchmarkCaseExecutionAuthorizationIssuer(<opaque evaluator owner>)"


_BENCHMARK_ISSUER_STATES: OneShotWeakRegistry[
    _BenchmarkCaseExecutionAuthorizationIssuer,
    _BenchmarkIssuerState,
]
_BENCHMARK_ISSUER_STATE_ISSUER: OneShotRegistryIssuer[
    _BenchmarkCaseExecutionAuthorizationIssuer,
    _BenchmarkIssuerState,
]
(_BENCHMARK_ISSUER_STATES, _BENCHMARK_ISSUER_STATE_ISSUER) = create_one_shot_registry()


def _benchmark_issuer_state(value: object) -> _BenchmarkIssuerState:
    if type(value) is not _BenchmarkCaseExecutionAuthorizationIssuer:
        raise TypeError("A genuine benchmark authorization issuer is required.")
    try:
        state = _BENCHMARK_ISSUER_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine benchmark authorization issuer is required.") from None
    if type(state) is not _BenchmarkIssuerState:
        raise TypeError("Benchmark authorization issuer storage is invalid.")
    _BENCHMARK_ISSUER_STATES.require(value, state)
    return state


def _read_benchmark_authorization_context(
    issuer: object,
    execution_owner: object,
) -> tuple[str, str]:
    state = _benchmark_issuer_state(issuer)
    if type(execution_owner) is not state.owner_type:
        raise TypeError("A genuine evaluator attempt owner is required.")
    attempt_material = state.attempt_material(execution_owner)
    manifest_context = state.manifest_context(execution_owner)
    if (
        type(attempt_material) is not tuple
        or len(attempt_material) != 5
        or type(attempt_material[0]) is not bytes
        or type(manifest_context) is not tuple
        or len(manifest_context) != 2
        or type(manifest_context[0]) is not bytes
        or attempt_material[0] != manifest_context[0]
    ):
        raise TypeError("The authenticated evaluator context is invalid.")
    heldout_attempt_id = _raw_sha256_hex(
        attempt_material[1],
        label="held-out attempt identity",
    )
    benchmark_subject_digest = _digest(
        manifest_context[1],
        code="SYNTHETIC.AUDIT_INPUT_BENCHMARK_SUBJECT_INVALID",
    )
    return heldout_attempt_id, benchmark_subject_digest


def _issue_benchmark_case_execution_authorization(
    issuer: _BenchmarkCaseExecutionAuthorizationIssuer,
    execution_owner: object,
    source_config: ResolvedAuditConfig,
    coordinate: CaseCoordinate,
    variant_index: int,
    resolver_capability: object,
    analysis_spec_bytes: tuple[bytes, ...],
    output_path: Path,
) -> SealedDevelopmentCaseExecutionAuthorization:
    """Bind one already-authenticated evaluator case to the ordinary input path."""

    if type(source_config) is not ResolvedAuditConfig:
        raise TypeError("A genuine resolved audit config is required.")
    coordinate_record = _heldout_coordinate_record(coordinate)
    if type(variant_index) is not int or variant_index < 0:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_VARIANT_INVALID")
    if not isinstance(output_path, Path) or not output_path.is_absolute():
        raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_OUTPUT_INVALID")
    if type(analysis_spec_bytes) is not tuple or not analysis_spec_bytes:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_ANALYSIS_SPEC_INVALID")
    try:
        heldout_attempt_id, benchmark_subject_digest = _read_benchmark_authorization_context(
            issuer, execution_owner
        )
    except (InvalidInputError, TypeError, ValueError):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_OWNER_INVALID") from None
    config_bytes, authority_bytes, worker_bytes = _read_exact_source_inputs(source_config)
    worker_config = WorkerConfig.from_yaml_bytes(worker_bytes)
    spec_ids: list[str] = []
    retained_spec_bytes: list[bytes] = []
    for exact_bytes in analysis_spec_bytes:
        try:
            retained_bytes, spec = _closed_mapping_bytes(
                exact_bytes,
                code="SYNTHETIC.AUDIT_INPUT_HELDOUT_ANALYSIS_SPEC_INVALID",
            )
            validate_instance(spec, "analysis-universe.schema.json", definition="AnalysisSpec")
            spec_id = analysis_spec_content_id(spec)
            _derived_profile_worker_config_bytes(worker_config, spec)
        except (InvalidInputError, SchemaValidationError, TypeError, ValueError):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_ANALYSIS_SPEC_INVALID") from None
        retained_spec_bytes.append(retained_bytes)
        spec_ids.append(spec_id)
    if len(set(spec_ids)) != len(spec_ids):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_ANALYSIS_SPEC_INVALID")
    coordinate_bytes = canonical_json_bytes(coordinate_record)
    execution_identity_sha256 = structured_sha256_hex(
        _BENCHMARK_EXECUTION_IDENTITY_DOMAIN,
        {
            "heldout_attempt_id": heldout_attempt_id,
            "benchmark_subject_digest": benchmark_subject_digest,
            "source_config_digest": source_config.public_digest,
            "coordinate": coordinate_record,
            "variant_index": variant_index,
            "ordered_analysis_spec_ids": spec_ids,
            "authorized_output_path": output_path.as_posix(),
        },
    )
    execution_preimage = {
        "heldout_attempt_id": heldout_attempt_id,
        "benchmark_subject_digest": benchmark_subject_digest,
        "execution_identity_sha256": execution_identity_sha256,
        "source_config_digest": source_config.public_digest,
        "authority_byte_digest": exact_file_sha256(authority_bytes),
        "worker_byte_digest": exact_file_sha256(worker_bytes),
        "coordinate": coordinate_record,
        "variant_index": variant_index,
        "ordered_analysis_spec_ids": spec_ids,
    }
    seed_placeholder = structured_sha256_hex(
        _BENCHMARK_EXECUTION_SEED_DOMAIN,
        execution_preimage,
    )[:16]
    participant_namespace = structured_sha256_hex(
        _BENCHMARK_PARTICIPANT_NAMESPACE_DOMAIN,
        execution_preimage,
    )
    case_digest = structured_sha256(_CASE_DIRECTORY_DOMAIN, execution_preimage)
    slot_digest = structured_sha256(
        _SLOT_DIRECTORY_DOMAIN,
        {
            "case_directory_digest": case_digest,
            "ordered_analysis_spec_ids": spec_ids,
        },
    )
    authorization = object.__new__(SealedDevelopmentCaseExecutionAuthorization)
    _AUTHORIZATION_STATE_ISSUER.bind_once(
        authorization,
        _AuthorizationState(
            origin="HELDOUT_BENCHMARK",
            execution_owner=execution_owner,
            execution_receipt_sha256=heldout_attempt_id,
            execution_identity_sha256=execution_identity_sha256,
            source_config=source_config,
            source_config_bytes=config_bytes,
            authority_bytes=authority_bytes,
            worker_bytes=worker_bytes,
            coordinate=coordinate,
            coordinate_bytes=coordinate_bytes,
            coordinate_ordinal=variant_index,
            analysis_spec_bytes=tuple(retained_spec_bytes),
            analysis_spec_ids=tuple(spec_ids),
            profile_synthetic_event_binding_bytes=None,
            execution_seed_placeholder=seed_placeholder,
            participant_namespace=participant_namespace,
            profile_seed_authority_state=None,
            profile_seed_matrix_requirement=None,
            heldout_attempt_id=heldout_attempt_id,
            benchmark_subject_digest=benchmark_subject_digest,
            heldout_resolver_capability=resolver_capability,
            benchmark_issuer_owner=issuer,
            public_batch_case=None,
            authorized_output_path=output_path,
            case_directory=f"{_PRIVATE_ROOT}/{case_digest[7:]}",
            slot_directory=f"{_PRIVATE_ROOT}/{case_digest[7:]}/{slot_digest[7:]}",
            lock=RLock(),
        ),
    )
    return authorization


def _issue_public_synthetic_batch_case_execution_authorization(
    batch_owner: object,
    source_config: ResolvedAuditConfig,
    family_id: str,
    case_id: str,
    analysis_spec_bytes: tuple[bytes, ...],
    output_path: Path,
) -> SealedDevelopmentCaseExecutionAuthorization:
    """Bind one exact authenticated public-synthetic batch member to admission."""

    from ebm_audit.evaluator.scenario_case_batch import (
        AuthenticatedScenarioCaseBatch,
        _claim_public_synthetic_input_member,
    )

    if type(batch_owner) is not AuthenticatedScenarioCaseBatch:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_OWNER_INVALID")
    if type(source_config) is not ResolvedAuditConfig:
        raise TypeError("A genuine resolved audit config is required.")
    if (
        type(family_id) is not str
        or not family_id
        or type(case_id) is not str
        or not case_id
        or not isinstance(output_path, Path)
        or not output_path.is_absolute()
        or type(analysis_spec_bytes) is not tuple
        or not analysis_spec_bytes
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_REQUEST_INVALID")
    config_bytes, authority_bytes, worker_bytes = _read_exact_source_inputs(source_config)
    worker_config = WorkerConfig.from_yaml_bytes(worker_bytes)
    spec_ids: list[str] = []
    retained_spec_bytes: list[bytes] = []
    for exact_bytes in analysis_spec_bytes:
        try:
            retained_bytes, spec = _closed_mapping_bytes(
                exact_bytes,
                code="SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_ANALYSIS_SPEC_INVALID",
            )
            validate_instance(spec, "analysis-universe.schema.json", definition="AnalysisSpec")
            spec_id = analysis_spec_content_id(spec)
            _derived_profile_worker_config_bytes(worker_config, spec)
        except (InvalidInputError, SchemaValidationError, TypeError, ValueError):
            raise _invalid(
                "SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_ANALYSIS_SPEC_INVALID"
            ) from None
        retained_spec_bytes.append(retained_bytes)
        spec_ids.append(spec_id)
    if len(set(spec_ids)) != len(spec_ids):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_ANALYSIS_SPEC_INVALID")

    scenario_bytes, case, benchmark_subject_digest = _claim_public_synthetic_input_member(
        batch_owner,
        family_id,
        case_id,
    )
    if (
        authority_bytes != scenario_bytes
        or case.coordinate.resolution_mode
        not in {"DEVELOPMENT_VARIANT", "TRANSFORMED_SOURCE"}
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_SOURCE_MISMATCH")
    coordinate_record = _public_batch_coordinate_record(case.coordinate)
    execution_preimage = {
        "benchmark_subject_digest": benchmark_subject_digest,
        "source_config_digest": source_config.public_digest,
        "coordinate": coordinate_record,
        "case_id": case.case_id,
        "variant_index": case.variant_index,
        "ordered_analysis_spec_ids": spec_ids,
        "authorized_output_path": output_path.as_posix(),
    }
    execution_identity_sha256 = structured_sha256_hex(
        _PUBLIC_BATCH_EXECUTION_IDENTITY_DOMAIN,
        execution_preimage,
    )
    seed_placeholder = structured_sha256_hex(
        _PUBLIC_BATCH_EXECUTION_SEED_DOMAIN,
        execution_preimage,
    )[:16]
    participant_namespace = structured_sha256_hex(
        _PUBLIC_BATCH_PARTICIPANT_NAMESPACE_DOMAIN,
        execution_preimage,
    )
    case_digest = structured_sha256(_CASE_DIRECTORY_DOMAIN, execution_preimage)
    slot_digest = structured_sha256(
        _SLOT_DIRECTORY_DOMAIN,
        {
            "case_directory_digest": case_digest,
            "ordered_analysis_spec_ids": spec_ids,
        },
    )
    authorization = object.__new__(SealedDevelopmentCaseExecutionAuthorization)
    _AUTHORIZATION_STATE_ISSUER.bind_once(
        authorization,
        _AuthorizationState(
            origin="PUBLIC_SYNTHETIC_BATCH",
            execution_owner=batch_owner,
            execution_receipt_sha256=benchmark_subject_digest,
            execution_identity_sha256=execution_identity_sha256,
            source_config=source_config,
            source_config_bytes=config_bytes,
            authority_bytes=authority_bytes,
            worker_bytes=worker_bytes,
            coordinate=case.coordinate,
            coordinate_bytes=canonical_json_bytes(coordinate_record),
            coordinate_ordinal=case.variant_index,
            analysis_spec_bytes=tuple(retained_spec_bytes),
            analysis_spec_ids=tuple(spec_ids),
            profile_synthetic_event_binding_bytes=None,
            execution_seed_placeholder=seed_placeholder,
            participant_namespace=participant_namespace,
            profile_seed_authority_state=None,
            profile_seed_matrix_requirement=None,
            heldout_attempt_id=None,
            benchmark_subject_digest=benchmark_subject_digest,
            heldout_resolver_capability=None,
            benchmark_issuer_owner=None,
            public_batch_case=case,
            authorized_output_path=output_path,
            case_directory=f"{_PRIVATE_ROOT}/{case_digest[7:]}",
            slot_directory=f"{_PRIVATE_ROOT}/{case_digest[7:]}/{slot_digest[7:]}",
            lock=RLock(),
        ),
    )
    return authorization


def _claim_benchmark_case_execution_authorization_issuer[T](
    *,
    owner_type: type[T],
    attempt_material: Callable[
        [T],
        tuple[bytes, str, str, str, Mapping[str, object]],
    ],
    manifest_context: Callable[[T], tuple[bytes, str]],
) -> _BenchmarkCaseExecutionAuthorizationIssuer:
    """Give the exact evaluator runner its sole benchmark authorization issuer."""

    claimed_owner_type = cast(type[object], owner_type)
    module_name = owner_type.__module__
    module = sys.modules.get(module_name)
    module_path = getattr(module, "__file__", None)
    expected_path = Path(__file__).resolve().parents[3] / "evaluator" / "run_benchmark.py"
    try:
        authentic = (
            type(module_path) is str
            and Path(module_path).resolve(strict=True) == expected_path
            and Path(attempt_material.__code__.co_filename).resolve(strict=True) == expected_path
            and Path(manifest_context.__code__.co_filename).resolve(strict=True) == expected_path
            and attempt_material.__module__ == module_name
            and manifest_context.__module__ == module_name
            and getattr(module, "_AuthenticatedHeldoutAttempt", None) is owner_type
            and getattr(module, "_heldout_attempt_material", None) is attempt_material
            and getattr(module, "_scenario_source_owner_manifest_context", None) is manifest_context
        )
    except (AttributeError, OSError, TypeError):
        authentic = False
    with _BENCHMARK_ISSUER_CLAIM_LOCK:
        if not authentic or claimed_owner_type in _BENCHMARK_ISSUER_CLAIMS:
            raise TypeError("The benchmark authorization issuer is invalid.")
        _BENCHMARK_ISSUER_CLAIMS.add(claimed_owner_type)
    issuer: _BenchmarkCaseExecutionAuthorizationIssuer = object.__new__(
        cast(
            type[_BenchmarkCaseExecutionAuthorizationIssuer],
            _BenchmarkCaseExecutionAuthorizationIssuer,
        )
    )
    _BENCHMARK_ISSUER_STATE_ISSUER.bind_once(
        issuer,
        _BenchmarkIssuerState(
            owner_type=claimed_owner_type,
            attempt_material=cast(
                Callable[
                    [object],
                    tuple[bytes, str, str, str, Mapping[str, object]],
                ],
                attempt_material,
            ),
            manifest_context=cast(
                Callable[[object], tuple[bytes, str]],
                manifest_context,
            ),
        ),
    )
    return issuer


@dataclass(frozen=True, slots=True, repr=False)
class _ValidatedProfilePlanProjection:
    plan_receipt_sha256: str
    profile_execution_identity_sha256: str
    coordinate_bytes: tuple[bytes, ...]
    ordered_analysis_spec_bytes: tuple[bytes, bytes, bytes]
    ordered_analysis_spec_ids: tuple[str, str, str]
    ordered_synthetic_event_binding_bytes: tuple[bytes, ...]


def _raw_sha256_hex(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TypeError(f"The projected profile plan has an invalid {label}.")
    return value


def _validated_profile_plan_projection(
    plan_owner: object,
    worker_config: WorkerConfig,
) -> _ValidatedProfilePlanProjection:
    """Canonicalize and validate one fresh public Plan projection locally."""

    from ebm_audit.evaluator import (
        SealedProfileCharacterizationPlan,
        profile_worker_invocation_semantics_digest,
        project_profile_characterization_plan,
    )

    if type(worker_config) is not WorkerConfig or worker_config.expected_identity is None:
        raise TypeError("The resolved config worker is detached from the projected profile plan.")
    sealed_plan = cast(SealedProfileCharacterizationPlan, plan_owner)
    detached = project_profile_characterization_plan(sealed_plan)
    try:
        projection = strict_json_loads(canonical_json_bytes(detached))
    except (SchemaValidationError, TypeError, ValueError):
        raise TypeError("The projected profile plan is not canonical closed JSON.") from None
    if type(projection) is not dict or set(projection) != {
        "plan_receipt",
        "blocked_diagnostic",
        "execution_contract",
    }:
        raise TypeError("The projected profile plan has an invalid top-level contract.")
    plan = projection.get("plan_receipt")
    diagnostic = projection.get("blocked_diagnostic")
    contract = projection.get("execution_contract")
    if not isinstance(plan, Mapping) or not isinstance(diagnostic, Mapping):
        raise TypeError("The projected profile plan has invalid receipt owners.")
    contract_fields = {
        "timeout_seconds",
        "worker_invocation_semantics_sha256",
        "expected_identity_pin_digest",
        "backend_identity_digest",
        "profile_execution_source_manifest_sha256",
    }
    if not isinstance(contract, Mapping) or set(contract) != contract_fields:
        raise TypeError("The projected profile plan has an invalid execution contract.")
    try:
        timeout_seconds = normalize_worker_timeout_seconds(contract["timeout_seconds"])
        invocation_digest = profile_worker_invocation_semantics_digest(
            worker_config.worker,
            timeout_seconds=timeout_seconds,
        )
        expected_pin_digest = expected_identity_pin_digest(worker_config.expected_identity)
    except (SchemaValidationError, TypeError, ValueError):
        raise TypeError(
            "The resolved config worker is detached from the projected profile plan."
        ) from None
    backend = plan.get("backend_identity")
    execution_identity = plan.get("profile_execution_identity")
    source_manifest = plan.get("execution_source_manifest")
    coordinates = plan.get("ordered_coordinates")
    budgets = plan.get("ordered_budgets")
    bindings = plan.get("ordered_synthetic_event_bindings")
    expected_identity = worker_config.expected_identity
    base_backend = expected_identity.get("base_backend_identity")
    if (
        not isinstance(backend, Mapping)
        or not isinstance(execution_identity, Mapping)
        or not isinstance(source_manifest, Mapping)
        or not isinstance(coordinates, list)
        or not isinstance(budgets, list)
        or len(budgets) != 3
        or not isinstance(bindings, list)
        or len(bindings) != len(coordinates)
        or not isinstance(base_backend, Mapping)
    ):
        raise TypeError("The projected profile plan has incomplete execution authority.")
    selected_backend = copy.deepcopy(dict(base_backend))
    selected_backend["algorithm_id"] = worker_config.algorithm_id
    try:
        projected_backend_digest = backend_identity_digest(backend)
        source_manifest_preimage = copy.deepcopy(dict(source_manifest))
        source_manifest_preimage["profile_execution_source_manifest_sha256"] = None
        recomputed_source_manifest_digest = structured_sha256_hex(
            _PROFILE_EXECUTION_SOURCE_MANIFEST_DOMAIN,
            source_manifest_preimage,
        )
    except (SchemaValidationError, TypeError, ValueError):
        raise TypeError("The projected profile plan has invalid execution identities.") from None
    contract_invocation_digest = _raw_sha256_hex(
        contract.get("worker_invocation_semantics_sha256"),
        label="worker invocation digest",
    )
    contract_source_manifest_digest = _raw_sha256_hex(
        contract.get("profile_execution_source_manifest_sha256"),
        label="execution source-manifest digest",
    )
    plan_receipt_sha256 = _raw_sha256_hex(
        plan.get("profile_characterization_plan_receipt_sha256"),
        label="receipt digest",
    )
    profile_execution_identity_sha256 = _raw_sha256_hex(
        execution_identity.get("profile_execution_identity_sha256"),
        label="execution identity digest",
    )
    expected_backend_digest = _digest(
        contract.get("backend_identity_digest"),
        code="SYNTHETIC.AUDIT_INPUT_PROFILE_BACKEND_DIGEST_INVALID",
    )
    expected_contract_pin_digest = _digest(
        contract.get("expected_identity_pin_digest"),
        code="SYNTHETIC.AUDIT_INPUT_PROFILE_EXPECTED_PIN_DIGEST_INVALID",
    )
    if (
        contract.get("timeout_seconds") != timeout_seconds
        or contract_invocation_digest != invocation_digest
        or contract_invocation_digest
        != execution_identity.get("worker_invocation_semantics_sha256")
        or expected_contract_pin_digest != expected_pin_digest
        or canonical_json_bytes(selected_backend) != canonical_json_bytes(backend)
        or expected_backend_digest != projected_backend_digest
        or expected_backend_digest != expected_identity.get("selected_backend_identity_digest")
        or expected_backend_digest != plan.get("backend_identity_digest")
        or expected_backend_digest != execution_identity.get("backend_identity_digest")
        or contract_source_manifest_digest != recomputed_source_manifest_digest
        or contract_source_manifest_digest
        != source_manifest.get("profile_execution_source_manifest_sha256")
        or contract_source_manifest_digest
        != execution_identity.get("profile_execution_source_manifest_sha256")
        or {
            budget.get("analysis_spec", {}).get("backend", {}).get("algorithm_id")
            for budget in budgets
            if isinstance(budget, Mapping) and isinstance(budget.get("analysis_spec"), Mapping)
        }
        != {worker_config.algorithm_id}
    ):
        raise TypeError("The resolved config worker is detached from the projected profile plan.")
    spec_bytes: list[bytes] = []
    spec_ids: list[str] = []
    for budget in budgets:
        if not isinstance(budget, Mapping) or not isinstance(budget.get("analysis_spec"), Mapping):
            raise TypeError("The projected profile plan has invalid budget authority.")
        analysis_spec = cast(Mapping[str, Any], budget["analysis_spec"])
        spec_id = analysis_spec_content_id(analysis_spec)
        if budget.get("analysis_spec_id") != spec_id:
            raise TypeError("The projected profile plan has detached AnalysisSpec authority.")
        spec_bytes.append(canonical_json_bytes(analysis_spec))
        spec_ids.append(spec_id)
    if any(not isinstance(row, Mapping) for row in coordinates) or any(
        not isinstance(row, Mapping) for row in bindings
    ):
        raise TypeError("The projected profile plan has invalid coordinate authority.")
    return _ValidatedProfilePlanProjection(
        plan_receipt_sha256=plan_receipt_sha256,
        profile_execution_identity_sha256=profile_execution_identity_sha256,
        coordinate_bytes=tuple(canonical_json_bytes(row) for row in coordinates),
        ordered_analysis_spec_bytes=cast(tuple[bytes, bytes, bytes], tuple(spec_bytes)),
        ordered_analysis_spec_ids=cast(tuple[str, str, str], tuple(spec_ids)),
        ordered_synthetic_event_binding_bytes=tuple(canonical_json_bytes(row) for row in bindings),
    )


def _profile_scientific_owner_preimage(
    profile_execution_identity_sha256: str,
    selected_binding_bytes: bytes,
    coordinate_bytes: bytes,
) -> dict[str, Any]:
    _binding_bytes, binding = _closed_mapping_bytes(
        selected_binding_bytes,
        code="SYNTHETIC.AUDIT_INPUT_PROFILE_BINDING_INVALID",
    )
    _coordinate_bytes, coordinate = _closed_mapping_bytes(
        coordinate_bytes,
        code="SYNTHETIC.AUDIT_INPUT_PROFILE_COORDINATE_INVALID",
    )
    binding_digest = binding.get("profile_synthetic_event_binding_sha256")
    if (
        _raw_sha256_hex(
            profile_execution_identity_sha256,
            label="execution identity digest",
        )
        != profile_execution_identity_sha256
        or _raw_sha256_hex(binding_digest, label="synthetic event-binding digest") != binding_digest
        or binding.get("coordinate") != coordinate
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_SEED_AUTHORITY_INVALID")
    return {
        "profile_execution_identity_sha256": profile_execution_identity_sha256,
        "profile_synthetic_event_binding_sha256": binding_digest,
        "coordinate": coordinate,
    }


def _reserved_profile_seed_placeholder(
    profile_execution_identity_sha256: str,
    selected_binding_bytes: bytes,
    coordinate_bytes: bytes,
) -> str:
    """Derive a schema-valid non-authoritative scientific placeholder."""

    return structured_sha256_hex(
        _PROFILE_RESERVED_SEED_DOMAIN,
        _profile_scientific_owner_preimage(
            profile_execution_identity_sha256,
            selected_binding_bytes,
            coordinate_bytes,
        ),
    )[:16]


def _profile_participant_namespace(
    profile_execution_identity_sha256: str,
    selected_binding_bytes: bytes,
    coordinate_bytes: bytes,
) -> str:
    return structured_sha256_hex(
        _PROFILE_PARTICIPANT_NAMESPACE_DOMAIN,
        _profile_scientific_owner_preimage(
            profile_execution_identity_sha256,
            selected_binding_bytes,
            coordinate_bytes,
        ),
    )


def _revalidate_authorization_plan(
    authorization: _AuthorizationState,
    worker_config: WorkerConfig,
) -> None:
    projected = _validated_profile_plan_projection(authorization.execution_owner, worker_config)
    ordinal = authorization.coordinate_ordinal
    if (
        projected.plan_receipt_sha256 != authorization.execution_receipt_sha256
        or projected.profile_execution_identity_sha256 != authorization.execution_identity_sha256
        or not 0 <= ordinal < len(projected.coordinate_bytes)
        or projected.coordinate_bytes[ordinal] != authorization.coordinate_bytes
        or projected.ordered_analysis_spec_bytes != authorization.analysis_spec_bytes
        or projected.ordered_analysis_spec_ids != authorization.analysis_spec_ids
        or projected.ordered_synthetic_event_binding_bytes[ordinal]
        != authorization.profile_synthetic_event_binding_bytes
    ):
        raise TypeError("The generated input is detached from its projected profile plan.")


def _validate_selected_profile_case(
    selected_binding_bytes: bytes,
    authority: ScenarioAuthority,
    case: ResolvedSyntheticCase,
    mapping: Mapping[str, Any],
) -> bool:
    """Validate one complete Plan/3 row against its genuine generated owners."""

    try:
        _binding_bytes, retained = _closed_mapping_bytes(
            selected_binding_bytes,
            code="SYNTHETIC.AUDIT_INPUT_PROFILE_BINDING_INVALID",
        )
        validate_instance(
            retained,
            "evaluator-receipts.schema.json",
            definition="ProfileSyntheticEventBinding",
        )
    except (InvalidInputError, SchemaValidationError):
        return False
    resolved = case.resolved_configuration
    manifest = case.resolved_parameter_manifest
    analysis_configuration = resolved.get("analysis_configuration")
    event_parameters = resolved.get("event_parameters")
    event_ids = resolved.get("event_ids")
    truth_directions = resolved.get("event_directions")
    event_bindings = mapping.get("event_bindings")
    field_resolutions = {
        field_id: [row for row in case.field_resolutions if row.field_id == field_id]
        for field_id in ("event_ids", "event_directions", "event_centers")
    }
    if (
        not isinstance(analysis_configuration, Mapping)
        or not isinstance(event_parameters, Mapping)
        or type(event_ids) is not list
        or type(truth_directions) is not list
        or type(event_bindings) is not list
        or any(not isinstance(row, Mapping) for row in event_bindings)
        or any(len(rows) != 1 for rows in field_resolutions.values())
    ):
        return False
    analysis_directions = analysis_configuration.get("event_spec_directions")
    event_centers = event_parameters.get("event_centers")
    if (
        type(analysis_directions) is not list
        or type(event_centers) is not list
        or not len(event_ids)
        == len(truth_directions)
        == len(analysis_directions)
        == len(event_centers)
        == len(event_bindings)
        or any(
            row.get("synthetic_event_id") != event_id
            or row.get("source_truth_direction") != truth_direction
            or row.get("analysis_direction") != analysis_direction
            for row, event_id, truth_direction, analysis_direction in zip(
                event_bindings,
                event_ids,
                truth_directions,
                analysis_directions,
                strict=True,
            )
        )
    ):
        return False
    resolver_method_ids: dict[str, str] = {}
    for field_id, rows in field_resolutions.items():
        row = rows[0]
        source = row.resolution_source
        derivation_id = source.get("derivation_id") if isinstance(source, Mapping) else None
        if (
            row.source_kind != "EVALUATOR_DERIVATION"
            or not isinstance(source, Mapping)
            or source.get("kind") != "DERIVED"
            or type(derivation_id) is not str
        ):
            return False
        resolver_method_ids[field_id] = derivation_id
    actual_event_centers = [
        {"type": "float64", "value": float(cast(float, center))}
        for center in event_centers
        if type(center) in {int, float}
    ]
    expected_body = {
        "binding_schema_version": "ebm-audit-profile-synthetic-event-binding/1.0",
        "coordinate": {
            "family_id": case.coordinate.family_id,
            "scenario_id": case.coordinate.variant_id,
            "replicate_index": case.coordinate.replicate_index,
        },
        "scenario_definitions_sha256": authority.definitions_sha256,
        "source_contract_sha256": case.source_contract_sha256,
        "resolved_parameter_manifest_sha256": manifest.get("resolved_parameter_manifest_sha256"),
        "resolved_generator_configuration_sha256": resolved.get(
            "resolved_generator_configuration_sha256"
        ),
        "mapping_method_id": "synthetic-e-id-lowercase-machine-id/1",
        "resolver_method_ids": resolver_method_ids,
        "ordered_event_mappings": [
            {
                "event_ordinal": ordinal,
                "synthetic_event_id": event_id,
                "analysis_event_id": row.get("event_id"),
            }
            for ordinal, (event_id, row) in enumerate(zip(event_ids, event_bindings, strict=True))
        ],
        "ordered_truth_directions": truth_directions,
        "ordered_analysis_directions": analysis_directions,
        "ordered_event_centers": actual_event_centers,
        "profile_synthetic_event_binding_sha256": None,
    }
    retained_body = copy.deepcopy(retained)
    retained_digest = retained_body.get("profile_synthetic_event_binding_sha256")
    retained_body["profile_synthetic_event_binding_sha256"] = None
    return (
        len(actual_event_centers) == len(event_centers)
        and canonical_json_bytes(retained_body) == canonical_json_bytes(expected_body)
        and retained_digest
        == structured_sha256_hex(
            _PROFILE_SYNTHETIC_EVENT_BINDING_DOMAIN,
            expected_body,
        )
    )


def _issue_profile_case_execution_authorization(
    plan_owner: object,
    source_config: ResolvedAuditConfig,
    coordinate: CaseCoordinate,
) -> SealedDevelopmentCaseExecutionAuthorization:
    """Authorize one plan-member coordinate with all three sealed budget specs."""

    from ebm_audit.evaluator.profile_characterization import (
        SealedProfileCharacterizationPlan,
    )

    if type(plan_owner) is not SealedProfileCharacterizationPlan:
        raise TypeError("A genuine sealed profile-characterization plan is required.")
    if type(source_config) is not ResolvedAuditConfig:
        raise TypeError("A genuine resolved audit config is required.")
    coordinate_record = _coordinate_record(coordinate)
    plan_coordinate = {
        "family_id": coordinate.family_id,
        "scenario_id": coordinate.variant_id,
        "replicate_index": coordinate.replicate_index,
    }
    config_bytes, authority_bytes, worker_bytes = _read_exact_source_inputs(source_config)
    worker_config = WorkerConfig.from_yaml_bytes(worker_bytes)
    projected = _validated_profile_plan_projection(plan_owner, worker_config)
    plan_coordinate_bytes = canonical_json_bytes(plan_coordinate)
    matches = [
        index
        for index, row in enumerate(projected.coordinate_bytes)
        if row == plan_coordinate_bytes
    ]
    if len(matches) != 1:
        raise TypeError("The requested coordinate is not a sealed profile-plan member.")
    selected_binding_bytes = projected.ordered_synthetic_event_binding_bytes[matches[0]]
    selected_binding = cast(dict[str, Any], strict_json_loads(selected_binding_bytes))
    if hashlib.sha256(authority_bytes).hexdigest() != selected_binding.get(
        "scenario_definitions_sha256"
    ):
        raise TypeError("The resolved config worker is detached from the sealed profile plan.")
    reserved_seed_placeholder = _reserved_profile_seed_placeholder(
        projected.profile_execution_identity_sha256,
        selected_binding_bytes,
        plan_coordinate_bytes,
    )
    participant_namespace = _profile_participant_namespace(
        projected.profile_execution_identity_sha256,
        selected_binding_bytes,
        plan_coordinate_bytes,
    )
    case_digest = structured_sha256(
        _CASE_DIRECTORY_DOMAIN,
        {
            "profile_plan_digest": projected.plan_receipt_sha256,
            "source_config_digest": source_config.public_digest,
            "coordinate": coordinate_record,
        },
    )
    slot_digest = structured_sha256(
        _SLOT_DIRECTORY_DOMAIN,
        {
            "case_directory_digest": case_digest,
            "analysis_spec_ids": list(projected.ordered_analysis_spec_ids),
        },
    )
    authorization = object.__new__(SealedDevelopmentCaseExecutionAuthorization)
    _AUTHORIZATION_STATE_ISSUER.bind_once(
        authorization,
        _AuthorizationState(
            origin="DEVELOPMENT_PROFILE",
            execution_owner=plan_owner,
            execution_receipt_sha256=projected.plan_receipt_sha256,
            execution_identity_sha256=projected.profile_execution_identity_sha256,
            source_config=source_config,
            source_config_bytes=config_bytes,
            authority_bytes=authority_bytes,
            worker_bytes=worker_bytes,
            coordinate=coordinate,
            coordinate_bytes=plan_coordinate_bytes,
            coordinate_ordinal=matches[0],
            analysis_spec_bytes=projected.ordered_analysis_spec_bytes,
            analysis_spec_ids=projected.ordered_analysis_spec_ids,
            profile_synthetic_event_binding_bytes=selected_binding_bytes,
            execution_seed_placeholder=reserved_seed_placeholder,
            participant_namespace=participant_namespace,
            profile_seed_authority_state=_PROFILE_SEED_AUTHORITY_STATE,
            profile_seed_matrix_requirement=_PROFILE_SEED_MATRIX_REQUIREMENT,
            heldout_attempt_id=None,
            benchmark_subject_digest=None,
            heldout_resolver_capability=None,
            benchmark_issuer_owner=None,
            public_batch_case=None,
            authorized_output_path=source_config.private_paths.output_root,
            case_directory=f"{_PRIVATE_ROOT}/{case_digest[7:]}",
            slot_directory=f"{_PRIVATE_ROOT}/{case_digest[7:]}/{slot_digest[7:]}",
            lock=RLock(),
        ),
    )
    return authorization


@dataclass(slots=True, repr=False, weakref_slot=True)
class _InputState:
    authorization: SealedDevelopmentCaseExecutionAuthorization
    source_config: ResolvedAuditConfig
    staging: StagedOutputTransaction
    authority: ScenarioAuthority
    resolved_case: ResolvedSyntheticCase
    generated_artifacts: SyntheticCaseArtifacts
    replay_receipt: _ClosedReplayReceipt
    csv_bytes: bytes
    mapping_bytes: bytes
    verified: VerifiedAuditConfigFiles
    authorized: RunEligibleAuditConfig
    prepared: PreparedAuditDataset
    projection_bytes: bytes
    lock: RLock
    truth_evidence_preparation_owners: set[PreparedExecutionAuthorization]
    truth_candidate_ids: set[str]
    private_inputs_removed: bool
    candidate_provenance_ids: set[str] = field(default_factory=set)


@dataclass(slots=True, repr=False)
class _PublicSyntheticInputReadLease:
    owner: object | None
    state: _InputState | None
    active: bool = True
    lock: RLock = field(default_factory=RLock)


_ACTIVE_PUBLIC_SYNTHETIC_INPUT_READS: ContextVar[
    tuple[_PublicSyntheticInputReadLease, ...]
] = ContextVar("ebm_audit_active_public_synthetic_input_reads", default=())


@dataclass(frozen=True, repr=False)
class _PendingPublicSyntheticCandidateProvenance:
    input_owner: SealedPublicSyntheticAuditInput
    input_state: _InputState
    candidate_id: str
    analysis_spec_id: str
    provenance_binding_sha256: str


@final
class SealedPublicSyntheticAuditInput:
    """Opaque owner of one generated case admitted as an ordinary exact file."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Public synthetic audit inputs are issued from exact authorization.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Public synthetic audit inputs cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Public synthetic audit inputs are immutable.")

    @property
    def authorized_config(self) -> RunEligibleAuditConfig:
        return _resolve_public_synthetic_audit_input(self).authorized

    @property
    def verified_config_files(self) -> VerifiedAuditConfigFiles:
        return _resolve_public_synthetic_audit_input(self).verified

    @property
    def prepared_dataset(self) -> PreparedAuditDataset:
        return _resolve_public_synthetic_audit_input(self).prepared

    def __copy__(self) -> Never:
        raise TypeError("Public synthetic audit inputs cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Public synthetic audit inputs cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Public synthetic audit inputs cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Public synthetic audit inputs cannot be serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Public synthetic audit inputs cannot be serialized.")

    def __repr__(self) -> str:
        projection = project_public_synthetic_audit_input(self)
        return (
            "SealedPublicSyntheticAuditInput("
            f"input_owner_digest={projection['input_owner_digest']!r})"
        )


_INPUT_STATES: OneShotWeakRegistry[SealedPublicSyntheticAuditInput, _InputState]
_INPUT_STATE_ISSUER: OneShotRegistryIssuer[SealedPublicSyntheticAuditInput, _InputState]
(_INPUT_STATES, _INPUT_STATE_ISSUER) = create_one_shot_registry()


def _public_synthetic_preparation_owner_route() -> tuple[
    Callable[[SealedPublicSyntheticAuditInput], None],
    Callable[
        [RunEligibleAuditConfig, PreparedAuditDataset],
        SealedPublicSyntheticAuditInput | None,
    ],
    Callable[[object, PreparedAuditDataset, str], bytes | None],
]:
    @dataclass(frozen=True, slots=True)
    class _RouteEntry:
        pair_key: tuple[int, int]
        owner_key: int
        token: object
        owner_reference: weakref.ReferenceType[SealedPublicSyntheticAuditInput]
        state_reference: weakref.ReferenceType[_InputState]
        prepared_reference: weakref.ReferenceType[PreparedAuditDataset]
        authorized_identity: int
        authority_identity: int
        case_identity: int
        projection_bytes: bytes
        config_digest: str
        case_binding_bytes: bytes
        case_binding_digest: str

    owners_by_pair: dict[tuple[int, int], _RouteEntry] = {}
    owners_by_owner: dict[int, _RouteEntry] = {}
    lock = RLock()

    def remove(entry: _RouteEntry) -> None:
        if owners_by_pair.get(entry.pair_key) is entry:
            owners_by_pair.pop(entry.pair_key, None)
        if owners_by_owner.get(entry.owner_key) is entry:
            owners_by_owner.pop(entry.owner_key, None)

    def live_binding(
        entry: _RouteEntry,
        *,
        owner: object | None = None,
        authorized_config: object | None = None,
        prepared_dataset: object | None = None,
        config_digest: object | None = None,
    ) -> tuple[SealedPublicSyntheticAuditInput, bytes] | None:
        expected_owner = entry.owner_reference()
        expected_state = entry.state_reference()
        expected_prepared = entry.prepared_reference()
        if expected_owner is None or expected_state is None or expected_prepared is None:
            return None
        if (
            (owner is not None and owner is not expected_owner)
            or (
                authorized_config is not None and authorized_config is not expected_state.authorized
            )
            or (prepared_dataset is not None and prepared_dataset is not expected_prepared)
            or (config_digest is not None and config_digest != entry.config_digest)
        ):
            return None
        try:
            _INPUT_STATES.require(expected_owner, expected_state)
        except TypeError:
            return None
        with expected_state.lock:
            case = expected_state.resolved_case
            authority = expected_state.authority
            binding = {
                "case_id": case.case_id,
                "source_contract_sha256": case.source_contract_sha256,
                "scenario_definitions_sha256": case.scenario_definitions_sha256,
            }
            binding_bytes = canonical_json_bytes(binding)
            if (
                id(expected_state.authorized) != entry.authorized_identity
                or expected_state.prepared is not expected_prepared
                or id(authority) != entry.authority_identity
                or id(case) != entry.case_identity
                or expected_state.projection_bytes != entry.projection_bytes
                or expected_state.authorized.resolved_public_digest != entry.config_digest
                or binding_bytes != entry.case_binding_bytes
                or structured_sha256_hex(_PREPARATION_BINDING_DOMAIN, binding)
                != entry.case_binding_digest
                or case.scenario_definitions_sha256 != authority.definitions_sha256
            ):
                return None
        return expected_owner, entry.case_binding_bytes

    def register(owner: SealedPublicSyntheticAuditInput) -> None:
        state = _resolve_public_synthetic_audit_input(owner)
        binding = {
            "case_id": state.resolved_case.case_id,
            "source_contract_sha256": state.resolved_case.source_contract_sha256,
            "scenario_definitions_sha256": state.resolved_case.scenario_definitions_sha256,
        }
        if binding["scenario_definitions_sha256"] != state.authority.definitions_sha256:
            raise TypeError("Public-synthetic case authority is invalid.")
        pair_key = (id(state.authorized), id(state.prepared))
        owner_key = id(owner)
        token = object()

        def discard[T](_reference: weakref.ReferenceType[T]) -> None:
            with lock:
                current = owners_by_pair.get(pair_key)
                if current is not None and current.token is token:
                    remove(current)

        entry = _RouteEntry(
            pair_key=pair_key,
            owner_key=owner_key,
            token=token,
            owner_reference=weakref.ref(owner, discard),
            state_reference=weakref.ref(state, discard),
            prepared_reference=weakref.ref(state.prepared, discard),
            authorized_identity=id(state.authorized),
            authority_identity=id(state.authority),
            case_identity=id(state.resolved_case),
            projection_bytes=state.projection_bytes,
            config_digest=state.authorized.resolved_public_digest,
            case_binding_bytes=canonical_json_bytes(binding),
            case_binding_digest=structured_sha256_hex(_PREPARATION_BINDING_DOMAIN, binding),
        )
        with lock:
            current_pair = owners_by_pair.get(pair_key)
            if current_pair is not None:
                current_binding = live_binding(current_pair)
                if (
                    current_binding is not None
                    and current_binding[0] is owner
                    and current_pair.state_reference() is state
                ):
                    return
                raise TypeError("Public-synthetic preparation pair is already bound.")
            current_owner = owners_by_owner.get(owner_key)
            if current_owner is not None:
                raise TypeError("Public-synthetic preparation owner is already bound.")
            owners_by_pair[pair_key] = entry
            owners_by_owner[owner_key] = entry

    def resolve(
        authorized_config: RunEligibleAuditConfig,
        prepared_dataset: PreparedAuditDataset,
    ) -> SealedPublicSyntheticAuditInput | None:
        with lock:
            entry = owners_by_pair.get((id(authorized_config), id(prepared_dataset)))
            if entry is None:
                return None
            binding = live_binding(
                entry,
                authorized_config=authorized_config,
                prepared_dataset=prepared_dataset,
            )
            return None if binding is None else binding[0]

    def resolve_binding(
        owner: object,
        prepared_dataset: PreparedAuditDataset,
        config_digest: str,
    ) -> bytes | None:
        with lock:
            entry = owners_by_owner.get(id(owner))
            if entry is None:
                return None
            binding = live_binding(
                entry,
                owner=owner,
                prepared_dataset=prepared_dataset,
                config_digest=config_digest,
            )
            return None if binding is None else binding[1]

    return register, resolve, resolve_binding


(
    _register_public_synthetic_preparation_owner,
    _resolve_public_synthetic_preparation_owner,
    _resolve_public_synthetic_preparation_binding,
) = _public_synthetic_preparation_owner_route()


def _input_projection(
    authorization: _AuthorizationState,
    case: ResolvedSyntheticCase,
    artifacts: SyntheticCaseArtifacts,
    replay: _ClosedReplayReceipt,
    csv_bytes: bytes,
    mapping: Mapping[str, Any],
    prepared: PreparedAuditDataset,
) -> dict[str, Any]:
    if authorization.origin == "DEVELOPMENT_PROFILE":
        binding_bytes = authorization.profile_synthetic_event_binding_bytes
        if binding_bytes is None:
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_BINDING_INVALID")
        origin_preimage: dict[str, Any] = {
            "input_owner_schema_version": "ebm-audit-public-synthetic-audit-input/3.0",
            "evidence_scope": "DEVELOPMENT_ONLY_PUBLIC_SYNTHETIC",
            "private_cleanup_state": "DEFERRED_TO_PROFILE_EXECUTOR",
            "profile_execution_identity_sha256": authorization.execution_identity_sha256,
            "profile_synthetic_event_binding_sha256": cast(
                str,
                strict_json_loads(binding_bytes)["profile_synthetic_event_binding_sha256"],
            ),
            "reserved_profile_seed_placeholder": authorization.execution_seed_placeholder,
            "profile_seed_authority_state": authorization.profile_seed_authority_state,
            "profile_seed_matrix_requirement": authorization.profile_seed_matrix_requirement,
            "profile_seed_derivation_version": _PROFILE_SEED_DERIVATION_VERSION,
        }
        coordinate_record = _coordinate_record(case.coordinate)
    elif authorization.origin == "HELDOUT_BENCHMARK":
        if (
            authorization.heldout_attempt_id is None
            or authorization.benchmark_subject_digest is None
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_OWNER_INVALID")
        origin_preimage = {
            "input_owner_schema_version": "ebm-audit-public-synthetic-audit-input/4.0",
            "evidence_scope": "PRIVATE_HELDOUT_SYNTHETIC",
            "private_cleanup_state": "DEFERRED_TO_BENCHMARK_EXECUTOR",
            "benchmark_subject_digest": authorization.benchmark_subject_digest,
            "heldout_attempt_id": authorization.heldout_attempt_id,
            "heldout_execution_identity_sha256": authorization.execution_identity_sha256,
            "heldout_execution_seed_placeholder": authorization.execution_seed_placeholder,
        }
        coordinate_record = _heldout_coordinate_record(case.coordinate)
    else:
        if authorization.benchmark_subject_digest is None:
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_OWNER_INVALID")
        origin_preimage = {
            "input_owner_schema_version": "ebm-audit-public-synthetic-audit-input/5.0",
            "evidence_scope": "PUBLIC_SYNTHETIC_VALIDATION",
            "private_cleanup_state": "DEFERRED_TO_PUBLIC_BATCH_EXECUTOR",
            "benchmark_subject_digest": authorization.benchmark_subject_digest,
            "public_batch_execution_identity_sha256": authorization.execution_identity_sha256,
            "public_batch_execution_seed_placeholder": authorization.execution_seed_placeholder,
        }
        coordinate_record = _public_batch_coordinate_record(case.coordinate)
    preimage: dict[str, Any] = {
        **origin_preimage,
        "mapping_rule_id": _INPUT_MAPPING_RULE_ID,
        "private_cleanup_rule_id": "retained-owner-graph-before-exact-cleanup/2",
        "authority_byte_digest": exact_file_sha256(authorization.authority_bytes),
        "ordered_analysis_spec_ids": list(authorization.analysis_spec_ids),
        "case_identity_digest": structured_sha256(
            "ebm-audit/public-synthetic-case-identity/1",
            {
                "coordinate": coordinate_record,
                "case_id": case.case_id,
            },
        ),
        "resolved_configuration_digest": _public_digest_from_generator_hex(
            case.resolved_configuration["resolved_generator_configuration_sha256"]
        ),
        "generated_data_digest": _public_digest_from_generator_hex(
            artifacts.scientific_data["generated_scientific_data_sha256"]
        ),
        "truth_digest": _public_digest_from_generator_hex(artifacts.truth["truth_object_sha256"]),
        "replay_receipt_digest": replay.receipt_digest,
        "mapping_digest": structured_sha256(_MAPPING_DOMAIN, mapping),
        "serialized_input_byte_digest": exact_file_sha256(csv_bytes),
        "source_admission_digest": prepared.source_admission_id,
        "prepared_dataset_digest": prepared.prepared_dataset_id,
        "participant_count": mapping["participant_count"],
        "event_count": mapping["event_count"],
        "covariate_count": mapping["covariate_count"],
        "missing_cell_count": mapping["missing_cell_count"],
        "generation_stage_count": replay.compared_stage_count,
    }
    projection = {
        **preimage,
        "input_owner_digest": structured_sha256(_INPUT_PROJECTION_DOMAIN, preimage),
    }
    assert_no_direct_identifier_fields(projection)
    return projection


def _claim_case_execution_authorization(
    authorization: SealedDevelopmentCaseExecutionAuthorization,
    *,
    expected_origin: Literal[
        "DEVELOPMENT_PROFILE", "PUBLIC_SYNTHETIC_BATCH", "HELDOUT_BENCHMARK"
    ],
    expected_staging_transaction: StagedOutputTransaction,
) -> _AuthorizationState:
    auth = _authorization_state(authorization)
    if auth.origin != expected_origin:
        raise TypeError("The execution authorization belongs to a different origin.")
    if type(expected_staging_transaction) is not StagedOutputTransaction:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_STAGING_INVALID")
    with auth.lock:
        if auth.consumed:
            raise TypeError("Development case execution authorization is one-use.")
        auth.consumed = True
    if expected_staging_transaction.final_output_path != auth.authorized_output_path:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_STAGING_OUTPUT_MISMATCH")
    return auth


def _open_case_execution_authorization(
    authorization: SealedDevelopmentCaseExecutionAuthorization,
    staging: StagedOutputTransaction,
    *,
    expected_origin: Literal[
        "DEVELOPMENT_PROFILE", "PUBLIC_SYNTHETIC_BATCH", "HELDOUT_BENCHMARK"
    ],
) -> SealedPublicSyntheticAuditInput:
    """Resolve, generate, replay, serialize, verify, authorize, and prepare."""

    auth = _claim_case_execution_authorization(
        authorization,
        expected_origin=expected_origin,
        expected_staging_transaction=staging,
    )
    source_inputs = _read_exact_source_inputs(auth.source_config)
    if source_inputs != (
        auth.source_config_bytes,
        auth.authority_bytes,
        auth.worker_bytes,
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_AUTHORIZED_SOURCE_CHANGED")
    source_worker_config = WorkerConfig.from_yaml_bytes(source_inputs[2])
    if expected_origin == "DEVELOPMENT_PROFILE":
        try:
            _revalidate_authorization_plan(
                auth,
                source_worker_config,
            )
        except (InvalidInputError, SchemaValidationError, TypeError, ValueError):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_PLAN_DRIFT") from None
    elif expected_origin == "HELDOUT_BENCHMARK":
        if (
            auth.benchmark_issuer_owner is None
            or auth.heldout_attempt_id is None
            or auth.benchmark_subject_digest is None
            or _read_benchmark_authorization_context(
                auth.benchmark_issuer_owner,
                auth.execution_owner,
            )
            != (auth.heldout_attempt_id, auth.benchmark_subject_digest)
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_OWNER_DRIFT")
    else:
        from ebm_audit.evaluator.scenario_case_batch import (
            AuthenticatedScenarioCaseBatch,
            _validate_public_synthetic_input_member,
        )

        if (
            auth.public_batch_case is None
            or auth.benchmark_subject_digest is None
            or _validate_public_synthetic_input_member(
                cast(AuthenticatedScenarioCaseBatch, auth.execution_owner),
                auth.public_batch_case,
            )
            != (auth.coordinate.family_id, auth.benchmark_subject_digest)
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_OWNER_DRIFT")
    authority = load_scenario_authority(auth.authority_bytes)
    source_owner: AuthenticatedSourceOwner | None = None
    if expected_origin == "DEVELOPMENT_PROFILE":
        case = resolve_development_case(authority, auth.coordinate)
        verify_exact_resolution(authority, case)
        if (
            case.coordinate != auth.coordinate
            or case.shared_draw_seed is not None
            or case.operation_seed is not None
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_RESOLUTION_OUT_OF_SCOPE")
        artifacts = generate_synthetic_case(authority, case)
        replay = _close_replay_receipt(
            replay_synthetic_case(case, artifacts, authority=authority),
            artifacts,
        )
    elif expected_origin == "HELDOUT_BENCHMARK":
        if auth.heldout_resolver_capability is None or auth.heldout_attempt_id is None:
            raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_OWNER_DRIFT")
        heldout_resolution = _resolve_authenticated_heldout_case(
            authority,
            auth.heldout_attempt_id,
            auth.heldout_resolver_capability,
        )
        if isinstance(heldout_resolution, RetainedGeneratorInvalid):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_GENERATOR_INVALID")
        case = heldout_resolution
        if (
            case.coordinate != auth.coordinate
            or case.variant_index != auth.coordinate_ordinal
            or case.scenario_definitions_sha256 != authority.definitions_sha256
            or case.coordinate.resolution_mode != "HELDOUT_RANGE"
            or case.shared_draw_seed is not None
            or case.operation_seed is not None
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_HELDOUT_RESOLUTION_MISMATCH")
        artifacts = _generate_already_authorized_case(case)
        replay = _close_replay_receipt(
            _replay_already_authorized_case(case, artifacts, authority=authority),
            artifacts,
        )
    else:
        if auth.public_batch_case is None:
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_OWNER_DRIFT")
        case = auth.public_batch_case
        if case.coordinate.resolution_mode == "TRANSFORMED_SOURCE":
            from ebm_audit.evaluator.scenario_case_batch import (
                AuthenticatedScenarioCaseBatch,
                _authenticated_source_case_for_transformed_member,
            )

            source_owner = AuthenticatedSourceOwner(
                _authenticated_source_case_for_transformed_member(
                    cast(AuthenticatedScenarioCaseBatch, auth.execution_owner),
                    case,
                )
            )
        try:
            authority.verify_resolved_case(case, source_owner=source_owner)
        except InvalidInputError:
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_RESOLUTION_MISMATCH") from None
        if (
            case.coordinate != auth.coordinate
            or case.variant_index != auth.coordinate_ordinal
            or case.scenario_definitions_sha256 != authority.definitions_sha256
            or case.coordinate.resolution_mode
            not in {"DEVELOPMENT_VARIANT", "TRANSFORMED_SOURCE"}
            or case.shared_draw_seed is not None
            or (
                case.coordinate.resolution_mode == "DEVELOPMENT_VARIANT"
                and case.operation_seed is not None
            )
            or (
                case.coordinate.resolution_mode == "TRANSFORMED_SOURCE"
                and case.operation_seed is None
            )
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PUBLIC_BATCH_RESOLUTION_MISMATCH")
        artifacts = generate_synthetic_case(
            authority,
            case,
            source_owner=source_owner,
        )
        replay = _close_replay_receipt(
            replay_synthetic_case(
                case,
                artifacts,
                authority=authority,
                source_owner=source_owner,
            ),
            artifacts,
        )
    csv_bytes, mapping = _serialize_generated_csv(
        artifacts,
        participant_namespace=auth.participant_namespace,
    )
    analysis_specs = tuple(
        cast(dict[str, Any], strict_json_loads(spec)) for spec in auth.analysis_spec_bytes
    )
    derived_worker_bytes = _derived_profile_worker_config_bytes(
        source_worker_config,
        analysis_specs[0],
    )
    _apply_profile_analysis_catalog(mapping, analysis_specs[0])
    baseline_analysis_spec_id = analysis_spec_content_id(analysis_specs[0])
    _validate_analysis_spec_for_mapping(analysis_specs[0], mapping)
    for analysis_spec in analysis_specs[1:]:
        _validate_analysis_spec_for_mapping(
            analysis_spec,
            mapping,
            baseline_analysis_spec_id=baseline_analysis_spec_id,
        )
    if expected_origin == "DEVELOPMENT_PROFILE":
        binding_bytes = auth.profile_synthetic_event_binding_bytes
        if binding_bytes is None or not _validate_selected_profile_case(
            binding_bytes,
            authority,
            case,
            mapping,
        ):
            raise _invalid("SYNTHETIC.AUDIT_INPUT_PROFILE_BINDING_MISMATCH")
    derived = _derived_config(
        auth.source_config.private_config,
        artifacts,
        csv_bytes,
        mapping,
        analysis_specs[0],
        exact_file_sha256(derived_worker_bytes),
        auth.execution_seed_placeholder,
        tuple(cast(Mapping[str, Mapping[str, Any]], spec) for spec in analysis_specs[1:]),
    )
    if (
        canonical_json_bytes(derived["baseline_analysis"]) != auth.analysis_spec_bytes[0]
        or analysis_spec_content_id(cast(Mapping[str, Any], derived["baseline_analysis"]))
        != auth.analysis_spec_ids[0]
        or "development_scenario_authority" in derived
    ):
        raise _invalid("SYNTHETIC.AUDIT_INPUT_ANALYSIS_SPEC_IDENTITY_CHANGED")
    try:
        validate_instance(derived, "audit-config.schema.json", definition="AuditConfig")
    except SchemaValidationError:
        raise _invalid("SYNTHETIC.AUDIT_INPUT_DERIVED_CONFIG_INVALID") from None
    store = staging.store
    store.ensure_directory(auth.slot_directory)
    store.write_bytes(f"{auth.slot_directory}/{_PRIVATE_CSV}", csv_bytes)
    store.write_bytes(f"{auth.slot_directory}/{_PRIVATE_WORKER}", derived_worker_bytes)
    config_bytes = canonical_json_bytes(derived)
    store.write_bytes(f"{auth.slot_directory}/{_PRIVATE_CONFIG}", config_bytes)
    config_path = store.resolve(f"{auth.slot_directory}/{_PRIVATE_CONFIG}")
    verified: VerifiedAuditConfigFiles | None = None
    try:
        verified = verify_audit_config_files(load_audit_config(config_path))
        run_authorized = authorize_audit_config_run(verified)
        prepared = prepare_audit_dataset(run_authorized)
        _assert_exact_generated_prepared_semantics(prepared, artifacts, mapping)
    except BaseException:
        if verified is not None:
            verified.close()
        raise
    if (
        verified.input_byte_digest != exact_file_sha256(csv_bytes)
        or prepared.source_admission_id != verified.source_admission_id
        or prepared.summary.input_byte_digest != exact_file_sha256(csv_bytes)
        or prepared.summary.participant_count != mapping["participant_count"]
        or prepared.summary.event_count != mapping["event_count"]
        or prepared.summary.covariate_count != mapping["covariate_count"]
        or prepared.summary.dropped_row_count != 0
    ):
        verified.close()
        raise _invalid("SYNTHETIC.AUDIT_INPUT_ORDINARY_ADMISSION_MISMATCH")
    projection = _input_projection(
        auth,
        case,
        artifacts,
        replay,
        csv_bytes,
        mapping,
        prepared,
    )
    owner = object.__new__(SealedPublicSyntheticAuditInput)
    _INPUT_STATE_ISSUER.bind_once(
        owner,
        _InputState(
            authorization=authorization,
            source_config=auth.source_config,
            staging=staging,
            authority=authority,
            resolved_case=case,
            generated_artifacts=artifacts,
            replay_receipt=replay,
            csv_bytes=csv_bytes,
            mapping_bytes=canonical_json_bytes(mapping),
            verified=verified,
            authorized=run_authorized,
            prepared=prepared,
            projection_bytes=canonical_json_bytes(projection),
            lock=RLock(),
            truth_evidence_preparation_owners=set(),
            truth_candidate_ids=set(),
            private_inputs_removed=False,
        ),
    )
    _register_public_synthetic_preparation_owner(owner)
    if expected_origin == "DEVELOPMENT_PROFILE":
        from ebm_audit.profile_input_identity import _register_profile_preparation_route

        _register_profile_preparation_route(owner, run_authorized)
    return owner


def _open_profile_case_execution_authorization(
    authorization: SealedDevelopmentCaseExecutionAuthorization,
    staging: StagedOutputTransaction,
) -> SealedPublicSyntheticAuditInput:
    return _open_case_execution_authorization(
        authorization,
        staging,
        expected_origin="DEVELOPMENT_PROFILE",
    )


def _open_benchmark_case_execution_authorization(
    authorization: SealedDevelopmentCaseExecutionAuthorization,
    staging: StagedOutputTransaction,
) -> SealedPublicSyntheticAuditInput:
    return _open_case_execution_authorization(
        authorization,
        staging,
        expected_origin="HELDOUT_BENCHMARK",
    )


def _open_public_synthetic_batch_case_execution_authorization(
    authorization: SealedDevelopmentCaseExecutionAuthorization,
    staging: StagedOutputTransaction,
) -> SealedPublicSyntheticAuditInput:
    return _open_case_execution_authorization(
        authorization,
        staging,
        expected_origin="PUBLIC_SYNTHETIC_BATCH",
    )


def open_public_synthetic_audit_input(*_args: object, **_kwargs: object) -> Never:
    """Retained only so the legacy lazy export remains import-compatible."""

    raise TypeError("Public synthetic inputs require private sealed profile-case authority.")


def _open_profile_generated_input(
    authorization: SealedDevelopmentCaseExecutionAuthorization,
    staging: StagedOutputTransaction,
) -> object:
    """Generate once, admit normally, then bind the input to its sealed plan."""

    from ebm_audit.profile_input_identity import _issue_profile_generated_input_binding

    owner = _open_profile_case_execution_authorization(authorization, staging)
    auth = _authorization_state(authorization)
    return _issue_profile_generated_input_binding(auth.execution_owner, owner)


def _resolve_public_synthetic_audit_input(value: object) -> _InputState:
    """Return exact retained input state after replay and ordinary-input readback."""

    if type(value) is not SealedPublicSyntheticAuditInput:
        raise TypeError("A genuine public synthetic audit input is required.")
    for lease in reversed(_ACTIVE_PUBLIC_SYNTHETIC_INPUT_READS.get()):
        with lease.lock:
            if not lease.active or lease.owner is not value:
                continue
            state = lease.state
        if type(state) is not _InputState:
            raise _integrity("SYNTHETIC.AUDIT_INPUT_OWNER_DRIFT")
        try:
            _INPUT_STATES.require(value, state)
        except Exception:
            raise _integrity("SYNTHETIC.AUDIT_INPUT_OWNER_DRIFT") from None
        return state
    return _revalidate_public_synthetic_audit_input(value)


def _revalidate_public_synthetic_audit_input(
    value: SealedPublicSyntheticAuditInput,
) -> _InputState:
    """Perform the complete retained-input integrity and replay check."""

    try:
        state = _INPUT_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine public synthetic audit input is required.") from None
    if type(state) is not _InputState:
        raise TypeError("Public synthetic audit input storage is invalid.")
    integrity_code = "SYNTHETIC.AUDIT_INPUT_OWNER_DRIFT"
    try:
        with state.lock:
            auth = _authorization_state(state.authorization)
            source_owner: AuthenticatedSourceOwner | None = None
            source_inputs = _read_exact_source_inputs(state.source_config)
            if auth.origin == "DEVELOPMENT_PROFILE":
                _revalidate_authorization_plan(
                    auth,
                    WorkerConfig.from_yaml_bytes(source_inputs[2]),
                )
            elif auth.origin == "HELDOUT_BENCHMARK":
                if (
                    auth.benchmark_issuer_owner is None
                    or auth.heldout_attempt_id is None
                    or auth.benchmark_subject_digest is None
                    or _read_benchmark_authorization_context(
                        auth.benchmark_issuer_owner,
                        auth.execution_owner,
                    )
                    != (auth.heldout_attempt_id, auth.benchmark_subject_digest)
                ):
                    raise _integrity("SYNTHETIC.AUDIT_INPUT_OWNER_DRIFT")
            else:
                from ebm_audit.evaluator.scenario_case_batch import (
                    AuthenticatedScenarioCaseBatch,
                    _authenticated_source_case_for_transformed_member,
                    _validate_public_synthetic_input_member,
                )

                if (
                    auth.public_batch_case is not state.resolved_case
                    or auth.benchmark_subject_digest is None
                    or _validate_public_synthetic_input_member(
                        cast(AuthenticatedScenarioCaseBatch, auth.execution_owner),
                        state.resolved_case,
                    )
                    != (state.resolved_case.coordinate.family_id, auth.benchmark_subject_digest)
                ):
                    raise _integrity("SYNTHETIC.AUDIT_INPUT_OWNER_DRIFT")
                if state.resolved_case.coordinate.resolution_mode == "TRANSFORMED_SOURCE":
                    source_owner = AuthenticatedSourceOwner(
                        _authenticated_source_case_for_transformed_member(
                            cast(AuthenticatedScenarioCaseBatch, auth.execution_owner),
                            state.resolved_case,
                        )
                    )
            if (
                auth.source_config is not state.source_config
                or not auth.consumed
                or source_inputs
                != (auth.source_config_bytes, auth.authority_bytes, auth.worker_bytes)
            ):
                raise _integrity("SYNTHETIC.AUDIT_INPUT_OWNER_DRIFT")
            integrity_code = "SYNTHETIC.AUDIT_INPUT_ORDINARY_ADMISSION_DRIFT"
            state.verified.assert_unchanged()
            state.authorized.assert_ready()
            integrity_code = "SYNTHETIC.AUDIT_INPUT_OWNER_DRIFT"
            if auth.origin == "DEVELOPMENT_PROFILE":
                verify_exact_resolution(
                    state.authority,
                    state.resolved_case,
                    source_owner=source_owner,
                )
            if auth.origin in {"DEVELOPMENT_PROFILE", "PUBLIC_SYNTHETIC_BATCH"}:
                replay_result = replay_synthetic_case(
                    state.resolved_case,
                    state.generated_artifacts,
                    authority=state.authority,
                    source_owner=source_owner,
                )
            else:
                replay_result = _replay_already_authorized_case(
                    state.resolved_case,
                    state.generated_artifacts,
                    authority=state.authority,
                )
            replay = _close_replay_receipt(replay_result, state.generated_artifacts)
            integrity_code = "SYNTHETIC.AUDIT_INPUT_MAPPING_DRIFT"
            mapping = strict_json_loads(state.mapping_bytes)
            if type(mapping) is not dict:
                raise _integrity(integrity_code)
            if auth.origin == "DEVELOPMENT_PROFILE":
                integrity_code = "SYNTHETIC.AUDIT_INPUT_PROFILE_BINDING_DRIFT"
                binding_bytes = auth.profile_synthetic_event_binding_bytes
                if binding_bytes is None or not _validate_selected_profile_case(
                    binding_bytes,
                    state.authority,
                    state.resolved_case,
                    cast(dict[str, Any], mapping),
                ):
                    raise _integrity(integrity_code)
            integrity_code = "SYNTHETIC.AUDIT_INPUT_OWNER_DRIFT"
            _assert_exact_generated_prepared_semantics(
                state.prepared,
                state.generated_artifacts,
                cast(dict[str, Any], mapping),
            )
            projection = _input_projection(
                auth,
                state.resolved_case,
                state.generated_artifacts,
                replay,
                state.csv_bytes,
                cast(dict[str, Any], mapping),
                state.prepared,
            )
            if (
                replay != state.replay_receipt
                or canonical_json_bytes(projection) != state.projection_bytes
            ):
                raise _integrity(integrity_code)
            _INPUT_STATES.require(value, state)
            return state
    except Exception:
        raise _integrity(integrity_code) from None


@contextmanager
def _public_synthetic_input_read_scope(
    value: SealedPublicSyntheticAuditInput,
) -> Iterator[None]:
    """Reuse one fully authenticated input only inside one transaction scope."""

    active_leases = _ACTIVE_PUBLIC_SYNTHETIC_INPUT_READS.get()
    for lease in reversed(active_leases):
        with lease.lock:
            reuses_active_lease = lease.active and lease.owner is value
        if reuses_active_lease:
            yield
            return
    state = _revalidate_public_synthetic_audit_input(value)
    retained_leases: list[_PublicSyntheticInputReadLease] = []
    for lease in active_leases:
        with lease.lock:
            if lease.active:
                retained_leases.append(lease)
    lease = _PublicSyntheticInputReadLease(owner=value, state=state)
    token = _ACTIVE_PUBLIC_SYNTHETIC_INPUT_READS.set(
        (*retained_leases, lease)
    )
    try:
        yield
    finally:
        with lease.lock:
            lease.active = False
            lease.owner = None
            lease.state = None
        try:
            current = _revalidate_public_synthetic_audit_input(value)
            if current is not state:
                raise _integrity("SYNTHETIC.AUDIT_INPUT_OWNER_DRIFT")
        finally:
            _ACTIVE_PUBLIC_SYNTHETIC_INPUT_READS.reset(token)


def _read_public_synthetic_batch_input_owner(
    value: object,
) -> object:
    """Return the exact private batch owner only for a revalidated public-batch input."""

    state = _resolve_public_synthetic_audit_input(value)
    auth = _authorization_state(state.authorization)
    if auth.origin != "PUBLIC_SYNTHETIC_BATCH" or auth.public_batch_case is not state.resolved_case:
        raise TypeError("A genuine public synthetic batch input is required.")
    return auth.execution_owner


def _read_public_synthetic_ordinary_transaction_owners(
    value: object,
) -> tuple[
    ResolvedAuditConfig,
    StagedOutputTransaction,
    VerifiedAuditConfigFiles,
    RunEligibleAuditConfig,
    PreparedAuditDataset,
]:
    """Return the exact ordinary owners retained by one public-batch input."""

    state = _resolve_public_synthetic_audit_input(value)
    auth = _authorization_state(state.authorization)
    if (
        auth.origin != "PUBLIC_SYNTHETIC_BATCH"
        or auth.public_batch_case is not state.resolved_case
        or state.private_inputs_removed
        or state.staging.closed
    ):
        raise TypeError("A live public synthetic batch input is required.")
    _ = state.staging.store
    return (
        state.source_config,
        state.staging,
        state.verified,
        state.authorized,
        state.prepared,
    )


def _issue_public_synthetic_candidate_provenance(
    input_owner: SealedPublicSyntheticAuditInput,
    *,
    prepared_dataset: PreparedAuditDataset,
    config_digest: str,
    candidate_id: str,
    analysis_spec_id: str,
    operation_intent: Mapping[str, Any],
    operation_seed: str | None,
    dataset_projection: Mapping[str, Any],
    arrays: Mapping[str, Any],
) -> tuple[dict[str, Any], _PendingPublicSyntheticCandidateProvenance]:
    """Construct one pending candidate projection from the exact live owner.

    Construction validates the closed record but does not spend its one-use
    candidate key. The complete preparation transaction commits that key only
    at its final publication boundary.
    """

    from ebm_audit.synthetic.provenance import (
        PROJECT_SYNTHETIC_ARRAY_NAMES,
        PROJECT_SYNTHETIC_GENERATOR_ID,
        PROJECT_SYNTHETIC_GENERATOR_VERSION,
        project_candidate_array_catalog_sha256,
        project_candidate_dataset_sha256,
        project_candidate_derivation_selector,
        project_candidate_operation_intent_sha256,
        project_candidate_provenance_binding_sha256,
        project_synthetic_generator_code_sha256,
        project_synthetic_generator_record_sha256,
    )
    from ebm_audit.workers.arrays import array_catalog_entry

    state = _resolve_public_synthetic_audit_input(input_owner)
    auth = _authorization_state(state.authorization)
    if (
        auth.origin != "PUBLIC_SYNTHETIC_BATCH"
        or auth.public_batch_case is not state.resolved_case
        or prepared_dataset is not state.prepared
        or config_digest != state.authorized.resolved_public_digest
        or state.private_inputs_removed
        or state.staging.closed
        or type(candidate_id) is not str
        or not candidate_id
        or type(analysis_spec_id) is not str
        or not analysis_spec_id
        or type(operation_intent) is not dict
        or type(dataset_projection) is not dict
        or "synthetic_provenance" in dataset_projection
    ):
        raise TypeError("Public-synthetic candidate provenance owners are detached.")
    try:
        validate_instance(
            dict(dataset_projection),
            "worker-protocol.schema.json",
            definition="DatasetDescriptor",
        )
    except SchemaValidationError:
        raise TypeError("Public-synthetic candidate dataset is invalid.") from None
    catalog = dataset_projection.get("array_catalog")
    if (
        not isinstance(catalog, Mapping)
        or set(catalog) != PROJECT_SYNTHETIC_ARRAY_NAMES
        or set(arrays) != PROJECT_SYNTHETIC_ARRAY_NAMES
    ):
        raise TypeError("Public-synthetic candidate array coverage is invalid.")
    rebuilt_catalog = {
        name: array_catalog_entry(
            name,
            arrays[name],
            semantic_version=cast(Mapping[str, Any], catalog[name])["semantic_version"],
        )
        for name in sorted(PROJECT_SYNTHETIC_ARRAY_NAMES)
    }
    if rebuilt_catalog != dict(catalog):
        raise TypeError("Public-synthetic candidate arrays differ from their catalog.")
    case = state.resolved_case
    artifacts = state.generated_artifacts
    truth = artifacts.truth
    scientific_data = artifacts.scientific_data
    truth_identity = truth.get("scenario_identity")
    truth_artifacts = truth.get("artifact_digests")
    root_context = case.component_seed_manifest.get("root_assignment_context")
    if (
        not isinstance(truth_identity, Mapping)
        or not isinstance(truth_artifacts, Mapping)
        or not isinstance(root_context, Mapping)
        or truth_identity.get("case_id") != case.case_id
        or truth_artifacts.get("scenario_definitions_sha256")
        != case.scenario_definitions_sha256
        or truth_artifacts.get("generator_code_sha256")
        != project_synthetic_generator_code_sha256()[7:]
        or scientific_data.get("case_id") != case.case_id
    ):
        raise TypeError("Public-synthetic generator and truth owners are detached.")
    source_case_id = root_context.get("source_case_id")
    if source_case_id is not None and type(source_case_id) is not str:
        raise TypeError("Public-synthetic source coordinate is invalid.")
    try:
        selector = project_candidate_derivation_selector(operation_intent)
    except ValueError:
        raise TypeError("Public-synthetic candidate selector is invalid.") from None
    operation_kind = operation_intent.get("kind")
    try:
        supplied_spec_ordinal = auth.analysis_spec_ids.index(analysis_spec_id)
        supplied_spec = cast(
            Mapping[str, Any],
            strict_json_loads(auth.analysis_spec_bytes[supplied_spec_ordinal]),
        )
        randomness = cast(Mapping[str, Any], state.authorized.private_config["randomness"])
        master_seed = randomness["master_seed"]
        expected_operation_seed = _expected_operation_seed(
            supplied_spec,
            cast(str, master_seed),
        )
    except (KeyError, TypeError, ValueError):
        raise TypeError("Public-synthetic candidate operation seed is invalid.") from None
    if (
        analysis_spec_content_id(supplied_spec) != analysis_spec_id
        or supplied_spec.get("operation_intent") != operation_intent
        or operation_seed != expected_operation_seed
    ):
        raise TypeError("Public-synthetic candidate operation seed is invalid.")
    dataset_event_ids = dataset_projection.get("event_ids")
    if (
        dataset_projection.get("event_count") != len(cast(list[object], dataset_event_ids))
        or dataset_projection.get("participant_count")
        != cast(Mapping[str, Any], catalog["train_values"])["shape"][0]
    ):
        raise TypeError("Public-synthetic candidate dimensions are detached.")
    candidate_key = candidate_id + ":" + analysis_spec_id
    with state.lock:
        if candidate_key in state.candidate_provenance_ids:
            raise TypeError("Public-synthetic candidate provenance is one-use.")
        project_candidate: dict[str, Any] = {
            "schema_version": "ebm-audit-project-synthetic-candidate-provenance/1.0",
            "trust_boundary": (
                "OPAQUE_LIVE_OWNER_ISSUANCE_AND_DETERMINISTIC_WORKER_HASH_VERIFICATION"
            ),
            "generator_code_sha256": project_synthetic_generator_code_sha256(),
            "authority_sha256": exact_file_sha256(auth.authority_bytes),
            "scenario_definitions_sha256": _public_digest_from_generator_hex(
                case.scenario_definitions_sha256
            ),
            "source_contract_sha256": _public_digest_from_generator_hex(
                case.source_contract_sha256
            ),
            "case_id": case.case_id,
            "case_coordinate": _public_batch_coordinate_record(case.coordinate),
            "source_case_id": source_case_id,
            "case_seed": case.case_seed,
            "shared_draw_seed": case.shared_draw_seed,
            "case_operation_seed": case.operation_seed,
            "component_seed_manifest_sha256": _public_digest_from_generator_hex(
                case.component_seed_manifest["component_seed_manifest_sha256"]
            ),
            "case_seed_identity_sha256": structured_sha256(
                "ebm-audit/project-synthetic-case-seed-identity/1",
                {
                    "case_seed": case.case_seed,
                    "shared_draw_seed": case.shared_draw_seed,
                    "case_operation_seed": case.operation_seed,
                    "component_seed_manifest_sha256": _public_digest_from_generator_hex(
                        case.component_seed_manifest["component_seed_manifest_sha256"]
                    ),
                },
            ),
            "base_generated_scientific_data_sha256": _public_digest_from_generator_hex(
                scientific_data["generated_scientific_data_sha256"]
            ),
            "candidate_id": candidate_id,
            "analysis_spec_id": analysis_spec_id,
            "candidate_derivation_kind": operation_kind,
            "candidate_derivation_selector": selector,
            "candidate_operation_seed": operation_seed,
            "candidate_operation_intent": copy.deepcopy(dict(operation_intent)),
            "candidate_operation_intent_sha256": (
                project_candidate_operation_intent_sha256(operation_intent)
            ),
            "candidate_dataset_sha256": project_candidate_dataset_sha256(
                dataset_projection
            ),
            "candidate_array_catalog_sha256": (
                project_candidate_array_catalog_sha256(cast(Mapping[str, Any], catalog))
            ),
            "provenance_binding_sha256": None,
        }
        provenance: dict[str, Any] = {
            "schema_version": "ebm-audit-synthetic-provenance/1.0",
            "classification": "SYNTHETIC-ONLY",
            "generator_id": PROJECT_SYNTHETIC_GENERATOR_ID,
            "generator_version": PROJECT_SYNTHETIC_GENERATOR_VERSION,
            "generator_record_sha256": project_synthetic_generator_record_sha256(),
            "generated_input_sha256": project_candidate[
                "base_generated_scientific_data_sha256"
            ],
            "complete_truth_sha256": _public_digest_from_generator_hex(
                truth["truth_object_sha256"]
            ),
            "complete_truth_record_id": case.case_id,
            "scenario_id": case.coordinate.variant_id,
            "replicate": case.coordinate.replicate_index,
            "seed": case.case_seed,
            "source_kind": "PROJECT_OWNED_DETERMINISTIC_GENERATOR",
            "participant_data_present": False,
            "external_source_present": False,
            "participant_count": dataset_projection["participant_count"],
            "event_count": dataset_projection["event_count"],
            "event_ids": copy.deepcopy(dataset_event_ids),
            "project_candidate": project_candidate,
        }
        project_candidate["provenance_binding_sha256"] = (
            project_candidate_provenance_binding_sha256(provenance)
        )
        try:
            validate_instance(
                provenance,
                "worker-protocol.schema.json",
                definition="SyntheticProvenance",
            )
        except SchemaValidationError:
            raise TypeError("Public-synthetic candidate provenance is invalid.") from None
        assert_no_direct_identifier_fields(provenance)
        pending = _PendingPublicSyntheticCandidateProvenance(
            input_owner=input_owner,
            input_state=state,
            candidate_id=candidate_id,
            analysis_spec_id=analysis_spec_id,
            provenance_binding_sha256=cast(
                str,
                project_candidate["provenance_binding_sha256"],
            ),
        )
        return copy.deepcopy(provenance), pending


def _commit_public_synthetic_candidate_provenances(
    pending_values: tuple[object, ...],
) -> None:
    """Atomically consume one complete transaction's pending candidate keys."""

    if type(pending_values) is not tuple:
        raise TypeError("Pending public-synthetic provenance coverage is invalid.")
    if not pending_values:
        return
    pending: list[_PendingPublicSyntheticCandidateProvenance] = []
    for value in pending_values:
        if type(value) is not _PendingPublicSyntheticCandidateProvenance:
            raise TypeError("Pending public-synthetic provenance is invalid.")
        pending.append(value)
    state = pending[0].input_state
    if any(value.input_state is not state for value in pending):
        raise TypeError("Pending public-synthetic provenance owners are mixed.")
    with state.lock:
        candidate_keys: list[str] = []
        for value in pending:
            current = _resolve_public_synthetic_audit_input(value.input_owner)
            candidate_key = value.candidate_id + ":" + value.analysis_spec_id
            if (
                current is not state
                or type(value.candidate_id) is not str
                or not value.candidate_id
                or type(value.analysis_spec_id) is not str
                or not value.analysis_spec_id
                or type(value.provenance_binding_sha256) is not str
                or not value.provenance_binding_sha256.startswith("sha256:")
            ):
                raise TypeError("Pending public-synthetic provenance changed.")
            candidate_keys.append(candidate_key)
        if len(set(candidate_keys)) != len(candidate_keys) or any(
            key in state.candidate_provenance_ids for key in candidate_keys
        ):
            raise TypeError("Public-synthetic candidate provenance is one-use.")
        state.candidate_provenance_ids.update(candidate_keys)


def _authenticate_public_synthetic_unprepared_result(
    input_owner: SealedPublicSyntheticAuditInput,
    authorization: UnpreparedResultAuthorization,
) -> None:
    """Bind one exact unprepared result to its retained public-synthetic input."""

    state = _resolve_public_synthetic_audit_input(input_owner)
    auth = _authorization_state(state.authorization)
    unprepared = _resolve_unprepared_result_authorization(authorization)
    family_id = state.resolved_case.coordinate.family_id
    expected_missingness = {
        "mcar_missingness": "MCAR",
        "mar_missingness": "MAR",
    }.get(family_id)
    missingness = state.resolved_case.resolved_configuration.get("missingness")
    if (
        auth.origin != "PUBLIC_SYNTHETIC_BATCH"
        or auth.public_batch_case is not state.resolved_case
        or expected_missingness is None
        or type(missingness) is not dict
        or missingness.get("family") != expected_missingness
        or len(auth.analysis_spec_ids) != 1
        or authorization.analysis_spec_id != auth.analysis_spec_ids[0]
        or authorization.preparation_state != "PREPARATION_UNSUPPORTED"
        or authorization.terminal_status != "UNSUPPORTED_CAPABILITY"
        or authorization.preparation_reasons
        != (
            {
                "reason_code": "PREPARATION.COMPLETE_CASE_ROW_LOSS_UNSUPPORTED",
                "rule_id": "preparation.capability/1",
            },
        )
        or unprepared.prepared_dataset is not state.prepared
        or unprepared.prepared_dataset_id != state.prepared.prepared_dataset_id
        or unprepared.config_digest != state.authorized.resolved_public_digest
        or unprepared.source_byte_digest != state.verified.input_byte_digest
        or unprepared.input_digest is None
    ):
        raise TypeError("The public-synthetic unprepared result is detached.")


def _remove_public_synthetic_batch_private_inputs_impl(
    value: object,
    *,
    allow_bound_truth_only: bool,
) -> None:
    """Remove only the exact private source files after truth evidence is sealed."""

    from ebm_audit.artifacts.store import (
        _DIRECTORY_OPEN_FLAGS,
        _validate_private_directory_descriptor,
    )

    state = _resolve_public_synthetic_audit_input(value)
    auth = _authorization_state(state.authorization)
    with state.lock:
        if auth.origin != "PUBLIC_SYNTHETIC_BATCH":
            raise TypeError("A genuine public synthetic batch input is required.")
        bound_truth_only = False
        if allow_bound_truth_only:
            tombstone = _TRUTH_SCORING_BY_INPUT.get(value)
            if tombstone is not None:
                with tombstone.lock:
                    evidence = tombstone.evidence_reference()
                    bound_truth_only = (
                        tombstone.manifest_bound
                        and evidence is not None
                        and _read_synthetic_truth_scoring_input_owner(evidence) is value
                    )
        if not state.truth_evidence_preparation_owners and not bound_truth_only:
            raise TypeError("Synthetic truth evidence must be sealed before private cleanup.")
        if state.private_inputs_removed:
            return
        case_parts = auth.case_directory.split("/")
        slot_parts = auth.slot_directory.split("/")
        if (
            len(case_parts) != 2
            or len(slot_parts) != 3
            or slot_parts[:2] != case_parts
            or case_parts[0] != _PRIVATE_ROOT
        ):
            raise _integrity("SYNTHETIC.AUDIT_INPUT_PRIVATE_CLEANUP")
        state.verified.close()
        root_fd = state.staging.store._open_owned_root()
        private_fd: int | None = None
        case_fd: int | None = None
        slot_fd: int | None = None
        try:
            private_fd = os.open(case_parts[0], _DIRECTORY_OPEN_FLAGS, dir_fd=root_fd)
            _validate_private_directory_descriptor(private_fd)
            case_fd = os.open(case_parts[1], _DIRECTORY_OPEN_FLAGS, dir_fd=private_fd)
            _validate_private_directory_descriptor(case_fd)
            slot_fd = os.open(slot_parts[2], _DIRECTORY_OPEN_FLAGS, dir_fd=case_fd)
            _validate_private_directory_descriptor(slot_fd)
            if (
                frozenset(os.listdir(root_fd)).intersection({_PRIVATE_ROOT}) != {_PRIVATE_ROOT}
                or frozenset(os.listdir(private_fd)) != {case_parts[1]}
                or frozenset(os.listdir(case_fd)) != {slot_parts[2]}
                or frozenset(os.listdir(slot_fd))
                != {_PRIVATE_CONFIG, _PRIVATE_CSV, _PRIVATE_WORKER}
            ):
                raise _integrity("SYNTHETIC.AUDIT_INPUT_PRIVATE_CLEANUP")
            for name in sorted((_PRIVATE_CONFIG, _PRIVATE_CSV, _PRIVATE_WORKER)):
                observed = os.stat(name, dir_fd=slot_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or stat.S_IMODE(observed.st_mode) != 0o600
                    or observed.st_nlink != 1
                    or (hasattr(os, "geteuid") and observed.st_uid != os.geteuid())
                ):
                    raise _integrity("SYNTHETIC.AUDIT_INPUT_PRIVATE_CLEANUP")
                os.unlink(name, dir_fd=slot_fd)
            os.fsync(slot_fd)
            os.rmdir(slot_parts[2], dir_fd=case_fd)
            os.fsync(case_fd)
            os.rmdir(case_parts[1], dir_fd=private_fd)
            os.fsync(private_fd)
            os.rmdir(case_parts[0], dir_fd=root_fd)
            os.fsync(root_fd)
            state.private_inputs_removed = True
        except OSError:
            raise _integrity("SYNTHETIC.AUDIT_INPUT_PRIVATE_CLEANUP") from None
        finally:
            for descriptor in (slot_fd, case_fd, private_fd, root_fd):
                if descriptor is not None:
                    with suppress(OSError):
                        os.close(descriptor)


def _remove_public_synthetic_batch_private_inputs(value: object) -> None:
    """Remove private inputs after full preparation-bound truth is sealed."""

    _remove_public_synthetic_batch_private_inputs_impl(
        value,
        allow_bound_truth_only=False,
    )


def _remove_public_synthetic_manifest_truth_private_inputs(value: object) -> None:
    """Remove private inputs after truth-only source-manifest binding."""

    _remove_public_synthetic_batch_private_inputs_impl(
        value,
        allow_bound_truth_only=True,
    )


def _remove_public_synthetic_unprepared_truth_private_inputs(
    value: SealedPublicSyntheticAuditInput,
    authorization: UnpreparedResultAuthorization,
) -> None:
    """Remove private inputs after exact typed-unprepared truth is manifest-bound."""

    _authenticate_public_synthetic_unprepared_result(value, authorization)
    _remove_public_synthetic_batch_private_inputs_impl(
        value,
        allow_bound_truth_only=True,
    )


def project_public_synthetic_audit_input(value: object) -> dict[str, Any]:
    """Return digest/count/rule metadata after exact private revalidation."""

    state = _resolve_public_synthetic_audit_input(value)
    projection = strict_json_loads(state.projection_bytes)
    if type(projection) is not dict:
        raise TypeError("Public synthetic audit input storage is invalid.")
    return cast(dict[str, Any], projection)


@dataclass(frozen=True, slots=True, repr=False)
class _EvaluationTruthRow:
    evaluation_row_index: int
    evaluation_unit_binding: str
    threshold_stage: int | None


@dataclass(frozen=True, slots=True, repr=False)
class _TruthMaterial:
    assessment_state: str
    reason_code: str | None
    rows: tuple[_EvaluationTruthRow, ...]
    cohort_binding: tuple[tuple[int, str], ...]
    membership_digest: str
    event_map: tuple[tuple[str, str], ...]
    directions: tuple[tuple[str, str], ...]
    strict_prefix_axis: tuple[str, ...]
    analysis_spec_id: str
    candidate_id: str
    projection_bytes: bytes


@dataclass(frozen=True, slots=True, repr=False)
class _TruthState:
    input_owner: SealedPublicSyntheticAuditInput
    preparation_owner: PreparedExecutionAuthorization
    material: _TruthMaterial


@final
class SyntheticEvaluationTruthEvidence:
    """Opaque exact unit-to-threshold-stage truth owned by preparation."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Synthetic evaluation truth evidence is issued from exact owners.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Synthetic evaluation truth evidence cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Synthetic evaluation truth evidence is immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Synthetic evaluation truth evidence cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Synthetic evaluation truth evidence cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Synthetic evaluation truth evidence cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Synthetic evaluation truth evidence cannot be serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Synthetic evaluation truth evidence cannot be serialized.")

    def __repr__(self) -> str:
        projection = project_synthetic_evaluation_truth_evidence(self)
        return (
            "SyntheticEvaluationTruthEvidence("
            f"assessment_state={projection['assessment_state']!r}, "
            f"evidence_digest={projection['evidence_digest']!r})"
        )


_TRUTH_STATES: OneShotWeakRegistry[SyntheticEvaluationTruthEvidence, _TruthState]
_TRUTH_STATE_ISSUER: OneShotRegistryIssuer[SyntheticEvaluationTruthEvidence, _TruthState]
(_TRUTH_STATES, _TRUTH_STATE_ISSUER) = create_one_shot_registry()


@dataclass(frozen=True, slots=True, repr=False)
class _SyntheticTruthScoringFacts:
    family_id: str
    case_id: str
    truth_object_sha256: str
    truth_kind: str
    non_identifiability_reason: str | None
    equivalence_block_sizes: tuple[int, ...]
    strict_order_identifiable: bool
    recoverable_signal: bool


@final
class SyntheticScientificDataEvidence:
    """Opaque authority over one retained generated scientific data object."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> SyntheticScientificDataEvidence:
        raise TypeError("Synthetic scientific data evidence is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Synthetic scientific data evidence cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Synthetic scientific data evidence is immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Synthetic scientific data evidence cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Synthetic scientific data evidence cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Synthetic scientific data evidence cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Synthetic scientific data evidence cannot be serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Synthetic scientific data evidence cannot be serialized.")


@dataclass(frozen=True, slots=True, repr=False)
class _SyntheticMissingnessProjection:
    """Detached missingness facts from one genuine scientific-data owner."""

    case_id: str
    generated_scientific_data_sha256: str
    dimensions: tuple[int, int]
    participant_internal_indexes: tuple[int, ...]
    event_ids: tuple[str, ...]
    analysis_group_labels: tuple[str, ...]
    missingness_mask: tuple[tuple[bool, ...], ...]

    def __copy__(self) -> Never:
        raise TypeError("Synthetic missingness projections cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Synthetic missingness projections cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Synthetic missingness projections cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Synthetic missingness projections cannot be serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Synthetic missingness projections cannot be serialized.")

    def __repr__(self) -> str:
        return (
            "_SyntheticMissingnessProjection("
            f"case_id={self.case_id!r}, "
            f"generated_scientific_data_sha256={self.generated_scientific_data_sha256!r}, "
            f"dimensions={self.dimensions!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _SyntheticScientificDataEvidenceState:
    input_owner_reference: weakref.ReferenceType[SealedPublicSyntheticAuditInput]
    record_bytes: bytes


@dataclass(slots=True, repr=False)
class _SyntheticScientificDataEvidenceTombstone:
    evidence_reference: weakref.ReferenceType[SyntheticScientificDataEvidence]
    manifest_bound: bool = False
    lock: RLock = field(default_factory=RLock)


_SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_STATES: OneShotWeakRegistry[
    SyntheticScientificDataEvidence, _SyntheticScientificDataEvidenceState
]
(
    _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_STATES,
    _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_STATE_ISSUER,
) = create_one_shot_registry()
_SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_BY_INPUT: OneShotWeakRegistry[
    SealedPublicSyntheticAuditInput, _SyntheticScientificDataEvidenceTombstone
]
(
    _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_BY_INPUT,
    _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_BY_INPUT_ISSUER,
) = create_one_shot_registry()


def _synthetic_scientific_data_record_bytes(
    input_owner: SealedPublicSyntheticAuditInput,
) -> bytes:
    input_state = _resolve_public_synthetic_audit_input(input_owner)
    auth = _authorization_state(input_state.authorization)
    if (
        auth.origin != "PUBLIC_SYNTHETIC_BATCH"
        or auth.public_batch_case is not input_state.resolved_case
    ):
        raise TypeError("A genuine public synthetic batch input is required.")
    artifacts = input_state.generated_artifacts
    record = artifacts.scientific_data
    validate_instance(record, "synthetic-scientific-data.schema.json")
    if type(record) is not dict:
        raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_STRUCTURE_DRIFT")
    case_id = record.get("case_id")
    digest = record.get("generated_scientific_data_sha256")
    if (
        artifacts.resolved_case is not input_state.resolved_case
        or type(case_id) is not str
        or case_id != input_state.resolved_case.case_id
        or record.get("digest_state") != "PERSISTED"
        or type(digest) is not str
    ):
        raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_STRUCTURE_DRIFT")
    preimage = copy.deepcopy(record)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage["generated_scientific_data_sha256"] = None
    if digest != structured_sha256_hex("ebm-audit/generated-scientific-data/1", preimage):
        raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_DIGEST_DRIFT")
    return canonical_json_bytes(record)


def _issue_synthetic_scientific_data_evidence(
    input_owner: SealedPublicSyntheticAuditInput,
) -> SyntheticScientificDataEvidence:
    tombstone = _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_BY_INPUT.get(input_owner)
    if tombstone is not None:
        existing = tombstone.evidence_reference()
        if existing is None:
            raise TypeError("Synthetic scientific data evidence was already issued and released.")
        state = _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_STATES.read(existing)
        if state.input_owner_reference() is not input_owner:
            raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_OWNER_DRIFT")
        record_bytes = _synthetic_scientific_data_record_bytes(input_owner)
        if state.record_bytes != record_bytes:
            raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_OWNER_DRIFT")
        return existing
    record_bytes = _synthetic_scientific_data_record_bytes(input_owner)
    evidence = object.__new__(SyntheticScientificDataEvidence)
    _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_STATE_ISSUER.bind_once(
        evidence,
        _SyntheticScientificDataEvidenceState(
            input_owner_reference=weakref.ref(input_owner),
            record_bytes=record_bytes,
        ),
    )
    _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_BY_INPUT_ISSUER.bind_once(
        input_owner,
        _SyntheticScientificDataEvidenceTombstone(
            evidence_reference=weakref.ref(evidence),
        ),
    )
    return evidence


def _read_synthetic_scientific_data_evidence(value: object) -> bytes:
    if type(value) is not SyntheticScientificDataEvidence:
        raise TypeError("A genuine synthetic scientific data capability is required.")
    try:
        state = _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_STATES.read(value)
    except (KeyError, TypeError):
        raise TypeError("A genuine synthetic scientific data capability is required.") from None
    input_owner = state.input_owner_reference()
    if input_owner is None:
        raise TypeError("The synthetic scientific data input owner was released.")
    record_bytes = _synthetic_scientific_data_record_bytes(input_owner)
    if record_bytes != state.record_bytes:
        raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_OWNER_DRIFT")
    _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_STATES.require(value, state)
    return bytes(record_bytes)


def _project_synthetic_scientific_data_missingness(
    value: object,
) -> _SyntheticMissingnessProjection:
    """Detach only the exact missingness facts from genuine retained evidence."""

    record = strict_json_loads(_read_synthetic_scientific_data_evidence(value))
    return _project_generated_scientific_data_missingness_record(record)


def _project_generated_scientific_data_missingness(
    artifacts: SyntheticCaseArtifacts,
    case: ResolvedSyntheticCase,
) -> _SyntheticMissingnessProjection:
    """Detach missingness from one exact generator-owned case artifact."""

    if type(artifacts) is not SyntheticCaseArtifacts or artifacts.resolved_case is not case:
        raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_OWNER_DRIFT")
    record = artifacts.scientific_data
    if (
        type(record) is not dict
        or record.get("case_id") != case.case_id
        or record.get("digest_state") != "PERSISTED"
        or type(record.get("generated_scientific_data_sha256")) is not str
    ):
        raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_STRUCTURE_DRIFT")
    return _project_generated_scientific_data_missingness_record(record)


def _project_generated_scientific_data_missingness_record(
    record: object,
) -> _SyntheticMissingnessProjection:
    if type(record) is not dict:
        raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_STRUCTURE_DRIFT")
    case_id = record.get("case_id")
    digest = record.get("generated_scientific_data_sha256")
    dimensions = record.get("dimensions")
    participant_indexes = record.get("participant_internal_indexes")
    event_ids = record.get("event_ids")
    group_labels = record.get("analysis_group_labels")
    missingness_mask = record.get("missingness_mask")
    if type(dimensions) is not dict:
        raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_STRUCTURE_DRIFT")
    participant_count = dimensions.get("participant_count")
    event_count = dimensions.get("event_count")
    if (
        type(case_id) is not str
        or not case_id
        or type(digest) is not str
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or type(participant_count) is not int
        or participant_count < 1
        or type(event_count) is not int
        or event_count < 1
        or type(participant_indexes) is not list
        or len(participant_indexes) != participant_count
        or any(type(index) is not int or index < 0 for index in participant_indexes)
        or len(set(participant_indexes)) != participant_count
        or type(event_ids) is not list
        or len(event_ids) != event_count
        or any(type(event_id) is not str or not event_id for event_id in event_ids)
        or len(set(event_ids)) != event_count
        or type(group_labels) is not list
        or len(group_labels) != participant_count
        or any(label not in {"reference", "at_risk"} for label in group_labels)
        or type(missingness_mask) is not list
        or len(missingness_mask) != participant_count
    ):
        raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_STRUCTURE_DRIFT")
    mask_rows: list[tuple[bool, ...]] = []
    for row in missingness_mask:
        if (
            type(row) is not list
            or len(row) != event_count
            or any(type(cell) is not bool for cell in row)
        ):
            raise _integrity("SYNTHETIC.SCIENTIFIC_DATA_STRUCTURE_DRIFT")
        mask_rows.append(tuple(cast(list[bool], row)))
    return _SyntheticMissingnessProjection(
        case_id=case_id,
        generated_scientific_data_sha256=digest,
        dimensions=(participant_count, event_count),
        participant_internal_indexes=tuple(cast(list[int], participant_indexes)),
        event_ids=tuple(cast(list[str], event_ids)),
        analysis_group_labels=tuple(cast(list[str], group_labels)),
        missingness_mask=tuple(mask_rows),
    )


def _read_synthetic_scientific_data_input_owner(
    value: object,
) -> SealedPublicSyntheticAuditInput:
    _read_synthetic_scientific_data_evidence(value)
    input_owner = _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_STATES.read(
        value
    ).input_owner_reference()
    if input_owner is None:
        raise TypeError("The synthetic scientific data input owner was released.")
    return input_owner


def _read_synthetic_scientific_data_batch_binding(
    value: object,
) -> tuple[object, ResolvedSyntheticCase]:
    """Return the exact batch and retained case behind genuine data evidence."""

    input_owner = _read_synthetic_scientific_data_input_owner(value)
    state = _resolve_public_synthetic_audit_input(input_owner)
    auth = _authorization_state(state.authorization)
    if (
        auth.origin != "PUBLIC_SYNTHETIC_BATCH"
        or auth.public_batch_case is not state.resolved_case
        or auth.execution_owner is not _read_public_synthetic_batch_input_owner(input_owner)
    ):
        raise TypeError("A genuine public synthetic batch data capability is required.")
    return auth.execution_owner, state.resolved_case


def _bind_synthetic_scientific_data_evidence(value: object) -> bytes:
    record_bytes = _read_synthetic_scientific_data_evidence(value)
    input_owner = _read_synthetic_scientific_data_input_owner(value)
    tombstone = _SYNTHETIC_SCIENTIFIC_DATA_EVIDENCE_BY_INPUT.read(input_owner)
    with tombstone.lock:
        if tombstone.evidence_reference() is not value:
            raise TypeError("Synthetic scientific data issuance ownership changed.")
        if tombstone.manifest_bound:
            raise TypeError("Synthetic scientific data capability is already manifest-bound.")
        tombstone.manifest_bound = True
        return record_bytes


@dataclass(frozen=True, slots=True, repr=False, weakref_slot=True)
class _SyntheticTruthScoringMaterial:
    record_bytes: bytes
    facts: _SyntheticTruthScoringFacts


@final
class SyntheticTruthScoringEvidence:
    """Opaque scoring-only authority derived from one retained generated truth."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> SyntheticTruthScoringEvidence:
        raise TypeError("Synthetic truth scoring evidence is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Synthetic truth scoring evidence cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Synthetic truth scoring evidence is immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Synthetic truth scoring evidence cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Synthetic truth scoring evidence cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Synthetic truth scoring evidence cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Synthetic truth scoring evidence cannot be serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Synthetic truth scoring evidence cannot be serialized.")


@dataclass(frozen=True, slots=True, repr=False)
class _SyntheticTruthScoringState:
    input_owner_reference: weakref.ReferenceType[SealedPublicSyntheticAuditInput]
    material: _SyntheticTruthScoringMaterial


@dataclass(slots=True, repr=False)
class _SyntheticTruthScoringTombstone:
    evidence_reference: weakref.ReferenceType[SyntheticTruthScoringEvidence]
    manifest_bound: bool
    lock: RLock


_TRUTH_SCORING_STATES: OneShotWeakRegistry[
    SyntheticTruthScoringEvidence, _SyntheticTruthScoringState
]
_TRUTH_SCORING_STATES, _TRUTH_SCORING_STATE_ISSUER = create_one_shot_registry()
_TRUTH_SCORING_BY_INPUT: OneShotWeakRegistry[
    SealedPublicSyntheticAuditInput, _SyntheticTruthScoringTombstone
]
_TRUTH_SCORING_BY_INPUT, _TRUTH_SCORING_BY_INPUT_ISSUER = create_one_shot_registry()


def _synthetic_truth_scoring_material(
    input_owner: SealedPublicSyntheticAuditInput,
) -> tuple[bytes, _SyntheticTruthScoringFacts]:
    input_state = _resolve_public_synthetic_audit_input(input_owner)
    artifacts = input_state.generated_artifacts
    record = artifacts.truth
    validate_instance(record, "synthetic-truth.schema.json")
    if type(record) is not dict:
        raise _integrity("SYNTHETIC.TRUTH_SCORING_STRUCTURE_DRIFT")
    scenario = record.get("scenario_identity")
    order = record.get("order_truth")
    dimensions = record.get("dimensions")
    if type(scenario) is not dict or type(order) is not dict or type(dimensions) is not dict:
        raise _integrity("SYNTHETIC.TRUTH_SCORING_STRUCTURE_DRIFT")
    family_id = scenario.get("family_id")
    case_id = scenario.get("case_id")
    truth_kind = order.get("truth_kind")
    reason = order.get("non_identifiability_reason")
    blocks = order.get("partial_order_blocks")
    strict_order = order.get("strict_order")
    event_count = dimensions.get("event_count")
    identifiable = order.get("strict_order_identifiable")
    recoverable = order.get("recoverable_signal")
    digest = record.get("truth_object_sha256")
    if (
        type(family_id) is not str
        or not family_id
        or type(case_id) is not str
        or not case_id
        or artifacts.resolved_case is not input_state.resolved_case
        or family_id != input_state.resolved_case.coordinate.family_id
        or case_id != input_state.resolved_case.case_id
        or type(truth_kind) is not str
        or (reason is not None and type(reason) is not str)
        or type(blocks) is not list
        or any(type(block) is not list or len(block) < 2 for block in blocks)
        or type(strict_order) is not list
        or type(event_count) is not int
        or event_count < 2
        or type(identifiable) is not bool
        or type(recoverable) is not bool
        or type(digest) is not str
    ):
        raise _integrity("SYNTHETIC.TRUTH_SCORING_STRUCTURE_DRIFT")
    flattened_blocks = [event_id for block in blocks for event_id in block]
    valid_semantics = (
        (
            truth_kind == "STRICT_TOTAL_ORDER"
            and identifiable
            and recoverable
            and reason is None
            and not blocks
            and len(strict_order) == event_count
        )
        or (
            truth_kind == "PARTIAL_ORDER"
            and not identifiable
            and recoverable
            and reason in {"EQUIVALENCE_BLOCK", "EXACT_DUPLICATE"}
            and bool(blocks)
            and not strict_order
            and len(flattened_blocks) == len(set(flattened_blocks))
        )
        or (
            truth_kind == "MIXTURE_OF_STRICT_ORDERS"
            and not identifiable
            and recoverable
            and reason in {"MINORITY_ALTERNATE_SEQUENCE", "OPPOSING_SEQUENCES"}
            and not blocks
            and not strict_order
        )
        or (
            truth_kind == "NONE"
            and not identifiable
            and not recoverable
            and reason in {"PURE_NO_SIGNAL", "REFITTED_NULL_TRANSFORMATION"}
            and not blocks
            and not strict_order
        )
    )
    preimage = copy.deepcopy(record)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage["truth_object_sha256"] = None
    if (
        not valid_semantics
        or record.get("digest_state") != "PERSISTED"
        or digest != structured_sha256_hex("ebm-audit/synthetic-truth/1", preimage)
    ):
        raise _integrity("SYNTHETIC.TRUTH_SCORING_SEMANTICS_DRIFT")
    return canonical_json_bytes(record), _SyntheticTruthScoringFacts(
        family_id=family_id,
        case_id=case_id,
        truth_object_sha256=digest,
        truth_kind=truth_kind,
        non_identifiability_reason=reason,
        equivalence_block_sizes=tuple(len(block) for block in blocks),
        strict_order_identifiable=identifiable,
        recoverable_signal=recoverable,
    )


def _issue_synthetic_truth_scoring_evidence(
    input_owner: SealedPublicSyntheticAuditInput,
) -> SyntheticTruthScoringEvidence:
    tombstone = _TRUTH_SCORING_BY_INPUT.get(input_owner)
    if tombstone is not None:
        existing = tombstone.evidence_reference()
        if existing is None:
            raise TypeError("Synthetic truth scoring evidence was already issued and released.")
        record_bytes, facts = _synthetic_truth_scoring_material(input_owner)
        state = _TRUTH_SCORING_STATES.read(existing)
        if state.material.record_bytes != record_bytes or state.material.facts != facts:
            raise _integrity("SYNTHETIC.TRUTH_SCORING_OWNER_DRIFT")
        return existing
    record_bytes, facts = _synthetic_truth_scoring_material(input_owner)
    material = _SyntheticTruthScoringMaterial(record_bytes=record_bytes, facts=facts)
    evidence = object.__new__(SyntheticTruthScoringEvidence)
    _TRUTH_SCORING_STATE_ISSUER.bind_once(
        evidence,
        _SyntheticTruthScoringState(
            input_owner_reference=weakref.ref(input_owner),
            material=material,
        ),
    )
    _TRUTH_SCORING_BY_INPUT_ISSUER.bind_once(
        input_owner,
        _SyntheticTruthScoringTombstone(
            evidence_reference=weakref.ref(evidence),
            manifest_bound=False,
            lock=RLock(),
        ),
    )
    return evidence


def _read_synthetic_truth_scoring_evidence(
    value: object,
) -> _SyntheticTruthScoringFacts:
    if type(value) is not SyntheticTruthScoringEvidence:
        raise TypeError("A genuine synthetic truth scoring capability is required.")
    try:
        state = _TRUTH_SCORING_STATES.read(value)
    except (KeyError, TypeError):
        raise TypeError("A genuine synthetic truth scoring capability is required.") from None
    input_owner = state.input_owner_reference()
    if input_owner is None:
        raise TypeError("The synthetic truth scoring input owner was released.")
    record_bytes, facts = _synthetic_truth_scoring_material(input_owner)
    if record_bytes != state.material.record_bytes or facts != state.material.facts:
        raise _integrity("SYNTHETIC.TRUTH_SCORING_OWNER_DRIFT")
    _TRUTH_SCORING_STATES.require(value, state)
    return facts


def _read_synthetic_truth_scoring_record_bytes(value: object) -> bytes:
    _read_synthetic_truth_scoring_evidence(value)
    return bytes(_TRUTH_SCORING_STATES.read(value).material.record_bytes)


def _read_synthetic_truth_scoring_input_owner(
    value: object,
) -> SealedPublicSyntheticAuditInput:
    _read_synthetic_truth_scoring_evidence(value)
    input_owner = _TRUTH_SCORING_STATES.read(value).input_owner_reference()
    if input_owner is None:
        raise TypeError("The synthetic truth scoring input owner was released.")
    return input_owner


def _bind_synthetic_truth_scoring_evidence(value: object) -> bytes:
    _read_synthetic_truth_scoring_evidence(value)
    state = _TRUTH_SCORING_STATES.read(value)
    input_owner = state.input_owner_reference()
    if input_owner is None:
        raise TypeError("The synthetic truth scoring input owner was released.")
    tombstone = _TRUTH_SCORING_BY_INPUT.read(input_owner)
    with tombstone.lock:
        if tombstone.evidence_reference() is not value:
            raise TypeError("Synthetic truth scoring issuance ownership changed.")
        if tombstone.manifest_bound:
            raise TypeError("Synthetic truth scoring capability is already manifest-bound.")
        tombstone.manifest_bound = True
        return bytes(state.material.record_bytes)


def _classify_threshold_truth(
    order_truth: Mapping[str, Any],
    stage_truth: Mapping[str, Any],
    truth_rows: list[dict[str, Any]],
    *,
    participant_count: int,
    event_count: int,
) -> tuple[str, str | None]:
    """Separate valid semantic incompatibility from corrupted truth state."""

    stage_state = stage_truth.get("state")
    participant_stages = stage_truth.get("participant_stages")
    recoverable = order_truth.get("recoverable_signal")
    if stage_state == _THRESHOLD_STAGE and recoverable is True:
        if (
            type(participant_stages) is not list
            or len(participant_stages) != participant_count
            or any(
                type(stage) is not int or not 0 <= stage <= event_count
                for stage in participant_stages
            )
            or tuple(row.get("threshold_stage") for row in truth_rows) != tuple(participant_stages)
        ):
            raise _integrity("SYNTHETIC.TRUTH_THRESHOLD_STAGE_DRIFT")
        if (
            order_truth.get("truth_kind") == "STRICT_TOTAL_ORDER"
            and order_truth.get("strict_order_identifiable") is True
        ):
            return "ASSESSABLE", None
        return (
            "NOT_ASSESSABLE",
            "SYNTHETIC.TRUTH_STRICT_PREFIX_AXIS_INCOMPATIBLE",
        )
    if (
        stage_state == "NONE"
        and recoverable is False
        and participant_stages == []
        and all(row.get("threshold_stage") is None for row in truth_rows)
    ):
        return "NOT_ASSESSABLE", "SYNTHETIC.TRUTH_THRESHOLD_STAGE_UNAVAILABLE"
    raise _integrity("SYNTHETIC.TRUTH_STAGE_STATE_DRIFT")


def _truth_material(
    input_owner: SealedPublicSyntheticAuditInput,
    preparation_owner: PreparedExecutionAuthorization,
) -> _TruthMaterial:
    input_state = _resolve_public_synthetic_audit_input(input_owner)
    preparation = _resolve_prepared_execution_authorization(preparation_owner)
    auth = _authorization_state(input_state.authorization)
    if (
        preparation.prepared_dataset is not input_state.prepared
        or preparation.prepared_dataset_id != input_state.prepared.prepared_dataset_id
        or preparation.config_digest != input_state.authorized.resolved_public_digest
        or preparation.analysis_spec_bytes not in auth.analysis_spec_bytes
    ):
        raise TypeError("Synthetic truth owners do not share one exact prepared input.")
    record = cast(dict[str, Any], strict_json_loads(preparation.record_bytes))
    universe = cast(dict[str, Any], strict_json_loads(preparation.universe_bytes))
    dataset = cast(dict[str, Any], strict_json_loads(preparation.dataset_projection_bytes))
    analysis_spec_id = record.get("analysis_spec_id")
    candidate_id = record.get("candidate_id")
    if (
        type(analysis_spec_id) is not str
        or type(candidate_id) is not str
        or analysis_spec_id not in auth.analysis_spec_ids
        or preparation.analysis_spec_bytes
        != auth.analysis_spec_bytes[auth.analysis_spec_ids.index(analysis_spec_id)]
        or dataset.get("stage_semantics") != _STAGE_SEMANTICS
    ):
        raise TypeError("Synthetic truth preparation semantics are incompatible.")
    mapping = strict_json_loads(input_state.mapping_bytes)
    if type(mapping) is not dict:
        raise _integrity("SYNTHETIC.TRUTH_MAPPING_DRIFT")
    participant_bindings = mapping.get("participant_bindings")
    event_bindings = mapping.get("event_bindings")
    if (
        type(participant_bindings) is not list
        or type(event_bindings) is not list
        or any(type(row) is not dict for row in (*participant_bindings, *event_bindings))
    ):
        raise _integrity("SYNTHETIC.TRUTH_MAPPING_DRIFT")
    private_id_to_generator_index = {
        row["participant_private_id"]: row["generator_participant_index"]
        for row in participant_bindings
    }
    if len(private_id_to_generator_index) != len(participant_bindings) or set(
        private_id_to_generator_index.values()
    ) != set(range(len(participant_bindings))):
        raise _integrity("SYNTHETIC.TRUTH_MAPPING_DRIFT")
    truth = input_state.generated_artifacts.truth
    scientific = input_state.generated_artifacts.scientific_data
    order_truth = truth.get("order_truth")
    stage_truth = truth.get("stage_truth")
    participant_truth = truth.get("participant_truth")
    event_truth = truth.get("event_truth")
    if (
        type(order_truth) is not dict
        or type(stage_truth) is not dict
        or type(participant_truth) is not dict
        or type(event_truth) is not dict
        or type(participant_truth.get("ordered_participants")) is not list
        or type(scientific.get("analysis_group_labels")) is not list
    ):
        raise _integrity("SYNTHETIC.TRUTH_STRUCTURE_DRIFT")
    truth_rows = cast(list[dict[str, Any]], participant_truth["ordered_participants"])
    participant_count = cast(int, mapping["participant_count"])
    if len(truth_rows) != participant_count or tuple(
        row.get("participant_internal_index") for row in truth_rows
    ) != tuple(range(participant_count)):
        raise _integrity("SYNTHETIC.TRUTH_PARTICIPANT_DRIFT")
    stage_state = stage_truth.get("state")
    assessment_state, reason_code = _classify_threshold_truth(
        order_truth,
        stage_truth,
        truth_rows,
        participant_count=participant_count,
        event_count=cast(int, mapping["event_count"]),
    )
    event_map = tuple(
        (
            cast(str, row["synthetic_event_id"]),
            cast(str, row["event_id"]),
        )
        for row in event_bindings
    )
    directions = tuple(
        (cast(str, row["event_id"]), cast(str, row["source_truth_direction"]))
        for row in event_bindings
    )
    generator_to_mapped = dict(event_map)
    generator_event_ids = scientific.get("event_ids")
    generator_directions = scientific.get("event_directions")
    if (
        type(generator_event_ids) is not list
        or type(generator_directions) is not list
        or tuple(generator_event_ids) != tuple(generator for generator, _mapped in event_map)
        or tuple(generator_directions) != tuple(direction for _mapped, direction in directions)
        or event_truth.get("event_ids") != generator_event_ids
        or event_truth.get("directions") != generator_directions
    ):
        raise _integrity("SYNTHETIC.TRUTH_EVENT_BINDING_DRIFT")
    strict_order = order_truth.get("strict_order")
    if assessment_state == "ASSESSABLE":
        if (
            type(strict_order) is not list
            or len(strict_order) != len(event_map)
            or set(strict_order) != set(generator_to_mapped)
        ):
            raise _integrity("SYNTHETIC.TRUTH_AXIS_DRIFT")
        strict_prefix_axis = tuple(generator_to_mapped[event_id] for event_id in strict_order)
    else:
        strict_prefix_axis = ()
    identity_rows = preparation.canonical_dataset.private.identity_map.rows
    evaluation_membership = preparation.private_replay.evaluation_membership
    evaluation_row_indexes = preparation.arrays["evaluation_row_indexes"]
    if (
        len(identity_rows) != participant_count
        or len(evaluation_membership) != participant_count
        or evaluation_row_indexes.ndim != 1
        or int(evaluation_row_indexes.shape[0]) != participant_count
    ):
        raise _integrity("SYNTHETIC.TRUTH_MEMBERSHIP_DRIFT")
    identity_by_internal_index = {row.participant_internal_index: row for row in identity_rows}
    labels = cast(list[str], scientific["analysis_group_labels"])
    private_rows: list[_EvaluationTruthRow] = []
    cohort_binding: list[tuple[int, str]] = []
    for row_index, membership in zip(
        evaluation_row_indexes.tolist(),
        evaluation_membership,
        strict=True,
    ):
        canonical_row = identity_by_internal_index.get(int(row_index))
        if (
            canonical_row is None
            or membership.internal_row_index != int(row_index)
            or membership.participant_token != canonical_row.participant_private_token
        ):
            raise _integrity("SYNTHETIC.TRUTH_UNIT_BINDING_DRIFT")
        generator_index = private_id_to_generator_index.get(canonical_row.participant_private_id)
        if type(generator_index) is not int:
            raise _integrity("SYNTHETIC.TRUTH_PRIVATE_ID_JOIN_DRIFT")
        expected_role = labels[generator_index]
        if membership.role != expected_role:
            raise _integrity("SYNTHETIC.TRUTH_COHORT_DRIFT")
        threshold = truth_rows[generator_index].get("threshold_stage")
        private_rows.append(
            _EvaluationTruthRow(
                evaluation_row_index=int(row_index),
                evaluation_unit_binding=membership.participant_token,
                threshold_stage=cast(int | None, threshold),
            )
        )
        cohort_binding.append((int(row_index), membership.role))
    membership_digest = cast(str, universe["evaluation_membership_digest"])
    if membership_digest != _private_evaluation_membership_digest(
        cast(str, universe["plan_digest"]),
        evaluation_membership,
    ):
        raise _integrity("SYNTHETIC.TRUTH_MEMBERSHIP_DIGEST_DRIFT")
    rows = tuple(private_rows)
    cohort = tuple(cohort_binding)
    rows_digest = structured_sha256(
        _TRUTH_ROWS_DOMAIN,
        [
            {
                "evaluation_row_index": row.evaluation_row_index,
                "evaluation_unit_binding": row.evaluation_unit_binding,
                "threshold_stage": row.threshold_stage,
            }
            for row in rows
        ],
    )
    cohort_digest = structured_sha256(
        _TRUTH_COHORT_DOMAIN,
        [{"evaluation_row_index": index, "role": role} for index, role in cohort],
    )
    event_map_digest = structured_sha256(
        _TRUTH_EVENT_MAP_DOMAIN,
        [{"generator_event_id": source, "mapped_event_id": target} for source, target in event_map],
    )
    direction_digest = structured_sha256(
        _TRUTH_DIRECTION_DOMAIN,
        [
            {"mapped_event_id": event_id, "direction": direction}
            for event_id, direction in directions
        ],
    )
    axis_digest = structured_sha256(
        _TRUTH_AXIS_DOMAIN,
        {
            "truth_state": _THRESHOLD_STAGE if stage_state == _THRESHOLD_STAGE else "NONE",
            "stage_semantics": _STAGE_SEMANTICS,
            "mapped_strict_prefix_axis": list(strict_prefix_axis),
        },
    )
    preimage: dict[str, Any] = {
        "truth_evidence_schema_version": "ebm-audit-synthetic-evaluation-truth-evidence/1.0",
        "assessment_state": assessment_state,
        "reason_code": reason_code,
        "truth_rule_id": _TRUTH_RULE_ID,
        "truth_state": _THRESHOLD_STAGE if stage_state == _THRESHOLD_STAGE else "NONE",
        "stage_semantics": _STAGE_SEMANTICS,
        "evaluation_row_count": len(rows),
        "threshold_stage_row_count": sum(row.threshold_stage is not None for row in rows),
        "rows_digest": rows_digest,
        "cohort_binding_digest": cohort_digest,
        "evaluation_membership_digest": membership_digest,
        "event_map_digest": event_map_digest,
        "direction_digest": direction_digest,
        "axis_digest": axis_digest,
        "input_owner_digest": project_public_synthetic_audit_input(input_owner)[
            "input_owner_digest"
        ],
        "analysis_spec_id": analysis_spec_id,
        "prepared_dataset_digest": input_state.prepared.prepared_dataset_id,
    }
    projection = {
        **preimage,
        "evidence_digest": structured_sha256(_TRUTH_PROJECTION_DOMAIN, preimage),
    }
    assert_no_direct_identifier_fields(projection)
    return _TruthMaterial(
        assessment_state=assessment_state,
        reason_code=reason_code,
        rows=rows,
        cohort_binding=cohort,
        membership_digest=membership_digest,
        event_map=event_map,
        directions=directions,
        strict_prefix_axis=strict_prefix_axis,
        analysis_spec_id=analysis_spec_id,
        candidate_id=candidate_id,
        projection_bytes=canonical_json_bytes(projection),
    )


def seal_synthetic_evaluation_truth_evidence(
    input_owner: SealedPublicSyntheticAuditInput,
    preparation_owner: PreparedExecutionAuthorization,
) -> SyntheticEvaluationTruthEvidence:
    """Join generator truth only through the exact preparation-owned units."""

    input_state = _resolve_public_synthetic_audit_input(input_owner)
    if type(preparation_owner) is not PreparedExecutionAuthorization:
        raise TypeError("A genuine prepared execution authorization is required.")
    with input_state.lock:
        if preparation_owner in input_state.truth_evidence_preparation_owners:
            raise TypeError(
                "Synthetic evaluation truth evidence is one-use per prepared authorization."
            )
        material = _truth_material(input_owner, preparation_owner)
        if material.candidate_id in input_state.truth_candidate_ids:
            raise TypeError("Synthetic evaluation truth evidence rejects duplicate candidates.")
        if len(input_state.truth_evidence_preparation_owners) >= 3:
            raise TypeError(
                "Synthetic evaluation truth evidence permits three profile candidates per input."
            )
        evidence = object.__new__(SyntheticEvaluationTruthEvidence)
        _TRUTH_STATE_ISSUER.bind_once(
            evidence,
            _TruthState(
                input_owner=input_owner,
                preparation_owner=preparation_owner,
                material=material,
            ),
        )
        input_state.truth_evidence_preparation_owners.add(preparation_owner)
        input_state.truth_candidate_ids.add(material.candidate_id)
        return evidence


def _resolve_synthetic_evaluation_truth_evidence(value: object) -> _TruthState:
    """Return exact private rows for trusted future profile evidence only."""

    if type(value) is not SyntheticEvaluationTruthEvidence:
        raise TypeError("A genuine synthetic evaluation truth evidence owner is required.")
    try:
        state = _TRUTH_STATES[value]
    except (KeyError, TypeError):
        raise TypeError(
            "A genuine synthetic evaluation truth evidence owner is required."
        ) from None
    if type(state) is not _TruthState:
        raise TypeError("Synthetic evaluation truth evidence storage is invalid.")
    rebuilt = _truth_material(state.input_owner, state.preparation_owner)
    if rebuilt != state.material:
        raise _integrity("SYNTHETIC.TRUTH_EVIDENCE_DRIFT")
    _TRUTH_STATES.require(value, state)
    return state


def project_synthetic_evaluation_truth_evidence(value: object) -> dict[str, Any]:
    """Return only digest/count/rule truth metadata."""

    state = _resolve_synthetic_evaluation_truth_evidence(value)
    projection = strict_json_loads(state.material.projection_bytes)
    if type(projection) is not dict:
        raise TypeError("Synthetic evaluation truth evidence storage is invalid.")
    return cast(dict[str, Any], projection)


__all__ = [
    "SealedDevelopmentCaseExecutionAuthorization",
    "SealedPublicSyntheticAuditInput",
    "SyntheticEvaluationTruthEvidence",
    "open_public_synthetic_audit_input",
    "project_public_synthetic_audit_input",
    "project_synthetic_evaluation_truth_evidence",
    "seal_synthetic_evaluation_truth_evidence",
]
