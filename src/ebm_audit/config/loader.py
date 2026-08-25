"""Strict YAML 1.2-subset loading and complete audit-config resolution."""

from __future__ import annotations

import copy
import itertools
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from ebm_audit.protocol import (
    PathBoundaryError,
    canonical_json_bytes,
    structured_sha256,
    validate_relative_posix_path,
)
from ebm_audit.schema import SchemaValidationError, load_protocol_registry, validate_instance
from ebm_audit.universe import (
    AxisCompositionError,
    AxisSemanticsError,
    analysis_spec_content_id,
    compose_analysis_spec,
    load_axis_semantics,
    scientific_backend_registry_digest,
)

from .models import (
    ConfigContractError,
    PrivatePathBindings,
    ResolvedAuditConfig,
    _construct_resolved_audit_config,
)
from .strict_yaml import StrictYamlError, load_strict_yaml_bytes

_ENV_INTERPOLATION = re.compile(r"(?:\$\{|\$\(|\{\{\s*env\b|%[A-Za-z_][A-Za-z0-9_]*%)")
_MAX_AUDIT_CONFIG_BYTES = 2 * 1024 * 1024
_STRICT_YAML_CODES = {
    "DUPLICATE_KEY": "CONFIG.DUPLICATE_KEY",
    "REFERENCE": "CONFIG.YAML_REFERENCE",
    "TAG": "CONFIG.YAML_TAG",
    "DOCUMENT_MARKER": "CONFIG.YAML_DOCUMENT_MARKER",
    "MERGE": "CONFIG.YAML_MERGE",
    "NONFINITE": "CONFIG.SCHEMA",
    "AMBIGUOUS_BOOLEAN": "CONFIG.YAML_AMBIGUOUS_BOOLEAN",
    "AMBIGUOUS_NUMBER_OR_TIMESTAMP": "CONFIG.YAML_TIMESTAMP_OR_NUMBER",
    "NON_STRING_KEY": "CONFIG.NON_STRING_KEY",
    "BYTE_BOUND": "CONFIG.SIZE",
    "BOM": "CONFIG.BOM",
    "STRUCTURAL_BOUND": "CONFIG.STRUCTURAL_BOUND",
    "SYNTAX_OR_CANONICAL_VALUE": "CONFIG.YAML_SYNTAX",
}


def _registered_config_contract() -> Mapping[str, Any]:
    registry = load_protocol_registry()
    return cast(Mapping[str, Any], registry["audit_config_identity_contract"])


_CONFIG_CONTRACT = _registered_config_contract()
_SOURCE_VARIANT_METHODS = {
    cast(str, row["variant_kind"]): frozenset(cast(Sequence[str], row["method_ids"]))
    for row in cast(Sequence[Mapping[str, Any]], _CONFIG_CONTRACT["source_variant_method_registry"])
}
_NULL_METHOD_BY_TRANSFORMATION = {
    "pure-no-signal-synthetic": "pure-no-signal-synthetic/1",
    "label-permutation": "label-permutation/1",
    "featurewise-participant-permutation": ("featurewise-within-group-participant-permutation/1"),
}
_COMPOSITION_CONFIG_CODES = {
    "COMPOSITION.AXIS_REGISTRY": "CONFIG.AXIS_REGISTRY",
    "COMPOSITION.AXIS_PATH_OWNERSHIP": "CONFIG.AXIS_SEMANTICS",
    "COMPOSITION.BASELINE_CHOICE_MISSING": "CONFIG.AXIS_SEMANTICS",
    "COMPOSITION.BASELINE_CHOICE_MISMATCH": "CONFIG.AXIS_BASELINE_CHOICE",
    "COMPOSITION.CHOICE_PATH_COVERAGE": "CONFIG.AXIS_ASSIGNMENT_COVERAGE",
    "COMPOSITION.DECORATIVE_ALTERNATIVE": "CONFIG.AXIS_DECORATIVE_CHOICE",
    "COMPOSITION.DUPLICATE_ASSIGNMENT_PATH": ("CONFIG.DUPLICATE_AXIS_ASSIGNMENT_PATH"),
    "COMPOSITION.DUPLICATE_AXIS_ID": "CONFIG.DUPLICATE_AXIS_ID",
    "COMPOSITION.DUPLICATE_CHOICE_ID": "CONFIG.DUPLICATE_AXIS_CHOICE_ID",
    "COMPOSITION.DUPLICATE_CHOICE_VALUE": "CONFIG.AXIS_DECORATIVE_CHOICE",
    "COMPOSITION.DUPLICATE_MEMBER_AXIS": "CONFIG.DUPLICATE_MEMBER_AXIS",
    "COMPOSITION.DUPLICATE_MEMBER_ID": "CONFIG.DUPLICATE_EXPERIMENT_MEMBER_ID",
    "COMPOSITION.DUPLICATE_MEMBER_VECTOR": "CONFIG.DUPLICATE_MEMBER_COMBINATION",
    "COMPOSITION.EMPTY_MEMBER_SET": "CONFIG.ENABLED_EXPERIMENT_EMPTY",
    "COMPOSITION.FACTORIAL_AXIS_COUNT": "CONFIG.EXPERIMENT_MODE_SHAPE",
    "COMPOSITION.FACTORIAL_COVERAGE": "CONFIG.FULL_FACTORIAL_COVERAGE",
    "COMPOSITION.MEMBER_AXIS_COVERAGE": "CONFIG.MEMBER_AXIS_BINDING",
    "COMPOSITION.NO_AXES": "CONFIG.EXPERIMENT_MODE_SHAPE",
    "COMPOSITION.ONE_AXIS_COVERAGE": "CONFIG.ONE_AXIS_COVERAGE",
    "COMPOSITION.OVERLAPPING_AXIS_PATH": "CONFIG.OVERLAPPING_AXIS_PATH",
    "COMPOSITION.UNKNOWN_CHOICE": "CONFIG.MEMBER_AXIS_BINDING",
    "COMPOSITION.IDENTITY_ISSUANCE_DEFERRED": ("CONFIG.PLANNING_IDENTITY_ISSUANCE_DEFERRED"),
}


def _validate_json_subset(value: object) -> None:
    def visit(node: object) -> None:
        if isinstance(node, str):
            if not unicodedata.is_normalized("NFC", node):
                raise ConfigContractError("CONFIG.NON_NFC")
            if _ENV_INTERPOLATION.search(node):
                raise ConfigContractError("CONFIG.ENV_INTERPOLATION")
            return
        if node is None or isinstance(node, bool):
            return
        if isinstance(node, int):
            if abs(node) > (1 << 53) - 1:
                raise ConfigContractError("CONFIG.UNSAFE_INTEGER")
            return
        if isinstance(node, float):
            if not math.isfinite(node):
                raise ConfigContractError("CONFIG.NON_FINITE_NUMBER")
            return
        if isinstance(node, list):
            for child in node:
                visit(child)
            return
        if isinstance(node, Mapping):
            for key, child in node.items():
                if not isinstance(key, str):
                    raise ConfigContractError("CONFIG.NON_STRING_KEY")
                visit(key)
                visit(child)
            return
        raise ConfigContractError("CONFIG.NON_JSON_VALUE")

    visit(value)
    canonicalization_failed = False
    try:
        canonical_json_bytes(value)
    except ValueError:
        canonicalization_failed = True
    if canonicalization_failed:
        raise ConfigContractError("CONFIG.NON_CANONICAL_VALUE")


def parse_audit_config(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Parse and schema-validate one strict UTF-8 YAML audit configuration."""

    raw = bytes(data)
    strict_yaml_failure: str | None = None
    try:
        value = load_strict_yaml_bytes(raw, maximum_bytes=_MAX_AUDIT_CONFIG_BYTES)
    except StrictYamlError as exc:
        strict_yaml_failure = _STRICT_YAML_CODES.get(exc.code, "CONFIG.YAML_SYNTAX")
        value = None
    if strict_yaml_failure is not None:
        raise ConfigContractError(strict_yaml_failure)
    if not isinstance(value, dict):
        raise ConfigContractError("CONFIG.ROOT_OBJECT")
    _validate_json_subset(value)
    schema_invalid = False
    try:
        validate_instance(value, "audit-config.schema.json", definition="AuditConfig")
    except SchemaValidationError:
        schema_invalid = True
    if schema_invalid:
        raise ConfigContractError("CONFIG.SCHEMA")
    return cast(dict[str, Any], copy.deepcopy(value))


def _require_unique(values: Sequence[object], code: str) -> None:
    def json_value(value: object) -> object:
        if isinstance(value, Mapping):
            return {str(key): json_value(child) for key, child in value.items()}
        if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray, memoryview)
        ):
            return [json_value(child) for child in value]
        return value

    if len({canonical_json_bytes(json_value(value)) for value in values}) != len(values):
        raise ConfigContractError(code)


def _group_source_columns(group: Mapping[str, Any]) -> list[str]:
    source = cast(Mapping[str, Any], group["source_column_or_rule"])
    if source["kind"] == "column":
        return [cast(str, source["source_column"])]
    return list(cast(Sequence[str], source["source_columns"]))


def _validate_column_contract(config: Mapping[str, Any]) -> None:
    source = cast(Mapping[str, Any], config["input"])
    csv_format = cast(Mapping[str, Any], source["format"])
    columns = cast(Sequence[Mapping[str, Any]], csv_format["columns"])
    names = [cast(str, row["source_column"]) for row in columns]
    _require_unique(names, "CONFIG.DUPLICATE_PHYSICAL_COLUMN")

    delimiter = cast(str, csv_format["delimiter"])
    quote = cast(str, csv_format["quote_character"])
    if delimiter == quote or delimiter in "\r\n" or quote in "\r\n":
        raise ConfigContractError("CONFIG.INVALID_CSV_DIALECT")
    missing = list(cast(Sequence[str], csv_format["missing_tokens"]))
    true_tokens = list(cast(Sequence[str], csv_format["true_tokens"]))
    false_tokens = list(cast(Sequence[str], csv_format["false_tokens"]))
    if set(missing) & (set(true_tokens) | set(false_tokens)) or set(true_tokens) & set(
        false_tokens
    ):
        raise ConfigContractError("CONFIG.OVERLAPPING_CSV_TOKENS")

    roles = cast(Mapping[str, Any], config["column_roles"])
    events = cast(Sequence[Mapping[str, Any]], roles["events"])
    groups = cast(Sequence[Mapping[str, Any]], roles["groups"])
    covariates = cast(Sequence[Mapping[str, Any]], roles["covariates"])
    metadata = cast(Sequence[Mapping[str, Any]], roles["metadata"])
    ignored = cast(Sequence[Mapping[str, Any]], roles["ignored_columns"])
    participant_columns = {cast(str, roles["participant_id_column"])}
    event_names = [cast(str, row["source_column"]) for row in events]
    covariate_names = [cast(str, row["source_column"]) for row in covariates]
    metadata_names = [cast(str, row["source_column"]) for row in metadata]
    _require_unique(event_names, "CONFIG.COLUMN_HAS_MULTIPLE_ROLES")
    _require_unique(covariate_names, "CONFIG.COLUMN_HAS_MULTIPLE_ROLES")
    _require_unique(metadata_names, "CONFIG.COLUMN_HAS_MULTIPLE_ROLES")
    group_columns: set[str] = set()
    for group in groups:
        group_sources = _group_source_columns(group)
        _require_unique(group_sources, "CONFIG.COLUMN_HAS_MULTIPLE_ROLES")
        group_columns.update(group_sources)
    role_families = (
        participant_columns,
        set(event_names),
        group_columns,
        set(covariate_names),
        set(metadata_names),
    )
    if any(left & right for left, right in itertools.combinations(role_families, 2)):
        raise ConfigContractError("CONFIG.COLUMN_HAS_MULTIPLE_ROLES")
    referenced = set().union(*role_families)
    ignored_names = [cast(str, row["source_column"]) for row in ignored]
    _require_unique(ignored_names, "CONFIG.DUPLICATE_IGNORED_COLUMN")
    if referenced & set(ignored_names):
        raise ConfigContractError("CONFIG.IGNORED_COLUMN_HAS_ROLE")
    if set(names) != referenced | set(ignored_names):
        raise ConfigContractError("CONFIG.COLUMN_DECLARATION_COVERAGE")

    physical_types = {cast(str, row["source_column"]): row["physical_type"] for row in columns}
    if physical_types[cast(str, roles["participant_id_column"])] not in {"string", "integer"}:
        raise ConfigContractError("CONFIG.PARTICIPANT_ID_PHYSICAL_TYPE")
    if any(
        physical_types[cast(str, row["source_column"])] not in {"integer", "float64"}
        for row in events
    ):
        raise ConfigContractError("CONFIG.EVENT_PHYSICAL_TYPE")

    _require_unique([cast(str, row["event_id"]) for row in events], "CONFIG.DUPLICATE_EVENT_ID")
    _require_unique(
        [cast(str, row["group_spec_id"]) for row in groups], "CONFIG.DUPLICATE_GROUP_ID"
    )
    _require_unique(
        [cast(str, row["covariate_id"]) for row in covariates],
        "CONFIG.DUPLICATE_COVARIATE_ID",
    )
    _require_unique(
        [cast(str, row["metadata_id"]) for row in metadata],
        "CONFIG.DUPLICATE_METADATA_ID",
    )


def _confirmation_issue_codes(config: Mapping[str, Any]) -> tuple[str, ...]:
    template = cast(Mapping[str, Any], config["template"])
    events = cast(
        Sequence[Mapping[str, Any]],
        cast(Mapping[str, Any], config["column_roles"])["events"],
    )
    issues: set[str] = set()
    if template["status"] == "REQUIRES_LOCAL_MAPPING_CONFIRMATION":
        issues.add("CONFIRMATION.TEMPLATE_LOCAL_MAPPING")
    if any(row["abnormal_direction"] == "REQUIRES_CONFIRMATION" for row in events):
        issues.add("CONFIRMATION.EVENT_DIRECTION")
    if any(row["identifier_risk_reviewed"] is not True for row in events):
        issues.add("CONFIRMATION.EVENT_IDENTIFIER_RISK_REVIEW")
    return tuple(sorted(issues, key=lambda value: value.encode("utf-8")))


def _validate_template(config: Mapping[str, Any]) -> None:
    template = cast(Mapping[str, Any], config["template"])
    if template["kind"] != "synthetic" and template["status"] == "READY_SYNTHETIC_EXAMPLE":
        raise ConfigContractError("CONFIG.TEMPLATE_DATASET_KIND")
    variant = cast(Mapping[str, Any], cast(Mapping[str, Any], config["input"])["variant"])
    if template["status"] == "READY_SYNTHETIC_EXAMPLE" and variant["is_synthetic"] is not True:
        raise ConfigContractError("CONFIG.TEMPLATE_DATASET_KIND")


def _validate_declared_paths(config: Mapping[str, Any]) -> None:
    values: list[object] = [
        cast(Mapping[str, Any], config["input"])["path"],
        cast(Mapping[str, Any], config["worker"])["config_path"],
        cast(Mapping[str, Any], config["output"])["root"],
        cast(Mapping[str, Any], config["baseline_reference"])["path"],
        cast(Mapping[str, Any], config["external_missingness_variant"])["path"],
    ]
    invalid_path = False
    try:
        for value in values:
            if value is not None:
                validate_relative_posix_path(cast(str, value))
    except PathBoundaryError:
        invalid_path = True
    if invalid_path:
        raise ConfigContractError("CONFIG.UNSAFE_PATH")


def _source_variant_intent(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project the exact row-free AnalysisSpec owner from one registry row."""

    return {
        "source_variant_id": row["source_variant_id"],
        "variant_kind": row["variant_kind"],
        "source_variant_id_ref": row["source_variant_id_ref"],
        "method_id": row["method_id"],
    }


def _validate_analysis_spec_variant_intent(
    spec: Mapping[str, Any],
    source_variants: Mapping[str, Mapping[str, Any]],
    *,
    code: str,
) -> None:
    intent = cast(Mapping[str, Any], spec["dataset_variant_intent"])
    owner = source_variants.get(cast(str, intent["source_variant_id"]))
    if owner is None or canonical_json_bytes(intent) != canonical_json_bytes(
        _source_variant_intent(owner)
    ):
        raise ConfigContractError(code)


def _validate_physical_input(config: Mapping[str, Any]) -> Mapping[str, Any]:
    source = cast(Mapping[str, Any], config["input"])
    variant = cast(Mapping[str, Any], source["variant"])
    if source["byte_digest_method"] != "sha256-exact-file-bytes/1":
        raise ConfigContractError("CONFIG.INPUT_BYTE_DIGEST_METHOD")
    if variant["source_digest_method"] != "exact-file/1":
        raise ConfigContractError("CONFIG.INPUT_VARIANT_SOURCE_METHOD")
    if source["expected_byte_digest"] != variant["source_digest"]:
        raise ConfigContractError("CONFIG.INPUT_DIGEST_ALIAS")
    return variant


def _validate_baseline(
    config: Mapping[str, Any], source_variants: Mapping[str, Mapping[str, Any]]
) -> str:
    baseline = cast(Mapping[str, Any], config["baseline_analysis"])
    roles = cast(Mapping[str, Any], config["column_roles"])
    events = cast(Sequence[Mapping[str, Any]], roles["events"])
    event_ids = [cast(str, row["event_id"]) for row in events]
    baseline_event_ids = [
        cast(str, row["event_id"])
        for row in cast(Sequence[Mapping[str, Any]], baseline["event_set"])
    ]
    if cast(Mapping[str, Any], baseline["operation_intent"])["kind"] != "ordinary":
        raise ConfigContractError("CONFIG.BASELINE_MODE")
    if baseline_event_ids != event_ids:
        raise ConfigContractError("CONFIG.BASELINE_EVENT_ORDER")
    directions = cast(Mapping[str, Any], baseline["event_directions"])
    if directions != {cast(str, row["event_id"]): row["abnormal_direction"] for row in events}:
        raise ConfigContractError("CONFIG.BASELINE_EVENT_DIRECTIONS")
    missingness = cast(Mapping[str, Any], baseline["missingness_policy"])
    if list(cast(Sequence[str], missingness["event_ids"])) != event_ids:
        raise ConfigContractError("CONFIG.BASELINE_MISSINGNESS_EVENTS")
    dataset = cast(Mapping[str, Any], baseline["dataset_variant_intent"])
    if (
        dataset["variant_kind"] != "baseline-input"
        or dataset["source_variant_id_ref"] is not None
        or dataset["method_id"] != "exact-input-bytes/1"
    ):
        raise ConfigContractError("CONFIG.BASELINE_DATASET_IDENTITY")
    _validate_analysis_spec_variant_intent(
        baseline,
        source_variants,
        code="CONFIG.BASELINE_VARIANT_PROJECTION",
    )
    physical_variant = _validate_physical_input(config)
    if physical_variant["variant_id"] != dataset["source_variant_id"]:
        raise ConfigContractError("CONFIG.BASELINE_VARIANT_JOIN")
    groups = cast(Sequence[Mapping[str, Any]], roles["groups"])
    cohort = cast(Mapping[str, Any], baseline["cohort_rule"])
    group_id = cast(str, cohort["group_spec_id"])
    group = next(
        (row for row in groups if row["group_spec_id"] == group_id),
        None,
    )
    if group is None:
        raise ConfigContractError("CONFIG.BASELINE_GROUP_RULE")
    group_roles = {
        cast(str, row["role"]) for row in cast(Sequence[Mapping[str, Any]], group["label_to_role"])
    }
    cohort_roles = {
        cast(str, row["role"]) for row in cast(Sequence[Mapping[str, Any]], cohort["label_roles"])
    }
    if cohort["required_roles"] != group["required_roles"] or cohort_roles != group_roles:
        raise ConfigContractError("CONFIG.BASELINE_GROUP_SEMANTICS")
    return analysis_spec_content_id(baseline)


def _validate_source_variants(
    config: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    variants = cast(Sequence[Mapping[str, Any]], config["source_variants"])
    variant_ids = [cast(str, row["source_variant_id"]) for row in variants]
    _require_unique(variant_ids, "CONFIG.DUPLICATE_SOURCE_VARIANT_ID")
    seen: set[str] = set()
    baseline_count = 0
    registry: dict[str, Mapping[str, Any]] = {}
    for row in variants:
        variant_id = cast(str, row["source_variant_id"])
        kind = cast(str, row["variant_kind"])
        source_ref = row["source_variant_id_ref"]
        method_id = cast(str, row["method_id"])
        if method_id not in _SOURCE_VARIANT_METHODS[kind]:
            raise ConfigContractError("CONFIG.SOURCE_VARIANT_METHOD")
        if kind == "baseline-input":
            baseline_count += 1
            if source_ref is not None:
                raise ConfigContractError("CONFIG.SOURCE_VARIANT_ROOT")
        elif source_ref not in seen:
            raise ConfigContractError("CONFIG.SOURCE_VARIANT_ORDER")
        seen.add(variant_id)
        registry[variant_id] = row
    if baseline_count != 1:
        raise ConfigContractError("CONFIG.ONE_BASELINE_SOURCE_VARIANT")
    return registry


def _reject_external_missingness(config: Mapping[str, Any]) -> None:
    """Fail closed until a complete physical external-variant owner exists."""

    external = cast(Mapping[str, Any], config["external_missingness_variant"])
    if external["status"] == "DECLARED":
        raise ConfigContractError("CONFIG.EXTERNAL_MISSINGNESS_UNSUPPORTED")

    def declared(node: object) -> bool:
        if isinstance(node, Mapping):
            if (
                node.get("variant_kind") == "external-missingness"
                or node.get("policy") == "external-variant"
                or node.get("missingness_declaration") == "external-variant"
                or node.get("missingness") == "external-variant"
            ):
                return True
            return any(declared(child) for child in node.values())
        if isinstance(node, Sequence) and not isinstance(node, (str, bytes, bytearray, memoryview)):
            return any(declared(child) for child in node)
        return False

    if declared(config):
        raise ConfigContractError("CONFIG.EXTERNAL_MISSINGNESS_UNSUPPORTED")


def _validate_experiments(
    config: Mapping[str, Any],
    baseline_id: str,
    source_variants: Mapping[str, Mapping[str, Any]],
) -> None:
    try:
        axis_semantics = load_axis_semantics()
    except AxisSemanticsError:
        raise ConfigContractError("CONFIG.AXIS_REGISTRY") from None
    declarations = cast(Mapping[str, Any], config["experiments"])
    sets = cast(Sequence[Mapping[str, Any]], declarations["sets"])
    set_ids = [cast(str, row["experiment_set_id"]) for row in sets]
    _require_unique(set_ids, "CONFIG.DUPLICATE_EXPERIMENT_SET_ID")
    baselines = [row for row in sets if row["mode"] == "baseline" and row["enabled"]]
    if len(baselines) != 1:
        raise ConfigContractError("CONFIG.ONE_BASELINE")
    baseline = cast(Mapping[str, Any], config["baseline_analysis"])
    ordinary_ids = {baseline_id}
    member_spec_ids_by_set: dict[str, tuple[str, ...]] = {}
    for declaration in sets:
        mode = cast(str, declaration["mode"])
        experiment_set_id = cast(str, declaration["experiment_set_id"])
        axes = cast(Sequence[Mapping[str, Any]], declaration["axes"])
        members = cast(Sequence[Mapping[str, Any]], declaration["members"])
        computed_ids: list[str] = []
        if (
            mode == "full-factorial"
            and declaration["enabled"]
            and (
                declarations["allow_full_factorial"] is not True
                or declarations["full_factorial_override_rationale"] is None
                or not members
            )
        ):
            raise ConfigContractError("CONFIG.FULL_FACTORIAL_NOT_AUTHORIZED")
        if mode in {"one-axis", "declared-combinations", "full-factorial"}:
            for member in members:
                try:
                    composed = compose_analysis_spec(
                        baseline,
                        experiment_set_id,
                        mode,
                        axes,
                        member,
                    )
                except AxisCompositionError as exc:
                    code = _COMPOSITION_CONFIG_CODES.get(exc.code, "CONFIG.MEMBER_COMPOSITION")
                    raise ConfigContractError(code) from None
                _validate_analysis_spec_variant_intent(
                    composed,
                    source_variants,
                    code="CONFIG.EXPERIMENT_MEMBER_VARIANT_PROJECTION",
                )
                if composed["dataset_variant_intent"]["variant_kind"] != "baseline-input":
                    raise ConfigContractError("CONFIG.EXPERIMENT_MEMBER_BINDING")
                computed_ids.append(analysis_spec_content_id(composed))
        elif mode == "custom":
            for member in members:
                spec = cast(Mapping[str, Any], member["analysis_spec"])
                _validate_analysis_spec_variant_intent(
                    spec,
                    source_variants,
                    code="CONFIG.EXPERIMENT_MEMBER_VARIANT_PROJECTION",
                )
                if spec["dataset_variant_intent"]["variant_kind"] != "baseline-input":
                    raise ConfigContractError("CONFIG.EXPERIMENT_MEMBER_BINDING")
                spec_id = analysis_spec_content_id(spec)
                if member["analysis_spec_id"] != spec_id:
                    raise ConfigContractError("CONFIG.EXPERIMENT_MEMBER_SPEC_ID")
                computed_ids.append(spec_id)
        member_spec_ids_by_set[experiment_set_id] = tuple(computed_ids)
        ordinary_ids.update(computed_ids)

    for declaration in sets:
        mode = cast(str, declaration["mode"])
        enabled = cast(bool, declaration["enabled"])
        axes = cast(Sequence[Mapping[str, Any]], declaration["axes"])
        members = cast(Sequence[Mapping[str, Any]], declaration["members"])
        bootstrap = declaration["bootstrap"]
        subsample = declaration["subsample"]
        influence = declaration["influence"]
        nulls = cast(Sequence[Mapping[str, Any]], declaration["null_families"])
        axis_ids = [cast(str, row["axis_id"]) for row in axes]
        _require_unique(axis_ids, "CONFIG.DUPLICATE_AXIS_ID")
        allowed_choices: dict[str, set[str]] = {}
        owned_paths_by_axis: dict[str, tuple[str, ...]] = {}
        for axis in axes:
            choices = cast(Sequence[Mapping[str, Any]], axis["choices"])
            choice_ids = [cast(str, row["choice_id"]) for row in choices]
            _require_unique(choice_ids, "CONFIG.DUPLICATE_AXIS_CHOICE_ID")
            semantic_target = cast(str, axis["semantic_target"])
            try:
                target_semantics = axis_semantics.target(semantic_target)
            except AxisSemanticsError:
                raise ConfigContractError("CONFIG.AXIS_REGISTRY") from None
            owned_paths = tuple(cast(Sequence[str], axis["owned_analysis_spec_paths"]))
            if (
                axis["baseline_choice_id"] not in choice_ids
                or target_semantics.primary_path not in owned_paths
                or not set(owned_paths).issubset(target_semantics.allowed_paths)
            ):
                raise ConfigContractError("CONFIG.AXIS_SEMANTICS")
            choice_values: dict[str, dict[str, Any]] = {}
            for choice in choices:
                assignments = cast(Sequence[Mapping[str, Any]], choice["assignments"])
                assignment_paths = [cast(str, row["path"]) for row in assignments]
                _require_unique(assignment_paths, "CONFIG.DUPLICATE_AXIS_ASSIGNMENT_PATH")
                if set(assignment_paths) != set(owned_paths):
                    raise ConfigContractError("CONFIG.AXIS_ASSIGNMENT_COVERAGE")
                choice_values[cast(str, choice["choice_id"])] = {
                    cast(str, row["path"]): copy.deepcopy(row["value"]) for row in assignments
                }
            baseline_values = choice_values[cast(str, axis["baseline_choice_id"])]
            try:
                baseline_choice_mismatch = any(
                    canonical_json_bytes(baseline_values[path])
                    != canonical_json_bytes(baseline[axis_semantics.analysis_spec_key(path)])
                    for path in owned_paths
                )
            except AxisSemanticsError:
                raise ConfigContractError("CONFIG.AXIS_REGISTRY") from None
            if baseline_choice_mismatch:
                raise ConfigContractError("CONFIG.AXIS_BASELINE_CHOICE")
            for choice_id, values in choice_values.items():
                if choice_id == axis["baseline_choice_id"]:
                    continue
                if all(
                    canonical_json_bytes(values[path])
                    == canonical_json_bytes(baseline_values[path])
                    for path in owned_paths
                ):
                    raise ConfigContractError("CONFIG.AXIS_DECORATIVE_CHOICE")
            axis_id = cast(str, axis["axis_id"])
            allowed_choices[axis_id] = set(choice_ids)
            owned_paths_by_axis[axis_id] = owned_paths
        if mode in {"declared-combinations", "full-factorial"}:
            flat_paths = [path for paths in owned_paths_by_axis.values() for path in paths]
            _require_unique(flat_paths, "CONFIG.OVERLAPPING_AXIS_PATH")
        _require_unique(
            [cast(str, row["member_id"]) for row in members],
            "CONFIG.DUPLICATE_EXPERIMENT_MEMBER_ID",
        )
        if not enabled and members:
            raise ConfigContractError("CONFIG.DISABLED_EXPERIMENT_HAS_WORK")
        member_combinations: list[tuple[tuple[str, str], ...]] = []
        member_spec_ids = list(member_spec_ids_by_set[cast(str, declaration["experiment_set_id"])])
        for member in members:
            if "axis_choices" in member:
                if mode not in {"one-axis", "declared-combinations", "full-factorial"}:
                    raise ConfigContractError("CONFIG.EXPERIMENT_MEMBER_KIND")
                selections = cast(Sequence[Mapping[str, Any]], member["axis_choices"])
                selection_axes = [cast(str, row["axis_id"]) for row in selections]
                _require_unique(selection_axes, "CONFIG.DUPLICATE_MEMBER_AXIS")
                if set(selection_axes) != set(axis_ids) or any(
                    cast(str, row["choice_id"])
                    not in allowed_choices.get(cast(str, row["axis_id"]), set())
                    for row in selections
                ):
                    raise ConfigContractError("CONFIG.MEMBER_AXIS_BINDING")
                vector = tuple(
                    (
                        axis_id,
                        next(
                            cast(str, row["choice_id"])
                            for row in selections
                            if row["axis_id"] == axis_id
                        ),
                    )
                    for axis_id in axis_ids
                )
                member_combinations.append(vector)
            else:
                if mode != "custom":
                    raise ConfigContractError("CONFIG.EXPERIMENT_MEMBER_KIND")
        if len(set(member_combinations)) != len(member_combinations):
            raise ConfigContractError("CONFIG.DUPLICATE_MEMBER_COMBINATION")
        _require_unique(member_spec_ids, "CONFIG.DUPLICATE_MEMBER_ANALYSIS_SPEC")
        if mode == "baseline":
            valid = (
                enabled
                and not axes
                and not members
                and bootstrap is None
                and subsample is None
                and influence is None
                and not nulls
            )
        elif mode == "one-axis":
            valid = (
                len(axes) == 1
                and bootstrap is None
                and subsample is None
                and influence is None
                and not nulls
            )
            if enabled and len(axes) == 1:
                axis_id = axis_ids[0]
                baseline_choice_id = cast(str, axes[0]["baseline_choice_id"])
                expected_one_axis = {
                    ((axis_id, choice_id),)
                    for choice_id in allowed_choices[axis_id]
                    if choice_id != baseline_choice_id
                }
                if set(member_combinations) != expected_one_axis:
                    raise ConfigContractError("CONFIG.ONE_AXIS_COVERAGE")
        elif mode == "declared-combinations":
            valid = (
                len(axes) >= 2
                and bootstrap is None
                and subsample is None
                and influence is None
                and not nulls
            )
        elif mode == "full-factorial":
            valid = (
                len(axes) >= 2
                and bootstrap is None
                and subsample is None
                and influence is None
                and not nulls
            )
            if enabled and (
                declarations["allow_full_factorial"] is not True
                or declarations["full_factorial_override_rationale"] is None
                or not members
            ):
                raise ConfigContractError("CONFIG.FULL_FACTORIAL_NOT_AUTHORIZED")
            if enabled:
                expected_factorial = set(
                    itertools.product(
                        *[
                            [(axis_id, choice_id) for choice_id in sorted(allowed_choices[axis_id])]
                            for axis_id in axis_ids
                        ]
                    )
                )
                if set(member_combinations) != expected_factorial:
                    raise ConfigContractError("CONFIG.FULL_FACTORIAL_COVERAGE")
        elif mode == "bootstrap":
            valid = (
                bootstrap is not None
                and subsample is None
                and influence is None
                and not axes
                and not members
                and not nulls
            )
        elif mode == "subsample":
            valid = (
                subsample is not None
                and bootstrap is None
                and influence is None
                and not axes
                and not members
                and not nulls
            )
        elif mode == "influence":
            valid = (
                influence is not None
                and bootstrap is None
                and subsample is None
                and not axes
                and not members
                and not nulls
            )
        elif mode == "null":
            valid = (
                bool(nulls)
                and bootstrap is None
                and subsample is None
                and influence is None
                and not axes
                and not members
            )
        else:
            valid = (
                not axes
                and bootstrap is None
                and subsample is None
                and influence is None
                and not nulls
            )
        if not valid:
            raise ConfigContractError("CONFIG.EXPERIMENT_MODE_SHAPE")
        if enabled and mode in {"one-axis", "declared-combinations", "custom"} and not members:
            raise ConfigContractError("CONFIG.ENABLED_EXPERIMENT_EMPTY")
        for member in members:
            if "analysis_spec" not in member:
                continue
            spec = cast(Mapping[str, Any], member["analysis_spec"])
            if cast(Mapping[str, Any], spec["operation_intent"])["kind"] != "ordinary":
                raise ConfigContractError("CONFIG.EXPERIMENT_MEMBER_BINDING")

        group_ids = {
            cast(str, row["group_spec_id"])
            for row in cast(
                Sequence[Mapping[str, Any]],
                cast(Mapping[str, Any], config["column_roles"])["groups"],
            )
        }
        declared_analysis_ids = ordinary_ids

        def validate_derived_owner(
            row: Mapping[str, Any],
            expected_variant_kind: str,
            declared_ids: set[str],
        ) -> None:
            source_ids = list(cast(Sequence[str], row["source_analysis_spec_ids"]))
            source_variant_id = cast(str, row["source_variant_id"])
            derived_variant_id = cast(str, row["derived_source_variant_id"])
            source_variant = source_variants.get(source_variant_id)
            derived_variant = source_variants.get(derived_variant_id)
            if (
                not source_ids
                or not set(source_ids).issubset(declared_ids)
                or source_variant is None
                or derived_variant is None
                or derived_variant["variant_kind"] != expected_variant_kind
                or derived_variant["source_variant_id_ref"] != source_variant_id
            ):
                raise ConfigContractError("CONFIG.DERIVED_OWNER_BINDING")

        if bootstrap is not None:
            bootstrap_row = cast(Mapping[str, Any], bootstrap)
            validate_derived_owner(bootstrap_row, "bootstrap-resample", declared_analysis_ids)
            strata = list(cast(Sequence[str], bootstrap_row["strata_group_spec_ids"]))
            if (
                not set(strata).issubset(group_ids)
                or (bootstrap_row["sampling_design"] == "stratified" and not strata)
                or (bootstrap_row["sampling_design"] == "ordinary" and strata)
            ):
                raise ConfigContractError("CONFIG.BOOTSTRAP_DECLARATION")
        if subsample is not None:
            subsample_row = cast(Mapping[str, Any], subsample)
            validate_derived_owner(subsample_row, "participant-subsample", declared_analysis_ids)
            strata = list(cast(Sequence[str], subsample_row["strata_group_spec_ids"]))
            if (
                not set(strata).issubset(group_ids)
                or (subsample_row["sampling_design"] == "stratified" and not strata)
                or (subsample_row["sampling_design"] == "ordinary" and strata)
            ):
                raise ConfigContractError("CONFIG.SUBSAMPLE_DECLARATION")
        if influence is not None:
            influence_row = cast(Mapping[str, Any], influence)
            validate_derived_owner(influence_row, "influence-removal", declared_analysis_ids)
            groups = list(cast(Sequence[str], influence_row["named_group_spec_ids"]))
            selection = influence_row.get("removal_selection")
            if (
                not set(groups).issubset(group_ids)
                or (influence_row["removal_kind"] == "named-group-removal" and not groups)
                or (influence_row["removal_kind"] == "leave-one-participant-out" and groups)
                or (
                    influence_row["removal_kind"] == "named-group-removal"
                    and selection is not None
                )
            ):
                raise ConfigContractError("CONFIG.INFLUENCE_DECLARATION")
        _require_unique(
            [cast(str, row["null_family_id"]) for row in nulls],
            "CONFIG.DUPLICATE_NULL_FAMILY_ID",
        )
        for null in nulls:
            validate_derived_owner(null, "null-transformation", declared_analysis_ids)
            transformation = null["transformation"]
            group_id = null["within_group_spec_id"]
            preserves = null["preserves_group_conditional_event_marginals"]
            if null["null_method_id"] != _NULL_METHOD_BY_TRANSFORMATION[transformation]:
                raise ConfigContractError("CONFIG.NULL_FAMILY_METHOD")
            if transformation == "featurewise-participant-permutation":
                if group_id not in group_ids or preserves is not True:
                    raise ConfigContractError("CONFIG.NULL_FAMILY_DECLARATION")
            elif group_id is not None or preserves is not False:
                raise ConfigContractError("CONFIG.NULL_FAMILY_DECLARATION")


def _validate_profiles(config: Mapping[str, Any]) -> None:
    profiles = cast(Mapping[str, Mapping[str, Any]], config["profiles"])
    for name in ("quick", "full", "release"):
        profile = profiles[name]
        if profile["profile_id"] != name:
            raise ConfigContractError("CONFIG.PROFILE_ID")
        if (
            cast(int, profile["ordinary_universe_limit"]) > 256
            and profile["ordinary_limit_override_rationale"] is None
        ):
            raise ConfigContractError("CONFIG.ORDINARY_LIMIT_OVERRIDE")

    monotonic_keys = (
        "ordinary_universe_limit",
        "max_total_fits",
        "max_wall_seconds",
        "max_parallel_workers",
        "bootstrap_replicates",
        "subsample_replicates",
        "influence_max_removals",
        "null_replicates_per_family",
    )
    if any(
        not (
            cast(int, profiles["quick"][key])
            <= cast(int, profiles["full"][key])
            <= cast(int, profiles["release"][key])
        )
        for key in monotonic_keys
    ):
        raise ConfigContractError("CONFIG.NON_MONOTONIC_PROFILES")

    declarations = cast(
        Sequence[Mapping[str, Any]],
        cast(Mapping[str, Any], config["experiments"])["sets"],
    )
    enabled_modes = {cast(str, row["mode"]) for row in declarations if row["enabled"]}
    for profile in profiles.values():
        bootstrap = cast(int, profile["bootstrap_replicates"])
        subsample = cast(int, profile["subsample_replicates"])
        influence = cast(int, profile["influence_max_removals"])
        null_replicates = cast(int, profile["null_replicates_per_family"])
        if ("bootstrap" in enabled_modes) != (bootstrap > 0):
            raise ConfigContractError("CONFIG.BOOTSTRAP_PROFILE_MISMATCH")
        if ("subsample" in enabled_modes) != (subsample > 0):
            raise ConfigContractError("CONFIG.SUBSAMPLE_PROFILE_MISMATCH")
        if ("influence" in enabled_modes) != (influence > 0):
            raise ConfigContractError("CONFIG.INFLUENCE_PROFILE_MISMATCH")
        if ("null" in enabled_modes) != (null_replicates > 0):
            raise ConfigContractError("CONFIG.NULL_PROFILE_MISMATCH")


def _validate_cross_fields(config: Mapping[str, Any]) -> None:
    _validate_template(config)
    _validate_declared_paths(config)
    _validate_column_contract(config)
    _reject_external_missingness(config)
    source_variants = _validate_source_variants(config)
    baseline_id = _validate_baseline(config, source_variants)
    _validate_experiments(config, baseline_id, source_variants)
    _validate_profiles(config)


def _scientific_backend_registry_preimage(
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Collect every selectable complete BackendSpec in canonical JCS order."""

    baseline = cast(Mapping[str, Any], config["baseline_analysis"])
    backends: list[Mapping[str, Any]] = [cast(Mapping[str, Any], baseline["backend"])]
    declarations = cast(Mapping[str, Any], config["experiments"])
    for experiment_set in cast(Sequence[Mapping[str, Any]], declarations["sets"]):
        if not experiment_set["enabled"]:
            continue
        for axis in cast(Sequence[Mapping[str, Any]], experiment_set["axes"]):
            for choice in cast(Sequence[Mapping[str, Any]], axis["choices"]):
                for assignment in cast(Sequence[Mapping[str, Any]], choice["assignments"]):
                    if assignment["path"] == "/backend":
                        backends.append(cast(Mapping[str, Any], assignment["value"]))
        if experiment_set["mode"] == "custom":
            for member in cast(Sequence[Mapping[str, Any]], experiment_set["members"]):
                spec = cast(Mapping[str, Any], member["analysis_spec"])
                backends.append(cast(Mapping[str, Any], spec["backend"]))

    by_jcs = {canonical_json_bytes(backend): copy.deepcopy(dict(backend)) for backend in backends}
    return {
        "registry_schema_version": "ebm-audit-scientific-backend-registry/1.0",
        "ordered_backends": [by_jcs[key] for key in sorted(by_jcs)],
    }


def _resolve_relative_path(base: Path, raw: str) -> Path:
    invalid_path = False
    try:
        normalized = validate_relative_posix_path(raw)
    except PathBoundaryError:
        invalid_path = True
        normalized = ""
    if invalid_path:
        raise ConfigContractError("CONFIG.UNSAFE_PATH")
    absolute_base = base.absolute()
    candidate = (absolute_base / Path(*normalized.split("/"))).absolute()
    if not candidate.is_relative_to(absolute_base):
        raise ConfigContractError("CONFIG.UNSAFE_PATH")
    return candidate


def resolve_audit_config(config: Mapping[str, Any], *, source_path: Path) -> ResolvedAuditConfig:
    """Resolve v0.3 paths and issue its path-free public prerequisite.

    Resolution never launches a worker, realizes participant rows, or accepts
    an AnalysisSpec for execution.  Plan/3 identity issuance remains owned by
    the later in-process PlanningAuthority boundary.
    """

    private_config = copy.deepcopy(dict(config))
    _validate_json_subset(private_config)
    schema_invalid = False
    try:
        validate_instance(private_config, "audit-config.schema.json", definition="AuditConfig")
    except SchemaValidationError:
        schema_invalid = True
    if schema_invalid:
        raise ConfigContractError("CONFIG.SCHEMA")
    _validate_cross_fields(private_config)
    scientific_backend_registry = _scientific_backend_registry_preimage(private_config)
    backend_registry_digest = scientific_backend_registry_digest(scientific_backend_registry)
    base = source_path.parent
    source = cast(Mapping[str, Any], private_config["input"])
    worker = cast(Mapping[str, Any], private_config["worker"])
    output = cast(Mapping[str, Any], private_config["output"])
    baseline_reference = cast(Mapping[str, Any], private_config["baseline_reference"])
    external = cast(Mapping[str, Any], private_config["external_missingness_variant"])
    development_authority = cast(
        Mapping[str, Any] | None,
        private_config.get("development_scenario_authority"),
    )
    private_paths = PrivatePathBindings(
        source_config=source_path.absolute(),
        input_table=_resolve_relative_path(base, cast(str, source["path"])),
        worker_config=_resolve_relative_path(base, cast(str, worker["config_path"])),
        output_root=_resolve_relative_path(base, cast(str, output["root"])),
        baseline_reference=(
            None
            if baseline_reference["path"] is None
            else _resolve_relative_path(base, cast(str, baseline_reference["path"]))
        ),
        external_missingness_variant=(
            None
            if external["path"] is None
            else _resolve_relative_path(base, cast(str, external["path"]))
        ),
        development_scenario_authority=(
            None
            if development_authority is None
            else _resolve_relative_path(base, cast(str, development_authority["path"]))
        ),
    )
    public_source_config = copy.deepcopy(private_config)
    del public_source_config["input"]["path"]
    del public_source_config["worker"]["config_path"]
    del public_source_config["baseline_reference"]["path"]
    del public_source_config["external_missingness_variant"]["path"]
    del public_source_config["output"]["root"]
    if development_authority is not None:
        del public_source_config["development_scenario_authority"]["path"]
    try:
        validate_instance(
            public_source_config,
            "audit-config.schema.json",
            definition="AuditConfigPublicProjection",
        )
    except SchemaValidationError:
        raise ConfigContractError("CONFIG.PUBLIC_SOURCE_PROJECTION") from None

    confirmation_issue_codes = list(_confirmation_issue_codes(private_config))
    placeholder_digest = "sha256:" + "0" * 64
    if any(
        digest == placeholder_digest
        for digest in (
            source["expected_byte_digest"],
            worker["worker_config_digest"],
            worker["worker_identity_digest"],
        )
    ):
        confirmation_issue_codes.append("CONFIRMATION.PLACEHOLDER_IDENTITY")
    baseline = cast(Mapping[str, Any], private_config["baseline_analysis"])
    randomness = cast(Mapping[str, Any], private_config["randomness"])
    template = cast(Mapping[str, Any], private_config["template"])
    projection: dict[str, Any] = {
        "resolved_config_schema_version": "ebm-audit-resolved-public-config/0.3",
        "source_config_digest": structured_sha256(
            "ebm-audit/audit-config-public/3", public_source_config
        ),
        "template_kind": template["kind"],
        "template_status": template["status"],
        "confirmation_issue_codes": sorted(
            set(confirmation_issue_codes), key=lambda value: value.encode("utf-8")
        ),
        "input_byte_digest": source["expected_byte_digest"],
        "input_format_digest": structured_sha256("ebm-audit/input-format/1", source["format"]),
        "column_roles_digest": structured_sha256(
            "ebm-audit/column-roles/1", private_config["column_roles"]
        ),
        "external_missingness_status": external["status"],
        "external_missingness_byte_digest": external["byte_digest"],
        "worker_config_digest": worker["worker_config_digest"],
        "worker_identity_digest": worker["worker_identity_digest"],
        "scientific_backend_registry_digest": backend_registry_digest,
        "baseline_reference_status": baseline_reference["status"],
        "baseline_reference_digest": baseline_reference["byte_digest"],
        "baseline_analysis_spec_id": analysis_spec_content_id(baseline),
        "source_variant_registry_digest": structured_sha256(
            "ebm-audit/source-variant-registry/2", private_config["source_variants"]
        ),
        "experiment_declarations_digest": structured_sha256(
            "ebm-audit/experiment-declarations/2", private_config["experiments"]
        ),
        "profiles_digest": structured_sha256(
            "ebm-audit/execution-profiles/2", private_config["profiles"]
        ),
        "master_seed": randomness["master_seed"],
        "seed_derivation_version": randomness["seed_derivation_version"],
        "output_layout_version": output["layout_version"],
        "output_overwrite": output["overwrite"],
        "private_directory_mode": output["private_directory_mode"],
        "offline": True,
    }
    if development_authority is not None:
        projection["development_scenario_authority_digest"] = development_authority[
            "expected_byte_digest"
        ]
    try:
        validate_instance(
            projection,
            "audit-config.schema.json",
            definition="ResolvedPublicConfig",
        )
    except SchemaValidationError:
        raise ConfigContractError("CONFIG.RESOLVED_PROJECTION") from None
    public_digest = structured_sha256("ebm-audit/resolved-audit-config/3", projection)
    return _construct_resolved_audit_config(
        private_config=private_config,
        private_paths=private_paths,
        public_projection=projection,
        public_digest=public_digest,
    )


def load_audit_config(path: Path) -> ResolvedAuditConfig:
    """Read, strictly validate, and resolve a local YAML configuration."""

    unreadable = False
    try:
        data = path.read_bytes()
    except OSError:
        unreadable = True
        data = b""
    if unreadable:
        raise ConfigContractError("CONFIG.UNREADABLE")
    return resolve_audit_config(parse_audit_config(data), source_path=path)
