"""Closed analysis-axis semantics loaded from the normative protocol registry."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, cast

from ebm_audit.schema import load_protocol_registry, load_schema


class AxisSemanticsError(ValueError):
    """A fail-closed defect in the normative axis registry or schema closure."""

    def __init__(self) -> None:
        super().__init__("The normative analysis-axis semantics are inconsistent.")


@dataclass(frozen=True, slots=True)
class AxisTargetSemantics:
    """The complete path authority for one semantic analysis axis."""

    primary_path: str
    allowed_paths: frozenset[str]


@dataclass(frozen=True, slots=True)
class AxisSemantics:
    """Validated registry projection shared by config loading and composition."""

    targets: Mapping[str, AxisTargetSemantics]
    path_to_analysis_spec_key: Mapping[str, str]

    def target(self, semantic_target: str) -> AxisTargetSemantics:
        try:
            return self.targets[semantic_target]
        except KeyError:
            raise AxisSemanticsError from None

    def analysis_spec_key(self, path: str) -> str:
        try:
            return self.path_to_analysis_spec_key[path]
        except KeyError:
            raise AxisSemanticsError from None


def _as_mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise AxisSemanticsError
    return cast(Mapping[str, Any], value)


def _as_sequence(value: object) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray, memoryview)):
        raise AxisSemanticsError
    return cast(Sequence[object], value)


def _unique_strings(value: object) -> tuple[str, ...]:
    rows = _as_sequence(value)
    if not all(isinstance(row, str) and row for row in rows):
        raise AxisSemanticsError
    strings = cast(tuple[str, ...], tuple(rows))
    if len(set(strings)) != len(strings):
        raise AxisSemanticsError
    return strings


def _local_definition_name(reference: object) -> str:
    prefix = "#/$defs/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        raise AxisSemanticsError
    name = reference.removeprefix(prefix)
    if not name or "/" in name:
        raise AxisSemanticsError
    return name


def _analysis_definition_name(reference: object, *, external: bool) -> str:
    prefix = "analysis-universe.schema.json#/$defs/" if external else "#/$defs/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        raise AxisSemanticsError
    name = reference.removeprefix(prefix)
    if not name or "/" in name:
        raise AxisSemanticsError
    return name


def _axis_assignment_value_schemas(
    audit_definitions: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    union = _as_mapping(audit_definitions.get("AxisAssignment"))
    branches = _as_sequence(union.get("oneOf"))
    result: dict[str, Mapping[str, Any]] = {}
    for raw_branch in branches:
        branch_ref = _as_mapping(raw_branch).get("$ref")
        branch = _as_mapping(audit_definitions.get(_local_definition_name(branch_ref)))
        if branch.get("type") != "object" or branch.get("additionalProperties") is not False:
            raise AxisSemanticsError
        if set(_unique_strings(branch.get("required"))) != {"path", "value"}:
            raise AxisSemanticsError
        properties = _as_mapping(branch.get("properties"))
        if set(properties) != {"path", "value"}:
            raise AxisSemanticsError
        path_schema = _as_mapping(properties.get("path"))
        path = path_schema.get("const")
        if not isinstance(path, str) or path in result:
            raise AxisSemanticsError
        result[path] = _as_mapping(properties.get("value"))
    if not result:
        raise AxisSemanticsError
    return result


def load_axis_semantics() -> AxisSemantics:
    """Load and cross-check the single normative analysis-axis registry.

    The registry vocabulary, audit-config typed assignments, and AnalysisSpec
    top-level value schemas must form one exact closed set. Any incomplete,
    duplicated, unknown, extra, or detached entry makes the contract unusable.
    """

    registry = _as_mapping(load_protocol_registry())
    contract = _as_mapping(registry.get("audit_config_identity_contract"))
    raw_rows = _as_sequence(contract.get("axis_semantic_target_registry"))
    expected_row_keys = {
        "semantic_target",
        "primary_analysis_spec_path",
        "allowed_analysis_spec_paths",
    }

    targets: dict[str, AxisTargetSemantics] = {}
    primary_paths: set[str] = set()
    registered_paths: set[str] = set()
    for raw_row in raw_rows:
        row = _as_mapping(raw_row)
        if set(row) != expected_row_keys:
            raise AxisSemanticsError
        semantic_target = row.get("semantic_target")
        primary_path = row.get("primary_analysis_spec_path")
        allowed_paths = _unique_strings(row.get("allowed_analysis_spec_paths"))
        if (
            not isinstance(semantic_target, str)
            or not semantic_target
            or semantic_target in targets
            or not isinstance(primary_path, str)
            or primary_path not in allowed_paths
            or primary_path in primary_paths
        ):
            raise AxisSemanticsError
        allowed_set = frozenset(allowed_paths)
        targets[semantic_target] = AxisTargetSemantics(primary_path, allowed_set)
        primary_paths.add(primary_path)
        registered_paths.update(allowed_set)
    if not targets:
        raise AxisSemanticsError

    audit_schema = _as_mapping(load_schema("audit-config.schema.json"))
    audit_definitions = _as_mapping(audit_schema.get("$defs"))
    axis_definition = _as_mapping(audit_definitions.get("AxisDefinition"))
    axis_properties = _as_mapping(axis_definition.get("properties"))
    target_schema = _as_mapping(axis_properties.get("semantic_target"))
    owned_paths_schema = _as_mapping(axis_properties.get("owned_analysis_spec_paths"))
    owned_path_items = _as_mapping(owned_paths_schema.get("items"))
    schema_targets = _unique_strings(target_schema.get("enum"))
    schema_owned_paths = _unique_strings(owned_path_items.get("enum"))
    if set(schema_targets) != set(targets) or set(schema_owned_paths) != registered_paths:
        raise AxisSemanticsError

    assignment_value_schemas = _axis_assignment_value_schemas(audit_definitions)
    if set(assignment_value_schemas) != registered_paths:
        raise AxisSemanticsError

    analysis_schema = _as_mapping(load_schema("analysis-universe.schema.json"))
    analysis_definitions = _as_mapping(analysis_schema.get("$defs"))
    analysis_spec = _as_mapping(analysis_definitions.get("AnalysisSpec"))
    analysis_properties = _as_mapping(analysis_spec.get("properties"))
    path_to_key: dict[str, str] = {}
    for path, assignment_value_schema in assignment_value_schemas.items():
        if not path.startswith("/") or path.count("/") != 1:
            raise AxisSemanticsError
        key = path[1:]
        analysis_value_schema = _as_mapping(analysis_properties.get(key))
        if path == "/mcmc":
            assignment_branches = _as_sequence(assignment_value_schema.get("oneOf"))
            analysis_branches = _as_sequence(analysis_value_schema.get("oneOf"))
            if len(assignment_branches) != 2 or len(analysis_branches) != 2:
                raise AxisSemanticsError
            assignment_ref = _as_mapping(assignment_branches[0]).get("$ref")
            analysis_ref = _as_mapping(analysis_branches[0]).get("$ref")
            if (
                _analysis_definition_name(assignment_ref, external=True) != "McmcSpec"
                or _analysis_definition_name(analysis_ref, external=False) != "McmcSpec"
                or _as_mapping(assignment_branches[1]) != {"type": "null"}
                or _as_mapping(analysis_branches[1]) != {"type": "null"}
            ):
                raise AxisSemanticsError
            path_to_key[path] = key
            continue
        if set(assignment_value_schema) != {"$ref"} or set(analysis_value_schema) != {"$ref"}:
            raise AxisSemanticsError
        assignment_reference = assignment_value_schema.get("$ref")
        analysis_reference = analysis_value_schema.get("$ref")
        if assignment_reference != analysis_reference and _analysis_definition_name(
            assignment_reference, external=True
        ) != _analysis_definition_name(analysis_reference, external=False):
            raise AxisSemanticsError
        path_to_key[path] = key

    return AxisSemantics(
        targets=MappingProxyType(targets),
        path_to_analysis_spec_key=MappingProxyType(path_to_key),
    )
