"""Deterministic composition of predeclared ordinary analysis choices."""

from __future__ import annotations

import copy
import itertools
from collections.abc import Mapping, Sequence
from typing import Any, cast

from ebm_audit.protocol import canonical_json_bytes
from ebm_audit.schema import SchemaValidationError, validate_instance

from .axis_semantics import AxisSemantics, AxisSemanticsError, load_axis_semantics
from .identities import analysis_spec_content_id

_COMPOSED_MODES = frozenset({"one-axis", "declared-combinations", "full-factorial"})


class AxisCompositionError(ValueError):
    """A privacy-safe failure in a declarative choice matrix."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Analysis-axis composition is invalid.")

    def __repr__(self) -> str:
        return f"AxisCompositionError(code={self.code!r})"


def _utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


def _copy_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(dict(value))


def _validate_config_definition(value: object, definition: str, code: str) -> None:
    try:
        validate_instance(value, "audit-config.schema.json", definition=definition)
    except SchemaValidationError:
        raise AxisCompositionError(code) from None


def _validate_analysis_spec(value: object) -> None:
    try:
        validate_instance(value, "analysis-universe.schema.json", definition="AnalysisSpec")
    except SchemaValidationError:
        raise AxisCompositionError("COMPOSITION.ANALYSIS_SPEC_SCHEMA") from None


def _canonical_equal(left: object, right: object) -> bool:
    try:
        return canonical_json_bytes(left) == canonical_json_bytes(right)
    except (TypeError, ValueError):
        raise AxisCompositionError("COMPOSITION.NON_CANONICAL_VALUE") from None


def _validated_axis_semantics() -> AxisSemantics:
    try:
        return load_axis_semantics()
    except AxisSemanticsError:
        raise AxisCompositionError("COMPOSITION.AXIS_REGISTRY") from None


def _assignment_values(choice: Mapping[str, Any]) -> dict[str, Any]:
    assignments = cast(Sequence[Mapping[str, Any]], choice["assignments"])
    result: dict[str, Any] = {}
    for assignment in assignments:
        path = cast(str, assignment["path"])
        if path in result:
            raise AxisCompositionError("COMPOSITION.DUPLICATE_ASSIGNMENT_PATH")
        result[path] = copy.deepcopy(assignment["value"])
    return result


def _choice_registry(
    baseline: Mapping[str, Any],
    axis: Mapping[str, Any],
    semantics: AxisSemantics,
) -> tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], str]], str]:
    _validate_config_definition(axis, "AxisDefinition", "COMPOSITION.AXIS_SCHEMA")
    semantic_target = cast(str, axis["semantic_target"])
    try:
        target_semantics = semantics.target(semantic_target)
    except AxisSemanticsError:
        raise AxisCompositionError("COMPOSITION.AXIS_REGISTRY") from None
    owned_paths = tuple(
        sorted(cast(Sequence[str], axis["owned_analysis_spec_paths"]), key=_utf8_key)
    )
    owned_set = set(owned_paths)
    if target_semantics.primary_path not in owned_set or not owned_set.issubset(
        target_semantics.allowed_paths
    ):
        raise AxisCompositionError("COMPOSITION.AXIS_PATH_OWNERSHIP")

    choices = cast(Sequence[Mapping[str, Any]], axis["choices"])
    registry: dict[str, tuple[dict[str, Any], str]] = {}
    fingerprints: set[bytes] = set()
    for choice in choices:
        choice_id = cast(str, choice["choice_id"])
        if choice_id in registry:
            raise AxisCompositionError("COMPOSITION.DUPLICATE_CHOICE_ID")
        values = _assignment_values(choice)
        if set(values) != owned_set:
            raise AxisCompositionError("COMPOSITION.CHOICE_PATH_COVERAGE")
        fingerprint = canonical_json_bytes(
            [{"path": path, "value": values[path]} for path in owned_paths]
        )
        if fingerprint in fingerprints:
            raise AxisCompositionError("COMPOSITION.DUPLICATE_CHOICE_VALUE")
        fingerprints.add(fingerprint)
        registry[choice_id] = (values, cast(str, choice["rationale"]))

    baseline_choice_id = cast(str, axis["baseline_choice_id"])
    baseline_choice = registry.get(baseline_choice_id)
    if baseline_choice is None:
        raise AxisCompositionError("COMPOSITION.BASELINE_CHOICE_MISSING")
    baseline_values = baseline_choice[0]
    if any(
        not _canonical_equal(
            baseline_values[path], baseline[semantics.analysis_spec_key(path)]
        )
        for path in owned_paths
    ):
        raise AxisCompositionError("COMPOSITION.BASELINE_CHOICE_MISMATCH")
    for choice_id, (values, _rationale) in registry.items():
        if choice_id == baseline_choice_id:
            continue
        if all(_canonical_equal(values[path], baseline_values[path]) for path in owned_paths):
            raise AxisCompositionError("COMPOSITION.DECORATIVE_ALTERNATIVE")
    return owned_paths, registry, baseline_choice_id


def _member_vector(
    member: Mapping[str, Any], ordered_axis_ids: tuple[str, ...]
) -> tuple[tuple[str, str], ...]:
    _validate_config_definition(member, "ComposedExperimentMember", "COMPOSITION.MEMBER_SCHEMA")
    selections = cast(Sequence[Mapping[str, Any]], member["axis_choices"])
    by_axis: dict[str, str] = {}
    for selection in selections:
        axis_id = cast(str, selection["axis_id"])
        if axis_id in by_axis:
            raise AxisCompositionError("COMPOSITION.DUPLICATE_MEMBER_AXIS")
        by_axis[axis_id] = cast(str, selection["choice_id"])
    if set(by_axis) != set(ordered_axis_ids):
        raise AxisCompositionError("COMPOSITION.MEMBER_AXIS_COVERAGE")
    return tuple((axis_id, by_axis[axis_id]) for axis_id in ordered_axis_ids)


def _validate_disjoint_paths(
    ordered_axis_ids: tuple[str, ...], owned_paths: Mapping[str, tuple[str, ...]]
) -> None:
    owner_by_path: dict[str, str] = {}
    for axis_id in ordered_axis_ids:
        for path in owned_paths[axis_id]:
            previous = owner_by_path.setdefault(path, axis_id)
            if previous != axis_id:
                raise AxisCompositionError("COMPOSITION.OVERLAPPING_AXIS_PATH")


def _expected_one_axis_vectors(
    ordered_axis_ids: tuple[str, ...],
    choices: Mapping[str, Mapping[str, tuple[dict[str, Any], str]]],
    baselines: Mapping[str, str],
) -> set[tuple[tuple[str, str], ...]]:
    expected: set[tuple[tuple[str, str], ...]] = set()
    for changed_axis in ordered_axis_ids:
        for choice_id in choices[changed_axis]:
            if choice_id == baselines[changed_axis]:
                continue
            expected.add(
                tuple(
                    (
                        axis_id,
                        choice_id if axis_id == changed_axis else baselines[axis_id],
                    )
                    for axis_id in ordered_axis_ids
                )
            )
    return expected


def _expected_factorial_vectors(
    ordered_axis_ids: tuple[str, ...],
    choices: Mapping[str, Mapping[str, tuple[dict[str, Any], str]]],
) -> set[tuple[tuple[str, str], ...]]:
    levels = [sorted(choices[axis_id], key=_utf8_key) for axis_id in ordered_axis_ids]
    return {
        tuple(zip(ordered_axis_ids, combination, strict=True))
        for combination in itertools.product(*levels)
    }


def _composed_rationales(
    baseline: Mapping[str, Any],
    member_rationale: str,
    selected_choices: Sequence[tuple[tuple[str, ...], dict[str, Any], str, bool]],
) -> list[dict[str, str]]:
    rationales: dict[str, str] = {}
    for row in cast(Sequence[Mapping[str, Any]], baseline["rationales"]):
        path = cast(str, row["choice_path"])
        if path in rationales:
            raise AxisCompositionError("COMPOSITION.DUPLICATE_BASELINE_RATIONALE")
        rationales[path] = cast(str, row["rationale"])
    rationales["/experiment_set_id"] = member_rationale
    for paths, _values, rationale, is_baseline in selected_choices:
        if is_baseline:
            continue
        for path in paths:
            rationales[path] = rationale
    return [
        {"choice_path": path, "rationale": rationales[path]}
        for path in sorted(rationales, key=_utf8_key)
    ]


def _compose_analysis_spec(
    baseline_analysis: Mapping[str, Any],
    experiment_set_id: str,
    mode: str,
    axes: Sequence[Mapping[str, Any]],
    member: Mapping[str, Any],
    semantics: AxisSemantics,
) -> dict[str, Any]:
    if mode not in _COMPOSED_MODES:
        raise AxisCompositionError("COMPOSITION.MODE")
    baseline = _copy_mapping(baseline_analysis)
    axis_by_id: dict[str, Mapping[str, Any]] = {}
    for axis in axes:
        _validate_config_definition(axis, "AxisDefinition", "COMPOSITION.AXIS_SCHEMA")
        axis_id = cast(str, axis["axis_id"])
        if axis_id in axis_by_id:
            raise AxisCompositionError("COMPOSITION.DUPLICATE_AXIS_ID")
        axis_by_id[axis_id] = axis
    if not axis_by_id:
        raise AxisCompositionError("COMPOSITION.NO_AXES")
    ordered_axis_ids = tuple(sorted(axis_by_id, key=_utf8_key))

    owned_paths: dict[str, tuple[str, ...]] = {}
    choices: dict[str, dict[str, tuple[dict[str, Any], str]]] = {}
    baselines: dict[str, str] = {}
    for axis_id in ordered_axis_ids:
        paths, registry, baseline_choice_id = _choice_registry(
            baseline, axis_by_id[axis_id], semantics
        )
        owned_paths[axis_id] = paths
        choices[axis_id] = registry
        baselines[axis_id] = baseline_choice_id
    if mode in {"declared-combinations", "full-factorial"}:
        _validate_disjoint_paths(ordered_axis_ids, owned_paths)

    vector = _member_vector(member, ordered_axis_ids)
    selected: list[tuple[tuple[str, ...], dict[str, Any], str, bool]] = []
    for axis_id, choice_id in vector:
        choice = choices[axis_id].get(choice_id)
        if choice is None:
            raise AxisCompositionError("COMPOSITION.UNKNOWN_CHOICE")
        values, rationale = choice
        selected.append((owned_paths[axis_id], values, rationale, choice_id == baselines[axis_id]))

    spec = copy.deepcopy(baseline)
    for paths, values, _rationale, is_baseline in selected:
        if is_baseline:
            continue
        for path in paths:
            spec[semantics.analysis_spec_key(path)] = copy.deepcopy(values[path])
    _validate_analysis_spec(spec)
    return spec


def compose_analysis_spec(
    baseline_analysis: Mapping[str, Any],
    experiment_set_id: str,
    mode: str,
    axes: Sequence[Mapping[str, Any]],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    """Compose one complete member from exact typed axis assignments.

    The caller's baseline, axes, and member are never mutated. Scientific
    cross-field constraints are intentionally left to the plan compiler so a
    well-formed but invalid combination remains representable.
    """

    return _compose_analysis_spec(
        baseline_analysis,
        experiment_set_id,
        mode,
        axes,
        member,
        _validated_axis_semantics(),
    )


def compose_experiment_set(
    baseline_analysis: Mapping[str, Any], experiment_set: Mapping[str, Any]
) -> tuple[dict[str, Any], ...]:
    """Validate mode coverage and derive every composed member deterministically."""

    raw_mode = experiment_set.get("mode")
    if not isinstance(raw_mode, str) or raw_mode not in _COMPOSED_MODES:
        raise AxisCompositionError("COMPOSITION.MODE")
    mode = raw_mode
    semantics = _validated_axis_semantics()
    raw_experiment_set_id = experiment_set.get("experiment_set_id")
    if not isinstance(raw_experiment_set_id, str):
        raise AxisCompositionError("COMPOSITION.EXPERIMENT_SET_ID")
    raw_axes = experiment_set.get("axes")
    raw_members = experiment_set.get("members")
    if not isinstance(raw_axes, Sequence) or isinstance(raw_axes, (str, bytes, bytearray)):
        raise AxisCompositionError("COMPOSITION.AXIS_SCHEMA")
    if not isinstance(raw_members, Sequence) or isinstance(raw_members, (str, bytes, bytearray)):
        raise AxisCompositionError("COMPOSITION.MEMBER_SCHEMA")
    axes = cast(Sequence[Mapping[str, Any]], raw_axes)
    members = cast(Sequence[Mapping[str, Any]], raw_members)
    if not members:
        raise AxisCompositionError("COMPOSITION.EMPTY_MEMBER_SET")

    for axis in axes:
        _validate_config_definition(axis, "AxisDefinition", "COMPOSITION.AXIS_SCHEMA")
    ordered_axes = sorted(axes, key=lambda row: _utf8_key(cast(str, row["axis_id"])))
    ordered_axis_ids = tuple(cast(str, axis["axis_id"]) for axis in ordered_axes)
    if len(set(ordered_axis_ids)) != len(ordered_axis_ids):
        raise AxisCompositionError("COMPOSITION.DUPLICATE_AXIS_ID")

    choice_registries: dict[str, dict[str, tuple[dict[str, Any], str]]] = {}
    baselines: dict[str, str] = {}
    owned_paths: dict[str, tuple[str, ...]] = {}
    baseline = _copy_mapping(baseline_analysis)
    for axis in ordered_axes:
        axis_id = cast(str, axis["axis_id"])
        paths, registry, baseline_choice_id = _choice_registry(baseline, axis, semantics)
        owned_paths[axis_id] = paths
        choice_registries[axis_id] = registry
        baselines[axis_id] = baseline_choice_id
    if mode in {"declared-combinations", "full-factorial"}:
        _validate_disjoint_paths(ordered_axis_ids, owned_paths)

    member_rows: list[tuple[tuple[tuple[str, str], ...], Mapping[str, Any]]] = []
    seen_member_ids: set[str] = set()
    seen_vectors: set[tuple[tuple[str, str], ...]] = set()
    for member in members:
        member_id = cast(str, member.get("member_id"))
        if member_id in seen_member_ids:
            raise AxisCompositionError("COMPOSITION.DUPLICATE_MEMBER_ID")
        seen_member_ids.add(member_id)
        vector = _member_vector(member, ordered_axis_ids)
        if vector in seen_vectors:
            raise AxisCompositionError("COMPOSITION.DUPLICATE_MEMBER_VECTOR")
        seen_vectors.add(vector)
        member_rows.append((vector, member))

    if mode == "one-axis":
        expected = _expected_one_axis_vectors(ordered_axis_ids, choice_registries, baselines)
        if seen_vectors != expected:
            raise AxisCompositionError("COMPOSITION.ONE_AXIS_COVERAGE")
    elif mode == "full-factorial":
        if len(ordered_axis_ids) < 2:
            raise AxisCompositionError("COMPOSITION.FACTORIAL_AXIS_COUNT")
        expected = _expected_factorial_vectors(ordered_axis_ids, choice_registries)
        if seen_vectors != expected:
            raise AxisCompositionError("COMPOSITION.FACTORIAL_COVERAGE")

    member_rows.sort(
        key=lambda row: (
            tuple((axis.encode("utf-8"), choice.encode("utf-8")) for axis, choice in row[0]),
            cast(str, row[1]["member_id"]).encode("utf-8"),
        )
    )
    result: list[dict[str, Any]] = []
    for vector, member in member_rows:
        spec = _compose_analysis_spec(
            baseline,
            raw_experiment_set_id,
            mode,
            ordered_axes,
            member,
            semantics,
        )
        result.append(
            {
                "member_id": cast(str, member["member_id"]),
                "axis_choices": [
                    {"axis_id": axis_id, "choice_id": choice_id}
                    for axis_id, choice_id in vector
                ],
                "analysis_spec": spec,
                # A deterministic content name only. Execution still requires
                # a genuine PlanningAuthority capability and rebuilt Plan/3.
                "analysis_spec_id": analysis_spec_content_id(spec),
                "rationale": cast(str, member["rationale"]),
            }
        )
    return tuple(result)
