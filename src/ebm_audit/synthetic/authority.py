"""Explicit, offline loading of the evaluator-owned scenario authority.

The evaluator YAML is intentionally injected as exact bytes.  Production code
never guesses a repository-relative path, because that file is not currently a
wheel resource and a stale local copy must not become scientific authority.
"""

from __future__ import annotations

import copy
import hashlib
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import yaml  # type: ignore[import-untyped]

from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol.canonical import canonical_json_bytes

if TYPE_CHECKING:
    from .models import AuthenticatedSourceOwner, ResolvedSyntheticCase

FIELD_IDS: tuple[str, ...] = (
    "participants",
    "events",
    "event_ids",
    "event_directions",
    "baseline",
    "event_center_range",
    "event_centers",
    "transition_width",
    "amplitude",
    "participant_random_effect_sd",
    "participant_random_effect_loading",
    "measurement_noise_family",
    "measurement_noise_sd",
    "equicorrelation",
    "reference_sampling_window",
    "at_risk_sampling_window",
    "reference_sampling_window_low",
    "at_risk_sampling_window_high",
    "latent_sampling_window",
    "reference_fraction",
    "missingness",
    "outliers",
    "covariates",
    "truth_type",
    "adjacent_center_gap",
    "adjacent_center_gap_over_width",
    "affected_events",
    "alternate_inversions",
    "base_boundary_rule_id",
    "base_quantile_cutoff",
    "boundary_quantile_shift",
    "boundary_quantile_shifts",
    "boundary_rule_ids",
    "center_gap_over_width",
    "centered_lognormal_sigma",
    "centered_lognormal_weight",
    "contamination_fraction",
    "covariate_event_effect",
    "covariate_log_odds_coefficient",
    "declared_rules",
    "duplicate_center_gap",
    "duplicate_pair_correlation",
    "equivalence_block_event_ids",
    "equivalence_block_size",
    "event_covariate_effect",
    "event_missing_probabilities",
    "event_missing_probability",
    "group_event_effect",
    "group_log_odds_coefficient",
    "injected_participants",
    "latent_group_distribution",
    "levels",
    "marginal_missing_probability",
    "matched_latent_draws_across_levels",
    "measurement_noise_sd_levels",
    "minority_fraction",
    "offset_noise_sd",
    "opposing_relation_fraction",
    "pair_direction_rule",
    "pair_event_ids",
    "pair_mode",
    "permutations_per_source",
    "reversed_direction_events",
    "source_events",
    "source_participants",
    "source_variant",
    "standardized_group_covariate_difference",
    "student_t_df",
    "subgroup_fraction",
    "target_pair_event_ids",
    "wrong_direction_event_ids",
)

COMPONENT_PATHS: tuple[str, ...] = (
    "parameters",
    "group_assignment",
    "latent_time",
    "covariates",
    "participant_effect",
    "subgroup_assignment",
    "measurement_normal",
    "measurement_scale",
    "measurement_skew",
    "contamination",
    "outliers",
    "missingness",
    "label_permutation",
    "within_group_feature_permutation",
)

GENERATION_STAGE_IDS: tuple[str, ...] = (
    "resolved_parameters",
    "group_assignment",
    "latent_coordinate",
    "latent_source_contamination",
    "transition_signal",
    "covariate_effect",
    "group_effect",
    "participant_effect",
    "base_measurement_noise",
    "centered_skew",
    "exact_duplicate_copy",
    "observed_label_contamination",
    "outliers",
    "missingness",
)
DEPENDENCY_STAGE_IDS: tuple[str, ...] = (
    "participants",
    "events",
    "group_counts",
    "mechanism",
    "event_arrays",
    "covariance_validity",
    "matched_comparator_overrides",
)
_UINT64_HEX = re.compile(r"[0-9a-f]{16}")


class _StrictLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe loader that rejects duplicate mapping keys."""


# PyYAML's default resolver implements YAML 1.1 (where words such as ``yes``
# become booleans).  The authority contract requires JSON-compatible YAML 1.2
# scalars, so install a closed core resolver on this subclass only.
_StrictLoader.yaml_implicit_resolvers = {
    key: [
        (tag, expression)
        for tag, expression in rows
        if tag
        not in {
            "tag:yaml.org,2002:bool",
            "tag:yaml.org,2002:float",
            "tag:yaml.org,2002:int",
            "tag:yaml.org,2002:timestamp",
        }
    ]
    for key, rows in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", flags=re.ASCII),
    list("tf"),
)
_StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    re.compile(r"^(?:0|-?[1-9][0-9]*)$", flags=re.ASCII),
    list("-0123456789"),
)
_StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(
        r"^(?:-?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?"
        r"|-?[0-9]+[eE][-+]?[0-9]+|[-+]?\.(?:inf|Inf|INF|nan|NaN|NAN))$",
        flags=re.ASCII,
    ),
    list("-+0123456789."),
)


def _construct_mapping(
    loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_INVALID",
                "The synthetic scenario authority contains an invalid mapping key.",
            ) from exc
        if duplicate:
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_DUPLICATE_KEY",
                "The synthetic scenario authority contains a duplicate key.",
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _validate_json_model(value: object, *, seen: set[int] | None = None) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if not unicodedata.is_normalized("NFC", value):
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_NON_NFC",
                "The synthetic scenario authority contains a non-NFC string.",
            )
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_NONFINITE",
                "The synthetic scenario authority contains a non-finite number.",
            )
        return
    if seen is None:
        seen = set()
    if isinstance(value, list):
        identity = id(value)
        if identity in seen:
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_CYCLIC",
                "The synthetic scenario authority contains a cyclic value.",
            )
        seen.add(identity)
        try:
            for item in value:
                _validate_json_model(item, seen=seen)
        finally:
            seen.remove(identity)
        return
    if isinstance(value, dict):
        identity = id(value)
        if identity in seen:
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_CYCLIC",
                "The synthetic scenario authority contains a cyclic value.",
            )
        seen.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise InvalidInputError(
                        "GENERATOR.AUTHORITY_INVALID_KEY",
                        "The synthetic scenario authority has a non-string key.",
                    )
                _validate_json_model(key, seen=seen)
                _validate_json_model(item, seen=seen)
        finally:
            seen.remove(identity)
        return
    raise InvalidInputError(
        "GENERATOR.AUTHORITY_NON_JSON",
        "The synthetic scenario authority contains a value outside the JSON data model.",
    )


def _mapping(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InvalidInputError(code, "The synthetic scenario authority is structurally invalid.")
    return value


def _ordered_strings(value: object, code: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise InvalidInputError(code, "A closed synthetic registry is structurally invalid.")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class ScenarioAuthority:
    """Exact injected public development scenario contract."""

    exact_bytes: bytes
    definitions_sha256: str
    _data: dict[str, Any] = field(repr=False)
    _data_sha256: str = field(repr=False)

    @property
    def data(self) -> dict[str, Any]:
        """Return a detached copy so callers cannot mutate the loaded authority."""

        if hashlib.sha256(self.exact_bytes).hexdigest() != self.definitions_sha256:
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_IDENTITY_MISMATCH",
                "The synthetic scenario authority bytes differ from their identity.",
            )
        if hashlib.sha256(canonical_json_bytes(self._data)).hexdigest() != self._data_sha256:
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_IDENTITY_MISMATCH",
                "The parsed synthetic scenario authority differs from its loaded identity.",
            )
        return copy.deepcopy(self._data)

    @property
    def field_registry(self) -> dict[str, Any]:
        return _mapping(self.data["generator_field_registry"], "GENERATOR.FIELD_REGISTRY_INVALID")

    @property
    def scenario_families(self) -> list[dict[str, Any]]:
        value = self.data["scenario_families"]
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise InvalidInputError(
                "GENERATOR.FAMILY_REGISTRY_INVALID",
                "The synthetic scenario family registry is invalid.",
            )
        return value

    def verify_resolved_case(
        self,
        candidate: ResolvedSyntheticCase,
        *,
        source_owner: AuthenticatedSourceOwner | None = None,
    ) -> None:
        """Reconstruct and compare every resolution owner from these exact bytes.

        Keeping the authority as an explicit argument prevents a schema-valid,
        re-signed caller object from becoming scientific authority.  The local
        import avoids an authority/resolver import cycle.
        """

        from .resolver import verify_exact_resolution

        strict_authority = load_scenario_authority(self.exact_bytes)
        if self != strict_authority:
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_OBJECT_MISMATCH",
                "The scenario authority object differs from its exact source bytes.",
            )
        verify_exact_resolution(strict_authority, candidate, source_owner=source_owner)


def scenario_authority_source_reference(
    authority: ScenarioAuthority,
    json_pointer: str,
) -> str:
    """Return one relocation-safe reference into the exact loaded authority."""

    if (
        type(authority) is not ScenarioAuthority
        or type(json_pointer) is not str
        or not json_pointer.startswith("/")
        or "#" in json_pointer
        or hashlib.sha256(authority.exact_bytes).hexdigest() != authority.definitions_sha256
    ):
        raise InvalidInputError(
            "GENERATOR.AUTHORITY_SOURCE_REFERENCE_INVALID",
            "A synthetic authority source reference is invalid.",
        )
    current: object = authority.data
    for encoded_token in json_pointer[1:].split("/"):
        if re.search(r"~(?![01])", encoded_token):
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_SOURCE_REFERENCE_INVALID",
                "A synthetic authority source reference is invalid.",
            )
        token = encoded_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif (
            isinstance(current, list)
            and token.isascii()
            and token.isdigit()
            and (token == "0" or not token.startswith("0"))
            and int(token) < len(current)
        ):
            current = current[int(token)]
        else:
            raise InvalidInputError(
                "GENERATOR.AUTHORITY_SOURCE_REFERENCE_INVALID",
                "A synthetic authority source reference is invalid.",
            )
    return f"scenario-authority:sha256:{authority.definitions_sha256}#{json_pointer}"


def load_scenario_authority(exact_yaml: bytes | bytearray | memoryview) -> ScenarioAuthority:
    """Load exact public authority bytes without a path or network fallback."""

    raw = bytes(exact_yaml)
    if not raw or raw.startswith(b"\xef\xbb\xbf"):
        raise InvalidInputError(
            "GENERATOR.AUTHORITY_INVALID",
            "The synthetic scenario authority bytes are invalid.",
        )
    try:
        text = raw.decode("utf-8", errors="strict")
        loaded = yaml.load(text, Loader=_StrictLoader)
    except InvalidInputError:
        raise
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError) as exc:
        raise InvalidInputError(
            "GENERATOR.AUTHORITY_INVALID",
            "The synthetic scenario authority is not valid strict UTF-8 YAML.",
        ) from exc
    _validate_json_model(loaded)
    data = _mapping(loaded, "GENERATOR.AUTHORITY_INVALID")
    if (
        data.get("data_classification") != "SYNTHETIC_ONLY"
        or data.get("published_order_targeting") is not False
    ):
        raise InvalidInputError(
            "GENERATOR.AUTHORITY_BOUNDARY_INVALID",
            "The synthetic-only authority boundary is absent or invalid.",
        )

    registry = _mapping(data.get("generator_field_registry"), "GENERATOR.FIELD_REGISTRY_INVALID")
    if (
        _ordered_strings(registry.get("ordered_field_ids"), "GENERATOR.FIELD_REGISTRY_INVALID")
        != FIELD_IDS
    ):
        raise InvalidInputError(
            "GENERATOR.FIELD_REGISTRY_DRIFT",
            "The closed 71-field synthetic registry differs from this implementation.",
        )
    fields = _mapping(registry.get("fields"), "GENERATOR.FIELD_REGISTRY_INVALID")
    if tuple(fields) != FIELD_IDS:
        raise InvalidInputError(
            "GENERATOR.FIELD_REGISTRY_DRIFT",
            "The closed synthetic field definitions are missing, extra, or reordered.",
        )
    field_id_set = set(FIELD_IDS)
    common_defaults = _mapping(data.get("common_defaults"), "GENERATOR.COMMON_DEFAULTS_INVALID")
    if not set(common_defaults).issubset(field_id_set):
        raise InvalidInputError(
            "GENERATOR.UNKNOWN_FIELD",
            "The synthetic common defaults contain an unregistered generator field.",
        )
    families = data.get("scenario_families")
    if not isinstance(families, list) or any(not isinstance(row, dict) for row in families):
        raise InvalidInputError(
            "GENERATOR.FAMILY_REGISTRY_INVALID",
            "The synthetic scenario family registry is invalid.",
        )
    development_replicate_counts: list[int] = []
    for family in families:
        replicate_count = family.get("development_replicates")
        if (
            not isinstance(replicate_count, int)
            or isinstance(replicate_count, bool)
            or replicate_count < 1
        ):
            raise InvalidInputError(
                "GENERATOR.FAMILY_REPLICATE_COUNT_INVALID",
                "A synthetic family development replicate count is invalid.",
            )
        development_replicate_counts.append(replicate_count)
        allowed_ranges = family.get("allowed_ranges", {})
        if not isinstance(allowed_ranges, dict) or any(
            not isinstance(key, str) for key in allowed_ranges
        ):
            raise InvalidInputError(
                "GENERATOR.FAMILY_RANGE_INVALID",
                "A synthetic family range map is structurally invalid.",
            )
        if not set(allowed_ranges).issubset(field_id_set):
            raise InvalidInputError(
                "GENERATOR.UNKNOWN_FIELD",
                "A synthetic family range map contains an unregistered generator field.",
            )
        variants = family.get("development_variants", [])
        if not isinstance(variants, list) or any(not isinstance(row, dict) for row in variants):
            raise InvalidInputError(
                "GENERATOR.VARIANT_REGISTRY_INVALID",
                "A synthetic development variant registry is structurally invalid.",
            )
        for variant in variants:
            if not set(variant).issubset(field_id_set | {"id"}):
                raise InvalidInputError(
                    "GENERATOR.UNKNOWN_FIELD",
                    "A synthetic development variant contains an unregistered generator field.",
                )

    seed_policy = _mapping(data.get("seed_policy"), "GENERATOR.SEED_POLICY_INVALID")
    development_roots = seed_policy.get("development_root_seeds")
    expected_root_count = max(development_replicate_counts, default=0)
    if (
        not isinstance(development_roots, list)
        or len(development_roots) != expected_root_count
        or any(
            not isinstance(root, str) or _UINT64_HEX.fullmatch(root) is None
            for root in development_roots
        )
        or len(set(development_roots)) != len(development_roots)
    ):
        raise InvalidInputError(
            "GENERATOR.SEED_POLICY_INVALID",
            (
                "Development roots must be unique UInt64 hex values with exact "
                "coverage of the largest declared family denominator."
            ),
        )
    component_assignment = _mapping(
        seed_policy.get("component_root_assignment"), "GENERATOR.SEED_POLICY_INVALID"
    )
    declared_paths = component_assignment.get("assignment_order")
    if declared_paths != ["OPERATION_SEED", "SHARED_DRAW_SEED", "CASE_SEED"]:
        raise InvalidInputError(
            "GENERATOR.SEED_POLICY_DRIFT",
            "The closed component-root precedence differs from this implementation.",
        )

    stage_registry = _mapping(
        data.get("generation_stage_hash_registry"), "GENERATOR.STAGE_REGISTRY_INVALID"
    )
    stages = stage_registry.get("ordered_stages")
    if not isinstance(stages, list):
        raise InvalidInputError(
            "GENERATOR.STAGE_REGISTRY_INVALID",
            "The closed synthetic stage registry is invalid.",
        )
    stage_ids = tuple(row.get("stage_id") for row in stages if isinstance(row, dict))
    if stage_ids != GENERATION_STAGE_IDS:
        raise InvalidInputError(
            "GENERATOR.STAGE_REGISTRY_DRIFT",
            "The closed 14-stage registry differs from this implementation.",
        )

    dependency_registry = _mapping(
        data.get("dependency_stage_registry"), "GENERATOR.DEPENDENCY_REGISTRY_INVALID"
    )
    dependency_stages = dependency_registry.get("ordered_stages")
    if not isinstance(dependency_stages, list):
        raise InvalidInputError(
            "GENERATOR.DEPENDENCY_REGISTRY_INVALID",
            "The closed synthetic dependency registry is invalid.",
        )
    dependency_stage_ids = tuple(
        row.get("stage") for row in dependency_stages if isinstance(row, dict)
    )
    if dependency_stage_ids != DEPENDENCY_STAGE_IDS:
        raise InvalidInputError(
            "GENERATOR.DEPENDENCY_REGISTRY_DRIFT",
            "The closed seven-stage dependency registry differs from this implementation.",
        )

    return ScenarioAuthority(
        exact_bytes=raw,
        definitions_sha256=hashlib.sha256(raw).hexdigest(),
        _data=copy.deepcopy(data),
        _data_sha256=hashlib.sha256(canonical_json_bytes(data)).hexdigest(),
    )
