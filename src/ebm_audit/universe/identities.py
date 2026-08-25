"""Acyclic Plan/3, PreparationReceipt/2, and UniverseSpec/3 identities."""

from __future__ import annotations

import copy
import hmac
import math
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from typing import Any, NamedTuple, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.protocol import (
    adapter_semantics_digest,
    canonical_json_bytes,
    capabilities_digest,
    requested_outputs_digest,
    settings_digest,
    settings_schema_digest,
    stage_semantics_digest,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.schema import (
    SchemaValidationError,
    load_protocol_registry,
    validate_instance,
    validate_settings,
)

_PUBLIC_SETTING_ID = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_RANDOM_OPERATION_KINDS = frozenset({"bootstrap", "subsample", "null"})
_MAX_PUBLIC_SETTING_ARRAY_ITEMS = 64
_SAMPLER_HISTORY_CAPABILITIES = (
    "order_samples",
    "likelihood_trace",
    "accepted_transition_diagnostics",
    "multiple_chains",
)
_SAMPLER_HISTORY_OUTPUTS = frozenset(_SAMPLER_HISTORY_CAPABILITIES[:-1])


def _is_safe_public_setting_string(value: object) -> bool:
    """Accept bounded display-like values while excluding path/URI syntax."""

    return (
        isinstance(value, str)
        and 1 <= len(value) <= 256
        and unicodedata.is_normalized("NFC", value)
        and not value.startswith((".", "~"))
        and "/" not in value
        and "\\" not in value
        and ":" not in value
        and all(unicodedata.category(character) not in {"Cc", "Cf", "Cs"} for character in value)
    )


class UniverseIdentityError(ValueError):
    """Raised when a planning or universe identity owner is inconsistent."""


@final
class ValidatedPlanningSummary:
    """Opaque validation-issued planning evidence."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ValidatedPlanningSummary:
        raise TypeError("Validated planning summaries come from the validation boundary.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Validated planning summaries cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Validated planning summaries are immutable.")

    @property
    def planning_summary_id(self) -> str:
        return _read_validated_planning_summary(self).planning_summary_id

    @property
    def binding(self) -> dict[str, Any]:
        value = strict_json_loads(_read_validated_planning_summary(self).binding_bytes)
        if type(value) is not dict:
            raise TypeError("Validated planning-summary storage is invalid.")
        return cast(dict[str, Any], value)

    def __copy__(self) -> ValidatedPlanningSummary:
        _read_validated_planning_summary(self)
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> ValidatedPlanningSummary:
        _read_validated_planning_summary(self)
        memo[id(self)] = self
        return self

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Validated planning summaries cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Validated planning summaries cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Validated planning summaries cannot be serialized.")

    def __repr__(self) -> str:
        _read_validated_planning_summary(self)
        return "ValidatedPlanningSummary(<sealed-planning-evidence>)"


@final
class PublicIntentManifest:
    """Opaque pre-data public-settings namespace capability."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PublicIntentManifest:
        raise TypeError("Public intent manifests come from verified public configuration.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Public intent manifests cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Public intent manifests are immutable.")

    @property
    def manifest_digest(self) -> str:
        return _read_public_intent_manifest(self).manifest_digest

    @property
    def preimage(self) -> dict[str, Any]:
        value = strict_json_loads(_read_public_intent_manifest(self).preimage_bytes)
        if type(value) is not dict:
            raise TypeError("Public intent-manifest storage is invalid.")
        return cast(dict[str, Any], value)

    def __copy__(self) -> PublicIntentManifest:
        _read_public_intent_manifest(self)
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> PublicIntentManifest:
        _read_public_intent_manifest(self)
        memo[id(self)] = self
        return self

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Public intent manifests cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Public intent manifests cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Public intent manifests cannot be serialized.")

    def __repr__(self) -> str:
        _read_public_intent_manifest(self)
        return "PublicIntentManifest(<sealed-public-intent>)"


class _PublicIntentManifestState(NamedTuple):
    preimage_bytes: bytes
    manifest_digest: str


class _ValidatedPlanningSummaryState(NamedTuple):
    binding_bytes: bytes
    planning_summary_id: str


def _build_planning_capability_registry(
    capability_type: type[object], state_type: type[object], error_message: str
) -> tuple[Callable[[object, object], None], Callable[[object], object]]:
    registry: OneShotWeakRegistry[object, object]
    issuer: OneShotRegistryIssuer[object, object]
    registry, issuer = create_one_shot_registry()

    def register(capability: object, state: object) -> None:
        if type(capability) is not capability_type or type(state) is not state_type:
            raise RuntimeError(error_message)
        issuer.bind_once(capability, state)

    def read(capability: object) -> object:
        state: object | None = None
        if type(capability) is capability_type:
            try:
                state = registry.get(capability)
            except BaseException:
                state = None
        if type(state) is not state_type:
            raise TypeError(error_message)
        return state

    return register, read


_register_public_intent_manifest, _read_public_intent_manifest_untyped = (
    _build_planning_capability_registry(
        PublicIntentManifest,
        _PublicIntentManifestState,
        "A genuine public intent manifest is required.",
    )
)
_register_validated_planning_summary, _read_validated_planning_summary_untyped = (
    _build_planning_capability_registry(
        ValidatedPlanningSummary,
        _ValidatedPlanningSummaryState,
        "A genuine validated planning summary is required.",
    )
)


def _read_public_intent_manifest(value: object) -> _PublicIntentManifestState:
    return cast(_PublicIntentManifestState, _read_public_intent_manifest_untyped(value))


def _read_validated_planning_summary(value: object) -> _ValidatedPlanningSummaryState:
    return cast(
        _ValidatedPlanningSummaryState,
        _read_validated_planning_summary_untyped(value),
    )


class _PrivateOperationInstance(NamedTuple):
    participant_token: str
    internal_row_index: int
    role: str
    draw_ordinal: int
    occurrence_ordinal: int


class _PrivateMembership(NamedTuple):
    participant_token: str
    internal_row_index: int
    role: str


class _PrivatePreparationReplayState(NamedTuple):
    plan_digest: str
    candidate_ordinal: int
    candidate_id: str
    analysis_spec_id: str
    source_analysis_spec_id: str | None
    operation_seed: str | None
    preparation_rule_registry_digest: str
    source_membership: tuple[_PrivateMembership, ...]
    cohort_membership: tuple[_PrivateMembership, ...]
    pre_operation_membership: tuple[_PrivateMembership, ...]
    operation_instances: tuple[_PrivateOperationInstance, ...]
    operation_unique_membership: tuple[_PrivateMembership, ...]
    training_instances: tuple[_PrivateOperationInstance, ...]
    training_unique_membership: tuple[_PrivateMembership, ...]
    evaluation_membership: tuple[_PrivateMembership, ...]
    removed_membership: tuple[_PrivateMembership, ...]
    public_universe_fields_bytes: bytes
    private_transition_chain_bytes: bytes


def _closed_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(dict(value))


def _schema_validate(instance: object, definition: str) -> None:
    try:
        validate_instance(instance, "analysis-universe.schema.json", definition=definition)
    except SchemaValidationError as exc:
        raise UniverseIdentityError(
            "The analysis-universe value does not satisfy its closed contract."
        ) from exc


def _validate_public_settings_schema(
    schema: Mapping[str, Any], allowed_parameter_ids: Sequence[str]
) -> None:
    """Require a closed privacy-safe schema for manifest-authorized values."""

    def require_safe_string(value: object) -> None:
        if not _is_safe_public_setting_string(value):
            raise UniverseIdentityError(
                "A public string setting is not a closed non-path NFC value."
            )

    def declared_type(node: Mapping[str, Any]) -> tuple[object, bool]:
        node_type = node.get("type")
        if isinstance(node_type, list):
            declared_types = set(node_type)
            if len(node_type) != len(declared_types) or "null" not in declared_types:
                raise UniverseIdentityError("A nullable public setting type is invalid.")
            declared_types.remove("null")
            if len(declared_types) != 1:
                raise UniverseIdentityError("A public setting has ambiguous value kinds.")
            return next(iter(declared_types)), True
        return node_type, node_type == "null"

    def visit(node: Mapping[str, Any], *, root: bool = False) -> None:
        node_type, nullable = declared_type(node)
        if node_type == "object":
            if not root:
                raise UniverseIdentityError("Nested public setting objects are not supported.")
            properties = node.get("properties", {})
            if not isinstance(properties, Mapping):
                raise UniverseIdentityError("A public settings schema is invalid.")
            if set(properties) != set(allowed_parameter_ids):
                raise UniverseIdentityError(
                    "A public settings schema differs from its issued parameter IDs."
                )
            for name, child in properties.items():
                if (
                    not isinstance(name, str)
                    or _PUBLIC_SETTING_ID.fullmatch(name) is None
                    or not isinstance(child, Mapping)
                ):
                    raise UniverseIdentityError(
                        "A public settings schema exposes a non-public property."
                    )
                visit(child)
        elif node_type == "array":
            maximum = node.get("maxItems")
            items = node.get("items")
            if (
                not isinstance(maximum, int)
                or isinstance(maximum, bool)
                or not 0 <= maximum <= _MAX_PUBLIC_SETTING_ARRAY_ITEMS
                or not isinstance(items, Mapping)
            ):
                raise UniverseIdentityError(
                    "A public array setting requires an explicit safe item ceiling."
                )
            item_type, _ = declared_type(items)
            if item_type in {"array", "object"}:
                raise UniverseIdentityError(
                    "Public array settings cannot contain nested arrays or objects."
                )
            visit(items)
        elif node_type == "string":
            literals: list[object] = []
            if "const" in node:
                literals.append(node["const"])
            if "enum" in node:
                enum_values = node["enum"]
                if not isinstance(enum_values, list):
                    raise UniverseIdentityError("A public string enum is invalid.")
                literals.extend(enum_values)
            if not literals:
                raise UniverseIdentityError(
                    "A public string setting requires a closed enum or const."
                )
            for literal in literals:
                if literal is None and nullable:
                    continue
                require_safe_string(literal)
            if "default" in node and node["default"] is not None:
                require_safe_string(node["default"])
        elif node_type not in {"number", "integer", "boolean", "null"}:
            raise UniverseIdentityError("A public settings schema uses an unsupported type.")

    try:
        from ebm_audit.schema import validate_settings_schema

        validate_settings_schema(schema)
    except SchemaValidationError as exc:
        raise UniverseIdentityError("A public settings schema is invalid.") from exc
    visit(schema, root=True)


def _authorized_setting_value_matches_kind(
    value: object, *, value_kind: str, nullable: bool
) -> bool:
    """Check one complete manifest value without accepting nested or path data."""

    if value is None:
        return nullable
    if value_kind == "boolean":
        return isinstance(value, bool)
    if value_kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if value_kind == "number":
        return (
            isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
        )
    if value_kind == "string":
        return _is_safe_public_setting_string(value)
    if value_kind == "array":
        return (
            isinstance(value, list)
            and len(value) <= _MAX_PUBLIC_SETTING_ARRAY_ITEMS
            and all(
                item is None
                or isinstance(item, bool)
                or (
                    isinstance(item, (int, float))
                    and not isinstance(item, bool)
                    and math.isfinite(item)
                )
                or _is_safe_public_setting_string(item)
                for item in value
            )
        )
    return False


def _utf8_key(value: str) -> bytes:
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise UniverseIdentityError("A stable identifier is not valid UTF-8.") from None


def _ordered_unique_strings(values: Sequence[object], *, label: str) -> tuple[str, ...]:
    if not all(
        isinstance(value, str) and value and unicodedata.is_normalized("NFC", value)
        for value in values
    ):
        raise UniverseIdentityError(f"{label} must contain non-empty NFC strings.")
    strings = cast(tuple[str, ...], tuple(values))
    if len(set(strings)) != len(strings):
        raise UniverseIdentityError(f"{label} must be unique.")
    if list(strings) != sorted(strings, key=_utf8_key):
        raise UniverseIdentityError(f"{label} must retain canonical UTF-8 order.")
    return strings


def _unique_strings(values: Sequence[object], *, label: str) -> tuple[str, ...]:
    if not all(
        isinstance(value, str) and value and unicodedata.is_normalized("NFC", value)
        for value in values
    ):
        raise UniverseIdentityError(f"{label} must contain non-empty NFC strings.")
    strings = cast(tuple[str, ...], tuple(values))
    for value in strings:
        _utf8_key(value)
    if len(set(strings)) != len(strings):
        raise UniverseIdentityError(f"{label} must be unique.")
    return strings


def _canonical_row_set(rows: Sequence[Mapping[str, Any]], *, label: str) -> None:
    keys = [canonical_json_bytes(row) for row in rows]
    if len(set(keys)) != len(keys):
        raise UniverseIdentityError(f"{label} must be unique.")
    if keys != sorted(keys):
        raise UniverseIdentityError(f"{label} must retain canonical JCS order.")


def public_intent_manifest_digest(preimage: Mapping[str, Any]) -> str:
    """Identify the one pre-data public intent and settings namespace."""

    value = _closed_copy(preimage)
    _schema_validate(value, "PublicIntentManifestDigestPreimage")
    public_id_keys = [
        f"{entry['namespace']}:{entry['public_id']}" for entry in value["ordered_public_ids"]
    ]
    _ordered_unique_strings(public_id_keys, label="Public intent IDs")
    owner_keys: list[str] = []
    for owner in value["ordered_setting_owners"]:
        owner_keys.append(f"{owner['owner_kind']}:{owner['adapter_id'] or ''}:{owner['owner_id']}")
        _ordered_unique_strings(
            [entry["setting_id"] for entry in owner["ordered_parameters"]],
            label="Public setting IDs",
        )
        for entry in owner["ordered_parameters"]:
            authorized = entry["authorized_values"]
            if list(authorized) != sorted(authorized, key=canonical_json_bytes):
                raise UniverseIdentityError(
                    "Authorized public setting values are not canonically ordered."
                )
            for setting_value in authorized:
                if not _authorized_setting_value_matches_kind(
                    setting_value,
                    value_kind=cast(str, entry["value_kind"]),
                    nullable=cast(bool, entry["nullable"]),
                ):
                    raise UniverseIdentityError(
                        "An authorized public setting value has the wrong kind."
                    )
    _ordered_unique_strings(owner_keys, label="Public settings owners")
    return structured_sha256("ebm-audit/public-intent-manifest/2", value)


def _issue_public_intent_manifest(
    preimage: Mapping[str, Any],
) -> PublicIntentManifest:
    """Issue the non-serializable manifest only from its exact validated owner."""

    value = _closed_copy(preimage)
    digest = public_intent_manifest_digest(value)
    canonical = canonical_json_bytes(value)
    reloaded = strict_json_loads(canonical)
    if type(reloaded) is not dict or not hmac.compare_digest(
        digest, public_intent_manifest_digest(reloaded)
    ):
        raise UniverseIdentityError("Public intent manifest issuance failed.")
    capability = object.__new__(PublicIntentManifest)
    _register_public_intent_manifest(
        capability,
        _PublicIntentManifestState(canonical, digest),
    )
    return capability


def scientific_backend_registry_digest(preimage: Mapping[str, Any]) -> str:
    """Identify every selectable transport-free scientific backend owner."""

    value = _closed_copy(preimage)
    _schema_validate(value, "ScientificBackendRegistryDigestPreimage")
    rows = cast(Sequence[Mapping[str, Any]], value["ordered_backends"])
    keys = [canonical_json_bytes(row) for row in rows]
    if len(set(keys)) != len(keys):
        raise UniverseIdentityError("The scientific backend registry contains a duplicate.")
    if keys != sorted(keys):
        raise UniverseIdentityError(
            "The scientific backend registry must retain canonical JCS order."
        )
    semantic_fields = (
        "adapter_semantics_digest",
        "expected_backend_name",
        "expected_backend_source_digest",
        "capabilities_digest",
        "settings_schema_digest",
        "stage_semantics_digest",
    )
    owners: dict[tuple[str, str], tuple[object, ...]] = {}
    for row in rows:
        owner_key = (cast(str, row["adapter_id"]), cast(str, row["algorithm_id"]))
        semantics = tuple(row[field] for field in semantic_fields)
        prior = owners.setdefault(owner_key, semantics)
        if prior != semantics:
            raise UniverseIdentityError(
                "One typed backend owner has conflicting scientific semantics."
            )
    return structured_sha256("ebm-audit/scientific-backend-registry/1", value)


def analysis_spec_content_id(analysis_spec: Mapping[str, Any]) -> str:
    """Return the deterministic content name of one closed AnalysisSpec/3.

    The input is copied through canonical JSON, schema validated, and hashed
    under the sole AnalysisSpec/3 domain.  The returned string is a name, never
    a capability: planning, validation, fitting, and staging still require
    their separately issued runtime authorities.
    """

    value = _closed_copy(analysis_spec)
    _schema_validate(value, "AnalysisSpec")
    return structured_sha256("ebm-audit/analysis-spec/3", value)


def planning_config_digest(preimage: Mapping[str, Any]) -> str:
    """Identify the closed row-free and seed-free planning configuration."""

    value = _closed_copy(preimage)
    _schema_validate(value, "PlanningConfigDigestPreimage")
    return structured_sha256("ebm-audit/planning-config/2", value)


def validated_planning_summary_id(preimage: Mapping[str, Any]) -> str:
    """Identify the runtime-only owner of one sealed planning summary."""

    value = _closed_copy(preimage)
    _schema_validate(value, "ValidatedPlanningSummaryBindingPreimage")
    _ordered_unique_strings(
        [
            f"{row['adapter_id']}:{row['algorithm_id']}"
            for row in value["selected_algorithm_bindings"]
        ],
        label="Selected algorithm bindings",
    )
    _ordered_unique_strings(
        [
            f"{row['owner_kind']}:{row['owner_id']}"
            for row in value["public_settings_schema_bindings"]
        ],
        label="Public settings schema bindings",
    )
    return structured_sha256("ebm-audit/validated-planning-summary/2", value)


def _issue_validated_planning_summary(
    binding: Mapping[str, Any],
) -> ValidatedPlanningSummary:
    """Issue one runtime-only planning summary from an exact closed binding."""

    value = _closed_copy(binding)
    identity = validated_planning_summary_id(value)
    canonical = canonical_json_bytes(value)
    reloaded = strict_json_loads(canonical)
    if type(reloaded) is not dict or not hmac.compare_digest(
        identity, validated_planning_summary_id(reloaded)
    ):
        raise UniverseIdentityError("Validated planning-summary issuance failed.")
    capability = object.__new__(ValidatedPlanningSummary)
    _register_validated_planning_summary(
        capability,
        _ValidatedPlanningSummaryState(canonical, identity),
    )
    return capability


def preparation_rule_registry_digest(preimage: Mapping[str, Any]) -> str:
    """Identify the complete ordered public preparation-rule registry."""

    value = _closed_copy(preimage)
    _schema_validate(value, "PreparationRuleRegistryDigestPreimage")
    rule_ids = [cast(str, row["rule_id"]) for row in value["ordered_rules"]]
    _ordered_unique_strings(rule_ids, label="Preparation rule IDs")
    operation_order = {
        kind: ordinal
        for ordinal, kind in enumerate(("ordinary", "bootstrap", "subsample", "influence", "null"))
    }
    state_order = {
        state: ordinal
        for ordinal, state in enumerate(
            ("PREPARED", "PREPARATION_INVALID", "PREPARATION_UNSUPPORTED")
        )
    }
    for rule in value["ordered_rules"]:
        if rule["operation_kinds"] != sorted(
            rule["operation_kinds"], key=operation_order.__getitem__
        ) or rule["states"] != sorted(rule["states"], key=state_order.__getitem__):
            raise UniverseIdentityError(
                "Preparation rule operation kinds and states require fixed order."
            )
        _ordered_unique_strings(
            cast(Sequence[object], rule["allowed_reason_codes"]),
            label="Preparation rule reason codes",
        )
    return structured_sha256("ebm-audit/preparation-rule-registry/1", value)


def analysis_plan_digest(preimage: Mapping[str, Any]) -> str:
    """Self-hash one v3 plan preimage; this does not accept it for execution."""

    value = _closed_copy(preimage)
    _schema_validate(value, "AnalysisPlanDigestPreimage")
    return structured_sha256("ebm-audit/analysis-plan/3", value)


def candidate_origin_id(preimage: Mapping[str, Any]) -> str:
    """Derive one compiler-owned candidate-origin identity."""

    value = _closed_copy(preimage)
    _schema_validate(value, "CandidateOriginDigestPreimage")
    return structured_sha256("ebm-audit/candidate-origin/1", value)


def declaration_provenance_digest(preimage: Mapping[str, Any]) -> str:
    """Identify one complete non-execution declaration-provenance owner."""

    value = _closed_copy(preimage)
    _schema_validate(value, "DeclarationProvenanceDigestPreimage")
    return structured_sha256("ebm-audit/analysis-declaration-provenance/1", value)


def preparation_receipt_digest(preimage: Mapping[str, Any]) -> str:
    """Identify one complete ordered PreparationReceipt/2."""

    value = _closed_copy(preimage)
    _schema_validate(value, "PreparationReceiptDigestPreimage")
    return structured_sha256("ebm-audit/preparation-receipt/2", value)


def universe_id(preimage: Mapping[str, Any]) -> str:
    """Identify one post-plan UniverseSpec/3 and its seeded chain plan."""

    value = _closed_copy(preimage)
    _schema_validate(value, "UniverseIdentityPreimage")
    return structured_sha256("ebm-audit/analysis-universe/3", value)


def chain_execution_id(universe_identity: str, chain_id: str, seed: str) -> str:
    """Identify one declared chain inside one immutable UniverseSpec/3."""

    preimage = {
        "universe_id": universe_identity,
        "chain_id": chain_id,
        "seed": seed,
    }
    _schema_validate(preimage, "ChainExecutionIdPreimage")
    return structured_sha256("ebm-audit/chain-execution/3", preimage)


def attempt_id(chain_identity: str, attempt_ordinal: int) -> str:
    """Identify one immutable transport attempt for a declared v3 chain."""

    preimage = {
        "chain_execution_id": chain_identity,
        "attempt_ordinal": attempt_ordinal,
    }
    _schema_validate(preimage, "AttemptIdPreimage")
    return structured_sha256("ebm-audit/chain-attempt/3", preimage)


def chain_cache_key(preimage: Mapping[str, Any]) -> str:
    """Identify one reusable, fully bound worker attempt response."""

    value = _closed_copy(preimage)
    _schema_validate(value, "ChainCachePreimage")
    expected_attempt = attempt_id(str(value["chain_execution_id"]), int(value["attempt_ordinal"]))
    if value["attempt_id"] != expected_attempt:
        raise UniverseIdentityError(
            "The chain cache attempt identity is detached from its chain and ordinal."
        )
    return structured_sha256("ebm-audit/chain-cache/4", value)


def universe_cache_key(preimage: Mapping[str, Any]) -> str:
    """Identify one reusable core-final multi-chain result."""

    value = _closed_copy(preimage)
    _schema_validate(value, "UniverseCachePreimage")
    return structured_sha256("ebm-audit/universe-cache/3", value)


def _derive_product_seed(master_seed: str, preimage: Mapping[str, object]) -> str:
    from ebm_audit.config.models import ConfigContractError
    from ebm_audit.config.seeds import derive_product_seed

    try:
        return derive_product_seed(master_seed, preimage=preimage)
    except ConfigContractError as exc:
        raise UniverseIdentityError("The product seed owner or UInt64 result is invalid.") from exc


def _operation_seed_preimage(spec: Mapping[str, Any]) -> dict[str, object] | None:
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    kind = cast(str, operation["kind"])
    if kind not in _RANDOM_OPERATION_KINDS:
        return None
    shared = {
        "seed_preimage_schema_version": "ebm-audit-product-seed-preimage/2.0",
        "seed_derivation_version": "hmac-sha256-u64be-v2",
        "seed_use": "operation",
        "operation_kind": kind,
        "source_analysis_spec_id": operation["source_analysis_spec_id"],
        "source_variant_id": operation["source_variant_id"],
        "derived_source_variant_id": operation["derived_source_variant_id"],
        "replicate_ordinal": operation["replicate_ordinal"],
    }
    if kind == "bootstrap":
        parameters = {
            "sampling_method_id": operation["sampling_method_id"],
            "sampling_design": operation["sampling_design"],
            "strata_group_spec_ids": operation["strata_group_spec_ids"],
            "refit_preprocessing": operation["refit_preprocessing"],
            "fixed_evaluation_cohort_policy": operation["fixed_evaluation_cohort_policy"],
        }
    elif kind == "subsample":
        parameters = {
            "sampling_method_id": operation["sampling_method_id"],
            "sampling_design": operation["sampling_design"],
            "retained_fraction": operation["retained_fraction"],
            "retained_count_rounding_rule": operation["retained_count_rounding_rule"],
            "strata_group_spec_ids": operation["strata_group_spec_ids"],
            "refit_preprocessing": operation["refit_preprocessing"],
            "fixed_evaluation_cohort_policy": operation["fixed_evaluation_cohort_policy"],
        }
    else:
        parameters = {
            "null_family_id": operation["null_family_id"],
            "null_method_id": operation["null_method_id"],
            "transformation": operation["transformation"],
            "within_group_spec_id": operation["within_group_spec_id"],
            "refit_preprocessing": operation["refit_preprocessing"],
            "preserves_group_conditional_event_marginals": operation[
                "preserves_group_conditional_event_marginals"
            ],
        }
    return {**shared, "operation_parameters": copy.deepcopy(parameters)}


def _expected_operation_seed(spec: Mapping[str, Any], master_seed: str) -> str | None:
    preimage = _operation_seed_preimage(spec)
    if preimage is None:
        return None
    return _derive_product_seed(master_seed, preimage)


def _expected_chain_seed(
    spec: Mapping[str, Any], analysis_identity: str, chain_ordinal: int, master_seed: str
) -> str:
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    preimage: dict[str, object] = {
        "seed_preimage_schema_version": "ebm-audit-product-seed-preimage/2.0",
        "seed_derivation_version": "hmac-sha256-u64be-v2",
        "seed_use": "universe-chain",
        "operation_kind": operation["kind"],
        "analysis_spec_id": analysis_identity,
        "chain_ordinal": chain_ordinal,
    }
    return _derive_product_seed(master_seed, preimage)


def _verify_plan_seed_collisions(plan: Mapping[str, Any], master_seed: str) -> None:
    """Reject any distinct ProductSeedPreimages colliding within one plan execution."""

    from ebm_audit.config.models import ConfigContractError
    from ebm_audit.config.seeds import validate_product_seed_assignments

    preimages: list[Mapping[str, object]] = []
    for candidate in cast(Sequence[Mapping[str, Any]], plan["candidates"]):
        if candidate["planning_outcome"] != "PLANNED":
            continue
        spec = cast(Mapping[str, Any], candidate["analysis_spec"])
        operation_preimage = _operation_seed_preimage(spec)
        if operation_preimage is not None:
            preimages.append(operation_preimage)
        operation = cast(Mapping[str, Any], spec["operation_intent"])
        for slot in cast(Sequence[Mapping[str, Any]], candidate["chain_slots"]):
            preimages.append(
                {
                    "seed_preimage_schema_version": "ebm-audit-product-seed-preimage/2.0",
                    "seed_derivation_version": "hmac-sha256-u64be-v2",
                    "seed_use": "universe-chain",
                    "operation_kind": operation["kind"],
                    "analysis_spec_id": candidate["analysis_spec_id"],
                    "chain_ordinal": slot["chain_ordinal"],
                }
            )
    try:
        validate_product_seed_assignments(master_seed, preimages)
    except ConfigContractError as exc:
        raise UniverseIdentityError(
            "Distinct product seed owners collide in UInt64 space."
        ) from exc


def _canonical_reason_rows(rows: Sequence[Mapping[str, Any]], *, label: str) -> None:
    keys = [(cast(str, row["reason_code"]), cast(str, row["rule_id"])) for row in rows]
    if len(set(keys)) != len(keys):
        raise UniverseIdentityError(f"{label} must be unique.")
    if keys != sorted(keys, key=lambda row: (_utf8_key(row[0]), _utf8_key(row[1]))):
        raise UniverseIdentityError(f"{label} must retain canonical order.")


def _canonical_origin(
    origin: Mapping[str, Any],
) -> bytes:
    preimage = {
        key: copy.deepcopy(origin[key])
        for key in (
            "analysis_declaration_id",
            "experiment_set_id",
            "experiment_mode",
            "declaration_ordinal",
            "axis_choices",
            "source_declaration_digest",
        )
    }
    if not hmac.compare_digest(cast(str, origin["origin_id"]), candidate_origin_id(preimage)):
        raise UniverseIdentityError("A candidate origin identity is not compiler-derived.")
    choices = cast(Sequence[Mapping[str, Any]], origin["axis_choices"])
    if origin["experiment_mode"] == "one-axis" and len(choices) != 1:
        raise UniverseIdentityError(
            "A one-axis candidate origin requires exactly one compiler-owned axis choice."
        )
    choice_keys = tuple((cast(str, row["axis_id"]), cast(str, row["choice_id"])) for row in choices)
    axis_ids = [axis_id for axis_id, _choice_id in choice_keys]
    if len(set(axis_ids)) != len(axis_ids) or list(choice_keys) != sorted(
        choice_keys, key=lambda row: (_utf8_key(row[0]), _utf8_key(row[1]))
    ):
        raise UniverseIdentityError(
            "Candidate axis choices require unique axes in canonical order."
        )
    return _utf8_key(cast(str, origin["origin_id"]))


def _candidate_order_key(candidate: Mapping[str, Any]) -> tuple[object, ...]:
    origin_key = _canonical_origin(cast(Mapping[str, Any], candidate["primary_origin"]))
    return (origin_key, _utf8_key(cast(str, candidate["candidate_id"])))


def _plan_preimage(plan: Mapping[str, Any]) -> dict[str, Any]:
    value = _closed_copy(plan)
    value.pop("plan_digest", None)
    return value


def _count_partition(
    candidates: Sequence[Mapping[str, Any]],
    association_ids: Sequence[Sequence[str]],
) -> list[dict[str, Any]]:
    all_ids = sorted(
        {partition_id for ids in association_ids for partition_id in ids},
        key=_utf8_key,
    )
    rows: list[dict[str, Any]] = []
    for partition_id in all_ids:
        selected = [
            candidate
            for candidate, ids in zip(candidates, association_ids, strict=True)
            if partition_id in ids
        ]
        origin_count = sum(ids.count(partition_id) for ids in association_ids)
        rows.append(
            {
                "id": partition_id,
                "origin_count": origin_count,
                "additional_origin_count": origin_count - len(selected),
                "candidate_count": len(selected),
                "planned_candidate_count": sum(
                    candidate["planning_outcome"] == "PLANNED" for candidate in selected
                ),
                "plan_ineligible_candidate_count": sum(
                    candidate["planning_outcome"] == "PLAN_INELIGIBLE" for candidate in selected
                ),
                "seedless_chain_slot_count": sum(
                    len(candidate["chain_slots"]) for candidate in selected
                ),
                "planned_fit_ceiling": sum(
                    cast(int, candidate["planned_fit_ceiling"]) for candidate in selected
                ),
            }
        )
    return rows


def _expected_plan_partitions(
    candidates: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    origins = [
        [candidate["primary_origin"], *candidate["duplicate_origins"]] for candidate in candidates
    ]
    experiment_associations = [
        [cast(str, origin["experiment_set_id"]) for origin in candidate_origins]
        for candidate_origins in origins
    ]
    axis_associations = [
        [
            cast(str, row["axis_id"])
            for origin in candidate_origins
            for row in origin["axis_choices"]
        ]
        for candidate_origins in origins
    ]
    operation_associations = [
        [cast(str, candidate["analysis_spec"]["operation_intent"]["kind"])] * len(candidate_origins)
        for candidate, candidate_origins in zip(candidates, origins, strict=True)
    ]
    return (
        _count_partition(candidates, experiment_associations),
        _count_partition(candidates, axis_associations),
        _count_partition(candidates, operation_associations),
    )


def _receipt_preimage(receipt: Mapping[str, Any]) -> dict[str, Any]:
    value = _closed_copy(receipt)
    value.pop("receipt_digest", None)
    return value


def _candidate_origins(candidate: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    return (
        cast(Mapping[str, Any], candidate["primary_origin"]),
        *cast(Sequence[Mapping[str, Any]], candidate["duplicate_origins"]),
    )


def _provenance_preimage(record: Mapping[str, Any]) -> dict[str, Any]:
    value = _closed_copy(record)
    value.pop("source_declaration_digest", None)
    return value


def _validate_provenance_for_spec(provenance: Mapping[str, Any], spec: Mapping[str, Any]) -> None:
    event_ids = [cast(str, row["event_id"]) for row in spec["event_set"]]
    provenance_event_ids = [
        cast(str, row["event_id"]) for row in provenance["event_inclusion_reasons"]
    ]
    if provenance_event_ids != event_ids:
        raise UniverseIdentityError("Declaration provenance event coverage is detached.")
    transformations = cast(Sequence[Mapping[str, Any]], provenance["preprocessing_declarations"])
    if [row["transformation_ordinal"] for row in transformations] != list(
        range(len(spec["preprocessing"]))
    ):
        raise UniverseIdentityError("Declaration provenance transform coverage is detached.")
    _unique_strings(
        cast(Sequence[object], [row["operation_id"] for row in transformations]),
        label="Declaration preprocessing operation IDs",
    )
    operation = cast(Mapping[str, Any], provenance["operation_declaration"])
    if operation["kind"] != spec["operation_intent"]["kind"]:
        raise UniverseIdentityError("Declaration provenance operation kind is detached.")
    rationales = cast(Sequence[Mapping[str, Any]], provenance["rationales"])
    rationale_keys = [f"{row['choice_target']}:{row['choice_id']}" for row in rationales]
    _ordered_unique_strings(rationale_keys, label="Declaration rationale choices")
    for row in rationales:
        _ordered_unique_strings(
            cast(Sequence[object], row["source_ids"]),
            label="Declaration rationale source IDs",
        )


def _verify_declaration_provenance_registry(
    candidates: Sequence[Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
) -> None:
    digests = [cast(str, row["source_declaration_digest"]) for row in records]
    _ordered_unique_strings(digests, label="Declaration provenance digests")
    by_digest: dict[str, Mapping[str, Any]] = {}
    for row in records:
        expected = declaration_provenance_digest(_provenance_preimage(row))
        supplied = cast(str, row["source_declaration_digest"])
        if not hmac.compare_digest(supplied, expected):
            raise UniverseIdentityError("A declaration provenance digest is detached.")
        by_digest[supplied] = row
    claimed = {
        cast(str, origin["source_declaration_digest"])
        for candidate in candidates
        for origin in _candidate_origins(candidate)
    }
    if set(by_digest) != claimed:
        raise UniverseIdentityError("Declaration provenance registry coverage is missing or extra.")
    for candidate in candidates:
        spec = cast(Mapping[str, Any], candidate["analysis_spec"])
        for origin in _candidate_origins(candidate):
            provenance = by_digest[cast(str, origin["source_declaration_digest"])]
            if provenance["analysis_declaration_id"] != origin["analysis_declaration_id"]:
                raise UniverseIdentityError("Declaration provenance resolves to the wrong origin.")
            _validate_provenance_for_spec(provenance, spec)


def _expected_declaration_resolutions(
    candidates: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows = [
        {
            "analysis_declaration_id": origin["analysis_declaration_id"],
            "source_declaration_digest": origin["source_declaration_digest"],
            "origin_id": origin["origin_id"],
            "analysis_spec_id": candidate["analysis_spec_id"],
        }
        for candidate in candidates
        for origin in _candidate_origins(candidate)
    ]
    origin_ids = [cast(str, row["origin_id"]) for row in rows]
    if len(set(origin_ids)) != len(origin_ids):
        raise UniverseIdentityError("Declaration resolutions require unique origin IDs.")
    return sorted(rows, key=lambda row: _utf8_key(cast(str, row["origin_id"])))


def _comparison_semantics(
    subject: Mapping[str, Any], comparator: Mapping[str, Any]
) -> dict[str, str]:
    subject_events = [cast(str, row["event_id"]) for row in subject["event_set"]]
    comparator_events = [cast(str, row["event_id"]) for row in comparator["event_set"]]
    identical_set = set(subject_events) == set(comparator_events)
    native_comparable = (
        subject_events == comparator_events
        and subject["event_directions"] == comparator["event_directions"]
        and subject["backend"]["stage_semantics_digest"]
        == comparator["backend"]["stage_semantics_digest"]
    )
    return {
        "order_event_alignment": ("identical-event-set" if identical_set else "common-event-only"),
        "native_stage_comparability": ("comparable" if native_comparable else "non-equivalent"),
    }


def _expected_origin_comparison_edges(
    candidates: Sequence[Mapping[str, Any]], baseline_id: str
) -> list[dict[str, Any]]:
    specs = {
        cast(str, candidate["analysis_spec_id"]): cast(
            Mapping[str, Any], candidate["analysis_spec"]
        )
        for candidate in candidates
    }
    baseline = specs.get(baseline_id)
    if baseline is None:
        raise UniverseIdentityError("The plan baseline AnalysisSpec is missing.")
    rows: list[dict[str, Any]] = []
    baseline_origin_count = 0
    for candidate in candidates:
        subject_id = cast(str, candidate["analysis_spec_id"])
        subject = cast(Mapping[str, Any], candidate["analysis_spec"])
        operation = cast(Mapping[str, Any], subject["operation_intent"])
        for origin in _candidate_origins(candidate):
            mode = cast(str, origin["experiment_mode"])
            if mode == "baseline":
                baseline_origin_count += 1
                if subject_id != baseline_id or operation["kind"] != "ordinary":
                    raise UniverseIdentityError(
                        "The baseline origin is detached from the plan root."
                    )
                comparator_id = subject_id
                rule_id = "baseline-origin-self/1"
            elif operation["kind"] == "ordinary":
                comparator_id = baseline_id
                rule_id = "ordinary-origin-to-plan-baseline/1"
            else:
                comparator_id = cast(str, operation["source_analysis_spec_id"])
                rule_id = "derived-origin-to-source/1"
            comparator = specs.get(comparator_id)
            if comparator is None:
                raise UniverseIdentityError("An origin comparison reference is missing.")
            rows.append(
                {
                    "origin_id": origin["origin_id"],
                    "subject_analysis_spec_id": subject_id,
                    "comparator_analysis_spec_id": comparator_id,
                    "derivation_rule_id": rule_id,
                    "semantics": _comparison_semantics(subject, comparator),
                }
            )
    if baseline_origin_count != 1:
        raise UniverseIdentityError("A plan requires exactly one baseline origin.")
    return sorted(rows, key=lambda row: _utf8_key(cast(str, row["origin_id"])))


def _is_authenticated_non_sampling_spec(
    spec: Mapping[str, Any], supported_algorithms: Sequence[Mapping[str, Any]]
) -> bool:
    if spec.get("mcmc") is not None:
        return False
    try:
        backend = cast(Mapping[str, Any], spec["backend"])
        matching = []
        for algorithm in supported_algorithms:
            semantics = algorithm.get("adapter_semantics")
            if (
                isinstance(semantics, Mapping)
                and semantics.get("adapter_id") == backend["adapter_id"]
                and semantics.get("algorithm_id") == backend["algorithm_id"]
                and algorithm.get("adapter_semantics_digest")
                == backend["adapter_semantics_digest"]
            ):
                matching.append(algorithm)
        if len(matching) != 1:
            return False
        algorithm = matching[0]
        semantics = cast(Mapping[str, Any], algorithm["adapter_semantics"])
        projection = cast(Mapping[str, Any], semantics["mcmc_projection"])
        capabilities = cast(Mapping[str, Any], algorithm["capabilities"])
        requested_outputs = cast(Sequence[str], backend["requested_outputs"])
        return (
            adapter_semantics_digest(semantics) == algorithm["adapter_semantics_digest"]
            and capabilities_digest(capabilities) == algorithm["capabilities_digest"]
            and algorithm["capabilities_digest"] == backend["capabilities_digest"]
            and set(projection)
            == {
                "projection_schema_version",
                "availability",
                "reason_code",
            }
            and projection["projection_schema_version"]
            == "ebm-audit-adapter-mcmc-projection/1.0"
            and projection["availability"] == "UNAVAILABLE"
            and projection["reason_code"] == "NON_CHAIN_ALGORITHM"
            and all(
                capabilities.get(capability) is False
                for capability in _SAMPLER_HISTORY_CAPABILITIES
            )
            and not _SAMPLER_HISTORY_OUTPUTS.intersection(requested_outputs)
        )
    except (KeyError, TypeError, ValueError):
        return False


def _validate_plan_candidate(
    candidate: Mapping[str, Any], *, authenticated_non_sampling: bool = False
) -> None:
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    identity = analysis_spec_content_id(spec)
    if not hmac.compare_digest(cast(str, candidate["analysis_spec_id"]), identity):
        raise UniverseIdentityError("A plan candidate has a detached analysis_spec_id.")
    if not hmac.compare_digest(cast(str, candidate["candidate_id"]), identity):
        raise UniverseIdentityError("candidate_id must equal analysis_spec_id.")

    origin = cast(Mapping[str, Any], candidate["primary_origin"])
    _canonical_origin(origin)
    duplicate_origins = cast(Sequence[Mapping[str, Any]], candidate["duplicate_origins"])
    duplicate_keys = [_canonical_origin(origin_row) for origin_row in duplicate_origins]
    if len(set(duplicate_keys)) != len(duplicate_keys) or duplicate_keys != sorted(duplicate_keys):
        raise UniverseIdentityError(
            "Duplicate candidate origins must retain canonical unique order."
        )
    primary_key = _canonical_origin(origin)
    if duplicate_keys and primary_key >= duplicate_keys[0]:
        raise UniverseIdentityError("The primary candidate origin is not the canonical minimum.")

    reasons = cast(Sequence[Mapping[str, Any]], candidate["planning_reasons"])
    _canonical_reason_rows(reasons, label="Static planning reasons")
    event_rows = cast(Sequence[Mapping[str, Any]], spec["event_set"])
    event_ids = [cast(str, row["event_id"]) for row in event_rows]
    if len(set(event_ids)) != len(event_ids):
        raise UniverseIdentityError("AnalysisSpec event IDs must be unique.")
    directions = cast(Mapping[str, Any], spec["event_directions"])
    expected_reasons: list[dict[str, str]] = []
    if len(event_ids) < 2:
        expected_reasons.append(
            {
                "reason_code": "PLAN.EVENT_COUNT_BELOW_TWO",
                "rule_id": "planning.event-count/1",
            }
        )
    if set(event_ids) != set(directions) or any(
        directions.get(event_id) not in {"higher", "lower"} for event_id in event_ids
    ):
        expected_reasons.append(
            {
                "reason_code": "PLAN.EVENT_DIRECTIONS_UNRESOLVED",
                "rule_id": "planning.event-directions/1",
            }
        )
    mcmc = spec["mcmc"]
    if mcmc is None and not authenticated_non_sampling:
        expected_reasons.append(
            {
                "reason_code": "PLAN.MCMC_UNAVAILABLE_FOR_MVP",
                "rule_id": "planning.mcmc-availability/1",
            }
        )
    expected_reasons.sort(
        key=lambda row: (_utf8_key(row["reason_code"]), _utf8_key(row["rule_id"]))
    )
    if list(reasons) != expected_reasons:
        raise UniverseIdentityError("Static planning reasons are not independently derived.")
    slots = cast(Sequence[Mapping[str, Any]], candidate["chain_slots"])
    outcome = candidate["planning_outcome"]
    expected_uncertainty_status = "UNAVAILABLE_NON_CHAIN_ALGORITHM" if mcmc is None else "AVAILABLE"
    if candidate["within_fit_chain_uncertainty_status"] != expected_uncertainty_status:
        raise UniverseIdentityError(
            "Within-fit chain uncertainty status differs from algorithm semantics."
        )
    if outcome == "PLANNED":
        if reasons:
            raise UniverseIdentityError("A planned candidate cannot carry an ineligibility reason.")
        if mcmc is None:
            if not authenticated_non_sampling:
                raise UniverseIdentityError(
                    "A planned non-sampling candidate requires authenticated evidence."
                )
            expected_slot_count = 1
        else:
            expected_slot_count = mcmc["chain_count"]
        if len(slots) != expected_slot_count:
            raise UniverseIdentityError("A planned candidate must own every declared chain slot.")
        if candidate["planned_fit_ceiling"] != len(slots):
            raise UniverseIdentityError("A candidate fit ceiling must equal its seedless slots.")
    elif slots or candidate["planned_fit_ceiling"] != 0 or not reasons:
        raise UniverseIdentityError(
            "A plan-ineligible candidate must be closed without chain slots."
        )

    ordinals = [slot["chain_ordinal"] for slot in slots]
    if ordinals != list(range(len(slots))):
        raise UniverseIdentityError("Chain-slot ordinals must be contiguous and ordered.")
    chain_ids = [slot["chain_id"] for slot in slots]
    _unique_strings(chain_ids, label="Chain-slot IDs")
    if chain_ids != [f"chain-{ordinal:04d}" for ordinal in ordinals]:
        raise UniverseIdentityError("Chain-slot IDs are not core-derived from their ordinals.")


def _verify_expansion_cardinalities(
    candidates: Sequence[Mapping[str, Any]],
    summary: Mapping[str, Any],
    declarations: Mapping[str, Any],
) -> None:
    leave_one_out: dict[tuple[str, str, str, str, str], list[int]] = {}
    named_groups: dict[tuple[str, str, str, str, str], list[tuple[int, str]]] = {}
    replicated: dict[tuple[str, str, str, str, str, str, str | None], list[int]] = {}
    for candidate in candidates:
        spec = cast(Mapping[str, Any], candidate["analysis_spec"])
        operation = cast(Mapping[str, Any], spec["operation_intent"])
        kind = cast(str, operation["kind"])
        experiment_set_ids = {
            cast(str, origin["experiment_set_id"])
            for origin in (candidate["primary_origin"], *candidate["duplicate_origins"])
        }
        for experiment_set_id in experiment_set_ids:
            if kind == "influence":
                influence_key = (
                    experiment_set_id,
                    cast(str, operation["source_analysis_spec_id"]),
                    cast(str, operation["source_variant_id"]),
                    cast(str, operation["derived_source_variant_id"]),
                    cast(str, operation["removal_kind"]),
                )
                if operation["removal_kind"] == "named-group-removal":
                    named_groups.setdefault(influence_key, []).append(
                        (
                            cast(int, operation["removal_slot_ordinal"]),
                            cast(str, operation["named_group_spec_id"]),
                        )
                    )
                else:
                    leave_one_out.setdefault(influence_key, []).append(
                        cast(int, operation["removal_slot_ordinal"])
                    )
            elif kind in _RANDOM_OPERATION_KINDS:
                method_id = cast(
                    str,
                    operation["null_method_id" if kind == "null" else "sampling_method_id"],
                )
                replicated_key = (
                    experiment_set_id,
                    cast(str, operation["source_analysis_spec_id"]),
                    cast(str, operation["source_variant_id"]),
                    cast(str, operation["derived_source_variant_id"]),
                    kind,
                    method_id,
                    cast(str, operation["null_family_id"]) if kind == "null" else None,
                )
                replicated.setdefault(replicated_key, []).append(
                    cast(int, operation["replicate_ordinal"])
                )

    influence_rows = cast(Sequence[Mapping[str, Any]], summary["influence_expansion_cardinalities"])
    expected_influence = {
        (
            cast(str, row["experiment_set_id"]),
            cast(str, row["source_analysis_spec_id"]),
            cast(str, row["source_variant_id"]),
            cast(str, row["derived_source_variant_id"]),
            cast(str, row["removal_kind"]),
        ): cast(int, row["eligible_target_count"])
        for row in influence_rows
    }
    if len(expected_influence) != len(influence_rows):
        raise UniverseIdentityError("Influence cardinality scopes must be unique.")
    if list(expected_influence) != sorted(
        expected_influence, key=lambda row: tuple(map(_utf8_key, row))
    ):
        raise UniverseIdentityError("Influence cardinality scopes are not canonically ordered.")
    if not set(leave_one_out).issubset(expected_influence):
        raise UniverseIdentityError("Influence cardinality coverage is incomplete.")
    for influence_key in expected_influence:
        ordinals = leave_one_out.get(influence_key, [])
        if sorted(ordinals) != list(range(expected_influence[influence_key])):
            raise UniverseIdentityError("Influence removal ordinals are not exact and contiguous.")

    replicated_rows = cast(Sequence[Mapping[str, Any]], declarations["replicated_operations"])
    expected_replicated = {
        (
            cast(str, row["experiment_set_id"]),
            cast(str, row["source_analysis_spec_id"]),
            cast(str, row["source_variant_id"]),
            cast(str, row["derived_source_variant_id"]),
            cast(str, row["operation_kind"]),
            cast(str, row["method_id"]),
            cast(str, row["null_family_id"]) if row["null_family_id"] is not None else None,
        ): cast(int, row["replicate_count"])
        for row in replicated_rows
    }
    if len(expected_replicated) != len(replicated_rows):
        raise UniverseIdentityError("Replicated-operation cardinality scopes must be unique.")
    if list(expected_replicated) != sorted(
        expected_replicated,
        key=lambda row: tuple(_utf8_key(value) if value is not None else b"" for value in row),
    ):
        raise UniverseIdentityError(
            "Replicated-operation cardinality scopes are not canonically ordered."
        )
    if not set(replicated).issubset(expected_replicated):
        raise UniverseIdentityError("Replicated-operation cardinality coverage is incomplete.")
    for replicated_key in expected_replicated:
        ordinals = replicated.get(replicated_key, [])
        if sorted(ordinals) != list(range(expected_replicated[replicated_key])):
            raise UniverseIdentityError("Replicate ordinals are not exact and contiguous.")

    named_rows = cast(Sequence[Mapping[str, Any]], declarations["named_group_removals"])
    expected_named = {
        (
            cast(str, row["experiment_set_id"]),
            cast(str, row["source_analysis_spec_id"]),
            cast(str, row["source_variant_id"]),
            cast(str, row["derived_source_variant_id"]),
            cast(str, row["removal_kind"]),
        ): cast(Sequence[str], row["ordered_named_group_spec_ids"])
        for row in named_rows
    }
    if len(expected_named) != len(named_rows):
        raise UniverseIdentityError("Named-group removal scopes must be unique.")
    if list(expected_named) != sorted(expected_named, key=lambda row: tuple(map(_utf8_key, row))):
        raise UniverseIdentityError("Named-group removal scopes are not canonically ordered.")
    if not set(named_groups).issubset(expected_named):
        raise UniverseIdentityError("Named-group removal declaration coverage is incomplete.")
    for named_key, declared_groups in expected_named.items():
        _ordered_unique_strings(
            cast(Sequence[object], declared_groups),
            label="Named-group removal IDs",
        )
        actual_rows = sorted(named_groups.get(named_key, []))
        if [ordinal for ordinal, _group_id in actual_rows] != list(range(len(declared_groups))) or [
            group_id for _ordinal, group_id in actual_rows
        ] != list(declared_groups):
            raise UniverseIdentityError(
                "Named-group removals do not exactly cover their declared groups."
            )


def _verify_analysis_plan_contract(
    plan: Mapping[str, Any],
    planning_config_preimage: Mapping[str, Any],
    expected_summary: Mapping[str, Any],
    supported_algorithms: Sequence[Mapping[str, Any]],
    public_settings_schemas: Mapping[tuple[str, str], Mapping[str, Any]],
    public_intent_manifest: Mapping[str, Any],
) -> None:
    """Unactivated post-rebuild invariant checker, not an acceptance boundary."""

    value = _closed_copy(plan)
    _schema_validate(value, "AnalysisPlan")
    expected_config_digest = planning_config_digest(planning_config_preimage)
    if not hmac.compare_digest(value["planning_config_digest"], expected_config_digest):
        raise UniverseIdentityError("The plan does not bind its planning configuration owner.")
    if value["planning_dataset_summary"] != expected_summary:
        raise UniverseIdentityError(
            "The plan summary differs from its validation-issued capability."
        )
    expected_plan_digest = analysis_plan_digest(_plan_preimage(value))
    if not hmac.compare_digest(value["plan_digest"], expected_plan_digest):
        raise UniverseIdentityError("The plan digest does not match its exact owner.")

    candidates = cast(Sequence[Mapping[str, Any]], value["candidates"])
    if [candidate["candidate_ordinal"] for candidate in candidates] != list(range(len(candidates))):
        raise UniverseIdentityError("Plan candidate ordinals must be contiguous and ordered.")
    public_setting_owners = {
        (
            cast(str, owner["owner_kind"]),
            "" if owner["adapter_id"] is None else cast(str, owner["adapter_id"]),
            cast(str, owner["owner_id"]),
        ): cast(Mapping[str, Any], owner)
        for owner in public_intent_manifest["ordered_setting_owners"]
    }
    public_ids = {
        (cast(str, row["namespace"]), cast(str, row["public_id"]))
        for row in public_intent_manifest["ordered_public_ids"]
    }
    for candidate in candidates:
        spec = cast(Mapping[str, Any], candidate["analysis_spec"])
        _validate_plan_candidate(
            candidate,
            authenticated_non_sampling=_is_authenticated_non_sampling_spec(
                spec, supported_algorithms
            ),
        )
        _validate_analysis_spec_contract(
            spec,
            supported_algorithms,
            public_settings_schemas,
            public_setting_owners,
            require_executable=candidate["planning_outcome"] == "PLANNED",
        )
    candidate_ids = [cast(str, candidate["candidate_id"]) for candidate in candidates]
    if len(set(candidate_ids)) != len(candidate_ids):
        raise UniverseIdentityError("Plan candidate identities must be unique.")
    candidate_keys = [_candidate_order_key(candidate) for candidate in candidates]
    if candidate_keys != sorted(candidate_keys):
        raise UniverseIdentityError("Plan candidates violate the declared ordering rule.")

    claimed_origins: set[bytes] = set()
    for candidate in candidates:
        primary_key = _canonical_origin(cast(Mapping[str, Any], candidate["primary_origin"]))
        duplicate_keys = [
            _canonical_origin(cast(Mapping[str, Any], origin))
            for origin in candidate["duplicate_origins"]
        ]
        if primary_key in duplicate_keys:
            raise UniverseIdentityError("A duplicate origin equals its primary origin.")
        for origin_key in (primary_key, *duplicate_keys):
            if origin_key in claimed_origins:
                raise UniverseIdentityError(
                    "One origin is claimed by multiple candidate identities."
                )
            claimed_origins.add(origin_key)

    candidates_by_id = {
        cast(str, candidate["analysis_spec_id"]): candidate for candidate in candidates
    }
    baseline_id = cast(str, value["baseline_analysis_spec_id"])
    baseline_candidate = candidates_by_id.get(baseline_id)
    if baseline_candidate is None:
        raise UniverseIdentityError("The plan baseline AnalysisSpec is missing.")
    if baseline_candidate["analysis_spec"]["operation_intent"]["kind"] != "ordinary":
        raise UniverseIdentityError("The plan baseline AnalysisSpec is not ordinary.")
    if planning_config_preimage["baseline_analysis_spec_id"] != baseline_id:
        raise UniverseIdentityError("The plan baseline differs from its planning owner.")
    source_edges: dict[str, str] = {}
    for candidate in candidates:
        spec = cast(Mapping[str, Any], candidate["analysis_spec"])
        operation = cast(Mapping[str, Any], spec["operation_intent"])
        if operation["kind"] != "ordinary":
            source_id = cast(str, operation["source_analysis_spec_id"])
            candidate_id = cast(str, candidate["analysis_spec_id"])
            if source_id == candidate_id or source_id not in candidates_by_id:
                raise UniverseIdentityError("A derived AnalysisSpec source is invalid.")
            if (
                candidate["planning_outcome"] == "PLANNED"
                and candidates_by_id[source_id]["planning_outcome"] != "PLANNED"
            ):
                raise UniverseIdentityError("A planned candidate depends on an ineligible source.")
            source = cast(Mapping[str, Any], candidates_by_id[source_id]["analysis_spec"])
            _validate_derived_source_pipeline(spec, source)
            if (
                operation["source_variant_id"]
                != source["dataset_variant_intent"]["source_variant_id"]
            ):
                raise UniverseIdentityError("A derived operation names the wrong source variant.")
            source_edges[candidate_id] = source_id
        for origin in _candidate_origins(candidate):
            mode = cast(str, origin["experiment_mode"])
            if (
                mode in {"bootstrap", "subsample", "influence", "null"}
                and mode != operation["kind"]
            ):
                raise UniverseIdentityError("An origin mode disagrees with its operation.")
            if mode == "baseline" and operation["kind"] != "ordinary":
                raise UniverseIdentityError("A baseline origin must be ordinary.")
    for start in source_edges:
        visited: set[str] = set()
        cursor = start
        while cursor in source_edges:
            if cursor in visited:
                raise UniverseIdentityError("Derived AnalysisSpec sources contain a cycle.")
            visited.add(cursor)
            cursor = source_edges[cursor]

    summary = cast(Mapping[str, Any], value["planning_dataset_summary"])
    manifest_digest = public_intent_manifest_digest(public_intent_manifest)
    if value["public_intent_manifest_digest"] != manifest_digest:
        raise UniverseIdentityError("The plan uses a detached public intent manifest.")
    provenance_records = cast(Sequence[Mapping[str, Any]], value["declaration_provenance_registry"])
    _verify_declaration_provenance_registry(candidates, provenance_records)
    expected_resolutions = _expected_declaration_resolutions(candidates)
    if value["declaration_resolution_registry"] != expected_resolutions:
        raise UniverseIdentityError(
            "Declaration resolution registry is missing, extra, forged, or noncanonical."
        )
    # Only caller-controlled AnalysisSpec, experiment, and axis-choice IDs
    # require pre-data manifest authority. Declaration, rationale, operation,
    # origin, and generated member IDs are independently rebuilt compiler output.
    required_public_ids: set[tuple[str, str]] = set()
    for candidate in candidates:
        required_public_ids.update(
            _analysis_spec_public_ids(cast(Mapping[str, Any], candidate["analysis_spec"]))
        )
        for origin in _candidate_origins(candidate):
            required_public_ids.add(("experiment", cast(str, origin["experiment_set_id"])))
            required_public_ids.update(
                ("choice", cast(str, choice["choice_id"]))
                for choice in cast(Sequence[Mapping[str, Any]], origin["axis_choices"])
            )
    if required_public_ids - public_ids:
        raise UniverseIdentityError("A caller-controlled public ID is absent from its manifest.")
    expected_edges = _expected_origin_comparison_edges(candidates, baseline_id)
    if value["origin_comparison_edges"] != expected_edges:
        raise UniverseIdentityError("Origin comparison edges are missing, forged, or noncanonical.")
    _verify_expansion_cardinalities(
        candidates,
        summary,
        cast(Mapping[str, Any], value["declared_operation_expansions"]),
    )

    counts = cast(Mapping[str, Any], value["counts"])
    expected_counts = {
        "candidate_count": len(candidates),
        "origin_count": sum(len(_candidate_origins(candidate)) for candidate in candidates),
        "additional_origin_count": sum(
            len(candidate["duplicate_origins"]) for candidate in candidates
        ),
        "planned_candidate_count": sum(
            candidate["planning_outcome"] == "PLANNED" for candidate in candidates
        ),
        "plan_ineligible_candidate_count": sum(
            candidate["planning_outcome"] == "PLAN_INELIGIBLE" for candidate in candidates
        ),
        "seedless_chain_slot_count": sum(len(candidate["chain_slots"]) for candidate in candidates),
        "planned_fit_ceiling": sum(
            cast(int, candidate["planned_fit_ceiling"]) for candidate in candidates
        ),
    }
    by_experiment_set, by_axis, by_operation = _expected_plan_partitions(candidates)
    expected_counts.update(
        {
            "by_experiment_set": by_experiment_set,
            "by_axis": by_axis,
            "by_operation": by_operation,
        }
    )
    if counts != expected_counts:
        raise UniverseIdentityError("The plan counts do not match its exact candidates.")

    _verify_budget_decision(
        candidates,
        summary,
        cast(Mapping[str, Any], value["declared_operation_expansions"]),
        expected_counts["planned_fit_ceiling"],
        cast(Mapping[str, Any], value["budget_decision"]),
    )

    runtime = cast(Mapping[str, Any], value["runtime_estimate"])
    if runtime["status"] == "UNVERIFIED":
        if (
            runtime["estimated_seconds"] is not None
            or runtime["evidence_digest"] is not None
            or runtime["evidence_source"] != "core-unverified"
        ):
            raise UniverseIdentityError("An unverified runtime estimate cannot carry evidence.")
    elif (
        runtime["estimated_seconds"] is None
        or runtime["evidence_digest"] is None
        or runtime["evidence_source"] != "authenticated-pilot-registry"
    ):
        raise UniverseIdentityError("A verified runtime estimate requires value and evidence.")


def _verify_budget_decision(
    candidates: Sequence[Mapping[str, Any]],
    planning_dataset_summary: Mapping[str, Any],
    declared_operation_expansions: Mapping[str, Any],
    planned_fit_ceiling: int,
    budget: Mapping[str, Any],
) -> None:
    """Verify the three independent v2 planning ceilings without truncation."""

    ordinary_candidate_count = 0
    for candidate in candidates:
        spec = cast(Mapping[str, Any], candidate["analysis_spec"])
        operation = cast(Mapping[str, Any], spec["operation_intent"])
        ordinary_candidate_count += operation["kind"] == "ordinary"
    influence_scope_counts = [
        cast(int, row["eligible_target_count"])
        for row in cast(
            Sequence[Mapping[str, Any]],
            planning_dataset_summary["influence_expansion_cardinalities"],
        )
    ]
    influence_scope_counts.extend(
        len(cast(Sequence[str], row["ordered_named_group_spec_ids"]))
        for row in cast(
            Sequence[Mapping[str, Any]],
            declared_operation_expansions["named_group_removals"],
        )
    )
    maximum_scoped_exact_influence_count = max(influence_scope_counts, default=0)
    if (
        budget["planned_ordinary_candidate_count"] != ordinary_candidate_count
        or budget["planned_fit_ceiling"] != planned_fit_ceiling
        or budget["maximum_scoped_exact_influence_count"] != maximum_scoped_exact_influence_count
    ):
        raise UniverseIdentityError("The budget decision does not bind the plan ceiling.")
    expected_reasons = []
    if ordinary_candidate_count > budget["ordinary_candidate_limit"]:
        expected_reasons.append("BUDGET.ORDINARY_CANDIDATE_LIMIT_EXCEEDED")
    if planned_fit_ceiling > budget["fit_limit"]:
        expected_reasons.append("BUDGET.FIT_LIMIT_EXCEEDED")
    if maximum_scoped_exact_influence_count > budget["influence_removal_limit"]:
        expected_reasons.append("BUDGET.INFLUENCE_REMOVAL_LIMIT_EXCEEDED")
    within_budget = not expected_reasons
    if within_budget != (budget["decision"] == "WITHIN_BUDGET"):
        raise UniverseIdentityError("The budget decision is inconsistent with its limits.")
    if budget["reason_codes"] != expected_reasons:
        raise UniverseIdentityError("The budget reasons do not match every exceeded ceiling.")


def _manifest_setting_ids(
    owners: Mapping[tuple[str, str, str], Mapping[str, Any]],
    owner_key: tuple[str, str, str],
    settings_schema: Mapping[str, Any],
    selected_settings: Mapping[str, Any],
    *,
    selected_setting_order: Sequence[str] | None = None,
) -> tuple[str, ...]:
    """Bind every complete selected value to one pre-data manifest authorization."""

    owner = owners.get(owner_key)
    if owner is None or owner["settings_schema_digest"] != settings_schema_digest(settings_schema):
        raise UniverseIdentityError("Public settings lack their exact manifest schema owner.")
    definitions = cast(Sequence[Mapping[str, Any]], owner["ordered_parameters"])
    by_id = {cast(str, row["setting_id"]): row for row in definitions}
    if len(by_id) != len(definitions):
        raise UniverseIdentityError("The public settings manifest repeats a setting owner.")
    manifest_order = tuple(cast(str, row["setting_id"]) for row in definitions)
    if set(selected_settings) != set(manifest_order):
        raise UniverseIdentityError("Selected settings differ from the exact manifest set.")
    if selected_setting_order is not None and tuple(selected_setting_order) != manifest_order:
        raise UniverseIdentityError("Selected setting rows differ from manifest order.")
    properties = cast(Mapping[str, Mapping[str, Any]], settings_schema["properties"])
    if set(properties) != set(manifest_order):
        raise UniverseIdentityError("The settings schema differs from its manifest parameters.")
    for setting_id in manifest_order:
        declaration = properties[setting_id]["type"]
        declared_types = {declaration} if isinstance(declaration, str) else set(declaration)
        nullable = "null" in declared_types
        declared_types.discard("null")
        definition = by_id[setting_id]
        if declared_types != {definition["value_kind"]} or nullable != definition["nullable"]:
            raise UniverseIdentityError("A manifest setting kind or nullability is detached.")
    for setting_id, value in selected_settings.items():
        definition = by_id[setting_id]
        if not _authorized_setting_value_matches_kind(
            value,
            value_kind=cast(str, definition["value_kind"]),
            nullable=cast(bool, definition["nullable"]),
        ):
            raise UniverseIdentityError("A selected setting has an unsafe value kind.")
        if not any(
            canonical_json_bytes(value) == canonical_json_bytes(authorized)
            for authorized in definition["authorized_values"]
        ):
            raise UniverseIdentityError("A selected setting value is not publicly authorized.")
    return manifest_order


def _analysis_spec_public_ids(spec: Mapping[str, Any]) -> set[tuple[str, str]]:
    """Collect execution-semantic public IDs from one closed AnalysisSpec/3."""

    found: set[tuple[str, str]] = set()

    def add(namespace: str, value: object) -> None:
        if value is not None:
            found.add((namespace, cast(str, value)))

    def add_many(namespace: str, values: Sequence[object]) -> None:
        for value in values:
            add(namespace, value)

    variant = cast(Mapping[str, Any], spec["dataset_variant_intent"])
    add("variant", variant["source_variant_id"])
    add("variant", variant["source_variant_id_ref"])

    cohort = cast(Mapping[str, Any], spec["cohort_rule"])
    add("group", cohort["group_spec_id"])
    add_many("field", cast(Sequence[object], cohort["public_field_ids"]))
    for row in cast(Sequence[Mapping[str, Any]], cohort["label_roles"]):
        add("label", row["public_label_id"])
    for role in cast(Sequence[Mapping[str, Any]], cohort["role_rules"]):
        for clause in cast(Sequence[Mapping[str, Any]], role["clauses"]):
            add("field", clause["public_field_id"])
            add("label", clause["value_alias_id"])

    for row in cast(Sequence[Mapping[str, Any]], spec["event_set"]):
        add("event", row["event_id"])
    add_many("event", list(cast(Mapping[str, Any], spec["event_directions"])))
    for transformation in cast(Sequence[Mapping[str, Any]], spec["preprocessing"]):
        add("preprocessing-method", transformation["method_id"])
        add_many("event", cast(Sequence[object], transformation["event_ids"]))

    missingness = cast(Mapping[str, Any], spec["missingness_policy"])
    add_many("event", cast(Sequence[object], missingness["event_ids"]))
    adjustment = cast(Mapping[str, Any], spec["covariate_adjustment"])
    add_many("covariate", cast(Sequence[object], adjustment["ordered_terms"]))

    backend = cast(Mapping[str, Any], spec["backend"])
    add("adapter", backend["adapter_id"])
    add("backend", backend["expected_backend_name"])
    add("algorithm", backend["algorithm_id"])
    mcmc = spec["mcmc"]
    if isinstance(mcmc, Mapping):
        add("proposal", mcmc["proposal_method_id"])
        add("initialization", mcmc["initialization_rule"])

    operation = cast(Mapping[str, Any], spec["operation_intent"])
    if operation["kind"] != "ordinary":
        add("variant", operation["source_variant_id"])
        add("variant", operation["derived_source_variant_id"])
    if operation["kind"] in {"bootstrap", "subsample"}:
        add_many("group", cast(Sequence[object], operation["strata_group_spec_ids"]))
    elif operation["kind"] == "influence":
        add("group", operation.get("named_group_spec_id"))
    elif operation["kind"] == "null":
        add("null-family", operation["null_family_id"])
        add("group", operation["within_group_spec_id"])
    return found


def _declaration_provenance_public_ids(
    provenance: Mapping[str, Any],
) -> set[tuple[str, str]]:
    """Collect plan-owned declaration labels without treating them as execution."""

    found: set[tuple[str, str]] = set()

    def add(namespace: str, value: object) -> None:
        if value is not None:
            found.add((namespace, cast(str, value)))

    add("declaration", provenance["analysis_declaration_id"])
    add("rationale", provenance["dataset_variant_rationale_id"])
    add("cohort", provenance["cohort_intent_id"])
    add("rationale", provenance["cohort_rationale_id"])
    for row in cast(Sequence[Mapping[str, Any]], provenance["event_inclusion_reasons"]):
        add("event", row["event_id"])
        add("rationale", row["inclusion_reason_id"])
    for row in cast(Sequence[Mapping[str, Any]], provenance["preprocessing_declarations"]):
        add("operation", row["operation_id"])
        add("rationale", row["rationale_id"])
    add("rationale", provenance["outlier_rationale_id"])
    operation = cast(Mapping[str, Any], provenance["operation_declaration"])
    add("rationale", operation.get("removal_rationale_id"))
    add("rationale", operation.get("rationale_id"))
    for rationale in cast(Sequence[Mapping[str, Any]], provenance["rationales"]):
        add("choice", rationale["choice_id"])
        add("rationale", rationale["rationale_id"])
        for source_id in cast(Sequence[object], rationale["source_ids"]):
            add("source", source_id)
    return found


def _validate_analysis_spec_public_ids(
    spec: Mapping[str, Any], allowed_public_ids: set[tuple[str, str]]
) -> None:
    missing = _analysis_spec_public_ids(spec) - allowed_public_ids
    if missing:
        raise UniverseIdentityError(
            "An AnalysisSpec caller-controlled ID is absent from its public manifest."
        )


def _validate_analysis_spec_canonical_sets(spec: Mapping[str, Any]) -> None:
    """Reject alternate encodings of semantically set-like public choices."""

    cohort = cast(Mapping[str, Any], spec["cohort_rule"])
    _canonical_row_set(
        cast(Sequence[Mapping[str, Any]], cohort["label_roles"]),
        label="Cohort label-role bindings",
    )
    for role in cast(Sequence[Mapping[str, Any]], cohort["role_rules"]):
        _canonical_row_set(
            cast(Sequence[Mapping[str, Any]], role["clauses"]),
            label="Declarative cohort clauses",
        )
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    if operation["kind"] in {"bootstrap", "subsample"}:
        _ordered_unique_strings(
            cast(Sequence[object], operation["strata_group_spec_ids"]),
            label="Sampling strata group IDs",
        )


def _validate_operation_variant_binding(spec: Mapping[str, Any]) -> None:
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    variant = cast(Mapping[str, Any], spec["dataset_variant_intent"])
    expected_variant_kinds = {
        "ordinary": {"baseline-input", "external-missingness"},
        "bootstrap": {"bootstrap-resample"},
        "subsample": {"participant-subsample"},
        "influence": {"influence-removal"},
        "null": {"null-transformation"},
    }
    if variant["variant_kind"] not in expected_variant_kinds[operation["kind"]]:
        raise UniverseIdentityError("The operation kind and dataset-variant intent disagree.")
    uses_external_missingness = spec["missingness_policy"]["policy"] == "external-variant"
    if operation["kind"] == "ordinary" and uses_external_missingness != (
        variant["variant_kind"] == "external-missingness"
    ):
        raise UniverseIdentityError("External missingness and its dataset variant must agree.")


def _validate_derived_source_pipeline(
    derived: Mapping[str, Any], source: Mapping[str, Any]
) -> None:
    source_operation = cast(Mapping[str, Any], source["operation_intent"])
    if source_operation["kind"] != "ordinary":
        raise UniverseIdentityError("A derived candidate source must be ordinary.")
    pipeline_fields = (
        "cohort_rule",
        "event_set",
        "event_directions",
        "preprocessing",
        "outlier_policy",
        "missingness_policy",
        "covariate_adjustment",
        "backend",
        "mcmc",
    )
    if any(derived[field] != source[field] for field in pipeline_fields):
        raise UniverseIdentityError("A derived candidate changes its source fitted pipeline.")


def _validate_analysis_spec_contract(
    spec: Mapping[str, Any],
    supported_algorithms: Sequence[Mapping[str, Any]],
    public_settings_schemas: Mapping[tuple[str, str], Mapping[str, Any]],
    public_setting_owners: Mapping[tuple[str, str, str], Mapping[str, Any]],
    *,
    require_executable: bool,
) -> None:
    """Reject schema-valid intent not resolved to authenticated public owners."""

    try:
        _validate_analysis_spec_canonical_sets(spec)
        event_rows = cast(Sequence[Mapping[str, Any]], spec["event_set"])
        directions = cast(Mapping[str, Any], spec["event_directions"])
        backend = cast(Mapping[str, Any], spec["backend"])
        operation = cast(Mapping[str, Any], spec["operation_intent"])
        variant = cast(Mapping[str, Any], spec["dataset_variant_intent"])
        operation_kind = cast(str, operation["kind"])
        _validate_operation_variant_binding(spec)
        event_ids = [cast(str, row["event_id"]) for row in event_rows]
        event_id_set = set(event_ids)
        if require_executable and len(event_ids) < 2:
            raise UniverseIdentityError("A prepared universe requires at least two events.")
        if require_executable and (
            len(event_id_set) != len(event_ids) or event_id_set != set(directions)
        ):
            raise UniverseIdentityError("Every selected event requires exactly one direction.")
        if require_executable and any(
            directions[event_id] not in {"higher", "lower"} for event_id in event_ids
        ):
            raise UniverseIdentityError("A prepared universe cannot use an unresolved direction.")

        for transformation in cast(Sequence[Mapping[str, Any]], spec["preprocessing"]):
            targets = cast(Sequence[str], transformation["event_ids"])
            if not set(targets).issubset(event_id_set):
                raise UniverseIdentityError("Preprocessing targets an unselected event.")
            if list(targets) != [event_id for event_id in event_ids if event_id in set(targets)]:
                raise UniverseIdentityError(
                    "Preprocessing event IDs are not in selected-event order."
                )
            names = cast(Sequence[object], [row["name"] for row in transformation["parameters"]])
            _ordered_unique_strings(names, label="Preprocessing parameter names")
            schema = public_settings_schemas.get(
                ("preprocessing-method", cast(str, transformation["method_id"]))
            )
            if (
                schema is None
                or settings_schema_digest(schema) != transformation["parameters_schema_digest"]
            ):
                raise UniverseIdentityError(
                    "Preprocessing parameters lack their authenticated public schema."
                )
            _validate_public_settings_schema(
                schema,
                _manifest_setting_ids(
                    public_setting_owners,
                    (
                        "preprocessing-method",
                        "",
                        cast(str, transformation["method_id"]),
                    ),
                    schema,
                    {cast(str, row["name"]): row["value"] for row in transformation["parameters"]},
                    selected_setting_order=[
                        cast(str, row["name"]) for row in transformation["parameters"]
                    ],
                ),
            )
            try:
                validate_settings(
                    {row["name"]: row["value"] for row in transformation["parameters"]},
                    schema,
                )
            except SchemaValidationError as exc:
                raise UniverseIdentityError(
                    "Preprocessing parameters violate their public schema."
                ) from exc
        if spec["missingness_policy"]["event_ids"] != event_ids:
            raise UniverseIdentityError("Missingness policy must bind every selected event.")

        cohort = cast(Mapping[str, Any], spec["cohort_rule"])
        if cohort["required_roles"] != ["reference", "at_risk"]:
            raise UniverseIdentityError("A prepared cohort must require both analysis roles.")
        public_field_ids = _ordered_unique_strings(
            cast(Sequence[object], cohort["public_field_ids"]),
            label="Cohort public field IDs",
        )
        if cohort["source_kind"] == "label-alias":
            label_rows = cast(Sequence[Mapping[str, Any]], cohort["label_roles"])
            label_ids = [cast(str, row["public_label_id"]) for row in label_rows]
            if len(set(label_ids)) != len(label_ids) or {row["role"] for row in label_rows} != {
                "reference",
                "at_risk",
            }:
                raise UniverseIdentityError("Cohort label aliases do not define both roles once.")
        else:
            role_rows = cast(Sequence[Mapping[str, Any]], cohort["role_rules"])
            if [row["role"] for row in role_rows] != ["reference", "at_risk"]:
                raise UniverseIdentityError(
                    "Declarative cohort rules must define both roles in order."
                )
            for role_row in role_rows:
                for clause in cast(Sequence[Mapping[str, Any]], role_row["clauses"]):
                    if clause["public_field_id"] not in public_field_ids:
                        raise UniverseIdentityError(
                            "A cohort clause names an undeclared public field."
                        )

        outlier = cast(Mapping[str, Any], spec["outlier_policy"])
        if outlier["policy_kind"] == "none" and (
            outlier["threshold"] is not None
            or outlier["scope"] != "none"
            or outlier["action"] != "none"
            or outlier["reference_population"] != "none"
            or outlier["value_transformation"] is not None
        ):
            raise UniverseIdentityError("The no-outlier policy carries hidden settings.")
        allowed_actions = {
            "none": {"none"},
            "cell": {"flag-only", "mask-cell", "transform-value"},
            "participant": {"flag-only", "remove-participant"},
            "event": {"flag-only", "transform-value"},
        }
        if outlier["action"] not in allowed_actions[outlier["scope"]]:
            raise UniverseIdentityError("The outlier action is incompatible with its scope.")
        if outlier["policy_kind"] == "tukey-iqr" and (
            not isinstance(outlier["threshold"], (int, float))
            or isinstance(outlier["threshold"], bool)
            or outlier["threshold"] <= 0
            or outlier["reference_population"] == "none"
        ):
            raise UniverseIdentityError("The Tukey-IQR policy is incomplete.")
        if (outlier["action"] == "transform-value") != (
            outlier["value_transformation"] == "winsorize-to-tukey-fence/1"
        ):
            raise UniverseIdentityError("The outlier value transformation is detached.")

        adjustment = cast(Mapping[str, Any], spec["covariate_adjustment"])
        if adjustment["method"] == "none":
            if (
                adjustment["ordered_terms"]
                or adjustment["intercept"] is not None
                or adjustment["categorical_encoding"] not in {"none", None}
                or adjustment["minimum_reference_rows"] is not None
                or adjustment["require_full_rank"] is not False
            ):
                raise UniverseIdentityError("The no-adjustment policy carries hidden settings.")
        elif (
            not adjustment["ordered_terms"]
            or not isinstance(adjustment["intercept"], bool)
            or adjustment["categorical_encoding"] not in {"none", "treatment/1"}
            or adjustment["minimum_reference_rows"] is None
            or adjustment["require_full_rank"] is not True
        ):
            raise UniverseIdentityError("Residualisation settings are incomplete.")

        method_rows = load_protocol_registry()["audit_config_identity_contract"][
            "source_variant_method_registry"
        ]
        methods_by_kind = {row["variant_kind"]: set(row["method_ids"]) for row in method_rows}
        if variant["method_id"] not in methods_by_kind[variant["variant_kind"]]:
            raise UniverseIdentityError("The source-variant kind and method disagree.")
        if variant["variant_kind"] == "baseline-input":
            if variant["source_variant_id_ref"] is not None:
                raise UniverseIdentityError("The baseline source variant cannot have a parent.")
        elif variant["source_variant_id_ref"] is None:
            raise UniverseIdentityError("A derived source variant requires its declared parent.")

        mcmc_value = spec["mcmc"]
        if mcmc_value is not None:
            mcmc = cast(Mapping[str, Any], mcmc_value)
            if not 0 <= mcmc["burn_in_count"] < mcmc["raw_iteration_count"]:
                raise UniverseIdentityError("Burn-in must leave at least one returned MCMC state.")
            proposal_names = cast(
                Sequence[object], [row["name"] for row in mcmc["proposal_settings"]]
            )
            _ordered_unique_strings(proposal_names, label="MCMC proposal-setting names")
            proposal_schema = public_settings_schemas.get(
                ("mcmc-proposal", cast(str, mcmc["proposal_method_id"]))
            )
            if (
                proposal_schema is None
                or settings_schema_digest(proposal_schema)
                != mcmc["proposal_settings_schema_digest"]
            ):
                raise UniverseIdentityError(
                    "MCMC proposal settings lack their authenticated public schema."
                )
            _validate_public_settings_schema(
                proposal_schema,
                _manifest_setting_ids(
                    public_setting_owners,
                    ("mcmc-proposal", "", cast(str, mcmc["proposal_method_id"])),
                    proposal_schema,
                    {cast(str, row["name"]): row["value"] for row in mcmc["proposal_settings"]},
                    selected_setting_order=[
                        cast(str, row["name"]) for row in mcmc["proposal_settings"]
                    ],
                ),
            )
            try:
                validate_settings(
                    {row["name"]: row["value"] for row in mcmc["proposal_settings"]},
                    proposal_schema,
                )
            except SchemaValidationError as exc:
                raise UniverseIdentityError(
                    "MCMC proposal settings violate their public schema."
                ) from exc

        requested_outputs = cast(Sequence[str], backend["requested_outputs"])
        registry_order = [row["output_id"] for row in load_protocol_registry()["requested_outputs"]]
        requested_set = set(requested_outputs)
        if list(requested_outputs) != [row for row in registry_order if row in requested_set] or (
            "central_order" not in requested_set
        ):
            raise UniverseIdentityError("Fit outputs must include central order in registry order.")
        if settings_digest(backend["settings"]) != backend["settings_digest"]:
            raise UniverseIdentityError("The backend settings digest is detached.")
        if (
            requested_outputs_digest("fit", requested_outputs)
            != backend["requested_outputs_digest"]
        ):
            raise UniverseIdentityError("The requested-output digest is detached.")
        matching_algorithms = []
        for algorithm in supported_algorithms:
            adapter_semantics = algorithm.get("adapter_semantics")
            if (
                isinstance(adapter_semantics, Mapping)
                and adapter_semantics.get("adapter_id") == backend["adapter_id"]
                and adapter_semantics.get("algorithm_id") == backend["algorithm_id"]
                and algorithm.get("adapter_semantics_digest") == backend["adapter_semantics_digest"]
            ):
                matching_algorithms.append(algorithm)
        if len(matching_algorithms) != 1:
            raise UniverseIdentityError(
                "The backend does not resolve to one authenticated SupportedAlgorithm."
            )
        selected_algorithm = matching_algorithms[0]
        if (
            backend["capabilities_digest"]
            != capabilities_digest(selected_algorithm["capabilities"])
            or capabilities_digest(selected_algorithm["capabilities"])
            != selected_algorithm["capabilities_digest"]
            or backend["settings_schema_digest"]
            != settings_schema_digest(selected_algorithm["settings_schema"])
            or settings_schema_digest(selected_algorithm["settings_schema"])
            != selected_algorithm["settings_schema_digest"]
            or backend["stage_semantics_digest"]
            != stage_semantics_digest(selected_algorithm["stage_semantics_definition"])
            or stage_semantics_digest(selected_algorithm["stage_semantics_definition"])
            != selected_algorithm["stage_semantics_digest"]
        ):
            raise UniverseIdentityError("The selected algorithm binding is detached.")
        _validate_public_settings_schema(
            cast(Mapping[str, Any], selected_algorithm["settings_schema"]),
            _manifest_setting_ids(
                public_setting_owners,
                (
                    "backend-algorithm",
                    cast(str, backend["adapter_id"]),
                    cast(str, backend["algorithm_id"]),
                ),
                cast(Mapping[str, Any], selected_algorithm["settings_schema"]),
                cast(Mapping[str, Any], backend["settings"]),
            ),
        )
        try:
            validate_settings(backend["settings"], selected_algorithm["settings_schema"])
        except SchemaValidationError as exc:
            raise UniverseIdentityError(
                "Backend settings are not valid public settings for the selected algorithm."
            ) from exc

        derived_kinds = {"bootstrap", "subsample", "influence", "null"}
        if operation_kind in derived_kinds:
            expected_variant_kind = {
                "bootstrap": "bootstrap-resample",
                "subsample": "participant-subsample",
                "influence": "influence-removal",
                "null": "null-transformation",
            }[operation_kind]
            if (
                operation["source_variant_id"] != variant["source_variant_id_ref"]
                or operation["derived_source_variant_id"] != variant["source_variant_id"]
                or variant["variant_kind"] != expected_variant_kind
            ):
                raise UniverseIdentityError("Derived operation and source-variant intent disagree.")
            method_field = {
                "bootstrap": "sampling_method_id",
                "subsample": "sampling_method_id",
                "influence": "removal_method_id",
                "null": "null_method_id",
            }[operation_kind]
            if operation[method_field] != variant["method_id"]:
                raise UniverseIdentityError("Operation and source-variant methods disagree.")
    except UniverseIdentityError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise UniverseIdentityError("The executable AnalysisSpec is inconsistent.") from exc


def _universe_preimage(universe: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "universe_schema_version": universe["universe_schema_version"],
        "plan_schema_version": universe["plan_schema_version"],
        "plan_digest": universe["plan_digest"],
        "candidate_ordinal": universe["candidate_ordinal"],
        "candidate_id": universe["candidate_id"],
        "analysis_spec_id": universe["analysis_spec_id"],
        "preparation_rule_registry_digest": universe["preparation_rule_registry_digest"],
        "stage_transition_rule_id": universe["stage_transition_rule_id"],
        "operation_seed": universe["operation_seed"],
        "source_prepared_data_digest": universe["source_prepared_data_digest"],
        "training_prepared_data_digest": universe["training_prepared_data_digest"],
        "evaluation_prepared_data_digest": universe["evaluation_prepared_data_digest"],
        "evaluation_membership_digest": universe["evaluation_membership_digest"],
        "source_accounting_digest": universe["source_accounting_digest"],
        "training_accounting_digest": universe["training_accounting_digest"],
        "evaluation_accounting_digest": universe["evaluation_accounting_digest"],
        "aggregate_counts": copy.deepcopy(universe["aggregate_counts"]),
        "ordered_chain_plan": [
            {
                "chain_ordinal": row["chain_ordinal"],
                "chain_id": row["chain_id"],
                "seed": row["seed"],
            }
            for row in universe["chain_plan"]
        ],
    }


def _private_evaluation_membership_digest(
    plan_digest: str, membership: Sequence[_PrivateMembership]
) -> str:
    preimage = {
        "membership_schema_version": "ebm-audit-evaluation-membership/1.0",
        "plan_digest": plan_digest,
        "ordered_run_local_participant_tokens": [row.participant_token for row in membership],
        "ordered_role_codes": [row.role for row in membership],
    }
    return structured_sha256("ebm-audit/evaluation-membership/1", preimage)


def _unique_private_membership(
    rows: Sequence[_PrivateMembership], *, label: str
) -> dict[tuple[str, int], str]:
    result: dict[tuple[str, int], str] = {}
    for row in rows:
        key = (row.participant_token, row.internal_row_index)
        if key in result or row.role not in {"reference", "at_risk"}:
            raise UniverseIdentityError(f"{label} is invalid.")
        result[key] = row.role
    return result


def _role_counts_from_membership(rows: Sequence[_PrivateMembership]) -> dict[str, int]:
    roles = _unique_private_membership(rows, label="Private role membership")
    return {
        "reference_unique_participant_count": sum(role == "reference" for role in roles.values()),
        "at_risk_unique_participant_count": sum(role == "at_risk" for role in roles.values()),
        "reference_participant_instance_count": sum(role == "reference" for role in roles.values()),
        "at_risk_participant_instance_count": sum(role == "at_risk" for role in roles.values()),
    }


def _role_counts_from_instances(rows: Sequence[_PrivateOperationInstance]) -> dict[str, int]:
    unique: dict[tuple[str, int], str] = {}
    for row in rows:
        unique[(row.participant_token, row.internal_row_index)] = row.role
    return {
        "reference_unique_participant_count": sum(role == "reference" for role in unique.values()),
        "at_risk_unique_participant_count": sum(role == "at_risk" for role in unique.values()),
        "reference_participant_instance_count": sum(row.role == "reference" for row in rows),
        "at_risk_participant_instance_count": sum(row.role == "at_risk" for row in rows),
    }


def _expected_subsample_retained_count(
    pre_operation_participant_count: int,
    retained_fraction: int | float,
) -> int:
    """Apply the sole declared global retained-total rounding rule."""

    if (
        type(pre_operation_participant_count) is not int
        or pre_operation_participant_count < 1
        or not isinstance(retained_fraction, (int, float))
        or isinstance(retained_fraction, bool)
        or not math.isfinite(retained_fraction)
        or not 0 < retained_fraction < 1
    ):
        raise UniverseIdentityError("The subsample retained-total inputs are invalid.")
    return math.floor(pre_operation_participant_count * retained_fraction)


def _verify_preparation_aggregate_counts(
    spec: Mapping[str, Any],
    counts: Mapping[str, Any],
    source_participant_count: int,
    *,
    has_exact_stratum_allocation_replay: bool = False,
) -> None:
    """Verify staged public totals while leaving exact membership to private replay."""

    if counts["source_participant_count"] != source_participant_count:
        raise UniverseIdentityError("Prepared source count does not match the planning summary.")
    if counts["event_count"] != len(spec["event_set"]):
        raise UniverseIdentityError("Prepared aggregate event count does not match the intent.")
    source = cast(int, counts["source_participant_count"])
    cohort = cast(int, counts["cohort_eligible_participant_count"])
    eligible = cast(int, counts["pre_operation_eligible_participant_count"])
    operation_instances = cast(int, counts["operation_output_participant_instance_count"])
    operation_unique = cast(int, counts["operation_output_unique_participant_count"])
    training_instances = cast(int, counts["training_participant_instance_count"])
    training_unique = cast(int, counts["training_unique_participant_count"])
    evaluation = cast(int, counts["evaluation_participant_count"])
    if not (
        source >= cohort >= eligible
        and operation_instances >= operation_unique
        and operation_instances >= training_instances
        and operation_unique >= training_unique
        and training_instances >= training_unique
    ):
        raise UniverseIdentityError("Prepared participant stage totals are not monotonic.")
    if (
        min(
            cohort,
            eligible,
            operation_instances,
            operation_unique,
            training_instances,
            training_unique,
        )
        < 2
    ):
        raise UniverseIdentityError("A prepared fit requires both participant roles.")

    def verify_roles(field: str, unique_count: int, instance_count: int) -> Mapping[str, Any]:
        roles = cast(Mapping[str, Any], counts[field])
        if (
            roles["reference_unique_participant_count"] + roles["at_risk_unique_participant_count"]
            != unique_count
            or roles["reference_participant_instance_count"]
            + roles["at_risk_participant_instance_count"]
            != instance_count
        ):
            raise UniverseIdentityError("Prepared role counts do not bind their stage total.")
        if (
            roles["reference_unique_participant_count"]
            > roles["reference_participant_instance_count"]
            or roles["at_risk_unique_participant_count"]
            > roles["at_risk_participant_instance_count"]
        ):
            raise UniverseIdentityError("Prepared role unique counts exceed role instances.")
        return roles

    cohort_roles = verify_roles("cohort_role_counts", cohort, cohort)
    pre_operation_roles = verify_roles("pre_operation_role_counts", eligible, eligible)
    operation_roles = verify_roles(
        "operation_output_role_counts", operation_unique, operation_instances
    )
    training_roles = verify_roles("training_role_counts", training_unique, training_instances)
    verify_roles("evaluation_role_counts", evaluation, evaluation)
    if (
        training_roles["reference_unique_participant_count"] < 1
        or training_roles["at_risk_unique_participant_count"] < 1
    ):
        raise UniverseIdentityError("Prepared training must retain both participant roles.")

    operation = cast(Mapping[str, Any], spec["operation_intent"])
    kind = cast(str, operation["kind"])
    if kind == "ordinary":
        valid_operation = operation_instances == operation_unique == eligible
    elif kind == "bootstrap":
        valid_operation = operation_instances == eligible and 1 <= operation_unique <= eligible
    elif kind == "subsample":
        expected_instances = _expected_subsample_retained_count(
            eligible,
            cast(float, operation["retained_fraction"]),
        )
        if operation["retained_count_rounding_rule"] != (
            "floor-pre-operation-count-times-fraction/1"
        ):
            raise UniverseIdentityError("The subsample rounding rule is detached.")
        valid_operation = (
            operation_instances == operation_unique == expected_instances
            and expected_instances < eligible
        )
    elif kind == "influence":
        removal_count = eligible - operation_unique
        valid_operation = operation_instances == operation_unique < eligible
        if operation["removal_kind"] == "leave-one-participant-out":
            valid_operation = valid_operation and removal_count == 1
        else:
            valid_operation = valid_operation and removal_count > 0
    else:
        valid_operation = operation_instances == operation_unique == eligible
    if not valid_operation:
        raise UniverseIdentityError("Prepared operation-stage participant totals are invalid.")
    if (
        kind in {"bootstrap", "subsample"}
        and operation["sampling_design"] == "stratified"
        and not has_exact_stratum_allocation_replay
    ):
        raise UniverseIdentityError(
            "Stratified preparation requires exact private stratum-allocation replay."
        )
    if (
        kind == "bootstrap"
        and operation["sampling_design"] == "stratified"
        and any(
            operation_roles[f"{role}_participant_instance_count"]
            != pre_operation_roles[f"{role}_participant_instance_count"]
            for role in ("reference", "at_risk")
        )
    ):
        raise UniverseIdentityError("A stratified bootstrap changed role draw sizes.")
    role_prefixes = ("reference", "at_risk")
    role_count_fields = (
        "unique_participant_count",
        "participant_instance_count",
    )
    if kind in {"ordinary", "null"} and any(
        operation_roles[f"{role}_{count_field}"] != pre_operation_roles[f"{role}_{count_field}"]
        for role in role_prefixes
        for count_field in role_count_fields
    ):
        raise UniverseIdentityError(
            "An identity-preserving operation changed the participant role vector."
        )
    if kind in {"bootstrap", "subsample", "influence"} and any(
        operation_roles[f"{role}_unique_participant_count"]
        > pre_operation_roles[f"{role}_unique_participant_count"]
        for role in role_prefixes
    ):
        raise UniverseIdentityError("An operation invented a participant role membership.")
    if any(
        training_roles[f"{role}_{count_field}"] > operation_roles[f"{role}_{count_field}"]
        for role in role_prefixes
        for count_field in role_count_fields
    ):
        raise UniverseIdentityError("Training preparation invented a participant role membership.")
    null_method = operation.get("null_method_id")
    source_identity_preserving = kind != "null" or null_method != "pure-no-signal-synthetic/1"
    if source_identity_preserving and evaluation > source:
        raise UniverseIdentityError("The fixed evaluation count exceeds its source population.")
    missingness_policy = spec["missingness_policy"]["policy"]
    outlier_action = spec["outlier_policy"]["action"]
    allows_post_operation_loss = missingness_policy == "complete-case" or outlier_action == (
        "remove-participant"
    )
    if not allows_post_operation_loss and (
        training_instances != operation_instances or training_unique != operation_unique
    ):
        raise UniverseIdentityError("Post-operation participant loss is not declared.")
    minimum_reference_rows = spec["covariate_adjustment"]["minimum_reference_rows"]
    if minimum_reference_rows is not None and (
        training_roles["reference_unique_participant_count"] < minimum_reference_rows
    ):
        raise UniverseIdentityError("Prepared training violates minimum reference rows.")

    if (
        missingness_policy == "error"
        and outlier_action != "remove-participant"
        and (eligible != cohort or pre_operation_roles != cohort_roles)
    ):
        raise UniverseIdentityError("No declared pre-operation policy permits cohort loss.")
    if counts["fit_ready_missing_cell_count"] != 0:
        raise UniverseIdentityError("Fit-ready data cannot retain missing cells.")
    if not spec["preprocessing"] and counts["preprocessing_transformed_cell_count"] != 0:
        raise UniverseIdentityError("Empty preprocessing cannot transform cells.")
    if spec["outlier_policy"]["policy_kind"] == "none" and (
        counts["preprocessing_flagged_cell_count"] != 0
        or counts["preprocessing_masked_cell_count"] != 0
    ):
        raise UniverseIdentityError("The no-outlier policy cannot flag or mask cells.")
    if outlier_action == "flag-only" and counts["preprocessing_masked_cell_count"] != 0:
        raise UniverseIdentityError("A flag-only outlier policy cannot mask cells.")
    if outlier_action == "mask-cell" and (
        counts["preprocessing_masked_cell_count"] != counts["preprocessing_flagged_cell_count"]
    ):
        raise UniverseIdentityError("Masked outlier cells must equal flagged outlier cells.")
    if (
        outlier_action in {"remove-participant", "transform-value"}
        and counts["preprocessing_masked_cell_count"] != 0
    ):
        raise UniverseIdentityError("This outlier action cannot mask cells.")

    operation_cells = counts["operation_transformed_cell_count"]
    operation_labels = counts["operation_transformed_label_count"]
    if kind != "null" and (operation_cells != 0 or operation_labels != 0):
        raise UniverseIdentityError("Only a null operation can own operation transforms.")
    if kind == "null":
        if null_method == "label-permutation/1" and (
            operation_cells != 0
            or operation_labels < 1
            or operation_labels > operation_instances
            or operation_labels % 2 != 0
        ):
            raise UniverseIdentityError("Label permutation accounting is not exact.")
        if null_method == "featurewise-within-group-participant-permutation/1" and (
            operation_labels != 0
            or operation_cells < 1
            or operation_cells > operation_instances * counts["event_count"]
        ):
            raise UniverseIdentityError("Feature permutation accounting is not exact.")
        if null_method == "pure-no-signal-synthetic/1" and (
            operation_labels != 0 or operation_cells != operation_instances * counts["event_count"]
        ):
            raise UniverseIdentityError("Null cell-transformation accounting is not exact.")
        if null_method not in {
            "label-permutation/1",
            "featurewise-within-group-participant-permutation/1",
            "pure-no-signal-synthetic/1",
        }:
            raise UniverseIdentityError("Null transformation accounting method is unknown.")
    operation_cell_ceiling = operation_instances * counts["event_count"]
    training_cell_ceiling = training_instances * counts["event_count"]
    if (
        counts["operation_transformed_cell_count"] > operation_cell_ceiling
        or counts["operation_transformed_label_count"] > operation_instances
        or counts["preprocessing_transformed_cell_count"] > operation_cell_ceiling
        or counts["preprocessing_flagged_cell_count"] > operation_cell_ceiling
        or counts["preprocessing_masked_cell_count"] > operation_cell_ceiling
        or counts["fit_ready_missing_cell_count"] > training_cell_ceiling
    ):
        raise UniverseIdentityError("Prepared cell accounting exceeds its stage cardinality.")


def _verify_preparation_record_rules(
    candidate: Mapping[str, Any],
    record: Mapping[str, Any],
    registry_rules: Sequence[Mapping[str, Any]],
    rules_by_id: Mapping[str, Mapping[str, Any]],
) -> None:
    """Keep planning ineligibility separate from preparation-rule outcomes."""

    state = record["state"]
    if candidate["planning_outcome"] == "PLAN_INELIGIBLE":
        if state != "PLAN_INELIGIBLE":
            raise UniverseIdentityError("A plan-ineligible candidate changed state in preparation.")
        if record["applied_preparation_rule_ids"]:
            raise UniverseIdentityError("Plan ineligibility cannot apply preparation rules.")
        if record["reasons"] != candidate["planning_reasons"]:
            raise UniverseIdentityError("Plan-ineligible receipt reasons differ from the plan.")
        return
    if state == "PLAN_INELIGIBLE":
        raise UniverseIdentityError("Preparation cannot invent plan ineligibility.")

    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    operation_kind = cast(str, operation["kind"])
    applied_rule_ids = cast(Sequence[str], record["applied_preparation_rule_ids"])
    for rule_id in applied_rule_ids:
        rule = rules_by_id.get(rule_id)
        if (
            rule is None
            or operation_kind not in rule["operation_kinds"]
            or state not in rule["states"]
        ):
            raise UniverseIdentityError("An applied preparation rule is absent or inapplicable.")
    required_rule_ids = {
        cast(str, rule["rule_id"])
        for rule in registry_rules
        if rule["required_when_applicable"]
        and operation_kind in rule["operation_kinds"]
        and state in rule["states"]
    }
    if not required_rule_ids.issubset(set(applied_rule_ids)):
        raise UniverseIdentityError("A required preparation rule was not applied.")
    for reason in cast(Sequence[Mapping[str, Any]], record["reasons"]):
        rule_id = cast(str, reason["rule_id"])
        rule = rules_by_id.get(rule_id)
        if (
            rule is None
            or rule_id not in applied_rule_ids
            or operation_kind not in rule["operation_kinds"]
            or state not in rule["states"]
            or reason["reason_code"] not in rule["allowed_reason_codes"]
        ):
            raise UniverseIdentityError("A preparation reason is not owned by its applied rule.")
