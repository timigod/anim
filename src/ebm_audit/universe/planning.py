"""Sealed Plan/3 compiler and exact-rebuild acceptance authority.

This module is the only positive AnalysisPlan/3 boundary.  The authority is an
in-process capability: configuration mappings, prepared-data summaries,
worker descriptions, serialized copies, and manually allocated lookalikes do
not carry its authority.
"""

from __future__ import annotations

import copy
import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePath
from threading import Lock
from typing import TYPE_CHECKING, Any, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.protocol import (
    adapter_semantics_digest,
    canonical_json_bytes,
    capabilities_digest,
    settings_schema_digest,
    stage_semantics_digest,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.schema import (
    SchemaValidationError,
    load_schema,
    validate_instance,
    validate_settings,
)

from .compiler import AxisCompositionError, compose_analysis_spec
from .identities import (
    PublicIntentManifest,
    UniverseIdentityError,
    ValidatedPlanningSummary,
    _analysis_spec_public_ids,
    _expected_declaration_resolutions,
    _expected_origin_comparison_edges,
    _expected_plan_partitions,
    _is_authenticated_non_sampling_spec,
    _issue_public_intent_manifest,
    _issue_validated_planning_summary,
    _verify_analysis_plan_contract,
    analysis_plan_digest,
    analysis_spec_content_id,
    candidate_origin_id,
    declaration_provenance_digest,
    planning_config_digest,
    scientific_backend_registry_digest,
)

if TYPE_CHECKING:
    from ebm_audit.adapters.invocation import (
        AuthenticatedWorkerDescription,
        _AuthenticatedDescriptionReadback,
    )
    from ebm_audit.config.verification import (
        PlanEligibleAuditConfig,
        RunEligibleAuditConfig,
    )
    from ebm_audit.data.preparation import PreparedAuditDataset

    from .preparation import PreparationTransaction

_PROFILE_IDS = frozenset({"quick", "full", "release"})
_COMPILER_CODE_DIGEST = structured_sha256(
    "ebm-audit/analysis-plan-compiler/3",
    {
        "compiler_id": "sealed-exact-rebuild-plan-compiler-v2",
        "candidate_ordering_rule": "primary-origin-id-then-candidate-id-utf8/1",
        "static_planning_rules": [
            "planning.event-count/1",
            "planning.event-directions/1",
            "planning.mcmc-availability/1",
        ],
    },
)


@dataclass(frozen=True, repr=False)
class _PlanningWorkerOwner:
    description: AuthenticatedWorkerDescription
    description_state: object
    description_readback: _AuthenticatedDescriptionReadback
    selected_algorithm_binding: Mapping[str, Any]


_PRIVACY_SURFACE_DEFINITIONS = frozenset({"AnalysisPlan", "PublicIntentManifestDigestPreimage"})
_PRIVACY_SCHEMA_DOCUMENTS = frozenset(
    {"analysis-universe.schema.json", "canonical-records.schema.json"}
)
_PRIVACY_OPAQUE_STRING_DEFINITIONS = frozenset({"Sha256Digest"})
_PRIVACY_COMPILER_GENERATED_STRING_FIELDS = frozenset(
    {
        "analysis_declaration_id",
        "chain_id",
        "cohort_intent_id",
        "cohort_rationale_id",
        "dataset_variant_rationale_id",
        "inclusion_reason_id",
        "operation_id",
        "outlier_rationale_id",
        "rationale_id",
        "removal_rationale_id",
    }
)


def _closed_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        canonical = canonical_json_bytes(value)
        result = strict_json_loads(canonical)
    except (TypeError, ValueError):
        raise UniverseIdentityError("Planning input is not closed canonical JSON.") from None
    if type(result) is not dict:
        raise UniverseIdentityError("Planning input must be an object.")
    return cast(dict[str, Any], result)


def _utf8(value: str) -> bytes:
    return value.encode("utf-8", errors="strict")


def _machine_id(prefix: str, value: object) -> str:
    digest = structured_sha256("ebm-audit/planning-label/1", {"value": value})
    return f"{prefix}-{digest.removeprefix('sha256:')[:16]}"


def _scientific_backend_registry_preimage(
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Rebuild every selectable transport-free BackendSpec without loader state."""

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
                backends.append(cast(Mapping[str, Any], member["analysis_spec"]["backend"]))
    by_jcs = {canonical_json_bytes(backend): copy.deepcopy(dict(backend)) for backend in backends}
    return {
        "registry_schema_version": "ebm-audit-scientific-backend-registry/1.0",
        "ordered_backends": [by_jcs[key] for key in sorted(by_jcs)],
    }


def _schema_validate(value: object, definition: str) -> None:
    try:
        validate_instance(value, "analysis-universe.schema.json", definition=definition)
    except SchemaValidationError:
        raise UniverseIdentityError(
            "Planning authority produced an invalid closed record."
        ) from None


class _PreparationPublication:
    """Mutable, authority-private publication cell for one successful transaction."""

    __slots__ = ("lock", "transaction")

    lock: Any
    transaction: object | None

    def __init__(self) -> None:
        self.lock = Lock()
        self.transaction = None


@dataclass(frozen=True, repr=False)
class _PlanningAuthorityState:
    run_config: PlanEligibleAuditConfig | RunEligibleAuditConfig
    prepared_dataset: PreparedAuditDataset
    authenticated_descriptions: tuple[AuthenticatedWorkerDescription, ...]
    authenticated_description_states: tuple[object, ...]
    authenticated_description_readbacks: tuple[_AuthenticatedDescriptionReadback, ...]
    profile_id: str
    private_config_bytes: bytes
    planning_config_bytes: bytes
    planning_summary: ValidatedPlanningSummary
    public_intent_manifest: PublicIntentManifest
    supported_algorithms_bytes: bytes
    public_settings_schemas_bytes: bytes
    core_settings_registry_bytes: bytes
    selected_algorithm_bindings_bytes: bytes
    preparation_namespace_key: object | None = None
    preparation_publication: _PreparationPublication | None = None
    preparation_publication_token: object | None = None


_PLANNING_AUTHORITY_STATES: OneShotWeakRegistry[object, _PlanningAuthorityState]
_PLANNING_AUTHORITY_STATE_ISSUER: OneShotRegistryIssuer[object, _PlanningAuthorityState]
(
    _PLANNING_AUTHORITY_STATES,
    _PLANNING_AUTHORITY_STATE_ISSUER,
) = create_one_shot_registry()


@final
class PlanningAuthority:
    """Opaque authority over one exact config, dataset, and Describe set."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PlanningAuthority:
        raise TypeError("Planning authorities come from the planning validation boundary.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Planning authorities cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Planning authorities are immutable.")

    def _state(self) -> _PlanningAuthorityState:
        try:
            state = _PLANNING_AUTHORITY_STATES[self]
        except (KeyError, TypeError):
            raise TypeError("A genuine in-process planning authority is required.") from None
        if type(state) is not _PlanningAuthorityState:
            raise TypeError("A genuine in-process planning authority is required.")
        return state

    @property
    def profile_id(self) -> str:
        return self._state().profile_id

    @property
    def planning_summary(self) -> ValidatedPlanningSummary:
        return self._state().planning_summary

    @property
    def planning_summary_id(self) -> str:
        return self._state().planning_summary.planning_summary_id

    @property
    def public_intent_manifest(self) -> PublicIntentManifest:
        return self._state().public_intent_manifest

    @property
    def public_intent_manifest_digest(self) -> str:
        return self._state().public_intent_manifest.manifest_digest

    @property
    def core_settings_registry_digest(self) -> str:
        registry = _load_object(self._state().core_settings_registry_bytes)
        return structured_sha256("ebm-audit/core-settings-registry/1", registry)

    def authenticated_description_for(
        self, adapter_id: str, algorithm_id: str
    ) -> AuthenticatedWorkerDescription:
        return self._worker_owner_for(adapter_id, algorithm_id).description

    def _worker_owner_for(self, adapter_id: str, algorithm_id: str) -> _PlanningWorkerOwner:
        return _worker_owner_for_state(self._state(), adapter_id, algorithm_id)

    def selected_algorithm_binding(self, adapter_id: str, algorithm_id: str) -> dict[str, Any]:
        return copy.deepcopy(
            dict(self._worker_owner_for(adapter_id, algorithm_id).selected_algorithm_binding)
        )

    def prepare(self) -> PreparationTransaction:
        """Run the sole complete Plan/3-to-PreparationReceipt/2 transaction."""

        from .preparation import _prepare_analysis_plan

        return _prepare_analysis_plan(self)

    def __copy__(self) -> PlanningAuthority:
        self._state()
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> PlanningAuthority:
        self._state()
        memo[id(self)] = self
        return self

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Planning authorities cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Planning authorities cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Planning authorities cannot be serialized.")

    def __repr__(self) -> str:
        self._state()
        return "PlanningAuthority(<sealed-exact-planning-owners>)"


def _load_object(value: bytes) -> dict[str, Any]:
    loaded = strict_json_loads(value)
    if type(loaded) is not dict:
        raise TypeError("Planning authority storage is invalid.")
    return cast(dict[str, Any], loaded)


def _load_array(value: bytes) -> list[dict[str, Any]]:
    loaded = strict_json_loads(value)
    if type(loaded) is not list or any(type(row) is not dict for row in loaded):
        raise TypeError("Planning authority storage is invalid.")
    return cast(list[dict[str, Any]], loaded)


def _all_ordinary_specs(config: Mapping[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Return each declared ordinary spec and its compiler provenance context."""

    baseline = _closed_copy(cast(Mapping[str, Any], config["baseline_analysis"]))
    rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
    baseline_seen = False
    declarations = cast(Mapping[str, Any], config["experiments"])
    for experiment_set in cast(Sequence[Mapping[str, Any]], declarations["sets"]):
        if not experiment_set["enabled"]:
            continue
        mode = cast(str, experiment_set["mode"])
        experiment_set_id = cast(str, experiment_set["experiment_set_id"])
        if mode == "baseline":
            if baseline_seen:
                raise UniverseIdentityError("The planning config declares more than one baseline.")
            baseline_seen = True
            rows.append(
                (
                    copy.deepcopy(baseline),
                    {
                        "experiment_set_id": experiment_set_id,
                        "experiment_mode": "baseline",
                        "member_id": "baseline",
                        "axis_choices": [],
                        "declaration_ordinal": 0,
                    },
                )
            )
        elif mode in {"one-axis", "declared-combinations", "full-factorial"}:
            for ordinal, member in enumerate(
                cast(Sequence[Mapping[str, Any]], experiment_set["members"])
            ):
                try:
                    spec = compose_analysis_spec(
                        baseline,
                        experiment_set_id,
                        mode,
                        cast(Sequence[Mapping[str, Any]], experiment_set["axes"]),
                        member,
                    )
                except AxisCompositionError as exc:
                    raise UniverseIdentityError(
                        "A composed planning declaration is invalid."
                    ) from exc
                choices = sorted(
                    copy.deepcopy(list(member["axis_choices"])),
                    key=lambda row: (_utf8(row["axis_id"]), _utf8(row["choice_id"])),
                )
                rows.append(
                    (
                        spec,
                        {
                            "experiment_set_id": experiment_set_id,
                            "experiment_mode": mode,
                            "member_id": member["member_id"],
                            "axis_choices": choices,
                            "declaration_ordinal": ordinal,
                        },
                    )
                )
        elif mode == "custom":
            for ordinal, member in enumerate(
                cast(Sequence[Mapping[str, Any]], experiment_set["members"])
            ):
                spec = _closed_copy(cast(Mapping[str, Any], member["analysis_spec"]))
                if member["analysis_spec_id"] != analysis_spec_content_id(spec):
                    raise UniverseIdentityError("A custom AnalysisSpec identity is detached.")
                rows.append(
                    (
                        spec,
                        {
                            "experiment_set_id": experiment_set_id,
                            "experiment_mode": "custom",
                            "member_id": member["member_id"],
                            "axis_choices": [],
                            "declaration_ordinal": ordinal,
                        },
                    )
                )
    if not baseline_seen:
        raise UniverseIdentityError("The planning config has no enabled baseline declaration.")
    return rows


def _variant_intent(
    variants: Mapping[str, Mapping[str, Any]], derived_source_variant_id: str
) -> dict[str, Any]:
    row = variants.get(derived_source_variant_id)
    if row is None:
        raise UniverseIdentityError("A derived operation names an undeclared source variant.")
    return {
        "source_variant_id": row["source_variant_id"],
        "variant_kind": row["variant_kind"],
        "source_variant_id_ref": row["source_variant_id_ref"],
        "method_id": row["method_id"],
    }


def _derived_specs(
    config: Mapping[str, Any],
    profile_id: str,
    ordinary: Sequence[tuple[dict[str, Any], dict[str, Any]]],
    participant_count: int,
) -> tuple[
    list[tuple[dict[str, Any], dict[str, Any]]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    by_id = {analysis_spec_content_id(spec): spec for spec, _context in ordinary}
    variants = {
        cast(str, row["source_variant_id"]): row
        for row in cast(Sequence[Mapping[str, Any]], config["source_variants"])
    }
    profile = cast(Mapping[str, Any], cast(Mapping[str, Any], config["profiles"])[profile_id])
    generated: list[tuple[dict[str, Any], dict[str, Any]]] = []
    replicated_rows: list[dict[str, Any]] = []
    named_rows: list[dict[str, Any]] = []
    influence_rows: list[dict[str, Any]] = []
    declarations = cast(Mapping[str, Any], config["experiments"])
    for experiment_set in cast(Sequence[Mapping[str, Any]], declarations["sets"]):
        if not experiment_set["enabled"]:
            continue
        mode = cast(str, experiment_set["mode"])
        experiment_set_id = cast(str, experiment_set["experiment_set_id"])
        if mode not in {"bootstrap", "subsample", "influence", "null"}:
            continue
        if mode in {"bootstrap", "subsample"}:
            declaration = cast(Mapping[str, Any], experiment_set[mode])
            replicate_count = cast(int, profile[f"{mode}_replicates"])
            for source_id in cast(Sequence[str], declaration["source_analysis_spec_ids"]):
                source = by_id.get(source_id)
                if source is None:
                    raise UniverseIdentityError("A replicated operation source is not ordinary.")
                expansion = {
                    "experiment_set_id": experiment_set_id,
                    "source_analysis_spec_id": source_id,
                    "source_variant_id": declaration["source_variant_id"],
                    "derived_source_variant_id": declaration["derived_source_variant_id"],
                    "operation_kind": mode,
                    "method_id": declaration["sampling_method_id"],
                    "null_family_id": None,
                    "replicate_count": replicate_count,
                }
                replicated_rows.append(expansion)
                for replicate_ordinal in range(replicate_count):
                    spec = copy.deepcopy(source)
                    spec["dataset_variant_intent"] = _variant_intent(
                        variants, cast(str, declaration["derived_source_variant_id"])
                    )
                    operation = {
                        "kind": mode,
                        "source_analysis_spec_id": source_id,
                        "source_variant_id": declaration["source_variant_id"],
                        "derived_source_variant_id": declaration["derived_source_variant_id"],
                        "replicate_ordinal": replicate_ordinal,
                        "sampling_method_id": declaration["sampling_method_id"],
                        "sampling_design": declaration["sampling_design"],
                        "strata_group_spec_ids": copy.deepcopy(
                            declaration["strata_group_spec_ids"]
                        ),
                        "refit_preprocessing": declaration["refit_preprocessing"],
                        "fixed_evaluation_cohort_policy": declaration[
                            "fixed_evaluation_cohort_policy"
                        ],
                    }
                    if mode == "subsample":
                        operation["retained_fraction"] = declaration["retained_fraction"]
                        operation["retained_count_rounding_rule"] = (
                            "floor-pre-operation-count-times-fraction/1"
                        )
                    spec["operation_intent"] = operation
                    generated.append(
                        (
                            spec,
                            {
                                "experiment_set_id": experiment_set_id,
                                "experiment_mode": mode,
                                "member_id": _machine_id(mode, [source_id, replicate_ordinal]),
                                "axis_choices": [],
                                "declaration_ordinal": replicate_ordinal,
                            },
                        )
                    )
        elif mode == "influence":
            declaration = cast(Mapping[str, Any], experiment_set["influence"])
            removal_kind = cast(str, declaration["removal_kind"])
            for source_id in cast(Sequence[str], declaration["source_analysis_spec_ids"]):
                source = by_id.get(source_id)
                if source is None:
                    raise UniverseIdentityError("An influence source is not ordinary.")
                if removal_kind == "leave-one-participant-out":
                    selection = declaration.get("removal_selection")
                    target_count = (
                        participant_count
                        if selection is None
                        else cast(int, cast(Mapping[str, Any], selection)["selected_removal_count"])
                    )
                    if target_count > participant_count:
                        raise UniverseIdentityError(
                            "A declared influence selection exceeds the prepared cohort."
                        )
                    influence_rows.append(
                        {
                            "experiment_set_id": experiment_set_id,
                            "source_analysis_spec_id": source_id,
                            "source_variant_id": declaration["source_variant_id"],
                            "derived_source_variant_id": declaration["derived_source_variant_id"],
                            "removal_kind": removal_kind,
                            "eligible_target_count": target_count,
                            "ordered_named_group_spec_ids": [],
                        }
                    )
                    named_groups: Sequence[str | None] = [None] * target_count
                else:
                    group_ids = sorted(
                        cast(Sequence[str], declaration["named_group_spec_ids"]), key=_utf8
                    )
                    target_count = len(group_ids)
                    named_groups = group_ids
                    named_rows.append(
                        {
                            "experiment_set_id": experiment_set_id,
                            "source_analysis_spec_id": source_id,
                            "source_variant_id": declaration["source_variant_id"],
                            "derived_source_variant_id": declaration["derived_source_variant_id"],
                            "removal_kind": removal_kind,
                            "ordered_named_group_spec_ids": list(group_ids),
                        }
                    )
                for ordinal, group_id in enumerate(named_groups):
                    spec = copy.deepcopy(source)
                    spec["dataset_variant_intent"] = _variant_intent(
                        variants, cast(str, declaration["derived_source_variant_id"])
                    )
                    operation = {
                        "kind": "influence",
                        "source_analysis_spec_id": source_id,
                        "source_variant_id": declaration["source_variant_id"],
                        "derived_source_variant_id": declaration["derived_source_variant_id"],
                        "removal_slot_ordinal": ordinal,
                        "removal_method_id": declaration["removal_method_id"],
                        "removal_kind": removal_kind,
                        "refit_preprocessing": declaration["refit_preprocessing"],
                        "fixed_non_removed_cohort_policy": declaration[
                            "fixed_non_removed_cohort_policy"
                        ],
                    }
                    if group_id is not None:
                        operation["named_group_spec_id"] = group_id
                    spec["operation_intent"] = operation
                    generated.append(
                        (
                            spec,
                            {
                                "experiment_set_id": experiment_set_id,
                                "experiment_mode": "influence",
                                "member_id": _machine_id(
                                    "influence", [source_id, ordinal, group_id]
                                ),
                                "axis_choices": [],
                                "declaration_ordinal": ordinal,
                            },
                        )
                    )
        else:
            replicate_count = cast(int, profile["null_replicates_per_family"])
            for family in cast(Sequence[Mapping[str, Any]], experiment_set["null_families"]):
                for source_id in cast(Sequence[str], family["source_analysis_spec_ids"]):
                    source = by_id.get(source_id)
                    if source is None:
                        raise UniverseIdentityError("A null-operation source is not ordinary.")
                    replicated_rows.append(
                        {
                            "experiment_set_id": experiment_set_id,
                            "source_analysis_spec_id": source_id,
                            "source_variant_id": family["source_variant_id"],
                            "derived_source_variant_id": family["derived_source_variant_id"],
                            "operation_kind": "null",
                            "method_id": family["null_method_id"],
                            "null_family_id": family["null_family_id"],
                            "replicate_count": replicate_count,
                        }
                    )
                    for ordinal in range(replicate_count):
                        spec = copy.deepcopy(source)
                        spec["dataset_variant_intent"] = _variant_intent(
                            variants, cast(str, family["derived_source_variant_id"])
                        )
                        spec["operation_intent"] = {
                            "kind": "null",
                            "source_analysis_spec_id": source_id,
                            "source_variant_id": family["source_variant_id"],
                            "derived_source_variant_id": family["derived_source_variant_id"],
                            "replicate_ordinal": ordinal,
                            "null_family_id": family["null_family_id"],
                            "null_method_id": family["null_method_id"],
                            "transformation": family["transformation"],
                            "within_group_spec_id": family["within_group_spec_id"],
                            "refit_preprocessing": family["refit_preprocessing"],
                            "preserves_group_conditional_event_marginals": family[
                                "preserves_group_conditional_event_marginals"
                            ],
                        }
                        generated.append(
                            (
                                spec,
                                {
                                    "experiment_set_id": experiment_set_id,
                                    "experiment_mode": "null",
                                    "member_id": _machine_id(
                                        "null", [source_id, family["null_family_id"], ordinal]
                                    ),
                                    "axis_choices": [],
                                    "declaration_ordinal": ordinal,
                                },
                            )
                        )
    replicated_rows.sort(
        key=lambda row: tuple(
            _utf8(cast(str, value)) if value is not None else b""
            for value in (
                row["experiment_set_id"],
                row["source_analysis_spec_id"],
                row["source_variant_id"],
                row["derived_source_variant_id"],
                row["operation_kind"],
                row["method_id"],
                row["null_family_id"],
            )
        )
    )
    named_rows.sort(
        key=lambda row: tuple(
            _utf8(row[key])
            for key in (
                "experiment_set_id",
                "source_analysis_spec_id",
                "source_variant_id",
                "derived_source_variant_id",
                "removal_kind",
            )
        )
    )
    influence_rows.sort(
        key=lambda row: tuple(
            _utf8(row[key])
            for key in (
                "experiment_set_id",
                "source_analysis_spec_id",
                "source_variant_id",
                "derived_source_variant_id",
                "removal_kind",
            )
        )
    )
    return generated, replicated_rows, named_rows, influence_rows


def _provenance(spec: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    declaration_id = _machine_id(
        "declaration",
        [context["experiment_set_id"], context["member_id"], spec["operation_intent"]],
    )
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    kind = cast(str, operation["kind"])
    if kind in {"ordinary", "bootstrap", "subsample"}:
        operation_declaration: dict[str, Any] = {"kind": kind}
    elif kind == "influence":
        operation_declaration = {
            "kind": kind,
            "removal_rationale_id": _machine_id("rationale", [declaration_id, "removal"]),
        }
    else:
        operation_declaration = {
            "kind": kind,
            "rationale_id": _machine_id("rationale", [declaration_id, "null"]),
        }
    core = {
        "provenance_schema_version": "ebm-audit-analysis-declaration-provenance/1.0",
        "analysis_declaration_id": declaration_id,
        "dataset_variant_rationale_id": _machine_id(
            "rationale", [declaration_id, "dataset-variant"]
        ),
        "cohort_intent_id": _machine_id("cohort", spec["cohort_rule"]),
        "cohort_rationale_id": _machine_id("rationale", [declaration_id, "cohort"]),
        "event_inclusion_reasons": [
            {
                "event_id": row["event_id"],
                "inclusion_reason_id": _machine_id(
                    "rationale", [declaration_id, "event", row["event_id"]]
                ),
            }
            for row in cast(Sequence[Mapping[str, Any]], spec["event_set"])
        ],
        "preprocessing_declarations": [
            {
                "transformation_ordinal": ordinal,
                "operation_id": _machine_id(
                    "operation", [declaration_id, ordinal, row["method_id"]]
                ),
                "rationale_id": _machine_id(
                    "rationale", [declaration_id, "preprocessing", ordinal]
                ),
            }
            for ordinal, row in enumerate(cast(Sequence[Mapping[str, Any]], spec["preprocessing"]))
        ],
        "outlier_rationale_id": _machine_id("rationale", [declaration_id, "outlier"]),
        "operation_declaration": operation_declaration,
        "rationales": [],
    }
    _schema_validate(core, "DeclarationProvenanceDigestPreimage")
    return {**core, "source_declaration_digest": declaration_provenance_digest(core)}


def _origin(provenance: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        "analysis_declaration_id": provenance["analysis_declaration_id"],
        "experiment_set_id": context["experiment_set_id"],
        "experiment_mode": context["experiment_mode"],
        "declaration_ordinal": context["declaration_ordinal"],
        "axis_choices": copy.deepcopy(context["axis_choices"]),
        "source_declaration_digest": provenance["source_declaration_digest"],
    }
    return {**core, "origin_id": candidate_origin_id(core)}


def _candidate_rows(
    declarations: Sequence[tuple[dict[str, Any], dict[str, Any]]],
    supported_algorithms: Sequence[Mapping[str, Any]] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_spec: dict[str, dict[str, Any]] = {}
    provenance_by_digest: dict[str, dict[str, Any]] = {}
    for spec, context in declarations:
        _schema_validate(spec, "AnalysisSpec")
        identity = analysis_spec_content_id(spec)
        provenance = _provenance(spec, context)
        provenance_by_digest[provenance["source_declaration_digest"]] = provenance
        origin = _origin(provenance, context)
        entry = by_spec.setdefault(identity, {"spec": spec, "origins": []})
        if entry["spec"] != spec:
            raise UniverseIdentityError("An AnalysisSpec digest collision was detected.")
        entry["origins"].append(origin)
    candidates: list[dict[str, Any]] = []
    for identity, entry in by_spec.items():
        origins = sorted(entry["origins"], key=lambda row: _utf8(row["origin_id"]))
        if len({row["origin_id"] for row in origins}) != len(origins):
            raise UniverseIdentityError("A declaration produced a duplicate origin identity.")
        spec = cast(dict[str, Any], entry["spec"])
        event_ids = [row["event_id"] for row in spec["event_set"]]
        directions = cast(Mapping[str, Any], spec["event_directions"])
        reasons: list[dict[str, str]] = []
        if len(event_ids) < 2:
            reasons.append(
                {"reason_code": "PLAN.EVENT_COUNT_BELOW_TWO", "rule_id": "planning.event-count/1"}
            )
        if set(event_ids) != set(directions) or any(
            directions.get(event_id) not in {"higher", "lower"} for event_id in event_ids
        ):
            reasons.append(
                {
                    "reason_code": "PLAN.EVENT_DIRECTIONS_UNRESOLVED",
                    "rule_id": "planning.event-directions/1",
                }
            )
        mcmc = spec["mcmc"]
        authenticated_non_sampling = _is_authenticated_non_sampling_spec(
            spec, supported_algorithms
        )
        if mcmc is None and not authenticated_non_sampling:
            reasons.append(
                {
                    "reason_code": "PLAN.MCMC_UNAVAILABLE_FOR_MVP",
                    "rule_id": "planning.mcmc-availability/1",
                }
            )
        reasons.sort(key=lambda row: (_utf8(row["reason_code"]), _utf8(row["rule_id"])))
        planned = not reasons
        slot_count = (
            0
            if not planned
            else 1
            if authenticated_non_sampling
            else cast(int, mcmc["chain_count"])
        )
        candidates.append(
            {
                "candidate_schema_version": "ebm-audit-analysis-candidate/3.0",
                "candidate_ordinal": 0,
                "candidate_id": identity,
                "analysis_spec_id": identity,
                "analysis_spec": spec,
                "primary_origin": origins[0],
                "duplicate_origins": origins[1:],
                "planning_outcome": "PLANNED" if planned else "PLAN_INELIGIBLE",
                "planning_reasons": reasons,
                "within_fit_chain_uncertainty_status": (
                    "UNAVAILABLE_NON_CHAIN_ALGORITHM" if mcmc is None else "AVAILABLE"
                ),
                "chain_slots": [
                    {"chain_ordinal": ordinal, "chain_id": f"chain-{ordinal:04d}"}
                    for ordinal in range(slot_count)
                ],
                "planned_fit_ceiling": slot_count,
            }
        )
    candidates.sort(
        key=lambda row: (
            _utf8(row["primary_origin"]["origin_id"]),
            _utf8(row["candidate_id"]),
        )
    )
    for ordinal, candidate in enumerate(candidates):
        candidate["candidate_ordinal"] = ordinal
    provenance_rows = [provenance_by_digest[key] for key in sorted(provenance_by_digest, key=_utf8)]
    return candidates, provenance_rows


def _projection_for_algorithm(algorithm: Mapping[str, Any]) -> Mapping[str, Any]:
    semantics = algorithm.get("adapter_semantics")
    if not isinstance(semantics, Mapping):
        raise UniverseIdentityError("An authenticated algorithm has no adapter semantics.")
    if adapter_semantics_digest(semantics) != algorithm.get("adapter_semantics_digest"):
        raise UniverseIdentityError("Authenticated adapter semantics are detached.")
    projection = semantics.get("mcmc_projection")
    if not isinstance(projection, Mapping):
        raise UniverseIdentityError("Authenticated adapter semantics omit MCMC availability.")
    return projection


def _proposal_schema(algorithm: Mapping[str, Any], projection: Mapping[str, Any]) -> dict[str, Any]:
    bindings = cast(Sequence[Mapping[str, Any]], projection["proposal_setting_bindings"])
    plan_ids = [cast(str, row["proposal_setting_id"]) for row in bindings]
    if plan_ids != sorted(plan_ids, key=_utf8) or len(set(plan_ids)) != len(plan_ids):
        raise UniverseIdentityError(
            "MCMC proposal setting mappings are not in canonical unique order."
        )
    backend_schema = cast(Mapping[str, Any], algorithm["settings_schema"])
    properties = cast(Mapping[str, Any], backend_schema["properties"])
    projected: dict[str, Any] = {}
    required: list[str] = []
    seen_backend: set[str] = set()
    for binding in bindings:
        if set(binding) != {"proposal_setting_id", "backend_setting_id"}:
            raise UniverseIdentityError("An MCMC proposal setting mapping is not closed.")
        plan_id = cast(str, binding["proposal_setting_id"])
        backend_id = cast(str, binding["backend_setting_id"])
        if plan_id in projected or backend_id in seen_backend or backend_id not in properties:
            raise UniverseIdentityError("An MCMC proposal setting mapping is not one-to-one.")
        seen_backend.add(backend_id)
        projected[plan_id] = copy.deepcopy(properties[backend_id])
        required.append(plan_id)
    required.sort(key=_utf8)
    ordered_properties = {key: projected[key] for key in sorted(projected, key=_utf8)}
    proposal_id = cast(str, projection["proposal_method_id"])
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"urn:ebm-audit:worker-settings-schema:{proposal_id}:1",
        "type": "object",
        "additionalProperties": False,
        "properties": ordered_properties,
        "required": required,
    }
    try:
        validate_instance(schema, "worker-protocol.schema.json", definition="ClosedSettingsSchema")
    except SchemaValidationError:
        raise UniverseIdentityError("An MCMC proposal projection is not a closed schema.") from None
    return schema


def _validate_mcmc_equivalence(
    spec: Mapping[str, Any], algorithm: Mapping[str, Any]
) -> dict[str, Any] | None:
    projection = _projection_for_algorithm(algorithm)
    availability = projection.get("availability")
    if availability == "UNAVAILABLE":
        if (
            set(projection)
            != {
                "projection_schema_version",
                "availability",
                "reason_code",
            }
            or projection.get("reason_code") != "NON_CHAIN_ALGORITHM"
            or projection.get("projection_schema_version")
            != "ebm-audit-adapter-mcmc-projection/1.0"
            or spec["mcmc"] is not None
        ):
            raise UniverseIdentityError("A non-chain algorithm must have exactly null MCMC intent.")
        return None
    if (
        availability != "AVAILABLE"
        or projection.get("projection_schema_version") != "ebm-audit-adapter-mcmc-projection/1.0"
        or set(projection)
        != {
            "projection_schema_version",
            "availability",
            "schedule_bindings",
            "indexing_rule",
            "proposal_method_id",
            "proposal_setting_bindings",
            "initialization_rule",
            "plan_owned_fields",
        }
        or spec["mcmc"] is None
    ):
        raise UniverseIdentityError("An MCMC-capable algorithm requires complete MCMC intent.")
    if projection.get("plan_owned_fields") != [
        "chain_count",
        "seed_derivation_version",
    ]:
        raise UniverseIdentityError("The adapter MCMC projection has invalid plan-owned fields.")
    mcmc = cast(Mapping[str, Any], spec["mcmc"])
    if (
        mcmc["indexing_rule"] != projection.get("indexing_rule")
        or mcmc["proposal_method_id"] != projection.get("proposal_method_id")
        or mcmc["initialization_rule"] != projection.get("initialization_rule")
    ):
        raise UniverseIdentityError("MCMC semantic identifiers differ from adapter semantics.")
    backend_settings = cast(Mapping[str, Any], spec["backend"]["settings"])
    backend_schema = cast(Mapping[str, Any], algorithm["settings_schema"])
    backend_properties = cast(Mapping[str, Mapping[str, Any]], backend_schema["properties"])
    backend_required = set(cast(Sequence[str], backend_schema["required"]))
    schedule = cast(Sequence[Mapping[str, Any]], projection.get("schedule_bindings", []))
    if [row.get("plan_field") for row in schedule] != [
        "raw_iteration_count",
        "burn_in_count",
        "thinning_interval",
    ]:
        raise UniverseIdentityError("MCMC schedule bindings are incomplete or reordered.")
    for row in schedule:
        if set(row) != {
            "plan_field",
            "source_kind",
            "backend_setting_id",
            "constant_value",
        }:
            raise UniverseIdentityError("An MCMC schedule binding is not closed.")
        plan_field = cast(str, row["plan_field"])
        source_kind = row.get("source_kind")
        if source_kind == "backend-setting":
            backend_id = row.get("backend_setting_id")
            if (
                not isinstance(backend_id, str)
                or row.get("constant_value") is not None
                or backend_id not in backend_required
                or backend_properties.get(backend_id, {}).get("type") != "integer"
                or backend_settings.get(backend_id) != mcmc[plan_field]
            ):
                raise UniverseIdentityError("MCMC schedule does not match backend settings.")
        elif source_kind == "adapter-constant":
            if (
                row.get("backend_setting_id") is not None
                or not isinstance(row.get("constant_value"), int)
                or isinstance(row.get("constant_value"), bool)
                or row.get("constant_value") != mcmc[plan_field]
            ):
                raise UniverseIdentityError("MCMC schedule does not match its adapter constant.")
        else:
            raise UniverseIdentityError("MCMC schedule uses an unknown source kind.")
    proposal_schema = _proposal_schema(algorithm, projection)
    if settings_schema_digest(proposal_schema) != mcmc["proposal_settings_schema_digest"]:
        raise UniverseIdentityError("The MCMC proposal schema digest is detached.")
    plan_settings = {
        cast(str, row["name"]): row["value"]
        for row in cast(Sequence[Mapping[str, Any]], mcmc["proposal_settings"])
    }
    binding_rows = cast(Sequence[Mapping[str, Any]], projection["proposal_setting_bindings"])
    expected_settings = {
        cast(str, row["proposal_setting_id"]): backend_settings[row["backend_setting_id"]]
        for row in binding_rows
    }
    if plan_settings != expected_settings or list(plan_settings) != sorted(
        plan_settings, key=_utf8
    ):
        raise UniverseIdentityError("MCMC proposal settings differ from backend settings.")
    try:
        validate_settings(plan_settings, proposal_schema)
    except SchemaValidationError:
        raise UniverseIdentityError(
            "MCMC proposal settings violate their projected schema."
        ) from None
    return proposal_schema


def _resolve_algorithms(
    config: Mapping[str, Any],
    descriptions: Sequence[AuthenticatedWorkerDescription],
    *,
    description_readbacks: Sequence[_AuthenticatedDescriptionReadback] | None = None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str], dict[str, Any]],
]:
    from ebm_audit.adapters.invocation import (
        AuthenticatedWorkerDescription,
        _readback_authenticated_description,
    )

    registry = _scientific_backend_registry_preimage(config)
    backends = cast(Sequence[Mapping[str, Any]], registry["ordered_backends"])
    description_by_owner: dict[tuple[str, str], AuthenticatedWorkerDescription] = {}
    description_readback_by_owner: dict[tuple[str, str], _AuthenticatedDescriptionReadback] = {}
    if description_readbacks is not None and len(description_readbacks) != len(descriptions):
        raise UniverseIdentityError("Planning descriptions lack exact retained Describe readbacks.")
    for position, description in enumerate(descriptions):
        if type(description) is not AuthenticatedWorkerDescription:
            raise UniverseIdentityError("A genuine authenticated worker description is required.")
        try:
            description_readback = (
                _readback_authenticated_description(description)
                if description_readbacks is None
                else description_readbacks[position]
            )
            if description_readback.description is not description:
                raise TypeError
            expected = description_readback.expected_identity
            algorithms = description_readback.supported_algorithms
        except TypeError:
            raise UniverseIdentityError(
                "A genuine authenticated worker description is required."
            ) from None
        base = cast(Mapping[str, Any], expected["base_backend_identity"])
        owner = (cast(str, base["adapter_id"]), cast(str, expected["selected_algorithm_id"]))
        if owner in description_by_owner:
            raise UniverseIdentityError("An algorithm has more than one planning description.")
        selected = [row for row in algorithms if row["algorithm_id"] == owner[1]]
        if len(selected) != 1:
            raise UniverseIdentityError("The expected algorithm is absent from Describe.")
        description_by_owner[owner] = description
        description_readback_by_owner[owner] = description_readback
    selected_algorithms: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    algorithm_by_owner: dict[tuple[str, str], dict[str, Any]] = {}
    backend_schema_by_owner: dict[tuple[str, str], dict[str, Any]] = {}
    for backend in backends:
        owner = (cast(str, backend["adapter_id"]), cast(str, backend["algorithm_id"]))
        selected_description = description_by_owner.get(owner)
        if selected_description is None:
            raise UniverseIdentityError(
                "A selectable backend lacks authenticated Describe evidence."
            )
        description_readback = description_readback_by_owner[owner]
        expected = description_readback.expected_identity
        base = cast(Mapping[str, Any], expected["base_backend_identity"])
        selected = [
            row
            for row in description_readback.supported_algorithms
            if row["algorithm_id"] == owner[1]
        ]
        algorithm = _closed_copy(selected[0])
        if (
            base["adapter_id"] != backend["adapter_id"]
            or base["backend_name"] != backend["expected_backend_name"]
            or (
                backend["expected_backend_source_digest"] is not None
                and base["backend_source_digest"] != backend["expected_backend_source_digest"]
            )
            or expected["capabilities_digest"] != backend["capabilities_digest"]
            or capabilities_digest(algorithm["capabilities"]) != algorithm["capabilities_digest"]
            or algorithm["capabilities_digest"] != backend["capabilities_digest"]
            or settings_schema_digest(algorithm["settings_schema"])
            != algorithm["settings_schema_digest"]
            or algorithm["settings_schema_digest"] != backend["settings_schema_digest"]
            or stage_semantics_digest(algorithm["stage_semantics_definition"])
            != algorithm["stage_semantics_digest"]
            or algorithm["stage_semantics_digest"] != backend["stage_semantics_digest"]
            or algorithm["adapter_semantics_digest"] != backend["adapter_semantics_digest"]
        ):
            raise UniverseIdentityError("A selectable backend differs from authenticated Describe.")
        prior = algorithm_by_owner.setdefault(owner, algorithm)
        if prior != algorithm:
            raise UniverseIdentityError("One algorithm owner has conflicting descriptions.")
        backend_schema_by_owner[owner] = cast(dict[str, Any], algorithm["settings_schema"])
    if set(description_by_owner) != set(algorithm_by_owner):
        raise UniverseIdentityError("Planning descriptions must exactly cover selectable backends.")
    for owner in sorted(algorithm_by_owner, key=lambda row: (_utf8(row[0]), _utf8(row[1]))):
        algorithm = algorithm_by_owner[owner]
        description_snapshot = description_readback_by_owner[owner]
        matching = [row for row in backends if (row["adapter_id"], row["algorithm_id"]) == owner]
        exemplar = matching[0]
        selected_algorithms.append(copy.deepcopy(algorithm))
        try:
            binding = dict(description_snapshot.selected_algorithm_binding)
        except TypeError:
            raise UniverseIdentityError(
                "A selectable backend lacks one exact Describe-owned algorithm binding."
            ) from None
        if (
            binding["adapter_id"] != exemplar["adapter_id"]
            or binding["adapter_semantics_digest"] != exemplar["adapter_semantics_digest"]
            or binding["expected_backend_name"] != exemplar["expected_backend_name"]
            or (
                exemplar["expected_backend_source_digest"] is not None
                and binding["expected_backend_source_digest"]
                != exemplar["expected_backend_source_digest"]
            )
            or binding["algorithm_id"] != exemplar["algorithm_id"]
            or binding["capabilities_digest"] != exemplar["capabilities_digest"]
            or binding["settings_schema_digest"] != exemplar["settings_schema_digest"]
            or binding["stage_semantics_digest"] != exemplar["stage_semantics_digest"]
            or binding["description_response_metadata_digest"]
            != description_snapshot.response_metadata_digest
            or binding["expected_identity_pin_digest"]
            != description_snapshot.expected_identity_digest
        ):
            raise UniverseIdentityError(
                "A Describe-owned algorithm binding differs from verified configuration."
            )
        bindings.append(copy.deepcopy(binding))
    return selected_algorithms, bindings, algorithm_by_owner, backend_schema_by_owner


def _setting_kind(node: Mapping[str, Any]) -> tuple[str, bool]:
    declared = node.get("type")
    if isinstance(declared, list):
        values = set(declared)
        nullable = "null" in values
        values.discard("null")
        if len(values) != 1:
            raise UniverseIdentityError("A public setting has an ambiguous value kind.")
        kind = cast(str, next(iter(values)))
    elif isinstance(declared, str):
        kind = declared
        nullable = False
    else:
        raise UniverseIdentityError("A public setting omits its value kind.")
    if kind not in {"number", "integer", "boolean", "string", "array"}:
        raise UniverseIdentityError("A public setting uses an unsupported value kind.")
    return kind, nullable


def _setting_owner(
    *,
    owner_kind: str,
    adapter_id: str | None,
    owner_id: str,
    schema: Mapping[str, Any],
    selected_values: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    properties = cast(Mapping[str, Mapping[str, Any]], schema["properties"])
    definitions: list[dict[str, Any]] = []
    for setting_id in sorted(properties, key=_utf8):
        values_by_bytes: dict[bytes, object] = {}
        for selected in selected_values:
            if setting_id in selected:
                value = selected[setting_id]
                values_by_bytes[canonical_json_bytes(value)] = copy.deepcopy(value)
        if not values_by_bytes:
            raise UniverseIdentityError(
                "Every public backend setting requires an explicitly selected value."
            )
        kind, nullable = _setting_kind(properties[setting_id])
        definitions.append(
            {
                "setting_id": setting_id,
                "value_kind": kind,
                "nullable": nullable,
                "authorized_values": [values_by_bytes[key] for key in sorted(values_by_bytes)],
            }
        )
    return {
        "owner_kind": owner_kind,
        "adapter_id": adapter_id,
        "owner_id": owner_id,
        "settings_schema_digest": settings_schema_digest(schema),
        "ordered_parameters": definitions,
    }


_FIXED_EVENT_RESCALE_SETTINGS_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:ebm-audit:worker-settings-schema:fixed-event-rescale-v1:1",
    "type": "object",
    "additionalProperties": False,
    "required": ["scale_factor"],
    "properties": {
        "scale_factor": {"type": "number", "const": 2.0},
    },
}
_CORE_PREPROCESSING_SCHEMAS: dict[str, dict[str, Any]] = {
    "fixed-event-rescale-v1": _FIXED_EVENT_RESCALE_SETTINGS_SCHEMA,
}


def _registries(
    specs: Sequence[Mapping[str, Any]],
    algorithms: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]], dict[str, Any]]:
    backend_values: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    proposal_values: dict[str, list[Mapping[str, Any]]] = {}
    proposal_schemas: dict[str, dict[str, Any]] = {}
    preprocessing_values: dict[str, list[Mapping[str, Any]]] = {}
    public_schemas: dict[tuple[str, str], dict[str, Any]] = {}
    for spec in specs:
        backend = cast(Mapping[str, Any], spec["backend"])
        owner = (cast(str, backend["adapter_id"]), cast(str, backend["algorithm_id"]))
        algorithm = algorithms.get(owner)
        if algorithm is None:
            raise UniverseIdentityError("An AnalysisSpec uses an unauthenticated algorithm.")
        try:
            validate_settings(backend["settings"], algorithm["settings_schema"])
        except SchemaValidationError:
            raise UniverseIdentityError(
                "Backend settings violate authenticated Describe."
            ) from None
        backend_values.setdefault(owner, []).append(cast(Mapping[str, Any], backend["settings"]))
        proposal_schema = _validate_mcmc_equivalence(spec, algorithm)
        if proposal_schema is not None:
            mcmc = cast(Mapping[str, Any], spec["mcmc"])
            proposal_id = cast(str, mcmc["proposal_method_id"])
            prior = proposal_schemas.setdefault(proposal_id, proposal_schema)
            if prior != proposal_schema:
                raise UniverseIdentityError("One proposal owner has conflicting schemas.")
            proposal_values.setdefault(proposal_id, []).append(
                {row["name"]: row["value"] for row in mcmc["proposal_settings"]}
            )
        for transformation in cast(Sequence[Mapping[str, Any]], spec["preprocessing"]):
            method_id = cast(str, transformation["method_id"])
            schema = _CORE_PREPROCESSING_SCHEMAS.get(method_id)
            if schema is None:
                raise UniverseIdentityError(
                    "Preprocessing requires a source-controlled core settings registry."
                )
            preprocessing_values.setdefault(method_id, []).append(
                {
                    cast(str, row["name"]): row["value"]
                    for row in cast(
                        Sequence[Mapping[str, Any]],
                        transformation["parameters"],
                    )
                }
            )
    owners: list[dict[str, Any]] = []
    for owner in sorted(backend_values, key=lambda row: (_utf8(row[0]), _utf8(row[1]))):
        algorithm = algorithms[owner]
        schema = cast(Mapping[str, Any], algorithm["settings_schema"])
        owners.append(
            _setting_owner(
                owner_kind="backend-algorithm",
                adapter_id=owner[0],
                owner_id=owner[1],
                schema=schema,
                selected_values=backend_values[owner],
            )
        )
    schema_bindings: list[dict[str, Any]] = []
    core_schema_rows: list[dict[str, Any]] = []
    for proposal_id in sorted(proposal_schemas, key=_utf8):
        schema = proposal_schemas[proposal_id]
        public_schemas[("mcmc-proposal", proposal_id)] = schema
        owners.append(
            _setting_owner(
                owner_kind="mcmc-proposal",
                adapter_id=None,
                owner_id=proposal_id,
                schema=schema,
                selected_values=proposal_values[proposal_id],
            )
        )
        schema_bindings.append(
            {
                "owner_kind": "mcmc-proposal",
                "owner_id": proposal_id,
                "settings_schema_digest": settings_schema_digest(schema),
                "classification_rule_id": "validation-issued-public-scientific-settings/1",
            }
        )
        core_schema_rows.append(
            {
                "owner_kind": "mcmc-proposal",
                "owner_id": proposal_id,
                "settings_schema": schema,
            }
        )
    for method_id in sorted(preprocessing_values, key=_utf8):
        schema = _CORE_PREPROCESSING_SCHEMAS[method_id]
        public_schemas[("preprocessing-method", method_id)] = schema
        owners.append(
            _setting_owner(
                owner_kind="preprocessing-method",
                adapter_id=None,
                owner_id=method_id,
                schema=schema,
                selected_values=preprocessing_values[method_id],
            )
        )
        schema_bindings.append(
            {
                "owner_kind": "preprocessing-method",
                "owner_id": method_id,
                "settings_schema_digest": settings_schema_digest(schema),
                "classification_rule_id": (
                    "validation-issued-public-scientific-settings/1"
                ),
            }
        )
        core_schema_rows.append(
            {
                "owner_kind": "preprocessing-method",
                "owner_id": method_id,
                "settings_schema": schema,
            }
        )
    owners.sort(
        key=lambda row: _utf8(f"{row['owner_kind']}:{row['adapter_id'] or ''}:{row['owner_id']}")
    )
    core_registry = {
        "registry_schema_version": "ebm-audit-core-settings-registry/1.0",
        "ordered_schemas": core_schema_rows,
    }
    return (
        {
            "manifest_schema_version": "ebm-audit-public-intent-manifest/2.0",
            "registry_rule_id": "data-independent-public-scientific-intent-registry/1",
            "ordered_public_ids": [],
            "ordered_setting_owners": owners,
        },
        public_schemas,
        {"registry": core_registry, "schema_bindings": schema_bindings},
    )


def _planning_dataset_summary(
    prepared_dataset: PreparedAuditDataset, influence_rows: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    summary = prepared_dataset.summary.preimage
    return {
        "summary_schema_version": "ebm-audit-planning-dataset-summary/1.0",
        "participant_count": summary["participant_count"],
        "event_count": summary["event_count"],
        "group_spec_count": summary["group_spec_count"],
        "influence_expansion_cardinalities": copy.deepcopy(list(influence_rows)),
    }


def _planning_config(config: Mapping[str, Any], profile_id: str) -> dict[str, Any]:
    baseline_id = analysis_spec_content_id(config["baseline_analysis"])
    backend_registry = _scientific_backend_registry_preimage(config)
    return {
        "planning_config_schema_version": "ebm-audit-planning-config/2.0",
        "profile_id": profile_id,
        "baseline_analysis_spec_id": baseline_id,
        "source_variant_registry_digest": structured_sha256(
            "ebm-audit/source-variant-registry/2", config["source_variants"]
        ),
        "experiment_declarations_digest": structured_sha256(
            "ebm-audit/experiment-declarations/2", config["experiments"]
        ),
        "profiles_digest": structured_sha256("ebm-audit/execution-profiles/2", config["profiles"]),
        "scientific_backend_registry_digest": scientific_backend_registry_digest(backend_registry),
    }


def _build_material(
    config: Mapping[str, Any],
    profile_id: str,
    prepared_dataset: PreparedAuditDataset,
    supported_algorithms: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    participant_count = cast(int, prepared_dataset.summary.preimage["participant_count"])
    ordinary = _all_ordinary_specs(config)
    derived, replicated, named, influence = _derived_specs(
        config, profile_id, ordinary, participant_count
    )
    candidates, provenance = _candidate_rows([*ordinary, *derived], supported_algorithms)
    return {
        "candidates": candidates,
        "provenance": provenance,
        "declared_operation_expansions": {
            "replicated_operations": replicated,
            "named_group_removals": named,
        },
        "planning_dataset_summary": _planning_dataset_summary(prepared_dataset, influence),
    }


def _operation_method_ids(spec: Mapping[str, Any]) -> set[str]:
    found = {cast(str, spec["dataset_variant_intent"]["method_id"])}
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    for field in ("sampling_method_id", "removal_method_id", "null_method_id"):
        value = operation.get(field)
        if isinstance(value, str):
            found.add(value)
    transformation = spec["outlier_policy"].get("value_transformation")
    if isinstance(transformation, str):
        found.add(transformation)
    return found


def _caller_public_ids(
    config: Mapping[str, Any], ordinary_specs: Sequence[Mapping[str, Any]]
) -> list[dict[str, str]]:
    """Collect exact caller IDs directly from verified configuration only."""

    found: set[tuple[str, str]] = set()

    def add(namespace: str, value: object) -> None:
        if isinstance(value, str):
            found.add((namespace, value))

    def add_spec(spec: Mapping[str, Any]) -> None:
        found.update(_analysis_spec_public_ids(spec))
        found.update(("operation", value) for value in _operation_method_ids(spec))

    for spec in ordinary_specs:
        add_spec(spec)
    for variant in cast(Sequence[Mapping[str, Any]], config["source_variants"]):
        add("variant", variant["source_variant_id"])
        add("variant", variant["source_variant_id_ref"])
        add("operation", variant["method_id"])
    column_roles = cast(Mapping[str, Any], config["column_roles"])
    for event in cast(Sequence[Mapping[str, Any]], column_roles["events"]):
        add("event", event["event_id"])
    for group in cast(Sequence[Mapping[str, Any]], column_roles["groups"]):
        add("group", group["group_spec_id"])
    for covariate in cast(Sequence[Mapping[str, Any]], column_roles["covariates"]):
        add("covariate", covariate["covariate_id"])

    baseline = cast(Mapping[str, Any], config["baseline_analysis"])
    declarations = cast(Mapping[str, Any], config["experiments"])
    for experiment_set in cast(Sequence[Mapping[str, Any]], declarations["sets"]):
        if not experiment_set["enabled"]:
            continue
        add("experiment", experiment_set["experiment_set_id"])
        for axis in cast(Sequence[Mapping[str, Any]], experiment_set["axes"]):
            add("axis", axis["axis_id"])
            add("choice", axis["baseline_choice_id"])
            for choice in cast(Sequence[Mapping[str, Any]], axis["choices"]):
                add("choice", choice["choice_id"])
                projected = copy.deepcopy(dict(baseline))
                for assignment in cast(Sequence[Mapping[str, Any]], choice["assignments"]):
                    path = cast(str, assignment["path"])
                    projected[path.removeprefix("/")] = copy.deepcopy(assignment["value"])
                add_spec(projected)
        for member in cast(Sequence[Mapping[str, Any]], experiment_set["members"]):
            add("member", member["member_id"])
            for selected in cast(Sequence[Mapping[str, Any]], member.get("axis_choices", [])):
                add("axis", selected["axis_id"])
                add("choice", selected["choice_id"])
            custom = member.get("analysis_spec")
            if isinstance(custom, Mapping):
                add_spec(custom)

        for declaration_name in ("bootstrap", "subsample", "influence"):
            declaration = experiment_set.get(declaration_name)
            if not isinstance(declaration, Mapping):
                continue
            add("variant", declaration["source_variant_id"])
            add("variant", declaration["derived_source_variant_id"])
            for field in ("sampling_method_id", "removal_method_id"):
                add("operation", declaration.get(field))
            for group_id in cast(
                Sequence[object],
                declaration.get(
                    "strata_group_spec_ids",
                    declaration.get("named_group_spec_ids", []),
                ),
            ):
                add("group", group_id)
        for family in cast(Sequence[Mapping[str, Any]], experiment_set["null_families"]):
            add("null-family", family["null_family_id"])
            add("variant", family["source_variant_id"])
            add("variant", family["derived_source_variant_id"])
            add("operation", family["null_method_id"])
            add("group", family["within_group_spec_id"])

    return [
        {"namespace": namespace, "public_id": public_id}
        for namespace, public_id in sorted(found, key=lambda row: _utf8(f"{row[0]}:{row[1]}"))
    ]


def _expected_public_intent_material(
    config: Mapping[str, Any],
    algorithms_by_owner: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]], dict[str, Any]]:
    """Build the exact pre-data manifest from config and Describe only."""

    ordinary = _all_ordinary_specs(config)
    specs = [spec for spec, _context in ordinary]
    manifest, public_schemas, core = _registries(specs, algorithms_by_owner)
    manifest["ordered_public_ids"] = _caller_public_ids(config, specs)
    return manifest, public_schemas, core


@dataclass(frozen=True, repr=False)
class _PublicIntentOwner:
    authorization_id: str
    selected_algorithm_bindings_bytes: bytes


_PUBLIC_INTENT_OWNERS: OneShotWeakRegistry[object, _PublicIntentOwner]
_PUBLIC_INTENT_OWNER_ISSUER: OneShotRegistryIssuer[object, _PublicIntentOwner]
(
    _PUBLIC_INTENT_OWNERS,
    _PUBLIC_INTENT_OWNER_ISSUER,
) = create_one_shot_registry()


_EMBEDDED_TOKEN_PREFIX_LENGTH = 8
_COMMON_PATH_COMPONENTS = frozenset(
    {
        "applications",
        "code",
        "config",
        "configs",
        "data",
        "desktop",
        "documents",
        "downloads",
        "example",
        "examples",
        "home",
        "input",
        "library",
        "output",
        "private",
        "project",
        "projects",
        "repo",
        "repos",
        "run",
        "runs",
        "src",
        "test",
        "tests",
        "tmp",
        "users",
        "var",
        "volumes",
        "work",
        "workspace",
    }
)


@dataclass(frozen=True, repr=False)
class _PrivateTokenMatcher:
    """Typed exact, embedded, and bounded private-token rules.

    Source-column and raw-label strings are exact-only because short/common
    values such as ``group`` must not collide with unrelated public semantics.
    Private physical-variant label and provenance text use embedded matching at
    eight characters or longer and alphanumeric-boundary matching when shorter.
    String participant IDs use embedded matching when they are at least eight
    characters. Shorter nonempty string participant IDs use Unicode-alphanumeric
    boundary matching, deliberately failing closed for a standalone token such
    as ``P1`` while allowing it inside ``unrelatedP1word``. Integer IDs remain
    type-distinct and exact string coercion is forbidden. Full paths and
    path-derived tokens of at least eight characters use embedded matching;
    common directory components are excluded.
    """

    exact_tokens: frozenset[str]
    embedded_tokens: frozenset[str]
    bounded_tokens: frozenset[str]

    def collides(self, public_values: set[str]) -> bool:
        if self.exact_tokens.intersection(public_values):
            return True
        by_prefix: dict[str, list[str]] = {}
        for token in self.embedded_tokens:
            if len(token) < _EMBEDDED_TOKEN_PREFIX_LENGTH:
                continue
            by_prefix.setdefault(token[:_EMBEDDED_TOKEN_PREFIX_LENGTH], []).append(token)
        for value in public_values:
            last = len(value) - _EMBEDDED_TOKEN_PREFIX_LENGTH
            for offset in range(last + 1):
                candidates = by_prefix.get(
                    value[offset : offset + _EMBEDDED_TOKEN_PREFIX_LENGTH], ()
                )
                if any(value.startswith(token, offset) for token in candidates):
                    return True
        bounded_by_prefix: dict[str, list[str]] = {}
        for token in self.bounded_tokens:
            if token:
                bounded_by_prefix.setdefault(token[0], []).append(token)
        for value in public_values:
            for offset, character in enumerate(value):
                if offset and value[offset - 1].isalnum():
                    continue
                for token in bounded_by_prefix.get(character, ()):
                    if not value.startswith(token, offset):
                        continue
                    end = offset + len(token)
                    if end == len(value) or not value[end].isalnum():
                        return True
        return False


def _participant_embedded_token(value: str) -> bool:
    return len(value) >= _EMBEDDED_TOKEN_PREFIX_LENGTH


def _add_path_tokens(path: object, exact: set[str], embedded: set[str]) -> None:
    text = str(path)
    if not text:
        return
    exact.add(text)
    if len(text) >= _EMBEDDED_TOKEN_PREFIX_LENGTH:
        embedded.add(text)
    parsed = PurePath(text)
    for value in (parsed.name, parsed.stem):
        if value:
            exact.add(value)
            if len(value) >= _EMBEDDED_TOKEN_PREFIX_LENGTH:
                embedded.add(value)
    for component in parsed.parts:
        folded = component.casefold()
        if (
            component
            and component not in {parsed.anchor, "."}
            and folded not in _COMMON_PATH_COMPONENTS
        ):
            exact.add(component)
        if (
            len(component) >= _EMBEDDED_TOKEN_PREFIX_LENGTH
            and component != parsed.anchor
            and folded not in _COMMON_PATH_COMPONENTS
        ):
            embedded.add(component)


def _known_private_config_tokens(
    run_config: PlanEligibleAuditConfig | RunEligibleAuditConfig,
    config: Mapping[str, Any],
) -> _PrivateTokenMatcher:
    from ebm_audit.config.verification import (
        PlanEligibleAuditConfig,
        _verified_files_for_planning_config,
    )

    exact: set[str] = set()
    embedded: set[str] = set()
    bounded: set[str] = set()

    def add_private_text(value: object) -> None:
        if isinstance(value, str) and value:
            exact.add(value)
            if len(value) >= _EMBEDDED_TOKEN_PREFIX_LENGTH:
                embedded.add(value)
            else:
                bounded.add(value)

    input_format = cast(Mapping[str, Any], cast(Mapping[str, Any], config["input"])["format"])
    for row in cast(Sequence[Mapping[str, Any]], input_format["columns"]):
        source_column = row.get("source_column")
        if type(source_column) is not str:
            raise UniverseIdentityError("The configured physical-column catalog is invalid.")
        exact.add(source_column)
    for group in cast(Sequence[Mapping[str, Any]], config["column_roles"]["groups"]):
        for row in cast(Sequence[Mapping[str, Any]], group["label_to_role"]):
            raw = cast(Mapping[str, Any], row["label"])["value"]
            if isinstance(raw, str):
                exact.add(raw)
    physical_variant = cast(Mapping[str, Any], cast(Mapping[str, Any], config["input"])["variant"])
    add_private_text(physical_variant["label"])
    add_private_text(physical_variant["provenance_note"])
    verified_files = (
        _verified_files_for_planning_config(run_config)
        if type(run_config) is PlanEligibleAuditConfig
        else run_config._verified_files
    )
    paths = verified_files._resolved.private_paths
    for path in (
        paths.source_config,
        paths.input_table,
        paths.worker_config,
        paths.output_root,
        paths.baseline_reference,
        paths.external_missingness_variant,
    ):
        if path is not None:
            _add_path_tokens(path, exact, embedded)
    return _PrivateTokenMatcher(
        exact_tokens=frozenset(exact),
        embedded_tokens=frozenset(embedded),
        bounded_tokens=frozenset(bounded),
    )


def _activate_public_intent_manifest(
    run_config: PlanEligibleAuditConfig | RunEligibleAuditConfig,
    config: Mapping[str, Any],
    manifest: Mapping[str, Any],
    selected_algorithm_bindings: Sequence[Mapping[str, Any]],
) -> PublicIntentManifest:
    public_values = _typed_public_content_strings(
        manifest,
        definition="PublicIntentManifestDigestPreimage",
    )
    if _known_private_config_tokens(run_config, config).collides(public_values):
        raise UniverseIdentityError(
            "The public intent manifest contains a private configuration token."
        )
    capability = _issue_public_intent_manifest(manifest)
    _PUBLIC_INTENT_OWNER_ISSUER.bind_once(
        capability,
        _PublicIntentOwner(
            authorization_id=run_config.authorization_id,
            selected_algorithm_bindings_bytes=canonical_json_bytes(selected_algorithm_bindings),
        ),
    )
    _require_exact_public_intent_manifest(
        capability,
        authorization_id=run_config.authorization_id,
        selected_algorithm_bindings=selected_algorithm_bindings,
        expected_manifest=manifest,
    )
    return capability


def issue_public_intent_manifest(
    run_config: PlanEligibleAuditConfig | RunEligibleAuditConfig,
    authenticated_descriptions: Sequence[AuthenticatedWorkerDescription],
) -> PublicIntentManifest:
    """Issue caller-owned public intent before any prepared dataset exists."""

    from ebm_audit.config.verification import (
        PlanEligibleAuditConfig,
        RunEligibleAuditConfig,
        _plan_eligible_owns_descriptions,
        _verified_files_for_planning_config,
    )

    if type(run_config) not in {PlanEligibleAuditConfig, RunEligibleAuditConfig}:
        raise UniverseIdentityError("A genuine planning configuration is required.")
    run_config.assert_ready()
    config = run_config.private_config
    descriptions = tuple(authenticated_descriptions)
    if type(run_config) is PlanEligibleAuditConfig and not _plan_eligible_owns_descriptions(
        run_config, descriptions
    ):
        raise UniverseIdentityError(
            "The plan-eligible configuration does not own this authenticated Describe."
        )
    _verified_files_for_planning_config(run_config)
    _algorithms, bindings, algorithms_by_owner, _backend_schemas = _resolve_algorithms(
        config, descriptions
    )
    manifest, _public_schemas, _core = _expected_public_intent_material(config, algorithms_by_owner)
    return _activate_public_intent_manifest(run_config, config, manifest, bindings)


def _require_exact_public_intent_manifest(
    capability: PublicIntentManifest,
    *,
    authorization_id: str,
    selected_algorithm_bindings: Sequence[Mapping[str, Any]],
    expected_manifest: Mapping[str, Any],
) -> None:
    if type(capability) is not PublicIntentManifest:
        raise UniverseIdentityError("A genuine public intent manifest is required.")
    expected_owner = _PublicIntentOwner(
        authorization_id=authorization_id,
        selected_algorithm_bindings_bytes=canonical_json_bytes(selected_algorithm_bindings),
    )
    try:
        observed_owner = _PUBLIC_INTENT_OWNERS[capability]
        observed_manifest = capability.preimage
    except (KeyError, TypeError):
        raise UniverseIdentityError("A genuine public intent manifest is required.") from None
    if observed_owner != expected_owner or not hmac.compare_digest(
        canonical_json_bytes(observed_manifest), canonical_json_bytes(expected_manifest)
    ):
        raise UniverseIdentityError(
            "The public intent manifest differs from verified config and Describe."
        )


def _activate_planning_authority(state: _PlanningAuthorityState) -> PlanningAuthority:
    """Issue only after exact rebuild and privacy scans have both succeeded."""

    if type(state) is not _PlanningAuthorityState:
        raise TypeError("A closed planning-authority state is required.")
    capability = object.__new__(PlanningAuthority)
    plan = _rebuild_plan_from_state(state)
    _scan_private_tokens(plan, state)
    _PLANNING_AUTHORITY_STATE_ISSUER.bind_once(capability, state)
    if _rebuild_plan(capability) != plan:
        raise TypeError("Planning authority changed during final validation.")
    return capability


def issue_planning_authority(
    run_config: PlanEligibleAuditConfig | RunEligibleAuditConfig,
    prepared_dataset: PreparedAuditDataset,
    authenticated_descriptions: Sequence[AuthenticatedWorkerDescription],
    *,
    public_intent_manifest: PublicIntentManifest,
    profile_id: str,
) -> PlanningAuthority:
    """Validate exact owners and issue the only Plan/3 compiler capability."""

    from ebm_audit.config.verification import (
        PlanEligibleAuditConfig,
        RunEligibleAuditConfig,
        _plan_eligible_owns_descriptions,
        _verified_files_for_planning_config,
    )
    from ebm_audit.data.identity import generate_namespace_key
    from ebm_audit.data.preparation import PreparedAuditDataset, _private_prepared_dataset

    if type(run_config) not in {PlanEligibleAuditConfig, RunEligibleAuditConfig}:
        raise UniverseIdentityError("A genuine planning configuration is required.")
    if type(prepared_dataset) is not PreparedAuditDataset:
        raise UniverseIdentityError("A genuine prepared audit dataset is required.")
    if profile_id not in _PROFILE_IDS:
        raise UniverseIdentityError("The planning profile is not registered.")
    run_config.assert_ready()
    try:
        _private_prepared_dataset(prepared_dataset)
    except TypeError:
        raise UniverseIdentityError("A genuine prepared audit dataset is required.") from None
    if prepared_dataset.authorization_id != run_config.authorization_id:
        raise UniverseIdentityError("The prepared dataset belongs to another authorization.")
    summary = prepared_dataset.summary.preimage
    if summary["resolved_config_digest"] != run_config.resolved_public_digest:
        raise UniverseIdentityError("The prepared summary belongs to another resolved config.")
    config = run_config.private_config
    planning_config = _planning_config(config, profile_id)
    public_projection = _verified_files_for_planning_config(run_config)._resolved.public_projection
    for field in (
        "baseline_analysis_spec_id",
        "source_variant_registry_digest",
        "experiment_declarations_digest",
        "profiles_digest",
        "scientific_backend_registry_digest",
    ):
        if planning_config[field] != public_projection[field]:
            raise UniverseIdentityError("The planning config differs from its resolved owner.")
    descriptions = tuple(authenticated_descriptions)
    if type(run_config) is PlanEligibleAuditConfig and not _plan_eligible_owns_descriptions(
        run_config, descriptions
    ):
        raise UniverseIdentityError(
            "The plan-eligible configuration does not own this authenticated Describe."
        )
    from ebm_audit.adapters.invocation import _capture_authenticated_description

    captured_descriptions = tuple(
        _capture_authenticated_description(description) for description in descriptions
    )
    description_states = tuple(state for state, _readback in captured_descriptions)
    description_readbacks = tuple(readback for _state, readback in captured_descriptions)
    algorithms, selected_bindings, algorithms_by_owner, backend_schemas = _resolve_algorithms(
        config,
        descriptions,
        description_readbacks=description_readbacks,
    )
    expected_manifest, public_schemas, core = _expected_public_intent_material(
        config, algorithms_by_owner
    )
    _require_exact_public_intent_manifest(
        public_intent_manifest,
        authorization_id=run_config.authorization_id,
        selected_algorithm_bindings=selected_bindings,
        expected_manifest=expected_manifest,
    )
    material = _build_material(config, profile_id, prepared_dataset, algorithms)
    core_registry = cast(dict[str, Any], core["registry"])
    summary_binding = {
        "binding_schema_version": "ebm-audit-validated-planning-summary-binding/2.0",
        "run_authorization_id": run_config.authorization_id,
        "resolved_public_config_digest": run_config.resolved_public_digest,
        "prepared_audit_dataset_id": prepared_dataset.prepared_dataset_id,
        "validated_dataset_summary_digest": prepared_dataset.summary_digest,
        "public_intent_manifest_digest": public_intent_manifest.manifest_digest,
        "scientific_backend_registry_digest": planning_config["scientific_backend_registry_digest"],
        "core_settings_registry_digest": structured_sha256(
            "ebm-audit/core-settings-registry/1", core_registry
        ),
        "planning_dataset_summary": material["planning_dataset_summary"],
        "selected_algorithm_bindings": selected_bindings,
        "public_settings_schema_bindings": core["schema_bindings"],
    }
    planning_summary = _issue_validated_planning_summary(summary_binding)
    all_schemas = {
        f"backend-algorithm:{adapter}:{algorithm}": schema
        for (adapter, algorithm), schema in backend_schemas.items()
    }
    all_schemas.update(
        {f"{kind}:{owner}": schema for (kind, owner), schema in public_schemas.items()}
    )
    execution_enabled = type(run_config) is RunEligibleAuditConfig
    state = _PlanningAuthorityState(
        run_config=run_config,
        prepared_dataset=prepared_dataset,
        authenticated_descriptions=descriptions,
        authenticated_description_states=description_states,
        authenticated_description_readbacks=description_readbacks,
        profile_id=profile_id,
        private_config_bytes=canonical_json_bytes(config),
        planning_config_bytes=canonical_json_bytes(planning_config),
        planning_summary=planning_summary,
        public_intent_manifest=public_intent_manifest,
        supported_algorithms_bytes=canonical_json_bytes(algorithms),
        public_settings_schemas_bytes=canonical_json_bytes(all_schemas),
        core_settings_registry_bytes=canonical_json_bytes(core_registry),
        selected_algorithm_bindings_bytes=canonical_json_bytes(selected_bindings),
        preparation_namespace_key=generate_namespace_key() if execution_enabled else None,
        preparation_publication=_PreparationPublication() if execution_enabled else None,
        preparation_publication_token=object() if execution_enabled else None,
    )
    return _activate_planning_authority(state)


def _plan_counts(candidates: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    by_experiment_set, by_axis, by_operation = _expected_plan_partitions(candidates)
    return {
        "candidate_count": len(candidates),
        "origin_count": sum(1 + len(row["duplicate_origins"]) for row in candidates),
        "additional_origin_count": sum(len(row["duplicate_origins"]) for row in candidates),
        "planned_candidate_count": sum(row["planning_outcome"] == "PLANNED" for row in candidates),
        "plan_ineligible_candidate_count": sum(
            row["planning_outcome"] == "PLAN_INELIGIBLE" for row in candidates
        ),
        "seedless_chain_slot_count": sum(len(row["chain_slots"]) for row in candidates),
        "planned_fit_ceiling": sum(row["planned_fit_ceiling"] for row in candidates),
        "by_experiment_set": by_experiment_set,
        "by_axis": by_axis,
        "by_operation": by_operation,
    }


def _budget(
    config: Mapping[str, Any], profile_id: str, material: Mapping[str, Any]
) -> dict[str, Any]:
    profile = cast(Mapping[str, Any], cast(Mapping[str, Any], config["profiles"])[profile_id])
    candidates = cast(Sequence[Mapping[str, Any]], material["candidates"])
    ordinary_count = sum(
        row["analysis_spec"]["operation_intent"]["kind"] == "ordinary" for row in candidates
    )
    fit_count = sum(cast(int, row["planned_fit_ceiling"]) for row in candidates)
    summary = cast(Mapping[str, Any], material["planning_dataset_summary"])
    influence_counts = [
        cast(int, row["eligible_target_count"])
        for row in cast(Sequence[Mapping[str, Any]], summary["influence_expansion_cardinalities"])
    ]
    influence_counts.extend(
        len(row["ordered_named_group_spec_ids"])
        for row in material["declared_operation_expansions"]["named_group_removals"]
    )
    maximum_influence = max(influence_counts, default=0)
    reasons: list[str] = []
    if ordinary_count > profile["ordinary_universe_limit"]:
        reasons.append("BUDGET.ORDINARY_CANDIDATE_LIMIT_EXCEEDED")
    if fit_count > profile["max_total_fits"]:
        reasons.append("BUDGET.FIT_LIMIT_EXCEEDED")
    if maximum_influence > profile["influence_max_removals"]:
        reasons.append("BUDGET.INFLUENCE_REMOVAL_LIMIT_EXCEEDED")
    return {
        "profile_id": profile_id,
        "ordinary_candidate_limit": profile["ordinary_universe_limit"],
        "fit_limit": profile["max_total_fits"],
        "influence_removal_limit": profile["influence_max_removals"],
        "max_parallel_workers": profile["max_parallel_workers"],
        "planned_ordinary_candidate_count": ordinary_count,
        "planned_fit_ceiling": fit_count,
        "maximum_scoped_exact_influence_count": maximum_influence,
        "decision": "BUDGET_EXCEEDED" if reasons else "WITHIN_BUDGET",
        "reason_codes": reasons,
    }


def _state_schemas(state: _PlanningAuthorityState) -> dict[tuple[str, str], dict[str, Any]]:
    stored = _load_object(state.public_settings_schemas_bytes)
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for key, schema in stored.items():
        parts = key.split(":")
        if parts[0] == "backend-algorithm":
            result[(parts[0], f"{parts[1]}:{parts[2]}")] = schema
        else:
            result[(parts[0], parts[1])] = schema
    return result


def _worker_owner_for_state(
    state: _PlanningAuthorityState,
    adapter_id: str,
    algorithm_id: str,
) -> _PlanningWorkerOwner:
    """Resolve one worker owner from one already authenticated authority snapshot."""

    if type(state) is not _PlanningAuthorityState:
        raise TypeError("A genuine planning-authority state is required.")
    _assert_planning_description_states_current(state)
    if not (
        len(state.authenticated_descriptions)
        == len(state.authenticated_description_states)
        == len(state.authenticated_description_readbacks)
    ):
        raise TypeError("Planning authority Describe ownership is incomplete.")
    matching_description = None
    matching_description_state = None
    matching_readback = None
    for description, description_state, readback in zip(
        state.authenticated_descriptions,
        state.authenticated_description_states,
        state.authenticated_description_readbacks,
        strict=True,
    ):
        if readback.description is not description:
            raise TypeError("Planning authority Describe ownership is invalid.")
        expected = readback.expected_identity
        base = cast(Mapping[str, Any], expected["base_backend_identity"])
        if base["adapter_id"] == adapter_id and expected["selected_algorithm_id"] == algorithm_id:
            if matching_description is not None:
                raise TypeError("The planning authority has duplicate authenticated descriptions.")
            matching_description = description
            matching_description_state = description_state
            matching_readback = readback
    if (
        matching_description is None
        or matching_description_state is None
        or matching_readback is None
    ):
        raise KeyError("The planning authority has no authenticated description for that owner.")
    rows = _load_array(state.selected_algorithm_bindings_bytes)
    bindings = [
        row
        for row in rows
        if row["adapter_id"] == adapter_id and row["algorithm_id"] == algorithm_id
    ]
    if len(bindings) != 1 or dict(matching_readback.selected_algorithm_binding) != bindings[0]:
        raise TypeError("The planning authority has no exact selected algorithm binding.")
    return _PlanningWorkerOwner(
        description=matching_description,
        description_state=matching_description_state,
        description_readback=matching_readback,
        selected_algorithm_binding=copy.deepcopy(bindings[0]),
    )


def _assert_planning_description_states_current(
    state: _PlanningAuthorityState,
) -> None:
    """Reject any replacement of a retained authenticated Describe state."""

    from ebm_audit.adapters.invocation import _AUTHENTICATED_DESCRIPTION_STATES

    if type(state) is not _PlanningAuthorityState or not (
        len(state.authenticated_descriptions)
        == len(state.authenticated_description_states)
        == len(state.authenticated_description_readbacks)
    ):
        raise TypeError("Planning authority Describe ownership is invalid.")
    for description, expected_state, readback in zip(
        state.authenticated_descriptions,
        state.authenticated_description_states,
        state.authenticated_description_readbacks,
        strict=True,
    ):
        if (
            _AUTHENTICATED_DESCRIPTION_STATES.get(description) is not expected_state
            or readback.description is not description
        ):
            raise TypeError("Planning authority Describe state changed.")


def _rebuild_plan_from_state(state: _PlanningAuthorityState) -> dict[str, Any]:
    """Rebuild Plan/3 from one already authenticated authority snapshot."""

    if type(state) is not _PlanningAuthorityState:
        raise TypeError("A genuine planning-authority state is required.")
    _assert_planning_description_states_current(state)
    state.run_config.assert_ready()
    if state.prepared_dataset.authorization_id != state.run_config.authorization_id:
        raise UniverseIdentityError("Planning authority owners changed.")
    config = _load_object(state.private_config_bytes)
    planning_config = _load_object(state.planning_config_bytes)
    recomputed_planning_config = _planning_config(config, state.profile_id)
    if recomputed_planning_config != planning_config:
        raise UniverseIdentityError("The sealed planning config cannot be exactly rebuilt.")
    material = _build_material(
        config,
        state.profile_id,
        state.prepared_dataset,
        _load_array(state.supported_algorithms_bytes),
    )
    candidates = cast(list[dict[str, Any]], material["candidates"])
    baseline_id = cast(str, planning_config["baseline_analysis_spec_id"])
    preimage = {
        "plan_schema_version": "ebm-audit-analysis-plan/3.0",
        "compiler_code_digest": _COMPILER_CODE_DIGEST,
        "planning_config_digest": planning_config_digest(planning_config),
        "public_intent_manifest_digest": state.public_intent_manifest.manifest_digest,
        "baseline_analysis_spec_id": baseline_id,
        "declaration_provenance_registry": material["provenance"],
        "declaration_resolution_registry": _expected_declaration_resolutions(candidates),
        "origin_comparison_edges": _expected_origin_comparison_edges(candidates, baseline_id),
        "planning_dataset_summary": material["planning_dataset_summary"],
        "declared_operation_expansions": material["declared_operation_expansions"],
        "candidate_ordering_rule": "primary-origin-id-then-candidate-id-utf8/1",
        "candidates": candidates,
        "counts": _plan_counts(candidates),
        "runtime_estimate": {
            "estimated_seconds": None,
            "status": "UNVERIFIED",
            "evidence_source": "core-unverified",
            "evidence_digest": None,
        },
        "budget_decision": _budget(config, state.profile_id, material),
    }
    plan = {**preimage, "plan_digest": analysis_plan_digest(preimage)}
    _schema_validate(plan, "AnalysisPlan")
    schemas = _state_schemas(state)
    public_schemas: dict[tuple[str, str], Mapping[str, Any]] = {}
    for (kind, owner), schema in schemas.items():
        if kind == "backend-algorithm":
            adapter_id, algorithm_id = owner.split(":", 1)
            public_schemas[(adapter_id, algorithm_id)] = schema
        else:
            public_schemas[(kind, owner)] = schema
    _verify_analysis_plan_contract(
        plan,
        planning_config,
        state.planning_summary.binding["planning_dataset_summary"],
        _load_array(state.supported_algorithms_bytes),
        public_schemas,
        state.public_intent_manifest.preimage,
    )
    return plan


def _rebuild_plan(authority: PlanningAuthority) -> dict[str, Any]:
    return _rebuild_plan_from_state(authority._state())


def _decode_json_pointer_token(value: str) -> str:
    return value.replace("~1", "/").replace("~0", "~")


def _resolve_privacy_schema_ref(
    ref: str,
    *,
    current_document: str,
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[str, Mapping[str, Any], str | None]:
    resource, separator, fragment = ref.partition("#")
    document_name = resource or current_document
    if document_name not in _PRIVACY_SCHEMA_DOCUMENTS or document_name not in documents:
        raise UniverseIdentityError("A privacy surface references an unknown schema resource.")
    target: object = documents[document_name]
    definition: str | None = None
    if separator:
        if fragment and not fragment.startswith("/"):
            raise UniverseIdentityError("A privacy surface has an unsupported schema reference.")
        tokens = fragment.removeprefix("/").split("/") if fragment else []
        for index, raw_token in enumerate(tokens):
            token = _decode_json_pointer_token(raw_token)
            if index == 1 and tokens[0] == "$defs":
                definition = token
            if not isinstance(target, Mapping) or token not in target:
                raise UniverseIdentityError("A privacy surface schema reference is unresolved.")
            target = target[token]
    if not isinstance(target, Mapping):
        raise UniverseIdentityError("A privacy surface schema reference is not an object.")
    return document_name, cast(Mapping[str, Any], target), definition


def _privacy_path_excludes_generated_string(path: tuple[str | int, ...]) -> bool:
    field = next((part for part in reversed(path) if isinstance(part, str)), None)
    if field in _PRIVACY_COMPILER_GENERATED_STRING_FIELDS:
        return True
    # This partition contains fixed operation-kind labels. The sibling
    # experiment-set and axis partitions contain caller-owned public IDs.
    return (
        len(path) >= 4
        and path[-4] == "counts"
        and path[-3] == "by_operation"
        and isinstance(path[-2], int)
        and path[-1] == "id"
    ) or (len(path) >= 2 and path[-2:] == ("budget_decision", "profile_id"))


def _typed_public_content_strings(
    value: Mapping[str, Any],
    *,
    definition: str,
) -> set[str]:
    """Extract only schema-typed caller/data content from one public surface.

    Fixed schema constants and enums are protocol structure, even when their
    text happens to equal a private column or label. Digests and the small set
    of compiler-generated MachineIds are likewise not caller/data content.
    Dynamic MachineId property names and string setting values remain visible.
    The same path-aware walk owns both manifest and final-plan privacy scans.
    """

    if definition not in _PRIVACY_SURFACE_DEFINITIONS:
        raise UniverseIdentityError("An unknown privacy surface was requested.")
    _schema_validate(value, definition)
    documents = {name: load_schema(name) for name in sorted(_PRIVACY_SCHEMA_DOCUMENTS, key=_utf8)}
    root = documents["analysis-universe.schema.json"].get("$defs")
    if not isinstance(root, Mapping) or not isinstance(root.get(definition), Mapping):
        raise UniverseIdentityError("The privacy surface schema is unavailable.")
    found: set[str] = set()

    def visit(
        node: object,
        schema: Mapping[str, Any],
        *,
        document_name: str,
        path: tuple[str | int, ...],
    ) -> None:
        ref = schema.get("$ref")
        if isinstance(ref, str):
            target_document, target, target_definition = _resolve_privacy_schema_ref(
                ref,
                current_document=document_name,
                documents=documents,
            )
            if target_definition not in _PRIVACY_OPAQUE_STRING_DEFINITIONS:
                visit(node, target, document_name=target_document, path=path)

        # Constants and enumerations are schema vocabulary, not leaked content.
        if "const" in schema or "enum" in schema:
            return

        for keyword in ("allOf", "anyOf", "oneOf"):
            branches = schema.get(keyword)
            if isinstance(branches, Sequence) and not isinstance(branches, (str, bytes, bytearray)):
                for branch in branches:
                    if isinstance(branch, Mapping):
                        visit(
                            node,
                            cast(Mapping[str, Any], branch),
                            document_name=document_name,
                            path=path,
                        )

        if isinstance(node, Mapping):
            properties_value = schema.get("properties")
            properties = (
                cast(Mapping[str, Any], properties_value)
                if isinstance(properties_value, Mapping)
                else {}
            )
            property_names = schema.get("propertyNames")
            additional = schema.get("additionalProperties")
            for raw_key, child in node.items():
                if not isinstance(raw_key, str):
                    raise UniverseIdentityError("A privacy surface contains a non-string key.")
                child_path = (*path, raw_key)
                child_schema = properties.get(raw_key)
                if isinstance(child_schema, Mapping):
                    visit(
                        child,
                        cast(Mapping[str, Any], child_schema),
                        document_name=document_name,
                        path=child_path,
                    )
                elif isinstance(additional, Mapping):
                    visit(
                        child,
                        cast(Mapping[str, Any], additional),
                        document_name=document_name,
                        path=child_path,
                    )
                if raw_key not in properties and isinstance(property_names, Mapping):
                    visit(
                        raw_key,
                        cast(Mapping[str, Any], property_names),
                        document_name=document_name,
                        path=(*path, "<property-name>"),
                    )
            return

        if isinstance(node, Sequence) and not isinstance(node, (str, bytes, bytearray, memoryview)):
            items = schema.get("items")
            if isinstance(items, Mapping):
                for index, child in enumerate(node):
                    visit(
                        child,
                        cast(Mapping[str, Any], items),
                        document_name=document_name,
                        path=(*path, index),
                    )
            return

        if not isinstance(node, str) or schema.get("type") != "string":
            return
        field = next((part for part in reversed(path) if isinstance(part, str)), "")
        if field.endswith("_digest") or _privacy_path_excludes_generated_string(path):
            return
        found.add(node)

    visit(
        value,
        cast(Mapping[str, Any], root[definition]),
        document_name="analysis-universe.schema.json",
        path=(),
    )
    return found


def _scan_private_tokens(plan: Mapping[str, Any], state: _PlanningAuthorityState) -> None:
    from ebm_audit.data.preparation import _private_prepared_dataset

    config = _load_object(state.private_config_bytes)
    prepared = _private_prepared_dataset(state.prepared_dataset)
    known = _known_private_config_tokens(state.run_config, config)
    exact = set(known.exact_tokens)
    embedded = set(known.embedded_tokens)
    bounded = set(known.bounded_tokens)
    catalog = cast(Mapping[str, Any], prepared.catalog)
    for row in cast(Sequence[Mapping[str, Any]], catalog["physical_columns"]):
        source_column = row.get("source_column")
        if type(source_column) is not str:
            raise UniverseIdentityError("The prepared physical-column catalog is invalid.")
        exact.add(source_column)
    exact.add(str(catalog["participant_private_id_column"]))
    participant_column = cast(str, catalog["participant_private_id_column"])
    for value in prepared.private_table[participant_column]:
        if isinstance(value, str):
            exact.add(value)
            if _participant_embedded_token(value):
                embedded.add(value)
            elif value:
                bounded.add(value)
        # Integer identifiers remain type-distinct. Stringifying them here
        # would make ordinary public counts or rule parameters look like leaks.
    public_values = _typed_public_content_strings(plan, definition="AnalysisPlan")
    public_values.update(
        _typed_public_content_strings(
            state.public_intent_manifest.preimage,
            definition="PublicIntentManifestDigestPreimage",
        )
    )
    matcher = _PrivateTokenMatcher(
        exact_tokens=frozenset(exact),
        embedded_tokens=frozenset(embedded),
        bounded_tokens=frozenset(bounded),
    )
    if matcher.collides(public_values):
        raise UniverseIdentityError("A public planning artifact contains a private source token.")


def compile_analysis_plan(authority: PlanningAuthority) -> dict[str, Any]:
    """Compile one Plan/3 only from a genuine in-process authority."""

    if type(authority) is not PlanningAuthority:
        raise UniverseIdentityError("A genuine planning authority is required.")
    try:
        plan = _rebuild_plan(authority)
        _scan_private_tokens(plan, authority._state())
    except TypeError:
        raise UniverseIdentityError("A genuine planning authority is required.") from None
    return copy.deepcopy(plan)


def _verify_analysis_plan(plan: Mapping[str, Any], authority: PlanningAuthority) -> None:
    """Rebuild, byte-compare, scan, and then check every Plan/3 invariant."""

    if type(authority) is not PlanningAuthority:
        raise UniverseIdentityError("A genuine planning authority is required.")
    try:
        supplied = _closed_copy(plan)
        expected = _rebuild_plan(authority)
        if not hmac.compare_digest(canonical_json_bytes(supplied), canonical_json_bytes(expected)):
            raise UniverseIdentityError("The plan differs from its exact authority rebuild.")
        state = authority._state()
        _scan_private_tokens(supplied, state)
        _scan_private_tokens(expected, state)
    except TypeError:
        raise UniverseIdentityError("A genuine planning authority is required.") from None
