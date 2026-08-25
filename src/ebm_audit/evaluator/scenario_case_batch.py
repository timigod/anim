"""Opaque authority for authenticated public synthetic scenario case coverage."""

from __future__ import annotations

import copy
import secrets
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any, Final, Literal, Never, SupportsIndex, cast, final
from weakref import WeakSet

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.config.strict_yaml import StrictYamlError, load_strict_yaml_bytes
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256,
    structured_sha256_hex,
)
from ebm_audit.synthetic.authority import ScenarioAuthority, load_scenario_authority
from ebm_audit.synthetic.models import (
    AuthenticatedSourceOwner,
    CaseCoordinate,
    ResolvedSyntheticCase,
)
from ebm_audit.synthetic.resolver import resolve_development_case

if TYPE_CHECKING:
    from ebm_audit.synthetic.audit_input import _SyntheticMissingnessProjection

_SUBJECT_DOMAIN: Final = "ebm-audit/authenticated-benchmark-subject/1"
_BATCH_DOMAIN: Final = "ebm-audit/authenticated-scenario-case-batch/1"
_CONTRACT_DOMAIN: Final = "ebm-audit/benchmark-contract/1"
_SCENARIO_DOMAIN: Final = "ebm-audit/scenario-definitions/1"
_CANDIDATE_DOMAIN: Final = "ebm-audit/candidate-tree/1"
_PUBLIC_BATCH_CONTEXT_DOMAIN: Final = "ebm-audit/public-batch-context/1"
_PUBLIC_BATCH_CASE_PLAN_DOMAIN: Final = "ebm-audit/public-batch-case-plan/1"
_MAXIMUM_YAML_BYTES: Final = 16 * 1024 * 1024
_SOURCE_IDENTITY_ROLES: Final = (
    "generator_sha256",
    "metrics_rules_sha256",
    "report_language_rules_sha256",
    "evaluator_source_sha256",
    "normative_authority_sha256",
)


def _validated_ordered_source_hashes(value: object) -> list[dict[str, str]]:
    """Return the exact ordered provenance vector without compatibility aliases."""

    if type(value) is not list or len(value) != len(_SOURCE_IDENTITY_ROLES):
        _reject("SUBJECT_IDENTITY")
    validated: list[dict[str, str]] = []
    for expected_role, row in zip(_SOURCE_IDENTITY_ROLES, value, strict=True):
        if (
            type(row) is not dict
            or set(row) != {"source_role", "sha256"}
            or row.get("source_role") != expected_role
            or not _is_sha256(row.get("sha256"))
        ):
            _reject("SUBJECT_IDENTITY")
        validated.append(
            {
                "source_role": expected_role,
                "sha256": cast(str, row["sha256"]),
            }
        )
    return validated


def _reject(code: str) -> Never:
    raise InvalidInputError(
        f"EVALUATOR.SCENARIO_CASE_BATCH_{code}",
        "The authenticated synthetic case batch failed closed validation.",
    )


def _json_copy(value: object) -> object:
    try:
        return strict_json_loads(canonical_json_bytes(value))
    except CanonicalizationError:
        _reject("JSON")


@dataclass(frozen=True, slots=True)
class _SubjectState:
    projection_bytes: bytes
    scenario_bytes: bytes
    expected_coordinates: tuple[CaseCoordinate, ...]


@dataclass(slots=True)
class _BatchState:
    projection_bytes: bytes
    subject: AuthenticatedBenchmarkSubject
    scenario_bytes: bytes
    resolved_cases: tuple[ResolvedSyntheticCase, ...]
    case_contexts: tuple[_AuthenticatedCaseContext, ...]
    manifest_authentication_key: bytes
    issued_public_input_identities: set[tuple[str, str]]
    public_case_plan_owners: tuple[object, ...] | None
    lock: RLock


@dataclass(frozen=True, slots=True)
class _AuthenticatedCaseContext:
    family_id: str
    case_id: str
    source_contract_sha256: str
    scenario_source_sha256: str
    subtype: str | None
    boundary_rule_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _AuthenticatedBatchContext:
    benchmark_subject_digest: str
    report_rule_registry_sha256: str
    cases: tuple[_AuthenticatedCaseContext, ...]


@dataclass(frozen=True, slots=True)
class _PublicBatchCasePlanState:
    projection_bytes: bytes
    batch: AuthenticatedScenarioCaseBatch
    input_owner: object
    truth_evidence: object
    ordered_analysis_spec_ids: tuple[str, ...]


_SUBJECT_STATES: OneShotWeakRegistry[object, _SubjectState]
_SUBJECT_STATES, _SUBJECT_ISSUER = create_one_shot_registry()
_BATCH_STATES: OneShotWeakRegistry[object, _BatchState]
_BATCH_STATES, _BATCH_ISSUER = create_one_shot_registry()
_PUBLIC_CASE_PLAN_STATES: OneShotWeakRegistry[object, _PublicBatchCasePlanState]
_PUBLIC_CASE_PLAN_STATES, _PUBLIC_CASE_PLAN_ISSUER = create_one_shot_registry()
_SUBJECT_ISSUER_CLAIMS: WeakSet[type[object]] = WeakSet()
_SUBJECT_ISSUER_CLAIM_LOCK = RLock()
_PUBLIC_SYNTHETIC_MANIFEST_BOUNDARY: tuple[Callable[..., object], Callable[..., object]] | None = (
    None
)
_PUBLIC_SYNTHETIC_MANIFEST_BOUNDARY_LOCK = RLock()


class _OpaqueOwner:
    __slots__ = ()

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Authenticated scenario owners are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Authenticated scenario owners cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Authenticated scenario owners cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Authenticated scenario owners cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Authenticated scenario owners cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Authenticated scenario owners cannot be copied or serialized.")


@final
class AuthenticatedBenchmarkSubject(_OpaqueOwner):
    """Privately issued owner of the exact preflight benchmark subject."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> AuthenticatedBenchmarkSubject:
        raise TypeError("Authenticated benchmark subjects are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Authenticated benchmark subjects cannot be subclassed.")

    @property
    def digest(self) -> str:
        return cast(str, _validated_subject_projection(self)["subject_authority_sha256"])


@final
class AuthenticatedScenarioCaseBatch(_OpaqueOwner):
    """Opaque digest-bound owner of authenticated ordered resolved-case coverage."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> AuthenticatedScenarioCaseBatch:
        raise TypeError("Authenticated scenario case batches are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Authenticated scenario case batches cannot be subclassed.")

    @property
    def digest(self) -> str:
        return cast(str, _validated_batch_projection(self)["case_batch_sha256"])

    @property
    def case_count(self) -> int:
        return cast(int, _validated_batch_projection(self)["case_count"])


@final
class PublicBatchCasePlan(_OpaqueOwner):
    """Opaque batch-issued owner of one exact public case identity."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PublicBatchCasePlan:
        raise TypeError("Public batch case plans are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Public batch case plans cannot be subclassed.")

    @property
    def digest(self) -> str:
        try:
            state = _PUBLIC_CASE_PLAN_STATES.read(self)
            value = strict_json_loads(state.projection_bytes)
        except (CanonicalizationError, OneShotRegistryError):
            _reject("PUBLIC_CASE_PLAN_OWNER")
        if type(value) is not dict or not _is_sha256(value.get("public_batch_case_plan_sha256")):
            _reject("PUBLIC_CASE_PLAN_OWNER")
        return cast(str, value["public_batch_case_plan_sha256"])


def _expected_coordinates(
    authority: ScenarioAuthority,
    ordered_family_ids: tuple[str, ...],
) -> tuple[CaseCoordinate, ...]:
    families = authority.scenario_families
    if tuple(row.get("id") for row in families) != ordered_family_ids:
        _reject("FAMILY_ORDER")
    coordinates: list[CaseCoordinate] = []
    for family in families:
        family_id = family.get("id")
        variants = family.get("development_variants")
        replicate_count = family.get("development_replicates")
        if (
            type(family_id) is not str
            or type(variants) is not list
            or not variants
            or type(replicate_count) is not int
            or replicate_count < 1
        ):
            _reject("COVERAGE_DEFINITION")
        mode: Literal["TRANSFORMED_SOURCE", "DEVELOPMENT_VARIANT"] = (
            "TRANSFORMED_SOURCE"
            if type(family.get("source_family")) is str
            else "DEVELOPMENT_VARIANT"
        )
        for variant in variants:
            variant_id = variant.get("id") if type(variant) is dict else None
            if type(variant_id) is not str or not variant_id:
                _reject("COVERAGE_DEFINITION")
            coordinates.extend(
                CaseCoordinate(family_id, variant_id, replicate_index, mode)
                for replicate_index in range(replicate_count)
            )
    if len({(row.family_id, row.variant_id, row.replicate_index) for row in coordinates}) != len(
        coordinates
    ):
        _reject("COVERAGE_DEFINITION")
    return tuple(coordinates)


def _representative_coordinates(
    expected_coordinates: tuple[CaseCoordinate, ...],
) -> tuple[CaseCoordinate, ...]:
    """Return one coordinate per family plus both correlated truth subtypes."""

    selected: list[CaseCoordinate] = []
    seen_slots: set[tuple[str, str | None]] = set()
    for coordinate in expected_coordinates:
        slot = (
            coordinate.family_id,
            coordinate.variant_id
            if coordinate.family_id == "correlated_duplicate_events"
            else None,
        )
        if slot in seen_slots:
            continue
        seen_slots.add(slot)
        selected.append(coordinate)
    correlated = tuple(
        coordinate
        for coordinate in selected
        if coordinate.family_id == "correlated_duplicate_events"
    )
    if not selected or len(correlated) != 2:
        _reject("CASE_COVERAGE")
    return tuple(selected)


def _proportional_challenge_coordinates(
    expected_coordinates: tuple[CaseCoordinate, ...],
) -> tuple[CaseCoordinate, ...]:
    """Select the frozen 57-case cohort that owns the 103-operation plan."""

    by_family: dict[str, list[CaseCoordinate]] = {}
    for coordinate in expected_coordinates:
        by_family.setdefault(coordinate.family_id, []).append(coordinate)
    selected: list[CaseCoordinate] = []
    for family_id, family_coordinates in by_family.items():
        if family_id == "moderate_mina_shape":
            family_selection = family_coordinates[:24]
            if len(family_selection) != 24:
                _reject("PROPORTIONAL_CASE_COVERAGE")
        elif family_id == "correlated_duplicate_events":
            by_variant: dict[str, list[CaseCoordinate]] = {}
            for coordinate in family_coordinates:
                by_variant.setdefault(coordinate.variant_id, []).append(coordinate)
            if len(by_variant) != 2 or any(len(rows) < 6 for rows in by_variant.values()):
                _reject("PROPORTIONAL_CASE_COVERAGE")
            family_selection = [
                coordinate for rows in by_variant.values() for coordinate in rows[:6]
            ]
        else:
            if not family_coordinates:
                _reject("PROPORTIONAL_CASE_COVERAGE")
            family_selection = family_coordinates[:1]
        selected.extend(family_selection)
    if len(by_family) != 23 or len(selected) != 57:
        _reject("PROPORTIONAL_CASE_COVERAGE")
    return tuple(selected)


def _validated_subject_projection(
    subject: AuthenticatedBenchmarkSubject,
) -> dict[str, object]:
    if type(subject) is not AuthenticatedBenchmarkSubject:
        _reject("SUBJECT_OWNER")
    try:
        state = _SUBJECT_STATES.read(subject)
        value = strict_json_loads(state.projection_bytes)
    except (CanonicalizationError, OneShotRegistryError):
        _reject("SUBJECT_OWNER")
    if type(value) is not dict:
        _reject("SUBJECT_PREIMAGE")
    projection = cast(dict[str, object], value)
    required = {
        "schema_version",
        "preflight_identity",
        "scenario_contract_sha256",
        "scenario_source_sha256",
        "ordered_case_coordinates",
        "subject_authority_sha256",
    }
    if set(projection) != required:
        _reject("SUBJECT_PREIMAGE")
    digest = projection["subject_authority_sha256"]
    preimage = copy.deepcopy(projection)
    preimage["subject_authority_sha256"] = None
    coordinate_rows = projection["ordered_case_coordinates"]
    if (
        projection["schema_version"] != "ebm-audit-authenticated-benchmark-subject/1.0"
        or type(digest) is not str
        or structured_sha256(_SUBJECT_DOMAIN, preimage) != digest
        or canonical_json_bytes(projection) != state.projection_bytes
        or type(coordinate_rows) is not list
        or coordinate_rows != [_coordinate_projection(row) for row in state.expected_coordinates]
    ):
        _reject("SUBJECT_BINDING")
    return projection


def _coordinate_projection(coordinate: CaseCoordinate) -> dict[str, object]:
    return {
        "family_id": coordinate.family_id,
        "variant_id": coordinate.variant_id,
        "replicate_index": coordinate.replicate_index,
        "resolution_mode": coordinate.resolution_mode,
    }


def _claim_authenticated_benchmark_subject_issuer[T](
    *,
    owner_type: type[T],
    identity_projection: Callable[[T], Mapping[str, object]],
    authenticated_sources: Callable[[T], tuple[bytes, bytes]],
) -> Callable[
    [T],
    AuthenticatedBenchmarkSubject,
]:
    """Give one exact runner result type its sole package-private subject issuer."""

    claimed_owner_type = cast(type[object], owner_type)
    with _SUBJECT_ISSUER_CLAIM_LOCK:
        if not _is_authentic_runner_claim(
            claimed_owner_type,
            identity_projection,
            authenticated_sources,
        ):
            _reject("SUBJECT_ISSUER")
        if claimed_owner_type in _SUBJECT_ISSUER_CLAIMS:
            _reject("SUBJECT_ISSUER")
        _SUBJECT_ISSUER_CLAIMS.add(claimed_owner_type)

    def issue(preflight_owner: T) -> AuthenticatedBenchmarkSubject:
        if type(preflight_owner) is not owner_type:
            _reject("SUBJECT_OWNER")
        exact_contract_bytes, exact_scenario_bytes = authenticated_sources(preflight_owner)
        identity = _json_copy(identity_projection(preflight_owner))
        try:
            contract = load_strict_yaml_bytes(
                exact_contract_bytes,
                maximum_bytes=_MAXIMUM_YAML_BYTES,
            )
            scenarios = load_strict_yaml_bytes(
                exact_scenario_bytes,
                maximum_bytes=_MAXIMUM_YAML_BYTES,
            )
        except StrictYamlError:
            _reject("SUBJECT_INPUT")
        if type(identity) is not dict or type(contract) is not dict or type(scenarios) is not dict:
            _reject("SUBJECT_INPUT")
        identity_map = cast(dict[str, Any], identity)
        contract_map = cast(dict[str, Any], contract)
        scenarios_map = cast(dict[str, Any], scenarios)
        contract_projection = copy.deepcopy(contract_map)
        claimed_contract_digest = contract_projection.get("contract_sha256")
        contract_projection["contract_sha256"] = None
        contract_digest = structured_sha256_hex(_CONTRACT_DOMAIN, contract_projection)
        scenario_digest = structured_sha256_hex(_SCENARIO_DOMAIN, scenarios_map)
        source_identities = contract_map.get("source_identities")
        scenario_identity = (
            source_identities.get("scenario_definitions")
            if type(source_identities) is dict
            else None
        )
        scenario_source = contract_map.get("scenario_source")
        required_families = (
            scenario_source.get("required_family_ids") if type(scenario_source) is dict else None
        )
        families = scenarios_map.get("scenario_families")
        actual_families = (
            [row.get("id") if type(row) is dict else None for row in families]
            if type(families) is list
            else None
        )
        object_format = identity_map.get("git_object_format")
        object_id_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
        git_commit = identity_map.get("git_commit")
        git_tree = identity_map.get("git_tree")
        expected_candidate_digest = structured_sha256_hex(
            _CANDIDATE_DOMAIN,
            {
                "schema_version": "ebm-audit-candidate-tree/1.0",
                "git_object_format": object_format,
                "git_commit": git_commit,
                "git_tree": git_tree,
            },
        )
        expected_source_hashes = _validated_ordered_source_hashes(
            identity_map.get("ordered_source_hashes")
        )
        required_identity_fields = {
            "mode",
            "git_object_format",
            "git_commit",
            "git_tree",
            "candidate_sha256",
            "contract_sha256",
            "scenario_definitions_sha256",
            "supersession_sha256",
            "direct_producer_source_set_sha256",
            "ordered_source_hashes",
            "ordered_scenario_families",
        }
        if (
            type(exact_contract_bytes) is not bytes
            or type(exact_scenario_bytes) is not bytes
            or set(identity_map) != required_identity_fields
            or identity_map.get("mode") != "local_offline"
            or object_id_length == 0
            or not _is_object_id(git_commit, object_id_length)
            or not _is_object_id(git_tree, object_id_length)
            or identity_map.get("candidate_sha256") != expected_candidate_digest
            or claimed_contract_digest != contract_digest
            or identity_map.get("contract_sha256") != contract_digest
            or not _is_sha256(identity_map.get("supersession_sha256"))
            or not _is_sha256(identity_map.get("direct_producer_source_set_sha256"))
            or identity_map.get("ordered_source_hashes") != expected_source_hashes
            or type(scenario_identity) is not dict
            or scenario_identity.get("path") != "evaluator/development_scenarios.yaml"
            or scenario_identity.get("status") != "FROZEN_EXACT_BYTES"
            or scenario_identity.get("sha256") != scenario_digest
            or identity_map.get("scenario_definitions_sha256") != scenario_digest
            or type(required_families) is not list
            or len(required_families) != 23
            or len(set(cast(list[object], required_families))) != 23
            or actual_families != required_families
            or identity_map.get("ordered_scenario_families") != required_families
        ):
            _reject("SUBJECT_IDENTITY")
        authority = load_scenario_authority(exact_scenario_bytes)
        if authority.data != scenarios_map:
            _reject("SCENARIO_SOURCE")
        ordered_family_ids = tuple(cast(list[str], required_families))
        expected = _expected_coordinates(authority, ordered_family_ids)
        preimage: dict[str, object] = {
            "schema_version": "ebm-audit-authenticated-benchmark-subject/1.0",
            "preflight_identity": identity_map,
            "scenario_contract_sha256": scenario_digest,
            "scenario_source_sha256": authority.definitions_sha256,
            "ordered_case_coordinates": [_coordinate_projection(row) for row in expected],
            "subject_authority_sha256": None,
        }
        preimage["subject_authority_sha256"] = structured_sha256(_SUBJECT_DOMAIN, preimage)
        owner = object.__new__(AuthenticatedBenchmarkSubject)
        _SUBJECT_ISSUER.bind_once(
            owner,
            _SubjectState(
                projection_bytes=canonical_json_bytes(preimage),
                scenario_bytes=bytes(exact_scenario_bytes),
                expected_coordinates=expected,
            ),
        )
        _validated_subject_projection(owner)
        return owner

    return issue


def _is_authentic_runner_claim(
    owner_type: type[object],
    identity_projection: object,
    authenticated_sources: object,
) -> bool:
    module_name = owner_type.__module__
    module = sys.modules.get(module_name)
    module_path = getattr(module, "__file__", None)
    if type(module_path) is not str:
        return False
    expected_path = Path(__file__).resolve().parents[3] / "evaluator" / "run_benchmark.py"
    try:
        resolved_module_path = Path(module_path).resolve(strict=True)
        identity_path = Path(cast(Any, identity_projection).__code__.co_filename).resolve(
            strict=True
        )
        sources_path = Path(cast(Any, authenticated_sources).__code__.co_filename).resolve(
            strict=True
        )
    except (AttributeError, OSError, TypeError):
        return False
    return (
        resolved_module_path == expected_path
        and identity_path == expected_path
        and sources_path == expected_path
        and getattr(identity_projection, "__module__", None) == module_name
        and getattr(authenticated_sources, "__module__", None) == module_name
        and getattr(module, "_PreflightResult", None) is owner_type
        and getattr(module, "_preflight_identity", None) is identity_projection
        and getattr(module, "_authenticated_preflight_sources", None) is authenticated_sources
    )


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _raw_sha256(value: object, *, code: str) -> str:
    raw = value.removeprefix("sha256:") if type(value) is str else None
    if not _is_sha256(raw):
        _reject(code)
    return cast(str, raw)


def _is_object_id(value: object, expected_length: int) -> bool:
    return (
        type(value) is str
        and len(value) == expected_length
        and all(character in "0123456789abcdef" for character in value)
    )


def _case_projection(candidate: ResolvedSyntheticCase) -> dict[str, object]:
    parameter_digest = candidate.resolved_parameter_manifest.get(
        "resolved_parameter_manifest_sha256"
    )
    configuration_digest = candidate.resolved_configuration.get(
        "resolved_generator_configuration_sha256"
    )
    mechanism_digest = candidate.resolved_mechanism.get("resolved_generator_mechanism_sha256")
    component_digest = candidate.component_seed_manifest.get("component_seed_manifest_sha256")
    if any(
        type(value) is not str or not value
        for value in (parameter_digest, configuration_digest, mechanism_digest, component_digest)
    ):
        _reject("CASE_IDENTITY")
    return {
        **_coordinate_projection(candidate.coordinate),
        "case_id": candidate.case_id,
        "variant_index": candidate.variant_index,
        "source_contract_sha256": candidate.source_contract_sha256,
        "scenario_source_sha256": candidate.scenario_definitions_sha256,
        "resolved_parameter_manifest_sha256": parameter_digest,
        "resolved_generator_configuration_sha256": configuration_digest,
        "resolved_generator_mechanism_sha256": mechanism_digest,
        "component_seed_manifest_sha256": component_digest,
    }


def _bind_public_synthetic_case_coverage(
    subject: AuthenticatedBenchmarkSubject,
    authority: ScenarioAuthority,
    cases: Sequence[ResolvedSyntheticCase],
    *,
    coverage_mode: Literal[
        "COMPLETE",
        "REPRESENTATIVE",
        "PROPORTIONAL_CHALLENGE",
        "SINGLE",
    ],
    cases_already_verified: bool = False,
) -> AuthenticatedScenarioCaseBatch:
    """Revalidate and bind one exact authenticated public coverage mode."""

    subject_projection = _validated_subject_projection(subject)
    try:
        subject_state = _SUBJECT_STATES.read(subject)
    except OneShotRegistryError:
        _reject("SUBJECT_OWNER")
    strict_authority = load_scenario_authority(subject_state.scenario_bytes)
    if type(authority) is not ScenarioAuthority or authority != strict_authority:
        _reject("SCENARIO_SOURCE")
    if type(cases) not in {list, tuple}:
        _reject("CASE_COVERAGE")
    candidates = tuple(cases)
    if any(type(candidate) is not ResolvedSyntheticCase for candidate in candidates):
        _reject("CASE_OWNER")
    observed_coordinates = tuple(candidate.coordinate for candidate in candidates)
    expected_representatives = _representative_coordinates(subject_state.expected_coordinates)
    if coverage_mode == "COMPLETE":
        coverage_valid = observed_coordinates == subject_state.expected_coordinates
    elif coverage_mode == "REPRESENTATIVE":
        coverage_valid = observed_coordinates == expected_representatives
    elif coverage_mode == "PROPORTIONAL_CHALLENGE":
        coverage_valid = observed_coordinates == _proportional_challenge_coordinates(
            subject_state.expected_coordinates
        )
    elif coverage_mode == "SINGLE":
        coverage_valid = not (
            len(observed_coordinates) != 1
            or observed_coordinates[0] not in subject_state.expected_coordinates
            or observed_coordinates[0].resolution_mode != "DEVELOPMENT_VARIANT"
        )
    else:
        coverage_valid = False
    if not coverage_valid:
        _reject("CASE_COVERAGE")

    if not cases_already_verified:
        _verify_retained_cases(strict_authority, candidates)
    case_contexts = tuple(_authenticated_case_context(candidate) for candidate in candidates)

    rows = [_case_projection(candidate) for candidate in candidates]
    preimage: dict[str, object] = {
        "schema_version": "ebm-audit-authenticated-scenario-case-batch/1.0",
        "subject_authority_sha256": subject_projection["subject_authority_sha256"],
        "case_count": len(rows),
        "ordered_cases": rows,
        "case_batch_sha256": None,
    }
    preimage["case_batch_sha256"] = structured_sha256(_BATCH_DOMAIN, preimage)
    owner = object.__new__(AuthenticatedScenarioCaseBatch)
    _BATCH_ISSUER.bind_once(
        owner,
        _BatchState(
            projection_bytes=canonical_json_bytes(preimage),
            subject=subject,
            scenario_bytes=bytes(subject_state.scenario_bytes),
            resolved_cases=candidates,
            case_contexts=case_contexts,
            manifest_authentication_key=secrets.token_bytes(32),
            issued_public_input_identities=set(),
            public_case_plan_owners=None,
            lock=RLock(),
        ),
    )
    _validated_batch_projection(owner)
    return owner


def _bind_public_synthetic_case_batch(
    subject: AuthenticatedBenchmarkSubject,
    authority: ScenarioAuthority,
    cases: Sequence[ResolvedSyntheticCase],
) -> AuthenticatedScenarioCaseBatch:
    """Revalidate and bind the complete public development case batch."""

    return _bind_public_synthetic_case_coverage(
        subject,
        authority,
        cases,
        coverage_mode="COMPLETE",
    )


def _bind_public_synthetic_representative_cohort(
    subject: AuthenticatedBenchmarkSubject,
    authority: ScenarioAuthority,
    cases: Sequence[ResolvedSyntheticCase],
) -> AuthenticatedScenarioCaseBatch:
    """Revalidate and bind exactly the first frozen case from every family."""

    return _bind_public_synthetic_case_coverage(
        subject,
        authority,
        cases,
        coverage_mode="REPRESENTATIVE",
    )


def _bind_public_synthetic_case_selection(
    subject: AuthenticatedBenchmarkSubject,
    authority: ScenarioAuthority,
    case: ResolvedSyntheticCase,
) -> AuthenticatedScenarioCaseBatch:
    """Bind one ordinary public case selected from the frozen subject."""

    return _bind_public_synthetic_case_coverage(
        subject,
        authority,
        (case,),
        coverage_mode="SINGLE",
    )


def _resolve_and_bind_public_synthetic_case_selection(
    subject: AuthenticatedBenchmarkSubject,
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
) -> tuple[AuthenticatedScenarioCaseBatch, ResolvedSyntheticCase]:
    """Resolve once and retain one ordinary case behind authenticated batch state."""

    case = resolve_development_case(authority, coordinate)
    batch = _bind_public_synthetic_case_coverage(
        subject,
        authority,
        (case,),
        coverage_mode="SINGLE",
        cases_already_verified=True,
    )
    return batch, case


def _resolve_and_bind_public_synthetic_representative_cohort(
    subject: AuthenticatedBenchmarkSubject,
    authority: ScenarioAuthority,
) -> tuple[AuthenticatedScenarioCaseBatch, tuple[ResolvedSyntheticCase, ...]]:
    """Resolve and bind one exact first-per-family cohort from full authority."""

    _validated_subject_projection(subject)
    try:
        subject_state = _SUBJECT_STATES.read(subject)
    except OneShotRegistryError:
        _reject("SUBJECT_OWNER")
    strict_authority = load_scenario_authority(subject_state.scenario_bytes)
    if type(authority) is not ScenarioAuthority or authority != strict_authority:
        _reject("SCENARIO_SOURCE")

    expected = _representative_coordinates(subject_state.expected_coordinates)
    expected_set = set(expected)
    family_rows = {cast(str, row["id"]): row for row in strict_authority.scenario_families}
    resolved_by_coordinate: dict[CaseCoordinate, ResolvedSyntheticCase] = {}
    cases: list[ResolvedSyntheticCase] = []
    for coordinate in expected:
        if coordinate.resolution_mode == "TRANSFORMED_SOURCE":
            family = family_rows.get(coordinate.family_id)
            variants = family.get("development_variants") if family is not None else None
            matches = (
                [
                    row
                    for row in variants
                    if type(row) is dict and row.get("id") == coordinate.variant_id
                ]
                if type(variants) is list
                else []
            )
            source_reference = matches[0].get("source_variant") if len(matches) == 1 else None
            if type(source_reference) is not str or source_reference.count("/") != 1:
                _reject("SOURCE_COVERAGE")
            source_family, source_variant = source_reference.split("/", 1)
            source_coordinate = CaseCoordinate(
                source_family,
                source_variant,
                coordinate.replicate_index,
            )
            source = resolved_by_coordinate.get(source_coordinate)
            if source_coordinate not in expected_set or source is None:
                _reject("SOURCE_COVERAGE")
            case = resolve_development_case(
                strict_authority,
                coordinate,
                source_owner=AuthenticatedSourceOwner(source),
            )
        else:
            case = resolve_development_case(strict_authority, coordinate)
        resolved_by_coordinate[coordinate] = case
        cases.append(case)

    resolved = tuple(cases)
    return (
        _bind_public_synthetic_case_coverage(
            subject,
            strict_authority,
            resolved,
            coverage_mode="REPRESENTATIVE",
            cases_already_verified=True,
        ),
        resolved,
    )


def _resolve_and_bind_public_synthetic_proportional_challenge_cohort(
    subject: AuthenticatedBenchmarkSubject,
    authority: ScenarioAuthority,
) -> tuple[AuthenticatedScenarioCaseBatch, tuple[ResolvedSyntheticCase, ...]]:
    """Resolve the exact 57 public cases used by the 103-operation challenge."""

    _validated_subject_projection(subject)
    try:
        subject_state = _SUBJECT_STATES.read(subject)
    except OneShotRegistryError:
        _reject("SUBJECT_OWNER")
    strict_authority = load_scenario_authority(subject_state.scenario_bytes)
    if type(authority) is not ScenarioAuthority or authority != strict_authority:
        _reject("SCENARIO_SOURCE")

    expected = _proportional_challenge_coordinates(subject_state.expected_coordinates)
    expected_set = set(expected)
    family_rows = {cast(str, row["id"]): row for row in strict_authority.scenario_families}
    resolved_by_coordinate: dict[CaseCoordinate, ResolvedSyntheticCase] = {}
    cases: list[ResolvedSyntheticCase] = []
    for coordinate in expected:
        if coordinate.resolution_mode == "TRANSFORMED_SOURCE":
            family = family_rows.get(coordinate.family_id)
            variants = family.get("development_variants") if family is not None else None
            matches = (
                [
                    row
                    for row in variants
                    if type(row) is dict and row.get("id") == coordinate.variant_id
                ]
                if type(variants) is list
                else []
            )
            source_reference = matches[0].get("source_variant") if len(matches) == 1 else None
            if type(source_reference) is not str or source_reference.count("/") != 1:
                _reject("SOURCE_COVERAGE")
            source_family, source_variant = source_reference.split("/", 1)
            source_coordinate = CaseCoordinate(
                source_family,
                source_variant,
                coordinate.replicate_index,
            )
            source = resolved_by_coordinate.get(source_coordinate)
            if source_coordinate not in expected_set or source is None:
                _reject("SOURCE_COVERAGE")
            case = resolve_development_case(
                strict_authority,
                coordinate,
                source_owner=AuthenticatedSourceOwner(source),
            )
        else:
            case = resolve_development_case(strict_authority, coordinate)
        resolved_by_coordinate[coordinate] = case
        cases.append(case)

    resolved = tuple(cases)
    return (
        _bind_public_synthetic_case_coverage(
            subject,
            strict_authority,
            resolved,
            coverage_mode="PROPORTIONAL_CHALLENGE",
            cases_already_verified=True,
        ),
        resolved,
    )


def _validated_batch_projection(batch: AuthenticatedScenarioCaseBatch) -> dict[str, object]:
    if type(batch) is not AuthenticatedScenarioCaseBatch:
        _reject("BATCH_OWNER")
    try:
        state = _BATCH_STATES.read(batch)
        if type(state) is not _BatchState:
            _reject("BATCH_OWNER")
        batch_bytes = state.projection_bytes
        value = strict_json_loads(batch_bytes)
    except (CanonicalizationError, OneShotRegistryError):
        _reject("BATCH_OWNER")
    if type(value) is not dict:
        _reject("BATCH_PREIMAGE")
    projection = cast(dict[str, object], value)
    required = {
        "schema_version",
        "subject_authority_sha256",
        "case_count",
        "ordered_cases",
        "case_batch_sha256",
    }
    if set(projection) != required:
        _reject("BATCH_PREIMAGE")
    digest = projection["case_batch_sha256"]
    preimage = copy.deepcopy(projection)
    preimage["case_batch_sha256"] = None
    rows = projection["ordered_cases"]
    if (
        projection["schema_version"] != "ebm-audit-authenticated-scenario-case-batch/1.0"
        or type(projection["subject_authority_sha256"]) is not str
        or type(projection["case_count"]) is not int
        or type(rows) is not list
        or projection["case_count"] != len(rows)
        or type(digest) is not str
        or structured_sha256(_BATCH_DOMAIN, preimage) != digest
        or canonical_json_bytes(projection) != batch_bytes
    ):
        _reject("BATCH_BINDING")
    return projection


def _resolved_subtype(candidate: ResolvedSyntheticCase) -> str | None:
    if candidate.coordinate.family_id != "correlated_duplicate_events":
        return None
    try:
        pair_mode = candidate.field_value("pair_mode")
    except KeyError:
        _reject("CASE_SUBTYPE")
    if type(pair_mode) is not str or pair_mode.upper() not in {
        "CORRELATED",
        "EXACT_DUPLICATE_POST_NOISE",
    }:
        _reject("CASE_SUBTYPE")
    return pair_mode.upper()


def _resolved_boundary_rule_ids(candidate: ResolvedSyntheticCase) -> tuple[str, ...]:
    if candidate.coordinate.family_id != "group_boundary_sensitivity":
        return ()
    try:
        resolved_rule_ids = candidate.field_value("boundary_rule_ids")
    except KeyError:
        _reject("BOUNDARY_RULES")
    if type(resolved_rule_ids) is not list:
        _reject("BOUNDARY_RULES")
    rule_ids = tuple(cast(list[object], resolved_rule_ids))
    if (
        len(rule_ids) not in {3, 5}
        or any(type(rule_id) is not str or not rule_id for rule_id in rule_ids)
        or len(set(rule_ids)) != len(rule_ids)
    ):
        _reject("BOUNDARY_RULES")
    return cast(tuple[str, ...], rule_ids)


def _authenticated_case_context(candidate: ResolvedSyntheticCase) -> _AuthenticatedCaseContext:
    return _AuthenticatedCaseContext(
        family_id=candidate.coordinate.family_id,
        case_id=candidate.case_id,
        source_contract_sha256=candidate.source_contract_sha256,
        scenario_source_sha256=candidate.scenario_definitions_sha256,
        subtype=_resolved_subtype(candidate),
        boundary_rule_ids=_resolved_boundary_rule_ids(candidate),
    )


def _verify_retained_cases(
    authority: ScenarioAuthority,
    cases: tuple[ResolvedSyntheticCase, ...],
) -> None:
    by_coordinate = {candidate.coordinate: candidate for candidate in cases}
    if len(by_coordinate) != len(cases):
        _reject("CASE_COVERAGE")
    families = {cast(str, row["id"]): row for row in authority.scenario_families}
    for candidate in cases:
        family = families.get(candidate.coordinate.family_id)
        if family is None:
            _reject("CASE_COVERAGE")
        if candidate.coordinate.resolution_mode == "TRANSFORMED_SOURCE":
            variants = cast(list[dict[str, object]], family["development_variants"])
            matches = [row for row in variants if row.get("id") == candidate.coordinate.variant_id]
            if len(matches) != 1:
                _reject("SOURCE_COVERAGE")
            source_reference = matches[0].get("source_variant")
            if type(source_reference) is not str or source_reference.count("/") != 1:
                _reject("SOURCE_COVERAGE")
            source_family, source_variant = source_reference.split("/")
            source = by_coordinate.get(
                CaseCoordinate(
                    source_family,
                    source_variant,
                    candidate.coordinate.replicate_index,
                )
            )
            if source is None:
                _reject("SOURCE_COVERAGE")
            try:
                authority.verify_resolved_case(
                    candidate,
                    source_owner=AuthenticatedSourceOwner(source),
                )
            except InvalidInputError:
                _reject("CASE_IDENTITY")
        else:
            try:
                authority.verify_resolved_case(candidate)
            except InvalidInputError:
                _reject("CASE_IDENTITY")


def _read_authenticated_batch_context(
    batch: AuthenticatedScenarioCaseBatch,
) -> _AuthenticatedBatchContext:
    """Revalidate retained resolved cases without exposing their private state."""

    projection = _validated_batch_projection(batch)
    try:
        state = _BATCH_STATES.read(batch)
        subject_state = _SUBJECT_STATES.read(state.subject)
    except OneShotRegistryError:
        _reject("BATCH_OWNER")
    subject = _validated_subject_projection(state.subject)
    if (
        projection["subject_authority_sha256"] != subject["subject_authority_sha256"]
        or state.scenario_bytes != subject_state.scenario_bytes
    ):
        _reject("BATCH_BINDING")
    rows = projection["ordered_cases"]
    if type(rows) is not list or [_case_projection(case) for case in state.resolved_cases] != rows:
        _reject("CASE_BINDING")
    contexts = tuple(_authenticated_case_context(candidate) for candidate in state.resolved_cases)
    if contexts != state.case_contexts:
        _reject("CASE_CONTEXT")
    for context, row in zip(contexts, cast(list[object], rows), strict=True):
        if type(row) is not dict:
            _reject("CASE_CONTEXT")
        row_map = cast(dict[str, object], row)
        if (
            context.family_id != row_map.get("family_id")
            or context.case_id != row_map.get("case_id")
            or context.source_contract_sha256 != row_map.get("source_contract_sha256")
            or context.scenario_source_sha256 != row_map.get("scenario_source_sha256")
        ):
            _reject("CASE_CONTEXT")

    identity = subject.get("preflight_identity")
    source_rows = identity.get("ordered_source_hashes") if type(identity) is dict else None
    report_rule_rows = (
        [
            row
            for row in source_rows
            if type(row) is dict and row.get("source_role") == "report_language_rules_sha256"
        ]
        if type(source_rows) is list
        else []
    )
    if len(report_rule_rows) != 1 or not _is_sha256(report_rule_rows[0].get("sha256")):
        _reject("REPORT_RULE_IDENTITY")

    return _AuthenticatedBatchContext(
        benchmark_subject_digest=cast(str, subject["subject_authority_sha256"]),
        report_rule_registry_sha256=cast(str, report_rule_rows[0]["sha256"]),
        cases=contexts,
    )


def _read_authenticated_batch_candidate_sha256(
    batch: AuthenticatedScenarioCaseBatch,
) -> str:
    """Read the exact candidate identity retained by the batch subject."""

    _read_authenticated_batch_context(batch)
    try:
        batch_state = _BATCH_STATES.read(batch)
    except OneShotRegistryError:
        _reject("BATCH_OWNER")
    subject = _validated_subject_projection(batch_state.subject)
    identity = subject.get("preflight_identity")
    candidate_sha256 = identity.get("candidate_sha256") if type(identity) is dict else None
    if not _is_sha256(candidate_sha256):
        _reject("SUBJECT_IDENTITY")
    return cast(str, candidate_sha256)


def _public_batch_context_projection(
    batch: AuthenticatedScenarioCaseBatch,
) -> dict[str, object]:
    context = _read_authenticated_batch_context(batch)
    batch_projection = _validated_batch_projection(batch)
    return {
        "schema_version": "ebm-audit-public-batch-context/1.0",
        "benchmark_subject_digest": context.benchmark_subject_digest,
        "authenticated_batch_sha256": _raw_sha256(
            batch_projection["case_batch_sha256"],
            code="PUBLIC_CASE_PLAN_BINDING",
        ),
        "ordered_cases": [
            {
                "case_ordinal": case_ordinal,
                "family_id": case.family_id,
                "case_id": case.case_id,
                "source_contract_sha256": case.source_contract_sha256,
                "scenario_source_sha256": case.scenario_source_sha256,
                "scenario_subtype_id": case.subtype,
                "ordered_boundary_rule_ids": list(case.boundary_rule_ids),
            }
            for case_ordinal, case in enumerate(context.cases)
        ],
    }


def _public_case_plan_material(
    batch: AuthenticatedScenarioCaseBatch,
    case_ordinal: int,
    input_owner: object,
    truth_evidence: object,
) -> tuple[dict[str, object], tuple[str, ...]]:
    from ebm_audit.synthetic.audit_input import (
        SealedPublicSyntheticAuditInput,
        SyntheticTruthScoringEvidence,
        _read_public_synthetic_batch_input_owner,
        _read_synthetic_truth_scoring_evidence,
        _read_synthetic_truth_scoring_input_owner,
        _resolve_public_synthetic_audit_input,
        project_public_synthetic_audit_input,
    )

    context = _read_authenticated_batch_context(batch)
    batch_projection = _validated_batch_projection(batch)
    try:
        batch_state = _BATCH_STATES.read(batch)
    except OneShotRegistryError:
        _reject("PUBLIC_CASE_PLAN_OWNER")
    if (
        type(case_ordinal) is not int
        or not 0 <= case_ordinal < len(context.cases)
        or type(input_owner) is not SealedPublicSyntheticAuditInput
        or type(truth_evidence) is not SyntheticTruthScoringEvidence
    ):
        _reject("PUBLIC_CASE_PLAN_EVIDENCE")
    try:
        input_state = _resolve_public_synthetic_audit_input(input_owner)
        input_projection = project_public_synthetic_audit_input(input_owner)
        truth_facts = _read_synthetic_truth_scoring_evidence(truth_evidence)
        truth_input_owner = _read_synthetic_truth_scoring_input_owner(truth_evidence)
        source_batch = _read_public_synthetic_batch_input_owner(input_owner)
    except (CanonicalizationError, InvalidInputError, TypeError):
        _reject("PUBLIC_CASE_PLAN_EVIDENCE")
    case = batch_state.resolved_cases[case_ordinal]
    case_context = context.cases[case_ordinal]
    projected_analysis_spec_ids = input_projection.get("ordered_analysis_spec_ids")
    analysis_spec_ids = (
        tuple(projected_analysis_spec_ids) if type(projected_analysis_spec_ids) is list else None
    )
    input_owner_digest = input_projection.get("input_owner_digest")
    input_benchmark_subject_digest = input_projection.get("benchmark_subject_digest")
    if (
        source_batch is not batch
        or truth_input_owner is not input_owner
        or input_state.resolved_case is not case
        or case_context.family_id != case.coordinate.family_id
        or case_context.case_id != case.case_id
        or truth_facts.family_id != case_context.family_id
        or truth_facts.case_id != case_context.case_id
        or input_benchmark_subject_digest != context.benchmark_subject_digest
        or type(input_owner_digest) is not str
        or not input_owner_digest.startswith("sha256:")
        or not _is_sha256(input_owner_digest.removeprefix("sha256:"))
        or type(analysis_spec_ids) is not tuple
        or not analysis_spec_ids
        or any(
            type(analysis_spec_id) is not str
            or not analysis_spec_id.startswith("sha256:")
            or not _is_sha256(analysis_spec_id.removeprefix("sha256:"))
            for analysis_spec_id in analysis_spec_ids
        )
        or len(set(analysis_spec_ids)) != len(analysis_spec_ids)
        or not _is_sha256(truth_facts.truth_object_sha256)
    ):
        _reject("PUBLIC_CASE_PLAN_BINDING")

    context_projection = _public_batch_context_projection(batch)
    batch_context_sha256 = structured_sha256_hex(
        _PUBLIC_BATCH_CONTEXT_DOMAIN,
        context_projection,
    )
    preimage: dict[str, object] = {
        "schema_version": "ebm-audit-public-batch-case-plan/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "benchmark_subject_digest": context.benchmark_subject_digest,
        "authenticated_batch_sha256": _raw_sha256(
            batch_projection["case_batch_sha256"],
            code="PUBLIC_CASE_PLAN_BINDING",
        ),
        "batch_context_sha256": batch_context_sha256,
        "case_ordinal": case_ordinal,
        "case_id": case_context.case_id,
        "family_id": case_context.family_id,
        "source_variant_id": case.coordinate.variant_id,
        "replicate_index": case.coordinate.replicate_index,
        "input_owner_digest": input_owner_digest,
        "truth_evidence_digest": f"sha256:{truth_facts.truth_object_sha256}",
        "public_batch_case_plan_sha256": None,
    }
    digest = structured_sha256_hex(_PUBLIC_BATCH_CASE_PLAN_DOMAIN, preimage)
    return (
        {
            **preimage,
            "digest_state": "PERSISTED",
            "public_batch_case_plan_sha256": digest,
        },
        cast(tuple[str, ...], analysis_spec_ids),
    )


def _issue_public_batch_case_plans(
    batch: AuthenticatedScenarioCaseBatch,
    case_evidence: tuple[tuple[object, object], ...],
) -> tuple[PublicBatchCasePlan, ...]:
    """Issue one genuine case-plan owner per retained case in batch order."""

    context = _read_authenticated_batch_context(batch)
    if (
        type(case_evidence) is not tuple
        or len(case_evidence) != len(context.cases)
        or any(type(row) is not tuple or len(row) != 2 for row in case_evidence)
        or len({id(row[0]) for row in case_evidence}) != len(case_evidence)
        or len({id(row[1]) for row in case_evidence}) != len(case_evidence)
    ):
        _reject("PUBLIC_CASE_PLAN_COVERAGE")
    materials = tuple(
        _public_case_plan_material(batch, case_ordinal, input_owner, truth_evidence)
        for case_ordinal, (input_owner, truth_evidence) in enumerate(case_evidence)
    )
    try:
        batch_state = _BATCH_STATES.read(batch)
    except OneShotRegistryError:
        _reject("PUBLIC_CASE_PLAN_OWNER")
    with batch_state.lock:
        existing = batch_state.public_case_plan_owners
        if existing is not None:
            if len(existing) != len(materials):
                _reject("PUBLIC_CASE_PLAN_COVERAGE")
            for owner, evidence, material in zip(
                existing,
                case_evidence,
                materials,
                strict=True,
            ):
                try:
                    state = _PUBLIC_CASE_PLAN_STATES.read(owner)
                except OneShotRegistryError:
                    _reject("PUBLIC_CASE_PLAN_OWNER")
                if (
                    state.batch is not batch
                    or state.input_owner is not evidence[0]
                    or state.truth_evidence is not evidence[1]
                    or state.projection_bytes != canonical_json_bytes(material[0])
                    or state.ordered_analysis_spec_ids != material[1]
                ):
                    _reject("PUBLIC_CASE_PLAN_REISSUE")
            return cast(tuple[PublicBatchCasePlan, ...], existing)

        issued: list[PublicBatchCasePlan] = []
        for evidence, (projection, analysis_spec_ids) in zip(
            case_evidence,
            materials,
            strict=True,
        ):
            owner = object.__new__(PublicBatchCasePlan)
            _PUBLIC_CASE_PLAN_ISSUER.bind_once(
                owner,
                _PublicBatchCasePlanState(
                    projection_bytes=canonical_json_bytes(projection),
                    batch=batch,
                    input_owner=evidence[0],
                    truth_evidence=evidence[1],
                    ordered_analysis_spec_ids=analysis_spec_ids,
                ),
            )
            issued.append(owner)
        owners = tuple(issued)
        batch_state.public_case_plan_owners = owners
        return owners


def _read_public_batch_case_plan(
    batch: AuthenticatedScenarioCaseBatch,
    owner: PublicBatchCasePlan,
) -> dict[str, object]:
    """Read one exact batch-owned case-plan projection after full revalidation."""

    if type(batch) is not AuthenticatedScenarioCaseBatch or type(owner) is not PublicBatchCasePlan:
        _reject("PUBLIC_CASE_PLAN_OWNER")
    try:
        state = _PUBLIC_CASE_PLAN_STATES.read(owner)
        batch_state = _BATCH_STATES.read(batch)
        value = strict_json_loads(state.projection_bytes)
    except (CanonicalizationError, OneShotRegistryError):
        _reject("PUBLIC_CASE_PLAN_OWNER")
    if (
        state.batch is not batch
        or batch_state.public_case_plan_owners is None
        or sum(candidate is owner for candidate in batch_state.public_case_plan_owners) != 1
        or type(value) is not dict
    ):
        _reject("PUBLIC_CASE_PLAN_OWNER")
    projection = cast(dict[str, object], value)
    case_ordinal = projection.get("case_ordinal")
    if type(case_ordinal) is not int:
        _reject("PUBLIC_CASE_PLAN_BINDING")
    rebuilt, analysis_spec_ids = _public_case_plan_material(
        batch,
        case_ordinal,
        state.input_owner,
        state.truth_evidence,
    )
    if (
        projection != rebuilt
        or canonical_json_bytes(projection) != state.projection_bytes
        or analysis_spec_ids != state.ordered_analysis_spec_ids
    ):
        _reject("PUBLIC_CASE_PLAN_BINDING")
    return cast(dict[str, object], _json_copy(projection))


def _read_public_batch_case_plan_set(
    batch: AuthenticatedScenarioCaseBatch,
    owners: tuple[PublicBatchCasePlan, ...],
) -> tuple[dict[str, object], ...]:
    """Read the complete unique case-plan set in authenticated batch order."""

    context = _read_authenticated_batch_context(batch)
    if (
        type(owners) is not tuple
        or len(owners) != len(context.cases)
        or any(type(owner) is not PublicBatchCasePlan for owner in owners)
        or len({id(owner) for owner in owners}) != len(owners)
    ):
        _reject("PUBLIC_CASE_PLAN_COVERAGE")
    rows = tuple(_read_public_batch_case_plan(batch, owner) for owner in owners)
    if tuple(row["case_ordinal"] for row in rows) != tuple(range(len(rows))):
        _reject("PUBLIC_CASE_PLAN_ORDER")
    return rows


def _read_public_batch_case_plan_analysis_spec_ids(
    batch: AuthenticatedScenarioCaseBatch,
    owner: PublicBatchCasePlan,
) -> tuple[str, ...]:
    """Return the exact ordered analysis identities retained by the input owner."""

    _read_public_batch_case_plan(batch, owner)
    try:
        state = _PUBLIC_CASE_PLAN_STATES.read(owner)
    except OneShotRegistryError:
        _reject("PUBLIC_CASE_PLAN_OWNER")
    return tuple(state.ordered_analysis_spec_ids)


def _read_authenticated_batch_zero_fit_fixture_projection(
    batch: AuthenticatedScenarioCaseBatch,
) -> dict[str, object]:
    """Derive privacy-safe permutation and seed facts from retained fixtures.

    The projection hashes synthetic fixture values inside the live authenticated
    batch.  It never returns participant rows or biomarker values and it never
    invokes an adapter or Fit.
    """

    from ebm_audit.synthetic.audit_input import (
        SealedPublicSyntheticAuditInput,
        _read_public_synthetic_batch_input_owner,
        _resolve_public_synthetic_audit_input,
    )

    _read_authenticated_batch_context(batch)
    try:
        batch_state = _BATCH_STATES.read(batch)
        plan_owners = batch_state.public_case_plan_owners
    except OneShotRegistryError:
        _reject("ZERO_FIT_FIXTURE")
    if (
        type(plan_owners) is not tuple
        or len(plan_owners) != len(batch_state.resolved_cases)
        or any(type(owner) is not PublicBatchCasePlan for owner in plan_owners)
    ):
        _reject("ZERO_FIT_FIXTURE")

    retained: list[tuple[ResolvedSyntheticCase, Mapping[str, object], str]] = []
    for owner, expected_case in zip(
        cast(tuple[PublicBatchCasePlan, ...], plan_owners),
        batch_state.resolved_cases,
        strict=True,
    ):
        try:
            plan_state = _PUBLIC_CASE_PLAN_STATES.read(owner)
            input_owner = plan_state.input_owner
            if (
                type(input_owner) is not SealedPublicSyntheticAuditInput
                or _read_public_synthetic_batch_input_owner(input_owner) is not batch
            ):
                _reject("ZERO_FIT_FIXTURE")
            input_state = _resolve_public_synthetic_audit_input(input_owner)
            artifacts = input_state.generated_artifacts
            data = artifacts.scientific_data
            clean_values = artifacts.clean_values.tolist()
        except (InvalidInputError, OneShotRegistryError, TypeError, ValueError):
            _reject("ZERO_FIT_FIXTURE")
        if (
            artifacts.resolved_case is not expected_case
            or not isinstance(data, Mapping)
            or type(clean_values) is not list
        ):
            _reject("ZERO_FIT_FIXTURE")
        retained.append(
            (
                expected_case,
                cast(Mapping[str, object], data),
                structured_sha256_hex(
                    "ebm-audit/proportional-scientific-clean-values/1",
                    clean_values,
                ),
            )
        )

    source_case, source_data, _source_clean_values_sha256 = retained[0]
    values = source_data.get("values")
    masks = source_data.get("missingness_mask")
    labels = source_data.get("analysis_group_labels")
    event_ids = source_data.get("event_ids")
    directions = source_data.get("event_directions")
    covariate_ids = source_data.get("covariate_ids")
    covariates = source_data.get("covariate_values")
    if (
        type(values) is not list
        or type(masks) is not list
        or type(labels) is not list
        or type(event_ids) is not list
        or type(directions) is not list
        or type(covariate_ids) is not list
        or type(covariates) is not list
        or len(values) < 2
        or len(values) != len(masks)
        or len(values) != len(labels)
        or len(values) != len(covariates)
        or len(event_ids) < 2
        or len(event_ids) != len(directions)
    ):
        _reject("ZERO_FIT_FIXTURE")
    participant_ids = [f"synthetic-row-{index:08d}" for index in range(len(values))]

    def fixture_rows(
        row_order: Sequence[int],
        column_order: Sequence[int],
        identifiers: Sequence[str],
    ) -> list[dict[str, object]]:
        if (
            sorted(row_order) != list(range(len(values)))
            or sorted(column_order) != list(range(len(event_ids)))
            or len(identifiers) != len(values)
            or len(set(identifiers)) != len(identifiers)
        ):
            _reject("ZERO_FIT_FIXTURE")
        rows: list[dict[str, object]] = []
        for output_position, source_position in enumerate(row_order):
            row_values = values[source_position]
            row_masks = masks[source_position]
            row_covariates = covariates[source_position]
            if (
                type(row_values) is not list
                or type(row_masks) is not list
                or type(row_covariates) is not list
                or len(row_values) != len(event_ids)
                or len(row_masks) != len(event_ids)
                or len(row_covariates) != len(covariate_ids)
            ):
                _reject("ZERO_FIT_FIXTURE")
            rows.append(
                {
                    "participant_id": identifiers[output_position],
                    "analysis_group": labels[source_position],
                    "events": [
                        {
                            "event_id": event_ids[column],
                            "direction": directions[column],
                            "value": row_values[column],
                            "missing": row_masks[column],
                        }
                        for column in column_order
                    ],
                    "covariates": [
                        {"covariate_id": item, "value": row_covariates[index]}
                        for index, item in enumerate(covariate_ids)
                    ],
                }
            )
        return rows

    def normalized(
        rows: Sequence[Mapping[str, object]],
        *,
        inverse_identifiers: Mapping[str, str] | None = None,
    ) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for row in rows:
            participant_id = row.get("participant_id")
            events = row.get("events")
            covariate_rows = row.get("covariates")
            if (
                type(participant_id) is not str
                or type(events) is not list
                or type(covariate_rows) is not list
            ):
                _reject("ZERO_FIT_FIXTURE")
            result.append(
                {
                    "participant_id": (
                        inverse_identifiers.get(participant_id)
                        if inverse_identifiers is not None
                        else participant_id
                    ),
                    "analysis_group": row.get("analysis_group"),
                    "events": sorted(
                        copy.deepcopy(events),
                        key=lambda item: cast(
                            str,
                            cast(dict[str, object], item)["event_id"],
                        ),
                    ),
                    "covariates": sorted(
                        copy.deepcopy(covariate_rows),
                        key=lambda item: cast(
                            str,
                            cast(dict[str, object], item)["covariate_id"],
                        ),
                    ),
                }
            )
        return sorted(result, key=lambda item: cast(str, item["participant_id"]))

    identity_rows = fixture_rows(
        list(range(len(values))),
        list(range(len(event_ids))),
        participant_ids,
    )
    row_order = list(reversed(range(len(values))))
    row_rows = fixture_rows(
        row_order,
        list(range(len(event_ids))),
        [participant_ids[index] for index in row_order],
    )
    column_order = list(reversed(range(len(event_ids))))
    column_rows = fixture_rows(
        list(range(len(values))),
        column_order,
        participant_ids,
    )
    relabelled_ids = [f"synthetic-relabel-{index:08d}" for index in reversed(range(len(values)))]
    relabelled_rows = fixture_rows(
        list(range(len(values))),
        list(range(len(event_ids))),
        relabelled_ids,
    )
    inverse_identifiers = dict(zip(relabelled_ids, participant_ids, strict=True))
    normalized_source = normalized(identity_rows)
    normalized_row = normalized(row_rows)
    normalized_column = normalized(column_rows)
    normalized_identifier = normalized(
        relabelled_rows,
        inverse_identifiers=inverse_identifiers,
    )
    if (
        normalized_source != normalized_row
        or normalized_source != normalized_column
        or normalized_source != normalized_identifier
        or all(
            original == relabelled
            for original, relabelled in zip(participant_ids, relabelled_ids, strict=True)
        )
    ):
        _reject("ZERO_FIT_FIXTURE")

    noise_rows: list[dict[str, str]] = []
    for case, retained_data, clean_values_sha256 in retained:
        if case.coordinate.family_id != "noise_ladder":
            continue
        stable_sha256 = structured_sha256_hex(
            "ebm-audit/proportional-scientific-stable-prefit-identity/1",
            {
                "event_ids": retained_data.get("event_ids"),
                "event_directions": retained_data.get("event_directions"),
                "analysis_group_labels": retained_data.get("analysis_group_labels"),
                "dimensions": retained_data.get("dimensions"),
                "clean_values_sha256": clean_values_sha256,
            },
        )
        noise_rows.append(
            {
                "stable_identity_sha256": stable_sha256,
                "seed_sha256": structured_sha256_hex(
                    "ebm-audit/proportional-scientific-prefit-seed/1",
                    case.case_seed,
                ),
                "stochastic_fields_sha256": structured_sha256_hex(
                    "ebm-audit/proportional-scientific-prefit-stochastic-fields/1",
                    {
                        "values": retained_data.get("values"),
                        "missingness_mask": retained_data.get("missingness_mask"),
                    },
                ),
            }
        )
    distinct_pair: tuple[dict[str, str], dict[str, str]] | None = None
    for first_index, first in enumerate(noise_rows):
        for second in noise_rows[first_index + 1 :]:
            if (
                first["stable_identity_sha256"] == second["stable_identity_sha256"]
                and first["seed_sha256"] != second["seed_sha256"]
                and first["stochastic_fields_sha256"]
                != second["stochastic_fields_sha256"]
            ):
                distinct_pair = (first, second)
                break
        if distinct_pair is not None:
            break
    if distinct_pair is None:
        _reject("ZERO_FIT_FIXTURE")
    first, second = distinct_pair

    source_fixture_sha256 = structured_sha256_hex(
        "ebm-audit/proportional-scientific-source-fixture/1",
        identity_rows,
    )
    normalized_sha256 = structured_sha256_hex(
        "ebm-audit/proportional-scientific-normalized-fixture/1",
        normalized_source,
    )
    return {
        "schema_version": "ebm-audit-proportional-zero-fit-fixture-projection/1.0",
        "source_case_id": source_case.case_id,
        "source_fixture_sha256": source_fixture_sha256,
        "normalized_source_fixture_sha256": normalized_sha256,
        "row_permutation": {
            "transformed_fixture_sha256": structured_sha256_hex(
                "ebm-audit/proportional-scientific-row-permuted-fixture/1",
                row_rows,
            ),
            "transform_sha256": structured_sha256_hex(
                "ebm-audit/proportional-scientific-row-permutation/1",
                row_order,
            ),
            "normalized_fixture_sha256": structured_sha256_hex(
                "ebm-audit/proportional-scientific-normalized-fixture/1",
                normalized_row,
            ),
        },
        "column_permutation": {
            "transformed_fixture_sha256": structured_sha256_hex(
                "ebm-audit/proportional-scientific-column-permuted-fixture/1",
                column_rows,
            ),
            "transform_sha256": structured_sha256_hex(
                "ebm-audit/proportional-scientific-column-permutation/1",
                column_order,
            ),
            "normalized_fixture_sha256": structured_sha256_hex(
                "ebm-audit/proportional-scientific-normalized-fixture/1",
                normalized_column,
            ),
        },
        "identifier_relabelling": {
            "transformed_fixture_sha256": structured_sha256_hex(
                "ebm-audit/proportional-scientific-identifier-relabelled-fixture/1",
                relabelled_rows,
            ),
            "transform_sha256": structured_sha256_hex(
                "ebm-audit/proportional-scientific-identifier-relabel/1",
                inverse_identifiers,
            ),
            "normalized_fixture_sha256": structured_sha256_hex(
                "ebm-audit/proportional-scientific-normalized-fixture/1",
                normalized_identifier,
            ),
            "positional_join_rejected": True,
        },
        "different_seed": {
            "first_stable_identity_sha256": first["stable_identity_sha256"],
            "second_stable_identity_sha256": second["stable_identity_sha256"],
            "first_seed_sha256": first["seed_sha256"],
            "second_seed_sha256": second["seed_sha256"],
            "first_stochastic_fields_sha256": first["stochastic_fields_sha256"],
            "second_stochastic_fields_sha256": second["stochastic_fields_sha256"],
        },
    }


def _authenticated_resolved_case_source_records(
    batch: AuthenticatedScenarioCaseBatch,
    family_id: str | None = None,
    case_id: str | None = None,
) -> tuple[object, ...]:
    """Rebuild canonical pre-science records from exact retained batch cases."""

    from ebm_audit.evaluator.scenario_source_owner_manifest import (
        _OWNER_BINDINGS,
        _ScenarioSourceRecordInput,
    )

    if type(batch) is not AuthenticatedScenarioCaseBatch or (
        (family_id is None) != (case_id is None)
    ):
        _reject("CASE_SOURCE_RECORD")
    if family_id is not None and (
        type(family_id) is not str or not family_id or type(case_id) is not str or not case_id
    ):
        _reject("CASE_SOURCE_RECORD")
    _read_authenticated_batch_context(batch)
    try:
        state = _BATCH_STATES.read(batch)
    except OneShotRegistryError:
        _reject("CASE_SOURCE_RECORD")
    selected = tuple(
        candidate
        for candidate in state.resolved_cases
        if family_id is None
        or (candidate.coordinate.family_id == family_id and candidate.case_id == case_id)
    )
    if not selected or (family_id is not None and len(selected) != 1):
        _reject("CASE_SOURCE_RECORD")

    records: list[_ScenarioSourceRecordInput] = []
    positions = {id(candidate): ordinal for ordinal, candidate in enumerate(state.resolved_cases)}
    for candidate in selected:
        ordinal = positions[id(candidate)]
        sources = (
            (
                "RESOLVED_GENERATOR_CONFIGURATION",
                "10-resolved-generator-configuration",
                candidate.resolved_configuration,
            ),
            (
                "RESOLVED_GENERATOR_MECHANISM",
                "11-resolved-generator-mechanism",
                candidate.resolved_mechanism,
            ),
            (
                "COMPONENT_SEED_MANIFEST",
                "12-component-seed-manifest",
                candidate.component_seed_manifest,
            ),
        )
        for owner_class, path_component, source_record in sources:
            binding = _OWNER_BINDINGS[owner_class]
            try:
                source_record_bytes = canonical_json_bytes(source_record)
                natural_identity = {field: source_record[field] for field in binding[1]}
            except (CanonicalizationError, KeyError, TypeError):
                _reject("CASE_SOURCE_RECORD")
            records.append(
                _ScenarioSourceRecordInput(
                    owner_class=owner_class,
                    owner_schema_ref=binding[0],
                    source_relative_path=(f"owners/{path_component}/{ordinal:08d}.json"),
                    source_content_bytes=source_record_bytes,
                    source_record_bytes=source_record_bytes,
                    natural_identity=natural_identity,
                    source_capability=batch,
                )
            )
    return tuple(records)


def _canonical_public_synthetic_source_records(
    batch: AuthenticatedScenarioCaseBatch,
    records: tuple[object, ...],
) -> tuple[object, ...]:
    """Order genuine source inputs by retained case and dependency class."""

    from ebm_audit.evaluator.scenario_source_owner_manifest import (
        _preparation_audit_evidence_source_records,
        _preparation_row_instance_manifest_source_records,
        _PreparationRowInstanceManifestSource,
        _read_scientific_meaning_source_owners,
        _read_scientific_meaning_source_records,
        _ScenarioSourceRecordInput,
    )
    from ebm_audit.science.capture import (
        CapturedScientificRun,
        PreparationAuditEvidence,
        _read_captured_scientific_run,
    )
    from ebm_audit.synthetic.audit_input import (
        SyntheticScientificDataEvidence,
        SyntheticTruthScoringEvidence,
        _read_public_synthetic_batch_input_owner,
        _read_synthetic_scientific_data_input_owner,
        _read_synthetic_truth_scoring_input_owner,
        _resolve_public_synthetic_audit_input,
    )

    context = _read_authenticated_batch_context(batch)
    if (
        type(records) is not tuple
        or not records
        or any(type(record) is not _ScenarioSourceRecordInput for record in records)
    ):
        _reject("PUBLIC_MANIFEST_RECORDS")
    positions = {case.case_id: index for index, case in enumerate(context.cases)}
    scientific_owner_pair: tuple[object, object] | None = None
    for candidate_record in cast(tuple[_ScenarioSourceRecordInput, ...], records):
        if candidate_record.owner_class not in {
            "FIT_RESPONSE_BINDING",
            "CANONICAL_SCIENTIFIC_PAYLOAD",
        }:
            continue
        try:
            candidate_pair = _read_scientific_meaning_source_owners(
                candidate_record.source_capability
            )
        except Exception:
            _reject("PUBLIC_MANIFEST_RECORDS")
        if candidate_pair[0] is not batch or (
            scientific_owner_pair is not None
            and any(
                candidate is not expected
                for candidate, expected in zip(
                    candidate_pair,
                    scientific_owner_pair,
                    strict=True,
                )
            )
        ):
            _reject("PUBLIC_MANIFEST_RECORDS")
        scientific_owner_pair = candidate_pair
    class_rank = {
        "RESOLVED_GENERATOR_CONFIGURATION": 0,
        "RESOLVED_GENERATOR_MECHANISM": 1,
        "COMPONENT_SEED_MANIFEST": 2,
        "SYNTHETIC_SCIENTIFIC_DATA": 3,
        "SYNTHETIC_TRUTH": 4,
        "ANALYSIS_SPEC": 5,
        "FIT_RESPONSE_BINDING": 6,
        "CANONICAL_SCIENTIFIC_PAYLOAD": 7,
        "PREPARATION_AUDIT_EVIDENCE": 8,
    }
    row_role_rank = {
        "INPUT": 9,
        "TRAINING": 10,
        "OUTPUT": 11,
        "REFERENCE_FIT": 12,
    }

    def case_position(record: _ScenarioSourceRecordInput) -> int:
        capability = record.source_capability
        if record.owner_class in {
            "RESOLVED_GENERATOR_CONFIGURATION",
            "RESOLVED_GENERATOR_MECHANISM",
            "COMPONENT_SEED_MANIFEST",
        }:
            if capability is not batch:
                _reject("PUBLIC_MANIFEST_RECORDS")
            matches = [
                index
                for index, case in enumerate(context.cases)
                if record
                in _authenticated_resolved_case_source_records(
                    batch,
                    case.family_id,
                    case.case_id,
                )
            ]
        elif record.owner_class in {
            "SYNTHETIC_SCIENTIFIC_DATA",
            "SYNTHETIC_TRUTH",
        }:
            input_owner = (
                _read_synthetic_scientific_data_input_owner(capability)
                if type(capability) is SyntheticScientificDataEvidence
                else _read_synthetic_truth_scoring_input_owner(capability)
                if type(capability) is SyntheticTruthScoringEvidence
                else None
            )
            if (
                input_owner is None
                or _read_public_synthetic_batch_input_owner(input_owner) is not batch
            ):
                _reject("PUBLIC_MANIFEST_RECORDS")
            case = _resolve_public_synthetic_audit_input(input_owner).resolved_case
            matches = [positions[case.case_id]] if case.case_id in positions else []
        elif record.owner_class == "ANALYSIS_SPEC":
            if type(capability) is not CapturedScientificRun:
                _reject("PUBLIC_MANIFEST_RECORDS")
            state = _read_captured_scientific_run(capability)
            binding = (
                strict_json_loads(state.synthetic_case_binding_bytes)
                if state.synthetic_case_binding_bytes is not None
                else None
            )
            bound_case_id = binding.get("case_id") if type(binding) is dict else None
            matches = [positions[bound_case_id]] if bound_case_id in positions else []
        elif record.owner_class in {
            "FIT_RESPONSE_BINDING",
            "CANONICAL_SCIENTIFIC_PAYLOAD",
        }:
            try:
                source_batch, source_capture = (
                    _read_scientific_meaning_source_owners(capability)
                )
                source_records = _read_scientific_meaning_source_records(capability)
                source_state = _read_captured_scientific_run(source_capture)
                binding = strict_json_loads(source_state.synthetic_case_binding_bytes or b"")
            except Exception:
                _reject("PUBLIC_MANIFEST_RECORDS")
            bound_case_id = binding.get("case_id") if type(binding) is dict else None
            if (
                source_batch is not batch
                or scientific_owner_pair is None
                or source_batch is not scientific_owner_pair[0]
                or source_capture is not scientific_owner_pair[1]
                or sum(candidate == record for candidate in source_records) != 1
            ):
                _reject("PUBLIC_MANIFEST_RECORDS")
            matches = [positions[bound_case_id]] if bound_case_id in positions else []
        elif record.owner_class == "PREPARATION_AUDIT_EVIDENCE":
            case_id = record.natural_identity.get("case_id")
            if (
                type(capability) is not PreparationAuditEvidence
                or type(case_id) is not str
                or record
                not in _preparation_audit_evidence_source_records(
                    capability,
                    case_id=case_id,
                )
            ):
                _reject("PUBLIC_MANIFEST_RECORDS")
            matches = [positions[case_id]] if case_id in positions else []
        elif record.owner_class == "PREPARATION_ROW_INSTANCE_MANIFEST":
            case_id = record.natural_identity.get("case_id")
            if (
                type(capability) is not _PreparationRowInstanceManifestSource
                or type(case_id) is not str
                or record
                not in _preparation_row_instance_manifest_source_records(
                    capability.evidence,
                    capability.manifests,
                    case_id=case_id,
                )
            ):
                _reject("PUBLIC_MANIFEST_RECORDS")
            matches = [positions[case_id]] if case_id in positions else []
        else:
            _reject("PUBLIC_MANIFEST_RECORDS")
        if len(matches) != 1:
            _reject("PUBLIC_MANIFEST_RECORDS")
        return matches[0]

    def record_rank(record: _ScenarioSourceRecordInput) -> tuple[int, int]:
        if record.owner_class == "PREPARATION_ROW_INSTANCE_MANIFEST":
            role = record.natural_identity.get("row_role")
            if type(role) is not str or role not in row_role_rank:
                _reject("PUBLIC_MANIFEST_RECORDS")
            return row_role_rank[role], 0
        rank = class_rank.get(record.owner_class)
        if rank is None:
            _reject("PUBLIC_MANIFEST_RECORDS")
        if record.owner_class in {
            "FIT_RESPONSE_BINDING",
            "CANONICAL_SCIENTIFIC_PAYLOAD",
        }:
            try:
                source_records = _read_scientific_meaning_source_records(record.source_capability)
            except Exception:
                _reject("PUBLIC_MANIFEST_RECORDS")
            indexes = tuple(
                index for index, candidate in enumerate(source_records) if candidate == record
            )
            if len(indexes) != 1:
                _reject("PUBLIC_MANIFEST_RECORDS")
            return rank, indexes[0]
        return rank, 0

    ordered = tuple(
        sorted(
            cast(tuple[_ScenarioSourceRecordInput, ...], records),
            key=lambda record: (case_position(record), *record_rank(record)),
        )
    )
    keys = [(case_position(record), *record_rank(record)) for record in ordered]
    if len(keys) != len(set(keys)):
        _reject("PUBLIC_MANIFEST_RECORDS")
    return cast(tuple[object, ...], ordered)


def _public_synthetic_manifest_context(
    batch: AuthenticatedScenarioCaseBatch,
) -> tuple[bytes, str]:
    """Return the private public-synthetic manifest key and subject binding."""

    context = _read_authenticated_batch_context(batch)
    try:
        state = _BATCH_STATES.read(batch)
    except OneShotRegistryError:
        _reject("BATCH_OWNER")
    with state.lock:
        if len(state.manifest_authentication_key) != 32:
            _reject("BATCH_BINDING")
        return bytes(state.manifest_authentication_key), context.benchmark_subject_digest


def _claim_public_synthetic_input_member(
    batch: AuthenticatedScenarioCaseBatch,
    family_id: str,
    case_id: str,
) -> tuple[bytes, ResolvedSyntheticCase, str]:
    """Consume one exact public-synthetic batch member for input issuance."""

    if (
        type(batch) is not AuthenticatedScenarioCaseBatch
        or type(family_id) is not str
        or not family_id
        or type(case_id) is not str
        or not case_id
    ):
        _reject("PUBLIC_INPUT_MEMBER")
    context = _read_authenticated_batch_context(batch)
    try:
        state = _BATCH_STATES.read(batch)
    except OneShotRegistryError:
        _reject("BATCH_OWNER")
    matches = tuple(
        case
        for case in state.resolved_cases
        if case.coordinate.family_id == family_id and case.case_id == case_id
    )
    if len(matches) != 1 or matches[0].coordinate.resolution_mode not in {
        "DEVELOPMENT_VARIANT",
        "TRANSFORMED_SOURCE",
    }:
        _reject("PUBLIC_INPUT_MEMBER")
    identity = (family_id, case_id)
    with state.lock:
        if identity in state.issued_public_input_identities:
            _reject("PUBLIC_INPUT_ALREADY_ISSUED")
        state.issued_public_input_identities.add(identity)
    return bytes(state.scenario_bytes), matches[0], context.benchmark_subject_digest


def _validate_public_synthetic_input_member(
    batch: AuthenticatedScenarioCaseBatch,
    case: ResolvedSyntheticCase,
) -> tuple[str, str]:
    """Revalidate one issued input member without exposing it through the batch reader."""

    if type(batch) is not AuthenticatedScenarioCaseBatch or type(case) is not ResolvedSyntheticCase:
        _reject("PUBLIC_INPUT_MEMBER")
    context = _read_authenticated_batch_context(batch)
    try:
        state = _BATCH_STATES.read(batch)
    except OneShotRegistryError:
        _reject("BATCH_OWNER")
    identity = (case.coordinate.family_id, case.case_id)
    with state.lock:
        matches = tuple(candidate for candidate in state.resolved_cases if candidate is case)
        if len(matches) != 1 or identity not in state.issued_public_input_identities:
            _reject("PUBLIC_INPUT_MEMBER")
    return identity[0], context.benchmark_subject_digest


def _authenticated_source_case_for_transformed_member(
    batch: AuthenticatedScenarioCaseBatch,
    transformed_case: ResolvedSyntheticCase,
) -> ResolvedSyntheticCase:
    """Return the exact retained source case for one transformed batch member."""

    if (
        type(batch) is not AuthenticatedScenarioCaseBatch
        or type(transformed_case) is not ResolvedSyntheticCase
        or transformed_case.coordinate.resolution_mode != "TRANSFORMED_SOURCE"
    ):
        _reject("SOURCE_ANCESTRY")
    _read_authenticated_batch_context(batch)
    try:
        state = _BATCH_STATES.read(batch)
    except OneShotRegistryError:
        _reject("SOURCE_ANCESTRY")
    if sum(candidate is transformed_case for candidate in state.resolved_cases) != 1:
        _reject("SOURCE_ANCESTRY")

    authority = load_scenario_authority(state.scenario_bytes)
    family_matches = tuple(
        family
        for family in authority.scenario_families
        if family.get("id") == transformed_case.coordinate.family_id
    )
    if len(family_matches) != 1:
        _reject("SOURCE_ANCESTRY")
    variants = family_matches[0].get("development_variants")
    variant_matches = (
        tuple(
            variant
            for variant in variants
            if type(variant) is dict and variant.get("id") == transformed_case.coordinate.variant_id
        )
        if type(variants) is list
        else ()
    )
    source_reference = (
        variant_matches[0].get("source_variant") if len(variant_matches) == 1 else None
    )
    if type(source_reference) is not str or source_reference.count("/") != 1:
        _reject("SOURCE_ANCESTRY")
    source_family, source_variant = source_reference.split("/")
    source_matches = tuple(
        candidate
        for candidate in state.resolved_cases
        if candidate.coordinate.family_id == source_family
        and candidate.coordinate.variant_id == source_variant
        and candidate.coordinate.replicate_index == transformed_case.coordinate.replicate_index
        and candidate.coordinate.resolution_mode == "DEVELOPMENT_VARIANT"
    )
    if len(source_matches) != 1:
        _reject("SOURCE_ANCESTRY")
    source_case = source_matches[0]
    root_context = transformed_case.component_seed_manifest.get("root_assignment_context")
    if (
        family_matches[0].get("source_family") != source_family
        or type(root_context) is not dict
        or root_context.get("source_case_id") != source_case.case_id
    ):
        _reject("SOURCE_ANCESTRY")
    return source_case


def _bind_public_synthetic_missingness_pair(
    batch: AuthenticatedScenarioCaseBatch,
    family_id: str,
    case_id: str,
    evidence_owners: tuple[object, ...],
) -> tuple[_SyntheticMissingnessProjection, _SyntheticMissingnessProjection] | None:
    """Bind an ordered source/transformed pair through retained case ancestry."""

    from ebm_audit.synthetic.audit_input import (
        SyntheticScientificDataEvidence,
        _project_generated_scientific_data_missingness,
        _project_synthetic_scientific_data_missingness,
        _read_synthetic_scientific_data_batch_binding,
    )
    from ebm_audit.synthetic.generator import generate_synthetic_case

    if (
        type(batch) is not AuthenticatedScenarioCaseBatch
        or type(family_id) is not str
        or not family_id
        or type(case_id) is not str
        or not case_id
        or type(evidence_owners) is not tuple
    ):
        _reject("MISSINGNESS_PAIR")
    if family_id != "within_group_feature_permutation_null":
        return None
    if not evidence_owners or len({id(owner) for owner in evidence_owners}) != len(evidence_owners):
        _reject("MISSINGNESS_PAIR")
    _read_authenticated_batch_context(batch)
    try:
        state = _BATCH_STATES.read(batch)
    except OneShotRegistryError:
        _reject("MISSINGNESS_PAIR")
    transformed_matches = tuple(
        candidate
        for candidate in state.resolved_cases
        if candidate.coordinate.family_id == family_id
        and candidate.case_id == case_id
        and candidate.coordinate.resolution_mode == "TRANSFORMED_SOURCE"
    )
    if len(transformed_matches) != 1:
        _reject("MISSINGNESS_PAIR")
    transformed_case = transformed_matches[0]
    source_case = _authenticated_source_case_for_transformed_member(batch, transformed_case)
    authority = load_scenario_authority(state.scenario_bytes)

    bindings: list[tuple[SyntheticScientificDataEvidence, ResolvedSyntheticCase]] = []
    try:
        for evidence in evidence_owners:
            if type(evidence) is not SyntheticScientificDataEvidence:
                _reject("MISSINGNESS_PAIR")
            evidence_batch, evidence_case = _read_synthetic_scientific_data_batch_binding(evidence)
            if (
                evidence_batch is not batch
                or sum(candidate is evidence_case for candidate in state.resolved_cases) != 1
            ):
                _reject("MISSINGNESS_PAIR")
            bindings.append((evidence, evidence_case))
    except TypeError:
        _reject("MISSINGNESS_PAIR")
    source_evidence_matches = tuple(
        evidence for evidence, evidence_case in bindings if evidence_case is source_case
    )
    transformed_evidence_matches = tuple(
        evidence for evidence, evidence_case in bindings if evidence_case is transformed_case
    )
    if len(transformed_evidence_matches) != 1 or len(source_evidence_matches) not in {
        0,
        1,
    }:
        _reject("MISSINGNESS_PAIR")
    transformed_evidence = transformed_evidence_matches[0]
    if source_evidence_matches:
        source_evidence = source_evidence_matches[0]
        if source_evidence is transformed_evidence:
            _reject("MISSINGNESS_PAIR")
        source_projection = _project_synthetic_scientific_data_missingness(source_evidence)
    else:
        source_projection = _project_generated_scientific_data_missingness(
            generate_synthetic_case(authority, source_case),
            source_case,
        )
    transformed_projection = _project_synthetic_scientific_data_missingness(transformed_evidence)
    if (
        source_projection.case_id != source_case.case_id
        or transformed_projection.case_id != transformed_case.case_id
    ):
        _reject("MISSINGNESS_PAIR")
    return source_projection, transformed_projection


def _public_synthetic_manifest_boundary() -> tuple[Callable[..., object], Callable[..., object]]:
    """Claim the public-development manifest capability once for this exact batch type."""

    global _PUBLIC_SYNTHETIC_MANIFEST_BOUNDARY
    with _PUBLIC_SYNTHETIC_MANIFEST_BOUNDARY_LOCK:
        if _PUBLIC_SYNTHETIC_MANIFEST_BOUNDARY is None:
            from ebm_audit.evaluator.scenario_source_owner_manifest import (
                _claim_scenario_source_owner_manifest_boundary,
            )

            _PUBLIC_SYNTHETIC_MANIFEST_BOUNDARY = cast(
                tuple[Callable[..., object], Callable[..., object]],
                _claim_scenario_source_owner_manifest_boundary(
                    authority_origin="PUBLIC_SYNTHETIC",
                    owner_type=AuthenticatedScenarioCaseBatch,
                    authenticated_context=_public_synthetic_manifest_context,
                    missingness_pair=_bind_public_synthetic_missingness_pair,
                ),
            )
        return _PUBLIC_SYNTHETIC_MANIFEST_BOUNDARY


def _issue_public_synthetic_source_owner_manifest_impl(
    batch: AuthenticatedScenarioCaseBatch,
    plan: tuple[object, ...],
    records: tuple[object, ...],
) -> object:
    """Issue one batch-owned manifest from exact retained input evidence."""

    from ebm_audit.evaluator.scenario_source_owner_manifest import (
        _preparation_row_instance_manifest_source_records,
        _PreparationRowInstanceManifestSource,
        _read_scientific_meaning_source_owners,
        _read_scientific_meaning_source_records,
        _ScenarioSourceRecordInput,
    )
    from ebm_audit.science.capture import (
        CapturedScientificRun,
        PreparationAuditEvidence,
        ScientificEvidenceError,
        _issue_preparation_audit_evidence,
        _issue_preparation_row_instance_manifests,
    )
    from ebm_audit.synthetic.audit_input import (
        _read_public_synthetic_batch_input_owner,
        _read_synthetic_scientific_data_input_owner,
        _read_synthetic_truth_scoring_input_owner,
    )

    _read_authenticated_batch_context(batch)
    if type(records) is not tuple or not records:
        _reject("PUBLIC_MANIFEST_RECORDS")
    captured_owners = tuple(
        getattr(record, "source_capability", None)
        for record in records
        if getattr(record, "owner_class", None) == "ANALYSIS_SPEC"
    )
    scientific_owner_pair: tuple[object, object] | None = None
    for record in records:
        owner_class = getattr(record, "owner_class", None)
        source_capability = getattr(record, "source_capability", None)
        if owner_class == "SYNTHETIC_TRUTH":
            input_owner = _read_synthetic_truth_scoring_input_owner(source_capability)
        elif owner_class == "SYNTHETIC_SCIENTIFIC_DATA":
            input_owner = _read_synthetic_scientific_data_input_owner(source_capability)
        elif owner_class in {
            "RESOLVED_GENERATOR_CONFIGURATION",
            "RESOLVED_GENERATOR_MECHANISM",
            "COMPONENT_SEED_MANIFEST",
        }:
            if source_capability is not batch:
                _reject("PUBLIC_MANIFEST_RECORDS")
            continue
        elif owner_class == "ANALYSIS_SPEC":
            if type(source_capability) is not CapturedScientificRun:
                _reject("PUBLIC_MANIFEST_RECORDS")
            continue
        elif owner_class in {
            "FIT_RESPONSE_BINDING",
            "CANONICAL_SCIENTIFIC_PAYLOAD",
        }:
            try:
                source_batch, source_capture = (
                    _read_scientific_meaning_source_owners(source_capability)
                )
                source_records = _read_scientific_meaning_source_records(source_capability)
            except Exception:
                _reject("PUBLIC_MANIFEST_RECORDS")
            if (
                source_batch is not batch
                or len(captured_owners) != 1
                or source_capture is not captured_owners[0]
                or (
                    scientific_owner_pair is not None
                    and (
                        source_batch is not scientific_owner_pair[0]
                        or source_capture is not scientific_owner_pair[1]
                    )
                )
                or sum(candidate == record for candidate in source_records) != 1
            ):
                _reject("PUBLIC_MANIFEST_RECORDS")
            scientific_owner_pair = (
                source_batch,
                source_capture,
            )
            continue
        elif owner_class == "PREPARATION_AUDIT_EVIDENCE":
            if (
                type(source_capability) is not PreparationAuditEvidence
                or len(captured_owners) != 1
                or type(captured_owners[0]) is not CapturedScientificRun
            ):
                _reject("PUBLIC_MANIFEST_RECORDS")
            try:
                expected = _issue_preparation_audit_evidence(captured_owners[0])
            except ScientificEvidenceError:
                _reject("PUBLIC_MANIFEST_RECORDS")
            if expected is not source_capability:
                _reject("PUBLIC_MANIFEST_RECORDS")
            continue
        elif owner_class == "PREPARATION_ROW_INSTANCE_MANIFEST":
            row_record = cast(_ScenarioSourceRecordInput, record)
            if (
                type(source_capability) is not _PreparationRowInstanceManifestSource
                or len(captured_owners) != 1
                or type(captured_owners[0]) is not CapturedScientificRun
            ):
                _reject("PUBLIC_MANIFEST_RECORDS")
            try:
                expected = _issue_preparation_audit_evidence(captured_owners[0])
                if (
                    type(expected) is not PreparationAuditEvidence
                    or source_capability.evidence is not expected
                    or source_capability.manifests
                    is not _issue_preparation_row_instance_manifests(expected)
                    or row_record
                    not in _preparation_row_instance_manifest_source_records(
                        expected,
                        source_capability.manifests,
                        case_id=cast(
                            str,
                            row_record.natural_identity.get("case_id"),
                        ),
                    )
                ):
                    _reject("PUBLIC_MANIFEST_RECORDS")
            except ScientificEvidenceError:
                _reject("PUBLIC_MANIFEST_RECORDS")
            continue
        else:
            _reject("PUBLIC_MANIFEST_RECORDS")
        if _read_public_synthetic_batch_input_owner(input_owner) is not batch:
            _reject("PUBLIC_MANIFEST_RECORDS")
    issue, _read = _public_synthetic_manifest_boundary()
    ordered_records = _canonical_public_synthetic_source_records(batch, records)
    return issue(
        batch,
        "DEVELOPMENT",
        plan,
        ordered_records,
    )


def _issue_public_synthetic_source_owner_manifest(
    batch: AuthenticatedScenarioCaseBatch,
    plan: tuple[object, ...],
    records: tuple[object, ...],
) -> object:
    """Issue one manifest within one transaction-local preparation bundle."""

    from ebm_audit.evaluator.scenario_source_owner_manifest import (
        _preparation_source_owner_transaction,
        _ScenarioSourceRecordInput,
        _scientific_meaning_source_owner_transaction,
    )

    if (
        type(records) is tuple
        and records
        and all(type(record) is _ScenarioSourceRecordInput for record in records)
    ):
        with _preparation_source_owner_transaction(
            cast(tuple[_ScenarioSourceRecordInput, ...], records)
        ):
            with _scientific_meaning_source_owner_transaction(
                cast(tuple[_ScenarioSourceRecordInput, ...], records)
            ):
                return _issue_public_synthetic_source_owner_manifest_impl(
                    batch,
                    plan,
                    records,
                )
    return _issue_public_synthetic_source_owner_manifest_impl(batch, plan, records)


def _read_public_synthetic_source_owner_manifest(
    batch: AuthenticatedScenarioCaseBatch,
    manifest: object,
    plan: tuple[object, ...],
) -> dict[str, object]:
    """Consume one exact public-development manifest through its batch authority."""

    _read_authenticated_batch_context(batch)
    _issue, read = _public_synthetic_manifest_boundary()
    value = read(batch, manifest, plan)
    if type(value) is not dict:
        _reject("PUBLIC_MANIFEST_RECORDS")
    return cast(dict[str, object], value)


__all__: list[str] = []
