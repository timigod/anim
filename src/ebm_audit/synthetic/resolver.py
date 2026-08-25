"""Typed reconstruction of synthetic parameters, seeds, and configuration."""

from __future__ import annotations

import copy
import hashlib
import hmac
import math
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from itertools import pairwise
from pathlib import Path
from threading import RLock
from typing import Any, Final, Literal, Never, SupportsIndex, cast, final
from weakref import WeakSet

import numpy as np

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol.canonical import (
    canonical_json_bytes,
    structured_sha256,
    structured_sha256_hex,
)
from ebm_audit.schema.validation import SchemaValidationError, validate_instance

from .authority import (
    COMPONENT_PATHS,
    DEPENDENCY_STAGE_IDS,
    FIELD_IDS,
    ScenarioAuthority,
    load_scenario_authority,
    scenario_authority_source_reference,
)
from .models import (
    AuthenticatedSourceOwner,
    CaseCoordinate,
    ComponentSeed,
    FieldResolution,
    HeldoutCaseResolution,
    HeldoutResolvedCase,
    ResolvedSyntheticCase,
    RetainedGeneratorInvalid,
    _freeze_field_resolution,
    _require_authenticated_retained_generator_invalid,
    _retain_generator_invalid,
)
from .pure_no_signal import verify_pure_no_signal_semantics

_UINT64_HEX = re.compile(r"[0-9a-f]{16}\Z")
DEFAULT_EVENT_COUNT: Final = 8
MATCHED_COMPARATOR_GENERATION_STATE: Final = "UNAVAILABLE_PENDING_AUTHENTICATED_TRANSACTION_OWNER"
TRANSFORMED_NULL_GENERATION_STATE: Final = "UNAVAILABLE_PENDING_GENERATED_DATA_OWNER"
_INTEGER_TYPES = {
    "uint16",
    "uint32",
    "positive_uint16",
    "positive_uint32",
    "nonnegative_uint32",
}
_OPERATION_PATHS = {
    "label_permutation_null": ("label_permutation",),
    "within_group_feature_permutation_null": ("within_group_feature_permutation",),
}
_TRANSFORMED_OPERATION_FIELDS = {
    "source_events",
    "source_participants",
    "source_variant",
    "permutations_per_source",
    "truth_type",
}
_HEAVY_TAIL_FAMILY_PARAMETERS = {
    "multivariate_student_t": ("student_t_df",),
    "normal_plus_centered_lognormal": (
        "centered_lognormal_sigma",
        "centered_lognormal_weight",
    ),
    "student_t_plus_centered_lognormal": (
        "student_t_df",
        "centered_lognormal_sigma",
        "centered_lognormal_weight",
    ),
}
_HEAVY_TAIL_CONDITIONAL_PARAMETERS = frozenset().union(*_HEAVY_TAIL_FAMILY_PARAMETERS.values())
_HELDOUT_OVERRIDE_KEYS = {
    "noise_ladder": frozenset({"ordered_measurement_noise_sd_levels", "baseline_level_index"}),
    "group_boundary_sensitivity": frozenset(
        {
            "ordered_rule_ids",
            "ordered_boundary_quantile_shifts",
            "base_quantile_cutoff",
            "baseline_rule_id",
        }
    ),
}
_GROUP_BOUNDARY_RULE_IDS = ["boundary_q50", "boundary_q35", "boundary_q65"]
_GROUP_BOUNDARY_QUANTILE_SHIFTS = [0.0, -0.15, 0.15]
_DIRECT_DESTINATIONS = {
    "participants": "/dimensions/participant_count",
    "events": "/dimensions/event_count",
    "amplitude": "/event_parameters/amplitude",
    "transition_width": "/event_parameters/transition_width",
    "covariate_event_effect": "/event_parameters/covariate_effect",
    "event_covariate_effect": "/event_parameters/covariate_effect",
    "group_event_effect": "/event_parameters/group_effect",
    "participant_random_effect_loading": "/event_parameters/participant_effect_loading",
    "measurement_noise_sd": "/measurement_noise/standard_deviations",
    "measurement_noise_sd_levels": "/scenario_parameters/measurement_noise_sd_levels",
    "reference_sampling_window": "/latent_sampling/reference_window",
    "at_risk_sampling_window": "/latent_sampling/at_risk_window",
    "boundary_rule_ids": "/scenario_parameters/boundary_rule_ids",
    "boundary_quantile_shifts": "/scenario_parameters/boundary_quantile_shifts",
    "base_quantile_cutoff": "/scenario_parameters/base_quantile_cutoff",
    "wrong_direction_event_ids": "/scenario_parameters/wrong_direction_event_ids",
}


_ROOT_COMMITMENT_FIELDS = (
    "heldout_manifest_template_sha256",
    "candidate_sha256",
    "analysis_plan_digest",
    "benchmark_contract_sha256",
    "generator_sha256",
    "scenario_definitions_sha256",
    "metrics_rules_sha256",
    "report_language_rules_sha256",
    "benchmark_freeze_receipt_sha256",
    "candidate_freeze_receipt_sha256",
    "benchmark_subject_digest",
)


@dataclass(slots=True)
class _HeldoutCaseResolverState:
    root_hmac: hmac.HMAC
    heldout_attempt_id: str
    verified_root_commitment: str
    coordinate: CaseCoordinate
    variant_index: int
    source_owner: AuthenticatedSourceOwner | None
    family_overrides: dict[str, Any] | None
    authentication_tag: bytes
    claimed: bool
    claim_lock: RLock


_CAPABILITY_STATES: OneShotWeakRegistry[_HeldoutCaseResolverCapability, _HeldoutCaseResolverState]
_CAPABILITY_STATES, _CAPABILITY_STATE_ISSUER = create_one_shot_registry()
_RUNNER_ISSUER_CLAIMS: WeakSet[type[object]] = WeakSet()
_RUNNER_ISSUER_CLAIM_LOCK = RLock()


@final
class _HeldoutCaseResolverCapability:
    """Opaque, authenticated, one-shot authority for one exact attempt coordinate."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _HeldoutCaseResolverCapability:
        raise TypeError("Held-out resolver capabilities are evaluator-issued only.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Held-out resolver capabilities are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Held-out resolver capabilities cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Held-out resolver capabilities cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Held-out resolver capabilities cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Held-out resolver capabilities cannot be copied or serialized.")

    def __repr__(self) -> str:
        return "_HeldoutCaseResolverCapability(<redacted>)"

    __str__ = __repr__

    @staticmethod
    def _authentication_digest(state: _HeldoutCaseResolverState) -> bytes:
        source_digest = (
            state.source_owner.resolved_case.resolved_parameter_manifest.get(
                "resolved_parameter_manifest_sha256"
            )
            if state.source_owner is not None
            else None
        )
        binding_digest = structured_sha256_hex(
            "ebm-audit/heldout-resolver-capability/1",
            {
                "heldout_attempt_id": state.heldout_attempt_id,
                "verified_root_commitment": state.verified_root_commitment,
                "family_id": state.coordinate.family_id,
                "variant_id": state.coordinate.variant_id,
                "variant_index": state.variant_index,
                "replicate_index": state.coordinate.replicate_index,
                "resolution_mode": state.coordinate.resolution_mode,
                "source_parameter_manifest_sha256": source_digest,
                "family_override": state.family_overrides,
            },
        )
        owner_hmac = state.root_hmac.copy()
        owner_hmac.update(
            b"ebm-audit-heldout-resolver-capability/v1\0" + binding_digest.encode("ascii")
        )
        return owner_hmac.digest()

    def _claim(
        self, heldout_attempt_id: str
    ) -> tuple[
        str,
        CaseCoordinate,
        int,
        AuthenticatedSourceOwner | None,
        dict[str, Any] | None,
        str | None,
    ]:
        try:
            state = _CAPABILITY_STATES.read(self)
        except OneShotRegistryError:
            raise _fail(
                "GENERATOR.HELDOUT_CAPABILITY_INVALID",
                "The held-out resolver capability is invalid.",
            ) from None
        if not hmac.compare_digest(state.authentication_tag, self._authentication_digest(state)):
            raise _fail(
                "GENERATOR.HELDOUT_CAPABILITY_AUTHENTICATION_FAILED",
                "The held-out resolver capability failed authentication.",
            )
        if heldout_attempt_id != state.heldout_attempt_id:
            raise _fail(
                "GENERATOR.HELDOUT_ATTEMPT_MISMATCH",
                "The held-out resolver capability belongs to a different attempt.",
            )
        with state.claim_lock:
            if state.claimed:
                raise _fail(
                    "GENERATOR.HELDOUT_CAPABILITY_REUSED",
                    "The held-out resolver capability has already been consumed.",
                )
            state.claimed = True
            message = (
                b"ebm-audit-heldout-case/v1\0"
                + state.heldout_attempt_id.encode("ascii")
                + b"\0"
                + state.coordinate.family_id.encode("utf-8")
                + b"\0"
                + _canonical_unsigned_decimal(state.variant_index).encode("ascii")
                + b"\0"
                + _canonical_unsigned_decimal(state.coordinate.replicate_index).encode("ascii")
            )
            case_hmac = state.root_hmac.copy()
            case_hmac.update(message)
            pre_root_stratum_id = None
            if state.coordinate.family_id == "correlated_duplicate_events":
                pre_root_stratum_id = (
                    "correlated"
                    if state.coordinate.replicate_index % 2 == 0
                    else "exact_duplicate_post_noise"
                )
        return (
            case_hmac.digest()[:8].hex(),
            state.coordinate,
            state.variant_index,
            state.source_owner,
            copy.deepcopy(state.family_overrides),
            pre_root_stratum_id,
        )


def _bind_heldout_case_resolver_capability(
    root_seed: bytes,
    *,
    heldout_attempt_id: str,
    claimed_root_commitment: str,
    root_commitment_domain: str,
    root_commitment_preimage: Mapping[str, object],
    coordinate: CaseCoordinate,
    variant_index: int,
    source_owner: AuthenticatedSourceOwner | None = None,
    family_override: Mapping[str, Any] | None = None,
) -> _HeldoutCaseResolverCapability:
    """Validate and bind one private attempted-case capability."""

    if type(root_seed) is not bytes or len(root_seed) != 32:
        raise _fail("GENERATOR.HELDOUT_ROOT_INVALID", "The held-out root is invalid.")
    if not heldout_attempt_id or not heldout_attempt_id.isascii() or "\0" in heldout_attempt_id:
        raise _fail("GENERATOR.HELDOUT_ATTEMPT_INVALID", "The held-out attempt is invalid.")
    preimage = copy.deepcopy(dict(root_commitment_preimage))
    expected_commitment = hashlib.sha256(
        root_commitment_domain.encode("ascii")
        + b"\0"
        + root_seed
        + b"\0"
        + canonical_json_bytes(preimage)
    ).hexdigest()
    if not hmac.compare_digest(claimed_root_commitment, expected_commitment):
        raise _fail(
            "GENERATOR.HELDOUT_ROOT_COMMITMENT_MISMATCH",
            "The private held-out root does not match its authenticated commitment.",
        )
    if type(coordinate) is not CaseCoordinate:
        raise _fail(
            "GENERATOR.HELDOUT_COORDINATE_INVALID",
            "A held-out case coordinate is structurally invalid.",
        )
    _canonical_unsigned_decimal(variant_index)
    _canonical_unsigned_decimal(coordinate.replicate_index)
    if (
        not coordinate.family_id
        or "\0" in coordinate.family_id
        or not coordinate.variant_id
        or "\0" in coordinate.variant_id
    ):
        raise _fail(
            "GENERATOR.HELDOUT_COORDINATE_INVALID",
            "A held-out case coordinate is structurally invalid.",
        )
    if coordinate.resolution_mode == "HELDOUT_RANGE":
        if coordinate.family_id in _OPERATION_PATHS or source_owner is not None:
            raise _fail(
                "GENERATOR.HELDOUT_CASE_PLAN_INVALID",
                "A held-out case plan is structurally invalid.",
            )
    elif coordinate.resolution_mode == "TRANSFORMED_SOURCE":
        if (
            coordinate.family_id not in _OPERATION_PATHS
            or type(source_owner) is not AuthenticatedSourceOwner
        ):
            raise _fail(
                "GENERATOR.HELDOUT_CASE_PLAN_INVALID",
                "A held-out case plan is structurally invalid.",
            )
    else:
        raise _fail(
            "GENERATOR.HELDOUT_CASE_PLAN_INVALID",
            "A held-out case plan is structurally invalid.",
        )
    override = copy.deepcopy(dict(family_override)) if family_override is not None else None
    if override is not None:
        allowed = _HELDOUT_OVERRIDE_KEYS.get(coordinate.family_id)
        if allowed is None or set(override) != allowed:
            raise _fail(
                "GENERATOR.HELDOUT_OVERRIDE_INVALID",
                "A held-out family override is structurally invalid.",
            )
        _validate_heldout_family_override(coordinate.family_id, override)
    root_hmac = hmac.new(root_seed, digestmod=hashlib.sha256)
    state = _HeldoutCaseResolverState(
        root_hmac=root_hmac,
        heldout_attempt_id=heldout_attempt_id,
        verified_root_commitment=expected_commitment,
        coordinate=coordinate,
        variant_index=variant_index,
        source_owner=source_owner,
        family_overrides=override,
        authentication_tag=b"",
        claimed=False,
        claim_lock=RLock(),
    )
    state.authentication_tag = _HeldoutCaseResolverCapability._authentication_digest(state)
    capability = object.__new__(_HeldoutCaseResolverCapability)
    _CAPABILITY_STATE_ISSUER.bind_once(capability, state)
    return capability


def _claim_heldout_case_resolver_issuer[T](
    *,
    owner_type: type[T],
    attempt_material: Callable[[T], tuple[bytes, str, str, str, Mapping[str, object]]],
) -> Callable[
    [T, CaseCoordinate, int, AuthenticatedSourceOwner | None, Mapping[str, Any] | None],
    _HeldoutCaseResolverCapability,
]:
    """Give the exact evaluator runner its sole ordinary resolver issuer."""

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
            and attempt_material.__module__ == module_name
            and getattr(module, "_AuthenticatedHeldoutAttempt", None) is owner_type
            and getattr(module, "_heldout_attempt_material", None) is attempt_material
        )
    except (AttributeError, OSError, TypeError):
        authentic = False
    with _RUNNER_ISSUER_CLAIM_LOCK:
        if not authentic or claimed_owner_type in _RUNNER_ISSUER_CLAIMS:
            raise _fail("GENERATOR.HELDOUT_ISSUER_INVALID", "The held-out issuer is invalid.")
        _RUNNER_ISSUER_CLAIMS.add(claimed_owner_type)

    def issue(
        attempt_owner: T,
        coordinate: CaseCoordinate,
        variant_index: int,
        source_owner: AuthenticatedSourceOwner | None,
        family_override: Mapping[str, Any] | None,
    ) -> _HeldoutCaseResolverCapability:
        if type(attempt_owner) is not owner_type:
            raise _fail("GENERATOR.HELDOUT_ATTEMPT_OWNER_INVALID", "The held-out owner is invalid.")
        root, attempt_id, commitment, domain, preimage = attempt_material(attempt_owner)
        return _bind_heldout_case_resolver_capability(
            root,
            heldout_attempt_id=attempt_id,
            claimed_root_commitment=commitment,
            root_commitment_domain=domain,
            root_commitment_preimage=preimage,
            coordinate=coordinate,
            variant_index=variant_index,
            source_owner=source_owner,
            family_override=family_override,
        )

    return issue


def _issue_heldout_case_resolver_capability_for_test(
    root_seed: bytes,
    *,
    heldout_attempt_id: str,
    claimed_root_commitment: str,
    root_commitment_preimage: Mapping[str, object],
    coordinate: CaseCoordinate,
    variant_index: int,
    source_owner: AuthenticatedSourceOwner | None = None,
    family_override: Mapping[str, Any] | None = None,
) -> _HeldoutCaseResolverCapability:
    """Deterministic synthetic-only hook; never used by the ordinary runner."""

    return _bind_heldout_case_resolver_capability(
        root_seed,
        heldout_attempt_id=heldout_attempt_id,
        claimed_root_commitment=claimed_root_commitment,
        root_commitment_domain="ebm-audit/heldout-root-commitment/4",
        root_commitment_preimage=root_commitment_preimage,
        coordinate=coordinate,
        variant_index=variant_index,
        source_owner=source_owner,
        family_override=family_override,
    )


def _fail(code: str, message: str) -> InvalidInputError:
    return InvalidInputError(code, message)


def _canonical_unsigned_decimal(value: object) -> str:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _fail(
            "GENERATOR.HELDOUT_COORDINATE_INVALID",
            "A held-out case coordinate integer is structurally invalid.",
        )
    return str(value)


def _validate_heldout_family_override(family_id: str, value: Mapping[str, Any]) -> None:
    valid = False
    if family_id == "noise_ladder":
        levels = value["ordered_measurement_noise_sd_levels"]
        baseline_index = value["baseline_level_index"]
        valid = (
            isinstance(levels, list)
            and bool(levels)
            and all(
                not isinstance(level, bool)
                and isinstance(level, (int, float))
                and math.isfinite(level)
                and level > 0
                for level in levels
            )
            and all(left < right for left, right in pairwise(levels))
            and isinstance(baseline_index, int)
            and not isinstance(baseline_index, bool)
            and 0 <= baseline_index < len(levels)
        )
    elif family_id == "group_boundary_sensitivity":
        rule_ids = value["ordered_rule_ids"]
        shifts = value["ordered_boundary_quantile_shifts"]
        cutoff = value["base_quantile_cutoff"]
        baseline_rule = value["baseline_rule_id"]
        valid = (
            isinstance(rule_ids, list)
            and bool(rule_ids)
            and all(isinstance(rule_id, str) and bool(rule_id) for rule_id in rule_ids)
            and len(set(rule_ids)) == len(rule_ids)
            and isinstance(shifts, list)
            and len(shifts) == len(rule_ids)
            and all(
                not isinstance(shift, bool)
                and isinstance(shift, (int, float))
                and math.isfinite(shift)
                for shift in shifts
            )
            and not isinstance(cutoff, bool)
            and isinstance(cutoff, (int, float))
            and math.isfinite(cutoff)
            and 0 < cutoff < 1
            and isinstance(baseline_rule, str)
            and baseline_rule in rule_ids
            and rule_ids == _GROUP_BOUNDARY_RULE_IDS
            and shifts == _GROUP_BOUNDARY_QUANTILE_SHIFTS
            and cutoff == 0.5
            and baseline_rule == "boundary_q50"
            and [cutoff + shift for shift in shifts] == [0.5, 0.35, 0.65]
        )
    if not valid:
        raise _fail(
            "GENERATOR.HELDOUT_OVERRIDE_INVALID",
            "A held-out family override is structurally invalid.",
        )


def _heavy_tail_mechanism(authority: ScenarioAuthority) -> list[str]:
    closure = _mapping(
        authority.data.get("family_mechanism_closure"),
        "GENERATOR.FAMILY_MECHANISM_INVALID",
    )
    mechanism = _mapping(
        closure.get("heavy_tailed_skewed"),
        "GENERATOR.FAMILY_MECHANISM_INVALID",
    )
    choices = mechanism.get("measurement_noise_family_choices")
    conditional = mechanism.get("conditional_parameter_draws")
    expected_choices = list(_HEAVY_TAIL_FAMILY_PARAMETERS)
    expected_conditional = {
        family_id: list(field_ids) for family_id, field_ids in _HEAVY_TAIL_FAMILY_PARAMETERS.items()
    }
    if choices != expected_choices or conditional != expected_conditional:
        raise _fail(
            "GENERATOR.HEAVY_TAIL_FAMILY_REGISTRY_INVALID",
            "The heavy-tail measurement-noise family mechanism is invalid.",
        )
    return copy.deepcopy(expected_choices)


def _mapping(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise _fail(code, "A closed synthetic contract object is structurally invalid.")
    return value


def _list_of_mappings(value: object, code: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise _fail(code, "A closed synthetic contract registry is structurally invalid.")
    return cast(list[dict[str, Any]], value)


def _validate_schema(instance: object, *, definition: str | None = None) -> None:
    try:
        validate_instance(
            instance,
            "synthetic-resolved-configuration.schema.json",
            definition=definition,
        )
    except SchemaValidationError as exc:
        raise _fail(
            "GENERATOR.RESOLUTION_SCHEMA_INVALID",
            "A reconstructed synthetic owner failed its closed schema.",
        ) from exc


def _persisted_record(record: dict[str, Any], digest_field: str, domain: str) -> dict[str, Any]:
    preimage = copy.deepcopy(record)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage[digest_field] = None
    result = copy.deepcopy(preimage)
    result["digest_state"] = "PERSISTED"
    result[digest_field] = structured_sha256_hex(domain, preimage)
    return result


def _case_seed(authority: ScenarioAuthority, coordinate: CaseCoordinate) -> str:
    policy = _mapping(authority.data.get("seed_policy"), "GENERATOR.SEED_POLICY_INVALID")
    roots = policy.get("development_root_seeds")
    if (
        not isinstance(roots, list)
        or coordinate.replicate_index < 0
        or coordinate.replicate_index >= len(roots)
    ):
        raise _fail(
            "GENERATOR.REPLICATE_OUTSIDE_AUTHORITY",
            "The synthetic replicate has no declared development root.",
        )
    root = roots[coordinate.replicate_index]
    if not isinstance(root, str) or _UINT64_HEX.fullmatch(root) is None:
        raise _fail("GENERATOR.SEED_POLICY_INVALID", "A declared development root is invalid.")
    message = (
        "ebm-audit-development/v1\0"
        + coordinate.family_id
        + "\0"
        + coordinate.variant_id
        + "\0"
        + str(coordinate.replicate_index)
    ).encode()
    return hmac.new(bytes.fromhex(root), message, hashlib.sha256).digest()[:8].hex()


def _operation_seed(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    source_case_id: str,
) -> str:
    roots = _mapping(authority.data.get("seed_policy"), "GENERATOR.SEED_POLICY_INVALID").get(
        "development_root_seeds"
    )
    if not isinstance(roots, list) or not 0 <= coordinate.replicate_index < len(roots):
        raise _fail(
            "GENERATOR.REPLICATE_OUTSIDE_AUTHORITY",
            "The synthetic null operation has no declared development root.",
        )
    root = roots[coordinate.replicate_index]
    if not isinstance(root, str) or _UINT64_HEX.fullmatch(root) is None:
        raise _fail("GENERATOR.SEED_POLICY_INVALID", "A declared development root is invalid.")
    message = (
        "ebm-audit-development-null-operation/v1\0"
        + source_case_id
        + "\0"
        + coordinate.family_id
        + "\0"
        + str(coordinate.replicate_index)
    ).encode()
    return hmac.new(bytes.fromhex(root), message, hashlib.sha256).digest()[:8].hex()


def _component_record(root_seed: str, path: str, root_kind: str) -> ComponentSeed:
    if _UINT64_HEX.fullmatch(root_seed) is None:
        raise _fail("GENERATOR.COMPONENT_ROOT_INVALID", "A component root seed is invalid.")
    digest = hmac.new(
        bytes.fromhex(root_seed),
        b"ebm-audit-synthetic-component/v1\0" + path.encode(),
        hashlib.sha256,
    ).digest()
    return ComponentSeed(
        component_path=path,
        root_kind=cast(Literal["CASE_SEED", "SHARED_DRAW_SEED", "OPERATION_SEED"], root_kind),
        full_digest="sha256:" + digest.hex(),
        seed_128=digest[:16].hex(),
        shared=root_kind == "SHARED_DRAW_SEED",
    )


def _component_manifest(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    case_seed: str,
    source_case_id: str | None,
) -> tuple[tuple[ComponentSeed, ...], dict[str, Any], str | None]:
    operation_paths: tuple[str, ...]
    if coordinate.resolution_mode == "TRANSFORMED_SOURCE":
        if coordinate.family_id not in _OPERATION_PATHS or source_case_id is None:
            raise _fail(
                "GENERATOR.NULL_CONTEXT_INVALID",
                "The transformed synthetic case has no closed null-operation context.",
            )
        context: dict[str, Any] = {
            "kind": "DEVELOPMENT_NULL_OPERATION",
            "source_case_id": source_case_id,
            "null_family_id": coordinate.family_id,
            "null_replicate_index": coordinate.replicate_index,
        }
        operation_paths = _OPERATION_PATHS[coordinate.family_id]
        operation_seed = _operation_seed(authority, coordinate, source_case_id)
    else:
        if coordinate.family_id in _OPERATION_PATHS:
            raise _fail(
                "GENERATOR.NULL_CONTEXT_INVALID",
                "A null-transformation family requires an authenticated source case.",
            )
        context = {"kind": "ORDINARY_CASE"}
        operation_paths = ()
        operation_seed = None

    rows: list[ComponentSeed] = []
    for path in COMPONENT_PATHS:
        if path in operation_paths:
            if operation_seed is None:
                raise _fail(
                    "GENERATOR.COMPONENT_ROOT_INVALID",
                    "A declared null-operation component root is absent.",
                )
            rows.append(_component_record(operation_seed, path, "OPERATION_SEED"))
        else:
            rows.append(_component_record(case_seed, path, "CASE_SEED"))
    preimage = {
        "schema_version": "ebm-audit-component-seed-manifest/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "scenario_family_id": coordinate.family_id,
        "root_assignment_context": context,
        "case_seed": case_seed,
        "shared_draw_seed": None,
        "operation_seed": operation_seed,
        "shared_component_paths": [],
        "operation_component_paths": list(operation_paths),
        "ordered_component_paths": list(COMPONENT_PATHS),
        "components": [
            {
                "component_path": row.component_path,
                "root_kind": row.root_kind,
                "full_digest": row.full_digest,
                "seed_128": row.seed_128,
                "numpy_version": np.__version__,
                "bit_generator": "PCG64DXSM",
                "shared": row.shared,
            }
            for row in rows
        ],
        "component_seed_manifest_sha256": None,
    }
    manifest = _persisted_record(
        preimage,
        "component_seed_manifest_sha256",
        "ebm-audit/component-seed-manifest/1",
    )
    _validate_schema(manifest, definition="ComponentSeedManifest")
    return tuple(rows), manifest, operation_seed


def _exact_tick(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _fail("GENERATOR.DECIMAL_TICK_INVALID", "A decimal-tick endpoint is invalid.")
    if isinstance(value, float) and not math.isfinite(value):
        raise _fail("GENERATOR.DECIMAL_TICK_INVALID", "A decimal-tick endpoint is invalid.")
    try:
        scaled = Decimal(str(value)) * Decimal(1_000_000)
    except InvalidOperation as exc:
        raise _fail(
            "GENERATOR.DECIMAL_TICK_INVALID", "A decimal-tick endpoint is invalid."
        ) from exc
    if scaled != scaled.to_integral_value():
        raise _fail(
            "GENERATOR.DECIMAL_TICK_INVALID",
            "A decimal-tick endpoint is not on the declared grid.",
        )
    return int(scaled)


def sample_decimal_tick(
    minimum: float,
    maximum: float,
    *,
    seed_128: str,
) -> tuple[int, float]:
    """Sample one signed inclusive 1e-6 tick using the normative RNG."""

    if re.fullmatch(r"[0-9a-f]{32}", seed_128) is None:
        raise _fail("GENERATOR.COMPONENT_SEED_INVALID", "A component seed is invalid.")
    low = _exact_tick(minimum)
    high = _exact_tick(maximum)
    if low > high:
        raise _fail("GENERATOR.PARAMETER_RANGE_REVERSED", "A parameter range is reversed.")
    rng = np.random.Generator(np.random.PCG64DXSM(int(seed_128, 16)))
    sampled = int(rng.integers(low, high + 1))
    return sampled, float(np.float64(sampled) / np.float64(1_000_000))


def _family_and_variant(
    authority: ScenarioAuthority, coordinate: CaseCoordinate
) -> tuple[int, dict[str, Any], int | None, dict[str, Any] | None]:
    family_matches = [
        (index, row)
        for index, row in enumerate(authority.scenario_families)
        if row.get("id") == coordinate.family_id
    ]
    if len(family_matches) != 1:
        raise _fail(
            "GENERATOR.FAMILY_NOT_UNIQUE",
            "The requested synthetic family is absent or duplicated.",
        )
    family_index, family = family_matches[0]
    if coordinate.resolution_mode == "HELDOUT_RANGE":
        if coordinate.family_id in _OPERATION_PATHS:
            raise _fail(
                "GENERATOR.NULL_HELDOUT_RANGE_PROHIBITED",
                "A transformed-source null cannot resolve through direct held-out range mode.",
            )
        return family_index, family, None, None
    variants = _list_of_mappings(
        family.get("development_variants", []), "GENERATOR.VARIANT_REGISTRY_INVALID"
    )
    variant_matches = [
        (index, row) for index, row in enumerate(variants) if row.get("id") == coordinate.variant_id
    ]
    if len(variant_matches) != 1:
        raise _fail(
            "GENERATOR.VARIANT_NOT_UNIQUE",
            "The requested synthetic development variant is absent or duplicated.",
        )
    variant_index, variant = variant_matches[0]
    replicate_count = family.get("development_replicates")
    if (
        not isinstance(replicate_count, int)
        or isinstance(replicate_count, bool)
        or not 0 <= coordinate.replicate_index < replicate_count
    ):
        raise _fail(
            "GENERATOR.REPLICATE_OUTSIDE_FAMILY",
            "The requested replicate is outside the declared family denominator.",
        )
    return family_index, family, variant_index, variant


def _middle_pair(event_ids: list[str], *, correlated: bool = False) -> list[str]:
    if correlated and not 7 <= len(event_ids) <= 10:
        raise _fail(
            "GENERATOR.DUPLICATE_DIMENSION_INVALID",
            "The duplicate-event selector requires seven to ten events.",
        )
    if len(event_ids) < 2:
        raise _fail("GENERATOR.EVENT_DIMENSION_INVALID", "At least two events are required.")
    if correlated:
        left, right = select_middle_adjacent_pair(len(event_ids))
    else:
        left = (len(event_ids) - 1) // 2
        right = left + 1
    return [event_ids[left], event_ids[right]]


def select_middle_adjacent_pair(event_count: int = DEFAULT_EVENT_COUNT) -> tuple[int, int]:
    """Return the normative zero-based adjacent pair for seven to ten events."""

    if (
        isinstance(event_count, bool)
        or not isinstance(event_count, int)
        or not 7 <= event_count <= 10
    ):
        raise _fail(
            "GENERATOR.DUPLICATE_DIMENSION_INVALID",
            "The duplicate-event selector requires seven to ten events.",
        )
    left = (event_count - 1) // 2
    return left, left + 1


def _broadcast(value: object, count: int, field_id: str, *, positive: bool = False) -> list[float]:
    values = value if isinstance(value, list) else [value] * count
    if len(values) != count:
        raise _fail(
            "GENERATOR.EVENT_ARRAY_MISALIGNED",
            "A synthetic event parameter does not match the event count.",
        )
    result: list[float] = []
    for item in values:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise _fail(
                "GENERATOR.EVENT_PARAMETER_INVALID",
                "A synthetic event parameter is not numeric.",
            )
        converted = float(np.float64(item))
        if not math.isfinite(converted) or (positive and converted <= 0):
            raise _fail(
                "GENERATOR.EVENT_PARAMETER_INVALID",
                "A synthetic event parameter is outside its finite domain.",
            )
        result.append(converted)
    return result


def _derived_value(
    field_id: str,
    resolved: dict[str, Any],
    family_id: str,
    replicate_index: int,
) -> Any:
    event_count = resolved.get("events")
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or not 2 <= event_count <= 12
    ):
        raise _fail(
            "GENERATOR.EVENT_DIMENSION_INVALID",
            "The resolved synthetic event count is invalid.",
        )
    event_ids = resolved.get("event_ids")
    if field_id == "event_ids":
        return [f"E{index + 1:02d}" for index in range(event_count)]
    if field_id == "pair_mode":
        if family_id != "correlated_duplicate_events":
            return None
        return "correlated" if replicate_index % 2 == 0 else "exact_duplicate_post_noise"
    if not isinstance(event_ids, list) or any(not isinstance(item, str) for item in event_ids):
        raise _fail("GENERATOR.EVENT_IDS_INVALID", "The resolved synthetic event IDs are invalid.")
    if field_id in {"pair_event_ids", "target_pair_event_ids"}:
        return _middle_pair(event_ids, correlated=family_id == "correlated_duplicate_events")
    if field_id == "pair_direction_rule":
        return (
            "target_equals_source"
            if resolved.get("pair_mode") == "exact_duplicate_post_noise"
            else "retain_common_directions"
        )
    if field_id == "equivalence_block_event_ids":
        if family_id == "correlated_duplicate_events":
            if resolved.get("pair_mode") == "exact_duplicate_post_noise":
                return _middle_pair(event_ids, correlated=True)
            return None
        size = resolved.get("equivalence_block_size")
        if not isinstance(size, int) or isinstance(size, bool) or not 2 <= size <= event_count:
            raise _fail(
                "GENERATOR.EQUIVALENCE_BLOCK_INVALID",
                "The equivalence-block selector has an invalid size.",
            )
        first = (event_count - size) // 2
        return event_ids[first : first + size]
    if field_id == "wrong_direction_event_ids":
        count = resolved.get("reversed_direction_events")
        if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= event_count:
            raise _fail(
                "GENERATOR.DIRECTION_SELECTOR_INVALID",
                "The direction-sabotage selector has an invalid count.",
            )
        first = (event_count - count) // 2
        return event_ids[first : first + count]
    if field_id == "event_directions":
        directions = ["higher" if index % 2 == 0 else "lower" for index in range(event_count)]
        if (
            family_id == "correlated_duplicate_events"
            and resolved.get("pair_mode") == "exact_duplicate_post_noise"
        ):
            source_id, target_id = _middle_pair(event_ids, correlated=True)
            directions[event_ids.index(target_id)] = directions[event_ids.index(source_id)]
        return directions
    if field_id == "event_centers":
        interval = resolved.get("event_center_range")
        if (
            not isinstance(interval, list)
            or len(interval) != 2
            or any(
                isinstance(value, bool) or not isinstance(value, (int, float)) for value in interval
            )
        ):
            raise _fail(
                "GENERATOR.CENTER_RANGE_INVALID",
                "The synthetic event-center interval is invalid.",
            )
        low = np.float64(interval[0])
        high = np.float64(interval[1])
        step = np.float64(np.float64(high - low) / np.float64(event_count - 1))
        centers = [
            float(np.float64(low + np.float64(index) * step)) for index in range(event_count)
        ]
        if family_id in {"correlated_duplicate_events", "tightly_spaced_events"}:
            source_id, target_id = _middle_pair(
                event_ids, correlated=family_id == "correlated_duplicate_events"
            )
            source = event_ids.index(source_id)
            target = event_ids.index(target_id)
            if family_id == "correlated_duplicate_events":
                if resolved.get("pair_mode") == "exact_duplicate_post_noise":
                    centers[target] = centers[source]
                else:
                    gap = resolved.get("duplicate_center_gap")
                    if isinstance(gap, bool) or not isinstance(gap, (int, float)) or gap <= 0:
                        raise _fail(
                            "GENERATOR.DUPLICATE_GAP_INVALID",
                            "The correlated-event center gap is invalid.",
                        )
                    centers[target] = float(np.float64(centers[source]) + np.float64(gap))
            else:
                gap_value = resolved.get("adjacent_center_gap")
                if gap_value is None:
                    ratio = resolved.get("adjacent_center_gap_over_width")
                    width = resolved.get("transition_width")
                    if not isinstance(ratio, (int, float)) or not isinstance(width, (int, float)):
                        raise _fail(
                            "GENERATOR.TIGHT_GAP_INVALID",
                            "The tightly-spaced event gap is invalid.",
                        )
                    gap_value = np.float64(ratio) * np.float64(width)
                gap = np.float64(gap_value)
                width_scalar = np.float64(resolved.get("transition_width"))
                if not np.isfinite(gap) or gap <= 0 or gap > width_scalar:
                    raise _fail(
                        "GENERATOR.TIGHT_GAP_INVALID",
                        "The tightly-spaced event gap is outside the declared domain.",
                    )
                midpoint = np.float64(
                    np.float64(centers[source] + centers[target]) / np.float64(2.0)
                )
                centers[source] = float(np.float64(midpoint - np.float64(gap / 2.0)))
                centers[target] = float(np.float64(midpoint + np.float64(gap / 2.0)))
        elif family_id == "near_simultaneous_events":
            block_size = resolved.get("equivalence_block_size")
            if (
                not isinstance(block_size, int)
                or isinstance(block_size, bool)
                or not 2 <= block_size <= event_count
            ):
                raise _fail(
                    "GENERATOR.EQUIVALENCE_BLOCK_INVALID",
                    "The near-simultaneous block parameters are invalid.",
                )
            first = (event_count - block_size) // 2
            block = event_ids[first : first + block_size]
            ratio = resolved.get("center_gap_over_width")
            width = resolved.get("transition_width")
            if (
                not isinstance(block, list)
                or not isinstance(ratio, (int, float))
                or not isinstance(width, (int, float))
            ):
                raise _fail(
                    "GENERATOR.EQUIVALENCE_BLOCK_INVALID",
                    "The near-simultaneous block parameters are invalid.",
                )
            indexes = [event_ids.index(item) for item in block]
            midpoint = np.float64(
                np.add.reduce(np.asarray([centers[index] for index in indexes], dtype=np.float64))
                / np.float64(len(indexes))
            )
            gap = np.float64(np.float64(ratio) * np.float64(width))
            for offset, index in enumerate(indexes):
                relative = np.float64(offset) - np.float64((len(indexes) - 1) / 2.0)
                centers[index] = float(np.float64(midpoint + np.float64(relative * gap)))
        if not all(math.isfinite(value) for value in centers):
            raise _fail("GENERATOR.CENTERS_NONFINITE", "Synthetic event centers are non-finite.")
        return centers
    raise _fail(
        "GENERATOR.DERIVATION_UNIMPLEMENTED",
        "A registered synthetic field derivation is not implemented.",
    )


def _source_projection(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    family_index: int,
    family: dict[str, Any],
    variant_index: int | None,
    variant: dict[str, Any] | None,
    source_owner: AuthenticatedSourceOwner | None,
    heldout_family_override: dict[str, Any] | None,
) -> tuple[str, dict[str, Any] | None]:
    binding: dict[str, Any] | None = None
    if source_owner is not None:
        source = source_owner.resolved_case
        binding = {
            "source_scenario_family_id": source.coordinate.family_id,
            "source_variant_id": source.coordinate.variant_id,
            "source_replicate_index": source.coordinate.replicate_index,
            "source_resolution_mode": source.coordinate.resolution_mode,
            "resolved_parameter_manifest_sha256": source.resolved_parameter_manifest[
                "resolved_parameter_manifest_sha256"
            ],
            "field_values": {
                row.field_id: copy.deepcopy(row.resolved_value) for row in source.field_resolutions
            },
        }
    contract = _mapping(
        authority.data.get("generator_parameter_source_contract"),
        "GENERATOR.PARAMETER_SOURCE_CONTRACT_INVALID",
    )
    projection = {
        "schema_version": contract.get("schema_version"),
        "resolution_mode": coordinate.resolution_mode,
        "generator_field_registry": authority.data["generator_field_registry"],
        "common_defaults": authority.data["common_defaults"],
        "family_index": family_index,
        "family": family,
        "development_variant_index": variant_index,
        "development_variant": variant,
        "family_mechanism_closure": authority.data["family_mechanism_closure"],
        "generator_parameter_source_contract": contract,
        "heldout_family_override": copy.deepcopy(heldout_family_override),
        "source_parameter_manifest_sha256": (
            binding["resolved_parameter_manifest_sha256"] if binding else None
        ),
        "transformed_source_binding": binding,
    }
    return structured_sha256_hex(
        "ebm-audit/generator-parameter-source-contract/1", projection
    ), binding


_NO_FAMILY_FIXED_VALUE = object()
_NO_HELDOUT_OVERRIDE = object()


def _development_family_fixed_value(
    field_id: str,
    definition: dict[str, Any],
    family: dict[str, Any],
) -> object:
    """Resolve only family values that the contract classifies as draw-free."""

    ranges = _mapping(family.get("allowed_ranges", {}), "GENERATOR.FAMILY_RANGE_INVALID")
    if field_id not in ranges:
        return _NO_FAMILY_FIXED_VALUE
    declared = ranges[field_id]
    allowed_form = definition.get("allowed_form")
    if allowed_form == "literal_endpoint_vector":
        return copy.deepcopy(declared)
    if allowed_form == "fixed":
        return copy.deepcopy(declared)
    if isinstance(declared, list) and len(declared) == 2 and declared[0] == declared[1]:
        return copy.deepcopy(declared[0])
    return _NO_FAMILY_FIXED_VALUE


def _heldout_override_value(
    field_id: str,
    family_id: str,
    override: dict[str, Any] | None,
) -> object:
    if override is None:
        return _NO_HELDOUT_OVERRIDE
    try:
        if family_id == "noise_ladder":
            levels = override["ordered_measurement_noise_sd_levels"]
            baseline_index = override["baseline_level_index"]
            if (
                not isinstance(levels, list)
                or not levels
                or not isinstance(baseline_index, int)
                or isinstance(baseline_index, bool)
                or not 0 <= baseline_index < len(levels)
            ):
                raise KeyError
            values = {
                "measurement_noise_sd_levels": levels,
                "measurement_noise_sd": levels[baseline_index],
                "levels": len(levels),
                "matched_latent_draws_across_levels": True,
            }
            if field_id in values:
                return copy.deepcopy(values[field_id])
            return _NO_HELDOUT_OVERRIDE
        if family_id == "group_boundary_sensitivity":
            rule_ids = override["ordered_rule_ids"]
            shifts = override["ordered_boundary_quantile_shifts"]
            if (
                not isinstance(rule_ids, list)
                or not isinstance(shifts, list)
                or len(rule_ids) != len(shifts)
                or not rule_ids
            ):
                raise KeyError
            values = {
                "boundary_rule_ids": rule_ids,
                "boundary_quantile_shifts": shifts,
                "base_quantile_cutoff": override["base_quantile_cutoff"],
                "base_boundary_rule_id": override["baseline_rule_id"],
                "declared_rules": len(rule_ids),
            }
            if field_id in values:
                return copy.deepcopy(values[field_id])
            return _NO_HELDOUT_OVERRIDE
    except (IndexError, KeyError, TypeError) as exc:
        raise _fail(
            "GENERATOR.HELDOUT_OVERRIDE_INVALID",
            "A held-out family override is structurally invalid.",
        ) from exc
    return _NO_HELDOUT_OVERRIDE


def _heldout_parameter_source(
    field_id: str,
    definition: dict[str, Any],
    family: dict[str, Any],
    family_draw_override: dict[str, Any] | None,
) -> dict[str, Any]:
    if family_draw_override is not None:
        ordered_values = family_draw_override.get("ordered_values")
        if not isinstance(ordered_values, list) or not ordered_values:
            raise _fail(
                "GENERATOR.FAMILY_DRAW_OVERRIDE_INVALID",
                "A family-specific parameter draw override is structurally invalid.",
            )
        return {"kind": "ORDERED_CHOICES", "ordered_values": copy.deepcopy(ordered_values)}
    ranges = _mapping(family.get("allowed_ranges", {}), "GENERATOR.FAMILY_RANGE_INVALID")
    declared = ranges[field_id]
    if definition.get("heldout_draw") == "fixed" or not isinstance(declared, list):
        return {"kind": "FIXED", "value": copy.deepcopy(declared)}
    if definition.get("heldout_draw") in {
        "ordered_enum_uniform_unless_stratified",
        "ordered_grid_uniform",
    }:
        if not declared:
            raise _fail(
                "GENERATOR.PARAMETER_CHOICES_INVALID",
                "An ordered parameter choice set is empty.",
            )
        return {"kind": "ORDERED_CHOICES", "ordered_values": copy.deepcopy(declared)}
    if len(declared) != 2:
        return {"kind": "ORDERED_CHOICES", "ordered_values": copy.deepcopy(declared)}
    if declared[0] == declared[1]:
        return {"kind": "FIXED", "value": copy.deepcopy(declared[0])}
    if definition.get("value_type") in _INTEGER_TYPES:
        if any(not isinstance(value, int) or isinstance(value, bool) for value in declared):
            raise _fail(
                "GENERATOR.INTEGER_RANGE_INVALID",
                "An integer parameter range has a non-integer endpoint.",
            )
        return {
            "kind": "INCLUSIVE_INTEGER_RANGE",
            "minimum": declared[0],
            "maximum": declared[1],
        }
    return {
        "kind": "DECIMAL_TICK_RANGE",
        "minimum_tick": _exact_tick(declared[0]),
        "maximum_tick": _exact_tick(declared[1]),
        "tick_scale": 1_000_000,
    }


def _sample_parameter_source(
    rng: np.random.Generator,
    source: dict[str, Any],
) -> tuple[int | None, Any]:
    kind = source["kind"]
    if kind == "FIXED":
        return None, copy.deepcopy(source["value"])
    if kind == "INCLUSIVE_INTEGER_RANGE":
        low = source["minimum"]
        high = source["maximum"]
        if low > high:
            raise _fail("GENERATOR.PARAMETER_RANGE_REVERSED", "A parameter range is reversed.")
        sampled = int(rng.integers(low, high + 1))
        return sampled, sampled
    if kind == "DECIMAL_TICK_RANGE":
        low = source["minimum_tick"]
        high = source["maximum_tick"]
        if low > high:
            raise _fail("GENERATOR.PARAMETER_RANGE_REVERSED", "A parameter range is reversed.")
        sampled = int(rng.integers(low, high + 1))
        return sampled, float(np.float64(sampled) / np.float64(source["tick_scale"]))
    if kind == "ORDERED_CHOICES":
        values = source["ordered_values"]
        if not isinstance(values, list) or not values:
            raise _fail(
                "GENERATOR.PARAMETER_CHOICES_INVALID",
                "An ordered parameter choice set is empty.",
            )
        sampled = int(rng.integers(0, len(values)))
        return sampled, copy.deepcopy(values[sampled])
    raise _fail(
        "GENERATOR.PARAMETER_SOURCE_INVALID",
        "A held-out parameter source kind is unsupported.",
    )


def _resolve_fields(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    family_index: int,
    family: dict[str, Any],
    variant_index: int | None,
    variant: dict[str, Any] | None,
    source_binding: dict[str, Any] | None,
    heldout_family_override: dict[str, Any] | None,
    parameters_seed: str,
) -> tuple[tuple[FieldResolution, ...], dict[str, Any]]:
    registry = authority.field_registry
    definitions = _mapping(registry.get("fields"), "GENERATOR.FIELD_REGISTRY_INVALID")
    common = _mapping(authority.data.get("common_defaults"), "GENERATOR.DEFAULTS_INVALID")
    source_contract = _mapping(
        authority.data.get("generator_parameter_source_contract"),
        "GENERATOR.PARAMETER_SOURCE_CONTRACT_INVALID",
    )
    mode_registry = _mapping(
        source_contract.get("family_mode_registry"), "GENERATOR.FAMILY_MODE_REGISTRY_INVALID"
    )
    derivations = _mapping(
        source_contract.get("derivation_registry"), "GENERATOR.DERIVATION_REGISTRY_INVALID"
    )
    family_id = coordinate.family_id
    family_draw_overrides = _mapping(
        registry.get("family_draw_overrides", {}),
        "GENERATOR.FAMILY_DRAW_OVERRIDE_INVALID",
    )
    family_draw_override = _mapping(
        family_draw_overrides.get(family_id, {}),
        "GENERATOR.FAMILY_DRAW_OVERRIDE_INVALID",
    )
    derived_applicability = {
        "event_ids": True,
        "event_directions": True,
        "event_centers": True,
        "pair_mode": family_id == "correlated_duplicate_events"
        and coordinate.resolution_mode == "HELDOUT_RANGE",
        "pair_event_ids": family_id == "correlated_duplicate_events",
        "target_pair_event_ids": family_id
        in {"correlated_duplicate_events", "tightly_spaced_events"},
        "pair_direction_rule": family_id == "correlated_duplicate_events",
        "equivalence_block_event_ids": family_id
        in {"correlated_duplicate_events", "near_simultaneous_events"},
        "wrong_direction_event_ids": family_id == "wrong_event_direction",
    }
    rows: list[FieldResolution] = []
    resolved: dict[str, Any] = {}
    if re.fullmatch(r"[0-9a-f]{32}", parameters_seed) is None:
        raise _fail("GENERATOR.COMPONENT_SEED_INVALID", "A component seed is invalid.")
    parameter_rng = np.random.Generator(np.random.PCG64DXSM(int(parameters_seed, 16)))
    draw_index = 0
    for field_id in FIELD_IDS:
        definition = _mapping(definitions[field_id], "GENERATOR.FIELD_REGISTRY_INVALID")
        draw_override = (
            _mapping(
                family_draw_override[field_id],
                "GENERATOR.FAMILY_DRAW_OVERRIDE_INVALID",
            )
            if coordinate.resolution_mode == "HELDOUT_RANGE" and field_id in family_draw_override
            else None
        )
        if draw_override is not None:
            definition = {
                **definition,
                **{
                    key: copy.deepcopy(draw_override[key])
                    for key in ("value_type", "allowed_form", "heldout_draw")
                },
            }
        family_fixed_value = _development_family_fixed_value(field_id, definition, family)
        sampled_integer: int | None = None
        draw_consumed = False
        draw_rule = cast(str, definition["heldout_draw"])
        if coordinate.resolution_mode == "TRANSFORMED_SOURCE" and field_id not in (
            _TRANSFORMED_OPERATION_FIELDS
        ):
            if source_binding is None:
                raise _fail(
                    "GENERATOR.SOURCE_OWNER_REQUIRED",
                    "A transformed synthetic case lacks its authenticated source binding.",
                )
            source_kind = "TRANSFORMED_SOURCE_BINDING"
            source_reference = "authenticated-source-parameter-manifest#/field_draws/" + field_id
            value = copy.deepcopy(source_binding["field_values"][field_id])
            resolution_source = {"kind": "FIXED", "value": value}
        elif coordinate.resolution_mode == "TRANSFORMED_SOURCE" and field_id in {
            "source_events",
            "source_participants",
        }:
            if source_binding is None:
                raise _fail(
                    "GENERATOR.SOURCE_OWNER_REQUIRED",
                    "A transformed synthetic case lacks its authenticated source binding.",
                )
            source_field = "events" if field_id == "source_events" else "participants"
            source_kind = "TRANSFORMED_SOURCE_BINDING"
            source_reference = (
                "authenticated-source-parameter-manifest#/field_draws/" + source_field
            )
            value = copy.deepcopy(source_binding["field_values"][source_field])
            resolution_source = {"kind": "FIXED", "value": value}
        elif (
            coordinate.resolution_mode == "TRANSFORMED_SOURCE"
            and field_id == "permutations_per_source"
        ):
            if (
                FIELD_IDS[61] != "permutations_per_source"
                or variant is None
                or variant_index is None
                or variant.get("permutations_per_source") != 59
            ):
                raise _fail(
                    "GENERATOR.PERMUTATIONS_PER_SOURCE_INVALID",
                    (
                        "The authenticated development null variant does not fix "
                        "the required permutation count."
                    ),
                )
            source_kind = "DEVELOPMENT_VARIANT"
            source_reference = scenario_authority_source_reference(
                authority,
                (
                    f"/scenario_families/{family_index}/development_variants/"
                    f"{variant_index}/permutations_per_source"
                ),
            )
            value = 59
            resolution_source = {"kind": "FIXED", "value": 59}
        elif derived_applicability.get(field_id, False):
            derivation = _mapping(derivations[field_id], "GENERATOR.DERIVATION_REGISTRY_INVALID")
            source_kind = "EVALUATOR_DERIVATION"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/generator_parameter_source_contract/derivation_registry/{field_id}",
            )
            resolution_source = {
                "kind": "DERIVED",
                "derivation_id": derivation["derivation_id"],
                "ordered_input_field_ids": copy.deepcopy(derivation["ordered_input_field_ids"]),
            }
            value = None
        elif field_id in mode_registry:
            family_modes = _mapping(
                mode_registry[field_id], "GENERATOR.FAMILY_MODE_REGISTRY_INVALID"
            )
            source_kind = "FAMILY_MECHANISM"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/generator_parameter_source_contract/family_mode_registry/{field_id}",
            )
            value = copy.deepcopy(family_modes.get(family_id, family_modes.get("default")))
            resolution_source = {"kind": "FIXED", "value": value}
        elif variant is not None and field_id in variant:
            source_kind = "DEVELOPMENT_VARIANT"
            if variant_index is None:
                raise _fail(
                    "GENERATOR.VARIANT_REGISTRY_INVALID",
                    "A development variant has no registry index.",
                )
            source_reference = scenario_authority_source_reference(
                authority,
                (
                    f"/scenario_families/{family_index}/development_variants/"
                    f"{variant_index}/{field_id}"
                ),
            )
            value = copy.deepcopy(variant[field_id])
            resolution_source = {"kind": "FIXED", "value": value}
        elif (
            coordinate.resolution_mode == "HELDOUT_RANGE"
            and (
                heldout_override_value := _heldout_override_value(
                    field_id,
                    family_id,
                    heldout_family_override,
                )
            )
            is not _NO_HELDOUT_OVERRIDE
        ):
            source_kind = "HELDOUT_STRATUM"
            source_reference = (
                f"authenticated-private-attempt#/family-overrides/{family_id}/{field_id}"
            )
            value = copy.deepcopy(heldout_override_value)
            resolution_source = {"kind": "FIXED", "value": value}
        elif (
            coordinate.resolution_mode == "HELDOUT_RANGE"
            and family_id == "heavy_tailed_skewed"
            and field_id == "measurement_noise_family"
        ):
            ordered_families = _heavy_tail_mechanism(authority)
            source_kind = "HELDOUT_ROOT_DRAW"
            source_reference = scenario_authority_source_reference(
                authority,
                "/family_mechanism_closure/heavy_tailed_skewed/measurement_noise_family_choices",
            )
            resolution_source = {
                "kind": "ORDERED_CHOICES",
                "ordered_values": copy.deepcopy(ordered_families),
            }
            draw_consumed = True
            sampled_integer, value = _sample_parameter_source(parameter_rng, resolution_source)
        elif (
            coordinate.resolution_mode == "HELDOUT_RANGE"
            and family_id == "heavy_tailed_skewed"
            and field_id in _HEAVY_TAIL_CONDITIONAL_PARAMETERS
            and field_id
            not in _HEAVY_TAIL_FAMILY_PARAMETERS.get(
                cast(str, resolved.get("measurement_noise_family")), ()
            )
        ):
            source_kind = "NOT_APPLICABLE"
            source_reference = scenario_authority_source_reference(
                authority,
                "/generator_parameter_source_contract/not_applicable_rule",
            )
            value = None
            resolution_source = {
                "kind": "NOT_APPLICABLE",
                "reason_id": f"{field_id}-not-applicable-for-measurement-noise-family",
            }
        elif coordinate.resolution_mode == "HELDOUT_RANGE" and field_id in _mapping(
            family.get("allowed_ranges", {}), "GENERATOR.FAMILY_RANGE_INVALID"
        ):
            resolution_source = _heldout_parameter_source(
                field_id,
                definition,
                family,
                draw_override,
            )
            draw_consumed = resolution_source["kind"] in {
                "INCLUSIVE_INTEGER_RANGE",
                "DECIMAL_TICK_RANGE",
                "ORDERED_CHOICES",
            }
            source_kind = "HELDOUT_ROOT_DRAW" if draw_consumed else "FAMILY_MECHANISM"
            source_reference = scenario_authority_source_reference(
                authority,
                (
                    f"/generator_field_registry/family_draw_overrides/{family_id}/{field_id}"
                    if draw_override is not None
                    else f"/scenario_families/{family_index}/allowed_ranges/{field_id}"
                ),
            )
            sampled_integer, value = _sample_parameter_source(parameter_rng, resolution_source)
        elif field_id == "truth_type":
            source_kind = "FAMILY_MECHANISM"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/scenario_families/{family_index}/truth_type",
            )
            value = copy.deepcopy(family["truth_type"])
            resolution_source = {"kind": "FIXED", "value": value}
        elif field_id in {"base_boundary_rule_id", "base_quantile_cutoff"} and field_id in family:
            source_kind = "FAMILY_MECHANISM"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/scenario_families/{family_index}/{field_id}",
            )
            value = copy.deepcopy(family[field_id])
            resolution_source = {"kind": "FIXED", "value": value}
        elif family_fixed_value is not _NO_FAMILY_FIXED_VALUE:
            source_kind = "FAMILY_MECHANISM"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/scenario_families/{family_index}/allowed_ranges/{field_id}",
            )
            value = copy.deepcopy(family_fixed_value)
            resolution_source = {"kind": "FIXED", "value": value}
        elif field_id in common and not (
            field_id == "covariate_event_effect"
            and "event_covariate_effect"
            in _mapping(family.get("allowed_ranges", {}), "GENERATOR.FAMILY_RANGE_INVALID")
        ):
            source_kind = "COMMON_DEFAULT"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/common_defaults/{field_id}",
            )
            value = copy.deepcopy(common[field_id])
            resolution_source = {"kind": "FIXED", "value": value}
        else:
            source_kind = "NOT_APPLICABLE"
            source_reference = scenario_authority_source_reference(
                authority,
                "/generator_parameter_source_contract/not_applicable_rule",
            )
            value = None
            resolution_source = {
                "kind": "NOT_APPLICABLE",
                "reason_id": f"{field_id}-not-applicable",
            }
        rows.append(
            FieldResolution(
                field_id=field_id,
                value_type=cast(str, definition["value_type"]),
                allowed_form=cast(str, definition["allowed_form"]),
                source_kind=source_kind,
                source_reference=source_reference,
                draw_rule=draw_rule,
                draw_consumed=draw_consumed,
                draw_index=draw_index if draw_consumed else None,
                sampled_integer=sampled_integer,
                resolution_source=resolution_source,
                resolved_destination_json_pointer=None,
                resolved_value=value,
            )
        )
        resolved[field_id] = copy.deepcopy(value)
        if draw_consumed:
            draw_index += 1

    replaced: list[FieldResolution] = []
    for row in rows:
        value = row.resolved_value
        if row.resolution_source["kind"] == "DERIVED":
            value = _derived_value(
                row.field_id,
                resolved,
                family_id,
                coordinate.replicate_index,
            )
            resolved[row.field_id] = copy.deepcopy(value)
        destination = _DIRECT_DESTINATIONS.get(row.field_id) if value is not None else None
        replaced.append(
            FieldResolution(
                field_id=row.field_id,
                value_type=row.value_type,
                allowed_form=row.allowed_form,
                source_kind=row.source_kind,
                source_reference=row.source_reference,
                draw_rule=row.draw_rule,
                draw_consumed=row.draw_consumed,
                draw_index=row.draw_index,
                sampled_integer=row.sampled_integer,
                resolution_source=row.resolution_source,
                resolved_destination_json_pointer=destination,
                resolved_value=value,
            )
        )
    return tuple(replaced), resolved


def _resolve_pointer(value: object, pointer: str) -> Any:
    current = value
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise _fail(
                "GENERATOR.DEPENDENCY_POINTER_INVALID",
                "A dependency pointer does not resolve against the configuration.",
            )
    return current


def _dependency_records(
    authority: ScenarioAuthority, configuration: dict[str, Any]
) -> list[dict[str, Any]]:
    registry = _mapping(
        authority.data.get("dependency_stage_registry"),
        "GENERATOR.DEPENDENCY_REGISTRY_INVALID",
    )
    contracts = _list_of_mappings(
        registry.get("ordered_stages"), "GENERATOR.DEPENDENCY_REGISTRY_INVALID"
    )
    if len(contracts) != 7:
        raise _fail(
            "GENERATOR.DEPENDENCY_REGISTRY_DRIFT",
            "The closed dependency registry does not contain seven stages.",
        )
    result: list[dict[str, Any]] = []
    for index, contract in enumerate(contracts):
        pointers = contract.get("output_json_pointers")
        if not isinstance(pointers, list) or any(not isinstance(item, str) for item in pointers):
            raise _fail(
                "GENERATOR.DEPENDENCY_REGISTRY_INVALID",
                "A dependency output registry row is invalid.",
            )
        output_digest = structured_sha256(
            "ebm-audit/generator-dependency-output/1",
            {
                "stage": contract["stage"],
                "ordered_outputs": [
                    {
                        "json_pointer": pointer,
                        "value": copy.deepcopy(_resolve_pointer(configuration, pointer)),
                    }
                    for pointer in pointers
                ],
            },
        )
        result.append(
            {
                "stage": contract["stage"],
                "stage_index": index,
                "input_field_ids": copy.deepcopy(contract["input_field_ids"]),
                "output_json_pointers": copy.deepcopy(pointers),
                "status": contract["status"],
                "rng_draw_count": 0,
                "output_digest": output_digest,
            }
        )
    return result


def _configuration(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    values: dict[str, Any],
) -> dict[str, Any]:
    participant_count = values["participants"]
    event_count = values["events"]
    if (
        not isinstance(participant_count, int)
        or isinstance(participant_count, bool)
        or participant_count < 2
    ):
        raise _fail(
            "GENERATOR.PARTICIPANT_DIMENSION_INVALID",
            "The resolved synthetic participant count is invalid.",
        )
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or not 2 <= event_count <= 12
    ):
        raise _fail(
            "GENERATOR.EVENT_DIMENSION_INVALID",
            "The resolved synthetic event count is invalid.",
        )
    event_ids = values["event_ids"]
    directions = values["event_directions"]
    centers = _broadcast(values["event_centers"], event_count, "event_centers")
    baselines = _broadcast(values["baseline"], event_count, "baseline")
    amplitudes = _broadcast(values["amplitude"], event_count, "amplitude")
    if any(value < 0 for value in amplitudes):
        raise _fail("GENERATOR.AMPLITUDE_INVALID", "Synthetic amplitudes must be nonnegative.")
    widths = _broadcast(values["transition_width"], event_count, "transition_width", positive=True)
    covariate_source = (
        values["event_covariate_effect"]
        if values["event_covariate_effect"] is not None
        else values["covariate_event_effect"]
    )
    covariate_effects = _broadcast(covariate_source or 0.0, event_count, "covariate_effect")
    if coordinate.family_id == "covariate_confounding":
        magnitude = float(covariate_effects[0])
        covariate_effects = [
            magnitude if index % 2 == 0 else -magnitude for index in range(event_count)
        ]
    group_effects = _broadcast(values["group_event_effect"] or 0.0, event_count, "group_effect")
    loadings = _broadcast(
        values["participant_random_effect_loading"], event_count, "participant_effect_loading"
    )
    noise_sd = _broadcast(
        values["measurement_noise_sd"], event_count, "measurement_noise_sd", positive=True
    )
    correlation = values["equicorrelation"]
    if isinstance(correlation, bool) or not isinstance(correlation, (int, float)):
        raise _fail("GENERATOR.CORRELATION_INVALID", "Synthetic equicorrelation is invalid.")
    rho = float(np.float64(correlation))
    matrix = np.full((event_count, event_count), rho, dtype=np.float64)
    np.fill_diagonal(matrix, 1.0)
    pair_ids = values["pair_event_ids"] or values["target_pair_event_ids"] or []
    pair_mode = values["pair_mode"]
    if coordinate.family_id == "correlated_duplicate_events" and pair_mode == "correlated":
        expected = _middle_pair(cast(list[str], event_ids), correlated=True)
        if pair_ids != expected:
            raise _fail(
                "GENERATOR.DUPLICATE_SELECTOR_INVALID",
                "The resolved duplicate-event pair differs from the dimension-derived pair.",
            )
        pair_rho = values["duplicate_pair_correlation"]
        if isinstance(pair_rho, bool) or not isinstance(pair_rho, (int, float)):
            raise _fail(
                "GENERATOR.DUPLICATE_CORRELATION_INVALID",
                "The correlated-event pair correlation is invalid.",
            )
        left, right = (cast(list[str], event_ids).index(item) for item in expected)
        matrix[left, right] = matrix[right, left] = np.float64(pair_rho)
    if not np.array_equal(matrix, matrix.T):
        raise _fail("GENERATOR.COVARIANCE_INVALID", "The noise correlation matrix is asymmetric.")
    covariance = np.diag(noise_sd) @ matrix @ np.diag(noise_sd)
    try:
        np.linalg.cholesky(covariance)
    except np.linalg.LinAlgError as exc:
        raise _fail(
            "GENERATOR.COVARIANCE_NOT_POSITIVE_DEFINITE",
            "The synthetic noise covariance is not positive definite.",
        ) from exc

    reference_fraction = values["reference_fraction"]
    if isinstance(reference_fraction, bool) or not isinstance(reference_fraction, (int, float)):
        raise _fail(
            "GENERATOR.REFERENCE_FRACTION_INVALID",
            "The synthetic reference fraction is invalid.",
        )
    reference_fraction_float = float(np.float64(reference_fraction))
    reference_count = min(
        participant_count - 1,
        max(1, round(participant_count * reference_fraction_float)),
    )
    at_risk_count = participant_count - reference_count

    independent_window = values["latent_sampling_window"]
    if independent_window is not None:
        latent_sampling = {
            "mode": "GROUP_INDEPENDENT_WINDOW",
            "reference_window": None,
            "at_risk_window": None,
            "group_independent_window": copy.deepcopy(independent_window),
        }
    else:
        latent_sampling = {
            "mode": "GROUP_WINDOWS",
            "reference_window": copy.deepcopy(values["reference_sampling_window"]),
            "at_risk_window": copy.deepcopy(values["at_risk_sampling_window"]),
            "group_independent_window": None,
        }

    missing_family = values["missingness"]
    if missing_family == "MCAR":
        if values["event_missing_probabilities"] is not None:
            event_probabilities = _broadcast(
                values["event_missing_probabilities"], event_count, "event_missing_probabilities"
            )
        else:
            event_probabilities = _broadcast(
                values["event_missing_probability"], event_count, "event_missing_probability"
            )
    else:
        event_probabilities = [0.0] * event_count
    if any(not 0 <= value <= 1 for value in event_probabilities):
        raise _fail(
            "GENERATOR.MISSINGNESS_PROBABILITY_INVALID",
            "A synthetic missingness probability is outside zero to one.",
        )

    boundary_ids = copy.deepcopy(values["boundary_rule_ids"] or [])
    boundary_shifts = [float(item) for item in (values["boundary_quantile_shifts"] or [])]
    base_cutoff = values["base_quantile_cutoff"] if boundary_ids else None
    if len(boundary_ids) != len(boundary_shifts):
        raise _fail(
            "GENERATOR.BOUNDARY_RULES_INVALID",
            "Synthetic boundary rule IDs and shifts are misaligned.",
        )
    if base_cutoff is not None and (
        isinstance(base_cutoff, bool)
        or not isinstance(base_cutoff, (int, float))
        or not 0 < base_cutoff < 1
    ):
        raise _fail(
            "GENERATOR.BOUNDARY_RULES_INVALID",
            "The synthetic base boundary cutoff is invalid.",
        )

    analysis_directions = list(directions)
    wrong_ids = values["wrong_direction_event_ids"] or []
    for event_id in wrong_ids:
        index = cast(list[str], event_ids).index(event_id)
        analysis_directions[index] = "lower" if analysis_directions[index] == "higher" else "higher"

    preimage: dict[str, Any] = {
        "schema_version": "ebm-audit-resolved-generator-configuration/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "synthetic_marker": "SYNTHETIC",
        "scenario_family_id": coordinate.family_id,
        "variant_id": coordinate.variant_id,
        "replicate_index": coordinate.replicate_index,
        "dimensions": {
            "participant_count": participant_count,
            "event_count": event_count,
        },
        "event_ids": copy.deepcopy(event_ids),
        "event_directions": copy.deepcopy(directions),
        "event_parameters": {
            "baseline": baselines,
            "amplitude": amplitudes,
            "transition_width": widths,
            "event_centers": centers,
            "covariate_effect": covariate_effects,
            "group_effect": group_effects,
            "participant_effect_loading": loadings,
        },
        "measurement_noise": {
            "family": values["measurement_noise_family"],
            "standard_deviations": noise_sd,
            "equicorrelation": rho,
            "correlation_matrix": matrix.tolist(),
            "student_t_df": values["student_t_df"],
            "centered_lognormal_sigma": values["centered_lognormal_sigma"],
            "centered_lognormal_weight": values["centered_lognormal_weight"],
        },
        "latent_sampling": latent_sampling,
        "group_generation": {
            "reference_fraction": reference_fraction_float,
            "reference_count": reference_count,
            "at_risk_count": at_risk_count,
            "boundary_rule_id": boundary_ids[0] if boundary_ids else None,
            "quantile_cutoff": float(base_cutoff) if base_cutoff is not None else None,
        },
        "covariates": {
            "mode": values["covariates"],
            "standardized_group_difference": (
                values["standardized_group_covariate_difference"]
                if values["covariates"] == "one_group_shifted_normal"
                else None
            ),
        },
        "participant_effect": {
            "standard_deviation": float(values["participant_random_effect_sd"]),
        },
        "missingness": {
            "family": missing_family,
            "event_probabilities": event_probabilities,
            "marginal_probability": (
                values["marginal_missing_probability"] if missing_family == "MAR" else None
            ),
            "covariate_log_odds_coefficient": (
                values["covariate_log_odds_coefficient"] if missing_family == "MAR" else None
            ),
            "group_log_odds_coefficient": (
                values["group_log_odds_coefficient"] if missing_family == "MAR" else None
            ),
        },
        "outliers": {
            "mode": values["outliers"],
            "injected_participant_count": int(values["injected_participants"] or 0),
            "affected_event_count": int(values["affected_events"] or 0),
            "offset_noise_sd": (
                float(values["offset_noise_sd"]) if values["outliers"] != "none" else None
            ),
        },
        "scenario_parameters": {
            "truth_type": values["truth_type"],
            "pair_mode": pair_mode,
            "pair_event_ids": copy.deepcopy(pair_ids),
            "equivalence_block_event_ids": copy.deepcopy(
                values["equivalence_block_event_ids"] or []
            ),
            "alternate_inversions": values["alternate_inversions"],
            "minority_fraction": values["minority_fraction"],
            "opposing_relation_fraction": values["opposing_relation_fraction"],
            "contamination_fraction": values["contamination_fraction"],
            "wrong_direction_event_ids": copy.deepcopy(wrong_ids),
            "measurement_noise_sd_levels": [
                float(item) for item in (values["measurement_noise_sd_levels"] or [])
            ],
            "boundary_rule_ids": boundary_ids,
            "boundary_quantile_shifts": boundary_shifts,
            "base_quantile_cutoff": float(base_cutoff) if base_cutoff is not None else None,
        },
        "analysis_configuration": {
            "reference_only_residualisation": False,
            "event_spec_directions": analysis_directions,
            "mcmc_profile_id": "characterization_2000",
        },
        "dependency_records": [],
        "resolved_generator_configuration_sha256": None,
    }
    preimage["dependency_records"] = _dependency_records(authority, preimage)
    configuration = _persisted_record(
        preimage,
        "resolved_generator_configuration_sha256",
        "ebm-audit/resolved-generator-configuration/1",
    )
    _validate_schema(configuration, definition="ResolvedGeneratorConfiguration")
    return configuration


def _lehmer_order(event_ids: list[str], inversions: int) -> list[str]:
    maximum = len(event_ids) * (len(event_ids) - 1) // 2
    if not 0 <= inversions <= maximum:
        raise _fail(
            "GENERATOR.ALTERNATE_ORDER_INVALID",
            "The requested alternate-order inversion count is invalid.",
        )
    remaining = list(event_ids)
    output: list[str] = []
    left = inversions
    while remaining:
        index = min(left, len(remaining) - 1)
        output.append(remaining.pop(index))
        left -= index
    return output


def _affected_tails(
    authority: ScenarioAuthority, configuration: dict[str, Any]
) -> tuple[list[str], list[str]]:
    if configuration["scenario_family_id"] != "incomplete_time_coverage":
        return [], []
    defaults = _mapping(authority.data["common_defaults"], "GENERATOR.DEFAULTS_INVALID")
    broad_low = min(
        defaults["reference_sampling_window"][0], defaults["at_risk_sampling_window"][0]
    )
    broad_high = max(
        defaults["reference_sampling_window"][1], defaults["at_risk_sampling_window"][1]
    )
    latent = configuration["latent_sampling"]
    restricted_low = min(latent["reference_window"][0], latent["at_risk_window"][0])
    restricted_high = max(latent["reference_window"][1], latent["at_risk_window"][1])
    event_parameters = configuration["event_parameters"]
    affected: list[str] = []
    sides: list[str] = []
    for event_id, center, width in zip(
        configuration["event_ids"],
        event_parameters["event_centers"],
        event_parameters["transition_width"],
        strict=True,
    ):
        broad_normal = broad_low <= center - 2.0 * width
        broad_abnormal = broad_high >= center + 2.0 * width
        restricted_normal = restricted_low <= center - 2.0 * width
        restricted_abnormal = restricted_high >= center + 2.0 * width
        missing_normal = broad_normal and not restricted_normal
        missing_abnormal = broad_abnormal and not restricted_abnormal
        if missing_normal or missing_abnormal:
            affected.append(event_id)
            sides.append(
                "BOTH"
                if missing_normal and missing_abnormal
                else "NORMAL"
                if missing_normal
                else "ABNORMAL"
            )
    return affected, sides


def _mechanism(
    authority: ScenarioAuthority,
    configuration: dict[str, Any],
    pre_root_stratum_id: str | None,
) -> dict[str, Any]:
    family_id = configuration["scenario_family_id"]
    event_ids = cast(list[str], configuration["event_ids"])
    parameters = configuration["scenario_parameters"]
    pair_mode = parameters["pair_mode"]
    if family_id == "minority_alternate_sequence":
        mechanism_kind = "MINORITY_ALTERNATE_SEQUENCE"
        alternate = _lehmer_order(event_ids, int(parameters["alternate_inversions"]))
        subgroup_orders = [event_ids, alternate]
        identifiable = False
    elif family_id == "opposing_sequences_50_50":
        mechanism_kind = "OPPOSING_SEQUENCES_50_50"
        inversions = round(
            float(parameters["opposing_relation_fraction"])
            * (len(event_ids) * (len(event_ids) - 1) // 2)
        )
        subgroup_orders = [event_ids, _lehmer_order(event_ids, inversions)]
        identifiable = False
    elif family_id == "near_simultaneous_events":
        mechanism_kind = "EQUIVALENCE_BLOCKS"
        subgroup_orders = []
        identifiable = False
    elif family_id == "correlated_duplicate_events" and pair_mode == "exact_duplicate_post_noise":
        mechanism_kind = "EXACT_DUPLICATE_POST_NOISE"
        subgroup_orders = []
        identifiable = False
    elif family_id == "control_contamination":
        mechanism_kind = "LABEL_CONTAMINATION"
        subgroup_orders = []
        identifiable = True
    elif family_id in _OPERATION_PATHS:
        mechanism_kind = "REFITTED_NULL_TRANSFORMATION"
        subgroup_orders = []
        identifiable = False
    elif family_id == "pure_no_signal":
        mechanism_kind = "PURE_NO_SIGNAL"
        subgroup_orders = []
        identifiable = False
    else:
        mechanism_kind = "STRICT_TOTAL_ORDER"
        subgroup_orders = []
        identifiable = True
    affected, _ = _affected_tails(authority, configuration)
    dependency_records = configuration["dependency_records"]
    preimage = {
        "schema_version": "ebm-audit-resolved-generator-mechanism/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "scenario_family_id": family_id,
        "mechanism_kind": mechanism_kind,
        "strict_order_identifiable": identifiable,
        "base_order": event_ids if mechanism_kind != "PURE_NO_SIGNAL" else [],
        "subgroup_orders": subgroup_orders,
        "equivalence_blocks": (
            [parameters["equivalence_block_event_ids"]]
            if parameters["equivalence_block_event_ids"]
            else []
        ),
        "target_event_ids": parameters["pair_event_ids"],
        "affected_tail_event_ids": affected,
        "wrong_direction_event_ids": parameters["wrong_direction_event_ids"],
        "pre_root_stratum_id": pre_root_stratum_id,
        "group_indicator_encoding": {"reference": 0, "at_risk": 1},
        "group_effect_application": (
            "gamma_i_times_binary_group_indicator_before_participant_and_noise"
        ),
        "group_effect_dependency_stage": "event_arrays",
        "group_effect_rng_draw_count": 0,
        "dependency_records_sha256": structured_sha256_hex(
            "ebm-audit/scenario-generator-dependencies/1", dependency_records
        ),
        "resolved_generator_mechanism_sha256": None,
    }
    mechanism = _persisted_record(
        preimage,
        "resolved_generator_mechanism_sha256",
        "ebm-audit/resolved-generator-mechanism/1",
    )
    _validate_schema(mechanism, definition="ResolvedGeneratorMechanism")
    return mechanism


def _validate_source_owner(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    family: dict[str, Any],
    variant: dict[str, Any] | None,
    source_owner: AuthenticatedSourceOwner | None,
) -> None:
    if coordinate.resolution_mode in {"DEVELOPMENT_VARIANT", "HELDOUT_RANGE"}:
        if source_owner is not None:
            raise _fail(
                "GENERATOR.SOURCE_OWNER_UNDECLARED",
                "An ordinary synthetic case carries an undeclared source owner.",
            )
        return
    if source_owner is None or coordinate.family_id not in _OPERATION_PATHS:
        raise _fail(
            "GENERATOR.SOURCE_OWNER_REQUIRED",
            "A transformed synthetic case requires an authenticated source owner.",
        )
    source = source_owner.resolved_case
    # A source manifest is not authority merely because it is internally
    # self-consistent.  Reconstruct the complete ordinary source from the same
    # exact evaluator bytes before copying even one field from it.
    strict_authority = load_scenario_authority(authority.exact_bytes)
    if strict_authority != authority:
        raise _fail(
            "GENERATOR.AUTHORITY_OBJECT_MISMATCH",
            "The scenario authority object differs from its exact source bytes.",
        )
    verify_exact_resolution(strict_authority, source)
    expected_reference = f"{source.coordinate.family_id}/{source.coordinate.variant_id}"
    if (
        family.get("source_family") != source.coordinate.family_id
        or variant is None
        or variant.get("source_variant") != expected_reference
        or source.coordinate.replicate_index != coordinate.replicate_index
        or source.coordinate.resolution_mode != "DEVELOPMENT_VARIANT"
        or tuple(row.field_id for row in source.field_resolutions) != FIELD_IDS
        or [row.as_dict() for row in source.field_resolutions]
        != source.resolved_parameter_manifest.get("field_draws")
        or source.resolution_bundle.get("resolved_parameter_manifest")
        != source.resolved_parameter_manifest
        or source.resolution_bundle.get("resolved_configuration") != source.resolved_configuration
    ):
        raise _fail(
            "GENERATOR.SOURCE_OWNER_MISMATCH",
            "The authenticated source owner differs from the null-operation plan.",
        )
    _validate_schema(source.resolved_parameter_manifest, definition="ResolvedParameterManifest")


def _dependency_failure_stage(code: str) -> tuple[int, str]:
    if code.startswith("GENERATOR.PARTICIPANT"):
        index = 0
    elif code.startswith(("GENERATOR.EVENT_DIMENSION", "GENERATOR.EVENT_IDS")):
        index = 1
    elif code.startswith(("GENERATOR.REFERENCE", "GENERATOR.GROUP", "GENERATOR.BOUNDARY")):
        index = 2
    elif code.startswith(
        (
            "GENERATOR.LATENT",
            "GENERATOR.MISSINGNESS",
            "GENERATOR.OUTLIER",
            "GENERATOR.ALTERNATE",
            "GENERATOR.EQUIVALENCE",
            "GENERATOR.PURE_NO_SIGNAL",
        )
    ):
        index = 3
    elif code.startswith(
        (
            "GENERATOR.EVENT_PARAMETER",
            "GENERATOR.AMPLITUDE",
            "GENERATOR.CENTER",
            "GENERATOR.TIGHT_GAP",
            "GENERATOR.DUPLICATE_GAP",
        )
    ):
        index = 4
    elif code.startswith(
        (
            "GENERATOR.CORRELATION",
            "GENERATOR.COVARIANCE",
            "GENERATOR.DUPLICATE_CORRELATION",
        )
    ):
        index = 5
    else:
        index = 6
    return index, DEPENDENCY_STAGE_IDS[index]


def _resolve_case(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    *,
    source_owner: AuthenticatedSourceOwner | None = None,
    private_case_seed: str | None = None,
    claimed_variant_index: int | None = None,
    heldout_family_override: dict[str, Any] | None = None,
    pre_root_stratum_id: str | None = None,
    heldout_attempt_id: str | None = None,
) -> ResolvedSyntheticCase | RetainedGeneratorInvalid:
    """Reconstruct one ordinary, held-out-range, or source-bound-null plan.

    Matched comparator members are deliberately unavailable here because their
    closed transaction owner and post-operation configuration are not yet an
    input to this API.  Treating an ordinary case as a matched member would
    silently lose the shared-draw root contract.
    """

    if coordinate.resolution_mode not in {
        "DEVELOPMENT_VARIANT",
        "HELDOUT_RANGE",
        "TRANSFORMED_SOURCE",
    }:
        if "MATCHED_COMPARATOR" in str(coordinate.resolution_mode):
            raise _fail(
                "GENERATOR.MATCHED_COMPARATOR_UNAVAILABLE",
                "Matched comparator generation requires its authenticated transaction owner.",
            )
        raise _fail(
            "GENERATOR.RESOLUTION_MODE_UNSUPPORTED",
            "The requested synthetic resolution mode is unsupported.",
        )
    strict_authority = load_scenario_authority(authority.exact_bytes)
    if authority != strict_authority:
        raise _fail(
            "GENERATOR.AUTHORITY_OBJECT_MISMATCH",
            "The scenario authority object differs from its exact source bytes.",
        )
    authority = strict_authority

    family_index, family, variant_index, variant = _family_and_variant(authority, coordinate)
    _validate_source_owner(authority, coordinate, family, variant, source_owner)
    private_resolution = private_case_seed is not None
    if private_resolution:
        if heldout_attempt_id is None or claimed_variant_index is None:
            raise _fail(
                "GENERATOR.HELDOUT_CAPABILITY_INVALID",
                "The held-out resolver capability is incomplete.",
            )
        if variant_index is not None and variant_index != claimed_variant_index:
            raise _fail(
                "GENERATOR.HELDOUT_VARIANT_MISMATCH",
                "The held-out resolver capability selects a different numeric variant.",
            )
        case_seed = cast(str, private_case_seed)
    else:
        if coordinate.resolution_mode == "HELDOUT_RANGE":
            raise _fail(
                "GENERATOR.HELDOUT_CAPABILITY_REQUIRED",
                "A held-out range case requires an evaluator-issued resolver capability.",
            )
        case_seed = _case_seed(authority, coordinate)
    source_case_id = source_owner.resolved_case.case_id if source_owner is not None else None
    components, component_manifest, operation_seed = _component_manifest(
        authority, coordinate, case_seed, source_case_id
    )
    source_contract_sha256, source_binding = _source_projection(
        authority,
        coordinate,
        family_index,
        family,
        variant_index,
        variant,
        source_owner,
        heldout_family_override,
    )
    parameters_seed = next(row.seed_128 for row in components if row.component_path == "parameters")
    field_rows, values = _resolve_fields(
        authority,
        coordinate,
        family_index,
        family,
        variant_index,
        variant,
        source_binding,
        heldout_family_override,
        parameters_seed,
    )
    if tuple(row.field_id for row in field_rows) != FIELD_IDS:
        raise _fail(
            "GENERATOR.FIELD_LEDGER_INVALID",
            "The reconstructed field ledger is incomplete or reordered.",
        )
    parameter_preimage = {
        "schema_version": "ebm-audit-resolved-parameter-manifest/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "scenario_family_id": coordinate.family_id,
        "variant_id": coordinate.variant_id,
        "replicate_index": coordinate.replicate_index,
        "resolution_mode": coordinate.resolution_mode,
        "source_contract_sha256": source_contract_sha256,
        "source_parameter_manifest_sha256": (
            source_binding["resolved_parameter_manifest_sha256"] if source_binding else None
        ),
        "ordered_field_ids": list(FIELD_IDS),
        "field_draws": [row.as_dict() for row in field_rows],
        "parameter_draw_count": sum(row.draw_consumed for row in field_rows),
        "parameters_component_seed": parameters_seed,
        "resolved_parameter_manifest_sha256": None,
    }
    parameter_manifest = _persisted_record(
        parameter_preimage,
        "resolved_parameter_manifest_sha256",
        "ebm-audit/resolved-parameter-manifest/1",
    )
    _validate_schema(parameter_manifest, definition="ResolvedParameterManifest")
    resolved_variant_index = (
        claimed_variant_index
        if claimed_variant_index is not None
        else variant_index
        if variant_index is not None
        else 0
    )
    case_id = f"{coordinate.family_id}-v{resolved_variant_index}-r{coordinate.replicate_index}"
    try:
        configuration = _configuration(authority, coordinate, values)
        verify_pure_no_signal_semantics(configuration)
        mechanism = _mechanism(authority, configuration, pre_root_stratum_id)
    except InvalidInputError as exc:
        if not private_resolution or heldout_attempt_id is None:
            raise
        failed_stage_index, failed_stage_id = _dependency_failure_stage(exc.code)
        frozen_rows = tuple(
            _freeze_field_resolution(row, ordinal=ordinal) for ordinal, row in enumerate(field_rows)
        )
        terminal = _retain_generator_invalid(
            heldout_attempt_id=heldout_attempt_id,
            coordinate=coordinate,
            variant_index=resolved_variant_index,
            case_id=case_id,
            source_contract_sha256=source_contract_sha256,
            scenario_definitions_sha256=authority.definitions_sha256,
            field_resolutions=frozen_rows,
            parameter_draw_count=sum(row.draw_consumed for row in field_rows),
            failed_dependency_stage_index=failed_stage_index,
            failed_dependency_stage_id=failed_stage_id,
            stable_reason=exc.code,
        )
        return _require_authenticated_retained_generator_invalid(terminal)
    bundle = {
        "schema_version": "ebm-audit-synthetic-resolution-bundle/1.0",
        "resolved_configuration": configuration,
        "resolved_parameter_manifest": parameter_manifest,
        "resolved_generator_mechanism": mechanism,
        "component_seed_manifest": component_manifest,
    }
    _validate_schema(bundle)
    return ResolvedSyntheticCase(
        coordinate=coordinate,
        variant_index=resolved_variant_index,
        case_id=case_id,
        case_seed=case_seed,
        shared_draw_seed=None,
        operation_seed=operation_seed,
        source_contract_sha256=source_contract_sha256,
        scenario_definitions_sha256=authority.definitions_sha256,
        field_resolutions=field_rows,
        component_seeds=components,
        component_seed_manifest=component_manifest,
        resolved_parameter_manifest=parameter_manifest,
        resolved_configuration=configuration,
        resolved_mechanism=mechanism,
        resolution_bundle=bundle,
    )


def resolve_development_case(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    *,
    source_owner: AuthenticatedSourceOwner | None = None,
) -> ResolvedSyntheticCase:
    """Reconstruct one public development case without private attempt authority."""

    resolved = _resolve_case(authority, coordinate, source_owner=source_owner)
    if not isinstance(resolved, ResolvedSyntheticCase):
        raise AssertionError("Development resolution produced a private failure record.")
    return resolved


def _resolve_authenticated_heldout_case(
    authority: ScenarioAuthority,
    heldout_attempt_id: str,
    capability: object,
) -> ResolvedSyntheticCase | RetainedGeneratorInvalid:
    """Consume one evaluator capability and retain the exact resolved case privately."""

    if type(capability) is not _HeldoutCaseResolverCapability:
        raise _fail(
            "GENERATOR.HELDOUT_CAPABILITY_INVALID",
            "The held-out resolver capability is invalid.",
        )
    (
        case_seed,
        coordinate,
        variant_index,
        source_owner,
        family_override,
        pre_root_stratum_id,
    ) = capability._claim(heldout_attempt_id)
    resolved = _resolve_case(
        authority,
        coordinate,
        source_owner=source_owner,
        private_case_seed=case_seed,
        claimed_variant_index=variant_index,
        heldout_family_override=family_override,
        pre_root_stratum_id=pre_root_stratum_id,
        heldout_attempt_id=heldout_attempt_id,
    )
    return resolved


def resolve_heldout_case(
    authority: ScenarioAuthority,
    heldout_attempt_id: str,
    capability: object,
) -> HeldoutCaseResolution:
    """Consume one evaluator-issued capability and return only a seed-free result."""

    resolved = _resolve_authenticated_heldout_case(
        authority,
        heldout_attempt_id,
        capability,
    )
    if isinstance(resolved, RetainedGeneratorInvalid):
        return resolved
    return HeldoutResolvedCase(
        status="RESOLVED",
        heldout_attempt_id=heldout_attempt_id,
        coordinate=resolved.coordinate,
        variant_index=resolved.variant_index,
        case_id=resolved.case_id,
        source_contract_sha256=resolved.source_contract_sha256,
        scenario_definitions_sha256=resolved.scenario_definitions_sha256,
        field_resolutions=copy.deepcopy(resolved.field_resolutions),
        parameter_draw_count=sum(row.draw_consumed for row in resolved.field_resolutions),
        resolved_configuration=copy.deepcopy(resolved.resolved_configuration),
        resolved_mechanism=copy.deepcopy(resolved.resolved_mechanism),
    )


def verify_exact_resolution(
    authority: ScenarioAuthority,
    candidate: ResolvedSyntheticCase,
    *,
    source_owner: AuthenticatedSourceOwner | None = None,
) -> None:
    """Reconstruct and byte-compare all schema-facing resolution owners."""

    expected = resolve_development_case(
        authority,
        candidate.coordinate,
        source_owner=source_owner,
    )
    if candidate != expected:
        raise _fail(
            "GENERATOR.RESOLUTION_REPLAY_MISMATCH",
            "The submitted synthetic resolution differs from evaluator reconstruction.",
        )
