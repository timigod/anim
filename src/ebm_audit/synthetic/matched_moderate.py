"""One closed public-synthetic source for the moderate matched comparator.

This development-only operation owns exactly eight prospective pairs. It is
not a general comparator API and grants no audit, profile, selection, report,
or held-out authority.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path
from typing import Any, Final, Literal, Never, SupportsIndex, cast, final

import numpy as np

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol.canonical import canonical_json_bytes, structured_sha256_hex
from ebm_audit.schema.validation import SchemaValidationError, validate_instance

from .authority import COMPONENT_PATHS, ScenarioAuthority, load_scenario_authority
from .generator import (
    _execute_ordinary,
    _immutable_bool,
    _immutable_float,
    _scientific_data,
    _truth,
)
from .models import CaseCoordinate, ComponentSeed, ResolvedSyntheticCase, SyntheticCaseArtifacts
from .pure_no_signal import verify_pure_no_signal_semantics
from .replay import _replay_authenticated_matched_case
from .resolver import resolve_development_case, verify_exact_resolution

_MANIFEST_FILENAME: Final = "matched-moderate-source-manifest.json"
_MANIFEST_SHA256: Final = "a3cd44756cd064137f6d137306d6b811cbf81c59917bd212d520718246c6739e"
_AUTHORITY_FILENAME: Final = "matched-moderate-authority.json"
_AUTHORITY_RELATIVE_PATH: Final = "examples/development/matched-moderate-authority.json"
_AUTHORITY_SHA256: Final = "656fea0659b8851d7c75fd577308bb9ae9c9b931d4024570d3efd7c344201bb2"
_AUTHORITY_ROOTS: Final = (
    "c9adc6fee9c00b79",
    "86b6740157a8ec3e",
    "725fb844ce462a7e",
    "e5d0209ee54c66a1",
    "dd399be8bd501127",
    "f4d96b9f89b343ac",
    "f6a23ede94bc2a08",
    "e5e6fccf71686a92",
)
_COMPARATOR_ID: Final = "cmp_moderate_signal_vs_pure_no_signal"
_PAIR_COUNT: Final = 8
_SHARED_PATHS: Final[tuple[str, ...]] = (
    "group_assignment",
    "latent_time",
    "covariates",
    "participant_effect",
    "measurement_normal",
    "measurement_scale",
    "measurement_skew",
    "contamination",
    "outliers",
    "missingness",
)
_EXCLUDED_PATHS: Final[tuple[str, ...]] = (
    "parameters",
    "subgroup_assignment",
    "label_permutation",
    "within_group_feature_permutation",
)


def _invalid(code: str) -> InvalidInputError:
    return InvalidInputError(code, "The matched moderate synthetic source is invalid.")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _invalid("GENERATOR.MATCHED_MANIFEST_INVALID")
        result[key] = value
    return result


def _decode_manifest(raw: bytes) -> dict[str, Any]:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _invalid("GENERATOR.MATCHED_MANIFEST_INVALID")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                _invalid("GENERATOR.MATCHED_MANIFEST_INVALID")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _invalid("GENERATOR.MATCHED_MANIFEST_INVALID") from exc
    if not isinstance(value, dict):
        raise _invalid("GENERATOR.MATCHED_MANIFEST_INVALID")
    return cast(dict[str, Any], value)


@dataclass(frozen=True, slots=True)
class MatchedModerateManifestOwner:
    """Exact checked-in bytes that own the only matched operation."""

    exact_bytes: bytes
    bytes_sha256: str
    _data: dict[str, Any] = field(repr=False)
    _data_sha256: str = field(repr=False)

    @property
    def data(self) -> dict[str, Any]:
        if (
            type(self) is not MatchedModerateManifestOwner
            or hashlib.sha256(self.exact_bytes).hexdigest() != self.bytes_sha256
            or self.bytes_sha256 != _MANIFEST_SHA256
            or hashlib.sha256(canonical_json_bytes(self._data)).hexdigest() != self._data_sha256
        ):
            raise _invalid("GENERATOR.MATCHED_MANIFEST_IDENTITY_MISMATCH")
        return copy.deepcopy(self._data)


def _fixed_development_resource(filename: str, expected_sha256: str) -> bytes:
    packaged = resources.files("ebm_audit").joinpath("examples", "development", filename)
    try:
        if packaged.is_file():
            raw = packaged.read_bytes()
            if hashlib.sha256(raw).hexdigest() == expected_sha256:
                return raw
    except (FileNotFoundError, OSError, TypeError):
        pass
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "examples" / "development" / filename
        if candidate.is_file():
            try:
                raw = candidate.read_bytes()
            except OSError as exc:
                raise _invalid("GENERATOR.MATCHED_RESOURCE_UNAVAILABLE") from exc
            if hashlib.sha256(raw).hexdigest() == expected_sha256:
                return raw
            raise _invalid("GENERATOR.MATCHED_RESOURCE_IDENTITY_MISMATCH")
    raise _invalid("GENERATOR.MATCHED_RESOURCE_UNAVAILABLE")


def matched_moderate_manifest_bytes() -> bytes:
    """Read the one fixed manifest without a caller-selected path."""

    return _fixed_development_resource(_MANIFEST_FILENAME, _MANIFEST_SHA256)


def _matched_moderate_authority_bytes() -> bytes:
    """Read the one fixed authority without a caller-selected path."""

    return _fixed_development_resource(_AUTHORITY_FILENAME, _AUTHORITY_SHA256)


def load_matched_moderate_manifest(
    exact_json: bytes | bytearray | memoryview,
) -> MatchedModerateManifestOwner:
    """Authenticate the exact checked-in manifest bytes."""

    raw = bytes(exact_json)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != _MANIFEST_SHA256:
        raise _invalid("GENERATOR.MATCHED_MANIFEST_IDENTITY_MISMATCH")
    data = _decode_manifest(raw)
    try:
        validate_instance(data, "matched-moderate-source.schema.json", definition="Manifest")
    except SchemaValidationError as exc:
        raise _invalid("GENERATOR.MATCHED_MANIFEST_SCHEMA_INVALID") from exc
    roots = [row["shared_draw_root"] for row in data["pairs"]]
    if len(set(roots)) != _PAIR_COUNT:
        raise _invalid("GENERATOR.MATCHED_SHARED_ROOT_INVALID")
    return MatchedModerateManifestOwner(
        exact_bytes=raw,
        bytes_sha256=digest,
        _data=copy.deepcopy(data),
        _data_sha256=hashlib.sha256(canonical_json_bytes(data)).hexdigest(),
    )


@dataclass(frozen=True, slots=True, repr=False)
class _PairState:
    pair_ordinal: int
    canonical_projection: bytes


@dataclass(frozen=True, slots=True, repr=False)
class _PairMaterial:
    manifest_owner: MatchedModerateManifestOwner
    authority: ScenarioAuthority
    pair_ordinal: int
    shared_root: str
    signal_ordinary: ResolvedSyntheticCase
    pure_ordinary: ResolvedSyntheticCase
    signal_case: ResolvedSyntheticCase
    pure_case: ResolvedSyntheticCase
    signal_artifacts: SyntheticCaseArtifacts
    pure_artifacts: SyntheticCaseArtifacts


def _reject_pair_copy() -> Never:
    raise TypeError("Matched moderate pair capabilities cannot be copied or serialized.")


@final
class SealedMatchedModeratePair:
    """Opaque non-transferable capability for exactly one regenerated pair."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Matched moderate pair capabilities cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Matched moderate pair capabilities are privately issued.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Matched moderate pair capabilities are immutable.")

    def __copy__(self) -> Never:
        _reject_pair_copy()

    def __deepcopy__(self, _memo: object) -> Never:
        _reject_pair_copy()

    def __reduce__(self) -> Never:
        _reject_pair_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        _reject_pair_copy()

    def __getstate__(self) -> Never:
        _reject_pair_copy()

    def __repr__(self) -> str:
        state = _pair_state(self)
        return f"SealedMatchedModeratePair(pair_ordinal={state.pair_ordinal})"


_PAIR_STATES: OneShotWeakRegistry[SealedMatchedModeratePair, _PairState]
_PAIR_STATE_ISSUER: OneShotRegistryIssuer[SealedMatchedModeratePair, _PairState]
(_PAIR_STATES, _PAIR_STATE_ISSUER) = create_one_shot_registry()


def _pair_state(value: object) -> _PairState:
    if type(value) is not SealedMatchedModeratePair:
        raise _invalid("GENERATOR.MATCHED_PAIR_SEAL_INVALID")
    try:
        state = _PAIR_STATES[value]
        _PAIR_STATES.require(value, state)
    except (KeyError, TypeError):
        raise _invalid("GENERATOR.MATCHED_PAIR_SEAL_INVALID") from None
    if type(state) is not _PairState:
        raise _invalid("GENERATOR.MATCHED_PAIR_SEAL_INVALID")
    return state


def _component_seed(root: str, path: str, *, shared: bool) -> ComponentSeed:
    digest = hmac.new(
        bytes.fromhex(root),
        b"ebm-audit-synthetic-component/v1\0" + path.encode(),
        hashlib.sha256,
    ).digest()
    return ComponentSeed(
        component_path=path,
        root_kind="SHARED_DRAW_SEED" if shared else "CASE_SEED",
        full_digest="sha256:" + digest.hex(),
        seed_128=digest[:16].hex(),
        shared=shared,
    )


def _matched_case(
    ordinary: ResolvedSyntheticCase,
    *,
    shared_root: str,
    pair_ordinal: int,
) -> ResolvedSyntheticCase:
    rows = tuple(
        _component_seed(shared_root, path, shared=True)
        if path in _SHARED_PATHS
        else ordinary.component_seed(path)
        for path in COMPONENT_PATHS
    )
    preimage: dict[str, Any] = {
        "schema_version": "ebm-audit-component-seed-manifest/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "scenario_family_id": ordinary.coordinate.family_id,
        "root_assignment_context": {
            "kind": "DEVELOPMENT_MATCHED_COMPARATOR",
            "comparator_id": _COMPARATOR_ID,
            "source_variant_id": "moderate_57_public",
            "pair_index": pair_ordinal,
        },
        "case_seed": ordinary.case_seed,
        "shared_draw_seed": shared_root,
        "operation_seed": None,
        "shared_component_paths": list(_SHARED_PATHS),
        "operation_component_paths": [],
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
    manifest = copy.deepcopy(preimage)
    manifest["digest_state"] = "PERSISTED"
    manifest["component_seed_manifest_sha256"] = structured_sha256_hex(
        "ebm-audit/component-seed-manifest/1", preimage
    )
    bundle = copy.deepcopy(ordinary.resolution_bundle)
    bundle["component_seed_manifest"] = manifest
    try:
        validate_instance(bundle, "synthetic-resolved-configuration.schema.json")
    except SchemaValidationError as exc:
        raise _invalid("GENERATOR.MATCHED_COMPONENT_MANIFEST_INVALID") from exc
    return replace(
        ordinary,
        shared_draw_seed=shared_root,
        component_seeds=rows,
        component_seed_manifest=manifest,
        resolution_bundle=bundle,
    )


def _configuration_common_projection(configuration: dict[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(configuration)
    for key in (
        "schema_version",
        "digest_state",
        "resolved_generator_configuration_sha256",
        "dependency_records",
        "scenario_family_id",
        "variant_id",
    ):
        projected.pop(key)
    event_parameters = cast(dict[str, Any], projected["event_parameters"])
    for key in (
        "amplitude",
        "covariate_effect",
        "group_effect",
        "participant_effect_loading",
    ):
        event_parameters.pop(key)
    projected.pop("latent_sampling")
    scenario_parameters = cast(dict[str, Any], projected["scenario_parameters"])
    scenario_parameters.pop("truth_type")
    return projected


def _all_zero(values: object, event_count: int) -> bool:
    return (
        isinstance(values, list)
        and len(values) == event_count
        and all(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value == 0
            for value in values
        )
    )


def _validate_configuration_ledger(
    signal: ResolvedSyntheticCase,
    pure: ResolvedSyntheticCase,
) -> list[str]:
    signal_config = signal.resolved_configuration
    pure_config = pure.resolved_configuration
    if _configuration_common_projection(signal_config) != _configuration_common_projection(
        pure_config
    ):
        raise _invalid("GENERATOR.MATCHED_CONFIGURATION_LEDGER_MISMATCH")
    event_count = signal_config["dimensions"]["event_count"]
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or event_count < 2
        or pure_config["dimensions"]["event_count"] != event_count
    ):
        raise _invalid("GENERATOR.MATCHED_CONFIGURATION_LEDGER_MISMATCH")
    pure_events = pure_config["event_parameters"]
    if any(
        not _all_zero(pure_events[key], event_count)
        for key in (
            "amplitude",
            "covariate_effect",
            "group_effect",
            "participant_effect_loading",
        )
    ):
        raise _invalid("GENERATOR.MATCHED_PURE_NO_SIGNAL_INVALID")
    signal_events = signal_config["event_parameters"]
    if (
        not _all_zero(signal_events["covariate_effect"], event_count)
        or not _all_zero(signal_events["group_effect"], event_count)
        or not any(value > 0 for value in signal_events["amplitude"])
        or signal_config["latent_sampling"]["mode"] != "GROUP_WINDOWS"
        or signal_config["latent_sampling"]["group_independent_window"] is not None
        or pure_config["latent_sampling"]["mode"] != "GROUP_INDEPENDENT_WINDOW"
        or pure_config["latent_sampling"]["reference_window"] is not None
        or pure_config["latent_sampling"]["at_risk_window"] is not None
    ):
        raise _invalid("GENERATOR.MATCHED_CONFIGURATION_LEDGER_MISMATCH")
    verify_pure_no_signal_semantics(pure_config)
    if (
        signal.field_value("subgroup_fraction") is not None
        or pure.field_value("subgroup_fraction") is not None
        or signal.resolved_mechanism["mechanism_kind"] != "STRICT_TOTAL_ORDER"
        or signal.resolved_mechanism["strict_order_identifiable"] is not True
        or signal.resolved_mechanism["base_order"] != signal_config["event_ids"]
        or signal.resolved_mechanism["subgroup_orders"] != []
        or pure.resolved_mechanism["mechanism_kind"] != "PURE_NO_SIGNAL"
        or pure.resolved_mechanism["strict_order_identifiable"] is not False
        or pure.resolved_mechanism["base_order"] != []
        or pure.resolved_mechanism["subgroup_orders"] != []
    ):
        raise _invalid("GENERATOR.MATCHED_SOURCE_ORDER_INVALID")
    return cast(list[str], copy.deepcopy(signal_config["event_ids"]))


def _validate_matched_case(
    ordinary: ResolvedSyntheticCase,
    matched: ResolvedSyntheticCase,
    *,
    shared_root: str,
    pair_ordinal: int,
) -> None:
    expected = _matched_case(ordinary, shared_root=shared_root, pair_ordinal=pair_ordinal)
    if matched != expected:
        raise _invalid("GENERATOR.MATCHED_TRANSACTION_MISMATCH")
    if matched.component_seed("subgroup_assignment").root_kind != "CASE_SEED":
        raise _invalid("GENERATOR.MATCHED_SUBGROUP_ROOT_INVALID")
    for path in _SHARED_PATHS:
        if (
            matched.component_seed(path).root_kind != "SHARED_DRAW_SEED"
            or matched.component_seed(path).shared is not True
        ):
            raise _invalid("GENERATOR.MATCHED_COMPONENT_SEED_MISMATCH")
    for path in _EXCLUDED_PATHS:
        if (
            matched.component_seed(path) != ordinary.component_seed(path)
            or matched.component_seed(path).root_kind != "CASE_SEED"
            or matched.component_seed(path).shared is not False
        ):
            raise _invalid("GENERATOR.MATCHED_COMPONENT_SEED_MISMATCH")


def _generate(case: ResolvedSyntheticCase) -> SyntheticCaseArtifacts:
    execution = _execute_ordinary(case)
    return SyntheticCaseArtifacts(
        resolved_case=case,
        scientific_data=_scientific_data(case, execution),
        truth=_truth(case, execution),
        stage_snapshots=execution.stage_snapshots,
        clean_values=_immutable_float(execution.clean_values),
        perturbed_values=_immutable_float(execution.perturbed_values),
        missingness_mask=_immutable_bool(execution.mask),
    )


def _member_evidence(
    role: Literal["SIGNAL", "PURE_NO_SIGNAL"],
    artifacts: SyntheticCaseArtifacts,
) -> dict[str, Any]:
    case = artifacts.resolved_case
    return {
        "role": role,
        "case_id": case.case_id,
        "resolved_configuration_sha256": case.resolved_configuration[
            "resolved_generator_configuration_sha256"
        ],
        "field_ledger_sha256": structured_sha256_hex(
            "ebm-audit/matched-moderate-field-ledger/1",
            [row.as_dict() for row in case.field_resolutions],
        ),
        "resolved_parameter_manifest_sha256": case.resolved_parameter_manifest[
            "resolved_parameter_manifest_sha256"
        ],
        "component_seed_manifest_sha256": case.component_seed_manifest[
            "component_seed_manifest_sha256"
        ],
        "source_order_sha256": structured_sha256_hex(
            "ebm-audit/matched-moderate-source-order/1",
            case.resolved_configuration["event_ids"],
        ),
        "components": [
            {
                "component_path": row.component_path,
                "root_kind": row.root_kind,
                "component_seed_digest": row.full_digest,
                "shared": row.shared,
            }
            for row in case.component_seeds
        ],
        "stages": [
            {
                "stage_index": row.stage_index,
                "stage_id": row.stage_id,
                "output_sha256": row.output_sha256,
            }
            for row in artifacts.stage_snapshots
        ],
        "generated_scientific_data_sha256": artifacts.scientific_data[
            "generated_scientific_data_sha256"
        ],
        "truth_object_sha256": artifacts.truth["truth_object_sha256"],
        "replay": {
            "status": "MATCH",
            "compared_stage_count": 14,
            "data_match": True,
            "truth_match": True,
        },
    }


def _validate_generated_truth(
    signal: SyntheticCaseArtifacts,
    pure: SyntheticCaseArtifacts,
    reference_order: list[str],
) -> None:
    signal_order = signal.truth["order_truth"]
    pure_order = pure.truth["order_truth"]
    if (
        signal_order["truth_kind"] != "STRICT_TOTAL_ORDER"
        or signal_order["strict_order_identifiable"] is not True
        or signal_order["strict_order"] != reference_order
        or signal_order["recoverable_signal"] is not True
        or pure_order["truth_kind"] != "NONE"
        or pure_order["strict_order_identifiable"] is not False
        or pure_order["strict_order"] != []
        or pure_order["recoverable_signal"] is not False
        or pure.truth["stage_truth"] != {"state": "NONE", "participant_stages": []}
    ):
        raise _invalid("GENERATOR.MATCHED_TRUTH_SEMANTICS_INVALID")


def _pinned_owners() -> tuple[MatchedModerateManifestOwner, ScenarioAuthority]:
    manifest_owner = load_matched_moderate_manifest(matched_moderate_manifest_bytes())
    authority = load_scenario_authority(_matched_moderate_authority_bytes())
    manifest = manifest_owner.data
    families = authority.scenario_families
    roots = authority.data.get("seed_policy", {}).get("development_root_seeds")
    coordinates = [
        (
            family.get("id"),
            family.get("development_replicates"),
            len(cast(list[object], family.get("development_variants"))),
            family["development_variants"][0].get("id"),
            family["development_variants"][0].get("participants"),
            family["development_variants"][0].get("events"),
        )
        for family in families
        if isinstance(family.get("development_variants"), list)
        and family["development_variants"]
        and isinstance(family["development_variants"][0], dict)
    ]
    if (
        manifest["authority_resource"]
        != {
            "relative_path": _AUTHORITY_RELATIVE_PATH,
            "expected_byte_sha256": _AUTHORITY_SHA256,
        }
        or authority.definitions_sha256 != _AUTHORITY_SHA256
        or tuple(roots) != _AUTHORITY_ROOTS
        or coordinates
        != [
            ("moderate_mina_shape", 8, 1, "moderate_57_public", 57, 9),
            ("pure_no_signal", 8, 1, "null_correlated", 57, 9),
        ]
    ):
        raise _invalid("GENERATOR.MATCHED_AUTHORITY_CONTRACT_INVALID")
    return manifest_owner, authority


def _derive_pair(pair_ordinal: int) -> _PairMaterial:
    manifest_owner, authority = _pinned_owners()
    pair = manifest_owner.data["pairs"][pair_ordinal]
    if pair["pair_ordinal"] != pair_ordinal or pair["replicate_index"] != pair_ordinal:
        raise _invalid("GENERATOR.MATCHED_PAIR_DENOMINATOR_INVALID")
    shared_root = cast(str, pair["shared_draw_root"])
    signal_ordinary = resolve_development_case(
        authority,
        CaseCoordinate("moderate_mina_shape", "moderate_57_public", pair_ordinal),
    )
    pure_ordinary = resolve_development_case(
        authority,
        CaseCoordinate("pure_no_signal", "null_correlated", pair_ordinal),
    )
    signal_case = _matched_case(signal_ordinary, shared_root=shared_root, pair_ordinal=pair_ordinal)
    pure_case = _matched_case(pure_ordinary, shared_root=shared_root, pair_ordinal=pair_ordinal)
    return _PairMaterial(
        manifest_owner=manifest_owner,
        authority=authority,
        pair_ordinal=pair_ordinal,
        shared_root=shared_root,
        signal_ordinary=signal_ordinary,
        pure_ordinary=pure_ordinary,
        signal_case=signal_case,
        pure_case=pure_case,
        signal_artifacts=_generate(signal_case),
        pure_artifacts=_generate(pure_case),
    )


def _build_evidence(material: _PairMaterial) -> dict[str, Any]:
    pinned_manifest, pinned_authority = _pinned_owners()
    if (
        type(material) is not _PairMaterial
        or material.manifest_owner != pinned_manifest
        or material.authority != pinned_authority
        or not 0 <= material.pair_ordinal < _PAIR_COUNT
        or material.shared_root
        != pinned_manifest.data["pairs"][material.pair_ordinal]["shared_draw_root"]
    ):
        raise _invalid("GENERATOR.MATCHED_TRANSACTION_MISMATCH")
    verify_exact_resolution(pinned_authority, material.signal_ordinary)
    verify_exact_resolution(pinned_authority, material.pure_ordinary)
    reference_order = _validate_configuration_ledger(
        material.signal_ordinary, material.pure_ordinary
    )
    for ordinary, matched in (
        (material.signal_ordinary, material.signal_case),
        (material.pure_ordinary, material.pure_case),
    ):
        _validate_matched_case(
            ordinary,
            matched,
            shared_root=material.shared_root,
            pair_ordinal=material.pair_ordinal,
        )
    if any(
        material.signal_case.component_seed(path) != material.pure_case.component_seed(path)
        for path in _SHARED_PATHS
    ):
        raise _invalid("GENERATOR.MATCHED_COMPONENT_SEED_MISMATCH")
    for ordinary, matched, artifacts in (
        (
            material.signal_ordinary,
            material.signal_case,
            material.signal_artifacts,
        ),
        (
            material.pure_ordinary,
            material.pure_case,
            material.pure_artifacts,
        ),
    ):
        receipt = _replay_authenticated_matched_case(
            ordinary,
            matched,
            artifacts,
            authority=pinned_authority,
        )
        if (
            receipt.status != "MATCH"
            or receipt.compared_stage_count != 14
            or receipt.data_match is not True
            or receipt.truth_match is not True
        ):
            raise _invalid("GENERATOR.MATCHED_REPLAY_MISMATCH")
    _validate_generated_truth(
        material.signal_artifacts,
        material.pure_artifacts,
        reference_order,
    )
    reference_digest = structured_sha256_hex(
        "ebm-audit/matched-moderate-source-order/1", reference_order
    )
    preimage: dict[str, Any] = {
        "schema_version": "ebm-audit-matched-moderate-pair-evidence/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "data_classification": "SYNTHETIC_ONLY",
        "operation_id": "open_matched_moderate_pair",
        "comparator_id": _COMPARATOR_ID,
        "pair_ordinal": material.pair_ordinal,
        "replicate_index": material.pair_ordinal,
        "authority_bytes_sha256": _AUTHORITY_SHA256,
        "manifest_bytes_sha256": _MANIFEST_SHA256,
        "shared_draw_root_sha256": hashlib.sha256(bytes.fromhex(material.shared_root)).hexdigest(),
        "shared_component_paths": list(_SHARED_PATHS),
        "excluded_component_paths": list(_EXCLUDED_PATHS),
        "reference_order_event_ids": reference_order,
        "reference_order_sha256": reference_digest,
        "semantic_checks": {
            "configuration_ledger_exact": True,
            "subgroup_absent_and_unconsumed": True,
            "strict_signal_order_identifiable": True,
            "pure_no_signal_semantics": True,
            "pure_no_signal_has_no_recoverable_order_or_stage": True,
            "shared_component_seeds_match": True,
            "excluded_components_are_not_shared": True,
        },
        "signal": _member_evidence("SIGNAL", material.signal_artifacts),
        "pure_no_signal": _member_evidence("PURE_NO_SIGNAL", material.pure_artifacts),
        "matched_pair_evidence_sha256": None,
    }
    evidence = copy.deepcopy(preimage)
    evidence["digest_state"] = "PERSISTED"
    evidence["matched_pair_evidence_sha256"] = structured_sha256_hex(
        "ebm-audit/matched-moderate-pair-evidence/1", preimage
    )
    try:
        validate_instance(evidence, "matched-moderate-source.schema.json", definition="Evidence")
    except SchemaValidationError as exc:
        raise _invalid("GENERATOR.MATCHED_EVIDENCE_SCHEMA_INVALID") from exc
    return evidence


def _fresh_material_and_projection(
    pair_ordinal: int,
) -> tuple[_PairMaterial, dict[str, Any]]:
    material = _derive_pair(pair_ordinal)
    return material, _build_evidence(material)


def open_matched_moderate_pair(
    manifest_owner: MatchedModerateManifestOwner,
    authority: ScenarioAuthority,
    pair_ordinal: int,
) -> SealedMatchedModeratePair:
    """Issue one opaque capability after exact pinned regeneration and replay."""

    if (
        type(manifest_owner) is not MatchedModerateManifestOwner
        or type(authority) is not ScenarioAuthority
        or type(pair_ordinal) is not int
        or not 0 <= pair_ordinal < _PAIR_COUNT
    ):
        raise _invalid("GENERATOR.MATCHED_PAIR_ORDINAL_INVALID")
    pinned_manifest, pinned_authority = _pinned_owners()
    if manifest_owner != pinned_manifest or authority != pinned_authority:
        raise _invalid("GENERATOR.MATCHED_AUTHORITY_IDENTITY_MISMATCH")
    _material, projection = _fresh_material_and_projection(pair_ordinal)
    capability = object.__new__(SealedMatchedModeratePair)
    _PAIR_STATE_ISSUER.bind_once(
        capability,
        _PairState(
            pair_ordinal=pair_ordinal,
            canonical_projection=canonical_json_bytes(projection),
        ),
    )
    return capability


def _verified_pair_material(
    value: object,
) -> tuple[SyntheticCaseArtifacts, SyntheticCaseArtifacts]:
    """Private future-runner seam returning only freshly verified artifacts."""

    state = _pair_state(value)
    material, projection = _fresh_material_and_projection(state.pair_ordinal)
    if canonical_json_bytes(projection) != state.canonical_projection:
        raise _invalid("GENERATOR.MATCHED_PAIR_SEAL_INVALID")
    _PAIR_STATES.require(value, state)
    return material.signal_artifacts, material.pure_artifacts


def project_matched_moderate_pair_evidence(
    value: object,
) -> dict[str, Any]:
    """Regenerate and replay before returning the participant-free projection."""

    state = _pair_state(value)
    _material, projection = _fresh_material_and_projection(state.pair_ordinal)
    if canonical_json_bytes(projection) != state.canonical_projection:
        raise _invalid("GENERATOR.MATCHED_PAIR_SEAL_INVALID")
    _PAIR_STATES.require(value, state)
    return projection
