"""Deterministic public-product seeds, isolated from evaluator-held private roots."""

from __future__ import annotations

import copy
import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from typing import Literal, TypedDict, cast, overload

from ebm_audit.protocol import canonical_json_bytes
from ebm_audit.schema import SchemaValidationError, validate_instance

from .models import ConfigContractError

PRODUCT_SEED_DOMAIN = "ebm-audit/product-seed/2"
PRODUCT_SEED_DERIVATION_VERSION = "hmac-sha256-u64be-v2"
PRODUCT_SEED_PREIMAGE_SCHEMA_VERSION = "ebm-audit-product-seed-preimage/2.0"

SeedUse = Literal["operation", "universe-chain"]
OperationKind = Literal["ordinary", "bootstrap", "subsample", "influence", "null"]
RandomOperationKind = Literal["bootstrap", "subsample", "null"]


class BootstrapSeedParameters(TypedDict):
    sampling_method_id: Literal["participant-bootstrap-with-replacement/1"]
    sampling_design: Literal["ordinary", "stratified"]
    strata_group_spec_ids: Sequence[str]
    refit_preprocessing: Literal[True]
    fixed_evaluation_cohort_policy: Literal["fixed-baseline-cohort-or-unsupported/1"]


class SubsampleSeedParameters(TypedDict):
    sampling_method_id: Literal["participant-subsample-without-replacement/1"]
    sampling_design: Literal["ordinary", "stratified"]
    retained_fraction: float
    retained_count_rounding_rule: Literal["floor-pre-operation-count-times-fraction/1"]
    strata_group_spec_ids: Sequence[str]
    refit_preprocessing: Literal[True]
    fixed_evaluation_cohort_policy: Literal["fixed-subsample-cohort-or-unsupported/1"]


class NullSeedParameters(TypedDict):
    null_family_id: str
    null_method_id: Literal[
        "pure-no-signal-synthetic/1",
        "label-permutation/1",
        "featurewise-within-group-participant-permutation/1",
    ]
    transformation: Literal[
        "pure-no-signal-synthetic",
        "label-permutation",
        "featurewise-participant-permutation",
    ]
    within_group_spec_id: str | None
    refit_preprocessing: Literal[True]
    preserves_group_conditional_event_marginals: bool


OperationSeedParameters = (
    BootstrapSeedParameters | SubsampleSeedParameters | NullSeedParameters
)


class OperationRandomizationSeedPreimage(TypedDict):
    seed_preimage_schema_version: Literal["ebm-audit-product-seed-preimage/2.0"]
    seed_derivation_version: Literal["hmac-sha256-u64be-v2"]
    seed_use: Literal["operation"]
    operation_kind: RandomOperationKind
    source_analysis_spec_id: str
    source_variant_id: str
    derived_source_variant_id: str
    replicate_ordinal: int
    operation_parameters: OperationSeedParameters


class UniverseChainSeedPreimage(TypedDict):
    seed_preimage_schema_version: Literal["ebm-audit-product-seed-preimage/2.0"]
    seed_derivation_version: Literal["hmac-sha256-u64be-v2"]
    seed_use: Literal["universe-chain"]
    operation_kind: OperationKind
    analysis_spec_id: str
    chain_ordinal: int


ProductSeedPreimage = OperationRandomizationSeedPreimage | UniverseChainSeedPreimage

_UINT64_HEX = re.compile(r"^[0-9a-f]{16}$")
_PRODUCT_SEED_DOMAIN_BYTES = PRODUCT_SEED_DOMAIN.encode("ascii")


def _derive_seed_u64(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).digest()[:8].hex()


def _validated_preimage(preimage: Mapping[str, object]) -> dict[str, object]:
    try:
        value = copy.deepcopy(dict(preimage))
        validate_instance(
            value,
            "audit-config.schema.json",
            definition="ProductSeedPreimage",
        )
    except (SchemaValidationError, TypeError, ValueError):
        raise ConfigContractError("CONFIG.SEED_PREIMAGE") from None
    return value


@overload
def build_operation_seed_preimage(
    *,
    operation_kind: Literal["bootstrap"],
    source_analysis_spec_id: str,
    source_variant_id: str,
    derived_source_variant_id: str,
    replicate_ordinal: int,
    operation_parameters: BootstrapSeedParameters,
) -> OperationRandomizationSeedPreimage: ...


@overload
def build_operation_seed_preimage(
    *,
    operation_kind: Literal["subsample"],
    source_analysis_spec_id: str,
    source_variant_id: str,
    derived_source_variant_id: str,
    replicate_ordinal: int,
    operation_parameters: SubsampleSeedParameters,
) -> OperationRandomizationSeedPreimage: ...


@overload
def build_operation_seed_preimage(
    *,
    operation_kind: Literal["null"],
    source_analysis_spec_id: str,
    source_variant_id: str,
    derived_source_variant_id: str,
    replicate_ordinal: int,
    operation_parameters: NullSeedParameters,
) -> OperationRandomizationSeedPreimage: ...


def build_operation_seed_preimage(
    *,
    operation_kind: RandomOperationKind,
    source_analysis_spec_id: str,
    source_variant_id: str,
    derived_source_variant_id: str,
    replicate_ordinal: int,
    operation_parameters: OperationSeedParameters,
) -> OperationRandomizationSeedPreimage:
    """Build the only random-operation seed owner, before derived analysis identity."""

    preimage: dict[str, object] = {
        "seed_preimage_schema_version": PRODUCT_SEED_PREIMAGE_SCHEMA_VERSION,
        "seed_derivation_version": PRODUCT_SEED_DERIVATION_VERSION,
        "seed_use": "operation",
        "operation_kind": operation_kind,
        "source_analysis_spec_id": source_analysis_spec_id,
        "source_variant_id": source_variant_id,
        "derived_source_variant_id": derived_source_variant_id,
        "replicate_ordinal": replicate_ordinal,
        "operation_parameters": copy.deepcopy(dict(operation_parameters)),
    }
    return cast(OperationRandomizationSeedPreimage, _validated_preimage(preimage))


def build_universe_chain_seed_preimage(
    *,
    operation_kind: OperationKind,
    analysis_spec_id: str,
    chain_ordinal: int,
) -> UniverseChainSeedPreimage:
    """Build a model-chain owner after the final analysis specification exists."""

    preimage: dict[str, object] = {
        "seed_preimage_schema_version": PRODUCT_SEED_PREIMAGE_SCHEMA_VERSION,
        "seed_derivation_version": PRODUCT_SEED_DERIVATION_VERSION,
        "seed_use": "universe-chain",
        "operation_kind": operation_kind,
        "analysis_spec_id": analysis_spec_id,
        "chain_ordinal": chain_ordinal,
    }
    return cast(UniverseChainSeedPreimage, _validated_preimage(preimage))


def derive_product_seed(
    master_seed: str,
    *,
    preimage: Mapping[str, object],
) -> str:
    """Derive one public-product UInt64 seed from the exact validated v2 preimage.

    The public master seed is an eight-byte reproducibility input, not a secret.
    Evaluator-held roots are 32-byte private values with separate domains and must
    never be passed to this function.
    """

    if not isinstance(master_seed, str) or _UINT64_HEX.fullmatch(master_seed) is None:
        raise ConfigContractError("CONFIG.MASTER_SEED")
    owner = _validated_preimage(preimage)
    key = bytes.fromhex(master_seed)
    message = _PRODUCT_SEED_DOMAIN_BYTES + b"\x00" + canonical_json_bytes(owner)
    return _derive_seed_u64(key, message)


def validate_product_seed_assignments(
    master_seed: str,
    ordered_preimages: Sequence[Mapping[str, object]],
) -> tuple[str, ...]:
    """Derive one explicit batch and reject truncated UInt64 collisions within it."""

    derived: list[str] = []
    owner_by_seed: dict[str, bytes] = {}
    for preimage in ordered_preimages:
        owner = _validated_preimage(preimage)
        seed = derive_product_seed(master_seed, preimage=owner)
        owner_bytes = canonical_json_bytes(owner)
        previous = owner_by_seed.get(seed)
        if previous is not None and previous != owner_bytes:
            raise ConfigContractError("CONFIG.SEED_U64_COLLISION")
        owner_by_seed[seed] = owner_bytes
        derived.append(seed)
    return tuple(derived)
