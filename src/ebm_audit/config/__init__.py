"""Strict local audit configuration and append-only run contracts."""

from __future__ import annotations

from ebm_audit.lifecycle import (
    PlanCandidateAuthorization,
    SealedCandidateExecutionDisposition,
    authorize_plan_candidates,
    classify_candidate_execution,
    project_candidate_execution_disposition,
)

from .loader import load_audit_config, parse_audit_config, resolve_audit_config
from .models import ConfigContractError, PrivatePathBindings, ResolvedAuditConfig
from .run_artifacts import (
    RUN_STATES,
    validate_append_only_transition,
    validate_run_artifact,
)
from .seeds import (
    PRODUCT_SEED_DERIVATION_VERSION,
    PRODUCT_SEED_DOMAIN,
    PRODUCT_SEED_PREIMAGE_SCHEMA_VERSION,
    BootstrapSeedParameters,
    NullSeedParameters,
    OperationKind,
    OperationRandomizationSeedPreimage,
    ProductSeedPreimage,
    RandomOperationKind,
    SeedUse,
    SubsampleSeedParameters,
    UniverseChainSeedPreimage,
    build_operation_seed_preimage,
    build_universe_chain_seed_preimage,
    derive_product_seed,
    validate_product_seed_assignments,
)
from .strict_yaml import StrictYamlError, load_strict_yaml_bytes
from .verification import (
    PlanEligibleAuditConfig,
    RunEligibleAuditConfig,
    VerifiedAuditConfigFiles,
    authorize_audit_config_plan,
    authorize_audit_config_run,
    verify_audit_config_files,
)

__all__ = [
    "PRODUCT_SEED_DERIVATION_VERSION",
    "PRODUCT_SEED_DOMAIN",
    "PRODUCT_SEED_PREIMAGE_SCHEMA_VERSION",
    "RUN_STATES",
    "BootstrapSeedParameters",
    "ConfigContractError",
    "NullSeedParameters",
    "OperationKind",
    "OperationRandomizationSeedPreimage",
    "PlanCandidateAuthorization",
    "PlanEligibleAuditConfig",
    "PrivatePathBindings",
    "ProductSeedPreimage",
    "RandomOperationKind",
    "ResolvedAuditConfig",
    "RunEligibleAuditConfig",
    "SealedCandidateExecutionDisposition",
    "SeedUse",
    "StrictYamlError",
    "SubsampleSeedParameters",
    "UniverseChainSeedPreimage",
    "VerifiedAuditConfigFiles",
    "authorize_audit_config_plan",
    "authorize_audit_config_run",
    "authorize_plan_candidates",
    "build_operation_seed_preimage",
    "build_universe_chain_seed_preimage",
    "classify_candidate_execution",
    "derive_product_seed",
    "load_audit_config",
    "load_strict_yaml_bytes",
    "parse_audit_config",
    "project_candidate_execution_disposition",
    "resolve_audit_config",
    "validate_append_only_transition",
    "validate_product_seed_assignments",
    "validate_run_artifact",
    "verify_audit_config_files",
]
