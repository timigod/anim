"""Immutable analysis-universe construction and identities."""

from __future__ import annotations

from .axis_semantics import AxisSemanticsError, load_axis_semantics
from .compiler import (
    AxisCompositionError,
    compose_analysis_spec,
    compose_experiment_set,
)
from .identities import (
    PublicIntentManifest,
    ValidatedPlanningSummary,
    analysis_plan_digest,
    analysis_spec_content_id,
    attempt_id,
    candidate_origin_id,
    chain_cache_key,
    chain_execution_id,
    declaration_provenance_digest,
    planning_config_digest,
    preparation_receipt_digest,
    preparation_rule_registry_digest,
    public_intent_manifest_digest,
    scientific_backend_registry_digest,
    universe_cache_key,
    universe_id,
    validated_planning_summary_id,
)
from .planning import (
    PlanningAuthority,
    compile_analysis_plan,
    issue_planning_authority,
    issue_public_intent_manifest,
)
from .preparation import (
    PreparationTransaction,
    PreparedExecutionAuthorization,
    ProfilePreparedCandidateGroup,
    UnpreparedResultAuthorization,
    prepare_profile_candidate_group,
)

__all__ = [
    "AxisCompositionError",
    "AxisSemanticsError",
    "PlanningAuthority",
    "PreparationTransaction",
    "PreparedExecutionAuthorization",
    "ProfilePreparedCandidateGroup",
    "PublicIntentManifest",
    "UnpreparedResultAuthorization",
    "ValidatedPlanningSummary",
    "analysis_plan_digest",
    "analysis_spec_content_id",
    "attempt_id",
    "candidate_origin_id",
    "chain_cache_key",
    "chain_execution_id",
    "compile_analysis_plan",
    "compose_analysis_spec",
    "compose_experiment_set",
    "declaration_provenance_digest",
    "issue_planning_authority",
    "issue_public_intent_manifest",
    "load_axis_semantics",
    "planning_config_digest",
    "preparation_receipt_digest",
    "preparation_rule_registry_digest",
    "prepare_profile_candidate_group",
    "public_intent_manifest_digest",
    "scientific_backend_registry_digest",
    "universe_cache_key",
    "universe_id",
    "validated_planning_summary_id",
]
