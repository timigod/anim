"""Project-owned, offline synthetic generation and replay.

Public exports are loaded on first access. In particular, importing the
independent replay module must not import the production generator or resolver.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .audit_input import (
        SealedDevelopmentCaseExecutionAuthorization as SealedDevelopmentCaseExecutionAuthorization,
    )
    from .audit_input import (
        SealedPublicSyntheticAuditInput as SealedPublicSyntheticAuditInput,
    )
    from .audit_input import (
        SyntheticEvaluationTruthEvidence as SyntheticEvaluationTruthEvidence,
    )
    from .audit_input import (
        open_public_synthetic_audit_input as open_public_synthetic_audit_input,
    )
    from .audit_input import (
        project_public_synthetic_audit_input as project_public_synthetic_audit_input,
    )
    from .audit_input import (
        project_synthetic_evaluation_truth_evidence as project_synthetic_evaluation_truth_evidence,
    )
    from .audit_input import (
        seal_synthetic_evaluation_truth_evidence as seal_synthetic_evaluation_truth_evidence,
    )
    from .authority import (
        ScenarioAuthority as ScenarioAuthority,
    )
    from .authority import (
        load_scenario_authority as load_scenario_authority,
    )
    from .development_candidate_source import (
        SealedDevelopmentCandidateSourceReceipt as SealedDevelopmentCandidateSourceReceipt,
    )
    from .development_candidate_source import (
        project_development_candidate_source_receipt as project_development_candidate_source_receipt,  # noqa: E501
    )
    from .development_candidate_source import (
        seal_development_candidate_source_receipt as seal_development_candidate_source_receipt,
    )
    from .generator import generate_synthetic_case as generate_synthetic_case
    from .models import (
        AuthenticatedSourceOwner as AuthenticatedSourceOwner,
    )
    from .models import (
        CaseCoordinate as CaseCoordinate,
    )
    from .models import (
        HeldoutCaseResolution as HeldoutCaseResolution,
    )
    from .models import (
        HeldoutResolvedCase as HeldoutResolvedCase,
    )
    from .models import (
        ReplayReceipt as ReplayReceipt,
    )
    from .models import (
        ResolvedSyntheticCase as ResolvedSyntheticCase,
    )
    from .models import (
        RetainedGeneratorInvalid as RetainedGeneratorInvalid,
    )
    from .models import (
        SyntheticCaseArtifacts as SyntheticCaseArtifacts,
    )
    from .replay import replay_synthetic_case as replay_synthetic_case
    from .resolver import (
        DEFAULT_EVENT_COUNT as DEFAULT_EVENT_COUNT,
    )
    from .resolver import (
        MATCHED_COMPARATOR_GENERATION_STATE as MATCHED_COMPARATOR_GENERATION_STATE,
    )
    from .resolver import (
        TRANSFORMED_NULL_GENERATION_STATE as TRANSFORMED_NULL_GENERATION_STATE,
    )
    from .resolver import (
        resolve_development_case as resolve_development_case,
    )
    from .resolver import (
        resolve_heldout_case as resolve_heldout_case,
    )
    from .resolver import (
        sample_decimal_tick as sample_decimal_tick,
    )
    from .resolver import (
        select_middle_adjacent_pair as select_middle_adjacent_pair,
    )
    from .resolver import (
        verify_exact_resolution as verify_exact_resolution,
    )

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "SealedDevelopmentCaseExecutionAuthorization": (
        ".audit_input",
        "SealedDevelopmentCaseExecutionAuthorization",
    ),
    "SealedPublicSyntheticAuditInput": (
        ".audit_input",
        "SealedPublicSyntheticAuditInput",
    ),
    "SyntheticEvaluationTruthEvidence": (
        ".audit_input",
        "SyntheticEvaluationTruthEvidence",
    ),
    "open_public_synthetic_audit_input": (
        ".audit_input",
        "open_public_synthetic_audit_input",
    ),
    "project_public_synthetic_audit_input": (
        ".audit_input",
        "project_public_synthetic_audit_input",
    ),
    "project_synthetic_evaluation_truth_evidence": (
        ".audit_input",
        "project_synthetic_evaluation_truth_evidence",
    ),
    "seal_synthetic_evaluation_truth_evidence": (
        ".audit_input",
        "seal_synthetic_evaluation_truth_evidence",
    ),
    "ScenarioAuthority": (".authority", "ScenarioAuthority"),
    "load_scenario_authority": (".authority", "load_scenario_authority"),
    "SealedDevelopmentCandidateSourceReceipt": (
        ".development_candidate_source",
        "SealedDevelopmentCandidateSourceReceipt",
    ),
    "project_development_candidate_source_receipt": (
        ".development_candidate_source",
        "project_development_candidate_source_receipt",
    ),
    "seal_development_candidate_source_receipt": (
        ".development_candidate_source",
        "seal_development_candidate_source_receipt",
    ),
    "generate_synthetic_case": (".generator", "generate_synthetic_case"),
    "AuthenticatedSourceOwner": (".models", "AuthenticatedSourceOwner"),
    "CaseCoordinate": (".models", "CaseCoordinate"),
    "HeldoutCaseResolution": (".models", "HeldoutCaseResolution"),
    "HeldoutResolvedCase": (".models", "HeldoutResolvedCase"),
    "ReplayReceipt": (".models", "ReplayReceipt"),
    "ResolvedSyntheticCase": (".models", "ResolvedSyntheticCase"),
    "RetainedGeneratorInvalid": (".models", "RetainedGeneratorInvalid"),
    "SyntheticCaseArtifacts": (".models", "SyntheticCaseArtifacts"),
    "replay_synthetic_case": (".replay", "replay_synthetic_case"),
    "DEFAULT_EVENT_COUNT": (".resolver", "DEFAULT_EVENT_COUNT"),
    "MATCHED_COMPARATOR_GENERATION_STATE": (
        ".resolver",
        "MATCHED_COMPARATOR_GENERATION_STATE",
    ),
    "TRANSFORMED_NULL_GENERATION_STATE": (
        ".resolver",
        "TRANSFORMED_NULL_GENERATION_STATE",
    ),
    "resolve_development_case": (".resolver", "resolve_development_case"),
    "resolve_heldout_case": (".resolver", "resolve_heldout_case"),
    "sample_decimal_tick": (".resolver", "sample_decimal_tick"),
    "select_middle_adjacent_pair": (".resolver", "select_middle_adjacent_pair"),
    "verify_exact_resolution": (".resolver", "verify_exact_resolution"),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    """Load one public export without coupling independent runtime modules."""

    try:
        module_name, attribute_name = _LAZY_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Expose lazy public names to interactive tools."""

    return sorted(set(globals()) | set(__all__))
