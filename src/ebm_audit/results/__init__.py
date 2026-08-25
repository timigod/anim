"""Core-owned candidate result finalization and create-once persistence.

Serialized ResultRecord mappings are readback material only.  Runtime authority
is carried by opaque finalization, persisted-result, and terminal-index
capabilities.  The cache surface exported here is write-side only; files never
recreate cache-hit authority.
"""

from .finalization import (
    FinalizedResult,
    VerifiedCacheLineage,
    candidate_terminal_from_finalized_result,
    finalize_prepared_candidate,
    finalize_unprepared_candidate,
    finalized_result_cache_admission_bytes,
    finalized_result_persistence_bytes,
)
from .persistence import (
    PersistedCacheResult,
    PersistedFinalizedResult,
    ResultPersistenceJournal,
    SealedCandidateTerminalIndex,
    SealedResultEvidenceSet,
    all_candidates_terminal,
    candidate_terminal_index_digest,
    open_result_persistence_journal,
    persist_cache_admissible_result,
    persist_finalized_candidate,
    persisted_candidate_terminals,
    project_terminal_ledgers,
    seal_candidate_terminal_index,
    seal_result_evidence_set,
)

__all__ = [
    "FinalizedResult",
    "PersistedCacheResult",
    "PersistedFinalizedResult",
    "ResultPersistenceJournal",
    "SealedCandidateTerminalIndex",
    "SealedResultEvidenceSet",
    "VerifiedCacheLineage",
    "all_candidates_terminal",
    "candidate_terminal_from_finalized_result",
    "candidate_terminal_index_digest",
    "finalize_prepared_candidate",
    "finalize_unprepared_candidate",
    "finalized_result_cache_admission_bytes",
    "finalized_result_persistence_bytes",
    "open_result_persistence_journal",
    "persist_cache_admissible_result",
    "persist_finalized_candidate",
    "persisted_candidate_terminals",
    "project_terminal_ledgers",
    "seal_candidate_terminal_index",
    "seal_result_evidence_set",
]
