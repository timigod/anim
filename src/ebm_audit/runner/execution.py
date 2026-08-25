"""Exact PreparationTransaction-to-terminal-index production execution.

The caller supplies only genuine in-process authorities.  Scientific request
mappings, arrays, validation receipts, fit receipts, retry decisions, result
bodies, cache lineages, and terminal rows are all derived inside this module.
"""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Never, SupportsIndex, cast, final

from ebm_audit.adapters.invocation import (
    AuthenticatedWorkerExecutionEvidence,
    InvocationFailureClass,
    WorkerExecution,
    WorkerInvocationObservation,
    WorkerInvoker,
    _read_prepared_candidate_execution_context,
    _readback_worker_invocation_observation,
)
from ebm_audit.errors import AuditError
from ebm_audit.lifecycle import (
    _candidate_terminal_rows,
    _plan_candidate_rows,
    _read_plan_candidate_authorization,
)
from ebm_audit.protocol import strict_json_loads
from ebm_audit.results.finalization import (
    _PREPARED_EXECUTION_FINALIZATION_ISSUER,
    _VERIFIED_CACHE_ISSUER,
    FinalizedResult,
    VerifiedCacheLineage,
    _capture_finalized_result_state_identity,
    _finalize_unprepared_candidate_with_state,
    _FinalizedResultState,
    _issue_prepared_execution_finalization,
    _issue_verified_cache_lineage,
    finalize_prepared_candidate,
)
from ebm_audit.results.persistence import (
    ResultPersistenceJournal,
    SealedCandidateTerminalIndex,
    _persist_cache_admissible_result_with_state,
    _persist_finalized_candidate_with_state_capture,
    _read_result_journal,
    _require_result_journal_state_identity,
    _ResultPersistenceJournalState,
    _seal_candidate_terminal_index_with_state,
)
from ebm_audit.universe.preparation import (
    PreparationTransaction,
    PreparedExecutionAuthorization,
    UnpreparedResultAuthorization,
    _CandidateAuthorizationState,
    _capture_preparation_transaction_candidate_state_identities,
    _capture_preparation_transaction_state_identity,
    _PreparationTransactionState,
    _require_preparation_transaction_candidate_state_identities_current,
    _resolve_unprepared_result_authorization,
)

_ELIGIBLE_RETRY_CODES = frozenset({"BACKEND.WORKER_START_FAILED", "BACKEND.WORKER_PROCESS_FAILED"})


@dataclass(frozen=True, repr=False)
class _CandidateExecutionProduct:
    """One finalized candidate retained for coordinator-only ordered persistence."""

    finalized_result: FinalizedResult
    finalized_state: _FinalizedResultState
    cache_lineage: VerifiedCacheLineage | None


def _reject_copy() -> Never:
    raise TypeError("Production executors cannot be copied or serialized.")


@final
class _ProductionExecutor:
    """One-use private executor over exact transaction, invoker, and journal owners."""

    __slots__ = (
        "_candidate_authorization_states",
        "_candidate_authorizations",
        "_invoker",
        "_journal",
        "_journal_state",
        "_max_parallel_workers",
        "_prepared_execution_contexts",
        "_retry_process_failures",
        "_transaction",
        "_transaction_state",
        "_unprepared_execution_states",
        "_used",
    )

    def __init__(
        self,
        transaction: PreparationTransaction,
        invoker: WorkerInvoker,
        journal: ResultPersistenceJournal,
        *,
        retry_process_failures: bool = True,
    ) -> None:
        if type(retry_process_failures) is not bool:
            raise TypeError("Production retry policy must be a closed boolean.")
        self._transaction = transaction
        self._invoker = invoker
        self._journal = journal
        self._journal_state: _ResultPersistenceJournalState | None = None
        self._max_parallel_workers = 0
        self._transaction_state: _PreparationTransactionState | None = None
        self._candidate_authorization_states: tuple[_CandidateAuthorizationState, ...] = ()
        self._candidate_authorizations: tuple[object, ...] = ()
        self._prepared_execution_contexts: dict[PreparedExecutionAuthorization, object] = {}
        self._retry_process_failures = retry_process_failures
        self._unprepared_execution_states: dict[UnpreparedResultAuthorization, object] = {}
        self._used = False
        self._preflight()

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Production executors cannot be subclassed.")

    def __copy__(self) -> _ProductionExecutor:
        _reject_copy()

    def __deepcopy__(self, _memo: object) -> _ProductionExecutor:
        _reject_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_copy()

    def __getstate__(self) -> object:
        _reject_copy()

    def _preflight(self) -> None:
        if (
            type(self._transaction) is not PreparationTransaction
            or type(self._invoker) is not WorkerInvoker
            or type(self._journal) is not ResultPersistenceJournal
        ):
            raise TypeError(
                "Production execution requires exact transaction, invoker, and journal authorities."
            )
        journal_state = _read_result_journal(self._journal)
        transaction_state = _capture_preparation_transaction_state_identity(self._transaction)
        candidate_states = _capture_preparation_transaction_candidate_state_identities(
            transaction_state
        )
        transaction_plan = strict_json_loads(transaction_state.plan_bytes)
        receipt = strict_json_loads(transaction_state.receipt_bytes)
        if type(transaction_plan) is not dict or type(receipt) is not dict:
            raise TypeError("Production execution requires an exact Plan/3 transaction.")
        plan_authorization_state = _read_plan_candidate_authorization(
            journal_state.plan_candidate_authorization
        )
        planned = _plan_candidate_rows(journal_state.plan_candidate_authorization)
        authorizations = transaction_state.candidate_authorizations
        if (
            journal_state.store.attachment_mode != "CREATED_FRESH"
            or journal_state.sealed_terminal_index is not None
            or _candidate_terminal_rows(journal_state.terminal_authorization)
            or transaction_plan["plan_digest"] != plan_authorization_state.plan_digest
            or transaction_plan["budget_decision"]["max_parallel_workers"]
            != plan_authorization_state.max_parallel_workers
            or plan_authorization_state.plan_digest != receipt["plan_digest"]
            or journal_state.preparation_transaction is not self._transaction
            or len(planned) != len(authorizations)
            or len(authorizations) != len(transaction_state.candidate_authorizations)
            or len(authorizations) != len(journal_state.candidate_result_authorizations)
            or any(
                current is not retained
                for current, retained in zip(
                    authorizations,
                    journal_state.candidate_result_authorizations,
                    strict=True,
                )
            )
        ):
            raise TypeError(
                "Production execution requires one fresh exact Plan/3 persistence journal."
            )
        if (
            type(plan_authorization_state.max_parallel_workers) is not int
            or plan_authorization_state.max_parallel_workers <= 0
        ):
            raise TypeError("Production execution requires one positive Plan/3 worker ceiling.")
        for ordinal, (planned_row, authorization, authorization_state) in enumerate(
            zip(planned, authorizations, candidate_states, strict=True)
        ):
            if type(authorization) is PreparedExecutionAuthorization:
                candidate_context = self._invoker._begin_prepared_candidate_execution_from_state(
                    authorization,
                    authorization_state,
                )
                candidate_context_state = _read_prepared_candidate_execution_context(
                    candidate_context
                )
                record = strict_json_loads(
                    candidate_context_state.invocation_context.prepared_state.record_bytes
                )
                self._prepared_execution_contexts[authorization] = candidate_context
            elif type(authorization) is UnpreparedResultAuthorization:
                record = strict_json_loads(authorization_state.record_bytes)
                self._unprepared_execution_states[authorization] = authorization_state
            else:
                raise TypeError("The preparation transaction contains an invalid authority.")
            if (
                type(record) is not dict
                or record["candidate_ordinal"] != ordinal
                or (
                    record["candidate_ordinal"],
                    record["candidate_id"],
                    record["analysis_spec_id"],
                )
                != (
                    planned_row["candidate_ordinal"],
                    planned_row["candidate_id"],
                    planned_row["analysis_spec_id"],
                )
            ):
                raise TypeError(
                    "The persistence journal is detached from the preparation transaction."
                )
        if (
            _capture_preparation_transaction_state_identity(self._transaction)
            is not transaction_state
            or _require_result_journal_state_identity(self._journal, journal_state)
            is not journal_state
        ):
            raise TypeError("Production execution authorities changed during preflight.")
        self._transaction_state = transaction_state
        self._journal_state = journal_state
        self._candidate_authorizations = tuple(authorizations)
        self._candidate_authorization_states = tuple(candidate_states)
        self._max_parallel_workers = plan_authorization_state.max_parallel_workers

    def _assert_execution_authorities_current(self) -> None:
        if (
            self._transaction_state is None
            or self._journal_state is None
            or _capture_preparation_transaction_state_identity(self._transaction)
            is not self._transaction_state
            or _require_result_journal_state_identity(
                self._journal,
                self._journal_state,
            )
            is not self._journal_state
        ):
            raise TypeError("Production execution authorities changed before terminal mutation.")
        _require_preparation_transaction_candidate_state_identities_current(
            self._transaction_state,
            self._candidate_authorization_states,
        )
        for context in self._prepared_execution_contexts.values():
            self._invoker._assert_prepared_candidate_execution_context_current(context)
        for authorization, expected_state in self._unprepared_execution_states.items():
            if _resolve_unprepared_result_authorization(authorization) is not expected_state:
                raise TypeError(
                    "Production execution authorities changed before terminal mutation."
                )

    @staticmethod
    def _worker_evidence(execution: WorkerExecution) -> AuthenticatedWorkerExecutionEvidence:
        evidence = execution.authenticated_execution
        if type(evidence) is not AuthenticatedWorkerExecutionEvidence:
            raise TypeError("Product worker execution lacks exact authenticated evidence.")
        return evidence

    @staticmethod
    def _observed_failure(error: AuditError) -> WorkerInvocationObservation:
        observation = error.invocation_observation
        if type(observation) is not WorkerInvocationObservation:
            raise error
        return observation

    @staticmethod
    def _retry_eligible(evidence: object) -> bool:
        if type(evidence) is not WorkerInvocationObservation:
            return False
        readback = _readback_worker_invocation_observation(evidence)
        return (
            readback.failure_class is InvocationFailureClass.PROCESS_FAILURE
            and readback.failure_code in _ELIGIBLE_RETRY_CODES
        )

    @staticmethod
    def _validation_retry_eligible(evidence: object) -> bool:
        if type(evidence) is not WorkerInvocationObservation:
            return False
        readback = _readback_worker_invocation_observation(evidence)
        return (
            readback.failure_class is InvocationFailureClass.PROCESS_FAILURE
            and readback.failure_code == "BACKEND.WORKER_START_FAILED"
        )

    def _execute_prepared(
        self,
        authorization: PreparedExecutionAuthorization,
    ) -> _CandidateExecutionProduct:
        try:
            candidate_execution_context = self._prepared_execution_contexts[authorization]
        except KeyError:
            raise TypeError("Prepared execution lacks its exact preflight context.") from None
        candidate_execution_state = _read_prepared_candidate_execution_context(
            candidate_execution_context
        )
        prepared_state = candidate_execution_state.invocation_context.prepared_state
        universe = strict_json_loads(prepared_state.universe_bytes)
        if type(universe) is not dict:
            raise TypeError("Prepared candidate execution has no exact universe.")
        chain_plan = universe.get("chain_plan")
        if not isinstance(chain_plan, list) or not chain_plan:
            raise TypeError("Prepared candidate execution has no exact chain plan.")
        started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        started = time.monotonic()
        validation_evidence: AuthenticatedWorkerExecutionEvidence | WorkerInvocationObservation
        try:
            validation_evidence = self._worker_evidence(
                self._invoker._invoke_prepared_validate(candidate_execution_context)
            )
        except AuditError as error:
            validation_evidence = self._observed_failure(error)
        if self._retry_process_failures and self._validation_retry_eligible(
            validation_evidence
        ):
            try:
                validation_evidence = self._worker_evidence(
                    self._invoker._invoke_prepared_validate(candidate_execution_context)
                )
            except AuditError as error:
                validation_evidence = self._observed_failure(error)

        fit_attempts: list[AuthenticatedWorkerExecutionEvidence | WorkerInvocationObservation] = []
        successful_terminals: list[AuthenticatedWorkerExecutionEvidence] = []
        validation_success = (
            type(validation_evidence) is AuthenticatedWorkerExecutionEvidence
            and validation_evidence.status == "SUCCESS"
        )
        if validation_success:
            fit_authorization = self._invoker._authorize_prepared_fit(
                candidate_execution_context,
                validation_evidence,
            )
            for position in range(len(chain_plan)):
                try:
                    initial: AuthenticatedWorkerExecutionEvidence | WorkerInvocationObservation = (
                        self._worker_evidence(
                            self._invoker._invoke_prepared_fit(
                                fit_authorization,
                                chain_plan_position=position,
                                attempt_ordinal=0,
                            )
                        )
                    )
                except AuditError as error:
                    initial = self._observed_failure(error)
                fit_attempts.append(initial)
                terminal = initial
                if self._retry_process_failures and self._retry_eligible(initial):
                    try:
                        retry: (
                            AuthenticatedWorkerExecutionEvidence | WorkerInvocationObservation
                        ) = self._worker_evidence(
                            self._invoker._invoke_prepared_fit(
                                fit_authorization,
                                chain_plan_position=position,
                                attempt_ordinal=1,
                            )
                        )
                    except AuditError as error:
                        retry = self._observed_failure(error)
                    fit_attempts.append(retry)
                    terminal = retry
                if (
                    type(terminal) is AuthenticatedWorkerExecutionEvidence
                    and terminal.status == "SUCCESS"
                ):
                    successful_terminals.append(terminal)
        cache_lineage = None
        if validation_success and len(successful_terminals) == len(chain_plan):
            cache_lineage = _issue_verified_cache_lineage(
                _VERIFIED_CACHE_ISSUER,
                cache_disposition="MISS",
                universe_id=cast(str, universe["universe_id"]),
                fit_execution_evidence=tuple(successful_terminals),
                source_result=None,
            )
        ended_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        runtime_seconds = max(0.0, time.monotonic() - started)
        owner = _issue_prepared_execution_finalization(
            _PREPARED_EXECUTION_FINALIZATION_ISSUER,
            authorization=authorization,
            started_at_utc=started_at,
            ended_at_utc=ended_at,
            runtime_seconds=runtime_seconds,
            validation_evidence=validation_evidence,
            fit_attempt_evidence=tuple(fit_attempts),
            cache_lineage=cache_lineage,
            candidate_execution_context=candidate_execution_context,
        )
        result = finalize_prepared_candidate(
            owner,
            validation_evidence=validation_evidence,
            fit_attempt_evidence=tuple(fit_attempts),
            cache_lineage=cache_lineage,
        )
        finalized_state = _capture_finalized_result_state_identity(result)
        self._invoker._assert_prepared_candidate_execution_context_current(
            candidate_execution_context
        )
        return _CandidateExecutionProduct(
            finalized_result=result,
            finalized_state=finalized_state,
            cache_lineage=cache_lineage,
        )

    def _execute_candidate(self, authorization: object) -> _CandidateExecutionProduct:
        if type(authorization) is PreparedExecutionAuthorization:
            return self._execute_prepared(authorization)
        if type(authorization) is not UnpreparedResultAuthorization:
            raise TypeError("The preparation transaction contains an invalid authority.")
        try:
            authorization_state = self._unprepared_execution_states[authorization]
        except KeyError:
            raise TypeError("Unprepared execution lacks its exact preflight state.") from None
        result = _finalize_unprepared_candidate_with_state(
            authorization,
            authorization_state,
        )
        return _CandidateExecutionProduct(
            finalized_result=result,
            finalized_state=_capture_finalized_result_state_identity(result),
            cache_lineage=None,
        )

    def _persist_candidate(self, product: _CandidateExecutionProduct) -> None:
        self._assert_execution_authorities_current()
        if self._journal_state is None:
            raise TypeError("Production execution has no exact journal state.")
        result = product.finalized_result
        _persisted, finalized_state = _persist_finalized_candidate_with_state_capture(
            self._journal,
            self._journal_state,
            result,
            prevalidated_finalized_state=product.finalized_state,
        )
        if finalized_state.record_kind == "COMPLETED":
            if product.cache_lineage is None:
                raise TypeError("A completed product result lacks exact MISS cache lineage.")
            self._assert_execution_authorities_current()
            _persist_cache_admissible_result_with_state(
                self._journal,
                self._journal_state,
                result,
                product.cache_lineage,
            )

    def _execute_and_persist_candidates(self) -> None:
        """Run a bounded whole-candidate window and consume it in Plan/3 order."""

        if self._max_parallel_workers == 1:
            for authorization in self._candidate_authorizations:
                product = self._execute_candidate(authorization)
                self._persist_candidate(product)
            return
        executor = ThreadPoolExecutor(
            max_workers=self._max_parallel_workers,
            thread_name_prefix="ebm-audit-candidate",
        )
        futures: dict[int, Future[_CandidateExecutionProduct]] = {}
        next_to_submit = 0
        try:
            while (
                next_to_submit < len(self._candidate_authorizations)
                and len(futures) < self._max_parallel_workers
            ):
                futures[next_to_submit] = executor.submit(
                    self._execute_candidate,
                    self._candidate_authorizations[next_to_submit],
                )
                next_to_submit += 1
            for ordinal in range(len(self._candidate_authorizations)):
                future = futures.pop(ordinal)
                product = future.result()
                self._assert_execution_authorities_current()
                self._persist_candidate(product)
                if next_to_submit < len(self._candidate_authorizations):
                    futures[next_to_submit] = executor.submit(
                        self._execute_candidate,
                        self._candidate_authorizations[next_to_submit],
                    )
                    next_to_submit += 1
        except BaseException:
            for future in futures.values():
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            raise
        executor.shutdown(wait=True, cancel_futures=False)

    def execute(self) -> SealedCandidateTerminalIndex:
        if self._used:
            raise TypeError("A production executor is one-use.")
        self._used = True
        self._assert_execution_authorities_current()
        self._execute_and_persist_candidates()
        self._assert_execution_authorities_current()
        if self._journal_state is None:
            raise TypeError("Production execution has no exact journal state.")
        return _seal_candidate_terminal_index_with_state(
            self._journal,
            self._journal_state,
        )


def execute_preparation_transaction(
    transaction: object,
    invoker: object,
    journal: object,
) -> SealedCandidateTerminalIndex:
    """Execute and persist one exact transaction in Plan/3 order, then seal it."""

    if (
        type(transaction) is not PreparationTransaction
        or type(invoker) is not WorkerInvoker
        or type(journal) is not ResultPersistenceJournal
    ):
        raise TypeError(
            "Production execution requires exact transaction, invoker, and journal authorities."
        )
    return _ProductionExecutor(transaction, invoker, journal).execute()


def execute_preparation_transaction_no_retry(
    transaction: object,
    invoker: object,
    journal: object,
) -> SealedCandidateTerminalIndex:
    """Execute one exact transaction while retaining every first terminal as final."""

    if (
        type(transaction) is not PreparationTransaction
        or type(invoker) is not WorkerInvoker
        or type(journal) is not ResultPersistenceJournal
    ):
        raise TypeError(
            "No-retry production execution requires exact transaction, invoker, "
            "and journal authorities."
        )
    return _ProductionExecutor(
        transaction,
        invoker,
        journal,
        retry_process_failures=False,
    ).execute()
