from __future__ import annotations

import threading

import pytest

from ebm_audit.errors import PrivacyViolationError
from ebm_audit.results import persisted_candidate_terminals
from ebm_audit.results.persistence import _read_result_journal, _result_path
from ebm_audit.runner import (
    ExecutionCancelled,
    ExecutionControl,
    ExecutionPhase,
    MemoryAdmissionError,
    execute_preparation_transaction,
    execute_preparation_transaction_no_retry,
)
from ebm_audit.runner.execution import _ProductionExecutor


def test_out_of_order_completion_persists_in_plan_order(synthetic_execution, monkeypatch):
    transaction, invoker, journal, plan, _store = synthetic_execution
    second_finished = threading.Event()
    finished = []
    original = _ProductionExecutor._execute_candidate

    def reordered(self, authorization):
        ordinal = self._candidate_authorizations.index(authorization)
        if ordinal == 0:
            assert second_finished.wait(30)
        product = original(self, authorization)
        finished.append(ordinal)
        if ordinal == 1:
            second_finished.set()
        return product

    monkeypatch.setattr(_ProductionExecutor, "_execute_candidate", reordered)
    progress = []
    control = ExecutionControl(progress_callback=progress.append)
    execute_preparation_transaction(transaction, invoker, journal, control=control)
    rows = persisted_candidate_terminals(journal)
    assert len(rows) == 3
    assert finished[:2] == [1, 0]
    assert [row["candidate_id"] for row in rows] == [
        row["candidate_id"] for row in plan["candidates"]
    ]
    assert [row["candidate_ordinal"] for row in rows] == [0, 1, 2]
    # Neither an unsupported preparation nor a worker's typed rejection may
    # disappear from the plan. Only the baseline is admissible for validation.
    assert [row["final_status"] for row in rows] == [
        "UNSUPPORTED_CAPABILITY", "INVALID_INPUT", "UNSUPPORTED_CAPABILITY"
    ]
    assert progress[-1].phase is ExecutionPhase.COMPLETED
    assert progress[-1].persisted_candidates == 3
    assert all(p.submitted_candidates - p.persisted_candidates <= 2 for p in progress)
    assert [p.persisted_candidates for p in progress] == sorted(
        p.persisted_candidates for p in progress
    )
    # Existing evidence cannot be promoted back to a fresh execution journal.
    with pytest.raises(TypeError, match="fresh exact Plan/3"):
        execute_preparation_transaction(transaction, invoker, journal)


def test_admission_reduces_concurrency_without_dropping_candidates(synthetic_execution):
    transaction, invoker, journal, plan, _store = synthetic_execution
    progress = []
    control = ExecutionControl(
        progress_callback=progress.append,
        memory_budget_bytes=150,
        per_worker_memory_bytes=100,
    )
    execute_preparation_transaction_no_retry(transaction, invoker, journal, control=control)
    rows = persisted_candidate_terminals(journal)
    assert len(rows) == len(plan["candidates"]) == 3
    assert [row["candidate_id"] for row in rows] == [
        row["candidate_id"] for row in plan["candidates"]
    ]
    assert [row["final_status"] for row in rows] == [
        "UNSUPPORTED_CAPABILITY", "INVALID_INPUT", "UNSUPPORTED_CAPABILITY"
    ]
    assert all(p.effective_parallel_workers == 1 for p in progress)
    assert all(p.submitted_candidates - p.persisted_candidates <= 1 for p in progress)
    assert plan["budget_decision"]["max_parallel_workers"] == 2


def test_admission_rejection_leaves_plan_and_empty_journal(synthetic_execution, monkeypatch):
    transaction, invoker, journal, plan, _store = synthetic_execution

    def forbidden(*_args, **_kwargs):
        pytest.fail("An inadmissible attempt must never execute a candidate.")

    monkeypatch.setattr(_ProductionExecutor, "_execute_candidate", forbidden)
    progress = []
    control = ExecutionControl(
        progress_callback=progress.append,
        memory_budget_bytes=99,
        per_worker_memory_bytes=100,
    )
    with pytest.raises(MemoryAdmissionError) as caught:
        execute_preparation_transaction(transaction, invoker, journal, control=control)
    assert caught.value.code == "EXECUTION.MEMORY_ADMISSION_REJECTED"
    assert persisted_candidate_terminals(journal) == ()
    assert _read_result_journal(journal).sealed_terminal_index is None
    assert len(plan["candidates"]) == 3
    assert progress[-1].phase is ExecutionPhase.ADMISSION_REJECTED
    assert progress[-1].submitted_candidates == 0


@pytest.mark.parametrize("parallel", [False, True])
def test_cancellation_preserves_persisted_prefix_and_fresh_contract(
    synthetic_execution, parallel
):
    transaction, invoker, journal, plan, store = synthetic_execution
    snapshots = {}
    progress = []

    def observe(event):
        progress.append(event)
        if event.persisted_candidates == 1:
            for row in persisted_candidate_terminals(journal):
                relative = _result_path(row["candidate_ordinal"])
                snapshots[relative] = store.read_bytes(relative)
            control.request_cancel()

    control = ExecutionControl(
        progress_callback=observe,
        memory_budget_bytes=200 if parallel else 100,
        per_worker_memory_bytes=100,
    )
    with pytest.raises(ExecutionCancelled) as caught:
        execute_preparation_transaction(transaction, invoker, journal, control=control)
    assert caught.value.code == "EXECUTION.CANCELLED"
    assert caught.value.details["persisted_candidates"] == 1
    assert caught.value.invocation_observation is None
    assert caught.value.__context__ is None
    assert progress[-1].phase is ExecutionPhase.CANCELLED
    rows = persisted_candidate_terminals(journal)
    assert len(rows) == 1
    assert len(plan["candidates"]) == 3
    assert rows[0]["final_status"] == "UNSUPPORTED_CAPABILITY"
    assert _read_result_journal(journal).sealed_terminal_index is None
    assert snapshots
    for relative, content in snapshots.items():
        assert store.read_bytes(relative) == content
    with pytest.raises(TypeError, match="fresh exact Plan/3"):
        execute_preparation_transaction(transaction, invoker, journal)


@pytest.mark.parametrize("synthetic_execution", [True], indirect=True)
def test_successful_fresh_fit_with_control(synthetic_execution):
    transaction, invoker, journal, plan, _store = synthetic_execution
    progress = []
    control = ExecutionControl(progress_callback=progress.append)
    execute_preparation_transaction(transaction, invoker, journal, control=control)
    rows = persisted_candidate_terminals(journal)
    assert len(rows) == len(plan["candidates"]) == 1
    assert rows[0]["final_status"] == "SUCCESS"
    state = _read_result_journal(journal)
    assert state.sealed_terminal_index is not None
    assert len(state.persisted_cache_results) == 1
    assert progress[-1].phase is ExecutionPhase.COMPLETED
    assert control.progress_callback_failures == 0


@pytest.mark.parametrize("synthetic_execution", [True], indirect=True)
def test_cancellation_keeps_a_successful_persisted_fit_unsealed(synthetic_execution):
    transaction, invoker, journal, _plan, store = synthetic_execution
    persisted = []

    def observe(progress):
        if progress.persisted_candidates == 1:
            persisted.append(store.read_bytes(_result_path(0)))
            control.request_cancel()

    control = ExecutionControl(progress_callback=observe)
    with pytest.raises(ExecutionCancelled):
        execute_preparation_transaction(transaction, invoker, journal, control=control)
    assert persisted_candidate_terminals(journal)[0]["final_status"] == "SUCCESS"
    assert _read_result_journal(journal).sealed_terminal_index is None
    assert persisted and all(content == persisted[0] for content in persisted)
    assert store.read_bytes(_result_path(0)) == persisted[0]
    assert control.progress_callback_failures == 0


def test_cancellation_does_not_hide_sibling_cleanup_failure(synthetic_execution, monkeypatch):
    transaction, invoker, journal, _plan, _store = synthetic_execution
    sibling_started = threading.Event()
    original = _ProductionExecutor._execute_candidate
    control = ExecutionControl()

    def execute(self, authorization):
        ordinal = self._candidate_authorizations.index(authorization)
        if ordinal == 1:
            sibling_started.set()
            raise PrivacyViolationError(
                "PRIVACY.SUBPROCESS_CLEANUP_FAILED",
                "A worker subprocess could not be terminated inside its process boundary.",
            )
        assert sibling_started.wait(5)
        control.request_cancel()
        return original(self, authorization)

    monkeypatch.setattr(_ProductionExecutor, "_execute_candidate", execute)
    with pytest.raises(PrivacyViolationError) as caught:
        execute_preparation_transaction(transaction, invoker, journal, control=control)
    assert caught.value.code == "PRIVACY.SUBPROCESS_CLEANUP_FAILED"
    assert _read_result_journal(journal).sealed_terminal_index is None


def test_control_cannot_replace_authority():
    with pytest.raises(TypeError, match="exact transaction"):
        execute_preparation_transaction(object(), object(), object(), control=ExecutionControl())
