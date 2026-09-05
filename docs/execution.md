# Operating long executions

Anim executes a bounded window of whole candidates. The plan's
`max_parallel_workers` is the ceiling. Candidates may finish out of order, but
the coordinator persists their genuine results in plan order. Prepared worker
failures and unsupported preparation results retain their scientific types.
Operational controls do not change candidate membership, identities, seeds,
retry eligibility, readiness definitions or scientific acceptance rules.

## Progress and memory admission

```sh
ebm-audit run --config audit.yaml --offline --progress \
  --memory-budget-mb 4096 --worker-memory-mb 1024
```

Both memory arguments use MiB (1,048,576 bytes) and must be supplied together as
positive integers. Effective concurrency is:

```text
min(planned worker ceiling, floor(memory budget / per-worker reservation))
```

A reservation that exceeds the entire budget rejects candidate execution with
`EXECUTION.MEMORY_ADMISSION_REJECTED` (exit 10). No planned candidates are removed
to make a run fit. The reservation is an explicit admission estimate, not a
measured memory footprint or an enforced operating-system RSS limit. It covers
the candidate worker window; input preparation, coordinator memory, worker
description and other system processes need their own headroom. Omitting both
arguments preserves the plan's original concurrency ceiling.

`--progress` writes JSON to stderr. Its payload contains only a closed phase and
counts: planned, submitted and persisted candidates, plus effective parallel
workers. `RUNNING` counts describe scheduling and durable persistence, not an
estimate of completion time. `COMPLETED` means the runner sealed full terminal
coverage; candidates can still have typed scientific failures and later report
assembly can still fail.

## Cancellation and recovery

On the CLI, SIGINT (Ctrl-C) and SIGTERM request cooperative cancellation. The
coordinator stops submitting candidates; active invocations check the flag at
their next process-wait poll (50 ms). Each invocation stops its fresh process
group with SIGTERM, allows 250 ms for the leader to exit, then escalates to
SIGKILL with a further 500 ms wait. Residual descendants use the same existing
bounded cleanup path. The coordinator waits for its worker threads to finish
cleanup before returning. A failure to verify cleanup remains the exact safe
privacy error; it is not hidden by cancellation.

Cancellation is checked between candidate and invocation operations. Local
Python preparation, response verification, persistence and caller callbacks
are cooperative boundaries, so these cleanup intervals are not an end-to-end
wall-clock guarantee. SIGKILL and machine failure cannot perform graceful
cleanup or guarantee an attempt-status update.

`EXECUTION.CANCELLED` (exit 12) is an incomplete attempt outcome, not a fabricated
worker failure or timeout. It has no scientific invocation-observation authority.
Persisted candidate results remain byte-for-byte intact. The attempt is not
sealed, and no terminal results are invented for unfinished candidates. A
later candidate that finished ahead of the durable prefix may need to be run
again. The full original plan remains the reference for missing work.

The workflow keeps operational replay and attempt-status records beside the
scientific output in `<run-name>.operations/`. Recovery validates saved input,
configuration, worker and environment identities, then starts a new attempt
with a new output root. It never rehydrates persisted results into live
scientific authorities. The production executor still refuses a previously
populated journal, a reopened store or an unauthenticated transaction.

## Python integration

```python
from ebm_audit.runner import ExecutionControl, execute_preparation_transaction

control = ExecutionControl(
    progress_callback=lambda event: print(event.phase, event.counts()),
    memory_budget_bytes=4 * 1024**3,
    per_worker_memory_bytes=1024**3,
)

# transaction, invoker and journal must be genuine, fresh in-process owners.
with control.signal_handlers():
    terminal_index = execute_preparation_transaction(
        transaction, invoker, journal, control=control
    )
```

The no-retry executor accepts the same optional `control=` argument.
`WorkerInvoker(..., execution_control=control)` also makes standalone worker
invocations cancellable. When both invoker and coordinator receive a control,
they must receive the same object. `run_audit(..., execution_control=control)`
is the workflow entry point.

An embedding application can call `control.request_cancel()` from another
thread. Installing signal handlers is optional and main-thread-only; the
context restores previous handlers on exit. Use a new control for each attempt:
cancellation is permanent for that object.

Progress callbacks run synchronously on the coordinator and must return
promptly. Events are immutable `ExecutionProgress` dataclasses with an
`ExecutionPhase` string enum, so `dataclasses.asdict(event)` is JSON serializable.
Ordinary callback exceptions are discarded and counted in
`control.progress_callback_failures`, preserving execution outcomes and avoiding
the exposure of arbitrary exception text. Callbacks should only observe or
request cancellation, and should not mutate execution authorities.
