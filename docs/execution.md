# Monitor and stop long runs

Use `--progress` to monitor a run and the two memory options to limit how many
analyses run at once:

```sh
ebm-audit run --config audit.yaml --offline --progress \
  --memory-budget-mb 4096 --worker-memory-mb 1024
```

An Anim plan lists the analyses to attempt. Each is called a **candidate**; a
**universe** records the prepared data, settings and seeds for an analysis that
can proceed. Anim schedules whole candidates, up to the plan's
`max_parallel_workers` limit. They may finish out of order, but their results
are saved in plan order.

## Read progress

`--progress` writes JSON to stderr. Each event contains a phase and four counts:

- `planned_candidates`: analyses in the original plan.
- `submitted_candidates`: candidates submitted for execution.
- `persisted_candidates`: candidate results saved so far, in plan order.
- `effective_parallel_workers`: the current concurrency limit.

`RUNNING` describes scheduling and saved results; it does not estimate time
remaining. `COMPLETED` means every planned candidate has a final recorded
outcome. Some outcomes can still be scientific failures, and report creation
can still fail after execution completes.

## Reserve worker memory

Both memory arguments use MiB (1,048,576 bytes). Supply them together as positive
integers, or omit both to keep the plan's original concurrency limit. The
effective limit is:

```text
min(planned worker ceiling, floor(memory budget / per-worker reservation))
```

The reservation is your estimate of memory needed per worker. Anim uses it to
decide how many candidates to run together; it does not measure memory use or
enforce an operating-system limit on resident set size (RSS, memory currently
held in RAM). Leave additional memory for input preparation, the coordinator
that schedules and saves results, worker description, and other system
processes.

If one worker's reservation exceeds the entire budget, execution is rejected
with `EXECUTION.MEMORY_ADMISSION_REJECTED` (exit 10). Anim never removes planned
candidates to fit the budget.

## Cancel and rerun

Press Ctrl-C (`SIGINT`) or send `SIGTERM` to request cancellation. Anim stops
submitting candidates and asks active worker invocations to stop. Cancellation
is cooperative: it takes effect when the running operation next checks the
request.

`EXECUTION.CANCELLED` (exit 12) means the attempt is incomplete. Already saved
candidate results remain byte-for-byte intact. Anim does not mark the attempt
complete or invent results for unfinished candidates. A result that finished
out of order may not yet have been saved.

Use [`ebm-audit rerun`](reproducibility.md) to recover. It checks the saved input,
configuration, worker and environment identities, then executes the **entire
original plan again** in a new output directory. It does not resume from the
last saved candidate. The original results remain available for inspection.

## Reference: cancellation and result handling

Active invocations check for cancellation at their next process-wait poll
(50 ms). Each invocation sends `SIGTERM` to its new process group, allows 250 ms
for the leader to exit, then escalates to `SIGKILL` with a further 500 ms wait.
Remaining descendant processes use the same cleanup procedure with fixed time
limits. The coordinator waits for worker threads to finish cleanup before
returning. If cleanup cannot be verified, the existing privacy error is returned
with its exact code and safe message; cancellation does not hide it.

These intervals do not guarantee a total cancellation time. Checks occur
between candidate and invocation operations. Local Python preparation,
response verification, persistence and caller callbacks must reach their next
check before cancellation can take effect. `SIGKILL` and machine failure cannot
perform graceful cleanup or guarantee an attempt-status update.

Cancellation is an operational outcome, not a worker failure or timeout, and
cannot serve as evidence of a scientific worker invocation. The original plan
defines all required work. Replay and attempt-status records are stored beside
the scientific output in `<run-name>.operations/`.

Saved results cannot be loaded as the live, verified objects required to execute
or create a scientific report. The production executor rejects an already
populated journal, a reopened result store or a transaction that was not
validated in the current process.

Execution controls do not change candidate membership, identities, seeds,
retry eligibility, readiness definitions or scientific acceptance rules. Worker
failures and unsupported preparation results keep their specific scientific
status and error types.

## Reference: Python integration

The example assumes the application has already created `transaction`, `invoker`
and `journal` for this attempt. They must be the validated in-process objects
for a fresh run, rather than objects reconstructed from saved results.

```python
from ebm_audit.runner import ExecutionControl, execute_preparation_transaction

control = ExecutionControl(
    progress_callback=lambda event: print(event.phase, event.counts()),
    memory_budget_bytes=4 * 1024**3,
    per_worker_memory_bytes=1024**3,
)

# Use transaction, invoker and journal objects validated for this fresh run.
with control.signal_handlers():
    terminal_index = execute_preparation_transaction(
        transaction, invoker, journal, control=control
    )
```

`execute_preparation_transaction_no_retry` accepts the same optional `control=`
argument. `WorkerInvoker(..., execution_control=control)` also makes standalone
worker invocations cancellable. When both invoker and coordinator receive a
control, they must receive the same object. The workflow entry point is
`ebm_audit.cli_workflows.run_audit(..., execution_control=control)`.

An embedding application can call `control.request_cancel()` from another
thread. Signal handlers are optional and can only be installed on the main
thread; the context restores the previous handlers on exit. Use a new control
for each attempt because cancellation is permanent for that object.

Progress callbacks run synchronously on the coordinator and must return
promptly. Events are immutable `ExecutionProgress` dataclasses with an
`ExecutionPhase` string enum, so `dataclasses.asdict(event)` is JSON serializable.
`event.counts()` returns the four counts listed above.

Ordinary callback exceptions are discarded and counted in
`control.progress_callback_failures`. They do not change execution outcomes or
expose arbitrary exception text. Callbacks should only observe or request
cancellation; they should not mutate the objects used to execute and verify the
run.
