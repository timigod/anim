# Reproduce an audit or recover an interrupted attempt

Use `ebm-audit rerun` to repeat an audit with the same configuration, inputs,
worker and runtime. Recovery after cancellation or failure runs the **whole
plan again**, including analyses that finished before interruption.

```sh
ebm-audit run --config audit.yaml --offline --profile quick --progress
ebm-audit rerun --manifest runs/first.operations/replay.json \
  --config audit.yaml --run-root runs/retry --offline --progress
ebm-audit diff --left runs/first --right runs/retry
```

This example assumes `audit.yaml` sets `output.root` to `runs/first`. An ordinary
`run` saves its replay recipe at `runs/first.operations/replay.json`, beside the
scientific output. Both directories are private. `diff` inspects saved reports;
it requires the report files on both sides, which an interrupted run may lack.

## Keep the original files and use a new output directory

Keep the original configuration, inputs, pinned worker and its environment.
The report's `config.resolved.yaml` is redacted and cannot replace the original
configuration. The replay recipe contains hashes and a profile identifier,
never participant rows, paths or a copy of the private configuration.

`--run-root` is relative to the original configuration directory and must name
a fresh directory. The command creates a temporary private configuration beside
the original and removes only that temporary file when it exits. It never
overwrites previous results.

The `demo` command uses a temporary configuration and does not provide this
recipe. Generator-managed development-null runs (synthetic checks using data
with no signal) also use a separate synthetic replay procedure. For `rerun`,
use an ordinary configuration with saved local input.

## Monitor or stop the new attempt

Use `--memory-budget-mb` with `--worker-memory-mb` to reserve worker capacity and
reduce concurrency. These are declared reservations, not measurements of
resident set size (RSS, memory currently held in RAM) or operating-system memory
limits. They never remove planned analyses, called **candidates**. Progress is
JSON on stderr; the final command result stays on stdout. See
[execution controls](execution.md).

`SIGINT` or `SIGTERM` requests cancellation. Results are saved in plan order,
so a candidate that finished out of order may not yet have been saved. An
interrupted attempt may lack a final report and must not be described as
complete. Earlier result files remain evidence of that attempt; `rerun` does
not load them to resume execution or create a new scientific report.

## Read the attempt status

`attempt-status.json` in the operations directory records one of these states:

| State | Meaning |
| --- | --- |
| `FINISHED` | The ordinary workflow emitted its final result. Read `run-status.json` for the separate scientific status and exit code. |
| `CANCELLED` | Cancellation ended the attempt before completion. |
| `FAILED` | The attempt failed. |
| File missing | The outcome is unknown; interruption or power loss can prevent a status update. |

Neither the recipe nor attempt status is the final scientific manifest. Neither
enables the standalone `report` command, which remains unavailable for saved
scientific evidence.

## Reference: what must match before fitting

The recipe records hashes that identify the parsed configuration, excluding
only the output destination; all verified input and reference files; worker
configuration and identity; randomness specification; selected profile; compiled
plan; and local runtime. `rerun` checks these identities again and rejects
changes before fitting any candidate.

The runtime fingerprint includes Python and platform, installed core dependency
versions, package code, required schema and specification resources, and
numerical thread settings. Worker libraries and the worker's execution
environment must also be covered by the adapter's declared identity. Passing
adapter qualification does not fill gaps in an incomplete identity declaration.

A matching recipe checks reproducibility within these recorded conditions. It
does not establish numerical equivalence across machines or software versions.

## Reference: interpretation limits

All execution and comparison are offline. No telemetry, cloud model or large
language model (LLM) interprets results. Software readiness, worker capability,
robustness evidence and scientific interpretation remain separate assessments.

Anim also keeps six sources of uncertainty separate: variation within a fit,
differences between model-fitting chains, sampling participants, analyst
decisions, participant influence (sensitivity to removing participants), and
null calibration (comparison with results expected without signal). Missing,
failed, invalid and incomparable evidence must not be interpreted as numerical
stability.
