# Reproduce an audit or recover an interrupted attempt

An ordinary `ebm-audit run` saves a local replay recipe beside its scientific
output. If `output.root` is `runs/first`, the recipe is
`runs/first.operations/replay.json`. Both directories are private. The recipe
contains hashes and a profile identifier, never participant rows, paths, or a
copy of the private configuration.

```sh
ebm-audit run --config audit.yaml --offline --profile quick --progress
ebm-audit rerun --manifest runs/first.operations/replay.json \
  --config audit.yaml --run-root runs/retry --offline --progress
ebm-audit diff --left runs/first --right runs/retry
```

Keep the original configuration, inputs, pinned worker and its environment.
`config.resolved.yaml` in the report is redacted and cannot replace the original.
`--run-root` is relative to the original configuration directory and must be
fresh. The command makes a temporary private sibling configuration and removes
only that temporary file when it exits. It never overwrites previous results.

The recipe binds parsed configuration (excluding only the output destination),
all verified input and reference files, worker configuration and identity,
randomness specification, selected profile, compiled plan, and local runtime.
The runtime fingerprint includes Python/platform, installed core dependency
versions, package code, normative resources, and numerical thread settings.
Changes are rejected before fitting. Worker libraries and execution environment
are also subject to the adapter's declared identity; qualification does not make
an incomplete worker identity complete. A matching recipe is a reproducibility
check, not a claim of cross-machine or cross-version numerical equivalence.

The same command recovers from cancellation or a process failure by executing a
**fresh complete attempt**. It validates all identities again and refits all
planned candidates. Existing result files remain useful evidence of the earlier
attempt; they are never loaded as trusted live scientific authorities. Completed
results are persisted in plan order. SIGINT or SIGTERM requests cancellation;
an interrupted run may lack a final report and must not be described as complete.

`attempt-status.json` in the operations directory distinguishes `FINISHED`,
`CANCELLED`, and `FAILED`. `FINISHED` means the ordinary workflow emitted its
terminal result; read `run-status.json` for its separate scientific status and
exit code. Missing attempt status means interruption or an unknown disposition,
including power loss. Neither recipe nor attempt status is the frozen final
scientific manifest, and neither reopens the standalone `report` command.
The ephemeral `demo` command and generator-owned development-null runs do not
advertise this recipe. Development-null retains its separate synthetic replay
contract. Use an ordinary configuration with saved local input for `rerun`.

Use `--memory-budget-mb` with `--worker-memory-mb` to reserve worker capacity and
reduce concurrency. These are admission reservations, not measured RSS or an OS
memory limit. They never remove planned candidates. Progress is JSON on stderr;
the final command result stays on stdout. See [execution controls](execution.md).

All execution and comparison are offline. No telemetry, cloud model, or LLM
interprets results. Software readiness, worker capability, robustness evidence,
and scientific interpretation are separate claims. Sampling, chain, analyst
decision, participant, and null uncertainty remain distinct; missing, failed,
invalid and incomparable evidence must not be converted into numerical stability.
