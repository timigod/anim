# Anim

Anim is local research software that checks whether an event-based model (EBM)
result changes when you run predeclared, scientifically reasonable alternatives.
You connect your EBM as a local worker. Anim does not import, select, download,
certify, or silently replace your model.

It is **not** a diagnostic, prognostic, treatment, causal, regulatory, or
medical-device tool. An emitted event order is not evidence that a recoverable
disease-order signal exists.

Development version: **0.2.0.dev0** (unreleased). The immutable public release
is **0.1.1**; installing from PyPI does not install this development checkout.

## Installation

The published Anim 0.1.1 requires CPython 3.12:

```sh
python3.12 -m pip install 'anim==0.1.1'
ebm-audit doctor
```

Anim 0.1.1 installs and runs `doctor` on macOS and Linux. Worker execution uses
the reviewed Seatbelt path on macOS. On Linux, it uses `/usr/bin/bwrap` when
Bubblewrap is installed and otherwise fails closed with
`PRIVACY.CONTAINMENT_UNAVAILABLE`. The 0.1.1 release does not claim full Linux
worker-execution support.

For development version 0.2.0.dev0 from this source checkout (CPython 3.12):

```sh
python3.12 --version
uv sync --frozen
uv run ebm-audit doctor
```

The development compatibility matrix covers CPython 3.12 on macOS and Linux.
macOS worker execution requires Seatbelt; Linux requires a working Bubblewrap
installation at `/usr/bin/bwrap` with namespaces enabled. Without a provider,
worker execution fails closed. Windows execution and other Python minors are
unsupported; no compatibility widening is claimed.

See the [packaging validation runbook](docs/handoff/packaging-validation.md) for
fresh wheel installation, enforced offline synthetic smoke, and the CI matrix.

## Smallest Runnable Example

Run the project-owned synthetic demo before opening or connecting any
participant data:

```sh
ebm-audit demo --conformance-ebm
```

It runs offline and uses only synthetic project-owned data. Its expected bounded
outcome is `PARTIAL` with an `INCOMPLETE` report at
`ebm-audit-demo/report/`. That result exercises the worker and report paths.
It is not scientific validation and does not accept a backend.

For a transferred offline kit, follow the
[offline kit guide](https://github.com/timigod/anim/blob/main/docs/handoff/offline-kit-verification.md). Its installed
command can be run from the supplied virtual environment:

```sh
cd "$PROOF_ROOT" || exit 1
"$VENV_ROOT/bin/ebm-audit" demo --conformance-ebm
```

1. Open `ebm-audit-demo/report/report.html` locally and inspect the matching
    `ebm-audit-demo/report/report.json`,
    `ebm-audit-demo/report/universes.csv`, and
    `ebm-audit-demo/warnings.jsonl` files. Inspect `warnings.jsonl` for
    visible cautions and diagnostics.
2. Read [How the synthetic route works](https://github.com/timigod/anim/blob/main/docs/how-it-works.md) before changing a
    worker. It follows a deliberately tiny two-event synthetic example from a
    request shape to the visible audit artifacts.
3. To start a researcher-owned worker project, run
    `ebm-audit adapter init /approved/local-config/my-ebm-worker`, then
    follow the generated `README.md`. The generated backend is a
    `SYNTHETIC-ONLY` transport example, not an EBM.
4. If the model lives in a private Jupyter notebook, follow the
   [frozen notebook handoff](https://github.com/timigod/anim/blob/main/docs/handoff/frozen-notebook-handoff.md). The
   notebook and data remain private and local.

## Development workflow

Version 0.2.0.dev0 adds local worker pinning and capability checks, saved-run
summaries and comparisons, and fresh-attempt replay with progress and memory
admission. Start with the synthetic demo above; inspect its saved evidence with:

```sh
ebm-audit summary --run-dir ebm-audit-demo
```

Use the [adapter runbook](docs/handoff/adapter-runbook.md) for `adapter pin`,
`adapter check`, and the separately provisioned synthetic-only open-source EBM
example. Software dependencies and public source code are prepared explicitly;
audit runtime remains offline, with no telemetry or LLM interpretation.

For ordinary configured runs, [reproduction and recovery](docs/reproducibility.md)
explains `rerun` and its refusal of identity drift. Replay recipes live beside
sealed results in `<run-name>.operations/`; the ephemeral demo has no recipe.
[Execution controls](docs/execution.md) describes cancellation, JSON progress on
stderr, and memory reservations that limit concurrency without dropping planned
candidates. Reservations are not measured RSS or an OS memory cap.

[Report comparison](docs/report-comparison.md) explains `summary` and `diff`.
Missing, invalid, failed and incomparable evidence remains explicit. A successful
software operation does not make its scientific result complete or valid.

## What The Audit Checks

For evidence that a worker can actually supply, the auditor keeps these
questions separate:

- How much order or stage uncertainty exists within one fit.
- How much results change across independent chains or seeds.
- How sampling, declared analyst decisions, and participant removal change it.
- Whether synthetic no-signal controls show an apparent result when they should
  not.
- Whether a worker omitted a capability, failed, or returned invalid evidence.

An emitted order is not proof that a disease-order signal is recoverable. The
auditor makes sensitivity and missing evidence visible; it does not diagnose,
predict, recommend treatment, or establish a causal result.

## Read Next

| Need | Read |
| --- | --- |
| See the end-to-end synthetic route and public Fit SDK | [How the synthetic route works](https://github.com/timigod/anim/blob/main/docs/how-it-works.md) |
| Build a local worker around an EBM | [Custom worker guide](https://github.com/timigod/anim/blob/main/docs/handoff/custom-worker-guide.md) |
| Preserve a private Jupyter baseline | [Frozen notebook handoff](https://github.com/timigod/anim/blob/main/docs/handoff/frozen-notebook-handoff.md) |
| Understand accepted input and privacy rules | [Input-data dictionary](https://github.com/timigod/anim/blob/main/docs/handoff/input-data-dictionary.md) |
| Understand the optional real-data handoff and current report limit | [Optional downstream real-data integration](https://github.com/timigod/anim/blob/main/docs/handoff/real-data-integration.md) |
| Verify a transferred offline kit instead of using this checkout | [Offline kit verification](https://github.com/timigod/anim/blob/main/docs/handoff/offline-kit-verification.md) |
| Read the exact worker wire contract | [Worker protocol schema](https://github.com/timigod/anim/blob/main/schemas/worker-protocol.schema.json) and [canonical records schema](https://github.com/timigod/anim/blob/main/schemas/canonical-records.schema.json) |
| Read the readiness claim boundary | [EBM integration readiness contract](https://github.com/timigod/anim/blob/main/docs/spec/ebm-integration-readiness.md) |
| Read the execution-boundary specification | [Adapter protocol](https://github.com/timigod/anim/blob/main/docs/spec/adapter-protocol.md) |
| Read report and claim wording rules | [Reporting and claim language](https://github.com/timigod/anim/blob/main/docs/spec/reporting-and-claim-language.md) |

Do not copy participant rows, private column names, raw values, reversible
mappings, or local paths into this repository, reports, tickets, chat, or a
corpus note. A real-data integration is optional downstream work that needs its
own local permission, privacy review, scientific review, and worker evidence.

The supported public integration surface is the `ebm-audit` CLI and the Python
package `ebm_audit.worker_sdk`. `cli_workflows` and reporting modules are
auditor internals, not alternate worker-integration APIs.

### Read the result states

- Warnings are visible cautions or diagnostics, not automatic failure or
  permission to ignore a scientific gate.
- `UNSUPPORTED_CAPABILITY` means the worker cannot perform a requested output.
  It is an explicit non-success universe, not missing evidence and not a pass.
- `UNAVAILABLE` in the training-stage status fields means required evidence
  cannot be supplied. It remains visible. It is neither pass nor fail.
- `NOT_APPLICABLE` in the training-stage status fields means evidence is outside
  the declared capability or analysis scope. It remains visible. It is neither
  pass nor fail.
- Inspect `capability_evidence.training_stage.posterior.status`,
  `capability_evidence.training_stage.hard_stage.status`, and
  `capability_evidence.training_stage.expected_stage.status` for the declared
  training-stage capability state.
- Failed universes remain visible with their terminal `final_status` in
  `candidate_records[].final_status` and `ebm-audit-demo/report/universes.csv`.
  Do not silently drop them or interpret them as successful scientific evidence.

### What this `PARTIAL`/`INCOMPLETE` result can establish

A `PARTIAL`/`INCOMPLETE` audit supports only the visible protocol and
capability-limited synthetic evidence actually present in its report. It does
not establish a recoverable disease-order signal, scientific validity,
diagnosis, prognosis, treatment, or causal claims. Unavailable evidence remains
missing and is neither pass nor fail. Product readiness and worker integration do
not certify `pysaebm`, PySuStaIn, or any named or future EBM backend.

## Status And Authority

The only product-readiness state is:

```text
READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY
```

The backend-neutral integration and local audit path has completed the project's
synthetic readiness review. This is software readiness, not scientific approval
of an EBM or dataset.

It means a researcher can connect a local EBM worker and run the auditor without
the original developer's help. It does not accept a named backend, validate an
untested integration, establish a disease-order signal, or authorize
participant-data use. The exact claim boundary is the normative
[EBM integration readiness contract](https://github.com/timigod/anim/blob/main/docs/spec/ebm-integration-readiness.md).

See the [0.1.1 changelog](https://github.com/timigod/anim/blob/main/CHANGELOG.md) for the public release scope.

Anim is licensed under the [Apache License 2.0](https://github.com/timigod/anim/blob/main/LICENSE).
