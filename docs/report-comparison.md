# Inspecting and comparing local reports

```sh
ebm-audit summary --run-dir ./run-a
ebm-audit diff --left ./run-a --right ./run-b
```

These offline commands inspect saved artifacts. They do not execute a worker,
load participant-level result arrays, contact a service, or rehydrate scientific
authority. `ebm-audit report` remains disabled for persisted scientific evidence.
An `UNCHANGED` comparison means the inspected values and states match; it is not
a finding of scientific stability. Two unavailable measurements remain unavailable.

`summary` requires a complete run directory with a schema-valid `run-status.json`
and `report/report.json`. It verifies the publication inventory digest, the
length and SHA-256 of every report artifact, and joins the report to the status by
plan, terminal-index and scientific-evidence identities. Candidate identities,
ordinals, individual terminal states and counts must agree. The bound scientific
projection supplies ordered event identities and existing within-fit/chain
metrics that are absent from the report's shorter candidate table.

Native central orders are read separately from canonical result JSON whose
schema, self-hash, publication hash, candidate/status and event identity all
match. Participant arrays are never loaded from their referenced files or
included in output. `objective_orders` and `objective_order_distances` preserve
each native chain order separately; retained-state modal order uncertainty is
not inferred from them. Strict Kendall and footrule distances reuse the existing
metrics only when candidates, chain positions, event sets and methods match.
Event-direction semantics must also match; equal event names alone do not make
opposite-direction definitions comparable.
Declared versus authenticated input classification is retained separately:
ordinary declared-synthetic input can correctly remain `PRIVATE_LOCAL_INPUT`
in the scientific report without the project's synthetic-provenance authority.

Inspection rejects symbolic links in any path component, non-regular files,
malformed JSON, duplicate JSON keys, non-finite JSON numbers, unsupported schemas,
and detached or changed artifacts. Reads are limited to 16 MiB per artifact and
64 MiB per inspection, with 200,000 JSON nodes, nesting depth 48, and 10,000
candidates. Larger runs are explicitly refused rather than partially summarized.
Errors contain a fixed code and message, without rejected values or paths.

Only packaged enum tokens, numeric values, nulls and hashed identities are
projected. Arbitrary event names, choice labels, prose and dictionary keys cannot
appear in the new command output or decision panel. Event identity hashes preserve
sequence order. These unsalted hashes are identifiers, not an anonymization or
confidentiality guarantee. Treat the full original run as private local evidence.

The sibling `<run-name>.operations/replay.json`, when present, is checked using
its bounded loader, self-hash, plan digest and source run identity. Its nonsecret
input/configuration/worker/randomness/environment bindings are compared separately.
Missing metadata is `MISSING_REPLAY_BINDINGS`; an invalid existing sidecar fails
inspection. Attempt lineage and run-specific provenance changes do not turn
identical metric values into scientific movement.

The comparison retains candidate additions/removals and individual status swaps,
ordered events, numeric deltas, stage aggregate values and comparability states,
all six uncertainty layers, their `implementation_status`, and capability states.
Provenance differences are reported separately. Changed candidate membership or
event/stage semantics is marked `NOT_COMPARABLE`; it is not silently treated as
a like-for-like numeric experiment. Existing `NOT_ASSESSABLE`, failed, invalid
and unavailable states remain visible in each side's projections and summary.

Local hashes establish consistency with the saved status, not cryptographic
authenticity against someone rewriting the whole directory and its hashes.
Inspection never issues scientific capabilities, unlocks validated language,
reclassifies an incomplete report, or changes a frozen contract.

## The opening HTML summary

New live reports include a decision panel above the detailed sections. It uses
the existing comparison metrics to show, separately for each uncertainty layer:

- How many order/stage comparisons had exactly zero difference, differed, or
  were unavailable, and the range of their reported magnitudes.
- Declared choices associated with those comparisons, using local `Decision 1 /
  Option 1` aliases and expandable full hashed identities.
- Software execution, baseline reproduction, worker capability and scientific
  completion as separate assessments, with implementation and missing states.
- Null calibration and the explicit caveat that stable or concentrated outputs
  can occur with no signal.

An additional native-order panel shows descriptive objective-order comparisons
on literal declared-choice edges, when both fits succeeded with exactly one
native order and matching semantics. Multiple-chain results are not reduced to
a selected chain. Its `objective_summary` projection is separate from scientific
uncertainty. This panel is built from existing live sealed result owners during
report creation; saved inspection never issues those owners. The frozen report
JSON schema is unchanged.

Zero versus positive distance is a descriptive display rule, not a new scientific
stability threshold. Signed means, stage agreement and other measures without a
zero-distance interpretation are displayed only as magnitudes. Different metric
units, operation families and uncertainty layers are never pooled. Association
does not establish a cause. Detailed JSON, CSV and HTML evidence remains available.

## Focused synthetic verification

```sh
.venv/bin/pytest -q tests/reporting --basetemp=tmp/reporting-tests
```

The tests generate three genuine synthetic conformance CLI runs and exercise
summary/diff, matching inputs, changed capabilities, typed missing states and the
new HTML panel. Synthetic artifact copies test status swaps, ordered values,
numeric changes, tampering, schema errors, bounded reads, symbolic links, FIFOs
and private-string canaries. Mutated fixtures are inspection tests, never evidence
of scientific issuance or baseline reproduction. No historical evaluator suite
or upstream participant dataset is involved.

An additional ordinary CLI test uses the existing custom-worker transport
fixture with declared one/two/three-chain choices. Its insufficient-convergence
states remain `CONVERGENCE_NOT_ASSESSABLE`; its supplied native orders still
exercise descriptive same-input comparison. Those deterministic fixture traces
are transport scaffolding, never genuine-backend acceptance. The real-backend
tests in `tests/replay/test_real_backend_replay.py` cover the implementation's native orders and
populated native decision panel on locally generated synthetic rows.

Python integration functions are `reporting.inspect_report(run_dir)` and
`reporting.compare_reports(left_dir, right_dir)`. Both raise the privacy-safe
`ReportInspectionError` when inspection fails. Their JSON schema versions are
`anim-report-inspection/1` and `anim-report-comparison/1`; they do not replace the
frozen scientific report schema.
