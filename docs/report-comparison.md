# Inspect and compare saved reports

Use `summary` to inspect one saved run and `diff` to compare two:

```sh
ebm-audit summary --run-dir ./run-a
ebm-audit diff --left ./run-a --right ./run-b
```

Both commands work offline on existing files. They do not run a worker, load
participant-level result arrays, contact a service or create a new scientific
report. `ebm-audit report` remains disabled for saved scientific evidence.

Each input must contain the complete set of report files, including valid
`run-status.json` and `report/report.json` files. An interrupted run may not
contain them. Inspection checks that the files belong to the same run and have
not changed since the run recorded their hashes.

## Read a comparison

`UNCHANGED` means the inspected values and states match. It does not establish
scientific stability: two unavailable measurements remain unavailable.

The comparison shows added or removed **candidates** (planned analyses), changes
to each candidate's final status, event order, numerical differences, aggregate
stage values, and whether the measurements can be compared. A stage describes
progress through the event sequence under the model's declared definition.
It retains capability states and all six uncertainty layers, including each
layer's `implementation_status`.

The six layers separate uncertainty within a fit, between model-fitting chains,
from participant sampling, from analyst decisions, from participant influence
(sensitivity to removing participants), and from null calibration (comparison
with results expected without signal). They are never pooled into one measure.

Changed candidate membership or event/stage definitions is marked
`NOT_COMPARABLE`; it must not be treated as a like-for-like numerical experiment.
Existing `NOT_ASSESSABLE`, failed, invalid and unavailable states remain visible
for each run. Changes to provenance (records of where results came from) are
reported separately from changes to measurements.

Keep the full original run private. Inspection outputs and the decision panel
use fixed tokens defined by Anim, numbers, nulls and hashed identities; they
exclude arbitrary event names, choice labels, prose and dictionary keys. The
hashes preserve event sequence order. They are unsalted identifiers, so they do
not guarantee anonymity or confidentiality.

## Read the opening HTML summary

New reports created during an audit include a decision panel above the detailed
sections. For each uncertainty layer, it shows:

- How many order/stage comparisons had exactly zero difference, differed or
  were unavailable, and the range of reported magnitudes.
- Declared choices associated with those comparisons, using local `Decision 1 /
  Option 1` aliases and expandable full hashed identities.
- Separate assessments of software execution, baseline reproduction, worker
  capability and scientific completion, with implementation and missing states.
- Null calibration and the warning that stable or concentrated outputs can
  occur with no signal.

An additional panel compares **native central orders**: the representative
event orders supplied by the backend's declared method. It compares pairs
connected by a declared analysis choice when both fits succeeded, each supplied
exactly one native order, and their definitions match. It does not select one
chain from a result with multiple chains.

This panel's `objective_summary` is descriptive and separate from scientific
uncertainty. Anim builds it from verified live results during report creation.
Inspecting a saved report cannot recreate the live objects needed for that
step. The fixed scientific report JSON schema is unchanged.

Zero versus positive distance is a display rule, not a new scientific stability
threshold. Signed means, stage agreement and other measures for which zero
does not mean identical results are displayed only as magnitudes. Different
metric units, operation families and uncertainty layers are never pooled.
An association with a choice does not establish a cause. Detailed JSON, CSV
and HTML evidence remains available.

## Reference: Python API

The functions are `ebm_audit.reporting.inspect_report(run_dir)` and
`ebm_audit.reporting.compare_reports(left_dir, right_dir)`. Both raise
`ReportInspectionError` if inspection fails, with a fixed code and message that
omit rejected values and paths.

Their output schema versions are `anim-report-inspection/1` and
`anim-report-comparison/1`. These summaries do not replace the fixed scientific
report schema.

## Reference: file and identity checks

Inspection verifies the publication inventory (the list of files recorded when
the run was finalized), its digest, and the length and SHA-256 hash of every
report artifact. It matches the report to the status by plan, terminal-index
(the record of final candidate outcomes) and scientific-evidence identities.
Candidate identities, plan positions, individual final states and counts must
agree. The linked scientific evidence also supplies ordered event identities
and existing within-fit/chain metrics omitted from the report's shorter
candidate table.

Native central orders are read separately from result JSON in Anim's standard
format. Its schema, self-hash, publication hash, candidate/status and event
identity must all match. Referenced participant array files are never loaded or
included in the output.

`objective_orders` and `objective_order_distances` keep each native chain order
separate. They do not infer uncertainty in the modal order (the most frequent
order among retained sampling states). Strict Kendall distance measures
pairwise order disagreements; footrule distance measures displacement in event
positions. These existing metrics are used only when candidates, chain
positions, event sets and methods match. Event directions must also match:
equal names do not make opposite definitions of abnormal change comparable.

Inspection keeps declared input classification separate from classification
verified by Anim. Ordinary input declared synthetic can correctly remain
`PRIVATE_LOCAL_INPUT` in the scientific report if it lacks the project's
verified synthetic-origin record.

When `<run-name>.operations/replay.json` exists beside the run, inspection checks
it with the size-limited loader and verifies its self-hash, plan digest and
source run identity. Its nonsecret input, configuration, worker, randomness and
environment identities are compared separately. Missing metadata is
`MISSING_REPLAY_BINDINGS`; an invalid existing file causes inspection to fail.
Attempt history and run-specific provenance changes do not make identical
metrics a scientific change.

## Reference: read limits and trust

Inspection rejects symbolic links in any path component, non-regular files,
malformed JSON, duplicate JSON keys, non-finite JSON numbers, unsupported
schemas, and changed files or files that do not match the recorded run.
The limits are 16 MiB per artifact and 64 MiB per inspection, with 200,000 JSON
nodes, nesting depth 48 and 10,000 candidates. Runs that exceed these limits
are refused rather than partially summarized.

Local hashes establish consistency with saved status. They cannot establish
authenticity against someone who rewrites the whole directory and its hashes.
Inspection does not grant scientific capabilities, permit validated claims,
reclassify an incomplete report or change a fixed specification.

## Maintainer reference: focused synthetic verification

```sh
.venv/bin/pytest -q tests/reporting --basetemp=tmp/reporting-tests
```

The tests execute three synthetic conformance CLI runs and exercise
`summary`/`diff`, matching inputs, changed capabilities, explicit missing states
and the HTML panel. Copies of synthetic artifacts test status swaps, ordered
values, numerical changes, tampering, schema errors, read limits, symbolic
links, FIFOs (named pipes), and strings planted to detect private-data leaks.
Edited test fixtures verify inspection only; they do not demonstrate scientific
report creation or baseline reproduction. No historical evaluator suite or
upstream participant dataset is involved.

An additional ordinary CLI test uses the existing custom-worker communication
fixture with declared one/two/three-chain choices. Its insufficient-convergence
states remain `CONVERGENCE_NOT_ASSESSABLE`; its supplied native orders still
exercise descriptive same-input comparison. The deterministic fixture traces
test communication with a worker, not acceptance of a real backend. Tests in
`tests/replay/test_real_backend_replay.py` cover a real implementation's native
orders and populated native decision panel on locally generated synthetic rows.
