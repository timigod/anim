# Reporting and claim-language developer contract

Status: `LIVE_INCOMPLETE_SCIENCE_V2_REPORT; PERSISTED_REHYDRATION_FAILS_CLOSED`

## Current product boundary

There is one narrow production report path: the `ebm-audit run` process may
write a deterministic, visibly `INCOMPLETE` report while it still owns the
exact in-process `SealedResultEvidenceSet` and the private artifact store that
persisted it. The reporting component derives its own sealed science-v2
projection from that capability. It does not accept a caller-authored
projection. The report includes all fifteen required section headings and
preserves missing or unusable scientific layers as `BLOCKED`, `PARTIAL`, or
`NOT_ASSESSABLE`.

The live machine-readable contract is `ebm-audit-report/13.0`. It projects the
sealed privacy-safe sampling owner and analyst-decision owner as separate
first-class objects, alongside the candidate within-fit/chain records,
participant-influence owner, and null owner. The six-layer summary is an exact
ordered ledger (`WITHIN_FIT`, `CHAIN`, `SAMPLING`, `ANALYST_DECISION`,
`PARTICIPANT_INFLUENCE`, `NULL`), not a substitute evidence source. Before
rendering, reporting revalidates each complete layer with that layer's own
schema, digest, accounting, and semantic rules; requires the common plan and
terminal-index identities; matches coverage digests and component rows to the
named owner; and matches every within-fit/chain coverage status and reason to
the corresponding candidate. Swapping, relabelling, digest-forking, or
count-forking layers fails closed as `REPORT.OUTPUT_CONTRACT`.

The live path also derives one total baseline assessment from the same exact
`SealedResultEvidenceSet`; it does not accept detached caller-authored baseline
files. Every live report-producing run persists
`evidence/baseline-assessment.json`. A successful baseline candidate also
persists `evidence/baseline-reproduction.json`, including the explicit
no-reference outcome; a non-successful baseline emits no reproduction record
and is `BASELINE_NOT_ASSESSABLE`. Report JSON projects the fixed ordered
nine-row comparison ledger, including `statistical-diagnostics`, and derives
its baseline wording and eligibility from these verified capabilities. A
cross-run assessment/reproduction pair, false reproduced status, or hidden
mismatch fails closed.

The scientific-contract comparison includes event IDs, effective event labels,
directions, preprocessing, missingness, inclusion, and stage semantics. An
effective event label is the event's `privacy_sensitive_display_override` when
present, otherwise its `display_name`; the order must match the declared event
IDs. Settings remain in implementation identity and are not duplicated into the
scientific contract. Reference diagnostics use the public
`statistical_diagnostics_digest(convergence,
ordered_chain_execution_ids=...)` helper over a schema-valid
`ConvergenceRecord` and exact plan-ordered chain IDs. A null reference
diagnostics digest is explicit unavailable evidence: when all supplied
comparisons match it can support only `BASELINE_PARTIALLY_REPRODUCED`, never
`BASELINE_REPRODUCED`.

Sampling and analysis-choice HTML sections render their own component coverage,
attempt rosters, contribution states, numeric-record identities, and typed
pending/unavailable reasons. Assessable numeric records show their exact
Kendall, footrule, rank-displacement where owned, matrix-distance, and pairwise
flip-fraction values; unavailable metrics show their typed reason instead.
They do not repeat a generic all-layer count table. Bootstrap evidence is not
relabelled as analyst-decision evidence;
baseline and other non-applicable analyst origins remain `NOT_CONTRIBUTING`;
participant-stage comparisons remain sourced from their declared owner; and no
overall score or combined uncertainty heatmap is produced.

Persisted cross-process report rehydration remains unavailable. The package
entrypoint `render_report_from_run_dir` still always raises
`ReportUnavailableError` with code `REPORT.V1_DISABLED` and typed reason
`PERSISTED_SCIENCE_V2_REHYDRATION_UNAVAILABLE`. It does so before opening the
run directory, inspecting the output path, or creating an artifact. The standalone
`ebm-audit report` command uses that same entrypoint, returns the invalid-input
exit code, and writes no report bundle.

`ReportModel`, its loader, and its renderer have been removed from production
code. Their former module paths and symbol imports fail. Test-only copies retain
the old shape solely to prove that the public boundary refuses former
`AUDIT_COMPLETE`, strong-null, and participant-stage outputs. There is no
production v1 bundle writer or callable prototype.

The incomplete live report emits no final manifest and makes no overall audit
completion claim. Its exact evidence includes every planned participant-
influence attempt, its privacy-safe pseudonymous removal alias, its separate
component metrics, and its typed contribution state. A zero-attempt run is
`NOT_ASSESSABLE`, any set containing descriptive-only or unusable attempts is
`PARTIAL`, and a fully interpretive set is `AVAILABLE`. The report does not
rank participants or invent a combined score while component scaling and
development sensitivity remain unvalidated.
For the selected worker, the report can show fixed-evaluation-cohort stage
movement derived from native participant posterior stages. It shows the
stage-model reference and headline central orders separately, the authenticated
cohort denominator, valid and missing counts, the fixed quantile rule, public
quantiles and IQR, aggregate metrics, and a digest linking to the
permission-restricted private participant evidence. It emits a numeric stage
comparison only when cohort, row alignment, private unit bindings, event
semantics, stage semantics, and likelihood semantics are all compatible.
Missing or incompatible capability is reported as typed not assessable; the
report never substitutes hard stages, the training cohort, or an event-order
metric. Existing refitted null attempts remain visible but uncalibrated, pending
null components remain typed, and the science completion gate remains blocked.
Candidate execution and whole-audit completion remain separate: a candidate set
can be `COMPLETE` with candidate exit `0`, while the current whole run is
`PARTIAL` with process exit `12` because the report is `INCOMPLETE` and the
science gate is `BLOCKED`. Specific candidate failure and privacy exits remain
visible and are not collapsed into `12`.
The standalone gate remains until a persisted authority can rehydrate all
required owners without trusting caller-authored files. Caller-authored
`uncertainty-summaries.json` therefore cannot emit `AUDIT_COMPLETE`,
`STRONGER_THAN_CHOSEN_REFITTED_NULLS`, or an authoritative participant-stage
conclusion through either Python or the CLI. Inputs are not silently
transformed into weaker claims.

This separation slice is `BUILT_UNVERIFIED`. It does not complete report
science, calibration, held-out evaluation, or standalone rehydration.

## Deprecated prototype contract

The sections below record the disabled ReportModel/1 prototype. They do not
describe an available product route and must not be used as scientific evidence.

### Sealed input

The retired test fixture loader reads
`RUN/report-seal.json`. The seal uses
`ebm-audit-report-input/1.0` and binds the exact file bytes, in this order:

1. `result-records.json`
2. `candidate-terminal-index.json`
3. `data-accounting.json`
4. `universe-coverage.json`
5. `failures.jsonl`
6. `warnings.jsonl`
7. `provenance.json`
8. `uncertainty-summaries.json`
9. optional `baseline-reproduction.json`

The loader opens no other run file. It holds one no-follow directory descriptor
for the complete load and reads each final regular-file object through one
no-follow descriptor, with before/after identity and size checks. A symlinked
run directory, a symlinked final artifact, or a final-path replacement cannot
redirect an already-open read.

The loader rejects missing or reordered entries, digest mismatches, duplicate
JSON keys or ledger rows, non-finite values, incomplete terminal coverage,
terminal/result mismatches, unverified baseline snapshots, and private/raw input
shapes. Every terminal result digest is recomputed from the exact canonical
record. Every result config/code digest must equal provenance, and every failure
ledger status must equal its terminal status. Coverage names each set's exact
ordered planned and valid candidate IDs; counts must equal those arrays, valid
IDs must be exactly the successful planned IDs, and the planned union must equal
the terminal candidate set. Failure messages are fixed and never echo source
values.

The runtime owner would still have to produce this projection after it has
finalized the ordered `ResultRecord/2` set and candidate-terminal index. That
integration is intentionally not approximated by the report command.

### Deterministic model and output

`ReportModel/1` preserves every planned terminal row. `SUCCESS` is the only
interpretive terminal status; warning, invalid, unsupported, failed, and
not-assessable rows remain visible in JSON, CSV, and HTML.

The model has five separate layers: within-model (with distinct within-fit and
chain components), sampling, analyst decision, participant influence, and lack
of recoverable signal. The metric/component/layer catalogue is closed and is
enforced by the loader, typed model, renderer selection, and output schema.
Every sealed input and emitted `ReportModel/1` contains exactly one explicit
row for each of the eight catalogue metrics: `position.entropy`,
`chain.kendall`, `bootstrap.kendall`, `decision.rank_shift`,
`pairwise.flip_rate`, `influence.kendall`, `stage.expected_shift`, and
`null.position_concentration`. Empty sets, missing metrics, duplicate metric
IDs, and cross-layer substitutions are malformed. When evidence is unavailable,
the row remains present with a closed typed non-assessable or
not-applicable status, a null value, and at least one closed reason code.
Every current quantitative metric is a finite, non-Boolean fraction in the
closed range `[0, 1]`; the catalogue also fixes its component and comparison
kind. A caller cannot make one metric pass by relabelling it as another
comparison. A native-stage summary must declare whether its event set and stage
semantics match the reference. If either differs, its comparability is
`SEMANTICALLY_NON_EQUIVALENT`.

This is a structural coverage and accountability rule, not evidence that
scientific aggregation rules are frozen or that an unavailable row is
assessable. Production derivation and exact source bindings for each summary
remain a separate required owner before a report can support scientific
interpretation. The presence of eight placeholder or unavailable rows does not
by itself make `AUDIT_COMPLETE` scientifically valid.

The lack-of-signal status
`STRONGER_THAN_CHOSEN_REFITTED_NULLS` is categorical rather than quantitative.
It is valid only for the null-comparison component, only with the Boolean value
`true`, and only when the comparison is `COMPARABLE`. A false, non-comparable,
or differently labelled result cannot acquire that status.

No caller-supplied prose enters the model. Summary metrics, statuses, units,
reason codes, failure/warning codes, hard-failure codes, protocol version, and
benchmark version use closed enumerations; scalar values are finite numeric,
Boolean, or null only. Experiment-set display uses a domain-separated digest,
not its caller-authored label. This makes private-looking text, medical or
causal prose, true-order claims, baseline overstatement, and project-readiness
labels unrepresentable in report JSON, CSV, and HTML.

The retired v1 bundle format contained:

- `report.json`: sorted canonical JSON using finite numbers, zero normalization,
  twelve significant decimal digits, and normalized exponent formatting. The
  exact emitted bytes are parsed back and validated against
  `report-model.schema.json` before any output file is created;
- `universes.csv`: fixed columns, terminal order, UTF-8, and LF line endings;
- `report.html`: UTF-8 self-contained HTML with inline CSS and no script,
  external URL, font, telemetry, network, or LLM dependency; and
- `manifest.json`: exact SHA-256 digests of the three report artifacts.

### Language gate

The primary language control is construction from fixed renderer prose and the
closed machine-value catalogue above. The executable matcher table remains a
defence-in-depth check in `ebm_audit.reporting.claims`. It enforces the mandatory
opening limitation, the baseline-not-reproduced wording gate, and the null-safe
fallback. It rejects clinical, causal, treatment, prognosis, regulatory/device,
scientific-truth, universal-robustness, bad-participant, baseline-overstatement,
and project-readiness claims. Frozen technical uses such as “convergence
diagnostics” remain allowed. Readiness phrases are normalized across spaces,
underscores, and hyphens and matched without case sensitivity, so spelling the
same claim as `READY_FOR_MINA` or `ready-for-mina` cannot bypass the gate.

Audit labels (`AUDIT_COMPLETE`, `AUDIT_PARTIAL`, `NO_VALID_UNIVERSES`, and
`AUDIT_INVALID`) describe only the sealed run. They are not a completion or
readiness decision for the project.

### Historical prototype verification record

These results predate the public fail-closed gate. They establish only the
retained prototype helpers' historical behavior and do not make report
generation available.

- The first focused correction run produced `65 passed, 1 failed`; the only
  failure was the expected deterministic snapshot change after replacing raw
  experiment-set display with its digest.
- The first static pass found Ruff `F841` for one unused exception binding;
  the binding was removed before the accepted pass.
- The accepted focused pass produced `87 passed`; Ruff, strict mypy,
  `compileall`, both reporting-schema meta-validations, and `git diff --check`
  also passed.
- The complete report CLI directory produced `4 passed`. A first wider CLI
  command was not a valid product result: it collected with `PYTHONPATH=src`,
  so one fixture import could not resolve `tests`, and the separately known
  planning seam still imported retired `verify_analysis_plan`. Rerunning the
  three unaffected CLI modules with `PYTHONPATH=src:.` produced `17 passed`.
  The planning seam remains outside this reporting correction and must be
  verified on the later combined tree.
- The final combined reporting, unaffected CLI, and schema-catalog run produced
  `104 passed`. Ruff, `compileall`, both reporting-schema meta-validations, and
  `git diff --check` passed. Whole-package mypy reported only the same separate
  `cli_workflows.py` import of retired `verify_analysis_plan`; strict mypy over
  the changed reporting/catalog source passed and is the accepted static result
  for this slice.
- Re-review then reproduced four narrower contract gaps: alternate separators
  could evade one readiness matcher; assessable metric scalars were not bound
  to exact units and ranges; native-stage comparability trusted a caller label;
  and the stronger-than-null status accepted `false`. The correction binds all
  four rules in the loader, typed model, output schema, and direct regression
  tests.
- The post-correction focused reporting, report CLI, and schema-catalog run
  produced `131 passed`. Ruff over the changed reporting and test code, strict
  mypy over the reporting package, Draft 2020-12 schema meta-validation, and
  `git diff --check` also passed.
- The final combined reporting, CLI-adapter, CLI-worker, and schema-catalog gate
  produced `148 passed`. Ruff, strict reporting-package mypy, `compileall`, both
  reporting-schema meta-validations, and `git diff --check` passed on that
  correction tree.
