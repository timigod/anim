# Input-data dictionary

## Prepare your local table

Use this dictionary to map a local CSV table into Anim's audit configuration.
Follow [real-data integration](real-data-integration.md) for setup, validation,
and run commands. This is a field dictionary, not a request for data. Do not copy
participant rows, private column names, raw values, reversible mappings, or
local file paths into this repository, shared project notes, chat, email, or ticket.

The exact machine contract is `AuditConfig/0.3` in
[`../../schemas/audit-config.schema.json`](../../schemas/audit-config.schema.json)
and
[`../../schemas/canonical-records.schema.json`](../../schemas/canonical-records.schema.json).
The installed starters show the required configuration shape. They contain no
real participant rows.

## Reference: CSV format requirements

The input is one UTF-8 CSV file with a header and one declared physical type
for every column.

| Property | Required value or rule |
| --- | --- |
| File kind | CSV |
| Encoding | UTF-8 |
| Header | Required |
| Line ending | Declare `lf` or `crlf` exactly |
| Delimiter and quote | Declare one character for each; they must differ and cannot be a line break |
| Quoted newlines | Not accepted |
| Whitespace | Never trimmed implicitly |
| Locale parsing | Disabled |
| Type inference | Disabled |
| Missing values | Only the explicitly declared `missing_tokens` |
| Booleans | Only the explicitly declared, non-overlapping true and false tokens |
| Column order | Must exactly match the declared `format.columns` order |
| Extra or missing columns | Rejected |
| File identity | Exact file-byte SHA-256 must match both configured input bindings |

Every physical column declares exactly one of `string`, `integer`, `float64`,
or `boolean`. Every column must have exactly one analysis role or be explicitly
listed as ignored with a reason. The auditor does not guess, trim, coerce, or
silently drop a column.

## Reference: column roles

### Participant identifier

Declare exactly one source column as `participant_id_column`.

- Its physical type must be `string` or `integer`.
- Every participant identifier must be present and unique.
- The source identifier stays in the local auditor process. It must not
  enter the worker, default report, logs, filenames, cache keys, or a bug
  report.
- The auditor creates its own internal row indexes and replacement labels for private review
  (pseudonymous aliases). Replacing an identifier does not anonymise the data.

The input must contain one row per participant for the declared version of the dataset.
Repeated measures require an explicit, separately reviewed data-variant design;
do not silently choose one row or aggregate rows before the audit.

### Event columns

Declare at least two events. For each event provide:

- a stable machine `event_id`;
- local source column;
- researcher-facing display name;
- category and unit, where known;
- abnormal direction: whether `higher` or `lower` values indicate abnormality;
- permitted transformations;
- missingness declaration;
- whether the event can be varied in a feature-sensitivity analysis;
- a completed review of whether names or values could identify participants; and
- an optional privacy-safe display override.

An event column must be physically `integer` or `float64`. Infinite values and
undeclared missing tokens are invalid. `REQUIRES_CONFIRMATION` is allowed in a
starter only so mapping can be reviewed; it must block fitting.

Do not derive abnormal direction from a published event order or tune it to
obtain a preferred sequence. Do not silently change units, signs, scales,
transformations, or event membership.

### Analysis groups

Declare at least one group specification. A group can come from:

- an exact local column with explicit typed-label-to-role mappings; or
- a predeclared rule whose source columns and semantics are recorded.

The supported scientific roles are `reference` (the comparison group) and
`at_risk` (the group assumed to be at risk for the modelled process). State which
roles are required and record the rationale. A paper's age band or cohort
label is an example from that study, not a default for another dataset.

### Covariates

Each covariate has a stable ID, source column, kind, and missingness rule.

- `continuous` covariates have no level order.
- `categorical` covariates require an explicit ordered list of typed levels.
- Current execution supports `error` or `complete-case`. The schema-reserved
  `external-variant` value is not currently executable.

Declaring a covariate does not authorize residualisation, an adjustment that
removes the effect estimated from covariates. Any
adjustment must be a separate predeclared analysis choice with its exact
operation and provenance.

### Metadata

Metadata columns may be `continuous`, `integer`, or `boolean`. Integer and
boolean metadata require `missingness: error`; continuous metadata may use
`error` or `allow-nan`.

Metadata describes the input. Declaring it does not make it a model feature.

### Ignored columns

Every remaining source column must be listed under `ignored_columns` with a
reason. An ignored column cannot simultaneously have another role. This
complete declaration prevents an unexpected column from disappearing
silently.

## Missingness and the reserved external-variant vocabulary

For current execution, choose one implemented policy for each event or
covariate:

- `error` — missing input makes the affected path invalid; or
- `complete-case` — use only the explicitly defined complete-case operation and
  record exactly which participants it excludes.

Although `AuditConfig/0.3` reserves the value and binding shape
`external-variant`, the configuration loader rejects it with
`CONFIG.EXTERNAL_MISSINGNESS_UNSUPPORTED`. Do not configure or claim an
external-missingness variant until that capability is implemented and
verified. Never replace, fill, or silently select cells merely to make
validation pass.

## What the pre-fit and first-run evidence must let the researcher check

Before fitting, `ebm-audit validate` must reject an invalid physical contract.
Its result reports a limited set of checks; detailed data accounting is
produced by `run`. Across the validation result, reviewed
plan, and the first dedicated baseline run, the researcher must be able to
reconcile:

- source and accepted participant counts;
- declared event, group, covariate, metadata, and ignored-column counts;
- missing, excluded, masked, or transformed counts;
- every enabled data variant and its provenance;
- every event direction and event-set choice; and
- the exact worker and configuration identity, checked against the recorded hashes.

A count mismatch is a stop condition. Correct the source or make a versioned,
reviewed configuration change; do not patch the table until validation happens
to pass.

## Safe examples

- [`../../examples/config/synthetic.audit.yaml`](../../examples/config/synthetic.audit.yaml)
  demonstrates the generic two-event configuration and contains
  placeholder digests that must be replaced for a local synthetic file.
- [`../../examples/config/idris-2025-public.structural.audit.yaml`](../../examples/config/idris-2025-public.structural.audit.yaml)
  is a structural mapping aid only. It is not reconstructed study data, a
  published order, or a ready-to-run participant configuration.
- [`../../examples/idris_2025_public/synthetic-example.csv`](../../examples/idris_2025_public/synthetic-example.csv)
  contains clearly labelled invented rows for column-mapping illustration
  only.

Follow [`real-data-integration.md`](real-data-integration.md) for the exact
local mapping, validation, baseline, run, report, interpretation, and
privacy-safe bug-report sequence.
