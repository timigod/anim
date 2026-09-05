# Custom worker guide

## Start here

Complete the README's [Offline first start](../../README.md)
route first. This guide begins only after the auditor is installed and the
six-file worker scaffold has been created with `ebm-audit adapter init`; it does
not replace the offline installation and initialization prerequisites.

For the current onboarding commands, use the [adapter runbook](adapter-runbook.md):
`adapter pin` records the exact worker identity, `adapter check` negotiates
requested capabilities and runs synthetic conformance, and the generated tests
exercise the worker through real subprocesses. The runbook also includes a
separately provisioned public pysaebm example with exact source/license hashes.
This guide remains the detailed worker protocol and implementation reference.

## Status and purpose

This guide defines the runnable researcher-facing route for connecting a private
or different EBM implementation without changing the auditor core. The worker
SDK, `adapter pin`, `adapter check`, `adapter describe`, and `adapter conformance` commands are implemented and
tested with the project-owned fixture and custom-worker example. Adapter
conformance runs Describe plus the synthetic contract cases and produces
researcher-facing protocol and capability evidence; it is not scientific backend
acceptance. The linked
[`adapter protocol`](../spec/adapter-protocol.md) remains a normative draft until
the specification freeze. After freeze, its exact frozen version wins if a later
detail conflicts with this guide.

This generic worker-conformance route is the integration surface for product
readiness. The only product readiness state is exactly
`READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY`. It does
not require a named backend, a public package, or participant data.

Use the executable schemas
[`../../schemas/worker-protocol.schema.json`](../../schemas/worker-protocol.schema.json),
[`../../schemas/canonical-records.schema.json`](../../schemas/canonical-records.schema.json),
and the exact output/check registry
[`../../schemas/protocol-registry.json`](../../schemas/protocol-registry.json).
Do not recreate a payload shape from the prose examples.

A worker is an external local executable. It reads one versioned request bundle,
invokes the researcher's model, and writes one canonical response bundle. The
model source and, for optional downstream real-data use, participant data remain
entirely inside the researcher's approved local environment. The core must not
import the private package.

The MVP contract supports one cross-sectional, strict single-sequence EBM with
stages `0..N`. Subtypes, temporal/dwell-time models, simultaneous/grouped events,
longitudinal visits, raw MRI processing, and automatic feature discovery are not
valid flattened outputs. Declare them unsupported rather than converting them to
a strict order.

## 1. Invocation contract

The core appends the exact protocol arguments to the configured worker
argv:

```text
<worker argv...>
  --protocol ebm-audit-worker/v2
  --command <describe|validate|fit|self-test>
  --request-dir <absolute-run-owned-request-dir>
  --response-dir <absolute-run-owned-response-dir>
```

The core invokes this as an argument vector without a shell. The closed worker
configuration stores those tokens in `worker.argv`, a non-empty list of strings,
not a command string to interpolate. Its first token must be an absolute
executable path. Any later token that the worker needs as a filesystem path must
also already be absolute because the worker starts from an isolated current
directory. The loader performs no shell interpolation or expansion of variables,
`~`, or globs; each YAML string is one literal argv token. The core supplies only
non-secret protocol, offline, and resource settings in an allowlisted
environment. Participant values and request metadata are files; they must never
be passed in argv or environment variables.

The worker process current directory is a fresh, run-owned directory. The worker
must not depend on the caller's current directory, home-directory caches, mutable
global state, a notebook kernel, or an internet connection.

## 2. Required commands

### `describe`

Runs without participant data and returns:

- worker and protocol versions;
- backend name, version, source commit or equivalent immutable identity;
- separate worker-executable, worker-code, backend-source, and environment
  digests;
- exact `supported_commands` and per-algorithm `supported_algorithms` entries;
- a truthful `AdapterCapabilities` object for each algorithm/command path;
- exact inline closed Draft 2020-12 settings schema, its domain-separated
  digest, and limits;
- deterministic seed and offline behavior; and
- known backend limitations.

`describe` must not probe a remote service, create persistent files, or claim a
capability merely because the upstream library has a similarly named function.
`backend_name` is always one stable, non-secret, non-null machine identifier;
only an unavailable backend version/source commit may be null.
The exact command set must include `describe`, `validate`, `fit`, and
`self-test`. Standalone `stage` is reserved wire framing only in protocol v2: a
worker does not advertise, parse, dispatch, or execute it. Fixed-cohort staging
remains inside `fit`; a future standalone command would require a reviewed typed
portable-artifact output path and a new admitted runtime contract.

### `validate`

Validates one complete request without fitting. It must check model shape,
settings, event directions, group requirements, missingness, finite values,
counts, and every claimed capability. Unsupported features return
`UNSUPPORTED_CAPABILITY`; contradictory/invalid settings return
`INVALID_SPECIFICATION`; malformed data return `INVALID_INPUT`.

Validation must not silently drop, cap, transform, impute, relabel, reorder, or
coerce a row, cell, participant, or event.

### `fit`

Fits exactly the supplied training data and model settings, using the supplied
seed. It may also stage a separately supplied fixed evaluation matrix when the
capability is declared. It returns only canonical outputs it genuinely has or can
derive under a documented, mathematically valid rule.

The worker must not silently substitute a backend, model family, algorithm, seed,
default setting, preprocessing step, event order, cache, or evaluation cohort.

### `stage` (reserved wire framing only in protocol v2)

Protocol v2 does not admit a standalone `stage` worker command or portable
fitted-model artifact. It is absent from worker CLI parsing and dispatch; callers
cannot request it. Do not guess a sibling response path or write an undeclared
model file. A future protocol must add one SDK-owned typed artifact-output
channel first.

Any future admitted success payload remains a distinct `StageResult`: aligned
stage posterior/MAP/expected-stage outputs and artifact/provenance binding only.
It does not require or fabricate a central order, fit chain, or fit likelihood
trace.

### `self-test`

Runs a tiny backend-owned, clearly labelled synthetic smoke test without external
data or network access. It checks install/runtime health; it is not scientific
acceptance and must not be presented as convergence proof.
Its receipt lists the exact synthetic fixture digest and every requested check as
`PASS` or `FAIL`; any failed/missing check requires a typed negative response.

## 3. Request and response bundles

The invocation directory contract is:

```text
invocation/
  request/
    request.json
    values.npz
    artifacts/       # reserved standalone-stage framing only; absent in active v2
  response/
    arrays.npz       # when result arrays exist
    warnings.jsonl
    side-effects.json
    artifacts/       # optional, declared model artifacts only
    response.json    # atomic completion marker, written last
  work/              # only permitted scratch location
```

JSON carries versioned metadata and small structured objects. Numeric arrays use
stored-only NumPy NPZ and must be opened with `allow_pickle=False`. The core
raw-checks the bounded central directory and aggregate uncompressed size before
ZIP or NumPy loading; private workers should use the supplied deterministic NPZ
writer. Every file is hashed and listed in its manifest. Compression, ZIP64,
encryption, data descriptors, extras, comments, unsafe names, absolute paths,
path traversal, symlinks, device files, FIFOs, undeclared files, duplicate
archive members, object arrays, and arrays that exceed declared byte/shape limits
must fail.

The core creates the request. The worker must treat it as read-only. The worker
creates response files only beneath `response/` and scratch files only beneath
`work/`. `response.json` is written last through a same-directory temporary file
and atomic rename so a partial response cannot look complete.

`request.json` and `response.json` are excluded from their own file maps. Each
closed map must equal the physical regular-file set for its bundle (apart from
the metadata file itself), and its RFC 8785 metadata digest binds every mapped
path, byte length, and file hash. Missing, extra, or self-listed files fail.

### Identifier rule

The request contains explicit contiguous internal row-index arrays only. It must
not contain:

- private participant identifiers;
- reversible mappings or report aliases;
- a private ID column name;
- source filenames or paths that embed identifiers; or
- raw caller metadata unrelated to the model.

Event machine IDs may cross the boundary because correct label alignment is a
scientific invariant. Private source column names must be mapped or sanitised by
the core before the request.

### Numeric input rule

The numeric request contains the selected event matrix and, where declared,
encoded group or fixed-evaluation arrays. Version 0.1 covariate residualisation
is performed by the core before invocation; no covariate array crosses this
worker boundary. Shapes, dtypes, missingness,
directions, encoding semantics, and row/event counts are explicit in
`request.json`. The worker must not infer meaning from array or alphabetical
column order; it must use declared event IDs.

`training_row_indexes`, `evaluation_row_indexes`, and `stage_row_indexes` are
exactly `[0, ..., count-1]` and are returned beside every stage output. They are
not private IDs. A worker must not reorder stage rows; exact array mismatch is a
protocol failure even when counts match.

Raw values are temporary and sensitive. They may not appear in response JSON,
warnings, errors, stdout/stderr, caches, or side-effect inventories.

## 4. Capability declaration

Declare, at minimum, whether the exact worker path supports:

- a strict single sequence;
- grouped/simultaneous events;
- subtypes;
- temporal events;
- missing values and per-feature missingness (both are fixed unsupported in
  protocol v2, so `missing_values=REJECT` and `per_feature_missingness=false`);
- order samples, position probabilities, and pairwise precedence;
- likelihood trace and accepted-transition diagnostics;
- fitted event distributions;
- participant stage posterior and hard stages;
- fixed-evaluation-cohort staging;
- a portable fitted artifact for separate `stage` (fixed false in protocol v2);
- multiple chains, bootstrap, and cross-validation;
- deterministic seed; and
- offline execution.

Capability fields describe observed/tested behavior of this command path, not the
backend family in general. If a field is unsupported, omit its output and declare
it false. The core may derive position or precedence matrices from a valid sampled
state chain, but the result must say it was core-derived. Never fabricate a field
to make a report section appear complete.

## 5. Canonical fit result

Where supported, the response includes:

- protocol/result schema versions;
- separate worker-executable, worker-code, backend-source, and environment
  identity;
- input, settings, distinct core/worker/backend/environment, and output digests;
- canonical 16-lowercase-hex `UInt64Hex` seed, chain ID, raw proposal-iteration
  count, burn-in, thinning, and runtime;
- event IDs and the central strict order as IDs and a valid permutation;
- a complete unthinned post-burn state/likelihood chain plus its exactly indexed
  thinned chain, if chain output is exposed;
- actual state-transition count, not a mislabeled accepted-proposal count;
- position-probability and pairwise-precedence matrices, if exposed or validly
  derived;
- training and optional evaluation stage posterior over `0..N`;
- MAP and expected stages where a posterior exists;
- fitted event-distribution parameters only when safe and meaningful;
- exact included/excluded participant/event manifest;
- warnings and per-chain convergence inputs only;
- backend-native artifact references confined to the response root; and
- files created/read, resource summary, and terminal status.

All order rows must be permutations of the declared event set. Probability arrays
must be finite, nonnegative, correctly shaped, and normalised within the protocol
tolerance. Participant and event counts must match the validated request exactly.
Version 0.1 defines no worker-side drop capability: any backend-required
exclusion or complete-case selection is compiled by the core into a distinct,
fully accounted request before invocation. Any worker-side loss, whether
disclosed or silent, is a hard protocol failure.

For an MCMC fit, `R=raw_iteration_count` is both the proposal count and the
number of returned rows. Returned row `q`, `0<=q<R`, is the current state after
proposal `q+1`, repeated on rejection when applicable. The initialized state
`S0` is not returned. With `0<=B<R` and `T>=1`, return the complete unthinned
post-burn slice `[B:R]` (`U=R-B` rows), then retained rows at returned indexes
`B+m*T<R`, so `S=floor((R-1-B)/T)+1`. Transition count compares adjacent
unthinned post-burn rows and has denominator `max(U-1,0)`; the count is zero and
fraction is null when that denominator is zero. Do not report an upstream object
named “accepted orders” as transition count. The contract suite checks the
boundary and off-by-one cases.

Backend-native artifacts are optional and private. They must not be required to
interpret the canonical result, escape the response directory, or contain direct
identifiers or raw values. If a private model creates raw intermediate files,
they remain inside its restrictive ephemeral worker workspace, are inventoried,
and are deleted rather than returned or persisted in the response bundle.
Version 0.1 defines no extension that weakens this rule. A non-portable in-memory
model is not a portable standalone-stage capability.

## 6. Terminal statuses and failure logging

Return exactly one terminal status:

- `SUCCESS`
- `INVALID_INPUT`
- `UNSUPPORTED_CAPABILITY`
- `INVALID_SPECIFICATION`
- `BACKEND_ERROR`
- `TIMEOUT`
- `PRIVACY_VIOLATION`
- `PROTOCOL_ERROR`

Worker `SUCCESS` means only that this command/chain returned a valid candidate
payload. A worker never emits `CONVERGENCE_WARN`, `CONVERGENCE_FAILED`, or
`CONVERGENCE_NOT_ASSESSABLE`. Each response is immutable. The core alone
finalises the complete chain set and may create those core-final states without
rewriting or losing worker responses. Only a core-final admitted result
contributes scientific output. Convergence states are not cosmetic warnings.

Failure details must include a stable error category, safe message, phase, and
relevant count/shape/type. They must not contain private IDs, raw values, full
rows, credentials, or private source paths. Global warning suppression is
forbidden. Captured stdout/stderr is not a result channel and may be retained only
after bounding and privacy sanitisation; otherwise the core keeps a digest and
byte count.

A timeout or crash remains a visible failed universe. A runner may perform one
identical transient retry if the declared runner contract allows it. The worker
must not retry internally with a changed seed, changed settings, or a fallback
algorithm.

## 7. Side effects, offline behavior, and isolation

A conforming worker:

- reads only its assigned request and reviewed local code/environment;
- writes only inside its assigned response/scratch directory;
- performs no telemetry, DNS, socket, API, remote asset, or package-download
  operation;
- creates no persistent backend cache;
- respects timeout, cancellation, process, CPU/thread, and output-size limits;
- does not mutate the request files;
- inventories every file retained in the invocation tree at completion; and
- can run with its working directory and cache/home variables pointed at fresh
  run-owned scratch.

The side-effect arrays are a final retained-tree snapshot. They inventory every
assigned-tree file still present at completion except exactly
`response/.side-effects.json.tmp`, `response/side-effects.json`,
`response/.response.json.tmp`, and `response/response.json`. The exact ordered
tuple is serialized as `inventory_exclusions`. `side-effects.json` is hashed in
the response `files` map; `response.json` is the completion metadata excluded
from its own map. No other file is exempt, and neither atomic temporary file may
remain at completion. Follow `$defs/SideEffectsRecord`; do not make the
inventory hash itself. This record does not observe file reads, transient
create/modify/delete activity, or forbidden-operation attempts; those limits
are named explicitly in `unobserved_activity_classes` and must not be converted
into zero-activity claims.

The subprocess boundary is not a malware sandbox. Contract tests detect common
misconfiguration and observable violations, but a malicious worker with the same
OS permissions can read/write outside the monitored directory or bypass
Python-level network hooks. Only run reviewed workers on participant data. Use a
separate OS account or institutionally approved filesystem/network sandbox for
code that is not trusted. See the [threat model](../security/threat-model.md).

## 8. Wrapping a private notebook/model

Keep the notebook as a development/reference surface, but extract its fitting and
staging call into a deterministic local command with these properties:

1. all required model settings are explicit inputs;
2. one supplied seed controls every stochastic source the model exposes;
3. preprocessing done by the notebook is either moved into declared auditor
   choices or fully recorded as a named external data variant;
4. the command consumes internal indexes and declared event IDs, not private IDs
   or implicit DataFrame index order;
5. cached notebook state is cleared or made impossible;
6. all outputs are translated to the canonical strict-order/stage semantics;
7. unavailable order samples, likelihoods, stage posteriors, or new-data staging
   are declared unsupported;
8. stdout/plots are disabled or contained without suppressing warnings; and
9. the command runs successfully in a fresh process with network denied.

Do not rewrite the model algorithm to satisfy the contract. If the model cannot
expose a required scientific output, report that limitation. If its model family
is outside the MVP, the correct result is `UNSUPPORTED_CAPABILITY`, not a lossy
conversion.

## 9. Trusted local Python helper contract

The required Python convenience layer is a **worker-side helper**, not an
in-process core plugin. The helper is imported by the researcher-owned
worker executable and runs only inside that subprocess/separate environment:

```python
from ebm_audit.worker_sdk import WorkerApplication
from private_model_adapter import PrivateModelBackend, build_private_identity

backend = PrivateModelBackend(build_private_identity())
raise SystemExit(WorkerApplication(backend).run())
```

`PrivateModelBackend` implements the public `WorkerBackend` methods `describe`,
`validate`, `fit`, and `self_test`, plus the identity/capability accessors. There
is no public stage callback: fixed evaluation staging happens inside `fit`; the
standalone stage wire schemas are reserved for a future reviewed protocol. The
runnable structural demonstration is
[`../../examples/custom_worker`](../../examples/custom_worker).
It deliberately retains fixture-owned identity, algorithm, capabilities,
settings, and stage semantics and is therefore transport-demo-only. A real
adapter replaces that complete declaration as well as validation, fit, and
self-test callbacks; replacing only three methods is never acceptance-ready.

`WorkerApplication` performs closed request/response schema parsing, file/hash
binding, `UInt64Hex` validation, atomic response finalisation, safe negative
errors, and array-catalog checks. The backend receives only canonical internal
indexes, event/group arrays, settings, and the validated seed. It must return the
same typed command payloads as any non-Python worker. The helper never imports or
invokes the research model in the auditor core process, never receives private
IDs, does no preprocessing, and does not weaken offline, file, privacy, identity,
or contract-test requirements. Helper version and code digest are part of
`worker_code_digest`.

## 10. Generic conformance route

Create a strict local YAML configuration with exactly the four top-level fields
shown below. `worker` contains exactly the nested `argv` field. Replace both path
placeholders with literal absolute paths before loading this example; the loader
does not expand them. The second token must be absolute because the worker script
is opened after the process moves to its isolated current directory.

```yaml
worker:
  argv:
    - /absolute/path/to/private-worker-python
    - /absolute/path/to/private-worker.py
algorithm_id: private-strict-sequence
settings: {}
expected_identity: null
```

```bash
ebm-audit adapter describe \
  --worker-config /approved/local-config/model-worker.yaml \
  --offline \
  --output /approved/local-output/worker-describe.json
```

A configured data-free `describe` explicitly allows `expected_identity: null`
for discovery and may be run again while the configuration remains unpinned. It
returns a versioned describe receipt containing the complete base
`backend_identity`, one `available_expected_identities` entry per algorithm, and
the exact `selected_expected_identity` for the configured `algorithm_id`. Review
the result, then copy that whole `selected_expected_identity` object into
`expected_identity` in `worker.yaml` without shortening or editing it. The pin
includes the complete base identity and digest, selected algorithm, selected
identity digest, and selected capabilities digest.

Only `self-test` and the synthetic contract harness's `validate`/`fit` executions
require this complete pin. Pinning does not grant product execution authority:
public scientific `validate`/`fit` remain blocked until their separately
documented prepared-execution authority exists. The YAML loader is strict; do
not use anchors, aliases, duplicate keys, custom tags, extra fields, or a shell
command string.

After pinning the complete identity, run the researcher-facing validation and
diagnosis command:

```bash
ebm-audit adapter conformance \
  --worker-config /approved/local-config/model-worker.yaml \
  --offline \
  --output-dir /approved/local-output/adapter-conformance
```

`adapter conformance` internally runs Describe plus the project-owned synthetic
contract cases. It writes
`/approved/local-output/adapter-conformance/adapter-conformance-receipt.json`,
reports the `overall_protocol_result`, and identifies the
`first_actionable_failure` with bounded `remediation` when correction is needed.
The receipt is protocol and declared-capability evidence. It is not scientific
acceptance of the EBM or its outputs.

The synthetic harness covers or explicitly records the applicability of:

1. closed payload shape for every active command, `describe` schema, exact
   `supported_commands`/`supported_algorithms`, and exact identity;
2. capability truthfulness and identity-drift `PROTOCOL_ERROR` behavior;
3. `self-test` offline smoke;
4. finite complete-data happy path;
5. invalid group and unsupported missingness failures;
6. malformed bundle/schema/version behavior;
7. timeout, crash, process-tree, and bounded stream capture;
8. unexpected-file and path-escape inventory;
9. same-seed repeatability;
10. different-seed no-cache behavior;
11. row permutation, internal-index remapping invariance, and deliberately
    reordered fit stage-output rows that must fail;
12. feature-column permutation with event-label remapping;
13. valid order/probability/stage invariants;
14. no silent participant/event/cell loss;
15. no network attempt in offline mode; and
16. no canary private ID/raw value in requests, outputs, logs, errors, or reports;
17. full-range canonical string seeds and closed file-set/metadata binding; and
18. raw/initial/proposal/burn/thinning off-by-one and immutable convergence-
    finalisation cases.

The low-level contract evidence contains a deterministic machine-readable case
table, exact worker-executable/worker-code/backend-source/environment identity,
protocol/schema versions, input fixture and output digests, captured
warnings/failures, privacy scan result, and one aggregate status. Missing cases
remain `UNVERIFIED`; capability-dependent cases that do not apply remain visibly
`UNSUPPORTED`/not applicable. Neither is counted as a case pass, and an
applicable unverified case prevents an aggregate pass.

Those are low-level contract-case statuses, not the researcher-facing evidence
decision. The conformance receipt projects an applicable missing case to
`UNAVAILABLE` and an honestly out-of-scope capability case to `NOT_APPLICABLE`;
it never projects either one to pass or fail.

The conformance evidence retains one of two capability scopes:

- **full conformance**: every canonical capability required by the full profile
  is available and has its required synthetic evidence;
- **partial conformance**: the worker can run the supported canonical subset and
  every absent evidence component remains explicitly `UNAVAILABLE` or
  `NOT_APPLICABLE`.

Missing evidence is never converted to `PASS`, converted to `FAIL`, inferred from
another output, or filled with a placeholder. `UNAVAILABLE` means the integration
does not supply that evidence. `NOT_APPLICABLE` means the evidence is not required
for the worker's truthfully declared capability scope. Both states remain visible
in the deterministic report.

A passing `adapter conformance` result provides protocol and declared-capability
evidence for the tested synthetic cases. It does not establish scientific
equivalence to the Idris model, convergence on real data, institutional approval,
or safety of hostile code.

For optional low-level diagnosis of the underlying synthetic case table, run:

```bash
ebm-audit adapter contract-test \
  --worker-config /approved/local-config/model-worker.yaml \
  --offline \
  --output-dir /approved/local-output/worker-contract-test
```

This diagnostic writes `contract-test-receipt.json`. An unpinned
`adapter contract-test` still runs the discovery describe and writes its receipt,
but records the required immutable-identity case and pin-dependent command cases
as `UNVERIFIED`; it cannot aggregate to `PASS`. This command exposes the
low-level cases when needed; it does not replace `adapter conformance` as the
researcher-facing route.

## 11. Baseline reference integration

If the private notebook is the scientific reference, export a canonical reference
bundle before changing its behavior. It must bind the exact dataset, connected
implementation/algorithm/settings, preprocessing/inclusion contract, stage
semantics, effective event labels, statistical diagnostics, and software
identity, and include central order plus adequate richer order-distribution and
participant-stage outputs where the original baseline produced them. An
effective event label is
`privacy_sensitive_display_override` when that value is present, otherwise
`display_name`, in the exact declared event order. Settings remain in the
reference implementation identity; do not duplicate or move them into the
scientific contract. Align rows through the closed private
`PrivateReferenceAlignmentArtifact` or a shared private namespace and dataset
digest. It binds every contiguous reference row to either one typed private ID
or one framed participant token, plus the reference-row-order digest repeated by
every participant-axis reference array. The reference uses
`ReferenceParticipantEventManifest`, never the worker
`ParticipantEventManifest`; direct IDs never enter the reference result, worker,
report, or default manifest.

Create the deliberately non-importable private draft and notebook example with:

```bash
uv run ebm-audit baseline-reference init \
  --output-dir /approved/local-config/baseline-reference-draft
```

Inside the approved private notebook, use
`ebm_audit.baseline.build_reference_result` to self-identify the complete
`reference_body`, then use
`ebm_audit.baseline.export.write_reference_bundle` with the resulting
`reference`, `arrays`, and `private_alignment` objects. The generated draft
names these exact construction contracts from
`schemas/canonical-records.schema.json`:

- `reference_body` is a `CanonicalReferenceResultBody`;
- `reference` is a `CanonicalReferenceResult`;
- `reference.scientific_contract` is a `ReferenceScientificContract`;
- `reference.outputs` is `ReferenceOutputs`;
- `reference.outputs.arrays` is the `ReferenceArrayCatalog`, while the separate
  notebook `arrays` mapping supplies the exact array material named by that
  catalog;
- `private_alignment` is a `PrivateReferenceAlignmentArtifact`; and
- the convergence object used to derive reference diagnostics is a
  `ConvergenceRecord`.

The writer validates these schemas, array/catalog equality, cross-field
bindings, self-identities, and private alignment before writing. It never
overwrites: if any canonical output already exists, export fails. A successful
call creates exactly `reference-bundle.json`, `arrays.npz`, and
`private-alignment.json` with private modes and publishes the manifest last.
Keep the bundle outside repositories and report output.

Derive the diagnostics field from the exact baseline convergence record and
plan-ordered chain execution IDs through the public helper:

```python
from ebm_audit.baseline.export import statistical_diagnostics_digest

diagnostics_digest = statistical_diagnostics_digest(
    convergence,
    ordered_chain_execution_ids=ordered_chain_execution_ids,
)
```

Store that digest as
`reference_body.outputs.statistical_diagnostics_digest` before calling
`build_reference_result`. If the notebook cannot provide the exact convergence
object and ordered chain IDs, store null rather than reconstructing them. Null
diagnostics prevent full reproduction and can yield at most
`BASELINE_PARTIALLY_REPRODUCED` when every supplied comparison matches; they can
never yield `BASELINE_REPRODUCED`.

Validate the exported bundle offline without fitting:

```bash
uv run ebm-audit baseline-reference validate \
  --manifest /approved/local-config/baseline-reference/reference-bundle.json \
  --offline \
  --output /approved/local-output/baseline-reference-validation.json
```

Configure the relative `reference-bundle.json` path and its exact byte digest
under `baseline_reference` with status
`SUPPLIED_INDEPENDENTLY_VERIFIED`. The manifest binds the adjacent arrays and
private-alignment files. `SUPPLIED_STRUCTURAL_ONLY` is validatable but is not
eligible for execution.

The connected worker's baseline comparison must yield one exact status:

- `BASELINE_REPRODUCED`
- `BASELINE_PARTIALLY_REPRODUCED`
- `BASELINE_NOT_REPRODUCED`
- `BASELINE_REFERENCE_NOT_SUPPLIED`

Full reproduction requires exact connected implementation and algorithm,
settings, preprocessing/inclusion, dataset/alignment, stage semantics,
effective event labels, statistical diagnostics, all predeclared comparable
fields, and adequate richer outputs to pass. When no supplied comparison fails,
a supported subset may justify
`BASELINE_PARTIALLY_REPRODUCED`; central order and counts alone can produce at
most that status. Null reference diagnostics also cap the result at partial.
Similarity to a paper figure or event order is not a reference comparison.

Every report-producing run emits `evidence/baseline-assessment.json`. A
successful baseline candidate also emits
`evidence/baseline-reproduction.json`, including the explicit
`BASELINE_REFERENCE_NOT_SUPPLIED` outcome when no reference is configured. A
non-successful baseline candidate emits the assessment only, with
`BASELINE_NOT_ASSESSABLE`. A valid reference from another cohort is retained as
scientific non-comparability: data-dependent rows are `NOT_COMPARABLE`; it is
not silently treated as a match or rejected as malformed input.

If baseline reproduction is not full, the report may characterise the connected
worker/configuration but must not call the robustness results an audit of the
original analysis.

“Diagnostics” in this guide means statistical sampling, convergence, software,
or protocol checks. It never means clinical diagnosis or a participant-level
clinical classification.

## 12. Optional downstream real-data checklist

After library readiness, a researcher who independently chooses optional
participant-data use should record the following inside the approved local
environment:

- [ ] immutable and separate executable/worker-code/backend-source/environment
  identity;
- [ ] truthful supported/unsupported capability matrix;
- [ ] no EBM backend imported by the auditor core;
- [ ] fresh-process and offline operation;
- [ ] deterministic same-seed behavior or an explicit hard rejection;
- [ ] no cross-seed or cross-input cache reuse;
- [ ] invariant row/event mapping and canonical output checks;
- [ ] restrictive temporary-file behavior and contained side effects;
- [ ] privacy-safe warnings/errors/streams;
- [ ] no direct IDs or raw values in retained artifacts;
- [ ] all required contract cases passed on the exact build;
- [ ] exact failures and unavailable capabilities retained; and
- [ ] separate scientific/backend benchmark acceptance where applicable.

Protocol conformance and per-integration scientific assessment are separate. A
worker can be protocol-conforming yet scientifically `EXPERIMENTAL` or
`REJECTED` for a particular downstream use. Such a result does not change product
readiness. Real-data integration is optional, occurs only in the researcher's
approved local environment after library readiness, and is never required for
product completion.
