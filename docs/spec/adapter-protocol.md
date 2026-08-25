# External worker protocol specification

Status: FROZEN SCIENTIFIC CONTRACT
Protocol: `ebm-audit-worker/v2`
Request schema: `ebm-audit-worker-request/2.0`
Response schema: `ebm-audit-worker-response/2.0`

Executable Draft 2020-12 schema:
[`../../schemas/worker-protocol.schema.json`](../../schemas/worker-protocol.schema.json).
Shared closed records:
[`../../schemas/canonical-records.schema.json`](../../schemas/canonical-records.schema.json).
Exact output/check/identity registry:
[`../../schemas/protocol-registry.json`](../../schemas/protocol-registry.json).
These machine files are normative for serialized shape and vocabulary; every
object rejects unknown fields except the one algorithm settings object, which is
validated by the inline closed settings schema returned by `describe`.

## 1. Purpose and conformance language

This protocol is the only model-fitting boundary used by the `ebm_audit` core.
It permits an installed reference engine, a private research implementation, or
a non-Python executable to fit data and produce fixed-cohort stage outputs inside
that fit without becoming a core dependency.

`MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY` are normative. A worker is
conformant only when it passes the protocol contract suite for every capability
it declares. Conformance establishes data exchange and containment behavior; it
does not establish scientific validity or backend acceptance.

### 1.1 Capability truthfulness and optional integration profiles

An adapter is usable for the parts of an audit that its declared, contract-tested
capabilities support. For example, a worker that returns only a final event
order can support declared cross-run order comparisons, but it MUST leave
within-fit chain uncertainty, convergence, position, pairwise, and stage layers
unavailable when it supplies no evidence for them. The report MUST show that
limit instead of inventing a substitute.

An optional downstream per-integration profile is a separate, stricter research
check. It may require a complete raw evidence set, fixed source/environment
identity, and reproducible synthetic results before researchers interpret that
specific EBM's output. Failing or not entering such a profile does not invalidate
a truthful ordinary adapter and cannot block product readiness. Passing protocol
conformance or ordinary adapter usability does not establish model validity or
scientific suitability.

ADR-0007 is historical evidence for this separation; ADR-0014 and
`ebm-integration-readiness.md` govern readiness. This generic worker is the sole
integration boundary. A per-integration profile may record only its own state;
it cannot create a second SDK, parallel protocol, hidden product status, or
release gate.

For full- and partial-capability conformance, every audit check appears in the
integration inventory. Missing evidence is emitted there as `UNAVAILABLE` or
`NOT_APPLICABLE`; it is never converted to pass, fail, zero, empty evidence, or
an inferred output. More-specific transport and scientific statuses remain
visible and map unambiguously to that enclosing applicability state.

## 2. Invocation

The configured worker command is an argv array, never a shell string. The core
appends exactly:

```text
--protocol ebm-audit-worker/v2
--command <describe|validate|fit|self-test>
--request-dir <absolute-request-directory>
--response-dir <absolute-response-directory>
```

The core launches that argv without shell expansion. Raw data, identifiers,
settings JSON, secrets, and file contents MUST NOT appear in argv or environment
variables. The process working directory is a fresh invocation directory inside
the assigned temporary root. The executable token is resolved once without
following away a virtual-environment launcher; every later configured token is
preserved exactly. The core does not guess from the caller's current directory
whether an argument is a file path. A worker that needs a filesystem path in its
base argv MUST therefore configure that token as an absolute path.

The core sets an allowlisted environment containing locale, temporary-directory,
offline, and thread-limit controls. It sets each supported BLAS/OpenMP thread
variable to the requested worker thread limit. The worker MUST NOT reinterpret an
absent environment variable as permission to use a network service or alternate
backend.

The current supported launch profiles are exact and fail closed: macOS uses the
fixed system `/usr/bin/sandbox-exec`; Linux uses `/usr/bin/bwrap` only at that
fixed path. The launcher is hashed, network operations are denied, writes are
limited to the invocation tree, request writes are denied, and child processes
are denied or confined to the provider's process namespace. Caller `PATH` never
selects the containment launcher. A host without a reviewed provider returns a
privacy/availability failure before the worker starts.

The process exit code reports transport completion:

- `0`: a complete `response.json` was written, including for a typed negative
  scientific status such as `INVALID_INPUT`;
- nonzero or signal: the process failed to complete the transport. A valid,
  already-complete negative response may be retained as evidence, but it does not
  become `SUCCESS`; without one, the core synthesizes `BACKEND_ERROR`.

The configured deadline MUST be a finite positive number; zero, negative, NaN,
and either infinity are rejected before launch. The core enforces that deadline,
terminates and reaps the fresh process group on expiry, inventories the bounded
partial workspace, and records `TIMEOUT`. A later file write cannot change that
terminal status.

## 3. Commands

| Command | Study data | Required behavior |
| --- | --- | --- |
| `describe` | Forbidden | Return exact backend/adapter identity, algorithms, capabilities, constraints, environment identity, and protocol versions. Do not initialize or fit a study model. |
| `validate` | Allowed | Validate shapes, values, groups, settings, requested outputs, and capabilities without fitting or creating a fitted-model artifact. |
| `fit` | Allowed | Fit exactly one canonical training dataset under the requested algorithm/settings/seed. Optionally stage one fixed evaluation cohort in the same invocation. |
| `stage` | Reserved wire schema only | No worker may advertise, parse, dispatch, or execute this command. Fixed evaluation staging remains part of a successful `fit`. |
| `self-test` | Forbidden | Run a tiny, clearly synthetic backend-owned smoke locally and return its identity and checks. Do not use external assets or network access. |

A command not supported by the worker returns `UNSUPPORTED_CAPABILITY`; it is not
silently mapped to another command. `describe`, `validate`, `fit`, and `self-test`
are mandatory for an MVP fit worker. Standalone `stage` is reserved wire framing
only: no v2 worker advertises, parses, dispatches, or executes it.

`supported_commands` is exactly
`["describe", "validate", "fit", "self-test"]`. Each algorithm's command list
is exactly `["validate", "fit"]`. `supported_algorithms` is a non-empty array of
closed `SupportedAlgorithm` objects. Each object contains `algorithm_id`, the
exact command subset it supports, its exact `AdapterCapabilities`, a settings
schema digest, and constraints. A capability is evaluated for the selected
algorithm and command, not for a backend family in the abstract. An algorithm or
command absent from these two declarations is unsupported even if upstream code
happens to contain a similarly named function.

### 3.1 Execution authority boundary

The public core invoker executes only `describe` and `self-test`. Raw public
`validate` or `fit` calls fail with
`CAPABILITY.PREPARED_EXECUTION_AUTHORITY_REQUIRED` before reading payload or
array mappings. The package-private, test-only synthetic contract harness may
characterize genuine validate/fit behavior, but its receipts have a null
`planning_summary_id`, have no promotion or conversion path, and cannot
authorize a product run, fit, finalization, persistence, or result.

The completed Plan/3-to-PreparationReceipt/2 transaction issues one sealed,
non-serializable `PreparedExecutionAuthorization` for each exact `PREPARED`
candidate. It privately owns the exact candidate, immutable prepared
bytes/array catalog, authenticated Describe evidence, and ten-field
`SelectedAlgorithmBinding`. The package-private executor resolves and
revalidates that capability before any validate or fit work. A later fit
authorization must derive from the exact successful validation authority. A
`PlanningAuthority`, object, digest string, mapping, universe, or receipt alone
never blesses raw ingress. No substitute token or compatibility seam is
permitted before that atomic capability boundary.

Each non-prepared candidate instead receives one sealed, non-serializable
`UnpreparedResultAuthorization` for final-result construction. It binds the
exact plan position, complete receipt record and reasons, and deterministic
terminal-status mapping. For a valid unsupported branch it privately owns and
recomputes the canonical `ScientificDataDigestPreimage` and
`ebm-audit/scientific-data/1` digest; for an invalid pre-canonical branch it
proves that `input_digest` must be null. The raw exact-file byte digest is never
an `input_digest`. The authorization contains no universe, prepared arrays,
replay, or worker/execution authority. Its sole package-private resolver is
`_resolve_unprepared_result_authorization`.

The private production executor accepts only one exact
`PreparationTransaction`, its configured `WorkerInvoker`, and a fresh
same-plan persistence journal. It preflights the complete candidate sequence
before writing anything. The exact selected-profile `max_parallel_workers`
value is retained in the digest-bound Plan/3 budget owner and its opaque
candidate authorization. At most that many whole candidates may overlap within
that one transaction executor; independently started transaction executors do
not share a process-global ceiling. The executor never splits one candidate's
chains across candidate tasks. Unprepared candidates finalize directly from
their bound authorization.
Prepared candidates validate once, authorize fit only from exact `SUCCESS` plus
`fit_permitted=true`, and run one fit per declared chain/seed. After successful
validation, every declared chain receives terminal evidence even when an
earlier chain fails; a negative terminal never truncates the frozen chain plan.
Only a core-observed worker start/crash may retry from ordinal 0 to 1; typed
worker failures and whole candidates do not retry. Candidate products are
consumed strictly by Plan/3 ordinal through a bounded in-flight window.
Consumption of finalized products and persistence of results, cache entries,
terminals, and the final terminal index remain exact-prefix ordered. A task
exception cancels queued work, joins running work, persists no result after the
gap, and never seals a partial terminal index.
Cache HIT and resume are fail-closed in this slice. The profile's
`max_wall_seconds` remains planning metadata here; this paragraph does not claim
a global wall-clock enforcement mechanism.

One `fit` request represents one declared chain and seed. The core obtains
independent chains by issuing independent requests. Protocol v2 does not admit
one response containing pooled or nested native chains. A backend that can run
multiple chains must be configured to run the one requested seed/chain per
invocation; otherwise that mode is `UNSUPPORTED_CAPABILITY`.

## 4. Bundle and filesystem contract

Before launch, the core creates the invocation/request/response/work directories
with mode `0700`; request files and every worker-created response/scratch file
use mode `0600` (or stricter). The worker MUST reject symlinks,
devices, sockets, path traversal, and paths resolving outside the assigned root.

```text
invocation/
  request/
    request.json
    values.npz                  # only for data-bearing commands
    artifacts/                  # reserved standalone-stage framing; absent in active v2
  response/
    arrays.npz                  # required when result arrays exist
    warnings.jsonl              # required, may be empty
    side-effects.json           # required
    artifacts/                  # optional, declared model artifacts only
    response.json               # required and written last
  work/                         # only permitted scratch location
```

The worker contract permits writes only inside `response/` and `work/`. It MUST
NOT modify request files. The core inventories the assigned invocation tree and
any explicitly configured watched sentinel roots. An observed outside write
attempt, request mutation, undeclared response file, or escaping symlink is
`PRIVACY_VIOLATION` or `PROTOCOL_ERROR` according to whether data could have
escaped. The product launch profile enforces this write boundary at OS level and
the core separately checks the retained tree. A fixed-size Python activation/
attempt marker makes caught Python denials observable; absence of that marker is
recorded as unverified attempt observability rather than a no-attempt proof.
The profile intentionally still permits reads of reviewed local code and the
worker environment. It therefore assumes a trusted/reviewed worker and does not
claim hostile-worker confidentiality containment.

Before launch, the core bounds the already-framed request tree. After worker
shutdown and before any completed or partial result tree is content-hashed, it
performs another metadata-only bounded inventory. The complete invocation tree,
including request, response, work, completion metadata, and bookkeeping files,
MUST retain no more than 256 regular files, 64 subdirectories, and 512 MiB of
regular-file bytes. Crossing any limit is
`PROTOCOL.INVOCATION_TREE_LIMIT_EXCEEDED`; its evidence contains only observed
counts, total bytes, configured limits, and a digest of the observed path/type/
size projection. The inventory stops as soon as a limit is crossed, so partial
failure evidence never requires an unbounded file read. The existing smaller
per-file limits remain independently binding: protocol metadata is at most 16
MiB and warnings and side-effect JSON are each at most 8 MiB.

`response.json` is the atomic completion marker and MUST be written last via a
same-directory temporary file and rename. Partial files are evidence, never a
successful result. Cleanup failures are warnings retained in the run ledger.

## 5. Serialization and hashing

JSON is UTF-8 without a byte-order mark and MUST contain no NaN, infinity, or
negative infinity. Every protocol digest is `Sha256Digest`, exactly
`sha256:<64 lowercase hex digits>`. Structured digests use
`SHA256(ASCII(domain) || NUL || RFC8785-JCS(object))`; exact-file digests use
`SHA256(file_bytes)`. Both are rendered with the prefix. Domains and preimages
are field-specific and MUST NOT be substituted. The common rules are normative
in [`artifact-hashing-and-freeze.md`](artifact-hashing-and-freeze.md).

Numeric arrays use NumPy `.npz`. Readers MUST use `allow_pickle=False`, reject
object/string arrays unless a field explicitly permits fixed-width UTF-8, and
verify every name, dtype, shape, and finite-value rule against the JSON catalog
before use. Before an ordinary ZIP parser or NumPy sees the archive, the core
MUST bound and parse the exact end record and central directory, cap it at 64
members and 256 KiB, require an exact ASCII-safe catalog/member set, and reject
multi-disk, ZIP64, encryption, data descriptors, extra fields, comments,
unsupported flags, and non-`ZIP_STORED` members. Aggregate uncompressed member
bytes are charged against the remaining 512-MiB invocation-tree allowance before
loading. ZIP members not listed in the catalog are `PROTOCOL_ERROR`. This closes
the compressed-expansion path; it is not an RSS guarantee because bounded NumPy
validation may create temporary copies.

The `files` map is closed and mandatory. Its keys are every regular bundle file
other than its own metadata file: `request.json` MUST NOT list itself and
`response.json` MUST NOT list itself. Every mapped entry is
`{"byte_length": <nonnegative integer>, "sha256": "sha256:..."}`. The physical
regular-file set below the bundle root, excluding the metadata file and declared
directories, MUST equal the map key set exactly. Missing, extra, duplicate,
symlinked, or non-regular entries are `PROTOCOL_ERROR`. For a data-bearing
request, `values.npz` is mandatory. For every complete response,
`warnings.jsonl` and `side-effects.json` are mandatory; `arrays.npz` and
artifacts are mandatory exactly when the command payload catalogs them.

`request_metadata_digest` uses domain `ebm-audit/worker-request-metadata/2` over
the complete `request.json` object with the top-level
`request_metadata_digest` member removed. Because that preimage contains the
closed `files` map, it binds the
mandatory file set, each path, byte length, and byte digest. The response rule is
identical with domain `ebm-audit/worker-response-metadata/2`:
`response_metadata_digest` is computed from the complete `response.json` object
with only that member removed, and binds its closed
`files` map. The metadata files are excluded from their own maps to avoid a
self-referential digest. Neither metadata digest replaces the core's scientific
cache key.

For active `validate` and `fit`, `scientific_request_digest` uses domain
`ebm-audit/scientific-request/2` over the exact closed command-specific member of
`ScientificCommandRequestProjection`. Each projection omits only the four
transport fields `request_id`, `request_metadata_digest`,
`scientific_request_digest`, and `created_at_utc`; its complete v2 payload and
file map remain in the preimage. In particular, a fit's `attempt_id` and
`attempt_ordinal` remain scientific inputs. The fit request UUID is derived
deterministically from that attempt identity, but the UUID itself remains a
transport field.

For active `describe` and `self-test`, `scientific_request_digest` is exactly
`null`; those commands have no registered scientific-request projection. The
reserved standalone-stage framing does have an exact
`ScientificStageRequestProjection` and therefore requires a non-null digest under
the same domain, but no v2 worker runtime accepts that command. Retaining that
reserved schema does not advertise or admit standalone-stage execution.

The executable response preimage is
`worker-protocol.schema.json#/$defs/WorkerResponseMetadataDigestPreimage`.
Evaluator-only redaction/replacement of payloads or files is a distinct
`EvaluatorWorkerResponseBinding` with its own schema, field, and domain; it never
uses `response_metadata_digest` or `ebm-audit/worker-response-metadata/2`.

All wire/JCS seeds use `UInt64Hex`: exactly 16 lowercase hexadecimal characters
matching `^[0-9a-f]{16}$`, representing the full unsigned range
`0..2^64-1` in big-endian textual form. For example, zero is
`"0000000000000000"`. A JSON number, uppercase hex, `0x` prefix, shortened
string, signed value, or decimal string is invalid. Implementations MAY convert
this string to an internal integer after schema and digest validation, but that
integer MUST NOT be inserted into a JCS object.

## 6. Closed command-discriminated request envelope

Every request is a closed tagged union discriminated by `command`. Unknown
top-level or payload keys are rejected in protocol v2. Common fields are:

```json
{
  "protocol_version": "ebm-audit-worker/v2",
  "request_schema_version": "ebm-audit-worker-request/2.0",
  "payload_schema_version": "ebm-audit-worker-fit-payload/2.0",
  "command": "fit",
  "request_id": "a UUIDv4 string",
  "request_metadata_digest": "sha256:...",
  "scientific_request_digest": "sha256:...",
  "created_at_utc": "RFC 3339 timestamp",
  "offline": true,
  "core_code_digest": "sha256:...",
  "payload": {},
  "files": {}
}
```

The active command-specific `payload` is exactly one of `DescribeRequestPayload`,
`ValidateRequestPayload`, `FitRequestPayload`, or `SelfTestRequestPayload`. The
schema-only `StageRequestPayload` shown below is reserved framing and is not an
accepted worker CLI/runtime command:

```text
DescribeRequestPayload
  expected_identity: ExpectedIdentity | null

ValidateRequestPayload
  execution_input_projection: ExecutionInputProjection
  execution_input_projection_digest: Sha256Digest

FitRequestPayload = BackendFitScientificInput
  scientific_input_schema_version:
    Literal["ebm-audit-backend-fit-scientific-input/2.0"]
  universe_id: matching Sha256Digest
  chain_execution_id: matching Sha256Digest
  attempt_id: matching Sha256Digest
  attempt_ordinal: Literal[0, 1]
  seed: UInt64Hex
  chain_id: matching planned non-empty run-local identifier
  execution_input_projection: ExecutionInputProjection
  execution_input_projection_digest: Sha256Digest

StageRequestPayload = StageScientificInput  # reserved schema only
  scientific_input_schema_version:
    Literal["ebm-audit-stage-scientific-input/2.0"]
  seed: UInt64Hex | null
  stage_call_id: non-empty run-local identifier
  fitted_artifact: StageArtifactBinding
  execution_input_projection: ExecutionInputProjection
  execution_input_projection_digest: Sha256Digest

SelfTestRequestPayload
  seed: UInt64Hex
  profile: Literal["tiny-synthetic/1"]
  requested_checks: duplicate-free tuple[registry self-test check_id]

ExecutionInputProjection
  projection_schema_version:
    Literal["ebm-audit-execution-input-projection/2.0"]
  trust_boundary:
    Literal["TRUSTED_WORKER_SHARED_PROCESS_REPEATABILITY_ONLY"]
  offline: Literal[true]
  core_code_digest / config_digest: Sha256Digest
  input_files: FilesMap
  dataset: DatasetDescriptor | StageDatasetDescriptor
  data_accounting: DataAccounting
  preprocessing_manifest_digest: Sha256Digest
  algorithm_id: non-empty backend-declared identifier
  settings: closed schema-declared object
  settings_digest: Sha256Digest
  requested_outputs: duplicate-free tuple[registered scientific output ID]
  requested_outputs_digest: Sha256Digest
  selected_backend_identity: BackendIdentity
  selected_backend_identity_digest: Sha256Digest
  capabilities: AdapterCapabilities
  capabilities_digest: Sha256Digest
  stage_semantics_definition: StageSemanticsDefinition
  stage_semantics_digest: Sha256Digest
  adapter_semantics: AdapterSemantics
  adapter_semantics_digest: Sha256Digest
```

Active `validate` and `fit` carry `DatasetDescriptor` in the one shared execution
projection; only the reserved stage framing carries `StageDatasetDescriptor`.
The projection digest uses domain `ebm-audit/execution-input-projection/2` over
that complete closed object. The projection's `core_code_digest` and
`input_files` must equal the request envelope's values, and every repeated
identity/digest pair is independently recomputed. This is a repeatability owner
for one trusted local worker process, not hostile-code isolation.

For a synthetic benchmark case, the truth-free configuration passed into the
normal compiler is the closed
`$defs/AuditCaseConfigurationDigestPreimage`. It contains exactly
`case_configuration_schema_version="ebm-audit-case-configuration/3.0"`, the case
ID, ordered operation bindings (operation-matrix ID, analysis-spec ID, and
ordinal), and the complete ordered canonical `AnalysisSpec` objects.
`case_configuration_sha256` uses domain
`ebm-audit/audit-case-configuration/3` over that object. It is not the raw
generator's `ResolvedGeneratorConfiguration`, and it is never hashed under the
raw `ebm-audit/resolved-generator-configuration/1` domain. The named runtime
hooks verify deterministic ordering and reject truth fields before admission.

`ExpectedIdentity` is one complete reviewed pin, not a nullable subset of
component hashes. It retains the exact worker-wide `BackendIdentity` observed by
the first data-free discovery describe, its complete digest, the selected
algorithm ID, the corresponding algorithm-bound identity digest, and that
algorithm's capabilities digest. It contains no data. The core recomputes every
owner and rejects any drift as `PROTOCOL_ERROR`; worker self-reporting is never
the trust boundary.

Rules:

- `offline` MUST be `true` for participant-data-time execution and all acceptance
  tests. A worker unable to run offline returns `UNSUPPORTED_CAPABILITY` before
  reading `values.npz`.
- `describe` and `self-test` have no dataset and MUST NOT include `values.npz`.
  Only the first discovery `describe` may carry `expected_identity: null`.
  Configured `describe`, `self-test`, `validate`, and `fit` require the
  complete reviewed pin before process launch. `describe` performs no RNG
  operation. `self-test` uses its exact explicit seed.
- `payload_schema_version` is `null` for `describe`/`self-test`,
  `ebm-audit-worker-validation/2.0` for `validate`, and
  `ebm-audit-worker-fit-payload/2.0` for `fit`. The reserved standalone-stage
  framing uses `ebm-audit-stage-scientific-input/2.0`, but no worker runtime
  accepts that command.
- `scientific_request_digest` is a derived non-null digest for active `validate`
  and `fit`, and for the reserved stage wire framing. It is exactly `null` for
  active `describe` and `self-test`. No worker runtime accepts the reserved stage
  command. The response must equal the request field.
- `validate` and a later `fit` carry the identical
  `ExecutionInputProjection`; validate has no fit scientific-input version,
  universe, chain, attempt, seed, or chain ID and MUST NOT fit.
- `fit` uses the exact supplied `UInt64Hex`; a worker MUST NOT replace or
  numerically round it. Fixed-cohort staging inside that fit follows the fit's
  declared staging RNG rule. No separate stage seed enters the active runtime.
- `settings_digest` is the prefixed `Sha256Digest` over RFC 8785 JCS bytes of
  `settings` with domain `ebm-audit/settings/1`. Unrecognized scientific settings
  produce `INVALID_SPECIFICATION`.
- `requested_outputs` uses only the IDs and canonical order in
  `protocol-registry.json`. `requested_outputs_digest` uses domain
  `ebm-audit/requested-outputs/2` over
  `{registry_digest, requested_outputs}` after sorting by registry order.
  The digest is command-neutral; command eligibility is validated separately at
  the request boundary. `registry_digest` owns the complete closed registry rows,
  including `capability_absence_behavior`; the runtime must not rebuild a shorter
  field projection. The registered exact-registry invariant also compares those
  complete rows rather than only their output IDs. A capability needed to fit, or
  needed by a non-evaluation-stage component, produces whole-request
  `UNSUPPORTED_CAPABILITY` when unavailable. The sole
  component-scoped exception is `fixed_evaluation_cohort_staging=false` for the
  three registered evaluation-stage outputs: the candidate remains `VALID`,
  validation permits fitting, fits execute, those component results are
  `{status: NOT_APPLICABLE_BY_CAPABILITY, value: null, reason_code:
  STAGING.FIXED_COHORT_UNAVAILABLE}`, and order, position, pairwise, influence,
  and convergence components continue. No value or in-bag/common-in-fit staging
  fallback is fabricated. The complete successful fit payload and every
  canonical scientific chain repeat the same component-applicability set. For
  an unavailable output, its frozen `result_members` are prohibited from the
  array catalog: `evaluation_stage_posterior` forbids
  `evaluation_row_indexes` and `evaluation_stage_posterior`;
  `evaluation_hard_stages` forbids `evaluation_row_indexes`,
  `evaluation_map_stage`, and `evaluation_map_tie_mask`; and
  `evaluation_expected_stage` forbids `evaluation_row_indexes` and
  `evaluation_expected_stage`. Schema conditionals and the runtime derivation
  both enforce this exclusion before any payload or canonical scientific digest
  is accepted. The runtime derives the complete ordered applicability set from
  the exact requested-output list and the observed boolean capability; the
  worker cannot erase the three unavailable-component rows and restore an array.
  Re-hashing the fit payload, wire response, evaluator binding, sealed result,
  and canonical payload cannot make a contradictory array applicable.
- Every registry row has `required_capabilities`, a duplicate-free conjunction.
  The request is supported only when every named capability satisfies its exact
  required value. A row that needs fixed evaluation staging and a participant
  stage posterior therefore requires both; satisfying either one alone is
  insufficient. The core and worker evaluate the same conjunction.
  `capability_absence_behavior=FIXED_COHORT_STAGE_COMPONENT_NOT_APPLICABLE` is
  frozen only on `evaluation_stage_posterior`, `evaluation_hard_stages`, and
  `evaluation_expected_stage`; attaching it to any other row is invalid.
- Equal eligible output-ID tuples for `validate` and `fit` intentionally produce
  the same command-neutral requested-output digest. Their distinct command and
  payload identities remain bound by the command-specific scientific-request
  digest.
- Data descriptors contain only counts, canonical event IDs, canonical group
  semantics, array catalog entries, and transformation/data-variant provenance
  digests. They MUST NOT contain private participant IDs, participant aliases,
  raw source column names, display labels marked sensitive, or raw values.
- `files` follows Section 5's closed file-set rule. Absolute paths and `..`
  segments are forbidden.

### 6.1 Data arrays

For `fit`, `values.npz` contains:

| Key | dtype | shape | Meaning |
| --- | --- | --- | --- |
| `train_values` | `float64` | `[P, N]` | Finite event measurements in the exact `dataset.event_ids` column order. Protocol v2 rejects NaN and infinities; any explicit complete-case or external data variant is resolved and accounted for by the core before transport. |
| `training_row_indexes` | `int64` | `[P]` | Exactly `[0, 1, ..., P-1]`; explicit row alignment for every training input and returned stage row. |
| `train_group_codes` | `int32` | `[P]` | Canonical group codes declared in `dataset.group_codebook`; no missing or undeclared code. |
| `evaluation_values` | `float64` | `[Q, N]` | Optional fixed-cohort values in the identical event order. |
| `evaluation_row_indexes` | `int64` | `[Q]` | Required with evaluation values; exactly `[0, 1, ..., Q-1]`. |
| `evaluation_group_codes` | `int32` | `[Q]` | Optional only when the backend requires evaluation-group values. |

These are explicit internal row indexes, not participant identifiers. No private
identifier or alias array is sent. The worker MUST preserve the declared index
alignment and return the same explicit row-index array beside every stage array.
Exactly one training-stage row is returned per training input row and, when
requested/supported, one evaluation-stage row per evaluation input row. A
permutation, omission, duplication, dtype change, or inferred positional match is
`PROTOCOL_ERROR`, even when participant counts are unchanged.

For the reserved, inactive `StageRequestPayload` framing, the keys are
`stage_values`, `stage_row_indexes`, and optional `stage_group_codes`, with the
same semantics; `stage_row_indexes` is exactly `[0, ..., Q-1]`. That reserved
shape also declares one artifact under `artifacts/` with its backend identity,
creating-request digest, media type, byte length, and exact-file
`Sha256Digest`. No v2 worker runtime receives this shape.

### 6.2 Dataset descriptor

`DatasetDescriptor` is closed and contains exactly:

```json
{
  "variant_id": "stable machine identifier",
  "participant_count": 57,
  "evaluation_participant_count": 0,
  "event_count": 2,
  "event_ids": ["event_01", "event_02"],
  "event_directions": ["higher", "lower"],
  "group_codebook": {"0": "reference", "1": "at_risk"},
  "training_row_index_array": "training_row_indexes",
  "evaluation_row_index_array": null,
  "array_catalog": {},
  "stage_semantics": "strict-prefix-count/1",
  "stage_semantics_digest": "sha256:...",
  "preprocessing_manifest_digest": "sha256:...",
  "scientific_data_digest": "sha256:..."
}
```

`event_ids` are canonical scientific aliases, not source column names. IDs are
unique and their order defines numeric event index `0..N-1`. The worker may
re-express directions internally only if the transformation is reversible,
tested, and returned in provenance.

`array_catalog` is a closed map whose keys equal the exact `.npz` member set.
Each `ArrayCatalogEntry` is closed and contains `member_name`, `dtype`, `shape`,
`semantic_version`, `byte_length`, and `array_digest`; its key MUST equal
`member_name`. `array_digest` uses the canonical array domain/preimage in the
canonical schema. `evaluation_participant_count=0` requires the evaluation index
name and every evaluation catalog entry to be `null`/absent; a positive count
requires them.

`StageDatasetDescriptor` is the separate closed object containing
`variant_id`, `participant_count`, `event_count`, ordered `event_ids`, ordered
`event_directions`, optional `group_codebook`, `stage_row_index_array`,
`array_catalog`, `stage_semantics`, `stage_semantics_digest`,
`preprocessing_manifest_digest`, and `scientific_data_digest`. Its catalog may
contain only the three stage input members declared in Section 6.1.

### 6.3 Other closed request objects

Every named nested request type is closed; unknown fields are rejected:

```text
ExpectedIdentity
  base_backend_identity: complete BackendIdentity with algorithm_id = null
  base_backend_identity_digest: Sha256Digest over that exact object
  selected_algorithm_id: MachineId
  selected_backend_identity_digest: Sha256Digest over the same identity with
    algorithm_id replaced by selected_algorithm_id
  capabilities_digest: Sha256Digest for the selected algorithm

ArtifactBinding
  artifact_id: non-empty MachineId
  relative_path: normalized relative POSIX path below request/artifacts
  media_type: non-empty allowlisted string
  byte_length: nonnegative safe integer
  sha256: Sha256Digest
  creating_chain_execution_id: Sha256Digest
  creating_scientific_request_digest: Sha256Digest
  adapter_id / algorithm_id: non-empty strings
  worker_executable_digest / worker_code_digest: Sha256Digest
  backend_source_digest: Sha256Digest | null
  environment_digest / settings_digest / stage_semantics_digest: Sha256Digest
  stage_model_reference_digest: Sha256Digest | null
  event_ids: ordered non-empty tuple[MachineId]
```

The reserved `StageArtifactBinding` is this same closed object with
`stage_model_reference_digest` required to be a non-null `Sha256Digest`.

An artifact binds to the nonrecursive creating chain execution and scientific
request identities, its exact file digest, and the worker/backend/settings/event
identities. It MUST NOT contain the digest of a worker payload that itself
contains the artifact reference; such a payload/artifact fixed point is invalid.

`settings` is the sole schema-parametric object: it MUST be closed by the exact
worker-declared Draft 2020-12 JSON Schema returned inline as `settings_schema` in
the selected `SupportedAlgorithm`. `settings_schema_digest` uses domain
`ebm-audit/settings-schema/1` over the complete schema after RFC 8785 JCS. The
schema is the recursively closed `$defs/ClosedSettingsSchema`: its root and
every nested object have `type=object`, `additionalProperties=false`, and
explicit `properties`/`required`; arrays have one recursively closed `items`
schema; scalars use only the allowlisted validation keywords. `$ref`,
`$dynamicRef`, `$defs`, anchors, applicator unions/conditionals,
`patternProperties`, `unevaluatedProperties`, external retrieval forms, boolean
schemas, and every unknown keyword are forbidden. The `$id` is a local
`urn:ebm-audit:worker-settings-schema:...`, never a retrievable URI. A digest
without matching inline bytes is nonconformant; no filesystem or network
retrieval is permitted.

JSON Schema cannot express that each string in a schema object's `required`
array is a key in that same object's `properties` map. Therefore every
`SupportedAlgorithm` also carries exactly one closed
`SettingsSchemaValidationRule` with rule ID
`settings-schema-required-subset-of-properties/1`, enforcement phase
`describe-validation`, failure status `PROTOCOL_ERROR`, and failure code
`PROTOCOL.SETTINGS_SCHEMA_REQUIRED_PROPERTY_UNDECLARED`. After validating the
closed inline shape, the core recursively executes that rule at the root and
every nested object schema. `required:["ghost"]` without a sibling
`properties.ghost` is rejected during `describe`; merely serializing the rule
ID does not satisfy it.

`constraints` uses the fixed
`AdapterConstraints` schema in Section 7, never an open extension map. Protocol
v2 defines no extension or free-form nested object.

## 7. Identity and capability declaration

Every response, including failures after initialization, contains this identity:

```json
{
  "adapter_id": "research-ebm-worker",
  "adapter_version": "owned wrapper version",
  "worker_executable_digest": "sha256:...",
  "worker_code_digest": "sha256:...",
  "backend_name": "research_ebm",
  "backend_version": "1.0",
  "backend_source_commit": "full commit or null",
  "backend_source_digest": "sha256:<digest> or null",
  "environment_digest": "sha256:<digest>",
  "algorithm_id": "declared_algorithm or null by command",
  "identity_evidence": [{
    "kind": "source_commit",
    "digest": "sha256:...",
    "note": "Reviewed source identity."
  }]
}
```

Custom/private workers MAY use `null` for source commit/version only when the
absence is explicit; `backend_name` is nevertheless a stable, non-null,
non-secret `MachineId`. They MUST still provide stable worker/backend identifiers,
the separate executable, worker-code, backend-source, and environment digests,
and an evidence note. Values reported by active `fit` MUST byte-match the
relevant `describe` response and requested algorithm. The reserved stage shapes
specify the same binding for a future reviewed runtime. A mismatch is
`PROTOCOL_ERROR`.

A non-null Git object ID is lowercase hexadecimal and is exactly 40 characters
for SHA-1 or exactly 64 for SHA-256. Lengths 41 through 63 are invalid. The
executable union is `canonical-records.schema.json#/$defs/GitObjectId`.

`BackendIdentity` is the exact closed object illustrated above. `algorithm_id`
is the exact selected algorithm for active `validate` and `fit`; it is `null`
for `describe` and algorithm-independent `self-test`. The reserved stage shape
also carries an exact selected algorithm but has no admitted runtime. Each
`EvidenceReference` is closed and contains `kind`, `digest: Sha256Digest`, and a
bounded safe `note`; unknown fields are rejected. The identity digests are not
interchangeable. Their normative preimages are:

- `core_code_digest`: prefixed SHA-256 over the bytes
  `ebm-audit/core-code/1 || NUL || JCS(manifest)`, where `manifest` has the exact
  auditor source identity and a path-sorted list of every auditor-owned
  executable/schema/rule file that can affect the operation, each with relative
  POSIX path, byte length, and prefixed exact-file `Sha256Digest`. Generated data, run files,
  caches, timestamps, and absolute paths are excluded. Manifest version
  `ebm-audit-core-code-manifest/1.1` uses logical paths `ebm_audit/**/*.py`,
  `sitecustomize.py`, and `schemas/<closed-resource-name>` so source and installed
  wheel bytes produce one identity. Packaged worker demonstrations and templates
  are excluded from the core manifest; if invoked, they are bound by the separate
  `worker_code_digest`.
- `worker_executable_digest`: prefixed SHA-256 over
  `ebm-audit/worker-executable/1 || NUL || exact executable file bytes`. It binds
  the resolved first argv executable, not its path string. When that executable
  is a general interpreter, the entry script/module is additionally bound by
  `worker_code_digest`.
- `worker_code_digest`: prefixed SHA-256 over
  `ebm-audit/worker-code/1 || NUL || JCS(manifest)`, where `manifest` is a
  path-sorted complete inventory of worker-owned wrapper source, entry points,
  compatibility code, schemas, and static configuration that can affect the
  command, each with relative POSIX path, byte length, and prefixed exact-file
  `Sha256Digest`.
  Backend source and installed third-party environment files are excluded because
  they have their own digests.
- `backend_source_digest`: prefixed SHA-256 over
  `ebm-audit/backend-source/1 || NUL || JCS(manifest)`, where `manifest` names the
  backend, exact source commit/version when known, acquisition artifact digest,
  and a path-sorted inventory of executable backend source bytes. Exclusions
  (only VCS metadata, build output, and caches) are explicit in the manifest.
  A private opaque backend may use a reviewed immutable artifact digest with the
  limitation recorded; it never reuses `worker_code_digest` as a substitute.
- `environment_digest`: prefixed SHA-256 over
  `ebm-audit/environment/1 || NUL || JCS(EnvironmentIdentity)`. There is one
  exact `EnvironmentIdentity`: schema version; runtime implementation, version,
  executable digest, and nullable reviewed launch-manifest digest; platform OS,
  architecture, and ABI; exact lock digest; name-sorted installed distributions
  with version, nullable acquisition digest, and direct-file-inventory digest;
  and name-sorted native libraries with nullable version and file-inventory
  digest. Its executable shape is
  `canonical-records.schema.json#/$defs/EnvironmentIdentity`. Volatile paths,
  timestamps, hostnames, and environment secrets are excluded. No abbreviated
  or alternate environment object may use this field/domain.

The `||` operator means byte concatenation and `NUL` is one zero byte. All
manifests carry their own schema version. The core recomputes its digest and
verifies expected worker/backend/environment digests where it has the bytes or a
retained installation receipt. Any identity drift is `PROTOCOL_ERROR`.
`backend_identity_digest` is the prefixed digest over
`ebm-audit/backend-identity/1 || NUL || JCS(BackendIdentity)` and binds the
complete closed object; it never substitutes for any component digest.

The capability object is closed and contains all fields below:

```json
{
  "capabilities_schema_version": "ebm-audit-worker-capabilities/1.0",
  "strict_single_sequence": true,
  "grouped_or_simultaneous_events": false,
  "subtypes": false,
  "temporal_events": false,
  "missing_values": "REJECT",
  "per_feature_missingness": false,
  "order_samples": true,
  "position_probabilities": true,
  "pairwise_precedence": true,
  "likelihood_trace": true,
  "accepted_transition_diagnostics": true,
  "fitted_event_distributions": true,
  "participant_stage_posterior": true,
  "hard_stages": true,
  "fixed_evaluation_cohort_staging": true,
  "portable_fitted_model_artifact": false,
  "multiple_chains": true,
  "bootstrap": false,
  "cross_validation": false,
  "deterministic_seed": true,
  "offline_execution": true,
  "constraints": {
    "minimum_participants": 2,
    "maximum_participants": null,
    "minimum_events": 2,
    "maximum_events": null,
    "required_group_roles": ["reference", "at_risk"],
    "maximum_threads": 1,
    "maximum_raw_iterations": null
  }
}
```

The values above illustrate the schema shape; they are not an acceptance claim
for any named worker. Each worker fills them from verified behavior, and the
contract suite tests every positive declaration.

Protocol v2 fixes `missing_values` to `REJECT` and
`per_feature_missingness=false`: it has no missingness-mask array, so claiming
native missing-data semantics would be unverifiable. Explicit
complete-case and external variants remain core-owned preprocessing choices, not
backend capabilities. `multiple_chains=true` means repeated `fit`
calls with distinct explicit seeds produce genuinely independent chains without
cache reuse; it does not authorize pooling. `bootstrap` and `cross_validation`
refer only to backend-native operations. The core may orchestrate those analyses
by repeated ordinary fits regardless of these two flags.

The bundled deterministic structural fixture is deliberately not a chain
algorithm: it declares `multiple_chains=false` and an unavailable MCMC
projection with reason `NON_CHAIN_ALGORITHM`. A successful fixture invocation
is valid protocol, containment, and test evidence only. Scientific planning for
v0.1 records that adapter as unsupported/ineligible; it must not turn fixture
success into scientific eligibility. Historical `pysaebm` behavior may remain as
an optional downstream integration profile; it is not the maintained product
reference path or a readiness dependency.

`AdapterConstraints` is the exact closed object illustrated above; integer bounds
are safe nonnegative integers or explicit `null`, roles are a duplicate-free
subset of the canonical roles, and unknown constraint kinds require a new schema
version. Constraints may narrow a true capability but never broaden a false one.
A worker returning an output
whose capability is false, omitting a requested output whose capability is true,
or varying capabilities between commands without an identity change produces
`PROTOCOL_ERROR`.

Every capability is independent. In particular, `order_samples`,
`likelihood_trace`, and `accepted_transition_diagnostics` do not imply one
another, and neither position nor precedence matrices imply retained order
samples. Field-presence rules are evaluated separately for every requested
capability.

Capabilities report native worker behavior. A mathematically valid derived field
is permitted only when `field_origins` labels it `WORKER_DERIVED` or
`CORE_DERIVED`, gives a versioned method ID, names its source fields, and those
source fields passed validation. Derived output MUST NOT change the corresponding
native capability to true.

The `describe` success payload contains the exact closed declaration:

```text
DescribeResult
  supported_commands: exact tuple["describe", "validate", "fit", "self-test"]
  supported_algorithms: non-empty tuple[SupportedAlgorithm]
  worker_limitations: tuple[safe text]
  requested_output_registry_digest: Sha256Digest
  self_test_check_registry_digest: Sha256Digest

SupportedAlgorithm
  algorithm_id: unique non-empty identifier
  supported_commands: exact tuple["validate", "fit"]
  capabilities: AdapterCapabilities
  capabilities_digest: Sha256Digest
  settings_schema: exact inline closed Draft 2020-12 JSON Schema
  settings_schema_digest: Sha256Digest
  settings_schema_validation_rules: exact tuple[SettingsSchemaValidationRule]
  stage_semantics_definition: StageSemanticsDefinition
  stage_semantics_digest: Sha256Digest
  adapter_semantics: AdapterSemantics
  adapter_semantics_digest: Sha256Digest

AdapterSemantics
  adapter_semantics_schema_version: Literal["ebm-audit-adapter-semantics/2.0"]
  adapter_id / algorithm_id: matching non-empty identifiers
  semantic_version: non-empty version string
  supported_commands: exact tuple["validate", "fit"]
  capabilities_digest / settings_schema_digest: matching Sha256Digest
  stage_semantics_digest / requested_output_registry_digest: matching Sha256Digest
  mcmc_projection: AdapterMcmcProjection
```

`adapter_semantics_digest` uses domain `ebm-audit/adapter-semantics/2` over the
complete closed `AdapterSemantics` object. Its command list is the exact active
algorithm command set and never includes the reserved standalone-stage framing.

`capabilities_digest` (always plural) is the prefixed digest over
`ebm-audit/capabilities/1 || NUL || JCS(capabilities)`. Every active `validate`
and `fit` response repeats the selected algorithm's exact capability object and
digest. The reserved stage response shape specifies the same binding but is not
runtime-admitted. Algorithm-independent `self-test` does not select one. The two
registry digests bind the corresponding complete closed ordered row arrays from
`protocol-registry.json`, not ID-only projections: domains
`ebm-audit/requested-output-registry/1` and
`ebm-audit/self-test-check-registry/1`, respectively. Their exact-registry
invariants compare every row member, including self-test `required` flags.
Describe validation recomputes all four declaration identities from those
complete source owners: each algorithm's capabilities and settings schema, plus
both complete ordered registries. Copying a changed digest through later
objects does not make the declaration valid.

## 8. Closed command-discriminated response envelope

Every complete response is a closed tagged union. It contains:

```json
{
  "protocol_version": "ebm-audit-worker/v2",
  "response_schema_version": "ebm-audit-worker-response/2.0",
  "payload_schema_version": "ebm-audit-worker-fit-payload/2.0",
  "request_id": "matching UUID",
  "request_metadata_digest": "matching digest",
  "scientific_request_digest": "matching digest",
  "response_metadata_digest": "sha256:...",
  "command": "fit",
  "status": "SUCCESS",
  "backend_identity": {},
  "backend_identity_digest": "sha256:...",
  "capabilities": {
    "capabilities_schema_version": "ebm-audit-worker-capabilities/1.0",
    "strict_single_sequence": true,
    "grouped_or_simultaneous_events": false,
    "subtypes": false,
    "temporal_events": false,
    "missing_values": "REJECT",
    "per_feature_missingness": false,
    "order_samples": true,
    "position_probabilities": true,
    "pairwise_precedence": true,
    "likelihood_trace": false,
    "accepted_transition_diagnostics": true,
    "fitted_event_distributions": true,
    "participant_stage_posterior": true,
    "hard_stages": true,
    "fixed_evaluation_cohort_staging": false,
    "portable_fitted_model_artifact": false,
    "multiple_chains": true,
    "bootstrap": false,
    "cross_validation": false,
    "deterministic_seed": true,
    "offline_execution": true,
    "constraints": {
      "minimum_participants": 2,
      "maximum_participants": null,
      "minimum_events": 2,
      "maximum_events": null,
      "required_group_roles": ["reference", "at_risk"],
      "maximum_threads": 1,
      "maximum_raw_iterations": null
    }
  },
  "capabilities_digest": "sha256:...",
  "settings_digest": "sha256:...",
  "requested_outputs_digest": "sha256:...",
  "execution_input_projection_digest": "sha256:...",
  "core_code_digest": "matching sha256:...",
  "started_at_utc": "RFC 3339 timestamp",
  "ended_at_utc": "RFC 3339 timestamp",
  "runtime_seconds": 1.25,
  "resource_summary": {},
  "warnings_record_count": 0,
  "warnings_file_digest": "sha256:...",
  "side_effects_file_digest": "sha256:...",
  "payload": {},
  "error": null,
  "files": {}
}
```

On `SUCCESS`, `error` is exactly `null` and `payload` is exactly one of:

```text
DescribeSuccessPayload
  result: DescribeResult

ValidateSuccessPayload
  algorithm_id: matching request identifier
  settings_digest: matching Sha256Digest
  config_digest / requested_outputs_digest: matching Sha256Digest
  execution_input_projection_digest: matching Sha256Digest
  validation_issues: tuple[ValidationIssue]
  predicted_accounting: DataAccounting
  component_applicability: FixedCohortStageComponentApplicabilitySet
  fit_permitted: bool

FitSuccessPayload
  universe_id: matching Sha256Digest
  chain_execution_id: matching Sha256Digest
  attempt_id: matching Sha256Digest
  attempt_ordinal: matching Literal[0, 1]
  algorithm_id: matching request identifier
  settings_digest: matching Sha256Digest
  config_digest / requested_outputs_digest: matching Sha256Digest
  execution_input_projection_digest: matching Sha256Digest
  seed: matching UInt64Hex
  chain_id: matching string
  result: WorkerFitPayload

StageSuccessPayload  # reserved schema only; never active v2 worker runtime
  algorithm_id: matching request identifier
  settings_digest: matching Sha256Digest
  config_digest / requested_outputs_digest: matching Sha256Digest
  execution_input_projection_digest: matching Sha256Digest
  seed: matching UInt64Hex | null
  stage_call_id: matching string
  result: StageResult

SelfTestSuccessPayload
  seed: matching UInt64Hex
  receipt: SelfTestReceipt
```

`SelfTestReceipt` is closed and contains `profile`, `fixture_id`,
`fixture_digest`, exact worker/backend identity digests, start/end times, and a
non-empty ordered list of checks. Each check has a stable ID, `PASS` or `FAIL`, a
safe message, and evidence digests/counts only. `SUCCESS` requires every requested
check to be present and `PASS`; otherwise the response uses the appropriate
negative status. A self-test receipt proves only installation/protocol smoke for
the exact identity. It is not convergence or scientific acceptance evidence.

All remaining named response objects are closed:

```text
ValidationIssue
  severity: Literal["ERROR", "WARNING", "REQUIRES_CONFIRMATION"]
  code: stable namespaced identifier
  safe_message: bounded safe text
  details: SafeDetails

SafeDetails
  counts: closed map[stable identifier, nonnegative safe integer]
  internal_indexes: bounded tuple[nonnegative safe integer]
  approved_event_ids: bounded tuple[MachineId]
  digests: closed map[stable identifier, Sha256Digest]

ResourceSummary
  peak_resident_bytes: nonnegative safe integer | null
  cpu_seconds: nonnegative finite number | null
  worker_process_count: positive safe integer
  effective_thread_limits: closed map[allowlisted library name, positive safe integer]

SelfTestReceipt
  profile: Literal["tiny-synthetic/1"]
  fixture_id: MachineId
  fixture_digest: Sha256Digest
  worker_executable_digest / worker_code_digest: Sha256Digest
  backend_source_digest: Sha256Digest | null
  environment_digest: Sha256Digest
  started_at_utc / ended_at_utc: RFC 3339 timestamps
  checks: non-empty ordered tuple[SelfTestCheck]

SelfTestCheck
  check_id: MachineId
  outcome: Literal["PASS", "FAIL"]
  safe_message: bounded safe text
  evidence_digests: closed map[stable identifier, Sha256Digest]
  evidence_counts: closed map[stable identifier, nonnegative safe integer]
```

`DataAccounting`, `BackendIdentity`, `FieldProvenance`, array-catalog entries,
artifact references, and stage rows use the exact closed definitions in this
protocol and `canonical-data-and-result-schema.md`; the wire schema references
those versioned definitions rather than copying an open object. `SafeDetails` is
the only error-detail shape; raw backend mappings are forbidden.

On any non-success status, `payload` is exactly `null` and `error` is the one
closed `NegativeResponseError` in Section 9. Negative scientific arrays and
artifacts are not admitted; any retained diagnostic artifact is declared only in
the private/quarantined file inventory. This single shape applies to every
command. Unknown payload members or a success payload for the wrong discriminator
are `PROTOCOL_ERROR`.

For a negative response, `payload_schema_version` is discriminated by command.
It is `null` for active `describe`/`self-test` and the one exact non-null command
schema version for active `validate` and `fit`. The reserved stage response shape
uses its exact stage-input version, but no v2 worker runtime emits it. Requiring
the version for negative validate and fit responses is deliberate: those two
commands enter held-out evaluator evidence, so the evaluator must be able to
reconstruct their actual command-specific subject even though `payload` is null.
A negative fit response cannot claim a validation or reserved stage payload
version, and vice versa. If the worker cannot supply the command version or
another actual-subject component, the response is `PROTOCOL_ERROR` and cannot be
sealed as benchmark-subject evidence.

For active `validate` and `fit`, the common `capabilities` and
`capabilities_digest` fields are the exact selected algorithm declaration. For
`describe` and algorithm-independent `self-test` they are exactly `null`; the
describe payload carries the complete per-algorithm declarations instead. The
reserved stage shape mirrors the selected-algorithm fields without admitting a
worker command.

The common `scientific_request_digest` follows the request discriminator:
non-null and independently rederived for active `validate`/`fit`, exactly `null`
for active `describe`/`self-test`, and non-null in the reserved standalone-stage
wire shape. The reserved digest and schema do not create an executable command or
cache identity.

The core accepts a response only after verifying the request binding, schema,
identity, capabilities digest, command-specific seed/settings/call identifiers,
timestamps/runtime, every
file/hash/catalog, status-specific field presence, warnings, and side-effect
inventory. Unknown fields are unconditionally rejected. Protocol v2 has no
extension negotiation field, namespaced extension escape hatch, or implicit
downgrade; an extension requires a reviewed new schema/protocol version.

For every `validate` or `fit` acceptance path, this is one atomic owner check,
not a series of trusted digest strings. The core validates the complete request,
the complete describe result, the uniquely selected algorithm declaration, and
the complete response owner. It validates `settings` against that exact inline
schema and independently recomputes the settings-schema, settings,
requested-output-registry, requested-outputs, capabilities, backend-identity,
request-metadata, and command-specific scientific-request digests. Every copy in
the request, response, described algorithm, and sealed evidence must then agree
with the recomputed value. Propagating the same invented digest through all of
those objects fails because the source owner still hashes differently.

For every schema-valid successful or negative `validate` and `fit` response, the
core constructs one command-specific actual-subject projection. Typed negative
evidence also carries that complete closed preimage so a sealed record remains
self-verifying, but the evaluator independently reconstructs it from the request
and response and requires exact equality; it never trusts the carried object:

- `$defs/ActualValidateWorkerSubjectProjection` is built from the validated
  validate request and response envelope, plus `ValidateSuccessPayload` on
  success. It has `command=validate`, `validation_payload_schema_version`, and
  `validate_requested_outputs_digest`. It never reads nonexistent
  `payload.result`; on a negative response it reads no payload.
- `$defs/ActualFitWorkerSubjectProjection` is built from the validated fit
  request and response envelope, plus `FitSuccessPayload.result` on success. It
  has `command=fit`, `worker_payload_schema_version`, and
  `fit_requested_outputs_digest`; on a negative response it reads no payload.

Both close the backend identity digest and every identity component, stable
backend name and nullable version/source commit, algorithm, distinct executable/
worker/backend/environment digests, capabilities/settings digests, and exact
protocol/request/response versions. Their digests use distinct domains
`ebm-audit/actual-validate-worker-subject/2` and
`ebm-audit/actual-fit-worker-subject/2`. Validate and fit requested-output
digests are each recomputed from the same command-neutral v2 owner; equal eligible
output-ID tuples therefore match, while command eligibility and command-specific
scientific-request identities are checked independently.

Sealed evaluator evidence uses command-specific closed projections rather than
one nullable catch-all record:

- `$defs/ValidateSuccessCommandEvidenceProjection` binds the successful
  validation payload digest, validate subject digest, exact validate payload
  schema version, request/response/scientific identities, requested-output
  digest, and backend identity;
- `$defs/FitSuccessCommandEvidenceProjection` binds the corresponding fit
  payload and fit subject evidence; and
- `$defs/NegativeCommandEvidenceProjection` version 1.1 requires no payload
  digest, retains the complete typed error, requires the one exact non-null
  schema version for its `validate` or `fit` discriminator, and carries exactly
  one complete `actual_*_worker_subject_preimage` plus its recomputed
  `actual_*_worker_subject_digest`. Both opposite-command fields are forbidden.
  The evaluator schema-validates the preimage, independently reconstructs it,
  requires exact object equality, and hashes
  `ASCII(command_domain) || NUL || RFC8785-JCS(preimage)`. A missing component,
  altered preimage, or wrong well-formed SHA fails closed as `PROTOCOL_ERROR`;
  the evaluator never fills the gap from the expected benchmark subject.

These projections are the executable leaves for the evaluator's sealed command
result union. They preserve distinct validate/fit scientific-request identities
while the requested-output digest remains command-neutral, and they do not
invent worker evidence for an unprepared Plan/3 candidate.

Scientific-success sealing resolves a complete fit-execution owner for every
row of the frozen chain plan: the exact `WorkerRequest`, the exact
`WorkerResponseMetadataDigestPreimage`, and the exact
`FitSuccessEvaluatorWorkerResponseBinding`. Each private-root-authenticated
chain row commits that request's command-specific `scientific_request_digest`,
so the complete scientific request projection—including the full dataset
descriptor and file catalog—cannot be changed and re-signed after the plan is
frozen. The core derives the fit request
UUID deterministically from the frozen chain-attempt ID, recomputes the complete
request-metadata and scientific-request digests, requires the wire response to
name that same request, reconstructs the successful payload from the wire
result, and independently derives the response-metadata, evaluator-binding, and
actual-fit-subject identities. Before doing so, it resolves the analysis
specification's algorithm against the exact describe owner, validates and hashes
the settings and settings schema, and derives the requested-output identity from
the complete registry. It also binds request configuration, canonical data,
event semantics, and backend settings/outputs to the resolved sealed case and
`AnalysisSpec`. Replacing and re-hashing a transport request, wire
response, binding, payload, subject, or atomic identity therefore cannot create
a second valid scientific owner graph.

At a production boundary the evaluator first validates the complete owner
artifact against the registered schema, then dispatches its attached rules.
The contract reference dispatcher mirrors that boundary for identity, digest,
source-file, and comparator rules where owner-binding material applies by
accepting the complete owner or complete registered preimage and validating it
before evaluation. Arithmetic, ordering, receipt-state, and count rules may use
an explicitly derived, rule-specific internal projection; those projections are
evaluator outputs, not caller assertions.
The rule ID selects every digest domain, schema reference, expected registry,
and scientific/comparator validator. No caller may supply one of those choices.

The handler set is exact—91 handlers for the 91 registry rows across all
fourteen schemas—and its companion fixture executes one negative per handler.
An unknown rule ID or missing handler returns a closed, schema-valid fail-closed
outcome; registry presence, a caller-selected function, a caller-selected
expected list, or a well-formed digest string is never execution evidence.

A benchmark runner binds both frozen projections in its subject/evidence model
for success and negative outcomes, fills only the frozen candidate/contract/
profile/rule fields around the actual fit projection, recomputes the complete
`BenchmarkSubjectIdentity`, and requires its digest to equal the precommitted
subject. Merely copying an expected `benchmark_subject_digest` into a chain/
result row is not evidence and fails. A response from which the actual subject
cannot be reconstructed is retained as a protocol failure, fails the attempt,
and contributes no scientific or acceptance evidence.

`resource_summary` contains peak resident memory when measurable, CPU time,
worker process count, and effective math-library thread limits. `runtime_seconds`
is nonnegative worker-observed monotonic elapsed time; core-observed elapsed time
is also retained and takes precedence for deadline enforcement.

The public same-seed check compares every canonical fit-result field and every
returned canonical array exactly, plus the warning count and warning-file
digest. It excludes only `resource_summary`, `backend_artifacts`, and the
consequently run-specific `worker_fit_payload_digest`. CPU/RSS measurements and
native diagnostic artifacts may legitimately differ between otherwise
identical executions; each remains schema-, identity-, and digest-validated for
its own run but is not scientific repeatability evidence. The harness records a
separate `ebm-audit/contract-repeatability-result/1` digest over the stable
comparison projection. A changed order, probability, stage value, provenance
field, component-applicability result, canonical array, or warning still fails.

## 9. Status and error model

The only worker-response statuses are:

| Status | Meaning | Scientific outputs admitted? |
| --- | --- | --- |
| `SUCCESS` | This one command/chain completed and every requested/supported output passed protocol invariants. It makes no cross-chain convergence claim. | Candidate output only, subject to core finalisation, convergence, baseline, null, and benchmark status. |
| `INVALID_INPUT` | Data values, shapes, identifiers-as-events, groups, or other input facts violate the canonical input contract. | No. |
| `UNSUPPORTED_CAPABILITY` | A valid request asks for a model family, data condition, command, or output the declared worker cannot perform. | No. |
| `INVALID_SPECIFICATION` | Scientific settings or their combination are malformed, contradictory, unknown, or outside declared constraints. | No. |
| `BACKEND_ERROR` | The selected backend raised, crashed, or returned unusable native output for reasons not better classified. | No; diagnostic native artifacts remain quarantined. |
| `TIMEOUT` | The core or worker deadline expired. | No. |
| `PRIVACY_VIOLATION` | Direct identifiers/raw-value leakage, forbidden file/network behavior, or another privacy invariant failed. | No; release hard-fails. |
| `PROTOCOL_ERROR` | Request binding, schema, hashes, identity, capability truthfulness, file inventory, or canonical output invariants failed. | No. |

The worker never emits `CONVERGENCE_WARN`, `CONVERGENCE_FAILED`, or
`CONVERGENCE_NOT_ASSESSABLE`; those are core-final outcomes calculated from the
complete declared chain set. Worker `SUCCESS` does not mean core-final `SUCCESS`,
integration-specific scientific qualification, convergence pass, recoverable
signal, baseline reproduction, or scientific truth.

Every non-success response has exactly one primary error:

```json
{
  "code": "CAPABILITY.MISSING_VALUES",
  "category": "UNSUPPORTED_CAPABILITY",
  "safe_message": "This worker requires a complete event matrix.",
  "phase": "request-validation",
  "retryable_identical_request": false,
  "issues": [],
  "details": {
    "counts": {"missing_cell_count": 4},
    "internal_indexes": [],
    "approved_event_ids": [],
    "digests": {}
  }
}
```

`NegativeResponseError` is the exact closed object above. `code`, `category`,
`safe_message`, `phase`, `retryable_identical_request`, `issues`, and `details`
are all required; `issues` is a tuple of the closed `ValidationIssue` type and
`details` is the closed `SafeDetails` type. No backend-provided arbitrary mapping
or exception object is admitted.

`code` is a stable namespaced identifier beginning with `DATA.`, `SPEC.`,
`CAPABILITY.`, `BACKEND.`, `TIMEOUT.`, `PRIVACY.`, or
`PROTOCOL.`. `category` equals the response status. `safe_message` and `details`
MUST contain only allowlisted scalar values, counts, event IDs approved for
display, and internal indexes. They MUST NOT contain rows, raw measurements,
private IDs, source paths, environment secrets, or unbounded backend exception
text. The private sanitized traceback artifact, if retained, is hash-referenced
and access-restricted.

`issues` is empty for commands without a validation issue set. A negative
`validate` response places its complete deterministic safe `ValidationIssue`
array there so the closed `payload=null` rule is preserved. It does not add a
second primary error.

### 9.1 Immutable worker response and core finalisation lifecycle

A `WorkerResponse` is immutable after `response.json` is atomically completed and
validated. Its `status`, seed, chain, arrays, hashes, warnings, and errors are
never rewritten. The core retains each attempt as a closed
`WorkerExecutionEvidenceReference`, even when a later aggregate result cannot use it.

For a multi-chain universe the lifecycle is:

1. create one request/response record per declared chain;
2. validate every response independently; a valid chain may have worker status
   `SUCCESS`;
3. retain all successful chain arrays as candidate evidence and all negative
   records as failures;
4. compute the frozen cross-chain convergence assessment in the core from the
   complete declared chain set and unthinned post-burn diagnostics; and
5. create a separate immutable final `ResultRecord/2` whose core `status` is
   `SUCCESS`, `CONVERGENCE_WARN`, `CONVERGENCE_FAILED`,
   `CONVERGENCE_NOT_ASSESSABLE`, or another precedence-selected failure.

The core transition is exact: `CONVERGENCE_PASS -> SUCCESS`,
`CONVERGENCE_WARN -> CONVERGENCE_WARN`, `CONVERGENCE_FAIL ->
CONVERGENCE_FAILED`, and `CONVERGENCE_NOT_ASSESSABLE ->` the same-named final
status. Warn/fail/not-assessable final records reference every constituent chain
response without changing any worker `SUCCESS` status. Their arrays remain raw
descriptive evidence but are excluded from admitted scientific/null/robustness
summaries, valid-coverage numerators, optional integration-profile qualification,
and CLI `COMPLETE`.
The final record binds the ordered response metadata digests, chain-execution and
attempt IDs, convergence rule/version, assessment inputs, and reason codes.

The product/CLI owner consumes the total, ordered machine vocabulary in
[`../../schemas/cli-lifecycle-registry.json`](../../schemas/cli-lifecycle-registry.json).
In particular, `COMPLETE` requires every requested Plan/3 candidate—including
an unprepared one—to have final `SUCCESS`; `PARTIAL`
requires at least one `SUCCESS` and at least one non-success terminal record.
Those predicates cannot overlap. Missing terminal records are `FAILED`, and a
privacy failure has first precedence.

Status precedence is fail-closed:

1. confirmed data escape/direct-identifier leakage -> `PRIVACY_VIOLATION`;
2. invalid response binding/schema/hash/identity/file boundary ->
   `PROTOCOL_ERROR` (or privacy violation if escape is possible);
3. enforced deadline -> `TIMEOUT`;
4. valid typed worker status -> that status;
5. crash/nonzero exit without a valid typed response -> `BACKEND_ERROR`.

One otherwise identical retry is permitted only for a transient
process/transport failure when the run policy declared it. In v2 the exact
`ScientificFitRequestProjection` is
`{protocol_version, request_schema_version, payload_schema_version, command,
offline, core_code_digest, payload, files}`. The complete
`BackendFitScientificInput` remains in `payload`, including `attempt_id` and
`attempt_ordinal`; only request UUID, creation time, and the two top-level request
digests are absent. Its digest uses domain `ebm-audit/scientific-request/2` and is
carried in the request, response, and response references.

A permitted ordinal-1 retry therefore has a newly derived attempt ID,
deterministically derived request UUID, distinct scientific-request digest, and
distinct attempt-specific cache key. Equivalence uses the separate domain
`ebm-audit/retry-equivalence/1`: begin with the complete
`ScientificFitRequestProjection` after its four existing transport exclusions,
then remove only `payload.attempt_id` and `payload.attempt_ordinal`. The two
attempts MUST have equal retry-equivalence digests, so universe, chain execution,
seed, chain ID, complete `ExecutionInputProjection`, request files, and every
other scientific field remain identical. Both attempt identities and both
scientific digests remain in provenance; v2 never erases a failed attempt by
reusing its scientific identity.

Only a core-observed `PROCESS_FAILURE` at process start or process crash is
eligible, and exactly one ordinal-1 retry is permitted. Timeout, worker response,
validation, scientific, convergence, privacy, protocol, and unexpected-core
failures are not retryable. A different seed or changed setting is a separate
predeclared candidate, never a retry.

## 10. Warnings and side effects

`warnings.jsonl` is append-only UTF-8, one closed object per line:

```json
{"code":"BACKEND.REPEATED_STATE_RUN","severity":"WARNING","safe_message":"A long repeated-state run was observed.","details":{"counts":{"max_run_length":410},"internal_indexes":[],"approved_event_ids":[],"digests":{}}}
```

Severity is `INFO`, `WARNING`, or `SEVERE`. Warnings are never globally
suppressed, do not carry raw values, and cannot be the only representation of a
terminal failure. The response records warning count and file hash.
Each warning line is exactly the closed `WarningRecord` with required `code`,
`severity`, `safe_message`, and closed `SafeDetails`; no timestamp, backend
exception object, or additional field is admitted.

`side-effects.json` is a required, closed final-tree inventory. Version
`ebm-audit-side-effects/1.1` has observation scope
`FINAL_RETAINED_TREE_ONLY`: it states only which files remain at the end of the
worker command, with exact byte lengths and hashes. It does not claim to have
observed file reads, file lifecycle history, or forbidden-operation attempts.
The retained files are partitioned into three ordered, disjoint arrays:
`retained_request_files`, `retained_output_files`, and
`retained_workspace_files`. Each entry has only an invocation-relative path,
nonnegative byte length, and `Sha256Digest`.

The exact `unobserved_activity_classes` value explicitly records the limits of
this evidence: file reads; transient file creations, modifications, and
deletions; denied network attempts; denied outside-path attempts; and denied or
transient subprocess activity are not established by the final snapshot. An
empty retained-file array means no file in that partition remained at the
snapshot boundary; it never means no earlier activity occurred. OS containment,
request before/after checks, Python guard markers, and residual-process checks
are separate core evidence. They can prove a configured boundary denied or
detected a tested operation, but they do not turn an absent final file into a
claim that no attempt occurred.

The inventory root is the invocation directory. To break self-reference, the
per-file arrays exclude exactly, in this order:

```json
[
  "response/.side-effects.json.tmp",
  "response/side-effects.json",
  "response/.response.json.tmp",
  "response/response.json"
]
```

That exact tuple is serialized as `inventory_exclusions`. No other assigned-tree
file is excluded. The worker records every other file retained in the final
tree, partitioned by the `request/`, `response/`, and `work/` prefixes. The core
independently rebuilds the same final snapshot and requires exact lexicographic
array equality, so a missing, extra, reordered, or false entry is a protocol
failure. Transient or deleted files are deliberately not represented as if they
had been observed. `side-effects.json` itself is instead hashed as the
`side-effects.json` entry in the response `files` map and repeated as
`side_effects_file_digest`. `response.json` is the metadata/completion marker and
is excluded from its own `files` map; its metadata digest is computed with only
`response_metadata_digest` removed. The two atomic temporary files must not
exist at completion. This projection is exact—an implementation cannot invent a
broader bookkeeping exclusion.

Stdout/stderr are drained concurrently without retaining their content. The
default evidence contains the digest, total byte count, and whether the fixed
64-KiB diagnostic-summary threshold was exceeded; no stream bytes enter the
default run bundle. Each stream has a separate hard limit of 1 MiB. On the first
byte beyond either limit, the core signals the fresh process group immediately,
escalates from termination to kill if needed, hashes remaining pipe bytes without
retaining them until shutdown closes the streams, and returns
`PROTOCOL.DIAGNOSTIC_STREAM_LIMIT_EXCEEDED`. Its details contain only the hard
limit and both streams' observed byte counts and SHA-256 digests. Protocol
metadata is capped at 16 MiB before allocation; each warnings and side-effect
record is capped at 8 MiB. The 512-MiB/256-file/64-directory invocation-tree
limit is checked before other file hashes and bundle snapshots stream in bounded
chunks. A retained NPZ is admitted only when its aggregate uncompressed member
bytes plus every other physical retained byte stay within that same 512-MiB
allowance. Neither stream is parsed as scientific output.

These controls are acceptance and cleanup bounds, not a claim of complete OS
resource quotas. Protocol v2 has a wall-clock deadline, single-thread library
environment, diagnostic kill limits, and a retained-tree acceptance limit; it
does not yet impose an OS CPU-time limit, an address-space/RSS limit, or a live
scratch-disk quota while the worker is running. Those missing controls remain an
explicit platform-hardening limitation.

## 11. Worker fit payload

On worker `SUCCESS`, `result` is exactly one closed `WorkerFitPayload`. It is a
one-chain wire object, never the multi-chain/core-final `ResultRecord`:

```text
WorkerFitPayload
  payload_schema_version: Literal["ebm-audit-worker-fit-payload/2.0"]
  worker_fit_payload_digest: Sha256Digest
  universe_id / chain_execution_id / attempt_id: matching Sha256Digest
  attempt_ordinal: matching Literal[0, 1]
  algorithm_id / settings_digest / config_digest: exact request values
  requested_outputs_digest / execution_input_projection_digest: exact request values
  seed / chain_id: exact request values
  event_ids: exact ordered request tuple[MachineId]
  central_order_permutation: int32[N]
  central_order_method: CentralOrderMethod
  raw_iteration_count: int R >= 1 | null for a non-chain algorithm
  burn_in_count: int B with 0<=B<R | null
  thinning_interval: int T>=1 | null
  postburn_unthinned_state_count: int U=R-B | null
  retained_state_count: int S=floor((R-1-B)/T)+1 | null
  likelihood_indexing: Literal["post-proposal-state/1"] | null
  actual_transition_count: nonnegative int | null
  actual_transition_fraction: finite number in [0,1] | null
  array_catalog: closed map[array key, ArrayCatalogEntry]
  field_origins: closed map[field name, FieldProvenance]
  participant_event_manifest: ParticipantEventManifest
  preprocessing_manifest_digest / stage_semantics_digest: Sha256Digest
  stage_model_reference: StageModelReference | null
  component_applicability: FixedCohortStageComponentApplicabilitySet
  input_digest / core_code_digest: Sha256Digest
  worker_executable_digest / worker_code_digest: Sha256Digest
  backend_source_digest: Sha256Digest | null
  environment_digest / capabilities_digest: Sha256Digest
  resource_summary: ResourceSummary
  backend_artifacts: tuple[ArtifactReference]
```

The payload contains per-chain convergence **inputs**, not a
`ConvergenceAssessment`, core result status, downstream integration-profile
decision,
universe cache key, or worker-response references. The core validates the payload
and later creates exactly one `ResultRecord` for the complete universe.
`worker_fit_payload_digest` uses domain `ebm-audit/worker-fit-payload/2` over the
exact closed `$defs/WorkerFitPayloadDigestPreimage`, which is the complete
payload with only `worker_fit_payload_digest` absent. Because artifact references
bind only nonrecursive chain/scientific-request identities, this preimage has no
digest fixed point. The core converts each validated
final successful attempt into one `FinalChainScientificPayload`, preserves exact
chain-plan order, and applies the non-pooling/reference-chain rules in the
canonical result schema.

`CentralOrderMethod` is the closed canonical method record.
`retained-state-mode/1` selects the highest-frequency retained state and breaks
frequency ties by the lexicographically smallest event-ID sequence.
`backend-objective-maximum/1` selects the greatest value of the declared
deterministic objective over the backend-explored order set and uses the same
lexicographic tie rule. An unnamed representative, first-observed tie, or method
that changes without an identity/cache change is nonconformant.

`FieldProvenance` is closed: `origin` is `BACKEND_NATIVE` or
`WORKER_DERIVED`; a native field has `method_id=null` and empty source fields,
while a derived field has a versioned `method_id`, non-empty ordered
`source_fields`, and aligned `source_hashes: tuple[Sha256Digest]`. The core may
later add `CORE_DERIVED` fields only in its final result. `ArtifactReference` is
closed and contains `artifact_id`, normalized relative response path, media type,
byte length, exact-file `sha256`, creating chain-execution and
scientific-request digests,
all worker/backend/environment/settings identities, event IDs, stage-semantics
digest, and a `contains_private_data` boolean. Unknown nested fields are rejected.

Canonical array keys are:

| Key | dtype | shape | Rule |
| --- | --- | --- | --- |
| `central_order_permutation` | `int32` | `[N]` | Event index at each position; a permutation of `0..N-1`. |
| `postburn_order_state_chain` | `int32` | `[U, N]` | Unthinned returned rows `B..R-1`; row `q` is state after proposal `q+1`; repeated states remain. |
| `postburn_likelihood_trace` | `float64` | `[U]` | Likelihood for exactly the same returned post-proposal indexes; independent of order-sample presence. |
| `order_state_chain` | `int32` | `[S, N]` | Thinned returned rows `B+m*T<R`; repeated retained states remain. |
| `likelihood_trace` | `float64` | `[S]` | Likelihood aligned one-to-one with the thinned retained states. |
| `postburn_state_change_mask` | `bool` | `[max(U-1,0)]` | Adjacent post-burn state-change indicator when transition diagnostics are exposed. |
| `position_probabilities` | `float64` | `[N, N]` | Row event, column position. |
| `pairwise_precedence` | `float64` | `[N, N]` | Entry `[a,b] = P(a before b)`; diagonal `0.5`. |
| `training_row_indexes` | `int64` | `[P]` | Exact request array `[0, ..., P-1]`; aligns every training stage row. |
| `training_stage_posterior` | `float64` | `[P, N+1]` | Canonical stages `0..N`. |
| `training_map_stage` | `int32` | `[P]` | Deterministic tie rule: lowest stage among equal maxima. |
| `training_map_tie_mask` | `bool` | `[P, N+1]` | `true` at every posterior-maximizing stage; MAP equals the lowest true index. |
| `training_expected_stage` | `float64` | `[P]` | Posterior expectation on `0..N`. |
| `evaluation_row_indexes` | `int64` | `[Q]` | Exact request array `[0, ..., Q-1]`; aligns every evaluation stage row. |
| `evaluation_stage_posterior` | `float64` | `[Q, N+1]` | Optional fixed evaluation cohort. |
| `evaluation_map_stage` | `int32` | `[Q]` | Same tie rule. |
| `evaluation_map_tie_mask` | `bool` | `[Q, N+1]` | Same complete tied-stage encoding. |
| `evaluation_expected_stage` | `float64` | `[Q]` | Same expectation rule. |

Capability presence is checked independently:

- `order_samples=true` requires both order-chain arrays and permits derived
  position/precedence matrices;
- `likelihood_trace=true` requires both finite likelihood arrays and exact
  `post-proposal-state/1` indexing, but does not require order samples;
- `accepted_transition_diagnostics=true` requires the state-change mask and
  count/fraction (the fraction is `null` only with zero opportunities), but does
  not require order or likelihood arrays; and
- native/derived position, precedence, stage, and hard-stage fields follow only
  their own capability plus explicit `field_origins`.

A true capability never silently forces another true capability. Returning only
the thinned half of any exposed chain-indexed capability is invalid. A genuinely
non-chain worker omits all chain schedule/count/indexing fields and arrays; the
core later makes convergence not assessable rather than inventing diagnostics.

Backend-specific fitted distribution arrays use a namespace
`backend.<adapter_id>.<name>` and an explicit catalog. They are private
provenance by default and never imply a cross-backend semantic contract.

One fit request and `WorkerFitPayload` always represent exactly one declared
chain. Protocol v2 does not admit pooled or prefixed native multi-chain arrays;
the core issues distinct requests and joins them only by the universe chain plan.

Every array must satisfy the canonical finite, permutation, normalization,
antisymmetry, participant-count, and event-count invariants. Violation is
`PROTOCOL_ERROR`, not a warning or repair opportunity.

For fit chain indexing, `R=raw_iteration_count` is both the number of proposal
updates and returned post-proposal rows. Returned row `q`, `0<=q<R`, is the
current state after proposal `q+1`, repeating the previous returned state after
a rejection when `q>0`. The initialized `S0` is not returned. With
`0<=B<R` and `T>=1`, burn-in discards the first `B` returned rows, so `U=R-B`.
Retained row `m` is returned row `B+m*T` while `B+m*T<R`, giving
`S=floor((R-1-B)/T)+1`. Transition opportunity count is `max(U-1,0)` and is
computed before thinning. Contract tests cover `R=1,B=0,T=1`, `B=0`, `B=R-1`,
`T>U`, repeated rejection states, every independent capability combination, and
exact likelihood sentinels.

If upstream likelihood and order histories describe different proposal states,
or likelihood was computed before accepting parameter changes without
reevaluation, that history is not a canonical likelihood trace. It may be
retained only as a namespaced private backend artifact. The worker MUST declare
`likelihood_trace=false` and MUST NOT shift, pad, replay, or instrument the
scientific algorithm to fabricate a canonical trace.

### 11.1 Reserved future stage result payload

This section reserves the closed shape for a future protocol. Protocol v2 has no
typed protocol-owned portable-artifact output channel, fixes
`portable_fitted_model_artifact=false`, and does not admit scientific `stage`
execution. When a later reviewed protocol admits it, `stage` returns a
`StageResult`, never a `WorkerFitPayload` or `ResultRecord`. It MUST NOT refit and it
does not require or fabricate a central order, MCMC chain, fit likelihood trace,
or fitted distributions. Its closed metadata contains exact protocol/result
schema versions, algorithm/settings/seed or deterministic-null seed, fitted
artifact binding, event IDs, stage-semantics digest, input/config/core/worker/
backend/environment digests, accounting manifest, field origins, warnings,
runtime, and resource summary.

Its canonical arrays are exactly `stage_row_indexes [Q]`,
`stage_posterior [Q,N+1]` when supported, `stage_map_stage [Q]`,
`stage_map_tie_mask [Q,N+1]`, and `stage_expected_stage [Q]`, subject to truthful
capabilities/requested outputs. `stage_row_indexes` MUST byte/value-match the
request's explicit contiguous array and aligns every output row. Posterior,
tie/MAP, finiteness, and stage-range invariants are identical to fit staging.
Central order absence is normal and MUST NOT be upgraded to a fit result.

## 12. Validation responses

`validate` reads and validates the same request that would be fitted but MUST NOT
fit. On success, `payload.validation_issues` contains deterministic typed items
with `severity`
(`ERROR`, `WARNING`, or `REQUIRES_CONFIRMATION`), stable code, safe message, and
count/internal-index/event-ID context.

- Any `ERROR` yields `INVALID_INPUT` or `INVALID_SPECIFICATION` and the complete
  safe issue array moves to `error.issues` in the exact negative shape.
- Any unsatisfied capability needed to fit or compute a non-stage requested
  output yields `UNSUPPORTED_CAPABILITY` with the same issue placement. Missing
  only `fixed_evaluation_cohort_staging` for a frozen evaluation-stage row is
  not a negative validation response: validation remains successful with
  `fit_permitted=true` and the exact typed component applicability records above.
- Any `REQUIRES_CONFIRMATION` blocks real `fit`; validation may otherwise
  complete and planning may continue.
- Warnings do not authorize coercion, imputation, exclusion, direction guessing,
  or setting substitution.

A successful validate payload includes predicted row/event/cell accounting for
every explicit core-side preprocessing choice. A negative response may include
only safe aggregate predicted accounting inside its error issue/details fields.
The worker itself predicts and performs no hidden exclusions.

When evaluator evidence binds a successful validation payload, its digest uses
domain `ebm-audit/worker-validation-payload/2` over the exact closed
`$defs/WorkerValidationPayloadDigestPreimage` (the complete
`ValidateSuccessPayload`). This is distinct from both the fit-payload digest and
the full wire-response metadata digest.

## 13. Privacy, offline, and error boundary

Direct participant identifiers and participant aliases remain in the core's
private mapping boundary. Workers see only contiguous indexes. Event IDs may
cross the boundary; sensitive display names and source columns do not.

Default logs and reports contain no raw measurements. Exceptions report shape,
dtype, finite/missing counts, internal indexes, and approved event IDs rather
than rows or values. Reversible participant mappings are opt-in, stored separately
with restrictive permissions, and excluded from response/report bundles.

Offline acceptance tests block sockets and DNS and inventory network attempts.
A worker that attempts network access during an offline invocation fails with
`PRIVACY_VIOLATION`, even if it later returns valid-looking arrays.

The protocol states technical properties only. It does not claim GDPR, NHS, KCL,
HIPAA, medical-device, or institutional information-governance compliance.
“Diagnostic” in this protocol means a statistical sampling, convergence,
software, or transport/protocol check; it never means clinical diagnosis or a
participant-level clinical classification.

## 14. Compatibility and versioning

Protocol and schema versions are exact. The core MUST refuse an unknown major
version. Additive optional fields require a reviewed schema minor version and
must not change existing semantics. Any change to array orientation, stage/order
meaning, capability truth conditions, status meaning, privacy boundary, or hash
binding requires a new protocol major version and ADR.

There is no automatic best-effort downgrade. A worker may advertise multiple
exact supported versions during an out-of-band installation check, but one
invocation uses one exact version recorded in the request, response, cache key,
and run ledger.

## 15. Contract-test acceptance

Every worker is tested for:

1. closed request/response union shapes for every active command, `describe`
   schema, exact supported command/algorithm sets, stable identity, and
   capability truthfulness;
2. finite complete-data happy path and canonical result invariants;
3. unsupported missingness and invalid-group failures before fitting;
4. invalid setting and unavailable-output failures without substitution;
5. timeout, crash, partial-response, and output-size handling;
6. unexpected/outside file detection and safe cleanup;
7. same-seed repeatability and distinct-seed/no-cache behavior;
8. row permutation, explicit row-index round trip, deliberately reordered fit
   stage-output rows (which MUST fail), column/event remapping, and label
   alignment;
9. offline/no-network behavior and no raw identifier/value leakage;
10. one-to-one participant/event accounting and immutable request files; and
11. provenance binding to data, settings, code, backend, environment, chain, and
    seed; and
12. full-range `UInt64Hex` seeds, file-set/metadata binding, raw/proposal/burn/
    thinning off-by-one cases, and immutable worker-to-core convergence
    finalisation.

Passing this suite yields `PROTOCOL_CONFORMANT`. It does not establish model
validity, scientific suitability, or readiness by itself. Known-truth, oracle,
convergence, null, privacy, and fresh-environment gates remain separate, and
missing evidence remains explicit rather than inferred.
