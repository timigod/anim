# Privacy contract

## Status and scope

This is the normative privacy contract for EBM Robustness Auditor 0.1. `MUST`,
`MUST NOT`, `SHOULD`, and `MAY` are requirements in the sense used by RFC 2119.
It applies whenever a researcher supplies participant-level data, including input
validation, worker execution, caching, result generation, reporting, and failure
handling.

The repository currently contains public information and clearly labelled
synthetic fixtures only. The controls below are requirements for the product;
they are not evidence that an incomplete implementation has passed them. Until
the corresponding privacy tests pass, the control status is `UNVERIFIED`.

This contract describes technical behavior. It does not claim GDPR, NHS, KCL,
HIPAA, medical-device, or institutional information-governance compliance. The
researcher and institution remain responsible for approval, lawful use, storage,
retention, access control, and scientific governance.

## Data that must never enter this project repository

The repository, its Git history, issue trackers, corpus notes, test snapshots,
and documentation MUST NOT contain:

- participant-level research data, whether public, private, or controlled;
- reconstructed, inferred, scraped, or fabricated Idris/LonDownS participant
  rows;
- direct participant identifiers;
- reversible participant mappings;
- raw biomarker or cognitive measurements;
- row-level exports from a real-data audit; or
- logs, screenshots, stack traces, or example commands containing any of the
  above.

Development and committed tests MUST use only clearly labelled synthetic data.
Synthetic examples MUST use generic event names and MUST NOT imitate or claim to
reconstruct the Idris cohort.

## Participant-data-time boundary

A real audit MUST run locally inside a researcher-approved environment. The
auditor and report generator MUST work without:

- network access;
- telemetry or analytics;
- a cloud account, cloud service, or external API;
- remotely loaded fonts, scripts, images, styles, or other report assets;
- an LLM; or
- Docker or another container runtime.

Every participant-data command requires an explicit `--offline`
acknowledgement. The CLI also forces that posture before argument parsing and
has no online alternative. This is not a statement that the host has no
network interface. The core MUST refuse known network-backed configuration,
the test harness MUST block or detect socket and DNS attempts, and any observed
attempt MUST fail the affected operation. See
[`docs/security/threat-model.md`](docs/security/threat-model.md) for the limit of
this control with a malicious native worker.

Dependencies and worker environments SHOULD be acquired and verified before
participant data are opened. A local wheelhouse or institutionally approved
package mirror MAY be used during setup, but dependency acquisition MUST NOT be
mixed into a participant-data-time run.

## Identity model

The core MUST keep three identities distinct:

| Identity | Purpose | Allowed destinations |
| --- | --- | --- |
| `participant_private_id` | Researcher's stable source identity | Core memory and, only when explicitly requested, a separate private mapping file |
| `participant_internal_index` | Contiguous zero-based worker row index | Worker request/result bundles and private machine-readable run results |
| `participant_alias` | Pseudonymous review label such as `P-014` | Reports and influence summaries |

The core MUST validate private IDs for missingness and duplication, then create
the internal index and alias itself. It MUST NOT expose an encoded, unsalted, or
public hash of a private ID as an alias. The canonical identity map orders typed
private IDs by HMAC-SHA256 under a locally generated secret namespace key, then
assigns sequential internal indexes and aliases. This makes mapping deterministic
and row-order invariant for that private namespace without revealing the source
identifier. The namespace key, HMAC tokens, private IDs, and source row positions
remain in the private boundary and never enter a worker or default report.

Workers receive explicit contiguous internal integer index arrays only. A worker
request MUST NOT contain
private IDs, source ID column names, report aliases, reversible mappings, or
private paths that embed an identifier. The core MUST reject a result that adds
an undeclared identifier field. Every returned stage array carries and exactly
round-trips the corresponding index array; count equality does not prove row
alignment.

An optional reversible mapping is a separate high-risk artifact. It MUST be:

- created only after an explicit opt-in;
- written under the run's `private/` directory, never the report bundle;
- permission-restricted to its owner;
- excluded from default archive/export operations;
- excluded from default manifests and reports; if an integrity digest is retained,
  stored only in the private metadata beside the mapping;
- covered by the researcher's institutional retention and deletion policy.

The alias namespace key is also a private mode-`0600` run artifact. It MUST be
excluded from report/export bundles even when no reversible mapping is persisted.
Consequently `run/private/` always exists; “mapping disabled” means the mapping
file is absent, not that the private directory/key is absent. The run root and
private directories MUST be mode `0700` or stricter. The namespace key, optional
mapping, private alignment metadata, resolved sensitive configuration, and all
other sensitive durable files MUST be mode `0600` or stricter.

Pseudonyms reduce disclosure risk but are not anonymisation. Row-level stage
posteriors, influence results, and other derived outputs can remain sensitive
even without direct identifiers.

## Raw measurement handling

Raw numeric event values are necessary for validation and model fitting. They MAY
exist only in:

1. the researcher-owned input source;
2. core memory while validating or preparing one request;
3. one assigned, restrictive worker request directory; and
4. backend memory during that request.

The auditor MUST NOT create an unrequested working copy of the input dataset.
The default run directory, cache metadata, provenance, logs, exceptions, report,
figures, and warning/failure ledgers MUST NOT contain raw participant-level event
values. Default provenance records digests, shapes, counts, decisions, versions,
and statuses instead.

Machine-readable canonical results MAY contain row-level derived stage or
influence outputs keyed only by internal indexes or aliases. They MUST NOT contain
raw input measurements or direct identifiers, and MUST be treated as sensitive
research outputs rather than as publishable anonymised data.

Errors MUST describe schema location, type, count, range category, or shape. They
MUST NOT include a full row, a raw offending value, an input-data excerpt, a
private identifier, or an absolute private data path. Captured worker stdout and
stderr are untrusted and MUST be sanitised before any retained excerpt is written.
If safe sanitisation cannot be established, retain only the stream digest, byte
count, truncation state, and a privacy-safe error category.

## Temporary workspaces

Each worker invocation MUST receive a new, exclusive temporary directory owned
by the current user. The implementation MUST:

- create the directory with mode `0700` and request/result files with mode
  `0600`, subject to stricter institutional controls;
- avoid predictable shared paths and reject symlink traversal;
- pass raw data in files, never command-line arguments or environment variables;
- set the worker working directory to the assigned directory;
- record an allowlisted inventory of files read and written in the assigned tree
  and explicitly configured watched roots without recording raw contents or
  private source paths;
- reject observed writes or response references that escape the assigned
  directory;
- inventory unexpected files and fail the result as `PRIVACY_VIOLATION` or
  `PROTOCOL_ERROR` as appropriate;
- avoid placing temporary workspaces inside the repository; and
- attempt cleanup after success, typed failure, timeout, crash, or interruption.

Cleanup MUST validate the exact run-owned path before deletion. It MUST NOT follow
symlinks or recursively delete an unresolved, broad, or caller-supplied path. If
cleanup is incomplete, the run MUST record a privacy-safe stale-workspace receipt
and return a visible warning or failure. The receipt MAY contain a random
workspace token and cleanup command, but MUST NOT reveal the input filename or a
private path by default.

Deletion is best-effort file removal, not a guarantee of forensic erasure from
SSDs, backups, snapshots, or institutional storage. A researcher requiring secure
erasure MUST use institution-approved encrypted storage and lifecycle controls.

## Worker trust boundary

The command-worker protocol is dependency and failure isolation; by itself it is
not a security sandbox. A conforming worker MUST write only inside its assigned
directory, remain offline, avoid telemetry, avoid persistent caches, and return
only declared outputs. The core MUST validate and inventory its response.

A custom worker that is malicious, compromised, or implemented in native code
may ignore those rules and access anything its operating-system account can
access. Therefore:

- real data MUST be processed only by a worker whose code and dependency lock are
  trusted or institutionally reviewed;
- a merely passing `describe` or contract test MUST NOT be treated as proof that
  a hostile worker is safe;
- a worker that needs broader filesystem access or network access MUST NOT be used
  for a participant-data-time audit;
- untrusted workers require a separate OS account or institutionally approved
  sandbox with explicit filesystem and network denial; and
- separate worker-executable, worker-code, backend-source, environment, and
  capabilities digests MUST be bound into run provenance.

Without an OS filesystem sandbox, absence of an observed outside write proves
only the assigned/watched roots were clean; arbitrary filesystem containment is
`UNVERIFIED`. The normal supported boundary is trusted or institutionally
reviewed worker code. Untrusted code requires OS-level containment.

A misconfigured worker that crashes, writes unexpected files, attempts network,
prints raw values, substitutes a backend, or silently drops rows/events MUST
produce a visible typed failure. It MUST NOT contribute scientific evidence.

## Results, logs, reports, and caches

Default retained artifacts MAY contain:

- hashes, versions, settings, seeds, and canonical universe IDs;
- aggregate counts and missingness/outlier accounting;
- event identifiers or sanitised display names;
- pseudonymous aliases and derived influence components;
- order, position, precedence, convergence, null, and aggregate stage summaries;
- typed warnings, failures, and unsupported capabilities; and
- row-level derived output only in private machine-readable results, never in the
  default human-readable report unless explicitly designed and reviewed.

They MUST NOT contain private IDs, raw values, reversible mappings, source ID
column names, or full input rows. Cache keys MUST use cryptographic content
digests and complete scientific identity. A data digest is sensitive linkage
metadata: it MUST not be used as a public data fingerprint or sent externally.

The self-contained HTML report MUST make no network requests and MUST embed no
remote resources. It MUST use deterministic templates and MUST NOT invoke an LLM.
Static report text and machine-readable labels remain subject to the versioned
claim-language rules.

Failed, invalid, timed-out, non-converged, unsupported, and privacy-failed
universes remain in summary counts. A privacy failure MUST never be hidden by a
successful aggregate run status.

## Reference-result bundles

A reference bundle exported from an existing private notebook can contain
sensitive derived participant results. It MUST remain local, use internal indexes
or tokens instead of direct IDs, and be stored outside this repository. Participant
alignment MUST use a separate private source-ID-to-run-token mapping or a shared
private namespace plus exact dataset digest; positional/count alignment is not
enough. The
auditor MUST validate the bundle before comparison and MUST not copy it into the
public/report bundle.

The allowed statuses are:

- `BASELINE_REPRODUCED`
- `BASELINE_PARTIALLY_REPRODUCED`
- `BASELINE_NOT_REPRODUCED`
- `BASELINE_REFERENCE_NOT_SUPPLIED`

Similarity to a published figure or event order is never a reference result and
MUST NOT produce `BASELINE_REPRODUCED`.
Full reproduction additionally requires exact connected implementation/
algorithm/settings, preprocessing/inclusion, stage semantics, dataset binding,
and adequate richer order/stage outputs. Central order and counts alone can
produce at most `BASELINE_PARTIALLY_REPRODUCED`.

## Required privacy gates

Real-data readiness is blocked until automated tests prove at least:

- socket creation and DNS are blocked or detected in offline tests;
- worker requests contain internal indexes and no private IDs;
- default artifacts do not contain seeded test IDs or representative raw values;
- raw values do not appear in exceptions or captured worker output;
- temporary directory and file permissions are restrictive;
- symlink/path-escape attempts fail;
- an optional mapping is separate, opt-in, restrictive, and excluded by default;
- unexpected worker files and network attempts are visible failures;
- reports contain only declared aggregates, event metadata, and pseudonyms; and
- safe cleanup is exercised after success, crash, timeout, and interruption.

An unavailable or unrun gate is `UNVERIFIED`, never a pass.

## Researcher checklist before a real-data run

1. Obtain institutional approval and use an approved encrypted local workspace.
2. Install dependencies before opening participant data.
3. Review and pin the exact worker executable and environment.
4. Disconnect or institutionally block network access, then pass the required
   `--offline` acknowledgement; there is no online run mode.
5. Keep input data and any reference bundle outside the repository.
6. Run validation and inspect predicted row/event accounting before fitting.
7. Do not enable a reversible mapping unless it is required and approved.
8. Treat derived row-level results and data digests as sensitive.
9. Review stale temporary-workspace and privacy-failure receipts before archiving.
10. Export only the approved aggregate report bundle.
