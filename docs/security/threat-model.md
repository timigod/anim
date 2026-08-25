# Threat model

## 1. Purpose and assurance state

This threat model defines the minimum security boundary for local EBM Robustness
Auditor 0.1 execution. It is normative for implementation and release review. It
does not claim that an unfinished build already implements the controls. Each
control remains `UNVERIFIED` until exercised on the exact release candidate.

The safety objective is narrow: process authorised participant data locally,
without network dependence, while preventing direct identifiers and raw
measurements from entering default retained artifacts or worker metadata, and
while making backend failures and side effects visible.

The model does not establish institutional compliance, anonymity, scientific
validity, or containment of hostile native code running with the researcher's OS
permissions.

## 2. Assets

| Asset | Sensitivity | Required protection |
| --- | --- | --- |
| Source dataset and private IDs | Highest | Remain in researcher-approved local storage; no repository, report, log, cache, or network disclosure |
| Raw event measurements and covariates | Highest | Exist only in source, core memory, and one temporary worker request; never in default retained artifacts |
| Alias namespace key and reversible ID-to-alias mapping | Highest | `private/` always exists for the owner-only key; mapping is opt-in and separate; both excluded from exports |
| Row-level derived stages/influence | Sensitive | Internal index or alias only; private machine-readable result; not treated as anonymous |
| Reference-result bundle | Sensitive | Local and separately controlled; no direct IDs; not copied into report bundle |
| Event names, units, directions, group rules | Scientific metadata; may still be private | Sanitise configurable source column names and private paths; retain only declared display metadata |
| Configuration, seeds, hashes, software identity | Provenance; hashes can be linkable | Integrity protected, local by default, no external transmission |
| Failure/warning ledger | Operational | Complete and tamper-evident by digest; privacy-safe contents |
| Benchmark and claim-language rules | Scientific safety | Versioned and integrity-bound; unavailable checks never become passes |

## 3. Actors and trust levels

### Trusted

- the authorised researcher operating an approved local workstation;
- the reviewed EBM Robustness Auditor core at a recorded commit/version;
- a reviewed worker executable and exact dependency environment;
- the local OS and filesystem controls supplied by the approved environment.

### Fallible but not intentionally hostile

- a custom worker with an incorrect schema, hidden cache, unexpected side effect,
  unsafe logging, unsupported missingness, or false capability declaration;
- a malformed or partially written reference/result bundle;
- a researcher configuration with wrong paths, aliases, event directions, group
  rules, or resource limits;
- a backend that crashes, hangs, changes behavior, or emits warnings/files.

### Potentially hostile

- a modified worker or dependency attempting data exfiltration;
- crafted JSON/NPZ input attempting path traversal, unsafe deserialisation,
  decompression/resource exhaustion, or schema confusion;
- another local process able to read permissive temporary files;
- a report consumer opening HTML that contains an external resource or active
  injection;
- a compromised dependency or substituted executable.

## 4. Trust boundaries and data flow

```text
Researcher-owned source
  private ID + event values + groups/covariates
                |
                v
        [Core input boundary]
  schema validation; ID separation; accounting
                |
                | explicit contiguous row-index arrays + numeric arrays + settings
                v
   [Restrictive per-invocation request directory]
                |
                v
       [External command worker]
  separate environment/process; untrusted output
                |
                | response bundle + captured streams + file inventory
                v
       [Core response boundary]
  hashes; schemas; numerical/scientific invariants; sanitisation
                |
          +-----+-------------------+
          |                         |
          v                         v
 [Private machine result]     [Default report/ledgers]
 internal indexes/derived     aliases, aggregates, statuses,
 participant outputs          hashes, no raw values/direct IDs
```

Boundary A, source to core, is an input-validation boundary. Boundary B, core to
worker, removes direct identifiers but necessarily carries raw measurements.
Boundary C, worker to core, treats every file and byte of stdout/stderr as
untrusted. Boundary D, retained output, is a disclosure-control boundary.

The subprocess boundary isolates Python environments, ordinary crashes, logging
configuration, and expected file side effects. Without OS sandboxing it is not a
confidentiality boundary against a malicious worker.

Profile-characterization authority and one-shot publication assume the
auditor's own process is trusted. Their supported public APIs prevent ordinary
stale, duplicate, or conflicting use; weak canonical-authority reclamation is a
lifecycle rule, not a security boundary. Arbitrary same-process reflection,
debugger access, mutation of private in-memory registries, and compromise of the
Python interpreter or process memory are outside this control's threat model.
An attacker with those capabilities can bypass process-local invariants and
requires a separate OS or process-isolation boundary.

## 5. Threats, controls, and verification

### T01 — network exfiltration or telemetry

**Threat.** Core, worker, dependency, report asset, DNS lookup, crash reporter, or
analytics library transmits data or metadata.

**Controls.** Participant-data commands require an explicit `--offline`
acknowledgement, force that posture before argument parsing, and expose no
online alternative; no cloud/API/LLM or remote report asset is allowed; core
network configuration is rejected; the worker receives an offline requirement;
tests block or detect DNS and socket creation; a detected attempt terminates the
operation as `PRIVACY_VIOLATION`.

**Verification.** Run no-socket/no-DNS tests against core and reference/fixture
workers, scan HTML/CSS/JS for external URLs and requests, and run the synthetic
end-to-end path with network denied. Retain exact command and terminal receipt.

**Residual risk.** Python monkeypatches and application hooks do not stop hostile
native code or a subprocess deliberately bypassing them. A non-reviewed worker
requires OS-level network denial under a separate account or approved sandbox.

### T02 — direct identifier crosses the worker or output boundary

**Threat.** Source IDs, identifying column names, filenames, or reversible aliases
appear in requests, results, logs, reports, cache metadata, or exceptions.

**Controls.** Core-generated contiguous internal indexes; aliases assigned through
a secret-keyed, private namespace rather than by displaying an encoded/public hash
of an ID; no IDs in worker requests; reversible mapping is opt-in and separate;
namespace key/tokens remain private; private paths are redacted; output schemas
reject undeclared identity fields. Public planning values are checked by private
token type: physical column names and raw labels require exact matches; full
private paths, plus string participant IDs, filenames, stems, and non-common
path components of eight or more characters, are also rejected when embedded in
longer text. Shorter nonempty string participant IDs are rejected when bounded
on both sides by the string edge or a non-alphanumeric Unicode character; this
deliberately fails closed for single-character or generic string IDs such as `1`
in `rule-1`, while avoiding a match inside a larger word. Underscores and slashes
are delimiters. Shorter path-derived tokens remain exact-only. Integer IDs are
not converted to strings, avoiding collisions with ordinary public counts and
rule parameters. Mapping keys are structural and are not treated as published
values.

**Verification.** Use distinctive synthetic canary IDs and source-column names,
then recursively scan request metadata, response metadata, logs, ledgers, report,
cache, and exception text. Contract-test workers receive only internal indexes.

**Residual risk.** Aliases and derived outcomes can be re-identifiable when
combined with outside knowledge. They remain sensitive.

### T03 — raw values leak through normal or failure output

**Threat.** Measurements appear in verbose logs, validation errors, warnings,
tracebacks, plots, captured worker streams, config snapshots, or copied inputs.

**Controls.** Errors use field role/type/count/shape rather than values or rows;
worker streams are bounded and sanitised; default provenance contains digests and
counts; raw input is not copied to the run/cache; reports show aggregates and
pseudonyms only.

**Verification.** Seed representative unique raw-value canaries, trigger validation
errors, backend errors, timeout, crash, and malformed response, then scan all
default artifacts and terminal captures. A match is a hard privacy failure.

**Residual risk.** A hostile worker can encode values into apparently benign text
or timing. Use reviewed workers and OS containment for adversarial code.

### T04 — permissive or stale temporary files

**Threat.** Another local user/process reads request files, or a crash leaves raw
values in a predictable/shared path.

**Controls.** Exclusive random directory mode `0700`; files mode `0600`; no repo
temp roots; bounded process termination; cleanup on all terminal paths; visible
stale-workspace receipt on incomplete cleanup.

The run root/private directories are also mode `0700`; namespace key, optional
mapping, private alignment metadata, and other sensitive durable files are mode
`0600`. `private/` exists even when no reversible mapping is requested.

**Verification.** Assert permissions, uniqueness, ownership, cleanup after success,
error, crash, timeout, and interruption, and safe behavior when a file is open or
cleanup is intentionally failed.

**Residual risk.** Privileged host processes, backups, snapshots, swap, and storage
forensics are outside application control. Use approved encrypted infrastructure.

### T05 — path traversal, symlink, or unsafe deletion

**Threat.** Crafted paths escape the request root, overwrite unrelated files, or
cause cleanup of a broad/caller-controlled directory.

**Controls.** Core creates roots; bundle paths are relative allowlisted filenames;
resolve-and-containment checks; no symlink/device/FIFO acceptance; exclusive file
creation; deletion only after exact ownership/root validation and without following
symlinks. Reattachment requires the caller-held random `run_root_id` and compares
it with the authenticated identity inside the root, so a different valid run root
moved into the expected path is rejected.

**Verification.** Test absolute paths, `..`, alternate separators where relevant,
symlink swaps, nested symlinks, hard links where detectable, device/FIFO entries,
an authenticated foreign-root swap, and an empty/root/home deletion target. All
must fail without touching the target.

**Residual risk.** Platform-specific filesystem races require careful primitives
and independent review; path-string prefix checks alone are insufficient.

### T06 — unsafe NPZ/JSON parsing or resource exhaustion

**Threat.** Pickled objects execute code, ZIP expansion exhausts disk/memory,
oversized shapes allocate resources, duplicate keys confuse validation, or NaN/
infinity reaches an unsafe backend.

**Controls.** `allow_pickle=False`; protocol and schema version checks; closed
required fields; member count/compressed/uncompressed byte limits; declared shape
and dtype limits before load; duplicate member/name rejection; finiteness and
capability validation before fitting.

**Verification.** Fuzz malformed JSON, unknown versions, duplicate JSON/ZIP names,
object arrays, truncated ZIPs, expansion bombs, enormous declared shapes, wrong
dtypes, NaNs, infinities, and count mismatches.

**Residual risk.** Parser/library vulnerabilities remain supply-chain risks; exact
dependencies and security review are required.

### T07 — shell injection or secret leakage through invocation

**Threat.** Worker paths/settings are shell-interpolated, or data/private paths are
placed in argv/environment and exposed to process listings or crash reports.

**Controls.** Invoke an explicit argument vector without a shell; allowlisted
non-secret environment; bundle files carry data; worker executable/config is
validated and identity-bound.

**Verification.** Use worker paths and settings containing spaces and shell
metacharacters; prove they are literal. Inspect recorded argv/environment keys and
process receipts for canaries.

**Residual risk.** The approved worker necessarily knows its request directory and
can inspect local environment permitted by the OS.

### T08 — worker writes outside its workspace or persists a cache

**Threat.** A backend creates logs, plots, caches, or configuration in the repo,
home directory, or upstream default path; later runs reuse stale scientific state.

**Controls.** Fresh working directory; minimal `HOME`/cache variables pointing to
run-owned scratch when safe; before/after inventory of the assigned workspace;
worker contract forbids external writes and upstream cache reuse; executable and
result identity are complete.

**Verification.** Contract tests use a side-effecting fixture, watch declared
sentinel roots where feasible, inventory unexpected files, and compare same- and
different-seed runs for cache contamination.

**Residual risk.** File inventory cannot observe arbitrary writes outside watched
roots. A malicious/native worker needs OS filesystem containment.

### T09 — worker lies about identity, capabilities, settings, or row/event use

**Threat.** Worker substitutes a backend or algorithm, ignores a seed, accepts an
unsupported feature, reorders labels, or silently drops data.

**Controls.** `describe` and every response carry protocol, separate core-code,
worker-executable, worker-code, backend-source and environment digests,
`capabilities_digest`, canonical string seed, settings, input, and output digests;
only the first data-free discovery describe may be unpinned, and core blocks
configured describe, self-test, validate, fit, and stage before launch unless it
has the complete reviewed base identity, selected-algorithm identity, and
capabilities pin;
core validates participant/event counts, included/excluded manifests, canonical
permutations, exact request/response row-index alignment, posterior shapes, and
numerical invariants; no silent drop is allowed. Any identity drift is always
`PROTOCOL_ERROR`.

**Verification.** Contract tests cover identity drift, false capabilities, seed
substitution, row/column permutation, ID remapping, event-label alignment, missing
rows/events, invalid probability arrays, and settings mismatch.

**Residual risk.** A coordinated malicious worker can forge self-reported
metadata. Trust requires code/environment review or external attestation supplied
by the approved institution.

### T10 — stdout/stderr or failure-ledger denial/disclosure

**Threat.** Worker emits unbounded output, terminal escape sequences, identifiers,
values, or binary data; the runner deadlocks or retains sensitive streams.

**Controls.** Concurrent bounded capture, timeout, truncation marker, control-
character neutralisation, privacy sanitisation, digest-only fallback, and no
scientific parsing from stdout/stderr.

**Verification.** Test large streams on both descriptors, no-newline streams,
binary/control bytes, raw-value canaries, and a process that keeps a descriptor
open through a child.

**Residual risk.** Sanitisation cannot prove absence of encoded data. Default to
digest-only retention when output is not known-safe.

### T11 — report exfiltration or active-content injection

**Threat.** Event display names, warnings, or metadata inject HTML/JS; report loads
remote resources or leaks local paths/data.

**Controls.** Context-sensitive output escaping, self-contained local assets,
deterministic templates, no LLM, no remote URLs, no inline execution dependent on
untrusted content, sanitised paths, versioned language rules.

**Verification.** Inject markup/script/URL/control-character event names and
warnings; scan and open the result with network blocked; verify deterministic
bytes and no request attempts.

**Residual risk.** Browser vulnerabilities and user-added post-processing are
outside the product boundary. Static figures are preferred where practical.

### T12 — cache/provenance poisoning or partial writes

**Threat.** Result from different data, seed, code, worker, or settings is reused;
an interrupted write is accepted; a digest is mistaken for proof of source
authenticity.

**Controls.** Complete cache identity, content hashes, write-to-exclusive-temp then
atomic finalisation, terminal manifest written last, no upstream caches, and
revalidation on read.

**Verification.** Vary every cache-identity component independently, interrupt at
each write phase, corrupt files/manifests, and prove miss/failure rather than reuse.

**Residual risk.** SHA-256 collision is not a material operational risk here, but
local file replacement by a privileged attacker remains outside the assumed host
trust boundary.

### T13 — reference baseline falsely marked reproduced

**Threat.** Similarity to the paper's published order, a partial output, or a
different preprocessing/model configuration is called reproduction.

**Controls.** Reference comparison requires a researcher-supplied canonical
bundle bound to the exact dataset and aligned through a private source-ID-to-run-
token mapping or shared private namespace. It compares exact connected
implementation/algorithm/settings/stage semantics, event identities, central
order, adequate richer uncertainty/stage outputs, inclusion counts,
preprocessing manifest, and statistical diagnostics; records one of four exact
baseline statuses; unavailable required comparisons cannot pass. Central order
and counts alone can produce at most partial reproduction.

**Verification.** Test no reference, partial reference, incompatible event set,
settings/preprocessing mismatch, count mismatch, order-only similarity, and a
fully matching fixture. Reorder reference rows while preserving counts and prove
private-token alignment succeeds or missing positional-only alignment fails.

**Residual risk.** A reference bundle reflects what the exporting notebook chose
to expose. Scientific equivalence still requires researcher/methods review.

### T14 — failure disappearance or unsafe scientific claim

**Threat.** Failed/unsupported/non-converged universes disappear, privacy failure
is hidden by aggregate success, or deterministic report text overstates evidence.

**Controls.** Immutable per-worker-response ledger plus a separate core-final
result; typed statuses; terminal count
reconciliation; hard claim-language rules; baseline and null gates independent of
fit success; a cross-chain convergence failure quarantines but never rewrites or
deletes successful chain evidence; prohibited diagnosis/prognosis/treatment/
causal/regulatory claims.

**Verification.** Inject every terminal status and reconcile plan-to-summary
counts; force null and convergence failures; scan rendered labels for forbidden
language; prove a privacy failure blocks readiness.

**Residual risk.** Downstream readers may overinterpret correct cautious language;
domain and supervisory review remains required.

In this threat model, “diagnostic” always means a statistical sampling,
convergence, software, or protocol check. It never means clinical diagnosis or a
participant-level clinical classification.

### T15 — dependency or executable substitution

**Threat.** A different package/version/source commit or compromised transitive
dependency runs under a familiar worker name.

**Controls.** Exact direct/transitive lock, acquired-artifact hashes, executable
and environment digest, source/version/licence checks, separate worker environment,
no source vendoring, fresh-install gate.

**Verification.** Recreate the environment from the lock, check every artifact,
deliberately alter worker/dependency identity, and require a hard mismatch. For
the reference worker, exact `pysaebm` commit and source version must match.

**Residual risk.** A lock does not prove upstream source is benign. Dependency and
licence review remains a release requirement.

## 6. Malicious versus misconfigured worker boundary

The product promises strong validation of a conforming or accidentally broken
worker. It can detect protocol violations, malformed results, unexpected files in
the assigned directory, leaked canaries in captured output, timeouts, crashes,
identity drift, and test-observable network attempts.

It does not promise to contain a deliberately hostile worker with the same OS
access as the researcher. A malicious process could read the source dataset,
write outside monitored roots, use native networking, inspect unrelated files, or
encode data in allowed outputs. For such a worker, the minimum safe boundary is a
separate OS identity or approved sandbox with:

- read access only to one request directory;
- write access only to one response/scratch directory;
- no network interface or denied outbound network;
- resource and process limits; and
- no access to the repository, private mappings, source dataset, credentials, or
  unrelated home directories.

Containerisation is not required by the product and is not automatically trusted.
Institutional containment may use OS-native mechanisms. The audit report must
record the actual containment state rather than imply it.

## 7. Security/privacy gate outcomes

Any of the following blocks real-data readiness:

- a direct identifier or raw measurement in a default artifact;
- an observed network attempt in offline mode;
- a worker path escape or unsafe cleanup;
- unbounded or unsanitised captured output;
- silent participant/event/cell loss;
- backend or environment identity mismatch;
- a privacy/protocol failure omitted from the run summary;
- an unrun hard privacy test reported as passed; or
- an unresolved P0/P1 privacy/security review finding.

An unavailable capability or check is retained as `UNVERIFIED` or
`UNSUPPORTED_CAPABILITY`; it is never converted to `SUCCESS`. See
[`PRIVACY.md`](../../PRIVACY.md) for researcher-facing handling rules and
[`SECURITY.md`](../../SECURITY.md) for the release and incident policy.
