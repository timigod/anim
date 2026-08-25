# Security policy and runtime contract

## Current status

Anim 0.1.1 is local research software. Its backend-neutral integration and
local audit path have completed the project's synthetic readiness review. This
is not a penetration-test certification, institutional approval, or scientific
approval of an EBM or dataset. A control remains `UNVERIFIED` unless a retained
test or review receipt proves it on the exact candidate and supported host.

Do not use participant data merely because this file describes intended
protections. A researcher must have separate institutional authority, privacy
review, approved local storage, and a reviewed worker. Anim's release readiness
does not certify a named backend or a future researcher-specific integration.

## Supported security posture

Version 0.1 is designed for one researcher running trusted, pinned code on an
approved local workstation. The supported path is:

- local CPU execution;
- explicit offline mode;
- a backend-neutral core and a separately installed command worker;
- one fresh, restrictive workspace per worker invocation;
- validated, hashed request and response bundles;
- no direct participant identifiers at the worker boundary;
- deterministic local reporting with no remote assets; and
- fail-closed statuses for malformed, unsupported, crashed, timed-out,
  non-converged, network-attempting, or privacy-violating work.

The product is not a multi-user service, access-control system, secure research
environment, malware sandbox, secrets manager, anonymisation tool, secure eraser,
or data-loss-prevention product. It does not make a worker safe merely by running
it as a subprocess.

The shipped top-level `sitecustomize.py` worker-containment sentinel is inert unless
`EBM_AUDIT_OFFLINE=1` and Anim supplies valid `EBM_AUDIT_WORK_DIR`,
`EBM_AUDIT_INVOCATION_ROOT`, `EBM_AUDIT_REQUEST_DIR`,
`EBM_AUDIT_NETWORK_ATTEMPT_FILE`, `EBM_AUDIT_OUTSIDE_ATTEMPT_FILE`, and
`EBM_AUDIT_GUARD_ACTIVE_FILE` values for that worker invocation.

## Trust assumptions

The security contract assumes:

1. the host OS, Python runtime, filesystem, and current user account are trusted;
2. input files are authorised for the researcher to process;
3. the auditor installation and dependency lock have been verified;
4. each real-data worker and its dependency environment are trusted or reviewed;
5. output and temporary roots are on researcher-approved local storage; and
6. the operator follows institutional rules for encryption, backups, access,
   retention, and deletion.

If a worker is untrusted or potentially malicious, run it under a separate OS
account or institutionally approved sandbox that denies network and restricts
filesystem access. Protocol validation, file inventories, and Python-level socket
tests detect important mistakes, but cannot contain arbitrary native code with
the same operating-system permissions as the researcher.

## Mandatory controls

### Offline execution

Every participant-data-time command MUST expose and honour `--offline`. Offline
mode MUST reject known remote configuration, disable telemetry, prevent the core
from initiating network access, propagate the offline requirement to the worker,
and treat a detected worker network attempt as a failed operation. Reports MUST
contain no CDN, web font, tracking pixel, remote script, remote image, or other
external dependency.

The test suite MUST block or detect DNS and socket creation in the core and test
workers. This is a release gate, not proof of kernel-level isolation. Native or
hostile workers require OS-level containment as described above.

### Worker process boundary

Worker commands MUST be passed as an argument vector from trusted configuration,
not interpolated into a shell command. Raw values, identifiers, credentials, and
private paths MUST NOT appear in arguments or environment variables. The worker
receives only a request directory, response directory, command, protocol version,
and non-secret resource/offline settings.

Each invocation MUST have:

- an exclusive working directory;
- a fixed timeout and process-tree termination path;
- explicit CPU/thread limits where supported;
- a minimal allowlisted environment;
- captured stdout and stderr with size limits and privacy sanitisation;
- an inventory of created files;
- response schema, hash, and scientific-invariant validation; and
- a typed terminal status.

Worker/request seeds are canonical 16-lowercase-hex `UInt64Hex` strings on every
wire/JCS boundary, not JSON numbers. Full-range and malformed-seed tests are part
of request parsing.

A timeout or crash MAY receive one byte-identical retry only when the runner's
declared transient-retry rule permits it. The retry, original failure, and shared
request digest MUST remain visible. Scientific failures MUST NOT be retried with
a changed seed or settings outside a declared universe.

### Request and response parsing

JSON is for metadata and small structured objects. Numeric arrays use NPZ and
MUST be loaded with `allow_pickle=False`. Parsers MUST enforce:

- exact protocol/schema versions;
- required fields and closed or explicitly versioned extension fields;
- size, dimensionality, dtype, finiteness, and count limits before allocation or
  fitting;
- filenames resolved beneath the assigned bundle root;
- no absolute paths, `..` traversal, symlink escape, device files, or FIFOs;
- declared SHA-256 digests for every bundle file;
- valid permutations, normalised probability arrays, and participant/event count
  invariants; and
- rejection of silent row, cell, or event loss.

NPZ is a ZIP container. Before ZIP or NumPy loading, implementations MUST bound
the raw central directory and member count; require an exact safe member set and
`ZIP_STORED`; reject ZIP64, encryption, data descriptors, extras, comments, and
unsupported flags; and charge aggregate uncompressed bytes against the remaining
invocation-tree budget. They MUST also reject duplicate names and arrays that
exceed the declared shape/byte budget. Hashes provide integrity and cache
identity, not authenticity; trust still depends on the local source and worker.

`request.json` and `response.json` are excluded from their own closed file maps.
The metadata digest is computed over the complete RFC 8785 object with only its
own digest member removed, so it binds the exact mandatory file set, paths,
lengths, and hashes. Parsers also enforce the command-discriminated request and
success payload and one exact negative-response shape.

### Filesystem and temporary data

Temporary directories MUST be mode `0700` and files mode `0600` or stricter. The
implementation MUST use exclusive creation, validate ownership and exact paths,
refuse symlink traversal, and never delete an unresolved or caller-selected broad
directory. A worker MUST write only under its assigned response/work directory.
Unexpected files, path escape, or unsafe cleanup are visible failures.

The run root and every private subdirectory MUST also be mode `0700`; namespace
keys, mappings, private alignment metadata, resolved sensitive configuration, and
other sensitive durable files MUST be mode `0600` or stricter. `run/private/`
always exists because the alias namespace key is mandatory even when reversible
mapping is disabled.

Assigned-tree and configured watched-root inventories detect observable outside
writes, but do not establish arbitrary filesystem containment. Without an OS
sandbox that property is `UNVERIFIED`; trusted/reviewed workers are the normal
participant-data boundary.

Raw input MUST not be copied into the run directory or cache. After a worker
terminal state, the core MUST attempt bounded, path-validated cleanup and record
a privacy-safe stale-workspace receipt if it cannot complete. Removal is not a
claim of forensic erasure.

### Logging and error handling

Logs, exceptions, ledgers, and reports MUST NOT contain direct identifiers, raw
event values, full rows, credentials, reversible mappings, or sensitive command
arguments. They SHOULD record category, field role, count, shape, digest,
executable identity, elapsed time, and typed status.

Untrusted worker output MUST be bounded and sanitised. If a safe excerpt cannot
be guaranteed, retain only a digest, byte count, truncation flag, and error
category. Global warning suppression is forbidden. Failed, invalid, unsupported,
non-converged, and privacy-failed universes MUST remain visible.

### Supply chain and executable identity

The core and every worker MUST record exact versions, acquired-artifact hashes,
and separate core-code, worker-executable, worker-code, backend-source, and
environment digests under the protocol's normative preimages. The core MUST not import an
EBM backend. The optional `pysaebm` reference worker is valid only for exact
source commit `54521a9adfedf58facd7bafd741a14d9ed110d2a`, expected source version
`7.7.9`, and the separately verified environment and licence bytes. PyPI version
`7.7.7` is not equivalent.

No backend source may be copied or vendored to bypass installation, licence, or
identity checks. A worker MUST NOT substitute a backend, algorithm, seed, or
configuration. Any expected-versus-observed identity drift is always
`PROTOCOL_ERROR`, never `INVALID_SPECIFICATION` or a warning-only success.
Only the first data-free discovery describe may be unpinned. The core retains
and recomputes the complete base backend identity, base digest, selected
algorithm, selected identity digest, and selected capabilities digest before
allowing configured describe, self-test, validate, fit, or stage to launch.

Dependency acquisition is a setup operation. Release evidence MUST include a
fresh locked installation and an offline end-to-end run. Anim is distributed
under Apache-2.0. Optional EBM backends remain separate installations with their
own licence, identity, and review requirements.

### Cache and provenance integrity

A cached result is reusable only when the full scientific and executable identity
matches: input digest, selected participants/events, preprocessing and group
rules, event directions, protocol and schema versions, the five distinct code/
executable/backend/environment digests, settings, canonical string seed, and
result schema.
Upstream backend caches MUST NOT be trusted or reused.

Same-seed repeatability, different-seed cache separation, row/column remapping
invariance, and serial/parallel equivalence are release gates. Cache mismatch,
partial write, or digest failure MUST leave a visible failure and MUST NOT return
a result as successful.

## Security-relevant statuses

The protocol terminal statuses include:

- `SUCCESS`
- `INVALID_INPUT`
- `UNSUPPORTED_CAPABILITY`
- `INVALID_SPECIFICATION`
- `BACKEND_ERROR`
- `TIMEOUT`
- `CONVERGENCE_FAILED`
- `CONVERGENCE_NOT_ASSESSABLE`
- `PRIVACY_VIOLATION`
- `PROTOCOL_ERROR`

A worker `SUCCESS` is immutable candidate evidence for one command/chain, not a
core-final scientific success. The core writes a separate final result after the
complete cross-chain convergence rule; it may quarantine all successful chain
responses as `CONVERGENCE_FAILED` or `CONVERGENCE_NOT_ASSESSABLE` without
rewriting or discarding them. Only a fully validated core-final `SUCCESS` can
contribute scientific outputs. All failures remain in summaries. A privacy or
protocol failure cannot be downgraded because other universes succeeded.

Baseline-reference status is independent of process success:

- `BASELINE_REPRODUCED`
- `BASELINE_PARTIALLY_REPRODUCED`
- `BASELINE_NOT_REPRODUCED`
- `BASELINE_REFERENCE_NOT_SUPPLIED`

No status may be inferred from similarity to a publication figure or reported
event order.

“Diagnostic” in this policy means a statistical sampling, convergence, software,
or protocol check. It does not authorize a clinical diagnostic claim or
participant classification.

## Security release gates

The exact release candidate MUST pass:

- no-network tests for core, worker invocation, and generated report;
- seeded identifier/raw-value scans over all default artifacts and errors;
- restrictive-permission and safe-cleanup tests, including crash and timeout;
- path traversal, symlink, malformed JSON, hostile NPZ, and oversized-input tests;
- command argument and environment leakage tests;
- timeout/process-tree and output-size-limit tests;
- worker unexpected-file and backend-identity-substitution tests;
- cache poisoning/partial-write/digest-mismatch tests;
- deterministic report and external-resource scans;
- fresh locked installation and offline synthetic end-to-end execution; and
- an independent privacy/security review with no unresolved P0/P1 finding.

An unavailable test is `UNVERIFIED`. A hard privacy failure blocks real-data
readiness regardless of aggregate benchmark results.

## Reporting a security or privacy issue

Do not place participant data, direct identifiers, raw values, credentials, or
private paths in a bug report. Record a minimal local reproduction using synthetic
data, the affected version or commit, operating system, typed status, and
sanitised digests. Submit the report through a
[private GitHub security advisory](https://github.com/timigod/anim/security/advisories/new),
not a public issue. Never attach participant data or a real-data artifact to the
advisory. Use the institution's incident channel for any matter that requires
sharing sensitive evidence.

If a real-data run may have disclosed or retained sensitive material:

1. stop the affected run and do not rerun it;
2. preserve only privacy-safe evidence needed to identify the affected paths and
   process;
3. restrict access to the run and temporary roots;
4. follow the institution's incident process and retention instructions;
5. mark the result `PRIVACY_VIOLATION`; and
6. do not treat any output from that operation as accepted scientific evidence.

The detailed threat analysis and residual risks are in
[`docs/security/threat-model.md`](docs/security/threat-model.md). Data-handling
rules are in [`PRIVACY.md`](PRIVACY.md).
