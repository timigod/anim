# Artifact hashing and freeze contract

This developer reference defines how exact files and selected fields identify
inputs, software, and verification records. A hash detects changed bytes; it
does not prove who supplied them. “Preimage” means the exact bytes or fields
hashed; “domain” is the prefix that distinguishes one type of identity from
another.

Some tables retain historical evaluator and worker definitions. In particular,
older `/1` worker hash inputs below are not the active v2 protocol. Use the
[protocol registry](../../schemas/protocol-registry.json) and
[worker protocol](adapter-protocol.md) for new integrations. See the
[technical reference guide](../handoff/technical-reference-guide.md) for the
specific differences and historical files absent from the public package.
The retained historical values below have not been rewritten.

Status: `FROZEN`
Contract version: `artifact-freeze/v0.1.0`

This contract defines the bytes used to identify the benchmark, generator,
implementation candidate, environments, and held-out commitments. A displayed Git
commit, filename, or self-reported version is useful provenance but is not a
substitute for these SHA-256 identities.

## 1. Canonical structured bytes

Machine contracts in YAML are loaded with a strict YAML 1.2 loader that rejects
duplicate keys, aliases, merge keys, non-string mapping keys, tags, NaN, infinity,
timestamps, and values outside the JSON data model. JSON is loaded with duplicate-
key rejection. Every string value and object key MUST already be NFC. The parser
rejects a non-NFC string; it MUST NOT normalize, replace, trim, case-fold, or
otherwise repair it before validation or hashing. Integer-valued JSON numbers
MUST be in `[-(2^53-1), 2^53-1]`; full-width seeds and other 64-bit identifiers are
lowercase fixed-width hexadecimal strings instead of JSON numbers.

The resulting JSON value is serialized as UTF-8 RFC 8785 JSON Canonicalization
Scheme (JCS) bytes with no byte-order mark or trailing newline. This project uses
two explicit, non-interchangeable textual encodings of the same 32 digest bytes:

```text
Sha256Digest = "sha256:" + lowercase_hex(32 digest bytes)
Sha256Hex = lowercase_hex(32 digest bytes)
```

`Sha256Digest` is the `SHA-256` type used by the core schemas, protocol, file
catalogs, source-entry hashes, and ordinary provenance. `Sha256Hex` is used only
by evaluator/freeze fields explicitly named `*_sha256`, `contract_sha256`, or
`candidate_sha256`, and by commitment preimages that call `hex_to_bytes`. Such
fields are exactly 64 lowercase hex characters with no prefix. A consumer MUST
NOT strip or add a prefix implicitly; the containing schema selects the type.

Every structured digest preimage is
`ASCII(domain) || NUL || RFC8785-JCS(object)`. Every domain is fixed below or in
the owning schema. Exact-file digests alone hash unprefixed file bytes. The
digest bytes are then rendered as the field's declared `Sha256Digest` or
`Sha256Hex`; the rendering does not add, remove, or replace the domain.

Parsing and canonicalization versions and the exact `REJECT_NON_NFC` policy are
part of every freeze receipt. A file that cannot pass this conversion cannot be
frozen. This rejection rule also applies to display strings that do not
participate in a path or identifier; JCS is serialization, not Unicode repair.
The executable reference uses the exact offline dependency `rfc8785==0.1.4`.
Both independent verifier modules must reproduce the same fixed RFC 8785 vectors,
including `1.0 -> 1`, `-0.0 -> 0`, ECMAScript exponent formatting, escaping,
and UTF-16 object-key ordering, and must produce the same domain-separated
digest. Python `json.dumps`, a locale formatter, or a self-described
"canonical" encoder is not interchangeable evidence.

## 2. Benchmark-contract digest

Before hashing `evaluator/benchmark_contract.yaml`, all freeze-time fields except
`contract_sha256` are populated, including version, status, date, source
identities, and rule versions. The hash projection is the complete parsed object
with `contract_sha256` set to JSON `null`. No other field is omitted. The raw
lowercase `Sha256Hex` of
`SHA256("ebm-audit/benchmark-contract/1" || NUL || JCS(projection))` becomes
`contract_sha256`, in agreement
with the machine-readable rule inside the benchmark contract.

Verification repeats the same projection and requires equality. Hashing the raw
YAML bytes is additionally allowed as a transport checksum, but it is not the
scientific contract identity.

The tracked frozen contract records every freeze-time field and its verified
self-hash. Recalculating a different digest never silently changes the contract;
that requires a new reviewed version.

## 3. Held-out manifest-template digest

The protected held-out manifest is a template, not an attempt state file. Its
exact projection is the machine-readable
`canonical_hash_contract.manifest_template_projection` inside that manifest:
apply every listed `set_null_json_pointers` transformation, then every listed
`set_literal_json_pointers` transformation, and exclude no field. An unknown,
missing, duplicate, or multiply targeted pointer is a hard failure. No field may
be transformed unless it appears in that closed projection object. The raw
lowercase `Sha256Hex` of
`SHA256("ebm-audit/heldout-manifest-template/1" || NUL || JCS(projection))` is
`heldout_manifest_template_sha256`.

All fields changed while binding or executing an attempt are covered by that
closed projection. The tracked template already contains the projected null and
literal values, so hashing it after applying the projection produces the same
bytes. Applying the projection to a populated private attempt copy MUST reproduce
the tracked template digest; this is the verification path that prevents attempt
metadata from redefining the template.

At held-out execution, the template is copied into a permission-restricted attempt
directory and populated there. Attempt identifiers, candidate and contract
digests, the root commitment, sealed-case manifest digest, and sealed-results
digest never mutate the tracked template or the already frozen implementation
candidate.

## 4. Candidate tree digest

A held-out candidate MUST be a clean, local Git commit. Untracked files, ignored
environments, run directories, private mappings, held-out roots, generated
results, and `.git/` are not candidate inputs. Every committed tree entry is
enumerated recursively without following symlinks and sorted by the UTF-8 bytes of
its already-NFC repository-relative POSIX path. A non-NFC candidate path is
rejected; the enumerator never normalizes or repairs it.

The candidate manifest is the closed `CandidateTreeManifest` in
[`../../schemas/source-set-manifest.schema.json`](../../schemas/source-set-manifest.schema.json).
`git_commit` is Git provenance and `candidate_sha256` is the evaluator identity;
neither field may be substituted for or parsed as the other. `GitSha1Oid` is
exactly 40 lowercase hexadecimal characters and `GitSha256Oid` is exactly 64;
the `git_object_format` discriminator selects one type. A generic 41--63 digit
hexadecimal value is never a Git object ID:

```json
{
  "schema_version": "ebm-audit-candidate-tree/1.0",
  "git_object_format": "sha1",
  "git_commit": "full lowercase Git object id",
  "entries": [
    {
      "path": "repository/relative/path",
      "git_mode": "100644",
      "kind": "file",
      "byte_length": 123,
      "sha256": "sha256:<digest>"
    }
  ]
}
```

Regular-file hashes cover exact bytes. A symlink entry uses `kind="symlink"` and
hashes the exact link-target bytes stored by Git; it is never dereferenced. Git
submodules are prohibited in the release candidate unless a later reviewed
contract defines their recursive identity. The raw lowercase `Sha256Hex` of
`SHA256("ebm-audit/candidate-tree/1" || NUL || JCS(manifest))` is
`candidate_sha256`. Entry-level `sha256` values remain
prefixed `Sha256Digest` values. The manifest and digest are written before held-
out root generation.

Repository-local Markdown link verification covers tracked, materialized project
documentation. It deliberately excludes the ignored sparse-upstream evidence file
`research/probes/pysaebm/README.md`: its six links point into upstream paths that
were intentionally not materialized. That exclusion is not a claim that those
targets exist locally and does not exclude any shipped or normative project note.

## 5. Source-component and environment digests

Code and prose components use the closed, versioned `SourceSetManifest` in
[`../../schemas/source-set-manifest.schema.json`](../../schemas/source-set-manifest.schema.json),
not an invented parse of Markdown. It has schema version
`ebm-audit-source-set/1.0`, a closed ordered list of declared root paths, and the
same recursively enumerated entry shape and path/mode/symlink rules as the
candidate manifest. Exact file bytes are entry-level `Sha256Digest` values. Roots
and entries are sorted by their already-NFC UTF-8 path bytes; a non-UTF-8 path,
non-NFC path, duplicate path, or normalization collision is a hard failure and is
never repaired. Every entry is under exactly one declared root and every root
contributes at least one entry. The raw `Sha256Hex` of
`SHA256("ebm-audit/source-set/1" || NUL ||
JCS({component_kind, destination_field, manifest}))` is the component field
stored by the evaluator. `component_kind`, `destination_field`, and the exact
ordered `declared_roots` vector are a closed discriminated union in the source-set
schema; identical bytes cannot substitute for another component or destination.

Source identity is observed, never supplied. The evaluator reads the committed
entry set and modes from the candidate's exact `HEAD` tree, reads committed blob
bytes from Git, and separately walks the physical filesystem without following
symlinks. The manifest passes only when those two complete sets and every mode,
kind, byte length, and byte digest agree exactly. A missing tracked entry, dirty
tracked byte or mode, unexpected or untracked entry under a declared root, or
missing/empty required root is a pre-freeze failure. The executable fixture
proves both a clean temporary Git tree and the corresponding dirty, fabricated,
and untracked-file rejections. The production evaluator source root now exists
and contributes its exact committed entries to the frozen source identity.

The closed vectors are:

- `generator_sha256`: `docs/spec/synthetic-and-null-validation.md`,
  `src/ebm_audit/synthetic`, and `uv.lock`;
- `metrics_rules_sha256`: `docs/spec/metrics-and-uncertainty.md`;
- `report_language_rules_sha256`: `docs/spec/report-language-rules.md`;
- `evaluator_source_sha256`: the exact fifteen roots
  `evaluator/scenario_derivation_registry.json`,
  `evaluator/scenario_predicate_registry.yaml`,
  `schemas/cli-lifecycle-registry.json`,
  `schemas/evaluator-receipts.schema.json`, `schemas/protocol-registry.json`,
  `schemas/scenario-derivation-registry.schema.json`,
  `schemas/scenario-evidence.schema.json`,
  `schemas/scenario-family-payload.schema.json`,
  `schemas/scenario-fixture-evidence.schema.json`,
  `schemas/scenario-fixture-contract.schema.json`,
  `schemas/scenario-fixture-predicate.schema.json`,
  `schemas/scenario-predicate.schema.json`,
  `schemas/scientific-invariant-counterexample.schema.json`,
  `schemas/scientific-invariant.schema.json`, and
  `src/ebm_audit/evaluator`;
- `normative_authority_sha256`: exactly the accepted public readiness
  specification, `docs/spec/ebm-integration-readiness-1.2.0-candidate.md`.

Every declared root must exist and contribute an entry. The evaluator root is
present in the frozen tree; future absence or emptiness remains a pre-freeze
failure and is never converted into a hashable empty source set.

This completeness rule is executable twice. Each discriminated source-set
schema restricts every entry to one of its closed roots and uses Draft 2020-12
`contains`/`minContains` constraints for every root, including at least one
`src/ebm_audit/evaluator/` entry. The registered runtime rule
`source-set-root-coverage-exact/1` then verifies the committed filesystem/tree
enumeration, exact-one-root ownership, and contribution counts before hashing.
The read-only reference enumerator uses the committed `HEAD` tree and matching filesystem
bytes, rejects unmerged or prohibited modes, reads regular files directly, reads
symlink target bytes without dereferencing them, and compares every observation
with the manifest. Schema success without that runtime enumeration is not a
freeze pass. A genuinely missing root emits the typed outcome
`BLOCKED/PRE_FREEZE_BLOCKED/SOURCE.COMMITTED_ROOT_OR_BYTE_IDENTITY_MISSING`; the
frozen tree instead records the independently recomputable positive evaluator
source identity and never accepts an invented manifest.

`generator_sha256` covers the declared generator implementation source, its
generator contract/schema source, and the exact generator dependency lock.
`metrics_rules_sha256` and `report_language_rules_sha256` each cover their
declared normative Markdown source set as exact bytes. Scenario/development YAML
uses the benchmark's strict YAML-to-JCS projection and domain
`ebm-audit/scenario-definitions/1`; its raw `Sha256Hex` is stored as
`scenario_definitions_sha256`. Sealed case and result indexes use domains
`ebm-audit/sealed-case-manifest/1` and `ebm-audit/sealed-results/1`
respectively. The benchmark contract lists all declared paths and domains;
missing or extra roots are a freeze failure. A plain unprefixed hash of the JCS
bytes is not interchangeable with any of these identities.

An environment digest uses domain `ebm-audit/environment/1` over the complete
closed `EnvironmentIdentity` in
[`../../schemas/canonical-records.schema.json`](../../schemas/canonical-records.schema.json).
That object contains exactly `environment_schema_version`; `runtime`
(`implementation`, `version`, `executable_digest`, and nullable
`launch_manifest_digest`); `platform` (`os`, `architecture`, and `abi`);
`lock_digest`; the ordered `installed_distributions` entries (`name`, `version`,
nullable `acquisition_digest`, and `direct_file_inventory_digest`); and the
ordered `native_libraries` entries (`name`, nullable `version`, and
`file_inventory_digest`). No second environment-manifest shape is permitted.
Absolute installation paths and timestamps are recorded separately and do not
change the environment identity. The digest uses the core/protocol
`Sha256Digest` encoding. Missing acquisition identity is explicit `null` plus
`UNVERIFIED` evidence and can never be an empty or substituted digest.

### 5.1 Nonrecursive worker artifact identity

`worker_fit_payload_digest` is computed over the complete closed
`WorkerFitPayloadDigestPreimage` in
[`../../schemas/worker-protocol.schema.json`](../../schemas/worker-protocol.schema.json).
That preimage is the fit payload with its own digest field absent. An artifact
inside it MUST NOT name the digest of the payload that is still being created.
Instead, each artifact binds the already established `creating_chain_execution_id`
and `creating_scientific_request_digest` plus its content digest and backend,
environment, settings, algorithm, event, and stage-semantics identities. This
orders the graph as request/execution identity, then artifact bytes, then fit
payload. There is no fixed-point search and no nested creating-payload
backreference to project away.

`response_metadata_digest` is the only wire response-metadata identity. It uses
domain `ebm-audit/worker-response-metadata/1` over the complete closed
`WorkerResponseMetadataDigestPreimage`, which is the validated `WorkerResponse`
with only `response_metadata_digest` absent. The evaluator does not reuse that
domain for a different projection. The separately named command-specific
evaluator bindings retain the already verified wire digest, replace the response
payload with its independently verified command-specific payload digest, and
represent the file map as a UTF-8-path-sorted closed catalog.
`validate_evaluator_worker_response_binding_sha256` uses
`ebm-audit/validate-evaluator-worker-response-binding/1` and
`ValidateEvaluatorWorkerResponseBinding`; the fit equivalents use
`ebm-audit/fit-evaluator-worker-response-binding/1` and
`FitEvaluatorWorkerResponseBinding`. Each is a closed success-or-negative union,
and a negative validate/fit payload version is that command's exact non-null
version. Negative command evidence also carries exactly one recomputed actual
validate or fit subject digest. If any actual-subject component is unavailable,
the response fails as `PROTOCOL_ERROR` and cannot become benchmark-subject
evidence; the evaluator never substitutes the expected subject.

### 5.2 Held-out benchmark subject identity

One readiness held-out attempt evaluates exactly one backend-neutral integration
subject: the exact project-owned `SYNTHETIC-ONLY` conformance EBM through the
ordinary generic worker. The closed `BenchmarkSubjectIdentity` in
[`../../schemas/evaluator-receipts.schema.json`](../../schemas/evaluator-receipts.schema.json)
is populated and validated before the root is drawn:

```text
BenchmarkSubjectIdentity
  subject_schema_version: Literal["ebm-audit-benchmark-subject/1.0"]
  subject_kind: Literal["synthetic-only-conformance-ebm"]
  backend_identity_digest: Sha256Digest
  adapter_id / adapter_version: exact strings
  backend_name: stable non-null machine ID
  backend_version: exact string | null when genuinely unavailable
  algorithm_id: exact string
  worker_executable_digest / worker_code_digest: Sha256Digest
  backend_source_commit: exact full commit | null for a reviewed opaque backend
  backend_source_digest: Sha256Digest | null only for a reviewed opaque backend
  environment_digest / capabilities_digest / settings_digest: Sha256Digest
  protocol_version / request_schema_version / response_schema_version: exact strings
  worker_payload_schema_version: exact string
  requested_outputs_digest: Sha256Digest
  benchmark_profile_id / convergence_rule_id / null_calibration_rule_id: exact strings
  candidate_git_object_format: Literal["sha1", "sha256"]
  candidate_git_commit: GitSha1Oid when sha1; GitSha256Oid when sha256
  candidate_sha256 / contract_sha256: Sha256Hex
```

`backend_identity_digest` uses domain `ebm-audit/backend-identity/1` over the
complete closed `BackendIdentity`. Here, backend-named fields identify the exact
implementation behind the conformance EBM; they do not require a named external
backend or an external qualification registry. Every worker-bound subject field is
first reconstructed from the validated request, response, backend identity, and,
for a successful response, its validate/fit payload as the command-specific
`ActualValidateWorkerSubjectProjection` or
`ActualFitWorkerSubjectProjection` in
[`../../schemas/worker-protocol.schema.json`](../../schemas/worker-protocol.schema.json).
Their `actual_validate_worker_subject_digest` and
`actual_fit_worker_subject_digest` use distinct command-specific domains and
are also required on their respective typed negative command evidence. Negative
evidence carries the corresponding complete closed subject preimage; the
evaluator schema-validates it, independently reconstructs it from the validated
request and response, requires exact equality, and recomputes the canonical
domain-separated digest. A merely well-formed substituted SHA is a protocol
failure. The evaluator then combines those exact
worker-bound fields with the evaluator-owned profile, convergence, calibration,
candidate, and contract fields to reconstruct the complete subject. The
recomputed subject must byte-match the committed object. Merely copying an
expected `benchmark_subject_digest` into a result is not evidence.
`benchmark_subject_digest` uses domain
`ebm-audit/benchmark-subject/1` over this complete object and is a prefixed
`Sha256Digest`. The private attempt manifest, root commitment preimage, sealed
case manifest, sealed results, authenticated score-evidence root, evaluation
receipt, score receipt, and score-validation receipt all bind that exact digest.
Any component drift ends the attempt before another fit.

The complete readiness subject graph additionally binds the frozen candidate,
ordinary generic worker executable and code, complete settings and requested
outputs, environment, generator and scenario source identities, and each sealed
case's generated known-truth identity. Generator and known-truth owners are
added only at their frozen commitment stage; they are never moved before root
commitment or exposed to a fit. Subject, worker, configuration, generator, or
known-truth mismatch fails closed and cannot reuse evidence.

No readiness precondition or result depends on an external qualification registry,
an acceptance-state transition, or prior acceptance. Scientific scoring derives
a sealed `PASS`, `WARN`, or `FAIL` from the exact authenticated score root, and
the `ScoreValidationReceipt` binds the exact evaluation, score, rule and gate
vectors, aggregate branch, fixed offline commands, and terminal timestamp. A
typed registered-UNIMPLEMENTED failure or any other fail-closed validation error
produces no readiness completion evidence.

A named-backend acceptance profile is permitted only as optional downstream
per-integration qualification. It must bind its own exact subject and evidence,
cannot replace the conformance subject, and cannot gate library readiness or
change the readiness held-out result.

### 5.3 Closed structured-digest registry

Every structured digest used by the freeze/evaluator has one owning domain and
one closed preimage. The generic form is the Section 1 structured-digest form;
the `object` column below is the complete JCS object and no implicit field may be
added or omitted. Fields named `*_sha256` are `Sha256Hex`; fields named
`*_digest` or `*_id` are prefixed `Sha256Digest` unless the row explicitly says
otherwise.

| Field | Domain | Complete object |
| --- | --- | --- |
| `contract_sha256` | `ebm-audit/benchmark-contract/1` | Complete parsed contract with only `contract_sha256=null`. |
| `heldout_manifest_template_sha256` | `ebm-audit/heldout-manifest-template/1` | Complete manifest after its closed JSON-pointer projection. |
| `candidate_sha256` | `ebm-audit/candidate-tree/1` | Complete executable `CandidateTreeManifest`, including separately typed Git provenance. |
| component source `*_sha256` | `ebm-audit/source-set/1` | Complete executable `SourceSetDigestPreimage` `{component_kind,destination_field,manifest}` using its exact closed root vector. |
| `scenario_definitions_sha256` | `ebm-audit/scenario-definitions/1` | Complete strict-YAML JSON value. |
| `scenario_derivation_registry_sha256` | `ebm-audit/scenario-derivation-registry/1` | Complete closed 23-family/102-field derivation registry with `digest_state=DIGEST_PREIMAGE` and only its own hash null. |
| `scenario_predicate_registry_sha256` | `ebm-audit/scenario-predicate-registry/1` | Complete closed substantive predicate schema; the fixture predicate schema is a separate, non-eligible registry. |
| `scenario_source_owner_manifest_sha256` | `ebm-audit/scenario-source-owner-manifest/1` | Complete ordered typed source-owner manifest with `digest_state=DIGEST_PREIMAGE` and only its own hash null. |
| scenario owner `source_record_sha256` | `ebm-audit/scenario-source-record/1` | Complete `{owner_class,natural_identity,source_record}` object after the source record passes the exact registry-selected owner schema. |
| `canonical_array_artifact_owner_sha256` | `ebm-audit/canonical-array-artifact-owner/1` | Complete canonical-array artifact owner with `digest_state=DIGEST_PREIMAGE` and only its own hash null. |
| `preprocessing_execution_record_sha256` | `ebm-audit/preprocessing-execution-record/1` | Complete typed preprocessing execution record with `digest_state=DIGEST_PREIMAGE` and only its own hash null. |
| `report_predicate_outcome_sha256` | `ebm-audit/report-predicate-outcome/1` | Complete deterministic report-predicate outcome with `digest_state=DIGEST_PREIMAGE` and only its own hash null. |
| `scenario_derived_field_sha256` | `ebm-audit/scenario-derived-field/1` | Complete payload-leaf value, exact output schema/derivation identity, and ordered typed owner vector, with only its own hash null in the digest preimage. |
| `evidence_tree_manifest_sha256` | `ebm-audit/scenario-evidence-tree-manifest/1` | Complete exact-byte evidence tree with `digest_state=DIGEST_PREIMAGE` and only its own hash null. |
| `family_evidence_sha256` | `ebm-audit/substantive-scenario-family-evidence/1` | Complete substantive family evidence with exact cases, derived fields, owner/tree identities, predicate result, eligibility markers, and only its own hash null in the digest preimage. |
| `scenario_family_evaluation_receipt_sha256` | `ebm-audit/scenario-family-evaluation-receipt/1` | Complete one-family evaluator receipt derived from substantive family evidence, with only its own hash null in the digest preimage. |
| `development_scenario_evaluation_receipt_sha256` | `ebm-audit/development-scenario-evaluation-receipt/3` | Reserved unresolved reference only. The current positive receipt schema is intentionally unsatisfiable because its family `RuleOutcome` evidence type is held-out-score-rooted. A later reviewed migration must replace it with a distinct qualification-only development assessment before issuance. |
| `profile_synthetic_event_binding_sha256` | `ebm-audit/profile-synthetic-event-binding/1` | Complete coordinate-bound owner for the exact synthetic authority, source contract, parameter manifest, generator configuration, resolver methods, `E01 -> e01` through `E09 -> e09` mapping, truth/analysis directions, and float64 centers, with only its own digest null. |
| `profile_execution_source_manifest_sha256` | `ebm-audit/profile-execution-source-manifest/1` | Complete ordered six-role declared fit-sensitive source manifest for generation, preparation, seed, request-execution, capture, and metric-calculation, with state `DECLARED_PRE_EXECUTION_NOT_ATTESTED`, an exact pre-fit candidate-tree derivation-and-match requirement, and only its own digest null. |
| `profile_worker_invocation_semantics_sha256` | `ebm-audit/profile-worker-invocation-semantics/1` | Exact closed worker invocation preimage containing the `WorkerCommand.argv` token vector and normalized timeout. |
| `profile_execution_identity_sha256` | `ebm-audit/profile-execution-identity/1` | Complete candidate-independent fit-sensitive execution identity with only its own digest null. It binds public scenario authority, coordinate/event-binding and AnalysisSpec identities, backend and environment, requested outputs, canonicalization, chain count, the no-cache/no-checkpoint/no-retry policy, observation policy, narrow source-manifest digest, and exact invocation-semantics digest. Candidate, contract, selection policy, and broad source-set provenance are excluded. |
| `profile_public_seed` | `ebm-audit/profile-public-seed/2` | Exact execution-identity, authenticated coordinate-specific event-binding, and chain-ID preimage; the seed is the first eight SHA-256 bytes interpreted as an unsigned big-endian integer. Candidate and budget are excluded. |
| `profile_characterization_plan_receipt_sha256` | `ebm-audit/profile-characterization-plan-receipt/3` | Complete fixed pre-execution intent with only its own digest null: candidate and contract provenance; five complete declared but not-yet-attested source-set identities; the narrow six-role execution-source manifest; candidate-independent execution identity; complete backend/environment identities; six signal coordinates and exact event bindings; three profile-refined AnalysisSpecs; exact canonical nine-output request; distinct experimental subjects and subject/backend bindings; six rotations; fresh serial execution with cache, checkpoint, and retry prohibited; public-seed policy; 18 logical case-chain slots; three ordered direct budget relations; closed evidence/metric registry; exact 6/18/54 cardinalities; paired-runtime policy; and fail-closed selection policy. The same 54 fit results supply transition review. It contains no generated data, final seed, result, metric value, reviewed transition decision, selection, release subject, or freeze claim. |
| `blocked_profile_diagnostic_sha256` | `ebm-audit/blocked-profile-diagnostic/2` | Complete plan-bound historical pre-execution diagnostic with only its own digest null. It records the earlier state before the retained 54-fit run. The six-case public authority and authenticated plan issuer already exist. It is not benchmark evidence and cannot override later retained evidence. |
| `pre_candidate_qualification_receipt_sha256` | `ebm-audit/pre-candidate-qualification-receipt/2` | Typed blocked record binding the exact final-candidate development evidence and two mandatory predicate IDs. It remains `BLOCKED` and candidate-freeze-ineligible until the authoritative 23-family resolver exists. |
| `heldout_scenario_evaluation_receipt_sha256` | `ebm-audit/heldout-scenario-evaluation-receipt/1` | Complete exact ordered 23-family held-out receipt, sealed-result/comparator bindings, source-owner identity, and only its own hash null in the digest preimage. This is the sole scenario-family score owner. |
| typed score `source_record_sha256` | `ebm-audit/score-source-evidence/1` | Complete registry-selected `TypedScoreSourceRecordBody` with `digest_state=DIGEST_PREIMAGE` and only `source_record_sha256=null`. The evaluator recomputes every source receipt before deriving an aggregate state. |
| `source_validation_registry_sha256` | `ebm-audit/score-source-validation-registry/1` | Complete ordered 101-row `ScoreSourceValidationRegistry`. It fixes each source key, owner schema, validator identity, implementation status, and scientific-pass eligibility. |
| `score_evidence_root_sha256` | `ebm-audit/score-evidence-root/1` | Complete closed `ScoreEvidenceBundleDigestPreimage`, including all fixed identities, the 14 core evidence references, 101 ordered source references, exact repository tree, source-validation-registry digest, and owner-authentication tag, with only its own root hash null. |
| `benchmark_freeze_receipt_sha256` | `ebm-audit/benchmark-freeze-receipt/3` | Complete subject-neutral blocked benchmark evidence audit with exact ordered equality to all 28 governing predicate rows and recomputed typed-owner hashes. It is not a freeze: current-byte resolution, registered-check execution, and predicate rederivation remain unavailable. |
| `evidence_owner_sha256` | `ebm-audit/freeze-predicate-evidence-owner/2` | One complete subject-neutral typed `FreezePredicateEvidenceOwnerDigestPreimage` for exactly one registered benchmark-freeze predicate, with only its own hash null. |
| `blocked_pre_root_diagnostic_sha256` | `ebm-audit/blocked-pre-root-diagnostic/1` | Complete blocked diagnostic binding benchmark freeze, unresolved development reference, qualification, candidate freeze, candidate, readiness integration subject, contract, source vector, and time. It fixes `ROOT_NOT_DRAWN`, creates no held-out attempt or root receipt, and grants no authority. |
| `candidate_freeze_receipt_sha256` | `ebm-audit/candidate-freeze-receipt/3` | Typed blocked candidate-freeze record. It binds the intended candidate tree and subject but fixes `candidate_frozen=false` until decisive pre-candidate qualification can be rederived. |
| `acceptance_candidate_transition_receipt_sha256` | `ebm-audit/acceptance-candidate-transition-receipt/2` | Legacy optional named-backend per-integration qualification record. It is excluded from the readiness root, attempt identity, score, and completion decision and cannot gate the library. |
| `heldout_attempt_id` | `ebm-audit/heldout-attempt/3` | Future-only complete `HeldoutAttemptIdentityPreimage` v4. No current blocked phase may construct it. Its later producer must bind a successfully frozen candidate and the exact readiness integration subject to the exact plan, source vector, private-root commitment, and positive authority receipts. |
| `operation_instance_id` | `ebm-audit/benchmark-operation-instance/1` | Complete `BenchmarkOperationInstancePreimage` for one held-out attempt, operation-matrix row, analysis specification, case coordinates, expansion axis, and expansion index. |
| `sealed_operation_plan_sha256` | `ebm-audit/sealed-operation-plan/1` | Complete evaluator-authenticated ordered `SealedOperationPlanDigestPreimage` v2, fixing the exact `AnalysisPlan/3` and `PreparationReceipt/2` digests. It has exactly one typed entry for every sealed case/analysis-spec slot and no chain rows. Every entry contains its operation preimage, case, analysis-spec ID and ordinal, operation kind, and comparator coordinates when applicable. Per-chain work is owned separately by `FrozenChainPlanDigestPreimage`. |
| `frozen_chain_plan_index_sha256` | `ebm-audit/frozen-chain-plan-index/2` | Complete ordered `FrozenChainPlanIndex` v2 with `digest_state=DIGEST_PREIMAGE` and only its own hash null. It carries the exact held-out-attempt preimage plus the one complete independently authenticated `AnalysisPlan/3` and `PreparationReceipt/2` owner pair used by the shared score/terminal/scientific identity resolver, even when every terminal universe is compile-time non-success and `ordered_plans` is empty. |
| `sealed_case_manifest_sha256` | `ebm-audit/sealed-case-manifest/1` | Complete evaluator-authenticated executable `SealedCaseManifest`. |
| `sealed_case_manifest_receipt_sha256` | `ebm-audit/sealed-case-manifest-receipt/1` | Complete executable `SealedCaseManifestReceiptDigestPreimage`; its persisted counterpart is non-null. |
| `one_shot_execution_receipt_sha256` | `ebm-audit/one-shot-execution-receipt/1` | Complete executable `OneShotExecutionReceiptDigestPreimage`; its persisted counterpart is non-null. |
| `sealed_results_sha256` | `ebm-audit/sealed-results/1` | Complete executable `SealedResultsIndex`. |
| `sealed_output_receipt_sha256` | `ebm-audit/sealed-output-receipt/1` | Complete executable `SealedOutputReceiptDigestPreimage`; its persisted counterpart is non-null. |
| `evaluation_receipt_sha256` | `ebm-audit/evaluation-receipt/1` | Complete executable `EvaluationReceiptDigestPreimage`; its persisted counterpart is non-null. |
| `RuleOutcome.evidence_sha256` | `ebm-audit/mandatory-rule-evidence/1` | Exact closed `ScoreAggregateEvidenceDigestPreimage` `{preimage_schema_version,score_evidence_root_sha256,source_validation_registry_sha256,aggregate_kind=MANDATORY_RULE,aggregate_id=registered rule_id}`. The authenticated root commits exact files and the registry commits their ordered validation meaning; alternate or counts-only owners are invalid. |
| non-baseline `BackendGateResult.evidence_sha256` | `ebm-audit/backend-gate-evidence/1` | Exact closed `ScoreAggregateEvidenceDigestPreimage` with the same root and registry, `aggregate_kind=BACKEND_GATE`, and the registered gate ID. The baseline gate instead points to the complete baseline-reproduction owner. |
| `rule_outcomes_sha256` | `ebm-audit/rule-outcomes/1` | Complete UTF-8 rule-ID-sorted array of executable `RuleOutcome` objects. |
| `score_receipt_sha256` | `ebm-audit/score-receipt/1` | Complete executable `ScoreReceiptDigestPreimage`; its persisted counterpart is non-null. |
| `score_validation_receipt_sha256` | `ebm-audit/score-validation-receipt/1` | Complete `ScoreValidationReceiptDigestPreimage` with `digest_state=DIGEST_PREIMAGE` and only its own hash null. Its private owner tag authenticates the exact score root, source registry, evaluation, score, rule vector, gate vector, aggregate branch, fixed commands, and workflow timestamp. |
| `score_validation_failure_record_sha256` | `ebm-audit/score-validation-failure-record/1` | Complete `ScoreValidationFailureRecordDigestPreimage` with `digest_state=DIGEST_PREIMAGE` and only its own hash null. The current typed boundary is exactly the three registered UNIMPLEMENTED semantic/source failures; it always forbids validation-receipt emission, and any optional downstream qualification remains unreachable. |
| `applicable_gate_results_sha256` | `ebm-audit/backend-applicable-gates/1` | Complete UTF-8 gate-ID-sorted array of executable `BackendGateResult` objects. |
| `backend_acceptance_receipt_sha256` | `ebm-audit/backend-acceptance-receipt/1` | Complete executable optional named-backend per-integration qualification preimage. It is downstream of product readiness and is not a readiness receipt. |
| `resolved_generator_configuration_sha256`, `comparator_pre_override_configuration_sha256`, `comparator_post_override_configuration_sha256`, `source_preoperation_resolved_generator_configuration_sha256`, and `member_postoperation_resolved_generator_configuration_sha256` | `ebm-audit/resolved-generator-configuration/1` | Executable raw `ResolvedGeneratorConfiguration`; these fields are roles for the same raw-object identity and are never aliases for audit configuration. |
| `case_configuration_sha256` | `ebm-audit/audit-case-configuration/1` | Complete canonical audit-case configuration preimage from the protocol schema; this identity is never an alias for generator configuration. |
| `matched_comparator_plan_evidence_sha256` | `ebm-audit/matched-comparator-plan-evidence/1` | Complete closed `MatchedComparatorPlanEvidence` before generation or execution. |
| `matched_comparator_execution_binding_sha256` | `ebm-audit/matched-comparator-execution-binding/1` | Complete closed `MatchedComparatorEvidence`, including raw/canonical member identities, equality evidence, subject/runtime identities, and four chain bindings. |
| `matched_comparator_evidence_sha256` | `ebm-audit/matched-comparator-evidence-manifest/1` | Complete `MatchedComparatorEvidenceManifestDigestPreimage`, with `digest_state=DIGEST_PREIMAGE` and only its own hash null. |
| `null_calibration_identity_digest` | `ebm-audit/null-calibration-identity/1` | Complete closed `NullCalibrationIdentity`, including the exact integration subject or conformance subject under evaluation, worker/backend, algorithm/settings, environment, candidate, statistic route, null procedures, convergence/profile, rules, and contract. |
| `refit_steps_digest` | `ebm-audit/refit-steps/1` | Complete closed `RefitStepsDigestPreimage` `{schema_version,digest_state=DIGEST_PREIMAGE,null_calibration_identity_digest,ordered_step_ids,refit_steps_digest=null}`. `ordered_step_ids` is exactly `prepared-input binding`, `authenticated worker invocation`, `fit-result validation`, `convergence derivation`, `pairwise concentration`, `position concentration` in that order. Persisted `RefitStepsEvidence` changes only `digest_state=PERSISTED` and stores the recomputed prefixed digest. Operation-role evidence is authenticated separately by the candidate decision and never enters this equality digest. |
| `candidate_strong_evidence_decision_sha256` / manifest `candidate_decision_sha256` | `ebm-audit/candidate-strong-evidence-decision/1` | Complete closed `CandidateStrongEvidenceDecision` with six ordered family/statistic tests, exact failed preconditions, and the pre-authorization state. |
| `false_positive_opportunity_manifest_sha256` | `ebm-audit/false-positive-opportunity-manifest/1` | Complete 60-opportunity `FalsePositiveOpportunityManifestDigestPreimage` with only its own hash null. |
| `false_positive_evaluation_sha256` | `ebm-audit/false-positive-evaluation/1` | Complete closed `FalsePositiveEvaluation` reconstructing the candidate-decision numerator, fixed denominator, rate, exact upper bound, and gate state. |
| `resolved_parameter_manifest_sha256` | `ebm-audit/resolved-parameter-manifest/1` | Executable `ResolvedParameterManifest` with `digest_state=DIGEST_PREIMAGE` and only its self hash null. |
| `resolved_generator_mechanism_sha256` | `ebm-audit/resolved-generator-mechanism/1` | Executable `ResolvedGeneratorMechanism` with `digest_state=DIGEST_PREIMAGE` and only its self hash null. |
| `component_seed_manifest_sha256` | `ebm-audit/component-seed-manifest/1` | Executable `ComponentSeedManifest` with `digest_state=DIGEST_PREIMAGE` and only its self hash null. |
| `generated_scientific_data_sha256` | `ebm-audit/generated-scientific-data/1` | Complete raw `SyntheticScientificData`; this object identity is never an alias for canonical auditor input. |
| `input_digest` | `ebm-audit/scientific-data/1` | When non-null, the complete canonical `ScientificDataDigestPreimage`; this identity is never an alias for the raw generated object or exact-file byte digest. It is null only for the exact pre-canonical invalid unprepared branches registered in `protocol-registry.json`. |
| `truth_object_sha256` | `ebm-audit/synthetic-truth/1` | Executable `SyntheticTruthObject` with `digest_state=DIGEST_PREIMAGE` and only `truth_object_sha256=null`. |
| resample/removal/transformation `*_sha256` | `ebm-audit/benchmark-operation-manifest/1` | Executable `BenchmarkOperationManifest` with `manifest_kind` exactly `resample`, `removal`, or `transformation` and the corresponding complete closed manifest. |
| scenario contract-fixture standard-array `array_digest` | `ebm-audit/array/1` | Recomputed from the literal worker artifact-file bytes after proving they equal canonical little-endian C-order values, plus the closed standard member name, dtype, case-sized shape, semantic version, byte length, and exact-byte digest preimage. A supplied array digest is never accepted. The reconstructed catalog entry must equal the fit response payload and path-free canonical chain; the file hash/reference must equal the fit payload's `backend_artifacts` entry and worker backend identity. This byte-ownership fixture is marked non-eligible for scientific acceptance. |
| contract-fixture `metric_input_projection_digest` | `ebm-audit/scenario-contract-fixture-case-metric-input/1` | Complete evaluator-built contract projection for the four standard arrays, its versioned synthetic-to-canonical event-ID mapping, and `[N,N]`, `[N,N]`, `[P]`, `[P,N+1]` case dimensions. It carries `CONTRACT_CLOSURE_FIXTURE_ONLY` and `scientific_acceptance_eligible=false`, validates literal array ownership only, and cannot establish substantive family metrics. |
| contract-fixture `metric_source_digest` | `ebm-audit/scenario-contract-fixture-derivation-registry/1` | Evaluator-generated fixture registry of output fields and array source locators. It is never supplied by the evidence producer and is explicitly insufficient as the production 23-family derivation registry. |
| contract-fixture `scenario_case_scientific_record_sha256` | `ebm-audit/scenario-contract-fixture-case-record/1` | Complete fixture-only case record with `digest_state=DIGEST_PREIMAGE`, only its self hash null, and the same explicit non-eligibility markers. It cannot be reused as a production `ScenarioCaseScientificRecord`. |
| `finalized_result_record_sha256` | `ebm-audit/finalized-result-record/1` | Complete immutable core `ResultRecord`, including its independently validated `result_id`; this pre-protected provenance identity is not an evaluator receipt or a bare result ID. |
| contract-fixture `scenario_family_evaluation_sha256` | `ebm-audit/scenario-contract-fixture-family-evaluation/1` | Complete fixture-only family evaluation with `digest_state=DIGEST_PREIMAGE`, every ordered fixture binding, and explicit non-eligibility markers. It yields a `PROCEDURE` receipt and cannot be reused as scientific family acceptance. |
| `canonical_scientific_payload_sha256` | `ebm-audit/canonical-scientific-payload/1` | Complete executable `CanonicalScientificPayload` from Section 7. |
| `frozen_chain_plan_sha256` | `ebm-audit/frozen-chain-plan/1` | Complete evaluator-authenticated ordered `FrozenChainPlanDigestPreimage` v3, binding the attempt, subject, operation, exact AnalysisPlan/3 schema version and digest, candidate ordinal, candidate ID, analysis specification ID, complete `UniverseIdentityPreimage`, universe, and every planned chain execution, attempt, ordinal, chain ID, seed, and command-specific `scientific_request_digest`. Candidate ID equals analysis specification ID. Acceptance additionally requires independently authenticated complete `AnalysisPlan/3` and `PreparationReceipt/2` owners: their existing digests are recomputed, the exact ordinal is resolved, and the selected PREPARED `UniverseSpec/3` projects byte-for-byte to the frozen preimage and chain rows. `HeldoutAttemptIdentityPreimage` v4 fixes the plan digest and `SealedOperationPlanDigestPreimage` v2 fixes both plan and receipt digests before the `/3` universe, chain-execution, and attempt identities are derived. Its null-tag preimage is authenticated under `ebm-audit/frozen-chain-plan-authentication/1`. |
| `request_metadata_digest` | `ebm-audit/worker-request-metadata/1` | Complete closed `WorkerRequestMetadataDigestPreimage`: the validated worker request with only `request_metadata_digest` removed. |
| `response_metadata_digest` | `ebm-audit/worker-response-metadata/1` | Complete executable `WorkerResponseMetadataDigestPreimage`, the wire response with only `response_metadata_digest` absent. |
| `validate_evaluator_worker_response_binding_sha256` | `ebm-audit/validate-evaluator-worker-response-binding/1` | Complete executable command-specific `ValidateEvaluatorWorkerResponseBinding`; this evaluator projection is not the wire response digest. |
| `fit_evaluator_worker_response_binding_sha256` | `ebm-audit/fit-evaluator-worker-response-binding/1` | Complete executable command-specific `FitEvaluatorWorkerResponseBinding`; this evaluator projection is not the wire response digest. |
| `scientific_request_digest` | `ebm-audit/scientific-request/1` | Exact `ScientificCommandRequestProjection`: validate excludes the four transport fields only; fit also excludes attempt ID/ordinal exactly as the schema registry declares. The field is exactly `null` for `describe`, `stage`, and `self-test`; those commands have no preimage in this domain and remain fully bound by request metadata. |
| `settings_schema_digest` | `ebm-audit/settings-schema/1` | Complete inline closed `ClosedSettingsSchema` from the selected described algorithm. |
| `settings_digest` | `ebm-audit/settings/1` | Complete settings object, after validation against that exact described schema. |
| `capabilities_digest` | `ebm-audit/capabilities/1` | Complete `AdapterCapabilities` object from the uniquely selected described algorithm and repeated response owner. |
| `backend_identity_digest` | `ebm-audit/backend-identity/1` | Complete closed `BackendIdentity` response owner. |
| requested-output `registry_digest` | `ebm-audit/requested-output-registry/1` | Complete closed requested-output rows in registry order, including each row's capability-absence behavior when present. |
| `requested_outputs_digest` | `ebm-audit/requested-outputs/1` | Complete `{registry_digest, command, requested_outputs}` object, with outputs unique and sorted by the protocol registry's canonical order. |
| `worker_validation_payload_digest` | `ebm-audit/worker-validation-payload/1` | Complete executable `WorkerValidationPayloadDigestPreimage`. |
| `worker_fit_payload_digest` | `ebm-audit/worker-fit-payload/1` | Complete executable `WorkerFitPayloadDigestPreimage`; artifacts bind prior request/execution identity and contain no creating-payload backreference. |
| `chain_payload_digest` | `ebm-audit/final-chain-payload/1` | Complete closed `FinalChainScientificPayload` with only `chain_payload_digest` removed. |
| `actual_validate_worker_subject_digest` | `ebm-audit/actual-validate-worker-subject/1` | Complete closed `ActualValidateWorkerSubjectProjection`, carried by negative evidence and independently reconstructed from validated validate evidence before digest comparison. |
| `actual_fit_worker_subject_digest` | `ebm-audit/actual-fit-worker-subject/1` | Complete closed `ActualFitWorkerSubjectProjection`, carried by negative evidence and independently reconstructed from validated fit evidence before digest comparison. |
| `private_alignment_artifact_digest` | `ebm-audit/reference-private-alignment/1` | Complete closed `PrivateReferenceAlignmentArtifact`; it remains under the private run root. |
| `reference_row_order_digest` | `ebm-audit/reference-row-order/1` | Exactly `{alignment_method, participant_count, ordered_reference_row_bindings}` for the reference array row order. |
| `participant_token_key_id_digest` | `ebm-audit/participant-token-key-id/1` | Exact 32-byte participant-token namespace key; the digest identifies the key without disclosing it. |
| `reference_id` | `ebm-audit/canonical-reference/2` | Complete `CanonicalReferenceResultDigestPreimage` with only `reference_id=null`; every supplied field has an explicit origin. |
| `statistical_diagnostics_digest` | `ebm-audit/baseline-statistical-diagnostics/1` | Complete `BaselineStatisticalDiagnosticsDigestPreimage` after every diagnostic chain identity is replaced by its deterministic plan-position surrogate and the normalized convergence record is revalidated. |
| `BaselineConnectedResultProjection.result_id` | `ebm-audit/baseline-connected-result/2` | Complete `BaselineConnectedResultDigestPreimage` with only `result_id=null`, binding the subject, implementation, dataset, scientific contract, and connected outputs. |
| `baseline_reproduction_id` | `ebm-audit/baseline-reproduction/2` | Complete `BaselineReproductionRecordDigestPreimage` with only `baseline_reproduction_id=null`, binding the reference presence, connected result, zero-tolerance comparison vector, derived status, reason codes, and language eligibility. |
| `baseline_assessment_id` | `ebm-audit/baseline-assessment/1` | Complete `BaselineAssessmentRecordDigestPreimage` with only `baseline_assessment_id=null`, binding the exact Plan/3 baseline candidate, finalized/persisted terminal identity, sealed candidate-terminal-index digest, optional exact reproduction identity, total status, reason codes, and language eligibility. |

All receipt, evaluator binding, sealed-index, benchmark-operation, and benchmark-
subject shapes named above are definitions in
[`../../schemas/evaluator-receipts.schema.json`](../../schemas/evaluator-receipts.schema.json).
Source-set and candidate-tree shapes are definitions in
[`../../schemas/source-set-manifest.schema.json`](../../schemas/source-set-manifest.schema.json).
The protocol registry gives the literal schema reference and projection for every
registered identity. A domain may occur in only one registry row; a row may list
multiple destination fields only when a discriminator inside its one complete
preimage (for example `component_kind` or `manifest_kind`) prevents substitution.

Core IDs and protocol digests retain the domains and complete objects in their
own normative schemas: `analysis_spec_id`, `universe_id`,
`chain_execution_id`, `attempt_id`, settings, capabilities, backend identity,
environment identity, scientific request, requested outputs, final chain
payload, command-specific actual worker subjects, private alignment, reference row order,
participant-token key identity, and `benchmark_subject_digest`. The executable
registry is
[`../../schemas/protocol-registry.json`](../../schemas/protocol-registry.json).
The evaluator repeats
those exact values; it does not define aliases such as `chain_attempt_id`,
`algorithm_settings_digest`, `profile_settings_digest`, or
`environment_lock_sha256`. Adding any structured digest requires adding one
closed row here (or to the owning normative schema) before freeze.

## 6. Held-out commitment ordering

The root commitment is exactly:

```text
Sha256Hex(SHA256(
  "ebm-audit/heldout-root-commitment/4" || NUL ||
  hex_to_bytes(root_256bit_hex) || NUL ||
  JCS({heldout_manifest_template_sha256, candidate_sha256,
       analysis_plan_digest,
       benchmark_contract_sha256, generator_sha256, scenario_definitions_sha256,
       metrics_rules_sha256, report_language_rules_sha256,
       benchmark_freeze_receipt_sha256, candidate_freeze_receipt_sha256,
       benchmark_subject_digest})
))
```

All fields in that preimage are populated before commitment and are immutable.
After the commitment is fixed, `heldout_attempt_id` is derived under
`ebm-audit/heldout-attempt/3` from the candidate, benchmark subject, contract,
exact analysis-plan digest, generator, scenarios, metric rules,
report-language rules, root commitment, benchmark-freeze receipt,
candidate-freeze receipt, and held-out
manifest-template digest. The root commitment
therefore does not depend on the attempt ID that depends on it. The root is not
written to the public receipt; it remains permission-restricted until the
attempt's disclosure rule permits verification.

The evaluator resolves that private root from its already selected private
attempt directory. No request, result, manifest, score owner, or caller-provided
context may supply or select it. Before accepting an attempt identity, the
evaluator recomputes the commitment from that private root and the complete
frozen public owner above. The same private root authenticates the complete
sealed-case manifest, sealed operation plan, frozen chain plan, closed
`ScoreEvidenceBundle`, and `ScoreValidationReceipt` with HMAC-SHA-256 under
distinct domains. Individual mandatory-rule and non-baseline-gate evidence
digests are ordinary closed `ScoreAggregateEvidenceDigestPreimage` hashes over
that authenticated root, the exact source-validation-registry digest, the
aggregate kind, and its registered ID; they do not have a second per-aggregate
HMAC owner. If private-root resolution, commitment verification, or required
owner authentication is unavailable, evaluation fails closed.

The case resolver receives that verified root/attempt pair only through an
evaluator-issued, authenticated, exact-type, one-shot capability for one frozen
coordinate. `CONFIDENTIAL_CASE_SEED_V1` binds the attempt ID, UTF-8 family ID,
numeric variant index, and replicate index; its message and all root, case, and
component seed bytes remain private. The public resolution union exposes only
the seed-free resolved projection or the seed-free retained
`GENERATOR_INVALID` projection. Reuse, owner substitution, attempt mismatch,
caller-selected structure, and direct held-out-range transformation-null
resolution fail closed before generation or worker execution.

The ordering is mandatory:

1. freeze the scientific contract, generator, scenarios, metrics, and report rules;
2. complete the audit engine, report, privacy gates, and development-only repair;
3. use the substantive evaluator to resolve and recompute the exact 23-family
   development evidence and only then issue final-candidate qualification;
4. commit a clean implementation candidate, calculate its tree digest, and
   issue a future decisive candidate-freeze receipt only after rederiving the
   qualification from that same authoritative graph;
5. resolve the exact project-owned `SYNTHETIC-ONLY` conformance EBM through the
   ordinary generic worker and verify its frozen candidate, worker, complete
   configuration, generator, and pre-root source identities without consulting
   any acceptance registry or state transition;
6. prove `benchmark freeze <= qualification <= candidate freeze`, copy the
   held-out template into the private attempt directory, then draw the
   256-bit root from the operating-system CSPRNG;
7. write the v4 root commitment, including `benchmark_subject_digest`,
   `benchmark_freeze_receipt_sha256`, `candidate_freeze_receipt_sha256`,
   and the exact `analysis_plan_digest`, and derive the v4 `heldout_attempt_id` from the
   complete commitment owner before generating any case. The current `/3`,
   `/2`, and `/3` benchmark, qualification, and candidate-freeze records are
   deliberately blocked evidence records and cannot
   satisfy these steps;
8. write and authenticate the complete sealed case manifest, typed operation
   plan, and exact per-operation frozen chain plans before inspecting a result;
9. execute once and seal outputs before truth scoring;
10. resolve and authenticate the complete score-evidence root, including its
   exact 14 core owners, 101 source records, source-validation registry, and
   repository tree;
11. derive evaluation and score without consulting an `ACCEPTED` state, then
    authenticate a `ScoreValidationReceipt` over the exact root and derived
    branch; a registered UNIMPLEMENTED semantic/source boundary instead emits
    only `ScoreValidationFailureRecord` and stops. This validated branch is the
    readiness result for the exact conformance subject.

Benchmark freeze in step 1 does **not** freeze an unfinished implementation and
does not authorize held-out seed generation. A changed candidate, contract,
generator, scenario definition, metric, report rule, conformance EBM, worker,
environment, capability, settings identity, or calibration route requires a new attempt and
fresh root. Prior attempts remain
append-only evidence.

## 7. Repeatability payload

Same-seed byte repeatability applies to the closed `CanonicalScientificPayload`
in [`../../schemas/canonical-records.schema.json`](../../schemas/canonical-records.schema.json),
not an entire run directory. The payload contains only validated discrete and
numeric scientific outputs plus their schema/field-origin metadata. It excludes
request UUIDs, timestamps, runtimes, paths, file ordering, logs, private namespace
keys, aliases, source-row positions, and transport hashes of those fields.

Benchmark repeatability reuses the exact synthetic canonical row order and a fixed
test-only namespace key. Real-data repeatability within one run reuses its private
namespace. Comparisons across independently created private namespaces are made
only after private core-side row alignment; a report never exposes the join.
Row-order invariance remains a separate property test and cannot be claimed from
byte comparison alone.

## 8. Receipts and failures

Every freeze/attempt receipt validates against its exact definition in
[`../../schemas/evaluator-receipts.schema.json`](../../schemas/evaluator-receipts.schema.json)
and records the parser and canonicalizer versions, `REJECT_NON_NFC` policy,
all declared input and output digests,
`benchmark_subject_digest` when applicable, a typed candidate Git identity,
command argv, UTC time, and terminal status. A persisted self-hashing receipt has
a non-null self hash and validates only against its persisted schema. Hashing
validates a separate `*ReceiptDigestPreimage` schema whose exact own hash is null;
the generic pointer-based self-hash projection has been removed, so no receipt can
null another field. Duplicate keys, unsafe
numbers, unexpected tree entries, dirty candidate
state, self-hash mismatch, symlink dereference, missing source identity, or a
changed preimage is a hard failure. No tool repairs or normalizes an invalid input
silently.

`SealedResultRecord` is a closed discriminated union. A
`COMPILE_TIME_NON_SUCCESS` record contains compile identity and error evidence but
cannot contain any request, response, payload, subject, chain, seed, or worker
binding field. `VALIDATE_TERMINAL` persists complete validate success-or-negative
command evidence and the validate binding identity. `FIT_TERMINAL` retains only
negative fit outcomes or a worker-success outcome finalized as
`CONVERGENCE_FAILED`/`CONVERGENCE_NOT_ASSESSABLE`; its status enum excludes final
`SUCCESS` and `CONVERGENCE_WARN`. Those two outcomes can be sealed only as
`SCIENTIFIC_SUCCESS`, which requires the successful fit evidence, the exact
passing/warning convergence assessment, and the canonical scientific payload
identity. Thus a standalone successful `FIT_TERMINAL` is structurally invalid,
not repaired by a later cross-record guess. Negative validate/fit command
evidence requires that command's exact payload schema version and its recomputed
actual subject digest. The closed branches make an impossible worker identity on
a compile-only universe a validation failure rather than a nullable placeholder.
The results-index runtime rule also derives one cross-branch natural identity:
the same fit chain and attempt cannot occur once as `FIT_TERMINAL` and again as
`SCIENTIFIC_SUCCESS`, even though the branch sort keys differ.

No terminal branch accepts a response binding by digest propagation alone.
`VALIDATE_TERMINAL` resolves the exact request and describe owner and recomputes
their atomic identities before binding the command evidence. `FIT_TERMINAL`
does the same, persists the exact `frozen_chain_plan_sha256`, and additionally
authenticates the frozen chain plan, complete `AnalysisPlan/3`, complete
`PreparationReceipt/2`, and sealed operation plan under distinct domains with
the private attempt root. The held-out attempt fixes the exact plan digest and
the operation plan fixes the exact receipt digest; the selected preparation
record must be `PREPARED` and its `UniverseSpec/3` must project exactly to the
frozen chain plan. It derives the seed, universe,
chain-execution, attempt, ordinal-zero, and deterministic request identities,
resolves the exact sealed case and `AnalysisSpec`, and requires the terminal
result and request to resolve to exactly one planned chain. That authenticated
chain row carries the exact command-specific `scientific_request_digest`, which
commits the complete scientific request projection, including every dataset
descriptor and file-catalog field. A failed fit therefore remains attached to the request and plan that
actually produced it; a fully rehashed replacement request/result graph is not
an alternate valid failure record.

Both fit-bearing branches require the closed `comparator_applicability`
discriminator. `NOT_APPLICABLE` requires a null comparator execution binding;
`MATCHED_COMPARATOR_CHAIN` requires a non-null binding. The registered runtime
rule resolves `operation_instance_id` exactly once against the complete sealed
operation plan, resolves its case exactly once against the complete sealed-case
manifest, and derives applicability from those objects before it evaluates the
null/non-null binding. A caller cannot evade comparator evidence by asserting
`NOT_APPLICABLE`.

Before a later held-out authorization receipt can exist, all 102 hook attachments across all eighteen
registered schemas must resolve to exactly the 91 unique registry IDs, the
reference dispatcher handler set must be exactly those 91 IDs, and every one of
the 91 registered handler-level counterexamples must return a failure validated
against the closed `RuntimeInvariantDispatchOutcome` schema in
[`../../schemas/evaluator-receipts.schema.json`](../../schemas/evaluator-receipts.schema.json).
Unknown dispatch IDs fail closed. These checks are pre-implementation contract
evidence and do not replace the required production evaluator source root.

The D04 contract-file freeze is subject-neutral and carries no caller-authored
PASS assertion, candidate, or benchmark-subject digest. It records exact source
identities, review disposition, retained failed characterization, untouched
held-out state, and a directly recomputable self-hash. This freezes the rules
that later evidence will face; it authorizes no execution.

The separate later held-out execution gate has a predicate list and typed-owner
list equal to the governing 28-row verifier registry exactly, in order. Every
owner digest is recomputed, and the production evaluator must resolve each
complete typed owner and rederive the predicate result. That production
authority is not implemented in this contract slice. Consequently
`BenchmarkFreezeReceipt/3` remains `BLOCKED`, `frozen=false`, and `DRAFT` as an
execution-authorization receipt; it does not undo the earlier D04 file freeze.
`ProfileCharacterizationPlanReceipt/3` fixes pre-execution intent only, and the
retained `BlockedProfileDiagnostic/2` records only the earlier pre-run state.
Neither is benchmark evidence or overrides the later retained 54-fit outcome.
The two profile predicates use a typed
unavailable marker until a future issuer-owned opaque
`ProfileCharacterizationEvidenceReceipt/3` exists under
`ebm-audit/profile-characterization-evidence-receipt/3`. That future issuer,
not a caller mapping validator, must bind the plan to product-owned
authenticated public case, execution, result, convergence, runtime, metric,
aggregation, comparison, and decision owners. It must enforce the plan's exact
requested-output sequence, evidence/metric registry, cardinalities, separate
per-distance-family and per-direct-relation aggregation, and fail-closed
selection policy. It must bind a versioned machine-executable independent
transition-quality decision owner over the exact transition rate, unique-state,
maximum-repeated-state, and endpoint/zero observations. The owner must state
each metric's direction, aggregation, tolerance, endpoint/zero rule, complete
denominators, exact plan/evidence/subject binding, and no
preferred-central-order targeting. No transition review or `PASS` exists in
the current plan.
The Plan's five complete source-set identities are declared provenance with
state `DECLARED_PRE_EXECUTION_NOT_ATTESTED`. They do not enter the
candidate-independent `ProfileExecutionIdentity/1`. That identity instead
binds the narrow six-role fit-sensitive source-manifest digest and exact worker
argv/timeout semantics. The Plan hashes the declared narrow manifest but does
not attest a candidate tree; a future trusted executor must derive and match
every manifest entry against the exact candidate tree before fitting. Its
execution policy prohibits cache reads/writes, checkpoint reads/writes, and all
retries, so the profile executor cannot inherit the ordinary runner's transient
retry path. Its public seed binds execution identity, authenticated
coordinate-specific event binding, and chain ID, not candidate or budget.
Transition review reuses the Plan's same 54 fits and cannot authorize another
fit matrix. The distinct moderate development qualification gate runs only
after the subject-neutral freeze and remains exactly eight pairs, 16 universes,
three chains per universe, and 48 separate fits.
The two complete 23-family development predicates are
absent here and
belong only to the distinct pre-candidate qualification gate. Fixture evidence,
an empty or `UNVERIFIED` assertion, a relabeled transcript, a final-candidate
development receipt in the benchmark gate, or a missing/extra evidence-tree
path fails closed. Other artifact and executed-check owners point to physical
evidence outside the candidate tree and, where registered, to a canonical
transcript; the fixed product verifier is the exact committed
`src/ebm_audit/evaluator/freeze_checks.py` file and is re-executed with the
already-running locked evaluator Python through the exact
`/usr/bin/sandbox-exec` boundary. The boundary receives one fresh mode-`0700`
scratch directory, denies every network operation, and denies every filesystem
write outside that scratch directory. It uses a closed environment, fixed
logical and derived physical arguments, a fixed sandbox profile, and a timeout;
the process group is terminated before evidence is accepted. The transcript
binds the runtime, verifier, sandbox launcher, sandbox policy, environment, and
logical arguments. A non-macOS host or a host without that exact registered
boundary fails closed before verifier execution until an equally explicit
platform adapter is specified and reviewed. The persisted transcript must
byte-equal the fresh observation. The typed owners derive the complete external
evidence file and directory set; missing, extra, symlinked, special, or unowned
paths fail. Candidate and evidence bytes are rechecked after every terminated
verifier process, including a failed or timed-out process, before its output is
interpreted. The executable malicious-verifier regression attempts an external
write and a loopback connection; both must be denied, the verifier must fail,
and no candidate, evidence, or external marker may change. Review
predicates resolve three distinct external read-only lane artifacts, all bound
to the exact unchanged candidate and joint normative source vector. Review
findings and separate dispositions must close one-to-one. After every verifier
execution, the evaluator requires the complete evidence-tree byte snapshot and
live committed candidate tree to remain unchanged and repeats the direct state
observation. The state predicate rejects any held-out root, case seed, or result
material. The product verifier and evaluator source root now exist and are
included in the frozen source identity. Held-out execution authorization remains
`PRE_FREEZE_BLOCKED` because the complete production evidence-owner resolution,
platform coverage, and held-out operation path are not yet implemented; this
does not undo the subject-neutral D04 contract-file freeze.

A sealed case is either outside a comparator or is a complete comparator member.
For a non-member, `comparator_id`, `derived_comparator_member_id`, `pair_index`, `shared_draw_seed`, both raw
pre/post generator-configuration identities, and the plan-evidence identity are
all null. For a member they are all non-null. The evaluator then verifies that
the complete case-configuration digest and plan digest are correct, validates
exactly one plan, requires the evidence IDs to equal its complete ordered member
set, validates every complete `MatchedComparatorEvidence`, and derives exactly one member whose
comparator, family, replicate, pair, pre/post configuration, generated-data
digest, and canonical-input digest equal the sealed case. That derived ID is
stored in the authenticated sealed case. Operation/result resolution repeats
the full semantic derivation before using that field, which is then the sole
member owner used by the operation plan and result evidence. There is no caller-provided `member_id`
selector; missing, extra, duplicate, reordered, alternate-plan, or case/member disagreement
member evidence fails, and a non-member carries no comparator evidence. Every asserted shared-component
equality is recomputed from the named components; and the four chain bindings
contain equal source/member seeds and the exact backend, settings, and environment
identities used by the sealed results. An `equal: true` literal alone is never
accepted as equality evidence.

A scientific-success payload is reconstructed from evidence owners rather than
trusted as a supplied hash preimage. The sealed result binds a private-root-
authenticated `FrozenChainPlanDigestPreimage` v3 carrying the exact attempt,
subject, operation, Plan/3 schema and digest, candidate ordinal and identity,
analysis-specification, complete `UniverseIdentityPreimage`, and universe
headers. The evaluator separately authenticates and recomputes the complete
`AnalysisPlan/3` and `PreparationReceipt/2`, resolves the exact ordinal and
candidate content identity, and requires the selected PREPARED
`UniverseSpec/3` to equal the frozen projection. The held-out attempt and sealed
operation plan independently fix the exact plan and receipt digests. Every row
also commits the exact
command-specific `scientific_request_digest` for its complete fit request
projection. Its row count must equal
`AnalysisSpec.mcmc.chain_count`, every held-out attempt ordinal is exactly zero,
and each seed is independently recalculated from
the private root using the ordinary or matched-comparator chain-seed formula.
The complete fit-payload and response-binding owner arrays must
equal frozen-plan order, and every planned chain resolves to exactly one of
each. The evaluator exact-compares those independently authenticated owners and
the ordered chain projection with the complete universe preimage, derives the
universe ID under `ebm-audit/analysis-universe/3`, requires every fit payload to
carry that same universe, then derives every chain and attempt ID under their
registered `/3` domains. It reconstructs the full ordered chain
projection, including central-order event IDs from the permutation, the
response-binding digest,
preprocessing, stage semantics, array catalog, origins, accounting, and
transition fields. Missing, extra, reordered, unplanned, duplicated, substituted, or reused
chains and bindings fail before `canonical_scientific_payload_sha256` is
recomputed.

The authenticated `ScoreEvidenceBundle` commits the exact
`NullCalibrationIdentity`, 60-entry false-positive opportunity evidence, 14 core
owners, 101 ordered source records, their exact repository bytes, and the closed
101-row source-validation registry. The evaluator derives counts and states from
those sources; it never accepts standalone counters. Each `RuleOutcome` uses one
closed `ScoreAggregateEvidenceDigestPreimage` containing the score-root digest,
source-registry digest, `MANDATORY_RULE`, and registered rule ID. Each
non-baseline `BackendGateResult` uses the same five-field preimage with
`BACKEND_GATE` and its registered gate ID. The baseline gate instead points to
the complete baseline-reproduction record. There is no alternate per-aggregate
typed-owner schema or count-only owner. The scenario rule is derived only from
the substantive held-out 23-family graph committed by the root; fixture and
development receipts are ineligible.

These structural identities do not prove scientific meaning. The execution
universe has five registered semantic branches and all five are currently
`UNIMPLEMENTED`; the 104 scenario derivation identities are also
`UNIMPLEMENTED`; and 100 of 101 score-source validators are `UNIMPLEMENTED`.
Those three runtime boundaries emit a root-bound
`ScoreValidationFailureRecord` and stop before any evaluation, score, or
score-validation artifact. Malformed, missing,
substituted, or incomplete inputs likewise fail closed, but the current contract
does not claim a typed record for every pre-handler error. Downstream scoring and
readiness completion remain pre-product scaffolding until these semantic owner sets and
handlers exist.

When a complete branch becomes reachable, the private-root-authenticated
`ScoreValidationReceipt` is the readiness completion marker. The evaluator
re-resolves the exact score root, recomputes the persisted evaluation and score
identities, and requires that receipt to bind the same attempt, exact conformance
subject, source registry, evaluation, score, rule vector, gate vector, aggregate
branch, fixed commands, and one workflow timestamp. The result remains the
derived `PASS`, `WARN`, or `FAIL`; no registry mutation can strengthen or weaken
it. An optional named-backend qualification may later apply its separately
versioned durable transaction rules to that integration's own exact subject, but
such a transaction is not part of this readiness attempt and cannot gate the
library.
