# Analysis-universe contract

Status: `FROZEN`
Contract version: `0.1.0`
Governing scope: strict, single-sequence, cross-sectional EBM only

Executable Draft 2020-12 contract:
[`../../schemas/analysis-universe.schema.json`](../../schemas/analysis-universe.schema.json).
Its identity projections and the ordered protocol vocabularies are registered in
[`../../schemas/protocol-registry.json`](../../schemas/protocol-registry.json).

This document defines how the auditor turns a predeclared set of defensible analysis choices into immutable, inspectable work. It is not permission to search all possible analyses. Invalid, unsupported, failed, and unrun specifications remain visible.

## 1. Identity model

The compiler uses nine distinct identities. None contains a timestamp, absolute
path, hostname, scheduler position, or wall-clock execution order. Every value is
a prefixed `Sha256Digest` as defined in
[`artifact-hashing-and-freeze.md`](artifact-hashing-and-freeze.md). Each
structured preimage is `ASCII(domain) || NUL || JCS(object)`.

1. `analysis_spec_id` is the deterministic content name of one closed,
   row-free `AnalysisSpec/3` before chain replication. Its domain is
   `ebm-audit/analysis-spec/3` and its object is the complete schema-validated
   `AnalysisSpec`. The digest is not authority: only an exact compiler rebuild
   behind a genuine `PlanningAuthority` may place that name in an accepted
   `AnalysisPlan/3`.
2. `receipt_digest` identifies the one complete ordered `PreparationReceipt/2`
   created internally by `PlanningAuthority` from an exact, within-budget
   `AnalysisPlan/3`. Its domain is `ebm-audit/preparation-receipt/2`. Every plan
   candidate has one record. An unprepared record has no universe.
3. `universe_id` identifies one successfully prepared candidate together with
   its exact preparation commitments and ordered chain plan. Its domain is
   `ebm-audit/analysis-universe/3` and its owner is the complete
   `$defs/UniverseIdentityPreimage`. Plan schema/digest, candidate ordinal/ID,
   analysis-spec ID, preparation commitments, and the seed-bearing chain plan
   are all identity inputs. An unprepared candidate never receives a substitute
   empty universe.
4. `chain_execution_id` identifies one declared chain within a universe. Its
   domain is `ebm-audit/chain-execution/3` and its object is
   `{universe_id, chain_id, seed}`. It never denotes the multi-chain scientific
   result. The executable preimage is `$defs/ChainExecutionIdPreimage`.
5. `attempt_id` identifies an immutable transport attempt. Its domain is
   `ebm-audit/chain-attempt/3` and its object is
   `{chain_execution_id, attempt_ordinal}`. The first ordinal is `0`; the only
   permitted identical transient retry is ordinal `1`. The executable preimage
   is `$defs/AttemptIdPreimage`.
6. `retry_equivalence_digest` determines whether ordinal `1` is the sole
   identical retry of ordinal `0`. Its domain is
   `ebm-audit/retry-equivalence/1`. Starting from the complete fit scientific
   projection after the existing transport exclusions, it removes only
   `payload.attempt_id` and `payload.attempt_ordinal`. Attempt-specific request
   and cache identities stay distinct.
7. `chain_cache_key` identifies a reusable validated worker response. Its domain
   is `ebm-audit/chain-cache/4` and its object binds
   exactly `{chain_execution_id, scientific_data_digest, config_digest,
   attempt_id, attempt_ordinal,
   core_code_digest, backend_identity_digest, worker_executable_digest,
   worker_code_digest, backend_source_digest, environment_digest,
   capabilities_digest, settings_digest, requested_outputs_digest,
   protocol_version, request_schema_version, response_schema_version,
   worker_payload_schema_version, canonical_result_schema_version}`. The
   executable shape is `$defs/ChainCachePreimage`; there is no
   `worker_identity_digest` alias.
8. `universe_cache_key` identifies a reusable core-final result. Its domain is
   `ebm-audit/universe-cache/3` and its object binds
   exactly `{universe_id, ordered_chain_cache_keys, convergence_rule_digest,
   reference_chain_rule_id, result_schema_version}`. The reference rule is
   `lowest-chain-plan-position/1`. An incomplete, negative, or stale chain cache set
   cannot be relabelled as a final success.
9. `result_id` identifies one complete closed candidate result body. Its domain
   is `ebm-audit/result-record/2` and its owner is exactly
   `{result_schema_version, body}` under `$defs/ResultRecordDigestPreimage`;
   `result_id` itself is absent from the preimage. The separate exact-file
   `CandidateTerminal.result_digest` does not reuse this identity domain.

Canonical JSON uses UTF-8 RFC 8785 JSON Canonicalization Scheme bytes, the same structured-digest domain as the worker protocol and canonical schemas. Strings must already be NFC-normalized before canonicalization; non-NFC input is rejected rather than silently rewritten. Quantitative configuration uses finite JSON numbers inside the interoperable safe-integer range and RFC 8785 number serialization. Every full-width seed uses `UInt64Hex`: exactly 16 lowercase hexadecimal characters matching `^[0-9a-f]{16}$`; it is never a JSON number. Arrays retain order unless their field is explicitly defined as set-valued; set-valued fields are sorted by stable machine ID before serialization. NaN, infinity, implicit defaults, environment interpolation, and path-dependent values are forbidden. Defaults are materialized before hashing.

`requested_outputs_digest` uses domain `ebm-audit/requested-outputs/2` over
exactly `{registry_digest, requested_outputs}`; outputs are unique and
sorted by the registry order, not caller order. `registry_digest` is computed
from every complete closed requested-output registry row, including
`capability_absence_behavior` when present; it is not a hand-selected field
projection. `backend_identity_digest` is the
defined full closed identity digest from the worker protocol. The one environment
identity is `$defs/EnvironmentIdentity` in `canonical-records.schema.json`, with
domain `ebm-audit/environment/1`; no shorter environment projection may reuse
that name/domain.

Command eligibility is validated separately. A validate request and fit request
with the same eligible output-ID tuple therefore use the same command-neutral
digest. The executable `$defs/RequestedOutputsPreimage` discriminates fit/validate
output IDs from reserved stage framing and rejects unknown values.

A changed row-free scientific choice produces a new `analysis_spec_id`.
Physical source bytes, a private variant label/provenance note, and local path
relocation do not change it because they are not AnalysisSpec fields. A changed
chain count, ID, order, or seed produces a new `universe_id` and
`chain_execution_id`. A code, input, protocol, capability, backend, settings, or
environment change invalidates the applicable cache even if the scientific
specification is unchanged.

## 2. Immutable `AnalysisSpec`

Every field below is required after resolution. `null` is permitted only where
the schema explicitly defines it as meaningful. The complete object is
scientific intent only: source tables, row selections, private values, paths,
worker transport, runtime evidence, evaluator state, and seeds are forbidden.
Algorithm `settings` is additionally validated against the exact authenticated
closed settings schema from `describe`.

| Field | Required content |
|---|---|
| `spec_schema_version` | Exactly `ebm-audit-analysis-spec/3.0`. |
| `dataset_variant_intent` | Exact row-free projection `{source_variant_id, variant_kind, source_variant_id_ref, method_id}` of one declared `SourceVariantDefinition`. |
| `cohort_rule` | Row-free public field/label aliases or declarative rules, with the required reference and at-risk roles. Physical source columns and raw labels remain in validation/preparation ownership. |
| `event_set` | Ordered stable public event IDs. Inclusion rationale is separate declaration provenance. |
| `event_directions` | Complete mapping of every selected event to `higher` or `lower`; `REQUIRES_CONFIRMATION` makes execution invalid. |
| `preprocessing` | Ordered typed public transformation methods and closed public settings. |
| `outlier_policy` | One closed semantic tuple: exact no-op or typed Tukey-IQR behavior. |
| `missingness_policy` | `error` or `complete-case` for the current physical contract. `external-variant` remains schema vocabulary but resolution rejects it until a complete physical owner exists. |
| `covariate_adjustment` | `none` or the closed reference-group residualisation intent with public ordered term IDs. |
| `backend` | Transport-free `BackendSpec/3`: adapter/algorithm semantics, authenticated digest expectations, public scientific settings, and requested fit outputs. |
| `mcmc` | `null` for authenticated non-chain algorithms, otherwise the complete schedule and public proposal semantics. |
| `operation_intent` | Exactly one row-free ordinary, bootstrap, subsample, influence, or null intent. Realized rows and seeds are later private execution evidence. |

The complete physical `DataVariant/2` is deliberately not nested in
`AnalysisSpec/3`. `AuditConfig/0.3.input.variant` owns it. The baseline join is
three-way and exact:

```text
input.variant.variant_id
  == baseline_analysis.dataset_variant_intent.source_variant_id
  == unique baseline-input SourceVariantDefinition.source_variant_id
```

The baseline source definition must have `source_variant_id_ref: null` and
`method_id: exact-input-bytes/1`. The input byte owner must use
`sha256-exact-file-bytes/1`; its physical variant must use `exact-file/1`; and
`input.expected_byte_digest` must equal `input.variant.source_digest`. Neither
field is defaulted or inferred. Verification independently compares both values
with the retained file bytes. Lossless preparation then copies that exact
physical variant into `AuditDatasetCatalog.variant` and changes no field.

Physical variant `label` and `provenance_note` are local/private. They may
change the transient path-free source-config digest and catalog/prepared
identities, but they cannot appear in the resolved public configuration, plan,
logs, reports, or exception text.

A `UniverseSpec/3` exists only for a `PREPARED` `AnalysisPlan/3` candidate and
binds the complete preparation commitments plus an ordered `chain_plan`:

```text
UniverseSpec
  universe_schema_version: Literal["ebm-audit-analysis-universe/3.0"]
  plan_schema_version: Literal["ebm-audit-analysis-plan/3.0"]
  plan_digest: Sha256Digest
  candidate_ordinal: SafeInteger
  candidate_id: Sha256Digest
  analysis_spec_id: Sha256Digest
  preparation commitments and aggregate counts
  chain_plan: tuple[ChainExecutionSpec]

ChainExecutionSpec
  chain_id: unique non-empty run-local string
  seed: UInt64Hex
  chain_execution_id: Sha256Digest
```

An executable universe has exactly `analysis_spec.mcmc.chain_count`
ordered entries, sorted by canonical `chain_id`; IDs and seeds are distinct. A
candidate that terminates during planning or preparation instead receives an
`Unprepared` `ResultRecord/2` with `universe_id=null`; it never receives an empty
or placeholder universe. Code may convert a validated seed string to an unsigned
integer only after identity construction and before calling an RNG/backend; the
serialized specification always retains the string. The universe and its chain
plan are immutable after planning. A retry creates another `attempt_id`; it does
not mutate any scientific or chain identity.

Identity construction is acyclic and ordered: compute `analysis_spec_id`, build
the exact Plan/3 candidate, complete its private preparation, materialize exact
`ordered_chain_plan: [{chain_id, seed}, ...]`, compute `universe_id`,
then compute each `chain_execution_id`, and finally verify the populated
`UniverseSpec/3` against those derived values. `PlanningAuthority` creates the
complete ordered receipt only after every candidate has reached either
`PREPARED` with that universe or one typed unprepared state.

The first successful call publishes exactly one transaction per
`PlanningAuthority`. Sequential and concurrent callers receive the identical
`PreparationTransaction` and identical candidate capability objects. The
authority synchronizes issuance, fully validates the transaction before
publication, and publishes nothing after a failed attempt so a later call may
retry.

That atomic transaction issues exactly one opaque candidate capability in plan
order. A prepared record receives a sealed `PreparedExecutionAuthorization`
that privately binds the immutable prepared arrays, replay, authenticated
worker binding, plan, receipt, and Universe/3. A non-prepared record receives a
sealed `UnpreparedResultAuthorization` that can authorize only its deterministic
terminal result. Valid unsupported branches privately bind the exact canonical
scientific-data preimage and digest; invalid pre-canonical branches bind the
required null `input_digest`. It owns no universe, arrays, replay, or
worker/execution authority. Neither capability is caller-constructible,
copyable, serializable, or replaceable by a digest or mapping.

The production unprepared-result builder consumes only the exact opaque
authorization bound to that candidate, constructs the deterministic terminal
body without worker, universe, arrays, or cache authority, and persists it in
Plan/3 order. Its regression gate is
`tests/integration/test_unprepared_result_authorization_finalization.py::test_exact_unprepared_authorization_constructs_and_persists_only_its_bound_result`;
that gate must remain green.

### Operation payloads

- `ordinary`: no derived-source payload.
- `bootstrap`: source analysis/variant IDs, derived variant ID, replicate ordinal,
  sampling method/design, public strata group IDs, and fixed-cohort/refit policy.
- `subsample`: the same source ownership plus retained fraction and the exact
  retained-count rounding rule.
- `influence`: source ownership plus the exact participant or named-group
  removal intent. It contains no removed row indexes.
- `null`: source ownership plus the declared null family/method and its
  preservation semantics. It contains no seed or realized transformation.

Selected row indexes, seeds, fixed-cohort membership, and realized
transformation manifests may exist only in later private preparation/execution
evidence. Direct participant identifiers never enter AnalysisSpec identities,
plans, default logs, or reports.

### Matched-comparator transactions

A matched comparator is not a loose pair of configurations. It is one replayable
transaction over the single closed
[`ComparatorTransactionState`](../../schemas/comparator-transaction.schema.json).
That state contains the complete raw resolved generator-configuration digest
preimage plus the exact truth and generated-state fields that comparator
operations may change. Implementations may not maintain a second mutable
dictionary, apply an ad hoc JSON patch, re-resolve defaults, or copy only the
fields they expect to use.

The exact target-to-field mapping is the 18-row
`semantic_target_write_registry` in the frozen development scenario registry,
whose machine schema is `$defs/SemanticTargetWriteBinding`. Each executed operation
persists a closed `$defs/ComparatorTransactionTransition` containing the
operation, its exact write binding, complete pre/post states, the derived changed
paths, and both state identities. The evaluator independently replays the
operation, diffs the typed states, recomputes the identities, and rejects a
computed target update omitted from the post-state, an undeclared changed path,
a discontinuous transition, or a supplied post-state that differs from replay.
A registered path may remain byte-unchanged only when the independently computed
result equals its pre-state value. One operation name therefore cannot lawfully
mutate a different real field.

Member selection is derived before replay. The evidence `member_id` must occur
exactly once in `ordered_member_ids`. Each operation is then resolved exactly
once: an operation's `member_id` names that member, while a concrete
`member_index` selects `ordered_member_ids[member_index]`. Outsiders and
unresolved or out-of-range indexes are invalid. The member's selected operations
retain complete-plan order, their exact array is the ordered-operation digest
preimage, and each selected operation requires one contiguous transition. Zero
transitions are legal only when this derivation selects no operation for that
in-plan member.

Every planned pair carries
`pairing_key = comparator_id + "/" + source_variant_id + "/" +
replicate_index_decimal`. The plan and every member evidence record carry the
same `comparator_id`, `source_variant_id`, `replicate_index`, `pair_index`, and
`pairing_key`; substitution across pairs is invalid. The evaluator recomputes,
rather than trusts:

- the complete plan and member-ordered operation identities;
- every transition-state and raw pre/post generator-configuration identity;
- the equal projection after removing only the registered varied-target paths;
- both complete raw generated-data identities and canonical `input_digest`
  preimages;
- the selected closed generated-input-relation proof; and
- every shared-component identity/equality and four-chain binding.

The equal-projection digest does not pretend that a state with removed required
fields still satisfies `ComparatorTransactionState`. Its closed
`EqualProjectionDigestPreimage` contains the derived varied targets, their exact
ordered union of registered write paths, and the canonical pruned
`retained_state`. Source and member wrappers must be byte-identical before the
shared digest is accepted.

Non-byte-identical relations require their typed witness: complete component
witnesses, retained parent indexes, standardized variates and scales, shared
latent quantiles and windows, a boundary-rule reconstruction, or the exact two
observed group vectors, as applicable. A boolean or caller-supplied digest alone
cannot turn unequal inputs into comparator evidence. Any failed reconstruction
keeps the complete planned comparator in the denominator and makes its consumer
rule fail; there is no unpaired fallback.

The executable relation check reads the complete source/member synthetic-data
objects. It first proves participant, event, covariate, matrix, mask, and null
alignment. It then permits only the relation-specific difference: value cells
with exact shared-component equality; a unique in-range row subset; values
reconstructed from one shared standardized-variate and unscaled-value matrix;
latent times reconstructed from shared quantiles and the actual group-selected
windows; labels reconstructed from the declared boundary; or labels equal to the
selected original/contaminated truth view. Every other payload change, including
a biomarker change in either label-only relation, is invalid.

### Generator-field ledger binding

The 71 positions in `ResolvedParameterManifest.field_draws` are not merely an
ordered list of names. `$defs/FieldDrawLedgerEntry` in
[`synthetic-resolved-configuration.schema.json`](../../schemas/synthetic-resolved-configuration.schema.json)
is a 71-branch closed union. At each already-fixed position it binds the field's
exact `field_id`, `value_type`, `allowed_form`, ledger `draw_rule`, and canonical
resolved-value type and bounds to the corresponding
`generator_field_registry.fields` row. The registry calls the last value
`heldout_draw`; the ledger field is `draw_rule`, and the two are required to be
equal. Range endpoints never infer or coerce a type.

Common resolved fields, including `participants`, are non-null and retain their
exact canonical type. A scenario-specific field may be `null` only when it is
semantically inapplicable; otherwise its non-null value must satisfy its declared
integer width/sign, probability bound, positive/nonnegative bound, enum,
event-ID shape, tuple shape, interval shape, or variant-reference shape. Thus a
`participants` entry labelled `closed_enum`, marked `fixed`, or carrying a string
is invalid even if it occupies the correct first slot. The pre-freeze negative
gate mutates every slot's four bindings and canonical value independently.

## 3. Baseline and axes

Every audit has exactly one baseline. All enabled alternatives must belong to a named axis:

- externally supplied dataset variant;
- cohort/group rule;
- feature/event set;
- explicitly justified event-direction sensitivity;
- preprocessing transform;
- outlier policy;
- missingness policy;
- covariate adjustment;
- backend/model setting;
- MCMC/chain setting;
- sampling operation;
- participant/group influence operation; or
- null operation.

The compiler must not infer an axis from values, fit quality, the published Idris order, or a previous result. Automatic feature selection, optimized cohort thresholds, best-seed selection, and settings searches aimed at a preferred order are prohibited.

## 4. Experiment-set modes

| Mode | Expansion rule |
|---|---|
| `baseline` | Emit the baseline only. |
| `one-axis` | For each declared alternative, change exactly its named family while all other baseline choices remain literal. Interactions are not inferred. |
| `declared-combinations` | Emit only the exact named combinations supplied by the user. Each combination has its own rationale. |
| `full-factorial` | Emit the Cartesian product only when `allow_full_factorial: true`, every level has a rationale, constraints are compiled first, and both logical-universe and fit budgets pass. |
| `bootstrap` | Emit predeclared resamples for selected analysis specifications. Refit preprocessing and model parameters within every resample. |
| `influence` | Emit every declared removal. Leave-one-out means every eligible participant, not a result-selected subset. |
| `null` | Emit every predeclared null family and replicate. Refit the complete selected pipeline. |
| `custom` | Validate and emit an explicit list of complete specifications; no omitted field inherits from the last list item. |

Combining modes requires separate named experiment sets. An experiment set cannot change mode after planning.

## 5. Deterministic compilation

The authority sequence is fixed:

```text
resolve -> verify exact files -> RunEligibleAuditConfig
        -> authenticated Describe -> pre-data public intent manifest
        -> lossless prepare
        -> PlanningAuthority -> rebuilt and privacy-scanned AnalysisPlan/3
        -> execution capability
```

Neither a caller mapping nor an `analysis_spec_id` content name can skip a
boundary. The manifest capability remains data-independent and is owned by the
exact run authorization plus authenticated Describe bindings; PlanningAuthority
separately binds the exact prepared-dataset capability.

Both privacy gates use one schema- and path-aware content extractor. It scans
only fields whose schema permits caller- or data-derived strings, including
public identifiers, dynamic setting names, authorized string values, and
free-text rationale content. Fixed schema constants and enums—versions,
namespaces, statuses, kinds, rule literals, and similar protocol vocabulary—are
structure, not content, and are never compared with private tokens. Opaque
digests and compiler-generated identifiers are likewise excluded.

Compilation is pure over the sealed owners:

1. Reject omitted choices; resolution materializes no scientific defaults.
2. Validate the baseline independently.
3. Expand the requested mode in lexicographic stable-ID order.
4. Evaluate every constraint in stable constraint-code order.
5. Retain every statically ineligible candidate with all applicable typed reasons.
6. Materialize only seedless chain slots and the conservative fit ceiling. Plan/3
   owns no rows, preparation outputs, operation seed, chain seed, universe, or cache identity.
7. Compute counts and budgets before any preparation or fit begins.
8. Rebuild the whole plan, byte-compare and privacy-scan it, then emit the
   immutable plan and its domain-separated digest.
9. Only after that exact plan is accepted, `PlanningAuthority` privately derives
   operation and chain seeds, prepares every candidate, and atomically creates
   one complete ordered `PreparationReceipt/2`. Prepared candidates receive a
   `UniverseSpec/3`; unprepared candidates receive no universe.

`plan_digest` is a prefixed `Sha256Digest` using domain
`ebm-audit/analysis-plan/3` over the exact closed
`$defs/AnalysisPlanDigestPreimage`: the complete plan core with `plan_digest`
absent, never null. The persisted `$defs/AnalysisPlan` adds one required,
non-null `plan_digest`, which must equal that recomputed digest. The plan
contains no `UniverseSpec` or preparation result.

The executable persisted root is `$defs/AnalysisPlan`; its only hash input is
the separate accepted root `$defs/AnalysisPlanDigestPreimage`. The persisted
plan contains exact compiler, resolved-config, validated-dataset, baseline,
ordering-rule, count, runtime, and budget bindings plus an ordered tuple of
closed `$defs/AnalysisCandidate` objects. Each candidate contains:

- one primary `$defs/CandidateOrigin` and every equivalent source declaration in
  `duplicate_origins`;
- the closed row-free `AnalysisSpec/3` and equal `candidate_id` /
  `analysis_spec_id` content names;
- one static planning outcome (`PLANNED` or `PLAN_INELIGIBLE`);
- every exact static planning reason; and
- seedless chain slots plus the conservative planned fit ceiling.

A `PLANNED` candidate has the exact seedless chain slots required by its MCMC
intent. A `PLAN_INELIGIBLE` candidate has no slots, zero fit ceiling, and at
least one exact planning reason. Preparation later produces `PREPARED`,
`PREPARATION_INVALID`, or `PREPARATION_UNSUPPORTED` without rewriting the plan.
Candidate ordinals are contiguous. Plan counts and all per-experiment/axis/operation partitions are
recomputed from the candidate and origin arrays and must equal the serialized
closed `$defs/AnalysisPlanCounts`; JSON Schema shape validation is followed by
these deterministic cross-field checks.

Equivalent declarations must compile to byte-identical canonical plans regardless of input mapping order, row order, feature-column order after event remapping, process count, or host path.

Duplicate canonical specifications are not executed twice. Every source
declaration is retained as a typed `$defs/CandidateOrigin` in
`duplicate_origins`, and the compiler emits
`DUPLICATE_EQUIVALENT_SPECIFICATION`. A string label, integer label, and boolean
label are distinct typed values throughout declaration, comparison, and JCS;
object-key/string coercion is forbidden. Deduplication may save compute; it may
not hide that two declarations were equivalent.

## 6. Constraints and fail-closed statuses

Constraint outcomes are `VALID`, `INVALID_SPECIFICATION`, or `UNSUPPORTED_CAPABILITY`. An executable fit can later end in a worker status, but compilation never converts an invalid specification into a failed fit.

Minimum required constraint codes are:

| Code | Outcome and condition |
|---|---|
| `UNRESOLVED_EVENT_DIRECTION` | `INVALID_SPECIFICATION` when any selected event is `REQUIRES_CONFIRMATION`. |
| `NONPOSITIVE_LOG_INPUT` | `INVALID_SPECIFICATION` when a declared log transform encounters a nonpositive value and no literal prior transform makes it valid. |
| `TRANSFORMATION_ROW_OR_CELL_LOSS` | `INVALID_SPECIFICATION` when a transform drops or masks data without its declared policy and exact accounting. |
| `REFERENCE_GROUP_TOO_SMALL` | `INVALID_SPECIFICATION` when residualisation lacks its predeclared minimum reference rows. |
| `REFERENCE_DESIGN_RANK_DEFICIENT` | `INVALID_SPECIFICATION` when the reference-only design matrix is not full column rank. |
| `COVARIATE_LEVEL_UNSEEN` | `INVALID_SPECIFICATION` when application rows contain categorical levels absent from the reference fit and no predeclared encoding supports them. |
| `EMPTY_REQUIRED_GROUP` | `INVALID_SPECIFICATION` when reference or at-risk group is empty. |
| `BOOTSTRAP_GROUP_MISSING` | `INVALID_SPECIFICATION` when a replicate lacks a required group; stratified plans must prevent, not retry, this condition. |
| `EVENT_SET_TOO_SMALL` | `INVALID_SPECIFICATION` when fewer than two events remain for strict-order comparison. A one-event smoke may fit only when explicitly marked `protocol_only`. |
| `CONSTANT_EVENT` | `INVALID_SPECIFICATION` for a selected constant event unless the backend contract explicitly defines and the benchmark validates that case. |
| `NEAR_CONSTANT_EVENT` | `INVALID_SPECIFICATION` under the declared numerical tolerance; never silently drop it. |
| `UNSUPPORTED_MISSING_VALUES` | `UNSUPPORTED_CAPABILITY` when missing values reach a worker that disallows them. |
| `CELL_MASK_REQUIRES_COMPLETED_VARIANT` | `UNSUPPORTED_CAPABILITY` when cell masking would feed NaNs to a complete-data worker without a declared external variant. |
| `INCOMPATIBLE_NATIVE_STAGE_SEMANTICS` | Stage comparison unavailable when event sets or stage definitions differ. It is not a failed order comparison. |
| `UNSUPPORTED_MODEL_FAMILY` | `UNSUPPORTED_CAPABILITY` for subtypes, temporal/dwell-time, grouped/simultaneous events, or longitudinal visits in v0.1. |
| `BACKEND_CAPABILITY_MISMATCH` | `UNSUPPORTED_CAPABILITY` when a fit capability, non-stage requested output, or setting is not truthfully declared. |
| `FULL_FACTORIAL_NOT_EXPLICIT` | `INVALID_SPECIFICATION` when a Cartesian expansion was not explicitly enabled. |
| `FIT_BUDGET_EXCEEDED` | Planning hard failure; no fit starts. |

The validator records predicted participant, event, and cell effects before fitting. Execution records actual effects and requires equality with the prediction. Any unexplained difference is the hard failure `SILENT_DATA_MODIFICATION`.

Fixed-cohort staging absence is deliberately not a compilation-terminal
constraint. When the worker can fit but
`fixed_evaluation_cohort_staging=false`, the candidate remains `VALID`, retains
its full chain plan and fit count, and serializes the fixed-cohort stage
component as `NOT_APPLICABLE_BY_CAPABILITY`, `value=null`, reason
`STAGING.FIXED_COHORT_UNAVAILABLE`. Order, position, pairwise, influence, and
convergence components continue. The exact requested-output registry/runtime
invariant rejects using this exception for a non-stage component or for a
worker that cannot fit.

## 7. Comparison semantics

For orders with identical event sets, all strict-order metrics are allowed. For different event sets, both orders are restricted to their common event IDs while preserving relative order; omitted and added IDs are always reported. Fewer than two common events produces `ORDER_COMPARISON_NOT_ASSESSABLE`.

Native stages are comparable only when event sets, event directions, and stage-likelihood semantics are identical. Otherwise native-stage agreement, movement, and pooling are prohibited. The descriptive quantity `expected_stage / event_count` may be shown as `SEMANTICALLY_NON_EQUIVALENT`; it is never included in native-stage aggregates or stability labels.

Bootstrap and influence stage comparisons stage one declared fixed evaluation
cohort under every refitted model. Their operation objects carry
`stage_comparison_policy=fixed-evaluation-cohort-or-unsupported/1` and the exact
fixed-cohort digest. If the selected worker cannot stage that cohort, compilation
still records the candidate as `VALID`; each fixed-cohort stage component records
`NOT_APPLICABLE_BY_CAPABILITY`, `value=null`, and reason
`STAGING.FIXED_COHORT_UNAVAILABLE`. Its fits and every other valid order,
position, pairwise, influence, and convergence component continue.
Whole-candidate `UNSUPPORTED_CAPABILITY` applies only when the requested fit or
a required non-stage output cannot execute. A common in-fit participant cohort
is not a bootstrap or influence fallback and must not be emitted as one.

## 8. Fit accounting and budgets

The plan reports both logical analysis specifications and executable fits. For experiment set `e`:

```text
fit_count(e) = sum over valid AnalysisSpecs a in e of chain_count(a)
total_fit_count = sum_e fit_count(e)
```

Bootstrap, subsample, influence, and null replicates are already distinct `AnalysisSpec` objects, so their chain multiplication is counted exactly once. Invalid/unsupported records count toward `candidate_spec_count` but not `fit_count`. Estimated runtime is `sum(expected_runtime_for_profile_and_shape)` and is explicitly `UNVERIFIED` until based on a measured pilot.

The following are frozen operational ceilings, not scientific performance
thresholds. A concrete plan may be smaller but must never exceed them:

| Limit | Proposed value | Status | Reason |
|---|---:|---|---|
| Ordinary logical specifications per audit | 256 | `FROZEN_OPERATIONAL` | Prevents accidental uncontrolled factorial expansion while allowing a substantial declared multiverse. |
| Total executable fits, quick profile | 256 | `FROZEN_OPERATIONAL` | Keeps a diagnostic run bounded; a smaller explicitly declared experiment set is required rather than truncation. |
| Total executable fits, full profile | 4,096 | `FROZEN_OPERATIONAL` | Accommodates medium-cohort leave-one-out and moderate bootstrap/null work while forcing an explicit plan. |
| Total executable fits, largest synthetic conformance profile | 50,000 | `FROZEN_OPERATIONAL` | Provides a hard upper bound; the exact predeclared conformance plan may be smaller and is counted before execution. |
| Identical retry after transient process failure | 1 | `FROZEN_OPERATIONAL` | Distinguishes a transient launch failure without seed/settings fishing; stricter profile-specific no-retry rules take precedence. |
| Scientific-failure retry with changed settings | 0 | `FROZEN_REQUIRED` | A changed seed or setting is a new predeclared universe, never a retry. |

Every profile has both a logical-specification budget and total-fit budget. Exceeding either stops before execution. The runner must never silently sample, truncate, skip, lower chain count, reduce iterations, or reuse a scientifically different result to meet a budget. A user may author a smaller complete experiment set and obtain a new plan digest.

## 9. Execution, retries, resume, and failures

- Each fit runs in an isolated temporary workspace with its own captured stdout, stderr, warnings, and side-effect inventory.
- A timeout, crash, protocol error, backend error, privacy error, or convergence
  outcome remains represented in the universe's one final record; every chain
  attempt remains separately referenced evidence.
- One scientifically identical retry is allowed only for a classified transient
  subprocess launch/crash. Both attempts are recorded under distinct
  `attempt_id` values. The retry reuses the same `universe_id`,
  `chain_execution_id`, seed, inputs, settings, and environment.
- Retry equality uses `ebm-audit/retry-equivalence/1` over the complete
  `ScientificFitRequestProjection` after the four normal transport exclusions,
  then removes only `payload.attempt_id` and `payload.attempt_ordinal`. The
  ordinal-0 and ordinal-1 scientific-request, request-metadata, attempt, UUID,
  and cache identities necessarily differ; their retry-equivalence digests must
  match exactly. Ordinal 1 is forbidden unless ordinal 0 is a core-observed
  `PROCESS_FAILURE` with exact start/crash code.
- A scientific or convergence failure is never retried under a new seed or altered settings unless that alternative existed in the frozen plan.
- Resume loads only exact `chain_cache_key` and `universe_cache_key` matches. A
  partial or failed result is not converted into success by cache lookup.
- Serial and parallel execution of the same immutable plan must produce value-equivalent canonical scientific results. Scheduling and timing fields are excluded from that equivalence assertion but retained in provenance.
- A completed executable universe serializes one `FinalChainScientificPayload`
  per chain in exact plan order. The headline/reference payload is plan position
  zero under `lowest-chain-plan-position/1`; it is never result-selected. The
  core computes cross-chain distance/convergence records without concatenating
  chain samples or pooling chain uncertainty into within-fit matrices.
- Upstream backend caches are prohibited. Discovery of reuse not represented by the auditor cache is `UPSTREAM_CACHE_CONTAMINATION`, a hard conformance failure.

## 10. Required plan outputs

Before execution, `plan` emits:

- baseline specification and ID;
- plan digest and contract versions;
- candidate, valid, invalid, unsupported, duplicate, and executable counts;
- counts by experiment set, axis, operation, universe, chain execution, attempt,
  and status;
- exact fit multiplication for bootstrap, influence, and each null family;
- every constraint failure with stable code;
- estimated runtime and the evidence/status of that estimate;
- output locations without private identifiers; and
- the budget decision.

These are fields of one closed `$defs/AnalysisPlan`, not an informal collection
of console values. The plan digest binds every retained origin, candidate,
constraint outcome, universe/chain identity, count partition, runtime-evidence
status, and budget decision.

The plan is an auditable declaration, not a promise of successful fits. Reports use planned denominators and retain every terminal state.
