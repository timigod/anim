# Scenario Derivation Semantics

Status: normative contract; runtime handlers are not implemented.

Contract ID: `scenario-derivation-semantics/5`

## Scope

This contract freezes the deterministic owner-to-output semantics for the 53
distinct active derivation IDs used by scenario-derivation registry `2.3`.
It defines public owner records. It does not implement their producers,
consumers, validators, Fits, benchmark, score, or downstream predicates.
Registry `2.3` retains an old implemented-validator declaration only when its
complete owner identity is unchanged and its exact runtime handler still
exists. This retained subset is not completion. `scientific_pass_eligible`
remains false until all 104 ordered meanings close.

The registry binding for an output is the tuple
`(derivation_id, semantics_version, normative_anchor, ordered_owner_slots)`.
The `semantics_version` MUST be `scenario-derivation-semantics/5`, the anchor
MUST identify the matching section in this document, and the bound
`derivation_id` MUST equal that section's ID. A missing, duplicate, mismatched,
or reordered binding is invalid.

## Global Rules

1. Case vectors use genuine `PUBLIC_BATCH_CASE_PLAN.case_ordinal` order.
2. Comparator vectors use comparator-plan member order and then replicate
   order. Subtype vectors use the authenticated proportional operation plan and
   then genuine public case ordinal order.
3. Boundary-rule vectors use `boundary_q50`, `boundary_q35`, `boundary_q65` in
   that order. Pair ordering is specified by the applicable row below.
   Five family-level rule-state vectors are exceptions to case and comparator
   order: `order_rule_states` contains the one known-truth order family state;
   `stage_rule_states` contains the one known-truth stage family state;
   `moderate_rule_states` is ordered `[reference_alignment,
   paired_randomization, signal_stage_mae, convergence]`;
   `noise_ladder_rule_states` contains the one family-level Spearman state; and
    `influence_rule_states` contains one injected-participant strict-majority
    family state.
4. Every float MUST be finite. Every ID, axis, digest, status, and natural
   identity MUST match its authenticated owner exactly. A fitted statistic is
   available only from a successful, converged result.
5. A missing, malformed, non-finite, cross-bound, incomplete, or
   non-comparable owner makes the whole family evidence `NOT_ASSESSABLE`, sets
   `payload` to `null`, and makes the outer rule `FAIL`. No vector primitive
   contains `NA`. `WARN` MUST NOT be coerced to a boolean.
6. Empirical quantile `q_p(x)` stably sorts ascending and returns
   `x[ceil(p*n)-1]`. An explicitly named upper median instead returns the upper
   middle order statistic. Means use `fsum(x)/n`.
7. Spearman correlation uses average ranks for exact ties. Intervals are
   inclusive. Where an existing metric contract permits a central-order tie,
   select the lexicographically smallest sequence of UTF-8 event-ID byte
   strings; this contract creates no new tie permission.
8. Every operation-bound public owner carries the exact
   `case_operation_join_key`, `proportional_operation_plan_sha256`, and
   `operation_plan_entry_sha256`. The join key is exactly
   `(benchmark_subject_digest, authenticated_batch_sha256, case_id,
   operation_instance_id)`. A digest, ordinal, filename, arrival position, or
   caller mapping does not replace this key.
9. The public batch owns shared case identity only. The authenticated planning
   authority owns pre-execution operation facts. Preparation and capture own
   executed rows, transformations, results, warnings, side effects, and one
   terminal per attempted operation. A planned fact never proves execution.
10. Ordinary public owners MUST NOT contain, fabricate, resolve, or require a
    held-out attempt, root commitment, private compiler record, sealed case,
    sealed result, or sealed manifest. Historical held-out schema definitions
    remain valid only for their historical evaluator path.
11. Derive all non-report meanings first. Issue one pre-render report claim
    projection, derive report-dependent meanings, assemble the final 104-row
    bundle, render once, then issue one non-recursive surface-verification
    receipt after artifact readback.
12. This contract does not change any scientific threshold, metric, family
    count, seed meaning, output meaning, applicability state, or downstream
    predicate. The active challenge plan contains exactly 104 ordered Fits.

## Shared Owner Records

The following records are closed source-owner classes. Their schemas and
natural identities are part of this contract. They contain no raw participant
values and do not create a public API.

### `PUBLIC_BATCH_CASE_PLAN/1`

Schema: `schemas/evaluator-receipts.schema.json#/$defs/PublicBatchCasePlan`.
Natural identity: `benchmark_subject_digest`, `authenticated_batch_sha256`,
`case_ordinal`, `case_id`. The batch authority issues one closed record for
each retained public case. Ordinals are unique and contiguous from zero. This
owner authenticates shared case identity only. It does not own an operation
plan and does not claim that an operation ran.

### `PROPORTIONAL_OPERATION_PLAN/1`

Schema:
`schemas/evaluator-receipts.schema.json#/$defs/ProportionalOperationPlan`.
Natural identity: `benchmark_subject_digest`, `contract_sha256`,
`authenticated_batch_sha256`, `proportional_operation_plan_sha256`. The
authenticated planning authority issues it before execution. It contains
exactly 104 entries in operation ordinal order. Every entry binds its public
case identity, complete `case_operation_join_key`, analysis identity, family,
member, pair, subtype, transformation, resample, removal, refit, source,
output, and planned parameter identities when applicable. Every entry has its
own structured `operation_plan_entry_sha256`.

The plan contains no observed row membership, actual transformation account,
terminal state, fitted parameter, result, warning, side effect, or claim that
execution occurred. Both transformation-null operations use the predeclared
shared source operation `moderate_mina_shape/pair_00/signal`. Plan order fixes
this source. Results MUST NOT select or replace it.

### `PUBLIC_TERMINAL_RESULT/1`

Schema: `schemas/evaluator-receipts.schema.json#/$defs/PublicTerminalResult`.
Natural identity: the complete `case_operation_join_key`. The capture/run
authority issues exactly one terminal for every attempted operation and reads
it back from the exact `captured_run_sha256`. Plan and entry hashes MUST equal
the authenticated pre-execution plan. A successful or convergence-warning
terminal requires the genuine Fit-response and canonical-payload bindings. A
pre-backend or failed terminal retains its exact typed status, reason, and
invocation state and contains no invented success-only binding.

### Direct preparation and transformation owners

`ExecutedPreparationRowInstanceManifest` owns ordered `(source_row_index,
occurrence_ordinal)` row instances for `INPUT`, `TRAINING`, `OUTPUT`, and
`REFERENCE_FIT`. `ExecutedPreprocessingExecutionRecord` version 3 owns every
executed step and parameter digest. Its natural identity is
`case_operation_join_key`, `execution_role`,
`proportional_operation_plan_sha256`, and
`operation_plan_entry_sha256`. The role is exactly `SOURCE` or `TRANSFORMED`.
The record also binds `complete_refit`, its authenticated component-seed
manifest, its training and reference-fit row manifests, the exact six ordered
complete-refit step records, and its procedure-only digest.
`ExecutedTransformationEvidence` owns the exact
source/output identities, parameters, axes, missingness, labels, covariates,
participant-event alignment, row manifests, and `DataAccounting`.
`ReferenceFitGroupRoleEvidence` owns the direct reference-fit population and
reference/at-risk group roles. Preparation issues each record only after it
matches the complete operation plan and entry hashes.

The `refit_procedure_sha256` field is the structured digest under
`ebm-audit/complete-refit-procedure/1` of the closed
`CompleteRefitProcedureDigestPreimage`. That preimage contains only
`schema_version`, `digest_state=DIGEST_PREIMAGE`, `refit_mode=complete_refit`,
the exact ordered step IDs, and `refit_procedure_sha256=null`. It excludes the
execution role, input identity, seed, manifests, per-step parameter digests,
fitted parameters, fitted values, and results.

`CanonicalArrayArtifactOwner` version 2 binds each captured canonical array to
one `PUBLIC_BATCH_CASE_PLAN`, exact `PROPORTIONAL_OPERATION_PLAN` entry,
`PUBLIC_TERMINAL_RESULT`, `captured_run_sha256`, finalized result, Fit response,
canonical payload, chain execution, array descriptor, artifact bytes, and
private value digest. Its complete `case_operation_join_key`, plan hash, and
entry hash MUST equal every operation-bound owner. It contains no held-out
attempt, sealed-case digest, or sealed-result digest.

### `EXECUTED_BOUNDARY_RULE_IDENTITY/1`

Schema:
`schemas/scenario-evidence.schema.json#/$defs/ExecutedBoundaryRuleIdentity`.
Natural identity: `case_operation_join_key`, `rule_id`,
`analysis_spec_sha256`. It binds the exact request, public terminal, executed
result, cutoff quantile and value, and comparator-member index. The only order
is `boundary_q50`, `boundary_q35`, `boundary_q65`. A configured but unexecuted
rule is not evidence.

### Pre-render report owners and post-render receipt

`AuthenticatedReportClaimProjection` is the only pre-render report identity.
It binds non-report meaning records, warning records, public terminals,
proposed claim IDs, and the report-rule registry. It contains no rendered
artifact identity. `REPORT_PREDICATE_OUTCOME` natural identity is exactly
`(benchmark_subject_digest, family_id, predicate_id,
cardinality_member_id, report_claim_projection_sha256)`.

After the final 104-meaning bundle renders once, artifact readback issues one
`ReportSurfaceVerificationReceipt`. It compares each applicable meaning ID,
state, typed value, warning, terminal, claim, and JSON, applicable CSV, and
self-contained HTML artifact hash. It is terminal hard-gate evidence. It never
re-enters the owner manifest, changes a meaning, or triggers another render.

### `PREPARATION_AUDIT_EVIDENCE/2`

Digest domain: `ebm-audit/preparation-audit-evidence/2`.

Natural identity: `case_id`, `operation_instance_id`, `analysis_spec_sha256`.
The record binds input and output scientific-data hashes; selected events;
missingness policy; source mask and counts; deterministic predicted removals;
input, training, output, and reference-fit row-instance manifest hashes; exact
`DataAccounting`; the ordered preprocessing/refit digest; `backend_invoked`;
request-all-finite and response-all-finite flags; participant-event manifest
digest; and finalized-result-record digest. It MUST NOT contain raw values.

The canonical digest preimage is the complete `PreparationAuditEvidence` (PAE)
object. The issuer MUST set `digest_state=DIGEST_PREIMAGE` and
`preparation_audit_evidence_sha256=null` in that preimage. It MUST NOT omit,
project, replace, or add a field. The persisted PAE MUST set
`digest_state=PERSISTED` and MUST contain the matching structured digest.

The `source_missingness_mask_sha256` field uses the existing
`event-missingness-mask/1` domain. Every row-instance manifest field uses the
existing `ebm-audit/preparation-row-instance-manifest/1` domain.

#### Participant-event manifest digest

Digest domain: `ebm-audit/participant-event-manifest/1`.

The canonical preimage is the complete closed manifest mapping validated by
`schemas/canonical-records.schema.json#/$defs/ParticipantEventManifest`. It has
no wrapper, `digest_state`, or self-hash field.

The trusted issuer MUST take the manifest only from the authenticated capture
authority for the exact planned public operation. It MUST validate the complete
manifest against that schema, recompute the structured digest under the named
domain, and bind the manifest and digest to the exact
`case_operation_join_key`, `proportional_operation_plan_sha256`, and
`operation_plan_entry_sha256`. Caller/source-owner participant-event manifests,
hashes, mappings, ordinals, or fabricated capture owners are never authority.

A missing, malformed, cross-bound, replaced, or inconsistent manifest or owner
prevents PAE issuance.

#### Ordered preprocessing/refit digest

Digest domain: `ebm-audit/ordered-preprocessing-refit/1`.

The canonical preimage is one exact closed object with these fields in this
shape:

1. `schema_version` is exactly
   `ebm-audit-ordered-preprocessing-refit/1.0`.
2. `case_id` is the PAE case identity.
3. `operation_instance_id` is the PAE operation identity.
4. `analysis_spec_sha256` is the PAE analysis-spec digest.
5. `ordered_preprocessing_execution_record_sha256` is an ordered array of
   unique SHA-256 hex digests.

Each array digest MUST bind exactly one authenticated persisted, already-defined
`PreprocessingExecutionRecord`. That record includes its ordered steps,
parameters, input manifest, training manifest, output manifest, and
fit-population manifests. For every listed digest, the issuer MUST resolve
exactly one such record from retained preparation authority. It MUST reconstruct
the record's complete `DIGEST_PREIMAGE` form, recompute the self-digest under
`ebm-audit/preprocessing-execution-record/1`, and require equality to both the
persisted self-digest and the listed digest. The record's `case_id`,
`operation_instance_id`, and `analysis_spec_sha256` MUST equal the enclosing
ordered preimage and PAE identities.

The array MUST preserve the exact authenticated preprocessing/refit execution
order. An absent, duplicate, cross-bound, reordered, or internally inconsistent
record invalidates issuance. Empty preprocessing/refit uses the same valid
preimage with an empty array only when the retained authenticated analysis and
preparation graph proves that no preprocessing/refit execution occurred. It
MUST NOT use a magic constant. The PAE `ordered_preprocessing_refit_sha256`
field is the structured hash of this exact preimage under the named domain.

#### Normative authority-owned issuance

The authenticated preparation authority MUST issue PAE only after it
authenticates one `PROPORTIONAL_OPERATION_PLAN`, resolves the exact plan entry,
and joins that entry to the capture authority's terminal and finalized result
for the same attempted public operation. The issuer MUST require exact
`case_operation_join_key`, `proportional_operation_plan_sha256`, and
`operation_plan_entry_sha256` equality across the plan entry and every retained
preparation, capture, terminal, and result owner. The PAE `case_id`,
`operation_instance_id`, and `analysis_spec_sha256` MUST equal the corresponding
authenticated join and plan-entry identities.

The issuer MUST reconstruct all preparation-side fields from the exact retained
executed row-instance, preprocessing/refit, transformation, and reference-fit
owners issued by preparation. These fields are the PAE natural identity; input
and output scientific-data hashes; selected events; missingness policy; source
missingness-mask hash and count; predicted complete-case removals; all four
row-instance manifest hashes; exact `DataAccounting`; and ordered
preprocessing/refit hash.

The issuer MUST source `backend_invoked` from the authenticated
`PUBLIC_TERMINAL_RESULT` issued by capture for the same joined operation. It
MUST apply the branch-total rules below before it sets either all-finite field.
It MUST source `participant_event_manifest_sha256` from the authenticated
capture owner and recompute `finalized_result_record_sha256` from capture's
authenticated finalized core-result owner. The issuer MUST validate the
complete canonical `ResultRecord`, validate its existing `result_id`, and
recompute the complete-record digest under
`ebm-audit/finalized-result-record/1`. A bare `result_id`, caller mapping or
hash, evaluator receipt, digest, ordinal, or caller-fabricated preparation or
capture owner is not a substitute. Every result-side field MUST agree with the
same joined plan entry, terminal, operation, case, analysis spec, and finalized
result.

A caller-provided PAE object is never authority. Caller/source-owner PAE
mappings and hashes are never authority. A source-owner record or hash does not
authorize the issuer to copy a PAE field or fabricate a preparation or capture
owner.

When `backend_invoked=true`, the issuer MUST recompute both all-finite flags
from the exact authenticated numeric arrays that crossed the worker boundary.
The authenticated finalized and execution owners MUST bind those exact request
and response arrays. When `backend_invoked=false`, the issuer MUST require an
authenticated pre-backend terminal and MUST prove that no worker-boundary
request or response array exists. `request_all_finite` and
`response_all_finite` MUST both be false sentinels. The two all-finite fields
MUST be interpreted only together with `backend_invoked`. The false sentinels
are not evidence that a non-finite request was admitted.

The authority MUST emit no PAE when an owner, natural identity, digest, required
field equality, execution fact, manifest, terminal binding, or finalized-result
binding is absent or inconsistent. It MUST NOT emit a partial, caller-repaired,
or not-assessable PAE.

The immediate runtime issuer implementation commit MUST add adversarial tests
for caller PAE substitution and owner substitution against the real retained
authority graph. This normative contract commit MUST NOT create a test-only
authority graph as a substitute for that issuer test.

### `PREPARATION_ROW_INSTANCE_MANIFEST/1`

Digest domain: `ebm-audit/preparation-row-instance-manifest/1`.
Natural identity: `case_id`, `operation_instance_id`, `row_role`,
`row_instance_manifest_sha256`. Entries are ordered pairs
`(source_row_index, occurrence_ordinal)`. Ordinary rows use ordinal zero;
resampled occurrences use increasing draw-order ordinals.

### Source and transformed data

`same-case-source-data/1` and `same-case-transformed-data/1` are distinct
selectors. Each binds one `SYNTHETIC_SCIENTIFIC_DATA` owner to the same case and
operation. A transformation comparison also requires the exact authenticated
`PROPORTIONAL_OPERATION_PLAN` entry and `EXECUTED_TRANSFORMATION_EVIDENCE`,
joined by `case_operation_join_key`, `proportional_operation_plan_sha256`, and
`operation_plan_entry_sha256`. A generic combined source/transformed selector
or caller operation mapping is not sufficient.

### `SCENARIO_MATCHED_METRIC_RECORD/2`

Digest domain: `ebm-audit/scenario-matched-metric-record/2`.

Natural identity: `benchmark_subject_digest`, `comparator_id`,
`source_variant_id`, `replicate_index`, `pair_index`, `pairing_key`,
`left_member_id`, `right_member_id`, and `metric_id`. The comparator plan fixes
all pair and member identities. A caller-supplied pair alias or one untyped
member identity is not evidence.

The version 2 public record contains exact comparator identity, digest-only
provenance for both operands, recomputed finite operand values, the finite
named-left-minus-named-right value, an optional truth digest, status, reason
codes, and its record digest. Each operand binds one `PUBLIC_BATCH_CASE_PLAN`,
the exact `PROPORTIONAL_OPERATION_PLAN` entry, one successful or
convergence-warning `PUBLIC_TERMINAL_RESULT`, its `captured_run_sha256`, the
finalized-result and canonical-payload digests issued by capture, the unique
reference-chain plan position and execution, canonical array descriptor,
canonical-array artifact owner, and private canonical array-value projection.
All operation-bound owners agree on `case_operation_join_key`,
`proportional_operation_plan_sha256`, and `operation_plan_entry_sha256`. The
record does not contain a raw array, event order, truth order, participant
identity, biomarker value, held-out attempt, sealed case, or sealed result.

The only admitted metric IDs are the already accepted
`within-fit-mean-normalized-position-entropy/1` and
`central-order-kendall-distance/1`. This contract does not define another
metric. Entropy binds `order_state_chain` and has no truth owner. Kendall binds
`central_order_permutation` and one exact strict-truth owner.

#### Normative issuance algorithm

The D28 integration surface exposes this issuance contract. It does not expose
an array, scalar, summary, metric selector, orientation selector, or digest as a
trusted caller input. Runtime issuance is package-private and capability-bound.

For one planned matched pair, the future issuer MUST do all of the following:

1. Validate the complete matched-comparator evidence manifest and independently
   apply its executable invariants. Resolve exactly one comparator plan from
   `comparator_id`, `source_variant_id`, `replicate_index`, `pair_index`, and the
   reconstructed `pairing_key`. Require `left_member_id` and `right_member_id`
   to equal the two ordered plan members. Require complete `PASS` evidence for
   both members.
2. For each member, resolve exactly one `PUBLIC_BATCH_CASE_PLAN`, the exact
   member entry from one authenticated `PROPORTIONAL_OPERATION_PLAN`, and one
   `PUBLIC_TERMINAL_RESULT` read back from its exact `captured_run_sha256`.
   Recompute every public-owner digest and require a successful or
   convergence-warning terminal. Require exact equality of benchmark subject,
   batch, case, operation, member, `case_operation_join_key`, plan hash, and
   entry hash across the comparator, case, plan, and terminal owners.
3. Resolve each complete `CanonicalScientificPayload`. Recompute its digest
   under `ebm-audit/canonical-scientific-payload/1`. Require that digest and its
   complete finalized-result digest to equal the corresponding public terminal
   bindings. Require its subject and operation to equal the joined public case
   and operation-plan entry.
4. Apply `lowest-chain-plan-position/1` to the authenticated frozen chain plan.
   Resolve exactly one reference chain in each payload. Require the bound plan
   position, ordered payload index, chain execution, chain ID, and seed to equal
   that plan row and the captured run.
   A supplied chain position is not selection evidence.
5. Resolve the metric's exact array-catalog entry from the bound canonical
   pointer. Resolve and recompute the corresponding
   `CanonicalArrayArtifactOwner`. Resolve its private
   `PrivateCanonicalArrayValueProjection`. Require exact agreement for payload,
   public case, operation-plan entry, public terminal, captured run, finalized
   result, operation, chain, member name, pointer, dtype, shape, semantic
   version, axes, canonical array digest, artifact bytes, and array-value digest.
   Private array values MUST remain outside public records, reports, logs,
   exceptions, and default artifacts.
6. For `within-fit-mean-normalized-position-entropy/1`, require an `int32`
   retained `order_state_chain` with one permutation of the payload event set in
   every row. Recompute the position-probability matrix from those rows. Apply
   `src/ebm_audit/science/_evidence_records.py:_within_entropy_metrics` to the
   accepted event-position summaries. Take only its assessable mean normalized
   position entropy.
7. For `central-order-kendall-distance/1`, require an `int32`
   `central_order_permutation` that is one permutation of the payload event set.
   Resolve the complete synthetic strict-truth owner and recompute
   `truth_sha256` under `ebm-audit/synthetic-truth/1`. Require the inferred and
   truth orders to contain the same event set. Apply
   `src/ebm_audit/metrics/core.py:normalized_kendall_distance` without changing
   its denominator, tie behavior, or not-assessable behavior.
8. Require `left.recomputed_value` and `right.recomputed_value` to equal the two
   recomputed results. Compute `derived_value` as the exact named-left value
   minus the exact named-right value. Reject a caller-supplied value or
   orientation. Require all three values to be finite.
9. Build the digest preimage with `digest_state=DIGEST_PREIMAGE` and
   `scenario_matched_metric_record_sha256=null`. Recompute the record digest
   under `ebm-audit/scenario-matched-metric-record/2`. Persist only the matching
   `PERSISTED` record.

JSON Schema validation proves only the closed public shape. It does not prove
owner resolution, digest recomputation, private array equality, metric
recomputation, or subtraction. An integrity mismatch rejects issuance and emits
no persisted record. A genuinely unavailable scientific input retains the
planned pair as `NOT_ASSESSABLE`, uses null operand and derived values, and emits
at least one stable reason code.

Focused adversarial tests MUST replace each public-case digest, join key,
operation-plan digest, plan-entry digest, public-terminal digest, captured-run
digest, finalized-result digest, payload digest, operation, reference chain,
array pointer, array digest, artifact owner, private-value projection,
array-value digest, truth digest, member role, pairing identity, recomputed
scalar, derived scalar, status, and self digest in turn.
Each replacement MUST fail.
Tests MUST also reject a swapped left/right binding, a non-reference chain, an
entropy record with truth, a Kendall record without truth, a
non-finite scalar, an assessable record with a null value, and a not-assessable
record with a numeric value.

### `REPORT_WARNING_LEDGER/1`

Natural identity: `benchmark_subject_digest`, `case_id`,
`report_claim_projection_sha256`. It binds exact ordered warning-record
digests, warning count, the pre-render claim projection, and its own digest. It
contains no rendered artifact or post-render receipt field.

### `REPORT_TERMINAL_VISIBILITY/1`

Natural identity: `benchmark_subject_digest`, `case_id`,
`case_operation_join_key`, `public_terminal_result_sha256`,
`report_claim_projection_sha256`. It binds the exact plan, entry, terminal, and
pre-render projection identities with terminal count one. It contains no
rendered artifact or post-render receipt field.

### Historical `ANALYSIS_RULE_IDENTITY/1`

Natural identity: `rule_id`, `analysis_spec_sha256`. It binds `rule_id`, cutoff
quantile, finite cutoff value, comparator member index, analysis-spec hash, and
its own digest. Registry `2.1` does not use this configured-rule owner. It uses
the executed boundary-rule owner defined above. The only boundary instances
remain `boundary_q50` at `0.50`, `boundary_q35` at `0.35`, and `boundary_q65`
at `0.65`.

### `PRIVATE_CANONICAL_ARRAY_VALUE_PROJECTION/1`

Natural identity: `canonical_array_artifact_owner_sha256`, `member_name`,
`array_value_sha256`. This private canonical projection binds exact dtype,
shape, semantic version, axes, and value bytes to an authenticated
`CanonicalArrayArtifactOwner` and its metadata and digests. It is required by
every array-value lookup below and MUST NOT be exposed in public evidence.

### `CASE_INFLUENCE_AGGREGATE/1`

Natural identity: `case_id`, `baseline_universe_id`, `influence_rule_version`.
It binds one `SYNTHETIC_TRUTH` object through an
`INJECTED_SYNTHETIC_PARTICIPANT_TRUTH_IDENTITY/1`. That private identity contains
only the truth-object hash and the injected participant's zero-based internal
index. Its structured digest domain is
`ebm-audit/injected-synthetic-participant-truth-identity/1`. It MUST NOT contain
a private participant ID, participant alias, source-row identity, or raw value.

The aggregate also binds baseline execution and convergence state, baseline
result digest, the complete planned removal-identity digest sequence, and one
ordered `INFLUENCE_REMOVAL_EVIDENCE/1` for every planned removal. Each removal
record contains its digest-bound zero-based internal index, removal-identity
digest, result digest or explicit absence, execution state, convergence state,
capability state, comparability state, all six component records, equal-weight
aggregate score or explicit absence, reason codes, and its own digest. The six
components are central-order distance, maximum event-position displacement,
pairwise-precedence flips, position-matrix distance, convergence/fit change,
and change in other participants' expected-stage distributions. The aggregate
binds missing and duplicate counts and its own digest. Component evidence is
never replaced by the aggregate score.

## Derivation Semantics

Every section below additionally requires all Global Rules and the exact
registry-ordered owner slots.

<a id="actual-complete-case-removals-1"></a>
### 1. `actual-complete-case-removals/1`

Emit a `UIntVector` counting input row instances absent from training solely due
to the complete-case step in `PREPARATION_AUDIT_EVIDENCE/2`. Require exact
equality to the bound `DataAccounting` complete-case removal count.

<a id="analysis-rule-identities-1"></a>
### 2. `analysis-rule-identities/1`

Emit exactly `[boundary_q50, boundary_q35, boundary_q65]` from three
genuine `EXECUTED_BOUNDARY_RULE_IDENTITY/1` records with quantiles `0.50`,
`0.35`, and `0.65`. Require exact plan, entry, request, terminal, and result
bindings. An unexecuted configured rule is not evidence.

<a id="backend-nonfinite-admission-flag-1"></a>
### 3. `backend-nonfinite-admission-flag/1`

Emit true only when `backend_invoked=true` and either exact recomputed
all-finite flag is false. Emit false only when an invoked backend has complete
finite request/response proof, or when the correct pre-backend terminal has
`backend_invoked=false` and both all-finite fields are the required false
sentinels. The false sentinels are not non-finite admission evidence.

<a id="block-aware-scoring-flag-1"></a>
### 4. `block-aware-scoring-flag/1`

Require partial-order truth with a non-empty declared equivalence block. For the
required report predicate, map `PASS` to true and `FAIL` to false; `WARN` or
`NOT_ASSESSABLE` makes the family not assessable.

<a id="false-positive-qualification-state-2"></a>
### 5. `false-positive-qualification-state/2`

Require the same-case `SYNTHETIC_TRUTH`, the genuine pre-render null-calibration
report predicate, and the exact authenticated proportional operation plan.
Emit the closed `FalsePositiveQualificationState` object with status
`NOT_STATISTICALLY_QUALIFIED`, reason
`CALIBRATION.OPTIONAL_RESEARCH_STRESS_NOT_RUN`, strong-language eligibility
false, cautious fallback required, and optional profile
`benchmark-contract/0.1.3`. Presence reports qualification state. It does not
invent a false-positive rate or convert absent optional calibration to pass.

<a id="complete-preprocessing-refit-equality-1"></a>
### 6. `complete-preprocessing-refit-equality/1`

For `mcar_missingness:/payload/preprocessing_refit_equal`, resolve exactly one
authenticated `PROPORTIONAL_OPERATION_PLAN`, one same-case
`PREPROCESSING_EXECUTION_RECORD` selected as `SOURCE`, and one same-case
`PREPROCESSING_EXECUTION_RECORD` selected as `TRANSFORMED`. Reject a missing,
duplicate, relabelled, or cross-case record. The authenticated plan MUST contain
two distinct ordered MCAR entries for the same comparison case: `SOURCE` first
and `TRANSFORMED` second. Each execution record MUST bind its own entry, exact
operation ID, operation ordinal, complete `case_operation_join_key`, and
`operation_plan_entry_sha256`. The records MUST share the authenticated
`proportional_operation_plan_sha256`, benchmark subject, authenticated batch,
family, and MCAR comparison `case_id`. Their operation IDs, operation ordinals,
complete join keys, and entry hashes MUST differ. Authenticate both role-specific
entries before comparing procedure digests.

Emit true only when both roles use `complete_refit`; each binds its own
authenticated input and component-seed manifest; and both contain these exact
six step IDs in this order:

1. `prepared-input binding`;
2. `authenticated worker invocation`;
3. `fit-result validation`;
4. `convergence derivation`;
5. `pairwise concentration`; and
6. `position concentration`.

Each non-null `fit_population_manifest_sha256` MUST equal that record's
authenticated `training_row_manifest_sha256` or
`reference_fit_row_manifest_sha256`. Reconstruct and validate the closed
`CompleteRefitProcedureDigestPreimage` for each record, then require equal
`refit_procedure_sha256` values. The digest compares procedure identity only.
It excludes fitted parameters and fitted values. Do not infer equality from a
present digest, from one execution record, or by comparing fitted values.

<a id="declared-contamination-fraction-1"></a>
### 7. `declared-contamination-fraction/1`

After exact operation binding, emit the declared
`truth.group_truth.contamination_fraction` unchanged in selector order. Do not
emit a realized rounded fraction.

<a id="forbidden-report-claim-flag-1"></a>
### 8. `forbidden-report-claim-flag/1`

For the exact selector, `FORBIDDEN_TRUE` report state `FAIL` with
`forbidden_claim_count=1` emits true; `PASS` emits false. `WARN` or
`NOT_ASSESSABLE` makes the family not assessable.

<a id="null-family-denominator-exclusion-2"></a>
### 9. `null-family-denominator-exclusion/2`

For each label-permutation or within-group-feature-permutation case, require
the exact `REFITTED_NULL_TRANSFORMATION` truth identity, the authenticated
operation-plan entry, its executed transformation evidence, and its public
terminal. Both operations bind the plan-declared shared source
`moderate_mina_shape/pair_00/signal`; a result-selected source is invalid. Emit
true only when the complete identities prove that the case is a refitted
transformation null and not a pure-no-signal opportunity. Any missing,
duplicate, failed, or cross-bound owner makes the family not assessable.

<a id="group-count-accounting-equality-1"></a>
### 10. `group-count-accounting-equality/1`

For q50, q35, and q65, recompute labels from the exact bound cutoff. Emit true
only if reference and at-risk counts equal authenticated request, training,
returned, and universe counts with no unexplained loss.

<a id="group-count-preservation-1"></a>
### 11. `group-count-preservation/1`

For label permutation, require source/output axes, values, mask, and covariates
to be byte-identical. Emit whether label multisets, including multiplicity, are
equal under the exact operation identity and digests.

<a id="group-marginal-preservation-1"></a>
### 12. `group-marginal-preservation/1`

For feature permutation, require unchanged axes. For every group-event pair,
compare the exact multiset of `(missing flag, canonical finite bytes when
observed)` between source and transformed data.

<a id="hidden-imputation-flag-1"></a>
### 13. `hidden-imputation-flag/1`

Emit true when a source-missing selected cell becomes observed and finite
without a declared `IMPUTATION` step that covers it. False requires complete
coverage proof.

<a id="hidden-modification-flag-1"></a>
### 14. `hidden-modification-flag/1`

Emit true when a finite cell, missingness flag, row/event removal, cap, or
transformation changes outside the declared operation and exact
`DataAccounting`. False requires complete equality/accounting proof.

<a id="ineligible-strong-evidence-flag-1"></a>
### 15. `ineligible-strong-evidence-flag/1`

Use both authenticated rendered strong-label evidence and the complete failed
eligibility conjunction; `CandidateStrongEvidenceDecision` alone is
insufficient. Emit true only for rendered
`STRONGER_THAN_CHOSEN_REFITTED_NULLS` while eligibility fails, false when the
case is assessable and that conjunction is absent, and otherwise make the
family not assessable.

<a id="influence-rule-state-1"></a>
### 16. `influence-rule-state/1`

The rule version MUST be
`influence-injected-participant-six-component-midranks/1`. Bind, in order, the
public outlier-sabotage case plan, exact proportional removal-operation plan,
all per-operation public terminals, the same-case `SYNTHETIC_TRUTH`, and the
same-case `CASE_INFLUENCE_AGGREGATE/1`. The truth MUST declare exactly one
injected participant. Recompute its
`INJECTED_SYNTHETIC_PARTICIPANT_TRUTH_IDENTITY/1` structured digest and require
exact equality to the aggregate identity. Match that zero-based internal index
to exactly one planned removal. Direct participant IDs, participant aliases,
source-row identities, and raw values are forbidden.

For each planned case, let `m` be the number of planned removals and require
`m >= 2`. Require the ordered removal records to have the same length, order,
and identity digests as the planned removal sequence, with no duplicate internal
index or identity digest. Every record MUST preserve these six non-negative
finite component values in this order: central-order distance, maximum
event-position displacement, pairwise-precedence flips, position-matrix
distance, convergence/fit change, and change in other participants'
expected-stage distributions where comparable. Larger values always mean more
influence.

Within one case, rank every planned removal separately for each component in
descending value order. Rank one is the largest value. Exact ties receive the
arithmetic mean of their occupied ranks. For midrank `r`, the deterministic
scaled score is `(m-r)/(m-1)`. The per-removal aggregate is the arithmetic mean
of the six scaled scores. Each component has weight `1/6`. No fitted or
data-dependent weight is permitted. Recompute and exactly match every stored
midrank and aggregate score. The stored component values and midranks remain
the primary evidence; the aggregate is rule and display convenience only.

A planned case is a success only when the baseline and every planned removal
have execution state `SUCCESS`, convergence state `CONVERGENCE_PASS`, capability
state `FULL_SIX_COMPONENT`, comparability state
`ALL_COMPONENTS_COMPARABLE`, six assessable component values, and exact ranks.
The injected participant's aggregate score MUST then be strictly greater than
every other removal's score. A tie for the highest aggregate score is not a
success. An explicit `FAILED` or `MISSING` execution, convergence warning or
failure, partial or unsupported capability, non-comparability, missing
component, non-finite component, missing planned removal result, or duplicate
removal makes that planned case unsuccessful. Such a case is not dropped.

Let `R` be the authenticated number of planned outlier-sabotage cases and `S` the
number of successful planned cases. The denominator is always `R`. Failed or
missing planned case results remain in `R` and cannot increment `S`. The strict
majority threshold is exactly `2*S > R`; it is not estimated from development
fixtures. Emit one `PASS` when the complete authenticated evidence satisfies
that inequality. Emit one `FAIL` when the complete authenticated evidence does
not satisfy it, including `2*S == R`. Emit one `NOT_ASSESSABLE` only when the
authenticated denominator, truth identity, case binding, aggregate binding, planned
removal identities, or required structured digests cannot be authenticated or
when the records are malformed or cross-bound. An explicit failed or missing
runtime result in an otherwise authenticated complete record is `FAIL`
evidence, not `NOT_ASSESSABLE`. The outer rule remains fail-closed under Global
Rule 5.

<a id="internal-concentration-flag-1"></a>
### 17. `internal-concentration-flag/1`

Use only `precision-report-predicate/1`. Emit true when a forbidden concentrated
or precise single-order label appears for the non-identifiable family; emit
false only when authenticated evidence proves it absent.

<a id="known-truth-order-rule-state-1"></a>
### 18. `known-truth-order-rule-state/1`

For 24 valid cases, compute central-order agreement as one minus normalized
Kendall distance to strict truth. Compute q50 and q10. Pass at q50 at least
`0.90` and q10 at least `0.75`; warn at q50 at least `0.80` and q10 at least
`0.60`; otherwise fail. Emit that one family result as `order_rule_states`;
do not emit one state per case.

<a id="known-truth-stage-rule-state-1"></a>
### 19. `known-truth-stage-rule-state/1`

Align posterior rows to truth stages by source-row identity. Expected stage is
`fsum(s*p_s)`. For each case, compute mean absolute error over training rows and
divide by event count. Across 24 cases compute q50 and q90. Pass at q50 at most
`0.10` and q90 at most `0.20`; warn at q50 at most `0.15` and q90 at most
`0.30`; otherwise fail. Emit that one family result as `stage_rule_states`;
do not emit one state per case.

<a id="label-manifest-equality-1"></a>
### 20. `label-manifest-equality/1`

Require generated observed labels to equal truth elementwise in participant
order. Contaminated count and fraction MUST agree, with exact case and digest
binding.

<a id="matched-cross-chain-delta-1"></a>
### 21. `matched-cross-chain-delta/1`

For the small-sample output, resolve the complete matched comparator plan, then
resolve exactly one successful or convergence-warning `PUBLIC_TERMINAL_RESULT`
and its exact canonical payload for each small and large member. Join each
terminal to its public case, operation-plan entry, captured run, finalized
result, and payload through subject, comparator, source variant, replicate,
pair, member, `case_operation_join_key`, plan hash, entry hash, operation,
terminal, result, and payload identities. From each payload, resolve the
complete declared chain set and the private `order_state_chain` projection for
every chain through the shared canonical-array assembler. Require exact
chain-plan order, event-set equality, descriptor/value agreement, and one
permutation of the event set in every retained row. A caller-selected chain,
array, member, terminal, result, value, or order is not evidence.

For each member, compute every unordered chain-pair position-matrix distance and
take its nearest-rank q50. Emit small minus large. Positive means the small
member is less stable. Do not issue or consume a scenario matched-metric record
for this output. A missing chain or any binding, convergence, array, permutation,
or finite-value defect applies Global Rule 5.

<a id="matched-entropy-delta-1"></a>
### 22. `matched-entropy-delta/1`

Use the existing within-fit mean normalized position entropy and emit named-left
minus named-right for small-large, weak-moderate, slow-narrow, and
mixture-single comparisons.

<a id="matched-kendall-agreement-1"></a>
### 23. `matched-kendall-agreement/1`

For contamination, emit the contaminated member's one minus normalized Kendall
distance between central order and strict truth. The clean member authenticates
pairing only.

<a id="matched-kendall-delta-1"></a>
### 24. `matched-kendall-delta/1`

Emit left minus right distance for weak-moderate and slow-narrow. For covariate
comparisons emit adjusted minus unadjusted agreement, and for direction emit
correct minus wrong agreement, regardless of manifest order.

<a id="matched-position-entropy-1"></a>
### 25. `matched-position-entropy/1`

For contamination, emit the contaminated member's within-fit mean normalized
position entropy. The clean member authenticates pairing only.

<a id="missing-count-equality-1"></a>
### 26. `missing-count-equality/1`

Recompute global and per-event counts from truth mask and scientific-data mask.
Require exact equality to each other and to preparation counts.

<a id="missing-count-preservation-1"></a>
### 27. `missing-count-preservation/1`

For feature permutation, require equal axes and groups and exact equality of
global, per-group, and per-event missing counts.

<a id="missingness-mask-digest-equality-1"></a>
### 28. `missingness-mask-digest-equality/1`

Require elementwise equality between the data mask and truth mask and require a
recomputed existing-domain mask digest to equal the truth digest.

<a id="moderate-matched-null-rule-state-1"></a>
### 29. `moderate-matched-null-rule-state/1`

Resolve the complete 24-pair comparator plan. For every signal and matched-null
member, resolve exactly one successful or convergence-warning
`PUBLIC_TERMINAL_RESULT` and its exact canonical payload. Join the public case,
operation-plan entry, captured run, terminal, finalized result, and payload by
subject, comparator, source variant, replicate, pair, member,
`case_operation_join_key`, plan hash, entry hash, operation, result, payload,
and complete declared chain identities. Use the shared canonical-array
assembler to resolve each chain's private `order_state_chain` projection.
Derive each chain central order as the modal permutation of its retained order
rows, with the existing lexicographic tie rule. Resolve the authenticated
source-reference truth and compute the existing fixed-reference alignment.
Never accept a worker headline order or a supplied alignment.

For each signal member, also resolve its private
`training_stage_posterior` projection, the exact training
`PREPARATION_ROW_INSTANCE_MANIFEST`, and the authenticated stage truth. Align
posterior rows to truth only by the ordered `(source_row_index,
occurrence_ordinal)` identities. Require compatible stage axes and compute the
existing normalized stage mean absolute error. Take each member's convergence
state only from its authenticated public terminal and canonical payload. Do not
issue or consume a scenario matched-metric record for this output.

This is the proportional 24-pair rule and is distinct from the development
eight-pair rule. For each pair, `d_r` is the signal member's universe-median reference
alignment minus its matched-null counterpart. Alignment median is empirical q50
(12th ordered value). Signal stage upper median is the 13th ordered signal
median normalized stage MAE. Let `Tobs=fsum(d)/24`. Enumerate all `2^24` sign
assignments and compute `Ts=fsum(s*d)/24`; count the inclusive upper tail
`Ts >= Tobs-1e-12`, retain zero differences, use no Monte Carlo and no plus-one
correction, and set `p=tail_count/2^24`. The p pass comparison is
`20*tail_count <= 2^24`.

State order is `[reference_alignment, paired_randomization,
signal_stage_mae, convergence]`. Alignment passes at least `0.15`, warns at
least `0.05`, otherwise fails. A valid paired p passes at most `0.05` and warns
above `0.05`; structural/binding defects fail or are not assessable. Stage
passes at most `0.25`, warns at most `0.35`, otherwise fails. Convergence passes
only when exactly one. Family state passes when all pass, warns when none fail
or are not assessable and at least one warns, and fails when any fail or are not
assessable. Require exactly 24 pairs and 48 convergence states with no dropping
or retry. Emit the four component states in the stated order as
`moderate_rule_states`; do not emit one aggregate state per case.

<a id="noise-ladder-monotonic-rule-state-1"></a>
### 30. `noise-ladder-monotonic-rule-state/1`

Resolve the complete noise-ladder comparator plan in level then replicate order.
For every planned level member, resolve exactly one successful,
convergence-warning `PUBLIC_TERMINAL_RESULT` and its exact canonical payload.
Join the public case, operation-plan entry, captured run, terminal, finalized
result, and payload by subject, comparator, source variant, replicate, pair,
member, `case_operation_join_key`, plan hash, entry hash, operation, result,
payload, and complete declared chain identities. Use the shared canonical-array
assembler to resolve the private `order_state_chain` projections. Derive the
central order from the retained rows under the existing modal-permutation and
lexicographic tie rules. Resolve the matching strict truth, compute agreement as
one minus the existing normalized Kendall distance, and compute the existing
within-fit mean normalized position entropy from the same authenticated rows. A
supplied level, order, entropy, agreement, convergence state, or orientation is
not evidence. Do not issue or consume a scenario matched-metric record for this
output.

Use SD levels `[0.20,0.55,0.90,1.25,1.60]` with 12 replicates each. Compute
nearest-rank q50 agreement and entropy at each level, then Spearman correlation
of SD with each median. Pass when agreement rho is at most `-0.70` and entropy
rho is at least `0.70`; warn at `-0.40` and `0.40`; otherwise fail. Emit that
one family result as `noise_ladder_rule_states`; do not emit one state per case.

<a id="nonfinite-admission-flag-1"></a>
### 31. `nonfinite-admission-flag/1`

Apply the backend non-finite admission rule to the heavy-tail family. A visible
terminal failure alone is not evidence of admission.

<a id="null-source-binding-equality-1"></a>
### 32. `null-source-binding-equality/1`

Require exact source and output data digests, public batch case-plan digests,
operation-plan and entry hashes, executed-transformation digests, public
terminal digests, and captured-run provenance. Require exact family,
transformation, operation, subject, case, `case_operation_join_key`, seed, and
replicate bindings. A sealed-case digest or held-out attempt is not an ordinary
source binding.

<a id="opposing-pair-absolute-precedence-from-half-1"></a>
### 33. `opposing-pair-absolute-precedence-from-half/1`

Require every unordered pair to reverse between subgroup orders. Orient each
pair with the UTF-8-smaller event first, order pairs lexicographically, and emit
`abs(P(a before b)-0.5)` for at least one pair.

<a id="participant-event-alignment-change-1"></a>
### 34. `participant-event-alignment-change/1`

For feature permutation, require preserved axes, groups, and multisets and an
exact replay manifest. Emit true only when at least one actual participant-event
value or missingness assignment changes; a non-identity index permutation with
duplicate values is insufficient.

<a id="partial-truth-scoring-without-tiebreak-1"></a>
### 35. `partial-truth-scoring-without-tiebreak/1`

Require exact-duplicate subtype partial truth, `EXACT_DUPLICATE` reason, and the
target pair in one equivalence block. Map the `REQUIRED_TRUE` report outcome
`PASS` to true and `FAIL` to false; other states make the family not assessable.

<a id="prebackend-terminal-contract-1"></a>
### 36. `prebackend-terminal-contract/1`

For `missingness=error` with a selected missing value, require
`INVALID_INPUT/DATA.MISSING_EVENT_VALUE`, backend false, and no fit arrays. For
`complete_case`, remove predicted rows; if none survive require
`INVALID_INPUT/DATA.NO_SELECTED_ROWS` pre-backend, otherwise require the normal
capability contract. All other branches require their exact frozen status,
reason, and invocation state.

<a id="predicted-complete-case-removals-1"></a>
### 37. `predicted-complete-case-removals/1`

Count input-order rows missing any consumed event or covariate under
`complete_case`. Emit zero for error and other non-complete-case policies.

<a id="reference-only-preprocessing-fit-1"></a>
### 38. `reference-only-preprocessing-fit/1`

Require method `reference-group-ordinary-linear-residualisation/1`. Every
fit-bearing step population MUST exactly equal current-resample reference rows,
contain no at-risk rows, and apply its parameters to both groups. Empty or
mismatched populations make the family not assessable.

<a id="report-decision-attribution-1"></a>
### 39. `report-decision-attribution/1`

For q50, q35, and q65, a bound `REQUIRED_TRUE` report `PASS` emits
`DESCRIPTIVE_ASSOCIATION`. `FAIL`, `WARN`, or `NOT_ASSESSABLE` makes the family
not assessable. Require the matching genuine
`EXECUTED_BOUNDARY_RULE_IDENTITY/1`.

<a id="required-report-claim-flag-1"></a>
### 40. `required-report-claim-flag/1`

For coverage, single-sequence limitation, direction sensitivity, and null
calibration selectors, map `REQUIRED_TRUE` `PASS` to true and `FAIL` to false;
other states make the family not assessable.

<a id="resample-leakage-count-1"></a>
### 41. `resample-leakage-count/1`

Build the allowed multiset from ordered source-row indexes with occurrence
ordinals. Count the union of fit-population row instances absent from that set
and reference-only fit rows that are not reference rows. Count each row instance
once. Resolve exactly four same-case `PREPARATION_ROW_INSTANCE_MANIFEST`
owners in canonical role order: `INPUT`, `TRAINING`, `OUTPUT`, then
`REFERENCE_FIT`. Each role uses its exact role selector and `ONE_PER_CASE`
cardinality. A combined all-role selector, missing role, duplicate role,
reordered role, or role substitution is invalid.

<a id="selected-threshold-flag-1"></a>
### 42. `selected-threshold-flag/1`

For q50, q35, and q65 with genuine
`EXECUTED_BOUNDARY_RULE_IDENTITY/1`, map a
threshold-selection `FORBIDDEN_TRUE` outcome of `FAIL` with forbidden count one
to true and `PASS` to false. Other states make the family not assessable. The
current `AnalysisSpec` natural identity alone cannot prove this rule identity.

<a id="silent-row-loss-flag-1"></a>
### 43. `silent-row-loss-flag/1`

Derive expected training and output row-instance manifests. Emit true when
actual manifests differ or `DataAccounting` lacks exact identity and reason
conservation. False requires input equals retained plus declared removals,
including multiplicity. Resolve exactly four same-case
`PREPARATION_ROW_INSTANCE_MANIFEST` owners in canonical role order: `INPUT`,
`TRAINING`, `OUTPUT`, then `REFERENCE_FIT`. Each role uses its exact role
selector and `ONE_PER_CASE` cardinality. A combined all-role selector, missing
role, duplicate role, reordered role, or role substitution is invalid.

<a id="stronger-than-null-flag-1"></a>
### 44. `stronger-than-null-flag/1`

From a validated same-case `CandidateStrongEvidenceDecision`, emit true for
`STRONG`, false for `NOT_STRONG`, and make the family not assessable for `NA`.

<a id="subtype-case-identities-1"></a>
### 45. `subtype-case-identities/1`

Read `scenario_subtype_id` from the exact proportional operation plan, resolve
each entry to its genuine public case plan, filter exactly `CORRELATED` or
`EXACT_DUPLICATE_POST_NOISE`, and emit unique case IDs in public case ordinal
order. Require exactly six of each subtype.

<a id="suppressed-warning-flag-1"></a>
### 46. `suppressed-warning-flag/1`

Bind exact ordered `WarningRecord` digests to the report warning ledger and
receipt. Emit true when any required source warning is absent or any count or
file digest differs; emit false only for exact equality, including empty sets.
Do not match warning text.

<a id="terminal-contract-equality-1"></a>
### 47. `terminal-contract-equality/1`

For MAR, apply the pre-backend branch table plus resampling and preprocessing.
Emit true only when terminal, status, reason, backend invocation, and invalid
array absence exactly match the expected branch.

<a id="training-row-manifest-equality-1"></a>
### 48. `training-row-manifest-equality/1`

Recompute the shared-domain ordered training row-instance manifest after
selection and resampling. Require exact digest equality across preprocessing,
participant request, participant return, and every applicable fit step.

<a id="truth-block-pair-precedence-1"></a>
### 49. `truth-block-pair-precedence/1`

Use truth block order. Within each block orient unordered pairs by UTF-8 event
ID and sort pairs lexicographically. Require exact axes and at least one pair,
then flatten `P(a before b)` in that order.

<a id="truth-scoring-mode-1"></a>
### 50. `truth-scoring-mode/1`

Apply this total map: `STRICT_TOTAL_ORDER` to `STRICT_TOTAL_ORDER`;
`PARTIAL_ORDER` to `PARTIAL_ORDER_EQUIVALENCE`;
`MIXTURE_OF_STRICT_ORDERS` to `MIXTURE_NON_IDENTIFIABLE`; `NONE` plus
`PURE_NO_SIGNAL` to `NO_RECOVERABLE_SIGNAL`; and `NONE` plus
`REFITTED_NULL_TRANSFORMATION` to `REFITTED_NULL_TRANSFORMATION`. Every other
tuple makes the family not assessable.

<a id="truth-target-pair-precedence-1"></a>
### 51. `truth-target-pair-precedence/1`

Use truth-order event IDs and the declared ordered target `[a,b]`; require both
unique and present. Read the private float64 `N x N` precedence value projection
bound to `CanonicalArrayArtifactOwner` and emit `M[index(a),index(b)]`. Require
diagonal `0.5` and complementary cells summing to one.

<a id="truth-targeted-tail-entropy-delta-1"></a>
### 52. `truth-targeted-tail-entropy-delta/1`

Resolve the complete restricted/broad comparator plan. Resolve exactly one
successful or convergence-warning `PUBLIC_TERMINAL_RESULT` and its exact
canonical payload for each member. Join the public case, operation-plan entry,
captured run, terminal, finalized result, and payload by subject, comparator,
source variant, replicate, pair, member, `case_operation_join_key`, plan hash,
entry hash, operation, result, payload, and complete declared chain identities.
Use the shared canonical-array assembler to resolve every declared chain's
private `order_state_chain` projection. Require exact chain-plan order,
event-set equality, descriptor/value agreement, and one permutation of the
event set in every retained row. Resolve the affected-tail truth and require
its event set to be non-empty, unique, and present in both payloads. A
caller-selected member, array, tail, value, or orientation is not evidence.

Compute the existing normalized position entropy for each affected-tail event
from each member's authenticated rows. Take `fsum/n` for the exact tail and emit
restricted minus broad. Do not issue or consume a scenario matched-metric record
for this output. A missing member, chain, event, or any binding, convergence,
array, permutation, or finite-value defect applies Global Rule 5.

<a id="visible-terminal-flag-1"></a>
### 53. `visible-terminal-flag/1`

Require exactly one `PUBLIC_TERMINAL_RESULT` per planned operation. Join it by
the complete `case_operation_join_key` and exact plan-entry hash. Require the
exact terminal digest, status, and reason in the pre-render report projection.
Emit true only for complete equality. Post-render visibility is verified once
by `ReportSurfaceVerificationReceipt`; disk existence alone is insufficient.
