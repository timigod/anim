# Synthetic and null validation contract

Status: `FROZEN`

Generator contract: `synthetic/v0.1.0`

Null contract: `nulls/v0.1.0`

The project-owned generator defined by this contract tests software and
scientific failure behavior against known mechanisms. The production generator
and an independently implemented numerical replay executor now exist. Their
outputs become conformance evidence only through the closed schema-owned receipt
and complete canonical synthetic gates. This
design does not recreate the Idris/LonDownS cohort, and its parameters are not
estimates of that population. All events use generic synthetic IDs. Every output
is labelled `SYNTHETIC` in its schema, filenames, report, and provenance.
For product readiness, these synthetic artifacts evaluate the exact
project-owned `SYNTHETIC-ONLY` conformance EBM through the ordinary generic
worker. That readiness subject is backend-neutral; a named backend is not a
precondition for running or passing this contract.

The executable boundaries are
[`synthetic-resolved-configuration.schema.json`](../../schemas/synthetic-resolved-configuration.schema.json),
[`synthetic-scientific-data.schema.json`](../../schemas/synthetic-scientific-data.schema.json),
[`synthetic-truth.schema.json`](../../schemas/synthetic-truth.schema.json),
[`comparator-transaction.schema.json`](../../schemas/comparator-transaction.schema.json),
[`scientific-invariant.schema.json`](../../schemas/scientific-invariant.schema.json),
[`scenario-evidence.schema.json`](../../schemas/scenario-evidence.schema.json),
and the closed
[`scenario_derivation_registry.json`](https://github.com/timigod/anim/blob/main/evaluator/scenario_derivation_registry.json).
These schemas use closed Draft 2020-12 objects and reject unknown fields. Every string
MUST already be Unicode NFC; a parser rejects a non-NFC string and MUST NOT
normalize or rewrite it before validation or hashing.

Raw generator artifacts and canonical analysis objects have four distinct
identities. `resolved_generator_configuration_sha256` hashes the raw resolved
generator configuration, while `case_configuration_sha256` hashes the
canonical case configuration. `generated_scientific_data_sha256` hashes the
raw synthetic scientific-data object, while `input_digest` hashes the
canonical scientific payload supplied to analysis. None is an alias for
another, and each is recomputed from its own closed schema and domain.

## 1. Generative model

For participant `j` and event `i`, draw a latent disease coordinate `t_j` from the exact mechanism below. Define:

```text
g_i(t_j) = 1 / [1 + exp(-(t_j - tau_i) / w_i)]
h_j = 0  if group_j = reference;  h_j = 1  if group_j = at_risk
x_ji* = b_i + d_i a_i g_i(t_j) + beta_i^T z_j + gamma_i h_j + lambda_i u_j + epsilon_ji
```

where:

- `tau_i` is the event transition center;
- `w_i > 0` is transition width;
- `b_i` is baseline location;
- `a_i > 0` is amplitude;
- `d_i` is `+1` for higher-is-more-abnormal and `-1` for lower-is-more-abnormal;
- `z_j` is a fully declared synthetic covariate vector and `beta_i` its event effect;
- `h_j` is the fixed binary group encoding above and `gamma_i` is the declared
  event-specific `group_effect[i]`; it is not inferred from the latent window;
- `u_j` is a participant random effect with declared distribution and loading `lambda_i`; and
- `epsilon_j` is a declared multivariate measurement-noise draw.

The default noise is `epsilon_j ~ Normal(0, D R D)`, where `D` contains event-specific standard deviations and `R` is a positive-definite declared correlation matrix. Every distribution family and parameter is in the truth object.

`gamma` is resolved as the complete event-length `group_effect` vector during
the `event_arrays` dependency stage. Resolution consumes no component RNG draw.
At generation time the already-drawn `group_assignment` supplies `h_j`; the
term `gamma_i h_j` is applied after the logistic and covariate terms and before
the participant-effect and measurement-noise terms. The resolved configuration
and truth object retain the vector in event-ID order. Changing this encoding,
stage, or order is a generator-contract version change.

The truth object also retains one `ordered_participants` row for every exact
zero-based generated-data participant index. Each row binds the latent time,
participant effect, original and observed group labels, binary `h_j`, the full
event-ordered `gamma_i h_j` vector, values before that group term, values before
missingness, and the participant's threshold stage or `null`. The legacy
participant vectors and group-label vectors are exact projections of these
indexed rows. Every non-missing generated cell must equal the row's
pre-missingness value; changing a group label, group-effect vector, participant
order, or group term without changing the exact owned row therefore fails.

The raw `SyntheticScientificData` object independently retains the exact
generator-owned `generation_components`: participant indexes; the original
generation labels; latent times; participant effects; binary group indicators;
transition-signal, covariate, participant-effect, and measurement-noise terms;
the standard-normal measurement draws; values without the group term; the
event-ordered group contribution; and pre-missingness values. Analysis labels
are a separate observed vector. `h_j` is derived only from the original
generation label, so binary label contamination can change the analysis label
without changing the generated signal.

The production evaluator must independently re-derive the HMAC component seed,
replay the exact pinned NumPy `PCG64DXSM` standard-normal array, reconstruct the
correlated noise, recompute every deterministic equation term, and then
reconstruct both `values_without_group_effect` and `pre_missingness_values`.
`generated_scientific_data_sha256` covers all of those primitive and derived
outputs together with the final values and mask. Truth rows must be
byte-equivalent projections of these indexed outputs. A changed `gamma_i`
therefore cannot be hidden by shifting a residual or even by rehashing a
compensating generated-data object; the replayed primitive would differ. A
joint latent-time/stage reversal likewise fails against the unchanged generated
data owner. The present verifier exercises this rule on contract fixtures only;
that is not production generator replay or scientific evidence.

### 1.1 Deterministic component RNGs

No global RNG is used. Every generated owner has a non-null unsigned 64-bit
`case_seed`, serialized as the canonical 16-lowercase-hex `UInt64Hex` string.
An exact matched comparator may additionally carry one immutable
`shared_draw_seed`; a refitted null transformation carries one immutable
`operation_seed`. Optional roots do not silently replace the case root. For each
component path in this ordered registry,

```text
parameters, group_assignment, latent_time, covariates, participant_effect,
subgroup_assignment, measurement_normal, measurement_scale,
measurement_skew, contamination, outliers, missingness,
label_permutation, within_group_feature_permutation
```

derive:

```text
component_digest = HMAC-SHA-256(
  key = hex_to_bytes(component_root_seed),
  message = utf8("ebm-audit-synthetic-component/v1\0" + component_path)
)
component_seed_bytes = first_16_bytes(component_digest)
rng = numpy.random.Generator(
  numpy.random.PCG64DXSM(uint128_be(component_seed_bytes))
)
```

The root is selected by one exact three-way algorithm, in this order:

1. use `OPERATION_SEED` only for `label_permutation` in a
   `label_permutation_null` case or `within_group_feature_permutation` in a
   `within_group_feature_permutation_null` case;
2. otherwise use `SHARED_DRAW_SEED` only when the component path occurs in the
   matched comparator's closed `shared_component_paths`; and
3. otherwise use `CASE_SEED`.

The operation and shared path sets must be disjoint. `operation_seed` is null if
and only if `operation_component_paths` is empty; the same rule applies to
`shared_draw_seed` and `shared_component_paths`. A supplied optional root never
changes an undeclared path. `ComponentSeedRecord.shared` is true exactly for a
`SHARED_DRAW_SEED` record. The component manifest retains both path sets, every
selected root kind, full digest, 128-bit seed, NumPy version, and bit-generator
name. The evaluator, not the manifest, supplies a typed root-assignment context
and resolves it against the closed comparator or null-operation plan. It derives
the optional root, both path lists, and every component seed itself. The
manifest may only repeat that result. A self-consistent but resealed manifest
that chooses another context, root, path list, shared seed, or operation seed
fails.

A participant-by-event array has shape `(J,N)` and is drawn in C order: event
index varies fastest within one participant row, then participant index
increments. Implementation tests pin this draw sequence. Adding a component
requires a new registry/version; it may not shift another component's stream.

The retained 128-bit component seed is exactly 32 lowercase hexadecimal
characters. Every 64-bit derived case/null/shared seed retained in truth or a
manifest is `UInt64Hex`. The full component digest uses the protocol
`sha256:<64 lowercase hex>` form.

Every scenario field is resolved through the closed `generator_field_registry`
in the frozen development scenario registry. That
registry assigns one value type, one allowed-range representation, and one draw
rule to every field. Unknown fields and values whose YAML type does not match
the registry are `GENERATOR_INVALID`. In particular, a two-number
`fixed_float64_interval` with `allowed_form: literal_endpoint_vector` is one
literal pair of endpoints and is never sampled as a scalar range; a float64
field with `allowed_form: inclusive_scalar_range` is sampled on the declared
decimal tick grid; and an integer field with that allowed form is sampled by
inclusive discrete uniform. YAML shape alone never determines semantics.

### 1.1.1 Case identity

Case identity is derived, never formatted ad hoc:

```text
case_id = family_id + "-v" + canonical_unsigned_decimal(variant_index)
                    + "-r" + canonical_unsigned_decimal(replicate_index)
```

The decimal form uses ASCII digits, has no sign, and has no leading zero unless
the value is zero. The same value must appear in synthetic truth, generated
data, the sealed case record, filenames, evidence owners, and report references.
`variant_id` remains descriptive metadata and is not substituted into this
numeric formula. Comparator member identity remains in the comparator fields;
it is not appended to `case_id`.

### 1.1.2 Private attempt resolution

`CONFIDENTIAL_CASE_SEED_V1` is the first eight bytes of HMAC-SHA-256, rendered
as lowercase `UInt64Hex`. Its key is the evaluator-private verified 32-byte
attempt root and its exact message is
`utf8("ebm-audit-heldout-case/v1") || NUL || ascii(heldout_attempt_id) || NUL ||
utf8(family_id) || NUL || ascii(canonical_unsigned_decimal(variant_index)) ||
NUL || ascii(canonical_unsigned_decimal(replicate_index))`. The descriptive
`variant_id` is excluded. Attempt identity is bound to the already verified
root commitment before this one-shot capability may resolve its single frozen
coordinate. The capability is opaque and exact-type checked; callers cannot
construct it, reuse it, substitute a duck type, inspect seed material, or
override its coordinate, numeric variant, source binding, family override, or
pre-root mode.

For authenticated `TRANSFORMED_SOURCE` cases in either required permutation
null family, zero-based field 61 is the fixed literal `59` from the selected
authenticated development variant. It consumes no parameter draw. Direct
`HELDOUT_RANGE` resolution of either transformation family is invalid, and the
field never expands cases, operations, Fits, or a nested battery.

After a coordinate is claimed, a dependency failure retains a closed immutable
`GENERATOR_INVALID` result with the attempt ID, canonical coordinate, numeric
variant index, canonical case ID, source/scenario digests, complete ordered
71-field ledger, draw count, failed stage index/ID, and a stable
`GENERATOR.[A-Z0-9_]+` reason. The ordered dependency stages are
`participants`, `events`, `group_counts`, `mechanism`, `event_arrays`,
`covariance_validity`, and `matched_comparator_overrides`. The original case is
not redrawn or replaced. It enters the existing `COMPILE_TIME_NON_SUCCESS`
`GENERATOR_INVALID` branch with no worker, Fit, retry, or science payload;
its planned denominator is retained and its rule state is `FAIL`. Authority,
source, commitment, and capability failures before a valid claim remain hard
errors. Public resolver returns, errors, strings, and representations contain no
root, HMAC message, case seed, or component seed.

### 1.1.3 Exact numerical kernel

The normative kernel is the `numerical_kernel_contract` in the frozen
development scenario registry. All scalar
arithmetic is NumPy `float64`. Event centers use the declared binary64 subtract,
divide, multiply, then add order. The sigmoid uses the two-branch stable formula:
for `q=(t-tau)/w`, compute `1/(1+exp(-q))` when `q>=0`; otherwise compute
`exp(q)/(1+exp(q))`. Cell terms are added by a left fold in this order:
baseline-plus-transition, covariate, group, participant, base measurement noise,
centered skew. Reassociation and implementation-selected reductions are
forbidden.

Build `Sigma=D R D` in float64 and retain the lower Cholesky factor `L` for
which `Sigma=L L^T`. Draw `Z` with shape `(J,N)` in C order and compute noise
as `Z @ L.T`, equivalently `L @ Z[j,:]` for each participant. `L.T @ Z[j,:]`
is the wrong orientation. Float arrays used in byte digests are C-contiguous
little-endian `<f8`; masks are C-order bytes containing only 0 or 1; index
arrays are little-endian signed 64-bit unless another closed schema says
otherwise.

Seeds, draws, IDs, shapes, masks, permutations, exact duplicate columns, bytes,
and hashes compare exactly. Independent equation replay outside the frozen
golden environment may use only `rtol=0, atol=1e-12` for finite derived
float64 values. Tolerance never applies to a hash preimage or discrete value.
Any non-finite intermediate is `GENERATOR_INVALID`. Golden vectors remain
explicitly `UNFROZEN` until the generator and environment are frozen.

### 1.2 Groups, latent coordinate, covariates, and participant effect

For window sampling, set `J_ref = clamp(round_half_even(J * reference_fraction), 1, J-1)` and `J_risk = J-J_ref`. Build exactly those labels, shuffle them once with `group_assignment`, then draw independently in participant-index order:

```text
t_j ~ Uniform(reference_window_low, reference_window_high)  if group_j = reference
t_j ~ Uniform(at_risk_window_low, at_risk_window_high)      if group_j = at_risk
```

Both intervals are finite and half-open; invalid or empty intervals fail generation. For the optional `discrete_stage_mixture` mode, the scenario supplies finite latent support `[L,U]` and probabilities `p_0..p_N` summing to one. Draw `K_j ~ Categorical(p)` by inverse CDF, then draw `t_j` uniformly in the half-open intersection of `[L,U]` with the stage interval bounded by adjacent sorted event centers (the final interval includes `U`). An empty selected interval is invalid. No stage mixture is inferred from group labels.

Each declared continuous covariate is drawn from its explicit Normal or Uniform distribution; each categorical covariate uses an explicit probability vector and fixed level order. Unless a scenario overrides it, there are no covariates. The participant random effect is exactly

```text
u_j ~ Normal(0, sigma_u^2)
```

drawn independently in participant order. `lambda_i` is a declared scalar or event-length vector. No participant effect is embedded into measurement noise.

### 1.3 Correlated, heavy-tailed, and skew noise

Construct `Sigma = D R D` and its lower Cholesky factor `L` after a float64 symmetric-positive-definite check. For each participant draw `z_j ~ Normal(0,I_N)` and use `L z_j`.

For `multivariate_student_t`, require integer or decimal `nu > 2`, draw `q_j ~ ChiSquare(nu)` independently from `measurement_scale`, and use:

```text
epsilon_j = sqrt((nu - 2) / q_j) L z_j
```

so `Cov(epsilon_j) = Sigma`. For a centered log-normal skew component, draw independent `h_ji ~ Normal(0,1)` and add

```text
s_ji = omega_i * (exp(kappa_i h_ji - kappa_i^2 / 2) - 1)
```

with declared `omega_i` and `kappa_i >= 0`; therefore `E[s_ji]=0`. `normal_plus_centered_lognormal` uses Normal base noise plus `s`; `student_t_plus_centered_lognormal` uses the variance-scaled Student-t base plus `s`. The skew draw is independent of the base draw. Overflow/non-finite output is a generation failure, never clipped.

### 1.4 Strict, alternate, opposing, tied, and duplicate mechanisms

The base strict order is `E01..EN`; distinct evenly spaced event centers are assigned in that order. A declared permutation `A` means that the event at `A[p]` receives the `p`th sorted center. When a scenario declares only an inversion count `q`, generate `A` by the exact Lehmer construction: starting with ascending remaining event IDs and `q_remaining=q`, at each position with `m` IDs remaining choose index `d=min(q_remaining,m-1)`, remove that ID, and set `q_remaining=q_remaining-d`. Reject `q` outside `0..choose(N,2)`.

For a minority alternate sequence, set the alternate count to `round_half_even(J * minority_fraction)`, clamp it to `1..J-1`, create that many alternate labels, and shuffle once with `subgroup_assignment`. For the 50/50 opposing scenario, draw `J` uniformly from the ordered even grid `80,82,...,140` at the registry's `participants` draw position; odd participant counts are outside the sample space and are never generated then rejected or redrawn. Assign exactly `J/2` participants to each subgroup, and use an alternate permutation with `q=round_half_even(opposing_relation_fraction * choose(N,2))`; `opposing_relation_fraction=1` is the full reverse. Each subgroup uses its own center-to-event assignment but the same declared amplitudes, widths, directions, and noise law. The truth object retains both orders and sets `strict_order_identifiable: false` for the combined population.

Exactly tied/near-simultaneous blocks retain their block membership and set `strict_order_identifiable: false`; no stable ID tie-break becomes scientific truth. This applies to `near_simultaneous_events`, not to `tightly_spaced_events`: tightly spaced centers remain distinct and retain strict-total-order truth even when recovery is difficult. Targeted pairs and blocks are resolved before arrays are drawn by the structured selectors in the frozen development scenario registry, and their resolved event IDs and float64 centers are stored in truth. For `correlated_duplicate_events`, `N` must be in `7..10`; the evaluator chooses `left=floor((N-1)/2)` and `right=left+1` in its own derived event-ID vector. Thus the positive eight-event case uses `E04,E05`. Submitted configuration, mechanism, truth, or copied columns never choose the pair, and a fully resealed alternate pair fails. An `exact_duplicate_post_noise` pair is made by literal `numpy.copyto` of the complete float64 source event column into the target column after all signal, covariate, group, participant, base-noise, and skew terms have been assembled. Its target direction is first set equal to the source direction, its center is equal to the source center, and the truth object records the evaluator-selected pair as one equivalence block. The target shares all subsequent outlier and missingness masks with the source, so the final observed `(value, missingness)` pairs are byte-identical. A merely correlated pair uses the same evaluator-selected pair and the declared covariance override and is named `correlated`, never `duplicate`; it retains strict-total-order truth.

The `correlated_duplicate_events` subtype is not a random parameter. Development
has the two explicit variants in the scenario registry. Held-out replicate
indexes are stratified before any root-derived field draw: even indexes are
`correlated` and odd indexes are `exact_duplicate_post_noise`. With the frozen
12-case denominator this gives exactly six cases of each subtype. Changing the
case count, assignment function, or subtype counts requires a new scenario
contract; an empty or chance-sized exact-duplicate denominator is invalid.

The strict truth order is the ascending sort of distinct `tau_i`, with stable event ID used only to serialize, never to resolve a scientific tie. When the
truth declares recoverable signal, the closed stage-truth branch is
`{state: "THRESHOLD_STAGE", participant_stages: [...]}` and each aligned entry is:

```text
K_j = sum_i 1[t_j >= tau_i]
```

and lies in `0..N`. This threshold stage is the generator's known truth, not a claim that a fitted backend uses the same likelihood semantics.

When the truth declares no recoverable order or stage signal, including pure
no-signal and refitted-null transformations, the only legal branch is
`{state: "NONE", participant_stages: []}`. Numeric participant stages are
prohibited in that branch even though latent coordinates may be retained for
reproduction. `stage_truth.state` is therefore derived from `recoverable_signal`,
not supplied as an independent assertion.
For the threshold branch, each `ordered_participants[j].threshold_stage` must
equal both `participant_stages[j]` and the threshold sum computed from that same
row's latent time. Reversing latent-time and stage vectors together cannot move
the claim to another participant because the indexed rows are the owner.

For near-simultaneous or exactly tied centers, the truth object contains a partial order/equivalence block; scoring a single arbitrary within-block order as truth is forbidden.

Reference/control-like and at-risk/progressing labels describe the synthetic sampling mechanism. They are not diagnoses. Windows may overlap. Control contamination is generated by replacing a declared fraction of label assignments or latent-window sources, with both original and observed labels retained in synthetic truth.

For binary label contamination, compute `m = round_half_even(J * contamination_fraction)`, select exactly `m` distinct participant indexes without replacement using `contamination`, sort the selected indexes for serialization, and flip each selected binary observed label. For a separately named latent-source contamination, use the same selection rule and map each selected participant's stored latent Uniform quantile into the opposite source window before signal generation. A scenario must name one mechanism; it may not ambiguously combine them.

### 1.5 Closed matched-comparator construction

A matched pair is generated as one transaction. First resolve and canonically
serialize the source configuration, including every scalar, event array,
mechanism selector, and dependency result. The source and comparator have
distinct `UInt64Hex` case seeds derived by their manifest's role-specific rule.
The pair also has one distinct `shared_draw_seed`; both sides use it only for the
exact component paths in the comparator registry. Using it on an undeclared path
or using either case seed on a declared shared path is `GENERATOR_INVALID`.

The comparator configuration is the complete resolved source configuration
copied byte-for-byte, followed by the comparator registry row's exact
`ordered_operations` (or `ordered_operations_template` after closed member
expansion). Every operation is one member of the closed
`ComparatorOperation` union and names a semantic target such as
`EVENT_PARAMETER_AMPLITUDE` or `ANALYSIS_EVENT_SPEC_DIRECTIONS`. Generic
`REPLACE`, JSON Pointer targets, `closed_overrides`,
`closed_comparator_overrides`, and prose `varies_only` fields do not exist.
No default is re-resolved and no unlisted semantic target may change.
Both truth objects record source and comparator case seeds, shared seed, pairing
key, raw pre/post configuration hashes, ordered-operation hash, equal-projection
hash, both raw generated-data hashes, both canonical `input_digest` values,
shared-component equality records, benchmark/backend/settings/environment
identity, and four exact chain bindings. A missing field, extra operation,
undeclared state change, or unequal supposedly shared component invalidates both
sides and the pair remains in the planned denominator.

For `cmp_moderate_signal_vs_pure_no_signal`, the ordered overrides set all event
amplitudes, event covariate effects, explicit group effects, and participant-effect
loadings to exact zero; set the latent windows to the one group-independent
source-span window; and set truth to `order_truth: NONE`, `stage_truth: NONE`,
`recoverable_signal: false`. Participant/event counts, IDs, directions, baselines,
centers, widths, marginal noise/correlation law, missingness, and outlier settings
are copied unchanged. The shared paths are exactly `group_assignment`,
`covariates`, `participant_effect`, `measurement_normal`, `measurement_scale`, and
`measurement_skew`. Latent time is deliberately not shared and is scientifically
unused after all signal/loadings are zero. The fixed source order remains only as
a predeclared reference for a symmetric alignment statistic; it is not stored as
the comparator's truth.

### 1.6 Typed reconstruction and matched-fit seeds

Case reconstruction uses this closed sequence:

1. resolve the evaluator-owned case identity, resolution mode, complete family
   row, complete selected development variant or held-out stratum, common
   defaults, family mechanisms, and any authenticated transformed-source owner;
2. hash that complete source projection and reconstruct all 71 field sources;
   a submitted destination value is never a source;
3. resolve fixed, sampled, derived, and not-applicable fields exactly once in
   `generator_field_registry.ordered_field_ids` order, using the case `parameters`
   component stream only for typed sampler sources;
4. compare the complete reconstructed field ledger before reading any resolved
   configuration destination, then apply the ordinary analysis defaults
   (`reference_only_residualisation=false`,
   event directions copied from the resolved generated directions, and
   `mcmc_profile_id=characterization_2000`), then after all field draws apply
   dependency operations in the fixed order
   `participants -> events -> group_counts -> mechanism -> event_arrays ->
   covariance_validity -> matched_comparator_overrides`; dependency operations
   consume no parameter-stream draws;
5. validate the resolved complete configuration and serialize it with JCS;
6. execute component draws in Section 1.1 order; and
7. retain the typed field-draw ledger and every pre/post digest in truth.

The field-draw ledger entry is
`{field_id, value_type, allowed_form, source_kind, source_reference, draw_rule,
draw_consumed, draw_index, sampled_integer, resolution_source,
resolved_destination_json_pointer, resolved_value}`. `source_kind` is exactly
one of `COMMON_DEFAULT`, `FAMILY_MECHANISM`, `DEVELOPMENT_VARIANT`,
`HELDOUT_STRATUM`, `HELDOUT_ROOT_DRAW`, `EVALUATOR_DERIVATION`,
`TRANSFORMED_SOURCE_BINDING`, or `NOT_APPLICABLE`. `resolution_source.kind` is
exactly one of `FIXED`, `INCLUSIVE_INTEGER_RANGE`, `DECIMAL_TICK_RANGE`,
`ORDERED_CHOICES`, `DERIVED`, or `NOT_APPLICABLE`. `draw_consumed=false`
requires both `draw_index=null` and `sampled_integer=null`; `draw_consumed=true`
requires the next zero-based draw position and the exact sampled integer. A
decimal-tick integer is signed, so a negative declared range can produce a
negative tick. Replacing any sampled source with a fixed value, a family value
with a common default, or an applicable value with null fails even if every
caller-visible digest is recomputed. `parameter_draw_count` equals the number
of consumed draws, and consumed indexes are exactly
`0..parameter_draw_count-1`. The schema
fixes all 71 field IDs in order, all 14 component paths in order, and all seven
dependency stages at indexes `0..6`; duplicate, missing, reordered, or invented
entries are invalid. The authoritative stage rows are the
`dependency_stage_registry` in the frozen development scenario registry. Their input
field union covers the complete 71-field registry, including mutually exclusive
aliases, and their output pointers cover every resolved scientific subobject.
No dependency may consume an unresolved prose description. Each stage has a
fixed, non-empty ordered `input_field_ids` list and a fixed, non-empty ordered
`output_json_pointers` list. The evaluator resolves every pointer against the
complete configuration and recomputes `output_digest` over those ordered
pointer/value pairs. Every stage has `rng_draw_count=0`; in particular,
`event_arrays` resolves both covariate-effect aliases and `group_effect` without
consuming a draw. Empty lists, altered pointers, an unresolved pointer, altered
values, a non-zero draw count, or a stale digest invalidate the configuration.

For `TRANSFORMED_SOURCE`, the evaluator first authenticates the source case's
resolved-parameter manifest and resolved configuration. Every ordinary generator
field, including derived event arrays and mechanism modes, is copied from that
source manifest. `source_events` and `source_participants` are bound to its
`events` and `participants`. Only the selected null variant's canonical
`source_variant`, `permutations_per_source`, and null `truth_type` are operation
fields. The transformation component alone uses the evaluator-derived
`OPERATION_SEED`; parameters and all ordinary generation components do not.

`base_quantile_cutoff` is null in an ordinary configuration with no boundary
rules. It is a finite number strictly between zero and one exactly when the
ordered `boundary_rule_ids` list is non-empty; the ordered shift list then has
the same length. An unrelated scenario is never silently assigned the group
boundary experiment's `0.50` cutoff.

All development matched comparisons use the exact comparator reconstruction,
ordered semantic operations, equality projection, evidence fields, and shared chain
seed derivation in the frozen development scenario registry's `matched_comparators`.
The chain seed is independent of both generator case seeds and is placed
identically into every matched member's chain plan for the same pairing key and
chain index. A missing chain root/domain/message field, a non-identical shared
chain seed, an unregistered semantic-target mutation, or failed equality projection makes
the entire comparison incomplete and retained in its planned denominator.

Comparator evidence is accepted only by the comparator owner's callable
schema-plus-semantic validator. That validator resolves `member_id` or
`member_index` against the sealed ordered member list, replays every operation,
and reconstructs each non-byte relation from the complete generated objects and
its typed witness. Six adversarial non-byte relations are exercised; changing a
value, row index, scale, latent time, boundary coordinate, or group vector while
leaving a contradictory witness must be rejected. A typed assertion such as
`generated_input_relation_verified: true` is never independent proof.

### 1.7 Executable cross-artifact invariants

The ordered registry at
`evaluator/fixtures/scientific-invariant-registry.json` is normative. Its 18
closed algorithms validate data/truth dimensions, zero-based contiguous
participant indexes, matrix and probability shapes, missingness/value alignment,
truth/mechanism consistency, pure-no-signal-only false-positive eligibility,
the 71/14/7 generator registries and draw count, exact-oracle normalization and
ties, semantic comparator transactions, null-calibration identity,
`CandidateStrongEvidenceDecision`, and the false-positive aggregate.
The executable checks cover all declared truth structures, complete covariate
row/column dimensions and truth/data covariate equality, literal event-direction
equality across resolved
configuration/mechanism/truth/data, finite symmetric positive-semidefinite noise
covariance, exact missingness mask/null-cell alignment, normalized probability
vectors, and truth-signal state consistent with the declared mechanism.

Schema validation runs first. The invariant algorithms then run in registry
order before sealing. Any failure retains the planned universe and emits a hard
failure. The 46 closed mutations in
`evaluator/fixtures/scientific-invariant-counterexamples.json` are a mandatory
negative gate; accepting any one blocks freeze.

## 2. Post-generation perturbations

Generation and perturbation occur in the following fixed 14-stage order:

1. `resolved_parameters`;
2. `group_assignment`;
3. `latent_coordinate`;
4. `latent_source_contamination`;
5. `transition_signal`;
6. `covariate_effect`;
7. `group_effect`;
8. `participant_effect`;
9. `base_measurement_noise`;
10. `centered_skew`;
11. `exact_duplicate_copy`;
12. `observed_label_contamination`;
13. `outliers`; and
14. `missingness`.

The group effect is therefore applied before the participant and noise terms,
matching the model equation. Exact duplicate copying happens after every signal,
effect, noise, and skew term but before labels, outliers, and missingness. A
scenario names at most one contamination mechanism. Latent-source contamination
necessarily precedes signal generation; binary label flipping changes only the
observed label and follows value generation.

The truth object retains one chained `GenerationStageHashRecord` for every
stage. The closed registry names the stage-specific digest domain and ordered
source projections. For each projection, the source owner kind, JSON Pointer,
and exact value are domain-hashed; the stage record then hashes those source
digests, its exact index/domain, and the preceding stage hash with only its own
hash set to null. The first preceding hash is null; every later one equals the
previous row. This truth-owned ledger proves internal integrity only. It does
not prove that the generator ran correctly: supplied truth can be changed and
resealed. Scientific acceptance therefore requires a separate evaluator to
execute the generator afresh from evaluator-reconstructed parameters, roots,
configuration, and numerical kernel, and compare its independently produced
stage outputs. That executor now independently reconstructs the evaluator-owned
resolution, component streams, and all 14 numerical stages without importing
the production generator or resolver. Its typed result remains
`UNSCHEMATIZED_INTERNAL_ONLY`, so it is ineligible for canonical conformance
evidence until a closed evaluator-owned replay receipt is implemented and
accepted. The clean, perturbed, and mask hashes are separate summary digests;
they do not replace independent stage execution.

### Outliers

- A cell outlier adds a declared signed offset measured in that event's clean-noise standard deviations.
- A participant sabotage applies a declared vector of event offsets or reverses a declared subset of measurements.
- When only counts are specified, select participant indexes without replacement and then event indexes without replacement using the `outliers` stream; serialize both in increasing order. Offset signs alternate `+,-,+,-,...` in that serialized cell order unless an explicit sign vector is supplied.
- Injected participant indexes and cells are recorded as synthetic truth.
- The evaluator never passes truth labels to the backend or auditor fit.

### Missingness

- `MCAR`: draw one independent `Uniform(0,1)` per cell in participant-major C order and mask when the draw is strictly below the declared event probability. It is independent of values, latent time, group, and covariates.
- `MAR`: `P(M_ji=1) = logistic(alpha_i + gamma_i^T z_j + eta_i group_j)`, using only the declared fully observed synthetic covariates/group. If a target marginal probability is supplied instead of `alpha_i`, solve the unique intercept by 200 fixed bisection steps on `[-40,40]` and fail if the target is not bracketed; then mask with independent participant-major Uniform draws. The measurement being masked and latent stage are not predictors.
- No MNAR claim is made in v0.1.

Missingness is represented explicitly. A complete-data backend must fail or use a separately declared complete-case/external-variant universe; the generator never silently imputes.

## 3. Required truth object

Every dataset has a machine-readable truth object containing at least:

- generator/schema version and `SYNTHETIC` marker;
- scenario family, variant ID, numeric variant index, normatively derived case
  ID, replicate ID, and all derived seeds;
- participant and event counts;
- strict order, or partial/non-identifiable order blocks with the reason;
- resolved target pair/block event IDs, centers, covariance/direction overrides,
  boundary rule IDs/cutoffs, skew mapping, or wrong-direction IDs whenever the
  family mechanism uses them;
- event centers, widths, baseline, amplitude, direction, unitless scale, and noise parameters;
- participant latent time and threshold stage;
- source group mechanism, latent subgroup, observed group, contamination, and label-noise manifests;
- covariates, covariate effects, participant-effect parameters, and noise covariance;
- injected outlier indexes/cells and parameters;
- missingness mask, family, probabilities/model, and seed;
- clean and perturbed array digests and the complete ordered 14-stage chained
  generation-hash ledger;
- generator-code and scenario-definition digests;
- the complete typed field-draw ledger and resolved-configuration digest;
- any pre-root stratum ID and its planned stratum denominator; and
- for `incomplete_time_coverage`, the ordered `affected_tail_event_ids`, each
  event's missing tail side, and the predicate inputs defined below.

For `incomplete_time_coverage`, define normal-tail coverage for event `i` as
`minimum declared latent-window endpoint <= tau_i - 2*w_i` and abnormal-tail
coverage as `maximum declared latent-window endpoint >= tau_i + 2*w_i`. An event
is affected exactly when the common-default broad-window comparator has both
coverages and the restricted source lacks at least one. The affected event IDs
are serialized in event-ID order together with `NORMAL`, `ABNORMAL`, or
`BOTH`. `COVERAGE_LIMITATION_REPORTED/v1` uses only that retained truth field
and the canonical report fields; no evaluator chooses tail events by inspection.

Participant-level truth may exist only in synthetic benchmark artifacts. The corpus working record contains aggregate results and hashes, never rows that could be mistaken for real participant data.

“Containing at least” above describes scientific content, not an open object. The
exact allowed fields, nullability, array shapes, and digest encodings are closed by
`schemas/synthetic-truth.schema.json`; unknown or missing required fields are
`GENERATOR_INVALID`. The complete resolved configuration and every field-draw,
dependency, mechanism, and component-seed record validate against
`schemas/synthetic-resolved-configuration.schema.json` before their JCS preimages
are hashed. Prose-only mechanism state is prohibited.

## 4. Scenario families

Both development and held-out manifests must instantiate every family below. Parameter ranges and development grids are in the frozen development scenario registry; held-out counts and commitment state are in the protected held-out authority.

| ID | Family | Required mechanism and expected test |
|---|---|---|
| `easy_known_truth` | Distinct centers, narrow transitions, low noise, broad latent-time coverage. Recovery and stage gates should pass. |
| `moderate_mina_shape` | Historical machine ID for a generic moderate 57-participant, nine-event mixed-direction shape with moderate overlap/noise. It is not a named-cohort reconstruction. Must outperform matched no-signal behavior without forced precision. |
| `small_sample` | Same mechanism at materially smaller `J`. Uncertainty should widen in aggregate. |
| `noise_ladder` | At least five matched levels from low to high noise. Recovery should degrade and entropy/variability rise in aggregate. |
| `weak_pre_post_separation` | Low amplitude relative to noise. Mixture estimation and null-relative language are stressed. |
| `incomplete_time_coverage` | Remove early-normal and/or late-abnormal tails. Tail-dependent events should become uncertain. |
| `tightly_spaced_events` | Adjacent distinct centers separated by at most one transition width. The target-pair precedence distribution must show ambiguity in aggregate, and no arbitrary within-pair truth claim is allowed. |
| `slow_overlapping_transitions` | Wide sigmoid transitions with substantial overlap. |
| `outlier_sabotage` | Inject one known influential participant and optional known cells without revealing them to fits. Influence components/rank are scored. |
| `mcar_missingness` | Event-specific MCAR masks. Count accounting and explicit missingness behavior are scored. |
| `mar_missingness` | Transparent covariate/group-dependent MAR masks. No leakage or hidden imputation is allowed. |
| `correlated_duplicate_events` | Exactly six `correlated` case IDs and six disjoint `exact_duplicate_post_noise` case IDs exhaust the family. Correlated cases retain strict truth but the targeted pair must show ambiguity without an arbitrary within-pair truth claim; exact duplicates require equivalence-block scoring, target-pair ambiguity, and no tie-break claim. |
| `minority_alternate_sequence` | A minority follows a declared alternate order. Single-sequence limitations must be visible. |
| `opposing_sequences_50_50` | Equal subgroups follow opposing orders. Truth is explicitly non-identifiable as one total order. |
| `near_simultaneous_events` | One or more equivalence blocks have equal/near-equal centers. Scoring uses block-aware truth. |
| `covariate_confounding` | A covariate shifts events and differs by analysis group. Reference-only residualisation should change results predictably without leakage. |
| `group_boundary_sensitivity` | Nearby predeclared group rules change composition. The report must attribute movement to the rule, not optimize a threshold. |
| `control_contamination` | Declared label/source contamination. Group and model sensitivity should become visible. |
| `heavy_tailed_skewed` | Student-t and centered skew components violate simple Gaussian shape. Warnings/failures and uncertainty remain visible. |
| `wrong_event_direction` | One declared direction is deliberately reversed relative to synthetic truth. The evaluator must detect material degradation or reported direction sensitivity; the product must not pretend it can validate real scientific direction without truth. |
| `pure_no_signal` | Set amplitudes and covariate group effects to zero; draw identical group distributions with no true order/stage signal. Strong null-relative language is a false positive. |
| `label_permutation_null` | Permute observed group labels globally while preserving counts, then refit the complete pipeline. |
| `within_group_feature_permutation_null` | Independently permute participant rows for each event inside each analysis group, preserving group-conditional marginals and missing counts while destroying cross-event alignment; then refit. |

Optional global feature permutation is a separate named family; it must never be reported as the within-group null.

## 5. Required null algorithms

All nulls receive independent deterministic `UInt64Hex` seeds derived from the
audit root seed, null-procedure version, null-family ID, source universe ID, and
replicate index. The domain-separated HMAC output is truncated to eight bytes and
serialized as 16 lowercase hexadecimal characters before it enters any manifest,
truth object, universe, or worker request. The corresponding component RNG is then
derived by Section 1.1. A null result never reuses a fitted observed model.

### 5.1 Group-label permutation

Permute the complete observed group-label vector without replacement, preserving exact label counts. Event values, participant rows, missingness pattern, and covariates stay fixed. Refit reference-group preprocessing, event distributions, order inference, and staging. A generated permutation may equal the original by chance; do not redraw, but record `identity_permutation: true`.

### 5.2 Independent within-group feature permutation

For each analysis group `g` and event `i`, draw an independent permutation of the row indexes belonging to `g`, then permute the `(value, missingness indicator)` pair together. This preserves event-specific group-conditional marginals and missing counts while destroying cross-event participant alignment. Covariates and participant IDs are not permuted into event values. Refit the complete pipeline.

### 5.3 Pure no-signal generation

Generate a fresh dataset with all event amplitudes `a_i = 0`, every `beta_i = 0`, every event-specific group effect equal to zero, `lambda_i = 0`, and identical latent/noise distributions across observed groups. Retain the declared marginal noise/correlation family, including participant-independent cross-event correlation. The truth object uses `order_truth: NONE`, `stage_truth: NONE`, and `recoverable_signal: false`. Only these generated cases are guaranteed no-signal opportunities for the held-out strong-label false-positive denominator.

Before a `PURE_NO_SIGNAL` mechanism, truth object, or case may be issued, the
complete resolved configuration must pass one deterministic semantic predicate.
For the `pure_no_signal` family, `truth_type` must be exactly
`no_recoverable_order_or_stage`; the event-length `amplitude`,
`covariate_effect`, `group_effect`, and `participant_effect_loading` arrays must
contain only exact finite numerical zero (booleans, non-finite values, any
nonzero magnitude, and wrong lengths fail); and latent sampling must use
`GROUP_INDEPENDENT_WINDOW` with one valid non-null
`group_independent_window` and null reference/at-risk windows. The existing
single global measurement-noise object supplies the group-independent noise
distribution and may retain cross-event correlation. The
`no_recoverable_order_or_stage` truth type is reserved to this family and is
invalid on every other family. Production resolution and independent replay
resolution apply the identical predicate and fail with
`GENERATOR.PURE_NO_SIGNAL_SEMANTICS_INVALID` without reporting values.

### 5.4 Optional diagnostics

Random-order likelihood comparisons and a stage-independent null may be added only as separately named, reviewed diagnostics. They do not replace the three required refitted families. A null that holds fitted preprocessing or mixture parameters fixed is invalid for null-relative report language. Group-label and within-group feature permutations are calibration diagnostics, not guaranteed absence-of-signal generators, and are excluded from the false-positive denominator.

## 6. Expected aggregate behavior

Expected behavior is assessed across predeclared replicates, never required in every seed:

- increasing noise/overlap and shrinking sample size should generally reduce known-order recovery;
- positional entropy and chain/bootstrap/decision variability should generally increase as information degrades;
- incomplete time coverage should particularly affect events whose normal/abnormal tails are missing;
- equal opposing sequences and simultaneous blocks must not receive a precise single-order claim;
- injected sabotage should appear across multiple influence components often enough to meet the frozen gate;
- null-relative evidence should weaken across the three required null/control
  families, while only `pure_no_signal` is treated as truth-guaranteed no-signal
  for false-positive calibration; and
- cautious/fallback report language should become more frequent as convergence, identifiability, or null calibration worsens.

The profile pilot is a separate signal-only compute-budget experiment. It uses
exactly three `easy_known_truth/profile-pilot` datasets and three datasets under
the historical machine ID `moderate_mina_shape/profile-pilot-57x9` at three
budgets and three chains: 18 universes and 54 chain executions. It does not
generate or consume a comparator dataset and does not compute a matched-null
delta, randomization p-value, or moderate scientific pass/fail. Its easy and
moderate stage MAE use
the exact generated fixed evaluation-cohort participant rows and their
`THRESHOLD_STAGE` truth. The plan requests all three evaluation-stage output
families from the live selected subject; incompatible stage axes are
`NOT_ASSESSABLE` and cannot select a budget.

The pilot records all four transition observations but does not invent their
selection tolerances. Its transition-review state is
`PENDING_INDEPENDENT_TRANSITION_RULE_REVIEW`, so its current outcome is
`NO_SELECTION`. Only a future versioned machine-executable independent owner
that fixes metric directions, per-metric aggregation/tolerances,
endpoint/zero-transition handling, complete denominators, exact
plan/evidence/subject binding, and no preferred-central-order targeting can
produce `REVIEWED_TRANSITION_QUALITY_PASS`.

For each direct budget relation, runtime uses 18 same-case/same-chain ratios:
candidate terminal core-observed runtime divided by strictly positive reference
terminal core-observed runtime. Both sides must be complete and finite. Sort
the 18 ratios and take non-interpolating inverse-empirical-CDF `Q(0.5)`, the
ninth one-based ordered value. The runtime component passes strictly below `1`
with tolerance `0`; equality or any invalid observation fails and defaults
upward.

The later moderate development gate remains a distinct signal/null experiment.
It has exactly eight predeclared atomic signal/null pairs, 16 universes, three
chain Fits per universe, and 48 fresh Fits. Each universe has three distinct
chain seeds and one convergence gate derived jointly from all three chains;
all 16 gates must be `CONVERGENCE_PASS`. Every pair must be complete,
binding-valid, and finite. Its prospectively frozen complete-pair rule requires
the exact eight-pair one-sided sign-flip test (`tail_count <= 12`, therefore
`p_paired <= 0.05`), fourth ordered alignment delta `>= 0.15`, and fifth
ordered signal-stage MAE `<= 0.25`. Retry, dropping, replacement, and adaptive
extra pairs or chains are forbidden. None of those cases, universes, or Fits is
part of the profile-pilot counts.

The reviewed quantitative rules live in `metrics-and-uncertainty.md` and `benchmark_contract.yaml`. They are frozen after development characterization and independent review. The retained characterization did not select a backend. Thresholds cannot be changed after held-out results to rescue a candidate.

### 6.1 Closed scenario-evidence evaluation

The executable fixture for this section is a contract-closure self-test only.
It deliberately uses minimal two-participant/two-event objects and controlled
standard-array outputs to exercise owner resolution and counterexamples. It is
not a development-scenario execution, known-truth recovery result, quantitative
threshold result, or substantive benchmark evidence. The real development and
held-out runners must generate each family at the dimensions and ranges frozen
in the development scenario registry and the benchmark contract; this self-test can
never satisfy those gates by itself.

The fixture lane is closed separately by
[`scenario-fixture-evidence.schema.json`](../../schemas/scenario-fixture-evidence.schema.json)
and
[`scenario-fixture-predicate.schema.json`](../../schemas/scenario-fixture-predicate.schema.json).
It carries the literal markers
`evidence_scope: CONTRACT_CLOSURE_FIXTURE_ONLY` and
`scientific_acceptance_eligible: false`. Relabelling the fixture as scientific
acceptance evidence is a validation error. The executable check reports the
substantive scenario benchmark as `UNVERIFIED`, even when every contract and
adversarial ownership check in the self-test passes. Its internal rule receipt
uses `rule_kind: PROCEDURE` with reason code `CONTRACT.FIXTURE_ONLY`; it never
emits a `SCENARIO_FAMILY` acceptance receipt.

The substantive lane is separately closed by
[`scenario-family-payload.schema.json`](../../schemas/scenario-family-payload.schema.json),
[`scenario-predicate.schema.json`](../../schemas/scenario-predicate.schema.json),
[`scenario-evidence.schema.json`](../../schemas/scenario-evidence.schema.json),
and
[`scenario_derivation_registry.json`](https://github.com/timigod/anim/blob/main/evaluator/scenario_derivation_registry.json).
Each of the 23 scenario families has one versioned machine predicate, one closed
payload definition, and complete derivation rows for every payload leaf. The
registry contains 102 derived fields and a closed union of 22 source-owner
classes. Each owner class names its exact source schema and unconditional natural
identity fields; an invented field, alternate owner class, omitted payload leaf,
or reordered family fails before evaluation. Evaluation order is fixed: validate
the complete evidence object, authenticate its exact source-owner and evidence-
tree manifests, prove planned/valid case-ID coverage and vector cardinalities,
reconstruct every derived field, dispatch the registered predicate, then emit
its derived `PASS`, `WARN`, or `FAIL`. Evidence is never dispatched first and
later treated as schema-valid. Missing, duplicate, cross-family, wrong-subtype,
wrong-truth-mode, non-finite, or `NOT_ASSESSABLE` evidence fails closed.

Scenario evidence is an evidence-derived projection, not an input summary. The
evaluator resolves the complete sealed-case manifest, its ordered cases, the
ordered persisted truth and generated-data objects, the exact resolved
generator configuration and mechanism, every component-seed manifest, the
complete sealed-results index, the canonical scientific payload for each
successful result, the ordered rule outcomes, and the case records described
below. It recomputes every owner digest, natural identity, subject binding,
index, order, and cardinality. It then runs the normal truth/data and
configuration/mechanism/RNG replay checks before projecting any family field.

The contract fixture exercises literal ownership for four normal worker arrays:
`pairwise_precedence`, `position_probabilities`, `training_row_indexes`, and
`training_stage_posterior`. Their shapes are not fixed to the fixture size. The
evaluator validates `[N,N]`, `[N,N]`, `[P]`, and `[P,N+1]` respectively against
the case dimensions. The fixture deterministically maps synthetic `E##` truth
IDs to their lowercase canonical `MachineId` forms and requires the generated
data, request, fit payload, participant/event manifest, artifact references, and
canonical payload to preserve that exact ordered binding. The projection stores
the ordered binding in
`ebm-audit-scenario-contract-event-id-mapping/1.0`; reorderings and canonical-ID
collisions fail closed. A substantive runner must use its declared input-column
mapping rather than infer a normalization.
The stage contract check must read
`training_stage_posterior`; pairwise precedence cannot stand in for stage
evidence.

That array chain proves only that literal fixture bytes, catalog entries,
response files, backend identity, and sealed digests agree. It does **not** make
the four arrays the complete scientific owners of all 23 family predicates.
In particular, a family result must never be inferred from a family name, a
constant boolean, a requested `PASS`/`WARN`/`FAIL` state, a fixed matrix cell, or
truth/data/policy context that its derivation did not declare.

The substantive contract replaces the fixture's single-array primitive with a
closed typed multi-owner graph, and the production runner must instantiate that
graph from real execution artifacts. Depending on the family, the graph includes:

- variable-shape fit arrays for order, position, and stage facts;
- complete `ComparisonRecord` sets for matched small/large, weak/moderate,
  slow/narrow, covariate, contamination, direction, ladder, chain, and null
  comparisons;
- complete `InfluenceRecord` sets for injected-participant scenarios;
- `ParticipantEventManifest`, preprocessing, operation, transformation, and
  data-accounting records for missingness, row inclusion, refits, boundaries,
  and permutation nulls;
- typed terminal results, warnings, side-effect records, and canonical report
  predicate outcomes for disclosure and prohibited-claim facts; and
- the complete `CandidateStrongEvidenceDecision` plus its observed fit, 177
  ordered null fits, and false-positive bundle for no-signal/strong-label facts.

Every derivation declares all ordered owners it reads and stores their digests
with a versioned derivation ID. Target pairs, equivalence blocks, affected tail
events, wrong-direction events, and opposing relations are resolved by exact
event ID rather than fixed offsets. Paired, ladder, and transformation families
must prove complete comparator-member coverage. Raw case metrics are emitted
first; family-level thresholds are applied only after the complete ordered case
set is reconstructed. A missing required owner yields `NOT_ASSESSABLE` or
`FAIL`, never a default pass.

The schemas, derivation registry, and adversarial contract checks now define and
verify that typed owner graph. The real scenario runner has not yet emitted a
complete development or held-out graph at the frozen dimensions. Until it does,
the substantive scenario-validation state remains `UNVERIFIED`. Contract fixture
`PASS` output is not a scientific benchmark pass.

Every independently hashable fixture record repeats
`evidence_scope: CONTRACT_CLOSURE_FIXTURE_ONLY` and
`scientific_acceptance_eligible: false` and uses a fixture-specific schema
version and digest domain. The executable self-test includes a positive
three-participant/four-event case, wrong-shape negatives, mapping reorder and
collision negatives, and a stage-only owner change that leaves pairwise order
evidence unchanged while changing the stage result. This proves the fixture
contract's dynamic shapes and source separation; it still does not execute the
substantive family definitions.

The benchmark's human-readable family rule embeds the exact same predicate
object as the machine registry entry. The verifier checks this equality for all
23 families, including separate truth-scoring modes for strict, mixture,
partial-order, refitted-null, and no-recoverable-signal evidence. Label- and
feature-permutation families must both report their calibration diagnostic and
prove exclusion from the pure-no-signal false-positive denominator.

## 7. Development and held-out separation

Development scenarios are public to implementers: fixed development seeds, grids, failures, and results may guide defect repair and pre-freeze threshold calibration. They may not be chosen to reproduce the published Idris order. For a family with `development_replicates: R`, every listed development variant is run for replicate indexes `0..R-1`; replicate `r` uses development root seed list element `r`. Matched variants share the same replicate index and the component streams named by their comparator contract; only the explicitly varied component receives a different stream or scale. A failed replicate remains one planned replicate.

Development and held-out executions require different evidence types and cannot
be relabeled. The current `DevelopmentScenarioEvaluationReceipt/3` is schema-
impossible, not a positive audit surface: the base
`ScenarioFamilyEvaluationReceipt` requires `RuleOutcome`, but the registered
`RuleOutcome.evidence_sha256` preimage is rooted in the held-out
`ScoreEvidenceBundle`. A future reviewed type migration must create a distinct
qualification-only development assessment and digest. Held-out evidence must
first be sealed into `ScoreEvidenceBundle`; only afterward may
`validate-substantive-score` independently emit `RuleOutcome` rooted in
`score_evidence_root`, avoiding a hash cycle. Until then,
`PreCandidateQualificationReceipt/2` is an explicitly blocked diagnostic with
an unresolved development reference and is candidate-freeze-ineligible. A
generic executed-check transcript,
profile-characterization owner, benchmark-freeze owner, fixture receipt, or
fully rehashed caller graph cannot qualify. Candidate, benchmark-subject, and
contract digests must still bind exactly. If the final identity differs,
development calibration and qualification rerun before held-out strong-label
eligibility. A
`HeldoutScenarioEvaluationReceipt` binds the separately sealed
held-out results and exact ordered 23-family set and is the only scenario-family
owner eligible for held-out scoring. Development evidence, fixture evidence,
counts without typed records, and a `PROCEDURE` outcome all fail the held-out
score path.

Held-out parameters are drawn by their individual entries in the closed
`generator_field_registry`; there is no generic shape-based interpretation.
Integer ranges are inclusive discrete uniforms; booleans and enums are uniform
over their declared ordered choices unless a pre-root stratum or explicit
weights apply; decimal ranges are sampled from an inclusive `10^-6` integer tick
grid and emitted as decimal JSON numbers with at most six fractional digits;
fixed scalar values and fixed endpoint vectors are not redrawn. All applicable
non-fixed fields are drawn first in registry order. Dependencies are then applied
in the frozen order `participants -> events -> group_counts -> mechanism ->
event_arrays -> covariance_validity -> matched_comparator_overrides` without
consuming the parameter RNG stream. Structured
family-mechanism rules in the frozen development scenario registry determine
targeted pair/block IDs and centers, covariance overrides and directions,
group-boundary IDs/cutoffs, centered-lognormal parameter mapping, and wrong-
direction event IDs. A dependency failure makes the case invalid and retained;
there is no redraw. These rules, the typed ledger, and the exact component seeds
make generation fully specified rather than an informal range description. The
implemented production generator and independent replay executor consume this
exact contract, but neither is canonical conformance evidence until the remaining
typed receipt and conformance gates pass.

Held-out scenario families and parameter ranges are declared before freeze, but concrete seeds are not. The anti-gaming sequence is:

1. Complete independent specification review and resolve all P0/P1 findings.
2. Resolve authoritative 2k/5k/10k profile results, review thresholds, and
   rederive every one of the exact 28 benchmark predicates from current bytes
   or versioned state before freezing the subject-neutral benchmark.
3. After the reviewed development-assessment type migration, resolve and
   recompute the complete final-candidate 23-family development graph under one
   exact integration subject: the project-owned `SYNTHETIC-ONLY` conformance EBM
   through the ordinary generic worker.
4. Freeze the unchanged implementation candidate only after rederiving that
   PASS qualification from the same authoritative graph and exact subject.
5. Bind that exact subject to the frozen candidate, ordinary generic worker,
   complete configuration, generator, and pre-root source identities, without
   consulting or mutating an external qualification registry. Then draw a 256-bit
   root from the operating system CSPRNG; never derive it from time, PID,
   developer seeds, or results. Generated known-truth identities are sealed at
   their existing post-root commitment stage before any result is inspected.
6. Commit to the root and freeze hashes using the domain-separated protected held-out procedure before generating cases.
7. Derive case seeds deterministically by HMAC-SHA-256 over canonical family/replicate labels; write and hash the sealed manifest before a result is inspected.
8. Run exactly once. Preserve all failures and the complete terminal receipt.
9. Do not tune thresholds, scenario parameters, report rules, or scientific behavior from held-out outcomes.
10. If a genuine implementation defect changes the candidate, record the failed attempt, increment candidate ID, discard no evidence, draw a fresh root, and run a fresh held-out set. A scientific failure is not an implementation defect.

Any held-out seed used for debugging becomes development evidence and cannot be reused as held-out. The implementation under evaluation receives only generated inputs and normal truth-free configuration; truth objects are read by the evaluator after outputs are sealed.

Named-backend acceptance is an optional downstream per-integration
qualification profile. It cannot replace this conformance subject, reuse its
identity across a mismatch, gate library readiness, or alter the commitment,
one-shot, no-tuning, fresh-seed, failure-retention, or privacy rules above.

## 8. Scenario-level hard failures

The benchmark fails regardless of aggregate scores if any scenario demonstrates:

- truth information passed into a backend/auditor fit;
- hidden participant, event, or cell removal/transformation;
- imputation not declared in the universe;
- a null that does not refit all data-dependent preprocessing/model parameters;
- scoring an arbitrary total order as truth for a non-identifiable/partial-order scenario;
- a convergence failure counted as valid evidence;
- failed/null scenarios omitted from denominators;
- strong null-relative language on a case that does not pass the frozen eligibility rule;
- raw direct identifiers or raw values in default report/log artifacts;
- network access in offline execution; or
- scenario/generator/seed provenance too incomplete to reproduce the exact synthetic case.

## 9. Scientific limits

Passing synthetic tests shows that the implementation behaves as predeclared on
these generators and null transformations. It does not validate a disease
mechanism, establish the true Idris event sequence, show that a researcher's EBM
is equivalent to any paper or package implementation, or demonstrate
diagnosis/prognosis/treatment utility. Synthetic misspecification remains a
benchmark risk and must appear in the final limitations.
