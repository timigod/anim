# Metrics and uncertainty contract

Status: `FROZEN`
Rule version: `metrics/v0.1.0`

All metrics are pure functions of canonical validated inputs. Machine positions and stages are zero-based; displays may add one to event positions but must say so. Logs use natural logarithms. Numerical comparisons use float64 and explicitly recorded tolerances. A metric that cannot satisfy its mathematical or data preconditions returns a typed `NOT_ASSESSABLE` result, never zero. A metric that is unavailable solely because the exact worker under evaluation truthfully declares that capability absent returns `{status: "NOT_APPLICABLE_BY_CAPABILITY", value: null, reason_code}`. `NOT_APPLICABLE` is not part of this contract. Capability absence is neither a pass nor a numerical zero and cannot replace a mandatory metric. Every numeric input to a metric must be finite. A non-finite input produces `{status: "NOT_ASSESSABLE", value: null, reason_code}` and cannot enter an aggregate unless another contract classifies the non-finite source as a harder invalid-result failure.

Unless a rule explicitly says otherwise, every reported median, percentile, and
quantile uses the same non-interpolating inverse empirical CDF. For sorted finite
values `x[0] <= ... <= x[n-1]`, `n > 0`, and `p in [0,1]`:

```text
Q(p) = x[max(0, ceil(p*n) - 1)]
```

Thus `Q(0)=x[0]`, the median is `Q(0.5)`, the interquartile range is
`Q(0.75)-Q(0.25)`, and `q10`/`q90` mean `Q(0.10)`/`Q(0.90)`. No interpolation
or implementation-library default is allowed. Empty input is `NOT_ASSESSABLE`.
For rank correlations, ties receive the average of their one-based rank
positions and Spearman correlation is the ordinary Pearson correlation of the
two resulting rank vectors. A constant rank vector, fewer than two pairs, or a
non-finite value is `NOT_ASSESSABLE`; it cannot be treated as zero correlation.

## 1. Uncertainty layers must remain separate

| Layer | Replication unit | Meaning | Prohibited pooling |
|---|---|---|---|
| `within_fit` | Post-burn/thinned states or stage posterior from one fit | Uncertainty represented by one fitted model/chain | Must not be labelled sampling or decision uncertainty. |
| `chain` | Independent seeds/chains for the identical analysis specification | Stochastic exploration and initialization variability | Must not be merged with within-fit samples as if one chain. |
| `sampling` | Independently refitted bootstrap/subsample datasets | Dependence on sampled participants | Must not reuse mixture/preprocessing parameters from baseline. |
| `analyst_decision` | Predeclared analysis specifications differing by declared choices | Sensitivity associated with analyst decisions | Must not be called causal effects. |
| `participant_influence` | Independently refitted participant/group removals | Dependence on particular observations | Must not be called data quality or outlier status. |
| `null` | Independently refitted no-signal transformations/generators | Behavior when relevant structure is destroyed or absent | Must not be pooled into an uncertainty band around observed results. |

Every array, table, figure, aggregate, and report label carries exactly one `uncertainty_layer`, or is explicitly a comparison between named layers. No combined “overall uncertainty” score or heatmap is defined.

### 1.1 Science-v2 source ownership and structural registry

Science-v2 names exactly six uppercase, non-poolable uncertainty layers:
`WITHIN_FIT`, `CHAIN`, `SAMPLING`, `ANALYST_DECISION`,
`PARTICIPANT_INFLUENCE`, and `NULL`. Its report-evidence domains are those six
names plus `PARTICIPANT_STAGE`. A report-evidence domain is not another
uncertainty layer. In particular, participant-stage evidence MUST retain the
uncertainty layer that produced it; `PARTICIPANT_STAGE` MUST NOT be hard-wired
or relabelled as `PARTICIPANT_INFLUENCE`. Quantitative thresholds and
aggregation rules are frozen by the benchmark contract, not by this structural
registry alone.

The in-process authority sequence is:

```text
SealedResultEvidenceSet
  -> private exact CapturedScientificRun
  -> SealedScientificEvidence
  -> fresh privacy-safe deterministic aggregate projection
```

`CapturedScientificRun` is opaque, non-copyable, nonserializable, and issued
only from the exact current `SealedResultEvidenceSet` through the trusted
sealed-run owner path. It retains and revalidates the identical plan,
preparation, terminal, finalized-result, convergence, event-semantic, and
authenticated response owners. Candidate origins and their derived comparison
edges come from the exact capability-owned Plan/3 projection. Scientific arrays
are private immutable copies rebuilt from the authenticated retained response
bundles; persisted JSON, caller mappings, caller summaries, and report-model
objects are not source authority.

`SealedScientificEvidence` is now implemented as the opaque one-argument
successor to one exact live `CapturedScientificRun`. It is non-copyable and
nonserializable. Its closure-owned issuer binds the complete canonical
projection bytes and digests before returning the object; every property read
and projection revalidates the still-live exact source graph, rederives every
candidate, sampling, analyst-decision, participant-stage, and
participant-influence record from that graph, derives the source-scoped null
terminal roster, and
exact-compares the new canonical bytes and digests with the sealed retention
before returning.
The outer projection is the single-cutover
`ebm-audit-sealed-scientific-evidence/10.0` record under
`ebm-audit/sealed-scientific-evidence/10`; there is no compatibility route to
an older sealed projection.
A projection returns a fresh decoded aggregate mapping. It does not
expose the private captured arrays, response payloads, participant identifiers,
or raw event measurements.

Only one capture may be live for one exact sealed owner. The live index uses
callback-free weak identities, retains no key-recovery surface, and permits a
deterministic new capture only after the prior capture is collected. Its
one-shot state issuer and mutable live index are closure-owned: neither a
module-visible issuer nor a registration helper exists. Issuance binds the
fresh state and canonical live-index entry before readback, under one reentrant
creation lock. Every read requires that the live index still maps the exact
sealed owner to that same capture identity, as well as revalidating the current
sealed source graph. The capture stage computes no metric, threshold,
aggregate, null authorization, completion state, or report language.

The existing report-model/1 and report-language/v0.1 surfaces are frozen
rendering contracts only. They are not science-v2 authority, cannot consume raw
arrays, and cannot turn caller-authored uncertainty summaries into completion
or scientific evidence.

### 1.2 Implemented within-fit, chain, sampling, ordinary-origin, influence, and null-roster evidence slice

The current sealed projection implements `WITHIN_FIT` and `CHAIN`, implements
the declared `SAMPLING` bootstrap and subsampling families as independently
refitted Plan/3 origins, and implements `ANALYST_DECISION` for ordinary
singleton `one-axis`, named `declared-combinations`, and `full-factorial`
origins. Every applicable ordinary origin is compared with the literal
declared baseline; combination and full-factorial vectors are reported only as
descriptive matched associations. It implements `PARTICIPANT_INFLUENCE` for exact independently refitted
single-participant removals whose preparation authority proves the complete
leave-one-out set. Declared named-group removals and role-empty removals remain
typed unsupported rather than being approximated. The selected worker can
stage the exact declared evaluation cohort from its native posterior output.
Participant-stage movement is compared only when both fits authenticate the
same evaluation participants, row alignment, unit bindings, event set,
directions, stage semantics, and likelihood semantics. The stage-model
reference order remains distinct from the headline central order. No hard-stage,
training-cohort, or event-order fallback is permitted. Per-participant stage
evidence remains in permission-restricted private artifacts; the public science
projection contains only authenticated provenance, counts, distribution
summaries, and aggregate metrics. Missing or incompatible stage evidence stays
typed not assessable. Every bootstrap or subsample refit is staged on the exact
fixed original evaluation cohort; duplicated in-bag bootstrap rows,
retained-subsample-only rows, training stages, and order-derived fallbacks are
forbidden. The canonical public stage comparison is bound into that sampling
numeric record and remains attributed to `SAMPLING`; bootstrap and subsample
operation families remain separate and no across-replicate stage score is
defined. `NULL` is
`PARTIALLY_IMPLEMENTED` under `science-v2-uncertainty-layer-coverage/3`: it
retains every declared pure-no-signal, label-permutation, and within-group
feature-permutation terminal against its exact ordinary source, transformation
method, family, source variant, and replicate. Label and feature permutations
are independently refitted through the ordinary worker path. Failed,
unsupported, and convergence-not-assessable refits remain visible. The roster
keeps distinct derived source variants separate. A feature permutation is
effective only when it changes the within-group multiset of joint event rows;
moving identical values or merely reordering whole rows fails closed. The
roster does not pool families or calculate a statistic, p-value, false-positive
rate, or null-relative classification. Calibration and the held-out
false-positive gate remain pending, so `NULL_CALIBRATION_NOT_VALIDATED` forbids
strong null-relative language.
The local `SAMPLING` and `ANALYST_DECISION` layer statuses are therefore
`IMPLEMENTED`, because all of their declared component-coverage rows are
implemented. The whole science completion gate remains `BLOCKED`, and the
report remains `INCOMPLETE`, because null calibration and the remaining global
completion gates are not satisfied. Local implementation status is not a
scientific pass.

Every candidate and both implemented layers carry separate counts for planned
chains, finalized terminal chains, authenticated available chains, and
contributing chains. Their unordered-pair counts use
`unordered-distinct-chain-pairs/1` and are respectively `choose(count, 2)`.
Metric summaries additionally carry their own contributing chain and pair
counts. A plan-ineligible candidate has zero planned chains and pairs. A failed,
unsupported, or non-assessable terminal remains visible with typed status,
reason, and denominator accounting.

`WITHIN_FIT` uses only the predeclared reference chain; it never pools retained
states across chains. Its frozen aggregate metric IDs are:

- `within-fit-mean-normalized-position-entropy/1`;
- `within-fit-per-event-normalized-position-entropy/1`;
- `within-fit-pairwise-precedence-inclusive-0.40-0.60-fraction/1`; and
- `within-fit-pairwise-precedence-strict-outside-0.25-0.75-fraction/1`.

The two boundary fractions preserve their literal inclusive and strict
inequalities and the unordered distinct-event-pair denominator. They are
classifier inputs only. The qualitative concentration boundaries are
`FROZEN_REVIEWED`, but this incomplete slice does not emit an authorized
concentrated, diffuse, or mixed label.

`CHAIN` compares every unordered pair of authenticated independent chains. The
frozen summary metric IDs are `central-order-kendall/1`,
`position-matrix/1`, and `pairwise-precedence-matrix/1`. Central-order Kendall
uses each chain's deterministic retained-state modal order, not a
backend-selected headline order. Headline orders remain separately comparable
only when their complete selection-method records match. Each metric reports
the inverse-empirical-CDF median and maximum under
`inverse-empirical-cdf-median-maximum/1`.

The sealed chain record binds the core convergence record and cross-checks every
overlapping pairwise summary against the science-derived values. `SUCCESS`
requires an exact `CONVERGENCE_PASS` record; `CONVERGENCE_WARN` remains
descriptive only; failed or non-assessable convergence cannot contribute
descriptive chain metrics.

`SAMPLING` compares each bootstrap or declared subsample candidate only with its
exact declared ordinary source candidate. The replication unit is one
independently refitted dataset, not one retained declaration origin. Duplicate
origins remain visible as attempts but cannot reweight numerical evidence or
double-count a failed resampled dataset. Candidate-level and origin-level
contribution counts are therefore separate. Bootstrap and subsample descriptors
are separate aggregation keys, including design, strata, retained fraction,
rounding rule, fixed-cohort policy, and refit-preprocessing declaration.

Bootstrap and subsample evidence contain normalized Kendall and footrule distance, per-event
rank displacement, the frozen `min(3,event_count)` top-k overlap/Jaccard rule,
first- and last-event stability, position- and pairwise-matrix distance, and
strict pairwise-majority flips. Aggregation keeps central-order relation
frequencies separate from within-fit majority-relation frequencies and from
the within-family distributions of each within-fit `P(A before B)`.
Warnings remain descriptive only; failed or non-assessable refits stay visible
and contribute no zero-valued metric. No qualitative sampling-stability
classification is frozen.

`PARTICIPANT_INFLUENCE` compares every exact removal only with its declared
non-removed source candidate. The removal preparation binding is read from the
same live preparation authority and is revalidated on every sealed projection
read. Missing, duplicated, detached, or replay-tampered bindings fail closed.
Each attempt remains visible, including failed and non-assessable refits. An
assessable record carries separate central-order, per-event displacement,
pairwise-majority-flip, position-matrix, pairwise-matrix, convergence-degradation,
and fixed-cohort stage components. These components remain separate. The
current multi-component labels are
`FROZEN_REVIEWED_WITH_DEVELOPMENT_SENSITIVITY_UNVERIFIED`; no combined display score, ranking,
exclusion rule, data-quality judgement, diagnosis, prognosis, or treatment
claim is authorized.

## 2. Strict-order metrics

Let orders `S` and `T` contain the same `m` unique event IDs, with zero-based rank functions `r_S(i)` and `r_T(i)`.

### 2.1 Normalized Kendall inversion distance

```text
D_K(S,T) = discordant unordered event pairs / choose(m,2)
```

`D_K` is in `[0,1]`, symmetric, zero for identical orders, and one for complete reversal. `kendall_agreement = 1 - D_K`. For `m < 2`, the metric is `NOT_ASSESSABLE`.

This is a permutation distance, not Kendall's hypothesis-test p-value. No p-value is called robustness.

### 2.2 Normalized Spearman footrule distance

```text
F(S,T) = sum_i |r_S(i) - r_T(i)|
D_F(S,T) = F(S,T) / floor(m^2 / 2)
```

`D_F` is in `[0,1]`. For `m < 2`, it is `NOT_ASSESSABLE`.

### 2.3 Event displacement and endpoints

For event `i`:

```text
absolute_rank_shift(i) = |r_S(i) - r_T(i)|
normalized_rank_shift(i) = absolute_rank_shift(i) / (m - 1)
```

For predeclared `k`, where `1 <= k <= m`:

```text
top_k_overlap = |first_k(S) intersect first_k(T)| / k
top_k_jaccard = |intersection| / |union|
first_event_stable = 1[S[0] = T[0]]
last_event_stable = 1[S[m-1] = T[m-1]]
```

The report names `k`; it does not select `k` after seeing results.

### 2.4 Different event sets

Let `C` be the intersection of event IDs. Restrict both orders to `C` while preserving relative order, then apply the equations above with `m = |C|`. Always return `events_only_in_S`, `events_only_in_T`, and `common_event_count`. Fewer than two common events is `ORDER_COMPARISON_NOT_ASSESSABLE`.

## 3. Position distributions

For `L > 0` valid order samples and `N` events, with `R_li` the position of event `i` in sample `l`:

```text
P[i,q] = (1/L) sum_l 1[R_li = q]
expected_position(i) = sum_q q P[i,q]
```

The median and quantiles use the global inverse-empirical-CDF rule above: the smallest position `q` whose cumulative probability is at least the requested probability. Report both zero-based machine positions and one-based display positions where displayed.

Normalized entropy is:

```text
H_norm(i) = -sum_{q:P[i,q]>0} P[i,q] log(P[i,q]) / log(N)
```

For `N = 1`, entropy is defined as `0` with `DEGENERATE_ONE_EVENT` metadata. A position matrix must be finite, nonnegative, square, and row/column normalized within the frozen numerical tolerance.

Distance between two position matrices with identical aligned event sets is mean row total variation:

```text
D_position(P,Q) = (1/N) sum_i [0.5 sum_q |P[i,q] - Q[i,q]|]
```

It lies in `[0,1]`. Matrices from different event sets are not cropped and renormalized; compare order samples on the common set or return `POSITION_MATRIX_EVENT_SET_MISMATCH`.

Concentration summaries are descriptive:

```text
position_concentration = 1 - mean_i H_norm(i)
```

They are never evidence of truth without known-truth or null calibration.

## 4. Pairwise precedence

For distinct events `a,b`:

```text
B[a,b] = (1/L) sum_l 1[r_l(a) < r_l(b)]
B[a,a] = 0.5
```

The invariant is `B[a,b] + B[b,a] = 1` within tolerance. The distance between aligned pairwise matrices is:

```text
D_pairwise(B,C) = mean over unordered pairs {a,b} of |B[a,b] - C[a,b]|
```

Pairwise concentration is:

```text
pairwise_concentration(B) = mean_{a<b} 2 |B[a,b] - 0.5|
```

With frozen absolute tolerance `eps`, a majority relation is `a before b` only if `B[a,b] > 0.5 + eps`, `b before a` only if `B[a,b] < 0.5 - eps`, and `tied` otherwise. A majority flip requires opposing strict majorities under those same inequalities. Reports additionally show the two probabilities; crossing 0.5 within tolerance is not described as decisive.

Across chains, bootstraps, and universes, the auditor reports separate frequencies of the central-order relation and separate distributions of `B[a,b]`. It never substitutes one for the other.

## 5. Participant-stage metrics

Let `p_j(k)` and `q_j(k)` be normalized stage posteriors over the same stages `k=0..N` for a participant in a fixed common evaluation cohort.

```text
expected_stage(p_j) = sum_{k=0}^N k p_j(k)
signed_expected_stage_change = expected_stage(q_j) - expected_stage(p_j)
normalized_absolute_expected_stage_change = |change| / N
```

Let `p_max` be the finite maximum posterior probability. All stages with
`|p_j(k)-p_max| <= eps` are tied maximizers, where `eps` is the frozen absolute
numeric tolerance. MAP stage is the smallest tied stage. A tie flag and the
complete increasing list of tied stages are retained. MAP agreement is the mean
of the equality indicator over participants; it is never the only stage result.

The normalized one-dimensional Wasserstein distance is:

```text
F_p(k) = sum_{h=0}^k p_j(h)
W1_norm(p_j,q_j) = [sum_{k=0}^{N-1} |F_p(k)-F_q(k)|] / N
```

It lies in `[0,1]` and preserves stage ordinality.

The optional Jensen-Shannon distance is:

```text
m = (p_j + q_j) / 2
JSD = 0.5 KL(p_j || m) + 0.5 KL(q_j || m)
JS_distance = sqrt(JSD / log(2))
```

Terms with zero numerator contribute zero. `JS_distance` lies in `[0,1]` and is a non-ordinal complement, not a replacement for Wasserstein distance.

Aggregate outputs include median, interquartile range, maximum, and predeclared quantiles of participant-level distances. The cohort stage distribution is the mean participant posterior; movement between two cohort distributions uses the same normalized Wasserstein equation.

For a synthetic case with generator truth stage `K_j`, the known-truth score is:

```text
normalized_stage_MAE = (1/J) sum_j |expected_stage(p_j) - K_j| / N
```

It is valid only when the generator and fitted model use the same event set and compatible `0..N` stage semantics. It validates behavior on that generator, not real-data stage truth.

Native stage comparisons require identical event IDs, directions, stage count, likelihood semantics, and evaluation cohort identity. Otherwise they are prohibited. `expected_stage/N` may be displayed only as `SEMANTICALLY_NON_EQUIVALENT` descriptive progress, with no MAP agreement or pooling. A common cohort selected separately by each ordinary fit may be retained only as a descriptive `SELECTION_COUPLED` comparison; it is not a stage-stability result.

Bootstrap participant-stage stability has a stricter invariant. Every
bootstrap-fitted model MUST stage one predeclared fixed baseline/evaluation cohort
that is identified before resampling. If the worker cannot stage that fixed
cohort, the bootstrap stage metric is exactly
`NOT_APPLICABLE_BY_CAPABILITY` with reason
`STAGING.FIXED_COHORT_UNAVAILABLE` and `value=null`. The candidate remains
`VALID`, all fits run, and order, position, pairwise, influence, and convergence
components continue. Comparing duplicated in-bag rows, intersecting
the rows selected by different bootstrap fits, or labelling such a comparison
`SELECTION_COUPLED` is prohibited.

This is a component state, not a whole-candidate terminal. A worker that can fit
but cannot stage the fixed cohort still produces its valid fit, order, position,
pairwise, influence, and convergence outputs. `UNSUPPORTED_CAPABILITY` is used
for the candidate only when the requested fit cannot run at all.

## 6. Influence components

For every declared removal, refit the model and compare it with baseline. Preserve these separate components:

1. normalized Kendall distance of central orders;
2. maximum per-event normalized rank displacement;
3. fraction and named list of strict pairwise-majority flips;
4. position-matrix distance;
5. pairwise-matrix distance;
6. convergence-status change and diagnostic differences;
7. median and maximum stage-posterior Wasserstein movement on the fixed non-removed evaluation cohort, when supported.

An observation is `influential` only relative to a named metric and tested removal. It is never labelled `bad`, `wrong`, or an `outlier` from influence alone.

For display ordering only, the frozen descriptive rank is allowed:

```text
component_percentile(c,j) = average-rank percentile of participant j for component c
influence_display_score(j) = mean_c component_percentile(c,j)
```

For a component with `M` finite assessable participants, sort movement ascending,
assign tied values the average of their one-based rank positions, and define
`component_percentile = (average_rank - 0.5) / M`. Higher means more movement.
For a “top quartile” rule, the threshold is the global `Q(0.75)` of the finite
component values and every value greater than or equal to that threshold is in
the top quartile; all ties at the threshold are retained. Components are equally
weighted, at least three supported components are required, and every component
remains visible. Scores with different supported-component sets are not
comparable. Status: `FROZEN_REVIEWED_WITH_DEVELOPMENT_SENSITIVITY_UNVERIFIED`; it is not a
scientific confidence score.

### 6.1 Frozen component-level influence states

Each supported component is classified independently, before any display rank is calculated. The frozen `HIGH` boundaries are:

| Component | `HIGH` when |
|---|---|
| central-order Kendall distance | `>= 0.25` |
| maximum normalized event-rank displacement | `>= 0.30` |
| strict pairwise-majority flip fraction | `>= 0.15` |
| position-matrix distance | `>= 0.20` |
| pairwise-matrix distance | `>= 0.15` |
| fixed-cohort stage movement | median normalized Wasserstein `>= 0.10` or maximum `>= 0.25` |
| convergence degradation | baseline `CONVERGENCE_PASS` becomes `CONVERGENCE_WARN`, `CONVERGENCE_FAIL`, or `CONVERGENCE_NOT_ASSESSABLE` |

For each component the state is exactly one of `INFLUENCE_COMPONENT_HIGH`, `INFLUENCE_COMPONENT_NOT_HIGH`, or `INFLUENCE_COMPONENT_NOT_ASSESSABLE`. The participant-level state is evaluated after component coverage: fewer than three assessable components gives `PARTICIPANT_INFLUENCE_NOT_ASSESSABLE`; otherwise two or more high components gives `PARTICIPANT_INFLUENCE_MULTICOMPONENT`, exactly one gives `PARTICIPANT_INFLUENCE_SINGLE_COMPONENT`, and zero gives `PARTICIPANT_INFLUENCE_NO_HIGH_COMPONENT`. These boundaries and labels are `FROZEN_REVIEWED_WITH_DEVELOPMENT_SENSITIVITY_UNVERIFIED`; they are not exclusion rules or data-quality judgements.

### 6.2 Required serializable influence evidence

The protocol representation of one declared removal MUST contain the complete
classifier input below. A renderer or evaluator MUST be able to recompute every
component state, the participant state, and the optional display rank without
consulting logs or backend-private artifacts.

```text
InfluenceMetricResult<T>
  metric_id: closed versioned metric ID
  status: ASSESSABLE | NOT_ASSESSABLE
  value: T | null
  reason_code: closed reason code | null

FixedCohortStageMetricResult
  metric_id: fixed-cohort-stage-wasserstein-median/1
             | fixed-cohort-stage-wasserstein-maximum/1
  status: ASSESSABLE | NOT_ASSESSABLE | NOT_APPLICABLE_BY_CAPABILITY
  value: finite probability | null
  reason_code: closed reason code | null

PairwiseMajorityFlip
  event_a_id: canonical event ID, where event_a_id < event_b_id by UTF-8 byte order
  event_b_id: canonical event ID
  baseline_probability_a_before_b: finite float64 in [0,1]
  removal_probability_a_before_b: finite float64 in [0,1]
  baseline_relation: A_BEFORE_B | B_BEFORE_A
  removal_relation: A_BEFORE_B | B_BEFORE_A

InfluenceRecord
  influence_rule_version: metrics/influence/v0.1.0
  uncertainty_layer: participant_influence
  removal_spec_id: prefixed digest
  removed_aliases: non-empty ordered tuple of privacy-safe aliases
  baseline_universe_id: prefixed digest
  removal_universe_id: prefixed digest
  baseline_event_ids: ordered tuple of canonical event IDs
  removal_event_ids: ordered tuple of canonical event IDs
  pairwise_assessment: ASSESSABLE | NOT_ASSESSABLE_FEWER_THAN_TWO_COMMON_EVENTS
  pairwise_assessment_reason_code: null | INFLUENCE.INSUFFICIENT_COMMON_EVENTS
  common_event_count: uint64
  fixed_evaluation_cohort_digest: prefixed digest | null
  fixed_evaluation_cohort_count: uint64 | null
  central_order_kendall_distance: InfluenceMetricResult<float64>
  maximum_normalized_event_rank_displacement: InfluenceMetricResult<float64>
  strict_pairwise_majority_flip_count: InfluenceMetricResult<uint64>
  strict_pairwise_majority_flip_denominator: uint64 | null
  strict_pairwise_majority_flip_fraction: InfluenceMetricResult<float64>
  strict_pairwise_majority_flips: ordered tuple[PairwiseMajorityFlip]
  position_matrix_distance: InfluenceMetricResult<float64>
  pairwise_matrix_distance: InfluenceMetricResult<float64>
  baseline_convergence_state: closed convergence assessment
  removal_convergence_state: closed convergence assessment
  convergence_degradation: InfluenceMetricResult<boolean>
  fixed_cohort_stage_wasserstein_median: FixedCohortStageMetricResult
  fixed_cohort_stage_wasserstein_maximum: FixedCohortStageMetricResult
  component_states: map[closed component ID, closed component state]
  assessable_component_ids: ordered tuple[closed component ID]
  participant_state: closed participant-level influence state
  display_component_percentiles: map[closed component ID, float64] | null
  influence_display_score: float64 | null
```

The closed component-ID order is
`central_order_kendall_distance`,
`maximum_normalized_event_rank_displacement`,
`strict_pairwise_majority_flip_fraction`, `position_matrix_distance`,
`pairwise_matrix_distance`, `fixed_cohort_stage_movement`, and
`convergence_degradation`. Maps serialize in that order. The flipped-pair tuple is
sorted by `(event_a_id, event_b_id)` after canonical orientation. Its count MUST
equal `strict_pairwise_majority_flip_count.value`; its count divided by
`strict_pairwise_majority_flip_denominator`, which MUST equal
`choose(common_event_count,2)`, MUST equal the fraction when at least two common
events exist. That branch has `pairwise_assessment=ASSESSABLE` and a null
assessment reason. With fewer than two common events the other closed
`InfluenceRecord` branch is required:
`pairwise_assessment=NOT_ASSESSABLE_FEWER_THAN_TWO_COMMON_EVENTS`, reason
`INFLUENCE.INSUFFICIENT_COMMON_EVENTS`, denominator `null`, count and fraction
`NOT_ASSESSABLE` with the same reason, and an empty flipped-pair tuple. No
numeric zero may stand in for an unassessable pairwise result.

Every `InfluenceMetricResult` obeys a closed nullability invariant:
`ASSESSABLE` requires a finite/non-null value and `reason_code=null`;
`NOT_ASSESSABLE` requires `value=null` and a non-null reason. The separate
`FixedCohortStageMetricResult` adds `NOT_APPLICABLE_BY_CAPABILITY` only for the
two fixed-cohort stage metric IDs and only with
`STAGING.FIXED_COHORT_UNAVAILABLE`; a non-stage metric cannot use that status.
A supported stage
capability with incompatible event/stage/cohort semantics uses
`NOT_ASSESSABLE`. A component state is
`INFLUENCE_COMPONENT_NOT_ASSESSABLE` for either non-assessable metric status,
but the underlying reason and capability distinction remain serialized.

For the convergence component, `value=true` exactly when the baseline is
`CONVERGENCE_PASS` and the removal is `CONVERGENCE_WARN`, `CONVERGENCE_FAIL`, or
`CONVERGENCE_NOT_ASSESSABLE`; otherwise it is `false` when both states are
present. The pairwise flip list includes only opposing strict majorities under
Section 4; a tied relation on either side is not a flip. Display percentiles and
the score are present only when at least three components are assessable and
every listed percentile is reconstructible from the complete planned removal
set. They never replace the component values.

## 7. Decision attribution

For every ordinary `one-axis`, `declared-combinations`, and `full-factorial`
origin, compare the subject with the literal declared baseline. Report
`one-axis` alternatives by decision family:

- median, interquartile range, maximum, and count of valid normalized Kendall and footrule distances;
- per-event median/max rank shifts;
- pairwise majority-flip count and rate;
- position and pairwise matrix distances;
- supported stage movements; and
- invalid, unsupported, convergence-failed, and other failed denominators.

The implemented ordinary-origin slice uses the exact active Plan/3
`axis_choices` vector; it does not add a second decision registry or change
candidate/origin/Plan identities. It creates one attempt per Plan origin and
one numeric record per unique directed subject/comparator result identity.
That numeric identity binds both ordered result IDs and both scientific
candidate-record digests. Duplicate origins remain visible as separate
attempts while reusing the same directed numeric record. One-axis rows
aggregate by `(experiment_set_id, axis_id)`. Declared-combination and
full-factorial rows retain their full axis-choice vector and mode in separate
per-vector aggregates, with planned, interpretive, descriptive-only,
not-assessable, failed, and terminal-unavailable denominators.

For different event sets, every retained raw reference-chain sample is first
projected separately to the canonical common event set. Modal orders, position
matrices, and pairwise matrices are then rebuilt from those projected samples.
Restricting a modal order or cropping a precomputed full-event matrix is
forbidden. Fewer than two common events is typed absence.

The closed ordinary-origin metric IDs are:

- `central-order-kendall-distance/1`;
- `central-order-footrule-distance/1`;
- `absolute-event-rank-shift/1`;
- `normalized-event-rank-shift/1`;
- `position-matrix-distance/1`;
- `pairwise-matrix-distance/1`;
- `strict-pairwise-majority-flip-count/1`; and
- `strict-pairwise-majority-flip-fraction/1`.

The rank-shift identifiers above are exact. This layer does not reuse the
chain-summary `maximum-normalized-event-rank-shift/1` identifier or an
influence-specific rank-displacement identifier. It emits no threshold,
stable/sensitive label, top-`k` rule, sampling, influence, or null result. In
particular, the combination/full-factorial path does not estimate factorial
effects, interactions, variance decomposition, or p-values.

Only comparisons whose two terminals are `SUCCESS` enter interpretive family
summaries. A pair containing `CONVERGENCE_WARN` remains visible as
`DESCRIPTIVE_ONLY` but cannot enter those summaries. Failed and unprepared
ordinary origins remain in planned and applicable accounting. Fewer than two
common events remains a typed not-assessable record rather than a numeric zero.

The current combination/full-factorial attribution is descriptive matched
comparison only. The wording is “associated with movement,” never “caused
movement.” A future balanced-design variance decomposition would require a
separate predeclared estimand, balance, interaction, and missing-cell contract;
it is not part of this implemented slice. A black-box feature-importance model
is not an accepted sole explanation.

## 8. Chain and convergence diagnostics

For each **unthinned post-burn** state chain of length `L`:

```text
transition_rate = sum_{l=1}^{L-1} 1[S_l != S_{l-1}] / (L-1)
unique_state_fraction = number_of_unique_permutations / L
repeated_state_runs = lengths of maximal identical-state runs
max_repeated_state_fraction = max(repeated_state_runs) / L
```

The upstream `all_accepted_orders`-style history is treated as a state chain.
Repeated states are not accepted proposals. Each frozen-plan chain binds the
same exact positive safe-integer thinning interval `T`. Core first copies the
complete unthinned post-burn order chain into an immutable snapshot. Transition
counts/rates, unique-state counts/fractions, repeated-state runs, maximum
repeated-state fractions, and endpoint evidence are calculated from every row
of that snapshot before thinning.

The retained order chain is then derived by core, and only by core, as the exact
zero-based stride projection `unthinned_rows[::T]`. The per-chain central order
used in headline cross-chain Kendall distances is the modal permutation of
those retained rows. A modal tie is resolved by the lexicographically smallest
event-ID sequence. Neither a caller-supplied retained chain nor a
caller-supplied central order is convergence evidence. Position and pairwise
summaries likewise describe retained samples, but transition-style diagnostics
must never be recomputed from them.

Every convergence-chain input carries sealed `postburn_unthinned_state_count`
and `retained_state_count`; there is no optional compatibility path. Core
validates `retained_state_count =
floor((postburn_unthinned_state_count-1)/T)+1`, validates both counts against the
admitted order arrays, and independently requires every available complete
post-burn likelihood trace to have exactly the actually admitted unthinned
order-chain length. A likelihood trace cannot fall back to a declared count when
the order chain is missing or invalid. Malformed, missing, inconsistent,
non-integral, boolean, non-positive, or unsafe-integer input accounting fails
closed. `T=1` is exactly equivalent to retaining the complete unthinned chain.

The convergence record emits `max_repeated_state_fraction` for every valid
chain. Its endpoint evidence records the final event-ID order and transition
count for every chain, plus the number of distinct endpoints among chains with
zero transitions. This is the evidence used to distinguish same-endpoint stuck
chains from stuck chains ending in distinct states.

For a finite unthinned post-burn likelihood trace, use the complete immutable
trace without applying `T`, then split it into the first and last equal-length
halves after discarding a middle element when odd:

```text
likelihood_drift_z = |mean(last)-mean(first)| / max(pooled_sample_sd, 1e-12)
```

For equal half length `h >= 2`, `pooled_sample_sd` is
`sqrt(((h-1)*sample_var(first) + (h-1)*sample_var(last))/(2*h-2))`, using the
ordinary unbiased within-half sample variances. No library-default population
variance may substitute.

If the pooled scale is finite and at least `1e-12`, use the displayed equation.
If the pooled scale is below `1e-12` and the finite means are equal within the
frozen tolerance, return finite value `0`. If the scale is below `1e-12` and the
means differ, return `{status: "NOT_ASSESSABLE", value: null,
reason_code: "ZERO_SCALE_UNEQUAL_HALVES"}`. Fewer than two values per unthinned
trace half returns the same shape with reason `INSUFFICIENT_TRACE_LENGTH`; any
non-finite raw value is an invalid-result failure and returns reason
`NONFINITE_RAW_LIKELIHOOD`. Infinity and NaN are never serialized.
The `1e-12` zero-scale threshold and `1e-12` equality tolerance are private
core-owned constants. Metric callers cannot select or override them.
Canonical per-chain rows use `INSUFFICIENT_TRACE_LENGTH` only at lengths zero
through three and `ZERO_SCALE_UNEQUAL_HALVES` only at lengths four or greater.
Because raw finiteness is checked first, `NONFINITE_RAW_LIKELIHOOD` is valid at
any positive trace length, including lengths below and above four.
`likelihood_drift_z` is descriptive only: it is displayed with trace length and
never changes `CONVERGENCE_PASS`, `CONVERGENCE_WARN`, or `CONVERGENCE_FAIL`.
The summary-level likelihood envelope is `{status, value, reason_code}`. The
scalar summary `value` is always null because drift values are per-chain. When
traces are available, summary status is `AVAILABLE`, reason is null, and the
per-chain rows carry the values. When the backend has no likelihood-trace
capability, the rows are empty and the envelope is exactly
`{status: "NOT_APPLICABLE_BY_CAPABILITY", value: null, reason_code:
"LIKELIHOOD_TRACE_UNAVAILABLE"}`.

Across independent chains, report all pairwise central-order Kendall distances, position-matrix distances, pairwise-matrix distances, and endpoint/transition summaries. Per-run convergence is classified only from that run's chains and outputs. Development budget qualification is a separate backend/profile gate and never changes the convergence state of an individual fit.

R-hat and conventional continuous-state ESS are not part of v0.1. They may be added only with a defensible permutation-valued representation and independent review.

### 8.1 Frozen per-run convergence classification

These numbers were frozen after retained development characterization and
independent review, without optimizing toward a preferred event order.

- `CONVERGENCE_NOT_ASSESSABLE`: fewer than three independent chains, missing order samples, fewer than 500 unthinned post-burn states per chain, or unavailable required cross-chain diagnostics.
- `CONVERGENCE_FAIL`: invalid/non-finite chain samples; any invalid permutation; stuck chains ending in at least two distinct states with zero transitions; or maximum pairwise position distance greater than `0.35` **and** maximum central-order Kendall distance greater than `0.50`.
- `CONVERGENCE_PASS`: all invariants pass, every chain has a nonzero unthinned post-burn transition rate, median pairwise position distance at most `0.10`, maximum at most `0.20`, and median pairwise-precedence distance at most `0.10`.
- `CONVERGENCE_WARN`: assessable and valid but neither pass nor fail.

Status: `FROZEN_AFTER_UNMODIFIED_BACKEND_CHARACTERIZATION`. The retained development characterization produced warnings and failures, not a backend selection; that result does not relax this rule. Zero transitions alone does not prove failure because a truly concentrated target can exist; disagreement among stuck chains is the fail condition. Only `CONVERGENCE_PASS` is eligible for interpretive aggregates in v0.1. `CONVERGENCE_WARN` is descriptive and ineligible unless a future contract version freezes an exact eligible warning reason after independent review.

### 8.2 Development budget qualification

This pilot selects a compute budget. It is not a scientific signal-versus-null
test. The typed characterization matrix is exactly two signal-only groups
(`easy_known_truth/profile-pilot` and
`moderate_mina_shape/profile-pilot-57x9`) by replicates `0..2` by three
budgets by three chains: three easy datasets plus three moderate datasets,
18 universes, and 54 chain executions. It contains no comparator dataset,
matched-null delta, randomization p-value, or moderate-family scientific
pass/fail. Settings are
exactly 2,000/400/10, 5,000/1,000/10, and 10,000/2,000/10 for raw
iterations/burn-in/thinning.

The hard-fenced `SYNTHETIC_ONLY` development Worker-v2 lane is owned by one
exact checked-in manifest. The manifest owns the six exact `E01 -> e01`
synthetic-to-analysis coordinates and 18 explicit UInt64 seeds, one for each
coordinate-and-chain slot. All 18 seeds are unique. Each coordinate-and-chain
seed is identical across the 2k, 5k, and 10k budgets; no seed is derived at
runtime. This narrow development lane does not change or broaden ordinary Plan
or held-out private-root seed logic. It cannot mint ordinary Plan, held-out,
scientific-acceptance, or production-audit receipts.

The manifest fixes the worker, candidate, source, environment, and request
bindings. It retains five complete source-set identities for provenance:
generator, metric rules, report-language rules, evaluator source, and governing
build prompt, plus exactly six ordered execution-source roles: generation,
preparation, seed, request-execution, capture, and metric-calculation. Before
fitting, a trusted executor must derive and match every source entry against the
exact candidate tree. The fixed request binds the coordinate/event-binding and
`AnalysisSpec` identities, backend settings, requested outputs,
canonicalization, chain count, execution and observation policy, exact
`WorkerCommand.argv` tokens, and normalized timeout.

The lane runs exactly 54 fresh serial real fits at attempt zero under the fixed
budget rotation below. Retry, cache, checkpoint, resume, and adaptation are
forbidden. Its evidence set is closed and durable: every required record must
bind to the same manifest and the same 54 terminal fits. Any missing,
non-terminal, or binding-mismatched evidence yields `NO_SELECTION`; no retry or
adaptive addition may complete the set. Runtime is invoker/core-observed around
the same terminal fit whose scientific outputs and transition diagnostics are
recorded, not a separate or substituted execution.

The pySaEBM profile `AnalysisSpec` requests exactly these nine outputs in
canonical registry order: `central_order`, `order_samples`,
`accepted_transition_diagnostics`, `position_probabilities`,
`pairwise_precedence`, `fitted_event_distributions`,
`evaluation_stage_posterior`, `evaluation_hard_stages`, and
`evaluation_expected_stage`. All 54 fits requested this identical nine-output
set. The fixed pySaEBM Worker-v2 subject does not expose a fixed-target
likelihood oracle or likelihood trace; neither capability may be invented or
substituted. Central-order-only, training-stage substitution, and
evaluation-stage omission fail closed. Stage MAE uses the exact generated
fixed evaluation-cohort rows, aligned to their
`THRESHOLD_STAGE` truth. An incompatible fitted/truth stage axis is
`NOT_ASSESSABLE` and cannot select a budget.

The evidence registry predeclares exactly:

- 54 terminal/core-observed runtime rows;
- 54 per-chain transition rows, each covering unthinned transition rate,
  unique-state fraction, maximum repeated-state fraction, and endpoint/zero
  transition evidence;
- 18 universe convergence classifications;
- for each of central-order Kendall, position-matrix distance, and
  pairwise-precedence-matrix distance, 54 within-budget cross-chain
  observations and 54 same-chain cross-budget observations;
- 54 paired candidate/reference runtime ratios;
- nine observations per easy metric: central-order Kendall truth agreement and
  normalized fixed-evaluation-cohort stage MAE; and
- nine observations per moderate descriptive metric: single-side
  fixed-reference alignment and normalized fixed-evaluation-cohort stage MAE.

The transition observations are required. Section 8.3 fixes the independently
reviewed pure transition-quality rule, including its metric directions,
per-metric aggregation, tolerances, endpoint/zero-transition handling, complete
denominators, and prohibition on targeting a preferred central order. The pure
rule has no evidence or profile-selection authority, and any Worker-v2 lane
receipt remains non-authorizing. The retained pySaEBM run completed all 54 fits,
but produced 12 convergence warnings, six convergence non-successes, no passes,
and no accepted authoritative evidence receipt. Independent review therefore
returned `DO_NOT_ADVANCE`; the outcome is `NO_SELECTION`.

The 54 same-chain comparisons are three ordered direct relations, never a
transitive inference: 18 `5k -> 10k`, then 18 `2k -> 10k`, then 18
`2k -> 5k`. Each relation aggregates each of the three distance families
separately; values are never pooled across families or relations. Every family
must have median distance `<= 0.10` and maximum distance `<= 0.20`. The
runtime rule is
`MEDIAN_OF_18_PAIRED_CANDIDATE_OVER_REFERENCE_RUNTIME_RATIOS_LT_ONE`.
For each direct relation, pair exactly 18 observations by
`(family_id, scenario_id, replicate_index, chain_id)` and divide candidate
terminal core-observed runtime by reference terminal core-observed runtime.
Every numerator and denominator must be complete, finite, and terminal
core-observed, and every denominator must be strictly positive. Sort the 18
ratios and apply the repository `inverse-empirical-cdf/1` rule at `Q(0.5)`,
which is the ninth one-based ordered value, without interpolation. It passes
only when that value is strictly `< 1` with comparison tolerance `0`. Equality,
missing/non-finite data, or an invalid denominator fails the relation and
defaults upward. This is deliberately not the ratio of two medians: for
candidate `[1,10,10]` and reference `[2,2,100]`, each repeated six times, the
paired-ratio median is `0.5` while the ratio of the separate medians is `5`.
Easy truth agreement, easy stage MAE, and moderate stage MAE are
non-inferential paired development safeguards. Moderate fixed-reference
alignment is descriptive only. This pilot uses no p-values and permits no
adaptive extra replicates.

Budget execution rotates deterministically by replicate (`2k,5k,10k`;
`5k,10k,2k`; `10k,2k,5k`) within each family. Every chain is a fresh
independent serial fit. Cache and checkpoint reads and writes are forbidden by
the plan-only `ProfileExecutionPolicy`, and its retry policy is `DISALLOWED`.
The separate profile executor must not inherit the ordinary runner's transient
retry allowance. This is executable intent, not evidence that a fit ran.
Complete backend settings remain hashed under
`ebm-audit/settings/1`; only raw iterations, burn-in, and thinning may vary,
while `n_shuffle`, `prior_n`, and `prior_v` remain identical.

All characterization and transition-review evidence must be calculated from
the same 54 fit results. The accepted pure rule may evaluate the retained
transition observations from those same results, subject to independent outer
evidence review; no second characterization fit matrix is authorized. The
later moderate development gate remains separate: its 48 fits are not
profile-pilot fits and cannot be used to increase or replace the 54-fit
characterization evidence.

The current contract slice has the closed six-case public authority and its
authenticated plan issuer. The retained pySaEBM characterization used the live
profile route for all 54 fits, but the post-fit projection did not produce an
accepted general 18-universe authoritative result receipt. The historical
`BlockedProfileDiagnostic/2` remains a record of the earlier pre-execution
state; it contains no result-shaped fields and is never benchmark evidence.
The rejected `ProfileCharacterizationReceipt/2` draft was never issued. A
future product-owned opaque
`ProfileCharacterizationEvidenceReceipt/3` must bind the fixed plan to
product-owned live case, generated-data, seed, execution, result, metric,
aggregation, comparison, and decision owners before selection may occur. The
release profile is 10k only when its complete required evidence is
`CONVERGENCE_PASS` and its reviewed transition-quality owner passes; otherwise
the outcome is `NO_SELECTION`. Full may be 5k only when the direct
`5k -> 10k` relation also has `REVIEWED_TRANSITION_QUALITY_PASS` and passes all
other components. Quick may be 2k only when 5k qualified and both direct
`2k -> 10k` and `2k -> 5k` relations do the same. Missing, pending, `WARN`,
`FAIL`, `NOT_ASSESSABLE`, borderline, incomplete, or unreviewed evidence
defaults upward; failed or unreviewed 10k evidence yields no selection. The
retained run's failed convergence profile and independent `DO_NOT_ADVANCE`
disposition make the current outcome `NO_SELECTION`; no rerun is authorized or
required for D04.

The later moderate development gate is separate and is not counted in this
profile pilot. It has exactly eight predeclared atomic signal/null pairs,
16 universes, three chain fits per universe, and 48 fresh fits. Each universe
has exactly three distinct chain seeds and one universe-level convergence gate
derived jointly from all three chains. All 16 universe gates must be
`CONVERGENCE_PASS`; convergence is not classified per chain. Any fit, chain,
universe, or pair that is missing makes the whole gate `FAIL`, as does any
invalid or failed fit/chain, any nonpass universe gate, or any structurally
invalid, binding-invalid, or nonfinite pair. Every complete, binding-valid,
finite `d_r`, including a value below `0.15`, remains in the fixed all-eight
denominator and is not a pair failure.

The conjunctive gate requires the one-sided paired sign-flip randomization test
on mean `d_r` to have exact `tail_count <= 12` and
`p_paired = tail_count / 256 <= 0.05`, the fourth one-based ordered `d_r` among
eight to be `>= 0.15`, and the fifth one-based ordered signal-universe
normalized stage MAE among eight to be `<= 0.25`. The stage rule is the fixed
upper-median safeguard. All eight pairs must be complete. Retry, dropping,
replacement, and adaptive extra pairs are forbidden. The randomization test
enumerates exactly all 256 sign assignments.

The execution uses exactly 24 distinct UInt64 fit seeds keyed by pair and chain
under predeclared `PAIRED_COMMON_RANDOM_NUMBERS`. Each seed is used exactly once
on the signal side and once on its matched-null side. The three seeds within
each side are distinct; the cross-side runs are deliberately paired and are not
claimed independent. No seed crosses pair-and-chain slots.

Eight pairs are the minimum equal/comparable nonzero-magnitude feasibility
boundary that can accommodate one discordant pair while still allowing
`p <= 0.05`. Seven equal positive differences and one equal-magnitude negative
difference give `9 / 256 = 0.03515625`; with only seven pairs, six equal
positive differences and one equal-magnitude negative difference give
`8 / 128 = 0.0625`. This rationale does not claim tolerance of an arbitrarily
large discordant pair.

### 8.3 Pure KDE exact-target transition-quality calculation

The KDE profile route has one reviewed pure calculation at
`kde-profile-exact-target-transition-quality/1`. It is deliberately not an
evidence owner. It accepts arrays and convergence states only after a future
genuine live product owner has authenticated them. It contains no receipt
issuer, caller-provided digest, persisted evidence path, pass authority, or
profile-selection authority. Its result cannot by itself freeze a profile or
turn a budget into quick, full, or release.

The calculation has exactly nine events and exactly 18 chain slots at each of
the 2,000-, 5,000-, and 10,000-iteration budgets. The retained denominators are
respectively 160, 400, and 800; a missing budget/slot, duplicate coordinate,
wrong denominator, non-finite value, malformed exact target, or non-permutation
state is an invalid calculation. There is no partial denominator. Event labels
establish array alignment only. The calculation operates on zero-based event
indexes, so a bijective event relabelling cannot change any score.
Exact position targets must be finite `[0,1]` doubly stochastic matrices;
pairwise targets must be finite `[0,1]` matrices with diagonal `0.5` and
complementary off-diagonal pairs. Those structural sum/complement identities
use absolute tolerance `1e-12` and are never repaired, clipped, or normalized.
The parity target must be one finite probability in `[0,1]`.

For every retained permutation, form exactly three non-poolable indicator
families:

- the 81 event-by-position indicators;
- the 36 upper-triangle unordered-pair precedence indicators; and
- one indicator that the permutation has even parity relative to the declared
  event-index order.

Each indicator is compared with its exact fitted-target probability. For an
even-length binary indicator series `x[0..n-1]` and exact target `theta`, use
binary64 arithmetic and the following Geyer initial monotone sequence rule.
Let `x_bar` be the complete-series mean and define the biased sample
autocovariance

```text
gamma_k = (1/n) sum_{t=0}^{n-k-1} (x_t - x_bar)(x_{t+k} - x_bar)
Gamma_j = gamma_{2j} + gamma_{2j+1}
```

Retain consecutive `Gamma_j` values only until the first value `<= 0`. Replace
each retained value after the first with the minimum of itself and its retained
predecessor. With those monotone values `Gamma_tilde_j`, define:

```text
long_run_variance = max(0, -gamma_0 + 2 sum_j Gamma_tilde_j)
MCSE = sqrt(long_run_variance / n)
z = 3.524846146812584
```

An empty positive sequence therefore yields zero after the explicit
non-negative clamp. This rule emits an MCSE, not an ESS or an R-hat. The
indicator score is:

```text
full_error = |mean(x) - theta|
first_half_error = |mean(x[0:n/2]) - theta|
second_half_error = |mean(x[n/2:n]) - theta|
score = max(
  full_error + z * MCSE,
  first_half_error,
  second_half_error
)
```

The half checks prevent early/late drift from cancelling in the complete
mean. Per chain, take the maximum score separately across all 81 position
indicators, all 36 pairwise indicators, and the one parity indicator. Never
pool the three families. For each budget and family, sort the 18 chain maxima.
The inverse-empirical-CDF median is the ninth one-based value. That family is
transition-qualified only when its median is `<= 0.10` and its maximum is
`<= 0.20`, with no added comparison tolerance. All three families must qualify.

The calculator also independently derives the complete unthinned post-burn
transition count/rate, unique-state count/fraction, repeated-state run lengths,
maximum repeated-state run length/fraction, final endpoint order, endpoint
position-change count, and distinct zero-transition endpoint count. These
diagnostics stay visible but introduce no additional raw-rate, unique-state,
repeat-run, or endpoint threshold. Every chain must nevertheless have more
than zero authenticated unthinned post-burn transitions, and the convergence
gate for every chain's universe must be exactly `CONVERGENCE_PASS`.

A complete valid budget that violates any family boundary, has a zero-transition
chain, or has a non-pass convergence gate is `PROFILE_UNQUALIFIED`. It is never
relabeled `SAMPLER_DEFECT`: even a genuinely concentrated exact target can
produce a valid zero-transition chain. Malformed or incomplete inputs are an
invalid calculation, not `PROFILE_UNQUALIFIED`. The pure calculator returns
only the three ordered per-budget transition outcomes. The genuine outer
evidence owner must emit `NO_SELECTION` when none transition-qualify and must
still apply the existing hierarchical cross-budget, runtime, truth/stage,
convergence, subject-binding, and freeze predicates. A transition-qualified
budget alone is not a profile selection.

## 9. Null-relative evidence metrics

Required refitted null families are defined in the synthetic/null specification. For an observed statistic `T_obs` where larger means more structure and `R` null replicates:

```text
p_empirical = [1 + sum_r 1(T_null_r >= T_obs)] / (R + 1)
null_effect = T_obs - median_r(T_null_r)
```

The backend-neutral primary statistic route is the ordered pair `pairwise_concentration/v1` plus `position_concentration/v1`. Both are required; there is no fallback statistic substitution. A commensurate best-order log-likelihood margin per participant may be displayed as `OPTIONAL_DESCRIPTIVE_LIKELIHOOD_MARGIN`, but it never enters strong-label eligibility or the held-out false-positive denominator. Stage summaries are not primary null evidence because using fitted stage structure can be circular.

### 9.1 Null calibration identity

Every calibrated strong-label rule is keyed by an immutable
`NullCalibrationIdentity`. Its canonical field set is the schema's exact
27-field `required` array, repeated in the same registry order in the benchmark
contract. Missing or additional fields are invalid; JSON object key order is
normalized by canonical serialization. It contains all of:

- the exact prefixed `benchmark_subject_digest` for the integration subject
  under evaluation; for product readiness this is the exact project-owned
  `SYNTHETIC-ONLY` conformance EBM through the ordinary generic worker;
- exact worker name/version, backend name/version, backend source commit and
  source digest, worker executable digest, worker code digest, and protocol
  version;
- exact backend algorithm and algorithm settings digest;
- exact environment/lock digest and platform qualification;
- exact frozen auditor candidate digest;
- ordered statistic route `pairwise_concentration/v1, position_concentration/v1`;
- exact versions of the pure-generator, label-permutation, and within-group-feature-permutation procedures;
- convergence eligibility rule (v0.1 is the singleton `CONVERGENCE_PASS`);
- MCMC/profile ID and complete profile settings digest; and
- null/report rule version and benchmark-contract hash.

The identity is serialized canonically and hashed with domain
`ebm-audit/null-calibration-identity/1` as a prefixed `Sha256Digest`.
Calibration is `NULL_CALIBRATION_IDENTITY_MISMATCH` if any field differs or is
missing; no thresholds, false-positive result, or strong-label eligibility may
be reused across that mismatch. A different exact integration subject or
conformance subject, worker/backend identity, algorithm, environment, candidate,
statistic route, null procedure, convergence rule, profile, or rule version
requires new development calibration and fresh held-out pure-no-signal cases.
The backend-named fields are exact identity fields for the implementation under
evaluation; they do not require a named external backend or an external
qualification registry. A named-backend acceptance profile may use its own exactly matching
identity only as optional downstream per-integration qualification and cannot
gate library readiness.

For the exactly eight matched synthetic signal/null replicate pairs from
comparator `cmp_moderate_signal_vs_pure_no_signal`, with exact pairing key
`<comparator_id>/<source_variant_id>/<replicate_index_decimal>`, a fixed source
reference order must be bound before any fit. This prospectively freezes the
calculation; it does not claim that matched-source authority or result evidence
exists yet.

For each signal and matched-null universe, calculate
`reference_order_alignment` for each of its three chain central orders against
the fixed injected source order. For this calculation, each chain central order
is derived by core as the modal permutation of that chain's exact retained
order rows. A modal tie is resolved by the lexicographically smallest event-ID
sequence. A Worker/headline `central_order` output is not trusted and must not
be used for this calculation. Sort the three core-derived alignment values and
take the second one-based ordered value, the `inverse-empirical-cdf/1` value at
`Q(0.5)`, as that universe's median alignment. For each signal universe,
calculate normalized stage MAE for each chain, sort the three values, and
likewise take the second one-based ordered value as that universe's median
normalized stage MAE.

For pair `r`, define:

```text
d_r = signal_universe_median_alignment_r
    - matched_null_universe_median_alignment_r
```

Sort the eight `d_r` values. The effect threshold uses the fourth one-based
ordered value and requires it to be `>= 0.15`, so at least five of eight pair
effects meet the threshold. Sort the eight signal-universe median normalized
stage MAEs. The stage threshold is the upper-median safeguard: the fifth
one-based ordered value must be `<= 0.25`, so at least five of eight signal
universes meet the threshold. This stage rule is not described as a generic
inverse-ECDF rule.

The comparator's alignment is a predeclared-reference statistic only: because
its generator truth is non-identifiable, it is never called truth recovery.
The prospectively frozen one-sided paired sign-flip randomization test operates
on mean `d_r` and enumerates exactly all `2^8 = 256` sign assignments:

```text
eps = 1e-12
tail_count = count_s[mean_r(s_r d_r) >= mean_r(d_r) - eps],
             where s ranges over {-1, +1}^8
p_paired = tail_count / 256
randomization_pass = (tail_count <= 12)
```

The tail comparison is inclusive: count a signed mean exactly when
`signed_mean >= observed_mean - eps`. Here `eps` is the absolute tolerance
`1e-12`; no relative tolerance applies. The test passes only when
`tail_count <= 12`, which is the exact 256-assignment realization of
`p_paired <= 0.05`.

The 48 fits use exactly 24 distinct UInt64 seeds keyed by `(pair, chain)`.
Under the predeclared `PAIRED_COMMON_RANDOM_NUMBERS` rule, each seed is reused
exactly once on the signal universe and exactly once on its matched-null
universe. The three seeds within each side are distinct, the cross-side chain
runs sharing a seed are deliberately paired rather than claimed independent,
and no seed crosses pair-and-chain slots. Signal and comparator may share only
the components that the future matched-source authority predeclares for that
comparator; the pure comparator zeros all signal effects. This contract does
not claim that authority exists yet.

Each universe has exactly one convergence gate derived jointly from all three
chains. All 16 universe gates must be `CONVERGENCE_PASS`. Any fit, chain,
universe, or pair that is missing makes the moderate benchmark rule `FAIL`, as
does any invalid or failed fit/chain, any nonpass universe gate, or any
structurally invalid, binding-invalid, or nonfinite pair. Every complete,
binding-valid, finite `d_r`, including a value below `0.15`, remains in the
fixed all-eight denominator. It is never dropped, replaced, retried, or
converted to an unpaired observation. Cross-pair matching, outcome-sorted
pairing, unpaired substitution, adaptive extra pairs, and adaptive extra chains
are prohibited.

### 9.2 Pre-authorization candidate decision

False-positive calibration evaluates a counterfactual numerical decision, not a
report label. For each calibration opportunity, compute exactly one
`CandidateStrongEvidenceDecision` before consulting any held-out false-positive
result, optional downstream qualification state, or authorization to emit final
report language. Its states are:

- `CANDIDATE_STRONG_EVIDENCE`;
- `CANDIDATE_NOT_STRONG_EVIDENCE`; or
- `CANDIDATE_STRONG_EVIDENCE_NOT_ASSESSABLE`.

The decision is derived from one observed-fit evidence record and the exact
ordered 177-fit universe: 59 replicates for each of the three null families,
with each fit carrying both primary statistics, fit/convergence state, complete
persisted refit-step evidence, role-specific operation evidence, and
hard-failure state. `RefitStepsDigestPreimage` is exactly
`{schema_version,digest_state=DIGEST_PREIMAGE,
null_calibration_identity_digest,ordered_step_ids,refit_steps_digest=null}` and
is hashed under `ebm-audit/refit-steps/1`. Its ordered step IDs are exactly:

1. `prepared-input binding`;
2. `authenticated worker invocation`;
3. `fit-result validation`;
4. `convergence derivation`;
5. `pairwise concentration`; and
6. `position concentration`.

Persisted `RefitStepsEvidence` changes only `digest_state` to `PERSISTED` and
stores the recomputed prefixed digest. The preimage's
`null_calibration_identity_digest` must equal the digest recomputed from the
complete candidate `NullCalibrationIdentity`. Missing, extra, reordered, or
substituted step IDs and mismatched persisted digests are invalid.

Observed and null operation-role evidence separately binds the opportunity,
source-input digest, transformation digest, explicit observed/null role, null
family or explicit null, replicate or explicit null, fit seed, and
`complete_refit=true`. The candidate-decision digest authenticates those
role-specific facts, but none enters `refit_steps_digest`: the observed and null
inputs, transformations, family/replicate coordinates, and seeds are expected
to differ without making the fixed refit procedure unequal. Omission,
relabeling, enclosing-slot mismatch, or cross-opportunity substitution is
invalid.

The decision is assessable only when that complete universe is present once in
the declared family/replicate order; observed and null pipelines refit the
identical six steps; the observed fit and every null fit are `SUCCESS` and
`CONVERGENCE_PASS`; both fixed primary statistics are finite; every artifact is
bound to one complete candidate `NullCalibrationIdentity`; and no hard failure
is present. Exact identity equality here means equality among the candidate
identity, the opportunity, the observed fit, and all 177 nested fits. It does
**not** require a prior held-out calibration receipt or an already-authorized
final label.

Each fit preserves the core convergence vocabulary exactly:
`CONVERGENCE_PASS`, `CONVERGENCE_WARN`, `CONVERGENCE_FAIL`, or
`CONVERGENCE_NOT_ASSESSABLE`. No candidate-evaluator alias may replace one of
those states. Only `CONVERGENCE_PASS` is eligible for an assessable decision;
the other three remain distinct retained evidence and fail that precondition.

For an assessable opportunity, the decision is
`CANDIDATE_STRONG_EVIDENCE` exactly when both fixed primary statistics have
positive `null_effect` and `p_empirical <= 0.05` in every required family. It is
`CANDIDATE_NOT_STRONG_EVIDENCE` otherwise. No likelihood-margin statistic enters
this decision. The decision record contains its rule ID, the complete candidate
`NullCalibrationIdentity` object and its recomputed domain-separated hash,
opportunity ID, the observed-fit record, all 177
ordered null-fit records, and ordered per-family/per-statistic
`{T_obs, ordered_null_statistics, null_replicate_count,
null_exceedance_count, p_empirical, null_median, null_effect}` results, state,
and exact failed precondition codes. Those results, codes, and state are derived
from the fit records; they are never trusted as independent assertions.
The closed schemas are
`scientific-invariant.schema.json#/$defs/NullCalibrationIdentity` and
`#/$defs/CandidateStrongEvidenceDecision`. Executable invariant hooks
recompute `p_empirical=(1+exceedances)/60`, `null_effect`, assessability, and
the three-state decision from the six ordered family/statistic tests. A supplied
state that contradicts those inputs is a hard failure.

This decision is evaluator evidence only. It MUST NOT be rendered as
`STRONGER_THAN_CHOSEN_REFITTED_NULLS`, copied into a production conclusion, or
used to claim an authorized strong label. The held-out aggregate of these
candidate decisions authorizes or rejects later report language for the exact
identity; it cannot change any already sealed candidate decision.

### 9.3 Authorized report-label eligibility

A `STRONGER_THAN_CHOSEN_REFITTED_NULLS` report label is eligible only when:

- all three required null families completed with the frozen minimum replicates;
- observed and null pipelines refit identical preprocessing/model steps;
- convergence is `CONVERGENCE_PASS` for the observed fit and every contributing null fit;
- both fixed primary statistics have positive `null_effect` and `p_empirical <= 0.05` in every required family;
- the held-out false-positive gate passed for the exact matching `NullCalibrationIdentity`; and
- no hard failure is present.

If any eligibility condition is absent, the strong label is prohibited. “Stable,” “internally concentrated,” “stronger than these nulls,” and “scientifically true” remain four distinct propositions. This product never emits the fourth.

For `x` `CANDIDATE_STRONG_EVIDENCE` decisions among `n` held-out no-signal
opportunities, the one-sided 95% Clopper-Pearson upper bound is
`BetaInverse(0.95; x+1, n-x)` for `x < n`, and `1` for `x = n`. Both the point
estimate `x/n` and this bound must be no greater than the frozen allowance. The
planned FPR denominator is exactly the 60 unique, ordered natural case
identities in one complete bound sealed-case manifest for independently generated
`pure_no_signal` cases whose generator truth guarantees `recoverable_signal:
false`. The evaluator hashes that manifest and each of the 60 complete persisted
truth objects, then derives eligibility from truth rather than a typed witness.
Each opportunity must match the sealed case's family and truth digest and must
bind exactly one recomputed candidate
decision digest and derived state. It never counts the final authorized report
label.
The gate is assessable only when all 60 opportunities have exactly one assessable
candidate decision and all required observed/null artifacts are complete,
finite, candidate-identity-matched, and `CONVERGENCE_PASS`. Any invalid, failed,
timed-out, unsupported, non-assessable, convergence-ineligible, incomplete, or
multiply scored opportunity remains in the planned denominator and makes the
FPR gate `FAIL`; it is never counted as a non-positive. Label permutations and
within-group feature permutations are transformation diagnostics: they may
expose model behavior but do not guarantee absence of every scientifically
relevant structure in their source data and are excluded from this denominator.

The ordered 60-opportunity manifest and aggregate use
`FalsePositiveOpportunityManifest` and `FalsePositiveEvaluation`. Their
invariant hooks recompute every count, `x/60`, the exact one-sided
Clopper-Pearson bound, and PASS/FAIL state from the sealed candidate decisions;
none is accepted as an independently asserted scalar.

### 9.4 Closed benchmark/report predicates

The following terms are versioned predicates, not prose judgements:

- `KNOWN_POOR_ORDER_RECOVERY/v1` is assessable only for an identifiable strict
  known-truth order with an eligible finite score, and is true exactly when
  `kendall_agreement < 0.70`.
- `KNOWN_POOR_STAGE_RECOVERY/v1` is assessable only with compatible known-truth
  stage semantics and an eligible finite score, and is true exactly when
  `normalized_stage_MAE > 0.35`.
- `KNOWN_POOR_RECOVERY/v1` is true when either assessable predicate above is
  true, false when at least one is assessable and none is true, and
  `NOT_ASSESSABLE` when neither is assessable. Non-identifiable truth is never
  converted to poor recovery.
- `PRECISE_ORDER_OUTPUT/v1` is true exactly when the independently computed
  within-fit state is `INTERNALLY_CONCENTRATED`.
- `FORCED_PRECISION/v1` is true exactly when
  `KNOWN_POOR_RECOVERY/v1=true` and `PRECISE_ORDER_OUTPUT/v1=true`; it is false
  when both inputs are assessable and that conjunction is false, and otherwise
  `NOT_ASSESSABLE`.
- `INELIGIBLE_STRONG_LABEL/v1` (the sole meaning of “unjustified strong label”)
  is true exactly when a rendered report contains
  `STRONGER_THAN_CHOSEN_REFITTED_NULLS` but any Section 9.3 eligibility
  conjunct is false. A candidate calibration decision is not a rendered label
  and does not satisfy this predicate.

Every predicate record contains `{predicate_id, status, value, reason_codes,
input_record_ids}`. `status=ASSESSABLE` requires Boolean `value` and no missing
input; `NOT_ASSESSABLE` requires `value=null`. Benchmark prose such as “poorly
recovered,” “forced precision,” or “unjustified strong” MUST resolve to these
IDs; an evaluator may not infer their meaning from output text.

## 10. Quantitative benchmark proposals

The following values are candidates for development review and are not frozen
thresholds except for the Moderate 57-by-9 row. That row alone is
`PROSPECTIVELY_FROZEN_NO_EXECUTION_OR_RESULT_AUTHORITY`: its calculation and
thresholds are fixed before execution, but this status supplies no
matched-source authority, execution authority, result authority, or result
evidence.

| Gate | Rule | Justification/status |
|---|---|---|
| Exact oracle and deterministic metric fixtures | Integer/order outputs exact; float probabilities/distances absolute error `<= 1e-12` for tiny fixtures. | Float64 operations on tiny enumerations should meet this; `FROZEN_REVIEWED`. |
| Easy known-truth order | Median Kendall agreement `>= 0.90`; 10th percentile `>= 0.75`. | Requires high typical recovery but preserves a stated lower tail; `FROZEN_REVIEWED`. |
| Easy known-truth stage | Median normalized stage MAE `<= 0.10`; 90th percentile `<= 0.20`. | Direct implementation of “small fraction of stage range”; `FROZEN_REVIEWED`. |
| Moderate 57-by-9 shape | Fourth one-based ordered `d_r` among 8 is `>= 0.15`, the one-sided paired sign-flip randomization test on mean `d_r` has exact `tail_count <= 12` and `p_paired = tail_count / 256`, and the upper-median safeguard (fifth one-based ordered signal-universe median normalized stage MAE among 8) is `<= 0.25`. | At least 5/8 pair effects and 5/8 signal universes meet their thresholds; null-side alignment is not truth recovery; every complete finite `d_r` remains in the all-eight denominator; all 8 pairs are complete and all 16 jointly derived universe convergence gates are `CONVERGENCE_PASS`; `PROSPECTIVELY_FROZEN_NO_EXECUTION_OR_RESULT_AUTHORITY`. |
| Noise ladder | Across at least five levels, Spearman correlation of noise with median agreement `<= -0.70` and with median entropy `>= 0.70`. | Aggregate trend, not replicate-by-replicate monotonicity; `FROZEN_REVIEWED`. |
| Single-participant sabotage | Injected participant is in top five display ranks in `>= 60%` and top ten in `>= 80%` of replicates, with at least two component metrics in the top quartile. | Tests useful detection without requiring one opaque score; `FROZEN_REVIEWED`. |
| No-signal strong-label false positives | Point estimate `<= 0.05` and one-sided 95% Clopper-Pearson upper bound `<= 0.05` over at least 60 held-out opportunities. | Controls uncertainty around the false-positive estimate; `FROZEN_REVIEWED`. |
| Same seed/environment | Canonical scientific payload byte-identical after removing declared runtime/path fields. | Prevents unexplained nondeterminism; `REQUIRED_HARD_GATE`. |
| Serial/parallel | Canonical scientific payload value-equivalent at the frozen numeric tolerance and identical discrete outputs. | Scheduling must not change science; `REQUIRED_HARD_GATE`. |
| Row/column remapping | Identical remapped scientific outputs. | Identity/order invariance; `REQUIRED_HARD_GATE`. |

No contingent threshold may be weakened after held-out results. A scientific change requires a new contract version, rationale, fresh candidate, and fresh held-out seeds.

## 11. Numerical and missing-result rules

- The frozen numerical tolerance is absolute `1e-12` and relative `1e-10` for invariant checks; cross-platform behavior remains `UNVERIFIED`.
- Aggregates always report numerator, planned denominator, valid denominator, and each excluded terminal status.
- NaN is never used as a silent placeholder in machine-readable metric output. Use `{status, value: null, reason_code}`.
- Failed, invalid, unsupported, convergence-failed, and non-assessable universes cannot contribute numerical values to valid-fit aggregates and cannot disappear from denominators.
- Multiple comparisons are not converted into discovery claims. Empirical null p-values describe only the predeclared diagnostic and null family.
- Every benchmark rule has a predeclared planned denominator and minimum valid
  coverage in the machine contract. Insufficient coverage is `FAIL`, never
  `WARN`, and can never improve a statistic. Matched rules additionally require
  the predeclared complete-pair coverage. A terminal failure is retained under
  its exact reason and cannot be removed before a quantile, rate, or trend is
  calculated.
