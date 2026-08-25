# Product and scientific specification

Status: FROZEN SCIENTIFIC CONTRACT; READINESS AMENDED BY ADR-0014
Product contract: `ebm-robustness-auditor-product/1.0`
Freeze date: 2026-07-28

## 1. Authority and document set

This is the top-level product and scientific contract for the private build of
**EBM Robustness Auditor**. The final build prompt supersedes the deprecated
master prompt. ADR-0001 closed prior-art research with `EXTEND`; ADR-0002 through
ADR-0004 record the fixed build architecture. Accepted ADR-0014 and
`ebm-integration-readiness.md` supersede only conflicting named-backend and
Mina-dependent readiness requirements; all other scientific and product rules
remain active.

The following documents are jointly normative. The original frozen set was
reviewed together; ADR-0014 later added the readiness contract:

- this product/scientific specification;
- `canonical-data-and-result-schema.md`;
- `adapter-protocol.md`;
- `analysis-universe.md`;
- `metrics-and-uncertainty.md`;
- `synthetic-and-null-validation.md`;
- `report-language-rules.md`;
- `artifact-hashing-and-freeze.md`;
- `ebm-integration-readiness.md` for the amended integration and readiness
  boundary;
- `../security/threat-model.md`; and
- the current `../../evaluator/benchmark_contract.yaml`.

If two frozen documents conflict, execution fails closed until the conflict is
resolved. For the readiness dependencies expressly listed in ADR-0014,
`ebm-integration-readiness.md` is the later authority. A change to frozen
scientific or benchmark semantics requires a new version, ADR,
benchmark-contract hash, and fresh held-out commitment. The published Idris
event order and retained backend probe outputs are context, not ground truth and
not authority to relax this contract.

## 2. Product question and answer boundary

Given an existing event-based disease-progression analysis and a predeclared,
constrained set of scientifically defensible alternatives, the product answers:

> Which event-order and participant-stage conclusions remain similar, which
> move, what declared decision is associated with the movement, which
> participants are influential, and is the apparent structure stronger than
> behavior under known-truth and refitted no-signal controls?

The product makes sensitivity, uncertainty, failure, and calibration inspectable.
It does not establish that an emitted sequence is biologically true. It does not
perform diagnosis, prognosis, individual time-to-conversion prediction, treatment
recommendation, causal inference, regulatory validation, or medical-device
assessment.

An order returned, repeated, concentrated, or stable under tested choices is not
by itself evidence that a recoverable disease-order signal exists. Cross-sectional
stage is a model-relative count of abnormal-prefix events, not an individual's
biological onset time, prognosis, or causal disease state.

## 3. Research baseline preserved

The motivating paper is Mina Idris et al., “Staging of Alzheimer’s disease
progression in Down syndrome using mixed clinical and plasma biomarker measures
with machine learning,” *Alzheimer’s & Dementia* (2025), DOI
`10.1002/alz.70446`.

Publicly established context is limited to:

- a cross-sectional EBM analysis of 57 adults with Down syndrome without a
  clinical Alzheimer’s diagnosis;
- nine publicly named plasma/cognitive events and reported stages `0..9`;
- age-defined groups used as a control/reference versus assumed preclinical
  proxy; and
- a reported movement of Aβ42/40 when plasma observations beyond a 1.5-IQR rule
  were retained.

The paper does not identify the EBM package/model version, mixture family, exact
MCMC schedule, chain count, seed, convergence rule, stage-likelihood formula,
missing-data behavior, residualisation formula, or complete executable
preprocessing contract. Ancillary MICE/PCA/GAM/LOESS work is not silently part of
the EBM pipeline. The paper's published order is contextual evidence, never
benchmark truth or evidence of baseline reproduction.

No participant-level research data are available during development. The build
uses public information and clearly labelled synthetic data only. It MUST NOT
request, obtain, reconstruct, infer, scrape, fabricate, or commit participant-
level research data.

## 4. Fixed product and architecture decisions

These are not optimization choices:

1. The product is new standalone software. It owns audit orchestration,
   uncertainty separation, influence, synthetic/null validation, provenance,
   privacy, CLI, and deterministic reporting.
2. Model fitting is replaceable. The core package MUST NOT structurally depend on
   an EBM implementation.
3. The primary integration contract is the versioned local external-command
   protocol `ebm-audit-worker/v2`.
4. Historical `pysaebm` work used exact source commit
   `54521a9adfedf58facd7bafd741a14d9ed110d2a`, source version `7.7.9`, as one
   conditional integration profile. It is not a product reference backend or a
   readiness dependency.
5. Any optional downstream `pysaebm` integration runs through the same generic
   worker boundary in a separate locked environment/process; it is not vendored
   or imported by the core.
6. Version 0.1 supports one strict single-sequence cross-sectional EBM only.
7. The generic worker protocol, template, and contract harness are the sole EBM
   integration surface. No competing SDK or model-specific execution boundary
   is a product deliverable.
8. Specification and benchmark contracts receive independent review and freeze
   before substantive optimization.
9. Participant-data-time execution and report generation are local and offline,
   with no telemetry, cloud/external API, remote assets, or LLM.
10. The repository remains local/private. This build adds no project licence and
    performs no push, publication, issue, pull request, package release, external
    upload, or researcher/institution contact.

If primary evidence makes a fixed decision technically impossible, work stops at
that boundary and records `IMPLEMENTATION-CONFLICT`; the strategy is not silently
changed.

## 5. Users, inputs, and outputs

The primary user is a non-software research scientist operating inside an
approved local or institutional environment. A methods/software reviewer is a
secondary user.

Required inputs are:

- one canonical cross-sectional wide dataset or named externally supplied data
  variants;
- one stable private participant identifier per row, using either an exact
  non-Boolean signed safe-range integer or visible Unicode text that is
  non-empty, not all whitespace, already NFC, valid scalar text, and contains
  no control, format, or surrogate character;
- explicit event specifications and abnormal directions;
- explicit reference/at-risk grouping where the backend requires it;
- an immutable baseline plus predeclared analysis-universe choices;
- an exact worker command and configuration; and
- optionally, a canonical reference-result export from the existing analysis.

Primary outputs are:

- immutable machine-readable run manifest, resolved configuration, data summary,
  universe table, result records, failure/warning ledgers, and provenance hashes;
- deterministic JSON/CSV and publication-quality static figures;
- a self-contained local HTML report with no external assets/network call; and
- an optional separate restricted participant-alias mapping, never included by
  default.

The report presents scientific accounting and limitations; it is not a manuscript
generator and never improvises model prose.

## 6. Supported scientific shape

Version 0.1 supports only:

- cross-sectional data with one row per participant;
- one numeric continuous biomarker/cognitive measurement per event and
  participant, with explicit missing values;
- one strict total order of `N >= 2` unique events;
- canonical stages `0..N`, where stage `k` means the first `k` events in the
  fitted order are treated as abnormal by that model;
- explicit event direction (`higher` or `lower`); unresolved direction can only
  validate/plan;
- declared reference/control-like and at-risk/progressing roles when required;
- central order and, where truthfully available, order states, position
  probabilities, pairwise precedence, likelihood trace, and participant-stage
  posterior/hard stages;
- fixed-evaluation-cohort staging where the worker supports it; and
- CPU-only local execution.

Version 0.1 does not implement or claim:

- a new EBM inference algorithm;
- subtype discovery or multi-sequence SuStaIn;
- temporal/dwell-time, simultaneous/grouped-event, or longitudinal models;
- repeated visits, raw MRI processing/segmentation, or automatic feature
  discovery;
- clinical classification, diagnosis, prognosis, conversion time, treatment
  recommendation, causality, or a medical device;
- cloud/telemetry/SaaS operation, a GUI, a general workflow engine, a manuscript
  generator, or a participant-data upload route.

Extension points may describe these as unsupported. They MUST NOT return false
placeholders or flatten incompatible semantics into strict-order output.

## 7. Scientific evidence layers

Every metric, table, figure, rule, and claim carries exactly one primary evidence
layer. Layers are never pooled merely to produce a single persuasive uncertainty
summary.

| Layer | Unit varied | Required interpretation |
| --- | --- | --- |
| `within_fit` | Retained order/stage samples inside one fit | Conditional uncertainty represented by one fitted model and its declared settings. |
| `chain` | Independent explicit chains/seeds for the identical specification | Stochastic/sampling variation of the fitting procedure. |
| `sampling` | Participant bootstrap or declared subsampling, with refitting | Variation associated with sampling participants. |
| `analyst_decision` | Predeclared cohort, preprocessing, feature, outlier, missingness, covariate, or model-setting choices | Descriptive association between a declared decision and movement. Not causal. |
| `participant_influence` | Leave-one-participant-out or declared small-group removal, with refitting | Sensitivity to specific observations. “Influential” does not mean bad data. |
| `null` | Complete refit after a declared no-signal intervention | Behavior of the same machinery when selected structure is destroyed or absent. |

An unavailable capability needed to fit or to compute a non-stage requested
component terminates as `UNSUPPORTED_CAPABILITY`; an
unverified release prerequisite is `UNVERIFIED`; and a metric that is inapplicable
because a predeclared capability is false is
`NOT_APPLICABLE_BY_CAPABILITY` with a typed reason and `value=null`. These are
different vocabularies and are never substituted for one another. Absence is
never converted to pass, stability, zero variability, or confidence.

In particular, absence of fixed-cohort staging does not terminate a candidate
that can otherwise fit. Order, position, pairwise, influence, and convergence
components continue. Only the fixed-cohort stage component is
`NOT_APPLICABLE_BY_CAPABILITY` with reason
`STAGING.FIXED_COHORT_UNAVAILABLE` and `value=null`. Whole-candidate
`UNSUPPORTED_CAPABILITY` is reserved for inability to fit the requested
universe or compute a required non-stage output.

## 8. Canonical data, identities, and data changes

`canonical-data-and-result-schema.md` is normative. In particular:

- private participant IDs remain in a separate core-owned mapping boundary;
- workers receive only contiguous row indexes;
- stable event IDs are distinct from display labels and private source columns;
- missing values are preserved by the core until an explicit policy acts;
- invalid numeric values and identifiers-as-events fail closed;
- every flag, mask, exclusion, transform, and data-variant selection has counts,
  manifests, rationale, input/output digests, and private joins where needed; and
- caller data are never mutated.

The currently executable missingness policies are `error` and explicit
`complete-case`. `external-variant` remains reserved vocabulary, but
`AuditConfig/0.3` resolution rejects every external-variant declaration or
selection because no complete physical owner exists yet. The core does not
fabricate a `DataVariant`, compatibility shim, or default imputation route.
Adding one later requires a versioned physical contract and scientific review,
and must propagate imputation uncertainty as its own declared layer.

The built-in covariate choices are no adjustment or ordinary linear
residualisation fitted only in the declared reference group and applied to all
participants. Formula, intercept, categorical encoding, design rank, and counts
are explicit; insufficient rows or rank deficiency fail. Resampling refits the
adjustment without leakage.

Outlier policy distinguishes `none`, `flag-only`, explicit IQR rules, whole-
participant exclusion, masking, and transformations. A worker that rejects NaNs
cannot run a cell-masking universe unless a separate complete external variant is
declared. Masking never becomes row deletion or imputation silently.

## 9. Backend and capability truthfulness

The protocol's capability declaration covers strict sequence, grouped events,
subtypes, temporal events, missingness, per-feature missingness, order samples,
position probability, pairwise precedence, likelihood trace, transition
diagnostics, fitted distributions, stage posteriors/hard stages, fixed-cohort
staging, portable models, multiple chains, bootstrap, cross-validation,
deterministic seed, and offline operation.

Rules:

- Capabilities report what the worker genuinely supports, not what the core could
  approximate around it.
- A requested capability needed to fit or compute a non-stage component yields
  `UNSUPPORTED_CAPABILITY` when unavailable. Missing only fixed-evaluation-cohort
  staging leaves the candidate `VALID` and fits running; only the fixed-cohort
  stage component is `NOT_APPLICABLE_BY_CAPABILITY` with `value=null` and
  `STAGING.FIXED_COHORT_UNAVAILABLE`. That status is derived into the complete
  fit payload and canonical chain. It excludes every array member owned by the
  unavailable output, including the shared `evaluation_row_indexes`; a worker
  cannot carry a posterior, MAP stage/tie mask, or expected-stage array beside
  the not-applicable record and recover acceptance by re-hashing downstream
  evidence.
- Unsupported fields are absent. Empty arrays, uniform matrices, hard-stage
  one-hot conversions, or copied baseline values are not substitutes.
- A mathematically valid derived field is labelled `WORKER_DERIVED` or
  `CORE_DERIVED`, with a versioned method and source hashes.
- A backend, algorithm, seed, setting, or source substitution is
  `PROTOCOL_ERROR`.
- Core scientific semantics remain unchanged when a worker is replaced.

The following `pysaebm` details are retained as historical evidence and as an
optional downstream per-integration profile; they do not select a product
backend or gate readiness. That profile supports the algorithm ID
`conjugate_priors`. Exact source characterization of commit
`54521a9adfedf58facd7bafd741a14d9ed110d2a` establishes that its returned order
history has `R` post-proposal current-state rows: returned row `q` is state after
proposal `q+1`, including repeats after rejection. The canonical worker therefore
uses that exact history, discards the first `B` rows, and thins rows `B+m*T<R`.
It infers transitions from adjacent unthinned post-burn states and correctly
converts the backend's one-based per-biomarker position assignments.

The same exact source returns a likelihood/acceptance-score history whose rows do
not identify the same canonical post-proposal state: values are recorded before
the proposal, the initialized order and final order likelihood are not both
represented, and an accepted parameter update is not followed by a matching
likelihood reevaluation. Consequently the v0.1 worker declares
`order_samples=true`, `accepted_transition_diagnostics=true`, and
`likelihood_trace=false`; canonical likelihood arrays are absent with a stable
limitation warning. It MUST NOT shift rows, pad endpoints, replay proposals, or
instrument/modify the scientific algorithm to fabricate a trace. The private
native score history may be retained only as a namespaced quarantined artifact.

This is the recorded `IMPLEMENTATION-CONFLICT` with build-prompt requirements
9.3(11–12). It is resolved within the higher-priority truthfulness and
unmodified-backend boundary by treating likelihood as an independent optional
capability. Likelihood/oracle-likelihood metrics are
`NOT_APPLICABLE_BY_CAPABILITY` for this exact
subject by predeclared capability; order, transition, multi-chain, known-truth,
null, privacy, and every other applicable gate remain mandatory. The wrapper may
use lower-level upstream functions but may not copy or modify the algorithm.

## 10. Analysis universe

An audit is a constrained, predeclared set of defensible analyses, not all
possible pipelines. One exact `AnalysisPlan/3` contains the complete ordered
candidate set. `PlanningAuthority` internally creates one complete ordered
`PreparationReceipt/2`; prepared candidates receive a `UniverseSpec/3`, while
unprepared candidates have no universe. Every candidate produces exactly one
core-final `ResultRecord/2`. Every immutable prepared universe records dataset variant, group rule,
event set/directions, preprocessing, outlier and missingness policy, covariate
adjustment, backend/model/chain settings, resampling/influence/null operation, and
rationale/source for each enabled choice.

Canonical serialization yields separate deterministic analysis-spec, preparation
receipt, universe, chain-execution, attempt, retry-equivalence, chain-cache,
universe-cache, and result identities. The
universe ID binds the ordered chain plan; chain identities bind individual seeds;
cache keys additionally bind input, code, capabilities, settings, backend,
environment, protocol, and payload/result schemas.

Held-out execution adds a stricter owner boundary. The evaluator authenticates
each complete `FrozenChainPlanDigestPreimage` v3, `AnalysisPlan/3` owner, and
`PreparationReceipt/2` owner under distinct domains with the selected private
attempt root. It recomputes the plan and receipt digests, resolves the exact
candidate ordinal and content identity, and requires the selected record to be
`PREPARED`. That record's `UniverseSpec/3` must project exactly to the frozen
plan's Plan fields, complete `UniverseIdentityPreimage`, operation seed,
registry digest, and chain rows. `HeldoutAttemptIdentityPreimage` v4 under
`ebm-audit/heldout-attempt/3` fixes the exact plan digest, while
`SealedOperationPlanDigestPreimage` v2 fixes that plan digest and the exact
receipt digest. The evaluator derives universe,
chain-execution, and attempt IDs only under their `/3` domains, requires the
plan length to equal the resolved analysis specification's chain count, and
re-derives each ordinary or matched-comparator seed from that root. Re-hashing
a replacement plan, receipt, universe, and result graph cannot substitute
another exact higher owner.

Required modes are:

- `baseline`;
- `one-axis` around baseline;
- named `declared-combinations`;
- explicitly enabled budget-limited `full-factorial`;
- `bootstrap`;
- `subsample`;
- `influence`;
- `null`; and
- `custom` supplied universes.

The default is not an uncontrolled Cartesian product. Planning reports ordinary
universe counts plus chain/bootstrap/subsample/influence/null multiplication before fitting
and enforces a configurable hard budget. The versioned default ordinary-universe
maximum is 256 unless explicitly overridden.

Statically ineligible and preparation-failed candidates remain visible with
typed reasons and `universe_id=null`. Examples include log of unhandled nonpositive values, rank-deficient
residualisation, unsupported NaNs, empty required group roles, incomparable stage
semantics, and bootstrap replicates lacking a required group. A scientific
failure is not retried with changed settings/seed. Exactly one ordinal-1 retry is
allowed only for a core-observed `PROCESS_FAILURE` at process start or crash.
It retains both attempt-specific identities and requires equality under the
separate retry-equivalence digest that removes only the two attempt coordinates.

Quick, full, and release profiles differ only in frozen budget/replicate settings,
not scientific meaning. Serial and parallel fixed-seed runs are scientifically
equivalent; every fit uses an isolated temporary workspace and capped math-library
threads.

### 10.1 Closed local audit configuration

[`../../schemas/audit-config.schema.json`](../../schemas/audit-config.schema.json)
is the closed `ebm-audit-config/0.3` mapping contract. Its strict YAML 1.2-subset
loader rejects duplicate keys, aliases/anchors, merges, tags, timestamp scalars,
non-NFC text, non-finite or unsafe numbers, unknown keys, environment
interpolation, scalar coercion, absolute paths, and parent traversal. Resolution
adds no defaults. All local paths remain in an in-memory `PrivatePathBindings`;
the persisted/public resolved projection is path-free and binds each private
choice by a domain-separated JCS digest.

The input declaration owns a complete physical `DataVariant/2` and fixes exact
file-byte SHA-256, UTF-8 CSV delimiter, quote,
header and line-ending behavior; an ordered physical type for every source
column; explicit missing and Boolean token sets; and fixed no-trim, no-locale,
no-type-inference, no-implicit-NA behavior. Column roles reuse the closed
`EventSpec`, `GroupSpec`, `CovariateSpec`, `MetadataSpec`, and ignored-column
contracts. The baseline is one complete `AnalysisSpec`. Exactly one enabled
baseline and named declarations covering baseline, one-axis,
declared-combinations, explicitly authorized full-factorial, bootstrap,
subsample, influence, null, and custom modes are required. Cross-field checks enforce unique
IDs, ordered event agreement, axis rationale/shape, and full-factorial
authorization. Every enabled ordinary variation carries declarative members with
an exact selection for every declared axis; callers never assert a composed
`AnalysisSpec` or its identity. Each axis names its baseline choice, one registered
semantic target, its complete owned `AnalysisSpec` paths, and typed assignment
values for every choice. The baseline choice must exactly reproduce those fields
from the baseline spec. The shared schema-validating
`analysis_spec_content_id` derives a deterministic content name under
`ebm-audit/analysis-spec/3`; that digest grants no compile, validate, fit, or
stage authority. Only `PlanningAuthority` can accept it into Plan/3. An enabled
full factorial enumerates the complete Cartesian selection set. Bootstrap,
subsample, influence, and null sets instead carry ordered source-analysis
references plus closed sampling/removal/transformation and source-variant bindings,
group-preservation, cohort-comparison, and refit declarations. Participant
selection is compiled later to private internal row indexes; a config has no
field for a participant identifier. Every subsample declaration explicitly owns
`sampling_design` as either `ordinary` with no stratum IDs or `stratified` with
one or more declared stratum IDs. Resolution never infers that design from the
strata list and never supplies a default.

`source_variants` is one ordered closed registry. Exactly one baseline-input row
has no parent. Every derived row names an earlier parent and one method allowed
for its variant kind, which makes the graph acyclic by construction. Bootstrap,
subsample, deterministic influence removal, and each null family bind their exact
source and derived variant rows; a string label alone is not a data-variant owner.

The baseline physical join is exact and three-way:
`input.variant.variant_id ==
baseline_analysis.dataset_variant_intent.source_variant_id ==` the unique
baseline-input source-variant ID. The AnalysisSpec intent must be the exact
four-field row-free projection of its source registry row. The root uses
`source_variant_id_ref: null` and `exact-input-bytes/1`; the input byte method is
`sha256-exact-file-bytes/1`; the physical source method is `exact-file/1`; and
`input.expected_byte_digest` exactly aliases `input.variant.source_digest`.
Verification independently compares both declarations with the retained file.
Lossless preparation copies the physical variant byte-for-byte into the dataset
catalog.

Physical variant label and provenance text are local/private. They affect the
path-free source-config and catalog/prepared identities, but never the
AnalysisSpec content name or the resolved public fields. Path relocation affects
neither public nor prepared identity.

Quick/full/release declarations are structural ceilings and replicate requests.
Config validation checks their types, 256-universe override rationale, monotonic
ordering, and consistency with enabled operation modes. It does not claim an
exact fit count. Only the compiler may expand the complete declarations, retain
invalid/unsupported candidates, calculate chain/bootstrap/subsample/influence/null
multiplication, and emit the sealed `BudgetDecision` against those ceilings. The
profile policies are exactly `error-before-execution/1` and
`error-if-exact-removal-count-exceeds-ceiling/1`: an exact fit-count or influence
removal-count overflow fails before execution. Prefix selection, truncation, or
partial-plan execution is forbidden.

`master_seed` is a required lowercase full-width `UInt64Hex` and
`seed_derivation_version` is exactly `hmac-sha256-u64be-v2` in both the public
randomness declaration and every MCMC declaration. Resolution never generates or
replaces the one declared master seed. Product seed derivation depends only on
that public reproducibility root plus one closed v2 preimage, never a global RNG,
environment state, realized row selection, or evaluator-held private root.

The path-free `AuditConfigPublicProjection` identity is
`SHA256("ebm-audit/audit-config-public/3" || NUL || JCS(projection))`; local locator
paths do not enter a public artifact or scientific identity. The public resolved
summary identity is
`SHA256("ebm-audit/resolved-audit-config/3" || NUL || JCS(projection))`.
The ordered source graph uses `ebm-audit/source-variant-registry/2`.
Packaged examples under [`../../examples/config/`](../../examples/config/) are
configuration-only: the synthetic template contains no participant rows, and the
Idris starter is explicitly structural, contains no real rows or published event
order, and requires confirmation of every local mapping and placeholder digest.

For ordinary product execution only, `ProductSeedPreimage` is this closed union in
`audit-config.schema.json`:

```text
OperationRandomizationSeedPreimage = {
  seed_preimage_schema_version, seed_derivation_version, seed_use="operation",
  operation_kind in {bootstrap, subsample, null}, experiment_set_id,
  source_analysis_spec_id, source_variant_id, derived_source_variant_id,
  replicate_ordinal, operation_parameters
}
UniverseChainSeedPreimage = {
  seed_preimage_schema_version, seed_derivation_version,
  seed_use="universe-chain", operation_kind, final analysis_spec_id,
  chain_ordinal
}
```

Decode the 16 lowercase hexadecimal `master_seed` to its exact eight big-endian
bytes. Compute
`HMAC-SHA-256(key=master_seed_bytes, message=ASCII("ebm-audit/product-seed/2") || NUL || JCS(preimage))`
and render the first eight digest bytes as a 16-character lowercase `UInt64Hex`.
The derivation version is `hmac-sha256-u64be-v2`.

Bootstrap, subsample, and null randomization happens before the derived table and
final `AnalysisSpec` exist. Its seed preimage therefore binds the experiment set,
source `AnalysisSpec`, source and already-declared derived source-variant IDs,
replicate ordinal, operation kind, and the exact typed operation parameters. It
MUST NOT contain a derived `AnalysisSpec` ID, realized rows, a transformation
manifest, or any detached field. Ordinary execution has no operation
randomization. Influence removal is deterministic from its validated removal
plan and likewise has no operation-randomization seed.

After each final `AnalysisSpec` exists and binds the realized operation, every
model chain receives a separate v2 chain seed binding that final
`analysis_spec_id`, its recomputed operation kind, and chain ordinal. This makes
the graph acyclic while keeping chain randomness distinct from operation
randomization. This public formula is not the evaluator's held-out private-root
derivation and MUST NOT be used to reproduce or replace it.

After lossless input admission, `ValidatedDatasetSummaryPreimage` is the closed
public aggregate owner for the validated dataset summary under domain
`ebm-audit/validated-dataset-summary/1`. It binds config/input/format/role and
audit-dataset digests, aggregate counts, `lossless-row-admission/1`, and
`dropped_row_count = 0`. It has no direct identifier, raw value, or private row
index field; those remain inside the private compiler boundary. Its
`canonical_dataset_digest` field is the lossless pre-plan
`AuditDatasetCatalog` digest under `ebm-audit/audit-dataset/1`, not a later
per-universe scientific-data digest. The sealed `PreparedAuditDataset` binds
the exact run authorization, source admission, audit-dataset digest, and summary
digest under `ebm-audit/prepared-audit-dataset/1`. Planning accepts that
identity-keyed capability, never the persisted public summary by itself.

## 11. Required perturbation families

The universe engine supports, when explicitly declared and valid:

- named external data variants;
- event-direction transformations;
- named group definitions and nearby justified group-rule alternatives;
- baseline feature set, leave-one-event-out, and named scientific families;
- no adjustment or reference-only linear residualisation;
- no outlier action, flag-only, fully specified IQR policy, explicit participant
  exclusion, and only independently justified transformations;
- `error` or `complete-case` missingness (`external-variant` declarations fail
  closed until a versioned physical owner is implemented);
- independent seed/chain, iterations, burn-in, thinning, proposal shuffle, and
  backend prior settings;
- stratified/ordinary bootstrap or declared subsampling, with complete refit;
- leave-one-participant-out and declared grouped removal; and
- required refitted null families.

There is no automatic feature selection or setting/threshold search to improve a
preferred order. MCMC quick/full/release profiles are calibrated on development
simulations using chain-distribution stability, transitions, runtime, and
oracle/known-truth performance, not agreement with the published Idris order.

Bootstrap stage stability uses a fixed baseline/evaluation participant set under
each bootstrap-fitted model. Duplicated in-bag rows are not compared as distinct
participants. If fixed-data staging is unsupported, participant-stage bootstrap
stability is exactly `NOT_APPLICABLE_BY_CAPABILITY` with `value=null` and reason
`STAGING.FIXED_COHORT_UNAVAILABLE`. The candidate remains `VALID`, every fit
executes, and order, position, pairwise, influence, and convergence components
continue; no in-bag or common-in-fit stage fallback is computed.

Influence refits the model after each removal and, where supported, stages the
fixed non-removed baseline cohort. It retains central-order distance, maximum
event displacement, pairwise flips, position-matrix distance, convergence/fit
change, and movement of other participants' stage distributions as separate
components.

## 12. Metric and comparison contract

Metrics are pure, independently tested functions with a small second reference
calculation where feasible. Required families are:

- normalized Kendall inversion and Spearman footrule distance;
- per-event rank shift, predeclared top-`k`, and endpoint stability;
- event position probability, expectation/median/interval/entropy;
- pairwise `P(A before B)`, chain/bootstrap/universe frequencies, and majority
  relation flips;
- expected-stage movement, MAP agreement, normalized stage movement,
  stage-posterior Wasserstein distance, optional Jensen-Shannon distance, and
  aggregate distribution movement;
- transparent decision-family grouped summaries and only design-supported
  decomposition/sensitivity indices;
- multi-component participant influence; and
- discrete-chain transition, unique-state, repeated-run, drift, cross-chain
  position/precedence, central-order, and budget-stability diagnostics.

Convergence is exactly one of `CONVERGENCE_PASS`, `CONVERGENCE_WARN`,
`CONVERGENCE_FAIL`, or `CONVERGENCE_NOT_ASSESSABLE`. Continuous-chain R-hat/ESS
is used only with a documented defensible representation. Failed or non-assessable
fits do not silently support strong language.

For different event sets, strict-order metrics restrict both orders to the common
set and disclose omitted events. Position matrices are recomputed on the common
set only from order samples; marginal position matrices alone are insufficient.
Native stages compare only with identical event sets and semantics. Each fit's
`stage/N` may be shown descriptively across different event sets only with the
exact label `SEMANTICALLY_NON_EQUIVALENT` and is never pooled with native-stage
agreement.

Decision attribution is descriptive association, not causality. A black-box
feature-importance model is not the sole explanation, and a composite confidence
or influence score is forbidden unless its components, scaling/weights,
calibration, false-positive behavior, and limitations receive separate review.

## 13. Exact oracle

The project owns an independent exact oracle for fixed event likelihoods and a
supported engineering ceiling of nine events. For
participant `j`, candidate order `S`, and stage `k`:

```text
log p(x_j | S,k)
  = sum(events in the first k positions) log p_i^1(x_ji)
  + sum(remaining events) log p_i^0(x_ji)

log p(x_j | S)
  = logsumexp_k [log pi_k + log p(x_j | S,k)]

log p(X | S) = sum_j log p(x_j | S)
```

Under an explicit prior over orders, it enumerates permutations and derives exact
best/MAP order, normalized order posterior, position probabilities, pairwise
precedence, and compatible participant-stage posteriors. It uses stable
`logsumexp`. The committed contract contains eight independently enumerated,
non-flat cases that separately detect swapped normal/abnormal states,
order-dependent likelihood, stage-prefix indexing, full order-posterior
normalization, exact best-order ties with lexicographic canonicalization,
strictly positive non-uniform stage priors, pre-oriented likelihood direction
metadata that must not be applied a second time, and extreme-log underflow.
Each fixture records every permutation's log likelihood and posterior,
position/pairwise matrices, and the canonical best-order stage posterior. The
closed schema and scientific invariant gate require exact dimensions,
probability normalization, complementary precedence, tie counts, and absolute
tolerance `1e-12`. Every stage-prior entry must be finite and strictly positive,
and the complete `N+1` vector must sum to one. Fixture likelihood arrays are
already oriented as normal-versus-abnormal evidence: event-direction metadata is
validated for alignment with configuration/data/truth elsewhere, but changing
that metadata alone must not change oracle arithmetic.

The order prior is exactly `uniform-over-all-event-permutations/1`: each of the
`N!` event-ID permutations has prior mass `1/N!`. The stage-prior input policy is
`positive-sum-within-1e-12-then-binary64-normalize/1`: all `N+1` entries must be
finite and strictly positive, the binary64 sum must be within `1e-12` of one,
and the accepted vector is divided by that sum once before use. The tolerance
therefore permits harmless serialization round-off; it does not permit an
unnormalized prior to change the evidence.

Best-order tie membership uses `binary64-exact-max-equality/1`: an order is tied
only when its versioned binary64 log likelihood is exactly equal to the observed
maximum. The `1e-12` fixture tolerance compares continuous expected outputs; it
must never promote a merely close losing order into the maximizer set. Because
permutations are enumerated in lexicographic event-ID order, the first exact
maximizer is the canonical representative.

The oracle validates ordering/staging given fixed likelihoods. It does not
validate mixture fitting. An optional `pysaebm` integration profile may compare
to it only when equivalent fixed-likelihood semantics can be exposed; otherwise
that limitation is explicit and the oracle validates canonical metrics/reference
sampling only.

The supported ceiling is nine events (`362,880` orders). The deterministic
57-participant, nine-event capacity regression enumerates the complete
posterior and checks its exact order count, normalization, position
probabilities, pairwise precedence, tie rule, and stage posterior. A dated
local runtime and peak-memory observation is retained in the project Working
Record; it is engineering evidence, not a portable CI performance guarantee or
a scientific-performance claim. Ten or more events fail closed.

## 14. Synthetic truth and scenario requirements

The transparent project-owned generator declares latent disease time/stage, true
strict order or non-identifiable structure, event thresholds/transitions,
baseline/amplitude/direction/width/noise, participant effects, correlated noise,
sampling windows/coverage, subgroup sequence, label contamination, covariates,
outliers, missingness, heavy tails/skew, and seed.

Every dataset has a machine-readable truth object recording all parameters,
seeds, latent times/stages, group mechanism, subgroup orders/proportions, injected
outliers, missingness mask/mechanism, and covariate effects. Generic event names
and explicit synthetic labels prevent confusion with the Idris cohort.

Development and held-out variants are required for:

1. easy known truth;
2. moderate approximately 57-participant/nine-event mixed-direction shape;
3. small sample;
4. noise ladder;
5. weak pre/post separation;
6. incomplete disease-time coverage;
7. tightly spaced events;
8. slow/overlapping transitions;
9. outlier sabotage;
10. MCAR missingness;
11. transparent MAR missingness;
12. correlated/duplicate events;
13. minority alternate sequence;
14. 50/50 opposing sequences;
15. near-simultaneous events;
16. covariate confounding;
17. group-boundary sensitivity;
18. control contamination/label noise;
19. heavy-tailed/skewed distributions;
20. wrong event direction;
21. pure no-signal;
22. label permutation; and
23. independent feature-wise participant permutation within analysis groups,
    with a separately named optional global variant.

Across repeated seeds, degradation SHOULD worsen known-order recovery, increase
positional/chain/bootstrap/decision uncertainty, weaken null-relative evidence,
and produce more cautious language. This is an aggregate expectation, not a
per-replicate monotonic requirement. Exact metrics/tolerances are frozen before
held-out evaluation.

## 15. Null calibration and claim separation

The complete selected pipeline, including preprocessing and model parameters, is
refitted under at least:

- group-label permutation;
- independent within-event participant permutation inside each analysis group,
  preserving group-conditional event marginals while destroying cross-event
  participant alignment; and
- synthetic pure no-signal generation.

Any stage-independent or random-order likelihood null is separately named and
justified. Candidate diagnostics may compare order/precedence concentration,
likelihood/margins, chain agreement, and non-circular stage structure to null.

The report keeps four claims distinct:

1. stable across the tested specifications;
2. internally concentrated within fitted samples;
3. stronger than the chosen refitted null diagnostics; and
4. scientifically true.

Only the first three may be reported under their frozen rules. The fourth is not
established by this product. A stable null result receives no strong signal
language.

Any rule that could emit strong null-relative support first computes a sealed
`CandidateStrongEvidenceDecision` from one observed-fit record and the exact
ordered 177 nested-null fit records: 59 replicates in each of three null
families. The six statistics, empirical p-values, null effects, failed
precondition codes, and decision state are recomputed from those raw records;
caller-supplied summaries or states are not trusted. The complete
`NullCalibrationIdentity` and subject digest bind the decision, observed fit,
and every nested fit; the identity digest is recomputed. The held-out no-signal
false-positive numerator counts those candidate decisions, before the
global calibration result or final report-label gate is known. It MUST NOT count
the gated final label, because that would make the calibration gate suppress its
own failures. The candidate decision is evaluator evidence only and is never
shown as a strong report claim. The exact 60 opportunities must match one
complete ordered sealed-case manifest and all 60 complete persisted truth
objects by natural case identity, recomputed truth digest, derived eligibility,
and candidate-decision digest/state. A reduced hash-only graph, missing, duplicate,
mismatched, ineligible, or non-assessable opportunity fails the aggregate. The
resulting false-positive rate must be no
greater than the frozen allowance. The starting proposal is 5%; the independently
reviewed benchmark contract fixes the final value before held-out results. If null
diagnostics are not validated, the report
must state exactly:

> This audit describes sensitivity across the tested choices, but it does not establish that the dataset contains a recoverable disease-order signal.

That fallback permits technical audit-layer reporting but prevents the highest
validated interpretive language until the applicable scientific gates pass.

## 16. Total baseline assessment gate

The product accepts an optional canonical reference result exported locally from
the researcher's current notebook/model. It compares every supplied supported
field, including event set/labels, central order, position samples/matrix,
participant-stage output, inclusion counts, preprocessing manifest, and
diagnostics/settings.

The total assessment statuses are:

- `BASELINE_REPRODUCED`;
- `BASELINE_PARTIALLY_REPRODUCED`;
- `BASELINE_NOT_REPRODUCED`; and
- `BASELINE_REFERENCE_NOT_SUPPLIED`; or
- `BASELINE_NOT_ASSESSABLE`.

Assignment rules are normative in `canonical-data-and-result-schema.md`.
Similarity to the publication alone can never count as reproduction. Unless
status is `BASELINE_REPRODUCED`, the report MUST stop short of interpreting the
connected worker's robustness results as an audit of the original analysis.
The assessment owner is total over the exact Plan/3 baseline candidate. After
all result terminals and the candidate-terminal index are sealed, a successful
baseline candidate must wrap the exact `VerifiedBaselineReproduction` derived
from that same `FinalizedResult`. A failed or unavailable exact baseline
candidate instead produces `BASELINE_NOT_ASSESSABLE`, carries no reproduction
identity, and is ineligible for validated report language. Caller-provided
statuses, mappings, digests, a foreign genuine assessment, or a reproduction
from another result have no authority. The assessment retains the exact
`SealedResultEvidenceSet` that issued it; report-language and future whole-run
gate consumption require that retained object to be the identical current run
set, not a sibling set with equal public content. Candidate-execution
classification is independent of baseline status and comes only from the exact
sealed result set.
The connected result is not identified by a caller label: its persisted
`result_id` is recomputed under `ebm-audit/baseline-connected-result/2` from the
complete subject, implementation, dataset, scientific-contract, and output
projection before any comparison or language eligibility is derived.

The Idris public starter contains no participant data or reconstructed values. It
lists the nine public event display names only as mapping aids and marks unknown
directions/internal columns as `REQUIRES_CONFIRMATION`. It states that group
boundaries are examples, residualisation/missingness/outlier scope are ambiguous,
ancillary MICE/PCA/GAM/LOESS is not assumed, published feature-selection wording
has an internal p-value tension, and `pysaebm` is not claimed to be the paper's
implementation.

## 17. Run and failure semantics

Every Plan/3 candidate has one immutable core-final `ResultRecord/2`. Its closed status is:

- `SUCCESS`;
- `CONVERGENCE_WARN`;
- `INVALID_INPUT`;
- `UNSUPPORTED_CAPABILITY`;
- `INVALID_SPECIFICATION`;
- `BACKEND_ERROR`;
- `TIMEOUT`;
- `CONVERGENCE_FAILED`;
- `CONVERGENCE_NOT_ASSESSABLE`;
- `PRIVACY_VIOLATION`; or
- `PROTOCOL_ERROR`.

The exact meanings, precedence, retry rule, and safe error shape are defined in
`adapter-protocol.md`. Worker responses are per-chain immutable transport
records; they are not this final status. The core maps
`CONVERGENCE_PASS/WARN/FAIL/NOT_ASSESSABLE` to
`SUCCESS/CONVERGENCE_WARN/CONVERGENCE_FAILED/CONVERGENCE_NOT_ASSESSABLE`
respectively. A zero process exit is not scientific success. Warned, invalid,
unsupported, failed, and non-assessable candidates remain in denominators,
candidate tables, failure/warning ledgers, and report sections; only final
`SUCCESS` is eligible for interpretive coverage.

A completed multi-chain result is consumed through its ordered `chain_results`
and deterministic `reference_chain` selection defined by the canonical schema.
Both `SUCCESS` and `CONVERGENCE_WARN` are descriptive completed results and
retain every exact successful chain-execution owner in plan order. Only
`SUCCESS` may supply baseline or interpretive authority. Every finalized result
also retains and revalidates the exact prepared or unprepared Plan/3 candidate
authorization that issued it; matching public IDs from another capability do
not authorize the result.
Within-fit displays and metrics use only the selected chain's within-fit payload;
chain/seed stability compares the separate chain payloads. Consumers MUST NOT
concatenate, average, or otherwise pool chain samples and then label the result
within-fit uncertainty.

Candidate-execution disposition is normatively evaluated from
[`../../schemas/cli-lifecycle-registry.json`](../../schemas/cli-lifecycle-registry.json).
The prose below is explanatory and MUST byte-for-byte agree with that registry:

- `COMPLETE`: every requested candidate has exactly one terminal result and every
  terminal is `SUCCESS`;
- `PARTIAL`: exact terminal coverage exists and at least one candidate is
  `SUCCESS`, but at least one other candidate is convergence-warned, invalid,
  unsupported, failed, timed out, convergence-failed/non-assessable, or otherwise
  non-successful;
- `FAILED`: exact terminal coverage exists and no candidate is `SUCCESS`; or
- `PRIVACY_FAILED`: at least one exact candidate terminal is
  `PRIVACY_VIOLATION`, regardless of other candidate results.

These four values classify candidate execution only. Baseline assessment owns
validated report-language eligibility and cannot change the disposition.
Benchmark, report, privacy beyond exact candidate terminals, unexpected-core,
and other whole-run gates require their own exact downstream owners. The run
remains fail closed at `MANIFEST_SEALED` until a future
`SealedRunGateDisposition` owns those facts; callers cannot substitute raw
counts, PASS defaults, report presence, or a baseline assessment.

The current deterministic report carries the separate status `INCOMPLETE`
regardless of candidate-execution success because the science and whole-run
gates are not yet closed. A future complete status requires its own exact
evidence authority; candidate `COMPLETE` or process exit `0` cannot create it.
A live `ebm-audit-report/13.0` JSON report carries the exact privacy-safe
sampling and analyst-decision layer projections separately from candidate
within-fit/chain records, participant influence, and null evidence. Its ordered
six-layer coverage ledger is validated against those named owners, including
layer digests, component coverage, accounting, and candidate status/reason
equality. Cross-layer substitution, relabelling, reordering, or digest/count
forking is a report-contract failure.
A planned candidate lacking a terminal record is a report/run abort, not a
fabricated candidate-execution disposition. Candidate execution and report
status are both serialized so CLI success is not mistaken for scientific
evidence eligibility.

The CLI uses stable exit codes:

| Code | Meaning |
| ---: | --- |
| `0` | Process success only when that command's complete gate passes. An embedded candidate-execution exit `0` means the candidates succeeded; it does not by itself make `run` exit `0`. |
| `10` | CLI usage error, invalid input, or invalid scientific specification. Malformed command usage emits the privacy-safe `SPEC.CLI_USAGE` JSON error. |
| `11` | Worker unavailable or required capability unsupported. |
| `12` | Partial audit, including the current case where candidates succeeded but the report is `INCOMPLETE` and the science gate is `BLOCKED`; inspect warning, failure, and unsupported ledgers. |
| `13` | Benchmark failed. |
| `14` | Privacy failure. |
| `15` | Fatal backend or protocol failure. |
| `16` | Unexpected core software error. |

Command-specific output always repeats the named status; scripts MUST NOT infer
status only from the numeric code.

## 18. CLI workflow and run artifacts

The current parser-supported routes, their scoped outcomes, and the exact
copyable command forms are maintained in the handoff guide's
[current command truth](../handoff/real-data-integration.md#current-command-truth)
section. That table is the command-syntax authority; this normative section
defines the outcome boundaries. Current `init` requires output, input,
worker-config, and run-root options and accepts
`--template {synthetic,idris-2025-public}`, defaulting to `synthetic`. Both routes
create installed `AuditConfig/0.3` starters. The Idris route is only the structural
public mapping aid defined above: it contains no real rows or published event
order and requires confirmation of every local mapping and placeholder digest.
Starter availability does not establish researcher-integration readiness. No
product `benchmark` subcommand is currently available.

The standalone report command is intentionally fail-closed. It returns exit
code `10` and `REPORT.V1_DISABLED` before reading `--run-dir` or touching
`--output-dir`, and it creates no report artifacts. The Python exception reason
is `PERSISTED_SCIENCE_V2_REHYDRATION_UNAVAILABLE`. The live `run` process may
write a deterministic report only while it retains the exact in-process result
evidence and matching artifact store. That report is prominently
`INCOMPLETE`, preserves every unavailable layer, and emits no final manifest.
Candidate execution and whole-audit completion are separate facts. A candidate
set may be `COMPLETE` with candidate exit `0`, but while the report is
`INCOMPLETE` and the science gate is `BLOCKED`, the `run` command is `PARTIAL`
and exits `12`. Candidate failures retain their specific `10`, `11`, `14`, or
`15` exit rather than being hidden behind the incomplete-report status.

The planned product `benchmark` command, which is not currently parser-supported,
is intended to run only the frozen public/development fixture suite. Even its
eventual `release` profile will not draw a held-out root, generate private held-out
cases, score a held-out attempt, or change an optional integration-profile
qualification. Held-out execution
is a separate evaluator-only command/control surface with no general product CLI
alias. `run` audits only the supplied local configuration and likewise cannot
mutate any optional integration-profile qualification record.

`doctor` currently emits only the top-level fields
`command_result_schema_version`, `status`, `offline`, `network_calls`,
`scientific_worker_commands_run`, `check_count`, `failure_count`, and `checks`.
Each check row has `check_id` and `status`, with optional `failure_code` and
`checked_count`. The mandatory checks cover the Python runtime, auditor package,
offline no-network posture, and package/normative resources. Optional flags add a
private-local-root write probe, configured-worker identity-checked describe, or
an optional integration-specific worker check. The receipt does not expose
private paths or worker
identity details. Core/Python version values, backend identity/environment,
writable-path detail, protocol self-test, and benchmark-contract version/hash are
required future completion fields, not current `doctor` output. `validate` never
fits. `plan` never fits and reports the baseline, multiplication/counts, invalid
combinations, measured-pilot runtime estimate, and output locations.

The current live incomplete `run` slice creates at least:

```text
run/
  run-status.json       # explicitly unsealed and incomplete
  config.resolved.yaml
  data-summary.json
  results/
  failures.jsonl
  warnings.jsonl
  evidence/
    scientific-evidence-projection.json
  report/
    report.json
    report.html
    universes.csv
```

The final accepted run contract additionally requires the append-only lifecycle,
baseline, benchmark, complete report, and last `manifest.json` described below.
The current incomplete artifact names cannot substitute for those gates.

[`../../schemas/run-artifacts.schema.json`](../../schemas/run-artifacts.schema.json)
defines the accepted append-only global sequence:

```text
RUN_CREATED -> INPUT_VALIDATED -> PLAN_SEALED -> EXECUTING
-> ALL_UNIVERSES_TERMINAL -> BASELINE_SEALED -> EVIDENCE_SEALED
-> REPORT_SEALED -> MANIFEST_SEALED
```

Each snapshot contains the exact state-history prefix and only the artifact
digests available at that phase. `planned_candidates` is the exact ordered
Plan/3 candidate key sequence. While executing, `candidate_terminals` is an exact
prefix; at `ALL_UNIVERSES_TERMINAL` and later it covers the complete candidate
sequence exactly once in ordinal order. Each row binds candidate key, nullable
universe, final status, result ID, exact result-file digest, and nullable error
evidence. The manifest digest is absent before the last transition and
is immutable afterwards. A transition may append terminal evidence or the next
state but cannot rewrite a prior transition, terminal record, identity, or
artifact digest.

At `EVIDENCE_SEALED` and later, validation requires both the exact current
`SealedResultEvidenceSet` and its identical live
`SealedCandidateExecutionDisposition`. `classify_candidate_execution` derives
requested, terminal, success, non-success, privacy, and closed terminal-status
counts only from that sealed owner graph. It accepts no caller counts, status,
baseline identity, benchmark result, mandatory-gate count, or unexpected-core
count. The disposition is opaque, non-copyable, nonserializable, revalidates
the exact sealed graph on every read, and reuses identity only while it remains
live so a dead capability cannot retain the run graph.

`VerifiedBaselineAssessment` remains a separate language-only authority. A
consumer must prove that it retains the identical sealed result-evidence set;
an absent, partial, mismatched, failed, unavailable, or foreign baseline keeps
original-analysis language locked but cannot change candidate-execution
`COMPLETE`, `PARTIAL`, `FAILED`, or `PRIVACY_FAILED`.

No `MANIFEST_SEALED` snapshot is currently accepted. Its candidate-execution
facts would have to exactly equal the opaque disposition, and its baseline
assessment would have to retain that same set, but those owners do not prove
benchmark and other whole-run gates. Final sealing therefore fails closed with
`RUN.RUN_GATE_DISPOSITION_REQUIRED` until a future exact
`SealedRunGateDisposition` owns those facts. Zero counts, a default pass,
report presence, or baseline authority cannot substitute. `BENCHMARK_FAILED`
and exit 13 remain reserved for that future gate authority; pre-plan,
incomplete-run, and unexpected-core aborts remain separate CLI abort semantics
and do not fabricate candidate-execution dispositions.

The exact packaged `ebm-audit-cli-lifecycle/4.0` registry and its exact-file
digest own the narrowed candidate-execution contract. Its ordered
`run_artifact_invariant_registry` owns eight rules: exact state-history prefix,
artifact availability, candidate-terminal coverage, exact
candidate-execution-disposition binding, fail-closed manifest run-gate
authority, registry-digest binding, manifest-last ordering, and exclusion of
private/path/participant/raw-value fields. Every row is required and binds the
`RunArtifactState` owner, enforcement kind, and whether complete
`VerifiedBaselineAssessment` authority is needed. Only the manifest run-gate
rule consumes that assessment, and only to prove exact same-set identity before
the missing run-gate authority rejects the state.

Product validation applies the closed JSON Schema first, verifies the exact
reviewed registry resource before dispatch, proves exact ordered equality
between all eight registry IDs and all eight handlers, then executes every
handler and checks its rule receipt. The manifest-last and private-field rules
are `schema-plus-runtime`: a structurally invalid early manifest or added
private field is rejected by the schema before any handler runs, while their
runtime handlers independently enforce the same rule for schema-valid owners.
Missing, extra, unknown, skipped, or reordered registry rows or handlers fail
closed. These rules do not belong to the global worker protocol registry or its
scientific-invariant dispatcher.

The exported run validator and append-only transition validator discard
rejected caller mappings and capabilities before raising a fresh fixed-message
error. There is no terminal-outcome derivation API while final run-gate
authority is absent. Unexpected exceptions, exception groups, and control-flow
subclasses are totalized without retaining their payload; only exact
`KeyboardInterrupt`, `SystemExit`, and `GeneratorExit` are recreated, with
non-integer `SystemExit` payloads replaced by exit code `1`.

The candidate-execution vocabulary is exactly
`COMPLETE | PARTIAL | FAILED | PRIVACY_FAILED`; privacy failure has first
precedence. Candidate terminal evidence can derive only
`INVALID_INPUT_OR_SPECIFICATION`, `WORKER_OR_CAPABILITY_UNAVAILABLE`, or
`BACKEND_OR_PROTOCOL_FAILURE` as a failed primary class. The closed snapshot
has no field for a local path, participant identifier, raw biomarker value, or
arbitrary backend error text.

Each universe ledger record binds universe decisions, input/config/code/backend/
environment/protocol digests, seed/chain, times/runtime, status, warnings/error,
output hashes, and cache lineage. Resuming never drops prior failures or reuses a
cache whose complete scientific identity differs.

## 19. Deterministic report and language

The HTML report is self-contained and local: no CDN, web font, remote asset,
telemetry, external JavaScript dependency, network call, or LLM. Text is selected
from a versioned deterministic rule set using exposed numerical inputs.

Required report sections are:

1. what the audit can/cannot establish;
2. dataset/specification summary;
3. preprocessing/data accounting;
4. baseline fit/diagnostics;
5. within-fit order uncertainty;
6. independent chain/seed stability;
7. sampling/bootstrap stability;
8. analysis-choice sensitivity;
9. pairwise precedence;
10. participant influence;
11. stage stability only when supported/comparable;
12. null/no-signal comparison;
13. failed/invalid/unsupported universes;
14. methods/metric definitions; and
15. provenance, worker/backend identity, integration-specific qualification when
    one exists, benchmark version, and limitations.

Where supported, visualizations separately show baseline position probability,
chain/bootstrap/decision variability, pairwise precedence, decision-family rank
shifts, multi-component influence, stage-posterior movement, null-relative
distributions, and failure counts. Uncertainty layers are not combined.
Until those visualizations and their substantive rules are completed, the live
HTML renders sampling and analyst-decision component coverage, exact attempt
and contribution rosters, numeric-record summaries, and typed pending or
unavailable states in distinct sections. It does not fill missing components
with zero-count placeholders and does not emit an overall score or combined
heatmap.

Allowed language states measured facts, for example “stable across tested
choices” or “the relative order reversed under the declared outlier policy.” The
rules prohibit or tightly restrict `proved`, `true disease sequence`, `caused`,
`will develop dementia`, clinical diagnostic claims, `clinically validated`,
`universally robust`, and claims that an influential participant is bad data.
The ordinary statistical noun “diagnostic” remains available for named
convergence, calibration, and order checks; it must not be used to say that the
auditor or an EBM output diagnoses a participant or condition.

Default reports contain no direct identifier or raw event measurement. They use
approved aggregates and pseudonymous participant aliases.

## 20. Privacy and security contract

Participant-data-time execution requires an explicit `--offline`
acknowledgement. The CLI also sets that posture before argument parsing and
exposes no online alternative, so omitting the flag is a usage error rather
than a switch to networked execution. Network/DNS/socket creation is blocked or
detected in acceptance tests. Docker/containerization, cloud accounts,
external services, and LLMs are not requirements.

The privacy boundary requires:

- internal integer worker indexes only;
- no direct ID or raw event value in default logs/reports/exceptions;
- separate, opt-in, permission-restricted reversible mapping;
- permission-restricted temporary directories and safe crash cleanup;
- file read/write and side-effect inventory;
- no unrequested input copies and only required retained artifacts;
- sanitized, bounded stdout/stderr and error details; and
- no participant data in the corpus.

Threats include command injection, path traversal/symlink escape, worker file or
network exfiltration, malicious/accidental backend output, raw-value leakage in
figures/errors, hash/cache confusion, dependency/source substitution, stale
upstream caches, and overclaiming. The security/threat model assigns controls and
tests.

The product reports technical properties only. It does not claim GDPR, NHS, KCL,
HIPAA, institutional governance, medical-device, or regulatory compliance. Local
institutional approval remains the researcher's responsibility.

## 21. Dependency and licence posture

The Python 3.12 core uses a modest, conservatively licensed, locked dependency
set and remains installable without any EBM engine. Worker dependencies have
separate exact locks and acquired-artifact hashes. The historical optional
`pysaebm` integration profile distinguishes its exact source/version/licence
evidence and does not equate PyPI `7.7.7` with source `7.7.9`; that profile is not
a product release gate.

No candidate/upstream source is copied from `pysaebm`, `kde_ebm`, `pySuStaIn`,
`pyebm`, ReduXis, or Academic Research Skills. Third-party notices are retained
for distributed artifacts, but this private build adds no project `LICENSE` and
makes no legal-compliance conclusion.

## 22. Specification and benchmark freeze gate

Before substantive optimization, a fresh read-only Sol reviewer in the trusted
local environment attacks the complete spec/benchmark candidate for scientific
circularity, benchmark leakage, invalid nulls, order/stage semantics, missing-
data leakage, unsupported claims, privacy failure, backend coupling, false
reproducibility, licence assumptions, and scope expansion.

Every P0/P1 is resolved before freeze. Each P2 is resolved or explicitly deferred
with rationale. Findings and dispositions are recorded locally. No project
content is sent to an external model/provider.

The D04 file freeze and later held-out execution authorization are different
states. D04 freezes the exact reviewed scientific rules, source identities,
failed 54-fit characterization disposition, untouched-held-out state, and
domain-separated contract self-hash. It does not select a backend, freeze a
candidate, authorize a held-out draw, or claim readiness.

The later machine execution gate is stricter. Its required predicate set is
exactly `freeze_requirements.required_predicates` in the benchmark contract and
the 28-row protocol registry. A self-hash is never enough for that later gate:
the evaluator must resolve every complete typed owner, re-execute or rederive
the registered predicate, and obtain PASS. `WARN`, `UNVERIFIED`,
`NOT_APPLICABLE_BY_CAPABILITY`, missing, duplicate, extra, digest-only, or
caller-constructed evidence prevents held-out authorization. Its production
resolver remains unimplemented, so `BenchmarkFreezeReceipt/3` remains
structurally blocked without preventing the earlier subject-neutral D04 file
freeze.

### 22.1 Historical named-backend profile evidence

The remainder of Section 22 through Section 23 records the earlier named-backend
profile and its exact evidence mechanics. It is historical evidence, not the
current product sequence, candidate-freeze route, release gate, or readiness
authority. A researcher may reuse suitable parts only as an optional downstream
per-integration profile after connecting an EBM through the generic worker. It
cannot qualify the conformance EBM, substitute for full- or partial-capability
conformance, or block the readiness state in `ebm-integration-readiness.md`.

The historical pre-freeze sequence was:

1. complete this specification set, benchmark candidate, ADRs, and independent
   review;
2. implement only the minimal canonical schemas, generic protocol, fixture and
   custom-worker path, privacy-safe bundles, and contract tests needed to test the
   contract;
3. implement and characterize the isolated, unmodified exact-source reference
   worker while retaining `EXPERIMENTAL` status;
4. implement the exact oracle, hand tests, minimal owned generator/truth object,
   reference metrics, and pilot harness;
5. run the predeclared signal-only compute-budget characterization at 2,000,
   5,000, and 10,000 iterations with multiple chains; and
6. independently review the resulting quantitative thresholds.

`ProfileCharacterizationPlanReceipt/3` fixes only the executable intent for
that pilot. It names the two public development groups
(`easy_known_truth/profile-pilot` and
`moderate_mina_shape/profile-pilot-57x9`), replicates `0..2`, three complete
`AnalysisSpec` owners for the exact 2,000/400/10, 5,000/1,000/10, and
10,000/2,000/10 iteration/burn-in/thinning budgets, and three distinct
`EXPERIMENTAL` subjects. For each coordinate it also binds the exact synthetic
`E01` through `E09` truth IDs, resolver-owned truth directions and float64
centers, and the deterministic `e01` through `e09` AnalysisSpec IDs with their
separately resolver-owned analysis directions under
`synthetic-e-id-lowercase-machine-id/1`. It fixes six deterministic budget rotations, fresh
independent serial fits, no cache or checkpoint reads or writes, no retries,
and 18 logical case-chain slots. The separate profile executor must not inherit
the ordinary runner's transient retry allowance. The six signal datasets,
three budgets, and three chains produce exactly 18 universes and 54 chain
executions. Transition review reuses these same 54 fit results and does not
authorize another fit matrix. The exact direct relation
order is 18 `5k -> 10k`, 18 `2k -> 10k`, then 18 `2k -> 5k`; no transitive
comparison is allowed. The plan also fixes 54 runtime rows, 54 transition
rows, 18 convergence classifications, 54 within-budget cross-chain
observations per distance family, 54 same-chain cross-budget observations per
family, 54 paired runtime ratios, nine observations per easy metric, and nine
observations per moderate descriptive metric. The distance families are
central-order Kendall, position matrix, and pairwise-precedence matrix. The
easy metrics are truth Kendall and stage MAE; the moderate metrics are
single-side fixed-reference alignment, which is descriptive only, and stage
MAE. No comparator dataset, matched-null delta, randomization p-value, or
moderate scientific decision belongs to this pilot.

The Plan retains complete declared provenance for the generator, metric rules,
report-language rules, evaluator source, and governing build prompt. These five
source-set identities are Plan content with state
`DECLARED_PRE_EXECUTION_NOT_ATTESTED`; they do not force scientifically
equivalent fits to run again. The candidate-independent
`ProfileExecutionIdentity/1` instead binds only fit-sensitive public authority,
the ordered coordinate/event-binding and AnalysisSpec identities, backend and
environment, requested outputs, canonicalization, chain count, execution and
observation policy, the narrow execution-source manifest digest, and worker
invocation semantics. It excludes the candidate, contract, selection policy,
and the five broad source sets.

The narrow `ProfileExecutionSourceManifest/1` has exactly six ordered roles:
generation, preparation, seed, request-execution, capture, and
metric-calculation. The Plan validates and hashes the declared manifest, but it
does not inspect or attest a candidate tree. Before any fit, a trusted executor
must derive every entry from the exact candidate tree and match it. Worker
invocation semantics bind the exact `WorkerCommand.argv` token vector and
normalized timeout; a change to either changes execution identity.

Transition quality is an explicit but not-yet-reviewed selection component.
The plan state is `PENDING_INDEPENDENT_TRANSITION_RULE_REVIEW`, with
pre-review outcome `NO_SELECTION`; it does not contain invented transition
tolerances or a claimed `PASS`. A future versioned machine-executable
independent decision owner must cover transition rate, unique-state fraction,
maximum repeated-state fraction, and endpoint/zero-transition evidence. It must
fix direction, per-metric aggregation, tolerance, endpoint/zero rules, complete
denominators, exact plan/evidence/subject binding, and no preferred-central-order
targeting.

The profile-only `AnalysisSpec` refinement closes nested `backend.settings` to
exactly `raw_iterations`, `burn_in`, `thinning`, `n_shuffle`, `prior_n`, and
`prior_v`. It also requires the exact canonical output sequence
`central_order`, `order_samples`, `accepted_transition_diagnostics`,
`position_probabilities`, `pairwise_precedence`,
`fitted_event_distributions`, `evaluation_stage_posterior`,
`evaluation_hard_stages`, and `evaluation_expected_stage`; generic
`AnalysisSpec/3` remains unchanged. The live selected pysaebm subject supports
fixed evaluation-cohort staging. Stage MAE uses the exact generated fixed
evaluation-cohort rows bound to `THRESHOLD_STAGE` truth; stage-axis
incompatibility is `NOT_ASSESSABLE` and permits no selection. Central-order
only, training-stage substitution, evaluation-stage omission, or
`likelihood_trace` substitution fails. The plan also carries one complete
`BackendIdentity` and its recomputed digest. Every experimental subject must
exactly match that identity and every overlapping `AnalysisSpec` backend fact,
including adapter, backend/source, algorithm, capabilities, settings, and the
canonically recomputed requested-output digest.

The plan deliberately contains no generated dataset, final seed, universe,
chain, attempt, result, convergence, runtime, resource, metric, comparison,
qualification, selection, release-subject, or freeze-eligibility value. Its
public seed policy says only that the live executor must derive seeds after it
has the fixed execution identity and authenticated coordinate-specific
synthetic-event binding; callers supply no seed material. The public seed
preimage is exactly the execution-identity digest, event-binding digest, and
`chain_id`. Candidate and budget are excluded, so all three budgets reuse the
same seed for one coordinate and chain. The retained pySaEBM characterization
executed all 54 planned fits through the fixed profile route. Its historical
`BlockedProfileDiagnostic/2` describes only the earlier pre-execution state and
has no authority over that later evidence. The exact six-case public authority
and authenticated plan issuer exist in this contract slice.

The rejected `ProfileCharacterizationReceipt/2` draft mixed that fixed intent
with caller-shaped result and decision fields and was never issued. The D04
subject-neutral contract-file freeze does not depend on backend qualification
or an accepted profile evidence receipt. A future product-owned, opaque
`ProfileCharacterizationEvidenceReceipt/3` is still required before any backend
selection; it must bind the plan to authenticated live case, chain, result,
metric, aggregation, comparison, and decision owners. No caller-mapping
validator is defined for that future receipt. Release is 10k
only when its complete required evidence is `CONVERGENCE_PASS`; otherwise
there is no selection. It also requires
`REVIEWED_TRANSITION_QUALITY_PASS`; failed or unreviewed 10k yields no
selection. Full is 5k only when direct `5k -> 10k` passes. Quick is 2k only
when 5k qualified and both direct `2k -> 10k` and `2k -> 5k` pass. Every direct
relation requires complete convergence evidence, its own reviewed
transition-quality pass, median distance `<= 0.10` and maximum distance
`<= 0.20` separately in all three distance families, and the non-inferential
paired development safeguards.

Runtime is computed as exactly 18 matched candidate/reference ratios per
relation, keyed by family, scenario, replicate, and chain. Each ratio is
candidate terminal core-observed runtime divided by strictly positive
reference terminal core-observed runtime; both must be complete and finite.
Sort the ratios and use non-interpolating inverse-empirical-CDF `Q(0.5)`, the
ninth one-based value. It passes strictly below `1` with tolerance `0`;
equality or any invalid observation fails the relation. This is the median of
paired ratios, not the ratio of separate medians. There are no p-values or
adaptive extra replicates. Missing, pending, `WARN`, `FAIL`,
`NOT_ASSESSABLE`, borderline, incomplete, or unreviewed evidence defaults
upward, except failed or unreviewed 10k yields no selection. The current
pre-review plan therefore selects nothing.

The profile pilot does not replace the later moderate development gate. That
separate backend/candidate qualification gate runs only after the
subject-neutral Milestone 4 contract freeze. It has exactly eight atomic
signal/null pairs, 16 universes, three chains per universe, and 48 fits, with
the exact paired sign-flip, alignment, stage-error, completeness, and
convergence rules frozen in the metrics contract. None of those universes or
fits is included in the profile counts, and it is not a prerequisite for the
subject-neutral freeze.

Complete the **Milestone 4 scientific benchmark freeze**:

1. canonicalize `evaluator/benchmark_contract.yaml`;
2. record version, SHA-256, date, generator/code identity, and rationale;
3. freeze the generator, development/held-out scenario definitions, metric rules,
   and report-language rules; and
4. retain the held-out manifest as an undrawn template.

`BenchmarkFreezeReceipt` is subject-neutral: neither it nor its generic
predicate owners contains a candidate or `benchmark_subject_digest`. Benchmark
freeze therefore does not freeze an unfinished implementation and does not draw
or run held-out cases. Milestones 5 through 7 then build and adversarially validate
the complete audit engine, CLI, report, starters, and privacy boundary using
development evidence only. At **Milestone 8**, freeze a clean implementation
candidate, record its Git commit as provenance separately from its SHA-256
candidate-tree identity, bind one exact genuine-real-backend `EXPERIMENTAL`
`BenchmarkSubjectIdentity`, and only then issue a future decisive candidate
freeze after rederiving the PASS qualification from authoritative evidence.
The state transition must be a real durable compare-and-set with operation
identity, expected before revision/digest, no-overwrite semantics, after
revision/digest, and durable readback before its receipt is recorded. The
current `CandidateFreezeReceipt/3` and
`AcceptanceCandidateTransitionReceipt/2` are typed blocked records:
`candidate_frozen=false`, `transition_applied=false`, and the subject remains
`EXPERIMENTAL`. They cannot authorize a root draw. After the real authorities
exist, store the commitment before case generation and execute held-out once. If an
implementation defect changes the candidate, preserve the failed attempt and use
a new candidate with fresh held-out seeds.

Before `CandidateFreezeReceipt`, the distinct pre-candidate qualification gate
requires a future qualification-only development assessment over the exact
ordered 23-family set for the final candidate under an `EXPERIMENTAL` subject.
The present `DevelopmentScenarioEvaluationReceipt/3` is schema-impossible
because its family `RuleOutcome` type is rooted in held-out score evidence.
`PreCandidateQualificationReceipt/2` therefore records only an unresolved
development reference and always blocks. The required current causal order is
`benchmark freeze <= blocked qualification <= blocked candidate freeze <
blocked acceptance transition <= ROOT_NOT_DRAWN diagnostic`; neither a
held-out attempt nor a root receipt exists in that path. If the
final candidate, subject, contract, backend, environment, capabilities,
settings, profile, or calibration route changes, final development calibration
and this gate run again before held-out strong-label eligibility.

The exact canonical bytes, self-hash exclusions, candidate-tree manifest, and
commitment ordering are normative in `artifact-hashing-and-freeze.md`.

Held-out acceptance has four ordered stages. First, the evaluator resolves and
authenticates the closed `ScoreEvidenceBundle` and its exact file tree. Second,
it derives the `EvaluationReceipt`, `ScoreReceipt`, rule vector, and gate vector
for the bound `ACCEPTANCE_CANDIDATE` without reading a prior `ACCEPTED` state.
Third, a fresh validation of that same root authenticates one
`ScoreValidationReceipt`, binding the root, source registry, evaluation, score,
gate vector, aggregate branch, fixed offline commands, and one terminal
timestamp. Only then may the fourth stage atomically compare-and-transition that
same subject: validated `PASS` selects `ACCEPTED`; validated `WARN` or `FAIL`
selects `REJECTED`. A typed `ScoreValidationFailureRecord` from one of the three
registered UNIMPLEMENTED semantic/source gates authorizes no acceptance receipt
or state transition. Other malformed, missing, substituted, or incomplete
inputs also fail closed before transition, without a current guarantee that
every pre-handler error produces that typed artifact. A result from one backend,
worker wrapper, environment, capability set, settings profile, or candidate
cannot accept another. In that historical profile, the generic custom-worker
route remained a separate completion condition and did not substitute for the
named integration subject.

Every sealed held-out `ResultRecord` also stores
`subject_acceptance_state_at_evaluation: ACCEPTANCE_CANDIDATE`. This is immutable
historical evidence of the state under which the result was produced; it is not
rewritten after the atomic transition. The score receipt records the same state,
while the backend-acceptance receipt separately records the compare-from and
terminal states.

Thresholds are not weakened after held-out failure. A scientific change uses a
new contract version and ADR.

Proposed development thresholds from the build prompt (including easy-truth
median normalized Kendall agreement at least 0.90 and null strong-support false-
positive rate at most 5%) are proposals until review/freeze. Exact equality/
tolerance applies to deterministic oracle cases. Stage error, lower-tail,
moderate-case, influence, stochastic, and runtime/memory tolerances must be fixed
in the benchmark contract before held-out evaluation.

## 23. Historical named-backend qualification profile

This section is part of the historical/optional profile boundary declared in
Section 22.1. Its qualification vocabulary is not product readiness, does not
select a product backend, and is not required for ordinary generic-worker
integrations. Within that profile, architectural selection, worker-response
status, capability applicability, and empirical qualification were separate
vocabularies. Profile states were exactly `NOT_EVALUATED`, `EXPERIMENTAL`,
`ACCEPTANCE_CANDIDATE`, `ACCEPTED`, and `REJECTED`; they were never
worker-response statuses. `pysaebm` begins
`EXPERIMENTAL`, may enter `ACCEPTANCE_CANDIDATE` only after its exact subject is
closed, and reaches `ACCEPTED` only through the atomic post-score transition.
That transition requires:

- exact source/version/licence and clean locked environment;
- deterministic same-seed results and distinct-seed no-cache behavior;
- row, feature-column/event-label, and participant-remapping invariance;
- valid permutations/posteriors and no silent row/event/cell loss;
- fail-before-backend behavior for unsupported NaNs;
- contained/inventoried side effects, visible warnings, and offline/no-network;
- exact-oracle comparison where equivalent fixed likelihoods exist;
- frozen easy/moderate known-truth gates;
- assessable passing multi-chain rules;
- null calibration that blocks unjustified signal language;
- fresh locked-environment end-to-end synthetic operation on every claimed
  platform; and
- a passing held-out receipt whose `benchmark_subject_digest` exactly matches
  the backend/worker/environment/capabilities/settings identity being accepted;
  and
- an authenticated `ScoreValidationReceipt` that binds the exact score-evidence
  root, source registry, evaluation receipt, score receipt, applicable gate
  vector, aggregate branch, and fixed workflow provenance used by acceptance.

Only owned wrapper/protocol/integration defects may be fixed to pass. An upstream
scientific failure is reported; the algorithm is not patched or tuned. A subject
that is not yet submitted remains `EXPERIMENTAL`; a scored `WARN` or `FAIL`
becomes `REJECTED` atomically with its acceptance receipt. The core, fixture
worker, custom-worker route, simulator, oracle, and report continue separately.

The held-out score is itself an owner-derivation gate. It resolves one
evaluator-selected, private-root-authenticated `ScoreEvidenceBundle`, verifies
its exact repository tree and ordered source-validation registry, and derives
the registered mandatory-rule and backend-gate sets from those sources. Each
non-baseline aggregate evidence digest is the closed
`ScoreAggregateEvidenceDigestPreimage`: exact score root, exact source-registry
digest, aggregate kind, and registered rule or gate ID. There is no second
typed-owner representation. The baseline gate still derives only from the
complete baseline-reproduction record. A caller may recompute ordinary hashes,
but cannot swap a file, source meaning, aggregate kind, or ID without changing
the authenticated root or closed aggregate digest. Missing, extra, reordered,
detached, caller-selected, rewritten, or arbitrarily re-identified evidence
fails before aggregate `PASS`/`WARN`/`FAIL` is accepted.

Structural identity is necessary but is not scientific validation. At this
pre-product boundary, all five execution-semantic branches, all 104 scenario
derivation validators, and 100 of 101 score-source validators remain explicitly
`UNIMPLEMENTED`. Those registered boundaries emit a typed validation-failure
record and stop before evaluation, score, validation, acceptance, or CAS output.
The downstream score-validation and acceptance code is scaffolding until those
owners and semantic handlers are implemented. Once reachable, acceptance
revalidates the exact score root and requires its authenticated
`ScoreValidationReceipt` before entering the one no-overwrite hard-link
transaction; it never scores and accepts in one unowned step.

Another optional named-integration profile requires its own reviewed profile and
the same protocol/isolation/licence rules. An ordinary researcher integration
through the generic worker does not require backend selection or a new SDK.

## 24. Hard release failures

Regardless of aggregate benchmark score, release readiness fails if any occurs:

1. silent participant, event, or cell modification;
2. unexplained same-seed nondeterminism;
3. row order changes scientific meaning;
4. feature labels misalign under column reordering;
5. failed, invalid, unsupported, or non-assessable universes disappear;
6. upstream cache contamination;
7. exact-oracle material disagreement without a surfaced failure;
8. unjustified strong support on null data;
9. systematic invisibility of injected influential observations;
10. convergence failure contributes as valid evidence;
11. baseline reproduction is marked passed without a supplied adequate reference;
12. raw direct identifiers or raw event values appear in default artifacts;
13. runtime attempts network access in offline mode;
14. warnings are globally suppressed;
15. provenance cannot identify data/config/code/backend/environment/seed, and
    synthetic conformance input cannot link deterministic project-owned generator
    identity/hash to its complete known-truth record;
16. report language makes diagnosis, prognosis, treatment, causal, regulatory, or
    medical-device claims;
17. fresh locked-environment install/run fails; or
18. an unresolved P0/P1 independent-review finding remains.

A privacy hard failure yields `PRIVACY_FAILED` and exit 14 even if other checks
pass. Failed capabilities or unverified checks remain explicit; they never become
aggregate success through omission.

## 25. Readiness mapping

ADR-0014 establishes one readiness state and one allowed readiness label:

### `READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY`

The normative conditions are in `ebm-integration-readiness.md`. They require the
complete generic integration surface, a transparent project-owned
`SYNTHETIC-ONLY` conformance EBM through the ordinary subprocess protocol, honest
full- and partial-capability behavior, the unchanged scientific and safety
gates, the held-out synthetic proof, independent remediation, a deterministic
usable report, and a clean offline researcher simulation requiring no developer
intervention.

This is a product and integration claim, not scientific acceptance of a public,
private, or future EBM. Missing checks remain explicitly `UNAVAILABLE` or
`NOT_APPLICABLE` and never become pass or fail. Every real integration retains
its own identity, capability, baseline-reproduction, validation, and
interpretation burden. The conformance EBM fails closed on non-synthetic input
and cannot be used as a research backend or silent fallback.

Before the complete condition passes, the task records readiness as unsatisfied,
names each exact gap, and emits no final readiness report. Partial
implementation, an experimental backend, a conformance receipt alone, a test
count, or an emitted order cannot substitute. Participant-level data are neither
required nor permitted during development or readiness validation.

## 26. Verification matrix and definition of done

Release evidence must include exact commands, environment/commit/contract hashes,
test counts, warnings/failures, and `UNVERIFIED` checks for:

- canonical serialization, schema validation, direction transforms,
  residualisation/leakage, outlier/missingness accounting, aliases, cache keys,
  and input immutability;
- all 18 closed scientific-invariant dispatch algorithms and all 46 registered
  negative counterexamples, with every owned schema hook registered and mapped
  to an executable rejecting mutation;
- pure order/position/precedence/stage/null/influence metrics and tiny exact-
  oracle cases;
- row, ID, and feature-column/remapping properties; matrix/posterior invariants;
  serial/parallel equivalence;
- every protocol status, capability truthfulness, timeout/crash/file inventory,
  same/different seed behavior, no-cache, and no-network;
- easy/moderate truth, degradation ladders, opposing-sequence non-identifiability,
  wrong direction, influence sabotage, complete-case accounting, stage/event-set
  safeguards, and null false-positive behavior;
- all 23 family-scoped scenario predicates against exact planned/valid case-ID
  coverage. The complete family-scoped evidence object is schema-validated
  before predicate dispatch, every case-indexed vector must have exactly the
  valid-case cardinality, and the machine predicate embedded in each human rule
  must equal the canonical registry row. Empty evidence, wrong subtype,
  non-finite evidence, `NOT_ASSESSABLE`, a wrong truth-scoring mode, and
  false-precision evidence are adversarial failures;
- baseline, chains, bootstrap, one-axis choices, influence, null, cache resume,
  deterministic report, and machine-readable output in end-to-end tests;
- privacy scanning for IDs/raw values, restrictive temp/mapping permissions,
  sanitized exceptions, worker integer indexes, and offline operation; and
- fresh locked-environment synthetic install/run plus one committed held-out
  release evaluation.

Completion also requires a practical no-upload handoff guide: install core and
worker, map columns locally, confirm directions/groups, validate without fitting,
optionally export baseline reference, run doctor/synthetic test, inspect accounting,
run baseline reproduction, run quick then full audit, and review interpretation
with the domain/supervisory team.

The custom-worker handoff contains both a standalone executable template and a
trusted-local-Python helper. The helper runs **inside the researcher's worker
process** to read/write protocol objects; it is never an in-process plugin imported
by `ebm_audit`. The baseline handoff includes a versioned reference template and
export/validation command so reproduction evidence is not assembled ad hoc.

## 27. Intentionally pending values, not product ambiguities

The following are decided by independent review and development-only calibration,
then fixed in the benchmark contract before held-out evaluation:

- exact oracle event-count ceiling measured on supported hardware;
- quick/full/release iteration, burn-in, thinning, chain, bootstrap, influence,
  and null-replicate budgets;
- convergence pass/warn/fail thresholds for discrete permutation chains;
- easy-truth lower-tail, stage-error, moderate-case, influence-rank, and tolerated
  stochastic-variation thresholds;
- final strong-null-support false-positive allowance (proposal: 5%); and
- runtime/memory reporting limits rather than scientific shortcuts.

These pending numerical values do not authorize changing the product boundary,
truth semantics, null families, privacy rules, hard failures, or readiness
requirements.
