# Deterministic report-language rules

Status: `FROZEN`
Rule-set ID: `report-language/v0.1.0`

Production reports are rendered from versioned templates and canonical numerical/status fields. No LLM, external API, remote asset, or improvised model prose is used. User-supplied notes are escaped, visibly labelled `USER-SUPPLIED CONTEXT`, and never interpolated into a product conclusion.

## 1. Four claims that never collapse

The report keeps these statements independent:

1. `specification_stability`: behavior across the tested, predeclared analysis choices;
2. `within_fit_concentration`: concentration of the fitted order samples inside a fit;
3. `null_relative_status`: comparison with the chosen refitted null diagnostics;
4. scientific truth.

The first three have deterministic labels below. The fourth is never emitted by this product. A stable or concentrated output can occur on null data.

## 2. Independent state computation and display precedence

`within_fit_concentration`, `specification_stability`, influence, and
`null_relative_status` are computed as separate pure states from their own
declared inputs. No state is supplied as an input to another unless an exact rule
below says so. In particular, null calibration, null-family coverage, null
identity, and null-relative authorization never change or suppress the computed
within-fit state.

After those states are sealed, report eligibility is evaluated in this order:

1. privacy/protocol/data-integrity hard failures;
2. baseline-reproduction gate;
3. planned-versus-terminal universe accounting;
4. convergence eligibility;
5. metric comparability, including event/stage semantics;
6. within-fit concentration;
7. specification stability;
8. influence;
9. null-relative eligibility and calibrated result;
10. readiness summary.

A higher-precedence failure cannot be overridden by a lower-precedence metric.
This precedence controls report disposition; it MUST NOT rewrite an independently
computed state to `NOT_ASSESSABLE`. Raw metric tables and their exact states
remain available even when a hard-failure page suppresses ordinary rendering.

## 3. Mandatory opening statement

Every report begins with this exact text:

> This audit measures how a cross-sectional event-based model behaves across the declared data, modelling, resampling, influence, and no-signal checks. It does not establish a true biological sequence, diagnosis, prognosis, treatment effect, causal mechanism, or time to an event.

## 4. Baseline reproduction labels

The only labels are:

- `BASELINE_REPRODUCED`
- `BASELINE_PARTIALLY_REPRODUCED`
- `BASELINE_NOT_REPRODUCED`
- `BASELINE_REFERENCE_NOT_SUPPLIED`

`BASELINE_REPRODUCED` requires the supplied canonical reference bundle and every frozen required comparison to pass. It is never inferred from similarity to a publication figure or event order.

Before validated report language is selected, the baseline owner
re-derives and validates the complete self-hashed `BaselineReproductionRecord`
from its connected result and any supplied canonical reference. A supplied
reference also requires its exact private alignment artifact; the owner
recomputes the row-order and artifact digests and checks the dataset, manifest,
and export-receipt bindings. Only that complete check produces the privacy-safe
verified-baseline capability consumed by the report-language path.
The later total `VerifiedBaselineAssessment` retains the exact
`SealedResultEvidenceSet` that issued it. Report-language and future whole-run
gate consumers accept it only when that retained set is the identical current
run set and its exact preparation transaction, ordered candidate
authorizations, terminal/index owners, and baseline result/status all
revalidate. A same-content assessment or sealed set from another genuine run
cannot unlock report language. Candidate-execution classification is derived
separately and solely from that run's opaque sealed result evidence; baseline
status cannot promote or demote it. Current `MANIFEST_SEALED` validation fails
closed until a distinct exact run-gate disposition exists.

`validated_language_eligibility=true` if and only if the verified record's
derived status is `BASELINE_REPRODUCED`; the other three statuses require it to
be false. The score's `baseline-reproduction` gate must carry that exact record
identity and the same reason vector. A standalone status string, central-order
match, caller-supplied eligibility boolean, or detached alignment digest cannot
unlock validated-language templates. An absent, partial, or mismatched optional
reference locks this language but does not by itself turn an otherwise complete
audit execution into a failed execution.

If the status is not `BASELINE_REPRODUCED`, the report says:

> This run has not fully reproduced a supplied canonical baseline from the original analysis. The results below describe this connected model and configuration; they must not be interpreted as a robustness audit of the original analysis.

## 5. Completion and evidence eligibility

| Label | Deterministic condition |
|---|---|
| `AUDIT_INVALID` | A hard failure occurred **or** at least one planned universe lacks exactly one terminal record. Evaluated first. |
| `NO_VALID_UNIVERSES` | Not invalid, every planned universe has one terminal record, and no universe is eligible for scientific comparison. Evaluated second. |
| `AUDIT_COMPLETE` | Not invalid, at least one universe is eligible, and every required experiment set reached its frozen minimum valid coverage. Evaluated third. |
| `AUDIT_PARTIAL` | Not invalid, at least one universe is eligible, and one or more required experiment sets missed valid coverage. This is the residual state. |

The report always gives planned, valid, invalid, unsupported, failed,
convergence-warn, convergence-failed, convergence-not-assessable, and
missing-terminal counts. The ordered evaluation above is total and mutually
exclusive; a planned universe without exactly one terminal record is
`AUDIT_INVALID`, not `AUDIT_PARTIAL`.

Only core-final `ResultRecord.status=SUCCESS` (the closed result of
`CONVERGENCE_PASS`) with valid comparison semantics enters interpretive
aggregates. `CONVERGENCE_WARN` is its own terminal core-final status; it is
descriptive only and counts as unavailable coverage for CLI/report completion.
Other records remain visible in denominators and failure sections.

## 6. Convergence language

Use the exact assessment labels and serialize the corresponding core-final
status. The mapping is `PASS -> SUCCESS`, `WARN -> CONVERGENCE_WARN`, `FAIL ->
CONVERGENCE_FAILED`, and `NOT_ASSESSABLE -> CONVERGENCE_NOT_ASSESSABLE`:

- `CONVERGENCE_PASS`: “The predeclared convergence checks passed for this fit.”
- `CONVERGENCE_WARN`: “The fit completed, but one or more convergence checks warned. Its metrics are descriptive only and do not contribute to interpretive robustness labels.”
- `CONVERGENCE_FAIL`: “The convergence checks failed. This fit is shown as a failure and does not contribute evidence to robustness labels.”
- `CONVERGENCE_NOT_ASSESSABLE`: “Convergence could not be assessed with the outputs or replication available. This fit does not support strong interpretive language.”

Counts use a literal template, for example: “Convergence could not be assessed for 12 of 48 planned universes.”

## 7. Within-fit concentration labels

Numeric boundaries are frozen after development characterization and independent review.
Evaluate only within-fit sample validity, convergence, and within-fit coverage;
then use the ordered conditions below:

- `WITHIN_FIT_NOT_ASSESSABLE`: order samples or valid position probabilities are unavailable, convergence is not `CONVERGENCE_PASS`, or frozen minimum sample coverage is absent.
- `INTERNALLY_DIFFUSE`: mean normalized position entropy `>= 0.65` or at least 50% of pairwise probabilities inside `[0.40, 0.60]`, with assessable valid samples.
- `INTERNALLY_CONCENTRATED`: not diffuse, mean normalized position entropy `<= 0.35`, at least 80% of pairwise probabilities outside `[0.25, 0.75]`, and convergence `CONVERGENCE_PASS`.
- `INTERNALLY_MIXED`: assessable but neither concentrated nor diffuse.

Null calibration state, null-family completion, empirical null results, and
report authorization are prohibited inputs to this classifier. An integrity
failure outside the within-fit samples may change the enclosing audit/report
disposition but MUST NOT mutate the sealed concentration state. An invalid or
non-finite within-fit order sample is instead a direct within-fit precondition
failure and yields `WITHIN_FIT_NOT_ASSESSABLE` with its reason.

Allowed template:

> The fitted order samples were internally concentrated under the frozen rule. This describes the fitted samples; it is not evidence that the order is scientifically true or stronger than no-signal behavior.

Status of boundaries: `FROZEN_REVIEWED`.

## 8. Specification-stability labels

Only predeclared comparable ordinary/`analyst_decision` universes are used. Bootstrap, `participant_influence`, and null fits are not specification universes. Evaluate the following in order so the state is total and mutually exclusive:

- `SPECIFICATION_STABILITY_NOT_ASSESSABLE` applies when comparable valid coverage is below 80%, fewer than two valid comparable specifications exist, or the baseline is ineligible.
- `SENSITIVE_TO_TESTED_SPECIFICATIONS` applies, after assessability passes, when a declared decision family has median Kendall distance `>= 0.25`, a baseline pair with probability at least `0.75` flips to the opposing majority in at least 25% of valid alternatives, or a selected event's median normalized shift is `>= 0.30`.
- `STABLE_ACROSS_TESTED_SPECIFICATIONS` applies only when sensitivity did not trigger and median baseline Kendall agreement `>= 0.85`, 10th percentile `>= 0.70`, maximum decision-family median normalized event shift `<= 0.20`, and overall strict pairwise-majority flip rate `<= 0.10`.
- `MIXED_SPECIFICATION_STABILITY` is the remaining assessable state.

Status of boundaries: `FROZEN_REVIEWED`. The stable template is always bounded:

> The order was stable across the tested specifications under the frozen numerical rule. This statement applies only to the declared choices and does not establish null-relative support or scientific truth.

For sensitivity:

> The result was sensitive to the tested specifications. The report identifies the declared choices associated with the movement; it does not claim those choices caused a biological change.

## 9. Pairwise and event language

Allowed deterministic templates include:

- “Event `{event}` remained in the first `{k}` positions in `{percent}` of `{valid}/{planned}` comparable tested specifications.”
- “The relative order of `{event_a}` and `{event_b}` reversed under `{decision_family}` in `{count}/{denominator}` valid comparisons.”
- “`{event}` moved by a median of `{positions}` positions under the declared `{decision_family}` alternatives.”

When event sets differ, append:

> Order distance was calculated on `{common_count}` common events. Added and omitted events are listed; native stages were not treated as equivalent.

No template describes a marginal 0.5 crossing as decisive without displaying both probabilities.

## 10. Stage language

When stage semantics and fixed evaluation cohort are identical:

> Expected stage changed by a median of `{median}` of `{N}` stage intervals across `{valid}` comparable fits; posterior-distribution movement is shown separately.

For an ordinary non-sampling descriptive comparison whose cohort was selected
separately by each fit:

> Stage comparison used participants common to the fitted cohorts and is labelled `SELECTION_COUPLED`; participant selection and model movement cannot be separated.

This template is prohibited for bootstrap and subsample stage stability. Each
sampling refit requires the same predeclared fixed original evaluation cohort;
in-bag bootstrap rows, retained-subsample-only rows, training stages, and
order-derived fallbacks are prohibited. Bootstrap and subsample families remain
separate and no across-replicate stage score is defined. When fixed-cohort
staging is unavailable, the stage result is
`NOT_APPLICABLE_BY_CAPABILITY` with reason
`STAGING.FIXED_COHORT_UNAVAILABLE`, `value=null`, and the report uses:

> Participant-stage sampling stability was not computed because the worker could not stage the fixed original evaluation cohort under each sampling-fitted model.

When event sets or semantics differ:

> Native stage numbers are not directly comparable because the event set or stage semantics changed. Normalized progress fractions, if shown, are descriptive and labelled `SEMANTICALLY_NON_EQUIVALENT`.

The report never converts cross-sectional stage into time, prognosis, conversion risk, diagnosis, or biological onset.

## 11. Influence language

The component and participant states are exactly those in
`metrics/v0.1.0`: each component is
`INFLUENCE_COMPONENT_HIGH`, `INFLUENCE_COMPONENT_NOT_HIGH`, or
`INFLUENCE_COMPONENT_NOT_ASSESSABLE` under the proposed pre-freeze thresholds;
participant coverage is evaluated first, then two-or-more, exactly-one, or zero
high components. Reports must print the threshold beside each component and mark
it `FROZEN_REVIEWED_WITH_DEVELOPMENT_SENSITIVITY_UNVERIFIED`. A display rank never
overrides these states.

Allowed:

- “Participant alias `{alias}` was influential under `{x}` of `{y}` supported component metrics.”
- “Removing `{alias}` was associated with a central-order Kendall distance of `{value}` and `{count}` pairwise-majority flips.”
- “Influence was concentrated in the stage metric and was not consistently high in order metrics.”

Required caveat:

> Influence means that a refitted result moved after a declared removal. It does not by itself identify bad data, an erroneous participant, or a reason for exclusion.

Direct identifiers are prohibited. Pseudonymous aliases are deterministic within a run but need not be stable across independent runs unless an opt-in private mapping is supplied.

## 12. Null-relative labels and safe fallback

The evaluator's `CandidateStrongEvidenceDecision` from
`metrics/v0.1.0` is a pre-authorization held-out scoring field, not a
report label. It is never rendered as a scientific conclusion and never
substitutes for one of the labels below. The final label classifier may use a
passed held-out aggregate receipt for the exact `NullCalibrationIdentity`; the
held-out aggregate itself counts the sealed candidate decisions, not these final
labels. The aggregate must validate as
`scientific-invariant.schema.json#/$defs/FalsePositiveEvaluation`, bind the
exact 60-opportunity manifest and `NullCalibrationIdentity`, and pass its
executable count/rate/Clopper-Pearson invariants. Missing, contradictory, or
identity-mismatched evidence takes the safe fallback; prose cannot repair it.

The only labels, evaluated in this exact order, are:

- `NULL_CALIBRATION_NOT_VALIDATED`
- `NULL_COMPARISON_NOT_ASSESSABLE`
- `STRONGER_THAN_CHOSEN_REFITTED_NULLS`
- `NULL_RESULTS_MIXED`
- `NOT_STRONGER_THAN_CHOSEN_REFITTED_NULLS`

1. `NULL_CALIBRATION_NOT_VALIDATED` when no held-out calibration passed or its
   `benchmark_subject_digest`/`NullCalibrationIdentity` differs in any backend,
   worker, capabilities, settings, algorithm, environment, candidate,
   statistic-route, null-procedure, convergence-rule, profile, or rule-version
   field.
2. `NULL_COMPARISON_NOT_ASSESSABLE` when calibration identity matches but any required current-run family lacks its frozen replicate coverage, any contributing fit is not `CONVERGENCE_PASS`, or either fixed primary statistic is unavailable/non-finite.
3. `STRONGER_THAN_CHOSEN_REFITTED_NULLS` when every required family has positive null effect and empirical `p <= 0.05` for both `pairwise_concentration/v1` and `position_concentration/v1`.
4. `NULL_RESULTS_MIXED` when at least one required family passes the two-statistic rule and at least one required family does not.
5. `NOT_STRONGER_THAN_CHOSEN_REFITTED_NULLS` when no required family passes the two-statistic rule.

This order is total and mutually exclusive. Likelihood-margin diagnostics never alter it. `STRONGER_THAN_CHOSEN_REFITTED_NULLS` is allowed only when the exact frozen rule passed its held-out pure-generator false-positive gate and every current-run eligibility condition in the metrics contract passes. Its template is:

> The predeclared order diagnostics were stronger than all chosen refitted null families under benchmark rule `{rule_id}`. This is evidence relative to those null procedures, not proof of a true disease sequence.

Neither `NOT_STRONGER_THAN_CHOSEN_REFITTED_NULLS` nor `NULL_RESULTS_MIXED` is proof that signal is absent. Only generated `pure_no_signal` cases enter the held-out false-positive denominator; transformed observed-data nulls remain required current-run diagnostics but are excluded from that denominator.

If held-out null calibration has not passed, nulls are incomplete, the rule version differs, or required diagnostics are unavailable, the report must include exactly:

> This audit describes sensitivity across the tested choices, but it does not establish that the dataset contains a recoverable disease-order signal.

That sentence is mandatory and cannot be replaced by a more optimistic
paraphrase. Stable or concentrated labels, if otherwise eligible, must appear in
the same summary block immediately before this sentence rather than overriding
it. The serialized `within_fit_concentration` field is unchanged. The opposing-
sequence and forced-precision benchmark predicates inspect that independent
field even when null-relative status is a fallback.

## 12.1 Closed report predicates

Mandatory benchmark language predicates are computed from canonical report
fields, never by searching prose:

- `PRECISE_ORDER_OUTPUT/v1`, `KNOWN_POOR_RECOVERY/v1`,
  `FORCED_PRECISION/v1`, and `INELIGIBLE_STRONG_LABEL/v1` have exactly the
  definitions in `metrics/v0.1.0` Section 9.4.
- `COVERAGE_LIMITATION_REPORTED/v1` is assessable only when the sealed scenario
  truth declares at least one ID in `affected_tail_event_ids`. It is true exactly when
  the canonical report model contains limitation code
  `INCOMPLETE_TIME_COVERAGE` once, its ordered `affected_event_ids` equals the
  truth object's ordered affected IDs, and the rendered limitations section
  contains the exact template below once. It is false for any mismatch or
  omission. It is `NOT_ASSESSABLE` when the scenario truth has no such IDs.

The exact coverage template is:

> The generated sampling windows did not provide the declared normal or abnormal tail coverage for events `{ordered_event_list}`. Their fitted positions may therefore be weakly informed by this scenario.

Each predicate is serialized as `{predicate_id, status, value, reason_codes,
input_record_ids}`. Benchmark expressions such as “forced precision,”
“unjustified strong label,” “poorly recovered case,” and “coverage limitation
reported” MUST reference these predicate IDs. An evaluator cannot define them
from ad hoc text, a human reading, or an unversioned synonym.

## 13. Failed, invalid, and unsupported universes

The report lists every terminal category and stable reason code. For full- and
partial-capability integrations, every omitted check is shown at the integration
level as `UNAVAILABLE` or `NOT_APPLICABLE`; neither state is pass, fail, zero,
empty evidence, or an inferred output. It uses literal language:

- “`{count}` universes were invalid before fitting because `{reason}`.”
- “`{count}` universes were unsupported by worker `{worker}` because `{capability}` is unavailable.”
- “`{count}` fits failed with `{error_category}`; they remain in the planned denominator.”
- “No result was inferred for unavailable metrics.”

Absence of a capability or result is never rendered as zero movement, agreement,
a pass, fail, or “no issue.” Where the existing scientific metric contract uses
`NOT_APPLICABLE_BY_CAPABILITY`, that exact underlying status and reason remain
visible and map to the enclosing integration-level `NOT_APPLICABLE` state. Bare
`NOT_APPLICABLE` remains prohibited as a replacement for the more-specific
underlying metric status. Report-domain labels ending in `_NOT_ASSESSABLE` remain
classifier states and do not erase the underlying metric status or reason.

## 14. Hard-failure report behavior

If any hard release failure occurs, ordinary report rendering stops after a minimal privacy-safe failure page. The page contains hashes, counts, typed failure codes, rule versions, and remediation boundaries, but no raw values or direct IDs. Its heading is `AUDIT INVALID — RESULTS MUST NOT BE INTERPRETED`.

Hard failures include silent data modification, identity/label misalignment, unexplained nondeterminism, upstream cache contamination, oracle disagreement without surfaced failure, invalid/null universes disappearing, convergence failure contributing as evidence, false baseline reproduction, raw identifier/value leakage, offline network access, globally suppressed warnings, incomplete provenance identity, prohibited medical/causal claims, fresh-environment failure at release readiness, or any unresolved P0/P1 review finding.

## 15. Prohibited claims and lexical gate

Product-authored conclusions and headings must not contain these claims or close variants:

- proved/proven a sequence;
- true disease sequence;
- caused/causal effect;
- will develop dementia;
- clinical diagnostic claims, including `diagnoses`, `diagnosed with`,
  `diagnostic of`, `diagnostic test`, or `can diagnose` when the object is a
  participant, disease, condition, or clinical state;
- prognosis/prognostic prediction;
- treatment recommendation/response;
- clinically validated;
- universally robust;
- medical device;
- bad/wrong participant or bad data based on influence;
- reproduced the original analysis without a supplied canonical reference.

The statistical noun “diagnostic” and its plural are allowed only in frozen
phrases naming a technical check, such as `convergence diagnostic`, `calibration
diagnostic`, `order diagnostic`, or `likelihood diagnostic`. They do not authorize
clinical diagnostic language. Other prohibited terms may appear only inside the
mandatory limitation text, methods definitions, quoted user-supplied context, or
a labelled prohibited-claim audit. The renderer uses a versioned phrase matcher
for the clinical patterns above, a template allowlist for technical diagnostic
phrases, and a case-insensitive lexical scan for the remaining prohibited terms.
Any unallowlisted match is `PROHIBITED_REPORT_CLAIM`, a hard failure. Contract
tests must both accept the frozen “order diagnostics” template and reject each
clinical pattern with singular/plural and case variants.

## 16. Required methods/provenance disclosure

Every complete or partial report displays:

- report-language rule ID and benchmark-contract version/hash/status;
- held-out `benchmark_subject_digest` and an exact match/mismatch result for the
  current worker/integration identity under evaluation;
- dataset/config/code/protocol/backend/environment digests;
- all seeds and chain settings without private identifiers;
- event-set and comparison semantics;
- planned and terminal universe accounting;
- exact metric definitions or local links to them;
- null families, replicate counts, empirical rule, and calibration status;
- complete `NullCalibrationIdentity` fields/hash and an exact-match or mismatch reason;
- baseline-reproduction status;
- all limitations and unsupported capabilities; and
- that institutional approval remains the researcher's responsibility.

No report claims GDPR, NHS, KCL, HIPAA, regulatory, or institutional compliance. It states only verified technical properties.

## 17. Only terminal condition

The only readiness label is exactly:

`READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY`

It is emitted only under `ebm-integration-readiness.md`, after one exact candidate
proves the sole generic-worker integration surface, the transparent
`SYNTHETIC-ONLY` conformance EBM, honest full- and partial-capability behavior,
baseline machinery, unchanged scientific and held-out synthetic gates,
privacy/offline/determinism/provenance gates, fresh-environment proof, usable
deterministic reporting, researcher simulation, and zero unresolved P0/P1
findings. It does not require a named backend, Mina-specific handoff, real
participant data, or backend acceptance. A specification, methods review,
conformance receipt, test count, or emitted order alone cannot satisfy it.

Before then, the machine state is `IN_PROGRESS` or `BLOCKED` with exact unsatisfied gates. Neither is a readiness label or terminal outcome. Technical/methods review is progress evidence only and must never terminate the build.
