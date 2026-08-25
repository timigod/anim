# EBM integration readiness contract 1.2.0

Status: **ACCEPTED AND FROZEN**

Version: 1.2.0

Date: 2026-08-24; accepted and frozen 2026-08-25

## Authority and preservation

This specification applies accepted ADR-0017 to the readiness state defined by
accepted ADR-0014 and ADR-0016. Version `1.1.3` remains immutable historical
evidence. All non-conflicting scientific, privacy, provenance, typed-state,
offline, report, and no-overclaim rules in `1.1.3` remain normative.

The only readiness claim remains:

`READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY`

It is not evidence for an untested EBM, disease signal, event truth, diagnosis,
prognosis, treatment, causation, regulation, a medical device, or a named
backend.

## Separate cardinalities

The receipt must report `planned_operation_count`, `attempted_fit_count`,
`successful_fit_count`, `failed_fit_count`,
`invalid_pre_fit_terminal_count`, and `output_obligation_count` separately.

The exact ordered 104 rows preserved from contract `0.2.3` are an
output-obligation compatibility and regression inventory. They are not 104
studies, user features, or mandatory Fits. Readiness must not require
`operation_count == meaning_count` or `fit_count == 104`.

Every actual data, preprocessing, resample, participant-membership, influence,
or null change requires its own Fit. Missing evidence remains `UNAVAILABLE`,
`NOT_APPLICABLE`, `INVALID`, or `FAILED`. It never becomes a scalar, zero,
pass, or inferred result.

## Compact live profile

The profile contains exactly six successful Fits:

1. `FULL_BASELINE`: 57 synthetic participants and nine events;
2. `SAMPLING_BOOTSTRAP`: participant bootstrap refit;
3. `PREPROCESSING_TRANSFORMED`: fixed public event-rescale preprocessing refit
   bound to the exact full baseline AnalysisSpec;
4. `INFLUENCE_PARTICIPANT_REMOVAL`: leave-one-participant-out refit;
5. `NO_SIGNAL_TRANSFORMED`: independently generated pure-no-signal refit; and
6. `PARTIAL_BASELINE`: partial-capability baseline.

The full baseline, bootstrap, fixed-rescale preprocessing,
participant-removal, and pure-no-signal members must have five distinct
AnalysisSpec identities, candidate identities, and captured Fits. The four
full derivatives are exactly baseline, bootstrap, participant removal, and pure
no signal. Preparation owns every changed dataset or preprocessing transform
and exact accounting. A pre-Fit invalid operation may prove invalid visibility
without adding a Fit.

All Fits must traverse the shipped conformance worker and ordinary audit,
scientific capture, evidence projection, grouped meaning derivation, and audit
result path. The five full-capability Fits feed the one final JSON, applicable
CSV, and self-contained HTML surface. The partial Fit feeds a distinct 104-row
typed meaning bundle that the final readiness receipt binds to the same final
surface. The compact profile must not run the 28-Fit full/partial
public-contract suite again.

## Output and branch coverage

The deterministic 104-by-three branch matrix remains mandatory. It covers
positive, missing-owner, and malformed branches for every ordered output. The
combined no-Fit gate also retains partial, unavailable, not-applicable,
invalid, and failed behavior. This no-Fit proof does not impersonate scientific
execution.

## Scientific separation

The report must keep within-Fit model uncertainty, participant sampling,
analyst-decision preprocessing, participant influence, and lack of recoverable
signal separate. An emitted order is not evidence of recoverable signal.
Pure-no-signal output uses the frozen cautious fallback unless a separate
reviewed calibration study supports stronger language.

## Exact oracle boundary

The public materialized `solve_exact_oracle()` accepts at most eight events and
must reject nine events before permutation enumeration. The compact summary
solver may accept nine events for ordinary Fits. It preserves exhaustive
lexicographic order, exact ties, the first maximizing order, log evidence,
stage posterior, position probabilities, pairwise precedence, public
identities, and fail-closed limits. Chunking does not claim a lower-complexity
algorithm. No cache may cross a call, request, identity, profile, or run.

## Hard gates

The 17 gate identities remain:

1. `contract_candidate_plan_frozen`;
2. `researcher_workflow_and_handoff`;
3. `meaning_inventory_complete`;
4. `substantive_scientific_validation`;
5. `full_partial_capability_honesty`;
6. `baseline_truthfulness`;
7. `no_silent_data_change`;
8. `uncertainty_separation`;
9. `provenance`;
10. `privacy`;
11. `offline_operation`;
12. `determinism`;
13. `visible_warnings_and_failures`;
14. `cautious_language`;
15. `no_result_conditioned_tuning`;
16. `independent_review`; and
17. `no_unauthorized_external_action`.

Each gate binds directly to genuine product evidence. A duplicate authority or
receipt that only revalidates an authenticated fact is not required.

## Report, runtime, privacy, and handoff

One ordinary report is required. The five full-capability Fits form the
`FULL_CAPABILITY_COHORT` final report subject. The partial worker forms one
distinct `PARTIAL_CAPABILITY_CASE` evidence subject because it must expose
honest omissions. The two meaning-bundle hashes must differ. Both subjects bind
to the same final report-binding hash. The readiness receipt declares the
full-capability cohort report as the one final surface and records exactly one
render plus exact artifact readback.

The installed path uses Seatbelt network, process, and file boundaries. It does
not access participant or protected data. Default artifacts contain no direct
identifiers or raw biomarker values. There is no telemetry, external API,
remote asset, LLM, credential use, or external action.

The candidate proves one clean locked build and audit installation. A fresh
finalizer may validate immutable report bytes and hashes. It must not re-render
only to reproduce evidence.

The final installed compact pilot's immutable receipt records completion on the
supported iMac with Python `3.12.13` in `247.2211161670275` seconds. The
readiness limit and terminal timeout are 300 seconds. The evaluated 240-second
stretch target is `NOT_MET` and must not be reported as passed.

## Acceptance boundary

The terminal receipt names the exact candidate, tree, source and artifact
hashes, all counts, limitations, public-synthetic classification, and the fact
that no participant data or unauthorized external action occurred.

Independent exact-candidate and artifact review returned
`ACCEPT_EXACT_COMPACT_READINESS_CANDIDATE`. ADR-0017, this specification, and
contract `0.3.0` are accepted and frozen. The final readiness receipt preserves
the report's `INCOMPLETE` state and blocked science-completion limitation while
establishing researcher integration and local-audit readiness.
