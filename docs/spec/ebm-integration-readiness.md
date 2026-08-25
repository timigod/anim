# EBM integration readiness contract

Status: normative stable candidate authority for contract binding; accepted by
ADR-0014 and amended by ADR-0016; bounded contract `0.2.3` correction in
progress
Version: 1.1.3
Date: 2026-08-21

ADR-0016 replaces the mandatory large held-out matrix with a bounded fresh-seed
23-family challenge that exercises all 104 meanings through the ordinary
full-capability worker, evidence, and report path. Sections 4, 5, and 11 remain
active. Partial EBM omissions stay visible and count as neither pass nor fail.
An unexplained omission from the full-capability challenge prevents readiness.
One closed terminal manifest must pass every preserved hard gate. Contract
`0.1.3` remains historical optional research-stress evidence. Accepted contract
`0.2.0` remains immutable historical evidence. Frozen contract `0.2.1`, its
hashes, and its acceptance verdict remain immutable historical evidence.
Implementation proved that one `PREPARATION_AUDIT_EVIDENCE` record cannot
prove the source-versus-transformed refit equality required by
`mcar_missingness /payload/preprocessing_refit_equal`. Independent review
returned `D04_CORRECTION_REQUIRED`. Independent exact review then rejected
contract `0.2.2`: its two genuine Fit-bearing executions contradicted the
one-MCAR-Fit ledger, and its metadata misnamed the hashed readiness artifact.
Implementation also exposed two impossible row-manifest cardinalities. Contract
`0.2.3` is the active candidate. It is not frozen or accepted. D04 is open.

## 1. Purpose and authority

This specification defines the only product-readiness state for the EBM
Robustness Auditor:

`READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY`

It governs the researcher integration surface, project-owned conformance EBM,
capability-limited behavior, synthetic validation, and evidence required to emit
that state. `ADR-0014` defines its supersession boundary. Every non-conflicting
scientific, privacy, provenance, failure-visibility, offline, deterministic,
benchmark, and report rule in the existing normative specifications remains in
force.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are
normative.

## 2. Claim boundary

The readiness state means only that a researcher can implement or connect a
local EBM worker through the documented protocol and run the auditor without
the original developer's help.

It MUST NOT be represented as evidence that:

- an untested EBM integration is correct or scientifically suitable;
- participant data contain a recoverable disease-order signal;
- an emitted event order is true;
- an EBM, dataset, diagnosis, prognosis, treatment, or causal claim is valid;
- a regulatory or medical-device standard is satisfied; or
- a named public backend has been accepted.

The auditor MUST remain backend-neutral. The subprocess protocol in
`adapter-protocol.md` is the only execution boundary. The core MUST NOT import,
bundle, select, download, or silently substitute an EBM implementation.

## 3. Researcher integration surface

The project MUST provide one coherent integration surface, not a second SDK or
parallel protocol. It MUST include all of the following from a clean installed
package:

1. **Adapter initializer.** One documented command creates a minimal worker
   project with configuration, protocol entry point, tests, and no participant
   rows or research-backend dependency. The intended command surface is
   `ebm-audit adapter init`.
2. **Typed builders.** Public typed builders construct Describe, Validate, Fit,
   capability, identity, warning, error, stage, chain, and artifact records.
   They MUST enforce the canonical schemas rather than duplicate them.
3. **Generated validation.** The initialized adapter can generate and run
   schema, identity, protocol-lifecycle, privacy, and capability validation from
   its declared worker description.
4. **Canonical Fit-result mapping.** A researcher can either map in-memory EBM
   output or import documented local result files into the canonical result
   record. Mapping MUST preserve every supplied chain, sample, stage result,
   diagnostic, warning, failure, and provenance field. Unknown or malformed
   material MUST fail closed; absent material MUST remain absent.
5. **Examples.** At least one full-capability and one partial-capability example
   use the same public helpers and protocol as external adapters. Examples MUST
   be synthetic and MUST identify every intentionally unavailable output.
6. **One conformance command.** `ebm-audit adapter conformance` runs all
   applicable checks and writes a deterministic machine-readable receipt.
   Human-readable output MUST point to that receipt and the first actionable
   failure without exposing raw inputs or local secrets.
7. **Clear errors.** Failures identify the protocol phase, stable error code,
   affected capability or field, and a bounded remediation. Arbitrary backend
   exception text MUST NOT enter default reports or receipts.
8. **One-command demo.** `ebm-audit demo --conformance-ebm` runs a complete
   project-owned synthetic audit and produces the deterministic report in a
   clean offline environment.

Command spelling MAY change before implementation only through a reviewed
specification update that preserves a single obvious path and updates all
examples, generated projects, tests, and handoff instructions atomically.

## 4. Worker capability contract

Each worker MUST declare a closed, versioned capability record during Describe.
Validation and Fit output MUST agree with that declaration.

For every audit check, the integration/conformance layer MUST derive exactly
one applicability state:

| State | Meaning | Scientific treatment |
|---|---|---|
| `AVAILABLE` | The worker declares and validly supplies all required evidence. | The check runs and may produce its own assessment. |
| `UNAVAILABLE` | Required evidence cannot be supplied by this worker or result. | The check does not run; absence remains visible. |
| `NOT_APPLICABLE` | The check does not apply under the declared model or analysis contract. | The check does not run; non-applicability remains visible. |
| `INVALID` | Evidence required for an applicable check is missing, malformed, contradictory, or otherwise invalid. | The check has no valid scientific result; invalidity remains a visible terminal state and MUST NOT be relabelled as unavailable or not applicable. |
| `FAILED` | The check is applicable and its validated prerequisites exist, but the worker, Fit, or derivation fails. | The check has no successful scientific result; failure remains a visible terminal state and MUST NOT be relabelled as unavailable or not applicable. |

Existing scientific-result contracts remain unchanged. Their more-specific
typed codes, including `NOT_APPLICABLE_BY_CAPABILITY`, MUST remain in the
underlying scientific record where currently required. The conformance receipt
and check inventory MUST map each such record unambiguously to the enclosing
`UNAVAILABLE` or `NOT_APPLICABLE` applicability state without rewriting or
duplicating the scientific result. The scientist-readable report MUST show the
plain-language applicability and preserve the exact underlying typed code.

An unavailable or inapplicable check MUST NOT be counted as pass or fail. It
MUST remain visible in machine-readable results and the scientist-readable
report. Aggregate status MUST distinguish:

- all required and applicable checks completed;
- a valid capability-limited audit with explicit omissions;
- failed or invalid applicable checks; and
- no scientifically interpretable result.

The auditor MUST NOT infer samples, likelihoods, stages, convergence,
transition diagnostics, uncertainty, or other evidence that the worker did not
supply. It MUST NOT derive an unavailable scientific output from a central
order merely to make a check runnable.

## 5. Full and partial conformance

The conformance suite MUST test both:

- one full-capability worker that validly supplies every capability required by
  the complete canonical synthetic audit; and
- partial-capability workers whose deliberate omissions cover each supported
  `UNAVAILABLE` or `NOT_APPLICABLE` branch.

For the full-capability worker, every declared output MUST cross request,
subprocess response, canonical finalization, immutable evidence, cache where
applicable, science projection, JSON report, CSV output where applicable, and
self-contained HTML without a silent drop or relabel.

For partial-capability workers, conformance MUST prove that:

- supported outputs are still validated and audited;
- omitted outputs remain explicitly unavailable or not applicable;
- unrelated checks continue when their prerequisites exist;
- no omission becomes a pass, fail, zero, empty estimate, or inferred output;
- overall language remains bounded by the available evidence; and
- capability changes alter worker identity and invalidate incompatible cached
  results.

A worker conformance pass proves protocol and declared-capability behavior. It
does not prove model validity or make that worker an accepted research EBM.

## 6. Conformance EBM

### 6.1 Role

The project MUST own one transparent reference implementation called the
**conformance EBM**. It is test infrastructure for the auditor. Every identity,
receipt, artifact, example, and report involving it MUST carry the literal
classification `SYNTHETIC-ONLY`.

It MUST NOT be called a production, research, genuine, accepted, or fallback
backend. It MUST NOT be recommended for participant data.

### 6.2 Fail-closed input admission

Before Validate or Fit can invoke model code, conformance-EBM input MUST prove:

- explicit synthetic classification;
- a deterministic project-owned generator and generator-version identity;
- deterministic generator and input-content hashes linked by digest to the
  complete known-truth record;
- a declared synthetic scenario, replicate, and seed;
- no external or participant-data source; and
- consistency between dimensions, event identities, generator record, and
  truth record.

For this admission boundary, **verified provenance** means exactly that
deterministic project-owned generator identity/hash and known-truth linkage. It
does not require or introduce signatures, credentials, attestations, a trust
service, or another authentication/security subsystem.

Any missing, unknown, malformed, inconsistent, or non-synthetic fact MUST stop
before model execution with a typed `CONFORMANCE.SYNTHETIC_ONLY` failure. No
flag, environment variable, configuration field, or source modification MAY
override this boundary through a supported path.

Default receipts and errors MUST NOT reproduce raw biomarker values or direct
identifiers, including when admission fails.

### 6.3 Transparent model and sampler

The implementation MUST version and document its:

- event model and likelihood;
- priors and state representation;
- exact or sampled order representation;
- initialization, proposal, acceptance, burn-in, thinning, and retained-sample
  rules where sampling is used;
- stage definition and fixed-evaluation behavior;
- seed derivation and deterministic numeric environment;
- warning and convergence rules; and
- canonical-output mapping.

For supported small-event cases it MUST reuse the project exact oracle or
demonstrate exact equality to it. Sampling MAY be used to exercise sampling
uncertainty and convergence paths, but its target and expected behavior MUST be
checkable against project-owned known truth. A sampled order is never by itself
evidence of recoverable signal.

The conformance EBM MUST run out of process through the ordinary worker
protocol. It receives no private API, relaxed validation, in-process arrays,
special cache authority, report shortcut, or exception from containment.

## 7. Baseline reproduction

Baseline reproduction remains a per-integration gate. Each research integration
MUST provide or deliberately declare the absence of its own versioned baseline
reference under the existing baseline contract.

The conformance EBM's baseline MAY test baseline machinery only for that exact
synthetic worker and scenario. It MUST NOT be reused, translated, or promoted
as the baseline for another EBM, source revision, environment, capability set,
configuration, or dataset.

A researcher integration that cannot reproduce its required baseline MUST
remain visibly blocked from interpretive language even if worker conformance
passes.

## 8. Synthetic benchmark and frozen challenge

The development suite MAY use only public information and clearly labelled
project-owned synthetic data. Contract `0.2.3` MUST be independently reviewed,
frozen, and hashed before C closes or Phase 3 begins. Unaffected Phase 2 C work
may continue during this bounded correction. It MUST define:

- the exact ordered inventory of all 104 audit meanings;
- full- and partial-capability applicability rules;
- deterministic expected typed results for complete, malformed, missing,
  invalid, failed, unavailable, and not-applicable cases;
- one closed terminal hard-gate manifest;
- one exact per-family and per-meaning Fit ledger with a total Fit ceiling and
  time budget derived from complete coverage;
- the candidate, conformance-EBM, plan, rule, and fresh-seed commitment order;
  and
- one immutable terminal receipt contract.

Readiness specification `1.1.3` is the stable candidate authority that contract
`0.2.3` MUST bind by exact raw bytes and SHA-256. The correction MUST change
exactly three effective meaning identities:

1. `mcar_missingness /payload/preprocessing_refit_equal` MUST derive
   `complete-preprocessing-refit-equality/1` from two direct authenticated
   executed `PREPROCESSING_EXECUTION_RECORD` roles. The proportional plan MUST
   contain two explicit ordered MCAR operations and Fits, `SOURCE` then
   `TRANSFORMED`. Each execution MUST bind its own plan entry and exact
   case-operation join key. The comparison MUST authenticate both entries under
   the same proportional plan, the same MCAR case and comparison pair, and the
   two fixed roles. One `PREPARATION_AUDIT_EVIDENCE`, a planned refit, a
   caller-made record, or inferred equality MUST NOT prove the comparison.
2. `mar_missingness /payload/silent_loss_flags` MUST select exactly four
   `PREPARATION_ROW_INSTANCE_MANIFEST` owners in canonical `INPUT`, `TRAINING`,
   `OUTPUT`, `REFERENCE_FIT` order. A `ONE_PER_CASE` declaration is invalid
   because it rejects this required valid set.
3. `covariate_confounding /payload/resample_leakage_count` MUST select exactly
   the same four canonical row-role manifests in the same order. Its
   `ONE_PER_CASE` declaration is invalid for the same reason.

The other 101 meaning identities and all 104 output types, scientific meanings,
applicability rules, and failure behaviors remain unchanged from frozen
`0.2.1`.

The challenge plan MUST contain exactly `104` ordered operations and Fits. It
MUST contain the MCAR `SOURCE` operation immediately before its `TRANSFORMED`
partner. It MUST include 24
matched moderate pairs with one signal and one matched-pure-no-signal Fit per
pair, for 48 moderate Fits. At most four Fits may run in parallel. The nominal
wall-clock target is `9,600` seconds. The terminal timeout is `10,500` seconds.
The execution allowance remains `ceil(104 / 4) * 300 = 7,800` seconds, the same
26 waves as the 103-Fit ledger, so neither time bound changes.
No meaning, comparator member, refit, influence removal, operation, report
surface, or hard gate may be removed to meet these bounds.

The ordinary evidence path MUST keep authority boundaries explicit:

- `PUBLIC_BATCH_CASE_PLAN` authenticates case identity only;
- the authenticated public planning authority issues the pre-execution
  `PROPORTIONAL_OPERATION_PLAN`;
- preparation and capture authorities issue executed preprocessing, row,
  transformation, result, warning, side-effect, and per-operation terminal
  evidence;
- every executed record binds the exact shared case-operation key, operation
  plan hash, and plan-entry hash; and
- `valid_case_ids` uses an explicit all-planned-operations reduction. A
  case-level terminal or one successful comparator member is insufficient.

Report assembly MUST be acyclic. It MUST assemble non-report meanings first,
issue one pre-render claim projection, derive report-dependent meanings,
assemble the final 104-meaning bundle, render JSON, applicable CSV, and HTML
once, then read those artifacts back and issue one surface-verification
receipt. That receipt MUST NOT re-enter the owner graph or cause another
render.

The one-shot bounded challenge MUST retain:

- commitment of the exact candidate, conformance EBM, public plan, rules, and
  expected interpretations before fresh challenge seeds are derived;
- fresh synthetic seeds generated only after that commitment;
- coverage of all 23 scenario families and all 104 meanings through the
  ordinary public worker, audit, evidence, JSON report, applicable CSV, and
  self-contained HTML path;
- zero unexplained `UNAVAILABLE` or `NOT_APPLICABLE` meanings for the
  full-capability conformance EBM;
- explicit partial-capability, malformed, missing-input, invalid, and failed
  branch proofs that are not promoted to pass or fail;
- one run, retained result, and no result-conditioned code, threshold,
  schedule, seed, or scenario change;
- independent exact-candidate and artifact review; and
- visible terminal failure for any missing inventory member, missing hard-gate
  field, stale identity, contradiction, or failed gate.

The challenge result is scoped to the auditor plus that exact conformance EBM.
It MUST NOT statistically qualify the conformance EBM, a public package, a
future research worker, participant data, or disease signal. The auditor MUST
use the exact cautious fallback unless a separate reviewed calibration study
supports stronger null-relative language. Each future integration remains
responsible for its own baseline, capability, and scientific evidence.

## 9. Conformance receipt

`ebm-audit adapter conformance` MUST write a versioned deterministic receipt
containing at least:

- receipt schema and tool version;
- exact package, source, configuration, worker, environment, and protocol
  identities;
- worker classification and declared capabilities;
- command and test-profile identity without local absolute paths;
- ordered check identifiers and applicability states;
- pass/fail results only for checks that ran;
- stable typed failures and bounded remediation identifiers;
- counts for `AVAILABLE`, `UNAVAILABLE`, `NOT_APPLICABLE`, `INVALID`, and
  `FAILED` checks;
- proof that no missing check was counted as pass or fail;
- offline/network-denial result;
- privacy scan result;
- deterministic artifact inventory and hashes;
- overall protocol-conformance result; and
- explicit limitations, including that conformance is not scientific
  acceptance.

The receipt MUST fail verification after any decision-relevant mutation. It
MUST exclude direct identifiers, raw biomarker values, arbitrary exception
text, credentials, hostnames, usernames, and local absolute paths.

## 10. Readiness evidence

The readiness state MAY be emitted only when one exact candidate has all of the
following retained and independently reviewed evidence:

1. the complete integration surface in Section 3 from a clean installed
   package;
2. protocol conformance for the full-capability conformance EBM;
3. the complete canonical synthetic audit and deterministic report through the
   conformance EBM;
4. the partial-capability matrix in Section 5;
5. baseline success and deliberate baseline-failure behavior for the exact
   conformance integration;
6. frozen contract `0.2.3`, complete 104-meaning deterministic branch proof,
   every terminal hard gate, and the one-shot 23-family bounded challenge;
7. repeated-byte determinism where required and honest visible failures;
8. default-artifact privacy and no-network proof;
9. a fresh supported offline installation and one-command demo from a neutral
   directory; and
10. documentation and a researcher simulation that use only the shipped
    instructions and require no developer repair or explanation.

The terminal receipt MUST name the exact candidate and evidence hashes, state
that no participant-level data were used, enumerate every residual limitation,
and use the readiness literal exactly. Test count, an emitted order, a worker
exit code, or a conformance receipt alone cannot create readiness.

## 11. Report requirements

Reports MUST keep within-model uncertainty, sampling uncertainty,
analyst-decision uncertainty, participant influence, and lack of recoverable
signal separate. They MUST show `AVAILABLE`, `UNAVAILABLE`, `NOT_APPLICABLE`,
`INVALID`, and `FAILED` checks as distinct states.

When a partial integration lacks evidence required for an interpretation, the
report MUST name the missing capability and withhold that interpretation. It
MUST NOT substitute conformance-EBM evidence or imply that omitted checks would
have passed.

All prose remains deterministic template output. No network service, external
API, remote asset, telemetry, or LLM is permitted during audit execution or
report generation.

## 12. Preserved evidence and prohibited shortcuts

All prior public-backend attempts, warnings, failures, reviews, and dispositions
remain historical evidence about their exact subjects. They MUST NOT be erased,
rewritten as conformance evidence, or generalized into unsupported package
claims.

The following do not satisfy this contract:

- renaming a structural fixture as an EBM;
- allowing the conformance EBM to accept real or unauthenticated data;
- adding a privileged in-process integration path;
- treating `UNAVAILABLE` or `NOT_APPLICABLE` as pass or fail;
- synthesizing missing backend outputs;
- relaxing thresholds, warnings, privacy, offline, provenance, or held-out
  rules to obtain a pass;
- using a public package result as the conformance-EBM proof;
- claiming readiness from documentation without clean installed execution; or
- waiting for, requesting, reconstructing, or fabricating participant-level
  data during product validation.
