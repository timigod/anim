# Idris 2025 public starter: limitations and confirmation gate

## Purpose and evidence boundary

The `idris-2025-public` starter is a local mapping and planning aid based only on
publicly reported study information. It contains no Idris/LonDownS participant
data, reconstructed values, inferred rows, private column names, or fitted model
output.

This starter is optional downstream per-integration context. It is not required
for product completion. The only product readiness state is exactly
`READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY`, which
does not require participant data, this paper mapping, or any named backend.

Motivating paper: Mina Idris et al., “Staging of Alzheimer’s disease progression
in Down syndrome using mixed clinical and plasma biomarker measures with machine
learning,” *Alzheimer’s & Dementia* (2025), DOI
[`10.1002/alz.70446`](https://doi.org/10.1002/alz.70446).

The public description is sufficient to create a fail-closed configuration. It
is not sufficient to reproduce the published EBM, identify its implementation,
or claim robustness of the unseen participant data.

The retained starter now uses `AuditConfig/0.3`. Its physical
`input.variant.variant_id`, baseline row-free
`dataset_variant_intent.source_variant_id`, and unique baseline-input source
registry ID are all exactly `baseline-input`. The zero exact-file digest is an
explicit placeholder duplicated in the two required digest-owner fields; it is
not proof that local bytes exist. The file remains structural-only and contains
no participant rows.

## Public aggregate facts the starter may encode

- The paper reports a cross-sectional EBM analysis of 57 adults with Down
  syndrome without a clinical Alzheimer's diagnosis.
- The reported age-defined groups were 29 participants aged 20–35 as the control
  group and 28 participants aged 36–59 as an assumed preclinical disease proxy.
- The older group was assumed to have some neuropathology; that status was not
  independently established by the EBM.
- The EBM used nine publicly named plasma/cognitive events and reported stages
  `0..9`.
- Intellectual-disability-level residualisation was described as fitted in the
  controls and applied to all observations.
- Retaining plasma observations described as beyond a `1.5 IQR` rule changed the
  reported position of Aβ42/40.
- The paper reports an event order and positional uncertainty, but that order is
  contextual evidence only. The starter must not encode it as truth, a benchmark
  target, or a default expected result.

The paper's age-defined grouping is a reported study choice, not a universal
control/disease definition and not a default scientific truth for another cohort.

## Public event mapping surface

The starter may list these public display names so the researcher can map them to
private local columns. It must not guess source column names, units, transformations,
or abnormal directions.

| Public display name | Public category | Starter direction | Required local confirmation |
| --- | --- | --- | --- |
| Plasma Aβ42/40 ratio | Plasma | `REQUIRES_CONFIRMATION` | Assay definition, unit/scaling, coding, abnormal direction |
| Plasma p-tau181 | Plasma | `REQUIRES_CONFIRMATION` | Assay definition, unit/scaling, coding, abnormal direction |
| Plasma p-tau231 | Plasma | `REQUIRES_CONFIRMATION` | Assay definition, unit/scaling, coding, abnormal direction |
| Plasma neurofilament light (NfL) | Plasma | `REQUIRES_CONFIRMATION` | Assay definition, unit/scaling, coding, abnormal direction |
| Plasma glial fibrillary acidic protein (GFAP) | Plasma | `REQUIRES_CONFIRMATION` | Assay definition, unit/scaling, coding, abnormal direction |
| CANTAB Paired Associates Learning first-trial memory score | Cognitive | `REQUIRES_CONFIRMATION` | Exact variable/scoring version, unit/range, abnormal direction |
| Tower of London total score | Cognitive | `REQUIRES_CONFIRMATION` | Exact instrument/variable/scoring version, unit/range, abnormal direction |
| CANTAB Intra/Extra Dimensional Set Shift stages completed | Cognitive | `REQUIRES_CONFIRMATION` | Exact variable/scoring version, unit/range, abnormal direction |
| NEPSY-II visuomotor precision car-and-motorcycle score | Cognitive | `REQUIRES_CONFIRMATION` | Exact variable/scoring version, unit/range, abnormal direction |

Conventional expectations about a biomarker or test score do not resolve this
gate. The researcher must confirm the actual local assay/score coding and the
meaning of increasing values. A configuration with any
`REQUIRES_CONFIRMATION` direction may validate and plan, but must not fit a real
backend.

## Unresolved implementation and model identity

The public paper does not identify:

- the EBM software package or source version;
- a code repository or executable environment;
- the exact mixture family and parameterisation;
- the exact MCMC schedule, chain count, draw count, burn-in, thinning, or proposal
  settings;
- the random seed or complete random-number contract;
- the convergence rule;
- the stage-likelihood formula and stage prior;
- the exact participant-stage posterior calculation;
- the exact handling of missing event values; or
- a complete executable preprocessing/model configuration.

Historical package-probe context only: an optional `pysaebm` worker was
investigated as one downstream integration example. It was never identified as
the paper implementation, designated as an accepted backend, or made a product
completion dependency. No public package is presumed scientifically
interchangeable with the reported classical mixture EBM or able to reproduce the
reported output.

## Unresolved preprocessing semantics

### Residualisation

The public description states that intellectual-disability-level residualisation
was fitted in controls and applied to all observations, but it does not provide a
complete executable formula. The starter must not guess:

- the exact outcome/covariate formula for each event;
- intercept handling;
- categorical reference levels or encoding;
- handling of missing covariates or event values;
- whether any additional covariates entered the same fit;
- transformation/scaling before or after residualisation; or
- the precise values supplied to the EBM.

The researcher must either configure a confirmed explicit supported
transformation or use unadjusted data as a separately labelled analysis choice.
A documented external data variant is a future extension, not a current route:
config v0.3 rejects it until a complete physical owner is implemented. None may
be called an exact reproduction without a matching reference manifest.

### Missing data

Public variable counts indicate remaining feature-level missingness, but the
paper does not publish the EBM missing-data behavior. The starter must not assume
imputation, per-event likelihood masking, complete-case analysis, whole-row
deletion, or backend-native missingness.

The local configuration must select one explicit supported policy:

- `error`;
- `complete-case`, with exact predicted/actual participant counts retained.

`external-variant` is reserved vocabulary but is deliberately unavailable in
the current physical contract. Any declaration or selection fails during
resolution before planning; the starter does not fabricate a `DataVariant` or
compatibility route.

The tool must not silently convert unsupported cell masking into row deletion or
imputation. In particular, a worker that rejects NaNs must fail before invoking
its backend.

### Outlier rule

The reported sensitivity involving plasma observations beyond a `1.5 IQR` rule
does not provide a complete predicate/application contract. Confirmation is
required for:

- which variables and cohort supplied the quartiles;
- whether bounds were event-specific and recomputed after other preprocessing;
- whether the rule was fitted in controls, the whole cohort, or another subset;
- whether a flagged cell was retained, masked, transformed, winsorised, or caused
  whole-participant exclusion;
- the order relative to residualisation and other transforms; and
- exact affected participant/event/cell counts.

The starter may offer explicit `none`, `flag-only`, or fully parameterised IQR
choices, but no one choice is the reconstructed paper rule.

### Ancillary analyses are separate

The paper's ancillary multiple-imputation/PCA/GAM/LOESS work must not be silently
imported into the EBM pipeline. The public report does not establish that these
steps produced the EBM input. If the researcher supplies a data variant produced
by another pipeline, it must be named and accompanied by local provenance rather
than treated as built-in EBM preprocessing.

## Feature-selection contradiction

The paper states that markers significant at `p < 0.05` were used, while Aβ42/40
appears in the EBM and the reported table gives `p = 0.058`. The public materials
do not provide an exception or unrounded value that resolves this discrepancy.

The starter must preserve this as an unresolved contradiction. It must not:

- remove Aβ42/40 to enforce the prose rule;
- change the threshold;
- treat the published nine-event set as internally proven by that rule; or
- search feature sets to recover the published order.

The researcher should predeclare the baseline event set used by the original local
analysis and, if scientifically justified, a separate named feature-set sensitivity.

## Optional downstream baseline-reference check

An audit of the original analysis requires a canonical reference-result bundle
exported from the existing notebook/model where available. The comparison should
cover the supported subset of:

- event set and labels;
- central order;
- order samples or position matrix;
- participant-stage output;
- participant/event inclusion counts;
- preprocessing/missingness/outlier manifest; and
- diagnostics, settings, software, and seed identity.

The only allowed statuses are:

- `BASELINE_REPRODUCED`
- `BASELINE_PARTIALLY_REPRODUCED`
- `BASELINE_NOT_REPRODUCED`
- `BASELINE_REFERENCE_NOT_SUPPLIED`

`BASELINE_REPRODUCED` requires all predeclared required comparable fields and
identities to pass the frozen rule/tolerance. When no supplied comparison fails,
matching only an available subset is at most `BASELINE_PARTIALLY_REPRODUCED`. A
required or supplied mismatch is `BASELINE_NOT_REPRODUCED`. With no bundle, use
`BASELINE_REFERENCE_NOT_SUPPLIED`.

Similarity to the published order, figure, stage range, or cohort size is never
evidence of baseline reproduction. If full reproduction fails or is unavailable,
the report may describe the connected configuration's sensitivity but must stop
short of calling it an audit of the original Idris analysis.

## What the starter can do before confirmation

With no participant data and unresolved fields, the starter may:

- show the nine public mapping targets;
- validate configuration structure;
- list every `REQUIRES_CONFIRMATION` item;
- compile a dry-run plan and invalid/unsupported universes;
- describe worker capability mismatches; and
- run an unrelated, clearly labelled project-owned synthetic demonstration.

It must not fit real data, reconstruct participant rows, fetch data, infer private
columns, infer event directions, reproduce the published model, or label a
baseline as passed.

## Prohibited claims

Neither the starter nor a later real-data report may claim:

- exact reproduction from public information alone;
- that `pysaebm` or another worker was used in the paper without primary evidence;
- that the published order is ground truth or the “true disease sequence”;
- that an emitted or stable order proves recoverable disease-order signal;
- diagnosis, prognosis, time to conversion, treatment response, or causality;
- that cross-sectional stage is biological onset time or individual prognosis;
- clinical validation, universal robustness, regulatory approval, or
  medical-device status;
- that an influential participant is bad/wrong/outlier data without a separate
  data-quality rule; or
- GDPR, NHS, KCL, HIPAA, or institutional information-governance compliance.

The strongest permitted language remains conditional on the exact gates, for
example: stable across the tested specifications; internally concentrated within
the fitted samples; or stronger than the chosen refitted null diagnostics. These
are distinct findings and none establishes scientific truth.

If null diagnostics are not validated, the report must state:

> This audit describes sensitivity across the tested choices, but it does not
> establish that the dataset contains a recoverable disease-order signal.

## Optional downstream local decisions

If a researcher chooses a real fit after library readiness, the researcher and
local methods/domain team must resolve and record:

1. exact private column mapping and one-row-per-participant semantics;
2. event direction, units, coding, and display/privacy names;
3. group definitions and the scientific meaning of the older-group proxy;
4. baseline event set and the feature-selection contradiction disposition;
5. residualisation formula (external-variant provenance cannot yet be executed);
6. missingness and outlier policies with predicted participant/event/cell counts;
7. the actual model worker, software identity, settings, and capabilities;
8. canonical reference-result availability and required comparison fields; and
9. institutional approval, offline execution, output retention, and review route.

Unknowns remain explicit. They must not be converted into defaults merely to make
the configuration runnable.
