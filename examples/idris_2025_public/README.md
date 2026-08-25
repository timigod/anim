# Idris 2025 public starter support files

This directory contains only public mapping guidance and project-owned synthetic
rows. It contains no Idris/LonDownS participant data, reconstructed values,
private column names, fitted output, published event order, or expected result.

The motivating paper is Mina Idris et al., "Staging of Alzheimer's disease
progression in Down syndrome using mixed clinical and plasma biomarker measures
with machine learning," *Alzheimer's & Dementia* (2025), DOI
[`10.1002/alz.70446`](https://doi.org/10.1002/alz.70446).

## Files

- [`idris-2025-public.structural.audit.yaml`](../config/idris-2025-public.structural.audit.yaml)
  is the strict `AuditConfig/0.3` mapping template used by
  `ebm-audit init --template idris-2025-public`.
- [`synthetic-example.csv`](synthetic-example.csv) is an unrelated, unmistakably
  synthetic table that demonstrates the generic `event_01` through `event_09`
  aliases. Its values and row order carry no scientific meaning.
- [`group-rule-examples.json`](group-rule-examples.json) contains two syntax
  examples. They are not defaults, recommendations, or fitted threshold choices.
- The complete confirmation and claim boundary is in
  [`idris-2025-public-starter-limitations.md`](../../docs/handoff/idris-2025-public-starter-limitations.md).

## Mapping boundary

The nine public display names are mapping targets only. Their array positions and
the aliases `event_01` through `event_09` are not the paper's event order, an
expected disease order, ground truth, or a benchmark target. Replace each alias
with a confirmed private local column and record its assay or scoring definition,
unit or range, coding, transformation, abnormal direction, and identifier-risk
review. Every direction remains `REQUIRES_CONFIRMATION` until that work is done.

The public paper does not resolve these implementation choices:

- The age-defined younger and older groups are a reported study choice, not a
  universal control/disease definition or a default for another cohort.
- The exact residualisation formula, intercept, encodings, transformations, and
  supplied EBM values are unpublished or ambiguous.
- The EBM missing-data behavior is unpublished; do not infer imputation, masking,
  complete-case analysis, row deletion, or backend-native handling.
- The reported `1.5 IQR` sensitivity does not define the fitted population,
  variables, operation order, or action on flagged cells or participants.
- Ancillary MICE, PCA, GAM, and LOESS analyses are not assumed to be EBM
  preprocessing.
- The published `p < 0.05` feature-selection wording conflicts with the reported
  Aβ42/40 `p = 0.058`; the starter does not resolve that contradiction.
- The paper does not identify an executable EBM package, complete model
  parameterisation, MCMC contract, seed, convergence rule, or staging formula.
- `pysaebm` is a conditional reference worker and is not claimed to be the
  paper's implementation or scientifically interchangeable with it.
- No canonical reference-result bundle is supplied. Similarity to a publication
  figure, event sequence, stage range, or cohort size cannot establish baseline
  reproduction.

## Group examples

The reported age ranges in `group-rule-examples.json` encode public study
structure only. A local methods and domain review must confirm whether those
ranges, a researcher-supplied group label, or another predeclared rule is valid
for the local analysis. Do not search thresholds to recover a preferred order.

## Synthetic example

`synthetic-example.csv` is not a drop-in representation of the study. Its row
identifiers, labels, event values, covariate, metadata, and ignored field are
invented solely to demonstrate the expected column surface. It must never be
presented as participant data, a paper reproduction, or scientific validation.
