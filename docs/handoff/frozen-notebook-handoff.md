# Preserve a notebook baseline before integration

This guide is for a research team whose current event-based model (EBM) lives in
a private Jupyter notebook. The notebook and its data remain private and local.
Anim does not require the notebook, participant rows, or private outputs to be
published.

Save the original model, settings, and results before changing the notebook.
This saved baseline lets you check whether the integrated model reproduces the
original analysis. Then extract a worker: a separate local command that runs
the same model with explicit settings and a supplied random seed.

## 1. Preserve the private baseline

Before changing the notebook or model, record its exact private identity:

- notebook byte hash (a digest identifying its exact contents) and trusted storage location;
- Python and Jupyter versions;
- exact installed package versions or environment lock;
- model implementation, algorithm, settings, seeds, and chain settings;
- dataset identity and the mapping between participants and result rows;
- preprocessing, inclusion, missingness, event labels, and the definition of each stage; and
- the outputs that the original notebook actually produced.

Keep this private record under the research team's approved storage and access
rules. Do not place the notebook, participant data, absolute private paths, or
reversible identifiers in the Anim repository, reports, issues, or support
material.

## 2. Export a reference bundle in Anim's required format

Create the private export draft without fitting:

```sh
ebm-audit baseline-reference init \
  --output-dir /approved/local-config/baseline-reference-draft
```

Inside the approved notebook, use
`ebm_audit.baseline.build_reference_result` and
`ebm_audit.baseline.export.write_reference_bundle` as described in the
[custom worker guide](custom-worker-guide.md#11-baseline-reference-integration).
The export creates exactly:

```text
reference-bundle.json
arrays.npz
private-alignment.json
```

The bundle records which dataset, implementation, settings, preprocessing,
stage definitions, software version, and private row mapping produced the
outputs. It does not infer fields the notebook did not produce.

Validate the bundle offline before changing the notebook:

```sh
ebm-audit baseline-reference validate \
  --manifest /approved/local-config/baseline-reference/reference-bundle.json \
  --offline \
  --output /approved/local-output/baseline-reference-validation.json
```

Keep all three bundle files private, together, and outside repositories and
report output. Successful validation confirms that the bundle follows the
required format and its recorded hashes match. It does not establish scientific
validity.

## 3. Extract a deterministic worker

Keep the notebook for development and reference. Move its fitting and
staging call into a local command that:

1. receives every model setting explicitly;
2. uses the supplied seed for every controllable stochastic source;
3. records or moves notebook preprocessing into declared Anim choices;
4. uses internal indexes and declared event IDs instead of private IDs or
   implicit DataFrame order;
5. cannot reuse cached notebook state;
6. translates only outputs the model produces, or mathematically valid derivations,
   into Anim's strict order and stage fields;
7. declares unsupported outputs honestly;
8. contains plots and standard output without hiding warnings; and
9. runs successfully as a fresh local process with network access denied.

Start from the generated worker scaffold:

```sh
ebm-audit adapter init /approved/local-config/my-ebm-worker
```

Then follow the [custom worker guide](custom-worker-guide.md). Do not rewrite the
model algorithm merely to satisfy Anim. An unavailable capability must remain
unavailable.

## 4. Compare before interpreting

Bind the validated reference manifest to the private audit configuration. Run
the synthetic and protocol checks before any approved participant-data work.
When the real local audit is authorized, compare the connected worker with the
frozen reference bundle.

`BASELINE_REPRODUCED` requires complete matching evidence. Missing diagnostics
or outputs can produce at most `BASELINE_PARTIALLY_REPRODUCED`. Similarity to a
paper figure or reported event order is never a reference result.

This handoff records where results came from and makes changes visible. It does
not prove that the original notebook, connected worker, EBM, dataset, or
scientific result is valid.
