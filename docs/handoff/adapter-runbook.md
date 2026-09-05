# Adapter onboarding and the real pysaebm example

Anim 0.2.0.dev0 provides a generated worker project, identity pinning, explicit
capability checks, and an optional integration with real open-source EBM code.
All commands run locally. Provision dependencies before disconnecting; fitting,
checking, and reporting do not access the network, send telemetry, or use an LLM.

## Start a worker project

Use the Python 3.12 environment containing Anim:

```sh
ebm-audit adapter init my-worker
cd my-worker
ebm-audit adapter describe --worker-config worker.yaml
ebm-audit adapter pin --worker-config worker.yaml
ebm-audit adapter check --worker-config worker.yaml --output check.json
python -m pytest -q tests/test_worker.py
```

The generated backend remains a clearly labelled **synthetic-only protocol
example, not an EBM**. Its tests run real CLI subprocesses: description, unpinned
state, idempotent pinning, same/full-range seeds, invalid-setting and unsupported
output rejection, row alignment, complete results, and source-drift refusal.
Tests operate on copies so the developer's worker configuration is not modified.

`pin` fills a null identity with the observed immutable worker identity. It writes
a complete configuration atomically, with mode 0600, without following links or
overwriting a concurrently edited file. Existing matching pins are unchanged;
existing mismatching pins fail. Pinning identifies the code you chose to execute;
it does not establish that the code is trustworthy or scientifically suitable.

To preserve the original configuration, use:

```sh
ebm-audit adapter pin --worker-config worker.yaml --output pinned.yaml
```

`--output` here names a **new worker configuration**. The pin receipt goes to
stdout. For an intentional upgrade, create a fresh unpinned configuration and
retain the old configuration and receipts with their original evidence.

## Require the outputs you actually need

```sh
ebm-audit adapter check --worker-config pinned.yaml \
  --require-output central_order \
  --require-output order_samples \
  --require-capability deterministic_seed \
  --output check.json
```

The receipt includes the frozen-registry output requirements, missing
capabilities, worker constraints, settings validation, applicable synthetic
conformance results, and safe remediation. Unknown requirements and arbitrary
settings values are not echoed in diagnostics. No capability is inferred from a
numeric array. Fixed-evaluation absence uses the protocol's exact exception:
`NOT_APPLICABLE_BY_CAPABILITY` only when fixed-cohort staging is the sole missing
requirement. Otherwise it is `UNSUPPORTED`. An explicitly required absent output
never makes the check pass.

| Check status | Exit | Meaning |
| --- | --- | --- |
| `PASS` | 0 | Applicable protocol checks passed and requirements are available. |
| `INVALID` | 10 | Configuration, settings, or requirement IDs are invalid. |
| `UNSUPPORTED` | 11 | Required capability/output is absent. |
| `UNAVAILABLE` | 11 or 12 | Worker unavailable, unpinned, or required checks unverified. |
| `FAIL` | 15 | Executed protocol/identity checks failed. |

Privacy failures retain exit 14 and remain failures. A `PASS` is software and
declared-capability evidence; scientific acceptance stays `NOT_ASSESSED`.
`adapter conformance --output-dir ...` remains available for the detailed
existing versioned receipt. Restore the pinned source/environment after drift;
do not erase old pins to make a check green. Use the named remediation for fit
mapping, seed, row/event alignment, sampler indexing, or offline containment.

## Optional real EBM: pysaebm

The maintained example is in `workers/pysaebm_example` in the source distribution
and `ebm_audit/workers/pysaebm_example` in the wheel. It imports no EBM into the
auditor process. Its source/license manifest identifies:

| Identity | Exact value |
| --- | --- |
| Public source | <https://github.com/jpcca/pysaebm> |
| Revision | `54521a9adfedf58facd7bafd741a14d9ed110d2a` |
| Version in upstream `pyproject.toml` | `7.7.9` |
| Upstream license | MIT, Copyright 2024 Hongtao Hao & Joseph Austerweil |
| Executed source | `pysaebm/mh.py`, `pysaebm/utils.py` |
| Algorithm | Native `metropolis_hastings(algorithm="hard_kmeans", ...)` |

Every file's exact SHA-256 and byte length is recorded in
`source-manifest.json`. The setup utility fetches only those two Python files,
`LICENSE`, and `pyproject.toml` at that revision. It never fetches an upstream
repository archive, package archive, data module, notebook, example or dataset.
The original license file remains beside the source. Neither PyPI 7.7.7 nor a
different Git revision is interchangeable with this source. No private wrapper,
participant record, evaluator, or heldout material is needed.

The example loads only these authenticated modules using an isolated package
namespace, bypassing upstream `__init__` and its dataset/viz imports. NumPy,
SciPy, scikit-learn, numba and transitive worker dependencies have exact versions
in `requirements.txt`; these are optional worker dependencies, not core Anim
dependencies. No dependency sample loader is called. Identity inventories hash
worker/source bytes and dependency executable code/native libraries, explicitly
excluding dataset/test resources. Standard-library bytes and unrelated installed
packages are not a fully hermetic OS image; reproduce on the same Python and OS
when comparing exact results. Numba JIT is explicitly disabled so unchanged
upstream functions execute as Python without compilation or cache writes.

### Provision, then run offline

For a source checkout, set `EXAMPLE` to its absolute `workers/pysaebm_example`
directory. For an unpacked wheel installation:

```sh
EXAMPLE=$(python -c 'from importlib.resources import files; print(files("ebm_audit").joinpath("workers/pysaebm_example"))')
```

Use an environment with Anim installed. Provision the optional numerical
dependencies from a prepared local wheelhouse when working offline:

```sh
python -m pip install --no-index --find-links /path/to/worker-wheelhouse \
  -r "$EXAMPLE/requirements.txt"
```

Perform the explicit source fetch once while network access is available. The
parent directory must exist and the destination must be new or already contain
exactly the four pinned files:

```sh
python "$EXAMPLE/provision.py" /absolute/local/pysaebm-source
python "$EXAMPLE/provision.py" /absolute/local/pysaebm-source --verify
```

The verification command is completely offline. Do not install the upstream
package or download its datasets. Transfer these four files and the prepared
worker environment if operating on an offline machine.

Generate one ordinary public audit config with only locally generated synthetic
rows and a predeclared 64-versus-128 native-search-budget comparison:

```sh
python "$EXAMPLE/synthetic_smoke.py" /absolute/local/new-example \
  --source-dir /absolute/local/pysaebm-source
ebm-audit adapter check --worker-config /absolute/local/new-example/worker.json
ebm-audit run --config /absolute/local/new-example/audit.json --offline --profile quick
```

The output directory must be fresh. The generated `audit.json`, `worker.json`,
and `rows-07a19.csv` are ordinary inputs to the public CLI. `--baseline-only`
omits the budget comparison. Synthetic generation uses fixed PCG64 seed 20260905,
48 rows, 3 events and noisy stage-prefix means. It does not screen outcomes or
claim backend acceptance. Keep input filenames distinct from public scientific
terms: the frozen privacy scan rejects a private filename stem such as
`synthetic` when it also occurs in public semantics.

### What this integration returns

The wrapper canonicalizes events by ID and training traversal by role and value
before passing data to the unchanged upstream EBM. It converts the upstream
one-based **stage-at-event** order into Anim's zero-based **event-at-position**
permutation. It rescores the native visited orders with the upstream likelihood
at the returned fixed nuisance parameters/prior, chooses the maximum, and uses
the frozen lexicographic event-ID tie rule. This is a real model fit and a
bounded explored-order optimum, not exhaustive enumeration or guaranteed truth.

Only central order is exposed. The source's likelihood history is shifted and
its stage prior changes during fitting. The wrapper therefore does not advertise
order samples, canonical likelihood traces, convergence diagnostics, stage
posteriors, hard stages, fitted-artifact reuse or fixed-cohort staging. Their
absence remains typed; no zero uncertainty, passed convergence, or clinical
stage is invented. Search iterations are a worker setting. `mcmc: null` and the
protocol's unavailable no-chain projection describe this exposed result surface,
not a claim that upstream performs no stochastic search.

Limits are explicit: 8–2048 rows, 2–32 events, at least two rows in each declared
reference/at-risk role, 8–20000 search iterations, finite nonconstant event
columns, one worker thread. Missing values, invalid groups/settings and constant
events are rejected; numerical failures return `BACKEND_ERROR`. High budgets
may hit the caller's timeout. Strong synthetic-order recovery, repeated seeds,
row/event remapping, closed source provenance and generic protocol conformance
are verification surfaces. They are not robustness evidence across scientific
choices, no-signal calibration, backend acceptance, or clinical interpretation.

The real worker uses code-only diagnostics so rejected data values never enter
operator messages:

| Code | Action |
| --- | --- |
| `SPEC.PYSAEBM_SETTINGS` | Supply exactly `iterations`, `prior_n`, and `prior_v` within the described ranges. |
| `CAPABILITY.PYSAEBM_SIZE_LIMIT` | Check row/event counts against the declared constraints. |
| `CAPABILITY.MISSING_VALUES` | Supply a complete finite input through an explicitly declared preparation choice; the worker does not impute. |
| `DATA.PYSAEBM_GROUP_ROLES` / `DATA.GROUP_CODE_UNDECLARED` | Map every group to exactly the declared reference or at-risk role. |
| `DATA.PYSAEBM_GROUP_SIZE` | Supply at least two rows in each role; retain the rejection for ineligible universes. |
| `DATA.PYSAEBM_CONSTANT_EVENT` | A selected event is constant; use an explicitly declared event-set choice or retain the failed universe. |
| `BACKEND.PYSAEBM_NUMERICAL_FAILURE` | Retain the failure. Inspect the synthetic setup and declared choices; no order or convergence claim was produced. |
| `EXAMPLE.SETUP_INVALID` | Run the offline source verifier and check the exact requirements in the worker environment. |

Run the optional maintained tests against already provisioned sources:

```sh
ANIM_PYSAEBM_SOURCE_DIR=/absolute/local/pysaebm-source \
  python -m pytest -q tests/adapters
```

These tests do not fetch anything. Without the optional source/environment,
real-backend tests are explicitly skipped; generated-starter and pin/check tests
still run. macOS or a supported Linux containment host is required for execution
checks; Windows execution remains unsupported.
