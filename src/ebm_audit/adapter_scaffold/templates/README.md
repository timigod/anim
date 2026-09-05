# Start a local EBM worker

Use this project to connect an event-based model (EBM) to Anim. A worker is a
separate local process that receives Anim's requests and returns model results.
This starter runs offline and contains no participant rows or research model
dependency.

The included backend (the code supplying results) is a **SYNTHETIC-ONLY protocol
example**. It is not an
EBM, does not establish recoverable disease-order signal, and is not scientific
acceptance evidence. Replace its complete declaration and callbacks when you
integrate a research model; do not relabel its deterministic fixture as a model.

## First local check

Use the Python environment in which `ebm-audit` is already installed. No
network access or package installation is needed.

```sh
ebm-audit adapter describe --worker-config worker.yaml --output describe.json
```

Record the worker's code and environment identity with `pin`, then check that
the synthetic example follows the protocol:

```sh
ebm-audit adapter pin --worker-config worker.yaml
ebm-audit adapter check --worker-config worker.yaml --output check.json
```

The check result's `diagnostics` list identifies the next item to fix. A `PASS`
means only that the worker followed the protocol for the supported features
covered by the checks. It
is not scientific acceptance.

Add `--require-output order_samples` or `--require-capability deterministic_seed`
to require those features. Unsupported outputs and explicitly unavailable stages
are never reported as available. `pin` refuses an existing identity when the code or environment has changed.
Restore the original environment or use a fresh configuration for an intentional
upgrade. `pin --output pinned.yaml` writes a new configuration instead of rewriting
the original. Keep the old pin with its evidence; pinning does not establish trust.

Run the focused generated test with your existing local test runner:

```sh
pytest -q tests/test_worker.py
```

Before connecting a research backend, review and replace the complete identity,
algorithm declaration, capabilities, settings schema, limitations, validation,
fit, and self-test behavior. Keep participant data outside this project.

## Reference: generated files

- `worker.py` starts the worker process.
- `synthetic_example.py` contains the non-scientific example.
- `worker.yaml` selects the example and initially has no identity pin.
- `tests/test_worker.py` checks description, pinning, changes to pinned code or
  dependencies, seeded synthetic fits, rejection, and complete results in the
  required format through the installed CLI.
