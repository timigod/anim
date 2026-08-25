# Start here: local EBM adapter

This project is a readable, local worker starting point for the EBM Robustness
Auditor. It runs offline and contains no participant rows or research-backend
dependency.

The included backend is a **SYNTHETIC-ONLY transport example**. It is not an
EBM, does not establish recoverable disease-order signal, and is not scientific
acceptance evidence. Replace its complete declaration and callbacks when you
integrate a research model; do not relabel its deterministic fixture as a model.

## Files

- `worker.py` is the subprocess entry point.
- `synthetic_example.py` is the clearly labelled non-scientific example.
- `worker.yaml` selects the example and starts with no immutable identity pin.
- `tests/test_worker.py` checks the generated project through the installed CLI.

## First local check

Use the Python environment in which `ebm-audit` is already installed. No
network access or package installation is needed.

```sh
ebm-audit adapter describe --worker-config worker.yaml --output describe.json
```

Copy `selected_expected_identity` from `describe.json` into
`expected_identity` in `worker.yaml`, then run the one conformance command:

```sh
ebm-audit adapter conformance --worker-config worker.yaml --output-dir conformance
```

The receipt's `first_actionable_failure` is the next item to fix. A `PASS`
means only that the declared protocol and applicable capabilities conform. It
is not scientific acceptance.

Run the focused generated test with your existing local test runner:

```sh
pytest -q tests/test_worker.py
```

Before connecting a research backend, review and replace the complete identity,
algorithm declaration, capabilities, settings schema, limitations, validation,
fit, and self-test behavior. Keep participant data outside this project.
