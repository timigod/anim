# Run pysaebm on synthetic data

This optional worker runs an actual open-source event-based model (EBM) on
locally generated synthetic data. Follow the
[adapter runbook](../../docs/handoff/adapter-runbook.md#provision-then-run-offline)
to install the dependencies, verify the source, generate inputs, and run the
public CLI. The runbook also explains identity pinning and the model's limits.

Only the central event order is returned, after rescoring the orders visited by
the model. Sampling uncertainty, convergence, and participant staging are
unavailable. The checks use synthetic data only; scientific suitability and
clinical validity are not assessed.

## Reference: source and files

The worker executes the MIT-licensed pysaebm 7.7.9 source at
`54521a9adfedf58facd7bafd741a14d9ed110d2a`. `source-manifest.json` pins four exact
public files. `provision.py` is the explicit setup-only fetcher and offline
verifier. The worker never downloads source, calls a dataset loader or imports
the upstream package initializer. No EBM or optional dependency is loaded by
Anim's core process.

`worker.py` accepts an absolute `--source-dir` before the generic protocol
arguments. `synthetic_smoke.py` generates a new synthetic CSV and ordinary audit
config with identity pins: recorded hashes that identify the code and environment.
`requirements.txt` pins only the optional numerical worker environment.
`model.py` declares the supported inputs, settings, outputs, and limits.
