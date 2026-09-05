# Real pysaebm worker example

See the shipped [adapter runbook](../../docs/handoff/adapter-runbook.md) for
provisioning, ordinary synthetic CLI runs, identity pinning and limitations.

This optional worker executes the real MIT-licensed pysaebm 7.7.9 source at
`54521a9adfedf58facd7bafd741a14d9ed110d2a`. `source-manifest.json` pins four exact
public files. `provision.py` is the explicit setup-only fetcher and offline
verifier. The worker never downloads source, calls a dataset loader or imports
the upstream package initializer. No EBM or optional dependency is loaded by
Anim's core process.

`worker.py` accepts an absolute `--source-dir` before the generic protocol
arguments. `synthetic_smoke.py` generates a new synthetic CSV and ordinary audit
config with identity pins. `requirements.txt` pins only the optional numerical
worker environment. `model.py` declares the complete supported surface.

Only the rescored native central order is exposed. Sampler uncertainty,
convergence, staging and scientific acceptance remain unavailable/not assessed.
All checked data is locally generated synthetic input.
