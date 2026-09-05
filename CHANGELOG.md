# Changelog

All notable public changes to Anim are recorded here.

## 0.2.0 - 2026-09-06

See [what changed in 0.2.0](docs/handoff/whats-new-0.2.md) for a plain-English
explanation and the limits of each addition.

- Makes it easier to connect a model: the worker starter includes runnable tests,
  `adapter pin` records the intended software, and `adapter check` tests the
  connection and requested outputs.
- Adds an optional example using the open-source pysaebm model on synthetic data.
  It returns an estimated event order; sampling and staging uncertainty remain
  unavailable. Its source, version, and licence are documented.
- Adds `rerun` to repeat a complete analysis plan in a new directory after checking
  the original data, settings, seeds, software, and environment. Changed inputs
  or software prevent an exact repeat; earlier results stay intact.
- Adds `summary` and `diff` to inspect and compare saved audits. Missing, invalid,
  failed, and incomparable results remain distinct from measured agreement.
- Makes the HTML report easier to read, with counts and sizes of differences
  across declared choices. Comparisons of single selected event orders are shown
  separately from uncertainty within a model fit.
- Adds progress messages, cancellation with process cleanup, and a memory
  allowance for scheduling concurrent model runs. Cancellation preserves saved
  results; memory settings change concurrency without dropping planned analyses.
- Fixes a report crash when a successful model returns an event order without
  retained samples. Checks that need those samples now remain `NOT_ASSESSABLE`.
- Fixes Linux test-worker startup and cancellation checks, including Python builds
  without `os.pidfd_open`. Isolates optional numerical-library tests so they do
  not change the environment of unrelated tests.
- Checks package versions, contents, and hashes, and tests fresh offline package
  installations on macOS and Linux with CPython 3.12. Tests also check that Anim
  refuses model execution when the required Linux sandbox is unavailable.
- Publishes the validated packages to PyPI and GitHub through the release
  workflow. Earlier 0.1.1 release files and their recorded hashes are unchanged.

## 0.1.1 - 2026-08-25

Initial public release candidate.

- Provides the backend-neutral `ebm-audit` command and `ebm_audit.worker_sdk`
  Python interface.
- Runs local, offline robustness audits through a versioned external-worker
  protocol.
- Keeps model uncertainty, sampling, preprocessing, participant influence, and
  no-signal evidence separate.
- Preserves unavailable, not-applicable, invalid, and failed evidence instead of
  converting missing information into a result.
- Produces deterministic local JSON, CSV, and self-contained HTML reports.
- Includes a synthetic-only conformance worker, researcher worker scaffold,
  input guide, offline-kit guide, and private-notebook handoff route.

Anim 0.1.1 does not certify a named EBM, dataset, disease sequence, diagnosis,
prognosis, treatment, causal result, regulatory status, or medical device.
