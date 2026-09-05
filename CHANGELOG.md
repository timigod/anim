# Changelog

All notable public changes to Anim are recorded here.

## 0.2.0.dev0 - Unreleased

- Adds worker identity pinning, capability negotiation, safe conformance
  diagnostics, generated starter tests, and a separately provisioned open-source
  EBM example using synthetic data and explicit source/version/license provenance.
- Adds local replay recipes that bind configuration, inputs, seeds, worker and
  environment; `rerun` refuses drift and starts a fresh complete attempt. The
  real pysaebm synthetic CLI run/rerun check completes both candidates with
  matching bindings and evidence while preserving the original files.
- Adds saved-report summaries and evidence-aware comparisons while preserving
  missing, invalid, failed and incomparable states and separate uncertainty types.
- Adds progress, cooperative cancellation and explicit memory admission for
  bounded execution without removing planned candidates or reusing stored results
  as live scientific evidence.
- Fixes report sealing for successful central-order-only workers without retained
  chains: analyst-decision evidence remains `NOT_ASSESSABLE` instead of crashing
  or inventing chain evidence.
- Adds development version consistency and distribution metadata, resource,
  integrity, and public-inventory validation.
- Adds fresh installed-wheel offline synthetic smoke and macOS/Linux CPython
  3.12 CI, including Linux containment-unavailable failure.
- Fixes contained adversary startup by launching the packaged worker entry point
  directly; tests verify exact rejection codes, intentional crash exits, and
  Linux cancellation on Python builds without `os.pidfd_open`.
- Preserves the immutable 0.1.1 release hashes and scientific claim boundaries.
  This development version has not been published.

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
