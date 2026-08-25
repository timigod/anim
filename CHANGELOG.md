# Changelog

All notable public changes to Anim are recorded here.

## 0.1.0 - 2026-08-25

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

Anim 0.1.0 does not certify a named EBM, dataset, disease sequence, diagnosis,
prognosis, treatment, causal result, regulatory status, or medical device.
