# How Anim runs a synthetic audit

Run `ebm-audit demo --conformance-ebm` to see how Anim sends work to a local
worker and produces a report from its responses. The demo uses generated data
labelled `SYNTHETIC-ONLY`. It tests communication and declared capabilities;
it does not fit a researcher's event-based model (EBM) or establish scientific
validity.

## Run the demo and inspect its output

The demo writes these local files:

```text
ebm-audit-demo/
  warnings.jsonl
  report/
    report.html
    report.json
    universes.csv
```

Open `report.html` for the readable report. `report.json` contains the structured
report state. `universes.csv` records the final status of every **candidate**,
meaning each planned analysis. A **universe** describes the prepared data,
settings and seeds for an analysis that can proceed. `warnings.jsonl` records
cautions and diagnostics.

The current demo returns `PARTIAL`/`INCOMPLETE`. Conclusions must stay within
the synthetic, protocol and capability evidence actually present in those
files. A passing conformance check shows that a worker follows the communication
protocol and its declared capabilities. It does not establish that the EBM is
scientifically valid or accepted.

Use `ebm-audit summary --run-dir ebm-audit-demo` to inspect the saved report.
[Report comparison](report-comparison.md) explains `diff`, comparisons of orders
supplied by the backend, and uncertainty measurements that remain unavailable.
These commands inspect existing files; they do not create a new scientific
report.

For a researcher-owned EBM, start with the
[custom worker guide](handoff/custom-worker-guide.md). The
[adapter runbook](handoff/adapter-runbook.md) covers `adapter pin`, `adapter check`,
generated tests and a separately installed pysaebm example that runs actual
upstream model code on generated synthetic rows.

For ordinary saved configurations, [reproducibility](reproducibility.md) covers
`rerun`, which executes the full plan again, and
[execution controls](execution.md) cover progress, cancellation and declared
memory reservations. The demo's temporary configuration does not produce a
replay recipe.

## Reference: request and result examples

The rest of this guide follows two synthetic event IDs, `synthetic_event_a` and
`synthetic_event_b`, through the worker protocol. It contains no participant
rows, private names, raw input values or real EBM implementation.

JSON blocks labelled **complete** contain all fields for their named schema
definition, not a complete worker message. Python snippets use placeholders and
are not directly runnable model integrations. The executable schemas define
which fields and values are accepted:

- [`worker-protocol.schema.json`](../schemas/worker-protocol.schema.json)
- [`canonical-records.schema.json`](../schemas/canonical-records.schema.json)
- [`protocol-registry.json`](../schemas/protocol-registry.json)

### 1. Send a request to the worker

Anim creates a request directory and invokes a separate local worker process.
The worker returns files in a response directory. Anim checks these files and
retains the permitted metadata and artifacts within its size limits.
Participant input values stay in `values.npz`; they must not appear in JSON,
stdout, warnings or the default report.

```text
invocation/
  request/
    request.json
    values.npz
  response/
    arrays.npz              # present only when result arrays exist
    warnings.jsonl
    side-effects.json
    response.json           # completion marker, written last
```

`request.json` carries protocol metadata. This **complete**
`SelfTestRequestPayload` is the smallest public request shape: `seed` makes the
synthetic check repeatable, `profile` selects the small test profile, and
`requested_checks` names the checks the worker must report.

```json
{
  "seed": "000000000000002a",
  "profile": "tiny-synthetic/1",
  "requested_checks": ["schema-roundtrip", "offline-no-network"]
}
```

A fit request needs the complete outer `WorkerRequest`, including its command,
versioned schema identifiers, UUID, timestamps, offline flag, digests (hashes
used to identify content), payload and input file references. `WorkerRequest`
and `FitRequestPayload` in the worker protocol define those fields. Do not
hand-assemble digests from this guide.

### 2. Describe the data without exposing participant values

This **complete** `DatasetDescriptor` shows metadata for two synthetic events
and two training rows. It names arrays in `values.npz` without including their
values. Each `sha256:` value is a syntactically valid placeholder. In a real
run, the auditor calculates digests from local content; these placeholders must
never be copied as claimed results.

```json
{
  "variant_id": "synthetic-two-event",
  "participant_count": 2,
  "evaluation_participant_count": 0,
  "event_count": 2,
  "event_ids": ["synthetic_event_a", "synthetic_event_b"],
  "event_directions": ["higher", "lower"],
  "group_codebook": {"0": "reference", "1": "at_risk"},
  "training_row_index_array": "training_row_indexes",
  "evaluation_row_index_array": null,
  "array_catalog": {
    "train_values": {
      "member_name": "train_values",
      "dtype": "float64",
      "shape": [2, 2],
      "semantic_version": "event-value-matrix/1",
      "byte_length": 32,
      "array_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "training_row_indexes": {
      "member_name": "training_row_indexes",
      "dtype": "int64",
      "shape": [2],
      "semantic_version": "internal-row-index/1",
      "byte_length": 16,
      "array_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  },
  "stage_semantics": "strict-prefix-count/1",
  "stage_semantics_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "preprocessing_manifest_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "scientific_data_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "synthetic_provenance": {
    "schema_version": "ebm-audit-synthetic-provenance/1.0",
    "classification": "SYNTHETIC-ONLY",
    "generator_id": "conformance-generator",
    "generator_version": "1.0.0",
    "generator_record_sha256": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "generated_input_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "complete_truth_sha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "complete_truth_record_id": "conformance-truth",
    "scenario_id": "strict-sequence",
    "replicate": 0,
    "seed": "000000000000002a",
    "source_kind": "PROJECT_OWNED_DETERMINISTIC_GENERATOR",
    "participant_data_present": false,
    "external_source_present": false,
    "participant_count": 2,
    "event_count": 2,
    "event_ids": ["synthetic_event_a", "synthetic_event_b"]
  }
}
```

`event_ids` keep events aligned between request and result. `event_directions`
state which direction is treated as abnormal; do not infer them from a desired
order. `group_codebook` explains the integer group codes when the worker needs
them as declared model input.

### 3. Implement a Fit callback with the worker SDK

The worker executable imports `ebm_audit.worker_sdk`, Anim's software development
kit for worker integrations. The worker remains a separate local process from
the auditor. Its Fit callback receives the full protocol request and the
request directory:

```python
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ebm_audit.worker_sdk import WorkerFailure, WorkerSuccess


def fit(request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess | WorkerFailure:
    # `request` is the complete protocol-v2 Fit request: header, payload, file
    # inventory, request bindings, and references to local request artifacts.
    # Do not rebuild its digests or copy raw values into logs.
    ...
```

Create `FitContext` only from that callback input. Direct `FitContext()`
construction is blocked because the SDK must validate and keep an unchanged
copy of the exact request before it builds a result. The request describes the
scientific input and requested outputs; the values themselves remain in the
private `values.npz` file.

```python
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

from ebm_audit.worker_sdk import FitContext, FitOutputs, WorkerFailure, WorkerSuccess


def fit(request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess | WorkerFailure:
    context = FitContext.from_request(request, request_dir)

    # Replace these synthetic transport values with output from your EBM.
    # The arrays shown must be ones the request actually asks the worker for.
    return context.fit_success(
        central_order=np.asarray([0, 1], dtype=np.int32),
        outputs=FitOutputs(
            position_probabilities=np.asarray(
                [[0.75, 0.25], [0.25, 0.75]], dtype=np.float64
            ),
        ),
        central_order_method={
            "method_id": "backend-objective-maximum/1",
            "candidate_source": "backend_explored_order_set",
            "objective_id": "synthetic-transport-objective-v1",
            "tie_break_rule": "lexicographically-smallest-event-id-sequence/1",
        },
        field_origins={
            "central_order_permutation": {
                "origin": "WORKER_DERIVED",
                "method_id": "synthetic-transport-order-v1",
                "source_fields": ["seed", "event_ids"],
                "source_hashes": ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            },
            "position_probabilities": {
                "origin": "WORKER_DERIVED",
                "method_id": "synthetic-transport-position-probability-v1",
                "source_fields": ["seed", "event_ids"],
                "source_hashes": ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            },
        },
        raw_iteration_count=None,
        burn_in_count=None,
        thinning_interval=None,
        postburn_unthinned_state_count=None,
        retained_state_count=None,
        likelihood_indexing=None,
        actual_transition_count=None,
        actual_transition_fraction=None,
        warnings=(),
    )
```

This is **illustrative synthetic communication code, not an EBM**. It uses a
placeholder digest and no participant values. Do not copy it as a scientific
model or report its two-event order as scientific evidence.

Supply only facts the EBM produced: its central order (the representative event
order chosen by the declared method), requested standard outputs, method
declaration, field origins (how each result was obtained), iteration facts,
any supported stage reference, artifacts and warnings.

The SDK calculates the identities linking the result to the request, input
accounting, capability applicability, standard array names and semantic versions,
array catalog metadata, resource defaults, result digest and standard
`WorkerSuccess` response. It does not invent a scientific method, field origin,
warning, array or fitted artifact.

`FitOutputs()` is empty by default. Optional `stage_model_reference` and
`backend_artifacts` are also absent by default. Leave an output absent when the
EBM did not supply it; do not fill it with zero, an empty estimate or an inferred
value. The SDK preserves the declared `UNAVAILABLE` or `NOT_APPLICABLE`
capability state instead of converting absence to a pass or fail.

`fit_success()` returns one of these structured result types:

```text
WorkerSuccess(
  payload=<SDK-built canonical Fit payload>,
  arrays={"central_order_permutation": <int32 array>, ...},
  warnings=(<safe, explicit warning records>, ...),
)

WorkerFailure(
  status="UNSUPPORTED_CAPABILITY",
  code="CAPABILITY.OUTPUT_UNSUPPORTED",
  safe_message=<core-owned safe message>,
  phase="capability-validation",
  counts={"unsupported_output_count": 1},
)
```

Use `WorkerFailure` to report an actual failure or unsupported capability with
its defined status and code. Anim supplies the safe message, so backend
exception text, raw values, identifiers and private paths do not enter the
default response.

`map_fit_result()` remains available if you have separately prepared a complete
payload in Anim's standard format. For a normal Fit callback, prefer
`FitContext.from_request()` with `FitOutputs` so the SDK keeps the result linked
to the exact request.

`WorkerApplication` handles the command and response protocol around the
backend. The generated adapter uses this complete synthetic-only entry point:

```python
from pathlib import Path

from ebm_audit.worker_sdk import (
    SyntheticProtocolExampleBackend,
    WorkerApplication,
    build_synthetic_protocol_identity,
)

identity = build_synthetic_protocol_identity(
    adapter_id="generated-synthetic-only-adapter",
    backend_name="generated-synthetic-only-protocol-example",
    code_paths=[Path(__file__).resolve()],
)
raise SystemExit(WorkerApplication(SyntheticProtocolExampleBackend(identity)).run())
```

This entry point demonstrates the protocol. A research integration must replace
the complete identity, algorithm declaration, capabilities, settings,
limitations, validation, fit and self-test behavior. It must not relabel the
synthetic test implementation as a model.

### 4. Return a standard result or a safe failure

For the two-event order `[0, 1]`, a complete Fit result describes its array in
`array_catalog`. This **complete** `ArrayCatalogEntry` describes that in-memory
`int32` array. The digest is illustrative; the SDK calculates it in real use.

```json
{
  "member_name": "central_order_permutation",
  "dtype": "int32",
  "shape": [2],
  "semantic_version": "event-index-at-position/1",
  "byte_length": 8,
  "array_digest": "sha256:9999999999999999999999999999999999999999999999999999999999999999"
}
```

The first entry, `0`, refers to `synthetic_event_a`; the second, `1`, refers to
`synthetic_event_b`. This emitted synthetic order does not show that a true
order can be recovered scientifically.

If an output cannot be supplied, the worker returns a defined negative response.
This **complete** `NegativeResponseError` is a schema-valid example. Anim
supplies its safe message; it includes counts but no raw values, private paths
or identifying information.

```json
{
  "code": "CAPABILITY.OUTPUT_UNSUPPORTED",
  "category": "UNSUPPORTED_CAPABILITY",
  "safe_message": "One or more requested outputs are unavailable.",
  "phase": "capability-validation",
  "retryable_identical_request": false,
  "issues": [],
  "details": {
    "counts": {"unsupported_output_count": 1},
    "internal_indexes": [],
    "approved_event_ids": [],
    "digests": {}
  }
}
```

The complete outer `WorkerResponse` adds request/response metadata, backend
identity, capabilities, resource summary, file map, timing, and either a
payload or this error. The protocol schema defines the full set of allowed
fields. In active protocol v2, executable commands are `describe`, `validate`,
`fit` and `self-test`. Standalone `stage` message framing is reserved and is not
an active worker command.
