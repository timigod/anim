# How The Synthetic Route Works

This walkthrough follows a deliberately small `SYNTHETIC-ONLY` example with two
machine event IDs: `synthetic_event_a` and `synthetic_event_b`. It explains the
public worker boundary without showing participant rows, private names, raw
values, or a real EBM.

The example is illustrative. JSON blocks labelled **complete** validate against
required object and deliberately omit fields; they are not directly runnable.
The executable schemas remain authoritative:

- [`worker-protocol.schema.json`](../schemas/worker-protocol.schema.json)
- [`canonical-records.schema.json`](../schemas/canonical-records.schema.json)
- [`protocol-registry.json`](../schemas/protocol-registry.json)

## 1. Start With A Synthetic Request

The public demo creates a request bundle, invokes a local worker, and retains
only bounded metadata and artifacts. Numeric values are in `values.npz`, never
in JSON, stdout, warnings, or the default report.

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

`request.json` carries protocol metadata. The following **complete**
`SelfTestRequestPayload` is the smallest public request shape: `seed` makes the
synthetic check repeatable, `profile` fixes the small test profile, and
`requested_checks` names the checks the worker must report.

```json
{
  "seed": "000000000000002a",
  "profile": "tiny-synthetic/1",
  "requested_checks": ["schema-roundtrip", "offline-no-network"]
}
```

For a fit, the complete outer `WorkerRequest` also includes its command,
versioned schema identifiers, UUID, timestamps, offline flag, digests, payload,
schema fields are defined by `WorkerRequest` and `FitRequestPayload` in the
worker protocol; do not hand-assemble digests from this guide.

## 2. Describe The Two-Event Data Without Exposing Values

This **complete** `DatasetDescriptor` is a schema-valid metadata shape for two
synthetic events and two training rows. It names arrays in `values.npz` but does
not contain any numerical values. Every `sha256:` value below is a syntactically
valid placeholder for a digest that the auditor calculates from real local
content; it must never be copied as a claimed result.

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

`event_ids` provide stable alignment across request and result. `event_directions`
state which direction is treated as abnormal; do not infer them from a desired
order. `group_codebook` explains the integer group codes when the worker needs
them for its declared model input.

## 3. Use The Public Fit SDK

A researcher-owned executable imports `ebm_audit.worker_sdk`. It remains a
separate local process from the auditor core. The Fit callback receives the full
protocol request and its request directory:

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

Create the context only from that callback input. Direct `FitContext()`
construction is blocked because the SDK must validate and snapshot the exact
request before result authoring. The request contains the scientific input and
requested-output declaration; `values.npz` stays in the private request
directory rather than in the JSON request or default reports.

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

This is **illustrative synthetic transport code, not an EBM**. It uses a
placeholder digest and no participant values. Do not copy it as a scientific
model or report its two-event order as scientific evidence.

The adapter author supplies only facts their EBM actually produced: the central
order, requested standard outputs, method declaration, field origins, iteration
facts, any supported stage reference, artifacts, and warnings. The SDK derives
the request-bound identities, input accounting, capability applicability,
standard array member names and semantic versions, array catalog metadata,
resource defaults, result digest, and canonical `WorkerSuccess` transport
shape. It does not invent a scientific method, a field origin, a warning, an
array, or a fitted artifact.

`FitOutputs()` is safely empty. Optional `stage_model_reference` and
`backend_artifacts` also default to absent. Leave an output absent when the EBM
did not supply it; do not fill it with a zero, an empty estimate, or an inferred
value. The SDK then preserves the declared `UNAVAILABLE` or `NOT_APPLICABLE`
capability state instead of silently turning absence into pass or fail.

At the callback boundary, `fit_success()` returns one of these typed shapes:

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

Use a `WorkerFailure` for a truthful typed negative response. Its safe message
is core-owned, so backend exception prose, raw values, identifiers, and private
paths do not enter the default response.

`map_fit_result()` remains available for a separately prepared complete
canonical payload. Prefer the request-bound `FitContext.from_request()` plus
`FitOutputs` route in a normal Fit callback so the SDK can preserve the exact
request binding.

The worker executable is then framed by `WorkerApplication`. The generated
adapter uses this complete synthetic-only entry point:

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

That entry point is a protocol demonstration only. A research integration must
replace the complete identity, algorithm declaration, capabilities, settings,
limitations, validation, fit, and self-test behavior. It must not relabel the
synthetic fixture as a model.

## 4. Return A Canonical Result Or A Safe Failure

For the two-event order `[0, 1]`, a complete Fit result declares the array in
its `array_catalog`. This **complete** `ArrayCatalogEntry` is the metadata shape
for that in-memory `int32` array. The digest is illustrative and must be
calculated by the SDK in real use.

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

The first position `0` refers to `synthetic_event_a`; the second position `1`
refers to `synthetic_event_b`. This is an emitted synthetic order only. It is not
evidence that an order is scientifically recoverable.

If an output cannot be supplied, the worker returns a typed negative response.
This **complete** `NegativeResponseError` is a schema-valid example. Its safe
message is core-owned; it contains counts and no raw values, private paths, or
identifier material.

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
payload or this error. The protocol schema, not this guide, defines its full
closed shape. In active protocol v2, the executable commands are `describe`,
`validate`, `fit`, and `self-test`; standalone `stage` wire framing is reserved
and is not an active worker command.

## 5. Inspect The Audit Artifacts

`ebm-audit demo --conformance-ebm` writes local synthetic artifacts:

```text
ebm-audit-demo/
  report/
    report.html
    report.json
    universes.csv
    warnings.jsonl
```

`report.html` is the readable local view. `report.json` carries the structured
report state. `universes.csv` retains every candidate's terminal status, and
`warnings.jsonl` retains visible cautions and diagnostics. The current demo's
`PARTIAL`/`INCOMPLETE` state limits conclusions to the visible synthetic,
protocol, and capability evidence in those files.

For a researcher-owned EBM, begin with the [custom worker guide](handoff/custom-worker-guide.md).
A passing conformance receipt demonstrates protocol and declared-capability
behavior only. It does not make the EBM scientifically valid or accepted.
