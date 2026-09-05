# Optional downstream real-data integration handoff

## Read this first

This is an optional downstream-use guide, not a product release gate. The only
product readiness state is exactly
`READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY`.
Participant data, a named backend, and reproduction of the paper analysis are
never required for product completion.

After library readiness, a researcher may choose to use real data only inside
the researcher's approved local or institutional environment. That separate
decision requires local permission, a reviewed worker, and the applicable
privacy, offline, scientific, and governance checks. Nothing in this guide
authorizes participant-data use.

No participant data need be sent to the project team. All mapping, validation,
model execution, reference comparison, and eventual report generation are
intended to run inside the researcher's approved local or institutional
environment.

The current `ebm-audit report` command intentionally does not rehydrate a
persisted report. It returns exit code `10` with error code
`REPORT.V1_DISABLED`, without reading the run directory or touching the output
path. The Python API exception carries the typed reason
`PERSISTED_SCIENCE_V2_REHYDRATION_UNAVAILABLE`; the CLI keeps its stable `code`
and `safe_message` error shape. It writes no artifact. The `ebm-audit run`
process may write a local HTML/JSON/CSV report only from its exact live evidence;
that report says `INCOMPLETE`, emits no final manifest, and is not product
readiness evidence.

Anim 0.2.0 adds `summary` and `diff` for bounded inspection
of saved report artifacts and `rerun` for a fresh complete attempt from an
ordinary configuration. These commands do not rehydrate scientific authority.
The sibling `<run-name>.operations/replay.json` is an operational recipe, separate
from the unavailable final scientific manifest. See [report comparison](../report-comparison.md),
[reproducibility](../reproducibility.md), and [execution controls](../execution.md).

The tool audits declared sensitivity. It does not establish a true disease
sequence, diagnosis, prognosis, treatment effect, causal mechanism, clinical
validation, regulatory status, or medical-device status.

## Current command truth

This records the package journey and command syntax used by this optional
downstream guide. "Current" means that the exact form is accepted by the parser;
it does not define product readiness or authorize participant-data use.

| Optional downstream route | Parser status | Current outcome and boundary |
| --- | --- | --- |
| `doctor` | Current | Produces a scoped local pre-execution receipt. It is not a product-readiness decision. |
| `init --template synthetic`, `init --template idris-2025-public` | Current | Create the selected `AuditConfig/0.3` starter from the four required path options. The Idris route is a structural public mapping aid only: it contains no real rows, published event order, reproduced model, or product-readiness claim. |
| `adapter describe`, `adapter conformance` | Current | Inspect a local worker and run the implemented public synthetic protocol cases. They are the generic integration route, but a passing receipt does not establish scientific suitability for an optional real-data use. |
| `adapter pin`, `adapter check` | Current | Pin an exact worker identity and negotiate required outputs/capabilities with synthetic conformance. Drift and unavailable requirements remain explicit failures. |
| `validate` | Current | Validates the configured local input and authenticated worker without fitting. A valid receipt does not authorize optional real-data use. |
| `plan` | Current | Compiles a safe plan summary without fitting. It does not decide the local scientific, privacy, offline, or governance checks for optional real-data use. |
| `run` | Current but incomplete | Executes the configured candidate set. Its live report remains `INCOMPLETE`, it emits no final manifest, and a candidate-complete run exits `12` while the science gate is `BLOCKED`. |
| `report` | Current typed refusal | Parses, then returns `REPORT.V1_DISABLED` before reading the run directory or touching the output directory. |
| `summary`, `diff` | Current | Inspect schema/hash-bound saved report artifacts and compare values, identities and typed states. No fitting or scientific rehydration. |
| `rerun` | Current | Validate an ordinary run's recipe against its original configuration, input, worker and runtime, then refit its whole plan into a fresh root. Existing results are preserved. |
| `baseline-reference init`, `baseline-reference validate` | Current | Creates a deliberately non-importable private draft/notebook example, or validates an exported three-file reference bundle offline. Neither command fits a model or changes product readiness. |
| `benchmark --profile ...` | Unavailable | Historical unavailable parser spelling retained as package-journey context. It is not the generic conformance route or a product-readiness condition. |

The commands inside the following marked block are the copyable current parser
contract examples. Paths are local examples and must remain outside the
repository when they refer to private configuration or output.

<!-- cli-current-commands:start -->
```bash
uv run ebm-audit doctor --worker-config /approved/local-config/model-worker.yaml
uv run ebm-audit init --template synthetic --output /approved/local-config/synthetic-audit/audit.yaml --input-path data/synthetic.csv --worker-config-path worker/model-worker.yaml --run-root runs/synthetic-audit
uv run ebm-audit init --template idris-2025-public --output /approved/local-config/idris-audit/audit.yaml --input-path data/local.csv --worker-config-path worker/model-worker.yaml --run-root runs/local-audit
uv run ebm-audit adapter describe --worker-config /approved/local-config/model-worker.yaml --offline --output /approved/local-output/worker-describe.json
uv run ebm-audit adapter conformance --worker-config /approved/local-config/model-worker.yaml --offline --output-dir /approved/local-output/worker-conformance
uv run ebm-audit baseline-reference init --output-dir /approved/local-config/baseline-reference-draft
uv run ebm-audit baseline-reference validate --manifest /approved/local-config/baseline-reference/reference-bundle.json --offline --output /approved/local-output/baseline-reference-validation.json
uv run ebm-audit validate --config /approved/local-config/idris-audit/audit.yaml --offline --output /approved/local-output/validation.json
uv run ebm-audit plan --config /approved/local-config/idris-audit/audit.yaml --offline --profile quick --output /approved/local-output/quick-plan.json
uv run ebm-audit run --config /approved/local-config/idris-audit/audit.yaml --offline --profile quick --timeout 30
uv run ebm-audit report --run-dir /approved/local-output/runs/local-audit --output-dir /approved/local-output/regenerated-report
```
<!-- cli-current-commands:end -->

The following historical spellings are machine-checked unavailable examples,
not commands to run or product release instructions:

<!-- cli-unavailable-commands:start -->
```text
ebm-audit benchmark --profile quick
ebm-audit benchmark --profile full
ebm-audit benchmark --profile release
```
<!-- cli-unavailable-commands:end -->

This parser contract does not authorize participant-data use and does not add a
second readiness state.

## 1. Prepare an approved local workspace

Before opening any participant file:

1. Confirm institutional permission, storage location, access controls, backup,
   retention, and deletion requirements.
2. Obtain the auditor source/package, its exact lock, and the chosen worker through
   an approved transfer route.
3. Verify the candidate version/commit and acquired-artifact hashes from the
   library handoff.
4. Install the core and worker dependencies while participant data are not open.
5. Put the participant input, optional reference bundle, run output, and any
   reversible mapping outside the Git repository and private corpus.
6. Use an approved encrypted local disk. A synced consumer folder is not an
   acceptable default.

The current source-install route is:

```bash
uv sync --frozen --offline
uv run ebm-audit doctor
```

The current prebuilt-wheel route is:

```bash
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python --no-index \
  --find-links /approved/local-wheelhouse \
  /approved/local-wheelhouse/anim-<version>-py3-none-any.whl
.venv/bin/ebm-audit doctor
```

Auditor commands are always offline and do not expose a flag that can turn
network access on. This is not a substitute for an institutionally enforced
network boundary. Acquire dependencies before the participant-data session. Do
not add a package index or remote URL to make an offline install succeed.

Current doctor output is a local machine-readable receipt with only
`command_result_schema_version`, `status`, `offline`, `network_calls`,
`scientific_worker_commands_run`, `check_count`, `failure_count`, and `checks`.
Each check row has `check_id` and `status`, and can include `failure_code` or
`checked_count`. Without optional flags, it checks the Python runtime, auditor
package, offline no-network posture, and package/normative resources. `--root`,
`--worker-config`, and the historical optional backend-specific
`--require-pysaebm` flag add only their respective scoped local checks. That
legacy flag is not a product dependency or evidence that the package was the
paper implementation. The receipt does not print private paths or emit version
values, backend
identity/environment, detailed writable-path evidence, protocol self-test state,
or benchmark-contract version/hash.

Those richer fields are outside the current `doctor` behavior. A passing doctor
receipt is only a scoped local pre-execution check; it neither establishes
product readiness nor authorizes optional participant-data use.

## 2. Install or expose the model worker

The worker is the local command that fits the researcher's EBM. The generic route
is a custom worker wrapping the implementation selected for that integration.

Historical package-probe context only: an earlier handoff investigated a
`pysaebm` worker at source commit
`54521a9adfedf58facd7bafd741a14d9ed110d2a`, source version `7.7.9`, and found
PyPI `7.7.7` non-equivalent. This records the package journey only. It does not
identify the paper implementation, designate an accepted backend, or create a
product-completion dependency.

The current worker description and conformance commands are:

```bash
uv run ebm-audit adapter describe \
  --worker-config /approved/local-config/model-worker.yaml \
  --offline \
  --output /approved/local-output/worker-describe.json

uv run ebm-audit adapter conformance \
  --worker-config /approved/local-config/model-worker.yaml \
  --offline \
  --output-dir /approved/local-output/worker-conformance
```

The worker configuration must store an argument vector, not a shell-interpolated
command. It must not contain credentials, participant identifiers, raw values, or
remote endpoints. A custom/private worker can remain in the researcher's
environment; the auditor needs the protocol output, not its source. See
[`custom-worker-guide.md`](custom-worker-guide.md).

Do not proceed if the worker's backend identity, environment digest, declared
capabilities, deterministic seed behavior, offline check, identifier-leak scan,
or canonical result invariants fail.

## 3. Create a local mapping configuration

Use the field-by-field
[`input-data dictionary`](input-data-dictionary.md) while mapping the local
table. It states the exact CSV, column-role, missingness, and no-silent-change
contract without including any private column name or participant row.

The current `init` command exposes both installed starters. The synthetic route
creates the strict synthetic mapping template:

```bash
uv run ebm-audit init \
  --template synthetic \
  --output /approved/local-config/synthetic-audit/audit.yaml \
  --input-path data/synthetic.csv \
  --worker-config-path worker/model-worker.yaml \
  --run-root runs/synthetic-audit
```

The Idris route creates the installed structural public mapping aid:

```bash
uv run ebm-audit init \
  --template idris-2025-public \
  --output /approved/local-config/idris-audit/audit.yaml \
  --input-path data/local.csv \
  --worker-config-path worker/model-worker.yaml \
  --run-root runs/local-audit
```

The Idris starter contains no real rows, private column names, published or
expected event order, or reproduced model. Every local mapping, event direction,
identifier review, and placeholder digest still requires confirmation. Creating
this structural starter does not establish product readiness or authorize
optional participant-data use.

Edit the generated configuration locally. At minimum map and confirm:

- the private participant-ID source column;
- one row per participant;
- each event's private source column and stable machine ID;
- each event's display name, unit if known, and abnormal direction;
- the exact reference/control-like and at-risk/progressing group labels or rule;
- covariates and the explicit residualisation choice, if any;
- an executable missingness policy (`error` or explicit `complete-case`); if the
  research requires an external data variant, record that as a blocker until
  the reserved capability is implemented and verified;
- outlier policy and its exact scope;
- baseline event set and any predeclared sensitivity sets;
- worker identity/settings, chains, seeds, burn-in, thinning, and resource limits;
- local input, output, and temporary paths; and
- the rationale/source for every enabled analysis choice.

Do not put private column names or paths into this repository, a corpus note, chat,
or a public ticket. The local configuration and resolved copy are sensitive.

Any event direction marked `REQUIRES_CONFIRMATION` permits plan/validation only;
it must block a real fit. Do not infer direction from the published event order.
The paper's age-defined groups are an example, not a default scientific truth.
Do not silently import ancillary MICE, PCA, GAM, or LOESS processing into the EBM
configuration.

### SYNTHETIC-ONLY structural-mapping witness

This copyable M04 witness proves only that the installed scaffold can be pinned
and mapped into `AuditConfig/0.3` without fitting. It uses six synthetic
participants and two synthetic events. It is not an EBM, a scientific result,
real-data evidence, or permission to use participant data.

Create one fresh private workspace. `umask 077` makes new files private; the
final two commands enforce mode `0700` on every directory and `0600` on every
file, including `audit.yaml`, the synthetic CSV, and all worker files. If a
command is interrupted before it returns a typed result, do not reuse that
partial workspace: rerun this opening block to create a new one.
The neutral private filename `table-01.csv` is intentional: private path tokens
must not repeat public adapter or algorithm identity text.

```bash
umask 077
TEMP_BASE="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
ROOT="$(mktemp -d "$TEMP_BASE/ebm-audit-m04-structural.XXXXXXXX")"
chmod 700 "$ROOT"
install -d -m 700 "$ROOT/data" "$ROOT/receipts"

uv run ebm-audit adapter init "$ROOT/worker"
uv run ebm-audit init \
  --template synthetic \
  --output "$ROOT/audit.yaml" \
  --input-path data/table-01.csv \
  --worker-config-path worker/worker.yaml \
  --run-root runs/structural-map

cat >"$ROOT/data/table-01.csv" <<'CSV'
participant_code,group,event_01,event_02,covariate_01,metadata_01,ignored_01
syn-001,reference,-2.0,2.0,20.0,1,a
syn-002,reference,-1.0,1.0,30.0,2,b
syn-003,reference,-0.5,0.5,40.0,3,c
syn-004,at-risk,0.5,-0.5,50.0,4,d
syn-005,at-risk,1.0,-1.0,60.0,5,e
syn-006,at-risk,2.0,-2.0,70.0,6,f
CSV

find "$ROOT" -type d -exec chmod 700 {} +
find "$ROOT" -type f -exec chmod 600 {} +
```

Describe the unpinned scaffold, then copy its complete
`selected_expected_identity` into `worker.yaml`. The Python step also
authenticates that pin, computes exact `sha256:<hex>` digests from the CSV bytes
and the final pinned `worker.yaml` bytes, and maps the selected worker into the
exact current configuration fields. It requests only `central_order`, sets
the authenticated adapter-owned MCMC projection as one complete seedless chain
slot, and keeps only the baseline experiment.

```bash
uv run ebm-audit adapter describe \
  --worker-config "$ROOT/worker/worker.yaml" \
  --offline \
  --output "$ROOT/receipts/worker-describe.json"

ROOT="$ROOT" uv run python - <<'PY'
import csv
import json
import os
from collections import Counter
from pathlib import Path

import yaml

from ebm_audit.adapters import WorkerCommand, WorkerInvoker
from ebm_audit.protocol import (
    exact_file_sha256,
    requested_outputs_digest,
    settings_digest,
    settings_schema_digest,
)

root = Path(os.environ["ROOT"])
worker_path = root / "worker" / "worker.yaml"
describe_path = root / "receipts" / "worker-describe.json"
audit_path = root / "audit.yaml"
input_path = root / "data" / "table-01.csv"

describe_receipt = json.loads(describe_path.read_text(encoding="utf-8"))
expected_identity = describe_receipt["selected_expected_identity"]
worker_config = yaml.safe_load(worker_path.read_text(encoding="utf-8"))
worker_config["expected_identity"] = expected_identity
worker_path.write_text(
    yaml.safe_dump(worker_config, sort_keys=False),
    encoding="utf-8",
)
worker_path.chmod(0o600)

command = WorkerCommand.from_tokens(tuple(worker_config["worker"]["argv"]))
description = WorkerInvoker(
    command,
    expected_identity=expected_identity,
).describe_authenticated()
algorithm = next(
    row
    for row in description.supported_algorithms
    if row["algorithm_id"] == worker_config["algorithm_id"]
)
base_identity = expected_identity["base_backend_identity"]
settings = worker_config["settings"]
requested_outputs = ["central_order"]

audit = json.loads(audit_path.read_text(encoding="utf-8"))
input_digest = exact_file_sha256(input_path.read_bytes())
audit["input"]["expected_byte_digest"] = input_digest
audit["input"]["variant"]["source_digest"] = input_digest
audit["worker"]["worker_config_digest"] = exact_file_sha256(worker_path.read_bytes())
audit["worker"]["worker_identity_digest"] = expected_identity[
    "selected_backend_identity_digest"
]
audit["baseline_analysis"]["backend"].update(
    {
        "adapter_id": base_identity["adapter_id"],
        "adapter_semantics_digest": algorithm["adapter_semantics_digest"],
        "expected_backend_name": base_identity["backend_name"],
        "expected_backend_source_digest": base_identity["backend_source_digest"],
        "algorithm_id": algorithm["algorithm_id"],
        "capabilities_digest": algorithm["capabilities_digest"],
        "settings_schema_digest": algorithm["settings_schema_digest"],
        "stage_semantics_digest": algorithm["stage_semantics_digest"],
        "settings": settings,
        "settings_digest": settings_digest(settings),
        "requested_outputs": requested_outputs,
        "requested_outputs_digest": requested_outputs_digest(
            "fit", requested_outputs
        ),
    }
)
projection = algorithm["adapter_semantics"]["mcmc_projection"]
if projection["availability"] != "AVAILABLE":
    raise RuntimeError("The selected scaffold algorithm must expose MCMC intent.")
mcmc = audit["baseline_analysis"]["mcmc"]
for binding in projection["schedule_bindings"]:
    if binding["source_kind"] != "adapter-constant":
        raise RuntimeError("The scaffold MCMC schedule must be adapter-owned.")
    mcmc[binding["plan_field"]] = binding["constant_value"]
proposal_schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": (
        "urn:ebm-audit:worker-settings-schema:"
        f"{projection['proposal_method_id']}:1"
    ),
    "type": "object",
    "additionalProperties": False,
    "properties": {},
    "required": [],
}
mcmc.update(
    {
        "chain_count": 1,
        "indexing_rule": projection["indexing_rule"],
        "initialization_rule": projection["initialization_rule"],
        "proposal_method_id": projection["proposal_method_id"],
        "proposal_settings": [],
        "proposal_settings_schema_digest": settings_schema_digest(proposal_schema),
    }
)
audit["experiments"]["sets"] = [
    row for row in audit["experiments"]["sets"] if row["mode"] == "baseline"
]
audit["experiments"]["sets"][0]["enabled"] = True
for profile in audit["profiles"].values():
    profile.update(
        {
            "bootstrap_replicates": 0,
            "subsample_replicates": 0,
            "influence_max_removals": 0,
            "null_replicates_per_family": 0,
            "max_parallel_workers": 1,
        }
    )
audit_path.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
audit_path.chmod(0o600)

with input_path.open(encoding="utf-8", newline="") as handle:
    reader = csv.DictReader(handle)
    header = list(reader.fieldnames or [])
    rows = list(reader)
group_column = audit["column_roles"]["groups"][0]["source_column_or_rule"][
    "source_column"
]
mapped_columns = {
    audit["column_roles"]["participant_id_column"],
    group_column,
    *(row["source_column"] for row in audit["column_roles"]["events"]),
    *(row["source_column"] for row in audit["column_roles"]["covariates"]),
    *(row["source_column"] for row in audit["column_roles"]["metadata"]),
    *(row["source_column"] for row in audit["column_roles"]["ignored_columns"]),
}
group_sizes = sorted(Counter(row[group_column] for row in rows).values())
if (
    len(header) != len(set(header))
    or set(header) != mapped_columns
    or len(rows) != 6
    or group_sizes != [3, 3]
):
    raise RuntimeError("The synthetic structural mapping is incomplete.")
structural_receipt = {
    "schema_version": "ebm-audit-m04-structural-witness/1.0",
    "status": "STRUCTURAL_MAPPING_CHECKED",
    "source_column_count": len(header),
    "unmapped_source_column_count": len(set(header) - mapped_columns),
    "participant_count": len(rows),
    "group_sizes": group_sizes,
    "event_count": len(audit["column_roles"]["events"]),
    "covariate_count": len(audit["column_roles"]["covariates"]),
    "metadata_count": len(audit["column_roles"]["metadata"]),
    "ignored_column_count": len(audit["column_roles"]["ignored_columns"]),
}
structural_path = root / "receipts" / "structural-mapping.json"
structural_path.write_text(
    json.dumps(structural_receipt, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
structural_path.chmod(0o600)
PY
```

The mapping above is deliberate. The scaffold advertises an MCMC-capable
algorithm, so its authenticated adapter-owned schedule and proposal rules are
mapped into one complete seedless chain slot; declaring `mcmc: null` would be a
contradiction and is correctly rejected before planning.

| Selected identity or local value | Exact `AuditConfig/0.3` destination |
| --- | --- |
| complete `selected_expected_identity` | `worker.yaml.expected_identity` |
| pinned `worker.yaml` exact bytes | `worker.worker_config_digest` |
| `selected_backend_identity_digest` | `worker.worker_identity_digest` |
| CSV exact bytes | `input.expected_byte_digest` and `input.variant.source_digest` |
| `base_backend_identity.adapter_id` | `baseline_analysis.backend.adapter_id` |
| selected algorithm semantics digest | `baseline_analysis.backend.adapter_semantics_digest` |
| `base_backend_identity.backend_name` | `baseline_analysis.backend.expected_backend_name` |
| `base_backend_identity.backend_source_digest` | `baseline_analysis.backend.expected_backend_source_digest` |
| selected algorithm ID and capability digest | `baseline_analysis.backend.algorithm_id` and `baseline_analysis.backend.capabilities_digest` |
| selected settings schema, stage semantics, and settings | matching `baseline_analysis.backend.settings_schema_digest`, `stage_semantics_digest`, `settings`, and `settings_digest` fields |
| `central_order` request | `baseline_analysis.backend.requested_outputs` and `requested_outputs_digest` |
| selected MCMC projection | complete one-chain `baseline_analysis.mcmc` intent |

Run generic conformance as the primary worker check. `adapter contract-test` is
only an optional diagnostic if conformance fails; it is not the main route and
does not replace conformance.

```bash
uv run ebm-audit adapter conformance \
  --worker-config "$ROOT/worker/worker.yaml" \
  --offline \
  --output-dir "$ROOT/receipts/worker-conformance"

uv run ebm-audit validate \
  --config "$ROOT/audit.yaml" \
  --offline \
  --output "$ROOT/receipts/validation.json"

uv run ebm-audit plan \
  --config "$ROOT/audit.yaml" \
  --offline \
  --profile quick \
  --output "$ROOT/receipts/quick-plan.json"

find "$ROOT" -type d -exec chmod 700 {} +
find "$ROOT" -type f -exec chmod 600 {} +
```

Stop here. Do not run `ebm-audit run` for this witness. The validation receipt
must be `VALID`, the plan receipt must be `PLANNED`, and both must report
`scientific_worker_commands_run: 0`. The private synthetic-only
`structural-mapping.json` receipt must be `STRUCTURAL_MAPPING_CHECKED` and
account for six participants, seven source columns, group sizes `[3, 3]`, two
events, one covariate, one metadata column, one ignored column, and zero
unmapped source columns. The plan's `dataset_counts` must report six rows and
participants, two events, one group specification, one covariate, and one
metadata column. Its `plan_counts` must report exactly one candidate, one
origin, zero additional origins, one planned candidate, zero plan-ineligible
candidates, one seedless chain slot, and a planned-fit ceiling of one. These
receipts prove structural mapping and planning only; they do not prove that the
scaffold is scientifically suitable.

## 4. Validate without fitting

Run validation before any model command:

```bash
uv run ebm-audit validate \
  --config /approved/local-config/idris-audit/audit.yaml \
  --offline \
  --output /approved/local-output/validation.json
```

Validation reads the configured input and authenticated worker description but
does not fit a model. The current command writes one privacy-safe validation
receipt. Detailed accounting artifacts are produced by `run`, not by
`validate`.

Validation must fail rather than coerce or silently drop duplicate IDs, nonnumeric
events, infinities, invalid groups, unknown directions, ambiguous aliases,
impossible transforms, or unsupported missingness. Inspect every predicted row,
event, and cell change. A count mismatch must be resolved in the source or explicit
configuration, never hidden by an ad hoc preprocessing step.

The current dry-run command for the available universe budget is:

```bash
uv run ebm-audit plan \
  --config /approved/local-config/idris-audit/audit.yaml \
  --offline \
  --profile quick \
  --output /approved/local-output/quick-plan.json
```

## 5. Export and validate a reference baseline, if available

The strongest route is to export a canonical reference-result bundle from the
existing notebook/model before changing it. The exporter must record, where
available:

- event IDs and effective labels, using
  `privacy_sensitive_display_override` when present and otherwise
  `display_name`, in declared event order;
- central order and order samples or position matrix;
- participant-stage probabilities or hard stages;
- exact dataset binding and private participant-alignment method;
- participant/event inclusion counts;
- preprocessing and missingness manifest;
- connected implementation/algorithm identity, settings, canonical string seeds,
  chains, stage semantics, statistical diagnostics, and software identity; and
- hashes and schema versions.

Use internal row indexes or private alignment tokens in the canonical bundle,
never direct IDs or report aliases as join keys. Direct IDs may exist only in the
separate private alignment file described below. Keep both outside the repository
and report output because participant-level derived results remain sensitive.

Create the private draft and notebook helper example without fitting:

```bash
uv run ebm-audit baseline-reference init \
  --output-dir /approved/local-config/baseline-reference-draft
```

The generated draft is deliberately not importable. It names every exact schema
contract needed to construct `reference_body`, `arrays`, and
`private_alignment` in the approved private notebook. Self-identify the body,
then export:

```python
from pathlib import Path

from ebm_audit.baseline import build_reference_result
from ebm_audit.baseline.export import write_reference_bundle

reference = build_reference_result(reference_body)
receipt = write_reference_bundle(
    output_dir=Path("/approved/local-config/baseline-reference"),
    reference=reference,
    arrays=arrays,
    private_alignment=private_alignment,
)
```

Use these exact construction definitions from
`schemas/canonical-records.schema.json`:

- `CanonicalReferenceResultBody` for `reference_body`;
- `CanonicalReferenceResult` for `reference`;
- `ReferenceScientificContract` for `reference.scientific_contract`;
- `ReferenceOutputs` for `reference.outputs`;
- `ReferenceArrayCatalog` for `reference.outputs.arrays`, with the separate
  notebook `arrays` mapping supplying exactly the named array material;
- `PrivateReferenceAlignmentArtifact` for `private_alignment`; and
- `ConvergenceRecord` for the convergence object used by the diagnostics
  helper.

The helper validates those schemas plus the array/catalog, identity,
cross-field, and alignment bindings before writing. It never overwrites: any
existing canonical output makes export fail. On success it creates exactly
`reference-bundle.json`, `arrays.npz`, and `private-alignment.json` with private
file modes, publishing the manifest last. Keep all three files together and
outside repositories and report output.

Reference statistical diagnostics are not an improvised notebook hash. Derive
them from the exact convergence record and plan-ordered chain execution IDs:

```python
from ebm_audit.baseline.export import statistical_diagnostics_digest

diagnostics_digest = statistical_diagnostics_digest(
    convergence,
    ordered_chain_execution_ids=ordered_chain_execution_ids,
)
```

Store the result as
`reference_body.outputs.statistical_diagnostics_digest` before calling
`build_reference_result`. If those exact inputs are unavailable, store null.
Null is honest but can produce at most `BASELINE_PARTIALLY_REPRODUCED`, never
`BASELINE_REPRODUCED`. The settings digest remains in reference implementation
identity; do not duplicate or move settings into the scientific contract.

Validate the exact exported bundle locally, without fitting:

```bash
uv run ebm-audit baseline-reference validate \
  --manifest /approved/local-config/baseline-reference/reference-bundle.json \
  --offline \
  --output /approved/local-output/baseline-reference-validation.json
```

The receipt contains digests and aggregate counts, not source paths, direct
identifiers, or raw biomarker values. A valid receipt proves structural
integrity only. To make the configured run eligible to use the reference, bind
the relative manifest path and exact manifest byte digest in
`baseline_reference`, with status
`SUPPLIED_INDEPENDENTLY_VERIFIED`. The other two files are bound by the manifest
and must remain beside it. `SUPPLIED_STRUCTURAL_ONLY` is deliberately rejected
for execution.

Participant alignment uses either a separate private source-ID-to-run-token file
consumed only by the core or a shared private HMAC namespace plus exact dataset
digest. Direct IDs must not enter the canonical reference bundle, worker, report,
or default manifest. Row positions/counts alone are not alignment; a reordered
reference must still join by private token.

If the notebook cannot export a field, mark it unavailable; do not reconstruct it
from the paper. A published figure or reported event order is not a canonical
reference bundle.

## 6. Run local synthetic and doctor checks

Before optional downstream participant-data use, run the current scoped local
pre-execution check:

```bash
uv run ebm-audit doctor \
  --worker-config /approved/local-config/model-worker.yaml
```

Use the generic conformance route in
[`custom-worker-guide.md#10-generic-conformance-route`](custom-worker-guide.md#10-generic-conformance-route).
It uses only project-owned synthetic fixtures and reports the exact
worker-executable, worker-code, backend-source, and environment identities,
contract hash, offline check, determinism and protocol results, and any missing
evidence. `UNAVAILABLE` and `NOT_APPLICABLE` remain explicit and never become
pass/fail by inference. Do not continue on an ordinary-looking order if a
required conformance or privacy check failed.

## 7. Run baseline reproduction first

There is no baseline-only command and no separate baseline selector. Use the
existing declarative `validate`, `plan`, and `run` route with a separate reviewed
configuration at
`/approved/local-config/idris-audit/audit.baseline.yaml`. Start from the exact
later quick-audit configuration and make only these baseline-run changes:

- exactly one experiment set is enabled, and its mode is `baseline`;
- every non-baseline set is disabled, including one-axis,
  declared-combinations/composed, full-factorial, bootstrap, subsample,
  influence, null, and custom sets; and
- `output.root` names a distinct baseline root such as
  `runs/baseline-reproduction`, with `overwrite: false`. That root must be
  absent before `run`.

The baseline configuration must retain the exact later-run `input`, `worker`,
`baseline_reference`, `baseline_analysis`, `randomness.master_seed`, and
`profiles.quick` values. Keep the rest of the reviewed randomness and quick
profile contract unchanged as well. Do not change settings, seeds, input,
worker, or reference merely to obtain a match.

Validate and plan that dedicated configuration without fitting:

```bash
uv run ebm-audit validate \
  --config /approved/local-config/idris-audit/audit.baseline.yaml \
  --offline \
  --output /approved/local-output/baseline-config-validation.json

uv run ebm-audit plan \
  --config /approved/local-config/idris-audit/audit.baseline.yaml \
  --offline \
  --profile quick \
  --output /approved/local-output/baseline-plan.json
```

Read back `baseline-plan.json` before execution. All three exact predicates are
mandatory:

- `plan_counts.candidate_count == 1`;
- `plan_counts.planned_candidate_count == 1`; and
- `plan_counts.plan_ineligible_candidate_count == 0`.

The plan result also exposes `planning_reason_count`, the bounded
`planning_reason_codes` list, `advisory_count`, and the bounded `advisories`
list. Planning reasons must be empty. For a sampling/MCMC baseline, all three
additional predicates are mandatory:

- `plan_counts.seedless_chain_slot_count == 3`;
- `plan_counts.planned_fit_ceiling == 3`; and
- no advisory has code `PLAN.INSUFFICIENT_INDEPENDENT_CHAINS`.

Three genuinely independent chains are the frozen minimum for assessable
convergence. A one- or two-chain configuration can still be validated and
planned for structural inspection, but its typed advisory means it must not
proceed to scientific worker `validate` or `fit`. Never manufacture independence
by repeating the same seed or copying one result. An authenticated exact or
otherwise non-chain algorithm is the capability-aware exception: it owns one
fit slot, emits no insufficient-chain advisory, and reports within-fit chain
convergence as `NOT_APPLICABLE`. Missing evidence remains explicit in either
route.

Do not run if any predicate fails, any planning reason is present, or a sampling
baseline has the insufficient-chain advisory. Reconfirm that
`/approved/local-config/idris-audit/runs/baseline-reproduction` does not exist,
then execute the one-candidate plan:

```bash
uv run ebm-audit run \
  --config /approved/local-config/idris-audit/audit.baseline.yaml \
  --offline \
  --profile quick \
  --timeout 30
```

The current `run` path treats that sole configured candidate as the baseline and
derives one total assessment from its exact sealed result evidence. When the
candidate succeeds, it also emits a reproduction record. The reproduction
record has exactly one of:

- `BASELINE_REPRODUCED` — every predeclared required comparable field matches its
  frozen rule/tolerance; exact dataset/alignment, connected implementation,
  algorithm/settings, preprocessing/inclusion, stage semantics, central order,
  and adequate richer order/stage outputs agree; and no required check is
  unavailable;
- `BASELINE_PARTIALLY_REPRODUCED` — no supplied comparable field fails and a
  clearly identified supported subset matches, but one or more optional
  reference outputs were not supplied; this is not full reproduction. Central
  order and counts alone can produce at most this status;
- `BASELINE_NOT_REPRODUCED` — a required comparable field, inclusion count,
  preprocessing/settings identity, or numerical rule fails; or
- `BASELINE_REFERENCE_NOT_SUPPLIED` — no canonical reference bundle was supplied.

Similarity to the paper's published sequence or figure can never produce
`BASELINE_REPRODUCED`. If the status is not `BASELINE_REPRODUCED`, results may
describe the connected configuration's sensitivity, but must not be interpreted
as an audit of the original Idris analysis.

If the baseline candidate does not finish successfully, the assessment is
`BASELINE_NOT_ASSESSABLE` and no reproduction record is emitted. A valid bundle
from a different cohort is scientific non-comparability, not malformed input:
data-dependent comparison rows remain visible as `NOT_COMPARABLE`, the overall
reproduction status is `BASELINE_NOT_REPRODUCED`, and validated-language
eligibility is false. Implementation identity remains a separate comparison.

Exit `12` can be expected even when the one baseline candidate completed,
because the overall live report remains `INCOMPLETE` and the whole science gate
remains `BLOCKED`. Do not decide from the process exit alone. Decide whether to
continue from the exact baseline assessment, reproduction record when emitted,
comparison ledger, candidate terminal, failures, and warnings in the dedicated
baseline root.

Only after that evidence is reviewed may the separate quick configuration and
its distinct, absent output root be run. The quick run plans and executes its
own baseline candidate again. It does not resume, splice, import, or reuse the
baseline-first result or run root.

## 8. Inspect participant and data accounting

After the baseline-first run, inspect these artifacts under the exact configured
baseline root
`/approved/local-config/idris-audit/runs/baseline-reproduction/`:

- `run-status.json` — explicitly unsealed, separate candidate-execution,
  whole-audit completion, process-exit, and report statuses;
- `config.resolved.yaml` — exact local decisions (treat as sensitive);
- `data-summary.json` — aggregate counts without raw values;
- `report/universes.csv` — terminal candidate coverage;
- `failures.jsonl` and `warnings.jsonl` — complete typed ledgers;
- `results/` — private machine-readable scientific results indexed without direct
  IDs;
- `evidence/scientific-evidence-projection.json` — the public projection derived
  from exact live evidence, not a persisted evidence seal; and
- `evidence/baseline-assessment.json` — the total baseline assessment, emitted
  for every report-producing run;
- `evidence/baseline-reproduction.json` — the reference comparison record,
  emitted only when the baseline candidate succeeds; and
- `report/report.json` and `report/report.html` — the canonical report path,
  currently marked `INCOMPLETE`.

There is no `manifest.json` until the exact final run-gate authority exists.
Report presence or candidate exit `0` cannot substitute for it. A current
candidate-complete run therefore exits `12` while its report is `INCOMPLETE` and
its science completion gate remains `BLOCKED`.

For ordinary runs, operational records live beside this closed scientific
publication in `<run-name>.operations/`: `replay.json` binds reproducibility
inputs, and `attempt-status.json` records `FINISHED`, `CANCELLED`, or `FAILED`.
`FINISHED` is an execution disposition, not scientific acceptance. Missing
attempt status means interruption or an unknown disposition.

The run root and every private subdirectory must be mode `0700` (or stricter).
The namespace key, optional mapping, resolved sensitive configuration, private
reference alignment, and other sensitive durable files must be mode `0600` (or
stricter). A permission mismatch is a privacy gate failure.

Confirm that every source participant/event is accounted for, every transformation
has an affected count, every exclusion or mask is explicit, and no universe has
disappeared. Treat private machine-readable results, resolved configuration, data
digests, and reference bundles as sensitive even when they contain no raw values.

## 9. Run the quick audit

Run the predeclared quick profile only after validation, synthetic checks, and
the dedicated baseline evidence above are sensible. This uses the separate
reviewed quick configuration and its own distinct, absent `output.root`; it does
not point at the baseline-first root:

```bash
uv run ebm-audit run \
  --config /approved/local-config/idris-audit/audit.yaml \
  --offline \
  --profile quick \
  --timeout 30
```

The output root and optional baseline reference are declared in the validated
configuration; the CLI has no `--reference` or `--output-dir` flags. The
quick plan includes and reruns its own baseline candidate; it never resumes or
splices the earlier one-candidate baseline run. The
required `--offline` acknowledgement has no online counterpart: the process
also forces offline mode before parsing arguments. Inspect the generated
report, which must say `INCOMPLETE`, plus the candidate and warning ledgers. The standalone
`ebm-audit report --run-dir ...` command still returns `REPORT.V1_DISABLED`
because persisted evidence cannot yet be rehydrated. A `PARTIAL` run is not
ordinary success.
Do not change a seed or model setting merely to remove an inconvenient failure;
the change must be a declared universe or a versioned correction.

## 10. Run the full audit only after review

If the quick run has correct accounting, acceptable worker behavior, plausible
resource estimates, and no privacy/protocol failure, run:

```bash
uv run ebm-audit plan \
  --config /approved/local-config/idris-audit/audit.yaml \
  --offline \
  --profile full \
  --output /approved/local-output/full-plan.json

uv run ebm-audit run \
  --config /approved/local-config/idris-audit/audit.yaml \
  --offline \
  --profile full \
  --timeout 30
```

Review the full plan's fit count, estimated runtime, disk use, chains, bootstraps,
influence removals, and null replicates before executing it. The hard fit budget
must not be bypassed casually. The live report remains `INCOMPLETE` until its
science and run gates close; the standalone persisted-report command remains the
typed refusal.

## 11. Interpret the current report safely

The current incomplete live science-v2 report route keeps its evidence layers
separate:

- **within-fit uncertainty** concerns samples inside one fitted model;
- **chain/seed uncertainty** concerns repeated stochastic fits of the same
  specification;
- **sampling uncertainty** concerns bootstrap or subsampling changes;
- **analyst-decision uncertainty** concerns declared cohort, preprocessing,
  feature, outlier, missingness, covariate, or setting choices;
- **participant influence** concerns refits after declared removals; and
- **null/no-signal behavior** asks what the same machinery emits without the
  intended cross-event structure.

“Stable across tested choices,” “internally concentrated,” and “stronger than the
chosen refitted null diagnostics” are different statements. None means
“scientifically true.” A stable order on null data must not receive strong
signal language. `CONVERGENCE_FAILED` and `CONVERGENCE_NOT_ASSESSABLE` universes
cannot support strong conclusions.

“Diagnostics” in this guide means statistical sampling, convergence, software,
or protocol checks. It never means clinical diagnosis or participant-level
clinical classification.

Across different event sets, order comparisons use only the common events. Native
stage numbers are not equivalent. A displayed `stage / N` is descriptive and must
remain labelled `SEMANTICALLY_NON_EQUIVALENT`.

An influential participant is not thereby “bad data” or an “outlier.” Influence
identifies sensitivity and requires domain/data-quality review.

## 12. Domain and supervisory review

Before scientific use, review with the domain/methods/supervisory team:

- every `REQUIRES_CONFIRMATION` resolution;
- cohort/group meaning and any proxy assumptions;
- event directions, units, and event-set rationale;
- missingness, outlier, residualisation, and external-variant provenance;
- baseline-reference status and all mismatches;
- convergence and failed-universe accounting;
- uncertainty separation, influence findings, and null calibration;
- model mismatch between the existing notebook, connected worker, and published
  method; and
- report language and publication limitations.

The public Idris starter limitations are enumerated in
[`idris-2025-public-starter-limitations.md`](idris-2025-public-starter-limitations.md).
Privacy and worker trust requirements are in [`../../PRIVACY.md`](../../PRIVACY.md)
and [`../security/threat-model.md`](../security/threat-model.md).

## 13. Prepare a privacy-safe bug report

Do not attach the input table, local configuration, resolved configuration,
reference bundle, private result files, reversible mapping, namespace key,
screenshots, stack traces, or captured worker streams. Do not paste direct
identifiers, raw biomarker values, private column names, absolute local paths,
data digests, or row-level derived results into a ticket, email, chat, or issue.
Pseudonyms and hashes can still be sensitive linkage information; they are not
automatically safe to share.

First try to reproduce the problem with the installed `synthetic` starter and
the same command family. If the synthetic reproduction fails in the same way,
prepare a small text-only report containing only:

- the auditor version and exact Git commit or distributed package digest;
- Python version, operating system name/version, and installation route;
- the command name (`doctor`, `init`, `validate`, `plan`, `run`, `report`,
  `adapter describe`, `adapter conformance`, `baseline-reference init`, or
  `baseline-reference validate`) without private path arguments;
- process exit code, typed public error or terminal code, and its documented
  safe message;
- aggregate candidate totals by public terminal status;
- aggregate warning and failure codes with counts;
- the worker's public adapter/backend names and version plus its published
  executable, code, backend-source, environment, and capability digests;
- whether the problem reproduces with the project-owned synthetic starter; and
- the smallest clearly synthetic configuration or reproduction steps needed
  to trigger it.

Do not attach an entire run directory or assume that a default report is
approved for external sharing. A report can exclude direct identifiers and raw
values while still containing sensitive research metadata. Have the prepared
text and any proposed attachment reviewed under the institution's disclosure
rules before sending it through an approved support channel.

If the problem occurs only with the participant dataset, report the failed
step, safe typed code, and aggregate counts. Describe the data shape in broad
terms only when approved; do not provide a sample row. A maintainer must be
able to ask for a synthetic reproduction, a safe aggregate receipt, or a local
debugging step without asking the researcher to disclose participant-level
material.
