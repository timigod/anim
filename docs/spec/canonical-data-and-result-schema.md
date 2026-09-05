# Canonical data and result schema

Use this reference for exact input and result fields. For data preparation,
start with the [input data guide](../handoff/input-data-dictionary.md); for model
code, start with the [worker guide](../handoff/custom-worker-guide.md).
“Canonical” means Anim's agreed representation. “Closed” objects reject unknown
fields, and validation checks types without silently converting or repairing
values. The [technical reference guide](../handoff/technical-reference-guide.md)
explains historical sections and scope differences.

Status: FROZEN SCIENTIFIC CONTRACT
Dataset schema: `ebm-audit-dataset/1.0`
Event schema: `ebm-audit-event/1.0`
Fit result schema: `ebm-audit-fit-result/2.0`
Comparison schema: `ebm-audit-comparison/1.0`

The executable Draft 2020-12 schema is
[`../../schemas/canonical-records.schema.json`](../../schemas/canonical-records.schema.json).
Its `$defs` are normative for every serialized nested type in this document;
unknown object members are rejected. The protocol and identity registries are
[`../../schemas/protocol-registry.json`](../../schemas/protocol-registry.json)
and [`../../schemas/cli-lifecycle-registry.json`](../../schemas/cli-lifecycle-registry.json).

## 1. Purpose

This document defines the backend-neutral typed objects at every public and
worker boundary. Implementations may use Pydantic v2, dataclasses plus explicit
validators, or an equivalent typed system, but serialized field names and
semantics are fixed here.

The schemas describe a strict single-sequence cross-sectional EBM only. A future
subtype, grouped-event, temporal, or longitudinal result MUST use a different
schema version. Such output cannot be flattened into this schema.

No validator repairs data. Coercion, imputation, transformation, relabelling,
exclusion, row reordering, or event reordering is valid only as an explicit,
versioned operation that produces accounting provenance.

## 2. Closed enums

The following values are case-sensitive:

| Type | Values |
| --- | --- |
| `AbnormalDirection` | `higher`, `lower`, `REQUIRES_CONFIRMATION` |
| `GroupRole` | `reference`, `at_risk` |
| `MissingnessPolicy` | `error`, `complete-case`, `external-variant` |
| `OutlierAction` | `none`, `flag-only`, `mask-cell`, `remove-participant`, `transform-value` |
| `FieldOrigin` | `BACKEND_NATIVE`, `WORKER_DERIVED`, `CORE_DERIVED`, `USER_SUPPLIED_REFERENCE` |
| `ConvergenceAssessment` | `CONVERGENCE_PASS`, `CONVERGENCE_WARN`, `CONVERGENCE_FAIL`, `CONVERGENCE_NOT_ASSESSABLE` |
| `Comparability` | `COMPARABLE`, `SELECTION_COUPLED`, `SEMANTICALLY_NON_EQUIVALENT`, `NOT_COMPARABLE` |
| `BaselineReproductionStatus` | `BASELINE_REPRODUCED`, `BASELINE_PARTIALLY_REPRODUCED`, `BASELINE_NOT_REPRODUCED`, `BASELINE_REFERENCE_NOT_SUPPLIED` |
| `BackendAcceptance` | `NOT_EVALUATED`, `EXPERIMENTAL`, `ACCEPTANCE_CANDIDATE`, `ACCEPTED`, `REJECTED` |

`BackendAcceptance` records evidence for one connected integration. It does not
name a required public backend, select a paper implementation, or define product
readiness. Product readiness is exactly
`READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY`.

Worker terminal statuses and errors are defined in
`adapter-protocol.md#9-status-and-error-model` and reused verbatim.

## 3. Lossless `AuditDatasetCatalog` and selected `AuditDataset`

Before any analysis universe is compiled, `prepare_audit_dataset` consumes only
a genuine `RunEligibleAuditConfig` and produces a sealed
`PreparedAuditDataset`. Its private `AuditDatasetCatalog` contains the shared
`DataVariant` copied exactly from `AuditConfig/0.3.input.variant`, every event
specification, every declared group specification,
all covariate/metadata/ignored declarations, and the complete ordered physical
column catalog. It contains no selected group rule, missingness policy, row
subset, preprocessing operation, namespace key, or fit result.

The source admission identity already binds every parsed cell, including
missing cells. Domain `ebm-audit/lossless-audit-table/1` additionally binds that
identity to the exact byte/format/role digests, counts, and ordered physical
column catalog. Domain `ebm-audit/audit-dataset/1` hashes the complete
`AuditDatasetCatalog`; this is the pre-plan `audit_dataset_digest`. The public
`ValidatedDatasetSummary.canonical_dataset_digest` means exactly this digest,
never the later per-universe `CanonicalDataset.scientific_data_digest`.

The private table and recursively immutable catalog remain in an identity-keyed
runtime registry. The public capability is bound under
`ebm-audit/prepared-audit-dataset/1` to the run authorization, source admission,
audit-dataset digest, and summary digest. A detached summary or reconstructed
object has no planning authority.

Preparation accepts only the physical exact-file owner: input byte method
`sha256-exact-file-bytes/1`, variant source method `exact-file/1`, and both
declared digests equal to the `ValidatedSourceAdmission.byte_digest`. It never
reconstructs a variant from AnalysisSpec intent. Raw variant label and
provenance remain in the private immutable catalog; public summaries expose
only derived digests and aggregate counts.

### 3.1 Per-universe researcher input

The canonical source is a wide table with exactly one row per participant. It is
accompanied by configuration; column roles MUST NOT be inferred from a dataframe
index.

Every private participant ID follows one rule at preparation, canonical
ingestion, token construction, and private reference alignment. It is either an
exact non-Boolean integer in the interoperable signed safe range, or a string
that is non-empty, not all whitespace, already Unicode NFC, valid scalar text,
and contains no Unicode control (`Cc`), format (`Cf`), or surrogate (`Cs`)
character. Ordinary visible text, including internal spaces, is allowed. The
runtime rejects rather than trims, normalizes, or coerces an ID, and uniqueness
is by the exact typed value, so string `"1"` and integer `1` remain distinct.

```text
AuditDataset
  schema_version: Literal["ebm-audit-dataset/1.0"]
  variant: DataVariant
  participant_private_id_column: non-empty source-column name
  event_specs: ordered tuple[EventSpec], length >= 2
  group_spec: GroupSpec
  covariate_specs: tuple[CovariateSpec]
  metadata_specs: tuple[MetadataSpec]
  ignored_columns: tuple[{source_column, reason}]
  missingness_policy: MissingnessPolicy
  source_table_content_digest: Sha256Digest
  source_table_row_count: positive safe integer
  source_column_names: non-empty duplicate-free tuple[source-column name]
```

Every source-column name is non-empty Unicode NFC. A non-NFC name is rejected;
the loader never silently normalizes it. The raw tabular source is held beside
this closed descriptor only inside the private core boundary; it is not embedded
in a worker request, report, or durable digest artifact. To verify content, the
loader creates one ephemeral
closed `$defs/CanonicalSourceColumnDigestPreimage` per column and hashes it. The
exact typed column preimages remain only inside the ephemeral private ingestion
binding so the production validator can replay source-to-canonical derivation;
they never enter logs, reports, caches, or default artifacts. The private-only
`$defs/CanonicalSourceTableDigestPreimage` contains the ordered source-column
catalog entries, declared roles, row/missing counts, logical scalar encodings,
and those column content digests. It is excluded from reports, logs, and default
artifact bundles; only its digest may cross the private ingestion boundary.
`$defs/AuditDataset`, `$defs/DataVariant`, and `$defs/EventSpec` are executable
accepted roots. The table loader proves that the descriptor count, ordered
column set, and content digest match before any value-level validation.

Requirements:

- The participant ID column is explicit, non-missing, and unique under exact
  typed equality. String IDs MUST already be Unicode NFC and are rejected when
  they are not; integer IDs MUST lie in `[-9007199254740991,
  9007199254740991]`. String trimming, case folding, numeric conversion, or
  Unicode normalization MUST NOT be applied silently.
- Every source column has exactly one declared role: private ID, event, group,
  covariate, metadata, or ignored-with-reason. Overlapping roles are errors.
- Event values are real numeric scalars. Boolean, date, categorical, complex,
  object, and numeric-looking string values are rejected rather than coerced.
- IEEE NaN is the canonical missing event value. Positive and negative infinity
  are always invalid. Group, private ID, and required covariate fields may not be
  NaN unless an explicit transformation specification defines their handling.
- Caller tables and arrays are never mutated in place.
- The `variant_id` and digest distinguish externally supplied variants. The core
  compares variants but does not claim to have created or validated them.

#### 3.1.1 Exact-byte source admission precedes scientific roles

`ValidatedSourceAdmission` is the only capability accepted from the physical
CSV boundary. Configuration verification creates it from the retained input
file descriptor, after the descriptor has been matched to the resolved path,
identity, and digest. The internal exact-byte admission operation receives all
three of: the exact retained source bytes, their expected
`sha256-exact-file-bytes/1` digest, and the complete closed `CsvFormat` mapping.
There is no constructor from a dataframe, column mapping, parsed table, or
scientific role declaration. The raw bytes are discarded after parsing. Parsed
source names and typed values exist only in the closure-held registry entry
associated with the capability; the public object exposes only:

- `admission_id`;
- exact `byte_digest` and `byte_length`;
- role-neutral `parsed_table_digest`;
- complete `input_format_digest`;
- aggregate `row_count` and `column_count`.

The capability is immutable, returns itself from copy/deep-copy, rejects
serialization, and has a redacted representation. Exact-byte parsing,
registration, and private projection form one trusted owning operation. The
internal bridge accepts only the same object identity registered by that
operation and rechecks the capability's complete public identity against a
separate closure-held immutable snapshot. That snapshot owns one immutable
private mapping and one tuple per source column. It is created only after every
v2 column, table, and admission digest has been derived; the transient parser
columns then unwind. Missing sentinels are converted to NaN exactly once during
that construction, and every supported projection call returns the same mapping
and value-tuple identities, so callers cannot accumulate repeated private-table
graphs. There is no module-visible construction token, seal key, or registration
helper, so importing underscore-prefixed digest helpers cannot register a forged
object. This is a supported-API capability boundary, not a claim of secrecy
from arbitrary same-process Python reflection, debugger access, memory
inspection, or interpreter compromise.

`VerifiedAuditConfigFiles` retains that same capability alongside the pinned
descriptors. Its `source_admission` projection reverifies every retained file
before returning the capability. Neither the verified configuration capability
nor `RunEligibleAuditConfig` exposes an input byte reader or input stream
consumer. Their version-2 verification and run-authorization identities both
commit `source_admission_id`; `RunEligibleAuditConfig.source_admission` is
therefore the only participant-table source handed to exact-file canonical
ingestion. Worker configuration and optional declared sidecars retain their
separate pinned-descriptor readers.

Every input rejection is converted to a code-only internal outcome before the
sensitive parsing frame returns. Only then, after the public wrapper has erased
its byte and format arguments, is a fresh `InvalidInputError` raised. Its cause,
context, attributes, and boundary-owned traceback locals contain no source
bytes, decoded rows, source names, or token values. Direct `KeyboardInterrupt`,
`SystemExit`, and `GeneratorExit` signals are likewise re-raised only after the
sensitive frame has unwound. Preservation applies only when the exception has
that exact built-in type; subclasses, grouped control-flow signals, and every
other `BaseException` are totalized to `DATA.SOURCE_INTERNAL_CONTRACT` without
reading subclass attributes. Only an exact internal rejection with a plain
string from the closed source-rejection code set may cross as its declared
code. Success and private-projection outcomes are also exact closed envelopes;
arbitrary or forged outcomes become fresh internal failures after their locals
are erased. The same fresh-error rule protects the private table-projection
boundary.

The versioned parser `strict-utf8-csv-source-admission/2` applies these rules
before any participant, event, group, covariate, metadata, or ignored role is
known:

- reject an empty source, a UTF-8 BOM, invalid UTF-8, and any decoded text that
  is not already Unicode NFC;
- accept exactly the declared `LF` or `CRLF` record ending, permit an optional
  final record ending, and reject quoted newlines or mixed/bare endings;
- require the exact ordered declared header, including no duplicate, missing,
  extra, or reordered columns;
- use only the declared one-character delimiter and quote character, with a
  quote valid only at field start and doubled quotes the only quote escape;
- require at least one rectangular non-blank data record and parse every field
  of every declared column, including a column later declared ignored;
- perform no trimming, normalization, type inference, locale conversion,
  implicit missing-token recognition, row selection, scientific transform, or
  role-based validation;
- recognize an exact declared missing token before physical-type conversion;
- parse integers only from canonical ASCII decimal syntax in the interoperable
  safe range; parse floats only from the closed ASCII decimal/exponent grammar,
  require a finite binary64 result, and reject nonzero literals that underflow
  to zero; and parse Booleans only from exact disjoint declared tokens.

The parser checks a 12 MiB source bound before copying the byte source, a 1 MiB
raw-field bound before growing a quoted-field buffer, a 256-byte numeric-token
bound, 4,096 columns, 1,000,000 rows, and 1,000,000 cells. It also enforces a
128 MiB deterministic retained-table estimate, charging 160 bytes plus the
UTF-8 field width per cell before appending it; the fixed charge includes the
parsed scalar, temporary parsing-list references, transient digest-column tuple,
and finalized registry-owned projection tuple. Before decoding, a conservative
whole-operation estimate charges ten times source size for
caller/copy/Unicode/transient field storage, the complete 128 MiB retained-table
allowance, and 8 MiB fixed headroom, and requires the total to remain at or below
256 MiB. The verification ceiling for a declared approximately 50 KiB numeric
fixture is both 2 MiB absolute and 32 times source size under `tracemalloc`,
after schema-cache warm-up and across admission plus private-projection
retrieval. Changing a bound, accounting rule, or parsing rule requires a new
parser version.

Identity is layered and role-neutral:

1. `ebm-audit/input-format/1` hashes the complete validated `CsvFormat`,
   including exact physical names, order, types, dialect, and tokens.
2. `ebm-audit/source-admission-column/2` streams the exact physical source name,
   index, type, row count, exact missing count, and ordered typed scalar vector
   into SHA-256 without constructing one dictionary per cell. The hash starts
   with `ASCII("ebm-audit/source-admission-column/2") || NUL`. Every following
   frame is `uint16be(tag_byte_length) || ASCII(tag) ||
   uint64be(payload_byte_length) || payload`. Frames, in order, are `schema`
   (`ebm-audit-source-admission-column/2.0`), `column-index` (unsigned 64-bit),
   `source-column` (exact NFC UTF-8), `physical-type` (ASCII), `row-count`
   (unsigned 64-bit), and `missing-count` (unsigned 64-bit), followed by one
   frame per value. Value tags are `value:missing` with an empty payload,
   `value:string` with exact NFC UTF-8, `value:integer` with signed 64-bit
   big-endian, `value:float64` with exact big-endian IEEE-754 binary64 bits, and
   `value:boolean` with exactly `00` or `01`. Thus negative zero remains distinct
   and chunk size cannot change identity. Before hashing, runtime validation
   enforces column length equals table row count, the non-missing scalar tag
   matches the declared physical type exactly, and the computed missing count is
   the catalog count.
3. `ebm-audit/source-admission-table/2` hashes the parser version, complete
   input-format digest, counts, and ordered physical column catalog.
4. `ebm-audit/source-admission/2` binds the exact byte digest and length, input
   format digest, parsed-table digest, parser version, and counts.

Consequently `1.0` and `1e0` under the same format have the same parsed-table
identity but different exact-byte and admission identities. The same bytes
under a different complete format retain their byte digest but receive a
different format, parsed-table, and admission identity. Later scientific role
choices cannot change any admission identity because roles are not an input to
this boundary.
The table and admission JSON preimages remain executable as
`$defs/SourceAdmissionTableDigestPreimage` and
`$defs/SourceAdmissionDigestPreimage`. The column grammar above is a byte-stream
contract and deliberately has no per-cell JSON-schema preimage.

### 3.2 Identity separation

After validation the private core boundary creates an `IdentityMap`:

```text
IdentityMap
  schema_version: Literal["ebm-audit-identity-map/1.0"]
  dataset_variant_id: str
  alias_namespace_id: str
  rows:
    participant_private_id: private scalar; never leaves this file/object
    participant_private_token: HMAC-SHA256; private joins/caching only
    participant_internal_index: contiguous int 0..P-1
    participant_alias: P-001, P-002, ...
```

The alias namespace uses exactly 32 bytes from the operating-system CSPRNG,
stored only in the private run directory with mode `0600`; a password, public
dataset fact, unsalted ID hash, seed, or deterministic run identifier is not a
key. The method is `hmac-sha256-typed-private-id/1` and the exact message is
`ASCII("ebm-audit/participant-token/1") || NUL || ASCII(type_tag) || NUL ||
uint64be(byte_length(value_bytes)) || value_bytes`. `type_tag` is exactly
`string` or `integer`. String bytes are the exact UTF-8 bytes of the
already-validated NFC source string, without trimming or case folding; a
non-NFC source string is rejected rather than normalized. Integers are first
validated in the interoperable safe range, then encoded as canonical ASCII
decimal (`0`, or an optional minus followed by a nonzero digit and digits), with
no plus or leading zero. The token is
`hmac-sha256:<64 lowercase hex>`. `ParticipantTokenParameters` records the actual
`key_byte_length`, which must equal 32. The key identifier is
`Sha256Digest(SHA256(ASCII("ebm-audit/participant-token-key-id/1") || NUL ||
key_bytes))`; it is not the key.

Rows are ordered lexicographically by the 32 raw HMAC bytes, then assigned
contiguous indexes and aliases. Given the same source IDs and namespace key,
mapping is deterministic and row-order invariant. The closed method record is
`ParticipantTokenParameters` in the executable schema and
[`protocol-registry.json`](../../schemas/protocol-registry.json). The key,
private IDs, and private tokens MUST NOT enter worker bundles, reports, default
logs, or corpus notes.

Tests of alias determinism supply a fixed test-only namespace key. Production
code never derives the key from public data or an unsalted identifier hash.

Workers receive only explicit internal row positions `0..P-1`. Default influence outputs
use `participant_alias`. An optional reversible mapping is written only on
explicit request under `run/private/`, excluded from the report bundle and
permission-restricted.

The worker bundle nevertheless carries an explicit numeric
`training_row_indexes` array equal to `[0, ..., P-1]` (and an analogous
evaluation/stage array) so response stage rows can be verified without exposing
identity. It is not an identifier array: the private ID/token/alias mapping stays
in the core. A worker response must return the exact index array beside every
stage output; counts alone never establish alignment.

### 3.3 Canonical internal view

```text
CanonicalDatasetView
  view_schema_version: Literal["ebm-audit-canonical-dataset-view/1.0"]
  variant_id: MachineId
  participant_count: int >= 1
  event_count: int >= 2
  participant_internal_indexes: exactly [0, ..., P-1]
  participant_aliases: unique tuple[str] held by core, not workers
  event_ids: unique ordered tuple[str]
  event_values: float64[P, N]
  group_roles: GroupRole[P]
  covariates: typed columns held by core preprocessing only
  metadata: declared numeric/boolean columns held by the private core only
  auxiliary_columns: exact ordered public bindings for every covariate/metadata array
  source_row_manifest: private mapping to original row positions
  missingness_mask: bool[P, N]
  data_accounting: DataAccounting
```

The JSON object stores numeric, mask, group, and covariate content through the
closed `CanonicalDatasetViewArrayCatalog`; entries bind canonical array name,
dtype, shape, byte length, semantics, and digest. The executable accepted root
is `$defs/CanonicalDatasetView`. Contract validation enforces exact `0..P-1`
indexes, count/shape equality, aligned event directions, and required catalog
members. The catalog is never empty: it contains exactly
`participant_internal_indexes [P]` (integer), `event_values [P,N]` (float64),
`missingness_mask [P,N]` (boolean), `group_role_codes [P]` (integer), plus every
and only the arrays named by `required_covariate_array_names` and
`required_metadata_array_names`. Missing, undeclared, extra, wrong-shape,
wrong-name, or wrong-dtype entries fail before the scientific-data digest is
computed. The same declarations and closure apply to
`ScientificDataDigestPreimage`. Both objects carry the same required
`auxiliary_columns` sequence. Each entry binds the array name, role, declared
kind, missingness semantics, and a categorical codebook digest exactly when the
column is categorical. Runtime validation requires exact key sets and dtypes;
an undeclared or omitted binding is not accepted.

Metadata has its own stable `metadata_id`; raw source names are never converted
into public machine IDs. Version 0.1 admits only declared continuous, integer,
or Boolean metadata. Continuous metadata may explicitly allow NaN; integer and
Boolean metadata require complete values. String/categorical metadata is
`UNSUPPORTED_CAPABILITY`, never guessed, sanitized, or silently omitted.
Categorical covariates are integer-coded only from their explicit ordered typed
level list. The private immutable codebook is retained by the core, while its
digest is bound in that covariate's `auxiliary_columns` entry; raw levels do not
enter the public view.

`source_row_manifest_digest` and `selected_row_manifest_digest` are the same
domain-separated digest under `ebm-audit/selected-row-manifest/1`. Their closed
`$defs/SelectedRowManifestDigestPreimage` binds the variant, original row count,
exact contiguous internal indexes, and the source-row index corresponding to
each internal index. The preimage remains private and is not written to default
artifacts. Complete-case removal therefore changes both accounting and the row
manifest; it can never masquerade as the unchanged input.

The loader validates one ephemeral private closed version-2
`$defs/CanonicalIngestionBinding` that contains the descriptor, every exact
typed source-column preimage, private table and row-manifest preimages, private
categorical codebooks, a digest-only exact-file admission proof when applicable,
public canonical view, scientific digest preimage, and resulting digest. It is
never written to logs, reports, caches, or default artifacts, and its redacted
private wrapper never renders contained values in `repr`. Its production
validator replays source-to-canonical derivation and recomputes every
ingestion-owned digest while enforcing role partition, catalog equality, exact
axes, exact auxiliary key sets/dtypes, accounting, source-row bounds, and the
exact-file admission seal. A self-consistent rehash of altered source and
canonical arrays is therefore rejected. Passing generic JSON Schema validation
alone is not sufficient.

The input `event_specs` order defines canonical event index `0..N-1`; backend
sorting never changes it. The participant mapping order defines canonical row
index. Row/column permutation tests revalidate and remap into this view before
scientific equality is assessed.

## 4. `DataVariant`

```text
DataVariant
  variant_schema_version: Literal["ebm-audit-data-variant/2.0"]
  variant_id: MachineId
  label: non-empty human label
  source_digest: Sha256Digest
  source_digest_method: Literal["exact-file/1", "canonical-table/1"]
  provenance_note: required non-empty text
  created_by: Literal["researcher", "auditor-synthetic-generator"]
  synthetic_truth_digest: Sha256Digest | null
  is_synthetic: bool
  externally_completed_or_transformed: bool
```

Externally completed/imputed or otherwise transformed datasets use distinct
variant IDs and digests. `created_by=researcher` states provenance, not auditor
validation; researcher-owned input may be real or explicitly synthetic and its
`synthetic_truth_digest` is always null. Only
`created_by=auditor-synthetic-generator` requires `is_synthetic=true` and a
non-null truth digest. `AuditConfig/0.3.input.variant` and canonical data use
this same closed v2 definition directly. `AnalysisSpec/3` carries only the exact
row-free `DatasetVariantIntent` projection of a declared source-variant row; it
contains no physical digest, label, provenance, path, or table. Synthetic rows
are stored only in test/example artifacts explicitly
labelled synthetic; they are never placed in the corpus working record.
`exact-file/1` accepts only `ValidatedSourceAdmission`; it cannot be claimed
from caller-supplied bytes, a reconstructed in-memory table, or a source-row
sidecar at canonical-ingestion time. `canonical-table/1` remains a separate
programmatic entry point that accepts a table plus its explicit source-row
indexes and rejects exact-file descriptors. At exact-file ingestion the loader
creates the version-2 private keyed `$defs/ExactFileAdmissionProof` under
`ebm-audit/exact-file-admission-proof/2`. It binds `source_admission_id`, the
complete `$defs/SourceAdmissionDigestPreimage`, the verified exact-file digest,
the independently canonicalized source-table digest, and the opaque run
namespace key. Runtime recomputes `source_admission_id` from that complete
preimage and requires its byte digest, row count, and column count to match the
exact-file variant and dataset descriptor. The role-neutral
`parsed_table_digest` and role-bound `canonical_source_table_digest` remain
separate fields and are both covered by the proof. The proof retains no exact bytes and,
like typed source replay values, never enters default artifacts. Later runtime
validation requires that original seal, so retaining the exact-file digest while
self-consistently rehashing a changed table is rejected. Independently, every
loaded table receives `source_table_content_digest` under
`ebm-audit/canonical-source-table/1` over the closed ordered column catalog
described above. For `canonical-table/1`, `DataVariant.source_digest` must equal
that table-content digest. Each column-content digest uses domain
`ebm-audit/canonical-source-column/1` over its validated typed scalar vector;
IEEE NaN is represented by the explicit `missing` tag, not serialized as a
non-finite JSON number.
`synthetic_truth_digest` uses domain `ebm-audit/synthetic-truth/1` over the
complete versioned truth object.

## 5. `EventSpec`

```text
EventSpec
  schema_version: Literal["ebm-audit-event/1.0"]
  event_id: MachineId
  display_name: non-empty text
  source_column: unique source-column name
  category: MachineId
  unit: text | null
  abnormal_direction: AbnormalDirection
  permitted_transformations: tuple[TransformationId]
  missingness_declaration: MissingnessPolicy
  feature_sensitivity_eligible: bool
  identifier_risk_reviewed: bool
  public_source_note: text | null
  privacy_sensitive_display_override: text | null
```

`MachineId` matches `[a-z][a-z0-9._-]{0,63}` and is unique in its scope.
`display_name` is presentation only; equality and joins use `event_id`.
`source_column` never crosses the worker boundary. When a privacy display override
is present, reports and errors use it instead of the source/display value.

A real fit is blocked while any selected event has
`abnormal_direction=REQUIRES_CONFIRMATION`. Validation and plan generation may
continue and MUST surface the unresolved event IDs. A lower-is-more-abnormal
event may be negated for a higher-oriented backend only through the reversible
versioned transform `direction-negation/1`, with before/after direction metadata
and a round-trip test.

Permitted transformations are an allowlist, not instructions to transform.
Actual transformations belong to the immutable universe specification and data
accounting. An unlisted transform is `INVALID_SPECIFICATION`.

An event candidate with the same source column as the private ID is an error. A
candidate that is unique for every participant and integer/string-like, or whose
name matches the versioned identifier-name heuristic, yields
`REQUIRES_CONFIRMATION` code `DATA.SUSPECT_IDENTIFIER_EVENT` unless
`identifier_risk_reviewed=true`. The heuristic cannot silently remove the event.

## 6. Groups and covariates

```text
GroupSpec
  group_spec_id: MachineId
  source: Literal["column", "declarative_rule"]
  source_column_or_rule: ColumnGroupSource | DeclarativeGroupSource
  label_to_role: tuple[TypedGroupLabelRole]
  required_roles: non-empty tuple[GroupRole]
  rationale: non-empty text
```

`ColumnGroupSource` contains only `kind="column"` and a non-empty private
`source_column`; for this form `label_to_role` is non-empty.
`DeclarativeGroupSource` contains only `kind="declarative_rule"`, a versioned
`rule_id`, a non-empty ordered tuple of source columns, and one or two explicit
role rules. Each role rule is `{role, match: "all", clauses}`. All clauses in
one rule are combined with Boolean AND. Every participant must match exactly
one role rule; no match and multiple matches are errors. For this form
`label_to_role` is empty because rules produce roles directly rather than an
unstated intermediate label. A clause is
`{source_column, operator, value}`, where `operator` is exactly `eq`, `lt`,
`lte`, `gt`, or `gte`. Ordered role rules must have unique roles, their clause
columns must equal the declared source-column set, and their roles must equal
the required role set. `eq` compares exact typed values without coercion;
strings and Booleans support only `eq`, while ordered operators accept only
finite integers or finite floats. Integer and float values are compared
numerically, but Booleans are never treated as integers. `TypedGroupLabelRole` contains
one `label={type,value}` pair (`string`, `integer`, or `boolean`) and one
`GroupRole`. A boolean, integer, and string with similar display text remain
distinct; object-key coercion is forbidden. Duplicate typed labels are invalid. These researcher-only
objects are closed by `$defs/GroupSpec` in the executable schema.

Unknown, missing, or multiply matched group values are invalid. Each worker
request contains canonical integer codes plus a codebook; it does not receive
the raw private group source values. A fit requiring both roles fails validation
when either role is absent or below the declared/backend minimum.

Group boundaries in the Idris public starter are examples, not scientific
defaults. Nearby threshold sensitivity is generated only from explicitly enabled,
rationalized rules; the core never searches thresholds for a preferred result.

```text
CovariateSpec
  covariate_id: MachineId
  source_column: source-column name
  kind: Literal["continuous", "categorical"]
  level_order: tuple[typed level] | null
  missingness: Literal["error", "complete-case", "external-variant"]
```

For `continuous`, `level_order` is `null`; for `categorical` it is a non-empty,
duplicate-free tuple of scalar string/integer/boolean levels. The serialized
shape is closed by `$defs/CovariateSpec`.

```text
MetadataSpec
  metadata_id: MachineId
  source_column: source-column name
  kind: Literal["continuous", "integer", "boolean"]
  missingness: Literal["error", "allow-nan"]
```

`allow-nan` is valid only for continuous metadata. Metadata is not sent to a
worker and is not an event-discovery surface.

The only built-in adjustment in version 0.1 is ordinary linear residualisation
fitted in the declared reference group and applied to all participants. Its
formula, intercept, categorical encoding, design rank, reference fit rows,
parameters, and affected counts are retained in private provenance. It fails on
rank deficiency or insufficient reference rows and is refitted inside every
resample. Raw parameters/values are not included in the default report.

## 7. Validation and data accounting

### 7.1 Required validation

Validation checks all of the following before fitting:

- missing, duplicate, or invalid private IDs;
- duplicate event IDs, aliases, display aliases, or source columns;
- nonnumeric event cells, infinities, and backend-incompatible NaNs;
- invalid or missing group labels and insufficient group sizes;
- missing event directions and impossible/unpermitted transforms;
- constant and near-constant selected events;
- event and participant missingness counts;
- suspected identifier columns included as events;
- covariate/reference-group insufficiency and rank deficiency;
- ambiguous aliases or privacy display collisions; and
- any participant, event, or cell change predicted by preprocessing.

A selected event is constant when all finite values are identical. It is
near-constant under the versioned default rule
`near-constant-range/1` when:

```text
max(x) - min(x) <= 1e-12 * max(1, max(abs(x)))
```

after the universe's explicit preprocessing and before fitting. Constant and
near-constant events are fit-blocking `INVALID_SPECIFICATION` outcomes in version
0.1; they are never silently removed. The configured tolerance is part of the
universe and cache identity. A future backend-specific exception requires a
schema/benchmark change rather than a confirmation flag.

### 7.2 `DataAccounting`

Every input-to-worker transition emits:

```text
DataAccounting
  accounting_schema_version: Literal["ebm-audit-data-accounting/1.0"]
  input_participants: int
  output_participants: int
  input_events: int
  output_events: int
  input_missing_cells: int
  output_missing_cells: int
  flagged_cells: int
  masked_cells: int
  transformed_cells: int
  removed_participants: int
  removed_events: int
  operations: tuple[AccountingOperation]
```

`AccountingOperation` is closed and contains `operation_id`, `method_id`,
`universe_decision_id`, `reason_code`, `rationale`, nonnegative participant/event/
cell counts, ordered affected event IDs, ordered affected canonical
covariate/metadata array names, `parameter_digest`, `input_digest`, and
`output_digest`. A complete-case operation records every event and covariate
whose missingness contributed to row removal, including overlaps. Its private
form MAY also contain private participant tokens; its
report projection MAY contain approved aliases. Neither form may contain raw
event values. Unknown fields are rejected. Default reports expose aggregate
counts and approved aliases only.

The four outlier effects are distinct: flagging does not change values, masking
creates explicit NaN cells, participant removal removes whole declared rows, and
transformation changes declared cells. No action implies another. A worker-side
row/event/cell change is forbidden in the current `ebm-audit-worker/v2` protocol.

The built-in missingness policies mean:

- `error`: any missing selected event cell blocks that universe;
- `complete-case`: remove every participant missing any selected event, before
  worker invocation, and record the exact count/manifest;
- `external-variant`: reserved but currently unsupported. Config resolution
  rejects its declaration or selection because no complete physical owner is
  implemented; no variant is fabricated.

There is no built-in MICE, median, KNN, or other imputation in the current
`AuditConfig/0.3` configuration.

## 8. Canonical serialization and identity

Schema JSON uses UTF-8 RFC 8785 canonical bytes and forbids non-finite JSON
numbers. `Sha256Digest` is always the prefixed form
`sha256:<64 lowercase hexadecimal characters>`. A structured digest is
`Sha256Digest(SHA256(ASCII(domain) || NUL || JCS(object)))`; an exact-file digest
is `Sha256Digest(SHA256(file_bytes))`. A caller MUST NOT strip/add the prefix or
reuse one domain's digest in another field. Array digests use domain
`ebm-audit/array/1` and hash a closed object containing field name, dtype, shape,
semantic version, byte length, and a prefixed exact-byte digest of canonical
little-endian C-contiguous array bytes.

The executable schema's `finite-number` format checker rejects IEEE NaN and
positive or negative infinity before JCS serialization. Missing source values
use the explicit typed `missing/null` branch instead of a non-finite JSON number.

Data-ingestion-owned structured domains are fixed as follows:

- `ebm-audit/canonical-source-column/1` for the ephemeral closed typed column
  preimage;
- `ebm-audit/canonical-source-table/1` for the private-only ordered column
  catalog preimage (only its digest may enter non-private artifacts);
- `ebm-audit/selected-row-manifest/1` for the private selected-row mapping;
- `ebm-audit/categorical-codebook/1` for the ephemeral closed ordered typed
  categorical-level preimage; and
- `ebm-audit/data-accounting/1` for the exact closed `DataAccounting` object.

The ingestion boundary does not invent the five upstream component identities.
It receives already validated `preprocessing_digest`, `missingness_digest`,
`outlier_digest`, `cohort_digest`, and `covariate_adjustment_digest` values from
their owning compiler/preprocessing modules and binds them into the scientific
preimage. This keeps one owner per decision and prevents a second, inconsistent
digest route inside the table loader.

Every seed inside a serialized schema/JCS object is `UInt64Hex`, exactly 16
lowercase hexadecimal characters matching `^[0-9a-f]{16}$` and covering the full
unsigned 64-bit range. Zero is `"0000000000000000"`. JSON numbers, signed or
shortened strings, uppercase hex, and `0x` prefixes are invalid. Code may convert
the validated string to an internal integer only outside JCS objects; serialized
results, universe/cache identities, requests, and receipts retain the canonical
string.

The private `scientific_data_digest` uses domain
`ebm-audit/scientific-data/1`. Its closed preimage contains:

- canonical dataset/view schema versions, variant ID, and prefixed source digest;
- alias namespace/mapping method versions and the ordered keyed participant
  tokens (never direct identifiers); the digest is intentionally private-
  namespace-scoped;
- ordered internal row indexes and the selected-row-manifest digest;
- ordered canonical event IDs and directions;
- event-value, missingness-mask, group-role, and each typed covariate array
  digest, including dtype/shape/semantic headers;
- preprocessing, missingness, outlier, cohort/group, covariate-adjustment, and
  `DataAccounting` digests for the exact worker input view; and
- explicit participant/event/cell counts.

The executable preimage is exactly
`canonical-records.schema.json#/$defs/ScientificDataDigestPreimage`. The digest
is computed over the complete preimage, not an untyped runtime mapping. Array
catalog equality, `cell_count = participant_count * event_count`, contiguous row
indexes, token uniqueness, and aligned event-direction length are mandatory
contract-test invariants.

This canonical auditor-input preimage is distinct from the generator's raw
`SyntheticScientificData` schema object and its
`generated_scientific_data_sha256`. The raw object is sealed before canonical
ingestion; canonical validation, row selection, typed tokenization,
preprocessing, and accounting then produce `ScientificDataDigestPreimage` and
`input_digest`. The two domains and byte preimages are never aliases, even when
the numeric values originated from the same generator run.

No path, timestamp, display label, raw identifier, or unhashed raw value appears
in this JCS object. A changed participant selection, row alignment, event order,
direction, value, missingness bit, group/covariate value, transformation, or
accounting fact changes the digest. `config_digest` separately binds the exact
per-analysis resolved core configuration. In a synthetic benchmark,
`case_configuration_sha256` additionally binds the complete ordered canonical
audit-case configuration under `ebm-audit/audit-case-configuration/3`. Neither
is the generator's full raw resolved configuration or its distinct
`resolved_generator_configuration_sha256`. A non-null `input_digest` is the
canonical auditor-input digest computed under `ebm-audit/scientific-data/1`
from the exact `ScientificDataDigestPreimage`; when a result also carries
`scientific_data_digest`, those two canonical fields MUST byte-match.
`generated_scientific_data_sha256` is instead the independently computed raw
`SyntheticScientificData` object digest under
`ebm-audit/generated-scientific-data/1`. Neither digest aliases or substitutes
for the other. These objects and domains are not interchangeable.

Cross-field arithmetic, exact array-length equality, set intersection, and
ordering are enforced after JSON Schema validation by the canonical runtime
validator. Schema definitions expose stable `x-ebm-invariants` IDs as registry
hooks. A conforming validator executes every named hook and fails closed on an
unknown or failed ID; the annotation is not a claim that JSON Schema alone
compares those fields.

Hook values are identifiers only, never prose. The protocol registry is the
exact dispatch allowlist and records the enforcement phase and deterministic
algorithm for evaluator-owned hooks. Pre-freeze validation enumerates every hook
attachment, requires registry membership and evaluator dispatch, and fails if a
required hook is missing, skipped, duplicated, or lacks a PASS outcome. Rules
already enforced structurally by a closed discriminated schema do not need a
second prose hook.

The executable contract-reference boundary is
`evaluator/fixtures/runtime_invariant_dispatcher.py`. It scans all eighteen
registered schemas, requires exact equality between the 91 registry IDs and its
91 callable handlers, and returns one closed
`ebm-audit-runtime-invariant-outcome/1.0` object validated against
`evaluator-receipts.schema.json#/$defs/RuntimeInvariantDispatchOutcome` per
dispatch. Unknown IDs return `FAIL/FREEZE_FAILED/RUNTIME.UNKNOWN_RULE`. The rule
ID fixes digest domains, owner/preimage schemas, expected registry contents, and
the applicable scientific or comparator validator; none is selected by caller
input. Owner artifacts are schema-validated at the boundary, while any smaller
arithmetic or ordering projection is derived internally for its one named rule.
The companion counterexample registry contains exactly one handler-level
negative for every rule, including digest, source-byte, receipt,
duplicate-index, score/FPR, comparator, and acceptance-CAS derivations. This
executable reference is contract evidence only: it does not by itself establish
runtime conformance for a researcher-supplied EBM.

The default provenance exposes only the resulting opaque digest, counts, and
method versions. Cache identity additionally includes protocol/schema, distinct
core-code/worker-executable/worker-code/backend-source/environment identity,
settings, canonical chain seed, capabilities, and result schema as defined in
`analysis-universe.md`. Upstream backend cache identity is never trusted.

There is one environment object and one preimage. `EnvironmentIdentity` is the
closed `$defs/EnvironmentIdentity` object in the executable schema, and
`environment_digest` is domain `ebm-audit/environment/1` over that complete
object. No alternate package-list, launch-manifest, path, or abbreviated
environment projection may use the same field name or domain.

## 9. Canonical result record

Every ordered `AnalysisPlan/3` candidate has exactly one immutable core-final
`ResultRecord/2`. A prepared candidate names one `UniverseSpec/3`; an unprepared
candidate has `universe_id=null`. A `ResultRecord` is never a one-chain worker
payload. The closed envelope contains `result_schema_version`, `result_id`, and
one closed discriminated `body`:

```text
ResultRecordBody =
    UnpreparedResultBody
  | ExecutionNonSuccessResultBody
  | ConvergenceNonSuccessResultBody
  | CompletedFitResultBody

CoreResultStatus =
  SUCCESS
  | CONVERGENCE_WARN
  | INVALID_INPUT
  | UNSUPPORTED_CAPABILITY
  | INVALID_SPECIFICATION
  | BACKEND_ERROR
  | TIMEOUT
  | CONVERGENCE_FAILED
  | CONVERGENCE_NOT_ASSESSABLE
  | PRIVACY_VIOLATION
  | PROTOCOL_ERROR
```

Every body begins with the closed candidate key and common local evidence:

```text
  record_kind: UNPREPARED | EXECUTION_NON_SUCCESS | CONVERGENCE_NON_SUCCESS | COMPLETED
  plan_schema_version: Literal["ebm-audit-analysis-plan/3.0"]
  plan_digest: Sha256Digest
  candidate_ordinal: SafeInteger
  candidate_id: Sha256Digest
  analysis_spec_id: Sha256Digest
  universe_id: Sha256Digest | null
  status: CoreResultStatus
  input_digest: Sha256Digest | null
  config_digest: Sha256Digest
  core_code_digest: Sha256Digest
  started_at_utc / ended_at_utc: RFC 3339
  runtime_seconds: nonnegative float
  warnings: tuple[WarningRecord]
  output_hashes: closed map[relative POSIX path, Sha256Digest]
```

`result_id` uses domain `ebm-audit/result-record/2` over the exact
`ResultRecordDigestPreimage`: `{result_schema_version:
"ebm-audit-fit-result/2.0", body}`. `result_id` is absent from that preimage, not
null. The separately retained canonical result-file digest is the
`CandidateTerminal.result_digest`; it does not reuse the content-name domain.
For every prepared result and valid unsupported unprepared result,
`input_digest` byte-matches the private canonical `scientific_data_digest`.
It is never the exact-file byte digest. It is null only for the two
pre-canonical invalid branches defined below.

`UnpreparedResultBody` is the only branch with `universe_id=null`. It retains
the exact planning/preparation state, operation seed when one was derived, every
typed reason, one safe error, and diagnostic references. It cannot contain any
protocol, worker, backend, chain, convergence, or cache field. Status mapping is
total: event-count/direction invalidity or `PREPARATION_INVALID` maps to
`INVALID_SPECIFICATION`; MCMC-unavailable as the only planning reason or
`PREPARATION_UNSUPPORTED` maps to `UNSUPPORTED_CAPABILITY`. Invalidity wins a
mixed planning reason set while every reason remains present. `INVALID_INPUT`
is reserved for an admitted-input failure or a genuine authenticated worker
rejection.

The same discriminator owns `input_digest`. A valid MCMC-only
`PLAN_INELIGIBLE` result and a valid `PREPARATION_UNSUPPORTED` result require
the exact private `ScientificDataDigestPreimage` and its recomputed
`ebm-audit/scientific-data/1` digest. An event-count/direction-invalid
`PLAN_INELIGIBLE` result and `PREPARATION_INVALID` require
`input_digest=null`, because no truthful canonical preimage exists.
`PREPARATION_INVALID` must reproduce the canonicalization failure during
authority revalidation. The exact source-file byte digest remains private under
its own source-admission meaning and must never be copied into `input_digest`.
The production builder for this body accepts only the exact
`UnpreparedResultAuthorization` for the candidate. It revalidates that
capability, constructs the fixed body and status without worker, universe,
arrays, or cache authority, and hands only the finalized result capability to
persistence. Its regression gate is
`tests/integration/test_unprepared_result_authorization_finalization.py::test_exact_unprepared_authorization_constructs_and_persists_only_its_bound_result`,
which proves construction and persistence use only that exact opaque
authorization.

Every prepared branch requires a non-null universe, protocol v2 backend
identities, the exact successful or failed validate evidence, every fit-attempt
reference, and applicable cache lineage. `ExecutionNonSuccessResultBody` covers
validate/fit non-success only. `ConvergenceNonSuccessResultBody` retains all
successful chain payloads and the exact fail/not-assessable convergence record.
`CompletedFitResultBody` maps only `CONVERGENCE_PASS -> SUCCESS` and
`CONVERGENCE_WARN -> CONVERGENCE_WARN`.

Schema validity alone cannot finalize a result. The required
`result-record-finalization-evidence-exact/1` semantic validator runs before
result-ID issuance, persistence, cache admission, and candidate-terminal
construction. Validate-terminal status equals its exact negative validate
evidence. Fit evidence is grouped in contiguous chain-plan order; each chain has
exactly ordinal `[0]` or `[0,1]`, never three attempts or ordinal 1 alone. A
retry requires ordinal 0 to be a core-observed process start/crash failure,
equal retry-equivalence digests, and distinct attempt-specific identities.
After successful validation, the groups cover every declared chain/seed even
when one or more terminals are negative. Fit-terminal status is derived from
that complete terminal set by the registry's fixed negative-status precedence.
Completed and convergence branches require every final chain attempt to be
`SUCCESS` and every chain payload to bind that final attempt.

`backend_acceptance` is the immutable state observed at result finalisation. It
may truthfully be `ACCEPTANCE_CANDIDATE` while sealed scoring is underway. A
later atomic acceptance-registry transition does not rewrite this result; a new
receipt or result records the later observation. The field is historical
evidence, not a mutable pointer to current registry state.

Supporting nested objects are also closed. `WarningRecord` contains stable
`code`, `severity` (`INFO`, `WARNING`, or `SEVERE`), bounded `safe_message`, and
the protocol's closed `SafeDetails`. `CacheLineage` contains the exact
`universe_cache_key`, ordered `chain_cache_keys`, cache disposition, nullable
earlier `source_result_id`, and a `cache_verification_digest`; a miss is null and
therefore cannot self-reference the result being created. It cannot describe a
partial hit as final reuse. The one safe error in a non-success branch is the protocol's closed
`NegativeResponseError` or a core-generated object with that identical shape.
`ResourceSummary`, `ArtifactReference`, and `EvidenceReference` use the exact
closed protocol definitions and versions; they are not arbitrary mappings.
An `ArtifactReference` binds to the nonrecursive creating
`chain_execution_id` and `scientific_request_digest`, plus its own exact file
digest and worker/backend identities. It MUST NOT contain or bind back to the
digest of a payload that itself contains the artifact reference.

The five code/execution identity digests have distinct normative preimages in
[`adapter-protocol.md#7-identity-and-capability-declaration`](adapter-protocol.md#7-identity-and-capability-declaration)
and MUST NOT substitute for one another. `capabilities_digest` is always plural
and uses that protocol's domain-separated capability preimage.

Non-success branches add one typed safe error, exact applicable evidence, and no
admitted scientific result. Failed, invalid, unsupported, timed-out,
privacy-violating, protocol-invalid, convergence-failed, and non-assessable
records remain rows in the universe summary and entries in the failure/warning
ledgers. They are never deleted or converted to missing data.

Each closed `WorkerExecutionEvidenceReference` retains one validate or fit
attempt. A framed worker outcome requires authenticated request/execution,
command-evidence, request/scientific/response metadata digests. A start/crash
failure instead requires authenticated request evidence plus the exact
`CoreObservedFailure` digest, class, and code and cannot invent response
evidence. The reference carries that closed privacy-safe failure preimage; the
finalizer recomputes its digest before trusting the class/code. Fit references also
retain `chain_plan_position`, `chain_execution_id`, `attempt_id`,
`attempt_ordinal`, and `retry_equivalence_digest`; validate references require
all five to be null. No response is mutated or discarded when the core
constructs the separate final result.

Held-out sealing uses the separate four-branch closed union in
`evaluator-receipts.schema.json`. `FIT_TERMINAL` cannot carry final `SUCCESS` or
`CONVERGENCE_WARN`; those states are valid only in `SCIENTIFIC_SUCCESS`, which
also requires the matching convergence assessment and canonical scientific
payload digest. Both fit-bearing branches carry
`comparator_applicability`. `MATCHED_COMPARATOR_CHAIN` structurally requires a
non-null comparator execution binding, while `NOT_APPLICABLE` requires null; the
runtime rule resolves `operation_instance_id` exactly once in the complete
sealed operation plan, resolves that operation's case exactly once in the
complete sealed-case manifest, derives the discriminator from the resolved
operation kind and comparator plan evidence, and then verifies the execution
binding against those same objects. The caller's discriminator is never its own
evidence.

The sealed operation plan is the exact deterministic expansion of the sealed
case manifest and the complete case-configuration owners: one entry per
case/analysis-spec ordinal. Its v2 header also fixes the exact
`AnalysisPlan/3` and `PreparationReceipt/2` digests selected by the held-out
attempt. `operation_instance_id` binds the exact
`analysis_spec_id` and the specification's `operation_matrix_id`. An ordinary
entry derives its expansion axis from the typed operation kind and its index
from the analysis-spec ordinal; a matched entry derives them from the comparator
ID and pair index. Chains are not extra operation rows; their complete set is
owned by the frozen chain plan. Extra, missing, duplicate, or out-of-range
operation rows fail even if every enclosing digest is recomputed.

For a matched comparator, the sealed case also carries
`derived_comparator_member_id`. The evaluator obtains this value by validating
the complete ordered member-evidence set and finding the one member whose
configuration and data identities equal the case. Result resolution repeats
that complete semantic derivation even after the case manifest has been
authenticated. The operation plan copies only the derived case value; it never
echoes a supplied operation row. Result evidence must agree with both the case
and operation.

Final records have no singular top-level seed, chain ID, central order, or chain
array. Those fields live in the ordered per-chain scientific payloads below.

Same-seed and serial/parallel scientific equivalence use the separate closed
`$defs/CanonicalScientificPayload`. It projects only the benchmark subject and
operation identities, analysis/universe identity, core-final convergence status,
ordered event set, ordered `$defs/CanonicalChainScientificProjection` values,
and cross-chain convergence. It excludes request UUIDs, timestamps, runtimes,
paths, resource summaries, artifact paths, file ordering, logs, aliases, private
namespace material, and transport hashes. It is an output projection and MUST
NOT be confused with the input-only `ScientificDataDigestPreimage`.

The `FrozenChainPlanDigestPreimage` v3 is authenticated under the private
attempt root and binds the exact attempt, subject, operation, AnalysisPlan/3
schema version and digest, candidate ordinal, candidate ID, analysis
specification ID, complete `UniverseIdentityPreimage`, universe, and chain rows.
Candidate ID must equal analysis specification ID. The evaluator independently
authenticates the complete `AnalysisPlan/3` and `PreparationReceipt/2`,
recomputes their existing digests, resolves the exact ordinal, and requires the
selected record to be `PREPARED`. That record's `UniverseSpec/3` must project
exactly to the frozen Plan fields, complete universe preimage, operation seed,
registry digest, and chain rows. `HeldoutAttemptIdentityPreimage` v4 fixes the
plan digest plus the benchmark-freeze, candidate-freeze, and atomic
acceptance-transition receipt digests, and
`SealedOperationPlanDigestPreimage` v2 fixes both the plan and
receipt digests. Only then does the evaluator derive the universe,
chain-execution, and attempt identities under their `/3` domains. The plan
length must equal `AnalysisSpec.mcmc.chain_count`, every held-out attempt
ordinal must equal zero, and every ordinary or matched-comparator seed is
re-derived from the same root before universe identity is accepted. The
convergence object is then derived, not accepted as a worker or caller summary.

The current contract remediation does not authorize that held-out chain.
`BenchmarkFreezeReceipt/3`, `PreCandidateQualificationReceipt/2`,
`CandidateFreezeReceipt/3`, and
`AcceptanceCandidateTransitionReceipt/2` are typed blocked records because the
authoritative benchmark/profile/development resolvers and durable acceptance
CAS do not yet exist. A structural binding audit may verify cardinality,
digests, links, the frozen public source vector, and time order only through a
`BlockedPreRootDiagnostic/1` whose state is `ROOT_NOT_DRAWN`. That audit accepts
no held-out attempt or root receipt. `RootCommitmentReceipt` is schema-
impossible in the current phase. A future root receipt requires complete
authoritative owners, durable acceptance-CAS readback, and the private-root
owner.
For every row of that plan, the evaluator consumes exactly one
local `ConvergenceArrayArtifact` for `postburn_order_state_chain`,
`position_probabilities`, and `pairwise_precedence`. It validates the one common
positive thinning interval and any canonical count accounting, validates shapes
and finite values, packs canonical little-endian C-order bytes, and recomputes
the array-catalog entries already bound to the successful fit. Transition,
unique-state, repeated-run, maximum-repeat, endpoint, and likelihood-drift
diagnostics use the complete immutable unthinned post-burn arrays. Core derives
the retained order rows only as `unthinned_rows[::thinning_interval]`, derives
the central order as their mode with the frozen event-ID tie break, and then
derives all cross-chain distance summaries. A supplied retained chain or
central order is not convergence evidence. The complete fixed
`ConvergenceRuleOwner` then deterministically produces PASS, WARN, FAIL, or
NOT_ASSESSABLE. The sealed result and canonical payload must match that result;
supplying a different assessment and re-hashing its containers is invalid.

The convergence-to-final transition is closed:

| Complete worker evidence | Core assessment | Final status | Scientific use |
| --- | --- | --- | --- |
| every declared final attempt is valid `SUCCESS` | `CONVERGENCE_PASS` | `SUCCESS` | eligible subject to every other gate |
| every declared final attempt is valid `SUCCESS` | `CONVERGENCE_WARN` | `CONVERGENCE_WARN` | descriptive only; never interpretive evidence |
| every declared final attempt is valid `SUCCESS` | `CONVERGENCE_FAIL` | `CONVERGENCE_FAILED` | quarantined |
| every declared final attempt is valid `SUCCESS` | `CONVERGENCE_NOT_ASSESSABLE` | `CONVERGENCE_NOT_ASSESSABLE` | descriptive/quarantined only |
| any declared chain ends negative | not run or retained diagnostically | precedence-selected negative status | no admitted scientific result |

`CompletedFitRecord` is permitted only for final status `SUCCESS` or
`CONVERGENCE_WARN`; it adds the scientific fields below. `CONVERGENCE_WARN` is
a terminal completed universe, but it is not an admitted result for CLI
`COMPLETE`, report coverage, robustness, null, or per-integration backend
assessment calculations.

### 9.1 `BackendIdentity`

Every described algorithm also owns one complete staging contract:

```text
StageSemanticsDefinition
  stage_semantics_schema_version: Literal["ebm-audit-stage-semantics/1.0"]
  stage_model_availability: AVAILABLE | UNAVAILABLE
  stage_axis_id: Literal["strict-prefix-count-v1"]
  unavailable_reason_code: null when AVAILABLE | StableCode when UNAVAILABLE
  # the remaining fields are all required only when AVAILABLE and all absent
  # when UNAVAILABLE
  reference_selection_method_id: MachineId
  fitted_distribution_method_id: MachineId
  stage_prior_method_id: MachineId
  stage_prior_max_iterations: positive safe integer
  final_prior_residual_method_id: MachineId
  final_prior_residual_tolerance: finite float > 0
  final_prior_residual_comparison_rule_id: Literal["strictly-less-than-v1"]
  final_prior_residual_failure_status: Literal["BACKEND_ERROR"]
  final_prior_residual_failure_code: StableCode
  posterior_method_id: MachineId
  staging_rng_rule_id: MachineId
  map_rule_id: MachineId
  expected_stage_rule_id: MachineId
  fixed_evaluation_rule_id: MachineId
```

`SupportedAlgorithm.stage_semantics_digest` is SHA-256 over
`ASCII("ebm-audit/stage-semantics/1") || NUL || RFC8785-JCS(definition)`.
`DatasetDescriptor` and `StageDatasetDescriptor` repeat that exact digest, so a
request cannot select a named algorithm while silently changing its stage axis,
reference-order rule, fitted distributions, prior, posterior, RNG, MAP,
expectation, or fixed-evaluation meaning.

An algorithm whose stage capabilities are all false declares `UNAVAILABLE` plus
one stable reason and omits every stage-model method/tolerance field. It does not
invent placeholder scientific settings. Any algorithm that emits a stage array
must declare `AVAILABLE`, a null reason, and the complete method/tolerance set.

```text
BackendIdentity
  adapter_id / adapter_version: non-empty stable strings
  worker_executable_digest: Sha256Digest
  worker_code_digest: Sha256Digest
  backend_name: non-empty stable MachineId
  backend_version: non-empty string | null
  backend_source_commit: exactly 40-hex SHA-1 OID, exactly 64-hex SHA-256 OID, or null
  backend_source_digest: Sha256Digest | null
  environment_digest: Sha256Digest
  algorithm_id: non-empty stable string
  identity_evidence: non-empty tuple[EvidenceReference]
```

`backend_name` is never null: an opaque/private backend still chooses and keeps
one stable non-secret machine identifier. Unknown version/source facts are
explicit `null`, never guessed. Any integration that declares an exact source
commit must bind and verify that commit; no named package is privileged or
presumed to be the paper implementation.

### 9.2 `CompletedFitRecord` and chain separation

A completed universe adds:

```text
  event_ids: ordered tuple[MachineId], length N
  chain_results: ordered tuple[FinalChainScientificPayload], one per chain-plan row
  reference_chain: ReferenceChainSelection
  convergence: ConvergenceRecord

FinalChainScientificPayload
  chain_payload_schema_version: Literal["ebm-audit-final-chain-payload/1.0"]
  chain_payload_digest: Sha256Digest
  chain_plan_position: nonnegative int
  chain_execution_id / final_attempt_id: Sha256Digest
  seed: UInt64Hex
  chain_id: exact planned ID
  event_ids: ordered tuple[MachineId], length N
  central_order_event_ids: tuple[MachineId], length N
  central_order_permutation: int32[N]
  central_order_method: CentralOrderMethod
  raw_iteration_count: int R >= 1 | null for a non-chain algorithm
  burn_in_count: int B with 0<=B<R | null
  thinning_interval: int T>=1 | null
  postburn_unthinned_state_count: int U = R-B | null
  retained_state_count: int S = floor((R-1-B)/thinning_interval)+1 | null
  likelihood_indexing: Literal["post-proposal-state/1"] | null
  actual_transition_count: int | null
  actual_transition_fraction: float in [0,1] | null
  arrays: typed array catalog
  field_origins: map[field name, FieldProvenance]
  participant_event_manifest: ParticipantEventManifest
  preprocessing_manifest_digest: Sha256Digest
  stage_semantics_digest: Sha256Digest
  stage_model_reference: StageModelReference | null
  component_applicability: FixedCohortStageComponentApplicabilitySet
  resource_summary: ResourceSummary
  backend_artifacts: tuple[ArtifactReference]

ReferenceChainSelection
  rule_id: Literal["lowest-chain-plan-position/1"]
  chain_plan_position: Literal[0]
  chain_execution_id / final_attempt_id / chain_payload_digest: exact selected values
```

`chain_results` is in exact chain-plan order and contains exactly one validated
final successful-attempt payload for every declared chain. The chain payload
digest uses domain `ebm-audit/final-chain-payload/1` over the complete object
with `chain_payload_digest` removed. `reference_chain` always selects plan
position zero; it is declared in the universe-cache preimage and cannot be chosen
from observed fit quality. The headline order and any API requesting the
"reference result" read only that selected payload.

Within-fit summaries are computed separately inside each chain payload. Chain
uncertainty is computed only from the ordered set of per-chain summaries and is
stored in `ConvergenceRecord`. The core MUST NOT concatenate chain samples,
average chain position/pairwise matrices into a within-fit matrix, choose a
chain by likelihood/convergence/order, or otherwise relabel between-chain
variation as within-fit uncertainty. A downstream aggregate may display all
per-chain values and the closed pairwise chain-distance summaries; it may not
manufacture a pooled posterior.

The central permutation representation is **event index at ordinal position**.
For example, `[2, 0, 1]` means the event whose canonical request index is 2 is
first. It is not a per-event position assignment. One-based backend assignments
must be explicitly converted and round-trip tested.

`central_order_event_ids[p] == event_ids[central_order_permutation[p]]` for every
position `p`.

Staging uses a distinct per-chain fitted-model owner:

```text
PrivateArrayBinding
  member_name: backend.<adapter>.<member>
  array_digest: Sha256Digest

StageModelReference
  stage_model_reference_schema_version:
    Literal["ebm-audit-stage-model-reference/1.0"]
  stage_model_reference_digest: Sha256Digest
  event_ids: exact ordered chain event IDs
  selection_method_id: exact StageSemanticsDefinition method
  reference_order_permutation: complete permutation of 0..N-1
  reference_order_binding: PrivateArrayBinding to one int32[N] private array
  fitted_distribution_bindings: non-empty unique tuple[PrivateArrayBinding]
  final_stage_prior_binding: PrivateArrayBinding to float64[N+1]
  final_stage_prior_fixed_point_l1_residual: finite float >= 0
  stage_semantics_digest: exact described algorithm digest
```

`stage_model_reference_digest` uses the sole domain
`ebm-audit/stage-model-reference/1` over the complete object with that digest
removed. Every binding resolves to exactly one identically named array-catalog
entry with the same array digest. Fitted-distribution bindings cover the full
event axis; the prior binding covers all stages `0..N`. The object is included
unchanged in the worker-fit digest, final-chain digest, canonical-chain
projection, and canonical-scientific-payload digest.

The final-prior residual is one additional upstream posterior/M-step evaluation
at the returned final pi, without replacing pi or emitting another posterior:
`L1(pi_next - final_pi)`. It must be strictly less than the declared tolerance.
Equality fails. Non-finite, negative, or above/equal-threshold residuals return
the declared typed failure and cannot produce stage output.

Any training or evaluation stage array makes `stage_model_reference` mandatory;
without a stage array it must be `null`. Thus training and fixed-evaluation
posteriors in one chain necessarily identify the same fitted order,
distributions, and final prior. This reference is independent of the headline
`central_order_permutation`. Optional downstream integration context: a backend
may derive the headline from retained-state mode while conditioning staging on a
different, explicitly declared native order and matched fitted distributions.
Equality is neither required nor implied, and the difference must remain
visible.

`CentralOrderMethod` is closed and records `method_id`, `candidate_source`,
nullable `objective_id`, and the mandatory tie rule
`lexicographically-smallest-event-id-sequence/1`. `ebm-audit-worker/v2` permits only:

- `retained-state-mode/1`: choose the most frequent retained canonical order;
  on equal frequency choose the lexicographically smallest event-ID sequence;
  or
- `backend-objective-maximum/1`: choose the greatest value of the declared
  deterministic backend `objective_id` over its explored order set; on an exact
  tie choose the lexicographically smallest event-ID sequence.

The method record is part of the worker payload, final chain payload, cache
identity, and comparison provenance. A worker cannot return an unnamed
representative order, use first-observed tie breaking, or change the method
without changing result/cache identity. Comparisons that require equivalent
summary semantics require equal method records.

### 9.3 Per-chain arrays

Every array below belongs to exactly one `FinalChainScientificPayload` (and its
one-chain worker antecedent), never to the multi-chain record itself.

| Field | Shape | Required semantics |
| --- | --- | --- |
| `postburn_order_state_chain` | `[U,N]` integer | Complete unthinned returned rows `B..R-1`; row `q` is current state after proposal `q+1`; repeated rejection states remain. |
| `postburn_likelihood_trace` | `[U]` float | Aligned one-to-one with the unthinned post-burn states. |
| `order_state_chain` | `[S,N]` integer | Thinned returned rows `B+m*T`, `m>=0`, `B+m*T<R`. |
| `likelihood_trace` | `[S]` float | Aligned one-to-one with the thinned retained states. |
| `postburn_state_change_mask` | `[max(U-1,0)]` boolean | Optional native/derived adjacent-state-change indicator; row `q` compares unthinned rows `q` and `q+1`. |
| `position_probabilities` | `[N,N]` float | Row `i`, column `p` is `P(event i at position p)`. |
| `pairwise_precedence` | `[N,N]` float | Cell `[i,j]` is `P(event i before event j)`; diagonal is `0.5`. |
| `training_row_indexes` | `[P]` int64 | Exact request array `[0,...,P-1]`; provides stage-row alignment. |
| `training_stage_posterior` | `[P,N+1]` float | Row probabilities for canonical stages `0..N`, conditioned on the chain's one `StageModelReference`. |
| `training_map_stage` | `[P]` integer | Lowest index among tied posterior maxima. |
| `training_map_tie_mask` | `[P,N+1]` boolean | `true` exactly at every posterior-maximizing stage; each row contains at least one `true`. |
| `training_expected_stage` | `[P]` float | `sum(k * posterior[k])`, `k=0..N`. |
| `evaluation_row_indexes` | `[Q]` int64 | Exact request array `[0,...,Q-1]`; provides stage-row alignment. |
| `evaluation_stage_posterior` | `[Q,N+1]` float | Optional separately supplied fixed cohort, conditioned on the same fitted `StageModelReference` with no refit. |
| `evaluation_map_stage` | `[Q]` integer | Same tie rule. |
| `evaluation_map_tie_mask` | `[Q,N+1]` boolean | Same complete tied-stage encoding. |
| `evaluation_expected_stage` | `[Q]` float | Same expectation. |

For every posterior row, the MAP stage equals the lowest `true` index in the
corresponding tie mask. A row is tied exactly when its mask has more than one
`true`; the mask therefore supplies both the tie flag and complete tied-stage
list without an object array or ambiguous variable-length JSON field.
Order samples, position probabilities, pairwise precedence, likelihood traces,
transition diagnostics, stage posteriors, and hard stages are **independently**
optional according to truthful capabilities and requested outputs. No true
capability makes another capability true. Central order is required for a
completed MVP fit. An unavailable field is absent, not an empty array, zero
matrix, uniform placeholder, shifted trace, or inferred native value.

The profile-characterization refinement is deliberately stricter than the
generic fit contract. Each of its three budget specifications requests exactly,
in canonical registry order, `central_order`, `order_samples`,
`accepted_transition_diagnostics`, `position_probabilities`,
`pairwise_precedence`, `fitted_event_distributions`,
`evaluation_stage_posterior`, `evaluation_hard_stages`, and
`evaluation_expected_stage`. A conformance EBM that declares
`fixed_evaluation_cohort_staging=true` must provide those requested evaluation
outputs; central-order-only output, evaluation-stage omission, training-stage
substitution, and `likelihood_trace` substitution are invalid profile plans. An
EBM that does not declare that capability keeps the affected evidence explicitly
`NOT_APPLICABLE_BY_CAPABILITY`; the missing component is never inferred or
converted to pass/fail. Profile stage MAE aligns the exact generated fixed
evaluation-cohort rows through `evaluation_row_indexes` to the same rows'
`THRESHOLD_STAGE` truth. An incompatible truth/fitted stage axis is
`NOT_ASSESSABLE` and cannot produce a budget selection.

The same pre-execution profile owner fixes selection-policy shape without
containing a result. Transition quality is
`PENDING_INDEPENDENT_TRANSITION_RULE_REVIEW` and therefore currently
`NO_SELECTION`; a caller cannot supply or rehash a `PASS`. A future opaque
product evidence receipt must bind a versioned machine-executable independent
decision owner over all four transition observations, including directions,
per-metric aggregation/tolerances, endpoint/zero rules, complete denominators,
exact plan/evidence/subject identity, and no preferred-central-order targeting.
Runtime comparison likewise operates on 18 complete matched rows per direct
relation. Each row is candidate terminal core-observed runtime divided by a
strictly positive reference terminal core-observed runtime. The selected
summary is non-interpolating inverse-empirical-CDF `Q(0.5)`, the ninth one-based
ordered ratio, and passes only when strictly below `1` at tolerance `0`.

The chain index convention is exact and represents only returned post-proposal
states. `R=raw_iteration_count` is both the number of proposal updates and the
number of returned rows. Returned row `q` for `0<=q<R` is current state after
proposal `q+1`; it repeats row `q-1` on rejection when `q>0`. Initialized state
`S0` is not a returned row. Burn-in `B` discards the first `B` returned rows, so
the unthinned post-burn slice is `[B:R]` and `U=R-B`. Thinned row `m` is returned
row `B+m*T` while `B+m*T<R`, so
`S=floor((R-1-B)/T)+1`. Actual transition count compares adjacent unthinned
post-burn rows; its opportunity denominator is `max(U-1,0)`. When that
denominator is zero, the count is `0` and the fraction is `null`, making any
rule that requires a fraction not assessable rather than fabricating a pass.

`order_samples=true` requires both order-chain arrays and their counts.
`likelihood_trace=true` independently requires both likelihood arrays, finite
values, `likelihood_indexing=post-proposal-state/1`, and exact one-to-one
alignment with the same returned-row indexes; it does not require order samples.
`accepted_transition_diagnostics=true` independently requires the state-change
mask plus count/fraction (null only for zero opportunities); it does not make
order samples or likelihood available. If order samples are present while the
native transition capability is false, the core may derive the mask/count and
labels them `CORE_DERIVED` without changing the worker capability. Position and
precedence matrices may likewise be native or truthfully derived from order
samples. A genuinely non-chain fit sets all chain schedule/count/indexing fields
to `null` and omits every chain-indexed array. Its core-final convergence state
is necessarily `CONVERGENCE_NOT_ASSESSABLE`.

Contract tests include `R=1,B=0,T=1`, zero burn-in, `B=R-1`, thinning wider than
the post-burn window, all-rejected proposals, independent capability
combinations, and aligned likelihood sentinels. A worker whose native likelihood
row and native order row describe different proposal states MUST declare
`likelihood_trace=false` and omit both likelihood arrays; shifting, padding,
replaying, or instrumenting the upstream algorithm to manufacture alignment is
forbidden.

Valid derivations include position and pairwise matrices from a valid retained
state chain, or MAP/expected stage from a valid posterior. Each derived field has:

```text
FieldProvenance
  origin: WORKER_DERIVED | CORE_DERIVED
  method_id: versioned non-empty identifier
  source_fields: non-empty tuple[field name]
  source_hashes: non-empty tuple[Sha256Digest]
```

### 9.4 Inclusion manifest

```text
ParticipantEventManifest
  request_training_participants: P
  returned_training_participants: P
  training_row_indexes_digest: exact shared request/response array digest
  request_evaluation_participants: Q
  returned_evaluation_participants: Q or 0 when not requested
  evaluation_row_indexes_digest: exact shared digest or null when absent
  request_events: ordered event IDs
  returned_events: identical ordered event IDs
  worker_removed_participants: exactly []
  worker_removed_events: exactly []
  worker_modified_cells: exactly []
  core_data_accounting_digest: Sha256Digest
```

Any mismatch or worker-side loss/modification is `PROTOCOL_ERROR`. Core-side
complete-case, feature-set, influence, or other declared operations produce a new
request plus accounting manifest; they are not worker exclusions.

### 9.5 `StageResult` is not a fit result

The separate `stage` command is reserved and unavailable in the current
protocol. Its future response schema is `ebm-audit-stage-result/1.0`, a
distinct closed object containing:

```text
StageResult
  stage_result_schema_version: Literal["ebm-audit-stage-result/1.0"]
  protocol_version / request_id / stage_call_id
  event_ids: exact artifact-bound order
  stage_semantics_digest: Sha256Digest
  stage_model_reference_digest: Sha256Digest
  fitted_artifact: ArtifactBinding
  stage_row_indexes: int64[Q], exactly [0, ..., Q-1]
  stage_posterior: float64[Q,N+1] | absent
  stage_map_stage: int32[Q] | absent
  stage_map_tie_mask: bool[Q,N+1] | absent
  stage_expected_stage: float64[Q] | absent
  field_origins / accounting manifest / warnings / resources
  input_digest / config_digest / settings_digest
  core_code_digest / worker_executable_digest / worker_code_digest
  backend_source_digest / environment_digest / capabilities_digest
  seed: UInt64Hex | null
```

The fitted artifact binds its creating request/result digest, backend/algorithm,
worker-executable/worker-code/backend-source/environment identity, event IDs,
settings, stage semantics, and nullable `stage_model_reference_digest`. A
stage-capable artifact carries the nonnull creating-chain digest. `StageResult`
must repeat that exact nonnull value; a different, missing, or artifact-detached
reference is `PROTOCOL_ERROR` even when the artifact file SHA is unchanged.
The closed schema shape alone cannot prove equality between those sibling
digest fields. Portable `stage` therefore remains **NOT ADMITTED / UNVERIFIED**
until the core implements and tests that exact runtime equality check; an
adapter must not claim the capability from schema-valid objects alone.
`stage` MUST NOT refit. A central order, MCMC chain, fit likelihood trace, or
fitted distribution is neither required nor permitted in `StageResult`; their
absence is not an empty fit. Posterior, MAP/tie, expected-stage, finiteness, and
row-alignment invariants are identical to fit staging. Unsupported fields are
absent according to truthful capabilities, never placeholders.

## 10. Result invariants

The core validates every invariant before admitting a result:

1. `event_ids` are unique, match the request exactly, and have length `N >= 2`.
2. Every central/chain order is an integer permutation of `0..N-1` with no
   duplicate, missing, one-based, negative, or out-of-range value.
3. All admitted numeric arrays are finite. Optional absent arrays are absent.
4. A position matrix has shape `[N,N]`, is nonnegative, and every row and column
   sums to 1 within the frozen canonical numerical tolerance.
5. A precedence matrix has shape `[N,N]`, entries in `[0,1]`, diagonal `0.5`
   within the frozen tolerance, and `P[i,j] + P[j,i] == 1` within that tolerance
   for `i != j`.
6. A stage posterior has shape `[participant_count,N+1]`, is nonnegative, and
   every row sums to 1 within the frozen tolerance.
7. MAP stages are integers in `0..N`; expected stages are in `[0,N]`; both equal
   the deterministic derivations from a supplied posterior within the frozen
   tolerance.
8. Every stage array has one nonnull, digest-valid `StageModelReference` whose
   event IDs, full permutation, selection method, private order/distribution/
   final-prior catalog bindings, and field provenance match the described stage
   semantics and exact chain. Training and evaluation posteriors share it. Its
   order may differ from the headline retained-state central order.
9. Each chain-indexed capability validates independently. When order samples are
   present, `postburn_unthinned_state_count=R-B` equals both order-array rules and
   `retained_state_count=floor((R-1-B)/T)+1` equals the retained order length;
   the thinned order array is the exact indexed subset. When likelihood is
   present, those same counts independently equal the likelihood-array lengths,
   each likelihood row represents the same returned post-proposal index, and the
   retained trace is its exact indexed subset. Absence of either capability
   requires absence of its arrays, not absence of the other capability.
10. When transition diagnostics are present, `actual_transition_count` equals the
   true count encoded by a mask of length `max(R-B-1,0)`. When order samples are
   also present, the mask exactly equals unequal adjacent unthinned states. The
   fraction uses denominator `R-B-1` when positive and is otherwise `null`. It is
   never calculated after thinning or inferred from an upstream variable name
   such as “accepted orders.”
11. Participant/event counts exactly match the request manifest, and returned
    training/evaluation/stage row-index arrays exactly equal their corresponding
    request arrays. Count equality without exact row alignment is insufficient.
12. Field presence and origin agree with requested outputs and each independently
    declared capability; a valid derivation does not promote a native capability.
13. All identity, canonical string seed, settings, distinct core/worker/backend/
    environment, input, and file digests bind to the invocation.

The pre-freeze tolerance proposal is absolute `1e-12` and relative `1e-10`, as
declared in the metric and benchmark drafts. The final values are read from the
frozen benchmark contract and recorded in every validation receipt. Any violation
is a visible `PROTOCOL_ERROR`; normalization, clipping, row
drops, relabelling, or shape repair after response is forbidden.

## 11. Convergence record

```text
ConvergenceRecord
  assessment: ConvergenceAssessment
  rule_set_version: non-empty string
  sampling_accounting_by_chain: tuple[ConvergenceSamplingAccounting]
  actual_transition_fraction_by_chain: tuple[ChainMetricValue]
  unique_state_count_by_chain: tuple[ChainMetricValue]
  unique_state_fraction_by_chain: tuple[ChainMetricValue]
  repeated_state_run_summary: RepeatedStateRunSummary | null
  likelihood_trace_summary: LikelihoodTraceSummary | null
  central_order_chain_distances: PairwiseDistanceSummary | null
  position_matrix_chain_distances: PairwiseDistanceSummary | null
  precedence_matrix_chain_distances: PairwiseDistanceSummary | null
  budget_stability_summary: BudgetStabilitySummary | null
  reasons: non-empty tuple[stable code] for WARN/FAIL/NOT_ASSESSABLE
```

`ConvergenceSamplingAccounting` is the closed row
`{chain_execution_id, order_state_status, thinning_interval,
postburn_unthinned_state_count, retained_state_count}`. The interval is always a
positive safe integer. `VALID` requires both core-derived safe-integer counts;
`MISSING` or `INVALID` requires both counts to be `null`. The named runtime hook
`convergence-sampling-accounting-exact/1` derives `0` when the unthinned count is
zero and otherwise derives
`floor((postburn_unthinned_state_count-1)/thinning_interval)+1`, then requires
the retained count to equal it. JSON Schema closes the typed branches but is
not arithmetic proof. `ChainMetricValue` is `{chain_execution_id, value}`. A
`PairwiseDistanceSummary` contains a fixed metric ID, every ordered
left/right-chain pair once, and finite median/maximum distance (or `null` when no
pair exists). `RepeatedStateRunSummary`, `LikelihoodTraceSummary`, and
`BudgetStabilitySummary` have the exact closed fields in
`canonical-records.schema.json`; they are not backend mappings. All chain-keyed
tuples follow chain-plan order and all pair tuples follow lexicographic
`(left plan position, right plan position)` order.

The frozen convergence rule is defined in the metric/benchmark contracts. R-hat
or ESS is included only when its representation and assumptions are explicitly
justified. The mapping is total: `CONVERGENCE_PASS -> SUCCESS`,
`CONVERGENCE_WARN -> CONVERGENCE_WARN`, `CONVERGENCE_FAIL ->
CONVERGENCE_FAILED`, and `CONVERGENCE_NOT_ASSESSABLE ->
CONVERGENCE_NOT_ASSESSABLE`. Warn/fail/not-assessable arrays may be retained for
descriptive diagnostics but cannot enter order/stage/null/robustness summaries,
valid-coverage numerators, backend acceptance, or CLI `COMPLETE` as valid
evidence.

Here and throughout the schema, “diagnostic” means a statistical sampling,
software, or protocol check. It is not a clinical diagnostic claim. Reports MUST
not use these records to describe a participant as diagnosed, disease-positive,
or clinically classified.

## 12. Comparison semantics

Every comparison emits the closed `$defs/ComparisonRecord` with schema and
comparison IDs; left/right universe and result IDs; versioned metric ID; evidence
axis; comparability; a closed participant-alignment method/count/digest record;
ordered common/left-only/right-only event IDs; scalar value or explicit absence;
and reason code. Private tokens exist only in private alignment provenance. A
value is forbidden and a reason is required when comparability is
`NOT_COMPARABLE`.

### 12.1 Strict orders with identical event sets

Let `r_A(i)` and `r_B(i)` be zero-based ranks of event `i`, and `N` be the event
count. Required metrics include:

- normalized Kendall inversion distance:
  `discordant_pairs / (N * (N - 1) / 2)`, in `[0,1]`;
- normalized Spearman footrule:
  `sum_i |r_A(i)-r_B(i)| / floor(N^2/2)`, in `[0,1]`;
- each event's absolute rank shift;
- predeclared top-`k` overlap `|intersection|/k` (also report intersection size
  and Jaccard);
- first-event and last-event equality.

For `N < 2`, pairwise order distances are `NOT_COMPARABLE`. A Kendall p-value is
never a robustness score.

### 12.2 Strict orders with differing event sets

Let `C` be the intersection of event IDs. Restrict each order to `C` while
preserving relative order, then compute strict-order distances on those restricted
orders. Report `A_only`, `B_only`, and `C` explicitly. With fewer than two common
events, the order distance is `NOT_COMPARABLE`.

Position matrices over different event sets are comparable only when order
samples are available for both sides: restrict every sample to `C`, rerank it to
`0..|C|-1`, and recompute common-set position matrices. Marginal position
matrices alone do not contain enough joint information to perform this operation;
without samples, position-distribution distance is `NOT_COMPARABLE`.

Pairwise precedence values may be compared directly for pairs wholly inside
`C`, because their relative relation is unchanged by removing other events. No
value is imputed for an omitted event.

### 12.3 Position and precedence matrices

Expected position is `sum_p p * P(event at p)`. Median and quantiles use the
smallest position whose cumulative probability meets the target. Normalized
entropy is `-sum_p q_p log(q_p) / log(N)` for `N > 1`, with `0 log 0 = 0`.

Position, pairwise, and rank summaries retain an explicit evidence axis:

- `within_fit`;
- `chain`;
- `sampling`;
- `analyst_decision`;
- `participant_influence`; or
- `null`.

Arrays from different axes MUST NOT be pooled into one distribution or heatmap.

### 12.4 Stage semantics

Native stages are directly comparable only when all are true:

1. event ID sets are identical;
2. both use canonical strict-prefix stages `0..N`;
3. event directions are identical;
4. `stage_semantics_digest` is identical, including prior and posterior
   definition relevant to comparison; and
5. participants are aligned to the same fixed evaluation cohort, or the selection
   limitation below is recorded.

Each compared posterior must additionally have a valid local
`StageModelReference`. Those reference digests normally differ across fits
because each binds its own selected order, fitted distributions, and final
prior; comparability requires equal semantics and aligned participants, not a
false claim that separately fitted models are byte-identical. Reports identify
the reference digest and disclose when its order differs from that fit's
headline central order.

Optional downstream integration context: a backend whose native routine returns
a posterior evaluated with a pre-update prior alongside an updated final prior
may treat that native posterior as private diagnostic evidence only. A worker may
recompute canonical training and fixed-evaluation posteriors exactly once with
the unchanged declared order, unchanged fitted distributions, and final prior
only when its authenticated stage-semantics definition specifies that operation.
Its provenance is `WORKER_DERIVED` and binds the stage-model-reference digest and
all private source-array digests. No refit, extra update, silent fixed-point
iteration, or inferred capability is allowed. The declared iteration bound,
method, tolerance, comparison rule, and typed failure are integration-specific
identity. A non-finite, negative, or out-of-tolerance residual is a typed failure,
never a warning-only posterior repair.

On a common participant, calculate:

- signed and absolute expected-stage difference;
- MAP-stage equality;
- normalized absolute stage difference `|s_A-s_B| / N`;
- one-dimensional Wasserstein-1 distance between the two stage posteriors on
  support `0..N`, divided by `N`; and
- optional Jensen-Shannon distance
  `sqrt(JSD(P,Q) / log(2))`, using the midpoint distribution and `0 log 0 = 0`.

Aggregate summaries report the complete denominator, missing comparisons, and
participant selection source. Probabilistic output is retained even when MAP
agreement is reported.

Bootstrap and influence comparisons stage one fixed declared evaluation cohort
under every fit. If the worker cannot stage that cohort, the stage comparison is
the component-level record `{status: NOT_APPLICABLE_BY_CAPABILITY, value: null,
reason_code: STAGING.FIXED_COHORT_UNAVAILABLE}`; the candidate remains `VALID`,
fits execute, and order, position, pairwise, influence, and convergence outputs
continue. Whole-candidate `UNSUPPORTED_CAPABILITY` applies only when the
requested fit or a required non-stage output cannot run. Training-cohort,
in-bag, and common-in-fit stage values are not fallbacks. `SELECTION_COUPLED`
remains available only for separately declared
descriptive comparisons outside bootstrap and influence and can never be
presented as fixed-cohort stage stability. The applicability record and array
catalog form one closed union in both `WorkerFitPayloadDigestPreimage` and
`CanonicalChainScientificProjection`. A not-applicable posterior forbids
`evaluation_row_indexes` and `evaluation_stage_posterior`; not-applicable hard
stages forbid `evaluation_row_indexes`, `evaluation_map_stage`, and
`evaluation_map_tie_mask`; and not-applicable expected stage forbids
`evaluation_row_indexes` and `evaluation_expected_stage`. The executable schemas
and runtime reconstruct this relation from the complete payload rather than
trusting an isolated status field.

The same closed union applies to `stage_model_reference`: any present training
or evaluation stage member requires exactly one valid nonnull reference, and no
present stage member requires `null`. Fully rehashed attacks that omit the
reference, mismatch a private binding, shorten final pi, detach field
provenance, change stage semantics, or substitute the canonical projection fail
at the runtime verifier.

When event sets differ, native stage numbers and posteriors are
`SEMANTICALLY_NON_EQUIVALENT`. The report MAY show each expected stage divided by
its own event count as a descriptive `normalized_progress_fraction`, but MUST:

- apply the exact label `SEMANTICALLY_NON_EQUIVALENT`;
- disclose both event sets and denominators;
- not pool the values with native-stage agreement; and
- not call the difference stage agreement, reproduction, or progression change.

Subtype, temporal, grouped-event, and longitudinal outputs are not compared in
version 0.1.

## 13. Participant influence records

An influence operation identifies a removed participant only by private token in
private provenance and by pseudonymous alias in authorized reports. It retains
components rather than one opaque score:

```text
InfluenceMetricResult<T>
  metric_id: exact versioned metric ID
  status: ASSESSABLE | NOT_ASSESSABLE
  value: T | null
  reason_code: stable code | null

FixedCohortStageMetricResult
  metric_id: fixed-cohort-stage-wasserstein-median/1
             | fixed-cohort-stage-wasserstein-maximum/1
  status: ASSESSABLE | NOT_ASSESSABLE | NOT_APPLICABLE_BY_CAPABILITY
  value: finite probability | null
  reason_code: stable code | null

PairwiseMajorityFlip
  event_a_id / event_b_id: canonical IDs, ordered by UTF-8 bytes
  baseline_probability_a_before_b / removal_probability_a_before_b: float [0,1]
  baseline_relation / removal_relation: A_BEFORE_B | B_BEFORE_A

InfluenceRecord
  influence_schema_version: Literal["ebm-audit-influence/2.0"]
  influence_rule_version: Literal["metrics/influence/v0.1.0"]
  uncertainty_layer: Literal["participant_influence"]
  removal_spec_id: Sha256Digest
  removed_aliases: non-empty ordered tuple[str]
  baseline_universe_id / removal_universe_id: Sha256Digest
  baseline_event_ids / removal_event_ids: ordered tuple[MachineId]
  pairwise_assessment: ASSESSABLE | NOT_ASSESSABLE_FEWER_THAN_TWO_COMMON_EVENTS
  pairwise_assessment_reason_code: null | INFLUENCE.INSUFFICIENT_COMMON_EVENTS
  common_event_count: nonnegative integer
  strict_pairwise_majority_flip_denominator: choose(common_event_count, 2) | null
  fixed_evaluation_cohort_digest: Sha256Digest | null
  fixed_evaluation_cohort_count: nonnegative int | null
  central_order_kendall_distance: InfluenceMetricResult<float>
  maximum_normalized_event_rank_displacement: InfluenceMetricResult<float>
  strict_pairwise_majority_flip_count: InfluenceMetricResult<int>
  strict_pairwise_majority_flip_fraction: InfluenceMetricResult<float>
  strict_pairwise_majority_flips: ordered tuple[PairwiseMajorityFlip]
  position_matrix_distance / pairwise_matrix_distance: InfluenceMetricResult<float>
  baseline_convergence_state / removal_convergence_state: ConvergenceAssessment
  convergence_degradation: InfluenceMetricResult<bool>
  fixed_cohort_stage_wasserstein_median: FixedCohortStageMetricResult
  fixed_cohort_stage_wasserstein_maximum: FixedCohortStageMetricResult
  component_states / assessable_component_ids / participant_state
  display_component_percentiles / influence_display_score
```

This is the complete classifier input from
[`metrics-and-uncertainty.md#62-required-serializable-influence-evidence`](metrics-and-uncertainty.md#62-required-serializable-influence-evidence),
not a display projection. Field-specific metric IDs, nullability, component
states, participant state, display-percentile closure, and pair ordering are
enforced by the discriminated `$defs/InfluenceRecord` union. The executable
record always serializes `common_event_count`. With at least two common events,
the `ASSESSABLE` branch requires a positive denominator, assessable count and
fraction, and null reason. The denominator equals
`common_event_count * (common_event_count-1) / 2`; the flipped-pair count equals
the tuple length, is no greater than that denominator, and the fraction equals
`count/denominator`.

With zero or one common event, the
`NOT_ASSESSABLE_FEWER_THAN_TWO_COMMON_EVENTS` branch requires denominator null,
an empty flipped-pair tuple, null count/fraction values, and the typed reason
`INFLUENCE.INSUFFICIENT_COMMON_EVENTS`. The stable runtime hooks
`influence-common-event-count-exact/1`,
`influence-pairwise-denominator-exact/1`,
`influence-flip-count-matches-pairs/1`, and
`influence-flip-fraction-exact/1` enforce the equalities JSON Schema cannot
express.

Every removal refits preprocessing and the model. Fixed-cohort stage movement is
computed for non-removed baseline participants only when supported. Only the
two fixed-cohort stage metric IDs may use
`NOT_APPLICABLE_BY_CAPABILITY`; that branch requires `value=null` and the exact
reason `STAGING.FIXED_COHORT_UNAVAILABLE`. An ordinary order, position,
pairwise, count, or convergence metric cannot carry that status or reason. The
candidate remains valid and its fit, order, position, pairwise, influence, and
convergence work continues; no in-bag, common-in-fit, or other staging fallback
is substituted. Reports call
an observation `influential`, never `bad`, `wrong`, or an `outlier` unless a
separate declared data-quality rule established that fact.

## 14. Baseline reference and reproduction

A `CanonicalReferenceResult` is an optional local export from the researcher's
existing implementation. It is **not** a `ResultRecord`, worker payload, or
synthetic worker response: it has no universe/chain execution, worker status,
capability declaration, or `WorkerExecutionEvidenceReference`. The closed object is:

```text
CanonicalReferenceResult
  reference_schema_version: Literal["ebm-audit-canonical-reference/2.0"]
  reference_id: Sha256Digest
  exporter: ReferenceExporterProvenance
  implementation: ReferenceImplementationProvenance
  dataset: ReferenceDatasetBinding
  scientific_contract: ReferenceScientificContract
  outputs: ReferenceOutputs
  field_origins: closed map[supplied field, ReferenceFieldProvenance]
  export_receipt: ReferenceExportReceipt

ReferenceExporterProvenance
  exporter_id / exporter_version: non-empty strings
  exporter_code_digest / exporter_environment_digest: Sha256Digest
  export_command_id: non-empty safe identifier

ReferenceImplementationProvenance
  implementation_id: non-empty MachineId
  implementation_version: non-empty string | null
  implementation_code_or_artifact_digest: Sha256Digest
  algorithm_id: non-empty string
  settings_digest / environment_digest: Sha256Digest
  seed_chain_policy_digest: Sha256Digest
  source_commit_or_version: string | null
  evidence: non-empty tuple[EvidenceReference]

ReferenceDatasetBinding
  scientific_data_digest: Sha256Digest
  participant_count / event_count: positive integers
  participant_alignment_method: Literal[
    "private-source-id-to-run-token/1",
    "shared-private-namespace/1"
  ]
  private_alignment_artifact_digest: Sha256Digest
  reference_row_order_digest: Sha256Digest
  token_parameters: ParticipantTokenParameters

ReferenceScientificContract
  event_ids: ordered non-empty tuple[MachineId]
  event_labels: aligned unique tuple[non-empty text]
  event_directions: aligned tuple[AbnormalDirection]
  preprocessing_digest / missingness_digest / inclusion_digest: Sha256Digest
  stage_semantics_digest: Sha256Digest | null

ReferenceOutputs
  central_order_permutation: int32[N]
  arrays: closed typed-array catalog
  participant_event_manifest: ReferenceParticipantEventManifest
  statistical_diagnostics_digest: Sha256Digest | null

ReferenceParticipantEventManifest
  manifest_schema_version: Literal["ebm-audit-reference-participant-event-manifest/1.0"]
  participant_count / event_count: positive integers
  event_ids: exact ordered reference event IDs
  reference_row_indexes_digest: Sha256Digest
  reference_row_order_digest: Sha256Digest
  core_data_accounting_digest: Sha256Digest

ReferenceFieldProvenance
  origin: Literal["USER_SUPPLIED_REFERENCE"]
  source_field: non-empty string
  method_id: non-empty versioned identifier
  source_digest: Sha256Digest

ReferenceExportReceipt
  created_at_utc: RFC 3339 timestamp
  exporter_input_manifest_digest: Sha256Digest
  private_alignment_artifact_digest: Sha256Digest
  warnings: tuple[WarningRecord]
```

All digest fields use their declared domain-separated `Sha256Digest` preimages;
`reference_id` uses domain `ebm-audit/canonical-reference/2` over the complete
object with only `reference_id=null`.

`statistical_diagnostics_digest` uses domain
`ebm-audit/baseline-statistical-diagnostics/1` over the closed
`BaselineStatisticalDiagnosticsDigestPreimage`. Before hashing, every diagnostic
chain identity is replaced by a deterministic digest derived only from its
ordered chain-plan position. The normalized object is revalidated as a
`ConvergenceRecord`; unknown, repeated, or uncovered chain identities fail.
`null` means comparable reference diagnostics were not supplied and caps the
outcome at `BASELINE_PARTIALLY_REPRODUCED`.

Typed negative worker evidence uses
`ebm-audit-negative-command-evidence/1.1`. It contains the complete closed
command-specific actual-subject preimage and its digest. The reference runtime
must validate that preimage, reconstruct it independently from the validated
request and response envelope, require exact equality, and recompute the
registered domain-separated digest. Shape validation or a well-formed supplied
SHA alone is never subject evidence.
`ReferenceOutputs.arrays` permits only the canonical order/position/pairwise/
stage names and invariants from Section 9.3; unsupported outputs are absent.
Every supplied field has `origin=USER_SUPPLIED_REFERENCE`. Unknown fields are
rejected. The object is bound to the exact private dataset and connected
scientific implementation, not merely to an event order.

The separate private alignment file is exactly
`PrivateReferenceAlignmentArtifact` from the executable schema. It contains
schema version, alignment method, scientific-data digest, participant count,
the same `reference_row_order_digest`, the closed participant-token parameters,
and rows numbered contiguously `0..P-1`. For
`private-source-id-to-run-token/1`, each row contains one `TypedPrivateId`; for
`shared-private-namespace/1`, each row contains one
`hmac-sha256:<64 lowercase hex>` token. Its digest uses domain
`ebm-audit/reference-private-alignment/1` over the complete private artifact.
Every typed ID MUST satisfy the single private-participant-ID rule in Section
3.1 before token or digest construction.
The row-order digest uses domain `ebm-audit/reference-row-order/1` over the
closed `$defs/ReferenceRowOrderDigestPreimage`, containing exactly
`{alignment_method, participant_count, ordered_reference_row_bindings}`. Every reference array's
participant axis uses that same row order and the reference-only manifest repeats
the digest. A mismatch is `BASELINE_NOT_REPRODUCED`.

The reference-only manifest intentionally has no worker request count, returned
count, worker removal list, worker modification list, request/response array
digest, chain, attempt, capability, or lifecycle field. A reference export MUST
NOT instantiate or reuse `ParticipantEventManifest`.

Reference participant rows are aligned inside the private core boundary by the
declared `ReferenceDatasetBinding.participant_alignment_method`, exactly one of:

1. `private-source-id-to-run-token/1`: the exporter supplies source IDs only to a
   separate private alignment file. The core validates unique typed equality and
   converts them to this run's keyed participant tokens before comparison. The ID
   file is never copied to the reference result, worker, report, or default
   manifest; or
2. `shared-private-namespace/1`: exporter and run use the same approved private
   namespace key and typed-ID HMAC method, and the bundle supplies only tokens,
   namespace method/version, and exact dataset digest.

Positional row equality without one of these methods is insufficient. Both
methods require the reference dataset digest to equal the audited baseline data
digest after the declared preprocessing/input contract. Contract tests reorder
reference rows and require correct token remapping; a count-preserving positional
match must fail.

Minimum fields for full baseline reproduction are:

- exact reference dataset digest and one valid private participant-alignment
  method above;
- exact event IDs/labels, directions, and event set;
- exact connected implementation identity, algorithm ID, worker/backend code or
  immutable artifact identity, settings digest, seed/chain policy, and software
  environment identity at the level predeclared by the reference profile;
- exact preprocessing, missingness, participant/event inclusion, and stage-
  semantics digests plus matching counts;
- central order; and
- adequate richer outputs: at least one order-distribution representation
  (sampled states, position probabilities, or pairwise precedence) and the
  participant-stage output used by the original baseline when staging is part of
  the claimed audit, all with explicit row alignment. If the original
  implementation genuinely did not produce a category, that absence is recorded
  and full reproduction is unavailable rather than inferred.

Every additional supplied position, sample, stage, inclusion, preprocessing, or
diagnostic field is compared using predeclared tolerances. Status is assigned:

- `BASELINE_REPRODUCED`: the dataset/alignment, connected implementation,
  algorithm/settings, preprocessing/inclusion, stage semantics, central order,
  and adequate richer-output requirements above were all supplied and every
  supplied comparison passed;
- `BASELINE_PARTIALLY_REPRODUCED`: no supplied comparison failed, but one or more
  full requirements or requested comparable outputs were unavailable. A matching
  central order and counts alone can produce at most this status;
- `BASELINE_NOT_REPRODUCED`: at least one supplied comparable field failed or
  dataset/alignment, implementation/algorithm/settings/stage semantics, or
  participant/event accounting differs;
- `BASELINE_REFERENCE_NOT_SUPPLIED`: no canonical reference bundle was supplied.

Similarity to a paper figure, published order, or hard stage summary can never
produce `BASELINE_REPRODUCED`. When status is not `BASELINE_REPRODUCED`, the
report MUST NOT describe subsequent robustness results as an audit of the
original analysis.

These statuses are executable, not prose-only. `reference_id` is the
domain-separated identity of the complete `CanonicalReferenceResult` with only
its own field null. `BaselineToleranceContract` fixes categorical and integer
equality, exact shapes, exact canonical array digests, and zero absolute and
relative float tolerance for the currently representable digest-only array
evidence; a non-zero numerical tolerance is prohibited until raw comparable
numeric values and a reviewed algorithm exist. `BaselineReproductionRecord`
contains nine ordered comparisons: dataset binding, implementation identity,
scientific contract, participant/event accounting, central order, order
distribution, participant-stage output, statistical diagnostics, and all supplied
fields. Its status, reasons, reference presence/identity, connected result, and
`validated_language_eligibility` are derived, and
`baseline_reproduction_id` hashes the complete preimage with only its own field
null. Validated-language eligibility is true if and only if status is
`BASELINE_REPRODUCED`. The applicable score gate carries that record identity
and passes under the same if-and-only-if rule.

Validated report language and future whole-run gates consume a separate total
`VerifiedBaselineAssessment`, never the reproduction capability directly.
Candidate-execution disposition does not consume baseline authority: it is
derived solely from the exact current sealed result set. The assessment is
issued only from the opaque `SealedResultEvidenceSet` created after the exact
candidate-terminal index is sealed. That evidence set retains
the exact Plan/3 authority, its genuine `PreparationTransaction`, that
transaction's complete ordered candidate-authorization tuple, every exact
finalized, persisted, and admitted cache result, the terminal authorization and
index, and—inside each descriptive `COMPLETED` result (`SUCCESS` or
`CONVERGENCE_WARN`)—the exact ordered tuple of every successful authenticated
chain execution. The Plan/3 projection and transaction must retain the identical
private preparation-publication owner from one `PlanningAuthority`; equal plan
bytes, IDs, or digests from a sibling authority cannot open the journal. A
warning retains the data owners needed for descriptive evidence but does not
gain baseline or interpretive authority. Every production finalized result also
retains and rereads the identical prepared or unprepared candidate
authorization at its transaction ordinal; equal public identifiers from a
different capability owner are insufficient. These identities are rechecked
before result or cache writes and on journal, cache, sealing, and sealed-set
readback. The evidence set is non-copyable, nonserializable, unavailable before
index sealing, and closes further result or cache persistence when issued. It
may issue an opaque non-copyable `SealedCandidateExecutionDisposition` whose
safe counts, state, exit, and terminal-derived failure class are recomputed
from that identical owner on every read. Caller counts, baseline facts,
benchmark facts, mandatory-gate facts, and unexpected-core facts cannot enter
that disposition. No manifest may seal until a future exact run-gate
disposition owns the separate whole-run gates.

The assessment resolves `baseline_analysis_spec_id` from Plan/3 at its actual
candidate ordinal. If that exact terminal is `SUCCESS`, assessment requires the
exact `VerifiedBaselineReproduction` whose connected source is the same
`FinalizedResult` and inherits its four reproduction outcomes. If the exact
terminal is any non-success status, assessment emits
`BASELINE_NOT_ASSESSABLE`, binds the exact result ID, result digest, persisted
owner, and terminal-index digest, carries no reproduction identity, and sets
`validated_language_eligibility` false. Caller status strings, mappings,
digests, reordered or missing chain owners, a foreign genuine assessment, or
detached transaction, candidate-authorization, plan, terminal, result, cache,
and index capabilities cannot issue or reconstruct either authority.

For a supplied reference, derivation also consumes the actual private alignment
artifact. The baseline owner validates its closed schema, exact contiguous row
axis, unique typed participant bindings, token parameters, scientific-data
identity, and participant count; recomputes its row-order and artifact digests;
and checks the same digests against the reference dataset, participant/event
manifest, and export receipt. Participant bindings stay private. A missing,
tampered, or digest-detached alignment artifact cannot produce
`BASELINE_REPRODUCED`. Complete re-verification returns only a privacy-safe
verified-baseline capability for downstream report-language selection and a
future exact whole-run gate.

The planned exporter interface is described in
[`../handoff/real-data-integration.md#5-export-and-validate-a-reference-baseline-if-available`](../handoff/real-data-integration.md#5-export-and-validate-a-reference-baseline-if-available).
It creates a schema/template first, then executes the actual export inside the
researcher's private notebook/process. No participant ID is accepted through the
worker protocol or report path.

## 15. Privacy and artifact exposure

Default public-to-the-researcher artifacts contain counts, hashes, versions,
decisions, approved event labels, aggregate metrics, and pseudonymous aliases.
They contain no direct participant identifiers or raw event measurements.

The following remain private and excluded from the default report bundle:

- identity map, namespace key, private tokens, and source row positions;
- raw input and transformed participant matrices;
- raw covariate/residualisation parameters when they could expose values;
- backend artifacts that embed rows, values, or identifiers;
- unsanitized stdout/stderr, exceptions, source paths, or environment details.

Errors use stable codes, shapes, counts, internal indexes, and approved event IDs.
Artifact scanners test representative direct IDs and raw values against default
outputs. A leak is `PRIVACY_VIOLATION` and a hard conformance failure, not a
warning.
