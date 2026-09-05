# Reading the technical specifications

Use the [practical guides](start-here.md) to install Anim, connect a model, run an
audit, or read its results. The specifications are for developers and methods
reviewers who need exact file formats, calculations, and requirements.

Some specifications preserve earlier designs and acceptance records. A requirement
in one of those records does not mean that the corresponding feature is available
in Anim 0.2.0. This guide distinguishes current interfaces from historical records.
Specification version numbers are separate from the package version.

## Find the relevant reference

| Reference | What to use it for |
| --- | --- |
| [Worker protocol](../spec/adapter-protocol.md) | Requests, responses, declared model outputs, and checks for a separate model process. Start with the [connection guide](adapter-runbook.md). |
| [Data and result formats](../spec/canonical-data-and-result-schema.md) | Exact fields, types, event definitions, and result alignment. “Canonical” means Anim's agreed representation; a “closed” object rejects unknown fields. |
| [Analysis plans](../spec/analysis-universe.md) | How declared choices become planned analyses, including failures and limits on fit counts. |
| [Metrics and uncertainty](../spec/metrics-and-uncertainty.md) | Mathematical definitions, denominators, missing-result rules, and statistical limitations. It also retains historical calibration work. |
| [Current reporting requirements](../spec/reporting-and-claim-language.md) | How a running audit creates a report and why reading saved files cannot regenerate one. The retired prototype is labelled separately. |
| [Report language rules](../spec/report-language-rules.md) | Exact allowed report wording and the evidence needed for each statement. Quoted templates are part of the contract. |
| [Synthetic and null validation](../spec/synthetic-and-null-validation.md) | How generated datasets and no-signal controls are defined. A known generating order is simulation truth, not evidence about a disease. |
| [Scenario calculations](../spec/scenario-derivation-semantics.md) | The calculations required for each synthetic benchmark output. A defined calculation is not evidence that the whole benchmark has passed. |
| [Hashes and frozen records](../spec/artifact-hashing-and-freeze.md) | Exact file and structured-data identities, including historical evaluator records. Use the active protocol registry for current worker hash inputs. |
| [Product and scientific scope](../spec/product-and-scientific-spec.md) | The research questions, prohibited claims, and scientific design, with historical development sections. |
| [Accepted readiness amendment](../spec/ebm-integration-readiness-1.2.0-candidate.md) | The accepted record of software integration readiness. The retained filename contains “candidate”, but the document records acceptance. |
| [Earlier readiness contract](../spec/ebm-integration-readiness.md) | Historical requirements inherited or amended by the accepted record above. Its “in progress” status describes that earlier record. |

## Current behaviour and historical requirements

- **Reports:** the current JSON format is `ebm-audit-report/14.0`. A live audit
  can write an `INCOMPLETE` report even when all its model fits succeed. The
  standalone `report` command remains disabled. Use `summary` and `diff` to
  inspect saved reports, or `rerun` to repeat the complete analysis.
- **Repeated runs:** old specifications describe requirements for cache reuse
  and resuming work. Those are not instructions for the current executor.
  `rerun` checks the original inputs and software and runs the whole plan again;
  it does not continue an old fit or reuse saved scientific results.
- **Readiness counts:** the accepted compact readiness check uses six successful
  fits. Its 104 required outputs are not 104 fits. The earlier proportional
  challenge had a different execution plan; its counts remain historical facts.
- **Exact solver:** `solve_exact_oracle()` returns the full order distribution
  for at most eight events. Internal compact calculations support nine events
  without returning every order as a materialized record. These are engineering
  limits, not thresholds for scientific validity.
- **Publication:** Anim 0.2.0 is published under Apache-2.0. Earlier private-build
  restrictions and references to internal decision records describe project
  history. They are not instructions to obtain private documents before using
  the public package.

## Which definitions to use when implementing a worker

The [protocol registry](../../schemas/protocol-registry.json) and
[worker schema](../../schemas/worker-protocol.schema.json) define the active
`ebm-audit-worker/v2` messages. The hashing specification retains older `/1`
worker definitions; do not copy those historical inputs into a v2 worker.
In particular, the current scientific-request identity includes fit attempt
fields, while a separate identity tests whether two attempts are equivalent
for a permitted retry. The requested-output identity is independent of the
command. Use the [worker SDK guide](custom-worker-guide.md) to avoid implementing
these rules yourself.

Do not resolve an apparent statistical conflict by choosing whichever rule
produces a preferred result. Some retained sections have different scopes:
native worker stage ties, ties used in derived comparisons, display summaries,
and synthetic benchmark classifications are not interchangeable. Historical
“proposed” threshold tables also appear beside later frozen values. Consult the
specific schema and calculation for the result being implemented; report a
remaining conflict with those references. This documentation update does not
change tie rules, numerical thresholds, scientific labels, or benchmark criteria.

## Why some records retain their original wording

The two readiness records, metric rules, report-language rules, and synthetic
generator specification are preserved byte for byte in this update. Their exact
contents identify historical evidence or are explicitly included in scientific
source hashes. Rewording them would change those identities. Their terminology
is explained in the [glossary](start-here.md#terms-you-will-encounter) and current
guides instead.

Several historical references point to evaluator files or internal decision
records that are not part of this public checkout. In particular,
`evaluator/benchmark_contract.yaml` and old `evaluator/fixtures` validation files
are historical references, not missing installation steps. The packaged
[compact readiness contract](https://github.com/timigod/anim/blob/main/evaluator/proportional_benchmark_contract-0.3.0-candidate.yaml)
is a different contract and must not be substituted for them when checking old
evidence.
