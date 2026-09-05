# Anim

Anim helps researchers check how much an event-based model (EBM) result changes
when they make different, scientifically reasonable analysis choices. You choose
the model and the alternatives to test. Anim runs the comparisons and reports
changes, uncertainty, missing results, and failures.

For example, you might compare two preprocessing choices or check how much an
estimated event order changes when individual participants are left out. The
comparisons must be specified before the audit; Anim does not choose a favourable
result for you.

Version: **0.2.0**. Read [what changed in this version](https://github.com/timigod/anim/blob/main/docs/handoff/whats-new-0.2.md).

## Install

Use CPython 3.12:

```sh
python3.12 -m pip install 'anim==0.2.0'
ebm-audit doctor
```

Anim supports macOS and Linux. On macOS it uses Seatbelt, the operating system's
sandbox. On Linux it needs Bubblewrap at `/usr/bin/bwrap` and working namespaces.
These restrict what the separate model process can do. If the required protection
is unavailable, model execution stops with `PRIVACY.CONTAINMENT_UNAVAILABLE`.
Windows and other Python versions are not supported.

For work on the source code, use `uv sync --frozen` followed by
`uv run ebm-audit doctor`. The [installation and packaging guide](https://github.com/timigod/anim/blob/main/docs/handoff/packaging-validation.md)
covers offline installation and the checks run on macOS and Linux.

## Try the example

Start with generated data, before connecting any participant data:

```sh
ebm-audit demo --conformance-ebm
```

Open `ebm-audit-demo/report/report.html`. The same directory contains
`report.json` and `universes.csv`; warnings are in
`ebm-audit-demo/warnings.jsonl`.

The example is designed to exercise Anim's software. Its expected result is
`PARTIAL`, with an `INCOMPLETE` report, because it does not supply everything
needed for a complete scientific assessment. That is expected behaviour for
this example. It does not show that a disease model is scientifically valid.

You can also read a summary in the terminal:

```sh
ebm-audit summary --run-dir ebm-audit-demo
```

## Connect your model

A **worker** is a small, separate program that runs your model and returns its
results to Anim. Start a worker project with:

```sh
ebm-audit adapter init my-worker
```

Follow the generated README and the [model connection guide](https://github.com/timigod/anim/blob/main/docs/handoff/adapter-runbook.md).
The starter teaches the connection format; it is not itself an EBM. The guide
also provides an optional example using the existing open-source **pysaebm**
model on generated data.

Use `adapter pin` to record the exact model software you chose. Use
`adapter check` to test the connection and check which outputs it supports.
A passing connection test does not establish that the model is appropriate for
your research question.

## Run, repeat, and compare

For a configured audit, `run` carries out the analyses you specified. `rerun`
checks the original inputs and software, then repeats the whole plan in a new
directory. It preserves the earlier results. `diff` compares two saved audits.

| What you want to do | Guide |
| --- | --- |
| Find the right starting point and understand terms used by Anim | [Documentation guide](https://github.com/timigod/anim/blob/main/docs/handoff/start-here.md) |
| Prepare data and declare analysis choices | [Input data](https://github.com/timigod/anim/blob/main/docs/handoff/input-data-dictionary.md) |
| Follow an example from input to report | [How the example works](https://github.com/timigod/anim/blob/main/docs/how-it-works.md) |
| Repeat an audit or recover from an interruption | [Repeating an audit](https://github.com/timigod/anim/blob/main/docs/reproducibility.md) |
| Track progress, stop a run, or limit simultaneous model processes | [Managing runs](https://github.com/timigod/anim/blob/main/docs/execution.md) |
| Understand the report and compare two audits | [Reading and comparing reports](https://github.com/timigod/anim/blob/main/docs/report-comparison.md) |
| Connect a model held in a private notebook | [Notebook handoff](https://github.com/timigod/anim/blob/main/docs/handoff/frozen-notebook-handoff.md) |
| Understand the current limits when using research data | [Research-data integration](https://github.com/timigod/anim/blob/main/docs/handoff/real-data-integration.md) |

The supported tools for connecting a model are the `ebm-audit` commands and the
Python `ebm_audit.worker_sdk` package. Developers can find the exact file formats
and requirements through the documentation guide.

## Understand the results

Anim keeps different questions separate: uncertainty within a model fit,
differences between sampling chains or random seeds, changes associated with sampling
or analysis choices, participant influence, and comparisons with generated data
that have no underlying disease-order signal. A check can only be made when the
model supplies the results it needs.

| Result label | How to read it |
| --- | --- |
| `SUCCESS` | The stated operation succeeded. Read the report's separate scientific checks before interpreting its results. |
| `UNSUPPORTED_CAPABILITY` | The model connection cannot provide a requested operation or output. |
| `UNAVAILABLE` | Information needed for this result is missing. |
| `NOT_APPLICABLE` | This result does not apply to the model's declared outputs or to this analysis. |
| `NOT_ASSESSABLE` | Anim cannot assess the stated question with the available results. |
| `PARTIAL` / `INCOMPLETE` | Some work or some required scientific checks are incomplete. Read the reasons in the report. |

Warnings and failed analyses remain visible. Missing results do not count as
agreement, zero uncertainty, or a passed check. The
[report guide](https://github.com/timigod/anim/blob/main/docs/report-comparison.md) explains these distinctions and where
to find the detailed status fields.

## Research use and privacy

Anim runs locally and offline. Reports use local files, without remote scripts,
telemetry, or LLM-generated interpretations. Install the model and its dependencies
before opening participant data. Keep research data, private paths, identifiers,
and individual results out of this repository, issue reports, and shared notes.
See [privacy requirements](https://github.com/timigod/anim/blob/main/PRIVACY.md) and the [security policy](https://github.com/timigod/anim/blob/main/SECURITY.md).

The software has been tested for researchers to connect a model and run audits.
A stable estimated order does not, by itself, show that the order is biologically
correct or that the data contain a disease-progression signal. Anim does not
provide diagnosis, prognosis, treatment advice, causal conclusions, or permission
to use participant data. Your model and study still need their own scientific
and institutional review.

See the [changelog](https://github.com/timigod/anim/blob/main/CHANGELOG.md) for the release history. Published release files,
including the earlier 0.1.1 files, are retained unchanged. Anim is licensed under
[Apache-2.0](https://github.com/timigod/anim/blob/main/LICENSE).
