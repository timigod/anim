# What changed in Anim 0.2.0

Version 0.2.0 makes Anim easier to connect to a model, run, repeat, and interpret.
The underlying purpose is the same: check how an existing event-based model's
results respond to analysis choices specified in advance.

## An easier way to connect a model

The worker starter now comes with tests you can run. A worker is the small
program that passes data and settings to your model and returns its results
to Anim.

`adapter pin` records the exact software files and versions you intend to use.
This helps catch an accidental change to the model or its environment.
`adapter check` tests the connection and checks whether it can supply the
outputs you request. It gives a status and guidance when something needs fixing.
Neither command decides whether the model is suitable for your study.

## An example using an existing EBM

The optional pysaebm example runs actual open-source model code on generated
synthetic data. Previously, the supplied starter mainly demonstrated how to
exchange requests and results.

The new example returns one estimated event order per fit. It does not yet
provide the samples and staging results needed for Anim's corresponding
uncertainty checks. Those results stay unavailable; Anim does not fill them
with zeros or call them certain. The example's software tests are separate from
validation of a model for research or clinical use.

## Repeat an audit without overwriting it

An ordinary audit now saves a record of the input, settings, random seeds,
model software, and environment used. It records checksums, not copies of the
participant data.

`rerun` checks those details against the original files, then performs the whole
analysis plan again in a new directory. It refuses an exact repeat if the inputs
or software have changed. The earlier run stays intact. Recovery after an
interruption also repeats the full plan; it does not pick up halfway through
an old model fit.

## Summarise and compare saved audits

`summary` gives an overview of one saved audit. `diff` compares two audits,
including results, which analyses were attempted, missing outputs, failures,
and changes to the recorded inputs or software.

If two runs cannot be compared fairly—for example, they use different event
definitions—Anim says so. Two missing measurements never count as two agreeing
measurements. Reading saved results does not fit the model again or create a
new scientific report.

## A more useful opening report

The HTML report brings the main comparisons forward. It shows which comparisons
had no difference, which differed, how large the differences were, and which
analysis choices were associated with them. Detailed results remain available
in HTML, JSON, and CSV.

For models that return only one event order per fit, a separate section compares
those orders. A difference between two selected orders is not an estimate of
uncertainty within either fit. The report keeps these meanings separate and
does not claim that an analysis choice caused a biological change.

## More control over long runs

Progress messages show how many planned analyses have started and how many
results have been saved. They do not estimate a finishing time.

Ctrl-C requests a stop, prevents more analyses from starting, and asks Anim to
clean up the model processes it launched. Results already saved stay on disk.
Work that did not finish remains incomplete rather than being given an invented
result.

A declared memory allowance can reduce how many model processes run at once.
It does not remove analyses from the plan. The allowance is an estimate used for
scheduling; it does not measure or enforce a hard limit on memory consumption.

## Fixes, installation checks, and publishing

A model that returned an event order without retained sampling results could
previously trigger a crash when Anim assembled its report. That case now produces
a report with the affected checks marked as not assessable.

We also fixed Linux-specific problems in worker cancellation tests and in the
launching of Anim's own test workers. Optional numerical-library tests now run
in separate processes so they do not change the environment of unrelated tests.

Automated checks install and exercise the actual package on macOS and Linux with
CPython 3.12. They cover model execution, summaries and comparisons, and the
expected refusal to run a model when Linux's required sandbox is unavailable.
Version checks ensure that the package, documentation, dependency list, and
release tag agree. Publication uses those validated files for both PyPI and
GitHub, while keeping older release files unchanged.

## What the release does not establish

The new commands make software operation and missing results easier to inspect.
They do not add a new disease model, validate a participant dataset, or turn a
repeatable event order into a scientifically established disease sequence.
Uncertainty, failed checks, and missing results remain visible throughout.

For commands and definitions, start with the [documentation guide](start-here.md).
