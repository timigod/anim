# Custom worker protocol example

Use this example to see how a separate local process exchanges requests and
results with Anim through the worker software development kit (SDK). For setup
and commands, follow the [adapter runbook](../../docs/handoff/adapter-runbook.md).
The example is synthetic. It is not an event-based model (EBM), and passing its
checks does not establish that a research model is scientifically suitable.

The example declares and returns a deterministic 500-state chain: a fixed
sequence of synthetic states. This lets an installed auditor exercise the complete
planning, validation, fitting, and report path. It tests data exchange only. It does not sample from a model or
provide scientific validation.

## Reference: what a real worker must replace

Do not subclass it and replace only `validate`, `fit`, and `self_test`. A real
worker must supply and review its complete declaration:

- exact adapter, backend, source, executable, code, and environment identity;
- algorithm ID and supported commands;
- truthful capabilities and limits;
- a settings schema that rejects unknown fields, and its digest (content hash);
- a definition of stage meanings, or an explicit unavailable declaration, and
  its digest;
- limitations and safe diagnostic codes; and
- validation, fitting, and backend-owned synthetic self-test behavior.

Reuse `WorkerApplication` and the protocol's strict request and response
formats. Replace the example's model metadata and calculations in full.
