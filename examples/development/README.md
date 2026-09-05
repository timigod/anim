# Public synthetic data for development checks

Use `mina-shaped-pure-no-signal-authority.json` as a public specification for
generating development data with and without a known signal. It defines
57 generated participants, nine generic events with both higher and lower
abnormal directions, and 59 pure-no-signal replicates (separately generated
datasets). It contains no participant data, held-out material (data reserved for
independent evaluation) or evidence that a benchmark has passed.

The file defines one `moderate_mina_shape` replicate with signal and 59
`pure_no_signal` replicates for comparison. The latter contain no recoverable
order or stage signal. Their participant and event dimensions, event identities
and directions, baselines, event centers, transition widths, noise distribution,
missingness and outlier settings match the signal case. The no-signal variant
sets amplitudes and participant-effect loadings (the strength of shared
participant effects on each event) to zero. It draws latent progression values,
the simulated underlying progression, from one range spanning the source,
independent of group.

These dimensions support development checks that run planned analyses through
the worker and assess their results. The scientific state remains `UNVERIFIED`
until actual worker execution and every required development evidence check
pass. The separate 2-by-2 helper only tests software contracts; passing it does
not verify scientific behavior.

## Reference: fixed development seeds

The 59 root seeds, from which generation seeds are derived, were fixed before
any generated result was examined. For index `r` in `0..58`, the root is the
first eight bytes of SHA-256 over:

```text
UTF8("ebm-audit-public-development-root/v1") || 0x00 || ASCII_DECIMAL(r)
```

Here `||` concatenates the byte sequences, and `0x00` separates the fixed label
from the decimal index. This deterministic public derivation is only for
development. It must never generate held-out roots, which follow a separate
procedure committed in advance and use a cryptographically secure pseudorandom
number generator (CSPRNG).
