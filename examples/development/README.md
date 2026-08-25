# Public development pure-no-signal authority

`mina-shaped-pure-no-signal-authority.json` is public, synthetic-only
development input. It declares 57 generated participants, nine generic
mixed-direction events, and 59 pure-no-signal replicates. It does not contain
participant data, held-out material, or benchmark acceptance evidence.

This authority contains both the one-replicate `moderate_mina_shape` public
source and its 59-replicate `pure_no_signal` counterpart. Their participant and
event dimensions, event identities and directions, baselines, centers, widths,
noise law, missingness, and outlier settings match. The no-signal variant zeros
the amplitudes and participant-effect loadings and uses one group-independent
source-span latent window.

It is sized for the substantive candidate-source vertical, but its scientific
state remains `UNVERIFIED` until genuine worker execution and the full typed
development evidence graph pass. The separately retained 2-by-2 test helper
remains contract-fixture evidence only.

The 59 literal root seeds were fixed before examining any generated result.
For index `r` in `0..58`, the root is the first eight bytes of SHA-256 over:

```text
UTF8("ebm-audit-public-development-root/v1") || 0x00 || ASCII_DECIMAL(r)
```

This deterministic public derivation is only for development. It must never be
used to create held-out roots, which have a separate precommitted CSPRNG
procedure.
