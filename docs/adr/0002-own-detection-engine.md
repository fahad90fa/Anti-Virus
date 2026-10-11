# ADR 0002 — Build the detection engine from scratch (no third-party AV SDK)

**Status:** Accepted

## Context

We could license a third-party AV SDK or embed an existing scanning library.

## Decision

Build the detection logic, drivers, and engine as our own code. We still build
*on* the official Windows kernel frameworks (Filter Manager, WFP, ELAM) because
those are the supported, documented, signable ways to run in the kernel.

We ship our own:
- static scanner (hash sets, YARA-style rule engine + rule format, PE heuristics,
  verdict cache);
- behavioral engine (action graph, heuristics, corroborating model, fusion);
- script deobfuscation + intent classifier;
- rollback gate, quarantine vault, EDR timeline, sandbox emulator.

## Rationale

- Refusing the kernel frameworks would mean an unsupported, unstable, unsignable
  driver — the opposite of safe.
- Owning the detection logic lets us implement the rollback gate and the
  side-effect boundary, which no mainstream consumer AV ships as true real-time
  prevention, and keeps us free of third-party licensing and telemetry.
- The model is a *corroborating* signal inside verdict fusion, never a sole
  judge, and is paired with deterministic layers — a design choice that is only
  possible when we own the fusion stage.

## Consequences

- More engineering up front (we write the rule engine, the PE parser, the
  emulator). Mitigated by keeping each layer small, independent, and tested.
- Full control over the latency budget, false-positive strategy (allowlist +
  fusion + reversible responses), and the update pipeline (signed, pinned-key).
