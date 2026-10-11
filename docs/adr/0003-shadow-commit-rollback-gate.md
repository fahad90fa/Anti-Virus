# ADR 0003 — Shadow-commit rollback gate

**Status:** Accepted

## Context

Ordinary antivirus is *detect then block*, and the gap between a threat running
and being detected is where damage happens. We want damage to be reversible by
construction.

## Decision

Route only **unknown/suspicious** processes through a copy-on-write shadow layer;
**trusted** processes write straight to disk at zero overhead. A gated process's
file writes are redirected into a per-process shadow staging area it cannot
distinguish from the real disk. The behavioral engine scores the process as it
runs:

- verdict stays clean past a threshold → **commit** the shadow writes to the real
  disk atomically;
- verdict turns malicious → **discard** the entire shadow layer: perfect
  rollback, no data loss, even for a zero-day.

The kernel half (`drivers/shadowfs`) is a thin, fast redirection enforcement
point; the authoritative staging store and the commit/discard decision live in
user mode (`engine/rollback/shadow_gate`).

## The hard part: the side-effect boundary

Not everything can be staged. A process can send a network packet, print, show
UI, or talk to an already-committed process, and you cannot un-send a packet.
While a process is gated, its irreversible actions are themselves gated:

- **Network:** outbound data is buffered or blocked until commit; dropped on
  discard.
- **Inter-process:** a gated process is prevented from injecting into or driving
  a non-gated process, so it cannot "launder" its effects through a trusted one.
- **Hardware/UI:** rare and low-risk; logged, and denied when paired with other
  suspicion.

## Consequences

- The shadow layer is the easy half; a correct, low-overhead side-effect boundary
  is the half that takes real work, and the honest limit is that effects which
  must be allowed in real time (an already-trusted network path) remain the one
  place a fast attacker could still act before the verdict lands — which is
  exactly why the gate sits *behind* the detection layers, not instead of them.
- Trusted-process fast path keeps the common case at zero overhead.
- Pairs directly with sandbox detonation: detonate, judge, then allow real writes.
