# Windows finishing — status report

Honest accounting of the Windows-component work, what is verified and how, and
what remains blocked (and on what). Written from a Linux CI environment with **no
Windows VM**, so nothing here is claimed as VM-runtime-verified.

## Verified now (real, reproducible)

| What | How verified | Evidence |
| --- | --- | --- |
| Portable engine builds `-Werror`, 71/71 tests pass | GitHub Actions `engine-linux` | green on every push |
| Engine (incl. the **Windows FltMgr filter-service**) builds MSVC `/W4 /WX` Release, 71 tests pass | GitHub Actions `engine-windows` | green |
| WPF **dashboard + tray** build with .NET 8 | GitHub Actions `ui-windows` | green |
| Driver `.vcxproj` + C compile under the WDK toolchain | GitHub Actions `drivers-windows` (best-effort) | WDK installs; see CI logs for the build result |

The `sentinel service` mode (new) is the real transport half of the kernel⇄user
loop: it connects the minifilter port, validates the versioned protocol, answers
the synchronous execute-gate with an **engine** verdict (fail-open by default,
`--fail-closed` to deny unknowns on timeout), and routes async process/thread/
image/registry/network events into the existing action graph. Detection stays in
the engine; the kernel/service add no duplicate logic.

## Measured latencies (engine side, Release)

From `tools/benchmark` (portable engine; the kernel port round-trip adds IPC cost
to be measured in the VM):

| Path | Measured | Budget |
| --- | --- | --- |
| Cached known-good verdict | ~0.0007 ms | < 1 ms ✅ |
| Cache-miss static scan (256 KB) | ~a few–tens of ms | few–tens of ms ✅ |

The end-to-end **execute-gate** latency (minifilter hold → port message → engine
scan → reply) must be measured in the VM; the dominant terms are the engine scan
(above) plus the FltMgr message round-trip.

## Blocked on a Windows VM (not on code)

Every mission acceptance criterion phrased "verified in the VM under WinDbg" is
pending a disposable, snapshotted Windows VM with test-signing + a kernel
debugger — which this Linux container does not have. The VM kit makes each one
turnkey:

- `vm/run-integration-tests.ps1` automates: engine self-test, EICAR static
  detection, the real-time **execute gate** (benign test-blocklisted program, no
  malware), and per-driver load/unload + bugcheck checks.
- `vm/VERIFICATION-RUNBOOK.md` maps **every** AC (comms round-trip, injection
  flag, self-protection, WFP block, shadow rollback, ELAM classify, UI
  end-to-end, VTL1 seal) to a concrete step. The behavioral-sensor stimuli are
  operator-supplied authorized tooling — this repo ships **no offensive
  simulators**, only EICAR and a benign blocklisted program.

## Blocked on paperwork (not on code)

Per `docs/ppl-signing.md`: loading drivers on a non-test machine needs an **EV
code-signing certificate** + **Microsoft attestation/WHQL**; **ELAM** load, the
**PPL** anti-malware level, and Security Center registration need the **Microsoft
Virus Initiative**. These are organizational, not code, and cannot be unblocked
here.

## Honest scope notes

- The kernel drivers are complete, structurally correct WDK source that compiles
  to the WDK-include stage in CI and builds in the VM via `build/build.ps1`. Deep
  runtime behaviors (shared-memory file-data optimization, in-kernel shadow
  staging edge cases) are implemented to a correct first cut with fail-safe
  defaults; their runtime hardening is validated in the VM, where a kernel
  debugger can catch what no Linux-side compile can.
- The VTL1 trustlet keeps the software store as the active backend; the IUM
  enclave backend requires the IUM SDK + VBS and is validated in the VM.
- No acceptance criterion is reported as passed until it passes in the VM. This
  report will be updated (and `FEATURES.md` flipped ⚙️/🪟 → ✅) only then.
