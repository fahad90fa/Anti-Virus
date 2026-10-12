# PPL, ELAM & signing — code-complete vs. paperwork-gated

This separates what is **code-side** (done or doable in the repo) from what is
**organizationally gated** and cannot be satisfied by code alone.

## What the code does (code-complete)

- **ELAM driver** (`drivers/elam`): registers the boot-driver callback and
  classifies boot drivers good/bad/unknown, consulting the constant-time BYOVD
  blocklist. It carries an `ELAMCERTIFICATEINFO` resource slot for the malware-
  signature measurements.
- **Service self-protection** (`drivers/procmon/selfprotect.c`): object callbacks
  strip terminate/inject rights to the Sentinel service + driver, the code-side
  half of running as a protected process.
- **ETW-TI consumer** (`engine/service/etw_ti.cpp`): subscribes to the
  Microsoft-Windows-Threat-Intelligence provider. The provider only delivers to a
  process running at the anti-malware PPL level, so this is exercised once the
  service is PPL (below).
- **Update pipeline** (`signatures/updater`): signed, pinned-key, fail-closed —
  no org gate; works today with your signing key.

## What is gated on Microsoft paperwork (NOT code)

| Capability | Requirement | Who/How |
| --- | --- | --- |
| Load any kernel driver on a non-test PC | **EV code-signing certificate** + **Microsoft attestation signing** (submit to the Hardware Dev Center) | Established business identity; per-driver submission |
| Broad distribution / hardware labs | **WHQL** via the Windows Hardware Lab Kit | HLK test pass + submission |
| **ELAM** load as a real anti-malware driver | Membership in the **Microsoft Virus Initiative (MVI)** + an ELAM certificate | MVI application: established company, third-party lab certification (e.g. AV-TEST/AV-Comparatives/SKD Labs), ongoing testing commitments |
| **PPL** anti-malware protection level | Granted via MVI (the ELAM cert pins the service's PPL signer) | Same MVI membership |
| Security Center registration | MVI | Same |

These are the single biggest barrier between this project and a "real" shippable
AV, and they are **not** something code can unblock. Plan for them early.

## Development path (no paperwork, test VM only)

1. `bcdedit /set testsigning on` (reboot) — loads test-signed drivers in the VM.
2. `build/signing/new-dev-cert.ps1` → a self-signed dev cert (VM cert store only).
3. `build/signing/test-sign.ps1` → sign the built `.sys` for VM testing.
4. For PPL/ETW-TI testing without MVI: use a kernel-debugger-attached VM where
   the PPL requirement can be relaxed for development, or validate the ETW-TI
   wiring against the provider with the debugger attached. The production PPL
   level still requires the MVI-issued ELAM cert.

## Exact steps to pursue the MVI (summary)

1. Establish the business identity and obtain an **EV code-signing certificate**.
2. Enroll in the **Microsoft Hardware Dev Center**; set up **attestation signing**
   and, for distribution, **WHQL/HLK**.
3. Get third-party lab certification of the detection engine.
4. Apply to the **Microsoft Virus Initiative**; on acceptance you receive the
   ELAM certificate and the PPL anti-malware signer, which unlock ELAM load, PPL,
   and Security Center registration on production machines.
