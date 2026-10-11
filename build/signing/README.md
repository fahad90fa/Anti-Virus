# Driver signing

Windows will not load an unsigned kernel driver on a normal machine. Signing is
the single biggest barrier between a hobby project and a shippable AV.

## What you need to SHIP (real users)

1. **EV (Extended Validation) code-signing certificate** tied to a verified
   business identity, from a trusted CA.
2. **Microsoft attestation signing** — submit the driver to the Microsoft
   Hardware Dev Center so it is accepted on current Windows.
3. **WHQL via the Windows Hardware Lab Kit (HLK)** for broad distribution and the
   hardware labs.
4. For the **ELAM, PPL, and Security Center** privileges: **Microsoft Virus
   Initiative (MVI)** membership, which has real requirements (established
   company, third-party lab certification, ongoing testing commitments).

None of these secrets live in this repository. `build/signing/` holds only
**configuration and scripts**; `.gitignore` excludes every key/certificate
format. Provision the EV key in your signing infrastructure (ideally an HSM) and
point the scripts at it via environment variables.

## DEVELOPMENT ONLY — test signing

For development you can enable **test-signing** on a disposable VM and sign with a
self-issued certificate. This is for your test machine only, **never for real
users**, and the VM shows a "Test Mode" watermark.

```powershell
# On the test VM, once:
bcdedit /set testsigning on   # reboot required

# Create a one-time dev cert (stored in the VM's cert store, not the repo):
pwsh build/signing/new-dev-cert.ps1

# Sign built drivers for VM testing:
pwsh build/signing/test-sign.ps1 -Configuration Debug
```

## Update-package signing

The signature **update pipeline** (`signatures/updater`) uses a separate signing
key and a pinned public key the client verifies against. See
`signatures/updater/README.md`. That key, too, lives only in the signing
infrastructure.
