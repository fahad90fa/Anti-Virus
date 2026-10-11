# Signature update pipeline

Signatures and rules live in a compact local database the engine memory-maps for
speed. Updates ship as **signed, incremental packages**: the client downloads a
delta, verifies the signature against a **pinned public key** (so a hijacked
update server cannot push malicious rules), and swaps it in without a restart.
Daily or faster updates keep known-threat coverage current between engine
releases.

## Package format

An update package is a directory (or tarball) containing:

```
update-<version>/
  manifest.json      # version, timestamp, per-file SHA-256, prev-version link
  manifest.sig       # detached signature of manifest.json (pinned-key verified)
  files/             # the changed signature files (rules, hash sets, driverblock)
```

`manifest.json` (see `manifest.schema.json`):

```json
{
  "format": 1,
  "version": "2026.10.11-001",
  "prev_version": "2026.10.10-003",
  "created_utc": "2026-10-11T00:00:00Z",
  "incremental": true,
  "files": [
    { "path": "rules/eicar.yar", "sha256": "…", "op": "upsert" },
    { "path": "hashes/blocklist.txt", "sha256": "…", "op": "upsert" }
  ],
  "digest": "…"        // SHA-256 over the canonical file list
}
```

## Trust model

- The engine pins **one public key** at build/install time (`pinned_pubkey.pem`,
  provisioned by the trustlet in production). Every manifest is verified against
  it before any file is applied.
- Signing is done offline with the matching private key (held in the signing
  infrastructure, never in this repo — see `build/signing/`).
- Verification is **fail-closed**: a missing, malformed, or mismatched signature
  rejects the entire update. A single changed byte in any listed file breaks the
  manifest digest and is rejected.
- Updates are **incremental**: only changed files travel, keyed by `prev_version`
  so the client applies them in order and can detect a skipped delta.

## Building and verifying

```sh
# Build an incremental package from the current signatures tree:
python3 build_update.py --version 2026.10.11-001 \
    --prev 2026.10.10-003 --signatures .. --out ./dist \
    [--sign-key ../../build/signing/update_sign_key.pem]

# Verify a package before applying (what the client does):
python3 verify_update.py --package ./dist/update-2026.10.11-001 \
    --pinned-key ./pinned_pubkey.pem
```

Signing/verification use `openssl` (Ed25519 or RSA-PSS) when a key is supplied.
With no key, the tools still enforce the manifest **digest** (integrity), and
`verify_update.py` reports that the signature was not checked — a state the
engine treats as untrusted and refuses to apply in production.
