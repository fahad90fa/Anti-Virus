# Test samples — SAFE material only

This directory holds **safe test material only** — the standard EICAR test
string and synthetic behavior simulators. **Live malware is never committed
here**, and `.gitignore` additionally excludes `tests/samples/live/` and any
`*.malware` file.

## What's here

| Path | What it is | Why it's safe |
| --- | --- | --- |
| `make_eicar.py` | Generates the canonical EICAR test file | EICAR is a harmless, non-executable-payload string every AV is *expected* to detect; it does nothing |
| `scripts/obfuscated_powershell.txt` | A synthetic obfuscated script-cradle, as **text** | Never executed; fed to the script-intent analyzer as a string to prove deobfuscation + classification |
| `scripts/benign.txt` | A plainly benign script | Control case: must NOT be flagged |
| `sentvm/*.sasm` | Synthetic SENTVM programs (injector, packer, ransom-sim, benign) | Run only in the memory-safe synthetic emulator (`docs/sandbox-vm.md`); they touch no real resources |

## Generating the EICAR file

The EICAR file is generated at test time rather than committed, so the repo
itself does not carry a file that external AV products flag:

```sh
python3 tests/samples/make_eicar.py tests/samples/eicar.com
```

The engine's own self-test (`sentinel-cli selftest`) builds the EICAR string at
runtime, scans it (expecting a Malicious verdict), and cleans up — no file is
left behind.

## Rules

1. Never commit live malware, packed real payloads, or anything whose only
   purpose is to cause harm.
2. Synthetic simulators model *behavior* (mass file writes, an injection chain)
   in a controlled way; they are not real malware.
3. All destructive-looking behavior runs against staging/temp dirs or the
   synthetic emulator, never real user data.
