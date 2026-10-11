#!/usr/bin/env python3
"""Verify a Sentinel AV signature update package before applying it.

This is the client-side gate. It is fail-closed:
  1. Re-hash every file in the package and check it against the manifest.
  2. Recompute the canonical manifest digest and compare.
  3. If a pinned public key is provided, verify the detached signature over the
     manifest. A missing/invalid signature with a pinned key present => REJECT.
If any check fails, the whole update is rejected (exit code 2). Nothing is
applied by this tool; it only validates.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_digest(file_entries):
    h = hashlib.sha256()
    for e in sorted(file_entries, key=lambda x: x["path"]):
        h.update((e["path"] + "\x00" + e["sha256"] + "\x00" + e["op"] + "\n").encode("utf-8"))
    return h.hexdigest()


def verify_signature(manifest_path, sig_path, pinned_key):
    if not os.path.isfile(sig_path):
        return False, "signature file missing"
    for args in (
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pinned_key,
         "-rawin", "-in", manifest_path, "-sigfile", sig_path],
        ["openssl", "dgst", "-sha256", "-verify", pinned_key,
         "-signature", sig_path, manifest_path],
    ):
        try:
            r = subprocess.run(args, capture_output=True)
            if r.returncode == 0:
                return True, "ok"
        except FileNotFoundError:
            return False, "openssl not available"
    return False, "signature verification failed"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package", required=True, help="path to update-<version>/ dir")
    ap.add_argument("--pinned-key", default=None, help="pinned public key PEM")
    args = ap.parse_args()

    pkg = os.path.abspath(args.package)
    manifest_path = os.path.join(pkg, "manifest.json")
    if not os.path.isfile(manifest_path):
        print("REJECT: manifest.json not found", file=sys.stderr)
        return 2

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    problems = []

    # 1. Per-file integrity.
    for e in manifest.get("files", []):
        if e.get("op") == "delete":
            continue
        fp = os.path.join(pkg, "files", e["path"])
        if not os.path.isfile(fp):
            problems.append("missing file: %s" % e["path"])
            continue
        actual = sha256_file(fp)
        if actual != e["sha256"]:
            problems.append("hash mismatch: %s" % e["path"])

    # 2. Manifest digest.
    recomputed = canonical_digest(manifest.get("files", []))
    if recomputed != manifest.get("digest"):
        problems.append("manifest digest mismatch")

    # 3. Signature (fail-closed when a key is pinned).
    sig_status = "not checked (no pinned key — UNTRUSTED)"
    if args.pinned_key:
        ok, msg = verify_signature(manifest_path,
                                   os.path.join(pkg, "manifest.sig"),
                                   args.pinned_key)
        sig_status = msg
        if not ok:
            problems.append("signature: %s" % msg)

    print("Package:   %s" % manifest.get("version"))
    print("Prev:      %s" % manifest.get("prev_version"))
    print("Files:     %d" % len(manifest.get("files", [])))
    print("Digest:    %s" % ("ok" if recomputed == manifest.get("digest") else "MISMATCH"))
    print("Signature: %s" % sig_status)

    if problems:
        print("\nREJECT:", file=sys.stderr)
        for p in problems:
            print("  - %s" % p, file=sys.stderr)
        return 2

    if not args.pinned_key:
        # Integrity passed but trust was not established.
        print("\nACCEPT (integrity only). Production REQUIRES a pinned key.")
        return 1

    print("\nACCEPT: integrity and signature verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
