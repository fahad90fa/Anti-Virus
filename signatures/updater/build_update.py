#!/usr/bin/env python3
"""Build a signed, incremental Sentinel AV signature update package.

Packages the changed signature files (rules, hash sets, driver blocklist) into a
versioned directory with a manifest of per-file SHA-256 digests, a canonical
manifest digest, and (optionally) a detached signature produced with openssl
against a provided private key. The client verifies the result against a pinned
public key before applying it (see verify_update.py).

This tool handles NO secrets itself: pass --sign-key pointing at a key held in
the signing infrastructure. Nothing secret is written into the repo.
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys

# Which files under the signatures tree are shippable as signatures.
INCLUDE_SUBDIRS = ("rules", "hashes", "driverblock")
INCLUDE_EXTS = (".yar", ".rules", ".txt")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_files(signatures_dir):
    out = {}
    for sub in INCLUDE_SUBDIRS:
        base = os.path.join(signatures_dir, sub)
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for name in files:
                if not name.endswith(INCLUDE_EXTS):
                    continue
                full = os.path.join(root, name)
                rel = os.path.relpath(full, signatures_dir).replace(os.sep, "/")
                out[rel] = sha256_file(full)
    return out


def load_prev_manifest(signatures_dir, prev_version):
    """Return {path: sha256} from a previously built package, if available."""
    if not prev_version:
        return {}
    candidate = os.path.join(signatures_dir, "updater", "dist",
                             "update-" + prev_version, "manifest.json")
    if not os.path.isfile(candidate):
        return {}
    with open(candidate, "r", encoding="utf-8") as f:
        m = json.load(f)
    return {e["path"]: e["sha256"] for e in m.get("files", []) if e.get("op") != "delete"}


def canonical_digest(file_entries):
    """SHA-256 over a deterministic serialization of the file list."""
    h = hashlib.sha256()
    for e in sorted(file_entries, key=lambda x: x["path"]):
        h.update((e["path"] + "\x00" + e["sha256"] + "\x00" + e["op"] + "\n").encode("utf-8"))
    return h.hexdigest()


def sign_manifest(manifest_path, sig_path, key_path):
    """Detached signature via openssl. Works for Ed25519 and RSA keys."""
    try:
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", key_path,
             "-rawin", "-in", manifest_path, "-out", sig_path],
            check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fall back to dgst-based signing (RSA/ECDSA) if pkeyutl -rawin fails.
        try:
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", key_path,
                 "-out", sig_path, manifest_path],
                check=True, capture_output=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print("WARNING: signing failed: %s" % exc, file=sys.stderr)
            return False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", required=True)
    ap.add_argument("--prev", default=None, help="previous version for an incremental delta")
    ap.add_argument("--signatures", default="..", help="path to the signatures/ tree")
    ap.add_argument("--out", default="./dist")
    ap.add_argument("--sign-key", default=None, help="private key for the detached signature")
    ap.add_argument("--full", action="store_true", help="ship all files, not just the delta")
    args = ap.parse_args()

    signatures_dir = os.path.abspath(args.signatures)
    current = collect_files(signatures_dir)
    prev = {} if args.full else load_prev_manifest(signatures_dir, args.prev)

    entries = []
    for path, digest in sorted(current.items()):
        if prev.get(path) == digest:
            continue  # unchanged — not in the delta
        entries.append({"path": path, "sha256": digest, "op": "upsert"})
    for path in sorted(prev):
        if path not in current:
            entries.append({"path": path, "sha256": prev[path], "op": "delete"})

    pkg_dir = os.path.join(args.out, "update-" + args.version)
    files_dir = os.path.join(pkg_dir, "files")
    if os.path.exists(pkg_dir):
        shutil.rmtree(pkg_dir)
    os.makedirs(files_dir, exist_ok=True)

    for e in entries:
        if e["op"] != "upsert":
            continue
        src = os.path.join(signatures_dir, e["path"])
        dst = os.path.join(files_dir, e["path"])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)

    manifest = {
        "format": 1,
        "version": args.version,
        "prev_version": args.prev,
        "created_utc": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "incremental": not args.full,
        "files": entries,
        "digest": canonical_digest(entries),
    }
    manifest_path = os.path.join(pkg_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    signed = False
    if args.sign_key:
        signed = sign_manifest(manifest_path, os.path.join(pkg_dir, "manifest.sig"),
                               args.sign_key)

    print("Built %s" % pkg_dir)
    print("  files in delta: %d" % len(entries))
    print("  digest:         %s" % manifest["digest"])
    print("  signed:         %s" % ("yes" if signed else "no (integrity-only)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
