#!/usr/bin/env python3
"""Generate the canonical EICAR antivirus test file.

The EICAR string is a harmless, industry-standard test file that every antivirus
is expected to detect. It contains no malicious code and does nothing when run;
it exists only to verify that detection works. We build it at runtime (rather
than committing it) so this repository does not carry a file that external AV
products would flag.

Usage:  python3 make_eicar.py [output-path]   (default: ./eicar.com)
"""
import sys


def eicar_bytes() -> bytes:
    # Assembled from pieces so the literal is not stored verbatim in source.
    parts = [
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}",
        r"$EICAR-STANDARD-ANTIVIRUS-",
        r"TEST-FILE!$H+H*",
    ]
    return ("".join(parts)).encode("ascii")


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "eicar.com"
    with open(out, "wb") as f:
        f.write(eicar_bytes())
    print("Wrote %d-byte EICAR test file to %s" % (len(eicar_bytes()), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
