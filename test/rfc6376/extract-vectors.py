#!/usr/bin/env python3
"""Regenerate the RFC 8463 Appendix A message vectors from the RFC text itself.

The `.eml` files under `messages/` are committed, because they are the test
vectors. This script exists so their provenance is checkable rather than
asserted: it fetches RFC 8463, locates Appendix A.3, removes the three-space
indent the RFC renders with, and writes the message out with CRLF line endings.

Run it to verify the committed files still match the published RFC:

    python3 extract-vectors.py --check

Transcribing a DKIM vector by hand is a bad idea. A single wrong byte anywhere
in the signed material changes the body hash or the signing input, the signature
fails, and the failure looks exactly like an implementation defect -- which is
the most expensive kind of harness bug to diagnose, because it points at
production code that is fine.
"""

import argparse
import os
import sys
import urllib.request

RFC_URL = "https://www.rfc-editor.org/rfc/rfc8463.txt"
HERE = os.path.dirname(os.path.abspath(__file__))
MESSAGES = os.path.join(HERE, "messages")

# A.3 renders the message indented by three spaces, with the DKIM-Signature
# continuation lines carrying one further space of their own -- which is part of
# the signed material, not presentation, so only the shared indent comes off.
INDENT = "   "
FIRST_LINE = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;"
LAST_LINE = "Joe."


def fetch_rfc():
    with urllib.request.urlopen(RFC_URL, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def extract(text):
    """Return the A.3 message as a list of lines, dedented."""
    lines = text.split("\n")
    start = None
    for i, ln in enumerate(lines):
        if ln == INDENT + FIRST_LINE:
            start = i
            break
    if start is None:
        raise SystemExit("could not find the start of RFC 8463 A.3 in the RFC text")

    end = None
    for i in range(start, len(lines)):
        if lines[i] == INDENT + LAST_LINE:
            end = i
            break
    if end is None:
        raise SystemExit("could not find the end of RFC 8463 A.3 in the RFC text")

    out = []
    for ln in lines[start:end + 1]:
        if ln == "":
            out.append("")
        elif ln.startswith(INDENT):
            out.append(ln[len(INDENT):])
        else:
            raise SystemExit(f"unexpected indent in A.3: {ln!r}")
    return out


def split_fields(lines):
    """Group header lines into fields, then return (fields, body_lines).

    A field starts on a line that does not begin with whitespace; continuation
    lines belong to the field above.
    """
    blank = lines.index("")
    header_lines, body_lines = lines[:blank], lines[blank + 1:]

    fields = []
    for ln in header_lines:
        if ln[:1] in (" ", "\t") and fields:
            fields[-1].append(ln)
        else:
            fields.append([ln])
    return fields, body_lines


def render(fields, body_lines):
    return "\r\n".join(
        [ln for f in fields for ln in f] + [""] + body_lines
    ) + "\r\n"


def build(lines):
    """The three vectors: both signatures, Ed25519 alone, RSA alone.

    RFC 8463 Appendix A states the signatures "are independent of each other, so
    either signature would be valid if the other were not present". The single
    signature files exist to test exactly that claim -- and to stop one good
    signature masking the other's failure, which is how the Ed25519 defect could
    have gone unnoticed behind a passing RSA signature.
    """
    fields, body = split_fields(lines)

    def is_alg(field, alg):
        return field[0].startswith("DKIM-Signature:") and alg in field[0]

    return {
        "rfc8463-both.eml": render(fields, body),
        "rfc8463-ed25519.eml": render(
            [f for f in fields if not is_alg(f, "a=rsa-sha256")], body),
        "rfc8463-rsa.eml": render(
            [f for f in fields if not is_alg(f, "a=ed25519-sha256")], body),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="compare against the committed files instead of writing")
    ap.add_argument("--rfc", help="read the RFC from this file instead of fetching")
    args = ap.parse_args()

    text = open(args.rfc, encoding="utf-8").read() if args.rfc else fetch_rfc()
    wanted = build(extract(text))

    os.makedirs(MESSAGES, exist_ok=True)
    bad = 0
    for name, content in wanted.items():
        path = os.path.join(MESSAGES, name)
        data = content.encode()
        if args.check:
            have = open(path, "rb").read() if os.path.exists(path) else b""
            if have == data:
                print(f"  ok       {name} ({len(data)} bytes)")
            else:
                print(f"  MISMATCH {name}")
                bad += 1
        else:
            open(path, "wb").write(data)
            print(f"  wrote    {name} ({len(data)} bytes)")

    if args.check and bad:
        print(f"\n{bad} file(s) differ from RFC 8463 as published", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
