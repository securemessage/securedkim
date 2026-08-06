#!/usr/bin/env python3
"""Drive the RFC 8463 Appendix A vectors and derived cases against `securedkim-check`.

Each case brings its own DNS zone, served on a loopback port by the shared DNS
fake, so the daemon's own resolver does the lookups. Nothing inside
`securedkim` is stubbed: the checker calls the same `verify.verifySignature` the
milter's `onEom` calls, with the same header list shape.

Exit status is non-zero if any case fails, so this can gate a build.

    python3 runsuite.py                 # run everything
    python3 runsuite.py -v              # list every case, log DNS queries
    python3 runsuite.py --test NAME     # one case
    python3 runsuite.py --section 8463  # cases whose section contains this
    SECUREDKIM_CHECK=/path/to/binary python3 runsuite.py

No dependencies beyond the Python standard library.
"""

import argparse
import os
import subprocess
import sys
import tempfile

# One DNS fake serves every conformance suite in the tree; securemilter-lib's
# test/dnsfake.py records why it is not four any more. Reachable because
# build.zig.zon already depends on ../securemilter-lib by path, so the six
# repositories are checked out side by side.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "..", "securemilter-lib", "test"))

from dnsfake import SERVFAIL, DnsFake, TxtZone   # noqa: E402
from cases import ALL_CASES

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CHECK = os.path.join(HERE, "..", "..", "zig-out", "bin", "securedkim-check")
DEFAULT_PORT = 5354


def parse_output(text):
    """Turn the checker's key=value lines into a dict."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def build_message(case):
    """Read the case's message and apply its mutations.

    Every mutation must match exactly once. A mutation that stopped matching --
    because the vector was regenerated, or a literal was mistyped -- would
    otherwise leave the message unmodified and the case would pass by testing
    nothing at all. That failure is silent and is worth being loud about.
    """
    path = os.path.join(HERE, "messages", case["message"])
    with open(path, "rb") as f:
        data = f.read().decode("utf-8")

    for old, new in case.get("mutate", []):
        n = data.count(old)
        if n != 1:
            raise AssertionError(
                f"mutation matched {n} times, expected exactly 1: {old[:60]!r}")
        data = data.replace(old, new, 1)

    return data.encode("utf-8")


def resolve_zone(case):
    """A case's `zone`, with the SERVFAIL shorthand expanded.

    `zone: "SERVFAIL"` makes every name answer SERVFAIL. Spelled as a string in
    cases.py so the case file needs no import from the DNS module.
    """
    zone = case.get("zone")
    if zone == "SERVFAIL":
        from cases import ED25519_NAME, RSA_NAME
        return {ED25519_NAME: SERVFAIL, RSA_NAME: SERVFAIL}
    return zone


def run_case(case, check_bin, port, verbose):
    """Run one case. Returns (ok, list_of_problem_strings)."""
    problems = []

    try:
        message = build_message(case)
    except AssertionError as e:
        return False, [f"harness: {e}"]

    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tf:
        tf.write(message)
        msg_path = tf.name

    try:
        with DnsFake(TxtZone(resolve_zone(case)), port=port, verbose=verbose) as dns:
            cmd = [check_bin, "-n", "127.0.0.1", "-p", str(port)]
            cmd += case.get("args", [])
            cmd.append(msg_path)
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=60)
            except subprocess.TimeoutExpired:
                return False, ["checker timed out"]

            if proc.returncode != 0:
                return False, [
                    f"checker exited {proc.returncode}: "
                    f"{proc.stderr.decode(errors='replace').strip()[:300]}"
                ]

            # A leak report or any other stderr noise is a defect in its own
            # right, and silently tolerating it here is how a per-signature leak
            # in the verify path went unnoticed until this suite was written.
            stderr = proc.stderr.decode(errors="replace").strip()
            if stderr:
                problems.append(f"unexpected stderr: {stderr[:300]}")

            got = parse_output(proc.stdout.decode(errors="replace"))
            for key, want in case["expect"].items():
                # `None` asserts the field is ABSENT. Needed for fields emitted
                # only when set, such as sig.N.testing: expecting a value proves
                # the flag can be raised, and only expecting its absence proves it
                # is not raised for every key -- which would suppress DMARC
                # alignment everywhere and look like nothing at all.
                if want is None:
                    if key in got:
                        problems.append(f"{key}: want absent, got {got[key]!r}")
                elif key not in got:
                    problems.append(f"{key}: missing from output")
                elif got[key] != want:
                    problems.append(f"{key}: want {want!r} got {got[key]!r}")

            if verbose:
                print(f"        queries: {dns.query_log()}")
    finally:
        os.unlink(msg_path)

    return not problems, problems


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every case, and log DNS queries")
    ap.add_argument("--test", metavar="NAME", help="run only this case")
    ap.add_argument("--section", metavar="SUBSTRING",
                    help="run cases whose RFC section contains this")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"loopback DNS port (default {DEFAULT_PORT})")
    ap.add_argument("--check", default=os.environ.get("SECUREDKIM_CHECK", DEFAULT_CHECK),
                    help="path to securedkim-check")
    args = ap.parse_args()

    check_bin = os.path.abspath(args.check)
    if not os.path.isfile(check_bin):
        print(f"securedkim-check not found at {check_bin}\n"
              f"Build it first:  cd ../.. && zig build", file=sys.stderr)
        return 2

    selected = ALL_CASES
    if args.test:
        selected = [c for c in selected if c["name"] == args.test]
    if args.section:
        selected = [c for c in selected if args.section in c["section"]]
    if not selected:
        print("no cases selected", file=sys.stderr)
        return 2

    passed = 0
    failures = []
    for case in selected:
        ok, problems = run_case(case, check_bin, args.port, args.verbose)
        if ok:
            passed += 1
            if args.verbose:
                print(f"  PASS  {case['name']:<36} [{case['section']}]")
        else:
            failures.append((case, problems))
            print(f"  FAIL  {case['name']:<36} [{case['section']}]")
            for p in problems:
                print(f"        {p}")

    total = len(selected)
    print(f"\ntotal={total} passed={passed} failed={len(failures)}")

    if failures:
        print("\nfailing cases, with the RFC text that fixes each expectation:")
        for case, problems in failures:
            print(f"\n  {case['name']}  [{case['section']}]")
            print(f"    RFC: {case['source']}")
            if case.get("note"):
                print(f"    note: {case['note']}")
            for p in problems:
                print(f"    -> {p}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
