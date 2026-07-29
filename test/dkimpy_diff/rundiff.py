#!/usr/bin/env python3.12
"""Differential test: dkimpy signs, and dkimpy and securedkim must agree on the verdict.

The assertion is **agreement**, not success. A case passes when both
implementations reach the same verdict, so the tamper sweep -- where both must say
*fail* -- carries the same weight as the positive sweeps. A harness that only
asserted `pass` could not tell "we correctly rejected this" from "we never noticed
it was broken".

Three outcomes per case, and the distinction matters more here than in a
vector-based suite:

  AGREE    both implementations reached the same verdict
  DISAGREE they differ -- a defect in one of them, reported with enough detail to
           say which
  HARNESS  dkimpy could not verify its OWN signature, so the case is malformed and
           securedkim is never consulted

The HARNESS outcome exists because a differential harness generates its inputs, so
one corpus bug can manufacture hundreds of plausible disagreements at once. Twice
on this project a harness defect has arrived disguised as a pile of product
defects. The control settles it before anyone reads Zig.

    python3.12 rundiff.py                    # everything
    python3.12 rundiff.py -v                 # list every case
    python3.12 rundiff.py --sweep bodies     # one sweep
    python3.12 rundiff.py --body trailing_wsp --canon relaxed/relaxed
    SECUREDKIM_CHECK=/path/to/binary python3.12 rundiff.py

Needs py312-dkimpy. Exits non-zero on any DISAGREE or HARNESS result.
"""

import argparse
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "rfc6376"))

from dkimdns import DkimDns          # noqa: E402  -- shared, not duplicated
import corpus                        # noqa: E402
import oracle                        # noqa: E402

DEFAULT_CHECK = os.path.join(HERE, "..", "..", "zig-out", "bin", "securedkim-check")
DEFAULT_PORT = 5364

DOMAIN = "example.com"
SELECTOR = "diff"
DNS_NAME = f"{SELECTOR}._domainkey.{DOMAIN}"

CANONS = ["simple/simple", "simple/relaxed", "relaxed/simple", "relaxed/relaxed"]


def securedkim_verify(check_bin, signed, key_record, port, min_key_bits=None):
    """Run securedkim-check against a signed message. Returns (verdict, reason, stderr)."""
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tf:
        tf.write(signed)
        path = tf.name
    try:
        with DkimDns({DNS_NAME: key_record}, port):
            # --no-normalize matters: the corpus is CRLF-canonical by
            # construction, and its bare CR and LF octets are deliberate body
            # *data*. Without this the checker rewrites them to CRLF before the
            # canonicalizer runs, which silently changes the body being hashed and
            # reports a disagreement that belongs to the tool, not the daemon.
            cmd = [check_bin, "-n", "127.0.0.1", "-p", str(port), "--no-normalize"]
            if min_key_bits is not None:
                cmd += ["-b", str(min_key_bits)]
            cmd.append(path)
            try:
                p = subprocess.run(cmd, capture_output=True, timeout=60)
            except subprocess.TimeoutExpired:
                return "timeout", "checker timed out", ""
    finally:
        os.unlink(path)

    out = {}
    for line in p.stdout.decode(errors="replace").splitlines():
        if "=" in line:
            k, _, v = line.strip().partition("=")
            out[k.strip()] = v.strip()

    stderr = p.stderr.decode(errors="replace").strip()
    if p.returncode != 0:
        return "error", f"exit {p.returncode}: {stderr[:200]}", stderr
    return out.get("sig.0.result", "none"), out.get("sig.0.reason", ""), stderr


def run_case(case, keys, check_bin, port):
    """Returns (outcome, detail) where outcome is AGREE / DISAGREE / HARNESS."""
    message, sign_headers = corpus.build_message(case["body"], case["header"])

    try:
        if case.get("rsa_bits"):
            signed = oracle.sign_with_bits(
                message, keys, selector=SELECTOR, domain=DOMAIN,
                canon=case["canon"], sign_headers=sign_headers,
                rsa_bits=case["rsa_bits"])
            key_record = keys.key_record("rsa-sha256", case["rsa_bits"])
        else:
            signed = oracle.sign(
                message, keys, selector=SELECTOR, domain=DOMAIN,
                algorithm=case["algorithm"], canon=case["canon"],
                sign_headers=sign_headers, use_length=case.get("use_length", False))
            key_record = keys.key_record(case["algorithm"], 2048)
    except Exception as e:
        return "HARNESS", f"dkimpy could not sign: {type(e).__name__}: {e}"

    if case.get("tamper"):
        old, new = case["tamper"]
        if signed.count(old) < 1:
            return "HARNESS", f"tamper target absent: {old[:40]!r}"
        signed = signed.replace(old, new, 1)

    # Control: dkimpy must agree with itself before securedkim is consulted.
    # A minkey of 1024 matches the floor we pass to securedkim so key size is not
    # silently a second variable.
    minkey = case.get("rsa_bits") or 1024
    dkimpy_ok = oracle.verify(signed, key_record, dns_name=DNS_NAME,
                              minkey=min(minkey, 1024))

    if not case.get("tamper") and not dkimpy_ok:
        return "HARNESS", ("dkimpy could not verify its own signature -- the case is "
                           "malformed, so securedkim was not consulted")

    verdict, reason, stderr = securedkim_verify(
        check_bin, signed, key_record, port,
        min_key_bits=1024 if (case.get("rsa_bits") or 2048) < 2048 else None)

    if stderr:
        return "DISAGREE", f"securedkim wrote to stderr: {stderr[:200]}"

    ours_ok = verdict == "pass"
    detail = (f"dkimpy={'pass' if dkimpy_ok else 'fail'} "
              f"securedkim={verdict}" + (f" ({reason})" if reason else ""))

    known = known_limitation(case)
    if known:
        # A disagreement that is understood, reproducible, and attributable stays
        # in the suite rather than being deleted, so it keeps being measured -- but
        # it must not make the run red, or the red stops meaning anything. If the
        # expected disagreement stops happening, that is reported too: it means the
        # limitation was fixed and this entry is now lying.
        if ours_ok == dkimpy_ok:
            return "DISAGREE", (
                f"expected a known disagreement and got agreement -- the limitation "
                f"may be fixed, so remove the entry: {known}")
        return "KNOWN", f"{detail} -- {known}"

    if ours_ok == dkimpy_ok:
        return "AGREE", f"both {'pass' if ours_ok else 'fail'}"

    return "DISAGREE", detail


def known_limitation(case):
    """Return a description if this case is a documented limitation, else None.

    Exactly one entry, and it is a real production limitation rather than a
    harness artifact -- which is why it is recorded here instead of being removed
    from the corpus.

    A milter never sees a header field's original octets. The MTA hands over a name
    and a value, with one leading space already removed unless the daemon
    negotiates `SMFIP_HDR_LEADSPC`, which none of these do. `securedkim` therefore
    reconstructs the field as `name + ": " + value`, and `securedkim-check`
    reproduces that deliberately (see `appendField`) so the tool predicts what the
    daemon does.

    For a field with an EMPTY value the reconstruction is `X-Empty: ` with a
    trailing space, where the wire almost certainly carried `X-Empty:`. Under
    relaxed header canonicalization that trailing WSP is deleted and nothing is
    lost, which is why only the `simple` header cases disagree. Under simple, which
    hashes the field verbatim, the extra octet breaks the signature.

    This is not fixable inside the daemon: both forms arrive as an empty value and
    are indistinguishable at the milter API. It is inherent to `c=simple` header
    canonicalization in any milter, and it is narrow -- essentially every real
    signer uses relaxed for headers, and the field must also have an empty value.
    Filed as D-23.
    """
    if case["header"] == "empty_value" and case["canon"].startswith("simple/"):
        return ("D-23: a milter cannot recover a header's original octets, so an "
                "empty-valued field reconstructs as 'X-Empty: ' and c=simple "
                "hashes one octet too many")
    return None


def build_cases():
    """The sweeps. Each varies one axis so a failure localises immediately."""
    cases = []

    def add(sweep, **kw):
        kw.setdefault("algorithm", "rsa-sha256")
        kw.setdefault("header", "plain")
        kw.setdefault("body", "plain")
        name_bits = [kw["body"], kw["header"], kw["canon"].replace("/", "-"),
                     kw["algorithm"].split("-")[0]]
        if kw.get("use_length"):
            name_bits.append("l")
        if kw.get("rsa_bits"):
            name_bits.append(f"{kw['rsa_bits']}b")
        if kw.get("tamper"):
            name_bits.append("tampered")
        cases.append({"sweep": sweep, "name": ".".join(name_bits), **kw})

    # Bodies x canonicalizations. The core of the suite: this is the axis D-16
    # lived on, and every body is one where simple and relaxed differ.
    for body in corpus.BODIES:
        for canon in CANONS:
            add("bodies", body=body, canon=canon)

    # Header shapes x canonicalizations. The axis D-1/A-6 lived on.
    for header in corpus.HEADERS:
        for canon in CANONS:
            add("headers", header=header, canon=canon)

    # Ed25519 across canonicalizations and a few awkward bodies. D-18's axis.
    for canon in CANONS:
        for body in ("plain", "trailing_wsp", "empty", "utf8"):
            add("ed25519", body=body, canon=canon, algorithm="ed25519-sha256")

    # l= body length. Deliberately paired with bodies that have content after
    # the signed prefix, since l= is only interesting when it truncates.
    for canon in CANONS:
        for body in ("plain", "trailing_wsp", "blank_lines_in_middle", "long_line"):
            add("length", body=body, canon=canon, use_length=True)

    # RSA key sizes, including 1024 which RFC 8463's own example uses.
    for bits in oracle.Keys.RSA_SIZES:
        for canon in ("simple/simple", "relaxed/relaxed"):
            add("keysize", canon=canon, rsa_bits=bits)

    # Tamper sweep: both implementations must FAIL. Asserting agreement on
    # failure is what stops the suite from rewarding a verifier that accepts
    # everything -- a pass-only suite cannot see that at all.
    tampers = [
        ("body_byte", (b"This is a plain body.", b"This is a plaan body.")),
        ("body_wsp", (b"Second line.", b"Second  line.")),
        ("subject", (b"Subject: Differential test message",
                     b"Subject: Differential test messagX")),
        ("from", (b"sender@example.com", b"attacker@example.com")),
    ]
    for canon in CANONS:
        for label, pair in tampers:
            add("tamper", canon=canon, tamper=pair)
            cases[-1]["name"] = f"{label}.{canon.replace('/', '-')}.tampered"

    return cases


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--sweep", help="one sweep: bodies, headers, ed25519, length, keysize, tamper")
    ap.add_argument("--body", help="filter by body key")
    ap.add_argument("--header", help="filter by header key")
    ap.add_argument("--canon", help="filter by canonicalization, e.g. relaxed/relaxed")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--check", default=os.environ.get("SECUREDKIM_CHECK", DEFAULT_CHECK))
    args = ap.parse_args()

    check_bin = os.path.abspath(args.check)
    if not os.path.isfile(check_bin):
        print(f"securedkim-check not found at {check_bin}\n"
              f"Build it first:  cd ../.. && zig build", file=sys.stderr)
        return 2

    cases = build_cases()
    if args.sweep:
        cases = [c for c in cases if c["sweep"] == args.sweep]
    if args.body:
        cases = [c for c in cases if c["body"] == args.body]
    if args.header:
        cases = [c for c in cases if c["header"] == args.header]
    if args.canon:
        cases = [c for c in cases if c["canon"] == args.canon]
    if not cases:
        print("no cases selected", file=sys.stderr)
        return 2

    print(f"dkimpy differential: {len(cases)} cases\n")

    agree = 0
    disagree = []
    harness = []
    known = []

    with oracle.Keys() as keys:
        for case in cases:
            outcome, detail = run_case(case, keys, check_bin, args.port)
            if outcome == "AGREE":
                agree += 1
                if args.verbose:
                    print(f"  AGREE     {case['name']:<52} {detail}")
            elif outcome == "KNOWN":
                known.append((case, detail))
                if args.verbose:
                    print(f"  KNOWN     {case['name']:<52} {detail}")
            elif outcome == "HARNESS":
                harness.append((case, detail))
                print(f"  HARNESS   {case['name']:<52} {detail}")
            else:
                disagree.append((case, detail))
                print(f"  DISAGREE  {case['name']:<52} {detail}")

    print(f"\ntotal={len(cases)} agree={agree} known={len(known)} "
          f"disagree={len(disagree)} harness={len(harness)}")

    if known:
        print(f"\n{len(known)} known limitation(s), documented in known_limitation() "
              f"and not counted as failures:")
        for case, detail in known:
            print(f"  {case['name']}")
            print(f"    {detail}")

    if harness:
        print("\nHARNESS ERRORS -- fix the harness, do NOT file these as defects.")
        print("dkimpy could not verify its own signature, so the case never reached")
        print("securedkim and says nothing about it.")
        for case, detail in harness:
            print(f"\n  {case['name']}  [sweep: {case['sweep']}]")
            print(f"    {detail}")

    if disagree:
        print("\nDISAGREEMENTS -- an independent implementation reached a different")
        print("verdict on the same message. Each names the canonicalization rule the")
        print("case was chosen to exercise.")
        for case, detail in disagree:
            print(f"\n  {case['name']}  [sweep: {case['sweep']}]")
            print(f"    canon={case['canon']} algorithm={case['algorithm']}")
            print(f"    {detail}")
            if case["body"] in corpus.BODIES:
                print(f"    body rule: {corpus.BODIES[case['body']]['note']}")
            if case["header"] in corpus.HEADERS and case["header"] != "plain":
                print(f"    header rule: {corpus.HEADERS[case['header']]['note']}")

    return 1 if (disagree or harness) else 0


if __name__ == "__main__":
    sys.exit(main())
