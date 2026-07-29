# DKIM conformance suite (RFC 8463 Appendix A + RFC 6376)

Drives the RFC 8463 Appendix A test vectors, and negative cases derived from
them, against `securedkim-check`.

Current result: **17 / 17.** The first run found **two real defects**, one of them
Critical.

```
$ cd ../.. && zig build                # produces zig-out/bin/securedkim-check
$ python3 runsuite.py

total=17 passed=17 failed=0
```

No dependencies beyond the Python standard library. Flags: `-v` lists every case
and logs DNS queries, `--test NAME` runs one case, `--section 8463` selects by RFC
section, `--port N` moves the loopback DNS port.
`SECUREDKIM_CHECK=/path/to/binary` overrides the checker location.

## Why RFC 8463's appendix and not RFC 6376's

There is no official DKIM conformance suite to vendor — `securespf` runs
openspf.org's RFC 7208 cases and `securearc` runs ValiMail's, but no equivalent
exists for RFC 6376.

**Watch out for a trap here:** the `dkim2tests` vectors on `forge.turscar.ie` look
like exactly the right thing and are not. They test **DKIM2**, the successor
protocol, not RFC 6376.

The obvious fallback would be RFC 6376's own Appendix A, and it does not work:

- It is marked **INFORMATIVE**, and its signature is not verifiable.
- Its `Received` field is line-wrapped to fit the page, and the original folding
  is unrecoverable. Folding is part of the signed material under both
  canonicalizations, so the signing input cannot be reconstructed.
- Appendix C presents its key as one that looks *"similar to"* a suitable key,
  not as the key that produced the signature.

**RFC 8463 Appendix A is a real vector.** It carries a complete signed message
with an Ed25519-SHA256 *and* an RSA-SHA256 signature over the same body, the two
matching public key DNS records, and an explicit statement of what must happen.
`dkimpy` and other implementations test against it.

`extract-vectors.py` regenerates the `.eml` files straight from the published RFC,
so their provenance is checkable rather than asserted:

```
$ python3 extract-vectors.py --check
  ok       rfc8463-both.eml (1088 bytes)
  ok       rfc8463-ed25519.eml (644 bytes)
  ok       rfc8463-rsa.eml (723 bytes)
```

Transcribing a DKIM vector by hand is a bad idea: one wrong byte changes the body
hash or the signing input, and the resulting failure looks exactly like an
implementation defect — the most expensive kind of harness bug, because it points
at production code that is fine.

## What it found

### D-18 — Ed25519-SHA256 signed and verified the wrong thing (Critical)

The first run: **RSA passed, Ed25519 failed.** Same message, same body, same `h=`,
same canonicalization — so body hashing, header canonicalization and the `h=`
handling were all already correct, and the difference was the algorithm alone.

RFC 8463 §3 is explicit:

> The Ed25519-SHA256 signing algorithm computes a message hash as defined in
> Section 3 of [RFC6376] using SHA-256 [FIPS-180-4-2015] as the hash-alg. It
> signs **the hash** with the PureEdDSA variant Ed25519

`securedkim` passed the canonicalized signing input straight to Ed25519 instead of
its SHA-256 digest. **RSA hid the bug**: OpenSSL's `EVP_DigestVerify` applies
SHA-256 internally, so handing it the signing input is correct there. PureEdDSA
hashes with SHA-512 as part of EdDSA itself and knows nothing about the DKIM
hash-alg, so the caller must supply the digest. Passing the signing input to both
*looks* uniform and is right for only one of them.

Both directions were wrong, symmetrically:

- **Verify** — every conformant Ed25519 signature returned `dkim=fail`, feeding
  DMARC and potentially rejecting legitimate mail.
- **Sign** — every Ed25519 signature this daemon produced was rejected by every
  conformant verifier.

**Nothing internal could have caught it.** Sign and verify were wrong in the same
direction, so they round-tripped against each other perfectly and the unit test —
which signed and then verified with the same code — passed. The signatures were
self-consistent and interoperable with nobody. This is the same blind spot that
produced D-15 and D-16, where the suite only ever asked the daemon to verify its
own signatures.

The fix moved the SHA-256 step *inside* `ed25519Sha256Sign`/`ed25519Sha256Verify`
and renamed them from `ed25519Sign`/`ed25519Verify`, so the function name is the
RFC's algorithm name and the hashing cannot be forgotten at a call site. The
crypto unit test was rewritten to compare against `std.crypto` directly rather
than against our own other function, which is what a round-trip test cannot do.

### D-19 — a memory leak on every signature verified (Medium)

Found because the checker runs under Zig's leak detector. `verify.zig` nested
`dkim.stripWhitespace(...)` inside a `base64Decode(...)` call for the `bh=` tag
and never freed the intermediate. The `b=` path six lines below always had its
`defer`; only this one was missed.

`conn.allocator` is the worker's allocator, **not a per-message arena** — nothing
reclaimed it when the message ended, so a busy daemon grew without limit.

The suite treats any output on stderr as a failure for this reason, so a leak
report cannot be quietly tolerated.

### D-20 — first-record key choice is fragile during key rotation (Low)

Not a conformance defect. RFC 6376 §3.6.2.2 permits either behaviour:

> If the query for the public key returns multiple key records, the Verifier can
> choose one of the key records or may cycle through the key records ... The order
> of the key records is unspecified.

`securedkim` chooses the first. That is conformant, but a domain rotating keys
publishes old and new at one selector, and RRset order is unspecified and commonly
rotated by resolvers — so the same message can verify on one lookup and fail on
the next. Cycling is the robust branch. Filed; not changed here.

## What it tests

Two tiers, and the difference in evidentiary weight is deliberate.

**Tier 1 — the RFC 8463 Appendix A vectors (5 cases).** Nobody here chose the
bytes or the expected outcomes. Includes the message with both signatures, each
signature alone (the RFC states *"either signature would be valid if the other
were not present"*), and a case where only one key is published.

`rfc8463_ed25519_alone` is the most important case in the suite. With both
signatures present, a passing RSA signature makes the overall verdict `pass` and
hides the Ed25519 failure completely — which is why `securedkim-check` reports
**every** signature individually rather than an overall verdict. Reintroducing
D-18 fails 6 cases; had the checker reported only an overall verdict, it would
have failed 1.

`rfc8463_oversigned_h_list` records what that vector's `h=` list contains:
`from`, `subject` and `date` each appear **twice**. RFC 6376 §5.4.2 defines the
repeat as signing a non-existent second occurrence, so the extra entries must hash
as the empty string. It is the most easily botched part of header canonicalization
and nothing else here covers it.

**Tier 2 — single-mutation negative cases (12 cases).** Each applies one stated
change and rests on a normative sentence quoted in its `source` field. Weaker
evidence, because the RFC does not enumerate them. Covers body and signed-header
alteration, an unsigned header added, wrong key, no key record (PERMFAIL),
SERVFAIL (TEMPFAIL), key type mismatch, revoked key, wrong key version, multiple
key records, and an unsigned `From`.

Every mutation must match its target exactly once or the runner aborts — a
mutation that silently stopped applying would leave the message unmodified and the
case would pass by testing nothing.

## Gate properties

| property | how it was verified |
|---|---|
| External | Vectors and expected outcomes authored by the RFC 8463 editor |
| Committed | In this repository, not `/tmp` |
| Proven able to fail | 0/17 against `/usr/bin/true`; three deliberate bug reintroductions |
| Correct exit status | Non-zero on any failure, so it can gate a build |
| Exercises the real component | Real DNS over UDP; the checker calls the shipped `verify.verifySignature` |

### Bug reintroductions

- **Revert Ed25519 to signing the raw input** — fails 6 cases, including
  `rfc8463_both_signatures`.
- **Remove the `bh_stripped` `defer`** — fails on `unexpected stderr` with the
  leak report, which is how D-19 was found in the first place.
- **`/usr/bin/true`** — 0/17, exit 1.

## A harness bug caught before it was filed as 11 product defects

The first full run reported 11 failures with reasons like `key revoked` on names
where a perfectly good key was published. That was the harness.

`DkimDns.__init__` asked `isinstance(v, (list, type(self.SERVFAIL)))` to decide
whether a value was already a list. `SERVFAIL` is a plain `object()`, so
`type(SERVFAIL)` is `object` and **the test matched everything** — single strings
were stored unwrapped, and `for value in values` iterated them one character at a
time, serving a TXT record per character.

Recorded because this is the second time on this project that a harness defect
presented as a pile of product defects (the first was `c=simple/*` in the ARC
suite). **Before filing a suite failure as a product defect, verify the harness
presents what production presents.**

## Not yet done: differential testing against `dkimpy`

The RFC vectors are few. Differential testing against an independent
implementation would cover far more ground — many `c=` combinations, `l=`, key
sizes, folding shapes — and it *is* viable for DKIM, unlike DMARC, because
RFC 6376 is stable and widely implemented.

It needs `py312-dkimpy`, which is available in ports but **not currently
installed**, so it is not wired up. Note the standing caveat: if both
implementations are wrong in the same way, differential testing passes. It
complements the RFC vectors rather than replacing them.

## Provenance

Vectors from <https://www.rfc-editor.org/rfc/rfc8463.txt> — *A New Cryptographic
Signature Method for DomainKeys Identified Mail (DKIM)*, September 2018,
Appendix A. Normative citations in `cases.py` refer to that RFC and to
<https://www.rfc-editor.org/rfc/rfc6376.txt>.
