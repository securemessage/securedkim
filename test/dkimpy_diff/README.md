# DKIM differential suite — dkimpy signs, both implementations must agree

dkimpy signs a matrix of messages, then dkimpy and `securedkim` must reach the
same verdict on each. **The first run found three real defects**, two of them
canonicalization bugs that would have rejected legitimate mail.

Current result: **156 agree, 2 known limitations, 0 disagreements.**

```
$ cd ../.. && zig build                          # produces securedkim-check
$ python3.12 rundiff.py

total=158 agree=156 known=2 disagree=0 harness=0
```

Needs `py312-dkimpy`. Note **python3.12**, not `python3` — the port targets 3.12
while the system default here is 3.11. The RFC 8463 suite in `../rfc6376/` is
stdlib-only and runs under either.

Flags: `-v` lists every case, `--sweep bodies|headers|ed25519|length|keysize|tamper`,
`--body`/`--header`/`--canon` filter, `SECUREDKIM_CHECK=` overrides the binary.

## Why this exists alongside the RFC 8463 suite

`../rfc6376/` runs the RFC 8463 Appendix A vectors: authoritative, externally
authored, and **five of them**. They cover one body, one header set, and one `h=`
pattern. That is enough to catch an algorithm-level defect like D-18 and nowhere
near enough to cover canonicalization, which is where DKIM implementations
actually go wrong — D-15, D-16, D-21 and D-22 were all canonicalization or header
handling.

This suite trades authority for coverage: 158 generated cases across bodies,
header shapes, canonicalizations, algorithms, `l=` and key sizes. Neither replaces
the other. **The standing caveat applies: two implementations wrong in the same way
agree, and this suite would report success.** That is precisely why the RFC vectors
remain the gate.

## The assertion is agreement, not success

A case passes when both implementations reach the same verdict. The tamper sweep —
where both must say *fail* — carries the same weight as the positive sweeps. A
suite that only asserted `pass` could not distinguish "we correctly rejected this"
from "we never noticed it was broken", and would quietly reward a verifier that
accepted everything.

Each case yields one of four outcomes:

| outcome | meaning |
|---|---|
| **AGREE** | both reached the same verdict |
| **KNOWN** | a documented, understood limitation — see `known_limitation()` |
| **HARNESS** | dkimpy could not verify its *own* signature, so the case is malformed and `securedkim` was never consulted |
| **DISAGREE** | a real difference; a defect in one of them |

**HARNESS exists because a differential harness generates its own inputs**, so one
corpus bug can manufacture hundreds of plausible disagreements at once. Every case
runs a dkimpy self-check control — dkimpy verifies what dkimpy just signed, through
an injected `dnsfunc` so no DNS is involved — before `securedkim` is consulted. It
settles which side is broken before anyone starts reading Zig.

That is not defensive padding. Twice on this project a harness defect has arrived
disguised as a pile of product defects: `c=simple/*` in the ARC suite, and a
`type(object())` mistake in the DKIM DNS server that served key records one
character at a time and produced 11 phantom failures in one run.

## The corpus is the whole point

Selection rule: **every body must be one where `simple` and `relaxed` produce
different octets.**

A body with no trailing whitespace and no internal whitespace runs hashes
identically under both, and a corpus of such bodies cannot detect a
canonicalization defect no matter how many algorithms and key sizes it is crossed
with. That is exactly how **D-16** — the body hash ignoring each signature's `c=`,
which meant no `c=*/relaxed` signature could verify, and therefore almost no real
mail — stayed invisible. From the audit: *"`simple` and `relaxed` body
canonicalization produce identical octets for a body with no trailing whitespace
and no internal whitespace runs — true of every message the suite sends"*.

So the 14 bodies each name the RFC 6376 §3.4 rule they exercise: trailing WSP,
internal WSP runs, trailing empty lines, empty body, CRLF-only body, missing final
CRLF, interior blank lines, whitespace-only lines, header-shaped body text, UTF-8,
2500-octet lines, leading dots, bare CR. The 11 header shapes do the same for
§3.4.1/§3.4.2: folding, tabs in continuations, mixed-case names, WSP runs, trailing
WSP, empty value, duplicate instances, oversigning, and an `h=` naming an absent
field.

## What it found

### D-21 — relaxed canonicalized an empty body as CRLF instead of null (Medium)

RFC 6376 §3.4.4 closes with: *"Note that a completely empty or missing body is
canonicalized as a null input."* §3.4.3 (simple) says the opposite for itself:
*"converts 0\*CRLF at the end of the body to a single CRLF"*.

`canon.zig` emitted CRLF for **both**, and its doc comment cited §3.4.4 for a rule
§3.4.4 does not contain. Easy to miss, because §3.4.4 states it in a closing note
rather than in its numbered steps.

Affects any `c=*/relaxed` signature over an empty body, a CRLF-only body, or a body
that reduces to nothing — a whitespace-only body does, since relaxed strips the
trailing WSP and then discards the resulting empty lines. Read receipts,
subject-only notes, and automated notifications all land here. Two-way, like D-18:
we rejected valid signatures *and* produced invalid ones.

### D-22 — relaxed deleted every CR and treated bare LF as a terminator (Medium)

**Only the exact sequence CRLF terminates a line.** RFC 5234 defines WSP as SP or
HTAB, so §3.4.4's "reduce WSP" and "ignore whitespace at the end of lines" give
relaxed no licence to touch a CR at all. `updateRelaxed` skipped every CR outright
and flushed a line on any LF, so a lone CR was silently deleted and a lone LF split
a line.

`simple` handled both correctly, so the two algorithms disagreed with each other
inside our own codebase — a good sign one of them was guessing.

Also fixed here, found while restructuring: **a CRLF split across two `update()`
calls became two data octets.** The old lookahead was `i + 1 < data.len`, which
cannot see into the next chunk. Latent — both callers pass the whole body in one
call — but `BodyCanonicalizer`'s own documentation invites streaming, and a latent
bug in a documented API is a live one waiting for its first caller. The new test
tries **every** split point of a body, not a hand-picked one.

### D-23 — `c=simple` header canonicalization of an empty-valued field (Low, not fixable)

Reported as **KNOWN**, not as a failure, and it is a genuine production limitation
rather than a harness artifact.

A milter never sees a header field's original octets. The MTA hands over a name and
a value with one leading space already removed, unless the daemon negotiates
`SMFIP_HDR_LEADSPC`, which none of these do. `securedkim` therefore rebuilds the
field as `name + ": " + value`, and `securedkim-check` reproduces that deliberately
so the tool predicts what the daemon does.

For an **empty** value that yields `X-Empty: ` where the wire almost certainly
carried `X-Empty:`. Relaxed deletes the trailing WSP and loses nothing — which is
why only the `simple` header cases disagree. Simple hashes the field verbatim and
the extra octet breaks the signature.

Not fixable in the daemon: both forms arrive as an empty value and are
indistinguishable at the milter API. Inherent to `c=simple` header canonicalization
in *any* milter, and narrow — the field must have an empty value, and essentially
every real signer uses relaxed for headers.

## Two traps this suite walked into, both worth remembering

**1. The oracle rewrote its input.** Four `bare_cr_and_lf` cases disagreed and
looked exactly like a canonicalization defect — while pointing at code that was
already correct. Cause: **dkimpy's `rfc822_parse` rewrites a bare LF to CRLF before
anything is hashed**, though its canonicalizer preserves it. dkimpy was signing and
verifying a *different body* from the one `securedkim` read.

> **Two implementations can agree perfectly on the algorithm and still disagree
> because one silently rewrote its input. Before believing a differential result,
> confirm both sides are looking at the same octets.**

The case was split: bare CR, which dkimpy preserves, stays here and does test the
D-22 fix. Bare LF moved to the `canon.zig` table, whose expectations come from
dkimpy's canonicalizer directly and so bypass its parser.

**2. Our own tool rewrote its input.** `securedkim-check` normalized bare CR/LF to
CRLF while reading the file. Sensible default — a `.eml` edited on a Unix host is
LF-only and DKIM is defined over CRLF — but it destroyed the very octets D-22 is
about. Unlike the header space-stripping, that normalization emulates nothing: a
milter receives body octets verbatim over `SMFIC_BODY`. Hence the new
`--no-normalize` flag, which this suite always passes.

## Gate properties

| property | how it was verified |
|---|---|
| Independent | dkimpy signs every message; nothing here verifies our own output |
| Committed | In this repository, keys generated per run and never committed |
| Proven able to fail | 142/158 disagree against `/usr/bin/true`; three deliberate bug reintroductions |
| Correct exit status | Non-zero on any DISAGREE or HARNESS |
| Real component | Real DNS over UDP; the shipped `verify.verifySignature` |

### Bug reintroductions

- **D-21 reverted** (relaxed empty body → CRLF) → 4 disagreements.
- **D-22 reverted** (relaxed deletes CR) → 2 disagreements, *and* the `canon.zig`
  conformance table fails.
- **`/usr/bin/true`** → 142 disagreements, exit 1. Note the honest limit: a stub
  trivially "agrees" on the tamper cases, because both sides say fail. That is
  inherent to asserting agreement, and it is why the positive sweeps carry the
  detection load.

## Not yet done

**The reverse direction: `securedkim` signs, dkimpy verifies.** This suite only
tests our *verify* path against an independent signer. D-18 was a two-way defect —
our signing half was equally broken — and nothing here would have caught that half.
It needs a signing entry point equivalent to `securedkim-check`; `sign.signMessage`
is already public, so the work is a CLI wrapper. This is the same gap `securearc`
has with the ValiMail signing half.

## Provenance

dkimpy 1.1.8 (`py312-dkimpy`), <https://launchpad.net/dkimpy>. Chosen because it is
widely deployed, tests against RFC 8463 Appendix A itself, and is not derived from
this codebase. Normative citations refer to
<https://www.rfc-editor.org/rfc/rfc6376.txt> and RFC 5234 for the WSP definition.
