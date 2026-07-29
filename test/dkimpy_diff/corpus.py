"""Message bodies and header shapes chosen to make the canonicalizations disagree.

This corpus is the whole point of the differential harness, so it is worth being
explicit about the selection rule: **every entry must be a case where `simple` and
`relaxed` produce different octets.** A body with no trailing whitespace and no
internal whitespace runs hashes identically under both, and a corpus of such
bodies cannot detect a canonicalization defect no matter how many algorithms and
key sizes it is crossed with.

That is not a hypothetical. D-16 -- the body hash ignoring each signature's `c=`,
which meant no `c=*/relaxed` signature could verify and therefore almost no real
mail -- was invisible to the entire existing test suite for exactly this reason.
The audit's own words: *"`simple` and `relaxed` body canonicalization produce
identical octets for a body with no trailing whitespace and no internal whitespace
runs -- true of every message the suite sends"*.

So each body below names the RFC 6376 §3.4 rule it exercises.
"""

CRLF = "\r\n"


# ---------------------------------------------------------------------------
# Bodies. RFC 6376 3.4.3 (simple) and 3.4.4 (relaxed).
# ---------------------------------------------------------------------------
#
# relaxed body canonicalization, 3.4.4:
#   - Reduce WSP runs within a line to a single SP
#   - Delete all trailing WSP at the end of each line
#   - Delete trailing empty lines (as simple also does)
#   - Ensure the body ends with CRLF if non-empty
# simple body canonicalization, 3.4.3:
#   - Delete trailing empty lines only. An empty body becomes a single CRLF.

BODIES = {
    "plain": {
        "note": "Control. Identical under both canonicalizations, which is exactly "
                "why a corpus of only bodies like this one is worthless -- it is "
                "here to prove the harness works, not to test anything.",
        "body": "This is a plain body." + CRLF + "Second line." + CRLF,
    },
    "trailing_wsp": {
        "note": "3.4.4: 'Delete all trailing WSP at the end of each line.' Trailing "
                "spaces and tabs survive simple and vanish under relaxed.",
        "body": "Line with trailing spaces.   " + CRLF
                + "Line with trailing tab.\t" + CRLF
                + "Mixed trailing. \t \t" + CRLF,
    },
    "internal_wsp_runs": {
        "note": "3.4.4: 'Reduce all sequences of WSP within a line to a single SP.' "
                "Runs of spaces and tabs mid-line.",
        "body": "Two  spaces and three   spaces." + CRLF
                + "A\ttab and\t\ttwo tabs." + CRLF
                + "Mixed \t \t whitespace run." + CRLF,
    },
    "both_wsp_rules": {
        "note": "Internal runs AND trailing WSP together, which is the ordinary "
                "shape of real mail that has been through a text editor.",
        "body": "Hello   world.  " + CRLF
                + "\tIndented\twith\ttabs.\t" + CRLF
                + "   Leading whitespace preserved as one SP.   " + CRLF,
    },
    "trailing_empty_lines": {
        "note": "3.4.3 and 3.4.4 both delete trailing empty lines. Several CRLF at "
                "the end must collapse identically under both.",
        "body": "Body text." + CRLF + CRLF + CRLF + CRLF,
    },
    "empty": {
        "note": "3.4.3: an empty body canonicalizes to a single CRLF under simple, "
                "and to nothing under relaxed -- so the two hashes differ for the "
                "degenerate case, which is the easiest one to get wrong.",
        "body": "",
    },
    "only_crlf": {
        "note": "A body that is nothing but one CRLF: a trailing empty line, so it "
                "must reduce to the same thing the empty body does.",
        "body": CRLF,
    },
    "no_final_crlf": {
        "note": "3.4.4: 'Ensure the body ends with a CRLF.' A body whose last line "
                "is unterminated must gain one.",
        "body": "No newline at the end of this body.",
    },
    "blank_lines_in_middle": {
        "note": "Interior empty lines must be PRESERVED -- only trailing ones are "
                "deleted. An implementation collapsing all empty lines passes "
                "trailing_empty_lines and fails here.",
        "body": "First para." + CRLF + CRLF + "Second para." + CRLF + CRLF
                + "Third para." + CRLF,
    },
    "wsp_only_lines": {
        "note": "Lines containing nothing but whitespace. Under relaxed the trailing "
                "WSP is deleted and they become empty lines; if they are at the end "
                "they then also become trailing empty lines and disappear. Two rules "
                "interacting, and order matters.",
        "body": "Text." + CRLF + "   " + CRLF + "\t" + CRLF + "More text." + CRLF
                + "  " + CRLF + "\t\t" + CRLF,
    },
    "looks_like_header": {
        "note": "A body line in header form. Must be hashed as body, never parsed as "
                "a header -- the body starts after the first empty line and nothing "
                "in it is structural.",
        "body": "Subject: this is body text, not a header" + CRLF
                + "From: also body" + CRLF + CRLF
                + "DKIM-Signature: v=1; a=rsa-sha256; this is body too" + CRLF,
    },
    "utf8": {
        "note": "8-bit content. Canonicalization is defined on octets, so multi-byte "
                "UTF-8 must pass through untouched -- and must not be mistaken for "
                "whitespace by a byte-wise WSP check.",
        "body": "Naïve café — 日本語 — Ωmega ✓" + CRLF
                + "Grüße aus München.  " + CRLF,
    },
    "long_line": {
        "note": "A line far past the 998-octet SMTP limit. Canonicalization imposes "
                "no line length, so a fixed-size line buffer breaks here.",
        "body": ("x" * 2500) + CRLF + "short" + CRLF,
    },
    "leading_dots": {
        "note": "Lines beginning with '.'. SMTP dot-stuffing happens at the transport "
                "layer, below DKIM; the body DKIM hashes must keep the dots exactly "
                "as they are.",
        "body": ".leading dot" + CRLF + ".." + CRLF + ". dot space" + CRLF,
    },
    "bare_cr": {
        "note": "A lone CR inside a line. RFC 5234 defines WSP as SP or HTAB, so a "
                "CR is neither whitespace to reduce nor a terminator -- only the "
                "exact sequence CRLF ends a line. It must survive both "
                "canonicalizations as data. This is the D-22 case: relaxed used to "
                "delete every CR octet outright.",
        "body": "line one" + CRLF + "bare cr\rhere" + CRLF,
    },
    # A bare LF case belongs here and cannot be driven through this oracle, which
    # is worth recording because it is a trap specific to differential testing.
    #
    # dkimpy's `rfc822_parse` REWRITES a bare LF to CRLF before anything is hashed,
    # while leaving a bare CR alone. Its canonicalizer preserves both -- verified
    # directly -- so the normalization is in the message parser, not in the
    # algorithm under comparison. Feeding it a bare-LF body therefore makes dkimpy
    # sign and verify a DIFFERENT BODY from the one securedkim reads, and the
    # resulting disagreement measures the oracle's input handling rather than
    # anyone's canonicalization.
    #
    # THE GENERAL LESSON: two implementations can agree perfectly on the algorithm
    # and still disagree because one silently rewrote its input. Before believing a
    # differential result, confirm both sides are looking at the same octets. Here
    # that cost one debugging pass; the four failures looked exactly like a
    # canonicalization defect and pointed at code that was already correct.
    #
    # Bare LF is covered instead by the conformance table in
    # securemilter-crypto/src/canon.zig, whose expectations come from dkimpy's
    # canonicalizer directly and so bypass the parser.
}


# ---------------------------------------------------------------------------
# Header shapes. RFC 6376 3.4.1 (simple) and 3.4.2 (relaxed).
# ---------------------------------------------------------------------------
#
# relaxed header canonicalization, 3.4.2:
#   - Lowercase the field name
#   - Unfold continuation lines
#   - Reduce WSP runs to a single SP
#   - Delete WSP at the end of the value
#   - Delete WSP before and after the colon
# simple header canonicalization, 3.4.1: pass the header through unchanged.
#
# Each entry supplies extra headers merged into the base message. `sign_headers`
# names what the signer should cover, so a case can deliberately point `h=` at an
# awkward field.

HEADERS = {
    "plain": {
        "note": "Control.",
        "extra": [("X-Test", "simple value")],
        "sign_headers": ["from", "to", "subject", "x-test"],
    },
    "folded": {
        "note": "3.4.2: 'Unfold all header field continuation lines.' Folding is "
                "signed material under simple and removed under relaxed, so a "
                "folded header is the clearest separator of the two.",
        "extra": [("X-Folded", "first line" + CRLF + " second line" + CRLF
                   + " third line")],
        "sign_headers": ["from", "to", "subject", "x-folded"],
    },
    "folded_with_tabs": {
        "note": "Continuation lines indented with tabs rather than spaces, and more "
                "than one WSP of indent -- unfolding plus WSP reduction together.",
        "extra": [("X-FoldedTab", "start" + CRLF + "\ttabbed cont" + CRLF
                   + "  \t mixed indent cont")],
        "sign_headers": ["from", "to", "subject", "x-foldedtab"],
    },
    "mixed_case_name": {
        "note": "3.4.2: 'Convert all header field names to lowercase.' The name's "
                "case is signed material under simple and irrelevant under relaxed.",
        "extra": [("X-MiXeD-CaSe", "value")],
        "sign_headers": ["from", "to", "subject", "x-mixed-case"],
    },
    # "wsp_around_colon" is deliberately absent, and the reason is worth keeping.
    #
    # RFC 6376 3.4.2 requires relaxed to "delete any WSP characters remaining
    # before and after the colon", which implies fields like `X-Spaced : value`
    # exist -- they are RFC 5322 obs-optional syntax, since `ftext` excludes SP and
    # so the non-obsolete grammar forbids WSP before the colon.
    #
    # dkimpy REFUSES TO SIGN such a message: `MessageFormatError: Unexpected
    # characters in RFC822 header`. That is defensible for a signer, but it means
    # dkimpy cannot act as the oracle here, and a case whose oracle cannot produce
    # an input tests nothing. Leaving it in produced four HARNESS results per run,
    # which is noise that trains you to ignore the harness column.
    #
    # The rule is still covered, by the header canonicalization table in
    # securemilter-crypto/src/canon.zig, whose expectations came from dkimpy's
    # canonicalizer directly rather than through its signer.
    "internal_wsp_runs_hdr": {
        "note": "3.4.2: WSP runs within the value reduce to a single SP.",
        "extra": [("X-Runs", "two  spaces\tand\t\ttabs   here")],
        "sign_headers": ["from", "to", "subject", "x-runs"],
    },
    "trailing_wsp_hdr": {
        "note": "3.4.2: 'Delete all WSP characters at the end of each unfolded "
                "header field value.'",
        "raw": "X-Trailing: value with trailing wsp   \t ",
        "sign_headers": ["from", "to", "subject", "x-trailing"],
    },
    "empty_value": {
        "note": "A header with an empty value. Degenerate, legal, and easy to "
                "mishandle when the code looks for a value after the colon.",
        "raw": "X-Empty:",
        "sign_headers": ["from", "to", "subject", "x-empty"],
    },
    "duplicate_instances": {
        "note": "Two instances of one field name. RFC 6376 5.4.2 requires the "
                "signer's h= to select them from the bottom up, and a verifier that "
                "picks the wrong instance disagrees here. Adjacent to D-1/A-6, which "
                "were header-selection defects.",
        "extra": [("X-Dup", "first instance"), ("X-Dup", "second instance")],
        "sign_headers": ["from", "to", "subject", "x-dup"],
    },
    "oversigned": {
        "note": "A field named twice in h= where it exists only once. RFC 6376 5.4.2 "
                "makes the second reference sign a non-existent field, hashing as "
                "the empty string. This is the RFC 8463 vector's own h= pattern.",
        "extra": [("X-Over", "signed twice in h=")],
        "sign_headers": ["from", "to", "subject", "x-over", "x-over"],
    },
    "signed_absent_header": {
        "note": "h= names a field the message does not contain at all. 5.4: "
                "'Signers MAY claim to have signed header fields that do not exist.'",
        "extra": [],
        "sign_headers": ["from", "to", "subject", "x-does-not-exist"],
    },
    "utf8_value": {
        "note": "Raw 8-bit octets in a header value. Not strictly legal without "
                "encoded-words, but it occurs, and canonicalization is octet-wise.",
        "extra": [("X-Utf8", "café — 日本語")],
        "sign_headers": ["from", "to", "subject", "x-utf8"],
    },
}


BASE_HEADERS = [
    ("From", "Test Sender <sender@example.com>"),
    ("To", "Test Recipient <rcpt@example.net>"),
    ("Subject", "Differential test message"),
    ("Date", "Tue, 29 Jul 2026 12:00:00 -0400"),
    ("Message-ID", "<diff-test@example.com>"),
]


def build_message(body_key, header_key):
    """Assemble a message from one body shape and one header shape.

    Returns CRLF-delimited bytes, plus the `h=` list the signer should use.
    """
    spec = HEADERS[header_key]
    lines = [f"{n}: {v}" for n, v in BASE_HEADERS]

    for name, value in spec.get("extra", []):
        lines.append(f"{name}: {value}")
    if "raw" in spec:
        lines.append(spec["raw"])

    body = BODIES[body_key]["body"]
    return (CRLF.join(lines) + CRLF + CRLF + body).encode("utf-8"), spec["sign_headers"]
