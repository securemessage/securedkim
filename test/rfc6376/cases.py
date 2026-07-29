"""DKIM conformance cases, built on the RFC 8463 Appendix A test vectors.

Two tiers, and the difference in evidentiary weight is the point:

  1. **The RFC 8463 Appendix A vectors themselves.** A complete signed message
     with an Ed25519-SHA256 and an RSA-SHA256 signature, the matching public key
     DNS records, and the RFC's own statement about what must happen. Nobody here
     chose these bytes or the expected outcome, which is what makes them an
     external oracle. **These found two real defects on the first run.**

  2. **Negative cases derived from vector 1 by a single, stated mutation.** These
     are weaker: the RFC does not enumerate them, so each rests on a normative
     sentence quoted in `source` plus the reasoning that the mutation breaks
     exactly what that sentence covers. Where a mutation's correct outcome was
     genuinely arguable, the case was left out rather than guessed at.

Why the vectors come from RFC 8463 and not RFC 6376: RFC 6376's Appendix A is
marked INFORMATIVE and its signature is not verifiable. Its `Received` field is
line-wrapped for the page and the original folding is unrecoverable, so the
signing input cannot be reconstructed, and Appendix C presents its key as one
that looks "similar to" a suitable key rather than as the key that produced the
signature. RFC 8463's appendix is a real vector: `dkimpy` and other
implementations test against it. See README.md.
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# RFC 8463 Appendix A.2, verbatim.
# ---------------------------------------------------------------------------
# The Ed25519 p= is the public key from RFC 8032 §7.1 Test 1, base64-encoded.
ED25519_KEY = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

RSA_P = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR"
    "iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC"
    "DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3"
    "Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
)
RSA_KEY = "v=DKIM1; k=rsa; p=" + RSA_P

ED25519_NAME = "brisbane._domainkey.football.example.com"
RSA_NAME = "test._domainkey.football.example.com"

FULL_ZONE = {ED25519_NAME: ED25519_KEY, RSA_NAME: RSA_KEY}

# A syntactically valid Ed25519 key that is not the signer's: the RFC 8032 §7.1
# Test 2 public key. Used to show a good signature failing against a wrong key,
# as opposed to failing because it was malformed.
ED25519_WRONG_KEY = "v=DKIM1; k=ed25519; p=PUiUEc/veRIfLbfeD2FKN3PriHTUvKirTB8xkTvvvHU="


# ===========================================================================
# Tier 1: the RFC 8463 Appendix A vectors
# ===========================================================================

VECTOR_CASES = [
    {
        "name": "rfc8463_both_signatures",
        "section": "RFC 8463 A.3",
        "source": "This is a small message with both RSA-SHA256 and "
                  "Ed25519-SHA256 DKIM signatures.",
        "message": "rfc8463-both.eml",
        "zone": FULL_ZONE,
        "expect": {
            "signatures": "2",
            "sig.0.result": "pass",
            "sig.0.selector": "brisbane",
            "sig.1.result": "pass",
            "sig.1.selector": "test",
            "result": "pass",
        },
    },
    {
        "name": "rfc8463_ed25519_alone",
        "section": "RFC 8463 A.3",
        "source": "The signatures are independent of each other, so either "
                  "signature would be valid if the other were not present.",
        "note": "The RSA signature removed. This is the case that matters most in "
                "the whole suite: with both present, a passing RSA signature makes "
                "the overall verdict `pass` and hides an Ed25519 failure "
                "completely. Ed25519 was in fact broken, and this is the shape of "
                "case that cannot miss it.",
        "message": "rfc8463-ed25519.eml",
        "zone": FULL_ZONE,
        "expect": {"signatures": "1", "sig.0.result": "pass", "result": "pass"},
    },
    {
        "name": "rfc8463_rsa_alone",
        "section": "RFC 8463 A.3",
        "source": "The signatures are independent of each other, so either "
                  "signature would be valid if the other were not present.",
        "note": "The Ed25519 signature removed.",
        "message": "rfc8463-rsa.eml",
        "zone": FULL_ZONE,
        "expect": {"signatures": "1", "sig.0.result": "pass", "result": "pass"},
    },
    {
        "name": "rfc8463_ed25519_key_alone_in_dns",
        "section": "RFC 8463 A.2",
        "source": "The DNS record for the verification public key has a "
                  "\"k=ed25519\" tag to indicate that the key is an Ed25519 "
                  "rather than an RSA key.",
        "note": "Only the Ed25519 key is published, so the RSA signature cannot "
                "find its key and must PERMFAIL while the Ed25519 one still "
                "passes. Separates 'the verifier found the right key' from 'the "
                "verifier happened to have a key that worked'.",
        "message": "rfc8463-both.eml",
        "zone": {ED25519_NAME: ED25519_KEY},
        "expect": {
            "signatures": "2",
            "sig.0.result": "pass",
            "sig.1.result": "permerror",
            "result": "pass",
        },
    },
    {
        "name": "rfc8463_oversigned_h_list",
        "section": "RFC 6376 5.4.2 / RFC 8463 A.3",
        "source": "h=from : to : subject : date : message-id : from : subject : "
                  "date",
        "note": "Not a separate message -- the same vector, recorded as its own "
                "case because of what that h= list contains. `from`, `subject` "
                "and `date` each appear twice, which RFC 6376 5.4.2 defines as "
                "signing a non-existent second occurrence: the extra entries must "
                "hash as the empty string. An implementation that instead hashed "
                "each header again, or stopped at the first occurrence, fails "
                "here. Nothing else in this suite covers it, and it is the single "
                "most easily botched part of header canonicalization.",
        "message": "rfc8463-ed25519.eml",
        "zone": FULL_ZONE,
        "expect": {"sig.0.result": "pass"},
    },
]


# ===========================================================================
# Tier 2: single-mutation negative cases
# ===========================================================================
#
# Each applies one change to a tier-1 vector. `mutate` is a list of
# (old, new) literal replacements, each of which must match exactly once --
# the runner aborts otherwise, so a mutation that silently stops applying
# cannot turn into a vacuous pass.

NEGATIVE_CASES = [
    {
        "name": "body_altered_fails",
        "section": "RFC 6376 3.7",
        "source": "the hash of the canonicalized message body ... is then "
                  "compared with the value of the \"bh\" tag",
        "message": "rfc8463-ed25519.eml",
        "mutate": [("We lost the game.", "We won the game.")],
        "zone": FULL_ZONE,
        "expect": {"sig.0.result": "fail", "sig.0.reason": "body hash mismatch"},
    },
    {
        "name": "signed_header_altered_fails",
        "section": "RFC 6376 3.7",
        "source": "The signature is then computed over the canonicalized "
                  "header fields",
        "note": "Subject is in h=, so changing it must break the signature "
                "without touching the body hash.",
        "message": "rfc8463-ed25519.eml",
        "mutate": [("Subject: Is dinner ready?", "Subject: Is lunch ready?")],
        "zone": FULL_ZONE,
        "expect": {"sig.0.result": "fail", "sig.0.reason": "signature mismatch"},
    },
    {
        "name": "unsigned_header_added_still_passes",
        "section": "RFC 6376 5.4",
        "source": "Signers MAY claim to have signed header fields that do not "
                  "exist",
        "note": "The converse of the case above, and the reason it is worth "
                "having: a header outside h= must NOT affect the verdict. An "
                "implementation that hashed every header rather than the ones h= "
                "names would pass the negative case above and fail this one.",
        "message": "rfc8463-ed25519.eml",
        "mutate": [("From: Joe SixPack",
                    "X-Added-By-Relay: some value\r\nFrom: Joe SixPack")],
        "zone": FULL_ZONE,
        "expect": {"sig.0.result": "pass"},
    },
    {
        "name": "wrong_key_in_dns_fails",
        "section": "RFC 6376 6.1.2",
        "source": "the Verifier ... uses the public key to verify the signature",
        "note": "A well-formed Ed25519 key that is not the signer's (RFC 8032 "
                "§7.1 Test 2). Must be `fail`, not `permerror`: the record and "
                "the key parse, so this is a signature that did not validate "
                "rather than a record that could not be used.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: ED25519_WRONG_KEY},
        "expect": {"sig.0.result": "fail"},
    },
    {
        "name": "no_key_record_permfails",
        "section": "RFC 6376 6.1.2",
        "source": "If the query for the public key fails because the "
                  "corresponding key record does not exist, the Verifier MUST "
                  "immediately return PERMFAIL (no key for signature).",
        "note": "NXDOMAIN. MUST be permerror and not temperror -- the difference "
                "decides whether the sending MTA is told to give up or to retry a "
                "message that can never verify.",
        "message": "rfc8463-ed25519.eml",
        "zone": {},
        "expect": {"sig.0.result": "permerror"},
    },
    {
        "name": "key_type_mismatch_permfails",
        "section": "RFC 6376 3.6.1",
        "source": "k= Key type ... Signers and Verifiers MUST support the "
                  "\"rsa\" key type.",
        "note": "The Ed25519 public key published with k=rsa. The key and the "
                "signature algorithm disagree, so the record cannot be used for "
                "this signature at all -- permerror, not a failed comparison. "
                "RFC 8463 §4.2 adds k=ed25519 precisely so this is decidable.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME:
                 "v=DKIM1; k=rsa; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
        "expect": {"sig.0.result": "permerror"},
    },
    {
        "name": "revoked_key_permfails",
        "section": "RFC 6376 6.1.2",
        "source": "If the \"p=\" tag is empty, the Verifier MUST treat the key as "
                  "revoked and return PERMFAIL (key revoked).",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: "v=DKIM1; k=ed25519; p="},
        "expect": {"sig.0.result": "permerror"},
    },
    {
        "name": "wrong_key_version_permfails",
        "section": "RFC 6376 3.6.1",
        "source": "v= Version of the DKIM key record ... If specified, this tag "
                  "MUST be set to \"DKIM1\" ... An unrecognized tag value MUST "
                  "cause the entire key to be ignored.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME:
                 "v=DKIM2; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
        "expect": {"sig.0.result": "permerror"},
    },
    # --- Multiple key records at one selector -----------------------------
    #
    # RFC 6376 §3.6.2.2 permits two behaviours, and this pair records which one
    # the daemon implements rather than asserting a preference:
    #
    #   "If the query for the public key returns multiple key records, the
    #    Verifier can choose one of the key records or may cycle through the key
    #    records ... The order of the key records is unspecified."
    #
    # It chooses one: the first returned. Both cases below are therefore
    # conformant outcomes, and together they prove the choice is the first record
    # rather than, say, a search.
    #
    # I first wrote this as a single case expecting `pass` on the assumption that
    # the daemon cycled. It does not, and the RFC explicitly allows that, so the
    # expectation was mine and wrong -- the same mistake as ARC finding A-18,
    # caught the same way. The cases were corrected; the code was not.
    #
    # **The operational consequence is a real one and is filed as a finding.** A
    # domain rotating keys publishes old and new at one selector, DNS RRset order
    # is unspecified and commonly rotated by resolvers, so the same message can
    # verify on one lookup and fail on the next. Cycling is the robust branch.
    {
        "name": "multiple_key_records_first_matches",
        "section": "RFC 6376 3.6.2.2",
        "source": "the Verifier can choose one of the key records or may cycle "
                  "through the key records",
        "note": "Correct key published first.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: [ED25519_KEY, ED25519_WRONG_KEY]},
        "expect": {"sig.0.result": "pass"},
    },
    {
        "name": "multiple_key_records_first_does_not_match",
        "section": "RFC 6376 3.6.2.2",
        "source": "the Verifier can choose one of the key records or may cycle "
                  "through the key records",
        "note": "Correct key published second. `fail` is the 'choose one' branch "
                "and is conformant; a verifier that cycled would return `pass`. "
                "If this case ever flips to `pass`, that is the cycling change "
                "being made deliberately -- not a regression.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: [ED25519_WRONG_KEY, ED25519_KEY]},
        "expect": {"sig.0.result": "fail"},
    },
    {
        "name": "dns_servfail_tempfails",
        "section": "RFC 6376 6.1.2",
        "source": "If the query for the public key fails to respond, the "
                  "Verifier MAY defer the message for later ... it MAY return "
                  "TEMPFAIL (key unavailable).",
        "note": "SERVFAIL rather than NXDOMAIN, which is the other half of the "
                "pair with no_key_record_permfails. The RFC says MAY, so `fail` "
                "would also be conformant; this pins the retry-friendly choice "
                "the daemon makes, and the point of the case is that it must not "
                "be confused with the permanent branch.",
        "message": "rfc8463-ed25519.eml",
        "zone": "SERVFAIL",
        "expect": {"sig.0.result": "temperror"},
    },
    {
        "name": "from_not_signed_permfails",
        "section": "RFC 6376 5.4",
        "source": "The From header field MUST be signed (that is, included in "
                  "the \"h=\" tag of the resulting DKIM-Signature header field).",
        "note": "`from` removed from h=. The signature will not verify anyway "
                "once h= changes, so what this case actually pins is the *reason*: "
                "an unsigned From must be rejected as a malformed signature "
                "before any cryptography, because otherwise a captured signature "
                "keeps verifying while From is rewritten at will.",
        "message": "rfc8463-ed25519.eml",
        "mutate": [(" q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n"
                    " subject : date : message-id : from : subject : date;",
                    " q=dns/txt; s=brisbane; t=1528637909; h=to :\r\n"
                    " subject : date : message-id : subject : date;")],
        "zone": FULL_ZONE,
        "expect": {"sig.0.result": "permerror", "sig.0.reason": "from not signed"},
    },
]


ALL_CASES = VECTOR_CASES + NEGATIVE_CASES
