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
    # --- Multiple key records at one selector (D-20) ----------------------
    #
    # RFC 6376 §6.1.2 step 4 permits two behaviours:
    #
    #   "If the query for the public key returns multiple key records, the
    #    Verifier can choose one of the key records or may cycle through the key
    #    records, performing the remainder of these steps on each record at the
    #    discretion of the implementer. The order of the key records is
    #    unspecified."
    #
    # **The daemon now cycles (D-20).** It previously took the first record only,
    # which is the other conformant branch, and the pair below recorded that.
    #
    # Note the section. These cases were originally filed against §3.6.2.2, and so
    # was the finding; the quoted sentence is genuine RFC 6376 but lives at §6.1.2
    # step 4. §3.6.2.2 says something complementary -- "TXT RRs MUST be unique for
    # a particular selector name; ... if there are multiple records in an RRset,
    # the results are undefined" -- which binds the SIGNER. The verifier's licence
    # to cycle is §6.1.2's. Corrected here when the behaviour changed.
    #
    # Why cycling rather than first-wins: a domain rotating keys publishes old and
    # new at one selector, and RRset order is unspecified and commonly rotated by
    # resolvers, so under first-wins the same message verifies on one lookup and
    # fails on the next. That is the whole finding.
    {
        "name": "multiple_key_records_first_matches",
        "section": "RFC 6376 6.1.2 step 4",
        "source": "the Verifier can choose one of the key records or may cycle "
                  "through the key records",
        "note": "Correct key published first. Unchanged by D-20, and that is the "
                "point of keeping it: cycling must not disturb the case that "
                "already worked, and it must still cost exactly one verification.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: [ED25519_KEY, ED25519_WRONG_KEY]},
        "expect": {"sig.0.result": "pass"},
    },
    {
        "name": "multiple_key_records_second_matches",
        "section": "RFC 6376 6.1.2 step 4",
        "source": "the Verifier can choose one of the key records or may cycle "
                  "through the key records",
        "note": "Correct key published SECOND -- the rotation case, and the one "
                "D-20 is about. Was `fail` while the daemon took only the first "
                "record; the old case said in as many words that a flip to `pass` "
                "would be the cycling change being made deliberately. This is that "
                "flip. Renamed from multiple_key_records_first_does_not_match, "
                "which described the old verdict rather than the scenario.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: [ED25519_WRONG_KEY, ED25519_KEY]},
        "expect": {"sig.0.result": "pass"},
    },
    {
        "name": "key_records_beyond_the_cap_are_not_tried",
        "section": "RFC 6376 6.1.2 step 4",
        "source": "at the discretion of the implementer",
        "note": "The cap has to be observable or it is not a cap. The good key is "
                "published second and only one record is allowed, so the daemon "
                "must stop before reaching it and report the first record's "
                "verdict. Without a bound, whoever publishes the zone chooses how "
                "many public-key verifications each signature costs us -- the same "
                "per-signature work D-4 caps. Pinning this also proves the cycling "
                "loop terminates on the operator's limit rather than on the "
                "RRset's length.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: [ED25519_WRONG_KEY, ED25519_KEY]},
        "args": ["--max-key-records", "1"],
        "expect": {"sig.0.result": "fail", "sig.0.reason": "signature mismatch"},
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

    # -----------------------------------------------------------------------
    # D-11: key-record restrictions.
    # -----------------------------------------------------------------------
    # These mutate the KEY RECORD rather than the message, which the `zone` key
    # already supports and no earlier case used this way. `securedkim` parsed
    # h=, s= and t= into its record struct from the first commit and then never
    # consulted any of them, so a key its owner had restricted verified exactly
    # as though it were unrestricted.
    #
    # Unit tests over the predicates cannot replace these. The predicates could
    # each be perfect while nothing called them -- which is precisely the state
    # this code was in -- so what these pin is the wiring: a restricted key,
    # served over real DNS, reaching the real verify path.
    #
    # Each restriction gets a matching positive case. A check that refuses too
    # much is as broken as one that refuses nothing, and would reject most of
    # the internet, since almost no real record publishes any of these tags.
    {
        "name": "key_h_excludes_signature_hash_permfails",
        "section": "RFC 6376 6.1.2",
        "source": "If the \"h=\" tag exists in the public-key record and the hash "
                  "algorithm implied by the \"a=\" tag in the DKIM-Signature "
                  "header field is not included in the contents of the \"h=\" "
                  "tag, the Verifier MUST ignore the key record and return "
                  "PERMFAIL (inappropriate hash algorithm).",
        "note": "Key restricted to sha1; the vector signs ed25519-sha256. "
                "permerror and not fail: the signature is almost certainly "
                "good, but the key record says it must not be used this way.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: "v=DKIM1; h=sha1; k=ed25519; "
                               "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
        "expect": {"sig.0.result": "permerror",
                   "sig.0.reason": "hash algorithm not permitted by the key record (h=)"},
    },
    {
        "name": "key_h_includes_signature_hash_passes",
        "section": "RFC 6376 3.6.1",
        "source": "h= Acceptable hash algorithms ... A colon-separated list of "
                  "hash algorithms that might be used.",
        "note": "The guard on the case above. `ed25519-sha256` hashes with "
                "SHA-256, so `h=sha256` permits it -- an implementation "
                "comparing the algorithm's own name against the list would "
                "reject every Ed25519 signature from a key that published h=.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: "v=DKIM1; h=sha256; k=ed25519; "
                               "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
        "expect": {"sig.0.result": "pass"},
    },
    {
        "name": "key_s_not_email_permfails",
        "section": "RFC 6376 3.6.1",
        "source": "Verifiers for a given service type MUST ignore this record "
                  "if the appropriate type is not listed.",
        "note": "A key published for some other service. We are unambiguously "
                "the email service, so this record is not ours to use.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: "v=DKIM1; s=tlsa; k=ed25519; "
                               "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
        "expect": {"sig.0.result": "permerror",
                   "sig.0.reason": "key not valid for the email service (s=)"},
    },
    {
        "name": "key_s_lists_email_passes",
        "section": "RFC 6376 3.6.1",
        "source": "email   electronic mail (not necessarily limited to SMTP)",
        "note": "`s=` is a colon-separated LIST. Matching the whole tag value "
                "against \"email\" rather than searching the list would reject "
                "this, and the default `*` case is covered by every other case "
                "in this file, all of which omit s= entirely.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: "v=DKIM1; s=tlsa:email; k=ed25519; "
                               "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
        "expect": {"sig.0.result": "pass"},
    },
    {
        "name": "key_t_s_with_exact_i_passes",
        "section": "RFC 6376 3.6.1",
        "source": "s  Any DKIM-Signature header fields using the \"i=\" tag MUST "
                  "have the same domain value on the right-hand side of the "
                  "\"@\" in the \"i=\" tag and the value of the \"d=\" tag.",
        "note": "The vector already carries i=@football.example.com against "
                "d=football.example.com, so it satisfies the strict flag "
                "unchanged. Without this, an over-strict implementation that "
                "rejected every t=s key would pass the negative case below.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: "v=DKIM1; t=s; k=ed25519; "
                               "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
        "expect": {"sig.0.result": "pass"},
    },
    {
        "name": "key_t_s_with_subdomain_i_permfails",
        "section": "RFC 6376 3.6.1",
        "source": "That is, the \"i=\" domain MUST NOT be a subdomain of \"d=\".",
        "note": "i= moved to a subdomain, which is the single thing t=s exists "
                "to refuse. As with from_not_signed_permfails, editing the "
                "DKIM-Signature breaks the signature too, so what this pins is "
                "the RESULT CLASS: permerror because the key record forbids the "
                "identity, not fail because the bytes did not match. Were the "
                "t=s check absent, this case would report fail and this "
                "expectation would catch it.",
        "message": "rfc8463-ed25519.eml",
        "mutate": [(" d=football.example.com; i=@football.example.com;",
                    " d=football.example.com; i=@mail.football.example.com;")],
        "zone": {ED25519_NAME: "v=DKIM1; t=s; k=ed25519; "
                               "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
        "expect": {"sig.0.result": "permerror",
                   "sig.0.reason": "i= is not exactly d= and the key record sets t=s"},
    },
    {
        "name": "key_t_y_still_reports_the_real_result",
        "section": "RFC 6376 3.6.1",
        "source": "y  This domain is testing DKIM.  Verifiers MUST NOT treat "
                  "messages from Signers in testing mode differently from "
                  "unsigned email, even should the signature fail to verify.  "
                  "Verifiers MAY wish to track testing mode results to assist "
                  "the Signer.",
        "note": "The MUST binds what a verifier DOES about the result, not what "
                "it reports. Reporting `none` would satisfy the first sentence "
                "and destroy the second -- the signer published a testing key "
                "precisely to find out whether it verifies. OpenDKIM resolves "
                "this the same way: the real result, annotated, with only the "
                "action suppressed. For us the suppressed action is DMARC "
                "alignment, since securedmarc consumes this A-R; that half is "
                "not visible to this suite and is pinned on the DMARC side.",
        "message": "rfc8463-ed25519.eml",
        "zone": {ED25519_NAME: "v=DKIM1; t=y; k=ed25519; "
                               "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
        "expect": {"sig.0.result": "pass", "sig.0.testing": "true"},
    },
    {
        "name": "key_without_t_y_is_not_marked_testing",
        "section": "RFC 6376 3.6.1",
        "source": "t= Flags ... OPTIONAL, default is no flags set.",
        "note": "The guard on the case above, and the one that matters most: if "
                "every key were marked testing, no DKIM pass would ever reach "
                "DMARC and the suppression would silently break all alignment. "
                "This is the ordinary vector with the ordinary key -- the same "
                "record every other case uses -- so the marker must be absent.",
        "message": "rfc8463-ed25519.eml",
        "zone": FULL_ZONE,
        "expect": {"sig.0.result": "pass", "sig.0.testing": None},
    },
]


ALL_CASES = VECTOR_CASES + NEGATIVE_CASES
