const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;
const canon = securemilter_crypto.canon;
const header_select = securemilter_crypto.header_select;
const sig_header = securemilter_crypto.sig_header;

const dkim = @import("dkim.zig");

/// DKIM verification result per RFC 6376 §6.1.
pub const Result = enum {
    pass,
    fail,
    temperror,
    permerror,
    neutral,
    none,
    /// The verifier declined this signature by policy, rather than finding it
    /// invalid; used when `l=` signatures are refused.
    policy,

    pub fn toString(self: Result) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .temperror => "temperror",
            .permerror => "permerror",
            .neutral => "neutral",
            .none => "none",
            .policy => "policy",
        };
    }
};

/// What to do with a signature that limits body coverage with `l=`.
pub const BodyLengthPolicy = enum {
    /// Hash only the first `l=` octets, as RFC 6376 §3.5 specifies. The rest of
    /// the body is not covered by the signature, and `unsigned_body_bytes` says
    /// how much of it is not.
    honor,
    /// Decline to evaluate the signature at all, reporting `policy`. RFC 6376
    /// §8.2 sanctions this directly: "Assessors might wish to ignore signatures
    /// that use the tag."
    refuse,
};

/// Detailed verification result for a single DKIM-Signature.
pub const VerifyResult = struct {
    result: Result,
    domain: []const u8,
    selector: []const u8,
    reason: ?[]const u8 = null,
    /// Canonicalized body octets not covered when `l=` is honoured.
    ///
    /// Partial coverage is weaker than a full-body pass and must remain visible.
    unsigned_body_bytes: u64 = 0,
    /// Testing mode: `t=y` in key record. NOT folded into `result` (RFC 6376 §3.6.1:
    /// must not treat testing messages differently, but MAY track for signer assistance).
    /// Reported separately so DMARC alignment (audit A-12) does not apply testing passes.
    testing: bool = false,
};

/// Verify a single DKIM-Signature against the message headers and body.
///
/// Steps (RFC 6376 §6.1):
/// 1. Parse DKIM-Signature tag-value list
/// 2. DNS lookup: selector._domainkey.domain TXT
/// 3. Parse DNS key record, extract public key
/// 4. Canonicalize and hash the body as *this* signature specifies
/// 5. Compare body hash with bh= tag value
/// 6. Reconstruct signed header block (canonicalized headers per h= list)
/// 7. Verify signature over the header block
///
/// Takes raw body, not a precomputed hash: each signature's `c=` and `l=` may
/// require different canonicalization and coverage.
///
/// `min_key_bits` is the smallest RSA modulus this verifier will accept, already
/// reconciled with the RFC 8301 floor by `crypto.resolveMinRsaBits`. It is a
/// parameter rather than a constant so an operator can tighten it past the RFC.
///
/// `max_key_records` bounds how many TXT records at the selector we are willing
/// to try (audit D-20). See `DEFAULT_MAX_KEY_RECORDS`.
pub const Request = struct {
    /// The DKIM-Signature field's **value** — everything after the colon, with
    /// the leading space already resolved per `Header.had_space` (D-23). This is
    /// what gets parsed as a tag-value list.
    sig_header_value: []const u8,
    /// The **whole field** as it arrived, name and colon included, rendered from
    /// the same `Header` (D-23). This is what gets canonicalized into the signed
    /// data, because a signature covers its own field.
    ///
    /// Transposing `sig_header_value` and `sig_header_raw` is caught by conformance
    /// (RFC 6376 drops from 26/26 to 4/26: `permerror`, `malformed signature`). This is
    /// a readability fix (nine positional arguments become legible), not a silent-defect
    /// guard; `worker.Options` is the case where transposition produced silent failure.
    sig_header_raw: []const u8,
    /// Every header field of the message, in arrival order, as the milter saw
    /// them. `h=` selects from these; it does not get to reorder them.
    headers: []const []const u8,
    /// The raw body. Not a hash — see the note above on why.
    body: []const u8,
    /// Already reconciled with the RFC 8301 floor by `crypto.resolveMinRsaBits`.
    min_key_bits: u32,
    /// Whether to honour `l=` or refuse the signature outright.
    body_length_policy: BodyLengthPolicy,
    /// TXT records to try at the selector (D-20). `DEFAULT_MAX_KEY_RECORDS` is
    /// the value config falls back to, not a value this struct supplies.
    max_key_records: u8,

    // No defaults: each is an operator policy read from config. A default here
    // would only be reached by a caller that forgot it (audit L-2: `MaxConnections`
    // honoured by one daemon, silently replaced by three others). Required fields
    // prevent regression.
};

pub fn verifySignature(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    req: Request,
) VerifyResult {
    // Apply the discovered `t=y` flag once so every post-key verdict carries it.
    var key_testing = false;
    var result = verifySignatureInner(allocator, resolver, req, &key_testing);
    result.testing = key_testing;
    return result;
}

/// Key records to try at one selector (audit D-20).
///
/// RFC 6376 §6.1.2 permits cycling during key rotation; the bound limits
/// attacker-controlled public-key verification work.
pub const DEFAULT_MAX_KEY_RECORDS: u8 = 3;

/// Ceiling on the configured value, so the cap cannot itself become the amplifier.
const MAX_KEY_RECORDS_CEILING: usize = 8;

/// Why this key record cannot be used for this signature, or null if it can.
///
/// Every one of these is a property of the *record*, so it decides only whether
/// this record is a candidate -- with several published, one being unusable says
/// nothing about the others. Ordered as RFC 6376 §6.1.2 orders them, so a record
/// tripping more than one reports what another implementation would report.
fn keyRecordRejection(
    rec: *const dkim.PublicKeyRecord,
    sig: *const dkim.Signature,
) ?[]const u8 {
    // Empty p= is a revoked key (RFC 6376 §3.6.1).
    if (rec.public_key.len == 0) return "key revoked";

    if (!keyTypeMatchesAlgorithm(rec.key_type, sig.algorithm)) return "key type mismatch";

    // D-11: `s=`, `h=` and `t=` were parsed into the record from the start and
    // then never consulted, so a key restricted by its owner verified exactly as
    // though it were unrestricted. Each is a MUST on the verifier, and each is a
    // restriction the *signer* asked for, which is why the answer is permerror
    // (the key is inapplicable) rather than fail (the signature is bad).

    // §3.6.1: "Verifiers for a given service type MUST ignore this record if the
    // appropriate type is not listed." We are unambiguously the email service.
    if (!dkim.keyAllowsEmailService(rec))
        return "key not valid for the email service (s=)";

    // §6.1.2 step 6, verbatim: "the Verifier MUST ignore the key record and return
    // PERMFAIL (inappropriate hash algorithm)".
    if (!dkim.keyAllowsHashAlgorithm(rec, sig.algorithm))
        return "hash algorithm not permitted by the key record (h=)";

    // §3.6.1 `t=s`: the `i=` domain "MUST NOT be a subdomain of 'd='". This is the
    // flag's entire purpose -- a domain sets it precisely to stop a signature
    // claiming an identity below the signing domain -- so ignoring it silently
    // granted every subdomain identity the operator had asked us to refuse.
    if (dkim.keyHasFlag(rec, "s") and !dkim.auidSatisfiesStrictFlag(sig))
        return "i= is not exactly d= and the key record sets t=s";

    return null;
}

/// Either a step's value, or the verdict that ends verification here.
///
/// RFC 6376 §6.1 is a sequence of steps and most of them can terminate the whole
/// procedure with a specific result. An error union cannot express that: the
/// domain, the selector and the reason string are all part of the answer, and
/// `VerifyResult` is what the caller needs. So each step returns one of these and
/// `verifySignatureInner` unwraps it -- the same value-or-early-return shape
/// stage 3.2 gave `doSeal`'s `cv=` decision.
fn StepResult(comptime T: type) type {
    return union(enum) {
        ok: T,
        reject: VerifyResult,
    };
}

/// The usable key records at one selector, in the order DNS returned them.
///
/// BORROWED, NOT OWNED. `parsePublicKeyRecord` slices its fields straight out of
/// the TXT record text, so every record here points into the `dns` result the
/// caller is still holding. That is precisely why the DNS lookup stays in
/// `verifySignatureInner` and only the collection loop moved out: putting
/// `resolve` in `collectKeyRecords` too would run its `deinit` on return and
/// leave every one of these dangling.
const Candidates = struct {
    records: [MAX_KEY_RECORDS_CEILING]dkim.PublicKeyRecord,
    usable: usize,
};

/// Step 1: parse the signature, and reject what cannot be evaluated at all.
fn parseAndValidate(sig_header_value: []const u8) StepResult(dkim.Signature) {
    // Step 1: Parse the DKIM-Signature. Every outcome is permerror -- we could not
    // evaluate this signature, which is not the claim `fail` makes -- but the reasons
    // have different causes and different fixes, and one "malformed" for all of them
    // leaves a postmaster to work out which by hand (audit D-6, D-14, D-17).
    const sig = dkim.parseSignature(sig_header_value) catch |err| {
        const reason: []const u8 = switch (err) {
            error.DuplicateTagName => "duplicate tag in signature (RFC 6376 3.2)",
            error.InvalidCanonicalization => "unsupported c= canonicalization (RFC 6376 6.1.1)",
            error.UnsupportedAlgorithm => "unsupported a= algorithm",
            error.TooManyTags => "signature carries too many tags",
            else => "malformed signature",
        };
        return .{ .reject = .{ .result = .permerror, .domain = "", .selector = "", .reason = reason } };
    };

    // Validate required fields for verification
    dkim.validateForVerification(&sig) catch
        return .{ .reject = .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "missing b= or bh=" } };

    // RFC 6376 §5.4: the From field MUST be signed, and §6.1.1 requires
    // PERMFAIL when h= omits it. Otherwise a captured signature keeps
    // verifying while the From header is rewritten at will — arbitrary
    // sender spoofing, and a DMARC pass whenever d= aligns.
    if (!signsFrom(sig.signed_headers))
        return .{ .reject = .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "from not signed" } };

    // RFC 6376 §3.5: x= is an absolute expiry and MUST be greater than t=.
    // Without this check a captured signed message replays forever.
    if (sig.expiration) |expiry| {
        if (sig.timestamp) |signed_at| {
            if (expiry <= signed_at)
                return .{ .reject = .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "expiration precedes timestamp" } };
        }
        if (isExpired(expiry))
            return .{ .reject = .{ .result = .fail, .domain = sig.domain, .selector = sig.selector, .reason = "signature expired" } };
    }

    return .{ .ok = sig };
}

/// Step 3: collect the usable key records at this selector (audit D-20).
///
/// The caller owns the DNS result these borrow from; see `Candidates`.
fn collectKeyRecords(
    dns_result: *const dns_mod.resolver.Result,
    sig: *const dkim.Signature,
    cap: usize,
) StepResult(Candidates) {
    // A rotation publishes the old and the new record together, and RFC 6376
    // §3.6.2.2 leaves the RRset order undefined, so taking only the first meant
    // whichever key DNS happened to list second could not verify anything. §6.1.2
    // step 4 permits cycling explicitly.
    //
    // Only the record-level checks happen here. Everything between this and the
    // signature check is identical for every record -- the body hash in
    // particular -- so it is computed once, outside this loop. Repeating it per
    // record would let whoever publishes the zone multiply our per-signature
    // hashing by the number of records they choose to publish, which is the same
    // work D-4 exists to bound.
    var out = Candidates{ .records = undefined, .usable = 0 };
    var seen: usize = 0;
    var first_rejection: ?[]const u8 = null;

    var txt_iter = dns_result.txtRecords();
    while (txt_iter.next()) |key_txt| {
        if (seen >= cap) break;
        seen += 1;

        const rec = dkim.parsePublicKeyRecord(key_txt) catch {
            if (first_rejection == null) first_rejection = "malformed key record";
            continue;
        };
        if (keyRecordRejection(&rec, sig)) |reason| {
            if (first_rejection == null) first_rejection = reason;
            continue;
        }
        out.records[out.usable] = rec;
        out.usable += 1;
    }

    if (seen == 0)
        return .{ .reject = .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "no TXT record" } };

    // Every record published here is unusable. Reporting the first one's reason
    // keeps a single-record zone -- overwhelmingly the common case -- answering
    // exactly what it answered before cycling existed.
    if (out.usable == 0)
        return .{ .reject = .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = first_rejection.? } };

    return .{ .ok = out };
}

/// Steps 4 and 5: hash the body as *this* signature specifies, and compare `bh=`.
///
/// Yields the count of canonicalized body octets the signature does not cover,
/// which is non-zero only for an `l=` that is being honoured.
fn checkBodyHash(
    allocator: Allocator,
    body: []const u8,
    sig: *const dkim.Signature,
    body_length_policy: BodyLengthPolicy,
) StepResult(u64) {
    // RFC 6376 §8.2 lets a verifier decline `l=` outright, and an operator may
    // prefer that to accepting a body whose tail nobody signed. Checked before
    // any hashing so a refused signature costs nothing.
    if (sig.body_length != null and body_length_policy == .refuse)
        return .{ .reject = .{ .result = .policy, .domain = sig.domain, .selector = sig.selector, .reason = "l= body length limit refused by policy" } };

    // Step 4-5: Verify body hash, canonicalized and bounded as *this* signature
    // asks rather than as the caller guessed.
    const body_result = computeBodyHash(allocator, body, sig.canonicalization.body, sig.body_length) catch |err| switch (err) {
        // RFC 6376 §3.5: l= "MUST NOT be larger than the actual number of octets
        // in the canonicalized message body". A signature claiming to cover more
        // body than exists is malformed, and honouring it would mean hashing
        // whatever happened to be in memory past the end.
        error.BodyLengthExceedsBody => return .{ .reject = .{
            .result = .permerror,
            .domain = sig.domain,
            .selector = sig.selector,
            .reason = "l= exceeds the canonicalized body length",
        } },
        error.OutOfMemory => return .{ .reject = .{
            .result = .temperror,
            .domain = sig.domain,
            .selector = sig.selector,
            .reason = "body canonicalization failed",
        } },
    };

    // Bound to a name so it can be freed. Nesting this call inside
    // `base64Decode` leaked it on every signature verified: `conn.allocator` is
    // the worker's allocator, not a per-message arena, so nothing reclaimed it
    // when the message ended and a busy daemon grew without limit. The b= path,
    // now in `verifySignatureInner`, always had the `defer`; only this one was
    // missed.
    const bh_stripped = dkim.stripWhitespace(allocator, sig.body_hash) catch
        return .{ .reject = .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid bh= encoding" } };
    defer allocator.free(bh_stripped);

    const bh_decoded = crypto.base64Decode(allocator, bh_stripped) catch
        return .{ .reject = .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid bh= base64" } };
    defer allocator.free(bh_decoded);

    if (bh_decoded.len != 32 or !mem.eql(u8, bh_decoded, &body_result.hash))
        return .{ .reject = .{ .result = .fail, .domain = sig.domain, .selector = sig.selector, .reason = "body hash mismatch" } };

    return .{ .ok = body_result.unsigned_bytes };
}

/// Step 8: try the candidate records against this one signed-data block (D-20).
///
/// REQUIRES A NON-EMPTY `records`, and returns `failure.?` on the strength of it.
/// `collectKeyRecords` guarantees it by rejecting `usable == 0` with its own
/// verdict; that invariant used to be three statements up in the same function
/// and now crosses a boundary, so it is stated rather than left to be noticed.
fn tryKeyRecords(
    allocator: Allocator,
    sig: *const dkim.Signature,
    records: []const dkim.PublicKeyRecord,
    signed_data: []const u8,
    sig_decoded: []const u8,
    min_key_bits: u32,
    unsigned_bytes: u64,
    testing_out: *bool,
) VerifyResult {
    // Everything before this is key-independent and has already been done once;
    // all that repeats here is the public-key operation itself, which is
    // irreducible -- deciding whether a key verifies a signature is the question.
    //
    // The first record that verifies wins and returns immediately, so the common
    // single-record case costs exactly one verification, and a rotation costs one
    // extra only when the first record tried is the wrong half of the pair.
    var failure: ?VerifyResult = null;
    var failure_testing: bool = false;

    for (records) |rec| {
        const verified = verifyWithKey(allocator, sig.algorithm, rec, signed_data, sig_decoded, min_key_bits) catch |err| {
            // RFC 8301 §3.2: a signature made with an RSA key below the floor "has
            // permanently failed evaluation", which is PERMFAIL — the same class as
            // a malformed key record, not a signature mismatch. Reported with its
            // own reason because "crypto verify error" would send an operator
            // hunting a canonicalization bug instead of telling the signer to
            // rotate to a 2048-bit key.
            const reason: []const u8 = switch (err) {
                error.RsaKeyTooSmall => "key too small",
                error.NotRsaPublicKey => "p= is not an RSA key",
                error.InvalidPublicKey => "unusable public key",
                else => "crypto verify error",
            };
            if (failure == null) {
                failure = .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = reason };
                failure_testing = dkim.keyHasFlag(&rec, "y");
            }
            continue;
        };

        if (verified) {
            // Re-taken from the record that actually carried the verdict, which
            // need not be the one the provisional flag came from.
            testing_out.* = dkim.keyHasFlag(&rec, "y");
            return .{
                .result = .pass,
                .domain = sig.domain,
                .selector = sig.selector,
                // Carried up so a partial pass can be reported as one.
                .unsigned_body_bytes = unsigned_bytes,
            };
        }

        // A key that simply did not match. Held rather than returned: a later
        // record may still verify, and until they have all been tried "this
        // signature does not verify" is not yet a fact.
        if (failure == null) {
            failure = .{ .result = .fail, .domain = sig.domain, .selector = sig.selector, .reason = "signature mismatch" };
            failure_testing = dkim.keyHasFlag(&rec, "y");
        }
    }

    testing_out.* = failure_testing;
    return failure.?;
}

/// The RFC 6376 §6.1 procedure, one named step at a time.
///
/// The steps are the numbered ones in the RFC and they read in order here. The
/// DNS lookup is the one piece that did not move into a step of its own: the key
/// records borrow from its result, so it has to outlive them (see `Candidates`).
fn verifySignatureInner(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    req: Request,
    testing_out: *bool,
) VerifyResult {
    const sig = switch (parseAndValidate(req.sig_header_value)) {
        .reject => |verdict| return verdict,
        .ok => |parsed| parsed,
    };

    // Step 2: DNS lookup for public key
    const dns_name = buildKeyDomain(allocator, sig.selector, sig.domain) catch
        return .{ .result = .temperror, .domain = sig.domain, .selector = sig.selector, .reason = "alloc failure" };
    defer allocator.free(dns_name);

    // RFC 6376 §6.1.2 splits these two deliberately, and in opposite
    // directions. Step 3: if the query fails "because the corresponding key
    // record does not exist", the Verifier "MUST immediately return PERMFAIL
    // (no key for signature)" — the signature can never verify, so deferring it
    // means retrying a message that will fail every time. Step 2: a query that
    // "fails to respond" only MAY return TEMPFAIL, which is the right answer
    // when the nameserver is merely unreachable.
    //
    // Collapsing both into temperror also disagreed with the empty-answer case,
    // which already returned permerror.
    var dns_result = resolver.resolve(dns_name, .TXT) catch |err| {
        if (dns_mod.isTransientError(err)) {
            return .{ .result = .temperror, .domain = sig.domain, .selector = sig.selector, .reason = "DNS lookup failed" };
        }
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "no key record for selector" };
    };
    defer dns_result.deinit();

    const cap = @min(@as(usize, req.max_key_records), MAX_KEY_RECORDS_CEILING);
    const candidates = switch (collectKeyRecords(&dns_result, &sig, cap)) {
        .reject => |verdict| return verdict,
        .ok => |found| found,
    };

    // §3.6.1 `t=y`: recorded, never acted on here. See `VerifyResult.testing`.
    // Set before any of the remaining verdicts so all of them carry it, including
    // the failures -- the MUST covers a testing key "even should the signature fail
    // to verify", so a `fail` from a testing key must be as inert as a `pass`.
    // Provisional until a record actually verifies, at which point the flag is
    // re-taken from *that* record: with several published they need not agree, and
    // the one that matters is the one the verdict rests on.
    testing_out.* = dkim.keyHasFlag(&candidates.records[0], "y");

    const unsigned_bytes = switch (checkBodyHash(allocator, req.body, &sig, req.body_length_policy)) {
        .reject => |verdict| return verdict,
        .ok => |uncovered| uncovered,
    };

    // Step 6: Build the signed data block (canonicalized headers + DKIM-Signature with empty b=)
    const signed_data = buildSignedData(allocator, sig, req.sig_header_raw, req.headers) catch
        return .{ .result = .temperror, .domain = sig.domain, .selector = sig.selector, .reason = "canonicalization failed" };
    defer allocator.free(signed_data);

    // Step 7: Decode signature and verify
    const sig_decoded_ws = dkim.stripWhitespace(allocator, sig.signature) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid b= encoding" };
    defer allocator.free(sig_decoded_ws);

    const sig_decoded = crypto.base64Decode(allocator, sig_decoded_ws) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid b= base64" };
    defer allocator.free(sig_decoded);

    return tryKeyRecords(
        allocator,
        &sig,
        candidates.records[0..candidates.usable],
        signed_data,
        sig_decoded,
        req.min_key_bits,
        unsigned_bytes,
        testing_out,
    );
}

/// A body hash together with how much of the body it left uncovered.
const BodyHashResult = struct {
    hash: [32]u8,
    unsigned_bytes: u64,
};

/// Canonicalize the body per `algorithm`, bound it per `body_length`, and hash it.
///
/// `body_length` is the `l=` tag: the count of octets **of the canonicalized
/// body** that the signature covers (RFC 6376 §3.5), so the bound is applied after
/// canonicalization and never before. Getting that order wrong would matter for
/// exactly the messages `l=` exists to serve, since relaxed canonicalization
/// changes the body's length.
fn computeBodyHash(
    allocator: Allocator,
    body: []const u8,
    algorithm: canon.Algorithm,
    body_length: ?u64,
) error{ OutOfMemory, BodyLengthExceedsBody }!BodyHashResult {
    var bc = canon.BodyCanonicalizer.init(allocator, algorithm);
    defer bc.deinit();
    try bc.update(body);
    const canonicalized = try bc.finish();
    defer allocator.free(canonicalized);

    const limit = body_length orelse
        return .{ .hash = crypto.sha256(canonicalized), .unsigned_bytes = 0 };

    // RFC 6376 §3.5 forbids l= from exceeding the canonicalized body length. The
    // comparison is done in u64 before any narrowing cast, because the tag is
    // specified as up to 76 digits and the RFC asks implementers explicitly to
    // "test for integer overflow when decoding the value".
    if (limit > canonicalized.len) return error.BodyLengthExceedsBody;

    const covered: usize = @intCast(limit);
    return .{
        .hash = crypto.sha256(canonicalized[0..covered]),
        .unsigned_bytes = canonicalized.len - covered,
    };
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Build the DNS name for key lookup: selector._domainkey.domain
fn buildKeyDomain(allocator: Allocator, selector: []const u8, domain: []const u8) ![]u8 {
    const total_len = selector.len + "._domainkey.".len + domain.len;
    var buf = try allocator.alloc(u8, total_len);
    var pos: usize = 0;
    @memcpy(buf[pos..][0..selector.len], selector);
    pos += selector.len;
    @memcpy(buf[pos..][0.."._domainkey.".len], "._domainkey.");
    pos += "._domainkey.".len;
    @memcpy(buf[pos..][0..domain.len], domain);
    return buf;
}

/// True if the `h=` list covers the From field (RFC 6376 §5.4).
fn signsFrom(signed_headers: []const u8) bool {
    var iter = mem.splitScalar(u8, signed_headers, ':');
    while (iter.next()) |field| {
        const trimmed = mem.trim(u8, field, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(trimmed, "from")) return true;
    }
    return false;
}

/// True if the signature's `x=` expiry has passed.
///
/// RFC 6376 §3.5 prefers the time the message was first received inside the
/// verifier's ADMD; the milter runs during that reception, so the current
/// time is that value. No skew is allowed: the signer chose the deadline.
fn isExpired(expiry: u64) bool {
    const now = std.time.timestamp();
    if (now <= 0) return false; // unusable clock: do not fail on it
    return @as(u64, @intCast(now)) >= expiry;
}

/// Check if key type (from DNS record) is compatible with the signature algorithm.
fn keyTypeMatchesAlgorithm(key_type: []const u8, algorithm: dkim.Algorithm) bool {
    return switch (algorithm) {
        .rsa_sha256 => mem.eql(u8, key_type, "rsa"),
        .ed25519_sha256 => mem.eql(u8, key_type, "ed25519"),
    };
}

/// Build the data block that was signed: canonicalized headers per h= list,
/// followed by the DKIM-Signature header with b= value emptied.
fn buildSignedData(
    allocator: Allocator,
    sig: dkim.Signature,
    sig_header_raw: []const u8,
    headers: []const []const u8,
) ![]u8 {
    var data: std.ArrayList(u8) = .{};
    errdefer data.deinit(allocator);

    // Each `h=` entry selects one header instance, walking up from the bottom
    // when a name is repeated, and selecting nothing once the instances run out
    // (RFC 6376 §5.4.2 and §3.7). This used to resolve every mention to the same
    // bottom-most header, so an oversigned message -- `h=from:from` over one
    // `From:`, which is what OpenDKIM's `OversignHeaders` produces -- hashed that
    // header twice where its signer hashed it once, and failed (audit D-1).
    var walk = header_select.lineWalker(sig.signed_headers, headers);
    while (walk.next()) |header| {
        const canonicalized = try canon.canonicalizeHeader(allocator, sig.canonicalization.header, header);
        defer allocator.free(canonicalized);
        try data.appendSlice(allocator, canonicalized);
        try data.appendSlice(allocator, "\r\n");
    }

    // Append the DKIM-Signature header itself with b= value emptied
    const dkim_header_cleaned = try sig_header.emptyBValue(allocator, sig_header_raw);
    defer allocator.free(dkim_header_cleaned);
    const dkim_canonicalized = try canon.canonicalizeHeader(allocator, sig.canonicalization.header, dkim_header_cleaned);
    defer allocator.free(dkim_canonicalized);
    // No trailing CRLF for the DKIM-Signature header (RFC 6376 §3.7)
    try data.appendSlice(allocator, dkim_canonicalized);

    return data.toOwnedSlice(allocator);
}

/// Find the bottom-most header with this field name, or null.
///
/// Only for callers that look up a single field outside the `h=` walk. Anything
/// resolving an `h=` entry must go through `header_select`, which handles a name
/// appearing more than once; this cannot (audit D-1).
fn findHeader(headers: []const []const u8, field_name: []const u8) ?[]const u8 {
    const idx = header_select.selectInstance(
        []const u8,
        headers,
        header_select.nameOfLine,
        field_name,
        0,
    ) orelse return null;
    return headers[idx];
}

/// Perform the actual cryptographic verification.
fn verifyWithKey(
    allocator: Allocator,
    algorithm: dkim.Algorithm,
    key_record: dkim.PublicKeyRecord,
    signed_data: []const u8,
    signature_bytes: []const u8,
    min_key_bits: u32,
) !bool {
    switch (algorithm) {
        .rsa_sha256 => {
            // Decode the public key from base64 DER
            const pub_key_der = try crypto.base64Decode(allocator, key_record.public_key);
            defer allocator.free(pub_key_der);

            // The size check lives inside the load so it cannot be skipped. Note
            // that the errors are deliberately *not* collapsed into one here:
            // the caller distinguishes an undersized key from an unparseable
            // one, and squashing them was how the old code lost that.
            const evp_pkey = crypto.loadRsaPublicKeyDer(pub_key_der, min_key_bits, null) catch |err| switch (err) {
                error.RsaKeyTooSmall, error.NotRsaPublicKey => return err,
                else => return error.InvalidPublicKey,
            };
            defer crypto.freePublicKey(evp_pkey);

            return crypto.rsaVerify(evp_pkey, signed_data, signature_bytes);
        },
        .ed25519_sha256 => {
            // Decode the 32-byte public key from base64
            const pub_key_raw = try crypto.base64Decode(allocator, key_record.public_key);
            defer allocator.free(pub_key_raw);

            if (pub_key_raw.len != 32) return error.InvalidPublicKey;
            if (signature_bytes.len != 64) return error.InvalidSignature;

            var pub_key: [32]u8 = undefined;
            @memcpy(&pub_key, pub_key_raw[0..32]);
            var sig_bytes: [64]u8 = undefined;
            @memcpy(&sig_bytes, signature_bytes[0..64]);

            // `signed_data` is the canonicalized signing input. RFC 8463 §3
            // signs the SHA-256 digest of it, and that hashing happens inside
            // `ed25519Sha256Verify` -- see its doc comment for why it is not
            // done here.
            return crypto.ed25519Sha256Verify(pub_key, signed_data, sig_bytes);
        },
    }
}

// =============================================================================
// Tests
// =============================================================================

test "build key domain" {
    const allocator = std.testing.allocator;
    const result = try buildKeyDomain(allocator, "sel2026", "example.com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("sel2026._domainkey.example.com", result);
}

test "key type matches algorithm" {
    try std.testing.expect(keyTypeMatchesAlgorithm("rsa", .rsa_sha256));
    try std.testing.expect(keyTypeMatchesAlgorithm("ed25519", .ed25519_sha256));
    try std.testing.expect(!keyTypeMatchesAlgorithm("rsa", .ed25519_sha256));
    try std.testing.expect(!keyTypeMatchesAlgorithm("ed25519", .rsa_sha256));
}

test "find header case insensitive reverse order" {
    const headers = &[_][]const u8{
        "From: first@example.com",
        "Subject: Hello",
        "From: second@example.com",
    };
    // Should find the LAST (bottom) "From" header
    const found = findHeader(headers, "from").?;
    try std.testing.expectEqualStrings("From: second@example.com", found);

    // Case insensitive match
    const subj = findHeader(headers, "SUBJECT").?;
    try std.testing.expectEqualStrings("Subject: Hello", subj);

    // Not found
    try std.testing.expect(findHeader(headers, "Date") == null);
}

// --- CRITICAL-2 / D-5: the body hash belongs to the signature ------------------

test "body canonicalization follows the signature, not a fixed choice" {
    // A body whose two canonicalizations differ: a line with trailing spaces and
    // a run of internal spaces. Plain one-line bodies canonicalize identically
    // under both algorithms, which is why hardcoding `simple` went unnoticed for
    // so long -- every message the lab ever verified had one.
    const allocator = std.testing.allocator;
    const body = "Trailing spaces here.   \r\nInternal    run.\r\n";

    const as_simple = try computeBodyHash(allocator, body, .simple, null);
    const as_relaxed = try computeBodyHash(allocator, body, .relaxed, null);

    try std.testing.expect(!mem.eql(u8, &as_simple.hash, &as_relaxed.hash));
    // Neither leaves anything uncovered when there is no l= tag.
    try std.testing.expectEqual(@as(u64, 0), as_simple.unsigned_bytes);
    try std.testing.expectEqual(@as(u64, 0), as_relaxed.unsigned_bytes);
}

test "l= hashes only the covered prefix, and reports the rest as unsigned" {
    const allocator = std.testing.allocator;
    // Simple canonicalization leaves this body's 14 octets alone: it already ends
    // in CRLF and has no trailing empty lines.
    const body = "Hello world.\r\n";

    const bounded = try computeBodyHash(allocator, body, .simple, 6);

    // Compared against the hash of the exact octets, not against another call to
    // this function on a shorter body -- canonicalization would append a CRLF to
    // a body that lacks one, so those are different operations.
    const expected = crypto.sha256("Hello ");
    try std.testing.expectEqualSlices(u8, &expected, &bounded.hash);
    try std.testing.expectEqual(@as(u64, 8), bounded.unsigned_bytes);
}

test "l= is counted after canonicalization, not before" {
    const allocator = std.testing.allocator;
    // Relaxed canonicalization collapses the run of spaces, so "a    b c\r\n"
    // becomes "a b c\r\n" -- 7 octets where the raw body had 10. An l= of 5 must
    // therefore cover "a b c", which is only true if the bound is applied to the
    // canonicalized stream. Applied to the raw body it would cover "a    ".
    const body = "a    b c\r\n";

    const bounded = try computeBodyHash(allocator, body, .relaxed, 5);

    const expected = crypto.sha256("a b c");
    try std.testing.expectEqualSlices(u8, &expected, &bounded.hash);
    try std.testing.expectEqual(@as(u64, 2), bounded.unsigned_bytes);
}

test "an l= larger than the body is a malformed signature" {
    // RFC 6376 §3.5: the value "MUST NOT be larger than the actual number of
    // octets in the canonicalized message body". Honouring it anyway would mean
    // hashing past the end of the buffer.
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.BodyLengthExceedsBody,
        computeBodyHash(allocator, "short\r\n", .simple, 999),
    );
}

test "an l= of exactly the body length covers everything" {
    const allocator = std.testing.allocator;
    const body = "Hello world.\r\n";

    const bounded = try computeBodyHash(allocator, body, .simple, body.len);
    const whole = try computeBodyHash(allocator, body, .simple, null);

    try std.testing.expectEqualSlices(u8, &whole.hash, &bounded.hash);
    try std.testing.expectEqual(@as(u64, 0), bounded.unsigned_bytes);
}

test "an l= of zero covers nothing at all" {
    // Legal, and worth pinning: the signature vouches for no body content
    // whatsoever, so the whole body is reported unsigned and the hash is the hash
    // of nothing.
    const allocator = std.testing.allocator;
    const body = "Hello world.\r\n";

    const bounded = try computeBodyHash(allocator, body, .simple, 0);

    const expected = crypto.sha256("");
    try std.testing.expectEqualSlices(u8, &expected, &bounded.hash);
    try std.testing.expectEqual(@as(u64, body.len), bounded.unsigned_bytes);
}

test "signed data matches an independent implementation, octet for octet" {
    // Captured from a message signed by dkimpy and delivered through the lab.
    // Everything about it is ordinary for real-world mail and absent from what
    // this suite's own signer emits: the signature is folded across six lines,
    // `h=` puts FWS around its colons, `from` is oversigned, and the header
    // canonicalization is relaxed rather than simple. The expectation below is
    // the exact octet string dkimpy hashes, not a string derived from this
    // implementation, so it checks agreement rather than self-consistency.
    const allocator = std.testing.allocator;

    const sig_value =
        " v=1; a=rsa-sha256; c=relaxed/simple; d=bambania.com;\r\n" ++
        " i=@bambania.com; q=dns/txt; s=test2026; t=1785285565; h=from : to :\r\n" ++
        " subject : date : message-id : from;\r\n" ++
        " bh=7Ef6s0nbzmxhseHpy+mgQFOhB4d3J6cgEWkp4fKGZEs=;\r\n" ++
        " b=PjWT1Bg9naGgw2RiJiEJjnmoJEp8ICB2FrKGqlsxqm5GjzFujPZNHBC76YTUZHr6oufLp\r\n" ++
        " J1Gz8dQl5NXqKP/qLxD3vGpWt8+OK0gfJaGcy236HVZPyU9TE0v0Wqui8o+PXnBLbepb5rN\r\n" ++
        " 0VvnaGlSL6JrtG4G6Hf4pwj9ruhc+LQZBzJ1qv9wwcRFRzG4MK4WZ+XBu6i07NQtH9hmW1c\r\n" ++
        " A+tei/JClENqLJuSA+sys2pwDoKpPQWq+0c3FGG2wIjR19Qria4ZHoArSgCLq7DMZryA72B\r\n" ++
        " TS0DaEJJlvWoLoGKv5/R942NT+nDQH/6dlL6sP5ycfgTWuq4J6+k9Ean5MAQ==";

    const sig = try dkim.parseSignature(sig_value);

    const sig_header_raw = "DKIM-Signature:" ++ sig_value;
    const headers = [_][]const u8{
        "From: boss@bambania.com",
        "To: testuser@example.org",
        "Subject: probe-relaxed-simple",
        "Date: Tue, 28 Jul 2026 20:00:00 -0400",
        "Message-ID: <probe-relaxed-simple@probe.pentest>",
    };

    const got = try buildSignedData(allocator, sig, sig_header_raw, &headers);
    defer allocator.free(got);

    // Five header lines, not six: `from` is named twice but the message carries
    // one From, so the second mention selects nothing (RFC 6376 §3.7). The
    // signature line is unfolded, its b= emptied, and carries no trailing CRLF.
    const expected =
        "from:boss@bambania.com\r\n" ++
        "to:testuser@example.org\r\n" ++
        "subject:probe-relaxed-simple\r\n" ++
        "date:Tue, 28 Jul 2026 20:00:00 -0400\r\n" ++
        "message-id:<probe-relaxed-simple@probe.pentest>\r\n" ++
        "dkim-signature:v=1; a=rsa-sha256; c=relaxed/simple; d=bambania.com;" ++
        " i=@bambania.com; q=dns/txt; s=test2026; t=1785285565;" ++
        " h=from : to : subject : date : message-id : from;" ++
        " bh=7Ef6s0nbzmxhseHpy+mgQFOhB4d3J6cgEWkp4fKGZEs=; b=";

    try std.testing.expectEqualStrings(expected, got);
}

test "signs from" {
    try std.testing.expect(signsFrom("from:to:subject:date:message-id"));
    try std.testing.expect(signsFrom("To : From : Subject"));
    try std.testing.expect(signsFrom("FROM"));
    // The bypass this guards: a valid signature that never covers From.
    try std.testing.expect(!signsFrom("to:subject:date:message-id"));
    try std.testing.expect(!signsFrom(""));
    // A field merely containing "from" is not the From field.
    try std.testing.expect(!signsFrom("x-from:resent-from"));
}

test "is expired" {
    const now: u64 = @intCast(std.time.timestamp());
    try std.testing.expect(isExpired(1_000_000_000)); // 2001-09-09
    try std.testing.expect(isExpired(now));
    try std.testing.expect(!isExpired(now + 3600));
}

test "eql ignore case" {
    try std.testing.expect(std.ascii.eqlIgnoreCase("From", "from"));
    try std.testing.expect(std.ascii.eqlIgnoreCase("SUBJECT", "Subject"));
    try std.testing.expect(!std.ascii.eqlIgnoreCase("From", "To"));
    try std.testing.expect(!std.ascii.eqlIgnoreCase("ab", "abc"));
}
