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
    /// RFC 8601 §2.7.1: "the message was signed but the signature or signatures
    /// were not acceptable to the verifier". Distinct from `fail`, which asserts
    /// the signature did not validate: `policy` says this verifier declined to
    /// evaluate a signature that might well be good. Used when a signature
    /// carries `l=` and the operator has chosen to refuse those.
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
    /// Octets of the canonicalized body this signature does not cover, which is
    /// non-zero only when the signature carries `l=` and it is being honoured.
    ///
    /// Reported because `pass` over part of a body is a weaker claim than `pass`
    /// over all of it, and nothing downstream can tell the difference otherwise.
    /// RFC 6376 §8.2: appended content "to completely replace the original
    /// content in the end recipient's eyes" is the attack this enables.
    unsigned_body_bytes: u64 = 0,
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
/// Takes the raw body rather than a hash of it. The body hash is not a property
/// of the message: `c=` chooses the canonicalization and `l=` chooses how much of
/// the body is covered, both per signature, and one message may carry several
/// signatures that disagree on both. A hash computed once by the caller can only
/// be right for signatures that happen to share the caller's assumptions -- which
/// is how this daemon came to hash every body with `simple` canonicalization no
/// matter what the signature asked for, and so could not verify the near-universal
/// `c=relaxed/relaxed`.
///
/// `min_key_bits` is the smallest RSA modulus this verifier will accept, already
/// reconciled with the RFC 8301 floor by `crypto.resolveMinRsaBits`. It is a
/// parameter rather than a constant so an operator can tighten it past the RFC.
pub fn verifySignature(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    sig_header_value: []const u8,
    sig_header_raw: []const u8,
    headers: []const []const u8,
    body: []const u8,
    min_key_bits: u32,
    body_length_policy: BodyLengthPolicy,
) VerifyResult {
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
        return .{ .result = .permerror, .domain = "", .selector = "", .reason = reason };
    };

    // Validate required fields for verification
    dkim.validateForVerification(&sig) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "missing b= or bh=" };

    // RFC 6376 §5.4: the From field MUST be signed, and §6.1.1 requires
    // PERMFAIL when h= omits it. Otherwise a captured signature keeps
    // verifying while the From header is rewritten at will — arbitrary
    // sender spoofing, and a DMARC pass whenever d= aligns.
    if (!signsFrom(sig.signed_headers))
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "from not signed" };

    // RFC 6376 §3.5: x= is an absolute expiry and MUST be greater than t=.
    // Without this check a captured signed message replays forever.
    if (sig.expiration) |expiry| {
        if (sig.timestamp) |signed_at| {
            if (expiry <= signed_at)
                return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "expiration precedes timestamp" };
        }
        if (isExpired(expiry))
            return .{ .result = .fail, .domain = sig.domain, .selector = sig.selector, .reason = "signature expired" };
    }

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
    // Collapsing both into temperror also disagreed with the empty-answer case
    // immediately below, which already returned permerror.
    var dns_result = resolver.resolve(dns_name, .TXT) catch |err| {
        if (dns_mod.isTransientError(err)) {
            return .{ .result = .temperror, .domain = sig.domain, .selector = sig.selector, .reason = "DNS lookup failed" };
        }
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "no key record for selector" };
    };
    defer dns_result.deinit();

    // Find the key record in TXT results
    var txt_iter = dns_result.txtRecords();
    const key_txt = txt_iter.next() orelse
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "no TXT record" };

    // Step 3: Parse DNS key record
    const key_record = dkim.parsePublicKeyRecord(key_txt) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "malformed key record" };

    // Check for revoked key (empty p=)
    if (key_record.public_key.len == 0)
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "key revoked" };

    // Check key type vs algorithm compatibility
    if (!keyTypeMatchesAlgorithm(key_record.key_type, sig.algorithm))
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "key type mismatch" };

    // RFC 6376 §8.2 lets a verifier decline `l=` outright, and an operator may
    // prefer that to accepting a body whose tail nobody signed. Checked before
    // any hashing so a refused signature costs nothing.
    if (sig.body_length != null and body_length_policy == .refuse)
        return .{ .result = .policy, .domain = sig.domain, .selector = sig.selector, .reason = "l= body length limit refused by policy" };

    // Step 4-5: Verify body hash, canonicalized and bounded as *this* signature
    // asks rather than as the caller guessed.
    const body_result = computeBodyHash(allocator, body, sig.canonicalization.body, sig.body_length) catch |err| switch (err) {
        // RFC 6376 §3.5: l= "MUST NOT be larger than the actual number of octets
        // in the canonicalized message body". A signature claiming to cover more
        // body than exists is malformed, and honouring it would mean hashing
        // whatever happened to be in memory past the end.
        error.BodyLengthExceedsBody => return .{
            .result = .permerror,
            .domain = sig.domain,
            .selector = sig.selector,
            .reason = "l= exceeds the canonicalized body length",
        },
        error.OutOfMemory => return .{
            .result = .temperror,
            .domain = sig.domain,
            .selector = sig.selector,
            .reason = "body canonicalization failed",
        },
    };

    // Bound to a name so it can be freed. Nesting this call inside
    // `base64Decode` leaked it on every signature verified: `conn.allocator` is
    // the worker's allocator, not a per-message arena, so nothing reclaimed it
    // when the message ended and a busy daemon grew without limit. The b= path
    // six lines below always had the `defer`; only this one was missed.
    const bh_stripped = dkim.stripWhitespace(allocator, sig.body_hash) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid bh= encoding" };
    defer allocator.free(bh_stripped);

    const bh_decoded = crypto.base64Decode(allocator, bh_stripped) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid bh= base64" };
    defer allocator.free(bh_decoded);

    if (bh_decoded.len != 32 or !mem.eql(u8, bh_decoded, &body_result.hash))
        return .{ .result = .fail, .domain = sig.domain, .selector = sig.selector, .reason = "body hash mismatch" };

    // Step 6: Build the signed data block (canonicalized headers + DKIM-Signature with empty b=)
    const signed_data = buildSignedData(allocator, sig, sig_header_raw, headers) catch
        return .{ .result = .temperror, .domain = sig.domain, .selector = sig.selector, .reason = "canonicalization failed" };
    defer allocator.free(signed_data);

    // Step 7: Decode signature and verify
    const sig_decoded_ws = dkim.stripWhitespace(allocator, sig.signature) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid b= encoding" };
    defer allocator.free(sig_decoded_ws);

    const sig_decoded = crypto.base64Decode(allocator, sig_decoded_ws) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid b= base64" };
    defer allocator.free(sig_decoded);

    const verified = verifyWithKey(allocator, sig.algorithm, key_record, signed_data, sig_decoded, min_key_bits) catch |err| {
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
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = reason };
    };

    if (verified) {
        return .{
            .result = .pass,
            .domain = sig.domain,
            .selector = sig.selector,
            // Carried up so a partial pass can be reported as one.
            .unsigned_body_bytes = body_result.unsigned_bytes,
        };
    } else {
        return .{ .result = .fail, .domain = sig.domain, .selector = sig.selector, .reason = "signature mismatch" };
    }
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
