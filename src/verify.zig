const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;
const canon = securemilter_crypto.canon;

const dkim = @import("dkim.zig");

/// DKIM verification result per RFC 6376 §6.1.
pub const Result = enum {
    pass,
    fail,
    temperror,
    permerror,
    neutral,
    none,

    pub fn toString(self: Result) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .temperror => "temperror",
            .permerror => "permerror",
            .neutral => "neutral",
            .none => "none",
        };
    }
};

/// Detailed verification result for a single DKIM-Signature.
pub const VerifyResult = struct {
    result: Result,
    domain: []const u8,
    selector: []const u8,
    reason: ?[]const u8 = null,
};

/// Verify a single DKIM-Signature against the message headers and body hash.
///
/// Steps (RFC 6376 §6.1):
/// 1. Parse DKIM-Signature tag-value list
/// 2. DNS lookup: selector._domainkey.domain TXT
/// 3. Parse DNS key record, extract public key
/// 4. Compute body hash (caller provides pre-computed canonicalized body hash)
/// 5. Compare body hash with bh= tag value
/// 6. Reconstruct signed header block (canonicalized headers per h= list)
/// 7. Verify signature over the header block
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
    body_hash: [32]u8,
    min_key_bits: u32,
) VerifyResult {
    // Step 1: Parse the DKIM-Signature
    const sig = dkim.parseSignature(sig_header_value) catch
        return .{ .result = .permerror, .domain = "", .selector = "", .reason = "malformed signature" };

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

    var dns_result = resolver.resolve(dns_name, .TXT) catch
        return .{ .result = .temperror, .domain = sig.domain, .selector = sig.selector, .reason = "DNS lookup failed" };
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

    // Step 4-5: Verify body hash
    const bh_decoded = crypto.base64Decode(allocator, dkim.stripWhitespace(allocator, sig.body_hash) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid bh= encoding" }) catch
        return .{ .result = .permerror, .domain = sig.domain, .selector = sig.selector, .reason = "invalid bh= base64" };
    defer allocator.free(bh_decoded);

    if (bh_decoded.len != 32 or !mem.eql(u8, bh_decoded, &body_hash))
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
        return .{ .result = .pass, .domain = sig.domain, .selector = sig.selector };
    } else {
        return .{ .result = .fail, .domain = sig.domain, .selector = sig.selector, .reason = "signature mismatch" };
    }
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
        if (eqlIgnoreCase(trimmed, "from")) return true;
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

    const header_list = try sig.getSignedHeaderList(allocator);
    defer allocator.free(header_list);

    // For each header in h= list, find it in the message headers and canonicalize
    for (header_list) |field_name| {
        const header = findHeader(headers, field_name) orelse continue;
        const canonicalized = try canon.canonicalizeHeader(allocator, sig.canonicalization.header, header);
        defer allocator.free(canonicalized);
        try data.appendSlice(allocator, canonicalized);
        try data.appendSlice(allocator, "\r\n");
    }

    // Append the DKIM-Signature header itself with b= value emptied
    const dkim_header_cleaned = try emptyBValue(allocator, sig_header_raw);
    defer allocator.free(dkim_header_cleaned);
    const dkim_canonicalized = try canon.canonicalizeHeader(allocator, sig.canonicalization.header, dkim_header_cleaned);
    defer allocator.free(dkim_canonicalized);
    // No trailing CRLF for the DKIM-Signature header (RFC 6376 §3.7)
    try data.appendSlice(allocator, dkim_canonicalized);

    return data.toOwnedSlice(allocator);
}

/// Find a header by field name (case-insensitive), searching from bottom to top
/// (RFC 6376 §5.4: "headers are presented to the algorithm in reverse order").
fn findHeader(headers: []const []const u8, field_name: []const u8) ?[]const u8 {
    var i = headers.len;
    while (i > 0) {
        i -= 1;
        const hdr = headers[i];
        const colon = mem.indexOfScalar(u8, hdr, ':') orelse continue;
        const name = mem.trimRight(u8, hdr[0..colon], " \t");
        if (eqlIgnoreCase(name, field_name)) {
            return hdr;
        }
    }
    return null;
}

/// Case-insensitive string comparison.
fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toLower(ca) != toLower(cb)) return false;
    }
    return true;
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

/// Remove the b= value from a DKIM-Signature header, leaving "b=" intact.
/// This is needed for signature verification: the signed data includes the
/// DKIM-Signature header with b= tag present but value empty.
fn emptyBValue(allocator: Allocator, header: []const u8) ![]u8 {
    // Find "b=" (the tag, not "bh=") and remove everything between = and the next ;
    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < header.len) {
        // Look for "b=" that is NOT preceded by another letter (i.e., not "bh=")
        if (i < header.len - 1 and header[i] == 'b' and header[i + 1] == '=') {
            // Make sure this isn't "bh=" — check previous non-whitespace char
            const is_bare_b = if (i == 0) true else blk: {
                var j = i - 1;
                while (j > 0 and (header[j] == ' ' or header[j] == '\t')) : (j -= 1) {}
                break :blk header[j] == ';' or j == 0;
            };
            if (is_bare_b) {
                // Append "b=" and skip the value until ; or end
                try result.appendSlice(allocator, "b=");
                i += 2;
                // Skip value (everything up to next ';')
                while (i < header.len and header[i] != ';') : (i += 1) {}
                continue;
            }
        }
        try result.append(allocator, header[i]);
        i += 1;
    }

    return result.toOwnedSlice(allocator);
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

            return crypto.ed25519Verify(pub_key, signed_data, sig_bytes);
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

test "empty b value" {
    const allocator = std.testing.allocator;
    const input = "DKIM-Signature: v=1; a=rsa-sha256; bh=abc; b=LONGSIGNATUREDATA; d=example.com";
    const result = try emptyBValue(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("DKIM-Signature: v=1; a=rsa-sha256; bh=abc; b=; d=example.com", result);
}

test "empty b value at end" {
    const allocator = std.testing.allocator;
    const input = "v=1; d=x.com; b=SIGDATA";
    const result = try emptyBValue(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("v=1; d=x.com; b=", result);
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
    try std.testing.expect(eqlIgnoreCase("From", "from"));
    try std.testing.expect(eqlIgnoreCase("SUBJECT", "Subject"));
    try std.testing.expect(!eqlIgnoreCase("From", "To"));
    try std.testing.expect(!eqlIgnoreCase("ab", "abc"));
}
