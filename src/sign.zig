const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const crypto = securemilter.crypto;

const dkim = @import("dkim.zig");
const canon = @import("canon.zig");

/// Signing parameters provided by config/keytable.
pub const SigningParams = struct {
    domain: []const u8,
    selector: []const u8,
    algorithm: dkim.Algorithm = .rsa_sha256,
    canonicalization: canon.CanonicalizationPair = .{ .header = .relaxed, .body = .relaxed },
    signed_headers: []const u8 = "from:to:subject:date:message-id",
    auid: ?[]const u8 = null,
    body_length: ?u64 = null,
    include_timestamp: bool = true,
    expiration_seconds: ?u64 = null,
};

/// Result of signing: the complete DKIM-Signature header to prepend.
pub const SignResult = struct {
    header: []u8,
    allocator: Allocator,

    pub fn deinit(self: *SignResult) void {
        self.allocator.free(self.header);
    }
};

/// Sign a message given headers, canonicalized body hash, and a private key.
///
/// Steps (RFC 6376 §5):
/// 1. Canonicalize body → compute bh= (body hash)
/// 2. Build DKIM-Signature header template with b= empty
/// 3. Canonicalize the signed headers (per h= list) + the template
/// 4. Compute signature over the canonicalized header block
/// 5. Base64 encode signature → fill in b= value
/// 6. Return the complete "DKIM-Signature: ..." header line
pub fn signMessage(
    allocator: Allocator,
    params: *const SigningParams,
    key: *const crypto.SigningKey,
    headers: []const []const u8,
    body_hash: [32]u8,
) !SignResult {
    // Step 1: Base64 encode the body hash for bh= tag
    const bh_b64 = try crypto.base64Encode(allocator, &body_hash);
    defer allocator.free(bh_b64);

    // Build the Signature struct for header generation
    const now = @as(u64, @intCast(std.time.timestamp()));

    var sig = dkim.Signature{
        .algorithm = params.algorithm,
        .domain = params.domain,
        .selector = params.selector,
        .signed_headers = params.signed_headers,
        .canonicalization = params.canonicalization,
        .body_hash = bh_b64,
        .auid = params.auid,
        .body_length = params.body_length,
    };

    if (params.include_timestamp) {
        sig.timestamp = now;
    }
    if (params.expiration_seconds) |exp_s| {
        sig.expiration = now + exp_s;
    }

    // Step 2: Generate the DKIM-Signature value with b= empty
    const header_value = try dkim.generateHeaderValue(allocator, &sig);
    defer allocator.free(header_value);

    // Build the full header line for canonicalization (without trailing CRLF)
    const dkim_header_line = try buildFullHeader(allocator, header_value);
    defer allocator.free(dkim_header_line);

    // Step 3: Build signed data (canonicalized h= headers + DKIM-Signature template)
    const signed_data = try buildSigningInput(allocator, params, headers, dkim_header_line);
    defer allocator.free(signed_data);

    // Step 4-5: Sign and base64 encode
    const signature_b64 = try computeSignature(allocator, params.algorithm, key, signed_data);
    defer allocator.free(signature_b64);

    // Step 6: Build final header: "DKIM-Signature: <value>b=<signature>"
    var final: std.ArrayList(u8) = .{};
    errdefer final.deinit(allocator);

    try final.appendSlice(allocator, "DKIM-Signature:");
    try final.appendSlice(allocator, header_value);
    try final.appendSlice(allocator, signature_b64);

    return .{
        .header = try final.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

/// Compute the canonicalized body hash for a message body.
///
/// This is a convenience wrapper: feed the full body through the
/// BodyCanonicalizer with the given algorithm, then SHA-256 hash it.
pub fn computeBodyHash(allocator: Allocator, body: []const u8, algorithm: canon.Algorithm) ![32]u8 {
    var bc = canon.BodyCanonicalizer.init(allocator, algorithm);
    defer bc.deinit();
    try bc.update(body);
    const canonicalized = try bc.finish();
    defer allocator.free(canonicalized);
    return crypto.sha256(canonicalized);
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Build "DKIM-Signature: <value>" (the full header line for canonicalization input).
fn buildFullHeader(allocator: Allocator, header_value: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, "DKIM-Signature:");
    try buf.appendSlice(allocator, header_value);
    return buf.toOwnedSlice(allocator);
}

/// Build the data block to be signed: canonicalized headers + DKIM-Signature template.
fn buildSigningInput(
    allocator: Allocator,
    params: *const SigningParams,
    headers: []const []const u8,
    dkim_header_line: []const u8,
) ![]u8 {
    var data: std.ArrayList(u8) = .{};
    errdefer data.deinit(allocator);

    // Canonicalize each header from the h= list
    var iter = mem.splitScalar(u8, params.signed_headers, ':');
    while (iter.next()) |field_name| {
        const trimmed = mem.trim(u8, field_name, " \t");
        if (trimmed.len == 0) continue;

        const header = findHeader(headers, trimmed) orelse continue;
        const canonicalized = try canon.canonicalizeHeader(allocator, params.canonicalization.header, header);
        defer allocator.free(canonicalized);
        try data.appendSlice(allocator, canonicalized);
        try data.appendSlice(allocator, "\r\n");
    }

    // Append the DKIM-Signature header (no trailing CRLF per RFC 6376 §3.7)
    const dkim_canon = try canon.canonicalizeHeader(allocator, params.canonicalization.header, dkim_header_line);
    defer allocator.free(dkim_canon);
    try data.appendSlice(allocator, dkim_canon);

    return data.toOwnedSlice(allocator);
}

/// Find a header by field name (case-insensitive), bottom-to-top.
fn findHeader(headers: []const []const u8, field_name: []const u8) ?[]const u8 {
    var i = headers.len;
    while (i > 0) {
        i -= 1;
        const hdr = headers[i];
        const colon = mem.indexOfScalar(u8, hdr, ':') orelse continue;
        const name = mem.trimRight(u8, hdr[0..colon], " \t");
        if (eqlIgnoreCase(name, field_name)) return hdr;
    }
    return null;
}

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

/// Compute the cryptographic signature and return base64-encoded result.
fn computeSignature(
    allocator: Allocator,
    algorithm: dkim.Algorithm,
    key: *const crypto.SigningKey,
    data: []const u8,
) ![]u8 {
    switch (algorithm) {
        .rsa_sha256 => {
            const sig_bytes = try crypto.rsaSign(allocator, key.rsa_pkey.?, data);
            defer allocator.free(sig_bytes);
            return crypto.base64Encode(allocator, sig_bytes);
        },
        .ed25519_sha256 => {
            const sig_bytes = try crypto.ed25519Sign(key.ed25519_seed.?, data);
            return crypto.base64Encode(allocator, &sig_bytes);
        },
    }
}

// =============================================================================
// Tests
// =============================================================================

test "compute body hash simple" {
    const allocator = std.testing.allocator;
    const body = "Hello World\r\n";
    const hash = try computeBodyHash(allocator, body, .simple);
    // Just verify it produces a deterministic 32-byte result
    try std.testing.expectEqual(@as(usize, 32), hash.len);

    // Same input should produce same hash
    const hash2 = try computeBodyHash(allocator, body, .simple);
    try std.testing.expectEqualSlices(u8, &hash, &hash2);
}

test "compute body hash relaxed strips trailing WSP" {
    const allocator = std.testing.allocator;
    const body1 = "Hello  \r\n";
    const body2 = "Hello\r\n";
    // After relaxed canonicalization, both should produce the same hash
    const hash1 = try computeBodyHash(allocator, body1, .relaxed);
    const hash2 = try computeBodyHash(allocator, body2, .relaxed);
    try std.testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "find header reverse order" {
    const headers = &[_][]const u8{
        "From: alpha@a.com",
        "To: beta@b.com",
        "From: gamma@c.com",
    };
    const found = findHeader(headers, "from").?;
    try std.testing.expectEqualStrings("From: gamma@c.com", found);
}

test "build signing input produces deterministic output" {
    const allocator = std.testing.allocator;
    const params = SigningParams{
        .domain = "example.com",
        .selector = "sel",
        .signed_headers = "from:to",
    };
    const headers = &[_][]const u8{
        "From: user@example.com",
        "To: rcpt@other.com",
        "Subject: Hello",
    };
    const dkim_line = "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from:to; bh=hash; b=";

    const result = try buildSigningInput(allocator, &params, headers, dkim_line);
    defer allocator.free(result);

    // Should contain canonicalized from + to + dkim-signature
    try std.testing.expect(mem.indexOf(u8, result, "from:") != null);
    try std.testing.expect(mem.indexOf(u8, result, "to:") != null);
    try std.testing.expect(mem.indexOf(u8, result, "dkim-signature:") != null);
}
