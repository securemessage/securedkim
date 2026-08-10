const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;
const canon = securemilter_crypto.canon;
const header_select = securemilter_crypto.header_select;

const dkim = @import("dkim.zig");

/// Default `h=` list shared by configuration and CLI parsing.
pub const DEFAULT_SIGNED_HEADERS = "from:to:subject:date:message-id";

/// Default oversigned headers (audit D-12).
///
/// Only `from` is oversigned by default; other fields may legitimately gain
/// instances in transit.
pub const DEFAULT_OVERSIGN_HEADERS = "from";

/// Signing parameters provided by config/keytable.
pub const SigningParams = struct {
    domain: []const u8,
    selector: []const u8,
    algorithm: dkim.Algorithm = .rsa_sha256,
    canonicalization: canon.CanonicalizationPair = .{ .header = .relaxed, .body = .relaxed },
    signed_headers: []const u8 = DEFAULT_SIGNED_HEADERS,
    /// Names listed one more time than the message contains them, so that adding
    /// another instance later breaks the signature. Empty disables it.
    oversign_headers: []const u8 = DEFAULT_OVERSIGN_HEADERS,
    auid: ?[]const u8 = null,
    body_length: ?u64 = null,
    include_timestamp: bool = true,
    expiration_seconds: ?u64 = null,
};

/// Result of signing: the complete DKIM-Signature header to prepend.
pub const SignResult = struct {
    header: []u8,
    allocator: Allocator,

    /// Field name and separator shared by header construction and `value`.
    ///
    /// `c=simple` requires the signed and transmitted bytes to match exactly.
    pub const PREFIX = "DKIM-Signature: ";

    pub fn deinit(self: *SignResult) void {
        self.allocator.free(self.header);
    }

    /// Header value without the field name and separator.
    ///
    /// The milter supplies the negotiated separator through `responses.addHeader`.
    pub fn value(self: *const SignResult) []const u8 {
        std.debug.assert(mem.startsWith(u8, self.header, PREFIX));
        return self.header[PREFIX.len..];
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

    // The `h=` actually emitted and hashed, which is the configured list plus
    // the oversigning surplus (audit D-12). Computed once and used for both: if
    // the emitted tag and the hashed tag could differ, the signature would cover
    // a header set other than the one it claims and no verifier would agree.
    const effective_h = try header_select.oversignedLineTag(
        allocator,
        params.signed_headers,
        params.oversign_headers,
        headers,
    );
    defer allocator.free(effective_h);

    // Build the Signature struct for header generation
    const now = @as(u64, @intCast(std.time.timestamp()));

    var sig = dkim.Signature{
        .algorithm = params.algorithm,
        .domain = params.domain,
        .selector = params.selector,
        .signed_headers = effective_h,
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
    const signed_data = try buildSigningInput(
        allocator,
        effective_h,
        params.canonicalization.header,
        headers,
        dkim_header_line,
    );
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

/// Canonicalize a message body and return its SHA-256 hash.
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

/// Build canonicalized signed headers and the DKIM-Signature template.
///
/// `h_tag` is the effective emitted list, including any oversigning surplus.
fn buildSigningInput(
    allocator: Allocator,
    h_tag: []const u8,
    header_canon: canon.Algorithm,
    headers: []const []const u8,
    dkim_header_line: []const u8,
) ![]u8 {
    var data: std.ArrayList(u8) = .{};
    errdefer data.deinit(allocator);

    // Use the verifier's header-instance selection rule for repeated `h=` names.
    var walk = header_select.lineWalker(h_tag, headers);
    while (walk.next()) |header| {
        const canonicalized = try canon.canonicalizeHeader(allocator, header_canon, header);
        defer allocator.free(canonicalized);
        try data.appendSlice(allocator, canonicalized);
        try data.appendSlice(allocator, "\r\n");
    }

    // Append the DKIM-Signature header (no trailing CRLF per RFC 6376 §3.7)
    const dkim_canon = try canon.canonicalizeHeader(allocator, header_canon, dkim_header_line);
    defer allocator.free(dkim_canon);
    try data.appendSlice(allocator, dkim_canon);

    return data.toOwnedSlice(allocator);
}

/// Find the bottom-most header with this field name, or null.
///
/// Only for callers that look up a single field outside the `h=` walk. Anything
/// resolving an `h=` entry must go through `header_select` (audit D-1).
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
            // RFC 8463 §3 signs the SHA-256 digest of the canonicalized input.
            // The keypair was derived during key loading.
            const sig_bytes = try key.signEd25519Sha256(data);
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

test "the signed line and the transmitted value share one separator" {
    const allocator = std.testing.allocator;

    // `PREFIX` is only the right split while `generateHeaderValue` opens with a
    // single space before its first tag, so that is asserted here rather than
    // assumed: `buildFullHeader` concatenates "DKIM-Signature:" with this, and
    // the result is the octet string the signature covers.
    const sig = dkim.Signature{
        .domain = "example.com",
        .selector = "sel",
        .signed_headers = "from",
        .body_hash = "aGFzaA==",
    };
    const generated = try dkim.generateHeaderValue(allocator, &sig);
    defer allocator.free(generated);
    try std.testing.expect(generated.len > 0 and generated[0] == ' ');

    const signed_line = try buildFullHeader(allocator, generated);
    defer allocator.free(signed_line);
    try std.testing.expect(mem.startsWith(u8, signed_line, SignResult.PREFIX));

    // What the milter hands to `addHeader`. Reassembling it with the separator
    // has to reproduce the signed line exactly -- under `c=simple` a verifier
    // hashes the transmitted field verbatim, so any difference here is a
    // signature that fails everywhere while this daemon reports success.
    var result = SignResult{ .header = try allocator.dupe(u8, signed_line), .allocator = allocator };
    defer result.deinit();

    try std.testing.expect(!mem.startsWith(u8, result.value(), " "));

    const reassembled = try std.fmt.allocPrint(allocator, "DKIM-Signature: {s}", .{result.value()});
    defer allocator.free(reassembled);
    try std.testing.expectEqualStrings(signed_line, reassembled);
}

test "build signing input produces deterministic output" {
    const allocator = std.testing.allocator;
    const headers = &[_][]const u8{
        "From: user@example.com",
        "To: rcpt@other.com",
        "Subject: Hello",
    };
    const dkim_line = "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from:to; bh=hash; b=";

    const result = try buildSigningInput(allocator, "from:to", .relaxed, headers, dkim_line);
    defer allocator.free(result);

    // Asserted byte for byte, not by substring presence. What is being signed
    // is the whole octet string; a test that only asks whether "from:" appears
    // somewhere cannot see a header hashed twice, which is precisely the defect
    // D-1 describes.
    try std.testing.expectEqualStrings(
        "from:user@example.com\r\n" ++
            "to:rcpt@other.com\r\n" ++
            "dkim-signature:v=1; a=rsa-sha256; d=example.com; s=sel; h=from:to; bh=hash; b=",
        result,
    );
}

test "an oversigned h= hashes the field once, not twice (D-1)" {
    // `h=from:from` over a message with one From. RFC 6376 §5.4.2: the second
    // mention has no instance left to consume, and §3.7 makes that the null
    // input -- nothing at all is added to the hash. A per-mention lookup that
    // returns the same header for both mentions would hash it twice, breaking
    // every message from a signer using OpenDKIM's `OverSignHeaders`.
    const allocator = std.testing.allocator;
    const headers = &[_][]const u8{
        "From: user@example.com",
        "Subject: Hello",
    };

    const result = try buildSigningInput(allocator, "from:from", .relaxed, headers, "DKIM-Signature: b=");
    defer allocator.free(result);

    try std.testing.expectEqualStrings(
        "from:user@example.com\r\ndkim-signature:b=",
        result,
    );
}

test "repeated h= mentions hash successive instances, bottom upward (D-1)" {
    const allocator = std.testing.allocator;
    const headers = &[_][]const u8{
        "From: top@example.com",
        "From: bottom@example.com",
    };

    const result = try buildSigningInput(allocator, "from:from", .relaxed, headers, "DKIM-Signature: b=");
    defer allocator.free(result);

    // Bottom-most first, then the next one up -- not the same header twice.
    try std.testing.expectEqualStrings(
        "from:bottom@example.com\r\nfrom:top@example.com\r\ndkim-signature:b=",
        result,
    );
}
