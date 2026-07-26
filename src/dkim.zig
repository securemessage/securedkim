const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const canon = securemilter.canon;

/// DKIM signing algorithm (RFC 6376 §3.3, RFC 8463).
pub const Algorithm = enum {
    rsa_sha256,
    ed25519_sha256,

    pub fn toString(self: Algorithm) []const u8 {
        return switch (self) {
            .rsa_sha256 => "rsa-sha256",
            .ed25519_sha256 => "ed25519-sha256",
        };
    }

    pub fn parse(s: []const u8) !Algorithm {
        if (mem.eql(u8, s, "rsa-sha256")) return .rsa_sha256;
        if (mem.eql(u8, s, "ed25519-sha256")) return .ed25519_sha256;
        return error.UnsupportedAlgorithm;
    }
};

/// Parsed DKIM-Signature header (RFC 6376 §3.5).
pub const Signature = struct {
    /// v= Version (MUST be "1")
    version: []const u8 = "1",
    /// a= Signing algorithm
    algorithm: Algorithm = .rsa_sha256,
    /// b= Signature data (base64, whitespace stripped)
    signature: []const u8 = "",
    /// bh= Body hash (base64, whitespace stripped)
    body_hash: []const u8 = "",
    /// c= Canonicalization (header/body)
    canonicalization: canon.CanonicalizationPair = .{},
    /// d= Signing domain (SDID)
    domain: []const u8 = "",
    /// h= Signed header fields (colon-separated in raw form)
    signed_headers: []const u8 = "",
    /// i= Agent or user identifier (AUID), optional
    auid: ?[]const u8 = null,
    /// l= Body length limit, optional
    body_length: ?u64 = null,
    /// q= Query method (default "dns/txt")
    query_method: []const u8 = "dns/txt",
    /// s= Selector
    selector: []const u8 = "",
    /// t= Signature timestamp (seconds since epoch), optional
    timestamp: ?u64 = null,
    /// x= Signature expiration (seconds since epoch), optional
    expiration: ?u64 = null,

    /// Parse the signed_headers field into individual header names.
    pub fn getSignedHeaderList(self: *const Signature, allocator: Allocator) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .{};
        errdefer list.deinit(allocator);

        var iter = mem.splitScalar(u8, self.signed_headers, ':');
        while (iter.next()) |field| {
            const trimmed = mem.trim(u8, field, " \t");
            if (trimmed.len > 0) {
                try list.append(allocator, trimmed);
            }
        }
        return list.toOwnedSlice(allocator);
    }
};

// =============================================================================
// Tag-Value Parsing (RFC 6376 §3.2)
// =============================================================================

/// Parse a DKIM-Signature header value into a Signature struct.
///
/// Tag-value syntax: tag=value pairs separated by semicolons.
/// Whitespace around tags and values is ignored.
/// FWS within base64 values (b=, bh=) is stripped.
pub fn parseSignature(value: []const u8) !Signature {
    var sig = Signature{};

    var pairs = mem.splitScalar(u8, value, ';');
    while (pairs.next()) |pair| {
        const trimmed = mem.trim(u8, pair, " \t\r\n");
        if (trimmed.len == 0) continue;

        const eq_pos = mem.indexOfScalar(u8, trimmed, '=') orelse continue;
        const tag = mem.trim(u8, trimmed[0..eq_pos], " \t");
        const val = mem.trim(u8, trimmed[eq_pos + 1 ..], " \t\r\n");

        if (tag.len == 0) continue;

        if (mem.eql(u8, tag, "v")) {
            sig.version = val;
        } else if (mem.eql(u8, tag, "a")) {
            sig.algorithm = Algorithm.parse(val) catch return error.UnsupportedAlgorithm;
        } else if (mem.eql(u8, tag, "b")) {
            sig.signature = val;
        } else if (mem.eql(u8, tag, "bh")) {
            sig.body_hash = val;
        } else if (mem.eql(u8, tag, "c")) {
            sig.canonicalization = canon.parseCanonicalization(val) catch .{};
        } else if (mem.eql(u8, tag, "d")) {
            sig.domain = val;
        } else if (mem.eql(u8, tag, "h")) {
            sig.signed_headers = val;
        } else if (mem.eql(u8, tag, "i")) {
            sig.auid = val;
        } else if (mem.eql(u8, tag, "l")) {
            sig.body_length = std.fmt.parseInt(u64, val, 10) catch null;
        } else if (mem.eql(u8, tag, "q")) {
            sig.query_method = val;
        } else if (mem.eql(u8, tag, "s")) {
            sig.selector = val;
        } else if (mem.eql(u8, tag, "t")) {
            sig.timestamp = std.fmt.parseInt(u64, val, 10) catch null;
        } else if (mem.eql(u8, tag, "x")) {
            sig.expiration = std.fmt.parseInt(u64, val, 10) catch null;
        }
        // Unknown tags are silently ignored per RFC 6376 §3.2
    }

    // Validate required tags (RFC 6376 §6.1.1)
    if (sig.domain.len == 0) return error.MissingRequiredTag;
    if (sig.selector.len == 0) return error.MissingRequiredTag;
    if (sig.signed_headers.len == 0) return error.MissingRequiredTag;
    if (!mem.eql(u8, sig.version, "1")) return error.UnsupportedVersion;

    return sig;
}

/// Validate that the DKIM-Signature contains the minimum required tags for verification.
pub fn validateForVerification(sig: *const Signature) !void {
    if (sig.signature.len == 0) return error.MissingSignature;
    if (sig.body_hash.len == 0) return error.MissingBodyHash;
    if (sig.domain.len == 0) return error.MissingRequiredTag;
    if (sig.selector.len == 0) return error.MissingRequiredTag;
}

// =============================================================================
// Tag-Value Generation (for signing)
// =============================================================================

/// Generate a DKIM-Signature header value string from a Signature struct.
/// The `b=` value is left empty (placeholder for the actual signature).
/// Caller must compute the signature and fill it in afterward.
pub fn generateHeaderValue(allocator: Allocator, sig: *const Signature) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    try appendTag(&buf, allocator, "v", sig.version);
    try appendTag(&buf, allocator, "a", sig.algorithm.toString());
    const canon_str = try canonPairToString(allocator, sig.canonicalization);
    defer allocator.free(canon_str);
    try appendTag(&buf, allocator, "c", canon_str);
    try appendTag(&buf, allocator, "d", sig.domain);
    try appendTag(&buf, allocator, "s", sig.selector);
    try appendTag(&buf, allocator, "h", sig.signed_headers);

    if (sig.timestamp) |t| {
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{t}) catch unreachable;
        try appendTag(&buf, allocator, "t", ts_str);
    }

    if (sig.expiration) |x| {
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{x}) catch unreachable;
        try appendTag(&buf, allocator, "x", ts_str);
    }

    if (sig.body_length) |l| {
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{l}) catch unreachable;
        try appendTag(&buf, allocator, "l", ts_str);
    }

    if (sig.auid) |auid| {
        try appendTag(&buf, allocator, "i", auid);
    }

    try appendTag(&buf, allocator, "bh", sig.body_hash);

    // b= tag always last (empty for initial signing pass)
    try buf.appendSlice(allocator, "; b=");

    return buf.toOwnedSlice(allocator);
}

fn appendTag(buf: *std.ArrayList(u8), allocator: Allocator, tag: []const u8, value: []const u8) !void {
    if (buf.items.len > 0) {
        try buf.appendSlice(allocator, ";");
    }
    try buf.appendSlice(allocator, " ");
    try buf.appendSlice(allocator, tag);
    try buf.append(allocator, '=');
    try buf.appendSlice(allocator, value);
}

fn canonPairToString(allocator: Allocator, pair: canon.CanonicalizationPair) ![]const u8 {
    const h = switch (pair.header) {
        .simple => "simple",
        .relaxed => "relaxed",
    };
    const b = switch (pair.body) {
        .simple => "simple",
        .relaxed => "relaxed",
    };
    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, h);
    try result.append(allocator, '/');
    try result.appendSlice(allocator, b);
    return result.toOwnedSlice(allocator);
}

// =============================================================================
// DNS Key Record Parsing (RFC 6376 §3.6.1)
// =============================================================================

/// Parsed DKIM DNS public key record.
pub const PublicKeyRecord = struct {
    /// v= Version (optional, if present MUST be "DKIM1")
    version: ?[]const u8 = null,
    /// k= Key type (default "rsa")
    key_type: []const u8 = "rsa",
    /// p= Public key data (base64)
    public_key: []const u8 = "",
    /// h= Acceptable hash algorithms (colon-separated, optional)
    hash_algorithms: ?[]const u8 = null,
    /// s= Service type (optional, default "*")
    service_type: []const u8 = "*",
    /// t= Flags (colon-separated: "y" = testing, "s" = strict)
    flags: ?[]const u8 = null,
};

/// Parse a DKIM DNS TXT record (tag=value format, same as signature).
pub fn parsePublicKeyRecord(value: []const u8) !PublicKeyRecord {
    var rec = PublicKeyRecord{};

    var pairs = mem.splitScalar(u8, value, ';');
    while (pairs.next()) |pair| {
        const trimmed = mem.trim(u8, pair, " \t\r\n");
        if (trimmed.len == 0) continue;

        const eq_pos = mem.indexOfScalar(u8, trimmed, '=') orelse continue;
        const tag = mem.trim(u8, trimmed[0..eq_pos], " \t");
        const val = mem.trim(u8, trimmed[eq_pos + 1 ..], " \t\r\n");

        if (mem.eql(u8, tag, "v")) {
            rec.version = val;
        } else if (mem.eql(u8, tag, "k")) {
            rec.key_type = val;
        } else if (mem.eql(u8, tag, "p")) {
            rec.public_key = val;
        } else if (mem.eql(u8, tag, "h")) {
            rec.hash_algorithms = val;
        } else if (mem.eql(u8, tag, "s")) {
            rec.service_type = val;
        } else if (mem.eql(u8, tag, "t")) {
            rec.flags = val;
        }
    }

    // If version is present, it MUST be "DKIM1"
    if (rec.version) |v| {
        if (!mem.eql(u8, v, "DKIM1")) return error.UnsupportedVersion;
    }

    // Empty p= means key has been revoked (RFC 6376 §3.6.1)
    // We allow parsing it — caller checks .public_key.len == 0 for revocation

    return rec;
}

// =============================================================================
// Utility: Strip FWS from base64 values
// =============================================================================

/// Strip all whitespace (SP, TAB, CR, LF) from a base64 value.
/// DKIM allows FWS within b= and bh= values.
pub fn stripWhitespace(allocator: Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    for (input) |c| {
        if (c != ' ' and c != '\t' and c != '\r' and c != '\n') {
            try result.append(allocator, c);
        }
    }
    return result.toOwnedSlice(allocator);
}

// =============================================================================
// Tests
// =============================================================================

test "parse algorithm" {
    try std.testing.expectEqual(Algorithm.rsa_sha256, try Algorithm.parse("rsa-sha256"));
    try std.testing.expectEqual(Algorithm.ed25519_sha256, try Algorithm.parse("ed25519-sha256"));
    try std.testing.expectError(error.UnsupportedAlgorithm, Algorithm.parse("rsa-sha1"));
}

test "parse signature basic" {
    const value = "v=1; a=rsa-sha256; d=example.com; s=sel2026; " ++
        "h=from:to:subject:date; bh=abc123; b=sig456; c=relaxed/simple";
    const sig = try parseSignature(value);

    try std.testing.expectEqualStrings("1", sig.version);
    try std.testing.expectEqual(Algorithm.rsa_sha256, sig.algorithm);
    try std.testing.expectEqualStrings("example.com", sig.domain);
    try std.testing.expectEqualStrings("sel2026", sig.selector);
    try std.testing.expectEqualStrings("from:to:subject:date", sig.signed_headers);
    try std.testing.expectEqualStrings("abc123", sig.body_hash);
    try std.testing.expectEqualStrings("sig456", sig.signature);
    try std.testing.expectEqual(canon.Algorithm.relaxed, sig.canonicalization.header);
    try std.testing.expectEqual(canon.Algorithm.simple, sig.canonicalization.body);
}

test "parse signature with optional tags" {
    const value = "v=1; a=ed25519-sha256; d=test.org; s=key1; " ++
        "h=from:subject; bh=hash; b=data; t=1700000000; x=1700086400; " ++
        "i=@test.org; l=1024; q=dns/txt";
    const sig = try parseSignature(value);

    try std.testing.expectEqual(Algorithm.ed25519_sha256, sig.algorithm);
    try std.testing.expectEqual(@as(?u64, 1700000000), sig.timestamp);
    try std.testing.expectEqual(@as(?u64, 1700086400), sig.expiration);
    try std.testing.expectEqualStrings("@test.org", sig.auid.?);
    try std.testing.expectEqual(@as(?u64, 1024), sig.body_length);
    try std.testing.expectEqualStrings("dns/txt", sig.query_method);
}

test "parse signature missing required tag" {
    // Missing d=
    const value = "v=1; a=rsa-sha256; s=sel; h=from; bh=x; b=y";
    try std.testing.expectError(error.MissingRequiredTag, parseSignature(value));
}

test "parse signature unsupported version" {
    const value = "v=2; a=rsa-sha256; d=example.com; s=sel; h=from; bh=x; b=y";
    try std.testing.expectError(error.UnsupportedVersion, parseSignature(value));
}

test "parse public key record" {
    const value = "v=DKIM1; k=rsa; p=MIGfMA0GCSq...base64data";
    const rec = try parsePublicKeyRecord(value);

    try std.testing.expectEqualStrings("DKIM1", rec.version.?);
    try std.testing.expectEqualStrings("rsa", rec.key_type);
    try std.testing.expectEqualStrings("MIGfMA0GCSq...base64data", rec.public_key);
}

test "parse public key record ed25519" {
    const value = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    const rec = try parsePublicKeyRecord(value);

    try std.testing.expectEqualStrings("ed25519", rec.key_type);
    try std.testing.expectEqualStrings("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", rec.public_key);
}

test "parse public key record revoked" {
    const value = "v=DKIM1; k=rsa; p=";
    const rec = try parsePublicKeyRecord(value);
    try std.testing.expectEqual(@as(usize, 0), rec.public_key.len);
}

test "generate header value" {
    const allocator = std.testing.allocator;
    const sig = Signature{
        .algorithm = .rsa_sha256,
        .domain = "example.com",
        .selector = "sel2026",
        .signed_headers = "from:to:subject:date",
        .body_hash = "base64bodyhash",
        .canonicalization = .{ .header = .relaxed, .body = .relaxed },
        .timestamp = 1700000000,
    };

    const result = try generateHeaderValue(allocator, &sig);
    defer allocator.free(result);

    // Verify key tags are present
    try std.testing.expect(mem.indexOf(u8, result, "v=1") != null);
    try std.testing.expect(mem.indexOf(u8, result, "a=rsa-sha256") != null);
    try std.testing.expect(mem.indexOf(u8, result, "d=example.com") != null);
    try std.testing.expect(mem.indexOf(u8, result, "s=sel2026") != null);
    try std.testing.expect(mem.indexOf(u8, result, "h=from:to:subject:date") != null);
    try std.testing.expect(mem.indexOf(u8, result, "bh=base64bodyhash") != null);
    try std.testing.expect(mem.indexOf(u8, result, "c=relaxed/relaxed") != null);
    try std.testing.expect(mem.indexOf(u8, result, "t=1700000000") != null);
    // b= should be last and empty (for signing pass)
    try std.testing.expect(mem.endsWith(u8, result, " b="));
}

test "strip whitespace from base64" {
    const allocator = std.testing.allocator;
    const result = try stripWhitespace(allocator, "abc def\r\n\tghi");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("abcdefghi", result);
}

test "signed header list parsing" {
    const allocator = std.testing.allocator;
    const sig = Signature{
        .domain = "x.com",
        .selector = "s",
        .signed_headers = "From : To : Subject:Date",
    };
    const list = try sig.getSignedHeaderList(allocator);
    defer allocator.free(list);

    try std.testing.expectEqual(@as(usize, 4), list.len);
    try std.testing.expectEqualStrings("From", list[0]);
    try std.testing.expectEqualStrings("To", list[1]);
    try std.testing.expectEqualStrings("Subject", list[2]);
    try std.testing.expectEqualStrings("Date", list[3]);
}
