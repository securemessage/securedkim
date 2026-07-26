const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const dkim = @import("dkim.zig");

/// A SigningTable entry: maps a sender pattern to a signing-entry name.
///
/// Format: pattern signing-entry
/// Examples:
///   *@example.com       example.com
///   *@*.clients.ex.com  ex.com
///   user@specific.com   specific.com
pub const SigningTableEntry = struct {
    pattern: []const u8,
    signing_entry: []const u8,
};

/// A KeyTable entry: maps a signing-entry to domain:selector:keypath.
///
/// Format: signing-entry domain:selector:keypath
/// Multiple entries with the same signing-entry = multi-sign.
pub const KeyTableEntry = struct {
    signing_entry: []const u8,
    domain: []const u8,
    selector: []const u8,
    key_path: []const u8,
};

/// Loaded SigningTable.
pub const SigningTable = struct {
    entries: []SigningTableEntry,
    allocator: Allocator,

    pub fn deinit(self: *SigningTable) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.pattern);
            self.allocator.free(entry.signing_entry);
        }
        self.allocator.free(self.entries);
    }

    /// Find the signing entry for a given sender address.
    /// Returns the signing-entry name or null if no match.
    pub fn lookup(self: *const SigningTable, sender: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (matchPattern(entry.pattern, sender)) {
                return entry.signing_entry;
            }
        }
        return null;
    }
};

/// Loaded KeyTable.
pub const KeyTable = struct {
    entries: []KeyTableEntry,
    allocator: Allocator,

    pub fn deinit(self: *KeyTable) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.signing_entry);
            self.allocator.free(entry.domain);
            self.allocator.free(entry.selector);
            self.allocator.free(entry.key_path);
        }
        self.allocator.free(self.entries);
    }

    /// Find all key entries for a given signing-entry name.
    /// Returns a slice of matching entries (may be multiple for multi-sign).
    pub fn lookup(self: *const KeyTable, signing_entry: []const u8) []const KeyTableEntry {
        var start: ?usize = null;
        var count: usize = 0;
        for (self.entries, 0..) |entry, i| {
            if (mem.eql(u8, entry.signing_entry, signing_entry)) {
                if (start == null) start = i;
                count += 1;
            }
        }
        if (start) |s| return self.entries[s .. s + count];
        return &.{};
    }
};

// =============================================================================
// File Parsing
// =============================================================================

/// Parse a SigningTable file. Format: one entry per line, "pattern signing-entry".
/// Lines starting with # are comments. Empty lines are skipped.
pub fn parseSigningTable(allocator: Allocator, content: []const u8) !SigningTable {
    var entries: std.ArrayList(SigningTableEntry) = .{};
    errdefer {
        for (entries.items) |entry| {
            allocator.free(entry.pattern);
            allocator.free(entry.signing_entry);
        }
        entries.deinit(allocator);
    }

    var lines = mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Split on whitespace: pattern <whitespace> signing-entry
        var parts = mem.tokenizeAny(u8, trimmed, " \t");
        const pattern = parts.next() orelse continue;
        const entry_name = parts.next() orelse continue;

        try entries.append(allocator, .{
            .pattern = try allocator.dupe(u8, pattern),
            .signing_entry = try allocator.dupe(u8, entry_name),
        });
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

/// Parse a KeyTable file. Format: one entry per line, "signing-entry domain:selector:keypath".
/// Lines starting with # are comments. Empty lines are skipped.
pub fn parseKeyTable(allocator: Allocator, content: []const u8) !KeyTable {
    var entries: std.ArrayList(KeyTableEntry) = .{};
    errdefer {
        for (entries.items) |entry| {
            allocator.free(entry.signing_entry);
            allocator.free(entry.domain);
            allocator.free(entry.selector);
            allocator.free(entry.key_path);
        }
        entries.deinit(allocator);
    }

    var lines = mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        var parts = mem.tokenizeAny(u8, trimmed, " \t");
        const entry_name = parts.next() orelse continue;
        const key_spec = parts.next() orelse continue;

        // Parse domain:selector:keypath
        var spec_parts = mem.splitScalar(u8, key_spec, ':');
        const domain = spec_parts.next() orelse continue;
        const selector = spec_parts.next() orelse continue;
        const key_path = spec_parts.rest();
        if (key_path.len == 0) continue;

        try entries.append(allocator, .{
            .signing_entry = try allocator.dupe(u8, entry_name),
            .domain = try allocator.dupe(u8, domain),
            .selector = try allocator.dupe(u8, selector),
            .key_path = try allocator.dupe(u8, key_path),
        });
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

// =============================================================================
// Pattern Matching
// =============================================================================

/// Match a signing-table pattern against a sender address.
/// Supports:
///   - Exact match: "user@domain.com"
///   - Wildcard local-part: "*@domain.com"
///   - Wildcard subdomain: "*@*.domain.com"
fn matchPattern(pattern: []const u8, sender: []const u8) bool {
    // Exact match first
    if (eqlIgnoreCase(pattern, sender)) return true;

    // Split pattern and sender at @
    const pat_at = mem.indexOfScalar(u8, pattern, '@') orelse return false;
    const snd_at = mem.indexOfScalar(u8, sender, '@') orelse return false;

    const pat_local = pattern[0..pat_at];
    const pat_domain = pattern[pat_at + 1 ..];
    const snd_local = sender[0..snd_at];
    const snd_domain = sender[snd_at + 1 ..];

    // Check local-part: * matches any, otherwise must match exactly
    if (!mem.eql(u8, pat_local, "*")) {
        if (!eqlIgnoreCase(pat_local, snd_local)) return false;
    }

    // Check domain: may have leading *. for subdomain wildcard
    if (mem.startsWith(u8, pat_domain, "*.")) {
        const suffix = pat_domain[1..]; // ".domain.com"
        // Sender domain must end with this suffix
        if (snd_domain.len > suffix.len) {
            const snd_suffix = snd_domain[snd_domain.len - suffix.len ..];
            return eqlIgnoreCase(snd_suffix, suffix);
        }
        // Or exact match on the base domain (without the dot prefix)
        return eqlIgnoreCase(snd_domain, pat_domain[2..]);
    }

    // Exact domain match
    return eqlIgnoreCase(pat_domain, snd_domain);
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

// =============================================================================
// Tests
// =============================================================================

test "parse signing table" {
    const allocator = std.testing.allocator;
    const content =
        \\# Comment line
        \\*@example.com       example.com
        \\*@bambania.com      bambania.com
        \\user@specific.net   specific.net
    ;

    var table = try parseSigningTable(allocator, content);
    defer table.deinit();

    try std.testing.expectEqual(@as(usize, 3), table.entries.len);
    try std.testing.expectEqualStrings("*@example.com", table.entries[0].pattern);
    try std.testing.expectEqualStrings("example.com", table.entries[0].signing_entry);
}

test "signing table lookup" {
    const allocator = std.testing.allocator;
    const content =
        \\*@example.com  example.com
        \\*@other.org    other.org
    ;

    var table = try parseSigningTable(allocator, content);
    defer table.deinit();

    try std.testing.expectEqualStrings("example.com", table.lookup("user@example.com").?);
    try std.testing.expectEqualStrings("other.org", table.lookup("admin@other.org").?);
    try std.testing.expect(table.lookup("user@unknown.com") == null);
}

test "parse key table" {
    const allocator = std.testing.allocator;
    const content =
        \\# Keys
        \\example.com    example.com:dkim2026:/keys/example-rsa.key
        \\example.com    example.com:ed2026:/keys/example-ed25519.key
        \\other.org      other.org:sel1:/keys/other.key
    ;

    var table = try parseKeyTable(allocator, content);
    defer table.deinit();

    try std.testing.expectEqual(@as(usize, 3), table.entries.len);
    try std.testing.expectEqualStrings("example.com", table.entries[0].domain);
    try std.testing.expectEqualStrings("dkim2026", table.entries[0].selector);
    try std.testing.expectEqualStrings("/keys/example-rsa.key", table.entries[0].key_path);
}

test "key table lookup multi-sign" {
    const allocator = std.testing.allocator;
    const content =
        \\example.com  example.com:rsa2026:/keys/rsa.key
        \\example.com  example.com:ed2026:/keys/ed.key
        \\other.org    other.org:sel:/keys/other.key
    ;

    var table = try parseKeyTable(allocator, content);
    defer table.deinit();

    const results = table.lookup("example.com");
    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqualStrings("rsa2026", results[0].selector);
    try std.testing.expectEqualStrings("ed2026", results[1].selector);

    const other = table.lookup("other.org");
    try std.testing.expectEqual(@as(usize, 1), other.len);

    const none = table.lookup("missing.com");
    try std.testing.expectEqual(@as(usize, 0), none.len);
}

test "pattern matching wildcard local" {
    try std.testing.expect(matchPattern("*@example.com", "user@example.com"));
    try std.testing.expect(matchPattern("*@example.com", "admin@example.com"));
    try std.testing.expect(!matchPattern("*@example.com", "user@other.com"));
}

test "pattern matching wildcard subdomain" {
    try std.testing.expect(matchPattern("*@*.example.com", "user@sub.example.com"));
    try std.testing.expect(matchPattern("*@*.example.com", "a@deep.sub.example.com"));
    try std.testing.expect(matchPattern("*@*.example.com", "user@example.com"));
    try std.testing.expect(!matchPattern("*@*.example.com", "user@other.com"));
}

test "pattern matching exact" {
    try std.testing.expect(matchPattern("admin@specific.net", "admin@specific.net"));
    try std.testing.expect(!matchPattern("admin@specific.net", "other@specific.net"));
}

test "pattern matching case insensitive" {
    try std.testing.expect(matchPattern("*@Example.COM", "user@example.com"));
    try std.testing.expect(matchPattern("Admin@test.org", "admin@TEST.ORG"));
}
