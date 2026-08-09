const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const dkim = @import("dkim.zig");
const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

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

    /// Key at `key_path`, loaded by `loadKeys` after parsing.
    key: ?crypto.SigningKey = null,
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
        for (self.entries) |*entry| {
            self.allocator.free(entry.signing_entry);
            self.allocator.free(entry.domain);
            self.allocator.free(entry.selector);
            self.allocator.free(entry.key_path);
            if (entry.key) |*k| k.deinit();
        }
        self.allocator.free(self.entries);
    }

    /// Load every row's key with the specified minimum size.
    ///
    /// The caller receives the failing path; reload remains all-or-nothing.
    pub fn loadKeys(self: *KeyTable, min_bits: u32, failed_path: *[]const u8) !void {
        for (self.entries) |*entry| {
            if (entry.key != null) continue;
            // KeyTable keys always sign mail, so safe file permissions are required.
            entry.key = crypto.loadRsaKeyFile(entry.key_path, min_bits, .require_safe) catch |err| {
                failed_path.* = entry.key_path;
                return err;
            };
        }
    }

    /// Find all adjacent entries for a signing-entry name.
    ///
    /// `parseKeyTable` groups matching rows; this scan returns only verified matches.
    pub fn lookup(self: *const KeyTable, signing_entry: []const u8) []const KeyTableEntry {
        const first = for (self.entries, 0..) |entry, i| {
            if (mem.eql(u8, entry.signing_entry, signing_entry)) break i;
        } else return &.{};

        var end = first + 1;
        while (end < self.entries.len and
            mem.eql(u8, self.entries[end].signing_entry, signing_entry)) : (end += 1)
        {}

        return self.entries[first..end];
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

    const owned = try entries.toOwnedSlice(allocator);
    groupBySigningEntry(owned);

    return .{
        .entries = owned,
        .allocator = allocator,
    };
}

/// Group rows by signing entry while preserving their file order.
///
/// This load-time quadratic pass keeps multi-sign lookup complete and ordered.
fn groupBySigningEntry(items: []KeyTableEntry) void {
    var group_start: usize = 0;
    while (group_start < items.len) {
        var insert = group_start + 1;
        var j = insert;
        while (j < items.len) : (j += 1) {
            if (!mem.eql(u8, items[j].signing_entry, items[group_start].signing_entry)) continue;
            if (j != insert) {
                // Shift rather than swap to preserve file order.
                const moved = items[j];
                var k = j;
                while (k > insert) : (k -= 1) items[k] = items[k - 1];
                items[insert] = moved;
            }
            insert += 1;
        }
        group_start = insert;
    }
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
    if (std.ascii.eqlIgnoreCase(pattern, sender)) return true;

    // Split pattern and sender at @
    const pat_at = mem.indexOfScalar(u8, pattern, '@') orelse return false;
    const snd_at = mem.indexOfScalar(u8, sender, '@') orelse return false;

    const pat_local = pattern[0..pat_at];
    const pat_domain = pattern[pat_at + 1 ..];
    const snd_local = sender[0..snd_at];
    const snd_domain = sender[snd_at + 1 ..];

    // Check local-part: * matches any, otherwise must match exactly
    if (!mem.eql(u8, pat_local, "*")) {
        if (!std.ascii.eqlIgnoreCase(pat_local, snd_local)) return false;
    }

    // Check domain: may have leading *. for subdomain wildcard
    if (mem.startsWith(u8, pat_domain, "*.")) {
        const suffix = pat_domain[1..]; // ".domain.com"
        // Sender domain must end with this suffix
        if (snd_domain.len > suffix.len) {
            const snd_suffix = snd_domain[snd_domain.len - suffix.len ..];
            return std.ascii.eqlIgnoreCase(snd_suffix, suffix);
        }
        // Or exact match on the base domain (without the dot prefix)
        return std.ascii.eqlIgnoreCase(snd_domain, pat_domain[2..]);
    }

    // Exact domain match
    return std.ascii.eqlIgnoreCase(pat_domain, snd_domain);
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

// --- D-7: rows for one signing entry need not be adjacent ---------------------
//
// The test above only ever asked the easy question. Its rows are grouped, which is
// what a freshly written table looks like and not what one looks like after six
// months of edits and appends -- and grouping was exactly the unstated assumption
// the lookup was built on. Same shape as D-15/D-16, where the suite only ever asked
// the daemon to verify its own signatures.

test "D-7: rows for one signing entry are found with another entry between them" {
    const allocator = std.testing.allocator;
    const content =
        \\example.com  example.com:rsa2026:/keys/rsa.key
        \\other.org    other.org:sel:/keys/other.key
        \\example.com  example.com:ed2026:/keys/ed.key
    ;

    var table = try parseKeyTable(allocator, content);
    defer table.deinit();

    const results = table.lookup("example.com");

    // Soundness first, because it is the worse half. The old lookup took the index
    // of the FIRST match and the count of ALL matches and returned that many rows
    // from there -- so this returned example.com's first key and then other.org's,
    // which is a different domain's signing key handed out under our name.
    for (results) |r| try std.testing.expectEqualStrings("example.com", r.signing_entry);

    // Completeness, and in file order: multi-sign order decides which signature is
    // added first, so it is part of the answer rather than an implementation detail.
    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqualStrings("rsa2026", results[0].selector);
    try std.testing.expectEqualStrings("ed2026", results[1].selector);
}

test "D-7: a trailing row is not dropped" {
    const allocator = std.testing.allocator;
    const content =
        \\other.org    other.org:s0:/keys/o0.key
        \\example.com  example.com:s1:/keys/e1.key
        \\other.org    other.org:s2:/keys/o2.key
    ;

    var table = try parseKeyTable(allocator, content);
    defer table.deinit();

    const results = table.lookup("other.org");
    for (results) |r| try std.testing.expectEqualStrings("other.org", r.signing_entry);
    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqualStrings("s0", results[0].selector);
    try std.testing.expectEqualStrings("s2", results[1].selector);
}

test "D-7: lookup is sound on a table the parser did not build" {
    // Built by hand, deliberately ungrouped. The parser groups rows now, which is
    // what makes the lookup COMPLETE -- but a lookup that hands out another
    // domain's key whenever that invariant is not upheld is one refactor away from
    // the original defect. Soundness must not depend on who built the table.
    var raw = [_]KeyTableEntry{
        .{ .signing_entry = "a", .domain = "a.example", .selector = "s1", .key_path = "/k/a1" },
        .{ .signing_entry = "b", .domain = "b.example", .selector = "s2", .key_path = "/k/b" },
        .{ .signing_entry = "a", .domain = "a.example", .selector = "s3", .key_path = "/k/a2" },
    };
    // Not deinit'd: the strings are literals, nothing was allocated.
    const table = KeyTable{ .entries = &raw, .allocator = std.testing.allocator };

    for (table.lookup("a")) |e| try std.testing.expectEqualStrings("a", e.signing_entry);
    for (table.lookup("b")) |e| try std.testing.expectEqualStrings("b", e.signing_entry);
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
