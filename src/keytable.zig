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

/// Hash-map context folding case on both sides of the comparison.
///
/// Patterns and sender addresses arrive in whatever case the operator and the
/// peer chose. Folding inside the context keeps the map keys borrowed from
/// `entries` rather than allocating a lowercased copy of every key, and lets a
/// lookup probe the sender in place.
const CaseFoldedKey = struct {
    pub fn hash(_: CaseFoldedKey, key: []const u8) u64 {
        // FNV-1a over the folded bytes: keys are short domain names.
        var h: u64 = 0xcbf29ce484222325;
        for (key) |c| {
            h ^= std.ascii.toLower(c);
            h *%= 0x100000001b3;
        }
        return h;
    }

    pub fn eql(_: CaseFoldedKey, a: []const u8, b: []const u8) bool {
        return std.ascii.eqlIgnoreCase(a, b);
    }
};

const PatternMap = std.HashMapUnmanaged(
    []const u8,
    SigningMatch,
    CaseFoldedKey,
    std.hash_map.default_max_load_percentage,
);

/// One indexed pattern: the signing entry it names and the line that named it.
///
/// `file_index` is what preserves first-match-wins across tiers. Several
/// patterns may match one sender, and the earliest line in the file decides.
const SigningMatch = struct {
    signing_entry: []const u8,
    file_index: u32,
};

/// Which tier can answer a pattern with a hash probe.
const PatternTier = enum { exact, domain, suffix, residual };

/// Loaded SigningTable, indexed by pattern shape.
pub const SigningTable = struct {
    entries: []SigningTableEntry,
    allocator: Allocator,

    /// Keyed by full sender address: "user@specific.com".
    exact_map: PatternMap = .{},
    /// Keyed by sender domain: "*@example.com" as "example.com".
    domain_map: PatternMap = .{},
    /// Keyed by base domain: "*@*.example.com" as "example.com".
    suffix_map: PatternMap = .{},
    /// Ascending indices of patterns no tier can key on: a literal local part
    /// with a wildcard domain ("admin@*.example.com"). Matched by scan.
    residual: []const u32 = &.{},

    pub fn deinit(self: *SigningTable) void {
        // Map keys point into the entries, so only the tables are freed here.
        self.exact_map.deinit(self.allocator);
        self.domain_map.deinit(self.allocator);
        self.suffix_map.deinit(self.allocator);
        self.allocator.free(self.residual);
        for (self.entries) |entry| {
            self.allocator.free(entry.pattern);
            self.allocator.free(entry.signing_entry);
        }
        self.allocator.free(self.entries);
    }

    /// Find the signing entry for a given sender address.
    /// Returns the signing-entry name or null if no match.
    ///
    /// Answers exactly what a file-order scan of every pattern would, at the
    /// cost of one hash probe per tier plus one per label of the sender domain.
    pub fn lookup(self: *const SigningTable, sender: []const u8) ?[]const u8 {
        // A table built without the parser has no index; its rows are still
        // matched, so soundness never depends on who built the table.
        if (self.indexedCount() == 0) return self.scan(sender);

        var best: ?SigningMatch = null;
        consider(&best, self.exact_map.get(sender));

        if (mem.indexOfScalar(u8, sender, '@')) |at| {
            const domain = sender[at + 1 ..];
            consider(&best, self.domain_map.get(domain));

            // "*@*.example.com" matches user@example.com as well as any
            // subdomain, so the sender's own domain is probed before the walk.
            consider(&best, self.suffix_map.get(domain));

            // Every suffix with a non-empty prefix, which is the set a trailing
            // ".base" comparison accepts. Starting at 1 skips a leading dot,
            // whose prefix is empty and which that comparison rejects.
            var pos: usize = 1;
            while (mem.indexOfScalarPos(u8, domain, pos, '.')) |dot| {
                const parent = domain[dot + 1 ..];
                if (parent.len == 0) break;
                consider(&best, self.suffix_map.get(parent));
                pos = dot + 1;
            }
        }

        // Residual indices ascend, so an earlier tier match at a lower index
        // already wins and the first residual match is the best one left.
        for (self.residual) |i| {
            if (best) |b| if (i > b.file_index) break;
            const entry = self.entries[i];
            if (!matchPattern(entry.pattern, sender)) continue;
            best = .{ .signing_entry = entry.signing_entry, .file_index = i };
            break;
        }

        return if (best) |b| b.signing_entry else null;
    }

    fn indexedCount(self: *const SigningTable) usize {
        return self.exact_map.count() + self.domain_map.count() + self.suffix_map.count();
    }

    fn scan(self: *const SigningTable, sender: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (matchPattern(entry.pattern, sender)) return entry.signing_entry;
        }
        return null;
    }
};

/// Keep the match from the earliest line among the tiers that answered.
fn consider(best: *?SigningMatch, found: ?SigningMatch) void {
    const match = found orelse return;
    if (best.*) |current| if (current.file_index <= match.file_index) return;
    best.* = match;
}

/// Half-open range of `KeyTable.entries` holding one signing entry's rows.
const KeyGroup = struct {
    start: u32,
    end: u32,
};

/// Loaded KeyTable.
pub const KeyTable = struct {
    entries: []KeyTableEntry,
    allocator: Allocator,

    /// Signing-entry name to its contiguous range in `entries`. Keys are
    /// borrowed from the rows they point at, so nothing extra is allocated.
    index: std.StringHashMapUnmanaged(KeyGroup) = .{},

    pub fn deinit(self: *KeyTable) void {
        self.index.deinit(self.allocator);
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

    /// Find every row for a signing-entry name, in file order.
    ///
    /// `parseKeyTable` sorts matching rows together and records each group's
    /// range, so this is one hash probe.
    pub fn lookup(self: *const KeyTable, signing_entry: []const u8) []const KeyTableEntry {
        if (self.index.count() == 0) return self.scan(signing_entry);
        const group = self.index.get(signing_entry) orelse return &.{};
        return self.entries[group.start..group.end];
    }

    /// Row scan for a table built without the parser's index. Returns only rows
    /// that carry the requested name, whether or not the rows are grouped.
    fn scan(self: *const KeyTable, signing_entry: []const u8) []const KeyTableEntry {
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

    var table = SigningTable{
        .entries = try entries.toOwnedSlice(allocator),
        .allocator = allocator,
    };
    errdefer table.deinit();
    try indexSigningTable(&table);
    return table;
}

/// File every pattern under the tier that can answer it with a hash probe.
///
/// Only the first row per key is kept: a later row with the same key can never
/// win, because the scan it replaces takes the earliest matching line.
fn indexSigningTable(table: *SigningTable) !void {
    const allocator = table.allocator;
    var residual: std.ArrayList(u32) = .{};
    errdefer residual.deinit(allocator);

    for (table.entries, 0..) |entry, i| {
        const file_index: u32 = @intCast(i);
        const tier = classify(entry.pattern);
        const map = switch (tier) {
            .exact => &table.exact_map,
            .domain => &table.domain_map,
            .suffix => &table.suffix_map,
            .residual => {
                try residual.append(allocator, file_index);
                continue;
            },
        };
        const gop = try map.getOrPut(allocator, tierKey(tier, entry.pattern));
        if (!gop.found_existing) gop.value_ptr.* = .{
            .signing_entry = entry.signing_entry,
            .file_index = file_index,
        };
    }

    table.residual = try residual.toOwnedSlice(allocator);
}

/// Classify a pattern by the shape of its local part and domain.
fn classify(pattern: []const u8) PatternTier {
    // No '@' at all can only ever match a sender literally.
    const at = mem.indexOfScalar(u8, pattern, '@') orelse return .exact;
    const wildcard_domain = mem.startsWith(u8, pattern[at + 1 ..], "*.");
    if (!mem.eql(u8, pattern[0..at], "*")) {
        // A literal local part with a wildcard domain needs both a suffix walk
        // and a local-part comparison, which no single key expresses.
        return if (wildcard_domain) .residual else .exact;
    }
    return if (wildcard_domain) .suffix else .domain;
}

/// The key a pattern is filed under within its tier's map.
fn tierKey(tier: PatternTier, pattern: []const u8) []const u8 {
    if (tier == .exact) return pattern;
    const at = mem.indexOfScalar(u8, pattern, '@').?;
    const domain = pattern[at + 1 ..];
    // ".example.com" and up: the suffix tier is keyed by the base domain.
    return if (tier == .suffix) domain[2..] else domain;
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
    errdefer {
        for (owned) |entry| {
            allocator.free(entry.signing_entry);
            allocator.free(entry.domain);
            allocator.free(entry.selector);
            allocator.free(entry.key_path);
        }
        allocator.free(owned);
    }

    // Stable, so rows keep their file order within a signing entry: multi-sign
    // order decides which signature is added first.
    mem.sort(KeyTableEntry, owned, {}, bySigningEntry);

    var index: std.StringHashMapUnmanaged(KeyGroup) = .{};
    errdefer index.deinit(allocator);
    try indexKeyGroups(allocator, owned, &index);

    return .{
        .entries = owned,
        .allocator = allocator,
        .index = index,
    };
}

fn bySigningEntry(_: void, a: KeyTableEntry, b: KeyTableEntry) bool {
    return mem.lessThan(u8, a.signing_entry, b.signing_entry);
}

/// Record the range of each signing entry's rows in the sorted row list.
fn indexKeyGroups(
    allocator: Allocator,
    items: []const KeyTableEntry,
    index: *std.StringHashMapUnmanaged(KeyGroup),
) !void {
    var start: usize = 0;
    while (start < items.len) {
        const name = items[start].signing_entry;
        var end = start + 1;
        while (end < items.len and mem.eql(u8, items[end].signing_entry, name)) : (end += 1) {}
        // Sorting makes each name contiguous, so a name is recorded once.
        try index.put(allocator, name, .{ .start = @intCast(start), .end = @intCast(end) });
        start = end;
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

    // Soundness first, because it is the worse half: a lookup that takes the index
    // of the first match and a count of all matches, and returns that many rows
    // from there, would span into another signing entry's rows whenever they are
    // not adjacent -- handing out a different domain's signing key under our name.
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

// --- Indexed signing-table lookup ---------------------------------------------
//
// The index answers what a file-order scan of every pattern answers. That is the
// property worth testing, rather than any one tier: a sender that reaches the
// wrong tier is signed with another domain's key, and the tier a pattern lands
// in is decided by `classify` at parse time where no caller can see it.

/// File-order scan, independent of the index. The answer the index must match.
fn referenceLookup(table: *const SigningTable, sender: []const u8) ?[]const u8 {
    for (table.entries) |entry| {
        if (matchPattern(entry.pattern, sender)) return entry.signing_entry;
    }
    return null;
}

fn expectAgreesWithScan(content: []const u8, senders: []const []const u8) !void {
    var table = try parseSigningTable(std.testing.allocator, content);
    defer table.deinit();

    for (senders) |sender| {
        const expected = referenceLookup(&table, sender);
        const actual = table.lookup(sender);
        if (expected) |want| {
            try std.testing.expectEqualStrings(want, actual orelse return error.MissedMatch);
        } else {
            try std.testing.expect(actual == null);
        }
    }
}

test "indexed lookup agrees with a file-order scan on every pattern shape" {
    try expectAgreesWithScan(
        \\admin@specific.com   specific
        \\*@example.com        example
        \\*@*.clients.net      clients
        \\*@*.com              anycom
        \\boss@*.corp.example  boss
        \\bare.pattern         bare
    , &.{
        "admin@specific.com",
        "other@specific.com",
        "user@example.com",
        "user@sub.example.com",
        "user@clients.net",
        "user@deep.sub.clients.net",
        "user@notclients.net",
        "user@example.org",
        "boss@a.corp.example",
        "boss@corp.example",
        "staff@a.corp.example",
        "bare.pattern",
        // Malformed shapes a scan rejects and a suffix walk must reject too.
        // A leading dot is the interesting one: "*@*.clients.net" is a trailing
        // ".clients.net" comparison, which ".clients.net" itself fails.
        "user@.clients.net",
        "user@.example.com",
        "user@example.com.",
        "nodomain",
        "@example.com",
        "",
    });
}

test "indexed lookup keeps first-match-wins across tiers" {
    // Each pair puts a matching pattern in two different tiers, in both orders:
    // the earlier line must win regardless of which tier answered.
    try expectAgreesWithScan(
        \\*@example.com     wildcard
        \\admin@example.com exact
    , &.{ "admin@example.com", "user@example.com" });

    try expectAgreesWithScan(
        \\admin@example.com exact
        \\*@example.com     wildcard
    , &.{ "admin@example.com", "user@example.com" });

    try expectAgreesWithScan(
        \\*@*.example.com suffix
        \\*@example.com   domain
    , &.{ "user@example.com", "user@sub.example.com" });

    try expectAgreesWithScan(
        \\*@*.com         anycom
        \\*@*.example.com suffix
    , &.{ "user@sub.example.com", "user@example.com" });

    // A residual pattern loses to an earlier tier match and wins over a later one.
    try expectAgreesWithScan(
        \\*@a.example      domain
        \\boss@*.a.example residual
    , &.{ "boss@a.example", "boss@sub.a.example" });

    try expectAgreesWithScan(
        \\boss@*.a.example residual
        \\*@a.example      domain
    , &.{ "boss@a.example", "user@a.example" });
}

test "indexed lookup folds case on both the pattern and the sender" {
    const allocator = std.testing.allocator;
    var table = try parseSigningTable(allocator,
        \\Admin@Specific.COM  specific
        \\*@Example.COM       example
        \\*@*.Clients.NET     clients
    );
    defer table.deinit();

    try std.testing.expectEqualStrings("specific", table.lookup("ADMIN@specific.com").?);
    try std.testing.expectEqualStrings("example", table.lookup("User@EXAMPLE.com").?);
    try std.testing.expectEqualStrings("clients", table.lookup("u@Sub.CLIENTS.net").?);
}

test "indexed lookup stores one signing entry per repeated pattern" {
    const allocator = std.testing.allocator;
    // Repeats differing only in case must not each allocate a map slot.
    var table = try parseSigningTable(allocator,
        \\*@example.com  first
        \\*@EXAMPLE.COM  second
        \\*@example.com  third
    );
    defer table.deinit();

    try std.testing.expectEqual(@as(usize, 1), table.domain_map.count());
    try std.testing.expectEqualStrings("first", table.lookup("user@example.com").?);
}

test "signing table lookup is sound on a table the parser did not build" {
    // Same property as the D-7 key-table test: a hand-built table carries no
    // index, and matching must not depend on who built it.
    var rows = [_]SigningTableEntry{
        .{ .pattern = "*@a.example", .signing_entry = "a" },
        .{ .pattern = "*@b.example", .signing_entry = "b" },
    };
    const table = SigningTable{ .entries = &rows, .allocator = std.testing.allocator };

    try std.testing.expectEqualStrings("a", table.lookup("user@a.example").?);
    try std.testing.expectEqualStrings("b", table.lookup("user@b.example").?);
    try std.testing.expect(table.lookup("user@c.example") == null);
}
