//! Load, validate, publish, and resolve DKIM signing configuration.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const log = securemilter.log;
const rcu_mod = securemilter.rcu;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

const keytable = @import("keytable.zig");
const sign_mod = @import("sign.zig");

/// Signing-configuration paths used by this module.
pub const Paths = struct {
    signing_table: ?[]const u8 = null,
    key_table: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
};

/// The single-domain shorthand, which has no table behind it.
pub const Shorthand = struct {
    domain: ?[]const u8 = null,
    selector: ?[]const u8 = null,
    signed_headers: []const u8 = sign_mod.DEFAULT_SIGNED_HEADERS,
    oversign_headers: []const u8 = sign_mod.DEFAULT_OVERSIGN_HEADERS,
};

/// Set once at startup and on reload, read by every worker thereafter.
var g_shorthand: Shorthand = .{};

pub fn setShorthand(s: Shorthand) void {
    g_shorthand = s;
}

pub fn signedHeaders() []const u8 {
    return g_shorthand.signed_headers;
}

/// Signing assets published as one atomic configuration snapshot.
///
/// A message sees either all old assets or all new assets after reload.
pub const Assets = struct {
    signing_table: ?keytable.SigningTable = null,
    key_table: ?keytable.KeyTable = null,
    sign_key: ?crypto.SigningKey = null,
};

pub const Rcu = rcu_mod.Rcu(Assets);
pub fn free(allocator: Allocator, assets: *Assets) void {
    if (assets.signing_table) |*st| st.deinit();
    if (assets.key_table) |*kt| kt.deinit();
    if (assets.sign_key) |*k| k.deinit();
    allocator.destroy(assets);
}

const build_options = @import("build_options");

/// Largest SigningTable/KeyTable we will read. Adjustable at compile time with
/// `-Dmax-table-bytes=<n>` to support deployments with more domains than the
/// default 1 MiB accommodates.
const MAX_TABLE_BYTES: usize = build_options.max_table_bytes;

fn loadSigningTable(allocator: Allocator, path: []const u8) !keytable.SigningTable {
    // The parser copies retained fields, so the file buffer is released here.
    const content = try std.fs.cwd().readFileAlloc(allocator, path, MAX_TABLE_BYTES);
    defer allocator.free(content);
    return keytable.parseSigningTable(allocator, content);
}

fn loadKeyTable(allocator: Allocator, path: []const u8) !keytable.KeyTable {
    const content = try std.fs.cwd().readFileAlloc(allocator, path, MAX_TABLE_BYTES);
    defer allocator.free(content);
    return keytable.parseKeyTable(allocator, content);
}

/// Build a complete set of signing assets from a parsed config.
///
/// All or nothing: if any piece fails to load the caller keeps the previous
/// set, rather than running on a half-updated mixture.
pub fn build(allocator: Allocator, cfg: Paths) !*Assets {
    const assets = try allocator.create(Assets);
    assets.* = .{};
    errdefer free(allocator, assets);

    if (cfg.signing_table) |path| assets.signing_table = try loadSigningTable(allocator, path);
    if (cfg.key_table) |path| assets.key_table = try loadKeyTable(allocator, path);

    // Table signing requires both tables; failed reloads retain the prior
    // published asset snapshot.
    if (assets.signing_table != null and assets.key_table == null) {
        log.err("SigningTable is set without a KeyTable: nothing can be signed through it", .{});
        return error.SigningTableWithoutKeyTable;
    }
    if (assets.key_table != null and assets.signing_table == null) {
        log.err("KeyTable is set without a SigningTable: the key table can never be consulted", .{});
        return error.KeyTableWithoutSigningTable;
    }

    if (assets.key_table) |*kt| {
        var failed_path: []const u8 = "";
        kt.loadKeys(crypto.RFC8301_MIN_RSA_BITS, &failed_path) catch |err| {
            if (err == error.RsaKeyTooSmall) {
                log.err(
                    "KeyTable key {s} is below the RFC 8301 minimum of {d} bits: refusing to sign with it",
                    .{ failed_path, crypto.RFC8301_MIN_RSA_BITS },
                );
            } else {
                log.err("KeyTable key {s} could not be loaded: {}", .{ failed_path, err });
            }
            return err;
        };
        log.info("loaded {d} KeyTable signing key(s)", .{kt.entries.len});

        // Every SigningTable entry must resolve to at least one KeyTable row.
        if (assets.signing_table) |*st| {
            for (st.entries) |entry| {
                if (kt.lookup(entry.signing_entry).len == 0) {
                    log.err(
                        "SigningTable pattern {s} maps to signing entry {s}, which the KeyTable does not define",
                        .{ entry.pattern, entry.signing_entry },
                    );
                    return error.SigningEntryHasNoKey;
                }
            }
        }
    }
    // Signing keys use the RFC 8301 minimum, independent of the verifier's
    // `MinimumKeyBits` policy.
    if (cfg.key_file) |path| {
        var key = crypto.loadRsaKeyFile(path, crypto.RFC8301_MIN_RSA_BITS, .require_safe) catch |err| {
            if (err == error.RsaKeyTooSmall) {
                log.err(
                    "signing key {s} is below the RFC 8301 minimum of {d} bits: refusing to sign with it",
                    .{ path, crypto.RFC8301_MIN_RSA_BITS },
                );
            } else if (err == error.KeyFilePermissionsTooOpen) {
                log.err("signing key {s} is mode {o}, {s}", .{
                    path,
                    crypto.keyFileMode(path) catch 0,
                    crypto.KEY_PERMISSIONS_ADVICE,
                });
            }
            return err;
        };
        log.info("loaded {d}-bit signing key from {s}", .{ crypto.signingKeyBits(&key), path });
        assets.sign_key = key;
    }

    return assets;
}

/// Signing parameters and the matching key for one message.
pub const Choice = struct {
    params: sign_mod.SigningParams,
    /// Borrowed from `assets`, valid for the rest of this message (see
    /// securemilter `rcu.zig`).
    key: *const crypto.SigningKey,
};

/// Resolve signing parameters and a key from one asset snapshot.
///
/// A result always contains a matching key and parameter set.
pub fn resolve(
    assets: *const Assets,
    domain: []const u8,
    sender: []const u8,
) ?Choice {
    const all = resolveAll(assets, domain, sender);
    if (all.len == 0) return null;
    return all.get(0);
}

/// Maximum concurrent signing keys per domain. Covers rotation (old + new)
/// and algorithm migration (RSA + Ed25519) simultaneously.
pub const MAX_MULTI_SIGN = 8;

pub const ChoiceList = struct {
    buf: [MAX_MULTI_SIGN]Choice = undefined,
    len: usize = 0,

    pub fn slice(self: *const ChoiceList) []const Choice {
        return self.buf[0..self.len];
    }

    pub fn get(self: *const ChoiceList, i: usize) Choice {
        std.debug.assert(i < self.len);
        return self.buf[i];
    }

    fn push(self: *ChoiceList, choice: Choice) void {
        if (self.len < MAX_MULTI_SIGN) {
            self.buf[self.len] = choice;
            self.len += 1;
        } else {
            log.warn(
                "more than {d} signing keys for {s}/{s}: excess key ignored",
                .{ MAX_MULTI_SIGN, choice.params.domain, choice.params.selector },
            );
        }
    }
};

/// Resolve ALL matching signing keys for a sender from one asset snapshot.
///
/// RFC 6376 Section 4 allows multiple DKIM-Signature headers per message.
/// During key rotation both the old and new selectors should sign, so
/// receivers can verify whichever signature matches their cached DNS record.
///
/// Returns every KeyTable row with a usable key for the sender's signing
/// entry, in file order. The shorthand (single-domain) path produces at
/// most one choice.
pub fn resolveAll(
    assets: *const Assets,
    domain: []const u8,
    sender: []const u8,
) ChoiceList {
    var list = ChoiceList{};

    // Single-domain shorthand: d=/s= from config, key from KeyFile.
    // Only one key is possible in this mode.
    if (g_shorthand.domain) |d| {
        if (std.ascii.eqlIgnoreCase(d, domain)) {
            const key = if (assets.sign_key) |*k| k else return list;
            list.push(.{
                .params = .{
                    .domain = d,
                    .selector = g_shorthand.selector orelse "default",
                    .signed_headers = g_shorthand.signed_headers,
                    .oversign_headers = g_shorthand.oversign_headers,
                },
                .key = key,
            });
            return list;
        }
    }

    // SigningTable + KeyTable: d=/s= and the key all come off the same row.
    // Every row with a usable key produces a signature (multi-sign).
    if (assets.signing_table) |*st| {
        const entry_name = st.lookup(sender) orelse return list;
        const kt = if (assets.key_table) |*t| t else return list;
        for (kt.lookup(entry_name)) |*row| {
            const key = if (row.key) |*k| k else continue;
            list.push(.{
                .params = .{
                    .domain = row.domain,
                    .selector = row.selector,
                    .signed_headers = g_shorthand.signed_headers,
                    .oversign_headers = g_shorthand.oversign_headers,
                },
                .key = key,
            });
        }
    }

    return list;
}

// =============================================================================
// Tests
// =============================================================================

// --- D-24: the d= and the key must come off the same row ----------------------
//
// These need to tell two keys apart, not use them, and `resolve` never
// dereferences the key it returns -- so the keys here are distinguishable
// sentinels rather than real ones. That keeps the test about resolution, which
// is where the defect was, and off OpenSSL entirely.
//
// The tables are built by hand and never deinit'd: every string is a literal
// and no key holds an EVP_PKEY, so there is nothing to free.

const D24_SHORTHAND_SEED: [32]u8 = @splat(0xAA);
const D24_TABLE_SEED: [32]u8 = @splat(0xBB);

// Goes through `loadEd25519Seed` rather than building the struct literally: the
// keypair is the only copy of the secret now (audit C-2), so a literal would leave
// it null and the sentinel would be indistinguishable from an unset key.
fn d24Key(seed: [32]u8) crypto.SigningKey {
    return crypto.loadEd25519Seed(seed) catch unreachable;
}

// Which sentinel a resolved key is, recovered from the derived keypair.
fn d24SeedOf(key: *const crypto.SigningKey) [32]u8 {
    return key.ed25519_key_pair.?.secret_key.seed();
}

test "D-24: a sender matched by the KeyTable is signed with that row's key" {
    const saved = g_shorthand;
    defer g_shorthand = saved;
    // Shorthand and table configuration deliberately select different domains.
    g_shorthand = .{ .domain = "a.example", .selector = "sela" };

    var st_rows = [_]keytable.SigningTableEntry{
        .{ .pattern = "*@b.example", .signing_entry = "b.example" },
    };
    var kt_rows = [_]keytable.KeyTableEntry{
        .{
            .signing_entry = "b.example",
            .domain = "b.example",
            .selector = "selb",
            .key_path = "/k/b",
            .key = d24Key(D24_TABLE_SEED),
        },
    };
    const assets = Assets{
        .signing_table = .{ .entries = &st_rows, .allocator = std.testing.allocator },
        .key_table = .{ .entries = &kt_rows, .allocator = std.testing.allocator },
        .sign_key = d24Key(D24_SHORTHAND_SEED),
    };

    const choice = resolve(&assets, "b.example", "user@b.example").?;
    try std.testing.expectEqualStrings("b.example", choice.params.domain);
    try std.testing.expectEqualStrings("selb", choice.params.selector);
    // The half that was broken: the right d= with the wrong key still fails at
    // every verifier, and nothing in the header would show it.
    try std.testing.expectEqual(D24_TABLE_SEED, d24SeedOf(choice.key));
}

test "D-24: a KeyTable-only config resolves a key instead of declining" {
    const saved = g_shorthand;
    defer g_shorthand = saved;
    g_shorthand = .{}; // no shorthand at all -- the sample's multi-domain stanza

    var st_rows = [_]keytable.SigningTableEntry{
        .{ .pattern = "*@b.example", .signing_entry = "b.example" },
    };
    var kt_rows = [_]keytable.KeyTableEntry{
        .{
            .signing_entry = "b.example",
            .domain = "b.example",
            .selector = "selb",
            .key_path = "/k/b",
            .key = d24Key(D24_TABLE_SEED),
        },
    };
    const assets = Assets{
        .signing_table = .{ .entries = &st_rows, .allocator = std.testing.allocator },
        .key_table = .{ .entries = &kt_rows, .allocator = std.testing.allocator },
        .sign_key = null,
    };

    // A null result here would let the caller silently `continue`, so the
    // documented multi-domain configuration (KeyTable with no shorthand key)
    // must still resolve rather than signing nothing with no log line.
    const choice = resolve(&assets, "b.example", "user@b.example").?;
    try std.testing.expectEqualStrings("b.example", choice.params.domain);
    try std.testing.expectEqual(D24_TABLE_SEED, d24SeedOf(choice.key));
}

test "D-24: a keyless row declines rather than borrowing the shorthand key" {
    const saved = g_shorthand;
    defer g_shorthand = saved;
    g_shorthand = .{ .domain = "a.example", .selector = "sela" };

    var st_rows = [_]keytable.SigningTableEntry{
        .{ .pattern = "*@b.example", .signing_entry = "b.example" },
    };
    // Key loading now fails the whole config load, so this state should be
    // unreachable in production. The invariant is asserted anyway: declining is
    // survivable, signing b.example with a.example's key is not, and the next
    // person to add a lazy-loading path should find that written down as a test.
    var kt_rows = [_]keytable.KeyTableEntry{
        .{
            .signing_entry = "b.example",
            .domain = "b.example",
            .selector = "selb",
            .key_path = "/k/b",
            .key = null,
        },
    };
    const assets = Assets{
        .signing_table = .{ .entries = &st_rows, .allocator = std.testing.allocator },
        .key_table = .{ .entries = &kt_rows, .allocator = std.testing.allocator },
        .sign_key = d24Key(D24_SHORTHAND_SEED),
    };

    try std.testing.expect(resolve(&assets, "b.example", "user@b.example") == null);
}

// --- Multi-sign: resolveAll returns every usable key for a signing entry ------

const D24_ROTATE_SEED: [32]u8 = @splat(0xCC);

test "resolveAll returns multiple keys for multi-sign during rotation" {
    const saved = g_shorthand;
    defer g_shorthand = saved;
    g_shorthand = .{};

    var st_rows = [_]keytable.SigningTableEntry{
        .{ .pattern = "*@example.com", .signing_entry = "example.com" },
    };
    // Two keys for the same signing entry: rotation overlap.
    var kt_rows = [_]keytable.KeyTableEntry{
        .{
            .signing_entry = "example.com",
            .domain = "example.com",
            .selector = "sm2026",
            .key_path = "/k/old",
            .key = d24Key(D24_TABLE_SEED),
        },
        .{
            .signing_entry = "example.com",
            .domain = "example.com",
            .selector = "sm2026r1",
            .key_path = "/k/new",
            .key = d24Key(D24_ROTATE_SEED),
        },
    };
    const assets = Assets{
        .signing_table = .{ .entries = &st_rows, .allocator = std.testing.allocator },
        .key_table = .{ .entries = &kt_rows, .allocator = std.testing.allocator },
        .sign_key = null,
    };

    const choices = resolveAll(&assets, "example.com", "user@example.com");
    try std.testing.expectEqual(@as(usize, 2), choices.len);
    try std.testing.expectEqualStrings("sm2026", choices.get(0).params.selector);
    try std.testing.expectEqualStrings("sm2026r1", choices.get(1).params.selector);
    try std.testing.expectEqual(D24_TABLE_SEED, d24SeedOf(choices.get(0).key));
    try std.testing.expectEqual(D24_ROTATE_SEED, d24SeedOf(choices.get(1).key));
}

test "resolveAll skips rows with null keys in multi-sign" {
    const saved = g_shorthand;
    defer g_shorthand = saved;
    g_shorthand = .{};

    var st_rows = [_]keytable.SigningTableEntry{
        .{ .pattern = "*@example.com", .signing_entry = "example.com" },
    };
    var kt_rows = [_]keytable.KeyTableEntry{
        .{
            .signing_entry = "example.com",
            .domain = "example.com",
            .selector = "sm2026",
            .key_path = "/k/old",
            .key = d24Key(D24_TABLE_SEED),
        },
        .{
            .signing_entry = "example.com",
            .domain = "example.com",
            .selector = "sm2026r1",
            .key_path = "/k/new",
            .key = null, // key failed to load
        },
    };
    const assets = Assets{
        .signing_table = .{ .entries = &st_rows, .allocator = std.testing.allocator },
        .key_table = .{ .entries = &kt_rows, .allocator = std.testing.allocator },
        .sign_key = null,
    };

    const choices = resolveAll(&assets, "example.com", "user@example.com");
    try std.testing.expectEqual(@as(usize, 1), choices.len);
    try std.testing.expectEqualStrings("sm2026", choices.get(0).params.selector);
}

test "resolveAll with shorthand returns single choice" {
    const saved = g_shorthand;
    defer g_shorthand = saved;
    g_shorthand = .{ .domain = "a.example", .selector = "sela" };

    const assets = Assets{
        .sign_key = d24Key(D24_SHORTHAND_SEED),
    };

    const choices = resolveAll(&assets, "a.example", "user@a.example");
    try std.testing.expectEqual(@as(usize, 1), choices.len);
    try std.testing.expectEqualStrings("a.example", choices.get(0).params.domain);
    try std.testing.expectEqualStrings("sela", choices.get(0).params.selector);
}

test "ChoiceList.push logs warning on overflow past MAX_MULTI_SIGN" {
    var list = ChoiceList{};
    const dummy_key = d24Key(D24_TABLE_SEED);
    const choice = Choice{
        .params = .{ .domain = "x.example", .selector = "sel" },
        .key = &dummy_key,
    };
    // Fill to capacity
    for (0..MAX_MULTI_SIGN) |_| list.push(choice);
    try std.testing.expectEqual(MAX_MULTI_SIGN, list.len);
    // Push beyond capacity: len stays at MAX_MULTI_SIGN (logged, not crashed)
    list.push(choice);
    try std.testing.expectEqual(MAX_MULTI_SIGN, list.len);
}

test "ChoiceList.get asserts on out-of-bounds in safe mode" {
    var list = ChoiceList{};
    const dummy_key = d24Key(D24_TABLE_SEED);
    list.push(.{
        .params = .{ .domain = "x.example", .selector = "sel" },
        .key = &dummy_key,
    });
    // Valid access
    try std.testing.expectEqualStrings("x.example", list.get(0).params.domain);
    // Out-of-bounds in safe mode would assert; we cannot test that without
    // crashing, so just verify the valid access works.
}

test "resolveAll returns empty for no match" {
    const saved = g_shorthand;
    defer g_shorthand = saved;
    g_shorthand = .{};

    const assets = Assets{
        .sign_key = null,
    };

    const choices = resolveAll(&assets, "unknown.example", "user@unknown.example");
    try std.testing.expectEqual(@as(usize, 0), choices.len);
}
