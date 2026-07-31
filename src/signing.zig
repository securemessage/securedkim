//! Loading, validating, publishing and consulting the signing configuration.
//!
//! Extracted from main.zig to pay back the ceiling raised for D-24, and because
//! these belong together: what the signing assets ARE, how they are loaded and
//! checked, and which of them applies to a given message. D-24 was precisely the
//! last of those three drifting away from the other two.

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

/// Where the signing configuration is read from.
///
/// Three paths rather than the whole DkimConfig: this module is imported BY
/// main.zig, so depending on a type declared there would be circular, and the
/// narrower argument says plainly what is used.
pub const Paths = struct {
    signing_table: ?[]const u8 = null,
    key_table: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
};

/// The single-domain shorthand, which has no table behind it.
pub const Shorthand = struct {
    domain: ?[]const u8 = null,
    selector: ?[]const u8 = null,
    signed_headers: []const u8 = "from:to:subject:date:message-id",
};

/// Set once at startup and on reload, read by every worker thereafter.
var g_shorthand: Shorthand = .{};

pub fn setShorthand(s: Shorthand) void {
    g_shorthand = s;
}

pub fn signedHeaders() []const u8 {
    return g_shorthand.signed_headers;
}

/// Everything a message needs in order to sign, published as one unit.
///
/// Bundling these is not tidiness. Reloading the table and the key as separate
/// atomic swaps lets a message resolve a domain out of the new SigningTable
/// and then sign it with the previous key. One pointer means a message sees
/// either the whole of the old configuration or the whole of the new one.
///
/// Previously these were three module globals replaced by value on SIGHUP
/// while workers held pointers into them — a torn read, and the old contents
/// (including the EVP_PKEY) were never freed (audit X-2).
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

/// Largest SigningTable/KeyTable we will read.
const MAX_TABLE_BYTES: usize = 1024 * 1024;

fn loadSigningTable(allocator: Allocator, path: []const u8) !keytable.SigningTable {
    // parseSigningTable copies what it keeps, so the file buffer is ours to
    // free. It previously was not freed, leaking the whole file on every read.
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

    // D-24: table-based signing has to be able to actually sign.
    //
    // Every one of these was previously a config that started cleanly and then
    // silently declined to sign, because parameters were resolved from the
    // KeyTable while the key came from somewhere else entirely. A refusal here
    // costs a restart; the silence cost unsigned outbound mail with nothing in
    // the log to say so. On SIGHUP an error is free — `buildSigningAssets` is
    // all-or-nothing, so the running daemon keeps the table it already had.
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

        // A SigningTable row naming an entry the KeyTable does not define is
        // the same silent hole one level up: the sender matches, the lookup
        // finds nothing, and the message goes out unsigned. Catch it while
        // somebody is watching the config, not per message in the dark.
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
    // The signing key is held to the RFC 8301 floor, not to the operator's
    // MinimumKeyBits. That option is a policy about keys *other people* publish;
    // coupling our own key to it would mean tightening the verify policy could
    // stop the daemon starting, which is a surprise nobody asked for. The floor
    // itself is not optional: RFC 8301 §3.2 says signers MUST use at least 1024
    // bits, and mail signed below it fails DKIM at every conformant verifier.
    if (cfg.key_file) |path| {
        var key = crypto.loadRsaKeyFile(path, crypto.RFC8301_MIN_RSA_BITS) catch |err| {
            if (err == error.RsaKeyTooSmall) {
                log.err(
                    "signing key {s} is below the RFC 8301 minimum of {d} bits: refusing to sign with it",
                    .{ path, crypto.RFC8301_MIN_RSA_BITS },
                );
            }
            return err;
        };
        log.info("loaded {d}-bit signing key from {s}", .{ crypto.signingKeyBits(&key), path });
        assets.sign_key = key;
    }

    return assets;
}

/// What to sign a message as, and the key to do it with.
///
/// One type, because they are one decision. D-24 was two functions answering
/// half the question each with nothing holding them together: parameters came
/// from the `KeyTable` while the key came from the single-domain `KeyFile`, so a
/// host with both configured signed `d=b.example` using a.example's key —
/// measured, and caught by key size rather than by anything the daemon said.
pub const Choice = struct {
    params: sign_mod.SigningParams,
    /// Borrowed from `assets`, valid for the rest of this message (see
    /// securemilter `rcu.zig`).
    key: *const crypto.SigningKey,
};

/// Resolve how to sign this message against one snapshot of the signing assets.
///
/// The snapshot is passed in rather than re-read here so that the table
/// consulted and the key used come from the same published configuration.
///
/// **Every branch yields the parameters and the key together or yields
/// nothing.** That is the invariant D-24 lacked, and it is structural now rather
/// than a rule somebody has to remember: there is no way to return a `d=` this
/// function cannot also hand over the matching key for.
pub fn resolve(
    assets: *const Assets,
    domain: []const u8,
    sender: []const u8,
) ?Choice {
    // Single-domain shorthand: d=/s= from config, key from KeyFile.
    if (g_shorthand.domain) |d| {
        if (std.ascii.eqlIgnoreCase(d, domain)) {
            const key = if (assets.sign_key) |*k| k else return null;
            return .{
                .params = .{
                    .domain = d,
                    .selector = g_shorthand.selector orelse "default",
                    .signed_headers = g_shorthand.signed_headers,
                },
                .key = key,
            };
        }
    }

    // SigningTable + KeyTable: d=/s= and the key all come off the same row.
    //
    // The first row with a usable key wins. Multi-sign — a signature per row —
    // is still not implemented, but the single signature now carries the key
    // belonging to the row that named the domain.
    if (assets.signing_table) |*st| {
        const entry_name = st.lookup(sender) orelse return null;
        const kt = if (assets.key_table) |*t| t else return null;
        for (kt.lookup(entry_name)) |*row| {
            const key = if (row.key) |*k| k else continue;
            return .{
                .params = .{
                    .domain = row.domain,
                    .selector = row.selector,
                    .signed_headers = g_shorthand.signed_headers,
                },
                .key = key,
            };
        }
    }

    return null;
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
    // Shorthand configured for a.example, table for b.example. This is the
    // migration-shaped config that produced d=b.example signed with a's key.
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

    // Previously null, which the caller turned into a silent `continue`: the
    // documented multi-domain configuration signed nothing and logged nothing.
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
