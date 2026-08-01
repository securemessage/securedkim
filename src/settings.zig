//! SecureDKIM configuration: listener modes, the `l=` tag policy, and the parser
//! that turns an INI file into a `DkimConfig`.
//!
//! Split out of `main.zig`, which was the largest file in the suite at 1008
//! production lines against a 400-line goal. This is the same seam `securearc`
//! took: nothing in here touches the daemon's global state, so the whole layer is
//! pure parsing and is testable without a listener, a worker or a resolver.
//!
//! The daemon re-exports every name at its old spelling, so the move is not a
//! rename at any call site.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const connection_mod = securemilter.connection;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

const sign = @import("sign.zig");
const verify = @import("verify.zig");

/// Listener mode for DKIM processing.
pub const Mode = enum {
    sign_only,
    verify_only,
    both,
};

/// Parse a `Mode` value from a config section.
///
/// An unrecognised value is an error rather than a silent fallback: the
/// previous parser tested three spellings and left the variable untouched on
/// anything else, so `Mode = signing` ran a signing listener in verify mode
/// and said nothing.
pub fn parseMode(raw: []const u8) error{InvalidMode}!Mode {
    if (mem.eql(u8, raw, "sign")) return .sign_only;
    if (mem.eql(u8, raw, "verify")) return .verify_only;
    if (mem.eql(u8, raw, "both")) return .both;
    return error.InvalidMode;
}

/// Config-facing spelling of a mode, for logs.
///
/// The enum tags carry an `_only` suffix that appears neither in the config file
/// nor in the documented log format, and operators grep these lines — the d4
/// pentest probe greps for `mode=verify` by name. Kept identical to the accepted
/// `Mode =` values so a log line reads back as the config that produced it.
pub fn modeLabel(m: Mode) []const u8 {
    return switch (m) {
        .sign_only => "sign",
        .verify_only => "verify",
        .both => "both",
    };
}

/// Parse `BodyLengthTag`, which decides what a signature's `l=` tag means here.
///
/// Rejected rather than defaulted on a typo, for the same reason `Mode` is: this
/// selects between accepting a body whose tail nobody signed and refusing it, and
/// quietly picking one because the operator misspelled the other is not a choice
/// this daemon should make on their behalf.
pub fn parseBodyLengthTag(raw: []const u8) error{InvalidBodyLengthTag}!verify.BodyLengthPolicy {
    if (mem.eql(u8, raw, "honor")) return .honor;
    if (mem.eql(u8, raw, "honour")) return .honor;
    if (mem.eql(u8, raw, "refuse")) return .refuse;
    return error.InvalidBodyLengthTag;
}

/// SecureDKIM runtime configuration.
pub const DkimConfig = struct {
    authserv_id: []const u8,
    listen_addresses: []const listener_mod.ListenAddress,
    worker_threads: u32,
    pid_file: []const u8,
    foreground: bool,
    user: ?[]const u8,
    dns_nameservers: []const []const u8,
    dns_timeout_ms: u32,
    dns_retries: u8,
    dns_cache_size: u32,
    dns_negative_ttl: u32,
    /// Mode per listener, index-parallel to `listen_addresses` (audit A-2).
    ///
    /// Sharing one value across sockets is worse here than in `securearc`: if
    /// a `Mode = sign` section is declared last it applied to the inbound
    /// socket too, and a spoof of our own domain arriving from the internet
    /// would match the signing table and be handed a valid signature under our
    /// own key — `dkim=pass` aligned with `From`, hence `dmarc=pass` against
    /// our own `p=reject`.
    modes: []const Mode,
    signing_table_path: ?[]const u8,
    key_table_path: ?[]const u8,
    // Single-domain shorthand
    sign_domain: ?[]const u8,
    sign_selector: ?[]const u8,
    sign_key_file: ?[]const u8,
    signed_headers: []const u8,
    oversign_headers: []const u8,
    strip_auth_results: bool,
    zmq_endpoint: ?[]const u8,
    zmq_topic: []const u8,
    limits: connection_mod.Limits,
    min_key_bits: crypto.MinRsaBits,
    /// What a verified signature's `l=` tag means here (audit D-5).
    body_length_policy: verify.BodyLengthPolicy,
    /// Key records tried at one selector before giving up (audit D-20).
    max_key_records: u8,
};

pub fn parseDkimConfig(allocator: Allocator, cfg: *const config_mod.Config) !DkimConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    // EVERY VALUE THAT CAN BE REJECTED FOR ITS CONTENT IS VALIDATED HERE, BEFORE
    // THE FIRST ALLOCATION. Not style: a validation failure below the allocations
    // has to unwind them, and one of them is a plain owned slice rather than an
    // ArrayList with an `errdefer`, so it does not unwind itself.
    //
    // `BodyLengthTag` used to be parsed at the far end of this function, after
    // `dns_nameservers` had been taken out of its ArrayList. A typo there leaked
    // that slice — and because `reloadConfig` frees those slices only on the path
    // where it got a config back, the leak repeated on every SIGHUP for as long
    // as the typo stayed in the file.
    //
    // `securearc` hit exactly this with `On-DNSError` and fixed it by moving the
    // validation up. The comment recording that lesson lived in the file that had
    // already learned it, so this daemon reintroduced the shape when
    // `BodyLengthTag` was added. Hence both halves here and an `errdefer` below:
    // the ordering is the fix, the `errdefer` is what holds when someone adds the
    // next `try`.
    //
    // RFC 6376 §3.5 says to honour l=; §8.2 says a verifier may refuse signatures
    // that carry it. Both are legitimate, so it is the operator's call.
    const body_length_policy: verify.BodyLengthPolicy = if (global.get("BodyLengthTag")) |raw|
        try parseBodyLengthTag(raw)
    else
        .honor;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);
    const pid_file = global.getOrDefault("PidFile", "/var/run/securedkim/securedkim.pid");
    const foreground_val = global.getBool("Foreground", false);
    const user = global.get("User");

    var addrs: std.ArrayListUnmanaged(listener_mod.ListenAddress) = .{};
    errdefer addrs.deinit(allocator);
    var modes: std.ArrayListUnmanaged(Mode) = .{};
    errdefer modes.deinit(allocator);

    // A `[global] Mode` supplies the default for any listener that does not
    // name one, so single-socket configs keep working unchanged.
    const default_mode: Mode = if (global.get("Mode")) |raw|
        try parseMode(raw)
    else
        .verify_only;

    var signing_table_path: ?[]const u8 = null;
    var key_table_path: ?[]const u8 = null;
    var sign_domain: ?[]const u8 = null;
    var sign_selector: ?[]const u8 = null;
    var sign_key_file: ?[]const u8 = null;

    for (cfg.section_order.items) |section_name| {
        if (mem.startsWith(u8, section_name, "listener:")) {
            const section = cfg.getSection(section_name) orelse continue;

            // X-14: a malformed or missing Socket is refused, not skipped.
            const addr = try listener_mod.parseListenerSocket(section_name, section.get("Socket"));
            try addrs.append(allocator, addr);

            // Appended in lockstep with `addrs`, so the index the worker
            // records on a connection selects this listener's own mode.
            const listener_mode: Mode = if (section.get("Mode")) |raw|
                try parseMode(raw)
            else
                default_mode;
            try modes.append(allocator, listener_mode);

            // Per-listener signing config
            signing_table_path = section.get("SigningTable") orelse signing_table_path;
            key_table_path = section.get("KeyTable") orelse key_table_path;
            sign_domain = section.get("Domain") orelse sign_domain;
            sign_selector = section.get("Selector") orelse sign_selector;
            sign_key_file = section.get("KeyFile") orelse sign_key_file;
        }
    }

    // Loopback, NOT 0.0.0.0. The milter protocol has no authentication, so anything
    // that reaches this socket is trusted absolutely. The stakes here are the
    // highest of the four daemons: on a sign listener a reachable port is an
    // unauthenticated signing oracle -- anyone can have arbitrary mail DKIM-signed
    // as the configured domain, which is the whole guarantee DKIM exists to make.
    // Postfix is the only intended client and it is local.
    //
    // A-2 was re-rated High because an instance of THIS daemon had its public
    // inbound socket in sign mode. Wide binding must be written down deliberately,
    // not inherited from an omitted config section.
    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "127.0.0.1", .port = 8891 } });
        try modes.append(allocator, default_mode);
    }

    // `modeFor` indexes `modes` with a listener index, so the two lists falling
    // out of step would silently mis-mode every socket above the shorter one.
    std.debug.assert(addrs.items.len == modes.items.len);

    // Owned slice, borrowed contents -- and unlike the ArrayLists above it does
    // not unwind itself, so it needs its own `errdefer`. Every `try` below this
    // line depends on that; `BodyLengthTag` was one such `try` until its
    // validation moved to the top of this function.
    const dns_nameservers = try global.getCsvList(allocator, "DnsNameserver", "127.0.0.1");
    errdefer allocator.free(dns_nameservers);
    const dns_timeout = global.getInt("DnsTimeout", u32, 5) * 1000;
    const dns_retries = global.getInt("DnsRetries", u8, 2);
    const dns_cache_size = global.getInt("DnsCacheSize", u32, 1000);
    const dns_negative_ttl = global.getInt("DnsNegativeTTL", u32, 60);
    const signed_headers = global.getOrDefault("SignedHeaders", sign.DEFAULT_SIGNED_HEADERS);

    // Spelled as OpenDKIM spells it, so a migrated opendkim.conf line works
    // verbatim. Empty disables oversigning (audit D-12).
    const oversign_headers = global.getOrDefault("OverSignHeaders", sign.DEFAULT_OVERSIGN_HEADERS);

    // A rotation legitimately publishes two key records at once, so taking only
    // the first broke whichever half DNS listed second (audit D-20). Bounded
    // because the count is the zone owner's choice and each record costs another
    // public-key verification.
    const max_key_records = global.getInt("MaxKeyRecords", u8, verify.DEFAULT_MAX_KEY_RECORDS);

    // Trust boundary: when this is the first milter in the chain, no A-R header
    // claiming our authserv-id can be genuine on arrival (RFC 8601 §5).
    const strip_auth_results = global.getBool("StripAuthResults", false);

    // Caps on attacker-controlled message content (audit X-4, D-4).
    const limits = connection_mod.Limits.fromSection(global);

    // Smallest RSA key we will accept from a signer (audit C-3). The floor is
    // the RFC's, not ours, so a configured value below it is raised rather than
    // honoured.
    const min_key_bits = crypto.resolveMinRsaBits(
        global.getInt(crypto.MIN_KEY_BITS_OPTION, u32, crypto.RFC8301_MIN_RSA_BITS),
    );

    // ZMQ event publishing
    const zmq_endpoint = global.get("ZmqEndpoint");
    const zmq_topic = global.getOrDefault("ZmqTopic", "dkim");

    return .{
        .authserv_id = authserv_id,
        .listen_addresses = try addrs.toOwnedSlice(allocator),
        .worker_threads = workers,
        .pid_file = pid_file,
        .foreground = foreground_val,
        .user = user,
        .dns_nameservers = dns_nameservers,
        .dns_timeout_ms = dns_timeout,
        .dns_retries = dns_retries,
        .dns_cache_size = dns_cache_size,
        .dns_negative_ttl = dns_negative_ttl,
        .modes = try modes.toOwnedSlice(allocator),
        .signing_table_path = signing_table_path,
        .key_table_path = key_table_path,
        .sign_domain = sign_domain,
        .sign_selector = sign_selector,
        .sign_key_file = sign_key_file,
        .signed_headers = signed_headers,
        .oversign_headers = oversign_headers,
        .strip_auth_results = strip_auth_results,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
        .limits = limits,
        .min_key_bits = min_key_bits,
        .body_length_policy = body_length_policy,
        .max_key_records = max_key_records,
    };
}

// =============================================================================
// Tests
// =============================================================================

// `parseDkimConfig` had no tests at all, which is why A-2 survived here after
// being written up against `securearc`.
//
// CAUTION: this frees the parsed config before returning, so anything in the result
// that BORROWS from it dangles. Safe for `modes` and slice lengths, which is all the
// existing callers touch. NOT safe for a listener host from a `Socket =` line -- the
// tests below that inspect host strings parse inline and keep `cfg` alive instead.
fn parseForTest(ini_text: []const u8) !DkimConfig {
    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();
    return parseDkimConfig(std.testing.allocator, &cfg);
}

fn freeTestConfig(dkim_cfg: DkimConfig) void {
    std.testing.allocator.free(dkim_cfg.listen_addresses);
    std.testing.allocator.free(dkim_cfg.modes);
    std.testing.allocator.free(dkim_cfg.dns_nameservers);
}

// The leak that this file's reordering exists to prevent. `std.testing.allocator`
// fails the test on an outstanding allocation, so the assertion is the absence of
// a leak report rather than anything written here.
//
// Teeth: move the `BodyLengthTag` parse back below `dns_nameservers` AND drop the
// `errdefer`, and this reports "memory address ... leaked" pointing at
// `toOwnedSlice`. Either one alone is enough to keep it green, which is why both
// are present -- the ordering can be undone by a future edit that has no idea it
// mattered, and the `errdefer` is what survives that.
test "an invalid BodyLengthTag does not leak the nameserver list" {
    try std.testing.expectError(error.InvalidBodyLengthTag, parseForTest(
        \\[global]
        \\BodyLengthTag = mabye
    ));
}

// An unrecognised value is refused rather than defaulted, on both spellings of
// the option that has one.
test "BodyLengthTag accepts both spellings and refuses a typo" {
    try std.testing.expectEqual(verify.BodyLengthPolicy.honor, try parseBodyLengthTag("honor"));
    try std.testing.expectEqual(verify.BodyLengthPolicy.honor, try parseBodyLengthTag("honour"));
    try std.testing.expectEqual(verify.BodyLengthPolicy.refuse, try parseBodyLengthTag("refuse"));

    try std.testing.expectError(error.InvalidBodyLengthTag, parseBodyLengthTag("Honor"));
    try std.testing.expectError(error.InvalidBodyLengthTag, parseBodyLengthTag(""));
}

// X-14. A malformed Socket must be refused rather than skipped. Safe through
// `parseForTest` despite its borrowing caveat above, because the failure path
// returns no config to read from.
test "a malformed listener Socket is refused, not replaced by the default" {
    try std.testing.expectError(error.InvalidListenerSocket, parseForTest(
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:typo]
        \\Socket = inet6:8891@::1
        \\Mode = verify
    ));
}

test "a hostname in Socket is refused at config time" {
    try std.testing.expectError(error.InvalidListenerSocket, parseForTest(
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:main]
        \\Socket = inet:8891@localhost
    ));
}

test "a listener section with no Socket is refused" {
    try std.testing.expectError(error.MissingListenerSocket, parseForTest(
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:empty]
        \\Mode = verify
    ));
}

// The worst consequence of the silent skip, and the reason this is not merely
// tidiness. `[global] Mode` is a documented way to supply the default for a
// listener that names none, so on a signing instance it is `sign`. A typo in the
// *only* listener's Socket emptied the address list, the loopback fallback fired,
// and the fallback takes `default_mode` -- so a listener written as `verify` came
// up in `sign` mode. That is an unauthenticated signing oracle reachable by any
// local process, assembled entirely out of one mistyped character.
//
// X-13's note beside that fallback asks for a wide bind to be "written down
// deliberately, not inherited from an omitted config section". A typo made the
// section omitted, which is the case it did not consider.
test "a typo cannot silently invert a verify listener into a signing one" {
    try std.testing.expectError(error.InvalidListenerSocket, parseForTest(
        \\[global]
        \\AuthservID = mail.test.com
        \\Mode = sign
        \\
        \\[listener:verify]
        \\Socket = inet6:8891@::1
        \\Mode = verify
    ));
}

// The implicit listener binds loopback, never 0.0.0.0.
//
// Until 2026-07-29 it bound 0.0.0.0 and NOTHING TESTED IT, in any of the four
// daemons -- a config-less run silently offered an unauthenticated signing oracle
// on every interface. The milter protocol has no authentication, so a reachable
// sign-mode port lets anyone have arbitrary mail signed as the configured domain.
//
// Pinned per daemon rather than once in the library because each hardcodes its own
// fallback, so one of them can regress alone.
test "the implicit listener binds loopback, not every interface" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
    );
    defer cfg.deinit();

    const dkim_cfg = try parseDkimConfig(std.testing.allocator, &cfg);
    defer freeTestConfig(dkim_cfg);

    try std.testing.expectEqual(@as(usize, 1), dkim_cfg.listen_addresses.len);
    switch (dkim_cfg.listen_addresses[0]) {
        .tcp => |tcp| {
            try std.testing.expectEqualStrings("127.0.0.1", tcp.host);
            try std.testing.expectEqual(@as(u16, 8891), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

// An explicit wide bind is still honoured: this is a safe DEFAULT, not a policy
// that overrides the operator. Removing this test would let a future "harden the
// listener" change quietly break every deployment that needs a routable socket
// because Postfix runs in a different jail.
test "an explicit 0.0.0.0 socket is still honoured" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:wide]
        \\Socket = inet:8891@0.0.0.0
        \\Mode = verify
    );
    defer cfg.deinit();

    const dkim_cfg = try parseDkimConfig(std.testing.allocator, &cfg);
    defer freeTestConfig(dkim_cfg);

    switch (dkim_cfg.listen_addresses[0]) {
        .tcp => |tcp| try std.testing.expectEqualStrings("0.0.0.0", tcp.host),
        else => return error.TestUnexpectedResult,
    }
}

// A-2 regression, and the reason this instance is worse than securearc's: with
// one shared `mode`, declaring the signing listener last put the INBOUND socket
// into sign mode. A spoof of our own domain arriving from the internet then
// matched the signing table and was handed a valid signature under our own key.
test "each listener keeps its own mode" {
    const dkim_cfg = try parseForTest(
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:verify]
        \\Socket = inet:8891@0.0.0.0
        \\Mode = verify
        \\
        \\[listener:sign]
        \\Socket = inet:8892@127.0.0.1
        \\Mode = sign
    );
    defer freeTestConfig(dkim_cfg);

    try std.testing.expectEqual(@as(usize, 2), dkim_cfg.listen_addresses.len);
    try std.testing.expectEqual(dkim_cfg.listen_addresses.len, dkim_cfg.modes.len);
    try std.testing.expectEqual(Mode.verify_only, dkim_cfg.modes[0]);
    try std.testing.expectEqual(Mode.sign_only, dkim_cfg.modes[1]);
}

// The dangerous ordering specifically: signing declared first, verify second.
// The old parser left BOTH in verify mode here, so outbound mail went unsigned.
test "signing listener declared first still signs" {
    const dkim_cfg = try parseForTest(
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:sign]
        \\Socket = inet:8892@127.0.0.1
        \\Mode = sign
        \\
        \\[listener:verify]
        \\Socket = inet:8891@0.0.0.0
        \\Mode = verify
    );
    defer freeTestConfig(dkim_cfg);

    try std.testing.expectEqual(Mode.sign_only, dkim_cfg.modes[0]);
    try std.testing.expectEqual(Mode.verify_only, dkim_cfg.modes[1]);
}

test "a listener without Mode inherits the global default" {
    const dkim_cfg = try parseForTest(
        \\[global]
        \\AuthservID = mail.test.com
        \\Mode = both
        \\
        \\[listener:inherits]
        \\Socket = inet:8891@0.0.0.0
        \\
        \\[listener:overrides]
        \\Socket = inet:8892@127.0.0.1
        \\Mode = sign
    );
    defer freeTestConfig(dkim_cfg);

    try std.testing.expectEqual(Mode.both, dkim_cfg.modes[0]);
    try std.testing.expectEqual(Mode.sign_only, dkim_cfg.modes[1]);
}

// The implicit default listener must still get a mode, or `modes` and
// `listen_addresses` fall out of step and every index lookup is wrong.
test "implicit default listener gets a mode" {
    const dkim_cfg = try parseForTest(
        \\[global]
        \\AuthservID = mail.test.com
    );
    defer freeTestConfig(dkim_cfg);

    try std.testing.expectEqual(@as(usize, 1), dkim_cfg.listen_addresses.len);
    try std.testing.expectEqual(@as(usize, 1), dkim_cfg.modes.len);
    try std.testing.expectEqual(Mode.verify_only, dkim_cfg.modes[0]);
}

test "an unrecognised Mode is refused" {
    try std.testing.expectEqual(Mode.sign_only, try parseMode("sign"));
    try std.testing.expectEqual(Mode.verify_only, try parseMode("verify"));
    try std.testing.expectEqual(Mode.both, try parseMode("both"));

    try std.testing.expectError(error.InvalidMode, parseMode("signing"));
    try std.testing.expectError(error.InvalidMode, parseMode("Sign"));
    try std.testing.expectError(error.InvalidMode, parseMode(""));

    try std.testing.expectError(error.InvalidMode, parseForTest(
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:typo]
        \\Socket = inet:8891@0.0.0.0
        \\Mode = signing
    ));
}

// The label a log line carries must read back as the config that produced it --
// the d4 pentest probe greps `mode=verify` by name, so a drift here breaks a
// probe rather than only a log.
test "modeLabel round-trips through parseMode" {
    for ([_]Mode{ .sign_only, .verify_only, .both }) |m| {
        try std.testing.expectEqual(m, try parseMode(modeLabel(m)));
    }
}
