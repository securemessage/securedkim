//! SecureDKIM configuration parsing: listener modes and `l=` tag policy.
//!
//! This module is independent of daemon globals and converts INI input into
//! `DkimConfig`.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;
const deadline_mod = securemilter.deadline;

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

/// Parse a listener mode; invalid values are configuration errors.
pub fn parseMode(raw: []const u8) error{InvalidMode}!Mode {
    if (mem.eql(u8, raw, "sign")) return .sign_only;
    if (mem.eql(u8, raw, "verify")) return .verify_only;
    if (mem.eql(u8, raw, "both")) return .both;
    return error.InvalidMode;
}

/// Config-facing mode spelling for logs.
pub fn modeLabel(m: Mode) []const u8 {
    return switch (m) {
        .sign_only => "sign",
        .verify_only => "verify",
        .both => "both",
    };
}

/// Parse `BodyLengthTag`, which controls handling of signature `l=` tags.
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
    /// Per-worker connection cap enforced by the accept path.
    max_connections: u32,
    pid_file: []const u8,
    foreground: bool,
    user: ?[]const u8,
    /// File-creation mask for the PID file and any unix-domain listener.
    umask: ?std.posix.mode_t,
    dns_nameservers: []const []const u8,
    dns_timeout_ms: u32,
    dns_retries: u8,
    dns_cache_size: u32,
    dns_negative_ttl: u32,
    /// Listener modes, index-parallel to `listen_addresses` (audit A-2).
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
    /// Signature-validation deadline in milliseconds; zero disables it.
    max_evaluation_ms: i64,
};

pub fn parseDkimConfig(allocator: Allocator, cfg: *const config_mod.Config) !DkimConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    // Validate `BodyLengthTag` before allocations so invalid configuration cannot
    // leak the subsequently allocated DNS nameserver slice.
    const body_length_policy: verify.BodyLengthPolicy = if (global.get("BodyLengthTag")) |raw|
        try parseBodyLengthTag(raw)
    else
        .honor;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);

    // Read beside `WorkerThreads` because the two are multiplied: `calculateFdNeed`
    // sizes the RLIMIT_NOFILE raise as workers x (max_connections + listeners + 3),
    // so raising either one alone is not the whole change.
    const max_connections = global.getInt("MaxConnections", u32, worker_mod.DEFAULT_MAX_CONNECTIONS);

    const pid_file = global.getOrDefault("PidFile", "/var/run/securedkim/securedkim.pid");
    const foreground_val = global.getBool("Foreground", false);
    const user = global.get("User");
    const umask = try global.getMode("UMask");

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

    // Default to loopback because the milter protocol does not authenticate clients.
    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "127.0.0.1", .port = 8891 } });
        try modes.append(allocator, default_mode);
    }

    // `modeFor` indexes `modes` with a listener index, so the two lists falling
    // out of step would silently mis-mode every socket above the shorter one.
    std.debug.assert(addrs.items.len == modes.items.len);

    // Owned slice, borrowed contents -- and unlike the ArrayLists above it does
    // not unwind itself, so it needs its own `errdefer`. Every `try` below this
    // line depends on that, which is why `BodyLengthTag` is validated at the top
    // of this function instead of here.
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

    // X-21: shared spelling and default with securespf's limit of the same
    // name -- an operator tuning one daemon must not find another counting
    // differently.
    const max_evaluation_ms = global.getInt(deadline_mod.OPTION_NAME, i64, deadline_mod.DEFAULT_MS);

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
        .max_connections = max_connections,
        .pid_file = pid_file,
        .foreground = foreground_val,
        .user = user,
        .umask = umask,
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
        .max_evaluation_ms = max_evaluation_ms,
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

// The implicit listener binds loopback, never 0.0.0.0: a config-less run must
// not silently offer an unauthenticated signing oracle on every interface. The
// milter protocol has no authentication, so a reachable sign-mode port lets
// anyone have arbitrary mail signed as the configured domain.
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

// L-2: `MaxConnections` must be honoured here the same way every other daemon
// honours it, silently ignoring the option would give an operator no diagnostic
// for a value that appears to do nothing. The value has two consumers -- the
// accept-path cap in `worker.handleAccept` and the RLIMIT_NOFILE calculation in
// `daemon.calculateFdNeed` -- and wiring only one of them would raise the fd
// budget without raising the limit that budget was sized for, or the reverse.
test "L-2: MaxConnections is honoured, and defaults when absent" {
    {
        var cfg = try config_mod.parse(std.testing.allocator,
            \\[global]
            \\AuthservID = mail.test.com
            \\MaxConnections = 32
        );
        defer cfg.deinit();

        const dkim_cfg = try parseDkimConfig(std.testing.allocator, &cfg);
        defer freeTestConfig(dkim_cfg);

        try std.testing.expectEqual(@as(u32, 32), dkim_cfg.max_connections);
    }

    {
        var cfg = try config_mod.parse(std.testing.allocator,
            \\[global]
            \\AuthservID = mail.test.com
        );
        defer cfg.deinit();

        const dkim_cfg = try parseDkimConfig(std.testing.allocator, &cfg);
        defer freeTestConfig(dkim_cfg);

        try std.testing.expectEqual(worker_mod.DEFAULT_MAX_CONNECTIONS, dkim_cfg.max_connections);
    }
}

// A-2: each listener must keep its own mode rather than sharing one. With a
// single shared mode, declaring the signing listener last would put the
// INBOUND socket into sign mode -- a spoof of our own domain arriving from the
// internet would then match the signing table and be handed a valid signature
// under our own key.
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
// Declaration order must not affect which listener signs.
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
