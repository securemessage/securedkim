//! Configuration tests for `main.zig` — listener addresses and per-listener modes.
//!
//! Separated following the `settings_test.zig` / `dmarc_test.zig` precedent, so
//! `main.zig` stays readable and its line count reflects the daemon rather than
//! its test fixtures. Pulled into the test build by `main.zig`.
//!
//! Only tests that touch ALREADY-PUBLIC symbols live here — `parseDkimConfig`,
//! `parseMode`, `DkimConfig` and `Mode` were all `pub` before this file existed,
//! so nothing was exported merely to satisfy a line count. Tests using private
//! helpers (`stripAngleBrackets`, `getSendingDomain`, `addArHeader`) deliberately
//! stay in `main.zig`: publishing internals to move a test is the worse trade.

const std = @import("std");

const securemilter = @import("securemilter");
const config_mod = securemilter.config;

const main = @import("main.zig");
const DkimConfig = main.DkimConfig;
const Mode = main.Mode;
const parseDkimConfig = main.parseDkimConfig;
const parseMode = main.parseMode;

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
