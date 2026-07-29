const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;
const daemon_mod = securemilter.daemon;
const auth_results = securemilter.auth_results;
const auth_stamp = securemilter.auth_stamp;
const escape = securemilter.escape;
const commands = securemilter.milter.commands;
const codec = securemilter.milter.codec;
const responses = securemilter.milter.responses;
const negotiate = securemilter.milter.negotiate;
const dns_mod = securemilter.dns;
const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;
const zmq = securemilter.zmq;
const log = securemilter.log;
const header_scrub = securemilter.header_scrub;

pub const canon = securemilter_crypto.canon;
pub const dkim = @import("dkim.zig");
pub const verify = @import("verify.zig");
pub const sign_mod = @import("sign.zig");
pub const keytable = @import("keytable.zig");

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

/// Listener mode for DKIM processing.
pub const Mode = enum {
    sign_only,
    verify_only,
    both,
};

/// Config-facing spelling of a mode, for logs.
///
/// The enum tags carry an `_only` suffix that appears neither in the config file
/// nor in the documented log format, and operators grep these lines — the d4
/// pentest probe greps for `mode=verify` by name. Kept identical to the accepted
/// `Mode =` values so a log line reads back as the config that produced it.
fn modeLabel(m: Mode) []const u8 {
    return switch (m) {
        .sign_only => "sign",
        .verify_only => "verify",
        .both => "both",
    };
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
    strip_auth_results: bool,
    zmq_endpoint: ?[]const u8,
    zmq_topic: []const u8,
    limits: connection_mod.Limits,
    min_key_bits: crypto.MinRsaBits,
    /// What a verified signature's `l=` tag means here (audit D-5).
    body_length_policy: verify.BodyLengthPolicy,
};

const reload_mod = securemilter.reload;
const rcu_mod = securemilter.rcu;

// Module-level config set before worker spawn, read-only during runtime.
var g_authserv_id: []const u8 = "localhost";
var g_dns_config: dns_mod.ResolverConfig = .{};
var g_modes: []const Mode = &.{};
var g_zmq_endpoint: ?[]const u8 = null;
var g_zmq_topic: []const u8 = "dkim";
var g_allocator: Allocator = undefined;
var g_config_path: []const u8 = "/usr/local/etc/securedkim/securedkim.conf";
var g_health_monitor: ?*dns_mod.HealthMonitor = null;
var g_config_gen: reload_mod.ConfigGeneration = reload_mod.ConfigGeneration.init();

// Thread-local ZMQ publisher (one socket per worker thread — ZMQ thread-safety)
threadlocal var tl_publisher: ?zmq.Publisher = null;

fn getPublisher() *zmq.Publisher {
    if (tl_publisher == null) {
        tl_publisher = zmq.Publisher.init(g_zmq_endpoint, g_zmq_topic);
    }
    return &tl_publisher.?;
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
const SigningAssets = struct {
    signing_table: ?keytable.SigningTable = null,
    key_table: ?keytable.KeyTable = null,
    sign_key: ?crypto.SigningKey = null,
};

const SigningRcu = rcu_mod.Rcu(SigningAssets);
var g_signing: SigningRcu = undefined;

fn freeSigningAssets(allocator: Allocator, assets: *SigningAssets) void {
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
fn buildSigningAssets(allocator: Allocator, cfg: *const DkimConfig) !*SigningAssets {
    const assets = try allocator.create(SigningAssets);
    assets.* = .{};
    errdefer freeSigningAssets(allocator, assets);

    if (cfg.signing_table_path) |path| assets.signing_table = try loadSigningTable(allocator, path);
    if (cfg.key_table_path) |path| assets.key_table = try loadKeyTable(allocator, path);
    // The signing key is held to the RFC 8301 floor, not to the operator's
    // MinimumKeyBits. That option is a policy about keys *other people* publish;
    // coupling our own key to it would mean tightening the verify policy could
    // stop the daemon starting, which is a surprise nobody asked for. The floor
    // itself is not optional: RFC 8301 §3.2 says signers MUST use at least 1024
    // bits, and mail signed below it fails DKIM at every conformant verifier.
    if (cfg.sign_key_file) |path| {
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

var g_sign_domain: ?[]const u8 = null;
var g_sign_selector: ?[]const u8 = null;
var g_signed_headers: []const u8 = "from:to:subject:date:message-id";
var g_strip_policy: header_scrub.StripPolicy = .{ .own_methods = &.{"dkim"} };

/// Smallest RSA modulus accepted from a signer's DNS key record.
///
/// Set once at startup and read by every worker thereafter. Deliberately not a
/// field on `connection.Limits`: that struct is shared by all four daemons, and
/// only the two that verify signatures have any use for this.
var g_min_key_bits: u32 = crypto.RFC8301_MIN_RSA_BITS;

/// Default `honor`, which is what RFC 6376 §3.5 specifies and what a signer using
/// `l=` expects. `refuse` is available for operators who would rather take RFC
/// 6376 §8.2 at its word and ignore such signatures; see the man page.
var g_body_length_policy: verify.BodyLengthPolicy = .honor;

pub fn parseDkimConfig(allocator: Allocator, cfg: *const config_mod.Config) !DkimConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

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
            const socket_str = section.get("Socket") orelse continue;
            const addr = listener_mod.ListenAddress.parse(socket_str) catch continue;
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

    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "0.0.0.0", .port = 8891 } });
        try modes.append(allocator, default_mode);
    }

    // `modeFor` indexes `modes` with a listener index, so the two lists falling
    // out of step would silently mis-mode every socket above the shorter one.
    std.debug.assert(addrs.items.len == modes.items.len);

    const dns_ns_raw = global.getOrDefault("DnsNameserver", "127.0.0.1");
    var ns_list: std.ArrayListUnmanaged([]const u8) = .{};
    var ns_iter = mem.splitSequence(u8, dns_ns_raw, ",");
    while (ns_iter.next()) |part| {
        const trimmed = mem.trim(u8, part, " \t");
        if (trimmed.len > 0) try ns_list.append(allocator, trimmed);
    }
    const dns_nameservers = try ns_list.toOwnedSlice(allocator);
    const dns_timeout = global.getInt("DnsTimeout", u32, 5) * 1000;
    const dns_retries = global.getInt("DnsRetries", u8, 2);
    const dns_cache_size = global.getInt("DnsCacheSize", u32, 1000);
    const dns_negative_ttl = global.getInt("DnsNegativeTTL", u32, 60);
    const signed_headers = global.getOrDefault("SignedHeaders", "from:to:subject:date:message-id");

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

    // RFC 6376 §3.5 says to honour l=; §8.2 says a verifier may refuse signatures
    // that carry it. Both are legitimate, so it is the operator's call.
    const body_length_policy: verify.BodyLengthPolicy = if (global.get("BodyLengthTag")) |raw|
        try parseBodyLengthTag(raw)
    else
        .honor;

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
        .strip_auth_results = strip_auth_results,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
        .limits = limits,
        .min_key_bits = min_key_bits,
        .body_length_policy = body_length_policy,
    };
}

fn usageError() error{InvalidArgument} {
    log.err("usage: securedkim -c <config-file>", .{});
    return error.InvalidArgument;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    g_allocator = allocator;

    // Parse command-line: securedkim -c /path/to/config
    var args = std.process.args();
    _ = args.next();
    const flag = args.next() orelse return usageError();
    if (!std.mem.eql(u8, flag, "-c")) return usageError();
    const config_path = args.next() orelse return usageError();
    g_config_path = config_path;

    var cfg = config_mod.parseFile(allocator, config_path) catch |err| {
        log.err("failed to load config {s}: {}", .{ config_path, err });
        return err;
    };
    defer cfg.deinit();

    const dkim_cfg = parseDkimConfig(allocator, &cfg) catch |err| {
        log.err("config parse error: {}", .{err});
        return err;
    };

    // Initialize logging from config
    const log_cfg = if (cfg.global()) |g| log.LogConfig.fromSection(g, "securedkim") else log.LogConfig.init(true, .mail, .info, "securedkim");
    log.initGlobal(&log_cfg);
    log.initThread();

    // Set module-level globals
    g_authserv_id = dkim_cfg.authserv_id;
    g_dns_config = .{
        .nameservers = dkim_cfg.dns_nameservers,
        .timeout_ms = dkim_cfg.dns_timeout_ms,
        .retries = dkim_cfg.dns_retries,
        .cache_size = dkim_cfg.dns_cache_size,
        .negative_ttl = dkim_cfg.dns_negative_ttl,
    };

    g_modes = dkim_cfg.modes;
    g_signed_headers = dkim_cfg.signed_headers;
    g_zmq_endpoint = dkim_cfg.zmq_endpoint;
    g_zmq_topic = dkim_cfg.zmq_topic;
    g_strip_policy = .{ .own_methods = &.{"dkim"}, .strip_all = dkim_cfg.strip_auth_results };
    g_min_key_bits = dkim_cfg.min_key_bits.bits;
    g_body_length_policy = dkim_cfg.body_length_policy;

    // Say so rather than silently disagreeing with the config file. An operator
    // who wrote a smaller number is trying to accept keys the RFC forbids, and
    // should learn that from the log and not from a support ticket.
    if (dkim_cfg.min_key_bits.raised) {
        log.warn(
            "{s} below the RFC 8301 minimum: using {d} bits",
            .{ crypto.MIN_KEY_BITS_OPTION, dkim_cfg.min_key_bits.bits },
        );
    }

    // Load signing config as one publishable unit.
    g_signing = SigningRcu.init(allocator, freeSigningAssets);
    const initial_assets = buildSigningAssets(allocator, &dkim_cfg) catch |err| {
        log.err("failed to load signing configuration: {}", .{err});
        return err;
    };
    g_signing.publish(&g_config_gen, initial_assets) catch |err| {
        freeSigningAssets(allocator, initial_assets);
        log.err("failed to publish signing configuration: {}", .{err});
        return err;
    };

    // Single-domain shorthand. These point into `cfg`, which lives for the
    // whole process, and are not reloadable.
    g_sign_domain = dkim_cfg.sign_domain;
    g_sign_selector = dkim_cfg.sign_selector;

    // Daemonize — MUST happen before spawning any threads (fork only preserves calling thread)
    if (!dkim_cfg.foreground) {
        daemon_mod.daemonize() catch |err| {
            log.err("daemonize failed: {}", .{err});
            return err;
        };
        log.initThread(); // re-init after fork (PID changed)
    }

    // Block the managed signals BEFORE spawning any thread, so every thread
    // inherits the mask and SIGHUP/SIGTERM can only be taken by sigwait in the
    // main thread. Ordering matters: this used to sit just above the worker
    // pool, leaving the health monitor thread below with SIGHUP unblocked and
    // able to take a reload signal and terminate the daemon (audit X-7).
    daemon_mod.ManagedSignals.blockForKqueue();

    // Start proactive DNS health monitor AFTER daemonize
    if (dns_mod.HealthMonitor.init(allocator, dkim_cfg.dns_nameservers, 53, 5, 2000)) |monitor| {
        monitor.start() catch |err| {
            log.warn("DNS health monitor thread failed: {}", .{err});
        };
        g_health_monitor = monitor;
    } else |err| {
        log.warn("DNS health monitor init failed: {}, falling back to reactive", .{err});
    }

    daemon_mod.writePidFile(dkim_cfg.pid_file) catch |err| {
        log.err("pid file write failed: {}", .{err});
    };
    defer daemon_mod.removePidFile(dkim_cfg.pid_file);

    // Raise fd limit to calculated budget before dropping privileges
    const num_workers = if (dkim_cfg.worker_threads == 0) @as(u32, @intCast(std.Thread.getCpuCount() catch 4)) else dkim_cfg.worker_threads;
    const fd_need = daemon_mod.calculateFdNeed(num_workers, worker_mod.DEFAULT_MAX_CONNECTIONS, @intCast(dkim_cfg.listen_addresses.len));
    daemon_mod.raiseFileLimit(fd_need);

    // Drop privileges after PID file is written, before workers spawn
    if (dkim_cfg.user) |user| {
        daemon_mod.dropPrivileges(user) catch |err| {
            log.err("privilege drop to '{s}' failed: {}", .{ user, err });
            return err;
        };
    }

    log.info("SecureDKIM starting, AuthservID={s}, MinimumKeyBits={d}, listeners={d}", .{
        dkim_cfg.authserv_id,
        dkim_cfg.min_key_bits.bits,
        dkim_cfg.listen_addresses.len,
    });

    // One line per socket. A single daemon-wide mode used to be logged even
    // when the config named two different ones, so the log agreed with the
    // config while the daemon did not (audit A-2).
    for (dkim_cfg.modes, 0..) |m, i| {
        log.info("listener[{d}] mode={s}", .{ i, modeLabel(m) });
    }

    // Required protocol flags: add headers (A-R for verify, DKIM-Sig for sign)
    // and change headers (removal of forged Authentication-Results).
    const required_actions = negotiate.ActionFlags{ .add_headers = true, .change_headers = true };

    const callbacks = worker_mod.Callbacks{
        .on_connect = onConnect,
        .on_helo = onHelo,
        .on_mail_from = onMailFrom,
        .on_header = onHeader,
        .on_eoh = onEoh,
        .on_body = onBody,
        .on_eom = onEom,
        .on_reload = onWorkerReload,
        .required_actions = required_actions,
        .limits = dkim_cfg.limits,
    };

    const shutdown_pipe = try posix.pipe();
    defer posix.close(shutdown_pipe[0]);

    var threads = try worker_mod.spawnPoolWithReload(
        allocator,
        dkim_cfg.worker_threads,
        dkim_cfg.listen_addresses,
        callbacks,
        shutdown_pipe[0],
        &g_config_gen,
        worker_mod.DEFAULT_MAX_CONNECTIONS,
    );
    defer threads.deinit(allocator);

    daemon_mod.ManagedSignals.signalLoop(shutdown_pipe[1], reloadConfig);
    for (threads.items) |t| t.join();

    // Workers are joined: nothing can be mid-signature, so the live snapshot
    // and any retired ones can all go.
    g_signing.deinit();
    g_config_gen.deinit(allocator);

    if (g_health_monitor) |monitor| monitor.deinit();
}

// =============================================================================
// Milter Callbacks
// =============================================================================

fn onConnect(conn: *connection_mod.Connection, _: commands.ConnectInfo) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onHelo(conn: *connection_mod.Connection, _: []const u8) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onMailFrom(conn: *connection_mod.Connection, _: []const u8) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onHeader(conn: *connection_mod.Connection, _: []const u8, _: []const u8) u8 {
    // Headers are already accumulated by Connection.addHeader() in the worker
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onEoh(conn: *connection_mod.Connection) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onBody(conn: *connection_mod.Connection, data: []const u8) u8 {
    // Accumulate the body so it can be hashed at end-of-message.
    //
    // A rejection here is not fatal to the SMTP transaction and must not be
    // silently discarded either: the connection latches the overflow, and
    // end-of-message declines to verify or sign rather than hashing a body the
    // MTA is not delivering (audit X-4). Continue so the MTA finishes the
    // transaction normally; each further chunk is now a cheap no-op.
    //
    // Only the chunk that trips the limit is logged. A large message arrives as
    // thousands of chunks, and one log line each would make an oversized message
    // a log-flooding tool in its own right.
    const already_tripped = conn.body_overflow;
    conn.appendBody(data) catch |e| {
        if (!already_tripped) {
            const peer = conn.getPeerDisplay();
            if (e == error.BodyTooLarge) {
                log.warn(
                    "body exceeds MaxBodyBytes={d} from {f}[{f}]: message will not be verified or signed",
                    .{ conn.limits.max_body_bytes, escape.logField(peer.name), escape.logField(peer.ip) },
                );
            } else {
                log.err(
                    "body accumulation failed for {f}[{f}]: {}",
                    .{ escape.logField(peer.name), escape.logField(peer.ip), e },
                );
            }
        }
    };
    return @intFromEnum(responses.Code.@"continue");
}

fn onEom(conn: *connection_mod.Connection) u8 {
    const start_ns = std.time.nanoTimestamp();

    // Drop forged results before producing our own, so nothing downstream can
    // read a dkim= verdict this daemon did not issue. Runs before signing too:
    // outbound mail must not carry results claiming our own authserv-id.
    _ = header_scrub.stripAuthResults(conn, g_authserv_id, g_strip_policy);

    const mode = modeFor(conn.listener_index);

    const result = switch (mode) {
        .verify_only => doVerify(conn),
        .sign_only => doSign(conn),
        .both => blk: {
            _ = doVerify(conn);
            break :blk doSign(conn);
        },
    };
    const elapsed_ms = @divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000);
    const queue_id = conn.macros.queue_id orelse "-";
    const client_addr = conn.macros.client_addr orelse "unknown";
    const mail_from = stripAngleBrackets(conn.mail_from_raw orelse "<>");
    const peer = conn.getPeerDisplay();
    // The queue id, peer name, client address and envelope sender are all
    // attacker-influenced -- the peer name comes from rDNS the sender may
    // control -- so each is rendered as a single bare token. A newline in any of
    // them would forge a second syslog line; a space would make the following
    // key appear to hold this value (audit X-5). `mode` and the numbers are ours.
    log.info("id={f} peer={f}[{f}] client={f} from={f} listener={d} mode={s} elapsed={d}ms", .{
        escape.logField(queue_id),
        escape.logField(peer.name),
        escape.logField(peer.ip),
        escape.logField(client_addr),
        escape.logField(mail_from),
        conn.listener_index,
        modeLabel(mode),
        elapsed_ms,
    });
    return result;
}

/// Mode for the socket a connection arrived on (audit A-2).
///
/// Every worker binds every configured address, so the index the worker
/// records on a connection indexes the same list `parseDkimConfig` built and
/// the lookup is always in range. Bounds-checked rather than asserted anyway:
/// an out-of-range index is a wiring bug, and the safe fallback is the mode
/// that only reads. Signing on a guess is how A-2 became a bypass.
fn modeFor(listener_index: usize) Mode {
    if (listener_index < g_modes.len) return g_modes[listener_index];
    log.err(
        "listener index {d} has no configured mode ({d} known): falling back to verify",
        .{ listener_index, g_modes.len },
    );
    return .verify_only;
}

fn doVerify(conn: *connection_mod.Connection) u8 {
    // A truncated copy cannot be verified. Reporting dkim=fail would be a lie
    // about the signature and dkim=none a lie about the message, so this is
    // temperror: the result is unknown for a local, transient reason, which is
    // exactly what RFC 6376 6.1 reserves TEMPFAIL for.
    if (conn.contentTruncated()) {
        addArHeader(conn, "dkim", "temperror", "", "") catch |err|
            return auth_stamp.deferCode(err, "dkim");
        publishEvent(conn.allocator, "verify", "temperror", "", "");
        return @intFromEnum(responses.Code.@"continue");
    }

    // Refuse a signature flood before spending anything on it. Each signature
    // costs an uncached DNS lookup plus an RSA verify, so the work is the
    // attack: 300 of them measured 355x the cost of a normal message and
    // stalled every worker (audit D-4). Counting is O(headers) with no I/O.
    const max_sigs = conn.limits.max_signatures;
    if (max_sigs != 0) {
        const sig_count = conn.countHeadersCapped("DKIM-Signature", max_sigs);
        if (sig_count > max_sigs) {
            const peer = conn.getPeerDisplay();
            log.warn(
                "more than MaxSignatures={d} DKIM-Signature headers from {f}[{f}]: not verifying",
                .{ max_sigs, escape.logField(peer.name), escape.logField(peer.ip) },
            );
            addArHeader(conn, "dkim", "permerror", "", "") catch |err|
                return auth_stamp.deferCode(err, "dkim");
            publishEvent(conn.allocator, "verify", "permerror", "", "");
            return @intFromEnum(responses.Code.@"continue");
        }
    }

    // The body is passed to each signature rather than hashed once here. `c=`
    // chooses the canonicalization and `l=` chooses how much of the body is
    // covered, both per signature, so one hash cannot serve them all. This used
    // to hash every body with `simple` regardless of what the signature asked,
    // which meant no `c=*/relaxed` signature could verify -- that is what almost
    // everything on the internet sends, Gmail included.
    // `contentTruncated` above already established the body is whole.
    const body_data = conn.getBody() orelse return @intFromEnum(responses.Code.@"continue");

    // Build header list from accumulated headers
    var header_strings: std.ArrayList([]const u8) = .{};
    defer header_strings.deinit(conn.allocator);

    for (conn.headers.items) |hdr| {
        const full = std.fmt.allocPrint(conn.allocator, "{s}: {s}", .{ hdr.name, hdr.value }) catch continue;
        header_strings.append(conn.allocator, full) catch continue;
    }
    defer {
        for (header_strings.items) |s| conn.allocator.free(s);
    }

    // Find DKIM-Signature headers and verify each
    var found_any = false;
    for (conn.headers.items) |hdr| {
        if (!eqlIgnoreCase(hdr.name, "DKIM-Signature")) continue;
        found_any = true;

        const sig_header_raw = std.fmt.allocPrint(conn.allocator, "DKIM-Signature: {s}", .{hdr.value}) catch continue;
        defer conn.allocator.free(sig_header_raw);

        var resolver = dns_mod.Resolver.initWithMonitor(conn.allocator, g_dns_config, g_health_monitor);
        defer resolver.deinit();

        const result = verify.verifySignature(
            conn.allocator,
            &resolver,
            hdr.value,
            sig_header_raw,
            header_strings.items,
            body_data,
            g_min_key_bits,
            g_body_length_policy,
        );

        // A weak key is a signer-side fault the postmaster on this side cannot
        // fix, so it is worth a log line: the A-R header records only the
        // permerror, and without this nobody can tell it apart from a
        // canonicalization failure without recomputing the signature by hand.
        if (result.reason) |reason| {
            if (mem.eql(u8, reason, "key too small")) {
                // The domain is the signature's own `d=` tag, so it is entirely
                // sender-chosen (audit X-5).
                log.warn(
                    "{f}: RSA key below MinimumKeyBits={d}, signature permanently failed (RFC 8301 3.2)",
                    .{ escape.logField(result.domain), g_min_key_bits },
                );
            }
        }

        // A pass that covers part of a body is a weaker claim than a pass that
        // covers all of it, and `dkim=pass` alone cannot express the difference.
        // Said out loud because RFC 6376 §8.2's attack is precisely that the
        // unsigned tail can "completely replace the original content in the end
        // recipient's eyes" while the signature still validates. The domain is
        // sender-chosen, hence escaped (audit X-5).
        if (result.unsigned_body_bytes > 0) {
            log.warn(
                "{f}: dkim=pass covers only the first l= octets, {d} trailing body octets are unsigned (RFC 6376 8.2)",
                .{ escape.logField(result.domain), result.unsigned_body_bytes },
            );
        }

        addArHeader(conn, "dkim", result.result.toString(), result.domain, result.selector) catch |err|
            return auth_stamp.deferCode(err, "dkim");
        publishEvent(conn.allocator, "verify", result.result.toString(), result.domain, result.selector);
    }

    if (!found_any) {
        addArHeader(conn, "dkim", "none", "", "") catch |err|
            return auth_stamp.deferCode(err, "dkim");
        publishEvent(conn.allocator, "verify", "none", "", "");
    }

    return @intFromEnum(responses.Code.@"continue");
}

fn doSign(conn: *connection_mod.Connection) u8 {
    // Never sign a message this daemon does not hold in full. A signature is a
    // claim about specific bytes; over a truncated copy it is a false claim, and
    // every recipient would compute dkim=fail on mail we vouched for. Leaving it
    // unsigned is a deliverability cost, signing it wrongly is a correctness one
    // paid by everyone downstream (audit X-4).
    if (conn.contentTruncated()) {
        const peer = conn.getPeerDisplay();
        log.warn(
            "not signing message from {f}[{f}]: accumulated copy is incomplete",
            .{ escape.logField(peer.name), escape.logField(peer.ip) },
        );
        return @intFromEnum(responses.Code.@"continue");
    }

    // Determine signing domain from sender
    const mail_from = stripAngleBrackets(conn.mail_from_raw orelse return @intFromEnum(responses.Code.@"continue"));
    const domain = getSendingDomain(mail_from) orelse return @intFromEnum(responses.Code.@"continue");

    // One snapshot of the signing configuration for the whole message: the
    // table that chose the domain and the key that signs it must agree, even
    // if a SIGHUP lands midway.
    const assets = g_signing.get() orelse return @intFromEnum(responses.Code.@"continue");

    // Look up signing parameters
    const sign_params = resolveSigningParams(assets, domain, mail_from) orelse
        return @intFromEnum(responses.Code.@"continue");
    const sign_key = resolveSigningKey(assets, sign_params) orelse
        return @intFromEnum(responses.Code.@"continue");

    // Build the header list that will be signed.
    //
    // One defer for both the strings and the list, registered before the loop, so
    // an early return below cannot leak the strings appended so far. The previous
    // arrangement put the string-freeing defer *after* the loop, which was safe
    // only because nothing in the loop returned.
    var header_strings: std.ArrayList([]const u8) = .{};
    defer {
        for (header_strings.items) |s| conn.allocator.free(s);
        header_strings.deinit(conn.allocator);
    }

    for (conn.headers.items) |hdr| {
        // `catch continue` here would drop a header from the signing input while
        // `h=` still names it, because h= is written verbatim from config and the
        // input is assembled by looking each name up in this list. The result is
        // a syntactically valid signature over a different header set than it
        // claims to cover, so every verifier computes a different hash and all
        // mail signed during the fault fails DKIM at the recipient -- while this
        // daemon reports success (audit X-10).
        const full = std.fmt.allocPrint(conn.allocator, "{s}: {s}", .{ hdr.name, hdr.value }) catch
            return signInternalError("building the header list to sign");
        header_strings.append(conn.allocator, full) catch {
            conn.allocator.free(full);
            return signInternalError("building the header list to sign");
        };
    }

    // Compute body hash. The truncation check at the top of doSign already
    // established the body is whole.
    const body_data = conn.getBody() orelse return signInternalError("the accumulated body is unavailable");
    const body_hash = sign_mod.computeBodyHash(conn.allocator, body_data, sign_params.canonicalization.body) catch
        return signInternalError("computing the body hash");

    // Sign the message
    var sign_result = sign_mod.signMessage(
        conn.allocator,
        &sign_params,
        sign_key,
        header_strings.items,
        body_hash,
    ) catch return signInternalError("signing the message");
    defer sign_result.deinit();

    // Prepend DKIM-Signature header via milter protocol
    const hdr_payload = responses.addHeader(
        conn.allocator,
        "DKIM-Signature",
        sign_result.header["DKIM-Signature:".len..],
    ) catch return signInternalError("building the DKIM-Signature header");
    defer conn.allocator.free(hdr_payload);

    // A swallowed write here delivered the message unsigned and then published
    // "sign pass" for it, so both the recipient and our own event stream were
    // misinformed at once (audit X-10).
    codec.writePacket(conn.fd, hdr_payload) catch
        return signInternalError("writing the DKIM-Signature header");

    publishEvent(conn.allocator, "sign", "pass", sign_params.domain, sign_params.selector);

    return @intFromEnum(responses.Code.accept);
}

/// Defer the message after an internal failure while signing (audit X-10).
///
/// Distinct from the deliberate "do not sign this" outcomes above it, which
/// correctly deliver the message unsigned: no envelope sender, no signing table
/// entry for the domain, or a body this daemon does not hold in full. Those are
/// statements about the message. What this covers is a local fault on a message we
/// were configured to sign and could have signed, where delivering it unsigned
/// means a `p=reject` domain's mail is rejected by the recipient instead.
fn signInternalError(what: []const u8) u8 {
    log.err("not signing: internal error {s}", .{what});
    return @intFromEnum(responses.Code.tempfail);
}

fn publishEvent(
    allocator: Allocator,
    action: []const u8,
    result_str: []const u8,
    domain: []const u8,
    selector: []const u8,
) void {
    // `domain` and `selector` are the signature's own `d=` and `s=` tags, so both
    // are sender-chosen. A `"` in `d=` used to end the JSON string early and
    // leave the remainder of the payload to be reinterpreted, which is exactly
    // what the x5b probe sends (audit X-5). `action` and `result_str` are ours.
    const json = std.fmt.allocPrint(allocator,
        \\{{"action":"{s}","result":"{s}","domain":"{f}","selector":"{f}"}}
    , .{
        action,
        result_str,
        escape.jsonString(domain),
        escape.jsonString(selector),
    }) catch return;
    defer allocator.free(json);

    getPublisher().publish(json);
}

/// Resolve signing parameters against one snapshot of the signing assets.
///
/// The snapshot is passed in rather than re-read here so that the table
/// consulted and the key used later in the same message come from the same
/// published configuration.
fn resolveSigningParams(
    assets: *const SigningAssets,
    domain: []const u8,
    sender: []const u8,
) ?sign_mod.SigningParams {
    // Single-domain shorthand
    if (g_sign_domain) |d| {
        if (eqlIgnoreCase(d, domain)) {
            return .{
                .domain = d,
                .selector = g_sign_selector orelse "default",
                .signed_headers = g_signed_headers,
            };
        }
    }

    // SigningTable + KeyTable lookup
    if (assets.signing_table) |*st| {
        const entry_name = st.lookup(sender) orelse return null;
        if (assets.key_table) |*kt| {
            const entries = kt.lookup(entry_name);
            if (entries.len > 0) {
                return .{
                    .domain = entries[0].domain,
                    .selector = entries[0].selector,
                    .signed_headers = g_signed_headers,
                };
            }
        }
    }

    return null;
}

/// The returned pointer is borrowed from `assets` and stays valid for the rest
/// of this message, which is what signing needs (see securemilter rcu.zig).
fn resolveSigningKey(assets: *const SigningAssets, params: sign_mod.SigningParams) ?*const crypto.SigningKey {
    _ = params;
    // Single-domain shorthand key
    if (assets.sign_key) |*k| return k;
    // KeyTable-based key loading (lazy-load, future LRU cache)
    // For v1, only single-domain shorthand is wired end-to-end
    return null;
}

fn addArHeader(
    conn: *connection_mod.Connection,
    method: []const u8,
    result_str: []const u8,
    domain: []const u8,
    selector: []const u8,
) !void {
    var properties: [2]auth_results.MethodResult.Property = undefined;
    var prop_count: usize = 0;

    if (domain.len > 0) {
        properties[prop_count] = .{ .ptype = "header", .property = "d", .value = domain };
        prop_count += 1;
    }
    if (selector.len > 0) {
        properties[prop_count] = .{ .ptype = "header", .property = "s", .value = selector };
        prop_count += 1;
    }

    try auth_stamp.stamp(conn.allocator, conn.fd, g_authserv_id, &.{
        .{
            .method = method,
            .result = result_str,
            .reason = null,
            .properties = properties[0..prop_count],
        },
    });
}

// =============================================================================
// Utilities
// =============================================================================

fn stripAngleBrackets(addr: []const u8) []const u8 {
    var s = addr;
    if (s.len > 0 and s[0] == '<') s = s[1..];
    if (s.len > 0 and s[s.len - 1] == '>') s = s[0 .. s.len - 1];
    return s;
}

fn getSendingDomain(sender: []const u8) ?[]const u8 {
    if (mem.lastIndexOfScalar(u8, sender, '@')) |at| {
        return sender[at + 1 ..];
    }
    return null;
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
// Reload
// =============================================================================

/// Main-thread reload callback: re-reads SigningTable, KeyTable and signing
/// key, and publishes them as a single new snapshot.
///
/// All or nothing. The previous code updated each of the three in place as it
/// managed to read them, so a run where only the KeyTable parsed left the
/// daemon signing with a new table and an old key. Building the whole set
/// first means a failure anywhere leaves the running configuration untouched.
///
/// The superseded set is retired, not freed: workers may be signing with it
/// right now. It is reclaimed once every worker has been seen at a quiescent
/// point past this generation (audit X-2).
fn reloadConfig() void {
    var cfg = config_mod.parseFile(g_allocator, g_config_path) catch {
        log.warn("reload: failed to re-read config file, keeping previous", .{});
        _ = g_config_gen.increment();
        return;
    };
    defer cfg.deinit();

    const dkim_cfg = parseDkimConfig(g_allocator, &cfg) catch {
        log.warn("reload: failed to parse config, keeping previous", .{});
        _ = g_config_gen.increment();
        return;
    };
    // parseDkimConfig allocates these three slices; only the signing paths in
    // it are used here, so without this they leaked on every SIGHUP.
    defer {
        g_allocator.free(dkim_cfg.listen_addresses);
        g_allocator.free(dkim_cfg.modes);
        g_allocator.free(dkim_cfg.dns_nameservers);
    }

    const assets = buildSigningAssets(g_allocator, &dkim_cfg) catch |err| {
        log.warn("reload: failed to load signing configuration ({}), keeping previous", .{err});
        _ = g_config_gen.increment();
        return;
    };

    g_signing.publish(&g_config_gen, assets) catch |err| {
        // publish reserves its retire slot before swapping, so on failure the
        // previous snapshot is still the live one.
        freeSigningAssets(g_allocator, assets);
        log.warn("reload: failed to publish signing configuration ({}), keeping previous", .{err});
        _ = g_config_gen.increment();
        return;
    };

    // Wake the workers so they reach a quiescent point and the superseded
    // snapshot becomes reclaimable rather than accumulating.
    g_config_gen.wake();

    log.info("signing configuration reloaded (generation {d}, {d} awaiting reclamation)", .{
        g_config_gen.load(),
        g_signing.retiredCount(),
    });
}

/// Per-worker reload callback: flush thread-local state.
/// Future: flush LRU key cache when implemented.
fn onWorkerReload() void {
    log.debug("worker: config reload acknowledged", .{});
}

// =============================================================================
// Tests
// =============================================================================

test {
    _ = canon;
    _ = dkim;
    _ = verify;
    _ = sign_mod;
    _ = keytable;
}

test "strip angle brackets" {
    try std.testing.expectEqualStrings("user@example.com", stripAngleBrackets("<user@example.com>"));
    try std.testing.expectEqualStrings("", stripAngleBrackets("<>"));
}

test "get sending domain" {
    try std.testing.expectEqualStrings("example.com", getSendingDomain("user@example.com").?);
    try std.testing.expect(getSendingDomain("postmaster") == null);
}

// `parseDkimConfig` had no tests at all, which is why A-2 survived here after
// being written up against `securearc`.
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

// X-9: this wrapper must stay fallible.
//
// It previously returned `u8` and swallowed all three failure points, and all
// four call sites discarded the result with `_ =`. A message could be delivered
// with no `dkim=` field while this daemon reported success, and `securedmarc`
// then evaluated DMARC without it. Asserting the type is what makes a revert a
// build failure rather than a silent behaviour change.
test "the Authentication-Results wrapper cannot swallow failures" {
    comptime {
        const ret = @typeInfo(@TypeOf(addArHeader)).@"fn".return_type.?;
        if (@typeInfo(ret) != .error_union) @compileError(
            "addArHeader must return an error union. Swallowing a stamping failure " ++
                "delivers the message with no dkim= field while reporting success, and " ++
                "securedmarc then evaluates DMARC without it (audit X-9).",
        );
        if (@typeInfo(ret).error_union.payload != void) @compileError(
            "addArHeader should return !void; the caller maps the error to a tempfail.",
        );
    }
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
