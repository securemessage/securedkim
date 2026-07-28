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

/// Listener mode for DKIM processing.
pub const Mode = enum {
    sign_only,
    verify_only,
    both,
};

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
    mode: Mode,
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
};

const reload_mod = securemilter.reload;
const rcu_mod = securemilter.rcu;

// Module-level config set before worker spawn, read-only during runtime.
var g_authserv_id: []const u8 = "localhost";
var g_dns_config: dns_mod.ResolverConfig = .{};
var g_mode: Mode = .verify_only;
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
    if (cfg.sign_key_file) |path| assets.sign_key = try crypto.loadRsaKeyFile(path);

    return assets;
}

var g_sign_domain: ?[]const u8 = null;
var g_sign_selector: ?[]const u8 = null;
var g_signed_headers: []const u8 = "from:to:subject:date:message-id";
var g_strip_policy: header_scrub.StripPolicy = .{ .own_methods = &.{"dkim"} };

pub fn parseDkimConfig(allocator: Allocator, cfg: *const config_mod.Config) !DkimConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);
    const pid_file = global.getOrDefault("PidFile", "/var/run/securedkim/securedkim.pid");
    const foreground_val = global.getBool("Foreground", false);
    const user = global.get("User");

    var addrs: std.ArrayListUnmanaged(listener_mod.ListenAddress) = .{};
    errdefer addrs.deinit(allocator);

    var mode: Mode = .verify_only;
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

            // Parse mode from listener section
            if (section.get("Mode")) |mode_str| {
                if (mem.eql(u8, mode_str, "sign")) mode = .sign_only else if (mem.eql(u8, mode_str, "verify")) mode = .verify_only else if (mem.eql(u8, mode_str, "both")) mode = .both;
            }

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
    }

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
        .mode = mode,
        .signing_table_path = signing_table_path,
        .key_table_path = key_table_path,
        .sign_domain = sign_domain,
        .sign_selector = sign_selector,
        .sign_key_file = sign_key_file,
        .signed_headers = signed_headers,
        .strip_auth_results = strip_auth_results,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
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

    g_mode = dkim_cfg.mode;
    g_signed_headers = dkim_cfg.signed_headers;
    g_zmq_endpoint = dkim_cfg.zmq_endpoint;
    g_zmq_topic = dkim_cfg.zmq_topic;
    g_strip_policy = .{ .own_methods = &.{"dkim"}, .strip_all = dkim_cfg.strip_auth_results };

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

    log.info("SecureDKIM starting, AuthservID={s}, mode={s}, listeners={d}", .{
        dkim_cfg.authserv_id,
        @tagName(dkim_cfg.mode),
        dkim_cfg.listen_addresses.len,
    });

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
    };

    const shutdown_pipe = try posix.pipe();
    defer posix.close(shutdown_pipe[0]);

    daemon_mod.ManagedSignals.blockForKqueue();

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
    // Accumulate body chunks in connection's body buffer
    conn.appendBody(data) catch {};
    return @intFromEnum(responses.Code.@"continue");
}

fn onEom(conn: *connection_mod.Connection) u8 {
    const start_ns = std.time.nanoTimestamp();

    // Drop forged results before producing our own, so nothing downstream can
    // read a dkim= verdict this daemon did not issue. Runs before signing too:
    // outbound mail must not carry results claiming our own authserv-id.
    _ = header_scrub.stripAuthResults(conn, g_authserv_id, g_strip_policy);

    const result = switch (g_mode) {
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
    const mode_str: []const u8 = switch (g_mode) {
        .verify_only => "verify",
        .sign_only => "sign",
        .both => "both",
    };
    log.info("id={s} peer={s}[{s}] client={s} from={s} mode={s} elapsed={d}ms", .{ queue_id, peer.name, peer.ip, client_addr, mail_from, mode_str, elapsed_ms });
    return result;
}

fn doVerify(conn: *connection_mod.Connection) u8 {
    // Compute body hash using the body accumulated on the connection
    const body_data = conn.getBody();
    const body_hash = sign_mod.computeBodyHash(conn.allocator, body_data, .simple) catch
        return @intFromEnum(responses.Code.@"continue");

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
            body_hash,
        );

        _ = addArHeader(conn, "dkim", result.result.toString(), result.domain, result.selector);
        publishEvent(conn.allocator, "verify", result.result.toString(), result.domain, result.selector);
    }

    if (!found_any) {
        _ = addArHeader(conn, "dkim", "none", "", "");
        publishEvent(conn.allocator, "verify", "none", "", "");
    }

    return @intFromEnum(responses.Code.@"continue");
}

fn doSign(conn: *connection_mod.Connection) u8 {
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

    // Build header list
    var header_strings: std.ArrayList([]const u8) = .{};
    defer header_strings.deinit(conn.allocator);

    for (conn.headers.items) |hdr| {
        const full = std.fmt.allocPrint(conn.allocator, "{s}: {s}", .{ hdr.name, hdr.value }) catch continue;
        header_strings.append(conn.allocator, full) catch continue;
    }
    defer {
        for (header_strings.items) |s| conn.allocator.free(s);
    }

    // Compute body hash
    const body_data = conn.getBody();
    const body_hash = sign_mod.computeBodyHash(conn.allocator, body_data, sign_params.canonicalization.body) catch
        return @intFromEnum(responses.Code.@"continue");

    // Sign the message
    var sign_result = sign_mod.signMessage(
        conn.allocator,
        &sign_params,
        sign_key,
        header_strings.items,
        body_hash,
    ) catch return @intFromEnum(responses.Code.@"continue");
    defer sign_result.deinit();

    // Prepend DKIM-Signature header via milter protocol
    const hdr_payload = responses.addHeader(
        conn.allocator,
        "DKIM-Signature",
        sign_result.header["DKIM-Signature:".len..],
    ) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(hdr_payload);

    codec.writePacket(conn.fd, hdr_payload) catch {};

    publishEvent(conn.allocator, "sign", "pass", sign_params.domain, sign_params.selector);

    return @intFromEnum(responses.Code.accept);
}

fn publishEvent(
    allocator: Allocator,
    action: []const u8,
    result_str: []const u8,
    domain: []const u8,
    selector: []const u8,
) void {
    const json = std.fmt.allocPrint(allocator,
        \\{{"action":"{s}","result":"{s}","domain":"{s}","selector":"{s}"}}
    , .{ action, result_str, domain, selector }) catch return;
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
) u8 {
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

    const ar_value = auth_results.build(conn.allocator, g_authserv_id, &.{
        .{
            .method = method,
            .result = result_str,
            .reason = null,
            .properties = properties[0..prop_count],
        },
    }) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(ar_value);

    const hdr_payload = responses.addHeader(
        conn.allocator,
        "Authentication-Results",
        ar_value,
    ) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(hdr_payload);

    codec.writePacket(conn.fd, hdr_payload) catch {};
    return @intFromEnum(responses.Code.@"continue");
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
    // parseDkimConfig allocates these two slices; only the signing paths in it
    // are used here, so without this they leaked on every SIGHUP.
    defer {
        g_allocator.free(dkim_cfg.listen_addresses);
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
