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
const bootstrap_mod = securemilter.bootstrap;
const auth_results = securemilter.auth_results;
const auth_stamp = securemilter.auth_stamp;
const escape = securemilter.escape;
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
pub const signing = @import("signing.zig");
pub const settings = @import("settings.zig");

var g_signing: signing.Rcu = undefined;

/// Re-exported at their old spellings, so extracting the configuration layer is
/// not a rename at every call site -- the same handling `securearc` gave its own
/// split. `settings.zig` carries the reasoning for each of these.
pub const Mode = settings.Mode;
pub const DkimConfig = settings.DkimConfig;
pub const parseMode = settings.parseMode;
pub const parseBodyLengthTag = settings.parseBodyLengthTag;
pub const parseDkimConfig = settings.parseDkimConfig;
const modeLabel = settings.modeLabel;

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

/// `daemon.Options.spawn_threads`: start the DNS health monitor.
///
/// Context-free because that is what `daemon.Options` takes, and deliberately so — the
/// hook runs at the one point in the bootstrap where creating a thread is safe, after
/// the fork and after the managed signals are blocked. `g_allocator` and `g_dns_config`
/// are both set from the parsed configuration before then.
fn spawnHealthMonitor() void {
    g_health_monitor = dns_mod.startMonitor(g_allocator, g_dns_config.nameservers);
}
var g_config_gen: reload_mod.ConfigGeneration = reload_mod.ConfigGeneration.init();

// Thread-local ZMQ publisher (one socket per worker thread — ZMQ thread-safety)
threadlocal var tl_publisher: ?zmq.Publisher = null;

// Thread-local DNS resolver (audit X-3).
//
// This one was the worst of the four: the resolver was built and destroyed
// inside the loop over `DKIM-Signature` headers, so the cost scaled with the
// number of signatures a sender chose to attach rather than with the number of
// messages. That is the mechanism behind D-4's measured 355x amplification --
// 300 signatures meant 300 resolvers and 300 uncached key fetches, ~5 seconds of
// wall time, and with `WorkerThreads=2` two such messages stalled every DKIM
// worker. A per-worker cache does not remove the per-signature RSA verify, but
// it does collapse repeated `selector._domainkey.domain` lookups -- including
// the identical-selector floods -- to one query.
//
// Per worker thread so it needs no lock, matching the publisher above.
// `g_allocator`, not `conn.allocator`, because it now outlives the connection --
// the same allocator either way, since the pool is handed `g_allocator`.
threadlocal var tl_resolver: ?dns_mod.Resolver = null;

fn getResolver() *dns_mod.Resolver {
    if (tl_resolver == null) {
        tl_resolver = dns_mod.Resolver.initWithMonitor(g_allocator, g_dns_config, g_health_monitor);
    }
    return &tl_resolver.?;
}

fn getPublisher() *zmq.Publisher {
    if (tl_publisher == null) {
        tl_publisher = zmq.Publisher.init(g_zmq_endpoint, g_zmq_topic);
    }
    return &tl_publisher.?;
}

var g_strip_policy: header_scrub.StripPolicy = .{ .own_methods = &.{"dkim"} };

/// Smallest RSA modulus accepted from a signer's DNS key record.
///
/// Set once at startup and read by every worker thereafter. Deliberately not a
/// field on `connection.Limits`: that struct is shared by all four daemons, and
/// only the two that verify signatures have any use for this.
var g_min_key_bits: u32 = crypto.RFC8301_MIN_RSA_BITS;

/// Key records tried at one selector before giving up (audit D-20). Set once at
/// startup alongside `g_min_key_bits`, and DKIM-only for the same reason.
var g_max_key_records: u8 = verify.DEFAULT_MAX_KEY_RECORDS;

/// Default `honor`, which is what RFC 6376 §3.5 specifies and what a signer using
/// `l=` expects. `refuse` is available for operators who would rather take RFC
/// 6376 §8.2 at its word and ignore such signatures; see the man page.
var g_body_length_policy: verify.BodyLengthPolicy = .honor;

fn usageError() error{InvalidArgument} {
    log.err("usage: securedkim -c <config-file>", .{});
    return error.InvalidArgument;
}

/// Every failure below is reported by `bootstrap.fatal`, which explains why: after
/// `daemonize` stderr is /dev/null and syslog is the only channel left (X-16).
pub fn main() !void {
    runDaemon() catch |e| return bootstrap_mod.fatal(e);
}

fn runDaemon() !void {
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
    // These three owned slices become process-lifetime globals, so freeing them
    // is not about reclaiming memory — the process is ending either way. It is
    // so that a startup failure prints its reason AND NOTHING ELSE. Every config
    // error used to be followed by three `error(gpa): ... leaked` lines, which is
    // how a reader learns to scroll past GPA output; this suite has had real
    // leaks (X-2) that looked exactly like those three. `reloadConfig` already
    // frees the same slices for the real reason, that SIGHUP repeats.
    //
    // Registered before the worker pool is built, so it runs after the join at
    // the end of this function and never while a worker can still read them.
    defer {
        allocator.free(dkim_cfg.listen_addresses);
        allocator.free(dkim_cfg.modes);
        allocator.free(dkim_cfg.dns_nameservers);
    }

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
    g_zmq_endpoint = dkim_cfg.zmq_endpoint;
    g_zmq_topic = dkim_cfg.zmq_topic;
    g_strip_policy = .{ .own_methods = &.{"dkim"}, .strip_all = dkim_cfg.strip_auth_results };
    g_min_key_bits = dkim_cfg.min_key_bits.bits;
    g_max_key_records = dkim_cfg.max_key_records;
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
    // Shorthand before the assets: `build` validates the table config, and a
    // failure there should report against the configuration actually in force.
    signing.setShorthand(.{
        .domain = dkim_cfg.sign_domain,
        .selector = dkim_cfg.sign_selector,
        .signed_headers = dkim_cfg.signed_headers,
        .oversign_headers = dkim_cfg.oversign_headers,
    });

    g_signing = signing.Rcu.init(allocator, signing.free);
    const initial_assets = signing.build(allocator, .{
        .signing_table = dkim_cfg.signing_table_path,
        .key_table = dkim_cfg.key_table_path,
        .key_file = dkim_cfg.sign_key_file,
    }) catch |err| {
        log.err("failed to load signing configuration: {}", .{err});
        return err;
    };
    g_signing.publish(&g_config_gen, initial_assets) catch |err| {
        signing.free(allocator, initial_assets);
        log.err("failed to publish signing configuration: {}", .{err});
        return err;
    };

    // Daemonize, block signals, start the monitor thread, claim the PID file, raise the
    // fd budget, drop privileges — in that order, for reasons recorded once in
    // `daemon.bootstrap` and enforced by its ordering tests.
    var boot = try bootstrap_mod.run(.{
        .foreground = dkim_cfg.foreground,
        .pid_file = dkim_cfg.pid_file,
        .user = dkim_cfg.user,
        .worker_threads = dkim_cfg.worker_threads,
        .max_connections = dkim_cfg.max_connections,
        .num_listeners = @intCast(dkim_cfg.listen_addresses.len),
        .spawn_threads = spawnHealthMonitor,
    });
    defer boot.deinit();

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
        .on_body = onBody,
        .on_eom = onEom,
        .on_reload = onWorkerReload,
        .required_actions = required_actions,
        // Ask for the separator as it appeared on the wire; `c=simple` hashes the
        // field verbatim (audit D-23). Masked against the MTA's offer, so one that
        // declines leaves the previous behaviour exactly as it was.
        .protocol_flags = .{ .header_leading_space = true },
        .limits = dkim_cfg.limits,
    };

    const shutdown_pipe = try posix.pipe();
    defer posix.close(shutdown_pipe[0]);

    var threads = try securemilter.pool.spawnPoolWithReload(
        allocator,
        dkim_cfg.worker_threads,
        dkim_cfg.listen_addresses,
        callbacks,
        shutdown_pipe[0],
        &g_config_gen,
        dkim_cfg.max_connections,
    );
    defer threads.deinit(allocator);

    // Bound and serving: release the parent blocked in `daemonize` (X-16).
    boot.notifyReady();

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

// Only the phases this daemon acts on are registered below. An unregistered
// callback yields `Code.continue`, which is exactly what a stub returning
// `continue` did.
//
// Notably absent is `on_header`: the worker calls `Connection.addHeader` itself
// before dispatching, so header accumulation does not depend on this daemon
// registering anything, and a stub here only looked like it did.

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
    // Via the accessor, not the macro: {client_addr} is absent from Postfix's
    // default milter_connect_macros, so reading it directly logs "unknown" for
    // every connection on a stock MTA. The accessor falls back to the address
    // SMFIC_CONNECT carried. Here the placeholder is display-only.
    const client_addr = conn.clientAddr() orelse "unknown";
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
        addArHeader(conn, "dkim", "temperror", "", "", false) catch |err|
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
            addArHeader(conn, "dkim", "permerror", "", "", false) catch |err|
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
        const full = hdr.render(conn.allocator) catch continue;
        header_strings.append(conn.allocator, full) catch continue;
    }
    defer {
        for (header_strings.items) |s| conn.allocator.free(s);
    }

    // One resolver for every signature in this message, not one each. Hoisted
    // out of the loop deliberately: signatures in a flood overwhelmingly repeat
    // the same `s=`/`d=` pair, and sharing the cache across them is what turns
    // that flood from N key fetches into one (audit X-3, and the amplification
    // measured as D-4).
    const resolver = getResolver();

    // Find DKIM-Signature headers and verify each
    var found_any = false;
    for (conn.headers.items) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, "DKIM-Signature")) continue;
        found_any = true;

        // The signature covers its own field, so under `c=simple` this separator
        // must be the one that arrived (audit D-23).
        const sig_header_raw = hdr.render(conn.allocator) catch continue;
        defer conn.allocator.free(sig_header_raw);

        const result = verify.verifySignature(
            conn.allocator,
            resolver,
            hdr.value,
            sig_header_raw,
            header_strings.items,
            body_data,
            g_min_key_bits,
            g_body_length_policy,
            g_max_key_records,
        );

        // D-17: `verify.zig` computes a precise reason for every outcome and this is
        // where it stopped -- only the weak-key case was logged, and the A-R carries
        // no reason, so `dkim=fail` reached the postmaster with the distinction gone.
        // A body-hash mismatch (transport or canonicalization) and a signature
        // mismatch (key, header set, or forgery) have opposite responses. Diagnosing
        // D-15/D-16 meant reimplementing the hash in Python to recover a fact this
        // daemon already had.
        //
        // No line for a pass: it is the common case and would bury the rest. `reason`
        // is one of our own literals so it is not escaped; `domain` is the signature's
        // sender-chosen `d=` and is (audit X-5).
        if (result.reason) |reason| {
            if (result.result != .pass) {
                log.info("{f}: dkim={s} ({s})", .{
                    escape.logField(result.domain),
                    result.result.toString(),
                    reason,
                });
            }

            // Weak keys keep a second line: it names the configured threshold, which
            // the generic reason cannot, and it is a signer-side fault.
            if (mem.eql(u8, reason, "key too small")) {
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

        addArHeader(conn, "dkim", result.result.toString(), result.domain, result.selector, result.testing) catch |err|
            return auth_stamp.deferCode(err, "dkim");
        publishEvent(conn.allocator, "verify", result.result.toString(), result.domain, result.selector);
    }

    if (!found_any) {
        addArHeader(conn, "dkim", "none", "", "", false) catch |err|
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

    // How to sign, and what with — resolved together so they cannot disagree.
    const choice = signing.resolve(assets, domain, mail_from) orelse
        return @intFromEnum(responses.Code.@"continue");
    const sign_params = choice.params;
    const sign_key = choice.key;

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
        const full = hdr.render(conn.allocator) catch
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

fn addArHeader(
    conn: *connection_mod.Connection,
    method: []const u8,
    result_str: []const u8,
    domain: []const u8,
    selector: []const u8,
    testing_key: bool,
) !void {
    var properties: [3]auth_results.MethodResult.Property = undefined;
    var prop_count: usize = 0;

    if (domain.len > 0) {
        properties[prop_count] = .{ .ptype = "header", .property = "d", .value = domain };
        prop_count += 1;
    }
    if (selector.len > 0) {
        properties[prop_count] = .{ .ptype = "header", .property = "s", .value = selector };
        prop_count += 1;
    }

    // D-11: the key is published `t=y`, so this result must not be acted on --
    // see `auth_results.testing_key_marker` for why it is reported anyway and why
    // the fact has to travel in the header rather than in memory.
    if (testing_key) {
        properties[prop_count] = .{
            .ptype = auth_results.testing_key_marker.ptype,
            .property = auth_results.testing_key_marker.property,
            .value = auth_results.testing_key_marker.value,
        };
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

    const assets = signing.build(g_allocator, .{
        .signing_table = dkim_cfg.signing_table_path,
        .key_table = dkim_cfg.key_table_path,
        .key_file = dkim_cfg.sign_key_file,
    }) catch |err| {
        log.warn("reload: failed to load signing configuration ({}), keeping previous", .{err});
        _ = g_config_gen.increment();
        return;
    };

    g_signing.publish(&g_config_gen, assets) catch |err| {
        // publish reserves its retire slot before swapping, so on failure the
        // previous snapshot is still the live one.
        signing.free(g_allocator, assets);
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

/// Per-worker reload callback: flush thread-local state. The resolver's TTL
/// cache is where verified signers' public keys are held between messages, so
/// dropping the resolver is what flushes the key cache.
fn onWorkerReload() void {
    // The resolver captured the nameserver list and cache sizing when it was
    // built, so a reload that changes either has to be able to replace it.
    // Dropping it also discards cached answers, which is the intent: after a
    // reload the operator means the new configuration, not keys fetched under
    // the old one.
    if (tl_resolver) |*r| {
        r.deinit();
        tl_resolver = null;
    }
    log.debug("worker: config reload acknowledged", .{});
}

// =============================================================================
// Tests
// =============================================================================

// THIS LIST IS LOAD-BEARING AND NOTHING ENFORCES IT. The test root is this file,
// and Zig only analyses what it references, so a module missing from here compiles,
// looks tested, and never executes. `securemilter-lib/src/pool.zig` sat in exactly
// that state for the life of the project (§11.47). Add every new module.
test {
    _ = canon;
    _ = dkim;
    _ = verify;
    _ = sign_mod;
    _ = keytable;
    _ = signing;
    _ = settings;
}

test "strip angle brackets" {
    try std.testing.expectEqualStrings("user@example.com", stripAngleBrackets("<user@example.com>"));
    try std.testing.expectEqualStrings("", stripAngleBrackets("<>"));
}

test "get sending domain" {
    try std.testing.expectEqualStrings("example.com", getSendingDomain("user@example.com").?);
    try std.testing.expect(getSendingDomain("postmaster") == null);
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
