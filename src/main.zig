const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;
const daemon_mod = securemilter.daemon;
const bootstrap_mod = securemilter.bootstrap;
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
pub const flow = @import("flow.zig");

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
        .on_body = flow.onBody,
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
//
// The message flow itself is `flow.zig`. What remains here is gathering the
// globals it reads: `on_body` needs none of them and is registered directly,
// `on_eom` needs all of them and gets this wrapper.

/// The globals the message flow reads, gathered per message.
///
/// Per message rather than held, because that is the point at which these
/// values are known to agree with one another. The resolver and publisher are
/// passed as ACCESSORS, not pointers: both build lazily into thread-local
/// storage, and a `sign_only` worker must not be made to construct a DNS
/// resolver or open a ZMQ socket just to hand them over. `flow.MsgCtx` carries
/// the full reasoning.
fn msgCtx() flow.MsgCtx {
    return .{
        .authserv_id = g_authserv_id,
        .strip_policy = g_strip_policy,
        .modes = g_modes,
        .signing_rcu = &g_signing,
        .min_key_bits = g_min_key_bits,
        .body_length_policy = g_body_length_policy,
        .max_key_records = g_max_key_records,
        .resolver = getResolver,
        .publisher = getPublisher,
    };
}

fn onEom(conn: *connection_mod.Connection) u8 {
    return flow.doEom(conn, msgCtx());
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
    _ = flow;
}
