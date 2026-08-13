//! End-of-message DKIM verification and signing pipeline.
//!
//! `MsgCtx` supplies the per-message configuration and accessors; `main.zig`
//! owns daemon lifecycle and global state.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const connection_mod = securemilter.connection;
const auth_results = securemilter.auth_results;
const auth_stamp = securemilter.auth_stamp;
const escape = securemilter.escape;
const codec = securemilter.milter.codec;
const responses = securemilter.milter.responses;
const dns_mod = securemilter.dns;
const deadline_mod = securemilter.deadline;
const zmq = securemilter.zmq;
const log = securemilter.log;
const header_scrub = securemilter.header_scrub;
const header_fold = securemilter.header_fold;

const verify = @import("verify.zig");
const sign_mod = @import("sign.zig");
const signing = @import("signing.zig");
const settings = @import("settings.zig");

const Mode = settings.Mode;
const modeLabel = settings.modeLabel;

/// Per-message inputs for the DKIM flow.
///
/// Resolver and publisher accessors preserve lazy per-thread initialization for
/// listener modes that do not use them.
pub const MsgCtx = struct {
    authserv_id: []const u8,
    strip_policy: header_scrub.StripPolicy,
    modes: []const Mode,
    signing_rcu: *signing.Rcu,
    min_key_bits: u32,
    body_length_policy: verify.BodyLengthPolicy,
    max_key_records: u8,
    /// Signature-validation deadline in milliseconds; zero disables it.
    max_evaluation_ms: i64,
    resolver: *const fn () *dns_mod.Resolver,
    publisher: *const fn () *zmq.Publisher,
};

pub fn onBody(conn: *connection_mod.Connection, data: []const u8) u8 {
    // Keep the full body for end-of-message processing. On overflow, the
    // connection latches the condition and later skips signing and verification.
    // Log only the first rejected chunk to avoid per-chunk log amplification.
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

pub fn doEom(conn: *connection_mod.Connection, ctx: MsgCtx) u8 {
    const start_ns = std.time.nanoTimestamp();

    // Remove forged results for this authserv-id before adding DKIM results.
    _ = header_scrub.stripAuthResults(conn, ctx.authserv_id, ctx.strip_policy);

    const mode = modeFor(ctx.modes, conn.listener_index);

    const result = switch (mode) {
        .verify_only => doVerify(conn, ctx),
        .sign_only => doSign(conn, ctx),
        .both => blk: {
            _ = doVerify(conn, ctx);
            break :blk doSign(conn, ctx);
        },
    };
    const elapsed_ms = @divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000);
    const queue_id = conn.macros.queue_id orelse "-";
    // Use the accessor because it falls back to the SMFIC_CONNECT address.
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

/// Return the mode for a connection's listener.
///
/// An invalid index falls back to verification-only mode.
fn modeFor(modes: []const Mode, listener_index: usize) Mode {
    if (listener_index < modes.len) return modes[listener_index];
    log.err(
        "listener index {d} has no configured mode ({d} known): falling back to verify",
        .{ listener_index, modes.len },
    );
    return .verify_only;
}

fn doVerify(conn: *connection_mod.Connection, ctx: MsgCtx) u8 {
    // An incomplete local copy cannot be verified, so report `dkim=temperror`.
    if (conn.contentTruncated()) {
        addArHeader(conn, ctx, "dkim", "temperror", "", "", false) catch |err|
            return auth_stamp.deferCode(err, "dkim");
        publishEvent(ctx, conn.allocator, "verify", "temperror", "", "");
        return @intFromEnum(responses.Code.@"continue");
    }

    // Enforce the signature cap before DNS lookups and cryptographic work.
    const max_sigs = conn.limits.max_signatures;
    if (max_sigs != 0) {
        const sig_count = conn.countHeadersCapped("DKIM-Signature", max_sigs);
        if (sig_count > max_sigs) {
            const peer = conn.getPeerDisplay();
            log.warn(
                "more than MaxSignatures={d} DKIM-Signature headers from {f}[{f}]: not verifying",
                .{ max_sigs, escape.logField(peer.name), escape.logField(peer.ip) },
            );
            addArHeader(conn, ctx, "dkim", "permerror", "", "", false) catch |err|
                return auth_stamp.deferCode(err, "dkim");
            publishEvent(ctx, conn.allocator, "verify", "permerror", "", "");
            return @intFromEnum(responses.Code.@"continue");
        }
    }

    // Each signature canonicalizes and optionally truncates the body differently,
    // so it receives the complete body rather than a shared hash.
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

    // Share one resolver and its cache across all message signatures.
    const resolver = ctx.resolver();

    // One deadline covers all signatures; an expiry yields `temperror` because
    // remaining signatures were not evaluated.
    const deadline = deadline_mod.Deadline.fromNow(ctx.max_evaluation_ms);

    // Find DKIM-Signature headers and verify each
    var found_any = false;
    for (conn.headers.items) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, "DKIM-Signature")) continue;
        found_any = true;

        if (deadline.expired()) {
            log.warn("dkim: evaluation deadline exceeded; remaining signatures not verified", .{});
            addArHeader(conn, ctx, "dkim", "temperror", "", "", false) catch |err|
                return auth_stamp.deferCode(err, "dkim");
            publishEvent(ctx, conn.allocator, "verify", "temperror", "", "");
            break;
        }

        // The signature covers its own field, so under `c=simple` this separator
        // must be the one that arrived (audit D-23).
        const sig_header_raw = hdr.render(conn.allocator) catch continue;
        defer conn.allocator.free(sig_header_raw);

        const result = verify.verifySignature(conn.allocator, resolver, .{
            .sig_header_value = hdr.value,
            .sig_header_raw = sig_header_raw,
            .headers = header_strings.items,
            .body = body_data,
            .min_key_bits = ctx.min_key_bits,
            .body_length_policy = ctx.body_length_policy,
            .max_key_records = ctx.max_key_records,
        });

        // Log non-pass diagnostic reasons. The domain is sender-controlled and
        // must be escaped; reasons are internal literals.
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
                    .{ escape.logField(result.domain), ctx.min_key_bits },
                );
            }
        }

        // Warn when `l=` leaves trailing body bytes unsigned.
        if (result.unsigned_body_bytes > 0) {
            log.warn(
                "{f}: dkim=pass covers only the first l= octets, {d} trailing body octets are unsigned (RFC 6376 8.2)",
                .{ escape.logField(result.domain), result.unsigned_body_bytes },
            );
        }

        addArHeader(conn, ctx, "dkim", result.result.toString(), result.domain, result.selector, result.testing) catch |err|
            return auth_stamp.deferCode(err, "dkim");
        publishEvent(ctx, conn.allocator, "verify", result.result.toString(), result.domain, result.selector);
    }

    if (!found_any) {
        addArHeader(conn, ctx, "dkim", "none", "", "", false) catch |err|
            return auth_stamp.deferCode(err, "dkim");
        publishEvent(ctx, conn.allocator, "verify", "none", "", "");
    }

    return @intFromEnum(responses.Code.@"continue");
}

fn doSign(conn: *connection_mod.Connection, ctx: MsgCtx) u8 {
    // Do not sign an incomplete local copy of the message.
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
    const assets = ctx.signing_rcu.get() orelse return @intFromEnum(responses.Code.@"continue");

    // How to sign, and what with — resolved together so they cannot disagree.
    const choice = signing.resolve(assets, domain, mail_from) orelse
        return @intFromEnum(responses.Code.@"continue");
    const sign_params = choice.params;
    const sign_key = choice.key;

    // Build the header list that will be signed.
    //
    // One defer for both the strings and the list, registered before the loop, so
    // an early return below cannot leak the strings appended so far.
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

    // Prepend DKIM-Signature header via milter protocol: SMFIR_INSHEADER at
    // index 0, as OpenDKIM does. An appended signature lands at the bottom of
    // the header block, adjacent to the body separator — off-convention for a
    // signature field, and visibly "in the body area" to anyone reading the
    // source.
    //
    // The separator is handed to `insertHeader` rather than carried inside the
    // value, which is what makes the transmitted bytes `"DKIM-Signature: " ++
    // value` under either negotiation: the milter writes the space when it owns
    // it, the MTA writes it otherwise, and exactly one of them does. Those are
    // the bytes `signMessage` canonicalized, and under `c=simple` -- which
    // hashes the field verbatim -- signed and transmitted have to agree
    // octet for octet or no verifier anywhere accepts the signature.
    //
    // Passing `false` and leaving the space inside the value agrees only while
    // the MTA grants `SMFIP_HDR_LEADSPC`. One that declines it puts a space in
    // front of the one already there, and every `c=simple` signature this
    // daemon produced would fail everywhere, silently, with the daemon
    // reporting `sign pass`.
    // The signed value folds with CRLF — the canonical form the hash covers.
    // The milter protocol carries folds as bare LF (smfi_addheader(3): the MTA
    // adds the CR), and sending CRLF lets the MTA double every fold into a
    // blank line, ending the header block early for every downstream parser.
    const wire_value = header_fold.toWire(conn.allocator, sign_result.value()) catch
        return signInternalError("building the DKIM-Signature header");
    defer conn.allocator.free(wire_value);

    const hdr_payload = responses.insertHeader(
        conn.allocator,
        0,
        "DKIM-Signature",
        wire_value,
        conn.negotiated_protocol.header_leading_space,
    ) catch return signInternalError("building the DKIM-Signature header");
    defer conn.allocator.free(hdr_payload);

    // A swallowed write here delivered the message unsigned and then published
    // "sign pass" for it, so both the recipient and our own event stream were
    // misinformed at once (audit X-10).
    codec.writePacket(conn.fd, hdr_payload) catch
        return signInternalError("writing the DKIM-Signature header");

    publishEvent(ctx, conn.allocator, "sign", "pass", sign_params.domain, sign_params.selector);

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
    ctx: MsgCtx,
    allocator: Allocator,
    action: []const u8,
    result_str: []const u8,
    domain: []const u8,
    selector: []const u8,
) void {
    // `domain` and `selector` are the signature's own `d=` and `s=` tags, so both
    // are sender-chosen: an unescaped `"` in `d=` would end the JSON string early
    // and let the remainder of the payload be reinterpreted, which is exactly
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

    ctx.publisher().publish(json);
}

fn addArHeader(
    conn: *connection_mod.Connection,
    ctx: MsgCtx,
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

    try auth_stamp.stamp(conn.allocator, conn.fd, ctx.authserv_id, &.{
        .{
            .method = method,
            .result = result_str,
            .reason = null,
            .properties = properties[0..prop_count],
        },
    }, conn.negotiated_protocol.header_leading_space);
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
// Tests
// =============================================================================

test "strip angle brackets" {
    try std.testing.expectEqualStrings("user@example.com", stripAngleBrackets("<user@example.com>"));
    try std.testing.expectEqualStrings("", stripAngleBrackets("<>"));
}

test "get sending domain" {
    try std.testing.expectEqualStrings("example.com", getSendingDomain("user@example.com").?);
    try std.testing.expect(getSendingDomain("postmaster") == null);
}

// X-9: this wrapper must stay fallible. Swallowing a stamping failure would
// deliver a message with no `dkim=` field while this daemon reported success,
// and `securedmarc` would then evaluate DMARC without it. Asserting the type
// is what makes a regression a build failure rather than a silent behaviour
// change.
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

// The mode lookup's out-of-range fallback is the safe one (audit A-2).
test "an out-of-range listener index falls back to verify, never to signing" {
    const modes = [_]Mode{ .sign_only, .both };
    try std.testing.expectEqual(Mode.sign_only, modeFor(&modes, 0));
    try std.testing.expectEqual(Mode.both, modeFor(&modes, 1));
    try std.testing.expectEqual(Mode.verify_only, modeFor(&modes, 2));
    try std.testing.expectEqual(Mode.verify_only, modeFor(&.{}, 0));
}
