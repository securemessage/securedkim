//! `securedkim-check` — verify every DKIM-Signature on a message file and print
//! the results, so an external conformance suite can drive the shipped verifier.
//!
//! Exists for the same reason `securespf-check` and `securearc-check` do: RFC
//! conformance is a V1 release gate, and a gate is only meaningful if the thing
//! under test is the code that ships.
//!
//! Two oracles need this interface, and they need different things from it:
//!
//!  - The **RFC 8463 Appendix A** message carries an Ed25519-SHA256 and an
//!    RSA-SHA256 signature over the same body, and the RFC states that "either
//!    signature would be valid if the other were not present". Reporting only an
//!    overall verdict would let one good signature hide the other's failure, so
//!    every signature is reported individually, in header order.
//!  - **Differential testing against `dkimpy`** compares per-signature verdicts
//!    on messages `dkimpy` signed, where the whole point is which signature
//!    disagreed and why.
//!
//! It deliberately calls the same `verify.verifySignature` the milter calls, with
//! the same header list shape — `"Name: value"` with folding intact and the
//! single space after the colon dropped, which is what Postfix delivers to a
//! milter that has not negotiated `SMFIP_HDR_LEADSPC`, and no daemon here does.
//! `onEom` is not reused directly only because it needs a live milter
//! `Connection`.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const process = std.process;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const cli = securemilter.cli.Tool("securedkim-check");
const dns_mod = securemilter.dns;
const crypto = @import("securemilter_crypto").crypto;

const verify = @import("verify.zig");

const Usage =
    \\Usage: securedkim-check [options] <message-file>
    \\
    \\Verify every DKIM-Signature on an RFC 5322 message and print the result of
    \\each as key=value lines on stdout.
    \\
    \\Options:
    \\  -f <file>        Message file (may also be given positionally)
    \\  -n <nameserver>  DNS nameserver (default: 127.0.0.1)
    \\  -p <port>        DNS nameserver port (default: 53)
    \\  -b <bits>        Minimum RSA key bits accepted (default: RFC 8301 floor)
    \\  --max-key-records <n>
    \\                   Key records tried at one selector (default: 3)
    \\  --refuse-l       Report `policy` for signatures carrying l= instead of
    \\                   honouring it (RFC 6376 §8.2 sanctions either)
    \\  --no-normalize   Do not rewrite bare CR/LF in the file to CRLF. Use when
    \\                   the file is already CRLF-canonical and a bare CR or LF
    \\                   is body *data* that canonicalization must not touch
    \\  -h               Show this help
    \\
    \\Output keys:
    \\  signatures            Count of DKIM-Signature fields found
    \\  sig.<n>.result        pass, fail, temperror, permerror, neutral, policy
    \\  sig.<n>.domain        the signature's d= tag
    \\  sig.<n>.selector      the signature's s= tag
    \\  sig.<n>.reason        failure detail, when the verifier supplied one
    \\  sig.<n>.unsigned      octets of body the signature does not cover (l=)
    \\  result                pass if any signature passed, else the first
    \\                        signature's result, else none
    \\
    \\Exit status is 0 whenever a verdict was reached, including "fail" — the
    \\verdict goes to stdout. A non-zero status means the tool could not run.
    \\
;

/// Largest message accepted. Generous for a conformance suite whose cases are a
/// few kilobytes, and bounded so a stray argument cannot exhaust memory.
const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;

/// The daemon's own header type, not a copy of it. This tool exists to predict
/// the daemon, and `had_space` plus `render` are exactly the part a copy would
/// have silently omitted (audit D-23).
const Header = securemilter.connection.Header;
const splitLeadingSpace = securemilter.connection.splitLeadingSpace;

const Message = struct {
    headers: []const Header,
    body: []const u8,
    arena: std.heap.ArenaAllocator,

    fn deinit(self: *Message) void {
        self.arena.deinit();
    }
};

/// Split an RFC 5322 message into header fields and a body.
///
/// Folded values keep their line breaks. That is not a convenience: DKIM
/// `relaxed` header canonicalization is defined as an operation *on* the folded
/// form (RFC 6376 §3.4.2, "Unfold all header field continuation lines"), and the
/// milter receives values from Postfix with folding intact, so unfolding here
/// would test the canonicalizer against input it never sees in production.
///
/// Line endings are normalised to CRLF first. A message arrives over SMTP with
/// CRLF and both canonicalizations in §3.4 are specified in terms of it; a file
/// on disk carries bare LF. Converting here rather than tolerating LF further
/// down keeps the run testing the same byte sequence a real message produces.
/// **If cases fail with a body-hash mismatch, check this first.**
fn parseMessage(allocator: Allocator, raw: []const u8, normalize_eol: bool) !Message {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const text = if (normalize_eol) try toCrlf(a, raw) else raw;

    const sep = mem.indexOf(u8, text, "\r\n\r\n");
    const header_block = if (sep) |s| text[0..s] else text;
    const body = if (sep) |s| text[s + 4 ..] else "";

    var headers: std.ArrayListUnmanaged(Header) = .{};

    var field_start: ?usize = null;
    var i: usize = 0;
    while (i <= header_block.len) {
        const line_end = mem.indexOfPos(u8, header_block, i, "\r\n") orelse header_block.len;
        const line = header_block[i..line_end];
        const is_continuation = line.len > 0 and (line[0] == ' ' or line[0] == '\t');

        if (!is_continuation and field_start != null) {
            try appendField(a, &headers, header_block[field_start.?..i]);
            field_start = null;
        }
        if (line.len > 0 and !is_continuation) field_start = i;

        if (line_end >= header_block.len) break;
        i = line_end + 2;
    }
    if (field_start) |s| try appendField(a, &headers, header_block[s..]);

    return .{
        .headers = try headers.toOwnedSlice(a),
        .body = body,
        .arena = arena,
    };
}

/// Record one complete field, trailing CRLF trimmed, split at the first colon.
///
/// **The single space after the colon is split off, not dropped.** A milter
/// receives header values with one leading space already removed by the MTA;
/// `securedkim` now negotiates `SMFIP_HDR_LEADSPC` and recovers the bit saying
/// whether there was one, so `simple` — which hashes the field verbatim — can
/// rebuild it exactly (audit D-23).
///
/// **One SP, never a TAB**, as measured against Postfix and sendmail in §11.40.
/// This line used to strip a leading TAB too, which no MTA does. Continuation
/// lines keep their own leading whitespace, which is also what the MTA delivers.
fn appendField(
    a: Allocator,
    headers: *std.ArrayListUnmanaged(Header),
    field_raw: []const u8,
) !void {
    const field = mem.trimRight(u8, field_raw, "\r\n");
    if (field.len == 0) return;
    const colon = mem.indexOfScalar(u8, field, ':') orelse return;
    const split = splitLeadingSpace(field[colon + 1 ..]);
    try headers.append(a, .{
        .name = field[0..colon],
        .value = split.value,
        .had_space = split.had_space,
    });
}

/// Normalise CR, LF and CRLF to CRLF.
fn toCrlf(a: Allocator, raw: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .{};
    try out.ensureTotalCapacity(a, raw.len + raw.len / 8 + 2);
    var i: usize = 0;
    while (i < raw.len) {
        const c = raw[i];
        if (c == '\r') {
            try out.appendSlice(a, "\r\n");
            i += if (i + 1 < raw.len and raw[i + 1] == '\n') 2 else 1;
        } else if (c == '\n') {
            try out.appendSlice(a, "\r\n");
            i += 1;
        } else {
            try out.append(a, c);
            i += 1;
        }
    }
    return out.toOwnedSlice(a);
}

const Args = struct {
    file: ?[]const u8 = null,
    nameserver: []const u8 = "127.0.0.1",
    port: u16 = 53,
    min_key_bits: ?u32 = null,
    max_key_records: u8 = verify.DEFAULT_MAX_KEY_RECORDS,
    body_length_policy: verify.BodyLengthPolicy = .honor,
    /// Rewrite bare CR and bare LF to CRLF while reading the file.
    ///
    /// On by default because a `.eml` edited on a Unix host is usually LF-only and
    /// DKIM is defined over CRLF, so without it the tool would be useless on
    /// ordinary files. Unlike the header space-stripping in `appendField`, this is
    /// **not** emulating anything the MTA does: a milter receives body octets
    /// verbatim over `SMFIC_BODY`, bare CR and LF included.
    ///
    /// That makes the default actively wrong for one job -- testing what body
    /// canonicalization does to a bare CR or LF, which RFC 5234 says are not WSP
    /// and RFC 6376 therefore leaves as data. The normalization destroys exactly
    /// those octets before the canonicalizer sees them, so the differential suite
    /// turns it off and D-22 was invisible through this tool until it could.
    normalize_eol: bool = true,
};

fn parseArgs(allocator: Allocator) !Args {
    var result = Args{};
    var it = try process.argsWithAllocator(allocator);
    defer it.deinit();
    _ = it.next();

    while (it.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            cli.out(Usage);
            process.exit(0);
        } else if (mem.eql(u8, arg, "-f")) {
            result.file = try allocator.dupe(u8, it.next() orelse cli.fatal("-f needs a value"));
        } else if (mem.eql(u8, arg, "-n")) {
            result.nameserver = try allocator.dupe(u8, it.next() orelse cli.fatal("-n needs a value"));
        } else if (mem.eql(u8, arg, "-p")) {
            const raw = it.next() orelse cli.fatal("-p needs a value");
            result.port = std.fmt.parseInt(u16, raw, 10) catch cli.fatal("invalid port");
        } else if (mem.eql(u8, arg, "-b")) {
            const raw = it.next() orelse cli.fatal("-b needs a value");
            result.min_key_bits = std.fmt.parseInt(u32, raw, 10) catch cli.fatal("invalid bits");
        } else if (mem.eql(u8, arg, "--max-key-records")) {
            const raw = it.next() orelse cli.fatal("--max-key-records needs a value");
            result.max_key_records = std.fmt.parseInt(u8, raw, 10) catch
                cli.fatal("invalid --max-key-records");
        } else if (mem.eql(u8, arg, "--refuse-l")) {
            result.body_length_policy = .refuse;
        } else if (mem.eql(u8, arg, "--no-normalize")) {
            result.normalize_eol = false;
        } else if (arg.len > 0 and arg[0] == '-') {
            cli.fatal("unknown option");
        } else {
            result.file = try allocator.dupe(u8, arg);
        }
    }

    if (result.file == null) cli.fatal("a message file is required (see -h)");
    return result;
}

fn emit(key: []const u8, value: []const u8) void {
    cli.out(key);
    cli.out("=");
    cli.out(value);
    cli.out("\n");
}

/// `sig.<n>.<field>=<value>`, built without an allocator so a reporting failure
/// cannot become an allocation failure mid-run.
fn emitSig(index: usize, field: []const u8, value: []const u8) void {
    var buf: [64]u8 = undefined;
    const key = std.fmt.bufPrint(&buf, "sig.{d}.{s}", .{ index, field }) catch return;
    emit(key, value);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Argument strings outlive parsing and are never individually freed, so they
    // get their own arena. Without it the leak detector prints a report on every
    // run, which a conformance harness reading stderr cannot distinguish from a
    // real fault.
    var arg_arena = std.heap.ArenaAllocator.init(allocator);
    defer arg_arena.deinit();

    const args = try parseArgs(arg_arena.allocator());

    const raw = std.fs.cwd().readFileAlloc(allocator, args.file.?, MAX_MESSAGE_BYTES) catch
        cli.fatal("could not read the message file");
    defer allocator.free(raw);

    var msg = parseMessage(allocator, raw, args.normalize_eol) catch
        cli.fatal("could not parse the message");
    defer msg.deinit();

    // Same floor reconciliation the daemon performs, so a conformance run cannot
    // accidentally accept a key the shipped verifier would reject. Note that
    // RFC 8463's own example uses a 1024-bit RSA key, which is exactly the
    // RFC 8301 floor -- a checker defaulting any higher could not verify it.
    const min_key_bits: u32 = if (args.min_key_bits) |b|
        crypto.resolveMinRsaBits(b).bits
    else
        crypto.RFC8301_MIN_RSA_BITS;

    var resolver = dns_mod.Resolver.init(allocator, .{
        .nameservers = &.{args.nameserver},
        .port = args.port,
    });
    defer resolver.deinit();

    // The header list the verifier sees: every field, in order, as the milter
    // would have accumulated them.
    var header_strings: std.ArrayListUnmanaged([]const u8) = .{};
    defer {
        for (header_strings.items) |s| allocator.free(s);
        header_strings.deinit(allocator);
    }
    for (msg.headers) |hdr| {
        const full = try hdr.render(allocator);
        try header_strings.append(allocator, full);
    }

    var count: usize = 0;
    var any_pass = false;
    var first: ?verify.Result = null;

    // Every signature is reported, not just the first to pass. RFC 8463's own
    // example message carries two independent signatures and states each must
    // stand alone; an overall verdict would let one mask the other.
    for (msg.headers) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, "DKIM-Signature")) continue;

        // Rendered, not fabricated: the signature covers its own field, so under
        // `c=simple` this separator is hashed verbatim (audit D-23).
        const sig_header_raw = try hdr.render(allocator);
        defer allocator.free(sig_header_raw);

        const result = verify.verifySignature(
            allocator,
            &resolver,
            hdr.value,
            sig_header_raw,
            header_strings.items,
            msg.body,
            min_key_bits,
            args.body_length_policy,
            args.max_key_records,
        );

        emitSig(count, "result", result.result.toString());
        emitSig(count, "domain", result.domain);
        emitSig(count, "selector", result.selector);
        if (result.reason) |reason| emitSig(count, "reason", reason);
        // Emitted only when set, so every existing expectation is untouched. The
        // verdict alone cannot show this: a `t=y` key is reported with its real
        // result precisely so it looks like any other, which means the suite has
        // no way to tell the flag survived unless it is printed (audit D-11).
        if (result.testing) emitSig(count, "testing", "true");
        if (result.unsigned_body_bytes > 0) {
            var buf: [24]u8 = undefined;
            const n = std.fmt.bufPrint(&buf, "{d}", .{result.unsigned_body_bytes}) catch "?";
            emitSig(count, "unsigned", n);
        }

        if (result.result == .pass) any_pass = true;
        if (first == null) first = result.result;
        count += 1;
    }

    var cbuf: [24]u8 = undefined;
    emit("signatures", std.fmt.bufPrint(&cbuf, "{d}", .{count}) catch "?");

    // RFC 6376 §6.1: a verifier that finds one valid signature "MAY choose to
    // stop", so a single pass makes the message verified regardless of the rest.
    const overall: []const u8 = if (any_pass)
        "pass"
    else if (first) |f| f.toString() else "none";
    emit("result", overall);
}
