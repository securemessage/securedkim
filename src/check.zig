//! `securedkim-check`: verify each DKIM-Signature, print per-signature results.
//! RFC 8463 Appendix A needs individual results (one good signature must not hide
//! another's failure); differential testing against `dkimpy` compares per-signature
//! verdicts. Uses the same `verify.verifySignature` and header format as the milter.
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
const deadline_mod = securemilter.deadline;

/// The one message-file parser in the suite. Not a copy of it: this tool exists
/// to predict the daemon, so a checker that models the message its own way is
/// measuring itself (refactor plan stage 5.2).
const msgfile = securemilter.msgfile;
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
    \\  -m <ms>            Wall-clock budget for the whole evaluation (default:
    \\                   20000, the daemon's MaxEvaluationMs; 0 disables)
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

const Args = struct {
    file: ?[]const u8 = null,
    nameserver: []const u8 = "127.0.0.1",
    port: u16 = 53,
    min_key_bits: ?u32 = null,
    max_key_records: u8 = verify.DEFAULT_MAX_KEY_RECORDS,
    /// The daemon's MaxEvaluationMs, for the same reason -b exists here (X-21).
    max_evaluation_ms: i64 = deadline_mod.DEFAULT_MS,
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
        } else if (mem.eql(u8, arg, "-m")) {
            const raw = it.next() orelse cli.fatal("-m needs a value");
            result.max_evaluation_ms = std.fmt.parseInt(i64, raw, 10) catch
                cli.fatal("-m must be a number of milliseconds");
            if (result.max_evaluation_ms < 0)
                cli.fatal("-m must be 0 (disabled) or a positive number of milliseconds");
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

    var msg = msgfile.parseMessage(allocator, raw, args.normalize_eol) catch
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
    // would have accumulated them. Rendered by the parser rather than here, so
    // this tool and `securedkim-sign` cannot disagree about the separator.
    const header_strings = try msg.rendered();

    var count: usize = 0;
    var any_pass = false;
    var first: ?verify.Result = null;

    // X-21: the daemon's MaxEvaluationMs applies here too -- the tool must
    // answer the question the daemon answers, budget included.
    const deadline = deadline_mod.Deadline.fromNow(args.max_evaluation_ms);

    // Every signature is reported, not just the first to pass. RFC 8463's own
    // example message carries two independent signatures and states each must
    // stand alone; an overall verdict would let one mask the other.
    for (msg.headers) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, "DKIM-Signature")) continue;

        if (deadline.expired()) {
            emit("note", "evaluation deadline exceeded; remaining signatures not verified");
            break;
        }

        // Rendered, not fabricated: the signature covers its own field, so under
        // `c=simple` this separator is hashed verbatim (audit D-23).
        const sig_header_raw = try hdr.render(allocator);
        defer allocator.free(sig_header_raw);

        const result = verify.verifySignature(allocator, &resolver, .{
            .sig_header_value = hdr.value,
            .sig_header_raw = sig_header_raw,
            .headers = header_strings,
            .body = msg.body,
            .min_key_bits = min_key_bits,
            .body_length_policy = args.body_length_policy,
            .max_key_records = args.max_key_records,
        });

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
