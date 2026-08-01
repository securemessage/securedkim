//! `securedkim-sign` — sign a message file with the daemon's own signing path.
//!
//! The counterpart to `securedkim-check`, and it exists for the same reason: the
//! milter's signing logic is otherwise reachable only through the milter protocol,
//! so nothing external can ever look at a signature this suite produces.
//!
//! That gap is not hypothetical. **D-18 was a two-way defect** — Ed25519-SHA256
//! signed the canonicalized signing input instead of its SHA-256 digest, so every
//! signature the daemon emitted was rejected by every conformant verifier. The
//! verify half was caught by the RFC 8463 vector. The signing half was caught by
//! nothing, and would have gone on being caught by nothing, because a round-trip
//! test agrees with a symmetric mistake and the daemon had no way to hand a
//! signature to anyone else.
//!
//! With this, `dkimpy` can verify what we sign.
//!
//! **This deliberately reproduces the milter's lossy view of headers.** It parses a
//! file, but then throws the original octets away and rebuilds each field as
//! `name + ": " + value`, exactly as `securedkim-check` does and for the same
//! reason: the MTA hands a milter a name and a value with one leading space already
//! removed, so a tool that signed the pristine file bytes would produce signatures
//! the daemon cannot produce, and would hide defects rather than expose them. See
//! `appendField` in `check.zig`, and D-23 for the one case where the reconstruction
//! is provably not byte-exact.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const process = std.process;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const cli = securemilter.cli.Tool("securedkim-sign");
const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;
const canon = securemilter_crypto.canon;

const dkim = @import("dkim.zig");
const sign = @import("sign.zig");

const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;
const MAX_KEY_BYTES = 64 * 1024;

const Usage =
    \\Usage: securedkim-sign [options] <message-file>
    \\
    \\Sign an RFC 5322 message with the same code path the milter uses, and write
    \\the signed message (DKIM-Signature prepended) to stdout.
    \\
    \\Required:
    \\  -d <domain>      Signing domain (d=)
    \\  -s <selector>    Selector (s=)
    \\  -k <file>        Private key: PEM for rsa-sha256, or a file holding the
    \\                   base64 of the 32-byte seed for ed25519-sha256
    \\
    \\Options:
    \\  -a <algorithm>   rsa-sha256 (default) or ed25519-sha256
    \\  -c <canon>       Canonicalization, e.g. relaxed/relaxed (default),
    \\                   simple/simple, relaxed/simple, simple/relaxed
    \\  --headers <list> Colon-separated h= list
    \\                   (default: from:to:subject:date:message-id)
    \\  --oversign <list> Colon-separated names to list once more than the message
    \\                   contains them, so a later addition breaks the signature
    \\                   (default: from; empty string disables)
    \\  -l               Include l= covering the whole canonicalized body
    \\  --no-timestamp   Omit t=, so output is byte-stable across runs
    \\  --no-normalize   Do not rewrite bare CR/LF in the file to CRLF
    \\  -h, --help       Show this help
    \\
    \\Note: -h is help, not the h= list, matching securedkim-check and the other
    \\tools here. opendkim and dkimpy spell the h= list -h, so this uses the long
    \\--headers rather than letting -h quietly mean something different.
    \\
    \\Exit status is 0 on success, 1 on any error, with a message on stderr.
    \\
;

const Args = struct {
    file: ?[]const u8 = null,
    domain: ?[]const u8 = null,
    selector: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    algorithm: dkim.Algorithm = .rsa_sha256,
    canonicalization: canon.CanonicalizationPair = .{ .header = .relaxed, .body = .relaxed },
    signed_headers: []const u8 = sign.DEFAULT_SIGNED_HEADERS,
    oversign_headers: []const u8 = sign.DEFAULT_OVERSIGN_HEADERS,
    include_length: bool = false,
    include_timestamp: bool = true,
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
        } else if (mem.eql(u8, arg, "-d")) {
            result.domain = try allocator.dupe(u8, it.next() orelse cli.fatal("-d needs a value"));
        } else if (mem.eql(u8, arg, "-s")) {
            result.selector = try allocator.dupe(u8, it.next() orelse cli.fatal("-s needs a value"));
        } else if (mem.eql(u8, arg, "-k")) {
            result.key_file = try allocator.dupe(u8, it.next() orelse cli.fatal("-k needs a value"));
        } else if (mem.eql(u8, arg, "-a")) {
            const raw = it.next() orelse cli.fatal("-a needs a value");
            result.algorithm = dkim.Algorithm.parse(raw) catch cli.fatal("unknown algorithm");
        } else if (mem.eql(u8, arg, "-c")) {
            const raw = it.next() orelse cli.fatal("-c needs a value");
            result.canonicalization = canon.parseCanonicalization(raw) catch
                cli.fatal("unknown canonicalization");
        } else if (mem.eql(u8, arg, "--headers")) {
            result.signed_headers = try allocator.dupe(u8, it.next() orelse
                cli.fatal("--headers needs a value"));
        } else if (mem.eql(u8, arg, "--oversign")) {
            result.oversign_headers = try allocator.dupe(u8, it.next() orelse
                cli.fatal("--oversign needs a value"));
        } else if (mem.eql(u8, arg, "-l")) {
            result.include_length = true;
        } else if (mem.eql(u8, arg, "--no-timestamp")) {
            result.include_timestamp = false;
        } else if (mem.eql(u8, arg, "--no-normalize")) {
            result.normalize_eol = false;
        } else if (arg.len > 0 and arg[0] == '-') {
            cli.fatal("unknown option (see --help)");
        } else {
            result.file = try allocator.dupe(u8, arg);
        }
    }

    if (result.file == null) cli.fatal("a message file is required (see --help)");
    if (result.domain == null) cli.fatal("-d <domain> is required");
    if (result.selector == null) cli.fatal("-s <selector> is required");
    if (result.key_file == null) cli.fatal("-k <keyfile> is required");
    return result;
}

/// Normalise CR, LF and CRLF to CRLF. See `check.zig` for why this is optional.
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

/// The message split into reconstructed header lines and a raw body.
const Message = struct {
    /// Full field lines, folding intact, rebuilt as the milter would see them.
    headers: []const []const u8,
    body: []const u8,
    arena: std.heap.ArenaAllocator,

    fn deinit(self: *Message) void {
        self.arena.deinit();
    }
};

fn parseMessage(allocator: Allocator, raw: []const u8, normalize_eol: bool) !Message {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const text = if (normalize_eol) try toCrlf(a, raw) else raw;

    const sep = mem.indexOf(u8, text, "\r\n\r\n");
    const header_block = if (sep) |s| text[0..s] else text;
    const body = if (sep) |s| text[s + 4 ..] else "";

    var headers: std.ArrayListUnmanaged([]const u8) = .{};

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

/// Rebuild one field the way the milter receives it, then re-emit it.
///
/// The round trip through name and value is the point, not an oversight: the
/// daemon signs what the MTA hands it, so signing the file's original octets
/// instead would produce signatures the daemon cannot produce.
///
/// It now round-trips through `Header`, which carries whether a space followed
/// the colon, so the re-emitted field is byte-identical to the original instead
/// of having its separator normalised to one space (audit D-23). One SP is split
/// off, never a TAB, matching what Postfix and sendmail were measured to do.
fn appendField(
    a: Allocator,
    headers: *std.ArrayListUnmanaged([]const u8),
    field_raw: []const u8,
) !void {
    const field = mem.trimRight(u8, field_raw, "\r\n");
    if (field.len == 0) return;
    const colon = mem.indexOfScalar(u8, field, ':') orelse return;
    const split = securemilter.connection.splitLeadingSpace(field[colon + 1 ..]);
    const hdr = securemilter.connection.Header{
        .name = field[0..colon],
        .value = split.value,
        .had_space = split.had_space,
    };
    try headers.append(a, try hdr.render(a));
}

/// Load a signing key, choosing the format from the algorithm.
///
/// RSA keys are PEM. An Ed25519 key is the base64 of its 32-byte seed, which is
/// what `securedkim-genkey` emits and what dkimpy accepts, so a single key file can
/// drive both implementations in a differential run.
fn loadKey(allocator: Allocator, path: []const u8, algorithm: dkim.Algorithm) !crypto.SigningKey {
    switch (algorithm) {
        .rsa_sha256 => return crypto.loadRsaKeyFile(path, crypto.RFC8301_MIN_RSA_BITS) catch
            cli.fatal("could not load the RSA private key"),
        .ed25519_sha256 => {
            // Three buffers hold the private seed on the way in -- the file text,
            // its base64 decoding, and the fixed-size copy handed to the loader --
            // and all three were released without being wiped (audit C-1). Each
            // gets zeroed here, in reverse order of creation.
            const raw = std.fs.cwd().readFileAlloc(allocator, path, MAX_KEY_BYTES) catch
                cli.fatal("could not read the key file");
            defer {
                std.crypto.secureZero(u8, raw);
                allocator.free(raw);
            }

            const trimmed = mem.trim(u8, raw, " \t\r\n");
            const decoded = crypto.base64Decode(allocator, trimmed) catch
                cli.fatal("Ed25519 key file is not valid base64");
            defer {
                std.crypto.secureZero(u8, decoded);
                allocator.free(decoded);
            }

            if (decoded.len != 32) cli.fatal("an Ed25519 seed must be exactly 32 bytes");
            var seed: [32]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            @memcpy(&seed, decoded[0..32]);

            return crypto.loadEd25519Seed(seed) catch
                cli.fatal("the Ed25519 seed does not yield a usable key");
        },
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Argument strings outlive parsing and are never individually freed, so they
    // get their own arena rather than tripping the leak detector on every run.
    var arg_arena = std.heap.ArenaAllocator.init(allocator);
    defer arg_arena.deinit();

    const args = try parseArgs(arg_arena.allocator());

    const raw = std.fs.cwd().readFileAlloc(allocator, args.file.?, MAX_MESSAGE_BYTES) catch
        cli.fatal("could not read the message file");
    defer allocator.free(raw);

    var msg = parseMessage(allocator, raw, args.normalize_eol) catch
        cli.fatal("could not parse the message");
    defer msg.deinit();

    var key = try loadKey(allocator, args.key_file.?, args.algorithm);
    defer key.deinit();

    // No key/algorithm cross-check here: `loadKey` switches on `-a` and can only
    // return the matching kind, and a file in the wrong format fails inside it --
    // an Ed25519 seed is not a valid PEM, and PEM text is not 32 base64 octets.
    // (`crypto.Algorithm` and `dkim.Algorithm` are separate enums in any case.)

    // The body hash and any l= must both describe the *canonicalized* body, so the
    // canonicalization is done once here and its length is what l= reports.
    var bc = canon.BodyCanonicalizer.init(allocator, args.canonicalization.body);
    defer bc.deinit();
    bc.update(msg.body) catch cli.fatal("body canonicalization failed");
    const canonical_body = bc.finish() catch cli.fatal("body canonicalization failed");
    defer allocator.free(canonical_body);

    const params = sign.SigningParams{
        .domain = args.domain.?,
        .selector = args.selector.?,
        .algorithm = args.algorithm,
        .canonicalization = args.canonicalization,
        .signed_headers = args.signed_headers,
        .oversign_headers = args.oversign_headers,
        .body_length = if (args.include_length) canonical_body.len else null,
        .include_timestamp = args.include_timestamp,
    };

    var result = sign.signMessage(
        allocator,
        &params,
        &key,
        msg.headers,
        crypto.sha256(canonical_body),
    ) catch cli.fatal("signing failed");
    defer result.deinit();

    // The signed message: our DKIM-Signature, then the original file unchanged.
    // The original is emitted rather than the reconstruction, because the point is
    // to produce something another implementation can verify -- and a verifier
    // reading the file must see the message it was signed over.
    cli.out(result.header);
    cli.out("\r\n");
    cli.out(if (args.normalize_eol) toCrlf(msg.arena.allocator(), raw) catch
        cli.fatal("out of memory") else raw);
}
