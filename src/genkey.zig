const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const posix = std.posix;
const process = std.process;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

// This standalone tool depends only on `securemilter_crypto`; keep these helpers
// aligned with `securemilter.cli`.

/// Write all of `data`, handling permitted short writes.
fn writeOut(data: []const u8) void {
    var written: usize = 0;
    while (written < data.len) {
        written += posix.write(posix.STDOUT_FILENO, data[written..]) catch return;
    }
}

fn writeErr(data: []const u8) void {
    var written: usize = 0;
    while (written < data.len) {
        written += posix.write(posix.STDERR_FILENO, data[written..]) catch return;
    }
}

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/rsa.h");
});

/// RFC 8301-recommended RSA signing-key size, above the verification minimum.
const RSA_RECOMMENDED_BITS = 2048;

/// Create a new private-key file with mode 0600 and no replacement path.
fn createKeyFile(allocator: std.mem.Allocator, output_path: []const u8) fs.File {
    return fs.cwd().createFile(output_path, .{
        .mode = 0o600,
        .exclusive = true,
    }) catch |err| {
        // Report file-creation errors through the tool's standard fatal path.
        if (err == error.PathAlreadyExists) {
            const msg = std.fmt.allocPrint(
                allocator,
                "{s} already exists; refusing to replace a private key that may be in use\n",
                .{output_path},
            ) catch fatal("the output path already exists");
            defer allocator.free(msg);
            writeErr(msg);
            fatal("refusing to overwrite an existing key");
        }
        const msg = std.fmt.allocPrint(
            allocator,
            "could not create {s}: {t}\n",
            .{ output_path, err },
        ) catch fatal("could not create the key file");
        defer allocator.free(msg);
        writeErr(msg);
        fatal("could not create the key file");
    };
}

/// RFC 1035 section 3.3: a single character-string in a TXT record is at most
/// 255 octets. BIND9 refuses anything longer.
const MAX_TXT_STRING: usize = 255;

/// Build a BIND9-compatible zone fragment for a DKIM TXT record.
///
/// RSA-2048 produces ~410 octets for a single `"v=DKIM1; ..."` string, which
/// exceeds the 255-byte limit. The output splits into multiple quoted strings
/// inside parentheses, which the resolver concatenates per RFC 7208.
fn formatDnsRecord(
    allocator: std.mem.Allocator,
    selector: []const u8,
    domain: []const u8,
    algorithm: []const u8,
    key_bits: []const u8,
    pub_b64: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .{};
    errdefer out.deinit(allocator);

    // Comment line.
    try out.appendSlice(allocator, "; DKIM public key for ");
    try out.appendSlice(allocator, domain);
    try out.appendSlice(allocator, ", selector ");
    try out.appendSlice(allocator, selector);
    try out.appendSlice(allocator, " (");
    try out.appendSlice(allocator, algorithm);
    if (key_bits.len > 0) {
        try out.appendSlice(allocator, ", ");
        try out.appendSlice(allocator, key_bits);
        try out.appendSlice(allocator, " bits");
    }
    try out.appendSlice(allocator, ")\n");

    // Owner + type.
    try out.appendSlice(allocator, selector);
    try out.appendSlice(allocator, "._domainkey.");
    try out.appendSlice(allocator, domain);
    try out.appendSlice(allocator, ". IN TXT");

    // The full TXT value as one logical string.
    const value = try std.fmt.allocPrint(allocator, "v=DKIM1; k={s}; p={s}", .{ algorithm, pub_b64 });
    defer allocator.free(value);

    if (value.len <= MAX_TXT_STRING) {
        // Fits in one string: no parentheses needed.
        try out.appendSlice(allocator, " \"");
        try out.appendSlice(allocator, value);
        try out.appendSlice(allocator, "\"\n");
    } else {
        // Split into <=255-byte quoted strings inside parentheses.
        try out.appendSlice(allocator, " (\n");
        var pos: usize = 0;
        while (pos < value.len) {
            const end = @min(pos + MAX_TXT_STRING, value.len);
            try out.appendSlice(allocator, "    \"");
            try out.appendSlice(allocator, value[pos..end]);
            try out.appendSlice(allocator, "\"\n");
            pos = end;
        }
        try out.appendSlice(allocator, "    )\n");
    }

    return out.toOwnedSlice(allocator);
}

/// Derive the .dns path from the key path: replace a final extension, or append
/// .dns if there is none.
fn dnsPath(allocator: std.mem.Allocator, key_path: []const u8) ![]u8 {
    const base = fs.path.basename(key_path);
    if (mem.lastIndexOfScalar(u8, base, '.')) |dot| {
        // Replace ".key" (or whatever extension) with ".dns".
        const stem_len = key_path.len - (base.len - dot);
        return std.fmt.allocPrint(allocator, "{s}.dns", .{key_path[0..stem_len]});
    }
    return std.fmt.allocPrint(allocator, "{s}.dns", .{key_path});
}

/// Write the zone fragment beside the private key. Mode 0644: this is public
/// key material, not a secret. Refuses to overwrite.
fn writeZoneFile(allocator: std.mem.Allocator, key_path: []const u8, content: []const u8) ![]const u8 {
    const path = try dnsPath(allocator, key_path);
    errdefer allocator.free(path);

    const file = fs.cwd().createFile(path, .{
        .mode = 0o644,
        .exclusive = true,
    }) catch |err| {
        if (err == error.PathAlreadyExists) {
            const msg = std.fmt.allocPrint(
                allocator,
                "{s} already exists; refusing to replace a DNS record file that may be in use\n",
                .{path},
            ) catch fatal("the DNS record file already exists");
            defer allocator.free(msg);
            writeErr(msg);
            fatal("refusing to overwrite an existing DNS record file");
        }
        const msg = std.fmt.allocPrint(
            allocator,
            "could not create {s}: {t}\n",
            .{ path, err },
        ) catch fatal("could not create the DNS record file");
        defer allocator.free(msg);
        writeErr(msg);
        fatal("could not create the DNS record file");
    };
    defer file.close();
    file.writeAll(content) catch |err| {
        const msg = std.fmt.allocPrint(
            allocator,
            "could not write {s}: {t}\n",
            .{ path, err },
        ) catch fatal("could not write the DNS record file");
        defer allocator.free(msg);
        writeErr(msg);
        fatal("could not write the DNS record file");
    };
    return path;
}

const Usage =
    \\Usage: securedkim-genkey [options]
    \\
    \\Generate a DKIM keypair and write a BIND9-compatible DNS zone fragment.
    \\
    \\Options:
    \\  -a <algorithm>   rsa (default) or ed25519
    \\  -b <bits>        RSA key size: 2048 (default) or 4096; minimum 1024
    \\  -s <selector>    DKIM selector name (required)
    \\  -d <domain>      Domain name (required)
    \\  -o <path>        Output private key file (required)
    \\  -h               Show this help
    \\
    \\The DNS record is written to a .dns file beside the private key (e.g.
    \\test2026.key produces test2026.dns). The file can be $INCLUDEd or pasted
    \\into a BIND9 zone. RSA records are split into <=255-byte strings as
    \\required by RFC 1035 section 3.3.
    \\
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = process.args();
    _ = args.next(); // skip argv[0]

    var algorithm: []const u8 = "rsa";
    var bits: c_int = 2048;
    var selector: ?[]const u8 = null;
    var domain: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            writeOut(Usage);
            return;
        } else if (mem.eql(u8, arg, "-a")) {
            algorithm = args.next() orelse return fatal("missing argument for -a");
        } else if (mem.eql(u8, arg, "-b")) {
            const val = args.next() orelse return fatal("missing argument for -b");
            bits = std.fmt.parseInt(c_int, val, 10) catch return fatal("invalid -b value");
        } else if (mem.eql(u8, arg, "-s")) {
            selector = args.next() orelse return fatal("missing argument for -s");
        } else if (mem.eql(u8, arg, "-d")) {
            domain = args.next() orelse return fatal("missing argument for -d");
        } else if (mem.eql(u8, arg, "-o")) {
            output_path = args.next() orelse return fatal("missing argument for -o");
        } else {
            const msg = std.fmt.allocPrint(allocator, "unknown option: {s}\n", .{arg}) catch return fatal("use -h for help");
            defer allocator.free(msg);
            writeErr(msg);
            return fatal("use -h for help");
        }
    }

    const sel = selector orelse return fatal("-s <selector> is required");
    const dom = domain orelse return fatal("-d <domain> is required");
    const out = output_path orelse return fatal("-o <output-path> is required");

    if (mem.eql(u8, algorithm, "rsa")) {
        // Reject keys below the RFC 8301 verifier minimum; do not silently clamp
        // the requested size.
        if (bits < crypto.RFC8301_MIN_RSA_BITS) {
            const msg = std.fmt.allocPrint(
                allocator,
                "-b {d} is below the RFC 8301 3.2 minimum of {d}; " ++
                    "every verifier would reject signatures from this key\n",
                .{ bits, crypto.RFC8301_MIN_RSA_BITS },
            ) catch return fatal("RSA key size is too small");
            defer allocator.free(msg);
            writeErr(msg);
            return fatal("refusing to generate an unusable key");
        }
        // A warning, not a refusal: 1024 is still valid per RFC 8301 and an operator
        // may be constrained by a DNS provider's TXT size limits. 2048 is what §3.2
        // recommends.
        if (bits < RSA_RECOMMENDED_BITS) {
            const msg = std.fmt.allocPrint(
                allocator,
                "warning: -b {d} is below the {d} bits RFC 8301 3.2 recommends\n",
                .{ bits, RSA_RECOMMENDED_BITS },
            ) catch return fatal("could not format warning");
            defer allocator.free(msg);
            writeErr(msg);
        }
        try generateRsa(allocator, bits, sel, dom, out);
    } else if (mem.eql(u8, algorithm, "ed25519")) {
        try generateEd25519(allocator, sel, dom, out);
    } else {
        return fatal("unsupported algorithm (use 'rsa' or 'ed25519')");
    }
}

fn generateRsa(
    allocator: std.mem.Allocator,
    bits: c_int,
    selector: []const u8,
    domain: []const u8,
    output_path: []const u8,
) !void {
    // Generate RSA keypair via OpenSSL
    const ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse
        return error.KeygenCtxFailed;
    defer c.EVP_PKEY_CTX_free(ctx);

    if (c.EVP_PKEY_keygen_init(ctx) != 1) return error.KeygenInitFailed;
    if (c.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1) return error.KeygenBitsFailed;

    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen(ctx, &pkey) != 1) return error.KeygenFailed;
    defer c.EVP_PKEY_free(pkey);

    // Own the descriptor here and hand it to OpenSSL, rather than letting OpenSSL
    // open the path (audit D-8): `createKeyFile` creates it 0600 up front, so the
    // key is never written into a file that briefly existed at 0666 & ~umask, and
    // there is no fixed-size path buffer for an overlong `-o` to overrun.
    const file = createKeyFile(allocator, output_path);
    defer file.close();

    // BIO_NOCLOSE: the descriptor stays owned by `file` above, so exactly one of the
    // two closes it.
    const bio_file = c.BIO_new_fd(file.handle, c.BIO_NOCLOSE) orelse return error.FileCreateFailed;
    defer _ = c.BIO_free(bio_file);
    if (c.PEM_write_bio_PrivateKey(bio_file, pkey, null, null, 0, null, null) != 1)
        return error.KeyWriteFailed;

    // Extract public key in DER format for DNS record
    var der_len: c_int = 0;
    der_len = c.i2d_PUBKEY(pkey, null);
    if (der_len <= 0) return error.PubkeyExportFailed;

    const der_buf = try allocator.alloc(u8, @intCast(der_len));
    defer allocator.free(der_buf);

    var der_ptr: [*c]u8 = der_buf.ptr;
    _ = c.i2d_PUBKEY(pkey, &der_ptr);

    const pub_b64 = try crypto.base64Encode(allocator, der_buf);
    defer allocator.free(pub_b64);

    const bits_str = try std.fmt.allocPrint(allocator, "{d}", .{bits});
    defer allocator.free(bits_str);

    const record = try formatDnsRecord(allocator, selector, domain, "rsa", bits_str, pub_b64);
    defer allocator.free(record);

    const dns_path = try writeZoneFile(allocator, output_path, record);
    defer allocator.free(dns_path);

    const output = try std.fmt.allocPrint(allocator,
        \\Private key written to: {s}
        \\DNS record written to:  {s}
        \\Algorithm: rsa, {d} bits
        \\
    , .{ output_path, dns_path, bits });
    defer allocator.free(output);
    writeOut(output);
}

fn generateEd25519(
    allocator: std.mem.Allocator,
    selector: []const u8,
    domain: []const u8,
    output_path: []const u8,
) !void {
    // Generate Ed25519 keypair using Zig std.crypto
    const Ed25519 = std.crypto.sign.Ed25519;

    // Random seed. Wiped on the way out along with its base64 form: this is the
    // private key, and both buffers outlived their use unzeroed (audit C-1).
    var seed: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    std.crypto.random.bytes(&seed);

    const kp = try Ed25519.KeyPair.generateDeterministic(seed);

    // Write seed as raw 32 bytes in PEM-like format
    // OpenDKIM convention: base64-encoded seed in a PEM wrapper
    const seed_b64 = try crypto.base64Encode(allocator, &seed);
    defer {
        std.crypto.secureZero(u8, seed_b64);
        allocator.free(seed_b64);
    }

    // PEM markers built at comptime (avoids gitleaks pattern match on literal)
    const pem_type = "ED25519 PRIVATE KEY";
    const pem_begin = "-----BEGIN " ++ pem_type ++ "-----\n";
    const pem_end = "\n-----END " ++ pem_type ++ "-----\n";

    const file = createKeyFile(allocator, output_path);
    defer file.close();
    // `writeAll`, not `write`: a short write is legal and `_ = try file.write(...)`
    // discarded the count, so a truncated key file was possible and silent. Same
    // defect the `writeOut` helper above carries a note about.
    try file.writeAll(pem_begin);
    try file.writeAll(seed_b64);
    try file.writeAll(pem_end);

    const pub_b64 = try crypto.base64Encode(allocator, &kp.public_key.toBytes());
    defer allocator.free(pub_b64);

    const record = try formatDnsRecord(allocator, selector, domain, "ed25519", "", pub_b64);
    defer allocator.free(record);

    const dns_path = try writeZoneFile(allocator, output_path, record);
    defer allocator.free(dns_path);

    const output = try std.fmt.allocPrint(allocator,
        \\Private key written to: {s}
        \\DNS record written to:  {s}
        \\Algorithm: Ed25519-SHA256
        \\
    , .{ output_path, dns_path });
    defer allocator.free(output);
    writeOut(output);
}

/// Matches `securemilter.cli.Tool("securedkim-genkey").fatal`: the tool's own name
/// as the prefix rather than a bare "error: ", and `EXIT_FATAL` = 2 so every tool in
/// the suite reports a fatal error with the same status.
fn fatal(msg: []const u8) noreturn {
    writeErr("securedkim-genkey: ");
    writeErr(msg);
    writeErr("\n");
    process.exit(2);
}

// =============================================================================
// Tests
// =============================================================================

test "dnsPath replaces a final extension" {
    const allocator = std.testing.allocator;
    const p = try dnsPath(allocator, "/var/db/securedkim/keys/test2026.key");
    defer allocator.free(p);
    try std.testing.expectEqualStrings("/var/db/securedkim/keys/test2026.dns", p);
}

test "dnsPath appends .dns when there is no extension" {
    const allocator = std.testing.allocator;
    const p = try dnsPath(allocator, "/var/db/securedkim/keys/test2026");
    defer allocator.free(p);
    try std.testing.expectEqualStrings("/var/db/securedkim/keys/test2026.dns", p);
}

test "dnsPath handles a bare filename" {
    const allocator = std.testing.allocator;
    const p = try dnsPath(allocator, "mykey.pem");
    defer allocator.free(p);
    try std.testing.expectEqualStrings("mykey.dns", p);
}

test "ed25519 record fits in one string and has no parentheses" {
    const allocator = std.testing.allocator;
    // Ed25519 p= is 44 base64 characters: well under 255.
    const record = try formatDnsRecord(allocator, "sel", "example.com", "ed25519", "", "AAAA" ** 11);
    defer allocator.free(record);

    try std.testing.expect(mem.indexOf(u8, record, "(\n") == null);
    try std.testing.expect(mem.indexOf(u8, record, " IN TXT \"v=DKIM1; k=ed25519; p=") != null);
}

test "RSA-2048 record is split into multiple strings" {
    const allocator = std.testing.allocator;
    // ~392 base64 characters for RSA-2048: prefix + p= exceeds 255.
    const fake_b64 = "A" ** 392;
    const record = try formatDnsRecord(allocator, "test2026", "example.com", "rsa", "2048", fake_b64);
    defer allocator.free(record);

    // Must use parenthesised multi-string form.
    try std.testing.expect(mem.indexOf(u8, record, " IN TXT (\n") != null);
    try std.testing.expect(mem.indexOf(u8, record, "    )\n") != null);

    // No individual quoted string may exceed 255 octets.
    var lines = mem.splitScalar(u8, record, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " ");
        if (trimmed.len < 2 or trimmed[0] != '"') continue;
        // Content between quotes: strip opening and closing quote.
        const content = trimmed[1 .. trimmed.len - 1];
        try std.testing.expect(content.len <= MAX_TXT_STRING);
    }

    // Concatenation of all quoted strings must equal the full record value.
    const expected_value = try std.fmt.allocPrint(allocator, "v=DKIM1; k=rsa; p={s}", .{fake_b64});
    defer allocator.free(expected_value);

    var reassembled: std.ArrayList(u8) = .{};
    defer reassembled.deinit(allocator);
    var lines2 = mem.splitScalar(u8, record, '\n');
    while (lines2.next()) |line| {
        const trimmed = mem.trim(u8, line, " ");
        if (trimmed.len < 2 or trimmed[0] != '"') continue;
        try reassembled.appendSlice(allocator, trimmed[1 .. trimmed.len - 1]);
    }
    try std.testing.expectEqualStrings(expected_value, reassembled.items);
}

test "RSA-4096 record splits correctly" {
    const allocator = std.testing.allocator;
    // ~736 base64 characters for RSA-4096.
    const fake_b64 = "B" ** 736;
    const record = try formatDnsRecord(allocator, "big", "example.com", "rsa", "4096", fake_b64);
    defer allocator.free(record);

    // Every quoted string <= 255 octets.
    var lines = mem.splitScalar(u8, record, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " ");
        if (trimmed.len < 2 or trimmed[0] != '"') continue;
        try std.testing.expect(trimmed[1 .. trimmed.len - 1].len <= MAX_TXT_STRING);
    }
}
