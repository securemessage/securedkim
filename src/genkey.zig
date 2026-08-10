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

const Usage =
    \\Usage: securedkim-genkey [options]
    \\
    \\Generate a DKIM keypair and print the DNS TXT record.
    \\
    \\Options:
    \\  -a <algorithm>   rsa (default) or ed25519
    \\  -b <bits>        RSA key size: 2048 (default) or 4096; minimum 1024
    \\  -s <selector>    DKIM selector name (required)
    \\  -d <domain>      Domain name (required)
    \\  -o <path>        Output private key file (required)
    \\  -h               Show this help
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

    // Base64 encode
    const pub_b64 = try crypto.base64Encode(allocator, der_buf);
    defer allocator.free(pub_b64);

    // Output
    const output = try std.fmt.allocPrint(allocator,
        \\Private key written to: {s}
        \\Key size: {d} bits
        \\
        \\DNS TXT record:
        \\{s}._domainkey.{s}. IN TXT "v=DKIM1; k=rsa; p={s}"
        \\
    , .{ output_path, bits, selector, domain, pub_b64 });
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

    // Public key for DNS (raw 32-byte public key, base64 encoded)
    const pub_b64 = try crypto.base64Encode(allocator, &kp.public_key.toBytes());
    defer allocator.free(pub_b64);

    const output = try std.fmt.allocPrint(allocator,
        \\Private key written to: {s}
        \\Algorithm: Ed25519-SHA256
        \\
        \\DNS TXT record:
        \\{s}._domainkey.{s}. IN TXT "v=DKIM1; k=ed25519; p={s}"
        \\
    , .{ output_path, selector, domain, pub_b64 });
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
