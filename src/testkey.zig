//! DKIM-specific wrapper for the shared `securemilter.testkey` tool.
//!
//! It supplies SecureDKIM's name, usage text, and daemon identifier.

const securemilter = @import("securemilter");
const securemilter_crypto = @import("securemilter_crypto");

const Usage =
    \\Usage: securedkim-testkey [options]
    \\
    \\Fetch a DKIM DNS key record and verify it matches a local private key.
    \\
    \\Options:
    \\  -s <selector>    DKIM selector name (required)
    \\  -d <domain>      Domain name (required)
    \\  -k <keyfile>     Private key file to compare against (required)
    \\  -n <nameserver>  DNS nameserver (default: 127.0.0.1)
    \\  -p <port>        DNS nameserver port (default: 53)
    \\  -h               Show this help
    \\
    \\Examples:
    \\  securedkim-testkey -s mail -d example.com -k /usr/local/etc/securedkim/keys/mail.key
    \\
;

const Tool = securemilter.testkey.Tool(securemilter_crypto, .{
    .name = "securedkim-testkey",
    .daemon = "securedkim",
    .usage = Usage,
});

pub const main = Tool.main;
