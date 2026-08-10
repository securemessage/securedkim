# SecureDKIM

High-performance DKIM signing and verification milter for Postfix, implementing RFC 6376 and RFC 8463 (Ed25519-SHA256).

## Features

- **RSA-SHA256 and Ed25519-SHA256** signature algorithms
- **Sign and verify modes** — configurable per listener
- **SigningTable/KeyTable** for multi-domain signing
- **Single-domain shorthand** — simple config for single-domain setups
- **Thread-per-core architecture** with kqueue I/O multiplexing
- **DNS resolution** with per-worker TTL caching and proactive health monitoring
- **Multi-listener** support (TCP and Unix domain sockets)
- **ZMQ event publishing** for analytics/reporting
- **SIGHUP reload** without dropping connections

## Quick Start

```sh
# Build
zig build

# Create user and directories
pw useradd _dkim -d /nonexistent -s /usr/sbin/nologin
mkdir -p /var/run/securedkim /usr/local/etc/securedkim
chown _dkim:_dkim /var/run/securedkim

# Generate DKIM key
securedkim-genkey -s 2026 -d example.com -o /usr/local/etc/securedkim/example.key
# (outputs DNS TXT record to add to your zone)

# Verify key is published
securedkim-testkey -s 2026 -d example.com -k /usr/local/etc/securedkim/example.key

# Set permissions
chmod 0600 /usr/local/etc/securedkim/example.key
chown _dkim:_dkim /usr/local/etc/securedkim/example.key

# Write config
cat > /usr/local/etc/securedkim/securedkim.conf << 'EOF'
[global]
AuthservID      = mail.example.com
User            = _dkim
PidFile         = /var/run/securedkim/securedkim.pid
DnsNameserver   = 127.0.0.1

[listener:verify-inbound]
Socket          = inet:8891@127.0.0.1
Mode            = verify

[listener:sign-outbound]
Socket          = inet:8892@127.0.0.1
Mode            = sign
Domain          = example.com
Selector        = 2026
KeyFile         = /usr/local/etc/securedkim/example.key
EOF

# Install and start
cp zig-out/bin/securedkim /usr/local/sbin/
cp zig-out/bin/securedkim-genkey /usr/local/sbin/
cp zig-out/bin/securedkim-testkey /usr/local/sbin/
securedkim -c /usr/local/etc/securedkim/securedkim.conf
```

## Configuration Reference

### [global]

| Option | Default | Description |
|--------|---------|-------------|
| `AuthservID` | `localhost` | Authentication-Results header identifier |
| `StripAuthResults` | `no` | Remove pre-existing Authentication-Results headers claiming our `AuthservID`; enable only on the first milter in the chain (RFC 8601 §5) |
| `WorkerThreads` | `0` (auto) | Worker thread count (0 = CPU count) |
| `MaxConnections` | `256` | Max simultaneous connections per worker |
| `PidFile` | `/var/run/securedkim/securedkim.pid` | PID file path |
| `Foreground` | `no` | Run in foreground (no daemonize) |
| `User` | *(none)* | Drop privileges to this user |
| `UMask` | *(inherited)* | File-creation mask (octal) for the PID file and any unix-domain listener |
| `Syslog` | `yes` | Enable syslog output |
| `SyslogFacility` | `mail` | Syslog facility |
| `LogLevel` | `info` | Log level: err, warn, info, debug |
| `DnsNameserver` | `127.0.0.1` | Comma-separated nameserver IPs |
| `DnsTimeout` | `5` | DNS timeout in seconds |
| `DnsRetries` | `2` | DNS retry count |
| `DnsCacheSize` | `1000` | Per-worker DNS cache max entries |
| `DnsNegativeTTL` | `60` | Negative cache TTL in seconds |
| `SignedHeaders` | `from:to:subject:date:message-id` | Headers to sign (colon-separated) |
| `OverSignHeaders` | `from` | Headers to oversign (colon-separated); empty disables oversigning |
| `MaxBodyBytes` | `10M` | Largest message body buffered to hash; 0 disables the limit |
| `MaxHeaders` | `500` | Largest number of headers accumulated per message; 0 disables the limit |
| `MaxHeaderBytes` | `1M` | Largest total header size per message; 0 disables the limit |
| `MaxSignatures` | `20` | Largest number of DKIM-Signature headers verified per message; 0 disables the limit |
| `MinimumKeyBits` | `1024` | Smallest RSA key size accepted from a signer's DNS key record (RFC 8301 floor) |
| `MaxKeyRecords` | `3` | TXT key records tried per selector before failing a signature (max 8) |
| `MaxEvaluationMs` | `20000` | Wall-clock ceiling for evaluating one message; 0 disables it |
| `BodyLengthTag` | `honor` | How a verified signature's `l=` tag is treated: `honor` or `refuse` |
| `ZmqEndpoint` | *(disabled)* | ZMQ PUB endpoint |
| `ZmqTopic` | `dkim` | ZMQ topic prefix |

### [listener:name]

| Option | Default | Description |
|--------|---------|-------------|
| `Socket` | — | `inet:port@ip` or `unix:/path`. The IP must be numeric (no DNS). An unparseable value is a fatal startup error, never ignored. |
| `Mode` | `verify` | `sign`, `verify`, or `both` |
| `SigningTable` | *(none)* | Path to signing table (multi-domain) |
| `KeyTable` | *(none)* | Path to key table (multi-domain) |
| `Domain` | *(none)* | Single-domain signing: domain name |
| `Selector` | *(none)* | Single-domain signing: selector |
| `KeyFile` | *(none)* | Single-domain signing: private key path |

### Multi-Domain Signing

For signing mail from multiple domains, use SigningTable + KeyTable:

**signing-table** (pattern → identity):
```
*@example.com       example
*@example.org       example-org
```

**key-table** (identity → domain:selector:keyfile):
```
example       example.com:2026:/usr/local/etc/securedkim/example.key
example-org   example.org:2026:/usr/local/etc/securedkim/example-org.key
```

## Postfix Integration

```ini
# Inbound verification (smtpd)
smtpd_milters = inet:127.0.0.1:8891

# Outbound signing (submission or transport)
# In master.cf submission service:
#   -o smtp_milters=inet:127.0.0.1:8892

milter_connect_macros = j {daemon_name} v {client_addr}
milter_default_action = accept
```

### Milter Chain Ordering

```ini
smtpd_milters = inet:127.0.0.1:8890,
                inet:127.0.0.1:8891,
                inet:127.0.0.1:8894,
                inet:127.0.0.1:8895
```

Order: **SPF (8890) → DKIM (8891) → DMARC (8894) → ARC (8895)**

## CLI Tools

### securedkim-genkey

Generate DKIM keypair and DNS TXT record:

```sh
securedkim-genkey -s 2026 -d example.com -o /path/to/key.pem
securedkim-genkey -a ed25519 -s ed2026 -d example.com -o /path/to/ed-key.pem
securedkim-genkey -b 4096 -s strong -d example.com -o /path/to/key.pem
```

### securedkim-testkey

Verify DNS record matches local key:

```sh
securedkim-testkey -s 2026 -d example.com -k /path/to/key.pem
```

## Signals

- **SIGHUP** — Reload configuration and key tables
- **SIGTERM** — Graceful shutdown (30s drain timeout)

## Part of the SecureMilter Suite

- [securemilter-lib](https://pacyworld.dev/securemessage/securemilter-lib) — Shared infrastructure library
- [securemilter-crypto](https://pacyworld.dev/securemessage/securemilter-crypto) — Cryptographic primitives
- [SecureSPF](https://pacyworld.dev/securemessage/securespf) — SPF verification
- **SecureDKIM** — DKIM signing and verification (this project)
- [SecureDMARC](https://pacyworld.dev/securemessage/securedmarc) — DMARC policy evaluation
- [SecureARC](https://pacyworld.dev/securemessage/securearc) — ARC chain validation and sealing

## Requirements

- Zig 0.15.x
- FreeBSD (kqueue/kevent)
- OpenSSL (libcrypto) for RSA operations
- Postfix with milter support (`milter_protocol = 6`)

## License

BSD-2-Clause. Copyright (c) 2026 Daniel Morante.
