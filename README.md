# SecureDKIM

High-performance DKIM signing and verification milter (RFC 6376, RFC 8463) written in Zig.

Part of the [SecureMilter Suite](https://pacyworld.dev/securemessage/).

## Status

**Work in progress.** Current modules:
- `canon.zig` — RFC 6376 §3.4 header + body canonicalization (simple and relaxed modes)

## Building

Requires Zig 0.15+ and the `securemilter-lib` sibling directory.

```sh
zig build        # compile
zig build test   # run tests
```

## License

BSD-2-Clause. Copyright (c) 2026 Daniel Morante.
