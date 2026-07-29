"""Minimal authoritative DNS server serving the TXT key records a DKIM case needs.

Adapted from `securearc/test/arc_valimail/txtdns.py`. Serving real DNS on a
loopback port rather than stubbing the lookup is deliberate: the resolver is part
of what RFC 6376 §6.1.2 specifies, and its two failure modes are required to
differ. A query that establishes the key record does not exist means PERMFAIL,
because the signature can never verify; a query that merely fails to respond may
only mean TEMPFAIL. Stubbing the lookup would leave that distinction untested,
and it is the distinction that decides whether a message is retried or rejected.

Multi-string TXT is supported and exercised. A 2048-bit RSA key does not fit in
one 255-byte TXT string, so every real-world RSA key record takes the joining
path -- which is also the path that catches a resolver reading only the first
string. RFC 8463 notes the contrast: an Ed25519 key is 44 base64 octets and fits
in one string.
"""

import socket
import struct
import threading

TYPE_TXT = 16
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
RCODE_SERVFAIL = 2


def _encode_name(name):
    """Encode a dotted name as DNS labels."""
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _decode_name(data, offset):
    """Decode a DNS name, following compression pointers. Returns (name, next_offset)."""
    labels = []
    jumped = False
    end = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
        if not jumped:
            end = offset
    return ".".join(labels), end


def _txt_rdata(value):
    """A TXT rdata field: one or more length-prefixed strings, each <= 255 bytes.

    Splitting at 255 is the wire format's requirement, not a choice.
    """
    raw = value.encode("utf-8")
    chunks = [raw[i:i + 255] for i in range(0, len(raw), 255)] or [b""]
    return b"".join(bytes([len(c)]) + c for c in chunks)


class DkimDns:
    """Serves {name: txt_value} on a UDP port, as a context manager.

    A value may be a list of strings to serve several TXT records at one name.
    The sentinel `DkimDns.SERVFAIL` makes a name answer SERVFAIL instead, which
    is how a case expresses the "failed to respond" branch of RFC 6376 §6.1.2 as
    distinct from "does not exist".
    """

    SERVFAIL = object()

    def __init__(self, records, port, verbose=False):
        # Order matters: test the sentinel by identity first, then a list, then
        # wrap a bare string. An earlier version asked
        # `isinstance(v, (list, type(SERVFAIL)))`, and since the sentinel is a
        # plain `object()` that type test matched *everything* -- so single
        # strings were stored unwrapped and `for value in values` below iterated
        # them one character at a time, serving a TXT record per character. Every
        # key record became garbage, and the suite reported 11 product defects
        # that did not exist.
        self.records = {}
        for k, v in (records or {}).items():
            key = k.lower().rstrip(".")
            if v is self.SERVFAIL:
                self.records[key] = self.SERVFAIL
            elif isinstance(v, list):
                self.records[key] = v
            else:
                self.records[key] = [v]
        self.port = port
        self.verbose = verbose
        self.sock = None
        self.thread = None
        self.running = False
        self.queries = []
        self._lock = threading.Lock()

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.sock:
            self.sock.close()
        return False

    def query_log(self):
        with self._lock:
            return list(self.queries)

    def _serve(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                reply = self._respond(data)
            except Exception:
                continue
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass

    def _respond(self, query):
        if len(query) < 12:
            return None
        txn = query[0:2]
        qname, offset = _decode_name(query, 12)
        if offset + 4 > len(query):
            return None
        qtype, _qclass = struct.unpack("!HH", query[offset:offset + 4])
        question = query[12:offset + 4]

        key = qname.lower().rstrip(".")
        values = self.records.get(key)

        if qtype == TYPE_TXT:
            with self._lock:
                self.queries.append(key)

        if self.verbose:
            state = "SERVFAIL" if values is self.SERVFAIL else (
                "hit" if values is not None else "NXDOMAIN")
            print(f"    dns: {qname} type={qtype} -> {state}")

        if values is self.SERVFAIL:
            flags = 0x8400 | RCODE_SERVFAIL
            return txn + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + question

        # Anything not held is an authoritative "no such name", which RFC 6376
        # §6.1.2 step 3 turns into PERMFAIL. NOERROR-with-no-answer would say the
        # name exists without a key, a different fact.
        if values is None or qtype != TYPE_TXT:
            flags = 0x8400 | RCODE_NXDOMAIN
            return txn + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + question

        answers = b""
        for value in values:
            rdata = _txt_rdata(value)
            answers += (
                _encode_name(qname)
                + struct.pack("!HHIH", TYPE_TXT, 1, 300, len(rdata))
                + rdata
            )
        flags = 0x8400 | RCODE_NOERROR
        return (txn + struct.pack("!HHHHH", flags, 1, len(values), 0, 0)
                + question + answers)
