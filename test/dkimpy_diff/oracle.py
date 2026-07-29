"""dkimpy as the independent implementation, plus disposable signing keys.

Two things live here, and the second is the one that makes the harness trustworthy.

**Signing.** `sign()` produces a DKIM-Signature with dkimpy, so every message the
differential suite feeds `securedkim` was signed by *something else*. That is the
property the internal tests never had: D-15, D-16 and D-18 all survived because
the suite only ever asked the daemon to verify its own signatures, and D-18 in
particular round-tripped perfectly against itself while interoperating with nobody.

**A self-check control.** `verify()` has dkimpy verify the message it just signed,
via an injected `dnsfunc` so no DNS is involved. Every case runs this control
before `securedkim` is consulted at all, and a case whose control fails is
reported as a **harness error, never as a product defect**.

That control is not defensive padding. Twice on this project a harness bug has
presented as a pile of product defects -- `c=simple/*` in the ARC suite, and a
`type(object())` mistake in the DKIM DNS server that served key records one
character at a time and produced 11 phantom failures in a single run. A
differential harness makes that failure mode worse, not better: it generates
messages programmatically, so a corpus bug can produce hundreds of plausible
"disagreements" at once. The control decides which side is broken before anyone
starts reading Zig.

Keys are generated fresh per run into a temporary directory and never committed.
DKIM test keys are private key material, `test/keys/` is gitignored precisely
because it holds some, and nothing here needs to persist: dkimpy signs anew each
run, so reproducibility comes from the corpus rather than from the keys.
"""

import base64
import os
import subprocess
import tempfile

import dkim
from nacl.signing import SigningKey


class Keys:
    """RSA keys at several sizes plus an Ed25519 key, as a context manager."""

    RSA_SIZES = (1024, 2048, 4096)

    def __init__(self):
        self.dir = None
        self.rsa = {}          # bits -> (pem_bytes, public_b64)
        self.ed25519 = None    # (seed_b64, public_b64)

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="dkimdiff-keys-")
        for bits in self.RSA_SIZES:
            self.rsa[bits] = self._gen_rsa(bits)
        sk = SigningKey.generate()
        self.ed25519 = (
            base64.b64encode(bytes(sk)).decode(),
            base64.b64encode(bytes(sk.verify_key)).decode(),
        )
        return self

    def __exit__(self, *exc):
        if self.dir and os.path.isdir(self.dir):
            for f in os.listdir(self.dir):
                os.unlink(os.path.join(self.dir, f))
            os.rmdir(self.dir)
        return False

    def _gen_rsa(self, bits):
        path = os.path.join(self.dir, f"rsa{bits}.pem")
        subprocess.run(["openssl", "genrsa", "-out", path, str(bits)],
                       check=True, capture_output=True)
        # The DKIM p= tag is the base64 of the DER SubjectPublicKeyInfo, which is
        # exactly a PEM public key with its armour and newlines removed.
        pub = subprocess.run(["openssl", "rsa", "-in", path, "-pubout"],
                             check=True, capture_output=True).stdout.decode()
        b64 = "".join(l for l in pub.splitlines() if not l.startswith("-----"))
        return open(path, "rb").read(), b64

    def privkey_for(self, algorithm, rsa_bits):
        if algorithm == "ed25519-sha256":
            return self.ed25519[0].encode()
        return self.rsa[rsa_bits][0]

    def key_record(self, algorithm, rsa_bits):
        """The TXT record a verifier will fetch for this key."""
        if algorithm == "ed25519-sha256":
            return f"v=DKIM1; k=ed25519; p={self.ed25519[1]}"
        return f"v=DKIM1; k=rsa; p={self.rsa[rsa_bits][1]}"


def sign(message, keys, *, selector, domain, algorithm, canon, sign_headers,
         use_length=False):
    """Sign `message` with dkimpy and return the full signed message.

    `canon` is a "header/body" string such as "relaxed/simple".
    """
    hdr_canon, body_canon = canon.split("/")
    sig = dkim.sign(
        message,
        selector.encode(),
        domain.encode(),
        keys.privkey_for(algorithm, 2048),
        canonicalize=(hdr_canon.encode(), body_canon.encode()),
        signature_algorithm=algorithm.encode(),
        include_headers=[h.encode() for h in sign_headers],
        length=use_length,
    )
    return sig + message


def sign_with_bits(message, keys, *, selector, domain, canon, sign_headers, rsa_bits):
    """RSA-only signing at a specific key size, for the key-size sweep."""
    hdr_canon, body_canon = canon.split("/")
    sig = dkim.sign(
        message,
        selector.encode(),
        domain.encode(),
        keys.rsa[rsa_bits][0],
        canonicalize=(hdr_canon.encode(), body_canon.encode()),
        signature_algorithm=b"rsa-sha256",
        include_headers=[h.encode() for h in sign_headers],
    )
    return sig + message


def verify(signed_message, key_record, *, dns_name, minkey=1024):
    """Have dkimpy verify, resolving the key through an injected function.

    Returns True or False. Injecting the lookup keeps this control independent of
    the DNS server `securedkim` talks to, so a fault in that server shows up as a
    disagreement rather than as a matching failure on both sides -- which would
    look like agreement and prove nothing.
    """
    want = dns_name.lower().rstrip(".").encode()
    record = key_record.encode()

    def dnsfunc(name, timeout=5):
        return record if name.lower().rstrip(b".") == want else b""

    try:
        return bool(dkim.verify(signed_message, dnsfunc=dnsfunc, minkey=minkey))
    except dkim.DKIMException:
        return False
    except Exception:
        return False
