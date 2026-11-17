"""Sealed hand-over from an unkeyed job to a key-holding job in the same workflow run (red team F18).

A job output reaches a later job only through an expression, and GitHub prints a step's `env:` in the
public log header, so a verdict or test report passed as a plain output is readable before it is
attested. Masking cannot help: the masking step would print the value in its own header. Instead the
key-holding job's environment secret (the App private key, present only in that environment) derives a
per-run X25519 key pair. The opening job publishes the public key as an output, the unkeyed job seals
the value to it, and only the recording job, which holds the same secret, can open it.

Format: `sox-seal-v1:` + base64(ephemeral X25519 public key (32) || HMAC-SHA256 tag (32) || ciphertext),
with AES-256-CTR under keys derived from the X25519 shared secret (zero IV: every key is single-use).
The primitives come from the runner's OpenSSL; Python's standard library has no X25519 or AES.

  seal.py pubkey --purpose P      (key-holding job: SEAL_SECRET in env; sets output seal_pub)
"""
import argparse
import base64
import hashlib
import hmac
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import REPO, set_output  # noqa: E402

PREFIX = "sox-seal-v1:"
PURPOSES = ("review-verdict", "qa-results")
# DER prefixes of a raw X25519 key: PKCS#8 private key and SubjectPublicKeyInfo.
_PRIV_DER = bytes.fromhex("302e020100300506032b656e04220420")
_PUB_DER = bytes.fromhex("302a300506032b656e032100")


def _openssl(*args, data=None):
    p = subprocess.run(["openssl", *args], input=data, capture_output=True)
    if p.returncode != 0:
        raise ValueError(f"openssl {args[0]} failed")
    return p.stdout


def _private(secret, purpose):
    if purpose not in PURPOSES:
        raise ValueError("unknown seal purpose")
    if not secret or not secret.strip():
        raise ValueError("no sealing secret")
    run = os.environ.get("GITHUB_RUN_ID", "local")
    return hmac.new(secret.strip().encode(), f"sox-seal/v1|{REPO}|{run}|{purpose}".encode(), hashlib.sha256).digest()


def _public_of(tmp, priv_der):
    path = os.path.join(tmp, "k.der")
    with open(path, "wb") as f:
        f.write(priv_der)
    pub = _openssl("pkey", "-inform", "DER", "-in", path, "-pubout", "-outform", "DER")
    if not pub.startswith(_PUB_DER) or len(pub) != len(_PUB_DER) + 32:
        raise ValueError("unexpected X25519 public key encoding")
    return pub[len(_PUB_DER):]


def _derive(tmp, priv_der, peer_pub):
    k, p = os.path.join(tmp, "self.der"), os.path.join(tmp, "peer.der")
    with open(k, "wb") as f:
        f.write(priv_der)
    with open(p, "wb") as f:
        f.write(_PUB_DER + peer_pub)
    shared = _openssl("pkeyutl", "-derive", "-keyform", "DER", "-inkey", k, "-peerform", "DER", "-peerkey", p)
    if len(shared) != 32 or not any(shared):
        raise ValueError("bad X25519 shared secret")
    return shared


def _keys(shared, eph_pub, pub):
    info = eph_pub + pub
    return (hmac.new(shared, b"enc" + info, hashlib.sha256).digest(),
            hmac.new(shared, b"mac" + info, hashlib.sha256).digest())


def _ctr(key, data):
    return _openssl("enc", "-aes-256-ctr", "-nosalt", "-K", key.hex(), "-iv", "00" * 16, data=data)


def public_key(secret, purpose):
    """Base64 raw X25519 public key for this run and purpose."""
    with tempfile.TemporaryDirectory() as tmp:
        return base64.b64encode(_public_of(tmp, _PRIV_DER + _private(secret, purpose))).decode()


def seal(pub_b64, plaintext):
    pub = base64.b64decode(pub_b64 or "", validate=True)
    if len(pub) != 32:
        raise ValueError("no sealing public key")
    with tempfile.TemporaryDirectory() as tmp:
        eph_der = _openssl("genpkey", "-algorithm", "X25519", "-outform", "DER")
        eph_pub = _public_of(tmp, eph_der)
        enc, mac = _keys(_derive(tmp, eph_der, pub), eph_pub, pub)
    ct = _ctr(enc, plaintext)
    tag = hmac.new(mac, eph_pub + ct, hashlib.sha256).digest()
    return PREFIX + base64.b64encode(eph_pub + tag + ct).decode()


def unseal(secret, purpose, sealed):
    """Plaintext bytes, or ValueError for anything not sealed to this run's key for `purpose`."""
    if not isinstance(sealed, str) or not sealed.startswith(PREFIX):
        raise ValueError("not a sealed value")
    raw = base64.b64decode(sealed[len(PREFIX):], validate=True)
    if len(raw) < 64:
        raise ValueError("sealed value too short")
    eph_pub, tag, ct = raw[:32], raw[32:64], raw[64:]
    priv_der = _PRIV_DER + _private(secret, purpose)
    with tempfile.TemporaryDirectory() as tmp:
        pub = _public_of(tmp, priv_der)
        enc, mac = _keys(_derive(tmp, priv_der, eph_pub), eph_pub, pub)
    if not hmac.compare_digest(tag, hmac.new(mac, eph_pub + ct, hashlib.sha256).digest()):
        raise ValueError("sealed value failed authentication")
    return _ctr(enc, ct)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pubkey"); p.add_argument("--purpose", required=True, choices=PURPOSES)
    args = ap.parse_args()
    set_output("seal_pub", public_key(os.environ.get("SEAL_SECRET"), args.purpose))
    print(f"sealing key for {args.purpose} published")


if __name__ == "__main__":
    main()
