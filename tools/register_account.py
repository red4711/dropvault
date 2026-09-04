#!/usr/bin/env python3
"""Headless Bitwarden/Vaultwarden account registration.

Implements the Bitwarden client key-derivation + registration payload:
  master key    = PBKDF2-SHA256(600k, password, email)
  stretched key = HKDF-SHA512 expand(master_key, "enc", 64)
  keys          = RSA-2048 (private PKCS#8, public) + mac-64 signing key
  user key      = stretched_key (single-key user)
Everything is encrypted client-side; the server never sees the password.

Reads:  --password-file (0600 file with the generated master password)
        --email, --server
Writes: /dev/stdout JSON {email, server, kdf, keys_payload_sent}
        (never the password itself)
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def enc_string(enc_type: int, iv: bytes, ct: bytes, mac: bytes) -> str:
    return f"{enc_type}.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def encrypt_with_keys(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> str:
    """Bitwarden EncString type 2: AES-256-CBC (PKCS7) + HMAC-SHA256(iv||ct)."""
    import os as _os
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = _os.urandom(16)
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len]) * pad_len
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return enc_string(2, iv, ct, mac)


def master_key(password: bytes, email: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=email.strip().lower().encode(), iterations=ITERATIONS)
    return kdf.derive(password)


def stretched(master: bytes) -> bytes:
    """Bitwarden 2026 stretchKey: HKDF-Expand-SHA256(mk, 'enc', 32) || HKDF-Expand-SHA256(mk, 'mac', 32)."""
    from cryptography.hazmat.primitives import hashes as _hashes
    enc = HKDFExpand(algorithm=_hashes.SHA256(), length=32, info=b"enc").derive(master)
    mac = HKDFExpand(algorithm=_hashes.SHA256(), length=32, info=b"mac").derive(master)
    return enc + mac


def _os_urandom(n: int) -> bytes:
    import os
    return os.urandom(n)


def encrypt_user_key(stretched_key: bytes, user_key: bytes) -> str:
    """User key wrapped with the stretched master key (enc=sk[:32], mac=sk[32:])."""
    return encrypt_with_keys(stretched_key[:32], stretched_key[32:], user_key)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--email", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--name", default="dropvault")
    ap.add_argument("--ca-cert", default=None, help="CA bundle for self-hosted TLS")
    args = ap.parse_args()

    password = Path(args.password_file).read_text().strip().encode()

    mk = master_key(password, args.email)
    sk = stretched(mk)

    # asymmetric keys (DER, not PEM — bw parses DER)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_der = priv.private_bytes(serialization.Encoding.DER,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_der = priv.public_key().public_bytes(Encoding.DER,
                                             PublicFormat.SubjectPublicKeyInfo)
    signing = _os_urandom(64)

    # user key: random 64 bytes (enc 32 + mac 32), wrapped by stretched master key
    user_key = _os_urandom(64)
    keys_b64 = encrypt_user_key(sk, user_key)  # "key" (akey) EncString type 1

    # private key blob = DER || 64-byte mac signing key, wrapped with user key
    uk_enc, uk_mac = user_key[:32], user_key[32:]
    priv_enc = encrypt_with_keys(uk_enc, uk_mac, priv_der + signing)

    payload = {
        "email": args.email,
        "name": args.name,
        "masterPasswordHash": b64(hashlib.pbkdf2_hmac("sha256", mk, password, 1)),
        "masterPasswordHint": None,
        "key": keys_b64,
        "keys": {
            "publicKey": b64(pub_der),
            "encryptedPrivateKey": priv_enc,
        },
        "kdf": 0,
        "kdfIterations": ITERATIONS,
        "kdfMemory": None,
        "kdfParallelism": None,
    }

    # Vaultwarden identity register endpoint (anonymous)
    url = args.server.rstrip("/") + "/identity/accounts/register"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    ssl_ctx = None
    if args.ca_cert:
        import ssl as _ssl
        ssl_ctx = _ssl.create_default_context(cafile=args.ca_cert)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            body = resp.read().decode()
            print(json.dumps({"ok": True, "status": resp.status,
                              "email": args.email, "server": args.server,
                              "kdf": "PBKDF2-600k"}))
            return 0
    except urllib.error.HTTPError as e:
        print(json.dumps({"ok": False, "status": e.code, "body": e.read().decode()[:300]}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
