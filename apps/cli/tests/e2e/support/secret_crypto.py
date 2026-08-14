#!/usr/bin/env python3
"""Stdin/stdout helper for IETF DH group 2 + AES-128-CBC PKCS7.

Each line is a JSON object. Operations:
  {"op":"open","client_pub":"<hex>"} -> {"server_pub":"<hex>","id":"..."}
  {"op":"decrypt","id":"...","iv":"<hex>","data":"<hex>"} -> {"plain":"<hex>"}
  {"op":"encrypt","id":"...","plain":"<hex>"} -> {"iv":"<hex>","data":"<hex>"}
"""

from __future__ import annotations

import json
import os
import sys

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DH_PRIME = int.from_bytes(
    bytes.fromhex(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
    ),
    "big",
)
DH_GENERATOR = 2
PARAMS = dh.DHParameterNumbers(DH_PRIME, DH_GENERATOR).parameters()

SESSIONS: dict[str, bytes] = {}
NEXT_ID = 1


def _hkdf_aes(shared: bytes) -> bytes:
    padded = shared.rjust(128, b"\x00")
    return HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"").derive(padded)


def open_session(client_pub_hex: str) -> dict:
    global NEXT_ID
    client_y = int(client_pub_hex, 16)
    peer = dh.DHPublicNumbers(client_y, PARAMS.parameter_numbers()).public_key()
    server = PARAMS.generate_private_key()
    shared = server.exchange(peer)
    key = _hkdf_aes(shared)
    sid = f"s{NEXT_ID}"
    NEXT_ID += 1
    SESSIONS[sid] = key
    server_pub = format(server.public_key().public_numbers().y, "x")
    if len(server_pub) % 2:
        server_pub = "0" + server_pub
    return {"server_pub": server_pub, "id": sid}


def decrypt(sid: str, iv_hex: str, data_hex: str) -> dict:
    key = SESSIONS[sid]
    iv = bytes.fromhex(iv_hex)
    data = bytes.fromhex(data_hex)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    return {"plain": plain.hex()}


def encrypt(sid: str, plain_hex: str) -> dict:
    key = SESSIONS[sid]
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    plain = bytes.fromhex(plain_hex)
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    data = encryptor.update(padded) + encryptor.finalize()
    return {"iv": iv.hex(), "data": data.hex()}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        op = req["op"]
        if op == "open":
            out = open_session(req["client_pub"])
        elif op == "decrypt":
            out = decrypt(req["id"], req["iv"], req["data"])
        elif op == "encrypt":
            out = encrypt(req["id"], req["plain"])
        else:
            out = {"error": f"unknown op {op}"}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
