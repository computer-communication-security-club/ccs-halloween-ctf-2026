#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""
Automated solver for DEAD SIGNAL (rev, static).

Recovers the flag from the player handout alone (dist/dead_signal):

  1. Locate the magic-tagged constant block ("DSIGCONSTv1") in the binary and
     unpack the five-stage validation pipeline's parameters.
  2. Invert the pipeline from the embedded target: undo the cross-dword chain
     (reverse order), undo the per-dword affine maps via the modular inverse
     of their odd multipliers mod 2^32, replay the rolling state forward while
     un-mixing, then undo the rotation/XOR stage and the permutation. This
     yields the unique 24-character authentication token.
  3. Derive the flag key from the recovered token with ARX_HASH and XOR-
     decrypt the embedded ciphertext.

Reads only dist/ (never flag.txt), needs no network, prints the flag to stdout
as the last line, and exits nonzero on any failure.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

MAGIC = b"DSIGCONSTv1\x00\x00\x00\x00\x00"
CONST_FMT = "<16s24s24s24sIII6I6I6s2s24s128sI"
CONST_SIZE = struct.calcsize(CONST_FMT)
TOKEN_LEN = 24
BLOCKS = 6


# --------------------------------------------------------------- primitives

def rol32(x: int, n: int) -> int:
    n &= 31
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> ((32 - n) & 31))) & 0xFFFFFFFF


def ror8(x: int, n: int) -> int:
    n &= 7
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def fold8(state: int) -> int:
    state &= 0xFFFFFFFF
    return (state ^ (state >> 8) ^ (state >> 16) ^ (state >> 24)) & 0xFF


def arx_hash(data: bytes) -> bytes:
    """ARX_HASH — identical definition to the challenge binary."""
    h = [(0x9E3779B9 * (j + 1)) ^ 0xC2B2AE35 for j in range(8)]
    for i, byte in enumerate(data):
        a, b, c = i & 7, (i + 3) & 7, (i + 5) & 7
        h[a] = (h[a] + byte) & 0xFFFFFFFF
        h[a] = rol32(h[a], ((i * 5) & 7) + 1)
        h[b] ^= h[a]
        h[c] = (h[c] + rol32(h[a], 9)) & 0xFFFFFFFF
    h[0] ^= (len(data) * 0x85EBCA6B) & 0xFFFFFFFF
    for _ in range(8):
        for j in range(8):
            h[j] = (h[j] + h[(j + 1) & 7]) & 0xFFFFFFFF
            h[j] = rol32(h[j], 7)
            h[j] ^= h[(j + 3) & 7]
            h[j] = (h[j] * 0x27D4EB2D) & 0xFFFFFFFF
    return b"".join(struct.pack("<I", x & 0xFFFFFFFF) for x in h)


# -------------------------------------------------------------- extraction

def extract_consts(blob: bytes) -> dict:
    off = blob.find(MAGIC)
    if off < 0:
        raise RuntimeError("constant block not found in binary")
    if blob.find(MAGIC, off + 1) >= 0 or off + CONST_SIZE > len(blob):
        raise RuntimeError("constant block missing, duplicated, or truncated")
    fields = struct.unpack_from(CONST_FMT, blob, off)
    rest = fields[7:]
    return {
        "perm": list(fields[1]),
        "xkey": list(fields[2]),
        "rots": list(fields[3]),
        "roll_seed": fields[4],
        "roll_mul": fields[5],
        "roll_add": fields[6],
        "blk_mul": list(rest[0:6]),
        "blk_add": list(rest[6:12]),
        "blk_rol": list(rest[12]),
        "target": rest[14],
        "flag_ct": rest[15],
        "flag_len": rest[16],
    }


def invert_transform(w: bytes, c: dict) -> bytes:
    d = list(struct.unpack("<6I", w))
    # undo the cross-dword chain, reverse order (later dwords stay final)
    for j in range(BLOCKS - 1, 0, -1):
        d[j] ^= rol32(d[j - 1], c["blk_rol"][j])
    # undo the affine maps; odd multipliers are invertible mod 2^32
    for j in range(BLOCKS):
        d[j] = ((d[j] - c["blk_add"][j]) * pow(c["blk_mul"][j], -1, 1 << 32)) & 0xFFFFFFFF
    v = list(b"".join(struct.pack("<I", x) for x in d))
    # replay the rolling state, un-mixing each byte
    state = c["roll_seed"]
    u = []
    for i in range(TOKEN_LEN):
        ui = v[i] ^ fold8(state)
        u.append(ui)
        state = (state * c["roll_mul"] + c["roll_add"] + ui) & 0xFFFFFFFF
    # undo rotations/XOR and the permutation
    x = [ror8(u[i], c["rots"][i]) ^ c["xkey"][i] for i in range(TOKEN_LEN)]
    tok = [0] * TOKEN_LEN
    for i in range(TOKEN_LEN):
        tok[c["perm"][i]] = x[i]
    return bytes(tok)


def decrypt_flag(c: dict, token: bytes) -> bytes:
    key = arx_hash(token)
    out = bytearray()
    for j in range((c["flag_len"] + 31) // 32):
        kb = key + struct.pack("<I", j)
        block = arx_hash(kb)
        for i in range(32):
            idx = j * 32 + i
            if idx < c["flag_len"]:
                out.append(c["flag_ct"][idx] ^ block[i])
    return bytes(out)


def main() -> int:
    binary = Path(__file__).resolve().parent.parent / "dist" / "dead_signal"
    if not binary.is_file():
        print(f"[!] handout not found: {binary}", file=sys.stderr)
        return 1
    c = extract_consts(binary.read_bytes())
    token = invert_transform(c["target"], c)
    try:
        text = token.decode("ascii")
    except UnicodeDecodeError:
        print("[!] recovered token is not ASCII", file=sys.stderr)
        return 1
    if not all(ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for ch in text):
        print("[!] recovered token outside the expected domain", file=sys.stderr)
        return 1
    # round-trip proof before decrypting
    flag = decrypt_flag(c, token)
    if not (flag.startswith(b"ccsCTF{") and flag.endswith(b"}")):
        print("[!] decrypted payload does not look like the flag", file=sys.stderr)
        return 1
    print(f"[*] recovered token: {text}")
    print(flag.decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
