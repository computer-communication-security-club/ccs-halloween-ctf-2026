#!/usr/bin/env python3
"""
DEAD SIGNAL -- organizer solver.

Recovers the 24-character authentication token from the distributed,
stripped ELF binary alone:

  1. Locate the embedded constant block via its 16-byte magic marker.
  2. Unpack the parameters of the five-stage transform.
  3. Invert the transform starting from the embedded target state.

The token is COMPUTED, never hardcoded: re-run the build with a different
random token and this solver recovers that one too.

Usage:
  solver.py <path-to-dead_signal> [--json]
"""

from __future__ import annotations

import argparse
import json
import struct
import sys

TOKEN_LEN = 24
BLOCKS = 6
MAGIC = b"DSIGCONSTv1\x00\x00\x00\x00\x00"
CONST_FMT = "<16s24s24s24sIII6I6I6s2s24s128sI"
CONST_SIZE = struct.calcsize(CONST_FMT)


# ---------------------------------------------------------------- primitives

def rol32(x: int, n: int) -> int:
    n &= 31
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def ror8(x: int, n: int) -> int:
    n &= 7
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def fold8(state: int) -> int:
    state &= 0xFFFFFFFF
    return (state ^ (state >> 8) ^ (state >> 16) ^ (state >> 24)) & 0xFF


def inv_odd_mod2_32(m: int) -> int:
    return pow(m, -1, 1 << 32)


# --------------------------------------------------------- binary extraction

def extract_consts(blob: bytes) -> dict:
    off = blob.find(MAGIC)
    if off < 0:
        raise SystemExit("solver: constant block (DSIGCONSTv1) not found in binary")
    if blob.find(MAGIC, off + 1) >= 0:
        raise SystemExit("solver: ambiguous constant block (marker not unique)")
    if off + CONST_SIZE > len(blob):
        raise SystemExit("solver: truncated constant block")

    (magic, perm, xkey, rots, roll_seed, roll_mul, roll_add,
     *rest) = struct.unpack_from(CONST_FMT, blob, off)
    blk_mul = rest[0:6]
    blk_add = rest[6:12]
    blk_rol = rest[12]
    _reserved = rest[13]
    target = rest[14]
    flag_ct = rest[15]
    flag_len = rest[16]

    if magic != MAGIC:
        raise SystemExit("solver: bad magic")
    return {
        "offset": off,
        "perm": list(perm),
        "xkey": list(xkey),
        "rots": list(rots),
        "roll_seed": roll_seed,
        "roll_mul": roll_mul,
        "roll_add": roll_add,
        "blk_mul": list(blk_mul),
        "blk_add": list(blk_add),
        "blk_rol": list(blk_rol),
        "target": target,
        "flag_ct": flag_ct,
        "flag_len": flag_len,
    }


# -------------------------------------------------------------- inversion

def invert_transform(w: bytes, c: dict) -> bytes:
    """Invert stages D..A, recovering the unique token that yields w."""
    assert len(w) == TOKEN_LEN
    d = list(struct.unpack("<6I", w))

    # Stage D inverse: undo the cross-dword chain (reverse order), then the
    # affine mix (odd multipliers are invertible modulo 2^32).
    for j in range(BLOCKS - 1, 0, -1):
        d[j] ^= rol32(d[j - 1], c["blk_rol"][j])
    for j in range(BLOCKS):
        d[j] = ((d[j] - c["blk_add"][j]) * inv_odd_mod2_32(c["blk_mul"][j])) & 0xFFFFFFFF
    v = list(b"".join(struct.pack("<I", x) for x in d))

    # Stage C inverse: replay the rolling state forward while un-mixing.
    state = c["roll_seed"]
    u = []
    for i in range(TOKEN_LEN):
        ui = v[i] ^ fold8(state)
        u.append(ui)
        state = (state * c["roll_mul"] + c["roll_add"] + ui) & 0xFFFFFFFF

    # Stage B inverse: rotations and index XOR.
    x = [ror8(u[i], c["rots"][i]) ^ c["xkey"][i] for i in range(TOKEN_LEN)]

    # Stage A inverse: undo the permutation.
    tok = [0] * TOKEN_LEN
    for i in range(TOKEN_LEN):
        tok[c["perm"][i]] = x[i]
    return bytes(tok)


def solve(path: str) -> tuple[str, dict]:
    with open(path, "rb") as f:
        blob = f.read()
    c = extract_consts(blob)
    tok = invert_transform(c["target"], c)
    try:
        text = tok.decode("ascii")
    except UnicodeDecodeError:
        raise SystemExit("solver: recovered bytes are not ASCII -- wrong constants?")
    return text, c


def main() -> int:
    ap = argparse.ArgumentParser(description="DEAD SIGNAL token solver")
    ap.add_argument("binary", help="path to the dead_signal ELF")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    token, c = solve(args.binary)
    if not all(ch.isalnum() and ch.isupper() or ch.isdigit() for ch in token):
        print("solver: warning -- recovered token outside [A-Z0-9] domain", file=sys.stderr)

    if args.json:
        print(json.dumps({"token": token, "consts_offset": c["offset"]}))
    else:
        print(f"[+] constant block at offset 0x{c['offset']:x}")
        print(f"[+] recovered token : {token}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
