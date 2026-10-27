#!/usr/bin/env python3
"""
DEAD SIGNAL — constant/target generator.

Implements the FORWARD authentication transform and the ARX key-derivation
function used by the challenge binary, then emits src/generated_constants.h
for compilation.

Forward pipeline over the 24-byte token b[0..23]:

  Stage A  (permutation)      c[i]     = b[PERM[i]]
  Stage B  (index XOR/ROL)    u[i]     = ROL8(c[i] ^ XKEY[i], ROTS[i])
  Stage C  (rolling state)    m8       = fold8(state)
                              v[i]     = u[i] ^ m8
                              state    = state * ROLL_MUL + ROLL_ADD + u[i]
  Stage D  (32-bit ARX)       d[j]     = LE32(v[4j .. 4j+3])
                              d[j]    *= BLK_MUL[j]          (odd multiplier)
                              d[j]    += BLK_ADD[j]
                              for j = 1..5:
                                  d[j] ^= ROL32(d[j-1], BLK_ROL[j])   (cross-dword chain)
  Stage E  (compare)          w        = LE32 concat of d[0..5], compared to TARGET[24]

Every stage is a bijection on 24-byte strings, so the whole transform is
invertible and the correct token is unique for a given TARGET.

Flag protection:  key = ARX_HASH(token)              (32 bytes)
                  ks_j = ARX_HASH(key || LE32(j))   (32-byte blocks)
                  flag_ct[i] = flag[i] ^ ks[i]

The binary derives the key from the SUPPLIED token at decrypt time, so a
patched acceptance branch with a wrong token prints only noise.

Usage:
  gen_constants.py --out src/generated_constants.h [--token TOK] [--flag FLAG] [--seed N]
"""

from __future__ import annotations

import argparse
import os
import random
import struct
import sys

TOKEN_LEN = 24
TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
FLAG_MAX = 128
BLOCKS = 6

MAGIC = b"DSIGCONSTv1\x00\x00\x00\x00\x00"  # 16 bytes
assert len(MAGIC) == 16

# ELF-embedded struct layout (must match src/dead_signal.c exactly):
#   <16s magic> <24s perm> <24s xkey> <24s rots> <III roll_seed,roll_mul,roll_add>
#   <6I blk_mul> <6I blk_add> <6s blk_rol> <2s reserved> <24s target>
#   <128s flag_ct> <I flag_len>
CONST_STRUCT_FMT = "<16s24s24s24sIII6I6I6s2s24s128sI"
CONST_STRUCT_SIZE = struct.calcsize(CONST_STRUCT_FMT)
assert CONST_STRUCT_SIZE == 312, CONST_STRUCT_SIZE


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def rol8(x: int, n: int) -> int:
    n &= 7
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF


def ror8(x: int, n: int) -> int:
    n &= 7
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def rol32(x: int, n: int) -> int:
    n &= 31
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def fold8(state: int) -> int:
    """Fold a 32-bit rolling state down to one byte."""
    state &= 0xFFFFFFFF
    return (state ^ (state >> 8) ^ (state >> 16) ^ (state >> 24)) & 0xFF


def inv_odd_mod2_32(m: int) -> int:
    """Modular inverse of an odd multiplier modulo 2^32."""
    return pow(m, -1, 1 << 32)


def arx_hash(data: bytes, out_len: int = 32) -> bytes:
    """
    ARX_HASH: Davies-Meyer-style 256-bit ARX sponge mixing.
    Deterministic; identical implementation in C and in solver.py.
    """
    assert out_len == 32
    h = [(0x9E3779B9 * (j + 1)) ^ 0xC2B2AE35 for j in range(8)]
    for i, byte in enumerate(data):
        a = i & 7
        b = (i + 3) & 7
        c = (i + 5) & 7
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


def derive_key(token: bytes) -> bytes:
    return arx_hash(token, 32)


def keystream(key: bytes, length: int) -> bytes:
    out = b""
    j = 0
    while len(out) < length:
        out += arx_hash(key + struct.pack("<I", j), 32)
        j += 1
    return out[:length]


def encrypt_flag(flag: bytes, token: bytes) -> bytes:
    key = derive_key(token)
    ks = keystream(key, len(flag))
    return bytes(f ^ k for f, k in zip(flag, ks))


# --------------------------------------------------------------------------
# forward validation transform
# --------------------------------------------------------------------------

def validate_forward(token: bytes, consts: dict) -> bytes:
    """Compute the 24-byte final state w for a token (Stage A..D)."""
    assert len(token) == TOKEN_LEN
    perm, xkey, rots = consts["perm"], consts["xkey"], consts["rots"]

    # Stage A: permutation
    c = [token[perm[i]] for i in range(TOKEN_LEN)]
    # Stage B: index-dependent XOR + rotation
    u = [rol8(c[i] ^ xkey[i], rots[i]) for i in range(TOKEN_LEN)]
    # Stage C: rolling state
    state = consts["roll_seed"]
    v = []
    for i in range(TOKEN_LEN):
        v.append(u[i] ^ fold8(state))
        state = (state * consts["roll_mul"] + consts["roll_add"] + u[i]) & 0xFFFFFFFF
    # Stage D: 32-bit ARX blocks with cross-dword chain
    d = []
    for j in range(BLOCKS):
        x = struct.unpack_from("<I", bytes(v[4 * j : 4 * j + 4]))[0]
        x = (x * consts["blk_mul"][j] + consts["blk_add"][j]) & 0xFFFFFFFF
        d.append(x)
    for j in range(1, BLOCKS):
        d[j] ^= rol32(d[j - 1], consts["blk_rol"][j])
    return b"".join(struct.pack("<I", x) for x in d)


def validate_inverse(w: bytes, consts: dict) -> bytes:
    """Reconstruct the unique token producing final state w. (Solver logic.)"""
    assert len(w) == TOKEN_LEN
    d = list(struct.unpack("<6I", w))

    # undo cross-dword chain, reverse order
    for j in range(BLOCKS - 1, 0, -1):
        d[j] ^= rol32(d[j - 1], consts["blk_rol"][j])
    # undo per-dword affine mix
    for j in range(BLOCKS):
        d[j] = ((d[j] - consts["blk_add"][j]) * inv_odd_mod2_32(consts["blk_mul"][j])) & 0xFFFFFFFF
    v = list(b"".join(struct.pack("<I", x) for x in d))

    # undo rolling state (replay forward while un-xoring)
    state = consts["roll_seed"]
    u = []
    for i in range(TOKEN_LEN):
        ui = v[i] ^ fold8(state)
        u.append(ui)
        state = (state * consts["roll_mul"] + consts["roll_add"] + ui) & 0xFFFFFFFF

    # undo index mix and permutation
    c = [ror8(u[i], consts["rots"][i]) ^ consts["xkey"][i] for i in range(TOKEN_LEN)]
    b = [0] * TOKEN_LEN
    for i in range(TOKEN_LEN):
        b[consts["perm"][i]] = c[i]
    return bytes(b)


# --------------------------------------------------------------------------
# constant generation
# --------------------------------------------------------------------------

def random_token(rng: random.Random) -> bytes:
    return "".join(rng.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LEN)).encode()


def generate_consts(token: bytes, flag: bytes, rng: random.Random) -> dict:
    if len(token) != TOKEN_LEN:
        raise ValueError(f"token must be exactly {TOKEN_LEN} bytes")
    if any(chr(x) not in TOKEN_ALPHABET for x in token):
        raise ValueError("token must match [A-Z0-9]{24}")
    if not flag.startswith(b"ccsCTF{") or not flag.endswith(b"}"):
        raise ValueError("flag must look like ccsCTF{...}")
    if len(flag) > FLAG_MAX:
        raise ValueError(f"flag longer than {FLAG_MAX} bytes")

    perm = list(range(TOKEN_LEN))
    rng.shuffle(perm)
    consts = {
        "perm": perm,
        "xkey": [rng.randrange(256) for _ in range(TOKEN_LEN)],
        "rots": [rng.randrange(1, 8) for _ in range(TOKEN_LEN)],
        "roll_seed": rng.randrange(1 << 32),
        "roll_mul": rng.randrange(1 << 31) | 1,  # odd -> invertible
        "roll_add": rng.randrange(1 << 32),
        "blk_mul": [rng.randrange(1 << 31) | 1 for _ in range(BLOCKS)],
        "blk_add": [rng.randrange(1 << 32) for _ in range(BLOCKS)],
        "blk_rol": [rng.randrange(1, 32) for _ in range(BLOCKS)],
    }
    consts["target"] = validate_forward(token, consts)
    consts["flag"] = flag
    consts["flag_ct"] = encrypt_flag(flag, token)
    consts["token"] = token
    return consts


def pack_consts(consts: dict) -> bytes:
    return struct.pack(
        CONST_STRUCT_FMT,
        MAGIC,
        bytes(consts["perm"]),
        bytes(consts["xkey"]),
        bytes(consts["rots"]),
        consts["roll_seed"],
        consts["roll_mul"],
        consts["roll_add"],
        *consts["blk_mul"],
        *consts["blk_add"],
        bytes(consts["blk_rol"]),
        b"\x00\x00",
        consts["target"],
        consts["flag_ct"].ljust(FLAG_MAX, b"\x00"),
        len(consts["flag"]),
    )


def fmt_u8_list(data) -> str:
    return ", ".join(f"0x{x:02X}" for x in data)


def fmt_u32_list(vals) -> str:
    return ", ".join(f"0x{x:08X}u" for x in vals)


def emit_header(consts: dict) -> str:
    """Emit generated_constants.h defining the single contiguous G_CONST object."""
    out = []
    out.append("/* generated by organizer/gen_constants.py -- DO NOT EDIT */\n")
    out.append("#ifndef GENERATED_CONSTANTS_H\n#define GENERATED_CONSTANTS_H\n\n")
    out.append("static const dsig_consts_t G_CONST = {\n")
    out.append('    .magic     = "DSIGCONSTv1",\n')
    out.append(f"    .perm      = {{ {fmt_u8_list(consts['perm'])} }},\n")
    out.append(f"    .xkey      = {{ {fmt_u8_list(consts['xkey'])} }},\n")
    out.append(f"    .rots      = {{ {fmt_u8_list(consts['rots'])} }},\n")
    out.append(f"    .roll_seed = 0x{consts['roll_seed']:08X}u,\n")
    out.append(f"    .roll_mul  = 0x{consts['roll_mul']:08X}u,\n")
    out.append(f"    .roll_add  = 0x{consts['roll_add']:08X}u,\n")
    out.append(f"    .blk_mul   = {{ {fmt_u32_list(consts['blk_mul'])} }},\n")
    out.append(f"    .blk_add   = {{ {fmt_u32_list(consts['blk_add'])} }},\n")
    out.append(f"    .blk_rol   = {{ {fmt_u8_list(consts['blk_rol'])} }},\n")
    out.append("    .reserved  = { 0x00, 0x00 },\n")
    out.append(f"    .target    = {{ {fmt_u8_list(consts['target'])} }},\n")
    out.append(f"    .flag_ct   = {{ {fmt_u8_list(consts['flag_ct'].ljust(FLAG_MAX, b'\x00'))} }},\n")
    out.append(f"    .flag_len  = {len(consts['flag'])}u,\n")
    out.append("};\n\n")
    out.append("#endif /* GENERATED_CONSTANTS_H */\n")
    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="DEAD SIGNAL constant generator")
    ap.add_argument("--out", required=True, help="path of generated_constants.h")
    ap.add_argument("--token", help="24-char [A-Z0-9] token (default: random)")
    ap.add_argument("--flag", help="flag string (default: random unique suffix)")
    ap.add_argument("--flag-file", help="file containing the flag string")
    ap.add_argument("--token-out", help="write the generated token here")
    ap.add_argument("--flag-out", help="write the flag in effect here (flag config persistence)")
    ap.add_argument("--seed", type=int, help="RNG seed (reproducible builds)")
    args = ap.parse_args()

    rng = random.Random(args.seed) if args.seed is not None else random.SystemRandom()

    token = args.token.encode() if args.token else random_token(rng)
    if args.flag_file:
        flag = open(args.flag_file, "rb").read().strip()
    elif args.flag:
        flag = args.flag.encode()
    else:
        suffix = "".join(rng.choice("0123456789abcdef") for _ in range(12))
        flag = f"ccsCTF{{dead_signal_{suffix}}}".encode()

    consts = generate_consts(token, flag, rng)

    # self-check: inverse reproduces the token
    assert validate_inverse(consts["target"], consts) == token, "inverse transform mismatch"

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(emit_header(consts))

    if args.token_out:
        with open(args.token_out, "w") as f:
            f.write(token.decode() + "\n")
    if args.flag_out:
        with open(args.flag_out, "w") as f:
            f.write(flag.decode() + "\n")

    print(f"[gen] token    : {token.decode()}")
    print(f"[gen] flag     : {flag.decode()}")
    print(f"[gen] target   : {consts['target'].hex()}")
    print(f"[gen] header   : {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
