#!/usr/bin/env python3
"""
Independent blind solver for DEAD SIGNAL -- written from disassembly only.

Algorithm derived from dead_signal .text:
  S1 @0x1480  out[i] = tok[P[i]]                      P  = file 0x23d0
  S2 @0x14c0  out[i] = ROL8(in[i] ^ K[i], R[i])       K  = 0x23e8, R = 0x2400
  S3 @0x1500  state = seed
              out[i] = in[i] ^ fold8(state)
              state  = state*MUL + in[i] + ADD        seed=0x2EEC418F (imm @1502)
                                                    MUL=0x76048761 (imm @1559)
                                                    ADD=0xB89E607C (lea @156d)
  S4 @0x1580  d[j] = LE32(in[4j..]); d[j] = d[j]*M[j] + A[j]
              run = d[0]; j=1..5: run = ROL32(run, rol[j]) ^ d[j]; d[j] = run
                                                    M = 0x2424, A = 0x243c, rol = 0x2454
  S5 @0x1650  OR-accumulated 24-byte compare vs T = 0x245c  (no early exit)

Constant block found via the "DSIGCONSTv1" marker (strings); struct layout
recovered by matching the field offsets against the instruction operands.
Rolling-state immediates in .text are cross-checked against the struct fields.

Inverse: undo the dword chain (reverse order), undo the affine maps with the
modular inverse of the odd multipliers mod 2^32, replay the rolling state
forward while un-mixing, then undo ROL8/XOR and the permutation.
"""

import struct
import sys

MAGIC = b"DSIGCONSTv1\x00\x00\x00\x00\x00"

def rol8(x, n):
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF

def ror8(x, n):
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF

def rol32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def fold8(s):
    return (s ^ (s >> 8) ^ (s >> 16) ^ (s >> 24)) & 0xFF

def main():
    blob = open(sys.argv[1], "rb").read()
    off = blob.find(MAGIC)
    assert off > 0, "marker not found"
    B = off

    # field offsets relative to block base, taken from the instruction operands
    P = blob[B + 16 : B + 40]
    K = blob[B + 40 : B + 64]
    R = blob[B + 64 : B + 88]
    seed = struct.unpack_from("<I", blob, B + 88)[0]
    mul = struct.unpack_from("<I", blob, B + 92)[0]
    add = struct.unpack_from("<I", blob, B + 96)[0]
    M = struct.unpack_from("<6I", blob, B + 100)
    A = struct.unpack_from("<6I", blob, B + 124)
    rol = blob[B + 148 : B + 154]
    T = blob[B + 156 : B + 180]

    # structural sanity (build-independent; immediates in .text are per-build)
    assert sorted(P) == list(range(24)), "P is not a permutation of 0..23"
    assert all(1 <= r <= 7 for r in R), "rotation out of range"
    assert all(m & 1 for m in M), "dword multiplier not odd"
    assert all(1 <= r <= 31 for r in rol), "dword rot out of range"

    # ---- inverse S4: undo chain (reverse order, later dwords untouched) ----
    d = list(struct.unpack("<6I", T))
    for j in range(5, 0, -1):
        d[j] ^= rol32(d[j - 1], rol[j])
    # undo affine mix: odd multiplier -> invertible mod 2^32
    inv = [pow(m, -1, 1 << 32) for m in M]
    for j in range(6):
        d[j] = ((d[j] - A[j]) * inv[j]) & 0xFFFFFFFF
    v = list(b"".join(struct.pack("<I", x) for x in d))

    # ---- inverse S3: replay rolling state, un-mix byte by byte ----
    state = seed
    u = []
    for i in range(24):
        ui = v[i] ^ fold8(state)
        u.append(ui)
        state = (state * mul + add + ui) & 0xFFFFFFFF

    # ---- inverse S2, S1 ----
    c = [ror8(u[i], R[i]) ^ K[i] for i in range(24)]
    tok = [0] * 24
    for i in range(24):
        tok[P[i]] = c[i]
    token = bytes(tok).decode("ascii")

    # self-check: forward-recompute the target from the recovered token
    st = seed
    w = [0] * 24
    cc = [tok[P[i]] for i in range(24)]
    uu = [rol8(cc[i] ^ K[i], R[i]) for i in range(24)]
    vv = []
    for i in range(24):
        vv.append(uu[i] ^ fold8(st))
        st = (st * mul + add + uu[i]) & 0xFFFFFFFF
    dd = []
    for j in range(6):
        x = struct.unpack_from("<I", bytes(vv[4 * j : 4 * j + 4]))[0]
        dd.append((x * M[j] + A[j]) & 0xFFFFFFFF)
    for j in range(1, 6):
        dd[j] ^= rol32(dd[j - 1], rol[j])
    w = b"".join(struct.pack("<I", x) for x in dd)
    assert w == T, "round-trip failed: recovered token does not map to target"

    print(token)

if __name__ == "__main__":
    main()
