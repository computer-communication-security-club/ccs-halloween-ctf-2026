#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""HYDRA VM solver.

Reads only the committed player handout (`dist/firmware.enc`), recovers the
verifier permutation from the encrypted firmware, inverts it, and submits one
proof to the service. It never reads the private flag.txt.

Usage:
    uv run solve/solve.py HOST PORT [--timeout SECONDS]

Exit codes: 0 = flag recovered, 1 = failure, 2 = bad usage.
"""

from __future__ import annotations

import socket
import struct
import sys
import zlib
from pathlib import Path

M32 = 0xFFFFFFFF
M16 = 0xFFFF
M64 = 0xFFFFFFFFFFFFFFFF
FW_PASSPHRASE = b"HYDRA-FIRMWARE-KEY-v1"

# HYDRA-MAC key and round constants recovered from the firmware disassembly.
K = [0x48594452, 0x412D4B45, 0x592D3235, 0x212D4343]
PI = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
]
RC = [PI[4 * r:4 * r + 4] for r in range(4)]
ROT = [7, 9, 13, 3]
G_K_ADDR = 0x4000


def rotl32(x: int, n: int) -> int:
    n &= 31
    x &= M32
    return x if n == 0 else ((x << n) | (x >> (32 - n))) & M32


def rotl16(x: int, n: int) -> int:
    n &= 15
    x &= M16
    return x if n == 0 else ((x << n) | (x >> (16 - n))) & M16


def mixw16(a: int, b: int) -> int:
    t = (a ^ b) & M16
    t = (t + rotl16(t, 5)) & M16
    return (t ^ rotl16(t, 9)) & M16


def mac(nonce: bytes) -> bytes:
    w = [int.from_bytes(nonce[4 * i:4 * i + 4], "little") for i in range(4)]
    for r in range(4):
        for j in range(4):
            x = (w[j] + w[(j + 1) % 4]) & M32
            x ^= K[(j + r) % 4]
            x ^= RC[r][j]
            x = rotl32(x, ROT[j])
            t = x
            t = (t ^ rotl32(t, 11)) & M32
            t = (t + rotl32(t, 7)) & M32
            w[j] = t
    return b"".join(v.to_bytes(4, "little") for v in w)


def _kdf() -> bytes:
    out = bytearray(32)
    n = len(FW_PASSPHRASE)
    for i in range(32):
        t = FW_PASSPHRASE[i % n] ^ ((i * 37 + 11) & 0xFF)
        out[i] = ((t << 3) | (t >> 5)) & 0xFF
    for i in range(1, 32):
        out[i] = (out[i] ^ ((out[i - 1] + i * 7 + 3) & 0xFF)) & 0xFF
    return bytes(out)


def _keystream(key: bytes, length: int) -> bytes:
    s0 = int.from_bytes(key[0:8], "little")
    s1 = int.from_bytes(key[8:16], "little") ^ 0x9E3779B97F4A7C15
    s2 = int.from_bytes(key[16:24], "little")
    s3 = int.from_bytes(key[24:32], "little") ^ 0xD1B54A32D192ED03
    out = bytearray()
    while len(out) < length:
        s2 = (s2 + 0x9E3779B97F4A7C15) & M64
        z = s2
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        z = (z ^ (z >> 31)) & M64
        x = s0
        y = s1
        s0 = y
        x = (x ^ ((x << 23) & M64)) & M64
        x = (x ^ (x >> 17)) & M64
        x = (x ^ y ^ (y >> 26)) & M64
        s1 = x
        s3 = (s3 * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & M64
        out += ((s0 + s1 + z + s3) & M64).to_bytes(8, "little")
    return bytes(out[:length])


def load_firmware() -> bytes:
    blob = (Path(__file__).resolve().parent.parent / "dist" / "firmware.enc").read_bytes()
    if len(blob) < 12 or blob[:4] != b"HYFW":
        raise RuntimeError("bad firmware container")
    (plain_len,) = struct.unpack_from("<I", blob, 4)
    if len(blob) != 8 + plain_len + 4:
        raise RuntimeError("bad firmware length")
    plain = bytes(a ^ b for a, b in zip(blob[8:8 + plain_len], _keystream(_kdf(), plain_len)))
    (crc,) = struct.unpack_from("<I", blob, 8 + plain_len)
    if zlib.crc32(plain) & M32 != crc:
        raise RuntimeError("firmware CRC mismatch")
    return plain


def rotation_for(nonce: bytes) -> int:
    return 7 if (nonce[0] & 1) == 0 else 11


def f32(x: int, key: int, n: int) -> int:
    y = rotl32((x ^ key) & M32, n)
    lo = mixw16(y & M16, (y >> 16) & M16)
    y = ((y >> 16) << 16) | lo
    return (y + x) & M32


def inverse(words, nonce: bytes, gk) -> list[int]:
    w = list(words)
    nw = [int.from_bytes(nonce[4 * i:4 * i + 4], "little") for i in range(4)]
    n = rotation_for(nonce)
    for r in range(3, -1, -1):
        for i in range(3, -1, -1):
            j = (i + 1) & 3
            key = (gk[4 * r + i] ^ nw[j]) & M32
            w[i] = (w[i] - f32(w[j], key, n)) & M32
    return w


def proof_for(nonce: bytes, gk) -> bytes:
    target = [int.from_bytes(mac(nonce)[4 * i:4 * i + 4], "little") for i in range(4)]
    return b"".join(v.to_bytes(4, "little") for v in inverse(target, nonce, gk))


def solve(host: str, port: int, timeout: float) -> str:
    firmware = load_firmware()
    gk = list(struct.unpack_from("<16I", firmware, G_K_ADDR))
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        f = s.makefile("rwb")
        banner = f.readline().decode("ascii", "replace").strip()
        nonce_line = f.readline().decode("ascii", "replace").strip()
        if not banner.startswith("HYDRA-SVC/") or not nonce_line.startswith("NONCE "):
            raise RuntimeError("unexpected service banner")
        nonce = bytes.fromhex(nonce_line.split(" ", 1)[1])
        if len(nonce) != 16:
            raise RuntimeError("bad nonce length")
        f.write(b"AUTH " + proof_for(nonce, gk).hex().encode("ascii") + b"\n")
        f.flush()
        if f.readline().strip() != b"AUTH-OK":
            raise RuntimeError("authentication failed")
        flag_line = f.readline().decode("ascii", "replace").strip()
        if not flag_line.startswith("FLAG ccsCTF{"):
            raise RuntimeError("unexpected flag line")
        return flag_line.split(" ", 1)[1]


def main() -> int:
    args = sys.argv[1:]
    timeout = 30.0
    if "--timeout" in args:
        idx = args.index("--timeout")
        try:
            timeout = float(args[idx + 1])
            del args[idx:idx + 2]
        except (IndexError, ValueError):
            print("solver error: bad --timeout", file=sys.stderr)
            return 2
    if len(args) != 2:
        print("usage: solve.py HOST PORT [--timeout SECONDS]", file=sys.stderr)
        return 2
    try:
        flag = solve(args[0], int(args[1]), timeout)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"solver error: {exc}", file=sys.stderr)
        return 1
    print(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
