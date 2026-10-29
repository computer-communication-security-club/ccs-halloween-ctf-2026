"""HYDRA firmware protection: custom key derivation + stream cipher.

Mirrors src/fw_crypto.c exactly.  All integer math is 8/32/64-bit unsigned
with explicit wraparound so the C and Python versions agree byte for byte.

Firmware file format (little-endian):
    magic   4 bytes   b"HYFW"
    length  u32       plaintext length in bytes
    body    length    ciphertext = plaintext XOR keystream(key, length)
    crc     u32       CRC-32 (IEEE, reflected) of the plaintext
"""

import struct
import zlib

FW_MAGIC = b"HYFW"
FW_PASSPHRASE = b"HYDRA-FIRMWARE-KEY-v1"

M64 = 0xFFFFFFFFFFFFFFFF


def kdf(passphrase: bytes = FW_PASSPHRASE) -> bytes:
    """Expand a passphrase into a 32-byte key (custom 8-bit mix)."""
    out = bytearray(32)
    plen = len(passphrase)
    for i in range(32):
        t = passphrase[i % plen] ^ ((i * 37 + 11) & 0xFF)
        t = ((t << 3) | (t >> 5)) & 0xFF
        out[i] = t
    for i in range(1, 32):
        out[i] = (out[i] ^ ((out[i - 1] + i * 7 + 3) & 0xFF)) & 0xFF
    return bytes(out)


def keystream(key: bytes, n: int) -> bytes:
    """Generate n keystream bytes (splitmix64-xorshift128+ hybrid)."""
    assert len(key) == 32
    s0 = int.from_bytes(key[0:8], "little")
    s1 = int.from_bytes(key[8:16], "little") ^ 0x9E3779B97F4A7C15
    s2 = int.from_bytes(key[16:24], "little")
    s3 = int.from_bytes(key[24:32], "little") ^ 0xD1B54A32D192ED03
    out = bytearray()
    while len(out) < n:
        # splitmix64 step
        s2 = (s2 + 0x9E3779B97F4A7C15) & M64
        z = s2
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        z = (z ^ (z >> 31)) & M64
        # xorshift128+ step
        x = s0
        y = s1
        s0 = y
        x = (x ^ ((x << 23) & M64)) & M64
        x = (x ^ (x >> 17)) & M64
        x = (x ^ y ^ (y >> 26)) & M64
        s1 = x
        s3 = (s3 * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & M64
        w = (s0 + s1 + z + s3) & M64
        out += w.to_bytes(8, "little")
    return bytes(out[:n])


def xor_keystream(key: bytes, data: bytes) -> bytes:
    ks = keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def pack_firmware(plain: bytes, key: bytes = None) -> bytes:
    key = key or kdf()
    ct = xor_keystream(key, plain)
    return FW_MAGIC + struct.pack("<I", len(plain)) + ct + struct.pack("<I", crc32(plain))


def unpack_firmware(blob: bytes, key: bytes = None) -> bytes:
    key = key or kdf()
    if len(blob) < 12 or blob[:4] != FW_MAGIC:
        raise ValueError("bad firmware magic")
    (plain_len,) = struct.unpack("<I", blob[4:8])
    if len(blob) != 8 + plain_len + 4:
        raise ValueError("bad firmware length")
    plain = xor_keystream(key, blob[8:8 + plain_len])
    (crc,) = struct.unpack("<I", blob[8 + plain_len:])
    if crc32(plain) != crc:
        raise ValueError("firmware CRC mismatch (bad key?)")
    return plain
