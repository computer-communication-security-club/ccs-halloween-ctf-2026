"""Shared HYDRA verifier constants and reference implementation.

The service no longer computes an expected tag and compares it to a client
tag.  The firmware is a *verifier*:

    H(N)        = HYDRA-MAC-128(nonce)
    G_N(P)      = 16-step reversible ARX permutation of a 16-byte proof P
    accept      iff G_N(P) == H(N)

The downloadable VM can evaluate G_N(P) and compare it to H(N), but contains
no routine that turns N into a valid P.  A player must recover the VM ISA,
lift the firmware, and invert G_N.

Memory map shared with src/hydra_vm.h:
    0xE000  NONCE_ADDR   16 bytes   input nonce
    0xE010  PROOF_ADDR   16 bytes   candidate proof submitted by the client
    0xE020  H_STATE      16 bytes   MAC working state
    0xE030  RESULT_ADDR   1 byte    1 = proof accepted, 0 = rejected
    0xE040  TARGET_ADDR  16 bytes   H(N)
    0xE050  G_STATE      16 bytes   permutation working state
    0xE060  COUNTER       2 bytes   round loop counter
    0xE070  ROTATION      2 bytes   nonce-selected rotation (7 or 11)
    0xE080  F_SCRATCH     4 bytes   saved x for F()
    0x4000  G_K table    64 bytes   16 x u32 round constants
    0xF000  STACK_TOP               initial stack pointer
    0x0000  ENTRY_ADDR               firmware entry point
"""

MEM_SIZE = 0x10000
NONCE_ADDR = 0xE000
PROOF_ADDR = 0xE010
TAG_ADDR = PROOF_ADDR  # backward-compatible name
H_STATE_ADDR = 0xE020
STATE_ADDR = H_STATE_ADDR
RESULT_ADDR = 0xE030
TARGET_ADDR = 0xE040
G_STATE_ADDR = 0xE050
COUNTER_ADDR = 0xE060
ROTATION_ADDR = 0xE070
F_SCRATCH_ADDR = 0xE080
G_K_ADDR = 0x4000
STACK_TOP = 0xF000
ENTRY_ADDR = 0x0000

# MAC key material.  ASCII: "HYDR" "A-KE" "Y-25" "!-CC" -> "HYDRA-KEY-25!-CC"
K = [0x48594452, 0x412D4B45, 0x592D3235, 0x212D4343]

# MAC round constants: first 16 words of the fractional part of pi.
PI = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
]
RC = [PI[4 * r:4 * r + 4] for r in range(4)]

# MAC per-lane rotation schedule.
ROT = [7, 9, 13, 3]

# Verifier permutation constants (SHA-256-derived, fixed).
G_K = [
    0x15731B40, 0xB0198F8A, 0x4327DB19, 0x4282EAB6,
    0xD7D56217, 0x6B2DE4EE, 0xD60E0E08, 0xF8C70E46,
    0x1325BC04, 0xC3856B78, 0x19FE1D22, 0xA1653C7D,
    0xDBE66148, 0x8026E0B1, 0x5E880956, 0x83B46ED4,
]

MASK32 = 0xFFFFFFFF
MASK16 = 0xFFFF


def rotl32(x: int, n: int) -> int:
    n &= 31
    x &= MASK32
    if n == 0:
        return x
    return ((x << n) | (x >> (32 - n))) & MASK32


def rotl16(x: int, n: int) -> int:
    n &= 15
    x &= MASK16
    if n == 0:
        return x
    return ((x << n) | (x >> (16 - n))) & MASK16


def mixw16(a: int, b: int) -> int:
    """Mirror of the VM's MIXW opcode (modifies the first operand)."""
    t = (a ^ b) & MASK16
    t = (t + rotl16(t, 5)) & MASK16
    return (t ^ rotl16(t, 9)) & MASK16


def mac(nonce: bytes) -> bytes:
    """HYDRA-MAC-128: 16-byte nonce -> 16-byte target H(N)."""
    assert len(nonce) == 16
    w = [int.from_bytes(nonce[4 * i:4 * i + 4], "little") for i in range(4)]
    for r in range(4):
        for j in range(4):
            x = (w[j] + w[(j + 1) % 4]) & MASK32
            x ^= K[(j + r) % 4]
            x ^= RC[r][j]
            x = rotl32(x, ROT[j])
            t = x
            t = (t ^ rotl32(t, 11)) & MASK32
            t = (t + rotl32(t, 7)) & MASK32
            w[j] = t
    return b"".join(v.to_bytes(4, "little") for v in w)


def _proof_words(nonce: bytes):
    assert len(nonce) == 16
    return [int.from_bytes(nonce[4 * i:4 * i + 4], "little") for i in range(4)]


def rotation_for(nonce: bytes) -> int:
    return 7 if (nonce[0] & 1) == 0 else 11


def f32(x: int, key: int, n: int) -> int:
    """Nonlinear step function used by the verifier permutation."""
    y = rotl32((x ^ key) & MASK32, n)
    lo = y & MASK16
    hi = (y >> 16) & MASK16
    lo = mixw16(lo, hi)
    y = ((hi << 16) | lo) & MASK32
    return (y + x) & MASK32


def _key(words, nonce_words, r: int, i: int) -> int:
    return (G_K[4 * r + i] ^ nonce_words[(i + 1) & 3]) & MASK32


def g_forward(words, nonce: bytes):
    w = list(words)
    nw = _proof_words(nonce)
    n = rotation_for(nonce)
    for r in range(4):
        for i in range(4):
            j = (i + 1) & 3
            w[i] = (w[i] + f32(w[j], _key(w, nw, r, i), n)) & MASK32
    return w


def g_inverse(words, nonce: bytes):
    w = list(words)
    nw = _proof_words(nonce)
    n = rotation_for(nonce)
    for r in range(3, -1, -1):
        for i in range(3, -1, -1):
            j = (i + 1) & 3
            w[i] = (w[i] - f32(w[j], _key(w, nw, r, i), n)) & MASK32
    return w


def proof(nonce: bytes) -> bytes:
    """Construct the unique valid proof P for a nonce (organizer solver)."""
    target = _proof_words(mac(nonce))
    return b"".join(v.to_bytes(4, "little") for v in g_inverse(target, nonce))


def verify(nonce: bytes, candidate: bytes) -> bool:
    assert len(nonce) == 16 and len(candidate) == 16
    target = _proof_words(mac(nonce))
    got = _proof_words(candidate)
    return g_forward(got, nonce) == target
