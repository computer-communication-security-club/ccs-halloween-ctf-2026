"""HYDRA verifier firmware.

The firmware no longer emits a tag for a nonce.  It implements:

    target = HYDRA-MAC-128(nonce)                 (unrolled ARX, as before)
    state  = proof supplied by the client
    for r in 0..3:                               (outer loop, JNZ)
        for i in 0..3:                           (unrolled lanes)
            state[i] += F(state[i+1], K[r][i] ^ nonce[i+1])
    accept iff state == target

F is nonlinear and uses the VM's MIXW instruction.  The 16-step update is a
composition of bijections, so exactly one proof exists per nonce; the VM only
verifies a supplied proof and never constructs one.

Memory map lives in tools/hydra_common.py and src/hydra_vm.h.
"""

from asm import Asm, R0, R1, R2, R3, R4, R5, R6, R7
from hydra_common import (
    COUNTER_ADDR, F_SCRATCH_ADDR, G_K, G_K_ADDR, G_STATE_ADDR,
    H_STATE_ADDR, K, NONCE_ADDR, PROOF_ADDR, RC, RESULT_ADDR, ROT,
    ROTATION_ADDR, TARGET_ADDR,
)

SRC_BASE = 0x0000


def _load32(a: Asm, base: int, idx: int):
    """R0(lo), R1(hi) <- memory[base + 4*idx]."""
    a.movi(R6, base + 4 * idx)
    a.ldw(R0, R6)
    a.addi(R6, 2)
    a.ldw(R1, R6)


def _load32_alt(a: Asm, base: int, idx: int):
    """R2(lo), R3(hi) <- memory[base + 4*idx]."""
    a.movi(R6, base + 4 * idx)
    a.ldw(R2, R6)
    a.addi(R6, 2)
    a.ldw(R3, R6)


def _store32(a: Asm, base: int, idx: int):
    """memory[base + 4*idx] <- R0(lo), R1(hi)."""
    a.movi(R6, base + 4 * idx)
    a.stw(R0, R6)
    a.addi(R6, 2)
    a.stw(R1, R6)


def _rotl32_inplace(a: Asm, n: int):
    """R0,R1 = ROTL32(R0,R1, n)."""
    assert 1 <= n <= 15
    a.mov(R2, R0)
    a.mov(R3, R1)
    a.movi(R4, n)
    a.movi(R5, 16 - n)
    a.shl(R2, R4)
    a.shr(R3, R5)
    a.or_(R2, R3)
    a.mov(R6, R1)
    a.shl(R6, R4)
    a.mov(R7, R0)
    a.shr(R7, R5)
    a.or_(R6, R7)
    a.mov(R0, R2)
    a.mov(R1, R6)


def _rotl32_copy(a: Asm, n: int):
    """R2,R3 = ROTL32(R0,R1, n); R0,R1 preserved."""
    assert 1 <= n <= 15
    a.movi(R4, n)
    a.movi(R5, 16 - n)
    a.mov(R2, R0)
    a.shl(R2, R4)
    a.mov(R6, R1)
    a.shr(R6, R5)
    a.or_(R2, R6)
    a.mov(R3, R1)
    a.shl(R3, R4)
    a.mov(R6, R0)
    a.shr(R6, R5)
    a.or_(R3, R6)


def _lane_step(a: Asm, r: int, j: int):
    """Unrolled MAC lane step: w[j] = mix(w[j] + w[j+1] ^ K ^ RC)."""
    _load32(a, H_STATE_ADDR, j)
    _load32_alt(a, H_STATE_ADDR, (j + 1) % 4)
    a.add(R0, R2)
    a.adc(R1, R3)
    c32 = K[(j + r) % 4] ^ RC[r][j]
    a.xori(R0, c32 & 0xFFFF)
    a.xori(R1, (c32 >> 16) & 0xFFFF)
    _rotl32_inplace(a, ROT[j])
    _rotl32_copy(a, 11)
    a.xor(R0, R2)
    a.xor(R1, R3)
    _rotl32_copy(a, 7)
    a.add(R0, R2)
    a.adc(R1, R3)
    _store32(a, H_STATE_ADDR, j)


def _copy16(a: Asm, src: int, dst: int):
    for k in range(8):
        a.movi(R6, src + 2 * k)
        a.ldw(R0, R6)
        a.movi(R6, dst + 2 * k)
        a.stw(R0, R6)


def _verifier_step(a: Asm, i: int):
    """One reversible permutation step on G_STATE[i].

    state[i] += F(state[i+1], G_K[r][i] ^ nonce[i+1])

    r is implicit in the G_K pointer held in R7.
    """
    j = (i + 1) & 3

    # key = G_K[r][i] ^ nonce[j]
    a.mov(R6, R7)
    if i:
        a.addi(R6, 4 * i)
    a.ldw(R2, R6)
    a.addi(R6, 2)
    a.ldw(R3, R6)
    a.movi(R6, NONCE_ADDR + 4 * j)
    a.ldw(R0, R6)
    a.xor(R2, R0)
    a.addi(R6, 2)
    a.ldw(R0, R6)
    a.xor(R3, R0)

    # x = state[j]; save x for F's final addition
    _load32(a, G_STATE_ADDR, j)
    a.movi(R6, F_SCRATCH_ADDR)
    a.stw(R0, R6)
    a.addi(R6, 2)
    a.stw(R1, R6)

    # y = ROTL32(x ^ key, rotation)
    a.xor(R0, R2)
    a.xor(R1, R3)
    a.movi(R6, ROTATION_ADDR)
    a.ldw(R2, R6)
    a.movi(R3, 16)
    a.sub(R3, R2)
    a.mov(R4, R0)
    a.mov(R5, R1)
    a.shl(R0, R2)
    a.shr(R5, R3)
    a.or_(R0, R5)
    a.shl(R1, R2)
    a.shr(R4, R3)
    a.or_(R1, R4)

    # absorb the high half into the low half using the custom MIXW opcode
    a.mixw(R0, R1)

    # F = (mixed y) + x; park F so the state load cannot clobber it
    a.movi(R6, F_SCRATCH_ADDR)
    a.ldw(R4, R6)
    a.addi(R6, 2)
    a.ldw(R5, R6)
    a.add(R0, R4)
    a.adc(R1, R5)
    a.movi(R6, F_SCRATCH_ADDR)
    a.stw(R0, R6)
    a.addi(R6, 2)
    a.stw(R1, R6)

    # state[i] += F
    _load32(a, G_STATE_ADDR, i)
    a.movi(R6, F_SCRATCH_ADDR)
    a.ldw(R4, R6)
    a.addi(R6, 2)
    a.ldw(R5, R6)
    a.add(R0, R4)
    a.adc(R1, R5)
    _store32(a, G_STATE_ADDR, i)


def build() -> bytes:
    a = Asm(SRC_BASE)

    # ---- target = H(nonce) -------------------------------------------------
    _copy16(a, NONCE_ADDR, H_STATE_ADDR)
    for r in range(4):
        for j in range(4):
            _lane_step(a, r, j)
    _copy16(a, H_STATE_ADDR, TARGET_ADDR)

    # ---- verifier state = candidate proof ----------------------------------
    _copy16(a, PROOF_ADDR, G_STATE_ADDR)

    # rotation = 7 if nonce[0] is even else 11 (nonce-dependent control flow)
    a.movi(R6, NONCE_ADDR)
    a.ldb(R0, R6)
    a.movi(R1, 1)
    a.and_(R0, R1)
    a.jz("rot7")
    a.movi(R0, 11)
    a.jmp("rot_done")
    a.label("rot7")
    a.movi(R0, 7)
    a.label("rot_done")
    a.movi(R6, ROTATION_ADDR)
    a.stw(R0, R6)

    # round counter and constant-table pointer
    a.movi(R0, 4)
    a.movi(R6, COUNTER_ADDR)
    a.stw(R0, R6)
    a.movi(R7, G_K_ADDR)

    # ---- four rounds, four unrolled lane steps per round -------------------
    a.label("round_loop")
    for i in range(4):
        _verifier_step(a, i)
    a.addi(R7, 16)
    a.movi(R6, COUNTER_ADDR)
    a.ldw(R0, R6)
    a.addi(R0, 0xFFFF)
    a.stw(R0, R6)
    a.jnz("round_loop")

    # ---- compare G(proof) with H(nonce) -----------------------------------
    a.movi(R4, 0)
    a.movi(R5, 0)
    for i in range(4):
        _load32(a, G_STATE_ADDR, i)
        _load32_alt(a, TARGET_ADDR, i)
        a.xor(R0, R2)
        a.xor(R1, R3)
        a.or_(R4, R0)
        a.or_(R5, R1)
    a.mov(R0, R4)
    a.or_(R0, R5)
    a.jz("accept")
    a.movi(R0, 0)
    a.jmp("store_result")
    a.label("accept")
    a.movi(R0, 1)
    a.label("store_result")
    a.movi(R6, RESULT_ADDR)
    a.stb(R0, R6)
    a.halt()

    # ---- constant table, outside the executable path ----------------------
    if a.pc > G_K_ADDR:
        raise ValueError(f"firmware code {a.pc:#x} overlaps G_K table at {G_K_ADDR:#x}")
    a.raw(b"\x00" * (G_K_ADDR - a.pc))
    for value in G_K:
        a.raw(value.to_bytes(4, "little"))
    return a.assemble()
