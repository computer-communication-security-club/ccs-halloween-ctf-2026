"""HYDRA VM assembler.

Instruction set (opcode -> length):
    0x00 NOP       1        0x11 LDW  d,a   3
    0x01 HALT      1        0x12 STW  s,a   3
    0x02 MOVI d,i16 4       0x13 ADDI d,i16 4
    0x03 MOV  d,s  3        0x14 CMPI d,i16 4
    0x04 ADD  d,s  3        0x15 CMP  d,s   3
    0x05 ADC  d,s  3        0x16 JMP  a16   3
    0x06 SUB  d,s  3        0x17 JZ   a16   3
    0x07 XOR  d,s  3        0x18 JNZ  a16   3
    0x08 AND  d,s  3        0x19 JC   a16   3
    0x09 OR   d,s  3        0x1A JNC  a16   3
    0x0A NOT  d    2        0x1B CALL a16   3
    0x0B SHL  d,s  3        0x1C RET       1
    0x0C SHR  d,s  3        0x1D PUSH s     2
    0x0D ROTL d,s  3        0x1E POP  d     2
    0x0E ROTR d,s  3        0x1F MIXW d,s   3
    0x0F LDB  d,a  3        0x20 XORI d,i16 4
    0x10 STB  s,a  3

Operands: d/s = register 0..7, a = register holding a byte address,
i16/a16 = little-endian 16-bit value (label or int).
"""

# Register names
R0, R1, R2, R3, R4, R5, R6, R7 = range(8)

OP = {
    "NOP": 0x00, "HALT": 0x01, "MOVI": 0x02, "MOV": 0x03, "ADD": 0x04,
    "ADC": 0x05, "SUB": 0x06, "XOR": 0x07, "AND": 0x08, "OR": 0x09,
    "NOT": 0x0A, "SHL": 0x0B, "SHR": 0x0C, "ROTL": 0x0D, "ROTR": 0x0E,
    "LDB": 0x0F, "STB": 0x10, "LDW": 0x11, "STW": 0x12, "ADDI": 0x13,
    "CMPI": 0x14, "CMP": 0x15, "JMP": 0x16, "JZ": 0x17, "JNZ": 0x18,
    "JC": 0x19, "JNC": 0x1A, "CALL": 0x1B, "RET": 0x1C, "PUSH": 0x1D,
    "POP": 0x1E, "MIXW": 0x1F, "XORI": 0x20,
}


class Asm:
    def __init__(self, base=0x0000):
        self.base = base
        self.pc = base
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []  # (buf_offset, name)

    # -- plumbing -----------------------------------------------------
    def _emit(self, *bs):
        for b in bs:
            self.buf.append(b & 0xFF)
        self.pc += len(bs)

    def _imm16(self, value):
        if isinstance(value, int):
            self._emit(value & 0xFF, (value >> 8) & 0xFF)
        else:
            self.fixups.append((len(self.buf), value))
            self._emit(0, 0)

    def label(self, name):
        if name in self.labels:
            raise ValueError(f"duplicate label {name}")
        self.labels[name] = self.pc

    def raw(self, data: bytes):
        self.buf += data
        self.pc += len(data)

    def word16(self, value):
        self._imm16(value)

    def assemble(self) -> bytes:
        for off, name in self.fixups:
            if name not in self.labels:
                raise ValueError(f"undefined label {name}")
            v = self.labels[name]
            self.buf[off] = v & 0xFF
            self.buf[off + 1] = (v >> 8) & 0xFF
        return bytes(self.buf)

    # -- instructions -------------------------------------------------
    def nop(self):
        self._emit(OP["NOP"])

    def halt(self):
        self._emit(OP["HALT"])

    def movi(self, d, imm):
        self._emit(OP["MOVI"], d)
        self._imm16(imm)

    def _rr(self, mnem, d, s):
        self._emit(OP[mnem], d, s)

    def mov(self, d, s):
        self._rr("MOV", d, s)

    def add(self, d, s):
        self._rr("ADD", d, s)

    def adc(self, d, s):
        self._rr("ADC", d, s)

    def sub(self, d, s):
        self._rr("SUB", d, s)

    def xor(self, d, s):
        self._rr("XOR", d, s)

    def and_(self, d, s):
        self._rr("AND", d, s)

    def or_(self, d, s):
        self._rr("OR", d, s)

    def not_(self, d):
        self._emit(OP["NOT"], d)

    def shl(self, d, s):
        self._rr("SHL", d, s)

    def shr(self, d, s):
        self._rr("SHR", d, s)

    def rotl(self, d, s):
        self._rr("ROTL", d, s)

    def rotr(self, d, s):
        self._rr("ROTR", d, s)

    def ldb(self, d, a):
        self._rr("LDB", d, a)

    def stb(self, s, a):
        self._rr("STB", s, a)

    def ldw(self, d, a):
        self._rr("LDW", d, a)

    def stw(self, s, a):
        self._rr("STW", s, a)

    def addi(self, d, imm):
        self._emit(OP["ADDI"], d)
        self._imm16(imm)

    def cmpi(self, d, imm):
        self._emit(OP["CMPI"], d)
        self._imm16(imm)

    def cmp_(self, d, s):
        self._rr("CMP", d, s)

    def xori(self, d, imm):
        self._emit(OP["XORI"], d)
        self._imm16(imm)

    def mixw(self, d, s):
        self._rr("MIXW", d, s)

    def _jmp(self, mnem, target):
        self._emit(OP[mnem])
        self._imm16(target)

    def jmp(self, t):
        self._jmp("JMP", t)

    def jz(self, t):
        self._jmp("JZ", t)

    def jnz(self, t):
        self._jmp("JNZ", t)

    def jc(self, t):
        self._jmp("JC", t)

    def jnc(self, t):
        self._jmp("JNC", t)

    def call(self, t):
        self._jmp("CALL", t)

    def ret(self):
        self._emit(OP["RET"])

    def push(self, s):
        self._emit(OP["PUSH"], s)

    def pop(self, d):
        self._emit(OP["POP"], d)
