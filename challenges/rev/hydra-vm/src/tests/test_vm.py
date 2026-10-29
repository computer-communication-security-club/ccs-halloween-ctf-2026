"""VM control-flow and firmware-verifier regression tests.

These cover the 3-byte branch encoding (target in bytes 1..2), which differs
from the 4-byte immediate instructions (bytes 2..3), plus C/Python parity for
the encrypted verifier firmware.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]  # challenge directory
SRC = ROOT / "src"
sys.path.insert(0, str(SRC / "tools"))

from asm import Asm, R0, R1  # noqa: E402
from hydra_common import mac, proof  # noqa: E402


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    out = tmp_path_factory.mktemp("vmprobe") / "vm_probe"
    r = subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-I", str(SRC),
         "-o", str(out), str(SRC / "tests" / "vm_probe.c"),
         str(SRC / "hydra_vm.c")],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return out


def run(probe, program, max_steps=10000):
    path = probe.parent / "prog.bin"
    path.write_bytes(program)
    r = subprocess.run([str(probe), str(path), str(max_steps)],
                       capture_output=True, text=True, check=True)
    status, pc, sp, z, c, *regs = r.stdout.split()
    return {
        "status": int(status), "pc": int(pc), "sp": int(sp),
        "z": int(z), "c": int(c), "regs": [int(v) for v in regs],
    }


def test_jmp(probe):
    a = Asm()
    a.jmp("target")
    a.movi(R0, 0xBAD)
    a.label("target")
    a.movi(R0, 0x1234)
    a.halt()
    st = run(probe, a.assemble())
    assert st["status"] == 0
    assert st["regs"][0] == 0x1234


def test_jz_taken_and_not_taken(probe):
    a = Asm()
    a.movi(R0, 0)
    a.cmpi(R0, 0)
    a.jz("taken")
    a.movi(R1, 1)
    a.halt()
    a.label("taken")
    a.movi(R1, 2)
    a.halt()
    assert run(probe, a.assemble())["regs"][1] == 2

    a = Asm()
    a.movi(R0, 1)
    a.cmpi(R0, 0)
    a.jz("taken")
    a.movi(R1, 1)
    a.halt()
    a.label("taken")
    a.movi(R1, 2)
    a.halt()
    assert run(probe, a.assemble())["regs"][1] == 1


def test_jnz(probe):
    a = Asm()
    a.movi(R0, 5)
    a.cmpi(R0, 5)
    a.jnz("bad")
    a.movi(R1, 7)
    a.label("bad")
    a.halt()
    assert run(probe, a.assemble())["regs"][1] == 7


def test_call_ret(probe):
    a = Asm()
    a.call("sub")
    a.movi(R1, 7)
    a.halt()
    a.label("sub")
    a.movi(R0, 5)
    a.ret()
    st = run(probe, a.assemble())
    assert st["status"] == 0
    assert st["regs"][0] == 5 and st["regs"][1] == 7


def test_step_limit(probe):
    a = Asm()
    a.label("loop")
    a.jmp("loop")
    st = run(probe, a.assemble(), max_steps=250)
    assert st["status"] == 1


def test_invalid_opcode_faults(probe):
    st = run(probe, bytes([0x21]) + bytes(15))
    assert st["status"] == -1


@pytest.fixture(scope="module")
def fw_probe(tmp_path_factory):
    out = tmp_path_factory.mktemp("fwprobe") / "fw_probe"
    r = subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-I", str(SRC),
         "-o", str(out), str(SRC / "tests" / "fw_probe.c"),
         str(SRC / "hydra_vm.c"), str(SRC / "fw_crypto.c")],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return out


def run_fw(fw_probe, nonce, candidate, steps="1000000"):
    r = subprocess.run(
        [str(fw_probe), str(SRC / "firmware" / "firmware.enc"),
         nonce.hex(), candidate.hex(), steps],
        capture_output=True, text=True, check=True,
        env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"})
    rc, result, target, gstate, pc, nsteps = r.stdout.split()
    return int(rc), int(result), target, gstate, int(pc), int(nsteps)


def test_firmware_verifier_parity(fw_probe):
    """C VM executing the encrypted verifier must agree with Python for
    arbitrary nonces, and must reject random wrong proofs."""
    for i in range(100):
        nonce = os.urandom(16)
        candidate = proof(nonce)
        rc, result, target, _, _, _ = run_fw(fw_probe, nonce, candidate)
        assert rc == 0
        assert target == mac(nonce).hex()
        assert result == 1, i
        rc, result, _, _, _, _ = run_fw(fw_probe, nonce, os.urandom(16))
        assert rc == 0 and result == 0, i


def test_firmware_step_limit_fails_closed(fw_probe):
    nonce = bytes(16)
    rc, result, _, _, _, _ = run_fw(fw_probe, nonce, proof(nonce), "10")
    assert rc == 1
    assert result == 0
