"""Firmware and MAC reference tests (algorithm stability + round trip)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import fw_key  # noqa: E402
from hydra_common import mac, proof, verify  # noqa: E402


# Frozen test vectors: guards against accidental algorithm drift between the
# Python reference and the firmware running in the C VM.
MAC_VECTORS = {
    bytes(16): "61b399115c1fde1a995b35d8b8e42c50",
    bytes(range(16)): "9ea63623ee43184b73ad792bb4411a4c",
    b"\xff" * 16: "c5c5e6f38e7acf9631ee128af9cd0767",
}


@pytest.mark.parametrize("nonce,expected", list(MAC_VECTORS.items()))
def test_mac_vectors(nonce, expected):
    assert mac(nonce).hex() == expected


def test_mac_deterministic():
    nonce = bytes(range(16))
    assert mac(nonce) == mac(nonce)
    assert mac(nonce) != mac(bytes(range(1, 17)))


def test_proof_roundtrip():
    nonce = bytes(16)
    p = proof(nonce)
    assert p.hex() == "4c4b412fb60125e54bc9f07f10d02396"
    assert verify(nonce, p)
    assert not verify(nonce, bytes(16))
    assert not verify(nonce, mac(nonce))


def test_mac_avalanche():
    nonce = bytes(16)
    base = mac(nonce)
    flipped = mac(b"\x01" + bytes(15))
    assert base != flipped
    diff = sum(a != b for a, b in zip(base, flipped))
    assert diff >= 4, "MAC output should change in several bytes"


def test_firmware_roundtrip(project_root):
    blob = (project_root / "src" / "firmware" / "firmware.enc").read_bytes()
    plain = fw_key.unpack_firmware(blob)
    assert len(plain) > 512
    assert len(plain) < 0xE000
    # Re-packing must reproduce the identical blob (deterministic cipher).
    assert fw_key.pack_firmware(plain) == blob


def test_firmware_rejects_corruption(project_root):
    blob = bytearray((project_root / "src" / "firmware" / "firmware.enc").read_bytes())
    blob[20] ^= 0x01  # corrupt ciphertext -> CRC mismatch
    with pytest.raises(ValueError):
        fw_key.unpack_firmware(bytes(blob))


def test_firmware_rejects_bad_magic(project_root):
    blob = bytearray((project_root / "src" / "firmware" / "firmware.enc").read_bytes())
    blob[0:4] = b"XXXX"
    with pytest.raises(ValueError):
        fw_key.unpack_firmware(bytes(blob))


def test_keystream_c_implementation_parity(project_root):
    """The C keystream must match the Python keystream byte for byte."""
    import subprocess
    import tempfile

    # Build a tiny C harness that dumps keystream bytes for a known key.
    harness = r"""
    #include <stdio.h>
    #include "fw_crypto.h"
    int main(void) {
        uint8_t key[32], out[64];
        hydra_kdf("HYDRA-FIRMWARE-KEY-v1", 21, key);
        hydra_keystream(key, out, 64);
        for (int i = 0; i < 64; i++) printf("%02x", out[i]);
        printf("\n");
        for (int i = 0; i < 32; i++) printf("%02x", key[i]);
        printf("\n");
        return 0;
    }
    """
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "h.c"
        src.write_text(harness)
        binp = Path(td) / "h"
        r = subprocess.run(
            ["gcc", "-O2", "-I", str(project_root / "src"), "-o", str(binp),
             str(src), str(project_root / "src" / "fw_crypto.c")],
            capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        out = subprocess.run([str(binp)], capture_output=True, text=True, check=True)
        ks_hex, key_hex = out.stdout.strip().splitlines()

    assert key_hex == fw_key.kdf().hex()
    assert ks_hex == fw_key.keystream(fw_key.kdf(), 64).hex()
