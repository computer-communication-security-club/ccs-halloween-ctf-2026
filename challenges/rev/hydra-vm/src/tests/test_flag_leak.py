"""Flag leak scan: the flag must never reach the player handout or
unauthenticated protocol surfaces."""

import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]  # challenge directory
DIST = ROOT / "dist"
sys.path.insert(0, str(ROOT / "src" / "tools"))

from hydra_common import proof  # noqa: E402

EXPECTED = {"README.md", "PROTOCOL.md", "hydra-server", "firmware.enc"}


@pytest.mark.skipif(not DIST.is_dir(), reason="run `uv run tools/ctf.py dist` first")
def test_player_dist_contains_no_flag_or_private_material(flag_text):
    files = {str(p.relative_to(DIST)) for p in DIST.rglob("*") if p.is_file()}
    assert files == EXPECTED
    for path in DIST.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        assert flag_text.encode() not in data, f"flag leaked into {path.name}"
    assert b"hydra_common" not in (DIST / "README.md").read_bytes()
    assert b"hydra_common" not in (DIST / "PROTOCOL.md").read_bytes()
    assert not any(p.name in ("solve.py", "WRITEUP.md") for p in DIST.rglob("*"))


def test_binary_and_firmware_contain_no_flag(flag_text):
    assert (DIST / "hydra-server").is_file()
    assert (DIST / "firmware.enc").is_file()
    assert flag_text.encode() not in (DIST / "hydra-server").read_bytes()
    assert flag_text.encode() not in (DIST / "firmware.enc").read_bytes()


def test_unauthenticated_responses_contain_no_flag(server):
    s = socket.create_connection((server["host"], server["port"]), timeout=10)
    f = s.makefile("rwb")
    banner = f.readline().decode()
    nonce_line = f.readline().decode()
    f.write(b"AUTH " + b"00" * 16 + b"\n")
    f.flush()
    fail = f.readline().decode()
    s.close()
    for surface in (banner, nonce_line, fail):
        assert server["flag"] not in surface
        assert "ccsCTF{" not in surface


def test_malformed_responses_contain_no_flag(server):
    s = socket.create_connection((server["host"], server["port"]), timeout=10)
    f = s.makefile("rwb")
    f.readline()
    f.readline()
    f.write(b"GARBAGE\n")
    f.flush()
    resp = f.readline().decode()
    s.close()
    assert server["flag"] not in resp
    assert "ccsCTF{" not in resp


def test_successful_auth_leaks_flag_only_to_holder(server):
    """Sanity: the only surface that carries the flag is the AUTH-OK path."""
    s = socket.create_connection((server["host"], server["port"]), timeout=10)
    f = s.makefile("rwb")
    f.readline()
    nonce_line = f.readline().decode()
    nonce = bytes.fromhex(nonce_line.split(" ", 1)[1])
    f.write(f"AUTH {proof(nonce).hex()}\n".encode())
    f.flush()
    f.readline()
    flag_line = f.readline().decode()
    s.close()
    assert flag_line.strip() == f"FLAG {server['flag']}"
