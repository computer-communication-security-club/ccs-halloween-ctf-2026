"""Protocol-level tests against the live server."""

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from hydra_common import mac, proof  # noqa: E402


def _connect(server):
    s = socket.create_connection((server["host"], server["port"]), timeout=10)
    f = s.makefile("rwb")
    return s, f


def _read_nonce(f, expected_banner="HYDRA-SVC/1.0 AUTH-REQUIRED"):
    banner = f.readline().decode().strip()
    assert banner == expected_banner
    nonce_line = f.readline().decode().strip()
    assert nonce_line.startswith("NONCE ")
    nonce = bytes.fromhex(nonce_line.split(" ", 1)[1])
    assert len(nonce) == 16
    return nonce


def test_banner_and_nonce(server):
    s, f = _connect(server)
    _read_nonce(f)
    s.close()


def test_fresh_nonce_per_connection(server):
    s1, f1 = _connect(server)
    n1 = _read_nonce(f1)
    s2, f2 = _connect(server)
    n2 = _read_nonce(f2)
    assert n1 != n2
    s1.close()
    s2.close()


def test_valid_proof_releases_flag(server):
    s, f = _connect(server)
    nonce = _read_nonce(f)
    f.write(f"AUTH {proof(nonce).hex()}\n".encode())
    f.flush()
    assert f.readline().decode().strip() == "AUTH-OK"
    assert f.readline().decode().strip() == f"FLAG {server['flag']}"
    s.close()


def test_old_mac_tag_is_not_a_valid_proof(server):
    """The retired nonce->tag routine must no longer authenticate."""
    s, f = _connect(server)
    nonce = _read_nonce(f)
    f.write(f"AUTH {mac(nonce).hex()}\n".encode())
    f.flush()
    resp = f.readline().decode()
    assert resp.strip() == "AUTH-FAIL"
    assert server["flag"] not in resp
    s.close()


def test_wrong_proof_rejected_without_flag(server):
    s, f = _connect(server)
    nonce = _read_nonce(f)
    bad = bytes(b ^ 0xFF for b in proof(nonce))
    f.write(f"AUTH {bad.hex()}\n".encode())
    f.flush()
    resp = f.readline().decode()
    assert resp.strip() == "AUTH-FAIL"
    assert server["flag"] not in resp
    s.close()


def test_proof_replay_rejected(server):
    # Authenticate on connection A (collect a valid proof), then replay it on B.
    s1, f1 = _connect(server)
    n1 = _read_nonce(f1)
    p1 = proof(n1)
    f1.write(f"AUTH {p1.hex()}\n".encode())
    f1.flush()
    assert f1.readline().decode().strip() == "AUTH-OK"
    f1.readline()
    s1.close()

    s2, f2 = _connect(server)
    n2 = _read_nonce(f2)
    assert n1 != n2
    f2.write(f"AUTH {p1.hex()}\n".encode())  # replayed proof
    f2.flush()
    resp = f2.readline().decode()
    assert resp.strip() == "AUTH-FAIL"
    assert server["flag"] not in resp
    s2.close()


def test_malformed_request_rejected(server):
    for line in [b"HELLO\n", b"AUTH\n", b"AUTH zz\n", b"AUTH " + b"00" * 15 + b"\n",
                 b"AUTH " + b"00" * 17 + b"\n", b"AUTH " + b"00" * 16 + b"GG\n",
                 b"AUTH " + b"00" * 17 + b"\n", b"AUTH \x00\x01\x02\n",
                 b"AUTH " + b"00" * 8 + b"\n"]:
        s, f = _connect(server)
        _read_nonce(f)
        f.write(line)
        f.flush()
        resp = f.readline().decode("ascii", "replace")
        assert resp.strip() == "ERR BAD-REQUEST", (line, resp)
        assert server["flag"] not in resp
        s.close()


def test_overlong_line_is_rejected_not_executed(server):
    s, f = _connect(server)
    _read_nonce(f)
    f.write(b"AUTH " + b"41" * 200 + b"\n")
    f.flush()
    resp = f.readline().decode("ascii", "replace")
    assert resp.strip() == "ERR BAD-REQUEST"
    s.close()


def test_uppercase_hex_accepted(server):
    s, f = _connect(server)
    nonce = _read_nonce(f)
    f.write(f"AUTH {proof(nonce).hex().upper()}\n".encode())
    f.flush()
    assert f.readline().decode().strip() == "AUTH-OK"
    s.close()


def test_activity_file_updated(server):
    # Activity is recorded when a client actually sends a protocol line, not
    # on bare connects (Docker health checks must not defeat auto-shutdown).
    s, f = _connect(server)
    _read_nonce(f)
    f.write(b"HELLO\n")
    f.flush()
    assert f.readline().decode().strip() == "ERR BAD-REQUEST"
    s.close()
    assert server["activity"].exists()


def test_logs_never_contain_flag(server):
    s, f = _connect(server)
    nonce = _read_nonce(f)
    f.write(f"AUTH {proof(nonce).hex()}\n".encode())
    f.flush()
    f.readline()
    f.readline()
    s.close()
    s, f = _connect(server)
    nonce = _read_nonce(f)
    f.write(b"AUTH " + b"00" * 16 + b"\n")
    f.flush()
    f.readline()
    s.close()
    log = server["log_path"].read_text()
    assert "result=OK" in log and "result=FAIL" in log
    assert server["flag"] not in log
