import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]  # challenge directory
SRC = ROOT / "src"
sys.path.insert(0, str(SRC / "tools"))


@pytest.fixture(scope="session")
def project_root():
    return ROOT


@pytest.fixture(scope="session")
def flag_text(project_root):
    return (project_root / "flag.txt").read_text().strip()


@pytest.fixture(scope="session")
def server_binary(project_root, tmp_path_factory):
    out = tmp_path_factory.mktemp("hydra-build") / "hydra-server"
    r = subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-static", "-pthread",
         "-I", str(SRC), "-o", str(out),
         str(SRC / "hydra_vm.c"), str(SRC / "fw_crypto.c"), str(SRC / "server.c")],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return out


@pytest.fixture(scope="session")
def firmware_blob(project_root):
    return (project_root / "src" / "firmware" / "firmware.enc").read_bytes()


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def server(server_binary, flag_text, tmp_path, project_root):
    port = _free_port()
    activity = tmp_path / "activity"
    log_path = tmp_path / "server.log"
    env = os.environ.copy()
    env.update({
        "HYDRA_PORT": str(port),
        "HYDRA_BIND": "127.0.0.1",
        "HYDRA_FW_FILE": str(project_root / "src" / "firmware" / "firmware.enc"),
        "HYDRA_FLAG_FILE": str(project_root / "flag.txt"),
        "HYDRA_ACTIVITY_FILE": str(activity),
    })
    with open(log_path, "w") as logf:
        proc = subprocess.Popen([str(server_binary)], env=env,
                                stdout=logf, stderr=subprocess.STDOUT)
    deadline = time.time() + 5
    up = False
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                up = True
                break
        except OSError:
            time.sleep(0.05)
    if not up:
        proc.kill()
        pytest.fail(f"server did not start: {log_path.read_text()}")
    yield {
        "host": "127.0.0.1",
        "port": port,
        "flag": flag_text,
        "activity": activity,
        "log_path": log_path,
        "proc": proc,
    }
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture()
def run_solver(server, project_root):
    def _run(host=None, port=None, timeout=10):
        return subprocess.run(
            [sys.executable, str(project_root / "solve" / "solve.py"),
             host or server["host"],
             str(port if port is not None else server["port"]),
             "--timeout", str(timeout)],
            capture_output=True, text=True, timeout=timeout + 10)
    return _run
