"""Concurrency tests: many solvers racing the service at once."""

from concurrent.futures import ThreadPoolExecutor


def test_concurrent_solvers(run_solver, server):
    n = 30
    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(lambda _: run_solver(), range(n)))
    for r in results:
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == server["flag"]


def test_concurrent_mixed_traffic(run_solver, server):
    """Solvers racing against garbage clients must all still succeed."""
    import socket

    def garbage(_):
        try:
            with socket.create_connection((server["host"], server["port"]), timeout=10) as s:
                s.sendall(b"AUTH " + b"11" * 16 + b"\n")
                s.recv(1024)
        except OSError:
            pass
        return run_solver()

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(garbage, range(12)))
    for r in results:
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == server["flag"]
