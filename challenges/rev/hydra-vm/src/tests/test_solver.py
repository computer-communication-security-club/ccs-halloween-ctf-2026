"""External solver tests."""


def test_external_solver_passes(run_solver, server):
    r = run_solver()
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == server["flag"]


def test_solver_rejects_wrong_service(run_solver):
    # Port with nothing listening: solver must fail cleanly, exit code 1.
    r = run_solver(host="127.0.0.1", port=1, timeout=3)
    assert r.returncode == 1
    assert "solver error" in r.stderr
