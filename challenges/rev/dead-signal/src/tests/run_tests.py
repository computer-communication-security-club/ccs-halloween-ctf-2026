#!/usr/bin/env python3
"""
DEAD SIGNAL — automated acceptance tests (repository layout).

Run from anywhere:  python3 src/tests/run_tests.py
Prerequisite:       bash src/build.sh   (builds src/build/dead_signal{,_bypass})

Verifies, against the ACTUAL built artifacts:

  1. Correct token succeeds and prints the flag.
  2. Incorrect tokens fail and never print the flag.
  3. Invalid input lengths / charset fail safely (no crash, no flag).
  4. The organizer solver (solver.py) reconstructs the correct token.
  5. The solvers are NOT hardcoded: a rebuilt binary with a different random
     token is solved to that different token.
  6. No plaintext flag/token in the binaries (build and dist handout).
  7. Bypassing the acceptance branch (forced-success build AND a real NOP
     patch of the conditional jump) does NOT decrypt the flag for an
     incorrect token — the key is derived from the input.
  8. The pipeline is bijective, so the correct token is unique.
"""

from __future__ import annotations

import os
import random
import shutil
import string
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent          # src/tests
SRC = HERE.parent                                # src
ROOT = SRC.parent                                # challenge root
BUILD = SRC / "build"

BIN = BUILD / "dead_signal"
BIN_BYPASS = BUILD / "dead_signal_bypass"

sys.path.insert(0, str(SRC))
sys.path.insert(0, str(HERE))
import gen_constants  # noqa: E402
import solver as solver_mod  # noqa: E402

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}" + (f" -- {detail}" if detail else ""))


def run_binary(bin_path: Path, token_input: str, timeout: int = 10):
    p = subprocess.run([str(bin_path)], input=token_input.encode(),
                       capture_output=True, timeout=timeout)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def read_flag() -> bytes:
    return (ROOT / "flag.txt").read_bytes().strip()


def read_token() -> str:
    tok_file = os.environ.get("DSIG_TOKEN")
    if tok_file and len(tok_file) == 24:
        return tok_file
    path = HERE / "token.txt"
    if path.is_file():
        return path.read_text().strip()
    raise SystemExit("no token: set DSIG_TOKEN or run src/build.sh first")


def main() -> int:
    flag = read_flag()
    token = read_token()
    flag_s = flag.decode()

    assert flag.startswith(b"ccsCTF{") and flag.endswith(b"}"), "bad flag config"
    assert len(token) == 24, "bad token config"
    print(f"[info] flag config : {flag_s}")
    print(f"[info] token       : {token}")
    print(f"[info] binary      : {BIN}\n")

    assert BIN.is_file(), "src/build/dead_signal missing — run bash src/build.sh"
    assert BIN_BYPASS.is_file(), "bypass build missing — run bash src/build.sh"

    # ---- 1. correct token succeeds --------------------------------------
    rc, out, err = run_binary(BIN, token + "\n")
    report("1a correct token accepted (exit 0)", rc == 0, f"rc={rc} err={err!r}")
    report("1b correct token prints the flag", flag_s in out, f"out={out[-200:]!r}")

    # ---- 2. incorrect tokens fail ---------------------------------------
    rng = random.Random(1234)
    wrong_tokens = [
        "AAAAAAAAAAAAAAAAAAAAAAAA",
        "ZZZZZZZZZZZZZZZZZZZZZZZZ",
        "000000000000000000000000",
        token[:-1] + ("A" if token[-1] != "A" else "B"),
        token[1:] + token[0],
    ]
    for _ in range(5):
        wrong_tokens.append("".join(rng.choice(string.ascii_uppercase + string.digits)
                                    for _ in range(24)))
    all_failed, leaked, wt = True, False, ""
    for wt in wrong_tokens:
        if wt == token:
            continue
        rc, out, err = run_binary(BIN, wt + "\n")
        if rc == 0 or flag_s in out:
            all_failed = False
            leaked = leaked or flag_s in out
            break
    report("2a incorrect 24-char tokens rejected", all_failed, f"token={wt!r}")
    report("2b incorrect tokens never leak the flag", not leaked)

    # ---- 3. invalid input fails safely ---------------------------------
    bad_inputs = [
        ("empty input", "\n"),
        ("23 chars", "A" * 23 + "\n"),
        ("25 chars", "A" * 25 + "\n"),
        ("1 char", "A\n"),
        ("200 chars", "B" * 200 + "\n"),
        ("no trailing newline", "A" * 24),
        ("bad charset", "a" * 24 + "\n"),
        ("bad charset symbols", "!" * 24 + "\n"),
        ("embedded space", "A" * 23 + " \n"),
        ("binary garbage", bytes(range(1, 32)).decode("latin1")),
    ]
    safe, detail = True, ""
    for name, inp in bad_inputs:
        try:
            rc, out, err = run_binary(BIN, inp)
        except subprocess.TimeoutExpired:
            safe, detail = False, f"{name}: timeout"
            break
        if rc < 0:
            safe, detail = False, f"{name}: killed by signal {-rc}"
            break
        if flag_s in out:
            safe, detail = False, f"{name}: flag leaked"
            break
        if rc == 0:
            safe, detail = False, f"{name}: accepted invalid input"
            break
    report("3  invalid lengths/charset fail safely", safe, detail)

    # ---- 4. organizer solver reconstructs the correct token -------------
    token_out, consts = solver_mod.solve(str(BIN))
    report("4a organizer solver recovers token from binary", token_out == token,
           f"solver={token_out!r} expected={token!r}")
    report("4b constants extracted from the ELF", consts["offset"] > 0)
    bl = subprocess.run([sys.executable, str(HERE / "blind_solver.py"), str(BIN)],
                        capture_output=True, text=True)
    report("4c independent blind solver agrees", bl.stdout.strip() == token,
           f"blind={bl.stdout.strip()!r}")

    # ---- 5. solvers are not hardcoded-token printers --------------------
    with tempfile.TemporaryDirectory(prefix="dsig_alt_") as tmp:
        alt_src = Path(tmp) / "src"
        shutil.copytree(SRC, alt_src, ignore=shutil.ignore_patterns("build", "__pycache__"))
        alt_token = "".join(random.Random(99).choice(string.ascii_uppercase + string.digits)
                            for _ in range(24))
        if alt_token == token:
            alt_token = "".join(random.Random(100).choice(string.ascii_uppercase + string.digits)
                                for _ in range(24))
        gen = subprocess.run(
            [sys.executable, str(SRC / "gen_constants.py"),
             "--out", str(alt_src / "generated_constants.h"),
             "--token", alt_token, "--flag", flag_s, "--seed", "7"],
            capture_output=True)
        alt_bin = Path(tmp) / "dead_signal_alt"
        build = subprocess.run(
            ["gcc", "-O2", "-std=c11", "-Wall", "-Wextra",
             "-o", str(alt_bin), str(alt_src / "dead_signal.c")],
            capture_output=True)
        ok_build = gen.returncode == 0 and build.returncode == 0
        report("5a alt build with different token compiles", ok_build,
               f"gen={gen.stderr.decode()[-200:]} gcc={build.stderr.decode()[-200:]}")
        if ok_build:
            subprocess.run(["strip", "--strip-all", str(alt_bin)], check=True)
            solved_alt, _ = solver_mod.solve(str(alt_bin))
            report("5b solver recovers the DIFFERENT token", solved_alt == alt_token,
                   f"solver={solved_alt!r} expected={alt_token!r}")
            report("5c solver output is not the static token", solved_alt != token)

    # ---- 6. no plaintext flag / token in the binaries -------------------
    blob = BIN.read_bytes()
    report("6a build binary contains no plaintext flag", flag not in blob)
    report("6b build binary contains no plaintext token", token.encode() not in blob)
    dist_bin = ROOT / "dist" / "dead_signal"
    if dist_bin.is_file():
        dblob = dist_bin.read_bytes()
        report("6c dist handout contains no plaintext flag/token",
               flag not in dblob and token.encode() not in dblob)
    else:
        print("[SKIP] 6c dist/dead_signal not built yet")

    # ---- 7. patched acceptance branch does not reveal the flag ---------
    rc, out, err = run_binary(BIN_BYPASS, "AAAAAAAAAAAAAAAAAAAAAAAA\n")
    report("7a bypass build accepts (branch really patched)", rc == 0, f"rc={rc}")
    report("7b bypass + wrong token does NOT print the flag", flag_s not in out,
           f"out={out[-200:]!r}")
    rc, out, err = run_binary(BIN_BYPASS, token + "\n")
    report("7c bypass + correct token still decrypts (control)", flag_s in out)

    b = bytearray(blob)
    pat = b"\x85\xc0\x0f\x84"  # test eax,eax ; je rel32
    idxs = [i for i in range(len(b) - 4)
            if bytes(b[i:i + 4]) == pat and (i == 0 or b[i - 1] != 0x48)]
    with tempfile.TemporaryDirectory(prefix="dsig_patch_") as tmp:
        patched = Path(tmp) / "dead_signal_patched"
        if len(idxs) == 1:
            i = idxs[0]
            b[i + 2:i + 8] = b"\x90" * 6  # NOP the je rel32
            patched.write_bytes(b)
            patched.chmod(0o755)
            rc, out, err = run_binary(patched, "AAAAAAAAAAAAAAAAAAAAAAAA\n")
            report("7d NOP-patched binary reaches success path", rc == 0, f"rc={rc}")
            report("7e NOP-patched + wrong token does NOT print flag", flag_s not in out,
                   f"out={out[-200:]!r}")
            rc, out, err = run_binary(patched, token + "\n")
            report("7f NOP-patched + correct token decrypts (control)", flag_s in out)
        else:
            report("7d acceptance branch located uniquely", False,
                   f"candidates={[hex(x) for x in idxs]}")

    # ---- 8. transform is a bijection -> the correct token is unique -----
    biject = True
    rng2 = random.Random(4242)
    for _ in range(200):
        t = bytes(rng2.randrange(256) for _ in range(24))
        c_fake = {k: consts[k] for k in
                  ("perm", "xkey", "rots", "roll_seed", "roll_mul", "roll_add",
                   "blk_mul", "blk_add", "blk_rol")}
        w = gen_constants.validate_forward(t, c_fake)
        if solver_mod.invert_transform(w, c_fake) != t:
            biject = False
            break
    report("8a pipeline is bijective (inverse matches)", biject)
    solved_again = solver_mod.invert_transform(consts["target"], consts)
    report("8b target maps to exactly the shipped token", solved_again == token.encode())

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
