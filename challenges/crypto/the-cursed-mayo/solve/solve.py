#!/usr/bin/env python3
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

V = 64
O = 17
K = 4
N = 81
SIG_BYTES = 186
MAGIC = b"CMAYO-SIGIL-v1\x00"

def gf_mul(a, b):
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        b >>= 1
        hi = a & 8
        a = (a << 1) & 15
        if hi:
            a ^= 3
    return p

GM = [[gf_mul(a, b) for b in range(16)] for a in range(16)]
GI = [0] * 16
for a in range(1, 16):
    for b in range(1, 16):
        if GM[a][b] == 1:
            GI[a] = b
            break
MPLANE = [[gf_mul(c, 1 << b) for b in range(4)] for c in range(16)]

def dot(a, b):
    s = 0
    for x, y in zip(a, b):
        s ^= GM[x][y]
    return s

def nib(b, idx):
    return (b[idx >> 1] >> ((idx & 1) * 4)) & 15

def read_offsets(signer_path, override=None):
    if override:
        vals = [int(x) for x in override.split(",")]
        if len(vals) != K or any(not (0 <= x < V) for x in vals) or len(set(vals)) != K:
            raise ValueError("bad --offsets")
        return vals
    with open(signer_path, "rb") as f:
        blob = f.read()
    at = blob.find(MAGIC)
    if at < 0:
        raise RuntimeError("sigil map not found in signer binary")
    vals = list(blob[at + len(MAGIC):at + len(MAGIC) + K])
    if len(vals) != K or any(x >= V for x in vals) or len(set(vals)) != K:
        raise RuntimeError("sigil map is malformed")
    return vals

def build_rows(equations):
    rows = []
    for eq in equations:
        planes = [0, 0, 0, 0]
        for idx, c in eq.items():
            if c == 0:
                continue
            base = idx * 4
            for b in range(4):
                m = MPLANE[c][b]
                if not m:
                    continue
                bit = 1 << (base + b)
                if m & 1:
                    planes[0] |= bit
                if m & 2:
                    planes[1] |= bit
                if m & 4:
                    planes[2] |= bit
                if m & 8:
                    planes[3] |= bit
        for p in planes:
            if p:
                rows.append(p)
    return rows

def rref(rows, ncols):
    rows = list(rows)
    piv = []
    r = 0
    for col in range(ncols):
        bit = 1 << col
        sel = None
        for i in range(r, len(rows)):
            if rows[i] & bit:
                sel = i
                break
        if sel is None:
            continue
        rows[r], rows[sel] = rows[sel], rows[r]
        pr = rows[r]
        for i in range(r + 1, len(rows)):
            if rows[i] & bit:
                rows[i] ^= pr
        piv.append(col)
        r += 1
        if r == len(rows):
            break
    for k in range(len(piv) - 1, -1, -1):
        bit = 1 << piv[k]
        pr = rows[k]
        for i in range(k):
            if rows[i] & bit:
                rows[i] ^= pr
    return rows[:len(piv)], piv

def nullspace(rows, piv, ncols):
    used = set(piv)
    free = [c for c in range(ncols) if c not in used]
    basis = []
    for f in free:
        v = 1 << f
        fb = 1 << f
        for k, pc in enumerate(piv):
            if rows[k] & fb:
                v |= 1 << pc
        basis.append(v)
    return free, basis

def equations_from_samples(samples, offsets, verbose=False):
    eqs = []
    zero_leaks = 0
    for base, sig in samples:
        ps = [(base + offsets[i]) % V for i in range(K)]
        xs = [[nib(sig, i * N + V + j) for j in range(O)] for i in range(K)]
        ys = [nib(sig, i * N + ps[i]) for i in range(K)]
        nz = [i for i in range(K) if ys[i] != 0]
        zero_leaks += K - len(nz)
        if nz:
            a = nz[0]
            for b in nz[1:]:
                eq = {}
                for j in range(O):
                    c = GM[ys[b]][xs[a][j]]
                    if c:
                        eq[ps[a] * O + j] = eq.get(ps[a] * O + j, 0) ^ c
                for j in range(O):
                    c = GM[ys[a]][xs[b][j]]
                    if c:
                        eq[ps[b] * O + j] = eq.get(ps[b] * O + j, 0) ^ c
                eq = {k: v for k, v in eq.items() if v}
                if eq:
                    eqs.append(eq)
        for i in range(K):
            if ys[i] == 0:
                eq = {ps[i] * O + j: xs[i][j] for j in range(O) if xs[i][j]}
                if eq:
                    eqs.append(eq)
    if verbose:
        sys.stderr.write(f"equations: {len(eqs)}, zero leaks: {zero_leaks}\n")
    return eqs

def recover(samples, offsets, verbose=False):
    eqs = equations_from_samples(samples, offsets, verbose)
    ncols = V * O * 4
    rows = build_rows(eqs)
    if verbose:
        sys.stderr.write(f"GF(2) rows: {len(rows)}\n")
    t0 = time.time()
    rows, piv = rref(rows, ncols)
    if verbose:
        sys.stderr.write(f"rank: {len(piv)}, nullity: {ncols - len(piv)}, time: {time.time()-t0:.1f}s\n")
    nullity = ncols - len(piv)
    if nullity != 4:
        return None, nullity
    free, basis = nullspace(rows, piv, ncols)
    flat = []
    v = basis[0]
    for idx in range(V * O):
        val = 0
        for b in range(4):
            if (v >> (idx * 4 + b)) & 1:
                val |= 1 << b
        flat.append(val)
    return bytes(flat), nullity

class Oracle:
    def __init__(self, host, port, timeout=60):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.recv_until(b"> ")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def recv_until(self, marker, timeout=180):
        self.sock.settimeout(timeout)
        while marker not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("connection closed")
            self.buf += chunk
        at = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:at], self.buf[at:]
        return out.decode("utf-8", "replace")

    def sendline(self, s):
        self.sock.sendall((s + "\n").encode())

    def public_key(self):
        self.sendline("1")
        out = self.recv_until(b"> ")
        m = re.search(r"public_key: ([0-9a-fA-F]+)", out)
        if not m:
            raise RuntimeError("no public key in response")
        return bytes.fromhex(m.group(1))

    def ritual(self, candle):
        self.sendline("2")
        self.recv_until(b"candle (0-63): ")
        self.sendline(str(candle))
        out = self.recv_until(b"> ")
        m = re.search(r"message: ([0-9a-fA-F]{64})", out)
        s = re.search(r"haunted_signature: ([0-9a-fA-F]{372})", out)
        left = re.search(r"queries_left: (\d+)", out)
        if not m or not s:
            raise RuntimeError(f"ritual failed: {out[-200:]}")
        return m.group(1), bytes.fromhex(s.group(1)), int(left.group(1)) if left else None

    def offer(self, msg_hex, sm_hex):
        self.sendline("3")
        out = self.recv_until(b"signature (hex, sig or sig||message): ")
        m = re.search(r"offering_message: ([0-9a-fA-F]{64})", out)
        if not m:
            raise RuntimeError("no offering message")
        if m.group(1) != msg_hex:
            raise RuntimeError("offering message mismatch")
        self.sendline(sm_hex)
        out2 = self.recv_until(b"> ")
        flag = re.search(r"the curse breaks\.\s*(.+)", out2)
        if flag:
            return flag.group(1).strip()
        if "rejects" in out2 or "malformed" in out2:
            return None
        raise RuntimeError(f"unexpected offering response: {out2[-200:]}")


def run_signer(args, timeout=60):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def normalize_and_forge(signer, pk_path, o_rec_path, workdir, msg_hex):
    o_norm = os.path.join(workdir, "O_normalized.bin")
    p = run_signer([signer, "normalize", pk_path, o_rec_path, o_norm], timeout=120)
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
        raise RuntimeError("could not normalize the recovered oil")
    m = re.search(r"scale: (\d+)", p.stdout)
    if m:
        sys.stderr.write(f"public-key scale: {m.group(1)}\n")
    p = run_signer([signer, "forge", pk_path, o_norm, msg_hex], timeout=60)
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
        raise RuntimeError("forge failed")
    m = re.search(r"signature: ([0-9a-fA-F]+)", p.stdout)
    if not m:
        raise RuntimeError("forge produced no signature")
    return o_norm, m.group(1)


def main():
    ap = argparse.ArgumentParser(description="intended solver for The Cursed MAYO")
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--signer", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dist", "cursed_signer"))
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--queries-per-candle", type=int, default=6)
    ap.add_argument("--offsets", default=None, help="override sigil offsets (comma separated)")
    ap.add_argument("--cache", default=None, help="JSON cache of ritual outputs")
    args = ap.parse_args()

    if args.workdir is None:
        args.workdir = tempfile.mkdtemp(prefix="cursed-mayo-")
    os.makedirs(args.workdir, exist_ok=True)
    signer = os.path.abspath(args.signer)
    offsets = read_offsets(signer, args.offsets)
    sys.stderr.write(f"sigil offsets: {offsets}\n")

    oracle = Oracle(args.host, args.port)
    pk = oracle.public_key()
    pk_path = os.path.join(args.workdir, "pk.bin")
    with open(pk_path, "wb") as f:
        f.write(pk)
    sys.stderr.write(f"public key: {len(pk)} bytes\n")

    cache = None
    if args.cache:
        try:
            with open(args.cache, "r", encoding="utf-8") as f:
                cache = json.load(f)
            if cache.get("pk") != pk.hex():
                cache = None
        except (OSError, ValueError):
            cache = None
    if cache is None:
        cache = {"pk": pk.hex(), "samples": [], "next": 0}
    samples = [(int(b), bytes.fromhex(s)) for b, s in cache["samples"]]
    cache["next"] = len(samples)

    total = V * args.queries_per_candle
    rounds = 0
    while len(samples) < total:
        base = (cache["next"] // args.queries_per_candle) % V
        try:
            msg_hex, sig, left = oracle.ritual(base)
        except RuntimeError as e:
            sys.stderr.write(f"{e}\n")
            break
        if left is not None and left <= 0:
            sys.stderr.write("query budget exhausted\n")
            break
        samples.append((base, sig))
        cache["samples"].append([base, sig.hex()])
        cache["next"] += 1
        if args.cache:
            tmp = args.cache + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cache, f)
            os.replace(tmp, args.cache)
        if len(samples) % 64 == 0:
            sys.stderr.write(f"collected {len(samples)}/{total} rituals\n")

    oracle.close()
    if len(samples) < total:
        sys.stderr.write(f"only collected {len(samples)} rituals; continuing\n")

    recovered = None
    nullity = None
    while True:
        rounds += 1
        recovered, nullity = recover(samples, offsets, verbose=True)
        if recovered is not None and nullity == 4:
            break
        sys.stderr.write(f"nullity {nullity}; need more equations\n")
        if rounds >= 3:
            break
        extra = V
        if len(samples) + extra > 600:
            extra = max(0, 600 - len(samples))
        if extra <= 0:
            break
        oracle = Oracle(args.host, args.port)
        for _ in range(extra):
            base = (cache["next"] // args.queries_per_candle) % V
            try:
                msg_hex, sig, left = oracle.ritual(base)
            except RuntimeError as e:
                sys.stderr.write(f"{e}\n")
                break
            samples.append((base, sig))
            cache["samples"].append([base, sig.hex()])
            cache["next"] += 1
        oracle.close()
        if args.cache:
            with open(args.cache, "w", encoding="utf-8") as f:
                json.dump(cache, f)

    if recovered is None or nullity != 4:
        raise SystemExit(f"recovery failed (nullity {nullity})")

    o_rec = os.path.join(args.workdir, "O_recovered.bin")
    with open(o_rec, "wb") as f:
        f.write(recovered)
    sys.stderr.write(f"recovered oil candidate: {o_rec}\n")

    oracle = Oracle(args.host, args.port)
    oracle.sendline("3")
    out = oracle.recv_until(b"signature (hex, sig or sig||message): ")
    m = re.search(r"offering_message: ([0-9a-fA-F]{64})", out)
    if not m:
        raise SystemExit("server did not issue an offering")
    offer_msg = m.group(1)
    o_norm, sm_hex = normalize_and_forge(signer, pk_path, o_rec, args.workdir, offer_msg)
    oracle.sendline(sm_hex)
    out2 = oracle.recv_until(b"> ")
    oracle.close()
    flag = re.search(r"the curse breaks\.\s*(.+)", out2)
    if not flag:
        sys.stderr.write(out2[-500:])
        raise SystemExit("the offering was rejected")
    print(flag.group(1))
    sys.stderr.write(f"normalized oil: {o_norm}\n")

if __name__ == "__main__":
    main()
