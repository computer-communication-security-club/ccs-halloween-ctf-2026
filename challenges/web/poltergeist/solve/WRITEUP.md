# 🕯️ Writeup — Poltergeist

> **SPOILERS.** Full intended solution. Author/organiser (or thoroughly stuck
> player) eyes only.

**TL;DR.** The Séance worker is a single long-lived process with an engine-global
pointer, `g_echo`, into the per-request *arena*. That pointer is cleared at the
end of every **normal** request — but a **fatal out-of-memory** error unwinds the
request with `longjmp` and **skips the cleanup**, leaving `g_echo` dangling into
the arena the next request reuses (a cross-request use-after-free; the PHP2Shell
shape). Poisoning `g_echo` and dropping a forged `Val` on top of it gives an
**arbitrary read** (`recall`) and an **arbitrary write** (`echo_write`). There is
no flag in memory and no gate to flip — the flag is only in `/flag.txt`. The build
is **PIE + Full RELRO + NX + canary and fully stripped**, so the solve is a real
pwn: leak the image and libc, leak the stack, lay an `open`/`read`/`write` **ROP
chain** over `process_request`'s return address, and exfiltrate `/flag.txt` to our
own socket.

Behind a warded door:

0. **Pass the wards** — solve the proof-of-work, keep payloads WAF-clean.
1. **Leak** the PIE base (dangling-descriptor window).
2. **Leak libc** (arbitrary-read `write@got`) and read `clientfd`.
3. **Leak the stack** (arbitrary-read libc `environ`) and find the return slot.
4. **ROP** — `echo_write` an `open`/`read`/`write("/flag.txt" → socket)` chain over
   `process_request`'s return address; when it returns, the flag is sent to you.

See [`../docs/cve-analysis.md`](../docs/cve-analysis.md) and
[`../docs/INVARIANTS.md`](../docs/INVARIANTS.md).

---

## 0. The warded door

Two things sit in front of `/seance`, both visible in `chall.c` and neither part
of the language or the bug:

* **A proof-of-work gate.** `GET /pow` returns `pow <challenge> <bits>`; find a
  nonce so `sha256(challenge + nonce)` has `<bits>` leading zero bits and send it
  back in `X-Pow: <challenge>.<nonce>` on every `/seance` request. A solved proof
  is valid for the whole window (~120 s) and reusable, so you solve it once.
* **A signature WAF.** It refuses 7+ digit decimal literals (body/`X-Seance-Echo`),
  generic scanner/traversal probes, and bodies over 4 KiB. The naive OOM trigger
  is a giant literal, so read the source: `memory_limit` is only 256 KiB, so a
  6-digit count (e.g. `900000`) both OOMs and clears the WAF. The forged-`Val` and
  chain bytes are `\xNN` escapes — no 7-digit run — so they pass.

## 1. Root cause — cleanup only on the happy path

`process_request()` ends by clearing `g_echo = NULL`, and the non-fatal
`script_fault` path clears it too. But a **fatal OOM** `longjmp`s from `ralloc()`
to a bailout in the accept loop that tidies the arena and answers `500` **without
clearing `g_echo`.** After an OOM, `g_echo` still points into the (reset,
about-to-be-reused) arena — the CVE-2026-109619 shape, triggered by a
CVE-2026-109618-class OOM. Invariant **I1** ("no engine global may reference arena
memory once a request ends") is violated on exactly that one path.

## 2. Two primitives from the dangling pointer

A `Val` is 24 bytes: `{ int64 type; int64 len; union { int64 i; char *s; Val *a; } }`.

* `do_unserialize()` (the `X-Seance-Echo` header) allocates the top-level value
  **first** and publishes it to `g_echo` before parsing, so `s:900000:x;` sets
  `g_echo = &arena[0]` and then OOMs → `g_echo` dangles at **offset 0**.
* In the next request the **first** arena allocation lands at offset 0. A string
  literal is copied verbatim (`str_val`), so a literal whose raw 24 bytes **are** a
  forged `Val{STR, len, addr}` overwrites `*g_echo`.

That yields:

* **arbitrary READ** — `recall()` returns the forged `Val`; `whisper` dumps `len`
  bytes at `addr`;
* **arbitrary WRITE** — `echo_write($s)` does `memcpy(addr, $s, min(len, $s.len))`,
  i.e. write-what-where of attacker bytes.

(`echo_poke` is the 8-byte-at-a-time cousin; `echo_write` is what lets you place a
whole ROP chain in one request.)

## 3. The binary is stripped — recover the offsets

The chain needs four things from the image, and **the binary has no symbols**:

* `arena` — bump-allocator base; turns a leaked arena pointer into the image base.
* `write@got` — a GOT slot (its relocation survives stripping: read it from
  `.rela.plt`/`.dynsym`); arbitrary-read it to leak libc.
* `clientfd` — the accepted socket fd (a `.data` int); read it so the chain can
  `write()` the flag back to us.
* **`process_request`'s return site** — the address in `serve` just after
  `call process_request`. Find the request handler in the disassembly (it is the
  function the accept loop calls to run a program); the instruction right after that
  call is the value you will scan the stack for.

`process_request` has a stack canary, but its saved **return address sits above the
frame that holds the canary**, so overwriting the return (and up) never touches it.

## 4. Leaks

```
# PIE: leave a 64-byte string, OOM so g_echo dangles at {STR,64,&arena[K]};
#      next request's array element pointer lands in that window and leaks
#      an arena address -> image base = leaked - off(arena) - 24.
# libc: arbitrary-read write@got -> write()'s libc address -> libc base.
# clientfd: arbitrary-read the clientfd global.
# stack: arbitrary-read libc `environ` -> a stack address; read a few KiB below
#        it and scan for (image_base + retsite) -> process_request's return slot.
```

All derived from a single leaked pointer and the handed-out `libc.so.6`, so the
exploit is ASLR-independent.

## 5. ROP — open / read / write the flag to our socket

Build, with libc gadgets (`pop rdi|rsi|rdx|rax ; ret`, `syscall ; ret`) and raw
syscalls, a chain laid out starting at the return slot (the `/flag.txt` string and
a scratch buffer ride along at the end of the chain, at known stack addresses):

```
open("/flag.txt", 0)                 # fd = clientfd + 1 (single-threaded, close-per-request)
read(clientfd+1, buf, 100)
write(clientfd, buf, 100)            # the flag, straight back down our own socket
exit(60)
```

`echo_write` that chain over the return slot in one request. `process_request`
finishes (it even sends its normal `200`), then **returns into the chain**, which
appends the flag to the response. `solve.py` reads it off the tail.

```bash
python3 solve/solve.py <HOST> <PORT>      # e.g. 127.0.0.1 32731
# [*] pie base ... libc base ... retslot ...
# [+] FLAG: ccsCTF{...}
```

The worker runs under a **watchdog parent**: the chain's `exit` kills only that
worker, and the parent immediately forks a fresh one, so a solve never takes the
service down (the port never drops, the container never restarts).

## 6. Automated solver

[`solve.py`](solve.py) does every stage, solving the proof-of-work with `hashlib`
and resolving libc gadgets/symbols from the handed-out `libc.so.6`. The four static
offsets (§3) are not in the stripped binary; for reproducibility the official
solver reads them from an author-only `solve/chall.offsets` (**never shipped** —
players reverse-engineer them). Against a non-stripped local rebuild it falls back
to the `.symtab`.

## 7. Why it's fair, and why it's hard

Everything is discoverable from the handed-out `chall.c` and binary:

1. Get past the door (proof-of-work + WAF).
2. See the persistent-worker + engine-global + per-request-arena shape, and that
   the flag is **not in memory** and there is **no gate** — you need code execution.
3. Spot that `g_echo` is cleared on the normal and script-error paths but **not**
   on the OOM bailout; turn the dangle into arbitrary read (`recall`) and write
   (`echo_write`).
4. **Reverse-engineer the stripped binary** for the four offsets, leak the image,
   libc and stack, and ROP `open`/`read`/`write` to exfiltrate `/flag.txt`.

No brute force and no guessing — a precise lifetime bug chained into a leak and a
full ROP, behind a stripped binary and a warded door.

## 8. How to fix it

* **Clear engine references to request memory on *every* exit path**, fatal
  included. Adding `g_echo = NULL;` to the OOM bailout kills the chain at the root:
  with no dangling pointer there is no read **and** no write, so there is no leak
  and no ROP. The handout ships only the vulnerable source; the regression harness
  applies this one-line patch and shows both primitives vanish.
* Better still: don't let a fatal path abandon an operation mid-way — either finish
  establishing invariants or terminate the worker (PHP's soft/hard `memory_limit`).
* Don't hand interpreter values raw pointers into a shared arena; use handles or
  copy out of request memory before publishing to engine scope.
