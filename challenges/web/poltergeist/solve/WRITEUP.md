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
is **PIE + NX + canary, GOT writable (no RELRO), fully stripped**, so the solve is
a real pwn: leak the image and libc, overwrite `puts@got` with `system`, and make
the worker run `system("cat /flag.txt 1>&<clientfd>")` so the flag is written
straight down your own socket.

(Why not a stack ROP? The write and read primitives are there for it, but modern
amd64 hosts enforce Intel **CET / shadow stack**, so overwriting a saved return
address does not redirect control. The GOT entry is an **indirect call**, not a
return, so it works regardless — this is why RELRO is deliberately off.)

Behind a warded door:

0. **Pass the wards** — solve the proof-of-work, keep payloads WAF-clean.
1. **Leak** the PIE base (dangling-descriptor window).
2. **Leak libc** (arbitrary-read `write@got`) and read `clientfd`.
3. **Overwrite** `puts@got` with `system` (arbitrary write; the GOT is writable).
4. **Trigger** `knell("cat /flag.txt 1>&<clientfd>")` → `puts` → `system` → the flag
   is `cat`-ed onto your socket.

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

(`echo_poke` is the 8-byte-at-a-time cousin; `echo_write` is the full
write-what-where that places `system`'s address on the GOT in one request.)

## 3. The binary is stripped — recover the offsets

The exploit needs four things from the image, and **the binary has no symbols**:

* `arena` — bump-allocator base; turns a leaked arena pointer into the image base.
* `write@got` — a GOT slot (its relocation survives stripping: read it from
  `.rela.plt`/`.dynsym`); arbitrary-read it to leak libc.
* `puts@got` — the GOT slot the `knell` builtin calls through; the write target.
* `clientfd` — the accepted socket fd (a `.data` int); read it so the shell can
  redirect its output to our socket.

## 4. Leaks

```
# PIE: leave a 64-byte string, OOM so g_echo dangles at {STR,64,&arena[K]};
#      next request's array element pointer lands in that window and leaks
#      an arena address -> image base = leaked - off(arena) - 24.
# libc: arbitrary-read write@got -> write()'s libc address -> libc base.
# clientfd: arbitrary-read the clientfd global.
```

All derived from a single leaked pointer and the handed-out `libc.so.6`, so the
exploit is ASLR-independent.

## 5. GOT overwrite → system → the flag on our socket

The GOT is writable (no RELRO). The `knell(s)` builtin calls `puts(s)`, so:

```
# overwrite puts@got with system()
echo_write(&puts@got, p64(libc_base + system_offset))

# trigger: knell(cmd) -> puts(cmd) -> system(cmd)
knell("cat /flag.txt 1>&<clientfd>")
```

`system("/bin/sh -c cat /flag.txt 1>&<clientfd>")` forks a shell that inherits the
accepted socket as `<clientfd>`, so `cat` writes the flag **straight down our own
connection** (before the request's `200`). `solve.py` reads the whole response.

Why an indirect call and not a stack ROP? Modern amd64 hosts enforce Intel **CET /
shadow stack**: overwriting a saved return address does not redirect control (the
`ret` uses the protected copy). Overwriting a **GOT** entry is an indirect call,
immune to the shadow stack — which is why the build is `-z norelro`.

```bash
python3 solve/solve.py <HOST> <PORT>      # e.g. 127.0.0.1 32731
# [*] pie base ... libc base ... system ...
# [+] FLAG: ccsCTF{...}
```

`system` forks a shell; the worker runs under a **watchdog parent** that re-spawns
it if anything ever kills it, so the service stays up for everyone.

## 6. Automated solver

[`solve.py`](solve.py) does every stage, solving the proof-of-work with `hashlib`
and resolving `write`/`system` from the handed-out `libc.so.6`. The four static
offsets (§3) are not in the stripped binary; for reproducibility the official
solver reads them from an author-only `solve/chall.offsets` (**never shipped** —
players reverse-engineer them).

## 7. Why it's fair, and why it's hard

Everything is discoverable from the handed-out `chall.c` and binary:

1. Get past the door (proof-of-work + WAF).
2. See the persistent-worker + engine-global + per-request-arena shape, and that
   the flag is **not in memory** and there is **no gate** — you need code execution.
3. Spot that `g_echo` is cleared on the normal and script-error paths but **not**
   on the OOM bailout; turn the dangle into arbitrary read (`recall`) and write
   (`echo_write`).
4. **Reverse-engineer the stripped binary** for the four offsets, leak the image
   and libc, overwrite `puts@got` with `system`, and trigger `knell` to read
   `/flag.txt` onto your socket.

No brute force and no guessing — a precise lifetime bug chained into a leak and a
GOT-overwrite RCE, behind a stripped binary and a warded door.

## 8. How to fix it

* **Clear engine references to request memory on *every* exit path**, fatal
  included. Adding `g_echo = NULL;` to the OOM bailout kills it at the root:
  with no dangling pointer there is no read **and** no write, so there is no leak
  and no GOT overwrite. The handout ships only the vulnerable source; the
  regression harness applies this one-line patch and shows both primitives vanish.
* Better still: don't let a fatal path abandon an operation mid-way — either finish
  establishing invariants or terminate the worker (PHP's soft/hard `memory_limit`).
* Don't hand interpreter values raw pointers into a shared arena; use handles or
  copy out of request memory before publishing to engine scope.
