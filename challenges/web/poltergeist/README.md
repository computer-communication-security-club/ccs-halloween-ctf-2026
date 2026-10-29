# 👻 Poltergeist — author notes (private)

**CCS Halloween CTF 2026 · Web · Difficulty: `insane` · Port `32731`**

> Private author/organizer notes: build/test commands, exact mitigations, the
> offsets the official solver uses, isolation, and risks. The player sees only
> `challenge.yml`'s description and the handout in `dist/`. The full intended
> solution is in [`solve/WRITEUP.md`](solve/WRITEUP.md).

## What it is

**Séance** is an original PHP-flavoured scripting language implemented 100 % in C,
with its **own persistent single-process HTTP worker** (`POST /seance` runs a
program; `GET /` playground; `GET /healthz`; `GET /pow`). The worker keeps an
engine-global pointer `g_echo` into a per-request *arena* and clears it at the end
of every normal request — but a **fatal out-of-memory** error `longjmp`s out and
**skips that cleanup**, leaving `g_echo` dangling into the arena the next request
reuses. This is a faithful toy of **PHP2Shell** (CVE-2026-109618 OOM bailout
leaving the CVE-2026-109619 cross-request use-after-free). See
[`docs/cve-analysis.md`](docs/cve-analysis.md) and
[`docs/INVARIANTS.md`](docs/INVARIANTS.md).

The forged `Val` yields **arbitrary read** (`recall`) and **arbitrary write**
(`echo_write`, a `memcpy`-what-where). There is **no flag in memory and no gate**:
the flag exists only in `/flag.txt`, so the intended solve is **remote code
execution** — leak PIE + libc + stack, then `echo_write` an `open`/`read`/`write`
ROP chain over `process_request`'s return address to exfiltrate `/flag.txt` down
the attacker's own socket. No container escape.

Front-door wards (both in the handed-out `chall.c`, neither touching the bug): a
**signature WAF** and a **proof-of-work gate** (`GET /pow` → solve → `X-Pow`
header).

## Build, export, check, test

From the repository root (CI runs these on native `ubuntu-24.04`):

```sh
uv run tools/ctf.py dist  challenges/web/poltergeist          # export dist/ (stripped)
uv run tools/ctf.py check challenges/web/poltergeist          # static rules
uv run tools/ctf.py test  challenges/web/poltergeist          # solve vs a fresh deploy (<60 s)
```

Local regression (compiles vulnerable + patched builds and drives them over
sockets; needs only `gcc`/`binutils`/stdlib):

```sh
python3 tests/test_chall.py            # 50 checks: language, limits, UAF, WAF, PoW, RCE primitives, stripped
```

Solver dependencies: **Python 3 standard library only** (declared in the `uv`
script header of `solve/solve.py`). It connects to the service and reads the
handed-out `dist/libc.so.6` plus the author-only `solve/chall.offsets`.

## Mitigations (recorded `checksec dist/chall`)

```
RELRO: Full    STACK CANARY: Canary found    NX: enabled    PIE: enabled
RPATH/RUNPATH: none    Symbols: No Symbols (fully stripped)    FORTIFY: Yes
```

`gcc -O1 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now`, then
`strip --strip-all`. Full RELRO removes the easy `puts@got → system` finish; the
chain targets `process_request`'s **return address**, which sits above the frame
holding the canary, so the write never touches the canary.

## Offsets (why `solve/chall.offsets` exists)

The handout binary is **stripped**, so a player reverse-engineers the four static
offsets the chain needs: `arena`, `clientfd`, `write@got`, and
`process_request`'s return site. For CI reproducibility the official solver reads
them from **`solve/chall.offsets`** (author-only, never in the handout). They are
captured deterministically from the UNstripped intermediate during the Docker
`dist` build and are regenerated with:

```sh
docker build --platform linux/amd64 --target offsets -o type=local,dest=/tmp/o . \
  && cp /tmp/o/chall.offsets solve/chall.offsets
```

libc gadgets and `write`/`environ` addresses come from the handed-out `libc.so.6`,
and all bases are leaked at runtime, so the exploit is **ASLR-independent** (it
works under native amd64 and under qemu-user emulation).

## Isolation and shared-mode safety

Non-root (`10001`), `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, CPU/mem/PID
limited, **egress none**; `/flag.txt` is `0444`. A solver's RCE can read the flag
but cannot write it (read-only fs), reach the network, escalate, or persist: the
worker is a single long-lived process under a **watchdog parent** that re-spawns it
on death (the chain ends in `exit`), so a solve never drops the port or restarts
the container, and no team can durably spoil the service for another. The watchdog
is a supervisor, **not** a per-connection fork server — this is an HTTP web
challenge, so the redpwn/jail requirement for stdin/stdout pwn does not apply. A
stalled client cannot wedge the sequential worker (15 s socket timeouts).

## Testing record and risks

* **Native Linux amd64:** `tools/ctf.py dist --verify` + `test` run on
  `ubuntu-24.04` in CI (`.github/workflows/challenges.yml`). Locally the author
  verified end-to-end under Colima/qemu-user amd64 (fixed base `0x4000000000`); the
  solver self-calibrates every base/stack address from leaks, so it is not tied to
  that environment.
* **Reproducibility:** base image pinned by SHA-256 digest; the handout binary is
  byte-identical to the deployed `/app/run` (same multi-stage build) and
  `dist --verify` enforces it.
* **Independent test-solve:** pending — a non-author solves from the description +
  handout + endpoint before freeze (per the rules).
* **Flag:** real flag in private `flag.txt` and the matching `challenge.yml` entry
  only; the handout and solver contain no plaintext flag.
