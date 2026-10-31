# PHPossessed — author notes (private)

| | |
| --- | --- |
| Deployment | `per-team`, isolated service (`chall`), renewable 30-minute lifetime |
| Player endpoint | HTTPS hostname supplied by rCTF; local HTTP on port 32003 |
| Handout | None (pure black-box); `dist/` intentionally empty |
| Solver | `solve/solve.py HOST PORT`, stdlib only, ~5 s, no PHP needed |

```
player ──HTTP──▶ apache2 prefork, ONE child, uid 10001, :8080
                   ▼
                 mod_php 8.4.26, stock php.ini-production  ← the sink is the RUNTIME
                   ▼
                 CVE-2026-109618: dangling PS(id) → Set-Cookie leaks heap + libphp base
                   ▼
                 CVE-2026-109619: fake zend_array, pDestructor = zif_system → system()
                   ▼
                 /flag.txt → /tmp/sess_zz (session flash) → rendered out
```

## Vulnerability

Real-world PHP2Shell, not an application bug: the STOCK
`php:8.4.26-apache` image with the STOCK `php.ini-production`
(display_errors=Off, 128M, post_max_size=8M, upload_progress at defaults).
That build predates the 2026-10-21 security release (8.4.27 fixed it). The
app has no `unserialize`, no custom ini — even Hello World on this image is
vulnerable. Chain adapted from `9bie/php2shell-bypass-aslr-exp`:

- **A1** — chunked multipart POST (no `Content-Length` → `post_max_size`
  check skipped) OOMs during upload-progress END cleanup before
  `PG(modules_activated)=1`; `PS(id)` dangles with `send_cookie=1`.
- **B1** — forged `zend_string` header; `Set-Cookie` url-encodes ~512KB of
  heap out: chunk bases + `zval_ptr_dtor` → libphp base.
- **A2** — cheap OOM on nested empty file fields dangles
  `PS(http_session_vars)`.
- **B2** — spray of fake `zend_reference`s + one fake `HashTable` with
  `pDestructor = zif_system`; request shutdown runs `system(<cmd>)`.

The exfil cmd (≤200 B, POSIX sh) writes `/flag.txt` as a php-serialized
flash to `/tmp/sess_zz`; a final GET with `PHPSESSID=zz` renders it.
Apache runs **one static prefork child** (`ServerLimit 1`, `KeepAlive Off`):
the bug is cross-request, and serializing also stops solvers racing.

## Discoverability

- `X-Powered-By: PHP/8.4.26` on every response — search it against the
  2026-10-21 advisory and the public chain comes up.
- The site is a red herring: `case` cookie is plain base64, `/archive`
  escapes it, no `unserialize` anywhere. App-bug hunters burn time.
- An earlier `/credits` manifest page was removed: it named
  `session.upload_progress` outright — an answer key.

## The app (Halloween UI)

Paranormal field journal: Mongolian haunted-places collection (Wikimedia
photos, CC-licensed, fictional/folklore samples), place detail pages, and
visitor story/photo submissions at `/report` (CSRF, 1 MB/photo, 6 MB and
100 reports total, stored in `/tmp/phpossessed-reports`, served via
`/photo/<name>`). No accounts; the plain-text `case` cookie + `/archive`
remain. Local preview: `php -S 127.0.0.1:8085 -t src/www src/www/router.php`.

## Build and test

```sh
# from the repo root, once at challenges/web/phpossessed/
uv run tools/ctf.py check challenges/web/phpossessed
uv run tools/ctf.py test  challenges/web/phpossessed

# by hand, from this directory
BIND_ADDR=0.0.0.0 docker compose up -d --build --wait
python3 solve/solve.py 127.0.0.1 32003
docker compose down --volumes --remove-orphans
```

Tested 2026-10-31 on **native linux/amd64**: `ctf.py test` 12/12 against the
hardened compose service (0.5 CPU, read-only rootfs, tmpfs `/tmp`, uid 10001).
A WSL2/Docker-Desktop pass is **not** evidence for production: the chain was
originally calibrated there and did not land a single leak on native Linux.
**After any app change, rerun the solver** — the chain is allocation-sensitive,
and B1 depends on `registry.php` staying output-free.

## Solver calibration (read before retargeting)

Calibrated and verified on **native linux/amd64** (12/12 `ctf.py test` runs,
Docker 28 / kernel 6.12, and GitHub's `ubuntu-24.04` runner shape). The four
items below are what native Linux needs beyond the published reference chain;
all of them are host behaviour, not app behaviour.

- **A1 frees main-chunk slots for the session init** (`DUP_SLOTS=4`): the same
  four field names are sent early and again just before the progress field, so
  `zend_hash_update` releases the early (main-chunk) values. ZendMM hands small
  slots out LIFO, so `s_open`'s `basedir` ("/tmp", bin 32) reuses one of them.
  Without this, `basedir` lives in a chunk that is gone by the next request and
  B1's `ps_close_files` -> `efree(basedir)` aborts the worker with
  `zend_mm_heap corrupted` before the leak is sent. The reference chain relies
  on the `G:511` fills overwriting `basedir`'s refcount instead; that cannot
  help here, because the panic is in `_efree`'s `chunk->heap` check and fires
  before any refcount is read.
- **The forged `zend_string` must be interned and carry a legal key.**
  `type_info = 0x106` (`IS_STRING|IS_STR_INTERNED`), because the rfc1867 END
  event runs `php_rshutdown_session_globals` ->
  `zend_string_release(PS(id))`; on a non-interned header that `efree()`s an
  address inside the fill and poisons a small-bin free list. The value is a
  NUL-terminated 31-char `[a-z0-9]` key, because `php_session_start()` runs
  `strpbrk(ZSTR_VAL(id), "\r\n\t <>'\"\\")` and drops `PS(id)` on a hit —
  the reference's `/NNBBBBB` payload loses the leak outright.
- **B1 targets `/registry.php`, not the front controller.** The Set-Cookie is
  built during request startup, but Apache only flushes it when the request
  finishes, and `ps_close_files` has by then freed A1's stale `ps_files`
  struct, which is live memory in this request. Compiling the whole front
  controller allocates from the poisoned bin and aborts first; `registry.php`
  only defines functions, emits nothing, and gets the response out. Response
  is **HTTP 200 with an ~810KB body**.
- **Retries, not precision**: a failed attempt costs ~2s (worker SIGSEGVs,
  prefork respawns) and a successful one ~3s, so the solver retries up to 14
  times inside the harness's 60s budget and waits on `/health.txt` between
  attempts. Per-attempt success is roughly one in two; 14 attempts make the
  run deterministic in practice.

Unchanged from the reference calibration, and re-verified here:

- **Pointer floor** `0x100000000000`, not `0x7F...` — WSL2/Docker-Desktop map
  heap/libphp at `0x7a..–0x7e..`, so a `0x7f` floor drops every pointer there.
- **Read window** `fake_len=0x80000`, not `0xC8000`: the stale id sits at page
  `0x137` of a 2MiB chunk and the longer read overruns it. 512KB still covers
  the `G:400` hole where the leak pointers are.
- **No warm-up request** — a warm GET runs the app right before A1 and shifts
  the ZendMM free lists off calibration. It also *clears* the dangle: any
  request that reaches userland starts a session and releases `PS(id)`.
- **A1 knobs travel in pairs**: query shape (5x 8-char params), BIG=78,
  BURN=20, F128=14 pin the dangling id to page `0x137` and keep the OOM inside
  `php_session_send_cookie`, which is what leaves `PS(send_cookie)=1`. Moving
  the progress field, or adding page-sized A1 fields, moves the OOM out of
  that window and the dangle disappears entirely.
- **Per-build offsets**: `zval_ptr_dtor=+0x65EB60`, `zif_system=+0x465370`,
  `S=main+0xF8398`, delta band `0x1A00000..0x1F00000` — pinned to the amd64
  digest below, and all correct on native Linux (leaked libphp base checked
  against `/proc/<worker>/maps`). Different build => re-derive.
- **MAIN_BUCKET_COUNT=87** fingerprints the main-chunk bucket in the leak. The
  solver now keeps every candidate whose libphp-main delta is in band instead
  of judging the attempt on the first one.

## Operator notes

- One published port, no other ingress, no egress. Non-root `10001`,
  `cap_drop: ALL`, `no-new-privileges`, read-only root fs.
- Writable tmpfs: `/tmp` (16 MB) for sessions, reports/photos, and the
  exfil channel; `/var/run/apache2` and `/var/lock` (1 MB each) for Apache.
  Reset via the instance controls, or locally with `compose down --volumes`.
- Flag baked from `flag.txt` to `/flag.txt`, `0444` root-owned.
- No `disable_functions`, no custom ini — don't "harden" the image; that
  breaks both calibration and the real-world framing.
- Readiness probes must hit `/health.txt` (static, never enters PHP), or
  they reset the cross-request state.
- Crashes are normal: a failed chain SIGSEGVs the child; the prefork master
  respawns it in ~1s. Players just retry.

## Reproducibility

- Image pinned: `php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a`
  (amd64 `sha256:b0ae0e0d4a3b7f0e800017482752b94f58ab049f2d7fcd108e5452afce3f50d1`).
  Never bump: 8.4.27 fixes the bug the challenge *is*.
- App = plain PHP, no Composer/vendor. Build+test on `linux/amd64` (the
  leak parser also carries an aarch64 offset profile).
