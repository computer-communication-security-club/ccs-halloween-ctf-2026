# PHPossessed — author notes (private)

| | |
| --- | --- |
| Deployment | `shared`, one Compose project, one service (`chall`) |
| Player endpoint | `http://CHALLENGE_HOST:32003`, plain HTTP, Apache + mod_php |
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

Tested 2026-10-30 (WSL2/Docker Desktop): solver 3/3 + UI upload smoke test
against the rebuilt image. **After any app change, rerun the solver** — the
chain is allocation-sensitive.

## Solver calibration (read before retargeting)

`solve.py` encodes all of these; if the image or host changes, these are
the knobs:

- **Pointer floor** `0x100000000000`, not the reference's `0x7F...` —
  WSL2/Docker-Desktop map heap/libphp at `0x7a..–0x7e..`.
- **Read window** `fake_len=0x80000`, not `0xC8000`: the stale id sits at
  page `0x137` of a 2MiB chunk and the longer read overruns it by 24 B →
  SIGSEGV. 512KB still covers the `G:400` hole where the leak pointers are.
- **No warm-up request** — the reference's warm GET runs our (heavy) app
  right before A1 and shifts the ZendMM free lists off calibration.
- **A1 knobs travel in pairs**: query shape (5× 8-char params), BIG=78,
  BURN=20, F128=14 pin the dangling id to page `0x137`.
- **Per-build offsets**: `zval_ptr_dtor=+0x65EB60`, `zif_system=+0x465370`,
  `S=main+0xF8398`, delta band `0x1A00000..0x1F00000` — pinned to the amd64
  digest below. Different build ⇒ re-derive.
- **MAIN_BUCKET_COUNT=87** fingerprints the main-chunk bucket in the leak.

## Operator notes

- One published port, no other ingress, no egress. Non-root `10001`,
  `cap_drop: ALL`, `no-new-privileges`, read-only root fs.
- Only writable path: `/tmp` tmpfs (16 MB) — sessions, reports/photos, and
  the exfil channel. Reset = `compose down --volumes`.
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
