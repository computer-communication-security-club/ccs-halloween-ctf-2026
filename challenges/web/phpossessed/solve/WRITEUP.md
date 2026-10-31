# PHPossessed — intended solution (spoilers)

Real-world PHP2Shell: no handout, no application bug, no `unserialize`.
The target is the stock `php:8.4.26-apache` runtime (CVE-2026-109618 /
CVE-2026-109619, disclosed 2026-10-21, fixed in 8.4.27) and the only
authored part is a themed app wrapped around it — the same app you'd find
on any small PHP site. Everything below is reproducible with the shipped
`solve/solve.py`, Python stdlib only, against
`http://HOST:32003`.

## 1. Reconnaissance

Three requests is the whole footprint:

- Any response carries `X-Powered-By: PHP/8.4.26` (stock `expose_php=On`)
  and `Server: Apache/2.4.69 (Debian)`. The version is the key: search it
  against the 2026-10-21 PHP security release and PHP2Shell comes up, with
  a published reference exploit (`9bie/php2shell-bypass-aslr-exp`).
- Poke the app: `/report` issues a `case` cookie that is plain
  `base64(text)` — not `serialize()` — and `/archive` renders it through
  `htmlspecialchars`. There is no `unserialize`, no file write, no query
  sink. The app is a red herring wearing a hint-shaped costume ("Our
  runtime is bleeding-edge PHP").
- There is deliberately **no `/credits` page** in the shipped version. An
  earlier draft listed the runtime manifest there; it named
  `session.upload_progress` outright — an answer key, not reconnaissance.
  The version info that makes the challenge solvable survives via the
  default header, which is how a real target would leak it too.

Difficulty knob check: this is a **pure black-box** challenge. Players who
know the CVE exist and can read a version header can solve it; players who
don't will learn what a "cross-request runtime UAF" is the hard way.

## 2. The bug

`session.upload_progress` tracks in-flight multipart uploads by starting a
session *during body parsing* — before any application code runs. In
8.4.26 that machinery has two flaws that chain:

1. **Chunked bodies bypass `post_max_size`.** `rfc1867_post_handler`
   checks `SG(request_info).content_length` once at entry; a chunked
   request has `content_length=0`, so the check passes and the multipart
   parser happily consumes a 30MB+ body. That's the heap-shaping
   primitive: attacker-controlled multi-megabyte allocations.
2. **The OOM bailout leaves dangling session globals.** Push memory to
   `memory_limit` (128M, stock) while the upload-progress code is writing
   its final state, and the bailout fires before
   `PG(modules_activated)=1`. The session module's shutdown cleanup is
   skipped, so `PS(id)` keeps pointing into freed chunk memory — and
   `PS(send_cookie)=1` means the next request will url-encode that
   pointer into a `Set-Cookie` header. The memory manager recycles those
   chunks for the *next* request in the same process, so an attacker who
   can land all requests in one worker controls what `PS(id)` reads.

Apache here is pinned to a single static prefork child
(`ServerLimit 1`, `KeepAlive Off`), so cross-request state is guaranteed —
the reference exploit needed 149 holder connections to pin one of 150
workers; here the choreography is just "send the four requests".

## 3. The four-request chain

All bodies are multipart POSTs sent with `Transfer-Encoding: chunked`
(essential — see §2.1). The solver builds them in Python byte-for-byte;
no target-side files, no PHP on the player side.

**A1 — dangle `PS(id)`** (`build_a1`, ~1MB, path `/index.php` +
`?q0000000=v&…` five 8-char params):

860 nested depth-64 empty-file fields + 14×103B fillers + 78×8000B values
+ 20×4000B burners + a 4000B `PHP_SESSION_UPLOAD_PROGRESS` value. The
query string is not decoration: GET params allocate before POST parsing
and shift the bin-40/bin-64 free-list heads, pinning the dangling id to
page `0x137` of its chunk. The trio *(query shape, BIG=78, burners)* is
calibrated as a set — move one and the id page moves with it. Expected
result: **HTTP 500** (the OOM bailout), worker survives.

**B1 — leak heap + libphp** (`build_leak_b`, ~33MB):

14× `G:511:0x137` full-chunk forgeries + 1× `G:400:0x137` + 1×
`G:511:0x137` + 900 nested `X` array fields, all with a fake
`zend_string` header at page `0x137` (where the stale id points),
`len=0x80000`, `refcount=0`, type `IS_STRING|GC_NOT_COLLECTABLE`, data
starting `/NNBBBBB`:

- The `G:511` values reuse the freed 2MiB chunks (basedir-killer: they
  overwrite `basedir`'s refcount so its release at close is a no-op
  instead of a `zend_mm_panic`).
- `G:400` stops at page 400, leaving an **111-page hole** (pages
  `0x191..0x1ff`) in the id's chunk; the 900 `X` fields' real HashTables
  are carved into it by Best-Fit, planting genuine `pDestructor =
  zval_ptr_dtor` pointers inside the read window.
- At session start the forged id is url-encoded into `Set-Cookie`:
  ~512KB of worker heap leave in the response header. Expected result:
  **HTTP 404 with an ~811KB body** (404 because `/index.php` as a path
  falls through the front controller — harmless).

`parse_leak` then scans the decoded window for user-space pointers,
clusters them by 2MiB (`& ~0x1FFFFF`), and reads off:

- `libphp = most_common(pointer) - 0x65EB60` (`zval_ptr_dtor`),
- `main chunk` = the non-lib, non-id bucket whose count matches the
  stable fingerprint **87**,
- sanity: `libphp - main ∈ 0x1A00000..0x1F00000`, else the leak is
  discarded and the whole chain restarts.

**A2 — dangle `PS(http_session_vars)`** (`build_cheap_oom_a`, ~1MB):

880 nested depth-64 empty-file fields after 115 fillers; a cheaper OOM
that leaves the session-vars array pointer dangling at a calibrated
offset inside the main chunk (`hsv ≈ main+0x7D720`, absorbed by the
spray below — the solver iterates the leaked main-chunk candidates).

**B2 — fake the array, get RCE** (`build_fake_ref_b` + `build_ht`):

A 384-byte carrier holds a fake `HashTable` at address `S=main+0xF8398`:
`pDestructor = zif_system = libphp+0x465370`, one element whose zval is a
fake `zend_string` containing the command, plus a fake `execute_data` so
the call convention lines up. ~995 spray values of fake
`zend_reference`s (`refcount=1`, `ptr=S`) overwrite the dangling
`PS(http_session_vars)` slot so request shutdown's
`zend_hash_destroy()` calls `system(<cmd>)` for us.

**Exfil.** The fake-string carrier only has ~200 bytes for the command,
and there is no egress. So the command writes the flag *into the target's
session storage* and the flag is read back through the app itself:

```sh
F=$(cat /flag.txt|tr -d '\n');
printf 'flash|s:%d:"%s";' "${#F}" "$F">/tmp/sess_zz
```

A final `GET /` with `Cookie: PHPSESSID=zz` makes the app's own
`render()` print `$_SESSION['flash']` — the flag, in the page.

## 4. Why the obvious alternatives fail (anti-cheese)

- **Application exploitation is a dead end by design.** No `unserialize`
  (the `case` cookie is plain base64 and is only ever echoed through
  `htmlspecialchars`), no file upload, no include, no SQL. The app is
  two clean files. Time spent here is time not spent reading the version
  header.
- **No `/credits`, no handout.** The runtime manifest used to exist;
  it's gone precisely because it pointed at `session.upload_progress`.
  The version must come from `X-Powered-By` like on a real target.
- **`Content-Length` bodies don't shape the heap.** Send the 30MB body
  with a declared length and `post_max_size=8M` discards it before the
  parser runs. The chunked framing is not optional — it *is* the
  primitive.
- **All four requests must hit one worker.** Any other deployment (or
  a player's own load balancer assumptions) loses the dangling pointers
  between requests. On this challenge `ServerLimit 1` guarantees it; on
  a stock 150-worker target the reference's 149-connection pinning dance
  is required.
- **Worker restarts reset everything.** A crashed chain leaves a fresh
  child with new mappings — the leak must be re-done, offsets can't be
  reused across attempts. The solver retries the *whole* chain, and
  validates each leak with the delta band before spending A2/B2 on it.
- **A too-large read window kills the worker.** The stale id sits 24
  bytes short of a 2MiB chunk boundary here; the reference's 800KB read
  (`0xC8000`) overruns it and SIGSEGVs on kernels where the neighbouring
  chunk isn't mapped. The solver uses 512KB (`0x80000`), which still
  covers the HashTable hole.
- **A `0x7f` pointer filter silently fails off-native-Linux.** WSL2 /
  Docker-Desktop kernels map heap and libphp at `0x7a..–0x7e..`; a
  `0x7F0000000000` floor drops every pointer and the leak looks empty.
  The solver's floor is `0x100000000000`.
- **No egress to exfil through.** DNS/HTTP callbacks are denied
  (firewall); the 200-byte carrier can't hold a reverse shell anyway.
  The session-file round-trip is the intended path — and it doubles as a
  nice proof that RCE actually happened *inside* the app's world.
- **Warm-up requests break the chain** on this app. A `GET /index.php`
  before A1 runs a real `session_start()` and a ~3KB render, shifting the
  ZendMM free lists so the dangling id misses the forged header. The
  solver sends no warm-up at all; `ServerLimit 1` makes it unnecessary.

## 5. Difficulty knobs

| Knob | Easier | Harder |
| --- | --- | --- |
| `/credits` manifest | list the runtime stack (removed) | shipped: fingerprint the version from `X-Powered-By` |
| Warm-up page | an `echo "OK"` target (reference) | shipped: a themed app whose per-request allocations break naive ports of the public chain |
| Worker pinning | `ServerLimit 1` (shipped) | stock `MaxRequestWorkers=150`: solver must pin workers with holder connections |
| Read window | ship `0x80000` (shipped) | let players discover the 2MiB-boundary overrun themselves |
| Exfil | `disable_functions` maze | shipped: none — the 200-byte carrier and no-egress are the real constraints |

Shipped difficulty: **hard**. The vulnerability is public, but the
reference exploit does not run unmodified against a real app: the warm-up
page, the pointer floor, and the read window all have to be re-derived,
and the exfil needs the session-file trick. That gap — public chain to
working solve on an unmodified, realistic target — is the challenge.

## 6. Test record

| Date | Platform | Command | Result |
| --- | --- | --- | --- |
| 2026-10-30 | WSL2 amd64, Docker 29.9.2, `BIND_ADDR=0.0.0.0` compose up | `python3 solve/solve.py 127.0.0.1 32003` | **4/4**, flag in 2.8–5.5s, including one full chain after `docker restart` (fresh ASLR) |
