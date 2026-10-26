# Piggyback — author notes (private)

**web / TLS, hard.** By deprrous. The player-facing text is in [`challenge.yml`](challenge.yml); the writeup, anti-cheese reasoning, difficulty knobs and vulnerability map are in [`solve/WRITEUP.md`](solve/WRITEUP.md) (spoilers).

| | |
| --- | --- |
| Deployment | `shared`, one Compose project with five services |
| Player endpoint | `https://CHALLENGE_HOST:32002`: TLS 1.3 only, self-signed, SNI ignored |
| Handout | None (black-box); `dist/` is intentionally empty |
| Solver | `solve/solve.py HOST PORT`, standard library + **OpenSSL 3+** `openssl` binary |

```text
 player ──TLS 1.3 0-RTT──▶  lb (haproxy, round-robin, L4 pass-through)
                               ├──▶ front1  (edge node A, 0-RTT on)
                               └──▶ front2  (edge node B, 0-RTT on)
                                         │  identical image, shared ticket key
                                         ▼
                                      backend  (HTTP/1.1, keep-alive; internal network only)
```

## Build and test

From the repository root:

```sh
uv run tools/ctf.py check challenges/web/piggyback
uv run tools/ctf.py test challenges/web/piggyback     # compose up, solve, compare, down
```

By hand, from this directory:

```sh
docker compose up -d --build --wait
uv run solve/solve.py 127.0.0.1 32002
docker compose down --volumes --remove-orphans
```

The solver drives `openssl s_client -early_data`. macOS ships LibreSSL as `/usr/bin/openssl`, which lacks it: `brew install openssl@3` and put Homebrew's `openssl` first on `PATH`.

## Operator notes

- **Only `lb` is published.** `front1`, `front2` and `backend` use `expose:`, never `ports:`. If a player can reach one edge node directly they can pin it, and a chunk of the challenge evaporates.
- `backend` sits on an `internal: true` network shared only with the fronts. `certgen` has no network.
- Promotion state is in memory, keyed by each player's own `X-Token`, so players never collide; a `backend` restart makes everyone redo the ~5-second solve.
- `certgen` runs once and is idempotent: a plain restart keeps the cert and session-ticket key (STEK), so tickets players already hold keep working. `docker compose down --volumes` wipes promotion state and rotates the STEK.
- The flag is baked into the `backend` image from `flag.txt` and served from `/app/flag.txt`.
- Every service runs as non-root (`10001`, or `haproxy` for lb) with a read-only root filesystem, all capabilities dropped and `no-new-privileges`.

## Files

```text
Dockerfile                 one build context; targets certgen, backend, front, lb (+ empty dist)
docker-compose.yml         certgen + backend + front1 + front2 + lb
src/certgen/gen-certs.sh   self-signed cert + shared 80-byte ticket key, idempotent
src/front/front.c          edge proxy: TLS termination, 0-RTT, replay cache
src/backend/main.go        origin app server
src/haproxy/haproxy.cfg    round-robin TCP load balancer (re-resolves on restart)
solve/solve.py             reference exploit (drives openssl -early_data)
solve/WRITEUP.md           writeup + difficulty knobs + vuln map (SPOILERS)
```

## Changes from the first push

Moved from `web/piggyback/` to `challenges/web/piggyback/` and fitted to [the rules](../../../docs/RULES.md):

- **New flag.** The original was hardcoded in `docker-compose.yml` and is in git history, so it is retired. The flag now lives only in `flag.txt` and `challenge.yml`.
- Port 443 and `piggyback.sict-ccs.club` → `${BIND_ADDR:-127.0.0.1}:${PUBLIC_PORT:-32002}`. Challenges have no domains; players connect by IP.
- Four per-service Dockerfiles → one root `Dockerfile` with targets; base images pinned by digest.
- The HAProxy config is baked into the `lb` image instead of bind-mounted; HAProxy listens on 8443 inside.
- Added non-root users, CPU/memory/PID limits, dropped capabilities, read-only filesystems, an internal backend network, and log rotation.
- `solver/` → `solve/`; the solver now takes `HOST PORT`. `SOLUTION.md` → `solve/WRITEUP.md`. The Compose `solver` service and the certbot instructions were removed.

## Test record

| Date | Platform | Command | Result |
| --- | --- | --- | --- |
| 2026-10-26 | macOS M2, Docker Desktop 29.9.2, OpenSSL 4.0.3 | Original layout (arm64), `solve.py` | PASS (baseline) |
| 2026-10-26 | macOS M2, Docker Desktop 29.9.2 (amd64 emulation), OpenSSL 4.0.3 | `uv run tools/ctf.py test` (new layout, new flag) | PASS |
