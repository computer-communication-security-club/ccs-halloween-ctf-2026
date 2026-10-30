# Shelloween — author notes (private)

| | |
| --- | --- |
| Deployment | `shared`, one Compose project, one service (`chall`) |
| Player endpoint | `http://CHALLENGE_HOST:32001`: plain HTTP Express API |
| Handout | None (black-box); `dist/` is intentionally empty |
| Solver | `solve/solve.py HOST PORT` |

```
 player ──HTTP──▶ chall  (Node 24 / Express "shell market" API, port 8000)
                    │  express.json()  (inflate: true)
                    ▼
                 body-parser  →  Content-Encoding: br  →  zlib Brotli decoder  ← vulnerable
                    │  RCE as `node`
                    ▼
                 cat /flag.txt   (0444, world-readable in the image)
```

## Vulnerability

Fictional-for-the-event **CVE-2026-111497 / "HTTP2Shell"**: the bundled Brotli
reference decoder mishandles the invalid block-switch case, and `body-parser`
feeds attacker-controlled `Content-Encoding: br` bodies straight into
`zlib.createBrotliDecompress()`. `express.json()` enables request inflation by
default, so every JSON endpoint (e.g. `POST /api/orders`) is a trigger with no
route change. See the header comment in [`Dockerfile`](Dockerfile) for the
exact decode path and upstream references.

The exploit is probabilistic (ASLR). A missed guess crashes the worker; the
crash-restart supervisor in the Dockerfile `CMD` brings it back with a fresh
layout and keeps the instance available after DoS-ish payloads. `UV_THREADPOOL_SIZE=1`
pins the single libuv worker the heap profile assumes — keep it.

## Build and test

From the repository root once this lives at `challenges/web/shelloween/`:

```sh
uv run tools/ctf.py check challenges/web/shelloween
uv run tools/ctf.py test  challenges/web/shelloween     # compose up, solve, compare, down
```

By hand, from this directory:

```sh
docker compose up -d --build --wait
uv run solve/solve.py 127.0.0.1 32001
docker compose down --volumes --remove-orphans
```

The vuln is amd64-specific heap behaviour; build and test on **native linux/amd64**
(`--platform linux/amd64`). Apple Silicon emulation can build the image but is not
evidence the RCE lands in production.
