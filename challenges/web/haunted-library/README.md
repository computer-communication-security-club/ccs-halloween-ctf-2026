# Haunted Library — author notes (private)

Example **web** challenge: a small Flask app served by gunicorn as a non-root user. Replace or substantially change it before using it in the event.

| | |
| --- | --- |
| Difficulty | easy |
| Deployment | `shared`, one stateless Compose project |
| Player endpoint | `http://CHALLENGE_HOST:32001` (container port 8080) |
| Handout | `dist/`: app source, player `Dockerfile`, fake flag |
| Solver | `solve/solve.py HOST PORT`, standard library only |
| Writeup | [`solve/WRITEUP.md`](solve/WRITEUP.md) |

## Build and test

From the repository root:

```sh
uv run tools/ctf.py dist challenges/web/haunted-library     # export dist/
uv run tools/ctf.py check challenges/web/haunted-library    # metadata, ports, leak scan
uv run tools/ctf.py test challenges/web/haunted-library     # compose up, solve, compare, down
```

The same steps by hand, from this directory:

```sh
docker build --platform linux/amd64 --target dist --output type=local,dest=dist .
docker compose up -d --build --wait
uv run solve/solve.py 127.0.0.1 32001
docker compose down --volumes --remove-orphans
```

## Runtime

- Python 3.12.8 slim-bookworm, pinned by digest; dependencies pinned in `src/requirements.txt`.
- Runs as `10001:10001`, read-only root filesystem, 16 MB `/tmp` tmpfs, all capabilities dropped, `no-new-privileges`.
- Limits: 0.25 CPU, 64 MB memory, 64 PIDs. Healthcheck: `GET /` within 2 s.
- No database, bot, volume, or outbound network dependency. Reset by recreating the container.

## Test record

| Date | Platform | Command | Result |
| --- | --- | --- | --- |
| 2026-10-26 | macOS M2, Docker Desktop 29.9.2 (amd64 emulation) | `uv run tools/ctf.py test` | PASS |
