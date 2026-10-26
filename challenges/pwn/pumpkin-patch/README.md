# Pumpkin Patch — author notes (private)

Example **pwn** challenge: a C binary served through [redpwn/jail](https://github.com/redpwn/jail), with a fresh sandbox for each TCP connection. Replace or substantially change it before using it in the event.

| | |
| --- | --- |
| Difficulty | easy |
| Deployment | `shared`, privileged jail on a dedicated native Linux amd64 VM |
| Player endpoint | `nc CHALLENGE_HOST 31001` (container port 5000) |
| Handout | `dist/`: `chall`, `chall.c`, `libc.so.6`, `ld-linux-x86-64.so.2`, player `Dockerfile`, fake flag |
| Solver | `solve/solve.py HOST PORT`, needs `pwntools==4.14.1` (declared inline; `uv run` installs it) |
| Writeup | [`solve/WRITEUP.md`](solve/WRITEUP.md) |

## Build and test

From the repository root:

```sh
uv run tools/ctf.py dist challenges/pwn/pumpkin-patch       # compile and export dist/
uv run tools/ctf.py check challenges/pwn/pumpkin-patch
uv run tools/ctf.py test challenges/pwn/pumpkin-patch       # native Linux amd64 only
```

By hand, from this directory:

```sh
docker build --platform linux/amd64 --target dist --output type=local,dest=dist .
docker compose up -d --build --wait
uv run solve/solve.py 127.0.0.1 31001
docker compose down --volumes --remove-orphans
```

Docker Desktop on macOS can build `dist/` but cannot run the jail: the container reports `init seccomp: operation canceled` and never becomes healthy. Test the service on native Linux amd64 with cgroup support (RULES §4.7). On Ubuntu 23.10+ hosts, also set `kernel.apparmor_restrict_unprivileged_userns=0` ([Architecture §3](../../../docs/ARCHITECTURE.md#3-docker-packaging)).

## Binary and runtime

- Built in `ubuntu:24.04` (pinned by digest) with `gcc -O0 -fno-stack-protector -no-pie -Wl,-z,relro,-z,now`. The handout `libc.so.6` and loader are exported from the same filesystem copied into `/srv`.
- `apt-get install` pulls the current Ubuntu packages, so a rebuild can change libc. `ctf.py dist --verify` (run in CI) fails if the handout no longer matches a fresh build. Pin the reviewed runtime image by digest for production.
- Jail limits: `JAIL_TIME=30`, `JAIL_MEM=32M`, `JAIL_PIDS=10`, `JAIL_CPU=100` (ms of CPU per second), `JAIL_CONNS=32`. Container limits: 1 CPU, 512 MB, 256 PIDs.

`pwn checksec dist/chall` (pwntools 4.14.1):

```text
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

## Test record

| Date | Platform | Command | Result |
| --- | --- | --- | --- |
| 2026-10-26 | macOS M2, Docker Desktop 29.9.2 | `uv run tools/ctf.py dist` | dist/ built |
| 2026-10-26 | macOS M2, Docker Desktop 29.9.2 | `uv run tools/ctf.py test` | Not valid: jail seccomp unsupported under Docker Desktop |
| — | Native Linux amd64 | `uv run tools/ctf.py test` | **Pending** |
