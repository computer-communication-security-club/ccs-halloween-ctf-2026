# The Cursed MAYO — author notes

**Category:** crypto
**Mode:** per-team TCP service
**Solver:** automated, intended runtime well under 60 seconds
**Flag:** private `flag.txt` and the matching `challenge.yml` flag entry only

## Package contents

- `src/cursed_signer.c` — MAYO-2 signer, four-wound fault injection, forge and
  normalize helpers.
- `src/server.py` — TCP oracle, query accounting, offering verification, flag
  gate.
- `src/Makefile` — builds MAYO-C and the static handout signer.
- `src/entrypoint.sh` — creates the ephemeral keypair, then starts the server.
- `src/handout/` — player README and ritual client copied into `dist/`.
- `Dockerfile` — `build` stage, `dist` handout export, private `runtime` image.
- `docker-compose.yml` — hardened per-team service.
- `solve/solve.py` — intended solver; reads only the handout binary and the
  live oracle, never `flag.txt`.
- `solve/WRITEUP.md` — full solution and fault derivation.

## Fault model

MAYO-2 uses `n=81`, `m=64`, `o=17`, `v=64`, `k=4`, `q=16`. The secret oil basis
is `O` in `F_16^{64x17}`.

For a ritual with candle `c` and sigil offsets `(3,21,42,60)`, the signer
overwrites four nibbles:

```
p_i = (c + delta_i) mod 64
s_i[p_i] = lambda_q * (O[p_i] . x_i)
```

where `lambda_q` is a fresh, nonzero, unexposed field element shared by the four
wounds of that ritual. The player sees `y_i = lambda_q * (O[p_i] . x_i)` and the
public `x_i` values. Pairing leaks within a ritual removes `lambda_q` and gives
linear equations in the 1088 entries of `O`. The system has a one-dimensional
nullspace over `F_16`; the public key resolves the remaining scalar. The solver
uses 384 of the 600 rituals.

## Build and test

From the repository root:

```sh
uv run tools/ctf.py check challenges/crypto/the-cursed-mayo
uv run tools/ctf.py dist challenges/crypto/the-cursed-mayo
uv run tools/ctf.py test challenges/crypto/the-cursed-mayo
```

The Docker build uses the repository's pinned Debian bookworm-slim digest and
the vendored MAYO-C source. `dist/` contains exactly the three player files
listed in `challenge.yml`.

## Runtime contract

- One published TCP port, default `33001`, internal `1337`.
- Per-team instance because the query counter is global to an instance.
- Keypair and counter live in `/tmp/cursed-data` on a size-limited tmpfs; no
  named volumes. Container recreation resets both.
- The runtime image carries the real flag at `/flag.txt`; `dist/` contains no
  flag, solver, writeup, or author notes.
- Suggested TTL: 30 minutes. Startup after build is a few seconds.
- No outbound dependency; the signer is fully local.

## Resource notes

The signer process is spawned once per ritual. 384 rituals complete in roughly
25-35 seconds on the development host; the solver's GF(2) elimination adds a
few seconds. Compose limits are 1.0 CPU, 512 MiB, and 128 PIDs. The solver is
non-destructive and reads its handout binary from `dist/` relative to
`__file__`.

## Verification status

Measured on Linux amd64 with Docker Compose:

- `ctf.py check`: pass.
- `ctf.py dist`: handout contains README, cursed_signer, ritual_client.
- `ctf.py dist --verify`: committed handout matches a fresh no-cache build.
- `ctf.py test`: pass; solver prints the flag and matches `flag.txt`.
- Per-team test: two Compose projects on different ports; instance A solved,
  A reset with `down --volumes`, instance B still solved.
- Full solve uses 384/600 rituals and produces a valid forged offering.

## Risks and notes

- The challenge is intentionally per-team; sharing an instance would share the
  query budget.
- Recreating the container invalidates player progress by design.
- The fault is synthetic and does not claim a weakness in real MAYO.
- The handout binary is unstripped enough for reverse engineering; it contains
  the sigil map but no key material or flag.
