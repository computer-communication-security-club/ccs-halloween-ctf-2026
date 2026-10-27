# DEAD SIGNAL (rev) — private author notes

> Everything outside `dist/` is private. The real flag lives only in `flag.txt`
> and the `challenge.yml` flag entry (repo rule 2.2) — it is intentionally not
> repeated in this README.

## What players get

`dist/dead_signal` — a stripped, optimized x86_64 ELF (C, glibc) presenting a
satellite recovery terminal that asks for a 24-character `[A-Z0-9]`
authentication token. The correct token is unique; the binary validates it
with a five-stage bijective transform and then derives the flag key from the
*supplied* token (patching the check cannot reveal the flag). Full algorithm
details are in `solve/WRITEUP.md`.

| | |
| --- | --- |
| Category / slug | `rev` / `dead-signal` |
| Mode | static (no service, no ports) |
| Difficulty | medium-hard (tagged `hard`) |
| Intended solve time | 45–90 min human; 20–45 min with AI tooling |
| Correct token | `QCDP59YT5IDGEKS9ZER5DYFW` |
| Flag | in `flag.txt` / `challenge.yml` only |

## Sources

- `src/dead_signal.c` — challenge source (staged validation + ARX key
  derivation + flag release).
- `src/dsig_consts.h` — layout of the magic-tagged constant block embedded in
  `.rodata` (`DSIGCONSTv1`, 312 bytes). This block is the intended RE entry
  point.
- `src/generated_constants.h` — committed generator output (the exact build
  input; contains the flag **ciphertext** and the transformed target, never the
  flag or token in plaintext).
- `src/gen_constants.py` — forward algorithm + ARX_HASH + header generator.
- `src/build.sh` — local organizer rebuild (custom flag/token via env).
- `src/tests/` — QA suite: `run_tests.py` (22 automated checks incl. real
  binary-patch PoCs), `blind_solver.py` (independent solver written from
  disassembly only), `solver.py` (organizer solver), `clean_ubuntu_test.sh`
  (clean-Ubuntu container test), and `token.txt` (the correct token for the
  committed constants — private, used by the QA suite).
- `src/hints.md` — three progressive hints for organizers to release manually.

## Rebuilding the handout

The build is deterministic: `src/generated_constants.h` is committed, so the
Docker build only compiles + strips. From the repository root:

```sh
uv run tools/ctf.py dist challenges/rev/dead-signal          # export dist/
uv run tools/ctf.py dist --verify challenges/rev/dead-signal # must match
```

To regenerate constants (new token / new flag), run `src/gen_constants.py`
(or `src/build.sh`) locally, commit the new `src/generated_constants.h`, then
re-export `dist/`. Toolchain: debian bookworm-slim, gcc 12 (`gcc` +
`libc6-dev`), pinned base image digest `sha256:7ff6ba31…` (same digest as
`challenges/web/piggyback`).

Reproducibility: byte-identical handouts are produced by the pinned image +
committed generator output + fixed compile flags. Recorded limits: none —
no timestamps, no randomness in the build.

## Validation performed (this branch)

```sh
uv run tools/ctf.py dist challenges/rev/dead-signal
uv run tools/ctf.py check challenges/rev/dead-signal
uv run tools/ctf.py dist --verify challenges/rev/dead-signal
uv run tools/ctf.py test challenges/rev/dead-signal
```

Also run locally by the author: the 22-check `src/tests/run_tests.py` suite
(correct/incorrect tokens, invalid input safety, solver independence via
rebuilt binaries, plaintext leak scans, forced-success build AND real NOP
patch of the acceptance branch — both fail to decrypt with a wrong token,
bijectivity/uniqueness proof), the clean-Ubuntu container test, and a
120-case ASan/UBSan fuzz. See `solve/WRITEUP.md` §7 for the summary.

## Risks / notes

- **AI solvability:** this challenge is not AI-proof. An agent with Ghidra can
  locate the constant block in minutes (the `DSIGCONSTv1` marker is
  deliberate — it is the map, not the answer). The genuine difficulty is the
  inversion: cross-dword chain direction, modular inverse of odd multipliers
  mod 2^32, and replaying the rolling state with the *recovered* byte values.
  A wrong inverse fails loudly (round-trip mismatch), so solvers self-correct.
- **No artificial obstacles:** no anti-debug, no sleeps, no VM tricks. The
  challenge is hard because of its algorithm.
- **Leak surface:** the binary contains no plaintext flag/token (checked);
  the only player-visible strings are the terminal UI and the constant-block
  marker. `dist/` contains only the handout files listed in `challenge.yml`.
- Independent test-solve before freeze still required per CONTRIBUTING
  (someone other than `bg0d-glitch` using only the description + handout).
