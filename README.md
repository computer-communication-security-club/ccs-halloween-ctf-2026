# CCS Halloween CTF 2026 🎃

This private repository contains challenge sources, real flags, and solutions. Only files explicitly listed from `dist/` are released to players.

| Document | Purpose |
| --- | --- |
| [Rules](docs/RULES.md) | Requirements for every challenge |
| [Architecture and instances](docs/ARCHITECTURE.md) | Hosting, isolation, ports, and instance lifecycle |
| [Challenge specification](docs/CHALLENGE_SPEC.md) | Directory structure and metadata |
| [Contributing](CONTRIBUTING.md) | Author workflow and review checklist |

**Every challenge is Dockerized**, including static challenges whose Dockerfile produces the handout. Remote pwn challenges use **redpwn/jail**. The default target is **Linux amd64**; authors on Apple Silicon should build with `--platform linux/amd64`. Pwn must also be tested on a native amd64 Linux host with jail support.

```
.
├── challenges/
│   ├── pwn/
│   ├── web/
│   ├── crypto/
│   ├── rev/
│   ├── forensics/
│   ├── misc/
│   └── osint/
├── docs/
├── tools/ctf.py                # check, dist, test, changed
├── .github/                    # CI workflow and PR template
├── CONTRIBUTING.md
└── README.md
```

## Start a challenge

Create `challenges/<category>/<slug>/` with the files in the [challenge specification](docs/CHALLENGE_SPEC.md). [Piggyback](challenges/web/piggyback/) is a complete hosted challenge to compare against: multi-service Compose, one root `Dockerfile` with targets, hardening, and an automated solver.

The original reference examples were removed, but they are still in git history at commit `287ebbd`. Copy them as a starting point if they help:

| Example | Pattern | Restore with |
| --- | --- | --- |
| Pumpkin Patch | pwn under redpwn/jail; exported binary, libc, and loader | `git archive 287ebbd challenges/pwn/pumpkin-patch \| tar -x` |

Rename the restored directory, then change its name, flag, port, sources, solver, and metadata.

```sh
uv run tools/ctf.py dist challenges/web/my-spooky-challenge    # export dist/
uv run tools/ctf.py check challenges/web/my-spooky-challenge   # rules, ports, leak scan
uv run tools/ctf.py test challenges/web/my-spooky-challenge    # compose up, solve, compare, down
```

## Tooling

You need [Docker](https://docs.docker.com/get-docker/) and [uv](https://docs.astral.sh/uv/). [`tools/ctf.py`](tools/ctf.py) and every `solve/solve.py` declare their Python dependencies inline ([PEP 723](https://peps.python.org/pep-0723/)), so `uv run` installs them; there is no virtualenv or requirements file to manage.

| Command | What it does |
| --- | --- |
| `uv run tools/ctf.py check [CHALLENGE ...]` | Checks structure, metadata, flag format, scoring, ports, Compose hardening, and scans `dist/` (including archives) for the real flag. No arguments checks everything. |
| `uv run tools/ctf.py dist CHALLENGE` | Exports `dist/` from the Dockerfile's `dist` stage and removes stale files. |
| `uv run tools/ctf.py dist --verify CHALLENGE` | Fails if the committed `dist/` differs from a fresh build. |
| `uv run tools/ctf.py test CHALLENGE` | Static: runs the solver. Hosted: `compose up --wait`, runs the solver against it, compares with `flag.txt`, then `down --volumes`. Never prints the flag. |

[GitHub Actions](.github/workflows/challenges.yml) runs `check` on every push and pull request, and `dist --verify` plus `test` for each changed challenge. Pwn needs a runner that can run privileged redpwn/jail; see the comment in the workflow. CI does not replace the independent test-solve or a manual look at `dist/`.

Flag format: **`ccsCTF{...}`**.
