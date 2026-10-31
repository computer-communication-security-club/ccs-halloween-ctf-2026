# Challenge package specification

## Directory structure

```text
challenges/<category>/<slug>/
├── challenge.yml         # player metadata and accepted flags (private until release)
├── kona.yaml             # generated Konata / rCTF sync config; flags read from flag.txt
├── deployment.yml        # organizer-only runtime/instance contract
├── README.md             # private author notes, exact commands, dependencies, risks
├── Dockerfile            # required for every category; dist export and/or service
├── .dockerignore         # exclude solve/, .git, host-generated artifacts
├── docker-compose.yml    # hosted challenges only
├── flag.txt              # real flag, one line; a final newline is allowed
├── src/                  # service source, generator, fixed inputs
├── dist/                 # committed player downloads; may be empty for black-box web
└── solve/
    ├── solve.py          # prints the recovered flag; never reads private flag.txt
    └── WRITEUP.md        # intended solution and relevant technical assumptions
```

Manual-only challenges may omit `solve.py` with explicit organizer approval and `solver: manual` in `deployment.yml`. Put the complete procedure in `WRITEUP.md`. Everything outside `dist/` is private. Generated pwn binaries and libraries must be built and committed before release; the source examples include the build recipe rather than fabricated binary artifacts.

Externally hosted challenges use `mode: external` and `solver: external` in
`deployment.yml`. They require `challenge.yml`, `flag.txt`, `README.md`, and a
generated `kona.yaml`, but may omit Docker files and `solve/`. Set `protocol`
to `http` or `https`, and `service`, both ports, and `ttl_minutes` to null.
Keep the other deployment fields to document external ownership and readiness.
Their `connection_info` is an absolute HTTP(S) URL matching `protocol`, without
credentials or template placeholders. Konata preserves that URL in the player
description. Metadata, flag, and any committed handout checks still apply;
CI excludes these entries from the local build/solver matrix, and direct `dist`
and `test` commands report a skip. External availability and solve verification
remain the organizer's responsibility and should be documented in `README.md`.

## `challenge.yml`

Use the repository's authoring schema below. It retains the existing metadata
layout; `tools/konata.py` converts it into native Konata rCTF configuration.
Do not import `challenge.yml` directly into rCTF. Example:

```yaml
name: My Spooky Challenge
author: your-handle
category: web
connection_info: http://CHALLENGE_HOST:32001
description: |
  The librarian filed a secret outside the public collection.
  Can you find it?
type: dynamic
value: 1000
extra:
  initial: 1000
  minimum: 100
flags:
  - type: static
    content: ccsCTF{replace_with_your_real_flag}
    data: case_sensitive
tags:
  - easy
files: []
hints: []
state: hidden
```

`value` matches `extra.initial`; `extra.initial` and `extra.minimum` set the rCTF
point range. `type: dynamic` maps to rCTF `scoring.kind: decay`, whose curve is
selected by the server's `scoreProvider` (see [Konata setup](KONATA.md)). Do not
set a per-challenge `decay` or `function`. Exactly one tag is a difficulty.
`author` must be a plain-text handle, e.g. `handle`; rCTF displays this field
as plain text. Put author profile links in the Markdown description if needed.
Omit `connection_info` for static challenges. For TCP use
`nc CHALLENGE_HOST <port>`. Minecraft deployments (`service: minecraft`) use
`CHALLENGE_HOST:<port>` so players can copy the address into the Minecraft
client. Plain HTTP and direct ports are the default.

After changing metadata, run `uv run tools/konata.py --write` and commit the generated
`kona.yaml`. [Konata](KONATA.md) syncs these generated configs to rCTF; `challenge.yml`
remains the canonical authoring format. The generator currently rejects regex
flags and nonempty hints rather than silently changing their semantics.

`files` lists explicit paths under `dist/`, e.g. `dist/chall`, `dist/libc.so.6`, `dist/ld-linux-x86-64.so.2`. Files aren't recursively uploaded just because the directory exists. Default to hidden; infra releases the challenge after endpoint and flag verification.

For an organizer-approved scheduled release, set `state: visible` and a
timezone-qualified `release_time`, for example `"2026-10-31T18:00:00+08:00"`.
The generator writes Konata's `hidden: false` and `release_time`; rCTF keeps the
challenge unavailable until that timestamp. Leaving `state: hidden` prevents
release even after the timestamp. Regenerate `kona.yaml` after changing either.

Use one static, case-sensitive flag. The generated rCTF `flags/static` entry
reads its value from `flag.txt`. rCTF also has a
[regex flag provider](https://rctf.osec.io/providers/flags/), but using it here
requires extending the generator and validation first. A regex does not bind
a flag to a team or create an instance. Never copy another event's flag prefix.

## `deployment.yml`

This is our private author/infra contract, separate from rCTF metadata. It is documentation, not an executable launcher schema.

```yaml
mode: shared                 # static | shared | per-team | external
protocol: http               # none | tcp | http | https
architecture: linux/amd64
service: chall               # Compose service; null for static
internal_port: 8080          # null for static
public_port: 32001           # default only; null for static
solver: automated           # automated | manual
readiness: GET / returns 200
reset: docker compose down --volumes --remove-orphans; docker compose up -d
state: No persistent state; /tmp is discarded on container recreation.
ttl_minutes: null            # 30 for per-team unless infra agrees otherwise
egress: none
notes: No database, bot, or external service dependency.
```

For per-team mode also list startup timeout, maximum simultaneous instances requested, volume ownership/reset effects, any destructive solve behavior, and required endpoint injection. Infra confirms the cap and lifecycle before deployment. `mode: static` uses `protocol: none` and null runtime fields.

## `docker-compose.yml`

A lightweight web pattern, with one published port:

```yaml
services:
  chall:
    build: .
    platform: linux/amd64
    ports:
      - "${BIND_ADDR:-127.0.0.1}:${PUBLIC_PORT:-32001}:8080"
    restart: unless-stopped
    user: '10001:10001'
    read_only: true
    tmpfs:
      - /tmp:size=16m,mode=1777
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    cpus: 0.25
    mem_limit: 64m
    pids_limit: 64
    logging:
      driver: json-file
      options:
        max-size: 5m
        max-file: '2'
```

Challenges build locally. Infra may substitute a private registry `image: ghcr.io/<org>/<challenge>@sha256:<reviewed-digest>` for deployment. Do not use `latest` for a reviewed production image. A single-service project needs no explicit network declaration; Compose supplies a project-scoped network. Infra still enforces egress policy at the host/upstream firewall.

Pwn uses `privileged: true` for redpwn/jail, its own jail limits, and a larger container budget. Do not copy web's user, capability, no-new-privileges, or read-only settings onto jail without validating them; the outer jail process needs privileges to establish its sandbox. Extra DB/bot services have no published ports and communicate on a project-scoped internal backend network.

Flags can be copied as files into private runtime images (Piggyback copies `flag.txt` into its backend image). If a challenge instead accepts an environment `FLAG`, document that contract, provide only a fake local default, and have infra inject the real value. Avoid `$` in flag values where Compose interpolation could alter them; use a mounted secret or explicit escaping when necessary. Dynamic per-team flags need a checker design as well as injection.

## Build and solver contract

From the repository root:

```sh
uv run tools/ctf.py dist challenges/<category>/<slug>    # export dist/
uv run tools/ctf.py check challenges/<category>/<slug>   # static rules
uv run tools/ctf.py test challenges/<category>/<slug>    # solve against a fresh deployment
```

`test` is equivalent to, from the challenge directory:

```sh
docker compose up -d --build --wait      # hosted challenges only
uv run solve/solve.py 127.0.0.1 32001    # static: uv run solve/solve.py
docker compose down --volumes --remove-orphans
```

Solvers finish in under 60 seconds, print the recovered flag to stdout, and exit zero on success; failure must exit nonzero. They resolve input paths from `__file__`, not the caller's working directory, and use bounded network timeouts. Declare exact dependency versions in an inline script block at the top of `solve.py` so `uv run` can install them:

```python
#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["pwntools==4.14.1"]
# ///
```

Before merge, review the structure, metadata, score policy, matching flag, port allocation, limits, image digests, handout content, and actual solve results. Record what was tested in the challenge README; do not claim checks passed that did not run (for example, pwn under Docker Desktop).
