# Challenge rules

**MUST** means required before merge. **SHOULD** means explain any exception in the PR. `uv run tools/ctf.py check` and CI enforce the mechanical rules (structure, metadata, flags, ports, Compose hardening, handout leaks). Authors and reviewers remain responsible for the rest.

## 1. General

1. Every challenge MUST live in `challenges/<category>/<slug>/`. Categories: `pwn`, `web`, `crypto`, `rev`, `forensics`, `misc`, `osint`. Slugs use lowercase words separated by hyphens and are unique across the repository.
2. Every challenge MUST have a Dockerfile, including static and OSINT challenges. Hosted services MUST also have `docker-compose.yml`. No manual server setup outside Docker.
3. Every challenge MUST include metadata, deployment notes, an intended writeup, and an automated solver that prints the flag within 60 seconds. A manual-only challenge needs `solver: manual` in `deployment.yml`, a documented procedure, and organizer approval.
4. Someone other than the author MUST test-solve before freeze, using only the player description, handout, and endpoint.
5. Steps MUST be discoverable from the supplied information. Avoid guessing, unstable third-party dependencies, and challenges that require attacking other teams, infrastructure, or real external services. Archive permitted OSINT material locally and document provenance.
6. Halloween themes are encouraged. Use original or licensed assets and remove personal metadata from handouts.

## 2. Flags and handouts

1. Flags MUST match `^ccsCTF\{[A-Za-z0-9_!?@#$%^&*.\-]+\}$`. Use a long, unpredictable value.
2. The plaintext real flag MUST be stored only in private `flag.txt` and the matching `challenge.yml` flag entry in the source tree. Generated private images necessarily also contain challenge flags. Do not copy real flags into solvers, writeups, logs, public build arguments, or player Dockerfiles.
3. `dist/` MUST contain exactly the intended player handout. List every downloadable file in `challenge.yml`. No plaintext real flags, solvers, writeups, `.git`, author notes, or unrelated secrets. A static artifact may encode the real flag for recovery through the intended solution.
4. Use `ccsCTF{fake_flag_for_testing}` in player runnable packages. Inspect archives as well as loose files. Maximum handout size is 50 MB unless infra approves external hosting.
5. Static flags are the default, including for per-team instances. Dynamic flags require an agreed injection and checking design from infra.

## 3. Docker and isolation

1. All builds MUST use the challenge directory as their entire build context. Include needed inputs under `src/`; no sibling copies, host-specific paths, or secret downloads. Pin base images by SHA-256 digest and application dependencies by exact version (and hashes where supported).
2. Builds may download pinned build dependencies. An offline build is only possible if images and dependencies are already cached or vendored. For byte-identical handouts, also pin the compiler, package snapshot, timestamps, and generator seed. Record any remaining reproducibility limits.
3. Target Linux amd64 by default. Another architecture needs explicit metadata, matching handouts, and infra approval.
4. Remote services MUST have CPU, memory, and PID limits, a readiness check, and a reset procedure. Add aggregate connection limits for jail services. Limits are defaults to tune with the real solver, not a guarantee of capacity.
5. Applications MUST run as non-root with dropped capabilities, `no-new-privileges`, and a read-only filesystem where possible. Use size-limited tmpfs or project-scoped volumes for writable state.
6. No host networking, bind mounts, Docker socket, host PID namespace, fixed container names, or external shared volumes/networks. **Only redpwn/jail may use `privileged: true`**, on dedicated challenge worker VMs. Jail does not make a compromised privileged container harmless.
7. Runtime outbound traffic is denied by default. Use a project-scoped internal network for private services. Published ingress may require an edge network; infra MUST enforce and test egress filtering at the host or upstream firewall, including access to cloud metadata and management services. An ordinary bridge alone does not block egress.
8. One challenge is one Compose project. DBs and admin bots are separate services in that project and MUST NOT publish their ports. Document approved exceptions, bot destinations, and every required writable path.

## 4. Pwn and TCP services

1. Remote pwn challenges MUST use [redpwn/jail](https://github.com/redpwn/jail). Other stdin/stdout TCP challenges SHOULD use it too. Do not add xinetd, socat, or custom fork servers.
2. Compile inside Docker. Export the exact deployed binary, libc, and loader from the same runtime filesystem. If build packages update libc, export from that updated filesystem too. Do not build on the host.
3. The handout MUST include `chall`, `libc.so.6`, `ld-linux-x86-64.so.2` (for the default architecture), and a runnable Dockerfile with a fake flag. Include source unless reverse engineering is intentional.
4. Install the executable at `/srv/app/run` and the flag at `/srv/app/flag.txt`. The sandbox sees these as `/app/run` and `/app/flag.txt`, with `/app` as its working directory. Real flags MUST be world-readable inside the jail if the intended exploit reads them.
5. Set per-connection wall time, memory, PID, and CPU budgets, plus a total connection cap. Start from `JAIL_TIME=30`, `JAIL_MEM=32M`, `JAIL_PIDS=10`, `JAIL_CPU=100`, `JAIL_CONNS=32` with a container budget of 1 CPU, 512 MB and 256 PIDs, and adjust only after testing. The removed Pumpkin Patch example (commit `287ebbd`) shows the full jail pattern. `JAIL_CPU` is **milliseconds of CPU per wall second**, not a core count. Document any proof of work and teach the solver to handle it.
6. Record actual `checksec` output, overflow offset or equivalent exploit assumptions, libc origin, and the native Linux test environment in the private README. Make mitigation choices deliberate.
7. Test the official jail container on native Linux with cgroup support. Docker Desktop/emulation may build artifacts but is not sufficient evidence that nsjail works in production.

## 5. Web

1. Listen on `0.0.0.0` using a production server (gunicorn, uvicorn, nginx, or equivalent), with debug mode disabled.
2. Run the app as non-root; flag owned by root, readable as required, and unwritable by the app. Handouts use fake flags.
3. Shared state MUST be safe against interference or reliably reset. If one team can spoil another team's challenge, use per-team instances and document why.
4. Admin bots MUST be separate services. Agree bot isolation, permitted destinations, credentials, queue limits, and timeout with infra before implementation.
5. Avoid hardcoded public hosts and ports; use relative URLs where possible.

## 6. Static challenges

1. The Dockerfile MUST generate and export `dist/` through a `dist` stage. There is no always-running service or Compose requirement.
2. Commit the generated handout. Make randomness deterministic with a documented seed, or commit the exact generator inputs. Re-run the solver after every regeneration.
3. The solver MUST resolve `dist/` relative to its own location and work without network access. Dockerizing OSINT means packaging/reproducing permitted evidence, not running a server needlessly.

## 7. Ports and instances

| Category | Default shared public port range |
| --- | --- |
| pwn | 31000–31999 |
| web | 32000–32999 |
| crypto | 33000–33999 |
| rev | 34000–34999 |
| misc / forensics / osint | 35000–35999 |

Remote challenges publish exactly one player ingress port. Its default MUST be unique, in range, and match `challenge.yml`. A port outside the range needs organizer approval, recorded as `port_exception: <who approved and why>` in `deployment.yml`. Parameterize it as `${PUBLIC_PORT:-31001}` (use your own default) and its bind address as `${BIND_ADDR:-127.0.0.1}`. Local defaults bind to loopback; infra explicitly exposes production endpoints. Per-team allocated ports may use a separate infra pool and must be shown by the instancer.

Declare `mode: static`, `shared`, or `per-team` in `deployment.yml`. A jail sandbox per connection is not a persistent team instance. Per-team authors MUST complete the lifecycle and two-instance checks in [Architecture §6](ARCHITECTURE.md#6-per-team-instances).

## 8. Scoring and schedule

Exactly one difficulty tag: `baby`, `easy`, `medium`, `hard`, or `insane`. Use dynamic scoring with `initial: 1000`, `minimum: 100`, `decay: 10`, unless organizers change the event policy. Baby challenges should be solvable by a beginner in under 30 minutes; aim for at least one per category.

Rules published: **2026-10-26**. Idea deadline, merge deadline, test-solve freeze, and event time are **TBD by organizers**. After freeze, changes require organizer approval and another solve check. Keep CTFd challenges hidden until release.
