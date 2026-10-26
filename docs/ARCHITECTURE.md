# Architecture and instances

The baseline is a small set of Linux amd64 challenge VMs running Docker Engine and Compose. CTFd handles descriptions, handouts, scoring, and submissions separately. There is **no Traefik, reverse proxy, Kubernetes, or instancer dependency** in the starter architecture.

```text
Players ── HTTPS ──> CTFd (separate platform)
                       ├── challenge.yml: descriptions and accepted flags
                       └── dist/: downloadable files
Players ── TCP :31001 ──> challenge VM ──> redpwn/jail ──> sandbox per connection
Players ── HTTP :32001 ─> challenge VM ──> non-root web application
Private repository ── build/review ──> private images + one Compose project/challenge
Static challenge ── Docker build ──> handout only; no hosted container
```

## 1. Ownership and deployment boundary

Authors supply self-contained Docker builds, Compose for hosted services, metadata, handouts, deployment requirements, and solvers. Reviewers test-solve and inspect the package. Infra owns VMs, firewall rules, any private registry, CTFd publication, resets, capacity, and uptime monitoring. Nothing here automatically publishes or deploys a challenge.

Keep the scoreboard and its credentials off challenge hosts. Put privileged pwn containers on dedicated worker VMs where practical. Jail is useful process isolation; the VM remains the boundary for a host or privileged-container compromise. Do not mount repository directories into production containers.

## 2. Three deployment modes

| Mode in `deployment.yml` | Runtime | Appropriate for |
| --- | --- | --- |
| `static` | None after handout generation | Rev, offline crypto, forensics, archived OSINT |
| `shared` | One Compose project per challenge | Stateless web, TCP services with per-connection jail |
| `per-team` | Independent Compose project per team | Stateful services where teams can corrupt or spoil each other |

Default to shared when safe. A redpwn connection gets a fresh process/sandbox, not a persistent team environment. Reconnects discard that connection's transient state. A web worker restart does not reset a database volume.

## 3. Docker packaging

Build with the challenge directory as context. The examples use a `dist` stage to export player files and a final runtime stage for hosted services. Never publish the private runtime image as a player download: it contains the real flag.

Pwn uses a pinned userland, a compiler stage, and a runtime filesystem derived from that same userland. The exported libc/loader must be the ones actually copied into `/srv`. `redpwn/jail` exposes stdin/stdout on TCP port 5000 and starts `/app/run` per connection. See the [upstream author guide](https://github.com/redpwn/jail/blob/main/docs/challenge-authors.md) and [limit reference](https://github.com/redpwn/jail#configuration-reference).

Builds can need network access for dependencies. Pin package versions and use package snapshots or vendoring when exact reconstruction matters. Save the reviewed private runtime image by digest for production rather than silently rebuilding against changed package repositories.

## 4. Lightweight networking

Web endpoints use **plain HTTP on an assigned port**, e.g. `http://CHALLENGE_HOST:32001`. TCP challenges use `nc CHALLENGE_HOST 31001`. Do not advertise HTTPS when there is no TLS endpoint. `CHALLENGE_HOST` is a documentation placeholder: infra replaces it in the release metadata before syncing CTFd.

Only CTFd gets a domain: **`ctf.sict-ccs.club`**, with HTTPS. Challenges have no domain. `CHALLENGE_HOST` is the challenge server's public IP, so reserve a static IP before syncing CTFd. Keeping challenges off `sict-ccs.club` also means challenge pages are never same-site with CTFd, so a web challenge cannot set cookies for, or send same-site requests to, the scoreboard. If you use Cloudflare, proxy only the CTFd record; challenge traffic goes directly to the IP.

Local Compose files bind published ports to `127.0.0.1` by default. Infra sets `BIND_ADDR=0.0.0.0` or a dedicated challenge-facing IP when publishing to players. Expose only the app ingress port; database and bot ports stay private. This pattern requires no domain per challenge and no shared proxy network.

A single app can use its ordinary project-scoped bridge for ingress. Multi-service challenges should add an `internal: true` backend network, with only the ingress app on both networks. Ordinary bridges allow outbound traffic; an internal network alone is not a complete policy for an app also attached to an ingress bridge. Infra must enforce runtime egress filtering at the Docker host or upstream firewall. Test external access, cloud metadata, platform access, and cross-challenge reachability from deployed containers. See [Docker bridge networking](https://docs.docker.com/engine/network/drivers/bridge/).

If HTTPS becomes a challenge requirement, infra can add a TLS endpoint later. Avoid introducing a reverse proxy just to run the examples.

## 5. Shared deployment

Run from the challenge directory, using a unique project name:

```sh
BIND_ADDR=0.0.0.0 docker compose -p ccs-pumpkin-patch up -d --build
docker compose -p ccs-pumpkin-patch ps
docker compose -p ccs-pumpkin-patch logs --tail=50
uv run solve/solve.py 127.0.0.1 31001
```

Check the solver from an external player network too. Start a TCP socket check before a solve if needed; a listening socket alone does not demonstrate challenge health. For pwn, confirm that two connections have independent files/processes and that jail timeouts work.

Reset with `docker compose -p ccs-pumpkin-patch down --volumes --remove-orphans`, then start again with the same project name. This deletes that project's data: authors must list any volumes and reset effects in `deployment.yml`. No source-host bind mounts or externally named persistent resources are allowed in challenge packages.

CTFd metadata uses the [ctfcli format](https://github.com/CTFd/ctfcli/blob/master/ctfcli/spec/challenge-example.yml). Infra replaces endpoint placeholders in a release copy, imports/syncs it with their configured CTFd tooling, checks scoring and flags, then makes the challenge visible. `deployment.yml` is an organizer document, not an instancer configuration or a CTFd plugin.

## 6. Per-team instances

Per-team orchestration is **not implemented** in this repository. For a small event, infra may manage instances manually; an authenticated launcher can be added only if demand requires it. Authors still make the package compatible now:

- No `container_name`, fixed network/volume names, or host mounts. Let the Compose project scope resources.
- Parameterize the public port and bind address. Accept the host/port assigned by infra, and avoid hardcoded origins in the application.
- Keep all team state within the project. Define startup readiness, destructive reset behavior, TTL, and resource needs in `deployment.yml`.
- Use the same private image across instances and the event's static flag unless infra has approved dynamic flag injection and checking.

An initial operational policy is one active instance per team per challenge, a **30-minute TTL**, an explicit reset action, and rate-limited starts/resets. Infra must choose a concurrent-instance cap based on VM capacity before enabling this mode. No infinite lifetime or unlimited launches.

The lifecycle is: authenticate team → enforce quota → allocate port/project → start services → wait for readiness and run a solve check → return endpoint and expiry → reset or expire → `down --volumes --remove-orphans` → verify resource cleanup → release port. Failed starts must also clean up. TTL cleanup must run outside the challenge container so players cannot disable it.

Before review, test two instances from the same directory in separate terminals:

```sh
PUBLIC_PORT=32101 docker compose -p ccs-example-team-a up -d --build
PUBLIC_PORT=32102 docker compose -p ccs-example-team-b up -d --build
uv run solve/solve.py 127.0.0.1 32101
uv run solve/solve.py 127.0.0.1 32102
# Mutate team A through its player endpoint; verify B is unaffected.
docker compose -p ccs-example-team-a down --volumes --remove-orphans
# Verify B still solves, then clean it up.
uv run solve/solve.py 127.0.0.1 32102
docker compose -p ccs-example-team-b down --volumes --remove-orphans
```

Use ports available on your machine. Also verify a fresh start clears state and that expiry removes containers, networks, and volumes. The per-team port pool is allocated by infra and need not match the challenge's shared default range.

## 7. Readiness, health, and capacity

Each README/deployment document gives a readiness command, solver dependency list, time budget, reset steps, and expected state effects. Solvers take `HOST PORT` for remote challenges, use timeouts, print the recovered flag, and never read private `flag.txt` to solve. Monitoring compares that result with the expected flag privately. A jail probe may open a connection; account for that in concurrency limits.

Before freeze, infra tests the expected number of concurrent connections, records memory/CPU needs, and sets host-wide connection/rate limits. Compose limits cap a service container; jail limits cap each connection. Keep both. Keep logs small and rotated, and avoid logging flag-bearing responses. Monitoring frequency must account for destructive solvers and costly instance resets.

Images containing flags remain private. Pin a reviewed deployment image digest, keep a rollback copy, back up CTFd independently, and solve-test after every rebuild or rollback. Do not assume rootless Docker supports privileged jail; validate the native Linux jail host separately.
