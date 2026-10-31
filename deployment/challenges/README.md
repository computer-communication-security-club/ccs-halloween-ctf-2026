# Event challenge workers

These workers are separate from the rCTF database and scoreboard host. The
deployment uses AWS profile `ccs`, region `ap-southeast-1`, and the settings in
`config.json`. Private keys, host pins, generated Compose files, and import state
are under ignored `.local/`. Keep a secure copy of that directory.

| Worker | Static IPv4 | Services | Plan |
| --- | --- | --- | --- |
| `ccs-challenges` | `54.255.7.242` | Piggyback, HYDRA, per-team web instances | `xlarge_3_0`, USD 84/month at creation |
| `ccs-minecraft` | `18.139.70.187` | Minecraft | `large_3_0`, USD 44/month at creation |

The worker plans total USD 128/month before additional usage. The existing
scoreboard is billed separately. Stopping Lightsail instances does not stop
their plan charges; destroy temporary workers after retaining needed data.

| Challenge | Player endpoint |
| --- | --- |
| Piggyback | `54.255.7.242:32002`, native challenge TLS |
| HYDRA VM | `54.255.7.242:34001`, plain TCP |
| SICT Halloween | `18.139.70.187:35001`, Minecraft Java 26.3 |
| Shelloween | Per-team HTTPS endpoint supplied by rCTF |
| Poltergeist | Per-team HTTPS endpoint supplied by rCTF |
| PHPossessed | Per-team HTTPS endpoint supplied by rCTF |
| Dead Signal | Static handout in rCTF |
| The Cursed MAYO | Per-team TCP-over-TLS hostname on port 443 supplied by rCTF |

The original seven challenges are scheduled through Konata to open on October 31, 2026 at
18:00 Ulaanbaatar time (10:00 UTC). Their canonical metadata uses `state: visible`
with `release_time: '2026-10-31T18:00:00+08:00'`; the future timestamp keeps them
unavailable before the event. Review the verification results before opening.
PHPossessed opens at 20:00 Ulaanbaatar time (12:00 UTC) on the same day.
Minecraft's status check is not a manual gameplay solve.
The operator explicitly accepted the Minecraft EULA for this deployment.

## Instance lifecycle and networking

rCTF connects to the worker's private address on TCP 12237 with a shared token.
The API is not published on the public interface. Its Docker forwarding rule
accepts only the scoreboard host's private IP. The worker has no scoreboard
database credentials or administrator token.

Shelloween, Poltergeist, and PHPossessed use isolated containers and networks, one instance
per team per challenge, a 30-minute renewable lifetime, a global cap of 60
instances, and a cap of 30 per web challenge. The Cursed MAYO uses the same
isolation and lifetime with a cap of 20, 1 CPU, 512 MiB RAM, 128 PIDs, and
64 MiB of tmpfs. Its TCP-over-TLS route uses SNI on port 443. Starts are serialized and limited to
one per team every ten seconds. The upstream pruner removes expired resources.
The policy accepts only the deployed image IDs and exact container settings.

Traefik terminates TLS and forwards the byte stream using TCP routers. This is
deliberate: both web solves can take over their HTTP socket and return raw data,
which an HTTP reverse proxy would alter. Normal browser HTTPS still works.

Challenge bridges use `10.202.0.0/16`; the control network is `10.203.0.0/24`.
`ccs-firewall.service` blocks challenge-initiated traffic to the Internet,
metadata, the scoreboard, the control API, and other bridges while allowing
established replies and communication within a challenge bridge. CPU, memory,
PID, filesystem, and capability limits come from the challenge packages.

## DNS and HTTPS

Create DNS-only A records for `challenge.ctf.sict-ccs.club` and
`*.challenge.ctf.sict-ccs.club`, both pointing to `54.255.7.242`. Do not use an
HTTP CDN proxy: the exploit traffic requires transparent stream forwarding.

The wildcard certificate uses a manual ACME DNS challenge. Its private key and
account live only on the challenge host under `/opt/ccs-worker/letsencrypt`.
After issuance or renewal, run `worker/install-tls.sh` on the host as root to
install the certificate and restart Traefik. Check its printed expiration date.
Manual DNS validation is not unattended renewal; renew before expiry if the
deployment remains online beyond this event.

## Operate and verify

Run scripts from the repository root with Python 3.12+ and PyYAML installed.
All builds execute on the private workers. Runtime images contain real flags;
do not push them to a public registry or offer them as player downloads.

```sh
python3 deployment/challenges/manage.py status
python3 deployment/challenges/manage.py ssh instancer
python3 deployment/challenges/manage.py ssh minecraft
python3 deployment/challenges/verify.py shared
python3 deployment/challenges/verify.py minecraft
python3 deployment/challenges/verify.py instances
```

`verify.py` compares solver output privately and records successful groups in
`verification-*.json`. The web check creates and deletes organizer instances;
do not run it while using those organizer instances for a demonstration.
The solvers exercise the intended vulnerabilities, so run only against these
event workers. Public health checks alone do not prove a challenge is solvable.

On a worker, generated Compose projects are under `/opt/ccs-worker/`. Use
`sudo docker compose ...` in the appropriate directory. Do not print `.env`,
unfiltered container environments, or full Compose configuration. Use
`docker compose config --quiet` for validation.

To rebuild and reapply the reviewed configuration:

```sh
python3 deployment/challenges/deploy.py build instancer
# Or rebuild only MAYO:
python3 deployment/challenges/deploy.py build instancer --challenge the-cursed-mayo
python3 deployment/challenges/deploy.py build-instancer instancer --upstream /path/to/pinned/rctf
python3 deployment/challenges/deploy.py install instancer
python3 deployment/challenges/deploy.py build minecraft
python3 deployment/challenges/deploy.py install minecraft
uv run tools/konata.py --write
python3 deployment/challenges/rctf.py configure
python3 deployment/challenges/rctf.py sync
```

The instance-manager checkout must match `upstream_revision` in `config.json`.
The installer refreshes `instances.json`; regenerate and commit the matching
Konata configs after changing images or runtime policy. The sync wrapper uses
the same pinned Konata version and stable path IDs as the repository CI.
The imported handouts come only from each challenge's approved `files` list.
The rCTF configuration step takes a scoreboard backup before setting its
private instancer connection. Rebuilding an image does not replace already
running team instances; expire or stop those instances before changing policy.

## Preserve progress and shut down

Minecraft stores player progress in `ccs-minecraft_server-data`. Container
recreation preserves that volume. `down --volumes` or deleting the VM destroys
progress. Before deletion, stop Minecraft gracefully and retain a volume
archive or Lightsail snapshot. Protect backups as private event data.

The other runtime challenges have no durable player data requiring retention.
rCTF submissions and team records remain on the separate scoreboard host.

```sh
# Destructive: deletes both event workers and releases their static IPs.
# Preserve Minecraft data first. This does not delete the scoreboard.
python3 deployment/challenges/manage.py destroy --delete-workers
```

Also remove stale challenge DNS records and the scoreboard's instancer
configuration when retiring the workers.

To update only the per-team launcher policy after building images, run
`python3 deployment/challenges/deploy.py install-instances instancer`. This
recreates the launcher without restarting the proxy or existing team containers.
Verify MAYO with `python3 deployment/challenges/verify.py instances --challenge the-cursed-mayo`.

To add or rebuild PHPossessed without restarting the proxy or syncing other
challenges:

```sh
python3 deployment/challenges/deploy.py build instancer --challenge phpossessed
python3 deployment/challenges/deploy.py install-instances instancer
uv run tools/konata.py --write
python3 deployment/challenges/rctf.py sync --challenge phpossessed
python3 deployment/challenges/verify.py instances --challenge phpossessed
```

PHPossessed uses 0.5 CPU, 256 MiB RAM, 128 PIDs, and three tmpfs mounts:
`/tmp` (16 MiB), `/var/run/apache2` (1 MiB), and `/var/lock` (1 MiB).
Its TCP router terminates TLS and forwards the unmodified HTTP stream to port
8080. Probe only `/health.txt`; PHP requests can disturb the cross-request
exploit state. Each team gets its own Apache worker and temporary reports.
