# CCS rCTF on AWS

The scoreboard runs on one dedicated Lightsail VM in Singapore. Challenge
containers belong on separate hosts. The instance is sized for an initial
100-player event, subject to testing with the final challenges and traffic.

| Setting | Value |
| --- | --- |
| AWS profile / region | `ccs` / `ap-southeast-1` |
| Instance / zone | `ccs-rctf` / `ap-southeast-1a` |
| Plan | `medium_3_0`: 2 vCPUs, 4 GB RAM, 80 GB disk |
| Instance price at creation | USD 24/month, before snapshots and extra usage |
| Static IPv4 | `13.215.75.166` (`ccs-rctf-ip`) |
| URL | `https://ctf.sict-ccs.club` |
| Host deployment directory | `/opt/rctf` |
| SSH key pair | `ccs-rctf-deploy` |
| Public ports | TCP 80 and 443; TCP 22 restricted to `45.117.34.126/32` |

DNS is managed outside this AWS account. Point the hostname's A record at the
static IP. Cloudflare proxying is supported; use **Full (strict)** TLS and leave
API responses uncached. Caddy obtains and renews its public certificate.
Its trusted proxy list comes from Cloudflare's published IP ranges. Update that
list if Cloudflare changes its networks. Direct traffic cannot supply a trusted
Cloudflare client-IP header.

## Deployment verification

On 2026-10-31, both public and direct-origin HTTPS readiness checks passed.
A read-only smoke test with 100 concurrent clients completed 1,000 requests
with zero failures and approximately 324 ms p95 latency through Cloudflare.
The logical backup restored successfully into a temporary database (11 public
tables). Results are recorded in `verification.json`.

```sh
python3 deployment/rctf/smoke-test.py
```

This test covers the homepage, public configuration, and database/Redis
readiness. It does not establish capacity for registration, flag submissions,
or the final event data. Repeat realistic event testing after importing
challenges. Public registration is open. An organizer admin account has
been created. Six challenges are now imported and scheduled to open at the
event start; see the [worker deployment](../challenges/README.md).

## Connect and operate

From the repository root:

```sh
bash deployment/rctf/ssh.sh
# On the server:
sudo -i
cd /opt/rctf
docker compose ps
docker compose logs --tail 100 rctf
curl --fail http://127.0.0.1:8080/api/readyz
```

The private SSH key and known-host entry are in the ignored `.local/` directory.
Keep a secure copy of the private key. It is not recoverable from this Git repo.
If your management IP changes, update the Lightsail SSH firewall rule using
`aws --profile ccs --region ap-southeast-1 lightsail put-instance-public-ports`;
that operation replaces the entire rule set, so retain ports 80 and 443.

The server generates database, Redis, and token-encryption secrets in
`/opt/rctf/.env`, mode 0600. Re-running `install.sh` preserves that file. Avoid
printing `docker compose config` or container environment variables: they
contain secrets. `docker compose config --quiet` validates without printing them.

## Event settings and registration

`rctf.d/01-event.yaml` sets a six-hour event on October 31, 2026, from
18:00 to midnight (November 1, 00:00) in `Asia/Ulaanbaatar` (UTC+8).
That is October 31, 10:00–16:00 UTC. Public team registration is enabled.

Email delivery is not configured. rCTF can issue team login tokens without
email verification; teams must keep those tokens. Configure a supported email
provider if verification and email recovery are required. Do not assume that
an unverified email address proves ownership when granting admin permissions.

For the first admin, run `bootstrap-admin.py --email organizer@example.com`
as root on the server with the confirmed organizer email. It temporarily runs
a registration-enabled API on loopback, creates the account through rCTF's API,
promotes it with the official CLI, verifies login and admin access, and removes
the temporary container. This does not change the public registration setting. The login link is
saved to root-only `/opt/rctf/admin-access.json`; keep it private.

The initial organizer account has been created for the email supplied by the
organizer. Its login URL is also saved in ignored
`deployment/rctf/.local/admin-access.json` on the operator workstation, mode
0600. Open the `login_url` value, then navigate to `/admin`. rCTF uses a team
login token rather than a password. Anyone with this URL has admin access;
do not commit it or share it with players. No email was sent.

For an existing organizer account, an operator can promote it on the server
(replace the example email with the verified organizer's account):

```sh
docker compose exec rctf rctf user promote organizer@example.com
docker compose exec rctf rctf user list-admins
```

The root `kona.yaml` and `tools/konata.py` target this rCTF server using Konata
0.0.33. They preserve the scheduled release time and the per-team instance
settings. See [Konata sync](../../docs/KONATA.md). The private worker connection
is configured in `/opt/rctf/rctf.d/50-challenge-instancer.yaml`, with its shared
token and API URL in the server's root-only `.env`.

## Apply configuration changes

### Discord first-blood notifications

`first-blood.template.json` prepares rCTF's native Discord notifier for the
first solve of each challenge (`bloodsCount: 1`). Messages include the team
profile link and challenge category/name. The Discord provider disables all
mentions and does not include submitted flags in the message.

First-blood notifications are enabled on the server in
`/opt/rctf/rctf.d/60-first-blood.json`. The file is owned by root with group 1001
and mode 0640 so the rCTF runtime can read it. The template remains outside
`rctf.d`; it contains no real webhook URL. For a webhook rotation, replace the
placeholder in a private copy, install it with the same ownership and mode,
then reload rCTF. Keep the filled file and webhook URL out of Git and command
output; the corresponding local config path is ignored. Do not install the
unfilled template into the active config.

### Other configuration

Update the local files first. Back up the current remote configuration, then
copy only the deployment files; never copy `.local/` or overwrite `.env`:

```sh
bash deployment/rctf/ssh.sh 'sudo bash /opt/rctf/backup.sh'
tar -C deployment/rctf -cf - compose.yml Caddyfile rctf.d install.sh backup.sh verify-restore.sh systemd \
  | bash deployment/rctf/ssh.sh 'sudo tar -C /opt/rctf -xf -'
bash deployment/rctf/ssh.sh 'sudo bash /opt/rctf/install.sh'
```

All four images are pinned to Linux amd64 digests. Deliberately update those
pins for maintenance, back up first, and verify compatibility. An image rollback
alone may not undo a database migration. Retain the matching database backup.
The application shuts down gracefully with a 45-second container grace period.

## Backups and recovery

At 02:00 UTC, `ccs-rctf-backup.timer` creates a compressed archive containing a
PostgreSQL logical dump, uploaded files, `.env`, Compose, Caddy, and event config.
Archives older than roughly seven days are removed. Treat every archive as a
secret: it contains account data, flags once imported, and credentials.

Lightsail takes an automatic VM snapshot at 03:00 UTC, storing the local
archives and Docker volumes off the instance. It keeps its seven most recent
automatic snapshots and bills snapshot storage separately. These are daily
recovery points, not continuous replication or high availability. Trigger
extra backups during the event if losing up to a day's data is unacceptable.
Do not delete the VM until required snapshots and archives have been retained
independently of the instance.

On the server:

```sh
sudo systemctl list-timers ccs-rctf-backup.timer
sudo systemctl status ccs-rctf-backup.service
sudo bash /opt/rctf/backup.sh
sudo bash /opt/rctf/verify-restore.sh /opt/rctf/backups/TIMESTAMP.tar.gz
```

The restore check creates a temporary database, restores the dump with errors
treated as failures, checks for application tables and the upload archive, and
drops only that temporary database. It does not change production data.

To recover a lost host, create a new instance from a retained Lightsail snapshot,
check the Docker services, apply the firewall rules, verify readiness and the
site, and reattach `ccs-rctf-ip`. Verify the new SSH host identity before updating
the local known-host entry. For logical recovery, restore the archive into a
fresh deployment with its matching `.env` and configuration, restore the dump
into its PostgreSQL database and uploaded files into the `uploads` volume,
then start rCTF. Do not test a restore over the running production database.

## Scale and cost

There is no ALB, NAT gateway, RDS, ElastiCache, or Kubernetes cluster in this
deployment. The VM is the primary fixed charge; snapshots, bandwidth above the
plan allowance, and any future email service add usage costs. Stopping a
Lightsail instance does not stop its plan charge.

Watch CPU utilization **and CPU burst capacity**, memory, disk, and application
latency. The general-purpose plan is burstable. For more memory, create an
8 GB `large_3_0` instance from a snapshot and move the static IP after testing
(USD 44/month at deployment time). Shut down writes before the final migration
snapshot to avoid losing submissions. Snapshot upgrades require a replacement
instance; they are not an in-place autoscaler. Increasing the plan does not
automatically increase this Compose file's per-container memory limits.

If horizontal scaling becomes necessary, separate PostgreSQL and Redis from
the app replicas and share them across replicas behind a load balancer. Move
uploads to shared object storage and preserve the same token key everywhere.
rCTF can run multiple `all` replicas with a PostgreSQL advisory lock electing
the leaderboard worker. Avoid transaction-pooling database proxies because
those locks require persistent sessions.

References: [rCTF scaling](https://rctf.osec.io/installation/scaling/),
[rCTF configuration](https://rctf.osec.io/configuration/),
[Lightsail pricing](https://aws.amazon.com/lightsail/pricing/).
