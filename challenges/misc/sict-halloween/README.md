# SICT After Dark — private author notes

A Minecraft Java **26.3** exploration challenge in the SICT campus, with a concealed entrance, four numbered flag fragments, nine-platform hard parkour, and a basketball shot. The intended solution is manual gameplay; see [solve/WRITEUP.md](solve/WRITEUP.md).

| Setting | Value |
| --- | --- |
| Category / difficulty | misc / hard |
| Deployment | Shared Minecraft server, Linux amd64 |
| Player endpoint | Minecraft Multiplayer → `CHALLENGE_HOST:35001` |
| Authentication | Offline mode (maintainer-selected); usernames are not authenticated |
| Handout | None; `dist/` intentionally empty |
| Resources | 2 CPUs, 6 GiB container memory, 4 GiB Java heap, 512 PIDs |
| Persistent state | Project-scoped `server-data` volume |
| Default game mode | Adventure, enforced on join and every tick |
| Spawn | `-175 64 78`, facing north |

## Run

Create a local `.env` with `EULA=TRUE` after accepting the [Minecraft EULA](https://www.minecraft.net/eula). Optional variables are `BIND_ADDR`, `PUBLIC_PORT`, `MEMORY`, and `MAX_PLAYERS`. Docker Engine with BuildKit and Compose is required. The default endpoint binds only to loopback; infra explicitly chooses its production bind address.

```sh
docker compose up -d --build --wait --wait-timeout 300
docker compose logs --tail=100 minecraft
uv run solve/check_endpoint.py 127.0.0.1 35001
```

For production ingress, set `BIND_ADDR=0.0.0.0` (or the dedicated challenge-facing IP). The `connection_info` netcat string in metadata follows the repository's generic TCP convention; players need the Minecraft client, as explained in the description.

The build downloads the official server JAR with a pinned SHA-256 checksum. The pinned base image contains Java 25, `mc-health`, and `rcon-cli`. The custom entrypoint runs Java directly as UID/GID 1000, with a read-only root filesystem and `/tmp` tmpfs. Only `/data` persists. No host mounts, elevated capabilities, downloaded runtime plugins, ViaProxy, builder bots, or host Java installation are needed.

The seed is copied into `/data/sict` on first start only. It contains no player profiles or old challenge progress. Normal restarts preserve the world and scores. The full answer exists only in `flag.txt` and `challenge.yml` in the source tree; the private image build fills eight fragment placeholders from `flag.txt`. Do not publish the runtime image or source world as a player handout.

## Operations

```sh
docker compose exec -T minecraft /opt/sict/admin list
docker compose exec -T minecraft /opt/sict/admin "data get storage sict:server initialized"
docker compose exec -T minecraft /opt/sict/admin "execute as PLAYER_NAME run function sict:server_reset_player"
```

RCON uses a random password saved inside `/data`; port 25575 is not published. `/opt/sict/admin` reads its private configuration. Resetting a connected player clears their CTF scores and challenge items, then returns them to spawn.

Full reset (deletes all players' progress and imports the clean seed):

```sh
docker compose down --volumes --remove-orphans
docker compose up -d --build --wait --wait-timeout 300
```

To back up, stop the service and archive the `server-data` volume with a temporary container before restarting it. Never run `function sict:build` as routine startup: the geometry is already saved.

## Gameplay and isolation

The entrance button is downward-facing at `-180 65 76`; both entrance buttons also have precise interaction targets. Safe door closing, stair connections, item-name fragments, and the gym logic are carried over from the verified local map. Hunger is replenished within the map and inventory is kept on death. Missing fragments can be reclaimed. There are no floating labels or challenge chat messages.

Scores and shot ownership are per player. The shared server disables PvP and player collision to prevent direct interference. Sharing fragments is allowed; this is not a system for enforcing team identity. Infra must capacity-test the requested 20-player limit.

## Review gates and egress

This branch does **not** record approval of the manual-solver exception. Organizer approval, an independent manual test-solve, and Linux amd64 Docker startup verification are required before merge/release. `ctf.py test` explicitly skips manual challenges; that result is not a successful automated solve.

Offline mode does not authenticate usernames. Do not grant OP to player names on an untrusted offline-mode server; administer through the private RCON wrapper. For identity protection, enable both `online-mode` and `enforce-secure-profile` in `src/start.sh` and approve account-service HTTPS access. Infra must deny unrelated outbound traffic, cloud metadata, and other challenge services. The runtime JAR and libraries are supplied by the image/server bundle; startup has no dependency-download step.

## Validation

```sh
uv run tools/ctf.py check challenges/misc/sict-halloween  # from repository root
uv run tests/check_package.py                            # from this directory
```

- The saved map passed 35 offline checks before packaging, including spawn, all nine platforms, button orientation, reset player state, and datapack references.
- On the original Java 26.3 world, a test client in Adventure mode verified both buttons, safe door closing, fragment recovery, ordered checkpoints, and a real basketball shot. Checkpoint tests used command-positioned clients, not a manual traversal.
- All nine jumps passed a local Java 1.21.11 physics approximation. An independent 26.3 gameplay solve is still required.
- Docker is unavailable on the preparation machine. No Linux container startup, full Docker build, `dist --verify`, multiplayer load test, or production egress test is claimed.
- `src/world-manifest.json` verifies the committed seed, and the package test renders fake flags including special characters without printing them. The world input is deterministic; filesystem/image layer timestamps may differ between builds.

The campus is an interpreted block model built from reference photographs and OpenStreetMap geometry, not an exact architectural survey. No reference images, third-party game binaries, or account credentials are included. OpenStreetMap contributors are attributed under the [ODbL](https://www.openstreetmap.org/copyright); the server JAR is fetched from Mojang during the private build.

### Packaging test record — 2026-10-30

| Check | Result |
| --- | --- |
| `uv run tools/ctf.py check challenges/misc/sict-halloween` | Passed, no errors or warnings |
| `uv run tests/check_package.py` | Passed: 292 seed-file hashes, absent player records, fragment rendering with special characters, invalid flag rejection |
| Official Docker Compose CLI 5.6.1 `config --quiet` | Passed |
| POSIX/Bash syntax checks for the entrypoint, admin wrapper, and renderer | Passed |
| Isolated Java 25 / Minecraft 26.3 startup on macOS arm64 | Passed: datapack load/reload, nine protection gamerules, border, team creation, initialization, status handshake, clean shutdown |
| Linux amd64 Docker build/start and `dist --verify` | Not run: Docker Engine unavailable |
| Independent manual solve / load / egress validation | Pending |

`validation/local-map-checks.json` records the earlier checks on the saved map before flag templating and repository packaging. It is evidence about that map, not a Docker runtime test.

`validation/hardening-checks.json` records a separate test of the committed seed with a fake flag and the official 26.3 server JAR. The server ran directly on Java 25 with loopback-only access; this verifies command compatibility and applied rules, but does not exercise the container entrypoint, RCON wrapper, or multiplayer behavior. PvP and border settings were rechecked after a datapack reload.

## Multiplayer defaults

This configuration targets a fresh deployment; no existing world migration is included.

- PvP and friendly fire are disabled by the Minecraft 26.3 gamerule and team settings; player collision is disabled.
- Adventure mode is enforced for every player each tick, preventing ordinary block placement and breaking even if a saved player was in Survival or Creative. Challenge items grant no placement or breaking permissions. This enforcement also applies to operators; map editing requires disabling it deliberately.
- Mob griefing, TNT explosions, fire spread, and projectile block damage cannot destroy the campus. Command blocks and Nether travel are disabled; datapack functions and basketball projectiles remain enabled.
- A 256-block world border centered on `-137 11` contains the whole campus and spawn, limiting exploration-driven chunk generation.
- Each refill replaces the requesting player's remaining tagged basketballs with eight shots; it cannot accumulate unlimited inventory stacks or affect another player.
- View distance 8, simulation distance 6, 15-minute idle timeout, and a 200-packet/second per-connection rate limit complement the existing CPU, memory, PID and log limits. These are starting limits, not a tested 20-player capacity guarantee.
- Remote management, JMX, query, server transfers and player-list disclosure are disabled. RCON is still private; operators and functions use permission level 2.

Offline mode remains enabled as requested by the maintainer. These controls protect gameplay and resources; they cannot prevent username impersonation. Enable authenticated online mode for an untrusted public event.
