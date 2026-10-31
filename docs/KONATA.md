# Konata / rCTF sync

This repository uses [Konata](https://github.com/project-sekai-ctf/konata)
**0.0.33** to sync challenge metadata, flags, tags, and handouts to **rCTF v2**
with flag-provider support. Older rCTF releases without
`/api/v2/admin/flags/providers` are not supported by this Konata version.
The root `kona.yaml` targets `https://ctf.sict-ccs.club` and discovers the
per-challenge configs three directories down. Docker Compose remains responsible
for starting, stopping, and resetting the hosted services. No image registry,
Kubernetes cluster, or instancer is needed for this integration.

## Author workflow

`challenge.yml` is the canonical metadata. After editing it, regenerate and check:

```sh
uv run tools/konata.py --write
uv run tools/ctf.py check
uv run tools/konata.py
uv run tools/test_konata.py
```

Commit the regenerated `kona.yaml` alongside the source edit. CI rejects stale
configs and checks the actual Konata schema, flag resolution, attachment paths,
rendered connection details, discovery, authentication, rCTF payload generation,
and repeated-sync idempotency offline using a mock HTTP transport.
The adapter currently supports the repository's dynamic challenges with one
case-sensitive static flag and no hints; unsupported variants fail explicitly.

Flags use rCTF's exact-match `flags/static` provider and are read from each
challenge's `flag.txt`. Konata's `pre_compressed`
attachment field passes through the explicit `challenge.yml` file list unchanged;
despite the name it accepts raw files too. It does not archive the source tree
or rebuild the committed handouts. Continue using the existing `dist --verify`
and solver checks before release.

## Organizer sync

First deploy and solve-test the hosted services using their Compose files and
`deployment.yml` contracts. Supply these environment variables in your shell or
private deployment environment:

- `RCTF_TOKEN`: an rCTF team token with `challsRead,challsWrite` permissions. Never commit it.
- `CHALLENGE_HOST`: the challenge server's public IP, without a scheme or port.
  For IPv6 use brackets, e.g. `[2001:db8::1]`.
- `MINECRAFT_HOST`: the separate Minecraft server's public IP.

Then, from the repository root:

```sh
: "${RCTF_TOKEN:?Set the rCTF admin team token}"
: "${CHALLENGE_HOST:?Set the public challenge server IP}"
: "${MINECRAFT_HOST:?Set the Minecraft server IP}"
uv run tools/ctf.py check
uv run tools/konata.py
for challenge in challenges/*/*; do
  [ -f "$challenge/kona.yaml" ] || continue
  host="$CHALLENGE_HOST"
  [ "$challenge" != challenges/misc/sict-halloween ] || host="$MINECRAFT_HOST"
  CHALLENGE_HOST="$host" LOGURU_LEVEL=WARNING LOGURU_DIAGNOSE=NO \
    uvx --from konata==0.0.33 kona sync "$challenge" || exit 1
done

# Or sync one challenge:
LOGURU_LEVEL=WARNING LOGURU_DIAGNOSE=NO uvx --from konata==0.0.33 kona sync challenges/web/piggyback
```

This is an explicit write to rCTF. The GitHub Action below also syncs after
successful main-branch checks.
Konata uses stable path-based IDs, for example
`challenges_web_piggyback`. Keep challenge paths stable after the first sync;
renaming a display name preserves its ID, while moving a directory can create a
new record. Current event configs set `hidden: false` and
`release_time: '2026-10-31T18:00:00+08:00'`, generated from the organizer-approved
`state` and `release_time` fields in `challenge.yml`. rCTF keeps them unavailable
until October 31 at 18:00 Ulaanbaatar time. `hidden: true` overrides the timestamp
and would prevent automatic opening. Future syncs preserve the schedule.

Connections render as rCTF `> [!CONNECTION]` callouts. The description template
renders Minecraft's named endpoint as a copyable `HOST:PORT` address, without
an `nc` command or an HTTP link. The Minecraft version stays in the description.
The description template also replaces `CHALLENGE_HOST` in narrative text.
Piggyback keeps its native TLS endpoint; TCP challenges retain
their assigned ports. Shelloween and Poltergeist use the reviewed per-team HTTPS
settings in `deployment/challenges/instances.json`, which the generator includes
as `instancer_config` instead of an obsolete shared HTTP endpoint. The author is
sent through rCTF's native `author` field.

The logging settings above suppress informational messages and traceback
local-variable dumps. Keep sync diagnostics private. The repository's offline
checks do not print flag values. For a staging rCTF instance, change the root
`rctf.base_url` in a local checkout before syncing; validation itself requires
neither tokens nor a running server.

## GitHub Actions

[`konata.yml`](../.github/workflows/konata.yml) runs after the **Challenges**
workflow succeeds for a push to `main`. It checks out the exact tested commit,
skips a queued commit if main has already advanced, and syncs all discovered
challenge configs with the upstream `konata-deploy-action/sync` action and
`konata==0.0.33`. Konata skips unchanged payloads. The action and checkout are
pinned to commit SHAs. Syncs run one at a time and are not cancelled halfway
through by a newer deployment.

Pull-request runs never trigger production sync. The separate validation jobs
do not receive the deployment secrets. Manual runs are allowed only on `main`
and require a successful **Challenges** run for that same commit:

```sh
gh workflow run konata.yml --ref main
gh run list --workflow konata.yml
```

The repository's Actions secrets are:

| Secret | Purpose |
| --- | --- |
| `RCTF_TOKEN` | Dedicated **Konata CI** team token; only `challsRead,challsWrite` permissions |
| `CHALLENGE_HOST` | Public challenge-server IP used in descriptions and endpoints |
| `MINECRAFT_HOST` | Separate Minecraft server IP, selected for `challenges/misc/sict-halloween` |

The workflow exports the selected IP as `CHALLENGE_HOST` for each individual
Konata invocation. A missing Minecraft host fails that challenge's job rather
than silently falling back to the general worker. When syncing Minecraft
locally, set `CHALLENGE_HOST` to the Minecraft server's IP for that invocation.

No AWS credentials or SSH private keys are needed for this action. It syncs
metadata, flags, and approved handouts; it does not deploy challenge containers.
Keep the worker services available and solve-tested before exposing challenges.
Every sync reapplies the repository's `hidden` settings, including on a manual
rerun. Change the canonical metadata to preserve intended visibility across
future syncs.

To rotate a secret, set it through the repository's Actions settings or
`gh secret set RCTF_TOKEN`, `gh secret set CHALLENGE_HOST`, or
`gh secret set MINECRAFT_HOST`. Supply values on
stdin or at the prompt, not in command-line arguments or Git commits.

## Scoring

`type: dynamic` in the authoring metadata becomes Konata `scoring.rctf.kind:
decay`. Each challenge supplies `initial_value: 1000` and its configured
`minimum_value`, which become rCTF `points.max` and `points.min`. The default
minimum is 100; SICT After Dark uses 10. Tiebreak eligibility is enabled.

Configure the **rCTF server**, separately from Konata, with:

```yaml
scoreProvider:
  name: scores/classic
```

This uses rCTF's native solve-count decay. The former per-challenge `decay: 10`
is removed: Konata's rCTF API does not send that setting. This preserves the
point range, not the old scoring curve. The generator and repository checks
reject legacy per-challenge decay/function settings so they cannot be silently
ignored. See the [rCTF scoring provider documentation](https://rctf.osec.io/providers/scores/).
In rCTF terminology, `kind: dynamic` instead means externally supplied scores;
it is not the mode used for these challenges.

The schema and CLI are pinned because Konata is pre-1.0. When upgrading, update
the pins in both Python scripts and these commands, then rerun the offline
checks and a staging sync. See the [upstream guide](https://rctf.osec.io/integrations/konata/).
