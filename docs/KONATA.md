# Konata / CTFd sync

This repository uses [Konata](https://github.com/project-sekai-ctf/konata)
**0.0.33** to sync challenge metadata, flags, tags, and handouts to CTFd.
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
rendered connection details, discovery, and CTFd payload generation offline.
The adapter currently supports the repository's dynamic challenges with one
case-sensitive static flag and no hints; unsupported variants fail explicitly.

Flags are read from each challenge's `flag.txt`. Konata's `pre_compressed`
attachment field passes through the explicit `challenge.yml` file list unchanged;
despite the name it accepts raw files too. It does not archive the source tree
or rebuild the committed handouts. Continue using the existing `dist --verify`
and solver checks before release.

## Organizer sync

First deploy and solve-test the hosted services using their Compose files and
`deployment.yml` contracts. Supply these environment variables in your shell or
private deployment environment:

- `CTFD_TOKEN`: a CTFd admin API token. Never commit it.
- `CHALLENGE_HOST`: the challenge server's public IP, without a scheme or port.
  For IPv6 use brackets, e.g. `[2001:db8::1]`.

Then, from the repository root:

```sh
: "${CTFD_TOKEN:?Set the CTFd admin API token}"
: "${CHALLENGE_HOST:?Set the public challenge server IP}"
uv run tools/ctf.py check
uv run tools/konata.py
LOGURU_LEVEL=WARNING LOGURU_DIAGNOSE=NO uvx --from konata==0.0.33 kona sync

# Or sync one challenge:
LOGURU_LEVEL=WARNING LOGURU_DIAGNOSE=NO uvx --from konata==0.0.33 kona sync challenges/web/piggyback
```

This is an explicit write to CTFd; CI only validates and does not sync on push.
Konata matches existing CTFd challenges by **name and category**. Renaming either
can create a new challenge, so review such changes before syncing an existing
event. All current configs set `hidden: true`, matching `state: hidden`; syncing
will hide a challenge again if it was made visible only in the CTFd UI. Organizer
release still happens after endpoint and flag verification.

Connections appear in the challenge description. Konata 0.0.33 does not render
templates in CTFd's separate `connection_info` field, so that field stays empty.
The description template also replaces `CHALLENGE_HOST` in narrative text,
including the Minecraft instructions. Piggyback keeps HTTPS; the other web
challenges keep HTTP; TCP challenges retain their assigned ports.

The logging settings above suppress upstream Konata's informational flag-update
messages and traceback local-variable dumps, which can contain flags or tokens.
Keep any remaining sync diagnostics private. The repository's offline checks do not print flag values.
For a staging CTFd instance, change the root `ctfd.base_url` in a local checkout
before syncing; validation itself requires neither tokens nor a running server.

The schema and CLI are pinned because Konata is pre-1.0. When upgrading, update
the pins in both Python scripts and these commands, then rerun the offline
checks and a staging sync. See the [upstream guide](https://rctf.osec.io/integrations/konata/).
