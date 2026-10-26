# Contributing a challenge

1. Read [the rules](docs/RULES.md), then agree on the category, idea, difficulty, and deployment mode with the organizers.
2. Create a branch: `git checkout -b chall/<category>-<slug>`.
3. Create `challenges/<category>/<slug>/` following the [specification](docs/CHALLENGE_SPEC.md), or restore an [old example](README.md#start-a-challenge) from git history as a starting point. Keep the slug unique across the repository.
4. Change `challenge.yml`, `deployment.yml`, `README.md`, `flag.txt`, sources, handout, and solver. Reserve an unused default port from your category range; search existing compose files with `rg 'published:|PUBLIC_PORT' challenges`.
5. Export the public handout with `uv run tools/ctf.py dist challenges/<category>/<slug>`. It runs the Dockerfile's `dist` stage and removes stale files. Check every output before committing. Commit the generated handout, including pwn binary and runtime libraries.
6. Run `uv run tools/ctf.py check challenges/<category>/<slug>` and fix every error. Then run `uv run tools/ctf.py test challenges/<category>/<slug>`: it starts hosted challenges with Compose, runs the real solver with a 60-second timeout, compares the result with `flag.txt` without printing it, and tears the project down. Static solvers must read only `dist/`. Declare solver dependencies inline at the top of `solve.py` (see the [specification](docs/CHALLENGE_SPEC.md#build-and-solver-contract)).
7. For pwn, run `pwn checksec dist/chall`, record the output, and confirm the handout binary and libraries match the deployed image. Test again on native Linux amd64. For per-team mode, complete the two-instance test in [Architecture §6](docs/ARCHITECTURE.md#6-per-team-instances).
8. Inspect `dist/` manually, including archive contents and metadata. It must contain no plaintext real flag or private solution. Verify every `files` entry exists and every intended download is listed.
9. Open a PR; the template contains the checklist below. CI must be green, or the PR must explain the failing job. An independent reviewer solves using only the description, handout, and player endpoint. Merge after organizer approval; deployment and CTFd publication are infra tasks.

## Review checklist

- [ ] Category, unique slug, difficulty, and dynamic scoring follow the spec.
- [ ] `Dockerfile` builds from this directory alone; remote Compose starts successfully.
- [ ] Base-image digests, application dependency versions, and architecture are recorded.
- [ ] `challenge.yml` and `flag.txt` agree; metadata defaults to `state: hidden`.
- [ ] Handout rebuilt, committed, listed in `files`, and inspected for accidental leaks.
- [ ] Solver prints the correct flag within 60 seconds; writeup explains the intended path.
- [ ] Ports, limits, jail/non-root setup, and outbound network policy reviewed.
- [ ] `deployment.yml` declares static/shared/per-team mode, readiness, reset, and dependencies.
- [ ] Per-team: two concurrent projects use different ports and independent state; reset and expiry tested.
- [ ] Independent test-solver: @___; platform and commands tested: ___; result: ___
- [ ] Extra infra requirements and any exceptions are documented with organizer approval.

CI ([`challenges.yml`](.github/workflows/challenges.yml)) automates the metadata, handout, leak, and solve checks. It does not replace the independent test-solve, native Linux pwn testing, per-team isolation checks, or a manual look at `dist/`.
