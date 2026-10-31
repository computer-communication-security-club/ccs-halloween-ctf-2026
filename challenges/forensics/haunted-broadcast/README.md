# The Haunted Broadcast

This is an externally hosted forensics challenge at
https://d2o1rk98pkw6lk.cloudfront.net. This repository contains its player
metadata and accepted flag, but no local service, handout build, or solver.

`deployment.yml` declares `mode: external`. CI validates the metadata and
generated Konata config, and excludes this entry from local Docker and solver
jobs. It does not verify the external site's availability or solve path.
Before release, the organizer must confirm the challenge is available and
solvable at the published URL.

From the repository root:

```sh
uv run tools/ctf.py check challenges/forensics/haunted-broadcast
uv run tools/konata.py
```
