# CCS Halloween theme

A small image layer over the exact rCTF image pinned by the event deployment.
It supplies orange/midnight semantic colors throughout the native UI, a warm
light mode, an interactive WebGL pumpkin, a custom SVG wordmark, and a responsive landing page.
All assets are local; the theme adds no third-party requests or dependencies.

## Local review

From the repository root:

```sh
python3 deployment/rctf/theme/generate-config.py
docker compose -f deployment/rctf/compose.preview.yml up -d --build
curl --fail http://localhost:8080/api/readyz
python3 deployment/rctf/theme/seed-preview.py
```

Wait for readiness to return `ok` before seeding. Open
<http://localhost:8080>. Registration, login, challenge browsing, sample flag
submission, and the scoreboard use the real rCTF API, PostgreSQL, and Redis.
The six demo challenges are clearly labeled and include their sample flags.
Register a disposable team to try the player experience. The optional demo
organizer login is saved in ignored `.local/preview-access.json`.

The Compose project `ccs-halloween-preview` has separate database/upload
volumes and binds only to loopback. Its intentionally public development
credentials must stay local. It does not read production secrets, call the
challenge worker, configure Discord, or import real challenges or users.
`preview.json` opens the local event one day early for review; the event's
actual October 31 closing time is preserved. Adjust this local-only file for
review after the event. Never install `preview.json` on the live server.

```sh
# Stop the local preview; retain its data.
docker compose -f deployment/rctf/compose.preview.yml down
```

## Editing

- `assets/halloween.css`: shared theme tokens and landing-page layout.
- `assets/pumpkin.js`: dependency-free 3D pumpkin with carved geometry, lighting,
  pointer/arrow-key rotation, and a subtle candle animation capped at 30 fps.
  Rendering pauses when hidden or offscreen; reduced motion disables the animation.
- `assets/haunt-background.svg`: original moon, stars, bats, and ground details
  layered behind the interactive pumpkin.
- `assets/haunt.svg`, `mark.svg`, `wordmark.svg`: original vector artwork. The
  illustration remains visible if WebGL is unavailable or the context is lost.
- `assets/theme.js`: midnight default, preserving the saved light/dark choice.
- `home.html`: landing content, passed through rCTF's Markdown sanitizer.
- `theme.json`: generated native rCTF UI configuration; regenerate after editing HTML.

After edits, regenerate the config and rerun `up -d --build --force-recreate`
so the image assets and bind-mounted config are reloaded. Hard-refresh open
browser tabs if necessary. No application source or lockfile changes are needed.

The Dockerfile inserts a same-origin stylesheet into rCTF's SPA shell and
removes the old compressed shell/script variants. rCTF still generates its
own Content Security Policy at startup. Existing routes, forms, keyboard
interaction, focus styling, and the theme toggle remain native rCTF features.

## Production integration

The parent `compose.yml` builds `ccs-rctf-halloween:2026-10-31-v1` using this
Dockerfile. The installer copies `theme.json` to `rctf.d/90-halloween.json`. It keeps
the existing production volumes, event schedule, and environment settings.
`install.sh` pulls the database/proxy images and builds the themed app before
starting services. Backups include the theme sources so the image can be rebuilt.

Deploy the image and UI config together because the config references bundled
assets. Do not use the preview Compose file, preview timing, seed script, or demo
data for production. `preview.json` is only mounted by the preview Compose file;
the Dockerfile copies only `assets/`. Follow the backup and verification procedure
in the parent README before a live rollout.
