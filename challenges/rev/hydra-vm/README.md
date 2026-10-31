# HYDRA VM

**Author:** bg0d-glitch  
**Category:** Reverse Engineering  
**Difficulty:** Hard  
**Type:** Hosted TCP Challenge  
**Port:** 34001

## Overview

HYDRA VM is a reverse engineering challenge built around a custom virtual machine and encrypted firmware.

Players must analyze the executable, understand the VM instructions, decrypt the firmware, and reconstruct the authentication algorithm to generate a valid response.

The server generates a unique nonce for each connection. A correct response reveals the flag.

## Challenge Files

- `dist/` — Files distributed to players.
- `src/` — VM, firmware, and server source code.
- `solve/solve.py` — Automated solution.
- `flag.txt` — Private challenge flag.
- `challenge.yml` — Challenge configuration.
- `Dockerfile` / `docker-compose.yml` — Build and deployment.

## Running Locally

```bash
docker compose up -d --build
```

Test the solution:

```bash
uv run solve/solve.py 127.0.0.1 34001
```

Stop the service:

```bash
docker compose down --volumes
```

## Validation

Run from the repository root:

```bash
uv run tools/ctf.py dist challenges/rev/hydra-vm
uv run tools/ctf.py check challenges/rev/hydra-vm
uv run tools/ctf.py dist --verify challenges/rev/hydra-vm
uv run tools/ctf.py test challenges/rev/hydra-vm
```

The challenge passed automated tests, solver verification, and concurrent connection testing.

## Notes

- Flag format: `ccsCTF{...}`
- Player files are generated in `dist/`.
- The real flag and organizer solutions must remain private.
- Live endpoint: `nc 35.253.220.32 34001` (current VM address; it is ephemeral and changes if the VM is restarted). Port 31337 is also published while the VM stays up. The VM idle auto-shutdown is disabled for the event.
- The VM publishes both 34001 and 31337 to the container's 31337; `deployment.yml` declares 34001.
- AI tools are allowed.
- `challenge.yml` and the player handout both use the required `nc CHALLENGE_HOST 34001` form; the event platform substitutes the live address so the handout never carries a stale ephemeral IP.
