# Piggyback

> Latency is a feature.
>
> Piggyback terminates TLS right at the edge and answers your very first request
> out of TLS 1.3 **0-RTT early data** — bytes coming back before the handshake
> has even finished settling. Two edge nodes up front, one warm origin behind
> them, keep-alives that never go cold. Two edges, one origin, zero wait.
>
> The security review left exactly one line on the whiteboard before lunch:
> **no privileged actions on the fast path.** We wrote the guard. We shipped on
> time. Ship fast, they said.
>
> Make yourself an admin and read `/flag`.

|            |                                            |
| ---------- | ------------------------------------------ |
| **Connect**    | `piggyback.sict-ccs.club:443` — TLS 1.3 only |
| **Flag**       | `ccsCTF{...}`                            |
| **Category**   | web / tls                               |
| **Difficulty** | hard                                    |

A client that actually speaks 0-RTT is the whole ballgame. `openssl s_client
-early_data` is more than enough — no exotic tooling required.

---

## Hosting

> Everything below is for whoever **runs** the challenge. Players only ever get
> the line above. The full writeup, the anti-cheese reasoning and the
> design-verification map are in [`SOLUTION.md`](./SOLUTION.md) — that file is
> spoilers, keep it off the scoreboard.

```
 player ──TLS 1.3 0-RTT──▶  lb (haproxy, round-robin, L4 pass-through)
                               ├──▶ front1  (edge node A, 0-RTT on)
                               └──▶ front2  (edge node B, 0-RTT on)
                                         │  identical image, shared ticket key
                                         ▼
                                      backend  (HTTP/1.1, keep-alive)
```

### Run it — one command

```bash
docker compose up --build -d
```

That's the whole deploy. No pre-steps: an init container generates the
self-signed cert and the shared ticket key into a volume before the edges start,
everything runs `restart: unless-stopped`, and the challenge is live on **:443**.
Nothing to babysit — crashes and host reboots self-recover.

Check it solves:

```bash
docker compose run --rm solver     # reference exploit, over the real LB
```

```
    [flight 1] promote: step=1 ok
    [flight 2] promote: step=2 ok admin-granted
[+] FLAG: ccsCTF{...}
```

### Settings

Set these in a `.env` next to `docker-compose.yml` (or as real env vars):

```ini
FLAG=ccsCTF{your_real_flag_here}
DOMAIN=piggyback.sict-ccs.club     # cert CN/SAN; players use it as -servername
PUBLISH_PORT=443                   # host port the LB listens on
```

- **Reset everything** (wipe promotion state *and* rotate the ticket key):
  `docker compose down -v && docker compose up --build -d`. A plain restart keeps
  the cert/STEK (idempotent), so tickets players already hold keep working.

### Optional: a real cert instead of self-signed

Self-signed is fine — CTF clients don't validate the chain — but if you want
`piggyback.sict-ccs.club` to look clean, seed the `certs` volume with a Let's
Encrypt cert once, before first `up`:

```bash
sudo certbot certonly --standalone -d piggyback.sict-ccs.club
docker volume create piggyback_certs
docker run --rm -v piggyback_certs:/c -v /etc/letsencrypt/live/piggyback.sict-ccs.club:/le:ro alpine \
  sh -c 'cp /le/fullchain.pem /c/server.crt && cp /le/privkey.pem /c/server.key && head -c80 /dev/urandom > /c/ticket.key'
docker compose up --build -d       # certgen sees existing certs and leaves them alone
```

### Operator notes

- **Only the LB is published.** `front1`, `front2` and `backend` stay on
  `expose:`, never `ports:`. If a player can reach one edge node directly they can
  pin it, and a chunk of the challenge evaporates. Keep it that way.
- Promotion state is in-memory, keyed by each player's own `X-Token`, so players
  never collide; a `backend` restart just makes everyone redo the ~5-second solve.
- The server ignores SNI, so any `-servername` connects; the real name just keeps
  TLS tidy.

### Files

```
docker-compose.yml     certgen + backend + front1 + front2 + lb (+ solver)
certgen/Dockerfile     one-shot init: generates cert + STEK into a volume
certs/gen-certs.sh     cert (DOMAIN-aware) + shared 80-byte ticket key, idempotent
front/front.c          edge proxy — TLS termination, 0-RTT, replay cache
backend/main.go        origin app server
haproxy/haproxy.cfg    round-robin TCP load balancer (re-resolves on restart)
solver/solve.py        reference exploit (Python; drives openssl -early_data)
SOLUTION.md            writeup + difficulty knobs + vuln map  (SPOILERS)
```
