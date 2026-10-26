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

### Run it locally

```bash
./certs/gen-certs.sh                 # self-signed cert + shared ticket key (STEK)
docker compose up --build -d
./solver/solve.sh                    # reference exploit — proves it's solvable
```

The solver should land on:

```
    [flight 1] promote: step=1 ok
    [flight 2] promote: step=2 ok admin-granted
[+] FLAG: ccsCTF{0rtt_early_data_desync_x_instance_replay}
```

### Deploy it publicly (real cert)

Self-signed is fine — CTF clients don't validate the chain — but a real cert
keeps `piggyback.sict-ccs.club` clean:

```bash
# 1) DNS: A record  piggyback.sict-ccs.club -> <server-ip>
# 2) Issue a cert (standalone needs :80 free for a moment)
sudo certbot certonly --standalone -d piggyback.sict-ccs.club
# 3) Drop it where the edges read it; mint the internal ticket key
sudo cp /etc/letsencrypt/live/piggyback.sict-ccs.club/fullchain.pem certs/server.crt
sudo cp /etc/letsencrypt/live/piggyback.sict-ccs.club/privkey.pem   certs/server.key
openssl rand 80 > certs/ticket.key            # STEK is internal, never from the CA
# 4) Map the LB to 443 (edit docker-compose.yml: lb ports -> "443:443") and bring it up
docker compose up --build -d
```

Operator checklist before you open it:

- **Publish only the LB.** `front1`, `front2` and `backend` stay on `expose:`,
  never `ports:`. If a player can reach one edge node directly, they can pin it,
  and a chunk of the challenge evaporates.
- **Set a real `FLAG`** in `docker-compose.yml`.
- Promotion state is in-memory, keyed by each player's own `X-Token`, so players
  never collide. Restart `backend` to wipe all progress.
- The server ignores SNI, so any `-servername` connects; the real name just keeps
  TLS tidy.

### Files

```
docker-compose.yml     lb + front1 + front2 + backend (+ optional solver)
certs/gen-certs.sh     cert (DOMAIN-aware) + shared 80-byte ticket key
front/front.c          edge proxy — TLS termination, 0-RTT, replay cache
backend/main.go        origin app server
haproxy/haproxy.cfg    round-robin TCP load balancer
solver/solve.sh        reference exploit (openssl s_client -early_data)
SOLUTION.md            writeup + difficulty knobs + vuln map  (SPOILERS)
```
