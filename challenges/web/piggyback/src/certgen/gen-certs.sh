#!/usr/bin/env bash
# Generate a cert for the front proxies and a SHARED session-ticket key (STEK).
#
# The shared STEK is what lets a ticket issued by one front instance resume (and
# do 0-RTT) on the other — the realistic "identical instances" setup.
#
# Honors two env vars:
#   OUT     where to write server.crt/server.key/ticket.key (default: this dir)
#   DOMAIN  cert CN/SAN (default: lab). For a public run set DOMAIN=piggyback.sict-ccs.club
#           and ship this self-signed cert (players ignore the warning), or drop a
#           real Let's Encrypt cert in place of server.crt/server.key (see README).
#
# Idempotent: if certs already exist in OUT it does nothing, so a container
# restart never rotates the STEK and invalidates tickets already issued.
set -eu

OUT="${OUT:-$(cd "$(dirname "$0")" && pwd)}"
DOMAIN="${DOMAIN:-lab}"

if [ -s "$OUT/server.crt" ] && [ -s "$OUT/server.key" ] && [ -s "$OUT/ticket.key" ]; then
  echo "certs already present in $OUT — leaving them (and the STEK) untouched"
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT/server.key" -out "$OUT/server.crt" -days 365 \
  -subj "/CN=${DOMAIN}" -addext "subjectAltName=DNS:${DOMAIN}" 2>/dev/null

# 80 bytes: 16 key-name + 32 AES-256 key + 32 HMAC-SHA256 key.
openssl rand 80 > "$OUT/ticket.key"

chmod 644 "$OUT/server.crt" "$OUT/ticket.key"
echo "generated: server.crt server.key ticket.key  (CN=${DOMAIN}) in $OUT"
