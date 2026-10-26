#!/usr/bin/env bash
# Generate a cert for the front proxies and a SHARED session-ticket key (STEK).
#
# The shared STEK is what lets a ticket issued by one front instance resume (and
# do 0-RTT) on the other — the realistic "identical instances" setup.
#
# DOMAIN controls the cert's CN/SAN. For a LOCAL run leave it as "lab". For a
# PUBLIC deployment behind a real name, either set DOMAIN=0rtt.sict-ccs.club and
# ship this self-signed cert (players just ignore the warning), OR drop a real
# Let's Encrypt cert in place of server.crt/server.key (see README). The STEK
# (ticket.key) is internal and is generated the same way either way.
set -euo pipefail
cd "$(dirname "$0")"

DOMAIN="${DOMAIN:-lab}"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=${DOMAIN}" -addext "subjectAltName=DNS:${DOMAIN}" 2>/dev/null

# 80 bytes: 16 key-name + 32 AES-256 key + 32 HMAC-SHA256 key.
openssl rand 80 > ticket.key

chmod 644 server.crt ticket.key
echo "generated: server.crt server.key ticket.key  (CN=${DOMAIN})"
