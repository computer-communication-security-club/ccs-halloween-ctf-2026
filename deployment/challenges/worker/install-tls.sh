#!/bin/bash
set -euo pipefail
domain=challenge.ctf.sict-ccs.club
source_dir="/opt/ccs-worker/letsencrypt/live/$domain"
destination=/opt/ccs-worker/instancer
install -d -m 0700 "$destination/certs"
install -m 0644 "$source_dir/fullchain.pem" "$destination/certs/fullchain.pem"
install -m 0600 "$source_dir/privkey.pem" "$destination/certs/privkey.pem"
openssl x509 -in "$destination/certs/fullchain.pem" -noout -dates
if [ -f "$destination/.env" ]; then
  cd "$destination"
  docker compose restart traefik
fi
