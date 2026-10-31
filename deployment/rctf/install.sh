#!/bin/bash
# Run on the server after copying this directory to /opt/rctf.
set -euo pipefail
cd /opt/rctf
umask 077
if [[ ! -f .env ]]; then
  python3 - <<'PY'
import base64, secrets
from pathlib import Path
values = {
    'RCTF_DATABASE_PASSWORD': secrets.token_hex(32),
    'RCTF_REDIS_PASSWORD': secrets.token_hex(32),
    'RCTF_TOKEN_KEY': base64.b64encode(secrets.token_bytes(32)).decode(),
}
Path('.env').write_text(''.join(f'{key}={value}\n' for key, value in values.items()))
PY
fi
chmod 600 .env
docker compose config --quiet
docker compose pull --quiet
docker compose up -d --wait --wait-timeout 180
install -m 0644 systemd/ccs-rctf-backup.service /etc/systemd/system/
install -m 0644 systemd/ccs-rctf-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ccs-rctf-backup.timer
