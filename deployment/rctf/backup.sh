#!/bin/bash
# Daily logical backup; Lightsail snapshots copy these off the instance.
set -euo pipefail
cd /opt/rctf
umask 077
mkdir -p backups
exec 9>/run/lock/ccs-rctf-backup.lock
flock -n 9 || exit 0
stamp=$(date -u +%Y%m%dT%H%M%SZ)
archive="backups/$stamp"
mkdir "$archive"
trap 'rm -rf "$archive"' EXIT
docker compose exec -T postgres pg_dump -U rctf -d rctf -Fc > "$archive/database.dump"
docker compose exec -T rctf tar -C /app/uploads -czf - . > "$archive/uploads.tar.gz"
cp .env compose.yml Caddyfile "$archive/"
cp -a rctf.d "$archive/"
tar -C backups -czf "backups/$stamp.tar.gz.partial" "$stamp"
mv "backups/$stamp.tar.gz.partial" "backups/$stamp.tar.gz"
find backups -maxdepth 1 -type f -name '*.tar.gz' -mtime +6 -delete
printf 'Backup complete: %s\n' "backups/$stamp.tar.gz"
