#!/bin/bash
# Restore a backup into a temporary database, never the production database.
set -euo pipefail
cd /opt/rctf
umask 077
archive=${1:?Usage: verify-restore.sh /opt/rctf/backups/TIMESTAMP.tar.gz}
work=$(mktemp -d)
database="rctf_restore_check_$(date +%s)_$$"
cleanup() {
  docker compose exec -T postgres dropdb -U rctf --if-exists "$database"
  rm -rf "$work"
}
trap cleanup EXIT
tar -xzf "$archive" -C "$work"
dump=$(find "$work" -name database.dump -type f -print -quit)
test -n "$dump"
docker compose exec -T postgres createdb -U rctf "$database"
docker compose exec -T postgres pg_restore -U rctf --exit-on-error --no-owner -d "$database" < "$dump"
tables=$(docker compose exec -T postgres psql -U rctf -d "$database" -Atc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
test "$tables" -gt 0
tar -tzf "$(dirname "$dump")/uploads.tar.gz" > /dev/null
test -s "$(dirname "$dump")/.env"
printf 'Restore verified: %s public tables; uploads and configuration present.\n' "$tables"
