#!/bin/sh
set -eu
umask 077
case "${EULA:-FALSE}" in
  TRUE|true) ;;
  *) printf '%s\n' 'Set EULA=TRUE after accepting https://www.minecraft.net/eula' >&2; exit 1 ;;
esac
memory=${MEMORY:-4G}
max_players=${MAX_PLAYERS:-20}
case "$memory" in
  ''|*[!0-9MGmg]*) printf '%s\n' 'MEMORY must be a heap size such as 4G or 2048M' >&2; exit 1 ;;
esac
case "$max_players" in
  ''|*[!0-9]*|0) printf '%s\n' 'MAX_PLAYERS must be a positive integer' >&2; exit 1 ;;
esac
cd /data
if [ ! -f sict/level.dat ]; then
  if [ -e sict ]; then
    printf '%s\n' 'Existing sict directory is incomplete; restore its backup instead of overwriting it.' >&2
    exit 1
  fi
  staging=".sict-import-$$"
  trap 'rm -rf "$staging"' EXIT HUP INT TERM
  cp -R /opt/sict/world "$staging"
  mv "$staging" sict
  trap - EXIT HUP INT TERM
fi
if [ ! -s .rcon-password ]; then
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > .rcon-password
fi
password=$(cat .rcon-password)
case "$password" in ''|*[!0-9a-f]*) printf '%s\n' 'Invalid stored RCON password' >&2; exit 1 ;; esac
printf 'eula=true\n' > eula.txt
cat > server.properties <<PROPERTIES
server-ip=
server-port=25565
level-name=sict
motd=CCS Halloween CTF
gamemode=adventure
force-gamemode=true
difficulty=normal
hardcore=false
online-mode=false
enforce-secure-profile=false
spawn-protection=0
max-players=$max_players
view-distance=8
simulation-distance=6
enable-query=false
enable-status=true
enable-rcon=true
rcon.port=25575
rcon.password=$password
broadcast-rcon-to-ops=false
broadcast-console-to-ops=false
white-list=false
sync-chunk-writes=true
allow-flight=false
accepts-transfers=false
hide-online-players=true
log-ips=false
enable-jmx-monitoring=false
management-server-enabled=false
op-permission-level=2
function-permission-level=2
rate-limit=200
player-idle-timeout=15
pause-when-empty-seconds=60
max-chained-neighbor-updates=100000
max-tick-time=60000
network-compression-threshold=256
PROPERTIES
printf 'host: 127.0.0.1\nport: 25575\npassword: %s\n' "$password" > .rcon-cli.yaml
exec java -Xms512M "-Xmx$memory" -Duser.home=/data -Djava.io.tmpdir=/tmp -jar /opt/sict/server.jar nogui
