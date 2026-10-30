#!/bin/sh
set -eu
exec rcon-cli --config /data/.rcon-cli.yaml "$@"
