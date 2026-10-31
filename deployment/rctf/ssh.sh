#!/bin/bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec ssh -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$root/.local/known_hosts" \
  -i "$root/.local/id_rsa" ubuntu@13.215.75.166 "$@"
