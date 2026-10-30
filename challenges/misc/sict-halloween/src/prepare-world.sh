#!/usr/bin/env bash
# Render private image contents; never print the flag or its fragments.
set -euo pipefail
world=$1
flag_file=$2
flag=$(cat "$flag_file")
pattern='^ccsCTF\{[A-Za-z0-9_!?@#$%^&*.-]+\}$'
if [[ ! $flag =~ $pattern ]]; then
  printf '%s\n' 'Invalid flag format' >&2
  exit 1
fi
width=$(( (${#flag} + 3) / 4 ))
if (( 3 * width >= ${#flag} )); then
  printf '%s\n' 'Flag too short for four fragments' >&2
  exit 1
fi
functions="$world/datapacks/sict-campus"
for n in 1 2 3 4; do
  token="@@FRAGMENT_${n}@@"
  count=$(grep -Roh --include='*.mcfunction' --include='*.json' "$token" "$functions" | wc -l)
  if (( count != 2 )); then
    printf '%s\n' 'Each fragment needs exactly two templates' >&2
    exit 1
  fi
done
for n in 1 2 3 4; do
  offset=$(( (n - 1) * width ))
  part=${flag:$offset:$width}
  # The accepted alphabet excludes slash/backslash; escape sed's replacement &.
  replacement=${part//&/\\&}
  find "$functions" -type f \( -name '*.mcfunction' -o -name '*.json' \) \
    -exec sed -i.sict-render-backup "s/@@FRAGMENT_${n}@@/${replacement}/g" {} +
done
find "$functions" -type f -name '*.sict-render-backup' -delete
printf '%s\n' 'Prepared four private fragment item names.'
