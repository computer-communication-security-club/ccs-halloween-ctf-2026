#!/usr/bin/env bash
# DEAD SIGNAL — organizer build script (repository layout).
#
# Regenerates src/generated_constants.h from the current flag/token and builds
# the local QA binaries into src/build/ (gitignored). The PLAYER HANDOUT is
# built by Docker instead:
#   uv run tools/ctf.py dist challenges/rev/dead-signal
#
# Configuration (env vars, all optional):
#   DEAD_SIGNAL_FLAG   flag string; else ROOT/flag.txt; else auto-generated
#                      default ccsCTF{dead_signal_<unique_suffix>}
#   DEAD_SIGNAL_TOKEN  24-char [A-Z0-9] token; else random
#   SEED               RNG seed for reproducible generator runs
#
# Outputs:
#   src/generated_constants.h   embedded constants (contains NO plaintext flag)
#   src/build/dead_signal       stripped binary (QA)
#   src/build/dead_signal_bypass  test-only forced-acceptance build
#   src/tests/token.txt         the correct authentication token (private)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="$ROOT/src/gen_constants.py"
FLAG_FILE="$ROOT/flag.txt"
TOKEN_FILE="$ROOT/src/tests/token.txt"

echo "[build] challenge root: $ROOT"

if [ -n "${REUSE_CONSTANTS:-}" ]; then
    echo "[build] REUSE_CONSTANTS: compiling the committed generated_constants.h"
    [ -f "$ROOT/src/generated_constants.h" ] || { echo "missing src/generated_constants.h"; exit 1; }
    mkdir -p "$ROOT/src/build"
    CC="${CC:-gcc}"
    CFLAGS="-O2 -std=c11 -Wall -Wextra -fno-ident"
    $CC $CFLAGS -o "$ROOT/src/build/dead_signal" "$ROOT/src/dead_signal.c"
    strip --strip-all "$ROOT/src/build/dead_signal"
    $CC $CFLAGS -DDSIG_BYPASS -o "$ROOT/src/build/dead_signal_bypass" "$ROOT/src/dead_signal.c"
    strip --strip-all "$ROOT/src/build/dead_signal_bypass"
    echo "[build] done."
    exit 0
fi

GEN_ARGS=(--out "$ROOT/src/generated_constants.h"
          --token-out "$TOKEN_FILE"
          --flag-out "$FLAG_FILE")

if [ -n "${DEAD_SIGNAL_FLAG:-}" ]; then
    GEN_ARGS+=(--flag "$DEAD_SIGNAL_FLAG")
    echo "[build] flag: from DEAD_SIGNAL_FLAG"
elif [ -s "$FLAG_FILE" ] && grep -q '^ccsCTF{' "$FLAG_FILE"; then
    GEN_ARGS+=(--flag-file "$FLAG_FILE")
    echo "[build] flag: from $FLAG_FILE"
else
    echo "[build] flag: auto-generated unique default"
fi

if [ -n "${DEAD_SIGNAL_TOKEN:-}" ]; then
    GEN_ARGS+=(--token "$DEAD_SIGNAL_TOKEN")
    echo "[build] token: from DEAD_SIGNAL_TOKEN"
else
    echo "[build] token: random"
fi
if [ -n "${SEED:-}" ]; then
    GEN_ARGS+=(--seed "$SEED")
fi

python3 "$GEN" "${GEN_ARGS[@]}"

mkdir -p "$ROOT/src/build"
CC="${CC:-gcc}"
CFLAGS="-O2 -std=c11 -Wall -Wextra -fno-ident"

echo "[build] compiling src/build/dead_signal"
$CC $CFLAGS -o "$ROOT/src/build/dead_signal" "$ROOT/src/dead_signal.c"
strip --strip-all "$ROOT/src/build/dead_signal"

echo "[build] compiling src/build/dead_signal_bypass (test-only)"
$CC $CFLAGS -DDSIG_BYPASS -o "$ROOT/src/build/dead_signal_bypass" "$ROOT/src/dead_signal.c"
strip --strip-all "$ROOT/src/build/dead_signal_bypass"

echo "[build] done."
