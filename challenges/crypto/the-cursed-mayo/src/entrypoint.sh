#!/bin/sh
set -eu
umask 077
mkdir -p "$CURSED_DATA_DIR"
if [ ! -s "$CURSED_DATA_DIR/pk.bin" ] || \
   [ ! -s "$CURSED_DATA_DIR/O.bin" ] || \
   [ ! -s "$CURSED_DATA_DIR/csk.bin" ]; then
    "$CURSED_APP_DIR/cursed_signer" keygen \
        "$CURSED_DATA_DIR/pk.bin" \
        "$CURSED_DATA_DIR/O.bin" \
        "$CURSED_DATA_DIR/csk.bin"
fi
chmod 600 "$CURSED_DATA_DIR/pk.bin" "$CURSED_DATA_DIR/O.bin" "$CURSED_DATA_DIR/csk.bin" 2>/dev/null || true
exec python3 "$CURSED_APP_DIR/server.py"
