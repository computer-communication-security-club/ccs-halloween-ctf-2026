#!/usr/bin/env bash
# DEAD SIGNAL — clean-environment compatibility test (repository layout).
#
# Runs the distributed handout (dist/dead_signal) inside a stock Ubuntu LTS
# container and checks: it is a dynamically linked ELF against plain glibc,
# the correct token releases the flag, a wrong token is rejected without
# leaking, and invalid input is rejected.
#
# Usage: bash src/tests/clean_ubuntu_test.sh [image]   (default ubuntu:24.04)

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMG="${1:-ubuntu:24.04}"
TOKEN="$(cat "$ROOT/src/tests/token.txt")"
FLAG="$(cat "$ROOT/flag.txt")"

echo "[clean-ubuntu] image: $IMG"
echo "[clean-ubuntu] mounting $ROOT/dist -> /chal (ro)"

docker run --rm -i \
    -v "$ROOT/dist:/chal:ro" \
    -e TOKEN="$TOKEN" \
    -e FLAG="$FLAG" \
    "$IMG" bash -s <<'EOS'
set -u
fail=0

echo "--- file type"
file /chal/dead_signal 2>/dev/null || echo "(file not in base image)"
ldd /chal/dead_signal

echo "--- correct token"
out="$(printf '%s\n' "$TOKEN" | /chal/dead_signal 2>/dev/null)"; rc=$?
if [ $rc -eq 0 ] && printf '%s' "$out" | grep -qF "$FLAG"; then
  echo "[PASS] correct token released the flag (exit $rc)"
else
  echo "[FAIL] correct token: rc=$rc out=${out: -120}"
  fail=1
fi

echo "--- wrong token"
out="$(printf 'AAAAAAAAAAAAAAAAAAAAAAAA\n' | /chal/dead_signal 2>/dev/null)"; rc=$?
if [ $rc -ne 0 ] && ! printf '%s' "$out" | grep -qF "$FLAG"; then
  echo "[PASS] wrong token rejected (exit $rc)"
else
  echo "[FAIL] wrong token: rc=$rc out=${out: -120}"
  fail=1
fi

echo "--- invalid length"
out="$(printf 'SHORT\n' | /chal/dead_signal 2>/dev/null)"; rc=$?
if [ $rc -ne 0 ]; then
  echo "[PASS] invalid length rejected (exit $rc)"
else
  echo "[FAIL] invalid length accepted"
  fail=1
fi

exit $fail
EOS
status=$?
if [ $status -eq 0 ]; then
    echo "[clean-ubuntu] ALL PASS"
else
    echo "[clean-ubuntu] FAILURES (status $status)"
fi
exit $status
