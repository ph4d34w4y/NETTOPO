#!/bin/bash
# Usage: ./tests/runtest.sh tests/browser/e2e.js
# Runs from the repo root. Requires a Chrome/Chromium (set CHROME_PATH if needed).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
node src/serve.js >/dev/null 2>&1 &
SRV=$!
sleep 2
node "$1" > "/tmp/$(basename "$1").log" 2>&1
EXIT=$?
kill $SRV 2>/dev/null || true
tail -6 "/tmp/$(basename "$1").log"
exit $EXIT
