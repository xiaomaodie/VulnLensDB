#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/VulnLensDB
if python -c 'import json,urllib.request; r=json.load(urllib.request.urlopen("http://127.0.0.1:5000/health", timeout=2)); assert r["service"] == "VulnLensDB"' 2>/dev/null; then
  echo "VulnLensDB is already running on port 5000."
  exit 0
fi
nohup python -m flask --app backend.app run --host 0.0.0.0 --port 5000 > /tmp/vulnlens-api.log 2>&1 < /dev/null &
for attempt in $(seq 1 30); do
  if python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:5000/health/db", timeout=2)' 2>/dev/null; then
    echo "VulnLensDB and MySQL are ready. Open port 5000 and visit /health/db."
    exit 0
  fi
  sleep 2
done
echo "Startup check failed. See /tmp/vulnlens-api.log."
exit 1
