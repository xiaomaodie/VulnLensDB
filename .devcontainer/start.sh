#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/VulnLensDB
python -m backend.catalog
if python -c 'import json,urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:5000/health",timeout=2)).get("stage")=="catalog"' 2>/dev/null; then
  echo "Catalog ready on port 5000."
  exit 0
fi
nohup python -m flask --app backend.app run --host 0.0.0.0 --port 5000 > /tmp/vulnlens-api.log 2>&1 < /dev/null &
pid=$!
for attempt in $(seq 1 30); do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "Start failed. Check /tmp/vulnlens-api.log and any service already using port 5000."
    exit 1
  fi
  if python -c 'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:5000/",timeout=2).status==200' 2>/dev/null; then
    echo "Open port 5000 for the course catalog."
    exit 0
  fi
  sleep 2
done
echo "Startup check failed. See /tmp/vulnlens-api.log."
exit 1
