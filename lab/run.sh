#!/usr/bin/env bash
# Start the lab, run every converted query against every engine, report, tear down.
#   lab/run.sh          run and tear down
#   KEEP=1 lab/run.sh   leave the containers running afterwards
set -euo pipefail
cd "$(dirname "$0")"
SPLUNK_PASSWORD=Lab-$(openssl rand -hex 12)   # random per run, never stored
export SPLUNK_PASSWORD
export SPLUNK_HEC_TOKEN="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"
docker compose up -d
trap '[ "${KEEP:-0}" = 1 ] || docker compose down -v' EXIT
python3 run_lab.py
