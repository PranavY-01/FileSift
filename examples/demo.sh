#!/usr/bin/env bash
set -u
rm -rf demo-data state reports
mkdir -p demo-data/config demo-data/scripts state reports

printf '{"debug": false}' > demo-data/config/settings.json
printf 'print("backup")\n' > demo-data/scripts/backup.py
printf 'print("legacy")\n' > demo-data/old_script.py

filesift init-baseline demo-data --baseline state/baseline.json

filesift scan demo-data --baseline state/baseline.json
echo "exit code: $?"                                   # expected 0

printf '{"debug": true}' > demo-data/config/settings.json
printf 'print("new")\n' > demo-data/scripts/new_task.py
rm demo-data/old_script.py
chmod +x demo-data/scripts/backup.py

filesift scan demo-data --baseline state/baseline.json --report reports/scan.json
echo "exit code: $?"                                   # expected 1

filesift scan demo-data --baseline state/baseline.json --format json | python -m json.tool | head -n 20
