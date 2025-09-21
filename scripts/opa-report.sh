#!/usr/bin/env bash
set -euo pipefail
mkdir -p artifacts/report
for f in examples/sess_*.jsonl; do
  base="$(basename "$f" .jsonl)"
  # warn.json は常時読み込んでも無害（該当しなければ空）
  ./opa064 eval -f json \
    -i "$f" \
    -d policy/agent.rego -d policy/labels.yaml -d policy/warn.json \
    'data.agent.summary' \
    | jq '.' > "artifacts/report/${base}.summary.json"
  echo "wrote artifacts/report/${base}.summary.json"
done
