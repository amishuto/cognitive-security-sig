#!/usr/bin/env bash
set -euo pipefail

out_dir="artifacts/report"
mkdir -p "$out_dir"
csv="$out_dir/summary_decisions.csv"

# ヘッダ
printf '%s\n' 'session,idx,step,zone,data_class,risky,gate,risk_score,over_budget' > "$csv"

shopt -s nullglob
for f in "$out_dir"/*.summary.json; do
  base="$(basename "$f" .summary.json)"
  BASE="$base" jq -r '
    # ラッパー対応：.result[0].expressions[0].value or 直値
    def getv: if has("result") then .result[0].expressions[0].value else . end;

    getv as $v
    | (($v.decisions // []) | to_entries[])
    | [
        env.BASE,                   # session
        .key,                       # idx
        (.value.step // null),      # step
        (.value.zone // ""),        # zone
        (.value.data_class // ""),  # data_class
        (.value.risky // false),    # risky
        (.value.gate // ""),        # gate
        ($v.risk_score // 0),       # risk_score
        ($v.over_budget // false)   # over_budget
      ]
    | @csv
  ' "$f" >> "$csv"
done

echo "wrote $csv"
