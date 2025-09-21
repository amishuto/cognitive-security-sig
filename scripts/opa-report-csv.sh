#!/usr/bin/env bash
set -euo pipefail
mkdir -p artifacts/report

# ヘッダ（reason を追加）
echo 'session,idx,step,zone,data_class,risky,gate,reason,risk_score,over_budget' > artifacts/report/summary_decisions.csv

shopt -s nullglob
for f in artifacts/report/*.summary.json; do
  sess="$(basename "$f" .summary.json)"
  jq -r --arg s "$sess" '
    # OPAの -f json 出力にも素のJSONにも対応
    def getv: if (type=="object" and has("result")) then .result[0].expressions[0].value else . end;

    getv as $v
    | ($v.explain // []) as $ex
    # step -> why のマップを作る
    | (reduce $ex[] as $e ({}; .[ ($e.step|tostring) ] = ($e.why // ""))) as $why
    # decisions を行化
    | ($v.decisions // []) | to_entries[]
    | [ $s
      , .key
      , (.value.step // "")
      , (.value.zone // "")
      , (.value.data_class // "")
      , (.value.risky // false)
      , (.value.gate // "")
      , ($why[(.value.step|tostring)] // "")
      , ($v.risk_score // 0)
      , ($v.over_budget // false)
      ] | @csv
  ' "$f" >> artifacts/report/summary_decisions.csv
done

echo "wrote artifacts/report/summary_decisions.csv"
