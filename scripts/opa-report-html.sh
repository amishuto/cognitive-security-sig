#!/usr/bin/env bash
set -euo pipefail

in_dir="artifacts/report"
out="${in_dir}/index.html"
mkdir -p "$in_dir"

rows=""
shopt -s nullglob
for f in "${in_dir}"/*.summary.json; do
  session="$(basename "$f" .summary.json)"
  part="$(jq -r --arg s "$session" '
    # OPAの -f json 出力にも素のJSONにも対応
    def getv:
      if type=="object" and has("result") then .result[0].expressions[0].value
      elif type=="object" then .
      else . end;
    # 文字列エスケープ（引数付き）
    def esc($x): ($x|tostring | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;"));

    getv as $v
    | ($v.decisions // [])           # decisions は配列
    | to_entries[]                   # => {key: idx, value: {...}}
    | "<tr>"
      + "<td>" + esc($s) + "</td>"
      + "<td>" + (.key|tostring) + "</td>"
      + "<td>" + ((.value.step // "")|tostring) + "</td>"
      + "<td>" + esc(.value.zone // "") + "</td>"
      + "<td>" + esc(.value.data_class // "") + "</td>"
      + "<td>" + ((.value.risky // false)|tostring) + "</td>"
      + "<td>" + esc(.value.gate // "") + "</td>"
      + "<td>" + (($v.risk_score // 0)|tostring) + "</td>"
      + "<td>" + (($v.over_budget // false)|tostring) + "</td>"
      + "</tr>"
  ' "$f")"
  rows+="$part"$'\n'
done

cat > "$out" <<HTML
<!doctype html>
<meta charset="utf-8">
<title>OPA Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:24px}
h1{font-size:20px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px}
th{background:#f6f8fa;text-align:left}
tbody tr:nth-child(even){background:#fafafa}
small{color:#666}
</style>
<h1>OPA Report <small>(decisions)</small></h1>
<table>
  <thead>
    <tr>
      <th>session</th><th>idx</th><th>step</th><th>zone</th><th>data_class</th>
      <th>risky</th><th>gate</th><th>risk_score</th><th>over_budget</th>
    </tr>
  </thead>
  <tbody>
${rows}
  </tbody>
</table>
<p>Source: <code>artifacts/report/*.summary.json</code></p>
HTML

echo "wrote $out"
