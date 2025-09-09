#!/usr/bin/env bash
set -euo pipefail

OPA_BIN="${OPA_BIN:-opa}" # CIでは /usr/local/bin/opa を想定
POLICY_REGO="policy/agent.rego"
POLICY_LABELS="policy/labels.yaml"
POLICY_WARN="policy/warn.json"

SC_PARTNER="examples/sess_partner.jsonl"
SC_UNKNOWN="examples/sess_unknown.jsonl"
SC_TRUSTED="examples/sess_trusted.jsonl"
SC_PARTNER_WARN="examples/sess_partner_warn.jsonl"

QUERY='data.agent.gate_decisions'

req() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 1; }; }
req "$OPA_BIN"
req jq

# 共通ランナー
eval_json () {
  local input="$1"; shift
  local extra=(-d "$POLICY_REGO" -d "$POLICY_LABELS")
  [[ -f "$POLICY_WARN" && "$input" == *"_warn."* ]] && extra+=(-d "$POLICY_WARN")
  "$OPA_BIN" eval -f json -i "$input" "${extra[@]}" "$QUERY" | jq -c '.result[0].expressions[0].value'
}

assert_eq () {
  local actual="$1" expect="$2" label="$3"
  if [[ "$actual" != "$expect" ]]; then
    echo "[FAIL] $label: expected=$expect got=$actual"
    exit 1
  else
    echo "[ OK ] $label: $actual"
  fi
}

echo "== OPA fmt & check =="
"$OPA_BIN" fmt -w "$POLICY_REGO"
"$OPA_BIN" check "$POLICY_REGO"

echo "== Scenarios =="
# 1) PARTNER → CONFIRM
j=$(eval_json "$SC_PARTNER")
gate=$(jq -r '.[0].gate' <<<"$j")
assert_eq "$gate" "CONFIRM" "PARTNER gate"

# 2) UNKNOWN → BLOCK
j=$(eval_json "$SC_UNKNOWN")
gate=$(jq -r '.[0].gate' <<<"$j")
assert_eq "$gate" "BLOCK" "UNKNOWN gate"

# 3) TRUSTED → ALLOW
j=$(eval_json "$SC_TRUSTED")
gate=$(jq -r '.[0].gate' <<<"$j")
assert_eq "$gate" "ALLOW" "TRUSTED gate"

# 4) PARTNER + WARN(high) → risky:true & CONFIRM
j=$(eval_json "$SC_PARTNER_WARN")
gate=$(jq -r '.[0].gate' <<<"$j")
risky=$(jq -r '.[0].risky' <<<"$j")
assert_eq "$gate"  "CONFIRM"        "PARTNER_WARN gate"
assert_eq "$risky" "true"           "PARTNER_WARN risky"

echo "All assertions passed."
