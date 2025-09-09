#!/usr/bin/env bash
set -euo pipefail

# === Settings ===
OPA_BIN="${OPA_BIN:-./opa064}"          # 環境変数で上書き可
POLICY_REGO="policy/agent.rego"
POLICY_LABELS="policy/labels.yaml"
POLICY_WARN="policy/warn.json"          # ある場合だけ使う

SC_PARTNER="examples/sess_partner.jsonl"
SC_UNKNOWN="examples/sess_unknown.jsonl"
SC_TRUSTED="examples/sess_trusted.jsonl"
SC_PARTNER_WARN="examples/sess_partner_warn.jsonl"

QUERY='data.agent.gate_decisions'

# === Helpers ===
c() { tput setaf "$1" 2>/dev/null || true; }
ce() { tput sgr0 2>/dev/null || true; }

check_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    echo "$(c 1)[X]$(ce) missing: $f" >&2
    exit 1
  fi
}

opa_eval() {
  local input="$1"; shift
  local extra=(-d "$POLICY_REGO" -d "$POLICY_LABELS")
  # WARN データが存在していて、シナリオが *_warn なら追加
  if [[ -f "$POLICY_WARN" && "$input" == *"_warn."* ]]; then
    extra+=(-d "$POLICY_WARN")
  fi
  "$OPA_BIN" eval -f pretty -i "$input" "${extra[@]}" "$QUERY"
}

section() {
  echo
  echo "$(c 4)==== $* ====$(ce)"
}

# === Pre-flight ===
check_file "$OPA_BIN"
check_file "$POLICY_REGO"
check_file "$POLICY_LABELS"
for f in "$SC_PARTNER" "$SC_UNKNOWN" "$SC_TRUSTED" "$SC_PARTNER_WARN"; do
  check_file "$f"
done

# === Lint / Static check ===
section "Formatting & Static Check"
"$OPA_BIN" fmt -w "$POLICY_REGO"
"$OPA_BIN" check "$POLICY_REGO"
echo "$(c 2)[OK]$(ce) Rego format & check passed"

echo -n "YAML load test (risk_budget): "
"$OPA_BIN" eval -f pretty -d "$POLICY_LABELS" 'data.risk_budget' || true

# === Run scenarios ===
section "Scenario: PARTNER  → expect gate=CONFIRM"
opa_eval "$SC_PARTNER"

section "Scenario: UNKNOWN  → expect gate=BLOCK"
opa_eval "$SC_UNKNOWN"

section "Scenario: TRUSTED  → expect gate=ALLOW"
opa_eval "$SC_TRUSTED"

section "Scenario: PARTNER + WARN(high) → expect risky=true & gate=CONFIRM"
opa_eval "$SC_PARTNER_WARN"

echo
echo "$(c 2)All scenarios executed.$(ce)  (Set OPA_BIN=/path/to/opa to use a different binary)"
