# OPA / Rego 手元チートシート

## CIバッジ（README用）
[![OPA CI](https://github.com/amishuto/cognitive-security-sig/actions/workflows/opa-ci.yml/badge.svg)](https://github.com/amishuto/cognitive-security-sig/actions/workflows/opa-ci.yml)

## 基本検証
make fmt && make fmtcheck && make check && make test

## シナリオ実行例
./opa064 eval -f pretty -i examples/sess_trusted.jsonl \
  -d policy/agent.rego -d policy/labels.yaml 'data.agent.gate_decisions'

./opa064 eval -f pretty -i examples/sess_partner.jsonl \
  -d policy/agent.rego -d policy/labels.yaml 'data.agent.gate_decisions'

./opa064 eval -f pretty -i examples/sess_unknown.jsonl \
  -d policy/agent.rego -d policy/labels.yaml 'data.agent.gate_decisions'

./opa064 eval -f pretty -i examples/sess_partner_warn.jsonl \
  -d policy/agent.rego -d policy/labels.yaml -d policy/warn.json \
  'data.agent.gate_decisions'
