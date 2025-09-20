#!/usr/bin/env bash
set -euo pipefail
./opa064 fmt --fail policy/*.rego
./opa064 check policy/*.rego
./opa064 test  -v    policy
echo "---- eval (trusted) ----"
./opa064 eval -f pretty -i examples/sess_trusted.jsonl \
  -d policy/agent.rego -d policy/labels.yaml 'data.agent.gate_decisions' | tee artifacts/eval_trusted.json
echo "---- eval (partner) ----"
./opa064 eval -f pretty -i examples/sess_partner.jsonl \
  -d policy/agent.rego -d policy/labels.yaml 'data.agent.gate_decisions' | tee artifacts/eval_partner.json
echo "---- eval (unknown) ----"
./opa064 eval -f pretty -i examples/sess_unknown.jsonl \
  -d policy/agent.rego -d policy/labels.yaml 'data.agent.gate_decisions' | tee artifacts/eval_unknown.json
echo "---- eval (partner + warn) ----"
./opa064 eval -f pretty -i examples/sess_partner_warn.jsonl \
  -d policy/agent.rego -d policy/labels.yaml -d policy/warn.json \
  'data.agent.gate_decisions' | tee artifacts/eval_partner_warn.json
