#!/usr/bin/env zsh
set -euo pipefail

./opa064 fmt --fail policy/*.rego
./opa064 check policy/*.rego
./opa064 test  -v    policy

for f in sess_trusted sess_partner sess_unknown; do
  echo "== $f =="
  ./opa064 eval -f pretty -i examples/${f}.jsonl \
    -d policy/agent.rego -d policy/labels.yaml \
    'data.agent.gate_decisions'
done

echo "== sess_partner_warn =="
./opa064 eval -f pretty \
  -i examples/sess_partner_warn.jsonl \
  -d policy/agent.rego -d policy/labels.yaml -d policy/warn.json \
  'data.agent.gate_decisions'
