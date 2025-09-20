# OPA 手元チートシート
- 主要コマンド: `opa fmt --fail`, `opa check`, `opa test -v`
- シナリオ実行:
  - trusted: `./opa064 eval -f pretty -i examples/sess_trusted.jsonl -d policy/agent.rego -d policy/labels.yaml 'data.agent.gate_decisions'`
  - partner: `./opa064 eval -f pretty -i examples/sess_partner.jsonl -d policy/agent.rego -d policy/labels.yaml 'data.agent.gate_decisions'`
  - unknown: `./opa064 eval -f pretty -i examples/sess_unknown.jsonl -d policy/agent.rego -d policy/labels.yaml 'data.agent.gate_decisions'`
  - partner+warn: `./opa064 eval -f pretty -i examples/sess_partner_warn.jsonl -d policy/agent.rego -d policy/labels.yaml -d policy/warn.json 'data.agent.gate_decisions'`
