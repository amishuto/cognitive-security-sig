package agent

test_trusted_allow {
	input := {"steps": [{"tool": "http_post", "args": {"url": "https://www.yourcorp.jp/submit", "data_class": "LOW"}}]}
	r := data.agent.gate_decisions[_] with input as input
	r.zone == "TRUSTED"
	r.data_class == "LOW"
	r.risky == false
	r.gate == "ALLOW"
}

test_partner_confirm {
	input := {"steps": [{}, {}, {"tool": "http_post", "args": {"url": "https://partner.example/submit", "data_class": "HIGH"}}]}
	r := data.agent.gate_decisions[_] with input as input
	r.zone == "PARTNER"
	r.data_class == "HIGH"
	r.gate == "CONFIRM"
}

test_unknown_block {
	input := {"steps": [{"tool": "http_post", "args": {"url": "https://evil.tld/collect", "data_class": "LOW"}}]}
	r := data.agent.gate_decisions[_] with input as input
	r.zone == "UNKNOWN"
	r.gate == "BLOCK"
}
