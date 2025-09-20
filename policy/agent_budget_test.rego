package agent_budget_test

import data.agent

# フィクスチャ（部分置換で使う）
fixture_destinations := {
	"TRUSTED": ["https://www.yourcorp.jp", "https://api.yourcorp.jp"],
	"PARTNER": ["https://partner.example/"],
}

fixture_budget := 3

# 予算超過の単体テスト：HIGH(3) + MEDIUM(2) = 5 >= 3
test_over_budget_true {
	in := {"steps": []}
	warns := [
		{"step": 0, "severity": "HIGH"},
		{"step": 1, "severity": "MEDIUM"},
	]

	agent.over_budget with input as in
		with data.destinations as fixture_destinations
		with data.risk_budget as fixture_budget
		with data.agent.policy.warn as warns
}

# zone ヘルパの単体テスト（PARTNERを返すこと）
test_zone_helper_partner {
	z := agent.zone("https://partner.example/submit") with data.destinations as fixture_destinations
		with data.risk_budget as fixture_budget
	z == "PARTNER"
}
