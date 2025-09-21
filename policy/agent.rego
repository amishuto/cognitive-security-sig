package agent

# ===== Zone match (safe; prefix-only) =====
zt_zone_trusted(u) {
	data.destinations
	data.destinations.TRUSTED
	p := data.destinations.TRUSTED[_]
	startswith(u, p)
}

zt_zone_partner(u) {
	data.destinations
	data.destinations.PARTNER
	p := data.destinations.PARTNER[_]
	startswith(u, p)
}

zone(u) = z {
	z = "TRUSTED"
	zt_zone_trusted(u)
} else = z {
	z = "PARTNER"
	not zt_zone_trusted(u)
	zt_zone_partner(u)
} else = z {
	z = "UNKNOWN"
	not zt_zone_trusted(u)
	not zt_zone_partner(u)
}

# ===== Data class (fallback) =====
data_class(s) = dc {
	dc := s.args.data_class
} else = "LOW" {
	not s.args.data_class
}

# ===== Gate rules =====
gate("TRUSTED", "LOW", false, "ALLOW")

gate("TRUSTED", _, true, "CONFIRM")

gate("PARTNER", "LOW", false, "CONFIRM")

gate("PARTNER", _, _, "CONFIRM")

gate("UNKNOWN", _, _, "BLOCK")

# ---- Cognitive WARN (safe, optional) ----
warn_defined {
	data.agent.policy.warn
}

related_to_step(i, w) {
	w.step == i
}

related_to_step(i, w) {
	w.to == i
}

related_to_step(i, w) {
	w.from == i
}

is_risky(i) {
	warn_defined
	count([1 |
		w := data.agent.policy.warn[_]
		related_to_step(i, w)
		lower(w.severity) == "high"
	]) > 0
}

# helper: always binds boolean
risky(i) {
	is_risky(i)
}

else = false {
	not is_risky(i)
}

# single rule: one decision per http_post step
gate_decisions[res] {
	some i
	s := input.steps[i]
	s.tool == "http_post"

	z := zone(s.args.url)
	dc := data_class(s)
	r := risky(i)

	decision := gate_decision(z, dc, r)

	res := {"step": i, "zone": z, "data_class": dc, "risky": r, "gate": decision}
}

# ===== Risk budget (safe, minimal) =====
sev_to_score(s) = n {
	ls := lower(s)
	n := {"high": 3, "medium": 2, "low": 1}[ls]
} else = 0

risk_score = sum([sev_to_score(w.severity) |
	warn_defined
	w := data.agent.policy.warn[_]
])

over_budget {
	data.risk_budget
	rb := data.risk_budget
	risk_score >= rb
}

# decision function (total)
gate_decision(z, dc, r) = "ALLOW" {
	z == "TRUSTED"
	dc == "LOW"
	r == false
} else = "CONFIRM" {
	z == "TRUSTED"
	r == true
} else = "CONFIRM" {
	z == "PARTNER"
} else = "BLOCK" {
	z == "UNKNOWN"
}

# ---- Explainability helpers (non-invasive) ----
# 与えた input.steps[i] について、判定に使った主要要素を1行で説明
explain_step(i) = why {
  s := input.steps[i]
  s.tool == "http_post"
  z  := zone(s.args.url)
  dc := data_class(s)
  r  := risky(i)
  d  := gate_decision(z, dc, r)
  why := sprintf("zone=%s data_class=%s risky=%v -> %s", [z, dc, r, d])
}

# まとめ出力：各ステップの説明 + 現在のリスク予算状況を添付
explain = [
  {
    "step": i,
    "why":  explain_step(i),
    "risk_score": risk_score,
    "over_budget": over_budget_flag
  } |
  some i; input.steps[i].tool == "http_post"
]

# ---- helpers: boolean wrapper for over_budget ----
over_budget_flag = true { over_budget }
else = false

# ---- Stable summary (for CLI/UX) ----
# decisions: 判定の配列（set→array化）
# explain  : 各ステップの「なぜ」 + 現在のリスク情報
# risk_*, budget: 集計
summary := {
  "decisions": [d | d := gate_decisions[_]],
  "explain":   explain,
  "risk_score": risk_score,
  "over_budget": over_budget_flag,
}
