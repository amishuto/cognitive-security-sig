package agent

# ===== Zone match (safe) =====
zt_zone_trusted(u) {
	count([1 |
		data.destinations
		data.destinations.TRUSTED
		p := data.destinations.TRUSTED[_]
		startswith(u, p)
	]) > 0
}

zt_zone_partner(u) {
	count([1 |
		data.destinations
		data.destinations.PARTNER
		p := data.destinations.PARTNER[_]
		startswith(u, p)
	]) > 0
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
}

else = "LOW" {
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

# single rule
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

# severity → score
sev_to_score(s) = n {
	ls := lower(s)
	n := {"high": 3, "medium": 2, "low": 1}[ls]
} else = 0

# sum scores of all WARNs (0 if none)
risk_score = sum([sev_to_score(w.severity) |
	warn_defined
	w := data.agent.policy.warn[_]
])

over_budget {
	data.risk_budget
	rb := data.risk_budget
	risk_score >= rb
}

gate_decision(z, dc, r) = "ALLOW" {
	z == "TRUSTED"
	dc == "LOW"
	r == false
}

else = "CONFIRM" {
	z == "TRUSTED"
	r == true
}

else = "CONFIRM" {
	z == "PARTNER"
}

else = "BLOCK" {
	z == "UNKNOWN"
}
