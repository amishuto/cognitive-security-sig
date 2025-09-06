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
  z = "TRUSTED"; zt_zone_trusted(u)
} else = z {
  z = "PARTNER"; not zt_zone_trusted(u); zt_zone_partner(u)
} else = z {
  z = "UNKNOWN"; not zt_zone_trusted(u); not zt_zone_partner(u)
}

# ===== Data class (fallback) =====
data_class(s, dc) { dc = s.args.data_class }
data_class(s, "LOW") { not s.args.data_class }

# ===== Gate rules =====
gate("TRUSTED", "LOW", false, "ALLOW")
gate("TRUSTED", _,     true,  "CONFIRM")
gate("PARTNER", "LOW", false, "CONFIRM")
gate("PARTNER", _,     _,     "CONFIRM")
gate("UNKNOWN", _,     _,     "BLOCK")

# ---- Cognitive WARN (safe, optional) ----
warn_defined { data.agent.policy.warn }
related_to_step(i, w) { w.step == i }
related_to_step(i, w) { w.to   == i }
related_to_step(i, w) { w.from == i }
is_risky(i) {
  warn_defined
  count([1 |
    w := data.agent.policy.warn[_];
    related_to_step(i, w);
    lower(w.severity) == "high"
  ]) > 0
}

# helper: always binds boolean
risky(i) = true  { is_risky(i) }
else     = false { not is_risky(i) }

# single rule
gate_decisions[res] {
  some i
  s := input.steps[i]
  s.tool == "http_post"

  z := zone(s.args.url)
  data_class(s, dc)
  r := risky(i)

  gate(z, dc, r, decision)

  res = {"step": i, "zone": z, "data_class": dc, "risky": r, "gate": decision}
}

# (optional) risk budget (kept minimal & safe)
sev_to_score("high", 3)
sev_to_score("medium", 2)
sev_to_score("low", 1)
sev_to_score(_, 0)

risk_score := sum([score |
  warn_defined;
  w := data.agent.policy.warn[_];
  s := lower(w.severity);
  (s == "high";   score = 3) |
  (s == "medium"; score = 2) |
  (s == "low";    score = 1)
])

over_budget {
  data.risk_budget
  rb := data.risk_budget
  risk_score >= rb
}
