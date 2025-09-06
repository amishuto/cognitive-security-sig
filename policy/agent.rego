package agent.policy

url_allowlisted(u) {
  some d
  startswith(u, d)
  d := input.policy.destinations.TRUSTED[_]
}

warn[{"rule":"no_http_plaintext","step":i,"reason":"HTTP"}] {
  input.steps[i].tool == "http_post"
  startswith(input.steps[i].args.url, "http://")
}

warn[{"rule":"pii_to_unknown","from":pii,"to":post,"reason":"PII->UNKNOWN"}] {
  some pii, post
  input.steps[pii].tool == "extract_pii"
  input.steps[post].tool == "http_post"
  post > pii
  not url_allowlisted(input.steps[post].args.url)
}

warn[{"rule":"domain_not_allowlisted","step":i,"reason":"unknown destination"}] {
  input.steps[i].tool == "http_post"
  not url_allowlisted(input.steps[i].args.url)
}
