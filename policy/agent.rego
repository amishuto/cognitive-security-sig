package agent.policy

# 許可ドメインか？
url_allowlisted(u) if {
  allow := input.policy.destinations.TRUSTED[_]
  startswith(u, allow)
}

# 1) HTTP平文送信（POST）
warn contains {"rule":"no_http_plaintext","step": i,"reason":"HTTP (POST)"} if {
  input.steps[i].tool == "http_post"
  startswith(input.steps[i].args.url, "http://")
}

# 1') HTTP平文取得（GET）
warn contains {"rule":"no_http_plaintext","step": i,"reason":"HTTP (GET)"} if {
  input.steps[i].tool == "http_get"
  startswith(input.steps[i].args.url, "http://")
}

# 2) PII抽出 → 未承認ドメインへPOST
warn contains {"rule":"pii_to_unknown","from": pii,"to": post,"reason":"PII->UNKNOWN"} if {
  some pii, post
  input.steps[pii].tool == "extract_pii"
  input.steps[post].tool == "http_post"
  post > pii
  not url_allowlisted(input.steps[post].args.url)
}

# 3) 許可ドメイン外へのPOST
warn contains {"rule":"domain_not_allowlisted","step": i,"reason":"unknown destination"} if {
  input.steps[i].tool == "http_post"
  not url_allowlisted(input.steps[i].args.url)
}

# 4) 行為列が長すぎる（暴走兆候の透明化）
warn contains {"rule":"excessive_chain_length","reason":"long action chain","length": n} if {
  n := count(input.steps)
  n > 6
}
