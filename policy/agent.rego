package agent.policy

# 許可ドメインか？
url_allowlisted(u) if {
  allow := input.policy.destinations.TRUSTED[_]
  startswith(u, allow)
}

# 1) HTTP平文送信（POST）
warn contains {"rule":"no_http_plaintext","step": i,"reason":"HTTP (POST)","refs":["OWASP-LLM02","NIST SP 800-53 SC-8"]} if {
  input.steps[i].tool == "http_post"
  startswith(input.steps[i].args.url, "http://")
}

# 1') HTTP平文取得（GET）
warn contains {"rule":"no_http_plaintext","step": i,"reason":"HTTP (GET)","refs":["OWASP-LLM02","NIST SP 800-53 SC-8"]} if {
  input.steps[i].tool == "http_get"
  startswith(input.steps[i].args.url, "http://")
}

# 2) PII抽出 → 未承認ドメインへPOST
warn contains {"rule":"pii_to_unknown","from": pii,"to": post,"reason":"PII->UNKNOWN","refs":["OWASP-LLM06","ISO/IEC 29100"]} if {
  some pii, post
  input.steps[pii].tool == "extract_pii"
  input.steps[post].tool == "http_post"
  post > pii
  not url_allowlisted(input.steps[post].args.url)
}

# 3) 許可ドメイン外へのPOST
warn contains {"rule":"domain_not_allowlisted","step": i,"reason":"unknown destination","refs":["Contextual Integrity"]} if {
  input.steps[i].tool == "http_post"
  not url_allowlisted(input.steps[i].args.url)
}

# 4) 行為列が長すぎる（暴走兆候の透明化）
warn contains {"rule":"excessive_chain_length","reason":"long action chain","length": n,"refs":["Operational Risk / Autonomy"]} if {
  n := count(input.steps)
  n > 6
}

# 5-A) Authority-like domain（GET）
warn contains {
  {"rule":"authority_like_domain",
   "step": i,
   "reason":"authority-like domain pattern",
   "refs":["Deception Heuristics","MITRE: Social Engineering"],
   "url": input.steps[i].args.url}
} if {
  input.steps[i].tool == "http_get"
  not url_allowlisted(input.steps[i].args.url)
  regex.match("(?i)://[^/]*(support|help|secure|verify|account|login|gov|official|customer|care)", input.steps[i].args.url)
}

# 5-B) Authority-like domain（POST）
warn contains {
  {"rule":"authority_like_domain",
   "step": i,
   "reason":"authority-like domain pattern",
   "refs":["Deception Heuristics","MITRE: Social Engineering"],
   "url": input.steps[i].args.url}
} if {
  input.steps[i].tool == "http_post"
  not url_allowlisted(input.steps[i].args.url)
  regex.match("(?i)://[^/]*(support|help|secure|verify|account|login|gov|official|customer|care)", input.steps[i].args.url)
}

# 6) Repetition effect（短時間に繰り返し検索）
warn contains {
  {"rule":"repetition_effect",
   "reason":"multiple repeated web_search",
   "count": n,
   "refs":["Cognitive Biases: Repetition Effect","Human Factors in Security"]}
} if {
  n := count({ i | input.steps[i].tool == "web_search" })
  n >= 3
}

# 7) Urgency framing（心理的圧迫ワード → 直後に外部送信）
warn contains {
  {"rule":"urgency_framing",
   "from": pii,
   "to": post,
   "reason":"urgency cue followed by external send",
   "refs":["Social Engineering: Urgency","Cialdini: Influence"],
   "cue": "urgency"}
} if {
  some pii, post
  input.steps[pii].tool == "extract_pii"
  post > pii

  # 緊急性キーワード（日本語・英語）
  regex.match("(?i)(至急|緊急|今すぐ|アカウント停止|直ちに|期限|urgent|immediately|now|suspend|deadline)", input.steps[pii].args.text)

  # 直後の送信系アクション（許可外）
  input.steps[post].tool == "http_post"
  not url_allowlisted(input.steps[post].args.url)
}
