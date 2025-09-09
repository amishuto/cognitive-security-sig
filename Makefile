OPA_BIN ?= ./opa064

.PHONY: fmt check test
fmt:
	$(OPA_BIN) fmt -w policy/agent.rego

check:
	$(OPA_BIN) check policy/agent.rego

test: fmt check
	./scripts/demo.sh
