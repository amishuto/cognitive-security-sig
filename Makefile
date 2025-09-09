OPA_BIN ?= ./opa064

.PHONY: fmt check demo test
fmt:
	$(OPA_BIN) fmt -w policy/agent.rego

check:
	$(OPA_BIN) check policy/agent.rego

demo: fmt check
	./scripts/demo.sh

test:
	OPA_BIN=$(OPA_BIN) ./scripts/ci.sh
