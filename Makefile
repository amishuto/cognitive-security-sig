OPA=./opa064

fmt:
	$(OPA) fmt -w policy/*.rego

fmtcheck:
	$(OPA) fmt --fail policy/*.rego

check:
	$(OPA) check policy/*.rego

test:
	$(OPA) test -v policy

.PHONY: fmt fmtcheck check test

report:
	./scripts/opa-report.sh

.PHONY: report
