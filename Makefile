# go-gostls — developer tasks.
#
# BSD pure-Go (CGO-free) TLS 1.2 client with GOST suites. Robustness fuzzers
# guard the attacker-facing wire parsers (internal/handshake.FuzzParseMessage,
# FuzzParseExtensions); `make fuzz` drives every Fuzz target.
#
# Override any variable on the command line, e.g.:
#   make test PKG=./internal/handshake/
#   make fuzz PKG=./internal/handshake/ FUZZTIME=2m

GO            ?= go
GOLANGCI      ?= golangci-lint
PKG           ?= ./...
FUZZTIME      ?= 1m
FUZZMINTIME   ?= 5s
COVERAGE_FILE ?= coverage.out

# Note: pin the linter so local and CI runs agree.
GOLANGCI_VERSION ?= v2.11.4

CGO_ENABLED ?= 0
export CGO_ENABLED

.DEFAULT_GOAL := help

.PHONY: help build test testrace coverage cover lint lint-fix fmt vet tidy \
	fuzz codespell govulncheck deps ci

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## --- building & testing ---

build: ## Build all packages (CGO-free)
	$(GO) build $(PKG)

test: ## Run the unit/round-trip tests (replays fuzz seeds too)
	$(GO) test -count=1 $(PKG)

testrace: ## Run the tests under the race detector (needs cgo)
	CGO_ENABLED=1 $(GO) test -race -count=1 $(PKG)

coverage: ## Run the tests and print the per-function coverage summary
	$(GO) test -covermode=atomic -coverprofile=$(COVERAGE_FILE) -count=1 $(PKG)
	$(GO) tool cover -func=$(COVERAGE_FILE)

cover: coverage ## Run the tests and open the HTML coverage report
	$(GO) tool cover -html=$(COVERAGE_FILE)

## --- linting ---

lint: ## Run golangci-lint
	$(GOLANGCI) run $(PKG)

lint-fix: ## Run golangci-lint and apply autofixes
	$(GOLANGCI) run --fix $(PKG)

fmt: ## gofmt-format all Go files in place
	$(GO) fmt $(PKG)

vet: ## Run go vet
	$(GO) vet $(PKG)

tidy: ## Tidy and verify go.mod / go.sum
	$(GO) mod tidy
	$(GO) mod verify

codespell: ## Spell-check the code and documentation
	codespell

govulncheck: ## Report known vulnerabilities in the dependency graph
	govulncheck $(PKG)

deps: ## Install the lint / vulncheck tooling at the pinned versions
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

## --- fuzzing ---

fuzz: ## Fuzz every target for FUZZTIME each (default 1m; e.g. FUZZTIME=10s)
	@for pkg in $$($(GO) list $(PKG)); do \
		for fz in $$($(GO) test $$pkg -list '^Fuzz' 2>/dev/null | grep '^Fuzz' || true); do \
			echo "=== $$pkg $$fz (fuzztime $(FUZZTIME), minimize $(FUZZMINTIME)) ==="; \
			$(GO) test $$pkg -run '^$$' -fuzz "^$$fz$$" -fuzztime $(FUZZTIME) -fuzzminimizetime $(FUZZMINTIME) || exit 1; \
		done; \
	done

## --- aggregate ---

ci: lint vet test ## Run lint + vet + tests (the pre-push gate)
