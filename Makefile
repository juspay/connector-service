# Makefile

# Use nightly for rustfmt
NIGHTLY := +nightly

# CI mode? (set CI=true to enforce warnings-as-errors)
CI ?= false
ifeq ($(CI),true)
	CLIPPY_EXTRA := -- -D warnings
endif

.PHONY: all fmt check clippy test nextest ci ucs-summary help proto-format proto-generate proto-build proto-lint proto-clean generate

UCS_CONNECTOR ?=
UCS_FLOW ?=
UCS_SUMMARY_FORMAT ?= table
UCS_CAPABILITIES_ONLY ?= true
UCS_SHOW_TEST_NAMES ?= false
UCS_TEST_NAME_VIEW ?=

## Run all checks: fmt → check → clippy → test
all: fmt check clippy test

## Run rustfmt on all crates
fmt:
	@echo "▶ rustfmt (nightly)…"
	cargo $(NIGHTLY) fmt --all

## Run cargo-hack check on each feature (no dev‑deps)
check:
	@echo "▶ cargo-hack check…"
	cargo hack check --each-feature --no-dev-deps

## Run cargo-hack clippy on each feature (no dev‑deps)
clippy:
	@echo "▶ cargo-hack clippy…"
	cargo hack clippy --each-feature --no-dev-deps $(CLIPPY_EXTRA)

## Run cargo-hack tests on each feature
test:
	@echo "▶ cargo-hack test…"
	cargo hack test --each-feature

## Run tests with nextest (faster test runner)
nextest:
	@echo "▶ cargo nextest…"
	cargo nextest run --config-file .nextest.toml

## Show UCS capability summary from test annotations
ucs-summary:
	@echo "▶ ucs test summary…"
	@ARGS="--format $(UCS_SUMMARY_FORMAT)"; \
	if [ -n "$(UCS_CONNECTOR)" ]; then ARGS="$$ARGS --connector $(UCS_CONNECTOR)"; fi; \
	if [ -n "$(UCS_FLOW)" ]; then ARGS="$$ARGS --flow $(UCS_FLOW)"; fi; \
	if [ "$(UCS_CAPABILITIES_ONLY)" = "true" ]; then ARGS="$$ARGS --capabilities-only"; fi; \
	if [ "$(UCS_SHOW_TEST_NAMES)" = "true" ]; then ARGS="$$ARGS --show-test-names"; fi; \
	if [ -n "$(UCS_TEST_NAME_VIEW)" ]; then ARGS="$$ARGS --test-name-view $(UCS_TEST_NAME_VIEW)"; fi; \
	cargo run -p ucs-connector-tests --bin ucs_test_summary -- $$ARGS

## CI-friendly invocation:
##    make ci
## or CI=true make all
ci:
	@echo "⚙️  Running in CI mode (warnings = errors)…"
	@$(MAKE) CI=true all


## Generate SDK flow bindings from services.proto ∩ bindings/uniffi.rs
generate:
	@echo "▶ Generating SDK flows from services.proto…"
	python3 sdk/codegen/generate.py

# Format proto files
proto-format:
	@echo "Formatting proto files..."
	buf format -w

# Generate code from proto files (e.g., OpenAPI specs)
proto-generate:
	@echo "Generating code from proto files..."
	buf generate

# Validate proto files
# This can catch issues before generating code or compiling
proto-build:
	@echo "Building/validating proto files..."
	buf build

# Lint proto files
proto-lint:
	@echo "Linting proto files..."
	buf lint

# Clean generated files
proto-clean:
	@echo "Cleaning generated files..."
	rm -rf gen

## Show this help
help:
	@echo "Usage: make [TARGET]"
	@echo
	@echo "Main Targets:"
	@echo "  all      Run fmt, check, clippy, test"
	@echo "  fmt      Format all crates with rustfmt (nightly)"
	@echo "  check    Run cargo-hack check (no dev-deps)"
	@echo "  clippy   Run cargo-hack clippy (no dev-deps)"
	@echo "  test     Run cargo-hack test"
	@echo "  nextest  Run tests with nextest (faster test runner)"
	@echo "  ucs-summary  Show UCS capability summary (vars: UCS_CONNECTOR optional, UCS_FLOW, UCS_SUMMARY_FORMAT, UCS_CAPABILITIES_ONLY, UCS_SHOW_TEST_NAMES, UCS_TEST_NAME_VIEW)"
	@echo "  ci       Same as '''all''' but with CI=true (treat warnings as errors)"
	@echo
	@echo "Proto Targets:"
	@echo "  proto-format     Format proto files"
	@echo "  proto-generate   Generate code from proto files"
	@echo "  proto-build      Build/validate proto files"
	@echo "  proto-lint       Lint proto files"
	@echo "  proto-clean      Clean generated proto files"
	@echo
	@echo "SDK Codegen Targets:"
	@echo "  generate         Generate SDK flow bindings (Python, JS, Kotlin) from services.proto"
	@echo
	@echo "Other Targets:"
	@echo "  help     Show this help message"
