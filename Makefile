# Makefile

# Use nightly for rustfmt
NIGHTLY := +nightly

# CI mode? (set CI=true to enforce warnings-as-errors)
CI ?= false
ifeq ($(CI),true)
	CLIPPY_EXTRA := -- -D warnings
endif

# Connector test parameters (override on command line)
connector ?=
suite     ?=
scenario  ?=
interface ?= grpc

# gRPC server settings
# The test harness connects to localhost:50051 by default.
# Override with: make test-connector connector=stripe GRPC_PORT=9090
GRPC_PORT  ?= 50051
GRPC_HOST  ?= 0.0.0.0
# PID file used to track the background server process
GRPC_PID_FILE := .grpc-server.pid

.PHONY: all fmt check clippy test nextest ci help \
        proto-format proto-generate proto-build proto-lint proto-clean \
        generate field-probe docs docs-check \
        setup-connector-tests \
        start-grpc stop-grpc \
        test-prism test-ucs test-connector test-scenario cargo

# ── Standard build/lint targets ────────────────────────────────────────────────

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

## CI-friendly invocation:
##    make ci
## or CI=true make all
ci:
	@echo "⚙️  Running in CI mode (warnings = errors)…"
	@$(MAKE) CI=true all

# ── Connector integration test setup ──────────────────────────────────────────

## One-time (idempotent) setup for connector integration tests.
## Installs npm deps, Playwright browsers, and deploys GPay pages to Netlify.
## Run this once before running any connector tests.
setup-connector-tests:
	@echo "▶ Setting up connector integration tests…"
	@bash scripts/setup-connector-tests.sh

# ── gRPC server lifecycle ──────────────────────────────────────────────────────

## Build and start the gRPC server in the background on GRPC_PORT (default 50051).
## The server PID is written to $(GRPC_PID_FILE) so stop-grpc can kill it.
## You rarely need to call this directly — test-prism / test-connector /
## test-scenario all manage the server lifecycle automatically.
start-grpc:
	@echo "▶ Building grpc-server…"
	@cargo build -p grpc-server --release 2>&1
	@echo "▶ Starting grpc-server on $(GRPC_HOST):$(GRPC_PORT)…"
	@CS__SERVER__HOST=$(GRPC_HOST) \
	 CS__SERVER__PORT=$(GRPC_PORT) \
	 CS__COMMON__ENVIRONMENT=development \
	 ./target/release/grpc-server &
	@echo $$! > $(GRPC_PID_FILE)
	@echo "[grpc] waiting for server to be ready on port $(GRPC_PORT)…"
	@for i in $$(seq 1 40); do \
	  if nc -z 127.0.0.1 $(GRPC_PORT) 2>/dev/null; then \
	    echo "[grpc] server is ready (PID $$(cat $(GRPC_PID_FILE)))"; \
	    exit 0; \
	  fi; \
	  sleep 0.5; \
	done; \
	echo "[grpc] ERROR: server did not start within 20 s"; \
	cat $(GRPC_PID_FILE) | xargs kill 2>/dev/null || true; \
	rm -f $(GRPC_PID_FILE); \
	exit 1

## Stop the background gRPC server that was started by start-grpc.
stop-grpc:
	@if [ -f $(GRPC_PID_FILE) ]; then \
	  PID=$$(cat $(GRPC_PID_FILE)); \
	  echo "[grpc] stopping server (PID $$PID)…"; \
	  kill $$PID 2>/dev/null || true; \
	  rm -f $(GRPC_PID_FILE); \
	  echo "[grpc] stopped"; \
	else \
	  echo "[grpc] no PID file found — server may not be running"; \
	fi

# ── Connector integration test runners ────────────────────────────────────────

# Internal macro: load .env.connector-tests and export GPAY_HOSTED_URL if present.
define load_env
	@[ -f .env.connector-tests ] && export $$(grep -v '^#' .env.connector-tests | xargs) || true
endef

## UCS connector test runner. After running setup, use `test-prism` directly.
## Handles first-run setup, gRPC server lifecycle, and all flags automatically.
##
##   make test-prism
##
## For full flag support use test-prism directly (installed by setup):
##   test-prism --help
test-prism:
	@./scripts/run-tests

## Backwards-compatible alias for test-prism.
test-ucs: test-prism

## Run all integration tests for a specific connector (non-interactive).
## Automatically starts the gRPC server before the run and stops it after.
##
##   make test-connector connector=stripe
##   make test-connector connector=cybersource interface=sdk
test-connector:
	@if [ -z "$(connector)" ]; then \
	  echo "Error: connector is required."; \
	  echo "Usage: make test-connector connector=stripe"; \
	  exit 1; \
	fi
	@echo "▶ Running all suites for connector '$(connector)' (interface=$(interface))…"
	@if [ "$(interface)" = "grpc" ]; then $(MAKE) start-grpc; fi
	@EXIT_CODE=0; \
	 [ -f .env.connector-tests ] && export $$(grep -v '^#' .env.connector-tests | xargs) 2>/dev/null || true; \
	 cargo run -p ucs-connector-tests --bin test_ucs -- \
	   --connector $(connector) \
	   --endpoint localhost:50051 \
	   --interface $(interface) || EXIT_CODE=$$?; \
	 [ "$(interface)" = "grpc" ] && $(MAKE) stop-grpc || true; \
	 exit $$EXIT_CODE

## Run a specific scenario (non-interactive).
## Automatically starts the gRPC server before the run and stops it after.
##
##   make test-scenario connector=stripe suite=authorize scenario=no3ds_auto_capture_credit_card
##   make test-scenario connector=stripe suite=authorize scenario=no3ds_auto_capture_google_pay_encrypted
test-scenario:
	@if [ -z "$(connector)" ] || [ -z "$(suite)" ] || [ -z "$(scenario)" ]; then \
	  echo "Error: connector, suite, and scenario are all required."; \
	  echo "Usage: make test-scenario connector=stripe suite=authorize scenario=no3ds_auto_capture_credit_card"; \
	  exit 1; \
	fi
	@echo "▶ Running $(connector)/$(suite)/$(scenario) (interface=$(interface))…"
	@if [ "$(interface)" = "grpc" ]; then $(MAKE) start-grpc; fi
	@EXIT_CODE=0; \
	 [ -f .env.connector-tests ] && export $$(grep -v '^#' .env.connector-tests | xargs) 2>/dev/null || true; \
	 cargo run -p ucs-connector-tests --bin test_ucs -- \
	   --connector $(connector) \
	   --suite $(suite) \
	   --scenario $(scenario) \
	   --endpoint localhost:50051 \
	   --interface $(interface) || EXIT_CODE=$$?; \
	 [ "$(interface)" = "grpc" ] && $(MAKE) stop-grpc || true; \
	 exit $$EXIT_CODE

# ── Cargo with environment ─────────────────────────────────────────────────────

## Run cargo commands with environment variables auto-loaded from .env.connector-tests
## Usage: make cargo ARGS="run -p ucs-connector-tests --bin test_ucs -- --connector stripe"
## Usage: make cargo ARGS="test"
## Usage: make cargo ARGS="build"
cargo:
	@if [ -f .env.connector-tests ]; then \
	  export $$(grep -v '^#' .env.connector-tests | xargs) 2>/dev/null; \
	fi; \
	cargo $(ARGS)

# ── Proto targets ──────────────────────────────────────────────────────────────

# Format proto files
proto-format:
	@echo "Formatting proto files..."
	buf format -w

# Generate code from proto files (e.g., OpenAPI specs)
proto-generate:
	@echo "Generating code from proto files..."
	buf generate

# Validate proto files
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

# ── SDK / docs targets ─────────────────────────────────────────────────────────

## Generate SDK flow bindings from services.proto ∩ bindings/uniffi.rs
generate:
	@echo "▶ Generating SDK flows from services.proto…"
	@$(MAKE) -C sdk generate

## Run field-probe to generate connector flow data
field-probe:
	@echo "▶ Running field-probe to generate connector flow data…"
	cargo run -p field-probe

## Generate connector docs from source code (all connectors)
docs: field-probe
	@echo "▶ Generating connector docs…"
	python3 scripts/generate-connector-docs.py --all --probe data/field_probe

## Report annotation coverage for connector docs
docs-check:
	@echo "▶ Checking connector annotation coverage…"
	python3 scripts/generate-connector-docs.py --check

# ── Help ───────────────────────────────────────────────────────────────────────

## Show this help
help:
	@echo "Usage: make [TARGET] [VARIABLE=value ...]"
	@echo
	@echo "Main Targets:"
	@echo "  all      Run fmt, check, clippy, test"
	@echo "  fmt      Format all crates with rustfmt (nightly)"
	@echo "  check    Run cargo-hack check (no dev-deps)"
	@echo "  clippy   Run cargo-hack clippy (no dev-deps)"
	@echo "  test     Run cargo-hack test"
	@echo "  nextest  Run tests with nextest (faster test runner)"
	@echo "  ci       Same as 'all' but with CI=true (treat warnings as errors)"
	@echo
	@echo "Connector Integration Test Targets:"
	@echo ""
	@echo "  setup-connector-tests"
	@echo "    One-time setup: npm install, Playwright browsers, Netlify deploy."
	@echo "    Safe to re-run (idempotent). Do this once before running tests."
	@echo ""
	@echo "  test-prism"
	@echo "    Run all connector tests. After setup, you can also just type: test-prism"
	@echo "    Starts the gRPC server automatically."
	@echo "    Example: make test-prism"
	@echo "    Alias:   make test-ucs (backwards compat)"
	@echo ""
	@echo "  test-connector connector=<name> [interface=grpc|sdk]"
	@echo "    Run all suites for one connector, non-interactively."
	@echo "    Starts + stops the gRPC server automatically."
	@echo "    Example: make test-connector connector=stripe"
	@echo "             make test-connector connector=cybersource interface=sdk"
	@echo ""
	@echo "  test-scenario connector=<name> suite=<suite> scenario=<scenario> [interface=grpc|sdk]"
	@echo "    Run a single scenario, non-interactively."
	@echo "    Starts + stops the gRPC server automatically."
	@echo "    Example: make test-scenario connector=stripe suite=authorize scenario=no3ds_auto_capture_credit_card"
	@echo "             make test-scenario connector=stripe suite=authorize scenario=no3ds_auto_capture_google_pay_encrypted"
	@echo ""
	@echo "  cargo ARGS=\"<cargo-args>\""
	@echo "    Run cargo commands with .env.connector-tests auto-loaded (GPAY_HOSTED_URL, etc)."
	@echo "    Use this when running cargo directly instead of via test-prism."
	@echo "    Example: make cargo ARGS=\"run -p ucs-connector-tests --bin test_ucs -- --connector stripe\""
	@echo "             make cargo ARGS=\"test\""
	@echo "             make cargo ARGS=\"build --release\""
	@echo ""
	@echo "  start-grpc [GRPC_PORT=50051]"
	@echo "    Build and start the gRPC server in the background."
	@echo ""
	@echo "  stop-grpc"
	@echo "    Stop the background gRPC server."
	@echo ""
	@echo "Credential resolution order (for connector tests):"
	@echo "  1. CONNECTOR_AUTH_FILE_PATH env var"
	@echo "  2. UCS_CREDS_PATH env var"
	@echo "  3. .github/test/creds.json (repo default)"
	@echo ""
	@echo "Google Pay tests require GPAY_HOSTED_URL to be set."
	@echo "Run 'make setup-connector-tests' to configure it automatically via Netlify."
	@echo ""
	@echo "Proto Targets:"
	@echo "  proto-format     Format proto files"
	@echo "  proto-generate   Generate code from proto files"
	@echo "  proto-build      Build/validate proto files"
	@echo "  proto-lint       Lint proto files"
	@echo "  proto-clean      Clean generated proto files"
	@echo ""
	@echo "SDK Codegen Targets:"
	@echo "  generate         Generate SDK flow bindings (Python, JS, Kotlin)"
	@echo ""
	@echo "Docs Targets:"
	@echo "  docs         Regenerate all connector docs from source"
	@echo "  docs-check   Report which connectors are missing annotation files"
	@echo ""
	@echo "Other:"
	@echo "  help     Show this help message"
