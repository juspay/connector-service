# Makefile

# Use nightly for rustfmt
NIGHTLY := +nightly

# CI mode? (set CI=true to enforce warnings-as-errors)
CI ?= false
ifeq ($(CI),true)
	CLIPPY_EXTRA := -- -D warnings
endif

.PHONY: all fmt check clippy test ci help proto-format proto-generate proto-build proto-lint proto-clean manage-creds test-setup

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

test:
	@echo "▶ Running comprehensive test suite..."
	@if [ -f "test-credentials.json.gpg" ]; then \
		if [ -n "$$GPG_PASSPHRASE" ] || [ -f ".env.gpg.key" ]; then \
			echo "🔐 Credentials detected - running all tests with encrypted credentials"; \
			./scripts/decrypt-and-test.sh; \
		else \
			echo "❌ Error: test-credentials.json.gpg file exists but no GPG passphrase available"; \
			echo "   This repository is configured for credential-based testing"; \
			echo "   Please set GPG_PASSPHRASE environment variable or create .env.gpg.key file"; \
			echo "   Contact your team lead to get the passphrase"; \
			exit 1; \
		fi; \
	else \
		if [ -n "$$GPG_PASSPHRASE" ] || [ -f ".env.gpg.key" ]; then \
			echo "❌ Error: GPG passphrase is available but test-credentials.json.gpg file is missing"; \
			echo "   Please ensure the encrypted credentials file is committed to the repository"; \
			echo "   Or remove/unset the passphrase to run tests without credentials"; \
			exit 1; \
		else \
			echo "❌ Error: GPG passphrase and test-credentials.json.gpg file is missing"; \
			exit 1; \
		fi; \
	fi

## CI-friendly invocation:
##    make ci
## or CI=true make all
ci:
	@echo "⚙️  Running in CI mode (warnings = errors)…"
	@$(MAKE) CI=true all


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


## Manage test credentials
manage-creds:
	@echo "▶ Credential management help:"
	@echo "  Add new:    ./scripts/manage-credentials.sh add <connector> <cred-file>"
	@echo "  Update:     ./scripts/manage-credentials.sh update <connector> <cred-file>"
	@echo "  Delete:     ./scripts/manage-credentials.sh delete <connector>"
	@echo "  List:       ./scripts/manage-credentials.sh list"
	@echo "  Verify:     ./scripts/manage-credentials.sh verify"

## First-time test setup for developers
test-setup:
	@echo "▶ Test setup instructions:"
	@echo "1. Get the GPG passphrase from your team lead"
	@echo "2. Create passphrase file: echo 'your_passphrase' > .env.gpg.key"
	@echo "3. Run tests: make test"
	@echo "4. For credential management: make manage-creds"

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
	@echo "  ci       Same as '''all''' but with CI=true (treat warnings as errors)"
	@echo
	@echo "Test Targets:"
	@echo "  test             Run comprehensive test suite (auto-detects credentials)"
	@echo "  test-setup       Show first-time setup instructions"
	@echo
	@echo "Credential Management:"
	@echo "  manage-creds     Show credential management commands"
	@echo
	@echo "Proto Targets:"
	@echo "  proto-format     Format proto files"
	@echo "  proto-generate   Generate code from proto files"
	@echo "  proto-build      Build/validate proto files"
	@echo "  proto-lint       Lint proto files"
	@echo "  proto-clean      Clean generated proto files"
	@echo
	@echo "Other Targets:"
	@echo "  help     Show this help message"
