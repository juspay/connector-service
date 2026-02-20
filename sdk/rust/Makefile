# Check if Rust toolchain is available
CHECK_CARGO := $(shell which cargo 2>/dev/null && echo "yes" || echo "no")

# Install/setup dependencies (noop for nix, helpful for manual setup)
install-deps:
	@echo "Checking Rust toolchain..."
ifeq ($(CHECK_CARGO),yes)
	@echo "  ✓ Cargo already available (version: $(shell cargo --version))"
else
	@echo "  ✗ Cargo not found - please install Rust or use nix develop"
	@exit 1
endif

.PHONY: setup run run-debug clean

setup: install-deps
	@echo "Building sdk/rust..."
	@cargo build --release -p hyperswitch-payments-client
	@echo "Setup complete. Run 'make run' to execute."

run:
	STRIPE_API_KEY=$(STRIPE_API_KEY) cargo run --release -p hyperswitch-payments-client

run-debug:
	STRIPE_API_KEY=$(STRIPE_API_KEY) cargo run -p hyperswitch-payments-client

clean:
	@echo "Cleaning build artifacts..."
	@cargo clean -p hyperswitch-payments-client
	@echo "Clean complete!"

# Packaging targets for release workflow
package: ## Package SDK for distribution
	@echo "Packaging Rust SDK..."
	@mkdir -p artifacts/rust
	@cargo build --release -p hyperswitch-payments-client
	@cp -rf src artifacts/rust/ 2>/dev/null || true
	@cp Cargo.toml artifacts/rust/
	@cp -rf target/release artifacts/rust/target/ 2>/dev/null || true
	@echo "Package created in artifacts/rust/"

dist: ## Create distribution archive
	@$(MAKE) package
	@cd artifacts && zip -r connector-service-rust-sdk.zip rust/
	@echo "Distribution archive: artifacts/connector-service-rust-sdk.zip"
