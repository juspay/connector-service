.PHONY: setup run run-debug clean

setup:
	@echo "Building sdk/rust..."
	@cargo build --release -p hyperswitch-payments-client
	@echo "Build complete!"

run:
	STRIPE_API_KEY=$(STRIPE_API_KEY) cargo run --release -p hyperswitch-payments-client

run-debug:
	STRIPE_API_KEY=$(STRIPE_API_KEY) cargo run -p hyperswitch-payments-client

clean:
	@echo "Cleaning build artifacts..."
	@cargo clean -p hyperswitch-payments-client
	@echo "Clean complete!"
