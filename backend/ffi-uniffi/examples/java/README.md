# Java Example — UniFFI Connector Client

Full-fledged Java example demonstrating the Rust connector-service bindings via
[UniFFI](https://mozilla.github.io/uniffi-rs/). This mirrors the Python
`example_with_http.py` and shows the complete flow:

1. **Rust (via UniFFI)** — transforms payment data into an HTTP request
2. **Java** — executes the HTTP request using `java.net.http.HttpClient`
3. **Rust (via UniFFI)** — transforms the HTTP response into a `PaymentResult`

## Prerequisites

| Tool    | Version      | Notes                                                |
|---------|-------------|------------------------------------------------------|
| Rust    | 1.70+       | `rustup` recommended                                |
| Java    | 11+         | `java.net.http.HttpClient` requires JDK 11          |
| Gradle  | 8.x         | Or use the Gradle wrapper (`./gradlew`)              |

## Quick Start

### 1. Automated setup

```bash
cd backend/ffi-uniffi/examples/java
./setup.sh
```

This script will:
- Build the Rust native library (`libconnector_ffi_uniffi.so` / `.dylib`)
- Check/generate Kotlin UniFFI bindings
- Copy the bindings into this Gradle project

### 2. Run the example

```bash
# From backend/ffi-uniffi/examples/java/
gradle run -PnativeLibDir=../../../../target/release

# Or with an absolute path:
gradle run -PnativeLibDir=/path/to/connector-service/target/release
```

## Manual Setup (Step by Step)

If you prefer not to use `setup.sh`:

### Step 1 — Build the Rust library

```bash
cd /path/to/connector-service
cargo build --release -p connector-ffi-uniffi
```

This produces the shared library:
- **Linux**: `target/release/libconnector_ffi_uniffi.so`
- **macOS**: `target/release/libconnector_ffi_uniffi.dylib`
- **Windows**: `target/release/connector_ffi_uniffi.dll`

### Step 2 — Generate Kotlin bindings (if not already present)

```bash
cargo run --release --bin uniffi-bindgen -- generate \
    --library target/release/libconnector_ffi_uniffi.so \
    --language kotlin \
    --out-dir backend/ffi-uniffi/bindings/kotlin
```

### Step 3 — Copy bindings into this project

```bash
mkdir -p backend/ffi-uniffi/examples/java/src/main/kotlin/io/juspay/connector
cp backend/ffi-uniffi/bindings/kotlin/io/juspay/connector/connector_ffi_uniffi.kt \
   backend/ffi-uniffi/examples/java/src/main/kotlin/io/juspay/connector/
```

### Step 4 — Run

```bash
cd backend/ffi-uniffi/examples/java
gradle run -PnativeLibDir=../../../../target/release
```

## Project Structure

```
java/
├── build.gradle.kts                          # Gradle build with Kotlin + JNA deps
├── settings.gradle.kts
├── setup.sh                                  # Automated build + setup script
├── README.md                                 # This file
├── gradle/wrapper/
│   └── gradle-wrapper.properties
└── src/main/
    ├── java/io/juspay/connector/example/
    │   ├── ConnectorExample.java             # Main demo (6 demos)
    │   └── ConnectorClient.java              # Reusable client with HTTP execution
    └── kotlin/io/juspay/connector/
        └── connector_ffi_uniffi.kt           # (copied from bindings/ by setup.sh)
```

## What the Example Demonstrates

| Demo | Description |
|------|-------------|
| 1. List connectors | Calls `listSupportedConnectors()` |
| 2. Connector info  | Shows auth type, supported flows, base URL for each connector |
| 3. Dry-run authorize | Transforms a payment → HTTP request for Stripe and Adyen |
| 4. Mock response flow | Full transform → mock HTTP → transform cycle |
| 5. ConnectorRegistry | Uses the stateful `ConnectorRegistry` object |
| 6. Real API call | Template for live Stripe test-mode calls (commented out) |

## Using `ConnectorClient` in Your Own Code

```java
import io.juspay.connector.example.ConnectorClient;
import java.util.HashMap;
import java.util.Map;

Map<String, String> auth = new HashMap<>();
auth.put("api_key", "sk_test_...");

ConnectorClient client = new ConnectorClient("stripe", auth);

// Authorize
Map<String, Object> result = client.authorize(
    1000L,                   // amount in cents
    "USD",                   // currency
    "4242424242424242",      // card number
    12, 2025, "123",         // exp_month, exp_year, cvc
    "Jane Doe",              // holder name
    "order_42"               // reference ID
);

System.out.println(result.get("success"));        // true
System.out.println(result.get("transaction_id")); // pi_...

// Capture
Map<String, Object> capture = client.capture(
    result.get("transaction_id").toString(),
    1000L, "USD"
);

// Void
Map<String, Object> voided = client.voidPayment("pi_...");

// Refund
Map<String, Object> refund = client.refund("pi_...", 500L, "USD");
```

## How It Works

```
┌──────────────────────┐     JNA (native call)     ┌───────────────────────┐
│  Java / Kotlin (JVM) │ ◄─────────────────────────►│  Rust (UniFFI cdylib) │
│                      │                            │                       │
│  ConnectorClient     │   transformRequest(...)    │  Connector logic      │
│  ConnectorExample    │ ──────────────────────────►│  (Stripe, Adyen, ...) │
│                      │   ◄── HttpRequest ────────│                       │
│  java.net.http       │                            │                       │
│  .HttpClient         │   transformResponse(...)   │  Response parsing     │
│  (executes HTTP)     │ ──────────────────────────►│                       │
│                      │   ◄── PaymentResult ──────│                       │
└──────────────────────┘                            └───────────────────────┘
```

## Troubleshooting

### `UnsatisfiedLinkError` / library not found

Make sure `-PnativeLibDir` points to the directory containing the `.so`/`.dylib`:

```bash
gradle run -PnativeLibDir=/absolute/path/to/target/release
```

Or set the environment variable:

```bash
export JNA_LIBRARY_PATH=/path/to/target/release
gradle run
```

### Kotlin version mismatch

The `build.gradle.kts` pins Kotlin 1.9.22. If your Gradle uses a different
version, update the `kotlin("jvm")` plugin version to match.

### `ConnectorException` at runtime

These are errors from the Rust side (e.g., unknown connector, missing auth
field). Wrap calls in try/catch:

```java
try {
    HttpRequest req = Connector_ffi_uniffiKt.transformRequest(input);
} catch (ConnectorException e) {
    System.err.println("Connector error: " + e.getMessage());
}
```
