# hyperswitch-prism

**Universal Connector Service — Java/Kotlin SDK**

A high-performance, type-safe Java/Kotlin SDK for payment processing through the Universal Connector Service. Connect to 50+ payment processors (Stripe, PayPal, Adyen, and more) through a single, unified API.

[![Maven Central](https://img.shields.io/maven-central/v/com.hyperswitch/hyperswitch-prism.svg)](https://central.sonatype.com/artifact/com.hyperswitch/hyperswitch-prism)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## Features

- 🚀 **High Performance** — Direct UniFFI FFI bindings to Rust core via JNA
- 🔌 **50+ Connectors** — Single SDK for Stripe, PayPal, Adyen, and more
- ☕ **Kotlin/Java Native** — Full Kotlin bindings with Java interop
- ⚡ **Connection Pooling** — Built-in HTTP connection pooling via OkHttp
- 🛡️ **Type-Safe** — Protobuf-based request/response serialization
- 🔧 **Configurable** — Per-request or global configuration for timeouts, proxies, and auth

---

## Installation

### Gradle (Kotlin DSL)

```kotlin
implementation("com.hyperswitch:hyperswitch-prism:0.0.1")
```

### Gradle (Groovy DSL)

```groovy
implementation 'com.hyperswitch:hyperswitch-prism:0.0.1'
```

### Maven

```xml
<dependency>
  <groupId>com.hyperswitch</groupId>
  <artifactId>hyperswitch-prism</artifactId>
  <version>0.0.1</version>
</dependency>
```

**Requirements:**
- JDK 17+
- Rust toolchain (for building native bindings from source)

**Platform Support:**
- ✅ macOS (x64, arm64)
- ✅ Linux (x64, arm64)
- ✅ Windows (x64)

---

## Quick Start

### 1. Configure the Client

```kotlin
import com.hyperswitch.payments.*
import com.hyperswitch.payments.generated.*

// Configure connector identity and authentication
val stripeConfig = ConnectorConfig(
    connectorConfig = ConnectorConfig.ConnectorConfigOneOf.Stripe(
        StripeConfig(
            apiKey = SecretString(value = System.getenv("STRIPE_API_KEY"))
        )
    )
)

// Optional: Request defaults for timeouts
val requestConfig = RequestConfig(
    http = HttpConfig(
        totalTimeoutMs = 30000,
        connectTimeoutMs = 10000
    )
)
```

### 2. Process a Payment

```kotlin
val client = PaymentClient(stripeConfig, requestConfig)

val authorizeRequest = PaymentServiceAuthorizeRequest(
    merchantTransactionId = "txn_order_001",
    amount = Amount(
        minorAmount = 1000,  // $10.00
        currency = Currency.USD
    ),
    captureMethod = CaptureMethod.AUTOMATIC,
    paymentMethod = PaymentMethod(
        card = CardPaymentMethod(
            cardNumber = SecretString(value = "4111111111111111"),
            cardExpMonth = SecretString(value = "12"),
            cardExpYear = SecretString(value = "2027"),
            cardCvc = SecretString(value = "123"),
            cardHolderName = "John Doe"
        )
    ),
    address = Address(billingAddress = AddressDetails()),
    authType = AuthenticationType.NO_THREE_DS,
    returnUrl = "https://example.com/return",
    orderDetails = emptyList()
)

val response = client.authorize(authorizeRequest)
println("Status: ${response.status}")
println("Transaction ID: ${response.connectorTransactionId}")
```

---

## Service Clients

The SDK provides specialized clients for different service domains:

| Client | Purpose | Key Methods |
|--------|---------|-------------|
| `PaymentClient` | Core payment operations | `authorize()`, `capture()`, `refund()`, `void()` |
| `CustomerClient` | Customer management | `create()` |
| `PaymentMethodClient` | Secure tokenization | `tokenize()` |
| `MerchantAuthenticationClient` | Auth token management | `createServerAuthenticationToken()`, `createServerSessionAuthenticationToken()`, `createClientAuthenticationToken()` |
| `EventClient` | Webhook processing | `handleEvent()` |
| `RecurringPaymentClient` | Subscription billing | `charge()` |
| `PaymentMethodAuthenticationClient` | 3DS authentication | `preAuthenticate()`, `authenticate()`, `postAuthenticate()` |

---

## Authentication Examples

### Stripe (HeaderKey)

```kotlin
val stripeConfig = ConnectorConfig(
    connectorConfig = ConnectorConfig.ConnectorConfigOneOf.Stripe(
        StripeConfig(
            apiKey = SecretString(value = System.getenv("STRIPE_API_KEY"))
        )
    )
)
```

### PayPal (SignatureKey)

```kotlin
val paypalConfig = ConnectorConfig(
    connectorConfig = ConnectorConfig.ConnectorConfigOneOf.Paypal(
        PaypalConfig(
            clientId = SecretString(value = System.getenv("PAYPAL_CLIENT_ID")),
            clientSecret = SecretString(value = System.getenv("PAYPAL_CLIENT_SECRET"))
        )
    )
)
```

---

## Advanced Configuration

### Proxy Settings

```kotlin
val proxyConfig = RequestConfig(
    http = HttpConfig(
        proxy = ProxyConfig(
            httpsUrl = "https://proxy.company.com:8443",
            bypassUrls = listOf("http://localhost")
        )
    )
)
```

### Per-Request Overrides

```kotlin
val response = client.authorize(request, RequestConfig(
    http = HttpConfig(
        totalTimeoutMs = 60000  // Override for this request only
    )
))
```

### Connection Pooling

Each client instance maintains its own connection pool. For best performance:

```kotlin
// ✅ Create client once, reuse for multiple requests
val client = PaymentClient(config, defaults)

for (payment in payments) {
    client.authorize(payment)
}
```

---

## Error Handling

```kotlin
import com.hyperswitch.payments.*

try {
    val response = client.authorize(request)
} catch (e: IntegrationError) {
    // Request-phase error (auth, URL construction, serialization, etc.)
    println("Code: ${e.errorCode}")
    println("Status: ${e.statusCode}")
    println("Message: ${e.message}")
} catch (e: ConnectorError) {
    // Response-phase error (deserialization, transformation, etc.)
    println("Code: ${e.errorCode}")
    println("Status: ${e.statusCode}")
    println("Message: ${e.message}")
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `CONNECT_TIMEOUT` | Failed to establish connection |
| `RESPONSE_TIMEOUT` | No response received from gateway |
| `TOTAL_TIMEOUT` | Overall request timeout exceeded |
| `NETWORK_FAILURE` | General network error |
| `INVALID_CONFIGURATION` | Configuration error |
| `CLIENT_INITIALIZATION` | SDK initialization failed |

---

## Complete Example: PayPal with Access Token

```kotlin
import com.hyperswitch.payments.*
import com.hyperswitch.payments.generated.*

// Configure PayPal
val paypalConfig = ConnectorConfig(
    connectorConfig = ConnectorConfig.ConnectorConfigOneOf.Paypal(
        PaypalConfig(
            clientId = SecretString(value = System.getenv("PAYPAL_CLIENT_ID")),
            clientSecret = SecretString(value = System.getenv("PAYPAL_CLIENT_SECRET"))
        )
    )
)

// Step 1: Get access token
val authClient = MerchantAuthenticationClient(paypalConfig)
val tokenResponse = authClient.createServerAuthenticationToken(
    MerchantAuthenticationRequest(
        merchantAccessTokenId = "token_001",
        connector = Connector.PAYPAL,
        testMode = true
    )
)

// Step 2: Authorize with access token
val paymentClient = PaymentClient(paypalConfig)
val paymentResponse = paymentClient.authorize(
    PaymentServiceAuthorizeRequest(
        merchantTransactionId = "txn_001",
        amount = Amount(
            minorAmount = 1000,
            currency = Currency.USD
        ),
        captureMethod = CaptureMethod.AUTOMATIC,
        paymentMethod = PaymentMethod(
            card = CardPaymentMethod(
                cardNumber = SecretString(value = "4111111111111111"),
                cardExpMonth = SecretString(value = "12"),
                cardExpYear = SecretString(value = "2027"),
                cardCvc = SecretString(value = "123")
            )
        ),
        state = ConnectorState(
            accessToken = AccessToken(
                token = SecretString(value = tokenResponse.accessToken.value),
                tokenType = "Bearer",
                expiresInSeconds = tokenResponse.expiresInSeconds
            )
        ),
        testMode = true
    )
)

println("Payment status: ${paymentResponse.status}")
```

---

## Architecture

```
Your App → Service Client → ConnectorClient → UniFFI FFI (JNA) → Rust Core → Connector API
                ↓
         Connection Pool (OkHttp)
```

The SDK uses:
- **UniFFI** — FFI bindings to Rust via JNA
- **protobuf-java** — Protocol buffer serialization
- **OkHttp** — High-performance HTTP client with connection pooling

---

## Building from Source

```bash
# Clone the repository
git clone https://github.com/juspay/connector-service.git
cd connector-service/sdk/java

# Build native library, generate bindings, and pack
make pack

# Run tests
make test-pack

# With live API credentials
STRIPE_API_KEY=sk_test_xxx make test-pack
```

---

## How it works

1. `make build-lib` — builds `crates/ffi/ffi` with `--features uniffi`
2. `make generate-bindings` — runs `uniffi-bindgen --language kotlin` to produce `generated/connector_service_ffi.kt`
3. `make generate-proto` — runs `protoc --java_out` to produce Java protobuf stubs (callable from Kotlin)
4. `make pack-archive` — runs `./gradlew jar` and copies the JAR to `artifacts/sdk-java/`
