<div align="center">

# Hyperswitch Prism

**One integration. Any payment processor. Zero lock-in.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

*A high-performance payment abstraction library, and part of [Juspay Hyperswitch](https://hyperswitch.io/) — the open-source, composable payments platform with 40,000+ GitHub stars, trusted by leading brands worldwide.*

[GitHub](https://github.com/juspay/hyperswitch) · [Website](https://hyperswitch.io/) · [Documentation](https://docs.hyperswitch.io/)

</div>

---

## 🎯 Why Prism?

Integrating multiple payment processors requires running in circles with AI agents to recreate integrations from specs, or developers spending months of engineering effort.

Every payment processor has diverse APIs, error codes, authentication methods, PDF documents to read, and above all - different behaviour in the actual environment when compared to documented specs. All this rests as tribal or undocumented knowledge making it harder for AI agents which are very good at implementing clearly documented specifications.

**Prism is the unified connector library for AI agents and Developers to connect with any payment processor.**

**Prism offers hardened transformation through testing on the payment processor environments.**

| ❌ Without Prism | ✅ With Prism |
|------------------------------|----------------------------|
| 🗂️ 100+ different API schemas | 📋 Single unified schema |
| ⏳ Never ending agent loops / months of integration work | ⚡ Hours to integrate, Agent driven |
| 🔗 Brittle, provider-specific code | 🔓 Portable, provider-agnostic code |
| 🚫 Hard to switch providers | 🔄 Change providers in 1 line |

---

## ✨ Features

- **🔌 100+ Connectors** — Stripe, Adyen, Braintree, PayPal, Worldpay, and more
- **🌍 Global Coverage** — Cards, wallets, bank transfers, BNPL, and regional methods
- **🚀 Zero Overhead** — Rust core with native bindings, no overhead
- **🔒 PCI-Compliant by Design** — Stateless, no data storage

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Application                         │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Prism Library                           │
│                 (Type-safe, idiomatic interface)                │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
         ┌───────────────────────┼───────────────────────┬───────────────────────┐
         ▼                       ▼                       ▼                       ▼
   ┌──────────┐           ┌──────────┐           ┌──────────┐           ┌──────────┐
   │  Stripe  │           │  Adyen   │           │ Braintree│           │ 50+ more │
   └──────────┘           └──────────┘           └──────────┘           └──────────┘
```

### Payment & Capture Flow Sequence

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#B3D9F2', 'primaryTextColor': '#333333', 'primaryBorderColor': '#5B9BD5', 'lineColor': '#666666', 'secondaryColor': '#C5E8C0', 'tertiaryColor': '#F9B872'}}}%%
sequenceDiagram
   autonumber
   participant App as Your App
   participant SDK as Prism SDK
   participant PSP as Payment Service Provider (PSP)
   
   Note over App,PSP: Payment Authorization
   App->>SDK: paymentservice.authorize(amount, currency, payment_method)
   activate SDK
   SDK->>PSP: Provider-specific Authorize API call
   activate PSP
   PSP-->>SDK: Provider-specific response
   deactivate PSP
   SDK-->>App: Unified authorize response
   deactivate SDK

   Note over App,PSP: Payment Capture
   App->>SDK: paymentservice.capture(payment_id, amount)
   activate SDK
   SDK->>PSP: Provider-specific Capture API call
   activate PSP
   PSP-->>SDK: Provider-specific Capture response
   deactivate PSP
   SDK-->>App: Unified capture response
   deactivate SDK

   Note over App,PSP: Event Service (Webhooks)
   PSP->>App: webhook(event_payload)
   activate App
   App->>SDK: eventservice.handle(unified_event)
   activate SDK
   SDK->>App: Unified event payload
   deactivate SDK
   deactivate App

```

---

## 🚀 Quick Start

### Install the Library

<!-- tabs:start -->

#### **Node.js**

```bash
npm install @juspay/hyperswitch-prism
```

#### **Python**

```bash
pip install hyperswitch-prism
```

#### **Java**

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>com.juspay</groupId>
    <artifactId>hyperswitch-prism</artifactId>
    <version>1.0.0</version>
</dependency>
```

#### **PHP**

```bash
composer require juspay/hyperswitch-prism
```

<!-- tabs:end -->

For detailed installation instructions, see [Installation Guide](./getting-started/installation.md).

---

### Make Your First Payment

<!-- tabs:start -->

#### **Node.js**

```bash
npm install @juspay/hyperswitch-prism
```

```javascript
const { PaymentClient, Connector, Currency } = require('@juspay/hyperswitch-prism');

async function main() {
    const client = new PaymentClient('your_api_key');

    const payment = await client.createPayment({
        amount: { value: 1000, currency: Currency.USD }, // $10.00
        connector: Connector.Stripe,
        paymentMethod: {
            card: {
                number: '4242424242424242',
                expMonth: 12,
                expYear: 2030,
                cvv: '123'
            }
        },
        captureMethod: 'automatic'
    });

    console.log('Payment ID:', payment.id);
    console.log('Status:', payment.status);
}

main();
```

#### **Python**

```bash
pip install hyperswitch-prism
```

```python
from hyperswitch_prism import PaymentClient, Connector, Currency

client = PaymentClient('your_api_key')

payment = client.create_payment({
    'amount': {'value': 1000, 'currency': Currency.USD},
    'connector': Connector.STRIPE,
    'payment_method': {
        'card': {
            'number': '4242424242424242',
            'exp_month': 12,
            'exp_year': 2030,
            'cvv': '123'
        }
    },
    'capture_method': 'automatic'
})

print(f"Payment ID: {payment.id}")
print(f"Status: {payment.status}")
```

#### **Java**

```xml
<!-- Add to pom.xml -->
<dependency>
    <groupId>com.juspay</groupId>
    <artifactId>hyperswitch-prism</artifactId>
    <version>1.0.0</version>
</dependency>
```

```java
import com.juspay.hyperswitchprism.*;

public class Example {
    public static void main(String[] args) {
        PaymentClient client = PaymentClient.create("your_api_key");

        PaymentRequest request = PaymentRequest.builder()
            .amount(Amount.of(1000, Currency.USD))
            .connector(Connector.STRIPE)
            .paymentMethod(PaymentMethod.card(
                "4242424242424242", 12, 2030, "123"))
            .captureMethod(CaptureMethod.AUTOMATIC)
            .build();

        Payment payment = client.createPayment(request);

        System.out.println("Payment ID: " + payment.getId());
        System.out.println("Status: " + payment.getStatus());
    }
}
```

<!-- tabs:end -->

For complete payment workflows, see [First Payment Guide](./getting-started/first-payment.md).

---

## 🔄 Switching Providers

One of Prism's core benefits: switch payment providers by changing **one line**.

```javascript
// Before: Using Stripe
const payment = await client.createPayment({
    connector: Connector.Stripe,  // ← Change this
    // ... rest stays the same
});

// After: Using Adyen
const payment = await client.createPayment({
    connector: Connector.Adyen,   // ← That's it!
    // ... everything else identical
});
```

No rewriting. No re-architecting. Just swap the connector.

---

## 🌊 Abstracted Payment Flows

Prism unifies complex payment operations across all processors:

### Core Payment Operations
| Flow | Description |
|------|-------------|
| **Authorize** | Hold funds on a customer's payment method |
| **Capture** | Complete an authorized payment and transfer funds |
| **Void** | Cancel an authorized payment without charging |
| **Refund** | Return captured funds to the customer |
| **Sync** | Retrieve the latest payment status from the processor |

### Advanced Flows
| Flow | Description |
|------|-------------|
| **Setup Mandate** | Create recurring payment authorizations |
| **Incremental Auth** | Increase the authorized amount post-transaction |
| **Partial Capture** | Capture less than the originally authorized amount |

Each flow uses the same unified schema regardless of the underlying processor's API differences. No custom code per provider.

For all supported flows, see [Extending to More Flows](./getting-started/extend-to-more-flows.md).

---

## 📚 Documentation

| Guide | Description |
|-------|-------------|
| [Installation](./getting-started/installation.md) | Install SDKs for all supported languages |
| [First Payment](./getting-started/first-payment.md) | Complete payment flow with error handling |
| [Extending Flows](./getting-started/extend-to-more-flows.md) | Subscriptions, 3DS, incremental auth, and more |
| [Architecture](./architecture/README.md) | How Prism works under the hood |
| [SDK Reference](../docs-generated/sdks/) | Language-specific API documentation |

---

## 🛠️ Development

### Prerequisites

- Rust 1.70+
- Protocol Buffers (protoc)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/juspay/hyperswitch.git
cd hyperswitch

# Build
cargo build --release

# Run tests
cargo test
```

---

## 🔒 Security

- **Stateless by design** — No PII or PCI data stored
- **Memory-safe** — Built in Rust, no buffer overflows
- **Encrypted credentials** — API keys never logged or exposed

### Reporting Vulnerabilities

Please report security issues to [security@juspay.in](mailto:security@juspay.in).

---

<div align="center">

**[⬆ Back to Top](#hyperswitch-prism)**

Built and maintained by [Juspay Hyperswitch](https://hyperswitch.io)

</div>
