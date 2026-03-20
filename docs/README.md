<div align="center">


# Hyperswitch Prism


**One integration. Any payment processor. Zero lock-in.**


[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


*A high-performance payment abstraction library, and part of [Juspay Hyperswitch](https://hyperswitch.io/) — the open-source, composable payments platform with 40,000+ GitHub stars, trusted by leading brands worldwide.*


[GitHub](https://github.com/juspay/hyperswitch) · [Website](https://hyperswitch.io/) · [Documentation](https://docs.hyperswitch.io/)


</div>


---


## 🎯 Why Prism?


Today, integrating multiple payment processors either makes developers running in cicles with AI agents to recreate integrations from specs, or developers spending months of engineering effort. 

Because every payment processor has diverse APIs, error codes, authentication methods, pdf documents to read, and above all - different behaviour in the actual environment when compared to documented specs. All this rests as tribal or undocumented knowledge making it harder AI agents which are very good at implementing clearly documented specification.

**Prism is a stateless, unified connector library for AI agents and Developers to connect with any payment processor**

**Prism offers hardened transformation through testing on payment processor environment & iterative bug fixing**

**Prism can be embedded in you server application with its wide range of mulit-language SDKs, or run as a rRPC microservice**


| ❌ Without Prism | ✅ With Prism |
|------------------------------|----------------------------|
| 🗂️ 100+ different API schemas | 📋 Single unified schema |
| ⏳ Never ending agent loops/ months of integration work | ⚡ Hours to integrate, Agent driven |
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
   participant SDK as Prism
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

### Install the Prism Library

<!-- tabs:start -->

#### **Node.js**

```bash
npm install @juspay-tech/hyperswitch-prism
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

### Create a Payment Order

<!-- tabs:start -->

#### **Node.js**

```javascript
const { ConnectorClient, Currency } = require('@juspay/hyperswitch-prism');

async function main() {
  const client = new ConnectorClient({
    connectors: {
      stripe: { apiKey: process.env.STRIPE_API_KEY }
    }
  });

  const order = await client.payments.createOrder({
    amount: {
      minorAmount: 1000,  // $10.00
      currency: Currency.USD
    },
    merchantOrderId: 'order-123'
  });

  console.log('Order ID:', order.connectorOrderId);
  console.log('Client Secret:', order.sessionToken.clientSecret);
}

main().catch(console.error);
```


#### **Java**


```java
import com.juspay.hyperswitchprism.*;

public class Example {
    public static void main(String[] args) {
        ConnectorClient client = ConnectorClient.builder()
            .connector("stripe", StripeConfig.builder()
                .apiKey(System.getenv("STRIPE_API_KEY"))
                .build())
            .build();

        CreateOrderResponse order = client.payments().createOrder(
            CreateOrderRequest.builder()
                .amount(Amount.of(1000, Currency.USD))
                .merchantOrderId("order-123")
                .build()
        );

        System.out.println("Order ID: " + order.getConnectorOrderId());
        System.out.println("Client Secret: " + order.getSessionToken().getClientSecret());
    }
}
```
<!-- tabs:end -->


---


## 🔄 Switching Providers


One of Prism's core benefits: switch payment providers by changing **one line**.


```javascript
// Before: Using Stripe
const client = new ConnectorClient({
    connectors: {
        stripe: { apiKey: process.env.STRIPE_API_KEY }
    }
});

const order = await client.payments.createOrder({
    amount: { minorAmount: 1000, currency: Currency.USD },
    merchantOrderId: 'order-123'
});

// After: Switching to Braintree
const client = new ConnectorClient({
    connectors: {
        braintree: {
            publicKey: process.env.BRAINTREE_PUBLIC_KEY,
            privateKey: process.env.BRAINTREE_PRIVATE_KEY,
            merchantAccountId: process.env.BRAINTREE_MERCHANT_ID
        }
    }
});

// The createOrder call stays exactly the same!
const order = await client.payments.createOrder({
    amount: { minorAmount: 1000, currency: Currency.USD },
    merchantOrderId: 'order-123'
});
```

**One integration pattern. Any service category.**

No rewriting. No re-architecting. Just swap the connector.
Each flow uses the same unified schema regardless of the underlying processor's API differences. No custom code per provider.

---

## 🛠️ Development


### Prerequisites

- Rust 1.70+
- Protocol Buffers (protoc)


### Building from Source

```bash
# Clone the repository
git clone https://github.com/manojradhakrishnan/connector-service.git
cd connector-service


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


**[⬆ Back to Top](#connector-service)**


Built and maintained by [Juspay hyperswitch](https://hyperswitch.io)


</div>