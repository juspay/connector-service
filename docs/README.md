<div align="center">


# Hyperswitch Prism


**One integration. Any payment processor. Zero lock-in.**


[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


*A high-performance payment abstraction library, and part of [Juspay Hyperswitch](https://hyperswitch.io/) — the open-source, composable payments platform with 40,000+ GitHub stars, trusted by leading brands worldwide.*


[GitHub](https://github.com/juspay/hyperswitch) · [Website](https://hyperswitch.io/) · [Documentation](https://docs.hyperswitch.io/)


</div>


---


## 🎯 What is Prism?

Today, integrating multiple payment processors either makes developers running in circles with AI agents to recreate integrations from specs, or developers spending months of engineering effort.

Because every payment processor has diverse APIs, error codes, authentication methods, pdf documents to read, and above all - different behaviour in the actual environment when compared to documented specs. All this rests as tribal or undocumented knowledge making it harder AI agents which are very good at implementing clearly documented specification.

**Prism is a stateless, unified connector library for AI agents and Developers to connect with any payment processor**

**Prism offers hardened transformation through testing on payment processor environment & iterative bug fixing**

**Prism can be embedded in you server application with its wide range of multi-language SDKs, or run as a rRPC microservice**


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

---


## 🚀 Quick Start

### Install the Prism Library

Start by installing the library in the language of your choice.
<!-- tabs:start -->

#### **Node.js**

```bash
npm install hs-playlib
```

#### **Python**

```bash
pip install payments
```

#### **Java**

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>com.juspay.hyperswitch</groupId>
    <artifactId>prism</artifactId>
    <version>1.0.0</version>
</dependency>
```

#### **PHP**

```bash
composer require juspay/hyperswitch-prism
```

For detailed installation instructions, see [Installation Guide](./getting-started/installation.md).

---

### Create a Payment Order

<!-- tabs:start -->

#### **Node.js**

```javascript
const { PaymentClient } = require('hs-playlib');
const { ConnectorConfig, ConnectorSpecificConfig, SdkOptions, Environment } = require('hs-playlib').types;

async function createOrder(orderId, currency, amount) {
  // Configure Stripe client (Primary payment processor)
  const stripeConfig = ConnectorConfig.create({
    options: SdkOptions.create({ environment: Environment.SANDBOX }),
  });
  stripeConfig.connectorConfig = ConnectorSpecificConfig.create({
    stripe: { apiKey: { value: process.env.STRIPE_API_KEY } }
  });
  const stripeClient = new PaymentClient(stripeConfig);

  // Configure Adyen client (Secondary payment processor)
  const adyenConfig = ConnectorConfig.create({
    options: SdkOptions.create({ environment: Environment.SANDBOX }),
  });
  adyenConfig.connectorConfig = ConnectorSpecificConfig.create({
    adyen: {
      apiKey: { value: process.env.ADYEN_API_KEY },
      merchantAccount: process.env.ADYEN_MERCHANT_ACCOUNT
    }
  });
  const adyenClient = new PaymentClient(adyenConfig);

  // Select client based on currency - EUR to Adyen, USD to Stripe
  const client = currency === 'EUR' ? adyenClient : stripeClient;

  // Create order - route EUR to Adyen, USD to Stripe
  const order = await client.createOrder({
    merchantOrderId: orderId,
    amount: {
      minorAmount: amount,
      currency: currency
    },
    orderType: 'PAYMENT',
    description: `Order ${orderId}`
  });

  console.log(`Order created with ${currency === 'EUR' ? 'Adyen' : 'Stripe'}`);
  console.log('Order ID:', order.connectorOrderId);
  return order;
}

// EUR order goes to Adyen
createOrder('order-456', 'EUR', 2500);

// USD order goes to Stripe
createOrder('order-123', 'USD', 1000);
```


#### **Python**

```python
import asyncio
import os
from payments import PaymentClient
from payments.generated import sdk_config_pb2, payment_pb2

async def create_payment(order_id, currency, amount):
    # Configure Stripe client for USD payments
    stripe_config = sdk_config_pb2.ConnectorConfig(
        options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX),
    )
    stripe_config.connector_config.stripe.api_key.value = os.getenv('STRIPE_API_KEY')
    stripe_client = PaymentClient(stripe_config)

    # Configure Adyen client for EUR payments
    adyen_config = sdk_config_pb2.ConnectorConfig(
        options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX),
    )
    adyen_config.connector_config.adyen.api_key.value = os.getenv('ADYEN_API_KEY')
    adyen_config.connector_config.adyen.merchant_account = os.getenv('ADYEN_MERCHANT_ACCOUNT')
    adyen_client = PaymentClient(adyen_config)

    # Select client based on currency
    client = adyen_client if currency == 'EUR' else stripe_client

    # Create payment - route EUR to Adyen, USD to Stripe
    payment = await client.authorize(payment_pb2.PaymentServiceAuthorizeRequest(
        merchant_transaction_id=order_id,
        amount=payment_pb2.Amount(
            minor_amount=amount,
            currency=currency
        ),
        payment_method=payment_pb2.PaymentMethod(
            card=payment_pb2.CardDetails(
                card_number={'value': '4111111111111111'},
                card_exp_month={'value': '12'},
                card_exp_year={'value': '2030'},
                card_cvc={'value': '123'},
                card_holder_name={'value': 'John Doe'}
            )
        ),
        capture_method='AUTOMATIC',
        auth_type='NO_THREE_DS',
        return_url='https://example.com/return'
    ))

    provider = 'Adyen' if currency == 'EUR' else 'Stripe'
    print(f'Payment created with {provider}')
    print(f'Transaction ID: {payment.connector_transaction_id}')
    return payment

# EUR payment goes to Adyen
asyncio.run(create_payment('order-456', 'EUR', 2500))

# USD payment goes to Stripe
asyncio.run(create_payment('order-123', 'USD', 1000))
```


#### **Java**

```java
import com.juspay.hyperswitch.prism.PaymentClient;
import com.juspay.hyperswitch.prism.config.ConnectorConfig;
import com.juspay.hyperswitch.prism.config.SdkOptions;
import com.juspay.hyperswitch.prism.config.Environment;
import com.juspay.hyperswitch.prism.types.*;

public class Example {
    public static Payment createPayment(String orderId, String currency, long amount) {
        // Configure Stripe client for USD payments
        ConnectorConfig stripeConfig = ConnectorConfig.builder()
            .options(SdkOptions.builder()
                .environment(Environment.SANDBOX)
                .build())
            .connectorSpecificConfig(ConnectorSpecificConfig.builder()
                .stripe(StripeConfig.builder()
                    .apiKey(SecretString.of(System.getenv("STRIPE_API_KEY")))
                    .build())
                .build())
            .build();
        PaymentClient stripeClient = new PaymentClient(stripeConfig);

        // Configure Adyen client for EUR payments
        ConnectorConfig adyenConfig = ConnectorConfig.builder()
            .options(SdkOptions.builder()
                .environment(Environment.SANDBOX)
                .build())
            .connectorSpecificConfig(ConnectorSpecificConfig.builder()
                .adyen(AdyenConfig.builder()
                    .apiKey(SecretString.of(System.getenv("ADYEN_API_KEY")))
                    .merchantAccount(System.getenv("ADYEN_MERCHANT_ACCOUNT"))
                    .build())
                .build())
            .build();
        PaymentClient adyenClient = new PaymentClient(adyenConfig);

        // Select client based on currency
        PaymentClient client = "EUR".equals(currency) ? adyenClient : stripeClient;

        // Create payment - route EUR to Adyen, USD to Stripe
        PaymentServiceAuthorizeResponse payment = client.authorize(
            PaymentServiceAuthorizeRequest.builder()
                .merchantTransactionId(orderId)
                .amount(Amount.of(amount, Currency.valueOf(currency)))
                .paymentMethod(PaymentMethod.builder()
                    .card(CardDetails.builder()
                        .cardNumber(SecretString.of("4111111111111111"))
                        .cardExpMonth(SecretString.of("12"))
                        .cardExpYear(SecretString.of("2030"))
                        .cardCvc(SecretString.of("123"))
                        .cardHolderName("John Doe")
                        .build())
                    .build())
                .captureMethod(CaptureMethod.AUTOMATIC)
                .authType(AuthType.NO_THREE_DS)
                .returnUrl("https://example.com/return")
                .build()
        );

        String provider = "EUR".equals(currency) ? "Adyen" : "Stripe";
        System.out.println("Payment created with " + provider);
        System.out.println("Transaction ID: " + payment.getConnectorTransactionId());
        return payment;
    }

    public static void main(String[] args) {
        // EUR payment goes to Adyen
        createPayment("order-456", "EUR", 2500);

        // USD payment goes to Stripe
        createPayment("order-123", "USD", 1000);
    }
}
```
<!-- tabs:end -->


---


## 🔄 Switching Providers

// Select client based on currency
const client = currency === 'EUR' ? adyenClient : stripeClient;



Once the basic plumbing is implemented you can leverage Prism's core benefit - **switch payment providers by changing one line**.


```javascript
const { PaymentClient } = require('hs-playlib');
const { ConnectorConfig, ConnectorSpecificConfig, SdkOptions, Environment } = require('hs-playlib').types;

// Before: Using Stripe
const stripeConfig = ConnectorConfig.create({
    options: SdkOptions.create({ environment: Environment.SANDBOX }),
});
stripeConfig.connectorConfig = ConnectorSpecificConfig.create({
    stripe: { apiKey: { value: process.env.STRIPE_API_KEY } }
});
const paymentClient = new PaymentClient(stripeConfig);

const payment = await paymentClient.authorize({
    merchantTransactionId: 'order-123',
    amount: { minorAmount: 1000, currency: 'USD' },
    paymentMethod: {
        card: {
            cardNumber: { value: '4111111111111111' },
            cardExpMonth: { value: '12' },
            cardExpYear: { value: '2030' },
            cardCvc: { value: '123' },
            cardHolderName: { value: 'John Doe' }
        }
    },
    captureMethod: 'AUTOMATIC',
    authType: 'NO_THREE_DS'
});

// After: Switching to Braintree
const braintreeConfig = ConnectorConfig.create({
    options: SdkOptions.create({ environment: Environment.SANDBOX }),
});
braintreeConfig.connectorConfig = ConnectorSpecificConfig.create({
    braintree: {
        publicKey: { value: process.env.BRAINTREE_PUBLIC_KEY },
        privateKey: { value: process.env.BRAINTREE_PRIVATE_KEY },
        merchantAccountId: process.env.BRAINTREE_MERCHANT_ID
    }
});
const paymentClient = new PaymentClient(braintreeConfig);

// The authorize call stays exactly the same!
const payment = await paymentClient.authorize({
    merchantTransactionId: 'order-123',
    amount: { minorAmount: 1000, currency: 'USD' },
    paymentMethod: {
        card: {
            cardNumber: { value: '4111111111111111' },
            cardExpMonth: { value: '12' },
            cardExpYear: { value: '2030' },
            cardCvc: { value: '123' },
            cardHolderName: { value: 'John Doe' }
        }
    },
    captureMethod: 'AUTOMATIC',
    authType: 'NO_THREE_DS'
});
```

**One integration pattern. Any service category.**

No rewriting. No re-architecting. Just swap the config.
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