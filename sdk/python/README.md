# hyperswitch-prism

**Universal Connector Service — Python SDK**

A high-performance, type-safe Python SDK for payment processing through the Universal Connector Service. Connect to 50+ payment processors (Stripe, PayPal, Adyen, and more) through a single, unified API.

[![PyPI version](https://badge.fury.io/py/hyperswitch-prism.svg)](https://pypi.org/project/hyperswitch-prism/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## 📚 Documentation

| Resource | Link |
|----------|------|
| **Getting Started** | [Installation](https://github.com/juspay/hyperswitch-prism/blob/main/docs/getting-started/installation.md) · [First Payment](https://github.com/juspay/hyperswitch-prism/blob/main/docs/getting-started/first-payment.md) |
| **Architecture** | [Overview](https://github.com/juspay/hyperswitch-prism/blob/main/docs/architecture/README.md) · [Core Concepts](https://github.com/juspay/hyperswitch-prism/tree/main/docs/architecture/concepts) |
| **API Reference** | [Payment Service](https://github.com/juspay/hyperswitch-prism/tree/main/docs/api-reference/services/payment-service) |
| **Examples** | [Connector Examples](https://github.com/juspay/hyperswitch-prism/tree/main/examples) · [Smoke Test](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/smoke-test) · [Tests](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/tests) |
| **Main Project** | [Prism Docs](https://github.com/juspay/hyperswitch-prism/blob/main/docs/README.md) |

---

## Features

- 🚀 **High Performance** — Direct UniFFI FFI bindings to Rust core
- 🔌 **50+ Connectors** — Single SDK for Stripe, PayPal, Adyen, and more
- 🐍 **Python Native** — Full Python bindings with type hints
- ⚡ **Connection Pooling** — Built-in HTTP connection pooling via httpx
- 🛡️ **Type-Safe** — Protobuf-based request/response serialization
- 🔧 **Configurable** — Per-request or global configuration for timeouts, proxies, and auth

---

## 🤖 AI Assistant Context

This SDK is part of **Hyperswitch Prism** — a unified connector library for payment processors.

### What This SDK Does

1. **Request Transformation**: Converts unified payment requests to connector-specific formats (Stripe, Adyen, PayPal, etc.)
2. **Response Normalization**: Transforms connector responses back to a unified schema
3. **Error Handling**: Provides consistent error types (`IntegrationError`, `ConnectorError`, `NetworkError`) regardless of connector

### Architecture

```
Your Python App
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  Service Clients (PaymentClient, CustomerClient, etc.)       │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  ConnectorClient (httpx connection pool + HTTP execution)    │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  UniFFI FFI Bindings (connector_service_ffi.py)              │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  Rust Core (connector transformation logic)                  │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
              Payment Processor APIs (Stripe, Adyen, etc.)
```

### Key Files

| File | Purpose |
|------|---------|
| `src/payments/__init__.py` | Public API exports (clients, types, errors) |
| `src/payments/connector_client.py` | HTTP execution layer with httpx |
| `src/payments/generated/connector_service_ffi.py` | UniFFI-generated FFI bindings |
| `src/payments/generated/payment_pb2.py` | Protobuf message definitions |

### Package & Import

- **Package Name**: `hyperswitch-prism`
- **Installation**: `pip install hyperswitch-prism`
- **Import**: `from payments import PaymentClient`

---

## Installation

```bash
pip install hyperswitch-prism
```

**Requirements:**
- Python 3.9+
- Rust toolchain (for building native bindings from source)

**Platform Support:**
- ✅ macOS (x64, arm64)
- ✅ Linux (x64, arm64)
- ✅ Windows (x64)

---

## Quick Start

### 1. Configure the Client

```python
import os
from payments import PaymentClient, types

# Configure connector identity and authentication
stripe_config: types.ConnectorConfig = {
    "connectorConfig": {
        "stripe": {
            "apiKey": {"value": os.environ["STRIPE_API_KEY"]}
        }
    }
}

# Optional: Request defaults for timeouts
request_config: types.RequestConfig = {
    "http": {
        "totalTimeoutMs": 30000,
        "connectTimeoutMs": 10000
    }
}
```

### 2. Process a Payment

```python
from payments import Currency, CaptureMethod, AuthenticationType

client = PaymentClient(stripe_config, request_config)

authorize_request = {
    "merchantTransactionId": "txn_order_001",
    "amount": {
        "minorAmount": 1000,  # $10.00
        "currency": Currency.USD
    },
    "captureMethod": CaptureMethod.AUTOMATIC,
    "paymentMethod": {
        "card": {
            "cardNumber": {"value": "4111111111111111"},
            "cardExpMonth": {"value": "12"},
            "cardExpYear": {"value": "2027"},
            "cardCvc": {"value": "123"},
            "cardHolderName": {"value": "John Doe"}
        }
    },
    "address": {"billingAddress": {}},
    "authType": AuthenticationType.NO_THREE_DS,
    "returnUrl": "https://example.com/return",
    "orderDetails": []
}

response = client.authorize(authorize_request)
print(f"Status: {response.status}")
print(f"Transaction ID: {response.connectorTransactionId}")
```

---

## Service Clients

The SDK provides specialized clients for different service domains:

| Client | Purpose | Key Methods |
|--------|---------|-------------|
| `PaymentClient` | Core payment operations | `authorize()`, `capture()`, `refund()`, `void()` |
| `CustomerClient` | Customer management | `create()` |
| `PaymentMethodClient` | Secure tokenization | `tokenize()` |
| `MerchantAuthenticationClient` | Auth token management | `create_server_authentication_token()`, `create_server_session_authentication_token()`, `create_client_authentication_token()` |
| `EventClient` | Webhook processing | `handle_event()` |
| `RecurringPaymentClient` | Subscription billing | `charge()` |
| `PaymentMethodAuthenticationClient` | 3DS authentication | `pre_authenticate()`, `authenticate()`, `post_authenticate()` |

---

## Authentication Examples

### Stripe (HeaderKey)

```python
import os
from payments import types

stripe_config: types.ConnectorConfig = {
    "connectorConfig": {
        "stripe": {
            "apiKey": {"value": os.environ["STRIPE_API_KEY"]}
        }
    }
}
```

### PayPal (SignatureKey)

```python
import os
from payments import types

paypal_config: types.ConnectorConfig = {
    "connectorConfig": {
        "paypal": {
            "clientId": {"value": os.environ["PAYPAL_CLIENT_ID"]},
            "clientSecret": {"value": os.environ["PAYPAL_CLIENT_SECRET"]}
        }
    }
}
```

---

## Advanced Configuration

### Proxy Settings

```python
from payments import types

proxy_config: types.RequestConfig = {
    "http": {
        "proxy": {
            "httpsUrl": "https://proxy.company.com:8443",
            "bypassUrls": ["http://localhost"]
        }
    }
}
```

### Per-Request Overrides

```python
response = client.authorize(request, {
    "http": {
        "totalTimeoutMs": 60000  # Override for this request only
    }
})
```

### Connection Pooling

Each client instance maintains its own connection pool. For best performance:

```python
# ✅ Create client once, reuse for multiple requests
client = PaymentClient(config, defaults)

for payment in payments:
    client.authorize(payment)
```

---

## Error Handling

```python
from payments import IntegrationError, ConnectorError

try:
    response = client.authorize(request)
except IntegrationError as e:
    # Request-phase error (auth, URL construction, serialization, etc.)
    print(f"Code: {e.error_code}")
    print(f"Status: {e.status_code}")
    print(f"Message: {e.message}")
except ConnectorError as e:
    # Response-phase error (deserialization, transformation, etc.)
    print(f"Code: {e.error_code}")
    print(f"Status: {e.status_code}")
    print(f"Message: {e.message}")
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

```python
import os
from payments import (
    PaymentClient,
    MerchantAuthenticationClient,
    types
)

# Configure PayPal
paypal_config: types.ConnectorConfig = {
    "connectorConfig": {
        "paypal": {
            "clientId": {"value": os.environ["PAYPAL_CLIENT_ID"]},
            "clientSecret": {"value": os.environ["PAYPAL_CLIENT_SECRET"]}
        }
    }
}

# Step 1: Get access token
auth_client = MerchantAuthenticationClient(paypal_config)
token_response = auth_client.create_server_authentication_token({
    "merchantAccessTokenId": "token_001",
    "connector": "PAYPAL",
    "testMode": True
})

# Step 2: Authorize with access token
payment_client = PaymentClient(paypal_config)
payment_response = payment_client.authorize({
    "merchantTransactionId": "txn_001",
    "amount": {
        "minorAmount": 1000,
        "currency": "USD"
    },
    "captureMethod": "AUTOMATIC",
    "paymentMethod": {
        "card": {
            "cardNumber": {"value": "4111111111111111"},
            "cardExpMonth": {"value": "12"},
            "cardExpYear": {"value": "2027"},
            "cardCvc": {"value": "123"}
        }
    },
    "state": {
        "accessToken": {
            "token": {"value": token_response.accessToken.value},
            "tokenType": "Bearer",
            "expiresInSeconds": token_response.expiresInSeconds
        }
    },
    "testMode": True
})

print(f"Payment status: {payment_response.status}")
```

---

## Architecture

```
Your App → Service Client → ConnectorClient → UniFFI FFI → Rust Core → Connector API
                ↓
         Connection Pool (httpx)
```

The SDK uses:
- **UniFFI** — FFI bindings to Rust
- **protobuf** — Protocol buffer serialization
- **httpx** — High-performance HTTP client with connection pooling

---

## Building from Source

```bash
# Clone the repository
git clone https://github.com/juspay/connector-service.git
cd connector-service/sdk/python

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
2. `make generate-bindings` — runs `uniffi-bindgen` to produce `generated/connector_service_ffi.py`
3. `make generate-proto` — runs `grpc_tools.protoc` to produce `generated/payment_pb2.py`
4. `make pack-archive` — runs `pip wheel` to produce the installable `.whl`
