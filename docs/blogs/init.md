# Connector Service: A Unified Payment Integration Layer

## The Problem

In the era of global commerce, integrating and maintaining dozens of disparate payment APIs is a heavy engineering burden. As the need to add new payment methods, payment flows, or a new processor arises, the integration burden snowballs, forcing teams to manage non-standardized payloads, authentication protocols, and inconsistent error codes.

This problem of non-standardized implementations of similar functionality is not new — it was the preferred approach at the application layer of the TCP/IP stack, where applications have the freedom to define and implement their own constructs even if they were similar in functionality. Over time, unification abstractions emerged that give consumers the ability to swap out one implementation for another without major effort — a design principle that gives freedom from vendor lock-in.

Examples include:

* **JDBC**: Oracle / MySQL / PostgreSQL / SQL Server / SQLite / ...
* **OpenTelemetry**: Datadog / New Relic / Jaeger / Zipkin / Prometheus / ...
* **LiteLLM**: Gemini / OpenAI / Anthropic / Mistral / ...
* **OpenFeature**: Statsig / Datadog / Flagsmith / Devcycle / ...

Most of these unification abstractions gradually evolve to become de-facto standards. Payment integrations also have such abstractions via payment orchestrators like Spreedly and Primer — but none were managed and maintained by the community. Hyperswitch started as an open-source orchestrator project focused on building a full-fledged payment orchestrator. Connector integrations were maintained under a separate internal abstraction all along, with the hope of unbundling it someday.

Over the past year, we felt the need to make that separation real. We believe businesses integrating with one processor should be vendor-independent from day one — not only at the point they decide to switch. When we decided to unbundle, we also decided that the unification constructs had to be comprehensive enough to evolve into a standard maintained by the payments community. So we set out to:

1. Build a **specification** for payment integrations that can be managed via a community-driven process.
2. Build an **implementation** of that specification that runs anywhere — embedded in your process or deployed as a standalone service.

---

## The Specification: Proto-First Design

We chose **Protocol Buffers (protobuf)** to describe and document services, their methods, and all message types. The choice was driven by protobuf's wide support for type and client generation across all languages — a critical requirement for a library meant to be consumed from Python, JavaScript, Java, Kotlin, Rust, and Go.

The specification lives in `backend/grpc-api-types/proto/` and defines a rich surface across nine services:

| Service | Purpose |
|---|---|
| `PaymentService` | Authorize, capture, void, refund, and sync payment states |
| `RecurringPaymentService` | Charge and revoke mandates for subscription billing |
| `RefundService` | Retrieve and synchronize refund statuses |
| `DisputeService` | Submit evidence, defend, and accept chargebacks |
| `EventService` | Process inbound webhook events from connectors |
| `PaymentMethodService` | Tokenize and retrieve payment methods |
| `CustomerService` | Create and manage customer profiles at connectors |
| `MerchantAuthenticationService` | Generate access tokens and SDK session credentials |
| `PaymentMethodAuthenticationService` | Execute 3DS pre/authenticate/post flows |

Each service method has fully typed request and response messages. For example, `PaymentService.Authorize` takes a `PaymentServiceAuthorizeRequest` (containing amount, currency, payment method, customer details, metadata) and returns a `PaymentServiceAuthorizeResponse` (with status, connector reference IDs, and error details). Nothing is stringly typed. Nothing is freeform JSON.

The specification is the contract. The implementation below honors it.

---

## The Implementation

### Rust at the Core

The entire connector integration logic is written in **Rust**, organized across a set of internal crates:

- `connector-integration` — Connector-specific HTTP transformation logic for 50+ payment processors (Stripe, Adyen, Braintree, PayPal, etc.)
- `domain_types` — Shared domain models: `RouterDataV2`, flow markers (`Authorize`, `Capture`, `Refund`, ...), request/response data types
- `grpc-api-types` — Rust types generated from the protobuf specification via `prost`
- `interfaces` — Trait definitions for connector integration points

#### The Two-Phase Flow Pattern

Every payment operation follows the same two-phase pattern, regardless of connector:

```
┌─────────────┐    req_transformer     ┌──────────────────┐
│  Unified    │ ──────────────────────▶ │ Connector HTTP   │
│  Request    │                         │ Request          │
│  (proto)    │                         │ (URL, headers,   │
└─────────────┘                         │  body)           │
                                        └────────┬─────────┘
                                                 │  HTTP call
                                                 ▼
┌─────────────┐    res_transformer     ┌──────────────────┐
│  Unified    │ ◀────────────────────── │ Connector HTTP   │
│  Response   │                         │ Response         │
│  (proto)    │                         │ (raw bytes)      │
└─────────────┘                         └──────────────────┘
```

The `req_transformer` takes a unified protobuf request, constructs the connector-specific HTTP request (URL, headers, serialized body), and returns it. The caller makes the actual HTTP call. The `res_transformer` takes the raw HTTP response and the original request, and returns a unified protobuf response.

This clean separation means the core library is **stateless** and **transport-agnostic**: it does not own any HTTP connections or make any network calls itself. The caller controls the transport.

#### Flow Registration via Macros

New payment flows are registered using Rust macros in `backend/ffi/src/services/payments.rs`. Each flow requires a pair of transformer implementations:

```rust
// authorize request transformer
req_transformer!(
    fn_name: authorize_req_transformer,
    request_type: PaymentServiceAuthorizeRequest,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<T>,
    response_data_type: PaymentsResponseData,
);

// authorize response transformer
res_transformer!(
    fn_name: authorize_res_transformer,
    request_type: PaymentServiceAuthorizeRequest,
    response_type: PaymentServiceAuthorizeResponse,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<T>,
    response_data_type: PaymentsResponseData,
);
```

The macros generate the full boilerplate: looking up the connector by name, getting the connector integration trait object, constructing the `RouterDataV2` struct, calling the connector's transformation logic, and serializing the result. Adding a new flow means implementing the connector trait method and registering it here — the rest flows from the code generator.

---

### Two Ways to Consume the Service

The same Rust core is exposed through two distinct deployment modes. Critically, the API surface — defined by the protobuf specification — is identical in both. Your application code does not need to change if you switch between modes.

```
┌─────────────────────────────────────────────────────────┐
│                   Your Application                       │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
  ┌──────────────┐         ┌─────────────────┐
  │  SDK Mode    │         │  gRPC Mode      │
  │  (FFI/UniFFI)│         │  (Client/Server)│
  └──────┬───────┘         └────────┬────────┘
         │                          │
         │  in-process              │  network call
         ▼                          ▼
  ┌──────────────────────────────────────────┐
  │           Rust Core (connector-service)   │
  │    req_transformer → HTTP → res_transformer│
  └──────────────────────────────────────────┘
```

#### Mode 1: Embedded SDK via FFI

In SDK mode, the Rust core is compiled into a native shared library (`.so` on Linux, `.dylib` on macOS) and exposed to host languages via **UniFFI** — Mozilla's Rust FFI framework that generates language bindings automatically from Rust interface definitions.

The FFI layer in `backend/ffi/` sits directly on top of the core:

- `bindings/uniffi.rs` — UniFFI bridge: the `define_ffi_flow!` macro exposes `{flow}_req_transformer` and `{flow}_res_transformer` as callable FFI symbols for each registered flow
- `handlers/payments.rs` — Loads the embedded config, delegates to service transformers via `impl_flow_handlers!`
- `services/payments.rs` — The actual transformer implementations, wired to domain types

When a Python application calls `authorize_req_transformer(request_bytes, options_bytes)`, the call goes directly into the Rust binary in the same process. No serialization overhead beyond protobuf (which would be needed regardless). No network round-trip. No separate process to manage.

The FFI layer passes data as serialized protobuf bytes in both directions — this is both efficient and language-neutral. Every language already has a protobuf runtime, so there is no custom serialization protocol to maintain.

#### Mode 2: gRPC Client/Server

In gRPC mode, the `backend/grpc-server` crate runs as a standalone Tonic (Rust async gRPC) server. It implements the same nine proto services, but instead of being called via FFI it accepts network connections from any language's generated gRPC client.

The gRPC server uses the Rust core **directly** — it calls the same service transformer functions as the FFI layer, just from a different entry point. The HTTP transport is handled by the server itself via a built-in HTTP client; the connector HTTP calls happen inside the server process, not in the caller's process.

Clients connect using standard gRPC stubs generated from the same `services.proto`. Each SDK includes a `grpc-client/` subdirectory alongside the FFI-based SDK client:

```
sdk/python/
├── src/payments/           ← FFI-based SDK client
│   ├── connector_client.py
│   └── _generated_service_clients.py
└── grpc-client/            ← gRPC stub client (generated from proto)

sdk/java/
├── src/                    ← FFI-based SDK client (JNA + UniFFI)
└── grpc-client/            ← gRPC stub client

sdk/javascript/
├── src/payments/           ← FFI-based SDK client (node-ffi)
└── grpc-client/            ← gRPC stub client
```

The same protobuf message types are used in both paths. `PaymentServiceAuthorizeRequest` is built identically whether you are calling the FFI SDK or a remote gRPC server.

#### Choosing Between the Two Modes

| Consideration | SDK (FFI) | gRPC Server |
|---|---|---|
| **Deployment** | Library bundled in your app | Separate service to deploy and scale |
| **Latency** | In-process, ~microseconds | Network call, ~milliseconds |
| **Language** | Python, JS, Java/Kotlin, Rust (native bindings) | Any language with gRPC support |
| **Process isolation** | Runs in your process | Fully isolated |
| **Connector HTTP** | Your app's outbound HTTP | Server's outbound HTTP |
| **Best for** | Serverless, edge, single-language services | Polyglot stacks, shared infrastructure |

---

### Code Generation: From Proto to Typed SDK

Adding a new flow to the connector service should not require writing boilerplate in five languages. The code generator at `sdk/codegen/generate.py` eliminates this entirely by cross-referencing two sources of truth and emitting all SDK client code automatically.

#### The Two Sources of Truth

1. **`services.proto`** (compiled to a binary descriptor via `protoc`): defines every RPC, its request type, its response type, and its doc comment.
2. **`backend/ffi/src/services/payments.rs`**: defines which flows are actually implemented (by the presence of `req_transformer!` invocations).

The generator performs a set intersection: only flows that appear in both the proto definition *and* the Rust implementation are emitted. A flow defined in proto but not yet implemented is reported as a warning and skipped. A flow implemented in Rust but missing from proto is also warned about — the spec is the authority.

#### What Gets Generated

Running `make generate` (or `python3 sdk/codegen/generate.py`) produces:

**Rust FFI registration files** (in `backend/ffi/src/`):
- `_generated_flow_registrations.rs` — `impl_flow_handlers!` calls wiring each flow to its handlers
- `_generated_ffi_flows.rs` — `define_ffi_flow!` calls exposing each flow via UniFFI

**Python SDK** (in `sdk/python/src/payments/`):
- `_generated_flows.py` — flow metadata dictionary (flow name → response type)
- `_generated_service_clients.py` — per-service client classes with typed methods:
  ```python
  class PaymentClient(_ConnectorClientBase):
      async def authorize(self, request: PaymentServiceAuthorizeRequest, options=None) -> PaymentServiceAuthorizeResponse:
          """PaymentService.Authorize — Authorizes a payment amount..."""
          return await self._execute_flow("authorize", request, _pb2.PaymentServiceAuthorizeResponse, options)
  ```
- `connector_client.pyi` — type stubs for IDE completions and static analysis (Pylance, mypy)

**JavaScript/TypeScript SDK** (in `sdk/javascript/src/payments/`):
- `_generated_flows.js` — flow dispatch table for the FFI layer
- `_generated_connector_client_flows.ts` — per-service typed client classes
- `_generated_uniffi_client_flows.ts` — typed wrappers around raw FFI byte calls

**Java/Kotlin SDK** (in `sdk/java/src/main/kotlin/`):
- `GeneratedFlows.kt` — `FlowRegistry` object (maps flow names to transformer function references via UniFFI Kotlin bindings) and per-service typed client classes:
  ```kotlin
  class PaymentClient(config: ConnectorConfig, ...) : ConnectorClient(config, ...) {
      fun authorize(request: PaymentServiceAuthorizeRequest, options: RequestConfig? = null): PaymentServiceAuthorizeResponse =
          executeFlow("authorize", request.toByteArray(), PaymentServiceAuthorizeResponse.parser(), options)
  }
  ```

The generator also handles **single-step flows** (such as webhook processing) that do not require an HTTP round-trip — these get a `_execute_direct` code path instead of the two-phase req/HTTP/res path.

#### The Full Code Generation Pipeline

```
services.proto
    │
    ├── protoc ──────────────────────────────────┐
    │   (compile to binary descriptor)            │
    │                                             ▼
    │                                     services.desc
    │                                             │
    ├── prost (Rust) ──────────────────────┐      │
    │   (generates Rust types)             │      │
    │                                      ▼      │
    │                               grpc-api-types │
    │                               (Rust crate)  │
    │                                             │
    ├── grpc_tools.protoc (Python) ───────────┐   │
    │   (generates Python proto stubs)        │   │
    │                                         ▼   │
    │                               payment_pb2.py │
    │                                             │
    ├── protoc-gen-java / Kotlin ─────────────┐   │
    │   (generates Java/Kotlin proto stubs)   │   │
    │                                         ▼   │
    │                              Payment.java    │
    │                                             │
    └── protoc (JS + TS plugin) ─────────────┐   │
        (generates JS proto stubs)            │   │
                                              ▼   ▼
                                         payment.js
                                              │
                                              │
backend/ffi/src/services/payments.rs ────────▼
    │  (transformer implementations)    generate.py
    │                                        │
    └────────────────────────────────────────┤
                                             │
                            ┌────────────────┼────────────────────┐
                            ▼                ▼                     ▼
                  _generated_ffi_flows.rs  *.py           GeneratedFlows.kt
                  _generated_flow_         *.ts           *.js
                  registrations.rs         *.pyi
```

UniFFI runs as a separate pass over the compiled Rust binary:

```
cargo build --features uniffi
    │
    └── uniffi-bindgen ───────────────────────────────────────────┐
        (reads Rust proc macros + UDL)                             │
                                         ┌─────────────────────────┼────────────────┐
                                         ▼                         ▼                ▼
                              connector_service_ffi.py   ConnectorServiceFfi.kt   ffi.js
                              (Python native bindings)   (Kotlin/JVM bindings)    (Node bindings)
```

The result: when a new payment flow is added to `services.proto` and implemented in Rust, a single `make generate` emits typed, documented client methods in Python, TypeScript, Kotlin, and Rust simultaneously. No manual SDK maintenance. No drift between languages.

---

### Multi-Language SDK Architecture

Each language SDK follows the same structural pattern but adapts it to language idioms:

#### Python
```
sdk/python/
├── src/payments/
│   ├── connector_client.py          ← _ConnectorClientBase: async httpx, protobuf bytes over FFI
│   ├── _generated_service_clients.py ← PaymentClient, MerchantAuthenticationClient, ...
│   ├── _generated_flows.py          ← flow metadata (generated)
│   ├── connector_client.pyi         ← type stubs for IDE (generated)
│   └── generated/
│       ├── connector_service_ffi.py ← UniFFI-generated Python bindings
│       └── payment_pb2.py           ← protoc-generated protobuf stubs
```

Python usage:
```python
from payments import PaymentClient, ConnectorConfig, ConnectorEnum, Environment
from payments.generated.payment_pb2 import (
    PaymentServiceAuthorizeRequest, Money, Currency, PaymentMethod, CardDetails
)

client = PaymentClient(ConnectorConfig(
    connector=ConnectorEnum.STRIPE,
    environment=Environment.SANDBOX,
    auth=...,
))

response = await client.authorize(PaymentServiceAuthorizeRequest(
    amount=Money(minor_amount=1000, currency=Currency.USD),
    payment_method=PaymentMethod(card=CardDetails(...)),
))
```

#### JavaScript / TypeScript
```
sdk/javascript/
├── src/payments/
│   ├── connector_client.ts                      ← ConnectorClient base (node-ffi, protobufjs)
│   ├── _generated_connector_client_flows.ts     ← PaymentClient, ... (generated)
│   ├── _generated_uniffi_client_flows.ts        ← raw FFI byte dispatch (generated)
│   ├── _generated_flows.js                      ← flow dispatch table (generated)
│   └── generated/
│       └── proto.js / proto.d.ts                ← protoc-generated stubs
```

#### Java / Kotlin
```
sdk/java/
├── src/main/kotlin/
│   ├── ConnectorClient.kt      ← base client (JNA for FFI, prost for proto)
│   └── GeneratedFlows.kt       ← FlowRegistry + PaymentClient, ... (generated)
└── src/main/proto/
    └── payment.proto           ← proto source (symlinked from backend/)
```

The Java SDK uses **JNA** (Java Native Access) to call into the native `.so`/`.dylib`, and the standard protobuf Java runtime for message serialization. The Kotlin `FlowRegistry` object maps flow names to UniFFI-generated Kotlin transformer functions, enabling the generic `ConnectorClient.executeFlow()` to dispatch correctly at runtime without reflection.

#### Rust
The Rust SDK is the most direct: it calls the FFI handlers without any language bridging layer. It links directly against the `connector-service-ffi` crate and calls `authorize_req_handler` / `authorize_res_handler` as ordinary Rust function calls. The `ConnectorClient` in `sdk/rust/src/connector_client.rs` owns an `HttpClient` (reqwest), builds the FFI request, executes the HTTP call, and runs the response transformer — all in idiomatic async Rust.

---

## Putting It All Together: The Full Request Lifecycle

Here is the complete lifecycle of an `authorize` call through the Python FFI SDK:

```
1. Application builds PaymentServiceAuthorizeRequest (protobuf message)

2. PaymentClient.authorize() calls _execute_flow("authorize", request, ...)

3. _ConnectorClientBase._execute_flow():
   a. Serializes request to bytes (request.SerializeToString())
   b. Calls authorize_req_transformer(request_bytes, options_bytes)
      └── FFI boundary: Python → Rust shared library
          └── Rust: build_router_data! macro
              ├── Looks up connector by name (e.g. ConnectorEnum::Stripe)
              ├── Gets connector integration trait object
              ├── Deserializes proto bytes → PaymentFlowData + PaymentsAuthorizeData
              ├── Constructs RouterDataV2
              └── Calls connector.build_request() → Returns HTTP Request
          └── Serializes HTTP Request → FfiConnectorHttpRequest bytes
      └── Returns: FfiConnectorHttpRequest bytes
   c. Deserializes FfiConnectorHttpRequest → url, method, headers, body
   d. Executes HTTP request via httpx AsyncClient
   e. Receives raw HTTP response bytes
   f. Calls authorize_res_transformer(response_bytes, request_bytes, options_bytes)
      └── FFI boundary: Python → Rust shared library
          └── Rust: calls connector.handle_response()
              ├── Deserializes connector-specific JSON response
              └── Maps to unified PaymentServiceAuthorizeResponse
          └── Serializes response → proto bytes
      └── Returns: PaymentServiceAuthorizeResponse bytes
   g. Deserializes bytes → PaymentServiceAuthorizeResponse

4. Application receives unified PaymentServiceAuthorizeResponse
```

In gRPC mode, steps 3b–3f happen inside the `grpc-server` process instead of in the caller's process. The application sends the protobuf request over the wire and receives the protobuf response back. Everything else — the connector lookup, the HTTP call to the payment processor, the response transformation — is identical.

---

## What This Means for the Community

The connector service is designed to be a community standard, not a proprietary integration layer. A few properties make this possible:

**The specification is the contract.** All nine services, every RPC, every message type is defined in `.proto` files that can be read, discussed, and evolved through community pull requests. Adding a new payment flow means first agreeing on the proto shape, then implementing it.

**Adding a connector is a single-language task.** New connector integrations are written once in Rust, in `connector-integration/`. The FFI layer, gRPC server, and all language SDKs automatically pick them up. You do not need to write Python or JavaScript to add a connector.

**Adding a flow is a two-step task.** Extend `services.proto` with the new RPC and message types, implement the Rust transformer pair in `services/payments.rs`, then run `make generate`. All SDK languages get typed, documented client methods automatically.

**The dual-mode design removes the "library vs. service" choice as a lock-in vector.** Start with the embedded SDK in development. Deploy the gRPC server in production for isolation and multi-language access. The API is the same.

The goal is a payments integration ecosystem where processors compete on features and pricing, not on API design. A unified, community-owned specification is the foundation for that.
