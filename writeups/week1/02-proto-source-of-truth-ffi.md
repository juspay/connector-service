# One Rust core. Five language SDKs. Zero behavioral drift.

> How `proto` + `uniffi` + a transformer-only core gets you Python, JS, Java, Kotlin, and Rust for the price of *one* implementation — without locking you into a Rust HTTP client.
> *Hyperswitch Prism · Week 1 / Post 2*

---

## The integration tax everybody pays

You pick a payments library in Python. Six months later, your platform team builds a backend service in Java. Same payment processors. Same contracts. Yet you're now maintaining:

- A Python SDK that drifted toward whatever the lead Python dev thought made sense at the time.
- A Java SDK that's "based on the same idea but written natively" (read: subtly different field names, slightly different error codes).
- A Node SDK that was rewritten by someone new and doesn't quite match either of the others.
- And a `tests/` folder full of bug reports of the form "works in Python, doesn't in Java, same processor, same API version."

This is the SDK-per-language tax. Every payments company pays it. Most pay it badly. The fundamental problem: each SDK is an *independent* port of the same intent. There's no source of truth. There's just N drifted forks.

Prism gives up on that model. We have **one source of truth — the `.proto` file — and one implementation — a Rust core**. Every SDK is a thin shell over that core, generated and bound by [`uniffi`](https://github.com/mozilla/uniffi-rs) (Mozilla's Rust→language binding generator, originally built for Firefox). Same bytes, same logic, same bugs (when they exist), same fixes (when we ship them).

Here's how it actually works.

---

## Layer 1 — the proto file is the contract

Open `crates/types-traits/grpc-api-types/proto/payment.proto`. Open `services.proto`. These two files **are** Prism. Every type, every flow, every field, every error code — defined once, in proto.

```proto
service PaymentService {
  rpc Authorize(PaymentServiceAuthorizeRequest) returns (PaymentServiceAuthorizeResponse);
  rpc Get(PaymentServiceGetRequest)             returns (PaymentServiceGetResponse);
  rpc Capture(PaymentServiceCaptureRequest)     returns (PaymentServiceCaptureResponse);
  rpc Refund(PaymentServiceRefundRequest)       returns (RefundResponse);
  rpc Reverse(PaymentServiceReverseRequest)     returns (PaymentServiceReverseResponse);
  rpc Void(PaymentServiceVoidRequest)           returns (PaymentServiceVoidResponse);
  // ...
}
```

```proto
message Money {
  int64 minor_amount = 1;
  Currency currency  = 2;
}

message RequestDetails {
  HttpMethod method                  = 1;
  optional string uri                = 2;
  map<string, string> headers        = 3;
  bytes body                         = 4;
  optional string query_params       = 5;
}
```

This isn't decoration. The proto is *consumed by every layer*:

- The Rust core uses `prost` types directly — no manual struct definitions.
- The gRPC server is generated from it (`tonic`).
- Each SDK's typed client is generated from it (`grpc_tools`, `protoc-gen-ts`, `protoc-gen-java`).
- The FFI layer's request/response envelopes are *also* proto messages (`FfiResult`, `FfiConnectorHttpRequest`, `FfiConnectorHttpResponse`) — yes, even the boundary itself is typed.
- The error model — `IntegrationError`, `ConnectorError` — is defined in proto so every language sees the *same* error fields with the *same* codes.

When we add a field to `PaymentServiceAuthorizeRequest`, it shows up in Python, Node, Java, Kotlin, and Rust on the next `make generate`. There is no "we forgot to update the Java SDK" story. There can't be.

## Layer 2 — the Rust core is a transformer, not a client

Here's the part that matters most and that most "multi-language SDKs" get wrong.

A traditional SDK looks like this:

```text
[user code] -> [SDK builds request] -> [SDK runs HTTP] -> [SDK parses response] -> [user code]
                                          ^^^^^^^^^^^^^
                                       this part is the SDK's
```

The HTTP execution is *inside* the SDK. The SDK ships with its own HTTP client (reqwest, httpx, OkHttp, undici…) embedded. Five SDKs = five embedded HTTP clients, each with their own retry policy, their own connection pool tuning, their own proxy handling, their own TLS story.

Prism is built differently. The Rust core is a pair of pure functions:

```rust
// Conceptual signature — see crates/ffi/ffi/src/bindings/uniffi.rs
fn req_transformer(request_proto: bytes, options: bytes) -> bytes;  // -> FfiConnectorHttpRequest
fn res_transformer(response_proto: bytes, options: bytes) -> bytes; // -> typed response
```

`req_transformer` takes your `PaymentServiceAuthorizeRequest` and returns the **HTTP request bytes that should go to the upstream processor** — URL, method, headers, body. It does not execute the request. It just builds it.

`res_transformer` takes the HTTP response bytes you got back and returns a typed `PaymentServiceAuthorizeResponse`.

In between those two FFI calls, the **SDK's `ConnectorClient`** runs the HTTP — using a *language-native* HTTP library (`httpx` in Python, `undici` / native `fetch` in Node, `OkHttp` in Java, …), not a Rust client crammed through FFI. From your application's point of view, you still make one method call (`connector_client.authorize(...)`); the FFI → HTTP → FFI loop happens inside the SDK. But the HTTP client is yours to shape: pass in your own configured instance, set proxy URL / timeouts / TLS, plug in a retry middleware, attach tracing — anything your language's HTTP ecosystem already supports works here, because the SDK is *using that ecosystem*, not reinventing it.

The Rust core itself has zero I/O. No reqwest. No tokio runtime touching sockets. No surprise behavior at 3 AM because an embedded Rust HTTP client decided to retry an idempotency-unsafe request.

This single design choice cascades into a lot of good consequences:

**Vault proxies just work.** VGS, Basis Theory, Spreedly — these substitute card aliases for real PANs in-flight. Configure the SDK's HTTP client to route through the vault proxy URL and Prism doesn't need to know. The proto has a `ProxyAuthorize` flow that uses vault aliases as card data, but the actual proxy intercept happens in the SDK's host HTTP client, exactly where it should.

**Mocking is trivial.** The Python SDK has a one-liner test hook to intercept HTTP without touching the FFI. The smoke tests use it. You can too:

```python
# sdk/python/src/payments/http_client.py
_intercept: Optional[callable] = None  # async (request: HttpRequest) -> HttpResponse
```

**Retries belong to the host.** A network blip retrying a `Capture` is a financial bug. A host-level retry policy that knows which flows are idempotent (and which connector idempotency keys are required) is yours to write. We don't guess.

**No fight over HTTP libraries.** Python users get `httpx`. Node users get the runtime's native fetch / undici. Java users get whatever HTTP client they were already using. Nobody has to swallow our opinion about TLS or connection pooling.

## Layer 3 — uniffi binds the core to every language

The core lives in `crates/ffi/ffi/`:

```toml
# crates/ffi/ffi/Cargo.toml
[lib]
name = "connector_service_ffi"
crate-type = ["cdylib", "rlib"]

[dependencies]
uniffi = { version = "0.29", optional = true }
prost  = { workspace = true }
```

We compile to a single `cdylib` — a C-compatible shared library (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows), one binary per `(OS, arch)`. `uniffi` then generates idiomatic bindings for Python, Kotlin, and Swift directly; JavaScript/TypeScript and Java sit on top of the same shared library via a thin generated client and the same proto envelopes.

The boundary itself is proto, not language types. From `bindings/uniffi.rs`:

```rust
pub fn run_req_transformer<Req>(
    request_bytes: Vec<u8>,
    options_bytes: Vec<u8>,
    handler: impl Fn(...) -> Result<Option<Request>, IntegrationError>,
) -> Vec<u8>
where Req: Message + Default
{
    let payload = Req::decode(Bytes::from(request_bytes))?;  // proto in
    // ... transform ...
    FfiResult { ... }.encode_to_vec()                        // proto out
}
```

Every language ↔ Rust call goes through `bytes` carrying a known proto message. Why bytes-and-proto instead of language-native types crossing the FFI?

1. **Schema is checked at the wire, not at the binding.** A breaking change in the proto fails decode loudly on every SDK at the same time. No "Java SDK accidentally accepts a missing field that Python rejects."
2. **Adding a language is small.** Take the cdylib, generate the proto bindings in the new language, write a few hundred lines of glue. No re-implementing payment logic.
3. **`FfiResult` is itself a proto union.** Success carries `FfiConnectorHttpRequest` / `FfiConnectorHttpResponse`. Failure carries `IntegrationError` or `ConnectorError`. One envelope, four cases, every language sees it the same.

Look at how the Python client handles it:

```python
# sdk/python/src/payments/connector_client.py
def check_req(result_bytes: bytes) -> Any:
    result = FfiResult()
    result.ParseFromString(result_bytes)
    if result.type == FfiResult.HTTP_REQUEST:
        return result.http_request
    elif result.type == FfiResult.INTEGRATION_ERROR:
        raise IntegrationError(result.integration_error)
    elif result.type == FfiResult.CONNECTOR_ERROR:
        raise ConnectorError(result.connector_error)
```

That same dispatch, line for line in shape, lives in the Node, Java, and Kotlin SDKs. Because they all decode the same `FfiResult` proto.

## Layer 4 — the SDK clients are mostly generated

`make generate` produces, per language:

- `_generated_grpc_client.{py,ts}` — typed gRPC client (when you talk to the Prism gRPC server).
- `_generated_uniffi_client_flows.{py,ts}` — typed FFI client (when you embed Prism in-process).
- `_generated_flows.{py,js}` — flow registry.
- `_generated_service_clients.py` — per-service classes (`PaymentClient`, `RefundClient`, `EventClient`, …).

The hand-written SDK code is small: the round-trip wrapper, the HTTP execution, the error model. Everything else is mechanical translation of the proto.

The result: when we add `PaymentService.IncrementalAuthorization` (we did), it appears in Python, Node, and Java in the same release. Same parameters. Same response shape. Same error codes.

## What this means in practice

Three concrete things:

**1. You write your code once. Connector quirks get fixed once.**

When a processor changes a field shape, an error-code mapping, or a 3DS flow, the patch is one change in Rust — it propagates to every SDK on the next release. Compare to the SDK-per-language model where the same fix has to be ported, reviewed, and released in N places, often by N different people, often with N different bugs introduced.

**2. The SDK uses your language's native HTTP client — you keep configuring it.**

Your existing infra doesn't get renegotiated when you adopt Prism:
- A retry policy your SREs trust.
- A proxy / vault setup (VGS, Basis Theory, mTLS to a payment HSM, whatever).
- A tracing system (OpenTelemetry, Datadog, your in-house thing).
- Network policies, allowlists, egress rules.

The SDK's `ConnectorClient` is the one running the HTTP — but it's running it through `httpx` / `undici` / `OkHttp` / etc., the *same library* your application is already using. You can pass the SDK a pre-configured client instance, attach middleware, set proxy and TLS, plug in tracing — and all of it works because the SDK isn't shipping a black-box HTTP stack, it's borrowing your language's.

**3. Adding a new language is cheap, not heroic.**

Want a Go SDK? Rust core stays the same. You write a `cgo` wrapper around the cdylib, generate proto stubs, add ~500 lines of glue. You do **not** rewrite a payments library. Same for Ruby, PHP, Elixir, .NET. The story Prism tells is "the payments logic is solved; binding it to your language is mechanical."

---

## TL;DR

- One **proto** file is the contract. Generated bindings are the SDK surface.
- One **Rust core** does request building and response parsing. It does *no* I/O.
- One **cdylib** is shipped. **uniffi** binds it. SDKs are thin shells.
- **The SDK uses your language's HTTP client.** Retries, proxies, TLS, observability — configured the way you already configure them, because Prism didn't ship its own stack to fight yours.
- Adding a language is mechanical. Fixing a connector quirk is one PR, not five.

Prism isn't five payment SDKs. It's **one payment library with five idiomatic skins** — and the skin doesn't lie about what's underneath.

Code: [github.com/juspay/hyperswitch-prism](https://github.com/juspay/hyperswitch-prism) · poke around `crates/ffi/ffi/`, `crates/types-traits/grpc-api-types/proto/`, and any of `sdk/{python,javascript,java,rust}/` — the symmetry is the proof.
