# One webhook handler. Every processor. Any domain.

> If you've ever written a webhook receiver, this one is for you.
> *Hyperswitch Prism · Week 1 / Post 1*

---

## The webhook problem nobody admits is hard

On paper, a webhook is "just" an HTTP POST you ack with `200 OK`.

In production, it's:

- A signed payload — the processor attaches a cryptographic signature so you can confirm the webhook actually came from them and wasn't tampered with. Sounds standard; it isn't. Every processor invented their own signing recipe (different headers, different canonicalization, HMAC vs RSA), so "verify the signature" is N implementations, not one.
- A signing secret you can't pick yet — because the secret lives *per credential set*, and which credential set this event belongs to isn't in the header; it's hidden inside the body, attached to a `payment_intent_id` or `refund_id` you haven't parsed.
- An event type that has to be mapped to *your* internal state machine, not the processor's.
- An outbound HTTP call to the processor in some cases — for example, PayPal's recommended verification path is `POST /v1/notifications/verify-webhook-signature` with OAuth2, meaning a network round-trip and a fresh access token *just to check a signature*.
- An ambiguous event status. Card payments have two stages — **authorize** (reserve funds, no money has moved yet) and **capture** (actually pull the money). Some processors send a single "payment.success" webhook for *both* and don't tell you which stage it was. To know whether to mark the order "paid" or just "reserved", you have to remember what *you* asked for — auto-capture or manual — and disambiguate on your side.
- And on top of all that — your own webhook endpoint has to figure out *which of your customers (tenant)* this event belongs to, *which secret* to verify it with, and *whether you've already processed this exact event before* (processors retry — sometimes for days), all before you've confirmed the request is even real.

Most webhook libraries collapse all of this into one function: `verify_and_parse(request, secret) -> Event`. That collapse is the bug. It forces you to know which credentials signed the webhook *before* you know what the webhook is about.

Prism splits it into two phases, and exposes both — granular (`EventService`) and composite (`CompositeEventService`) — so you can pick the shape that matches your architecture.

---

## The two phases

```proto
service EventService {
  // Phase 1: Parse a raw webhook payload. No credentials required.
  // Returns resource reference and event type — sufficient to resolve
  // secrets or early-exit.
  rpc ParseEvent(EventServiceParseRequest) returns (EventServiceParseResponse);

  // Phase 2: Verify webhook source and return a unified typed response.
  // Response mirrors PaymentService.Get / RefundService.Get / DisputeService.Get.
  rpc HandleEvent(EventServiceHandleRequest) returns (EventServiceHandleResponse);
}
```

That's it. Two RPCs. Read them slowly:

**`ParseEvent`** takes only the raw HTTP request — headers, body, method, URI, query params. **No secret. No credentials.** It returns an `EventReference` (a oneof of `payment | refund | dispute | mandate | payout` IDs — both connector-side and merchant-side) plus a `WebhookEventType`.

**`HandleEvent`** takes the request *plus* the secret(s), an optional access token, and an optional `EventContext`. It does source verification, returns the verified, unified typed event content, and an `EventAckResponse` you should send back to the connector.

```proto
message EventReference {
  oneof resource {
    PaymentEventReference payment = 1;  // connector_transaction_id, merchant_transaction_id
    RefundEventReference  refund  = 2;  // connector_refund_id, merchant_refund_id, parent payment id
    DisputeEventReference dispute = 3;  // connector_dispute_id, parent payment id
    MandateEventReference mandate = 4;
    PayoutEventReference  payout  = 5;
  }
}
```

## Why splitting matters

Once you have `ParseEvent` separately, a whole class of architectures that used to be painful become trivial.

**1. Resolve the right secret before verifying.**
If you're a payment platform serving multiple businesses, you don't have *one* webhook secret per processor — you have one per credential set (your customer's account at the processor). The webhook arrives carrying only a processor-side ID like `pi_abc123` and a signature; nothing in the headers tells you which credential set it belongs to.

The lookup chain — exactly what Hyperswitch's open-source router does in `get_mca_from_object_reference_id` (`crates/router/src/utils.rs`):

```
incoming webhook
   └── ParseEvent →  reference: { payment: { connector_transaction_id: "pi_abc123" } }
                       │
                       ▼
       SELECT * FROM payment_intent
        WHERE connector_payment_id = 'pi_abc123';
                       │
                       ▼  (gives you merchant_id + merchant_connector_id)
       SELECT connector_webhook_details
         FROM merchant_connector_account
        WHERE id = <merchant_connector_id>;
                       │
                       ▼
       connector_webhook_details.webhook_secret   ← the right secret
                       │
                       ▼
   HandleEvent(request_details, webhook_secrets={that one})
```

Without phase-1 parse, you can't run this query — you don't have the ID yet, only an opaque body and a signature. Your only alternative is preloading every customer's secret into memory and trying them one by one, which is both slow and a security smell. With `ParseEvent`, the lookup is one indexed row read on the hot path, and `HandleEvent` runs verification with exactly the right secret on the first try.

**2. Idempotency and dedup before you do crypto.**
Verifying signatures is the most expensive thing you do per webhook (HMAC, timing-safe compare, sometimes an outbound HTTP call for processors that require it). `ParseEvent` is dirt cheap — just a payload parse. Use it to compute a dedup key from `(connector_event_id, reference_id)` and short-circuit replays *before* you touch crypto. At any non-trivial volume this is the difference between "200ms p99" and "30ms p99".

**3. Early-exit on irrelevant events.**
Connectors fire events you don't care about — `account.updated`, `capability.changed`, endpoint verification probes. `ParseEvent` returns `WebhookEventType` and an *optional* reference (absent for non-resource events). One cheap call, you ack and move on. No wasted verification.

**4. Routing.**
Got a multi-region setup? `ParseEvent` is enough to route the webhook to the region that owns the resource. The expensive `HandleEvent` runs once, in the right place.

## When you don't need any of that — the composite shape

If you're a single-tenant integrator, none of the above matters. You already know the secret. You just want a `webhook_in -> typed_event_out` function.

That's `CompositeEventService.HandleEvent`. One RPC. Internally orchestrates `ParseEvent` then `HandleEvent`. From the implementation:

```rust
// crates/internal/composite-service/src/events.rs
async fn handle_event(...) -> ... {
    // Phase 1: ParseEvent — extract reference and event type from the raw payload.
    let parse_resp = self.event_service.parse_event(parse_req).await?;

    // Phase 2: HandleEvent — source verification + unified event content.
    let handle_resp = self.event_service.handle_event(handle_req).await?;

    Ok(CompositeEventHandleResponse {
        reference: parse_resp.reference,
        event_type: handle_resp.event_type,
        event_content: handle_resp.event_content,
        source_verified: handle_resp.source_verified,
        merchant_event_id: handle_resp.merchant_event_id,
        event_ack_response: handle_resp.event_ack_response,
    })
}
```

Same building blocks. Different ergonomic. **Granular for orchestrators, composite for integrators.** You pick.

---

## The detail that makes it actually unified

The killer feature isn't the split. It's what `HandleEvent` returns:

```proto
message EventContent {
  oneof content {
    PaymentServiceGetResponse payments_response = 1;  // same shape as PaymentService.Get
    RefundResponse            refunds_response  = 2;  // same shape as RefundService.Get
    DisputeResponse           disputes_response = 3;  // same shape as DisputeService.Get
  }
}
```

A webhook from Stripe and a poll from Stripe collapse into the **same response type**. A webhook from Adyen and a poll from Adyen — same. A webhook from Stripe and a webhook from Adyen — same.

That means your downstream code — your state machine, your audit log, your reconciliation pipeline — has *one* code path. Not "polled-payment-handler" and "webhook-payment-handler" and "stripe-webhook-handler" and "adyen-webhook-handler". One handler, one type, done.

This is the part that makes Prism's webhook handling not just *a* webhook library but a **webhook unification layer**.

## Stateless, by design — the EventContext handshake

Here's a sharp edge most webhook libraries hit: some connectors send you events whose *meaning depends on something you sent earlier*. A common case: a connector sends an event saying `transaction.success` — but doesn't tell you whether the original payment was created as authorize-only or authorize-and-capture. The same webhook payload means `AUTHORIZED` for one merchant and `CAPTURED` for another, and only your own records know which.

Stateful gateways solve this by pulling the original capture intent from their DB. Prism is **stateless** — it can't. So Prism inverts the contract:

```proto
message EventServiceHandleRequest {
  optional string         merchant_event_id = 1;
  RequestDetails          request_details   = 2;
  optional WebhookSecrets webhook_secrets   = 3;
  optional AccessToken    access_token      = 4;  // for processors that need an outbound call to verify
  optional EventContext   event_context     = 5;  // your business context, passed back in
}

message PaymentEventContext {
  optional CaptureMethod capture_method = 1;  // pass back what you sent in Authorize
}
```

You pass back the bits Prism needs. If a connector requires `event_context.payment.capture_method` and you don't supply it, you get `INVALID_ARGUMENT` with an actionable message — *which* field, *why*, *for which connector*. No silent wrong status.

Why this shape matters in practice: many libraries marketed as "stateless" quietly need a cache or KV store to remember things like the original capture intent — meaning you're on the hook for one more piece of infra, one more failure mode, and one more thing to keep consistent across regions. Prism makes the dependency explicit instead of hidden: the bits it can't infer are part of the request, not a side-channel. Nothing to provision, nothing to migrate, nothing to keep in sync.

## And one more — the ack response is part of the contract

Connectors care what you reply with. Some want `200 OK` with an empty body. Some want a specific JSON shape. Some want `204`. Get it wrong and they retry, often for days, and your "webhook" turns into "denial of service from your own payment processor".

```proto
message EventServiceHandleResponse {
  WebhookEventType event_type             = 1;
  EventContent     event_content          = 2;
  bool             source_verified        = 3;
  optional string  merchant_event_id      = 4;
  optional EventAckResponse event_ack_response = 5;  // <— what to send back
}

message EventAckResponse {
  uint32 status_code           = 1;
  map<string, string> headers  = 2;
  bytes body                   = 3;
}
```

Prism tells you the *exact* status, headers and body to return for that connector. You don't memorize 50 processor quirks. You return what Prism told you to return.

---

## Why this isn't just for payments

The shape — *identify before authenticate* — isn't payment-specific. Anything that emits signed events with multiple resource types over HTTP fits the same pattern: GitHub, Slack, Twilio, Shopify, AWS SNS, observability vendors, calendar webhooks. Today we already cover payments, refunds, and disputes through one envelope; payouts, mandates, and other callback-driven domains slot into the same contract without changing the integration surface.

If you've ever found yourself writing a "webhook router" service that does verification + event normalization + dedup + downstream fan-out, you've already built half of `EventService` by hand. The other half is the part where every processor has a slightly different signing scheme, and you're maintaining 40 forks of the same `verify()` function. That's the part Prism takes off your plate.

---

## TL;DR

- **Two RPCs**: `ParseEvent` (no secret) and `HandleEvent` (with secret). Plus `CompositeEventService` for one-shot.
- **Reference before verify** lets you do tenant resolution, dedup, routing, early-exit cheaply.
- **Webhook output = poll output** — same proto types. One handler downstream.
- **EventContext** is the explicit stateless handshake — the bits Prism can't infer, you pass back in.
- **EventAckResponse** tells you exactly what to reply with.

It's a webhook library that takes the shape of webhooks seriously, instead of pretending they're "just HTTP POST + signature".

> *You shouldn't need to know which credentials signed the webhook to find out what's inside it. We fixed that — for payments, refunds, and disputes today; every callback-driven domain tomorrow.*

Code: [github.com/juspay/hyperswitch-prism](https://github.com/juspay/hyperswitch-prism) · `proto/services.proto` and `proto/payment.proto` are where this design lives.
