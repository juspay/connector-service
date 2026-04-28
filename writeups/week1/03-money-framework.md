# Prism's Money framework — one type for every amount in the API

> An entire class of payment-integration bugs becomes impossible to write when amounts and currencies are bound at the type level.
> *Hyperswitch Prism · Week 1 / Post 3*

---

## Three bugs every payment integration eventually hits

If you have written code that moves money, you have either shipped one of these or watched a colleague do it. They are widely documented and not exotic. They are the reason payment-systems engineers care about types more than most other domains.

### 1. The off-by-100x bug

Different processors expect amounts in different shapes:

```jsonc
// minor units, integer
{ "amount": 1000, "currency": "usd" }                // $10.00

// minor units, nested
{ "amount": { "value": 1000, "currency": "USD" } }   // $10.00

// decimal string
{ "amount": "10.00", "currency": "USD" }             // $10.00

// (some legacy integrations) float in a major unit
{ "amount": 10.0, "currency": "USD" }                // $10.00
```

A developer maintaining integrations against four of these — after a week of switching between processor docs — writes `amount: 10` for an integration that expects `1000`. The transaction goes through. The customer is charged `$0.10`.

A discrepancy of this exact shape can survive every layer of testing that does not independently verify the amount in major units against an external reference. Unit tests pass because the developer asserts on the value they typed. Staging passes because staging hits the same connector with the same buggy multiplier. Merchant-side dashboards can display minor-units values and look merely low rather than wrong. Realistic detection often comes from finance reconciliation, days or weeks after the first affected transaction.

The root cause is not developer carelessness. The root cause is that the type system permitted the wrong shape.

### 2. Floating-point arithmetic on currency

```python
>>> 10.99 + 20.99
31.980000000000004
```

Currency is a discrete quantity. The smallest representable unit of USD is one cent, of JPY one yen, of BHD one-thousandth of a dinar. None of these are exactly representable in IEEE 754 binary floating point at common scales. Any system that accumulates currency in floats accumulates rounding error, and those errors compound asymmetrically: refund engines drift, ledger balances disagree, and reconciliation consumes engineering time that should have been spent elsewhere.

### 3. Currency confusion

```json
{ "amount": 1000 }
```

This is $10.00 if the currency is USD. It is ¥1,000 if the currency is JPY. It is exactly one dinar if the currency is BHD (three decimal places, so 1000 fils = 1.000 BHD). Without the currency in the same value, the amount is ambiguous to your code, ambiguous to any downstream service, and ambiguous to anyone reading the audit log two years later under SOC review.

Any system that lets `amount` travel separately from `currency` — even briefly, even just on the wire — has this bug in waiting.

---

## How Prism represents money

```proto
message Money {
  int64 minor_amount = 1;  // smallest currency unit
  Currency currency  = 2;  // ISO 4217 enum
}
```

Two fields, both required, bound together at the type level. This type is used in every monetary field of the API — `PaymentServiceAuthorizeRequest.amount`, `PaymentServiceCaptureRequest.amount_to_capture`, `PaymentServiceRefundRequest.refund_amount`, the `dispute_amount` on dispute responses, the amount on payout requests, and so on. There is no place in the API where an amount appears without its currency.

Because every SDK is generated from the same proto (see [post 2](./02-proto-source-of-truth-ffi.md)), the same shape appears in every language:

```typescript
// TypeScript
const request: types.PaymentServiceAuthorizeRequest = {
    merchantTransactionId: "authorize_123",
    amount: { minorAmount: 1000, currency: types.Currency.USD },
};
```

```python
# Python
request = PaymentServiceAuthorizeRequest(
    merchant_transaction_id="authorize_123",
    amount=Money(minor_amount=1000, currency=Currency.USD),
)
```

```kotlin
// Kotlin
val request = PaymentServiceAuthorizeRequest(
    merchantTransactionId = "authorize_123",
    amount = Money(minorAmount = 1000, currency = Currency.USD),
)
```

The proto generator and the host language's type checker both reject calls that omit either field. There is no path through the API that accepts a bare integer, a float, or an amount without its currency.

---

## Each of the three bugs, addressed

**Off-by-100x.** `minor_amount` is unambiguously the smallest currency unit. The connector layer translates from this canonical representation to whatever the upstream processor expects — cents in an integer, decimal string, nested JSON object, query-param-encoded, anything else. One representation in application code; N translations live inside Prism.

The translation is verified against the *processor's merchant dashboard*, not only the API response. A processor can accept a request and return a successful response while the dashboard shows a different figure — rounding, settlement-time FX, percentage-based fees, or simply a misinterpretation of the request shape. Prism's amount tests pin both ends so that what the developer sent is what the merchant sees.

**Floating-point arithmetic.** `minor_amount` is `int64` in the proto, in the Rust core, in the Python typed stubs, in TypeScript, and in Kotlin. Passing a float requires explicit truncation in user code, which most language toolchains warn about before it compiles or runs. The most useful piece of advice that falls out of this design — applicable regardless of whether you adopt Prism — is to store currency as integers in minor units in your database, your cache, your logs, and on the wire, and to convert to a display format only at the UI boundary.

**Currency confusion.** The `Currency` enum is ISO 4217. A `Money` cannot exist without it. Because the connector layer knows which currencies use which decimal scale, the third trap — non-two-decimal currencies — also disappears:

```text
USD → minor_amount: 2500   → $25.00      (two decimals)
JPY → minor_amount: 1000   → ¥1,000      (zero decimals)
KRW → minor_amount: 10000  → ₩10,000     (zero decimals)
BHD → minor_amount: 1500   → BD 1.500    (three decimals)
```

The application writes `minor_amount: 1500, currency: BHD`. Prism knows BHD has three decimal places, knows what the upstream serialization requires, and converts. There is no `if currency == "JPY"` branch to maintain, and no out-of-band knowledge of decimal scales to keep current as new connectors are added.

---

## What changes when one type is used everywhere

Representing money in minor units is a decades-old technique; every careful payments engineer arrives at it eventually. What is worth more attention is the consequence of using the *same type* across the entire API:

1. **The whole API surface uses it consistently.** Authorize, capture, refund, dispute, payout, multi-capture — all `Money`. There is no flow that quietly accepts a `Decimal`, a string, or a bare integer.

2. **It survives the FFI boundary.** Because `Money` is a proto message and the FFI carries proto bytes, every language SDK sees the same `Money` shape with the same constraints. The Python SDK and the JavaScript SDK cannot drift on what an amount looks like; they decode the same bytes against the same schema.

3. **Per-connector serialization quirks live in exactly one place.** Whatever a new processor requires — float, string, divided-by-100, divided-by-1000, JSON-nested, header-encoded — the translation lives in the corresponding Rust connector implementation and propagates to every SDK on the next release. None of it leaks into application code.

4. **No implicit FX.** Prism does not convert between currencies. If a payment is authorized in USD, it is captured in USD. Currency conversion is a business decision: which rate, sourced when, recorded where for compliance, applied with what spread. A payments library that silently performs FX hides decisions an auditor will eventually need to find.

---

## The principle this is an instance of

The Money type is two fields and a few well-chosen constraints. The broader principle has a name — popularized in the typed-FP community, often attributed to Yaron Minsky:

> Make illegal states unrepresentable.

A `Money` value without a currency is illegal, and is unrepresentable. A floating-point currency is illegal, and is unrepresentable. Half a cent is illegal, and is unrepresentable. The cost of these guarantees is one extra field on every request payload. The benefit is that an entire category of bug cannot be written.

If a payment-integration codebase you maintain accepts a bare `amount` without a currency, or accepts a `float`, that is the first file to look at.

---

## TL;DR

- `Money { minor_amount: int64, currency: Currency }` is used in every monetary field of the API.
- Integers only — the off-by-100x and floating-point rounding bugs are syntactically impossible to write.
- Currency is required and travels with the amount — ambiguous values are syntactically impossible to write.
- Zero-decimal (JPY, KRW) and three-decimal (BHD) currencies are converted by the connector layer; application code never branches on decimal scale.
- The same `Money` shape appears in every SDK because every SDK is generated from the same proto.
- Prism does not perform currency conversion. Authorize in USD → capture in USD. FX remains an explicit decision in application code.

Code: [github.com/juspay/hyperswitch-prism](https://github.com/juspay/hyperswitch-prism) · `proto/payment.proto` defines `Money` · `docs/architecture/frameworks/money-struct.md` is the longer internal write-up.
