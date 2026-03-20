# Proto File Consistency Review: `grpc-api-types/proto/`

## 1. Enum Naming Violations

**`BankType` and `BankHolderType`** in `payment_methods.proto:1762-1772` violate the project's own convention stated in `payment.proto:33` (*"Enum zero values follow the convention `ENUM_NAME_UNSPECIFIED = 0`"*):

```protobuf
// BAD — uses PascalCase values and wrong UNSPECIFIED format
enum BankType {
  BankType_UNSPECIFIED = 0;  // should be BANK_TYPE_UNSPECIFIED
  Checking = 1;              // should be BANK_TYPE_CHECKING
  Savings = 2;               // should be BANK_TYPE_SAVINGS
}
enum BankHolderType {
  BankHolderType_UNSPECIFIED = 0;  // should be BANK_HOLDER_TYPE_UNSPECIFIED
  Personal = 1;                     // should be BANK_HOLDER_TYPE_PERSONAL
  Business = 2;                     // should be BANK_HOLDER_TYPE_BUSINESS
}
```

Every other enum in the codebase (`PaymentStatus`, `Currency`, `CardNetwork`, `HttpMethod`, etc.) uses `SCREAMING_SNAKE_CASE`. These two are the only violations.

**`Environment`** in `sdk_config.proto:24` is missing an `_UNSPECIFIED` zero value — `SANDBOX = 0` doubles as both the default and a meaningful value, which makes it impossible to distinguish "not set" from "explicitly sandbox."

**`PaymentStatus`** in `payment.proto:137` names its zero value `ATTEMPT_STATUS_UNSPECIFIED` rather than the expected `PAYMENT_STATUS_UNSPECIFIED`. The enum is called `PaymentStatus` but the prefix is `ATTEMPT_STATUS`.

---

## 2. `int64` vs `Money` for Amounts

The codebase mixes raw `int64` and the `Money` message type for monetary amounts without a clear rule:

| Location | Field | Type |
| --- | --- | --- |
| `PaymentServiceAuthorizeRequest:2` | `amount` | `Money` (required) |
| `PaymentServiceAuthorizeRequest:3` | `order_tax_amount` | `int64` |
| `PaymentServiceAuthorizeRequest:4` | `shipping_cost` | `int64` |
| `PaymentServiceRefundRequest:3` | `payment_amount` | `int64` |
| `PaymentServiceRefundRequest:4` | `refund_amount` | `Money` |
| `PaymentServiceAuthorizeResponse:13-15` | `captured_amount`, `capturable_amount`, `authorized_amount` | `int64` |

The `payment_amount` field in `PaymentServiceRefundRequest` is a bare `int64` while `refund_amount` next to it is `Money`. This is confusing — if the currency is always inherited from context, that should be documented; otherwise both should be `Money`.

---

## 3. Optionality Inconsistencies for the Same Semantic Field

**`connector_transaction_id`:**

| Location | Optionality |
| --- | --- |
| `PaymentServiceAuthorizeResponse:2` | `optional string` |
| `PaymentServiceGetRequest:2` | `string` (required) |
| `RecurringPaymentServiceChargeResponse:1` | `optional string` |
| `CompositeGetRequest:1` | `string` (required) |

**`address` (PaymentAddress):**

| Location | Optionality |
| --- | --- |
| `PaymentServiceAuthorizeRequest:8` | required |
| `CompositeAuthorizeRequest:6` | `optional` |
| `PaymentMethodAuthenticationServicePreAuthenticateRequest:5` | required |

**`enrolled_for_3ds`:**

| Location | Optionality |
| --- | --- |
| `PaymentServiceAuthorizeRequest:10` | `optional bool` |
| `PaymentMethodAuthenticationServicePreAuthenticateRequest:6` | `bool` (required) |

These should be consistently optional or required across equivalent request types.

---

## 4. Duplicate RPC Method: `HandleEvent`

`services.proto` defines `HandleEvent` on **four** separate services:

- `EventService.HandleEvent` (line 82)
- `PaymentService.HandleEvent` (line 134)
- `RefundService.HandleEvent` (line 163)
- `DisputeService.HandleEvent` (line 191)

All four take the **same** request/response types (`EventServiceHandleRequest`/`EventServiceHandleResponse`). The comment on `PaymentService.HandleEvent` says *"This will delegate to the appropriate service transform based on the event type"* — if that's the case, the copies on `RefundService` and `DisputeService` appear redundant. At minimum, the purpose of having the same RPC on multiple services should be clarified or consolidated.

---

## 5. Package Inconsistency

- `health_check.proto` uses `package grpc.health.v1;`
- Every other file uses `package types;`

This is likely intentional (standard gRPC health check convention), but it means the health check messages live in a different namespace and can't be directly referenced from the other files without an import + fully-qualified name.

---

## 6. Response Structure Inconsistencies

Response messages don't follow a consistent pattern:

| Response | `raw_connector_request` | `connector_response` | `connector_feature_data` |
| --- | --- | --- | --- |
| `PaymentServiceAuthorizeResponse` | Yes | Yes | Yes |
| `PaymentServiceVoidResponse` | No | No | No |
| `RefundResponse` | No | No | No |
| `RecurringPaymentServiceChargeResponse` | Yes | Yes | Yes |
| `PreAuthenticateResponse` | Response only | No | Yes |

If debug fields like `raw_connector_request`/`raw_connector_response` are useful, they should be available on all responses, not just some.

---

## 7. `RequestError` / `ResponseError` Duplication

`sdk_config.proto:163-176` defines two identical messages:

```protobuf
message RequestError {
  PaymentStatus status = 1;
  optional string error_message = 2;
  optional string error_code = 3;
  optional uint32 status_code = 4;
}
message ResponseError {
  PaymentStatus status = 1;
  optional string error_message = 2;
  optional string error_code = 3;
  optional uint32 status_code = 4;
}
```

These are structurally identical. Consider a single `FfiError` message with a field or context to distinguish request vs response errors.

---

## 8. Connector Config Credential Naming

The `*Config` messages in `payment.proto:2797+` have no consistent naming for credentials:

| Config | Field 1 | Field 2 |
| --- | --- | --- |
| `StripeConfig` | `api_key` | — |
| `RevolutConfig` | `secret_api_key` | `signing_secret` |
| `MifinityConfig` | `key` | — |
| `AuthorizedotnetConfig` | `name` | `transaction_key` |
| `BamboraConfig` | `merchant_id` | `api_key` |

`MifinityConfig.key` is particularly vague. Consider standardizing to `api_key` / `api_secret` / `signing_key` patterns where possible.

---

## 9. Commented-Out Dead Code

`payment_methods.proto` has ~150 lines of commented-out message definitions in block comments (`/* ... */`):

- Lines 169-279 (old `RTPPaymentMethodType`, etc.)
- Lines 1227-1263 (old VA bank messages like `BNIVA`, `BRIVA`, etc.)
- Lines 1269+ (more unsupported methods)

These are replaced by active definitions elsewhere in the file. They add noise — either remove them or move to a separate `_unsupported.proto` file.

---

## 10. Misplaced Comment

`payment_methods.proto:152-153`:

```protobuf
Indomaret indomaret = 146;
Oxxo oxxo = 147;                // Indomaret - Indonesian convenience store payment
```

The comment on `Oxxo` says "Indomaret" — it was clearly copy-pasted incorrectly. Oxxo is a Mexican convenience store chain.

---

## 11. Field Number Gaps and Organization in `PaymentMethod` oneof

The `PaymentMethod` oneof in `payment_methods.proto:43-160` allocates ranges (1-9 cards, 10-29 wallets, etc.) but has range violations:

- `bizum = 156` and `eft = 157` are placed inside the "ONLINE BANKING (40-59)" section but use numbers from the 150s
- Indonesian bank transfers (130-136) are in the "BANK TRANSFER (90-99)" section
- Gift cards section says "130-139" but bank transfers already used 130-136

The numbering ranges in the comments are misleading. They should either be updated to reflect reality or the field numbers should be reorganized.

---

## 12. Missing Reserved Field in `PaymentServiceAuthorizeRequest`

Field number `20` is skipped (goes from `merchant_order_id = 19` to `setup_future_usage = 21`). This might be an intentional reservation, but there's no `reserved 20;` statement. Per the file's own header: *"Any removed field must be listed in a reserved statement."*

---

## Summary by Priority

### High — Correctness/Safety

1. Enum naming violations (`BankType`, `BankHolderType`) — breaks codegen conventions
2. `ATTEMPT_STATUS_UNSPECIFIED` prefix mismatch on `PaymentStatus`
3. Missing `_UNSPECIFIED` on `Environment` enum
4. Wrong comment on `Oxxo` field
5. Missing `reserved` statement for field 20

### Medium — Consistency

6. `int64` vs `Money` for monetary amounts
7. Optionality mismatches across equivalent fields
8. Response structure inconsistencies (debug fields present/absent)
9. Duplicate `HandleEvent` RPC across 4 services
10. Credential field naming in `*Config` messages

### Low — Cleanup

11. ~150 lines of commented-out dead code
12. `RequestError`/`ResponseError` duplication
13. Misleading field number range comments in `PaymentMethod`
14. `health_check.proto` package divergence (likely intentional)
