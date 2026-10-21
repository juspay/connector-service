# Adyen Platform payouts in UCS

This ports the existing Hyperswitch `adyenplatform` connector into hyperswitch-prism.
Reference: Hyperswitch commit `7306f61562187d75b151d46b8563262bd2f27c5c`,
`crates/hyperswitch_connectors/src/connectors/adyenplatform.rs` and
`adyenplatform/transformers/payouts.rs`.

The earlier custom `adyen` payout integration was removed. Existing Adyen payment
code and `AdyenConfig` are unchanged. The new connector identifier is
`adyenplatform` (the existing protobuf `ADYENPLATFORM = 1` value).

The payout module exports `AdyenplatformPayouts` and uses
`create_all_prerequisites!` and `macro_connector_implementation!` for the transfer
request/response plumbing. Webhook dispatch reuses this type under the
`connectors::Adyenplatform` export.

## Flow parity

| Hyperswitch | UCS | Behavior |
| --- | --- | --- |
| `PoFulfill`, raw card | `PayoutTransfer`, `Card` | Minor amount; destination currency; cardholder split into first and remaining names; four-digit expiry year |
| `PoFulfill`, stored card | `PayoutTransfer`, `connector_payout_method_id` | Stored ID takes precedence over raw card; billing names with cardholder fallback |
| `PoFulfill`, SEPA | `PayoutTransfer`, `Bank::Sepa` | IBAN; billing full name; priority required |
| Other payout flows | Unsupported flow stubs | No create, eligibility, stage, approve, void/cancel, recipient, enrolment, link or GET API added |
| Transfer webhooks | Incoming payout webhooks | Same event/status/tracking precedence and payout-attempt reference |

Both implementations send `POST /btl/v4/transfers`. Configuration uses the root
`https://balanceplatform-api-test.adyen.com/` (sandbox/development) or
`https://balanceplatform-api-live.adyen.com/` (production).

Authentication uses **one API key in `X-API-Key`**, with no Bearer prefix, as
specified in the [Adyen Transfers API authentication documentation](https://docs.adyen.com/api-explorer/transfers/4/overview#authentication).
This intentionally corrects Hyperswitch's `Authorization` header while retaining
the same API-key value. No separate transfer key, merchant account or review key
is introduced. Live Adyen account behavior has not been exercised.

## UCS field adapters

Typed configuration uses `AdyenplatformConfig` in `ConnectorSpecificConfig`:

```json
{
  "adyenplatform": {
    "api_key": {"value": "<api-key>"},
    "source_balance_account": {"value": "<balance-account-id>"}
  }
}
```

The snippet shows protobuf message structure; use the client SDK's SecretString
representation when constructing a request. Optional `base_url` uses the normal
UCS URL override machinery. Legacy authentication accepts `HeaderKey`.

Hyperswitch's connector metadata `source_balance_account` maps to the typed
configuration above. For legacy callers, `payout_connector_metadata` may contain
`source_balance_account`; typed configuration takes precedence.

The UCS payout DTO does not have Hyperswitch's separate entity type, payout type
or additional cardholder data fields. Supply these through the JSON encoded in
`payout_connector_metadata` when needed:

```json
{
  "entity_type": "Individual",
  "payout_type": "card",
  "card_holder_name": "Jane Doe"
}
```

- `entity_type` defaults to Hyperswitch's `Individual`. `Individual`, `Personal`
  and `NaturalPerson` become `individual`; `Company` and `Business` become
  `organization`; `NonProfit` and `PublicSector` become `unknown`.
- `payout_type: "card"` is required only for a stored-card request without raw
  payout method data. Otherwise the payout type is inferred from the method.
- `card_holder_name` supplies the additional-data fallback for stored cards when
  billing first/last name is missing or blank. Raw cards use their own holder name.
- Customer reference comes from `customer.connector_customer_id`. Email comes
  from the billing address. Address line1, line2, city and country are required.
- Both provider reference fields use `connector_request_reference_id`, which
  must remain the payout attempt reference for webhook correlation.
- This port accepts raw PANs; vault aliases are rejected until injector support
  is wired for this connector.

## Response and webhook behavior

Transfer `authorised`/`booked` map to `Initiated`, `pending`/`received` to `Pending`,
and `returned` to `Reversed`. `refused`/`error`/`failed` return a connector error
with the transfer ID and the reference implementation's status display code
(`Refused`, `Error`, `Failed`). A nonempty reason becomes the error message.
Unknown statuses fail deserialization, as in Hyperswitch.

Created webhooks always map to `PayoutCreated`. Updated webhooks with tracking
map `accepted`/`credited` to success and `pending` to processing, regardless of
the transfer status. Without tracking, `authorised`/`received` map to created,
`booked`/`pending` to processing, `failed` to failure and `returned` to reversed.
UCS detail statuses use `Initiated` for created and `Pending` for processing.
The merchant payout reference is `data.reference`; no PSP transfer ID is inferred.
Error details prefer `data.reason` over `tracking.reason`.

Webhook authentication verifies Base64 HMAC-SHA256 from `hmacsignature` over the
raw body with the hex-decoded webhook secret. Comparison is constant time. Error
acknowledgements retain Hyperswitch's `x-http-code: 404` header and JSON null body;
success acknowledgements are empty HTTP 200.

Tests cover payloads, required fields, stored-card precedence, entity adapters,
status mappings, tracking precedence and signed/tampered webhooks. Live sandbox
execution requires account credentials and an enabled balance account.
