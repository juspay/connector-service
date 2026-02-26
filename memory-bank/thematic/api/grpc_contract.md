# gRPC API Contract

## Overview

The Connector Service exposes a gRPC API that provides a unified interface for interacting with various payment processors. The API is defined using Protocol Buffers (protobuf) and implemented using the Tonic framework in Rust.

## Service Definition

The main service is `PaymentService`, which is defined in the `payment.proto` file:

```protobuf
service PaymentService {
  rpc PaymentAuthorize(PaymentsAuthorizeRequest) returns (PaymentsAuthorizeResponse);
  rpc PaymentSync(PaymentsSyncRequest) returns (PaymentsSyncResponse);
  rpc RefundSync(RefundsSyncRequest) returns (RefundsSyncResponse);
  rpc VoidPayment(PaymentsVoidRequest) returns (PaymentsVoidResponse);
  rpc IncomingWebhook(IncomingWebhookRequest) returns (IncomingWebhookResponse);
  rpc Refund(RefundsRequest) returns (RefundsResponse);
  rpc PaymentCapture(PaymentsCaptureRequest) returns (PaymentsCaptureResponse);
  rpc SetupMandate(SetupMandateRequest) returns (SetupMandateResponse);
  rpc AcceptDispute(DisputeServiceAcceptRequest) returns (DisputeServiceAcceptResponse);
}
```

## API Methods

### 1. PaymentAuthorize

**Purpose**: Authorize a payment without capturing funds.

**Request**: `PaymentsAuthorizeRequest`
```protobuf
message PaymentsAuthorizeRequest {
  int64 amount = 10;
  Currency currency = 15;
  PaymentMethod payment_method = 2;
  PaymentMethodData payment_method_data = 14;
  optional string connector_customer = 1;
  PaymentAddress address = 3;
  AuthenticationType auth_type = 4;
  optional bytes connector_meta_data = 5;
  optional AccessToken access_token = 6;
  optional string session_token = 7;
  optional PaymentMethodToken payment_method_token = 8;
  string connector_request_reference_id = 9;
  optional int64 order_tax_amount = 11;
  optional string email = 12;
  optional string customer_name = 13;
  optional CaptureMethod capture_method = 16;
  optional string return_url = 17;
  optional string webhook_url = 18;
  optional string complete_authorize_url = 19;
  optional FutureUsage setup_future_usage = 20;
  optional bool off_session = 21;
  optional CustomerAcceptance customer_acceptance = 22;
  optional BrowserInformation browser_info = 23;
  optional string order_category = 24;
  bool enrolled_for_3ds = 25;
  optional PaymentExperience payment_experience = 26;
  optional PaymentMethodType payment_method_type = 27;
  bool request_incremental_authorization = 28;
  optional AuthenticationData authentication_data = 29;
  optional bool request_extended_authorization = 30;
  int64 minor_amount = 31;
  optional string merchant_order_reference_id = 32;
  optional int64 shipping_cost = 33;
}
```

**Response**: `PaymentsAuthorizeResponse`
```protobuf
message PaymentsAuthorizeResponse {
  ResponseId resource_id = 1;
  optional RedirectForm redirection_data = 2;
  optional MandateReference mandate_reference = 4;
  optional string network_txn_id = 5;
  optional string connector_response_reference_id = 6;
  optional bool incremental_authorization_allowed = 7;
  AttemptStatus status = 8;
  optional string error_code = 9;
  optional string error_message = 10;
}
```

**Usage Example**:
```rust
let request = PaymentsAuthorizeRequest {
    amount: 1000,
    currency: Currency::Usd as i32,
    payment_method: PaymentMethod::Card as i32,
    payment_method_data: Some(PaymentMethodData {
        data: Some(payment_method_data::Data::Card(Card {
            card_number: "4111111111111111".to_string(),
            card_exp_month: "03".to_string(),
            card_exp_year: "2030".to_string(),
            card_cvc: "737".to_string(),
            ..Default::default()
        })),
    }),
    connector_request_reference_id: "ref-123".to_string(),
    minor_amount: 1000,
    address: Some(PaymentAddress::default()),
    auth_type: AuthenticationType::NoThreeDs as i32,
    ..Default::default()
};

let response = client.payment_authorize(request).await?;
```

### 2. PaymentSync

**Purpose**: Check the status of a payment.

**Request**: `PaymentsSyncRequest`
```protobuf
message PaymentsSyncRequest {
  string resource_id = 1;
  optional string connector_request_reference_id = 2;
}
```

**Response**: `PaymentsSyncResponse`
```protobuf
message PaymentsSyncResponse {
  ResponseId resource_id = 1;
  AttemptStatus status = 2;
  optional MandateReference mandate_reference = 3;
  optional string network_txn_id = 4;
  optional string connector_response_reference_id = 5;
  optional string error_code = 9;
  optional string error_message = 10;
}
```

**Usage Example**:
```rust
let request = PaymentsSyncRequest {
    resource_id: "8837968461238652".to_string(),
    connector_request_reference_id: Some("ref-123".to_string()),
};

let response = client.payment_sync(request).await?;
```

### 3. RefundSync

**Purpose**: Check the status of a refund.

**Request**: `RefundsSyncRequest`
```protobuf
message RefundsSyncRequest {
  string connector_refund_id = 2;
  string connector_transaction_id = 1;
  optional string refund_reason = 3;
}
```

**Response**: `RefundsSyncResponse`
```protobuf
message RefundsSyncResponse {
  optional string connector_refund_id = 1;
  RefundStatus status = 2;
  optional string connector_response_reference_id = 5;
  optional string error_code = 9;
  optional string error_message = 10;
}
```

**Usage Example**:
```rust
let request = RefundsSyncRequest {
    connector_refund_id: "ref_123456789".to_string(),
    connector_transaction_id: "8837968461238652".to_string(),
    refund_reason: Some("Customer requested".to_string()),
};

let response = client.refund_sync(request).await?;
```

### 4. VoidPayment

**Purpose**: Cancel a previously authorized payment.

**Request**: `PaymentsVoidRequest`
```protobuf
message PaymentsVoidRequest {
  string connector_request_reference_id = 2;
  optional string cancellation_reason = 1;
}
```

**Response**: `PaymentsVoidResponse`
```protobuf
message PaymentsVoidResponse {
  ResponseId resource_id = 1;
  optional string connector_response_reference_id = 3;
  AttemptStatus status = 8;
  optional string error_code = 4;
  optional string error_message = 5;
}
```

**Usage Example**:
```rust
let request = PaymentsVoidRequest {
    connector_request_reference_id: "8837968461238652".to_string(),
    cancellation_reason: Some("Order cancelled".to_string()),
};

let response = client.void_payment(request).await?;
```

### 5. IncomingWebhook

**Purpose**: Process webhooks from payment processors.

**Request**: `IncomingWebhookRequest`
```protobuf
message IncomingWebhookRequest {
  RequestDetails request_details = 2;
  optional ConnectorWebhookSecrets webhook_secrets = 3;
}
```

**Response**: `IncomingWebhookResponse`
```protobuf
message IncomingWebhookResponse {
  EventType event_type = 1;
  WebhookResponseContent content = 2;
  bool source_verified = 3;
}
```

**Usage Example**:
```rust
let request = IncomingWebhookRequest {
    request_details: Some(RequestDetails {
        method: Method::Post as i32,
        headers: HashMap::from([
            ("Content-Type".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "Adyen".to_string()),
        ]),
        body: webhook_body.into(),
        ..Default::default()
    }),
    webhook_secrets: Some(ConnectorWebhookSecrets {
        secret: "your-webhook-secret".to_string(),
        ..Default::default()
    }),
};

let response = client.incoming_webhook(request).await?;
```

### 6. Refund

**Purpose**: Refund a previously captured payment.

**Request**: `RefundsRequest`
```protobuf
message RefundsRequest {
  string refund_id = 1;
  string connector_transaction_id = 2;
  optional string connector_refund_id = 3;
  Currency currency = 15;
  int64 payment_amount = 4;
  optional string reason = 5;
  optional string webhook_url = 6;
  int64 refund_amount = 7;
  optional bytes connector_metadata = 8;
  optional bytes refund_connector_metadata = 9;
  optional BrowserInformation browser_info = 23;
  int64 minor_payment_amount = 10;
  int64 minor_refund_amount = 11;
  optional string merchant_account_id = 12;
  optional CaptureMethod capture_method = 16;
}
```

**Response**: `RefundsResponse`
```protobuf
message RefundsResponse {
  optional string connector_refund_id = 1;
  RefundStatus refund_status = 36;
  optional string error_code = 2;
  optional string error_message = 3;
}
```

**Usage Example**:
```rust
let request = RefundsRequest {
    refund_id: "refund_123".to_string(),
    connector_transaction_id: "8837968461238652".to_string(),
    currency: Currency::Usd as i32,
    payment_amount: 1000,
    refund_amount: 500,
    minor_payment_amount: 1000,
    minor_refund_amount: 500,
    reason: Some("Customer requested".to_string()),
    ..Default::default()
};

let response = client.refund(request).await?;
```

### 7. PaymentCapture

**Purpose**: Capture a previously authorized payment.

**Request**: `PaymentsCaptureRequest`
```protobuf
message PaymentsCaptureRequest {
  string connector_transaction_id = 1;
  int64 amount_to_capture = 2;
  Currency currency = 15;
  optional MultipleCaptureRequestData multiple_capture_data = 21;
  optional bytes connector_meta_data = 3;
}
```

**Response**: `PaymentsCaptureResponse`
```protobuf
message PaymentsCaptureResponse {
  ResponseId resource_id = 1;
  optional string connector_response_reference_id = 2;
  AttemptStatus status = 8;
  optional string error_code = 3;
  optional string error_message = 4;
}
```

**Usage Example**:
```rust
let request = PaymentsCaptureRequest {
    connector_transaction_id: "8837968461238652".to_string(),
    amount_to_capture: 1000,
    currency: Currency::Usd as i32,
    ..Default::default()
};

let response = client.payment_capture(request).await?;
```

### 8. SetupMandate

**Purpose**: Set up a payment mandate for recurring payments.

**Request**: `SetupMandateRequest`
```protobuf
message SetupMandateRequest {
  Currency currency = 15;
  PaymentMethod payment_method = 2;
  PaymentMethodData payment_method_data = 14;
  optional string connector_customer = 1;
  PaymentAddress address = 3;
  AuthenticationType auth_type = 4;
  optional bytes connector_meta_data = 5;
  optional AccessToken access_token = 6;
  optional string session_token = 7;
  optional PaymentMethodToken payment_method_token = 8;
  string connector_request_reference_id = 9;
  optional int64 order_tax_amount = 11;
  optional string email = 12;
  optional string customer_name = 13;
  optional CaptureMethod capture_method = 16;
  optional string return_url = 17;
  optional string webhook_url = 18;
  optional string complete_authorize_url = 19;
  optional FutureUsage setup_future_usage = 20;
  optional bool off_session = 21;
  optional CustomerAcceptance customer_acceptance = 22;
  optional BrowserInformation browser_info = 23;
  optional string order_category = 24;
  bool enrolled_for_3ds = 25;
  optional PaymentExperience payment_experience = 26;
  optional PaymentMethodType payment_method_type = 27;
  bool request_incremental_authorization = 28;
  optional AuthenticationData authentication_data = 29;
  optional bool request_extended_authorization = 30;
  int64 minor_amount = 31;
  optional string merchant_order_reference_id = 32;
  optional int64 shipping_cost = 33;
}
```

**Response**: `SetupMandateResponse`
```protobuf
message SetupMandateResponse {
  ResponseId resource_id = 1;
  MandateReference mandate_reference = 4;
  AttemptStatus status = 8;
  optional RedirectForm redirection_data = 2;
  optional string network_txn_id = 5;
  optional string connector_response_reference_id = 6;
  optional bool incremental_authorization_allowed = 7;
  optional string error_code = 9;
  optional string error_message = 10;
}
```

**Usage Example**:
```rust
let request = SetupMandateRequest {
    currency: Currency::Usd as i32,
    payment_method: PaymentMethod::Card as i32,
    payment_method_data: Some(PaymentMethodData {
        data: Some(payment_method_data::Data::Card(Card {
            card_number: "4111111111111111".to_string(),
            card_exp_month: "03".to_string(),
            card_exp_year: "2030".to_string(),
            card_cvc: "737".to_string(),
            ..Default::default()
        })),
    }),
    connector_request_reference_id: "ref-123".to_string(),
    setup_future_usage: Some(FutureUsage::OffSession as i32),
    customer_acceptance: Some(CustomerAcceptance {
        acceptance_type: AcceptanceType::Online as i32,
        ..Default::default()
    }),
    address: Some(PaymentAddress::default()),
    auth_type: AuthenticationType::NoThreeDs as i32,
    minor_amount: 0,
    ..Default::default()
};

let response = client.setup_mandate(request).await?;
```

### 9. AcceptDispute

**Purpose**: Accept a dispute raised by a customer.

**Request**: `DisputeServiceAcceptRequest`
```protobuf
message DisputeServiceAcceptRequest {
  optional string dispute_id = 1;
  string connector_dispute_id = 3;
}
```

**Response**: `DisputeServiceAcceptResponse`
```protobuf
message DisputeServiceAcceptResponse {
  optional string connector_dispute_id = 1;
  DisputeStatus dispute_status = 2;
  optional string connector_dispute_status = 3;
  optional string error_code = 4;
  optional string error_message = 5;
}
```

**Usage Example**:
```rust
let request = DisputeServiceAcceptRequest {
    connector_dispute_id: "dispute_123456789".to_string(),
    ..Default::default()
};

let response = client.accept_dispute(request).await?;
```

## Common Data Structures

### ResponseId

Represents a resource identifier, which can be a connector transaction ID, encoded data, or no response ID.

```protobuf
message ResponseId {
  oneof id {
    string connector_transaction_id = 1;
    string encoded_data = 2;
    bool no_response_id = 3; // Using bool as a presence indicator for NoResponseId
  }
}
```

### RedirectForm

Represents a form for redirecting the user to a payment page.

```protobuf
message RedirectForm {
  oneof form_type {
    FormData form = 1;
    HtmlData html = 2;
  }
}

message FormData {
  string endpoint = 1;
  Method method = 2;
  map<string, string> form_fields = 3;
}

message HtmlData {
  string html_data = 1;
}
```

### PaymentMethodData

Represents payment method data, currently supporting card payments.

```protobuf
message PaymentMethodData {
  oneof data {
    Card card = 1;
  }
}

message Card {
  string card_number = 1;
  string card_exp_month = 2;
  string card_exp_year = 3;
  optional string card_holder_name = 4;
  string card_cvc = 5;
  optional string card_issuer = 6;
  optional CardNetwork card_network = 7;
  optional string card_type = 8;
  optional string card_issuing_country = 9;
  optional string bank_code = 10;
  optional string nick_name = 11;
}
```

### PaymentAddress

Represents billing and shipping addresses.

```protobuf
message PaymentAddress {
  optional Address shipping = 1;
  optional Address billing = 2;
  optional Address unified_payment_method_billing = 3;
  optional Address payment_method_billing = 4;
}

message Address {
  optional AddressDetails address = 1;
  optional PhoneDetails phone = 2;
  optional string email = 3; // Using string for Email
}

message AddressDetails {
  optional string city = 1;
  optional CountryAlpha2 country = 2;
  optional string line1 = 3;
  optional string line2 = 4;
  optional string line3 = 5;
  optional string zip = 6;
  optional string state = 7;
  optional string first_name = 8;
  optional string last_name = 9;
}
```

### BrowserInformation

Represents browser information for 3DS authentication.

```protobuf
message BrowserInformation {
  optional uint32 color_depth = 1;
  optional bool java_enabled = 2;
  optional bool java_script_enabled = 3;
  optional string language = 4;
  optional uint32 screen_height = 5;
  optional uint32 screen_width = 6;
  optional int32 time_zone = 7;
  optional string ip_address = 8; // Using string for IP address
  optional string accept_header = 9;
  optional string user_agent = 10;
  optional string os_type = 11;
  optional string os_version = 12;
  optional string device_model = 13;
  optional string accept_language = 14;
}
```

### CustomerAcceptance

Represents customer acceptance for mandate setup.

```protobuf
message CustomerAcceptance {
  AcceptanceType acceptance_type = 1;
  string accepted_at = 2; // ISO8601 formatted string
  optional OnlineMandate online = 3;
}

enum AcceptanceType {
  ONLINE = 0;
  OFFLINE = 1;
}

message OnlineMandate {
  optional string ip_address = 1;
  string user_agent = 2;
}
```

## Enumerations

### Currency

Represents supported currencies.

```protobuf
enum Currency {
  AED = 0;
  AFN = 1;
  ALL = 2;
  // ... (many more currencies)
  USD = 145;
  // ... (more currencies)
}
```

### PaymentMethod

Represents supported payment methods.

```protobuf
enum PaymentMethod {
  CARD = 0;
}
```

### PaymentMethodType

Represents specific payment method types.

```protobuf
enum PaymentMethodType {
  ACH = 0;
  AFFIRM = 1;
  AFTERPAY_CLEARPAY = 2;
  // ... (many more payment method types)
  CREDIT = 23;
  // ... (more payment method types)
}
```

### AttemptStatus

Represents the status of a payment attempt.

```protobuf
enum AttemptStatus {
  STARTED = 0;
  AUTHENTICATION_FAILED = 1;
  ROUTER_DECLINED = 2;
  // ... (many more statuses)
  CHARGED = 7;
  // ... (more statuses)
}
```

### RefundStatus

Represents the status of a refund.

```protobuf
enum RefundStatus {
  REFUND_FAILURE = 0;
  REFUND_MANUAL_REVIEW = 1;
  REFUND_PENDING = 2;
  REFUND_SUCCESS = 3;
  REFUND_TRANSACTION_FAILURE = 4;
}
```

### DisputeStatus

Represents the status of a dispute.

```protobuf
enum DisputeStatus {
  DisputeOpened = 0;
  DisputeExpired = 1;
  DisputeAccepted = 2;
  DisputeCancelled = 3;
  DisputeChallenged = 4;
  DisputeWon = 5;
  DisputeLost = 6;
}
```

### CaptureMethod

Represents the method for capturing funds.

```protobuf
enum CaptureMethod {
  AUTOMATIC = 0;
  MANUAL = 1;
  MANUAL_MULTIPLE = 2;
  SCHEDULED = 3;
  SEQUENTIAL_AUTOMATIC = 4;
}
```

### FutureUsage

Represents how a payment method will be used in the future.

```protobuf
enum FutureUsage {
  OFF_SESSION = 0;
  ON_SESSION = 1;
}
```

### AuthenticationType

Represents the type of authentication to use.

```protobuf
enum AuthenticationType {
  THREE_DS = 0;
  NO_THREE_DS = 1;
}
```

## Authentication

The API uses metadata for authentication. Clients need to provide the following metadata:

1. **x-connector**: The name of the connector to use (e.g., "adyen", "razorpay")
2. **x-auth**: The authentication type (e.g., "header-key", "body-key", "signature-key")
3. **x-api-key**: The API key for authentication
4. **x-key1** (optional): Additional key for authentication
5. **x-api-secret** (optional): API secret for authentication

Example:

```rust
let mut metadata = MetadataMap::new();
metadata.insert("x-connector", "adyen".parse().unwrap());
metadata.insert("x-auth", "header-key".parse().unwrap());
metadata.insert("x-api-key", "your-api-key".parse().unwrap());

let request = Request::from_parts(metadata, Extensions::default(), payment_request);
```

## Error Handling

Errors are returned in the response with the following fields:

1. **error_code**: A code identifying the error
2. **error_message**: A human-readable error message
3. **status**: The status of the operation (e.g., FAILURE)

Example error response:

```json
{
  "resource_id": {
    "id": {
      "no_response_id": true
    }
  },
  "status": 20,
  "error_code": "invalid_request",
  "error_message": "Invalid payment details"
}
```

## Versioning

The API is versioned through the proto file. Changes to the API should be backward compatible, with new fields being added as optional.

## Best Practices

1. **Error Handling**: Always check for error responses and handle them appropriately.

2. **Idempotency**: Use unique reference IDs for each request to ensure idempotency.

3. **Metadata**: Provide all required metadata for authentication.

4. **Validation**: Validate request data before sending it to the API.

5. **Timeouts**: Set appropriate timeouts for API calls.

6. **Retries**: Implement retry logic for transient errors.

7. **Logging**: Log API requests and responses for debugging.

## Client SDKs

The Connector Service provides client SDKs for various programming languages:

1. **Node.js**: `sdk/node-grpc-client`
2. **Python**: `sdk/python-grpc-client`
3. **Rust**: `sdk/rust-grpc-client`

These SDKs provide a convenient way to interact with the API without having to deal with the low-level gRPC details.

## Examples

The `examples` directory contains example implementations for various programming languages:

1. **CLI**: `examples/example-cli`
2. **Rust**: `examples/example-rs`
3. **Node.js**: `examples/example-js`
4. **Python**: `examples/example-py`
5. **Haskell**: `examples/example-hs`
6. **Haskell gRPC**: `examples/example-hs-grpc`
7. **TUI**: `examples/example-tui`
8. **MCP**: `examples/example-mcp`

These examples demonstrate how to use the API for common payment operations.
