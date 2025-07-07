# gRPC API Contract

## Overview

The Connector Service exposes a gRPC API that provides a unified interface for interacting with various payment processors. The API is defined using Protocol Buffers (protobuf) and implemented using the Tonic framework in Rust.

## Service Architecture

The API is organized into three main services defined in the `services.proto` file, each handling specific aspects of payment processing:

### 1. PaymentService

Handles core payment operations:

```protobuf
service PaymentService {
  // Authorizes a payment.
  rpc Authorize(PaymentServiceAuthorizeRequest) returns (PaymentServiceAuthorizeResponse);
  
  // Synchronizes the status of a payment.
  rpc Get(PaymentServiceGetRequest) returns (PaymentServiceGetResponse);
  
  // Voids an authorized payment.
  rpc Void(PaymentServiceVoidRequest) returns (PaymentServiceVoidResponse);
  
  // Captures a previously authorized payment.
  rpc Capture(PaymentServiceCaptureRequest) returns (PaymentServiceCaptureResponse);

  // Processes a refund request.
  rpc Refund(PaymentServiceRefundRequest) returns (RefundResponse);

  // Sets up a mandate for future payments.
  rpc Register(PaymentServiceRegisterRequest) returns (PaymentServiceRegisterResponse);

  // Creates a new dispute.
  rpc Dispute(PaymentServiceDisputeRequest) returns (DisputeResponse);

  // Handles incoming webhooks from connectors.
  // This will delegate to the appropriate service transform based on the event type.
  rpc Transform(PaymentServiceTransformRequest) returns (PaymentServiceTransformResponse);
}
```

### 2. RefundService

Handles refund-specific operations:

```protobuf
service RefundService {
  // Synchronizes the status of a refund.
  rpc Get(RefundServiceGetRequest) returns (RefundResponse);

  // Handles incoming webhooks from connectors.
  rpc Transform(RefundServiceTransformRequest) returns (RefundServiceTransformResponse);
}
```

### 3. DisputeService

Handles dispute-specific operations:

```protobuf
service DisputeService {
  // Submits evidence for a dispute.
  rpc SubmitEvidence(DisputeServiceSubmitEvidenceRequest) returns (DisputeServiceSubmitEvidenceResponse);

  // Retrieves dispute information or evidence submission status.
  rpc Get(DisputeServiceGetRequest) returns (DisputeResponse);

  // Defends a dispute with a reason code.
  rpc Defend(DisputeDefendRequest) returns (DisputeDefendResponse);

  // Accepts a dispute.
  rpc Accept(AcceptDisputeRequest) returns (AcceptDisputeResponse);

  // Handles incoming webhooks from connectors.
  rpc Transform(DisputeServiceTransformRequest) returns (DisputeServiceTransformResponse);
}
```

### 4. Health Service

Provides health check capabilities for service monitoring:

```protobuf
service Health {
  // Check the health status of the service.
  rpc Check(HealthCheckRequest) returns (HealthCheckResponse);
}

message HealthCheckRequest {
  // Service name to check (optional)
  string service = 1;
}

message HealthCheckResponse {
  // Health status of the service
  ServingStatus status = 1;
}

enum ServingStatus {
  UNKNOWN = 0;
  SERVING = 1;
  NOT_SERVING = 2;
  SERVICE_UNKNOWN = 3;
}
```

## Package Information

- **Package**: `ucs.v2`
- **Go Package**: `github.com/juspay/connector-service/backend/grpc-api-types/proto;proto`
```

## API Methods

### PaymentService Methods

#### 1. Authorize

**Purpose**: Authorize a payment without capturing funds.

**Request**: `PaymentServiceAuthorizeRequest`
```protobuf
message PaymentServiceAuthorizeRequest {
  // Payment Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  
  // Amount Information
  int64 amount = 2; // The amount for the payment in major currency units
  Currency currency = 3; // The currency for the payment, in ISO 4217 three-letter code
  int64 minor_amount = 4; // The minor amount for the payment (e.g., cents)
  optional int64 order_tax_amount = 5; // Tax amount for the order
  optional int64 shipping_cost = 6; // Cost of shipping for the order
  
  // Payment Method and Capture Settings
  PaymentMethod payment_method = 7; // Payment method to be used
  optional CaptureMethod capture_method = 8; // Method for capturing the payment
  
  // Customer Information
  optional string email = 9; // Email address of the customer
  optional string customer_name = 10; // Name of the customer
  optional string connector_customer_id = 11; // Customer ID as recognized by the connector
  
  // Address Information
  PaymentAddress address = 12; // Billing and shipping address details
  
  // Authentication Details
  AuthenticationType auth_type = 13; // Type of authentication to be used
  bool enrolled_for_3ds = 14; // Indicates if the customer is enrolled for 3D Secure
  optional AuthenticationData authentication_data = 15; // Additional authentication data
  
  // Metadata
  map<string, string> metadata = 16; // Additional metadata for the connector
  
  // URLs for Redirection and Webhooks
  optional string return_url = 17; // URL to redirect after payment
  optional string webhook_url = 18; // URL for webhook notifications
  optional string complete_authorize_url = 19; // URL to complete authorization
  
  // Session and Token Information
  optional AccessToken access_token = 20; // Access token for secure communication
  optional string session_token = 21; // Session token, if applicable
  
  // Order Details
  optional string order_category = 22; // Category of the order
  optional string merchant_order_reference_id = 23; // Merchant's internal reference ID
  
  // Behavioral Flags and Preferences
  optional FutureUsage setup_future_usage = 24; // Indicates future usage intention
  optional bool off_session = 25; // Indicates if off-session transaction
  bool request_incremental_authorization = 26; // Indicates if incremental authorization is requested
  optional bool request_extended_authorization = 27; // Indicates if extended authorization is requested
  
  // Contextual Information
  optional CustomerAcceptance customer_acceptance = 28; // Details of customer acceptance
  optional BrowserInformation browser_info = 29; // Information about the customer's browser
  optional PaymentExperience payment_experience = 30; // Preferred payment experience
}
```

**Response**: `PaymentServiceAuthorizeResponse`
```protobuf
message PaymentServiceAuthorizeResponse {
  // Identification
  Identifier transaction_id = 1; // Identifier for the resource created
  
  // Status Information
  PaymentStatus status = 2; // Status of the payment attempt
  optional string error_code = 3; // Error code if the authorization failed
  optional string error_message = 4; // Error message if the authorization failed
  
  // Redirection and Transaction Details
  optional RedirectForm redirection_data = 5; // Data for redirecting the customer's browser
  optional string network_txn_id = 6; // Transaction ID from the payment network
  optional Identifier response_ref_id = 7; // Response reference ID for tracking
  
  // Authorization Details
  optional bool incremental_authorization_allowed = 8; // Indicates if incremental authorization is allowed
}
```

**Usage Example**:
```rust
let request = PaymentServiceAuthorizeRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("ref-123".to_string())),
    }),
    amount: 1000,
    currency: Currency::Usd as i32,
    minor_amount: 1000,
    payment_method: PaymentMethod::Card as i32,
    capture_method: Some(CaptureMethod::Manual as i32),
    email: Some("customer@example.com".to_string()),
    customer_name: Some("John Doe".to_string()),
    address: Some(PaymentAddress {
        billing_address: Some(Address {
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            line1: Some("123 Main St".to_string()),
            city: Some("New York".to_string()),
            state: Some("NY".to_string()),
            zip_code: Some("10001".to_string()),
            country_alpha2_code: Some(CountryAlpha2::Us as i32),
            email: Some("customer@example.com".to_string()),
            ..Default::default()
        }),
        shipping_address: Some(Address::default()),
    }),
    auth_type: AuthenticationType::NoThreeDs as i32,
    enrolled_for_3ds: false,
    ..Default::default()
};

let response = client.authorize(request).await?;
```

#### 2. Get (Payment Status)

**Purpose**: Synchronize and check the status of a payment.

**Request**: `PaymentServiceGetRequest`
```protobuf
message PaymentServiceGetRequest {
  // Identification
  Identifier transaction_id = 1; // The resource ID to synchronize
  
  // Reference
  optional Identifier request_ref_id = 2; // Reference ID for tracking
}
```

**Response**: `PaymentServiceGetResponse`
```protobuf
message PaymentServiceGetResponse {
  // Identification
  Identifier transaction_id = 1; // Identifier for the synchronized resource
  
  // Status Information
  PaymentStatus status = 2; // Current status of the payment attempt
  optional string error_code = 3; // Error code if synchronization encountered an issue
  optional string error_message = 4; // Error message if synchronization encountered an issue
  
  // Transaction Details
  optional MandateReference mandate_reference = 5; // Mandate reference, if applicable
  optional string network_txn_id = 6; // Transaction ID from the payment network
  optional Identifier response_ref_id = 7; // Response reference ID for tracking
  
  // Payment Details
  optional int64 amount = 8; // Payment amount in major currency units
  optional int64 minor_amount = 9; // Payment amount in minor currency units
  optional Currency currency = 10; // Currency of the payment
  optional int64 captured_amount = 11; // Amount that has been captured
  optional int64 minor_captured_amount = 12; // Captured amount in minor currency units
  optional PaymentMethodType payment_method_type = 13; // Type of payment method used
  optional CaptureMethod capture_method = 14; // Capture method for the payment
  optional AuthenticationType auth_type = 15; // Type of authentication used
  
  // Timestamps
  optional int64 created_at = 16; // Unix timestamp when the payment was created
  optional int64 updated_at = 17; // Unix timestamp when the payment was last updated
  optional int64 authorized_at = 18; // Unix timestamp when the payment was authorized
  optional int64 captured_at = 19; // Unix timestamp when the payment was captured
  
  // Additional Context
  optional string customer_name = 20; // Name of the customer
  optional string email = 21; // Email address of the customer
  optional string connector_customer_id = 22; // Customer ID as recognized by the connector
  optional string merchant_order_reference_id = 23; // Merchant's internal reference ID
  map<string, string> metadata = 24; // Additional metadata from the connector
}
```

**Usage Example**:
```rust
let request = PaymentServiceGetRequest {
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("ref-123".to_string())),
    }),
};

let response = client.get(request).await?;
```

#### 3. Void

**Purpose**: Cancel a previously authorized payment.

**Request**: `PaymentServiceVoidRequest`
```protobuf
message PaymentServiceVoidRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  Identifier transaction_id = 2; // Transaction ID to void
  
  // Void Details
  optional string cancellation_reason = 3; // Reason for cancelling/voiding the payment
  optional bool all_keys_required = 4;
}
```

**Response**: `PaymentServiceVoidResponse`
```protobuf
message PaymentServiceVoidResponse {
  // Identification
  Identifier transaction_id = 1; // Identifier for the voided resource
  
  // Status Information
  PaymentStatus status = 2; // Status of the payment attempt after voiding
  optional string error_code = 3; // Error code if the void operation failed
  optional string error_message = 4; // Error message if the void operation failed
  
  // Reference
  optional Identifier response_ref_id = 5; // Response reference ID for tracking
}
```

**Usage Example**:
```rust
let request = PaymentServiceVoidRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("ref-void-123".to_string())),
    }),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    cancellation_reason: Some("Order cancelled by customer".to_string()),
    ..Default::default()
};

let response = client.void(request).await?;
```

#### 4. Capture

**Purpose**: Capture a previously authorized payment.

**Request**: `PaymentServiceCaptureRequest`
```protobuf
message PaymentServiceCaptureRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  Identifier transaction_id = 2; // Transaction ID to capture
  
  // Capture Details
  int64 amount_to_capture = 3; // Amount to capture, in minor currency units
  Currency currency = 4; // Currency of the amount to capture
  
  // Metadata
  map<string, string> metadata = 5; // Additional metadata for the connector
  
  // Multiple Capture Information
  optional MultipleCaptureRequestData multiple_capture_data = 6; // Data for multiple capture scenarios
}
```

**Response**: `PaymentServiceCaptureResponse`
```protobuf
message PaymentServiceCaptureResponse {
  // Identification
  Identifier transaction_id = 1; // Identifier for the captured resource
  
  // Status Information
  PaymentStatus status = 2; // Status of the payment after the capture attempt
  optional string error_code = 3; // Error code if the capture failed
  optional string error_message = 4; // Error message if the capture failed
  
  // Reference
  optional Identifier response_ref_id = 5; // Response reference ID for tracking
}
```

**Usage Example**:
```rust
let request = PaymentServiceCaptureRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("capture-ref-123".to_string())),
    }),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    amount_to_capture: 1000, // Amount in minor currency units (e.g., cents)
    currency: Currency::Usd as i32,
    ..Default::default()
};

let response = client.capture(request).await?;
```

#### 5. Refund

**Purpose**: Process a refund for a previously captured payment.

**Request**: `PaymentServiceRefundRequest`
```protobuf
message PaymentServiceRefundRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  string refund_id = 2; // Unique identifier for the refund
  Identifier transaction_id = 3; // Transaction ID to refund
  
  // Amount Information
  int64 payment_amount = 4; // Amount to be refunded, in major currency units
  Currency currency = 5; // Currency of the refund, ISO 4217 code
  int64 minor_payment_amount = 6; // Amount to be refunded, in minor currency units
  int64 refund_amount = 7; // Actual amount to refund, in major units
  int64 minor_refund_amount = 8; // Actual amount to refund in minor units
  
  // Refund Context
  optional string reason = 9; // Reason for the refund
  optional string webhook_url = 10; // URL for webhook notifications
  optional string merchant_account_id = 11; // Merchant account ID for the refund
  optional CaptureMethod capture_method = 12; // Capture method related to the original payment
  
  // Metadata
  map<string, string> metadata = 13; // Metadata specific to the connector
  map<string, string> refund_metadata = 14; // Metadata specific to the refund
  
  // Browser Information
  optional BrowserInformation browser_info = 15; // Browser information, if relevant
}
```

**Response**: `RefundResponse`
```protobuf
message RefundResponse {
  // Identification
  Identifier transaction_id = 1; // Identifier for the synchronized resource
  string refund_id = 2; // Connector's ID for the refund
  
  // Status Information
  RefundStatus status = 3; // Current status of the refund
  optional string error_code = 4; // Error code if synchronization encountered an issue
  optional string error_message = 5; // Error message if synchronization encountered an issue
  
  // Reference
  optional Identifier response_ref_id = 6; // Response reference ID for tracking
  
  // Refund Details
  optional int64 refund_amount = 7; // Refunded amount in major currency units
  optional int64 minor_refund_amount = 8; // Refunded amount in minor currency units
  optional Currency refund_currency = 9; // Currency of the refund
  optional int64 payment_amount = 10; // Original payment amount in major currency units
  optional int64 minor_payment_amount = 11; // Original payment amount in minor currency units
  optional string refund_reason = 12; // Reason for the refund
  
  // Timestamps
  optional int64 created_at = 13; // Unix timestamp when the refund was created
  optional int64 updated_at = 14; // Unix timestamp when the refund was last updated
  optional int64 processed_at = 15; // Unix timestamp when the refund was processed
  
  // Additional Context
  optional string customer_name = 16; // Name of the customer
  optional string email = 17; // Email address of the customer
  optional string merchant_order_reference_id = 18; // Merchant's internal reference ID
  map<string, string> metadata = 19; // Additional metadata from the connector
  map<string, string> refund_metadata = 20; // Refund-specific metadata from the connector
}
```

**Usage Example**:
```rust
let request = PaymentServiceRefundRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("refund-ref-123".to_string())),
    }),
    refund_id: "refund_123456789".to_string(),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    payment_amount: 1000,
    currency: Currency::Usd as i32,
    minor_payment_amount: 1000,
    refund_amount: 500,
    minor_refund_amount: 500,
    reason: Some("Customer requested refund".to_string()),
    ..Default::default()
};

let response = client.refund(request).await?;
```

#### 6. Register (Mandate Setup)

**Purpose**: Set up a payment mandate for recurring payments.

**Request**: `PaymentServiceRegisterRequest`
```protobuf
message PaymentServiceRegisterRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  
  // Mandate Details
  Currency currency = 2; // The currency for the mandate
  PaymentMethod payment_method = 3; // Payment method to be used for the mandate
  optional int64 minor_amount = 4; // Optional: Amount to authorize during mandate setup
  
  // Customer Information
  optional string email = 5; // Email address of the customer
  optional string customer_name = 6; // Name of the customer
  optional string connector_customer_id = 7; // Customer ID as recognized by the connector
  
  // Address Information
  PaymentAddress address = 8; // Billing address details for the mandate
  
  // Authentication Details
  AuthenticationType auth_type = 9; // Type of authentication to be used
  bool enrolled_for_3ds = 10; // Indicates if the customer is enrolled for 3D Secure
  optional AuthenticationData authentication_data = 11; // Additional authentication data
  
  // Metadata
  map<string, string> metadata = 12; // Additional metadata for the connector
  
  // URLs for Redirection and Webhooks
  optional string return_url = 13; // URL to redirect after setup
  optional string webhook_url = 14; // URL for webhook notifications
  optional string complete_authorize_url = 15; // URL to complete authorization
  
  // Session and Token Information
  optional AccessToken access_token = 16; // Access token for secure communication
  optional string session_token = 17; // Session token, if applicable
  
  // Order Details
  optional int64 order_tax_amount = 18; // Tax amount, if an initial payment is part of setup
  optional string order_category = 19; // Category of the order/service related to the mandate
  optional string merchant_order_reference_id = 20; // Merchant's internal reference ID
  optional int64 shipping_cost = 21; // Shipping cost, if an initial payment is part of setup
  
  // Behavioral Flags and Preferences
  optional FutureUsage setup_future_usage = 22; // Indicates future usage intention
  optional bool off_session = 23; // Indicates if off-session process
  bool request_incremental_authorization = 24; // Indicates if incremental authorization is requested
  optional bool request_extended_authorization = 25; // Indicates if extended authorization is requested
  
  // Contextual Information
  optional CustomerAcceptance customer_acceptance = 26; // Details of customer acceptance
  optional BrowserInformation browser_info = 27; // Information about the customer's browser
  optional PaymentExperience payment_experience = 28; // Preferred payment experience
}
```

**Response**: `PaymentServiceRegisterResponse`
```protobuf
message PaymentServiceRegisterResponse {
  // Identification
  Identifier registration_id = 1; // Identifier for the mandate registration
  
  // Status Information
  MandateStatus status = 2; // Status of the mandate setup attempt
  optional string error_code = 3; // Error code if the mandate setup failed
  optional string error_message = 4; // Error message if the mandate setup failed
  
  // Mandate Details
  MandateReference mandate_reference = 5; // Reference to the created mandate
  
  // Redirection and Transaction Details
  optional RedirectForm redirection_data = 6; // Data for redirecting the customer's browser
  optional string network_txn_id = 7; // Network transaction ID
  optional Identifier response_ref_id = 8; // Response reference ID for tracking
  
  // Authorization Details
  optional bool incremental_authorization_allowed = 9; // Indicates if incremental authorization is allowed
}
```

**Usage Example**:
```rust
let request = PaymentServiceRegisterRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("mandate-ref-123".to_string())),
    }),
    currency: Currency::Usd as i32,
    payment_method: PaymentMethod::Card as i32,
    minor_amount: Some(0), // Usually 0 for mandate setup
    email: Some("customer@example.com".to_string()),
    customer_name: Some("John Doe".to_string()),
    address: Some(PaymentAddress {
        billing_address: Some(Address::default()),
        shipping_address: Some(Address::default()),
    }),
    auth_type: AuthenticationType::NoThreeDs as i32,
    enrolled_for_3ds: false,
    setup_future_usage: Some(FutureUsage::OffSession as i32),
    customer_acceptance: Some(CustomerAcceptance {
        acceptance_type: AcceptanceType::Online as i32,
        accepted_at: 1234567890, // Unix timestamp
        online_mandate_details: Some(OnlineMandate {
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: "Mozilla/5.0...".to_string(),
        }),
    }),
    ..Default::default()
};

let response = client.register(request).await?;
```

#### 7. Dispute

**Purpose**: Create a new dispute for a payment.
**⚠️ Implementation Status**: Currently returns placeholder response; full connector integration pending.

**Request**: `PaymentServiceDisputeRequest`
```protobuf
message PaymentServiceDisputeRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  Identifier transaction_id = 2; // Transaction ID to raise the dispute for
  string dispute_id = 3; // Connector's unique identifier
}
```

**Response**: `DisputeResponse`
```protobuf
message DisputeResponse {
  // Identification
  optional string dispute_id = 1; // Connector's unique identifier for the dispute
  optional Identifier transaction_id = 2; // Transaction ID associated with the dispute
  
  // Status Information
  DisputeStatus dispute_status = 3; // Status of the dispute
  DisputeStage dispute_stage = 4; // Current stage of the dispute
  optional string connector_status_code = 5; // Connector status code
  optional string error_code = 6; // Error code if retrieval failed
  optional string error_message = 7; // Error message if retrieval failed
  
  // Dispute Details
  optional int64 dispute_amount = 8; // Amount in dispute (minor currency units)
  optional Currency dispute_currency = 9; // Currency of the disputed amount
  optional int64 dispute_date = 10; // Unix timestamp when dispute was created
  optional int64 service_date = 11; // Unix timestamp of service date, if applicable
  optional int64 shipping_date = 12; // Unix timestamp of shipping date, if applicable
  optional int64 due_date = 13; // Unix timestamp of due date for response to dispute
  
  // Evidence
  repeated EvidenceDocument evidence_documents = 14; // Collection of evidence documents submitted
  
  // Additional Context
  optional string dispute_reason = 15; // Reason for the dispute
  optional string dispute_message = 16; // Message from the disputor
  
  // Reference
  optional Identifier response_ref_id = 17; // Response reference ID for tracking
}
```

**Usage Example**:
```rust
let request = PaymentServiceDisputeRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("dispute-ref-123".to_string())),
    }),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    dispute_id: "dispute_123456789".to_string(),
};

let response = client.dispute(request).await?;
```

#### 8. Transform (Webhook Processing)

**Purpose**: Process incoming webhooks from payment processors.

**Request**: `PaymentServiceTransformRequest`
```protobuf
message PaymentServiceTransformRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  
  // Request Details
  RequestDetails request_details = 2; // Details of the incoming HTTP request
  
  // Security
  optional WebhookSecrets webhook_secrets = 3; // Secrets for verifying authenticity
}
```

**Response**: `PaymentServiceTransformResponse`
```protobuf
message PaymentServiceTransformResponse {
  // Event Information
  WebhookEventType event_type = 1; // Type of event indicated by the webhook
  
  // Content
  WebhookResponseContent content = 2; // Content of the webhook, parsed into a specific response type
  
  // Verification
  bool source_verified = 3; // Indicates if the source was successfully verified
  
  // Reference
  optional Identifier response_ref_id = 4; // Response reference ID for tracking
}
```

**Usage Example**:
```rust
use std::collections::HashMap;

let request = PaymentServiceTransformRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("webhook-ref-123".to_string())),
    }),
    request_details: Some(RequestDetails {
        method: HttpMethod::Post as i32,
        uri: Some("/webhook/payment".to_string()),
        headers: HashMap::from([
            ("Content-Type".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "Adyen/1.0".to_string()),
            ("Authorization".to_string(), "Basic xyz123".to_string()),
        ]),
        body: webhook_body_bytes,
        query_params: None,
    }),
    webhook_secrets: Some(WebhookSecrets {
        secret: "your-webhook-secret".to_string(),
        additional_secret: None,
    }),
};

let response = client.transform(request).await?;
```

### RefundService Methods

#### 1. Get (Refund Status)

**Purpose**: Synchronize and check the status of a refund.

**Request**: `RefundServiceGetRequest`
```protobuf
message RefundServiceGetRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  Identifier transaction_id = 2; // Transaction ID associated with the refund
  string refund_id = 3; // Refund identifier
  
  // Refund Details
  optional string refund_reason = 4; // Reason for the refund, if provided during sync
}
```

**Response**: `RefundResponse` (same as PaymentService.Refund response)

**Usage Example**:
```rust
let request = RefundServiceGetRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("refund-sync-ref-123".to_string())),
    }),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    refund_id: "refund_123456789".to_string(),
    refund_reason: Some("Customer requested refund".to_string()),
};

let response = refund_client.get(request).await?;
```

#### 2. Transform (Refund Webhook Processing)

**Purpose**: Process incoming refund-related webhooks from payment processors.

**Request**: `RefundServiceTransformRequest`
```protobuf
message RefundServiceTransformRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  
  // Request Details
  RequestDetails request_details = 2; // Details of the incoming HTTP request
  
  // Security
  optional WebhookSecrets webhook_secrets = 3; // Secrets for verifying authenticity
}
```

**Response**: `RefundServiceTransformResponse`
```protobuf
message RefundServiceTransformResponse {
  // Event Information
  WebhookEventType event_type = 1; // Type of event indicated by the webhook
  
  // Content
  WebhookResponseContent content = 2; // Content of the webhook, parsed into a specific response type
  
  // Verification
  bool source_verified = 3; // Indicates if the source was successfully verified
  
  // Reference
  optional Identifier response_ref_id = 4; // Response reference ID for tracking
}
```

**Usage Example**:
```rust
let request = RefundServiceTransformRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("refund-webhook-ref-123".to_string())),
    }),
    request_details: Some(RequestDetails {
        method: HttpMethod::Post as i32,
        uri: Some("/webhook/refund".to_string()),
        headers: webhook_headers,
        body: webhook_body_bytes,
        query_params: None,
    }),
    webhook_secrets: Some(WebhookSecrets {
        secret: "your-webhook-secret".to_string(),
        additional_secret: None,
    }),
};

let response = refund_client.transform(request).await?;
```

### DisputeService Methods

#### 1. SubmitEvidence

**Purpose**: Submit evidence for a dispute.

**Request**: `DisputeServiceSubmitEvidenceRequest`
```protobuf
message DisputeServiceSubmitEvidenceRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  optional Identifier transaction_id = 2; // Transaction ID associated with the dispute
  string dispute_id = 3; // Dispute identifier
  
  // Dates
  optional int64 service_date = 4; // Unix timestamp of service date, if applicable
  optional int64 shipping_date = 5; // Unix timestamp of shipping date, if applicable
  
  // Evidence
  repeated EvidenceDocument evidence_documents = 6; // Collection of evidence documents
}
```

**Response**: `DisputeServiceSubmitEvidenceResponse`
```protobuf
message DisputeServiceSubmitEvidenceResponse {
  // Identification
  optional string dispute_id = 1; // Connector's unique identifier for the dispute
  repeated string submitted_evidence_ids = 2; // IDs of the submitted evidence documents
  
  // Status Information
  DisputeStatus dispute_status = 3; // Status of the dispute after submitting evidence
  optional string connector_status_code = 4; // Connector status code
  optional string error_code = 5; // Error code if submitting evidence failed
  optional string error_message = 6; // Error message if submitting evidence failed
  
  // Reference
  optional Identifier response_ref_id = 7; // Response reference ID for tracking
}
```

**Usage Example**:
```rust
let request = DisputeServiceSubmitEvidenceRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("evidence-ref-123".to_string())),
    }),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    dispute_id: "dispute_123456789".to_string(),
    service_date: Some(1234567890), // Unix timestamp
    shipping_date: Some(1234567890), // Unix timestamp
    evidence_documents: vec![
        EvidenceDocument {
            evidence_type: EvidenceType::Receipt as i32,
            file_content: Some(receipt_pdf_bytes),
            file_mime_type: Some("application/pdf".to_string()),
            text_content: Some("Receipt for transaction #12345".to_string()),
            ..Default::default()
        },
        EvidenceDocument {
            evidence_type: EvidenceType::CustomerCommunication as i32,
            text_content: Some("Email exchange with customer showing satisfaction".to_string()),
            ..Default::default()
        },
    ],
};

let response = dispute_client.submit_evidence(request).await?;
```

#### 2. Get (Dispute Status)

**Purpose**: Retrieve dispute information.
**⚠️ Implementation Status**: Currently returns placeholder response; full implementation pending.

**Request**: `DisputeServiceGetRequest`
```protobuf
message DisputeServiceGetRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  optional string dispute_id = 2; // Dispute identifier
  string connector_dispute_id = 3; // Connector's unique identifier
}
```

**Response**: `DisputeResponse` (same as PaymentService.Dispute response)

**Usage Example**:
```rust
let request = DisputeServiceGetRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("dispute-get-ref-123".to_string())),
    }),
    dispute_id: Some("dispute_123456789".to_string()),
    connector_dispute_id: "adyen_dispute_id_xyz".to_string(),
};

let response = dispute_client.get(request).await?;
```

#### 3. Defend

**Purpose**: Defend a dispute with a reason code.

**Request**: `DisputeDefendRequest`
```protobuf
message DisputeDefendRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  Identifier transaction_id = 2; // Transaction ID to defend dispute for
  string dispute_id = 3; // Connector's unique identifier
  
  // Defend Details
  optional string reason_code = 4; // Reason code for defending the dispute
}
```

**Response**: `DisputeDefendResponse`
```protobuf
message DisputeDefendResponse {
  // Identification
  string dispute_id = 1; // Connector's unique identifier for the dispute
  
  // Status Information
  DisputeStatus dispute_status = 2; // Status of the dispute after defending
  optional string connector_status_code = 3; // Connector status code
  optional string error_code = 4; // Error code if defending failed
  optional string error_message = 5; // Error message if defending failed
  
  // Reference
  optional Identifier response_ref_id = 6; // Response reference ID for tracking
}
```

**Usage Example**:
```rust
let request = DisputeDefendRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("defend-ref-123".to_string())),
    }),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    dispute_id: "dispute_123456789".to_string(),
    reason_code: Some("MERCHANDISE_NOT_RECEIVED".to_string()),
};

let response = dispute_client.defend(request).await?;
```

#### 4. Accept

**Purpose**: Accept a dispute raised by a customer.

**Request**: `AcceptDisputeRequest`
```protobuf
message AcceptDisputeRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  Identifier transaction_id = 2; // Transaction ID to accept dispute for
  string dispute_id = 3; // Connector's unique identifier
}
```

**Response**: `AcceptDisputeResponse`
```protobuf
message AcceptDisputeResponse {
  // Identification
  string dispute_id = 1; // Connector's unique identifier for the dispute
  
  // Status Information
  DisputeStatus dispute_status = 2; // Status of the dispute after accepting
  optional string connector_status_code = 3; // Connector status code
  optional string error_code = 4; // Error code if accepting failed
  optional string error_message = 5; // Error message if accepting failed
  
  // Reference
  optional Identifier response_ref_id = 6; // Response reference ID for tracking
}
```

**Usage Example**:
```rust
let request = AcceptDisputeRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("accept-ref-123".to_string())),
    }),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    dispute_id: "dispute_123456789".to_string(),
};

let response = dispute_client.accept(request).await?;
```

#### 5. Transform (Dispute Webhook Processing)

**Purpose**: Process incoming dispute-related webhooks from payment processors.

**Request**: `DisputeServiceTransformRequest`
```protobuf
message DisputeServiceTransformRequest {
  // Identification
  Identifier request_ref_id = 1; // Reference ID for tracking
  
  // Request Details
  RequestDetails request_details = 2; // Details of the incoming HTTP request
  
  // Security
  optional WebhookSecrets webhook_secrets = 3; // Secrets for verifying authenticity
}
```

**Response**: `DisputeServiceTransformResponse`
```protobuf
message DisputeServiceTransformResponse {
  // Event Information
  WebhookEventType event_type = 1; // Type of event indicated by the webhook
  
  // Content
  WebhookResponseContent content = 2; // Content of the webhook, parsed into a specific response type
  
  // Verification
  bool source_verified = 3; // Indicates if the source was successfully verified
  
  // Reference
  optional Identifier response_ref_id = 4; // Response reference ID for tracking
}
```

**Usage Example**:
```rust
let request = DisputeServiceTransformRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("dispute-webhook-ref-123".to_string())),
    }),
    request_details: Some(RequestDetails {
        method: HttpMethod::Post as i32,
        uri: Some("/webhook/dispute".to_string()),
        headers: webhook_headers,
        body: webhook_body_bytes,
        query_params: None,
    }),
    webhook_secrets: Some(WebhookSecrets {
        secret: "your-webhook-secret".to_string(),
        additional_secret: None,
    }),
};

let response = dispute_client.transform(request).await?;
```

## Common Data Structures

### Identifier

Represents an identifier, which can be one of several types.

```protobuf
message Identifier {
  oneof id_type {
    // Connector's transaction ID.
    string id = 1;
    
    // Encoded data representing the ID or related information.
    string encoded_data = 2;
    
    // Indicates that no specific ID is returned or applicable.
    google.protobuf.Empty no_response_id_marker = 3;
  }
}
```

### RedirectForm

Represents data for a redirection, can be either form data or raw HTML.

```protobuf
message RedirectForm {
  oneof form_type {
    // Data for constructing an HTML form for redirection.
    FormData form = 1;
    
    // Raw HTML data for redirection.
    HtmlData html = 2;
  }
}

message FormData {
  // The endpoint URL where the form should be submitted.
  string endpoint = 1;
  
  // HTTP method to be used for form submission (e.g., POST).
  HttpMethod method = 2;
  
  // Key-value pairs representing the form fields.
  map<string, string> form_fields = 3;
}

message HtmlData {
  // The HTML content as a string.
  string html_data = 1;
}
```

### PaymentAddress

Represents billing and shipping addresses.

```protobuf
message PaymentAddress {
  // Shipping address.
  Address shipping_address = 1;
  
  // Customer Billing address.
  Address billing_address = 2;
}

message Address {
  // Personal Information
  optional string first_name = 1;
  optional string last_name = 2;
  
  // Address Details
  optional string line1 = 3;
  optional string line2 = 4;
  optional string line3 = 5;
  optional string city = 6;
  optional string state = 7;
  optional string zip_code = 8;
  optional CountryAlpha2 country_alpha2_code = 9;

  // Contact Information
  optional string email = 10;
  optional string phone_number = 11;
  optional string phone_country_code = 12;
}
```

### BrowserInformation

Represents browser information for 3DS authentication.

```protobuf
message BrowserInformation {
  // Display Information
  optional uint32 color_depth = 1;
  optional uint32 screen_height = 5;
  optional uint32 screen_width = 6;
  
  // Browser Settings
  optional bool java_enabled = 2;
  optional bool java_script_enabled = 3;
  optional string language = 4;
  optional int32 time_zone_offset_minutes = 7;
  
  // Browser Headers
  optional string accept_header = 9;
  optional string user_agent = 10;
  optional string accept_language = 14;
  
  // Device Information
  optional string ip_address = 8;
  optional string os_type = 11;
  optional string os_version = 12;
  optional string device_model = 13;
}
```

### CustomerAcceptance

Represents customer acceptance for mandate setup.

```protobuf
message CustomerAcceptance {
  // Type of acceptance (e.g., online, offline).
  AcceptanceType acceptance_type = 1;
  
  // Unix timestamp (seconds since epoch) of when the acceptance was given.
  int64 accepted_at = 2;
  
  // Details if the acceptance was an online mandate.
  optional OnlineMandate online_mandate_details = 3;
}

enum AcceptanceType {
  ACCEPTANCE_TYPE_UNSPECIFIED = 0; // Default value
  ONLINE = 1;                      // Acceptance was given online.
  OFFLINE = 2;                     // Acceptance was given offline.
}

message OnlineMandate {
  // IP address from which the mandate was accepted.
  optional string ip_address = 1;
  
  // User agent string of the browser used for mandate acceptance.
  string user_agent = 2;
}
```

### AccessToken

Access token details.

```protobuf
message AccessToken {
  // The token string.
  string token = 1;
  
  // Expiration timestamp of the token (seconds since epoch).
  int64 expires_in_seconds = 2;
}
```

### AuthenticationData

Additional authentication data, typically from 3DS.

```protobuf
message AuthenticationData {
  // Electronic Commerce Indicator (ECI) from 3DS.
  optional string eci = 1;
  
  // Cardholder Authentication Verification Value (CAVV).
  string cavv = 2;
  
  // 3DS Server Transaction ID.
  optional Identifier threeds_server_transaction_id = 3;
  
  // 3DS Message Version (e.g., "2.1.0", "2.2.0").
  optional string message_version = 4;
  
  // Directory Server Transaction ID (DS Trans ID).
  optional string ds_transaction_id = 5;
}
```

### MandateReference

Reference to a payment mandate.

```protobuf
message MandateReference {
  // Connector's unique identifier for the mandate.
  optional string mandate_id = 1;
}
```

### RequestDetails

Details of an HTTP request, typically for incoming webhooks.

```protobuf
message RequestDetails {
  // HTTP method of the request (e.g., GET, POST).
  HttpMethod method = 1;
  
  // URI of the request.
  optional string uri = 2;
  
  // Headers of the HTTP request.
  map<string, string> headers = 3;
  
  // Body of the HTTP request.
  bytes body = 4;
  
  // Query parameters of the request.
  optional string query_params = 5;
}
```

### WebhookSecrets

Secrets used for verifying connector webhooks.

```protobuf
message WebhookSecrets {
  // Primary secret for webhook verification.
  string secret = 1;
  
  // Additional secret, if required by the connector.
  optional string additional_secret = 2;
}
```

### WebhookResponseContent

Content of a webhook response, can be one of several types.

```protobuf
message WebhookResponseContent {
  oneof content {
    // Content if the webhook is for a payment synchronization.
    PaymentServiceGetResponse payments_response = 1;
    
    // Content if the webhook is for a refund synchronization.
    RefundResponse refunds_response = 2;
    
    // Content if the webhook is for a dispute synchronization.
    DisputeResponse disputes_response = 3;
  }
}
```

### MultipleCaptureRequestData

Data for a multiple capture request.

```protobuf
message MultipleCaptureRequestData {
  // Sequence number for this capture in a series of multiple captures.
  int64 capture_sequence = 1;
  
  // Reference for this specific capture.
  string capture_reference = 2;
}
```

### EvidenceDocument

Represents a single piece of evidence for a dispute.

```protobuf
message EvidenceDocument {
  // Type of the evidence.
  EvidenceType evidence_type = 1;

  // Content Options
  // Content of the document, if it's a file.
  optional bytes file_content = 2;
  
  // MIME type of the file (e.g., "application/pdf", "image/png"), if file_content is provided.
  optional string file_mime_type = 3;
  
  // Identifier for the file if stored with an external provider.
  optional string provider_file_id = 4;

  // Textual content of the evidence, if it's not a file or in addition to a file.
  optional string text_content = 5;
}
```

## Enumerations

### PaymentStatus

Represents the status of a payment attempt.

```protobuf
enum PaymentStatus {
  ATTEMPT_STATUS_UNSPECIFIED = 0; // Default value

  // Initial states
  STARTED = 1;
  PAYMENT_METHOD_AWAITED = 22;    // Waiting for customer to provide payment method
  DEVICE_DATA_COLLECTION_PENDING = 24; // Waiting for device data collection
  CONFIRMATION_AWAITED = 23;      // Waiting for customer confirmation

  // Authentication flow
  AUTHENTICATION_PENDING = 4;
  AUTHENTICATION_SUCCESSFUL = 5;
  AUTHENTICATION_FAILED = 2;

  // Authorization flow
  AUTHORIZING = 9;
  AUTHORIZED = 6;
  AUTHORIZATION_FAILED = 7;

  // Charging flow
  CHARGED = 8;
  PARTIAL_CHARGED = 17;
  PARTIAL_CHARGED_AND_CHARGEABLE = 18; // Partially charged, remaining amount can be captured
  AUTO_REFUNDED = 16;

  // Capture flow
  CAPTURE_INITIATED = 13;
  CAPTURE_FAILED = 14;

  // Void flow
  VOID_INITIATED = 12;
  VOIDED = 11;
  VOID_FAILED = 15;

  // Other payment flows
  COD_INITIATED = 10; // Cash on Delivery initiated

  // Terminal/fallback states
  ROUTER_DECLINED = 3;
  PENDING = 20;       // General pending state
  FAILURE = 21;       // General failure state
  UNRESOLVED = 19;    // Status could not be determined
}
```

### MandateStatus

Represents the status of a mandate setup attempt.

```protobuf
enum MandateStatus {
  MANDATE_STATUS_UNSPECIFIED = 0; // Default value

  // Initial states
  MANDATE_INITIATED = 1;           // Mandate setup has been initiated
  MANDATE_PENDING = 2;             // Mandate setup is pending (waiting for processing)
  
  // Authentication flow
  MANDATE_AUTHENTICATION_PENDING = 3;      // Waiting for customer authentication
  MANDATE_AUTHENTICATION_SUCCESSFUL = 4;   // Customer authentication successful
  MANDATE_AUTHENTICATION_FAILED = 5;       // Customer authentication failed

  // Setup completion states
  MANDATE_ESTABLISHED = 6;         // Mandate has been successfully established
  MANDATE_FAILED = 7;              // Mandate setup failed
  MANDATE_CANCELLED = 8;           // Mandate setup was cancelled
  MANDATE_EXPIRED = 9;             // Mandate setup expired

  // Terminal/fallback states
  MANDATE_ROUTER_DECLINED = 10;    // Mandate declined by router
  MANDATE_UNRESOLVED = 11;         // Status could not be determined
}
```

### RefundStatus

Represents the status of a refund.

```protobuf
enum RefundStatus {
  REFUND_STATUS_UNSPECIFIED = 0; // Default value
  REFUND_FAILURE = 1;
  REFUND_MANUAL_REVIEW = 2;      // Refund requires manual review
  REFUND_PENDING = 3;
  REFUND_SUCCESS = 4;
  REFUND_TRANSACTION_FAILURE = 5; // Failure at the transaction level for the refund
}
```

### DisputeStatus

Represents the status of a dispute.

```protobuf
enum DisputeStatus {
  DISPUTE_STATUS_UNSPECIFIED = 0; // Default value
  DISPUTE_OPENED = 1;
  DISPUTE_EXPIRED = 2;
  DISPUTE_ACCEPTED = 3;
  DISPUTE_CANCELLED = 4;
  DISPUTE_CHALLENGED = 5;         // Dispute is being challenged with evidence
  DISPUTE_WON = 6;
  DISPUTE_LOST = 7;
}
```

### DisputeStage

Represents the stage of a dispute.

```protobuf
enum DisputeStage {
  DISPUTE_STAGE_UNSPECIFIED = 0; // Default value
  PRE_DISPUTE = 1;
  ACTIVE_DISPUTE = 2;
  PRE_ARBITRATION = 3;
}
```

### CaptureMethod

Represents the method for capturing a payment.

```protobuf
enum CaptureMethod {
  CAPTURE_METHOD_UNSPECIFIED = 0; // Default value
  AUTOMATIC = 1;                  // Capture is done automatically after authorization.
  MANUAL = 2;                     // Capture must be triggered manually.
  MANUAL_MULTIPLE = 3;            // Multiple manual captures are possible.
  SCHEDULED = 4;                  // Capture is scheduled for a later time.
  SEQUENTIAL_AUTOMATIC = 5;       // Sequential automatic captures.
}
```

### FutureUsage

Represents how a payment method might be used in the future.

```protobuf
enum FutureUsage {
  FUTURE_USAGE_UNSPECIFIED = 0;   // Default value
  OFF_SESSION = 1;                // For merchant-initiated transactions (e.g., subscriptions).
  ON_SESSION = 2;                 // For customer-initiated transactions.
}
```

### AuthenticationType

Represents the type of authentication used for a payment.

```protobuf
enum AuthenticationType {
  AUTHENTICATION_TYPE_UNSPECIFIED = 0; // Default value
  THREE_DS = 1;                        // 3D Secure authentication.
  NO_THREE_DS = 2;                     // No 3D Secure, or 3DS explicitly bypassed.
}
```

### PaymentExperience

Represents the preferred payment experience for the customer.

```protobuf
enum PaymentExperience {
  PAYMENT_EXPERIENCE_UNSPECIFIED = 0; // Default value
  REDIRECT_TO_URL = 1;                // Redirect customer to a URL.
  INVOKE_SDK_CLIENT = 2;              // Invoke a client-side SDK.
  DISPLAY_QR_CODE = 3;                // Display a QR code.
  ONE_CLICK = 4;                      // One-click payment experience.
  LINK_WALLET = 5;                    // Link a digital wallet.
  INVOKE_PAYMENT_APP = 6;             // Invoke a payment application.
  DISPLAY_WAIT_SCREEN = 7;            // Display a waiting screen.
  COLLECT_OTP = 8;                    // Collect an OTP from the customer.
}
```

### WebhookEventType

Represents the type of event that a webhook can represent.

```protobuf
enum WebhookEventType {
  WEBHOOK_EVENT_TYPE_UNSPECIFIED = 0;  // Default, unspecified webhook event type.
  WEBHOOK_PAYMENT = 1;                 // Webhook event related to a payment.
  WEBHOOK_REFUND = 2;                  // Webhook event related to a refund.
  WEBHOOK_DISPUTE = 3;                 // Webhook event related to a dispute.
}
```

### HttpMethod

Represents HTTP methods.

```protobuf
enum HttpMethod {
  HTTP_METHOD_UNSPECIFIED = 0; // Default, unspecified HTTP method.
  GET = 1;                     // HTTP GET method.
  POST = 2;                    // HTTP POST method.
  PUT = 3;                     // HTTP PUT method.
  DELETE = 4;                  // HTTP DELETE method.
}
```

### Currency

Represents supported currencies (ISO 4217).

```protobuf
enum Currency {
  CURRENCY_UNSPECIFIED = 0; // Default value
  AED = 1;   // UAE Dirham
  AFN = 2;   // Afghan Afghani
  ALL = 3;   // Albanian Lek
  // ... (many more currencies)
  USD = 146; // US Dollar
  EUR = 45;  // Euro
  GBP = 48;  // British Pound
  JPY = 69;  // Japanese Yen
  // ... (complete list available in proto file)
}
```

### PaymentMethod

Represents supported payment methods using a oneof structure for different payment types.

```protobuf
message PaymentMethod {
  oneof payment_method {
    CardPaymentMethodType card = 1;                      // Card-based payment methods - SUPPORTED
    TokenPaymentMethodType token = 4;                    // Tokenized payment methods - SUPPORTED
    // Additional payment method types are defined but currently commented out in the proto
    // This includes: wallets, RTP, bank transfers, BNPL, etc.
  }
}
```

#### CardPaymentMethodType

Card-specific payment method handling:

```protobuf
message CardPaymentMethodType {
  oneof card_type {
    CardDetails card_details = 1;     // Direct card information
    CardRedirect card_redirect = 2;   // Card redirect flows
  }
}
```

#### CardDetails

Comprehensive card information structure:

```protobuf
message CardDetails {
  // Card Information
  string card_number = 1;           // Primary Account Number (PAN)
  string card_exp_month = 2;        // Expiry month (MM)
  string card_exp_year = 3;         // Expiry year (YYYY)
  optional string card_cvc = 4;     // Card Verification Code
  optional string card_holder_name = 5;  // Cardholder name
  
  // Additional Card Data
  optional CardNetwork card_network = 6;     // Card network/brand
  optional string card_issuer = 7;           // Issuing bank
  optional CountryAlpha2 card_issuing_country = 8;  // Issuing country
  optional PaymentMethodType card_type = 9;  // Credit/Debit classification
  optional string last_four_digits = 10;     // Last 4 digits for display
  
  // Security and Metadata
  optional string card_fingerprint = 11;     // Unique card identifier
  optional int64 card_exp_month_num = 12;    // Expiry month as number
  optional int64 card_exp_year_num = 13;     // Expiry year as number
}
```

#### TokenPaymentMethodType

Tokenized payment method handling:

```protobuf
message TokenPaymentMethodType {
  string token = 1;                          // Payment method token
  optional PaymentMethodType payment_method_type = 2;  // Original payment method type
  optional string payment_method = 3;        // Payment method identifier
  optional string payment_method_issuer = 4; // Token issuer
  optional CardNetwork card_network = 5;     // Associated card network
}
```

### PaymentMethodType

Represents specific payment method types.

```protobuf
enum PaymentMethodType {
  PAYMENT_METHOD_TYPE_UNSPECIFIED = 0; // Default value
  ACH = 1;
  AFFIRM = 2;
  AFTERPAY_CLEARPAY = 3;
  ALFAMART = 4;
  ALI_PAY = 5;
  ALI_PAY_HK = 6;
  ALMA = 7;
  AMAZON_PAY = 8;
  APPLE_PAY = 9;
  ATOME = 10;
  BACS = 11;
  BANCONTACT_CARD = 12;
  BECS = 13;
  BENEFIT = 14;
  BIZUM = 15;
  BLIK = 16;
  BOLETO = 17;
  // ... (many more payment method types)
  CREDIT = 24;
  DEBIT = 29;
  GOOGLE_PAY = 38;
  IDEAL = 41;
  PAYPAL = 62; // Note: PAYPAL enum value from Connector enum
  SEPA = 73;
  UPI_COLLECT = 80;
  UPI_INTENT = 81;
  // ... (complete list available in proto file)
}
```

### Connector

Enumeration of supported payment processors.

```protobuf
enum Connector {
  CONNECTOR_UNSPECIFIED = 0; // Default value
  ADYENPLATFORM = 1;
  ACI = 2;
  ADYEN = 3;
  AIRWALLEX = 4;
  AUTHORIZEDOTNET = 5;
  BAMBORA = 6;
  BAMBORAAPAC = 7;
  BANKOFAMERICA = 8;
  BILLWERK = 9;
  BITPAY = 10;
  BLUESNAP = 11;
  BOKU = 12;
  BRAINTREE = 13;
  CASHTOCODE = 14;
  CHARGEBEE = 15;
  CHECKOUT = 16;
  COINBASE = 17;
  COINGATE = 18;
  CRYPTOPAY = 19;
  CTP_MASTERCARD = 20;
  CTP_VISA = 21;
  CYBERSOURCE = 22;
  DATATRANS = 23;
  DEUTSCHEBANK = 24;
  DIGITALVIRGO = 25;
  DLOCAL = 26;
  EBANX = 27;
  ELAVON = 28;
  FISERV = 29;
  FISERVEMEA = 30;
  FIUU = 31;
  FORTE = 32;
  GETNET = 33;
  GLOBALPAY = 34;
  GLOBEPAY = 35;
  GOCARDLESS = 36;
  GPAYMENTS = 37;
  HIPAY = 38;
  HELCIM = 39;
  INESPAY = 40;
  IATAPAY = 41;
  ITAUBANK = 42;
  JPMORGAN = 43;
  JUSPAYTHREEDSSERVER = 44;
  KLARNA = 45;
  MIFINITY = 46;
  MOLLIE = 47;
  MONERIS = 48;
  MULTISAFEPAY = 49;
  NETCETERA = 50;
  NEXINETS = 51;
  NEXIXPAY = 52;
  NMI = 53;
  NOMUPAY = 54;
  NOON = 55;
  NOVALNET = 56;
  NUVEI = 57;
  OPENNODE = 58;
  PAYBOX = 59;
  PAYME = 60;
  PAYONE = 61;
  PAYPAL = 62;
  PAYSTACK = 63;
  PAYU = 64;
  PLACETOPAY = 65;
  POWERTRANZ = 66;
  PROPHETPAY = 67;
  RAPYD = 68;
  RAZORPAY = 69;
  RECURLY = 70;
  REDSYS = 71;
  SHIFT4 = 72;
  SQUARE = 73;
  STAX = 74;
  STRIPE = 75;
  TAXJAR = 76;
  THREEDSECUREIO = 77;
  TRUSTPAY = 78;
  TSYS = 79;
  VOLT = 80;
  WELLSFARGO = 81;
  WISE = 82;
  WORLDLINE = 83;
  WORLDPAY = 84;
  SIGNIFYD = 85;
  PLAID = 86;
  RISKIFIED = 87;
  XENDIT = 88;
  ZEN = 89;
  ZSL = 90;
}
```

### CountryAlpha2

Country Alpha-2 code enumeration.

```protobuf
enum CountryAlpha2 {
  COUNTRY_ALPHA2_UNSPECIFIED = 0; // Default value must be first
  US = 1;   // United States
  AF = 2;   // Afghanistan
  AX = 3;   // Aland Islands
  AL = 4;   // Albania
  // ... (complete list of countries)
  GB = 236; // United Kingdom
  CA = 41;  // Canada
  AU = 15;  // Australia
  IN = 104; // India
  // ... (complete list available in proto file)
}
```

### EvidenceType

Type of evidence that can be submitted for a dispute.

```protobuf
enum EvidenceType {
  EVIDENCE_TYPE_UNSPECIFIED = 0;              // Default value
  CANCELLATION_POLICY = 1;                    // Cancellation policy document
  CUSTOMER_COMMUNICATION = 2;                 // Communication with customer
  CUSTOMER_SIGNATURE = 3;                     // Customer signature document
  RECEIPT = 4;                                // Receipt or proof of purchase
  REFUND_POLICY = 5;                         // Refund policy document
  SERVICE_DOCUMENTATION = 6;                  // Service documentation
  SHIPPING_DOCUMENTATION = 7;                // Shipping documentation
  INVOICE_SHOWING_DISTINCT_TRANSACTIONS = 8;  // Invoice showing distinct transactions
  RECURRING_TRANSACTION_AGREEMENT = 9;        // Recurring transaction agreement
  UNCATEGORIZED_FILE = 10;                   // Uncategorized evidence file
}
```

## Authentication

The API uses gRPC metadata for authentication. Clients need to provide the following metadata headers:

1. **x-connector**: The name of the connector to use (e.g., "adyen", "razorpay", "stripe")
2. **x-auth**: The authentication type (e.g., "header-key", "body-key", "signature-key")
3. **x-api-key**: The API key for authentication
4. **x-key1** (optional): Additional key for authentication (used by some connectors)
5. **x-api-secret** (optional): API secret for authentication (used by some connectors)

Example using Rust with Tonic:

```rust
use tonic::metadata::MetadataMap;
use tonic::Request;

let mut metadata = MetadataMap::new();
metadata.insert("x-connector", "adyen".parse().unwrap());
metadata.insert("x-auth", "header-key".parse().unwrap());
metadata.insert("x-api-key", "your-api-key-here".parse().unwrap());

// Create the request with metadata
let mut request = Request::new(payment_request);
*request.metadata_mut() = metadata;

// Make the call
let response = client.authorize(request).await?;
```

Example using Node.js with @grpc/grpc-js:

```javascript
const metadata = new grpc.Metadata();
metadata.add('x-connector', 'adyen');
metadata.add('x-auth', 'header-key');
metadata.add('x-api-key', 'your-api-key-here');

client.authorize(paymentRequest, metadata, (error, response) => {
  if (error) {
    console.error('Error:', error);
  } else {
    console.log('Response:', response);
  }
});
```

### Supported Connectors

The following connectors are currently supported (see `Connector` enum for complete list):
- **ADYEN** (3): Adyen payment processor
- **RAZORPAY** (69): Razorpay payment processor
- **STRIPE** (75): Stripe payment processor (planned/in development)
- And many more (see the `Connector` enum above for the complete list)

### Authentication Types

Different connectors support different authentication methods:
- **header-key**: API key passed in HTTP headers
- **body-key**: API key included in request body
- **signature-key**: HMAC signature-based authentication

## Error Handling

Errors are returned in the response messages with the following fields:

1. **error_code**: A code identifying the error
2. **error_message**: A human-readable error message
3. **status**: The status of the operation (using appropriate status enum)

### Common Error Patterns

#### Payment Authorization Errors
```protobuf
PaymentServiceAuthorizeResponse {
  transaction_id: {
    id_type: {
      no_response_id_marker: {}
    }
  },
  status: AUTHORIZATION_FAILED,
  error_code: "card_declined",
  error_message: "The card was declined by the issuing bank"
}
```

#### Refund Errors
```protobuf
RefundResponse {
  transaction_id: {
    id_type: {
      id: "8837968461238652"
    }
  },
  refund_id: "ref_123456789",
  status: REFUND_FAILURE,
  error_code: "insufficient_funds",
  error_message: "Insufficient funds available for refund"
}
```

#### Dispute Errors
```protobuf
DisputeResponse {
  dispute_id: "dispute_123456789",
  dispute_status: DISPUTE_STATUS_UNSPECIFIED,
  error_code: "evidence_deadline_passed",
  error_message: "The deadline for submitting evidence has passed"
}
```

### Error Codes

Common error codes include:
- **invalid_request**: Request validation failed
- **authentication_failed**: Authentication credentials invalid
- **card_declined**: Card payment was declined
- **insufficient_funds**: Insufficient funds for the operation
- **connector_error**: Error from the payment processor
- **network_error**: Network communication error
- **timeout**: Request timed out
- **rate_limit_exceeded**: Too many requests

### Status Field Values

Each service uses specific status enums:
- **PaymentStatus**: For payment operations (STARTED, AUTHORIZED, CHARGED, FAILED, etc.)
- **RefundStatus**: For refund operations (REFUND_PENDING, REFUND_SUCCESS, REFUND_FAILURE, etc.)
- **DisputeStatus**: For dispute operations (DISPUTE_OPENED, DISPUTE_ACCEPTED, DISPUTE_WON, etc.)
- **MandateStatus**: For mandate operations (MANDATE_ESTABLISHED, MANDATE_FAILED, etc.)

## Versioning

The API is versioned through the protobuf package name and file structure:

- **Package**: `ucs.v2` (Unified Connector Service version 2)
- **Proto Files**: Located in `backend/grpc-api-types/proto/`
  - `services.proto`: Service definitions
  - `payment.proto`: Message definitions and enums
  - `payment_methods.proto`: Payment method specific definitions
  - `health_check.proto`: Health check service

### Backward Compatibility

Changes to the API follow protobuf best practices:
1. **New fields**: Added as optional to maintain backward compatibility
2. **Enum values**: New enum values can be added without breaking existing clients
3. **Deprecated fields**: Marked as deprecated but not removed
4. **Breaking changes**: Require a new version (e.g., v3)

### Legacy Support

The current API includes some legacy message types for backward compatibility:
- `PaymentServiceRefundResponse` (use `RefundResponse` instead)
- `RefundServiceGetResponse` (use `RefundResponse` instead)
- `PaymentServiceDisputeResponse` (use `DisputeResponse` instead)
- `DisputeServiceGetResponse` (use `DisputeResponse` instead)

## Best Practices

### 1. Error Handling
Always check for error responses and handle them appropriately:

```rust
match response.status {
    PaymentStatus::Charged => {
        // Payment successful
        println!("Payment completed: {:?}", response.transaction_id);
    },
    PaymentStatus::AuthorizationFailed | PaymentStatus::Failure => {
        // Handle payment failure
        eprintln!("Payment failed: {} - {}", 
                 response.error_code.unwrap_or_default(),
                 response.error_message.unwrap_or_default());
    },
    _ => {
        // Handle other statuses (pending, etc.)
        println!("Payment status: {:?}", response.status);
    }
}
```

### 2. Idempotency
Use unique reference IDs for each request to ensure idempotency:

```rust
use uuid::Uuid;

let request_ref_id = Identifier {
    id_type: Some(identifier::IdType::Id(Uuid::new_v4().to_string())),
};

let payment_request = PaymentServiceAuthorizeRequest {
    request_ref_id: Some(request_ref_id),
    // ... other fields
};
```

### 3. Metadata and Authentication
Provide all required metadata for authentication:

```rust
// Always set authentication metadata
let mut metadata = MetadataMap::new();
metadata.insert("x-connector", connector_name.parse().unwrap());
metadata.insert("x-auth", auth_type.parse().unwrap());
metadata.insert("x-api-key", api_key.parse().unwrap());

// Add optional metadata if required by connector
if let Some(secret) = api_secret {
    metadata.insert("x-api-secret", secret.parse().unwrap());
}
```

### 4. Request Validation
Validate request data before sending to the API:

```rust
// Validate amount is positive
if request.amount <= 0 || request.minor_amount <= 0 {
    return Err("Amount must be positive");
}

// Validate currency is specified
if request.currency == Currency::CurrencyUnspecified as i32 {
    return Err("Currency must be specified");
}

// Validate required fields
if request.request_ref_id.is_none() {
    return Err("Request reference ID is required");
}
```

### 5. Timeouts and Retries
Set appropriate timeouts and implement retry logic:

```rust
use tonic::transport::Channel;
use tower::timeout::Timeout;
use std::time::Duration;

// Set timeout
let channel = Channel::from_static("http://localhost:50051")
    .timeout(Duration::from_secs(30))
    .connect()
    .await?;

// Implement retry logic for transient errors
for attempt in 1..=3 {
    match client.authorize(request.clone()).await {
        Ok(response) => return Ok(response),
        Err(status) if status.code() == tonic::Code::Unavailable && attempt < 3 => {
            tokio::time::sleep(Duration::from_millis(1000 * attempt)).await;
            continue;
        },
        Err(e) => return Err(e),
    }
}
```

### 6. Logging and Monitoring
Log API requests and responses for debugging and monitoring:

```rust
use tracing::{info, warn, error};

// Log request
info!(
    "Making payment authorization request: ref_id={}, amount={}, currency={:?}",
    request.request_ref_id.as_ref().unwrap_or(&Default::default()),
    request.amount,
    Currency::from_i32(request.currency)
);

// Log response
match response.status {
    PaymentStatus::Charged => {
        info!("Payment successful: transaction_id={:?}", response.transaction_id);
    },
    PaymentStatus::AuthorizationFailed => {
        warn!(
            "Payment authorization failed: error_code={}, error_message={}",
            response.error_code.unwrap_or_default(),
            response.error_message.unwrap_or_default()
        );
    },
    _ => {
        info!("Payment status: {:?}", response.status);
    }
}
```

### 7. Webhook Verification
Always verify webhook authenticity:

```rust
// Verify webhook signature
let webhook_request = PaymentServiceTransformRequest {
    request_ref_id: Some(webhook_ref_id),
    request_details: Some(RequestDetails {
        method: HttpMethod::Post as i32,
        headers: webhook_headers,
        body: webhook_body,
        uri: Some(webhook_uri),
        ..Default::default()
    }),
    webhook_secrets: Some(WebhookSecrets {
        secret: webhook_secret,
        additional_secret: webhook_additional_secret,
    }),
};

let transform_response = client.transform(webhook_request).await?;

if !transform_response.source_verified {
    return Err("Webhook source verification failed");
}
```

### 8. Service Selection
Use the appropriate service for your operation:

```rust
// Payment operations
let payment_client = PaymentServiceClient::new(channel.clone());

// Refund operations
let refund_client = RefundServiceClient::new(channel.clone());

// Dispute operations  
let dispute_client = DisputeServiceClient::new(channel.clone());
```

## Client SDKs

The Connector Service provides client SDKs for various programming languages:

### Available SDKs

1. **Node.js**: `sdk/node-grpc-client`
   - Full TypeScript support
   - Promise-based and callback-based APIs
   - Built-in retry and error handling

2. **Python**: `sdk/python-grpc-client`
   - Python 3.7+ support
   - Async/await support
   - Type hints included

3. **Rust**: `sdk/rust-grpc-client`
   - Native Rust implementation using Tonic
   - Full async/await support
   - Strong type safety

### SDK Features

All SDKs provide:
- **Service Clients**: Pre-configured clients for PaymentService, RefundService, and DisputeService
- **Authentication**: Automatic metadata handling for connector authentication
- **Error Handling**: Structured error types and proper error propagation
- **Type Safety**: Generated types from protobuf definitions
- **Documentation**: Comprehensive API documentation and examples

For detailed installation and usage instructions, refer to the respective SDK documentation in their directories.

## Examples

The `examples` directory contains comprehensive example implementations for various programming languages and use cases:

### Language-Specific Examples

1. **CLI Tool**: `examples/example-cli`
   - Command-line interface for testing API operations
   - Interactive payment flow demonstrations
   - Webhook testing utilities

2. **Rust**: `examples/example-rs`
   - Complete Rust implementation using the native gRPC client
   - Demonstrates all service operations (Payment, Refund, Dispute)
   - Error handling and retry logic examples

3. **Node.js**: `examples/example-js`
   - JavaScript/TypeScript examples using @grpc/grpc-js
   - Express.js webhook handler implementation
   - Promise-based and async/await patterns

4. **Python**: `examples/example-py`
   - Python examples using grpcio
   - FastAPI webhook integration
   - Async and sync client implementations

5. **Haskell**: `examples/example-hs`
   - Pure Haskell HTTP client implementation
   - Functional programming patterns for payment processing

6. **Haskell gRPC**: `examples/example-hs-grpc`
   - Haskell gRPC client using proto-lens
   - Type-safe payment operations

### Interactive Examples

7. **TUI (Terminal User Interface)**: `examples/example-tui`
   - Interactive terminal application
   - Visual payment flow testing
   - Real-time status monitoring

8. **MCP (Model Context Protocol)**: `examples/example-mcp`
   - Integration with AI/ML models for payment decision making
   - Context-aware payment routing

### What Each Example Demonstrates

All examples include:
- **Authentication**: Proper metadata setup for different connectors
- **Payment Flows**: Authorization, capture, void, refund operations
- **Mandate Management**: Setting up recurring payment mandates
- **Dispute Handling**: Submitting evidence, accepting/defending disputes
- **Webhook Processing**: Handling incoming webhook events
- **Error Handling**: Proper error detection and recovery
- **Best Practices**: Idempotency, logging, monitoring

Each example directory contains detailed setup instructions and comprehensive documentation.

## API Contract Summary

This document provides a comprehensive reference for the Connector Service gRPC API, including:

### Key Features
- **Three-Service Architecture**: Separate services for payments, refunds, and disputes
- **Unified API Contract**: Consistent interfaces across all supported payment processors
- **Webhook Support**: Built-in webhook processing with source verification
- **Multi-Language SDKs**: Client libraries for Rust, Node.js, Python, and more
- **Comprehensive Examples**: Production-ready code samples for all major use cases

### Service Capabilities
- **Payment Processing**: Authorization, capture, void, status synchronization
- **Refund Management**: Full and partial refunds with status tracking
- **Dispute Handling**: Evidence submission, acceptance, and defense
- **Mandate Setup**: Recurring payment tokenization and management
- **Webhook Processing**: Real-time event handling with verification

### Integration Points
- gRPC API with protobuf message definitions
- HTTP webhook endpoints for real-time notifications
- Metadata-based authentication system
- Comprehensive error handling and status reporting

For the most up-to-date API definitions, refer to the protobuf files in `backend/grpc-api-types/proto/`.
