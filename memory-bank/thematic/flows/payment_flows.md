# Payment Flows

## Overview

The Connector Service supports various payment flows that represent different operations in the payment lifecycle. These flows are exposed through three main gRPC services (`PaymentService`, `RefundService`, and `DisputeService`) and are implemented internally using the `ConnectorIntegration` trait, allowing connectors to provide specific implementations for each flow.

## gRPC Service Architecture

The payment flows are organized into three main services:

1. **PaymentService**: Handles core payment operations (authorize, capture, void, refund, register, dispute, transform)
2. **RefundService**: Handles refund-specific operations (get status, transform webhooks)
3. **DisputeService**: Handles dispute-specific operations (submit evidence, get status, defend, accept, transform webhooks)

Each service method corresponds to one or more internal flow types, providing a clean separation of concerns while maintaining backward compatibility.

## Core Payment Flows

### 1. Authorization Flow

**gRPC Method**: `PaymentService.Authorize`
**Internal Type**: `Authorize`

**Purpose**: Authorize a payment without capturing funds. This reserves the funds on the customer's payment method but does not transfer them to the merchant.

**gRPC Flow**:
1. Client sends `PaymentServiceAuthorizeRequest` to `PaymentService.Authorize`
2. Service extracts connector information from metadata
3. Service converts gRPC request to internal `PaymentsAuthorizeData`
4. Service calls the appropriate connector integration
5. Connector sends the request to the payment processor
6. Payment processor validates the payment details and reserves funds
7. Connector receives the response and converts it to internal format
8. Service converts internal response to `PaymentServiceAuthorizeResponse`
9. Service returns gRPC response to the client

**Key Components**:
- **gRPC Request**: `PaymentServiceAuthorizeRequest`
- **gRPC Response**: `PaymentServiceAuthorizeResponse`
- **Internal Request Data**: `PaymentsAuthorizeData`
- **Internal Response Data**: `PaymentsResponseData`

**gRPC Example**:
```rust
let request = PaymentServiceAuthorizeRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("auth-ref-123".to_string())),
    }),
    amount: 1000,
    currency: Currency::Usd as i32,
    minor_amount: 1000,
    payment_method: PaymentMethod::Card as i32,
    // ... other fields
};

let response = payment_client.authorize(request).await?;
```

**Internal Connector Implementation**:
```rust
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 2. Capture Flow

**gRPC Method**: `PaymentService.Capture`
**Internal Type**: `Capture`

**Purpose**: Capture previously authorized funds. This transfers the reserved funds from the customer to the merchant.

**gRPC Flow**:
1. Client sends `PaymentServiceCaptureRequest` to `PaymentService.Capture`
2. Service extracts connector information from metadata
3. Service converts gRPC request to internal `PaymentsCaptureData`
4. Service calls the appropriate connector integration
5. Connector sends the request to the payment processor
6. Payment processor transfers the funds
7. Connector receives the response and converts it to internal format
8. Service converts internal response to `PaymentServiceCaptureResponse`
9. Service returns gRPC response to the client

**Key Components**:
- **gRPC Request**: `PaymentServiceCaptureRequest`
- **gRPC Response**: `PaymentServiceCaptureResponse`
- **Internal Request Data**: `PaymentsCaptureData`
- **Internal Response Data**: `PaymentsResponseData`

**gRPC Example**:
```rust
let request = PaymentServiceCaptureRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("capture-ref-123".to_string())),
    }),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    amount_to_capture: 1000, // Amount in minor currency units
    currency: Currency::Usd as i32,
    // ... other fields
};

let response = payment_client.capture(request).await?;
```

**Internal Connector Implementation**:
```rust
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 3. Void Flow

**gRPC Method**: `PaymentService.Void`
**Internal Type**: `Void`

**Purpose**: Cancel a previously authorized payment. This releases the reserved funds back to the customer.

**gRPC Flow**:
1. Client sends `PaymentServiceVoidRequest` to `PaymentService.Void`
2. Service extracts connector information from metadata
3. Service converts gRPC request to internal `PaymentVoidData`
4. Service calls the appropriate connector integration
5. Connector sends the request to the payment processor
6. Payment processor releases the reserved funds
7. Connector receives the response and converts it to internal format
8. Service converts internal response to `PaymentServiceVoidResponse`
9. Service returns gRPC response to the client

**Key Components**:
- **gRPC Request**: `PaymentServiceVoidRequest`
- **gRPC Response**: `PaymentServiceVoidResponse`
- **Internal Request Data**: `PaymentVoidData`
- **Internal Response Data**: `PaymentsResponseData`

**gRPC Example**:
```rust
let request = PaymentServiceVoidRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("void-ref-123".to_string())),
    }),
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    cancellation_reason: Some("Order cancelled by customer".to_string()),
    // ... other fields
};

let response = payment_client.void(request).await?;
```

**Internal Connector Implementation**:
```rust
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 4. Refund Flow

**gRPC Method**: `PaymentService.Refund`
**Internal Type**: `Refund`

**Purpose**: Refund previously captured funds. This returns funds from the merchant to the customer.

**gRPC Flow**:
1. Client sends `PaymentServiceRefundRequest` to `PaymentService.Refund`
2. Service extracts connector information from metadata
3. Service converts gRPC request to internal `RefundsData`
4. Service calls the appropriate connector integration
5. Connector sends the request to the payment processor
6. Payment processor transfers the funds back to the customer
7. Connector receives the response and converts it to internal format
8. Service converts internal response to `RefundResponse`
9. Service returns gRPC response to the client

**Key Components**:
- **gRPC Request**: `PaymentServiceRefundRequest`
- **gRPC Response**: `RefundResponse`
- **Internal Request Data**: `RefundsData`
- **Internal Response Data**: `RefundsResponseData`

**gRPC Example**:
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
    refund_amount: 500,
    minor_refund_amount: 500,
    reason: Some("Customer requested refund".to_string()),
    // ... other fields
};

let response = payment_client.refund(request).await?;
```

**Internal Connector Implementation**:
```rust
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 5. Payment Status Flow

**gRPC Method**: `PaymentService.Get`
**Internal Type**: `PSync`

**Purpose**: Check the status of a payment. This allows clients to verify the current state of a payment.

**gRPC Flow**:
1. Client sends `PaymentServiceGetRequest` to `PaymentService.Get`
2. Service extracts connector information from metadata
3. Service converts gRPC request to internal `PaymentsSyncData`
4. Service calls the appropriate connector integration
5. Connector sends the request to the payment processor
6. Payment processor returns the current status
7. Connector receives the response and converts it to internal format
8. Service converts internal response to `PaymentServiceGetResponse`
9. Service returns gRPC response to the client

**Key Components**:
- **gRPC Request**: `PaymentServiceGetRequest`
- **gRPC Response**: `PaymentServiceGetResponse`
- **Internal Request Data**: `PaymentsSyncData`
- **Internal Response Data**: `PaymentsResponseData`

**gRPC Example**:
```rust
let request = PaymentServiceGetRequest {
    transaction_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("8837968461238652".to_string())),
    }),
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("sync-ref-123".to_string())),
    }),
};

let response = payment_client.get(request).await?;
```

**Internal Connector Implementation**:
```rust
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 6. Refund Status Flow

**gRPC Method**: `RefundService.Get`
**Internal Type**: `RSync`

**Purpose**: Check the status of a refund. This allows clients to verify the current state of a refund.

**gRPC Flow**:
1. Client sends `RefundServiceGetRequest` to `RefundService.Get`
2. Service extracts connector information from metadata
3. Service converts gRPC request to internal `RefundSyncData`
4. Service calls the appropriate connector integration
5. Connector sends the request to the payment processor
6. Payment processor returns the current status
7. Connector receives the response and converts it to internal format
8. Service converts internal response to `RefundResponse`
9. Service returns gRPC response to the client

**Key Components**:
- **gRPC Request**: `RefundServiceGetRequest`
- **gRPC Response**: `RefundResponse`
- **Internal Request Data**: `RefundSyncData`
- **Internal Response Data**: `RefundsResponseData`

**gRPC Example**:
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

**Internal Connector Implementation**:
```rust
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 7. Mandate Setup Flow

**gRPC Method**: `PaymentService.Register`
**Internal Type**: `SetupMandate`

**Purpose**: Set up a payment mandate for recurring payments. This allows merchants to charge customers on a recurring basis.

**gRPC Flow**:
1. Client sends `PaymentServiceRegisterRequest` to `PaymentService.Register`
2. Service extracts connector information from metadata
3. Service converts gRPC request to internal `SetupMandateRequestData`
4. Service calls the appropriate connector integration
5. Connector sends the request to the payment processor
6. Payment processor sets up the mandate
7. Connector receives the response and converts it to internal format
8. Service converts internal response to `PaymentServiceRegisterResponse`
9. Service returns gRPC response to the client

**Key Components**:
- **gRPC Request**: `PaymentServiceRegisterRequest`
- **gRPC Response**: `PaymentServiceRegisterResponse`
- **Internal Request Data**: `SetupMandateRequestData`
- **Internal Response Data**: `PaymentsResponseData`

**gRPC Example**:
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
    setup_future_usage: Some(FutureUsage::OffSession as i32),
    customer_acceptance: Some(CustomerAcceptance {
        acceptance_type: AcceptanceType::Online as i32,
        accepted_at: 1234567890, // Unix timestamp
        // ... other fields
    }),
    // ... other fields
};

let response = payment_client.register(request).await?;
```

**Internal Connector Implementation**:
```rust
impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 8. Dispute Management Flows

#### 8a. Create Dispute Flow

**gRPC Method**: `PaymentService.Dispute`
**⚠️ Implementation Status**: Currently returns placeholder response; full connector integration pending.

**Purpose**: Create a new dispute for a payment transaction.

**gRPC Example**:
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

let response = payment_client.dispute(request).await?;
```

#### 8b. Accept Dispute Flow

**gRPC Method**: `DisputeService.Accept`
**Internal Type**: `Accept`

**Purpose**: Accept a dispute raised by a customer. This acknowledges the dispute and typically results in a refund.

**gRPC Flow**:
1. Client sends `AcceptDisputeRequest` to `DisputeService.Accept`
2. Service extracts connector information from metadata
3. Service converts gRPC request to internal `AcceptDisputeData`
4. Service calls the appropriate connector integration
5. Connector sends the request to the payment processor
6. Payment processor processes the dispute acceptance
7. Connector receives the response and converts it to internal format
8. Service converts internal response to `AcceptDisputeResponse`
9. Service returns gRPC response to the client

**Key Components**:
- **gRPC Request**: `AcceptDisputeRequest`
- **gRPC Response**: `AcceptDisputeResponse`
- **Internal Request Data**: `AcceptDisputeData`
- **Internal Response Data**: `DisputeResponseData`

**gRPC Example**:
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

**Internal Connector Implementation**:
```rust
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Adyen
{
    // Implementation details
}
```

#### 8c. Defend Dispute Flow

**gRPC Method**: `DisputeService.Defend`
**Internal Type**: `Defend`

**Purpose**: Defend a dispute with a reason code, typically when the merchant believes the dispute is invalid.

**gRPC Example**:
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

#### 8d. Submit Evidence Flow

**gRPC Method**: `DisputeService.SubmitEvidence`
**Internal Type**: `SubmitEvidence`

**Purpose**: Submit evidence for a dispute to support the merchant's case.

**gRPC Example**:
```rust
let request = DisputeServiceSubmitEvidenceRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("evidence-ref-123".to_string())),
    }),
    dispute_id: "dispute_123456789".to_string(),
    evidence_documents: vec![
        EvidenceDocument {
            evidence_type: EvidenceType::Receipt as i32,
            file_content: Some(receipt_pdf_bytes),
            file_mime_type: Some("application/pdf".to_string()),
            text_content: Some("Receipt for transaction #12345".to_string()),
            // ... other fields
        },
    ],
    // ... other fields
};

let response = dispute_client.submit_evidence(request).await?;
```

#### 8e. Get Dispute Status Flow

**gRPC Method**: `DisputeService.Get`
**⚠️ Implementation Status**: Currently returns placeholder response; no actual flow type implementation.

**Purpose**: Check the status of a dispute and retrieve dispute information.

**gRPC Example**:
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

### 9. Webhook Processing Flows

#### 9a. Payment Webhook Flow

**gRPC Method**: `PaymentService.Transform`
**Implementation**: Uses `IncomingWebhook` trait methods rather than a specific flow type

**Purpose**: Process incoming webhooks from payment processors for payment-related events.

**gRPC Example**:
```rust
let request = PaymentServiceTransformRequest {
    request_ref_id: Some(Identifier {
        id_type: Some(identifier::IdType::Id("webhook-ref-123".to_string())),
    }),
    request_details: Some(RequestDetails {
        method: HttpMethod::Post as i32,
        uri: Some("/webhook/payment".to_string()),
        headers: webhook_headers,
        body: webhook_body_bytes,
        query_params: None,
    }),
    webhook_secrets: Some(WebhookSecrets {
        secret: "your-webhook-secret".to_string(),
        additional_secret: None,
    }),
};

let response = payment_client.transform(request).await?;
```

#### 9b. Refund Webhook Flow

**gRPC Method**: `RefundService.Transform`
**Implementation**: Uses `IncomingWebhook` trait methods for refund-specific processing

**Purpose**: Process incoming webhooks from payment processors for refund-related events.

#### 9c. Dispute Webhook Flow

**gRPC Method**: `DisputeService.Transform`
**Implementation**: Uses `IncomingWebhook` trait methods for dispute-specific processing

**Purpose**: Process incoming webhooks from payment processors for dispute-related events.

### 10. Create Order Flow

**Internal Type**: `CreateOrder`

**Purpose**: Create an order before processing a payment. This is used by some payment processors that require an order to be created first. This flow is typically used internally and may not have a direct gRPC endpoint.

**Key Components**:
- **Internal Request Data**: `PaymentCreateOrderData`
- **Internal Response Data**: `PaymentCreateOrderResponse`

**Internal Connector Implementation**:
```rust
impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
    for Adyen
{
    // Implementation details
}
```

## Flow Data Structures

### Common Flow Data

Each flow uses common data structures to represent the request and response data:

1. **RouterDataV2**: A generic struct that encapsulates all the data needed for a payment operation:
   - Flow-specific type parameters
   - Common resource data
   - Connector authentication details
   - Request data
   - Response data

2. **PaymentFlowData**: Common data for payment operations:
   - Merchant ID
   - Payment ID
   - Attempt ID
   - Status
   - Payment method
   - Address
   - Authentication type
   - Connector request reference ID
   - Other metadata

3. **RefundFlowData**: Common data for refund operations:
   - Status
   - Refund ID
   - Connector configuration

4. **DisputeFlowData**: Common data for dispute operations:
   - Dispute ID
   - Connector configuration
   - Connector dispute ID

### Request Data Structures

1. **PaymentsAuthorizeData**: Data for authorization requests:
   - Payment method data
   - Amount
   - Currency
   - Customer information
   - Billing/shipping address
   - Other payment details

2. **PaymentsCaptureData**: Data for capture requests:
   - Amount to capture
   - Currency
   - Connector transaction ID
   - Multiple capture data (if applicable)

3. **PaymentVoidData**: Data for void requests:
   - Connector transaction ID
   - Cancellation reason

4. **RefundsData**: Data for refund requests:
   - Refund ID
   - Connector transaction ID
   - Refund amount
   - Currency
   - Reason

5. **PaymentsSyncData**: Data for payment sync requests:
   - Connector transaction ID
   - Encoded data (if applicable)
   - Capture method
   - Sync type

6. **RefundSyncData**: Data for refund sync requests:
   - Connector transaction ID
   - Connector refund ID
   - Reason

7. **SetupMandateRequestData**: Data for mandate setup requests:
   - Currency
   - Payment method data
   - Customer information
   - Mandate details

8. **AcceptDisputeData**: Data for dispute acceptance requests:
   - (Empty structure, as no additional data is needed)

9. **PaymentCreateOrderData**: Data for order creation requests:
   - Amount
   - Currency

### Response Data Structures

1. **PaymentsResponseData**: Data for payment operation responses:
   - Resource ID
   - Redirection data (if applicable)
   - Connector metadata
   - Network transaction ID
   - Connector response reference ID
   - Incremental authorization allowed
   - Mandate reference

2. **RefundsResponseData**: Data for refund operation responses:
   - Connector refund ID
   - Refund status
   - Connector metadata

3. **DisputeResponseData**: Data for dispute operation responses:
   - Connector dispute ID
   - Dispute status

4. **PaymentCreateOrderResponse**: Data for order creation responses:
   - Order ID

## Flow Status Handling

Each flow has its own set of status values that represent the state of the operation:

### 1. PaymentStatus (formerly AttemptStatus)

Status values for payment operations:

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

### 2. MandateStatus

Status values for mandate setup operations:

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

### 3. RefundStatus

Status values for refund operations:

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

### 4. DisputeStatus

Status values for dispute operations:

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

### 5. DisputeStage

Stage values for dispute operations:

```protobuf
enum DisputeStage {
  DISPUTE_STAGE_UNSPECIFIED = 0; // Default value
  PRE_DISPUTE = 1;
  ACTIVE_DISPUTE = 2;
  PRE_ARBITRATION = 3;
}
```

## Flow Implementation Pattern

Each connector implements the `ConnectorIntegrationV2` trait for each supported flow. The trait provides methods for:

1. **get_headers**: Get the headers for the request
2. **get_content_type**: Get the content type for the request
3. **get_url**: Get the URL for the request
4. **get_request_body**: Get the request body
5. **build_request**: Build the complete request
6. **handle_response**: Process the response
7. **get_error_response**: Handle error responses

Example implementation pattern:

```rust
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for SomeConnector
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Implementation
    }

    fn get_content_type(&self) -> &'static str {
        // Implementation
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Implementation
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // Implementation
    }

    fn build_request(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        // Implementation
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // Implementation
    }

    fn get_error_response(
        &self,
        res: Response,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Implementation
    }
}
```

## Flow Execution

The flow execution process follows these steps:

### gRPC Service Layer Flow

1. **Request Reception**: Client sends a gRPC request to one of the three services (`PaymentService`, `RefundService`, or `DisputeService`)
2. **Authentication Extraction**: Server extracts connector authentication details from gRPC metadata headers (`x-connector`, `x-auth`, `x-api-key`, etc.)
3. **Request Conversion**: Server converts the gRPC request message to internal domain types
4. **Connector Selection**: Server identifies the appropriate connector based on metadata
5. **Flow Type Mapping**: Server maps the gRPC method to the corresponding internal flow type
6. **Router Data Creation**: Server creates the appropriate `RouterDataV2` instance with flow-specific type parameters
7. **Connector Execution**: Server calls the `execute_connector_processing_step` function
8. **Response Processing**: Connector integration processes the request and response
9. **Response Conversion**: Server converts internal response to gRPC response message
10. **Response Return**: Server returns the gRPC response to the client

### Internal Connector Flow

```rust
// 1. Extract connector integration
let connector_integration: BoxedConnectorIntegrationV2<
    '_,
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData,
    PaymentsResponseData,
> = connector_data.connector.get_connector_integration_v2();

// 2. Create router data with flow-specific types
let router_data = RouterDataV2::<
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData,
    PaymentsResponseData,
> {
    flow: std::marker::PhantomData,
    resource_common_data: payment_flow_data,
    connector_auth_type: connector_auth_details,
    request: payment_authorize_data,
    response: Err(ErrorResponse::default()),
};

// 3. Execute connector processing
let response = external_services::service::execute_connector_processing_step(
    &self.config.proxy,
    connector_integration,
    router_data,
).await?;

// 4. Convert internal response to gRPC response
let grpc_response = PaymentServiceAuthorizeResponse {
    transaction_id: Some(convert_identifier(response.response?.resource_id)),
    status: convert_payment_status(response.resource_common_data.status),
    error_code: response.response?.error_code,
    error_message: response.response?.error_message,
    redirection_data: response.response?.redirection_data.map(convert_redirect_form),
    network_txn_id: response.response?.network_txn_id,
    response_ref_id: response.response?.connector_response_reference_id.map(convert_identifier),
    incremental_authorization_allowed: response.response?.incremental_authorization_allowed,
};
```

### Service Method to Flow Type Mapping

| gRPC Service Method | Internal Flow Type | Purpose | Implementation Status |
|--------------------|--------------------|---------|--------------------|
| `PaymentService.Authorize` | `Authorize` | Payment authorization | ✅ Fully implemented |
| `PaymentService.Get` | `PSync` | Payment status check | ✅ Fully implemented |
| `PaymentService.Void` | `Void` | Payment cancellation | ✅ Fully implemented |
| `PaymentService.Capture` | `Capture` | Payment capture | ✅ Fully implemented |
| `PaymentService.Refund` | `Refund` | Payment refund | ✅ Fully implemented |
| `PaymentService.Register` | `SetupMandate` | Mandate setup | ✅ Fully implemented |
| `PaymentService.Dispute` | *Placeholder* | Dispute creation | ⚠️ Returns empty response |
| `PaymentService.Transform` | *Trait methods* | Payment webhook processing | ✅ Fully implemented |
| `RefundService.Get` | `RSync` | Refund status check | ✅ Fully implemented |
| `RefundService.Transform` | *Trait methods* | Refund webhook processing | ✅ Fully implemented |
| `DisputeService.SubmitEvidence` | `SubmitEvidence` | Evidence submission | ✅ Fully implemented |
| `DisputeService.Get` | *Placeholder* | Dispute status check | ⚠️ Returns empty response |
| `DisputeService.Defend` | `DefendDispute` | Dispute defense | ✅ Fully implemented |
| `DisputeService.Accept` | `Accept` | Dispute acceptance | ✅ Fully implemented |
| `DisputeService.Transform` | *Trait methods* | Dispute webhook processing | ✅ Fully implemented |

## Flow Relationships

The payment flows are related in the following ways:

### 1. Payment Lifecycle Flows

**Authorization → Capture**: 
- `PaymentService.Authorize` reserves funds
- `PaymentService.Capture` transfers them to the merchant
- A payment can be authorized and then captured later (two-step payment)

**Authorization → Void**: 
- `PaymentService.Authorize` reserves funds
- `PaymentService.Void` cancels the authorization
- A payment can be authorized and then voided if the merchant decides not to proceed

**Capture → Refund**: 
- `PaymentService.Capture` transfers funds to the merchant
- `PaymentService.Refund` returns them to the customer
- A payment must be captured before it can be refunded

### 2. Status Check Flows

**Payment Status Monitoring**:
- `PaymentService.Get` checks the current status of any payment operation
- Can be called at any time to verify payment state
- Returns comprehensive payment information including timestamps and metadata

**Refund Status Monitoring**:
- `RefundService.Get` checks the current status of refund operations
- Can be called to track refund processing progress
- Returns refund-specific status and metadata

### 3. Mandate and Recurring Payments

**Mandate Setup → Future Authorizations**:
- `PaymentService.Register` establishes a recurring payment agreement
- Sets up payment method tokenization for future use
- Subsequent authorizations can reference the mandate for off-session payments

### 4. Dispute Management Flows

**Dispute Lifecycle**:
- `PaymentService.Dispute` or external dispute notification initiates dispute
- `DisputeService.Get` retrieves current dispute status and information
- `DisputeService.SubmitEvidence` provides supporting documentation
- `DisputeService.Defend` contests the dispute with reason codes
- `DisputeService.Accept` acknowledges the dispute (typically results in refund)

### 5. Webhook Processing Integration

**Real-time Event Handling**:
- `PaymentService.Transform` processes payment-related webhook events
- `RefundService.Transform` processes refund-related webhook events  
- `DisputeService.Transform` processes dispute-related webhook events
- These flows provide real-time status updates and event notifications

### 6. Internal Order Management

**Order Creation → Authorization**:
- Some payment processors require `CreateOrder` flow before authorization
- This is typically handled internally and not exposed via gRPC
- The order creation flow prepares the payment context for authorization

### Flow Sequence Examples

#### Two-Step Payment Flow
```
1. PaymentService.Authorize (reserve funds)
2. PaymentService.Get (check authorization status)
3. PaymentService.Capture (transfer funds)
4. PaymentService.Get (verify capture completion)
```

#### Refund Flow
```
1. PaymentService.Refund (initiate refund)
2. RefundService.Get (check refund status)
3. RefundService.Transform (process webhook updates)
```

#### Dispute Resolution Flow
```
1. DisputeService.Get (check dispute details)
2. DisputeService.SubmitEvidence (provide supporting docs)
3. DisputeService.Defend (contest with reason code)
4. DisputeService.Get (monitor resolution status)
```

## Best Practices

### 1. Error Handling

Implement robust error handling for each flow, considering the various error cases that can occur:

```rust
match response.status {
    PaymentStatus::Charged => {
        // Payment successful - proceed with business logic
        process_successful_payment(&response).await?;
    },
    PaymentStatus::AuthorizationFailed | PaymentStatus::Failure => {
        // Payment failed - handle gracefully
        handle_payment_failure(&response).await?;
    },
    PaymentStatus::AuthenticationPending => {
        // 3DS authentication required - redirect customer
        redirect_for_authentication(&response.redirection_data).await?;
    },
    _ => {
        // Other statuses - log and monitor
        log_payment_status(&response);
    }
}
```

### 2. Idempotency

Ensure that operations are idempotent to prevent duplicate transactions:

```rust
// Always use unique reference IDs
let request_ref_id = Identifier {
    id_type: Some(identifier::IdType::Id(Uuid::new_v4().to_string())),
};

// Store reference IDs to prevent duplicate operations
if payment_already_processed(&request_ref_id) {
    return Ok(get_existing_payment_response(&request_ref_id));
}
```

### 3. Authentication and Metadata

Provide all required metadata for connector authentication:

```rust
// Set authentication metadata for every request
let mut metadata = MetadataMap::new();
metadata.insert("x-connector", connector_name.parse().unwrap());
metadata.insert("x-auth", "header-key".parse().unwrap());
metadata.insert("x-api-key", api_key.parse().unwrap());

// Add optional metadata if required
if let Some(secret) = api_secret {
    metadata.insert("x-api-secret", secret.parse().unwrap());
}

let mut request = Request::new(payment_request);
*request.metadata_mut() = metadata;
```

### 4. Request Validation

Validate request data before sending to the API:

```rust
// Validate required fields
if request.request_ref_id.is_none() {
    return Err("Request reference ID is required");
}

// Validate amounts
if request.amount <= 0 || request.minor_amount <= 0 {
    return Err("Amount must be positive");
}

// Validate currency
if request.currency == Currency::CurrencyUnspecified as i32 {
    return Err("Currency must be specified");
}

// Validate connector-specific requirements
validate_connector_requirements(&request, &connector_name)?;
```

### 5. Webhook Security

Always verify webhook authenticity and process them safely:

```rust
// Verify webhook source
let webhook_request = PaymentServiceTransformRequest {
    webhook_secrets: Some(WebhookSecrets {
        secret: webhook_secret,
        additional_secret: webhook_additional_secret,
    }),
    request_details: Some(webhook_details),
    // ... other fields
};

let transform_response = client.transform(webhook_request).await?;

if !transform_response.source_verified {
    return Err("Webhook source verification failed");
}

// Process verified webhook content
match transform_response.event_type {
    WebhookEventType::WebhookPayment => {
        handle_payment_webhook(transform_response.content).await?;
    },
    WebhookEventType::WebhookRefund => {
        handle_refund_webhook(transform_response.content).await?;
    },
    WebhookEventType::WebhookDispute => {
        handle_dispute_webhook(transform_response.content).await?;
    },
    _ => {
        log_unknown_webhook_event(transform_response.event_type);
    }
}
```

### 6. Status Monitoring

Implement proper status monitoring and polling:

```rust
// Poll payment status with exponential backoff
let mut attempts = 0;
let max_attempts = 5;
let mut delay = Duration::from_secs(1);

while attempts < max_attempts {
    let status_response = payment_client.get(PaymentServiceGetRequest {
        transaction_id: Some(transaction_id.clone()),
        request_ref_id: Some(generate_sync_ref_id()),
    }).await?;

    match status_response.status {
        PaymentStatus::Charged | PaymentStatus::AuthorizationFailed | PaymentStatus::Failure => {
            // Terminal status reached
            return Ok(status_response);
        },
        _ => {
            // Still processing - wait and retry
            tokio::time::sleep(delay).await;
            delay *= 2; // Exponential backoff
            attempts += 1;
        }
    }
}
```

### 7. Service Client Management

Use appropriate service clients for different operations:

```rust
// Create service-specific clients
let payment_client = PaymentServiceClient::connect(grpc_endpoint).await?;
let refund_client = RefundServiceClient::connect(grpc_endpoint).await?;
let dispute_client = DisputeServiceClient::connect(grpc_endpoint).await?;

// Use the appropriate client for each operation
match operation_type {
    OperationType::Payment => {
        // Use payment_client for authorize, capture, void, etc.
        payment_client.authorize(request).await?
    },
    OperationType::Refund => {
        // Use refund_client for refund status checks
        refund_client.get(request).await?
    },
    OperationType::Dispute => {
        // Use dispute_client for evidence submission, etc.
        dispute_client.submit_evidence(request).await?
    },
}
```

### 8. Logging and Monitoring

Implement comprehensive logging for debugging and auditing:

```rust
use tracing::{info, warn, error, span, Level};

// Log all payment operations
let span = span!(Level::INFO, "payment_operation", 
    operation_type = %operation_type,
    connector = %connector_name,
    reference_id = %request_ref_id
);

let _enter = span.enter();

info!("Starting payment operation");

match client.authorize(request).await {
    Ok(response) => {
        info!("Payment operation completed successfully", 
            status = ?response.status,
            transaction_id = ?response.transaction_id
        );
    },
    Err(error) => {
        error!("Payment operation failed", 
            error = %error,
            error_code = ?error.code()
        );
    }
}
```

### 9. Testing and Quality Assurance

Test each flow thoroughly with different scenarios:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_successful_authorization() {
        // Test successful payment authorization
        let response = test_payment_authorization().await.unwrap();
        assert_eq!(response.status, PaymentStatus::Authorized as i32);
    }

    #[tokio::test]
    async fn test_failed_authorization() {
        // Test failed payment authorization
        let response = test_failed_payment().await.unwrap();
        assert_eq!(response.status, PaymentStatus::AuthorizationFailed as i32);
        assert!(response.error_code.is_some());
    }

    #[tokio::test]
    async fn test_webhook_verification() {
        // Test webhook verification and processing
        let verified_webhook = test_webhook_processing().await.unwrap();
        assert!(verified_webhook.source_verified);
    }
}
```

### 10. Security and Compliance

Handle sensitive payment data securely:

- Never log sensitive payment information (card numbers, CVV, etc.)
- Use secure connections (TLS) for all API communications
- Implement proper access controls and authentication
- Follow PCI DSS guidelines for payment data handling
- Regularly rotate API keys and secrets
- Implement rate limiting and abuse detection
- Use structured logging that can be easily monitored and alerted on

### 11. Performance Optimization

Optimize for high throughput and low latency:

- Use connection pooling for gRPC clients
- Implement proper timeout and retry strategies
- Cache connector configurations and authentication details
- Use batch operations where supported by connectors
- Monitor and optimize database queries
- Implement circuit breakers for external service calls
