# Payment Flows

## Overview

The Connector Service supports various payment flows that represent different operations in the payment lifecycle. Each flow is implemented as a separate type parameter in the `ConnectorIntegration` trait, allowing connectors to provide specific implementations for each flow.

## Core Payment Flows

### 1. Authorization Flow

**Type**: `Authorize`

**Purpose**: Authorize a payment without capturing funds. This reserves the funds on the customer's payment method but does not transfer them to the merchant.

**Process**:
1. Client sends an authorization request with payment details
2. Service converts the request to the connector's format
3. Connector sends the request to the payment processor
4. Payment processor validates the payment details and reserves funds
5. Connector receives the response and converts it to the service's format
6. Service returns the response to the client

**Key Components**:
- `PaymentsAuthorizeData`: Request data for authorization
- `PaymentsResponseData`: Response data from authorization

**Example**:
```rust
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 2. Capture Flow

**Type**: `Capture`

**Purpose**: Capture previously authorized funds. This transfers the reserved funds from the customer to the merchant.

**Process**:
1. Client sends a capture request with the transaction ID and amount
2. Service converts the request to the connector's format
3. Connector sends the request to the payment processor
4. Payment processor transfers the funds
5. Connector receives the response and converts it to the service's format
6. Service returns the response to the client

**Key Components**:
- `PaymentsCaptureData`: Request data for capture
- `PaymentsResponseData`: Response data from capture

**Example**:
```rust
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 3. Void Flow

**Type**: `Void`

**Purpose**: Cancel a previously authorized payment. This releases the reserved funds back to the customer.

**Process**:
1. Client sends a void request with the transaction ID
2. Service converts the request to the connector's format
3. Connector sends the request to the payment processor
4. Payment processor releases the reserved funds
5. Connector receives the response and converts it to the service's format
6. Service returns the response to the client

**Key Components**:
- `PaymentVoidData`: Request data for void
- `PaymentsResponseData`: Response data from void

**Example**:
```rust
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 4. Refund Flow

**Type**: `Refund`

**Purpose**: Refund previously captured funds. This returns funds from the merchant to the customer.

**Process**:
1. Client sends a refund request with the transaction ID and amount
2. Service converts the request to the connector's format
3. Connector sends the request to the payment processor
4. Payment processor transfers the funds back to the customer
5. Connector receives the response and converts it to the service's format
6. Service returns the response to the client

**Key Components**:
- `RefundsData`: Request data for refund
- `RefundsResponseData`: Response data from refund

**Example**:
```rust
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 5. Payment Sync Flow

**Type**: `PSync`

**Purpose**: Check the status of a payment. This allows clients to verify the current state of a payment.

**Process**:
1. Client sends a sync request with the transaction ID
2. Service converts the request to the connector's format
3. Connector sends the request to the payment processor
4. Payment processor returns the current status
5. Connector receives the response and converts it to the service's format
6. Service returns the response to the client

**Key Components**:
- `PaymentsSyncData`: Request data for payment sync
- `PaymentsResponseData`: Response data from payment sync

**Example**:
```rust
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 6. Refund Sync Flow

**Type**: `RSync`

**Purpose**: Check the status of a refund. This allows clients to verify the current state of a refund.

**Process**:
1. Client sends a sync request with the refund ID
2. Service converts the request to the connector's format
3. Connector sends the request to the payment processor
4. Payment processor returns the current status
5. Connector receives the response and converts it to the service's format
6. Service returns the response to the client

**Key Components**:
- `RefundSyncData`: Request data for refund sync
- `RefundsResponseData`: Response data from refund sync

**Example**:
```rust
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 7. Setup Mandate Flow

**Type**: `SetupMandate`

**Purpose**: Set up a payment mandate for recurring payments. This allows merchants to charge customers on a recurring basis.

**Process**:
1. Client sends a mandate setup request with payment details
2. Service converts the request to the connector's format
3. Connector sends the request to the payment processor
4. Payment processor sets up the mandate
5. Connector receives the response and converts it to the service's format
6. Service returns the response to the client

**Key Components**:
- `SetupMandateRequestData`: Request data for mandate setup
- `PaymentsResponseData`: Response data from mandate setup

**Example**:
```rust
impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>
    for Adyen
{
    // Implementation details
}
```

### 8. Accept Dispute Flow

**Type**: `Accept`

**Purpose**: Accept a dispute raised by a customer. This acknowledges the dispute and typically results in a refund.

**Process**:
1. Client sends a dispute acceptance request with the dispute ID
2. Service converts the request to the connector's format
3. Connector sends the request to the payment processor
4. Payment processor processes the dispute acceptance
5. Connector receives the response and converts it to the service's format
6. Service returns the response to the client

**Key Components**:
- `AcceptDisputeData`: Request data for dispute acceptance
- `DisputeResponseData`: Response data from dispute acceptance

**Example**:
```rust
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Adyen
{
    // Implementation details
}
```

### 9. Create Order Flow

**Type**: `CreateOrder`

**Purpose**: Create an order before processing a payment. This is used by some payment processors that require an order to be created first.

**Process**:
1. Client sends an order creation request with order details
2. Service converts the request to the connector's format
3. Connector sends the request to the payment processor
4. Payment processor creates the order
5. Connector receives the response and converts it to the service's format
6. Service returns the response to the client

**Key Components**:
- `PaymentCreateOrderData`: Request data for order creation
- `PaymentCreateOrderResponse`: Response data from order creation

**Example**:
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

1. **AttemptStatus**: Status values for payment operations:
   - Started
   - AuthenticationFailed
   - RouterDeclined
   - AuthenticationPending
   - AuthenticationSuccessful
   - Authorized
   - AuthorizationFailed
   - Charged
   - Authorizing
   - CodInitiated
   - Voided
   - VoidInitiated
   - CaptureInitiated
   - CaptureFailed
   - VoidFailed
   - AutoRefunded
   - PartialCharged
   - PartialChargedAndChargeable
   - Unresolved
   - Pending
   - Failure
   - PaymentMethodAwaited
   - ConfirmationAwaited
   - DeviceDataCollectionPending

2. **RefundStatus**: Status values for refund operations:
   - RefundFailure
   - RefundManualReview
   - RefundPending
   - RefundSuccess
   - RefundTransactionFailure

3. **DisputeStatus**: Status values for dispute operations:
   - DisputeOpened
   - DisputeExpired
   - DisputeAccepted
   - DisputeCancelled
   - DisputeChallenged
   - DisputeWon
   - DisputeLost

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

## Connector Authentication Resolution

Connector credentials are resolved entirely from gRPC metadata headers — the request payload carries only business data.

### Auth Paths (in priority order)

1. **Typed header** (`x-connector-auth`): A JSON-serialized `ConnectorAuth` proto message containing connector-specific credentials. Format uses PascalCase enum variant names (matching prost serde):
   ```
   x-connector-auth: {"auth_type":{"Stripe":{"api_key":"sk_test_..."}}}
   x-connector-auth: {"auth_type":{"Adyen":{"api_key":"...","merchant_account":"...","review_key":"..."}}}
   ```

2. **Legacy headers** (fallback): Generic auth spread across multiple headers:
   ```
   x-auth: header-key|body-key|signature-key|multi-auth-key|no-key
   x-api-key: <key>
   x-key1: <key>
   x-key2: <key>
   x-api-secret: <secret>
   ```

### Resolution Flow

```
x-connector-auth present?
├─ YES → parse JSON → ForeignTryFrom<ConnectorAuth> → ConnectorSpecificAuth
└─ NO  → read x-auth + x-api-key + ... → ConnectorAuthType → ForeignTryFrom<(&AuthType, &Connector)> → ConnectorSpecificAuth
```

Both paths produce `ConnectorSpecificAuth` (e.g., `Stripe { api_key }`, `Adyen { api_key, merchant_account, review_key }`), which connector transformers consume via `TryFrom<&ConnectorSpecificAuth>`.

### Key files
- `backend/grpc-server/src/utils.rs`: `resolve_connector_auth()`, `extract_connector_auth_from_header()`
- `backend/common_utils/src/consts.rs`: `X_CONNECTOR_AUTH` header constant
- `backend/domain_types/src/router_data.rs`: `ConnectorSpecificAuth` enum, `ForeignTryFrom` impls

## Flow Execution

The flow execution process follows these steps:

1. Client sends a request to the gRPC server with auth in metadata headers
2. Server resolves connector auth from headers (`resolve_connector_auth`)
3. Server identifies the connector and flow type
4. Server creates the appropriate `RouterDataV2` instance with resolved `ConnectorSpecificAuth`
5. Server calls the `execute_connector_processing_step` function with the connector integration and router data
6. Connector integration processes the request and sends it to the payment processor
7. Connector integration processes the response and returns it to the server
8. Server converts the response to the gRPC response format and returns it to the client

Example flow execution:

```rust
let connector_integration: BoxedConnectorIntegrationV2<
    '_,
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData,
    PaymentsResponseData,
> = connector_data.connector.get_connector_integration_v2();

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

let response = external_services::service::execute_connector_processing_step(
    &self.config.proxy,
    connector_integration,
    router_data,
).await?;
```

## Flow Relationships

The payment flows are related in the following ways:

1. **Authorization and Capture**: Authorization reserves funds, and Capture transfers them to the merchant. A payment can be authorized and then captured later.

2. **Authorization and Void**: Authorization reserves funds, and Void cancels the authorization. A payment can be authorized and then voided if the merchant decides not to proceed.

3. **Capture and Refund**: Capture transfers funds to the merchant, and Refund returns them to the customer. A payment must be captured before it can be refunded.

4. **Payment Sync and Refund Sync**: These flows check the status of payments and refunds, respectively. They can be used at any time to verify the current state.

5. **Create Order and Authorization**: Some payment processors require an order to be created before authorization. In these cases, the Create Order flow is executed first, followed by the Authorization flow.

6. **Setup Mandate and Authorization**: Setup Mandate establishes a recurring payment agreement, which can then be used for future authorizations without requiring the customer to re-enter payment details.

## Best Practices

1. **Error Handling**: Implement robust error handling for each flow, considering the various error cases that can occur.

2. **Idempotency**: Ensure that operations are idempotent to prevent duplicate transactions.

3. **Validation**: Validate request data before sending it to the payment processor to catch errors early.

4. **Logging**: Log important events and errors for debugging and auditing purposes.

5. **Security**: Handle sensitive payment data securely, following PCI DSS guidelines.

6. **Testing**: Test each flow thoroughly with different scenarios and edge cases.

7. **Documentation**: Document the implementation details and usage examples for each flow.
