# Connector Integration Coding Guidelines

This document outlines the coding guidelines and best practices for integrating new connectors into the connector-service.

## 1. Directory Structure

Each new connector, named `my_connector`, should follow this directory structure:

```
backend/connector-integration/src/connectors/
├── my_connector.rs
└── my_connector/
    ├── transformers.rs
    └── test.rs
```

- **`my_connector.rs`**: This is the main file for the connector. It defines the connector's struct, implements the required traits, and handles the high-level logic for each payment flow.
- **`my_connector/transformers.rs`**: This file contains the data transformation logic. It defines the structs that represent the connector's API requests and responses, and it implements the `TryFrom` trait to convert between the router's data structures and the connector's.
- **`my_connector/test.rs`**: This file contains the unit tests for the connector.

## 2. `my_connector.rs`

### 2.1. Connector Struct

Define a struct for your connector. If the connector requires an amount converter, include it in the struct.

```rust
#[derive(Clone)]
pub struct MyConnector {
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl MyConnector {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::MinorUnitForConnector,
        }
    }
}
```

### 2.2. Trait Implementations

Your connector must implement several traits from `connector_types`. At a minimum, you should implement `ConnectorServiceTrait`. Then, for each payment flow your connector supports, you must implement the corresponding trait (e.g., `PaymentAuthorizeV2`, `PaymentSyncV2`, `RefundV2`, etc.).

```rust
impl connector_types::ConnectorServiceTrait for MyConnector {}
impl connector_types::PaymentAuthorizeV2 for MyConnector {}
impl connector_types::PaymentSyncV2 for MyConnector {}
// ... other trait implementations
```

### 2.3. `ConnectorCommon` Implementation

Implement the `ConnectorCommon` trait to provide essential information about your connector.

```rust
impl ConnectorCommon for MyConnector {
    fn id(&self) -> &'static str {
        "my_connector"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        // ...
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // ...
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        // ...
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // ...
    }
}
```

### 2.4. `ConnectorIntegrationV2` Implementation

For each payment flow, implement the `ConnectorIntegrationV2` trait. This is where you'll define the HTTP method, headers, URL, and request body for the connector's API calls. You'll also handle the response from the connector.

```rust
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for MyConnector
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // ...
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        // ...
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // ...
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // ...
    }
}
```

### 2.5. Webhook Handling

If your connector supports webhooks, implement the `IncomingWebhook` trait.

```rust
impl connector_types::IncomingWebhook for MyConnector {
    fn get_event_type(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<errors::ConnectorError>> {
        // ...
    }

    fn process_payment_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        // ...
    }

    // ... other webhook processing functions
}
```

### 2.6. Connector Specifications and Validation

Implement the `ConnectorSpecifications` and `ConnectorValidation` traits to provide metadata and validation logic for your connector.

```rust
impl ConnectorSpecifications for MyConnector {
    // ...
}

impl ConnectorValidation for MyConnector {
    // ...
}
```

## 3. `my_connector/transformers.rs`

### 3.1. Connector-Specific Structs

Define structs that represent the request and response bodies of the connector's API. Use `serde` to serialize and deserialize these structs to and from JSON.

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct MyConnectorPaymentRequest {
    // ... fields for the request
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MyConnectorPaymentResponse {
    // ... fields for the response
}
```

### 3.2. `TryFrom` Implementations

Implement the `TryFrom` trait to convert between the router's `RouterDataV2` struct and your connector-specific structs.

**Request Transformation:**

```rust
impl
    TryFrom<
        &MyConnectorRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for MyConnectorPaymentRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: &MyConnectorRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // ... transformation logic
    }
}
```

**Response Transformation:**

```rust
impl<F, Req>
    ForeignTryFrom<(
        MyConnectorPaymentResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        u16,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = domain_types::errors::ConnectorError;

    fn foreign_try_from(
        (response, data, http_code): (
            MyConnectorPaymentResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        // ... transformation logic
    }
}
```

### 3.3. Enums and Helper Functions

Use enums to represent statuses, types, and other categorical data from the connector's API. Create helper functions to encapsulate reusable logic, such as building authentication headers or handling specific payment methods.

## 4. Error Handling

Use `CustomResult` and `error_stack` for robust error handling. When building error responses, parse the connector's error response and map it to the router's `ErrorResponse` struct.

## 5. Testing

Write comprehensive unit tests for your connector in `my_connector/test.rs`. Test all payment flows, webhook handling, and data transformations.

## 6. General Best Practices

*   **Follow Rust best practices:** Write clean, idiomatic, and well-documented Rust code.
*   **Use macros for boilerplate:** Leverage the existing macros (`create_all_prerequisites!`, `macro_connector_implementation!`, `with_error_response_body!`, `with_response_body!`) to reduce boilerplate code.
*   **Keep transformers clean:** The `transformers.rs` file should only contain data transformation logic. Keep business logic in `my_connector.rs`.
*   **Handle all payment methods:** If your connector supports multiple payment methods, ensure that you have the necessary logic to handle each one.
*   **Be consistent:** Follow the patterns and conventions established in the existing connectors.

## 7. Connector Registration

When adding a new connector, it must be added to the `ConnectorEnum` in `domain_types/src/connector_types.rs` and to the `convert_connector` function in `backend/connector-integration/src/types.rs`.

## 8. Handling XML Responses

If your connector returns XML responses, use the `preprocess_xml_response_bytes` function in `backend/connector-integration/src/utils/xml_utils.rs` to convert the XML to a flattened JSON structure. This will make it easier to parse the response in your `handle_response_v2` function.

## 9. Utility Functions

The `backend/connector-integration/src/utils.rs` file contains several useful utility functions, such as `missing_field_err` for creating "missing field" errors. Use these functions to reduce boilerplate and improve code consistency.

## 10. Authentication

The `ConnectorAuthType` enum in `backend/domain_types/src/router_data.rs` defines the supported authentication methods. Your connector's `get_auth_header` function should handle the appropriate authentication method for your connector.

The supported authentication methods are:

*   `HeaderKey`: For connectors that use a single API key in the request header.
*   `BodyKey`: For connectors that use an API key and another key in the request body.
*   `SignatureKey`: For connectors that use an API key, another key, and an API secret to generate a signature.
*   `MultiAuthKey`: For connectors that use multiple keys for authentication.
*   `CertificateAuth`: For connectors that use client certificates for authentication.

## 11. Core Data Structures

The `backend/domain_types/src/connector_types.rs` file defines many of the core data structures used in connector integrations. Familiarize yourself with these structs, especially:

*   **`PaymentsAuthorizeData`**: Contains the data for an authorization request.
*   **`PaymentsSyncData`**: Contains the data for a payment sync request.
*   **`RefundsData`**: Contains the data for a refund request.
*   **`PaymentFlowData`**: Contains the common data available for all payment flows.
*   **`ResponseId`**: Represents the different types of response IDs a connector can return.
*   **`PaymentsResponseData`**: Represents the different types of responses a connector can return for a payment.
