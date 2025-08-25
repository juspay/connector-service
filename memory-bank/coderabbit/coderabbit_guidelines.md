# Connector Integration Coding Guidelines

This document outlines the coding guidelines and best practices for integrating new connectors into the connector-service, with a focus on the macro-driven framework.

## 1. Directory and File Structure

Each new connector, named `my_connector`, should follow this directory structure:

```
backend/connector-integration/src/connectors/
├── my_connector.rs                 # Main connector logic and macro invocations
└── my_connector/
    └── transformers.rs             # Request/Response structs and TryFrom implementations

backend/grpc-server/tests/
└── my_connector_payment_flows_test.rs # End-to-end tests for the connector
```

- **`my_connector.rs`**: This is the main file for the connector. It uses the macro framework to define the connector's structure, supported flows, and flow-specific logic like URL and header generation.
- **`my_connector/transformers.rs`**: This file contains the data transformation logic. It defines the structs that represent the connector's native API requests and responses, and implements the `TryFrom` traits to convert between the router's generic data structures and the connector's specific formats.
- **`my_connector_payment_flows_test.rs`**: This file contains the end-to-end tests for the connector, which are executed via the gRPC server.

## 2. The Macro-Driven Workflow

Connector integration is primarily achieved through a set of powerful macros that generate the necessary boilerplate code. The main steps are:
1.  Define the connector's capabilities using `create_all_prerequisites!`.
2.  Implement the `ConnectorCommon` trait for basic connector information.
3.  Implement marker traits for each supported flow (e.g., `PaymentAuthorizeV2`).
4.  Use `macro_connector_implementation!` for each flow to specify its implementation details.
5.  Create the necessary request/response structs and `TryFrom` implementations in the `transformers.rs` file.

---

## 3. Implementing `my_connector.rs`

### 3.1. Step 1: Define Prerequisites with `create_all_prerequisites!`

This is the first and most important macro call. It sets up the connector's struct and defines all the API flows it supports.

```rust
macros::create_all_prerequisites!(
    // 1. The name of your connector struct
    connector_name: MyConnector,

    // 2. A list of all supported API flows
    api: [
        (
            flow: Authorize,
            request_body: MyConnectorAuthRequest,
            response_body: MyConnectorAuthResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        (
            flow: PSync,
            request_body: MyConnectorPSyncRequest,
            response_body: MyConnectorPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        ),
        (
            flow: Capture,
            request_body: MyConnectorCaptureRequest,
            response_body: MyConnectorCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        ),
        // ... other flows: Void, Refund, SetupMandate, etc.
    ],

    // 3. (Optional) Amount converters if not using MinorUnit directly
    amount_converters: [],

    // 4. Common helper functions for the connector
    member_functions: {
        // Example: A common function to build authentication headers
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }
        // Other helpers like getting base URLs can go here
    }
);
```

### 3.2. Step 2: Implement `ConnectorCommon`

This trait provides the basic, essential information about the connector.

```rust
impl ConnectorCommon for MyConnector {
    fn id(&self) -> &'static str {
        "my_connector"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Logic to convert the generic ConnectorAuthType into the specific
        // headers required by the connector.
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.my_connector.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // 1. Deserialize the raw response into your connector's error struct
        let response: my_connector::transformers::MyConnectorErrorResponse = res
            .response
            .parse_struct("MyConnectorErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // 2. Map the fields to the standard ErrorResponse struct
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code,
            message: response.error_message,
            reason: response.error_reason,
            // ... other fields
        })
    }
}
```

### 3.3. Step 3: Implement Flow Marker Traits

For each flow defined in `create_all_prerequisites!`, add an empty "marker" trait implementation. This signals that your connector supports the flow.

```rust
impl connector_types::PaymentAuthorizeV2 for MyConnector {}
impl connector_types::PaymentSyncV2 for MyConnector {}
impl connector_types::PaymentCapture for MyConnector {}
// ... and so on for all supported flows.
```

### 3.4. Step 4: Implement Flows with `macro_connector_implementation!`

For each flow, use this macro to generate the `ConnectorIntegrationV2` trait implementation.

```rust
// Implementation for the Authorize flow
macros::macro_connector_implementation!(
    // 1. List of default functions to use from the framework
    connector_default_implementations: [get_content_type, get_error_response_v2],

    // 2. Connector and flow details
    connector: MyConnector,
    flow_name: Authorize,
    http_method: Post,

    // 3. Request and Response structs (must match those in create_all_prerequisites!)
    curl_request: Json(MyConnectorAuthRequest),
    curl_response: MyConnectorAuthResponse,

    // 4. RouterDataV2 generic types for this flow
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,

    // 5. Flow-specific functions (get_url is almost always required)
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // You can call a common helper from member_functions
            self.build_headers(req)
        }

        fn get_url(
            &self,
            _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Construct the specific endpoint URL for this flow
            Ok(format!("{}{}", self.base_url(_req.resource_common_data.connectors), "/payments"))
        }
    }
);

// Repeat macro_connector_implementation! for every other flow (PSync, Capture, etc.)
```

---

## 4. Implementing `my_connector/transformers.rs`

This file is the heart of the data mapping logic.

### 4.1. Request and Response Structs

Define Rust structs that exactly match the JSON (or other format) structure of the connector's API.

```rust
// Request for the Authorize flow
#[derive(Debug, Serialize)]
pub struct MyConnectorAuthRequest {
    // ... fields for the request
}

// Response for the Authorize flow
#[derive(Debug, Deserialize)]
pub struct MyConnectorAuthResponse {
    // ... fields for the response
}

// Error response
#[derive(Debug, Deserialize)]
pub struct MyConnectorErrorResponse {
    // ... fields for the error response
}
```

### 4.2. `TryFrom` Implementations

This is where you map data between the application's generic `RouterDataV2` and your connector-specific structs.

**Request Transformation:**
Convert `RouterDataV2` into your request struct.

```rust
impl TryFrom<MyConnectorRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>>
    for MyConnectorAuthRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: MyConnectorRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        // Extract data from item.router_data.request, item.router_data.resource_common_data, etc.
        // and build the MyConnectorAuthRequest struct.
    }
}
```

**Response Transformation:**
Update `RouterDataV2` based on the connector's response struct.

```rust
impl<F> TryFrom<ResponseRouterData<MyConnectorAuthResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        value: ResponseRouterData<MyConnectorAuthResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, mut router_data, .. } = value;

        // 1. Map the connector's status to the application's AttemptStatus
        // 2. Populate router_data.response with either Ok(PaymentsResponseData) or Err(ErrorResponse)
        // 3. Update router_data.resource_common_data.status
        // 4. Return the updated router_data
    }
}
```

---

## 5. Other Key Guidelines

*   **Authentication**: In your `ConnectorCommon::get_auth_header` implementation, correctly handle the `ConnectorAuthType` enum variant that corresponds to your connector's authentication scheme.
*   **Connector Registration**: Add your new connector to the `ConnectorEnum` in `backend/domain_types/src/connector_types.rs` and to the `convert_connector` function in `backend/connector-integration/src/types.rs`.
*   **Response Preprocessing**: If a connector's response needs to be modified before deserialization (e.g., converting XML to JSON, or other transformations), use the `preprocess_response` mechanism.
    1.  In the `member_functions` block of `create_all_prerequisites!`, define a `preprocess_response_bytes` function. This function will receive the raw response bytes and should return the processed bytes.
        ```rust
        // In member_functions
        fn preprocess_response_bytes<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
            bytes: bytes::Bytes,
        ) -> CustomResult<bytes::Bytes, errors::ConnectorError> {
            // For XML, call the utility function
            // return crate::utils::preprocess_xml_response_bytes(bytes);

            // For no preprocessing, just return the bytes
            Ok(bytes)
        }
        ```
    2.  In the `macro_connector_implementation!` for the relevant flow, add the `preprocess_response: true` flag. This tells the macro to call the function you defined. If this flag is `false` or omitted, the function will not be called.
*   **Error Handling**: Use `error_stack` for error propagation. Your `build_error_response` function is the primary place to map connector errors to the standard `ErrorResponse` struct.
*   **Testing**: Write thorough end-to-end tests in `backend/grpc-server/tests/` to cover all supported payment flows, including success and failure scenarios.
*   **Duck**: If any comment is found which contains the word "duck" then point it out and ask to remove it.