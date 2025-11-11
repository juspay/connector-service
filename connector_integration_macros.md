# Guide: Integrating a New Connector with Macros

This guide provides a step-by-step process for integrating a new payment connector into the hyperswitch system using the provided macro framework. It leverages the `adyen.rs` and `macros.rs` files as primary examples.

## Overview

The integration process relies heavily on Rust macros to reduce boilerplate code and ensure consistency across connectors. You'll define connector-specific data structures (requests, responses, errors) and then use macros to wire them into the generic payment flow framework.

## File Structure

It's recommended to follow a structure similar to the Adyen connector:

```
backend/connector-integration/src/connectors/
├── <connector_name>/
│   ├── transformers.rs             // Request/Response structs and TryFrom implementations
│   └── test.rs                     // Tests
├── macros.rs                       // Core macros (already provided)
└── <connector_name>.rs             // Main Connector logic
```

## Step 1: Define Connector Struct and Prerequisites (`create_all_prerequisites!`)

In your `<connector_name>.rs` or a dedicated file imported into it, start by using the `create_all_prerequisites!` macro. This macro sets up the main connector struct, its associated data types for different flows, and common member functions.

**Macro Usage:**

```rust
macros::create_all_prerequisites!(
    connector_name: YourConnectorName, // e.g., Adyen
    api: [
        (
            flow: FlowName1, // e.g., Authorize
            request_body: ConnectorRequestStruct1, // e.g., AdyenPaymentRequest
            response_body: ConnectorResponseStruct1, // e.g., AdyenPaymentResponse
            router_data: RouterDataV2<FlowName1, CommonFlowData1, RequestData1, ResponseData1>
        ),
        (
            flow: FlowName2, // e.g., PSync
            request_body: ConnectorRequestStruct2, // Can be different or same
            response_body: ConnectorResponseStruct2,
            router_data: RouterDataV2<FlowName2, CommonFlowData2, RequestData2, ResponseData2>
        ),
        // ... other flows like Capture, Void, Refund, SetupMandate, Accept (Dispute), SubmitEvidence (Dispute)
        // For flows without a request body:
        (
            flow: FlowNameWithoutRequestBody,
            // request_body is omitted
            response_body: ConnectorResponseStructForNoBody,
            router_data: RouterDataV2<FlowNameWithoutRequestBody, CommonFlowDataX, RequestDataX, ResponseDataX>
        )
    ],
    amount_converters: [ // If your connector needs specific amount unit conversions
        // converter_name : AmountUnitType (e.g., minor_unit_converter: MinorUnit)
    ], // Can be empty: amount_converters: [],
    member_functions: {
        // Define common helper functions for your connector here
        // These functions will be part of the YourConnectorName struct implementation
        // Example from adyen.rs:
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            // ... logic to build common headers ...
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            // ... logic to get base URL for payment related APIs ...
        }
        // ... other common functions
    }
);
```

**Explanation:**

*   **`connector_name`**: The name of your connector struct (e.g., `Adyen`).
*   **`api` array**: This is crucial. Each tuple defines a payment flow your connector supports.
    *   `flow`: The specific flow type (e.g., `Authorize`, `Capture`, `Refund`, `PSync`, `SetupMandate`, `Accept`, `SubmitEvidence`). These types are typically defined in `domain_types::connector_flow`.
    *   `request_body`: (Optional) The name of the Rust struct that represents the request body for this flow specific to your connector. You'll define this in `transformers.rs`. If a flow doesn't have a request body (e.g., some GET requests for sync), omit this field.
    *   `response_body`: The name of the Rust struct for the connector's response for this flow. Define this in `transformers.rs`.
    *   `router_data`: The fully qualified type of `RouterDataV2` for this specific flow, including its generic parameters (flow type, common flow data, request data, response data). These types are usually found in `domain_types::connector_types`.
*   **`amount_converters`**: If your connector handles amounts in a unit different from the system's default, you can specify converters here. Often, this might be empty if you work with `MinorUnit` directly.
*   **`member_functions`**: A block to define functions that will be part of your connector's struct (`impl YourConnectorName { ... }`). These are typically helper functions used across different flows, like building authentication headers or constructing base URLs.

## Step 2: Implement Transformer Structs (`<connector_name>/transformers.rs`)

This file is where you define the Rust structs that mirror the connector's native API request and response formats, as well as error and webhook structures.

**Key struct types to define:**

1.  **Request Structs**: For each `request_body` specified in `create_all_prerequisites!`.
    *   Example: `AdyenPaymentRequest`, `AdyenCaptureRequest`, `AdyenVoidRequest`, `AdyenRefundRequest`, `SetupMandateRequest`.
    *   These structs should use `serde::Serialize`.
    *   Use `Secret` for sensitive data.
    *   Use `Option` for optional fields and `serde_with::skip_serializing_none` to omit them from JSON if `None`.

    ```rust
    // Example from adyen/transformers.rs
    #[serde_with::skip_serializing_none]
    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AdyenPaymentRequest {
        amount: Amount, // Another struct you define
        merchant_account: Secret<String>,
        payment_method: PaymentMethod, // Enum or struct
        reference: String,
        return_url: String,
        // ... other fields
        additional_data: Option<AdditionalData>,
    }

    #[derive(Debug, Serialize)]
    pub struct SetupMandateRequest(AdyenPaymentRequest); // Can wrap another request
    ```

2.  **Response Structs**: For each `response_body` specified in `create_all_prerequisites!`.
    *   Example: `AdyenPaymentResponse`, `AdyenPSyncResponse` (can wrap another response), `AdyenCaptureResponse`, `AdyenVoidResponse`, `AdyenRefundResponse`, `SetupMandateResponse`.
    *   These structs should use `serde::Deserialize`.
    *   They might be enums if the connector returns different structures for success/redirection (e.g., `AdyenPaymentResponse` enum).

    ```rust
    // Example from adyen/transformers.rs
    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(untagged)] // Useful if response varies structurally
    pub enum AdyenPaymentResponse {
        Response(Box<AdyenResponse>),
        RedirectionResponse(Box<RedirectionResponse>),
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct AdyenPSyncResponse(AdyenPaymentResponse); // Wraps the main payment response

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AdyenResponse { // Actual successful response structure
        psp_reference: String,
        result_code: AdyenStatus, // Enum for connector status
        // ... other fields
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct RedirectionResponse { // Structure for redirection
        result_code: AdyenStatus,
        action: AdyenRedirectAction, // Struct detailing the redirect
        // ... other fields
    }
    ```

3.  **Error Response Structs**: To deserialize error responses from the connector.
    *   Example: `AdyenErrorResponse`.
    *   Implement `TryFrom` for this to convert it into the system's `ErrorResponse`.

    ```rust
    // Example from adyen/transformers.rs
    #[derive(Debug, Default, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AdyenErrorResponse {
        pub status: i32,
        pub error_code: String,
        pub message: String,
        pub error_type: String,
        pub psp_reference: Option<String>,
    }
    ```

4.  **Helper Enums/Structs**: Any other enums or structs needed by your request/response types (e.g., `Amount`, `Currency`, `AdyenStatus`, `PaymentType`).

## Step 3: Implement `TryFrom` for Request Transformers

For each connector-specific request struct (e.g., `AdyenPaymentRequest`), you need to implement `TryFrom<YourConnectorRouterData<RouterDataV2<...>>> for YourConnectorRequestStruct`. The `YourConnectorRouterData` is a wrapper struct automatically generated by `macros::expand_connector_input_data!` (which is called by `create_all_prerequisites!`).

**Example (`adyen/transformers.rs` - `AdyenPaymentRequest`):**

```rust
// In adyen/transformers.rs, AdyenRouterData is defined by the macros
// pub struct AdyenRouterData<RD: FlowTypes> {
//     pub connector: Adyen,
//     pub router_data: RD,
// }


// For Authorize flow
impl TryFrom<AdyenRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>>
    for AdyenPaymentRequest
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(
        item: AdyenRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        // 1. Handle different payment methods (Card, Mandate ID, etc.)
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(ref card) => {
                // Extract card details and other necessary data from item.router_data
                let auth_type = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;
                let amount = Amount {
                    currency: item.router_data.request.currency,
                    value: item.router_data.request.minor_amount.to_owned(),
                };
                let payment_method_object = PaymentMethod::AdyenPaymentMethod(Box::new(
                    AdyenPaymentMethod::try_from((card, item.router_data.request.customer_name.clone()))?,
                )); // AdyenPaymentMethod::try_from would be another TryFrom

                let return_url = item.router_data.request.router_return_url.clone().ok_or_else(|| {
                    errors::ConnectorError::MissingRequiredField { field_name: "return_url" }
                })?;

                // Extract billing address, shopper details, recurring info, etc.
                let billing_address = get_address_info(
                    item.router_data.resource_common_data.address.get_payment_billing(),
                ).and_then(Result::ok);

                let (recurring_processing_model, store_payment_method, shopper_reference) =
                    get_recurring_processing_model(&item.router_data)?; // Helper function

                let additional_data = get_additional_data(&item.router_data); // Helper for metadata/risk data

                Ok(AdyenPaymentRequest {
                    amount,
                    merchant_account: auth_type.merchant_account,
                    payment_method: payment_method_object,
                    reference: item.router_data.connector_request_reference_id.clone(),
                    return_url,
                    shopper_interaction: AdyenShopperInteraction::from(&item.router_data), // Can be another From/TryFrom
                    recurring_processing_model,
                    additional_data,
                    shopper_reference,
                    store_payment_method,
                    billing_address,
                    // ... other fields initialized from item.router_data
                })
            }
            PaymentMethodData::Wallet(_) | // ... other payment method types
            PaymentMethodData::MandatePayment => {
                // Handle mandate payments by extracting mandate_id if available
                // Or return ConnectorError::NotImplemented or specific error
                Err(errors::ConnectorError::NotImplemented("Payment method not supported".into()).into())
            }
            // Handle other payment method data types as needed
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".into()).into()),
        }
    }
}

// Similar TryFrom implementations for:
// - AdyenCaptureRequest using RouterDataV2<Capture, ...>
// - AdyenVoidRequest using RouterDataV2<Void, ...>
// - AdyenRefundRequest using RouterDataV2<Refund, ...>
// - SetupMandateRequest using RouterDataV2<SetupMandate, ...>
// - AdyenDisputeAcceptRequest using RouterDataV2<Accept, ...>
// - AdyenDisputeSubmitEvidenceRequest using RouterDataV2<SubmitEvidence, ...>
```

**Key points for Request `TryFrom`:**

*   **Access `router_data`**: The core data is in `item.router_data`. This contains `request` (e.g., `PaymentsAuthorizeData`), `resource_common_data` (e.g., `PaymentFlowData`), `connector_auth_type`, etc.
*   **Authentication**: Extract API keys and other auth details from `item.router_data.connector_auth_type`. You might need a helper struct like `AdyenAuthType` and a `TryFrom` for it.
*   **Payment Method Data**: Handle various `PaymentMethodData` enums (Card, Wallet, BankRedirect, etc.).
*   **Amounts and Currency**: Extract and format amounts and currencies as required by the connector.
*   **Addresses**: Transform billing and shipping addresses.
*   **Recurring Payments/Mandates**: Handle logic for `setup_future_usage`, `off_session`, and `mandate_id`.
*   **Metadata/Additional Data**: Map `item.router_data.request.metadata` to the connector's equivalent.
*   **Error Handling**: Return `Err(error_stack::Report<errors::ConnectorError>)` for failures (e.g., missing fields, unsupported payment methods).
*   **Helper Functions**: Use internal helper functions (like `get_address_info`, `get_recurring_processing_model`, `get_additional_data` in Adyen) to keep the `TryFrom` clean.

## Step 4: Implement `TryFrom` for Response Transformers

For each connector flow, you need to implement:
`TryFrom<ResponseRouterData<YourConnectorResponseStruct, RouterDataV2<Flow, ...>>> for RouterDataV2<Flow, ...>`

`ResponseRouterData` is a generic wrapper:
```rust
// From crate::types
pub struct ResponseRouterData<Resp, T> {
    pub response: Resp,      // YourConnectorResponseStruct
    pub router_data: T,      // The original RouterDataV2<Flow, ...> passed to the request
    pub http_code: u16,
}
```

**Example (`adyen/transformers.rs` - `AdyenPaymentResponse` for Authorize flow):**

```rust
// For Authorize flow
// Note: F is a generic type parameter representing the flow (e.g., Authorize)
impl<F> TryFrom<ResponseRouterData<AdyenPaymentResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(
        value: ResponseRouterData<AdyenPaymentResponse, Self>, // Self here refers to the RouterDataV2 output type
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,        // This is AdyenPaymentResponse
            mut router_data, // This is the original RouterDataV2 instance
            http_code,
        } = value;

        // AdyenPaymentResponse can be an enum (e.g., Response vs. RedirectionResponse)
        let (status_update, error_response_data, payments_response_data_inner) = match response {
            AdyenPaymentResponse::Response(adyen_resp_box) => { // Successful direct response
                let adyen_resp = *adyen_resp_box;
                let attempt_status = get_adyen_payment_status( // Helper to map connector status to AttemptStatus
                    false, // is_manual_capture - determine this from router_data.request.capture_method
                    adyen_resp.result_code,
                    router_data.request.payment_method_type,
                );

                let mut error_data = None;
                if attempt_status == AttemptStatus::Failure || adyen_resp.refusal_reason.is_some() {
                    error_data = Some(ErrorResponse {
                        code: adyen_resp.refusal_reason_code.unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                        message: adyen_resp.refusal_reason.clone().unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                        reason: adyen_resp.refusal_reason,
                        status_code: http_code,
                        attempt_status: Some(attempt_status),
                        connector_transaction_id: Some(adyen_resp.psp_reference.clone()),
                    });
                }

                let mandate_reference = adyen_resp
                    .additional_data
                    .as_ref()
                    .and_then(|data| data.recurring_detail_reference.to_owned())
                    .map(|mandate_id| MandateReference {
                        connector_mandate_id: Some(mandate_id.expose()),
                        payment_method_id: None,
                    });

                let response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(adyen_resp.psp_reference),
                    redirection_data: Box::new(None),
                    connector_metadata: None, // Or some JSON value if connector provides extra info
                    network_txn_id: None,     // Extract if available
                    connector_response_reference_id: Some(adyen_resp.merchant_reference),
                    incremental_authorization_allowed: None, // Determine if applicable
                    mandate_reference: Box::new(mandate_reference),
                };
                (attempt_status, error_data, response_data)
            }
            AdyenPaymentResponse::RedirectionResponse(adyen_redirect_resp_box) => { // Redirection needed
                let adyen_redirect_resp = *adyen_redirect_resp_box;
                let attempt_status = get_adyen_payment_status(
                    false, // is_manual_capture
                    adyen_redirect_resp.result_code,
                    router_data.request.payment_method_type,
                );

                let mut error_data = None;
                // ... similar error checking as above ...

                let redirection_data = adyen_redirect_resp.action.url.clone().map(|url| {
                    RedirectForm::Form {
                        endpoint: url.to_string(),
                        method: adyen_redirect_resp.action.method.unwrap_or(Method::Get),
                        form_fields: adyen_redirect_resp.action.data.clone().unwrap_or_default(),
                    }
                });

                let response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        adyen_redirect_resp.psp_reference.unwrap_or_default(),
                    ),
                    redirection_data: Box::new(redirection_data),
                    // ... other fields ...
                };
                (attempt_status, error_data, response_data)
            }
        };

        router_data.resource_common_data.status = status_update; // Update the status in PaymentFlowData
        router_data.response = error_response_data.map_or_else(|| Ok(payments_response_data_inner), Err);

        Ok(router_data)
    }
}

// Similar TryFrom implementations for:
// - AdyenPSyncResponse for RouterDataV2<PSync, ...>
// - AdyenCaptureResponse for RouterDataV2<Capture, ...>
// - AdyenVoidResponse for RouterDataV2<Void, ...>
// - AdyenRefundResponse for RouterDataV2<Refund, ...> (populating RefundsResponseData)
// - SetupMandateResponse for RouterDataV2<SetupMandate, ...>
// - AdyenDisputeAcceptResponse for RouterDataV2<Accept, ...> (populating DisputeResponseData)
// - AdyenSubmitEvidenceResponse for RouterDataV2<SubmitEvidence, ...> (populating DisputeResponseData)
```

**Key points for Response `TryFrom`:**

*   **Update `router_data`**: You receive the original `router_data` and should update its fields (especially `status` in `resource_common_data` and the main `response` field).
*   **Map Status**: Convert the connector's status codes/messages into the system's `AttemptStatus` (for payments/captures/voids) or `RefundStatus` (for refunds) or `DisputeStatus`. Use helper functions for this mapping.
*   **Error Handling**: If the connector indicates an error, populate `router_data.response` with `Err(ErrorResponse { ... })`.
*   **Success Data**: If successful, populate `router_data.response` with `Ok(PaymentsResponseData::TransactionResponse { ... })` or `Ok(RefundsResponseData { ... })` or `Ok(DisputeResponseData { ... })`.
*   **Redirection**: If the connector response indicates a redirect is needed, populate `redirection_data` in `PaymentsResponseData` with a `RedirectForm`.
*   **Mandates**: Populate `mandate_reference` in `PaymentsResponseData` if the connector returns a mandate/token ID.
*   **Connector Transaction ID**: Always populate `resource_id` in `PaymentsResponseData` (or `connector_refund_id` in `RefundsResponseData`, `connector_dispute_id` in `DisputeResponseData`) with the connector's unique transaction/refund/dispute identifier.
*   **HTTP Status Code**: The `http_code` from the response is available in `ResponseRouterData` and can be used in `ErrorResponse`.

## Step 5: Implement `ConnectorCommon` Trait

In `<connector_name>/mod.rs`, implement the `ConnectorCommon` trait for your connector struct.

```rust
// In <connector_name>/mod.rs
impl ConnectorCommon for YourConnectorName {
    fn id(&self) -> &'static str {
        "your_connector_id_string" // e.g., "adyen"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        // e.g., api::CurrencyUnit::Minor, api::CurrencyUnit::Base
        api::CurrencyUnit::Minor // Default for many
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Use a helper struct (e.g., YourConnectorAuthType) and TryFrom<&ConnectorAuthType>
        // to parse auth_type and construct the specific headers.
        // Example from adyen.rs:
        let auth = adyen::AdyenAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::X_API_KEY.to_string(), // Define in your_connector_name::headers
            auth.api_key.into_masked(),
        )])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        // Return the base URL from the configuration
        // e.g., connectors.your_connector_name.base_url.as_ref()
        connectors.adyen.base_url.as_ref() // Placeholder, replace adyen
    }

    fn build_error_response(
        &self,
        res: Response, // hyperswitch_interfaces::types::Response
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Deserialize res.response (which is bytes::Bytes) into your
        // connector-specific error response struct (e.g., AdyenErrorResponse).
        let response_struct: your_connector_name::transformers::YourConnectorErrorResponse = res
            .response
            .parse_struct("YourConnectorErrorResponseName") // For logging
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Use with_error_response_body! macro if needed for event logging
        with_error_response_body!(event_builder, response_struct);

        // Map it to the generic ErrorResponse struct.
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response_struct.error_code, // Or some field from your error struct
            message: response_struct.message.to_owned(),
            reason: Some(response_struct.message), // Or more detailed reason
            attempt_status: None, // This can be set based on the error
            connector_transaction_id: response_struct.psp_reference, // Or connector's error ref
        })
    }
}
```

## Step 6: Implement Flow-Specific Marker Traits

For each flow your connector supports (Authorize, PSync, Capture, Void, Refund, etc.), you'll typically add an empty trait implementation for your connector struct. These are defined in `domain_types::connector_types`.

```rust
// In <connector_name>/mod.rs
use domain_types::connector_types::{
    PaymentAuthorizeV2, PaymentSyncV2, PaymentVoidV2, RefundSyncV2, RefundV2, PaymentCapture,
    SetupMandateV2, AcceptDispute, SubmitEvidenceV2, // etc.
};

impl PaymentAuthorizeV2 for YourConnectorName {}
impl PaymentSyncV2 for YourConnectorName {}
impl PaymentVoidV2 for YourConnectorName {}
impl RefundV2 for YourConnectorName {}
impl PaymentCapture for YourConnectorName {}
// ... and so on for all supported flows.
```

## Step 7: Use `macro_connector_implementation!`

This macro generates the `ConnectorIntegrationV2` trait implementation for each specific flow. You'll call this multiple times, once for each flow defined in your `create_all_prerequisites!` macro's `api` array.

**Macro Usage (example for Authorize flow):**

```rust
// In <connector_name>/mod.rs
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2], // List default functions to implement from ConnectorIntegrationV2
    connector: YourConnectorName,
    curl_request: Json(YourConnectorPaymentRequest), // Content type (Json, Form) and request struct
    curl_response: YourConnectorPaymentResponse,    // Response struct
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,          // from domain_types
    flow_request: PaymentsAuthorizeData,            // from domain_types
    flow_response: PaymentsResponseData,            // from domain_types
    http_method: Post, // Get, Post, Put, Delete
    other_functions: { // Implement flow-specific functions here
        // Mandatory: get_url
        // Optional: get_headers (if different from default get_headers in ConnectorCommon)
        //           get_request_body (if custom logic beyond TryFrom is needed, rare)
        //           handle_response_v2 (if custom logic beyond TryFrom is needed, rare)

        // Example from Adyen for Authorize flow:
        fn get_headers( // Overrides default if needed, or uses build_headers from member_functions
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req) // Calls common header builder
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Use connector_base_url_payments or similar from member_functions
            // and append flow-specific path.
            // Example:
            // Ok(format!("{}{}/payments", self.connector_base_url_payments(req), API_VERSION_CONST))
            let base_url = self.connector_base_url_payments(req); // Assuming this exists
            Ok(format!("{}/v1/payments", base_url)) // Replace with actual path
        }
    }
);

// Repeat macro_connector_implementation! for PSync:
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: YourConnectorName,
    curl_request: Json(YourConnectorRedirectRequest), // e.g., AdyenRedirectRequest for PSync
    curl_response: YourConnectorPSyncResponse,     // e.g., AdyenPSyncResponse
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post, // Or Get, depending on connector
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // URL for payment/details or sync endpoint
             let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}/v1/payments/details", base_url)) // Replace
        }
    }
);

// Repeat for Capture, Void, Refund, SetupMandate, etc.
// For flows without a request body (e.g. RSync if it's a GET with no body):
/*
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2, get_headers], // get_request_body is NOT included by default
    connector: YourConnectorName,
    // curl_request is omitted
    curl_response: YourConnectorRSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData, // Or PaymentFlowData depending on sync type
    flow_request: RefundSyncData,         // Or PaymentsSyncData
    flow_response: RefundsResponseData,   // Or PaymentsResponseData
    http_method: Get,
    other_functions: {
        // No get_request_body needed by default if curl_request is omitted
        // get_headers might be needed if not covered by default
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // ... logic to build URL, possibly using req.request.connector_transaction_id ...
            let refund_id = req.request.connector_refund_ids.first().cloned().ok_or(...)?;
            Ok(format!("{}/v1/refunds/{}", self.connector_base_url_refunds(req), refund_id))
        }
    }
);
*/
```

**Explanation of `macro_connector_implementation!` parameters:**

*   `connector_default_implementations`: A list of functions from `ConnectorIntegrationV2` that should use a default implementation provided by `macros.rs` (e.g., `get_content_type`, `get_error_response_v2`, `get_headers`). If you provide a function in `other_functions`, it overrides the default.
    *   `get_request_body` is automatically handled by the macro based on `curl_request` type (Json/Form) and the `TryFrom` you wrote for the request struct. Only override if you need very custom logic.
    *   `handle_response_v2` is also automatically handled using the `TryFrom` for your response struct.
*   `connector`: Your connector struct name.
*   `curl_request`: (Optional) Specifies the content type and the request struct.
    *   `Json(YourConnectorRequestStruct)` for JSON body.
    *   `FormData(YourConnectorRequestStruct)` for form data (your struct must implement `GetFormData` trait from `macros.rs`).
    *   If omitted, the request will have no body (typical for GET requests).
*   `curl_response`: Your connector-specific response struct for this flow.
*   `flow_name`, `resource_common_data`, `flow_request`, `flow_response`: Match the types used in `RouterDataV2` for this specific flow.
*   `http_method`: `Post`, `Get`, `Put`, `Delete`.
*   `other_functions`: A block to implement flow-specific versions of `ConnectorIntegrationV2` functions.
    *   `get_url` is almost always required here to define the specific API endpoint for the flow.
    *   `get_headers` can be defined here if this flow requires headers different from the common ones generated by `build_headers` or the default.
    *   Rarely, you might override `get_request_body` or `handle_response_v2` if the `TryFrom` implementations are not sufficient for a particular flow's complex logic.
