# Connector Capture Flow Implementation Guide

This guide provides step-by-step instructions for implementing the payment capture flow for a new or existing connector in the connector service. It assumes that the connector has already been set up as per the `connector_implementation_guide.md` and that the Authorize flow is functional.

## Table of Contents
1.  [Prerequisites](#prerequisites)
2.  [Implementing Capture Flow](#implementing-capture-flow)
    *   [A. Update Connector Trait Implementations](#a-update-connector-trait-implementations)
    *   [B. Define Request Structures (`transformers.rs`)](#b-define-request-structures-transformersrs)
    *   [C. Implement `TryFrom` for Request (`transformers.rs`)](#c-implement-tryfrom-for-request-transformersrs)
    *   [D. Define Response Structures (`transformers.rs`)](#d-define-response-structures-transformersrs)
    *   [E. Implement `ForeignTryFrom` for Response (`transformers.rs`)](#e-implement-foreigntryfrom-for-response-transformersrs)
    *   [F. Implement `ConnectorIntegrationV2` for Capture (`<connector_name>.rs`)](#f-implement-connectorintegrationv2-for-capture-connector_namers)
3.  [Key Considerations](#key-considerations)
4.  [Referencing Razorpay and Elavon](#referencing-razorpay-and-elavon)
5.  [Testing](#testing)

## 1. Prerequisites

*   The connector is already added to the framework (as per `connector_implementation_guide.md`).
*   The Authorize flow for the connector is implemented and working.
*   You have the connector's API documentation for the "Capture" or "Settle" operation. This typically involves sending the original transaction ID (obtained from authorize) and the amount to capture.

## 2. Implementing Capture Flow

### A. Update Connector Trait Implementations
In your connector's main file (e.g., `backend/connector-integration/src/connectors/new_connector_name.rs`):

Ensure that the `PaymentCapture` trait is implemented for your connector struct.

```rust
// In backend/connector-integration/src/connectors/new_connector_name.rs

// ... other imports ...
use domain_types::connector_types::PaymentCapture; // Ensure this is imported

// ... struct definition ...

impl PaymentCapture for NewConnectorName {} // Add this line if not present

// ... other trait implementations ...
```

### B. Define Request Structures (`transformers.rs`)
In your connector's `transformers.rs` file (e.g., `backend/connector-integration/src/connectors/new_connector_name/transformers.rs`):

Define the request structure that your connector expects for a capture API call. This will vary based on the connector.

*   **Example (Elavon-like, where capture is `CcComplete`):**
    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs

    // TransactionType enum should already exist from Authorize flow, ensure CcComplete is there
    // pub enum TransactionType {
    //     CcSale,
    //     CcAuthOnly,
    //     CcComplete, // <<< For Capture
    //     // ... other types
    // }

    #[skip_serializing_none]
    #[derive(Debug, Serialize)]
    pub struct ElavonCaptureRequest {
        pub ssl_transaction_type: TransactionType,
        pub ssl_account_id: Secret<String>, // Merchant account ID from auth
        pub ssl_user_id: Secret<String>,    // User ID from auth
        pub ssl_pin: Secret<String>,        // PIN from auth
        pub ssl_amount: StringMajorUnit,    // Amount to capture (ensure it's in major units if required)
        pub ssl_txn_id: String,             // The original transaction ID from authorize
        // Potentially other fields like ssl_invoice_number, ssl_transaction_currency if needed
    }
    ```

*   **Example (Razorpay-like):**
    ```rust
    // In backend/connector-integration/src/connectors/razorpay/transformers.rs
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")] // Or snake_case, check connector docs
    pub struct RazorpayCaptureRequest {
        pub amount: MinorUnit, // Amount to capture (ensure it's in minor units if required)
        pub currency: String,  // Currency of the amount
    }
    ```
    (Note: Razorpay's capture URL includes the payment ID, so it's not in the request body struct itself for them.)

**Key Fields for Capture Request:**
*   Original `connector_transaction_id` (from the Authorize step).
*   `amount_to_capture` (this might be the full authorized amount or a partial amount).
*   Currency (often part of amount or a separate field).
*   Authentication details if required by the capture endpoint (though often inherited from general auth headers).

### C. Implement `TryFrom` for Request (`transformers.rs`)
Create a `TryFrom` implementation to convert the generic `RouterDataV2` for the Capture flow into your connector-specific capture request struct.

This involves:
1.  Extracting authentication details (`ConnectorAuthType`).
2.  Getting the `connector_transaction_id` from `router_data.request`.
3.  Getting the `amount_to_capture` from `router_data.request.minor_amount_to_capture` (and converting it to major/minor units as needed by the connector).
4.  Mapping any other required fields.

*   **Example (Elavon-like):**
    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs

    impl TryFrom<&ElavonRouterData<&RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>>> for ElavonCaptureRequest {
        type Error = error_stack::Report<errors::ConnectorError>;
        fn try_from(
            item: &ElavonRouterData<&RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>>,
        ) -> Result<Self, Self::Error> {
            let router_data = item.router_data;
            let auth_type = ElavonAuthType::try_from(&router_data.connector_auth_type)?; // Assuming ElavonAuthType is defined

            let previous_connector_txn_id = match &router_data.request.connector_transaction_id {
                DomainResponseId::ConnectorTransactionId(id) => id.clone(),
                _ => return Err(report!(errors::ConnectorError::MissingConnectorTransactionID))
                           .attach_printable("Missing connector_transaction_id for Elavon Capture"),
            };

            Ok(Self {
                ssl_transaction_type: TransactionType::CcComplete, // Specific to Elavon's capture
                ssl_account_id: auth_type.ssl_merchant_id,
                ssl_user_id: auth_type.ssl_user_id,
                ssl_pin: auth_type.ssl_pin,
                ssl_amount: item.amount.clone(), // Amount already converted to StringMajorUnit in ElavonRouterData
                ssl_txn_id: previous_connector_txn_id,
            })
        }
    }
    ```

*   **Example (Razorpay-like):**
    ```rust
    // In backend/connector-integration/src/connectors/razorpay/transformers.rs

    impl TryFrom<&RazorpayRouterData<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>> for RazorpayCaptureRequest {
        type Error = hyperswitch_interfaces::errors::ConnectorError;

        fn try_from(
            item: &RazorpayRouterData<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
        ) -> Result<Self, Self::Error> {
            let request_data = &item.router_data.request;

            Ok(RazorpayCaptureRequest {
                amount: item.amount, // Amount already converted to MinorUnit in RazorpayRouterData
                currency: request_data.currency.to_string(),
            })
        }
    }
    ```
    Remember to wrap `router_data` with your connector's `RouterData` wrapper (e.g., `ElavonRouterData`, `RazorpayRouterData`) if you use one, especially for amount conversion.

### D. Define Response Structures (`transformers.rs`)
Define the structure(s) that your connector returns for a capture API call. This might be similar to the authorize response or could be simpler.

*   **Example (Elavon-like, assuming `ElavonResult` and `PaymentResponse` can be reused or adapted):**
    Elavon's capture response (`CcComplete`) often mirrors its sale/auth response structure. You might reuse the `ElavonResult` enum and `PaymentResponse` struct defined for Authorize if the fields are the same or substantially similar.
    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs
    // Assume ElavonResult and PaymentResponse are already defined (as in the provided file content)
    // pub enum SslResult { Approved, Declined, Other }
    // pub struct PaymentResponse {
    //     pub ssl_result: SslResult,
    //     pub ssl_txn_id: String,
    //     pub ssl_result_message: String,
    //     pub ssl_transaction_type: Option<String>, // "cccomplete" for successful capture
    //     // ... other fields like ssl_approval_code
    // }
    // pub enum ElavonResult { Success(PaymentResponse), Error(ElavonErrorResponse) }
    // pub struct ElavonPaymentsResponse { pub result: ElavonResult } // Main wrapper
    ```

*   **Example (Razorpay-like):**
    ```rust
    // In backend/connector-integration/src/connectors/razorpay/transformers.rs
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")] // or snake_case
    pub struct RazorpayCaptureResponse {
        pub id: String, // Connector's transaction ID for this capture
        pub entity: String, // e.g., "payment"
        pub amount: i64,
        pub currency: String,
        pub status: RazorpayPaymentStatus, // e.g., "captured", "failed"
        pub order_id: String,
        pub captured: bool, // Should be true for successful capture
        // ... other relevant fields like error_code, error_description
    }

    // Ensure RazorpayPaymentStatus enum is defined:
    // #[derive(Debug, Clone, Serialize, Deserialize)]
    // #[serde(rename_all = "lowercase")]
    // pub enum RazorpayPaymentStatus {
    //     Authorized,
    //     Captured,
    //     Failed,
    //     // ... other statuses
    // }
    ```

### E. Implement `ForeignTryFrom` for Response (`transformers.rs`)
Implement `ForeignTryFrom` to convert the connector's capture response back into the generic `RouterDataV2`.

This involves:
1.  Determining the `HyperswitchAttemptStatus` (e.g., `Charged`, `Failure`).
2.  Populating `PaymentsResponseData` with `resource_id` (connector's transaction ID for the capture), and other relevant details.
3.  Handling potential errors from the connector and mapping them to `ErrorResponse`.

*   **Example (Elavon-like):**
    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs
    // The get_elavon_attempt_status helper needs to correctly interpret "cccomplete"
    // from ssl_transaction_type for status.

    impl ForeignTryFrom<(
        ElavonResult, // Elavon's response (success or error)
        RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>,
        u16, // http_code
    )> for RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData> {
        type Error = error_stack::Report<errors::ConnectorError>;

        fn foreign_try_from(
            item: (
                ElavonResult,
                RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>,
                u16, // http_code
            ),
        ) -> Result<Self, Self::Error> {
            let (elavon_response_result, router_data_in, http_code) = item;

            // Use a helper like get_elavon_attempt_status, ensuring it handles capture specifics
            let (initial_status, error_response_opt) =
                get_elavon_attempt_status(&elavon_response_result, http_code);
            
            match elavon_response_result {
                ElavonResult::Success(success_payload) => {
                    let final_status = match success_payload.ssl_transaction_type.as_deref() {
                        Some("cccomplete") | Some("ccsale") => { // ccsale also results in Charged
                            match success_payload.ssl_result {
                                SslResult::Approved => HyperswitchAttemptStatus::Charged,
                                _ => HyperswitchAttemptStatus::Failure,
                            }
                        },
                        _ => initial_status, // Fallback, but should be Charged for successful capture
                    };

                    let response_data = PaymentsResponseData::TransactionResponse {
                        resource_id: DomainResponseId::ConnectorTransactionId(success_payload.ssl_txn_id.clone()),
                        redirection_data: Box::new(None),
                        mandate_reference: Box::new(None),
                        connector_metadata: Some(serde_json::to_value(success_payload.clone()).unwrap_or(serde_json::Value::Null)),
                        network_txn_id: success_payload.ssl_approval_code.clone(), // If applicable
                        connector_response_reference_id: None, // Or a relevant ID
                        incremental_authorization_allowed: None,
                    };
                    
                    Ok(RouterDataV2 {
                        response: Ok(response_data),
                        resource_common_data: PaymentFlowData {
                            status: final_status,
                            ..router_data_in.resource_common_data
                        },
                        ..router_data_in
                    })
                }
                ElavonResult::Error(error_payload_struct) => {
                     let final_error_response = error_response_opt.unwrap_or_else(|| ErrorResponse {
                        code: error_payload_struct.error_code.clone().unwrap_or_else(|| hs_interface_consts::NO_ERROR_CODE.to_string()),
                        message: error_payload_struct.error_message.clone(),
                        reason: error_payload_struct.error_name.clone(),
                        status_code: http_code,
                        attempt_status: Some(initial_status), // Should be Failure
                        connector_transaction_id: error_payload_struct.ssl_txn_id.clone(),
                    });
                    Ok(RouterDataV2 {
                        response: Err(final_error_response),
                        resource_common_data: PaymentFlowData {
                            status: initial_status, // Overall flow status is Failure
                            ..router_data_in.resource_common_data
                        },
                        ..router_data_in
                    })
                }
            }
        }
    }
    ```

*   **Example (Razorpay-like):**
    ```rust
    // In backend/connector-integration/src/connectors/razorpay/transformers.rs
    // Note: The existing ForeignTryFrom for RazorpayResponse might need to be split or adapted
    // if RazorpayCaptureResponse has a different structure or needs special handling.
    // For simplicity, if CaptureResponse can be handled by a generic Psync-like response,
    // we might have a more general ForeignTryFrom. However, often a dedicated one is cleaner.

    impl ForeignTryFrom<(
        RazorpayCaptureResponse, // Specific capture response
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    )> for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> {
        type Error = hyperswitch_interfaces::errors::ConnectorError;
        fn foreign_try_from(
            (response, data): (
                RazorpayCaptureResponse,
                RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
            ),
        ) -> Result<Self, Self::Error> {
            let status = match response.status { // Assuming RazorpayPaymentStatus enum
                RazorpayPaymentStatus::Captured => AttemptStatus::Charged,
                // RazorpayPaymentStatus::Authorized => AttemptStatus::Authorized, // Unlikely for capture response
                RazorpayPaymentStatus::Failed => AttemptStatus::Failure,
                _ => AttemptStatus::Pending, // Or Failure, depending on connector behavior
            };
            Ok(Self {
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(response.id),
                    redirection_data: Box::new(None),
                    connector_metadata: None, // Or some JSON from response
                    network_txn_id: None,    // If available in response
                    connector_response_reference_id: Some(response.order_id), // Or other reference
                    incremental_authorization_allowed: None,
                    mandate_reference: Box::new(None),
                }),
                resource_common_data: PaymentFlowData {
                    status,
                    ..data.resource_common_data
                },
                ..data
            })
        }
    }
    ```

### F. Implement `ConnectorIntegrationV2` for Capture (`<connector_name>.rs`)
In your connector's main file (e.g., `backend/connector-integration/src/connectors/new_connector_name.rs`), implement the `ConnectorIntegrationV2` trait for the `Capture` flow.

```rust
// In backend/connector-integration/src/connectors/new_connector_name.rs

// ... other imports ...
use domain_types::connector_flow::Capture;
use domain_types::connector_types::{PaymentsCaptureData, PaymentFlowData, PaymentsResponseData};
use hyperswitch_common_utils::request::RequestContent;
use hyperswitch_interfaces::events::connector_api_logs::ConnectorEvent; // If using event_builder
use hyperswitch_interfaces::types::Response; // For raw response

// ...

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for NewConnectorName {
    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Similar to Authorize: set Content-Type and Authorization headers
        let mut header = vec![(
            // headers::CONTENT_TYPE.to_string(), // If using crate::headers
            "Content-Type".to_string(), // Or directly
            self.common_get_content_type().to_string().into(), // Assuming common_get_content_type from ConnectorCommon
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?; // Assuming get_auth_header from ConnectorCommon
        header.append(&mut auth_headers);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Construct the capture URL. This often includes the original connector_transaction_id.
        // Example for Elavon (it's the same base URL, type of transaction in body):
        // Ok(format!(
        //     "{}",
        //     req.resource_common_data.connectors.elavon.base_url // Or your connector's base_url
        // ))

        // Example for Razorpay:
        let transaction_id = match &req.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
        };
        Ok(format!(
            "{}v1/payments/{}/capture", // Replace with your connector's path structure
            req.resource_common_data.connectors.razorpay.base_url, // Or your connector's base_url
            transaction_id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // Convert minor_amount_to_capture to the connector's expected unit (major/minor)
        // Use your connector's specific amount converter if you have one
        // Example: let connector_amount = self.amount_converter.convert(req.request.minor_amount_to_capture, req.request.currency)?;

        // Wrap with your connector's RouterData if needed (e.g., for amount conversion)
        // let elavon_router_data = elavon::ElavonRouterData::try_from((connector_amount_string_major, req))?;
        // let connector_req = elavon::ElavonCaptureRequest::try_from(&elavon_router_data)?;

        // Example: Direct use (assuming amount is already in correct unit or handled in TryFrom for request struct)
        let connector_router_data =
            your_connector_transformers::YourConnectorRouterDataWrapper::try_from((req.request.minor_amount_to_capture, req))?; // Adjust if needed
        let connector_req =
            your_connector_transformers::YourConnectorCaptureRequest::try_from(&connector_router_data)?;

        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>, // Optional: for logging connector events
        res: Response, // The raw HTTP response from the connector
    ) -> CustomResult<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, errors::ConnectorError> {
        // Parse the raw response into your connector-specific capture response struct
        // Example:
        // let response: your_connector_transformers::YourConnectorCaptureResponse = res
        //     .response
        //     .parse_struct("YourConnectorCaptureResponse")
        //     .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        // For Elavon, which uses URL-encoded form data response:
        let response_text = String::from_utf8(res.response.to_vec())
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)
            .attach_printable("Failed to convert Elavon response to String")?;
        
        let elavon_response: your_connector_transformers::ElavonPaymentsResponse = 
            serde_qs::from_str(&response_text)
                .map_err(|e| errors::ConnectorError::ResponseDeserializationFailed)
                .attach_printable_lazy(|| format!("Failed to deserialize Elavon response: {}", e))?;

        // with_response_body!(event_builder, elavon_response.result); // If you log the inner result

        // Convert the connector's response (and original data) back to RouterDataV2
        RouterDataV2::foreign_try_from((elavon_response.result, data.clone(), res.status_code)) // Adjust arguments for ForeignTryFrom
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Reuse the common error response building logic if applicable
        self.build_error_response(res, event_builder) // Assumes build_error_response is defined in ConnectorCommon
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}
```

## 3. Key Considerations

*   **Amount Conversion**: Ensure amounts are converted to the correct unit (major or minor) expected by the connector. Use `AmountConvertor` if necessary. The `StringMajorUnit` (for Elavon) or `MinorUnit` (for Razorpay) types help manage this.
*   **Transaction ID**: The capture call nearly always requires the `connector_transaction_id` from the preceding Authorize call.
*   **Endpoint URL**: The capture endpoint might be different from the authorize endpoint. It might also require the transaction ID in the URL path.
*   **Error Handling**: Map connector-specific error codes and messages to the standard `ErrorResponse` structure.
*   **Idempotency**: If the connector supports idempotency keys for capture, consider implementing them. (This is an advanced topic not covered in detail here).
*   **Partial Captures**: If your connector supports capturing less than the authorized amount, ensure your request structure and logic can handle this. The `amount_to_capture` field in `PaymentsCaptureData` will hold the desired amount.
*   **Response Status**: Correctly map the connector's capture response status (e.g., "captured", "completed", "failed") to `HyperswitchAttemptStatus::Charged` or `HyperswitchAttemptStatus::Failure`.

## 4. Referencing Razorpay and Elavon

*   **Razorpay (`razorpay.rs`, `razorpay/transformers.rs`):**
    *   Capture request (`RazorpayCaptureRequest`) is simple, with amount and currency.
    *   The `connector_transaction_id` is part of the URL.
    *   Capture response (`RazorpayCaptureResponse`) provides a clear status.
*   **Elavon (`elavon.rs`, `elavon/transformers.rs`):**
    *   Capture is a specific transaction type (`CcComplete`) in the request body.
    *   The request (`ElavonCaptureRequest`) includes auth details and the original `ssl_txn_id`.
    *   Response parsing is more complex due to URL-encoded form data and an `ElavonResult` enum handling success/error.

Study how these connectors handle:
*   URL construction in `get_url`.
*   Request body creation in `get_request_body` and the `TryFrom` implementations for their request structs.
*   Response handling in `handle_response_v2` and the `ForeignTryFrom` implementations for `RouterDataV2`.

## 5. Testing

*   Thoroughly test the capture flow with various scenarios:
    *   Full capture of an authorized amount.
    *   Attempted capture of an already captured transaction (if possible to test, check connector behavior).
    *   Attempted capture of a failed/non-existent authorization.
    *   If partial captures are supported by the connector, test partial captures.
    *   Test error responses from the connector.
*   Use `cargo build` frequently to catch compilation errors.
*   Add unit tests for your transformer logic if it's complex.

By following these steps and referring to existing connector implementations, you can successfully add the Capture flow to your connector. 