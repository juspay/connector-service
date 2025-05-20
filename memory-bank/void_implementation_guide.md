# Connector Void Flow Implementation Guide

This guide provides step-by-step instructions for implementing the payment void (or cancellation) flow for a new or existing connector in the connector service. It assumes that the connector has already been set up as per the `connector_implementation_guide.md` and that the Authorize flow is functional.

## Table of Contents
1.  [Prerequisites](#prerequisites)
2.  [Implementing Void Flow](#implementing-void-flow)
    *   [A. Update Connector Trait Implementations](#a-update-connector-trait-implementations)
    *   [B. Define Request Structures (`transformers.rs`)](#b-define-request-structures-transformersrs)
    *   [C. Implement `TryFrom` for Request (`transformers.rs`)](#c-implement-tryfrom-for-request-transformersrs)
    *   [D. Define Response Structures (`transformers.rs`)](#d-define-response-structures-transformersrs)
    *   [E. Implement `ForeignTryFrom` for Response (`transformers.rs`)](#e-implement-foreigntryfrom-for-response-transformersrs)
    *   [F. Implement `ConnectorIntegrationV2` for Void (`<connector_name>.rs`)](#f-implement-connectorintegrationv2-for-void-connector_namers)
3.  [Key Considerations](#key-considerations)
4.  [Referencing Authorizedotnet](#referencing-authorizedotnet)
5.  [Testing](#testing)

## 1. Prerequisites

*   The connector is already added to the framework (as per `connector_implementation_guide.md`).
*   The Authorize flow for the connector is implemented and working.
*   You have the connector's API documentation for the "Void" or "Cancel" operation. This typically involves sending the original `connector_transaction_id` obtained from the Authorize step.
*   A void operation is generally only possible for transactions that have been authorized but not yet captured or settled.

## 2. Implementing Void Flow

### A. Update Connector Trait Implementations
In your connector's main file (e.g., `backend/connector-integration/src/connectors/new_connector_name.rs`):

Ensure that the `PaymentVoidV2` (or equivalent, e.g., `PaymentVoid`, `PaymentCancel`) trait is implemented for your connector struct.

```rust
// In backend/connector-integration/src/connectors/new_connector_name.rs

// ... other imports ...
use domain_types::connector_types::PaymentVoid; // Or PaymentVoidV2, PaymentCancel etc. ensure this is imported

// ... struct definition ...

impl PaymentVoid for NewConnectorName {} // Add this line if not present, adjust trait name as per project

// ... other trait implementations ...
```

### B. Define Request Structures (`transformers.rs`)
In your connector's `transformers.rs` file (e.g., `backend/connector-integration/src/connectors/new_connector_name/transformers.rs`):

Define the request structure that your connector expects for a void API call. This will vary based on the connector. Unlike capture, a void request typically does not include an amount.

*   **Example (Authorizedotnet-like):**
    ```rust
    // In backend/connector-integration/src/connectors/authorizedotnet/transformers.rs

    // TransactionType enum should already exist from Authorize/Capture flow, ensure VoidTransaction is there
    // pub enum TransactionType {
    //     // ... other types
    //     #[serde(rename = "voidTransaction")]
    //     VoidTransaction,
    // }

    #[skip_serializing_none]
    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AuthorizedotnetTransactionVoidDetails { // Specific transaction details for Void
        transaction_type: TransactionType,
        ref_trans_id: String, // The original transaction ID from authorize
    }

    #[skip_serializing_none]
    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CreateTransactionVoidRequest { // Wraps void transaction details and merchant auth
        merchant_authentication: MerchantAuthentication, // Assuming MerchantAuthentication is defined
        transaction_request: AuthorizedotnetTransactionVoidDetails,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AuthorizedotnetVoidRequest { // Top-level wrapper for Void Flow
        create_transaction_request: CreateTransactionVoidRequest,
    }
    ```

**Key Fields for Void Request:**
*   Original `connector_transaction_id` (from the Authorize step).
*   A specific transaction type indicator for "void" or "cancel".
*   Authentication details if required by the void endpoint (though often inherited from general auth headers or handled in a wrapper structure like `MerchantAuthentication`).
*   Amount is usually **not** required or allowed for a void operation.

### C. Implement `TryFrom` for Request (`transformers.rs`)
Create a `TryFrom` implementation to convert the generic `RouterDataV2` for the Void flow into your connector-specific void request struct.

This involves:
1.  Extracting authentication details (`ConnectorAuthType`) if needed for the request body (or it might be handled only in headers).
2.  Getting the `connector_transaction_id` from `router_data.request`.
3.  Mapping any other required fields, such as a transaction type specifier.

*   **Example (Authorizedotnet-like):**
    ```rust
    // In backend/connector-integration/src/connectors/authorizedotnet/transformers.rs

    impl<'a> TryFrom<(&'a RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>, MerchantAuthentication)> for AuthorizedotnetVoidRequest {
        type Error = HsInterfacesConnectorError; // Your project's connector error type

        fn try_from(
            item: (
                &'a RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>,
                MerchantAuthentication
            ),
        ) -> Result<Self, Self::Error> {
            let (router_data, merchant_auth) = item;

            let transaction_void_details = AuthorizedotnetTransactionVoidDetails {
                transaction_type: TransactionType::VoidTransaction, // Specific to Authorizedotnet's void
                ref_trans_id: router_data.request.connector_transaction_id.clone(),
            };

            let create_transaction_void_request = CreateTransactionVoidRequest {
                merchant_authentication: merchant_auth, // Cloned or constructed
                transaction_request: transaction_void_details,
            };

            Ok(Self {
                create_transaction_request: create_transaction_void_request,
            })
        }
    }
    ```
    Note: The `AuthorizedotnetRouterData` wrapper might not be used if the amount is not part of the void request structure. Authentication might be passed separately as shown.

### D. Define Response Structures (`transformers.rs`)
Define the structure(s) that your connector returns for a void API call. This is often simpler than authorize or capture responses, mainly indicating success or failure.

*   **Example (Authorizedotnet-like, using a general response structure):**
    Authorizedotnet might return a similar top-level response structure (`AuthorizedotnetPaymentsResponse`) for void as it does for other operations. The key is in interpreting the `transaction_response` and `messages` fields.
    ```rust
    // In backend/connector-integration/src/connectors/authorizedotnet/transformers.rs
    // Assume AuthorizedotnetPaymentsResponse, TransactionResponse, ResponseMessages, ResultCode etc.
    // are already defined (as in the provided file content from previous context).

    // #[derive(Debug, Default, Clone, Deserialize, Serialize)]
    // #[serde(rename_all = "camelCase")]
    // pub struct ResponseMessages {
    //     result_code: ResultCode, // Ok or Error
    //     pub message: Vec<ResponseMessage>,
    // }

    // #[skip_serializing_none]
    // #[derive(Debug, Clone, Deserialize, Serialize)]
    // #[serde(rename_all = "camelCase")]
    // pub struct AuthorizedotnetPaymentsResponse {
    //     pub transaction_response: Option<TransactionResponse>, // May be present or null for void
    //     pub messages: ResponseMessages,
    //     // ... other fields like profile_response
    // }
    ```
    For some connectors, the void response might be very minimal, perhaps just an HTTP status code with an empty body or a simple JSON like `{"status": "success", "transaction_id": "original_txn_id"}`.

### E. Implement `ForeignTryFrom` for Response (`transformers.rs`)
Implement `ForeignTryFrom` (or a direct `TryFrom` on `RouterDataV2`) to convert the connector's void response back into the generic `RouterDataV2`.

This involves:
1.  Determining the `HyperswitchAttemptStatus` (e.g., `Voided`, `Failure`).
2.  Populating `PaymentsResponseData`. For a successful void, `resource_id` might be the original `connector_transaction_id` or `ResponseId::NoResponseId` if the connector doesn't return it explicitly in the void response.
3.  Handling potential errors from the connector and mapping them to `ErrorResponse`.

*   **Example (Authorizedotnet-like, using a helper function):**
    Authorizedotnet uses a general `convert_to_payments_response_data_or_error` function, where an `Operation::Void` variant helps determine the status.
    ```rust
    // In backend/connector-integration/src/connectors/authorizedotnet/transformers.rs

    // pub enum Operation { Authorize, Capture, Void }

    // fn get_hs_status(response: &AuthorizedotnetPaymentsResponse, _http_status_code: u16, operation: Operation) -> hyperswitch_common_enums::enums::AttemptStatus {
    //     match response.messages.result_code {
    //         ResultCode::Error => hyperswitch_common_enums::enums::AttemptStatus::Failure,
    //         ResultCode::Ok => {
    //             match response.transaction_response {
    //                 Some(ref trans_res_enum) => {
    //                     // ... logic for Approved, Declined etc.
    //                     match trans_res.response_code {
    //                         AuthorizedotnetPaymentStatus::Approved => match operation {
    //                             // ...
    //                             Operation::Void => hyperswitch_common_enums::enums::AttemptStatus::Voided,
    //                         },
    //                         // ...
    //                     }
    //                 }
    //                 None => { // If transaction_response is null
    //                     match operation {
    //                         Operation::Void => hyperswitch_common_enums::enums::AttemptStatus::Voided, // Success if ResultCode is Ok
    //                         _ => hyperswitch_common_enums::enums::AttemptStatus::Pending,
    //                     }
    //                 }
    //             }
    //         }
    //     }
    // }

    // pub fn convert_to_payments_response_data_or_error(
    //     response: &AuthorizedotnetPaymentsResponse,
    //     http_status_code: u16,
    //     operation: Operation,
    // ) -> Result<(hyperswitch_common_enums::enums::AttemptStatus, Result<PaymentsResponseData, ErrorResponse>), HsInterfacesConnectorError> {
    //     let status = get_hs_status(response, http_status_code, operation);
    //     let response_payload_result = match &response.transaction_response {
    //         // ... existing logic ...
    //         None => { // No transaction_response part
    //             if status == hyperswitch_common_enums::enums::AttemptStatus::Voided && operation == Operation::Void {
    //                  Ok(PaymentsResponseData::TransactionResponse {
    //                     resource_id: ResponseId::NoResponseId, // Or original if known and expected
    //                     // ... other fields typically None or default for void
    //                 })
    //             } else {
    //                 // Handle as error or unexpected pending
    //                 Err(ErrorResponse { /* ... */ })
    //             }
    //         }
    //     };
    //     Ok((status, response_payload_result))
    // }

    // In connector_name.rs, handle_response_v2 would call this:
    // let (status, response_data_result) = authorizedotnet::convert_to_payments_response_data_or_error(
    //     &connector_response,
    //     res.status_code,
    //     authorizedotnet::Operation::Void,
    // )?;
    //
    // Ok(RouterDataV2 {
    //     response: response_data_result,
    //     resource_common_data: PaymentFlowData {
    //         status,
    //         ..data.resource_common_data
    //     },
    //     ..data.clone() // Or specific fields
    // })
    ```
    If not using a generic helper, a dedicated `ForeignTryFrom` for the Void response would be:
    ```rust
    // In backend/connector-integration/src/connectors/new_connector_name/transformers.rs
    impl ForeignTryFrom<(
        YourConnectorVoidResponse, // Connector-specific void response struct
        RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>,
        u16, // http_status_code
    )> for RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData> {
        type Error = error_stack::Report<errors::ConnectorError>; // Your project's error type

        fn foreign_try_from(
            item: (
                YourConnectorVoidResponse,
                RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>,
                u16,
            ),
        ) -> Result<Self, Self::Error> {
            let (connector_response, router_data_in, http_code) = item;
            
            // Determine status based on connector_response and http_code
            // Example:
            let final_status = if connector_response.is_successful() && http_code == 200 { // Replace with actual check
                HyperswitchAttemptStatus::Voided
            } else {
                HyperswitchAttemptStatus::Failure
            };

            if final_status == HyperswitchAttemptStatus::Voided {
                Ok(RouterDataV2 {
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(router_data_in.request.connector_transaction_id.clone()), // Or NoResponseId
                        redirection_data: Box::new(None),
                        mandate_reference: Box::new(None),
                        connector_metadata: None, // Or Some(serde_json::to_value(connector_response).unwrap_or_default()),
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                    }),
                    resource_common_data: PaymentFlowData {
                        status: final_status,
                        ..router_data_in.resource_common_data
                    },
                    ..router_data_in
                })
            } else {
                // Construct ErrorResponse
                let error_response = ErrorResponse {
                    code: connector_response.get_error_code().unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                    message: connector_response.get_error_message().unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                    reason: connector_response.get_error_reason(),
                    status_code: http_code,
                    attempt_status: Some(final_status),
                    connector_transaction_id: Some(router_data_in.request.connector_transaction_id.clone()),
                };
                Ok(RouterDataV2 {
                    response: Err(error_response),
                    resource_common_data: PaymentFlowData {
                        status: final_status, // Overall flow status is Failure
                        ..router_data_in.resource_common_data
                    },
                    ..router_data_in
                })
            }
        }
    }
    ```

### F. Implement `ConnectorIntegrationV2` for Void (`<connector_name>.rs`)
In your connector's main file (e.g., `backend/connector-integration/src/connectors/new_connector_name.rs`), implement the `ConnectorIntegrationV2` trait for the `Void` flow.

```rust
// In backend/connector-integration/src/connectors/new_connector_name.rs

// ... other imports ...
use domain_types::connector_flow::Void;
use domain_types::connector_types::{PaymentVoidData, PaymentFlowData, PaymentsResponseData}; // Adjust PaymentVoidData if it's named differently
use hyperswitch_common_utils::request::RequestContent;
use hyperswitch_interfaces::events::connector_api_logs::ConnectorEvent; // If using event_builder
use hyperswitch_interfaces::types::Response as HsResponse; // For raw response
// ...

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for NewConnectorName {
    fn get_headers(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Similar to Authorize/Capture: set Content-Type and Authorization headers
        let mut header = vec![(
            // headers::CONTENT_TYPE.to_string(), // If using crate::headers
            "Content-Type".to_string(),
            self.common_get_content_type().to_string().into(), // Assuming common_get_content_type from ConnectorCommon
        )];
        // Auth headers might come from a shared helper or be specific if auth type varies
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?; // Assuming get_auth_header
        header.append(&mut auth_headers);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Construct the void URL. For many connectors, this is the same base transaction processing URL.
        // Example: Authorizedotnet uses the same base URL for all createTransaction operations.
        Ok(format!(
            "{}", // The endpoint path might be constant or derived
            req.resource_common_data.connectors.your_connector_name.base_url // Or self.base_url()
        ))
        // Some connectors might require the transaction ID in the URL path for void:
        // Ok(format!(
        //     "{}/payments/{}/void",
        //     self.base_url(&req.resource_common_data.connectors),
        //     req.request.connector_transaction_id
        // ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // For Authorizedotnet, MerchantAuthentication is created first
        // let merchant_auth = your_connector_transformers::MerchantAuthentication::try_from(&req.connector_auth_type)?;
        // Then the specific request struct is created using this and router_data
        // let connector_req = your_connector_transformers::YourConnectorVoidRequest::try_from((req, merchant_auth))?;

        // Simpler example if auth is only in headers:
        let connector_req = your_connector_transformers::YourConnectorVoidRequest::try_from(req)?;

        Ok(Some(RequestContent::Json(Box::new(connector_req)))) // Or FormUrlEncoded, Xml as per connector
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>, // Optional: for logging connector events
        res: HsResponse, // The raw HTTP response from the connector
    ) -> CustomResult<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, errors::ConnectorError> {
        // Parse the raw response into your connector-specific void response struct
        let response_text = String::from_utf8(res.response.to_vec())
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)
            .attach_printable("Failed to convert connector response to String")?;
        
        let connector_response: your_connector_transformers::YourConnectorVoidResponse = 
            serde_json::from_str(&response_text) // Or serde_xml, serde_qs etc.
                .map_err(|e| errors::ConnectorError::ResponseDeserializationFailed)
                .attach_printable_lazy(|| format!("Failed to deserialize connector void response: {}", e))?;
        
        // with_response_body!(event_builder, connector_response); // Log if needed

        // Convert the connector's response (and original data) back to RouterDataV2
        // This might call a helper function or a ForeignTryFrom implementation
        // Example using Authorizedotnet's helper:
        // let (status, response_data_result) = your_connector_transformers::convert_to_payments_response_data_or_error(
        //     &connector_response, // Assuming it's the compatible general response type
        //     res.status_code,
        //     your_connector_transformers::Operation::Void,
        // )?;
        // Ok(RouterDataV2 {
        //     response: response_data_result,
        //     resource_common_data: PaymentFlowData { status, ..data.resource_common_data },
        //     ..data.clone()
        // })

        // Example using ForeignTryFrom:
        RouterDataV2::foreign_try_from((connector_response, data.clone(), res.status_code))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: HsResponse,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Reuse the common error response building logic if applicable
        self.build_error_response(res, event_builder) // Assumes build_error_response is defined
    }

    fn get_5xx_error_response(
        &self,
        res: HsResponse,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}
```

## 3. Key Considerations

*   **Transaction State**: Void operations are typically only valid for transactions that are authorized but not yet captured/settled. Attempting to void a captured or already voided transaction will usually result in an error.
*   **No Amount**: Void requests generally do not include an amount field. The entire authorized amount is voided.
*   **Original Transaction ID**: The `connector_transaction_id` from the original Authorize call is almost always required.
*   **Endpoint URL**: The void endpoint might be the same as other transaction endpoints or a specific one.
*   **Error Handling**: Map connector-specific error codes for void failures (e.g., "transaction already settled", "transaction not found") to the standard `ErrorResponse` structure.
*   **Response Status**: Correctly map the connector's void response status (e.g., "voided", "cancelled", "success") to `HyperswitchAttemptStatus::Voided` or `HyperswitchAttemptStatus::Failure`.
*   **Idempotency**: If the connector supports idempotency keys for void, consider implementing them.

## 4. Referencing Authorizedotnet

*   **Authorizedotnet (`authorizedotnet.rs`, `authorizedotnet/transformers.rs`):**
    *   Void request (`AuthorizedotnetVoidRequest`) involves a `transaction_type` set to `VoidTransaction` and the `ref_trans_id` (original connector transaction ID).
    *   It uses the same `createTransactionRequest` structure as Authorize and Capture, but with different inner `transaction_request` details.
    *   The response handling is part of a more generic `convert_to_payments_response_data_or_error` function, distinguished by an `Operation::Void` parameter. A successful void might not have a `transaction_response` block in the JSON but will have `messages.result_code == Ok`.

Study how `authorizedotnet` handles:
*   Construction of the void request in `get_request_body` and the `TryFrom` implementation for `AuthorizedotnetVoidRequest`.
*   Interpretation of the response in `handle_response_v2` and the `convert_to_payments_response_data_or_error` helper, specifically for `Operation::Void`.

## 5. Testing

*   Thoroughly test the void flow with various scenarios:
    *   Voiding a successfully authorized (but not captured) transaction.
    *   Attempting to void an already captured transaction.
    *   Attempting to void an already voided transaction.
    *   Attempting to void a transaction that failed authorization.
    *   Attempting to void with an invalid/non-existent `connector_transaction_id`.
    *   Test error responses from the connector for void operations.
*   Use `cargo build` frequently to catch compilation errors.
*   Add unit tests for your transformer logic if it's complex.

By following these steps and referring to existing connector implementations like Authorizedotnet, you can successfully add the Void flow to your connector. 