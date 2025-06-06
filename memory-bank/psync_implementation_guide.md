# Connector PSync (Payment Sync) Flow Implementation Guide

This guide provides step-by-step instructions for implementing the PSync (Payment Sync) flow for a connector in the service. This flow is used to query the status of a previously initiated payment transaction.

## Table of Contents
1.  [Prerequisites](#prerequisites)
2.  [Implementing PSync Flow](#implementing-psync-flow)
    *   [A. Update Connector Trait Implementations (`<connector_name>.rs`)](#a-update-connector-trait-implementations--connector_namers)
    *   [B. Define Request Structures (`transformers.rs`)](#b-define-request-structures-transformersrs)
    *   [C. Implement `TryFrom` for Request (`transformers.rs`)](#c-implement-tryfrom-for-request-transformersrs)
    *   [D. Define Response Structures (`transformers.rs`)](#d-define-response-structures-transformersrs)
    *   [E. Implement `ForeignTryFrom` for Response (`transformers.rs`)](#e-implement-foreigntryfrom-for-response-transformersrs)
3.  [Key Considerations](#key-considerations)
4.  [Testing](#testing)

## Prerequisites

*   The connector is already set up as per the `connector_implementation_guide.md`.
*   The Authorize flow (and potentially Capture/Refund if they generate the transaction IDs to be synced) should be functional or understood.
*   Familiarity with the connector's API documentation for querying transaction status.

## Implementing PSync Flow

### A. Update Connector Trait Implementations (`<connector_name>.rs`)

Ensure your main connector struct implements the necessary traits for PSync.

```rust
// In backend/connector-integration/src/connectors/<connector_name>.rs

// ... other imports ...
use domain_types::connector_flow::PSync; // Ensure PSync is imported
use domain_types::connector_types::{PaymentFlowData, PaymentsSyncData, PaymentsResponseData};
use hyperswitch_domain_models::router_request_types::SyncRequestType; // If handling multiple capture sync

// ... Ensure your connector struct exists ...
// pub struct Elavon { ... }

// Ensure the PSync V2 trait is implemented (if not already by a blanket impl)
// impl PaymentSyncV2 for Elavon {}

impl connector_integration_v2::ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Elavon // Replace Elavon with your connector name
{
    fn get_http_method(&self) -> hyperswitch_common_utils::request::Method {
        // Typically GET or POST, depending on the connector's API
        // Elavon uses POST for TxnQuery
        hyperswitch_common_utils::request::Method::Post
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(), // Or specific content type for PSync
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, hs_errors::ConnectorError> {
        // Construct the URL for the connector's PSync/Transaction Query endpoint.
        // This often involves using the connector_transaction_id from req.request.
        // Example for Elavon (uses the same base endpoint):
        Ok(format!("{}processxml.do", req.resource_common_data.connectors.elavon.base_url))
        // Example for a connector with a dedicated sync endpoint using payment_id:
        // let payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
        //     .change_context(hs_errors::ConnectorError::MissingConnectorTransactionID)?;
        // Ok(format!("{}/payments/{}", self.base_url(&req.resource_common_data.connectors), payment_id))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> {
        // Create the connector-specific request struct for PSync.
        // Example for Elavon:
        let elavon_req = elavon::ElavonPsyncRequest::try_from(req) // Note: pass `req` directly
            .change_context(hs_errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to create ElavonPsyncRequest")?;

        // Serialize to the required format (e.g., XML for Elavon, JSON for others)
        Ok(Some(RequestContent::FormUrlEncoded(Box::new(super::struct_to_xml(
            &elavon_req,
        )?)))) // For Elavon (XML in form data)
        // For JSON: Ok(Some(RequestContent::Json(Box::new(connector_req))))
        // If no body is needed (e.g. for GET requests with ID in URL): Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: hs_types::Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, hs_errors::ConnectorError> {
        // Deserialize the connector's response into your PSync response struct.
        // Example for Elavon (response is XML, deserialized into ElavonPSyncResponse):
        let response: elavon::ElavonPSyncResponse = super::deserialize_xml_to_struct(&res.response)
            .change_context(hs_errors::ConnectorError::ResponseDeserializationFailed)?;
        
        with_response_body!(event_builder, response); // Log the raw response

        // Determine if this is for multiple capture sync if your connector supports it.
        let is_multiple_capture_sync = match data.request.sync_type {
            SyncRequestType::MultipleCaptureSync(_) => true,
            SyncRequestType::SinglePaymentSync => false,
        };

        // Transform the connector's response struct back into RouterDataV2 using ForeignTryFrom.
        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code,
            data.request.capture_method, // May or may not be relevant for PSync status mapping
            is_multiple_capture_sync,
            data.request.payment_method_type, // May or may not be relevant
        ))
        .change_context(hs_errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(&self, res: hs_types::Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> {
        // Use the common error response builder, or a specific one if PSync errors are different.
        self.build_error_response(res, event_builder)
    }

    // Optional: If your connector handles multiple captures and syncs them individually.
    // fn get_multiple_capture_sync_method(&self) -> CustomResult<CaptureSyncMethod, errors::ConnectorError> {
    //     Ok(CaptureSyncMethod::Individual) // Or Batched
    // }
}
```

### B. Define Request Structures (`transformers.rs`)

In your connector's `transformers.rs` file (`backend/connector-integration/src/connectors/<connector_name>/transformers.rs`):

1.  **Add PSync to `TransactionType` (or similar enum if used by your connector for requests):**

    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs
    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum TransactionType {
        // ... other types ...
        TxnQuery,   // For Elavon's PSync
    }
    ```

2.  **Define the PSync Request struct:** This struct should model the payload your connector expects for a status query.

    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs
    use hyperswitch_masking::Secret;
    use hyperswitch_common_enums::Currency; // If currency is needed

    #[skip_serializing_none]
    #[derive(Debug, Serialize)]
    pub struct ElavonPsyncRequest { // Replace ElavonPsyncRequest with <YourConnectorName>PsyncRequest
        pub ssl_transaction_type: TransactionType, // e.g., TxnQuery for Elavon
        // Authentication fields (often required for Elavon in the body)
        pub ssl_account_id: Secret<String>,
        pub ssl_user_id: Secret<String>,
        pub ssl_pin: Secret<String>,
        pub ssl_txn_id: String, // The connector_transaction_id of the payment to query
        // Add other fields as required by your connector's API for PSync.
        // e.g., pub original_reference: String,
        // e.g., pub query_scope: String,
    }
    ```

### C. Implement `TryFrom` for Request (`transformers.rs`)

Convert the generic `RouterDataV2<PSync, ...>` into your connector-specific PSync request struct.

```rust
// In backend/connector-integration/src/connectors/elavon/transformers.rs
use domain_types::{
    connector_flow::PSync,
    connector_types::{PaymentFlowData, PaymentsSyncData, PaymentsResponseData, ResponseId as DomainResponseId},
};
use crate::connectors::elavon::ElavonAuthType; // Your connector's AuthType

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>> 
    for ElavonPsyncRequest { // Replace ElavonPsyncRequest
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let request_data = &router_data.request;
        let auth_type = ElavonAuthType::try_from(&router_data.connector_auth_type)?;

        let connector_txn_id = match &request_data.connector_transaction_id {
            DomainResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(report!(errors::ConnectorError::MissingConnectorTransactionID))
                       .attach_printable("Missing connector_transaction_id for PSync"),
        };

        Ok(Self {
            ssl_transaction_type: TransactionType::TxnQuery, // Or your connector's equivalent
            ssl_account_id: auth_type.ssl_merchant_id, // Map auth details
            ssl_user_id: auth_type.ssl_user_id,
            ssl_pin: auth_type.ssl_pin,
            ssl_txn_id: connector_txn_id,
            // Map other necessary fields from router_data or its nested structs.
        })
    }
}
```

### D. Define Response Structures (`transformers.rs`)

Define structs that can deserialize the connector's response for a PSync query. This might involve fields indicating the transaction status, type, IDs, and potentially error details if the query itself had issues (though often, API call errors are handled by `build_error_response`).

```rust
// In backend/connector-integration/src/connectors/elavon/transformers.rs

// Example for Elavon, which has specific status and type enums for TxnQuery response:
#[derive(Debug, Deserialize, Serialize, Clone)] // Ensure Deserialize is derived
pub struct ElavonPSyncResponse { // Replace ElavonPSyncResponse
    pub ssl_trans_status: TransactionSyncStatus,
    pub ssl_transaction_type: SyncTransactionType,
    pub ssl_txn_id: String,
    // Potentially other fields returned by the connector for a sync query
    // pub ssl_amount: Option<StringMajorUnit>,
    // pub ssl_currency: Option<Currency>,
    // pub ssl_approval_code: Option<String>,
}

// Enum for Elavon's specific transaction status in PSync response
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TransactionSyncStatus {
    PEN, // Pended
    OPN, // Unpended / release / open
    REV, // Review
    STL, // Settled
    PST, // Failed due to post-auth rule
    FPR, // Failed due to fraud prevention rules
    PRE, // Failed due to pre-auth rule
}

// Enum for Elavon's specific transaction type in PSync response
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum SyncTransactionType {
    Sale,
    AuthOnly,
    Return,
}

// If your connector returns a more generic success/error wrapper like Authorize:
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ConnectorPsyncSuccessResponse { ... }
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ConnectorPsyncErrorResponse { ... }
// #[derive(Debug, Clone, Serialize, Deserialize)]
// #[serde(untagged)]
// pub enum ConnectorPsyncResult {
// Success(ConnectorPsyncSuccessResponse),
// Error(ConnectorPsyncErrorResponse),
// }
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct YourConnectorPsyncResponseContainer {
// pub result: ConnectorPsyncResult, // Or whatever the top-level field is
// }

```

### E. Implement `ForeignTryFrom` for Response (`transformers.rs`)

Convert the connector's PSync response struct back into `RouterDataV2<PSync, ...>`. This involves mapping the connector's status fields to `HyperswitchAttemptStatus` and populating `PaymentsResponseData`.

```rust
// In backend/connector-integration/src/connectors/elavon/transformers.rs
use hyperswitch_common_enums::AttemptStatus as HyperswitchAttemptStatus;
use hyperswitch_domain_models::router_data::ErrorResponse; // If you need to construct ErrorResponse
use hyperswitch_interfaces::consts as hs_interface_consts;

impl
    ForeignTryFrom<(
        ElavonPSyncResponse, // Your connector's PSync response struct
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        u16, // http_code (may or may not be needed if response struct implies API call success)
        Option<HyperswitchCaptureMethod>, // capture_method from original request (contextual)
        bool, // is_multiple_capture_sync
        Option<hyperswitch_api_models::enums::PaymentMethodType>, // pmt (contextual)
    )> for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        item: (
            ElavonPSyncResponse, // Your connector's PSync response struct
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            u16, // http_code
            Option<HyperswitchCaptureMethod>,
            bool, // is_multiple_capture_sync
            Option<hyperswitch_api_models::enums::PaymentMethodType>,
        ),
    ) -> Result<Self, Self::Error> {
        let (connector_response, router_data_in, _http_code, _capture_method, _is_multiple_capture_sync, _pmt) = item;

        // --- Map Connector Status to HyperswitchAttemptStatus ---
        // This is highly connector-specific. Refer to API docs.
        // Example for ElavonPSyncResponse:
        let final_status = match connector_response.ssl_trans_status {
            TransactionSyncStatus::STL => { // Settled
                match connector_response.ssl_transaction_type {
                    SyncTransactionType::Sale => HyperswitchAttemptStatus::Charged,
                    SyncTransactionType::AuthOnly => HyperswitchAttemptStatus::Charged, // Settled AuthOnly means captured
                    SyncTransactionType::Return => HyperswitchAttemptStatus::AutoRefunded, // PSync on a payment that was refunded
                }
            }
            TransactionSyncStatus::OPN => { // Open / Unpended
                match connector_response.ssl_transaction_type {
                    SyncTransactionType::AuthOnly => HyperswitchAttemptStatus::Authorized,
                    SyncTransactionType::Sale => HyperswitchAttemptStatus::Pending, // Sale is open but not settled
                    SyncTransactionType::Return => HyperswitchAttemptStatus::Pending, // Refund is open/initiated
                }
            }
            TransactionSyncStatus::PEN | TransactionSyncStatus::REV => HyperswitchAttemptStatus::Pending,
            TransactionSyncStatus::PST | TransactionSyncStatus::FPR | TransactionSyncStatus::PRE => {
                if connector_response.ssl_transaction_type == SyncTransactionType::AuthOnly && connector_response.ssl_trans_status == TransactionSyncStatus::PRE {
                    HyperswitchAttemptStatus::AuthenticationFailed
                } else {
                    HyperswitchAttemptStatus::Failure
                }
            }
        };
        // --- End Status Mapping ---

        // Populate PaymentsResponseData
        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: DomainResponseId::ConnectorTransactionId(connector_response.ssl_txn_id.clone()),
            redirection_data: Box::new(None), // PSync typically doesn't involve redirection
            mandate_reference: Box::new(None), // PSync typically doesn't return mandate info
            connector_metadata: Some(serde_json::json!(connector_response)), // Store raw response as metadata
            network_txn_id: None, // Populate if available in connector_response, e.g., connector_response.ssl_approval_code
            connector_response_reference_id: None, // Populate if available
            incremental_authorization_allowed: None, // Typically not applicable for PSync
        };

        Ok(RouterDataV2 {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status: final_status,
                ..router_data_in.resource_common_data
            },
            ..router_data_in
        })
    }
}
```

## Key Considerations

*   **Status Mapping**: Accurately map the connector's transaction statuses to `HyperswitchAttemptStatus`. This is crucial for consistent state management. Consult the connector's API documentation thoroughly.
*   **Error Handling**: Differentiate between errors in the PSync API call itself (e.g., auth failure, invalid request, handled by `build_error_response`) and statuses of the queried transaction (e.g., payment failed, payment pending, payment successful).
*   **Idempotency**: PSync calls should be idempotent. Retrying a PSync should not have unintended side effects.
*   **Request Parameters**: Ensure all required parameters for the connector's status query API are included. Some connectors might require more than just the transaction ID (e.g., original amount, currency, merchant identifiers).
*   **Response Data**: Capture all relevant information from the connector's PSync response, such as updated status, amounts, fees, error codes/messages related to the original transaction, and any new reference IDs.
*   **Multiple Captures**: If your connector supports multiple partial captures for a single authorization, consider how PSync will behave. `get_multiple_capture_sync_method` can be implemented if the connector allows syncing individual captures or a batch of captures.

## Testing

*   **Test Cases**: Create test cases for various scenarios:
    *   Syncing a successful (Captured/Charged) payment.
    *   Syncing an authorized but not captured payment.
    *   Syncing a pending payment.
    *   Syncing a failed payment.
    *   Syncing a refunded payment (if PSync also returns refund status).
    *   Syncing a voided payment.
    *   Attempting to sync a non-existent transaction ID.
*   **Connector Sandbox**: Utilize the connector's sandbox environment to test these scenarios.
*   **Status Consistency**: Verify that the status returned by PSync aligns with the status observed after other flows (Authorize, Capture, Refund).
*   **Error Responses**: Test how the connector handles invalid PSync requests (e.g., malformed transaction ID, authentication issues for the PSync call itself).

This guide provides a comprehensive overview. Always refer to the specific connector's API documentation for the most accurate and detailed information. 