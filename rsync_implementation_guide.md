# Elavon RSync (Refund Sync) Implementation Guide

This document outlines the implementation of the Refund Sync (RSync) flow for the Elavon connector.

## 1. Overview

The RSync flow allows the system to query the status of a previously initiated refund with Elavon. Elavon typically uses a general transaction query mechanism (`TxnQuery`) for various transaction types, including refunds. The key is to correctly interpret the response status for a refund transaction.

## 2. File Changes

### 2.1. `backend/connector-integration/src/connectors/elavon/transformers.rs`

*   **Import `RefundStatus as HyperswitchRefundStatus`**:
    ```rust
    use hyperswitch_common_enums::{
        // ... other imports
        RefundStatus as HyperswitchRefundStatus,
    };
    ```

*   **`ElavonRSyncRequest` Struct**:
    Defines the request structure for an RSync operation. It's similar to `ElavonPsyncRequest` as both use `TxnQuery`.
    ```rust
    #[derive(Debug, Serialize)]
    pub struct ElavonRSyncRequest {
        pub ssl_transaction_type: TransactionType, // Will be TransactionType::TxnQuery
        pub ssl_account_id: Secret<String>,
        pub ssl_user_id: Secret<String>,
        pub ssl_pin: Secret<String>,
        pub ssl_txn_id: String, // The connector_refund_id (original connector_transaction_id of the refund)
    }
    ```

*   **`TryFrom` for `ElavonRSyncRequest`**:
    Converts `RouterDataV2<RSync, ...>` into `ElavonRSyncRequest`.
    ```rust
    impl TryFrom<&RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>> for ElavonRSyncRequest {
        type Error = error_stack::Report<errors::ConnectorError>;

        fn try_from(
            router_data: &RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>,
        ) -> Result<Self, Self::Error> {
            let auth_type = ElavonAuthType::try_from(&router_data.connector_auth_type)?;
            let connector_refund_id = router_data.request.get_connector_refund_id()?; // Get the ID of the refund to query

            Ok(Self {
                ssl_transaction_type: TransactionType::TxnQuery,
                ssl_account_id: auth_type.ssl_merchant_id,
                ssl_user_id: auth_type.ssl_user_id,
                ssl_pin: auth_type.ssl_pin,
                ssl_txn_id: connector_refund_id,
            })
        }
    }
    ```

*   **`ElavonRSyncResponse` Struct**:
    Defines the expected response structure from Elavon's `TxnQuery` for a refund. It mirrors `ElavonPSyncResponse` as the underlying API call is the same.
    ```rust
    #[derive(Debug, Deserialize, Clone)]
    pub struct ElavonRSyncResponse {
        pub ssl_trans_status: TransactionSyncStatus, // e.g., PEN, OPN, STL
        pub ssl_transaction_type: SyncTransactionType, // e.g., Sale, Return
        pub ssl_txn_id: String, // Original transaction ID
    }
    ```

*   **`get_refund_status_from_elavon_sync_response` Helper Function**:
    Maps Elavon's `ssl_trans_status` and `ssl_transaction_type` to `HyperswitchRefundStatus`.
    ```rust
    fn get_refund_status_from_elavon_sync_response(
        elavon_response: &ElavonRSyncResponse,
    ) -> HyperswitchRefundStatus {
        match elavon_response.ssl_transaction_type {
            SyncTransactionType::Return => { // Crucial to check if the queried transaction is indeed a refund
                match elavon_response.ssl_trans_status {
                    TransactionSyncStatus::STL => HyperswitchRefundStatus::Success,
                    TransactionSyncStatus::PEN | TransactionSyncStatus::OPN => HyperswitchRefundStatus::Pending,
                    TransactionSyncStatus::REV => HyperswitchRefundStatus::ManualReview,
                    TransactionSyncStatus::PST | TransactionSyncStatus::FPR | TransactionSyncStatus::PRE => HyperswitchRefundStatus::Failure,
                }
            }
            _ => HyperswitchRefundStatus::Pending, // Default or if transaction type is not 'Return'
        }
    }
    ```

*   **`ForeignTryFrom` for `RouterDataV2<RSync, ...>`**:
    Converts `ElavonRSyncResponse` (and HTTP status) back into `RouterDataV2<RSync, ...>`.
    ```rust
    impl ForeignTryFrom<(
        ElavonRSyncResponse,
        RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>,
        u16, // http_status_code
    )> for RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData> {
        type Error = error_stack::Report<errors::ConnectorError>;

        fn foreign_try_from(
            item: (
                ElavonRSyncResponse,
                RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>,
                u16,
            ),
        ) -> Result<Self, Self::Error> {
            let (elavon_response, router_data_in, _http_status_code) = item;

            let refund_status = get_refund_status_from_elavon_sync_response(&elavon_response);

            Ok(
                RouterDataV2::from((
                    router_data_in,
                    domain_types::connector_types::RefundsResponseData {
                        refund_status,
                        connector_refund_id: elavon_response.ssl_txn_id.clone(),
                    },
                )).set_resource_common_data(|_common_data| {
                    // Optionally set raw_response if needed
                    // common_data.raw_response = serde_json::to_value(elavon_response.clone()).ok();
                })
            )
        }
    }
    ```

### 2.2. `backend/connector-integration/src/connectors/elavon.rs`

*   **`ConnectorIntegrationV2<RSync, ...>` Implementation**:
    ```rust
    impl connector_integration_v2::ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Elavon {
        fn get_http_method(&self) -> hyperswitch_common_utils::request::Method {
            hyperswitch_common_utils::request::Method::Post // Elavon uses POST for TxnQuery
        }

        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?; // Though auth is in body for Elavon
            header.append(&mut api_key);
            Ok(header)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, hs_errors::ConnectorError> {
            // The endpoint for TxnQuery is typically the same as other transaction posts.
            Ok(format!("{}/processxml.asp", self.base_url(&req.connector_meta_data)))
        }

        fn get_request_body(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> {
            let elavon_request = elavon::ElavonRSyncRequest::try_from(req)?;
            let form_payload = struct_to_xml(&elavon_request)?; // Uses the existing struct_to_xml helper

            Ok(Some(RequestContent::FormUrlEncoded(form_payload)))
        }

        fn handle_response_v2(
            &self,
            data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            event_builder: Option<&mut ConnectorEvent>,
            res: hs_types::Response,
        ) -> CustomResult<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, hs_errors::ConnectorError> {
            // Deserialize into ElavonRSyncResponse first
            let response_data = deserialize_xml_to_struct::<elavon::ElavonRSyncResponse>(&res.response)
                .change_context(hs_errors::ConnectorError::ResponseDeserializationFailed)?;
            with_response_body!(event_builder, response_data); // Log the raw response if event_builder is present

            // Convert ElavonRSyncResponse to RouterDataV2<RSync, ...>
            RouterDataV2::foreign_try_from((
                response_data,
                data.clone(), // Clone to pass ownership if necessary for ForeignTryFrom
                res.status_code,
            ))
        }

        fn get_error_response_v2(
            &self,
            res: hs_types::Response,
            event_builder: Option<&mut ConnectorEvent>,
        ) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> {
            // Reuse the common error response builder. If TxnQuery itself fails at Elavon's end
            // (e.g., malformed XML, invalid merchant details), it might return an error in the
            // standard ElavonPaymentsResponse format.
            self.build_error_response(res, event_builder)
        }
    }
    ```

## 3. Key Considerations

*   **Transaction Type (`ssl_transaction_type`)**: The request uses `TransactionType::TxnQuery`. The response's `ssl_transaction_type` (e.g., `SyncTransactionType::Return`) should be checked to ensure the status being interpreted is for a refund.
*   **Status Mapping (`ssl_trans_status`)**: The `ssl_trans_status` field from Elavon's response needs careful mapping to `HyperswitchRefundStatus`. The `get_refund_status_from_elavon_sync_response` function handles this.
*   **Error Handling**: The `get_error_response_v2` reuses `build_error_response`. This assumes that errors from the `TxnQuery` API call itself (not business logic errors about the refund status) will come in a format parsable by `ElavonPaymentsResponse`. If `TxnQuery` has a distinct error structure for API-level failures, `build_error_response` or a new error handler might need adjustment.
*   **Idempotency**: RSync operations are typically idempotent by nature as they are read operations.
*   **XML Serialization/Deserialization**: Uses the existing `struct_to_xml` and `deserialize_xml_to_struct` helpers. Ensure `ElavonRSyncResponse` is correctly annotated for `quick_xml` deserialization if its structure deviates significantly from other query responses (though it's expected to be similar).

## 4. Testing

*   Verify that RSync correctly retrieves the status of successful refunds.
*   Verify correct status mapping for pending refunds.
*   Verify correct status mapping for failed refunds (if Elavon provides distinct failed states via `TxnQuery` for refunds).
*   Test scenarios where the `connector_refund_id` is not found or invalid.
*   Test error responses from Elavon during the RSync API call. 