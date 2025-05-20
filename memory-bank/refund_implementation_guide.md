# Connector Refund Flow Implementation Guide

This guide provides step-by-step instructions for implementing the payment refund flow for a new or existing connector in the connector service. It assumes that the connector has already been set up as per the `connector_implementation_guide.md` and that the Authorize and Capture flows are functional.

## Table of Contents
1.  [Prerequisites](#prerequisites)
2.  [Implementing Refund Flow](#implementing-refund-flow)
    *   [A. Update Connector Trait Implementations](#a-update-connector-trait-implementations)
    *   [B. Define Request Structures (`transformers.rs`)](#b-define-request-structures-transformersrs)
    *   [C. Implement `TryFrom` for Request (`transformers.rs`)](#c-implement-tryfrom-for-request-transformersrs)
    *   [D. Define Response Structures (`transformers.rs`)](#d-define-response-structures-transformersrs)
    *   [E. Implement `ForeignTryFrom` for Response (`transformers.rs`)](#e-implement-foreigntryfrom-for-response-transformersrs)
    *   [F. Implement `ConnectorIntegrationV2` for Refund (`<connector_name>.rs`)](#f-implement-connectorintegrationv2-for-refund-connector_namers)
3.  [Key Considerations](#key-considerations)
4.  [Referencing Razorpay and Elavon](#referencing-razorpay-and-elavon)
5.  [Testing](#testing)

## 1. Prerequisites

*   The connector is already added to the framework (as per `connector_implementation_guide.md`).
*   The Authorize and Capture flows for the connector are implemented and working.
*   You have the connector's API documentation for the "Refund" or "Return" operation. This typically involves sending the original transaction ID (obtained from authorize/capture) and the amount to refund.

## 2. Implementing Refund Flow

### A. Update Connector Trait Implementations
In your connector's main file (e.g., `backend/connector-integration/src/connectors/new_connector_name.rs`):

Ensure that the `RefundV2` (and `RefundSyncV2` if applicable) trait is implemented for your connector struct.

```rust
// In backend/connector-integration/src/connectors/new_connector_name.rs

// ... other imports ...
use domain_types::connector_types::{RefundV2, RefundSyncV2}; // Ensure these are imported

// ... struct definition ...

impl RefundV2 for NewConnectorName {} // Add this line if not present
// impl RefundSyncV2 for NewConnectorName {} // Add if you will implement sync for refunds

// ... other trait implementations ...
```

### B. Define Request Structures (`transformers.rs`)
In your connector's `transformers.rs` file (e.g., `backend/connector-integration/src/connectors/new_connector_name/transformers.rs`):

Define the request structure that your connector expects for a refund API call.

*   **Example (Elavon-like, where refund is `CcReturn`):**
    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs

    // TransactionType enum should already exist, ensure CcReturn is there
    // pub enum TransactionType {
    //     // ... other types ...
    //     CcReturn, // <<< For Refund
    // }

    #[skip_serializing_none]
    #[derive(Debug, Serialize)]
    pub struct ElavonRefundRequest {
        pub ssl_transaction_type: TransactionType,
        pub ssl_account_id: Secret<String>, // Merchant account ID from auth
        pub ssl_user_id: Secret<String>,    // User ID from auth
        pub ssl_pin: Secret<String>,        // PIN from auth
        pub ssl_amount: StringMajorUnit,    // Amount to refund
        pub ssl_txn_id: String,             // The original transaction ID to be refunded
        pub ssl_transaction_currency: Currency,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ssl_invoice_number: Option<String>, // Optional: original or new refund invoice
    }
    ```

*   **Example (Razorpay-like):**
    ```rust
    // In backend/connector-integration/src/connectors/razorpay/transformers.rs
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")] // Or camelCase, check connector docs
    pub struct RazorpayRefundRequest {
        pub amount: MinorUnit, // Amount to refund
        // currency and other fields might be part of the URL or implicit
    }
    ```
    (Note: Razorpay's refund URL includes the payment ID, and the request body is simple.)

**Key Fields for Refund Request:**
*   Original `connector_transaction_id` (from the Authorize/Capture step that needs to be refunded).
*   `amount_to_refund` (this might be the full captured amount or a partial amount).
*   Currency (often part of amount or a separate field).
*   Reason for refund (optional, connector-dependent).
*   Authentication details if required by the refund endpoint.

### C. Implement `TryFrom` for Request (`transformers.rs`)
Create a `TryFrom` implementation to convert the generic `RouterDataV2` for the Refund flow into your connector-specific refund request struct.

This involves:
1.  Extracting authentication details (`ConnectorAuthType`).
2.  Getting the `connector_transaction_id` from `router_data.request`.
3.  Getting the `minor_refund_amount` from `router_data.request` (and converting it as needed).
4.  Mapping any other required fields like currency or original payment ID as an invoice/reference.

*   **Example (Elavon-like):**
    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs

    impl TryFrom<&ElavonRouterData<&RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>>> for ElavonRefundRequest {
        type Error = error_stack::Report<errors::ConnectorError>;
        fn try_from(
            item: &ElavonRouterData<&RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>>,
        ) -> Result<Self, Self::Error> {
            let router_data = item.router_data;
            let request_data = &router_data.request;
            let auth_type = ElavonAuthType::try_from(&router_data.connector_auth_type)?;

            let original_connector_txn_id = match &request_data.connector_transaction_id {
                DomainResponseId::ConnectorTransactionId(id) => id.clone(),
                _ => return Err(report!(errors::ConnectorError::MissingConnectorTransactionID))
                           .attach_printable("Missing connector_transaction_id for Elavon Refund"),
            };

            Ok(Self {
                ssl_transaction_type: TransactionType::CcReturn,
                ssl_account_id: auth_type.ssl_merchant_id,
                ssl_user_id: auth_type.ssl_user_id,
                ssl_pin: auth_type.ssl_pin,
                ssl_amount: item.amount.clone(), // Amount already converted to StringMajorUnit
                ssl_txn_id: original_connector_txn_id,
                ssl_transaction_currency: request_data.currency,
                ssl_invoice_number: Some(request_data.payment_id.clone()), // Using original payment_id as ref
            })
        }
    }
    ```

*   **Example (Razorpay-like):**
    ```rust
    // In backend/connector-integration/src/connectors/razorpay/transformers.rs

    impl TryFrom<&RazorpayRouterData<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>> for RazorpayRefundRequest {
        type Error = errors::ConnectorError;
        fn try_from(
            item: &RazorpayRouterData<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                amount: item.amount, // Amount already converted to MinorUnit
            })
        }
    }
    ```

### D. Define Response Structures (`transformers.rs`)
Define the structure(s) that your connector returns for a refund API call.

*   **Example (Elavon-like, reusing `ElavonResult` and `PaymentResponse`):**
    Elavon's refund response (`CcReturn`) often mirrors its other transaction responses.
    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs
    // Assume ElavonResult and PaymentResponse are already defined.
    // pub enum SslResult { Approved, Declined, Other }
    // pub struct PaymentResponse {
    //     pub ssl_result: SslResult,
    //     pub ssl_txn_id: String, // May be a new ID for refund or the original
    //     pub ssl_result_message: String,
    //     pub ssl_transaction_type: Option<String>, // "ccreturn" for successful refund
    //     // ... other fields
    // }
    // pub enum ElavonResult { Success(PaymentResponse), Error(ElavonErrorResponse) }
    // pub struct ElavonPaymentsResponse { pub result: ElavonResult }
    ```

*   **Example (Razorpay-like):**
    ```rust
    // In backend/connector-integration/src/connectors/razorpay/transformers.rs
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub struct RazorpayRefundResponse {
        pub id: String, // Connector's refund ID
        pub status: RazorpayRefundStatus, // e.g., "processed", "pending", "failed"
        pub receipt: Option<String>,
        pub amount: i64,
        pub currency: String,
    }

    // Ensure RazorpayRefundStatus enum is defined:
    // #[derive(Debug, Clone, Serialize, Deserialize)]
    // #[serde(rename_all = "lowercase")]
    // pub enum RazorpayRefundStatus {
    //     Created, // Could map to Pending
    //     Processed, // Maps to Success
    //     Failed,
    //     Pending,
    // }
    ```

### E. Implement `ForeignTryFrom` for Response (`transformers.rs`)
Implement `ForeignTryFrom` to convert the connector's refund response back into the generic `RouterDataV2`.

This involves:
1.  Determining the `hyperswitch_common_enums::RefundStatus` (e.g., `Success`, `Failure`, `Pending`).
2.  Populating `RefundsResponseData` with `connector_refund_id` and `refund_status`.
3.  Handling potential errors and mapping them to `ErrorResponse`.

*   **Example (Elavon-like):**
    ```rust
    // In backend/connector-integration/src/connectors/elavon/transformers.rs

    impl ForeignTryFrom<(
        ElavonResult,
        RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>,
        u16, // http_code
    )> for RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData> {
        type Error = error_stack::Report<errors::ConnectorError>;

        fn foreign_try_from(
            item: (
                ElavonResult,
                RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>,
                u16,
            ),
        ) -> Result<Self, Self::Error> {
            let (elavon_response_result, router_data_in, http_code) = item;
            let (attempt_status, error_response_opt) = get_elavon_attempt_status(&elavon_response_result, http_code); // Note: get_elavon_attempt_status might need to be aware of refund context or a new helper created if logic diverges significantly.
            
            match elavon_response_result {
                ElavonResult::Success(success_payload) => {
                    let refund_status = match success_payload.ssl_transaction_type.as_deref() {
                        Some("ccreturn") => match success_payload.ssl_result {
                            SslResult::Approved => hyperswitch_common_enums::RefundStatus::Success,
                            SslResult::Declined => hyperswitch_common_enums::RefundStatus::Failure,
                            SslResult::Other(_) => hyperswitch_common_enums::RefundStatus::Pending,
                        },
                        _ => hyperswitch_common_enums::RefundStatus::Pending, // Unexpected type
                    };

                    let response_data = domain_types::connector_types::RefundsResponseData {
                        connector_refund_id: success_payload.ssl_txn_id.clone(),
                        refund_status,
                    };
                    
                    Ok(RouterDataV2 {
                        response: Ok(response_data),
                        resource_common_data: domain_types::connector_types::RefundFlowData {
                            status: refund_status, 
                            ..router_data_in.resource_common_data
                        },
                        ..router_data_in
                    })
                }
                ElavonResult::Error(error_payload_struct) => {
                    let final_error_response = error_response_opt.unwrap_or_else(|| /* ... build error ... */);
                    Ok(RouterDataV2 {
                        response: Err(final_error_response),
                        resource_common_data: domain_types::connector_types::RefundFlowData {
                            status: hyperswitch_common_enums::RefundStatus::Failure,
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
    impl ForeignTryFrom<RazorpayRefundStatus> for hyperswitch_common_enums::RefundStatus {
        type Error = hyperswitch_interfaces::errors::ConnectorError;
        fn foreign_try_from(item: RazorpayRefundStatus) -> Result<Self, Self::Error> {
            match item {
                RazorpayRefundStatus::Failed => Ok(Self::Failure),
                RazorpayRefundStatus::Pending | RazorpayRefundStatus::Created => Ok(Self::Pending),
                RazorpayRefundStatus::Processed => Ok(Self::Success),
            }
        }
    }

    impl ForeignTryFrom<(
        RazorpayRefundResponse,
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    )> for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> {
        type Error = hyperswitch_interfaces::errors::ConnectorError;
        fn foreign_try_from(
            (response, data): (
                RazorpayRefundResponse,
                RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
            ),
        ) -> Result<Self, Self::Error> {
            let status = hyperswitch_common_enums::RefundStatus::foreign_try_from(response.status)?;
            let refunds_response_data = RefundsResponseData {
                connector_refund_id: response.id,
                refund_status: status,
            };
            Ok(Self {
                resource_common_data: RefundFlowData {
                    status,
                    ..data.resource_common_data
                },
                response: Ok(refunds_response_data),
                ..data
            })
        }
    }
    ```

### F. Implement `ConnectorIntegrationV2` for Refund (`<connector_name>.rs`)
In your connector's main file, implement `ConnectorIntegrationV2` for the `Refund` flow.

```rust
// In backend/connector-integration/src/connectors/new_connector_name.rs

// ... other imports ...
use domain_types::connector_flow::Refund;
use domain_types::connector_types::{RefundFlowData, RefundsData, RefundsResponseData};
// ...

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for NewConnectorName {
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Similar to Authorize/Capture: set Content-Type and Auth headers
        let mut header = vec![(
            "Content-Type".to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut auth_headers);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Construct the refund URL.
        // Example for Elavon (same base URL, transaction type in body):
        // Ok(format!("{}", req.resource_common_data.connectors.elavon.base_url))

        // Example for Razorpay (includes original payment ID in URL):
        // let connector_payment_id = req.request.connector_transaction_id.clone();
        // Ok(format!(
        //     "{}v1/payments/{}/refund",
        //     req.resource_common_data.connectors.razorpay.base_url,
        //     connector_payment_id
        // ))
        Ok(format!("{}processxml.do", req.resource_common_data.connectors.new_connector.base_url)) // Adjust for your connector
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // Convert minor_refund_amount
        let connector_amount = self.amount_converter.convert(req.request.minor_refund_amount, req.request.currency)?;
        
        let connector_router_data =
            your_connector_transformers::YourConnectorRouterDataWrapper::try_from((connector_amount, req))?;
        let connector_req =
            your_connector_transformers::YourConnectorRefundRequest::try_from(&connector_router_data)?;

        // For Elavon (XML):
        // Ok(Some(RequestContent::FormUrlEncoded(Box::new(struct_to_xml(&connector_req)?))))
        // For Razorpay (JSON):
        Ok(Some(RequestContent::Json(Box::new(connector_req)))) // Adjust as per your connector
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, errors::ConnectorError> {
        // For Elavon (XML response):
        // let response_text = String::from_utf8(res.response.to_vec())...
        // let elavon_response: your_connector_transformers::ElavonPaymentsResponse = serde_qs::from_str(&response_text)...
        // RouterDataV2::foreign_try_from((elavon_response.result, data.clone(), res.status_code))...

        // For Razorpay (JSON response):
        let response: your_connector_transformers::RazorpayRefundResponse = res
            .response
            .parse_struct("RazorpayRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, response); // Optional logging
        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2( /* ... */ ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
    fn get_5xx_error_response( /* ... */ ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}
```

## 3. Key Considerations

*   **Amount Conversion**: Ensure `minor_refund_amount` is converted correctly.
*   **Transaction ID**: The refund call needs the `connector_transaction_id` of the transaction to be refunded.
*   **Refund ID**: The connector's response should provide a `connector_refund_id`.
*   **Status Mapping**: Carefully map the connector's refund statuses to `hyperswitch_common_enums::RefundStatus` (`Success`, `Failure`, `Pending`).
*   **Partial Refunds**: If supported, ensure logic handles refunding less than the original captured amount.
*   **Multiple Refunds**: Check if the connector supports multiple partial refunds for a single transaction and how it behaves.
*   **Idempotency**: If supported, implement idempotency keys for refund requests.
*   **Error Handling**: Map connector-specific refund errors appropriately.

## 4. Referencing Razorpay and Elavon

*   **Razorpay (`razorpay.rs`, `razorpay/transformers.rs`):**
    *   Simple refund request (`RazorpayRefundRequest`).
    *   `connector_transaction_id` is part of the URL.
    *   `RazorpayRefundResponse` provides a clear status and a distinct refund ID.
    *   Has a specific `ForeignTryFrom<RazorpayRefundStatus> for hyperswitch_common_enums::RefundStatus`.
*   **Elavon (`elavon.rs`, `elavon/transformers.rs`):**
    *   Refund is a transaction type (`CcReturn`) in `ElavonRefundRequest`.
    *   Request includes auth details and original `ssl_txn_id`.
    *   Response parsing from URL-encoded XML uses `ElavonPaymentsResponse` and `ElavonResult`.
    *   `ForeignTryFrom` for refunds maps `ssl_result` and `ssl_transaction_type` to `RefundStatus`.

## 5. Testing

*   Test full and partial refunds (if supported).
*   Test refunding an already refunded transaction.
*   Test refunding a non-existent/failed transaction.
*   Verify correct mapping of connector refund statuses.
*   Test error responses from the connector during refunds.
*   Use `cargo build` and add unit tests.

This guide should help you implement the Refund flow for your connector. 