#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::borrow::Cow;

    use bytes::Bytes;
    use hyperswitch_cards::CardNumber;
    use hyperswitch_common_enums::{AttemptStatus, AuthenticationType, Currency, PaymentMethod, PaymentMethodType};
    use hyperswitch_common_utils::{
        id_type::MerchantId,
        pii::Email,
        // request::RequestContent, // Not directly used in these transformer tests
        types::MinorUnit,
    };
    use hyperswitch_masking::PeekInterface; // Added for Secret::peek()
    use hyperswitch_domain_models::{
        payment_address::PaymentAddress,
        payment_method_data::{Card, PaymentMethodData},
        router_data::{ConnectorAuthType, ErrorResponse as DomainErrorResponse},
        router_data_v2::RouterDataV2,
        router_request_types::BrowserInformation,
    };
    // Use PaymentsResponseData from domain_types::connector_types for the 4th generic arg in RouterDataV2
    use domain_types::connector_types::PaymentsResponseData as ConnectorPaymentsResponseData; 
    use hyperswitch_interfaces::{
        connector_integration_v2::ConnectorIntegrationV2,
        types::Response as HsResponse, // Renamed to avoid conflict if Response is used from elsewhere
    };
    use hyperswitch_masking::Secret;
    use serde_json::to_value;

    // Import Fiserv connector and its transformer items
    use crate::connectors::fiserv::Fiserv; 
    use crate::connectors::fiserv::transformers::{
        FiservPaymentsRequest, FiservRouterData, FiservSessionObject, 
        ErrorResponse as FiservErrorResponse, FiservPaymentsResponse, 
        FiservPaymentStatus, GatewayResponse, TransactionProcessingDetails
    };
    
    use domain_types::{
        connector_flow::Authorize,
        connector_types::{
            PaymentFlowData, PaymentsAuthorizeData, 
            ResponseId as ConnectorResponseId, 
        },
        types::{ConnectorParams, Connectors}, 
    };
    use hyperswitch_connectors::utils; // For convert_amount

    // Helper function to create a basic RouterDataV2 for Fiserv Authorize testing
    fn fn_to_get_router_data_for_fiserv_authorize(
        payment_method_data: PaymentMethodData,
        auth_type: AuthenticationType,
        amount: MinorUnit,
        capture_method: Option<hyperswitch_common_enums::CaptureMethod>,
        merchant_account_id: Secret<String>, // Corresponds to key1 in SignatureKey
        api_key: Secret<String>,          // Corresponds to api_key in SignatureKey
        api_secret: Secret<String>,       // Corresponds to api_secret in SignatureKey
        terminal_id: Secret<String>,      // Specific to Fiserv, passed via connector_meta_data
    ) -> RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, ConnectorPaymentsResponseData> {
        let session_object = FiservSessionObject { terminal_id: terminal_id.clone() }; // Clone terminal_id for session_object
        let session_object_str = serde_json::to_string(&session_object).unwrap();

        RouterDataV2 {
            flow: std::marker::PhantomData,
            resource_common_data: PaymentFlowData {
                merchant_id: MerchantId::default(), // Changed to default for simplicity in test
                customer_id: Some(hyperswitch_common_utils::id_type::CustomerId::try_from(Cow::from("cust_123")).unwrap()),
                connector_customer: None,
                payment_id: "test_payment_id_fiserv".to_string(),
                attempt_id: "test_attempt_id_fiserv".to_string(),
                status: AttemptStatus::Pending,
                payment_method: PaymentMethod::Card,
                description: Some("Test Fiserv Payment".to_string()),
                return_url: Some("https://hyperswitch.io/fiserv_return".to_string()),
                address: PaymentAddress::default(), 
                auth_type,
                connector_meta_data: Some(Secret::new(serde_json::Value::String(session_object_str))), // Corrected Secret value
                amount_captured: None,
                minor_amount_captured: None,
                access_token: None,
                session_token: None,
                reference_id: Some("test_order_id_fiserv".to_string()), // Typically connector_request_reference_id
                payment_method_token: None,
                preprocessing_id: None,
                connector_api_version: None,
                connector_request_reference_id: "test_conn_ref_id_fiserv".to_string(),
                test_mode: Some(true),
                connector_http_status_code: None,
                external_latency: None,
                connectors: Connectors {
                    adyen: ConnectorParams { base_url: "dummy_adyen_url".into(), dispute_base_url: None },
                    razorpay: ConnectorParams { base_url: "dummy_razorpay_url".into(), dispute_base_url: None },
                    elavon: ConnectorParams { base_url: "dummy_elavon_url".into(), dispute_base_url: None },
                    authorizedotnet: ConnectorParams { base_url: "dummy_authnet_url".into(), dispute_base_url: None },
                    fiserv: ConnectorParams {
                        base_url: "https://cert.api.fiserv.com/".to_string(), // Example base URL
                        dispute_base_url: None,
                    },
                },
            },
            request: PaymentsAuthorizeData {
                payment_method_data,
                amount: amount.get_amount_as_i64(),
                minor_amount: amount,
                email: Some(Email::from_str("testuser@fiserv.com").unwrap()),
                customer_name: Some("Fiserv Test User".to_string()),
                currency: Currency::USD,
                confirm: true,
                statement_descriptor_suffix: None,
                statement_descriptor: None,
                capture_method,
                router_return_url: Some("https://hyperswitch.io/fiserv_router_return".to_string()),
                webhook_url: Some("https://hyperswitch.io/fiserv_webhook".to_string()),
                complete_authorize_url: None,
                mandate_id: None,
                setup_future_usage: None,
                off_session: None,
                browser_info: Some(BrowserInformation {
                    color_depth: Some(24),
                    java_enabled: Some(true),
                    java_script_enabled: Some(true),
                    language: Some("en-US".to_string()),
                    screen_height: Some(1080),
                    screen_width: Some(1920),
                    time_zone: Some(300),
                    ip_address: Some(std::net::IpAddr::from_str("192.168.1.100").unwrap()),
                    accept_header: Some("application/json, text/plain, */*".to_string()),
                    user_agent: Some("Fiserv Test Agent/1.0".to_string()),
                }),
                order_category: None,
                session_token: None,
                enrolled_for_3ds: false,
                related_transaction_id: None,
                payment_experience: None,
                payment_method_type: Some(PaymentMethodType::Credit),
                customer_id: Some(hyperswitch_common_utils::id_type::CustomerId::try_from(Cow::from("cust_123")).unwrap()),
                request_incremental_authorization: false,
                metadata: None,
                merchant_order_reference_id: None,
                shipping_cost: None,
                merchant_account_id: Some(merchant_account_id.peek().clone()), 
                merchant_config_currency: Some(Currency::USD),
                order_tax_amount: None,
            },
            response: Err(DomainErrorResponse::default()), // Default to error, will be populated by handle_response
            connector_auth_type: ConnectorAuthType::SignatureKey {
                api_key, 
                key1: merchant_account_id, // Fiserv's "Merchant ID" often used as part of auth
                api_secret, 
            },
        }
    }

    #[test]
    fn test_authorize_request_build() {
        let fiserv_connector = Fiserv::new();
        let card_data = PaymentMethodData::Card(Card {
            card_number: CardNumber::from_str("4012888818888").unwrap(), 
            card_exp_month: Secret::new("12".to_string()),
            card_exp_year: Secret::new("2025".to_string()),
            card_cvc: Secret::new("123".to_string()),
            ..Default::default()
        });
        let router_data = fn_to_get_router_data_for_fiserv_authorize(
            card_data,
            AuthenticationType::NoThreeDs,
            MinorUnit::new(1500), // 15.00 USD
            Some(hyperswitch_common_enums::CaptureMethod::Automatic),
            Secret::new("test_merchant_id_fiserv".to_string()),
            Secret::new("test_api_key_fiserv".to_string()),
            Secret::new("test_api_secret_fiserv".to_string()),
            Secret::new("test_terminal_id_fiserv".to_string()),
        );

        let converted_amount = utils::convert_amount(
            fiserv_connector.amount_converter, 
            router_data.request.minor_amount,
            router_data.request.currency,
        ).unwrap();

        // Test FiservRouterData::try_from
        let fiserv_router_data_result = FiservRouterData::try_from((converted_amount, &router_data));
        assert!(fiserv_router_data_result.is_ok(), "FiservRouterData creation failed: {:?}", fiserv_router_data_result.err());
        let fiserv_router_data = fiserv_router_data_result.unwrap();
        
        // Test FiservPaymentsRequest::try_from
        let result = FiservPaymentsRequest::try_from(&fiserv_router_data);
        assert!(result.is_ok(), "FiservPaymentsRequest transformation failed: {:?}", result.err());
        
        let connector_request = result.unwrap();
        let json_request = to_value(connector_request).unwrap();

        // Assertions based on Fiserv's expected request structure
        assert_eq!(json_request["transactionDetails"]["captureFlag"], true);
        // assert_eq!(json_request["transactionDetails"]["transactionType"], "SALE"); // This field does not exist in TransactionDetails
        assert_eq!(json_request["amount"]["total"], 15.00); // Converted to major unit
        assert_eq!(json_request["amount"]["currency"], "USD");
        assert_eq!(json_request["source"]["sourceType"], "PaymentCard"); 
        assert_eq!(json_request["source"]["card"]["cardData"], "4012888818888"); // Corrected path: source.card.cardData
        assert_eq!(json_request["source"]["card"]["expirationMonth"], "12"); // Corrected path
        assert_eq!(json_request["source"]["card"]["expirationYear"], "2025"); // Corrected path
        assert_eq!(json_request["source"]["card"]["securityCode"], "123"); // Corrected path
        assert_eq!(json_request["merchantDetails"]["merchantId"], "test_merchant_id_fiserv");
        assert_eq!(json_request["merchantDetails"]["terminalId"], "test_terminal_id_fiserv");
        // The following fields are not part of FiservPaymentsRequest struct and were causing test failure.
        // assert_eq!(json_request["device"]["browserDetails"]["ip"], "192.168.1.100");
        // assert_eq!(json_request["paymentFacilitator"]["subMerchantData"]["merchantId"], "test_merchant_id_fiserv");
    }

    #[test]
    fn test_authorize_response_handling_success_authorized() {
        let fiserv_connector = Fiserv::new();
        let router_data = fn_to_get_router_data_for_fiserv_authorize(
            PaymentMethodData::Card(Card::default()),
            AuthenticationType::NoThreeDs,
            MinorUnit::new(1500),
            Some(hyperswitch_common_enums::CaptureMethod::Manual), // Manual capture
            Secret::new("test_merchant_id".to_string()),
            Secret::new("test_api_key".to_string()),
            Secret::new("test_api_secret".to_string()),
            Secret::new("test_terminal_id".to_string()),
        );

        // Mock a successful "Authorized" response from Fiserv
        let mock_fiserv_response_struct = FiservPaymentsResponse {
            gateway_response: GatewayResponse {
                gateway_transaction_id: Some("FISERV_TXN_AUTH_SUCCESS_123".to_string()),
                transaction_state: FiservPaymentStatus::Authorized,
                transaction_processing_details: TransactionProcessingDetails {
                    order_id: "test_order_id_fiserv".to_string(), // Matches router_data.reference_id
                    transaction_id: "PROC_TXN_AUTH_456".to_string(),
                },
            },
        };
        let response_bytes = Bytes::from(serde_json::to_vec(&mock_fiserv_response_struct).unwrap());
        let hs_response = HsResponse {
            status_code: 200, // Fiserv might return 200 for logical success/decline
            response: response_bytes,
            headers: None,
        };
            
        let result = fiserv_connector.handle_response_v2(&router_data, None, hs_response);
        assert!(result.is_ok(), "handle_response_v2 failed: {:?}", result.err());
        let router_data_updated = result.unwrap();

        assert_eq!(router_data_updated.resource_common_data.status, AttemptStatus::Authorized);
        match router_data_updated.response {
            Ok(ConnectorPaymentsResponseData::TransactionResponse { resource_id, connector_response_reference_id, .. }) => {
                match resource_id {
                    ConnectorResponseId::ConnectorTransactionId(id) => assert_eq!(id, "FISERV_TXN_AUTH_SUCCESS_123"),
                    _ => panic!("Unexpected resource_id variant"),
                }
                assert_eq!(connector_response_reference_id, Some("test_order_id_fiserv".to_string()));
            }
            _ => panic!("Expected successful TransactionResponse"),
        }
    }

    #[test]
    fn test_authorize_response_handling_success_captured() {
        let fiserv_connector = Fiserv::new();
        let router_data = fn_to_get_router_data_for_fiserv_authorize(
            PaymentMethodData::Card(Card::default()),
            AuthenticationType::NoThreeDs,
            MinorUnit::new(2500),
            Some(hyperswitch_common_enums::CaptureMethod::Automatic), // Automatic capture
            Secret::new("test_merchant_id_capture".to_string()),
            Secret::new("test_api_key_capture".to_string()),
            Secret::new("test_api_secret_capture".to_string()),
            Secret::new("test_terminal_id_capture".to_string()),
        );

        let mock_fiserv_response_struct = FiservPaymentsResponse {
            gateway_response: GatewayResponse {
                gateway_transaction_id: Some("FISERV_TXN_CAPTURED_789".to_string()),
                transaction_state: FiservPaymentStatus::Captured,
                transaction_processing_details: TransactionProcessingDetails {
                    order_id: "test_order_id_fiserv_capture".to_string(),
                    transaction_id: "PROC_TXN_CAPTURE_101".to_string(),
                },
            },
        };
        let response_bytes = Bytes::from(serde_json::to_vec(&mock_fiserv_response_struct).unwrap());
        let hs_response = HsResponse {
            status_code: 200,
            response: response_bytes,
            headers: None,
        };
            
        let result = fiserv_connector.handle_response_v2(&router_data, None, hs_response);
        assert!(result.is_ok(), "handle_response_v2 failed for capture: {:?}", result.err());
        let router_data_updated = result.unwrap();

        assert_eq!(router_data_updated.resource_common_data.status, AttemptStatus::Charged); // Charged for automatic capture
         match router_data_updated.response {
            Ok(ConnectorPaymentsResponseData::TransactionResponse { resource_id, connector_response_reference_id, .. }) => {
                match resource_id {
                    ConnectorResponseId::ConnectorTransactionId(id) => assert_eq!(id, "FISERV_TXN_CAPTURED_789"),
                    _ => panic!("Unexpected resource_id variant"),
                }
                assert_eq!(connector_response_reference_id, Some("test_order_id_fiserv_capture".to_string()));
            }
            _ => panic!("Expected successful TransactionResponse for capture"),
        }
    }
    
    #[test]
    fn test_authorize_response_handling_failure_declined() {
        let fiserv_connector = Fiserv::new();
        let router_data = fn_to_get_router_data_for_fiserv_authorize(
            PaymentMethodData::Card(Card::default()),
            AuthenticationType::NoThreeDs,
            MinorUnit::new(500),
            Some(hyperswitch_common_enums::CaptureMethod::Automatic),
            Secret::new("test_merchant_id_decline".to_string()),
            Secret::new("test_api_key_decline".to_string()),
            Secret::new("test_api_secret_decline".to_string()),
            Secret::new("test_terminal_id_decline".to_string()),
        );

        let mock_fiserv_response_struct = FiservPaymentsResponse {
            gateway_response: GatewayResponse {
                gateway_transaction_id: Some("FISERV_TXN_DECLINED_XYZ".to_string()),
                transaction_state: FiservPaymentStatus::Declined,
                transaction_processing_details: TransactionProcessingDetails {
                    order_id: "test_order_id_fiserv_declined".to_string(),
                    transaction_id: "PROC_TXN_DECLINED_ABC".to_string(), // This becomes the error code
                },
            },
        };
        let response_bytes = Bytes::from(serde_json::to_vec(&mock_fiserv_response_struct).unwrap());
        let hs_response = HsResponse {
            status_code: 200, // Fiserv might still return 200 for a logical decline
            response: response_bytes,
            headers: None,
        };
            
        let result = fiserv_connector.handle_response_v2(&router_data, None, hs_response);
        assert!(result.is_ok(), "handle_response_v2 itself should not fail for logical decline");
        let router_data_updated = result.unwrap();
        
        assert_eq!(router_data_updated.resource_common_data.status, AttemptStatus::Failure);
        match router_data_updated.response {
            Err(err_resp) => {
                assert_eq!(err_resp.code, "PROC_TXN_DECLINED_ABC");
                assert_eq!(err_resp.message, "Payment status: Declined"); // Based on current Fiserv connector logic
                assert_eq!(err_resp.reason, None); // Fiserv transformer might not populate reason for simple declines
                assert_eq!(err_resp.status_code, 200);
                assert_eq!(err_resp.connector_transaction_id, Some("FISERV_TXN_DECLINED_XYZ".to_string()));
            }
            _ => panic!("Expected ErrorResponse for declined transaction"),
        }
    }

    #[test]
    fn test_authorize_get_error_response() {
        let fiserv_connector = Fiserv::new();
        // Mock a Fiserv error response (structure from fiserv/transformers.rs)
        let mock_error_struct = FiservErrorResponse {
            error: Some(vec![
                crate::connectors::fiserv::transformers::ErrorDetails { // Corrected path and added error_type
                    error_type: "VALIDATION_ERROR".to_string(), // Added missing field
                    code: Some("INVALID_FIELD_FORMAT".to_string()),
                    message: "The format of the card number is incorrect.".to_string(),
                    field: Some("source.paymentCard.card.cardData".to_string()),
                    // `details` is not a field of ErrorDetails, it's part of ErrorResponse
                }
            ]),
            details: None, 
        };
        let response_bytes = Bytes::from(serde_json::to_vec(&mock_error_struct).unwrap());
        let hs_response = HsResponse {
            status_code: 400, // Typical HTTP status for client errors
            response: response_bytes,
            headers: None,
        };

        // get_error_response_v2 calls build_error_response internally
        let result = <Fiserv as ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, ConnectorPaymentsResponseData>>::get_error_response_v2(&fiserv_connector, hs_response, None);
        assert!(result.is_ok(), "get_error_response_v2 failed: {:?}", result.err());
        let domain_error_response = result.unwrap();

        assert_eq!(domain_error_response.status_code, 400);
        assert_eq!(domain_error_response.code, "INVALID_FIELD_FORMAT");
        assert_eq!(domain_error_response.message, "The format of the card number is incorrect.");
        assert_eq!(domain_error_response.reason, Some("source.paymentCard.card.cardData".to_string()));
    }
}
