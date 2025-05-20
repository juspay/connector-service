#[cfg(test)]
mod tests {
    use hyperswitch_common_enums::{AttemptStatus, AuthenticationType, Currency, PaymentMethod, PaymentMethodType};
    use hyperswitch_domain_models::{
        payment_address::PaymentAddress,
        payment_method_data::{Card, PaymentMethodData},
        router_data::{ConnectorAuthType, ErrorResponse},
        router_data_v2::RouterDataV2,
        router_request_types::BrowserInformation,
        // PaymentsResponseData will be from domain_types::connector_types
    };
    use hyperswitch_interfaces::{connector_integration_v2::ConnectorIntegrationV2, types::Response as HsResponse};
    use hyperswitch_masking::Secret;
    use std::{str::FromStr, borrow::Cow};
    use bytes::Bytes;
    use hyperswitch_common_utils::{id_type::MerchantId, pii::Email, request::RequestContent, types::MinorUnit};
    use domain_types::{
        connector_types::{
            PaymentsAuthorizeData,
            ResponseId as ConnectorResponseId,
            PaymentsResponseData, // Import from domain_types::connector_types
            PaymentFlowData, // Added back
            // ConnectorEnum, // This was for the commented out get_elavon_connector_data
        },
        types::{ConnectorParams, Connectors},
        connector_flow::{Authorize},
    };
    use crate::{
        connectors::Elavon,
        // types::ConnectorData, // This was for the commented out get_elavon_connector_data
    };
    use hyperswitch_cards::CardNumber;

    // Helper function to create a basic RouterDataV2 for testing
    fn fn_to_get_router_data_for_elavon(
        payment_method_data: PaymentMethodData,
        auth_type: AuthenticationType,
        amount: MinorUnit,
    ) -> RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> { // Use the imported PaymentsResponseData
        RouterDataV2 {
            flow: std::marker::PhantomData,
            resource_common_data: PaymentFlowData {
                merchant_id: MerchantId::default(),
                customer_id: Some(hyperswitch_common_utils::id_type::CustomerId::try_from(Cow::from("cust_123")).unwrap()),
                connector_customer: None,
                payment_id: "test_payment_id".to_string(),
                attempt_id: "test_attempt_id".to_string(),
                status: AttemptStatus::Pending,
                payment_method: PaymentMethod::Card,
                description: Some("Test Payment".to_string()),
                return_url: Some("https://hyperswitch.io".to_string()),
                address: PaymentAddress::default(),
                auth_type,
                connector_meta_data: None,
                amount_captured: None,
                minor_amount_captured: None,
                access_token: None,
                session_token: None,
                reference_id: Some("test_order_id".to_string()),
                payment_method_token: None,
                preprocessing_id: None,
                connector_api_version: None,
                connector_request_reference_id: "test_connector_ref_id".to_string(),
                test_mode: Some(true),
                connector_http_status_code: None,
                external_latency: None,
                connectors: Connectors {
                    adyen: ConnectorParams {
                        base_url: "https://adyen.example.com".to_string(),
                        dispute_base_url: None,
                    },
                    razorpay: ConnectorParams {
                        base_url: "https://razorpay.example.com".to_string(),
                        dispute_base_url: None,
                    },
                    elavon: ConnectorParams {
                        base_url: "https://elavon_test.com/".to_string(),
                        dispute_base_url: None,
                    },
                    authorizedotnet: ConnectorParams {
                        base_url: "MOCK_AUTHORIZEDOTNET_URL".to_string(),
                        dispute_base_url: None,
                    },
                    fiserv: ConnectorParams { 
                        base_url: "https://cert.api.fiserv.com/".to_string(), 
                        dispute_base_url: None,
                    },
                },
            },
            request: PaymentsAuthorizeData {
                payment_method_data,
                amount: amount.get_amount_as_i64(),
                minor_amount: amount,
                email: Some(Email::from_str("test@example.com").unwrap()),
                customer_name: Some("Test User".to_string()),
                currency: Currency::USD,
                confirm: true,
                statement_descriptor_suffix: None,
                statement_descriptor: None,
                capture_method: Some(hyperswitch_common_enums::CaptureMethod::Automatic),
                router_return_url: Some("https://hyperswitch.io/complete".to_string()),
                webhook_url: Some("https://hyperswitch.io/webhook".to_string()),
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
                    ip_address: Some(std::net::IpAddr::from_str("192.168.1.1").unwrap()),
                    accept_header: Some("application/json".to_string()),
                    user_agent: Some("Test Agent".to_string()),
                    ..Default::default()
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
                merchant_account_id: Some("merchant_test_account".to_string()),
                merchant_config_currency: Some(Currency::USD),
                order_tax_amount: None,
            },
            response: Err(ErrorResponse::default()),
            connector_auth_type: ConnectorAuthType::SignatureKey {
                api_key: Secret::new("test_account_id".to_string()),
                key1: Secret::new("test_user_id".to_string()),
                api_secret: Secret::new("test_pin".to_string()),
            },
        }
    }

    // fn get_elavon_connector_data() -> ConnectorData { // This function is unused
    //     ConnectorData {
    //         connector: Box::new(Elavon::new()),
    //         connector_name: ConnectorEnum::Elavon,
    //     }
    // }


    mod authorize_tests {
        use super::*;

        #[test]
        fn test_authorize_request_build() {
            let elavon_connector = Elavon::new();
            let router_data = fn_to_get_router_data_for_elavon(
                PaymentMethodData::Card(Card {
                    card_number: CardNumber::from_str("4012888818888").unwrap(),
                    card_exp_month: "12".to_string().into(),
                    card_exp_year: "2025".to_string().into(),
                    card_cvc: "123".to_string().into(),
                    ..Default::default()
                }),
                AuthenticationType::NoThreeDs,
                MinorUnit::new(1000),
            );

            let result = elavon_connector.get_request_body(&router_data);
            assert!(result.is_ok());
            let request_content = result.unwrap().unwrap();

            match request_content {
                RequestContent::FormUrlEncoded(form_data_map_wrapper) => {
                    let json_val = form_data_map_wrapper.masked_serialize().unwrap();
                    let xml_data = json_val.get("xmldata").unwrap().as_str().unwrap();
                    println!("Generated XML data for Elavon authorize request: {}", xml_data); // Print the XML
                    // Assuming quick_xml serializes enum variants in PascalCase if #[serde(rename_all = "lowercase")] is not fully effective for this context.
                    // If Elavon API strictly needs lowercase "ccsale", the transformer's serialization of TransactionType needs adjustment.
                    assert!(xml_data.contains("<ssl_transaction_type>CcSale</ssl_transaction_type>")); 
                    assert!(xml_data.contains("<ssl_amount>10.00</ssl_amount>"));
                    assert!(xml_data.contains("<ssl_card_number>4012888818888</ssl_card_number>"));
                }
                _ => panic!("Expected FormUrlEncoded request body"),
            }
        }

        #[test]
        fn test_authorize_response_handling_success() {
            let elavon_connector = Elavon::new();
            let router_data = fn_to_get_router_data_for_elavon(
                PaymentMethodData::Card(Card::default()),
                AuthenticationType::NoThreeDs,
                MinorUnit::new(1000),
            );

            let mock_response_xml = [
                "<txn>",
                "    <ssl_result>0</ssl_result>",
                "    <ssl_result_message>APPROVAL</ssl_result_message>",
                "    <ssl_txn_id>TEST_TXN_ID_SUCCESS</ssl_txn_id>",
                "    <ssl_cvv2_response>M</ssl_cvv2_response>",
                "    <ssl_avs_response>Y</ssl_avs_response>",
                "    <ssl_transaction_type>ccsale</ssl_transaction_type>",
                "</txn>"
            ].join("\n");

            let response = HsResponse {
                status_code: 200,
                response: Bytes::from(mock_response_xml),
                headers: None,
            };
            
            let result = elavon_connector.handle_response_v2(&router_data, None, response);
            assert!(result.is_ok());
            let router_data_updated = result.unwrap();

            assert_eq!(router_data_updated.resource_common_data.status, AttemptStatus::Charged);
            match router_data_updated.response {
                Ok(PaymentsResponseData::TransactionResponse { resource_id, .. }) => {
                    match resource_id {
                        ConnectorResponseId::ConnectorTransactionId(id) => assert_eq!(id, "TEST_TXN_ID_SUCCESS"),
                        _ => panic!("Unexpected resource_id variant"),
                    }
                }
                _ => panic!("Expected successful TransactionResponse"),
            }
        }

        #[test]
        fn test_authorize_response_handling_failure() {
            let elavon_connector = Elavon::new();
            let router_data = fn_to_get_router_data_for_elavon(
                PaymentMethodData::Card(Card::default()),
                AuthenticationType::NoThreeDs,
                MinorUnit::new(1000),
            );
            
            let mock_response_xml = [
                "<txn>",
                "    <errorName>DECLINED</errorName>",
                "    <errorMessage>Card Declined</errorMessage>",
                "    <errorCode>101</errorCode>",
                "</txn>"
            ].join("\n");

            let response = HsResponse {
                status_code: 200,
                response: Bytes::from(mock_response_xml),
                headers: None,
            };

            let result = elavon_connector.handle_response_v2(&router_data, None, response);
            assert!(result.is_ok());
            let router_data_updated = result.unwrap();
            
            assert_eq!(router_data_updated.resource_common_data.status, AttemptStatus::Failure);
            match router_data_updated.response {
                Err(err_resp) => {
                    assert_eq!(err_resp.code, "101");
                    assert_eq!(err_resp.message, "Card Declined");
                    assert_eq!(err_resp.reason, Some("DECLINED".to_string()));
                }
                _ => panic!("Expected ErrorResponse"),
            }
        }
    }
}
