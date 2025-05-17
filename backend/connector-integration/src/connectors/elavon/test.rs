#[cfg(test)]
mod tests {
    use hyperswitch_common_enums::{AttemptStatus, AuthenticationType, Currency, PaymentMethod, PaymentMethodType, RefundStatus, CaptureMethod as HyperswitchCaptureMethod};
    use hyperswitch_domain_models::{
        payment_address::PaymentAddress,
        payment_method_data::{Card, PaymentMethodData},
        router_data::{ConnectorAuthType, ErrorResponse, AccessToken},
        router_data_v2::RouterDataV2,
        router_request_types::BrowserInformation,
        router_response_types::{PaymentsResponseData, RefundsResponseData as HyperswitchRefundsResponseData},
    };
    use hyperswitch_interfaces::{connector_integration_v2::ConnectorIntegrationV2, types::Response as HsResponse, api::ConnectorCommon};
    use hyperswitch_masking::Secret;
    use serde_json::json;
    use std::{str::FromStr, borrow::Cow};
    use hyperswitch_common_utils::{id_type::MerchantId, pii::Email, request::RequestContent, types::{MinorUnit, StringMajorUnit}};
    use domain_types::{
        connector_types::{
            BoxedConnector, ConnectorServiceTrait, PaymentFlowData, RefundFlowData, ConnectorEnum,
            PaymentsAuthorizeData,
            PaymentsCaptureData,
            PaymentsSyncData,
            RefundsData,
            RefundSyncData,
            ResponseId as ConnectorResponseId,
            MultipleCaptureRequestData
        },
        types::{ConnectorParams, Connectors},
        connector_flow::{Authorize, Capture, PSync, Refund, RSync},
    };
    use crate::{
        connectors::Elavon,
        types::ConnectorData,
    };
    use hyperswitch_cards::CardNumber;
    use serde_json::de;

    // Helper function to create a basic RouterDataV2 for testing
    fn fn_to_get_router_data_for_elavon(
        payment_method_data: PaymentMethodData,
        auth_type: AuthenticationType,
        amount: MinorUnit,
    ) -> RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
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

    fn get_elavon_connector_data() -> ConnectorData {
        ConnectorData {
            connector: Box::new(Elavon::new()),
            connector_name: ConnectorEnum::Elavon,
        }
    }


    mod authorize_tests {
        use super::*;

        #[test]
        fn test_authorize_request_build() {
            let connector_data = get_elavon_connector_data();
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

            let authorize_integration = ConnectorCommon::get_connector_integration_v2::<
                Authorize, 
                PaymentFlowData, 
                PaymentsAuthorizeData, 
                PaymentsResponseData
            >(connector_data.connector.as_ref());

            let result = authorize_integration.get_request_body(&router_data);
            assert!(result.is_ok());
            let request_content = result.unwrap().unwrap();

            match request_content {
                RequestContent::FormUrlEncoded(form_data_map_wrapper) => {
                    let json_val = form_data_map_wrapper.masked_serialize().unwrap();
                    let xml_data = json_val.get("xmldata").unwrap().as_str().unwrap();
                    assert!(xml_data.contains("<ssl_transaction_type>ccsale</ssl_transaction_type>"));
                    assert!(xml_data.contains("<ssl_amount>10.00</ssl_amount>"));
                    assert!(xml_data.contains("<ssl_card_number>4012888818888</ssl_card_number>"));
                }
                _ => panic!("Expected FormUrlEncoded request body"),
            }
        }

        #[test]
        fn test_authorize_response_handling_success() {
            let connector_data = get_elavon_connector_data();
            let router_data = fn_to_get_router_data_for_elavon(
                PaymentMethodData::Card(Card::default()),
                AuthenticationType::NoThreeDs,
                MinorUnit::new(1000),
            );

            let response_xml = br#"
                <txn>
                    <ssl_result>0</ssl_result>
                    <ssl_txn_id>TEST_TXN_123</ssl_txn_id>
                    <ssl_result_message>APPROVAL</ssl_result_message>
                    <ssl_approval_code>A123</ssl_approval_code>
                    <ssl_transaction_type>ccsale</ssl_transaction_type>
                </txn>
            "#;

            let response = HsResponse {
                headers: None,
                response: response_xml.to_vec().into(),
                status_code: 200,
            };
            
            let authorize_integration = ConnectorCommon::get_connector_integration_v2::<
                Authorize, 
                PaymentFlowData, 
                PaymentsAuthorizeData, 
                PaymentsResponseData
            >(connector_data.connector.as_ref());

            let result = authorize_integration.handle_response_v2(&router_data, None, response);
            assert!(result.is_ok());
            let response_router_data = result.unwrap();
            assert_eq!(response_router_data.resource_common_data.status, AttemptStatus::Charged);
            match response_router_data.response {
                Ok(PaymentsResponseData::TransactionResponse { resource_id, .. }) => {
                     match resource_id {
                        ConnectorResponseId::ConnectorTransactionId(id) => assert_eq!(id, "TEST_TXN_123"),
                        _ => panic!("Unexpected resource_id variant")
                     }
                },
                _ => panic!("Expected successful transaction response"),
            }
        }

         #[test]
        fn test_authorize_response_handling_failure() {
            let connector_data = get_elavon_connector_data();
            let router_data = fn_to_get_router_data_for_elavon(
                PaymentMethodData::Card(Card::default()),
                AuthenticationType::NoThreeDs,
                MinorUnit::new(1000),
            );

            let response_xml = br#"
                <txn>
                    <ssl_result>1</ssl_result>
                    <ssl_txn_id>TEST_TXN_FAIL</ssl_txn_id>
                    <ssl_result_message>DECLINED</ssl_result_message>
                    <error_name>DECLINED</error_name>
                    <error_message>Card Declined</error_message>
                    <error_code>001</error_code>
                </txn>
            "#;
             let response = HsResponse {
                headers: None,
                response: response_xml.to_vec().into(),
                status_code: 200,
            };

            let authorize_integration = ConnectorCommon::get_connector_integration_v2::<
                Authorize, 
                PaymentFlowData, 
                PaymentsAuthorizeData, 
                PaymentsResponseData
            >(connector_data.connector.as_ref());

            let result = authorize_integration.handle_response_v2(&router_data, None, response);
            assert!(result.is_ok());
            let response_router_data = result.unwrap();
            assert_eq!(response_router_data.resource_common_data.status, AttemptStatus::Failure);
            match response_router_data.response {
                Err(err) => {
                    assert_eq!(err.code, "001");
                    assert_eq!(err.message, "Card Declined");
                    assert_eq!(err.reason, Some("DECLINED".to_string()));
                },
                _ => panic!("Expected error response"),
            }
        }
    }

    // mod capture_tests {
    //     use super::*;
    //     use domain_types::connector_flow::Capture;
    //     // PaymentsCaptureData is now from domain_types::connector_types

    //     fn get_router_data_for_capture() -> RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> {
    //         let authorize_router_data = fn_to_get_router_data_for_elavon(
    //             PaymentMethodData::Card(Card::default()),
    //             AuthenticationType::NoThreeDs,
    //             MinorUnit::new(1000),
    //         );

    //         RouterDataV2 {
    //             flow: std::marker::PhantomData,
    //             resource_common_data: authorize_router_data.resource_common_data.clone(),
    //             request: PaymentsCaptureData { // This is domain_types::connector_types::PaymentsCaptureData
    //                 amount_to_capture: authorize_router_data.request.minor_amount.get_amount_as_i64(),
    //                 minor_amount_to_capture: authorize_router_data.request.minor_amount,
    //                 currency: authorize_router_data.request.currency,
    //                 connector_transaction_id: ConnectorResponseId::ConnectorTransactionId("AUTH_TXN_123".to_string()), // domain_types::connector_types::ResponseId
    //                 multiple_capture_data: None,
    //                 connector_metadata: None, // field from domain_types::connector_types::PaymentsCaptureData
    //             },
    //             response: Err(ErrorResponse::default()),
    //             connector_auth_type: authorize_router_data.connector_auth_type,
    //         }
    //     }

    //     #[test]
    //     fn test_capture_request_build() {
    //         let (_connector, connector_data) = get_elavon_connector_data();
    //         let router_data = get_router_data_for_capture();
            
    //         let capture_integration = connector_data.connector
    //             .get_connector_integration_v2::<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>();

    //         let result = capture_integration.get_request_body(&router_data);
    //         assert!(result.is_ok());
    //         let request_content = result.unwrap().unwrap();
    //         match request_content {
    //             RequestContent::FormUrlEncoded(form_data_map_wrapper) => {
    //                 let json_val = form_data_map_wrapper.masked_serialize().unwrap();
    //                 let xml_data = json_val.get("xmldata").unwrap().as_str().unwrap();
    //                 assert!(xml_data.contains("<ssl_transaction_type>cccomplete</ssl_transaction_type>"));
    //                 assert!(xml_data.contains("<ssl_amount>10.00</ssl_amount>"));
    //                 assert!(xml_data.contains("<ssl_txn_id>AUTH_TXN_123</ssl_txn_id>"));
    //             }
    //             _ => panic!("Expected FormUrlEncoded request body"),
    //         }
    //     }

    //     #[test]
    //     fn test_capture_response_handling_success() {
    //         let (_connector, connector_data) = get_elavon_connector_data();
    //         let router_data = get_router_data_for_capture();
    //          let response_xml = br#"
    //             <txn>
    //                 <ssl_result>0</ssl_result>
    //                 <ssl_txn_id>CAPTURE_TXN_456</ssl_txn_id>
    //                 <ssl_result_message>APPROVAL</ssl_result_message>
    //                 <ssl_transaction_type>cccomplete</ssl_transaction_type>
    //             </txn>
    //         "#;
    //         let response = HsResponse {
    //             headers: None,
    //             response: response_xml.to_vec().into(),
    //             status_code: 200,
    //         };
            
    //         let capture_integration = connector_data.connector
    //             .get_connector_integration_v2::<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>();
                
    //         let result = capture_integration.handle_response_v2(&router_data, None, response);
    //         assert!(result.is_ok());
    //         let response_router_data = result.unwrap();
    //         assert_eq!(response_router_data.resource_common_data.status, AttemptStatus::Charged);
    //     }
    // }


    // mod psync_tests {
    //     use super::*;
    //     use domain_types::connector_flow::PSync;
    //     // PaymentsSyncData is now from domain_types::connector_types
    //     // ConnectorResponseId is from domain_types::connector_types

    //     fn get_router_data_for_psync() -> RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> {
    //          let authorize_router_data = fn_to_get_router_data_for_elavon(
    //             PaymentMethodData::Card(Card::default()), 
    //             AuthenticationType::NoThreeDs,
    //             MinorUnit::new(0), // Amount not relevant for PSync request body itself for Elavon's txnquery
    //         );
    //         RouterDataV2 {
    //             flow: std::marker::PhantomData,
    //             resource_common_data: authorize_router_data.resource_common_data.clone(),
    //             request: PaymentsSyncData { // This is domain_types::connector_types::PaymentsSyncData
    //                 connector_transaction_id: ConnectorResponseId::ConnectorTransactionId("PAY_SYNC_123".to_string()), // domain_types::connector_types::ResponseId
    //                 sync_type: hyperswitch_domain_models::router_request_types::SyncRequestType::SinglePaymentSync, // This type is from hyperswitch_domain_models
    //                 capture_method: None,
    //                 connector_meta: None, // field from domain_types::connector_types::PaymentsSyncData
    //                 payment_method_type: None,
    //                 encoded_data: None,
    //                 mandate_id: None, // This type would be hyperswitch_api_models::payments::MandateIds
    //                 currency: authorize_router_data.request.currency, // currency from domain_types
    //                 payment_experience: None, // This type is hyperswitch_common_enums::PaymentExperience
    //                 amount: MinorUnit::new(0), // amount from domain_types
    //                 // integrity_object is NOT a field in domain_types::connector_types::PaymentsSyncData
    //             },
    //             response: Err(ErrorResponse::default()),
    //             connector_auth_type: authorize_router_data.connector_auth_type,
    //         }
    //     }

    //     #[test]
    //     fn test_psync_request_build() {
    //         let (_connector, connector_data) = get_elavon_connector_data();
    //         let router_data = get_router_data_for_psync();

    //         let psync_integration = connector_data.connector
    //             .get_connector_integration_v2::<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>();

    //         let result = psync_integration.get_request_body(&router_data);
    //         assert!(result.is_ok());
    //          let request_content = result.unwrap().unwrap();
    //         match request_content {
    //             RequestContent::FormUrlEncoded(form_data_map_wrapper) => {
    //                 let json_val = form_data_map_wrapper.masked_serialize().unwrap();
    //                 let xml_data = json_val.get("xmldata").unwrap().as_str().unwrap();
    //                 assert!(xml_data.contains("<ssl_transaction_type>txnquery</ssl_transaction_type>"));
    //                 assert!(xml_data.contains("<ssl_txn_id>PAY_SYNC_123</ssl_txn_id>"));
    //             }
    //             _ => panic!("Expected FormUrlEncoded request body"),
    //         }
    //     }

    //     #[test]
    //     fn test_psync_response_handling_settled_sale() {
    //         let (_connector, connector_data) = get_elavon_connector_data();
    //         let router_data = get_router_data_for_psync();
    //         let response_body_str = r#"<txn><ssl_trans_status>STL</ssl_trans_status><ssl_transaction_type>SALE</ssl_transaction_type><ssl_txn_id>PAY_SYNC_123</ssl_txn_id></txn>"#;

    //         let response = HsResponse {
    //             headers: None,
    //             response: response_body_str.as_bytes().to_vec().into(),
    //             status_code: 200,
    //         };

    //         let psync_integration = connector_data.connector
    //             .get_connector_integration_v2::<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>();

    //         let result = psync_integration.handle_response_v2(&router_data, None, response);
    //         assert!(result.is_ok());
    //         let response_router_data = result.unwrap();
    //         assert_eq!(response_router_data.resource_common_data.status, AttemptStatus::Charged);
    //     }
    // }

    // mod refund_tests {
    //     use super::*;
    //     use domain_types::connector_flow::Refund;
    //     use domain_types::connector_types::{RefundFlowData, RefundsData, RefundsResponseData as DomainRefundsResponseData};
    //     use hyperswitch_common_enums::RefundStatus;


    //     fn get_router_data_for_refund() -> RouterDataV2<Refund, RefundFlowData, RefundsData, DomainRefundsResponseData> {
    //         let authorize_router_data = fn_to_get_router_data_for_elavon(
    //             PaymentMethodData::Card(Card::default()),
    //             AuthenticationType::NoThreeDs,
    //             MinorUnit::new(1000),
    //         );
    //         RouterDataV2 {
    //             flow: std::marker::PhantomData,
    //             resource_common_data: RefundFlowData {
    //                 refund_id: Some("test_refund_flow_id".to_string()),
    //                 status: RefundStatus::Pending,
    //                  connectors: authorize_router_data.resource_common_data.connectors.clone(),
    //                 // customer_id, connector_customer etc. are NOT fields here
    //             },
    //             request: RefundsData {
    //                 connector_transaction_id: "PAY_TO_REFUND_123".to_string(),
    //                 minor_refund_amount: MinorUnit::new(500),
    //                 currency: Currency::USD,
    //                 refund_id: "test_refund_id".to_string(),
    //                 reason: Some("Test refund reason".to_string()),
    //                 connector_metadata: None,
    //                 merchant_account_id: authorize_router_data.request.merchant_account_id.clone(),
    //                 connector_refund_id: None,
    //                 webhook_url: None,
    //                 refund_connector_metadata: None,
    //                 payment_amount: authorize_router_data.request.amount,
    //                 minor_payment_amount: authorize_router_data.request.minor_amount,
    //                 refund_amount: 500,
    //                 refund_status: RefundStatus::Pending,
    //                 capture_method: None,
    //             },
    //             response: Err(ErrorResponse::default()),
    //             connector_auth_type: authorize_router_data.connector_auth_type.clone(),
    //         }
    //     }

    //     #[test]
    //     fn test_refund_request_build() {
    //         let (_connector, connector_data) = get_elavon_connector_data();
    //         let router_data = get_router_data_for_refund();

    //         let refund_integration = connector_data.connector
    //             .get_connector_integration_v2::<Refund, RefundFlowData, RefundsData, DomainRefundsResponseData>();

    //         let result = refund_integration.get_request_body(&router_data);
    //         assert!(result.is_ok());
    //         let request_content = result.unwrap().unwrap();
    //          match request_content {
    //             RequestContent::FormUrlEncoded(form_data_map_wrapper) => {
    //                 let json_val = form_data_map_wrapper.masked_serialize().unwrap();
    //                 let xml_data = json_val.get("xmldata").unwrap().as_str().unwrap();
    //                 assert!(xml_data.contains("<ssl_transaction_type>ccreturn</ssl_transaction_type>"));
    //                 assert!(xml_data.contains("<ssl_amount>5.00</ssl_amount>"));
    //                 assert!(xml_data.contains("<ssl_txn_id>PAY_TO_REFUND_123</ssl_txn_id>"));
    //             }
    //             _ => panic!("Expected FormUrlEncoded request body"),
    //         }
    //     }

    //     #[test]
    //     fn test_refund_response_handling_success() {
    //         let (_connector, connector_data) = get_elavon_connector_data();
    //         let router_data = get_router_data_for_refund();
    //         let response_xml = br#"
    //             <txn>
    //                 <ssl_result>0</ssl_result>
    //                 <ssl_txn_id>REFUND_TXN_789</ssl_txn_id>
    //                 <ssl_result_message>APPROVAL</ssl_result_message>
    //                 <ssl_transaction_type>ccreturn</ssl_transaction_type>
    //             </txn>
    //         "#;
    //         let response = HsResponse {
    //             headers: None,
    //             response: response_xml.to_vec().into(),
    //             status_code: 200,
    //         };

    //         let refund_integration = connector_data.connector
    //             .get_connector_integration_v2::<Refund, RefundFlowData, RefundsData, DomainRefundsResponseData>();
                
    //         let result = refund_integration.handle_response_v2(&router_data, None, response);
    //         assert!(result.is_ok());
    //         let response_router_data = result.unwrap();
    //         assert_eq!(response_router_data.resource_common_data.status, RefundStatus::Success);
    //         match response_router_data.response {
    //             Ok(DomainRefundsResponseData { connector_refund_id, refund_status, .. }) => {
    //                 assert_eq!(connector_refund_id, "REFUND_TXN_789".to_string());
    //                 assert_eq!(refund_status, RefundStatus::Success);
    //             },
    //             _ => panic!("Expected successful refund response"),
    //         }
    //     }
    // }

    // mod rsync_tests {
    //     use super::*;
    //     use domain_types::connector_flow::RSync;
    //     use domain_types::connector_types::{RefundSyncData, RefundFlowData, RefundsResponseData as DomainRefundsResponseData};
    //     use hyperswitch_common_enums::RefundStatus;

    //     fn get_router_data_for_rsync() -> RouterDataV2<RSync, RefundFlowData, RefundSyncData, DomainRefundsResponseData> {
    //          let authorize_router_data = fn_to_get_router_data_for_elavon(
    //             PaymentMethodData::Card(Card::default()),
    //             AuthenticationType::NoThreeDs,
    //             MinorUnit::new(0), // Amount not relevant for RSync request
    //         );
    //         RouterDataV2 {
    //             flow: std::marker::PhantomData,
    //              resource_common_data: RefundFlowData {
    //                 refund_id: Some("test_rsync_flow_id".to_string()),
    //                 status: RefundStatus::Pending,
    //                  connectors: authorize_router_data.resource_common_data.connectors.clone(),
    //                 // customer_id, connector_customer etc. are NOT fields here
    //             },
    //             request: RefundSyncData {
    //                 connector_refund_id: "REF_SYNC_456".to_string(),
    //                 connector_transaction_id: "SOME_ORIGINAL_TXN_ID_FOR_REFUND_SYNC".to_string(), // Needs a valid original connector_txn_id
    //                 reason: None,
    //                 refund_connector_metadata: None,
    //                 refund_status: RefundStatus::Pending, // Initial status for request
    //             },
    //             response: Err(ErrorResponse::default()),
    //             connector_auth_type: authorize_router_data.connector_auth_type.clone(),
    //         }
    //     }

    //     #[test]
    //     fn test_rsync_request_build() {
    //         let (_connector, connector_data) = get_elavon_connector_data();
    //         let router_data = get_router_data_for_rsync();

    //         let rsync_integration = connector_data.connector
    //             .get_connector_integration_v2::<RSync, RefundFlowData, RefundSyncData, DomainRefundsResponseData>();

    //         let result = rsync_integration.get_request_body(&router_data);
    //         assert!(result.is_ok());
    //         let request_content = result.unwrap().unwrap();
    //         match request_content {
    //             RequestContent::FormUrlEncoded(form_data_map_wrapper) => {
    //                 let json_val = form_data_map_wrapper.masked_serialize().unwrap();
    //                 let xml_data = json_val.get("xmldata").unwrap().as_str().unwrap();
    //                 assert!(xml_data.contains("<ssl_transaction_type>txnquery</ssl_transaction_type>"));
    //                 assert!(xml_data.contains("<ssl_txn_id>REF_SYNC_456</ssl_txn_id>"));
    //             }
    //             _ => panic!("Expected FormUrlEncoded request body"),
    //         }
    //     }

    //     #[test]
    //     fn test_rsync_response_handling_settled_return() {
    //         let (_connector, connector_data) = get_elavon_connector_data();
    //         let router_data = get_router_data_for_rsync();
    //         let response_body_str = r#"<txn><ssl_trans_status>STL</ssl_trans_status><ssl_transaction_type>RETURN</ssl_transaction_type><ssl_txn_id>REF_SYNC_456</ssl_txn_id></txn>"#;
    //         let response = HsResponse {
    //             headers: None,
    //             response: response_body_str.as_bytes().to_vec().into(),
    //             status_code: 200,
    //         };

    //         let rsync_integration = connector_data.connector
    //             .get_connector_integration_v2::<RSync, RefundFlowData, RefundSyncData, DomainRefundsResponseData>();
                
    //         let result = rsync_integration.handle_response_v2(&router_data, None, response);
    //         assert!(result.is_ok());
    //         let response_router_data = result.unwrap();
    //         assert_eq!(response_router_data.resource_common_data.status, RefundStatus::Success);
    //     }
    // }
} 