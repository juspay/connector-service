#[cfg(test)]
mod tests {
    pub mod authorize {
        use crate::connectors::Xendit;
        use crate::types::ConnectorData;
        use domain_types::connector_flow::Authorize;
        use domain_types::connector_types::{
            BoxedConnector, ConnectorEnum, PaymentFlowData, PaymentsAuthorizeData,
            PaymentsResponseData,
        };
        use domain_types::types::{ConnectorParams, Connectors};
        use hyperswitch_common_utils::pii::Email;
        use hyperswitch_common_utils::request::RequestContent;
        use hyperswitch_common_utils::types::MinorUnit;
        use hyperswitch_domain_models::{
            payment_method_data::PaymentMethodData,
            router_data::{ConnectorAuthType, ErrorResponse},
            router_data_v2::RouterDataV2,
        };
        use hyperswitch_interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;
        use hyperswitch_masking::Secret;
        use serde_json::json;
        use std::borrow::Cow;
        use std::env;
        use std::marker::PhantomData;
        use std::str::FromStr;

        #[test]
        fn test_build_request_valid() {
            let api_key = env::var("XENDIT_API_KEY").expect("XENDIT_API_KEY not set");
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: PaymentFlowData {
                    merchant_id: hyperswitch_common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: Some("conn_cust_987654".to_string()),
                    payment_id: "pay_abcdef123456".to_string(),
                    attempt_id: "attempt_123456abcdef".to_string(),
                    status: hyperswitch_common_enums::AttemptStatus::Pending,
                    payment_method: hyperswitch_common_enums::PaymentMethod::Card,
                    description: Some("Payment for order #12345".to_string()),
                    return_url: Some("www.google.com".to_string()),
                    address: hyperswitch_domain_models::payment_address::PaymentAddress::new(
                        None, None, None, None,
                    ),
                    auth_type: hyperswitch_common_enums::AuthenticationType::ThreeDs,
                    connector_meta_data: None,
                    amount_captured: None,
                    minor_amount_captured: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    payment_method_token: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: "conn_ref_123456789".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: Connectors {
                        adyen: ConnectorParams {
                            base_url: "https://checkout-test.adyen.com/".to_string(),
                        },
                        razorpay: ConnectorParams {
                            base_url: "https://sandbox.juspay.in/".to_string(),
                        },
                        checkout: ConnectorParams {
                            base_url: "https://api.sandbox.checkout.com/".to_string(),
                        },
                        paypal: ConnectorParams {
                            base_url: "https://api-m.sandbox.paypal.com/".to_string(),
                        },
                        jpmorgan: ConnectorParams {
                            base_url: "https://api-m.sandbox.jpmorgan.com/".to_string(),
                        },
                        airwallex: ConnectorParams {
                            base_url: "https://api-demo.airwallex.com/".to_string(),
                        },
                        xendit: ConnectorParams {
                            base_url: "https://api.xendit.co/v2".to_string(),
                        },
                    },
                    external_latency: None,
                },
                connector_auth_type: ConnectorAuthType::HeaderKey {
                    api_key: Secret::new(api_key),
                },
                request: PaymentsAuthorizeData {
                    payment_method_data: PaymentMethodData::Card(
                        hyperswitch_domain_models::payment_method_data::Card {
                            card_number: hyperswitch_cards::CardNumber::from_str(
                                "5123456789012346",
                            )
                            .unwrap(),
                            card_cvc: Secret::new("100".into()),
                            card_exp_month: Secret::new("03".into()),
                            card_exp_year: Secret::new("2030".into()),
                            ..Default::default()
                        },
                    ),
                    amount: 1000,
                    order_tax_amount: None,
                    email: Some(
                        Email::try_from("test@example.com".to_string())
                            .expect("Failed to parse email"),
                    ),
                    customer_name: None,
                    currency: hyperswitch_common_enums::Currency::USD,
                    confirm: true,
                    statement_descriptor_suffix: None,
                    statement_descriptor: None,
                    capture_method: None,
                    router_return_url: Some("www.google.com".to_string()),
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    browser_info: Some(
                        hyperswitch_domain_models::router_request_types::BrowserInformation {
                            color_depth: None,
                            java_enabled: Some(false),
                            screen_height: Some(1080),
                            screen_width: Some(1920),
                            user_agent: Some(
                                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string(),
                            ),
                            accept_header: Some(
                                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                                    .to_string(),
                            ),
                            java_script_enabled: Some(false),
                            language: Some("en-US".to_string()),
                            time_zone: None,
                            ip_address: None,
                        },
                    ),
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: true,
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: Some(hyperswitch_common_enums::PaymentMethodType::Credit),
                    customer_id: Some(
                        hyperswitch_common_utils::id_type::CustomerId::try_from(Cow::from(
                            "cus_123456789".to_string(),
                        ))
                        .unwrap(),
                    ),
                    request_incremental_authorization: false,
                    metadata: None,
                    minor_amount: MinorUnit::new(1000),
                    merchant_order_reference_id: None,
                    shipping_cost: None,
                    merchant_account_id: None,
                    merchant_config_currency: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector = Box::new(Xendit::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Xendit,
            };

            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            let request = connector_integration.build_request_v2(&req).unwrap();
            let req = request.as_ref().map(|request| {
                let masked_request = match request.body.as_ref() {
                    Some(request) => match request {
                        RequestContent::Json(i)
                        | RequestContent::FormUrlEncoded(i)
                        | RequestContent::Xml(i) => i.masked_serialize().unwrap_or(
                            json!({ "error": "failed to mask serialize connector request"}),
                        ),
                        RequestContent::FormData(_) => json!({"request_type": "FORM_DATA"}),
                        RequestContent::RawBytes(_) => json!({"request_type": "RAW_BYTES"}),
                    },
                    None => serde_json::Value::Null,
                };
                masked_request
            });
            println!("request: {:?}", req);
            assert_eq!(req.as_ref().unwrap()["external_id"], "conn_ref_123456789");
        }

        #[test]
        fn test_build_request_missing() {
            let api_key = env::var("XENDIT_API_KEY").expect("XENDIT_API_KEY not set");
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: PaymentFlowData {
                    merchant_id: hyperswitch_common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: None,
                    payment_id: "".to_string(),
                    attempt_id: "".to_string(),
                    status: hyperswitch_common_enums::AttemptStatus::Pending,
                    payment_method: hyperswitch_common_enums::PaymentMethod::Card,
                    description: None,
                    return_url: None,
                    address: hyperswitch_domain_models::payment_address::PaymentAddress::new(
                        None, None, None, None,
                    ),
                    auth_type: hyperswitch_common_enums::AuthenticationType::ThreeDs,
                    connector_meta_data: None,
                    amount_captured: None,
                    minor_amount_captured: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    payment_method_token: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: "".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: Connectors {
                        adyen: ConnectorParams {
                            base_url: "https://checkout-test.adyen.com/".to_string(),
                        },
                        razorpay: ConnectorParams {
                            base_url: "https://sandbox.juspay.in/".to_string(),
                        },
                        checkout: ConnectorParams {
                            base_url: "https://api.sandbox.checkout.com/".to_string(),
                        },
                        paypal: ConnectorParams {
                            base_url: "https://api-m.sandbox.paypal.com/".to_string(),
                        },
                        jpmorgan: ConnectorParams {
                            base_url: "https://api-m.sandbox.jpmorgan.com/".to_string(),
                        },
                        airwallex: ConnectorParams {
                            base_url: "https://api-demo.airwallex.com/".to_string(),
                        },
                        xendit: ConnectorParams {
                            base_url: "https://api.xendit.co/v2".to_string(),
                        },
                    },
                    external_latency: None,
                },
                connector_auth_type: ConnectorAuthType::HeaderKey {
                    api_key: Secret::new(api_key),
                },
                request: PaymentsAuthorizeData {
                    payment_method_data: PaymentMethodData::Card(Default::default()),
                    amount: 0,
                    order_tax_amount: None,
                    email: None,
                    customer_name: None,
                    currency: hyperswitch_common_enums::Currency::USD,
                    confirm: true,
                    statement_descriptor_suffix: None,
                    statement_descriptor: None,
                    capture_method: None,
                    router_return_url: None,
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    browser_info: None,
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: false,
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: None,
                    customer_id: None,
                    request_incremental_authorization: false,
                    metadata: None,
                    minor_amount: MinorUnit::new(0),
                    merchant_order_reference_id: None,
                    shipping_cost: None,
                    merchant_account_id: None,
                    merchant_config_currency: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector = Box::new(Xendit::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Xendit,
            };

            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            let result = connector_integration.build_request_v2(&req);
            assert!(result.is_err(), "Expected error for missing fields");
        }

        #[test]
        fn test_handle_response_v2_valid_authorize_response() {
            let api_key = env::var("XENDIT_API_KEY").expect("XENDIT_API_KEY not set");
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: PaymentFlowData {
                    merchant_id: hyperswitch_common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: Some("conn_cust_987654".to_string()),
                    payment_id: "pay_abcdef123456".to_string(),
                    attempt_id: "attempt_123456abcdef".to_string(),
                    status: hyperswitch_common_enums::AttemptStatus::Pending,
                    payment_method: hyperswitch_common_enums::PaymentMethod::Card,
                    description: Some("Payment for order #12345".to_string()),
                    return_url: Some("www.google.com".to_string()),
                    address: hyperswitch_domain_models::payment_address::PaymentAddress::new(
                        None, None, None, None,
                    ),
                    auth_type: hyperswitch_common_enums::AuthenticationType::ThreeDs,
                    connector_meta_data: None,
                    amount_captured: None,
                    minor_amount_captured: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    payment_method_token: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: "conn_ref_123456789".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: Connectors {
                        adyen: ConnectorParams {
                            base_url: "https://checkout-test.adyen.com/".to_string(),
                        },
                        razorpay: ConnectorParams {
                            base_url: "https://sandbox.juspay.in/".to_string(),
                        },
                        checkout: ConnectorParams {
                            base_url: "https://api.sandbox.checkout.com/".to_string(),
                        },
                        paypal: ConnectorParams {
                            base_url: "https://api-m.sandbox.paypal.com/".to_string(),
                        },
                        jpmorgan: ConnectorParams {
                            base_url: "https://api-m.sandbox.jpmorgan.com/".to_string(),
                        },
                        airwallex: ConnectorParams {
                            base_url: "https://api-demo.airwallex.com/".to_string(),
                        },
                        xendit: ConnectorParams {
                            base_url: "https://api.xendit.co/v2".to_string(),
                        },
                    },
                    external_latency: None,
                },
                connector_auth_type: ConnectorAuthType::HeaderKey {
                    api_key: Secret::new(api_key),
                },
                request: PaymentsAuthorizeData {
                    payment_method_data: PaymentMethodData::Card(
                        hyperswitch_domain_models::payment_method_data::Card {
                            card_number: hyperswitch_cards::CardNumber::from_str(
                                "5123456789012346",
                            )
                            .unwrap(),
                            card_cvc: Secret::new("100".into()),
                            card_exp_month: Secret::new("03".into()),
                            card_exp_year: Secret::new("2030".into()),
                            ..Default::default()
                        },
                    ),
                    amount: 1000,
                    order_tax_amount: None,
                    email: Some(
                        Email::try_from("test@example.com".to_string())
                            .expect("Failed to parse email"),
                    ),
                    customer_name: None,
                    currency: hyperswitch_common_enums::Currency::USD,
                    confirm: true,
                    statement_descriptor_suffix: None,
                    statement_descriptor: None,
                    capture_method: None,
                    router_return_url: Some("www.google.com".to_string()),
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    browser_info: Some(
                        hyperswitch_domain_models::router_request_types::BrowserInformation {
                            color_depth: None,
                            java_enabled: Some(false),
                            screen_height: Some(1080),
                            screen_width: Some(1920),
                            user_agent: Some(
                                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string(),
                            ),
                            accept_header: Some(
                                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                                    .to_string(),
                            ),
                            java_script_enabled: Some(false),
                            language: Some("en-US".to_string()),
                            time_zone: None,
                            ip_address: None,
                        },
                    ),
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: true,
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: Some(hyperswitch_common_enums::PaymentMethodType::Credit),
                    customer_id: Some(
                        hyperswitch_common_utils::id_type::CustomerId::try_from(Cow::from(
                            "cus_123456789".to_string(),
                        ))
                        .unwrap(),
                    ),
                    request_incremental_authorization: false,
                    metadata: None,
                    minor_amount: MinorUnit::new(1000),
                    merchant_order_reference_id: None,
                    shipping_cost: None,
                    merchant_account_id: None,
                    merchant_config_currency: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector = Box::new(Xendit::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Xendit,
            };

            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            let response = hyperswitch_common_utils::request::Response {
                status_code: 200,
                headers: vec![],
                response: r#"{
                    "id": "xendit_payment_123",
                    "status": "PENDING",
                    "amount": 1000,
                    "currency": "USD",
                    "external_id": "conn_ref_123456789",
                    "payment_method": {
                        "type": "CARD",
                        "card": {
                            "last_four_digits": "2346",
                            "brand": "MASTERCARD"
                        }
                    },
                    "actions": {
                        "desktop_web_checkout_url": "https://checkout.xendit.co/web/123",
                        "mobile_web_checkout_url": "https://checkout.xendit.co/web/123",
                        "mobile_deeplink_checkout_url": "https://checkout.xendit.co/deeplink/123"
                    }
                }"#
                .as_bytes()
                .to_vec()
                .into(),
            };

            let result = connector_integration.handle_response_v2(&req, None, response);
            assert!(result.is_ok(), "Expected successful response handling");
            let response = result.unwrap();
            assert_eq!(
                response.resource_common_data.status,
                hyperswitch_common_enums::AttemptStatus::Pending
            );
        }

        #[test]
        fn test_handle_authorize_error_response() {
            let api_key = env::var("XENDIT_API_KEY").expect("XENDIT_API_KEY not set");
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: PaymentFlowData {
                    merchant_id: hyperswitch_common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: Some("conn_cust_987654".to_string()),
                    payment_id: "pay_abcdef123456".to_string(),
                    attempt_id: "attempt_123456abcdef".to_string(),
                    status: hyperswitch_common_enums::AttemptStatus::Pending,
                    payment_method: hyperswitch_common_enums::PaymentMethod::Card,
                    description: Some("Payment for order #12345".to_string()),
                    return_url: Some("www.google.com".to_string()),
                    address: hyperswitch_domain_models::payment_address::PaymentAddress::new(
                        None, None, None, None,
                    ),
                    auth_type: hyperswitch_common_enums::AuthenticationType::ThreeDs,
                    connector_meta_data: None,
                    amount_captured: None,
                    minor_amount_captured: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    payment_method_token: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: "conn_ref_123456789".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: Connectors {
                        adyen: ConnectorParams {
                            base_url: "https://checkout-test.adyen.com/".to_string(),
                        },
                        razorpay: ConnectorParams {
                            base_url: "https://sandbox.juspay.in/".to_string(),
                        },
                        checkout: ConnectorParams {
                            base_url: "https://api.sandbox.checkout.com/".to_string(),
                        },
                        paypal: ConnectorParams {
                            base_url: "https://api-m.sandbox.paypal.com/".to_string(),
                        },
                        jpmorgan: ConnectorParams {
                            base_url: "https://api-m.sandbox.jpmorgan.com/".to_string(),
                        },
                        airwallex: ConnectorParams {
                            base_url: "https://api-demo.airwallex.com/".to_string(),
                        },
                        xendit: ConnectorParams {
                            base_url: "https://api.xendit.co/v2".to_string(),
                        },
                    },
                    external_latency: None,
                },
                connector_auth_type: ConnectorAuthType::HeaderKey {
                    api_key: Secret::new(api_key),
                },
                request: PaymentsAuthorizeData {
                    payment_method_data: PaymentMethodData::Card(
                        hyperswitch_domain_models::payment_method_data::Card {
                            card_number: hyperswitch_cards::CardNumber::from_str(
                                "5123456789012346",
                            )
                            .unwrap(),
                            card_cvc: Secret::new("100".into()),
                            card_exp_month: Secret::new("03".into()),
                            card_exp_year: Secret::new("2030".into()),
                            ..Default::default()
                        },
                    ),
                    amount: 1000,
                    order_tax_amount: None,
                    email: Some(
                        Email::try_from("test@example.com".to_string())
                            .expect("Failed to parse email"),
                    ),
                    customer_name: None,
                    currency: hyperswitch_common_enums::Currency::USD,
                    confirm: true,
                    statement_descriptor_suffix: None,
                    statement_descriptor: None,
                    capture_method: None,
                    router_return_url: Some("www.google.com".to_string()),
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    browser_info: Some(
                        hyperswitch_domain_models::router_request_types::BrowserInformation {
                            color_depth: None,
                            java_enabled: Some(false),
                            screen_height: Some(1080),
                            screen_width: Some(1920),
                            user_agent: Some(
                                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string(),
                            ),
                            accept_header: Some(
                                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                                    .to_string(),
                            ),
                            java_script_enabled: Some(false),
                            language: Some("en-US".to_string()),
                            time_zone: None,
                            ip_address: None,
                        },
                    ),
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: true,
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: Some(hyperswitch_common_enums::PaymentMethodType::Credit),
                    customer_id: Some(
                        hyperswitch_common_utils::id_type::CustomerId::try_from(Cow::from(
                            "cus_123456789".to_string(),
                        ))
                        .unwrap(),
                    ),
                    request_incremental_authorization: false,
                    metadata: None,
                    minor_amount: MinorUnit::new(1000),
                    merchant_order_reference_id: None,
                    shipping_cost: None,
                    merchant_account_id: None,
                    merchant_config_currency: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector = Box::new(Xendit::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Xendit,
            };

            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            let response = hyperswitch_common_utils::request::Response {
                status_code: 400,
                headers: vec![],
                response: r#"{
                    "error_code": "INVALID_PAYMENT_METHOD",
                    "message": "Invalid payment method",
                    "reason": "Card details are invalid"
                }"#
                .as_bytes()
                .to_vec()
                .into(),
            };

            let result = connector_integration.handle_response_v2(&req, None, response);
            assert!(result.is_err(), "Expected error response handling");
        }
    }
} 