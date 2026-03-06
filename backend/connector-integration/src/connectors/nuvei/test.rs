#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::panic)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::print_stdout)]
mod tests {
    pub mod authorize_cit {
        use std::{borrow::Cow, marker::PhantomData, net::IpAddr, str::FromStr};

        use common_utils::{pii::Email, request::RequestContent, types::MinorUnit};
        use domain_types::{
            connector_flow::Authorize,
            connector_types::{
                ConnectorEnum, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
            },
            payment_method_data::{DefaultPCIHolder, PaymentMethodData, RawCardNumber},
            router_data::{ConnectorSpecificAuth, ErrorResponse},
            router_data_v2::RouterDataV2,
            types::{ConnectorParams, Connectors},
        };
        use hyperswitch_masking::Secret;
        use interfaces::{
            connector_integration_v2::BoxedConnectorIntegrationV2,
            connector_types::BoxedConnector,
        };
        use serde_json::json;

        use crate::{connectors::Nuvei, types::ConnectorData};

        fn build_payment_flow_data() -> PaymentFlowData {
            PaymentFlowData {
                merchant_id: common_utils::id_type::MerchantId::default(),
                customer_id: None,
                connector_customer: None,
                payment_id: "pay_ntid_test_001".to_string(),
                attempt_id: "attempt_ntid_test_001".to_string(),
                status: common_enums::AttemptStatus::Pending,
                payment_method: common_enums::PaymentMethod::Card,
                description: Some("NTID CIT test payment".to_string()),
                return_url: Some("https://example.com/return".to_string()),
                order_details: None,
                address: domain_types::payment_address::PaymentAddress::new(
                    None,
                    Some(domain_types::payment_address::Address {
                        address: Some(domain_types::payment_address::AddressDetails {
                            city: Some(Secret::new("New York".to_string())),
                            country: Some(common_enums::CountryAlpha2::US),
                            line1: Some(Secret::new("123 Main St".to_string())),
                            line2: None,
                            line3: None,
                            zip: Some(Secret::new("10001".to_string())),
                            state: Some(Secret::new("NY".to_string())),
                            first_name: Some(Secret::new("John".to_string())),
                            last_name: Some(Secret::new("Doe".to_string())),
                            origin_zip: None,
                        }),
                        phone: None,
                        email: Some(
                            Email::try_from("test@example.com".to_string())
                                .expect("Failed to parse email"),
                        ),
                    }),
                    None,
                    None,
                ),
                auth_type: common_enums::AuthenticationType::NoThreeDs,
                connector_meta_data: None,
                amount_captured: None,
                minor_amount_captured: None,
                minor_amount_authorized: None,
                access_token: None,
                session_token: Some("test_session_token_12345".to_string()),
                reference_id: None,
                payment_method_token: None,
                preprocessing_id: None,
                connector_api_version: None,
                connector_request_reference_id: "conn_ref_ntid_test_001".to_string(),
                test_mode: None,
                connector_http_status_code: None,
                connectors: Connectors {
                    nuvei: ConnectorParams {
                        base_url: "https://ppp-test.nuvei.com/ppp/api/v1".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                external_latency: None,
                connector_response_headers: None,
                raw_connector_response: None,
                vault_headers: None,
                raw_connector_request: None,
                minor_amount_capturable: None,
                connector_response: None,
                recurring_mandate_payment_data: None,
            }
        }

        fn build_nuvei_auth() -> ConnectorSpecificAuth {
            ConnectorSpecificAuth::Nuvei {
                merchant_id: Secret::new("test_merchant_id".to_string()),
                merchant_site_id: Secret::new("test_site_id".to_string()),
                merchant_secret: Secret::new("test_secret".to_string()),
            }
        }

        #[test]
        fn test_cit_authorize_with_setup_future_usage_includes_stored_credentials() {
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: build_payment_flow_data(),
                connector_auth_type: build_nuvei_auth(),
                request: PaymentsAuthorizeData {
                    payment_channel: None,
                    authentication_data: None,
                    connector_testing_data: None,
                    payment_method_data: PaymentMethodData::Card(
                        domain_types::payment_method_data::Card {
                            card_number: RawCardNumber(
                                cards::CardNumber::from_str("4111111111111111").unwrap(),
                            ),
                            card_cvc: Secret::new("123".into()),
                            card_exp_month: Secret::new("12".into()),
                            card_exp_year: Secret::new("2030".into()),
                            ..Default::default()
                        },
                    ),
                    amount: MinorUnit::new(1000),
                    order_tax_amount: None,
                    email: Some(
                        Email::try_from("test@example.com".to_string())
                            .expect("Failed to parse email"),
                    ),
                    customer_name: Some("John Doe".to_string()),
                    currency: common_enums::Currency::USD,
                    confirm: true,
                    capture_method: None,
                    integrity_object: None,
                    router_return_url: Some("https://example.com/return".to_string()),
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: Some(common_enums::FutureUsage::OffSession),
                    off_session: None,
                    browser_info: Some(
                        domain_types::router_request_types::BrowserInformation {
                            color_depth: Some(24),
                            java_enabled: Some(false),
                            screen_height: Some(1080),
                            screen_width: Some(1920),
                            user_agent: Some("Mozilla/5.0".to_string()),
                            accept_header: Some("text/html".to_string()),
                            java_script_enabled: Some(false),
                            language: Some("en-US".to_string()),
                            time_zone: Some(-480),
                            referer: None,
                            ip_address: Some(IpAddr::from_str("127.0.0.1").unwrap()),
                            os_type: None,
                            os_version: None,
                            device_model: None,
                            accept_language: None,
                        },
                    ),
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: Some(false),
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: Some(common_enums::PaymentMethodType::Card),
                    customer_id: Some(
                        common_utils::id_type::CustomerId::try_from(Cow::from(
                            "cus_ntid_test".to_string(),
                        ))
                        .unwrap(),
                    ),
                    request_incremental_authorization: Some(false),
                    metadata: None,
                    minor_amount: MinorUnit::new(1000),
                    merchant_order_reference_id: None,
                    shipping_cost: None,
                    merchant_account_id: None,
                    merchant_config_currency: None,
                    all_keys_required: None,
                    access_token: None,
                    customer_acceptance: None,
                    split_payments: None,
                    request_extended_authorization: None,
                    setup_mandate_details: None,
                    enable_overcapture: None,
                    merchant_account_metadata: None,
                    billing_descriptor: None,
                    enable_partial_authorization: None,
                    locale: None,
                    continue_redirection_url: None,
                    redirect_response: None,
                    threeds_method_comp_ind: None,
                    tokenization: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Nuvei::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Nuvei,
            };

            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            let request = connector_integration.build_request_v2(&req).unwrap();
            let req_body = request.as_ref().map(|request_val| {
                match request_val.body.as_ref() {
                    Some(request_content) => match request_content {
                        RequestContent::Json(i)
                        | RequestContent::FormUrlEncoded(i)
                        | RequestContent::Xml(i) => i.masked_serialize().unwrap_or(
                            json!({ "error": "failed to mask serialize connector request"}),
                        ),
                        RequestContent::FormData(_) => json!({"request_type": "FORM_DATA"}),
                        RequestContent::RawBytes(_) => json!({"request_type": "RAW_BYTES"}),
                    },
                    None => serde_json::Value::Null,
                }
            });

            println!("CIT request body: {req_body:?}");
            let body = req_body.unwrap();

            // Verify stored_credentials is present with mode "0" (First) for CIT
            assert!(
                body["paymentOption"]["card"]["storedCredentials"].is_object(),
                "stored_credentials should be present for CIT with setup_future_usage=OffSession"
            );
            assert_eq!(
                body["paymentOption"]["card"]["storedCredentials"]["storedCredentialsMode"],
                "0",
                "storedCredentialsMode should be '0' (First) for CIT"
            );

            // Verify basic payment fields
            assert_eq!(body["currency"], "USD");
            assert_eq!(
                body["clientRequestId"], "conn_ref_ntid_test_001",
                "clientRequestId should match connector_request_reference_id"
            );
        }

        #[test]
        fn test_authorize_without_setup_future_usage_no_stored_credentials() {
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: build_payment_flow_data(),
                connector_auth_type: build_nuvei_auth(),
                request: PaymentsAuthorizeData {
                    payment_channel: None,
                    authentication_data: None,
                    connector_testing_data: None,
                    payment_method_data: PaymentMethodData::Card(
                        domain_types::payment_method_data::Card {
                            card_number: RawCardNumber(
                                cards::CardNumber::from_str("4111111111111111").unwrap(),
                            ),
                            card_cvc: Secret::new("123".into()),
                            card_exp_month: Secret::new("12".into()),
                            card_exp_year: Secret::new("2030".into()),
                            ..Default::default()
                        },
                    ),
                    amount: MinorUnit::new(500),
                    order_tax_amount: None,
                    email: Some(
                        Email::try_from("test@example.com".to_string())
                            .expect("Failed to parse email"),
                    ),
                    customer_name: Some("John Doe".to_string()),
                    currency: common_enums::Currency::USD,
                    confirm: true,
                    capture_method: None,
                    integrity_object: None,
                    router_return_url: Some("https://example.com/return".to_string()),
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    browser_info: Some(
                        domain_types::router_request_types::BrowserInformation {
                            color_depth: Some(24),
                            java_enabled: Some(false),
                            screen_height: Some(1080),
                            screen_width: Some(1920),
                            user_agent: Some("Mozilla/5.0".to_string()),
                            accept_header: Some("text/html".to_string()),
                            java_script_enabled: Some(false),
                            language: Some("en-US".to_string()),
                            time_zone: Some(-480),
                            referer: None,
                            ip_address: Some(IpAddr::from_str("127.0.0.1").unwrap()),
                            os_type: None,
                            os_version: None,
                            device_model: None,
                            accept_language: None,
                        },
                    ),
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: Some(false),
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: Some(common_enums::PaymentMethodType::Card),
                    customer_id: None,
                    request_incremental_authorization: Some(false),
                    metadata: None,
                    minor_amount: MinorUnit::new(500),
                    merchant_order_reference_id: None,
                    shipping_cost: None,
                    merchant_account_id: None,
                    merchant_config_currency: None,
                    all_keys_required: None,
                    access_token: None,
                    customer_acceptance: None,
                    split_payments: None,
                    request_extended_authorization: None,
                    setup_mandate_details: None,
                    enable_overcapture: None,
                    merchant_account_metadata: None,
                    billing_descriptor: None,
                    enable_partial_authorization: None,
                    locale: None,
                    continue_redirection_url: None,
                    redirect_response: None,
                    threeds_method_comp_ind: None,
                    tokenization: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Nuvei::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Nuvei,
            };

            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            let request = connector_integration.build_request_v2(&req).unwrap();
            let req_body = request.as_ref().map(|request_val| {
                match request_val.body.as_ref() {
                    Some(request_content) => match request_content {
                        RequestContent::Json(i)
                        | RequestContent::FormUrlEncoded(i)
                        | RequestContent::Xml(i) => i.masked_serialize().unwrap_or(
                            json!({ "error": "failed to mask serialize connector request"}),
                        ),
                        RequestContent::FormData(_) => json!({"request_type": "FORM_DATA"}),
                        RequestContent::RawBytes(_) => json!({"request_type": "RAW_BYTES"}),
                    },
                    None => serde_json::Value::Null,
                }
            });

            let body = req_body.unwrap();

            // Verify stored_credentials is NOT present when setup_future_usage is None
            assert!(
                body["paymentOption"]["card"]["storedCredentials"].is_null(),
                "stored_credentials should NOT be present when setup_future_usage is not OffSession"
            );
        }
    }

    pub mod repeat_payment_mit {
        use std::{marker::PhantomData, str::FromStr};

        use common_utils::{pii::Email, request::RequestContent, types::MinorUnit};
        use domain_types::{
            connector_flow::RepeatPayment,
            connector_types::{
                ConnectorEnum, MandateReferenceId, PaymentFlowData, PaymentsResponseData,
                RepeatPaymentData,
            },
            payment_method_data::{
                CardDetailsForNetworkTransactionId, DefaultPCIHolder, PaymentMethodData,
            },
            router_data::{ConnectorSpecificAuth, ErrorResponse},
            router_data_v2::RouterDataV2,
            types::{ConnectorParams, Connectors},
        };
        use hyperswitch_masking::Secret;
        use interfaces::{
            connector_integration_v2::BoxedConnectorIntegrationV2,
            connector_types::BoxedConnector,
        };
        use serde_json::json;

        use crate::{connectors::Nuvei, types::ConnectorData};

        fn build_payment_flow_data() -> PaymentFlowData {
            PaymentFlowData {
                merchant_id: common_utils::id_type::MerchantId::default(),
                customer_id: None,
                connector_customer: None,
                payment_id: "pay_mit_test_001".to_string(),
                attempt_id: "attempt_mit_test_001".to_string(),
                status: common_enums::AttemptStatus::Pending,
                payment_method: common_enums::PaymentMethod::Card,
                description: Some("NTID MIT test payment".to_string()),
                return_url: Some("https://example.com/return".to_string()),
                order_details: None,
                address: domain_types::payment_address::PaymentAddress::new(
                    None,
                    Some(domain_types::payment_address::Address {
                        address: Some(domain_types::payment_address::AddressDetails {
                            city: Some(Secret::new("New York".to_string())),
                            country: Some(common_enums::CountryAlpha2::US),
                            line1: Some(Secret::new("123 Main St".to_string())),
                            line2: None,
                            line3: None,
                            zip: Some(Secret::new("10001".to_string())),
                            state: Some(Secret::new("NY".to_string())),
                            first_name: Some(Secret::new("John".to_string())),
                            last_name: Some(Secret::new("Doe".to_string())),
                            origin_zip: None,
                        }),
                        phone: None,
                        email: Some(
                            Email::try_from("test@example.com".to_string())
                                .expect("Failed to parse email"),
                        ),
                    }),
                    None,
                    None,
                ),
                auth_type: common_enums::AuthenticationType::NoThreeDs,
                connector_meta_data: None,
                amount_captured: None,
                minor_amount_captured: None,
                minor_amount_authorized: None,
                access_token: None,
                session_token: Some("test_session_token_12345".to_string()),
                reference_id: None,
                payment_method_token: None,
                preprocessing_id: None,
                connector_api_version: None,
                connector_request_reference_id: "conn_ref_mit_test_001".to_string(),
                test_mode: None,
                connector_http_status_code: None,
                connectors: Connectors {
                    nuvei: ConnectorParams {
                        base_url: "https://ppp-test.nuvei.com/ppp/api/v1".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                external_latency: None,
                connector_response_headers: None,
                raw_connector_response: None,
                vault_headers: None,
                raw_connector_request: None,
                minor_amount_capturable: None,
                connector_response: None,
                recurring_mandate_payment_data: None,
            }
        }

        fn build_nuvei_auth() -> ConnectorSpecificAuth {
            ConnectorSpecificAuth::Nuvei {
                merchant_id: Secret::new("test_merchant_id".to_string()),
                merchant_site_id: Secret::new("test_site_id".to_string()),
                merchant_secret: Secret::new("test_secret".to_string()),
            }
        }

        #[test]
        fn test_repeat_payment_with_ntid_builds_external_scheme_details() {
            let ntid = "483297487231504";
            let req: RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<RepeatPayment>,
                resource_common_data: build_payment_flow_data(),
                connector_auth_type: build_nuvei_auth(),
                request: RepeatPaymentData {
                    mandate_reference: MandateReferenceId::NetworkMandateId(ntid.to_string()),
                    amount: 1000,
                    minor_amount: MinorUnit::new(1000),
                    currency: common_enums::Currency::USD,
                    merchant_order_reference_id: None,
                    metadata: None,
                    webhook_url: None,
                    integrity_object: None,
                    capture_method: None,
                    browser_info: Some(
                        domain_types::router_request_types::BrowserInformation {
                            color_depth: None,
                            java_enabled: None,
                            screen_height: None,
                            screen_width: None,
                            user_agent: None,
                            accept_header: None,
                            java_script_enabled: None,
                            language: None,
                            time_zone: None,
                            referer: None,
                            ip_address: Some(std::net::IpAddr::from_str("127.0.0.1").unwrap()),
                            os_type: None,
                            os_version: None,
                            device_model: None,
                            accept_language: None,
                        },
                    ),
                    email: Some(
                        Email::try_from("test@example.com".to_string())
                            .expect("Failed to parse email"),
                    ),
                    payment_method_type: Some(common_enums::PaymentMethodType::Card),
                    merchant_account_metadata: None,
                    off_session: Some(true),
                    router_return_url: Some("https://example.com/return".to_string()),
                    split_payments: None,
                    recurring_mandate_payment_data: None,
                    shipping_cost: None,
                    mit_category: None,
                    enable_partial_authorization: None,
                    billing_descriptor: None,
                    payment_method_data: PaymentMethodData::CardDetailsForNetworkTransactionId(
                        CardDetailsForNetworkTransactionId {
                            card_number: cards::CardNumber::from_str("4111111111111111").unwrap(),
                            card_exp_month: Secret::new("12".into()),
                            card_exp_year: Secret::new("2030".into()),
                            card_issuer: None,
                            card_network: Some(common_enums::CardNetwork::Visa),
                            card_type: None,
                            card_issuing_country: None,
                            bank_code: None,
                            nick_name: None,
                            card_holder_name: Some(Secret::new("John Doe".to_string())),
                        },
                    ),
                    authentication_data: None,
                    locale: None,
                    connector_testing_data: None,
                    merchant_account_id: None,
                    merchant_configured_currency: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Nuvei::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Nuvei,
            };

            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            let request = connector_integration.build_request_v2(&req).unwrap();
            let req_body = request.as_ref().map(|request_val| {
                match request_val.body.as_ref() {
                    Some(request_content) => match request_content {
                        RequestContent::Json(i)
                        | RequestContent::FormUrlEncoded(i)
                        | RequestContent::Xml(i) => i.masked_serialize().unwrap_or(
                            json!({ "error": "failed to mask serialize connector request"}),
                        ),
                        RequestContent::FormData(_) => json!({"request_type": "FORM_DATA"}),
                        RequestContent::RawBytes(_) => json!({"request_type": "RAW_BYTES"}),
                    },
                    None => serde_json::Value::Null,
                }
            });

            println!("MIT RepeatPayment request body: {req_body:?}");
            let body = req_body.unwrap();

            // Verify externalSchemeDetails is present with the NTID
            assert!(
                body["externalSchemeDetails"].is_object(),
                "externalSchemeDetails should be present for MIT with NTID"
            );
            // transactionId is a Secret so it will be masked in serialization
            assert!(
                !body["externalSchemeDetails"]["transactionId"].is_null(),
                "transactionId should be present in externalSchemeDetails"
            );
            assert_eq!(
                body["externalSchemeDetails"]["brand"], "Visa",
                "brand should be Visa for Visa card network"
            );

            // Verify card details are present (without CVV)
            assert!(
                body["paymentOption"]["card"].is_object(),
                "card details should be present in paymentOption"
            );
            // Card number is masked, just verify it exists
            assert!(
                !body["paymentOption"]["card"]["cardNumber"].is_null(),
                "cardNumber should be present"
            );

            // Verify basic payment fields
            assert_eq!(body["currency"], "USD");
            assert_eq!(
                body["clientRequestId"], "conn_ref_mit_test_001",
                "clientRequestId should match connector_request_reference_id"
            );
        }

        #[test]
        fn test_repeat_payment_url_uses_payment_do_endpoint() {
            let req: RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<RepeatPayment>,
                resource_common_data: build_payment_flow_data(),
                connector_auth_type: build_nuvei_auth(),
                request: RepeatPaymentData {
                    mandate_reference: MandateReferenceId::NetworkMandateId(
                        "test_ntid_12345".to_string(),
                    ),
                    amount: 500,
                    minor_amount: MinorUnit::new(500),
                    currency: common_enums::Currency::EUR,
                    merchant_order_reference_id: None,
                    metadata: None,
                    webhook_url: None,
                    integrity_object: None,
                    capture_method: None,
                    browser_info: None,
                    email: Some(
                        Email::try_from("test@example.com".to_string())
                            .expect("Failed to parse email"),
                    ),
                    payment_method_type: None,
                    merchant_account_metadata: None,
                    off_session: Some(true),
                    router_return_url: None,
                    split_payments: None,
                    recurring_mandate_payment_data: None,
                    shipping_cost: None,
                    mit_category: None,
                    enable_partial_authorization: None,
                    billing_descriptor: None,
                    payment_method_data: PaymentMethodData::CardDetailsForNetworkTransactionId(
                        CardDetailsForNetworkTransactionId {
                            card_number: cards::CardNumber::from_str("5123456789012346").unwrap(),
                            card_exp_month: Secret::new("06".into()),
                            card_exp_year: Secret::new("2028".into()),
                            card_issuer: None,
                            card_network: Some(common_enums::CardNetwork::Mastercard),
                            card_type: None,
                            card_issuing_country: None,
                            bank_code: None,
                            nick_name: None,
                            card_holder_name: Some(Secret::new("Jane Smith".to_string())),
                        },
                    ),
                    authentication_data: None,
                    locale: None,
                    connector_testing_data: None,
                    merchant_account_id: None,
                    merchant_configured_currency: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Nuvei::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Nuvei,
            };

            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            let url = connector_integration.get_url(&req).unwrap();
            assert!(
                url.ends_with("/payment.do"),
                "RepeatPayment URL should end with /payment.do, got: {url}"
            );
        }
    }

    pub mod response_parsing {
        use crate::{
            connectors::nuvei::transformers::{
                NuveiPaymentResponse, NuveiPaymentStatus, NuveiTransactionStatus,
            },
            types::ResponseRouterData,
        };
        use domain_types::{
            connector_flow::Authorize,
            connector_types::{
                PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
            },
            payment_method_data::DefaultPCIHolder,
            router_data::ErrorResponse,
            router_data_v2::RouterDataV2,
            types::{ConnectorParams, Connectors},
        };
        use hyperswitch_masking::Secret;
        use std::marker::PhantomData;

        #[test]
        fn test_authorize_response_extracts_network_txn_id() {
            let response = NuveiPaymentResponse {
                order_id: Some("ord_123".to_string()),
                transaction_id: Some("txn_456".to_string()),
                transaction_status: Some(NuveiTransactionStatus::Approved),
                status: NuveiPaymentStatus::Success,
                err_code: None,
                reason: None,
                gw_error_code: None,
                gw_error_reason: None,
                auth_code: None,
                session_token: None,
                client_unique_id: None,
                client_request_id: Some("ref_789".to_string()),
                internal_request_id: None,
                external_scheme_transaction_id: Some(Secret::new(
                    "483297487231504".to_string(),
                )),
            };

            let router_data: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: PaymentFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: None,
                    payment_id: "pay_resp_test".to_string(),
                    attempt_id: "attempt_resp_test".to_string(),
                    status: common_enums::AttemptStatus::Pending,
                    payment_method: common_enums::PaymentMethod::Card,
                    description: None,
                    return_url: None,
                    order_details: None,
                    address: domain_types::payment_address::PaymentAddress::new(
                        None, None, None, None,
                    ),
                    auth_type: common_enums::AuthenticationType::NoThreeDs,
                    connector_meta_data: None,
                    amount_captured: None,
                    minor_amount_captured: None,
                    minor_amount_authorized: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    payment_method_token: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: "ref_resp_test".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: Connectors {
                        nuvei: ConnectorParams {
                            base_url: "https://ppp-test.nuvei.com/ppp/api/v1".to_string(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    external_latency: None,
                    connector_response_headers: None,
                    raw_connector_response: None,
                    vault_headers: None,
                    raw_connector_request: None,
                    minor_amount_capturable: None,
                    connector_response: None,
                    recurring_mandate_payment_data: None,
                },
                connector_auth_type: domain_types::router_data::ConnectorSpecificAuth::Nuvei {
                    merchant_id: Secret::new("test".to_string()),
                    merchant_site_id: Secret::new("test".to_string()),
                    merchant_secret: Secret::new("test".to_string()),
                },
                request: PaymentsAuthorizeData {
                    payment_channel: None,
                    authentication_data: None,
                    connector_testing_data: None,
                    payment_method_data:
                        domain_types::payment_method_data::PaymentMethodData::Card(
                            Default::default(),
                        ),
                    amount: common_utils::types::MinorUnit::new(1000),
                    order_tax_amount: None,
                    email: None,
                    customer_name: None,
                    currency: common_enums::Currency::USD,
                    confirm: true,
                    capture_method: None,
                    integrity_object: None,
                    router_return_url: None,
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: Some(common_enums::FutureUsage::OffSession),
                    off_session: None,
                    browser_info: None,
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: None,
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: None,
                    customer_id: None,
                    request_incremental_authorization: None,
                    metadata: None,
                    minor_amount: common_utils::types::MinorUnit::new(1000),
                    merchant_order_reference_id: None,
                    shipping_cost: None,
                    merchant_account_id: None,
                    merchant_config_currency: None,
                    all_keys_required: None,
                    access_token: None,
                    customer_acceptance: None,
                    split_payments: None,
                    request_extended_authorization: None,
                    setup_mandate_details: None,
                    enable_overcapture: None,
                    merchant_account_metadata: None,
                    billing_descriptor: None,
                    enable_partial_authorization: None,
                    locale: None,
                    continue_redirection_url: None,
                    redirect_response: None,
                    threeds_method_comp_ind: None,
                    tokenization: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let response_router_data = ResponseRouterData {
                response,
                router_data,
                http_code: 200,
            };

            let result: Result<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<DefaultPCIHolder>,
                    PaymentsResponseData,
                >,
                _,
            > = response_router_data.try_into();

            assert!(result.is_ok(), "Response parsing should succeed");
            let parsed = result.unwrap();

            // Verify status is Charged (auto capture)
            assert_eq!(
                parsed.resource_common_data.status,
                common_enums::AttemptStatus::Charged,
                "Status should be Charged for approved transaction with auto capture"
            );

            // Verify network_txn_id is extracted from external_scheme_transaction_id
            match &parsed.response {
                Ok(PaymentsResponseData::TransactionResponse { network_txn_id, .. }) => {
                    assert_eq!(
                        network_txn_id.as_deref(),
                        Some("483297487231504"),
                        "network_txn_id should be extracted from external_scheme_transaction_id"
                    );
                }
                other => panic!(
                    "Expected Ok(TransactionResponse), got: {:?}",
                    other
                ),
            }
        }

        #[test]
        fn test_authorize_response_without_ntid() {
            let response = NuveiPaymentResponse {
                order_id: Some("ord_no_ntid".to_string()),
                transaction_id: Some("txn_no_ntid".to_string()),
                transaction_status: Some(NuveiTransactionStatus::Approved),
                status: NuveiPaymentStatus::Success,
                err_code: None,
                reason: None,
                gw_error_code: None,
                gw_error_reason: None,
                auth_code: None,
                session_token: None,
                client_unique_id: None,
                client_request_id: Some("ref_no_ntid".to_string()),
                internal_request_id: None,
                external_scheme_transaction_id: None,
            };

            let router_data: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: PaymentFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: None,
                    payment_id: "pay_no_ntid".to_string(),
                    attempt_id: "attempt_no_ntid".to_string(),
                    status: common_enums::AttemptStatus::Pending,
                    payment_method: common_enums::PaymentMethod::Card,
                    description: None,
                    return_url: None,
                    order_details: None,
                    address: domain_types::payment_address::PaymentAddress::new(
                        None, None, None, None,
                    ),
                    auth_type: common_enums::AuthenticationType::NoThreeDs,
                    connector_meta_data: None,
                    amount_captured: None,
                    minor_amount_captured: None,
                    minor_amount_authorized: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    payment_method_token: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: "ref_no_ntid".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: Connectors::default(),
                    external_latency: None,
                    connector_response_headers: None,
                    raw_connector_response: None,
                    vault_headers: None,
                    raw_connector_request: None,
                    minor_amount_capturable: None,
                    connector_response: None,
                    recurring_mandate_payment_data: None,
                },
                connector_auth_type: domain_types::router_data::ConnectorSpecificAuth::Nuvei {
                    merchant_id: Secret::new("test".to_string()),
                    merchant_site_id: Secret::new("test".to_string()),
                    merchant_secret: Secret::new("test".to_string()),
                },
                request: PaymentsAuthorizeData {
                    payment_channel: None,
                    authentication_data: None,
                    connector_testing_data: None,
                    payment_method_data:
                        domain_types::payment_method_data::PaymentMethodData::Card(
                            Default::default(),
                        ),
                    amount: common_utils::types::MinorUnit::new(500),
                    order_tax_amount: None,
                    email: None,
                    customer_name: None,
                    currency: common_enums::Currency::USD,
                    confirm: true,
                    capture_method: None,
                    integrity_object: None,
                    router_return_url: None,
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    browser_info: None,
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: None,
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: None,
                    customer_id: None,
                    request_incremental_authorization: None,
                    metadata: None,
                    minor_amount: common_utils::types::MinorUnit::new(500),
                    merchant_order_reference_id: None,
                    shipping_cost: None,
                    merchant_account_id: None,
                    merchant_config_currency: None,
                    all_keys_required: None,
                    access_token: None,
                    customer_acceptance: None,
                    split_payments: None,
                    request_extended_authorization: None,
                    setup_mandate_details: None,
                    enable_overcapture: None,
                    merchant_account_metadata: None,
                    billing_descriptor: None,
                    enable_partial_authorization: None,
                    locale: None,
                    continue_redirection_url: None,
                    redirect_response: None,
                    threeds_method_comp_ind: None,
                    tokenization: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let response_router_data = ResponseRouterData {
                response,
                router_data,
                http_code: 200,
            };

            let result: Result<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<DefaultPCIHolder>,
                    PaymentsResponseData,
                >,
                _,
            > = response_router_data.try_into();

            assert!(result.is_ok(), "Response parsing should succeed");
            let parsed = result.unwrap();

            // Verify network_txn_id is None when external_scheme_transaction_id is not present
            match &parsed.response {
                Ok(PaymentsResponseData::TransactionResponse { network_txn_id, .. }) => {
                    assert!(
                        network_txn_id.is_none(),
                        "network_txn_id should be None when external_scheme_transaction_id is absent"
                    );
                }
                other => panic!(
                    "Expected Ok(TransactionResponse), got: {:?}",
                    other
                ),
            }
        }
    }
}
