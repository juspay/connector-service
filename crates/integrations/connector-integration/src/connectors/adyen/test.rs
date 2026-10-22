#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::panic)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::print_stdout)]
mod tests {
    pub mod authorize {
        use std::{borrow::Cow, marker::PhantomData, str::FromStr};

        use common_utils::{pii::Email, request::RequestContent, types::MinorUnit};
        use domain_types::{
            connector_flow::Authorize,
            connector_types::{
                ConnectorEnum, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
            },
            payment_method_data::{DefaultPCIHolder, PaymentMethodData, RawCardNumber},
            router_data::{ConnectorSpecificConfig, ErrorResponse},
            router_data_v2::RouterDataV2,
            types::{ConnectorParams, Connectors},
        };
        use hyperswitch_masking::Secret;
        use interfaces::{
            connector_integration_v2::BoxedConnectorIntegrationV2, connector_types::BoxedConnector,
        };
        use serde_json::json;

        use crate::{connectors::Adyen, types::ConnectorData};
        #[test]
        fn test_build_request_valid() {
            let api_key = "test_adyen_api_key".to_string(); // Hardcoded dummy value
            let key1 = "test_adyen_key1".to_string(); // Hardcoded dummy value
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: PaymentFlowData {
                    raw_connector_status: None,
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: Some("conn_cust_987654".to_string()),
                    payment_id: "pay_abcdef123456".to_string(),
                    attempt_id: "attempt_123456abcdef".to_string(),
                    status: common_enums::AttemptStatus::Pending,
                    payment_method: common_enums::PaymentMethod::Card,
                    payment_method_type: None,
                    description: Some("Payment for order #12345".to_string()),
                    return_url: Some("www.google.com".to_string()),
                    order_details: None,
                    address: domain_types::payment_address::PaymentAddress::new(
                        None, None, None, None,
                    ),
                    auth_type: common_enums::AuthenticationType::ThreeDs,
                    connector_feature_data: None,
                    amount_captured: None,
                    amount_authorized: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    connector_order_id: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: "conn_ref_123456789".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: Connectors {
                        adyen: ConnectorParams {
                            base_url: "https://checkout-test.adyen.com/".to_string(),
                            dispute_base_url: Some("https://ca-test.adyen.com/ca/services/DisputeService/v30/defendDispute".to_string()),
                            ..Default::default()
                        },
                        ..Default::default()
                    }.into(),
                    external_latency: None,
                    connector_response_headers: None,
                    raw_connector_response: None,
                    vault_headers: None,
                    raw_connector_request: None,
                    typed_connector_request: None,
                    amount_capturable: None,
                    amount: None,
                    connector_response: None,
                    recurring_mandate_payment_data: None,
                    l2_l3_data: None,
                    merchant_request_id: None,
                    sender_payment_instrument_id: None,
                    connector_returned_payment_method_details: None,
                    settlement_status: None,
                    typed_connector_response: None,
},
                connector_config: ConnectorSpecificConfig::Adyen {
                    api_key: Secret::new(api_key),
                    merchant_account: Secret::new(key1),
                    review_key: None,
                    base_url: None,
                    dispute_base_url: None,
                    endpoint_prefix: None,
                    native_three_ds: None
},
                request: PaymentsAuthorizeData {
                    split_settlement: None,
                    customer_document_details: None,
                    customer_date_of_birth: None,
                    payment_channel: None,
                    authentication_data: None,
                    connector_testing_data: None,
                    currency_conversion_data: None,
                    payment_method_data: PaymentMethodData::Card(
                        domain_types::payment_method_data::Card {
                            card_number: RawCardNumber(cards::CardNumber::from_str(
                                "5123456789012346",
                            )
                            .unwrap()),
                            card_cvc: Secret::new("100".into()),
                            card_exp_month: Secret::new("03".into()),
                            card_exp_year: Secret::new("2030".into()),
                            ..Default::default()
                        },
                    ),
                    amount: common_utils::types::Money { amount: MinorUnit::new(1000), currency: common_enums::Currency::USD },
                    order_tax_amount: None,
                    surcharge_amount: None,
                    email: Some(
                        Email::try_from("test@example.com".to_string())
                            .expect("Failed to parse email"),
                    ),
                    customer_name: None,
                    currency: common_enums::Currency::USD,
                    confirm: true,
                    capture_method: None,
                    integrity_object: None,
                    router_return_url: Some("www.google.com".to_string()),
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
                            user_agent: Some(
                                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string(),
                            ),
                            accept_header: Some(
                                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                                    .to_string(),
                            ),
                            java_script_enabled: Some(false),
                            language: Some("en-US".to_string()),
                            time_zone: Some(-480),
                            referer: None,
                            ip_address: None,
                            os_type: None,
                            os_version: None,
                            device_model: None,
                            accept_language: None
},
                    ),
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: Some(true),
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: Some(common_enums::PaymentMethodType::Card),
                    customer_id: Some(
                        common_utils::id_type::CustomerId::try_from(Cow::from(
                            "cus_123456789".to_string(),
                        ))
                        .unwrap(),
                    ),
                    request_incremental_authorization: Some(false),
                    metadata: None,
                    merchant_order_id: None,
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
                    connector_feature_data: None,
                    billing_descriptor: None,
                    enable_partial_authorization: None,
                    locale: None,
                    continue_redirection_url: None,
                    redirect_response: None,
                    threeds_method_comp_ind: None,
                    tokenization: None,
                    mit_category: None,
                    domain_data: None,
                    partner_merchant_identifier_details: None,
                    is_account_funding_transaction: None,
                    recipient_details: None,
                    business_country: None,
                    enable_avs_check: None,
                    additional_connector_details: None,
                    customer: None,
},
                response: Err(ErrorResponse::default())
};

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Adyen::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Adyen,
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
                let masked_request = match request_val.body.as_ref() {
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
                };
                masked_request
            });
            println!("request: {req_body:?}");
            assert_eq!(
                req_body.as_ref().unwrap()["reference"],
                "conn_ref_123456789"
            );
        }
        #[test]
        fn test_build_request_missing() {
            let api_key = "test_adyen_api_key_missing".to_string(); // Hardcoded dummy value
            let key1 = "test_adyen_key1_missing".to_string(); // Hardcoded dummy value
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: PaymentFlowData {
                    raw_connector_status: None,
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: None,
                    payment_id: "".to_string(),
                    attempt_id: "".to_string(),
                    status: common_enums::AttemptStatus::Pending,
                    payment_method: common_enums::PaymentMethod::Card,
                    payment_method_type: None,
                    description: None,
                    return_url: None,
                    order_details: None,
                    address: domain_types::payment_address::PaymentAddress::new(
                        None, None, None, None,
                    ),
                    auth_type: common_enums::AuthenticationType::ThreeDs,
                    connector_feature_data: None,
                    amount_captured: None,
                    amount_authorized: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    connector_order_id: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: "".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: Connectors {
                        adyen: ConnectorParams {
                            base_url: "https://checkout-test.adyen.com/".to_string(),
                            dispute_base_url: Some("https://ca-test.adyen.com/ca/services/DisputeService/v30/defendDispute".to_string()),
                            ..Default::default()
                        },
                        ..Default::default()
                    }.into(),
                    external_latency: None,
                    connector_response_headers: None,
                    raw_connector_response: None,
                    vault_headers: None,
                    raw_connector_request: None,
                    typed_connector_request: None,
                    amount_capturable: None,
                    amount: None,
                    connector_response: None,
                    recurring_mandate_payment_data: None,
                    l2_l3_data: None,
                    merchant_request_id: None,
                    sender_payment_instrument_id: None,
                    connector_returned_payment_method_details: None,
                    settlement_status: None,
                    typed_connector_response: None,
},
                connector_config: ConnectorSpecificConfig::Adyen {
                    api_key: Secret::new(api_key),
                    merchant_account: Secret::new(key1),
                    review_key: None,
                    base_url: None,
                    dispute_base_url: None,
                    endpoint_prefix: None,
                    native_three_ds: None
},
                request: PaymentsAuthorizeData {
                    split_settlement: None,
                    customer_document_details: None,
                    customer_date_of_birth: None,
                    payment_channel: None,
                    authentication_data: None,
                    connector_testing_data: None,
                    currency_conversion_data: None,
                    payment_method_data: PaymentMethodData::Card(Default::default()),
                    amount: common_utils::types::Money { amount: MinorUnit::new(1000), currency: common_enums::Currency::USD },
                    order_tax_amount: None,
                    surcharge_amount: None,
                    email: None,
                    customer_name: None,
                    currency: common_enums::Currency::USD,
                    confirm: true,
                    capture_method: None,
                    router_return_url: None,
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    browser_info: None,
                    integrity_object: None,
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: Some(false),
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: None,
                    customer_id: None,
                    request_incremental_authorization: Some(false),
                    metadata: None,
                    merchant_order_id: None,
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
                    connector_feature_data: None,
                    billing_descriptor: None,
                    enable_partial_authorization: None,
                    locale: None,
                    continue_redirection_url: None,
                    redirect_response: None,
                    threeds_method_comp_ind: None,
                    tokenization: None,
                    mit_category: None,
                    domain_data: None,
                    partner_merchant_identifier_details: None,
                    is_account_funding_transaction: None,
                    recipient_details: None,
                    business_country: None,
                    enable_avs_check: None,
                    additional_connector_details: None,
                    customer: None,
},
                response: Err(ErrorResponse::default())
};

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Adyen::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Adyen,
            };

            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            let result = connector_integration.build_request_v2(&req);
            assert!(result.is_err(), "Expected error for missing fields");
        }
        // #[test]
        // fn test_build_request_invalid() {
        //     let api_key = env::var("API_KEY").expect("API_KEY not set");
        //     let key1 = env::var("KEY1").expect("KEY1 not set");
        //     let req: RouterDataV2<
        //         Authorize,
        //         PaymentFlowData,
        //         PaymentsAuthorizeData,
        //         PaymentsResponseData
        //     > = RouterDataV2 {
        //         flow: PhantomData::<Authorize>,
        //         resource_common_data: PaymentFlowData {
        //             merchant_id: common_utils::id_type::MerchantId::default(),
        //             customer_id: None,
        //             connector_customer: None,
        //             payment_id: "pay_invalid".to_string(),
        //             attempt_id: "attempt_invalid".to_string(),
        //             status: common_enums::AttemptStatus::Pending,
        //             payment_method: common_enums::PaymentMethod::Card,
        //             description: Some("Invalid test".to_string()),
        //             return_url: None,
        //             address: domain_types::payment_address::PaymentAddress::new(
        //                 None,
        //                 None,
        //                 None,
        //                 None
        //             ),
        //             auth_type: common_enums::AuthenticationType::ThreeDs,
        //             connector_meta_data: None,
        //             amount_captured: None,
        //             amount_authorized: None,
        //             access_token: None,
        //             session_token: None,
        //             reference_id: None,
        //
        //             preprocessing_id: None,
        //             connector_api_version: None,
        //             connector_request_reference_id: "invalid_ref".to_string(),
        //             test_mode: None,
        //             connector_http_status_code: None,
        //             connectors: Connectors {
        //                 adyen: ConnectorParams {
        //                     base_url: "https://checkout-test.adyen.com/".to_string(),
        //                 },
        //                 razorpay: ConnectorParams {
        //                     base_url: "https://sandbox.juspay.in/".to_string(),
        //                 },
        //             },
        //             external_latency: None,
        //         },
        //         connector_config: ConnectorSpecificConfig::BodyKey {
        //             api_key: Secret::new(api_key.into()),
        //             key1: Secret::new(key1.into()),
        //,
        //         },
        //         request: PaymentsAuthorizeData {
        //             payment_method_data: PaymentMethodData::Card(
        //                 (domain_types::payment_method_data::Card {
        //                     card_number: cards::CardNumber
        //                         ::from_str("1234567890123456")
        //                         .unwrap(),
        //                     card_cvc: Secret::new("12".into()),
        //                     card_exp_month: Secret::new("00".into()), // invalid month
        //                     card_exp_year: Secret::new("1999".into()), // past year
        //                     ..Default::default()
        //                 }).into()
        //             ),
        //             amount: 100,
        //             order_tax_amount: None,
        //             email: Some("invalid-email".to_string())
        //                 .map(|email_str| Email::try_from(email_str))
        //                 .transpose()
        //                 .unwrap_or(None),
        //             customer_name: None,
        //             currency: common_enums::Currency::USD,
        //             confirm: true,
        //             statement_descriptor_suffix: None,
        //             statement_descriptor: None,
        //             capture_method: None,
        //             router_return_url: None,
        //             webhook_url: None,
        //             complete_authorize_url: None,
        //             mandate_id: None,
        //             setup_future_usage: None,
        //             off_session: None,
        //             browser_info: None,
        //             order_category: None,
        //             session_token: None,
        //             enrolled_for_3ds: Some(false),
        //             related_transaction_id: None,
        //             payment_experience: None,
        //             payment_method_type: None,
        //             customer_id: None,
        //             request_incremental_authorization: Some(false),
        //             metadata: None,
        //             minor_amount: common_utils::types::Money { amount: MinorUnit::new(100), currency: common_enums::Currency::USD },
        //             merchant_order_id: None,
        //             shipping_cost: None,
        //             merchant_account_id: None,
        //             merchant_config_currency: None,
        //         },
        //         response: Err(ErrorResponse::default()),
        //     };

        //     let connector: BoxedConnector = Box::new(Adyen::new());
        //     let connector_data = ConnectorData {
        //         connector,
        //         connector_name: ConnectorEnum::Adyen,
        //     };

        //     let connector_integration: BoxedConnectorIntegrationV2<
        //         '_,
        //         Authorize,
        //         PaymentFlowData,
        //         PaymentsAuthorizeData,
        //         PaymentsResponseData
        //     > = connector_data.connector.get_connector_integration_v2();

        //     let result = connector_integration.build_request_v2(&req);
        //     assert!(result.is_err(), "Expected error for invalid fields");
        // }
    }

    /// `RouterDataV2` scaffolding shared by the native 3DS2 and Level 2/3 tests. The flow data
    /// has fifty-odd fields and at most two matter per test, so it is built once here.
    pub mod fixtures {
        use domain_types::{
            connector_types::PaymentFlowData,
            router_data::ConnectorSpecificConfig,
            types::{ConnectorParams, Connectors},
        };
        use hyperswitch_masking::Secret;

        pub fn payment_flow_data() -> PaymentFlowData {
            PaymentFlowData {
                raw_connector_status: None,
                merchant_id: common_utils::id_type::MerchantId::default(),
                customer_id: None,
                connector_customer: None,
                payment_id: "pay_adyen_test".to_string(),
                attempt_id: "attempt_adyen_test".to_string(),
                status: common_enums::AttemptStatus::Pending,
                payment_method: common_enums::PaymentMethod::Card,
                payment_method_type: None,
                description: None,
                return_url: Some("https://hs.example/return".to_string()),
                order_details: None,
                address: domain_types::payment_address::PaymentAddress::new(None, None, None, None),
                auth_type: common_enums::AuthenticationType::ThreeDs,
                connector_feature_data: None,
                amount_captured: None,
                amount_authorized: None,
                access_token: None,
                session_token: None,
                reference_id: None,
                connector_order_id: None,
                preprocessing_id: None,
                connector_api_version: None,
                connector_request_reference_id: "conn_ref_adyen_test".to_string(),
                test_mode: None,
                connector_http_status_code: None,
                connectors: Connectors {
                    adyen: ConnectorParams {
                        base_url: "https://checkout-test.adyen.com/".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                }
                .into(),
                external_latency: None,
                connector_response_headers: None,
                raw_connector_response: None,
                vault_headers: None,
                raw_connector_request: None,
                typed_connector_request: None,
                amount_capturable: None,
                amount: None,
                connector_response: None,
                recurring_mandate_payment_data: None,
                l2_l3_data: None,
                merchant_request_id: None,
                sender_payment_instrument_id: None,
                connector_returned_payment_method_details: None,
                settlement_status: None,
                typed_connector_response: None,
            }
        }

        pub fn adyen_config() -> ConnectorSpecificConfig {
            ConnectorSpecificConfig::Adyen {
                api_key: Secret::new("test_adyen_api_key".to_string()),
                merchant_account: Secret::new("test_adyen_merchant_account".to_string()),
                review_key: None,
                base_url: None,
                dispute_base_url: None,
                endpoint_prefix: None,
                native_three_ds: Some(true),
            }
        }
    }

    /// Native (SDK-less) 3DS2 standalone authentication: the untagged variant order that keeps a
    /// `threeDS2` action from parsing as a redirect, the `action.token` decode, and the outcome
    /// table of each of the three legs — PostAuthenticate included, which the integration
    /// harness cannot reach.
    ///
    /// Everything here goes through the public surface: a response body is `from_str`-parsed into
    /// the leg's response type and handed to its `TryFrom<ResponseRouterData<..>>`, which is the
    /// only caller of the private decoder, state helpers and outcome table.
    pub mod native_three_ds {
        use std::{collections::HashMap, marker::PhantomData};

        use base64::Engine;
        use common_enums::{AttemptStatus, CaptureMethod};
        use common_utils::types::{MinorUnit, Money};
        use domain_types::{
            connector_flow::{Authenticate, PostAuthenticate, PreAuthenticate},
            connector_types::{
                PaymentFlowData, PaymentsAuthenticateData, PaymentsPostAuthenticateData,
                PaymentsPreAuthenticateData, PaymentsResponseData,
            },
            payment_method_data::DefaultPCIHolder,
            router_data::ErrorResponse,
            router_data_v2::RouterDataV2,
            router_request_types::AuthenticationData,
            router_response_types::RedirectForm,
        };

        use super::fixtures::{adyen_config, payment_flow_data};
        use crate::{
            connectors::adyen::transformers::{
                AdyenAuthenticationResponse, AdyenPaymentResponse, AdyenPostAuthenticationResponse,
                AdyenPreAuthenticationResponse,
            },
            types::ResponseRouterData,
        };

        type PreAuthRouterData = RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<DefaultPCIHolder>,
            PaymentsResponseData,
        >;
        type AuthRouterData = RouterDataV2<
            Authenticate,
            PaymentFlowData,
            PaymentsAuthenticateData<DefaultPCIHolder>,
            PaymentsResponseData,
        >;
        type PostAuthRouterData = RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<DefaultPCIHolder>,
            PaymentsResponseData,
        >;
        type LegResponse = Result<PaymentsResponseData, ErrorResponse>;

        // ===== inputs =====

        fn b64url(payload: &str) -> String {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
        }

        /// `action.token` of a `fingerprint` action: base64url(no pad) JSON.
        fn fingerprint_token() -> String {
            b64url(
                r#"{"threeDSMethodUrl":"https://acs.example/3ds-method","threeDSMethodNotificationURL":"https://hs.example/notify","threeDSServerTransID":"srv-1","threeDSMessageVersion":"2.2.0"}"#,
            )
        }

        /// `action.token` of a `challenge` action.
        fn challenge_token() -> String {
            b64url(
                r#"{"acsURL":"https://acs.example/challenge","acsTransID":"acs-1","acsReferenceNumber":"ref-1","messageVersion":"2.2.0","threeDSNotificationURL":"https://adyen.example/notify","threeDSServerTransID":"srv-1"}"#,
            )
        }

        /// A `resultCode` + `threeDS2` action body, as adyen sends it.
        fn action_body(result_code: &str, subtype: &str, token: &str) -> String {
            format!(
                r#"{{"resultCode":"{result_code}","action":{{"type":"threeDS2","subtype":"{subtype}","token":"{token}","paymentData":"Ab02b4c0!payment-data","authorisationToken":"Ab02b4c0!auth-token","paymentMethodType":"scheme"}},"pspReference":"psp-1","merchantReference":"ref-1"}}"#
            )
        }

        /// An `AuthenticationFinished` body with the `threeDS2Result` adyen returns.
        fn authentication_finished_body(trans_status: &str, eci: &str) -> String {
            format!(
                r#"{{"resultCode":"AuthenticationFinished","pspReference":"psp-1","merchantReference":"ref-1","threeDS2Result":{{"authenticationValue":"cavv-value","eci":"{eci}","transStatus":"{trans_status}","dsTransID":"ds-1","threeDSServerTransID":"srv-1","messageVersion":"2.2.0"}}}}"#
            )
        }

        /// A body carrying only a `resultCode`, plus a refusal reason where adyen sends one.
        fn result_code_body(result_code: &str) -> String {
            format!(
                r#"{{"resultCode":"{result_code}","pspReference":"psp-1","merchantReference":"ref-1","refusalReason":"Refused","refusalReasonCode":"2"}}"#
            )
        }

        // ===== the three legs, through their public response transforms =====

        fn pre_authenticate(
            body: &str,
            capture_method: Option<CaptureMethod>,
        ) -> PreAuthRouterData {
            let response = serde_json::from_str::<AdyenPreAuthenticationResponse>(body).unwrap();
            let router_data: PreAuthRouterData = RouterDataV2 {
                flow: PhantomData::<PreAuthenticate>,
                resource_common_data: payment_flow_data(),
                connector_config: adyen_config(),
                request: PaymentsPreAuthenticateData {
                    payment_method_data: None,
                    amount: Money {
                        amount: MinorUnit::new(1000),
                        currency: common_enums::Currency::USD,
                    },
                    email: None,
                    currency: Some(common_enums::Currency::USD),
                    payment_method_type: None,
                    router_return_url: None,
                    continue_redirection_url: None,
                    browser_info: None,
                    enrolled_for_3ds: true,
                    redirect_response: None,
                    capture_method,
                    mandate_reference: None,
                    merchant_transaction_id: None,
                    metadata: None,
                    customer_date_of_birth: None,
                },
                response: Err(ErrorResponse::default()),
            };
            RouterDataV2::try_from(ResponseRouterData {
                response,
                router_data,
                http_code: 200,
            })
            .unwrap()
        }

        fn authenticate(body: &str) -> AuthRouterData {
            let response = serde_json::from_str::<AdyenAuthenticationResponse>(body).unwrap();
            let router_data: AuthRouterData = RouterDataV2 {
                flow: PhantomData::<Authenticate>,
                resource_common_data: payment_flow_data(),
                connector_config: adyen_config(),
                request: PaymentsAuthenticateData {
                    payment_method_data: None,
                    amount: Money {
                        amount: MinorUnit::new(1000),
                        currency: common_enums::Currency::USD,
                    },
                    email: None,
                    currency: Some(common_enums::Currency::USD),
                    payment_method_type: None,
                    router_return_url: None,
                    continue_redirection_url: None,
                    browser_info: None,
                    enrolled_for_3ds: true,
                    redirect_response: None,
                    capture_method: None,
                    authentication_data: None,
                    webhook_url: None,
                    domain_data: None,
                    sdk_information: None,
                    device_channel: None,
                    setup_future_usage: None,
                    customer_acceptance: None,
                    enable_partial_authorization: None,
                    payment_channel: None,
                    billing_descriptor: None,
                },
                response: Err(ErrorResponse::default()),
            };
            RouterDataV2::try_from(ResponseRouterData {
                response,
                router_data,
                http_code: 200,
            })
            .unwrap()
        }

        fn post_authenticate(body: &str) -> PostAuthRouterData {
            let response = serde_json::from_str::<AdyenPostAuthenticationResponse>(body).unwrap();
            let router_data: PostAuthRouterData = RouterDataV2 {
                flow: PhantomData::<PostAuthenticate>,
                resource_common_data: payment_flow_data(),
                connector_config: adyen_config(),
                request: PaymentsPostAuthenticateData {
                    payment_method_data: None,
                    amount: Money {
                        amount: MinorUnit::new(1000),
                        currency: common_enums::Currency::USD,
                    },
                    email: None,
                    currency: Some(common_enums::Currency::USD),
                    payment_method_type: None,
                    router_return_url: None,
                    continue_redirection_url: None,
                    browser_info: None,
                    enrolled_for_3ds: true,
                    redirect_response: None,
                    capture_method: None,
                    connector_order_reference_id: None,
                },
                response: Err(ErrorResponse::default()),
            };
            RouterDataV2::try_from(ResponseRouterData {
                response,
                router_data,
                http_code: 200,
            })
            .unwrap()
        }

        // ===== reading an outcome =====

        fn authentication_data(data: &PaymentsResponseData) -> Option<&AuthenticationData> {
            match data {
                PaymentsResponseData::PreAuthenticateResponse {
                    authentication_data,
                    ..
                }
                | PaymentsResponseData::AuthenticateResponse {
                    authentication_data,
                    ..
                }
                | PaymentsResponseData::PostAuthenticateResponse {
                    authentication_data,
                    ..
                } => authentication_data.as_ref(),
                _ => None,
            }
        }

        /// `(endpoint, form_fields)` of the browser form the leg handed back.
        fn redirect_form(data: &PaymentsResponseData) -> Option<(String, HashMap<String, String>)> {
            let form = match data {
                PaymentsResponseData::PreAuthenticateResponse {
                    redirection_data, ..
                }
                | PaymentsResponseData::AuthenticateResponse {
                    redirection_data, ..
                } => redirection_data.as_deref(),
                _ => None,
            }?;
            match form {
                RedirectForm::Form {
                    endpoint,
                    form_fields,
                    ..
                } => Some((endpoint.clone(), form_fields.clone())),
                _ => None,
            }
        }

        /// `(status, produced authentication data, produced a shopper form)`.
        fn outcome(status: AttemptStatus, response: &LegResponse) -> (AttemptStatus, bool, bool) {
            let data = response.as_ref().ok();
            (
                status,
                data.and_then(authentication_data).is_some(),
                data.and_then(redirect_form).is_some(),
            )
        }

        /// `(code, message, reason)` of a refused leg. `None` when the leg did not fail.
        fn refusal(response: &LegResponse) -> Option<(String, String, Option<String>)> {
            response.as_ref().err().map(|error| {
                (
                    error.code.clone(),
                    error.message.clone(),
                    error.reason.clone(),
                )
            })
        }

        fn form_field(fields: &HashMap<String, String>, key: &str) -> String {
            fields.get(key).cloned().unwrap_or_default()
        }

        /// The EMVCo blobs the forms carry are base64url(no pad) JSON.
        fn decode_b64url(value: &str) -> serde_json::Value {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(serde_json::Value::Null)
        }

        // ===== (a) untagged variant order =====

        /// `ThreeDs2Action` must stay ahead of `RedirectionResponse` in the untagged enum:
        /// `AdyenRedirectAction`'s url / method / data are all optional, so a `threeDS2` body
        /// parses cleanly as a redirect, yields `redirection_data: None` and hangs the payment.
        #[test]
        fn three_ds2_action_body_is_not_a_redirection_response() {
            let body = format!(
                r#"{{"resultCode":"IdentifyShopper","action":{{"type":"threeDS2","subtype":"fingerprint","token":"{}","paymentData":"Ab02b4c0!payment-data","authorisationToken":"Ab02b4c0!auth-token","paymentMethodType":"scheme"}},"pspReference":"X"}}"#,
                fingerprint_token()
            );
            assert!(matches!(
                serde_json::from_str::<AdyenPaymentResponse>(&body),
                Ok(AdyenPaymentResponse::ThreeDs2Action(_))
            ));
        }

        /// ... and a real redirect action must still reach `RedirectionResponse`: the required
        /// `subtype` + `token` on the native action are what keep the two apart.
        #[test]
        fn redirect_action_body_still_parses_as_a_redirection_response() {
            let body = r#"{"resultCode":"RedirectShopper","action":{"paymentMethodType":"scheme","type":"redirect","url":"https://acs.example/redirect","method":"GET"},"pspReference":"X"}"#;
            assert!(matches!(
                serde_json::from_str::<AdyenPaymentResponse>(body),
                Ok(AdyenPaymentResponse::RedirectionResponse(_))
            ));
        }

        // ===== (b) action.token decode =====

        /// The decoded fingerprint token becomes the hidden-iframe 3DS-method form. The field
        /// spellings are the ones hyperswitch's converter sniffs for, so they are asserted
        /// verbatim.
        #[test]
        fn fingerprint_action_token_decodes_into_the_three_ds_method_form() {
            let out = pre_authenticate(
                &action_body("IdentifyShopper", "fingerprint", &fingerprint_token()),
                None,
            );
            let (endpoint, fields) = out
                .response
                .as_ref()
                .ok()
                .and_then(redirect_form)
                .unwrap_or_default();
            assert_eq!(endpoint, "https://acs.example/3ds-method");
            assert_eq!(
                (
                    form_field(&fields, "threeDsMethodUrl"),
                    form_field(&fields, "threeDSServerTransID"),
                    form_field(&fields, "messageVersion"),
                    form_field(&fields, "threeDsMethodDataSubmission"),
                ),
                (
                    "https://acs.example/3ds-method".to_string(),
                    "srv-1".to_string(),
                    "2.2.0".to_string(),
                    "true".to_string(),
                )
            );
            // `threeDSMethodData` is the EMVCo blob the ACS reads back.
            let method_data = decode_b64url(&form_field(&fields, "threeDsMethodData"));
            assert_eq!(
                (
                    method_data
                        .get("threeDSServerTransID")
                        .and_then(|value| value.as_str()),
                    method_data
                        .get("threeDSMethodNotificationURL")
                        .and_then(|value| value.as_str()),
                ),
                (Some("srv-1"), Some("https://hs.example/notify"))
            );
        }

        /// The decoded challenge token becomes the `creq` posted to `acsURL`.
        #[test]
        fn challenge_action_token_decodes_into_the_creq_form() {
            let out = pre_authenticate(
                &action_body("ChallengeShopper", "challenge", &challenge_token()),
                None,
            );
            let (endpoint, fields) = out
                .response
                .as_ref()
                .ok()
                .and_then(redirect_form)
                .unwrap_or_default();
            assert_eq!(endpoint, "https://acs.example/challenge");
            assert_eq!(fields.len(), 1);
            let creq = decode_b64url(&form_field(&fields, "creq"));
            assert_eq!(
                (
                    creq.get("threeDSServerTransID")
                        .and_then(|value| value.as_str()),
                    creq.get("acsTransID").and_then(|value| value.as_str()),
                    creq.get("messageVersion").and_then(|value| value.as_str()),
                    creq.get("messageType").and_then(|value| value.as_str()),
                ),
                (Some("srv-1"), Some("acs-1"), Some("2.2.0"), Some("CReq"))
            );
        }

        /// A token that is not base64url JSON, and one that decodes to the wrong shape, are both
        /// errors rather than panics. The transform itself still returns `Ok`: the failure
        /// surfaces as `response: Err(..)` with an `AuthenticationFailed` status.
        #[test]
        fn malformed_action_token_is_an_error_not_a_panic() {
            let not_base64 = pre_authenticate(
                &action_body("IdentifyShopper", "fingerprint", "!!!not base64!!!"),
                None,
            );
            assert_eq!(
                (
                    not_base64.resource_common_data.status,
                    not_base64.response.is_err()
                ),
                (AttemptStatus::AuthenticationFailed, true)
            );
            // `e30` is base64url for `{}`: valid base64, wrong JSON shape.
            let wrong_shape =
                pre_authenticate(&action_body("ChallengeShopper", "challenge", "e30"), None);
            assert_eq!(
                (
                    wrong_shape.resource_common_data.status,
                    wrong_shape.response.is_err()
                ),
                (AttemptStatus::AuthenticationFailed, true)
            );
        }

        // ===== (c) outcome table, per leg =====

        /// `IdentifyShopper` is the fingerprint step, and only the first leg can ask for one.
        /// The state the next leg needs is left in `connector_feature_data`, stamped with the
        /// step the shopper was handed.
        #[test]
        fn identify_shopper_hands_back_the_fingerprint_step_on_the_pre_authenticate_leg() {
            let out = pre_authenticate(
                &action_body("IdentifyShopper", "fingerprint", &fingerprint_token()),
                None,
            );
            assert_eq!(
                outcome(out.resource_common_data.status, &out.response),
                (AttemptStatus::AuthenticationPending, false, true)
            );
            let state = out
                .resource_common_data
                .connector_feature_data
                .as_ref()
                .map(|carrier| {
                    use hyperswitch_masking::PeekInterface;
                    carrier.peek().clone()
                })
                .unwrap_or(serde_json::Value::Null);
            assert_eq!(
                (
                    state.pointer("/three_ds_data/paymentData"),
                    state.pointer("/three_ds_data/authorisationToken"),
                    state.pointer("/three_ds_data/stage"),
                ),
                (
                    Some(&serde_json::json!("Ab02b4c0!payment-data")),
                    Some(&serde_json::json!("Ab02b4c0!auth-token")),
                    Some(&serde_json::json!("fingerprint")),
                )
            );
        }

        /// A fingerprint that arrives after the fingerprint leg has nowhere to run: fail closed
        /// rather than drop the action and leave the payment pending with no next step.
        #[test]
        fn identify_shopper_is_refused_on_the_later_legs() {
            let body = action_body("IdentifyShopper", "fingerprint", &fingerprint_token());
            let on_authenticate = authenticate(&body);
            assert_eq!(
                outcome(
                    on_authenticate.resource_common_data.status,
                    &on_authenticate.response
                ),
                (AttemptStatus::AuthenticationFailed, false, false)
            );
            let on_post_authenticate = post_authenticate(&body);
            assert_eq!(
                on_post_authenticate.resource_common_data.status,
                AttemptStatus::AuthenticationFailed
            );
        }

        /// `ChallengeShopper` is the ACS challenge: legs 1 and 2 surface it, leg 3 cannot —
        /// it is the leg that carries the challenge result back.
        #[test]
        fn challenge_shopper_is_surfaced_by_the_first_two_legs_only() {
            let body = action_body("ChallengeShopper", "challenge", &challenge_token());
            let on_pre = pre_authenticate(&body, None);
            assert_eq!(
                outcome(on_pre.resource_common_data.status, &on_pre.response),
                (AttemptStatus::AuthenticationPending, false, true)
            );
            let on_auth = authenticate(&body);
            assert_eq!(
                outcome(on_auth.resource_common_data.status, &on_auth.response),
                (AttemptStatus::AuthenticationPending, false, true)
            );
            let on_post = post_authenticate(&body);
            assert_eq!(
                outcome(on_post.resource_common_data.status, &on_post.response),
                (AttemptStatus::AuthenticationFailed, false, false)
            );
        }

        /// A `threeDS2Result` whose ECI corroborates its `transStatus` becomes the
        /// `AuthenticationData` that Authorize sends on as `mpiData`. Asserted on every leg,
        /// PostAuthenticate included.
        #[test]
        fn authentication_finished_with_a_corroborated_result_becomes_authentication_data() {
            let body = authentication_finished_body("Y", "05");
            for (status, response) in [
                {
                    let out = pre_authenticate(&body, None);
                    (out.resource_common_data.status, out.response)
                },
                {
                    let out = authenticate(&body);
                    (out.resource_common_data.status, out.response)
                },
                {
                    let out = post_authenticate(&body);
                    (out.resource_common_data.status, out.response)
                },
            ] {
                assert_eq!(
                    outcome(status, &response),
                    (AttemptStatus::AuthenticationSuccessful, true, false)
                );
                let mapped = response
                    .as_ref()
                    .ok()
                    .and_then(authentication_data)
                    .map(|data| {
                        use hyperswitch_masking::PeekInterface;
                        (
                            data.trans_status.clone(),
                            data.eci.clone(),
                            data.cavv.as_ref().map(|cavv| cavv.peek().clone()),
                            data.ds_trans_id.clone(),
                            data.threeds_server_transaction_id.clone(),
                            data.message_version.is_some(),
                        )
                    });
                assert_eq!(
                    mapped,
                    Some((
                        Some(common_enums::TransactionStatus::Success),
                        Some("05".to_string()),
                        Some("cavv-value".to_string()),
                        Some("ds-1".to_string()),
                        Some("srv-1".to_string()),
                        true,
                    ))
                );
            }
        }

        /// A `transStatus` its ECI does not corroborate is refused, not passed on as a
        /// successful authentication: `Y` with a "not authenticated" ECI, `N` with a success
        /// ECI, and an unlisted `transStatus` all fail closed.
        #[test]
        fn authentication_finished_without_corroboration_is_refused() {
            for (trans_status, eci) in [("Y", "07"), ("N", "05"), ("Z", "05")] {
                let out = post_authenticate(&authentication_finished_body(trans_status, eci));
                assert_eq!(
                    outcome(out.resource_common_data.status, &out.response),
                    (AttemptStatus::AuthenticationFailed, false, false)
                );
                assert_eq!(
                    refusal(&out.response).and_then(|(_, _, reason)| reason),
                    Some("threeDS2Result transStatus is not corroborated by its ECI".to_string())
                );
            }
            // A missing `threeDS2Result` is the same refusal.
            let no_result = post_authenticate(
                r#"{"resultCode":"AuthenticationFinished","pspReference":"psp-1"}"#,
            );
            assert_eq!(
                no_result.resource_common_data.status,
                AttemptStatus::AuthenticationFailed
            );
        }

        /// `Refused` / `Error` / `Cancelled` report adyen's own refusal reason.
        #[test]
        fn refused_error_and_cancelled_are_authentication_failures() {
            for result_code in ["Refused", "Error", "Cancelled"] {
                let out = post_authenticate(&result_code_body(result_code));
                assert_eq!(
                    outcome(out.resource_common_data.status, &out.response),
                    (AttemptStatus::AuthenticationFailed, false, false)
                );
                assert_eq!(
                    refusal(&out.response),
                    Some((
                        "2".to_string(),
                        "Refused".to_string(),
                        Some("Refused".to_string()),
                    ))
                );
            }
        }

        /// `AuthenticationNotRequired` (and the two in-flight codes) are not failures: Authorize
        /// proceeds without `mpiData`, so the leg succeeds with neither a form nor
        /// authentication data.
        #[test]
        fn authentication_not_required_is_pending_without_authentication_data() {
            for result_code in ["AuthenticationNotRequired", "Received", "Pending"] {
                let out = pre_authenticate(&result_code_body(result_code), None);
                assert_eq!(
                    outcome(out.resource_common_data.status, &out.response),
                    (AttemptStatus::Pending, false, false)
                );
            }
        }

        /// The `serde(other)` `Unknown` arm: a `resultCode` this integration has never seen
        /// fails closed. Grouping it with `AuthenticationNotRequired` would authorise the
        /// payment with no `mpiData` on the strength of a response nobody has read.
        #[test]
        fn an_unrecognised_result_code_fails_closed() {
            let out = post_authenticate(
                r#"{"resultCode":"SomethingAdyenInventedLastTuesday","pspReference":"psp-1"}"#,
            );
            assert_eq!(
                outcome(out.resource_common_data.status, &out.response),
                (AttemptStatus::AuthenticationFailed, false, false)
            );
            assert_eq!(
                refusal(&out.response).and_then(|(_, _, reason)| reason),
                Some("adyen returned a resultCode this integration does not recognise".to_string())
            );
        }

        /// `nativeThreeDS` was asked for, so the redirect 3DS2 variant is not something these
        /// legs can run.
        #[test]
        fn redirect_shopper_is_refused_on_the_native_legs() {
            let out = pre_authenticate(&result_code_body("RedirectShopper"), None);
            assert_eq!(
                outcome(out.resource_common_data.status, &out.response),
                (AttemptStatus::AuthenticationFailed, false, false)
            );
        }

        /// Money moved on an `authenticationOnly` call: reported as an error, but with the
        /// honest money status so the composite loop does not authorise the payment twice.
        #[test]
        fn authorised_on_an_authentication_only_leg_reports_the_money_status() {
            let auto_capture = pre_authenticate(&result_code_body("Authorised"), None);
            assert_eq!(
                (
                    auto_capture.resource_common_data.status,
                    auto_capture.response.is_err()
                ),
                (AttemptStatus::Charged, true)
            );
            let manual_capture =
                pre_authenticate(&result_code_body("Authorised"), Some(CaptureMethod::Manual));
            assert_eq!(
                (
                    manual_capture.resource_common_data.status,
                    manual_capture.response.is_err()
                ),
                (AttemptStatus::Authorized, true)
            );
        }
    }

    /// Level 2/3 data on the wire: the legacy flat `additionalData.enhancedSchemeData.*` keys,
    /// including one `itemDetailLine{n}` group per order line numbered from 1.
    pub mod level_two_three {
        use std::{marker::PhantomData, str::FromStr};

        use common_utils::{request::RequestContent, types::MinorUnit};
        use domain_types::{
            connector_flow::Authorize,
            connector_types::{
                ConnectorEnum, L2L3Data, OrderInfo, PaymentFlowData, PaymentsAuthorizeData,
                PaymentsResponseData, TaxInfo,
            },
            payment_address::OrderDetailsWithAmount,
            payment_method_data::{DefaultPCIHolder, PaymentMethodData, RawCardNumber},
            router_data::ErrorResponse,
            router_data_v2::RouterDataV2,
        };
        use hyperswitch_masking::Secret;
        use interfaces::{
            connector_integration_v2::BoxedConnectorIntegrationV2, connector_types::BoxedConnector,
        };

        use super::fixtures::{adyen_config, payment_flow_data};
        use crate::{
            connectors::{adyen::transformers::AdditionalData, Adyen},
            types::ConnectorData,
        };

        fn money(minor_units: i64) -> common_utils::types::Money {
            common_utils::types::Money {
                amount: MinorUnit::new(minor_units),
                currency: common_enums::Currency::USD,
            }
        }

        fn order_line(
            product_name: &str,
            product_id: &str,
            quantity: u16,
            unit_price: i64,
        ) -> OrderDetailsWithAmount {
            OrderDetailsWithAmount {
                product_name: product_name.to_string(),
                product_id: Some(product_id.to_string()),
                quantity,
                amount: MinorUnit::new(unit_price),
                unit_of_measure: Some("EA".to_string()),
                ..Default::default()
            }
        }

        /// Two order lines, a shipping cost and an order tax amount — the fields that become
        /// `itemDetailLine1` / `itemDetailLine2`, `freightAmount` and `totalTaxAmount`.
        fn level_two_three_data() -> L2L3Data {
            L2L3Data {
                order_info: Some(OrderInfo {
                    order_date: None,
                    order_details: Some(vec![
                        order_line("widget", "SKU-1", 2, 1000),
                        order_line("gadget", "SKU-2", 3, 250),
                    ]),
                    merchant_order_reference_id: Some("order-7".to_string()),
                    discount_amount: None,
                    shipping_cost: Some(money(500)),
                    duty_amount: None,
                }),
                tax_info: Some(TaxInfo {
                    tax_status: None,
                    customer_tax_registration_id: None,
                    merchant_tax_registration_id: None,
                    shipping_amount_tax: None,
                    order_tax_amount: Some(money(250)),
                }),
                customer_info: None,
                shipping_details: None,
                billing_details: None,
            }
        }

        /// The Authorize request body the connector would send, as JSON.
        fn authorize_body(l2_l3_data: Option<Box<L2L3Data>>) -> serde_json::Value {
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<Authorize>,
                resource_common_data: PaymentFlowData {
                    l2_l3_data,
                    ..payment_flow_data()
                },
                connector_config: adyen_config(),
                request: PaymentsAuthorizeData {
                    split_settlement: None,
                    customer_document_details: None,
                    customer_date_of_birth: None,
                    payment_channel: None,
                    authentication_data: None,
                    connector_testing_data: None,
                    currency_conversion_data: None,
                    payment_method_data: PaymentMethodData::Card(
                        domain_types::payment_method_data::Card {
                            card_number: RawCardNumber(
                                cards::CardNumber::from_str("5123456789012346").unwrap(),
                            ),
                            card_cvc: Secret::new("100".into()),
                            card_exp_month: Secret::new("03".into()),
                            card_exp_year: Secret::new("2030".into()),
                            ..Default::default()
                        },
                    ),
                    amount: money(3250),
                    order_tax_amount: None,
                    surcharge_amount: None,
                    email: None,
                    customer_name: None,
                    currency: common_enums::Currency::USD,
                    confirm: true,
                    capture_method: None,
                    integrity_object: None,
                    router_return_url: Some("https://hs.example/return".to_string()),
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    browser_info: Some(domain_types::router_request_types::BrowserInformation {
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
                        ip_address: None,
                        os_type: None,
                        os_version: None,
                        device_model: None,
                        accept_language: None,
                    }),
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: Some(true),
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: Some(common_enums::PaymentMethodType::Card),
                    customer_id: None,
                    request_incremental_authorization: Some(false),
                    metadata: None,
                    merchant_order_id: None,
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
                    connector_feature_data: None,
                    billing_descriptor: None,
                    enable_partial_authorization: None,
                    locale: None,
                    continue_redirection_url: None,
                    redirect_response: None,
                    threeds_method_comp_ind: None,
                    tokenization: None,
                    mit_category: None,
                    domain_data: None,
                    partner_merchant_identifier_details: None,
                    is_account_funding_transaction: None,
                    recipient_details: None,
                    business_country: None,
                    enable_avs_check: None,
                    additional_connector_details: None,
                    customer: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Adyen::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Adyen,
            };
            let connector_integration: BoxedConnectorIntegrationV2<
                '_,
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = connector_data.connector.get_connector_integration_v2();

            connector_integration
                .build_request_v2(&req)
                .unwrap()
                .and_then(|request| request.body)
                .and_then(|content| match content {
                    RequestContent::Json(body)
                    | RequestContent::FormUrlEncoded(body)
                    | RequestContent::Xml(body) => body.masked_serialize().ok(),
                    _ => None,
                })
                .unwrap_or(serde_json::Value::Null)
        }

        /// Every L2/L3 key reaches adyen as a flat dotted `additionalData` key with a string
        /// value, one `itemDetailLine{n}` group per order line numbered from 1, and
        /// `totalAmount` = quantity x unitPrice (less any line discount, of which there is none
        /// here).
        #[test]
        fn level_two_three_data_serialises_to_flat_dotted_item_detail_line_keys() {
            let body = authorize_body(Some(Box::new(level_two_three_data())));
            let additional_data = body
                .get("additionalData")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            let key = |name: &str| additional_data.get(name).cloned();
            assert_eq!(
                (
                    key("enhancedSchemeData.customerReference"),
                    key("enhancedSchemeData.totalTaxAmount"),
                    key("enhancedSchemeData.freightAmount"),
                ),
                (
                    Some(serde_json::json!("order-7")),
                    Some(serde_json::json!("250")),
                    Some(serde_json::json!("500")),
                )
            );
            // Line numbering starts at 1, and the amounts and the quantity are strings: every
            // `additionalData` value is a string on the wire.
            assert_eq!(
                (
                    key("enhancedSchemeData.itemDetailLine1.description"),
                    key("enhancedSchemeData.itemDetailLine1.productCode"),
                    key("enhancedSchemeData.itemDetailLine1.quantity"),
                    key("enhancedSchemeData.itemDetailLine1.unitPrice"),
                    key("enhancedSchemeData.itemDetailLine1.totalAmount"),
                    key("enhancedSchemeData.itemDetailLine1.unitOfMeasure"),
                ),
                (
                    Some(serde_json::json!("widget")),
                    Some(serde_json::json!("SKU-1")),
                    Some(serde_json::json!("2")),
                    Some(serde_json::json!("1000")),
                    Some(serde_json::json!("2000")),
                    Some(serde_json::json!("EA")),
                )
            );
            assert_eq!(
                (
                    key("enhancedSchemeData.itemDetailLine2.description"),
                    key("enhancedSchemeData.itemDetailLine2.productCode"),
                    key("enhancedSchemeData.itemDetailLine2.quantity"),
                    key("enhancedSchemeData.itemDetailLine2.unitPrice"),
                    key("enhancedSchemeData.itemDetailLine2.totalAmount"),
                ),
                (
                    Some(serde_json::json!("gadget")),
                    Some(serde_json::json!("SKU-2")),
                    Some(serde_json::json!("3")),
                    Some(serde_json::json!("250")),
                    Some(serde_json::json!("750")),
                )
            );
            // There is no third line, and an absent optional key is omitted, never null.
            assert_eq!(key("enhancedSchemeData.itemDetailLine3.description"), None);
            assert_eq!(
                key("enhancedSchemeData.itemDetailLine1.commodityCode"),
                None
            );
            assert_eq!(key("enhancedSchemeData.dutyAmount"), None);

            // No L2/L3 data on the request, no `enhancedSchemeData.*` keys at all.
            let without = authorize_body(None);
            assert_eq!(
                without
                    .get("additionalData")
                    .and_then(|data| data.as_object())
                    .map(|data| data
                        .keys()
                        .any(|name| name.starts_with("enhancedSchemeData."))),
                Some(false)
            );
        }

        /// The keys are request-only (`#[serde(flatten, skip_deserializing)]`): a response that
        /// echoes one must not populate the field, and must not have it absorbed by the
        /// flattened line map either.
        #[test]
        fn a_response_never_populates_the_request_only_keys() {
            let parsed = serde_json::from_str::<AdditionalData>(
                r#"{"cardSummary":"0000","expiryDate":"03/2030","authCode":"012345","avsResult":"7 Both postal code and address match","recurring.recurringDetailReference":"tok_1","enhancedSchemeData.customerReference":"echoed-by-nobody","enhancedSchemeData.itemDetailLine1.description":"echoed-by-nobody"}"#,
            )
            .unwrap_or_default();
            assert_eq!(parsed.auth_code, Some("012345".to_string()));
            // Round-tripping is the public view of the skipped field: nothing was captured, so
            // nothing comes back out.
            let round_tripped = serde_json::to_value(&parsed).unwrap_or_default();
            assert_eq!(
                round_tripped.as_object().map(|data| data
                    .keys()
                    .any(|name| name.starts_with("enhancedSchemeData."))),
                Some(false)
            );
        }
    }
}
