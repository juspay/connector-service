#[cfg(test)]
mod tests {
    pub mod authorize {
        use std::{borrow::Cow, marker::PhantomData};

        use common_utils::{
            pii::{self, Email},
            request::RequestContent,
            types::MinorUnit,
        };
        use domain_types::{
            self,
            connector_flow::Authorize,
            connector_types::{
                ConnectorEnum, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
            },
            payment_method_data::{DefaultPCIHolder, PaymentMethodData, WalletData},
            router_data::{ConnectorAuthType, ErrorResponse},
            router_data_v2::RouterDataV2,
            types::{ConnectorParams, Connectors},
        };
        use hyperswitch_masking::Secret;
        use interfaces::{
            connector_integration_v2::BoxedConnectorIntegrationV2, connector_types::BoxedConnector,
        };
        use serde_json::json;

        use crate::{
            connectors::Bluecode,
            types::ConnectorData,
        };

        #[test]
        fn test_build_request_valid() {
            let api_key = "test_bluecode_api_key".to_string();
            let req: RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<DefaultPCIHolder>,
                PaymentsResponseData,
            > = RouterDataV2 {
                flow: PhantomData::<domain_types::connector_flow::Authorize>,
                resource_common_data: PaymentFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: Some("conn_cust_987654".to_string()),
                    payment_id: "pay_abcdef123456".to_string(),
                    attempt_id: "attempt_123456abcdef".to_string(),
                    status: common_enums::AttemptStatus::Pending,
                    payment_method: common_enums::PaymentMethod::Wallet,
                    description: Some("Payment for order #12345".to_string()),
                    return_url: Some("https://www.google.com".to_string()),
                    address: domain_types::payment_address::PaymentAddress::new(
                        None,
                        Some(domain_types::payment_address::AddressDetails {
                            first_name: Some(Secret::new("John".to_string())),
                            last_name: Some(Secret::new("Doe".to_string())),
                            line1: Some(Secret::new("123 Main St".to_string())),
                            city: Some("Anytown".to_string()),
                            zip: Some(Secret::new("12345".to_string())),
                            country: Some(common_enums::CountryAlpha2::US),
                            ..Default::default()
                        }),
                        None,
                        None,
                    ),
                    auth_type: common_enums::AuthenticationType::NoThreeDs,
                    connector_meta_data: Some(pii::SecretSerdeValue::new(
                        serde_json::json!({ "shop_name": "test_shop" }),
                    )),
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
                        bluecode: ConnectorParams {
                            base_url: "https://api.bluecode.com/".to_string(),
                            dispute_base_url: None,
                        },
                        ..Default::default()
                    },
                    external_latency: None,
                    connector_response_headers: None,
                    raw_connector_response: None,
                },
                connector_auth_type: ConnectorAuthType::HeaderKey {
                    api_key: Secret::new(api_key),
                },
                request: PaymentsAuthorizeData {
                    payment_method_data: PaymentMethodData::Wallet(WalletData::BluecodeRedirect {}),
                    amount: 1000,
                    order_tax_amount: None,
                    email: Some(
                        Email::try_from("test@example.com".to_string())
                            .expect("Failed to parse email"),
                    ),
                    customer_name: None,
                    currency: common_enums::Currency::USD,
                    confirm: true,
                    statement_descriptor_suffix: None,
                    statement_descriptor: None,
                    capture_method: None,
                    integrity_object: None,
                    router_return_url: Some("https://www.google.com".to_string()),
                    webhook_url: Some("https://webhook.site/".to_string()),
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
                    customer_id: Some(
                        common_utils::id_type::CustomerId::try_from(Cow::from(
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
                    all_keys_required: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Bluecode::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Bluecode,
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
        fn test_build_request_missing_fields() {
            let api_key = "test_bluecode_api_key_missing".to_string();
            let req: RouterDataV2<
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
                    payment_id: "".to_string(),
                    attempt_id: "".to_string(),
                    status: common_enums::AttemptStatus::Pending,
                    payment_method: common_enums::PaymentMethod::Wallet,
                    description: None,
                    return_url: None,
                    address: domain_types::payment_address::PaymentAddress::new(
                        None, None, None, None,
                    ),
                    auth_type: common_enums::AuthenticationType::NoThreeDs,
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
                        bluecode: ConnectorParams {
                            base_url: "https://api.bluecode.com/".to_string(),
                            dispute_base_url: None,
                        },
                        ..Default::default()
                    },
                    external_latency: None,
                    connector_response_headers: None,
                    raw_connector_response: None,
                },
                connector_auth_type: ConnectorAuthType::HeaderKey {
                    api_key: Secret::new(api_key),
                },
                request: PaymentsAuthorizeData {
                    payment_method_data: PaymentMethodData::Wallet(WalletData::BluecodeRedirect {}),
                    amount: 0,
                    order_tax_amount: None,
                    email: None,
                    customer_name: None,
                    currency: common_enums::Currency::USD,
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
                    integrity_object: None,
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
                    all_keys_required: None,
                },
                response: Err(ErrorResponse::default()),
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Bluecode::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Bluecode,
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
    }
}
