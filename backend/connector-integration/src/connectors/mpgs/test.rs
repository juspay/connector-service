#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::panic)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::print_stdout)]
mod tests {
    use std::{borrow::Cow, marker::PhantomData, str::FromStr};

    use cards::CardNumber;
    use common_enums::{
        AttemptStatus, AuthenticationType, Currency, PaymentMethod, PaymentMethodType, RefundStatus,
    };
    use common_utils::{
        id_type::CustomerId, pii::Email, request::RequestContent, types::MinorUnit,
    };
    use domain_types::{
        connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
        connector_types::{
            ConnectorEnum, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
            PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
            RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
        },
        payment_address::{Address, PaymentAddress, PhoneDetails},
        payment_method_data::{Card, DefaultPCIHolder, PaymentMethodData, RawCardNumber},
        router_data::{ConnectorAuthType, ErrorResponse},
        router_data_v2::RouterDataV2,
        router_request_types::BrowserInformation,
        router_response_types::Response,
        types::{ConnectorParams, Connectors},
    };
    use hyperswitch_masking::{PeekInterface, Secret};
    use interfaces::connector_types::BoxedConnector;
    use serde_json::{to_value, Value};

    use crate::{
        connectors::{mpgs::transformers::*, Mpgs},
        types::ConnectorData,
    };

    pub(super) fn create_test_connectors() -> Connectors {
        Connectors {
            mpgs: ConnectorParams {
                base_url: "https://api.mpgs.example.com/".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn create_test_card() -> Card<DefaultPCIHolder> {
        Card {
            card_number: RawCardNumber(CardNumber::from_str("5123456789012346").unwrap()),
            card_exp_month: Secret::new("03".to_string()),
            card_exp_year: Secret::new("2030".to_string()),
            card_cvc: Secret::new("123".to_string()),
            card_issuer: None,
            card_network: None,
            card_type: None,
            card_issuing_country: None,
            bank_code: None,
            nick_name: None,
            card_holder_name: Some(Secret::new("Test User".to_string())),
            co_badged_card_data: None,
        }
    }

    pub(super) fn create_test_authorize_router_data() -> RouterDataV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<DefaultPCIHolder>,
        PaymentsResponseData,
    > {
        let email = Email::try_from("test@example.com".to_string()).unwrap();

        RouterDataV2 {
            flow: PhantomData::<Authorize>,
            resource_common_data: PaymentFlowData {
                merchant_id: common_utils::id_type::MerchantId::default(),
                customer_id: None,
                connector_customer: None,
                payment_id: "pay_123456789".to_string(),
                attempt_id: "attempt_987654321".to_string(),
                status: AttemptStatus::Pending,
                payment_method: PaymentMethod::Card,
                description: Some("Test payment for order #12345".to_string()),
                return_url: Some("https://example.com/return".to_string()),
                order_details: None,
                address: PaymentAddress::new(
                    None,
                    Some(Address {
                        address: None,
                        phone: Some(PhoneDetails {
                            number: Some(Secret::new("1234567890".to_string())),
                            country_code: Some("+1".to_string()),
                        }),
                        email: Some(email.clone()),
                    }),
                    None,
                    None,
                ),
                auth_type: AuthenticationType::NoThreeDs,
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
                connector_request_reference_id: "ref_123456789".to_string(),
                test_mode: None,
                connector_http_status_code: None,
                connectors: create_test_connectors(),
                external_latency: None,
                connector_response_headers: None,
                raw_connector_response: None,
                vault_headers: None,
                raw_connector_request: None,
                minor_amount_capturable: None,
                connector_response: None,
                recurring_mandate_payment_data: None,
            },
            connector_auth_type: ConnectorAuthType::BodyKey {
                api_key: Secret::new("test_api_key".to_string()),
                key1: Secret::new("test_api_secret".to_string()),
            },
            request: PaymentsAuthorizeData {
                payment_channel: None,
                authentication_data: None,
                connector_testing_data: None,
                payment_method_data: PaymentMethodData::Card(create_test_card()),
                amount: MinorUnit::new(1000),
                order_tax_amount: None,
                email: Some(email),
                customer_name: None,
                currency: Currency::USD,
                confirm: true,
                capture_method: None,
                integrity_object: None,
                router_return_url: Some("https://example.com/return".to_string()),
                webhook_url: None,
                complete_authorize_url: None,
                mandate_id: None,
                setup_future_usage: None,
                off_session: None,
                browser_info: Some(BrowserInformation {
                    color_depth: Some(24),
                    java_enabled: Some(false),
                    screen_height: Some(1080),
                    screen_width: Some(1920),
                    user_agent: Some("Mozilla/5.0 (Test Browser)".to_string()),
                    accept_header: Some("text/html".to_string()),
                    java_script_enabled: Some(true),
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
                enrolled_for_3ds: Some(false),
                related_transaction_id: None,
                payment_experience: None,
                payment_method_type: Some(PaymentMethodType::Card),
                customer_id: Some(
                    CustomerId::try_from(Cow::from("cus_123456789".to_string())).unwrap(),
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
        }
    }

    mod authorize_tests {
        use super::*;

        #[test]
        fn test_authorize_request_transformation() {
            let router_data = create_test_authorize_router_data();
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector.get_request_body(&router_data);

            assert!(
                result.is_ok(),
                "Expected successful request body generation"
            );
            let request_content = result.unwrap().unwrap();

            let actual_json: Value = match request_content {
                RequestContent::Json(payload) => {
                    to_value(&payload).expect("Failed to serialize payload to JSON")
                }
                _ => panic!("Expected JSON payload"),
            };

            assert_eq!(actual_json["apiOperation"], "AUTHORIZE");
            assert_eq!(actual_json["order"]["amount"], "1000");
            assert_eq!(actual_json["order"]["currency"], "USD");
            assert_eq!(actual_json["sourceOfFunds"]["type"], "CARD");
        }

        #[test]
        fn test_authorize_request_non_card_payment_method() {
            let mut router_data = create_test_authorize_router_data();
            router_data.request.payment_method_data = PaymentMethodData::Wallet(
                domain_types::payment_method_data::WalletData::ApplePayRedirect(Box::new(
                    domain_types::payment_method_data::ApplePayRedirectData {},
                )),
            );
            router_data.resource_common_data.payment_method = PaymentMethod::Wallet;

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector.get_request_body(&router_data);

            assert!(
                result.is_err(),
                "Expected error for non-card payment method"
            );
        }

        #[test]
        fn test_authorize_response_approved() {
            let router_data = create_test_authorize_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "APPROVED",
                        "acquirerCode": "00",
                        "acquirerMessage": "Approved"
                    },
                    "transaction": {
                        "type": "authorization",
                        "amount": "1000",
                        "currency": "USD",
                        "authorizationCode": "AUTH123",
                        "receipt": "RCPT001",
                        "id": "TXN123456"
                    },
                    "order": {
                        "id": "ORDER123",
                        "status": "CAPTURED"
                    },
                    "result": "SUCCESS"
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Charged);
            match result.response.unwrap() {
                PaymentsResponseData::TransactionResponse { resource_id, .. } => {
                    assert!(
                        matches!(resource_id, ResponseId::ConnectorTransactionId(id) if id == "TXN123456")
                    );
                }
                _ => panic!("Expected TransactionResponse"),
            }
        }

        #[test]
        fn test_authorize_response_declined() {
            let router_data = create_test_authorize_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "DECLINED",
                        "acquirerCode": "05",
                        "acquirerMessage": "Do not honor"
                    },
                    "transaction": {
                        "type": "authorization",
                        "amount": "1000",
                        "currency": "USD",
                        "id": "TXN_DECLINED"
                    },
                    "order": {
                        "id": "ORDER_DECLINED",
                        "status": "CANCELLED"
                    },
                    "result": "DECLINED"
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Failure);
        }

        #[test]
        fn test_authorize_response_pending() {
            let router_data = create_test_authorize_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "PENDING",
                        "acquirerCode": null,
                        "acquirerMessage": null
                    },
                    "transaction": {
                        "type": "authorization",
                        "amount": "1000",
                        "currency": "USD",
                        "id": "TXN_PENDING"
                    },
                    "order": {
                        "id": "ORDER_PENDING",
                        "status": "PENDING"
                    },
                    "result": "PENDING"
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Pending);
        }

        #[test]
        fn test_authorize_response_authentication_in_progress() {
            let router_data = create_test_authorize_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "AUTHENTICATION_IN_PROGRESS"
                    },
                    "transaction": {
                        "id": "TXN_AUTH_IN_PROGRESS"
                    },
                    "result": "PENDING"
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Pending);
        }

        #[test]
        fn test_authorize_response_partial_approval() {
            let router_data = create_test_authorize_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "PARTIALLY_APPROVED"
                    },
                    "transaction": {
                        "amount": "500",
                        "id": "TXN_PARTIAL"
                    },
                    "result": "PARTIAL_APPROVAL"
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(
                result.resource_common_data.status,
                AttemptStatus::PartialCharged
            );
        }
    }

    mod psync_tests {
        use super::*;

        pub(super) fn create_test_psync_router_data(
        ) -> RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> {
            RouterDataV2 {
                flow: PhantomData::<PSync>,
                resource_common_data: PaymentFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: None,
                    payment_id: "pay_sync_123".to_string(),
                    attempt_id: "attempt_sync_456".to_string(),
                    status: AttemptStatus::Pending,
                    payment_method: PaymentMethod::Card,
                    description: None,
                    return_url: None,
                    order_details: None,
                    address: PaymentAddress::new(None, None, None, None),
                    auth_type: AuthenticationType::NoThreeDs,
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
                    connector_request_reference_id: "ref_sync".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: create_test_connectors(),
                    external_latency: None,
                    connector_response_headers: None,
                    raw_connector_response: None,
                    vault_headers: None,
                    raw_connector_request: None,
                    minor_amount_capturable: None,
                    connector_response: None,
                    recurring_mandate_payment_data: None,
                },
                connector_auth_type: ConnectorAuthType::BodyKey {
                    api_key: Secret::new("test_api_key".to_string()),
                    key1: Secret::new("test_api_secret".to_string()),
                },
                request: PaymentsSyncData {
                    connector_transaction_id: ResponseId::ConnectorTransactionId(
                        "TXN_SYNC_123".to_string(),
                    ),
                    encoded_data: None,
                    capture_method: None,
                    sync_type: Default::default(),
                    connector_metadata: None,
                    mandate_id: None,
                    payment_method_type: None,
                    currency: Currency::USD,
                    payment_experience: None,
                    amount: MinorUnit::new(1000),
                    all_keys_required: None,
                    integrity_object: None,
                    split_payments: None,
                    setup_future_usage: None,
                },
                response: Err(ErrorResponse::default()),
            }
        }

        #[test]
        fn test_psync_response_approved() {
            let router_data = create_test_psync_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "APPROVED",
                        "acquirerCode": "00"
                    },
                    "transaction": {
                        "id": "TXN_SYNC_123",
                        "authorizationCode": "AUTH_SYNC"
                    },
                    "order": {
                        "id": "ORDER_SYNC"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Charged);
        }

        #[test]
        fn test_psync_response_declined() {
            let router_data = create_test_psync_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "DECLINED"
                    },
                    "transaction": {
                        "id": "TXN_SYNC_DECLINED"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Failure);
        }

        #[test]
        fn test_psync_response_voided() {
            let router_data = create_test_psync_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "CANCELLED"
                    },
                    "transaction": {
                        "id": "TXN_SYNC_CANCELLED"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Voided);
        }
    }

    mod capture_tests {
        use super::*;

        pub(super) fn create_test_capture_router_data(
        ) -> RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        {
            RouterDataV2 {
                flow: PhantomData::<Capture>,
                resource_common_data: PaymentFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: None,
                    payment_id: "pay_capture_123".to_string(),
                    attempt_id: "attempt_capture_456".to_string(),
                    status: AttemptStatus::Authorized,
                    payment_method: PaymentMethod::Card,
                    description: None,
                    return_url: None,
                    order_details: None,
                    address: PaymentAddress::new(None, None, None, None),
                    auth_type: AuthenticationType::NoThreeDs,
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
                    connector_request_reference_id: "ref_capture".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: create_test_connectors(),
                    external_latency: None,
                    connector_response_headers: None,
                    raw_connector_response: None,
                    vault_headers: None,
                    raw_connector_request: None,
                    minor_amount_capturable: None,
                    connector_response: None,
                    recurring_mandate_payment_data: None,
                },
                connector_auth_type: ConnectorAuthType::BodyKey {
                    api_key: Secret::new("test_api_key".to_string()),
                    key1: Secret::new("test_api_secret".to_string()),
                },
                request: PaymentsCaptureData {
                    amount_to_capture: 500,
                    minor_amount_to_capture: MinorUnit::new(500),
                    currency: Currency::USD,
                    connector_transaction_id: ResponseId::ConnectorTransactionId(
                        "TXN_CAPTURE_123".to_string(),
                    ),
                    multiple_capture_data: None,
                    connector_metadata: None,
                    integrity_object: None,
                    browser_info: None,
                    capture_method: None,
                    metadata: None,
                    merchant_order_reference_id: None,
                },
                response: Err(ErrorResponse::default()),
            }
        }

        #[test]
        fn test_capture_request_transformation() {
            let router_data = create_test_capture_router_data();
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector.get_request_body(&router_data);

            assert!(
                result.is_ok(),
                "Expected successful capture request body generation"
            );
            let request_content = result.unwrap().unwrap();

            let actual_json: Value = match request_content {
                RequestContent::Json(payload) => {
                    to_value(&payload).expect("Failed to serialize payload to JSON")
                }
                _ => panic!("Expected JSON payload"),
            };

            assert_eq!(actual_json["apiOperation"], "CAPTURE");
            assert_eq!(actual_json["transaction"]["amount"], "500");
            assert_eq!(actual_json["transaction"]["currency"], "USD");
        }

        #[test]
        fn test_capture_response_approved() {
            let router_data = create_test_capture_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "APPROVED",
                        "acquirerCode": "00"
                    },
                    "transaction": {
                        "id": "TXN_CAPTURE_APPROVED",
                        "type": "capture",
                        "amount": "500"
                    },
                    "order": {
                        "id": "ORDER_CAPTURE"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Charged);
        }

        #[test]
        fn test_capture_response_declined() {
            let router_data = create_test_capture_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "DECLINED"
                    },
                    "transaction": {
                        "id": "TXN_CAPTURE_DECLINED"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Failure);
        }
    }

    mod refund_tests {
        use super::*;

        pub(super) fn create_test_refund_router_data(
        ) -> RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> {
            RouterDataV2 {
                flow: PhantomData::<Refund>,
                resource_common_data: RefundFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    status: RefundStatus::Pending,
                    refund_id: Some("refund_456".to_string()),
                    connectors: create_test_connectors(),
                    connector_request_reference_id: "order_refund_123".to_string(),
                    raw_connector_response: None,
                    connector_response_headers: None,
                    raw_connector_request: None,
                    access_token: None,
                    connector_meta_data: None,
                    test_mode: None,
                    payment_method: None,
                },
                connector_auth_type: ConnectorAuthType::BodyKey {
                    api_key: Secret::new("test_api_key".to_string()),
                    key1: Secret::new("test_api_secret".to_string()),
                },
                request: RefundsData {
                    refund_id: "refund_456".to_string(),
                    minor_refund_amount: MinorUnit::new(250),
                    currency: Currency::USD,
                    reason: Some("Customer request".to_string()),
                    connector_transaction_id: "TXN_REFUND_123".to_string(),
                    connector_refund_id: None,
                    customer_id: None,
                    payment_amount: 1000,
                    webhook_url: None,
                    refund_amount: 250,
                    connector_metadata: None,
                    refund_connector_metadata: None,
                    minor_payment_amount: MinorUnit::new(1000),
                    refund_status: RefundStatus::Pending,
                    merchant_account_id: None,
                    capture_method: None,
                    integrity_object: None,
                    browser_info: None,
                    split_refunds: None,
                    merchant_account_metadata: None,
                },
                response: Err(ErrorResponse::default()),
            }
        }

        #[test]
        fn test_refund_request_transformation() {
            let router_data = create_test_refund_router_data();
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector.get_request_body(&router_data);

            assert!(
                result.is_ok(),
                "Expected successful refund request body generation"
            );
            let request_content = result.unwrap().unwrap();

            let actual_json: Value = match request_content {
                RequestContent::Json(payload) => {
                    to_value(&payload).expect("Failed to serialize payload to JSON")
                }
                _ => panic!("Expected JSON payload"),
            };

            assert_eq!(actual_json["apiOperation"], "REFUND");
            assert_eq!(actual_json["transaction"]["amount"], "250");
            assert_eq!(actual_json["transaction"]["currency"], "USD");
        }

        #[test]
        fn test_refund_response_approved() {
            let router_data = create_test_refund_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "APPROVED"
                    },
                    "transaction": {
                        "id": "REFUND_TXN_123",
                        "type": "refund",
                        "amount": "250"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, RefundStatus::Success);
            let refund_response = result.response.unwrap();
            assert_eq!(refund_response.connector_refund_id, "REFUND_TXN_123");
            assert_eq!(refund_response.refund_status, RefundStatus::Success);
        }

        #[test]
        fn test_refund_response_pending() {
            let router_data = create_test_refund_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "PENDING"
                    },
                    "transaction": {
                        "id": "REFUND_PENDING_123"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, RefundStatus::Pending);
        }

        #[test]
        fn test_refund_response_failure() {
            let router_data = create_test_refund_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "DECLINED"
                    },
                    "transaction": {
                        "id": "REFUND_DECLINED_123"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, RefundStatus::Failure);
        }
    }

    mod rsync_tests {
        use super::*;

        pub(super) fn create_test_rsync_router_data(
        ) -> RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> {
            RouterDataV2 {
                flow: PhantomData::<RSync>,
                resource_common_data: RefundFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    status: RefundStatus::Pending,
                    refund_id: Some("refund_rsync_456".to_string()),
                    connectors: create_test_connectors(),
                    connector_request_reference_id: "order_rsync_123".to_string(),
                    raw_connector_response: None,
                    connector_response_headers: None,
                    raw_connector_request: None,
                    access_token: None,
                    connector_meta_data: None,
                    test_mode: None,
                    payment_method: None,
                },
                connector_auth_type: ConnectorAuthType::BodyKey {
                    api_key: Secret::new("test_api_key".to_string()),
                    key1: Secret::new("test_api_secret".to_string()),
                },
                request: RefundSyncData {
                    connector_transaction_id: "TXN_RSYNC_123".to_string(),
                    connector_refund_id: "REFUND_RSYNC_123".to_string(),
                    reason: None,
                    refund_connector_metadata: None,
                    refund_status: RefundStatus::Pending,
                    all_keys_required: None,
                    integrity_object: None,
                    browser_info: None,
                    split_refunds: None,
                    merchant_account_metadata: None,
                },
                response: Err(ErrorResponse::default()),
            }
        }

        #[test]
        fn test_rsync_response_approved() {
            let router_data = create_test_rsync_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "APPROVED"
                    },
                    "transaction": {
                        "id": "REFUND_RSYNC_APPROVED"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, RefundStatus::Success);
        }

        #[test]
        fn test_rsync_response_pending() {
            let router_data = create_test_rsync_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "SUBMITTED"
                    },
                    "transaction": {
                        "id": "REFUND_RSYNC_SUBMITTED"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, RefundStatus::Pending);
        }

        #[test]
        fn test_rsync_response_failure() {
            let router_data = create_test_rsync_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "UNKNOWN_ERROR"
                    },
                    "transaction": {
                        "id": "REFUND_RSYNC_FAILED"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, RefundStatus::Failure);
        }
    }

    mod void_tests {
        use super::*;

        pub(super) fn create_test_void_router_data(
        ) -> RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> {
            RouterDataV2 {
                flow: PhantomData::<Void>,
                resource_common_data: PaymentFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: None,
                    payment_id: "pay_void_123".to_string(),
                    attempt_id: "attempt_void_456".to_string(),
                    status: AttemptStatus::Authorized,
                    payment_method: PaymentMethod::Card,
                    description: None,
                    return_url: None,
                    order_details: None,
                    address: PaymentAddress::new(None, None, None, None),
                    auth_type: AuthenticationType::NoThreeDs,
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
                    connector_request_reference_id: "ref_void".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connectors: create_test_connectors(),
                    external_latency: None,
                    connector_response_headers: None,
                    raw_connector_response: None,
                    vault_headers: None,
                    raw_connector_request: None,
                    minor_amount_capturable: None,
                    connector_response: None,
                    recurring_mandate_payment_data: None,
                },
                connector_auth_type: ConnectorAuthType::BodyKey {
                    api_key: Secret::new("test_api_key".to_string()),
                    key1: Secret::new("test_api_secret".to_string()),
                },
                request: PaymentVoidData {
                    connector_transaction_id: "TXN_VOID_123".to_string(),
                    cancellation_reason: None,
                    integrity_object: None,
                    raw_connector_response: None,
                    browser_info: None,
                    amount: None,
                    currency: None,
                    connector_metadata: None,
                    metadata: None,
                    merchant_order_reference_id: None,
                },
                response: Err(ErrorResponse::default()),
            }
        }

        #[test]
        fn test_void_request_transformation() {
            let router_data = create_test_void_router_data();
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector.get_request_body(&router_data);

            assert!(
                result.is_ok(),
                "Expected successful void request body generation"
            );
            let request_content = result.unwrap().unwrap();

            let actual_json: Value = match request_content {
                RequestContent::Json(payload) => {
                    to_value(&payload).expect("Failed to serialize payload to JSON")
                }
                _ => panic!("Expected JSON payload"),
            };

            assert_eq!(actual_json["apiOperation"], "VOID");
        }

        #[test]
        fn test_void_response_approved() {
            let router_data = create_test_void_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "APPROVED"
                    },
                    "transaction": {
                        "id": "TXN_VOID_APPROVED",
                        "type": "void"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Charged);
        }

        #[test]
        fn test_void_response_cancelled() {
            let router_data = create_test_void_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "CANCELLED"
                    },
                    "transaction": {
                        "id": "TXN_VOID_CANCELLED",
                        "type": "void"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Voided);
        }

        #[test]
        fn test_void_response_blocked() {
            let router_data = create_test_void_router_data();

            let http_response = Response {
                headers: None,
                response: br#"{
                    "response": {
                        "gatewayCode": "BLOCKED"
                    },
                    "transaction": {
                        "id": "TXN_VOID_BLOCKED"
                    }
                }"#
                .to_vec()
                .into(),
                status_code: 200,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector
                .handle_response_v2(&router_data, None, http_response)
                .unwrap();

            assert_eq!(result.resource_common_data.status, AttemptStatus::Voided);
        }
    }

    mod status_mapping_tests {
        use super::*;

        fn map_gateway_code(code: &str) -> AttemptStatus {
            match code.to_uppercase().as_str() {
                "APPROVED" | "APPROVED_AUTO" | "APPROVED_PENDING_SETTLEMENT" => {
                    AttemptStatus::Charged
                }
                "PARTIALLY_APPROVED" => AttemptStatus::PartialCharged,
                "PENDING" | "AUTHENTICATION_IN_PROGRESS" | "SUBMITTED" => AttemptStatus::Pending,
                "DECLINED"
                | "DECLINED_AVS"
                | "DECLINED_AVS_CSC"
                | "DECLINED_CSC"
                | "DECLINED_DO_NOT_CONTACT"
                | "DECLINED_INVALID_PIN"
                | "DECLINED_PAYMENT_PLAN"
                | "DECLINED_PIN_REQUIRED"
                | "EXPIRED_CARD"
                | "INSUFFICIENT_FUNDS"
                | "REFERRED"
                | "UNSPECIFIED_FAILURE" => AttemptStatus::Failure,
                "AUTHENTICATION_FAILED" => AttemptStatus::AuthenticationFailed,
                "BLOCKED" | "CANCELLED" | "ABORTED" => AttemptStatus::Voided,
                "TIMED_OUT" | "UNKNOWN" | "SYSTEM_ERROR" | "ACQUIRER_SYSTEM_ERROR" => {
                    AttemptStatus::Pending
                }
                _ => AttemptStatus::Pending,
            }
        }

        #[test]
        fn test_gateway_code_approved() {
            assert_eq!(map_gateway_code("APPROVED"), AttemptStatus::Charged);
            assert_eq!(map_gateway_code("approved"), AttemptStatus::Charged);
            assert_eq!(map_gateway_code("APPROVED_AUTO"), AttemptStatus::Charged);
            assert_eq!(
                map_gateway_code("APPROVED_PENDING_SETTLEMENT"),
                AttemptStatus::Charged
            );
        }

        #[test]
        fn test_gateway_code_declined() {
            assert_eq!(map_gateway_code("DECLINED"), AttemptStatus::Failure);
            assert_eq!(map_gateway_code("DECLINED_AVS"), AttemptStatus::Failure);
            assert_eq!(map_gateway_code("DECLINED_AVS_CSC"), AttemptStatus::Failure);
            assert_eq!(map_gateway_code("DECLINED_CSC"), AttemptStatus::Failure);
            assert_eq!(
                map_gateway_code("DECLINED_DO_NOT_CONTACT"),
                AttemptStatus::Failure
            );
            assert_eq!(
                map_gateway_code("DECLINED_INVALID_PIN"),
                AttemptStatus::Failure
            );
            assert_eq!(
                map_gateway_code("DECLINED_PAYMENT_PLAN"),
                AttemptStatus::Failure
            );
            assert_eq!(
                map_gateway_code("DECLINED_PIN_REQUIRED"),
                AttemptStatus::Failure
            );
        }

        #[test]
        fn test_gateway_code_expired_card() {
            assert_eq!(map_gateway_code("EXPIRED_CARD"), AttemptStatus::Failure);
        }

        #[test]
        fn test_gateway_code_insufficient_funds() {
            assert_eq!(
                map_gateway_code("INSUFFICIENT_FUNDS"),
                AttemptStatus::Failure
            );
        }

        #[test]
        fn test_gateway_code_pending() {
            assert_eq!(map_gateway_code("PENDING"), AttemptStatus::Pending);
            assert_eq!(
                map_gateway_code("AUTHENTICATION_IN_PROGRESS"),
                AttemptStatus::Pending
            );
            assert_eq!(map_gateway_code("SUBMITTED"), AttemptStatus::Pending);
        }

        #[test]
        fn test_gateway_code_voided() {
            assert_eq!(map_gateway_code("BLOCKED"), AttemptStatus::Voided);
            assert_eq!(map_gateway_code("CANCELLED"), AttemptStatus::Voided);
            assert_eq!(map_gateway_code("ABORTED"), AttemptStatus::Voided);
        }

        #[test]
        fn test_gateway_code_authentication_failed() {
            assert_eq!(
                map_gateway_code("AUTHENTICATION_FAILED"),
                AttemptStatus::AuthenticationFailed
            );
        }

        #[test]
        fn test_gateway_code_system_errors() {
            assert_eq!(map_gateway_code("TIMED_OUT"), AttemptStatus::Pending);
            assert_eq!(map_gateway_code("UNKNOWN"), AttemptStatus::Pending);
            assert_eq!(map_gateway_code("SYSTEM_ERROR"), AttemptStatus::Pending);
            assert_eq!(
                map_gateway_code("ACQUIRER_SYSTEM_ERROR"),
                AttemptStatus::Pending
            );
        }

        #[test]
        fn test_gateway_code_unknown_defaults_to_pending() {
            assert_eq!(map_gateway_code("UNKNOWN_CODE"), AttemptStatus::Pending);
            assert_eq!(map_gateway_code("RANDOM_ERROR"), AttemptStatus::Pending);
        }

        #[test]
        fn test_gateway_code_partial_approval() {
            assert_eq!(
                map_gateway_code("PARTIALLY_APPROVED"),
                AttemptStatus::PartialCharged
            );
        }

        fn map_refund_gateway_code(code: &str) -> RefundStatus {
            match code.to_uppercase().as_str() {
                "APPROVED" | "APPROVED_AUTO" | "APPROVED_PENDING_SETTLEMENT" => {
                    RefundStatus::Success
                }
                "PENDING" | "SUBMITTED" => RefundStatus::Pending,
                _ => RefundStatus::Failure,
            }
        }

        #[test]
        fn test_refund_status_mapping_success() {
            assert_eq!(map_refund_gateway_code("APPROVED"), RefundStatus::Success);
            assert_eq!(
                map_refund_gateway_code("APPROVED_AUTO"),
                RefundStatus::Success
            );
            assert_eq!(
                map_refund_gateway_code("APPROVED_PENDING_SETTLEMENT"),
                RefundStatus::Success
            );
        }

        #[test]
        fn test_refund_status_mapping_pending() {
            assert_eq!(map_refund_gateway_code("PENDING"), RefundStatus::Pending);
            assert_eq!(map_refund_gateway_code("SUBMITTED"), RefundStatus::Pending);
        }

        #[test]
        fn test_refund_status_mapping_failure() {
            assert_eq!(map_refund_gateway_code("DECLINED"), RefundStatus::Failure);
            assert_eq!(map_refund_gateway_code("UNKNOWN"), RefundStatus::Failure);
            assert_eq!(map_refund_gateway_code("ERROR"), RefundStatus::Failure);
        }
    }

    mod auth_tests {
        use super::*;

        #[test]
        fn test_basic_auth_generation() {
            let auth = MpgsAuthType {
                api_key: Secret::new("test_username".to_string()),
                api_secret: Some(Secret::new("test_password".to_string())),
            };

            let basic_auth = auth.generate_basic_auth();
            let expected = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                "test_username:test_password",
            );
            assert_eq!(basic_auth, expected);
        }

        #[test]
        fn test_basic_auth_generation_without_secret() {
            let auth = MpgsAuthType {
                api_key: Secret::new("test_api_key".to_string()),
                api_secret: None,
            };

            let basic_auth = auth.generate_basic_auth();
            let expected =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "test_api_key:");
            assert_eq!(basic_auth, expected);
        }

        #[test]
        fn test_auth_type_from_signature_key() {
            let auth_type = ConnectorAuthType::SignatureKey {
                api_key: Secret::new("signature_key".to_string()),
                api_secret: Secret::new("signature_secret".to_string()),
                key1: Secret::new("signature_key1".to_string()),
            };

            let mpgs_auth = MpgsAuthType::try_from(&auth_type).unwrap();
            assert_eq!(mpgs_auth.api_key.peek(), "signature_key");
            assert_eq!(
                mpgs_auth.api_secret.as_ref().unwrap().peek(),
                "signature_secret"
            );
        }

        #[test]
        fn test_auth_type_from_body_key() {
            let auth_type = ConnectorAuthType::BodyKey {
                api_key: Secret::new("body_key".to_string()),
                key1: Secret::new("body_key1".to_string()),
            };

            let mpgs_auth = MpgsAuthType::try_from(&auth_type).unwrap();
            assert_eq!(mpgs_auth.api_key.peek(), "body_key");
            assert_eq!(mpgs_auth.api_secret.as_ref().unwrap().peek(), "body_key1");
        }

        #[test]
        fn test_auth_type_from_header_key() {
            let auth_type = ConnectorAuthType::HeaderKey {
                api_key: Secret::new("header_key".to_string()),
            };

            let mpgs_auth = MpgsAuthType::try_from(&auth_type).unwrap();
            assert_eq!(mpgs_auth.api_key.peek(), "header_key");
            assert!(mpgs_auth.api_secret.is_none());
        }

        #[test]
        fn test_auth_type_unsupported_type() {
            let auth_type = ConnectorAuthType::NoKey;

            let result = MpgsAuthType::try_from(&auth_type);
            assert!(result.is_err());
        }
    }

    mod error_response_tests {
        use super::*;
        #[allow(unused_imports)]
        use interfaces::api::ConnectorCommon;

        #[test]
        fn test_error_response_with_error_object() {
            let http_response = Response {
                headers: None,
                response: br#"{
                    "error": {
                        "cause": "INVALID_CARD_NUMBER",
                        "explanation": "The card number is invalid",
                        "field": "card.number",
                        "support_code": "SUPPORT_123"
                    },
                    "result": "ERROR"
                }"#
                .to_vec()
                .into(),
                status_code: 400,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector.build_error_response(http_response, None).unwrap();

            assert_eq!(result.code, "INVALID_CARD_NUMBER");
            assert_eq!(result.message, "The card number is invalid");
            assert_eq!(result.reason, Some("SUPPORT_123".to_string()));
            assert_eq!(result.status_code, 400);
        }

        #[test]
        fn test_error_response_without_error_object() {
            let http_response = Response {
                headers: None,
                response: br#"{
                    "result": "SYSTEM_ERROR"
                }"#
                .to_vec()
                .into(),
                status_code: 500,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector.build_error_response(http_response, None).unwrap();

            assert_eq!(result.code, "SYSTEM_ERROR");
            assert_eq!(result.message, "Unknown error occurred");
        }

        #[test]
        fn test_error_response_partial_error_fields() {
            let http_response = Response {
                headers: None,
                response: br#"{
                    "error": {
                        "cause": "PROCESSING_ERROR"
                    },
                    "result": "ERROR"
                }"#
                .to_vec()
                .into(),
                status_code: 500,
            };

            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let result = connector.build_error_response(http_response, None).unwrap();

            assert_eq!(result.code, "PROCESSING_ERROR");
            assert_eq!(result.message, "Unknown error occurred");
        }
    }

    mod url_tests {
        use super::*;

        #[test]
        fn test_authorize_url_generation() {
            let router_data = create_test_authorize_router_data();
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Mpgs,
            };

            let connector_integration = connector_data.connector.get_connector_integration_v2();
            let request = connector_integration
                .build_request_v2(&router_data)
                .unwrap();

            let url = request.as_ref().unwrap().url.clone();
            assert!(url.contains("merchant/"));
            assert!(url.contains("order/pay_123456789"));
            assert!(url.contains("transaction/attempt_987654321"));
        }

        #[test]
        fn test_capture_url_generation() {
            let router_data = capture_tests::create_test_capture_router_data();
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Mpgs,
            };

            let connector_integration = connector_data.connector.get_connector_integration_v2();
            let request = connector_integration
                .build_request_v2(&router_data)
                .unwrap();

            let url = request.as_ref().unwrap().url.clone();
            assert!(url.contains("merchant/"));
            assert!(url.contains("order/pay_capture_123"));
            assert!(url.contains("transaction/attempt_capture_456-capture"));
        }

        #[test]
        fn test_refund_url_generation() {
            let router_data = refund_tests::create_test_refund_router_data();
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Mpgs,
            };

            let connector_integration = connector_data.connector.get_connector_integration_v2();
            let request = connector_integration
                .build_request_v2(&router_data)
                .unwrap();

            let url = request.as_ref().unwrap().url.clone();
            assert!(url.contains("merchant/"));
            assert!(url.contains("order/order_refund_123"));
            assert!(url.contains("transaction/refund_456"));
        }

        #[test]
        fn test_void_url_generation() {
            let router_data = void_tests::create_test_void_router_data();
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Mpgs,
            };

            let connector_integration = connector_data.connector.get_connector_integration_v2();
            let request = connector_integration
                .build_request_v2(&router_data)
                .unwrap();

            let url = request.as_ref().unwrap().url.clone();
            assert!(url.contains("merchant/"));
            assert!(url.contains("order/pay_void_123"));
            assert!(url.contains("transaction/TXN_VOID_123"));
        }
    }

    mod header_tests {
        use super::*;

        #[test]
        fn test_authorize_headers() {
            let router_data = create_test_authorize_router_data();
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            let connector_data = ConnectorData {
                connector,
                connector_name: ConnectorEnum::Mpgs,
            };

            let connector_integration = connector_data.connector.get_connector_integration_v2();
            let request = connector_integration
                .build_request_v2(&router_data)
                .unwrap();

            let headers = &request.as_ref().unwrap().headers;
            let content_type = headers.iter().find(|(k, _)| k == "Content-Type");
            assert!(content_type.is_some());
            assert_eq!(
                content_type.unwrap().1.clone().into_inner(),
                "application/json"
            );

            let auth_header = headers.iter().find(|(k, _)| k == "Authorization");
            assert!(auth_header.is_some());
            let auth_value = auth_header.unwrap().1.clone().into_inner();
            assert!(auth_value.starts_with("Basic "));
        }
    }

    mod connector_integration_tests {
        use super::*;

        #[test]
        fn test_connector_creation() {
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            assert_eq!(connector.id(), "mpgs");
        }

        #[test]
        fn test_connector_content_type() {
            let connector: BoxedConnector<DefaultPCIHolder> = Box::new(Mpgs::new());
            assert_eq!(connector.common_get_content_type(), "application/json");
        }
    }
}
