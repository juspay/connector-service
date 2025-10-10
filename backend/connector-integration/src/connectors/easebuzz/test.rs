use std::str::FromStr;

use common_enums::{
    AttemptStatus, Currency, PaymentMethod, PaymentMethodType, UpiPaymentMethod,
};
use common_utils::{
    pii::{Email, Phone},
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    payment_method_data::{PaymentMethodData, UpiData},
    router_data_v2::{PaymentAmount, RouterDataV2},
    types::{PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData},
};
use hyperswitch_domain_models::router_data_v2::{PaymentFlowData, PaymentIntentData};
use masking::{ExposeInterface, Secret};
use rust_decimal::Decimal;

use crate::{
    connectors::easebuzz::{
        transformers::{EaseBuzzSeamlessTxnRequest, EaseBuzzTxnSyncRequest, EaseBuzzRefundRequest, EaseBuzzRefundSyncRequest},
        EaseBuzz,
    },
    services,
    types::{self, api, ConnectorAuthType},
};

#[test]
fn test_easebuzz_seamless_txn_request_upi_intent() {
    let router_data = get_authorize_router_data(UpiPaymentMethod::Intent);
    let request = EaseBuzzSeamlessTxnRequest::try_from(router_data).unwrap();

    assert_eq!(request.txnid, "test_payment_123");
    assert_eq!(request.amount, "10000");
    assert_eq!(request.payment_source, "upi");
    assert_eq!(request.upi_intent, Some("intent".to_string()));
    assert_eq!(request.upi_vpa, None);
    assert!(request.hash.len() > 0);
}

#[test]
fn test_easebuzz_seamless_txn_request_upi_collect() {
    let router_data = get_authorize_router_data(UpiPaymentMethod::Collect);
    let request = EaseBuzzSeamlessTxnRequest::try_from(router_data).unwrap();

    assert_eq!(request.txnid, "test_payment_123");
    assert_eq!(request.amount, "10000");
    assert_eq!(request.payment_source, "upi");
    assert_eq!(request.upi_intent, None);
    assert_eq!(request.upi_vpa, Some("test@upi".to_string()));
    assert!(request.hash.len() > 0);
}

#[test]
fn test_easebuzz_txn_sync_request() {
    let router_data = get_psync_router_data();
    let request = EaseBuzzTxnSyncRequest::try_from(router_data).unwrap();

    assert_eq!(request.txnid, "easebuzz_txn_456");
    assert_eq!(request.amount, "10000");
    assert_eq!(request.email, "test@example.com");
    assert_eq!(request.phone, "9999999999");
    assert!(request.hash.len() > 0);
}

#[test]
fn test_easebuzz_refund_request() {
    let router_data = get_refund_router_data();
    let request = EaseBuzzRefundRequest::try_from(router_data).unwrap();

    assert_eq!(request.txnid, "easebuzz_txn_456");
    assert_eq!(request.refund_amount, "5000");
    assert_eq!(request.refund_reason, "Customer requested refund");
    assert!(request.hash.len() > 0);
}

#[test]
fn test_easebuzz_refund_sync_request() {
    let router_data = get_rsync_router_data();
    let request = EaseBuzzRefundSyncRequest::try_from(router_data).unwrap();

    assert_eq!(request.easebuzz_id, "easebuzz_txn_456");
    assert_eq!(request.merchant_refund_id, "refund_789");
    assert!(request.hash.len() > 0);
}

fn get_authorize_router_data(upi_method: UpiPaymentMethod) -> RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<PaymentMethodData>, PaymentsResponseData> {
    let payment_method_data = PaymentMethodData::Upi(UpiData {
        upi_payment_method: upi_method,
        vpa: if upi_method == UpiPaymentMethod::Collect {
            Some(Secret::new("test@upi".to_string()))
        } else {
            None
        },
        ..Default::default()
    });

    RouterDataV2 {
        flow: Authorize,
        resource_common_data: PaymentFlowData {
            connector: types::Connectors::Easebuzz,
            payment_method: PaymentMethod::Upi,
            payment_method_type: PaymentMethodType::UpiIntent,
            connector_meta_data: None,
            merchant_connector_details: None,
            description: Some("Test payment".to_string()),
            connector_customer: None,
            connectors: types::Connectors {
                easebuzz: types::EasebuzzConnector {
                    base_url: "https://pay.easebuzz.in".to_string(),
                },
            },
        },
        request: PaymentsAuthorizeData {
            payment_id: "test_payment_123".to_string(),
            amount: PaymentAmount {
                amount: Decimal::from_str("100.00").unwrap(),
                currency: Currency::INR,
            },
            payment_method_data,
            email: Some(Email::from_str("test@example.com").unwrap()),
            phone: Some(Phone::from_str("9999999999").unwrap()),
            customer_name: Some("Test Customer".to_string()),
            return_url: Some("https://example.com/return".to_string()),
            ..Default::default()
        },
        response: PaymentsResponseData::default(),
        connector_auth_type: ConnectorAuthType::HeaderKey {
            api_key: Secret::new("test_api_key".to_string()),
            key1: Secret::new("test_merchant_key".to_string()),
        },
        test_mode: true,
        ..Default::default()
    }
}

fn get_psync_router_data() -> RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> {
    RouterDataV2 {
        flow: PSync,
        resource_common_data: PaymentFlowData {
            connector: types::Connectors::Easebuzz,
            payment_method: PaymentMethod::Upi,
            payment_method_type: PaymentMethodType::UpiIntent,
            connector_meta_data: None,
            merchant_connector_details: None,
            description: Some("Test payment".to_string()),
            connector_customer: None,
            connectors: types::Connectors {
                easebuzz: types::EasebuzzConnector {
                    base_url: "https://pay.easebuzz.in".to_string(),
                },
            },
        },
        request: PaymentsSyncData {
            payment_id: "test_payment_123".to_string(),
            connector_transaction_id: Some("easebuzz_txn_456".to_string()),
            amount: PaymentAmount {
                amount: Decimal::from_str("100.00").unwrap(),
                currency: Currency::INR,
            },
            email: Some(Email::from_str("test@example.com").unwrap()),
            phone: Some(Phone::from_str("9999999999").unwrap()),
            ..Default::default()
        },
        response: PaymentsResponseData::default(),
        connector_auth_type: ConnectorAuthType::HeaderKey {
            api_key: Secret::new("test_api_key".to_string()),
            key1: Secret::new("test_merchant_key".to_string()),
        },
        test_mode: true,
        ..Default::default()
    }
}

fn get_refund_router_data() -> RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> {
    RouterDataV2 {
        flow: Refund,
        resource_common_data: RefundFlowData {
            connector: types::Connectors::Easebuzz,
            payment_method: PaymentMethod::Upi,
            payment_method_type: PaymentMethodType::UpiIntent,
            connector_meta_data: None,
            merchant_connector_details: None,
            description: Some("Test refund".to_string()),
            connector_customer: None,
            connectors: types::Connectors {
                easebuzz: types::EasebuzzConnector {
                    base_url: "https://pay.easebuzz.in".to_string(),
                },
            },
        },
        request: RefundsData {
            refund_id: "refund_789".to_string(),
            connector_transaction_id: Some("easebuzz_txn_456".to_string()),
            refund_amount: PaymentAmount {
                amount: Decimal::from_str("50.00").unwrap(),
                currency: Currency::INR,
            },
            refund_reason: Some("Customer requested refund".to_string()),
            ..Default::default()
        },
        response: RefundsResponseData::default(),
        connector_auth_type: ConnectorAuthType::HeaderKey {
            api_key: Secret::new("test_api_key".to_string()),
            key1: Secret::new("test_merchant_key".to_string()),
        },
        test_mode: true,
        ..Default::default()
    }
}

fn get_rsync_router_data() -> RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> {
    RouterDataV2 {
        flow: RSync,
        resource_common_data: RefundFlowData {
            connector: types::Connectors::Easebuzz,
            payment_method: PaymentMethod::Upi,
            payment_method_type: PaymentMethodType::UpiIntent,
            connector_meta_data: None,
            merchant_connector_details: None,
            description: Some("Test refund sync".to_string()),
            connector_customer: None,
            connectors: types::Connectors {
                easebuzz: types::EasebuzzConnector {
                    base_url: "https://pay.easebuzz.in".to_string(),
                },
            },
        },
        request: RefundSyncData {
            refund_id: "refund_789".to_string(),
            connector_transaction_id: Some("easebuzz_txn_456".to_string()),
            amount: PaymentAmount {
                amount: Decimal::from_str("50.00").unwrap(),
                currency: Currency::INR,
            },
            ..Default::default()
        },
        response: RefundsResponseData::default(),
        connector_auth_type: ConnectorAuthType::HeaderKey {
            api_key: Secret::new("test_api_key".to_string()),
            key1: Secret::new("test_merchant_key".to_string()),
        },
        test_mode: true,
        ..Default::default()
    }
}