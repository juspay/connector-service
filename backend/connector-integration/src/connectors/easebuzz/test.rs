#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use common_enums::{
        AttemptStatus, Currency, PaymentMethod, PaymentMethodType, UpiPaymentMethod,
    };
    use common_utils::types::MinorUnit;
    use domain_types::{
        connector_flow::{Authorize, PSync, Refund, RSync},
        payment_method_data::{PaymentMethodData, UpiData},
        router_data_v2::{PaymentAmount, RouterDataV2},
        types::{PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData},
    };
    use error_stack::ResultExt;
    use hyperswitch_domain_models::router_data_v2::{PaymentFlowData, ResourceCommonData};
    use masking::{ExposeInterface, Secret};
    use serde_json::json;

    use super::*;
    use super::transformers::*;

#[test]
    fn test_easebuzz_seamless_txn_request_conversion() {
    let payment_data = PaymentsAuthorizeData {
        payment_id: "test_payment_123".to_string(),
        amount: PaymentAmount {
            value: 10000, // 100.00 INR in minor units
            currency: Currency::INR,
        },
        payment_method_data: PaymentMethodData::Upi(UpiData {
            upi_payment_method: UpiPaymentMethod::Intent,
            vpa: Secret::new("test@upi".to_string()),
        }),
        ..Default::default()
    };

    let router_data = RouterDataV2 {
        flow: Authorize,
        resource_common_data: PaymentFlowData {
            connector: "easebuzz".to_string(),
            ..Default::default()
        },
        request: payment_data,
        response: Ok(PaymentsResponseData::default()),
        connector_auth_type: domain_types::router_data::ConnectorAuthType::HeaderKey {
            api_key: Secret::new("test_api_key".to_string()),
            key1: Secret::new("test_merchant_key".to_string()),
        },
        test_mode: true,
        ..Default::default()
    };

    let result = EaseBuzzSeamlessTxnRequest::try_from(router_data);
    assert!(result.is_ok());
    
    let request = result.unwrap();
    assert_eq!(request.txnid, "test_payment_123");
    assert_eq!(request.amount, "100.00");
    assert_eq!(request.payment_source, "upi");
    assert_eq!(request.upi_intent, Some("intent".to_string()));
    assert_eq!(request.upi_vpa, None);
}

#[test]
    fn test_easebuzz_upi_collect_request() {
    let payment_data = PaymentsAuthorizeData {
        payment_id: "test_payment_456".to_string(),
        amount: PaymentAmount {
            value: 5000, // 50.00 INR in minor units
            currency: Currency::INR,
        },
        payment_method_data: PaymentMethodData::Upi(UpiData {
            upi_payment_method: UpiPaymentMethod::Collect,
            vpa: Secret::new("customer@bank".to_string()),
        }),
        ..Default::default()
    };

    let router_data = RouterDataV2 {
        flow: Authorize,
        resource_common_data: PaymentFlowData {
            connector: "easebuzz".to_string(),
            ..Default::default()
        },
        request: payment_data,
        response: Ok(PaymentsResponseData::default()),
        connector_auth_type: domain_types::router_data::ConnectorAuthType::HeaderKey {
            api_key: Secret::new("test_api_key".to_string()),
            key1: Secret::new("test_merchant_key".to_string()),
        },
        test_mode: true,
        ..Default::default()
    };

    let result = EaseBuzzSeamlessTxnRequest::try_from(router_data);
    assert!(result.is_ok());
    
    let request = result.unwrap();
    assert_eq!(request.txnid, "test_payment_456");
    assert_eq!(request.amount, "50.00");
    assert_eq!(request.payment_source, "upi");
    assert_eq!(request.upi_intent, None);
    assert_eq!(request.upi_vpa, Some("customer@bank".to_string()));
}

#[test]
    fn test_easebuzz_txn_sync_request() {
    let sync_data = PaymentsSyncData {
        connector_transaction_id: Some("easebuzz_txn_789".to_string()),
        amount: PaymentAmount {
            value: 15000, // 150.00 INR in minor units
            currency: Currency::INR,
        },
        ..Default::default()
    };

    let router_data = RouterDataV2 {
        flow: PSync,
        resource_common_data: PaymentFlowData {
            connector: "easebuzz".to_string(),
            ..Default::default()
        },
        request: sync_data,
        response: Ok(PaymentsResponseData::default()),
        connector_auth_type: domain_types::router_data::ConnectorAuthType::HeaderKey {
            api_key: Secret::new("test_api_key".to_string()),
            key1: Secret::new("test_merchant_key".to_string()),
        },
        test_mode: true,
        ..Default::default()
    };

    let result = EaseBuzzTxnSyncRequest::try_from(router_data);
    assert!(result.is_ok());
    
    let request = result.unwrap();
    assert_eq!(request.txnid, "easebuzz_txn_789");
    assert_eq!(request.amount, "150.00");
}

#[test]
    fn test_easebuzz_refund_request() {
    let refund_data = RefundsData {
        connector_transaction_id: Some("easebuzz_txn_123".to_string()),
        refund_amount: PaymentAmount {
            value: 5000, // 50.00 INR in minor units
            currency: Currency::INR,
        },
        refund_reason: Some("Customer requested refund".to_string()),
        ..Default::default()
    };

    let router_data = RouterDataV2 {
        flow: Refund,
        resource_common_data: RefundFlowData {
            connector: "easebuzz".to_string(),
            ..Default::default()
        },
        request: refund_data,
        response: Ok(RefundsResponseData::default()),
        connector_auth_type: domain_types::router_data::ConnectorAuthType::HeaderKey {
            api_key: Secret::new("test_api_key".to_string()),
            key1: Secret::new("test_merchant_key".to_string()),
        },
        test_mode: true,
        ..Default::default()
    };

    let result = EaseBuzzRefundRequest::try_from(router_data);
    assert!(result.is_ok());
    
    let request = result.unwrap();
    assert_eq!(request.txnid, "easebuzz_txn_123");
    assert_eq!(request.refund_amount, "50.00");
    assert_eq!(request.refund_reason, "Customer requested refund");
}

#[test]
    fn test_easebuzz_upi_intent_response_deserialization() {
    let response_json = json!({
        "status": true,
        "msg_desc": "Payment initiated successfully",
        "qr_link": "https://upi.qr.example.com/xyz123",
        "msg_title": "UPI Payment",
        "easebuzz_id": "ezb_123456"
    });

    let result: Result<EaseBuzzUpiIntentResponse, _> = serde_json::from_value(response_json);
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response.status, true);
    assert_eq!(response.msg_desc, "Payment initiated successfully");
    assert_eq!(response.qr_link, Some("https://upi.qr.example.com/xyz123".to_string()));
    assert_eq!(response.msg_title, "UPI Payment");
    assert_eq!(response.easebuzz_id, Some("ezb_123456".to_string()));
}

#[test]
    fn test_easebuzz_webhook_parsing() {
    let webhook_json = json!({
        "type": "payment",
        "status": "success",
        "txnid": "test_txn_123",
        "amount": "100.00",
        "easebuzz_id": "ezb_456789",
        "email": "customer@example.com",
        "phone": "9876543210"
    });

    let result: Result<EaseBuzzWebhookTypes, _> = serde_json::from_value(webhook_json);
    assert!(result.is_ok());
    
    let webhook = result.unwrap();
    match webhook {
        EaseBuzzWebhookTypes::Payment(payment) => {
            assert_eq!(payment.status, "success");
            assert_eq!(payment.txnid, "test_txn_123");
            assert_eq!(payment.easebuzz_id, "ezb_456789");
        }
        _ => panic!("Expected payment webhook"),
    }
}

#[test]
    fn test_easebuzz_refund_webhook_parsing() {
    let webhook_json = json!({
        "type": "refund",
        "easebuzz_id": "ezb_456789",
        "refund_id": "refund_123",
        "refund_status": "success",
        "refund_amount": "50.00",
        "merchant_refund_id": "merchant_ref_456"
    });

    let result: Result<EaseBuzzWebhookTypes, _> = serde_json::from_value(webhook_json);
    assert!(result.is_ok());
    
    let webhook = result.unwrap();
    match webhook {
        EaseBuzzWebhookTypes::Refund(refund) => {
            assert_eq!(refund.easebuzz_id, "ezb_456789");
            assert_eq!(refund.refund_id, "refund_123");
            assert_eq!(refund.refund_status, "success");
            assert_eq!(refund.refund_amount, "50.00");
            assert_eq!(refund.merchant_refund_id, "merchant_ref_456");
        }
        _ => panic!("Expected refund webhook"),
    }
}