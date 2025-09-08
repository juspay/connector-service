use crate::connector::{{connector_camel}};
use crate::types::ResponseRouterData;
use domain_types::{
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData},
    payment_method_data::{CardNumber, CardSecurityCode, PaymentMethodData},
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::Secret;
use serial_test::serial;

#[actix_rt::test]
#[serial]
async fn should_only_authorize_payment() {
    let response = {{connector_camel}}::authorize_payment(None, get_default_payment_info(), None)
        .await
        .expect("Authorize payment response");
    assert_eq!(response.status, common_enums::AttemptStatus::Authorized);
}

#[actix_rt::test]
#[serial]
async fn should_authorize_and_capture_payment() {
    let response = {{connector_camel}}::authorize_and_capture_payment(
        None,
        get_default_payment_info(),
        None,
    )
    .await
    .expect("Authorize and capture payment response");
    assert_eq!(response.status, common_enums::AttemptStatus::Charged);
}

#[actix_rt::test]
#[serial]
async fn should_sync_authorized_payment() {
    let authorize_response = {{connector_camel}}::authorize_payment(None, get_default_payment_info(), None)
        .await
        .expect("Authorize payment response");
    assert_eq!(authorize_response.status, common_enums::AttemptStatus::Authorized);
    let sync_response = {{connector_camel}}::sync_payment(
        None,
        get_default_payment_sync_info(&authorize_response),
        None,
    )
    .await
    .expect("Sync payment response");
    assert_eq!(sync_response.status, common_enums::AttemptStatus::Authorized);
}

#[actix_rt::test]
#[serial]
async fn should_capture_authorized_payment() {
    let authorize_response = {{connector_camel}}::authorize_payment(None, get_default_payment_info(), None)
        .await
        .expect("Authorize payment response");
    assert_eq!(authorize_response.status, common_enums::AttemptStatus::Authorized);
    
    let capture_response = {{connector_camel}}::capture_payment(
        authorize_response.connector_transaction_id.unwrap(),
        None,
        get_default_capture_info(),
    )
    .await
    .expect("Capture payment response");
    assert_eq!(capture_response.status, common_enums::AttemptStatus::Charged);
}

#[actix_rt::test]
#[serial]
async fn should_void_authorized_payment() {
    let authorize_response = {{connector_camel}}::authorize_payment(None, get_default_payment_info(), None)
        .await
        .expect("Authorize payment response");
    assert_eq!(authorize_response.status, common_enums::AttemptStatus::Authorized);
    
    let void_response = {{connector_camel}}::void_payment(
        authorize_response.connector_transaction_id.unwrap(),
        None,
        get_default_void_info(),
    )
    .await
    .expect("Void payment response");
    assert_eq!(void_response.status, common_enums::AttemptStatus::Voided);
}

#[actix_rt::test]
#[serial]
async fn should_refund_manually_captured_payment() {
    let capture_response = {{connector_camel}}::authorize_and_capture_payment(
        None,
        get_default_payment_info(),
        None,
    )
    .await
    .expect("Capture payment response");
    assert_eq!(capture_response.status, common_enums::AttemptStatus::Charged);
    
    let refund_response = {{connector_camel}}::refund_payment(
        capture_response.connector_transaction_id.unwrap(),
        None,
        get_default_refund_info(),
    )
    .await
    .expect("Refund payment response");
    assert_eq!(
        refund_response.response.unwrap().refund_status,
        common_enums::RefundStatus::Success,
    );
}

#[actix_rt::test]
#[serial]
async fn should_sync_refund() {
    let capture_response = {{connector_camel}}::authorize_and_capture_payment(
        None,
        get_default_payment_info(),
        None,
    )
    .await
    .expect("Capture payment response");
    assert_eq!(capture_response.status, common_enums::AttemptStatus::Charged);
    
    let refund_response = {{connector_camel}}::refund_payment(
        capture_response.connector_transaction_id.unwrap(),
        None,
        get_default_refund_info(),
    )
    .await
    .expect("Refund payment response");
    assert_eq!(
        refund_response.response.unwrap().refund_status,
        common_enums::RefundStatus::Success,
    );
    
    let sync_response = {{connector_camel}}::sync_refund(
        refund_response.response.unwrap().connector_refund_id,
        get_default_refund_sync_info(),
    )
    .await
    .expect("Sync refund response");
    assert_eq!(
        sync_response.response.unwrap().refund_status,
        common_enums::RefundStatus::Success,
    );
}

fn get_default_payment_info() -> PaymentInfo {
    PaymentInfo {
        address: Some(Address {
            line1: Some(Secret::new("line1".to_string())),
            line2: Some(Secret::new("line2".to_string())),
            line3: Some(Secret::new("line3".to_string())),
            city: Some("city".to_string()),
            zip: Some(Secret::new("zip".to_string())),
            country: Some(api_models::enums::CountryAlpha2::US),
            first_name: Some(Secret::new("John".to_string())),
            last_name: Some(Secret::new("Doe".to_string())),
        }),
        currency: Some(common_enums::Currency::USD),
        amount: Some(PaymentAmount::from(MinorUnit::new(100))),
        payment_method_data: Some(PaymentMethodData::Card(Card {
            card_number: CardNumber::from_str("4242424242424242").unwrap(),
            card_exp_month: Secret::new("10".to_string()),
            card_exp_year: Secret::new("2025".to_string()),
            card_cvc: Some(CardSecurityCode::from_str("123").unwrap()),
            card_holder_name: Some(Secret::new("John Doe".to_string())),
        })),
        ..Default::default()
    }
}

fn get_default_payment_sync_info(response: &PaymentResponse) -> PaymentSyncInfo {
    PaymentSyncInfo {
        connector_transaction_id: response.connector_transaction_id.clone(),
        ..Default::default()
    }
}

fn get_default_capture_info() -> PaymentsCaptureData {
    PaymentsCaptureData {
        amount_to_capture: MinorUnit::new(100),
        currency: common_enums::Currency::USD,
        connector_transaction_id: String::new(),
        ..Default::default()
    }
}

fn get_default_void_info() -> PaymentsCancelData {
    PaymentsCancelData {
        connector_transaction_id: String::new(),
        cancellation_reason: Some("Customer Request".to_string()),
        ..Default::default()
    }
}

fn get_default_refund_info() -> RefundsData {
    RefundsData {
        refund_amount: MinorUnit::new(100),
        currency: common_enums::Currency::USD,
        payment_amount: MinorUnit::new(100),
        refund_id: uuid::Uuid::new_v4().to_string(),
        connector_transaction_id: String::new(),
        reason: Some("Customer Request".to_string()),
        ..Default::default()
    }
}

fn get_default_refund_sync_info() -> RefundSyncData {
    RefundSyncData {
        connector_refund_id: String::new(),
        ..Default::default()
    }
}