//! Shared builders for connector transformer unit tests.

use domain_types::{
    connector_types::PaymentFlowData,
    payment_address::{Address, AddressDetails, PaymentAddress, PhoneDetails},
    types::Connectors,
};
use hyperswitch_masking::Secret;

/// A complete US billing address (Jane Doe, New York) with a phone number.
pub(crate) fn billing_address() -> Address {
    Address {
        address: Some(AddressDetails {
            first_name: Some(Secret::new("Jane".to_string())),
            last_name: Some(Secret::new("Doe".to_string())),
            line1: Some(Secret::new("1 Billing St".to_string())),
            line2: None,
            line3: None,
            city: Some(Secret::new("New York".to_string())),
            state: Some(Secret::new("NY".to_string())),
            zip: Some(Secret::new("10001".to_string())),
            country: Some(common_enums::CountryAlpha2::US),
            origin_zip: None,
        }),
        phone: Some(PhoneDetails {
            number: Some(Secret::new("2125550100".to_string())),
            country_code: Some("+1".to_string()),
        }),
        email: None,
    }
}

/// Payment flow data whose only meaningful content is the given billing address.
pub(crate) fn payment_flow_data(billing: Option<Address>) -> PaymentFlowData {
    PaymentFlowData {
        merchant_id: common_utils::id_type::MerchantId::default(),
        customer_id: None,
        connector_customer: None,
        payment_id: "pay_test".to_string(),
        attempt_id: "attempt_test".to_string(),
        status: common_enums::AttemptStatus::Pending,
        payment_method: common_enums::PaymentMethod::Card,
        payment_method_type: None,
        description: None,
        return_url: None,
        address: PaymentAddress::new(None, billing, None, None),
        auth_type: common_enums::AuthenticationType::NoThreeDs,
        connector_feature_data: None,
        amount_captured: None,
        amount_capturable: None,
        amount: None,
        access_token: None,
        session_token: None,
        reference_id: None,
        connector_order_id: None,
        preprocessing_id: None,
        connector_api_version: None,
        connector_request_reference_id: "ref_test".to_string(),
        test_mode: None,
        connector_http_status_code: None,
        connector_response_headers: None,
        external_latency: None,
        connectors: Connectors::default().into(),
        raw_connector_response: None,
        typed_connector_response: None,
        raw_connector_request: None,
        typed_connector_request: None,
        vault_headers: None,
        connector_response: None,
        recurring_mandate_payment_data: None,
        order_details: None,
        amount_authorized: None,
        l2_l3_data: None,
        merchant_request_id: None,
        sender_payment_instrument_id: None,
        connector_returned_payment_method_details: None,
        settlement_status: None,
        raw_connector_status: None,
    }
}
