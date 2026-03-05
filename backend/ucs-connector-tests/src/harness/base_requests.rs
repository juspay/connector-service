use std::str::FromStr;

use cards::CardNumber;
use grpc_api_types::payments::{
    identifier::IdType, payment_method, Address, AuthenticationType, BrowserInformation,
    CaptureMethod, CardDetails, CountryAlpha2, Currency, CustomerServiceCreateRequest, Identifier,
    PaymentAddress, PaymentMethod, PaymentServiceAuthorizeRequest, PaymentServiceCaptureRequest,
    PaymentServiceGetRequest, PaymentServiceRefundRequest, PaymentServiceVoidRequest,
};
use hyperswitch_masking::Secret;

use crate::harness::generators::GeneratedInputVariant;

const DEFAULT_CARD_NUMBER: &str = "5123456789012346";
const DEFAULT_CARD_EXP_MONTH: &str = "12";
const DEFAULT_CARD_EXP_YEAR: &str = "2050";
const DEFAULT_CARD_CVC: &str = "123";
const DEFAULT_CARD_HOLDER: &str = "Ucs Test Customer";
const AUTHNET_BASE64_METADATA: &str =
    "eyJ1c2VyRmllbGRzIjp7Ik1lcmNoYW50RGVmaW5lZEZpZWxkTmFtZTEiOiJNZXJjaGFudERlZmluZWRGaWVsZFZhbHVlMSIsImZhdm9yaXRlX2NvbG9yIjoiYmx1ZSJ9fQ==";

fn id(id: String) -> Identifier {
    Identifier {
        id_type: Some(IdType::Id(id)),
    }
}

fn default_browser_info() -> BrowserInformation {
    BrowserInformation {
        color_depth: Some(24),
        java_enabled: Some(false),
        screen_height: Some(1080),
        screen_width: Some(1920),
        user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string()),
        accept_header: Some(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        ),
        java_script_enabled: Some(false),
        language: Some("en-US".to_string()),
        referer: None,
        ip_address: Some("127.0.0.1".to_string().into()),
        os_type: None,
        os_version: None,
        device_model: None,
        accept_language: Some("en-US".to_string()),
        time_zone_offset_minutes: Some(330),
    }
}

pub fn card_details(card_number: &str) -> CardDetails {
    CardDetails {
        card_number: Some(CardNumber::from_str(card_number).expect("valid card number for test")),
        card_exp_month: Some(Secret::new(DEFAULT_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(DEFAULT_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(DEFAULT_CARD_CVC.to_string())),
        card_holder_name: Some(Secret::new(DEFAULT_CARD_HOLDER.to_string())),
        card_issuer: None,
        card_network: Some(2),
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    }
}

pub fn base_authorize_request(case: &GeneratedInputVariant) -> PaymentServiceAuthorizeRequest {
    base_authorize_request_for_connector("authorizedotnet", case)
}

pub fn base_authorize_request_for_connector(
    connector: &str,
    case: &GeneratedInputVariant,
) -> PaymentServiceAuthorizeRequest {
    let metadata = match connector {
        "authorizedotnet" => {
            let mut metadata_map = std::collections::HashMap::new();
            metadata_map.insert("metadata".to_string(), AUTHNET_BASE64_METADATA.to_string());
            let metadata_json =
                serde_json::to_string(&metadata_map).expect("authorize metadata should serialize");
            Some(Secret::new(metadata_json))
        }
        "cybersource" => Some(Secret::new("{}".to_string())),
        _ => None,
    };

    PaymentServiceAuthorizeRequest {
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: case.amount_minor,
            currency: i32::from(Currency::Usd),
        }),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(card_details(
                DEFAULT_CARD_NUMBER,
            ))),
        }),
        return_url: Some("https://example.com/return".to_string()),
        webhook_url: Some("https://example.com/webhook".to_string()),
        customer: Some(grpc_api_types::payments::Customer {
            email: Some(case.email.clone().into()),
            name: None,
            id: Some("ucs_connector_tests".to_string()),
            connector_customer_id: None,
            phone_number: None,
        }),
        address: Some(PaymentAddress {
            billing_address: Some(Address {
                first_name: Some(case.first_name.clone().into()),
                last_name: Some(case.last_name.clone().into()),
                email: Some(case.email.clone().into()),
                line1: Some(case.line1.clone().into()),
                city: Some(case.city.clone().into()),
                state: Some("TX".to_string().into()),
                zip_code: Some(case.zip_code.clone().into()),
                country_alpha2_code: Some(i32::from(CountryAlpha2::Us)),
                phone_number: None,
                phone_country_code: None,
                line2: None,
                line3: None,
            }),
            shipping_address: None,
        }),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        merchant_transaction_id: Some(id(case.merchant_txn_id.clone())),
        enrolled_for_3ds: Some(false),
        request_incremental_authorization: Some(false),
        capture_method: Some(i32::from(CaptureMethod::Automatic)),
        browser_info: Some(default_browser_info()),
        metadata,
        ..Default::default()
    }
}

pub fn capture_request(transaction_id: &str, amount_minor: i64) -> PaymentServiceCaptureRequest {
    capture_request_for_connector("authorizedotnet", transaction_id, amount_minor)
}

pub fn capture_request_for_connector(
    connector: &str,
    transaction_id: &str,
    amount_minor: i64,
) -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        connector_transaction_id: Some(id(transaction_id.to_string())),
        amount_to_capture: Some(grpc_api_types::payments::Money {
            minor_amount: amount_minor,
            currency: i32::from(Currency::Usd),
        }),
        metadata: if connector == "cybersource" {
            Some(Secret::new("{}".to_string()))
        } else {
            None
        },
        ..Default::default()
    }
}

pub fn get_request(transaction_id: &str, amount_minor: i64) -> PaymentServiceGetRequest {
    get_request_for_connector("authorizedotnet", transaction_id, amount_minor)
}

pub fn get_request_for_connector(
    connector: &str,
    transaction_id: &str,
    amount_minor: i64,
) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        connector_transaction_id: Some(id(transaction_id.to_string())),
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: amount_minor,
            currency: i32::from(Currency::Usd),
        }),
        metadata: if connector == "cybersource" {
            Some(Secret::new("{}".to_string()))
        } else {
            None
        },
        ..Default::default()
    }
}

pub fn void_request(transaction_id: &str, amount_minor: i64) -> PaymentServiceVoidRequest {
    void_request_for_connector("authorizedotnet", transaction_id, amount_minor)
}

pub fn void_request_for_connector(
    connector: &str,
    transaction_id: &str,
    amount_minor: i64,
) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        connector_transaction_id: Some(id(transaction_id.to_string())),
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: amount_minor,
            currency: i32::from(Currency::Usd),
        }),
        merchant_void_id: Some(id(format!("void_{transaction_id}"))),
        cancellation_reason: Some("requested_by_customer".to_string()),
        metadata: if connector == "cybersource" {
            Some(Secret::new("{}".to_string()))
        } else {
            None
        },
        ..Default::default()
    }
}

pub fn customer_create_request(
    merchant_customer_id: &str,
    case: &GeneratedInputVariant,
) -> CustomerServiceCreateRequest {
    CustomerServiceCreateRequest {
        merchant_customer_id: Some(id(merchant_customer_id.to_string())),
        customer_name: Some(format!("{} {}", case.first_name, case.last_name)),
        email: Some(case.email.clone().into()),
        phone_number: None,
        address: Some(PaymentAddress {
            billing_address: Some(Address {
                first_name: Some(case.first_name.clone().into()),
                last_name: Some(case.last_name.clone().into()),
                email: Some(case.email.clone().into()),
                line1: Some(case.line1.clone().into()),
                city: Some(case.city.clone().into()),
                state: Some("TX".to_string().into()),
                zip_code: Some(case.zip_code.clone().into()),
                country_alpha2_code: Some(i32::from(CountryAlpha2::Us)),
                phone_number: None,
                phone_country_code: None,
                line2: None,
                line3: None,
            }),
            shipping_address: None,
        }),
        metadata: None,
        connector_feature_data: None,
        test_mode: Some(true),
    }
}

pub fn refund_request(
    transaction_id: &str,
    merchant_refund_id: &str,
    amount_minor: i64,
    customer_id: Option<String>,
) -> PaymentServiceRefundRequest {
    refund_request_for_connector(
        "authorizedotnet",
        transaction_id,
        merchant_refund_id,
        amount_minor,
        customer_id,
    )
}

pub fn refund_request_for_connector(
    connector: &str,
    transaction_id: &str,
    merchant_refund_id: &str,
    amount_minor: i64,
    customer_id: Option<String>,
) -> PaymentServiceRefundRequest {
    let connector_feature_data = if connector == "authorizedotnet" {
        let connector_feature_data = serde_json::json!({
            "creditCard": {
                "cardNumber": DEFAULT_CARD_NUMBER,
                "expirationDate": format!("{}-{}", DEFAULT_CARD_EXP_YEAR, DEFAULT_CARD_EXP_MONTH),
            }
        });
        let connector_feature_data_json = serde_json::to_string(&connector_feature_data)
            .expect("refund connector_feature_data should serialize");
        Some(Secret::new(connector_feature_data_json))
    } else {
        None
    };

    PaymentServiceRefundRequest {
        merchant_refund_id: Some(id(merchant_refund_id.to_string())),
        connector_transaction_id: Some(id(transaction_id.to_string())),
        payment_amount: amount_minor,
        refund_amount: Some(grpc_api_types::payments::Money {
            minor_amount: amount_minor,
            currency: i32::from(Currency::Usd),
        }),
        reason: Some(if connector == "adyen" {
            "CUSTOMER REQUEST".to_string()
        } else {
            "UCS connector test refund".to_string()
        }),
        webhook_url: None,
        merchant_account_id: None,
        capture_method: None,
        metadata: if connector == "cybersource" {
            Some(Secret::new("{}".to_string()))
        } else {
            None
        },
        refund_metadata: None,
        connector_feature_data,
        browser_info: None,
        state: None,
        test_mode: Some(true),
        payment_method_type: None,
        customer_id,
    }
}
