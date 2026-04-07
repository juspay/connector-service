// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py stripe
//
// Stripe — all scenarios and flows in one file.
// Run a scenario:  cargo run --example stripe -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;

#[allow(dead_code)]
fn build_client() -> ConnectorClient {
    // Set connector_config to authenticate: use ConnectorSpecificConfig with your StripeConfig
    let config = ConnectorConfig {
        connector_config: None, // TODO: Some(ConnectorSpecificConfig { config: Some(...) })
        options: Some(SdkOptions {
            environment: Environment::Sandbox.into(),
        }),
    };
    ConnectorClient::new(config, None).unwrap()
}

// Scenario: One-step Payment (Authorize + Capture)
// Simple payment that authorizes and captures in one call. Use for immediate charges.
#[allow(dead_code)]
pub async fn process_checkout_autocapture(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client
        .authorize(
            serde_json::from_value(serde_json::json!({
                "merchant_transaction_id": "probe_txn_001",
                "amount": {
                    "minor_amount": 1000,
                    "currency": "USD",
                },
                "payment_method": {
                    "card": {
                        "card_number": "4111111111111111",
                        "card_exp_month": "03",
                        "card_exp_year": "2030",
                        "card_cvc": "737",
                        "card_holder_name": "John Doe",
                    },
                },
                "capture_method": "AUTOMATIC",
                "address": {
                    "billing_address": {
                    },
                },
                "auth_type": "NO_THREE_DS",
                "return_url": "https://example.com/return",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => {
            return Err(format!("Payment failed: {:?}", authorize_response.error).into())
        }
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _ => {}
    }

    Ok(format!(
        "Payment: {:?} — {}",
        authorize_response.status(),
        authorize_response
            .connector_transaction_id
            .as_deref()
            .unwrap_or("")
    ))
}

// Scenario: Card Payment (Authorize + Capture)
// Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.
#[allow(dead_code)]
pub async fn process_checkout_card(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client
        .authorize(
            serde_json::from_value(serde_json::json!({
                "merchant_transaction_id": "probe_txn_001",
                "amount": {
                    "minor_amount": 1000,
                    "currency": "USD",
                },
                "payment_method": {
                    "card": {
                        "card_number": "4111111111111111",
                        "card_exp_month": "03",
                        "card_exp_year": "2030",
                        "card_cvc": "737",
                        "card_holder_name": "John Doe",
                    },
                },
                "capture_method": "MANUAL",
                "address": {
                    "billing_address": {
                    },
                },
                "auth_type": "NO_THREE_DS",
                "return_url": "https://example.com/return",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => {
            return Err(format!("Payment failed: {:?}", authorize_response.error).into())
        }
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _ => {}
    }

    // Step 2: Capture — settle the reserved funds
    let capture_response = client
        .capture(
            serde_json::from_value(serde_json::json!({
                "merchant_capture_id": "probe_capture_001",
                "amount_to_capture": {
                    "minor_amount": 1000,
                    "currency": "USD",
                },
                "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;

    if capture_response.status() == PaymentStatus::Failure {
        return Err(format!("Capture failed: {:?}", capture_response.error).into());
    }

    Ok(format!(
        "Payment completed: {}",
        authorize_response
            .connector_transaction_id
            .as_deref()
            .unwrap_or("")
    ))
}

// Scenario: Refund
// Return funds to the customer for a completed payment.
#[allow(dead_code)]
pub async fn process_refund(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client
        .authorize(
            serde_json::from_value(serde_json::json!({
                "merchant_transaction_id": "probe_txn_001",
                "amount": {
                    "minor_amount": 1000,
                    "currency": "USD",
                },
                "payment_method": {
                    "card": {
                        "card_number": "4111111111111111",
                        "card_exp_month": "03",
                        "card_exp_year": "2030",
                        "card_cvc": "737",
                        "card_holder_name": "John Doe",
                    },
                },
                "capture_method": "AUTOMATIC",
                "address": {
                    "billing_address": {
                    },
                },
                "auth_type": "NO_THREE_DS",
                "return_url": "https://example.com/return",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => {
            return Err(format!("Payment failed: {:?}", authorize_response.error).into())
        }
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _ => {}
    }

    // Step 2: Refund — return funds to the customer
    let refund_response = client
        .refund(
            serde_json::from_value(serde_json::json!({
                "merchant_refund_id": "probe_refund_001",
                "payment_amount": 1000,
                "refund_amount": {
                    "minor_amount": 1000,
                    "currency": "USD",
                },
                "reason": "customer_request",
                "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;

    if refund_response.status() == RefundStatus::RefundFailure {
        return Err(format!("Refund failed: {:?}", refund_response.error).into());
    }

    Ok(format!("Refunded: {:?}", refund_response.status()))
}

// Scenario: Void Payment
// Cancel an authorized but not-yet-captured payment.
#[allow(dead_code)]
pub async fn process_void_payment(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client
        .authorize(
            serde_json::from_value(serde_json::json!({
                "merchant_transaction_id": "probe_txn_001",
                "amount": {
                    "minor_amount": 1000,
                    "currency": "USD",
                },
                "payment_method": {
                    "card": {
                        "card_number": "4111111111111111",
                        "card_exp_month": "03",
                        "card_exp_year": "2030",
                        "card_cvc": "737",
                        "card_holder_name": "John Doe",
                    },
                },
                "capture_method": "MANUAL",
                "address": {
                    "billing_address": {
                    },
                },
                "auth_type": "NO_THREE_DS",
                "return_url": "https://example.com/return",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => {
            return Err(format!("Payment failed: {:?}", authorize_response.error).into())
        }
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _ => {}
    }

    // Step 2: Void — release reserved funds (cancel authorization)
    let void_response = client
        .void(
            serde_json::from_value(serde_json::json!({
                "merchant_void_id": "probe_void_001",
                "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;

    Ok(format!("Voided: {:?}", void_response.status()))
}

// Scenario: Get Payment Status
// Retrieve current payment status from the connector.
#[allow(dead_code)]
pub async fn process_get_payment(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client
        .authorize(
            serde_json::from_value(serde_json::json!({
                "merchant_transaction_id": "probe_txn_001",
                "amount": {
                    "minor_amount": 1000,
                    "currency": "USD",
                },
                "payment_method": {
                    "card": {
                        "card_number": "4111111111111111",
                        "card_exp_month": "03",
                        "card_exp_year": "2030",
                        "card_cvc": "737",
                        "card_holder_name": "John Doe",
                    },
                },
                "capture_method": "MANUAL",
                "address": {
                    "billing_address": {
                    },
                },
                "auth_type": "NO_THREE_DS",
                "return_url": "https://example.com/return",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => {
            return Err(format!("Payment failed: {:?}", authorize_response.error).into())
        }
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _ => {}
    }

    // Step 2: Get — retrieve current payment status from the connector
    let get_response = client
        .get(
            serde_json::from_value(serde_json::json!({
                "merchant_transaction_id": "probe_merchant_txn_001",
                "amount": {
                    "minor_amount": 1000,
                    "currency": "USD",
                },
                "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;

    Ok(format!("Status: {:?}", get_response.status()))
}

// Flow: PaymentService.authorize (Card)
#[allow(dead_code)]
pub async fn authorize(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .authorize(
            serde_json::from_value(serde_json::json!({
            "merchant_transaction_id": "probe_txn_001",
            "amount": {
                "minor_amount": 1000,
                "currency": "USD",
            },
            "payment_method": {
                "card": {
                    "card_number": "4111111111111111",
                    "card_exp_month": "03",
                    "card_exp_year": "2030",
                    "card_cvc": "737",
                    "card_holder_name": "John Doe",
                },
            },
            "capture_method": "AUTOMATIC",
            "address": {
                "billing_address": {
                },
            },
            "auth_type": "NO_THREE_DS",
            "return_url": "https://example.com/return",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    match response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => {
            Err(format!("Authorize failed: {:?}", response.error).into())
        }
        PaymentStatus::Pending => Ok("pending — await webhook".to_string()),
        _ => Ok(format!(
            "Authorized: {}",
            response.connector_transaction_id.as_deref().unwrap_or("")
        )),
    }
}

// Flow: PaymentService.capture
#[allow(dead_code)]
pub async fn capture(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .capture(
            serde_json::from_value(serde_json::json!({
            "merchant_capture_id": "probe_capture_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "amount_to_capture": {
                "minor_amount": 1000,
                "currency": "USD",
            },
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.create_client_authentication_token
#[allow(dead_code)]
pub async fn create_client_authentication_token(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .create_client_authentication_token(
            serde_json::from_value(serde_json::json!({
            "merchant_client_session_id": "probe_sdk_session_001",
            "domain_context": {
                "payment": {
                    "amount": {
                        "minor_amount": 1000,
                        "currency": "USD",
                    },
                },
            },
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status_code))
}

// Flow: PaymentService.create_customer
#[allow(dead_code)]
pub async fn create_customer(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .create_customer(
            serde_json::from_value(serde_json::json!({
            "merchant_customer_id": "cust_probe_123",
            "customer_name": "John Doe",
            "email": "test@example.com",
            "phone_number": "4155552671",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("customer_id: {}", response.connector_customer_id))
}

// Flow: PaymentService.get
#[allow(dead_code)]
pub async fn get(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .get(
            serde_json::from_value(serde_json::json!({
            "merchant_transaction_id": "probe_merchant_txn_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "amount": {
                "minor_amount": 1000,
                "currency": "USD",
            },
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.incremental_authorization
#[allow(dead_code)]
pub async fn incremental_authorization(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .incremental_authorization(
            serde_json::from_value(serde_json::json!({
            "merchant_authorization_id": "probe_auth_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "amount": {
                "minor_amount": 1100,
                "currency": "USD",
            },
            "reason": "incremental_auth_probe",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.proxy_authorize
#[allow(dead_code)]
pub async fn proxy_authorize(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .proxy_authorize(
            serde_json::from_value(serde_json::json!({
            "merchant_transaction_id": "probe_proxy_txn_001",
            "amount": {
                "minor_amount": 1000,
                "currency": "USD",
            },
            "card_proxy": {
                "card_number": "4111111111111111",
                "card_exp_month": "03",
                "card_exp_year": "2030",
                "card_cvc": "123",
                "card_holder_name": "John Doe",
            },
            "address": {
                "billing_address": {
                },
            },
            "capture_method": "AUTOMATIC",
            "auth_type": "NO_THREE_DS",
            "return_url": "https://example.com/return",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.proxy_setup_recurring
#[allow(dead_code)]
pub async fn proxy_setup_recurring(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .proxy_setup_recurring(
            serde_json::from_value(serde_json::json!({
            "merchant_recurring_payment_id": "probe_proxy_mandate_001",
            "amount": {
                "minor_amount": 0,
                "currency": "USD",
            },
            "card_proxy": {
                "card_number": "4111111111111111",
                "card_exp_month": "03",
                "card_exp_year": "2030",
                "card_cvc": "123",
                "card_holder_name": "John Doe",
            },
            "address": {
                "billing_address": {
                },
            },
            "customer_acceptance": {
                "acceptance_type": "OFFLINE",
                "accepted_at": 0,
            },
            "auth_type": "NO_THREE_DS",
            "setup_future_usage": "OFF_SESSION",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.recurring_charge
#[allow(dead_code)]
pub async fn recurring_charge(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .recurring_charge(
            serde_json::from_value(serde_json::json!({
            "connector_recurring_payment_id": {
                "mandate_id_type": {
                    "connector_mandate_id": {
                        "connector_mandate_id": "probe-mandate-123",
                    },
                },
            },
            "amount": {
                "minor_amount": 1000,
                "currency": "USD",
            },
            "payment_method": {
                "token": {
                    "token": "probe_pm_token",
                },
            },
            "return_url": "https://example.com/recurring-return",
            "connector_customer_id": "cust_probe_123",
            "payment_method_type": "PAY_PAL",
            "off_session": true,
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.refund
#[allow(dead_code)]
pub async fn refund(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .refund(
            serde_json::from_value(serde_json::json!({
            "merchant_refund_id": "probe_refund_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "payment_amount": 1000,
            "refund_amount": {
                "minor_amount": 1000,
                "currency": "USD",
            },
            "reason": "customer_request",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.refund_get
#[allow(dead_code)]
pub async fn refund_get(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .refund_get(
            serde_json::from_value(serde_json::json!({
            "merchant_refund_id": "probe_refund_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "refund_id": "probe_refund_id_001",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.setup_recurring
#[allow(dead_code)]
pub async fn setup_recurring(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .setup_recurring(
            serde_json::from_value(serde_json::json!({
            "merchant_recurring_payment_id": "probe_mandate_001",
            "amount": {
                "minor_amount": 0,
                "currency": "USD",
            },
            "payment_method": {
                "card": {
                    "card_number": "4111111111111111",
                    "card_exp_month": "03",
                    "card_exp_year": "2030",
                    "card_cvc": "737",
                    "card_holder_name": "John Doe",
                },
            },
            "address": {
                "billing_address": {
                },
            },
            "auth_type": "NO_THREE_DS",
            "enrolled_for_3ds": false,
            "return_url": "https://example.com/mandate-return",
            "setup_future_usage": "OFF_SESSION",
            "request_incremental_authorization": false,
            "customer_acceptance": {
                "acceptance_type": "OFFLINE",
                "accepted_at": 0,
            },
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    if response.status() == PaymentStatus::Failure {
        return Err(format!("Setup failed: {:?}", response.error).into());
    }
    Ok(format!(
        "Mandate: {}",
        response
            .connector_recurring_payment_id
            .as_deref()
            .unwrap_or("")
    ))
}

// Flow: PaymentService.tokenize
#[allow(dead_code)]
pub async fn tokenize(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .tokenize(
            serde_json::from_value(serde_json::json!({
            "amount": {
                "minor_amount": 1000,
                "currency": "USD",
            },
            "payment_method": {
                "card": {
                    "card_number": "4111111111111111",
                    "card_exp_month": "03",
                    "card_exp_year": "2030",
                    "card_cvc": "737",
                    "card_holder_name": "John Doe",
                },
            },
            "address": {
                "billing_address": {
                },
            },
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("token: {}", response.payment_method_token))
}

// Flow: PaymentService.void
#[allow(dead_code)]
pub async fn void(
    client: &ConnectorClient,
    _merchant_transaction_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .void(
            serde_json::from_value(serde_json::json!({
            "merchant_void_id": "probe_void_001",
            "connector_transaction_id": "probe_connector_txn_001",
            }))
            .unwrap_or_default(),
            &HashMap::new(),
            None,
        )
        .await?;
    Ok(format!("status: {:?}", response.status()))
}

#[allow(dead_code)]
#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "process_checkout_autocapture".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "process_checkout_autocapture" => process_checkout_autocapture(&client, "order_001").await,
        "process_checkout_card" => process_checkout_card(&client, "order_001").await,
        "process_refund" => process_refund(&client, "order_001").await,
        "process_void_payment" => process_void_payment(&client, "order_001").await,
        "process_get_payment" => process_get_payment(&client, "order_001").await,
        "authorize" => authorize(&client, "order_001").await,
        "capture" => capture(&client, "order_001").await,
        "create_client_authentication_token" => {
            create_client_authentication_token(&client, "order_001").await
        }
        "create_customer" => create_customer(&client, "order_001").await,
        "get" => get(&client, "order_001").await,
        "incremental_authorization" => incremental_authorization(&client, "order_001").await,
        "proxy_authorize" => proxy_authorize(&client, "order_001").await,
        "proxy_setup_recurring" => proxy_setup_recurring(&client, "order_001").await,
        "recurring_charge" => recurring_charge(&client, "order_001").await,
        "refund" => refund(&client, "order_001").await,
        "refund_get" => refund_get(&client, "order_001").await,
        "setup_recurring" => setup_recurring(&client, "order_001").await,
        "tokenize" => tokenize(&client, "order_001").await,
        "void" => void(&client, "order_001").await,
        _ => {
            eprintln!("Unknown flow: {}. Available: process_checkout_autocapture, process_checkout_card, process_refund, process_void_payment, process_get_payment, authorize, capture, create_client_authentication_token, create_customer, get, incremental_authorization, proxy_authorize, proxy_setup_recurring, recurring_charge, refund, refund_get, setup_recurring, tokenize, void", flow);
            return;
        }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
