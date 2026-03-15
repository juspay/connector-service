// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py bamboraapac
//
// Bamboraapac — all scenarios and flows in one file.
// Run a scenario:  cargo run --example bamboraapac -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;


fn build_client() -> ConnectorClient {
    let config = ConnectorConfig {
        connector: Connector::Bamboraapac.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth { ... })  — set your connector auth here
        ..Default::default()
    };
    ConnectorClient::new(config, None).unwrap()
}


// Scenario: Card Payment (Authorize + Capture)
// Reserve funds with Authorize, then settle with a separate Capture call. Use for physical goods or delayed fulfillment where capture happens later.
pub async fn process_checkout_card(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client.authorize(serde_json::from_value::<PaymentServiceAuthorizeRequest>(serde_json::json!({
        "merchant_transaction_id": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {  // Payment method to be used
            "payment_method": {
                "card": {  // Generic card payment
                    "card_number": "4111111111111111",  // Card Identification
                    "card_exp_month": "03",
                    "card_exp_year": "2030",
                    "card_cvc": "737",
                    "card_holder_name": "John Doe",  // Cardholder Information
                },
            }
        },
        "capture_method": "MANUAL",  // Method for capturing the payment
        "customer": {  // Customer Information
            "name": "John Doe",  // Customer's full name
            "email": "test@example.com",  // Customer's email address
            "id": "cust_probe_123",  // Internal customer ID
            "phone_number": "4155552671",  // Customer's phone number
            "phone_country_code": "+1",  // Customer's phone country code
        },
        "address": {  // Address Information
            "shipping_address": {
                "first_name": "John",  // Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  // Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  // Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1",
            },
            "billing_address": {
                "first_name": "John",  // Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  // Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  // Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1",
            },
        },
        "auth_type": "NO_THREE_DS",  // Authentication Details
        "return_url": "https://example.com/return",  // URLs for Redirection and Webhooks
        "webhook_url": "https://example.com/webhook",
        "complete_authorize_url": "https://example.com/complete",
        "browser_info": {
            "color_depth": 24,  // Display Information
            "screen_height": 900,
            "screen_width": 1440,
            "java_enabled": false,  // Browser Settings
            "java_script_enabled": true,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            "accept_header": "application/json",  // Browser Headers
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            "ip_address": "1.2.3.4",  // Device Information
        },
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    // Step 2: Capture — settle the reserved funds
    let capture_response = client.capture(serde_json::from_value::<PaymentServiceCaptureRequest>(serde_json::json!({
        "merchant_capture_id": "probe_capture_001",  // Identification
        "amount_to_capture": {  // Capture Details
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    if capture_response.status() == PaymentStatus::Failure {
        return Err(format!("Capture failed: {:?}", capture_response.error).into());
    }

    Ok(format!("Payment completed: {}", authorize_response.connector_transaction_id.as_deref().unwrap_or("")))
}

// Scenario: Card Payment (Automatic Capture)
// Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.
pub async fn process_checkout_autocapture(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client.authorize(serde_json::from_value::<PaymentServiceAuthorizeRequest>(serde_json::json!({
        "merchant_transaction_id": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {  // Payment method to be used
            "payment_method": {
                "card": {  // Generic card payment
                    "card_number": "4111111111111111",  // Card Identification
                    "card_exp_month": "03",
                    "card_exp_year": "2030",
                    "card_cvc": "737",
                    "card_holder_name": "John Doe",  // Cardholder Information
                },
            }
        },
        "capture_method": "AUTOMATIC",  // Method for capturing the payment
        "customer": {  // Customer Information
            "name": "John Doe",  // Customer's full name
            "email": "test@example.com",  // Customer's email address
            "id": "cust_probe_123",  // Internal customer ID
            "phone_number": "4155552671",  // Customer's phone number
            "phone_country_code": "+1",  // Customer's phone country code
        },
        "address": {  // Address Information
            "shipping_address": {
                "first_name": "John",  // Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  // Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  // Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1",
            },
            "billing_address": {
                "first_name": "John",  // Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  // Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  // Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1",
            },
        },
        "auth_type": "NO_THREE_DS",  // Authentication Details
        "return_url": "https://example.com/return",  // URLs for Redirection and Webhooks
        "webhook_url": "https://example.com/webhook",
        "complete_authorize_url": "https://example.com/complete",
        "browser_info": {
            "color_depth": 24,  // Display Information
            "screen_height": 900,
            "screen_width": 1440,
            "java_enabled": false,  // Browser Settings
            "java_script_enabled": true,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            "accept_header": "application/json",  // Browser Headers
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            "ip_address": "1.2.3.4",  // Device Information
        },
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    Ok(format!("Payment: {:?} — {}", authorize_response.status(), authorize_response.connector_transaction_id.as_deref().unwrap_or("")))
}

// Scenario: Refund a Payment
// Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.
pub async fn process_refund(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client.authorize(serde_json::from_value::<PaymentServiceAuthorizeRequest>(serde_json::json!({
        "merchant_transaction_id": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {  // Payment method to be used
            "payment_method": {
                "card": {  // Generic card payment
                    "card_number": "4111111111111111",  // Card Identification
                    "card_exp_month": "03",
                    "card_exp_year": "2030",
                    "card_cvc": "737",
                    "card_holder_name": "John Doe",  // Cardholder Information
                },
            }
        },
        "capture_method": "AUTOMATIC",  // Method for capturing the payment
        "customer": {  // Customer Information
            "name": "John Doe",  // Customer's full name
            "email": "test@example.com",  // Customer's email address
            "id": "cust_probe_123",  // Internal customer ID
            "phone_number": "4155552671",  // Customer's phone number
            "phone_country_code": "+1",  // Customer's phone country code
        },
        "address": {  // Address Information
            "shipping_address": {
                "first_name": "John",  // Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  // Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  // Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1",
            },
            "billing_address": {
                "first_name": "John",  // Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  // Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  // Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1",
            },
        },
        "auth_type": "NO_THREE_DS",  // Authentication Details
        "return_url": "https://example.com/return",  // URLs for Redirection and Webhooks
        "webhook_url": "https://example.com/webhook",
        "complete_authorize_url": "https://example.com/complete",
        "browser_info": {
            "color_depth": 24,  // Display Information
            "screen_height": 900,
            "screen_width": 1440,
            "java_enabled": false,  // Browser Settings
            "java_script_enabled": true,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            "accept_header": "application/json",  // Browser Headers
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            "ip_address": "1.2.3.4",  // Device Information
        },
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    // Step 2: Refund — return funds to the customer
    let refund_response = client.refund(serde_json::from_value::<PaymentServiceRefundRequest>(serde_json::json!({
        "merchant_refund_id": "probe_refund_001",  // Identification
        "payment_amount": 1000,  // Amount Information
        "refund_amount": {
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "reason": "customer_request",  // Reason for the refund
        "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    if refund_response.status() == RefundStatus::RefundFailure {
        return Err(format!("Refund failed: {:?}", refund_response.error).into());
    }

    Ok(format!("Refunded: {:?}", refund_response.status()))
}

// Scenario: Recurring / Mandate Payments
// Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.
pub async fn process_recurring(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Setup Recurring — store the payment mandate
    let setup_response = client.setup_recurring(serde_json::from_value::<PaymentServiceSetupRecurringRequest>(serde_json::json!({
        "merchant_recurring_payment_id": "probe_mandate_001",  // Identification
        "amount": {  // Mandate Details
            "minor_amount": 0,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {
            "payment_method": {
                "card": {  // Generic card payment
                    "card_number": "4111111111111111",  // Card Identification
                    "card_exp_month": "03",
                    "card_exp_year": "2030",
                    "card_cvc": "737",
                    "card_holder_name": "John Doe",  // Cardholder Information
                },
            }
        },
        "customer": {
            "name": "John Doe",  // Customer's full name
            "email": "test@example.com",  // Customer's email address
            "id": "cust_probe_123",  // Internal customer ID
            "phone_number": "4155552671",  // Customer's phone number
            "phone_country_code": "+1",  // Customer's phone country code
        },
        "address": {  // Address Information
            "billing_address": {
                "first_name": "John",  // Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  // Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  // Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1",
            },
        },
        "auth_type": "NO_THREE_DS",  // Type of authentication to be used
        "enrolled_for_3ds": false,  // Indicates if the customer is enrolled for 3D Secure
        "return_url": "https://example.com/mandate-return",  // URL to redirect after setup
        "setup_future_usage": "OFF_SESSION",  // Indicates future usage intention
        "request_incremental_authorization": false,  // Indicates if incremental authorization is requested
        "customer_acceptance": {  // Details of customer acceptance
            "acceptance_type": "OFFLINE",  // Type of acceptance (e.g., online, offline).
            "accepted_at": 0,  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
        },
        "browser_info": {  // Information about the customer's browser
            "color_depth": 24,  // Display Information
            "screen_height": 900,
            "screen_width": 1440,
            "java_enabled": false,  // Browser Settings
            "java_script_enabled": true,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            "accept_header": "application/json",  // Browser Headers
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            "ip_address": "1.2.3.4",  // Device Information
        },
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    if setup_response.status() == PaymentStatus::Failure {
        return Err(format!("Setup failed: {:?}", setup_response.error).into());
    }

    // Step 2: Recurring Charge — charge against the stored mandate
    let recurring_response = client.recurring_charge(serde_json::from_value::<RecurringPaymentServiceChargeRequest>(serde_json::json!({
        "amount": {  // Amount Information
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "return_url": "https://example.com/recurring-return",
        "off_session": true,  // Behavioral Flags and Preferences
        // "connector_recurring_payment_id": ???,  // TODO: extract from setup_response.mandate_reference
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    if recurring_response.status() == PaymentStatus::Failure {
        return Err(format!("Recurring Charge failed: {:?}", recurring_response.error).into());
    }

    Ok(format!("Charged: {:?}", recurring_response.status()))
}

// Scenario: Get Payment Status
// Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.
pub async fn process_get_payment(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client.authorize(serde_json::from_value::<PaymentServiceAuthorizeRequest>(serde_json::json!({
        "merchant_transaction_id": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {  // Payment method to be used
            "payment_method": {
                "card": {  // Generic card payment
                    "card_number": "4111111111111111",  // Card Identification
                    "card_exp_month": "03",
                    "card_exp_year": "2030",
                    "card_cvc": "737",
                    "card_holder_name": "John Doe",  // Cardholder Information
                },
            }
        },
        "capture_method": "MANUAL",  // Method for capturing the payment
        "customer": {  // Customer Information
            "name": "John Doe",  // Customer's full name
            "email": "test@example.com",  // Customer's email address
            "id": "cust_probe_123",  // Internal customer ID
            "phone_number": "4155552671",  // Customer's phone number
            "phone_country_code": "+1",  // Customer's phone country code
        },
        "address": {  // Address Information
            "shipping_address": {
                "first_name": "John",  // Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  // Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  // Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1",
            },
            "billing_address": {
                "first_name": "John",  // Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  // Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  // Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1",
            },
        },
        "auth_type": "NO_THREE_DS",  // Authentication Details
        "return_url": "https://example.com/return",  // URLs for Redirection and Webhooks
        "webhook_url": "https://example.com/webhook",
        "complete_authorize_url": "https://example.com/complete",
        "browser_info": {
            "color_depth": 24,  // Display Information
            "screen_height": 900,
            "screen_width": 1440,
            "java_enabled": false,  // Browser Settings
            "java_script_enabled": true,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            "accept_header": "application/json",  // Browser Headers
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            "ip_address": "1.2.3.4",  // Device Information
        },
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    // Step 2: Get — retrieve current payment status from the connector
    let get_response = client.get(serde_json::from_value::<PaymentServiceGetRequest>(serde_json::json!({
        "amount": {  // Amount Information
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    Ok(format!("Status: {:?}", get_response.status()))
}

// Flow: PaymentService.Authorize (Card)
pub async fn authorize(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.authorize(serde_json::from_value::<PaymentServiceAuthorizeRequest>(serde_json::json!({
    "merchant_transaction_id": "probe_txn_001",  // Identification
    "amount": {  // The amount for the payment
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "payment_method": {  // Payment method to be used
        "payment_method": {
            "card": {  // Generic card payment
                "card_number": "4111111111111111",  // Card Identification
                "card_exp_month": "03",
                "card_exp_year": "2030",
                "card_cvc": "737",
                "card_holder_name": "John Doe",  // Cardholder Information
            },
        }
    },
    "capture_method": "AUTOMATIC",  // Method for capturing the payment
    "customer": {  // Customer Information
        "name": "John Doe",  // Customer's full name
        "email": "test@example.com",  // Customer's email address
        "id": "cust_probe_123",  // Internal customer ID
        "phone_number": "4155552671",  // Customer's phone number
        "phone_country_code": "+1",  // Customer's phone country code
    },
    "address": {  // Address Information
        "shipping_address": {
            "first_name": "John",  // Personal Information
            "last_name": "Doe",
            "line1": "123 Main St",  // Address Details
            "city": "Seattle",
            "state": "WA",
            "zip_code": "98101",
            "country_alpha2_code": "US",
            "email": "test@example.com",  // Contact Information
            "phone_number": "4155552671",
            "phone_country_code": "+1",
        },
        "billing_address": {
            "first_name": "John",  // Personal Information
            "last_name": "Doe",
            "line1": "123 Main St",  // Address Details
            "city": "Seattle",
            "state": "WA",
            "zip_code": "98101",
            "country_alpha2_code": "US",
            "email": "test@example.com",  // Contact Information
            "phone_number": "4155552671",
            "phone_country_code": "+1",
        },
    },
    "auth_type": "NO_THREE_DS",  // Authentication Details
    "return_url": "https://example.com/return",  // URLs for Redirection and Webhooks
    "webhook_url": "https://example.com/webhook",
    "complete_authorize_url": "https://example.com/complete",
    "browser_info": {
        "color_depth": 24,  // Display Information
        "screen_height": 900,
        "screen_width": 1440,
        "java_enabled": false,  // Browser Settings
        "java_script_enabled": true,
        "language": "en-US",
        "time_zone_offset_minutes": -480,
        "accept_header": "application/json",  // Browser Headers
        "user_agent": "Mozilla/5.0 (probe-bot)",
        "accept_language": "en-US,en;q=0.9",
        "ip_address": "1.2.3.4",  // Device Information
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    match response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed
            => return Err(format!("Authorize failed: {:?}", response.error).into()),
        PaymentStatus::Pending => return Ok("pending — await webhook".to_string()),
        _  => return Ok(format!("Authorized: {}", response.connector_transaction_id.as_deref().unwrap_or(""))),
    }
}

// Flow: PaymentService.Capture
pub async fn capture(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.capture(serde_json::from_value::<PaymentServiceCaptureRequest>(serde_json::json!({
    "merchant_capture_id": "probe_capture_001",  // Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "amount_to_capture": {  // Capture Details
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: PaymentService.Get
pub async fn get(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.get(serde_json::from_value::<PaymentServiceGetRequest>(serde_json::json!({
    "connector_transaction_id": "probe_connector_txn_001",
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: RecurringPaymentService.Charge
pub async fn recurring_charge(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.recurring_charge(serde_json::from_value::<RecurringPaymentServiceChargeRequest>(serde_json::json!({
    "connector_recurring_payment_id": {  // Reference to existing mandate
        "mandate_id_type": {
            "connector_mandate_id": "probe_mandate_123",
        },
    },
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "payment_method": {  // Optional payment Method Information (for network transaction flows)
        "payment_method": {
            "token": "probe_pm_token",  // Payment tokens
        }
    },
    "return_url": "https://example.com/recurring-return",
    "connector_customer_id": "probe_cust_connector_001",
    "payment_method_type": "PAY_PAL",
    "off_session": true,  // Behavioral Flags and Preferences
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: PaymentService.Refund
pub async fn refund(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.refund(serde_json::from_value::<PaymentServiceRefundRequest>(serde_json::json!({
    "merchant_refund_id": "probe_refund_001",  // Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "payment_amount": 1000,  // Amount Information
    "refund_amount": {
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "reason": "customer_request",  // Reason for the refund
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: PaymentService.SetupRecurring
pub async fn setup_recurring(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.setup_recurring(serde_json::from_value::<PaymentServiceSetupRecurringRequest>(serde_json::json!({
    "merchant_recurring_payment_id": "probe_mandate_001",  // Identification
    "amount": {  // Mandate Details
        "minor_amount": 0,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "payment_method": {
        "payment_method": {
            "card": {  // Generic card payment
                "card_number": "4111111111111111",  // Card Identification
                "card_exp_month": "03",
                "card_exp_year": "2030",
                "card_cvc": "737",
                "card_holder_name": "John Doe",  // Cardholder Information
            },
        }
    },
    "customer": {
        "name": "John Doe",  // Customer's full name
        "email": "test@example.com",  // Customer's email address
        "id": "cust_probe_123",  // Internal customer ID
        "phone_number": "4155552671",  // Customer's phone number
        "phone_country_code": "+1",  // Customer's phone country code
    },
    "address": {  // Address Information
        "billing_address": {
            "first_name": "John",  // Personal Information
            "last_name": "Doe",
            "line1": "123 Main St",  // Address Details
            "city": "Seattle",
            "state": "WA",
            "zip_code": "98101",
            "country_alpha2_code": "US",
            "email": "test@example.com",  // Contact Information
            "phone_number": "4155552671",
            "phone_country_code": "+1",
        },
    },
    "auth_type": "NO_THREE_DS",  // Type of authentication to be used
    "enrolled_for_3ds": false,  // Indicates if the customer is enrolled for 3D Secure
    "return_url": "https://example.com/mandate-return",  // URL to redirect after setup
    "setup_future_usage": "OFF_SESSION",  // Indicates future usage intention
    "request_incremental_authorization": false,  // Indicates if incremental authorization is requested
    "customer_acceptance": {  // Details of customer acceptance
        "acceptance_type": "OFFLINE",  // Type of acceptance (e.g., online, offline).
        "accepted_at": 0,  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
    },
    "browser_info": {  // Information about the customer's browser
        "color_depth": 24,  // Display Information
        "screen_height": 900,
        "screen_width": 1440,
        "java_enabled": false,  // Browser Settings
        "java_script_enabled": true,
        "language": "en-US",
        "time_zone_offset_minutes": -480,
        "accept_header": "application/json",  // Browser Headers
        "user_agent": "Mozilla/5.0 (probe-bot)",
        "accept_language": "en-US,en;q=0.9",
        "ip_address": "1.2.3.4",  // Device Information
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    if response.status() == PaymentStatus::Failure {
        return Err(format!("Setup failed: {:?}", response.error).into());
    }
    return Ok(format!("Mandate: {}", response.connector_recurring_payment_id.as_deref().unwrap_or("")));
}


#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args().nth(1).unwrap_or_else(|| "process_checkout_card".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "process_checkout_card" => process_checkout_card(&client, "order_001").await,
        "process_checkout_autocapture" => process_checkout_autocapture(&client, "order_001").await,
        "process_refund" => process_refund(&client, "order_001").await,
        "process_recurring" => process_recurring(&client, "order_001").await,
        "process_get_payment" => process_get_payment(&client, "order_001").await,
        "authorize" => authorize(&client, "order_001").await,
        "capture" => capture(&client, "order_001").await,
        "get" => get(&client, "order_001").await,
        "recurring_charge" => recurring_charge(&client, "order_001").await,
        "refund" => refund(&client, "order_001").await,
        "setup_recurring" => setup_recurring(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: process_checkout_card, process_checkout_autocapture, process_refund, process_recurring, process_get_payment, authorize, capture, get, recurring_charge, refund, setup_recurring", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
