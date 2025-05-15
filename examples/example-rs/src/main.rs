use rust_grpc_client::payments::{self, payment_service_client::PaymentServiceClient,Address, PhoneDetails};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get the URL from command line arguments
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        eprintln!("Usage: {} <url> [operation]", args[0]);
        eprintln!("Operations: authorize, sync");
        std::process::exit(1);
    }

    let url = &args[1];
    let operation = args.get(2).map(|s| s.as_str()).unwrap_or("authorize");

    let response = match operation {
        "authorize" => {
            let auth_response = make_payment_authorization_request(url.to_string()).await?;
            format!("Authorization Response: {:?}", auth_response)
        }
        "sync" => {
            let sync_response = make_payment_sync_request(url.to_string()).await?;
            format!("Sync Response: {:?}", sync_response)
        }
        _ => {
            eprintln!(
                "Unknown operation: {}. Use 'authorize' or 'sync'.",
                operation
            );
            std::process::exit(1);
        }
    };

    // Print the response
    println!("{}", response);
    Ok(())
}

/// Creates a gRPC client and sends a payment authorization request
async fn make_payment_authorization_request(
    url: String,
) -> Result<tonic::Response<payments::PaymentsAuthorizeResponse>, Box<dyn Error>> {
    // Create a gRPC client
    let mut client = PaymentServiceClient::connect(url).await?;

    let api_key = std::env::var("API_KEY").unwrap_or_else(|_| "default_api_key".to_string());
    let key1 = std::env::var("KEY1").unwrap_or_else(|_| "default_key1".to_string());
    println!("api_key is {} and key1 is {}", api_key,key1);

    // Create a request with the updated values
    let request = payments::PaymentsAuthorizeRequest {
        amount: 1000 as i64,
        currency: payments::Currency::Usd as i32,
        // connector: payments::Connector::Adyen as i32,
        // auth_creds: Some(payments::AuthType {
        //     auth_details: Some(payments::auth_type::AuthDetails::BodyKey(  // Changed to BodyKey
        //         payments::BodyKey {
        //             api_key,
        //             key1
        //         },
        //     )),
        // }),
        // connector: payments::Connector::Adyen as i32,
        // auth_creds: Some(payments::AuthType {
        //     auth_details: Some(payments::auth_type::AuthDetails::BodyKey(  // Changed to BodyKey
        //         payments::BodyKey {
        //             api_key,
        //             key1
        //         },
        //     )),
        // }),
        payment_method: payments::PaymentMethod::Card as i32,
        payment_method_data: Some(payments::PaymentMethodData {
            data: Some(payments::payment_method_data::Data::Card(payments::Card {
                card_number: "5123456789012346".to_string(), // Updated card number
                card_exp_month: "03".to_string(),
                card_exp_year: "2030".to_string(),
                card_cvc: "100".to_string(), // Updated CVC
                ..Default::default()
            })),
        }),
        // connector_customer: Some("customer_12345".to_string()),
        // return_url: Some("www.google.com".to_string()),
        address:Some(payments::PaymentAddress{
            shipping:None,
            billing:Some(Address { address: None, phone: Some(PhoneDetails { number: Some("1234567890".to_string()), country_code: Some("+1".to_string()) }), email: Some("sweta.sharma@juspay.in".to_string()) }),
            unified_payment_method_billing: None,
            payment_method_billing: None
        }),
        auth_type: payments::AuthenticationType::ThreeDs as i32,
        connector_request_reference_id: "ref_12345".to_string(),
        enrolled_for_3ds: true,
        request_incremental_authorization: false,
        minor_amount: 1000 as i64,
        email: Some("sweta.sharma@juspay.in".to_string()),
        connector_customer: Some("cus_1234".to_string()),
        return_url: Some("www.google.com".to_string()),
        browser_info: Some(payments::BrowserInformation {
            // Added browser_info
            user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string()),
            accept_header: Some(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
            ),
            language: Some("en-US".to_string()),
            color_depth: Some(24),
            screen_height: Some(1080),
            screen_width: Some(1920),
            java_enabled: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut request = tonic::Request::new(request);
    request
        .metadata_mut()
        .append("x-connector", "adyen".parse().unwrap());
    request
        .metadata_mut()
        .append("x-auth", "body-key".parse().unwrap());
    request
        .metadata_mut()
        .append("x-api-key", api_key.parse().unwrap());
    request
        .metadata_mut()
        .append("x-key1", key1.parse().unwrap());

    // Send the request
    let response = client.payment_authorize(request).await?;

    Ok(response)
}

/// Creates a gRPC client and sends a payment sync request
async fn make_payment_sync_request(
    url: String,
) -> Result<tonic::Response<payments::PaymentsSyncResponse>, Box<dyn Error>> {
    // Create a gRPC client
    let mut client = PaymentServiceClient::connect(url).await?;

    let resource_id =
        std::env::var("RESOURCE_ID").unwrap_or_else(|_| "pay_QHj9Thiy5mCC4Y".to_string());

    let api_key = std::env::var("API_KEY").unwrap_or_else(|_| "default_api_key".to_string());
    let key1 = std::env::var("KEY1").unwrap_or_else(|_| "default_key1".to_string());

    // Create a request
    let request = payments::PaymentsSyncRequest {
        // connector: payments::Connector::Razorpay as i32,
        // auth_creds: Some(payments::AuthType {
        //     auth_details: Some(payments::auth_type::AuthDetails::BodyKey(
        //         payments::BodyKey {
        //             api_key,
        //             key1
        //         },
        //     )),
        // }),
        resource_id,
        connector_request_reference_id: Some("conn_req_abc".to_string()),
    };

    let mut request = tonic::Request::new(request);
    request
        .metadata_mut()
        .append("x-connector", "razorpay".parse().unwrap());
    request
        .metadata_mut()
        .append("x-auth", "body-key".parse().unwrap());
    request
        .metadata_mut()
        .append("x-api-key", api_key.parse().unwrap());
    request
        .metadata_mut()
        .append("x-key1", key1.parse().unwrap());

    let response = client.payment_sync(request).await?;

    Ok(response)
}
