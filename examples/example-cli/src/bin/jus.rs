// src/main.rs

// --- Imports ---
use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use strum::{EnumString, EnumVariantNames}; // For parsing enums
use tonic::transport::{Channel, Endpoint}; // For client connection
use tonic::metadata::MetadataMap;
use tonic::Extensions;
use tonic::Request;
use tonic::transport::Channel as TonicChannel;

// --- Use gRPC types from the crate ---
use grpc_api_types::payments;
use grpc_api_types::payments::payment_service_client::PaymentServiceClient;

// --- Type Aliases ---
type PaymentClient = PaymentServiceClient<TonicChannel>;

// --- Constants ---
const X_CONNECTOR: &str = "x-connector";
const X_AUTH: &str = "x-auth";
const X_API_KEY: &str = "x-api-key";
const X_KEY1: &str = "x-key1";
const X_API_SECRET: &str = "x-api-secret";

// --- Enums ---
#[derive(
    Debug,
    Clone,
    Copy,
    EnumString,
    EnumVariantNames,
    PartialEq,
    clap::ValueEnum,
    Serialize,
    Deserialize,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
enum ConnectorChoice {
    Adyen,
    Razorpay,
}

impl std::fmt::Display for ConnectorChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorChoice::Adyen => write!(f, "adyen"),
            ConnectorChoice::Razorpay => write!(f, "razorpay"),
        }
    }
}

// --- Auth Details ---
#[derive(Debug, Args, Clone, Serialize, Deserialize, Default)]
struct AuthDetails {
    /// API key for authentication
    #[arg(long, required = false)]
    #[serde(default)]
    api_key: String,

    /// Key1 for authentication (used in BodyKey and SignatureKey auth)
    #[arg(long, required = false)]
    #[serde(default)]
    key1: Option<String>,

    /// API secret for authentication (used in SignatureKey auth)
    #[arg(long, required = false)]
    #[serde(default)]
    api_secret: Option<String>,

    /// Authentication type (bodykey, headerkey, signaturekey)
    #[arg(long, value_enum, required = false)]
    #[serde(default)]
    auth_type: AuthType,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthType {
    /// Use body key authentication
    BodyKey,

    /// Use header key authentication
    HeaderKey,

    /// Use signature key authentication
    SignatureKey,
}

impl Default for AuthType {
    fn default() -> Self {
        AuthType::HeaderKey // Using HeaderKey as default since it requires the least parameters
    }
}

// --- Card Args ---
#[derive(Debug, Args, Clone, Serialize, Deserialize, Default)]
struct CardArgs {
    /// Card number
    #[arg(long, required = false)]
    #[serde(default)]
    number: String,

    /// Card expiry month
    #[arg(long, required = false)]
    #[serde(default)]
    exp_month: String,

    /// Card expiry year
    #[arg(long, required = false)]
    #[serde(default)]
    exp_year: String,

    /// Card CVC
    #[arg(long, required = false)]
    #[serde(default)]
    cvc: String,
}

// --- Credential file structure ---
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialData {
    pub connector: ConnectorChoice,
    pub auth: AuthDetails,
}

// --- Payment data file structure ---
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PaymentData {
    pub amount: i64,
    pub currency: String,
    pub email: Option<String>,
    pub card: CardArgs,
}

// --- Sync data file structure ---
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GetData {
    pub payment_id: String,
}

// --- Subcommands ---
#[derive(Debug, Subcommand, Clone)]
enum Command {
    /// Create a payment
    Pay(PayArgs),

    /// Get payment status
    Get(GetArgs),
}

// --- Command Args ---
#[derive(Debug, Args, Clone)]
struct PayArgs {
    /// URL of the gRPC server
    #[arg(long)]
    url: String,

    /// Connector to use (can be provided via cred_file)
    #[arg(long, value_enum)]
    connector: Option<ConnectorChoice>,

    /// Amount to charge (can be provided via payment_file)
    #[arg(long)]
    amount: Option<i64>,

    /// Currency to use (usd, gbp, eur) (can be provided via payment_file)
    #[arg(long)]
    currency: Option<String>,

    /// Email address (can be provided via payment_file)
    #[arg(long)]
    email: Option<String>,

    /// Path to credential file (contains connector and auth details)
    #[arg(long)]
    cred_file: Option<PathBuf>,

    /// Path to payment data file (contains payment details)
    #[arg(long)]
    payment_file: Option<PathBuf>,

    /// Capture method (automatic, manual, manual_multiple, scheduled, sequential_automatic)
    #[arg(long)]
    capture_method: Option<String>,

    /// Return URL for redirect flows
    #[arg(long)]
    return_url: Option<String>,

    /// Webhook URL for notifications
    #[arg(long)]
    webhook_url: Option<String>,

    /// Complete authorize URL
    #[arg(long)]
    complete_authorize_url: Option<String>,

    /// Future usage (off_session, on_session)
    #[arg(long)]
    future_usage: Option<String>,

    /// Whether the payment is off session
    #[arg(long)]
    off_session: Option<bool>,

    /// Order category
    #[arg(long)]
    order_category: Option<String>,

    /// Whether enrolled for 3DS
    #[arg(long)]
    enrolled_for_3ds: Option<bool>,

    /// Payment experience (redirect_to_url, invoke_sdk_client, etc.)
    #[arg(long)]
    payment_experience: Option<String>,

    /// Payment method type
    #[arg(long)]
    payment_method_type: Option<String>,

    /// Whether to request incremental authorization
    #[arg(long)]
    request_incremental_authorization: Option<bool>,

    /// Whether to request extended authorization
    #[arg(long)]
    request_extended_authorization: Option<bool>,

    /// Merchant order reference ID
    #[arg(long)]
    merchant_order_reference_id: Option<String>,

    /// Shipping cost
    #[arg(long)]
    shipping_cost: Option<i64>,

    #[command(flatten)]
    auth: Option<AuthDetails>,

    #[command(flatten)]
    card: Option<CardArgs>,
}

#[derive(Debug, Args, Clone)]
struct GetArgs {
    /// URL of the gRPC server
    #[arg(long)]
    url: String,

    /// Connector to use (can be provided via cred_file)
    #[arg(long, value_enum)]
    connector: Option<ConnectorChoice>,

    /// Resource ID to sync (can be provided via get_file)
    #[arg(long)]
    payment_id: Option<String>,

    /// Path to credential file (contains connector and auth details)
    #[arg(long)]
    cred_file: Option<PathBuf>,

    /// Path to sync data file (contains sync details)
    #[arg(long)]
    get_file: Option<PathBuf>,

    #[command(flatten)]
    auth: Option<AuthDetails>,
}

// --- Main CLI Args ---
#[derive(Debug, Parser, Clone)]
#[command(name = "example-cli")]
#[command(about = "gRPC Payment CLI Client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// --- gRPC Client Helper ---
async fn connect_client(url: &str) -> Result<PaymentClient> {
    println!("Attempting to connect to gRPC server at: {}", url);

    // Validate URL format
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(anyhow!("URL must start with http:// or https://"));
    }

    let endpoint = Endpoint::try_from(url.to_string())
        .with_context(|| format!("Failed to create endpoint for URL: {}", url))?;

    // Add connection timeout
    let endpoint = endpoint.connect_timeout(std::time::Duration::from_secs(5));

    println!("Connecting to server...");
    let channel = match endpoint.connect().await {
        Ok(channel) => {
            println!("Successfully connected to gRPC server");
            channel
        }
        Err(err) => {
            println!("Connection error: {}", err);
            println!("Troubleshooting tips:");
            println!("1. Make sure the server is running on the specified host and port");
            println!("2. Check if the URL format is correct (e.g., http://localhost:8080)");
            println!("3. Verify that the server is accepting gRPC connections");
            println!(
                "4. Check if there are any network issues or firewalls blocking the connection"
            );
            return Err(anyhow!("Failed to connect to gRPC server: {}", err));
        }
    };

    Ok(PaymentClient::new(channel))
}

// --- Get Auth Details ---
fn get_auth_details(auth: &AuthDetails) -> Result<Vec<(String, String)>> {
    match auth.auth_type {
        AuthType::BodyKey => {
            let key1 = auth
                .key1
                .clone()
                .ok_or_else(|| anyhow!("key1 is required for BodyKey authentication"))?;

            Ok(payments::AuthType {
                auth_details: Some(payments::auth_type::AuthDetails::BodyKey(
                    payments::BodyKey {
                        api_key: auth.api_key.clone(),
                        key1,
                    },
                )),
            })
        }
        AuthType::HeaderKey => Ok(payments::AuthType {
            auth_details: Some(payments::auth_type::AuthDetails::HeaderKey(
                payments::HeaderKey {
                    api_key: auth.api_key.clone(),
                },
            )),
        }),
        AuthType::SignatureKey => {
            let key1 = auth
                .key1
                .clone()
                .ok_or_else(|| anyhow!("key1 is required for SignatureKey authentication"))?;
            let api_secret = auth
                .api_secret
                .clone()
                .ok_or_else(|| anyhow!("api_secret is required for SignatureKey authentication"))?;

            Ok(payments::AuthType {
                auth_details: Some(payments::auth_type::AuthDetails::SignatureKey(
                    payments::SignatureKey {
                        api_key: auth.api_key.clone(),
                        key1,
                        api_secret,
                    },
                )),
            })
        }
    }
}

// --- Parse Currency ---
fn parse_currency(currency_str: &str) -> Result<i32> {
    match currency_str.to_lowercase().as_str() {
        "usd" => Ok(payments::Currency::Usd as i32),
        "gbp" => Ok(payments::Currency::Gbp as i32),
        "eur" => Ok(payments::Currency::Eur as i32),
        _ => Err(anyhow!(
            "Unsupported currency: {}. Use usd, gbp, eur",
            currency_str
        )),
    }
}

// --- Command Handlers ---
// --- File Loading Functions ---
fn load_credential_file(file_path: &PathBuf) -> Result<CredentialData> {
    println!("Loading credential data from: {}", file_path.display());
    let file = File::open(file_path)
        .with_context(|| format!("Failed to open credential file: {}", file_path.display()))?;

    let reader = BufReader::new(file);
    let cred_data: CredentialData = serde_json::from_reader(reader)
        .with_context(|| format!("Failed to parse credential file: {}", file_path.display()))?;

    Ok(cred_data)
}

fn load_payment_file(file_path: &PathBuf) -> Result<PaymentData> {
    println!("Loading payment data from: {}", file_path.display());
    let file = File::open(file_path)
        .with_context(|| format!("Failed to open payment file: {}", file_path.display()))?;

    let reader = BufReader::new(file);
    let payment_data: PaymentData = serde_json::from_reader(reader)
        .with_context(|| format!("Failed to parse payment file: {}", file_path.display()))?;

    Ok(payment_data)
}

fn load_sync_file(file_path: &PathBuf) -> Result<GetData> {
    println!("Loading sync data from: {}", file_path.display());
    let file = File::open(file_path)
        .with_context(|| format!("Failed to open sync file: {}", file_path.display()))?;

    let reader = BufReader::new(file);
    let sync_data: GetData = serde_json::from_reader(reader)
        .with_context(|| format!("Failed to parse sync file: {}", file_path.display()))?;

    Ok(sync_data)
}

async fn handle_pay(mut args: PayArgs) -> Result<()> {
    // Initialize auth details if not provided
    let mut auth_details = AuthDetails::default();
    let mut card_details = CardArgs::default();

    // Load credential file if provided
    if let Some(cred_file) = &args.cred_file {
        let cred_data = load_credential_file(cred_file)?;

        // Set connector if not provided in command line
        if args.connector.is_none() {
            args.connector = Some(cred_data.connector);
            println!(
                "Using connector from credential file: {:?}",
                cred_data.connector
            );
        }

        // Set auth details from credential file
        auth_details = cred_data.auth;
        println!("Using authentication details from credential file");
    }

    // Override with command line auth if provided
    if let Some(cmd_auth) = &args.auth {
        if !cmd_auth.api_key.is_empty() {
            auth_details.api_key = cmd_auth.api_key.clone();
        }
        if cmd_auth.key1.is_some() {
            auth_details.key1 = cmd_auth.key1.clone();
        }
        if cmd_auth.api_secret.is_some() {
            auth_details.api_secret = cmd_auth.api_secret.clone();
        }
        if cmd_auth.auth_type != AuthType::default() {
            auth_details.auth_type = cmd_auth.auth_type;
        }
    }

    // Load payment file if provided
    if let Some(payment_file) = &args.payment_file {
        let payment_data = load_payment_file(payment_file)?;

        // Set payment data if not provided in command line
        if args.amount.is_none() {
            args.amount = Some(payment_data.amount);
            println!("Using amount from payment file: {}", payment_data.amount);
        }

        if args.currency.is_none() {
            args.currency = Some(payment_data.currency.clone());
            println!(
                "Using currency from payment file: {}",
                payment_data.currency
            );
        }

        if args.email.is_none() {
            args.email = payment_data.email.clone();
            println!("Using email from payment file: {:?}", payment_data.email);
        }

        // Set card details from payment file
        card_details = payment_data.card;
        println!("Using card details from payment file");
    }

    // Override with command line card details if provided
    if let Some(cmd_card) = &args.card {
        if !cmd_card.number.is_empty() {
            card_details.number = cmd_card.number.clone();
        }
        if !cmd_card.exp_month.is_empty() {
            card_details.exp_month = cmd_card.exp_month.clone();
        }
        if !cmd_card.exp_year.is_empty() {
            card_details.exp_year = cmd_card.exp_year.clone();
        }
        if !cmd_card.cvc.is_empty() {
            card_details.cvc = cmd_card.cvc.clone();
        }
    }

    // Validate required fields
    let connector = args.connector.ok_or_else(|| {
        anyhow!("Connector is required either via --connector or in the credential file")
    })?;

    let amount = args
        .amount
        .ok_or_else(|| anyhow!("Amount is required either via --amount or in the payment file"))?;

    let currency_str = args.currency.as_deref().ok_or_else(|| {
        anyhow!("Currency is required either via --currency or in the payment file")
    })?;

    let currency = parse_currency(currency_str)?;

    // Validate card details
    if card_details.number.is_empty() {
        return Err(anyhow!(
            "Card number is required either via --number or in the payment file"
        ));
    }

    if card_details.exp_month.is_empty() {
        return Err(anyhow!(
            "Card expiry month is required either via --exp-month or in the payment file"
        ));
    }

    if card_details.exp_year.is_empty() {
        return Err(anyhow!(
            "Card expiry year is required either via --exp-year or in the payment file"
        ));
    }

    if card_details.cvc.is_empty() {
        return Err(anyhow!(
            "Card CVC is required either via --cvc or in the payment file"
        ));
    }

    // Connect to the server
    let mut client = connect_client(&args.url).await?;

    // Create metadata with auth details
    let mut metadata = MetadataMap::new();
    
    // Add connector
    metadata.insert(
        X_CONNECTOR,
        connector.to_string().parse().unwrap(),
    );

    // Add auth details based on auth type
    match auth_details.auth_type {
        AuthType::HeaderKey => {
            metadata.insert(
                X_AUTH,
                "header-key".parse().unwrap(),
            );
            metadata.insert(
                X_API_KEY,
                auth_details.api_key.parse().unwrap(),
            );
        }
        AuthType::BodyKey => {
            metadata.insert(
                X_AUTH,
                "body-key".parse().unwrap(),
            );
            metadata.insert(
                X_API_KEY,
                auth_details.api_key.parse().unwrap(),
            );
            if let Some(key1) = auth_details.key1 {
                metadata.insert(
                    X_KEY1,
                    key1.parse().unwrap(),
                );
            }
        }
        AuthType::SignatureKey => {
            metadata.insert(
                X_AUTH,
                "signature-key".parse().unwrap(),
            );
            metadata.insert(
                X_API_KEY,
                auth_details.api_key.parse().unwrap(),
            );
            if let Some(key1) = auth_details.key1 {
                metadata.insert(
                    X_KEY1,
                    key1.parse().unwrap(),
                );
            }
            if let Some(api_secret) = auth_details.api_secret {
                metadata.insert(
                    X_API_SECRET,
                    api_secret.parse().unwrap(),
                );
            }
        }
    }

    let request = payments::PaymentsAuthorizeRequest {
        amount,
        currency,
        payment_method: payments::PaymentMethod::Card as i32,
        payment_method_data: Some(payments::PaymentMethodData {
            data: Some(payments::payment_method_data::Data::Card(payments::Card {
                card_number: card_details.number,
                card_exp_month: card_details.exp_month,
                card_exp_year: card_details.exp_year,
                card_cvc: card_details.cvc,
                ..Default::default()
            })),
        }),
        email: args.email,
        address: Some(payments::PaymentAddress::default()),
        auth_type: payments::AuthenticationType::NoThreeDs as i32,
        minor_amount: amount,
        connector_request_reference_id: format!(
            "cli-ref-{}",
            chrono::Utc::now().timestamp_millis()
        ),
        capture_method: args.capture_method.map(|cm| {
            match cm.to_lowercase().as_str() {
                "automatic" => payments::CaptureMethod::Automatic as i32,
                "manual" => payments::CaptureMethod::Manual as i32,
                "manual_multiple" => payments::CaptureMethod::ManualMultiple as i32,
                "scheduled" => payments::CaptureMethod::Scheduled as i32,
                "sequential_automatic" => payments::CaptureMethod::SequentialAutomatic as i32,
                _ => payments::CaptureMethod::Automatic as i32,
            }
        }),
        return_url: args.return_url,
        webhook_url: args.webhook_url,
        complete_authorize_url: args.complete_authorize_url,
        off_session: args.off_session,
        order_category: args.order_category,
        enrolled_for_3ds: args.enrolled_for_3ds.unwrap_or(false),
        payment_experience: args.payment_experience.map(|pe| {
            match pe.to_lowercase().as_str() {
                "redirect_to_url" => payments::PaymentExperience::RedirectToUrl as i32,
                "invoke_sdk_client" => payments::PaymentExperience::InvokeSdkClient as i32,
                "display_qr_code" => payments::PaymentExperience::DisplayQrCode as i32,
                "one_click" => payments::PaymentExperience::OneClick as i32,
                "link_wallet" => payments::PaymentExperience::LinkWallet as i32,
                "invoke_payment_app" => payments::PaymentExperience::InvokePaymentApp as i32,
                "display_wait_screen" => payments::PaymentExperience::DisplayWaitScreen as i32,
                "collect_otp" => payments::PaymentExperience::CollectOtp as i32,
                _ => payments::PaymentExperience::RedirectToUrl as i32,
            }
        }),
        payment_method_type: args.payment_method_type.map(|pmt| {
            match pmt.to_lowercase().as_str() {
                "card" => payments::PaymentMethodType::Credit as i32,
                "credit" => payments::PaymentMethodType::Credit as i32,
                "debit" => payments::PaymentMethodType::Debit as i32,
                _ => payments::PaymentMethodType::Credit as i32,
            }
        }),
        request_incremental_authorization: args.request_incremental_authorization.unwrap_or(false),
        request_extended_authorization: args.request_extended_authorization.unwrap_or(false),
        merchant_order_reference_id: args.merchant_order_reference_id,
        shipping_cost: args.shipping_cost,
        setup_future_usage: args.future_usage.map(|fu| {
            match fu.to_lowercase().as_str() {
                "off_session" => payments::FutureUsage::OffSession as i32,
                "on_session" => payments::FutureUsage::OnSession as i32,
                _ => payments::FutureUsage::OffSession as i32,
            }
        }),
        ..Default::default()
    };

    let response = client.payment_authorize(Request::from_parts(metadata, Extensions::default(), request)).await;

    match response {
        Ok(response) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&response.into_inner()).unwrap()
            );
            Ok(())
        }
        Err(err) => {
            println!("Error during authorize call: {:#?}", err);
            Err(anyhow!("Authorize call failed"))
        }
    }
}

async fn handle_get(mut args: GetArgs) -> Result<()> {
    // Initialize auth details if not provided
    let mut auth_details = AuthDetails::default();

    // Load credential file if provided
    if let Some(cred_file) = &args.cred_file {
        let cred_data = load_credential_file(cred_file)?;

        // Set connector if not provided in command line
        if args.connector.is_none() {
            args.connector = Some(cred_data.connector);
            println!(
                "Using connector from credential file: {:?}",
                cred_data.connector
            );
        }

        // Set auth details from credential file
        auth_details = cred_data.auth;
        println!("Using authentication details from credential file");
    }

    // Override with command line auth if provided
    if let Some(cmd_auth) = &args.auth {
        if !cmd_auth.api_key.is_empty() {
            auth_details.api_key = cmd_auth.api_key.clone();
        }
        if cmd_auth.key1.is_some() {
            auth_details.key1 = cmd_auth.key1.clone();
        }
        if cmd_auth.api_secret.is_some() {
            auth_details.api_secret = cmd_auth.api_secret.clone();
        }
        if cmd_auth.auth_type != AuthType::default() {
            auth_details.auth_type = cmd_auth.auth_type;
        }
    }

    // Load sync file if provided
    if let Some(get_file) = &args.get_file {
        let sync_data = load_sync_file(get_file)?;

        // Set payment_id if not provided in command line
        if args.payment_id.is_none() {
            args.payment_id = Some(sync_data.payment_id.clone());
            println!("Using resource ID from sync file: {}", sync_data.payment_id);
        }
    }

    // Validate required fields
    let connector = args.connector.ok_or_else(|| {
        anyhow!("Connector is required either via --connector or in the credential file")
    })?;

    let payment_id = args.payment_id.as_deref().ok_or_else(|| {
        anyhow!("Resource ID is required either via --resource-id or in the sync file")
    })?;

    // Connect to the server
    let mut client = connect_client(&args.url).await?;

    // Create metadata with auth details
    let mut metadata = MetadataMap::new();
    
    // Add connector
    metadata.insert(
        X_CONNECTOR,
        connector.to_string().parse().unwrap(),
    );

    // Add auth details based on auth type
    match auth_details.auth_type {
        AuthType::HeaderKey => {
            metadata.insert(
                X_AUTH,
                "header-key".parse().unwrap(),
            );
            metadata.insert(
                X_API_KEY,
                auth_details.api_key.parse().unwrap(),
            );
        }
        AuthType::BodyKey => {
            metadata.insert(
                X_AUTH,
                "body-key".parse().unwrap(),
            );
            metadata.insert(
                X_API_KEY,
                auth_details.api_key.parse().unwrap(),
            );
            if let Some(key1) = auth_details.key1 {
                metadata.insert(
                    X_KEY1,
                    key1.parse().unwrap(),
                );
            }
        }
        AuthType::SignatureKey => {
            metadata.insert(
                X_AUTH,
                "signature-key".parse().unwrap(),
            );
            metadata.insert(
                X_API_KEY,
                auth_details.api_key.parse().unwrap(),
            );
            if let Some(key1) = auth_details.key1 {
                metadata.insert(
                    X_KEY1,
                    key1.parse().unwrap(),
                );
            }
            if let Some(api_secret) = auth_details.api_secret {
                metadata.insert(
                    X_API_SECRET,
                    api_secret.parse().unwrap(),
                );
            }
        }
    }

    let request = payments::PaymentsSyncRequest {
        resource_id: payment_id.to_string(),
        connector_request_reference_id: Some(format!(
            "cli-sync-ref-{}",
            chrono::Utc::now().timestamp_millis()
        )),
    };

    let response = client.payment_sync(Request::from_parts(metadata, Extensions::default(), request)).await;

    match response {
        Ok(response) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&response.into_inner()).unwrap()
            );
            Ok(())
        }
        Err(err) => {
            println!("Error during sync call: {:#?}", err);
            Err(anyhow!("Sync call failed"))
        }
    }
}

// --- Main ---
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Pay(args) => {
            handle_pay(args.clone()).await?;
        }
        Command::Get(args) => {
            handle_get(args.clone()).await?;
        }
    }

    Ok(())
}
