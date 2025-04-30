// src/main.rs

// --- Imports ---
use anyhow::{Context, Result, anyhow};
use shelgon::{command, renderer}; // Import shelgon types
use std::{env, str::FromStr};
use strum::{EnumString, EnumVariantNames, VariantNames}; // For parsing enums
use tokio::runtime::Runtime; // Need runtime for blocking async calls
// Import Endpoint for client connection
use tonic::{
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
}; // <-- Added Endpoint

// --- Use gRPC types from the crate ---
use grpc_api_types::payments::{self, Address};

// --- Type Aliases ---
// Alias for the client type
type PaymentClient = payments::payment_service_client::PaymentServiceClient<Channel>;

// --- Enums ---
#[derive(Debug, Clone, Copy, EnumString, EnumVariantNames, PartialEq)]
#[strum(serialize_all = "snake_case")]
enum ConnectorChoice {
    Adyen,
    Razorpay,
    // Add other connectors defined in the crate's payments::Connector enum
}

impl From<ConnectorChoice> for i32 {
    fn from(choice: ConnectorChoice) -> Self {
        match choice {
            ConnectorChoice::Adyen => payments::Connector::Adyen as i32,
            ConnectorChoice::Razorpay => payments::Connector::Razorpay as i32,
            // Add mappings
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum AuthDetailsChoice {
    BodyKey {
        api_key: String,
        key1: String,
    },
    // Updated HeaderKey to only have api_key
    HeaderKey {
        api_key: String,
    }, // <-- Removed key1
    // Add other auth types matching the crate's payments::auth_type::AuthDetails oneof
    SignatureKey {
        api_key: String,
        key1: String,
        api_secret: String,
    },
    // e.g., NoKey,
}

// impl From<AuthDetailsChoice> for payments::AuthType {
//     fn from(choice: AuthDetailsChoice) -> Self {
//         match choice {
//             AuthDetailsChoice::BodyKey { api_key, key1 } => payments::AuthType {
//                 auth_details: Some(payments::auth_type::AuthDetails::BodyKey(
//                     payments::BodyKey { api_key, key1 },
//                 )),
//             },
//             // Updated HeaderKey mapping
//             AuthDetailsChoice::HeaderKey { api_key } => payments::AuthType {
//                 // <-- Removed key1
//                 auth_details: Some(payments::auth_type::AuthDetails::HeaderKey(
//                     // Construct HeaderKey correctly using crate type
//                     payments::HeaderKey { api_key }, // <-- Removed key1
//                 )),
//             },
//             AuthDetailsChoice::SignatureKey {
//                 api_key,
//                 key1,
//                 api_secret,
//             } => payments::AuthType {
//                 auth_details: Some(payments::auth_type::AuthDetails::SignatureKey(
//                     payments::SignatureKey {
//                         api_key,
//                         key1,
//                         api_secret,
//                     },
//                 )),
//             },
//             // Add mappings for other AuthDetailsChoice variants if added
//             // e.g., AuthDetailsChoice::NoKey => payments::AuthType {
//             //     auth_details: Some(payments::auth_type::AuthDetails::NoKey(true)),
//             // },
//         }
//     }
// }

// --- Application State ---
#[derive(Debug, Default, Clone)]
struct AppState {
    url: Option<String>,
    connector: Option<ConnectorChoice>,
    auth_details: Option<String>,
    card_number: Option<String>,
    card_exp_month: Option<String>,
    card_exp_year: Option<String>,
    card_cvc: Option<String>,
    amount: Option<i64>,
    currency: Option<i32>,
    resource_id: Option<String>,
    email: Option<String>,
    api_key: Option<String>,
    key1: Option<String>,
    api_secret: Option<String>,
}

// --- Shelgon Context ---
struct ShellContext {
    state: AppState,
    // Store the client directly, as it's created from the channel
    client: Option<PaymentClient>,
}

// --- Shelgon Executor ---
struct PaymentShellExecutor {}

// --- Command Parsing (Helper) ---
fn parse_command_parts(line: &str) -> Vec<String> {
    line.split_whitespace().map(String::from).collect()
}

// --- gRPC Client Helper ---
// Corrected function to create endpoint, connect channel, and return client
async fn connect_client(url: &str) -> Result<PaymentClient> {
    let endpoint = Endpoint::try_from(url.to_string())
        .with_context(|| format!("Failed to create endpoint for URL: {}", url))?;

    // Optional: Configure endpoint (e.g., timeouts)
    // let endpoint = endpoint.connect_timeout(std::time::Duration::from_secs(5));

    let channel = endpoint
        .connect()
        .await
        .with_context(|| format!("Failed to connect channel to gRPC server at URL: {}", url))?;

    Ok(PaymentClient::new(channel))
}

// --- Command Handlers (Adapted for Shelgon Context) ---

fn handle_set(args: &[String], ctx: &mut ShellContext) -> Result<String> {
    if args.len() < 3 {
        // Updated help hint for auth headerkey
        return Err(anyhow!(
            "Usage: set <key> <value...> \nKeys: url, connector, amount, currency, email, resource_id, auth, card\nAuth Types: bodykey <api_key> <key1>, headerkey <api_key>"
        ));
    }

    let key = args[1].to_lowercase();
    let value_parts = &args[2..];
    let state = &mut ctx.state;

    match key.as_str() {
        "url" => {
            let new_url = value_parts[0].clone().trim().to_string();
            // Disconnect old client if URL changes
            ctx.client = None;
            state.url = Some(new_url.clone());
            // Attempt to connect immediately when URL is set
            let rt = Runtime::new().context("Failed to create Tokio runtime for connect")?;
            match rt.block_on(connect_client(&new_url)) {
                Ok(client) => {
                    ctx.client = Some(client); // Store the actual client
                    Ok(format!("URL set to: {} and client connected.", new_url))
                }
                Err(e) => {
                    state.url = Some(new_url.clone());
                    // Provide more context on connection failure
                    Err(anyhow!(
                        "URL set to: {}, but failed to connect client: {:?}",
                        new_url,
                        e
                    ))
                }
            }
        }
        "connector" => {
            let connector_str = value_parts[0].to_lowercase();
            let connector = ConnectorChoice::from_str(&connector_str).map_err(|_| {
                anyhow!(
                    "Invalid connector '{}'. Valid options: {:?}",
                    value_parts[0],
                    ConnectorChoice::VARIANTS
                )
            })?;
            state.connector = Some(connector);
            Ok(format!("Connector set to: {:?}", connector))
        }
        "amount" => {
            let amount = value_parts[0]
                .parse::<i64>()
                .with_context(|| format!("Invalid amount value: {}", value_parts[0]))?;
            state.amount = Some(amount);
            Ok(format!("Amount set to: {}", amount))
        }
        "currency" => {
            let currency_str = value_parts[0].to_lowercase();
            let currency_val = match currency_str.as_str() {
                "usd" => payments::Currency::Usd as i32,
                "gbp" => payments::Currency::Gbp as i32,
                "eur" => payments::Currency::Eur as i32,
                _ => {
                    return Err(anyhow!(
                        "Unsupported currency: {}. Use usd, gbp, eur, etc.",
                        currency_str
                    ));
                }
            };
            state.currency = Some(currency_val);
            Ok(format!(
                "Currency set to: {} ({})",
                currency_str, currency_val
            ))
        }
        "email" => {
            state.email = Some(value_parts[0].clone());
            Ok(format!("Email set to: {}", value_parts[0]))
        }
        "resource_id" => {
            state.resource_id = Some(value_parts[0].clone());
            Ok(format!("Resource ID set to: {}", value_parts[0]))
        }
        // "auth" => {
        //     if value_parts.len() < 1 {
        //         return Err(anyhow!("Usage: set auth <type> [params...]"));
        //     }
        //     let auth_type = value_parts[0].to_lowercase();
        //     match auth_type.as_str() {
        //         "bodykey" => {
        //             if value_parts.len() != 3 {
        //                 return Err(anyhow!("Usage: set auth bodykey <api_key> <key1>"));
        //             }
        //             state.auth_details = Some(AuthDetailsChoice::BodyKey {
        //                 api_key: value_parts[1].clone(),
        //                 key1: value_parts[2].clone(),
        //             });
        //             Ok("Auth set to: BodyKey".to_string())
        //         }
        //         "headerkey" => {
        //             // Updated headerkey to expect only api_key
        //             if value_parts.len() != 2 {
        //                 // <-- Changed from 3 to 2
        //                 return Err(anyhow!("Usage: set auth headerkey <api_key>")); // <-- Updated usage
        //             }
        //             state.auth_details = Some(AuthDetailsChoice::HeaderKey {
        //                 api_key: value_parts[1].clone(), // <-- Only api_key
        //             });
        //             Ok("Auth set to: HeaderKey".to_string())
        //         }
        //         "signaturekey" => {
        //             if value_parts.len() != 4 {
        //                 return Err(anyhow!("Usage: set auth bodykey <api_key> <key1>"));
        //             }
        //             state.auth_details = Some(AuthDetailsChoice::SignatureKey {
        //                 api_key: value_parts[1].clone(),
        //                 key1: value_parts[2].clone(),
        //                 api_secret: value_parts[3].clone(),
        //             });
        //             Ok("Auth set to: SignatureKey".to_string())
        //         }
        //         _ => Err(anyhow!(
        //             "Unknown auth type: {}. Supported: bodykey, headerkey",
        //             auth_type
        //         )),
        //     }
        // }
        "api_key" => {
            state.api_key = Some(value_parts[0].to_string());
            Ok(format!("API key set to: {}", value_parts[0]))
        }
        "key1" => {
            state.key1 = Some(value_parts[0].to_string());
            Ok(format!("Key1 set to: {}", value_parts[0]))
        }
        "auth" => {
            state.auth_details = Some(value_parts[0].to_string());
            Ok(format!("Auth set to: {}", value_parts[0]))
        }
        "card" => {
            if value_parts.len() < 2 {
                return Err(anyhow!("Usage: set card <field> <value>"));
            }
            let field = value_parts[0].to_lowercase();
            let value = &value_parts[1];
            match field.as_str() {
                "number" => {
                    state.card_number = Some(value.clone());
                    Ok("Card number set".to_string())
                }
                "exp_month" => {
                    state.card_exp_month = Some(value.clone());
                    Ok("Card expiry month set".to_string())
                }
                "exp_year" => {
                    state.card_exp_year = Some(value.clone());
                    Ok("Card expiry year set".to_string())
                }
                "cvc" => {
                    state.card_cvc = Some(value.clone());
                    Ok("Card CVC set".to_string())
                }
                _ => Err(anyhow!(
                    "Unknown card field: {}. Use number, exp_month, exp_year, cvc",
                    field
                )),
            }
        }
        _ => Err(anyhow!("Unknown set key: {}", key)),
    }
}

fn handle_unset(args: &[String], ctx: &mut ShellContext) -> Result<String> {
    if args.len() < 2 {
        return Err(anyhow!(
            "Usage: unset <key>\nKeys: url, connector, amount, currency, email, resource_id, auth, card, card.number, ..."
        ));
    }
    let key = args[1].to_lowercase();
    let state = &mut ctx.state;

    match key.as_str() {
        "url" => {
            state.url = None;
            ctx.client = None;
            Ok("URL unset and client disconnected".to_string())
        }
        "connector" => {
            state.connector = None;
            Ok("Connector unset".to_string())
        }
        "amount" => {
            state.amount = None;
            Ok("Amount unset".to_string())
        }
        "currency" => {
            state.currency = None;
            Ok("Currency unset".to_string())
        }
        "email" => {
            state.email = None;
            Ok("Email unset".to_string())
        }
        "api_key" => {
            state.api_key = None;
            Ok("Api key unset".to_string())
        }
        "key1" => {
            state.key1 = None;
            Ok("Key1 unset".to_string())
        }
        "resource_id" => {
            state.resource_id = None;
            Ok("Resource ID unset".to_string())
        }
        "auth" => {
            state.auth_details = None;
            Ok("Auth details unset".to_string())
        }
        "card" => {
            state.card_number = None;
            state.card_exp_month = None;
            state.card_exp_year = None;
            state.card_cvc = None;
            Ok("All card details unset".to_string())
        }
        "card.number" => {
            state.card_number = None;
            Ok("Card number unset".to_string())
        }
        "card.exp_month" => {
            state.card_exp_month = None;
            Ok("Card expiry month unset".to_string())
        }
        "card.exp_year" => {
            state.card_exp_year = None;
            Ok("Card expiry year unset".to_string())
        }
        "card.cvc" => {
            state.card_cvc = None;
            Ok("Card CVC unset".to_string())
        }
        _ => Err(anyhow!("Unknown unset key: {}", key)),
    }
}

// Async handler for gRPC calls
async fn handle_call_async(args: &[String], ctx: &mut ShellContext) -> Result<String> {
    if args.len() < 2 {
        return Err(anyhow!(
            "Usage: call <operation>\nOperations: authorize, sync"
        ));
    }
    let operation = args[1].to_lowercase();
    let state = &ctx.state;

    // // Get a mutable reference to the client stored in the context
    // let client = ctx
    //     .client
    //     .as_mut()
    //     .ok_or_else(|| anyhow!("Client not connected. Use 'set url <value>' first."))?;

    let mut client = connect_client(&state.url.as_ref().unwrap()).await?;

    // let auth_creds = state
    //     .auth_details
    //     .clone()
    //     .ok_or_else(|| anyhow!("Authentication details are not set."))?
    //     .into();
    // let connector_val = state
    //     .connector
    //     .ok_or_else(|| anyhow!("Connector is not set."))?;

    match operation.as_str() {
        "authorize" => {
            let amount = state.amount.ok_or_else(|| anyhow!("Amount is not set."))?;
            let currency = state
                .currency
                .ok_or_else(|| anyhow!("Currency is not set."))?;
            let card_number = state
                .card_number
                .as_ref()
                .ok_or_else(|| anyhow!("Card number is not set."))?;
            let card_exp_month = state
                .card_exp_month
                .as_ref()
                .ok_or_else(|| anyhow!("Card expiry month is not set."))?;
            let card_exp_year = state
                .card_exp_year
                .as_ref()
                .ok_or_else(|| anyhow!("Card expiry year is not set."))?;
            let card_cvc = state
                .card_cvc
                .as_ref()
                .ok_or_else(|| anyhow!("Card CVC is not set."))?;

            let request = payments::PaymentsAuthorizeRequest {
                amount,
                currency,
                // connector: connector_val.into(),
                // auth_creds: Some(auth_creds),
                connector_customer: Some("cus_1234".to_string()),
                return_url: Some("www.google.com".to_string()),
                payment_method: payments::PaymentMethod::Card as i32,
                payment_method_data: Some(payments::PaymentMethodData {
                    data: Some(payments::payment_method_data::Data::Card(payments::Card {
                        card_number: card_number.clone(),
                        card_exp_month: card_exp_month.clone(),
                        card_exp_year: card_exp_year.clone(),
                        card_cvc: card_cvc.clone(),
                        ..Default::default()
                    })),
                }),
                email: state.email.clone(),
                address: Some(payments::PaymentAddress::default()),
                auth_type: payments::AuthenticationType::NoThreeDs as i32,
                minor_amount: amount,
                request_incremental_authorization: false,
                connector_request_reference_id: format!(
                    "shell-ref-{}",
                    chrono::Utc::now().timestamp_millis()
                ),
                browser_info: Some(payments::BrowserInformation {
                    user_agent: Some("Mozilla/5.0".to_string()),
                    accept_header: Some("*/*".to_string()),
                    language: Some("en-US".to_string()),
                    color_depth: Some(24),
                    screen_height: Some(1080),
                    screen_width: Some(1920),
                    java_enabled: Some(false),
                    java_script_enabled: None,
                    time_zone: None,
                    ip_address: None,
                    os_type: None,
                    os_version: None,
                    device_model: None,
                    accept_language: None,
                }),
                ..Default::default()
            };

            // println!("Sending Authorize request: {:#?}", request);
            // Call the method on the mutable client reference
            let mut request = tonic::Request::new(request);
            request
                .metadata_mut()
                .append("x-connector", "adyen".parse().unwrap());
            request.metadata_mut().append(
                "x-auth",
                MetadataValue::from_str(&state.auth_details.clone().unwrap())?,
            );
            request.metadata_mut().append(
                "x-api-key",
                MetadataValue::from_str(&state.api_key.clone().unwrap())?,
            );
            request.metadata_mut().append(
                "x-key1",
                MetadataValue::from_str(&state.key1.clone().unwrap())?,
            );
            let response = client.payment_authorize(request).await;

            match response {
                Ok(response) => Ok(format!("{:#?}", response.into_inner())),
                Err(err) => Ok(format!("Error during authorize call: {:#?}", err)),
            }
            // Use Debug formatting for potentially multi-line responses
        }
        "sync" => {
            let resource_id = state
                .resource_id
                .as_ref()
                .ok_or_else(|| anyhow!("Resource ID is not set."))?;
            let request = payments::PaymentsSyncRequest {
                // connector: connector_val.into(),
                // auth_creds: Some(auth_creds),
                resource_id: resource_id.clone(),
                connector_request_reference_id: Some(format!(
                    "shell-sync-ref-{}",
                    chrono::Utc::now().timestamp_millis()
                )),
            };

            // println!("Sending Sync request: {:#?}", request);
            // Call the method on the mutable client reference
            let mut request = tonic::Request::new(request);
            request
                .metadata_mut()
                .append("x-connector", "razorpay".parse().unwrap());
            request.metadata_mut().append(
                "x-auth",
                MetadataValue::from_str(&state.auth_details.clone().unwrap())?,
            );
            request.metadata_mut().append(
                "x-api-key",
                MetadataValue::from_str(&state.api_key.clone().unwrap())?,
            );
            request.metadata_mut().append(
                "x-key1",
                MetadataValue::from_str(&state.key1.clone().unwrap())?,
            );
            let response = client
                .payment_sync(request)
                .await
                .context("Sync call failed")?;
            // Use Debug formatting for potentially multi-line responses
            Ok(format!("{:#?}", response.into_inner()))
        }
        _ => Err(anyhow!(
            "Unknown call operation: {}. Use authorize or sync",
            operation
        )),
    }
}

fn handle_show(ctx: &ShellContext) -> Result<String> {
    // Use Debug formatting which might produce multiple lines
    Ok(format!("{:#?}", ctx.state))
}

// Updated help text for auth headerkey
fn handle_help() -> Result<String> {
    // Help text itself contains newlines
    Ok("Available Commands:\n".to_string() +
        "  set <key> <value...>   - Set a configuration value. Keys: url, connector, amount, currency, email, resource_id, auth, card\n" +
        "                           Example: set url http://localhost:8080\n" +
        "                           Example: set connector adyen\n" +
        "                           Example: set amount 1000\n" +
        "                           Example: set currency usd\n" +
        "                           Example: set email user@example.com\n" +
        "                           Example: set resource_id pay_12345\n" +
        "                           Example: set auth bodykey your_api_key your_key1\n" +
        "                           Example: set auth headerkey your_api_key\n" + // <-- Updated example
        "                           Example: set auth signaturekey your_api_key your_key1 your_api_secret\n" +
        "                           Example: set card number 1234...5678\n" +
        "                           Example: set card exp_month 12\n" +
        "                           Example: set card exp_year 2030\n" +
        "                           Example: set card cvc 123\n" +
        "  unset <key>          - Unset a configuration value. Keys: url, connector, amount, currency, email, resource_id, auth, card, card.number, ...\n" +
        "                           Example: unset card.cvc\n" +
        "                           Example: unset auth\n" +
        "  call <operation>     - Call a gRPC method. Operations: authorize, sync\n" +
        "                           Example: call authorize\n" +
        "  show                 - Show the current configuration state.\n" +
        "  help                 - Show this help message.\n" +
        "  exit                 - Exit the shell.")
}

// --- Shelgon Execute Implementation ---
impl command::Execute for PaymentShellExecutor {
    type Context = ShellContext;

    fn prompt(&self, _ctx: &Self::Context) -> String {
        ">> ".to_string()
    }

    fn execute(
        &self,
        ctx: &mut Self::Context,
        cmd_input: command::CommandInput,
    ) -> anyhow::Result<command::OutputAction> {
        let args = parse_command_parts(&cmd_input.command);
        if args.is_empty() {
            // Correctly create an empty CommandOutput
            let empty_output = command::CommandOutput {
                prompt: cmd_input.prompt,
                command: cmd_input.command,
                stdin: cmd_input.stdin.unwrap_or_default(),
                stdout: Vec::new(), // Empty stdout
                stderr: Vec::new(),
            };
            return Ok(command::OutputAction::Command(empty_output));
        }

        let command_name = args[0].to_lowercase();
        // Create runtime once for the execution block if needed
        let rt = Runtime::new().context("Failed to create Tokio runtime")?;

        let result: Result<String> = match command_name.as_str() {
            "set" => handle_set(&args, ctx),
            "unset" => handle_unset(&args, ctx),
            // Block on the async call handler
            "call" => rt.block_on(handle_call_async(&args, ctx)),
            "show" => handle_show(ctx),
            "help" => handle_help(),
            "exit" | "quit" => return Ok(command::OutputAction::Exit),
            "clear" => return Ok(command::OutputAction::Clear),
            _ => Err(anyhow!("Unknown command: {}", command_name)),
        };

        // Construct the output, splitting successful stdout messages into lines
        let output = match result {
            Ok(stdout_msg) => command::CommandOutput {
                prompt: cmd_input.prompt,
                command: cmd_input.command,
                stdin: cmd_input.stdin.unwrap_or_default(),
                // --- FIX: Split stdout_msg by lines ---
                stdout: stdout_msg.lines().map(String::from).collect(),
                // --- End Fix ---
                stderr: Vec::new(),
            },
            Err(e) => command::CommandOutput {
                prompt: cmd_input.prompt,
                command: cmd_input.command,
                stdin: cmd_input.stdin.unwrap_or_default(),
                stdout: Vec::new(),
                // Keep stderr as a single-element vector for the error message
                stderr: vec![format!("Error: {:?}", e)],
            },
        };

        Ok(command::OutputAction::Command(output))
    }

    fn prepare(&self, cmd: &str) -> shelgon::Prepare {
        shelgon::Prepare {
            command: cmd.to_string(),
            stdin_required: false,
        }
    }

    fn completion(
        &self,
        _ctx: &Self::Context,
        incomplete_command: &str,
    ) -> anyhow::Result<(String, Vec<String>)> {
        let commands = ["set", "unset", "call", "show", "help", "exit", "clear"];
        let mut completions = Vec::new();
        let mut remaining = String::new();
        let parts = parse_command_parts(incomplete_command);

        if parts.len() <= 1 {
            let current_part = parts.first().map_or("", |s| s.as_str());
            let mut exact_match = None;
            for &cmd in commands.iter() {
                if cmd.starts_with(current_part) {
                    completions.push(cmd.to_string());
                    if cmd == current_part {
                        exact_match = Some(cmd);
                    }
                }
            }
            if completions.len() == 1 && exact_match.is_none() {
                remaining = completions[0]
                    .strip_prefix(current_part)
                    .unwrap_or("")
                    .to_string();
                completions.clear();
            } else if exact_match.is_some() {
                completions.clear();
                // TODO: Add argument/subcommand completion
            }
        } else {
            // TODO: Add argument completion
        }
        Ok((remaining, completions))
    }
}

// --- Main Function ---
fn main() -> anyhow::Result<()> {
    println!("gRPC Payment Shell (Shelgon / Crate). Type 'help' for commands.");

    let rt = Runtime::new().context("Failed to create Tokio runtime")?;
    let initial_state = AppState::default();
    let context = ShellContext {
        state: initial_state,
        client: None,
    };

    let app = renderer::App::<PaymentShellExecutor>::new_with_executor(
        rt,
        PaymentShellExecutor {},
        context,
    );

    app.execute()
}
