//! Common credential loading utilities for test files
//!
//! This module provides a generic way to load connector credentials from
//! the JSON configuration file (.github/test/creds.json)

#![allow(dead_code)]

use common_enums::enums::Currency;
use common_utils::pii::SecretSerdeValue;
use domain_types::router_data::ConnectorAuthType;
use hyperswitch_masking::Secret;
use std::{collections::HashMap, fs};

// Path to the credentials file - use environment variable if set (for CI), otherwise use relative path (for local)
fn get_creds_file_path() -> String {
    std::env::var("CONNECTOR_AUTH_FILE_PATH").unwrap_or_else(|_| {
        "/home/runner/work/connector-service/connector-service/.github/test/creds.json".to_string()
    })
}

/// Generic credential structure that can deserialize any connector's credentials
#[derive(serde::Deserialize, Debug, Clone)]
pub struct ConnectorAccountDetails {
    pub auth_type: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub key1: Option<String>,
    #[serde(default)]
    pub api_secret: Option<String>,
    #[serde(default)]
    pub key2: Option<String>,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub auth_key_map: Option<HashMap<Currency, SecretSerdeValue>>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct ConnectorCredentials {
    pub connector_account_details: ConnectorAccountDetails,
    #[serde(default)]
    pub metadata: Option<HashMap<String, String>>,
}

/// All connector credentials stored in the JSON file
pub type AllCredentials = HashMap<String, ConnectorCredentials>;

/// Error type for credential loading operations
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("Failed to read credentials file: {0}")]
    FileReadError(#[from] std::io::Error),
    #[error("Failed to parse credentials JSON: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("Connector '{0}' not found in credentials")]
    ConnectorNotFound(String),
    #[error("Invalid auth type '{0}' for connector '{1}'")]
    InvalidAuthType(String, String),
    #[error("Missing required field '{0}' for auth type '{1}'")]
    MissingField(String, String),
}

/// Load credentials for a specific connector from the JSON configuration file
///
/// # Arguments
/// * `connector_name` - Name of the connector (e.g., "aci", "authorizedotnet")
///
/// # Returns
/// * `ConnectorAuthType` - The loaded and converted credentials
///
/// # Examples
/// ```
/// // Load Authorize.Net credentials
/// let auth = load_connector_auth("authorizedotnet").unwrap();
/// ```
pub fn load_connector_auth(connector_name: &str) -> Result<ConnectorAuthType, CredentialError> {
    load_from_json(connector_name)
}

/// Load metadata for a specific connector from the JSON configuration file
///
/// # Arguments
/// * `connector_name` - Name of the connector (e.g., "nexinets", "fiserv")
///
/// # Returns
/// * `HashMap<String, String>` - The metadata key-value pairs, or empty map if no metadata
///
/// # Examples
/// ```
/// // Load connector metadata (e.g., terminal_id, shop_name)
/// let metadata = load_connector_metadata("fiserv").unwrap();
/// let terminal_id = metadata.get("terminal_id");
/// ```
pub fn load_connector_metadata(
    connector_name: &str,
) -> Result<HashMap<String, String>, CredentialError> {
    let creds_file_path = get_creds_file_path();
    let creds_content = fs::read_to_string(&creds_file_path).map_err(|e| {
        eprintln!("Failed to read credentials file at: {}", creds_file_path);
        eprintln!("Error: {}", e);
        CredentialError::FileReadError(e)
    })?;

    // First, let's try to parse as raw JSON to provide better error context
    let json_value: serde_json::Value = serde_json::from_str(&creds_content).map_err(|e| {
        eprintln!("Failed to parse credentials JSON file for metadata loading");
        eprintln!("JSON parsing error: {}", e);
        eprintln!("File path: {}", creds_file_path);
        CredentialError::ParseError(e)
    })?;

    // Try to load using the enhanced individual parsing approach
    let all_credentials = match load_credentials_individually(&json_value) {
        Ok(creds) => creds,
        Err(e) => {
            eprintln!("Failed to load credentials using individual parsing approach for metadata");
            eprintln!("Falling back to standard parsing...");
            
            // Try standard parsing as fallback
            serde_json::from_value(json_value).map_err(|e| {
                eprintln!("Standard parsing also failed for metadata: {}", e);
                CredentialError::ParseError(e)
            })?
        }
    };

    let connector_creds = all_credentials
        .get(connector_name)
        .ok_or_else(|| {
            eprintln!("Connector '{}' not found in credentials file for metadata", connector_name);
            eprintln!("Available connectors: {:?}", all_credentials.keys().collect::<Vec<_>>());
            CredentialError::ConnectorNotFound(connector_name.to_string())
        })?;

    Ok(connector_creds.metadata.clone().unwrap_or_default())
}

/// Load credentials from JSON file with enhanced error handling
fn load_from_json(connector_name: &str) -> Result<ConnectorAuthType, CredentialError> {
    let creds_file_path = get_creds_file_path();
    let creds_content = fs::read_to_string(&creds_file_path).map_err(|e| {
        eprintln!("Failed to read credentials file at: {}", creds_file_path);
        eprintln!("Error: {}", e);
        CredentialError::FileReadError(e)
    })?;

    // First, let's try to parse as raw JSON to provide better error context
    let json_value: serde_json::Value = serde_json::from_str(&creds_content).map_err(|e| {
        eprintln!("Failed to parse credentials JSON file");
        eprintln!("JSON parsing error: {}", e);
        eprintln!("File path: {}", creds_file_path);
        CredentialError::ParseError(e)
    })?;

    // Try to load each connector individually to isolate issues
    let all_credentials = match load_credentials_individually(&json_value) {
        Ok(creds) => creds,
        Err(e) => {
            eprintln!("Failed to load credentials using individual parsing approach");
            eprintln!("Falling back to standard parsing...");
            
            // Try standard parsing as fallback
            serde_json::from_value(json_value).map_err(|e| {
                eprintln!("Standard parsing also failed: {}", e);
                CredentialError::ParseError(e)
            })?
        }
    };

    let connector_creds = all_credentials
        .get(connector_name)
        .ok_or_else(|| {
            eprintln!("Connector '{}' not found in credentials file", connector_name);
            eprintln!("Available connectors: {:?}", all_credentials.keys().collect::<Vec<_>>());
            CredentialError::ConnectorNotFound(connector_name.to_string())
        })?;

    convert_to_auth_type(&connector_creds.connector_account_details, connector_name)
}

/// Load credentials by parsing each connector individually to isolate issues
fn load_credentials_individually(json_value: &serde_json::Value) -> Result<AllCredentials, CredentialError> {
    let mut all_credentials = std::collections::HashMap::new();
    
    let root_object = json_value.as_object()
        .ok_or_else(|| {
            // Create a custom ParseError using serde_json::from_str with invalid JSON
            let parse_error = serde_json::from_str::<()>("").unwrap_err();
            CredentialError::ParseError(parse_error)
        })?;

    for (connector_name, connector_value) in root_object {
        match parse_single_connector(connector_name, connector_value) {
            Ok(creds) => {
                eprintln!("Successfully loaded credentials for connector: {}", connector_name);
                all_credentials.insert(connector_name.clone(), creds);
            }
            Err(_e) => {
                eprintln!("Warning: Failed to load credentials for connector '{}': {}", connector_name, _e);
                eprintln!("Skipping connector '{}' and continuing with others", connector_name);
                // Continue loading other connectors instead of failing completely
            }
        }
    }

    if all_credentials.is_empty() {
        // Create a custom ParseError using serde_json::from_str with invalid JSON
        let parse_error = serde_json::from_str::<()>("").unwrap_err();
        return Err(CredentialError::ParseError(parse_error));
    }

    Ok(all_credentials)
}

/// Parse a single connector's credentials with detailed error reporting
fn parse_single_connector(connector_name: &str, connector_value: &serde_json::Value) -> Result<ConnectorCredentials, CredentialError> {
    // First validate the basic structure
    let connector_obj = connector_value.as_object()
        .ok_or_else(|| {
            eprintln!("Connector '{}' value must be an object", connector_name);
            let parse_error = serde_json::from_str::<()>("").unwrap_err();
            CredentialError::ParseError(parse_error)
        })?;

    // Check for required connector_account_details field
    let account_details_value = connector_obj.get("connector_account_details")
        .ok_or_else(|| {
            eprintln!("Connector '{}' missing 'connector_account_details' field", connector_name);
            let parse_error = serde_json::from_str::<()>("").unwrap_err();
            CredentialError::ParseError(parse_error)
        })?;

    // Parse connector_account_details with enhanced error handling
    let account_details = parse_connector_account_details(connector_name, account_details_value)?;

    // Parse metadata if present
    let metadata = connector_obj.get("metadata")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| {
            eprintln!("Failed to parse metadata for connector '{}': {}", connector_name, e);
            CredentialError::ParseError(e)
        })?;

    Ok(ConnectorCredentials {
        connector_account_details: account_details,
        metadata,
    })
}

/// Parse connector account details with field-specific error handling
fn parse_connector_account_details(connector_name: &str, value: &serde_json::Value) -> Result<ConnectorAccountDetails, CredentialError> {
    let obj = value.as_object()
        .ok_or_else(|| {
            eprintln!("connector_account_details for '{}' must be an object", connector_name);
            let parse_error = serde_json::from_str::<()>("").unwrap_err();
            CredentialError::ParseError(parse_error)
        })?;

    // Extract auth_type first
    let auth_type = obj.get("auth_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            eprintln!("Connector '{}' missing or invalid 'auth_type' field", connector_name);
            let parse_error = serde_json::from_str::<()>("").unwrap_err();
            CredentialError::ParseError(parse_error)
        })?
        .to_string();

    eprintln!("Parsing connector '{}' with auth_type: {}", connector_name, auth_type);

    // Handle different auth types with specific parsing logic
    match auth_type.as_str() {
        "CurrencyAuthKey" => {
            // Special handling for CurrencyAuthKey which has complex nested structure
            parse_currency_auth_key_details(connector_name, obj)
        }
        _ => {
            // For other auth types, use standard serde parsing
            serde_json::from_value(value.clone()).map_err(|e| {
                eprintln!("Failed to parse connector_account_details for '{}' with auth_type '{}': {}", 
                         connector_name, auth_type, e);
                CredentialError::ParseError(e)
            })
        }
    }
}

/// Special parsing logic for CurrencyAuthKey auth type
fn parse_currency_auth_key_details(connector_name: &str, obj: &serde_json::Map<String, serde_json::Value>) -> Result<ConnectorAccountDetails, CredentialError> {
    let auth_key_map_value = obj.get("auth_key_map")
        .ok_or_else(|| {
            eprintln!("Connector '{}' with CurrencyAuthKey missing 'auth_key_map' field", connector_name);
            let parse_error = serde_json::from_str::<()>("").unwrap_err();
            CredentialError::ParseError(parse_error)
        })?;

    // Parse auth_key_map manually to provide better error messages
    let auth_key_map = parse_auth_key_map(connector_name, auth_key_map_value)?;

    Ok(ConnectorAccountDetails {
        auth_type: "CurrencyAuthKey".to_string(),
        api_key: None,
        key1: None,
        api_secret: None,
        key2: None,
        certificate: None,
        private_key: None,
        auth_key_map: Some(auth_key_map),
    })
}

/// Parse auth_key_map with detailed error handling
fn parse_auth_key_map(connector_name: &str, value: &serde_json::Value) -> Result<HashMap<Currency, SecretSerdeValue>, CredentialError> {
    let obj = value.as_object()
        .ok_or_else(|| {
            eprintln!("auth_key_map for '{}' must be an object", connector_name);
            let parse_error = serde_json::from_str::<()>("").unwrap_err();
            CredentialError::ParseError(parse_error)
        })?;

    let mut auth_key_map = HashMap::new();

    for (currency_str, secret_value) in obj {
        // Parse currency string to Currency enum
        let currency = currency_str.parse::<Currency>().map_err(|_parse_err| {
            eprintln!("Invalid currency '{}' in auth_key_map for connector '{}'", currency_str, connector_name);
            let parse_error = serde_json::from_str::<()>("").unwrap_err();
            CredentialError::ParseError(parse_error)
        })?;

        // Create SecretSerdeValue from the JSON value
        let secret_serde_value = SecretSerdeValue::new(secret_value.clone());
        
        auth_key_map.insert(currency, secret_serde_value);
    }

    Ok(auth_key_map)
}

/// Convert generic credential details to specific ConnectorAuthType
fn convert_to_auth_type(
    details: &ConnectorAccountDetails,
    connector_name: &str,
) -> Result<ConnectorAuthType, CredentialError> {
    match details.auth_type.as_str() {
        "HeaderKey" => {
            let api_key = details.api_key.as_ref().ok_or_else(|| {
                CredentialError::MissingField("api_key".to_string(), "HeaderKey".to_string())
            })?;

            Ok(ConnectorAuthType::HeaderKey {
                api_key: Secret::new(api_key.clone()),
            })
        }
        "BodyKey" => {
            let api_key = details.api_key.as_ref().ok_or_else(|| {
                CredentialError::MissingField("api_key".to_string(), "BodyKey".to_string())
            })?;
            let key1 = details.key1.as_ref().ok_or_else(|| {
                CredentialError::MissingField("key1".to_string(), "BodyKey".to_string())
            })?;

            Ok(ConnectorAuthType::BodyKey {
                api_key: Secret::new(api_key.clone()),
                key1: Secret::new(key1.clone()),
            })
        }
        "SignatureKey" => {
            let api_key = details.api_key.as_ref().ok_or_else(|| {
                CredentialError::MissingField("api_key".to_string(), "SignatureKey".to_string())
            })?;
            let key1 = details.key1.as_ref().ok_or_else(|| {
                CredentialError::MissingField("key1".to_string(), "SignatureKey".to_string())
            })?;
            let api_secret = details.api_secret.as_ref().ok_or_else(|| {
                CredentialError::MissingField("api_secret".to_string(), "SignatureKey".to_string())
            })?;

            Ok(ConnectorAuthType::SignatureKey {
                api_key: Secret::new(api_key.clone()),
                key1: Secret::new(key1.clone()),
                api_secret: Secret::new(api_secret.clone()),
            })
        }
        "MultiAuthKey" => {
            let api_key = details.api_key.as_ref().ok_or_else(|| {
                CredentialError::MissingField("api_key".to_string(), "MultiAuthKey".to_string())
            })?;
            let key1 = details.key1.as_ref().ok_or_else(|| {
                CredentialError::MissingField("key1".to_string(), "MultiAuthKey".to_string())
            })?;
            let api_secret = details.api_secret.as_ref().ok_or_else(|| {
                CredentialError::MissingField("api_secret".to_string(), "MultiAuthKey".to_string())
            })?;
            let key2 = details.key2.as_ref().ok_or_else(|| {
                CredentialError::MissingField("key2".to_string(), "MultiAuthKey".to_string())
            })?;

            Ok(ConnectorAuthType::MultiAuthKey {
                api_key: Secret::new(api_key.clone()),
                key1: Secret::new(key1.clone()),
                api_secret: Secret::new(api_secret.clone()),
                key2: Secret::new(key2.clone()),
            })
        }
        "CurrencyAuthKey" => {
            // For CurrencyAuthKey, we expect the auth_key_map field to contain the mapping
            let auth_key_map = details.auth_key_map.as_ref().ok_or_else(|| {
                CredentialError::MissingField(
                    "auth_key_map".to_string(),
                    "CurrencyAuthKey".to_string(),
                )
            })?;

            Ok(ConnectorAuthType::CurrencyAuthKey {
                auth_key_map: auth_key_map.clone(),
            })
        }
        "CertificateAuth" => {
            let certificate = details.certificate.as_ref().ok_or_else(|| {
                CredentialError::MissingField(
                    "certificate".to_string(),
                    "CertificateAuth".to_string(),
                )
            })?;
            let private_key = details.private_key.as_ref().ok_or_else(|| {
                CredentialError::MissingField(
                    "private_key".to_string(),
                    "CertificateAuth".to_string(),
                )
            })?;

            Ok(ConnectorAuthType::CertificateAuth {
                certificate: Secret::new(certificate.clone()),
                private_key: Secret::new(private_key.clone()),
            })
        }
        "NoKey" => Ok(ConnectorAuthType::NoKey),
        "TemporaryAuth" => Ok(ConnectorAuthType::TemporaryAuth),
        _ => Err(CredentialError::InvalidAuthType(
            details.auth_type.clone(),
            connector_name.to_string(),
        )),
    }
}
