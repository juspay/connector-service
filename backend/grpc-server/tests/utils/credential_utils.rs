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

// Path to the credentials file
const CREDS_FILE_PATH: &str = "../../.github/test/creds.json";

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
    let creds_content = fs::read_to_string(CREDS_FILE_PATH)?;
    let all_credentials: AllCredentials = serde_json::from_str(&creds_content)?;

    let connector_creds = all_credentials
        .get(connector_name)
        .ok_or_else(|| CredentialError::ConnectorNotFound(connector_name.to_string()))?;

    Ok(connector_creds.metadata.clone().unwrap_or_default())
}

/// Load credentials from JSON file
fn load_from_json(connector_name: &str) -> Result<ConnectorAuthType, CredentialError> {
    let creds_content = fs::read_to_string(CREDS_FILE_PATH)?;
    let all_credentials: AllCredentials = serde_json::from_str(&creds_content)?;

    let connector_creds = all_credentials
        .get(connector_name)
        .ok_or_else(|| CredentialError::ConnectorNotFound(connector_name.to_string()))?;

    convert_to_auth_type(&connector_creds.connector_account_details, connector_name)
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
