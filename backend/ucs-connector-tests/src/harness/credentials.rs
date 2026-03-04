use std::{fs, path::PathBuf};

#[derive(Clone, Debug)]
pub struct ConnectorAuth {
    pub api_key: String,
    pub key1: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("Failed to read credentials file: {0}")]
    FileRead(#[from] std::io::Error),
    #[error("Failed to parse credentials file: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Connector '{0}' not found in credentials file")]
    ConnectorNotFound(String),
    #[error("Missing connector_account_details for '{0}'")]
    MissingAccountDetails(String),
    #[error("Invalid auth_type '{auth_type}' for '{connector}' (expected body_key/body-key)")]
    InvalidAuthType {
        connector: String,
        auth_type: String,
    },
    #[error("Missing field '{field}' for connector '{connector}'")]
    MissingField { connector: String, field: String },
}

fn default_creds_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/test/creds.json")
}

fn creds_file_path() -> PathBuf {
    std::env::var("CONNECTOR_AUTH_FILE_PATH")
        .or_else(|_| std::env::var("UCS_CREDS_PATH"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_creds_path())
}

fn extract_account_details<'a>(
    root: &'a serde_json::Value,
    connector: &str,
) -> Result<&'a serde_json::Value, CredentialError> {
    let connector_value = root
        .get(connector)
        .ok_or_else(|| CredentialError::ConnectorNotFound(connector.to_string()))?;

    if let Some(account_details) = connector_value.get("connector_account_details") {
        return Ok(account_details);
    }

    if let Some(connector_obj) = connector_value.as_object() {
        for nested_value in connector_obj.values() {
            if let Some(account_details) = nested_value.get("connector_account_details") {
                return Ok(account_details);
            }
        }
    }

    Err(CredentialError::MissingAccountDetails(
        connector.to_string(),
    ))
}

pub fn load_body_key_auth(connector: &str) -> Result<ConnectorAuth, CredentialError> {
    let content = fs::read_to_string(creds_file_path())?;
    let json: serde_json::Value = serde_json::from_str(&content)?;
    let account_details = extract_account_details(&json, connector)?;

    let auth_type = account_details
        .get("auth_type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CredentialError::MissingField {
            connector: connector.to_string(),
            field: "auth_type".to_string(),
        })?;

    let normalized_auth_type = auth_type.to_ascii_lowercase();
    if normalized_auth_type != "body_key"
        && normalized_auth_type != "body-key"
        && normalized_auth_type != "bodykey"
    {
        return Err(CredentialError::InvalidAuthType {
            connector: connector.to_string(),
            auth_type: auth_type.to_string(),
        });
    }

    let api_key = account_details
        .get("api_key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CredentialError::MissingField {
            connector: connector.to_string(),
            field: "api_key".to_string(),
        })?
        .to_string();

    let key1 = account_details
        .get("key1")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CredentialError::MissingField {
            connector: connector.to_string(),
            field: "key1".to_string(),
        })?
        .to_string();

    Ok(ConnectorAuth { api_key, key1 })
}
