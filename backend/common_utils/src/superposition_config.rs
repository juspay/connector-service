//! Superposition configuration wrapper for connector-service
//!
//! This module provides a thin wrapper around `superposition_core::SuperpositionToml`
//! for loading and resolving configuration based on dimensions (connector, environment).

use std::collections::HashMap;
use serde_json::Value;

/// Error type for superposition configuration operations
#[derive(Debug, thiserror::Error)]
pub enum SuperpositionConfigError {
    /// Failed to read the configuration file
    #[error("Failed to read superposition config file '{path}': {source}")]
    FileReadError {
        path: String,
        source: std::io::Error,
    },
    /// Failed to parse the TOML configuration
    #[error("Failed to parse superposition.toml: {0}")]
    ParseError(String),
    /// Failed to resolve configuration for given context
    #[error("Failed to resolve configuration: {0}")]
    ResolutionError(String),
}

/// Parsed and cached representation of superposition.toml
#[derive(Debug, Clone)]
pub struct SuperpositionConfig {
    toml: superposition_core::SuperpositionToml,
}

impl SuperpositionConfig {
    /// Load and parse superposition.toml from the given path.
    ///
    /// # Arguments
    /// * `path` - Path to the superposition.toml file
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    ///
    /// # Example
    /// ```ignore
    /// let config = SuperpositionConfig::from_file("config/superposition.toml")?;
    /// ```
    pub fn from_file(path: &str) -> Result<Self, SuperpositionConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            SuperpositionConfigError::FileReadError {
                path: path.to_string(),
                source: e,
            }
        })?;

        let toml = superposition_core::SuperpositionToml::try_from_str(&contents)
            .map_err(SuperpositionConfigError::ParseError)?;

        Ok(Self { toml })
    }

    /// Resolve the flat key-value map for given dimensions.
    ///
    /// # Arguments
    /// * `connector` - The connector name (e.g., "stripe", "adyen")
    /// * `environment` - Optional environment name (e.g., "production", "sandbox")
    ///
    /// # Returns
    /// A HashMap of configuration keys to their resolved values.
    /// If `environment` is None, only the connector dimension is used for resolution.
    ///
    /// # Example
    /// ```ignore
    /// let resolved = config.resolve("stripe", Some("production"))?;
    /// let base_url = resolved.get("connector_base_url").and_then(|v| v.as_str());
    /// ```
    pub fn resolve(
        &self,
        connector: &str,
        environment: Option<&str>,
    ) -> Result<HashMap<String, Value>, SuperpositionConfigError> {
        let mut context = HashMap::new();
        context.insert("connector".to_string(), connector.to_string());
        if let Some(env) = environment {
            context.insert("environment".to_string(), env.to_string());
        }

        self.toml
            .resolve(context)
            .map_err(SuperpositionConfigError::ResolutionError)
    }
}

/// Helper function to extract a string value from the resolved configuration
pub fn get_string(resolved: &HashMap<String, Value>, key: &str) -> String {
    resolved
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Helper function to extract an optional non-empty string from the resolved configuration
pub fn get_optional_nonempty_string(resolved: &HashMap<String, Value>, key: &str) -> Option<String> {
    let value = get_string(resolved, key);
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_string_returns_empty_for_missing_key() {
        let resolved = HashMap::new();
        assert_eq!(get_string(&resolved, "missing_key"), "");
    }

    #[test]
    fn test_get_string_returns_value() {
        let mut resolved = HashMap::new();
        resolved.insert(
            "connector_base_url".to_string(),
            Value::String("https://api.example.com/".to_string()),
        );
        assert_eq!(
            get_string(&resolved, "connector_base_url"),
            "https://api.example.com/"
        );
    }

    #[test]
    fn test_get_optional_nonempty_string_returns_none_for_empty() {
        let mut resolved = HashMap::new();
        resolved.insert("key".to_string(), Value::String("".to_string()));
        assert_eq!(get_optional_nonempty_string(&resolved, "key"), None);
    }

    #[test]
    fn test_get_optional_nonempty_string_returns_some_for_value() {
        let mut resolved = HashMap::new();
        resolved.insert(
            "key".to_string(),
            Value::String("value".to_string()),
        );
        assert_eq!(
            get_optional_nonempty_string(&resolved, "key"),
            Some("value".to_string())
        );
    }
}